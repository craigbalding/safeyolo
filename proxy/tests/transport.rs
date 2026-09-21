use std::{
    convert::Infallible,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use safeyolo_proxy::{AgentListener, Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::{Notify, oneshot},
    task::JoinHandle,
};

struct Policy {
    task: JoinHandle<()>,
    requests: Arc<Mutex<Vec<Value>>>,
    waiting: Arc<Notify>,
    release: Arc<Notify>,
}

impl Policy {
    async fn start(path: &Path) -> Self {
        let socket = UnixListener::bind(path).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let waiting = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (seen, pending, released) = (requests.clone(), waiting.clone(), release.clone());
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = socket.accept().await.unwrap();
                let (seen, pending, released) = (seen.clone(), pending.clone(), released.clone());
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let (seen, pending, released) =
                            (seen.clone(), pending.clone(), released.clone());
                        async move {
                            assert_eq!(request.uri(), "/decision");
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            let metadata: Value = serde_json::from_slice(&body).unwrap();
                            let allow = metadata["agent_id"] == "alice"
                                && metadata["path"] != "/deny-inner";
                            let wait = metadata["path"] == "/wait";
                            let inconsistent = metadata["path"] == "/inconsistent";
                            seen.lock().unwrap().push(metadata);
                            if wait {
                                pending.notify_one();
                                released.notified().await;
                            }
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(json!({
                                "allow":allow, "decision": if allow && !inconsistent {"allow"} else {"deny"},
                                "status":if allow {200} else {403}, "headers":[["x-blocked-by","network-guard"]],
                                "body":"denied by existing policy",
                            }).to_string()))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        Self {
            task,
            requests,
            waiting,
            release,
        }
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(directory: &TempDir) -> Config {
    Config {
        agent_map_file: String::new(),
        data_dir: None,
        listeners: ["alice", "bob"]
            .iter()
            .map(|agent| AgentListener {
                agent_id: (*agent).into(),
                socket_path: directory.path().join(format!("{agent}.sock")),
                source_id: None,
            })
            .collect(),
        temporary_policy_socket: Some(directory.path().join("policy.sock")),
        policy_file: None,
        gateway_builtin_services_dir: None,
        gateway_services_dir: None,
        network_guard_enabled: true,
        network_guard_block: true,
        network_guard_homoglyph: true,
        credential_guard_block: true,
        circuit_breaker_enabled: true,
        circuit_state_file: None,
        agent_api_enabled: false,
        test_context_block: true,
        test_context_inject_declared: false,
        test_context_declared_ttl: json!(900),
        sse_streaming_enabled: true,
        sse_stream_json: false,
        flow_store_enabled: false,
        flow_store_db_path: directory.path().join("flows.sqlite3"),
        flow_pruner_max: 5000,
        flow_pruner_max_body_bytes: 1024 * 1024 * 1024,
        admin_port: None,
        admin_api_token_file: None,
        admin_shield_extra_ports: String::new(),
        plumb: Default::default(),
        readiness_file: directory.path().join("ready.json"),
        reload_id: None,
        audit_log_path: Some(directory.path().join("audit.jsonl")),
        event_log: directory.path().join("events.jsonl"),
        parent_proxy: None,
        upstream_ca_file: None,
        tls_ca_file: None,
        ignore_hosts: Vec::new(),
        via_token: Some("test-instance".into()),
        inspection: None,
    }
}

async fn request(socket: &Path, target: &str, headers: &str) -> String {
    raw(
        socket,
        &format!(
            "GET {target} HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n{headers}\r\n"
        ),
    )
    .await
}

async fn raw(socket: &Path, bytes: &str) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(bytes.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    })
    .await
    .expect("proxy response timed out")
}

async fn connect_raw(socket: &Path, authority: &str) -> UnixStream {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    stream
}

#[tokio::test]
async fn opaque_connect_preserves_each_tcp_half_close() {
    for server_half_first in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory);
        let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let payload = vec![0; 1024 * 1024];
        let expected = payload.clone();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if server_half_first {
                stream.write_all(b"server-first").await.unwrap();
                stream.shutdown().await.unwrap();
            }
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
            if !server_half_first {
                stream.write_all(b"after-client-eof").await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let mut client = connect_raw(&config.listeners[0].socket_path, &authority).await;
        let mut received = Vec::new();
        if server_half_first {
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, b"server-first");
        }
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        if !server_half_first {
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, b"after-client-eof");
        }
        tokio::time::timeout(Duration::from_secs(3), origin)
            .await
            .unwrap()
            .unwrap();
        drop(client);
        // Completion evidence is emitted by the owned tunnel task.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if events(&config)
                    .iter()
                    .any(|event| event["event"] == "proxy.tunnel")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let event = events(&config)
            .into_iter()
            .find(|event| event["event"] == "proxy.tunnel")
            .unwrap();
        assert_eq!(event["uploaded_bytes"], payload.len());
        assert_eq!(event["downloaded_bytes"], received.len());
        assert_eq!(event["coverage"], "opaque");
        assert_eq!(event["outcome"], "completed");
        assert_eq!(event["agent"], "alice");
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn opaque_connect_uses_parent_tunnel_and_denial_never_dials() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    // A configured logical destination still travels through the physical
    // parent route; parent connections are outside direct passthrough.
    config.ignore_hosts = vec!["destination.invalid:23456".into()];
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.parent_proxy = Some(format!("http://{}", listener.local_addr().unwrap()));
    let contacts = Arc::new(AtomicUsize::new(0));
    let seen = contacts.clone();
    let parent = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        seen.fetch_add(1, Ordering::SeqCst);
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"CONNECT destination.invalid:23456 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nserver-first")
            .await
            .unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"client");
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let denied = raw(&config.listeners[1].socket_path, "CONNECT destination.invalid:23456 HTTP/1.1\r\nHost: destination.invalid:23456\r\nConnection: close\r\n\r\n").await;
    assert!(denied.starts_with("HTTP/1.1 403"));
    assert_eq!(contacts.load(Ordering::SeqCst), 0);
    assert!(
        events(&config)
            .iter()
            .all(|event| event["event"] != "proxy.egress")
    );
    let mut client = connect_raw(
        &config.listeners[0].socket_path,
        "destination.invalid:23456",
    )
    .await;
    let mut banner = [0; 12];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut banner))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&banner, b"server-first");
    client.write_all(b"client").await.unwrap();
    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), parent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(contacts.load(Ordering::SeqCst), 1);
    assert!(passthrough_events(&config).is_empty());
    proxy.shutdown().await;
}

#[tokio::test]
async fn configured_passthrough_entry_does_not_bypass_parent_route() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;

    // Keep an independently listening origin as a no-egress canary. The exact
    // authority is a configured passthrough match, but the parent route must
    // still own the physical connection.
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let authority = format!("127.0.0.1:{origin_port}");
    config.ignore_hosts = vec![authority.clone()];

    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let parent_address = parent.local_addr().unwrap();
    config.parent_proxy = Some(format!("http://{parent_address}"));
    let origin_contacts = Arc::new(AtomicUsize::new(0));
    let origin_seen = origin_contacts.clone();
    let origin_task = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(2), origin.accept()).await {
            Ok(Ok((_socket, _peer))) => {
                origin_seen.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Err(error)) => panic!("origin accept failed: {error}"),
            Err(_) => {}
        }
    });
    let parent_task = tokio::spawn(async move {
        let (mut socket, peer) = tokio::time::timeout(Duration::from_secs(2), parent.accept())
            .await
            .unwrap()
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nparent-first")
            .await
            .unwrap();
        let mut payload = Vec::new();
        socket.read_to_end(&mut payload).await.unwrap();
        socket.write_all(b"parent-final").await.unwrap();
        socket.shutdown().await.unwrap();
        (peer, head, payload)
    });

    let proxy = Proxy::start(config.clone()).await.unwrap();
    let mut client = connect_raw(&config.listeners[0].socket_path, &authority).await;
    let mut first = [0; 12];
    client.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"parent-first");
    client.write_all(b"client").await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"parent-final");

    let (parent_peer, parent_head, parent_payload) =
        tokio::time::timeout(Duration::from_secs(2), parent_task)
            .await
            .unwrap()
            .unwrap();
    origin_task.await.unwrap();
    assert_eq!(
        parent_peer.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert!(parent_address.port() != origin_port);
    assert!(parent_head.starts_with(format!("CONNECT {authority} HTTP/1.1\r\n").as_bytes()));
    assert_eq!(parent_payload, b"client");
    assert_eq!(origin_contacts.load(Ordering::SeqCst), 0);

    let egress = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let rows = events(&config)
                .into_iter()
                .filter(|event| event["event"] == "proxy.egress")
                .collect::<Vec<_>>();
            if !rows.is_empty() {
                break rows;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0]["agent"], "alice");
    assert_eq!(egress[0]["host"], "127.0.0.1");
    assert_eq!(egress[0]["port"], origin_port);
    assert_eq!(egress[0]["route"], "parent");
    assert!(passthrough_events(&config).is_empty());

    if let Ok(path) = std::env::var("SAFEYOLO_PARENT_PARITY_EVIDENCE") {
        let witness = json!({
            "logical_authority": authority,
            "origin_port": origin_port,
            "parent_listener": parent_address.to_string(),
            "parent_peer": parent_peer.to_string(),
            "parent_connect": String::from_utf8_lossy(&parent_head),
            "parent_payload": String::from_utf8_lossy(&parent_payload),
            "origin_accepts": origin_contacts.load(Ordering::SeqCst),
            "proxy_egress": egress[0],
            "passthrough_events": passthrough_events(&config),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&witness).unwrap()).unwrap();
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn opaque_disconnect_and_shutdown_release_the_destination() {
    for shutdown in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory);
        let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"server-first").await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let mut client = connect_raw(&config.listeners[0].socket_path, &authority).await;
        client.read_exact(&mut [0; 12]).await.unwrap();
        if shutdown {
            tokio::time::timeout(Duration::from_secs(2), proxy.shutdown())
                .await
                .unwrap();
            assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        } else {
            drop(client);
            tokio::time::timeout(Duration::from_secs(2), origin)
                .await
                .unwrap()
                .unwrap();
            proxy.shutdown().await;
            continue;
        }
        tokio::time::timeout(Duration::from_secs(2), origin)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn fragmented_plaintext_connect_keeps_inner_policy_and_reuses_admitted_socket() {
    for (method, first) in ["GET", "SSH", "SSHGET", "SSH-EXT", "SSH-2.0-test"]
        .into_iter()
        .flat_map(|method| [1, 2, 3, 16].map(|first| (method, first)))
    {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory);
        let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert!(
                bytes.is_empty(),
                "denied inner HTTP reached the destination"
            );
        });
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let mut client = connect_raw(&config.listeners[0].socket_path, &authority).await;
        let request = format!(
            "{method} /deny-inner HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        client
            .write_all(&request.as_bytes()[..first])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        client
            .write_all(&request.as_bytes()[first..])
            .await
            .unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        assert_eq!(
            policy
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request["method"] == method)
                .count(),
            1
        );
        tokio::time::timeout(Duration::from_secs(2), origin)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            events(&config)
                .iter()
                .filter(|event| event["event"] == "proxy.egress")
                .count(),
            1
        );
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn exact_passthrough_keeps_origin_tls_and_reload_restores_interception() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy_ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let origin_ca = cert.der().clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = format!("localhost:{port}");
    let adjacent_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let adjacent_authority = format!(
        "localhost:{}",
        adjacent_listener.local_addr().unwrap().port()
    );
    config.ignore_hosts = vec![authority.clone()];
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_ca.clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let exact_request =
        format!("GET /deny-inner HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    let expected_request = exact_request.clone();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        assert_eq!(head, expected_request.as_bytes());
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    });
    let adjacent_origin = tokio::spawn(async move {
        let (mut socket, _) = adjacent_listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(
            bytes.is_empty(),
            "intercepted control leaked inner bytes: {bytes:?}"
        );
    });
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let mut client = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        origin_ca.clone(),
    )
    .await
    .unwrap();
    client.write_all(exact_request.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    client.read_to_end(&mut received).await.unwrap();
    assert!(received.ends_with(b"origin"));
    assert_eq!(
        client
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap()
            .as_ref(),
        origin_ca.as_ref()
    );
    drop(client);
    let lifecycle = wait_passthrough_events(&config, 2).await;
    assert_eq!(lifecycle[0]["event"], "traffic.passthrough_start");
    assert_eq!(lifecycle[1]["event"], "traffic.passthrough_end");
    assert_eq!(lifecycle[0]["host"], "localhost");
    assert_eq!(lifecycle[0]["details"]["port"], port);
    assert!(
        policy
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request["method"] == "CONNECT")
    );
    let mut adjacent = connect_tls(
        &config.listeners[0].socket_path,
        &adjacent_authority,
        "localhost",
        proxy_ca.clone(),
    )
    .await
    .unwrap();
    assert_ne!(
        adjacent
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap()
            .as_ref(),
        origin_ca.as_ref()
    );
    adjacent
        .write_all(
            format!(
                "GET /deny-inner HTTP/1.1\r\nHost: {adjacent_authority}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut adjacent_received = Vec::new();
    adjacent.read_to_end(&mut adjacent_received).await.unwrap();
    assert!(adjacent_received.starts_with(b"HTTP/1.1 403"));
    drop(adjacent);
    tokio::time::timeout(Duration::from_secs(2), adjacent_origin)
        .await
        .unwrap()
        .unwrap();
    config.ignore_hosts.clear();
    proxy.reload(config.clone()).await.unwrap();
    let mut client = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        proxy_ca,
    )
    .await
    .unwrap();
    client.write_all(exact_request.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    let _ = client.read_to_end(&mut received).await;
    assert!(received.starts_with(b"HTTP/1.1 403"));
    tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(passthrough_events(&config), lifecycle);
    proxy.shutdown().await;
}

#[tokio::test]
async fn unconfigured_tls_interception_failure_never_uses_configured_passthrough() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy_ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let origin_certificate = cert.der().clone();

    let configured_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let configured_port = configured_listener.local_addr().unwrap().port();
    let configured_authority = format!("localhost:{configured_port}");
    // The supported configuration boundary keeps the explicit port: this is
    // the admitted opaque control, while the next loopback port stays
    // inspected even though it has the same logical hostname.
    config.ignore_hosts = vec![configured_authority.clone()];
    let intercepted_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let intercepted_port = intercepted_listener.local_addr().unwrap().port();
    let intercepted_authority = format!("localhost:{intercepted_port}");

    let origin_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_certificate.clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let configured_request = format!(
        "GET /configured-opaque HTTP/1.1\r\nHost: {configured_authority}\r\nConnection: close\r\n\r\n"
    );
    let expected_configured_request = configured_request.clone();
    let configured_origin = tokio::spawn(async move {
        let (socket, peer) = configured_listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(origin_tls))
            .accept(socket)
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        assert_eq!(request, expected_configured_request.as_bytes());
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nconfigured",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        (peer, request)
    });
    // Both unconfigured attempts reach this controlled origin because CONNECT
    // opens its admitted destination before TLS classification. Neither may
    // deliver client handshake or application bytes to it.
    let intercepted_origin = tokio::spawn(async move {
        let mut observations = Vec::new();
        for _ in 0..2 {
            let (mut socket, peer) = intercepted_listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            observations.push((peer, bytes));
        }
        observations
    });

    let proxy = Proxy::start(config.clone()).await.unwrap();

    let mut configured = connect_tls(
        &config.listeners[0].socket_path,
        &configured_authority,
        "localhost",
        origin_certificate.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        configured
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap()
            .as_ref(),
        origin_certificate.as_ref(),
        "the exact configured port must retain the origin TLS certificate"
    );
    configured
        .write_all(configured_request.as_bytes())
        .await
        .unwrap();
    let mut configured_response = Vec::new();
    configured
        .read_to_end(&mut configured_response)
        .await
        .unwrap();
    assert!(configured_response.ends_with(b"configured"));
    drop(configured);

    // This neighboring endpoint uses the proxy trust root and proves that a
    // normal unconfigured TLS connection remains intercepted before the
    // deliberately failing client follows it.
    let mut intercepted = connect_tls(
        &config.listeners[0].socket_path,
        &intercepted_authority,
        "localhost",
        proxy_ca.clone(),
    )
    .await
    .unwrap();
    let proxy_certificate = intercepted
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .first()
        .unwrap()
        .clone();
    assert_ne!(
        proxy_certificate.as_ref(),
        origin_certificate.as_ref(),
        "the unconfigured port must receive a proxy certificate"
    );
    intercepted
        .write_all(
            format!(
                "GET /deny-inner HTTP/1.1\r\nHost: {intercepted_authority}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut denied = Vec::new();
    intercepted.read_to_end(&mut denied).await.unwrap();
    assert!(denied.starts_with(b"HTTP/1.1 403"));
    drop(intercepted);

    // Trusting the unrelated configured-origin certificate forces the client
    // to reject the proxy-issued leaf. A TLS failure on this unconfigured
    // endpoint must close rather than turn the pre-opened socket into opaque
    // forwarding.
    let client_error = match connect_tls(
        &config.listeners[0].socket_path,
        &intercepted_authority,
        "localhost",
        origin_certificate.clone(),
    )
    .await
    {
        Ok(_) => panic!("unconfigured TLS interception unexpectedly succeeded"),
        Err(error) => error.to_string(),
    };
    assert!(
        client_error.contains("invalid peer certificate"),
        "expected a client certificate-verification failure, got {client_error}"
    );

    let (configured_peer, configured_bytes) =
        tokio::time::timeout(Duration::from_secs(2), configured_origin)
            .await
            .unwrap()
            .unwrap();
    assert!(configured_peer.ip().is_loopback());
    assert_eq!(configured_bytes, configured_request.as_bytes());
    let intercepted_observations = tokio::time::timeout(Duration::from_secs(2), intercepted_origin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intercepted_observations.len(), 2);
    assert!(
        intercepted_observations
            .iter()
            .all(|(peer, bytes)| { peer.ip().is_loopback() && bytes.is_empty() })
    );

    let lifecycle = wait_passthrough_events(&config, 2).await;
    assert_eq!(
        lifecycle
            .iter()
            .map(|event| event["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["traffic.passthrough_start", "traffic.passthrough_end"]
    );
    assert!(lifecycle.iter().all(|event| {
        event["host"] == "localhost"
            && event["details"]["port"] == configured_port
            && event["event"] != "traffic.passthrough_error"
    }));
    let egress = events(&config)
        .into_iter()
        .filter(|event| event["event"] == "proxy.egress")
        .collect::<Vec<_>>();
    assert_eq!(egress.len(), 3, "each CONNECT must retain its own dial");
    assert!(egress.iter().all(|event| event["route"] == "direct"));
    assert_eq!(
        egress
            .iter()
            .filter(|event| event["host"] == "localhost" && event["port"] == configured_port)
            .count(),
        1
    );
    assert_eq!(
        egress
            .iter()
            .filter(|event| { event["host"] == "localhost" && event["port"] == intercepted_port })
            .count(),
        2
    );
    let tunnel_events = events(&config)
        .into_iter()
        .filter(|event| event["event"] == "proxy.tunnel")
        .collect::<Vec<_>>();
    assert_eq!(tunnel_events.len(), 1);
    assert_eq!(tunnel_events[0]["coverage"], "configured_passthrough");
    assert_eq!(tunnel_events[0]["host"], "localhost");
    assert_eq!(tunnel_events[0]["port"], configured_port);

    if let Some(path) = std::env::var_os("SAFEYOLO_631_EVIDENCE_DIR") {
        let path = Path::new(&path);
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(
            path.join("invalid-interception.json"),
            serde_json::to_vec_pretty(&json!({
                "candidate": std::env::var("SAFEYOLO_CANDIDATE_COMMIT")
                    .unwrap_or_else(|_| "unrecorded-test-binary".into()),
                "test": "unconfigured_tls_interception_failure_never_uses_configured_passthrough",
                "config_sha256": sha256_bytes(&serde_json::to_vec(&config).unwrap()),
                "certificate_sha256": {
                    "configured_origin": sha256_bytes(origin_certificate.as_ref()),
                    "proxy_root": sha256_bytes(proxy_ca.as_ref()),
                    "observed_proxy_leaf": sha256_bytes(proxy_certificate.as_ref()),
                },
                "configured_passthrough": {
                    "authority": configured_authority,
                    "origin_peer": configured_peer.to_string(),
                    "origin_certificate_matches_client": true,
                    "origin_request": String::from_utf8_lossy(&configured_bytes),
                },
                "unconfigured_interception": {
                    "authority": intercepted_authority,
                    "accepted_connections": intercepted_observations.len(),
                    "origin_received_byte_counts": intercepted_observations
                        .iter()
                        .map(|(_, bytes)| bytes.len())
                        .collect::<Vec<_>>(),
                    "intercepted_control_status": String::from_utf8_lossy(
                        &denied[..denied.iter().position(|byte| *byte == b'\r').unwrap_or(0)]
                    ),
                    "client_handshake": "failed against the untrusted proxy leaf",
                    "client_error": client_error,
                },
                "proxy_egress": egress,
                "proxy_tunnel": tunnel_events,
                "passthrough_events": lifecycle,
                "limits": [
                    "One direct loopback hostname with one exact configured port and one same-host, different-port control.",
                    "The failed interception is a client rejection of the proxy certificate; this does not prove every malformed TLS record or upstream-verification failure.",
                    "Parent routes, aliases, reserved-name containment, and the remaining D29 matrix remain outside this witness."
                ],
            }))
            .unwrap(),
        )
        .unwrap();
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn configured_sni_alias_passthrough_keeps_origin_tls_and_intercepts_neighbor() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy_ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["sni.alias.invalid".into()]).unwrap();
    let origin_ca = cert.der().clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = format!("localhost:{port}");
    let alias = format!("sni.alias.invalid:{port}");
    config.ignore_hosts = vec![alias.clone()];
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_ca.clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let expected_request =
        format!("GET /sni-alias HTTP/1.1\r\nHost: {alias}\r\nConnection: close\r\n\r\n");
    let origin_expected_request = expected_request.clone();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut record_header = [0_u8; 5];
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if socket.peek(&mut record_header).await.unwrap() == record_header.len() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(record_header[0], 0x16, "SNI control did not send TLS");
        let record_length = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        let mut initial_record = vec![0_u8; record_header.len() + record_length];
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if socket.peek(&mut initial_record).await.unwrap() == initial_record.len() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        assert_eq!(request, origin_expected_request.as_bytes());
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nalias")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();

        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        match tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes)).await {
            Ok(Ok(_)) | Err(_) => {}
            Ok(Err(error)) => panic!("intercepted neighbor origin read failed: {error}"),
        }
        assert!(
            bytes.is_empty(),
            "intercepted neighbor leaked bytes: {bytes:?}"
        );
        (initial_record, request)
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();

    let mut passthrough = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "sni.alias.invalid",
        origin_ca.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        passthrough
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap()
            .as_ref(),
        origin_ca.as_ref(),
        "configured SNI alias must receive the origin certificate"
    );
    passthrough
        .write_all(expected_request.as_bytes())
        .await
        .unwrap();
    let mut received = Vec::new();
    passthrough.read_to_end(&mut received).await.unwrap();
    assert!(received.ends_with(b"alias"));
    drop(passthrough);

    let mut intercepted = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        proxy_ca.clone(),
    )
    .await
    .unwrap();
    assert_ne!(
        intercepted
            .get_ref()
            .1
            .peer_certificates()
            .unwrap()
            .first()
            .unwrap()
            .as_ref(),
        origin_ca.as_ref(),
        "neighboring unconfigured SNI must receive the proxy certificate"
    );
    intercepted
        .write_all(
            format!("GET /deny-inner HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut denied = Vec::new();
    intercepted.read_to_end(&mut denied).await.unwrap();
    assert!(denied.starts_with(b"HTTP/1.1 403"));
    drop(intercepted);

    let (initial_record, request) = tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();
    let lifecycle = wait_passthrough_events(&config, 2).await;
    assert_eq!(lifecycle[0]["event"], "traffic.passthrough_start");
    assert_eq!(lifecycle[1]["event"], "traffic.passthrough_end");
    assert_eq!(lifecycle[0]["host"], "sni.alias.invalid");
    assert_eq!(lifecycle[0]["details"]["port"], port);
    assert!(passthrough_events(&config).iter().all(|event| {
        event["host"] == "sni.alias.invalid" && event["addon"] == "ignored-host-logger"
    }));
    let policy_requests = policy.requests.lock().unwrap().clone();
    assert!(
        policy_requests
            .iter()
            .any(|request| request["method"] == "CONNECT")
    );

    if let Some(path) = std::env::var_os("SAFEYOLO_631_EVIDENCE_DIR") {
        let path = Path::new(&path);
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(
            path.join("sni-alias.json"),
            serde_json::to_vec_pretty(&json!({
                "candidate": std::env::var("SAFEYOLO_CANDIDATE_COMMIT")
                    .unwrap_or_else(|_| "unrecorded-test-binary".into()),
                "configured_alias": alias,
                "connect_authority": authority,
                "sni": "sni.alias.invalid",
                "initial_tls_record_hex": hex_bytes(&initial_record),
                "origin_request": String::from_utf8_lossy(&request),
                "origin_certificate_matches": true,
                "intercepted_neighbor": {
                    "sni": "localhost",
                    "certificate_is_origin": false,
                    "status": String::from_utf8_lossy(&denied[..denied.iter().position(|byte| *byte == b'\r').unwrap_or(0)]),
                    "origin_bytes": 0,
                },
                "passthrough_events": passthrough_events(&config),
                "policy_requests": policy_requests,
                "limits": [
                    "One direct native TLS connection matched by configured SNI alias and one neighboring intercepted connection.",
                    "The protected-admin and parent-route controls remain inherited from accepted #631 evidence; this slice does not broaden either scope.",
                    "No IPv6, parent, invalid-interception or long-duration claim is made."
                ]
            }))
            .unwrap(),
        )
        .unwrap();
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn configured_inner_host_alias_cannot_expand_admitted_destination() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy_ca = interception_ca(&directory, &mut config);

    let alias_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = alias_listener.local_addr().unwrap().port();
    let authority = format!("localhost:{port}");
    let inner_alias = format!("inner.alias.invalid:{port}");
    config.ignore_hosts = vec![inner_alias.clone()];
    let alias_request = format!(
        "GET /inner-host-alias HTTP/1.1\r\nHost: {inner_alias}\r\nConnection: close\r\n\r\n"
    );
    let neighbor_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let neighbor_authority = format!(
        "localhost:{}",
        neighbor_listener.local_addr().unwrap().port()
    );
    let rcgen::CertifiedKey {
        cert: origin_cert,
        signing_key: origin_signing_key,
    } = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let upstream_ca = directory.path().join("inner-host-upstream.pem");
    std::fs::write(&upstream_ca, origin_cert.pem()).unwrap();
    config.upstream_ca_file = Some(upstream_ca);
    let origin_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(origin_signing_key.serialize_der()).into(),
    )
    .unwrap();
    let origin_certificate = origin_cert.der().clone();
    let neighbor_request = format!(
        "GET /inner-host-neighbor HTTP/1.1\r\nHost: {neighbor_authority}\r\nConnection: close\r\n\r\n"
    );
    let expected_neighbor_origin_request = format!(
        "GET /inner-host-neighbor HTTP/1.1\r\nHost: {neighbor_authority}\r\nvia: 1.1 test-instance\r\n\r\n"
    );
    let expected_neighbor_response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nneighbor".to_vec();
    let origin_neighbor_response = expected_neighbor_response.clone();
    let alias_origin = tokio::spawn(async move {
        let (mut socket, _) = alias_listener.accept().await.unwrap();
        let mut alias_bytes = Vec::new();
        socket.read_to_end(&mut alias_bytes).await.unwrap();
        assert!(
            alias_bytes.is_empty(),
            "mismatched inner Host must not send application bytes to origin"
        );
        alias_bytes
    });
    let neighbor_origin = tokio::spawn(async move {
        let (socket, _) = neighbor_listener.accept().await.unwrap();
        let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(origin_tls))
            .accept(socket)
            .await
            .unwrap();
        let mut neighbor_bytes = Vec::new();
        while !neighbor_bytes.ends_with(b"\r\n\r\n") {
            neighbor_bytes.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(&origin_neighbor_response).await.unwrap();
        socket.shutdown().await.unwrap();
        neighbor_bytes
    });

    let proxy = Proxy::start(config.clone()).await.unwrap();
    let proxy_ca_subject = x509_parser::parse_x509_certificate(proxy_ca.as_ref())
        .unwrap()
        .1
        .subject()
        .to_string();
    let mut alias_client = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        proxy_ca.clone(),
    )
    .await
    .unwrap();
    let alias_certificate = alias_client
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .first()
        .unwrap()
        .as_ref()
        .to_vec();
    alias_client
        .write_all(alias_request.as_bytes())
        .await
        .unwrap();
    let mut alias_response = Vec::new();
    alias_client.read_to_end(&mut alias_response).await.unwrap();
    assert!(alias_response.starts_with(b"HTTP/1.1 400"));
    drop(alias_client);

    let mut neighbor_client = connect_tls(
        &config.listeners[0].socket_path,
        &neighbor_authority,
        "localhost",
        proxy_ca,
    )
    .await
    .unwrap();
    let neighbor_certificate = neighbor_client
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .first()
        .unwrap()
        .as_ref()
        .to_vec();
    assert!(!alias_certificate.is_empty());
    assert!(!neighbor_certificate.is_empty());
    for certificate in [&alias_certificate, &neighbor_certificate] {
        let (_, certificate) = x509_parser::parse_x509_certificate(certificate).unwrap();
        assert_eq!(
            certificate.issuer().to_string(),
            proxy_ca_subject,
            "intercepted TLS must receive a leaf issued by the configured proxy CA"
        );
    }
    neighbor_client
        .write_all(neighbor_request.as_bytes())
        .await
        .unwrap();
    let mut neighbor_response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        neighbor_client.read_to_end(&mut neighbor_response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(neighbor_response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(neighbor_response.ends_with(b"\r\nneighbor"));
    drop(neighbor_client);
    let alias_origin_bytes = alias_origin.await.unwrap();
    let neighbor_origin_bytes = neighbor_origin.await.unwrap();
    assert_eq!(
        neighbor_origin_bytes,
        expected_neighbor_origin_request.as_bytes(),
        "intercepted neighbor changed the origin request bytes"
    );

    let passthrough = passthrough_events(&config);
    assert!(
        passthrough.is_empty(),
        "inner Host must not create an opaque passthrough lifecycle: {passthrough:?}"
    );
    if let Some(path) = std::env::var_os("SAFEYOLO_631_EVIDENCE_DIR") {
        let path = Path::new(&path);
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(
            path.join("inner-host-alias.json"),
            serde_json::to_vec_pretty(&json!({
                "candidate": std::env::var("SAFEYOLO_CANDIDATE_COMMIT")
                    .unwrap_or_else(|_| "unrecorded-test-binary".into()),
                "configured_alias": inner_alias,
                "connect_authority": authority,
                "neighbor_authority": neighbor_authority,
                "client_sni": "localhost",
                "alias": {
                    "inner_request": String::from_utf8_lossy(alias_request.as_bytes()),
                    "response": String::from_utf8_lossy(&alias_response),
                    "proxy_certificate_der_hex": hex_bytes(&alias_certificate),
                    "proxy_certificate_issuer": x509_parser::parse_x509_certificate(&alias_certificate).unwrap().1.issuer().to_string(),
                    "origin_application_bytes": alias_origin_bytes.len(),
                },
                "intercepted_neighbor": {
                    "inner_request": String::from_utf8_lossy(neighbor_request.as_bytes()),
                    "origin_request": String::from_utf8_lossy(&neighbor_origin_bytes),
                    "response": String::from_utf8_lossy(&neighbor_response),
                    "origin_certificate_der_hex": hex_bytes(origin_certificate.as_ref()),
                    "proxy_certificate_der_hex": hex_bytes(&neighbor_certificate),
                    "proxy_certificate_issuer": x509_parser::parse_x509_certificate(&neighbor_certificate).unwrap().1.issuer().to_string(),
                    "origin_application_bytes": neighbor_origin_bytes.len(),
                },
                "passthrough_events": passthrough,
                "limits": [
                    "The configured entry is consulted only for the admitted CONNECT destination and captured SNI; a decrypted inner Host cannot switch this connection to opaque forwarding.",
                    "The neighboring request proves the same SNI remains intercepted and can deliver only its admitted-authority request bytes after policy.",
                    "It does not implement inner-Host alias passthrough or claim parent-route parity.",
                ]
            }))
            .unwrap(),
        )
        .unwrap();
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn host_and_address_passthrough_preserve_bytes_and_canonical_events() {
    for entry in ["localhost", "127.0.0.1"] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(&directory);
        config.ignore_hosts = vec![entry.into()];
        let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let authority = format!("{entry}:{port}");
        let expected = b"\x16\x03\x03\x00\x0eopaque-initial".to_vec();
        let origin_expected = expected.clone();
        let origin = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            socket.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, origin_expected);
        });
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let mut client = connect_raw(&config.listeners[0].socket_path, &authority).await;
        client.write_all(&expected).await.unwrap();
        client.shutdown().await.unwrap();
        origin.await.unwrap();
        drop(client);
        let lifecycle = wait_passthrough_events(&config, 2).await;
        assert_eq!(lifecycle[0]["event"], "traffic.passthrough_start");
        assert_eq!(lifecycle[1]["event"], "traffic.passthrough_end");
        assert_eq!(lifecycle[0]["host"], entry);
        assert_eq!(lifecycle[0]["details"]["port"], port);
        assert_eq!(lifecycle[0]["details"]["transport"], "tcp");
        assert_eq!(lifecycle[0]["details"]["client"], Value::Null);
        assert_eq!(lifecycle[1]["host"], entry);
        assert_eq!(lifecycle[1]["details"]["port"], port);
        assert!(lifecycle[1]["details"]["duration_ms"].is_u64());
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn admin_ignore_hosts_replaces_live_match_and_keeps_admitted_session() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let token = "transport-ignore-hosts-admin";
    let token_path = directory.path().join("admin-token");
    std::fs::write(&token_path, token).unwrap();
    config.admin_port = Some(0);
    config.admin_api_token_file = Some(token_path);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;

    // Before the live update, the same origin is inspected and the inner
    // policy denial reaches the client without bytes reaching the origin.
    let intercepted_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let intercepted_authority = intercepted_listener.local_addr().unwrap().to_string();
    let intercepted_origin = tokio::spawn(async move {
        let (mut stream, _) = intercepted_listener.accept().await.unwrap();
        let mut byte = [0; 1];
        match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte)).await {
            Ok(Ok(0)) | Err(_) => {}
            Ok(Ok(read)) => panic!("inspected denial reached origin: {read} bytes"),
            Ok(Err(error)) => panic!("origin read failed: {error}"),
        }
    });
    let mut intercepted =
        connect_raw(&config.listeners[0].socket_path, &intercepted_authority).await;
    intercepted
        .write_all(
            format!(
                "GET /deny-inner HTTP/1.1\r\nHost: {intercepted_authority}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let denial = read_proxy_headers(&mut intercepted).await;
    assert!(
        denial.starts_with(b"HTTP/1.1 403"),
        "unexpected inspected response: {:?}",
        String::from_utf8_lossy(&denial)
    );
    drop(intercepted);
    intercepted_origin.await.unwrap();

    // A real authenticated admin request changes the live matcher. An
    // admitted connection then keeps relaying even after the entry is removed.
    let (status, _) = admin_transport(
        admin_port,
        token,
        "PUT",
        "/admin/proxy/ignore-hosts",
        r#"{"hosts":["*.example.test"]}"#,
    )
    .await;
    assert_eq!(status, 400);
    let (status, body) = admin_transport(
        admin_port,
        token,
        "PUT",
        "/admin/proxy/ignore-hosts",
        &format!(r#"{{"hosts":["{intercepted_authority}"]}}"#),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["hosts"], json!([intercepted_authority]));
    assert_eq!(body["operator_entry_count"], 1);
    assert_eq!(body["pattern_count"], 2);

    let admitted_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admitted_authority = admitted_listener.local_addr().unwrap().to_string();
    let (host, port) = admitted_authority.rsplit_once(':').unwrap();
    let (admitted_payload, after_removal) = (b"first".as_slice(), b"second".as_slice());
    let admitted_origin = tokio::spawn(async move {
        let (mut stream, _) = admitted_listener.accept().await.unwrap();
        let mut bytes = vec![0; admitted_payload.len() + after_removal.len()];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"firstsecond");
    });
    let entry = format!("{host}:{port}");
    let (status, _) = admin_transport(
        admin_port,
        token,
        "PUT",
        "/admin/proxy/ignore-hosts",
        &format!(r#"{{"hosts":["{entry}"]}}"#),
    )
    .await;
    assert_eq!(status, 200);
    let mut admitted = connect_raw(&config.listeners[0].socket_path, &admitted_authority).await;
    admitted.write_all(admitted_payload).await.unwrap();
    tokio::task::yield_now().await;
    let (status, body) = admin_transport(
        admin_port,
        token,
        "PUT",
        "/admin/proxy/ignore-hosts",
        r#"{"hosts":[]}"#,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["operator_entry_count"], 0);
    assert_eq!(body["pattern_count"], 1);
    admitted.write_all(after_removal).await.unwrap();
    admitted.shutdown().await.unwrap();
    admitted_origin.await.unwrap();

    // New connections observe the removal and return to inspected handling.
    let removed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let removed_authority = removed_listener.local_addr().unwrap().to_string();
    let removed_origin = tokio::spawn(async move {
        let (mut stream, _) = removed_listener.accept().await.unwrap();
        let mut byte = [0; 1];
        match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte)).await {
            Ok(Ok(0)) | Err(_) => {}
            Ok(Ok(read)) => panic!("removed entry still relayed {read} byte(s)"),
            Ok(Err(error)) => panic!("origin read failed: {error}"),
        }
    });
    let mut removed = connect_raw(&config.listeners[0].socket_path, &removed_authority).await;
    removed
        .write_all(
            format!(
                "GET /deny-inner HTTP/1.1\r\nHost: {removed_authority}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let removed_denial = read_proxy_headers(&mut removed).await;
    assert!(removed_denial.starts_with(b"HTTP/1.1 403"));
    drop(removed);
    removed_origin.await.unwrap();
    assert!(
        std::fs::read_to_string(&config.audit_log_path.as_ref().unwrap())
            .unwrap()
            .contains("admin.proxy_ignore_hosts_update")
    );
    assert!(
        policy
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["path"] == "/deny-inner")
    );
    proxy.shutdown().await;
}

async fn admin_transport(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, Value) {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let split = bytes
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .unwrap();
    let status = std::str::from_utf8(&bytes[..split])
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = serde_json::from_slice(&bytes[split + 4..]).unwrap();
    (status, body)
}

async fn read_proxy_headers(stream: &mut UnixStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        head
    })
    .await
    .unwrap()
}

fn passthrough_events(config: &Config) -> Vec<Value> {
    let Some(path) = config.audit_log_path.as_ref() else {
        return Vec::new();
    };
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &Value| event["addon"] == "ignored-host-logger")
        .collect()
}

async fn wait_passthrough_events(config: &Config, count: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let events = passthrough_events(config);
            if events.len() == count {
                return events;
            }
            assert!(
                events.len() < count,
                "unexpected duplicate passthrough events: {events:?}"
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

fn events(config: &Config) -> Vec<Value> {
    std::fs::read_to_string(&config.event_log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

async fn origin() -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let contacts = Arc::new(AtomicUsize::new(0));
    let seen = contacts.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    bytes.push(socket.read_u8().await.unwrap());
                }
                let received = String::from_utf8(bytes).unwrap();
                assert!(!received.to_lowercase().contains("proxy-authorization:"));
                assert!(!received.to_lowercase().contains("x-safeyolo-request-id:"));
                assert!(!received.to_lowercase().contains("x-remove-me:"));
                assert!(received.to_lowercase().contains("via: 1.1 test-instance"));
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed",
                    )
                    .await
                    .unwrap();
            });
        }
    });
    (authority, contacts, task)
}

#[tokio::test]
async fn two_agents_cannot_spoof_identity_and_denied_requests_never_reach_egress() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let (authority, contacts, origin) = origin().await;
    let target = format!("http://{authority}/signed?a=1&a=2&value=%2F");
    let alice = request(&config.listeners[0].socket_path, &target,
        "X-SafeYolo-Agent: bob\r\nX-SafeYolo-Request-Id: forged\r\nProxy-Authorization: synthetic\r\n").await;
    let bob = request(
        &config.listeners[1].socket_path,
        &target,
        "X-SafeYolo-Agent: alice\r\n",
    )
    .await;
    assert!(alice.starts_with("HTTP/1.1 200"), "{alice}");
    assert!(bob.starts_with("HTTP/1.1 403"), "{bob}");
    assert_eq!(contacts.load(Ordering::SeqCst), 1);
    let denied = request(
        &config.listeners[1].socket_path,
        "http://must-not-resolve.invalid/",
        "",
    )
    .await;
    assert!(denied.starts_with("HTTP/1.1 403"));
    let recorded = events(&config);
    let egress: Vec<_> = recorded
        .iter()
        .filter(|event| event["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0]["agent"], "alice");
    let requests = policy.requests.lock().unwrap().clone();
    assert_eq!(requests[0]["agent_id"], "alice");
    assert_eq!(requests[1]["agent_id"], "bob");
    assert_ne!(requests[0]["connection_id"], requests[1]["connection_id"]);
    assert!(
        requests[0]["request_id"]
            .as_str()
            .unwrap()
            .starts_with("req-")
    );
    assert_eq!(requests[0]["path"], "/signed?a=1&a=2&value=%2F");
    assert!(requests[0].get("headers").is_none());
    drop(requests);
    proxy.shutdown().await;
    assert!(!config.readiness_file.exists());
    assert!(!config.listeners[0].socket_path.exists());
    origin.abort();
}

#[tokio::test]
async fn reserved_and_invalid_requests_stay_local_even_without_the_adapter() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(&directory);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    for target in [
        "http://_safeyolo.proxy.internal/not-an-api?token=synthetic",
        "http://_SAFEYOLO.PROBE.INTERNAL/",
        "https://_safeyolo.proxy.internal/",
    ] {
        assert!(
            request(
                &config.listeners[0].socket_path,
                target,
                "Authorization: Bearer synthetic\r\n"
            )
            .await
            .starts_with("HTTP/1.1 503")
        );
    }
    let connect = raw(&config.listeners[0].socket_path, "CONNECT _safeyolo.proxy.internal:443 HTTP/1.1\r\nHost: _safeyolo.proxy.internal:443\r\nConnection: close\r\n\r\n").await;
    assert!(connect.starts_with("HTTP/1.1 403"));
    let invalid = raw(
        &config.listeners[0].socket_path,
        "GET / HTTP/1.1\r\nHost: _safeyolo.proxy.internal:99999\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(invalid.starts_with("HTTP/1.1 400"));
    assert!(
        events(&config)
            .iter()
            .all(|event| event["event"] != "proxy.egress")
    );
    assert!(
        !std::fs::read_to_string(&config.event_log)
            .unwrap()
            .contains("synthetic")
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn configured_parent_receives_absolute_target_without_origin_dns() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.parent_proxy = Some(format!("http://{}", parent.local_addr().unwrap()));
    let parent_task = tokio::spawn(async move {
        let (mut socket, _) = parent.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(socket.read_u8().await.unwrap());
        }
        let request = String::from_utf8(bytes).unwrap();
        assert!(
            request.starts_with("GET http://origin.invalid:8181/x?key=a&key=b HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("host: origin.invalid:8181\r\n")
        );
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nparent")
            .await
            .unwrap();
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let reply = request(
        &config.listeners[0].socket_path,
        "http://origin.invalid:8181/x?key=a&key=b",
        "",
    )
    .await;
    assert!(reply.ends_with("parent"), "{reply}");
    let looped = request(
        &config.listeners[0].socket_path,
        "http://origin.invalid/",
        "Via: 1.1 test-instance\r\n",
    )
    .await;
    assert!(looped.starts_with("HTTP/1.1 508"));
    assert_eq!(
        events(&config)
            .iter()
            .filter(|event| event["event"] == "proxy.egress")
            .count(),
        1
    );
    parent_task.await.unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn reserved_root_dot_aliases_never_expose_tokens_to_a_parent() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let (parent_address, accepted, parent_task) = origin().await;
    config.parent_proxy = Some(format!("http://{parent_address}"));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    for host in ["_safeyolo.proxy.internal.", "_SAFEYOLO.PROBE.INTERNAL."] {
        let result = request(
            &config.listeners[0].socket_path,
            &format!("http://{host}/secret?key=synthetic"),
            "Authorization: Bearer synthetic-local-secret\r\n",
        )
        .await;
        assert!(result.starts_with("HTTP/1.1 503"), "{result}");
        let mut invalid_parent = config.clone();
        invalid_parent.parent_proxy = Some(format!("http://{host}:8080"));
        assert!(invalid_parent.validate().is_err());
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(policy.requests.lock().unwrap().is_empty());
    assert!(
        events(&config)
            .iter()
            .all(|event| event["event"] != "proxy.egress")
    );
    assert!(
        !std::fs::read_to_string(&config.event_log)
            .unwrap()
            .contains("synthetic-local-secret")
    );
    proxy.shutdown().await;
    parent_task.abort();
}

#[tokio::test]
async fn duplicate_host_headers_are_rejected_before_policy_or_parent_contact() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let (parent_address, accepted, parent_task) = origin().await;
    config.parent_proxy = Some(format!("http://{parent_address}"));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    for target in ["/", "http://allowed.invalid/"] {
        let result = raw(
            &config.listeners[0].socket_path,
            &format!("GET {target} HTTP/1.1\r\nHost: allowed.invalid\r\nHost: other.invalid\r\nConnection: close\r\n\r\n"),
        ).await;
        assert!(result.starts_with("HTTP/1.1 400"), "{result}");
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(policy.requests.lock().unwrap().is_empty());
    assert!(
        events(&config)
            .iter()
            .all(|event| event["event"] != "proxy.egress")
    );
    proxy.shutdown().await;
    parent_task.abort();
}

#[tokio::test]
async fn reload_adds_removes_and_reassigns_listeners_without_changing_inflight_identity() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let (authority, contacts, origin) = origin().await;
    let alice_path = config.listeners[0].socket_path.clone();
    let target = format!("http://{authority}/wait");
    let pending_path = alice_path.clone();
    let pending = tokio::spawn(async move { request(&pending_path, &target, "").await });
    tokio::time::timeout(Duration::from_secs(5), policy.waiting.notified())
        .await
        .unwrap();
    config.listeners = vec![
        AgentListener {
            agent_id: "bob".into(),
            socket_path: alice_path.clone(),
            source_id: None,
        },
        AgentListener {
            agent_id: "alice".into(),
            socket_path: directory.path().join("new-alice.sock"),
            source_id: None,
        },
    ];
    proxy.reload(config.clone()).await.unwrap();
    policy.release.notify_one();
    assert!(pending.await.unwrap().starts_with("HTTP/1.1 200"));
    let bob = request(&alice_path, &format!("http://{authority}/"), "").await;
    assert!(bob.starts_with("HTTP/1.1 403"));
    let alice = request(
        &config.listeners[1].socket_path,
        &format!("http://{authority}/"),
        "",
    )
    .await;
    assert!(alice.starts_with("HTTP/1.1 200"));
    assert!(
        UnixStream::connect(directory.path().join("bob.sock"))
            .await
            .is_err()
    );
    assert_eq!(contacts.load(Ordering::SeqCst), 2);
    assert_eq!(policy.requests.lock().unwrap()[0]["agent_id"], "alice");
    proxy.shutdown().await;
    origin.abort();
}

#[tokio::test]
async fn upstream_response_streams_early_and_disconnect_closes_the_upstream() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\nD\r\ndata: first\n\n\r\n").await.unwrap();
        // No terminal chunk is sent. The next observation must be client cancellation.
        let mut byte = [0u8];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), socket.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let mut stream = UnixStream::connect(&config.listeners[0].socket_path)
        .await
        .unwrap();
    stream
        .write_all(format!("GET http://{authority}/ HTTP/1.1\r\nHost: ignored\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !String::from_utf8_lossy(&received).contains("data: first\n\n") {
            received.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .expect("SSE first chunk must arrive before upstream completion");
    drop(stream);
    origin_task.await.unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn failed_start_preserves_existing_files_and_live_sockets() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(&directory);
    std::fs::write(&config.listeners[1].socket_path, "operator file").unwrap();
    assert!(Proxy::start(config.clone()).await.is_err());
    assert_eq!(
        std::fs::read_to_string(&config.listeners[1].socket_path).unwrap(),
        "operator file"
    );
    assert!(!config.listeners[0].socket_path.exists());
    assert!(!config.readiness_file.exists());
    std::fs::remove_file(&config.listeners[1].socket_path).unwrap();
    let live = Proxy::start(config.clone()).await.unwrap();
    let marker = std::fs::read(&config.readiness_file).unwrap();
    assert!(Proxy::start(config.clone()).await.is_err());
    assert!(config.listeners[0].socket_path.exists());
    assert_eq!(std::fs::read(&config.readiness_file).unwrap(), marker);
    live.shutdown().await;
}

async fn https_parent_case(certificate_host: &str, trust_certificate: bool, expected_status: u16) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![certificate_host.to_owned()]).unwrap();
    if trust_certificate {
        let ca = directory.path().join("parent-ca.pem");
        std::fs::write(&ca, cert.pem()).unwrap();
        config.upstream_ca_file = Some(ca);
    }
    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.parent_proxy = Some(format!(
        "https://localhost:{}",
        parent.local_addr().unwrap().port()
    ));
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let parent_task = tokio::spawn(async move {
        let (socket, _) = parent.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await;
        if expected_status != 200 {
            assert!(tls.is_err());
            return;
        }
        let mut socket = tls.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(socket.read_u8().await.unwrap());
        }
        assert!(bytes.starts_with(b"GET http://origin.invalid/path HTTP/1.1\r\n"));
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ntls-parent",
            )
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let reply = request(
        &config.listeners[0].socket_path,
        "http://origin.invalid/path",
        "",
    )
    .await;
    assert!(
        reply.starts_with(&format!("HTTP/1.1 {expected_status}")),
        "{reply}"
    );
    parent_task.await.unwrap();
    let recorded = events(&config);
    let egress: Vec<_> = recorded
        .iter()
        .filter(|event| event["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), 1, "TLS failure must not retry directly");
    assert_eq!(egress[0]["route"], "parent");
    proxy.shutdown().await;
}

#[tokio::test]
async fn https_parent_uses_configured_ca_and_verifies_hostname() {
    https_parent_case("localhost", true, 200).await;
    https_parent_case("wrong.invalid", true, 502).await;
    https_parent_case("localhost", false, 502).await;
}

fn interception_ca(
    directory: &TempDir,
    config: &mut Config,
) -> rustls::pki_types::CertificateDer<'static> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&key).unwrap();
    let path = directory.path().join("mitmproxy-ca.pem");
    std::fs::write(&path, format!("{}{}", key.serialize_pem(), ca.pem())).unwrap();
    config.tls_ca_file = Some(path);
    ca.der().clone()
}

async fn connect_tls(
    socket: &Path,
    authority: &str,
    sni: &str,
    ca: rustls::pki_types::CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<UnixStream>, safeyolo_proxy::Error> {
    connect_tls_with_alpn(socket, authority, sni, ca, &[]).await
}

async fn connect_tls_with_alpn(
    socket: &Path,
    authority: &str,
    sni: &str,
    ca: rustls::pki_types::CertificateDer<'static>,
    protocols: &[&[u8]],
) -> Result<tokio_rustls::client::TlsStream<UnixStream>, safeyolo_proxy::Error> {
    let mut socket = UnixStream::connect(socket).await?;
    socket
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        response.push(socket.read_u8().await?);
    }
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca)?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from(sni.to_owned())?,
            socket,
        )
        .await?)
}

fn h2_wire_frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        (payload.len() >> 16) as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
        kind,
        flags,
        (stream_id >> 24) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
    ];
    frame.extend_from_slice(payload);
    frame
}

async fn read_h2_wire<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await.unwrap();
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    (header[3], header[4], stream_id, payload)
}

async fn raw_h2_origin(
    listener: TcpListener,
    tls: rustls::ServerConfig,
    partial_reset: bool,
    release: oneshot::Receiver<()>,
) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
        .accept(socket)
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let mut preface = [0_u8; 24];
    stream.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    stream
        .write_all(&h2_wire_frame(4, 0, 0, &[]))
        .await
        .unwrap();
    loop {
        let (kind, flags, _, _) = read_h2_wire(&mut stream).await;
        if kind == 4 && flags == 0 {
            stream
                .write_all(&h2_wire_frame(4, 1, 0, &[]))
                .await
                .unwrap();
        }
        if kind == 1 {
            break;
        }
    }
    // Frozen D54 response head and body prefix: status 503 followed by DATA
    // and either END_STREAM or RST_STREAM(NO_ERROR).
    stream
        .write_all(&h2_wire_frame(1, 4, 1, b"\x08\x03\x35\x30\x33"))
        .await
        .unwrap();
    stream
        .write_all(&h2_wire_frame(0, u8::from(!partial_reset), 1, b"body"))
        .await
        .unwrap();
    if partial_reset {
        // The test releases this peer only after the downstream client has
        // observed the 503 head and shared DATA prefix. This keeps the frozen
        // DATA and RST frames distinct without relying on flow-control timing.
        let _ = release.await;
        stream
            .write_all(&h2_wire_frame(3, 0, 1, &0_u32.to_be_bytes()))
            .await
            .unwrap();
    }
}

struct PausedBody {
    first: bool,
    finished: bool,
    release: tokio::sync::oneshot::Receiver<()>,
    dropped: Arc<Notify>,
}
impl hyper::body::Body for PausedBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        use std::{future::Future, task::Poll};
        let this = self.get_mut();
        if !this.first {
            this.first = true;
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                b"first",
            )))));
        }
        if this.finished {
            return Poll::Ready(None);
        }
        if std::pin::Pin::new(&mut this.release)
            .poll(context)
            .is_ready()
        {
            this.finished = true;
            Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                b"second",
            )))))
        } else {
            Poll::Pending
        }
    }
    fn is_end_stream(&self) -> bool {
        self.finished
    }
}
impl Drop for PausedBody {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}

async fn http2_stream_lifecycle(cancel_response: bool) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let path = directory.path().join("upstream.pem");
    std::fs::write(&path, cert.pem()).unwrap();
    config.upstream_ca_file = Some(path);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("localhost:{}", listener.local_addr().unwrap().port());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let (release, released) = tokio::sync::oneshot::channel();
    let released = Arc::new(Mutex::new(Some(released)));
    let dropped = Arc::new(Notify::new());
    let body_dropped = dropped.clone();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let socket = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(socket.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let service = service_fn(move |_: Request<Incoming>| {
            let body = PausedBody {
                first: false,
                finished: false,
                release: released.lock().unwrap().take().unwrap(),
                dropped: body_dropped.clone(),
            };
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("content-length", "11")
                        .body(body)
                        .unwrap(),
                )
            }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(socket), service)
            .await;
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let socket = connect_tls_with_alpn(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        ca,
        &[b"h2"],
    )
    .await
    .unwrap();
    assert_eq!(socket.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .unwrap();
    let client = tokio::spawn(connection);
    let mut response = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/stream"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let first = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), b"first".as_slice());
    if cancel_response {
        drop(response);
        tokio::time::timeout(Duration::from_secs(2), dropped.notified())
            .await
            .expect("reset client stream must drop the paused upstream body");
        assert!(
            release.send(()).is_err(),
            "canceled body still retained its receiver"
        );
        tokio::time::timeout(Duration::from_secs(2), proxy.shutdown())
            .await
            .unwrap();
    } else {
        let shutdown = tokio::spawn(proxy.shutdown());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !shutdown.is_finished(),
            "shutdown discarded an active H2 response"
        );
        release.send(()).unwrap();
        let body = tokio::time::timeout(Duration::from_secs(2), response.into_body().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        assert_eq!(body, b"second".as_slice());
        tokio::time::timeout(Duration::from_secs(2), shutdown)
            .await
            .unwrap()
            .unwrap();
    }
    drop(sender);
    client.abort();
    tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn http2_cancellation_releases_a_paused_upstream_stream() {
    http2_stream_lifecycle(true).await;
}

#[tokio::test]
async fn http2_shutdown_drains_a_paused_response() {
    http2_stream_lifecycle(false).await;
}

async fn full_proxy_h2_response_outcome(partial_reset: bool) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let proxy_ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let origin_cert = cert.der().clone();
    let ca_path = directory.path().join("upstream.pem");
    std::fs::write(&ca_path, cert.pem()).unwrap();
    config.upstream_ca_file = Some(ca_path);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("localhost:{}", listener.local_addr().unwrap().port());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_cert],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let (release, release_received) = oneshot::channel();
    let origin = tokio::spawn(raw_h2_origin(
        listener,
        tls,
        partial_reset,
        release_received,
    ));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let socket = connect_tls_with_alpn(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        proxy_ca,
        &[b"h2"],
    )
    .await
    .unwrap();
    assert_eq!(socket.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .unwrap();
    let client = tokio::spawn(connection);
    let mut response = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/d54"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let first = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), b"body".as_slice());
    if partial_reset {
        let _ = release.send(());
        let terminal = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
            .await
            .unwrap();
        assert!(
            matches!(terminal, Some(Err(_))),
            "reset must fail downstream"
        );
    } else {
        let terminal = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
            .await
            .unwrap();
        assert!(terminal.is_none(), "END_STREAM must remain clean");
        let _ = release.send(());
    }
    drop(response);
    drop(sender);
    client.abort();
    proxy.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn full_proxy_h2_partial_reset_fails_while_same_prefix_end_stream_is_clean() {
    full_proxy_h2_response_outcome(false).await;
    full_proxy_h2_response_outcome(true).await;
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn full_proxy_h2_terminal_evidence_case(partial_reset: bool) -> Value {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = directory.path().join("policy.toml");
    std::fs::write(
        &policy,
        "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"allow\"\n[addons.circuit_breaker]\nenabled = true\nfailure_threshold = 1\nexcluded_domains = []\n",
    )
    .unwrap();
    config.temporary_policy_socket = None;
    config.policy_file = Some(policy.clone());
    config.data_dir = Some(directory.path().join("data"));
    config.circuit_state_file = Some(directory.path().join("circuit-state.json"));
    let proxy_ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.2".into()]).unwrap();
    let origin_cert = cert.der().clone();
    let ca_path = directory.path().join("upstream.pem");
    std::fs::write(&ca_path, cert.pem()).unwrap();
    config.upstream_ca_file = Some(ca_path);
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let authority = format!("127.0.0.2:{}", listener.local_addr().unwrap().port());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_cert],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let (release, release_received) = oneshot::channel();
    let origin = tokio::spawn(raw_h2_origin(
        listener,
        tls,
        partial_reset,
        release_received,
    ));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let socket = connect_tls_with_alpn(
        &config.listeners[0].socket_path,
        &authority,
        "127.0.0.2",
        proxy_ca,
        &[b"h2"],
    )
    .await
    .unwrap();
    assert_eq!(socket.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .unwrap();
    let client = tokio::spawn(connection);
    let mut response = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/d54-correlated"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let request_id = response
        .headers()
        .get("x-safeyolo-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let first = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"body"));
    let _ = release.send(());
    let terminal = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .unwrap();
    let terminal_kind = if partial_reset {
        assert!(
            matches!(terminal, Some(Err(_))),
            "reset must fail downstream"
        );
        "reset_error"
    } else {
        assert!(terminal.is_none(), "END_STREAM must remain clean");
        "end_stream"
    };
    drop(response);
    drop(sender);
    client.abort();
    proxy.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();

    let recorded = events(&config);
    let request_events: Vec<_> = recorded
        .iter()
        .filter(|event| event["event"] == "proxy.request")
        .cloned()
        .collect();
    let terminal_requests: Vec<_> = request_events
        .iter()
        .filter(|event| event["request_id"] == request_id)
        .cloned()
        .collect();
    assert_eq!(terminal_requests.len(), 1);
    assert_eq!(terminal_requests[0]["status"], 503);
    assert_eq!(
        terminal_requests[0]["coverage"],
        "native_network_guard_circuits_and_test_context"
    );
    let circuit_events: Vec<_> = recorded
        .iter()
        .filter(|event| event["event"] == "proxy.circuit")
        .cloned()
        .collect();
    if partial_reset {
        assert!(
            circuit_events.is_empty(),
            "reset must not count: {circuit_events:?}"
        );
    } else {
        assert_eq!(circuit_events.len(), 1, "complete 503 must count once");
        assert_eq!(circuit_events[0]["host"], "127.0.0.2");
    }
    let state = config
        .circuit_state_file
        .as_ref()
        .filter(|path| path.exists())
        .map(|path| {
            serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()
        });
    let domain_state = state
        .as_ref()
        .and_then(|value| value["states"].get("127.0.0.2"));
    if partial_reset {
        assert!(
            domain_state.is_none(),
            "reset created circuit state: {domain_state:?}"
        );
    } else {
        assert_eq!(domain_state.unwrap()["failure_count"], 1);
    }
    let mut upstream_frames = vec![
        json!({
            "kind": "SETTINGS",
            "frame_hex": hex_bytes(&h2_wire_frame(4, 0, 0, &[])),
        }),
        json!({
            "kind": "SETTINGS_ACK",
            "frame_hex": hex_bytes(&h2_wire_frame(4, 1, 0, &[])),
        }),
        json!({
            "kind": "HEADERS",
            "flags": 4,
            "stream_id": 1,
            "payload_hex": hex_bytes(b"\x08\x03\x35\x30\x33"),
            "frame_hex": hex_bytes(&h2_wire_frame(1, 4, 1, b"\x08\x03\x35\x30\x33")),
        }),
        json!({
            "kind": "DATA",
            "flags": u8::from(!partial_reset),
            "stream_id": 1,
            "payload_hex": hex_bytes(b"body"),
            "frame_hex": hex_bytes(&h2_wire_frame(0, u8::from(!partial_reset), 1, b"body")),
        }),
    ];
    if partial_reset {
        upstream_frames.push(json!({
            "kind": "RST_STREAM",
            "flags": 0,
            "stream_id": 1,
            "error_code": 0,
            "frame_hex": hex_bytes(&h2_wire_frame(3, 0, 1, &0_u32.to_be_bytes())),
        }));
    }
    let evidence = json!({
        "backend": "rust",
        "authority": authority,
        "partial_reset": partial_reset,
        "downstream": {
            "status": 503,
            "body_prefix_hex": hex_bytes(b"body"),
            "terminal": terminal_kind,
            "request_id": request_id,
        },
        "upstream_frames": upstream_frames,
        "proxy_request_events": terminal_requests,
        "proxy_circuit_events": circuit_events,
        "circuit_state": state,
        "limits": [
            "One native TLS/ALPN h2 request per control, with the same 503 head and body prefix.",
            "This proves the reset-versus-END_STREAM terminal and circuit consequence in the full proxy; it does not compare a frozen pre-fix executable or cover concurrent/long-duration H2 traffic.",
        ],
    });
    if let Some(root) = std::env::var_os("SAFEYOLO_633_EVIDENCE_DIR") {
        let root = Path::new(&root);
        std::fs::create_dir_all(root).unwrap();
        let name = if partial_reset {
            "partial-reset"
        } else {
            "same-prefix-end-stream"
        };
        std::fs::write(
            root.join(format!("{name}.json")),
            format!("{}\n", serde_json::to_string_pretty(&evidence).unwrap()),
        )
        .unwrap();
    }
    evidence
}

#[tokio::test]
async fn full_proxy_h2_terminal_outcome_correlates_wire_terminal_and_circuit_state() {
    let clean = full_proxy_h2_terminal_evidence_case(false).await;
    let reset = full_proxy_h2_terminal_evidence_case(true).await;
    assert_eq!(clean["downstream"]["terminal"], "end_stream");
    assert_eq!(reset["downstream"]["terminal"], "reset_error");
    assert!(clean["proxy_circuit_events"].as_array().unwrap().len() == 1);
    assert!(reset["proxy_circuit_events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn intercepted_https_pins_authority_and_checks_inner_policy_before_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let ca = interception_ca(&directory, &mut config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = format!("localhost:{port}");
    let origin = tokio::spawn(async move {
        for _ in 0..7 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.unwrap();
            assert!(
                bytes.is_empty(),
                "inner denial or invalid authority sent origin bytes"
            );
        }
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    for (target, expected) in [
        ("GET /deny-inner HTTP/1.1\r\nHost: localhost:18443", 403),
        ("GET / HTTP/1.1\r\nHost: other.invalid:18443", 400),
        ("GET / HTTP/1.1\r\nHost: localhost:18444", 400),
        (
            "GET https://other.invalid:18443/ HTTP/1.1\r\nHost: localhost:18443",
            400,
        ),
        (
            "GET http://localhost:18443/ HTTP/1.1\r\nHost: localhost:18443",
            400,
        ),
        (
            "GET / HTTP/1.1\r\nHost: localhost:18443\r\nHost: localhost:18443",
            400,
        ),
    ] {
        let target = target
            .replace("18443", &port.to_string())
            .replace("18444", &((port % 65534) + 1).to_string());
        let socket = connect_tls(
            &config.listeners[0].socket_path,
            &authority,
            "localhost",
            ca.clone(),
        )
        .await
        .unwrap();
        let mut socket = socket;
        socket
            .write_all(format!("{target}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        let _ = socket.read_to_end(&mut bytes).await;
        assert!(
            bytes.starts_with(format!("HTTP/1.1 {expected}").as_bytes()),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
    assert!(
        connect_tls(
            &config.listeners[0].socket_path,
            &authority,
            "other.invalid",
            ca
        )
        .await
        .is_err()
    );
    let egress = events(&config)
        .into_iter()
        .filter(|event| event["event"] == "proxy.egress")
        .collect::<Vec<_>>();
    assert_eq!(egress.len(), 7);
    assert!(
        egress
            .iter()
            .all(|event| event["host"] == "localhost" && event["port"] == port)
    );
    tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();
    {
        let requests = policy.requests.lock().unwrap();
        assert_eq!(
            requests.iter().filter(|row| row["method"] == "GET").count(),
            1
        );
        assert!(
            requests
                .iter()
                .any(|row| row["method"] == "GET" && row["scheme"] == "https")
        );
    }
    proxy.shutdown().await;
}

async fn intercepted_https_origin_case(
    cert_host: &str,
    trust_origin: bool,
    parent: bool,
    expected: u16,
) {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![cert_host.into()]).unwrap();
    if trust_origin {
        let path = directory.path().join("upstream.pem");
        std::fs::write(&path, cert.pem()).unwrap();
        config.upstream_ca_file = Some(path);
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let authority = if parent {
        "target.invalid:18443".to_owned()
    } else {
        format!("localhost:{port}")
    };
    if parent {
        config.parent_proxy = Some(format!("http://127.0.0.1:{port}"));
    }
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let origin = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        if parent {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"CONNECT target.invalid:18443 HTTP/1.1\r\n"));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        }
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await;
        if expected != 200 {
            assert!(tls.is_err());
            return;
        }
        let mut socket = tls.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"GET /signed?x=one&x=two%2Fthree HTTP/1.1\r\n"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let host = if parent {
        "target.invalid"
    } else {
        "localhost"
    };
    let mut socket = connect_tls(&config.listeners[0].socket_path, &authority, host, ca)
        .await
        .unwrap();
    socket.write_all(format!("GET /signed?x=one&x=two%2Fthree HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    let _ = socket.read_to_end(&mut bytes).await;
    assert!(
        bytes.starts_with(format!("HTTP/1.1 {expected}").as_bytes()),
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    if expected == 200 {
        assert!(bytes.ends_with(b"hello"));
    }
    origin.await.unwrap();
    assert_eq!(
        events(&config)
            .iter()
            .filter(|row| row["event"] == "proxy.egress")
            .count(),
        1
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn intercepted_https_verifies_origin_and_parent_connect_without_fallback() {
    intercepted_https_origin_case("localhost", true, false, 200).await;
    intercepted_https_origin_case("wrong.invalid", true, false, 502).await;
    intercepted_https_origin_case("localhost", false, false, 502).await;
    intercepted_https_origin_case("target.invalid", true, true, 200).await;
    intercepted_https_origin_case("wrong.invalid", true, true, 502).await;
}

#[tokio::test]
async fn intercepted_https_drains_an_active_response_during_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let ca = interception_ca(&directory, &mut config);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let path = directory.path().join("upstream.pem");
    std::fs::write(&path, cert.pem()).unwrap();
    config.upstream_ca_file = Some(path);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("localhost:{}", listener.local_addr().unwrap().port());
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let (release, released) = tokio::sync::oneshot::channel();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(socket)
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nfirst")
            .await
            .unwrap();
        released.await.unwrap();
        socket.write_all(b"second").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let mut socket = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        ca,
    )
    .await
    .unwrap();
    socket
        .write_all(format!("GET /stream HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !bytes.ends_with(b"first") {
            bytes.push(socket.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    let shutdown = tokio::spawn(proxy.shutdown());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown discarded an active TLS response"
    );
    release.send(()).unwrap();
    // A missing TLS close_notify is distinct from the HTTP body completion.
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 200"));
    assert!(bytes.ends_with(b"firstsecond"));
    origin.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_cancels_an_idle_intercepted_connection() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let ca = interception_ca(&directory, &mut config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("localhost:{}", listener.local_addr().unwrap().port());
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let mut socket = connect_tls(
        &config.listeners[0].socket_path,
        &authority,
        "localhost",
        ca,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), proxy.shutdown())
        .await
        .unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
}

#[tokio::test]
async fn adapter_failure_closes_locally_without_outbound_contact() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(&directory);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let reply = request(
        &config.listeners[0].socket_path,
        "http://must-not-resolve.invalid/",
        "",
    )
    .await;
    assert!(reply.starts_with("HTTP/1.1 502"));
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let inconsistent = request(
        &config.listeners[0].socket_path,
        "http://must-not-resolve.invalid/inconsistent",
        "",
    )
    .await;
    assert!(inconsistent.starts_with("HTTP/1.1 502"));
    assert!(
        events(&config)
            .iter()
            .all(|event| event["event"] != "proxy.egress")
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn internal_policy_handler_failure_does_not_redirect_to_origin() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(&directory);
    let _policy = Policy::start(config.temporary_policy_socket.as_deref().unwrap()).await;
    let (authority, contacts, origin) = origin().await;
    let proxy = Proxy::start(config.clone()).await.unwrap();

    // The existing temporary policy adapter's deliberately inconsistent
    // response is a disposable internal-handler fault. It is reached through
    // the real agent HTTP listener, before the proxy opens an origin socket.
    let reply = request(
        &config.listeners[0].socket_path,
        &format!("http://{authority}/inconsistent"),
        "",
    )
    .await;
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert_eq!(contacts.load(Ordering::SeqCst), 0);
    assert!(
        events(&config)
            .iter()
            .all(|event| event["event"] != "proxy.egress")
    );

    proxy.shutdown().await;
    origin.abort();
}

#[tokio::test]
async fn invalid_reload_keeps_existing_listener_and_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(&directory);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let marker = std::fs::read(&config.readiness_file).unwrap();
    config.parent_proxy = Some("http://localhost:99999".into());
    assert!(proxy.reload(config.clone()).await.is_err());
    assert_eq!(std::fs::read(&config.readiness_file).unwrap(), marker);
    assert!(
        request(
            &config.listeners[0].socket_path,
            "http://_safeyolo.proxy.internal/",
            ""
        )
        .await
        .starts_with("HTTP/1.1 503")
    );
    proxy.shutdown().await;
}
