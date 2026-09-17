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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::Notify,
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
