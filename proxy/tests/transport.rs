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
use hyper_util::rt::TokioIo;
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
                            let allow = metadata["agent_id"] == "alice";
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
        listeners: ["alice", "bob"]
            .iter()
            .map(|agent| AgentListener {
                agent_id: (*agent).into(),
                socket_path: directory.path().join(format!("{agent}.sock")),
            })
            .collect(),
        temporary_policy_socket: directory.path().join("policy.sock"),
        readiness_file: directory.path().join("ready.json"),
        event_log: directory.path().join("events.jsonl"),
        parent_proxy: None,
        upstream_ca_file: None,
        via_token: Some("test-instance".into()),
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
    let policy = Policy::start(&config.temporary_policy_socket).await;
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
    let _policy = Policy::start(&config.temporary_policy_socket).await;
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
    let policy = Policy::start(&config.temporary_policy_socket).await;
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
    let policy = Policy::start(&config.temporary_policy_socket).await;
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
    let policy = Policy::start(&config.temporary_policy_socket).await;
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
        },
        AgentListener {
            agent_id: "alice".into(),
            socket_path: directory.path().join("new-alice.sock"),
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
    let _policy = Policy::start(&config.temporary_policy_socket).await;
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
    let _policy = Policy::start(&config.temporary_policy_socket).await;
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
    let _policy = Policy::start(&config.temporary_policy_socket).await;
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
