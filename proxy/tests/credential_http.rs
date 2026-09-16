use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use safeyolo_proxy::{AgentListener, Config, Proxy};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::Notify,
};

fn config(directory: &TempDir, policy: &std::path::Path, socket: &std::path::Path) -> Config {
    Config {
        listeners: vec![AgentListener {
            agent_id: "alice".into(),
            socket_path: socket.to_owned(),
            source_id: None,
        }],
        agent_map_file: String::new(),
        data_dir: Some(directory.path().join("data")),
        temporary_policy_socket: None,
        policy_file: Some(policy.to_owned()),
        gateway_builtin_services_dir: None,
        gateway_services_dir: None,
        network_guard_enabled: true,
        network_guard_block: true,
        network_guard_homoglyph: true,
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
        via_token: Some("credential-http-test".into()),
        inspection: None,
    }
}

async fn origin(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>, ready: Arc<Notify>) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let Ok(size) = socket.read(&mut buffer).await else {
                    return;
                };
                if size == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..size]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            seen.lock().unwrap().push(request);
            ready.notify_one();
            let body = b"origin-ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
        });
    }
}

async fn send(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    uri: Uri,
    credential: &str,
) -> hyper::Response<hyper::body::Incoming> {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", credential)
        .header("authorization", "Bearer duplicate")
        .header("Connection", "keep-alive, x-remove")
        .header("X-Remove", "header-canary")
        .body(Empty::new())
        .unwrap();
    sender.send_request(request).await.unwrap()
}

#[tokio::test]
async fn native_guard_allows_origin_bytes_blocks_forbidden_host_and_reuses_h1() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-test-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"synthetic",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket))
        .await
        .unwrap();

    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let local_uri: Uri = "http://_safeyolo.proxy.internal/status".parse().unwrap();
    let local = send(&mut sender, local_uri, "Bearer key-allowed").await;
    assert_eq!(local.status(), 503);
    assert!(
        !local
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .windows(b"key-allowed".len())
            .any(|window| window == b"key-allowed")
    );
    let allowed_uri: Uri = format!("http://127.0.0.1:{origin_port}/allowed?Q=%252F")
        .parse()
        .unwrap();
    let allowed = send(&mut sender, allowed_uri, "Bearer key-allowed").await;
    assert_eq!(allowed.status(), 200);
    assert_eq!(
        allowed.collect().await.unwrap().to_bytes(),
        b"origin-ok".as_slice()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let blocked_uri: Uri = "http://blocked.invalid/private".parse().unwrap();
    let blocked = send(&mut sender, blocked_uri, "Bearer key-allowed").await;
    assert_eq!(blocked.status(), 428);
    let blocked_body = blocked.collect().await.unwrap().to_bytes();
    assert!(
        !blocked_body
            .windows(b"key-allowed".len())
            .any(|window| window == b"key-allowed")
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    let delivered = String::from_utf8(seen.lock().unwrap()[0].clone()).unwrap();
    assert!(delivered.contains("authorization: Bearer key-allowed\r\n"));
    assert!(delivered.contains("authorization: Bearer duplicate\r\n"));
    assert!(!delivered.contains("header-canary"));
    assert!(delivered.contains("GET /allowed?Q=%252F HTTP/1.1\r\n"));

    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"synthetic-reloaded",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket))
        .await
        .unwrap();
    let blocked_after_reload = send(
        &mut sender,
        "http://blocked.invalid/reloaded".parse().unwrap(),
        "Bearer key-allowed",
    )
    .await;
    assert_eq!(blocked_after_reload.status(), 428);
    let _ = blocked_after_reload.collect().await.unwrap();

    drop(sender);
    let _ = connection_task.await;
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    assert_eq!(events.matches("proxy.credential_guard").count(), 3);
    assert!(!events.contains("key-allowed"));
    assert!(!events.contains("header-canary"));
    let guard_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    let fingerprints = guard_events
        .iter()
        .map(|event| event["evaluations"][0]["finding"]["fingerprint"].clone())
        .collect::<Vec<_>>();
    assert_eq!(fingerprints.len(), 3);
    assert_eq!(fingerprints[1], fingerprints[2]);
    assert_eq!(
        guard_events[2]["evaluations"][0]["finding"]["rule"],
        "synthetic-reloaded"
    );
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("security.credential_guard"));
    assert!(!audit.contains("key-allowed"));
    origin_task.abort();
}
