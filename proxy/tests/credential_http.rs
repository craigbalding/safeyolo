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
    net::{TcpListener, TcpStream, UnixStream},
    sync::Notify,
};

fn config(
    directory: &TempDir,
    policy: &std::path::Path,
    socket: &std::path::Path,
    block: bool,
) -> Config {
    let token = directory.path().join("admin-token");
    std::fs::write(token, b"credential-http-admin").unwrap();
    Config {
        listeners: vec![
            AgentListener {
                agent_id: "alice".into(),
                socket_path: socket.to_owned(),
                source_id: None,
            },
            AgentListener {
                agent_id: "bob".into(),
                socket_path: directory.path().join("bob.sock"),
                source_id: None,
            },
        ],
        agent_map_file: String::new(),
        data_dir: Some(directory.path().join("data")),
        temporary_policy_socket: None,
        policy_file: Some(policy.to_owned()),
        gateway_builtin_services_dir: None,
        gateway_services_dir: None,
        network_guard_enabled: true,
        network_guard_block: true,
        network_guard_homoglyph: true,
        credential_guard_block: block,
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
        admin_port: Some(0),
        admin_api_token_file: Some(directory.path().join("admin-token")),
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

async fn stats(directory: &TempDir) -> Value {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("ready.json")).unwrap())
            .unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer credential-http-admin\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let split = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    assert!(
        std::str::from_utf8(&bytes[..split])
            .unwrap()
            .contains(" 200 ")
    );
    serde_json::from_slice(&bytes[split + 4..]).unwrap()
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

async fn wait_for_seen(seen: &Arc<Mutex<Vec<Vec<u8>>>>, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while seen.lock().unwrap().len() < count {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
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
        .header("X-SafeYolo-Trace", "1")
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
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
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

    // Two independent trusted UDS identities exercise concurrent native H1
    // admission while Alice's connection is also reused for later requests.
    let bob_stream = UnixStream::connect(directory.path().join("bob.sock"))
        .await
        .unwrap();
    let (mut bob_sender, bob_connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(bob_stream))
            .await
            .unwrap();
    let bob_connection_task = tokio::spawn(bob_connection);
    let (alice_again, bob_again) = tokio::join!(
        send(
            &mut sender,
            format!("http://127.0.0.1:{origin_port}/alice-again")
                .parse()
                .unwrap(),
            "Bearer key-allowed",
        ),
        send(
            &mut bob_sender,
            format!("http://127.0.0.1:{origin_port}/bob")
                .parse()
                .unwrap(),
            "Bearer key-allowed",
        )
    );
    assert_eq!(alice_again.status(), 200);
    assert_eq!(bob_again.status(), 200);
    let _ = alice_again.collect().await.unwrap();
    let _ = bob_again.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    wait_for_seen(&seen, 3).await;

    let blocked_uri: Uri = "http://blocked.invalid/private".parse().unwrap();
    let blocked = send(&mut sender, blocked_uri, "Bearer key-allowed").await;
    assert_eq!(blocked.status(), 428);
    let blocked_body = blocked.collect().await.unwrap().to_bytes();
    assert!(
        !blocked_body
            .windows(b"key-allowed".len())
            .any(|window| window == b"key-allowed")
    );
    assert_eq!(seen.lock().unwrap().len(), 3);
    let delivered = String::from_utf8(seen.lock().unwrap()[0].clone()).unwrap();
    assert!(delivered.contains("authorization: Bearer key-allowed\r\n"));
    assert!(delivered.contains("authorization: Bearer duplicate\r\n"));
    assert!(!delivered.contains("header-canary"));
    assert!(delivered.contains("GET /allowed?Q=%252F HTTP/1.1\r\n"));

    let initial_stats = stats(&directory).await;
    assert_eq!(
        initial_stats["credential-guard"],
        json!({
            "violations_total": 1,
            "violations_by_type": {"synthetic": 1},
            "rules_count": 1
        })
    );

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
        .reload(config(&directory, &policy_path, &socket, true))
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
    let reloaded_stats = stats(&directory).await;
    assert_eq!(reloaded_stats["credential-guard"]["violations_total"], 2);
    assert_eq!(reloaded_stats["credential-guard"]["rules_count"], 1);

    drop(sender);
    let _ = connection_task.await;
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    assert_eq!(events.matches("proxy.credential_guard").count(), 5);
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
    assert_eq!(fingerprints.len(), 5);
    assert_eq!(fingerprints[0], fingerprints[1]);
    assert_eq!(fingerprints[1], fingerprints[2]);
    assert_eq!(fingerprints[2], fingerprints[3]);
    assert_eq!(fingerprints[3], fingerprints[4]);
    assert_eq!(
        guard_events[0]["evaluations"][0]["finding"]["header"],
        "authorization"
    );
    assert_eq!(
        guard_events[4]["evaluations"][0]["finding"]["rule"],
        "synthetic-reloaded"
    );
    assert_eq!(guard_events[0]["trace"][0]["state"], "evaluated");
    assert_eq!(guard_events[0]["trace"][0]["outcome"], "detected");
    assert_eq!(guard_events[1]["trace"][0]["outcome"], "detected");
    drop(bob_sender);
    let _ = bob_connection_task.await;
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("security.credential_guard"));
    assert!(!audit.contains("key-allowed"));
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_warn_mode_delivers_and_reports_trace_audit_and_stats() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-warn-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"blocked.invalid/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"warn-rule",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["blocked.invalid"],
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
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, false))
        .await
        .unwrap();

    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let response = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/warn")
            .parse()
            .unwrap(),
        "Bearer key-warn",
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.collect().await.unwrap().to_bytes(),
        b"origin-ok".as_slice()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    let report = stats(&directory).await;
    assert_eq!(report["credential-guard"]["violations_total"], 1);
    assert_eq!(
        report["credential-guard"]["violations_by_type"]["warn-rule"],
        1
    );
    assert_eq!(report["credential-guard"]["rules_count"], 1);

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let event = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["event"] == "proxy.credential_guard")
        .unwrap();
    assert_eq!(event["outcome"], "warned");
    assert_eq!(event["trace"][0]["outcome"], "detected");
    assert_eq!(event["trace"][1]["outcome"], "warned");
    assert!(!events.contains("key-warn"));
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"decision\": \"warn\""));
    assert!(!audit.contains("key-warn"));
    origin_task.abort();
}
