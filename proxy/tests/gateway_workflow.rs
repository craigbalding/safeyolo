use safeyolo_proxy::{
    AgentListener, Config, Proxy,
    credentials::{Credential, Secret, Vault},
};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::oneshot,
};

const PASS: &str = "synthetic-vault-passphrase";
const INITIAL_POLICY: &str = r#"
[hosts."127.0.0.1"]
service = "simple"
egress = "allow"

[hosts."*"]
egress = "allow"

[agents.alice]
egress = "allow"

[agents.bob]
egress = "allow"

[addons.credential_guard]
enabled = true

[addons.credential_guard.settings]
use_default_credential_rules = false
"#;

const SERVICE: &str = r#"
schema_version: 1
name: simple
default_host: 127.0.0.1
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /v1/value
"#;

fn config(root: &Path) -> Config {
    Config {
        listeners: vec![
            AgentListener {
                agent_id: "alice".into(),
                socket_path: root.join("alice.sock"),
                source_id: None,
            },
            AgentListener {
                agent_id: "bob".into(),
                socket_path: root.join("bob.sock"),
                source_id: None,
            },
        ],
        agent_map_file: String::new(),
        data_dir: Some(root.join("data")),
        temporary_policy_socket: None,
        policy_file: Some(root.join("policy.toml")),
        gateway_builtin_services_dir: Some(root.join("builtin")),
        gateway_services_dir: Some(root.join("services")),
        network_guard_enabled: true,
        network_guard_block: true,
        network_guard_homoglyph: true,
        credential_guard_block: true,
        circuit_breaker_enabled: true,
        circuit_state_file: None,
        agent_api_enabled: true,
        test_context_block: true,
        test_context_inject_declared: false,
        test_context_declared_ttl: serde_json::json!(900),
        sse_streaming_enabled: true,
        sse_stream_json: false,
        flow_store_enabled: false,
        flow_store_db_path: root.join("flows.sqlite3"),
        flow_pruner_max: 5000,
        flow_pruner_max_body_bytes: 1024 * 1024 * 1024,
        admin_port: Some(0),
        admin_api_token_file: Some(root.join("admin-token")),
        admin_shield_extra_ports: String::new(),
        readiness_file: root.join("ready.json"),
        reload_id: None,
        audit_log_path: Some(root.join("audit.jsonl")),
        event_log: root.join("events.jsonl"),
        parent_proxy: None,
        upstream_ca_file: None,
        tls_ca_file: None,
        ignore_hosts: Vec::new(),
        via_token: Some("gateway-workflow-test".into()),
        inspection: None,
    }
}

async fn origin(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let Ok(size) = stream.read(&mut buffer).await else {
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
            let body = b"ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        });
    }
}

async fn raw_http(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

async fn admin_http(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn body(response: &[u8]) -> &[u8] {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    &response[split + 4..]
}

fn status(response: &[u8], expected: &str) {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap();
    assert!(
        std::str::from_utf8(&response[..line_end])
            .unwrap()
            .contains(expected),
        "{response:?}"
    );
}

fn request_access() -> Vec<u8> {
    let payload = br#"{"service":"simple","capability":"reader","reason":"integration"}"#;
    format!(
        "POST http://_safeyolo.proxy.internal/gateway/request-access HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer agent-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(), String::from_utf8_lossy(payload)
    ).into_bytes()
}

async fn wait_for_alice(socket: &Path) -> Value {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let request = b"GET http://_safeyolo.proxy.internal/gateway/services HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer agent-token\r\nConnection: close\r\n\r\n";
            let response = raw_http(socket, request).await;
            if response.starts_with(b"HTTP/1.1 503") {
                eprintln!("gateway view 503: {}", String::from_utf8_lossy(body(&response)));
            }
            if response.starts_with(b"HTTP/1.1 200") {
                let value: Value = serde_json::from_slice(body(&response)).unwrap();
                if value["authorized"]["simple"]["token"].as_str().is_some() {
                    return value;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.unwrap()
}

async fn send_agent(socket: &Path, port: u16, token: &str, host: &str) -> Vec<u8> {
    let request = format!(
        "GET http://{host}:{port}/v1/value?sig=%252F HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    raw_http(socket, request.as_bytes()).await
}

#[tokio::test]
async fn simple_service_access_watcher_discovery_retry_and_isolation() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("policy.toml"), INITIAL_POLICY).unwrap();
    std::fs::write(root_path.join("services/simple.yaml"), SERVICE).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "simple-secret",
            "bearer",
            Secret::new("exact-synthetic-origin-credential"),
        ))
        .unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, seen.clone()));

    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;

    // The authenticated Agent API request is only pending; it creates no
    // binding and cannot reach the origin by itself.
    let pending = raw_http(&root_path.join("alice.sock"), &request_access()).await;
    status(&pending, "202");
    assert_eq!(
        serde_json::from_slice::<Value>(body(&pending)).unwrap()["status"],
        "pending"
    );
    assert!(seen.lock().unwrap().is_empty());

    let payload = br#"{"service":"simple","capability":"reader","credential":"simple-secret"}"#;
    let admin_request = format!(
        "POST /admin/agents/alice/services HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        String::from_utf8_lossy(payload)
    );
    let authorized = admin_http(admin_port, admin_request.as_bytes()).await;
    status(&authorized, "200");

    // Drive the same process-owned service/policy watcher as main.rs. The
    // test does not call a loader or publish a hand-built snapshot.
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let watcher = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => { proxy.shutdown().await; break; }
                _ = proxy.wait_for_service_catalog_check() => { let _ = proxy.reload_services_if_changed().await; }
                _ = proxy.wait_for_policy_check() => { let _ = proxy.reload_policy_if_changed().await; }
            }
        }
    });
    let alice_view = wait_for_alice(&root_path.join("alice.sock")).await;
    let gateway_token = alice_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let delivered = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &gateway_token,
        "127.0.0.1",
    )
    .await;
    status(&delivered, "200");
    assert_eq!(body(&delivered), b"ok");
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let origin_request = seen.lock().unwrap()[0].clone();
    assert!(
        origin_request
            .windows(b"Authorization: Bearer exact-synthetic-origin-credential".len())
            .any(|window| window == b"Authorization: Bearer exact-synthetic-origin-credential")
    );
    assert!(
        !origin_request
            .windows(gateway_token.len())
            .any(|window| window == gateway_token.as_bytes())
    );
    assert!(
        origin_request
            .windows(b"/v1/value?sig=%252F".len())
            .any(|window| window == b"/v1/value?sig=%252F")
    );

    // Trusted Bob cannot reuse Alice's published token. A destination outside
    // the service host map is rejected before the controlled origin sees it.
    let bob = send_agent(
        &root_path.join("bob.sock"),
        origin_port,
        &gateway_token,
        "127.0.0.1",
    )
    .await;
    status(&bob, "403");
    let wrong_destination = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &gateway_token,
        "127.0.0.2",
    )
    .await;
    status(&wrong_destination, "503");
    assert_eq!(seen.lock().unwrap().len(), 1);
    let bob_view_request = b"GET http://_safeyolo.proxy.internal/gateway/services HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer agent-token\r\nConnection: close\r\n\r\n";
    let bob_view = raw_http(&root_path.join("bob.sock"), bob_view_request).await;
    status(&bob_view, "200");
    assert_eq!(
        serde_json::from_slice::<Value>(body(&bob_view)).unwrap()["authorized"],
        serde_json::json!({})
    );

    // Removing the persisted binding and waiting for watcher publication
    // revokes the old token atomically with the policy snapshot.
    // Let the accepted snapshot's watermark advance before replacing the
    // durable binding. The native watcher compares the source mtime.
    tokio::time::sleep(Duration::from_millis(25)).await;
    std::fs::write(root_path.join("policy.toml"), INITIAL_POLICY).unwrap();
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let response = raw_http(&root_path.join("alice.sock"), bob_view_request).await;
            if response.starts_with(b"HTTP/1.1 200") {
                let value: Value = serde_json::from_slice(body(&response)).unwrap();
                if value["authorized"] == serde_json::json!({}) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let stale = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &gateway_token,
        "127.0.0.1",
    )
    .await;
    status(&stale, "403");
    assert_eq!(seen.lock().unwrap().len(), 1);

    let _ = stop_tx.send(());
    watcher.await.unwrap();
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    let events = std::fs::read_to_string(root_path.join("events.jsonl")).unwrap();
    assert!(audit.contains("gateway.request_access"));
    assert!(audit.contains("gateway.allow"));
    assert!(!audit.contains("exact-synthetic-origin-credential"));
    assert!(!audit.contains(&gateway_token));
    assert!(!events.contains("exact-synthetic-origin-credential"));
    assert!(!events.contains(&gateway_token));
    origin_task.abort();
}
