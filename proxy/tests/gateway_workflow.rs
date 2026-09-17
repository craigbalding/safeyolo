use safeyolo_proxy::{
    AgentListener, Config, Proxy,
    credentials::{Credential, Secret, Vault},
};
use serde_json::Value;
use std::{
    path::Path,
    process::Command,
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
      - methods: [GET, POST]
        path: /v1/value
      - methods: [GET]
        path: /v1/redirect
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

async fn origin(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>, redirect_port: u16) {
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
                if let Some(split) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    let content_length = std::str::from_utf8(&request[..split])
                        .ok()
                        .and_then(|headers| {
                            headers.lines().find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                        })
                        .unwrap_or(0);
                    if request.len() >= split + 4 + content_length {
                        break;
                    }
                }
            }
            let redirect = request
                .windows(b"GET /v1/redirect".len())
                .any(|window| window == b"GET /v1/redirect");
            seen.lock().unwrap().push(request);
            let body: &[u8] = if redirect { b"redirect" } else { b"ok" };
            let response = if redirect {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:{redirect_port}/evil?next=%252F\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
            };
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

async fn wait_for_audit_event(path: &Path, name: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(content) = std::fs::read_to_string(path)
                && let Some(event) = content.lines().find_map(|line| {
                    let value = serde_json::from_str::<Value>(line).ok()?;
                    (value["event"] == name).then_some(value)
                })
            {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

fn approve_service_with_existing_consumer(
    root: &Path,
    event: &Value,
    credential: &str,
) -> std::process::Output {
    let event_path = root.join("approval-event.json");
    let request_path = root.join("approval-request.json");
    std::fs::write(&event_path, serde_json::to_vec(event).unwrap()).unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let script = r#"
import json
import os
import sys
from safeyolo.operator_approvals import approve

class NativeAdminAPI:
    """Capture the existing approval consumer's typed request for native API."""
    def __init__(self, request_path):
        self.request_path = request_path

    def authorize_service(self, *, agent, service, capability, credential):
        with open(self.request_path, "w", encoding="utf-8") as stream:
            json.dump({
                "agent": agent,
                "service": service,
                "capability": capability,
                "credential": credential,
            }, stream)
        return {"status": "authorized"}

with open(sys.argv[1], encoding="utf-8") as stream:
    event = json.load(stream)
api = NativeAdminAPI(sys.argv[2])
result = approve(event, api, service_credential=os.environ["TEST_SERVICE_CREDENTIAL"])
assert result == "authorized", result
"#;
    Command::new("python3")
        .current_dir(repository)
        .env("PYTHONPATH", repository.join("cli/src"))
        .env("TEST_SERVICE_CREDENTIAL", credential)
        .args([
            "-c",
            script,
            event_path.to_str().unwrap(),
            request_path.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

fn admin_request(root: &Path) -> Vec<u8> {
    let request: Value =
        serde_json::from_slice(&std::fs::read(root.join("approval-request.json")).unwrap())
            .unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "service":request["service"],
        "capability":request["capability"],
        "credential":request["credential"],
    }))
    .unwrap();
    format!(
        "POST /admin/agents/{}/services HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        request["agent"].as_str().unwrap(),
        body.len(),
        String::from_utf8_lossy(&body)
    )
    .into_bytes()
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
        "expected {expected}, got {}",
        String::from_utf8_lossy(response)
    );
}

fn request_access_with(token: Option<&str>, payload: &[u8]) -> Vec<u8> {
    let authorization = token.map_or(String::new(), |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    format!(
        "POST http://_safeyolo.proxy.internal/gateway/request-access HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        String::from_utf8_lossy(payload)
    ).into_bytes()
}

fn request_access() -> Vec<u8> {
    request_access_with(
        Some("agent-token"),
        br#"{"service":"simple","capability":"reader","reason":"integration"}"#,
    )
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

async fn wait_for_alice_token_change(socket: &Path, previous: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let value = wait_for_alice(socket).await;
            if value["authorized"]["simple"]["token"]
                .as_str()
                .is_some_and(|token| token != previous)
            {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap()
}

async fn send_agent_request(
    socket: &Path,
    port: u16,
    token: &str,
    host: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let request = format!(
        "{method} http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body),
    );
    raw_http(socket, request.as_bytes()).await
}

async fn send_agent(socket: &Path, port: u16, token: &str, host: &str) -> Vec<u8> {
    send_agent_request(socket, port, token, host, "GET", "/v1/value?sig=%252F", b"").await
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
    vault
        .store(Credential::new(
            "crlf-secret",
            "bearer",
            Secret::new("bad\r\nInjected: leaked"),
        ))
        .unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, seen.clone(), origin_port));

    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;

    let access_body = br#"{"service":"simple","capability":"reader"}"#;
    let absent_token = raw_http(
        &root_path.join("alice.sock"),
        &request_access_with(None, access_body),
    )
    .await;
    status(&absent_token, "401");
    let bad_token = raw_http(
        &root_path.join("alice.sock"),
        &request_access_with(Some("wrong-agent-token"), access_body),
    )
    .await;
    status(&bad_token, "401");
    let forged_identity = raw_http(
        &root_path.join("alice.sock"),
        &request_access_with(
            Some("agent-token"),
            br#"{"agent":"bob","service":"simple","capability":"reader"}"#,
        ),
    )
    .await;
    status(&forged_identity, "202");
    assert_eq!(
        serde_json::from_slice::<Value>(body(&forged_identity)).unwrap()["agent"],
        "alice"
    );
    let unknown_service = raw_http(
        &root_path.join("alice.sock"),
        &request_access_with(
            Some("agent-token"),
            br#"{"service":"missing","capability":"reader"}"#,
        ),
    )
    .await;
    status(&unknown_service, "404");
    let unknown_capability = raw_http(
        &root_path.join("alice.sock"),
        &request_access_with(
            Some("agent-token"),
            br#"{"service":"simple","capability":"missing"}"#,
        ),
    )
    .await;
    status(&unknown_capability, "404");

    // The authenticated Agent API request is only pending; it creates no
    // binding and cannot reach the origin by itself.
    let pending = raw_http(&root_path.join("alice.sock"), &request_access()).await;
    status(&pending, "202");
    assert_eq!(
        serde_json::from_slice::<Value>(body(&pending)).unwrap()["status"],
        "pending"
    );
    assert!(seen.lock().unwrap().is_empty());

    let request_event =
        wait_for_audit_event(&root_path.join("audit.jsonl"), "gateway.request_access").await;
    let approval =
        approve_service_with_existing_consumer(root_path, &request_event, "simple-secret");
    assert!(
        approval.status.success(),
        "operator approval failed: {}",
        String::from_utf8_lossy(&approval.stderr)
    );
    let authorized = admin_http(admin_port, &admin_request(root_path)).await;
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
    let post = send_agent_request(
        &root_path.join("alice.sock"),
        origin_port,
        &gateway_token,
        "127.0.0.1",
        "POST",
        "/v1/value?sig=%252F&body=%252F",
        b"signed-request-body",
    )
    .await;
    status(&post, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let post_request = seen.lock().unwrap()[1].clone();
    assert!(post_request.ends_with(b"signed-request-body"));
    assert!(
        post_request
            .windows(b"/v1/value?sig=%252F&body=%252F".len())
            .any(|window| window == b"/v1/value?sig=%252F&body=%252F")
    );

    // Re-approving the same durable binding publishes a replacement token;
    // the old token is rejected while the current token remains usable.
    let replacement_approval =
        approve_service_with_existing_consumer(root_path, &request_event, "simple-secret");
    assert!(
        replacement_approval.status.success(),
        "replacement approval failed: {}",
        String::from_utf8_lossy(&replacement_approval.stderr)
    );
    let replacement_response = admin_http(admin_port, &admin_request(root_path)).await;
    status(&replacement_response, "200");
    let replacement_view =
        wait_for_alice_token_change(&root_path.join("alice.sock"), &gateway_token).await;
    let replacement_token = replacement_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let stale_replacement = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &gateway_token,
        "127.0.0.1",
    )
    .await;
    status(&stale_replacement, "403");
    assert_eq!(seen.lock().unwrap().len(), 2);
    let current_replacement = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &replacement_token,
        "127.0.0.1",
    )
    .await;
    status(&current_replacement, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().len() < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let wrong_method = send_agent_request(
        &root_path.join("alice.sock"),
        origin_port,
        &replacement_token,
        "127.0.0.1",
        "PUT",
        "/v1/value?sig=%252F",
        b"",
    )
    .await;
    status(&wrong_method, "403");
    let wrong_path = send_agent_request(
        &root_path.join("alice.sock"),
        origin_port,
        &replacement_token,
        "127.0.0.1",
        "GET",
        "/v1/private?sig=%252F",
        b"",
    )
    .await;
    status(&wrong_path, "403");
    assert_eq!(seen.lock().unwrap().len(), 3);

    // A credential value containing CRLF is rejected at the native header
    // boundary. The response is generic and the controlled origin receives
    // neither the malformed value nor a partially injected request.
    let crlf_approval =
        approve_service_with_existing_consumer(root_path, &request_event, "crlf-secret");
    assert!(
        crlf_approval.status.success(),
        "CRLF approval failed: {}",
        String::from_utf8_lossy(&crlf_approval.stderr)
    );
    let crlf_response = admin_http(admin_port, &admin_request(root_path)).await;
    status(&crlf_response, "200");
    let crlf_view =
        wait_for_alice_token_change(&root_path.join("alice.sock"), &replacement_token).await;
    let crlf_token = crlf_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let crlf_delivery = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &crlf_token,
        "127.0.0.1",
    )
    .await;
    status(&crlf_delivery, "503");
    assert_eq!(seen.lock().unwrap().len(), 3);
    let crlf_body = String::from_utf8_lossy(body(&crlf_delivery));
    assert!(!crlf_body.contains("bad") && !crlf_body.contains("Injected"));

    // Restore the usable vault reference through the same approval consumer
    // and watcher before exercising transport policy controls.
    let restored_approval =
        approve_service_with_existing_consumer(root_path, &request_event, "simple-secret");
    assert!(
        restored_approval.status.success(),
        "restore approval failed: {}",
        String::from_utf8_lossy(&restored_approval.stderr)
    );
    let restored_response = admin_http(admin_port, &admin_request(root_path)).await;
    status(&restored_response, "200");
    let restored_view =
        wait_for_alice_token_change(&root_path.join("alice.sock"), &crlf_token).await;
    let restored_token = restored_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Service auth refuses ordinary HTTP by default and emits a redirect. The
    // explicit allow_http service setting above is the positive control.
    tokio::time::sleep(Duration::from_millis(25)).await;
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace("allow_http: true", "allow_http: false"),
    )
    .unwrap();
    let refusal_view =
        wait_for_alice_token_change(&root_path.join("alice.sock"), &restored_token).await;
    let refusal_token = refusal_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let refusal = send_agent(
        &root_path.join("alice.sock"),
        origin_port,
        &refusal_token,
        "127.0.0.1",
    )
    .await;
    status(&refusal, "301");
    let refusal_text = String::from_utf8_lossy(&refusal);
    assert!(
        refusal_text.contains(&format!(
            "location: https://127.0.0.1:{origin_port}/v1/value?sig=%252F"
        )),
        "unexpected HTTP refusal response: {refusal_text}"
    );
    assert_eq!(seen.lock().unwrap().len(), 3);

    tokio::time::sleep(Duration::from_millis(25)).await;
    std::fs::write(root_path.join("services/simple.yaml"), SERVICE).unwrap();
    let restored_service_view =
        wait_for_alice_token_change(&root_path.join("alice.sock"), &refusal_token).await;
    let current_token = restored_service_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // A client-followed redirect cannot carry the selected credential to a
    // different authority. The first hop reaches the controlled origin; the
    // second hop is rejected before the origin can observe it.
    let redirect = send_agent_request(
        &root_path.join("alice.sock"),
        origin_port,
        &current_token,
        "127.0.0.1",
        "GET",
        "/v1/redirect?next=%252F",
        b"",
    )
    .await;
    status(&redirect, "302");
    let redirect_text = String::from_utf8_lossy(&redirect);
    assert!(
        redirect_text.contains(&format!(
            "Location: http://127.0.0.2:{origin_port}/evil?next=%252F"
        )),
        "unexpected origin redirect response: {redirect_text}"
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let followed = send_agent_request(
        &root_path.join("alice.sock"),
        origin_port,
        &current_token,
        "127.0.0.2",
        "GET",
        "/evil?next=%252F",
        b"",
    )
    .await;
    status(&followed, "503");
    assert_eq!(seen.lock().unwrap().len(), 4);

    // Port is part of network admission. With no listener at this controlled
    // port, the request fails closed and the selected origin remains untouched;
    // the gateway intentionally has no new host/port restriction of its own.
    let wrong_port = send_agent(
        &root_path.join("alice.sock"),
        1,
        &current_token,
        "127.0.0.1",
    )
    .await;
    status(&wrong_port, "502");
    assert_eq!(seen.lock().unwrap().len(), 4);

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
    assert_eq!(seen.lock().unwrap().len(), 4);
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
    assert_eq!(seen.lock().unwrap().len(), 4);

    let _ = stop_tx.send(());
    watcher.await.unwrap();
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    let events = std::fs::read_to_string(root_path.join("events.jsonl")).unwrap();
    assert!(audit.contains("gateway.request_access"));
    assert!(audit.contains("gateway.allow"));
    assert!(!audit.contains("exact-synthetic-origin-credential"));
    assert!(!audit.contains("bad\r\nInjected: leaked"));
    assert!(!events.contains("exact-synthetic-origin-credential"));
    assert!(!events.contains("bad\r\nInjected: leaked"));
    for token in [
        &gateway_token,
        &replacement_token,
        &crlf_token,
        &restored_token,
        &refusal_token,
        &current_token,
    ] {
        assert!(!audit.contains(token));
        assert!(!events.contains(token));
    }
    origin_task.abort();
}
