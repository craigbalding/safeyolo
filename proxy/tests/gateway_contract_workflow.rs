use safeyolo_proxy::{
    AgentListener, Config, Proxy,
    credentials::{Credential, Secret, Vault},
};
use serde_json::Value;
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::{Notify, oneshot},
};

const PASS: &str = "contract-workflow-pass";
const SERVICE: &str = r#"
schema_version: 1
name: contract
default_host: 127.0.0.1
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
risky_routes:
  - path: /v1/write
    methods: [POST]
    tactics: [exfiltration]
capabilities:
  writer:
    routes:
      - methods: [POST]
        path: /v1/write
    contract:
      template: contract.write.v1
      bindings:
        project:
          source: operator
          type: enum
          options: [alpha, beta]
        ticket:
          source: operator
          type: string
      operations:
        - name: write
          request:
            method: POST
            path: /v1/write
            query:
              allow:
                ticket:
                  equals_var: ticket
            body:
              allow:
                project:
                  equals_var: project
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
        response_validators: declared
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
        via_token: Some("contract-test".into()),
        inspection: None,
    }
}

fn policy(port: u16) -> String {
    format!(
        r#"
[hosts."127.0.0.1"]
service = "contract"
[hosts."127.0.0.1:{port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
[agents.alice.services.contract]
capability = "writer"
token = "contract-secret"
[agents.bob]
[addons.credential_guard]
enabled = true
[addons.credential_guard.settings]
use_default_credential_rules = false
"#
    )
}

async fn origin(
    listener: TcpListener,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_first: Arc<AtomicBool>,
    hold_first: Arc<AtomicBool>,
    first_accepted: Arc<Notify>,
    release_first: Arc<Notify>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        let fail_first = fail_first.clone();
        let hold_first = hold_first.clone();
        let first_accepted = first_accepted.clone();
        let release_first = release_first.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                request.extend_from_slice(&buf[..n]);
                let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let length = std::str::from_utf8(&request[..end])
                    .ok()
                    .and_then(|head| {
                        head.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    break;
                }
            }
            let failed = fail_first.swap(false, Ordering::SeqCst);
            let first = hold_first.swap(false, Ordering::SeqCst);
            seen.lock().unwrap().push(request);
            if first {
                first_accepted.notify_one();
                release_first.notified().await;
            }
            let body = b"ok";
            let _ = stream
                .write_all(
                    format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        if failed {
                            "500 Internal Server Error"
                        } else {
                            "200 OK"
                        },
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
            let _ = stream.write_all(body).await;
        });
    }
}

async fn raw(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
async fn admin(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
fn status(response: &[u8], expected: u16) {
    assert!(
        std::str::from_utf8(response)
            .unwrap()
            .starts_with(&format!("HTTP/1.1 {expected}")),
        "{}",
        String::from_utf8_lossy(response)
    );
}
fn body(response: &[u8]) -> &[u8] {
    &response[response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..]
}
fn agent_api(path: &str, body: &[u8]) -> Vec<u8> {
    format!("POST http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer agent-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), String::from_utf8_lossy(body)).into_bytes()
}
fn gateway_request(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    format!("{method} http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), String::from_utf8_lossy(body)).into_bytes()
}
fn admin_request(path: &str, body: &[u8]) -> Vec<u8> {
    format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), String::from_utf8_lossy(body)).into_bytes()
}
fn admin_get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer operator-token\r\nConnection: close\r\n\r\n").into_bytes()
}
fn admin_delete(path: &str) -> Vec<u8> {
    format!("DELETE {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer operator-token\r\nConnection: close\r\n\r\n").into_bytes()
}

async fn gateway_call(
    socket: &Path,
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    payload: &[u8],
) -> Vec<u8> {
    let request = gateway_request(port, token, method, path, payload);
    raw(socket, &request).await
}

async fn current_gateway_token(socket: &Path) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = raw(socket, &agent_api("/gateway/services", b"")).await;
            if let Ok(view) = serde_json::from_slice::<Value>(body(&response))
                && let Some(token) = view["authorized"]["contract"]["token"].as_str()
            {
                return token.to_owned();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn contract_binding_body_query_and_risk_grant_are_live() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for dir in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(dir)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("services/contract.yaml"), SERVICE).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "contract-secret",
            "bearer",
            Secret::new("exact-contract-origin-secret"),
        ))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    std::fs::write(root_path.join("policy.toml"), policy(port)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let fail_first = Arc::new(AtomicBool::new(true));
    let hold_first = Arc::new(AtomicBool::new(false));
    let first_accepted = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(
        listener,
        seen.clone(),
        fail_first,
        hold_first.clone(),
        first_accepted.clone(),
        release_first.clone(),
    ));
    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let watcher = tokio::spawn(async move {
        loop {
            tokio::select! { _ = &mut stop_rx => { proxy.shutdown().await; break; }, _ = proxy.wait_for_service_catalog_check() => { let _ = proxy.reload_services_if_changed().await; }, _ = proxy.wait_for_policy_check() => { let _ = proxy.reload_policy_if_changed().await; } }
        }
    });
    let challenge = raw(
        &root_path.join("alice.sock"),
        &agent_api(
            "/gateway/request-access",
            br#"{"service":"contract","capability":"writer"}"#,
        ),
    )
    .await;
    status(&challenge, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(body(&challenge)).unwrap()["decision"],
        "needs_contract_binding"
    );
    let submitted = raw(&root_path.join("alice.sock"), &agent_api("/gateway/submit-binding", br#"{"service":"contract","capability":"writer","bindings":{"project":"alpha","ticket":"T-1"},"purpose_code":"write"}"#)).await;
    status(&submitted, 202);
    let binding = br#"{"agent":"alice","service":"contract","capability":"writer","template":"contract.write.v1","bindings":{"project":"alpha","ticket":"T-1"},"grantable_operations":["write"]}"#;
    let approved = admin(
        admin_port,
        &admin_request("/admin/gateway/contract-binding", binding),
    )
    .await;
    status(&approved, 200);
    let grant = br#"{"agent":"alice","service":"contract","method":"POST","path":"/v1/write","lifetime":"once"}"#;
    let granted = admin(admin_port, &admin_request("/admin/gateway/grant", grant)).await;
    status(&granted, 200);

    // Policy publication mints the process-owned gateway token. Discover the
    // current value through the same Agent API surface used by the client.
    let mut gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;

    // Give the watcher one real publication boundary; all controls below use
    // requests against the same process-owned snapshot. The first origin
    // response is deliberately unsuccessful: its once lease must be released
    // before the retry can reserve and consume the same approval.
    let mut failed = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
            failed = gateway_call(
                &root_path.join("alice.sock"),
                port,
                &gateway_token,
                "POST",
                "/v1/write?ticket=T-1",
                br#"{"project":"alpha"}"#,
            )
            .await;
            if failed.starts_with(b"HTTP/1.1 500") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    status(&failed, 500);
    assert!(
        String::from_utf8_lossy(&seen.lock().unwrap()[0]).contains("exact-contract-origin-secret")
    );
    let mut allowed = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
            allowed = gateway_call(
                &root_path.join("alice.sock"),
                port,
                &gateway_token,
                "POST",
                "/v1/write?ticket=T-1",
                br#"{"project":"alpha"}"#,
            )
            .await;
            if allowed.starts_with(b"HTTP/1.1 200") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    status(&allowed, 200);
    let count = seen.lock().unwrap().len();

    // Hold the next origin response after it is accepted. A concurrent
    // request sees the reserved once grant and is rejected before dial;
    // releasing the origin then lets the first request consume it.
    let granted = admin(admin_port, &admin_request("/admin/gateway/grant", grant)).await;
    status(&granted, 200);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    hold_first.store(true, Ordering::SeqCst);
    let first_token = gateway_token.clone();
    let first_socket = root_path.join("alice.sock");
    let first = tokio::spawn(async move {
        gateway_call(
            &first_socket,
            port,
            &first_token,
            "POST",
            "/v1/write?ticket=T-1",
            br#"{"project":"alpha"}"#,
        )
        .await
    });
    first_accepted.notified().await;
    let concurrent = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&concurrent, 428);
    release_first.notify_one();
    let held = first.await.unwrap();
    status(&held, 200);
    assert_eq!(seen.lock().unwrap().len(), count + 1);
    let count = seen.lock().unwrap().len();

    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let wrong_body = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"beta"}"#,
    )
    .await;
    status(&wrong_body, 403);
    assert_eq!(seen.lock().unwrap().len(), count);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let unknown_body = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha","extra":1}"#,
    )
    .await;
    status(&unknown_body, 403);
    assert_eq!(seen.lock().unwrap().len(), count);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let wrong_query = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-2",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&wrong_query, 403);
    assert_eq!(seen.lock().unwrap().len(), count);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let wrong_method = {
        gateway_call(
            &root_path.join("alice.sock"),
            port,
            &gateway_token,
            "GET",
            "/v1/write?ticket=T-1",
            b"",
        )
        .await
    };
    status(&wrong_method, 403);
    assert_eq!(seen.lock().unwrap().len(), count);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let wrong_agent = gateway_call(
        &root_path.join("bob.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&wrong_agent, 403);
    assert_eq!(seen.lock().unwrap().len(), count);
    let no_token = gateway_call(
        &root_path.join("alice.sock"),
        port,
        "sgw_unknown",
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&no_token, 403);
    assert_eq!(seen.lock().unwrap().len(), count);

    // Session grants survive response completion and can authorize repeated
    // requests until the operator revokes their durable record.
    let session_grant =
        br#"{"agent":"alice","service":"contract","method":"POST","path":"/v1/write","lifetime":"session"}"#;
    let granted = admin(
        admin_port,
        &admin_request("/admin/gateway/grant", session_grant),
    )
    .await;
    status(&granted, 200);
    for _ in 0..2 {
        gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
        let session_request = gateway_call(
            &root_path.join("alice.sock"),
            port,
            &gateway_token,
            "POST",
            "/v1/write?ticket=T-1",
            br#"{"project":"alpha"}"#,
        )
        .await;
        status(&session_request, 200);
    }
    let session_count = seen.lock().unwrap().len();
    assert_eq!(session_count, count + 2);
    let grants = admin(admin_port, &admin_get("/admin/gateway/grants")).await;
    status(&grants, 200);
    let grants: Value = serde_json::from_slice(body(&grants)).unwrap();
    let session_id = grants["grants"]
        .as_array()
        .and_then(|values| values.iter().find(|grant| grant["scope"] == "session"))
        .and_then(|grant| grant["grant_id"].as_str())
        .unwrap();
    let revoked = admin(
        admin_port,
        &admin_delete(&format!("/admin/gateway/grants/{session_id}")),
    )
    .await;
    status(&revoked, 200);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let after_revoke = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&after_revoke, 428);
    assert_eq!(seen.lock().unwrap().len(), session_count);

    // Replacing the alpha binding with beta changes the live contract scope;
    // the token minted by the previous publication is rejected as stale.
    let stale_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let beta_binding = br#"{"agent":"alice","service":"contract","capability":"writer","template":"contract.write.v1","bindings":{"project":"beta","ticket":"T-2"},"grantable_operations":["write"]}"#;
    let replaced = admin(
        admin_port,
        &admin_request("/admin/gateway/contract-binding", beta_binding),
    )
    .await;
    status(&replaced, 200);
    let beta_grant =
        br#"{"agent":"alice","service":"contract","method":"POST","path":"/v1/write","lifetime":"once"}"#;
    let granted = admin(
        admin_port,
        &admin_request("/admin/gateway/grant", beta_grant),
    )
    .await;
    status(&granted, 200);
    let mut beta = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
            beta = gateway_call(
                &root_path.join("alice.sock"),
                port,
                &gateway_token,
                "POST",
                "/v1/write?ticket=T-2",
                br#"{"project":"beta"}"#,
            )
            .await;
            if beta.starts_with(b"HTTP/1.1 200") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    status(&beta, 200);
    let replacement_count = seen.lock().unwrap().len();
    assert_eq!(replacement_count, session_count + 1);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let old_values = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&old_values, 403);
    assert_eq!(seen.lock().unwrap().len(), replacement_count);
    let stale = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &stale_token,
        "POST",
        "/v1/write?ticket=T-2",
        br#"{"project":"beta"}"#,
    )
    .await;
    status(&stale, 403);
    assert_eq!(seen.lock().unwrap().len(), replacement_count);

    // Remove the persisted binding and let the process-owned watcher publish
    // the empty collection. The old route then disappears at the same live
    // admission boundary; no hand-built snapshot is injected by the test.
    let mut document = std::fs::read_to_string(root_path.join("policy.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    document["agents"]["alice"]["contract_bindings"] =
        toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    std::fs::write(root_path.join("policy.toml"), document.to_string()).unwrap();
    let mut removed = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
            removed = gateway_call(
                &root_path.join("alice.sock"),
                port,
                &gateway_token,
                "POST",
                "/v1/write?ticket=T-2",
                br#"{"project":"beta"}"#,
            )
            .await;
            if removed.starts_with(b"HTTP/1.1 403") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    status(&removed, 403);
    assert_eq!(seen.lock().unwrap().len(), replacement_count);
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    assert!(!audit.contains("exact-contract-origin-secret"));
    stop_tx.send(()).unwrap();
    watcher.await.unwrap();
    origin_task.abort();
}
