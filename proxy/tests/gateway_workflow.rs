use ring::digest::{SHA256, digest};
use safeyolo_proxy::{
    AgentListener, Config, Proxy,
    credentials::{Credential, Secret, Vault},
};
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::{Notify, mpsc, oneshot},
};
use tokio_rustls::{TlsAcceptor, rustls};

const PASS: &str = "synthetic-vault-passphrase";
fn initial_policy(origin_port: u16) -> String {
    format!(
        r#"
[hosts."127.0.0.1"]
service = "simple"

[hosts."127.0.0.1:{origin_port}"]
egress = "allow"

[hosts."*"]
egress = "deny"

[agents.alice]

[agents.bob]

[addons.credential_guard]
enabled = true
detection_level = "none"

[addons.credential_guard.settings]
use_default_credential_rules = false

[addons.credential_guard.settings.entropy]
min_length = 1000
"#
    )
}

fn deny_refreshed_credential_policy(origin_port: u16) -> String {
    initial_policy(origin_port)
        .replace("detection_level = \"none\"", "detection_level = \"standard\"")
        .replace(
            "use_default_credential_rules = false",
            "use_default_credential_rules = true",
        )
        .replace(
            "[hosts.\"127.0.0.1\"]\nservice = \"simple\"",
            "[hosts.\"127.0.0.1\"]\nservice = \"simple\"\nrules = [{ action = \"credential:use\", resource = \"127.0.0.1/*\", effect = \"deny\", condition = { credential = \"github-refresh:*\" } }]",
        )
}

fn budgeted_credential_policy(origin_port: u16) -> String {
    let mut source = deny_refreshed_credential_policy(origin_port);
    source.push_str(
        r#"
[credentials.unrelated]
patterns = ["unrelated-[a-z]+"]
headers = ["x-api-key"]

[[permissions]]
action = "credential:use"
resource = "127.0.0.1/*"
effect = "budget"
budget = 1
condition = { credential = "unrelated:*" }
"#,
    );
    source = source.replace(
        "[hosts.\"127.0.0.1\"]\nservice = \"simple\"",
        "[hosts.\"127.0.0.1\"]\nservice = \"simple\"\ncredentials = [\"unrelated:*\"]",
    );
    source
}

fn bound_gateway_policy(origin_port: u16) -> String {
    let mut source = initial_policy(origin_port);
    source.push_str(
        r#"
[agents.alice.services.simple]
capability = "reader"
token = "simple-secret"
"#,
    );
    source
}

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

const NO_AUTH_SERVICE: &str = r#"
schema_version: 1
name: simple
default_host: localhost
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

fn interception_ca(root: &Path, config: &mut Config) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let certificate = params.self_signed(&key).unwrap();
    let path = root.join("interception-ca.pem");
    std::fs::write(
        &path,
        format!("{}{}", key.serialize_pem(), certificate.pem()),
    )
    .unwrap();
    config.tls_ca_file = Some(path);
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

fn response_header(response: &[u8], name: &str) -> Option<String> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    std::str::from_utf8(&response[..split])
        .ok()?
        .lines()
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
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

async fn wait_for_audit_count(path: &Path, name: &str, request_id: &str, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(content) = std::fs::read_to_string(path) {
                let observed = content
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter(|event| event["event"] == name && event["request_id"] == request_id)
                    .count();
                if observed >= count {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {count} {name} audit events"));
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

async fn wait_for_gateway_outcome(path: &Path, outcome: &str) -> Value {
    loop {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Some(event) = content.lines().find_map(|line| {
                let value = serde_json::from_str::<Value>(line).ok()?;
                (value["event"] == "proxy.gateway" && value["outcome"] == outcome).then_some(value)
            })
        {
            return event;
        }
        tokio::task::yield_now().await;
    }
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
    send_agent_with_scheme(socket, port, token, host, "http").await
}

async fn send_agent_with_scheme(
    socket: &Path,
    port: u16,
    token: &str,
    host: &str,
    scheme: &str,
) -> Vec<u8> {
    let request = format!(
        "GET {scheme}://{host}:{port}/v1/value?sig=%252F HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    raw_http(socket, request.as_bytes()).await
}

async fn send_agent_with_unrelated_credential(
    socket: &Path,
    port: u16,
    token: &str,
    host: &str,
) -> Vec<u8> {
    let request = format!(
        "GET http://{host}:{port}/v1/value?sig=%252F HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nX-Api-Key: unrelated-synthetic\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    raw_http(socket, request.as_bytes()).await
}

async fn raw_http_without_timeout(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldRefreshPhase {
    BeforeRequest,
    Send,
    Body,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldParentPhase {
    ParentTls,
    Connect,
    OriginTls,
}

/// Run one refresh response through the complete native UDS gateway path. The
/// endpoint and origin are local TCP listeners, and the binding is loaded from
/// the real policy/vault files rather than a hand-built injection result.
async fn run_live_refresh_response_case(
    response_status: u16,
    response_body: &'static [u8],
    expected_reason: &'static str,
    save_failure: bool,
    activation_failure: bool,
    held_phase: Option<HeldRefreshPhase>,
) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let origin_task = tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port));
    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_seen = Arc::new(Mutex::new(Vec::new()));
    let token_ready = Arc::new(Notify::new());
    let token_release = Arc::new(Notify::new());
    let token_task = tokio::spawn({
        let token_seen = token_seen.clone();
        let token_ready = token_ready.clone();
        let token_release = token_release.clone();
        async move {
            let Ok((mut stream, _)) = token_listener.accept().await else {
                return;
            };
            if held_phase == Some(HeldRefreshPhase::BeforeRequest) {
                token_ready.notify_one();
                token_release.notified().await;
                return;
            }
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
                    let length = std::str::from_utf8(&request[..split])
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
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            token_seen.lock().unwrap().push(request);
            if activation_failure || held_phase == Some(HeldRefreshPhase::Send) {
                token_ready.notify_one();
                token_release.notified().await;
            }
            let response = format!(
                "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_status,
                response_body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            if held_phase == Some(HeldRefreshPhase::Body) {
                token_ready.notify_one();
                token_release.notified().await;
                return;
            }
            let _ = stream.write_all(response_body).await;
        }
    });

    std::fs::write(
        root_path.join("policy.toml"),
        bound_gateway_policy(origin_port),
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(format!("http://127.0.0.1:{token_port}/oauth/token"));
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();

    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    if save_failure {
        std::fs::remove_file(&vault_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();
    }
    if activation_failure {
        let request = tokio::spawn({
            let socket = socket.clone();
            let gateway_token = gateway_token.clone();
            async move { send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await }
        });
        tokio::time::timeout(Duration::from_secs(3), token_ready.notified())
            .await
            .expect("refresh request did not reach provider");
        let shutdown = tokio::spawn(proxy.shutdown());
        token_release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(3), request)
            .await
            .expect("activation failure request hung")
            .unwrap();
        status(&response, "503");
        assert!(String::from_utf8_lossy(&response).contains(expected_reason));
        assert!(origin_seen.lock().unwrap().is_empty());
        assert_eq!(token_seen.lock().unwrap().len(), 1);
        tokio::time::timeout(Duration::from_secs(3), shutdown)
            .await
            .expect("proxy shutdown hung during activation failure")
            .unwrap();
        wait_for_audit_event(&root_path.join("audit.jsonl"), "gateway.refresh_failed").await;
        let events = std::fs::read_to_string(root_path.join("events.jsonl")).unwrap();
        let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
        assert!(audit.contains(expected_reason));
        assert!(!events.contains("synthetic-activation-failed"));
        assert!(!audit.contains("synthetic-activation-failed"));
        assert_eq!(
            Vault::unlock(&vault_path, &Secret::new(PASS))
                .unwrap()
                .get("simple-secret")
                .unwrap()
                .unwrap()
                .value
                .expose_secret(),
            "synthetic-expired-access"
        );
        return;
    }
    if held_phase.is_some() {
        let request = tokio::spawn({
            let socket = socket.clone();
            let gateway_token = gateway_token.clone();
            async move {
                let request = format!(
                    "GET http://127.0.0.1:{origin_port}/v1/value?sig=%252F HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nAuthorization: Bearer {gateway_token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                raw_http_without_timeout(&socket, request.as_bytes()).await
            }
        });
        token_ready.notified().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;
        let response = request.await.unwrap();
        status(&response, "503");
        assert!(String::from_utf8_lossy(&response).contains(expected_reason));
        assert!(origin_seen.lock().unwrap().is_empty());
        assert_eq!(
            token_seen.lock().unwrap().len(),
            usize::from(held_phase != Some(HeldRefreshPhase::BeforeRequest))
        );
        token_release.notify_one();
        proxy.shutdown().await;
        origin_task.abort();
        token_task.abort();
        return;
    }
    let response = send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await;
    status(&response, "503");
    assert!(String::from_utf8_lossy(&response).contains(expected_reason));
    assert!(origin_seen.lock().unwrap().is_empty());
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    wait_for_audit_event(&root_path.join("audit.jsonl"), "gateway.refresh_failed").await;
    let events = std::fs::read_to_string(root_path.join("events.jsonl")).unwrap();
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    assert!(audit.contains("gateway.refresh_failed"));
    assert!(audit.contains(expected_reason));
    assert!(!events.contains("synthetic-expired-access"));
    assert!(!events.contains("synthetic-refresh"));
    assert!(!audit.contains("synthetic-expired-access"));
    assert!(!audit.contains("synthetic-refresh"));
    proxy.shutdown().await;
    origin_task.abort();
    token_task.abort();
}

/// Hold each configured parent transport boundary on the real refresh path.
/// The paused test clock keeps the production ten-second phase budget while
/// making parent TLS, CONNECT, and origin TLS timeout cases deterministic.
async fn run_live_parent_timeout_case(phase: HeldParentPhase) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let origin_release = Arc::new(Notify::new());
    let origin_ready = Arc::new(Notify::new());
    let origin_task = if phase == HeldParentPhase::OriginTls {
        let origin_release = origin_release.clone();
        let origin_ready = origin_ready.clone();
        Some(tokio::spawn(async move {
            let Ok((mut stream, _)) = origin_listener.accept().await else {
                return;
            };
            origin_ready.notify_waiters();
            origin_release.notified().await;
            let _ = stream.shutdown().await;
        }))
    } else {
        drop(origin_listener);
        None
    };

    let parent_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let parent_port = parent_listener.local_addr().unwrap().port();
    let parent_ready = Arc::new(Notify::new());
    let parent_release = Arc::new(Notify::new());
    let (parent_task, token_url, mut runtime_config) = if phase == HeldParentPhase::ParentTls {
        let parent_ready = parent_ready.clone();
        let parent_release = parent_release.clone();
        let task = tokio::spawn(async move {
            let Ok((_socket, _)) = parent_listener.accept().await else {
                return;
            };
            parent_ready.notify_one();
            parent_release.notified().await;
        });
        (
            task,
            "http://provider.invalid/oauth/token".to_owned(),
            config(root_path),
        )
    } else {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca_path = root_path.join("parent-ca.pem");
        std::fs::write(&ca_path, cert.pem()).unwrap();
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
        let parent_ready_for_task = parent_ready.clone();
        let parent_release_for_task = parent_release.clone();
        let origin_ready_for_task = origin_ready.clone();
        let task = tokio::spawn(async move {
            let Ok((socket, _)) = parent_listener.accept().await else {
                return;
            };
            let Ok(mut stream) = TlsAcceptor::from(Arc::new(tls)).accept(socket).await else {
                return;
            };
            let Some(request) = read_refresh_request(&mut stream).await else {
                return;
            };
            assert!(request.starts_with(b"CONNECT provider.invalid:"));
            if phase == HeldParentPhase::Connect {
                parent_ready_for_task.notify_one();
                parent_release_for_task.notified().await;
                return;
            }
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let Ok(mut origin) = TcpStream::connect(("127.0.0.1", origin_port)).await else {
                return;
            };
            origin_ready_for_task.notified().await;
            parent_ready_for_task.notify_one();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut origin).await;
        });
        let mut runtime_config = config(root_path);
        runtime_config.parent_proxy = Some(format!("https://localhost:{parent_port}"));
        runtime_config.upstream_ca_file = Some(ca_path);
        (
            task,
            format!("https://provider.invalid:{parent_port}/oauth/token"),
            runtime_config,
        )
    };
    if phase == HeldParentPhase::ParentTls {
        runtime_config.parent_proxy = Some(format!("https://127.0.0.1:{parent_port}"));
    }
    runtime_config.parent_proxy = runtime_config
        .parent_proxy
        .or_else(|| Some(format!("https://127.0.0.1:{parent_port}")));
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();
    std::fs::write(
        root_path.join("policy.toml"),
        bound_gateway_policy(origin_port),
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(token_url);
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();
    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(runtime_config).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = tokio::spawn({
        let socket = socket.clone();
        async move {
            let request = format!(
                "GET http://127.0.0.1:{origin_port}/v1/value HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nAuthorization: Bearer {gateway_token}\r\nConnection: close\r\n\r\n"
            );
            raw_http_without_timeout(&socket, request.as_bytes()).await
        }
    });
    if phase == HeldParentPhase::OriginTls {
        origin_ready.notified().await;
    } else {
        parent_ready.notified().await;
    }
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    let response = request.await.unwrap();
    status(&response, "503");
    assert!(String::from_utf8_lossy(&response).contains("REFRESH_TRANSPORT"));
    assert!(origin_seen.lock().unwrap().is_empty());
    parent_release.notify_one();
    origin_release.notify_one();
    proxy.shutdown().await;
    parent_task.abort();
    if let Some(origin_task) = origin_task {
        origin_task.abort();
    }
}

#[derive(Clone, Copy)]
enum LiveVaultMutation {
    Edit,
    Delete,
    Replace,
    AdverseGeneration,
    Malformed,
    Empty,
    SaltChanged,
}

/// Hold the provider response while the native vault is edited through each
/// stale-generation path. The response must be rejected as superseded and the
/// replacement token must never reach either the vault or the origin.
async fn run_live_superseded_case(mutation: LiveVaultMutation) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port));
    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_seen = Arc::new(Mutex::new(Vec::new()));
    let token_ready = Arc::new(Notify::new());
    let token_release = Arc::new(Notify::new());
    let token_task = tokio::spawn({
        let token_seen = token_seen.clone();
        let token_ready = token_ready.clone();
        let token_release = token_release.clone();
        async move {
            let Ok((mut stream, _)) = token_listener.accept().await else {
                return;
            };
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
                    let length = std::str::from_utf8(&request[..split])
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
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            token_seen.lock().unwrap().push(request);
            token_ready.notify_one();
            token_release.notified().await;
            let body = br#"{"access_token":"synthetic-refresh-result","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        }
    });
    std::fs::write(
        root_path.join("policy.toml"),
        bound_gateway_policy(origin_port),
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(format!("http://127.0.0.1:{token_port}/oauth/token"));
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth.clone()).unwrap();
    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = tokio::spawn({
        let socket = socket.clone();
        async move { send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await }
    });
    tokio::time::timeout(Duration::from_secs(3), token_ready.notified())
        .await
        .expect("refresh request did not reach provider");
    let edited = {
        let mut credential = oauth.clone();
        credential.value = Secret::new("synthetic-external-edit");
        credential
    };
    match mutation {
        LiveVaultMutation::Edit => vault.store(edited.clone()).unwrap(),
        LiveVaultMutation::Delete => {
            vault.remove("simple-secret").unwrap();
        }
        LiveVaultMutation::Replace => vault
            .store(Credential::new(
                "simple-secret",
                "bearer",
                Secret::new("synthetic-replacement"),
            ))
            .unwrap(),
        LiveVaultMutation::AdverseGeneration => {
            vault.remove("simple-secret").unwrap();
            vault.store(edited.clone()).unwrap();
        }
        LiveVaultMutation::Malformed => {
            std::fs::write(&vault_path, b"malformed-vault").unwrap();
        }
        LiveVaultMutation::Empty => {
            std::fs::write(&vault_path, []).unwrap();
        }
        LiveVaultMutation::SaltChanged => {
            let alternate_path = root_path.join("alternate-vault.yaml.enc");
            let alternate = Vault::unlock(&alternate_path, &Secret::new(PASS)).unwrap();
            alternate.store(edited.clone()).unwrap();
            std::fs::copy(alternate_path, &vault_path).unwrap();
        }
    }
    token_release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(3), request)
        .await
        .expect("superseded request hung")
        .unwrap();
    status(&response, "503");
    assert!(String::from_utf8_lossy(&response).contains("REFRESH_SUPERSEDED"));
    assert!(origin_seen.lock().unwrap().is_empty());
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    match mutation {
        LiveVaultMutation::Malformed | LiveVaultMutation::Empty => {
            assert!(Vault::unlock(&vault_path, &Secret::new(PASS)).is_err());
        }
        LiveVaultMutation::SaltChanged => assert_eq!(
            Vault::unlock(&vault_path, &Secret::new(PASS))
                .unwrap()
                .get("simple-secret")
                .unwrap()
                .unwrap()
                .value
                .expose_secret(),
            "synthetic-external-edit"
        ),
        mutation => {
            let current = Vault::unlock(&vault_path, &Secret::new(PASS))
                .unwrap()
                .get("simple-secret")
                .unwrap();
            match mutation {
                LiveVaultMutation::Delete => assert!(current.is_none()),
                LiveVaultMutation::Replace => assert_eq!(
                    current.unwrap().value.expose_secret(),
                    "synthetic-replacement"
                ),
                LiveVaultMutation::Edit | LiveVaultMutation::AdverseGeneration => assert_eq!(
                    current.unwrap().value.expose_secret(),
                    "synthetic-external-edit"
                ),
                _ => unreachable!(),
            }
        }
    }
    let events = std::fs::read_to_string(root_path.join("events.jsonl")).unwrap();
    assert!(events.contains("REFRESH_SUPERSEDED"));
    wait_for_audit_event(&root_path.join("audit.jsonl"), "gateway.refresh_failed").await;
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    assert!(!audit.contains("synthetic-refresh-result"));
    proxy.shutdown().await;
    origin_task.abort();
    token_task.abort();
}

/// Exercise refresh waiters over the real request owner. One case cancels a
/// follower while the leader is held; the other shuts down the only waiter
/// while its provider response is held. Both cases must release their owned
/// work without publishing a token or sending an origin request after cancel.
async fn run_live_cancellation_case(shutdown: bool) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port));
    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_seen = Arc::new(Mutex::new(Vec::new()));
    let token_ready = Arc::new(Notify::new());
    let token_release = Arc::new(Notify::new());
    let token_task = tokio::spawn({
        let token_seen = token_seen.clone();
        let token_ready = token_ready.clone();
        let token_release = token_release.clone();
        async move {
            let Ok((mut stream, _)) = token_listener.accept().await else {
                return;
            };
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
                    let length = std::str::from_utf8(&request[..split])
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
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            token_seen.lock().unwrap().push(request);
            token_ready.notify_one();
            token_release.notified().await;
            let body = br#"{"access_token":"synthetic-cancel-result","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        }
    });
    std::fs::write(
        root_path.join("policy.toml"),
        bound_gateway_policy(origin_port),
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(format!("http://127.0.0.1:{token_port}/oauth/token"));
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();
    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let leader = tokio::spawn({
        let socket = socket.clone();
        let gateway_token = gateway_token.clone();
        async move { send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await }
    });
    tokio::time::timeout(Duration::from_secs(3), token_ready.notified())
        .await
        .expect("refresh request did not reach provider");
    if shutdown {
        // Cancel the only waiter while the response is held, then shut down
        // the process owner. Releasing the provider latch lets its native
        // listener task finish after the request owner has disappeared.
        leader.abort();
        proxy.shutdown().await;
        token_release.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(3), leader).await;
        assert!(origin_seen.lock().unwrap().is_empty());
        assert_eq!(token_seen.lock().unwrap().len(), 1);
    } else {
        let follower = tokio::spawn({
            let socket = socket.clone();
            let gateway_token = gateway_token.clone();
            async move { send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await }
        });
        tokio::time::timeout(
            Duration::from_secs(3),
            wait_for_gateway_outcome(&root_path.join("events.jsonl"), "refresh_follower"),
        )
        .await
        .expect("follower did not join the held refresh");
        follower.abort();
        token_release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(3), leader)
            .await
            .expect("leader hung after follower cancellation")
            .unwrap();
        status(&response, "200");
        tokio::time::timeout(Duration::from_secs(3), async {
            while origin_seen.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(origin_seen.lock().unwrap().len(), 1);
        assert_eq!(token_seen.lock().unwrap().len(), 1);
        proxy.shutdown().await;
    }
    origin_task.abort();
    token_task.abort();
}

async fn read_refresh_request<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let size = stream.read(&mut buffer).await.ok()?;
        if size == 0 {
            return None;
        }
        request.extend_from_slice(&buffer[..size]);
        if let Some(split) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let length = std::str::from_utf8(&request[..split])
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
            if request.len() >= split + 4 + length {
                return Some(request);
            }
        }
    }
}

async fn serve_refresh_response<S>(
    mut stream: S,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    origin_port: Option<u16>,
    parent_connects: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    refresh_origin_port: Option<u16>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(request) = read_refresh_request(&mut stream).await else {
        return;
    };
    let is_refresh = request.starts_with(b"POST ");
    if is_refresh {
        seen.lock().unwrap().push(request.clone());
    }
    if request.starts_with(b"CONNECT ")
        && let Some(origin_port) = origin_port
    {
        if let Some(parent_connects) = parent_connects {
            parent_connects.lock().unwrap().push(request.clone());
        }
        let target = request
            .split(|byte| *byte == b'\r' || *byte == b'\n')
            .next()
            .unwrap_or_default();
        let origin_port = if target.starts_with(b"CONNECT provider.invalid:") {
            refresh_origin_port.unwrap_or(origin_port)
        } else {
            origin_port
        };
        let Ok(mut origin) = tokio::net::TcpStream::connect(("127.0.0.1", origin_port)).await
        else {
            return;
        };
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut origin).await;
        return;
    }
    if !is_refresh && let Some(origin_port) = origin_port {
        let Ok(mut origin) = tokio::net::TcpStream::connect(("127.0.0.1", origin_port)).await
        else {
            return;
        };
        if origin.write_all(&request).await.is_err() {
            return;
        }
        let mut response = Vec::new();
        if origin.read_to_end(&mut response).await.is_err() {
            return;
        }
        let _ = stream.write_all(&response).await;
        return;
    }
    let body = if is_refresh {
        &br#"{"access_token":"synthetic-route-result","expires_in":3600}"#[..]
    } else {
        &b"ok"[..]
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
}

async fn serve_origin_response<S>(mut stream: S, seen: Arc<Mutex<Vec<Vec<u8>>>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(request) = read_refresh_request(&mut stream).await else {
        return;
    };
    seen.lock().unwrap().push(request);
    let body = b"ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
}

#[derive(Clone, Copy, Debug)]
enum LiveRefreshRoute {
    DirectTls,
    ParentHttp,
    ParentTls,
}

/// Drive refresh through direct HTTPS and both configured parent transport
/// forms. Each case uses the production egress route and a controlled native
/// server, then verifies the replacement reaches the origin only once.
async fn run_live_refresh_route_case(route: LiveRefreshRoute) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let (origin_task, origin_certificate) = if matches!(route, LiveRefreshRoute::ParentTls) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_pem = cert.pem();
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
        let seen = origin_seen.clone();
        let task = tokio::spawn(async move {
            let Ok((socket, _)) = origin_listener.accept().await else {
                return;
            };
            let Ok(stream) = TlsAcceptor::from(Arc::new(tls)).accept(socket).await else {
                return;
            };
            serve_origin_response(stream, seen).await;
        });
        (task, Some(certificate_pem))
    } else {
        (
            tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port)),
            None,
        )
    };
    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_seen = Arc::new(Mutex::new(Vec::new()));
    let parent_connects = Arc::new(Mutex::new(Vec::new()));
    let mut runtime_config = config(root_path);
    let token_url = match route {
        LiveRefreshRoute::DirectTls => {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let ca_path = root_path.join("refresh-ca.pem");
            std::fs::write(&ca_path, cert.pem()).unwrap();
            runtime_config.upstream_ca_file = Some(ca_path);
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
            let token_seen_for_tls = token_seen.clone();
            tokio::spawn(async move {
                let Ok((socket, _)) = token_listener.accept().await else {
                    return;
                };
                let Ok(stream) = TlsAcceptor::from(Arc::new(tls)).accept(socket).await else {
                    return;
                };
                serve_refresh_response(stream, token_seen_for_tls, None, None, None).await;
            });
            format!("https://localhost:{token_port}/oauth/token")
        }
        LiveRefreshRoute::ParentHttp => {
            let parent_port = token_listener.local_addr().unwrap().port();
            runtime_config.parent_proxy = Some(format!("http://127.0.0.1:{parent_port}"));
            let seen = token_seen.clone();
            tokio::spawn(async move {
                while let Ok((socket, _)) = token_listener.accept().await {
                    serve_refresh_response(socket, seen.clone(), Some(origin_port), None, None)
                        .await;
                }
            });
            "http://provider.invalid/oauth/token".into()
        }
        LiveRefreshRoute::ParentTls => {
            interception_ca(root_path, &mut runtime_config);
            let token_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let token_origin_port = token_origin_listener.local_addr().unwrap().port();
            let rcgen::CertifiedKey {
                cert: token_cert,
                signing_key: token_signing_key,
            } = rcgen::generate_simple_self_signed(vec!["provider.invalid".into()]).unwrap();
            let token_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![token_cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(token_signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
            let seen = token_seen.clone();
            tokio::spawn(async move {
                let Ok((socket, _)) = token_origin_listener.accept().await else {
                    return;
                };
                let Ok(stream) = TlsAcceptor::from(Arc::new(token_tls)).accept(socket).await else {
                    return;
                };
                serve_refresh_response(stream, seen, None, None, None).await;
            });
            let token_origin_port_for_parent = token_origin_port;
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let ca_path = root_path.join("parent-refresh-ca.pem");
            let mut trust = cert.pem();
            trust.push_str(&token_cert.pem());
            if let Some(origin_certificate) = origin_certificate.as_ref() {
                trust.push_str(origin_certificate);
            }
            std::fs::write(&ca_path, trust).unwrap();
            runtime_config.upstream_ca_file = Some(ca_path);
            runtime_config.parent_proxy = Some(format!("https://localhost:{token_port}"));
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
            let seen = token_seen.clone();
            let parent_connects_for_task = parent_connects.clone();
            tokio::spawn(async move {
                let acceptor = TlsAcceptor::from(Arc::new(tls));
                while let Ok((socket, _)) = token_listener.accept().await {
                    let Ok(stream) = acceptor.accept(socket).await else {
                        continue;
                    };
                    serve_refresh_response(
                        stream,
                        seen.clone(),
                        Some(origin_port),
                        Some(parent_connects_for_task.clone()),
                        Some(token_origin_port_for_parent),
                    )
                    .await;
                }
            });
            format!("https://provider.invalid:{token_origin_port}/oauth/token")
        }
    };
    std::fs::write(
        root_path.join("policy.toml"),
        if matches!(route, LiveRefreshRoute::ParentTls) {
            bound_gateway_policy(origin_port).replace("127.0.0.1", "localhost")
        } else {
            bound_gateway_policy(origin_port)
        },
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(token_url);
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();
    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(runtime_config).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = if matches!(route, LiveRefreshRoute::ParentTls) {
        send_agent_with_scheme(&socket, origin_port, &gateway_token, "localhost", "https").await
    } else {
        send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await
    };
    status(&response, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin_seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(origin_seen.lock().unwrap().len(), 1);
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    assert!(
        origin_seen.lock().unwrap()[0]
            .windows(b"Authorization: Bearer synthetic-route-result".len())
            .any(|window| window == b"Authorization: Bearer synthetic-route-result")
    );
    if matches!(route, LiveRefreshRoute::ParentTls) {
        let connects = parent_connects.lock().unwrap();
        assert_eq!(connects.len(), 2);
        assert!(
            connects
                .iter()
                .any(|request| request.starts_with(b"CONNECT provider.invalid:"))
        );
        assert!(
            connects
                .iter()
                .any(|request| request.starts_with(b"CONNECT localhost:"))
        );
        assert!(origin_seen.lock().unwrap()[0].starts_with(b"GET /v1/value"));
    }
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn oauth_refresh_live_invalid_expiry_and_http_failures_are_categorical() {
    run_live_refresh_response_case(
        200,
        br#"{"access_token":42}"#,
        "REFRESH_INVALID_RESPONSE",
        false,
        false,
        None,
    )
    .await;
    run_live_refresh_response_case(
        200,
        br#"{"access_token":"synthetic-new","expires_in":"never"}"#,
        "REFRESH_EXPIRY",
        false,
        false,
        None,
    )
    .await;
    run_live_refresh_response_case(
        401,
        br#"{"error":"invalid_grant","access_token":"synthetic-leaked"}"#,
        "REFRESH_INVALID_RESPONSE",
        false,
        false,
        None,
    )
    .await;
    run_live_refresh_response_case(
        200,
        br#"{"access_token":"synthetic-new","expires_in":3600}"#,
        "REFRESH_SAVE",
        true,
        false,
        None,
    )
    .await;
}

#[tokio::test]
async fn oauth_refresh_live_activation_failure_blocks_before_injection() {
    run_live_refresh_response_case(
        200,
        br#"{"access_token":"synthetic-activation-failed","expires_in":3600}"#,
        "REFRESH_ACTIVATION",
        false,
        true,
        None,
    )
    .await;
}

#[tokio::test]
async fn oauth_refresh_live_distinct_candidates_rollback_after_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    let refresh_service = |name: &str, host: &str| {
        SERVICE
            .replace("name: simple", &format!("name: {name}"))
            .replace("default_host: 127.0.0.1", &format!("default_host: {host}"))
            .replace(
                "allow_http: true",
                "allow_http: true\n  refresh_on_401: true",
            )
    };
    std::fs::write(
        root_path.join("services/one.yaml"),
        refresh_service("one", "127.0.0.1"),
    )
    .unwrap();
    std::fs::write(
        root_path.join("services/two.yaml"),
        refresh_service("two", "127.0.0.2"),
    )
    .unwrap();

    let origin_one = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_one_port = origin_one.local_addr().unwrap().port();
    let origin_two = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let origin_two_port = origin_two.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let origin_one_task = tokio::spawn(origin(origin_one, origin_seen.clone(), origin_one_port));
    let origin_two_task = tokio::spawn(origin(origin_two, origin_seen.clone(), origin_two_port));

    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let both_ready = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let token_task = tokio::spawn({
        let token_seen = token_seen.clone();
        let both_ready = both_ready.clone();
        let release = release.clone();
        async move {
            for _ in 0..2 {
                let Ok((mut stream, _)) = token_listener.accept().await else {
                    return;
                };
                let token_seen = token_seen.clone();
                let both_ready = both_ready.clone();
                let release = release.clone();
                tokio::spawn(async move {
                    let Some(request) = read_refresh_request(&mut stream).await else {
                        return;
                    };
                    let ready = {
                        let mut seen = token_seen.lock().unwrap();
                        seen.push(request);
                        seen.len() == 2
                    };
                    if ready {
                        both_ready.notify_one();
                    }
                    release.notified().await;
                    let response_body =
                        b"{\"access_token\":\"synthetic-shutdown-failed\",\"expires_in\":3600}";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(response_body).await;
                });
            }
        }
    });

    let policy = format!(
        r#"
[hosts."127.0.0.1"]
service = "one"

[hosts."127.0.0.1:{origin_one_port}"]
egress = "allow"

[hosts."127.0.0.2"]
service = "two"

[hosts."127.0.0.2:{origin_two_port}"]
egress = "allow"

[hosts."*"]
egress = "deny"

[agents.alice]

[agents.bob]

[agents.alice.services.one]
capability = "reader"
token = "one-secret"

[agents.alice.services.two]
capability = "reader"
token = "two-secret"

[addons.credential_guard]
enabled = true
detection_level = "none"

[addons.credential_guard.settings]
use_default_credential_rules = false

[addons.credential_guard.settings.entropy]
min_length = 1000
"#
    );
    std::fs::write(root_path.join("policy.toml"), policy).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    for (name, old, refresh) in [
        ("one-secret", "synthetic-one-old", "synthetic-one-refresh"),
        ("two-secret", "synthetic-two-old", "synthetic-two-refresh"),
    ] {
        let mut oauth = Credential::new(name, "oauth2", Secret::new(old));
        oauth.refresh_token = Some(Secret::new(refresh));
        oauth.token_url = Some(format!("http://127.0.0.1:{token_port}/oauth/token"));
        oauth.client_id = Some("synthetic-client".into());
        oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
        oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
        vault.store(oauth).unwrap();
    }

    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let view = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let request = b"GET http://_safeyolo.proxy.internal/gateway/services HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer agent-token\r\nConnection: close\r\n\r\n";
            let response = raw_http(&socket, request).await;
            if response.starts_with(b"HTTP/1.1 200") {
                let value: Value = serde_json::from_slice(body(&response)).unwrap();
                if value["authorized"]["one"]["token"].as_str().is_some()
                    && value["authorized"]["two"]["token"].as_str().is_some()
                {
                    return value;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let one_token = view["authorized"]["one"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let two_token = view["authorized"]["two"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let first = tokio::spawn({
        let socket = socket.clone();
        async move {
            let request = format!(
                "GET http://127.0.0.1:{origin_one_port}/v1/value HTTP/1.1\r\nHost: 127.0.0.1:{origin_one_port}\r\nAuthorization: Bearer {one_token}\r\nConnection: close\r\n\r\n"
            );
            raw_http_without_timeout(&socket, request.as_bytes()).await
        }
    });
    let second = tokio::spawn({
        let socket = socket.clone();
        async move {
            let request = format!(
                "GET http://127.0.0.2:{origin_two_port}/v1/value HTTP/1.1\r\nHost: 127.0.0.2:{origin_two_port}\r\nAuthorization: Bearer {two_token}\r\nConnection: close\r\n\r\n"
            );
            raw_http_without_timeout(&socket, request.as_bytes()).await
        }
    });
    tokio::time::timeout(Duration::from_secs(3), both_ready.notified())
        .await
        .expect("both distinct refreshes did not reach provider");
    let shutdown = tokio::spawn(proxy.shutdown());
    tokio::task::yield_now().await;
    release.notify_waiters();
    let first_response = tokio::time::timeout(Duration::from_secs(3), first)
        .await
        .unwrap()
        .unwrap();
    let second_response = tokio::time::timeout(Duration::from_secs(3), second)
        .await
        .unwrap()
        .unwrap();
    status(&first_response, "503");
    status(&second_response, "503");
    assert!(String::from_utf8_lossy(&first_response).contains("REFRESH_ACTIVATION"));
    assert!(String::from_utf8_lossy(&second_response).contains("REFRESH_ACTIVATION"));
    assert!(origin_seen.lock().unwrap().is_empty());
    let (request_count, saw_one, saw_two) = {
        let requests = token_seen.lock().unwrap();
        (
            requests.len(),
            requests.iter().any(|request| {
                request
                    .windows(b"synthetic-one-refresh".len())
                    .any(|window| window == b"synthetic-one-refresh")
            }),
            requests.iter().any(|request| {
                request
                    .windows(b"synthetic-two-refresh".len())
                    .any(|window| window == b"synthetic-two-refresh")
            }),
        )
    };
    assert_eq!(request_count, 2);
    assert!(saw_one);
    assert!(saw_two);
    tokio::time::timeout(Duration::from_secs(3), shutdown)
        .await
        .expect("shutdown with two rejected candidates hung")
        .unwrap();
    let retained = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    assert_eq!(
        retained
            .get("one-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-one-old"
    );
    assert_eq!(
        retained
            .get("two-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-two-old"
    );
    let events = std::fs::read_to_string(root_path.join("events.jsonl")).unwrap();
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    assert_eq!(audit.matches("REFRESH_ACTIVATION").count(), 2);
    assert!(!events.contains("synthetic-shutdown-failed"));
    assert!(!audit.contains("synthetic-shutdown-failed"));
    origin_one_task.abort();
    origin_two_task.abort();
    token_task.abort();
}

#[tokio::test]
async fn oauth_refresh_live_held_send_and_body_phases_timeout() {
    tokio::time::pause();
    run_live_refresh_response_case(
        200,
        br#"{"access_token":"synthetic-handshake-timeout","expires_in":3600}"#,
        "REFRESH_TRANSPORT",
        false,
        false,
        Some(HeldRefreshPhase::BeforeRequest),
    )
    .await;
    run_live_refresh_response_case(
        200,
        br#"{"access_token":"synthetic-send-timeout","expires_in":3600}"#,
        "REFRESH_TRANSPORT",
        false,
        false,
        Some(HeldRefreshPhase::Send),
    )
    .await;
    run_live_refresh_response_case(
        200,
        br#"{"access_token":"synthetic-body-timeout","expires_in":3600}"#,
        "REFRESH_TRANSPORT",
        false,
        false,
        Some(HeldRefreshPhase::Body),
    )
    .await;
    run_live_parent_timeout_case(HeldParentPhase::ParentTls).await;
    run_live_parent_timeout_case(HeldParentPhase::Connect).await;
    run_live_parent_timeout_case(HeldParentPhase::OriginTls).await;
}

#[tokio::test]
async fn oauth_refresh_live_stale_edit_delete_replace_and_adverse_generation() {
    for mutation in [
        LiveVaultMutation::Edit,
        LiveVaultMutation::Delete,
        LiveVaultMutation::Replace,
        LiveVaultMutation::AdverseGeneration,
    ] {
        run_live_superseded_case(mutation).await;
    }
}

#[tokio::test]
async fn oauth_refresh_live_malformed_empty_and_salt_change_fail_closed() {
    for mutation in [
        LiveVaultMutation::Malformed,
        LiveVaultMutation::Empty,
        LiveVaultMutation::SaltChanged,
    ] {
        run_live_superseded_case(mutation).await;
    }
}

#[test]
fn native_live_vault_lock_unlock_and_d38_rollback_retain_external_state() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("vault.yaml.enc");
    let vault = Vault::unlock(&path, &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "simple-secret",
            "bearer",
            Secret::new("synthetic-original"),
        ))
        .unwrap();
    assert!(Vault::unlock(&path, &Secret::new("wrong-passphrase")).is_err());
    assert_eq!(
        Vault::unlock(&path, &Secret::new(PASS))
            .unwrap()
            .get("simple-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-original"
    );

    let snapshot = vault.snapshot("simple-secret").unwrap().unwrap();
    let external = Vault::unlock(&path, &Secret::new(PASS)).unwrap();
    external
        .store(Credential::new(
            "simple-secret",
            "bearer",
            Secret::new("synthetic-external"),
        ))
        .unwrap();
    let mut activation_calls = 0;
    let activation = vault.store_with_activation(
        Credential::new("other-secret", "bearer", Secret::new("synthetic-unrelated")),
        |_| {
            activation_calls += 1;
            (activation_calls > 1).then_some(()).ok_or(())
        },
    );
    assert!(matches!(
        activation,
        Err(safeyolo_proxy::credentials::VaultError {
            kind: safeyolo_proxy::credentials::ErrorKind::Activation,
            ..
        })
    ));
    let attempted = vault.replace_if_current(
        &snapshot,
        Credential::new(
            "simple-secret",
            "bearer",
            Secret::new("synthetic-late-refresh"),
        ),
        |_| Ok(()),
    );
    assert!(!attempted.unwrap());
    assert_eq!(
        Vault::unlock(&path, &Secret::new(PASS))
            .unwrap()
            .get("simple-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-external"
    );
}

#[tokio::test]
async fn oauth_refresh_live_follower_cancel_and_last_waiter_shutdown() {
    run_live_cancellation_case(false).await;
    run_live_cancellation_case(true).await;
}

#[tokio::test]
async fn oauth_refresh_live_direct_tls_and_parent_routes() {
    run_live_refresh_route_case(LiveRefreshRoute::DirectTls).await;
    run_live_refresh_route_case(LiveRefreshRoute::ParentHttp).await;
    run_live_refresh_route_case(LiveRefreshRoute::ParentTls).await;
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
    let wrong_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wrong_port = wrong_listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let wrong_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, seen.clone(), origin_port));
    let wrong_origin_task = tokio::spawn(origin(wrong_listener, wrong_seen.clone(), origin_port));
    std::fs::write(root_path.join("policy.toml"), initial_policy(origin_port)).unwrap();

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
    status(&followed, "403");
    assert_eq!(seen.lock().unwrap().len(), 4);

    // Port is part of the existing network policy. A live second listener on
    // the same allowed host is denied before gateway injection, and therefore
    // observes no request or credential. The gateway adds no port policy.
    let wrong_port_response = send_agent(
        &root_path.join("alice.sock"),
        wrong_port,
        &current_token,
        "127.0.0.1",
    )
    .await;
    status(&wrong_port_response, "403");
    let wrong_port_request_id = response_header(&wrong_port_response, "x-safeyolo-request-id")
        .expect("network denial must be correlated");
    assert_eq!(seen.lock().unwrap().len(), 4);
    assert!(wrong_seen.lock().unwrap().is_empty());

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
    status(&wrong_destination, "403");
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
    std::fs::write(root_path.join("policy.toml"), initial_policy(origin_port)).unwrap();
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
    let event_rows: Vec<Value> = events
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(event_rows.iter().any(|row| {
        row["event"] == "proxy.network_guard"
            && row["request_id"] == wrong_port_request_id
            && row["port"] == wrong_port
            && row["outcome"] == "blocked"
    }));
    assert!(!event_rows.iter().any(|row| {
        row["event"] == "proxy.gateway" && row["request_id"] == wrong_port_request_id
    }));
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
    wrong_origin_task.abort();
}

/// The gateway's expired OAuth path is exercised through the real UDS listener,
/// watcher publication and two controlled TCP origins. The token endpoint is
/// intentionally delayed so the second request must join the first flight.
#[tokio::test]
async fn oauth_refresh_reaches_origin_once_and_shared_flight_reuses_token() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port));
    let token_seen = Arc::new(Mutex::new(Vec::new()));
    let token_ready = Arc::new(Notify::new());
    let token_release = Arc::new(Notify::new());
    let token_task = tokio::spawn({
        let token_seen = token_seen.clone();
        let token_ready = token_ready.clone();
        let token_release = token_release.clone();
        async move {
            loop {
                let Ok((mut stream, _)) = token_listener.accept().await else {
                    return;
                };
                let token_seen = token_seen.clone();
                let token_ready = token_ready.clone();
                let token_release = token_release.clone();
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
                        let Some(split) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let length = std::str::from_utf8(&request[..split])
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
                        if request.len() >= split + 4 + length {
                            break;
                        }
                    }
                    token_seen.lock().unwrap().push(request);
                    token_ready.notify_one();
                    // Hold the response until the test has observed a follower
                    // on the reloaded Runtime. This is a release latch rather
                    // than a scheduler sleep, so one POST and shared ownership
                    // are deterministic.
                    token_release.notified().await;
                    let body =
                        br#"{"access_token":"synthetic-refreshed-access","expires_in":3600}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        }
    });

    std::fs::write(root_path.join("policy.toml"), initial_policy(origin_port)).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(format!("http://127.0.0.1:{token_port}/oauth/token"));
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2099-01-01T00:00:00+00:00".into());
    vault.store(oauth.clone()).unwrap();

    let socket = root_path.join("alice.sock");
    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let pending = raw_http(&socket, &request_access()).await;
    status(&pending, "202");
    let event =
        wait_for_audit_event(&root_path.join("audit.jsonl"), "gateway.request_access").await;
    let approval = approve_service_with_existing_consumer(root_path, &event, "simple-secret");
    assert!(
        approval.status.success(),
        "{}",
        String::from_utf8_lossy(&approval.stderr)
    );
    let authorized = admin_http(admin_port, &admin_request(root_path)).await;
    status(&authorized, "200");

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (reload_tx, mut reload_rx) =
        mpsc::unbounded_channel::<oneshot::Sender<Result<(), String>>>();
    let reload_config = config(root_path);
    let watcher = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => { proxy.shutdown().await; break; }
                Some(done) = reload_rx.recv() => {
                    let result = proxy.reload(reload_config.clone()).await.map_err(|error| error.to_string());
                    let _ = done.send(result);
                }
                _ = proxy.wait_for_service_catalog_check() => { let _ = proxy.reload_services_if_changed().await; }
                _ = proxy.wait_for_policy_check() => { let _ = proxy.reload_policy_if_changed().await; }
            }
        }
    });
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let current = send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await;
    status(&current, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin_seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(token_seen.lock().unwrap().is_empty());
    assert!(
        origin_seen.lock().unwrap()[0]
            .windows(b"Authorization: Bearer synthetic-expired-access".len())
            .any(|window| window == b"Authorization: Bearer synthetic-expired-access")
    );

    // An external vault edit is picked up at the native request boundary. The
    // same process then takes the refresh path for the next pair of requests.
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();

    let first = tokio::spawn({
        let socket = socket.clone();
        let gateway_token = gateway_token.clone();
        async move { send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await }
    });
    if tokio::time::timeout(Duration::from_secs(2), token_ready.notified())
        .await
        .is_err()
    {
        eprintln!(
            "token request timed out; events: {}",
            std::fs::read_to_string(root_path.join("events.jsonl")).unwrap_or_default()
        );
        eprintln!("token rows: {:?}", token_seen.lock().unwrap());
        panic!("token endpoint was not reached");
    }
    let (reload_done, reload_result) = oneshot::channel::<Result<(), String>>();
    reload_tx.send(reload_done).unwrap();
    reload_result.await.unwrap().unwrap();
    let reloaded_view = wait_for_alice(&socket).await;
    let reloaded_token = reloaded_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(reloaded_token, gateway_token);
    let gateway_token = reloaded_token;
    let second = tokio::spawn({
        let socket = socket.clone();
        let gateway_token = gateway_token.clone();
        async move { send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await }
    });
    let follower_observed = tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_gateway_outcome(&root_path.join("events.jsonl"), "refresh_follower"),
    )
    .await;
    token_release.notify_one();
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    let second = second.unwrap();
    assert!(
        follower_observed.is_ok(),
        "follower did not join shared flight; events: {}",
        std::fs::read_to_string(root_path.join("events.jsonl")).unwrap_or_default()
    );
    status(&first, "200");
    status(&second, "200");
    assert_eq!(body(&first), b"ok");
    assert_eq!(body(&second), b"ok");
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin_seen.lock().unwrap().len() < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    assert!(
        token_seen.lock().unwrap()[0]
            .windows(b"refresh_token=synthetic-refresh".len())
            .any(|window| window == b"refresh_token=synthetic-refresh")
    );
    {
        let requests = origin_seen.lock().unwrap();
        assert!(requests[1..].iter().all(|request| {
            request
                .windows(b"Authorization: Bearer synthetic-refreshed-access".len())
                .any(|window| window == b"Authorization: Bearer synthetic-refreshed-access")
        }));
    }

    // The accepted expiry is persisted in the encrypted vault. A later request
    // is current-token delivery and cannot contact the token endpoint again.
    let third = send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await;
    status(&third, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin_seen.lock().unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    let reopened = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    assert_eq!(
        reopened
            .get("simple-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-refreshed-access"
    );

    let _ = stop_tx.send(());
    watcher.await.unwrap();
    proxy = Proxy::start(config(root_path)).await.unwrap();
    let restarted_view = wait_for_alice(&socket).await;
    let restarted_token = restarted_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let stale = send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await;
    status(&stale, "403");
    let after_restart = send_agent(&socket, origin_port, &restarted_token, "127.0.0.1").await;
    status(&after_restart, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin_seen.lock().unwrap().len() < 5 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    proxy.shutdown().await;
    origin_task.abort();
    token_task.abort();
}

/// A refreshed credential is checked on the actual native forwarding path. The
/// policy uses the shipped GitHub refresh pattern and denies `credential:use`;
/// the controlled origin must never receive a request or the replacement.
#[tokio::test]
async fn gateway_refreshed_github_credential_use_deny_blocks_before_origin() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(
        root_path.join("services/simple.yaml"),
        SERVICE.replace(
            "allow_http: true",
            "allow_http: true\n  refresh_on_401: true",
        ),
    )
    .unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port));
    let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_port = token_listener.local_addr().unwrap().port();
    let token_seen = Arc::new(Mutex::new(Vec::new()));
    let token_task = tokio::spawn({
        let token_seen = token_seen.clone();
        async move {
            let Ok((mut stream, _)) = token_listener.accept().await else {
                return;
            };
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
                    let length = std::str::from_utf8(&request[..split])
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
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            token_seen.lock().unwrap().push(request);
            let body =
                br#"{"access_token":"ghr_synthetic_refreshed_access_token_value_123456","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        }
    });

    std::fs::write(
        root_path.join("policy.toml"),
        budgeted_credential_policy(origin_port),
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    let mut oauth = Credential::new(
        "simple-secret",
        "oauth2",
        Secret::new("synthetic-expired-access"),
    );
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some(format!("http://127.0.0.1:{token_port}/oauth/token"));
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2020-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();

    let socket = root_path.join("alice.sock");
    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let pending = raw_http(&socket, &request_access()).await;
    status(&pending, "202");
    let event =
        wait_for_audit_event(&root_path.join("audit.jsonl"), "gateway.request_access").await;
    let approval = approve_service_with_existing_consumer(root_path, &event, "simple-secret");
    assert!(
        approval.status.success(),
        "approval failed: {}",
        String::from_utf8_lossy(&approval.stderr)
    );
    let authorized = admin_http(admin_port, &admin_request(root_path)).await;
    status(&authorized, "200");
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
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let denied =
        send_agent_with_unrelated_credential(&socket, origin_port, &gateway_token, "127.0.0.1")
            .await;
    status(&denied, "403");
    assert!(String::from_utf8_lossy(&denied).contains("credential-guard"));
    assert!(origin_seen.lock().unwrap().is_empty());
    assert_eq!(token_seen.lock().unwrap().len(), 1);
    let request_id = response_header(&denied, "x-safeyolo-request-id").unwrap();
    let event_rows: Vec<Value> = std::fs::read_to_string(root_path.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(event_rows.iter().any(|row| {
        row["event"] == "proxy.credential_guard"
            && row["request_id"] == request_id
            && row["outcome"] == "blocked"
    }));
    let guard_rows: Vec<_> = event_rows
        .iter()
        .filter(|row| row["event"] == "proxy.credential_guard" && row["request_id"] == request_id)
        .collect();
    assert_eq!(
        guard_rows.len(),
        2,
        "each final credential gets one guard evaluation"
    );
    assert_eq!(guard_rows[0]["evaluations"].as_array().unwrap().len(), 1);
    assert_eq!(guard_rows[1]["evaluations"].as_array().unwrap().len(), 1);
    assert!(
        !event_rows
            .iter()
            .any(|row| { row["event"] == "proxy.gateway" && row["request_id"] == request_id })
    );
    wait_for_audit_count(
        &root_path.join("audit.jsonl"),
        "security.credential_guard",
        &request_id,
        2,
    )
    .await;
    let audit = std::fs::read_to_string(root_path.join("audit.jsonl")).unwrap();
    assert_eq!(
        audit
            .lines()
            .filter(|line| line.contains("security.credential_guard") && line.contains(&request_id))
            .count(),
        2,
        "unrelated credentials are audited once despite final gateway checking"
    );
    assert!(!audit.contains("ghr_synthetic_refreshed_access_token_value_123456"));
    let _ = stop_tx.send(());
    watcher.await.unwrap();
    origin_task.abort();
    token_task.abort();
}

/// A selected service without an auth stanza removes the gateway token and
/// still forwards over an HTTPS origin. The final credential guard must skip
/// this intentionally materialized absence.
#[tokio::test]
async fn gateway_no_auth_selection_removes_token_before_https_origin() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("services/simple.yaml"), NO_AUTH_SERVICE).unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let origin_ca = root_path.join("origin-ca.pem");
    std::fs::write(&origin_ca, cert.pem()).unwrap();
    let origin_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    let origin_task = tokio::spawn({
        let origin_seen = origin_seen.clone();
        async move {
            let Ok((socket, _)) = origin_listener.accept().await else {
                return;
            };
            let Ok(stream) = TlsAcceptor::from(Arc::new(origin_tls)).accept(socket).await else {
                return;
            };
            serve_origin_response(stream, origin_seen).await;
        }
    });

    let mut runtime_config = config(root_path);
    runtime_config.upstream_ca_file = Some(origin_ca);
    interception_ca(root_path, &mut runtime_config);
    std::fs::write(
        root_path.join("policy.toml"),
        bound_gateway_policy(origin_port).replace("127.0.0.1", "localhost"),
    )
    .unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "simple-secret",
            "bearer",
            Secret::new("synthetic-origin-secret"),
        ))
        .unwrap();

    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(runtime_config).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response =
        send_agent_with_scheme(&socket, origin_port, &gateway_token, "localhost", "https").await;
    status(&response, "200");
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin_seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let request = origin_seen.lock().unwrap()[0].clone();
    assert!(
        !request
            .windows(b"Authorization:".len())
            .any(|window| window.eq_ignore_ascii_case(b"Authorization:"))
    );
    assert!(
        !request
            .windows(b"synthetic-origin-secret".len())
            .any(|window| window == b"synthetic-origin-secret")
    );
    proxy.shutdown().await;
    origin_task.abort();
}

fn state_sha256(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn git_output(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn comparator_python_stage(script: &str, input: &Value) -> Value {
    let source = Path::new(
        &std::env::var("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("set SAFEYOLO_STATE_PYTHON_SOURCE to the selected comparator checkout"),
    )
    .canonicalize()
    .unwrap();
    let executable_path = std::env::var("SAFEYOLO_POLICY_PYTHON")
        .expect("set SAFEYOLO_POLICY_PYTHON to the selected comparator interpreter");
    let executable = Path::new(&executable_path);
    let expected_executable = source.join(".venv/bin/python");
    assert_eq!(
        executable.canonicalize().unwrap(),
        expected_executable.canonicalize().unwrap()
    );
    let mut child = Command::new(executable)
        .args(["-c", script])
        .env(
            "PYTHONPATH",
            format!("{}:{}", source.join("cli/src").display(), source.display()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_vec(input).unwrap().as_slice())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "comparator stage failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Exercise the encrypted vault through the actual gateway consumer across
/// both implementations. Python creates the initial file, Rust reads and
/// writes it before serving a gateway injection, Python reads and mutates it,
/// and a fresh Rust gateway reads and injects that mutation. The rejected Rust
/// activation is retained as encrypted bytes and observed by Python.
#[tokio::test]
#[ignore = "selected Python→Rust→Python→Rust vault consumer transition"]
async fn selected_python_native_python_native_gateway_vault_transition() {
    let comparator = Path::new(
        &std::env::var("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("set SAFEYOLO_STATE_PYTHON_SOURCE to the selected comparator checkout"),
    )
    .canonicalize()
    .unwrap();
    assert_eq!(
        git_output(&comparator, &["rev-parse", "HEAD"]),
        "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a"
    );
    assert!(git_output(&comparator, &["status", "--porcelain"]).is_empty());
    let comparator_python = comparator.join(".venv/bin/python");
    assert!(comparator_python.is_file());
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    std::fs::set_permissions(
        root_path.join("data/vault.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(root_path.join("services/simple.yaml"), SERVICE).unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(origin_listener, origin_seen.clone(), origin_port));
    std::fs::write(
        root_path.join("policy.toml"),
        bound_gateway_policy(origin_port),
    )
    .unwrap();
    let vault_path = root_path.join("data/vault.yaml.enc");
    let input = json!({"path":vault_path,"password":PASS});
    let initial = comparator_python_stage(
        r#"
import hashlib,importlib.metadata,json,sys
from pathlib import Path
import mitmproxy,safeyolo
from safeyolo.core.vault import Vault,VaultCredential
x=json.load(sys.stdin);p=Path(x['path']);v=Vault(p);v.unlock(x['password'])
v.store(VaultCredential('simple-secret','bearer','synthetic-python-access'))
v.store(VaultCredential('python-only','api_key','synthetic-python-api-key'))
raw=p.read_bytes()
print(json.dumps({'program':sys.executable,'python_version':sys.version.split()[0],
 'safeyolo':importlib.metadata.version('safeyolo'),'mitmproxy':importlib.metadata.version('mitmproxy'),
 'safeyolo_file':str(Path(safeyolo.__file__).resolve()),'mitmproxy_file':str(Path(mitmproxy.__file__).resolve()),
 'names':v.list_names(),'mode':p.stat().st_mode&0o777,'sha256':hashlib.sha256(raw).hexdigest()}))
"#,
        &input,
    );
    assert_eq!(
        initial["program"],
        comparator_python.to_string_lossy().as_ref()
    );
    assert_eq!(initial["python_version"], "3.12.14");
    assert_eq!(initial["safeyolo"], "0.1.0");
    assert_eq!(initial["mitmproxy"], "12.2.3");
    assert!(
        Path::new(initial["safeyolo_file"].as_str().unwrap())
            .starts_with(comparator.join("cli/src"))
    );
    assert!(
        Path::new(initial["mitmproxy_file"].as_str().unwrap())
            .starts_with(comparator.join(".venv"))
    );
    assert_eq!(initial["mode"], 0o600);
    assert_eq!(initial["sha256"], state_sha256(&vault_path));

    let mut stages = vec![json!({
        "backend":"python-comparator",
        "operation":"write-initial-vault",
        "path":vault_path,
        "sha256":initial["sha256"],
        "mode":initial["mode"],
        "names":initial["names"],
        "effective":{"credential":"simple-secret","version":"python-v1"}
    })];
    let vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    assert_eq!(
        vault.list_names().unwrap(),
        ["simple-secret", "python-only"]
    );
    assert_eq!(
        vault
            .get("simple-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-python-access"
    );
    let original = std::fs::read(&vault_path).unwrap();
    let mut activation_calls = 0;
    assert_eq!(
        vault
            .store_with_activation(
                Credential::new(
                    "rejected",
                    "bearer",
                    Secret::new("synthetic-rejected-value"),
                ),
                |_| {
                    activation_calls += 1;
                    (activation_calls > 1).then_some(()).ok_or(())
                },
            )
            .unwrap_err()
            .kind,
        safeyolo_proxy::credentials::ErrorKind::Activation
    );
    assert_eq!(activation_calls, 2);
    assert_eq!(std::fs::read(&vault_path).unwrap(), original);
    assert!(vault.get("rejected").unwrap().is_none());
    stages.push(json!({
        "backend":"rust-native-vault",
        "operation":"read-and-reject-activation-with-rollback",
        "path":vault_path,
        "sha256":state_sha256(&vault_path),
        "mode":file_mode(&vault_path),
        "names":vault.list_names().unwrap(),
        "effective":{"activation":"rejected","rollback_bytes_equal":true}
    }));
    let mut rust_credential = Credential::new(
        "simple-secret",
        "bearer",
        Secret::new("synthetic-rust-access"),
    );
    rust_credential.token_url = None;
    vault.store(rust_credential).unwrap();
    assert_eq!(
        vault
            .get("simple-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-rust-access"
    );
    stages.push(json!({
        "backend":"rust-native-vault",
        "operation":"write-rust-v1",
        "path":vault_path,
        "sha256":state_sha256(&vault_path),
        "mode":file_mode(&vault_path),
        "names":vault.list_names().unwrap(),
        "effective":{"credential":"simple-secret","version":"rust-v1"}
    }));

    let socket = root_path.join("alice.sock");
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let view = wait_for_alice(&socket).await;
    let gateway_token = view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = send_agent(&socket, origin_port, &gateway_token, "127.0.0.1").await;
    status(&response, "200");
    {
        let seen = origin_seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let request = String::from_utf8_lossy(&seen[0]).to_ascii_lowercase();
        assert!(request.contains("authorization: bearer synthetic-rust-access"));
    }
    proxy.shutdown().await;
    stages.push(json!({
        "backend":"rust-native-gateway",
        "operation":"read-rust-v1-and-inject",
        "path":vault_path,
        "sha256":state_sha256(&vault_path),
        "mode":file_mode(&vault_path),
        "effective":{"credential":"simple-secret","version":"rust-v1","origin_contacts":1}
    }));

    let python_after = comparator_python_stage(
        r#"
import hashlib,json,sys
from pathlib import Path
from safeyolo.core.vault import Vault,VaultCredential
x=json.load(sys.stdin);p=Path(x['path']);v=Vault(p);v.unlock(x['password'])
assert v.get('simple-secret').value=='synthetic-rust-access'
assert v.get('python-only').value=='synthetic-python-api-key'
v.store(VaultCredential('simple-secret','bearer','synthetic-python-access-v2'))
raw=p.read_bytes()
print(json.dumps({'names':v.list_names(),'mode':p.stat().st_mode&0o777,'sha256':hashlib.sha256(raw).hexdigest()}))
"#,
        &input,
    );
    assert_eq!(
        python_after["names"],
        json!(["simple-secret", "python-only"])
    );
    assert_eq!(python_after["mode"], 0o600);
    assert_eq!(python_after["sha256"], state_sha256(&vault_path));
    stages.push(json!({
        "backend":"python-comparator",
        "operation":"read-rust-v1-and-write-python-v2",
        "path":vault_path,
        "sha256":python_after["sha256"],
        "mode":python_after["mode"],
        "names":python_after["names"],
        "effective":{"credential":"simple-secret","version":"python-v2"}
    }));

    let final_vault = Vault::unlock(&vault_path, &Secret::new(PASS)).unwrap();
    assert_eq!(
        final_vault
            .get("simple-secret")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-python-access-v2"
    );
    assert_eq!(
        final_vault.list_names().unwrap(),
        ["simple-secret", "python-only"]
    );
    let final_proxy = Proxy::start(config(root_path)).await.unwrap();
    let final_view = wait_for_alice(&socket).await;
    let final_token = final_view["authorized"]["simple"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let final_response = send_agent(&socket, origin_port, &final_token, "127.0.0.1").await;
    status(&final_response, "200");
    {
        let seen = origin_seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let request = String::from_utf8_lossy(&seen[1]).to_ascii_lowercase();
        assert!(request.contains("authorization: bearer synthetic-python-access-v2"));
    }
    final_proxy.shutdown().await;
    stages.push(json!({
        "backend":"rust-native-gateway",
        "operation":"read-python-v2-and-inject",
        "path":vault_path,
        "sha256":state_sha256(&vault_path),
        "mode":file_mode(&vault_path),
        "names":final_vault.list_names().unwrap(),
        "effective":{"credential":"simple-secret","version":"python-v2","origin_contacts":2}
    }));
    origin_task.abort();

    let manifest = json!({
        "schema":1,
        "family":"encrypted-vault",
        "comparator":{
            "source":comparator,
            "commit":"7e934a5470f1aa9b74052fea08c6bae9b5f32e8a",
            "launcher":comparator_python,
            "program":initial["program"],
            "python_version":initial["python_version"],
            "safeyolo":initial["safeyolo"],
            "mitmproxy":initial["mitmproxy"],
            "safeyolo_file":initial["safeyolo_file"],
            "mitmproxy_file":initial["mitmproxy_file"]
        },
        "native":{
            "source":git_output(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(), &["rev-parse", "HEAD"]),
            "package":"safeyolo-proxy",
            "version":env!("CARGO_PKG_VERSION")
        },
        "files":{
            "data_dir":root_path.join("data"),
            "vault":vault_path,
            "vault_key":root_path.join("data/vault.key"),
            "vault_mode":format!("{:04o}", file_mode(&vault_path)),
            "vault_key_mode":format!("{:04o}", file_mode(&root_path.join("data/vault.key")))
        },
        "vault_path":vault_path,
        "stages":stages
    });
    let manifest_text = serde_json::to_string_pretty(&manifest).unwrap();
    for secret in [
        "synthetic-vault-passphrase",
        "synthetic-python-access",
        "synthetic-python-api-key",
        "synthetic-rust-access",
        "synthetic-python-access-v2",
        "synthetic-rejected-value",
    ] {
        assert!(!manifest_text.contains(secret));
    }
    println!("vault cross-version manifest: {manifest_text}");
    if let Some(directory) = std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR") {
        let directory = Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("vault-python-rust-python-rust.json"),
            format!("{manifest_text}\n"),
        )
        .unwrap();
    }
}
