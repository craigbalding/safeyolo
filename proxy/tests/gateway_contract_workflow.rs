use ring::digest::{SHA256, digest};
use safeyolo_proxy::{
    AgentListener, Config, Proxy,
    credentials::{Credential, Secret, Vault},
};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
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
const COMPARATOR_COMMIT: &str = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a";
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
      - methods: [GET]
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
        - name: read
          request:
            method: GET
            path: /v1/write
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
        response_validators: declared
"#;

const OTHER_SERVICE: &str = r#"
schema_version: 1
name: other
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
        path: /v1/other
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
        plumb: Default::default(),
    }
}

fn policy(port: u16) -> String {
    format!(
        r#"
[hosts."127.0.0.1"]
service = "contract"
credentials = ["unknown:*"]
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

fn legacy_policy(port: u16) -> String {
    let mut source = policy(port);
    source.push_str(
        r#"
[[agents.alice.contract_bindings]]
service = "contract"
capability = "writer"
template = "contract.write.v1"
bound_values = { project = "alpha", ticket = "T-1" }
grantable_operations = ["write"]

[[agents.alice.grants]]
service = "contract"
method = "POST"
path = "/v1/write"
scope = "remembered"
"#,
    );
    source
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
fn gateway_request_at(
    host: &str,
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    format!("{method} http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), String::from_utf8_lossy(body)).into_bytes()
}
fn gateway_request(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    gateway_request_at("127.0.0.1", port, token, method, path, body)
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

async fn gateway_call_at(
    socket: &Path,
    host: &str,
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    payload: &[u8],
) -> Vec<u8> {
    let request = gateway_request_at(host, port, token, method, path, payload);
    raw(socket, &request).await
}

async fn current_service_token(socket: &Path, service: &str) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = raw(socket, &agent_api("/gateway/services", b"")).await;
            if let Ok(view) = serde_json::from_slice::<Value>(body(&response))
                && let Some(token) = view["authorized"][service]["token"].as_str()
            {
                return token.to_owned();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap()
}

async fn current_gateway_token(socket: &Path) -> String {
    current_service_token(socket, "contract").await
}

async fn gateway_services(socket: &Path) -> Value {
    let response = raw(socket, &agent_api("/gateway/services", b"")).await;
    status(&response, 200);
    serde_json::from_slice(body(&response)).unwrap()
}

fn state_sha256(path: &Path) -> String {
    digest(&SHA256, &fs::read(path).unwrap())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn token_sha256(token: &str) -> String {
    digest(&SHA256, token.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn git_output(directory: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn python_service_rollback(policy: &Path, binding_id: &str, grant_id: &str) -> Value {
    let source = Path::new(
        &std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("SAFEYOLO_STATE_PYTHON_SOURCE must name the comparator checkout"),
    )
    .to_owned();
    let executable = Path::new(
        &std::env::var_os("SAFEYOLO_POLICY_PYTHON")
            .expect("SAFEYOLO_POLICY_PYTHON must name the comparator interpreter"),
    )
    .to_owned();
    assert_eq!(
        git_output(&source, &["rev-parse", "HEAD"]),
        COMPARATOR_COMMIT
    );
    assert!(
        git_output(&source, &["status", "--porcelain"]).is_empty(),
        "selected Python comparator must be clean"
    );
    assert!(
        executable.is_file(),
        "selected Python comparator is missing"
    );
    let script = r#"
import hashlib
import importlib.metadata
import json
import pathlib
import sys

from safeyolo.mitm_addons.service_gateway import ServiceGateway
from safeyolo.policy.toml_roundtrip import (
    load_agents,
    load_roundtrip,
    locked_policy_mutate,
    upsert_agent,
)

policy = pathlib.Path(sys.argv[1])
expected_binding = sys.argv[2]
expected_grant = sys.argv[3]
expected_executable = pathlib.Path(sys.argv[4])
source = pathlib.Path(sys.argv[5])
assert pathlib.Path(sys.executable).resolve() == expected_executable.resolve()

def snapshot():
    agents = load_agents(load_roundtrip(policy))
    alice = agents['alice']
    service = alice.get('services', {}).get('contract')
    return {
        'policy': {
            'sha256': hashlib.sha256(policy.read_bytes()).hexdigest(),
            'mode': format(policy.stat().st_mode & 0o777, '04o'),
        },
        'service_authorization': None if service is None else {
            'capability': service['capability'],
            'credential_name': service['token'],
        },
        'bindings': [
            {
                'binding_id': item.get('binding_id'),
                'service': item.get('service'),
                'capability': item.get('capability'),
                'template': item.get('template'),
                'bound_values': item.get('bound_values', {}),
                'grantable_operations': item.get('grantable_operations', []),
            }
            for item in alice.get('contract_bindings', [])
        ],
        'grants': [
            {
                'grant_id': item.get('grant_id'),
                'service': item.get('service'),
                'method': item.get('method'),
                'path': item.get('path'),
                'scope': item.get('scope'),
            }
            for item in alice.get('grants', [])
        ],
    }

gateway = ServiceGateway()
gateway._get_policy_path = lambda: policy
gateway._load_grants_from_policy()
gateway._load_contract_bindings_from_policy()
binding = gateway.get_contract_binding('alice', 'contract', 'writer')
assert binding is not None and binding.binding_id == expected_binding
grant = gateway._check_grant('alice', 'contract', 'POST', '/v1/write')
assert grant is not None and grant.grant_id == expected_grant
before = snapshot()
assert before['service_authorization']['capability'] == 'writer'
assert before['service_authorization']['credential_name'] == 'contract-secret'
assert gateway.revoke_grant(expected_grant)
assert gateway.revoke_contract_binding(expected_binding)

def remove_service_authorization(document):
    agents = load_agents(document)
    alice = agents['alice']
    services = alice.get('services', {})
    assert services['contract']['capability'] == 'writer'
    del services['contract']
    if services:
        alice['services'] = services
    else:
        alice.pop('services', None)
    upsert_agent(document, 'alice', alice)

locked_policy_mutate(policy, remove_service_authorization, save_if_unchanged=False)
gateway._grants.clear()
gateway._contract_bindings.clear()
gateway._load_grants_from_policy()
gateway._load_contract_bindings_from_policy()
assert gateway._check_grant('alice', 'contract', 'POST', '/v1/write') is None
assert gateway.get_contract_binding('alice', 'contract', 'writer') is None
after = snapshot()
assert not after['grants']
assert not after['bindings']
assert after['service_authorization'] is None
print(json.dumps({
    'backend': 'python-comparator',
    'operation': 'read-native-state-and-rollback-service-access',
    'runtime': {
        'source': str(source),
        'commit': '7e934a5470f1aa9b74052fea08c6bae9b5f32e8a',
        'launcher': str(expected_executable),
        'program': sys.executable,
        'python_version': '.'.join(map(str, sys.version_info[:3])),
        'safeyolo': importlib.metadata.version('safeyolo'),
        'mitmproxy': importlib.metadata.version('mitmproxy'),
        'tomlkit': importlib.metadata.version('tomlkit'),
    },
    'before': before,
    'after': after,
    'rollback': {
        'grant_id': expected_grant,
        'binding_id': expected_binding,
        'service_authorization_removed': True,
    },
}))
"#;
    let output = Command::new(&executable)
        .args([
            "-c",
            script,
            policy.to_str().unwrap(),
            binding_id,
            grant_id,
            executable.to_str().unwrap(),
            source.to_str().unwrap(),
        ])
        .env(
            "PYTHONPATH",
            format!("{}:{}", source.join("cli/src").display(), source.display()),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Python service rollback failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "Python service rollback returned invalid JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[tokio::test]
async fn unchanged_policy_reload_does_not_race_service_token_publication() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for dir in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(dir)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("services/contract.yaml"), SERVICE).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault = Vault::unlock(root_path.join("data/vault.yaml.enc"), &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "contract-secret",
            "bearer",
            Secret::new("exact-contract-origin-secret"),
        ))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    std::fs::write(root_path.join("policy.toml"), policy(port)).unwrap();

    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let socket = root_path.join("alice.sock");
    let before_token = current_gateway_token(&socket).await;
    let before_policy = std::fs::metadata(root_path.join("policy.toml"))
        .unwrap()
        .modified()
        .unwrap();

    // An unchanged service document still reaches the real catalog watcher
    // when its metadata changes, which publishes one new service token.
    tokio::time::sleep(Duration::from_millis(25)).await;
    std::fs::write(root_path.join("services/contract.yaml"), SERVICE).unwrap();
    assert!(proxy.reload_services_if_changed().await.unwrap());
    let after_token = current_gateway_token(&socket).await;
    assert_ne!(after_token, before_token);

    // Store reconciliation must not rewrite the byte-identical baseline. A
    // policy watcher therefore sees no synthetic change or second token mint.
    let after_service_policy = std::fs::metadata(root_path.join("policy.toml"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(after_service_policy, before_policy);
    assert!(!proxy.reload_policy_if_changed().await.unwrap());
    assert_eq!(current_gateway_token(&socket).await, after_token);
    proxy.shutdown().await;
}

#[tokio::test]
async fn legacy_normalization_keeps_watcher_watermark_and_origin_token_valid() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for dir in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(dir)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("services/contract.yaml"), SERVICE).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault = Vault::unlock(root_path.join("data/vault.yaml.enc"), &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "contract-secret",
            "bearer",
            Secret::new("exact-contract-origin-secret"),
        ))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    std::fs::write(root_path.join("policy.toml"), legacy_policy(port)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(
        listener,
        seen.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    ));

    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let socket = root_path.join("alice.sock");
    let token = current_gateway_token(&socket).await;
    // Store normalization has already filled IDs/creation/expiry in place.
    // The accepted policy watermark must describe those resulting bytes.
    assert!(!proxy.reload_policy_if_changed().await.unwrap());
    assert_eq!(current_gateway_token(&socket).await, token);
    let delivered = gateway_call(
        &socket,
        port,
        &token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&delivered, 200);
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        String::from_utf8_lossy(&seen.lock().unwrap()[0]).contains("exact-contract-origin-secret")
    );
    assert_eq!(current_gateway_token(&socket).await, token);
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn expired_grant_reload_restart_and_legacy_consumer_removal_are_live() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for dir in ["data", "builtin", "services"] {
        std::fs::create_dir_all(root_path.join(dir)).unwrap();
    }
    std::fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    std::fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    std::fs::write(root_path.join("services/contract.yaml"), SERVICE).unwrap();
    std::fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault = Vault::unlock(root_path.join("data/vault.yaml.enc"), &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "contract-secret",
            "bearer",
            Secret::new("exact-contract-origin-secret"),
        ))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut source = policy(port);
    source.push_str("\n[gateway]\ngrant_ttl_seconds = 1\n");
    std::fs::write(root_path.join("policy.toml"), source).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(
        listener,
        seen.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    ));

    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let binding = admin(
        admin_port,
        &admin_request(
            "/admin/gateway/contract-binding",
            br#"{"agent":"alice","service":"contract","capability":"writer","template":"contract.write.v1","bindings":{"project":"alpha","ticket":"T-1"},"grantable_operations":["write"]}"#,
        ),
    )
    .await;
    status(&binding, 200);
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    let token = current_gateway_token(&root_path.join("alice.sock")).await;
    let session = admin(
        admin_port,
        &admin_request(
            "/admin/gateway/grant",
            br#"{"agent":"alice","service":"contract","method":"POST","path":"/v1/write","lifetime":"session"}"#,
        ),
    )
    .await;
    status(&session, 200);
    let allowed = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&allowed, 200);
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        String::from_utf8_lossy(&seen.lock().unwrap()[0]).contains("exact-contract-origin-secret")
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut document = std::fs::read_to_string(root_path.join("policy.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    document["gateway"]["reload_marker"] = toml_edit::value("expiry");
    std::fs::write(root_path.join("policy.toml"), document.to_string()).unwrap();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    let expired = admin(admin_port, &admin_get("/admin/gateway/grants")).await;
    status(&expired, 200);
    assert!(
        serde_json::from_slice::<Value>(body(&expired)).unwrap()["grants"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    let blocked = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &current_gateway_token(&root_path.join("alice.sock")).await,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&blocked, 428);
    assert_eq!(seen.lock().unwrap().len(), 1);

    // Establish a fresh, non-expired session immediately before restart. This
    // request proves the restart assertion is independent of expiry.
    let restart_session = admin(
        admin_port,
        &admin_request(
            "/admin/gateway/grant",
            br#"{"agent":"alice","service":"contract","method":"POST","path":"/v1/write","lifetime":"session"}"#,
        ),
    )
    .await;
    status(&restart_session, 200);
    let before_restart = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &current_gateway_token(&root_path.join("alice.sock")).await,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&before_restart, 200);
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    // A new process owner does not replay the still-valid session grant. The
    // same live origin remains untouched after restart.
    proxy.shutdown().await;
    let mut restarted = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let restarted_grants = admin(admin_port, &admin_get("/admin/gateway/grants")).await;
    status(&restarted_grants, 200);
    assert!(
        serde_json::from_slice::<Value>(body(&restarted_grants)).unwrap()["grants"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    let restarted_blocked = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &current_gateway_token(&root_path.join("alice.sock")).await,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&restarted_blocked, 428);
    assert_eq!(seen.lock().unwrap().len(), 2);

    // Add a legacy remembered record through the authored policy, then let
    // the existing policy reload normalize and publish it. It authorizes one
    // real origin request before the operator consumer removes the last grant.
    let mut document = std::fs::read_to_string(root_path.join("policy.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let mut legacy = toml_edit::InlineTable::new();
    legacy.insert("service", toml_edit::Value::from("contract"));
    legacy.insert("method", toml_edit::Value::from("POST"));
    legacy.insert("path", toml_edit::Value::from("/v1/write"));
    legacy.insert("scope", toml_edit::Value::from("remembered"));
    let mut records = toml_edit::Array::new();
    records.push(toml_edit::Value::InlineTable(legacy));
    document["agents"]["alice"]["grants"] =
        toml_edit::Item::Value(toml_edit::Value::Array(records));
    std::fs::write(root_path.join("policy.toml"), document.to_string()).unwrap();
    assert!(restarted.reload_policy_if_changed().await.unwrap());
    let legacy_grants = admin(admin_port, &admin_get("/admin/gateway/grants")).await;
    status(&legacy_grants, 200);
    let legacy_grants: Value = serde_json::from_slice(body(&legacy_grants)).unwrap();
    let legacy_id = legacy_grants["grants"][0]["grant_id"].as_str().unwrap();
    let legacy_allowed = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &current_gateway_token(&root_path.join("alice.sock")).await,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&legacy_allowed, 200);
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let removed = admin(
        admin_port,
        &admin_delete(&format!("/admin/gateway/grants/{legacy_id}")),
    )
    .await;
    status(&removed, 200);
    let empty = admin(admin_port, &admin_get("/admin/gateway/grants")).await;
    status(&empty, 200);
    assert!(
        serde_json::from_slice::<Value>(body(&empty)).unwrap()["grants"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    let after_removal = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &current_gateway_token(&root_path.join("alice.sock")).await,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&after_removal, 428);
    assert_eq!(seen.lock().unwrap().len(), 3);
    restarted.shutdown().await;
    origin_task.abort();
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
    std::fs::write(root_path.join("services/other.yaml"), OTHER_SERVICE).unwrap();
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
    vault
        .store(Credential::new(
            "other-secret",
            "bearer",
            Secret::new("exact-other-origin-secret"),
        ))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let other_listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let other_port = other_listener.local_addr().unwrap().port();
    let mut source = policy(port);
    source.push_str(&format!(
        "\n[hosts.\"127.0.0.2\"]\nservice = \"other\"\ncredentials = [\"unknown:*\"]\n[hosts.\"127.0.0.2:{other_port}\"]\negress = \"allow\"\n[agents.alice.services.other]\ncapability = \"reader\"\ntoken = \"other-secret\"\n"
    ));
    std::fs::write(root_path.join("policy.toml"), source).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let other_seen = Arc::new(Mutex::new(Vec::new()));
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
    let other_origin_task = tokio::spawn(origin(
        other_listener,
        other_seen.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
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
    let unknown_service = raw(
        &root_path.join("alice.sock"),
        &agent_api(
            "/gateway/request-access",
            br#"{"service":"missing","capability":"writer"}"#,
        ),
    )
    .await;
    status(&unknown_service, 404);
    let unknown_capability = raw(
        &root_path.join("alice.sock"),
        &agent_api(
            "/gateway/request-access",
            br#"{"service":"contract","capability":"missing"}"#,
        ),
    )
    .await;
    status(&unknown_capability, 404);
    let submitted = raw(&root_path.join("alice.sock"), &agent_api("/gateway/submit-binding", br#"{"service":"contract","capability":"writer","bindings":{"project":"alpha","ticket":"T-1"},"purpose_code":"write"}"#)).await;
    status(&submitted, 202);
    let binding = br#"{"agent":"alice","service":"contract","capability":"writer","template":"contract.write.v1","bindings":{"project":"alpha","ticket":"T-1"},"grantable_operations":["write","read"]}"#;
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
    let other_token = current_service_token(&root_path.join("alice.sock"), "other").await;
    let other_allowed = gateway_call_at(
        &root_path.join("alice.sock"),
        "127.0.0.2",
        other_port,
        &other_token,
        "GET",
        "/v1/other",
        b"",
    )
    .await;
    status(&other_allowed, 200);
    tokio::time::timeout(Duration::from_secs(3), async {
        while other_seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let other_count = other_seen.lock().unwrap().len();
    // A token issued for contract cannot cross into another live service
    // origin, and the other service token cannot select an undeclared
    // capability route. Both deny before a second origin observes bytes.
    let wrong_service = gateway_call_at(
        &root_path.join("alice.sock"),
        "127.0.0.2",
        other_port,
        &gateway_token,
        "GET",
        "/v1/other",
        b"",
    )
    .await;
    status(&wrong_service, 403);
    let wrong_capability = gateway_call_at(
        &root_path.join("alice.sock"),
        "127.0.0.2",
        other_port,
        &other_token,
        "GET",
        "/v1/undeclared",
        b"",
    )
    .await;
    status(&wrong_capability, 403);
    assert_eq!(other_seen.lock().unwrap().len(), other_count);

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

    // A declared operation without query/body constraints remains an
    // unconstrained positive: the selected credential reaches the origin
    // without a risk grant or body matcher, while constrained write retains
    // its checks.
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let unconstrained = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "GET",
        "/v1/write",
        b"",
    )
    .await;
    status(&unconstrained, 200);
    assert!(
        String::from_utf8_lossy(&seen.lock().unwrap()[count])
            .contains("exact-contract-origin-secret")
    );
    assert_eq!(seen.lock().unwrap().len(), count + 1);
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

    // Downstream cancellation releases a held once reservation. The origin
    // receives the first request, but the client closes its UDS stream before
    // the held response is released; a later retry can reserve the same grant.
    let granted = admin(admin_port, &admin_request("/admin/gateway/grant", grant)).await;
    status(&granted, 200);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    hold_first.store(true, Ordering::SeqCst);
    let mut canceled = UnixStream::connect(root_path.join("alice.sock"))
        .await
        .unwrap();
    let canceled_request = gateway_request(
        port,
        &gateway_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    );
    canceled.write_all(&canceled_request).await.unwrap();
    first_accepted.notified().await;
    drop(canceled);
    release_first.notify_one();
    let mut canceled_retry = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
            canceled_retry = gateway_call(
                &root_path.join("alice.sock"),
                port,
                &gateway_token,
                "POST",
                "/v1/write?ticket=T-1",
                br#"{"project":"alpha"}"#,
            )
            .await;
            if canceled_retry.starts_with(b"HTTP/1.1 200") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    status(&canceled_retry, 200);
    assert_eq!(seen.lock().unwrap().len(), count + 2);
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
            "PUT",
            "/v1/write?ticket=T-1",
            b"",
        )
        .await
    };
    status(&wrong_method, 403);
    assert_eq!(seen.lock().unwrap().len(), count);
    gateway_token = current_gateway_token(&root_path.join("alice.sock")).await;
    let wrong_endpoint = gateway_call(
        &root_path.join("alice.sock"),
        port,
        &gateway_token,
        "POST",
        "/v1/unknown",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&wrong_endpoint, 403);
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
    let remaining = admin(admin_port, &admin_get("/admin/gateway/grants")).await;
    status(&remaining, 200);
    assert!(
        serde_json::from_slice::<Value>(body(&remaining)).unwrap()["grants"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

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
    other_origin_task.abort();
}

#[tokio::test]
#[ignore = "selected Python→Rust→Python service authorization and gateway rollback"]
async fn selected_python_native_python_service_authorization_rollback() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    for directory in ["data", "builtin", "services"] {
        fs::create_dir_all(root_path.join(directory)).unwrap();
    }
    fs::write(root_path.join("admin-token"), b"operator-token").unwrap();
    fs::write(root_path.join("data/agent_token"), b"agent-token").unwrap();
    fs::write(root_path.join("services/contract.yaml"), SERVICE).unwrap();
    fs::write(root_path.join("data/vault.key"), PASS).unwrap();
    let vault = Vault::unlock(root_path.join("data/vault.yaml.enc"), &Secret::new(PASS)).unwrap();
    vault
        .store(Credential::new(
            "contract-secret",
            "bearer",
            Secret::new("exact-contract-origin-secret"),
        ))
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Start without an authorization record so this fixture exercises the
    // native service writer itself. The catalog is present, but access is
    // published only after the operator authorization route commits it.
    let initial_policy = policy(port).replace(
        "[agents.alice.services.contract]\ncapability = \"writer\"\ntoken = \"contract-secret\"\n",
        "",
    );
    fs::write(root_path.join("policy.toml"), initial_policy).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(
        listener,
        seen.clone(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    ));

    let mut proxy = Proxy::start(config(root_path)).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root_path.join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let socket = root_path.join("alice.sock");
    let initial_services = gateway_services(&socket).await;
    assert!(initial_services["authorized"]["contract"].is_null());
    let authorization = admin(
        admin_port,
        &admin_request(
            "/admin/agents/alice/services",
            br#"{"service":"contract","capability":"writer","credential":"contract-secret"}"#,
        ),
    )
    .await;
    status(&authorization, 200);
    let authorization_body: Value = serde_json::from_slice(body(&authorization)).unwrap();
    assert_eq!(authorization_body["status"], "authorized");
    assert_eq!(authorization_body["agent"], "alice");
    assert_eq!(authorization_body["service"], "contract");
    assert_eq!(authorization_body["capability"], "writer");
    let binding_response = admin(
        admin_port,
        &admin_request(
            "/admin/gateway/contract-binding",
            br#"{"agent":"alice","service":"contract","capability":"writer","template":"contract.write.v1","bindings":{"project":"alpha","ticket":"T-1"},"grantable_operations":["write"]}"#,
        ),
    )
    .await;
    status(&binding_response, 200);
    let binding_body: Value = serde_json::from_slice(body(&binding_response)).unwrap();
    let binding_id = binding_body["binding_id"].as_str().unwrap().to_owned();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    let initial_token = current_gateway_token(&socket).await;

    let grant_response = admin(
        admin_port,
        &admin_request(
            "/admin/gateway/grant",
            br#"{"agent":"alice","service":"contract","method":"POST","path":"/v1/write","lifetime":"remembered"}"#,
        ),
    )
    .await;
    status(&grant_response, 200);
    let grant_body: Value = serde_json::from_slice(body(&grant_response)).unwrap();
    let grant_id = grant_body["grant_id"].as_str().unwrap().to_owned();
    let _ = proxy.reload_policy_if_changed().await.unwrap();

    let native_token = current_gateway_token(&socket).await;
    let allowed = gateway_call(
        &socket,
        port,
        &native_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&allowed, 200);
    tokio::time::timeout(Duration::from_secs(3), async {
        while seen.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        String::from_utf8_lossy(&seen.lock().unwrap()[0]).contains("exact-contract-origin-secret")
    );
    let native_written_hash = state_sha256(&root_path.join("policy.toml"));
    let origin_count_before_rollback = seen.lock().unwrap().len();

    // Stop the native consumer before the selected prior release reads the
    // records it just wrote. The Python ServiceGateway performs the real
    // grant/binding lookup and durable removal under its existing policy lock.
    proxy.shutdown().await;
    let python_rollback =
        python_service_rollback(&root_path.join("policy.toml"), &binding_id, &grant_id);
    assert_eq!(
        python_rollback["rollback"]["binding_id"],
        binding_id.as_str()
    );
    assert_eq!(python_rollback["rollback"]["grant_id"], grant_id.as_str());
    assert_eq!(
        python_rollback["before"]["policy"]["sha256"],
        native_written_hash
    );

    let restarted = Proxy::start(config(root_path)).await.unwrap();
    let restarted_services = gateway_services(&socket).await;
    assert!(restarted_services["authorized"]["contract"].is_null());
    let rolled_back = gateway_call(
        &socket,
        port,
        &initial_token,
        "POST",
        "/v1/write?ticket=T-1",
        br#"{"project":"alpha"}"#,
    )
    .await;
    status(&rolled_back, 403);
    assert_eq!(seen.lock().unwrap().len(), origin_count_before_rollback);
    assert!(python_rollback["after"]["service_authorization"].is_null());
    assert!(
        python_rollback["after"]["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        python_rollback["after"]["bindings"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let evidence_dir = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR")
            .expect("SAFEYOLO_STATE_EVIDENCE_DIR must retain evidence"),
    );
    fs::create_dir_all(&evidence_dir).unwrap();
    let final_hash = state_sha256(&root_path.join("policy.toml"));
    let manifest = serde_json::json!({
        "schema": 1,
        "family": "service-authorization-contract-binding-grant-token",
        "comparator": python_rollback["runtime"],
        "native": {
            "source": git_output(
                Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(),
                &["rev-parse", "HEAD"],
            ),
            "package": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "test": "selected_python_native_python_service_authorization_rollback",
        },
        "commands": {
            "python": "selected Python ServiceGateway comparator script embedded in the Rust fixture",
            "native": "cargo test --test gateway_contract_workflow selected_python_native_python_service_authorization_rollback -- --ignored --exact --nocapture",
        },
        "state": {
            "native_written_sha256": native_written_hash,
            "python_rollback_sha256": python_rollback["after"]["policy"]["sha256"],
            "final_native_sha256": final_hash,
            "initial_token_sha256": token_sha256(&initial_token),
            "native_token_sha256": token_sha256(&native_token),
            "restarted_token_sha256": Value::Null,
            "mode": python_rollback["after"]["policy"]["mode"],
        },
        "actions": {
            "service_authorization_written": authorization_body,
            "binding_written": binding_id,
            "grant_written": grant_id,
            "request_before_rollback": "200 with credential injection and one origin request",
            "python_rollback": {
                "service_authorization": "contract",
                "binding_id": binding_id,
                "grant_id": grant_id,
            },
            "request_after_rollback": "403 with zero additional origin requests",
        },
        "stages": [
            {"backend": "rust-native", "operation": "write-reload-request", "status": 200},
            python_rollback,
            {"backend": "rust-native", "operation": "restart-read-rolled-back-service-request", "status": 403},
        ],
        "secret_free": true,
    });
    fs::write(
        evidence_dir.join("service-authorization-python-rust-python-rust.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!(
        "service authorization rollback manifest: {}",
        serde_json::to_string_pretty(&manifest).unwrap()
    );
    restarted.shutdown().await;
    origin_task.abort();
}
