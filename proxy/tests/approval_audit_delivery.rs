//! Real AgentAPI approval responses must agree with the operator's audit view.

use safeyolo_proxy::{AgentListener, Config, Proxy};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};

const SIMPLE: &str = r#"
schema_version: 1
name: simple
default_host: 127.0.0.1
capabilities:
  read:
    routes:
      - methods: [GET]
        path: /v1/read
"#;
const CONTRACT: &str = r#"
schema_version: 1
name: contract
default_host: 127.0.0.1
capabilities:
  write:
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
      operations:
        - name: write
          request:
            method: POST
            path: /v1/write
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
        native_product: true,
        ingress_bindings: vec![],
        native_settings: None,
        native_config_dir: Some(root.to_owned()),
        native_config_path: None,
        listeners: vec![AgentListener {
            agent_id: "alice".into(),
            socket_path: root.join("alice.sock"),
            source_id: None,
        }],
        data_dir: Some(root.join("data")),
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
        test_context_declared_ttl: json!(900),
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
        retired_event_log: Default::default(),
        parent_proxy: None,
        parent_proxy_agents: Vec::new(),
        parent_proxy_hosts: Vec::new(),
        target_ip_mappings: Vec::new(),
        upstream_ca_file: None,
        tls_ca_file: None,
        ignore_hosts: Vec::new(),
        via_token: Some("approval-audit-test".into()),
        inspection: None,
        plumb: Default::default(),
    }
}

fn agent_request(path: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "POST http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer agent-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body),
    )
    .into_bytes()
}

async fn agent(socket: &Path, path: &str, body: &[u8]) -> (u16, Value) {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(&agent_request(path, body)).await.unwrap();
    reply(&mut stream).await
}

async fn admin(port: u16) -> Value {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(b"GET /admin/approvals HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer operator-token\r\nConnection: close\r\n\r\n").await.unwrap();
    let (status, body) = reply(&mut stream).await;
    assert_eq!(status, 200);
    body["approvals"].clone()
}

async fn reply(stream: &mut (impl AsyncReadExt + Unpin)) -> (u16, Value) {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let status = text
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = text.split_once("\r\n\r\n").unwrap().1;
    (status, serde_json::from_str(body).unwrap())
}

async fn operator_pending(root: &Path) -> Value {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(root)
            .args(["approvals", "list", "--json"])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "operator approvals: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["approvals"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approval_claims_require_operator_visible_audit_and_recover_in_one_process() {
    let root = tempfile::Builder::new()
        .prefix("sy-approval-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = root.path();
    fs::create_dir_all(root.join("data")).unwrap();
    fs::create_dir(root.join("builtin")).unwrap();
    fs::create_dir(root.join("services")).unwrap();
    fs::write(root.join("data/agent_token"), "agent-token").unwrap();
    fs::write(root.join("admin-token"), "operator-token").unwrap();
    fs::write(root.join("services/simple.yaml"), SIMPLE).unwrap();
    fs::write(root.join("services/contract.yaml"), CONTRACT).unwrap();
    fs::write(
        root.join("policy.toml"),
        "[hosts.\"127.0.0.1\"]\nservice = \"simple\"\n[agents.alice]\nagent_id = \"ag-11111111111111111111111111111111\"\n",
    )
    .unwrap();
    let audit_path = root.join("audit.jsonl");
    fs::create_dir(&audit_path).unwrap();
    let proxy = Proxy::start(config(root)).await.unwrap();
    let ready: Value = serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;
    fs::write(root.join("config.toml"), format!(
        "admin_port={port}\nadmin_api_token_file='admin-token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n"
    )).unwrap();
    let socket = root.join("alice.sock");
    let cases = [
        (
            "/gateway/request-access",
            br#"{"service":"simple","capability":"read","reason":"test"}"#.as_slice(),
            "service",
            "gateway.request_access",
        ),
        (
            "/gateway/submit-binding",
            br#"{"service":"contract","capability":"write","bindings":{"project":"alpha"},"purpose_code":"test"}"#.as_slice(),
            "contract_binding",
            "gateway.submit_binding",
        ),
        (
            "/desktop/present",
            br#"{"target":"fixture"}"#.as_slice(),
            "desktop_present",
            "agent.desktop_present_requested",
        ),
    ];

    let policy = fs::read_to_string(root.join("policy.toml")).unwrap();
    for (path, body, _, _) in cases {
        let (status, response) = agent(&socket, path, body).await;
        assert_eq!(status, 500, "{path}: {response}");
        assert_eq!(response["error"], "Internal error: RuntimeError");
        assert!(response.get("status").is_none(), "{path}: {response}");
    }
    // Canonical requests survive failed audit delivery. They remain pending,
    // without a permission effect or a successful response to the requester.
    // Desktop presentation still requires its audit-backed prompt.
    let retained = admin(port).await;
    assert_eq!(retained.as_array().unwrap().len(), 2, "{retained}");
    for approval_type in ["service", "contract_binding"] {
        let record = retained
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["approval"]["approval_type"] == approval_type)
            .unwrap();
        assert_eq!(record["status"], "pending");
        assert_eq!(record["agent"], "alice");
        assert_eq!(
            record["action"]["agent_id"],
            "ag-11111111111111111111111111111111"
        );
        assert_eq!(record["approval"]["required"], true);
        assert!(record["result"].is_null());
    }
    assert_eq!(
        fs::read_to_string(root.join("policy.toml")).unwrap(),
        policy
    );
    assert!(audit_path.is_dir());

    fs::remove_dir(&audit_path).unwrap();
    let mut desktop_request_id = None;
    for (path, body, _, _) in cases {
        let (status, response) = agent(&socket, path, body).await;
        assert_eq!(status, 202, "{path}: {response}");
        assert_eq!(response["status"], "pending");
        assert_eq!(response["agent"], "alice");
        if path == "/desktop/present" {
            desktop_request_id = response["request_id"].as_str().map(str::to_owned);
        }
    }
    let pending = admin(port).await;
    let listed = operator_pending(root).await;
    let audit: Vec<Value> = fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| event["approval"]["required"] == true)
        .collect();
    assert_eq!(pending.as_array().unwrap().len(), 3, "{pending}");
    assert_eq!(listed.as_array().unwrap().len(), 3, "{listed}");
    assert_eq!(audit.len(), 3, "{audit:?}");
    for (_, _, approval_type, event_name) in cases {
        let event = audit
            .iter()
            .find(|event| event["event"] == event_name)
            .unwrap();
        assert_eq!(event["schema_version"], 2);
        assert_eq!(event["agent"], "alice");
        assert_eq!(event["approval"]["approval_type"], approval_type);
        let record = pending
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["approval"]["approval_type"] == approval_type)
            .unwrap();
        assert_eq!(record["agent"], "alice");
        assert_eq!(record["approval"]["required"], true);
        let id = if approval_type == "desktop_present" {
            assert_eq!(record["event"], event_name);
            assert_eq!(event["request_id"], desktop_request_id.as_deref().unwrap());
            assert_eq!(record["request_id"], event["request_id"]);
            &record["request_id"]
        } else {
            let canonical_event = if approval_type == "contract_binding" {
                "gateway.contract_binding_requested"
            } else {
                event_name
            };
            assert_eq!(record["event"], canonical_event);
            assert_eq!(record["status"], "pending");
            assert_eq!(
                record["action"]["agent_id"],
                "ag-11111111111111111111111111111111"
            );
            assert_eq!(event["details"]["approval_id"], record["approval_id"]);
            let prior = retained
                .as_array()
                .unwrap()
                .iter()
                .find(|prior| prior["approval_id"] == record["approval_id"])
                .unwrap();
            assert_eq!(record["request_id"], prior["request_id"]);
            assert_eq!(record["authority_digest"], prior["authority_digest"]);
            &record["approval_id"]
        };
        let visible = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|visible| visible["approval_id"] == *id)
            .unwrap();
        assert!(id.as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(visible["agent"], "alice");
        assert_eq!(visible["status"], "pending");
        for field in ["request_id", "summary", "action", "options"] {
            assert_eq!(visible[field], record[field], "{approval_type}: {field}");
        }
        assert_eq!(visible["target"], record["approval"]["target"]);
    }
    assert_eq!(
        fs::read_to_string(root.join("policy.toml")).unwrap(),
        policy
    );
    proxy.shutdown().await;
}
