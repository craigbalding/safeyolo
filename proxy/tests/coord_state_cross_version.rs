//! Cross-release coordination state witness for #638.
//!
//! The fixture is created by the retained Python coordination store.  This
//! test then reads and replaces the same capability declarations through the
//! native agent API, waits for the Python comparator to write its next
//! generation, and starts a fresh native proxy to read that generation.  The
//! SQLite file is the existing coordination boundary; this test does not add
//! a proxy-owned persistence layer.

use ring::digest::{Context, SHA256};
use safeyolo_proxy::{AgentListener, Config, Proxy};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{sleep, timeout},
};

const AGENT_TOKEN: &str = "coord-rollback-agent-token";
const OPERATOR_TOKEN: &str = "coord-rollback-operator-token";

#[derive(Debug)]
struct Reply {
    status: u16,
    body: Value,
}

fn config(root: &Path) -> Config {
    Config {
        listeners: vec![AgentListener {
            agent_id: "alice".into(),
            socket_path: root.join("alice.sock"),
            source_id: None,
        }],
        agent_map_file: String::new(),
        data_dir: Some(root.join("data")),
        temporary_policy_socket: None,
        policy_file: Some(root.join("policy.toml")),
        gateway_builtin_services_dir: None,
        gateway_services_dir: None,
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
        event_log: root.join("events.jsonl"),
        parent_proxy: None,
        upstream_ca_file: None,
        tls_ca_file: None,
        ignore_hosts: Vec::new(),
        via_token: Some("coord-rollback-test".into()),
        inspection: None,
        plumb: Default::default(),
    }
}

fn request(method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {AGENT_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body),
    )
    .into_bytes()
}

fn parse_reply(bytes: &[u8]) -> Reply {
    let text = String::from_utf8_lossy(bytes);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("HTTP status");
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body)
            .unwrap_or_else(|error| panic!("JSON body for HTTP {status}: {error}: {body:?}"))
    };
    Reply { status, body }
}

async fn exchange(socket: &Path, bytes: &[u8]) -> Reply {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("coord response timeout")
        .unwrap();
    parse_reply(&response)
}

async fn wait_for_path(path: &Path) {
    timeout(Duration::from_secs(5), async {
        while !path.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("coord socket/readiness path must appear");
}

async fn wait_for_file(path: &Path) -> Value {
    timeout(Duration::from_secs(40), async {
        loop {
            if let Ok(bytes) = fs::read(path) {
                if let Ok(value) = serde_json::from_slice(&bytes) {
                    return value;
                }
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Python comparator update timeout")
}

fn write_native_fixture(root: &Path) {
    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root.join("admin-token"), OPERATOR_TOKEN).unwrap();
    fs::write(
        root.join("policy.toml"),
        "[agents.alice]\nagent_id = 'ag-11111111111111111111111111111111'\n\n[[permissions]]\naction = 'network:request'\nresource = '*'\neffect = 'deny'\n",
    )
    .unwrap();
}

fn sha256(path: &Path) -> String {
    let mut digest = Context::new(&SHA256);
    digest.update(&fs::read(path).unwrap());
    digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn declared_capabilities(state: &Value) -> Vec<String> {
    let mut capabilities = state["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["agent_id"] == "ag-11111111111111111111111111111111")
        .unwrap()["declared"]
        .as_array()
        .unwrap()
        .iter()
        .map(|declaration| declaration["capability"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities
}

fn append_observation(observations: &mut Vec<Value>, step: &str, reply: &Reply) {
    observations.push(json!({
        "step": step,
        "status": reply.status,
        "body": reply.body,
    }));
}

fn save_evidence(path: &Path, evidence: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_vec_pretty(evidence).unwrap()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coordination_state_round_trips_between_python_and_native() {
    assert!(
        std::env::var_os("SAFEYOLO_NATS_TEST_INSTANCE").is_some(),
        "set SAFEYOLO_NATS_TEST_INSTANCE for the real coordination fixture"
    );
    let coord_root = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_DATA_DIR")
            .expect("set SAFEYOLO_COORD_DATA_DIR to the Python-owned fixture"),
    );
    let fixture: Value =
        serde_json::from_slice(&fs::read(coord_root.join("fixture.json")).unwrap()).unwrap();
    let room = fixture["room_name"].as_str().unwrap();
    assert_eq!(room, "coord-rollback-room");
    assert_eq!(fixture["agent_id"], "ag-11111111111111111111111111111111");

    let runtime = TempDir::new().unwrap();
    write_native_fixture(runtime.path());
    let socket = runtime.path().join("alice.sock");
    let db = coord_root.join("v0.db");
    let mut observations = Vec::new();

    let proxy = Proxy::start(config(runtime.path())).await.unwrap();
    wait_for_path(&socket).await;
    let state_path = format!("/api/coord/rooms/{room}/state");
    let initial = exchange(&socket, &request("GET", &state_path, b"")).await;
    assert_eq!(initial.status, 200);
    assert_eq!(
        declared_capabilities(&initial.body),
        vec!["python:initial", "python:shared"]
    );
    append_observation(&mut observations, "native_read_python_state", &initial);
    let hash_after_python = sha256(&db);

    let native_body = br#"{"capabilities":["rust:native","rust:shared"],"ttl_seconds":900}"#;
    let native_write = exchange(
        &socket,
        &request(
            "POST",
            &format!("/api/coord/rooms/{room}/declarations"),
            native_body,
        ),
    )
    .await;
    assert_eq!(native_write.status, 200);
    assert_eq!(
        native_write.body["agent_id"],
        "ag-11111111111111111111111111111111"
    );
    assert_eq!(native_write.body["count"], 2);
    append_observation(&mut observations, "native_write_state", &native_write);
    let native_read = exchange(&socket, &request("GET", &state_path, b"")).await;
    assert_eq!(native_read.status, 200);
    assert_eq!(
        declared_capabilities(&native_read.body),
        vec!["rust:native", "rust:shared"]
    );
    append_observation(&mut observations, "native_read_own_write", &native_read);
    let hash_after_native = sha256(&db);
    assert_ne!(hash_after_native, hash_after_python);

    // Release the database before the retained Python writer replaces this
    // agent's declarations. The next native process will then read its exact
    // updated v0 schema after a real close/reopen boundary.
    proxy.shutdown().await;
    fs::write(
        coord_root.join("native-written.json"),
        serde_json::to_vec_pretty(&json!({
            "db_sha256": hash_after_native,
            "capabilities": ["rust:native", "rust:shared"],
        }))
        .unwrap(),
    )
    .unwrap();
    let python_update = wait_for_file(&coord_root.join("python-updated.json")).await;
    assert_eq!(
        python_update["capabilities"],
        json!(["python:final", "python:shared"])
    );
    assert_ne!(python_update["db_sha256"], hash_after_native);

    let restarted = Proxy::start(config(runtime.path())).await.unwrap();
    wait_for_path(&socket).await;
    let reloaded = exchange(&socket, &request("GET", &state_path, b"")).await;
    assert_eq!(reloaded.status, 200);
    assert_eq!(
        declared_capabilities(&reloaded.body),
        vec!["python:final", "python:shared"]
    );
    append_observation(&mut observations, "native_reload_python_write", &reloaded);
    restarted.shutdown().await;

    let evidence_path = std::env::var_os("SAFEYOLO_COORD_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| coord_root.join("native-evidence.json"));
    save_evidence(
        &evidence_path,
        &json!({
            "workflow": "coordination-state-cross-version",
            "room_name": room,
            "agent_id": "ag-11111111111111111111111111111111",
            "external_store": "retained coord v0.db",
            "db_sha256_after_python": hash_after_python,
            "db_sha256_after_native": hash_after_native,
            "db_sha256_after_python_reload": python_update["db_sha256"],
            "observations": observations,
            "limits": [
                "This covers capability declarations only; resource leases and provider live state remain separate.",
                "The test uses a close/reopen boundary; it does not claim process lifecycle or NATS subscription shutdown behavior.",
            ],
        }),
    );
}
