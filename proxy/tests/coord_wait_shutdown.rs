//! Native coordination wait ownership at the process shutdown boundary.
//!
//! This is a wire-level witness for one real coordination worker.  A room and
//! receive grant are prepared in the retained SQLite control plane and its
//! JetStream stream is live.  The native agent API starts an attention wait,
//! the operator API stays responsive while that wait is pending, and the
//! supported `Proxy::shutdown` boundary then cancels the request and removes
//! the NATS subscription before returning.
//!
//! The test needs a real SafeYolo NATS fixture.  The command used to produce
//! the retained evidence starts the pinned fixture through the existing
//! Python `nats_runtime`; the test does not create a second coordination
//! database or substitute a fake provider.

use rusqlite::Connection;
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
    net::{TcpStream, UnixStream},
    time::{sleep, timeout},
};

const AGENT_TOKEN: &str = "coord-wait-agent-token";
const OPERATOR_TOKEN: &str = "coord-wait-operator-token";

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
        via_token: Some("coord-wait-test".into()),
        inspection: None,
        plumb: Default::default(),
    }
}

fn request(method: &str, path: &str, token: &str) -> Vec<u8> {
    format!(
        "{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn admin_request(path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {OPERATOR_TOKEN}\r\nConnection: close\r\n\r\n"
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

async fn exchange_admin(port: u16, bytes: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("operator response timeout")
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
    .expect("readiness/socket path must appear");
}

fn monitor_port() -> u16 {
    let root = std::env::var_os("SAFEYOLO_COORD_DATA_DIR")
        .expect("real coord fixture must set SAFEYOLO_COORD_DATA_DIR");
    let endpoints: Value = serde_json::from_slice(
        &fs::read(PathBuf::from(root).join("nats/test-endpoints.json")).unwrap(),
    )
    .unwrap();
    endpoints["monitor_port"].as_u64().unwrap() as u16
}

async fn nats_connz() -> Value {
    let port = monitor_port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"GET /connz?subs=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("NATS connz response timeout")
        .unwrap();
    let body = String::from_utf8_lossy(&response)
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("NATS connz response head")
        .to_owned();
    serde_json::from_str(&body).expect("NATS connz JSON")
}

fn connection_subscription_count(connz: &Value, subject: &str) -> usize {
    connz["connections"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|connection| connection["subscriptions_list"].as_array())
        .map(|subscriptions| {
            subscriptions
                .iter()
                .filter(|value| value.as_str() == Some(subject))
                .count()
        })
        .sum()
}

fn write_fixture(root: &Path) {
    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root.join("admin-token"), OPERATOR_TOKEN).unwrap();
    // The native coordination principal is resolved from this exact policy
    // file. The room grant and room id are read from the retained fixture DB.
    fs::write(
        root.join("policy.toml"),
        "[agents.alice]\nagent_id = 'ag-alice'\n\n[[permissions]]\naction = 'network:request'\nresource = '*'\neffect = 'deny'\n",
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_attention_wait_is_reclaimed_by_proxy_shutdown() {
    assert!(
        std::env::var_os("SAFEYOLO_NATS_TEST_INSTANCE").is_some(),
        "set SAFEYOLO_NATS_TEST_INSTANCE for the real NATS fixture"
    );
    let fixture_root = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_DATA_DIR")
            .expect("real coord fixture must set SAFEYOLO_COORD_DATA_DIR"),
    );
    let fixture: Value =
        serde_json::from_slice(&fs::read(fixture_root.join("fixture.json")).unwrap()).unwrap();
    assert!(fixture["room_id"].as_str().unwrap().starts_with("rm-"));
    let backing = Connection::open(fixture_root.join("v0.db")).unwrap();
    let (room_id, permissions): (String, String) = backing
        .query_row(
            "SELECT r.room_id, m.permissions
             FROM rooms AS r
             JOIN memberships AS m ON m.room_id = r.room_id
             WHERE r.name = 'coord-shutdown-room'
               AND m.principal_kind = 'agent'
               AND m.principal_id = 'ag-alice'
               AND m.revoked_at IS NULL
             ORDER BY m.granted_at DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(Some(room_id.as_str()), fixture["room_id"].as_str());
    assert!(
        permissions
            .split(',')
            .any(|permission| permission == "receive")
    );

    let root = TempDir::new().unwrap();
    write_fixture(root.path());
    let config = config(root.path());
    let proxy = Proxy::start(config.clone()).await.unwrap();
    wait_for_path(&config.listeners[0].socket_path).await;
    wait_for_path(&config.readiness_file).await;
    let readiness: Value =
        serde_json::from_slice(&fs::read(&config.readiness_file).unwrap()).unwrap();
    let admin_port = readiness["admin_port"].as_u64().unwrap() as u16;
    let instance_id = readiness["instance_id"].as_str().unwrap().to_owned();

    // Keep the request's stream open. The route has already authenticated the
    // configured listener identity, read the durable room grant, and entered
    // its real attention subscription when this observation is captured.
    let mut wait_socket = UnixStream::connect(&config.listeners[0].socket_path)
        .await
        .unwrap();
    wait_socket
        .write_all(&request(
            "GET",
            "/api/coord/attention/wait?since=0&limit=1&timeout=300",
            AGENT_TOKEN,
        ))
        .await
        .unwrap();
    let nats_subscription_subject = "coord.attention.ag-alice";
    let mut connz_before = Value::Null;
    let mut subscriptions_before = 0;
    for _ in 0..50 {
        connz_before = nats_connz().await;
        subscriptions_before =
            connection_subscription_count(&connz_before, nats_subscription_subject);
        if subscriptions_before >= 1 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        subscriptions_before >= 1,
        "native attention wait must create a live NATS subscription: {connz_before}"
    );

    // The unrelated native operator path remains responsive while the wait is
    // held. This is a concrete process-level check, not an internal counter.
    let admin_response = exchange_admin(admin_port, &admin_request("/stats")).await;
    assert_eq!(admin_response.status, 200);
    assert!(admin_response.body.is_object());
    let admin_identity =
        exchange_admin(admin_port, &admin_request("/admin/runtime-identity")).await;
    assert_eq!(admin_identity.status, 200);
    assert_eq!(admin_identity.body["instance_id"], instance_id);

    let started = tokio::time::Instant::now();
    proxy.shutdown().await;
    let shutdown_elapsed_ms = started.elapsed().as_millis();

    // The process-owned cleanup has completed before Proxy::shutdown returns.
    // The NATS client itself remains available for the external fixture, so
    // connz gives an independent observation of the subscription disappearing.
    let mut subscriptions_after = usize::MAX;
    for _ in 0..50 {
        let connz_after = nats_connz().await;
        subscriptions_after =
            connection_subscription_count(&connz_after, nats_subscription_subject);
        if subscriptions_after == 0 {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        subscriptions_after, 0,
        "wait subscription must be reclaimed"
    );
    assert!(!config.readiness_file.exists());
    assert!(!config.listeners[0].socket_path.exists());
    let mut wait_bytes = Vec::new();
    timeout(
        Duration::from_secs(2),
        wait_socket.read_to_end(&mut wait_bytes),
    )
    .await
    .expect("shutdown must close the held wait connection")
    .unwrap();
    assert!(
        wait_bytes.is_empty(),
        "shutdown must close, not fabricate a wait result"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", admin_port)).await.is_err(),
        "admin listener must close at shutdown"
    );

    let evidence = json!({
        "workflow": "native-coordination-attention-wait-shutdown",
        "candidate": std::env::var("SAFEYOLO_CANDIDATE_COMMIT").unwrap_or_else(|_| "unknown".into()),
        "room_id": fixture["room_id"],
        "backing_membership": {"principal_id":"ag-alice", "permissions":permissions},
        "agent_identity": "ag-alice resolved from configured Unix listener + policy",
        "origin_instance_id": instance_id,
        "nats_subscription_subject": nats_subscription_subject,
        "subscriptions_before": subscriptions_before,
        "subscriptions_after": subscriptions_after,
        "admin_status_while_wait": admin_response.status,
        "admin_runtime_identity_status": admin_identity.status,
        "shutdown_elapsed_ms": shutdown_elapsed_ms,
        "readiness_removed": !config.readiness_file.exists(),
        "agent_socket_removed": !config.listeners[0].socket_path.exists(),
        "remaining_scope": [
            "other #626/#628/#629 standalone workers",
            "full producer/protocol matrix",
            "abrupt termination and blocked I/O",
        ],
    });
    println!("coord-wait-634 observation: {evidence}");
    if let Some(path) = std::env::var_os("SAFEYOLO_COORD_WAIT_EVIDENCE") {
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}
