//! Real loopback operator-consumer witnesses for the retained #627 facade.
//! The bearer and policy values are synthetic; responses are observed over the
//! bound admin TCP listener and the event stream is a real WebSocket upgrade.

use std::{
    io::Write as _,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Uri, body::Incoming};
use hyper_util::rt::TokioIo;
use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UnixStream},
    sync::Notify,
};

const POLICY: &str = r#"
budget = 10

[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
"#;

#[tokio::test]
async fn native_operator_consumer_controls_and_event_stream_are_live() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let config = config(directory.path(), token);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);

    let instance = admin(port, token, "GET", "/admin/instance", b"").await;
    assert_eq!(instance.status, 200);
    let instance_json = instance.json();
    assert_eq!(instance_json["schema_version"], 1);
    assert!(instance_json["safeyolo_instance_id"].is_string());
    assert_eq!(instance_json["capabilities"]["approvals"], true);

    let identity = admin(port, token, "GET", "/admin/runtime-identity", b"").await;
    assert_eq!(identity.status, 200);
    assert_eq!(identity.json()["state"], "active");

    let modes = admin(port, token, "GET", "/modes", b"").await;
    assert_eq!(modes.status, 200);
    assert_eq!(modes.json()["modes"]["network-guard"], "block");
    let changed = admin(
        port,
        token,
        "PUT",
        "/plugins/network-guard/mode",
        br#"{"mode":"warn"}"#,
    )
    .await;
    assert_eq!(changed.status, 200);
    assert_eq!(
        admin(port, token, "GET", "/plugins/network-guard/mode", b"")
            .await
            .json()["mode"],
        "warn"
    );
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(
        admin(port, token, "GET", "/plugins/network-guard/mode", b"")
            .await
            .json()["mode"],
        "warn"
    );

    let baseline = admin(port, token, "GET", "/admin/policy/baseline", b"").await;
    assert_eq!(baseline.status, 200);
    assert!(baseline.json()["baseline"]["permissions"].is_array());

    let validation = admin(
        port,
        token,
        "POST",
        "/admin/policy/validate",
        br#"{"content":"permissions:\n  - action: network:request\n    resource: '*'\n    effect: allow\n"}"#,
    )
    .await;
    assert_eq!(validation.status, 200);
    assert_eq!(validation.json()["valid"], true);

    let replaced = admin(
        port,
        token,
        "PUT",
        "/admin/policy/baseline",
        br#"{"policy":{"budget":10,"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}}"#,
    )
    .await;
    assert_eq!(replaced.status, 200);
    assert!(proxy.reload_policy_if_changed().await.unwrap());

    let allowed = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/allow",
        br#"{"host":"approved.example","rate":5}"#,
    )
    .await;
    assert_eq!(allowed.status, 200);
    assert!(
        std::fs::read_to_string(config.policy_file.as_ref().unwrap())
            .unwrap()
            .contains("approved.example")
    );
    let rate = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/rate",
        br#"{"host":"approved.example","rate":4}"#,
    )
    .await;
    assert_eq!(rate.status, 200);
    let bypass = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/bypass",
        br#"{"host":"approved.example","addon":"network-guard"}"#,
    )
    .await;
    assert_eq!(bypass.status, 200);
    let host_denied = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/deny",
        br#"{"host":"blocked.example","expires":"2030-01-01T00:00:00Z"}"#,
    )
    .await;
    assert_eq!(host_denied.status, 200);
    let credential_approval = admin(
        port,
        token,
        "POST",
        "/admin/policy/baseline/approve",
        br#"{"destination":"approved.example","cred_id":["synthetic:one","synthetic:two"],"tier":"explicit"}"#,
    )
    .await;
    assert_eq!(credential_approval.status, 200);
    let policy_text = std::fs::read_to_string(config.policy_file.as_ref().unwrap()).unwrap();
    assert!(policy_text.contains("network-guard"));
    assert!(policy_text.contains("synthetic:one"));

    let denied = admin(
        port,
        token,
        "POST",
        "/admin/policy/baseline/deny",
        br#"{"destination":"approved.example","cred_id":"synthetic:fingerprint","reason":"fixture"}"#,
    )
    .await;
    assert_eq!(denied.status, 200);
    let approvals = admin(port, token, "GET", "/admin/approvals", b"").await;
    assert_eq!(approvals.status, 200);
    assert!(approvals.json()["approvals"].is_array());

    let agents = admin(port, token, "GET", "/admin/agents", b"").await;
    assert_eq!(agents.status, 200);
    assert_eq!(agents.json()["agents"].as_array().unwrap().len(), 1);

    let mut events = connect_events(port, token).await;

    let live_event = admin(
        port,
        token,
        "POST",
        "/admin/policy/baseline/deny",
        br#"{"destination":"stream.example","cred_id":"synthetic:stream","reason":"fixture"}"#,
    )
    .await;
    assert_eq!(live_event.status, 200);
    let (header, body) = read_ws_frame(&mut events).await;
    assert_eq!(header[0] & 0x0f, 1);
    let event: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["event"], "admin.denial");
    assert_eq!(event["details"]["destination"], "stream.example");

    // Invalid credentials are rejected before any event upgrade.
    let unauthorized = admin(port, "wrong-synthetic-token", "GET", "/admin/events", b"").await;
    assert_eq!(unauthorized.status, 401);
    proxy.shutdown().await;
    let (header, _) = read_ws_frame(&mut events).await;
    assert_eq!(
        header[0] & 0x0f,
        8,
        "shutdown must close owned event streams"
    );
}

#[tokio::test]
async fn native_operator_approval_denial_then_retry_is_resolved() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let policy = r#"
budget = 10

[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"

[[permissions]]
action = "credential:use"
resource = "*"
effect = "prompt"

[[credential_rules]]
name = "synthetic"
patterns = ["key-[a-z]+"]
allowed_hosts = ["127.0.0.1"]
header_names = ["authorization"]

[addons.credential_guard]
enabled = true

[addons.credential_guard.settings]
use_default_credential_rules = false
"#;
    let config = config_with_policy(directory.path(), token, policy);
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_count = Arc::new(AtomicUsize::new(0));
    let origin_ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(approval_origin(origin, origin_count.clone(), origin_ready));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let mut events = connect_events(port, token).await;

    let stream = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let uri: Uri = format!("http://127.0.0.1:{origin_port}/approval")
        .parse()
        .unwrap();

    let first = agent_request(&mut sender, uri.clone(), "Bearer key-retry").await;
    assert_eq!(first.status(), 428);
    let first_response_id = agent_request_id(&first);
    let _ = first.collect().await.unwrap();
    assert_eq!(origin_count.load(Ordering::Acquire), 0);

    let prompt_event = read_event(&mut events).await;
    assert_eq!(prompt_event["event"], "security.credential_guard");
    assert_eq!(prompt_event["request_id"], first_response_id);
    assert_eq!(prompt_event["agent"], "alice");
    assert_eq!(
        prompt_event["details"]["attribution"]["evidence_owner"],
        "alice"
    );
    assert_eq!(
        prompt_event["details"]["attribution"]["trusted_transport_identity"],
        "alice"
    );
    assert_eq!(prompt_event["approval"]["required"], true);

    let first_pending = wait_for_pending(port, token, None).await;
    let first_event = first_pending["approvals"]
        .as_array()
        .and_then(|items| items.first())
        .unwrap();
    let fingerprint = first_event["approval"]["key"].as_str().unwrap().to_owned();
    let destination = first_event["approval"]["target"]
        .as_str()
        .unwrap()
        .to_owned();
    let first_prompt_id = first_event["request_id"].as_str().unwrap().to_owned();
    assert_eq!(first_prompt_id, first_response_id);
    let denial = serde_json::to_vec(&json!({
        "destination": destination,
        "cred_id": fingerprint,
        "reason": "fixture",
        "approval_request_id": first_prompt_id,
    }))
    .unwrap();
    assert_eq!(
        admin(port, token, "POST", "/admin/policy/baseline/deny", &denial,)
            .await
            .status,
        200
    );

    let denial_event = read_event(&mut events).await;
    assert_eq!(denial_event["event"], "admin.denial");
    assert_eq!(
        denial_event["details"]["approval_request_id"],
        first_prompt_id
    );

    let second = agent_request(&mut sender, uri, "Bearer key-retry").await;
    assert_eq!(second.status(), 428);
    let second_response_id = agent_request_id(&second);
    let _ = second.collect().await.unwrap();
    assert_ne!(first_response_id, second_response_id);
    assert_eq!(origin_count.load(Ordering::Acquire), 0);

    let retry_event = read_event(&mut events).await;
    assert_eq!(retry_event["event"], "security.credential_guard");
    assert_eq!(retry_event["request_id"], second_response_id);
    assert_eq!(retry_event["agent"], "alice");

    let second_pending = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let pending = admin(port, token, "GET", "/admin/approvals", b"").await;
            let document = pending.json();
            if document["approvals"].as_array().is_some_and(Vec::is_empty) {
                break document;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(second_pending["approvals"].as_array().unwrap().is_empty());

    events.shutdown().await.unwrap();
    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_operator_event_reconnect_does_not_replay_old_events() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let config = config(directory.path(), token);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);

    let mut first = connect_events(port, token).await;
    assert_eq!(
        admin(
            port,
            token,
            "POST",
            "/admin/policy/baseline/deny",
            br#"{"destination":"before-reconnect.example","cred_id":"synthetic:old","reason":"fixture"}"#,
        )
        .await
        .status,
        200
    );
    let old_event = read_event(&mut first).await;
    assert_eq!(
        old_event["details"]["destination"],
        "before-reconnect.example"
    );
    first.shutdown().await.unwrap();

    let mut reconnect = connect_events(port, token).await;
    let replay =
        tokio::time::timeout(Duration::from_millis(250), read_ws_frame(&mut reconnect)).await;
    assert!(
        replay.is_err(),
        "reconnect replayed an event from before its handshake"
    );

    assert_eq!(
        admin(
            port,
            token,
            "POST",
            "/admin/policy/baseline/deny",
            br#"{"destination":"after-reconnect.example","cred_id":"synthetic:new","reason":"fixture"}"#,
        )
        .await
        .status,
        200
    );
    let live_event = read_event(&mut reconnect).await;
    assert_eq!(live_event["event"], "admin.denial");
    assert_eq!(
        live_event["details"]["destination"],
        "after-reconnect.example"
    );

    reconnect.shutdown().await.unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn native_operator_stalled_event_subscriber_does_not_block_controls() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let policy = r#"
budget = 10

[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"

[[permissions]]
action = "credential:use"
resource = "*"
effect = "prompt"

[[credential_rules]]
name = "synthetic"
patterns = ["key-[a-z]+"]
allowed_hosts = ["127.0.0.1"]
header_names = ["authorization"]

[addons.credential_guard]
enabled = true

[addons.credential_guard.settings]
use_default_credential_rules = false
"#;
    let config = config_with_policy(directory.path(), token, policy);
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_count = Arc::new(AtomicUsize::new(0));
    let origin_task = tokio::spawn(approval_origin(
        origin,
        origin_count.clone(),
        Arc::new(Notify::new()),
    ));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let mut stalled = connect_stalled_events(port, token).await;
    let mut observer = connect_events(port, token).await;

    // Keep `stalled` connected but never read from it. Each complete selected
    // event is 256 KiB and the burst is larger than TCP's send buffer. The
    // second real WebSocket drains the same burst and waits for its final
    // marker, providing a stream-tail barrier instead of a timer.
    let summary = "x".repeat(256 * 1024);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(config.audit_log_path.as_ref().unwrap())
        .unwrap();
    for sequence in 0..32 {
        let line = serde_json::to_vec(&json!({
            "event":"security.credential_guard",
            "kind":"security",
            "severity":"critical",
            "summary":summary,
            "details":{"sequence":sequence}
        }))
        .unwrap();
        file.write_all(&line).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.write_all(
        serde_json::to_string(&json!({
            "event":"security.credential_guard",
            "kind":"security",
            "severity":"critical",
            "summary":"event stream backpressure barrier",
            "details":{"barrier":true}
        }))
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
    file.write_all(b"\n").unwrap();
    file.flush().unwrap();

    let (barrier, sequences) = tokio::time::timeout(Duration::from_secs(20), async {
        let mut sequences = Vec::new();
        loop {
            let event = read_event(&mut observer).await;
            if event["details"]["barrier"] == true {
                break (event, sequences);
            }
            sequences.push(event["details"]["sequence"].as_u64().unwrap());
        }
    })
    .await
    .expect("fast observer did not reach the stream-tail barrier");
    assert_eq!(barrier["summary"], "event stream backpressure barrier");
    assert_eq!(sequences, (0..32).collect::<Vec<_>>());

    let mut discarded = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stalled.read_to_end(&mut discarded))
        .await
        .expect("stalled stream did not reach EOF after the bounded server write timeout")
        .unwrap();

    let stream = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let uri: Uri = format!("http://127.0.0.1:{origin_port}/stalled")
        .parse()
        .unwrap();
    let started = Instant::now();
    let response = agent_request(&mut sender, uri, "Bearer key-stalled").await;
    assert_eq!(response.status(), 428);
    let _ = response.collect().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stalled event subscriber delayed enforcement"
    );
    assert_eq!(origin_count.load(Ordering::Acquire), 0);

    drop(sender);
    let _ = connection_task.await;
    drop(stalled);
    drop(observer);
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_operator_invalid_mutations_are_terminal_and_state_preserving() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let config = config(directory.path(), token);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let policy_path = config.policy_file.as_ref().unwrap();
    let before_policy = std::fs::read(policy_path).unwrap();

    // Malformed JSON reaches one terminal response and never enters the
    // policy transaction.
    let malformed_baseline = admin(port, token, "PUT", "/admin/policy/baseline", b"{").await;
    assert_eq!(malformed_baseline.status, 400);
    assert_eq!(
        malformed_baseline.json()["error"],
        "Malformed JSON in request body"
    );
    assert_eq!(std::fs::read(policy_path).unwrap(), before_policy);

    // A syntactically valid body with an invalid policy is also rejected before
    // the durable file changes.
    let invalid_policy = admin(
        port,
        token,
        "PUT",
        "/admin/policy/baseline",
        br#"{"policy":{"permissions":[{"action":"network:request","resource":"*","effect":"not-a-policy-effect"}]}}"#,
    )
    .await;
    assert_eq!(invalid_policy.status, 400);
    assert_eq!(invalid_policy.json()["error"], "invalid policy");
    assert_eq!(std::fs::read(policy_path).unwrap(), before_policy);

    // Registration has its own atomic document owner. Both malformed JSON and
    // an invalid replacement retain the previously registered task.
    let initial_task = br#"{"policy":{"permissions":[]}}"#;
    assert_eq!(
        admin(port, token, "PUT", "/admin/policy/task/alpha", initial_task,)
            .await
            .status,
        200
    );
    let malformed_task = admin(port, token, "PUT", "/admin/policy/task/alpha", b"{").await;
    assert_eq!(malformed_task.status, 400);
    assert_eq!(
        malformed_task.json()["error"],
        "Malformed JSON in request body"
    );
    assert_eq!(
        admin(port, token, "GET", "/admin/policy/task/alpha", b"")
            .await
            .json()["policy"],
        json!({"permissions": []})
    );
    let invalid_task = admin(
        port,
        token,
        "PUT",
        "/admin/policy/task/alpha",
        br#"{"policy":{"permissions":false}}"#,
    )
    .await;
    assert_eq!(invalid_task.status, 400);
    assert_eq!(invalid_task.json()["error"], "Invalid policy document");
    assert_eq!(
        admin(port, token, "GET", "/admin/policy/task/alpha", b"")
            .await
            .json()["policy"],
        json!({"permissions": []})
    );

    // The malformed reset bodies terminate before either owner is consulted.
    // Component controls separately prove that the corresponding counters and
    // circuit domains retain their pre-request state.
    let malformed_budget = admin(port, token, "POST", "/admin/budgets/reset", b"{").await;
    assert_eq!(malformed_budget.status, 400);
    assert_eq!(
        malformed_budget.json()["error"],
        "Malformed JSON in request body"
    );
    let malformed_circuit =
        admin(port, token, "POST", "/admin/circuit-breaker/reset", b"\xff").await;
    assert_eq!(malformed_circuit.status, 400);
    assert_eq!(
        malformed_circuit.json()["error"],
        "Malformed JSON in request body"
    );

    let malformed_mode = admin(port, token, "PUT", "/plugins/network-guard/mode", b"{").await;
    assert_eq!(malformed_mode.status, 400);
    assert_eq!(
        malformed_mode.json()["error"],
        "Malformed JSON in request body"
    );
    assert_eq!(
        admin(port, token, "GET", "/plugins/network-guard/mode", b"",)
            .await
            .json()["mode"],
        "block"
    );

    // Make the policy directory unable to create the transaction temporary
    // file. The existing policy bytes remain the only accepted snapshot, and
    // both baseline and host mutations return one ordinary 400 response.
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let failed_baseline = admin(
        port,
        token,
        "PUT",
        "/admin/policy/baseline",
        br#"{"policy":{"budget":10,"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}}"#,
    )
    .await;
    assert_eq!(failed_baseline.status, 400);
    assert_eq!(failed_baseline.json()["error"], "invalid policy");
    assert_eq!(std::fs::read(policy_path).unwrap(), before_policy);
    let failed_host = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/allow",
        br#"{"host":"write-failure.example","rate":5}"#,
    )
    .await;
    assert_eq!(failed_host.status, 400);
    assert_eq!(failed_host.json()["error"], "invalid policy");
    assert_eq!(std::fs::read(policy_path).unwrap(), before_policy);
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    proxy.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_operator_mutations_keep_committed_state_when_audit_sink_fails() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let mut config = config(directory.path(), token);
    // This is an actual failing canonical audit sink after Writer::emit has
    // accepted the event. The worker reports the asynchronous flush failure
    // through stderr fallback and continues; mutation owners retain their
    // normal committed response semantics and do not roll state back.
    // Synchronous submission errors are covered by the crate-internal listener
    // test.
    config.audit_log_path = Some("/dev/full".into());
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let policy_path = config.policy_file.as_ref().unwrap();

    let baseline = admin(
        port,
        token,
        "PUT",
        "/admin/policy/baseline",
        br#"{"policy":{"budget":10,"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}}"#,
    )
    .await;
    assert_eq!(baseline.status, 200);
    assert_eq!(baseline.header("x-safeyolo-evidence-error"), None);
    assert!(
        std::fs::read_to_string(policy_path)
            .unwrap()
            .contains("action = \"network:request\"")
    );

    let mode = admin(
        port,
        token,
        "PUT",
        "/plugins/network-guard/mode",
        br#"{"mode":"warn"}"#,
    )
    .await;
    assert_eq!(mode.status, 200);
    assert_eq!(mode.header("x-safeyolo-evidence-error"), None);
    assert_eq!(
        admin(port, token, "GET", "/plugins/network-guard/mode", b"",)
            .await
            .json()["mode"],
        "warn"
    );

    let host = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/allow",
        br#"{"host":"diagnostic-failure.example","rate":5}"#,
    )
    .await;
    assert_eq!(host.status, 200);
    assert_eq!(host.header("x-safeyolo-evidence-error"), None);
    assert!(
        std::fs::read_to_string(policy_path)
            .unwrap()
            .contains("diagnostic-failure.example")
    );

    proxy.shutdown().await;
}

async fn connect_stalled_events(port: u16, token: &str) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut events = socket
        .connect((Ipv4Addr::LOCALHOST, port).into())
        .await
        .unwrap();
    events
        .write_all(
            format!(
                "GET /admin/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Authorization: Bearer {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let handshake = read_headers(&mut events).await;
    assert!(handshake.starts_with(b"HTTP/1.1 101"));
    events
}

fn config(directory: &Path, token: &str) -> Config {
    config_with_policy(directory, token, POLICY)
}

fn config_with_policy(directory: &Path, token: &str, policy: &str) -> Config {
    std::fs::write(directory.join("policy.toml"), policy).unwrap();
    std::fs::write(directory.join("operator-token"), token).unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":directory.join("policy.toml"),
        "data_dir":directory.join("data"),
        "agent_api_enabled":false,
        "admin_port":0,
        "admin_api_token_file":directory.join("operator-token"),
        "readiness_file":directory.join("ready.json"),
        "flow_store_enabled":false,
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl")
    }))
    .unwrap()
}

async fn approval_origin(listener: TcpListener, count: Arc<AtomicUsize>, ready: Arc<Notify>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let count = count.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut chunk).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            count.fetch_add(1, Ordering::Release);
            ready.notify_one();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });
    }
}

async fn connect_events(port: u16, token: &str) -> TcpStream {
    let mut events = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    events
        .write_all(
            format!(
                "GET /admin/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Authorization: Bearer {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let handshake = read_headers(&mut events).await;
    assert!(handshake.starts_with(b"HTTP/1.1 101"));
    events
}

async fn read_event(stream: &mut TcpStream) -> Value {
    let (header, body) = read_ws_frame(stream).await;
    assert_eq!(header[0] & 0x0f, 1);
    serde_json::from_slice(&body).unwrap()
}

async fn wait_for_pending(port: u16, token: &str, request_id: Option<&str>) -> Value {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let pending = admin(port, token, "GET", "/admin/approvals", b"").await;
            let document = pending.json();
            let matches = document["approvals"].as_array().is_some_and(|items| {
                !items.is_empty()
                    && request_id.is_none_or(|request_id| {
                        items.iter().any(|item| item["request_id"] == request_id)
                    })
            });
            if matches {
                return document;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

async fn agent_request(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    uri: Uri,
    credential: &str,
) -> hyper::Response<Incoming> {
    sender
        .send_request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("Authorization", credential)
                .body(Empty::new())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn agent_request_id(response: &hyper::Response<Incoming>) -> String {
    response
        .headers()
        .get("x-safeyolo-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn admin_port(config: &Config) -> u16 {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
    ready["admin_port"].as_u64().unwrap().try_into().unwrap()
}

struct Reply {
    status: u16,
    #[cfg(target_os = "linux")]
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    #[cfg(target_os = "linux")]
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn admin(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bytes
            .windows(b"HTTP/1.1 ".len())
            .filter(|window| *window == b"HTTP/1.1 ")
            .count(),
        1,
        "one request must produce one final HTTP response"
    );
    let split = bytes
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&bytes[..split]).unwrap();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    #[cfg(target_os = "linux")]
    let headers = head
        .lines()
        .skip(1)
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_owned(), value.trim().to_owned())
        })
        .collect();
    Reply {
        status,
        #[cfg(target_os = "linux")]
        headers,
        body: bytes[split + 4..].to_vec(),
    }
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut one = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut one).await.unwrap();
        bytes.push(one[0]);
    }
    bytes
}

async fn read_ws_frame(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let mut length = usize::from(header[1] & 0x7f);
    if length == 126 {
        let mut extended = [0u8; 2];
        stream.read_exact(&mut extended).await.unwrap();
        length = usize::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0u8; 8];
        stream.read_exact(&mut extended).await.unwrap();
        length = u64::from_be_bytes(extended).try_into().unwrap();
    }
    assert_eq!(header[1] & 0x80, 0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (header.to_vec(), body)
}
