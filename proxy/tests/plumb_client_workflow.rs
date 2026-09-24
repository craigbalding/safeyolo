//! Running-client proof for the retained native collaboration workflow.
//!
//! The client identities in this test come from the accepted Unix listener,
//! while the operator mutations use the retained authenticated admin listener.
//! Request bodies deliberately contain an attempted caller override so the
//! evidence records the identity and membership decisions made at the real
//! transport boundary.

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
};

const AGENT_TOKEN: &str = "plumb-client-agent-token";
const OPERATOR_TOKEN: &str = "plumb-client-operator-token";

#[derive(Debug)]
struct Reply {
    status: u16,
    body: Value,
}

fn config(root: &Path) -> Config {
    Config {
        listeners: ["alice", "bob", "carol", "dave"]
            .into_iter()
            .map(|agent| AgentListener {
                agent_id: agent.into(),
                socket_path: root.join(format!("{agent}.sock")),
                source_id: None,
            })
            .collect(),
        agent_map_file: String::new(),
        data_dir: Some(root.join("data")),
        temporary_policy_socket: Some(root.join("policy.sock")),
        policy_file: None,
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
        via_token: Some("plumb-client-test".into()),
        inspection: None,
        plumb: Default::default(),
    }
}

fn request(method: &str, path: &str, token: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body),
    )
    .into_bytes()
}

fn admin_request(method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {OPERATOR_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

async fn exchange_unix(socket: &Path, bytes: &[u8]) -> Reply {
    exchange_unix_with_timeout(socket, bytes, Duration::from_secs(5)).await
}

async fn exchange_unix_with_timeout(socket: &Path, bytes: &[u8], timeout: Duration) -> Reply {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut response))
        .await
        .expect("Unix client response timeout")
        .unwrap();
    parse_reply(&response)
}

async fn exchange_admin(port: u16, bytes: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("operator response timeout")
        .unwrap();
    parse_reply(&response)
}

fn admin_port(root: &Path) -> u16 {
    serde_json::from_slice::<Value>(&fs::read(root.join("ready.json")).unwrap())
        .unwrap()["admin_port"]
        .as_u64()
        .unwrap() as u16
}

fn write_evidence(root: &Path, observations: &[Value]) {
    let Some(path) = std::env::var_os("SAFEYOLO_PLUMB_EVIDENCE") else {
        return;
    };
    let evidence = json!({
        "workflow": "native-plumb-running-client",
        "candidate": std::env::var("SAFEYOLO_CANDIDATE_COMMIT").unwrap_or_default(),
        "listener_identity_source": "configured Unix listener path",
        "operator_identity_source": "authenticated loopback admin listener",
        "agent_token_used": "synthetic fixture; not retained",
        "data_dir": root.join("data").display().to_string(),
        "observations": observations,
        "audit_events": fs::read_to_string(root.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|row| row.get("event").and_then(Value::as_str).map(str::to_owned))
            .collect::<Vec<_>>(),
    });
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_clients_share_operator_approval_membership_and_messages() {
    let root = TempDir::new().unwrap();
    let root_path = root.path();
    fs::create_dir_all(root_path.join("data")).unwrap();
    fs::write(root_path.join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root_path.join("admin-token"), OPERATOR_TOKEN).unwrap();
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let operator_port = admin_port(root_path);
    let alice = root_path.join("alice.sock");
    let bob = root_path.join("bob.sock");
    let carol = root_path.join("carol.sock");
    let dave = root_path.join("dave.sock");
    let mut observations = Vec::new();

    // Alice's supplied requester field is ignored; the accepted listener owns
    // the identity recorded in the pending state and approval event.
    let requested = exchange_unix(
        &alice,
        &request(
            "POST",
            "/plumb/request-chat",
            AGENT_TOKEN,
            br#"{"requester":"dave","participants":["bob","carol"],"topic":"release","reason":"acceptance"}"#,
        ),
    )
    .await;
    assert_eq!(requested.status, 202);
    assert_eq!(requested.body["state"], "pending");
    assert_eq!(
        requested.body["participants"],
        json!(["alice", "bob", "carol"])
    );
    let request_id = requested.body["request_id"].as_str().unwrap().to_owned();
    observations
        .push(json!({"step":"alice_request","status":requested.status,"body":requested.body}));

    let pending = exchange_admin(
        operator_port,
        &admin_request("GET", "/admin/plumb/pending", b""),
    )
    .await;
    assert_eq!(pending.status, 200);
    assert_eq!(pending.body["pending"][0]["request_id"], request_id);
    assert_eq!(pending.body["pending"][0]["requester"], "alice");
    observations
        .push(json!({"step":"operator_pending","status":pending.status,"body":pending.body}));

    // A pending request has no conversation, even when its request ID is
    // presented as a conversation ID by the requesting client.
    let pending_read = exchange_unix(
        &alice,
        &request(
            "GET",
            &format!("/plumb/conversations/{request_id}/messages"),
            AGENT_TOKEN,
            b"",
        ),
    )
    .await;
    assert_eq!(pending_read.status, 403);
    observations.push(
        json!({"step":"pending_cannot_read","status":pending_read.status,"body":pending_read.body}),
    );

    // A second request exercises the retained deny consumer and leaves no
    // stale pending approval which could later become a conversation.
    let denied_request = exchange_unix(
        &dave,
        &request(
            "POST",
            "/plumb/request-chat",
            AGENT_TOKEN,
            br#"{"agent":"alice","participants":["alice"],"note":"must be denied"}"#,
        ),
    )
    .await;
    assert_eq!(denied_request.status, 202);
    let denied_id = denied_request.body["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        denied_request.body["participants"],
        json!(["alice", "dave"])
    );
    let denied = exchange_admin(
        operator_port,
        &admin_request(
            "POST",
            "/admin/plumb/deny",
            serde_json::to_string(&json!({"request_id":denied_id}))
                .unwrap()
                .as_bytes(),
        ),
    )
    .await;
    assert_eq!(denied.status, 200);
    let denied_read = exchange_unix(
        &dave,
        &request(
            "GET",
            &format!("/plumb/conversations/{denied_id}/messages"),
            AGENT_TOKEN,
            b"",
        ),
    )
    .await;
    assert_eq!(denied_read.status, 403);
    let pending_after_deny = exchange_admin(
        operator_port,
        &admin_request("GET", "/admin/plumb/pending", b""),
    )
    .await;
    assert_eq!(pending_after_deny.status, 200);
    assert_eq!(
        pending_after_deny.body["pending"].as_array().unwrap().len(),
        1
    );
    observations.push(json!({"step":"deny","status":denied.status,"body":denied.body,"forbidden_read_status":denied_read.status,"pending_after_deny":pending_after_deny.body}));

    let approved = exchange_admin(
        operator_port,
        &admin_request(
            "POST",
            "/admin/plumb/approve",
            serde_json::to_string(&json!({"request_id":request_id,"ttl_seconds":120}))
                .unwrap()
                .as_bytes(),
        ),
    )
    .await;
    assert_eq!(approved.status, 200);
    let conversation_id = approved.body["conversation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        approved.body["participants"],
        json!(["alice", "bob", "carol"])
    );
    observations
        .push(json!({"step":"operator_approve","status":approved.status,"body":approved.body}));

    let alice_conversations = exchange_unix(
        &alice,
        &request("GET", "/plumb/conversations", AGENT_TOKEN, b""),
    )
    .await;
    let bob_conversations = exchange_unix(
        &bob,
        &request("GET", "/plumb/conversations", AGENT_TOKEN, b""),
    )
    .await;
    let dave_conversations = exchange_unix(
        &dave,
        &request("GET", "/plumb/conversations", AGENT_TOKEN, b""),
    )
    .await;
    assert_eq!(alice_conversations.status, 200);
    assert_eq!(bob_conversations.status, 200);
    assert_eq!(dave_conversations.status, 200);
    assert_eq!(
        alice_conversations.body["conversations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        bob_conversations.body["conversations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        dave_conversations.body["conversations"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // Knowing the ID does not confer membership. This positive-control client
    // is authenticated but was never approved for this conversation.
    for (agent, socket) in [("dave", &dave), ("forged-body", &dave)] {
        let forged = exchange_unix(
            socket,
            &request(
                "POST",
                &format!("/plumb/conversations/{conversation_id}/messages"),
                AGENT_TOKEN,
                format!(r#"{{"agent":"alice","from":"alice","body":"{agent}"}}"#).as_bytes(),
            ),
        )
        .await;
        assert_eq!(forged.status, 403);
        assert_eq!(forged.body["error"], "not a participant");
    }
    let forged_read = exchange_unix(
        &dave,
        &request(
            "GET",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            b"",
        ),
    )
    .await;
    let forged_leave = exchange_unix(
        &dave,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/leave"),
            AGENT_TOKEN,
            b"{}",
        ),
    )
    .await;
    assert_eq!(forged_read.status, 403);
    assert_eq!(forged_leave.status, 403);
    observations.push(json!({"step":"non_member_access","send_status":403,"read_status":forged_read.status,"leave_status":forged_leave.status,"body_identity_fields_ignored":true}));

    let first_message = exchange_unix(
        &alice,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"hello from alice","metadata":{"references":["release"]}}"#,
        ),
    )
    .await;
    assert_eq!(first_message.status, 200);
    let first_id = first_message.body["id"].as_str().unwrap().to_owned();
    let bob_read = exchange_unix(
        &bob,
        &request(
            "GET",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            b"",
        ),
    )
    .await;
    assert_eq!(bob_read.status, 200);
    assert_eq!(bob_read.body["messages"][0]["id"], first_id);
    assert_eq!(bob_read.body["messages"][0]["from_agent"], "alice");
    assert_eq!(bob_read.body["messages"][0]["body"], "hello from alice");
    assert_eq!(
        bob_read.body["messages"][0]["metadata"]["references"],
        json!(["release"])
    );

    // A real long-poll is woken by publication from another permitted client.
    let bob_wait_socket = bob.clone();
    let wait_path =
        format!("/plumb/conversations/{conversation_id}/messages?after={first_id}&wait=4");
    let waiter = tokio::spawn(async move {
        exchange_unix(
            &bob_wait_socket,
            &request("GET", &wait_path, AGENT_TOKEN, b""),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second_message = exchange_unix(
        &carol,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"publication wakes the permitted waiter"}"#,
        ),
    )
    .await;
    assert_eq!(second_message.status, 200);
    let waited = waiter.await.unwrap();
    assert_eq!(waited.status, 200);
    assert_eq!(
        waited.body["messages"][0]["body"],
        "publication wakes the permitted waiter"
    );
    observations.push(json!({"step":"message_exchange_and_long_poll","first_message":first_message.body,"bob_read":bob_read.body,"second_message":second_message.body,"waited":waited.body}));

    // Bob leaves while Alice and Carol remain. His outstanding wait is allowed
    // to finish with the source-compatible empty page; subsequent membership
    // checks reject him, while Alice remains able to publish.
    let bob_wait_socket = bob.clone();
    let leave_wait_path = format!(
        "/plumb/conversations/{conversation_id}/messages?after={}&wait=1",
        second_message.body["id"].as_str().unwrap()
    );
    let leave_waiter = tokio::spawn(async move {
        exchange_unix(
            &bob_wait_socket,
            &request("GET", &leave_wait_path, AGENT_TOKEN, b""),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let left = exchange_unix(
        &bob,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/leave"),
            AGENT_TOKEN,
            b"{}",
        ),
    )
    .await;
    assert_eq!(left.status, 200);
    let leave_wait = leave_waiter.await.unwrap();
    assert_eq!(leave_wait.status, 200);
    assert!(leave_wait.body["messages"].as_array().unwrap().is_empty());
    let bob_after_leave = exchange_unix(
        &bob,
        &request("GET", "/plumb/conversations", AGENT_TOKEN, b""),
    )
    .await;
    assert_eq!(bob_after_leave.status, 200);
    assert!(
        bob_after_leave.body["conversations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let alice_after_leave = exchange_unix(
        &alice,
        &request("GET", "/plumb/conversations", AGENT_TOKEN, b""),
    )
    .await;
    assert_eq!(
        alice_after_leave.body["conversations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let after_leave_message = exchange_unix(
        &alice,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"alice remains permitted after bob leaves"}"#,
        ),
    )
    .await;
    assert_eq!(after_leave_message.status, 200);
    observations.push(json!({"step":"leave_membership_and_wait","left":left.body,"wait":leave_wait.body,"bob_after_leave":bob_after_leave.body,"alice_after_leave":alice_after_leave.body,"post_after_leave":after_leave_message.body}));

    // Malformed JSON is contained at the local API boundary and does not
    // disturb a permitted member's subsequent operation.
    let malformed = exchange_unix(
        &alice,
        &request(
            "POST",
            "/plumb/request-chat",
            AGENT_TOKEN,
            br#"{"participants": ["bob"]"#,
        ),
    )
    .await;
    assert_eq!(malformed.status, 400);
    assert_eq!(malformed.body["error"], "no participants to chat with");
    observations
        .push(json!({"step":"malformed_request","status":malformed.status,"body":malformed.body}));

    // Operator close removes the remaining membership and prevents later
    // message reads. An outstanding waiter returns its source-compatible
    // empty page before the close is observable on the next request.
    let close_wait_socket = alice.clone();
    let close_after = after_leave_message.body["id"].as_str().unwrap().to_owned();
    let close_wait_path =
        format!("/plumb/conversations/{conversation_id}/messages?after={close_after}&wait=1");
    let close_waiter = tokio::spawn(async move {
        exchange_unix(
            &close_wait_socket,
            &request("GET", &close_wait_path, AGENT_TOKEN, b""),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let closed = exchange_admin(
        operator_port,
        &admin_request(
            "POST",
            "/admin/plumb/close",
            serde_json::to_string(&json!({"conversation_id":conversation_id}))
                .unwrap()
                .as_bytes(),
        ),
    )
    .await;
    assert_eq!(closed.status, 200);
    let close_wait = close_waiter.await.unwrap();
    assert_eq!(close_wait.status, 200);
    assert!(close_wait.body["messages"].as_array().unwrap().is_empty());
    let alice_after_close = exchange_unix(
        &alice,
        &request(
            "GET",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            b"",
        ),
    )
    .await;
    let carol_after_close = exchange_unix(
        &carol,
        &request("GET", "/plumb/conversations", AGENT_TOKEN, b""),
    )
    .await;
    assert_eq!(alice_after_close.status, 403);
    assert!(
        carol_after_close.body["conversations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    observations.push(json!({"step":"operator_close","closed":closed.body,"wait":close_wait.body,"alice_after_close":alice_after_close.body,"carol_after_close":carol_after_close.body}));

    write_evidence(root_path, &observations);
    proxy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_clients_release_wait_capacity_for_permitted_peer() {
    let root = TempDir::new().unwrap();
    let root_path = root.path();
    fs::create_dir_all(root_path.join("data")).unwrap();
    fs::write(root_path.join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root_path.join("admin-token"), OPERATOR_TOKEN).unwrap();
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let operator_port = admin_port(root_path);
    let alice = root_path.join("alice.sock");
    let bob = root_path.join("bob.sock");
    let carol = root_path.join("carol.sock");

    let requested = exchange_unix(
        &alice,
        &request(
            "POST",
            "/plumb/request-chat",
            AGENT_TOKEN,
            br#"{"requester":"forged","participants":["bob","carol"]}"#,
        ),
    )
    .await;
    assert_eq!(requested.status, 202);
    assert_eq!(
        requested.body["participants"],
        json!(["alice", "bob", "carol"])
    );
    let request_id = requested.body["request_id"].as_str().unwrap();
    let approved = exchange_admin(
        operator_port,
        &admin_request(
            "POST",
            "/admin/plumb/approve",
            serde_json::to_string(&json!({"request_id":request_id,"ttl_seconds":120}))
                .unwrap()
                .as_bytes(),
        ),
    )
    .await;
    assert_eq!(approved.status, 200);
    let conversation_id = approved.body["conversation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let first_message = exchange_unix(
        &alice,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"baseline before client disconnects"}"#,
        ),
    )
    .await;
    assert_eq!(first_message.status, 200);
    let first_id = first_message.body["id"].as_str().unwrap().to_owned();
    let wait_request = request(
        "GET",
        &format!("/plumb/conversations/{conversation_id}/messages?after={first_id}&wait=30"),
        AGENT_TOKEN,
        b"",
    );

    // MAX_WAITERS is 64 in the native owner. Keep these clients open until
    // their requests have had time to enter the real listener and long-poll
    // path, then close every client before a message is published.
    let mut disconnected_clients = Vec::new();
    for _ in 0..64 {
        let mut stream = UnixStream::connect(&bob).await.unwrap();
        stream.write_all(&wait_request).await.unwrap();
        disconnected_clients.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    drop(disconnected_clients);
    tokio::time::sleep(Duration::from_millis(250)).await;

    // If the dropped requests retained all 64 waiter slots, this request
    // returns an empty page immediately instead of waiting for the next
    // permitted publication. Its successful message proves both cleanup and
    // that another member's operation remains usable.
    let carol_wait_socket = carol.clone();
    let carol_wait_path =
        format!("/plumb/conversations/{conversation_id}/messages?after={first_id}&wait=5");
    let carol_waiter = tokio::spawn(async move {
        exchange_unix(
            &carol_wait_socket,
            &request("GET", &carol_wait_path, AGENT_TOKEN, b""),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let published = exchange_unix(
        &alice,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"permitted peer remains usable after disconnect cleanup"}"#,
        ),
    )
    .await;
    assert_eq!(published.status, 200);
    let carol_reply = tokio::time::timeout(Duration::from_secs(5), carol_waiter)
        .await
        .expect("permitted waiter response timeout")
        .unwrap();
    assert_eq!(carol_reply.status, 200);
    assert_eq!(carol_reply.body["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        carol_reply.body["messages"][0]["body"],
        "permitted peer remains usable after disconnect cleanup"
    );

    write_evidence(
        root_path,
        &[json!({
            "step":"client_disconnect_waiter_cleanup",
            "listener_identity_source":"bob and carol configured Unix listener paths",
            "conversation_participants":["alice","bob","carol"],
            "initial_waiters":64,
            "initial_wait_after_seconds":30,
            "disconnected_waiters":64,
            "cleanup_observation":"all client streams dropped before publication",
            "permitted_publisher":"alice",
            "permitted_waiter":"carol",
            "published_status":published.status,
            "waiter_status":carol_reply.status,
            "waiter_message":carol_reply.body["messages"][0],
            "state_owner":"native process-owned PlumbOwner",
            "limit":"bounded MAX_WAITERS saturation probe; no load or restart claim"
        })],
    );
    proxy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backing_state_failure_is_truthful_and_other_member_recovers() {
    let root = TempDir::new().unwrap();
    let root_path = root.path();
    fs::create_dir_all(root_path.join("data")).unwrap();
    fs::write(root_path.join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root_path.join("admin-token"), OPERATOR_TOKEN).unwrap();
    let proxy = Proxy::start(config(root_path)).await.unwrap();
    let operator_port = admin_port(root_path);
    let alice = root_path.join("alice.sock");
    let carol = root_path.join("carol.sock");

    let requested = exchange_unix(
        &alice,
        &request(
            "POST",
            "/plumb/request-chat",
            AGENT_TOKEN,
            br#"{"requester":"forged","participants":["bob","carol"]}"#,
        ),
    )
    .await;
    assert_eq!(requested.status, 202);
    assert_eq!(
        requested.body["participants"],
        json!(["alice", "bob", "carol"])
    );
    let request_id = requested.body["request_id"].as_str().unwrap();
    let approved = exchange_admin(
        operator_port,
        &admin_request(
            "POST",
            "/admin/plumb/approve",
            serde_json::to_string(&json!({"request_id":request_id,"ttl_seconds":120}))
                .unwrap()
                .as_bytes(),
        ),
    )
    .await;
    assert_eq!(approved.status, 200);
    let conversation_id = approved.body["conversation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let baseline = exchange_unix(
        &alice,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"durable baseline"}"#,
        ),
    )
    .await;
    assert_eq!(baseline.status, 200);
    let baseline_id = baseline.body["id"].as_str().unwrap().to_owned();

    // Hold the real SQLite writer lock from a second connection. The native
    // owner must report its failed write as 503 rather than claiming success.
    let blocker_path = root_path.join("data/plumb/plumb.db");
    let blocker = Connection::open(&blocker_path).unwrap();
    blocker
        .execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
        .unwrap();
    let failed = exchange_unix(
        &alice,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"must not be reported as committed"}"#,
        ),
    )
    .await;
    assert_eq!(failed.status, 503);
    assert_eq!(failed.body["error"], "plumb backing state unavailable");
    blocker.execute_batch("ROLLBACK").unwrap();

    // The failed row is absent, while another permitted listener identity can
    // publish successfully after the transient backing-state failure.
    let after_failure = exchange_unix(
        &carol,
        &request(
            "GET",
            &format!("/plumb/conversations/{conversation_id}/messages?after={baseline_id}"),
            AGENT_TOKEN,
            b"",
        ),
    )
    .await;
    assert_eq!(after_failure.status, 200);
    assert!(
        after_failure.body["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let recovered = exchange_unix(
        &carol,
        &request(
            "POST",
            &format!("/plumb/conversations/{conversation_id}/messages"),
            AGENT_TOKEN,
            br#"{"body":"Carol remains permitted after store recovery"}"#,
        ),
    )
    .await;
    assert_eq!(recovered.status, 200);
    let recovered_id = recovered.body["id"].as_str().unwrap();
    assert!(!recovered_id.is_empty());

    proxy.shutdown().await;
    let events = fs::read_to_string(root_path.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    let message_allowed = events
        .iter()
        .filter(|event| event["event"] == "plumb.message_allowed")
        .count();
    assert_eq!(message_allowed, 2, "baseline and Carol recovery only");
    write_evidence(
        root_path,
        &[json!({
            "step":"backing_state_write_failure_and_recovery",
            "listener_identity_source":"alice and carol configured Unix listener paths",
            "conversation_participants":["alice","bob","carol"],
            "failure_injection":"independent SQLite BEGIN IMMEDIATE writer lock",
            "failed_status":failed.status,
            "failed_body":failed.body,
            "failed_message_audit_present":false,
            "after_failure_messages":after_failure.body["messages"],
            "recovery_publisher":"carol",
            "recovery_status":recovered.status,
            "recovery_message_id":recovered_id,
            "message_allowed_audit_count":message_allowed,
            "state_owner":"native process-owned PlumbOwner",
            "limit":"transient SQLite writer-lock failure only; no corrupt-file or restart claim"
        })],
    );
}
