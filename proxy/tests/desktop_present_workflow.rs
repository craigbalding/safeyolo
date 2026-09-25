//! Running native agent-request/operator-approval desktop presentation proof.
//!
//! The first witness follows the retained operator client contract: a real
//! agent listener requests presentation, the authenticated operator lists the
//! durable approval, and the exact request ID is passed to the admin desktop
//! route. A harmless executable stands in for the host helper on this Linux
//! lane. The second witness removes that capability and records the real
//! unavailable response and correlated failure event. The lifetime tests
//! keep their process-global helper separate from the library test process.

use safeyolo_proxy::{AgentListener, Config, Proxy};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream as PreviewStream,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};

const AGENT_TOKEN: &str = "desktop-workflow-agent-token";
const OPERATOR_TOKEN: &str = "desktop-workflow-operator-token";

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
        temporary_policy_socket: Some(root.join("policy.sock")),
        policy_file: None,
        gateway_builtin_services_dir: None,
        gateway_services_dir: None,
        network_guard_enabled: false,
        network_guard_block: false,
        network_guard_homoglyph: false,
        credential_guard_block: false,
        circuit_breaker_enabled: false,
        circuit_state_file: None,
        agent_api_enabled: true,
        test_context_block: false,
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
        via_token: Some("desktop-workflow-test".into()),
        inspection: None,
        plumb: Default::default(),
    }
}

fn config_with_sibling(root: &Path) -> Config {
    let mut config = config(root);
    config.listeners.push(AgentListener {
        agent_id: "bob".into(),
        socket_path: root.join("bob.sock"),
        source_id: None,
    });
    config
}

fn agent_request(path: &str, body: &[u8]) -> Vec<u8> {
    format!(
        "POST http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {AGENT_TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    parse_reply(&response)
}

async fn exchange_admin(port: u16, bytes: &[u8]) -> Reply {
    parse_reply(&exchange_admin_raw(port, bytes).await)
}

async fn exchange_admin_raw(port: u16, bytes: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

fn admin_port(root: &Path) -> u16 {
    serde_json::from_slice::<Value>(&fs::read(root.join("ready.json")).unwrap())
        .unwrap()["admin_port"]
        .as_u64()
        .unwrap() as u16
}

fn fixture_helper(root: &Path) -> PathBuf {
    let script = root.join("desktop-presenter-fixture");
    fs::write(
        &script,
        r##"#!/bin/sh
IFS= read -r request
printf '%s\n' "$request" > "$0.request"
printf '%s %s %s\n' "$1" "$2" "$3" > "$0.args"
printf '%s\n' '{"agent_id":"durable-alice","agent":"alice","url":"http://127.0.0.1:1/vnc.html#fixture","unlock_code":"fixture-code","reused":false}'
"##,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    script
}

fn preview_helper(root: &Path, protocol_failure: bool) -> PathBuf {
    let script = root.join("desktop-presenter-preview");
    let body = r#"#!/usr/bin/env python3
import http.server
import json
import os
import sys
import threading

PROTOCOL_FAILURE = __PROTOCOL_FAILURE__

class Preview(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"preview-alive")

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Preview)
threading.Thread(target=server.serve_forever, daemon=True).start()
with open(__file__ + ".pids", "a", encoding="utf-8") as pids:
    pids.write(str(os.getpid()) + "\n")
url = "http://127.0.0.1:%s/vnc.html" % server.server_port
seen = False
try:
    for line in sys.stdin:
        request = json.loads(line)
        if request.get("shutdown"):
            break
        if request["agent_id"] == "bob":
            print("not-json" if PROTOCOL_FAILURE else '{"kind":"failed","error":"fixture"}', flush=True)
        else:
            print(json.dumps({"agent_id":"durable-alice","agent":"alice","url":url,
                              "unlock_code":"fixture","reused":seen}), flush=True)
            seen = True
finally:
    server.shutdown()
    server.server_close()
    with open(__file__ + ".closed", "a", encoding="utf-8") as closed:
        closed.write(str(os.getpid()) + "\n")
"#
    .replace(
        "__PROTOCOL_FAILURE__",
        if protocol_failure { "True" } else { "False" },
    );
    fs::write(&script, body).unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    script
}

fn helper_pids(script: &Path) -> Vec<u32> {
    fs::read_to_string(script.with_extension("pids"))
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect()
}

fn preview_replies(url: &str) -> bool {
    let port = url
        .split(':')
        .nth(2)
        .and_then(|value| value.split('/').next())
        .and_then(|value| value.parse::<u16>().ok())
        .expect("preview URL port");
    let Ok(mut stream) = PreviewStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .is_err()
        || stream
            .write_all(b"GET /vnc.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).is_ok()
        && response.starts_with("HTTP/1.0 200")
        && response.contains("preview-alive")
}

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn write_evidence(root: &Path, observations: &[Value], outcome: &str) {
    let Some(path) = std::env::var_os("SAFEYOLO_DESKTOP_EVIDENCE") else {
        return;
    };
    let path =
        PathBuf::from(path).with_file_name(format!("desktop-present-workflow-{outcome}.json"));
    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap_or_default();
    let events = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "workflow": "native-desktop-present-approval",
            "listener_identity_source": "accepted alice Unix listener",
            "operator_identity_source": "authenticated loopback admin listener",
            "tokens": "synthetic fixture; not retained",
            "observations": observations,
            "audit": events,
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)] // The process-global presenter environment must span this bounded native workflow.
async fn pending_agent_request_operator_approval_reaches_native_presenter() {
    let _lock = test_lock();
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root.path().join("admin-token"), OPERATOR_TOKEN).unwrap();
    let helper = fixture_helper(root.path());
    unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &helper) };
    let config = config(root.path());
    let proxy = Proxy::start(config).await.unwrap();
    let port = admin_port(root.path());
    let mut observations = Vec::new();

    let requested = exchange_unix(
        &root.path().join("alice.sock"),
        &agent_request("/desktop/present", br#"{"agent":"bob","target":"fixture"}"#),
    )
    .await;
    assert_eq!(requested.status, 202);
    assert_eq!(requested.body["status"], "pending");
    assert_eq!(requested.body["agent"], "alice");
    let request_id = requested.body["request_id"].as_str().unwrap().to_owned();
    observations
        .push(json!({"step":"agent_request","status":requested.status,"body":requested.body}));

    let pending = exchange_admin(port, &admin_request("GET", "/admin/approvals", b"")).await;
    assert_eq!(pending.status, 200);
    let pending_event = &pending.body["approvals"][0];
    assert_eq!(pending_event["request_id"], request_id);
    assert_eq!(pending_event["agent"], "alice");
    assert_eq!(
        pending_event["approval"]["approval_type"],
        "desktop_present"
    );
    assert_eq!(pending_event["approval"]["target"], "desktop:alice");
    observations
        .push(json!({"step":"operator_pending","status":pending.status,"body":pending.body}));

    let missing = exchange_admin(
        port,
        &admin_request(
            "POST",
            "/admin/agents/bob/desktop/present",
            br#"{"approval_request_id":"wrong-agent"}"#,
        ),
    )
    .await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body["error"], "Agent not found");
    assert!(!root.path().join("desktop-presenter-fixture.args").exists());
    observations.push(json!({"step":"unknown_agent","status":missing.status,"body":missing.body}));

    let body = serde_json::to_vec(&json!({"approval_request_id":request_id})).unwrap();
    let presented = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", &body),
    )
    .await;
    assert_eq!(presented.status, 200);
    assert_eq!(presented.body["agent"], "alice");
    assert_eq!(presented.body["agent_id"], "durable-alice");
    assert_eq!(presented.body["reused"], false);
    let audit_at_success = fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    assert!(
        audit_at_success.contains("admin.desktop_presented"),
        "a successful presentation must have its resolution on disk"
    );
    observations
        .push(json!({"step":"operator_present","status":presented.status,"body":presented.body}));

    let helper_args =
        fs::read_to_string(root.path().join("desktop-presenter-fixture.args")).unwrap();
    let helper_request =
        fs::read_to_string(root.path().join("desktop-presenter-fixture.request")).unwrap();
    assert_eq!(helper_args, "-m safeyolo.desktop_presenter_rpc --daemon\n");
    assert_eq!(
        serde_json::from_str::<Value>(helper_request.trim()).unwrap()["agent_id"],
        "alice"
    );

    let resolved = exchange_admin(port, &admin_request("GET", "/admin/approvals", b"")).await;
    assert_eq!(resolved.status, 200);
    assert_eq!(resolved.body["approvals"], json!([]));
    observations
        .push(json!({"step":"operator_resolved","status":resolved.status,"body":resolved.body}));

    proxy.shutdown().await;
    unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
    let audit = fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("agent.desktop_present_requested"));
    assert!(audit.contains("admin.desktop_presented"));
    assert!(audit.contains(&request_id));
    assert!(!audit.contains(AGENT_TOKEN));
    assert!(!audit.contains(OPERATOR_TOKEN));
    write_evidence(root.path(), &observations, "success");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)] // The process-global presenter environment spans this native workflow.
async fn failed_resolution_write_cannot_report_success_or_clear_pending_approval() {
    let _lock = test_lock();
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root.path().join("admin-token"), OPERATOR_TOKEN).unwrap();
    let helper = preview_helper(root.path(), false);
    unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &helper) };
    let proxy = Proxy::start(config(root.path())).await.unwrap();
    let port = admin_port(root.path());

    let requested = exchange_unix(
        &root.path().join("alice.sock"),
        &agent_request("/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(requested.status, 202);
    let request_id = requested.body["request_id"].as_str().unwrap();
    let body = serde_json::to_vec(&json!({"approval_request_id":request_id})).unwrap();
    let path = root.path().join("audit.jsonl");
    let held = root.path().join("pending-audit.jsonl");
    fs::rename(&path, &held).unwrap();
    fs::create_dir(&path).unwrap();

    let failed = exchange_admin_raw(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", &body),
    )
    .await;
    assert!(
        failed.is_empty(),
        "audit failure must close without a response: {failed:?}"
    );
    assert_eq!(helper_pids(&helper).len(), 1, "presenter ran");
    fs::remove_dir(&path).unwrap();
    fs::rename(&held, &path).unwrap();
    assert!(
        !fs::read_to_string(&path)
            .unwrap()
            .contains("admin.desktop_presented")
    );
    let pending = exchange_admin(port, &admin_request("GET", "/admin/approvals", b"")).await;
    assert_eq!(pending.status, 200);
    assert_eq!(pending.body["approvals"][0]["request_id"], request_id);

    let retried = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", &body),
    )
    .await;
    assert_eq!(retried.status, 200);
    assert_eq!(retried.body["reused"], true);
    let resolved = exchange_admin(port, &admin_request("GET", "/admin/approvals", b"")).await;
    assert_eq!(resolved.body["approvals"], json!([]));
    proxy.shutdown().await;
    unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)] // The process-global presenter environment must span this unavailable-host control.
async fn approved_request_reports_unavailable_host_presenter_without_false_success() {
    let _lock = test_lock();
    unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/agent_token"), AGENT_TOKEN).unwrap();
    fs::write(root.path().join("admin-token"), OPERATOR_TOKEN).unwrap();
    let config = config(root.path());
    let proxy = Proxy::start(config).await.unwrap();
    let port = admin_port(root.path());
    let requested = exchange_unix(
        &root.path().join("alice.sock"),
        &agent_request("/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(requested.status, 202);
    let request_id = requested.body["request_id"].as_str().unwrap().to_owned();
    let pending = exchange_admin(port, &admin_request("GET", "/admin/approvals", b"")).await;
    assert_eq!(pending.body["approvals"][0]["request_id"], request_id);

    let body = serde_json::to_vec(&json!({"approval_request_id":request_id})).unwrap();
    let failed = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", &body),
    )
    .await;
    assert_eq!(failed.status, 503);
    assert_eq!(failed.body["error"], "desktop presenter is unavailable");
    let still_pending = exchange_admin(port, &admin_request("GET", "/admin/approvals", b"")).await;
    assert_eq!(still_pending.body["approvals"][0]["request_id"], request_id);
    proxy.shutdown().await;

    let audit = fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("admin.desktop_presentation_failed"));
    let failure = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["event"] == "admin.desktop_presentation_failed")
        .expect("failure audit");
    assert_eq!(failure["details"]["approval_request_id"], request_id);
    assert_eq!(
        failure["details"]["reason"],
        "desktop_presenter_unavailable"
    );
    assert!(!audit.contains(AGENT_TOKEN));
    assert!(!audit.contains(OPERATOR_TOKEN));
    write_evidence(
        root.path(),
        &[json!({
            "step": "unavailable",
            "request_id": request_id,
            "status": failed.status,
            "body": failed.body,
            "pending_after_failure": still_pending.body,
            "failure_audit": failure,
        })],
        "unavailable",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)] // One integration-test process owns the global helper and its environment.
async fn typed_sibling_failure_keeps_shared_preview_alive() {
    let _lock = test_lock();
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("data")).unwrap();
    fs::write(root.path().join("admin-token"), OPERATOR_TOKEN).unwrap();
    let helper = preview_helper(root.path(), false);
    unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &helper) };
    let proxy = Proxy::start(config_with_sibling(root.path()))
        .await
        .unwrap();
    let port = admin_port(root.path());

    let first = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(first.status, 200);
    let url = first.body["url"].as_str().unwrap().to_owned();
    let first_pid = helper_pids(&helper)[0];
    assert!(preview_replies(&url), "initial preview must serve requests");

    let failed = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/bob/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(failed.status, 409);
    assert_eq!(failed.body["error"], "Desktop presentation failed");
    assert_eq!(helper_pids(&helper), [first_pid]);
    assert!(!helper.with_extension("closed").exists());
    assert!(
        preview_replies(&url),
        "failed sibling must not close preview"
    );

    let again = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(again.status, 200);
    assert_eq!(again.body["url"], url);
    assert_eq!(again.body["reused"], true);
    assert!(preview_replies(&url));

    proxy.shutdown().await;
    assert_eq!(
        fs::read_to_string(helper.with_extension("closed")).unwrap(),
        format!("{first_pid}\n")
    );
    assert!(!preview_replies(&url), "shutdown must close preview");
    unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)] // One integration-test process owns the global helper and its environment.
async fn broken_protocol_closes_preview_before_replacing_helper() {
    let _lock = test_lock();
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("data")).unwrap();
    fs::write(root.path().join("admin-token"), OPERATOR_TOKEN).unwrap();
    let helper = preview_helper(root.path(), true);
    unsafe { std::env::set_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON", &helper) };
    let proxy = Proxy::start(config_with_sibling(root.path()))
        .await
        .unwrap();
    let port = admin_port(root.path());

    let first = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(first.status, 200);
    let url = first.body["url"].as_str().unwrap().to_owned();
    let first_pid = helper_pids(&helper)[0];
    assert!(preview_replies(&url));

    let failed = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/bob/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(failed.status, 500);
    assert_eq!(
        failed.body["error"],
        "desktop presenter returned an invalid result"
    );
    assert_eq!(
        fs::read_to_string(helper.with_extension("closed")).unwrap(),
        format!("{first_pid}\n")
    );
    assert!(
        !preview_replies(&url),
        "retirement must close the old preview"
    );

    let again = exchange_admin(
        port,
        &admin_request("POST", "/admin/agents/alice/desktop/present", b"{}"),
    )
    .await;
    assert_eq!(again.status, 200);
    assert_eq!(again.body["reused"], false);
    let replacement_pid = helper_pids(&helper)[1];
    assert_ne!(replacement_pid, first_pid);
    let new_url = again.body["url"].as_str().unwrap();
    assert!(
        preview_replies(new_url),
        "replacement preview must serve requests"
    );

    proxy.shutdown().await;
    assert_eq!(
        fs::read_to_string(helper.with_extension("closed")).unwrap(),
        format!("{first_pid}\n{replacement_pid}\n")
    );
    assert!(
        !preview_replies(new_url),
        "shutdown must close replacement preview"
    );
    unsafe { std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") };
}
