//! Owned H1 runtime checks for reached circuit audit and response continuation.
use crate::{Config, Proxy, Runtime};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::oneshot,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"circuit_breaker":{"failure_threshold":1,"timeout_seconds":60}},
        })
        .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")},
                     {"agent_id":"bob","socket_path":directory.join("bob.sock")}],
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),
        "event_log":directory.join("diagnostic.jsonl"),"audit_log_path":directory.join("audit.jsonl"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("flows.sqlite3"),
        "circuit_breaker_enabled":true,"circuit_state_file":"",
    })).unwrap()
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        head
    })
    .await
    .unwrap()
}

async fn request(
    directory: &Path,
    agent: &str,
    origin: std::net::SocketAddr,
    length: usize,
) -> UnixStream {
    let mut stream = UnixStream::connect(directory.join(format!("{agent}.sock")))
        .await
        .unwrap();
    stream.write_all(format!(
        "POST http://{origin}/owned HTTP/1.1\r\nHost: {origin}\r\nContent-Length: {length}\r\nX-SafeYolo-Trace: 1\r\nX-SafeYolo-Agent: forged-owner\r\nX-SafeYolo-Request-Id: forged-id\r\nConnection: close\r\n\r\n"
    ).as_bytes()).await.unwrap();
    stream
}

async fn reply(mut stream: UnixStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

fn records(directory: &Path) -> Vec<Value> {
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        // Preserve all other producer events and their original order.
        .filter(|row: &Value| {
            !(row["addon"] == "memory-monitor"
                && matches!(
                    row["event"].as_str(),
                    Some("ops.startup" | "ops.memory.conn_closed")
                ))
        })
        .collect()
}

fn logger_stats(runtime: &Runtime) -> Value {
    runtime
        .request_logger
        .stats()
        .unwrap()
        .document()
        .json()
        .unwrap()
}

fn circuit_stats(runtime: &Runtime) -> Value {
    runtime
        .circuits
        .stats(true, crate::circuit_runtime::now(), &mut || 0.5)
        .unwrap()
        .value
}

fn trace_steps(runtime: &Runtime, response: &[u8], agent: &str) -> Vec<Value> {
    let id = String::from_utf8_lossy(response)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-safeyolo-request-id")
                .then(|| value.trim().to_owned())
        })
        .unwrap();
    let report = runtime
        .traces
        .get(&id, Some(agent), crate::circuit_runtime::now())
        .unwrap()
        .unwrap();
    report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            json!([
                step["addon"],
                step["hook"],
                step["state"],
                step.get("outcome").or_else(|| step.get("reason")).unwrap()
            ])
        })
        .collect()
}

fn check_open(event: &Value, host: &str) {
    assert_eq!(event["event"], "ops.circuit_breaker.open");
    assert_eq!(event["schema_version"], 1);
    assert_eq!(event["kind"], "ops");
    assert_eq!(event["severity"], "medium");
    assert_eq!(event["addon"], "circuit-breaker");
    assert_eq!(event["host"], host);
    assert_eq!(
        event["details"],
        json!({"failure_count":1,"error":"HTTP 500"})
    );
    assert!(event.get("decision").is_none());
    assert!(event["details"].get("attribution").is_none());
}

#[tokio::test]
async fn response_open_and_next_denial_emit_once_with_stage_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let port = address.port();
    let host = address.ip().to_string();
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = timeout(LIMIT, origin.accept()).await.unwrap().unwrap();
        let head = read_head(&mut stream).await;
        assert!(!String::from_utf8_lossy(&head).contains("forged-id"));
        stream
            .write_all(b"HTTP/1.1 500 Owned\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
            .await
            .unwrap();
        drop(stream);
        origin
    });
    let response = reply(request(directory.path(), "alice", address, 0).await).await;
    assert!(response.starts_with(b"HTTP/1.1 500") && response.ends_with(b"body"));
    let origin = timeout(LIMIT, peer).await.unwrap().unwrap();
    let denied = reply(request(directory.path(), "bob", address, 0).await).await;
    assert!(denied.starts_with(b"HTTP/1.1 503"));
    assert_eq!(
        trace_steps(&runtime, &response, "alice"),
        vec![
            json!(["network-guard", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "request", "evaluated", "allowed"]),
            json!(["credential-guard", "request", "evaluated", "no_detection"]),
            json!(["test-context", "request", "evaluated", "not_target_host"]),
            json!([
                "circuit-breaker",
                "response",
                "evaluated",
                "failure_recorded"
            ]),
            json!(["test-context", "response", "evaluated", "not_applicable"]),
        ]
    );
    assert_eq!(
        trace_steps(&runtime, &denied, "bob"),
        vec![
            json!(["network-guard", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "request", "evaluated", "blocked"]),
            json!(["circuit-breaker", "response", "evaluated", "prior_block"]),
            json!(["test-context", "response", "evaluated", "not_applicable"]),
        ]
    );
    assert!(
        timeout(Duration::from_millis(20), origin.accept())
            .await
            .is_err()
    );
    let stats = circuit_stats(&runtime);
    assert_eq!(stats["opens_total"], 1);
    assert_eq!(stats["checks_total"], 2);
    assert_eq!(stats["domains"][host.as_str()]["state"], "open");
    proxy.shutdown().await;
    let rows = records(directory.path());
    let names: Vec<_> = rows
        .iter()
        .map(|row| row["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "ops.policy_reload",
            "traffic.request",
            "ops.circuit_breaker.open",
            "traffic.response",
            "security.circuit_breaker",
            "traffic.request",
            "traffic.response"
        ]
    );
    check_open(&rows[2], &host);
    assert_eq!(rows[2]["agent"], "alice");
    assert_eq!(rows[2]["request_id"], rows[1]["request_id"]);
    assert_eq!(rows[2]["request_id"], rows[3]["request_id"]);
    assert!(rows[2]["request_id"].as_str().unwrap().starts_with("req-"));
    let security = &rows[4];
    assert_eq!(security["kind"], "security");
    assert_eq!(security["severity"], "high");
    assert_eq!(security["decision"], "deny");
    assert_eq!(security["agent"], "bob");
    assert_eq!(security["host"], host);
    assert_eq!(security["request_id"], rows[5]["request_id"]);
    assert_ne!(security["request_id"], rows[2]["request_id"]);
    assert_eq!(security["details"]["circuit_state"], "open");
    assert_eq!(security["details"]["failure_count"], 1);
    assert_eq!(security["details"]["method"], "POST");
    assert_eq!(security["details"]["port"], port);
    assert_eq!(security["details"]["path"], "/owned");
    assert_eq!(
        security["details"]["attribution"],
        json!({
            "evidence_owner":"bob", "trusted_transport_identity":"bob", "initiator":"unknown",
            "attribution_status":"resolved", "attribution_provenance":{"transport_source":"uds","uds_agent":"bob"},
        })
    );
    let diagnostics: Vec<Value> =
        std::fs::read_to_string(directory.path().join("diagnostic.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let request = diagnostics
        .iter()
        .find(|row| row["event"] == "proxy.request" && row["request_id"] == security["request_id"])
        .unwrap();
    assert!(security["details"]["connection_id"].is_string());
    assert_eq!(
        security["details"]["connection_id"],
        request["connection_id"]
    );
    assert!(!serde_json::to_string(&rows).unwrap().contains("forged"));
}

#[tokio::test]
async fn early_response_open_omits_unreached_source_correlation() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = timeout(LIMIT, origin.accept()).await.unwrap().unwrap();
        let _ = read_head(&mut stream).await;
        let mut first = [0; 5];
        timeout(LIMIT, stream.read_exact(&mut first))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&first, b"first");
        stream
            .write_all(b"HTTP/1.1 500 Owned\r\nContent-Length: 5\r\nConnection: close\r\n\r\nearly")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut client = request(
        directory.path(),
        "alice",
        address,
        crate::http_content::BUFFERED_BODY_THRESHOLD + 1,
    )
    .await;
    client.write_all(b"first").await.unwrap();
    let head = read_head(&mut client).await;
    assert!(head.starts_with(b"HTTP/1.1 500"));
    let mut body = [0; 5];
    timeout(LIMIT, client.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&body, b"early");
    drop(client);
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    assert_eq!(logger_stats(&runtime)["requests_total"], 0);
    assert_eq!(
        trace_steps(&runtime, &head, "alice"),
        vec![
            json!(["network-guard", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "request", "evaluated", "allowed"]),
            json!(["credential-guard", "request", "evaluated", "no_detection"]),
            json!([
                "circuit-breaker",
                "response",
                "evaluated",
                "failure_recorded"
            ]),
            json!(["test-context", "response", "evaluated", "not_applicable"]),
        ]
    );
    assert_eq!(logger_stats(&runtime)["responses_total"], 1);
    let rows = records(directory.path());
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["event"], "ops.policy_reload");
    check_open(&rows[1], &address.ip().to_string());
    assert!(rows[1].get("agent").is_none());
    assert!(rows[1].get("request_id").is_none());
    assert_eq!(rows[2]["event"], "traffic.response");
    assert!(rows[2].get("request_id").is_none());
}

#[tokio::test]
async fn synchronous_response_audit_error_preserves_partial_state_and_skips_children() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let (admitted, received) = oneshot::channel();
    let (respond, allowed) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = timeout(LIMIT, origin.accept()).await.unwrap().unwrap();
        let _ = read_head(&mut stream).await;
        admitted.send(()).unwrap();
        timeout(LIMIT, allowed).await.unwrap().unwrap();
        stream
            .write_all(b"HTTP/1.1 500 Owned\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
            .await
            .unwrap();
    });
    let client = request(directory.path(), "alice", address, 0).await;
    timeout(LIMIT, received).await.unwrap().unwrap();
    assert_eq!(logger_stats(&runtime)["requests_total"], 1);
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    let before = runtime
        .circuits
        .snapshot(crate::circuit_runtime::now())
        .unwrap();
    runtime.audit.poison_for_test();
    respond.send(()).unwrap();
    let response = reply(client).await;
    assert!(response.starts_with(b"HTTP/1.1 500") && response.ends_with(b"body"));
    timeout(LIMIT, peer).await.unwrap().unwrap();
    let after = runtime
        .circuits
        .snapshot(crate::circuit_runtime::now())
        .unwrap();
    assert_eq!(
        after["states"], before["states"],
        "failed open audit must not publish staged circuit state"
    );
    let stats = circuit_stats(&runtime);
    assert_eq!(stats["opens_total"], 1);
    assert_eq!(stats["checks_total"], 1);
    assert_eq!(logger_stats(&runtime)["responses_total"], 0);
    assert_eq!(
        trace_steps(&runtime, &response, "alice"),
        vec![
            json!(["network-guard", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "request", "evaluated", "allowed"]),
            json!(["credential-guard", "request", "evaluated", "no_detection"]),
            json!(["test-context", "request", "evaluated", "not_target_host"]),
            json!(["circuit-breaker", "response", "error", "AuditError"]),
        ]
    );
    assert_eq!(
        runtime.flow_recorder.stats(),
        json!({"recorded":0,"errors":0,"skipped":0})
    );
    proxy.shutdown().await;
    let rows = records(directory.path());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["event"], "ops.policy_reload");
    assert_eq!(rows[1]["event"], "traffic.request");
}
