//! Owned UDS probes, synthetic memory samples, and real native hook receipts.
mod body;
mod doctor_api;

use super::*;
use crate::{Config, Proxy};
use serde_json::Value;
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const CLAIM: &str = "run=owned-probe;agent=claimed;test=pipeline-probe";

#[test]
fn exact_probe_host_matches_source_inputs_except_root_dot() {
    let source: Value =
        serde_json::from_str(include_str!("../../../tests/probe_doctor_source.json")).unwrap();
    for row in source["matcher"].as_array().unwrap() {
        let host = row["host"].as_str().unwrap_or_default();
        if host == "_safeyolo.probe.internal." {
            // Python's sink now accepts one DNS root dot. Native still
            // contains that spelling without treating it as a positive probe.
            assert!(row["matches"].as_bool().unwrap());
            assert!(!is_host(host));
            assert!(crate::is_reserved(host));
            continue;
        }
        assert_eq!(is_host(host), row["matches"].as_bool().unwrap(), "{}", host);
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    proxy: Proxy,
    runtime: Arc<Runtime>,
}

impl Fixture {
    async fn new(stream_json: bool, required: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("policy.json"),
            json!({
                "permissions":[{"action":"network:request","resource":"*","effect":"deny"}],
                "addons":{"test_context":{"target_hosts":if required {vec![HOST]} else {vec![]}}}
            })
            .to_string(),
        )
        .unwrap();
        let configuration: Config = serde_json::from_value(json!({
            "listeners":[{"agent_id":"alice","source_id":"192.0.2.10","socket_path":directory.path().join("alice.sock")},
                {"agent_id":"bob","source_id":"192.0.2.11","socket_path":directory.path().join("bob.sock")}],
            "policy_file":directory.path().join("policy.json"), "data_dir":directory.path().join("data"), "readiness_file":directory.path().join("ready"),
            "event_log":directory.path().join("events.jsonl"), "audit_log_path":directory.path().join("audit.jsonl"),
            "flow_store_enabled":true, "flow_store_db_path":directory.path().join("flows.sqlite3"),
            "circuit_breaker_enabled":true, "circuit_state_file":"", "sse_stream_json":stream_json,
        })).unwrap();
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        Self {
            directory,
            proxy,
            runtime,
        }
    }

    fn trace(&self, response: &[u8]) -> Value {
        self.runtime
            .traces
            .get(
                &request_id(response),
                Some("alice"),
                crate::circuit_runtime::now(),
            )
            .unwrap()
            .unwrap()
    }

    async fn exchange(&self, request: &str) -> Vec<u8> {
        exchange(self.directory.path(), "alice", request).await
    }

    async fn stop(self) -> Vec<Value> {
        timeout(LIMIT, self.proxy.shutdown()).await.unwrap();
        let diagnostics = records(self.directory.path(), "events.jsonl");
        assert!(!diagnostics.iter().any(|row| row["event"] == "proxy.egress"));
        assert!(
            self.runtime
                .flow_recorder
                .store()
                .unwrap()
                .get_flow(1)
                .unwrap()
                .is_none()
        );
        records(self.directory.path(), "audit.jsonl")
    }
}

fn records(directory: &Path, name: &str) -> Vec<Value> {
    std::fs::read_to_string(directory.join(name))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

async fn exchange(directory: &Path, agent: &str, request: &str) -> Vec<u8> {
    let mut stream = UnixStream::connect(directory.join(format!("{agent}.sock")))
        .await
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    remaining(&mut stream).await
}

async fn remaining(stream: &mut UnixStream) -> Vec<u8> {
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn header(response: &[u8], name: &str) -> Option<String> {
    std::str::from_utf8(response)
        .unwrap()
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}
fn request_id(response: &[u8]) -> String {
    header(response, "x-safeyolo-request-id").unwrap()
}
fn body(response: &[u8]) -> &[u8] {
    &response[response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4..]
}
fn status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn request(host: &str, method: &str, path: &str, extra: &str, payload: &str) -> String {
    format!(
        "{method} http://{host}{path} HTTP/1.0\r\nHost: {host}\r\nX-SafeYolo-Trace: 1\r\nX-SafeYolo-Test-Context: {CLAIM}\r\nConnection: close\r\n{extra}\r\n{payload}"
    )
}

#[tokio::test]
async fn buffered_probe_runs_real_hooks_and_matches_source_sink() {
    for stream_json in [false, true] {
        let fixture = Fixture::new(stream_json, false).await;
        let reply = fixture
            .exchange(&request(HOST, "GET", "/__pipeline_probe", "", ""))
            .await;
        assert_eq!(status(&reply), 200);
        assert_eq!(
            header(&reply, "content-type").as_deref(),
            Some("application/json")
        );
        assert!(header(&reply, "x-blocked-by").is_none());
        let source: Value =
            serde_json::from_str(include_str!("../../../tests/probe_doctor_source.json")).unwrap();
        let expected = &source["sink_rows"][0];
        let source_id = expected["metadata"]["request_id"].as_str().unwrap();
        assert_eq!(
            std::str::from_utf8(body(&reply))
                .unwrap()
                .replace(&request_id(&reply), source_id),
            expected["response"]["body_text"]
        );
        let trace = fixture.trace(&reply);
        let steps = trace["steps"].as_array().unwrap();
        assert_eq!(
            steps
                .iter()
                .map(|step| (
                    step["addon"].as_str().unwrap(),
                    step["hook"].as_str().unwrap()
                ))
                .collect::<Vec<_>>(),
            [
                ("network-guard", "request"),
                ("circuit-breaker", "request"),
                ("credential-guard", "request"),
                ("test-context", "request"),
                ("probe-sink", "request"),
                ("circuit-breaker", "response"),
                ("test-context", "response")
            ]
        );
        assert_eq!(steps[1]["outcome"], "excluded_domain");
        assert_eq!(steps[5]["outcome"], "excluded_domain");
        assert_eq!(steps[6]["outcome"], "response_recorded");
        assert_eq!(trace["agent_id"], "alice");
        let mut sink = steps[4].clone();
        assert!(sink["duration_us"].is_number());
        assert!(sink["connection_id"].as_str().unwrap().starts_with("conn-"));
        sink["duration_us"] = json!("<measured>");
        sink["connection_id"] = expected["trace"]["steps"][0]["connection_id"].clone();
        assert_eq!(sink, expected["trace"]["steps"][0]);
        assert_eq!(
            trace["not_loaded"],
            json!([
                {"addon":"service-gateway","state":"not_loaded"},
                {"addon":"pattern-scanner","state":"not_loaded"}
            ])
        );
        assert!(
            fixture
                .runtime
                .traces
                .get(
                    &request_id(&reply),
                    Some("bob"),
                    crate::circuit_runtime::now()
                )
                .unwrap()
                .is_none()
        );
        let counts = fixture
            .runtime
            .request_logger
            .stats()
            .unwrap()
            .document()
            .json()
            .unwrap();
        assert_eq!(counts["requests_total"], 1);
        assert_eq!(counts["responses_total"], 1);
        assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
        let audit = fixture.stop().await;
        let context: Vec<_> = audit
            .iter()
            .filter(|row| row["event"] == "security.test_context")
            .collect();
        assert_eq!(context.len(), 2);
        assert_eq!(context[0]["details"]["phase"], "request");
        assert_eq!(context[1]["details"]["phase"], "response");
        assert_eq!(
            context[1]["details"]["response_body_snippet"],
            std::str::from_utf8(body(&reply)).unwrap()
        );
        let closed: Vec<_> = audit
            .iter()
            .filter(|row| row["event"] == "ops.memory.conn_closed")
            .collect();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0]["details"]["flow_count"], 1);
        assert_eq!(
            closed[0]["details"]["bytes_received"],
            if stream_json { 0 } else { body(&reply).len() }
        );
    }
}

#[tokio::test]
async fn host_selects_probe_across_method_path_port_and_upgrade_headers() {
    let fixture = Fixture::new(false, false).await;
    for (host, method, path, extra, payload) in [
        (
            "_SAFEYOLO.PROBE.INTERNAL:8123",
            "POST",
            "/elsewhere?q=1",
            "Content-Length: 4\r\n",
            "body",
        ),
        (HOST, "HEAD", "/other", "", ""),
        (
            HOST,
            "GET",
            "/socket",
            "Upgrade: websocket\r\nSec-WebSocket-Key: invalid\r\n",
            "",
        ),
    ] {
        let reply = fixture
            .exchange(&request(host, method, path, extra, payload))
            .await;
        assert_eq!(status(&reply), 200);
        if method == "HEAD" {
            assert!(body(&reply).is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(body(&reply)).unwrap()["probe_ok"],
                true
            );
        }
        let trace = fixture.trace(&reply);
        assert!(
            trace["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["outcome"] == "probe_terminated")
        );
    }
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 3);
    fixture.stop().await;
}

#[tokio::test]
async fn pending_buffered_upload_does_not_publish_sink_before_completion() {
    let fixture = Fixture::new(false, false).await;
    let mut stream = UnixStream::connect(fixture.directory.path().join("alice.sock"))
        .await
        .unwrap();
    stream
        .write_all(request(HOST, "POST", "/held", "Content-Length: 4\r\n", "ab").as_bytes())
        .await
        .unwrap();
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(30), stream.read(&mut byte))
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .runtime
            .test_context
            .stats(super::super::declaration_time())
            .unwrap()
            .checks_total,
        0
    );
    stream.write_all(b"cd").await.unwrap();
    let reply = remaining(&mut stream).await;
    assert_eq!(status(&reply), 200);
    assert!(
        fixture.trace(&reply)["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["outcome"] == "probe_terminated")
    );
    fixture.stop().await;
}

#[tokio::test]
async fn streamed_probe_is_refused_without_draining_or_success_hooks() {
    let fixture = Fixture::new(false, false).await;
    let size = crate::http_content::BUFFERED_BODY_THRESHOLD + 1;
    // The client does not request closure or send the body. Refusal must still
    // arrive and finish without waiting for the remaining upload.
    let upload = request(
        HOST,
        "POST",
        "/stream",
        &format!("Content-Length: {size}\r\n"),
        "",
    )
    .replace("Connection: close", "Connection: keep-alive");
    let reply = fixture.exchange(&upload).await;
    assert_eq!(status(&reply), 502);
    let trace = fixture.trace(&reply);
    let steps = trace["steps"].as_array().unwrap();
    assert!(steps.iter().all(|step| step["addon"] != "probe-sink"
        && step["addon"] != "test-context"
        && step["hook"] != "response"));
    let error = steps.last().unwrap();
    assert_eq!(error["addon"], "transport-guard");
    assert_eq!(error["reason"], "probe_reached_upstream");
    assert!(error.get("duration_us").is_none());
    assert_eq!(
        fixture
            .runtime
            .request_logger
            .stats()
            .unwrap()
            .document()
            .json()
            .unwrap()["requests_total"],
        0
    );
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
    let audit = fixture.stop().await;
    let refused: Vec<_> = audit
        .iter()
        .filter(|row| row["event"] == "security.probe_reached_upstream")
        .collect();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["agent"], "alice");
    assert_eq!(
        refused[0]["details"],
        json!({"reason_code":"probe_reached_upstream","client_ip":"192.0.2.10","server_address":[HOST,80],"sni":null})
    );
    assert!(refused[0].get("request_id").is_none());
    assert!(
        !audit
            .iter()
            .any(|row| row["event"] == "security.test_context")
    );
}

#[tokio::test]
async fn prior_denial_and_reserved_alias_do_not_report_probe_success() {
    let fixture = Fixture::new(false, true).await;
    let denied=fixture.exchange(&format!("GET http://{HOST}/ HTTP/1.0\r\nHost: {HOST}\r\nX-SafeYolo-Trace: 1\r\nConnection: close\r\n\r\n")).await;
    assert_eq!(status(&denied), 428);
    let trace = fixture.trace(&denied);
    let sink: Vec<_> = trace["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["addon"] == "probe-sink")
        .collect();
    assert_eq!(sink.len(), 1);
    assert_eq!(sink[0]["outcome"], "probe_preempted");
    assert_eq!(sink[0]["details"], json!({"preempted_by":"test-context"}));
    let dotted = fixture
        .exchange(&request(&format!("{HOST}."), "GET", "/", "", ""))
        .await;
    assert_eq!(status(&dotted), 503);
    let similar = fixture
        .exchange(&request(
            "_safeyolo.probe.internal.owned.invalid",
            "GET",
            "/",
            "X-SafeYolo-Probe: true\r\n",
            "",
        ))
        .await;
    assert_eq!(status(&similar), 403);
    fixture.stop().await;
}

#[tokio::test]
async fn disabled_installed_guards_report_bypass_and_empty_opt_in_keeps_trace_absent() {
    let mut fixture = Fixture::new(false, false).await;
    let mut configuration = fixture.runtime.config.clone();
    configuration.network_guard_enabled = false;
    configuration.circuit_breaker_enabled = false;
    fixture.proxy.reload(configuration).await.unwrap();
    fixture.runtime = fixture.proxy.runtime.read().unwrap().clone();
    let reply = fixture
        .exchange(&request(HOST, "GET", "/disabled", "", ""))
        .await;
    assert_eq!(status(&reply), 200);
    let trace = fixture.trace(&reply);
    for (index, addon) in [
        (0, "network-guard"),
        (1, "circuit-breaker"),
        (5, "circuit-breaker"),
    ] {
        let step = &trace["steps"][index];
        assert_eq!(step["addon"], addon);
        assert_eq!(step["state"], "bypassed");
        assert_eq!(step["reason"], "addon_disabled");
    }
    assert_eq!(trace["steps"][4]["outcome"], "probe_terminated");
    assert_eq!(trace["not_loaded"].as_array().unwrap().len(), 2);
    let untraced = request(HOST, "GET", "/untraced", "", "")
        .replace("X-SafeYolo-Trace: 1", "X-SafeYolo-Trace:");
    let reply = fixture.exchange(&untraced).await;
    assert_eq!(status(&reply), 200);
    assert!(
        fixture
            .runtime
            .traces
            .get(
                &request_id(&reply),
                Some("alice"),
                crate::circuit_runtime::now()
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 2);
    fixture.stop().await;
}
