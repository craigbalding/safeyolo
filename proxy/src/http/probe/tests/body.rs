//! Ordinary owned H1 upload boundaries. No H2, trailers or operational endpoints.
use super::*;

fn upload_head(framing: &str, extra: &str, context: bool) -> String {
    let claim = if context {
        format!("X-SafeYolo-Test-Context: {CLAIM}\r\n")
    } else {
        String::new()
    };
    format!(
        "POST http://{HOST}/body HTTP/1.1\r\nHost: {HOST}\r\nX-SafeYolo-Trace: 1\r\nConnection: close\r\n{claim}{framing}{extra}\r\n"
    )
}
fn logger(fixture: &Fixture) -> Value {
    fixture
        .runtime
        .request_logger
        .stats()
        .unwrap()
        .document()
        .json()
        .unwrap()
}
fn memory(fixture: &Fixture) -> Value {
    fixture
        .runtime
        .memory_monitor
        .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap()
}
fn context_counts(fixture: &Fixture) -> (u64, u64) {
    let stats = fixture
        .runtime
        .test_context
        .stats(crate::http::declaration_time())
        .unwrap();
    (stats.checks_total, stats.allowed_total)
}
fn trace_from_owned_diagnostic(fixture: &Fixture) -> Value {
    let rows = records(fixture.directory.path(), "events.jsonl");
    let request = rows
        .iter()
        .find(|row| row["event"] == "proxy.network_guard")
        .expect("request reached actual head admission");
    fixture
        .runtime
        .traces
        .get(
            request["request_id"].as_str().unwrap(),
            Some("alice"),
            crate::circuit_runtime::now(),
        )
        .unwrap()
        .unwrap()
}
fn no_sink_or_response(trace: &Value) {
    let steps = trace["steps"].as_array().unwrap();
    assert!(!steps.is_empty());
    assert!(
        steps
            .iter()
            .all(|step| step["addon"] != "probe-sink" && step["hook"] != "response"),
        "{trace}"
    );
}
async fn held_without_success(fixture: &Fixture, stream: &mut UnixStream) {
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(30), stream.read(&mut byte))
            .await
            .is_err(),
        "incomplete buffered request must have no reply"
    );
    assert_eq!(context_counts(fixture), (0, 0));
    assert_eq!(memory(fixture)["total_flows"], 0);
    assert_eq!(logger(fixture)["requests_total"], 0);
    no_sink_or_response(&trace_from_owned_diagnostic(fixture));
}

#[tokio::test]
async fn chunked_small_body_applies_once_only_after_terminal() {
    let fixture = Fixture::new(false, false).await;
    let mut stream = UnixStream::connect(fixture.directory.path().join("alice.sock"))
        .await
        .unwrap();
    stream
        .write_all(upload_head("Transfer-Encoding: chunked\r\n", "", true).as_bytes())
        .await
        .unwrap();
    stream
        .write_all(b"5\r\nowned\r\n5\r\n body\r\n")
        .await
        .unwrap();
    held_without_success(&fixture, &mut stream).await;
    stream.write_all(b"0\r\n\r\n").await.unwrap();
    let reply = remaining(&mut stream).await;
    assert_eq!(status(&reply), 200);
    assert_eq!(
        serde_json::from_slice::<Value>(body(&reply)).unwrap()["probe_ok"],
        true
    );
    assert_eq!(context_counts(&fixture), (1, 1));
    assert_eq!(memory(&fixture)["total_flows"], 1);
    assert_eq!(logger(&fixture)["requests_total"], 1);
    assert_eq!(logger(&fixture)["responses_total"], 1);
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
    let trace = fixture.trace(&reply);
    let steps = trace["steps"].as_array().unwrap();
    assert_eq!(
        steps
            .iter()
            .map(|s| (s["addon"].as_str().unwrap(), s["hook"].as_str().unwrap()))
            .collect::<Vec<_>>(),
        [
            ("network-guard", "request"),
            ("circuit-breaker", "request"),
            ("test-context", "request"),
            ("probe-sink", "request"),
            ("circuit-breaker", "response"),
            ("test-context", "response"),
        ]
    );
    assert_eq!(steps[3]["outcome"], "probe_terminated");
    let audit = fixture.stop().await;
    let contexts: Vec<_> = audit
        .iter()
        .filter(|r| r["event"] == "security.test_context")
        .collect();
    assert_eq!(contexts.len(), 2);
    assert_eq!(contexts[0]["details"]["request_body_snippet"], "owned body");
    assert_eq!(
        contexts[1]["details"]["response_body_snippet"],
        std::str::from_utf8(body(&reply)).unwrap()
    );
    let requests: Vec<_> = audit
        .iter()
        .filter(|r| r["event"] == "traffic.request")
        .collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["details"]["size"], 10);
    let closed: Vec<_> = audit
        .iter()
        .filter(|r| r["event"] == "ops.memory.conn_closed")
        .collect();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0]["details"]["flow_count"], 1);
    assert_eq!(closed[0]["details"]["bytes_sent"], 10);
    assert_eq!(closed[0]["details"]["bytes_received"], body(&reply).len());
}

#[tokio::test]
async fn chunked_crossing_existing_threshold_refuses_without_terminal_or_drain() {
    let fixture = Fixture::new(false, false).await;
    let mut stream = UnixStream::connect(fixture.directory.path().join("alice.sock"))
        .await
        .unwrap();
    stream
        .write_all(upload_head("Transfer-Encoding: chunked\r\n", "", true).as_bytes())
        .await
        .unwrap();
    const CHUNK: usize = 64 * 1024;
    let chunk = vec![b'x'; CHUNK];
    let threshold = crate::http_content::BUFFERED_BODY_THRESHOLD;
    assert_eq!(threshold % CHUNK, 0);
    timeout(LIMIT, async {
        for _ in 0..threshold / CHUNK {
            stream.write_all(b"10000\r\n").await.unwrap();
            stream.write_all(&chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
        }
    })
    .await
    .unwrap();
    // Exactly the existing threshold is still an incomplete buffered request.
    held_without_success(&fixture, &mut stream).await;
    stream.write_all(b"1\r\nx\r\n").await.unwrap();
    // Deliberately keep the upload side open and never send the zero chunk.
    let reply = remaining(&mut stream).await;
    assert_eq!(status(&reply), 502);
    assert_eq!(context_counts(&fixture), (0, 0));
    assert_eq!(memory(&fixture)["total_flows"], 0);
    assert_eq!(logger(&fixture)["requests_total"], 0);
    assert_eq!(logger(&fixture)["responses_total"], 0);
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
    let trace = fixture.trace(&reply);
    no_sink_or_response(&trace);
    assert!(
        trace["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["addon"] != "test-context")
    );
    let last = trace["steps"].as_array().unwrap().last().unwrap();
    assert_eq!(last["addon"], "transport-guard");
    assert_eq!(last["reason"], "probe_reached_upstream");
    let audit = fixture.stop().await;
    assert_eq!(
        audit
            .iter()
            .filter(|r| r["event"] == "security.probe_reached_upstream")
            .count(),
        1
    );
    assert!(!audit.iter().any(|r| matches!(
        r["event"].as_str(),
        Some("security.test_context" | "traffic.request" | "traffic.response")
    )));
}

#[tokio::test]
async fn truncated_small_upload_never_applies_context_or_sink() {
    let fixture = Fixture::new(false, false).await;
    let mut stream = UnixStream::connect(fixture.directory.path().join("alice.sock"))
        .await
        .unwrap();
    stream
        .write_all(upload_head("Content-Length: 4\r\n", "", true).as_bytes())
        .await
        .unwrap();
    stream.write_all(b"ab").await.unwrap();
    held_without_success(&fixture, &mut stream).await;
    stream.shutdown().await.unwrap();
    let reply = remaining(&mut stream).await;
    assert!(reply.is_empty() || status(&reply) != 200);
    no_sink_or_response(&trace_from_owned_diagnostic(&fixture));
    assert_eq!(context_counts(&fixture), (0, 0));
    assert_eq!(memory(&fixture)["total_flows"], 0);
    assert_eq!(logger(&fixture)["requests_total"], 0);
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
    let audit = fixture.stop().await;
    assert!(!audit.iter().any(|r| matches!(
        r["event"].as_str(),
        Some(
            "security.test_context"
                | "traffic.request"
                | "traffic.response"
                | "security.probe_reached_upstream"
        )
    )));
}

#[tokio::test]
async fn reached_logger_configuration_error_cannot_publish_sink_success() {
    let mut fixture = Fixture::new(false, false).await;
    std::fs::write(
        fixture.directory.path().join("policy.json"),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"deny"}],
            "addons":{"test_context":{"target_hosts":[]}, "request_logger":{"quiet_hosts":42}}
        })
        .to_string(),
    )
    .unwrap();
    fixture
        .proxy
        .reload(fixture.runtime.config.clone())
        .await
        .unwrap();
    fixture.runtime = fixture.proxy.runtime.read().unwrap().clone();
    let reply = fixture
        .exchange(&request(
            HOST,
            "POST",
            "/logger-error",
            "Content-Length: 4\r\n",
            "body",
        ))
        .await;
    assert_eq!(status(&reply), 502);
    assert_eq!(
        context_counts(&fixture),
        (1, 1),
        "earlier context hook still ran"
    );
    assert_eq!(
        logger(&fixture)["requests_total"],
        1,
        "logger count precedes the reached Attribute error"
    );
    assert_eq!(logger(&fixture)["responses_total"], 0);
    assert_eq!(
        fixture.runtime.metrics.get_stats().unwrap().json().unwrap()["requests_total"],
        0
    );
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
    let trace = fixture.trace(&reply);
    no_sink_or_response(&trace);
    assert!(
        trace["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["addon"] == "test-context" && s["hook"] == "request")
    );
    assert_eq!(
        trace["steps"].as_array().unwrap().last().unwrap()["addon"],
        "transport-guard"
    );
    let audit = fixture.stop().await;
    assert_eq!(
        audit
            .iter()
            .filter(|r| r["event"] == "security.test_context" && r["details"]["phase"] == "request")
            .count(),
        1
    );
    assert!(
        !audit
            .iter()
            .any(|r| r["event"] == "traffic.request" || r["event"] == "traffic.response")
    );
    assert_eq!(
        audit
            .iter()
            .filter(|r| r["event"] == "security.probe_reached_upstream")
            .count(),
        1
    );
}

#[tokio::test]
async fn contained_memory_decode_error_preserves_later_valid_hooks() {
    let fixture = Fixture::new(false, false).await;
    let payload = "invalid gzip";
    let reply = fixture
        .exchange(&request(
            HOST,
            "POST",
            "/memory-error",
            &format!(
                "Content-Length: {}\r\nContent-Encoding: gzip\r\nConnection: Content-Encoding\r\n",
                payload.len()
            ),
            payload,
        ))
        .await;
    assert_eq!(status(&reply), 200);
    assert!(header(&reply, "x-safeyolo-evidence-error").is_none());
    assert_eq!(context_counts(&fixture), (1, 1));
    assert_eq!(memory(&fixture)["total_flows"], 1);
    assert_eq!(logger(&fixture)["requests_total"], 1);
    assert_eq!(logger(&fixture)["responses_total"], 1);
    assert_eq!(
        fixture.runtime.metrics.get_stats().unwrap().json().unwrap()["requests_total"],
        1
    );
    let trace = fixture.trace(&reply);
    assert_eq!(
        trace["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["outcome"] == "probe_terminated")
            .count(),
        1
    );
    let audit = fixture.stop().await;
    assert_eq!(
        audit
            .iter()
            .filter(|r| r["event"] == "security.test_context")
            .count(),
        2
    );
    let request = audit
        .iter()
        .find(|r| r["event"] == "traffic.request")
        .unwrap();
    assert_eq!(request["details"]["size"], payload.len());
    let closed = audit
        .iter()
        .find(|r| r["event"] == "ops.memory.conn_closed")
        .unwrap();
    assert_eq!(closed["details"]["flow_count"], 1);
    assert_eq!(
        closed["details"]["bytes_sent"], 0,
        "pre-hygiene memory decode failed"
    );
    assert_eq!(closed["details"]["bytes_received"], body(&reply).len());
    assert!(
        !audit
            .iter()
            .any(|r| r["event"] == "security.probe_reached_upstream")
    );
}
