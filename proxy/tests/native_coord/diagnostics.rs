//! Real native HTTP/MCP boundaries; canned responses vary only the failure.
use super::*;
use std::sync::{Arc, Mutex};

const ORIGINAL: &str = "req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const READ: &str = "req-dddddddddddddddddddddddddddddddd";

#[derive(Clone)]
struct Reply {
    status: &'static str,
    body: String,
    headers: String,
    length: Option<usize>,
    delay: Duration,
}
impl Reply {
    fn json(status: &'static str, value: Value) -> Self {
        Self {
            status,
            body: value.to_string(),
            headers: format!("X-SafeYolo-Request-Id: {READ}\r\n"),
            length: None,
            delay: Duration::ZERO,
        }
    }
    fn evidence(status: &str) -> Self {
        Self::json(
            "200 OK",
            json!({"request_id":ORIGINAL,"status":status,"events":[{"event":"agent.api_response","request_id":ORIGINAL,"details":{"status":503,"blocked_by":"agent-api"}}]}),
        )
    }
    fn failure() -> Self {
        let mut reply = Self::json(
            "503 Service Unavailable",
            json!({"error":"publication uncertain","send_outcome":"unknown","action":"inspect retained history","reason":"fixture refusal","retry_after":3}),
        );
        reply.headers = format!(
            "X-SafeYolo-Request-Id: {ORIGINAL}\r\nX-Blocked-By: agent-api\r\nRetry-After: 3\r\n"
        );
        reply
    }
}

async fn failure_result(original: Reply, evidence: Vec<Reply>) -> (Value, Vec<String>, Duration) {
    let (result, requests, elapsed) = served_result(original, evidence, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"send\",\"arguments\":{\"room_name\":\"shared\",\"body\":\"one write\",\"notify\":\"none\"}}}\n").await;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    assert!(
        requests
            .iter()
            .skip(1)
            .all(|r| r == &format!("GET /explain?request_id={ORIGINAL} HTTP/1.1"))
    );
    assert_eq!(result["isError"], true);
    (result, requests, elapsed)
}

async fn served_result(
    original: Reply,
    evidence: Vec<Reply>,
    request: &str,
) -> (Value, Vec<String>, Duration) {
    let root = tempfile::Builder::new()
        .prefix("diag-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/agent_token"), "fixture-token").unwrap();
    let socket = root.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
                assert!(head.len() < 8192);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(
                head.to_ascii_lowercase()
                    .contains("authorization: bearer fixture-token\r\n")
            );
            let line = head.lines().next().unwrap().to_owned();
            let index = {
                let mut requests = observed.lock().unwrap();
                requests.push(line);
                requests.len() - 1
            };
            let reply = if index == 0 {
                original.clone()
            } else {
                evidence
                    .get(index - 1)
                    .unwrap_or_else(|| panic!("unexpected diagnostic/retry {index}"))
                    .clone()
            };
            connections.spawn(async move {
                tokio::time::sleep(reply.delay).await;
                let response = format!(
                    "HTTP/1.1 {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.status,
                    reply.headers,
                    reply.length.unwrap_or(reply.body.len()),
                    reply.body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    let started = std::time::Instant::now();
    let response = mcp(root.path(), &socket, request).await;
    let elapsed = started.elapsed();
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let requests = requests.lock().unwrap().clone();
    (response["result"].clone(), requests, elapsed)
}

#[tokio::test]
async fn failed_attention_resolution_preserves_each_source_position_and_its_failure() {
    let page = Reply::json(
        "200 OK",
        json!({"instance_id":"si-test","edges":[{"attention_id":"attn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":99}],"next_cursor":99}),
    );
    for multiple in [false, true] {
        let arguments = if multiple {
            json!({"sources":[{"instance_id":"si-test","since_sequence":77}],"timeout_seconds":0})
        } else {
            json!({"since_sequence":77,"timeout_seconds":0})
        };
        let request = format!(
            "{}\n",
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait_for_coord","arguments":arguments}})
        );
        let (result, requests, _) = served_result(
            page.clone(),
            vec![Reply::failure(), Reply::evidence("complete")],
            &request,
        )
        .await;
        if multiple {
            assert_eq!(result["isError"], false);
            let source = &result["structuredContent"]["sources"][0];
            assert_eq!(source["next_cursor"], 77);
            assert_eq!(source["objects"], json!([]));
            assert_eq!(source["availability"], "unavailable");
            assert_eq!(source["failure"]["http_status"], 503);
            assert_eq!(
                source["failure"]["diagnostic"]["evidence"]["status"],
                "complete"
            );
        } else {
            assert_eq!(result["isError"], true);
            assert!(result["structuredContent"].get("next_cursor").is_none());
            assert_eq!(result["structuredContent"]["http_status"], 503);
        }
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|r| r.starts_with("GET ")));
        assert!(
            requests[1]
                .contains("/api/coord/attention/attn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/object")
        );
        assert_eq!(
            requests[2],
            format!("GET /explain?request_id={ORIGINAL} HTTP/1.1")
        );
    }
}

#[tokio::test]
async fn tool_failure_preserves_original_and_bounded_reader_states() {
    for (states, expected, reads) in [
        (vec!["complete"], "complete", 1),
        (vec!["pending", "complete"], "complete", 2),
        (vec!["pending", "pending"], "pending", 2),
        (vec!["incomplete_search"], "incomplete_search", 1),
        (vec!["error"], "error", 1),
    ] {
        let (result, requests, elapsed) = failure_result(
            Reply::failure(),
            states.into_iter().map(Reply::evidence).collect(),
        )
        .await;
        let failure = &result["structuredContent"];
        assert_eq!(failure["http_status"], 503);
        assert_eq!(failure["request_id"], ORIGINAL);
        assert_eq!(failure["error_details"]["send_outcome"], "unknown");
        assert_eq!(
            failure["error_details"]["action"],
            "inspect retained history"
        );
        assert_eq!(failure["blocked_by"], "agent-api");
        assert_eq!(failure["retry_after"], "3");
        assert_eq!(failure["diagnostic"]["evidence"]["status"], expected);
        assert_eq!(failure["diagnostic"]["reads"][0]["request_id"], READ);
        assert_eq!(failure["diagnostic"]["limits"]["max_reads"], 2);
        assert!(
            failure["diagnostic"]["reference"]
                .as_str()
                .unwrap()
                .ends_with(ORIGINAL)
        );
        assert_eq!(requests.len(), reads + 1);
        assert!(elapsed < Duration::from_secs(3));
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("send outcome unknown")
        );
    }
}

#[tokio::test]
async fn diagnostic_limits_and_failures_never_replace_or_repeat_the_original() {
    let mut other_status = Reply::evidence("complete");
    other_status.status = "201 Created";
    let (observed, _, _) = failure_result(Reply::failure(), vec![other_status]).await;
    assert_eq!(
        observed["structuredContent"]["diagnostic"]["reads"][0]["http_status"],
        201
    );
    let mut missing = Reply::evidence("complete");
    missing.body = json!({"request_id":ORIGINAL,"status":"complete","events":[]}).to_string();
    let mut fabricated = Reply::evidence("complete");
    fabricated.body =
        json!({"request_id":READ,"status":"complete","events":[{"private":"must-not-attach"}]})
            .to_string();
    let mut oversized = Reply::evidence("complete");
    oversized.body = "x".repeat(65537);
    let mut timeout = Reply::evidence("complete");
    timeout.delay = Duration::from_secs(3);
    let mut limited = Reply::evidence("incomplete_search");
    limited.body = json!({"request_id":ORIGINAL,"status":"incomplete_search","searched_lines_per_file":10000,"events":[{"summary":"x".repeat(3000)}]}).to_string();
    for (replies, expected) in [
        (vec![missing], "collected"),
        (
            vec![Reply::json(
                "403 Forbidden",
                json!({"error":"not available to this agent"}),
            )],
            "denied",
        ),
        (vec![Reply::failure()], "unavailable"),
        (vec![fabricated], "invalid_response"),
        (vec![oversized], "unavailable"),
        (vec![timeout.clone()], "timeout"),
        (vec![Reply::evidence("pending"), timeout], "timeout"),
        (vec![limited], "collected"),
    ] {
        let expected_reads = replies.len() + 1;
        let (result, requests, elapsed) = failure_result(Reply::failure(), replies).await;
        let failure = &result["structuredContent"];
        assert_eq!(failure["http_status"], 503);
        assert_eq!(failure["error_details"]["send_outcome"], "unknown");
        assert_eq!(
            failure["diagnostic"]["collection_state"], expected,
            "{result}"
        );
        assert_eq!(requests.len(), expected_reads);
        assert!(elapsed < Duration::from_secs(3));
        assert!(!result.to_string().contains("must-not-attach"));
        assert!(result.to_string().len() < 150_000);
    }
}

#[tokio::test]
async fn error_body_states_and_correlation_remain_explicit() {
    for (body, length, state) in [
        ("", None, "empty"),
        ("<html>bad</html>", None, "malformed"),
        ("{bad", None, "malformed"),
        ("{\"error\":", Some(200), "incomplete"),
    ] {
        let mut reply = Reply::failure();
        reply.body = body.into();
        reply.length = length;
        let (result, requests, _) = failure_result(reply, vec![Reply::evidence("complete")]).await;
        assert_eq!(result["structuredContent"]["body_state"], state);
        assert_eq!(result["structuredContent"]["http_status"], 503);
        assert_eq!(result["structuredContent"]["request_id"], ORIGINAL);
        assert_eq!(requests.len(), 2);
    }
    for headers in [
        "".to_owned(),
        "X-SafeYolo-Request-Id: fabricated\r\n".into(),
        format!("X-SafeYolo-Request-Id: {ORIGINAL}\r\nX-SafeYolo-Request-Id: {READ}\r\n"),
    ] {
        let mut reply = Reply::failure();
        reply.headers = headers;
        reply.body = json!({"request_id":ORIGINAL,"error":"unavailable"}).to_string();
        let (result, requests, _) = failure_result(reply, vec![]).await;
        assert_eq!(result["structuredContent"]["request_id"], Value::Null);
        assert_eq!(
            result["structuredContent"]["diagnostic"]["collection_state"],
            "missing_correlation"
        );
        assert_eq!(requests.len(), 1);
    }
    let mut absent = Reply::failure();
    absent.status = "invalid HTTP status";
    let (result, requests, _) = failure_result(absent, vec![]).await;
    assert_eq!(result["structuredContent"]["response_received"], false);
    assert_eq!(result["structuredContent"]["http_status"], Value::Null);
    assert_eq!(result["structuredContent"]["request_id"], Value::Null);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn sensitive_and_unbounded_failures_do_not_escape_to_mcp() {
    // Padding arrives before the endpoint's critical fields on the wire.
    let mut padded = Reply::failure();
    padded.body = json!({"padding":vec![vec!["x";128];5],"send_outcome":"unknown","error":"publication uncertain","reason":"retained receipt unavailable","action":"inspect retained history"}).to_string();
    let (padded, _, _) = failure_result(padded, vec![Reply::evidence("complete")]).await;
    assert_eq!(
        padded["structuredContent"]["error_details"]["send_outcome"],
        "unknown"
    );
    assert_eq!(
        padded["structuredContent"]["error_details"]["action"],
        "inspect retained history"
    );
    assert_eq!(padded["structuredContent"]["details_limited"], true);
    let mut number = Reply::failure();
    number.body = json!({"error":serde_json::from_str::<Value>(&"9".repeat(40000)).unwrap(),"send_outcome":"unknown","action":"inspect retained history"}).to_string();
    let (number, _, _) = failure_result(number, vec![Reply::evidence("complete")]).await;
    assert_eq!(
        number["structuredContent"]["error_details"]["send_outcome"],
        "unknown"
    );
    assert_eq!(number["structuredContent"]["details_limited"], true);
    let mut reply = Reply::failure();
    reply.body = json!({"error":"echo fixture-token and Bearer other-private", "send_outcome":"unknown", "password":"password-canary", "nested":{"access_token":"access-canary"}, "detail":"x".repeat(4000)}).to_string();
    let mut evidence = Reply::evidence("complete");
    evidence.body = json!({"request_id":ORIGINAL,"status":"complete","events":[{"secret":"event-canary","summary":"echo fixture-token"}]}).to_string();
    let (result, _, _) = failure_result(reply, vec![evidence]).await;
    let text = result.to_string();
    for secret in [
        "fixture-token",
        "other-private",
        "password-canary",
        "access-canary",
        "event-canary",
    ] {
        assert!(!text.contains(secret), "{secret}");
    }
    assert_eq!(result["structuredContent"]["details_limited"], true);
    assert!(text.contains("redacted"));
    let mut reply = Reply::failure();
    reply.body = "x".repeat(65537);
    let (result, _, _) = failure_result(reply, vec![Reply::evidence("complete")]).await;
    assert_eq!(result["structuredContent"]["body_state"], "too_large");
}

#[tokio::test]
async fn real_agent_api_refusal_uses_its_existing_scoped_audit_reader() {
    let root = tempfile::Builder::new()
        .prefix("diag-reader-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = root.path();
    fs::create_dir(root.join("data")).unwrap();
    fs::create_dir(root.join("builtin-services")).unwrap();
    fs::write(root.join("data/agent_token"), "fixture-token").unwrap();
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(
        root.join("policy.toml"),
        "[agents.alice]\nagent_id='ag-alice'\n[agents.bob]\nagent_id='ag-bob'\n",
    )
    .unwrap();
    // This disposable instance has no Coord backend. Production is untouched.
    let proxy = Proxy::start(native_config::read(&root.join("config.toml")).unwrap())
        .await
        .unwrap();
    let result = mcp(root, &root.join("alice.sock"), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_room\",\"arguments\":{\"room_name\":\"shared\"}}}\n").await;
    let failure = &result["result"]["structuredContent"];
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(failure["http_status"], 503, "{result}");
    let evidence = &failure["diagnostic"]["evidence"];
    assert_eq!(evidence["request_id"], failure["request_id"]);
    let events = evidence["events"].as_array().unwrap();
    assert!(
        events.iter().any(
            |event| event["event"] == "agent.api_response" && event["details"]["status"] == 503
        )
    );
    assert!(events.iter().all(|event| event["agent"] == "alice"));
    let bob = Client {
        socket: Some(root.join("bob.sock")),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let foreign = bob
        .get(&format!(
            "/explain?request_id={}",
            failure["request_id"].as_str().unwrap()
        ))
        .await
        .unwrap();
    assert_eq!(foreign["events"], json!([]));
    let fabricated = bob
        .get(&format!("/explain?request_id={ORIGINAL}"))
        .await
        .unwrap();
    assert_eq!(fabricated["events"], json!([]));
    proxy.shutdown().await;
}

#[tokio::test]
async fn generic_transport_and_explicit_diagnostic_reads_do_not_collect() {
    for (generic, request_path) in [
        (false, "/explain"),
        (false, "/explain///"),
        (true, "/admin/operation"),
    ] {
        let root = tempfile::Builder::new()
            .prefix("diag-no-loop-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let token = root.path().join("agent_token");
        fs::write(&token, "fixture-token").unwrap();
        let path = root.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let reply = Reply::failure();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        reply.status,
                        reply.headers,
                        reply.body.len(),
                        reply.body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            drop(stream);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        let error = if generic {
            safeyolo_proxy::native_client::send_json(
                tokio::net::UnixStream::connect(&path).await.unwrap(),
                "fixture-admin",
                request_path,
                "fixture-token",
                hyper::Method::POST,
                Value::Null,
                Duration::from_secs(2),
            )
            .await
            .unwrap_err()
        } else {
            Client {
                socket: Some(path),
                token_file: token,
                home: None,
            }
            .get(&format!("{request_path}?request_id={ORIGINAL}"))
            .await
            .unwrap_err()
        };
        assert!(error.to_string().contains(ORIGINAL));
        assert!(error.to_string().contains("send outcome unknown"));
        server.await.unwrap();
    }
}
