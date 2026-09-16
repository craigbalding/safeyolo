use super::*;

#[path = "trace_tests.rs"]
mod trace_tests;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{StatusCode, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::{convert::Infallible, sync::RwLock, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(3);
const CLAIM: &str = "run=owned;agent=claim;test=T1";

struct Fixture {
    directory: TempDir,
    runtime: Arc<Runtime>,
}
impl Fixture {
    fn new(block: bool, targets: Value, full_sink: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.json");
        std::fs::write(
            &policy,
            json!({"addons":{"test_context":{
                "target_hosts": targets, "inject_declared": true
            }}})
            .to_string(),
        )
        .unwrap();
        let config = serde_json::from_value(json!({
            "listeners":[], "policy_file":policy,
            "readiness_file":directory.path().join("ready"),
            "flow_store_enabled": false,
            "audit_log_path": directory.path().join("audit.jsonl"),
            "event_log": if full_sink { std::path::PathBuf::from("/dev/full") }
                else {directory.path().join("events.jsonl")},
            "test_context_block":block,
        }))
        .unwrap();
        let runtime = Arc::new(
            Runtime::new(
                config,
                "request-context-fixture",
                Arc::new(tokio::sync::Mutex::new(())),
                None,
                None,
            )
            .unwrap(),
        );
        Self { directory, runtime }
    }

    fn identity(&self) -> ConnectionIdentity {
        ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: "owned-connection".into(),
            source_id: Some("owned-slot".into()),
        }
    }

    fn destination(&self) -> super::super::Destination {
        super::super::Destination {
            host: "dial.invalid".into(),
            policy_host: "owned.invalid".into(),
            port: 8123,
            authority: "dial.invalid:8123".into(),
            uri_authority: "dial.invalid:8123".into(),
            scheme: "http".into(),
            path: "/path?raw=1".into(),
        }
    }

    fn prepare<B>(&self, request: &mut Request<B>) -> Result<Admission, Error> {
        prepare(
            self.runtime.clone(),
            &self.identity(),
            "owned-request",
            request,
            &self.destination(),
            None,
        )
    }

    fn counts(&self) -> [u64; 5] {
        let stats = self
            .runtime
            .test_context
            .stats(super::super::declaration_time())
            .unwrap();
        [
            stats.checks_total,
            stats.allowed_total,
            stats.blocked_total,
            stats.warned_total,
            stats.declared_injections_total,
        ]
    }

    fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.directory.path().join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn pending(admission: Admission) -> RequestContext {
    match admission {
        Admission::Pending(context) => context,
        _ => panic!("expected pending request context"),
    }
}

fn memory_stats(runtime: &Runtime) -> Value {
    runtime
        .memory_monitor
        .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap()
}

#[tokio::test]
async fn memory_original_decode_failure_does_not_skip_reached_test_context() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    fixture
        .runtime
        .memory_monitor
        .client_connected(
            &fixture.identity().connection_id,
            crate::circuit_runtime::now,
        )
        .unwrap();
    let mut peer = H1::new().await;
    peer.socket.write_all(format!(
        "POST /path HTTP/1.1\r\nHost: owned.invalid\r\nContent-Length: 4\r\nContent-Encoding: gzip\r\nConnection: Content-Encoding\r\n{}: {CLAIM}\r\n\r\n",
        test_context::HEADER,
    ).as_bytes()).await.unwrap();
    let mut request = timeout(LIMIT, peer.requests.recv()).await.unwrap().unwrap();
    let traffic = super::super::traffic::Traffic::new(
        Arc::new(RwLock::new(fixture.runtime.clone())),
        &fixture.identity(),
        "owned-request",
        &request,
        &fixture.destination(),
    );
    let mut headers = crate::request_headers::RequestHeaders::take(&mut request).unwrap();
    headers.apply_hygiene(request.headers_mut());
    assert!(!request.headers().contains_key(header::CONTENT_ENCODING));
    let mut context = pending(fixture.prepare(&mut request).unwrap());
    context.attach_traffic(traffic.clone());
    peer.socket.write_all(b"body").await.unwrap();
    let (body, mut context) = context.buffer(request.into_body(), Some(4)).await.unwrap();
    assert_eq!(body.collect().await.unwrap().to_bytes(), b"body".as_slice());
    assert_eq!(context.try_finish(), Some(false));
    assert_eq!(context.try_finish(), Some(false));
    assert!(traffic.source_metadata_reached());
    assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
    assert_eq!(
        fixture
            .runtime
            .request_logger
            .stats()
            .unwrap()
            .requests_total,
        num_bigint::BigInt::from(1)
    );
    let stats = memory_stats(&fixture.runtime);
    assert_eq!(stats["total_flows"], 1);
    assert_eq!(stats["connections"][0]["flows"], 1);
    assert_eq!(stats["connections"][0]["domain"], "owned.invalid");
    assert_eq!(stats["connections"][0]["bytes_sent"], 0);
    assert!(fixture.runtime.audit.wait_for_drain(LIMIT).unwrap());
    let records: Vec<Value> = std::fs::read_to_string(fixture.directory.path().join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let applied = records
        .iter()
        .find(|row| row["event"] == "security.test_context" && row["details"]["phase"] == "request")
        .unwrap();
    assert_eq!(applied["details"]["request_body_snippet"], "body");
    assert!(records.iter().any(|row| row["event"] == "traffic.request"));
    assert!(!records.iter().any(|row| row["event"] == "ops.memory"));
}

#[tokio::test]
async fn memory_request_audit_error_keeps_partial_effects_without_terminal_failure() {
    let fixture = Fixture::new(true, json!([]), false);
    fixture
        .runtime
        .memory_monitor
        .running(&fixture.runtime.audit, crate::memory_runtime::sample, || 0.)
        .unwrap();
    fixture
        .runtime
        .memory_monitor
        .client_connected(&fixture.identity().connection_id, || 0.)
        .unwrap();
    assert!(fixture.runtime.audit.wait_for_drain(LIMIT).unwrap());
    fixture.runtime.audit.poison_for_test();
    let mut peer = H1::new().await;
    let mut request = peer.request(0, None, "identity").await;
    let traffic = super::super::traffic::Traffic::new(
        Arc::new(RwLock::new(fixture.runtime.clone())),
        &fixture.identity(),
        "owned-request",
        &request,
        &fixture.destination(),
    );
    // Isolate memory's synchronous submission result from a later logger's
    // independent use of this same deliberately poisoned Writer.
    let mut context = RequestContext::traffic_only(&mut request, true, None).unwrap();
    context.attach_traffic(traffic.clone());
    let (_, mut context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
    assert_eq!(context.try_finish(), Some(false));
    assert_eq!(context.try_finish(), Some(false));
    assert!(traffic.source_metadata_reached());
    assert!(!context.evidence_failed());
    let stats = memory_stats(&fixture.runtime);
    assert_eq!(stats["total_flows"], 1);
    assert_eq!(stats["connections"][0]["flows"], 1);
    assert_eq!(stats["connections"][0]["bytes_sent"], 0);

    let fixture = Fixture::new(true, json!([]), false);
    let mut peer = H1::new().await;
    let mut request = peer.request(4, None, "identity").await;
    let traffic = super::super::traffic::Traffic::new(
        Arc::new(RwLock::new(fixture.runtime.clone())),
        &fixture.identity(),
        "aborted-request",
        &request,
        &fixture.destination(),
    );
    let mut context = RequestContext::traffic_only(&mut request, true, None).unwrap();
    context.attach_traffic(traffic.clone());
    peer.socket.write_all(b"bo").await.unwrap();
    peer.socket.shutdown().await.unwrap();
    assert!(context.buffer(request.into_body(), Some(4)).await.is_err());
    assert!(!traffic.source_metadata_reached());
    assert_eq!(memory_stats(&fixture.runtime)["total_flows"], 0);
}

struct Task<T>(JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct H1 {
    socket: DuplexStream,
    requests: mpsc::UnboundedReceiver<Request<Incoming>>,
    _driver: Task<()>,
}
impl H1 {
    async fn new() -> Self {
        let (socket, server) = tokio::io::duplex(65536);
        let (send, requests) = mpsc::unbounded_channel();
        let driver = Task(tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |request| {
                        assert!(send.send(request).is_ok());
                        std::future::pending::<Result<Response<Empty<Bytes>>, Infallible>>()
                    }),
                )
                .await;
        }));
        Self {
            socket,
            requests,
            _driver: driver,
        }
    }

    async fn request(
        &mut self,
        length: usize,
        claim: Option<&str>,
        encoding: &str,
    ) -> Request<Incoming> {
        let mut head = format!(
            "POST /path?raw=1 HTTP/1.1\r\nHost: owned.invalid\r\nContent-Length: {length}\r\nContent-Encoding: {encoding}\r\n"
        );
        if let Some(claim) = claim {
            head.push_str(&format!("{}: {claim}\r\n", test_context::HEADER));
        }
        head.push_str("X-Unrelated: retained\r\n\r\n");
        self.socket.write_all(head.as_bytes()).await.unwrap();
        timeout(LIMIT, self.requests.recv()).await.unwrap().unwrap()
    }
}

#[tokio::test]
async fn head_block_requires_neither_body_poll_nor_completion_observer() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    for (claim, reason) in [
        (None, "missing_context"),
        (Some("invalid"), "malformed_context"),
    ] {
        let mut peer = H1::new().await;
        let mut request = peer.request(100, claim, "invalid").await;
        if claim.is_some() {
            request
                .headers_mut()
                .append(test_context::HEADER, "second-invalid".parse().unwrap());
        }
        // No DATA has been supplied. A buffering call would remain pending.
        let Admission::Block(response) = fixture.prepare(&mut request).unwrap() else {
            panic!("expected head denial");
        };
        assert_eq!(response.status(), 428);
        assert_eq!(response.headers()["x-blocked-by"], "test-context");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert!(!request.headers().contains_key(test_context::HEADER));
        assert_eq!(request.headers()["x-unrelated"], "retained");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["type"], reason);
        assert_eq!(body["destination"], "owned.invalid");
    }
    assert_eq!(fixture.counts(), [2, 0, 2, 0, 0]);
    assert!(
        fixture
            .events()
            .iter()
            .all(|event| event["decision"] == "deny")
    );
}

#[tokio::test]
async fn small_h1_validated_buffer_applies_once_and_replays_original_body() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let mut peer = H1::new().await;
    let mut request = peer.request(4, Some(CLAIM), "identity").await;
    let context = pending(fixture.prepare(&mut request).unwrap());
    assert_eq!(fixture.counts(), [0; 5]);
    assert!(context.response_provenance().is_some());
    assert!(!request.headers().contains_key(test_context::HEADER));
    peer.socket.write_all(b"body").await.unwrap();
    let (body, mut context) = timeout(LIMIT, context.buffer(request.into_body(), Some(4)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body.collect().await.unwrap().to_bytes(), b"body".as_slice());
    assert_eq!(context.try_finish(), Some(false));
    assert_eq!(context.try_finish(), Some(false));
    assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["details"]["request_body_snippet"], "body");
    assert_eq!(events[0]["details"]["trusted_agent"], "alice");
    assert_eq!(events[0]["details"]["context"]["agent"], "claim");
    assert_eq!(events[0]["details"]["test_agent_match"], false);
    assert_eq!(events[0]["host"], "owned.invalid");
    assert!(!context.evidence_failed());
}

#[tokio::test]
async fn actual_h2_no_error_reset_cannot_publish_buffered_context() {
    for reason in [None, Some(h2::Reason::NO_ERROR), Some(h2::Reason::CANCEL)] {
        let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
        let (client, server) = tokio::io::duplex(65536);
        let (send, receive) = oneshot::channel();
        let send = Arc::new(std::sync::Mutex::new(Some(send)));
        let _server = Task(tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |request| {
                        assert!(send.lock().unwrap().take().unwrap().send(request).is_ok());
                        std::future::pending::<Result<Response<Empty<Bytes>>, Infallible>>()
                    }),
                )
                .await;
        }));
        let (mut sender, driver) = h2::client::handshake(client).await.unwrap();
        let _client = Task(tokio::spawn(driver));
        let (_response, mut stream) = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://owned.invalid/path?raw=1")
                    .header(test_context::HEADER, CLAIM)
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let mut request = timeout(LIMIT, receive).await.unwrap().unwrap();
        let context = pending(fixture.prepare(&mut request).unwrap());
        if let Some(reason) = reason {
            stream.send_reset(reason);
        } else {
            stream
                .send_data(Bytes::from_static(b"complete"), true)
                .unwrap();
        }
        let result = timeout(LIMIT, context.buffer(request.into_body(), None))
            .await
            .unwrap();
        if reason.is_some() {
            assert!(result.is_err());
            assert_eq!(fixture.counts(), [0; 5]);
            assert!(fixture.events().is_empty());
        } else {
            let (body, _) = result.unwrap();
            assert_eq!(
                body.collect().await.unwrap().to_bytes(),
                b"complete".as_slice()
            );
            assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
        }
    }
}

#[tokio::test]
async fn streamed_drop_has_no_effects_and_forwarded_terminal_applies_once() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let length = crate::http_content::BUFFERED_BODY_THRESHOLD + 1;
    for complete in [false, true] {
        let mut peer = H1::new().await;
        let mut request = peer.request(length, Some(CLAIM), "invalid").await;
        let context = pending(fixture.prepare(&mut request).unwrap());
        let (body, mut context) = timeout(
            LIMIT,
            context.buffer(request.into_body(), Some(length as u64)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(context.try_finish(), None);
        assert!(
            context
                .poll(&mut Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        assert_eq!(fixture.counts(), [0; 5]);
        if complete {
            let mut outbound = Request::new(body);
            let completion = super::super::circuit_completion::Completion::register(
                &mut outbound,
                false,
                Arc::new(RwLock::new(fixture.runtime.clone())),
                fixture.identity(),
                "forwarded-request".into(),
                "owned.invalid".into(),
                Some(context),
            );
            let mut body = super::super::ForwardedRequestBody {
                body: outbound.into_body(),
                completion: completion.clone(),
            };
            let mut writer = Task(tokio::spawn(async move {
                let chunk = [b'x'; 8192];
                let mut remaining = length;
                while remaining != 0 {
                    let count = remaining.min(chunk.len());
                    peer.socket.write_all(&chunk[..count]).await.unwrap();
                    remaining -= count;
                }
                // Keep the parser driver alive until the application is done.
                peer
            }));
            let mut received = 0;
            while let Some(frame) = timeout(LIMIT, body.frame()).await.unwrap() {
                if let Some(data) = frame.unwrap().data_ref() {
                    received += data.len();
                    if received == length {
                        // No connection driver has run. The independently
                        // validated request must apply before its final bytes
                        // are returned to the encoder and can reach an origin.
                        assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
                    }
                }
            }
            assert_eq!(received, length);
            let _peer = timeout(LIMIT, &mut writer.0).await.unwrap().unwrap();
            let _ = completion.try_finish();
            assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
            assert_eq!(fixture.events()[0]["details"]["request_body_snippet"], "");
        } else {
            drop(context);
            drop(body);
            assert_eq!(fixture.counts(), [0; 5]);
            assert!(fixture.events().is_empty());
        }
    }
}

#[tokio::test]
async fn decode_failure_keeps_metadata_for_response_but_not_allowed_counter() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let mut peer = H1::new().await;
    let mut request = peer.request(7, Some(CLAIM), "gzip").await;
    let context = pending(fixture.prepare(&mut request).unwrap());
    peer.socket.write_all(b"invalid").await.unwrap();
    let (body, context) = timeout(LIMIT, context.buffer(request.into_body(), Some(7)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        body.collect().await.unwrap().to_bytes(),
        b"invalid".as_slice()
    );
    assert_eq!(fixture.counts(), [1, 0, 0, 0, 0]);
    assert!(fixture.events().is_empty());
    let capture = super::super::test_context::ResponseCapture::new(
        Arc::new(RwLock::new(fixture.runtime.clone())),
        context.response_provenance(),
        None,
        None,
        None,
    );
    hyper::ext::ResponseBodyCapture::head(&capture, StatusCode::OK, &hyper::HeaderMap::new(), true);
    assert!(!capture.finish(true));
    assert_eq!(fixture.events().len(), 1);
    assert_eq!(fixture.events()[0]["details"]["phase"], "response");
}

#[tokio::test]
async fn missing_and_optional_warn_skip_decode_and_declared_selection_is_pinned() {
    for targets in [json!(["owned.invalid"]), json!([])] {
        let fixture = Fixture::new(false, targets.clone(), false);
        let mut peer = H1::new().await;
        let optional = targets.as_array().unwrap().is_empty();
        let mut request = peer
            .request(0, optional.then_some("invalid"), "invalid")
            .await;
        let context = pending(fixture.prepare(&mut request).unwrap());
        assert!(context.response_provenance().is_none());
        let (_, mut context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
        assert_eq!(context.try_finish(), Some(false));
        assert_eq!(fixture.counts(), [1, 0, 0, 1, 0]);
        assert_eq!(fixture.events()[0]["decision"], "warn");
    }
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let identity = TrustedIdentity::new("owned-slot", "alice").unwrap();
    fixture
        .runtime
        .test_context
        .set_declaration(
            &identity,
            test_context::Context::parse(CLAIM).unwrap(),
            None,
            super::super::declaration_time(),
        )
        .unwrap();
    let mut peer = H1::new().await;
    let mut request = peer.request(0, None, "identity").await;
    let context = pending(fixture.prepare(&mut request).unwrap());
    fixture
        .runtime
        .test_context
        .clear_declaration(&identity)
        .unwrap();
    let (_, _) = context.buffer(request.into_body(), Some(0)).await.unwrap();
    assert_eq!(fixture.counts(), [1, 1, 0, 0, 1]);
    assert_eq!(
        fixture.events()[0]["details"]["test_context_source"],
        "declared"
    );
}

#[test]
fn reached_target_error_is_forwarding_compatible_but_still_strips_reserved_header() {
    let fixture = Fixture::new(true, json!([null]), false);
    let mut request = Request::builder()
        .header(test_context::HEADER, CLAIM)
        .header("x-unrelated", "retained")
        .body(())
        .unwrap();
    assert!(matches!(
        fixture.prepare(&mut request).unwrap(),
        Admission::HookError
    ));
    assert!(!request.headers().contains_key(test_context::HEADER));
    assert_eq!(request.headers()["x-unrelated"], "retained");
    assert_eq!(fixture.counts(), [0; 5]);
    assert!(fixture.events().is_empty());
}

#[tokio::test]
async fn postcheck_lookup_error_is_deferred_and_counts_only_at_validated_eom() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let huge: serde_json::Number = format!("1{}", "0".repeat(308)).parse().unwrap();
    fixture
        .runtime
        .test_context
        .configure_declarations(
            None,
            test_context::Options {
                inject_declared: true,
                declared_ttl: Value::Number(huge),
                ..test_context::Options::default()
            },
        )
        .unwrap();
    let identity = TrustedIdentity::new("owned-slot", "alice").unwrap();
    fixture
        .runtime
        .test_context
        .set_declaration(
            &identity,
            test_context::Context::parse(CLAIM).unwrap(),
            None,
            1e308,
        )
        .unwrap();
    for complete in [false, true] {
        let mut peer = H1::new().await;
        let mut request = peer.request(0, None, "identity").await;
        let context = pending(fixture.prepare(&mut request).unwrap());
        assert!(context.response_provenance().is_none());
        assert_eq!(fixture.counts(), [0; 5]);
        if complete {
            let (_, mut context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
            assert_eq!(context.try_finish(), Some(false));
            assert_eq!(context.try_finish(), Some(false));
            assert_eq!(fixture.counts(), [1, 0, 0, 0, 0]);
        } else {
            drop(context);
            assert_eq!(fixture.counts(), [0; 5]);
        }
        assert!(fixture.events().is_empty());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sink_failure_marks_block_and_applied_response_without_rolling_back_counters() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), true);
    let mut blocked = Request::builder().body(()).unwrap();
    let Admission::Block(response) = fixture.prepare(&mut blocked).unwrap() else {
        panic!("expected block")
    };
    assert_eq!(response.headers()["x-safeyolo-evidence-error"], "true");
    assert_eq!(fixture.counts(), [1, 0, 1, 0, 0]);
    let mut peer = H1::new().await;
    let mut request = peer.request(0, Some(CLAIM), "identity").await;
    let context = pending(fixture.prepare(&mut request).unwrap());
    let (_, context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
    assert!(context.evidence_failed());
    assert_eq!(fixture.counts(), [2, 1, 1, 0, 0]);
}

#[test]
fn canonical_test_context_events_and_submission_effects_match_source_hooks() {
    let Some(python) = std::env::var_os("SAFEYOLO_SOURCE_PYTHON") else {
        eprintln!("set SAFEYOLO_SOURCE_PYTHON to run the selected source hook oracle");
        return;
    };
    let source = std::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/test_context_audit_source.py"
        ))
        .output()
        .unwrap();
    assert!(
        source.status.success(),
        "{}",
        String::from_utf8_lossy(&source.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&source.stdout).unwrap();
    let mut observed = Vec::new();
    for row in &expected {
        let case = row["case"].as_str().unwrap();
        let optional = case.starts_with("optional");
        let applied = case.starts_with("applied");
        let fixture = Fixture::new(
            !case.starts_with("warn"),
            if optional {
                json!([])
            } else {
                json!(["owned.invalid"])
            },
            false,
        );
        let mut headers = Vec::new();
        if applied || optional || case == "malformed" {
            headers.push((
                test_context::HEADER.into(),
                if applied { CLAIM } else { "invalid" }.as_bytes().to_vec(),
            ));
        }
        let identity = fixture.identity();
        let trusted = TrustedIdentity::new("owned-slot", "alice").unwrap();
        let prepared = fixture
            .runtime
            .test_context
            .prepare_request_current(
                fixture.runtime.policy.as_ref(),
                test_context::Request {
                    host: "owned.invalid",
                    prior_response: false,
                    identity: Some(&trusted),
                    metadata_agent: Some("alice"),
                },
                &mut headers,
                super::super::declaration_time(),
            )
            .unwrap();
        let block_status = match prepared.result() {
            Ok(RequestOutcome::Block { status, .. }) => Some(*status),
            _ => None,
        };
        let provenance = Arc::new(Provenance::new(
            fixture.runtime.clone(),
            identity.clone(),
            "owned-request".into(),
            "POST".into(),
            "owned.invalid".into(),
            "/path?raw=1".into(),
        ));
        if case.ends_with("error") && case != "applied_response_error" {
            fixture.runtime.audit.poison_for_test();
        }
        let result = apply(
            &provenance,
            8123,
            prepared,
            Some(b"body"),
            Ok(b""),
            0.,
            None,
        );
        let mut errors = Vec::new();
        if result.is_err() {
            errors.push("request");
        }
        let counts = fixture.counts();
        let request_status = result.is_ok().then_some(block_status).flatten();
        if applied {
            if case == "applied_response_error" {
                fixture.runtime.audit.poison_for_test();
            }
            let state = Arc::new(RwLock::new(fixture.runtime.clone()));
            let request = Request::builder()
                .method("POST")
                .uri("http://owned.invalid:8123/path?raw=1")
                .body(())
                .unwrap();
            let traffic = super::super::traffic::Traffic::new(
                state.clone(),
                &identity,
                "owned-request",
                &request,
                &fixture.destination(),
            );
            let recording = super::super::flow_recording::Recording::new(
                fixture.runtime.flow_recorder.clone(),
                identity,
                "owned-request".into(),
                true,
            );
            let capture = super::super::test_context::ResponseCapture::new(
                state,
                Some(provenance),
                Some(traffic),
                Some(recording),
                None,
            );
            hyper::ext::ResponseBodyCapture::head(
                &capture,
                StatusCode::OK,
                &hyper::HeaderMap::new(),
                false,
            );
            hyper::ext::ResponseBodyCapture::data(&capture, b"reply");
            if capture.finish(true) {
                errors.push("response");
            }
            // A failed provenance hook stops both later production children.
            let failed = case.ends_with("error");
            assert_eq!(
                fixture.runtime.flow_recorder.stats()["skipped"],
                usize::from(!failed) as u64
            );
            assert_eq!(
                fixture
                    .runtime
                    .request_logger
                    .stats()
                    .unwrap()
                    .responses_total,
                num_bigint::BigInt::from(usize::from(!failed))
            );
        }
        // The drain uses the queue's independent lock, so a request accepted
        // before the later worker-lock poison can still finish normally.
        assert!(
            fixture
                .runtime
                .audit
                .wait_for_drain(Duration::from_secs(3))
                .unwrap()
        );
        let mut events: Vec<Value> =
            std::fs::read_to_string(fixture.directory.path().join("audit.jsonl"))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|event: &Value| event["event"] == "security.test_context")
                .collect();
        for event in &mut events {
            event.as_object_mut().unwrap().remove("ts");
        }
        let context_applied = errors.contains(&"response")
            || events
                .iter()
                .any(|event| event["details"]["phase"] == "response");
        observed.push(json!({"case":case, "events":events, "errors":errors,
            "counts":counts, "request_status":request_status,
            "context_applied":context_applied, "header_contained":headers.is_empty()}));
    }
    assert_eq!(observed, expected);
}

#[test]
fn head_audit_error_returns_hook_error_without_committing_block() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    fixture.runtime.audit.poison_for_test();
    let mut request = Request::builder()
        .header(test_context::HEADER, "invalid")
        .body(())
        .unwrap();
    assert!(matches!(
        fixture.prepare(&mut request).unwrap(),
        Admission::HookError
    ));
    assert!(!request.headers().contains_key(test_context::HEADER));
    assert_eq!(fixture.counts(), [1, 0, 0, 0, 0]);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn canonical_sink_fallback_keeps_context_counters_and_response_children() {
    let mut fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    Arc::get_mut(&mut fixture.runtime).unwrap().audit = Arc::new(crate::audit::Writer::new(
        "/dev/full".into(),
        crate::audit::Settings::default(),
    ));
    let mut peer = H1::new().await;
    let mut request = peer.request(0, Some(CLAIM), "identity").await;
    let context = pending(fixture.prepare(&mut request).unwrap());
    let (_, context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
    assert!(!context.evidence_failed());
    assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
    let state = Arc::new(RwLock::new(fixture.runtime.clone()));
    let request = Request::builder()
        .method("POST")
        .uri("http://owned.invalid:8123/path?raw=1")
        .body(())
        .unwrap();
    let traffic = super::super::traffic::Traffic::new(
        state.clone(),
        &fixture.identity(),
        "owned-request",
        &request,
        &fixture.destination(),
    );
    let recording = super::super::flow_recording::Recording::new(
        fixture.runtime.flow_recorder.clone(),
        fixture.identity(),
        "owned-request".into(),
        true,
    );
    let capture = super::super::test_context::ResponseCapture::new(
        state,
        context.response_provenance(),
        Some(traffic),
        Some(recording),
        None,
    );
    hyper::ext::ResponseBodyCapture::head(&capture, StatusCode::OK, &hyper::HeaderMap::new(), true);
    assert!(!capture.finish(true));
    assert_eq!(fixture.runtime.flow_recorder.stats()["skipped"], 1);
    assert_eq!(
        fixture
            .runtime
            .request_logger
            .stats()
            .unwrap()
            .responses_total,
        1.into()
    );
    assert!(fixture.runtime.audit.wait_for_drain(LIMIT).unwrap());
}
