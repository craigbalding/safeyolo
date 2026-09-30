use super::*;

impl Fixture {
    fn drain(&self) {
        assert!(self.runtime.audit.wait_for_drain(LIMIT).unwrap());
    }

    fn assert_source_step(&self, native_index: usize, source_name: &str, hook_index: usize) {
        static SOURCE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
        let source = SOURCE.get_or_init(|| {
            serde_json::from_str(include_str!("../../../tests/security_trace_source.json")).unwrap()
        });
        let row = source["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["input"]["component"] == "context" && row["input"]["name"] == source_name
            })
            .unwrap();
        let attempts: Vec<_> = row["hooks"][hook_index]["timeline"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["kind"] == "trace" && entry["accepted"] == true)
            .collect();
        assert_eq!(attempts.len(), 1);
        let mut expected = attempts[0]["step"].clone();
        expected
            .as_object_mut()
            .unwrap()
            .retain(|key, value| key != "ts" && !value.is_null());
        let report = self
            .runtime
            .traces
            .get(
                "owned-request",
                Some("alice"),
                crate::circuit_runtime::now(),
            )
            .unwrap()
            .unwrap();
        let mut actual = report["steps"][native_index].clone();
        if actual.get("duration_us").is_some() {
            assert!(actual["duration_us"].is_number());
            actual["duration_us"] = json!("<measured>");
        }
        assert_eq!(actual, expected, "{source_name}/{hook_index}");
    }

    fn trace(&self, enabled: bool) -> Arc<RequestTrace> {
        let trace = Arc::new(RequestTrace::new(
            self.runtime.traces.clone(),
            &self.identity(),
            "owned-request",
            "POST",
            "owned.invalid",
            8123,
        ));
        trace.enable(enabled);
        trace
    }

    fn prepare_traced<B>(&self, request: &mut Request<B>, trace: &Arc<RequestTrace>) -> Admission {
        prepare(
            self.runtime.clone(),
            &self.identity(),
            "owned-request",
            request,
            &self.destination(),
            Some(trace.clone()),
        )
        .unwrap()
    }

    fn steps(&self) -> Vec<Value> {
        let Some(report) = self
            .runtime
            .traces
            .get(
                "owned-request",
                Some("alice"),
                crate::circuit_runtime::now(),
            )
            .unwrap()
        else {
            return Vec::new();
        };
        report["steps"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(|mut step| {
                assert_eq!(step["addon"], "test-context");
                assert_eq!(step["connection_id"], "owned-connection");
                assert_eq!(step["method"], "POST");
                assert_eq!(step["host"], "owned.invalid");
                assert_eq!(step["port"], 8123);
                assert!(step["duration_us"].is_number());
                for key in [
                    "addon",
                    "connection_id",
                    "method",
                    "host",
                    "port",
                    "duration_us",
                ] {
                    step.as_object_mut().unwrap().remove(key);
                }
                step
            })
            .collect()
    }

    fn capture_traced(
        &self,
        provenance: Option<Arc<Provenance>>,
        trace: Arc<RequestTrace>,
        encoding: &str,
    ) -> super::super::super::test_context::ResponseCapture {
        let state = Arc::new(RwLock::new(self.runtime.clone()));
        let request = Request::builder()
            .method("POST")
            .uri("http://owned.invalid:8123/path?raw=1")
            .body(())
            .unwrap();
        let traffic = super::super::super::traffic::Traffic::new(
            state.clone(),
            &self.identity(),
            "owned-request",
            &request,
            &self.destination(),
        );
        let capture = super::super::super::test_context::ResponseCapture::new(
            state,
            provenance,
            Some(traffic),
            None,
            Some(trace),
        );
        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, encoding.parse().unwrap());
        hyper::ext::ResponseBodyCapture::head(&capture, StatusCode::OK, &headers, true);
        capture
    }
}

#[tokio::test]
async fn not_target_trace_waits_for_eom_and_aborted_request_emits_nothing() {
    let fixture = Fixture::new(true, json!([]), false);
    let trace = fixture.trace(true);
    let mut peer = H1::new().await;
    let mut request = peer.request(10, None, "identity").await;
    let context = pending(fixture.prepare_traced(&mut request, &trace));
    assert!(fixture.steps().is_empty());
    drop(context);
    drop(request);
    assert!(fixture.steps().is_empty());
    assert_eq!(fixture.counts(), [0; 5]);

    let mut peer = H1::new().await;
    let mut request = peer.request(0, None, "identity").await;
    let context = pending(fixture.prepare_traced(&mut request, &trace));
    assert!(fixture.steps().is_empty());
    let (_, context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
    assert!(context.response_provenance().is_none());
    assert_eq!(
        fixture.steps(),
        [json!({"hook":"request", "state":"evaluated", "outcome":"not_target_host"})]
    );
    assert_eq!(fixture.counts(), [0; 5]);
    fixture.assert_source_step(0, "request_nontarget", 0);
}

#[tokio::test]
async fn allowed_warned_and_blocked_trace_follow_reached_counters_and_reply() {
    for (case, block, targets, claim, expected, counts) in [
        (
            "header",
            true,
            json!(["owned.invalid"]),
            Some(CLAIM),
            json!({"hook":"request","state":"evaluated","outcome":"allowed","details":{"context_source":"header"}}),
            [1, 1, 0, 0, 0],
        ),
        (
            "declared",
            true,
            json!(["owned.invalid"]),
            None,
            json!({"hook":"request","state":"evaluated","outcome":"allowed","details":{"context_source":"declared"}}),
            [1, 1, 0, 0, 1],
        ),
        (
            "optional-warn",
            true,
            json!([]),
            Some("invalid"),
            json!({"hook":"request","state":"evaluated","outcome":"warned"}),
            [1, 0, 0, 1, 0],
        ),
        (
            "malformed-warn",
            false,
            json!(["owned.invalid"]),
            Some("invalid"),
            json!({"hook":"request","state":"evaluated","outcome":"warned"}),
            [1, 0, 0, 1, 0],
        ),
        (
            "missing-block",
            true,
            json!(["owned.invalid"]),
            None,
            json!({"hook":"request","state":"evaluated","outcome":"blocked","details":{"status":428}}),
            [1, 0, 1, 0, 0],
        ),
    ] {
        let fixture = Fixture::new(block, targets, false);
        let trace = fixture.trace(true);
        if case == "declared" {
            fixture
                .runtime
                .test_context
                .set_declaration(
                    &TrustedIdentity::new("owned-slot", "alice").unwrap(),
                    test_context::Context::parse(CLAIM).unwrap(),
                    None,
                    super::super::super::declaration_time(),
                )
                .unwrap();
        }
        let mut peer = H1::new().await;
        let mut request = peer.request(0, claim, "identity").await;
        let admission = fixture.prepare_traced(&mut request, &trace);
        if case == "missing-block" {
            let Admission::Block(reply) = admission else {
                panic!("expected actual block reply")
            };
            assert_eq!(reply.status(), 428);
            assert_eq!(reply.headers()["x-blocked-by"], "test-context");
        } else {
            assert!(fixture.steps().is_empty(), "{case}");
            let (_, _) = pending(admission)
                .buffer(request.into_body(), Some(0))
                .await
                .unwrap();
        }
        assert_eq!(fixture.counts(), counts, "{case}");
        assert_eq!(fixture.steps(), [expected], "{case}");
        fixture.assert_source_step(
            0,
            match case {
                "header" => "request_header_then_response",
                "declared" => "request_declared_then_response_absent",
                "optional-warn" => "request_optional_malformed_warn",
                "malformed-warn" => "request_malformed_warn",
                "missing-block" => "request_missing_block_then_not_applicable",
                _ => unreachable!(),
            },
            0,
        );
        fixture.drain();
    }
}

#[tokio::test]
async fn request_decode_error_keeps_response_trace_independent_and_response_error_skips_logger() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let trace = fixture.trace(true);
    let mut peer = H1::new().await;
    let mut request = peer.request(7, Some(CLAIM), "gzip").await;
    let context = pending(fixture.prepare_traced(&mut request, &trace));
    peer.socket.write_all(b"invalid").await.unwrap();
    let (_, context) = context.buffer(request.into_body(), Some(7)).await.unwrap();
    assert_eq!(fixture.counts(), [1, 0, 0, 0, 0]);
    assert_eq!(
        fixture.steps(),
        [json!({"hook":"request","state":"error","reason":"ValueError"})]
    );
    let capture = fixture.capture_traced(context.response_provenance(), trace.clone(), "identity");
    assert!(!capture.finish(true));
    assert!(!capture.finish(true));
    assert_eq!(
        fixture.steps()[1],
        json!({"hook":"response","state":"evaluated","outcome":"response_recorded","details":{"status_code":200}})
    );
    assert_eq!(fixture.steps().len(), 2);
    let before = fixture
        .runtime
        .request_logger
        .stats()
        .unwrap()
        .responses_total;
    let capture = fixture.capture_traced(context.response_provenance(), trace, "gzip");
    hyper::ext::ResponseBodyCapture::data(&capture, b"invalid");
    assert!(!capture.finish(true));
    assert_eq!(
        fixture.steps()[2],
        json!({"hook":"response","state":"error","reason":"ValueError"})
    );
    assert_eq!(
        fixture
            .runtime
            .request_logger
            .stats()
            .unwrap()
            .responses_total,
        before
    );
    fixture.assert_source_step(0, "request_decode_error_then_response", 0);
    fixture.assert_source_step(1, "request_decode_error_then_response", 1);
    fixture.assert_source_step(2, "response_decode_error", 0);
    fixture.drain();
}

#[tokio::test]
async fn response_not_applicable_is_reached_without_provenance_but_not_after_skip_or_abort() {
    let fixture = Fixture::new(true, json!([]), false);
    let trace = fixture.trace(true);
    let skipped = fixture.capture_traced(None, trace.clone(), "identity");
    skipped.skip_response();
    assert!(!skipped.finish(true));
    let aborted = fixture.capture_traced(None, trace.clone(), "identity");
    assert!(!aborted.finish(false));
    assert!(!aborted.finish(true));
    assert!(fixture.steps().is_empty());
    let reached = fixture.capture_traced(None, trace, "identity");
    assert!(!reached.finish(true));
    assert_eq!(
        fixture.steps(),
        [json!({"hook":"response","state":"evaluated","outcome":"not_applicable"})]
    );
    fixture.assert_source_step(0, "request_missing_block_then_not_applicable", 1);
    fixture.drain();

    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let trace = fixture.trace(true);
    let mut peer = H1::new().await;
    let mut request = peer.request(8, Some(CLAIM), "identity").await;
    let context = pending(fixture.prepare_traced(&mut request, &trace));
    let early = fixture.capture_traced(context.response_provenance(), trace, "identity");
    assert!(!early.finish(true));
    assert_eq!(
        fixture.steps(),
        [json!({"hook":"response","state":"evaluated","outcome":"not_applicable"})]
    );
    assert_eq!(fixture.counts(), [0; 5]);
    fixture.assert_source_step(0, "request_missing_block_then_not_applicable", 1);
    fixture.drain();
}

#[tokio::test]
async fn native_writer_failure_has_categorical_trace_and_never_a_block_success() {
    let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
    let trace = fixture.trace(true);
    fixture.runtime.audit.poison_for_test();
    let mut request = Request::builder().method("POST").body(()).unwrap();
    assert!(matches!(
        fixture.prepare_traced(&mut request, &trace),
        Admission::HookError
    ));
    assert_eq!(fixture.counts(), [1, 0, 0, 0, 0]);
    assert_eq!(
        fixture.steps(),
        [json!({"hook":"request","state":"error","reason":"AuditPoisoned"})]
    );

    let fixture = Fixture::new(true, json!(42), false);
    let trace = fixture.trace(true);
    let mut request = Request::builder()
        .header(test_context::HEADER, CLAIM)
        .body(())
        .unwrap();
    assert!(matches!(
        fixture.prepare_traced(&mut request, &trace),
        Admission::HookError
    ));
    assert_eq!(
        fixture.steps(),
        [json!({"hook":"request","state":"error","reason":"TypeError"})]
    );
    // Source publishes the invalid targets before its len() error. Its stats
    // projection therefore fails too; do not replace that partial state.
    assert_eq!(
        fixture
            .runtime
            .test_context
            .stats(super::super::super::declaration_time())
            .unwrap_err()
            .kind(),
        ContextErrorKind::Type
    );
    assert!(!request.headers().contains_key(test_context::HEADER));
    fixture.assert_source_step(0, "request_config_type_error", 0);
}

#[tokio::test]
async fn disabled_or_failing_trace_store_does_not_change_application_or_evidence_flags() {
    for enabled in [false, true] {
        let fixture = Fixture::new(true, json!(["owned.invalid"]), false);
        let store = Arc::new(crate::trace::TraceStore::new(crate::trace::Settings {
            global_max: (-1).into(),
            ..crate::trace::Settings::default()
        }));
        let trace = Arc::new(RequestTrace::new(
            store,
            &fixture.identity(),
            "owned-request",
            "POST",
            "owned.invalid",
            8123,
        ));
        trace.enable(enabled);
        let mut peer = H1::new().await;
        let mut request = peer.request(0, Some(CLAIM), "identity").await;
        let context = pending(fixture.prepare_traced(&mut request, &trace));
        let (_, context) = context.buffer(request.into_body(), Some(0)).await.unwrap();
        assert!(!context.evidence_failed());
        assert_eq!(fixture.counts(), [1, 1, 0, 0, 0]);
        let capture = fixture.capture_traced(context.response_provenance(), trace, "identity");
        assert!(!capture.finish(true));
        assert_eq!(
            fixture
                .events()
                .iter()
                .filter(|event| event["event"] == "security.test_context")
                .count(),
            2
        );
        fixture.drain();
    }
}
