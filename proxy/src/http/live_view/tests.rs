//! Pure producer controls: owned files and direct existing capture callbacks.
//! No listener, HTTP driver, real process sampler, or Agent API is exercised.

use super::*;
use crate::{
    RuntimeState, http_content::BUFFERED_BODY_THRESHOLD, test_context, traffic_view::Side,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{HeaderMap, StatusCode, ext::ResponseBodyCapture as _, header};
use serde_json::{Value, json};
use std::sync::RwLock;
use tempfile::TempDir;

use super::super::{
    test_context::{HookError, Provenance, ResponseCapture},
    traffic::Traffic,
};

struct Fixture {
    _directory: TempDir,
    runtime: Arc<Runtime>,
    state: RuntimeState,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.json");
        std::fs::write(
            &policy,
            json!({
                "addons":{"test_context":{"target_hosts":["owned.invalid"]}}
            })
            .to_string(),
        )
        .unwrap();
        let config = serde_json::from_value(json!({
            "listeners":[], "policy_file":policy,
            "readiness_file":directory.path().join("ready"),
            "audit_log_path":directory.path().join("audit.jsonl"),
            "event_log":directory.path().join("events.jsonl"),
            "flow_store_enabled":false,
        }))
        .unwrap();
        let runtime = Arc::new(
            Runtime::new(
                config,
                "live-producer-fixture",
                Arc::new(tokio::sync::Mutex::new(())),
                None,
                None,
            )
            .unwrap(),
        );
        let state = Arc::new(RwLock::new(runtime.clone()));
        Self {
            _directory: directory,
            runtime,
            state,
        }
    }

    fn identity(&self) -> ConnectionIdentity {
        ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: "owned-connection".into(),
            source_id: None,
        }
    }

    fn request(&self) -> Request<Empty<Bytes>> {
        Request::builder()
            .method("POST")
            .uri("http://owned.invalid/path?x=1&x=2")
            .header("x-safeyolo-agent", "mallory")
            .body(Empty::new())
            .unwrap()
    }

    fn destination(&self) -> Destination {
        Destination::from_request(&self.request(), None).unwrap()
    }

    fn begin(&self, id: &str) -> Arc<Exchange> {
        super::begin(
            &self.runtime,
            &self.identity(),
            id,
            &self.request(),
            &self.destination(),
        )
        .unwrap()
    }

    fn capture(&self, id: &str, live: Arc<Exchange>) -> ResponseCapture {
        let traffic = Traffic::new(
            self.state.clone(),
            &self.identity(),
            id,
            &self.request(),
            &self.destination(),
        );
        let mut capture = ResponseCapture::new(self.state.clone(), None, Some(traffic), None, None);
        capture.attach_live(Some(live));
        capture
    }

    fn row(&self, id: &str) -> Value {
        self.runtime.traffic_view.detail(id).unwrap()
    }

    fn body(&self, id: &str) -> Value {
        self.runtime.traffic_view.body(id, Side::Response).unwrap()
    }
}

#[test]
fn ordinary_head_is_pending_without_context_and_keeps_trusted_identity() {
    let fixture = Fixture::new();
    let live = fixture.begin("req-owned");
    let row = fixture.row("req-owned");
    assert_eq!(row["agent"], "alice");
    assert_eq!(row["connection_id"], "owned-connection");
    assert_eq!(row["id"], "req-owned");
    assert_eq!(row["url"], "http://owned.invalid/path?x=1&x=2");
    assert_eq!(row["state"], "pending");
    assert!(row["metadata"].get("test_context").is_none());
    assert_eq!(row["request_body"]["reason"], "pending");
    assert!(fixture.runtime.flow_recorder.store().is_none());
    drop(live);
    assert_eq!(fixture.row("req-owned")["state"], "incomplete");

    let mut request = fixture.request();
    *request.method_mut() = hyper::Method::CONNECT;
    assert!(
        begin(
            &fixture.runtime,
            &fixture.identity(),
            "connect",
            &request,
            &fixture.destination()
        )
        .is_none()
    );
    *request.method_mut() = hyper::Method::GET;
    let mut destination = fixture.destination();
    for host in ["_safeyolo.proxy.internal", "_safeyolo.probe.internal"] {
        destination.host = host.into();
        assert!(
            begin(
                &fixture.runtime,
                &fixture.identity(),
                "reserved",
                &request,
                &destination
            )
            .is_none()
        );
    }
    assert_eq!(
        fixture.runtime.traffic_view.flows().unwrap()["flows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn ordered_headers_preserve_case_duplicates_and_non_utf8_bytes() {
    let fields: &[(&[u8], &[u8])] = &[
        (b"X-One", b"first"),
        (b"x-Two", b"\xff"),
        (b"X-One", b"second"),
    ];
    assert_eq!(
        pairs(fields.iter().copied()),
        vec![
            ("X-One".into(), "first".into()),
            ("x-Two".into(), "ÿ".into()),
            ("X-One".into(), "second".into())
        ]
    );
}

#[test]
fn applied_metadata_survives_the_real_provenance_decode_error() {
    let fixture = Fixture::new();
    let live = fixture.begin("context-error");
    let mut headers = vec![(
        test_context::HEADER.into(),
        b"run=run1;agent=claimed;test=T1;intent=inspect".to_vec(),
    )];
    let prepared = fixture
        .runtime
        .test_context
        .prepare_request_current(
            fixture.runtime.policy.as_ref(),
            test_context::Request {
                host: "owned.invalid",
                prior_response: false,
                identity: None,
                metadata_agent: Some("alice"),
            },
            &mut headers,
            10.,
        )
        .unwrap();
    let application = prepared.begin().unwrap();
    let test_context::RequestOutcome::Applied { applied } = application.result().as_ref().unwrap()
    else {
        panic!("context not applied")
    };
    let provenance = Provenance::new(
        fixture.runtime.clone(),
        fixture.identity(),
        "context-error".into(),
        "POST".into(),
        "owned.invalid".into(),
        "/path".into(),
    );
    provenance.attach_live(Some(live.clone()));
    assert_eq!(
        provenance.apply_request(applied.clone(), Some(b"invalid"), Ok(b"gzip"), 10.),
        Err(HookError::Content(crate::http_content::ContentError::Value))
    );
    let row = fixture.row("context-error");
    assert_eq!(row["agent"], "alice");
    assert_eq!(row["metadata"]["agent"], "alice");
    assert_eq!(row["metadata"]["test_agent"], "claimed");
    assert_eq!(row["metadata"]["test_id"], "T1");
    assert_eq!(row["metadata"]["test_intent"], "inspect");
    assert_eq!(
        row["metadata"]["test_context"],
        json!({"run":"run1","agent":"claimed","test":"T1","intent":"inspect"})
    );
    assert_eq!(row["state"], "pending");
}

#[test]
fn response_capture_keeps_encoded_content_independently_of_later_hook_skip() {
    let fixture = Fixture::new();
    let live = fixture.begin("response");
    let capture = fixture.capture("response", live.clone());
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
    headers.append("x-repeat", "one".parse().unwrap());
    headers.append("x-repeat", "two".parse().unwrap());
    capture.head_with_fields(StatusCode::CREATED, &headers, false, None, None);
    capture.data(b"not decoded ");
    capture.data(b"by the live view");
    assert_eq!(fixture.row("response")["status"], 201);
    assert_eq!(fixture.row("response")["state"], "pending");
    capture.apply_head();
    capture.finish_live(true, None);
    capture.skip_response();
    assert_eq!(fixture.row("response")["state"], "complete");
    assert_eq!(
        fixture.body("response")["data_base64"],
        STANDARD.encode(b"not decoded by the live view")
    );
    assert_eq!(
        fixture.row("response")["response_headers"],
        json!([
            ["content-encoding", "gzip"],
            ["x-repeat", "one"],
            ["x-repeat", "two"]
        ])
    );
}

#[test]
fn response_capture_preserves_reached_protocol_reason_and_trailers() {
    for (id, version, reason, expected_start) in [
        (
            "canonical-h1",
            "HTTP/1.1",
            Some(b"OK".as_slice()),
            b"HTTP/1.1 200 OK\r\n".as_slice(),
        ),
        (
            "custom-h1",
            "HTTP/1.0",
            Some(b"Accepted by upstream".as_slice()),
            b"HTTP/1.0 200 Accepted by upstream\r\n".as_slice(),
        ),
        (
            "empty-h2",
            "HTTP/2.0",
            Some(b"".as_slice()),
            b"HTTP/2.0 200 \r\n".as_slice(),
        ),
    ] {
        let fixture = Fixture::new();
        let live = fixture.begin(id);
        let capture = fixture.capture(id, live.clone());
        // The relay receives parser version/reason facts before the later
        // response capture callback supplies status and headers. A callback
        // without those optional facts must not erase the reached values.
        live.response_details(Some(version), reason);
        let mut headers = HeaderMap::new();
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.append("x-reached-trailer", "one".parse().unwrap());
        headers.append("x-reached-trailer", "two".parse().unwrap());
        capture.head_with_fields(StatusCode::OK, &headers, false, None, None);
        capture.data(b"body");
        capture.apply_head();
        capture.finish_live(true, None);
        live.response_trailers(vec![
            ("x-reached-trailer".into(), "one".into()),
            ("x-reached-trailer".into(), "two".into()),
        ]);

        let mut plan = fixture
            .runtime
            .traffic_view
            .export(id, crate::traffic_view::ExportFormat::RawResponse)
            .unwrap();
        let mut output = Vec::new();
        while let Some(chunk) = plan.next_chunk().unwrap() {
            output.extend_from_slice(&chunk);
        }
        assert!(output.starts_with(expected_start), "{id}");
        assert!(output.ends_with(
            b"4\r\nbody\r\n0\r\nx-reached-trailer: one\r\nx-reached-trailer: two\r\n\r\n"
        ));
    }
}

#[test]
fn completed_empty_streamed_and_sse_bodies_are_distinct() {
    let fixture = Fixture::new();
    for (id, headers, expected_available) in [
        ("empty", vec![], true),
        (
            "large",
            vec![(
                header::CONTENT_LENGTH,
                (BUFFERED_BODY_THRESHOLD + 1).to_string(),
            )],
            false,
        ),
        (
            "sse",
            vec![(header::CONTENT_TYPE, "text/event-stream".into())],
            false,
        ),
    ] {
        let live = fixture.begin(id);
        let capture = fixture.capture(id, live);
        let headers: HeaderMap = headers
            .into_iter()
            .map(|(name, value)| (name, value.parse().unwrap()))
            .collect();
        capture.head_with_fields(StatusCode::OK, &headers, false, None, None);
        capture.apply_head();
        capture.finish_live(true, None);
        let body = fixture.body(id);
        assert_eq!(body["available"], expected_available, "{id}");
        assert_eq!(fixture.row(id)["state"], "complete");
        if expected_available {
            assert_eq!(body["data_base64"], "");
            assert!(body["reason"].is_null());
        } else {
            assert_eq!(body["reason"], "streamed_or_unavailable");
        }
    }
}

#[test]
fn failed_response_retains_observed_head_but_not_partial_body() {
    let fixture = Fixture::new();
    let live = fixture.begin("aborted");
    let capture = fixture.capture("aborted", live);
    capture.head_with_fields(StatusCode::ACCEPTED, &HeaderMap::new(), false, None, None);
    capture.data(b"partial");
    capture.finish_live(false, Some("owned producer error"));
    let row = fixture.row("aborted");
    assert_eq!(row["status"], 202);
    assert_eq!(row["state"], "error");
    assert_eq!(row["error"], "owned producer error");
    assert_eq!(fixture.body("aborted")["available"], false);

    let live = fixture.begin("latched-success");
    let capture = fixture.capture("latched-success", live);
    capture.head_with_fields(StatusCode::OK, &HeaderMap::new(), false, None, None);
    capture.data(b"complete");
    capture.finish_live(true, Some("later connection error"));
    let row = fixture.row("latched-success");
    assert_eq!(row["state"], "complete");
    assert!(row["error"].is_null());
    assert_eq!(
        fixture.body("latched-success")["data_base64"],
        STANDARD.encode(b"complete")
    );
}

#[test]
fn local_response_uses_known_head_without_polling_or_guessing_empty_body() {
    let fixture = Fixture::new();
    let live = fixture.begin("local");
    let response = super::super::response(StatusCode::FORBIDDEN, "owned local denial");
    local_response(&live, &response);
    let row = fixture.row("local");
    assert_eq!(row["state"], "complete");
    assert_eq!(row["status"], 403);
    assert_eq!(row["request_body"]["reason"], "pending");
    assert_eq!(fixture.body("local")["reason"], "streamed_or_unavailable");
    drop(live);
    assert_eq!(fixture.row("local")["state"], "complete");
    assert_eq!(
        fixture.row("local")["request_body"]["reason"],
        "streamed_or_unavailable"
    );
}

/// The existing H1 parser supplies the real independent request observation.
/// This is an in-memory byte stream with a permanently pending local service:
/// no origin, listener, Proxy, Agent API, H2 or operational state is involved.
#[tokio::test]
async fn real_request_context_waits_for_complete_body_and_rejects_truncation() {
    use super::super::request_context::RequestContext;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::{convert::Infallible, time::Duration};
    use tokio::{io::AsyncWriteExt, sync::mpsc, task::JoinHandle, time::timeout};

    struct Driver(JoinHandle<hyper::Result<()>>);
    impl Drop for Driver {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    const LIMIT: Duration = Duration::from_secs(3);
    for complete in [true, false] {
        let fixture = Fixture::new();
        let (mut client, server) = tokio::io::duplex(4096);
        let (send, mut requests) = mpsc::unbounded_channel();
        let mut driver = Driver(tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |request| {
                        assert!(send.send(request).is_ok());
                        std::future::pending::<Result<Response<Empty<Bytes>>, Infallible>>()
                    }),
                )
                .await
        }));
        client
            .write_all(b"POST /path HTTP/1.1\r\nHost: owned.invalid\r\nContent-Length: 4\r\n\r\nbo")
            .await
            .unwrap();
        let mut request = timeout(LIMIT, requests.recv()).await.unwrap().unwrap();
        let destination = Destination::from_request(&request, None).unwrap();
        let live = begin(
            &fixture.runtime,
            &fixture.identity(),
            "barrier",
            &request,
            &destination,
        )
        .unwrap();
        let mut context = RequestContext::traffic_only(&mut request, false, None).unwrap();
        context.attach_live(Some(live.clone()));
        let mut buffered =
            tokio::spawn(async move { context.buffer(request.into_body(), Some(4)).await });
        assert!(
            timeout(Duration::from_millis(20), &mut buffered)
                .await
                .is_err()
        );
        assert_eq!(fixture.row("barrier")["request_body"]["reason"], "pending");
        if complete {
            client.write_all(b"dy").await.unwrap();
            let (body, context) = timeout(LIMIT, &mut buffered)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                fixture
                    .runtime
                    .traffic_view
                    .body("barrier", Side::Request)
                    .unwrap()["data_base64"],
                STANDARD.encode(b"body")
            );
            drop((body, context));
        } else {
            client.shutdown().await.unwrap();
            assert!(
                timeout(LIMIT, &mut buffered)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert_eq!(
                fixture
                    .runtime
                    .traffic_view
                    .body("barrier", Side::Request)
                    .unwrap()["available"],
                false
            );
        }
        // Neither request-only control fabricated a successful response.
        assert_eq!(fixture.row("barrier")["state"], "pending");
        drop(live);
        assert_eq!(fixture.row("barrier")["state"], "incomplete");
        driver.0.abort();
        let _ = timeout(LIMIT, &mut driver.0).await.unwrap();
    }
}
