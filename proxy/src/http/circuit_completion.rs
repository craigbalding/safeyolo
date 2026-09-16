//! Request and response application effects owned by the HTTP connection driver.
//! Protocol receivers supply completion; this module never reads a body.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use hyper::{Request, StatusCode};

use super::{request_context::RequestContext, test_context::ResponseCapture};
use crate::{ConnectionIdentity, RuntimeState};

enum Protocol {
    Http1(hyper::ext::ResponseCompletion),
    Http2(h2::ext::ResponseCompletion),
}

impl Protocol {
    fn try_result(&mut self) -> Option<Result<StatusCode, ()>> {
        match self {
            Self::Http1(observer) => observer.try_result().map(|result| result.map_err(|_| ())),
            Self::Http2(observer) => observer.try_result().map(|result| result.map_err(|_| ())),
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<StatusCode, ()>> {
        match self {
            Self::Http1(observer) => Pin::new(observer).poll(cx).map_err(|_| ()),
            Self::Http2(observer) => Pin::new(observer).poll(cx).map_err(|_| ()),
        }
    }
}

struct Observation {
    protocol: Option<Protocol>,
    applied: Option<bool>,
    request: Option<RequestContext>,
    request_failed: bool,
}

/// Trusted request context and cached application outcomes. Selected response
/// fields and bounded content remain private in the optional capture owner.
pub(super) struct Completion {
    observation: Mutex<Observation>,
    state: RuntimeState,
    identity: ConnectionIdentity,
    request_id: String,
    host: String,
    capture: Option<Arc<ResponseCapture>>,
    recording: Option<Arc<super::flow_recording::Recording>>,
    traffic: Option<Arc<super::traffic::Traffic>>,
    trace: Option<Arc<crate::request_trace::RequestTrace>>,
}

impl Completion {
    pub(super) fn register<B>(
        request: &mut Request<B>,
        http2: bool,
        state: RuntimeState,
        identity: ConnectionIdentity,
        request_id: String,
        host: String,
        context: Option<RequestContext>,
    ) -> Arc<Self> {
        let recording = request
            .extensions_mut()
            .remove::<Arc<super::flow_recording::Recording>>();
        let request_failed = context
            .as_ref()
            .is_some_and(RequestContext::evidence_failed);
        let traffic = context.as_ref().and_then(RequestContext::traffic);
        let trace = context.as_ref().and_then(RequestContext::trace);
        let capture = context.as_ref().and_then(|context| {
            let provenance = context.response_provenance();
            let traffic = context.traffic();
            (provenance.is_some() || traffic.is_some()).then(|| {
                Arc::new(ResponseCapture::new(
                    state.clone(),
                    provenance,
                    traffic,
                    recording.clone(),
                    trace.clone(),
                ))
            })
        });
        let protocol = match (http2, &capture) {
            (true, Some(capture)) => Protocol::Http2(h2::ext::on_response_complete_with_capture(
                request,
                capture.clone(),
            )),
            (false, Some(capture)) => Protocol::Http1(
                hyper::ext::on_response_complete_with_capture(request, capture.clone()),
            ),
            (true, None) => Protocol::Http2(h2::ext::on_response_complete(request)),
            (false, None) => Protocol::Http1(hyper::ext::on_response_complete(request)),
        };
        Arc::new(Self {
            observation: Mutex::new(Observation {
                protocol: Some(protocol),
                applied: None,
                request: context,
                request_failed,
            }),
            state,
            identity,
            request_id,
            host,
            capture,
            recording,
            traffic,
            trace,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Observation> {
        // Terminal application is reserved before calling the runtime helper.
        // If it unwinds, a poisoned observation retains failure and cannot replay
        // the possibly committed circuit mutation.
        self.observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn apply(&self, observation: &mut Observation, result: Result<StatusCode, ()>) -> bool {
        observation.applied = Some(true);
        observation.protocol = None;
        if result.is_ok()
            && let Some(capture) = &self.capture
        {
            capture.apply_head();
        }
        let circuit = match result {
            Ok(status) => crate::circuit_runtime::completed_response(
                &self.state,
                &self.identity,
                &self.request_id,
                self.traffic
                    .as_ref()
                    .is_some_and(|traffic| traffic.source_metadata_reached()),
                &self.host,
                status.as_u16(),
                self.trace.as_ref(),
            ),
            Err(()) => crate::circuit_runtime::ResponseOutcome::Complete {
                evidence_failed: false,
            },
        };
        let mut failed = circuit.evidence_failed();
        if matches!(
            circuit,
            crate::circuit_runtime::ResponseOutcome::Exception { .. }
        ) {
            if let Some(capture) = &self.capture {
                capture.skip_response();
            }
            if let Some(recording) = &self.recording {
                recording.skip_response();
            }
            observation.applied = Some(failed);
            return failed;
        }
        if let Some(capture) = &self.capture {
            failed |= capture.finish(result.is_ok());
        } else if let Some(recording) = &self.recording {
            recording.finish(result.is_ok(), None, false);
        }
        observation.applied = Some(failed);
        failed
    }

    /// Observe a latched result without replacing the connection driver's waker.
    /// Some is terminal; true reports an evidence failure after application.
    pub(super) fn try_finish(&self) -> Option<bool> {
        let mut observation = self.lock();
        if observation.applied.is_none()
            && let Some(result) = observation.protocol.as_mut().and_then(Protocol::try_result)
        {
            self.apply(&mut observation, result);
        }
        // Source response() reads currently applied metadata. Do not publish a
        // later request hook ahead of a response completion already observable.
        if let Some(failed) = observation
            .request
            .as_mut()
            .and_then(RequestContext::try_finish)
        {
            observation.request_failed |= failed;
            observation.request = None;
        }
        observation
            .applied
            .map(|failed| failed || observation.request_failed)
    }

    /// Poll with the connection driver's waker and cache application exactly once.
    pub(super) fn poll(&self, cx: &mut Context<'_>) -> Poll<bool> {
        let mut observation = self.lock();
        if observation.applied.is_none()
            && let Poll::Ready(result) = observation
                .protocol
                .as_mut()
                .expect("pending observation has a protocol receiver")
                .poll(cx)
        {
            self.apply(&mut observation, result);
        }
        if let Some(request) = observation.request.as_mut()
            && let Poll::Ready(failed) = request.poll(cx)
        {
            observation.request_failed |= failed;
            observation.request = None;
        }
        match observation.applied {
            Some(failed) => Poll::Ready(failed || observation.request_failed),
            None => Poll::Pending,
        }
    }

    /// Run the source header-time streaming decision once, outside parser locks.
    pub(super) fn headers_received(&self) {
        let _observation = self.lock();
        if let Some(capture) = &self.capture {
            capture.apply_head();
        }
    }

    pub(super) fn evidence_failed(&self) -> bool {
        let observation = self.lock();
        observation.request_failed || observation.applied.unwrap_or(false)
    }

    /// Construct the teardown owner now, so even an unpolled future has its guard.
    /// Connection errors are returned unchanged; an aborted response has no status.
    pub(super) fn drive<F>(
        self: Arc<Self>,
        connection: F,
    ) -> impl Future<Output = hyper::Result<()>> + Send
    where
        F: Future<Output = hyper::Result<()>> + Send + 'static,
    {
        let driving = Driving {
            completion: self,
            connection: Some(Box::pin(connection)),
        };
        // Registration alone leaves client/parent handshakes unowned. Handoff
        // occurs only once this synchronous teardown guard actually exists.
        if let Some(recording) = &driving.completion.recording {
            recording.defer();
        }
        driving
    }
}

struct Driving<F> {
    completion: Arc<Completion>,
    connection: Option<Pin<Box<F>>>,
}

impl<F> Driving<F> {
    fn finish(&mut self) {
        let _ = self.completion.try_finish();
        // Connection drop can abort a pending observer. H2's existing receive
        // task may also have latched completion concurrently with this drop.
        drop(self.connection.take());
        let _ = self.completion.try_finish();
    }
}

impl<F> Future for Driving<F>
where
    F: Future<Output = hyper::Result<()>>,
{
    type Output = hyper::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let _ = this.completion.poll(cx);
        let result = this
            .connection
            .as_mut()
            .expect("connection driver polled after completion")
            .as_mut()
            .poll(cx);
        if let Poll::Ready(Err(error)) = &result
            && let Some(recording) = &this.completion.recording
        {
            recording.producer_error(error);
        }
        let _ = this.completion.poll(cx);
        if result.is_ready() {
            this.finish();
        }
        result
    }
}

impl<F> Drop for Driving<F> {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::RwLock, time::Duration};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        sync::oneshot,
        task::JoinHandle,
    };

    const LIMIT: Duration = Duration::from_secs(3);

    struct Fixture {
        directory: TempDir,
        state: RuntimeState,
    }

    impl Fixture {
        fn new(full_sink: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let policy = directory.path().join("policy.json");
            std::fs::write(
                &policy,
                r#"{"addons":{"circuit_breaker":{"failure_threshold":1,"jitter_factor":0}}}"#,
            )
            .unwrap();
            let config = serde_json::from_value(json!({
                "listeners":[],"policy_file":policy,
                "readiness_file":directory.path().join("ready"),
                "flow_store_enabled": false,
                "audit_log_path": directory.path().join("audit.jsonl"),
                "event_log":if full_sink {std::path::PathBuf::from("/dev/full")} else {directory.path().join("events.jsonl")},
                "circuit_breaker_enabled":true,
            }))
            .unwrap();
            let runtime = crate::Runtime::new(
                config,
                "completion-fixture",
                Arc::new(tokio::sync::Mutex::new(())),
                None,
                None,
            )
            .unwrap();
            Self {
                directory,
                state: Arc::new(RwLock::new(Arc::new(runtime))),
            }
        }

        fn register(&self, http2: bool) -> (Request<Empty<Bytes>>, Arc<Completion>) {
            let mut request = Request::builder()
                .uri("http://owned.invalid/")
                .body(Empty::new())
                .unwrap();
            let completion = Completion::register(
                &mut request,
                http2,
                self.state.clone(),
                ConnectionIdentity {
                    agent_id: "alice".into(),
                    connection_id: "owned-connection".into(),
                    source_id: None,
                },
                "owned-request".into(),
                "owned.invalid".into(),
                None,
            );
            (request, completion)
        }

        fn failures(&self) -> Option<Value> {
            self.state
                .read()
                .unwrap()
                .circuits
                .snapshot(crate::circuit_runtime::now())
                .unwrap()["states"]["owned.invalid"]
                .get("failure_count")
                .cloned()
        }

        fn events(&self) -> Vec<Value> {
            std::fs::read_to_string(self.directory.path().join("events.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|event: &Value| event["event"] == "proxy.circuit")
                .collect()
        }

        fn reload_threshold(&self, threshold: u64) {
            let mut state = self.state.write().unwrap();
            let old = state.clone();
            let config = old.config.clone();
            std::fs::write(
                config.policy_file.as_ref().unwrap(),
                json!({"addons":{"circuit_breaker":{"failure_threshold":threshold,"jitter_factor":0}}}).to_string(),
            )
            .unwrap();
            *state = Arc::new(
                crate::Runtime::new(
                    config,
                    "completion-fixture",
                    old.temporary_policy_lock.clone(),
                    Some(&old),
                    None,
                )
                .unwrap(),
            );
        }
    }

    struct Task<T>(JoinHandle<T>);
    impl<T> Drop for Task<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn read_head(peer: &mut DuplexStream) {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(peer.read_u8().await.unwrap());
        }
    }

    #[tokio::test]
    async fn actual_h1_driver_applies_completed_status_and_preserves_response() {
        for (name, wire, body, expected_failures) in [
            (
                "empty",
                &b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
                Some(&b""[..]),
                Some(1),
            ),
            (
                "body",
                &b"HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
                    [..],
                Some(&b"body"[..]),
                Some(1),
            ),
            (
                "truncated",
                &b"HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbo"[..],
                None,
                None,
            ),
        ] {
            let fixture = Fixture::new(false);
            let (client, mut peer) = tokio::io::duplex(4096);
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(client))
                    .await
                    .unwrap();
            let (request, completion) = fixture.register(false);
            assert_eq!(completion.try_finish(), None);
            let mut driver = Task(tokio::spawn(completion.clone().drive(connection)));
            let response = sender.send_request(request);
            read_head(&mut peer).await;
            peer.write_all(wire).await.unwrap();
            peer.shutdown().await.unwrap();
            if name == "empty" {
                // The application owner observes completion before the response
                // future is consumed, including a body that is never polled.
                let _ = tokio::time::timeout(LIMIT, &mut driver.0)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(completion.try_finish(), Some(false));
                assert_eq!(fixture.failures(), Some(json!(1)));
            }
            let response = tokio::time::timeout(LIMIT, response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let result = tokio::time::timeout(LIMIT, response.into_body().collect())
                .await
                .unwrap();
            if let Some(expected) = body {
                assert_eq!(result.unwrap().to_bytes(), expected, "{name}");
            } else {
                assert!(result.is_err(), "{name}");
            }
            if name != "empty" {
                let _ = tokio::time::timeout(LIMIT, &mut driver.0)
                    .await
                    .unwrap()
                    .unwrap();
            }
            assert_eq!(completion.try_finish(), Some(false));
            assert_eq!(
                fixture.failures(),
                expected_failures.map(|count| json!(count)),
                "{name}"
            );
            assert_eq!(
                fixture.events().len(),
                usize::from(expected_failures.is_some())
            );
        }
    }

    fn h2_frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            (payload.len() >> 16) as u8,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
            kind,
            flags,
            0,
            0,
            0,
            if kind == 4 || kind == 6 { 0 } else { 1 },
        ];
        bytes.extend_from_slice(payload);
        bytes
    }

    async fn read_h2(peer: &mut DuplexStream) -> (u8, u8, Vec<u8>) {
        let mut header = [0_u8; 9];
        peer.read_exact(&mut header).await.unwrap();
        let length =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let mut payload = vec![0; length];
        peer.read_exact(&mut payload).await.unwrap();
        (header[3], header[4], payload)
    }

    fn h2_peer(mut peer: DuplexStream, terminal: &str) -> (Task<()>, oneshot::Receiver<()>) {
        let (ready, receiver) = oneshot::channel();
        let terminal = match terminal {
            "reset" => h2_frame(3, 0, &0_u32.to_be_bytes()),
            "partial" => h2_frame(0, 0, b"body"),
            "complete" => h2_frame(0, 1, b"body"),
            _ => panic!("unknown owned H2 fixture"),
        };
        let task = tokio::spawn(async move {
            let mut preface = [0_u8; 24];
            peer.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            peer.write_all(&h2_frame(4, 0, &[])).await.unwrap();
            loop {
                let (kind, flags, _) = read_h2(&mut peer).await;
                if kind == 4 && flags == 0 {
                    peer.write_all(&h2_frame(4, 1, &[])).await.unwrap();
                }
                if kind == 1 {
                    break;
                }
            }
            // Literal :status 503. The test owns only protocol bytes; the
            // production parser remains responsible for validation.
            peer.write_all(&h2_frame(1, 4, b"\x08\x03\x35\x30\x33"))
                .await
                .unwrap();
            peer.write_all(&terminal).await.unwrap();
            peer.write_all(&h2_frame(6, 0, b"barrier!")).await.unwrap();
            loop {
                let (kind, flags, payload) = read_h2(&mut peer).await;
                if kind == 6 && flags == 1 && payload == b"barrier!" {
                    break;
                }
            }
            let _ = ready.send(());
            // Keep the transport live while the test controls driver teardown.
            std::future::pending::<()>().await;
        });
        (Task(task), receiver)
    }

    #[tokio::test]
    async fn actual_h2_latched_unread_response_survives_unpolled_driver_drop_once() {
        for mode in [
            "unpolled_drop",
            "concurrent_finish",
            "no_error",
            "current_runtime",
        ] {
            let fixture = Fixture::new(false);
            let (client, peer) = tokio::io::duplex(4096);
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                    .await
                    .unwrap();
            let (request, completion) = fixture.register(true);
            let response = sender.send_request(request);
            if mode == "current_runtime" {
                fixture.reload_threshold(2);
            }
            let (_peer, mut barrier) = h2_peer(
                peer,
                if mode == "no_error" {
                    "reset"
                } else {
                    "complete"
                },
            );
            let mut connection = Box::pin(connection);
            tokio::time::timeout(
                LIMIT,
                std::future::poll_fn(|cx| {
                    assert!(
                        connection.as_mut().poll(cx).is_pending(),
                        "owned H2 transport remains live"
                    );
                    Pin::new(&mut barrier).poll(cx)
                }),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                fixture.failures(),
                None,
                "the bare Hyper driver does not apply circuits"
            );
            if mode == "concurrent_finish" {
                std::thread::scope(|scope| {
                    for _ in 0..4 {
                        let completion = completion.clone();
                        scope.spawn(move || assert_eq!(completion.try_finish(), Some(false)));
                    }
                });
            }
            // Constructing drive installs its guard synchronously. Dropping it
            // before its first poll must still apply the already latched status.
            drop(completion.clone().drive(connection));
            assert_eq!(completion.try_finish(), Some(false));
            let expected = if mode == "no_error" {
                None
            } else {
                Some(json!(1))
            };
            assert_eq!(fixture.failures(), expected, "{mode}");
            assert_eq!(
                fixture.events().len(),
                usize::from(mode != "no_error" && mode != "current_runtime")
            );
            if mode != "no_error" {
                let response = response.await.unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    "body",
                    "validated final DATA remained available"
                );
            } else {
                drop(response);
            }
        }
    }

    #[tokio::test]
    async fn actual_h2_live_driver_distinguishes_unread_completion_from_body_cancellation() {
        for terminal in ["complete", "partial"] {
            let fixture = Fixture::new(false);
            let (client, peer) = tokio::io::duplex(4096);
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                    .await
                    .unwrap();
            let (request, completion) = fixture.register(true);
            let response = sender.send_request(request);
            let (_peer, barrier) = h2_peer(peer, terminal);
            let driver = Task(tokio::spawn(completion.clone().drive(connection)));
            tokio::time::timeout(LIMIT, barrier).await.unwrap().unwrap();
            // Poll the owner directly so this assertion does not depend on the
            // relative scheduling of the already-woken connection driver.
            let observed = completion.try_finish();
            assert_eq!(observed, (terminal == "complete").then_some(false));
            let response = tokio::time::timeout(LIMIT, response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            // Body drop aborts incomplete reception. A previously latched END_STREAM
            // remains successful even though none of its buffered body was read.
            drop(response);
            assert_eq!(completion.try_finish(), Some(false));
            drop(driver);
            assert_eq!(
                fixture.failures(),
                (terminal == "complete").then(|| json!(1)),
                "{terminal}"
            );
            assert_eq!(fixture.events().len(), usize::from(terminal == "complete"));
        }
    }

    #[tokio::test]
    async fn queued_request_and_unpolled_connection_drop_abort_without_circuit_effects() {
        let fixture = Fixture::new(false);
        let (client, _peer) = tokio::io::duplex(4096);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let (request, completion) = fixture.register(false);
        let response = sender.send_request(request);
        drop(response);
        drop(completion.clone().drive(connection));
        assert_eq!(completion.try_finish(), Some(false));
        assert_eq!(fixture.failures(), None);
        assert!(fixture.events().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn evidence_failure_is_cached_after_mutation_and_does_not_change_body() {
        let fixture = Fixture::new(true);
        let (client, mut peer) = tokio::io::duplex(4096);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        let (request, completion) = fixture.register(false);
        let mut driver = Task(tokio::spawn(completion.clone().drive(connection)));
        let response = sender.send_request(request);
        read_head(&mut peer).await;
        peer.write_all(
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
        )
        .await
        .unwrap();
        peer.shutdown().await.unwrap();
        let response = tokio::time::timeout(LIMIT, response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "body"
        );
        let _ = tokio::time::timeout(LIMIT, &mut driver.0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completion.try_finish(), Some(true));
        assert_eq!(completion.try_finish(), Some(true));
        assert_eq!(
            fixture.failures(),
            Some(json!(1)),
            "failed evidence did not roll back or replay the response"
        );
    }
}
