use atomic_waker::AtomicWaker;
use http::{Request, StatusCode};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const PENDING: u16 = 0;
const ABORTED: u16 = 1;

/// Observe validated completion of the response to this request.
///
/// Register before sending the request. The observer completes when the receiver
/// validates the final response's END_STREAM, independently of body consumption.
/// Informational responses, resets (including NO_ERROR), and connection EOF do
/// not constitute response completion. Dropping the request, response future or
/// receive body before completion aborts the observation. A completed result is
/// immutable and survives subsequent cancellation or connection failure.
///
/// This optional metadata does not drain a response, retain its payload, or
/// change HTTP/2 admission. Re-registering replaces the previous registration.
/// Cloning request extensions shares a registration: use a fresh registration
/// for each independently sent request.
pub fn on_response_complete<B>(request: &mut Request<B>) -> ResponseCompletion {
    register(request, None)
}

/// A synchronous sink for accepted response headers and encoded DATA payloads.
///
/// Calls run under protocol/producer locks. Short private capture-state
/// synchronization is permitted for bounded copying or state updates. Do not
/// perform I/O, wait for protocol/task progress, panic, or re-enter the protocol
/// or observer. Body decoding and policy decisions belong to the application
/// after these calls return. A partial capture is not evidence of a complete
/// response; use the paired completion result.
pub trait ResponseBodyCapture: Send + Sync {
    /// Observe the final accepted head, before delivery or head-only completion.
    /// `end_stream_at_head` distinguishes a response with no following body.
    fn head(&self, status: StatusCode, headers: &http::HeaderMap, end_stream_at_head: bool);

    /// Observe the final head with parser-owned field order and reason bytes.
    ///
    /// `original_fields` is absent when original field capture was not enabled;
    /// it must not be reconstructed from the grouped HeaderMap. HTTP/1 clients
    /// enable it with `preserve_header_case(true)`. HTTP/2 supplies decoded
    /// regular fields and an empty reason. A response without a status line can
    /// have no observed reason. All borrows end when this callback returns.
    /// The default preserves existing `head` implementations and call order.
    fn head_with_fields(
        &self,
        status: StatusCode,
        headers: &http::HeaderMap,
        end_stream_at_head: bool,
        _original_fields: Option<&crate::ext::OriginalHeaderFields>,
        _reason: Option<&[u8]>,
    ) {
        self.head(status, headers, end_stream_at_head);
    }

    /// Observe accepted body bytes, excluding transfer framing and padding.
    /// The final payload is observed before successful completion is published.
    fn data(&self, payload: &[u8]);
}

/// Observe completion and copy accepted response bytes into a caller sink.
///
/// The sink sees the final head and DATA before their ordinary delivery. Calls
/// stop when completion or cancellation wins. No additional reads, flow-control
/// releases, payload queue or content decoding is introduced.
pub fn on_response_complete_with_capture<B>(
    request: &mut Request<B>,
    capture: Arc<dyn ResponseBodyCapture>,
) -> ResponseCompletion {
    register(request, Some(capture))
}

fn register<B>(
    request: &mut Request<B>,
    capture: Option<Arc<dyn ResponseBodyCapture>>,
) -> ResponseCompletion {
    let shared = Arc::new(Shared {
        terminal: AtomicU16::new(PENDING),
        waker: AtomicWaker::new(),
        capture: Mutex::new(capture),
    });
    let producer = ResponseCompletionProducer(Arc::new(Producer {
        shared: shared.clone(),
    }));
    if let Some(previous) = request.extensions_mut().insert(producer) {
        previous.abort();
    }
    ResponseCompletion { shared }
}

/// A response-completion observation with content-free `Debug` output.
#[must_use = "completion is observed by polling this future"]
pub struct ResponseCompletion {
    shared: Arc<Shared>,
}

/// The response was not validated as complete before cancellation or failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aborted;

impl fmt::Display for Aborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("response completion aborted")
    }
}

impl std::error::Error for Aborted {}

impl fmt::Debug for ResponseCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseCompletion").finish_non_exhaustive()
    }
}

impl ResponseCompletion {
    /// Read the terminal result without registering or replacing a waker.
    ///
    /// `None` means the response is still pending. `Some` completes this
    /// observation, like `Future::poll` returning `Poll::Ready`; the caller
    /// must apply its result only once. The underlying terminal state is latched.
    pub fn try_result(&mut self) -> Option<Result<StatusCode, Aborted>> {
        match self.shared.terminal.load(Ordering::Acquire) {
            PENDING => None,
            ABORTED => Some(Err(Aborted)),
            status => {
                Some(Ok(StatusCode::from_u16(status)
                    .expect("completion contains a validated HTTP status")))
            }
        }
    }
}

impl Future for ResponseCompletion {
    type Output = Result<StatusCode, Aborted>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.shared.waker.register(cx.waker());
        self.try_result().map_or(Poll::Pending, Poll::Ready)
    }
}

struct Shared {
    terminal: AtomicU16,
    waker: AtomicWaker,
    // Serializes callbacks with the existing terminal latch. No payload is
    // stored here; the caller owns its bounded capture and error state.
    capture: Mutex<Option<Arc<dyn ResponseBodyCapture>>>,
}

impl Shared {
    fn finish(&self, terminal: u16) {
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let changed = self
            .terminal
            .compare_exchange(PENDING, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        let finished_capture = capture.take();
        drop(capture);
        // Never wake or drop the caller-owned sink while holding our mutex.
        if changed {
            self.waker.wake();
        }
        drop(finished_capture);
    }
}

// Separate producer ownership makes dropping an unsent request observable even
// while the caller retains its observer. Cloned extensions share this ownership.
struct Producer {
    shared: Arc<Shared>,
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.shared.finish(ABORTED);
    }
}

#[derive(Clone)]
pub(crate) struct ResponseCompletionProducer(Arc<Producer>);

impl ResponseCompletionProducer {
    pub(crate) fn head(
        &self,
        status: StatusCode,
        headers: &http::HeaderMap,
        end_stream: bool,
        original_fields: Option<&crate::ext::OriginalHeaderFields>,
        reason: Option<&[u8]>,
    ) {
        let capture = self
            .0
            .shared
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(capture) = capture.as_ref() {
            capture.head_with_fields(status, headers, end_stream, original_fields, reason);
        }
    }

    pub(crate) fn data(&self, payload: &[u8]) {
        let capture = self
            .0
            .shared
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(capture) = capture.as_ref() {
            capture.data(payload);
        }
    }

    pub(crate) fn complete(&self, status: StatusCode) {
        self.0.shared.finish(status.as_u16());
    }

    pub(crate) fn abort(&self) {
        self.0.shared.finish(ABORTED);
    }
}

impl fmt::Debug for ResponseCompletionProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseCompletionProducer")
            .finish_non_exhaustive()
    }
}
