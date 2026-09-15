use atomic_waker::AtomicWaker;
use http::{Request, StatusCode};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
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
    let shared = Arc::new(Shared {
        terminal: AtomicU16::new(PENDING),
        waker: AtomicWaker::new(),
    });
    let producer = ResponseCompletionProducer(Arc::new(Producer {
        shared: shared.clone(),
    }));
    if let Some(previous) = request.extensions_mut().insert(producer) {
        previous.abort();
    }
    ResponseCompletion { shared }
}

/// A response-completion observation containing no request or response content.
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
}

impl Shared {
    fn finish(&self, terminal: u16) {
        if self
            .terminal
            .compare_exchange(PENDING, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.waker.wake();
        }
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
