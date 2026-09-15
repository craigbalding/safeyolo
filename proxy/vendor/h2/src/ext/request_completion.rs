use atomic_waker::AtomicWaker;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const PENDING: u8 = 0;
const COMPLETE: u8 = 1;
const ABORTED: u8 = 2;

/// Take the HTTP/2 server parser's request completion observation.
///
/// Available in parsed request extensions before body replacement/forwarding.
/// Only validated HEADERS/DATA/trailing HEADERS END_STREAM completes it. Queued
/// unread payload does not delay observation. Reset (including NO_ERROR), read
/// cancellation, incomplete framing and connection errors abort pending work;
/// latched completion survives later cancellation. No body data is retained or
/// drained and normal flow control is unchanged.
///
/// Cloned request extensions share one takeable receiver; subsequent takes
/// return None. Drive the observer alongside ingress connection ownership.
pub fn take_request_completion<B>(request: &mut http::Request<B>) -> Option<RequestCompletion> {
    let slot = request.extensions_mut().remove::<RequestCompletionSlot>()?;
    let receiver = slot
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
    receiver
}

/// Payload-free, noncloneable observation of one parsed request.
#[must_use = "request completion is observed by polling this future"]
pub struct RequestCompletion {
    shared: Arc<Shared>,
}
impl std::fmt::Debug for RequestCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestCompletion").finish_non_exhaustive()
    }
}
impl RequestCompletion {
    /// None is pending without registering/replacing the async waker. Some
    /// finishes observation, just like Future::Ready; do not observe it again.
    pub fn try_result(&mut self) -> Option<Result<(), RequestAborted>> {
        match self.shared.terminal.load(Ordering::Acquire) {
            PENDING => None,
            COMPLETE => Some(Ok(())),
            _ => Some(Err(RequestAborted)),
        }
    }
}
impl Future for RequestCompletion {
    type Output = Result<(), RequestAborted>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.shared.waker.register(cx.waker());
        self.try_result().map_or(Poll::Pending, Poll::Ready)
    }
}
/// The parser did not validate request EOM before read cancellation or failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestAborted;
impl std::fmt::Display for RequestAborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request completion aborted")
    }
}
impl std::error::Error for RequestAborted {}

struct Shared {
    terminal: AtomicU8,
    waker: AtomicWaker,
}
impl Shared {
    fn finish(&self, terminal: u8) {
        if self
            .terminal
            .compare_exchange(PENDING, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.waker.wake();
        }
    }
}
#[derive(Clone)]
struct RequestCompletionSlot(Arc<Mutex<Option<RequestCompletion>>>);

pub(crate) struct RequestCompletionProducer(Arc<Shared>);
impl std::fmt::Debug for RequestCompletionProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestCompletionProducer")
            .finish_non_exhaustive()
    }
}
impl RequestCompletionProducer {
    pub(crate) fn complete(self) {
        self.0.finish(COMPLETE);
    }
}
impl Drop for RequestCompletionProducer {
    fn drop(&mut self) {
        self.0.finish(ABORTED);
    }
}
pub(crate) fn register_request_completion(
    extensions: &mut http::Extensions,
) -> RequestCompletionProducer {
    let shared = Arc::new(Shared {
        terminal: AtomicU8::new(PENDING),
        waker: AtomicWaker::new(),
    });
    extensions.insert(RequestCompletionSlot(Arc::new(Mutex::new(Some(
        RequestCompletion {
            shared: shared.clone(),
        },
    )))));
    RequestCompletionProducer(shared)
}
