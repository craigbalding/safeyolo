use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Take the HTTP/1 server parser's completion observation from this request.
///
/// Available on parsed server requests before body replacement or forwarding.
/// Completes only at validated request EOM (immediately for a bodyless head),
/// independently of whether the final body frame is consumed. Read cancellation,
/// incomplete framing and connection closure abort pending observation. A valid
/// completion survives later cancellation. No bytes are captured or drained.
///
/// The private extension is cloneable, but shares one takeable receiver. A second
/// take, including through cloned extensions, returns None. HTTP/2 servers use
/// h2::ext::take_request_completion instead.
pub fn take_request_completion<B>(request: &mut http::Request<B>) -> Option<RequestCompletion> {
    let slot = request.extensions_mut().remove::<RequestCompletionSlot>()?;
    let receiver = slot
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
    receiver
}

/// Payload-free observation of one parsed request. Drive alongside the ingress
/// connection; body None, content-length and downstream polling are not EOM.
#[derive(Debug)]
#[must_use = "request completion is observed by polling this future"]
pub struct RequestCompletion(oneshot::Receiver<()>);

impl RequestCompletion {
    /// None is pending without registering/replacing the async waker. Some
    /// finishes observation, just like Future::Ready; do not observe it again.
    pub fn try_result(&mut self) -> Option<Result<(), RequestAborted>> {
        match self.0.try_recv() {
            Ok(()) => Some(Ok(())),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => Some(Err(RequestAborted)),
        }
    }
}
impl Future for RequestCompletion {
    type Output = Result<(), RequestAborted>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.map_err(|_| RequestAborted))
    }
}
/// The parser did not validate request EOM before read cancellation or failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequestAborted;
impl std::fmt::Display for RequestAborted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request completion aborted")
    }
}
impl std::error::Error for RequestAborted {}

#[derive(Clone)]
struct RequestCompletionSlot(Arc<Mutex<Option<RequestCompletion>>>);

#[derive(Debug)]
pub(crate) struct RequestCompletionProducer(oneshot::Sender<()>);
impl RequestCompletionProducer {
    pub(crate) fn complete(self) {
        let _ = self.0.send(());
    }
}
pub(crate) fn register_request_completion(
    extensions: &mut http::Extensions,
) -> RequestCompletionProducer {
    let (sender, receiver) = oneshot::channel();
    extensions.insert(RequestCompletionSlot(Arc::new(Mutex::new(Some(
        RequestCompletion(receiver),
    )))));
    RequestCompletionProducer(sender)
}
