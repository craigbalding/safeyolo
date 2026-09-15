use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use http::StatusCode;
use tokio::sync::oneshot;

/// Observe validated completion of the final HTTP/1 response to this request.
///
/// Install this before sending the request on an HTTP/1 client connection. The
/// observer completes when the parser validates the response message boundary,
/// independently of delivery to the body consumer. Informational responses do
/// not complete it; a successful upgrade completes at its response head.
///
/// Dropping the request, canceling its response body, or closing its read side
/// before completion aborts the observer. Existing connection cleanup may still
/// drain a canceled body for reuse; that does not complete the observer.
/// This extension does not drain bodies, change buffering, or support HTTP/2.
pub fn on_response_complete<B>(request: &mut http::Request<B>) -> ResponseCompletion {
    let (sender, receiver) = oneshot::channel();
    request
        .extensions_mut()
        .insert(OnResponseComplete(Arc::new(Mutex::new(Some(sender)))));
    ResponseCompletion(receiver)
}

/// A parser completion observer installed by [`on_response_complete`].
#[derive(Debug)]
pub struct ResponseCompletion(oneshot::Receiver<StatusCode>);

impl ResponseCompletion {
    /// Take a ready result without registering or replacing the async waker.
    ///
    /// `None` means the response remains pending. After `Some`, observation is
    /// complete, as if the future had returned `Poll::Ready`.
    pub fn try_result(&mut self) -> Option<Result<StatusCode, Aborted>> {
        match self.0.try_recv() {
            Ok(status) => Some(Ok(status)),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => Some(Err(Aborted)),
        }
    }
}

/// Completion was not observed before cancellation or read closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Aborted;

impl std::fmt::Display for Aborted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("response completion aborted")
    }
}

impl std::error::Error for Aborted {}

impl Future for ResponseCompletion {
    type Output = Result<StatusCode, Aborted>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.map_err(|_| Aborted))
    }
}

#[derive(Clone)]
pub(crate) struct OnResponseComplete(Arc<Mutex<Option<oneshot::Sender<StatusCode>>>>);

impl OnResponseComplete {
    pub(crate) fn complete(self, status: StatusCode) {
        let sender = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(sender) = sender {
            // Wake only after releasing the latch lock.
            let _ = sender.send(status);
        }
    }

    pub(crate) fn abort(self) {
        let sender = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        drop(sender);
    }
}
