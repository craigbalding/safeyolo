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

    /// Observe accepted body bytes, excluding transfer framing and padding.
    /// The final payload is observed before successful completion is published.
    fn data(&self, payload: &[u8]);
}

/// Observe HTTP/1 completion and copy accepted response bytes into a caller sink.
///
/// The sink sees a final head and DATA before their ordinary delivery. Calls stop
/// when completion or cancellation wins, including before a canceled-body reuse
/// drain. No additional reads, payload queue or content decoding is introduced.
pub fn on_response_complete_with_capture<B>(
    request: &mut http::Request<B>,
    capture: Arc<dyn ResponseBodyCapture>,
) -> ResponseCompletion {
    register(request, Some(capture))
}

fn register<B>(
    request: &mut http::Request<B>,
    capture: Option<Arc<dyn ResponseBodyCapture>>,
) -> ResponseCompletion {
    let (sender, receiver) = oneshot::channel();
    request
        .extensions_mut()
        .insert(OnResponseComplete(Arc::new(Mutex::new(Some(Producer {
            sender,
            capture,
        })))));
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

struct Producer {
    sender: oneshot::Sender<StatusCode>,
    capture: Option<Arc<dyn ResponseBodyCapture>>,
}

#[derive(Clone)]
pub(crate) struct OnResponseComplete(Arc<Mutex<Option<Producer>>>);

impl OnResponseComplete {
    pub(crate) fn head(&self, status: StatusCode, headers: &http::HeaderMap, end_stream: bool) {
        let producer = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(capture) = producer
            .as_ref()
            .and_then(|producer| producer.capture.as_ref())
        {
            capture.head(status, headers, end_stream);
        }
    }

    pub(crate) fn data(&self, payload: &[u8]) {
        let producer = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(capture) = producer
            .as_ref()
            .and_then(|producer| producer.capture.as_ref())
        {
            capture.data(payload);
        }
    }

    pub(crate) fn complete(self, status: StatusCode) {
        let producer = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(producer) = producer {
            // Wake only after releasing the latch lock.
            let _ = producer.sender.send(status);
        }
    }

    pub(crate) fn abort(self) {
        let producer = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        drop(producer);
    }
}
