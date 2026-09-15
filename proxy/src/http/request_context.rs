//! Select at the admitted request head; apply only at validated ingress EOM.
//!
//! This owner never drives a connection or reads extra body frames. Root's
//! exchange owner orders response completion ahead of late request application.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http_body_util::BodyExt;
use hyper::{Request, Response, body::Incoming, header};
use zeroize::Zeroizing;

use crate::{
    ConnectionIdentity, Error, Runtime,
    http_content::ContentError,
    test_context::{self, ContextErrorKind, PreparedRequest, RequestOutcome, TrustedIdentity},
};

use super::test_context::{Provenance, combined};

pub(super) enum Admission {
    Inactive,
    Block(Response<super::Body>),
    Pending(RequestContext),
}

enum Observer {
    Http1(hyper::ext::RequestCompletion),
    Http2(h2::ext::RequestCompletion),
}

impl Observer {
    fn take<B>(request: &mut Request<B>) -> Result<Self, Error> {
        if let Some(observer) = hyper::ext::take_request_completion(request) {
            Ok(Self::Http1(observer))
        } else if let Some(observer) = h2::ext::take_request_completion(request) {
            Ok(Self::Http2(observer))
        } else {
            Err("request completion observer unavailable".into())
        }
    }

    fn try_result(&mut self) -> Option<Result<(), ()>> {
        match self {
            Self::Http1(observer) => observer.try_result().map(|result| result.map_err(|_| ())),
            Self::Http2(observer) => observer.try_result().map(|result| result.map_err(|_| ())),
        }
    }
}

impl Future for Observer {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Http1(observer) => Pin::new(observer).poll(cx).map_err(|_| ()),
            Self::Http2(observer) => Pin::new(observer).poll(cx).map_err(|_| ()),
        }
    }
}

struct Pending {
    observer: Observer,
    prepared: PreparedRequest,
    encoding: Result<Zeroizing<Vec<u8>>, ContentError>,
}

pub(super) struct RequestContext {
    pending: Option<Pending>,
    terminal: Option<bool>,
    provenance: Arc<Provenance>,
    port: u16,
    valid_context: bool,
}

/// Call after network/circuit admission and CONNECT exclusion. Only reserved
/// context values are copied into the core's header input. Real containment is
/// unconditional after that call, including source target/config exceptions.
pub(super) fn prepare<B>(
    runtime: Arc<Runtime>,
    identity: &ConnectionIdentity,
    request_id: &str,
    request: &mut Request<B>,
    destination: &super::Destination,
) -> Result<Admission, Error> {
    let Some(policy) = runtime.policy.as_ref() else {
        return Ok(Admission::Inactive);
    };
    let mut headers = request
        .headers()
        .get_all(test_context::HEADER)
        .iter()
        .map(|value| (test_context::HEADER.to_owned(), value.as_bytes().to_vec()))
        .collect();
    let trusted = identity
        .source_id
        .as_ref()
        .and_then(|source| TrustedIdentity::new(source.clone(), identity.agent_id.clone()).ok());
    let selected = runtime.test_context.prepare_request_current(
        Some(policy),
        test_context::Request {
            host: &destination.policy_host,
            prior_response: false,
            identity: trusted.as_ref(),
            metadata_agent: Some(&identity.agent_id),
        },
        &mut headers,
        super::declaration_time(),
    );
    request.headers_mut().remove(test_context::HEADER);
    let prepared = match selected {
        Ok(prepared) => prepared,
        Err(error) => {
            report_core_error(error.kind());
            return Ok(Admission::Inactive);
        }
    };
    if matches!(
        prepared.result(),
        Ok(RequestOutcome::NotTargetHost | RequestOutcome::PriorResponse)
    ) {
        return Ok(Admission::Inactive);
    }
    let provenance = Arc::new(Provenance::new(
        runtime,
        identity.clone(),
        request_id.to_owned(),
        request.method().to_string(),
        destination.policy_host.clone(),
        destination.path.clone(),
    ));
    if let Ok(RequestOutcome::Block { status, body, .. }) = prepared.result() {
        let bytes = crate::network_guard::Response {
            status: *status,
            headers: Vec::new(),
            body: body.clone(),
        }
        .body_bytes();
        let mut response = Response::builder()
            .status(*status)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-blocked-by", "test-context")
            .body(super::full(bytes))?;
        let failed = apply(&provenance, destination.port, prepared, None, Ok(&[]));
        if failed {
            response
                .headers_mut()
                .insert("x-safeyolo-evidence-error", "true".parse()?);
        }
        return Ok(Admission::Block(super::prior_block(response)));
    }
    let valid_context = matches!(prepared.result(), Ok(RequestOutcome::Applied { .. }));
    let observer = Observer::take(request)?;
    let encoding = combined(request.headers(), header::CONTENT_ENCODING);
    Ok(Admission::Pending(RequestContext {
        pending: Some(Pending {
            observer,
            prepared,
            encoding,
        }),
        terminal: None,
        provenance,
        port: destination.port,
        valid_context,
    }))
}

impl RequestContext {
    /// Small buffered requests must cross the independent parser barrier before
    /// the caller may dial. Streamed bodies retain their still-pending permit.
    pub(super) async fn buffer(
        mut self,
        body: Incoming,
        content_length: Option<u64>,
    ) -> Result<(super::Body, Self), Error> {
        let prepared = super::request_body::prepare(body, content_length, false).await?;
        if let Some(content) = prepared.unvalidated_content {
            if let Some(mut pending) = self.pending.take() {
                if (&mut pending.observer).await.is_err() {
                    return Err("request completion aborted".into());
                }
                self.apply(pending, Some(&content));
            }
        } else {
            self.try_finish();
        }
        Ok((
            prepared
                .body
                .map_err(|error| -> Error { Box::new(error) })
                .boxed(),
            self,
        ))
    }

    /// None is pending without registering/replacing the parser-driver waker.
    pub(super) fn try_finish(&mut self) -> Option<bool> {
        if let Some(failed) = self.terminal {
            return Some(failed);
        }
        let result = self.pending.as_mut()?.observer.try_result()?;
        self.finish(result);
        self.terminal
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if let Some(failed) = self.terminal {
            return Poll::Ready(failed);
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(false);
        };
        match Pin::new(&mut pending.observer).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.finish(result);
                Poll::Ready(self.terminal.unwrap_or(false))
            }
        }
    }

    fn finish(&mut self, result: Result<(), ()>) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        if result.is_ok() {
            self.apply(pending, None);
        } else {
            // Aborted validation drops the unbegun permit without metadata,
            // counters or a fabricated successful body terminal.
            self.terminal = Some(false);
        }
    }

    fn apply(&mut self, pending: Pending, content: Option<&[u8]>) {
        // Reserve terminal application before metadata/audit work: unwinding
        // cannot replay the single-use counter permit.
        self.terminal = Some(false);
        self.terminal = Some(apply(
            &self.provenance,
            self.port,
            pending.prepared,
            content,
            pending
                .encoding
                .as_ref()
                .map(|bytes| bytes.as_slice())
                .map_err(|error| *error),
        ));
    }

    pub(super) fn response_provenance(&self) -> Option<Arc<Provenance>> {
        self.valid_context.then(|| self.provenance.clone())
    }

    pub(super) fn evidence_failed(&self) -> bool {
        self.terminal.unwrap_or(false)
    }
}

fn report_core_error(kind: ContextErrorKind) {
    eprintln!("Test context request hook failed: {kind:?}");
}

fn apply(
    provenance: &Provenance,
    port: u16,
    prepared: PreparedRequest,
    content: Option<&[u8]>,
    encoding: Result<&[u8], ContentError>,
) -> bool {
    let application = match prepared.begin() {
        Ok(application) => application,
        Err(error) => {
            report_core_error(error.kind());
            return error.kind() == ContextErrorKind::Poisoned;
        }
    };
    let failed = match application.result() {
        Ok(RequestOutcome::Applied { applied }) => {
            // Source request_id.request stamps start_time after request EOM,
            // so upload duration is not part of response elapsed time.
            match provenance.apply_request(
                applied.clone(),
                content,
                encoding,
                crate::circuit_runtime::now(),
            ) {
                Ok(failed) => failed,
                Err(error) => {
                    eprintln!("Test context request content failed: {error}");
                    return error == ContentError::Allocation;
                }
            }
        }
        Ok(RequestOutcome::Warn { reason, .. }) => provenance.decision(*reason, false, port),
        Ok(RequestOutcome::Block { reason, .. }) => provenance.decision(*reason, true, port),
        Ok(RequestOutcome::PriorResponse | RequestOutcome::NotTargetHost) => false,
        Err(error) => {
            report_core_error(error.kind());
            return error.kind() == ContextErrorKind::Poisoned;
        }
    };
    // A normal sink write error is swallowed by production submission. Retain
    // the marker separately and commit its source terminal counters.
    match application.finish() {
        Ok(_) => failed,
        Err(error) => {
            report_core_error(error.kind());
            failed || error.kind() == ContextErrorKind::Poisoned
        }
    }
}

#[cfg(test)]
mod tests;
