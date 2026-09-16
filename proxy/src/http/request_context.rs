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
    request_trace::{RequestTrace, TraceHook},
    test_context::{self, ContextErrorKind, PreparedRequest, RequestOutcome, TrustedIdentity},
};

use super::test_context::{Provenance, combined};

pub(super) enum Admission {
    Inactive,
    HookError,
    Block(Response<super::Body>),
    Pending(RequestContext),
}

pub(super) enum Observer {
    Http1(hyper::ext::RequestCompletion),
    Http2(h2::ext::RequestCompletion),
}

impl Observer {
    pub(super) fn take<B>(request: &mut Request<B>) -> Result<Self, Error> {
        if let Some(observer) = hyper::ext::take_request_completion(request) {
            Ok(Self::Http1(observer))
        } else if let Some(observer) = h2::ext::take_request_completion(request) {
            Ok(Self::Http2(observer))
        } else {
            Err("request completion observer unavailable".into())
        }
    }

    pub(super) fn try_result(&mut self) -> Option<Result<(), ()>> {
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
    prepared: Option<PreparedRequest>,
    encoding: Result<Zeroizing<Vec<u8>>, ContentError>,
}

pub(super) struct RequestContext {
    pending: Option<Pending>,
    terminal: Option<bool>,
    provenance: Option<Arc<Provenance>>,
    traffic: Option<Arc<super::traffic::Traffic>>,
    live: Option<Arc<crate::traffic_view::Exchange>>,
    skip_logger: bool,
    port: u16,
    valid_context: bool,
    trace: Option<Arc<RequestTrace>>,
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
    trace: Option<Arc<RequestTrace>>,
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
    let head_hook = trace
        .as_ref()
        .and_then(|trace| trace.hook("test-context", "request"));
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
            trace_core_error(head_hook.as_ref(), error.kind());
            report_core_error(error.kind());
            return Ok(Admission::HookError);
        }
    };
    let provenance = Arc::new(Provenance::new(
        runtime,
        identity.clone(),
        request_id.to_owned(),
        request.method().to_string(),
        destination.policy_host.clone(),
        destination.path.clone(),
    ));
    if let Ok(RequestOutcome::Block { status, body, .. }) = prepared.result() {
        let status = *status;
        let body = body.clone();
        let failed = match apply(
            &provenance,
            destination.port,
            prepared,
            None,
            Ok(&[]),
            crate::circuit_runtime::now(),
            head_hook.as_ref(),
        ) {
            Ok(failed) => failed,
            Err(_) => return Ok(Admission::HookError),
        };
        let bytes = crate::network_guard::Response {
            status,
            headers: Vec::new(),
            body,
        }
        .body_bytes();
        let mut response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-blocked-by", "test-context")
            .body(super::full(bytes))?;
        if failed {
            response
                .headers_mut()
                .insert("x-safeyolo-evidence-error", "true".parse()?);
        }
        if let Some(hook) = &head_hook {
            hook.evaluated("blocked", Some(serde_json::json!({"status":status}).into()));
        }
        return Ok(Admission::Block(super::prior_block(response)));
    }
    let valid_context = matches!(prepared.result(), Ok(RequestOutcome::Applied { .. }));
    let observer = Observer::take(request)?;
    let encoding = combined(request.headers(), header::CONTENT_ENCODING);
    Ok(Admission::Pending(RequestContext {
        pending: Some(Pending {
            observer,
            prepared: Some(prepared),
            encoding,
        }),
        terminal: None,
        provenance: Some(provenance),
        traffic: None,
        live: None,
        skip_logger: false,
        port: destination.port,
        valid_context,
        trace,
    }))
}

impl RequestContext {
    /// Ordinary HTTP shares the same buffering and independent EOM owner.
    pub(super) fn traffic_only<B>(
        request: &mut Request<B>,
        skip_logger: bool,
        trace: Option<Arc<RequestTrace>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            pending: Some(Pending {
                observer: Observer::take(request)?,
                prepared: None,
                encoding: combined(request.headers(), header::CONTENT_ENCODING),
            }),
            terminal: None,
            provenance: None,
            traffic: None,
            live: None,
            skip_logger,
            port: 0,
            valid_context: false,
            trace,
        })
    }

    pub(super) fn attach_traffic(&mut self, traffic: Arc<super::traffic::Traffic>) {
        self.traffic = Some(traffic);
    }

    pub(super) fn attach_live(&mut self, live: Option<Arc<crate::traffic_view::Exchange>>) {
        if let Some(provenance) = &self.provenance {
            provenance.attach_live(live.clone());
        }
        self.live = live;
    }

    pub(super) fn live(&self) -> Option<Arc<crate::traffic_view::Exchange>> {
        self.live.clone()
    }

    pub(super) fn traffic(&self) -> Option<Arc<super::traffic::Traffic>> {
        self.traffic.clone()
    }

    pub(super) fn trace(&self) -> Option<Arc<RequestTrace>> {
        self.trace.clone()
    }

    /// Small buffered requests must cross the independent parser barrier before
    /// the caller may dial. Streamed bodies retain their still-pending permit.
    pub(super) async fn buffer(
        mut self,
        body: Incoming,
        content_length: Option<u64>,
    ) -> Result<(super::Body, Self), Error> {
        let prepared = super::request_body::prepare(body, content_length, false).await?;
        if let Some(content) = prepared.unvalidated_content {
            self.apply_buffered(&content).await?;
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

    /// A local probe can reach its sink only through the source-buffered path.
    /// Streaming selects transport before the source request hook, so return
    /// None without applying context or consuming the remaining upload.
    pub(super) async fn buffer_probe(
        mut self,
        body: Incoming,
        content_length: Option<u64>,
    ) -> Result<Option<Self>, Error> {
        let prepared = super::request_body::prepare(body, content_length, false).await?;
        let Some(content) = prepared.unvalidated_content else {
            return Ok(None);
        };
        self.apply_buffered(&content).await?;
        Ok(Some(self))
    }

    async fn apply_buffered(&mut self, content: &[u8]) -> Result<(), Error> {
        if let Some(mut pending) = self.pending.take() {
            if (&mut pending.observer).await.is_err() {
                return Err("request completion aborted".into());
            }
            self.apply(pending, Some(content));
        }
        Ok(())
    }

    pub(super) fn request_hooks_completed(&self) -> bool {
        self.terminal.is_some()
            && !self.skip_logger
            && self
                .traffic
                .as_ref()
                .is_some_and(|traffic| traffic.request_hooks_completed())
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
        self.terminal = Some(false);
        if let Some(live) = &self.live {
            // This method is reached only after the existing parser barrier.
            // Retain encoded source-buffered bytes without another decode.
            live.request_body(content);
        }
        if let Some(traffic) = &self.traffic {
            // Memory failures retain partial accounting but must not abandon
            // existing security hooks, as source container exceptions can.
            traffic.memory_request(content);
        }
        let started = self
            .traffic
            .as_ref()
            .map_or_else(crate::circuit_runtime::now, |traffic| {
                traffic.begin_request()
            });
        let encoding = pending
            .encoding
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .map_err(|error| *error);
        let outcome = match (pending.prepared, self.provenance.as_deref()) {
            (Some(prepared), Some(provenance)) => {
                // Measure the reached application, not the pending upload interval.
                let hook = self
                    .trace
                    .as_ref()
                    .and_then(|trace| trace.hook("test-context", "request"));
                apply(
                    provenance,
                    self.port,
                    prepared,
                    content,
                    encoding,
                    started,
                    hook.as_ref(),
                )
            }
            _ => Ok(false),
        };
        let mut failed = outcome.unwrap_or_else(|failed| failed);
        self.skip_logger |= outcome.is_err();
        if outcome.is_ok()
            && !self.skip_logger
            && let Some(traffic) = &self.traffic
        {
            failed |= traffic.request(|| super::traffic::decoded_size(content, encoding));
        }
        self.terminal = Some(failed);
    }

    pub(super) fn response_provenance(&self) -> Option<Arc<Provenance>> {
        self.provenance.clone().filter(|_| self.valid_context)
    }

    pub(super) fn evidence_failed(&self) -> bool {
        self.terminal.unwrap_or(false)
    }
}

fn report_core_error(kind: ContextErrorKind) {
    eprintln!("Test context request hook failed: {kind:?}");
}

fn trace_core_error(hook: Option<&TraceHook>, kind: ContextErrorKind) {
    if let Some(hook) = hook {
        hook.error(match kind {
            ContextErrorKind::Value => "ValueError",
            ContextErrorKind::Overflow => "OverflowError",
            ContextErrorKind::Type => "TypeError",
            ContextErrorKind::Attribute => "AttributeError",
            ContextErrorKind::Poisoned => "ContextPoisoned",
        });
    }
}

fn apply(
    provenance: &Provenance,
    port: u16,
    prepared: PreparedRequest,
    content: Option<&[u8]>,
    encoding: Result<&[u8], ContentError>,
    started: f64,
    hook: Option<&TraceHook>,
) -> Result<bool, bool> {
    let application = match prepared.begin() {
        Ok(application) => application,
        Err(error) => {
            trace_core_error(hook, error.kind());
            report_core_error(error.kind());
            return Err(error.kind() == ContextErrorKind::Poisoned);
        }
    };
    let submitted = match application.result() {
        Ok(RequestOutcome::Applied { applied }) => {
            // Source request_id.request stamps start_time after request EOM,
            // so upload duration is not part of response elapsed time.
            provenance.apply_request(applied.clone(), content, encoding, started)
        }
        Ok(RequestOutcome::Warn { reason, .. }) => provenance.decision(*reason, false, port),
        Ok(RequestOutcome::Block { reason, .. }) => provenance.decision(*reason, true, port),
        Ok(RequestOutcome::PriorResponse | RequestOutcome::NotTargetHost) => Ok(false),
        Err(error) => {
            trace_core_error(hook, error.kind());
            report_core_error(error.kind());
            return Err(error.kind() == ContextErrorKind::Poisoned);
        }
    };
    let failed = match submitted {
        Ok(failed) => failed,
        Err(error) => {
            if let Some(hook) = hook {
                hook.error(error.trace_reason());
            }
            eprintln!("Test context request hook failed: {error}");
            return Err(error.evidence_failed());
        }
    };
    // Canonical submission succeeded. An asynchronous writer sink failure does
    // not undo terminal counters; a separate diagnostic failure only marks evidence.
    match application.finish() {
        Ok(outcome) => {
            if let Some(hook) = hook {
                match outcome {
                    RequestOutcome::Applied { applied } => hook.evaluated(
                        "allowed",
                        Some(serde_json::json!({"context_source":applied.source}).into()),
                    ),
                    RequestOutcome::Warn { .. } => hook.evaluated("warned", None),
                    RequestOutcome::NotTargetHost => hook.evaluated("not_target_host", None),
                    RequestOutcome::PriorResponse => hook.bypassed("prior_response"),
                    // The caller must construct the actual reply first.
                    RequestOutcome::Block { .. } => {}
                }
            }
            Ok(failed)
        }
        Err(error) => {
            trace_core_error(hook, error.kind());
            report_core_error(error.kind());
            Err(failed || error.kind() == ContextErrorKind::Poisoned)
        }
    }
}

#[cfg(test)]
mod tests;
