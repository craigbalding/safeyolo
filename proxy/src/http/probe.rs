//! Local termination after the real request hooks; reserved transport remains
//! independently contained if a request cannot reach that sink.

use std::{io::Write, sync::Arc};

use hyper::{Response, StatusCode, header};
use serde_json::json;

use crate::{
    ConnectionIdentity, Error, Runtime, RuntimeState, audit, circuits::CircuitValue,
    request_trace::RequestTrace,
};

use super::{Body, Destination, flow_recording::Recording, request_context::RequestContext};

pub(super) const HOST: &str = "_safeyolo.probe.internal";

pub(super) fn is_host(host: &str) -> bool {
    host.eq_ignore_ascii_case(HOST)
}

#[derive(Clone)]
pub(super) struct Completed {
    pub(super) capture: Arc<super::test_context::ResponseCapture>,
    pub(super) source_metadata_reached: bool,
}

pub(super) fn response(
    state: RuntimeState,
    context: &RequestContext,
    recording: Arc<Recording>,
    request_id: &str,
) -> Result<Response<Body>, Error> {
    let hook = context
        .trace()
        .and_then(|trace| trace.hook("probe-sink", "request"));
    let body = crate::python_json::encode(&json!({
        "probe_ok":true, "host":HOST, "request_id":request_id
    }));
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len())
        .header("x-safeyolo-request-id", request_id)
        .body(super::full(body.clone()))?;
    let traffic = context.traffic();
    let source_metadata_reached = traffic
        .as_ref()
        .is_some_and(|traffic| traffic.source_metadata_reached());
    let capture = Arc::new(super::test_context::ResponseCapture::new(
        state,
        context.response_provenance(),
        traffic,
        Some(recording),
        context.trace(),
    ));
    capture.local_probe(response.status(), response.headers(), body.as_bytes());
    response.extensions_mut().insert(Completed {
        capture,
        source_metadata_reached,
    });
    if let Some(hook) = hook {
        hook.evaluated("probe_terminated", Some(json!({"host":HOST}).into()));
    }
    Ok(response)
}

/// Observe an existing reply only after its completed request logger/metrics
/// hooks. The response and the earlier guard's decision remain unchanged.
pub(super) fn preempted(trace: Option<&Arc<RequestTrace>>, blocked_by: Option<&CircuitValue>) {
    if let Some(hook) = trace.and_then(|trace| trace.hook("probe-sink", "request")) {
        hook.evaluated(
            "probe_preempted",
            Some(CircuitValue::Object(
                std::iter::once((
                    "preempted_by".into(),
                    blocked_by
                        .cloned()
                        .unwrap_or_else(|| serde_json::Value::Null.into()),
                ))
                .collect(),
            )),
        );
    }
}

#[derive(Debug)]
pub(super) struct TransportRefused;

impl std::fmt::Display for TransportRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "SafeYolo: reserved pipeline-probe host must never egress ({HOST})"
        )
    }
}
impl std::error::Error for TransportRefused {}

/// The caller returns this refusal before DNS or socket creation. Observation
/// failures cannot turn the returned error into a transport permission.
pub(super) fn refuse_transport(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    destination: &Destination,
) -> Error {
    let mut event = audit::Event::new(
        "security.probe_reached_upstream",
        audit::Kind::Security,
        audit::Severity::Critical,
        format!("Probe host reached upstream connect stage — sink failed for {HOST}"),
    );
    event.decision = Some(audit::Decision::Deny);
    event.addon = Some("transport-guard".into());
    event.host = Some(HOST.into());
    event.agent = Some(identity.agent_id.clone());
    event.details = json!({
        "reason_code":"probe_reached_upstream", "client_ip":identity.source_id,
        "server_address":[destination.host, destination.port], "sni":null
    })
    .into();
    if runtime.audit.emit(event).is_err() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "Probe transport-refusal audit failed"
        );
    }
    TransportRefused.into()
}

#[cfg(test)]
mod tests;
