//! Read retained audit evidence through the shared process writer. Admission
//! belongs here; retention, attribution filtering and freshness belong to it.

use std::sync::Arc;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Decoded, Failure, Outcome, Request, ResponseBody, agent, response};
use crate::{audit, circuits::CircuitValue};

/// Content-free categories distinguish source exceptions from native gaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainFailure {
    Reader(audit::ExplainErrorKind),
    Worker,
    Rendering(crate::circuits::ErrorKind),
}

pub(super) async fn respond(
    request: Request<'_>,
    writer: Option<&Arc<audit::Writer>>,
) -> Outcome<'static> {
    let mut query = super::query(request);
    let Some(Decoded::Scalar(request_id)) = query.remove("request_id") else {
        return invalid_id();
    };
    let request_id = Zeroizing::new(request_id);
    if !super::valid_request_id(&request_id) {
        return invalid_id();
    }
    let Some(agent) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let Some(writer) = writer else {
        let mut outcome = response(
            503,
            json!({"error":"Agent API endpoint unavailable in native development mode"}),
        );
        outcome.failure = Some(Failure::DevelopmentEndpoint);
        return outcome;
    };
    let agent = Zeroizing::new(agent.to_owned());
    let writer = Arc::clone(writer);
    // Blocking file reads/drain never run on Tokio's worker. A canceled caller
    // leaves wiping inputs and serialized output owned by this task until drop.
    let result = tokio::task::spawn_blocking(move || {
        let value = writer
            .explain(&request_id, &agent)
            .map_err(|error| ExplainFailure::Reader(error.kind()))?;
        let document = Document(value);
        document
            .0
            .render_json(false)
            .map(Zeroizing::new)
            .map_err(|error| ExplainFailure::Rendering(error.kind()))
    })
    .await;
    match result {
        Ok(Ok(text)) => {
            let mut outcome = response(200, Value::Null);
            outcome.response.body = ResponseBody::Circuit(text);
            outcome
        }
        Ok(Err(failure)) => failed(request, failure),
        Err(_) => failed(request, ExplainFailure::Worker),
    }
}

struct Document(CircuitValue);
impl Drop for Document {
    fn drop(&mut self) {
        audit::wipe(&mut self.0);
    }
}

fn invalid_id() -> Outcome<'static> {
    response(
        400,
        json!({"error":"Invalid or missing request_id", "usage":"/explain?request_id=req-<32hex>"}),
    )
}

fn failed(request: Request<'_>, failure: ExplainFailure) -> Outcome<'static> {
    let class = match failure {
        ExplainFailure::Reader(audit::ExplainErrorKind::Attribute) => "AttributeError",
        ExplainFailure::Reader(audit::ExplainErrorKind::UnicodeDecode) => "UnicodeDecodeError",
        ExplainFailure::Reader(audit::ExplainErrorKind::Value) => "ValueError",
        ExplainFailure::Reader(audit::ExplainErrorKind::Permission) => "PermissionError",
        ExplainFailure::Reader(audit::ExplainErrorKind::Io) => "OSError",
        ExplainFailure::Reader(audit::ExplainErrorKind::Compatibility)
        | ExplainFailure::Worker
        | ExplainFailure::Rendering(_) => {
            return super::unavailable(request, Failure::ExplainReporting(failure));
        }
    };
    let mut outcome = response(500, json!({"error":format!("Internal error: {class}")}));
    outcome.failure = Some(Failure::ExplainReporting(failure));
    outcome
}
