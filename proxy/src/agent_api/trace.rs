//! Agent-owned reads of the process's opt-in request traces.

use serde_json::json;
use zeroize::Zeroizing;

use super::{Decoded, Failure, Outcome, Request, TraceContext, agent, response};

pub(super) fn respond(request: Request<'_>, context: Option<TraceContext<'_>>) -> Outcome<'static> {
    let mut query = super::query(request);
    let Some(Decoded::Scalar(request_id)) = query.remove("request_id") else {
        return invalid_id();
    };
    let request_id = Zeroizing::new(request_id);
    if !super::valid_request_id(&request_id) {
        return invalid_id();
    }
    let Some(owner) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let Some(context) = context else {
        let mut outcome = response(
            503,
            json!({"error":"Agent API endpoint unavailable in native development mode"}),
        );
        outcome.failure = Some(Failure::DevelopmentEndpoint);
        return outcome;
    };
    match context.store.get(&request_id, Some(owner), (context.now)()) {
        Ok(Some(record)) => response(200, record),
        Ok(None) => response(
            404,
            json!({"error":"No trace for request_id", "request_id":request_id.as_str()}),
        ),
        Err(error) => {
            use crate::trace::ErrorKind;
            let class = match error.kind() {
                ErrorKind::Type => "TypeError",
                ErrorKind::Attribute => "AttributeError",
                ErrorKind::Overflow => "OverflowError",
                ErrorKind::Index => "IndexError",
                ErrorKind::StopIteration => "StopIteration",
                ErrorKind::Poisoned | ErrorKind::Compatibility => {
                    return super::unavailable(request, Failure::TraceReporting(error.kind()));
                }
            };
            let mut outcome = response(500, json!({"error":format!("Internal error: {class}")}));
            outcome.failure = Some(Failure::TraceReporting(error.kind()));
            outcome
        }
    }
}

fn invalid_id() -> Outcome<'static> {
    response(
        400,
        json!({"error":"Invalid or missing request_id", "usage":"/trace?request_id=req-<32hex>"}),
    )
}
