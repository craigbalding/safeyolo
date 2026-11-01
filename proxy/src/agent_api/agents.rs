//! Listener reports after the existing method and bearer checks.

use super::{AgentReportContext, Failure, Outcome, Request, ResponseBody, response};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub(super) fn respond(
    request: Request<'_>,
    context: Option<AgentReportContext<'_>>,
) -> Outcome<'static> {
    let Some(context) = context else {
        return response(503, json!({"error":"agent listener report unavailable"}));
    };
    let document = context
        .activity
        .report(context.listeners, crate::circuit_runtime::now());
    let Ok(mut document) = document else {
        return super::unavailable(request, Failure::AgentReporting);
    };
    let body = document.render_json(false).map(Zeroizing::new);
    crate::audit::wipe(&mut document);
    match body {
        Ok(body) => {
            let mut outcome = response(200, Value::Null);
            outcome.response.body = ResponseBody::Circuit(body);
            outcome
        }
        Err(_) => super::unavailable(request, Failure::AgentReporting),
    }
}
