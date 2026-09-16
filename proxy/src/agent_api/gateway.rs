//! Read the calling agent's bindings and the remaining accepted service catalog.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Failure, Outcome, Request, ResponseBody, agent, response};
use crate::services::{GatewaySnapshot, ServiceViewError};

/// The installed read owner borrows the catalog/policy publication. An absent
/// snapshot means no catalog was configured; canonical policy tokens alone do
/// not establish live service bindings. This owner does not enable injection.
pub struct GatewayContext<'a> {
    pub snapshot: Option<&'a GatewaySnapshot>,
}

pub(super) fn respond(
    request: Request<'_>,
    context: Option<GatewayContext<'_>>,
) -> Outcome<'static> {
    let Some(owner) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let Some(context) = context else {
        return response(503, json!({"error":"service-gateway addon not loaded"}));
    };
    let Some(snapshot) = context.snapshot else {
        return response(200, json!({"agent":owner,"authorized":{},"available":[]}));
    };
    let authorized = match snapshot.agent_services_json(owner) {
        Ok(authorized) => authorized,
        Err(kind) => {
            return match kind {
                ServiceViewError::Type => {
                    let mut outcome = response(500, json!({"error":"Internal error: TypeError"}));
                    outcome.failure = Some(Failure::GatewayReporting(kind));
                    outcome
                }
                ServiceViewError::Compatibility => {
                    super::unavailable(request, Failure::GatewayReporting(kind))
                }
            };
        }
    };
    let available = snapshot.available_services(owner);
    // Keep the source JSON projection encoded. Decoding it again would lose
    // accepted numeric spellings, add a nesting limit and copy secret tokens.
    let owner = Value::from(owner);
    let capacity = [
        "{\"agent\": , \"authorized\": , \"available\": }".len(),
        crate::python_json::encoded_len(&owner),
        authorized.expose_secret().len(),
        crate::python_json::encoded_len(&available),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .expect("JSON response length overflow");
    let mut body = Zeroizing::new(String::with_capacity(capacity));
    body.push_str("{\"agent\": ");
    crate::python_json::write(&owner, &mut *body).expect("String writes cannot fail");
    body.push_str(", \"authorized\": ");
    body.push_str(authorized.expose_secret());
    body.push_str(", \"available\": ");
    crate::python_json::write(&available, &mut *body).expect("String writes cannot fail");
    body.push('}');
    let mut outcome = response(200, Value::Null);
    outcome.response.body = ResponseBody::Circuit(body);
    outcome
}

#[cfg(test)]
mod tests;
