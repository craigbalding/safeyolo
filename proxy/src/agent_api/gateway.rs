//! Read the calling agent's bindings and the remaining accepted service catalog.

use indexmap::IndexMap;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    AuditApproval, AuditIntent, AuditKind, Failure, Outcome, Request, ResponseBody, agent, response,
};
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

/// Handle the source AgentAPI request-access operation after authentication
/// and body decoding. Catalog lookup is read-only. The simple no-contract branch
/// returns an audit intent for the existing writer to submit; contract workflows
/// remain an explicit compatibility response until their owner lands.
pub(super) fn request_access(
    request: Request<'_>,
    context: Option<GatewayContext<'_>>,
    body: &[u8],
) -> Outcome<'static> {
    let text = match crate::python_json::decode_json_text(body) {
        Ok(text) => text,
        Err(_) => return response(400, json!({"error":"Invalid JSON body"})),
    };
    let parsed = if text.is_empty() {
        crate::circuits::CircuitValue::Object(IndexMap::new())
    } else {
        match crate::circuits::CircuitValue::parse_api_json(&text) {
            Ok(value) => value,
            Err(_) => return response(400, json!({"error":"Invalid JSON body"})),
        }
    };
    let Some(fields) = parsed.as_object() else {
        return response(400, json!({"error":"Invalid JSON body"}));
    };
    let Some(service_name) = required_text(fields, "service") else {
        return response(400, json!({"error":"service and capability are required"}));
    };
    let Some(capability_name) = required_text(fields, "capability") else {
        return response(400, json!({"error":"service and capability are required"}));
    };
    let reason = optional_text(fields, "reason").unwrap_or_default();
    let Some(agent_name) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let Some(context) = context else {
        return response(503, json!({"error":"Service registry not available"}));
    };
    let Some(snapshot) = context.snapshot else {
        return response(503, json!({"error":"Service registry not available"}));
    };
    let Some(registry) = snapshot.registry() else {
        return response(503, json!({"error":"Service registry not available"}));
    };
    let Some(service) = registry.services.get(service_name) else {
        return response(
            404,
            json!({"error":format!("Service '{service_name}' not found")}),
        );
    };
    let Some(capability) = service.capabilities.get(capability_name) else {
        return response(
            404,
            json!({"error":format!(
                "Capability '{capability_name}' not found in service '{service_name}'"
            )}),
        );
    };

    if capability.contract.is_some() {
        return response(
            503,
            json!({"error":"contract workflow is outside the simple-service path"}),
        );
    }
    let description = service
        .raw
        .get("description")
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let capability_description = service
        .raw
        .get("capabilities")
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get(capability_name))
        .and_then(Value::as_object)
        .and_then(|capability| capability.get("description"))
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let scope_hint = json!({
        "service":service_name,
        "capability":capability_name,
        "description":description,
        "capability_description":capability_description,
        "reason":reason,
        "proposed_lifetime":"session",
    });
    let summary = if reason.is_empty() {
        format!("{agent_name} requests {service_name}/{capability_name}")
    } else {
        format!("{agent_name} requests {service_name}/{capability_name}: {reason}")
    };
    let mut outcome = response(
        202,
        json!({
            "status":"pending",
            "agent":agent_name,
            "service":service_name,
            "capability":capability_name,
            "reason":reason,
            "message":"Access request submitted. Operator will review in watch.",
        }),
    );
    outcome.audit = Some(AuditIntent {
        kind: AuditKind::GatewayAccessRequested,
        event: "gateway.request_access",
        severity: "critical",
        addon: "agent-api",
        summary,
        agent: Some(agent_name.to_owned()),
        // The source handler does not pass its flow request ID to write_event;
        // keep this approval envelope free of native-only correlation metadata.
        request_id: None,
        host: Some(service.default_host.clone()),
        details: Value::Object(serde_json::Map::new()),
        approval: Some(AuditApproval {
            required: true,
            approval_type: crate::audit::ApprovalType::Service,
            key: format!("{agent_name}:{service_name}"),
            target: service_name.to_owned(),
            scope_hint,
        }),
    });
    outcome
}

fn required_text<'a>(
    fields: &'a IndexMap<String, crate::circuits::CircuitValue>,
    name: &str,
) -> Option<&'a str> {
    optional_text(fields, name).filter(|value| !value.is_empty())
}

fn optional_text<'a>(
    fields: &'a IndexMap<String, crate::circuits::CircuitValue>,
    name: &str,
) -> Option<&'a str> {
    match fields.get(name) {
        Some(crate::circuits::CircuitValue::Other(Value::String(value))) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
