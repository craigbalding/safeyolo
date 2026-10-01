//! Read the calling agent's bindings and the remaining accepted service catalog.

use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::{
    AuditApproval, AuditIntent, AuditKind, Failure, Outcome, Request, ResponseBody, agent, response,
};
use crate::{
    contracts::ContractTemplate,
    services::{GatewaySnapshot, ServiceViewError},
};

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
/// and body decoding. Catalog lookup is read-only. Contract capabilities return
/// the same binding challenge as the source; simple capabilities retain the
/// existing approval event.
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

    if let Some(contract) = &capability.contract {
        return contract_challenge(service_name, capability_name, contract);
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

fn contract_challenge(
    service: &str,
    capability: &str,
    contract: &ContractTemplate,
) -> Outcome<'static> {
    if !contract.is_grantable() {
        return response(
            200,
            json!({
                "decision":"contract_not_enforceable",
                "service":service,
                "capability":capability,
                "missing_tiers": ["request_shape"],
            }),
        );
    }
    let mut bindings = Map::new();
    for (name, definition) in &contract.bindings {
        let mut info = Map::new();
        if let Some(object) = definition.as_object() {
            for key in [
                "source",
                "type",
                "visible_to_operator",
                "options",
                "pattern",
                "required_if",
            ] {
                if let Some(value) = object.get(key) {
                    info.insert(key.into(), value.clone());
                }
            }
        }
        if !info.contains_key("type") {
            info.insert("type".into(), Value::String("string".into()));
        }
        bindings.insert(name.clone(), Value::Object(info));
    }
    let grantable_operations: Vec<Value> = contract
        .grantable_operations()
        .map(|operation| {
            json!({
                "name":operation.name,
                "method":operation.request.method,
                "path":operation.request.path,
            })
        })
        .collect();
    response(
        200,
        json!({
            "decision":"needs_contract_binding",
            "service":service,
            "capability":capability,
            "template":contract.template,
            "bindings":bindings,
            "grantable_operations":grantable_operations,
        }),
    )
}

/// Validate and submit a contract binding challenge. The request remains an
/// approval intent; only the existing operator consumer can persist it.
pub(super) fn submit_binding(
    request: Request<'_>,
    context: Option<GatewayContext<'_>>,
    body: &[u8],
) -> Outcome<'static> {
    let text = match crate::python_json::decode_json_text(body) {
        Ok(text) => text,
        Err(_) => return response(400, json!({"error":"Invalid JSON body"})),
    };
    let parsed = match crate::policy::parse_json(&text, true) {
        Ok(value) => value,
        Err(_) => return response(400, json!({"error":"Invalid JSON body"})),
    };
    let Some(fields) = parsed.as_object() else {
        return response(400, json!({"error":"Invalid JSON body"}));
    };
    let Some(service_name) = fields
        .get("service")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    else {
        return response(400, json!({"error":"service and capability are required"}));
    };
    let Some(capability_name) = fields
        .get("capability")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    else {
        return response(400, json!({"error":"service and capability are required"}));
    };
    let Some(bindings) = fields
        .get("bindings")
        .and_then(Value::as_object)
        .filter(|v| !v.is_empty())
    else {
        return response(400, json!({"error":"bindings must be a non-empty object"}));
    };
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
            json!({"error":format!("Capability '{capability_name}' not found")}),
        );
    };
    let Some(contract) = capability.contract.as_ref() else {
        return response(
            400,
            json!({"error":format!("Capability '{capability_name}' has no contract")}),
        );
    };
    if !contract.is_grantable() {
        return response(
            200,
            json!({"decision":"contract_not_enforceable","missing_tiers":["request_shape"]}),
        );
    }
    let mut errors = Vec::new();
    for (name, definition) in &contract.bindings {
        let object = definition.as_object();
        let kind = object
            .and_then(|o| o.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("string");
        let value = bindings.get(name);
        let required = object
            .and_then(|o| o.get("required_if"))
            .and_then(Value::as_object)
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .all(|(key, expected)| bindings.get(key) == Some(expected))
            });
        if required && value.is_none_or(Value::is_null) {
            errors.push(format!("'{name}' is required"));
            continue;
        }
        let Some(value) = value else { continue };
        let valid = match kind {
            "enum" => object
                .and_then(|o| o.get("options"))
                .and_then(Value::as_array)
                .is_some_and(|options| options.iter().any(|candidate| candidate == value)),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "string_list" => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            _ => value.is_string(),
        };
        if !valid {
            errors.push(format!("'{name}' has invalid type or value"));
        }
        if kind == "string"
            && let Some(pattern) = object
                .and_then(|o| o.get("pattern"))
                .and_then(Value::as_str)
            && let Some(value) = value.as_str()
            && regex::Regex::new(pattern).is_ok_and(|regex| !regex.is_match(value))
        {
            errors.push(format!("'{name}' does not match pattern"));
        }
    }
    for name in bindings.keys() {
        if !contract.bindings.contains_key(name) {
            errors.push(format!("Unknown binding variable '{name}'"));
        }
    }
    for operation in contract.grantable_operations() {
        for name in operation.bound_value_references() {
            if bindings.get(name).is_none_or(Value::is_null) {
                errors.push(format!(
                    "'{name}' is required by operation '{}'",
                    operation.name
                ));
            }
        }
    }
    if !errors.is_empty() {
        return response(
            200,
            json!({"decision":"denied_out_of_scope","errors":errors}),
        );
    }
    let grantable_operations: Vec<String> = contract
        .grantable_operations()
        .map(|operation| operation.name.clone())
        .collect();
    let reason = fields
        .get("purpose_code")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut outcome = response(
        202,
        json!({
            "status":"pending",
            "agent":agent_name,
            "service":service_name,
            "capability":capability_name,
            "bindings":bindings,
            "message":"Contract binding submitted. Operator will review in watch.",
        }),
    );
    outcome.audit = Some(AuditIntent {
        kind: AuditKind::GatewayBindingSubmitted,
        event: "gateway.submit_binding",
        severity: "critical",
        addon: "agent-api",
        summary: format!(
            "{agent_name} submits contract binding for {service_name}/{capability_name}"
        ),
        agent: Some(agent_name.to_owned()),
        request_id: None,
        host: Some(service.default_host.clone()),
        details: json!({"purpose_code":reason,"binding_fields":bindings.keys().collect::<Vec<_>>()}),
        approval: Some(AuditApproval {
            required: true,
            approval_type: crate::audit::ApprovalType::ContractBinding,
            key: format!("{agent_name}:{service_name}:{capability_name}"),
            target: service_name.to_owned(),
            scope_hint: json!({
                "service":service_name,
                "capability":capability_name,
                "template":contract.template,
                "bindings":bindings,
                "grantable_operations":grantable_operations,
            }),
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
