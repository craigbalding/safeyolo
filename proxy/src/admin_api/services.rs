//! Persist operator-selected service bindings in the configured policy.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use hyper::{Request, StatusCode, body::Body};
use serde_json::{Value, json};
use toml_edit::{InlineTable, Item, Table};
use zeroize::Zeroizing;

use super::{Audit, Error, Json, Outcome, ParsedBody, Policy, read_json, response, truthy};

/// Audit ownership after persistence. Credential is a vault entry name, not a
/// fetched secret. No diagnostic formatter exposes request or policy fields.
pub struct Authorization {
    pub(super) agent: Zeroizing<String>,
    pub(super) service: Zeroizing<String>,
    pub(super) capability: Zeroizing<String>,
    pub(super) credential: Zeroizing<String>,
}

pub(super) fn agent_path(path: &str) -> Option<&str> {
    let agent = path
        .strip_prefix("/admin/agents/")?
        .strip_suffix("/services")?;
    (!agent.is_empty() && !agent.contains('/')).then_some(agent)
}

pub(super) async fn authorize<B: Body<Data = Bytes>>(
    request: Request<B>,
    agent: String,
    policy: Option<&Policy>,
    policy_path: Option<&Path>,
    audit: Option<super::ServiceAudit<'_>>,
) -> Result<Outcome, Error> {
    let data = match read_json(request).await? {
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => Json(Value::Null),
        ParsedBody::Value(data) => data,
    };
    if !truthy(&data.0) {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing request body"}),
        ));
    }
    let fields = data.0.as_object().ok_or(Error::NonObjectBody)?;
    if ["service", "capability", "credential"]
        .iter()
        .any(|field| !fields.get(*field).is_some_and(truthy))
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing required fields: service, capability, credential"}),
        ));
    }
    // Current clients send string names. Other truthy source values are a
    // representation failure, not a new permission or a persisted coercion.
    let text = |field| {
        fields
            .get(field)
            .and_then(Value::as_str)
            .ok_or(Error::ServiceRepresentation)
    };
    let service = text("service")?;
    let capability = text("capability")?;
    let credential = text("credential")?;
    let Some(registry) = policy
        .and_then(Policy::gateway)
        .and_then(crate::services::GatewaySnapshot::registry)
    else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service registry is not available"}),
        ));
    };
    let Some(definition) = registry.services.get(service) else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":format!("service '{service}' is not loaded by the running gateway")}),
        ));
    };
    if !definition.capabilities.contains_key(capability) {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":format!("capability '{capability}' is not loaded for service '{service}'")}),
        ));
    }
    let Some(path) = policy_path else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"Policy path not available"}),
        ));
    };
    let Some(audit) = audit else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"Operator audit unavailable"}),
        ));
    };
    let writer = audit.writer.clone();
    let mutation_owner = audit.mutation_owner.clone();
    let client_ip = Zeroizing::new(audit.client_ip.to_owned());
    let target = Zeroizing::new(audit.target.to_owned());
    let authorization = Authorization {
        agent: Zeroizing::new(agent),
        service: Zeroizing::new(service.to_owned()),
        capability: Zeroizing::new(capability.to_owned()),
        credential: Zeroizing::new(credential.to_owned()),
    };
    let path = path.to_owned();
    // Request cancellation drops only this receiver. The process owner retains
    // the worker and its audit attempt until graceful shutdown joins it.
    let result = mutation_owner
        .spawn_blocking(move || {
            let outcome = persist(path, authorization)?;
            let mut outcome = outcome.submit_audit(&writer, &client_ip, &target)?;
            // The listener still submits intents for other routes; this one has
            // already reached its canonical submission owner.
            outcome.audit = None;
            Ok(outcome)
        })
        .await?
        .await
        .map_err(|_| Error::ServiceMutation)?;
    result
}

fn persist(path: PathBuf, authorization: Authorization) -> Result<Outcome, Error> {
    let mut missing_agent = false;
    let mut invalid_shape = false;
    let result = crate::approvals::update_policy(
        &path,
        false,
        |document| {
            let Some(agents) = document.get_mut("agents") else {
                missing_agent = true;
                return Err(mutation_error());
            };
            let Some(agents) = agents.as_table_like_mut() else {
                invalid_shape = true;
                return Err(mutation_error());
            };
            let Some(agent) = agents.get_mut(&authorization.agent) else {
                missing_agent = true;
                return Err(mutation_error());
            };
            let Some(agent) = agent.as_table_like_mut() else {
                invalid_shape = true;
                return Err(mutation_error());
            };
            if !agent.contains_key("services") {
                agent.insert("services", Item::Table(Table::new()));
            }
            let Some(services) = agent.get_mut("services").and_then(Item::as_table_like_mut) else {
                invalid_shape = true;
                return Err(mutation_error());
            };
            let mut binding = InlineTable::new();
            binding.insert(
                "capability",
                toml_edit::Value::from(authorization.capability.as_str()),
            );
            binding.insert(
                "token",
                toml_edit::Value::from(authorization.credential.as_str()),
            );
            services.insert(
                &authorization.service,
                Item::Value(toml_edit::Value::InlineTable(binding)),
            );
            Ok(())
        },
        |_| Ok(()),
    );
    if missing_agent {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":format!("agent '{}' not found", authorization.agent.as_str())}),
        ));
    }
    if invalid_shape {
        return Err(Error::ServiceRepresentation);
    }
    result.map_err(|_| Error::ServiceMutation)?;
    let mut outcome = response(
        StatusCode::OK,
        json!({
            "status":"authorized", "agent":authorization.agent.as_str(),
            "service":authorization.service.as_str(), "capability":authorization.capability.as_str(),
        }),
    );
    outcome.audit = Some(Audit::ServiceAuthorized(authorization));
    Ok(outcome)
}

fn mutation_error() -> crate::approvals::ApprovalError {
    crate::approvals::ApprovalError {
        kind: crate::approvals::ErrorKind::Invalid,
        message: "service policy update unavailable".into(),
    }
}

#[cfg(test)]
mod tests;
