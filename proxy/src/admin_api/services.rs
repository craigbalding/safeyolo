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

/// Audit ownership after a service binding is removed. The credential is the
/// vault entry name from policy, never the vault value.
pub struct Revocation {
    pub(super) agent: Zeroizing<String>,
    pub(super) service: Zeroizing<String>,
    pub(super) credential: Zeroizing<String>,
}

pub(super) fn decode_name(segment: &str) -> Result<String, Error> {
    percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .map(|name| name.into_owned())
        .map_err(|_| Error::ServiceRepresentation)
}

pub(super) fn agent_path(path: &str) -> Option<&str> {
    let agent = path
        .strip_prefix("/admin/agents/")?
        .strip_suffix("/services")?;
    (!agent.is_empty() && !agent.contains('/')).then_some(agent)
}

pub(super) fn revocation_path(path: &str) -> Option<(&str, &str)> {
    let mut segments = path.strip_prefix("/admin/agents/")?.split('/');
    let agent = segments.next().filter(|value| !value.is_empty())?;
    if segments.next()? != "services" {
        return None;
    }
    let service = segments.next().filter(|value| !value.is_empty())?;
    segments.next().is_none().then_some((agent, service))
}

pub(super) fn catalogue(policy: Option<&Policy>) -> Result<Outcome, Error> {
    let Some(registry) = policy
        .and_then(Policy::gateway)
        .and_then(crate::services::GatewaySnapshot::registry)
    else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service catalogue is unavailable"}),
        ));
    };
    let services = registry.services.iter().map(|(name, definition)| {
        json!({"definition":definition.raw,"source":registry.source_by_service.get(name)})
    }).collect::<Vec<_>>();
    Ok(response(StatusCode::OK, json!({"services":services})))
}

pub(super) fn authorized(policy: Option<&Policy>, agent: &str) -> Result<Outcome, Error> {
    let Some(gateway) = policy.and_then(Policy::gateway) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"service catalogue is unavailable"}),
        ));
    };
    let encoded = gateway
        .agent_services_json(agent)
        .map_err(|_| Error::ServiceRepresentation)?;
    let mut services: Value =
        serde_json::from_str(encoded.expose_secret()).map_err(|_| Error::ServiceRepresentation)?;
    if let Some(entries) = services.as_object_mut() {
        for (name, service) in entries {
            // Use the accepted token binding and compiled routes, not a second
            // catalogue load or the possibly newer saved policy file.
            let credential = service["token"]
                .as_str()
                .and_then(|token| gateway.canonical_gateway()["token_map"].get(token))
                .and_then(|binding| binding.get("token"))
                .cloned()
                .unwrap_or(Value::Null);
            service["credential"] = credential;
            service["routes"] = json!(
                gateway
                    .compiled_routes()
                    .iter()
                    .filter(|route| route.agent == agent && route.service == *name)
                    .map(|route| json!({"methods":route.methods,"path":route.path}))
                    .collect::<Vec<_>>()
            );
        }
    }
    Ok(response(
        StatusCode::OK,
        json!({"agent":agent,"services":services}),
    ))
}

pub(super) async fn authorize<B: Body<Data = Bytes>>(
    request: Request<B>,
    agent: String,
    policy: Option<&Policy>,
    policy_path: Option<&Path>,
    audit: Option<super::ServiceAudit<'_>>,
    state: Option<&crate::RuntimeState>,
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
    if ["service", "capability"]
        .iter()
        .any(|field| !fields.get(*field).is_some_and(truthy))
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing required fields: service, capability"}),
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
    let credential = if definition.auth.is_some() {
        if !fields.get("credential").is_some_and(truthy) {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing required field: credential"}),
            ));
        }
        text("credential")?
    } else if fields.get("credential").is_some_and(truthy) {
        text("credential")?
    } else {
        ""
    };
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
    if let Some(state) = state.filter(|_| policy.and_then(Policy::native_controls).is_some()) {
        let host = fields
            .get("host")
            .map(|_| text("host"))
            .transpose()?
            .unwrap_or(&definition.default_host)
            .to_owned();
        let account = fields
            .get("account")
            .map(|_| text("account"))
            .transpose()?
            .unwrap_or("agent")
            .to_owned();
        let allow_host_network = match fields.get("allow_host_network") {
            None => false,
            Some(Value::Bool(value)) => *value,
            _ => return Err(Error::ServiceRepresentation),
        };
        // Service routing uses the hostname. Egress can separately retain an
        // operator's explicit port constraint.
        let service_host = if host.is_empty() {
            String::new()
        } else {
            crate::policy::split_destination(&host)
                .map_err(|_| Error::ServiceRepresentation)?
                .0
        };
        let state = state.clone();
        return mutation_owner.spawn_blocking(move || {
            crate::edit_native_policy(&state, |document| {
                document["agents"][authorization.agent.as_str()]["services"][authorization.service.as_str()]["capability"] = toml_edit::value(authorization.capability.as_str());
                if !authorization.credential.is_empty() {
                    document["agents"][authorization.agent.as_str()]["services"][authorization.service.as_str()]["token"] = toml_edit::value(authorization.credential.as_str());
                } else if let Some(binding) = document["agents"][authorization.agent.as_str()]["services"].get_mut(authorization.service.as_str()).and_then(Item::as_table_like_mut) {
                    binding.remove("token");
                }
                document["agents"][authorization.agent.as_str()]["services"][authorization.service.as_str()]["account"] = toml_edit::value(&account);
                if !host.is_empty() {
                    document["hosts"][&service_host]["service"] = toml_edit::value(authorization.service.as_str());
                    if allow_host_network { document["hosts"][&host]["egress"] = toml_edit::value("allow"); }
                } else if allow_host_network { return Err(mutation_error()); }
                Ok(())
            }).map_err(|_| Error::ServiceMutation)?;
            let mut outcome = response(StatusCode::OK, json!({"status":"authorized","agent":authorization.agent.as_str(),"service":authorization.service.as_str(),"capability":authorization.capability.as_str(),"credential":authorization.credential.as_str(),"account":account,"host":host,"next":"Use services authorized for the minted credential. Contract binding and risky-route approval are separate steps."}));
            outcome.audit = Some(Audit::ServiceAuthorized(authorization));
            let mut outcome = outcome.submit_audit(&writer, &client_ip, &target)?;
            outcome.audit = None;
            Ok(outcome)
        }).await?.await.map_err(|_| Error::ServiceMutation)?;
    }
    // Request cancellation drops only this receiver. The process owner retains
    // the worker and its audit attempt until graceful shutdown joins it.
    mutation_owner
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
        .map_err(|_| Error::ServiceMutation)?
}

pub(super) async fn revoke<B: Body<Data = Bytes>>(
    _request: Request<B>,
    agent: String,
    service: String,
    policy_path: Option<&Path>,
    audit: Option<super::ServiceAudit<'_>>,
    state: Option<&crate::RuntimeState>,
) -> Result<Outcome, Error> {
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
    let path = path.to_owned();
    let revocation = Revocation {
        agent: Zeroizing::new(agent),
        service: Zeroizing::new(service),
        credential: Zeroizing::new(String::new()),
    };
    if let Some(state) = state {
        let state = state.clone();
        return mutation_owner.spawn_blocking(move || {
            crate::edit_native_policy(&state, |document| {
                let services = document.get_mut("agents").and_then(|agents| agents.get_mut(revocation.agent.as_str()))
                    .and_then(|agent| agent.get_mut("services")).and_then(Item::as_table_like_mut).ok_or_else(mutation_error)?;
                services.remove(revocation.service.as_str()).ok_or_else(mutation_error)?;
                Ok(())
            }).map_err(|_| Error::ServiceMutation)?;
            let mut outcome = response(StatusCode::OK, json!({"status":"revoked","agent":revocation.agent.as_str(),"service":revocation.service.as_str()}));
            outcome.audit = Some(Audit::ServiceRevoked(revocation));
            let mut outcome = outcome.submit_audit(&writer, &client_ip, &target)?;
            outcome.audit = None;
            Ok(outcome)
        }).await?.await.map_err(|_| Error::ServiceMutation)?;
    }
    mutation_owner
        .spawn_blocking(move || {
            let outcome = persist_revocation(path, revocation)?;
            let mut outcome = outcome.submit_audit(&writer, &client_ip, &target)?;
            // The worker owns canonical audit submission for this mutation.
            outcome.audit = None;
            Ok(outcome)
        })
        .await?
        .await
        .map_err(|_| Error::ServiceMutation)?
}

fn persist(path: PathBuf, authorization: Authorization) -> Result<Outcome, Error> {
    let mut missing_agent = false;
    let mut invalid_shape = false;
    let result = crate::approvals::update_policy(
        &path,
        false,
        |document, _| {
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
            if !authorization.credential.is_empty() {
                binding.insert(
                    "token",
                    toml_edit::Value::from(authorization.credential.as_str()),
                );
            }
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

fn persist_revocation(path: PathBuf, mut revocation: Revocation) -> Result<Outcome, Error> {
    let mut missing_binding = false;
    let mut invalid_shape = false;
    let result = crate::approvals::update_policy(
        &path,
        false,
        |document, _| {
            let Some(agents) = document.get_mut("agents") else {
                missing_binding = true;
                return Err(mutation_error());
            };
            let Some(agents) = agents.as_table_like_mut() else {
                invalid_shape = true;
                return Err(mutation_error());
            };
            let Some(agent) = agents.get_mut(&revocation.agent) else {
                missing_binding = true;
                return Err(mutation_error());
            };
            let Some(agent) = agent.as_table_like_mut() else {
                invalid_shape = true;
                return Err(mutation_error());
            };
            let (credential, remove_services) = {
                let Some(services) = agent.get_mut("services").and_then(Item::as_table_like_mut)
                else {
                    missing_binding = true;
                    return Err(mutation_error());
                };
                let Some(binding) = services.remove(&revocation.service) else {
                    missing_binding = true;
                    return Err(mutation_error());
                };
                let credential = binding
                    .as_table_like()
                    .and_then(|binding| binding.get("token"))
                    .and_then(Item::as_str)
                    .unwrap_or_default()
                    .to_owned();
                (credential, services.is_empty())
            };
            revocation.credential = Zeroizing::new(credential);
            if remove_services {
                agent.remove("services");
            }
            Ok(())
        },
        |_| Ok(()),
    );
    if missing_binding {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":format!("agent '{}' or service '{}' not found", revocation.agent.as_str(), revocation.service.as_str())}),
        ));
    }
    if invalid_shape {
        return Err(Error::ServiceRepresentation);
    }
    result.map_err(|_| Error::ServiceMutation)?;
    let mut outcome = response(
        StatusCode::OK,
        json!({
            "status":"revoked", "agent":revocation.agent.as_str(),
            "service":revocation.service.as_str(), "credential":revocation.credential.as_str(),
        }),
    );
    outcome.audit = Some(Audit::ServiceRevoked(revocation));
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
