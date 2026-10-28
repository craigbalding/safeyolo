//! Pending gateway requests use the same host record and existing grant store.

use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::{Authority, OptionScope, Record, annotate, digest, revision, unavailable};
use crate::{
    Runtime,
    approvals::{Result, invalid},
    audit::Event,
    policy::NetworkRequest,
};

pub(super) fn credentials_current(runtime: &Runtime, record: &Record) -> Result<bool> {
    for (name, binding) in &record.authority.credential_bindings {
        let loaded = runtime.gateway_vault.load().map_err(unavailable)?;
        let (Some(loaded), Some(guard)) = (loaded.as_ref(), &runtime.credential_guard) else {
            return Err(invalid("credential binding unavailable"));
        };
        let vault = &loaded.vault;
        let Some(snapshot) = vault.snapshot(name).map_err(unavailable)? else {
            return Ok(false);
        };
        if !vault.is_current(&snapshot).map_err(unavailable)?
            || guard.approval_binding(snapshot.credential()) != *binding
        {
            return Ok(false);
        }
    }
    if let Some(option) = record.option.as_deref().and_then(|id| {
        record
            .authority
            .options
            .iter()
            .find(|option| option.id == id)
    }) {
        return option_current(runtime, option);
    }
    Ok(true)
}

pub(super) fn option_current(runtime: &Runtime, option: &OptionScope) -> Result<bool> {
    if option
        .session_id
        .as_ref()
        .is_some_and(|id| id != &runtime.audit.approvals().session_id)
    {
        return Ok(false);
    }
    if super::expired_at(
        option.parameters["expires_at"].as_str(),
        time::OffsetDateTime::now_utc(),
    ) {
        return Ok(false);
    }
    if let Some(name) = option.parameters["credential"]
        .as_str()
        .filter(|name| !name.is_empty())
    {
        let loaded = runtime.gateway_vault.load().map_err(unavailable)?;
        let (Some(loaded), Some(guard)) = (loaded.as_ref(), &runtime.credential_guard) else {
            return Err(invalid("credential binding unavailable"));
        };
        let vault = &loaded.vault;
        let Some(snapshot) = vault.snapshot(name).map_err(unavailable)? else {
            return Ok(false);
        };
        return Ok(vault.is_current(&snapshot).map_err(unavailable)?
            && option.parameters["credential_binding"]
                == guard.approval_binding(snapshot.credential()));
    }
    Ok(true)
}

fn credential_bindings(
    runtime: &Runtime,
    names: &[String],
) -> Result<(BTreeMap<String, String>, Option<String>)> {
    let mut bindings = BTreeMap::new();
    let mut expiry: Option<time::OffsetDateTime> = None;
    for name in names.iter().filter(|name| !name.is_empty()) {
        let loaded = runtime.gateway_vault.load().map_err(unavailable)?;
        let (Some(loaded), Some(guard)) = (loaded.as_ref(), &runtime.credential_guard) else {
            return Err(invalid("credential binding unavailable"));
        };
        let vault = &loaded.vault;
        vault.reload_if_changed().map_err(unavailable)?;
        let Some(snapshot) = vault.snapshot(name).map_err(unavailable)? else {
            return Err(invalid("selected credential unavailable"));
        };
        if !vault.is_current(&snapshot).map_err(unavailable)? {
            return Err(invalid("selected credential changed"));
        }
        let credential = snapshot.credential();
        bindings.insert(name.clone(), guard.approval_binding(credential));
        if let Some(expires) = credential
            .expires_at
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let expires = crate::policy::parse_expiry(expires)
                .filter(|_| crate::policy::expiry_has_offset(expires))
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
            expiry = Some(expiry.map_or(expires, |prior| prior.min(expires)));
        }
    }
    Ok((
        bindings,
        expiry.map(|value| {
            value
                .to_offset(time::UtcOffset::UTC)
                .format(&time::format_description::well_known::Rfc3339)
                .expect("UTC date")
        }),
    ))
}

pub(crate) async fn bind_risky(
    runtime: &std::sync::Arc<Runtime>,
    run: Option<&crate::host_runs::AgentRun>,
    event: &mut Event,
    request: NetworkRequest<'_>,
    scheme: &str,
    selection: &crate::services::CredentialSelection,
) -> Result<Option<Record>> {
    let Some(policy) = runtime
        .policy
        .as_ref()
        .filter(|policy| policy.native_controls().is_some())
    else {
        return Ok(None);
    };
    let agent = request
        .agent
        .ok_or_else(|| invalid("requester identity unavailable"))?;
    let agent_id = policy
        .evidence_agent_id(agent)
        .ok_or_else(|| invalid("requester identity unavailable"))?;
    let path = request.path.split('?').next().unwrap_or("/");
    let mut action = json!({"kind":"gateway_route","agent":agent,"agent_id":agent_id,
        "service":selection.service,"capability":selection.capability,"credential":selection.vault_token,
        "account":selection.account,"host":request.host,"method":request.method,"path":path,
        "run":run,"binding_id":selection.binding_id,
        "irreversible":selection.risky_route.as_ref().is_some_and(|route| route.irreversible)});
    if let Some(git) = &selection.github_git {
        action["github_repository"] = git.repository.clone().into();
        action["git_operation"] = git.operation.clone().into();
    }
    let ttl = runtime
        .gateway_grants
        .as_ref()
        .ok_or_else(|| invalid("gateway grant store unavailable"))?
        .approval_ttl_seconds()?;
    let mut options: Vec<_> = ["once", "session", "remembered"].into_iter().map(|id| OptionScope {
        id:id.into(), effect:selection.github_git.as_ref().map_or_else(
            || format!("Allow {agent} to use {} at the exact path {} on {} with a {id} grant. The grant expires {ttl} seconds after approval. A successful response consumes once; proxy restart also ends session.", request.method, path, selection.service),
            |git| format!("{agent} wants to {} to {}. Allow with a {id} grant, expiring {ttl} seconds after approval. Ref discovery retains once; the successful pack response consumes it. Proxy restart ends session.", git.action(), git.repository)),
        session_id:(id == "session").then(|| runtime.audit.approvals().session_id.clone()),
        parameters:json!({"lifetime":id,"ttl_seconds":ttl,"path_match":"literal"}) }).collect();
    options.push(super::run_option("Run-bound reusable access to the canonical service, capability, binding, method and exact path. Gateway expiry and all contract checks remain. This is not payload-bound approval."));
    options.push(OptionScope { id: "delegated_once".into(), effect: "One reserved gateway route use for the current worker run. Existing response consumption/release semantics apply. This does not guarantee exactly-once external effects or bind the payload.".into(), session_id: None, parameters: Value::Null });
    let authority = Authority {
        revision: revision(policy, &action)
            .ok_or_else(|| invalid("gateway revision unavailable"))?,
        action,
        method: request.method.into(),
        scheme: scheme.into(),
        port: request.port,
        resource_digest: runtime
            .credential_guard
            .as_ref()
            .ok_or_else(|| invalid("request binding unavailable"))?
            .approval_resource(request.path),
        options,
        expires_at: None,
        credential_bindings: Default::default(),
    };
    submit(
        runtime,
        event,
        authority,
        vec![selection.vault_token.clone()],
    )
    .await
    .map(Some)
}

async fn submit(
    runtime: &std::sync::Arc<Runtime>,
    event: &mut Event,
    mut authority: Authority,
    credentials: Vec<String>,
) -> Result<Record> {
    let request_id = event
        .request_id
        .clone()
        .ok_or_else(|| invalid("traffic identity unavailable"))?;
    let runtime = runtime.clone();
    let record = tokio::task::spawn_blocking(move || {
        let (bindings, expires_at) = credential_bindings(&runtime, &credentials)?;
        authority.credential_bindings = bindings;
        authority.expires_at = expires_at;
        runtime.audit.approvals().submit(
            authority,
            &request_id,
            runtime
                .policy
                .as_ref()
                .ok_or_else(|| invalid("active policy unavailable"))?,
        )
    })
    .await
    .map_err(unavailable)??;
    annotate(event, &record);
    Ok(record)
}

pub(crate) async fn bind_agent_request(
    runtime: &std::sync::Arc<Runtime>,
    event: &mut Event,
    request_id: &str,
) -> Result<Option<Record>> {
    let Some(policy) = runtime
        .policy
        .as_ref()
        .filter(|policy| policy.native_controls().is_some())
    else {
        return Ok(None);
    };
    let Some(approval) = event.approval.as_ref().filter(|approval| approval.required) else {
        return Ok(None);
    };
    if !matches!(
        approval.approval_type,
        crate::audit::ApprovalType::Service | crate::audit::ApprovalType::ContractBinding
    ) {
        return Ok(None);
    }
    let hint = approval.scope_hint.json().map_err(unavailable)?;
    let agent = event
        .agent
        .as_deref()
        .ok_or_else(|| invalid("requester identity unavailable"))?;
    let agent_id = policy
        .evidence_agent_id(agent)
        .ok_or_else(|| invalid("requester identity unavailable"))?;
    let service = hint["service"]
        .as_str()
        .ok_or_else(|| invalid("service unavailable"))?;
    let capability = hint["capability"]
        .as_str()
        .ok_or_else(|| invalid("capability unavailable"))?;
    let registry = policy
        .gateway()
        .and_then(|gateway| gateway.registry())
        .ok_or_else(|| invalid("service catalogue unavailable"))?;
    let definition = registry
        .services
        .get(service)
        .ok_or_else(|| invalid("service unavailable"))?;
    let binding = approval.approval_type == crate::audit::ApprovalType::ContractBinding;
    let mut action = json!({"kind":if binding {"contract_binding"} else {"service_authorize"},
        "agent":agent,"agent_id":agent_id,"service":service,"capability":capability,
        "host":definition.default_host});
    let mut credentials = Vec::new();
    let options = if binding {
        for key in ["template", "bindings", "grantable_operations"] {
            action[key] = hint[key].clone();
        }
        if let Some(name) = policy.service_credential(agent, service) {
            credentials.push(name);
        }
        vec![OptionScope {
            id: "persistent".into(),
            effect: format!(
                "Save the selected contract values for {agent} on {service}/{capability} until explicitly replaced or removed. This does not authorize the service or approve risky routes."
            ),
            session_id: None,
            parameters: Value::Null,
        }]
    } else if definition.auth.is_none() {
        vec![OptionScope {
            id: "credential_free".into(),
            effect: format!(
                "Authorize {agent} to use {service}/{capability} without a credential until revoked. Existing network policy still applies."
            ),
            session_id: None,
            parameters: json!({"credential":""}),
        }]
    } else {
        let mut options = Vec::new();
        let loaded = runtime
            .gateway_vault
            .load_async()
            .await
            .map_err(unavailable)?;
        if let (Some(loaded), Some(guard)) = (loaded.as_ref(), &runtime.credential_guard) {
            let vault = &loaded.vault;
            vault.reload_if_changed().map_err(unavailable)?;
            for metadata in vault.metadata().map_err(unavailable)? {
                let Some(snapshot) = vault.snapshot(&metadata.name).map_err(unavailable)? else {
                    continue;
                };
                if !vault.is_current(&snapshot).map_err(unavailable)? {
                    return Err(invalid("credential options changed; retry the request"));
                }
                let credential = snapshot.credential();
                let expires_at = credential
                    .expires_at
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .map(super::normalized_expiry);
                options.push(OptionScope { id:format!("credential:{}", metadata.name),
                    effect:format!("Authorize {agent} to use {service}/{capability} with credential reference {} and account agent until revoked. Existing network policy still applies.", metadata.name),
                    session_id:None,parameters:json!({"credential":metadata.name,"credential_binding":guard.approval_binding(credential),"expires_at":expires_at}) });
            }
        }
        options.sort_by(|a, b| a.id.cmp(&b.id));
        options
    };
    let authority = Authority {
        revision: revision(policy, &action)
            .ok_or_else(|| invalid("gateway revision unavailable"))?,
        resource_digest: digest(&action),
        action,
        method: "POST".into(),
        scheme: "http".into(),
        port: None,
        options,
        expires_at: None,
        credential_bindings: Default::default(),
    };
    event.request_id = Some(request_id.into());
    if !binding && let Some(approval) = event.approval.as_mut() {
        let mut hint = approval.scope_hint.json().map_err(unavailable)?;
        hint["proposed_lifetime"] = json!("persistent");
        approval.scope_hint = hint.into();
    }
    submit(runtime, event, authority, credentials)
        .await
        .map(Some)
}
