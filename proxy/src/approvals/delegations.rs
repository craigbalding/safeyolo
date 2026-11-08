//! Operator delegation preview, compare-and-set edits and source-owned revocation.
use super::{Result, invalid};
use crate::policy::{Policy, delegation::Delegation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proposal {
    pub expected_revision: Option<String>,
    pub delegation: Delegation,
}

#[derive(Serialize)]
pub(crate) struct Preview {
    name: String,
    before: Value,
    after: Delegation,
    revision: String,
    acknowledgment: String,
    warnings: Vec<String>,
    effect: &'static str,
    revocation: &'static str,
}

pub(crate) fn preview(
    policy: &Policy,
    name: &str,
    proposal: &Proposal,
    state: &crate::RuntimeState,
) -> Result<Value> {
    if !crate::host_platform::valid_agent_name(name) {
        return Err(invalid("invalid delegation name"));
    }
    let mut candidate = proposal.delegation.clone();
    for reviewer in &mut candidate.reviewers {
        if let Some(instance) = &reviewer.instance_id {
            let conn = crate::coord_rooms::open(
                policy
                    .identity_root()
                    .ok_or_else(|| invalid("owning identity root unavailable"))?,
            )
            .map_err(|_| invalid("trust the reviewer instance before previewing delegation"))?;
            let epoch: i64 = conn
                .query_row(
                    "SELECT epoch FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1",
                    [instance],
                    |row| row.get(0),
                )
                .map_err(|_| invalid("reviewer instance is not trusted"))?;
            if reviewer.peer_epoch.is_some_and(|saved| saved != epoch) {
                return Err(invalid(
                    "reviewer trust changed; preview against current trust",
                ));
            }
            reviewer.peer_epoch = Some(epoch);
            crate::coord_rooms::federation::registration_available(
                &conn,
                policy,
                instance,
                &reviewer.agent_id,
                &reviewer.name,
            )
            .map_err(|error| invalid(error.to_string()))?;
        }
    }
    let runtime = state
        .read()
        .map_err(|_| invalid("runtime unavailable"))?
        .clone();
    for scope in &mut candidate.scopes {
        if let crate::policy::delegation::Scope::DesktopPresent {
            presentation,
            instance_id,
            configuration_revision,
            ..
        } = scope
        {
            let path = crate::operator_actions::config_path(state)?;
            let revision = crate::host_platform::with_config(
                path,
                crate::desktop_present::configuration_revision,
            )
            .map_err(|_| invalid("host desktop configuration unavailable"))?;
            if configuration_revision
                .as_ref()
                .is_some_and(|saved| saved != &revision)
            {
                return Err(invalid(
                    "host desktop configuration changed; preview without the old configuration_revision and acknowledgment",
                ));
            }
            // The route is an explicit operator selection. Execution also checks
            // actual readiness and the current configured route.
            let settings = crate::host_platform::with_config(
                crate::operator_actions::config_path(state)?,
                crate::native_config::host_settings,
            )
            .map_err(|_| invalid("host desktop settings unavailable"))?;
            if (*presentation == crate::desktop_present::Route::Tailnet)
                != (settings.command_centre.share == "tailnet")
            {
                return Err(invalid(
                    "select the host's configured desktop presentation route",
                ));
            }
            *configuration_revision = Some(revision);
            let current_instance = crate::host_platform::with_config(
                crate::operator_actions::config_path(state)?,
                crate::desktop_present::instance_id,
            )
            .map_err(|_| invalid("desktop instance identity unavailable"))?;
            if instance_id
                .as_ref()
                .is_some_and(|saved| saved != &current_instance)
            {
                return Err(invalid(
                    "desktop instance changed; preview without the old instance_id and acknowledgment",
                ));
            }
            *instance_id = Some(current_instance);
        }
        if let crate::policy::delegation::Scope::ServiceAuthorization {
            service,
            capability,
            credential,
            credential_binding,
            ..
        } = scope
        {
            let registry = policy
                .gateway()
                .and_then(|gateway| gateway.registry())
                .ok_or_else(|| invalid("service catalogue unavailable"))?;
            let definition = registry
                .services
                .get(service)
                .filter(|definition| definition.capabilities.contains_key(capability))
                .ok_or_else(|| invalid("service or capability unavailable"))?;
            if definition.auth.is_some() == credential.is_empty() {
                return Err(invalid(
                    "select a configured credential for an authenticated service, or an empty credential for a credential-free service",
                ));
            }
            let current = if credential.is_empty() {
                None
            } else {
                let loaded = runtime
                    .gateway_vault
                    .load()
                    .map_err(|_| invalid("credential store unavailable"))?;
                let (Some(loaded), Some(guard)) = (loaded, &runtime.credential_guard) else {
                    return Err(invalid("credential binding unavailable"));
                };
                loaded
                    .vault
                    .reload_if_changed()
                    .map_err(|_| invalid("credential store unavailable"))?;
                let snapshot = loaded
                    .vault
                    .snapshot(credential)
                    .map_err(|_| invalid("credential unavailable"))?
                    .ok_or_else(|| invalid("credential unavailable"))?;
                if !loaded
                    .vault
                    .is_current(&snapshot)
                    .map_err(|_| invalid("credential unavailable"))?
                {
                    return Err(invalid("credential changed; preview again"));
                }
                Some(guard.approval_binding(snapshot.credential()))
            };
            if credential_binding.is_some() && *credential_binding != current {
                return Err(invalid(
                    "credential definition changed; preview without the old credential_binding and acknowledgment",
                ));
            }
            *credential_binding = current;
        }
    }
    candidate.valid().map_err(|e| invalid(e.to_string()))?;
    let dependencies = candidate
        .dependencies(policy)
        .map_err(|e| invalid(e.to_string()))?;
    if !candidate.definition_revisions.is_empty() && candidate.definition_revisions != dependencies
    {
        return Err(invalid(
            "relevant definitions changed; preview a new proposal without the old definition_revisions and acknowledgment",
        ));
    }
    candidate.definition_revisions = dependencies;
    let before = policy.delegations().get(name);
    if proposal.expected_revision.as_deref() != before.map(|d| d.revision()).as_deref() {
        return Err(invalid(
            "delegation changed; inspect and preview the current revision",
        ));
    }
    for agent in candidate
        .reviewers
        .iter()
        .filter_map(crate::policy::delegation::Reviewer::local_agent)
        .chain(candidate.beneficiaries.iter().cloned())
    {
        if policy.evidence_agent_id(&agent.name) != Some(agent.agent_id.as_str()) {
            return Err(invalid(format!(
                "agent {} has a missing, duplicate or changed durable identity",
                agent.name
            )));
        }
    }
    let mut warnings = proposal.delegation.warnings();
    if candidate
        .reviewers
        .iter()
        .any(|reviewer| reviewer.instance_id.is_some())
    {
        warnings.push("The selected remote reviewer uses its own qualified identity. This instance owns each approval, deciding scope, issued permission and result. Trust alone and peer repair grants do not authorize decisions. Revoking peer trust invalidates this delegation's remote deciding authority and derived access; re-trust requires a new preview.".into());
        warnings.push("This instance cannot inspect the remote reviewer's startup files, mounts or other grants. This preview does not establish independence or bound indirect administration.".into());
    }
    warnings.extend(policy.reviewer_write_warnings(&proposal.delegation));
    if !candidate.reciprocal_agent_pairs(policy).is_empty() {
        warnings.push("These reviewers and beneficiaries have reciprocal deciding authority through another delegation. This does not prevent indirect cooperation.".into());
    }
    let revision = candidate.revision();
    let independent = policy.independent_delegation_access(&candidate);
    let mut preview = json!(Preview {
        name: name.into(),
        before: json!(before),
        after: candidate,
        acknowledgment: revision.clone(),
        revision,
        warnings,
        effect: "Any one named reviewer may select a canonical option wholly inside this delegation. Network, credential, service authorization, contract binding, Coord room access and desktop presentation are bounded to the current worker run. Optional grant expiry is separate from delegation validity and pending-request expiry. Desktop presentation adds a separately expiring preview source. Gateway once uses the existing reservation and response-completion rules.",
        revocation: "Changing or revoking this delegation invalidates its derived access. Independently sourced permission remains. Future authorizations are rechecked. An admitted opaque tunnel may continue; revocation cannot undo upstream effects. Desktop viewers disconnect when the last valid preview source ends; opening a browser cannot be undone. Inspect network, credential and service permissions for residual access."
    });
    preview["independent_access"] = json!(independent);
    Ok(preview)
}

pub(crate) fn apply(state: &crate::RuntimeState, name: &str, proposal: Proposal) -> Result<Value> {
    crate::edit_native_policy(state, true, |source| {
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
        let current = runtime
            .policy
            .as_ref()
            .ok_or_else(|| invalid("policy unavailable"))?;
        let path = runtime
            .config
            .policy_file
            .as_ref()
            .ok_or_else(|| invalid("policy path unavailable"))?;
        let saved = current
            .reload_native_source(source, path)
            .map_err(|e| invalid(e.to_string()))?;
        let view = preview(&saved, name, &proposal, state)?;
        if proposal.delegation.revision() != view["revision"].as_str().unwrap_or("")
            || proposal.delegation.acknowledgment.as_deref() != view["revision"].as_str()
        {
            return Err(invalid(
                "acknowledge this exact delegation preview revision before apply",
            ));
        }
        drop(runtime);
        for reviewer in &proposal.delegation.reviewers {
            if let Some(instance) = &reviewer.instance_id {
                let conn = crate::coord_rooms::open(
                    saved
                        .identity_root()
                        .ok_or_else(|| invalid("owning identity root unavailable"))?,
                )
                .map_err(|_| invalid("remote identity store unavailable"))?;
                crate::coord_rooms::federation::register(
                    &conn,
                    &saved,
                    instance,
                    &reviewer.agent_id,
                    &reviewer.name,
                )
                .map_err(|error| invalid(error.to_string()))?;
            }
        }
        let (mut document, context) =
            crate::policy::parse_toml_for_edit(source).map_err(|e| invalid(e.to_string()))?;
        if proposal.expected_revision.as_deref() != Some(proposal.delegation.revision().as_str()) {
            remove_issued(&mut document, source, name)?;
        }
        document["approval_delegations"][name] = toml_edit::value(
            serde_json::to_string(&proposal.delegation).map_err(|e| invalid(e.to_string()))?,
        );
        Ok((
            view,
            crate::policy::restore_large_toml_integers(&document.to_string(), &context),
        ))
    })
    .map_err(|e| invalid(e.to_string()))
}

pub(crate) fn revoke(
    state: &crate::RuntimeState,
    name: &str,
    expected_revision: &str,
) -> Result<Value> {
    crate::edit_native_policy(state,true,|source| {
        let (mut document,context)=crate::policy::parse_toml_for_edit(source).map_err(|e| invalid(e.to_string()))?;
        let value = crate::policy::parse_toml_document(source).map_err(|e| invalid(e.to_string()))?;
        let delegations=crate::policy::delegation::parse(&value).map_err(|e| invalid(e.to_string()))?;
        let current=delegations.get(name).ok_or_else(|| invalid("delegation unavailable"))?;
        if current.revision() != expected_revision { return Err(invalid("delegation changed; inspect its current revision before revoking")); }
        remove_issued(&mut document,source,name)?;
        document["approval_delegations"].as_table_like_mut().ok_or_else(|| invalid("delegations unavailable"))?.remove(name);
        Ok((json!({"status":"revoked","name":name,"residual_access":"independent policy and grants remain; admitted opaque tunnels may continue"}),crate::policy::restore_large_toml_integers(&document.to_string(),&context)))
    }).map_err(|e| invalid(e.to_string()))
}

fn remove_issued(document: &mut toml_edit::DocumentMut, source: &str, name: &str) -> Result<()> {
    let value = crate::policy::parse_toml_document(source).map_err(|e| invalid(e.to_string()))?;
    for (agent, fields) in value["agents"].as_object().into_iter().flatten() {
        for collection in [
            "network_grants",
            "credential_grants",
            "service_grants",
            "binding_grants",
            "coord_grants",
            "desktop_grants",
        ] {
            for (id, raw) in fields[collection].as_object().into_iter().flatten() {
                let issued = raw.as_str().and_then(|s| {
                    serde_json::from_str::<crate::policy::delegation::IssuedAccess>(s).ok()
                });
                if issued.is_some_and(|issued| issued.delegation == name)
                    && let Some(table) = document["agents"][agent][collection].as_table_like_mut()
                {
                    table.remove(id);
                }
            }
        }
        let removals: Vec<_> = fields["grants"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(index, grant)| {
                grant["delegated"]
                    .as_str()
                    .and_then(|s| {
                        serde_json::from_str::<crate::policy::delegation::IssuedAccess>(s).ok()
                    })
                    .filter(|issued| issued.delegation == name)
                    .map(|_| index)
            })
            .collect();
        if !removals.is_empty() {
            let item = &mut document["agents"][agent]["grants"];
            for index in removals.into_iter().rev() {
                if let Some(array) = item.as_array_of_tables_mut() {
                    array.remove(index);
                } else if let Some(array) = item.as_array_mut() {
                    array.remove(index);
                } else {
                    return Err(invalid("gateway grants must be an array"));
                }
            }
        }
    }
    Ok(())
}
