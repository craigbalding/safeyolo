//! Operator previews and compare-and-set edits use the native policy transaction.

use crate::{
    RuntimeState,
    approvals::{Result, invalid},
    policy::{Policy, support::Grant},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proposal {
    pub expected_revision: Option<String>,
    pub grant: Grant,
}

pub(crate) fn preview(policy: &Policy, name: &str, proposal: &Proposal) -> Result<Value> {
    if !crate::host_platform::valid_agent_name(name) {
        return Err(invalid("invalid support grant name"));
    }
    let grant = &proposal.grant;
    grant
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if grant.instance_id != super::instance_id().map_err(|error| invalid(error.to_string()))? {
        return Err(invalid("select this owning instance's durable identity"));
    }
    if !grant.identities_current(policy) {
        return Err(invalid(
            "support or target durable identity is missing, duplicate or changed",
        ));
    }
    let grants = policy.support_grants();
    let before = grants.get(name);
    if proposal.expected_revision.as_deref() != before.map(Grant::revision).as_deref() {
        return Err(invalid(
            "support grant changed; inspect and preview its current revision",
        ));
    }
    let mut warnings = vec![
        "Inspection reports selected host-observed states. Guest output is untrusted. Other workers and host secrets remain private.".to_owned(),
        "Revocation, narrowing and expiry prevent newly unauthorized operations and subsequent result reads. Already-admitted commands and their pending responses can continue, including output delivery. Revocation cannot undo commands, file changes or disclosed data. Killing a transport does not prove guest descendants stopped.".to_owned(),
    ];
    if grant.guest_admin {
        warnings.push("Guest administration permits arbitrary guest commands, including existing passwordless guest sudo, all target-accessible files, writable mounts, credentials, network and services, Agent API permissions and existing delegations. Authority can reach other peers and approval decisions through the target. Standing grants follow capabilities later given to the target. Direct target checks do not confine this indirect reach.".into());
        let deciding: Vec<_> = policy
            .delegations()
            .iter()
            .filter(|(_, delegation)| {
                delegation
                    .reviewers
                    .iter()
                    .any(|reviewer| grant.targets.contains(reviewer))
            })
            .map(|(name, _)| name)
            .collect();
        warnings.push(format!("Targets can act as reviewers in these configured approval delegations: {}. A support agent controlling a reviewer is not independent of that reviewer.", serde_json::to_string(&deciding).unwrap_or_default()));
        let indirect: Vec<_> = policy
            .support_grants()
            .into_iter()
            .filter(|(_, other)| grant.targets.contains(&other.support))
            .map(|(name, _)| name)
            .collect();
        warnings.push(format!("Targets hold these configured support grants: {}. This preview does not recursively calculate indirect authority.", serde_json::to_string(&indirect).unwrap_or_default()));
    }
    if !grant.guest_logs.is_empty() {
        warnings.push("Selected log paths are read inside the guest. Guest links may lead to any target-accessible data, including shared mounts and credentials. This permission is broader than host-observed inspection.".into());
    }
    Ok(
        json!({"name":name,"before":before,"after":grant,"revision":grant.revision(),"acknowledgment":grant.revision(),
        "lifetime":if grant.expires_at.is_some() {"temporary"} else {"standing"},
        "effect":"Inspection is always included. Only the selected guest evidence, administration and lifecycle actions are granted. Routine in-scope operations require no further prompt. Ordinary support and target restarts preserve a standing grant; recreated identities do not inherit it. Lifecycle uses saved worker configuration and accepts no host scripts, mounts, credentials or host commands.",
        "warnings":warnings}),
    )
}

pub(crate) fn apply(state: &RuntimeState, name: &str, proposal: Proposal) -> Result<Value> {
    crate::edit_native_policy(state, true, |source| {
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
        let policy = runtime
            .policy
            .as_ref()
            .ok_or_else(|| invalid("policy unavailable"))?;
        let path = runtime
            .config
            .policy_file
            .as_ref()
            .ok_or_else(|| invalid("policy path unavailable"))?;
        let saved = policy
            .reload_native_source(source, path)
            .map_err(|error| invalid(error.to_string()))?;
        let view = preview(&saved, name, &proposal)?;
        if proposal.grant.acknowledgment.as_deref() != view["revision"].as_str() {
            return Err(invalid(
                "acknowledge the exact support preview revision before apply",
            ));
        }
        let (mut document, context) = crate::policy::parse_toml_for_edit(source)
            .map_err(|error| invalid(error.to_string()))?;
        document["support_grants"][name] = toml_edit::value(
            serde_json::to_string(&proposal.grant).map_err(|error| invalid(error.to_string()))?,
        );
        Ok((
            view,
            crate::policy::restore_large_toml_integers(&document.to_string(), &context),
        ))
    })
    .map_err(|error| invalid(error.to_string()))
}

pub(crate) fn revoke(state: &RuntimeState, name: &str, expected_revision: &str) -> Result<Value> {
    crate::edit_native_policy(state, true, |source| {
        let (mut document, context) = crate::policy::parse_toml_for_edit(source)
            .map_err(|error| invalid(error.to_string()))?;
        let value = crate::policy::parse_toml_document(source)
            .map_err(|error| invalid(error.to_string()))?;
        let grants =
            crate::policy::support::parse(&value).map_err(|error| invalid(error.to_string()))?;
        let current = grants
            .get(name)
            .ok_or_else(|| invalid("support grant unavailable"))?;
        if current.revision() != expected_revision {
            return Err(invalid(
                "support grant changed; inspect its current revision",
            ));
        }
        document["support_grants"]
            .as_table_like_mut()
            .ok_or_else(|| invalid("support grants unavailable"))?
            .remove(name);
        Ok((
            json!({"name":name,"revoked":true,"previous_revision":expected_revision}),
            crate::policy::restore_large_toml_integers(&document.to_string(), &context),
        ))
    })
    .map_err(|error| invalid(error.to_string()))
}
