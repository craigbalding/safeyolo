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
    let mut prepared = proposal.grant.clone();
    if let Some(instance) = &prepared.support_instance_id {
        let conn = crate::coord_rooms::open(&crate::host_platform::config_dir())
            .map_err(|_| invalid("trust the source instance before previewing remote support"))?;
        let epoch: i64 = conn
            .query_row(
                "SELECT epoch FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1",
                [instance],
                |row| row.get(0),
            )
            .map_err(|_| invalid("source instance is not trusted"))?;
        if prepared
            .support_peer_epoch
            .is_some_and(|selected| selected != epoch)
        {
            return Err(invalid(
                "peer trust changed; preview a new grant against current trust",
            ));
        }
        prepared.support_peer_epoch = Some(epoch);
        crate::coord_rooms::federation::registration_available(
            &conn,
            policy,
            instance,
            &prepared.support.agent_id,
            &prepared.support.name,
        )
        .map_err(|error| invalid(error.to_string()))?;
    } else if prepared.support_peer_epoch.is_some() {
        return Err(invalid("local support has no remote peer trust epoch"));
    }
    let grant = &prepared;
    grant
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if grant.instance_id != super::instance_id().map_err(|error| invalid(error.to_string()))? {
        return Err(invalid("select this owning instance's durable identity"));
    }
    if !grant
        .targets
        .iter()
        .all(|target| policy.evidence_agent_id(&target.name) == Some(target.agent_id.as_str()))
        || (grant.support_instance_id.is_none()
            && policy.evidence_agent_id(&grant.support.name)
                != Some(grant.support.agent_id.as_str()))
    {
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
        "Revocation, narrowing and expiry prevent newly unauthorized operations and subsequent result reads. Already-admitted commands can continue. Local pending responses can still deliver output; remote pending responses recheck the owner's current disclosure authority. Revocation cannot undo commands, file changes or disclosed data. Killing a transport does not prove guest descendants stopped.".to_owned(),
    ];
    let mut factory_directions = Vec::new();
    for selected in &grant.factory_directions {
        let root = policy
            .identity_root()
            .ok_or_else(|| invalid("owning identity root unavailable"))?;
        for kind in &selected.types {
            let snapshot = crate::factory::direction_binding(
                root,
                &selected.factory,
                &selected.snapshot_id,
                Some(kind),
            )
            .map_err(|_| {
                invalid("select the current approved factory snapshot and declared direction types")
            })?;
            if !grant
                .targets
                .iter()
                .any(|target| target.name == snapshot.operator_agent())
            {
                return Err(invalid(
                    "include the factory's current operator-input agent as an explicit target",
                ));
            }
        }
        let snapshot =
            crate::factory::direction_binding(root, &selected.factory, &selected.snapshot_id, None)
                .map_err(|_| invalid("current approved factory unavailable"))?;
        factory_directions.push(json!({"factory":selected.factory,"snapshot_id":selected.snapshot_id,
            "room_name":snapshot.room,"recipient_agent":snapshot.operator_agent(),"types":selected.types,
            "state_disclosure":"The selected factory's role identities and observed runtime states; no checkpoint, contract, guest output or room history."}));
        warnings.push(format!("Factory {}: selected direction types {} reach its approved operator-input agent under the manager's own identity. This grants selected factory state and direction publication, not room history, native work ownership, acceptance or policy administration. Required checks, challenges and actor rules remain in force.",selected.factory,selected.types.join(", ")));
    }
    if grant.guest_admin {
        warnings.push("Guest administration of both producer and reviewer is common administrative control. Configured actor checks still apply, but the reviewer is not independent of this manager. Keep a required independent decider outside the manager's administration.".into());
        warnings.push("Guest administration permits arbitrary guest commands, including existing passwordless guest sudo, all target-accessible files, writable mounts, credentials, network and services, Agent API permissions and existing delegations. Authority can reach other peers and approval decisions through the target. Standing grants follow capabilities later given to the target. Direct target checks do not confine this indirect reach.".into());
        let deciding: Vec<_> = policy
            .delegations()
            .iter()
            .filter(|(_, delegation)| {
                delegation.reviewers.iter().any(|reviewer| {
                    reviewer
                        .local_agent()
                        .is_some_and(|agent| grant.targets.contains(&agent))
                })
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
    if !grant.signal_rooms.is_empty() {
        let connection = crate::coord_rooms::open(&crate::host_platform::config_dir())
            .map_err(|_| invalid("signal disclosure needs the owning instance's Coord store"))?;
        for room in &grant.signal_rooms {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM rooms WHERE name=?1)",
                    [room],
                    |row| row.get(0),
                )
                .map_err(|_| invalid("signal room lookup unavailable"))?;
            if !exists {
                return Err(invalid(
                    "selected signal room does not exist in this instance",
                ));
            }
        }
        warnings.push("Signal disclosure includes selected subjects' material signal summaries and references in the named rooms, including retained revisions and current resolution state. These are agent-authored claims and can contain sensitive text. It grants no room history or unrelated signals.".into());
    }
    Ok(
        json!({"name":name,"before":before,"after":grant,"revision":grant.revision(),"previous_revision":proposal.expected_revision,"acknowledgment":grant.revision(),"factory_directions":factory_directions,
        "lifetime":if grant.expires_at.is_some() {"temporary"} else {"standing"},
        "notifications":{"subjects":grant.targets,"recipient":grant.support,"kinds":grant.notifications,"signal_rooms":grant.signal_rooms,
            "disclosure":"Selected operational references and current observation evidence. Signal text requires the explicit signal_rooms selection. Current authority is checked at delivery and resolution. Notifications do not grant or execute repair."},
        "effect":"Inspection is always included. Only the selected guest evidence, administration and lifecycle actions are granted. Routine in-scope operations require no further prompt. Ordinary support and target restarts preserve a standing grant; recreated identities do not inherit it. Lifecycle uses saved worker configuration and accepts no host scripts, mounts, credentials or host commands.",
        "warnings":warnings}),
    )
}

pub(crate) fn apply(state: &RuntimeState, name: &str, proposal: Proposal) -> Result<Value> {
    let _audit_lock =
        super::audit_delivery::lock_grants().map_err(|error| invalid(error.to_string()))?;
    let mut pending = None;
    let result = crate::edit_native_policy(state, true, |source| {
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
        if let Some(instance) = &proposal.grant.support_instance_id {
            let conn = crate::coord_rooms::open(&crate::host_platform::config_dir())
                .map_err(|_| invalid("remote identity store unavailable"))?;
            crate::coord_rooms::federation::register(
                &conn,
                &saved,
                instance,
                &proposal.grant.support.agent_id,
                &proposal.grant.support.name,
            )
            .map_err(|_| {
                invalid("remote identity registration conflicts; inspect the current handle")
            })?;
        }
        let (mut document, context) = crate::policy::parse_toml_for_edit(source)
            .map_err(|error| invalid(error.to_string()))?;
        document["support_grants"][name] = toml_edit::value(
            serde_json::to_string(&proposal.grant).map_err(|error| invalid(error.to_string()))?,
        );
        pending = Some(
            super::audit_delivery::prepare_grant(name, "apply", &view)
                .map_err(|error| invalid(error.to_string()))?,
        );
        Ok((
            view,
            crate::policy::restore_large_toml_integers(&document.to_string(), &context),
        ))
    });
    saved_change(result, pending)
}

pub(crate) fn revoke(state: &RuntimeState, name: &str, expected_revision: &str) -> Result<Value> {
    let _audit_lock =
        super::audit_delivery::lock_grants().map_err(|error| invalid(error.to_string()))?;
    let mut pending = None;
    let result = crate::edit_native_policy(state, true, |source| {
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
        let view = json!({"name":name,"revoked":true,"previous_revision":expected_revision});
        pending = Some(
            super::audit_delivery::prepare_grant(name, "revoke", &view)
                .map_err(|error| invalid(error.to_string()))?,
        );
        Ok((
            view,
            crate::policy::restore_large_toml_integers(&document.to_string(), &context),
        ))
    });
    saved_change(result, pending)
}

fn saved_change(
    result: std::result::Result<Value, crate::Error>,
    pending: Option<String>,
) -> Result<Value> {
    let mut value = result.map_err(|error| invalid(error.to_string()))?;
    let id = pending.ok_or_else(|| invalid("support audit obligation unavailable"))?;
    value["audit_event_id"] = json!(id);
    if super::audit_delivery::grant_saved(&id).is_err() {
        value["audit_status"] = json!(
            "Canonical transaction outcome unavailable; the saved authority can have an outcome_unknown audit record. Inspect the current grant before another change."
        );
    }
    Ok(value)
}
