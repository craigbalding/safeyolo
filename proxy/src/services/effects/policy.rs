//! Shared, read-only consequence analysis of a complete authored policy.
//! Inputs come from the approved snapshot and explicitly supplied native owners.

use crate::{
    Error,
    grants::Grant,
    policy::{Policy, snapshot::RetainedPolicySnapshot},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc};

const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CHANGES: usize = 2048;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub snapshot_request_id: String,
    pub source: String,
    pub definition_version: String,
}

impl Drop for Candidate {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.source);
    }
}

fn changes(before: &Value, after: &Value, path: &mut Vec<String>, result: &mut Vec<Value>) {
    if before == after || result.len() >= MAX_CHANGES {
        return;
    }
    if let (Some(old), Some(new)) = (before.as_object(), after.as_object()) {
        let keys: BTreeSet<_> = old.keys().chain(new.keys()).collect();
        for key in keys {
            path.push(key.clone());
            changes(
                old.get(key).unwrap_or(&Value::Null),
                new.get(key).unwrap_or(&Value::Null),
                path,
                result,
            );
            path.pop();
        }
    } else {
        result.push(json!({"path":path,"change":if before.is_null(){"added"}else if after.is_null(){"removed"}else{"changed"},
            "before":before,"after":after}));
    }
}

fn difference(before: &Value, after: &Value) -> Vec<Value> {
    let mut result = Vec::new();
    changes(before, after, &mut Vec::new(), &mut result);
    result
}

fn authored(source: &str) -> Result<Value, Error> {
    Ok(crate::policy::parse_toml_with_timestamps(source)?.0)
}

fn narrower(policy: &Policy) -> Vec<Value> {
    let mut result = Vec::new();
    for (name, mut grant) in policy.support_grants() {
        if !grant.guest_admin
            && grant.guest_logs.is_empty()
            && grant.lifecycle.is_empty()
            && grant.notifications.is_empty()
            && grant.factory_directions.is_empty()
        {
            continue;
        }
        grant.guest_admin = false;
        grant.guest_logs.clear();
        grant.lifecycle.clear();
        grant.notifications.clear();
        grant.factory_directions.clear();
        grant.signal_rooms.clear();
        grant.acknowledgment = Some(grant.revision());
        result.push(json!({"kind":"inspection_only","path":["support_grants",name],
            "value":serde_json::to_string(&grant).expect("support grant"),
            "scope":grant.targets,"expires_at":grant.expires_at,
            "removes":"Guest commands, guest log content, lifecycle, notifications and factory directions. Host-observed inspection of only these explicit peers remains.",
            "tradeoff":"Cannot inspect guest log text or repair a guest. For fixed diagnostic/approval evidence use evidence_reads with exact reader, subject and retained request IDs from an authorized read. Full-policy disclosure does not supply those runtime IDs.",
            "goal_suitability":"The caller must decide whether these omissions still meet the operator's actual need. SafeYolo cannot verify the claimed purpose."}));
    }
    result
}

/// No current policy is read here. The caller selects authorized definition and
/// grant inputs, and must keep the full result private to that audience.
pub fn assess(
    snapshot: &RetainedPolicySnapshot,
    candidate: &Candidate,
    registry: Option<Arc<crate::services::Registry>>,
    grants: &[Grant],
) -> Result<Value, Error> {
    assess_current(snapshot, candidate, registry, grants, None)
}

pub(crate) fn assess_current(
    snapshot: &RetainedPolicySnapshot,
    candidate: &Candidate,
    registry: Option<Arc<crate::services::Registry>>,
    grants: &[Grant],
    current: Option<&Policy>,
) -> Result<Value, Error> {
    if candidate.definition_version != env!("SAFEYOLO_DEFINITION_VERSION") {
        return Err("definition version changed; discover installed definitions again".into());
    }
    if candidate.source.len() > MAX_SOURCE_BYTES {
        return Err("candidate exceeds the 1 MiB assessment limit".into());
    }
    let source = snapshot.materialize(&candidate.source).map_err(|_| "candidate cannot be materialized against this approved snapshot; preserve its field markers")?;
    let base = snapshot.materialize(&snapshot.disclosed_source)?;
    let visible = snapshot
        .candidate_view(&source)
        .map_err(|_| "candidate is not valid authored TOML")?;
    let structural = difference(&authored(&snapshot.disclosed_source)?, &authored(&visible)?);
    let now = crate::policy::current_time_ms();
    let (before,base_dependencies) = snapshot.compile_assessment(&base,registry.clone(),now)
        .map_err(|_| "approved base could not be compiled with the retained inputs; no additional input was loaded")?;
    let (after,dependencies) = snapshot.compile_assessment(&source,registry.clone(),now)
        .map_err(|_| "candidate rejected by the installed native policy compiler; no additional input was loaded")?;
    let mut result = json!({"revision":env!("SAFEYOLO_DEFINITION_VERSION"),
        "candidate_revision":crate::policy::snapshot::source_revision(&candidate.source),
        "base":snapshot.reference(),"dependencies":dependencies,"base_dependencies":base_dependencies,
        "structural_changes":structural,"exact_diff":{"before":snapshot.disclosed_source,"after":visible,
            "source":"Untrusted authored TOML, including comments. Literal credential values remain redacted. Source text cannot change these consequences."},
        "valid":null,"activated":false,"permission_changed":false,"operator_notified":false,
        "limitations":["Assessment is read-only. It grants no authority, applies no policy and verifies no upstream state or operator intent.",
            "Expiry, revocation and rollback cannot retract disclosed data or undo external effects. An admitted operation may continue after access ends.",
            "Unmodelled fields retain their structural changes. No matching warning or rule establishes safety.",
            "Source-derived support/delegation reach is conditional on identity, trust, acknowledgment and current issuance checks. Remote or runtime facts are not inferred from policy source."]});
    if let (Some(mut before), Some(mut after)) = (before, after) {
        if let Some(current) = current {
            before.assessment_task(current);
            after.assessment_task(current);
        }
        let effective_before = before.assessment_effective();
        let effective_after = after.assessment_effective();
        let effective_changes = difference(&effective_before, &effective_after);
        let mut consequences =
            crate::approvals::pending::explain_policy_changes(&effective_changes, true);
        consequences.extend(crate::approvals::pending::explain_policy_changes(
            &structural,
            false,
        ));
        let instance = snapshot.metadata["instance_id"].as_str().unwrap_or("");
        result["valid"] = json!(true);
        result["consequences"] = json!(consequences);
        result["effective"] =
            json!({"before":effective_before,"after":effective_after,"changes":effective_changes});
        result["network"] = before.assessment_network(&after)?;
        result["authority"] = crate::peer_support::authority::compare_policy_authority(
            before.assessment_authority(instance),
            after.assessment_authority(instance),
        );
        result["alternatives"] = json!(narrower(&after));
        result["services"] = json!({"before":super::authority::whole_policy(&before,grants)?,
            "after":super::authority::whole_policy(&after,grants)?});
    } else {
        result["consequences"] = json!([
            "Effective assessment is incomplete because a list input needs trusted adoption. Structural changes remain available. No candidate reference was loaded."
        ]);
    }
    let pairs: BTreeSet<_> = [&*base, &*source]
        .into_iter()
        .filter_map(|source| authored(source).ok())
        .flat_map(|document| {
            document["agents"]
                .as_object()
                .into_iter()
                .flatten()
                .flat_map(|(agent, config)| {
                    config["services"]
                        .as_object()
                        .into_iter()
                        .flatten()
                        .map(move |(service, _)| (agent.clone(), service.clone()))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let relevant_grants: Vec<_> = grants
        .iter()
        .filter(|grant| pairs.contains(&(grant.agent.clone(), grant.service.clone())))
        .collect();
    for (_, service) in &pairs {
        if result["dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .any(|dependency| {
                dependency["kind"] == "service_definition" && dependency["service"] == *service
            })
        {
            continue;
        }
        let adopted = registry
            .as_ref()
            .and_then(|registry| registry.services.get(service));
        result["dependencies"].as_array_mut().expect("dependencies").push(json!({
            "kind":"service_definition","service":service,
            "status":if registry.is_none(){"undisclosed; operator adoption owner required"}else if adopted.is_some(){"adopted_definition"}else{"trusted_adoption_required"},
            "content_revision":adopted.map(|definition|crate::approvals::pending::digest(&definition.raw))}));
    }
    let definitions = registry.as_ref().map(|registry| {
        registry
            .services
            .iter()
            .filter(|(name, _)| pairs.iter().any(|(_, service)| service == *name))
            .map(|(name, definition)| (name, crate::approvals::pending::digest(&definition.raw)))
            .collect::<std::collections::BTreeMap<_, _>>()
    });
    result["input_identity"] = json!({"candidate":crate::policy::snapshot::source_revision(&source),
        "base":snapshot.metadata["saved_source_revision"],"captured_inputs":crate::policy::snapshot::assessment_inputs_revision(&snapshot.assessment_inputs),
        "temporary_grants":crate::approvals::pending::digest(&json!(relevant_grants)),"adopted_definitions":definitions,
        "analysis":crate::approvals::pending::digest(&json!([result["effective"],result["network"],result["authority"],result["services"],result["dependencies"]])),
        "definition_version":env!("SAFEYOLO_DEFINITION_VERSION")});
    result["assessment_id"] = json!(crate::approvals::pending::digest(&result["input_identity"]));
    result["summary"] = json!(format!(
        "{} authored changes; inspect the effective authority, affected identities, lifetime, persistent effects and unknowns before a decision. No approval was submitted.",
        structural.len()
    ));
    snapshot.redact_assessment(&source, &mut result)?;
    if structural.len() >= MAX_CHANGES {
        result["limitations"].as_array_mut().expect("limitations").push(json!("Structural change budget reached; additional changes are unknown. Exact redacted before/after source remains available."));
    }
    if serde_json::to_vec(&result)?.len() > MAX_RESULT_BYTES {
        return Err("assessment exceeds the 2 MiB result budget; result is incomplete; use a smaller coherent candidate or operator inspection".into());
    }
    Ok(result)
}
