//! Audience selection for one shared policy assessment. Private preparation
//! never submits an approval, emits attention, or changes a grant.
use super::*;
use crate::{
    host_runs::AgentRun,
    services::effects::policy::{self, Candidate},
};

pub(super) fn snapshot(
    writer: &Writer,
    input: &Candidate,
) -> Result<crate::policy::snapshot::RetainedPolicySnapshot> {
    let record = writer
        .approvals()
        .get(&input.snapshot_request_id)?
        .ok_or_else(|| invalid("approved snapshot unavailable"))?;
    policy_snapshot::retained(writer, &record)
}

pub(crate) fn private(
    state: &crate::RuntimeState,
    writer: &Writer,
    run: &AgentRun,
    input: &Candidate,
) -> Result<Value> {
    // No live policy content, catalogue, temporary grant or freshness signal
    // enters the authorized projection. A later unapproved revision must not
    // become visible through errors, IDs, differences or alternatives.
    let check_owner = || -> Result<bool> {
        let runtime = state.read().map_err(unavailable)?;
        let record = writer
            .approvals()
            .get(&input.snapshot_request_id)?
            .ok_or_else(|| invalid("approved snapshot unavailable"))?;
        Ok(runtime
            .policy
            .as_deref()
            .is_some_and(|policy| policy_snapshot::owner(&record, policy, run)))
    };
    if !check_owner()? {
        return Err(invalid("approved snapshot unavailable"));
    }
    let retained = snapshot(writer, input)?;
    let result = authorized_projection(&retained, input)?;
    if !check_owner()? {
        return Err(invalid("approved snapshot unavailable"));
    }
    Ok(result)
}

fn authorized_projection(
    retained: &crate::policy::snapshot::RetainedPolicySnapshot,
    input: &Candidate,
) -> Result<Value> {
    let mut result =
        policy::assess(retained, input, None, &[]).map_err(|error| invalid(error.to_string()))?;
    result["audience"] = json!("approved_snapshot_requester");
    result["current_state"] = json!(
        "undisclosed; assessment uses only the approved source snapshot, not later policy or unrelated runtime state"
    );
    result["limitations"].as_array_mut().expect("assessment limits").push(json!(
        "Adopted service model contents, live temporary grants, peer trust, runtime readiness and later source revisions are outside this disclosure. Their effects and currentness are unknown here. An authorized operator receives those inputs through the same assessment owner."));
    Ok(result)
}

pub(crate) fn operator(
    state: &crate::RuntimeState,
    writer: &Writer,
    input: &Candidate,
) -> Result<Value> {
    let retained = snapshot(writer, input)?;
    let (policy, store, path) = {
        let runtime = state.read().map_err(unavailable)?;
        (
            runtime
                .policy
                .clone()
                .ok_or_else(|| invalid("policy unavailable"))?,
            runtime.gateway_grants.clone(),
            runtime
                .config
                .policy_file
                .clone()
                .ok_or_else(|| invalid("policy source unavailable"))?,
        )
    };
    let saved = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(unavailable)?);
    let grants = store
        .map(|store| store.current_grants_for_report(time::OffsetDateTime::now_utc()))
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            !entry.expired
                && entry.grant.delegated.as_ref().is_none_or(|encoded| {
                    serde_json::from_str::<crate::policy::delegation::IssuedAccess>(encoded)
                        .is_ok_and(|issued| issued.active(&policy))
                })
        })
        .map(|entry| entry.grant)
        .collect::<Vec<_>>();
    operator_materialized(&retained, input, &policy, &saved, &grants, None)
}

/// Shared assessment with caller-held policy/store/file locks at adoption.
pub(super) fn operator_materialized(
    retained: &crate::policy::snapshot::RetainedPolicySnapshot,
    input: &Candidate,
    policy: &Policy,
    saved: &str,
    grants: &[crate::grants::Grant],
    materialized: Option<&str>,
) -> Result<Value> {
    let saved_revision = crate::policy::snapshot::source_revision(saved);
    let active_revision = policy
        .native_source_text()
        .map(crate::policy::snapshot::source_revision);
    let mut operator_inputs = retained.clone();
    operator_inputs.assessment_inputs = policy.assessment_list_inputs();
    let inputs_match =
        crate::policy::snapshot::assessment_inputs_revision(&operator_inputs.assessment_inputs)
            == crate::policy::snapshot::assessment_inputs_revision(&retained.assessment_inputs);
    let mut result = if let Some(source) = materialized {
        policy::assess_materialized(
            &operator_inputs,
            input,
            policy.gateway().and_then(|gateway| gateway.registry()),
            grants,
            Some(policy),
            source,
        )
    } else {
        policy::assess_current(
            &operator_inputs,
            input,
            policy.gateway().and_then(|gateway| gateway.registry()),
            grants,
            Some(policy),
        )
    }
    .map_err(|error| invalid(error.to_string()))?;
    result["audience"] = json!("authenticated_operator");
    result["input_identity"]["current_policy"] =
        json!({"saved":saved_revision,"active":active_revision});
    result["input_identity"]["check_feeds"] = policy.named_checks().adopted_feed_revisions();
    result["assessment_id"] = json!(digest(&result["input_identity"]));
    result["current_state"] = json!({"active_source_revision":active_revision,"saved_source_revision":saved_revision,
        "captured_inputs_match_active":inputs_match,
        "assessment_inputs":"current adopted lists, service definitions and applicable temporary grants; original authorized projection is separate",
        "base_matches_active":active_revision.as_deref() == retained.metadata["saved_source_revision"].as_str(),
        "base_matches_saved":saved_revision == retained.metadata["saved_source_revision"],
        "saved_matches_active":active_revision.as_deref() == Some(saved_revision.as_str()),
        "observed_at_ms":crate::policy::current_time_ms(),
        "final_revalidation":"The adoption owner must revalidate the candidate, base, grants and definitions at decision. This read grants no apply authority."});
    if materialized.is_none() {
        result["authorized_projection"] = authorized_projection(retained, input)?;
    }
    Ok(result)
}
