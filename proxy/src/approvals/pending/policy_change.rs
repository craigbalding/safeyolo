//! Exact human decisions over retained policy candidates. Private bytes live
//! with pending approvals; the policy file remains the authoritative source.
use super::*;
use crate::{
    host_runs::AgentRun,
    policy::snapshot::{RetainedPolicySnapshot, source_revision},
    services::effects::policy::Candidate,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Submission {
    pub operation_id: String,
    pub candidate: Candidate,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained {
    snapshot: RetainedPolicySnapshot,
    candidate: Candidate,
    materialized: String,
    assessment: Value,
}

impl Drop for Retained {
    fn drop(&mut self) {
        self.materialized.zeroize();
        crate::credentials::wipe_json(&mut self.assessment);
    }
}

fn retained(writer: &Writer, record: &Record) -> Result<Retained> {
    if record.authority.action["kind"] != "policy_change"
        || record
            .authority
            .expires_at
            .as_deref()
            .is_some_and(|expiry| expired_at(Some(expiry), time::OffsetDateTime::now_utc()))
        || record
            .decided_at
            .is_some_and(|at| results::now() >= at.saturating_add(results::RETAIN_SECONDS))
    {
        return Err(invalid("retained policy candidate unavailable or expired"));
    }
    let encoded: Option<String> = writer
        .approvals()
        .connect()?
        .query_row(
            "SELECT record FROM policy_snapshots WHERE approval_id=?1",
            [&record.approval_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(unavailable)?;
    let encoded =
        Zeroizing::new(encoded.ok_or_else(|| invalid("retained policy candidate unavailable"))?);
    let retained: Retained = serde_json::from_str(&encoded).map_err(unavailable)?;
    if source_revision(&retained.candidate.source) != record.authority.action["candidate_revision"]
        || source_revision(&retained.materialized)
            != record.authority.action["materialized_revision"]
        || !retained
            .snapshot
            .matches_reference(&record.authority.action["base"])
        || digest(&retained.assessment["input_identity"])
            != record.authority.action["assessment_id"]
    {
        return Err(invalid(
            "retained candidate differs from the reviewed identity",
        ));
    }
    Ok(retained)
}

fn current_grants(policy: &Policy, grants: &[crate::grants::Grant]) -> Vec<crate::grants::Grant> {
    grants
        .iter()
        .filter(|grant| {
            !grant.is_expired(time::OffsetDateTime::now_utc())
                && grant.delegated.as_ref().is_none_or(|encoded| {
                    serde_json::from_str::<crate::policy::delegation::IssuedAccess>(encoded)
                        .is_ok_and(|issued| issued.active(policy))
                })
        })
        .cloned()
        .collect()
}

fn review(
    retained: &Retained,
    policy: &Policy,
    saved: &str,
    grants: &[crate::grants::Grant],
    restore: bool,
) -> Result<Value> {
    policy_assessment::operator_materialized(
        &retained.snapshot,
        &retained.candidate,
        policy,
        saved,
        &current_grants(policy, grants),
        restore.then_some(retained.materialized.as_str()),
    )
}

fn dependencies_ready(data: &Retained, assessment: &Value) -> bool {
    assessment["valid"] == true
        && data
            .snapshot
            .adoption_references_allowed(&data.materialized)
        && !assessment["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|input| {
                input["status"].as_str().is_none_or(|status| {
                    status.contains("trusted_adoption_required") || status.contains("undisclosed")
                })
            })
}

fn base_current(runtime: &crate::Runtime, saved: &str, record: &Record) -> Result<bool> {
    let policy = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let action = &record.authority.action;
    let requester_current = if action["initiator"] == "operator" {
        true
    } else {
        serde_json::from_value::<AgentRun>(action["run"].clone())
            .is_ok_and(|run| run.current(policy))
    };
    Ok(requester_current
        && action["base"]["instance_id"] == policy_snapshot::instance_id(&runtime.config)?
        && source_revision(saved) == action["base"]["saved_source_revision"]
        && policy.native_source_text().map(source_revision).as_deref()
            == action["base"]["active_source_revision"].as_str())
}

fn retain(
    writer: &Writer,
    policy: &Policy,
    run: &AgentRun,
    operation: &str,
    data: &Retained,
    restore_of: Option<&str>,
) -> Result<Record> {
    let basis = json!({"base":data.snapshot.reference(),
        "candidate_revision":source_revision(&data.candidate.source),"materialized_revision":source_revision(&data.materialized),
        "assessment_id":data.assessment["assessment_id"],"restore_of":restore_of});
    let revision = digest(&basis);
    let action = json!({"kind":"policy_change","agent":run.agent,"agent_id":run.agent_id,
        "run":if restore_of.is_some(){Value::Null}else{json!(run)},
        "initiator":if restore_of.is_some(){"operator"}else{"agent"},
        "basis_revision":revision,"base":basis["base"],"candidate_revision":basis["candidate_revision"],
        "materialized_revision":basis["materialized_revision"],"assessment_id":basis["assessment_id"],
        "snapshot_request_id":data.candidate.snapshot_request_id,"definition_version":data.candidate.definition_version,
        "restore_of":restore_of});
    let authority = Authority { action, revision, method:"POST".into(),scheme:"http".into(),port:None,
        resource_digest:source_revision(&data.materialized),
        options:vec![OptionScope {id:"apply".into(),effect:
            "Save and activate this exact complete local policy candidate under the current human decision. Inspect the trusted consequences and complete redacted source diff. No agent may approve it. A later restore requires a new candidate bound to its current base; policy restoration cannot undo disclosures or external effects.".into(),session_id:None,parameters:Value::Null}],
        expires_at:Some((time::OffsetDateTime::now_utc()+time::Duration::seconds(results::RETAIN_SECONDS)).format(&time::format_description::well_known::Rfc3339).map_err(unavailable)?),
        credential_bindings:Default::default() };
    let encoded = Zeroizing::new(serde_json::to_string(data).map_err(unavailable)?);
    writer
        .approvals()
        .submit_retained(authority, operation, policy, "pending", Some(&encoded))
}

pub(crate) fn submit(
    state: &crate::RuntimeState,
    writer: &Writer,
    run: &AgentRun,
    input: &Submission,
) -> Result<Record> {
    if !crate::agent_api::valid_request_id(&input.operation_id) {
        return Err(invalid("choose a req- operation_id before submitting"));
    }
    if let Some(record) = writer.approvals().get(&input.operation_id)? {
        let runtime = state.read().map_err(unavailable)?.clone();
        if !requester(&runtime, &record, run)?
            || record.authority.action["candidate_revision"]
                != source_revision(&input.candidate.source)
            || record.authority.action["snapshot_request_id"] != input.candidate.snapshot_request_id
            || record.authority.action["definition_version"] != input.candidate.definition_version
        {
            return Err(invalid(
                "changed or unavailable submission; use its original exact input",
            ));
        }
        return Ok(record);
    }
    // The same private preparation boundary authorizes source and marker use.
    policy_assessment::private(state, writer, run, &input.candidate)?;
    let snapshot = policy_assessment::snapshot(writer, &input.candidate)?;
    let materialized = snapshot
        .materialize(&input.candidate.source)
        .map_err(|_| invalid("candidate preservation failed"))?;
    let assessment = policy_assessment::operator(state, writer, &input.candidate)?;
    let runtime = state.read().map_err(unavailable)?.clone();
    let policy = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    if !run.current(policy)
        || snapshot.metadata["instance_id"] != policy_snapshot::instance_id(&runtime.config)?
    {
        return Err(invalid("approved snapshot unavailable"));
    }
    let data = Retained {
        snapshot,
        candidate: input.candidate.clone(),
        materialized: materialized.to_string(),
        assessment,
    };
    if !dependencies_ready(&data, &data.assessment) {
        return Err(invalid(
            "candidate is invalid or needs its existing trusted dependency adoption path; no approval was submitted",
        ));
    }
    retain(writer, policy, run, &input.operation_id, &data, None)
}

fn requester(runtime: &crate::Runtime, record: &Record, run: &AgentRun) -> Result<bool> {
    Ok(record.authority.action["kind"] == "policy_change"
        && record.authority.action["run"] == json!(run)
        && runtime
            .policy
            .as_deref()
            .is_some_and(|policy| run.current(policy))
        && record.authority.action["base"]["instance_id"]
            == policy_snapshot::instance_id(&runtime.config)?)
}

/// Safe on shared approval reads: no current policy, model, source or grant
/// content from the operator's review enters this projection.
pub(crate) fn view(writer: &Writer, policy: &Policy, record: &Record) -> Result<Value> {
    let mut view = record.view(policy)?;
    let status = if view["status"] == "pending" {
        json!("available")
    } else {
        view["status"].clone()
    };
    for option in view["options"].as_array_mut().into_iter().flatten() {
        option["status"] = status.clone();
    }
    view["request_history"] = writer.approvals().request_history(record)?;
    view["attention"] = json!(record.attention);
    view["result_delivery"] = record.result_delivery.view();
    view["recovery"] = json!(
        "Read this canonical request after a lost reply. An applying or unresolved result grants no retry. A stale candidate needs a fresh approved snapshot, preparation and human decision."
    );
    Ok(view)
}

pub(crate) fn read_agent(
    state: &crate::RuntimeState,
    writer: &Writer,
    run: &AgentRun,
    id: &str,
) -> Result<Option<Value>> {
    let Some(record) = recover(state, writer, id)? else {
        return Ok(None);
    };
    let runtime = state.read().map_err(unavailable)?.clone();
    if !requester(&runtime, &record, run)? {
        return Ok(None);
    }
    view(
        writer,
        runtime
            .policy
            .as_deref()
            .ok_or_else(|| invalid("policy unavailable"))?,
        &record,
    )
    .map(Some)
}

pub(crate) fn operator_view(
    state: &crate::RuntimeState,
    writer: &Writer,
    id: &str,
) -> Result<Value> {
    let record = recover(state, writer, id)?.ok_or_else(|| invalid("policy change unavailable"))?;
    let policy = active_policy(state)?;
    let mut view = view(writer, &policy, &record)?;
    let runtime = state.read().map_err(unavailable)?.clone();
    let path = runtime
        .config
        .policy_file
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let source = Zeroizing::new(std::fs::read_to_string(path).map_err(unavailable)?);
    let saved = source_revision(&source);
    let active = policy.native_source_text().map(source_revision);
    view["observed_policy_state"] = json!({"saved_source_revision":saved,"active_source_revision":active,
        "saved_matches_active":active.as_deref()==Some(saved.as_str()),
        "recorded_result_is_current":record.result["saved_source_revision"]==saved && record.result["active_source_revision"].as_str()==active.as_deref()});
    match retained(writer, &record) {
        Ok(data) => {
            if record.status == "pending" {
                let grants = runtime
                    .gateway_grants
                    .as_ref()
                    .map(|store| store.current_grants_for_report(time::OffsetDateTime::now_utc()))
                    .transpose()?
                    .unwrap_or_default()
                    .into_iter()
                    .map(|entry| entry.grant)
                    .collect::<Vec<_>>();
                let current = review(
                    &data,
                    &policy,
                    &source,
                    &grants,
                    !record.authority.action["restore_of"].is_null(),
                );
                let matches = current.is_ok_and(|current| {
                    current["input_identity"] == data.assessment["input_identity"]
                }) && base_current(&runtime, &source, &record)?;
                view["reviewed_inputs_match_current"] = json!(matches);
                if !matches {
                    view["status"] = json!("stale");
                    view["approval"]["required"] = json!(false);
                    for option in view["options"].as_array_mut().into_iter().flatten() {
                        option["status"] = json!("stale");
                    }
                }
            }
            view["assessment"] = data.assessment.clone();
            view["assessment"]["summary"] = json!(
                "Trusted read-only assessment retained for this exact submission. The canonical status and result identify the decision and activation outcome. Inspect the complete diff, authority and limitations before deciding."
            );
            view["prior_revision"] = data.snapshot.disclosed();
            view["review_content"] = json!(
                "Host-computed consequences and complete redacted before/after source. Authored comments and rationale are untrusted. Hidden fields are preserved; a restore explicitly reinstates the retained prior content."
            );
        }
        Err(_) => {
            view["review_content"] = json!(
                "Private candidate/prior source unavailable or expired. Canonical outcome metadata remains; no decision can apply missing content."
            )
        }
    }
    Ok(view)
}

/// Recover only an interrupted owner from a previous proxy session. Never
/// reapply. A consistent exact file/live pair is evidence; other states stay
/// explicitly unresolved for the operator's ordinary policy recovery.
fn recover(state: &crate::RuntimeState, writer: &Writer, id: &str) -> Result<Option<Record>> {
    let Some(record) = writer.approvals().get(id)? else {
        return Ok(None);
    };
    if record.authority.action["kind"] != "policy_change" {
        return Ok(None);
    }
    if record.status != "applying"
        || record.result["owner_session"] == writer.approvals().session_id
    {
        return Ok(Some(record));
    }
    let path = state
        .read()
        .map_err(unavailable)?
        .config
        .policy_file
        .clone()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let runtime = state.read().map_err(unavailable)?.clone();
    let source = Zeroizing::new(std::fs::read_to_string(&path).map_err(unavailable)?);
    let saved = source_revision(&source);
    let active = runtime
        .policy
        .as_deref()
        .and_then(Policy::native_source_text)
        .map(source_revision);
    writer.approvals().decide(id, |current| {
        if current.status != "applying" || current.result["owner_session"] == writer.approvals().session_id { return Ok(()); }
        let applied = current.authority.action["materialized_revision"].as_str() == Some(saved.as_str()) && active.as_deref() == Some(saved.as_str());
        let unchanged = current.authority.action["base"]["saved_source_revision"] == saved
            && current.authority.action["base"]["active_source_revision"].as_str() == active.as_deref();
        current.status = if applied { "approved" } else if unchanged { "failed" } else { "unresolved" }.into();
        current.result = json!({"status":if applied{"active"}else if unchanged{"interrupted_before_apply"}else{"unresolved"},
            "saved_source_revision":saved,"active_source_revision":active,"recovered":true,
            "policy_changed":if applied{json!(true)}else if unchanged{json!(false)}else{Value::Null},
            "next_action":if applied||unchanged{Value::Null}else{json!("Inspect saved/active policy with policy show; do not replay. Prepare a new reviewed candidate or use the operator policy repair path.")}});
        Ok(())
    })
}

pub(crate) fn resolve(
    state: &crate::RuntimeState,
    writer: &Writer,
    id: &str,
    decision: super::super::network_action::Decision,
    option: Option<&str>,
    reviewer: Option<(&crate::peer_support::Caller, &str)>,
) -> Result<(u16, Value)> {
    if reviewer.is_some() {
        // DOC: docs/policy-adoption.md
        return Err(invalid(
            "full policy adoption requires the human operator's decision",
        ));
    }
    if option.is_some_and(|option| option != "apply") {
        return Err(invalid("select the exact policy apply option"));
    }
    let original =
        recover(state, writer, id)?.ok_or_else(|| invalid("policy change unavailable"))?;
    if original.status != "pending" {
        return decision_view(state, writer, id);
    }
    let data = retained(writer, &original)?;
    let mut selected = false;
    writer.approvals().decide(id, |record| {
        if record.status != "pending" { return Ok(()); }
        selected = true;
        record.option = Some("apply".into());
        record.status = if matches!(decision, super::super::network_action::Decision::Reject) { "rejected" } else { "applying" }.into();
        record.result = json!({"status":record.status,"decided_by":{"kind":"operator"},"owner_session":writer.approvals().session_id,"policy_changed":false});
        Ok(())
    })?;
    if !selected || matches!(decision, super::super::network_action::Decision::Reject) {
        return decision_view(state, writer, id);
    }
    let stale = std::cell::Cell::new(false);
    let outcome = crate::adopt_native_policy(
        state,
        |saved, runtime, grants| {
            let policy = runtime
                .policy
                .as_deref()
                .ok_or_else(|| invalid("policy unavailable"))?;
            if original.expired()
                || data.candidate.definition_version != env!("SAFEYOLO_DEFINITION_VERSION")
                || !base_current(runtime, saved, &original)?
            {
                stale.set(true);
                return Err(invalid(
                    "policy base, requester, retention or installed definitions changed; prepare a fresh candidate and review",
                ));
            }
            let assessment = review(
                &data,
                policy,
                saved,
                grants,
                !original.authority.action["restore_of"].is_null(),
            )?;
            if !base_current(runtime, saved, &original)?
                || assessment["input_identity"] != data.assessment["input_identity"]
            {
                stale.set(true);
                return Err(invalid(
                    "policy candidate is stale; prepare a fresh candidate and human review",
                ));
            }
            if !dependencies_ready(&data, &assessment) {
                return Err(invalid(
                    "candidate dependencies require their existing trusted adoption path before submission",
                ));
            }
            // Only already authorized references reach the native loader. Compare
            // the actually loaded list contents too, before any policy save.
            let candidate = policy
                .reload_native_source(
                    &data.materialized,
                    runtime
                        .config
                        .policy_file
                        .as_deref()
                        .ok_or_else(|| invalid("policy unavailable"))?,
                )
                .map_err(|_| {
                    stale.set(true);
                    invalid("materialized validity or adopted inputs changed; prepare a fresh candidate and review")
                })?;
            if !data.snapshot.adoption_inputs_match(&candidate)
                || candidate
                    .named_checks()
                    .adopted_feed_revisions()
                    .as_object()
                    .into_iter()
                    .flatten()
                    .any(|(name, revision)| {
                        data.assessment["input_identity"]["check_feeds"][name] != *revision
                    })
            {
                stale.set(true);
                return Err(invalid(
                    "adopted input changed; prepare a fresh candidate and review",
                ));
            }
            if !base_current(runtime, saved, &original)? {
                stale.set(true);
                return Err(invalid(
                    "requester or policy base changed during preparation",
                ));
            }
            Ok((data.materialized.clone(), candidate))
        },
        || {
            writer.approvals().decide(id, |record| {
            if record.status != "applying" || record.authority_digest != original.authority_digest { return Err(invalid("policy decision changed during adoption")); }
            record.status = "approved".into();
            record.result = json!({"status":"active","policy_changed":true,"decided_by":{"kind":"operator"},
                "candidate_revision":record.authority.action["candidate_revision"],
                "saved_source_revision":record.authority.action["materialized_revision"],"active_source_revision":record.authority.action["materialized_revision"],
                "saved_matches_active":true,"activation_required":false});
            Ok(())
        })?.ok_or_else(|| invalid("canonical policy receipt unavailable"))?;
            Ok(())
        },
    );
    if let Err(error) = outcome {
        writer.approvals().decide(id, |record| {
            if matches!(record.status.as_str(), "applying" | "approved") {
                record.status = if stale.get() { "stale" } else if error.kind == super::super::ErrorKind::Rollback { "unresolved" } else { "failed" }.into();
                record.result = json!({"status":record.status,"policy_changed":if error.kind==super::super::ErrorKind::Rollback{Value::Null}else{json!(false)},
                    "error":error.to_string(),"decided_by":{"kind":"operator"},
                    "next_action":"Inspect policy show and this canonical receipt. Stale/failed candidates need fresh preparation and review. An unresolved recovery requires operator policy repair; never replay the decision."});
            }
            Ok(())
        })?;
    }
    decision_view(state, writer, id)
}

fn decision_view(state: &crate::RuntimeState, writer: &Writer, id: &str) -> Result<(u16, Value)> {
    let mut view = operator_view(state, writer, id)?;
    let decided = writer
        .approvals()
        .get(id)?
        .ok_or_else(|| invalid("canonical decision unavailable"))?;
    if writer
        .emit(event(&decided, "admin.policy_change_decided"))
        .is_err()
    {
        view["audit_status"] =
            json!("unavailable; the canonical decision and outcome are retained");
    }
    Ok((200, view))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Restore {
    pub operation_id: String,
    pub proposal_id: String,
}

/// A restore is another exact candidate and human decision against the current
/// base, never a write of an old file over an intervening edit.
pub(crate) fn restore(
    state: &crate::RuntimeState,
    writer: &Writer,
    input: &Restore,
) -> Result<Value> {
    if !crate::agent_api::valid_request_id(&input.operation_id) {
        return Err(invalid(
            "choose a req- operation_id before preparing restore",
        ));
    }
    if let Some(record) = writer.approvals().get(&input.operation_id)? {
        if record.authority.action["restore_of"] != input.proposal_id {
            return Err(invalid("changed restore requires a new operation_id"));
        }
        return operator_view(state, writer, &record.approval_id);
    }
    let original = writer
        .approvals()
        .get(&input.proposal_id)?
        .ok_or_else(|| invalid("prior revision unavailable"))?;
    let prior = retained(writer, &original)?;
    let path = state
        .read()
        .map_err(unavailable)?
        .config
        .policy_file
        .clone()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let runtime = state.read().map_err(unavailable)?.clone();
    let policy = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let saved = Zeroizing::new(std::fs::read_to_string(&path).map_err(unavailable)?);
    let run: AgentRun =
        serde_json::from_value(original.authority.action["base"]["requester"].clone())
            .map_err(unavailable)?;
    let snapshot = policy
        .full_snapshot(
            &saved,
            &path,
            &policy_snapshot::instance_id(&runtime.config)?,
            &run,
        )
        .map_err(|_| invalid("current policy snapshot unavailable"))?;
    let source = prior
        .snapshot
        .materialize(&prior.snapshot.disclosed_source)
        .map_err(|_| invalid("prior policy restoration unavailable"))?;
    let candidate = Candidate {
        snapshot_request_id: input.proposal_id.clone(),
        source: source.to_string(),
        definition_version: env!("SAFEYOLO_DEFINITION_VERSION").into(),
    };
    let grants = runtime
        .gateway_grants
        .as_ref()
        .map(|store| store.current_grants_for_report(time::OffsetDateTime::now_utc()))
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .map(|entry| entry.grant)
        .collect::<Vec<_>>();
    let mut data = Retained {
        snapshot,
        candidate,
        materialized: source.to_string(),
        assessment: Value::Null,
    };
    data.assessment = review(&data, policy, &saved, &grants, true)?;
    let record = retain(
        writer,
        policy,
        &run,
        &input.operation_id,
        &data,
        Some(&input.proposal_id),
    )?;
    drop(runtime);
    writer
        .emit(event(&record, "admin.policy_restore_prepared"))
        .map_err(unavailable)?;
    operator_view(state, writer, &record.approval_id)
}

pub(crate) fn event(record: &Record, name: &'static str) -> Event {
    let requested = name == "agent.policy_change_submitted";
    let mut event = Event::new(
        name,
        if requested {
            crate::audit::Kind::Agent
        } else {
            crate::audit::Kind::Admin
        },
        crate::audit::Severity::High,
        "Exact local policy change requires a human decision",
    );
    event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
    event.request_id = Some(record.request_id.clone());
    event.attribution = Some(crate::audit::Attribution {
        evidence_owner: event.agent.clone(),
        trusted_transport_identity: if requested { event.agent.clone() } else { None },
        initiator: Some(if requested {
            crate::audit::Initiator::Agent
        } else {
            crate::audit::Initiator::Operator
        }),
        status: Some(crate::audit::AttributionStatus::Resolved),
        provenance: None,
    });
    event.approval = Some(crate::audit::Approval {
        required: record.status == "pending",
        approval_type: crate::audit::ApprovalType::PolicyChange,
        key: record.approval_id.clone(),
        target: record.authority.action["base"]["instance_id"]
            .as_str()
            .unwrap_or("")
            .into(),
        scope_hint: json!({"candidate_revision":record.authority.action["candidate_revision"]})
            .into(),
    });
    event.details =
        json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
        "candidate_revision":record.authority.action["candidate_revision"],"outcome":record.status})
        .into();
    event
}
