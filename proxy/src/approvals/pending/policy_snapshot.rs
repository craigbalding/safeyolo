//! Full-source disclosure is a human decision over a private retained snapshot.

use super::*;
use crate::{
    audit::{Approval, ApprovalType, Kind, Severity},
    host_runs::AgentRun,
    policy::snapshot::{RetainedPolicySnapshot, source_revision},
};

fn instance_id(config: &crate::Config) -> Result<String> {
    let data = config
        .data_dir
        .as_ref()
        .ok_or_else(|| invalid("local instance data directory unavailable"))?;
    let id = std::fs::read_to_string(data.join("instance_id")).map_err(unavailable)?;
    if id.trim().is_empty() {
        return Err(invalid("local instance identity unavailable"));
    }
    Ok(id.trim().to_owned())
}

fn owner(record: &Record, policy: &Policy, run: &AgentRun) -> bool {
    record.authority.action["kind"] == "policy_snapshot"
        && record.authority.action["run"] == json!(run)
        && context::owner(policy, record, &run.agent)
        && run.current(policy)
}

fn current(state: &crate::RuntimeState, record: &Record) -> Result<bool> {
    let path = state
        .read()
        .map_err(unavailable)?
        .config
        .policy_file
        .clone()
        .ok_or_else(|| invalid("policy source unavailable"))?;
    let _lock = super::super::lock_policy(&path).map_err(unavailable)?;
    let runtime = state.read().map_err(unavailable)?;
    let policy = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let run: AgentRun =
        serde_json::from_value(record.authority.action["run"].clone()).map_err(unavailable)?;
    let saved = zeroize::Zeroizing::new(std::fs::read_to_string(&path).map_err(unavailable)?);
    Ok(owner(record, policy, &run)
        && record.authority.action["snapshot"]["instance_id"] == instance_id(&runtime.config)?
        && policy.native_source_text().map(source_revision).as_deref()
            == record.authority.action["snapshot"]["active_source_revision"].as_str()
        && source_revision(&saved) == record.authority.action["snapshot"]["saved_source_revision"])
}

pub(crate) fn request(
    state: &crate::RuntimeState,
    writer: &Writer,
    run: &AgentRun,
    operation_id: &str,
) -> Result<Record> {
    if !crate::agent_api::valid_request_id(operation_id) {
        return Err(invalid(
            "operation_id must be a req- identifier chosen before submission",
        ));
    }
    if let Some(record) = writer.approvals().get(operation_id)? {
        let runtime = state.read().map_err(unavailable)?;
        if !runtime
            .policy
            .as_deref()
            .is_some_and(|policy| owner(&record, policy, run))
        {
            return Err(invalid("snapshot request unavailable"));
        }
        return Ok(record);
    }
    let path = state
        .read()
        .map_err(unavailable)?
        .config
        .policy_file
        .clone()
        .ok_or_else(|| invalid("policy source unavailable"))?;
    let (snapshot, policy) = {
        let _lock = super::super::lock_policy(&path).map_err(unavailable)?;
        let runtime = state.read().map_err(unavailable)?;
        let policy = runtime
            .policy
            .clone()
            .ok_or_else(|| invalid("policy unavailable"))?;
        if !run.current(&policy) {
            return Err(invalid("trusted current-run requester identity required"));
        }
        let source = zeroize::Zeroizing::new(std::fs::read_to_string(&path).map_err(unavailable)?);
        let snapshot = policy
            .full_snapshot(&source, &path, &instance_id(&runtime.config)?, run)
            .map_err(|_| invalid("full authored policy snapshot unavailable"))?;
        (snapshot, policy)
    };
    let reference = snapshot.reference();
    let basis_revision = digest(&reference);
    let action = json!({"kind":"policy_snapshot","agent":run.agent,"agent_id":run.agent_id,
        "run":run,"basis_revision":basis_revision,"snapshot":reference});
    let authority = Authority {
        action, revision:basis_revision, method:"POST".into(),scheme:"http".into(),port:None,
        resource_digest:snapshot.metadata["snapshot_id"].as_str().unwrap_or("").into(),
        options:vec![OptionScope {id:"snapshot".into(),
            effect:"Disclose this complete authored local policy snapshot, with literal credential redactions, to this requester/run. No future revision, policy application or additional permission is approved.".into(),
            session_id:None,parameters:Value::Null}],
        expires_at:None,credential_bindings:Default::default(),
    };
    // Snapshot data and its approval are committed together. Never put source
    // or restoration values in the public approval/action/result record.
    writer
        .approvals()
        .submit_retained(authority, operation_id, &policy, "pending", Some(&snapshot))
}

pub(crate) fn approval_view(
    writer: &Writer,
    policy: &Policy,
    record: &Record,
    state: Option<&crate::RuntimeState>,
) -> Result<Value> {
    let mut view = record.view(policy)?;
    if record.status == "pending" {
        match state.map(|state| current(state, record)).transpose()? {
            Some(true) => {}
            Some(false) => {
                view["status"] = json!("superseded");
                view["approval"]["required"] = json!(false);
            }
            None => {
                view["status"] = json!("unavailable");
                view["approval"]["required"] = json!(false);
            }
        }
    }
    view["snapshot"] = record.authority.action["snapshot"].clone();
    let option_status = if view["status"] == "pending" {
        "available".to_owned()
    } else {
        view["status"].as_str().unwrap_or("unavailable").to_owned()
    };
    for option in view["options"].as_array_mut().into_iter().flatten() {
        option["status"] = json!(option_status);
    }
    view["approval"]["required"] = json!(view["status"] == "pending");
    view["request_history"] = writer.approvals().request_history(record)?;
    view["attention"] = json!(record.attention);
    view["result_delivery"] = record.result_delivery.view();
    Ok(view)
}

pub(crate) fn read_snapshot(
    state: &crate::RuntimeState,
    writer: &Writer,
    run: &AgentRun,
    id: &str,
) -> Result<Option<Value>> {
    let Some(record) = writer.approvals().get(id)? else {
        return Ok(None);
    };
    let policy = {
        let runtime = state.read().map_err(unavailable)?;
        let policy = runtime
            .policy
            .clone()
            .ok_or_else(|| invalid("policy unavailable"))?;
        if !owner(&record, &policy, run)
            || record.authority.action["snapshot"]["instance_id"] != instance_id(&runtime.config)?
        {
            return Ok(None);
        }
        policy
    };
    let mut result = approval_view(writer, &policy, &record, Some(state))?;
    if record.status != "approved" {
        return Ok(Some(result));
    }
    if record
        .decided_at
        .is_none_or(|at| results::now() >= at.saturating_add(results::RETAIN_SECONDS))
    {
        result["status"] = json!("expired");
        return Ok(Some(result));
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
        zeroize::Zeroizing::new(encoded.ok_or_else(|| invalid("retained snapshot unavailable"))?);
    let snapshot: RetainedPolicySnapshot = serde_json::from_str(&encoded).map_err(unavailable)?;
    let restored = snapshot
        .materialize(&snapshot.disclosed_source)
        .map_err(unavailable)?;
    if snapshot.reference() != record.authority.action["snapshot"]
        || source_revision(&restored) != snapshot.metadata["saved_source_revision"]
        || source_revision(&snapshot.disclosed_source)
            != snapshot.metadata["disclosed_source_revision"]
    {
        return Err(invalid(
            "retained snapshot identity differs from approved source",
        ));
    }
    // Recheck after the blocking private read/materialization, before releasing
    // source. A replacement while that read waited cannot inherit disclosure.
    let runtime = state.read().map_err(unavailable)?;
    let current = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    if !owner(&record, current, run)
        || snapshot.metadata["instance_id"] != instance_id(&runtime.config)?
    {
        return Ok(None);
    }
    result["snapshot"] = snapshot.disclosed();
    Ok(Some(result))
}

pub(crate) fn resolve(
    state: &crate::RuntimeState,
    writer: &Writer,
    id: &str,
    decision: super::super::network_action::Decision,
    option: Option<&str>,
    reviewer: Option<(&crate::peer_support::Caller, &str)>,
) -> Result<(u16, Value)> {
    // DOC: docs/policy-snapshots.md docs/operator-guide.md
    if reviewer.is_some() {
        return Err(invalid(
            "full policy disclosure requires the human operator's decision",
        ));
    }
    let record = writer
        .approvals()
        .decide(id, |record| {
            if record.status != "pending" {
                return Ok(());
            }
            if option.is_some_and(|option| option != "snapshot") {
                return Err(invalid("select the snapshot disclosure option"));
            }
            if !current(state, record)? {
                record.status = "superseded".into();
            } else {
                record.status = match decision {
                    super::super::network_action::Decision::Approve => "approved",
                    super::super::network_action::Decision::Reject => "rejected",
                }
                .into();
                record.option = Some("snapshot".into());
            }
            record.result = json!({"snapshot_id":record.authority.action["snapshot"]["snapshot_id"],
            "permission_changed":false,"policy_changed":false,"decided_by":{"kind":"operator"}});
            Ok(())
        })?
        .ok_or_else(|| invalid("snapshot request unavailable"))?;
    let policy = active_policy(state)?;
    let mut view = approval_view(writer, &policy, &record, Some(state))?;
    // The approval owner retains terminal identity and outcomes. Public audit
    // and private result attention carry references, never the authored source.
    if writer
        .emit(event(&record, "admin.policy_snapshot_decided"))
        .is_err()
    {
        view["audit_status"] = json!("unavailable; canonical disclosure decision is retained");
    }
    Ok((200, view))
}

pub(crate) fn event(record: &Record, name: &'static str) -> Event {
    let mut event = Event::new(
        name,
        if name == "agent.policy_snapshot_requested" {
            Kind::Agent
        } else {
            Kind::Admin
        },
        Severity::High,
        "Local full-policy snapshot disclosure",
    );
    event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
    event.request_id = Some(record.request_id.clone());
    let requested = name == "agent.policy_snapshot_requested";
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
    event.approval = Some(Approval {
        required: record.status == "pending",
        approval_type: ApprovalType::PolicySnapshot,
        key: record.approval_id.clone(),
        target: record.authority.action["snapshot"]["instance_id"]
            .as_str()
            .unwrap_or("")
            .into(),
        scope_hint: json!({"snapshot_id":record.authority.action["snapshot"]["snapshot_id"]})
            .into(),
    });
    event.details =
        json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
        "snapshot_id":record.authority.action["snapshot"]["snapshot_id"],"outcome":record.status})
        .into();
    event
}
