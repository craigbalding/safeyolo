//! Diagnostic requests and decisions remain in the canonical approval owner.
use super::*;
use crate::{
    host_runs::AgentRun,
    policy::support::{Grant, diagnostics::Scope},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub operation_id: String,
    pub instance_id: String,
    pub subjects: Vec<String>,
    pub scope: Scope,
    pub expires_at: Option<String>,
    pub reason: String,
}

pub(crate) fn revision(policy: &Policy, action: &Value) -> Option<String> {
    let grant: Grant = serde_json::from_value(action["grant"].clone()).ok()?;
    let instance = crate::peer_support::events::instance(policy.identity_root()?).ok()?;
    if grant.instance_id != instance
        || policy.evidence_agent_id(&grant.support.name) != Some(&grant.support.agent_id)
        || grant
            .targets
            .iter()
            .any(|a| policy.evidence_agent_id(&a.name) != Some(&a.agent_id))
    {
        return None;
    }
    Some(digest(&json!([instance, grant.support, grant.targets])))
}

pub(crate) fn submit(
    writer: &Writer,
    policy: &Policy,
    run: &AgentRun,
    input: Request,
) -> Result<Record> {
    if !run.current(policy)
        || input.instance_id != crate::peer_support::instance_id().map_err(unavailable)?
    {
        return Err(invalid(
            "current requester run and owning instance required",
        ));
    }
    if !crate::peer_support::operations::valid_operation_id(&input.operation_id)
        || input.reason.trim().is_empty()
        || input.reason.len() > context::MAX_FIELD_BYTES
    {
        return Err(invalid(
            "supply operation_id and a short untrusted reason without credentials",
        ));
    }
    input.scope.validate().map_err(unavailable)?;
    if !input.scope.rooms.is_empty() {
        let root = policy
            .identity_root()
            .ok_or_else(|| invalid("owning Coord identity unavailable"))?;
        let conn = crate::coord_rooms::open(root)
            .map_err(|_| invalid("selected Coord source unavailable"))?;
        for room in &input.scope.rooms {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM rooms WHERE room_id=?1)",
                    [&room.room_id],
                    |row| row.get(0),
                )
                .map_err(|_| invalid("selected Coord source unavailable"))?;
            if !exists {
                return Err(invalid("select an existing canonical local room ID"));
            }
        }
    }
    let targets = input
        .subjects
        .iter()
        .map(|name| {
            let id = policy
                .evidence_agent_id(name)
                .ok_or_else(|| invalid("selected subject has no current durable identity"))?;
            Ok(crate::policy::delegation::Agent {
                name: name.clone(),
                agent_id: id.into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let grant = Grant {
        instance_id: input.instance_id,
        support: crate::policy::delegation::Agent {
            name: run.agent.clone(),
            agent_id: run.agent_id.clone(),
        },
        support_instance_id: None,
        support_peer_epoch: None,
        targets,
        guest_admin: false,
        guest_logs: Vec::new(),
        lifecycle: Vec::new(),
        notifications: Vec::new(),
        signal_rooms: Vec::new(),
        factory_directions: Vec::new(),
        diagnostics: Some(input.scope),
        expires_at: input.expires_at,
        acknowledgment: None,
    };
    grant.validate().map_err(unavailable)?;
    if grant
        .expires_at
        .as_deref()
        .is_some_and(|expiry| crate::policy::delegation::expired(Some(expiry)))
    {
        return Err(invalid(
            "select a future access expiry or null for until revoked",
        ));
    }
    let action = json!({"kind":"diagnostic_disclosure","agent":run.agent,"agent_id":run.agent_id,"run":run,"grant":grant});
    let authority = Authority {
        revision:revision(policy,&action).ok_or_else(||invalid("diagnostic identities unavailable"))?,
        action, method:"POST".into(),scheme:"agent-api".into(),port:None,
        resource_digest:digest(&json!([run.agent_id,input.operation_id])),
        options:vec![OptionScope {id:"diagnostics".into(),session_id:None,parameters:Value::Null,
            effect:"Read only the selected local diagnostic subjects, sources and historical range. A snapshot freezes one bounded collection; retained results expire after seven days. Temporary and until-revoked access may include future records only when selected. Every read checks current host-held authority. No room send, policy change, lifecycle or guest administration permission is added. Already disclosed bytes cannot be recalled. Narrow or revoke through this owner's existing support grant controls.".into()}],
        expires_at:None,credential_bindings:Default::default(),
    };
    let id = format!(
        "req-{}",
        &digest(&json!(["diagnostics", run.agent_id, input.operation_id]))[..32]
    );
    let record = writer.approvals().submit(authority, &id, policy)?;
    writer
        .approvals()
        .decide(&record.approval_id, |record| {
            if record.status == "pending" && record.untrusted_reason_text.is_none() {
                record.untrusted_reason_text = Some(input.reason);
            }
            Ok(())
        })?
        .ok_or_else(|| invalid("canonical diagnostic approval unavailable"))
}

pub(super) fn issue(state: &crate::RuntimeState, record: &mut Record) -> Result<()> {
    let mut grant: Grant = serde_json::from_value(
        record
            .result
            .get("diagnostic_selection")
            .unwrap_or(&record.authority.action["grant"])
            .clone(),
    )
    .map_err(unavailable)?;
    grant.acknowledgment = Some(grant.revision());
    grant.validate().map_err(unavailable)?;
    record.result = json!({"permission_changed":true,"grant":record.approval_id,
        "instance_id":grant.instance_id,"disclosure":grant,"lifetime":if grant.diagnostics.as_ref().is_some_and(|s|s.snapshot){"snapshot"}else if grant.expires_at.is_some(){"temporary"}else{"until_revoked"}});
    crate::edit_native_policy(state,true,|source| {
        if !check_saved(state,source,record)? { return Err(invalid("diagnostic authority changed before commit")); }
        let (mut document,context) = crate::policy::parse_toml_for_edit(source).map_err(unavailable)?;
        document["support_grants"][&record.approval_id] = toml_edit::value(serde_json::to_string(&grant).map_err(unavailable)?);
        save_receipt(&mut document,record)?;
        Ok(((),crate::policy::restore_large_toml_integers(&document.to_string(),&context)))
    }).map_err(|_|invalid("diagnostic disclosure could not be confirmed; read the original canonical approval before retrying"))?;
    record.status = "approved".into();
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub expected_authority_digest: String,
    pub expected_selection_revision: Option<String>,
    pub subject_ids: Vec<String>,
    pub scope: Scope,
    pub expires_at: Option<String>,
}

/// Prepare a narrower choice, then use the ordinary canonical decision.
pub(crate) fn narrow(
    state: &crate::RuntimeState,
    writer: &Writer,
    id: &str,
    input: Selection,
) -> Result<Value> {
    let policy = crate::peer_support::current_policy(state).map_err(unavailable)?;
    let record=writer.approvals().decide(id,|record| {
        if record.authority.action["kind"]!="diagnostic_disclosure" || record.current_status(&policy)?!="pending"
            || record.authority_digest!=input.expected_authority_digest {
            return Err(invalid("inspect this pending diagnostic approval and its exact authority before narrowing"));
        }
        let original:Grant=serde_json::from_value(record.authority.action["grant"].clone()).map_err(unavailable)?;
        let mut selected=original.clone();
        selected.targets.retain(|a|input.subject_ids.contains(&a.agent_id));
        if selected.targets.len()!=input.subject_ids.len() {return Err(invalid("a narrowed selection may retain only originally selected durable subjects"));}
        selected.diagnostics=Some(input.scope.clone());selected.expires_at=input.expires_at.clone();
        if !grant_subset(&selected,&original) {
            return Err(invalid("narrowing cannot add a source, subject, historical reach, future records, run or access lifetime"));
        }
        selected.validate().map_err(unavailable)?;
        let previous:Option<Grant>=record.result.get("diagnostic_selection").cloned().map(serde_json::from_value).transpose().map_err(unavailable)?;
        if previous.as_ref().map(Grant::revision).as_deref()!=input.expected_selection_revision.as_deref()
            && previous.as_ref().map(Grant::revision)!=Some(selected.revision()) {
            return Err(invalid("diagnostic preview changed; read its current selection revision"));
        }
        record.result=json!({"permission_changed":false,"diagnostic_selection":selected,"selection_revision":selected.revision(),
            "next_action":"Inspect this fixed selection, then approve or reject through the ordinary canonical approval decision. No permission has changed."});
        Ok(())
    })?.ok_or_else(||invalid("canonical diagnostic approval unavailable"))?;
    let mut event = Event::new(
        "admin.diagnostic_disclosure_narrowed",
        crate::audit::Kind::Admin,
        crate::audit::Severity::High,
        "Operator narrowed a pending diagnostic disclosure",
    );
    event.agent = Some(
        record.authority.action["agent"]
            .as_str()
            .unwrap_or("")
            .into(),
    );
    event.details=json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,"selection":record.result}).into();
    let mut view = record.view(&policy)?;
    if writer.emit(event).is_err() {
        view["audit_status"] = json!("unavailable; canonical selection is saved");
    }
    Ok(view)
}

fn expiry_subset(selected: Option<&str>, original: Option<&str>) -> bool {
    use crate::policy::support::diagnostics::timestamp;
    match (selected, original) {
        (None, Some(_)) => false,
        (Some(s), Some(o)) => timestamp(s).is_some_and(|s| timestamp(o).is_some_and(|o| s <= o)),
        (Some(s), None) => timestamp(s).is_some(),
        (None, None) => true,
    }
}

pub(crate) fn grant_subset(selected: &Grant, original: &Grant) -> bool {
    let (Some(selected_scope), Some(original_scope)) =
        (&selected.diagnostics, &original.diagnostics)
    else {
        return false;
    };
    let mut original_scope = original_scope.clone();
    original_scope
        .runs
        .retain(|id, _| selected.targets.iter().any(|a| &a.agent_id == id));
    selected.instance_id == original.instance_id
        && selected.support == original.support
        && selected
            .targets
            .iter()
            .all(|a| original.targets.contains(a))
        && is_subset(selected_scope, &original_scope)
        && expiry_subset(
            selected.expires_at.as_deref(),
            original.expires_at.as_deref(),
        )
}

pub(crate) fn is_subset(selected: &Scope, original: &Scope) -> bool {
    use crate::policy::support::diagnostics::timestamp;
    selected.snapshot == original.snapshot
        && (!selected.audit || original.audit)
        && (!selected.runtime || original.runtime)
        && (!selected.history.future || original.history.future)
        && expiry_subset(
            selected.history.until.as_deref(),
            original.history.until.as_deref(),
        )
        && original
            .history
            .since
            .as_deref()
            .and_then(timestamp)
            .is_none_or(|o| {
                selected
                    .history
                    .since
                    .as_deref()
                    .and_then(timestamp)
                    .is_some_and(|s| s >= o)
            })
        && selected
            .system_categories
            .iter()
            .all(|c| original.system_categories.contains(c))
        && selected.rooms.iter().all(|room| {
            original.rooms.iter().any(|o| {
                room.room_id == o.room_id
                    && (!room.history || o.history)
                    && (!room.membership || o.membership)
                    && (!room.attention || o.attention)
            })
        })
        && original.runs.iter().all(|(id, runs)| {
            runs.is_empty()
                || selected
                    .runs
                    .get(id)
                    .is_some_and(|s| !s.is_empty() && s.iter().all(|r| runs.contains(r)))
        })
}
