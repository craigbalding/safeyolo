//! Before-admission actions retain immutable revisions in the Coord operation ledger.
use super::*;

const KIND: &str = "coord.work.prerequisite";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Invocation {
    pub id: String,
    pub version: i64,
    pub room_id: String,
    pub requester: subjects::Principal,
    pub operation_id: String,
    pub request: Value,
    pub attempts: u32,
    pub record: Obligation,
}

fn load(conn: &Connection, id: &str) -> Result<Option<Invocation>, WorkError> {
    if !id
        .strip_prefix("prerequisite-")
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(invalid("invalid prerequisite invocation ID"));
    }
    let value: Option<String> = conn.query_row(
        "SELECT outcome_json FROM coord_operations WHERE operation_type=?1 AND operation_id GLOB ?2 ORDER BY operation_id DESC LIMIT 1",
        params![KIND, format!("{id}/*")], |row| row.get(0),
    ).optional()?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}

fn append(conn: &Connection, invocation: &mut Invocation) -> Result<(), WorkError> {
    invocation.version = invocation
        .version
        .checked_add(1)
        .ok_or_else(|| conflict("prerequisite version cannot advance"))?;
    invocation.record.updated_at = now();
    let document = serde_json::to_string(invocation)?;
    conn.execute(
        "INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES(?1,?2,?3,?4,?5,'retained',?6,?7)",
        params![invocation.requester.kind, invocation.requester.id, KIND, format!("{}/{:020}",invocation.id,invocation.version), hash(document.as_bytes()), document, now()],
    )?;
    Ok(())
}

pub(crate) fn read(
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    id: &str,
) -> Result<Value, WorkError> {
    let room_id = authorize(conn, room, actor, false)?;
    let invocation = load(conn, id)?
        .filter(|i| i.room_id == room_id)
        .ok_or_else(|| invalid("prerequisite invocation not found in this room"))?;
    Ok(json!(invocation))
}

fn adopted(policy: &Policy, invocation: &Invocation) -> bool {
    let record = &invocation.record;
    record.policy_hash == policy.work_authority_digest()
        && record.service_definitions_hash.as_ref()
            == Some(&policy.work_service_definitions_digest())
        && source_current(record)
        && policy
            .named_checks()
            .work_bindings
            .iter()
            .any(|b| json!(b) == json!(record.binding))
}

pub(super) fn current(conn: &Connection, record: &Obligation) -> Result<bool, WorkError> {
    Ok(load(conn, &record.id)?.is_some_and(|i| {
        matches!(i.record.state, State::Completed) && json!(i.record) == json!(record)
    }))
}

pub(super) async fn invoke(
    root: &Path,
    room: &str,
    actor: Actor<'_>,
    operation: Option<&str>,
    prepared: &Prepared,
    mut record: Obligation,
) -> Result<Obligation, WorkError> {
    let state = &prepared.state;
    let input = &prepared.request;
    let operation = operation
        .ok_or_else(|| invalid("effectful prerequisites require a caller-selected operation ID"))?;
    let id = format!(
        "prerequisite-{}",
        hash(
            json!([
                room,
                actor.principal(),
                input["action"],
                operation,
                record.binding.name
            ])
            .to_string()
            .as_bytes()
        )
    );
    record.id = id.clone();
    let policy = prepared.runtime.policy.as_ref().unwrap();
    record.service_definitions_hash = Some(policy.work_service_definitions_digest());
    record.source_version = source_version(policy, &record.binding);
    let mut invocation = {
        let mut conn = open(root)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let request = validate_request(
            &tx,
            room,
            actor,
            &serde_json::from_value(input.clone())?,
            Some(operation),
        )?;
        if request.replay.is_some() {
            return Err(conflict(
                "protected operation already committed; recover its original operation receipt",
            ));
        }
        let room_id = request.room_id;
        let configured = Configuration {
            policy: prepared.runtime.policy.clone(),
            root: Some(root.to_owned()),
        };
        let guard = guard(
            &configured,
            &tx,
            room,
            &room_id,
            input,
            None,
            Validation::Preflight,
        )?;
        prepare_change(
            files(&prepared.runtime),
            &configured,
            &tx,
            room,
            &room_id,
            actor,
            serde_json::from_value(input.clone())?,
            &guard,
            Validation::Preflight,
        )?;
        let mut invocation = if let Some(existing) = load(&tx, &id)? {
            if existing.request != *input
                || !adopted(policy, &existing)
                || existing.record.subject != record.subject
            {
                return Err(conflict(
                    "prerequisite invocation conflicts with the original request or adopted authority; inspect its retained result before another effect",
                ));
            }
            if matches!(existing.record.state, State::Completed) {
                return Ok(existing.record);
            }
            if !matches!(existing.record.state, State::Pending) {
                return Err(conflict(&format!(
                    "prerequisite {id} is {:?}: {}; read its invocation and reconcile at the external authority before a separately authorized retry",
                    existing.record.state, existing.record.detail
                )));
            }
            existing
        } else {
            Invocation {
                id: id.clone(),
                version: 0,
                room_id,
                requester: actor.principal(),
                operation_id: operation.into(),
                request: input.clone(),
                attempts: 0,
                record,
            }
        };
        invocation.record.state = State::Dispatching;
        invocation.record.detail =
            "dispatch retained; external completion has not been established".into();
        invocation.attempts = invocation
            .attempts
            .checked_add(1)
            .ok_or_else(|| conflict("prerequisite attempt count cannot advance"))?;
        // Reserve the protected operation's identity independently of its bindings.
        // This and the invocation revision commit together before any external effect.
        tx.execute(
            "INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES(?1,?2,?3,?4,?5,'retained',?6,?7) ON CONFLICT(principal_kind,principal_id,operation_type,operation_id) DO NOTHING",
            params![actor.kind(),actor.id(),format!("{}.prerequisite",request.operation_type),operation,request.request_hash,json!({"room_id":invocation.room_id,"mutation":input}).to_string(),now()],
        )?;
        append(&tx, &mut invocation)?;
        let _current = prepared.current()?;
        tx.commit()?;
        invocation
    };
    let result = super::invoke(&prepared.runtime, state, invocation.record.clone()).await;
    let mut conn = open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let latest =
        load(&tx, &id)?.ok_or_else(|| conflict("retained prerequisite invocation disappeared"))?;
    if latest.version != invocation.version {
        return Err(conflict(
            "prerequisite changed during execution; inspect its current invocation",
        ));
    }
    invocation.record = result;
    // Keep the captured execution even when its authority was invalidated.
    // Hold current runtime authority during retention, after external execution.
    let authority = prepared.current();
    if matches!(invocation.record.state, State::Completed)
        && (authority.is_err() || !source_current(&invocation.record))
    {
        invocation.record.state = State::Uncertain;
        invocation.record.detail = "execution authority changed or became unavailable while the prerequisite was pending; inspect the retained invocation at the external authority before any further effect".into();
    }
    append(&tx, &mut invocation)?;
    tx.commit()?;
    Ok(invocation.record)
}

/// Shared recovery validation is used by both preflight and the committing transaction.
pub(crate) fn prepare_recovery(
    configured: &Configuration,
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    mutation: &Mutation,
) -> Result<Option<Invocation>, WorkError> {
    let (id, version, retry, outcome, summary, refs) = match mutation {
        Mutation::ResolvePrerequisite {
            invocation_id,
            expected_version,
            outcome,
            summary,
            evidence_refs,
        } => (
            invocation_id,
            *expected_version,
            false,
            Some(outcome),
            summary,
            evidence_refs,
        ),
        Mutation::RetryPrerequisite {
            invocation_id,
            expected_version,
            summary,
            evidence_refs,
        } => (
            invocation_id,
            *expected_version,
            true,
            None,
            summary,
            evidence_refs,
        ),
        _ => return Ok(None),
    };
    let room_id = authorize(conn, room, actor, true)?;
    let mut invocation = load(conn, id)?
        .filter(|i| i.room_id == room_id)
        .ok_or_else(|| invalid("prerequisite invocation not found in this room"))?;
    if invocation.version != version {
        return Err(conflict(
            "stale prerequisite version; read the current invocation",
        ));
    }
    let policy = configured
        .policy
        .as_ref()
        .ok_or_else(|| conflict("current prerequisite policy unavailable"))?;
    if !adopted(policy, &invocation) {
        return Err(WorkError(403, "prerequisite authority was revoked or changed; recovery cannot adopt new capabilities or replace its subject".into()));
    }
    let recovery = invocation.record.binding.recovery.as_ref();
    let allowed = recovery.is_some_and(|r| {
        let agents = if retry { &r.retryers } else { &r.reconcilers };
        actor.kind() == "agent" && agents.iter().any(|id| id == actor.id())
    });
    if !matches!(actor, Actor::Operator) && !allowed {
        return Err(WorkError(
            403,
            "actor lacks the separately adopted prerequisite recovery permission".into(),
        ));
    }
    if !matches!(
        invocation.record.state,
        State::Uncertain | State::Failed | State::Unavailable
    ) {
        return Err(conflict(
            "only a failed or uncertain prerequisite may be reconciled or selected for retry",
        ));
    }
    subjects::evidence(summary, refs)?;
    if refs.is_empty() {
        return Err(invalid(
            "prerequisite recovery requires an external observation reference",
        ));
    }
    if retry {
        if invocation.record.binding.retry != Some(checks::work::Retry::Idempotent)
            || recovery.is_none_or(|r| invocation.attempts > r.max_retries)
        {
            return Err(WorkError(
                403,
                "no remaining adopted idempotent retry authority".into(),
            ));
        }
        invocation.record.state = State::Pending;
        invocation.record.detail = "bounded retry selected; the original requester must resume the exact protected operation under current authority".into();
    } else {
        let outcome = outcome.unwrap();
        if !matches!(outcome, State::Completed | State::Failed | State::Uncertain) {
            return Err(invalid(
                "prerequisite reconciliation outcome must be completed, failed or uncertain",
            ));
        }
        invocation.record.state = outcome.clone();
        invocation.record.detail = "adopted recovery actor reconciled the prerequisite at its external authority; protected commit remains pending".into();
    }
    invocation.record.resolution = Some(
        json!({"author":actor.principal(),"summary":summary,"evidence_refs":refs,"retry_selected":retry,"observed_at":now()}),
    );
    Ok(Some(invocation))
}

pub(crate) fn retain_recovery(
    conn: &Connection,
    invocation: &mut Invocation,
) -> Result<Value, WorkError> {
    append(conn, invocation)?;
    Ok(json!({"prerequisite":invocation}))
}

pub(super) fn recover(root: &Path) -> Result<(), WorkError> {
    let mut conn = open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut query = tx.prepare("SELECT outcome_json FROM coord_operations WHERE operation_type=?1 AND operation_id IN (SELECT MAX(operation_id) FROM coord_operations WHERE operation_type=?1 GROUP BY json_extract(outcome_json,'$.id'))")?;
    let latest = query
        .query_map([KIND], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(query);
    for document in latest {
        let mut invocation: Invocation = serde_json::from_str(&document)?;
        if matches!(invocation.record.state, State::Dispatching) {
            invocation.record.state = State::Uncertain;
            invocation.record.detail = "proxy restarted after prerequisite dispatch; reconcile the same invocation at the external authority before any separately adopted retry".into();
            append(&tx, &mut invocation)?;
        }
    }
    tx.commit()?;
    Ok(())
}
