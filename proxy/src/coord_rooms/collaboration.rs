//! Operator-approved, expiring collaboration through ordinary Coord rooms.
//! Native approval receipts activate prepared membership; no message store or
//! additional attention feed is owned here.
use super::{
    Error,
    membership::{EffectiveMember, Participant},
    now,
};
use crate::{
    approvals::pending::{self, Record},
    policy::Policy,
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

/// A request binds names to current durable identities before the operator sees
/// it. Replacement identities require a new approval.
pub(crate) fn revision(policy: &Policy, action: &Value) -> Option<String> {
    let root = super::membership::root(policy).ok()?;
    for participant in action["participants"].as_array()? {
        if policy.evidence_agent_id(participant["name"].as_str()?)
            != participant["agent_id"].as_str()
        {
            return None;
        }
    }
    let instance = std::fs::read_to_string(root.join("data/instance_id")).ok()?;
    Some(pending::digest(
        &json!({"instance":instance.trim(),"participants":action["participants"]}),
    ))
}

pub(crate) fn prepare(policy: &Policy, record: &Record) -> Result<(), Error> {
    let action = &record.authority.action;
    let root = super::membership::root(policy)?;
    let room = action["room_id"].as_str().ok_or("room ID unavailable")?;
    let name = action["room_name"]
        .as_str()
        .ok_or("room name unavailable")?;
    // The deterministic room ID is private to this effect. An interrupted room
    // registration can be retried without creating another stream or room.
    tokio::runtime::Handle::current().block_on(super::create_named_room(
        &root,
        name,
        Some(room),
    ))?;
    let mut conn = super::open(&root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // A failed activation can leave an operator-visible prepared room. A
    // later explicit grant must not silently add an audience to this approval
    // when it is retried. Independent rights of approved identities remain.
    let audience = super::membership::effective(&tx, room)?;
    if audience.iter().any(|member| {
        let participant = &member.participant;
        let operator =
            participant.principal_kind == "operator" && participant.principal_id == "operator";
        let approved_agent = participant.principal_kind == "agent"
            && action["participants"].as_array().is_some_and(|approved| {
                approved
                    .iter()
                    .any(|p| p["agent_id"] == participant.principal_id)
            });
        !(operator || approved_agent)
    }) {
        return Err(
            "collaboration audience changed before activation; inspect the room and request".into(),
        );
    }
    let path = policy.source_path().ok_or("policy file unavailable")?;
    let expiry = record
        .authority
        .expires_at
        .as_deref()
        .ok_or("collaboration expiry required")?;
    let mut generation: i64 = tx.query_row("SELECT max(v) FROM (SELECT coalesce(max(granted_at),0) AS v FROM memberships UNION ALL SELECT coalesce(max(granted_at),0) FROM coord_membership_grants UNION ALL SELECT coalesce(max(granted_at),0) FROM coord_collaboration_grants)", [], |r|r.get(0))?;
    for participant in action["participants"]
        .as_array()
        .ok_or("participants required")?
    {
        generation = now().max(
            generation
                .checked_add(1)
                .ok_or("membership generation exhausted")?,
        );
        let id = participant["agent_id"]
            .as_str()
            .ok_or("participant identity required")?;
        let name = participant["name"]
            .as_str()
            .ok_or("participant name required")?;
        let prior: Option<(String, String, Option<i64>)> = {
            use rusqlite::OptionalExtension;
            tx.query_row("SELECT authority_digest,receipt_json,revoked_at FROM coord_collaboration_grants WHERE approval_id=?1 AND agent_id=?2",params![record.approval_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?
        };
        if let Some((digest, receipt, revoked)) = prior {
            if revoked.is_some() {
                return Err(
                    "prepared collaboration membership was revoked; make a new request".into(),
                );
            }
            if digest != record.authority_digest
                || serde_json::from_str::<Value>(&receipt)? != record.receipt()
            {
                return Err(
                    "collaboration preparation conflicts with its original approval".into(),
                );
            }
            continue;
        }
        tx.execute("INSERT INTO coord_collaboration_grants(approval_id,room_id,agent_id,agent_name,granted_at,authority_digest,receipt_json,policy_file,identity_root,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![record.approval_id,room,id,name,generation,record.authority_digest,record.receipt().to_string(),path.to_str().ok_or("policy path is not UTF-8")?,root.to_str().ok_or("identity root is not UTF-8")?,expiry])?;
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn members(conn: &Connection, room: &str) -> Result<Vec<EffectiveMember>, Error> {
    let mut members = vec![];
    let mut policies = std::collections::BTreeMap::new();
    let mut query = conn.prepare("SELECT approval_id,agent_id,agent_name,granted_at,receipt_json,policy_file,identity_root,expires_at FROM coord_collaboration_grants WHERE room_id=?1 AND revoked_at IS NULL")?;
    let rows = query.query_map([room], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;
    for row in rows {
        let (approval, id, name, generation, encoded, path, root, expiry) = row?;
        if crate::policy::parse_expiry(&expiry)
            .is_none_or(|expiry| time::OffsetDateTime::now_utc() >= expiry)
        {
            continue;
        }
        let policy = policies
            .entry((path.clone(), root.clone()))
            .or_insert_with(|| {
                let selected = super::read_config(std::path::Path::new(&root))
                    .ok()?
                    .policy_file?;
                if selected.canonicalize().ok()? != std::fs::canonicalize(&path).ok()? {
                    return None;
                }
                let mut policy = Policy::from_native_path(std::path::Path::new(&path)).ok()?;
                policy.set_identity_root(root.into());
                Some(policy)
            });
        let Some(policy) = policy else {
            continue;
        };
        let receipt: Value = serde_json::from_str(&encoded)?;
        if policy.evidence_agent_id(&name) != Some(id.as_str())
            || policy.approval_result(&approval)? != Some(receipt)
        {
            continue;
        }
        members.push(EffectiveMember {
            participant: Participant {
                principal_kind: "agent".into(),
                principal_id: id,
                permissions: vec!["receive".into(), "send".into()],
            },
            granted_at: generation,
            receive_generations: vec![generation],
        });
    }
    Ok(members)
}

pub(crate) fn is_collaboration(conn: &Connection, room: &str) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM coord_collaboration_grants WHERE room_id=?1)",
        [room],
        |r| r.get(0),
    )?)
}

pub(crate) fn revoke_identity(data_dir: &std::path::Path, id: &str) -> Result<(), Error> {
    // A removed identity must not regain an old source if the operator later
    // restores the same policy text. Retain the original grant and its receipt.
    let database = data_dir.join("coord/v0.db");
    if !database.is_file() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute("UPDATE coord_collaboration_grants SET revoked_at=?2 WHERE agent_id=?1 AND revoked_at IS NULL",params![id,now()])?;
    Ok(())
}
