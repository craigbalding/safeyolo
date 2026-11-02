//! Atomic operator membership transitions and their immutable retry results.
use super::{Error, hash, now};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

#[allow(clippy::too_many_arguments)]
pub(super) fn change(
    transaction: &Connection,
    room_id: &str,
    kind: &str,
    principal: &str,
    permissions: &[String],
    revoke: bool,
    operation_id: &str,
    display_name: Option<&str>,
) -> Result<Value, Error> {
    if operation_id.trim().is_empty() {
        return Err("operation ID must be nonempty".into());
    }
    let mut permissions = permissions.to_vec();
    if revoke {
        permissions.clear();
    } else if permissions.is_empty() {
        permissions = vec!["receive".into(), "send".into(), "page_operator".into()];
    }
    permissions.sort();
    permissions.dedup();
    if permissions
        .iter()
        .any(|p| !["send", "receive", "page_operator"].contains(&p.as_str()))
    {
        return Err("room permission must be send, receive or page_operator".into());
    }
    let operation_type = if revoke {
        "coord.revoke"
    } else {
        "coord.grant"
    };
    // Fixed field order and normalized permission sets define canonical input.
    let mut request = json!({"room_id":room_id,"principal_kind":kind,"principal_id":principal,"permissions":permissions});
    if let Some(name) = display_name {
        request["display_name"] = json!(name);
    }
    let request_hash = hash(request.to_string().as_bytes());
    let prior: Option<(String, String)> = transaction
        .query_row(
            "SELECT request_hash,outcome_json FROM coord_operations
         WHERE principal_kind='operator' AND principal_id='operator'
           AND operation_type=?1 AND operation_id=?2",
            params![operation_type, operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((original_hash, result)) = prior {
        if original_hash != request_hash {
            return Err("operation ID conflicts with the original canonical request".into());
        }
        return Ok(serde_json::from_str(&result)?);
    }
    let latest: Option<i64> = transaction.query_row(
        "SELECT MAX(granted_at) FROM memberships WHERE room_id=?1 AND principal_kind=?2 AND principal_id=?3",
        params![room_id,kind,principal], |row| row.get(0),
    )?;
    let active: Option<(String, i64)> = transaction.query_row(
        "SELECT permissions,granted_at FROM memberships WHERE room_id=?1 AND principal_kind=?2 AND principal_id=?3 AND revoked_at IS NULL ORDER BY granted_at DESC LIMIT 1",
        params![room_id,kind,principal], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    let changed_at = now();
    let mut generation = active.as_ref().map(|(_, generation)| *generation);
    if revoke {
        transaction.execute(
            "UPDATE memberships SET revoked_at=?4 WHERE room_id=?1 AND principal_kind=?2 AND principal_id=?3 AND revoked_at IS NULL",
            params![room_id,kind,principal,changed_at],
        )?;
        transaction.execute("UPDATE coord_membership_grants SET revoked_at=?3 WHERE room_id=?1 AND agent_id=?2 AND revoked_at IS NULL",params![room_id,principal,changed_at])?;
    } else if active.as_ref().map(|(p, _)| p.as_str()) != Some(permissions.join(",").as_str()) {
        let next = changed_at.max(
            latest
                .unwrap_or(0)
                .checked_add(1)
                .ok_or("membership generation cannot advance")?,
        );
        transaction.execute(
            "INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES(?1,?2,?3,?4,?5)",
            params![room_id,kind,principal,permissions.join(","),next],
        )?;
        generation = Some(next);
    }
    let mut result = json!({"room_id":room_id,"agent_id":principal,"permissions":permissions,
        "operation_id":operation_id,"membership_granted_at":generation,"changed_at":changed_at});
    if let Some(name) = display_name {
        result["display_name"] = json!(name);
    }
    transaction.execute(
        "INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at)
         VALUES('operator','operator',?1,?2,?3,'success',?4,?5)",
        params![operation_type,operation_id,request_hash,result.to_string(),changed_at],
    )?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let event_type = if revoke {
        "coord.membership_revoked"
    } else {
        "coord.membership_granted"
    };
    let timestamp =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let event = json!({"schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,"ts":timestamp,
        "event":event_type,"kind":"coord","severity":"low","summary":if revoke {"Coord membership revoked"} else {"Coord membership granted"},"addon":"coord",
        "details":{"actor":"operator","room_id":room_id,"principal_kind":kind,"principal_id":principal,
            "permissions":permissions,"membership_granted_at":generation,"operation_id":operation_id,"operation_type":operation_type}});
    transaction.execute(
        "INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl',?2,?3,?4)",
        params![event_id,event_type,event.to_string(),changed_at],
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests;

/// The audience is part of the approval effect, including rights of existing
/// members. Operator membership is independent of every approval source.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Participant {
    pub principal_kind: String,
    pub principal_id: String,
    pub permissions: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct EffectiveMember {
    pub participant: Participant,
    pub granted_at: i64,
}

pub(crate) fn valid_permissions(permissions: &[String]) -> bool {
    !permissions.is_empty()
        && permissions
            .iter()
            .all(|p| matches!(p.as_str(), "send" | "receive" | "page_operator"))
}

pub(crate) fn audience_contains(allowed: &[Participant], actual: &[Participant]) -> bool {
    actual.iter().all(|member| {
        allowed.iter().any(|entry| {
            entry.principal_kind == member.principal_kind
                && entry.principal_id == member.principal_id
                && member
                    .permissions
                    .iter()
                    .all(|right| entry.permissions.contains(right))
        })
    })
}

fn independent(conn: &Connection, room: &str) -> Result<Vec<EffectiveMember>, Error> {
    Ok(conn.prepare("SELECT principal_kind,principal_id,permissions,granted_at FROM memberships AS m
        WHERE room_id=?1 AND revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM memberships AS n
        WHERE n.room_id=m.room_id AND n.principal_kind=m.principal_kind AND n.principal_id=m.principal_id
        AND n.revoked_at IS NULL AND n.granted_at>m.granted_at) ORDER BY principal_kind,principal_id")?
        .query_map([room], |row| Ok(EffectiveMember {
            participant:Participant {principal_kind:row.get(0)?,principal_id:row.get(1)?,permissions:row.get::<_,String>(2)?.split(',').filter(|p|!p.is_empty()).map(str::to_owned).collect()},
            granted_at:row.get(3)?,
        }))?.collect::<rusqlite::Result<_>>()?)
}

fn merge(members: &mut Vec<EffectiveMember>, member: EffectiveMember) {
    if let Some(existing) = members.iter_mut().find(|m| {
        m.participant.principal_kind == member.participant.principal_kind
            && m.participant.principal_id == member.participant.principal_id
    }) {
        existing
            .participant
            .permissions
            .extend(member.participant.permissions);
        existing.participant.permissions.sort();
        existing.participant.permissions.dedup();
        existing.granted_at = existing.granted_at.max(member.granted_at);
    } else {
        members.push(member);
    }
}

/// Every consumer uses this projection. Each source is revalidated against
/// current saved policy, durable identity, trusted run, lifetime and audience.
/// A prepared membership without its policy receipt is deliberately inert.
pub(crate) fn effective(conn: &Connection, room: &str) -> Result<Vec<EffectiveMember>, Error> {
    Ok(effective_with_sources(conn, room)?.0)
}

pub(crate) fn issued_effective(
    policy: &crate::policy::Policy,
    issued: &crate::policy::delegation::IssuedAccess,
) -> Result<bool, Error> {
    let (_, sources) = effective_with_sources(
        &super::open(&root(policy)?)?,
        issued.action["room_id"]
            .as_str()
            .ok_or("room unavailable")?,
    )?;
    Ok(sources.contains(&issued.approval_id))
}

fn effective_with_sources(
    conn: &Connection,
    room: &str,
) -> Result<(Vec<EffectiveMember>, Vec<String>), Error> {
    let mut members = independent(conn, room)?;
    let mut candidates = vec![];
    let mut policies = std::collections::BTreeMap::new();
    let mut query = conn.prepare(
        "SELECT agent_id,permissions,granted_at,issued_json,policy_file,identity_root,approval_id
        FROM coord_membership_grants WHERE room_id=?1 AND revoked_at IS NULL ORDER BY approval_id",
    )?;
    let rows = query.query_map([room], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (agent, permissions, granted_at, encoded, path, root, approval) = row?;
        let Ok(issued) = serde_json::from_str::<crate::policy::delegation::IssuedAccess>(&encoded)
        else {
            continue;
        };
        let key = (path.clone(), root.clone());
        let policy = policies.entry(key).or_insert_with(|| {
            // An old policy file can remain on disk after an operator selects
            // another one. It must not keep authorizing this instance's rooms.
            let selected = super::read_config(std::path::Path::new(&root))
                .ok()?
                .policy_file?;
            if selected.canonicalize().ok()? != std::fs::canonicalize(&path).ok()? {
                return None;
            }
            crate::policy::Policy::from_native_path(std::path::Path::new(&path))
                .ok()
                .map(|mut policy| {
                    policy.set_identity_root(root.into());
                    policy
                })
        });
        let Some(policy) = policy else {
            continue;
        };
        if issued.approval_id != approval
            || issued.action["room_id"] != room
            || issued.beneficiary.agent_id != agent
            || issued.action["permissions"]
                != serde_json::json!(permissions.split(',').collect::<Vec<_>>())
            || !issued.active(policy)
        {
            continue;
        }
        let Ok(audience) =
            serde_json::from_value::<Vec<Participant>>(issued.action["participants"].clone())
        else {
            continue;
        };
        // Later grants may add rights already acknowledged in this same
        // envelope. Do not accidentally revoke a still-valid source merely
        // because another separately attributable source became effective.
        let audiences = match policy.delegations().get(&issued.delegation) {
            Some(delegation) => delegation
                .scopes
                .iter()
                .filter_map(|scope| {
                    let crate::policy::delegation::Scope::CoordRoom { participants, .. } = scope
                    else {
                        return None;
                    };
                    let mut single = delegation.clone();
                    single.scopes = vec![scope.clone()];
                    single
                        .contains_effect(&issued.action, &issued.option)
                        .then(|| participants.clone())
                })
                .collect::<Vec<_>>(),
            None => vec![audience],
        };
        candidates.push((
            approval,
            EffectiveMember {
                participant: Participant {
                    principal_kind: "agent".into(),
                    principal_id: agent,
                    permissions: permissions.split(',').map(str::to_owned).collect(),
                },
                granted_at,
            },
            audiences,
        ));
    }
    // Use the full potentially active audience, before filtering each grant.
    // This avoids recursive permission evaluation between two issued grants.
    let mut potential = members.clone();
    for (_, member, _) in &candidates {
        merge(&mut potential, member.clone());
    }
    let audience = potential
        .iter()
        .map(|m| m.participant.clone())
        .collect::<Vec<_>>();
    let mut sources = vec![];
    for (approval, member, allowed) in candidates {
        // Another source may add rights to this same beneficiary. Those
        // rights do not add a room audience and must not suppress this source.
        let peers = audience
            .iter()
            .filter(|participant| {
                participant.principal_kind != "agent"
                    || participant.principal_id != member.participant.principal_id
            })
            .cloned()
            .collect::<Vec<_>>();
        if allowed
            .iter()
            .any(|allowed| audience_contains(allowed, &peers))
        {
            merge(&mut members, member);
            sources.push(approval);
        }
    }
    members.sort_by(|a, b| {
        (&a.participant.principal_kind, &a.participant.principal_id)
            .cmp(&(&b.participant.principal_kind, &b.participant.principal_id))
    });
    Ok((members, sources))
}

pub(crate) fn root(policy: &crate::policy::Policy) -> Result<std::path::PathBuf, Error> {
    policy
        .identity_root()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "native identity root unavailable".into())
}

pub(crate) fn room_basis(policy: &crate::policy::Policy, room: &str) -> Result<Value, Error> {
    let conn = super::open(&root(policy)?)?;
    let name: String = conn.query_row("SELECT name FROM rooms WHERE room_id=?1", [room], |r| {
        r.get(0)
    })?;
    let members = independent(&conn, room)?
        .into_iter()
        .map(|m| json!({"participant":m.participant,"generation":m.granted_at}))
        .collect::<Vec<_>>();
    let instance: String = conn.query_row("SELECT id FROM instance", [], |r| r.get(0))?;
    Ok(
        json!({"instance_id":instance,"room_id":room,"room_name":name,"independent_members":members}),
    )
}

pub(crate) fn participants(
    policy: &crate::policy::Policy,
    room: &str,
) -> Result<Vec<Participant>, Error> {
    Ok(effective(&super::open(&root(policy)?)?, room)?
        .into_iter()
        .map(|m| m.participant)
        .collect())
}

/// Prepare the source, retry receipt and outbox in one existing Coord
/// transaction. Only subsequent publication of the matching policy receipt
/// activates it. An interrupted retry reuses the original expiry and decider.
pub(crate) fn prepare(
    policy: &crate::policy::Policy,
    record: &crate::approvals::pending::Record,
    issued: &crate::policy::delegation::IssuedAccess,
) -> Result<crate::policy::delegation::IssuedAccess, Error> {
    let root = root(policy)?;
    let mut conn = super::open(&root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let prior: Option<(String, String, Option<i64>)> = tx
        .query_row(
            "SELECT authority_digest,issued_json,revoked_at FROM coord_membership_grants WHERE approval_id=?1",
            [&record.approval_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((digest, encoded, revoked)) = prior {
        let prior: crate::policy::delegation::IssuedAccess = serde_json::from_str(&encoded)?;
        if digest != record.authority_digest
            || prior.action != issued.action
            || prior.delegation != issued.delegation
            || prior.delegation_revision != issued.delegation_revision
        {
            return Err("membership operation conflicts with its original approval".into());
        }
        if revoked.is_some() || !prior.active_snapshot(policy) {
            return Err(
                "prepared membership authority expired or changed; make a new request".into(),
            );
        }
        return Ok(prior);
    }
    if !issued.active_snapshot(policy) {
        return Err("membership authority changed before preparation".into());
    }
    let room = issued.action["room_id"]
        .as_str()
        .ok_or("room unavailable")?;
    let permissions: Vec<String> = serde_json::from_value(issued.action["permissions"].clone())?;
    if !valid_permissions(&permissions) {
        return Err("explicit room permissions required".into());
    }
    let allowed: Vec<Participant> = serde_json::from_value(issued.action["participants"].clone())?;
    let mut audience = effective(&tx, room)?;
    merge(
        &mut audience,
        EffectiveMember {
            participant: Participant {
                principal_kind: "agent".into(),
                principal_id: issued.beneficiary.agent_id.clone(),
                permissions: permissions.clone(),
            },
            granted_at: 0,
        },
    );
    if !audience_contains(
        &allowed,
        &audience
            .into_iter()
            .map(|m| m.participant)
            .collect::<Vec<_>>(),
    ) {
        return Err("room audience changed before membership preparation".into());
    }
    let changed_at = now();
    let latest: i64 = tx.query_row("SELECT max(v) FROM (SELECT coalesce(max(granted_at),0) AS v FROM memberships UNION ALL SELECT coalesce(max(granted_at),0) FROM coord_membership_grants)",[],|r|r.get(0))?;
    let generation = changed_at.max(
        latest
            .checked_add(1)
            .ok_or("membership generation exhausted")?,
    );
    let path = policy.source_path().ok_or("policy path unavailable")?;
    let encoded = serde_json::to_string(issued)?;
    tx.execute("INSERT INTO coord_membership_grants(approval_id,room_id,agent_id,permissions,granted_at,issued_json,authority_digest,policy_file,identity_root) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![record.approval_id,room,issued.beneficiary.agent_id,permissions.join(","),generation,encoded,record.authority_digest,path.to_str().ok_or("non-UTF8 policy path")?,root.to_str().ok_or("non-UTF8 identity root")?])?;
    let result = json!({"approval_id":record.approval_id,"issued_access":issued,"membership_granted_at":generation,"activation":"matching policy receipt required"});
    tx.execute("INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES(?1,?2,'coord.approval_grant',?3,?4,'prepared',?5,?6)",params![if issued.delegation.is_empty(){"operator"}else{"agent"},issued.reviewer.agent_id,record.approval_id,record.authority_digest,result.to_string(),changed_at])?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let event = json!({"schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,"ts":time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,"event":"coord.membership_prepared","kind":"coord","severity":"low","summary":"Approval room membership prepared; matching policy receipt activates access","addon":"coord","details":{"actor_kind":if issued.delegation.is_empty(){"operator"}else{"agent"},"actor_id":issued.reviewer.agent_id,"room_id":room,"principal_id":issued.beneficiary.agent_id,"permissions":permissions,"delegation":issued.delegation,"delegation_revision":issued.delegation_revision,"approval_id":record.approval_id,"membership_granted_at":generation}});
    tx.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl','coord.membership_prepared',?2,?3)",params![event_id,event.to_string(),changed_at])?;
    tx.commit()?;
    Ok(issued.clone())
}
