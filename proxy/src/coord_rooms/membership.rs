//! Atomic operator membership transitions and their immutable retry results.
use super::{Error, hash, now};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

pub(super) fn change(
    transaction: &Connection,
    room_id: &str,
    kind: &str,
    principal: &str,
    permissions: &[String],
    revoke: bool,
    operation_id: &str,
) -> Result<Value, Error> {
    if operation_id.trim().is_empty() {
        return Err("operation ID must be nonempty".into());
    }
    let mut permissions = permissions.to_vec();
    if revoke {
        permissions.clear();
    } else if permissions.is_empty() {
        permissions = vec!["receive".into(), "send".into()];
    }
    permissions.sort();
    permissions.dedup();
    if permissions
        .iter()
        .any(|p| !["send", "receive"].contains(&p.as_str()))
    {
        return Err("room permission must be send or receive".into());
    }
    let operation_type = if revoke {
        "coord.revoke"
    } else {
        "coord.grant"
    };
    // Fixed field order and normalized permission sets define canonical input.
    let request = json!({"room_id":room_id,"principal_kind":kind,"principal_id":principal,"permissions":permissions});
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
    let result = json!({"room_id":room_id,"agent_id":principal,"permissions":permissions,
        "operation_id":operation_id,"membership_granted_at":generation,"changed_at":changed_at});
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
