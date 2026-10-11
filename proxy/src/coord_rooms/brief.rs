//! Host-local operator brief reads and atomic revision-checked writes.

use super::{Error, Path, hash, now, open, open_with_flags};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};

// Preserve the existing Coord brief input bound, including UTF-8 byte counting.
const MAX_BRIEF_BYTES: usize = 64 * 1024;

pub(crate) fn current(connection: &Connection, room_id: &str) -> rusqlite::Result<Value> {
    Ok(connection.query_row(
        "SELECT revision, markdown, content_hash, updated_at FROM coord_briefs WHERE room_id=?1",
        [room_id],
        |row| Ok(json!({
            "room_id":room_id,
            "object_id":format!("brief-{}",room_id.trim_start_matches("rm-")),
            "revision":row.get::<_,i64>(0)?,
            "markdown":row.get::<_,String>(1)?,
            "content_hash":row.get::<_,String>(2)?,
            "updated_at":row.get::<_,i64>(3)?,
        })),
    ).optional()?.unwrap_or_else(|| json!({
        "room_id":room_id,
        "object_id":format!("brief-{}",room_id.trim_start_matches("rm-")),
        "revision":0,"markdown":null,"content_hash":null,"updated_at":null,
    })))
}

fn room_id(connection: &Connection, room: &str) -> Result<String, Error> {
    connection
        .query_row("SELECT room_id FROM rooms WHERE name=?1", [room], |row| {
            row.get(0)
        })
        .optional()?
        .ok_or_else(|| format!("Coord room {room} does not exist").into())
}

pub(crate) fn read(root: &Path, room: &str) -> Result<Value, Error> {
    let connection = open_with_flags(root, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(current(&connection, &room_id(&connection, room)?)?)
}

pub(crate) fn set(root: &Path, room: &str, markdown: &str, expected: i64) -> Result<Value, Error> {
    if markdown.trim().is_empty() {
        return Err("brief Markdown must be nonempty".into());
    }
    if markdown.len() > MAX_BRIEF_BYTES {
        return Err(format!("brief Markdown exceeds {MAX_BRIEF_BYTES} UTF-8 bytes").into());
    }
    if expected < 0 {
        return Err("expected revision must be nonnegative".into());
    }
    let mut connection = open(root)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let room_id = room_id(&transaction, room)?;
    let actual: i64 = transaction
        .query_row(
            "SELECT revision FROM coord_briefs WHERE room_id=?1",
            [&room_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if actual != expected {
        return Err(format!("expected revision {expected}, current revision is {actual}; read the brief before updating").into());
    }
    let revision = actual
        .checked_add(1)
        .ok_or("brief revision cannot advance")?;
    let changed_at = now();
    let content_hash = hash(markdown.as_bytes());
    let operation_id = uuid::Uuid::new_v4().simple().to_string();
    transaction.execute(
        "INSERT INTO coord_brief_revisions(room_id,revision,markdown,content_hash,actor_kind,actor_id,operation_id,created_at) VALUES(?1,?2,?3,?4,'operator','operator',?5,?6)",
        params![room_id,revision,markdown,content_hash,operation_id,changed_at],
    )?;
    transaction.execute(
        "INSERT INTO coord_briefs(room_id,revision,markdown,content_hash,actor_kind,actor_id,operation_id,updated_at) VALUES(?1,?2,?3,?4,'operator','operator',?5,?6)
         ON CONFLICT(room_id) DO UPDATE SET revision=excluded.revision,markdown=excluded.markdown,content_hash=excluded.content_hash,actor_kind=excluded.actor_kind,actor_id=excluded.actor_id,operation_id=excluded.operation_id,updated_at=excluded.updated_at",
        params![room_id,revision,markdown,content_hash,operation_id,changed_at],
    )?;
    let object_id = format!("brief-{}", room_id.trim_start_matches("rm-"));
    let recipients = transaction
        .prepare(
            "SELECT principal_id, granted_at FROM memberships AS m
         WHERE room_id=?1 AND principal_kind='agent' AND revoked_at IS NULL
           AND instr(',' || permissions || ',', ',receive,') > 0
           AND NOT EXISTS(SELECT 1 FROM memberships AS newer
             WHERE newer.room_id=m.room_id AND newer.principal_kind=m.principal_kind
               AND newer.principal_id=m.principal_id AND newer.revoked_at IS NULL
               AND newer.granted_at > m.granted_at)
         ORDER BY principal_id",
        )?
        .query_map([&room_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (agent_id, granted_at) in &recipients {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let attention_id = format!("attn-{suffix}");
        transaction.execute("INSERT OR IGNORE INTO coord_attention_feeds(recipient_agent_id,last_sequence) VALUES(?1,0)",[agent_id])?;
        let sequence: i64 = transaction.query_row("UPDATE coord_attention_feeds SET last_sequence=last_sequence+1 WHERE recipient_agent_id=?1 RETURNING last_sequence",[agent_id],|row|row.get(0))?;
        transaction.execute(
            "INSERT INTO coord_attention_edges(recipient_agent_id,feed_sequence,attention_id,room_id,kind,object_id,revision_or_sequence,membership_granted_at,created_at) VALUES(?1,?2,?3,?4,'brief_changed',?5,?6,?7,?8)",
            params![agent_id,sequence,attention_id,room_id,object_id,revision,granted_at,changed_at],
        )?;
        transaction.execute(
            "INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'attention-nats','coord.attention_hint',?2,?3)",
            params![format!("evt-{suffix}"),json!({"attention_id":attention_id,"recipient_agent_id":agent_id,"feed_sequence":sequence}).to_string(),changed_at],
        )?;
    }
    let mut result = current(&transaction, &room_id)?;
    result
        .as_object_mut()
        .ok_or("invalid brief result")?
        .remove("markdown");
    result["attention_count"] = json!(recipients.len());
    // Keep mutation metadata in the existing operator ledger and audit outbox;
    // trusted prose belongs only in the canonical current/history tables.
    let request = json!({"expected_revision":expected,"markdown":markdown,"room_id":room_id});
    transaction.execute(
        "INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('operator','operator','coord.brief.set',?1,?2,'success',?3,?4)",
        params![operation_id,hash(request.to_string().as_bytes()),result.to_string(),changed_at],
    )?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let timestamp =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let event = json!({
        "schema_version":1,"event_id":event_id,"ts":timestamp,"event":"coord.brief_updated",
        "kind":"coord","severity":"low","summary":"Coord operator brief updated","addon":"coord",
        "details":{"actor":"operator","room_id":room_id,"object_id":object_id,"revision":revision,"content_hash":content_hash,"operation_id":operation_id,"operation_type":"coord.brief.set"},
    });
    transaction.execute(
        "INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl','coord.brief_updated',?2,?3)",
        params![event_id,event.to_string(),changed_at],
    )?;
    transaction.commit()?;
    Ok(result)
}
