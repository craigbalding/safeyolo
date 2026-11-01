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

pub(crate) fn set(
    root: &Path,
    room: &str,
    markdown: &str,
    expected: i64,
    operation_id: Option<&str>,
) -> Result<Value, Error> {
    if markdown.trim().is_empty() {
        return Err("brief Markdown must be nonempty".into());
    }
    if markdown.len() > MAX_BRIEF_BYTES {
        return Err(format!("brief Markdown exceeds {MAX_BRIEF_BYTES} UTF-8 bytes").into());
    }
    if expected < 0 {
        return Err("expected revision must be nonnegative".into());
    }
    let generated = uuid::Uuid::new_v4().simple().to_string();
    let operation_id = operation_id.unwrap_or(&generated);
    if operation_id.trim().is_empty() {
        return Err("operation ID must be nonempty".into());
    }
    let mut connection = open(root)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let room_id = room_id(&transaction, room)?;
    // Match the common operator ledger's principal/type/ID scope. The exact
    // Markdown bytes and resolved room define input, not its CLI source.
    let request = json!({"expected_revision":expected,"markdown":markdown,"room_id":room_id});
    let request_hash = hash(request.to_string().as_bytes());
    let prior: Option<(String, String)> = transaction
        .query_row(
            "SELECT request_hash,outcome_json FROM coord_operations
             WHERE principal_kind='operator' AND principal_id='operator'
               AND operation_type='coord.brief.set' AND operation_id=?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((original_hash, result)) = prior {
        if original_hash != request_hash {
            return Err("operation ID conflicts with the original canonical request".into());
        }
        return Ok(serde_json::from_str(&result)?);
    }
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
    result["operation_id"] = json!(operation_id);
    // Keep mutation metadata in the existing operator ledger and audit outbox;
    // trusted prose belongs only in the canonical current/history tables.
    transaction.execute(
        "INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('operator','operator','coord.brief.set',?1,?2,'success',?3,?4)",
        params![operation_id,request_hash,result.to_string(),changed_at],
    )?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let timestamp =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let event = json!({
        "schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,"ts":timestamp,"event":"coord.brief_updated",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, Barrier},
    };

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("instance_id"), "owned-instance").unwrap();
        fs::write(
            root.path().join("config.toml"),
            format!("data_dir={:?}\n", data),
        )
        .unwrap();
        super::super::bootstrap(root.path()).unwrap();
        let db = open(root.path()).unwrap();
        db.execute("INSERT INTO rooms VALUES('rm-owned','owned',0)", [])
            .unwrap();
        root
    }

    fn counts(root: &Path) -> (i64, i64, i64, i64) {
        open(root).unwrap().query_row(
            "SELECT (SELECT count(*) FROM coord_brief_revisions), (SELECT count(*) FROM coord_operations), (SELECT count(*) FROM coord_attention_edges), (SELECT count(*) FROM coord_outbox)",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).unwrap()
    }

    #[test]
    fn brief_mutation_stages_a_current_audit_record_without_trusted_prose() {
        let root = fixture();
        let db = open(root.path()).unwrap();
        let result = set(root.path(), "owned", "Private standing context", 0, None).unwrap();
        assert_eq!(result["revision"], 1);
        let payload: String = db
            .query_row(
                "SELECT payload_json FROM coord_outbox WHERE destination='audit-jsonl'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let record = crate::audit::parse_record(&payload).unwrap();
        assert_eq!(record["schema_version"], 2);
        assert_eq!(record["event"], "coord.brief_updated");
        assert_eq!(record["details"]["actor"], "operator");
        assert_eq!(record["details"]["revision"], 1);
        assert!(record.get("agent").is_none());
        assert!(!payload.contains("Private standing context"));
    }

    #[test]
    fn replay_returns_the_original_result_before_revision_check_and_never_reapplies_intent() {
        let root = fixture();
        let first = set(
            root.path(),
            "owned",
            "π\r\nOriginal intent\n",
            0,
            Some("one"),
        )
        .unwrap();
        assert_eq!(first["operation_id"], "one");
        assert!(first.get("markdown").is_none());
        let later = set(root.path(), "owned", "Later intent", 1, None).unwrap();
        assert!(!later["operation_id"].as_str().unwrap().is_empty());
        let before = counts(root.path());
        super::super::bootstrap(root.path()).unwrap();
        assert_eq!(
            set(
                root.path(),
                "owned",
                "π\r\nOriginal intent\n",
                0,
                Some("one")
            )
            .unwrap(),
            first
        );
        for (markdown, revision) in [
            ("changed", 0),
            ("π\nOriginal intent\n", 0),
            ("π\r\nOriginal intent\n", 1),
        ] {
            assert!(
                set(root.path(), "owned", markdown, revision, Some("one"))
                    .unwrap_err()
                    .to_string()
                    .contains("conflicts")
            );
        }
        let db = open(root.path()).unwrap();
        db.execute("INSERT INTO rooms VALUES('rm-other','other',0)", [])
            .unwrap();
        assert!(
            set(
                root.path(),
                "other",
                "π\r\nOriginal intent\n",
                0,
                Some("one")
            )
            .unwrap_err()
            .to_string()
            .contains("conflicts")
        );
        assert!(
            set(root.path(), "owned", "stale", 0, Some("different"))
                .unwrap_err()
                .to_string()
                .contains("current revision is 2")
        );
        assert!(set(root.path(), "owned", "new", 2, Some(" ")).is_err());
        assert_eq!(counts(root.path()), before);
        assert_eq!(
            read(root.path(), "owned").unwrap()["markdown"],
            "Later intent"
        );
        let history: String = db
            .query_row(
                "SELECT markdown FROM coord_brief_revisions WHERE revision=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(history, "π\r\nOriginal intent\n");
    }

    #[test]
    fn concurrent_retries_commit_once_and_different_operations_conflict_on_revision() {
        let root = fixture();
        let barrier = Arc::new(Barrier::new(6));
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let root = root.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    set(&root, "owned", "original", 0, Some("retry")).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(results.iter().all(|r| r == &results[0]));
        assert_eq!(counts(root.path()), (1, 1, 0, 1));
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = ["left", "right"]
            .into_iter()
            .map(|operation| {
                let root = root.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    set(&root, "owned", operation, 1, Some(operation)).map_err(|e| e.to_string())
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .find_map(|r| r.as_ref().err())
                .unwrap()
                .contains("current revision is 2")
        );
        assert_eq!(counts(root.path()), (2, 2, 0, 2));
    }

    #[test]
    fn ledger_and_audit_failures_roll_back_revision_projection_attention_and_retry() {
        for table in ["coord_operations", "coord_outbox"] {
            let root = fixture();
            let db = open(root.path()).unwrap();
            db.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-owned','agent','ag-owned','receive',1)", []).unwrap();
            let condition = if table == "coord_outbox" {
                "WHEN NEW.destination='audit-jsonl'"
            } else {
                ""
            };
            db.execute_batch(&format!("CREATE TRIGGER fail_write BEFORE INSERT ON {table} {condition} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
            assert!(set(root.path(), "owned", "intent", 0, Some("retry")).is_err());
            assert_eq!(counts(root.path()), (0, 0, 0, 0));
            assert_eq!(read(root.path(), "owned").unwrap()["revision"], 0);
            assert_eq!(
                db.query_row("SELECT count(*) FROM coord_attention_feeds", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            db.execute_batch("DROP TRIGGER fail_write").unwrap();
            assert_eq!(
                set(root.path(), "owned", "intent", 0, Some("retry")).unwrap()["revision"],
                1
            );
            assert_eq!(counts(root.path()), (1, 1, 1, 2));
        }
    }
}
