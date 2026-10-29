//! One native delivery loop for the existing Coord audit and wake-hint outbox.
use super::{CoordClient, CoordError, Duration, Path, open_db};
use crate::{Error, audit};
use rusqlite::params;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::{sync::watch, task::JoinHandle};

pub(crate) struct Delivery {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Delivery {
    pub(crate) fn start(client: Arc<CoordClient>, audit: Arc<audit::Writer>) -> Option<Self> {
        // A passive client's HOME fallback is not authority for a background
        // writer to drain an unrelated instance into this proxy's audit sink.
        if !client.owner.explicit_directory {
            return None;
        }
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.changed() => break,
                    _ = drain(&client, &audit) => {},
                }
                tokio::select! {
                    _ = stopped.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {},
                }
            }
        });
        Some(Self {
            stop,
            task: Some(task),
        })
    }

    pub(crate) async fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct Pending {
    id: String,
    event_type: String,
    payload: String,
}

fn pending(db: &Path, destination: &str) -> Result<Vec<Pending>, CoordError> {
    let connection = open_db(db, false)?;
    connection
        .prepare(
            "SELECT event_id,event_type,payload_json FROM coord_outbox
         WHERE destination=?1 AND delivered_at IS NULL ORDER BY created_at,event_id LIMIT 64",
        )
        .map_err(|_| CoordError::Data)?
        .query_map([destination], |row| {
            Ok(Pending {
                id: row.get(0)?,
                event_type: row.get(1)?,
                payload: row.get(2)?,
            })
        })
        .map_err(|_| CoordError::Data)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoordError::Data)
}

fn record_attempt(db: &Path, id: &str, delivered: bool) -> Result<(), CoordError> {
    open_db(db, true)?
        .execute(
            "UPDATE coord_outbox SET attempt_count=attempt_count+1,
         delivered_at=CASE WHEN ?2 THEN ?3 ELSE NULL END,
         last_error_class=CASE WHEN ?2 THEN NULL ELSE 'delivery_failed' END
         WHERE event_id=?1 AND delivered_at IS NULL",
            params![id, delivered, super::now_ms()],
        )
        .map_err(|_| CoordError::Data)?;
    Ok(())
}

async fn deliver(
    client: &CoordClient,
    audit: &audit::Writer,
    destination: &str,
    row: &Pending,
) -> Result<(), Error> {
    let value: Value = serde_json::from_str(&row.payload)?;
    match destination {
        "audit-jsonl" => {
            if value["event_id"] != row.id
                || value["event"] != row.event_type
                || value["kind"] != "coord"
            {
                return Err("Coord audit outbox identity is invalid".into());
            }
            audit.deliver_coord(&row.payload).await?;
        }
        "attention-nats" => {
            let recipient = value["recipient_agent_id"]
                .as_str()
                .filter(|id| super::valid_agent_id(id))
                .ok_or("invalid Coord hint recipient")?;
            let attention = value["attention_id"]
                .as_str()
                .filter(|id| super::valid_attention_id(id))
                .ok_or("invalid Coord hint attention ID")?;
            let sequence = value["feed_sequence"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("invalid Coord hint sequence")?;
            let connection = client
                .client()
                .await
                .map_err(|_| "Coord NATS is unavailable")?;
            connection
                .publish(
                    format!("coord.attention.{recipient}"),
                    json!({"event_id":row.id,"attention_id":attention,"feed_sequence":sequence})
                        .to_string()
                        .into(),
                )
                .await?;
            // A queued publish is not a delivery receipt. An ambiguous flush
            // leaves the row pending, so a retry may publish the same event ID.
            connection.flush().await?;
        }
        _ => return Err("unknown Coord outbox destination".into()),
    }
    Ok(())
}

async fn drain(client: &CoordClient, audit: &audit::Writer) {
    let db = client.owner.data_dir.join("v0.db");
    // Bound each pass and attempt both destinations even when one is down.
    for destination in ["audit-jsonl", "attention-nats"] {
        let path = db.clone();
        let Ok(Ok(rows)) = tokio::task::spawn_blocking(move || pending(&path, destination)).await
        else {
            continue;
        };
        for row in rows {
            let delivered = deliver(client, audit, destination, &row).await.is_ok();
            let path = db.clone();
            let _ = tokio::task::spawn_blocking(move || record_attempt(&path, &row.id, delivered))
                .await;
            if !delivered {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord_rooms;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, CoordClient, String) {
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        fs::create_dir(root.path().join("data")).unwrap();
        fs::write(root.path().join("data/instance_id"), "si-owned").unwrap();
        fs::write(root.path().join("config.toml"), "admin_port=0\n").unwrap();
        coord_rooms::bootstrap(root.path()).unwrap();
        let data = root.path().join("data/coord");
        let db = open_db(&data.join("v0.db"), true).unwrap();
        db.execute("INSERT INTO rooms VALUES('rm-owned','owned',0)", [])
            .unwrap();
        coord_rooms::brief::set(root.path(), "owned", "Private canonical brief", 0).unwrap();
        let id = db
            .query_row("SELECT event_id FROM coord_outbox", [], |row| row.get(0))
            .unwrap();
        (root, CoordClient::new(None, Some(data)), id)
    }

    #[tokio::test]
    async fn audit_failure_stays_pending_and_ambiguous_mark_replays_the_same_event() {
        let (root, client, id) = fixture();
        let db = open_db(&client.owner.data_dir.join("v0.db"), true).unwrap();
        let path = root.path().join("audit.jsonl");
        fs::create_dir(&path).unwrap();
        let writer = audit::Writer::new(path.clone(), audit::Settings::default());
        drain(&client, &writer).await;
        let pending: (Option<i64>, i64, String) = db
            .query_row(
                "SELECT delivered_at,attempt_count,last_error_class FROM coord_outbox",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(pending, (None, 1, "delivery_failed".into()));
        fs::remove_dir(&path).unwrap();
        // The external write succeeds, but the delivery marker cannot commit.
        db.execute_batch("CREATE TRIGGER reject_mark BEFORE UPDATE ON coord_outbox WHEN NEW.delivered_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected delivery mark failure'); END;").unwrap();
        drain(&client, &writer).await;
        assert!(
            db.query_row("SELECT delivered_at FROM coord_outbox", [], |r| r
                .get::<_, Option<i64>>(0))
                .unwrap()
                .is_none()
        );
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
        db.execute_batch("DROP TRIGGER reject_mark").unwrap();
        // A new owner resumes the still-pending row after the ambiguous append.
        let restarted = CoordClient::new(None, Some(client.owner.data_dir.clone()));
        let writer = audit::Writer::new(path.clone(), audit::Settings::default());
        drain(&restarted, &writer).await;
        drain(&restarted, &writer).await;
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
        let lines = fs::read_to_string(&path).unwrap();
        assert!(!lines.contains("Private canonical brief"));
        let events: Vec<_> = lines
            .lines()
            .map(|line| audit::parse_record(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], events[1]);
        assert_eq!(events[0]["event_id"], id);
        assert!(
            db.query_row("SELECT delivered_at FROM coord_outbox", [], |r| r
                .get::<_, Option<i64>>(0))
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn unavailable_nats_keeps_hints_pending_without_stalling_audit() {
        let (root, client, _) = fixture();
        let db = open_db(&client.owner.data_dir.join("v0.db"), true).unwrap();
        let hint = json!({"attention_id":format!("attn-{}","a".repeat(32)),"recipient_agent_id":format!("ag-{}","b".repeat(32)),"feed_sequence":1});
        db.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES('evt-hint','attention-nats','coord.attention_hint',?1,0)", [hint.to_string()]).unwrap();
        let writer =
            audit::Writer::new(root.path().join("audit.jsonl"), audit::Settings::default());
        drain(&client, &writer).await;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM coord_outbox WHERE delivered_at IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(
            db.query_row(
                "SELECT delivered_at FROM coord_outbox WHERE event_id='evt-hint'",
                [],
                |r| r.get::<_, Option<i64>>(0)
            )
            .unwrap()
            .is_none()
        );
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    }

    #[tokio::test]
    async fn unknown_publish_stages_a_valid_operator_event_and_preserves_unknown_on_failure() {
        let (_root, client, _) = fixture();
        let db = open_db(&client.owner.data_dir.join("v0.db"), true).unwrap();
        let result =
            super::super::publish_unknown_response(&client, super::super::local_operator_request())
                .await;
        assert_eq!(result.response.status, 503);
        assert!(result.audit_owned);
        let payload: String = db.query_row("SELECT payload_json FROM coord_outbox WHERE event_type='coord.publish_outcome_unknown'", [], |r|r.get(0)).unwrap();
        let record = audit::parse_record(&payload).unwrap();
        assert_eq!(record["kind"], "coord");
        assert_eq!(record["details"]["send_outcome"], "unknown");
        assert!(record.get("agent").is_none());
        db.execute_batch("CREATE TRIGGER reject_unknown BEFORE INSERT ON coord_outbox BEGIN SELECT RAISE(ABORT,'injected staging failure'); END;").unwrap();
        let result =
            super::super::publish_unknown_response(&client, super::super::local_operator_request())
                .await;
        assert_eq!(result.response.status, 503);
        assert!(result.audit_owned);
        let body: Value = serde_json::from_slice(&result.response.body_bytes()).unwrap();
        assert_eq!(body["send_outcome"], "unknown");
        assert_eq!(db.query_row("SELECT count(*) FROM coord_outbox WHERE event_type='coord.publish_outcome_unknown'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    }
}
