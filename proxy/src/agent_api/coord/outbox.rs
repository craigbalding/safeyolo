//! Bounded delivery and owner-side repair for the existing Coord outbox.
use super::{CoordClient, CoordError, Duration, Path, open_db};
use crate::{Error, audit};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::{sync::watch, task::JoinHandle};

pub(crate) struct Delivery {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Delivery {
    pub(crate) fn start(
        client: Arc<CoordClient>,
        audit: Arc<audit::Writer>,
        runtime: crate::RuntimeState,
    ) -> Option<Self> {
        // A passive client's HOME fallback is not authority for a background
        // writer to drain an unrelated instance into this proxy's audit sink.
        if !client.owner.explicit_directory {
            return None;
        }
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            for destination in ["audit-jsonl", "attention-nats", "federation-nats"] {
                let (client, audit) = (client.clone(), audit.clone());
                workers.spawn(async move {
                    loop {
                        drain_destination(&client, &audit, destination).await;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                });
            }
            let (approval_client, approval_runtime) = (client.clone(), runtime.clone());
            workers.spawn(async move {
                let mut position = 0;
                let mut unavailable = false;
                loop {
                    let failed = super::approval_results::reconcile(
                        &approval_client,
                        &approval_runtime,
                        &mut position,
                    ).await.is_err();
                    if failed != unavailable {
                        eprintln!("Private approval result delivery {}. Canonical approvals and operator controls remain available.",if failed {"unavailable"}else{"recovered"});
                    }
                    unavailable=failed;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            });
            let observer = client.clone();
            workers.spawn(async move {
                let mut position = 0;
                let mut signals = std::collections::HashMap::new();
                let mut unavailable=false;
                loop {
                    let failed = super::operational::reconcile(
                        &observer,
                        &runtime,
                        &mut position,
                        &mut signals,
                    ).await.is_err();
                    if failed != unavailable {
                        eprintln!("Selected operational observation {}. Inspect per-source Coord diagnostics; missing evidence is not target failure.",if failed {"unavailable"}else{"recovered"});
                    }
                    unavailable=failed;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
            workers.spawn(async move {
                let mut position = String::new();
                loop {
                    let _ = client.repair_projections(&mut position).await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            });
            tokio::select! {
                _=stopped.changed()=>{},
                result=workers.join_next()=>{ eprintln!("Coord delivery worker stopped; delivery is unavailable: {}", if matches!(result,Some(Err(_))) {"task failed"} else {"worker ended"}); },
            }
            workers.abort_all();
            while workers.join_next().await.is_some() {}
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

fn coord_audit_payload(row: &Pending) -> Result<&str, Error> {
    let value: Value = serde_json::from_str(&row.payload)?;
    let kind_matches = value["kind"] == "coord"
        || (value["kind"] == "agent" && row.event_type == "agent.operational");
    if value["event_id"] != row.id || value["event"] != row.event_type || !kind_matches {
        return Err("Coord audit outbox identity is invalid".into());
    }
    Ok(&row.payload)
}

pub(crate) fn diagnostics(db: &Path) -> Result<Value, crate::Error> {
    let connection = super::open_db(db, false).map_err(|_| "Coord store unavailable")?;
    let destinations=connection.prepare("SELECT destination,count(*),sum(delivered_at IS NULL),min(CASE WHEN delivered_at IS NULL THEN created_at END),sum(CASE WHEN delivered_at IS NULL AND last_error_class IS NOT NULL THEN 1 ELSE 0 END),sum(attempt_count) FROM coord_outbox GROUP BY destination")?
        .query_map([],|row|Ok(json!({"destination":row.get::<_,String>(0)?,"retained_rows":row.get::<_,i64>(1)?,"pending":row.get::<_,i64>(2)?,"oldest_pending_age_ms":row.get::<_,Option<i64>>(3)?.map(|time|super::now_ms().saturating_sub(time)),"failed_pending":row.get::<_,i64>(4)?,"attempts":row.get::<_,i64>(5)?})))?.collect::<Result<Vec<_>,_>>()?;
    let observations=connection.prepare("SELECT agent_id,source,last_success_at,unavailable_reason,last_observed_at,changed_at FROM coord_observation_health ORDER BY agent_id,source")?
        .query_map([],|row|Ok(json!({"agent_id":row.get::<_,String>(0)?,"source":row.get::<_,String>(1)?,"last_success_at":row.get::<_,Option<i64>>(2)?,"unavailable_reason":row.get::<_,Option<String>>(3)?,"last_observed_at":row.get::<_,i64>(4)?,"changed_at":row.get::<_,i64>(5)?})))?.collect::<Result<Vec<_>,_>>()?;
    let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let free_pages: i64 =
        connection.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
    Ok(
        json!({"outbox":destinations,"observations":observations,"sqlite":{"bytes":pages*page_size,"free_pages":free_pages},"retention":"Canonical references and delivered outbox rows have no automatic pruning. Preserve the owning store; delivery is not an audit completeness guarantee."}),
    )
}

fn pending(db: &Path, destination: &str) -> Result<Vec<Pending>, CoordError> {
    let connection = open_db(db, false)?;
    connection
        .prepare(
            "SELECT event_id,event_type,payload_json FROM coord_outbox
         WHERE destination=?1 AND delivered_at IS NULL AND next_attempt_at<=?2 ORDER BY next_attempt_at,created_at,event_id LIMIT 64",
        )
        .map_err(|_| CoordError::Data)?
        .query_map(params![destination,super::now_ms()], |row| {
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
         last_error_class=CASE WHEN ?2 THEN NULL ELSE 'delivery_failed' END,
         next_attempt_at=CASE WHEN ?2 THEN 0 ELSE ?3 + min(30000, 1000 * (1 << min(attempt_count,5))) END
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
            audit.deliver_coord(coord_audit_payload(row)?).await?;
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
            let connection = super::open_db(&client.owner.data_dir.join("v0.db"), true)
                .map_err(|_| "Coord identity store unavailable")?;
            let remote: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM coord_federation_agents WHERE principal_id=?1)",
                [recipient],
                |row| row.get(0),
            )?;
            if remote {
                connection.execute("INSERT OR IGNORE INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'federation-nats',?2,?3,?4)", params![format!("{}-federation",row.id),row.event_type,row.payload,super::now_ms()])?;
            }
        }
        "federation-nats" => {
            let recipient = value["recipient_agent_id"]
                .as_str()
                .ok_or("invalid hint recipient")?;
            let attention = value["attention_id"]
                .as_str()
                .ok_or("invalid hint attention")?;
            let sequence = value["feed_sequence"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("invalid hint sequence")?;
            let remote: Option<String> =
                super::open_db(&client.owner.data_dir.join("v0.db"), false)
                    .map_err(|_| "Coord identity store unavailable")?
                    .query_row(
                        "SELECT instance_id FROM coord_federation_agents WHERE principal_id=?1",
                        [recipient],
                        |row| row.get(0),
                    )
                    .optional()?;
            if let Some(source) = remote {
                if !remote_hint_allowed(client, &source, recipient, attention, sequence)? {
                    return Ok(());
                }
                let instance = std::fs::read_to_string(client.owner.data_dir.join("instance_id"))?;
                let connection = client
                    .owner
                    .federation_nats
                    .lock()
                    .await
                    .clone()
                    .ok_or("federation notifications unavailable")?;
                crate::coord_rooms::federation::nats::retained_notices(
                    &connection,
                    instance.trim(),
                    &source,
                )
                .await?;
                async_nats::jetstream::new(connection)
                    .publish(
                        crate::coord_rooms::federation::nats::notice_subject(
                            instance.trim(),
                            &source,
                            recipient,
                        ),
                        json!({"wake":true}).to_string().into(),
                    )
                    .await?
                    .await?;
            }
        }
        _ => return Err("unknown Coord outbox destination".into()),
    }
    Ok(())
}

fn remote_hint_allowed(
    client: &CoordClient,
    source: &str,
    principal: &str,
    attention: &str,
    sequence: u64,
) -> Result<bool, Error> {
    let db = client.owner.data_dir.join("v0.db");
    let conn = super::open_db(&db, false).map_err(|_| "Coord identity store unavailable")?;
    let trusted: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND enabled=1)",
        [source],
        |row| row.get(0),
    )?;
    if !trusted {
        return Ok(false);
    }
    let page = super::read_attention_feed(&db, principal, sequence - 1, 1)
        .map_err(|_| "canonical attention unavailable")?;
    let Some(edge) = page
        .edges
        .into_iter()
        .find(|edge| edge.attention_id == attention)
    else {
        return Ok(false);
    };
    if edge.kind != "operational_event" {
        return Ok(true);
    }
    let mut policy = crate::policy::Policy::from_native_path(
        client.policy_file.as_deref().ok_or("policy unavailable")?,
    )?;
    if let Some(root) = &client.instance_root {
        policy.set_identity_root(root.clone());
    }
    let reference = super::operational::retained(&db, &edge.object_id)
        .map_err(|_| "canonical operational reference unavailable")?;
    let instance = std::fs::read_to_string(client.owner.data_dir.join("instance_id"))?;
    crate::peer_support::events::permits(&policy, instance.trim(), principal, &reference, true)
}

#[cfg(test)]
async fn drain(client: &CoordClient, audit: &audit::Writer) {
    for destination in ["audit-jsonl", "attention-nats", "federation-nats"] {
        drain_destination(client, audit, destination).await;
    }
}

async fn drain_destination(client: &CoordClient, audit: &audit::Writer, destination: &str) {
    use futures_util::{StreamExt, stream};
    let db = client.owner.data_dir.join("v0.db");
    let path = db.clone();
    let destination = destination.to_owned();
    let selected = destination.clone();
    let Ok(Ok(rows)) = tokio::task::spawn_blocking(move || pending(&path, &selected)).await else {
        return;
    };
    let concurrency = if destination == "audit-jsonl" { 1 } else { 8 };
    let attempts = stream::iter(rows)
        .map(|row| {
            let (db, destination) = (db.clone(), destination.clone());
            async move {
                let delivered = matches!(
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        deliver(client, audit, &destination, &row)
                    )
                    .await,
                    Ok(Ok(()))
                );
                let _ =
                    tokio::task::spawn_blocking(move || record_attempt(&db, &row.id, delivered))
                        .await;
            }
        })
        .buffer_unordered(concurrency);
    attempts.collect::<Vec<_>>().await;
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
        coord_rooms::brief::set(root.path(), "owned", "Private canonical brief", 0, None).unwrap();
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
        drain(&client, &writer).await;
        assert_eq!(
            db.query_row("SELECT attempt_count FROM coord_outbox", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "retry ignored the backoff deadline"
        );
        fs::remove_dir(&path).unwrap();
        db.execute("UPDATE coord_outbox SET next_attempt_at=0", [])
            .unwrap();
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

    #[test]
    fn failed_batch_cannot_starve_new_hints_or_unattempted_retries() {
        let (_root, client, _) = fixture();
        let path = client.owner.data_dir.join("v0.db");
        let db = open_db(&path, true).unwrap();
        for index in 0..64 {
            db.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at,attempt_count,next_attempt_at) VALUES(?1,'federation-nats','coord.attention_hint','{}',0,5,1)", [format!("failed-{index:02}")]).unwrap();
        }
        db.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES('fresh','federation-nats','coord.attention_hint','{}',2)", []).unwrap();
        let batch = pending(&path, "federation-nats").unwrap();
        assert_eq!(batch.len(), 64);
        assert!(
            batch.iter().any(|row| row.id == "fresh"),
            "a full failed batch starved a later hint"
        );
        for row in batch {
            record_attempt(&path, &row.id, false).unwrap();
        }
        let next = pending(&path, "federation-nats").unwrap();
        assert_eq!(
            next.len(),
            1,
            "attempted retries crowded out an older eligible row"
        );
        assert!(next[0].id.starts_with("failed-"));
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
