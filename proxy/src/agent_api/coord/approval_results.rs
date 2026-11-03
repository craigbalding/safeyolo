//! The existing attention feed carries private canonical approval references.
//! JetStream retains references; the approval owners retain every decision and
//! irreversible withholding receipt. No room membership authorizes this path.
use super::*;
use crate::approvals::pending::results::{RETAIN_SECONDS, Ready, Reference};

const STREAM: &str = "APPROVAL_RESULTS";

fn reference(edge: &FeedEdge, principal: &str) -> Reference {
    Reference {
        source: "approval".into(),
        approval_id: edge.object_id.clone(),
        agent_id: principal.into(),
        attention_id: edge.attention_id.clone(),
    }
}

async fn canonical(
    runtime: Option<&crate::RuntimeState>,
    reference: &Reference,
) -> Result<Option<Ready>, CoordError> {
    let runtime = runtime
        .ok_or(CoordError::Unavailable)?
        .read()
        .map_err(|_| CoordError::Unavailable)?
        .clone();
    let policy = runtime.policy.clone().ok_or(CoordError::Unavailable)?;
    match reference.source.as_str() {
        "approval" => {
            let store = runtime.audit.approvals().clone();
            let reference = reference.clone();
            tokio::task::spawn_blocking(move || store.result(&reference, &policy))
                .await
                .map_err(|_| CoordError::Unavailable)?
                .map_err(|_| CoordError::Unavailable)
        }
        _ => Err(CoordError::Data),
    }
}

pub(super) async fn authorized(
    runtime: Option<&crate::RuntimeState>,
    edge: &FeedEdge,
    principal: &str,
) -> Result<bool, CoordError> {
    Ok(canonical(runtime, &reference(edge, principal))
        .await?
        .is_some())
}

pub(super) async fn read(
    client: &CoordClient,
    runtime: Option<&crate::RuntimeState>,
    principal: &str,
    edge: &AttentionEdge,
) -> Result<Value, CoordError> {
    if edge.room_id.is_some() {
        return Err(CoordError::Data);
    }
    let reference = reference(
        &FeedEdge {
            attention_id: edge.attention_id.clone(),
            room_id: None,
            kind: edge.kind.clone(),
            object_id: edge.object_id.clone(),
            revision_or_sequence: edge.revision_or_sequence,
        },
        principal,
    );
    canonical(runtime, &reference)
        .await?
        .ok_or(CoordError::NotFound)?;
    let js = jetstream::new(client.client().await?);
    let stream = js
        .get_stream(STREAM)
        .await
        .map_err(|_| CoordError::Unavailable)?;
    let raw = stream
        .get_raw_message(edge.revision_or_sequence)
        .await
        .map_err(|_| CoordError::Unavailable)?;
    let retained: Reference = serde_json::from_slice(&raw.payload).map_err(|_| CoordError::Data)?;
    if retained != reference {
        return Err(CoordError::Data);
    }
    // Recheck the canonical owner and irreversible tombstone after broker I/O,
    // immediately before disclosing even the outcome or approval identifier.
    let ready = canonical(runtime, &reference)
        .await?
        .ok_or(CoordError::NotFound)?;
    client.bound_current()?;
    Ok(json!({"edge":edge.public_json(),"object":{
        "kind":"approval_result","approval_id":reference.approval_id,"source":reference.source,
        "status":ready.outcome,
        "message":"Read the canonical approval and effective access before retrying. Receiving this result does not grant permission or retry the original request."
    }}))
}

fn projected(db: &Path, reference: &Reference) -> Result<bool, CoordError> {
    open_db(db, false)?.query_row("SELECT EXISTS(SELECT 1 FROM coord_attention_edges WHERE recipient_agent_id=?1 AND attention_id=?2)", params![reference.agent_id, reference.attention_id], |r| r.get(0)).map_err(|_| CoordError::Data)
}

fn project(db: &Path, reference: &Reference, sequence: u64) -> Result<(), CoordError> {
    let mut db = open_db(db, true)?;
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| CoordError::Unavailable)?;
    if tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM coord_attention_edges WHERE attention_id=?1)",
            [&reference.attention_id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|_| CoordError::Data)?
    {
        return Ok(());
    }
    tx.execute("INSERT OR IGNORE INTO coord_attention_feeds(recipient_agent_id,last_sequence) VALUES(?1,0)", [&reference.agent_id]).map_err(|_| CoordError::Data)?;
    tx.execute("UPDATE coord_attention_feeds SET last_sequence=last_sequence+1 WHERE recipient_agent_id=?1", [&reference.agent_id]).map_err(|_| CoordError::Data)?;
    let feed_sequence: i64 = tx
        .query_row(
            "SELECT last_sequence FROM coord_attention_feeds WHERE recipient_agent_id=?1",
            [&reference.agent_id],
            |r| r.get(0),
        )
        .map_err(|_| CoordError::Data)?;
    tx.execute("INSERT INTO coord_attention_edges(recipient_agent_id,feed_sequence,attention_id,room_id,kind,object_id,revision_or_sequence,membership_granted_at,created_at) VALUES(?1,?2,?3,NULL,'approval_result',?4,?5,0,?6)", params![reference.agent_id, feed_sequence, reference.attention_id, reference.approval_id, i64::try_from(sequence).map_err(|_| CoordError::Data)?, now_ms()]).map_err(|_| CoordError::Data)?;
    let hint = json!({"recipient_agent_id":reference.agent_id,"attention_id":reference.attention_id,"feed_sequence":feed_sequence});
    tx.execute("INSERT OR IGNORE INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'attention-nats','coord.attention_hint',?2,?3)", params![attention_event_id(&reference.attention_id), hint.to_string(), now_ms()]).map_err(|_| CoordError::Data)?;
    tx.commit().map_err(|_| CoordError::Unavailable)
}

async fn deliver(
    client: &CoordClient,
    runtime: &crate::RuntimeState,
    ready: Ready,
) -> Result<(), CoordError> {
    let reference = ready.reference;
    let db = client.owner.data_dir.join("v0.db");
    let (path, check) = (db.clone(), reference.clone());
    if tokio::task::spawn_blocking(move || projected(&path, &check))
        .await
        .map_err(|_| CoordError::Unavailable)??
    {
        return Ok(());
    }
    // Admission uses the same canonical owner check as disclosure. A revoke
    // after publication can leave broker bytes, but can never release them.
    let ready = canonical(Some(runtime), &reference)
        .await?
        .ok_or(CoordError::NotFound)?;
    let js = jetstream::new(client.client().await?);
    let stream = js
        .get_or_create_stream(jetstream::stream::Config {
            name: STREAM.into(),
            subjects: vec!["coord.approval_results.>".into()],
            storage: jetstream::stream::StorageType::File,
            max_age: Duration::from_secs(RETAIN_SECONDS as u64),
            max_bytes: 4 * 1024 * 1024,
            max_messages: 100_000,
            max_message_size: 1024,
            discard: jetstream::stream::DiscardPolicy::New,
            duplicate_window: Duration::from_secs(120),
            ..Default::default()
        })
        .await
        .map_err(|_| CoordError::Unavailable)?;
    let sequence = if let Some(sequence) = ready.delivery.stream_sequence {
        let raw = stream
            .get_raw_message(sequence)
            .await
            .map_err(|_| CoordError::Unavailable)?;
        if serde_json::from_slice::<Reference>(&raw.payload).map_err(|_| CoordError::Data)?
            != reference
        {
            return Err(CoordError::Data);
        }
        sequence
    } else {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", reference.attention_id.as_str());
        let ack = js
            .publish_with_headers(
                format!("coord.approval_results.{}", reference.agent_id),
                headers,
                serde_json::to_vec(&reference)
                    .map_err(|_| CoordError::Data)?
                    .into(),
            )
            .await
            .map_err(|_| CoordError::Unavailable)?
            .await
            .map_err(|_| CoordError::Unavailable)?;
        let snapshot = runtime.read().map_err(|_| CoordError::Unavailable)?.clone();
        let store = snapshot.audit.approvals().clone();
        let published = reference.clone();
        let sequence = ack.sequence;
        tokio::task::spawn_blocking(move || store.result_published(&published, sequence))
            .await
            .map_err(|_| CoordError::Unavailable)?
            .map_err(|_| CoordError::Unavailable)?;
        ack.sequence
    };
    canonical(Some(runtime), &reference)
        .await?
        .ok_or(CoordError::NotFound)?;
    tokio::task::spawn_blocking(move || project(&db, &reference, sequence))
        .await
        .map_err(|_| CoordError::Unavailable)?
}

pub(super) async fn reconcile(
    client: &CoordClient,
    runtime: &crate::RuntimeState,
    position: &mut i64,
) -> Result<(), CoordError> {
    let snapshot = runtime.read().map_err(|_| CoordError::Unavailable)?.clone();
    let policy = snapshot.policy.clone().ok_or(CoordError::Unavailable)?;
    let (store, page_policy, after) = (
        snapshot.audit.approvals().clone(),
        policy.clone(),
        *position,
    );
    let (next, ready) = tokio::task::spawn_blocking(move || store.result_page(&page_policy, after))
        .await
        .map_err(|_| CoordError::Unavailable)?
        .map_err(|_| CoordError::Unavailable)?;
    let mut remaining = ready.len();
    if ready.is_empty() {
        *position = next;
        return Ok(());
    }
    if !client.owner.data_dir.join("v0.db").is_file() {
        let root = snapshot
            .config
            .native_config_dir
            .clone()
            .ok_or(CoordError::Unavailable)?;
        tokio::task::spawn_blocking(move || crate::coord_rooms::bootstrap(&root))
            .await
            .map_err(|_| CoordError::Unavailable)?
            .map_err(|_| CoordError::Unavailable)?;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut unavailable = false;
    for result in ready {
        let time_left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if time_left.is_zero() {
            break;
        }
        let scanned = result.scan_position;
        match tokio::time::timeout(time_left, deliver(client, runtime, result)).await {
            Ok(Ok(())) | Ok(Err(CoordError::NotFound)) => {}
            _ => unavailable = true,
        }
        // Advance past an attempted item even on failure. A later page cycle
        // retries it without starving subsequent references.
        remaining -= 1;
        *position = if remaining == 0 { next } else { scanned };
    }
    if unavailable {
        Err(CoordError::Unavailable)
    } else {
        Ok(())
    }
}
