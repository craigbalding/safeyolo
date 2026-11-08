//! Local, room-independent operational references on ordinary Coord attention.
use super::*;
use crate::peer_support::{
    self,
    events::{self, Reference},
};
use crate::policy::support::Notification;

pub(super) fn retained(db: &Path, event: &str) -> Result<Reference, CoordError> {
    let reference: String = open_db(db, false)?
        .query_row(
            "SELECT reference_json FROM coord_operational_references WHERE event_id=?1",
            [event],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoordError::Unavailable)?
        .ok_or(CoordError::NotFound)?;
    let reference: Reference = serde_json::from_str(&reference).map_err(|_| CoordError::Data)?;
    if reference.event_id != event {
        return Err(CoordError::Data);
    }
    Ok(reference)
}

pub(super) async fn authorized(
    runtime: Option<&crate::RuntimeState>,
    edge: &FeedEdge,
    principal: &str,
) -> Result<bool, CoordError> {
    let runtime = runtime.ok_or(CoordError::Unavailable)?;
    let db = runtime
        .read()
        .map_err(|_| CoordError::Unavailable)?
        .coord
        .owner
        .data_dir
        .join("v0.db");
    let reference = retained(&db, &edge.object_id)?;
    let policy = peer_support::current_policy(runtime).map_err(|_| CoordError::Unavailable)?;
    let root = runtime
        .read()
        .map_err(|_| CoordError::Unavailable)?
        .config
        .native_config_dir
        .clone()
        .ok_or(CoordError::Unavailable)?;
    let instance = events::instance(&root).map_err(|_| CoordError::Unavailable)?;
    events::permits(&policy, &instance, principal, &reference, false)
        .map_err(|_| CoordError::Unavailable)
}

fn signal_evidence(db: &Path, reference: &Reference) -> Result<Value, CoordError> {
    let conn = open_db(db, false)?;
    let (room,document):(String,String) = conn.query_row(
        "SELECT r.name,s.document_json FROM coord_signals s JOIN rooms r ON r.room_id=s.room_id WHERE s.signal_id=?1",[reference.signal_id.as_deref().ok_or(CoordError::Data)?],|row|Ok((row.get(0)?,row.get(1)?)))
        .optional().map_err(|_|CoordError::Data)?.ok_or(CoordError::NotFound)?;
    let signal: Value = serde_json::from_str(&document).map_err(|_| CoordError::Data)?;
    if room != reference.source_id
        || signal["author"]["kind"] != "agent"
        || signal["author"]["id"] != reference.target.agent_id
    {
        return Err(CoordError::Data);
    }
    let revision = crate::coord_rooms::signals::revision(
        &conn,
        signal["room_id"].as_str(),
        signal["signal_id"].as_str().ok_or(CoordError::Data)?,
        reference.sequence as i64,
    )
    .map_err(|_| CoordError::NotFound)?;
    Ok(
        json!({"source_status":"retained","selected_revision":revision,"current":signal,
        "attribution":"Canonical author identity; signal body and basis are agent-authored claims. No room history is disclosed."}),
    )
}

pub(super) async fn read(
    client: &CoordClient,
    runtime: Option<&crate::RuntimeState>,
    principal: &str,
    edge: &AttentionEdge,
) -> Result<Value, CoordError> {
    let runtime = runtime.ok_or(CoordError::Unavailable)?;
    let db = client.owner.data_dir.join("v0.db");
    let reference = retained(&db, &edge.object_id)?;
    let policy = peer_support::current_policy(runtime).map_err(|_| CoordError::Unavailable)?;
    let root = runtime
        .read()
        .map_err(|_| CoordError::Unavailable)?
        .config
        .native_config_dir
        .clone()
        .ok_or(CoordError::Unavailable)?;
    let instance = events::instance(&root).map_err(|_| CoordError::Unavailable)?;
    if !events::permits(&policy, &instance, principal, &reference, false)
        .map_err(|_| CoordError::Unavailable)?
    {
        return Err(CoordError::ObservationRequired);
    }
    let evidence = if reference.kind == Notification::NeedsOperator {
        signal_evidence(&db, &reference)?
    } else {
        events::evidence(&root, &reference).map_err(|_| CoordError::Unavailable)?
    };
    // Source I/O is not authority. Recheck current observation and disclosure
    // immediately before returning any identifiers or source facts.
    let policy = peer_support::current_policy(runtime).map_err(|_| CoordError::Unavailable)?;
    if !events::permits(&policy, &instance, principal, &reference, false)
        .map_err(|_| CoordError::Unavailable)?
    {
        return Err(CoordError::ObservationRequired);
    }
    client.bound_current()?;
    Ok(
        json!({"edge":edge.public_json(),"object":{"kind":"operational_event","reference":reference,"evidence":evidence,
        "message":message(reference.kind),"authority":"Notification and resolution create no work, grant no permission and execute no repair. Use current support grants for a separate inspection or action."}}),
    )
}

fn message(kind: Notification) -> &'static str {
    match kind {
        Notification::LaunchFailed => {
            "A host start request failed. Inspect current sandbox and control evidence before retrying."
        }
        Notification::SandboxAvailability | Notification::ControlAvailability => {
            "The host observed an availability change. Check expected_stop and current state; unknown or degraded does not mean the sandbox died."
        }
        Notification::SandboxRecovered => {
            "The host observed running sandbox and ready control after an unavailable condition. Model progress is unverified."
        }
        Notification::CommandExit => {
            "The guest command supervisor reaped its configured child. Inspect exit status, signal and expected stop. This is not a normal invocation exit inside a live Coord supervisor."
        }
        Notification::CommandRestart => {
            "The guest command supervisor started a replacement child. Sustained model health remains unverified."
        }
        Notification::CommandFailed => {
            "Guest command supervision reached terminal failure. Inspect its saved result before a separately authorized recovery."
        }
        Notification::SupervisorExit => {
            "Guest PID 1 reaped its command supervisor unexpectedly. Inspect the owner exit and any replacement outcome."
        }
        Notification::SupervisorRestart => {
            "Guest command supervision resumed its preserved launch after a PID-1-observed owner exit."
        }
        Notification::NeedsOperator => {
            "A selected subject's material signal needs operator attention. Read its canonical current state and attributed claim."
        }
    }
}

fn stage(db: &Path, reference: &Reference, recipients: &[String]) -> Result<(), CoordError> {
    let mut conn = open_db(db, true)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| CoordError::Unavailable)?;
    let inserted = tx.execute("INSERT OR IGNORE INTO coord_operational_references(event_id,reference_json,created_at) VALUES(?1,?2,?3)",
        params![reference.event_id,serde_json::to_string(reference).map_err(|_|CoordError::Data)?,now_ms()]).map_err(|_|CoordError::Data)?;
    if inserted != 0 && reference.kind != Notification::NeedsOperator {
        // Signals already have their canonical audit outbox event. Other
        // references add one operational event to that same JSONL path.
        let mut event = crate::audit::Event::new(
            "agent.operational",
            crate::audit::Kind::Agent,
            crate::audit::Severity::Low,
            "Selected agent operational transition",
        );
        event.event_id = Some(reference.event_id.clone());
        event.agent = Some(reference.target.name.clone());
        event.details = json!({"reference":reference,
            "audit_status":"This record is an observation. It does not establish an earlier audit write or model receipt."}).into();
        let payload = event
            .encode_at(OffsetDateTime::now_utc())
            .map_err(|_| CoordError::Data)?;
        tx.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl','agent.operational',?2,?3)",params![reference.event_id,payload,now_ms()]).map_err(|_|CoordError::Data)?;
    }
    for recipient in recipients {
        let suffix = crate::approvals::pending::digest(&json!([
            reference.instance_id,
            reference.event_id,
            recipient
        ]));
        let attention = format!("attn-{}", &suffix[..32]);
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM coord_attention_edges WHERE attention_id=?1)",
                [&attention],
                |row| row.get(0),
            )
            .map_err(|_| CoordError::Data)?;
        if exists {
            continue;
        }
        tx.execute("INSERT OR IGNORE INTO coord_attention_feeds(recipient_agent_id,last_sequence) VALUES(?1,0)",[recipient]).map_err(|_|CoordError::Data)?;
        tx.execute("UPDATE coord_attention_feeds SET last_sequence=last_sequence+1 WHERE recipient_agent_id=?1",[recipient]).map_err(|_|CoordError::Data)?;
        let sequence: i64 = tx
            .query_row(
                "SELECT last_sequence FROM coord_attention_feeds WHERE recipient_agent_id=?1",
                [recipient],
                |row| row.get(0),
            )
            .map_err(|_| CoordError::Data)?;
        tx.execute("INSERT INTO coord_attention_edges(recipient_agent_id,feed_sequence,attention_id,room_id,kind,object_id,revision_or_sequence,membership_granted_at,created_at) VALUES(?1,?2,?3,NULL,'operational_event',?4,0,0,?5)",params![recipient,sequence,attention,reference.event_id,now_ms()]).map_err(|_|CoordError::Data)?;
        tx.execute("INSERT OR IGNORE INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'attention-nats','coord.attention_hint',?2,?3)",params![attention_event_id(&attention),json!({"recipient_agent_id":recipient,"attention_id":attention,"feed_sequence":sequence}).to_string(),now_ms()]).map_err(|_|CoordError::Data)?;
    }
    tx.commit().map_err(|_| CoordError::Unavailable)
}

fn signal_references(
    db: &Path,
    instance: &str,
    agent: &crate::host_agents::Agent,
    rooms: &[String],
    positions: &mut HashMap<(String, String), i64>,
) -> Result<Vec<Reference>, CoordError> {
    let conn = open_db(db, false)?;
    let mut refs = Vec::new();
    for room in rooms {
        let key = (agent.id.clone(), room.clone());
        let mut position = positions.get(&key).copied().unwrap_or(0);
        let mut count = 0;
        // Canonical revisions preserve a short create/resolve cycle even when
        // the host never observed it pending. Only paged material revisions
        // are selected; there is no second signal/approval state machine.
        let mut query = conn.prepare("SELECT s.rowid,s.signal_id,s.revision,s.document_json FROM coord_signal_revisions s JOIN rooms r ON r.room_id=s.room_id WHERE r.name=?1 AND s.actor_kind='agent' AND s.actor_id=?2 AND s.rowid>?3 AND json_extract(s.document_json,'$.needs_operator')=1 ORDER BY s.rowid LIMIT 64").map_err(|_|CoordError::Data)?;
        let rows = query
            .query_map(params![room, agent.id, position], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| CoordError::Data)?;
        for row in rows {
            let (scanned, signal, revision, document) = row.map_err(|_| CoordError::Data)?;
            position = scanned;
            count += 1;
            let revision = u64::try_from(revision).map_err(|_| CoordError::Data)?;
            let value: Value = serde_json::from_str(&document).map_err(|_| CoordError::Data)?;
            let suffix = crate::approvals::pending::digest(&json!([instance, signal, revision]));
            refs.push(Reference {
                event_id: format!("evt-{}", &suffix[..32]),
                instance_id: instance.into(),
                target: crate::policy::delegation::Agent {
                    name: agent.name.clone(),
                    agent_id: agent.id.clone(),
                },
                kind: Notification::NeedsOperator,
                source: "coord_signal".into(),
                run_id: Value::Null,
                launch_id: Value::Null,
                signal_id: Some(signal),
                source_id: room.clone(),
                sequence: revision,
                source_time: json!(value["updated_at"].as_i64().ok_or(CoordError::Data)? / 1000),
                observed_at: OffsetDateTime::now_utc().unix_timestamp(),
                expected_stop: false,
                state: json!("needs_operator"),
            });
        }
        positions.insert(key, if count == 64 { position } else { 0 });
    }
    Ok(refs)
}

pub(super) async fn reconcile(
    client: &CoordClient,
    runtime: &crate::RuntimeState,
    after: &mut usize,
    signal_positions: &mut HashMap<(String, String), i64>,
) -> Result<(), CoordError> {
    let snapshot = runtime.read().map_err(|_| CoordError::Unavailable)?.clone();
    let root = snapshot
        .config
        .native_config_dir
        .clone()
        .ok_or(CoordError::Unavailable)?;
    crate::host_platform::in_config(root.join("config.toml"), async {
        let policy = peer_support::current_policy(runtime).map_err(|_| CoordError::Unavailable)?;
        let instance = peer_support::instance_id().map_err(|_| CoordError::Unavailable)?;
        let mut grants = std::collections::BTreeMap::new();
        for (name, grant) in policy.support_grants() {
            if peer_support::checked_support_principal(&policy, &grant)
                .map_err(|_| CoordError::Unavailable)?
                .is_some()
            {
                grants.insert(name, grant);
            }
        }
        let targets: std::collections::BTreeSet<_> = grants
            .values()
            .filter(|grant| {
                grant.active() && grant.instance_id == instance && !grant.notifications.is_empty()
            })
            .flat_map(|grant| {
                grant
                    .targets
                    .iter()
                    .filter(|target| {
                        policy.evidence_agent_id(&target.name) == Some(target.agent_id.as_str())
                    })
                    .map(|target| target.agent_id.clone())
            })
            .collect();
        if targets.is_empty() {
            *after = 0;
            return Ok(());
        }
        crate::coord_rooms::bootstrap(&root).map_err(|_| CoordError::Unavailable)?;
        let agents = crate::host_agents::list().map_err(|_| CoordError::Unavailable)?;
        let agents: Vec<_> = agents
            .iter()
            .filter(|agent| targets.contains(&agent.id))
            .collect();
        if *after >= agents.len() {
            *after = 0;
        }
        let db = client.owner.data_dir.join("v0.db");
        let end = (*after + 8).min(agents.len());
        let mut failed = false;
        for agent in &agents[*after..end] {
            let observed = events::observe(&root, &instance, agent).await;
            let mut refs = match observed {
                Ok((refs, unavailable)) => {
                    failed |= unavailable;
                    refs
                }
                Err(_) => {
                    failed = true;
                    Vec::new()
                }
            };
            let rooms: std::collections::BTreeSet<_> = grants
                .values()
                .filter(|grant| {
                    grant.active()
                        && grant.instance_id == instance
                        && grant.notifications.contains(&Notification::NeedsOperator)
                        && grant
                            .targets
                            .iter()
                            .any(|target| target.agent_id == agent.id)
                })
                .flat_map(|grant| grant.signal_rooms.iter().cloned())
                .collect();
            match signal_references(
                &db,
                &instance,
                agent,
                &rooms.into_iter().collect::<Vec<_>>(),
                signal_positions,
            ) {
                Ok(signals) => refs.extend(signals),
                Err(_) => failed = true,
            }
            for reference in refs {
                // Reload the saved policy after observation. A revoke while a
                // backend probe was in flight must prevent new delivery.
                let policy =
                    peer_support::current_policy(runtime).map_err(|_| CoordError::Unavailable)?;
                let mut recipients = std::collections::BTreeSet::new();
                for grant in policy.support_grants().values() {
                    if let Some(principal) = peer_support::checked_support_principal(&policy, grant)
                        .map_err(|_| CoordError::Unavailable)?
                        && events::permits(&policy, &instance, &principal, &reference, true)
                            .map_err(|_| CoordError::Unavailable)?
                    {
                        recipients.insert(principal);
                    }
                }
                if !recipients.is_empty()
                    && stage(&db, &reference, &recipients.into_iter().collect::<Vec<_>>()).is_err()
                {
                    failed = true;
                }
            }
        }
        *after = if end == agents.len() { 0 } else { end };
        if failed {
            Err(CoordError::Unavailable)
        } else {
            Ok(())
        }
    })
    .await
}
