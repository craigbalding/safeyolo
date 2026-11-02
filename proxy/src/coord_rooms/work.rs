//! Durable work ownership. Authorization, replay, versions and delivery commit together.
use super::{hash, now};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) mod attestations;
pub(crate) mod github;

// Reuse the Coord message content bound for a complete work mutation.
pub(crate) const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub(crate) const MAX_PAGE: usize = 200;

#[derive(Debug)]
pub(crate) struct WorkError(pub u16, pub String);
impl std::fmt::Display for WorkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}
impl std::error::Error for WorkError {}
impl From<rusqlite::Error> for WorkError {
    fn from(error: rusqlite::Error) -> Self {
        Self(503, format!("work store unavailable: {error}"))
    }
}
impl From<serde_json::Error> for WorkError {
    fn from(error: serde_json::Error) -> Self {
        Self(500, format!("invalid stored work: {error}"))
    }
}
fn invalid(detail: &str) -> WorkError {
    WorkError(400, detail.into())
}
fn conflict(detail: &str) -> WorkError {
    WorkError(409, detail.into())
}

#[derive(Clone, Copy)]
pub(crate) enum Actor<'a> {
    Operator,
    Agent(&'a str),
    Remote(&'a super::federation::RemoteAgent),
}
impl<'a> Actor<'a> {
    pub(super) fn kind(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Agent(_) | Self::Remote(_) => "agent",
        }
    }
    pub(super) fn id(self) -> &'a str {
        match self {
            Self::Operator => "operator",
            Self::Agent(id) => id,
            Self::Remote(remote) => &remote.principal_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Mutation {
    Create {
        title: String,
        external_ref: Option<String>,
    },
    Claim {
        work_id: String,
        expected_version: i64,
        expected_generation: i64,
    },
    Release {
        work_id: String,
        expected_version: i64,
        expected_generation: i64,
    },
    Complete {
        work_id: String,
        expected_version: i64,
        expected_generation: i64,
        short_result: Option<String>,
    },
    Reassign {
        work_id: String,
        expected_version: i64,
        expected_generation: i64,
        agent_id: String,
    },
    ChangeTarget {
        work_id: String,
        expected_version: i64,
        expected_target_generation: i64,
        target_ref: String,
    },
    Attest {
        work_id: String,
        target_generation: i64,
        kind: String,
        verdict: attestations::Verdict,
        summary: String,
        #[serde(default)]
        evidence_refs: Vec<String>,
    },
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Work {
    pub work_id: String,
    pub room_id: String,
    pub title: String,
    pub external_ref: Option<String>,
    pub target_ref: Option<String>,
    pub target_generation: i64,
    pub state: String,
    pub claim_agent_id: Option<String>,
    pub claim_generation: i64,
    pub claimed_at: Option<i64>,
    pub claim_expires_at: Option<i64>,
    pub created_by: Value,
    pub short_result: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: i64,
}

pub(super) fn authorize(
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    write: bool,
) -> Result<String, WorkError> {
    let room_id: String = conn
        .query_row("SELECT room_id FROM rooms WHERE name=?1", [room], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(|| WorkError(404, "room not found or not accessible".into()))?;
    if let Actor::Remote(remote) = actor {
        super::federation::authorize(conn, remote)
            .map_err(|_| WorkError(403, "federation access changed".into()))?;
    }
    if !matches!(actor, Actor::Operator) {
        member(conn, &room_id, actor.id(), write)?;
    }
    Ok(room_id)
}

fn member(conn: &Connection, room_id: &str, agent: &str, write: bool) -> Result<(), WorkError> {
    let permissions = super::membership::effective(conn, room_id)
        .map_err(|e| WorkError(503, e.to_string()))?
        .into_iter()
        .find(|m| m.participant.principal_kind == "agent" && m.participant.principal_id == agent)
        .map(|m| m.participant.permissions)
        .ok_or_else(|| WorkError(404, "room not found or not accessible".into()))?;
    let permits = |p| permissions.iter().any(|v| v == p);
    if !permits("receive") || (write && !permits("send")) {
        return Err(WorkError(
            403,
            "work reads require receive; mutations require send and receive".into(),
        ));
    }
    Ok(())
}

pub(crate) fn read(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    work_id: &str,
) -> Result<Value, WorkError> {
    let tx = conn.transaction()?;
    let room_id = authorize(&tx, room, actor, false)?;
    Ok(serde_json::to_value(current(&tx, &room_id, work_id)?)?)
}

pub(crate) fn list(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    after: &str,
    limit: usize,
    state: Option<&str>,
) -> Result<Value, WorkError> {
    let tx = conn.transaction()?;
    let room_id = authorize(&tx, room, actor, false)?;
    if !(1..=MAX_PAGE).contains(&limit)
        || state.is_some_and(|s| !["open", "claimed", "done"].contains(&s))
    {
        return Err(invalid(
            "limit must be 1..200; state must be open, claimed or done",
        ));
    }
    let mut rows = tx.prepare("SELECT document_json FROM coord_work WHERE room_id=?1 AND work_id>?2 AND (?3 IS NULL OR state=?3) ORDER BY work_id LIMIT ?4")?;
    let items = rows
        .query_map(params![room_id, after, state, limit as i64 + 1], |r| {
            r.get::<_, String>(0)
        })?
        .map(|r| Ok(serde_json::from_str::<Value>(&r?)?))
        .collect::<Result<Vec<_>, WorkError>>()?;
    let more = items.len() > limit;
    let items: Vec<_> = items.into_iter().take(limit).collect();
    let next = more.then(|| items.last().unwrap()["work_id"].clone());
    Ok(json!({"room_id":room_id,"items":items,"next_after":next}))
}

fn current(conn: &Connection, room_id: &str, work_id: &str) -> Result<Work, WorkError> {
    let document: String = conn
        .query_row(
            "SELECT document_json FROM coord_work WHERE room_id=?1 AND work_id=?2",
            params![room_id, work_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| WorkError(404, "work not found or not accessible".into()))?;
    Ok(serde_json::from_str(&document)?)
}

pub(crate) fn revision(
    conn: &Connection,
    room_id: &str,
    work_id: &str,
    version: i64,
) -> Result<Value, WorkError> {
    let document: String = conn.query_row("SELECT document_json FROM coord_work_revisions WHERE room_id=?1 AND work_id=?2 AND version=?3", params![room_id,work_id,version], |r| r.get(0))?;
    Ok(serde_json::from_str(&document)?)
}

pub(crate) fn mutate(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    mutation: Mutation,
    operation: Option<&str>,
) -> Result<Value, WorkError> {
    // A burst of independent claimers serializes at SQLite's writer. Keep the
    // wait within the client's 60-second request deadline for the 100-caller case.
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let room_id = authorize(&tx, room, actor, true)?;
    let generated = uuid::Uuid::new_v4().simple().to_string();
    let operation = operation.unwrap_or(&generated);
    if operation.trim().is_empty() {
        return Err(invalid("operation ID must be nonempty"));
    }
    let input = serde_json::to_value(&mutation)?;
    if input.to_string().len().saturating_add(operation.len()) > MAX_REQUEST_BYTES {
        return Err(invalid("work mutation exceeds 262144 UTF-8 bytes"));
    }
    let action = input["action"].as_str().unwrap();
    let operation_type = format!("coord.work.{action}");
    let request_hash = hash(
        json!({"room_id":room_id,"mutation":input})
            .to_string()
            .as_bytes(),
    );
    let prior: Option<(String,String)> = tx.query_row(
        "SELECT request_hash,outcome_json FROM coord_operations WHERE principal_kind=?1 AND principal_id=?2 AND operation_type=?3 AND operation_id=?4",
        params![actor.kind(),actor.id(),operation_type,operation], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    if let Some((original, result)) = prior {
        if original != request_hash {
            return Err(conflict(
                "operation ID conflicts with the original canonical request",
            ));
        }
        return Ok(serde_json::from_str(&result)?);
    }
    let changed_at = now();
    let mut attestation = None;
    let mut work = if let Mutation::Create {
        title,
        external_ref,
    } = mutation
    {
        if title.trim().is_empty() {
            return Err(invalid("work title must be nonempty"));
        }
        Work {
            work_id: format!("work-{}", uuid::Uuid::new_v4().simple()),
            room_id: room_id.clone(),
            title,
            external_ref,
            target_ref: None,
            target_generation: 0,
            state: "open".into(),
            claim_agent_id: None,
            claim_generation: 0,
            claimed_at: None,
            claim_expires_at: None,
            created_by: json!({"kind":actor.kind(),"id":actor.id()}),
            short_result: None,
            created_at: changed_at,
            updated_at: changed_at,
            version: 1,
        }
    } else {
        let id = input["work_id"].as_str().unwrap();
        let mut work = current(&tx, &room_id, id)?;
        // Independent append-only attestations contend only on the candidate,
        // not on another author's submission or on ownership changes.
        if !matches!(mutation, Mutation::Attest { .. }) {
            let version = input["expected_version"].as_i64().unwrap();
            let target_change = matches!(mutation, Mutation::ChangeTarget { .. });
            let generation = input[if target_change {
                "expected_target_generation"
            } else {
                "expected_generation"
            }]
            .as_i64()
            .unwrap();
            if version < 1 || generation < 0 {
                return Err(invalid(
                    "expected version must be positive and expected generation nonnegative",
                ));
            }
            if work.version != version
                || generation
                    != if target_change {
                        work.target_generation
                    } else {
                        work.claim_generation
                    }
            {
                return Err(conflict(
                    "stale work version or generation; read current work before changing it",
                ));
            }
        }
        match mutation {
            Mutation::ChangeTarget { target_ref, .. } => {
                if target_ref.trim().is_empty() || target_ref.len() > 1024 {
                    return Err(invalid("target_ref must contain 1..1024 UTF-8 bytes"));
                }
                work.target_generation = work
                    .target_generation
                    .checked_add(1)
                    .ok_or_else(|| conflict("target generation cannot advance"))?;
                // An explicit change can advance a reused opaque ref after an
                // external squash/rebase. Only operation replay is a no-op.
                work.target_ref = Some(target_ref);
            }
            Mutation::Attest {
                target_generation,
                kind,
                verdict,
                summary,
                evidence_refs,
                ..
            } => {
                if target_generation < 1 {
                    return Err(invalid("target_generation must be positive"));
                }
                if work.target_ref.is_none() || work.target_generation != target_generation {
                    return Err(conflict(
                        "stale or unset work target; read current work before attesting",
                    ));
                }
                if kind.trim().is_empty()
                    || kind.len() > 128
                    || summary.trim().is_empty()
                    || summary.len() > 1024
                    || evidence_refs.len() > 16
                    || evidence_refs.iter().any(|r| r.len() > 1024)
                {
                    return Err(invalid(
                        "attestation kind must contain 1..128 UTF-8 bytes; summary 1..1024; evidence_refs at most 16 strings of 1024 bytes each",
                    ));
                }
                let record = json!({"attestation_id":format!("att-{}",uuid::Uuid::new_v4().simple()),"room_id":room_id,"work_id":work.work_id,
                    "work_version":work.version.checked_add(1).ok_or_else(||conflict("work version cannot advance"))?,
                    "target_generation":target_generation,"target_ref":work.target_ref,"kind":kind,"verdict":verdict,
                    "author":{"kind":actor.kind(),"id":actor.id()},"summary":summary,"evidence_refs":evidence_refs,"created_at":changed_at});
                if record.to_string().len() > attestations::MAX_RECORD_BYTES {
                    return Err(invalid("attestation exceeds 32768 serialized UTF-8 bytes"));
                }
                attestation = Some(record);
            }
            Mutation::Claim { .. } | Mutation::Reassign { .. } => {
                let agent_id = match &mutation {
                    Mutation::Reassign { agent_id, .. } if matches!(actor, Actor::Operator) => {
                        agent_id.as_str()
                    }
                    Mutation::Reassign { .. } => {
                        return Err(WorkError(403, "only the operator may reassign work".into()));
                    }
                    _ => match actor {
                        Actor::Agent(id) => id,
                        Actor::Remote(remote) => &remote.principal_id,
                        Actor::Operator => {
                            return Err(invalid(
                                "operator claims use reassign with a durable agent ID",
                            ));
                        }
                    },
                };
                if work.state == "done" || (action == "claim" && work.state != "open") {
                    return Err(conflict("work is not open for claim"));
                }
                member(&tx, &room_id, agent_id, true)?;
                work.state = "claimed".into();
                work.claim_agent_id = Some(agent_id.into());
                work.claim_generation = work
                    .claim_generation
                    .checked_add(1)
                    .ok_or_else(|| conflict("claim generation cannot advance"))?;
                work.claimed_at = Some(changed_at);
            }
            Mutation::Release { .. } | Mutation::Complete { .. } => {
                if work.state != "claimed" {
                    return Err(conflict("work has no active claim"));
                }
                if !matches!(actor, Actor::Operator)
                    && work.claim_agent_id.as_deref() != Some(actor.id())
                {
                    return Err(WorkError(
                        403,
                        "only the holder or operator may release or complete work".into(),
                    ));
                }
                work.state = if action == "release" { "open" } else { "done" }.into();
                if let Mutation::Complete { short_result, .. } = mutation {
                    work.short_result = short_result;
                }
                if action == "release" {
                    work.claim_agent_id = None;
                    work.claimed_at = None;
                }
            }
            Mutation::Create { .. } => unreachable!(),
        }
        work.version = work
            .version
            .checked_add(1)
            .ok_or_else(|| conflict("work version cannot advance"))?;
        work
    };
    work.updated_at = changed_at;
    let mut result = json!({"work":work,"operation_id":operation});
    let document = result["work"].to_string();
    let mut revision = result["work"].clone();
    if let Some(record) = attestation {
        tx.execute("INSERT INTO coord_work_attestations(attestation_id,work_id,room_id,work_version,target_generation,kind,verdict) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![record["attestation_id"].as_str(),work.work_id,room_id,work.version,work.target_generation,record["kind"].as_str(),record["verdict"].as_str()])?;
        revision["attestation"] = record.clone();
        result["attestation"] = record;
    }
    let revision_document = revision.to_string();
    let content_hash = hash(revision_document.as_bytes());
    tx.execute("INSERT INTO coord_work_revisions(work_id,room_id,version,document_json,content_hash,actor_kind,actor_id,operation_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![work.work_id,room_id,work.version,revision_document,content_hash,actor.kind(),actor.id(),operation,changed_at])?;
    tx.execute("INSERT INTO coord_work(work_id,room_id,version,state,document_json) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(work_id) DO UPDATE SET version=excluded.version,state=excluded.state,document_json=excluded.document_json",params![work.work_id,room_id,work.version,work.state,document])?;
    tx.execute("INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES(?1,?2,?3,?4,?5,'success',?6,?7)", params![actor.kind(),actor.id(),operation_type,operation,request_hash,result.to_string(),changed_at])?;
    stage_attention(&tx, &work, actor, changed_at)?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| WorkError(500, "work timestamp unavailable".into()))?;
    let event_type = format!("coord.work_{action}");
    let event = json!({"schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,"ts":timestamp,"event":event_type,"kind":"coord","severity":"low","summary":"Coord work changed","addon":"coord",
        "details":{"actor_kind":actor.kind(),"actor_id":actor.id(),"room_id":room_id,"object_id":work.work_id,"version":work.version,"claim_generation":work.claim_generation,"target_generation":work.target_generation,"attestation_id":result.get("attestation").and_then(|a|a.get("attestation_id")),"content_hash":content_hash,"operation_id":operation,"operation_type":operation_type}});
    tx.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl',?2,?3,?4)", params![event_id,event_type,event.to_string(),changed_at])?;
    tx.commit()?;
    Ok(result)
}

fn stage_attention(
    conn: &Connection,
    work: &Work,
    actor: Actor<'_>,
    changed_at: i64,
) -> Result<(), WorkError> {
    let recipients = super::membership::effective(conn, &work.room_id)
        .map_err(|e| WorkError(503, e.to_string()))?
        .into_iter()
        .filter(|m| {
            m.participant.principal_kind == "agent"
                && m.participant.permissions.iter().any(|p| p == "receive")
        })
        .map(|m| (m.participant.principal_id, m.granted_at))
        .collect::<Vec<_>>();
    for (agent, granted_at) in recipients {
        if !matches!(actor, Actor::Operator) && actor.id() == agent {
            continue;
        }
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let attention = format!("attn-{suffix}");
        conn.execute("INSERT OR IGNORE INTO coord_attention_feeds(recipient_agent_id,last_sequence) VALUES(?1,0)",[&agent])?;
        let sequence:i64 = conn.query_row("UPDATE coord_attention_feeds SET last_sequence=last_sequence+1 WHERE recipient_agent_id=?1 RETURNING last_sequence",[&agent],|r|r.get(0))?;
        conn.execute("INSERT INTO coord_attention_edges(recipient_agent_id,feed_sequence,attention_id,room_id,kind,object_id,revision_or_sequence,membership_granted_at,created_at) VALUES(?1,?2,?3,?4,'work_changed',?5,?6,?7,?8)",params![agent,sequence,attention,work.room_id,work.work_id,work.version,granted_at,changed_at])?;
        conn.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'attention-nats','coord.attention_hint',?2,?3)",params![format!("evt-{suffix}"),json!({"attention_id":attention,"recipient_agent_id":agent,"feed_sequence":sequence}).to_string(),changed_at])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
