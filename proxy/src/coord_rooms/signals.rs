//! Attributed material claims and bounded operator attention, committed together.
use super::{
    hash, now,
    work::{self, Actor},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const MAX_REQUEST_BYTES: usize = 32 * 1024;
const MAX_SUMMARY_BYTES: usize = 1024;
const MAX_PAGE_BYTES: usize = 64 * 1024;
const MAX_PAGE: usize = 100;
const PAGE_WINDOW_MS: i64 = 60_000;
const AUTHOR_PAGES: i64 = 5;
const ROOM_PAGES: i64 = 20;

#[derive(Debug)]
pub(crate) struct SignalError(pub u16, pub String);
impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}
impl std::error::Error for SignalError {}
impl From<rusqlite::Error> for SignalError {
    fn from(error: rusqlite::Error) -> Self {
        Self(503, format!("signal store unavailable: {error}"))
    }
}
impl From<serde_json::Error> for SignalError {
    fn from(error: serde_json::Error) -> Self {
        Self(500, format!("invalid stored signal: {error}"))
    }
}
impl From<work::WorkError> for SignalError {
    fn from(error: work::WorkError) -> Self {
        Self(error.0, error.1)
    }
}
fn invalid(message: &str) -> SignalError {
    SignalError(400, message.into())
}
fn conflict(message: &str) -> SignalError {
    SignalError(409, message.into())
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Blocker,
    Decision,
    Result,
    Correction,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Basis {
    Observed,
    Inferred,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Supersedes {
    pub signal_id: String,
    pub expected_revision: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Mutation {
    Create {
        kind: Kind,
        summary: String,
        basis: Basis,
        work_id: Option<String>,
        #[serde(default)]
        refs: Vec<String>,
        supersedes: Option<Supersedes>,
    },
    Resolve {
        signal_id: String,
        expected_revision: i64,
    },
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Signal {
    pub signal_id: String,
    pub room_id: String,
    pub revision: i64,
    pub kind: Kind,
    pub summary: String,
    pub basis: Basis,
    pub author: Value,
    pub work_id: Option<String>,
    pub refs: Vec<String>,
    pub supersedes: Option<Supersedes>,
    pub superseded_by: Option<String>,
    pub state: String,
    pub needs_operator: bool,
    pub page_status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

fn current(conn: &Connection, room: Option<&str>, id: &str) -> Result<Signal, SignalError> {
    let document: String = conn.query_row(
        "SELECT document_json FROM coord_signals WHERE signal_id=?1 AND (?2 IS NULL OR room_id=?2)",
        params![id,room], |r| r.get(0),
    ).optional()?.ok_or_else(|| SignalError(404,"signal not found or not accessible".into()))?;
    Ok(serde_json::from_str(&document)?)
}

pub(crate) fn revision(
    conn: &Connection,
    room_id: Option<&str>,
    id: &str,
    revision: i64,
) -> Result<Value, SignalError> {
    let (document, content_hash): (String,String) = conn.query_row(
        "SELECT document_json,content_hash FROM coord_signal_revisions WHERE signal_id=?1 AND revision=?2 AND (?3 IS NULL OR room_id=?3)",
        params![id,revision,room_id], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional()?.ok_or_else(|| SignalError(404,"signal revision not found or not accessible".into()))?;
    Ok(json!({"signal":serde_json::from_str::<Value>(&document)?,"content_hash":content_hash}))
}

pub(crate) fn read(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    id: &str,
    rev: Option<i64>,
) -> Result<Value, SignalError> {
    let tx = conn.transaction()?;
    let room_id = work::authorize(&tx, room, actor, false)?;
    let rev = match rev {
        Some(rev) => rev,
        None => current(&tx, Some(&room_id), id)?.revision,
    };
    revision(&tx, Some(&room_id), id, rev)
}

pub(crate) fn list(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    after: &str,
    limit: usize,
    state: Option<&str>,
    needs_operator: bool,
) -> Result<Value, SignalError> {
    let tx = conn.transaction()?;
    let room_id = work::authorize(&tx, room, actor, false)?;
    page(
        &tx,
        Some(&room_id),
        after,
        limit,
        state,
        needs_operator,
        false,
    )
}

// The same bounded selection feeds Agent API, room_state and operator reads.
// A continuation is an ID, not a snapshot across pages.
pub(crate) fn page(
    conn: &Connection,
    room_id: Option<&str>,
    after: &str,
    limit: usize,
    state: Option<&str>,
    needs_operator: bool,
    metadata: bool,
) -> Result<Value, SignalError> {
    if !(1..=MAX_PAGE).contains(&limit)
        || state.is_some_and(|s| !["current", "resolved", "superseded", "all"].contains(&s))
    {
        return Err(invalid(
            "limit must be 1..100; state must be current, resolved, superseded or all",
        ));
    }
    let state = state.unwrap_or("current");
    let sql = "FROM coord_signals s JOIN coord_signal_revisions r ON s.signal_id=r.signal_id AND s.revision=r.revision WHERE (?1 IS NULL OR s.room_id=?1) AND (?2='all' OR s.state=?2) AND (NOT ?3 OR s.needs_operator=1)";
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) {sql}"),
        params![room_id, state, needs_operator],
        |r| r.get(0),
    )?;
    let mut query=conn.prepare(&format!("SELECT s.document_json,r.content_hash {sql} AND s.signal_id>?4 ORDER BY s.signal_id LIMIT ?5"))?;
    let mut rows = query.query(params![
        room_id,
        state,
        needs_operator,
        after,
        limit as i64 + 1
    ])?;
    let mut items = Vec::new();
    let mut bytes = 0;
    let mut more = false;
    while let Some(row) = rows.next()? {
        let document: String = row.get(0)?;
        let content_hash: String = row.get(1)?;
        let signal: Value = serde_json::from_str(&document)?;
        let item = if metadata {
            metadata_for(&signal, &content_hash)
        } else {
            json!({"signal":signal,"content_hash":content_hash})
        };
        let size = item.to_string().len();
        if items.len() == limit || bytes + size > MAX_PAGE_BYTES {
            more = true;
            break;
        }
        bytes += size;
        items.push(item);
    }
    let next = if more {
        items.last().map(|v| {
            if metadata {
                v["signal_id"].clone()
            } else {
                v["signal"]["signal_id"].clone()
            }
        })
    } else {
        None
    };
    Ok(json!({"room_id":room_id,"items":items,"total":total,"next_after":next,"truncated":more}))
}

fn metadata_for(signal: &Value, content_hash: &str) -> Value {
    json!({"signal_id":signal["signal_id"],"room_id":signal["room_id"],"revision":signal["revision"],"kind":signal["kind"],"author":signal["author"],"basis":signal["basis"],"state":signal["state"],"needs_operator":signal["needs_operator"],"content_hash":content_hash})
}

pub(crate) fn mutate(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    mutation: Mutation,
    operation: Option<&str>,
) -> Result<Value, SignalError> {
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let room_id = work::authorize(&tx, room, actor, true)?;
    let generated = uuid::Uuid::new_v4().simple().to_string();
    let operation = operation.unwrap_or(&generated);
    let input = serde_json::to_value(&mutation)?;
    if operation.trim().is_empty()
        || input.to_string().len().saturating_add(operation.len()) > MAX_REQUEST_BYTES
    {
        return Err(invalid(
            "signal mutation requires a nonempty operation ID and at most 32768 UTF-8 bytes",
        ));
    }
    let action = input["action"].as_str().unwrap();
    let operation_type = format!("coord.signal.{action}");
    let request_hash = hash(
        json!({"room_id":room_id,"mutation":input})
            .to_string()
            .as_bytes(),
    );
    let prior:Option<(String,String)>=tx.query_row("SELECT request_hash,outcome_json FROM coord_operations WHERE principal_kind=?1 AND principal_id=?2 AND operation_type=?3 AND operation_id=?4",params![actor.kind(),actor.id(),operation_type,operation],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((original, result)) = prior {
        if original != request_hash {
            return Err(conflict(
                "operation ID conflicts with the original canonical request",
            ));
        }
        return Ok(serde_json::from_str(&result)?);
    }
    let changed_at = now();
    let mut claim_hash = String::new();
    let signal = match mutation {
        Mutation::Create {
            kind,
            summary,
            basis,
            work_id,
            refs,
            supersedes,
        } => {
            if summary.trim().is_empty()
                || summary.len() > MAX_SUMMARY_BYTES
                || refs.len() > 16
                || refs.iter().any(|r| r.len() > 1024)
            {
                return Err(invalid(
                    "summary must be nonempty and at most 1024 UTF-8 bytes; refs allow at most 16 opaque strings of 1024 bytes each",
                ));
            }
            if let Some(id) = &work_id {
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM coord_work WHERE room_id=?1 AND work_id=?2)",
                    params![room_id, id],
                    |r| r.get(0),
                )?;
                if !exists {
                    return Err(SignalError(404, "work not found or not accessible".into()));
                }
            }
            if (kind == Kind::Correction) != supersedes.is_some() {
                return Err(invalid(
                    "a correction must identify the signal and expected revision it supersedes; other kinds do not supersede",
                ));
            }
            claim_hash = hash(input.to_string().as_bytes());
            let duplicate: Option<(String, i64)> = if matches!(kind, Kind::Blocker | Kind::Decision)
            {
                tx.query_row("SELECT signal_id,revision FROM coord_signals WHERE room_id=?1 AND author_kind=?2 AND author_id=?3 AND state='current' AND claim_hash=?4 ORDER BY signal_id LIMIT 1",params![room_id,actor.kind(),actor.id(),claim_hash],|r|Ok((r.get(0)?,r.get(1)?))).optional()?
            } else {
                None
            };
            if let Some((id, rev)) = duplicate {
                let mut result = revision(&tx, Some(&room_id), &id, rev)?;
                result["operation_id"] = json!(operation);
                result["deduplicated"] = json!(true);
                record_operation(
                    &tx,
                    actor,
                    &operation_type,
                    operation,
                    &request_hash,
                    &result,
                    changed_at,
                )?;
                tx.commit()?;
                return Ok(result);
            }
            let id = format!("sig-{}", uuid::Uuid::new_v4().simple());
            if let Some(target) = &supersedes {
                let mut old = current(&tx, Some(&room_id), &target.signal_id)?;
                if old.author != json!({"kind":actor.kind(),"id":actor.id()}) {
                    return Err(SignalError(403,"only the original author may supersede a signal; the operator may resolve it".into()));
                }
                if old.revision != target.expected_revision || old.state == "superseded" {
                    return Err(conflict(
                        "stale signal revision; read the current signal before correcting it",
                    ));
                }
                old.revision = old
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| conflict("signal revision cannot advance"))?;
                old.state = "superseded".into();
                old.needs_operator = false;
                old.superseded_by = Some(id.clone());
                old.updated_at = changed_at;
                store(&tx, &old, None, actor, operation, changed_at)?;
            }
            let page_status = if !matches!(kind, Kind::Blocker | Kind::Decision) {
                "not_requested"
            } else if !can_page(&tx, &room_id, actor)? {
                "permission_denied"
            } else if page_limited(&tx, &room_id, actor, changed_at)? {
                "rate_limited"
            } else {
                "paged"
            };
            Signal {
                signal_id: id,
                room_id: room_id.clone(),
                revision: 1,
                kind,
                summary,
                basis,
                author: json!({"kind":actor.kind(),"id":actor.id()}),
                work_id,
                refs,
                supersedes,
                superseded_by: None,
                state: "current".into(),
                needs_operator: page_status == "paged",
                page_status: page_status.into(),
                created_at: changed_at,
                updated_at: changed_at,
            }
        }
        Mutation::Resolve {
            signal_id,
            expected_revision,
        } => {
            if !matches!(actor, Actor::Operator) {
                return Err(SignalError(
                    403,
                    "only the operator may resolve signals".into(),
                ));
            }
            let mut signal = current(&tx, Some(&room_id), &signal_id)?;
            if expected_revision < 1
                || signal.revision != expected_revision
                || signal.state != "current"
            {
                return Err(conflict(
                    "stale signal revision or signal is no longer current",
                ));
            }
            signal.revision = signal
                .revision
                .checked_add(1)
                .ok_or_else(|| conflict("signal revision cannot advance"))?;
            signal.state = "resolved".into();
            signal.needs_operator = false;
            signal.updated_at = changed_at;
            signal
        }
    };
    let content_hash = store(
        &tx,
        &signal,
        (!claim_hash.is_empty()).then_some(claim_hash.as_str()),
        actor,
        operation,
        changed_at,
    )?;
    let result = json!({"signal":signal,"content_hash":content_hash,"operation_id":operation,"deduplicated":false});
    record_operation(
        &tx,
        actor,
        &operation_type,
        operation,
        &request_hash,
        &result,
        changed_at,
    )?;
    tx.commit()?;
    Ok(result)
}

fn can_page(conn: &Connection, room: &str, actor: Actor<'_>) -> Result<bool, SignalError> {
    if matches!(actor, Actor::Operator) {
        return Ok(true);
    }
    let permissions:String=conn.query_row("SELECT permissions FROM memberships WHERE room_id=?1 AND principal_kind='agent' AND principal_id=?2 AND revoked_at IS NULL ORDER BY granted_at DESC LIMIT 1",params![room,actor.id()],|r|r.get(0))?;
    Ok(permissions.split(',').any(|p| p == "page_operator"))
}
fn page_limited(
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    at: i64,
) -> Result<bool, SignalError> {
    let (room_count,author_count):(i64,i64)=conn.query_row("SELECT count(*),coalesce(sum(actor_kind=?3 AND actor_id=?4),0) FROM coord_signal_revisions WHERE room_id=?1 AND created_at>?2 AND revision=1 AND json_extract(document_json,'$.page_status')='paged'",params![room,at-PAGE_WINDOW_MS,actor.kind(),actor.id()],|r|Ok((r.get(0)?,r.get(1)?)))?;
    Ok(room_count >= ROOM_PAGES || author_count >= AUTHOR_PAGES)
}
fn record_operation(
    conn: &Connection,
    actor: Actor<'_>,
    kind: &str,
    operation: &str,
    request_hash: &str,
    result: &Value,
    at: i64,
) -> Result<(), SignalError> {
    conn.execute("INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES(?1,?2,?3,?4,?5,'success',?6,?7)",params![actor.kind(),actor.id(),kind,operation,request_hash,result.to_string(),at])?;
    Ok(())
}
fn store(
    conn: &Connection,
    signal: &Signal,
    claim_hash: Option<&str>,
    actor: Actor<'_>,
    operation: &str,
    at: i64,
) -> Result<String, SignalError> {
    let document = serde_json::to_string(signal)?;
    let content_hash = hash(document.as_bytes());
    conn.execute("INSERT INTO coord_signal_revisions(signal_id,room_id,revision,document_json,content_hash,actor_kind,actor_id,operation_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![signal.signal_id,signal.room_id,signal.revision,document,content_hash,actor.kind(),actor.id(),operation,at])?;
    conn.execute("INSERT INTO coord_signals(signal_id,room_id,revision,state,needs_operator,author_kind,author_id,claim_hash,created_at,document_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(signal_id) DO UPDATE SET revision=excluded.revision,state=excluded.state,needs_operator=excluded.needs_operator,document_json=excluded.document_json",params![signal.signal_id,signal.room_id,signal.revision,signal.state,signal.needs_operator,signal.author["kind"].as_str(),signal.author["id"].as_str(),claim_hash.unwrap_or(""),signal.created_at,document])?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let event_type = if signal.revision == 1 {
        "coord.signal_created"
    } else if signal.state == "superseded" {
        "coord.signal_superseded"
    } else {
        "coord.signal_resolved"
    };
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| SignalError(500, "signal timestamp unavailable".into()))?;
    let event = json!({"schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,"ts":timestamp,"event":event_type,"kind":"coord","severity":"low","summary":"Coord material signal changed","addon":"coord","details":metadata_for(&serde_json::to_value(signal)?,&content_hash)});
    conn.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl',?2,?3,?4)",params![event_id,event_type,event.to_string(),at])?;
    Ok(content_hash)
}

#[cfg(test)]
mod tests;
