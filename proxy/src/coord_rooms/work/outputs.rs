//! Publication selects a retained artifact and its execution outcome together.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExecutionOutcome {
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Publication {
    pub producer: Value,
    pub claim_generation: i64,
    pub work_version: i64,
    pub execution_outcome: ExecutionOutcome,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub published_at: i64,
}

pub(crate) fn list(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    work_id: &str,
    after_version: i64,
    limit: usize,
) -> Result<Value, WorkError> {
    let tx = conn.transaction()?;
    let room_id = authorize(&tx, room, actor, false)?;
    current(&tx, &room_id, work_id)?;
    if after_version < 0 || !(1..=MAX_PAGE).contains(&limit) {
        return Err(invalid(
            "after_version must be nonnegative; limit must be 1..200",
        ));
    }
    // A publication is copied into later work revisions. Return its original
    // revision once, rather than counting later attestations as more outputs.
    let mut query = tx.prepare("SELECT version,document_json FROM coord_work_revisions WHERE room_id=?1 AND work_id=?2 AND version>?3 AND json_extract(document_json,'$.output.work_version')=version ORDER BY version LIMIT ?4")?;
    let rows = query.query_map(
        params![room_id, work_id, after_version, limit as i64 + 1],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
    )?;
    let mut items = Vec::new();
    let mut bytes = 2;
    let mut more = false;
    for row in rows {
        let (version, document) = row?;
        let work: Value = serde_json::from_str(&document)?;
        let item = json!({"work_version":version,"target_ref":work["target_ref"],"target_generation":work["target_generation"],"output":work["output"]});
        bytes += item.to_string().len() + 1;
        if items.len() == limit || bytes > 64 * 1024 {
            more = true;
            break;
        }
        items.push(item);
    }
    let next = more.then(|| items.last().unwrap()["work_version"].clone());
    Ok(json!({"room_id":room_id,"work_id":work_id,"items":items,"next_after_version":next}))
}

// Keep the typed mutation's publication fields at this validation boundary.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish(
    work: &mut Work,
    actor: Actor<'_>,
    expected_target_generation: i64,
    target_ref: String,
    execution_outcome: ExecutionOutcome,
    summary: String,
    evidence_refs: Vec<String>,
    changed_at: i64,
) -> Result<(), WorkError> {
    if expected_target_generation < 0 {
        return Err(invalid("expected target generation must be nonnegative"));
    }
    if work.target_generation != expected_target_generation {
        return Err(conflict(
            "stale output generation; read current work before publishing",
        ));
    }
    if !["claimed", "done"].contains(&work.state.as_str()) {
        return Err(conflict("output publication requires current owned work"));
    }
    // An integration uses the producing holder's authenticated transport,
    // never an actor/producer field supplied in the request.
    if work.claim_agent_id.as_deref() != Some(actor.id()) {
        return Err(WorkError(
            403,
            "only the current holder may publish its output".into(),
        ));
    }
    if target_ref.trim().is_empty() || target_ref.len() > 1024 {
        return Err(invalid("target_ref must contain 1..1024 UTF-8 bytes"));
    }
    if summary.trim().is_empty()
        || summary.len() > 1024
        || evidence_refs.len() > 16
        || evidence_refs.iter().any(|r| r.len() > 1024)
    {
        return Err(invalid(
            "output summary must contain 1..1024 UTF-8 bytes; evidence_refs at most 16 strings of 1024 bytes each",
        ));
    }
    work.target_generation = work
        .target_generation
        .checked_add(1)
        .ok_or_else(|| conflict("target generation cannot advance"))?;
    work.target_ref = Some(target_ref);
    let publication = Publication {
        producer: json!({"kind":actor.kind(),"id":actor.id()}),
        claim_generation: work.claim_generation,
        work_version: work
            .version
            .checked_add(1)
            .ok_or_else(|| conflict("work version cannot advance"))?,
        execution_outcome,
        summary,
        evidence_refs,
        published_at: changed_at,
    };
    if serde_json::to_vec(&publication)?.len() > attestations::MAX_RECORD_BYTES {
        return Err(invalid(
            "output publication exceeds 32768 serialized UTF-8 bytes",
        ));
    }
    work.output = Some(publication);
    Ok(())
}
