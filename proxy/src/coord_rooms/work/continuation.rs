//! Explicit further attempts with the same retained worker or exact-subject reviewer.
use super::*;
use subjects::Principal;

#[derive(Serialize, Deserialize)]
pub(crate) struct Continuation {
    pub author: Principal,
    pub participant: Principal,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub previous_work_version: i64,
    pub claim_generation: i64,
    pub selected_at: i64,
}

pub(super) fn select(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    reason: String,
    evidence_refs: Vec<String>,
    at: i64,
) -> Result<(), WorkError> {
    if work.state != "done" || work.challenge.is_some() {
        return Err(conflict(
            "continuation requires completed ordinary work or an answered check",
        ));
    }
    subjects::evidence(&reason, &evidence_refs)?;
    if evidence_refs.is_empty() || evidence_refs.iter().any(|r| r.trim().is_empty()) {
        return Err(invalid(
            "continuation requires findings or changed-input evidence references",
        ));
    }
    let author = actor.principal();
    let (participant, authorized) = if let Some(check) = &work.check {
        if check.answer.is_none() {
            return Err(conflict("continuation requires an answered check"));
        }
        let root = current(conn, &work.room_id, &check.subject.root_work_id)?;
        let required = root
            .acceptance_requirements
            .as_ref()
            .filter(|r| r.checks.iter().any(|c| c.work_id == work.work_id));
        let authorized = required.map_or_else(
            || check.requester == author,
            |r| r.authorities.contains(&author),
        );
        (check.reviewer.clone(), authorized)
    } else {
        let participant = work.assignee.clone().ok_or_else(|| {
            conflict("unassigned work requires operator reassignment before continuation")
        })?;
        (participant, work.created_by == json!(author))
    };
    if !matches!(actor, Actor::Operator) && !authorized {
        return Err(WorkError(403, "ordinary continuation requires its creator; required-check continuation requires the root acceptance-amendment authority; advisory continuation requires its requester".into()));
    }
    // Selection grants no room access and cannot replace or bind a participant.
    participant.validate(conn, &work.room_id)?;
    match participant.kind.as_str() {
        "agent" if work.claim_agent_id.as_deref() == Some(&participant.id) => {}
        "operator" if work.claim_agent_id.is_none() && work.check.is_some() => {}
        _ => {
            return Err(conflict(
                "continuation requires the participant's retained completed claim",
            ));
        }
    }
    let generation = work
        .claim_generation
        .checked_add(1)
        .ok_or_else(|| conflict("claim generation cannot advance"))?;
    let continuation = Continuation {
        author,
        participant: participant.clone(),
        reason,
        evidence_refs,
        previous_work_version: work.version,
        claim_generation: generation,
        selected_at: at,
    };
    work.continuation = Some(continuation);
    work.claim_generation = generation;
    // Retain the previous answer as history. Only a done check can satisfy an
    // obligation; answering this new generation changes the acceptance basis.
    work.state = if participant.kind == "operator" {
        "open"
    } else {
        "claimed"
    }
    .into();
    if participant.kind == "agent" {
        work.claimed_at = Some(at);
    }
    Ok(())
}
