//! Response completion and an authorized challenge disposition are separate facts.
use super::*;
use subjects::{Principal, Subject, SubjectRef};

#[derive(Serialize, Deserialize)]
pub(crate) struct Challenge {
    pub author: Principal,
    pub subject: Subject,
    pub assertion: String,
    pub grounds: String,
    pub evidence_refs: Vec<String>,
    pub responder: Principal,
    pub deciders: Vec<Principal>,
    pub independent: bool,
    pub response: Option<Response>,
    pub disposition: Option<Disposition>,
    pub recovery_reason: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Response {
    pub author: Principal,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub correction: Option<Subject>,
    pub work_version: i64,
    pub claim_generation: i64,
    pub responded_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Decision {
    Upheld,
    Dismissed,
    Withdrawn,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Disposition {
    pub author: Principal,
    pub decision: Decision,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub response_version: i64,
    pub correction: Option<Subject>,
    pub work_version: i64,
    pub resolved_at: i64,
}

fn validate_deciders(
    conn: &Connection,
    room: &str,
    challenge: &Challenge,
    deciders: &[Principal],
) -> Result<(), WorkError> {
    if deciders.is_empty() {
        return Err(invalid(
            "a challenge must name at least one deciding participant",
        ));
    }
    for decider in deciders {
        decider.validate(conn, room)?;
        if challenge.independent {
            subjects::independent(&challenge.subject, decider)?;
            if *decider == challenge.responder {
                return Err(WorkError(
                    403,
                    "responder cannot provide the independent challenge disposition".into(),
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn raise(
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    reference: SubjectRef,
    assertion: String,
    grounds: String,
    evidence_refs: Vec<String>,
    responder: Principal,
    deciders: Vec<Principal>,
    independent: bool,
    external_ref: Option<String>,
    at: i64,
) -> Result<Work, WorkError> {
    subjects::evidence(&assertion, &[])?;
    subjects::evidence(&grounds, &evidence_refs)?;
    responder.validate(conn, room)?;
    let subject = subjects::bind(conn, room, reference)?;
    let challenge = Challenge {
        author: actor.principal(),
        subject,
        assertion: assertion.clone(),
        grounds,
        evidence_refs,
        responder,
        deciders,
        independent,
        response: None,
        disposition: None,
        recovery_reason: None,
    };
    validate_deciders(conn, room, &challenge, &challenge.deciders)?;
    subjects::record_bound(&challenge)?;
    let mut work = new_work(room, actor, assertion, external_ref, at);
    work.challenge = Some(challenge);
    Ok(work)
}

pub(super) fn assign(work: &mut Work, agent_id: &str, reassign: bool) -> Result<(), WorkError> {
    let Some(challenge) = &mut work.challenge else {
        return Ok(());
    };
    let selected = Principal {
        kind: "agent".into(),
        id: agent_id.into(),
    };
    if !reassign && challenge.responder != selected {
        return Err(WorkError(
            403,
            "only the assigned responder may claim the challenge response".into(),
        ));
    }
    if reassign {
        if challenge.independent && challenge.deciders.contains(&selected) {
            return Err(WorkError(
                403,
                "independent decider cannot become the responder".into(),
            ));
        }
        challenge.responder = selected;
        challenge.response = None;
        challenge.disposition = None;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn respond(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    summary: String,
    evidence_refs: Vec<String>,
    correction: Option<SubjectRef>,
    at: i64,
) -> Result<(), WorkError> {
    let challenge = work
        .challenge
        .as_ref()
        .ok_or_else(|| conflict("work is not a challenge"))?;
    checks::may_answer(work, actor, &challenge.responder)?;
    subjects::evidence(&summary, &evidence_refs)?;
    let correction = correction
        .map(|s| subjects::bind(conn, &work.room_id, s))
        .transpose()?;
    let response = Response {
        author: actor.principal(),
        summary: summary.clone(),
        evidence_refs,
        correction,
        work_version: work
            .version
            .checked_add(1)
            .ok_or_else(|| conflict("work version cannot advance"))?,
        claim_generation: work.claim_generation,
        responded_at: at,
    };
    subjects::record_bound(&response)?;
    let challenge = work.challenge.as_mut().unwrap();
    challenge.response = Some(response);
    // A revised answer needs its own disposition. The old resolution remains
    // in the immutable work revision, never silently applying to new evidence.
    challenge.disposition = None;
    work.state = "done".into();
    work.short_result = Some(summary);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve(
    work: &mut Work,
    actor: Actor<'_>,
    expected_response_version: i64,
    decision: Decision,
    reason: String,
    evidence_refs: Vec<String>,
    at: i64,
) -> Result<(), WorkError> {
    let challenge = work
        .challenge
        .as_mut()
        .ok_or_else(|| conflict("work is not a challenge"))?;
    if !matches!(actor, Actor::Operator) && !challenge.deciders.contains(&actor.principal()) {
        return Err(WorkError(
            403,
            "only a named deciding participant or the operator may resolve a challenge".into(),
        ));
    }
    if challenge.independent {
        subjects::independent(&challenge.subject, &actor.principal())?;
        if challenge.responder == actor.principal() {
            return Err(WorkError(
                403,
                "responder cannot provide the independent challenge disposition".into(),
            ));
        }
    }
    let response_version = challenge.response.as_ref().map_or(0, |r| r.work_version);
    if response_version != expected_response_version {
        return Err(conflict(
            "stale challenge response; read current challenge before deciding",
        ));
    }
    subjects::evidence(&reason, &evidence_refs)?;
    let disposition = Disposition {
        author: actor.principal(),
        decision,
        reason: reason.clone(),
        evidence_refs,
        response_version,
        correction: challenge
            .response
            .as_ref()
            .and_then(|r| r.correction.clone()),
        work_version: work
            .version
            .checked_add(1)
            .ok_or_else(|| conflict("work version cannot advance"))?,
        resolved_at: at,
    };
    subjects::record_bound(&disposition)?;
    challenge.disposition = Some(disposition);
    if ["open", "claimed"].contains(&work.state.as_str()) {
        work.state = "cancelled".into();
        work.claim_generation = work
            .claim_generation
            .checked_add(1)
            .ok_or_else(|| conflict("claim generation cannot advance"))?;
        work.claim_agent_id = None;
        work.claimed_at = None;
        work.cancellation =
            Some(json!({"author":actor.principal(),"reason":reason,"cancelled_at":at}));
    }
    Ok(())
}

pub(super) fn recover_deciders(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    deciders: Vec<Principal>,
    reason: String,
) -> Result<(), WorkError> {
    if !matches!(actor, Actor::Operator) {
        return Err(WorkError(
            403,
            "only the operator may recover unavailable challenge deciders".into(),
        ));
    }
    subjects::evidence(&reason, &[])?;
    let challenge = work
        .challenge
        .as_mut()
        .ok_or_else(|| conflict("work is not a challenge"))?;
    validate_deciders(conn, &work.room_id, challenge, &deciders)?;
    challenge.deciders = deciders;
    challenge.recovery_reason = Some(reason);
    Ok(())
}
