//! One assigned check is ordinary durable work with one effective answer.
use super::*;
use subjects::{Principal, Subject, SubjectRef};

#[derive(Serialize, Deserialize)]
pub(crate) struct Check {
    pub requester: Principal,
    pub subject: Subject,
    pub criterion: String,
    pub reviewer: Principal,
    pub independent: bool,
    pub answer: Option<Answer>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Answer {
    pub author: Principal,
    pub verdict: attestations::Verdict,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub work_version: i64,
    pub claim_generation: i64,
    pub answered_at: i64,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn request(
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    reference: SubjectRef,
    criterion: String,
    reviewer: Principal,
    independent: bool,
    external_ref: Option<String>,
    at: i64,
) -> Result<Work, WorkError> {
    subjects::evidence(&criterion, &[])?;
    reviewer.validate(conn, room)?;
    let subject = subjects::bind(conn, room, reference)?;
    if independent {
        subjects::independent(&subject, &reviewer)?;
    }
    let mut work = new_work(room, actor, criterion.clone(), external_ref, at);
    work.check = Some(Check {
        requester: actor.principal(),
        subject,
        criterion,
        reviewer,
        independent,
        answer: None,
    });
    Ok(work)
}

pub(super) fn assign(work: &mut Work, agent_id: &str, reassign: bool) -> Result<(), WorkError> {
    let Some(check) = &mut work.check else {
        return Ok(());
    };
    let selected = Principal {
        kind: "agent".into(),
        id: agent_id.into(),
    };
    if !reassign && check.reviewer != selected {
        return Err(WorkError(
            403,
            "only the assigned reviewer may claim the check".into(),
        ));
    }
    if check.independent {
        subjects::independent(&check.subject, &selected)?;
    }
    if reassign {
        check.reviewer = selected;
        check.answer = None;
    }
    Ok(())
}

pub(super) fn may_answer(
    work: &Work,
    actor: Actor<'_>,
    responsible: &Principal,
) -> Result<(), WorkError> {
    if actor.principal() != *responsible {
        return Err(WorkError(
            403,
            "only the assigned participant may answer review work".into(),
        ));
    }
    let operator_direct = matches!(actor, Actor::Operator)
        && ["open", "done"].contains(&work.state.as_str())
        && work.claim_agent_id.is_none();
    if !operator_direct
        && (!["claimed", "done"].contains(&work.state.as_str())
            || work.claim_agent_id.as_deref() != Some(actor.id()))
    {
        return Err(conflict(
            "answer requires the assigned participant's current claim or retained completed claim",
        ));
    }
    Ok(())
}

pub(super) fn answer(
    work: &mut Work,
    actor: Actor<'_>,
    verdict: attestations::Verdict,
    summary: String,
    evidence_refs: Vec<String>,
    at: i64,
) -> Result<(), WorkError> {
    let check = work
        .check
        .as_ref()
        .ok_or_else(|| conflict("work is not an assigned check"))?;
    may_answer(work, actor, &check.reviewer)?;
    if check.independent {
        subjects::independent(&check.subject, &actor.principal())?;
    }
    subjects::evidence(&summary, &evidence_refs)?;
    let answer = Answer {
        author: actor.principal(),
        verdict,
        summary: summary.clone(),
        evidence_refs,
        work_version: work
            .version
            .checked_add(1)
            .ok_or_else(|| conflict("work version cannot advance"))?,
        claim_generation: work.claim_generation,
        answered_at: at,
    };
    subjects::record_bound(&answer)?;
    work.check.as_mut().unwrap().answer = Some(answer);
    work.short_result = Some(summary);
    work.state = "done".into();
    Ok(())
}
