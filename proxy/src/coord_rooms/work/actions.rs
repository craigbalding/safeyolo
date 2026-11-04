//! Participant actions derived from canonical work, with immutable delivery receipts.
//! Receiving an action never claims work, changes a verdict or accepts an output.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    pub key: String,
    pub kind: String,
    pub work_id: String,
    pub work_version: i64,
    pub claim_generation: i64,
    pub target_generation: i64,
    pub requires_action: bool,
}

fn push(
    actions: &mut Vec<Action>,
    work: &Work,
    actor: Actor<'_>,
    kind: &str,
    basis: Value,
    required: bool,
) {
    let key = hash(json!({"room":work.room_id,"work":work.work_id,"participant":actor.principal(),"kind":kind,"basis":basis}).to_string().as_bytes());
    actions.push(Action {
        key: format!("action-{key}"),
        kind: kind.into(),
        work_id: work.work_id.clone(),
        work_version: work.version,
        claim_generation: work.claim_generation,
        target_generation: work.target_generation,
        requires_action: required,
    });
}

fn for_work(conn: &Connection, work: &Work, actor: Actor<'_>) -> Result<Vec<Action>, WorkError> {
    let mut actions = Vec::new();
    let participant = actor.principal();
    // A claim is part of the same assignment delivery, not a second model job.
    let episode = if work.state == "open" {
        work.claim_generation + 1
    } else {
        work.claim_generation
    };
    let unfinished = ["open", "claimed"].contains(&work.state.as_str());
    if let Some(check) = &work.check {
        if unfinished && check.reviewer == participant {
            push(
                &mut actions,
                work,
                actor,
                "answer_check",
                json!(episode),
                true,
            );
        }
        if check.requester == participant
            && let Some(answer) = &check.answer
        {
            push(
                &mut actions,
                work,
                actor,
                "check_answered",
                json!(answer.work_version),
                false,
            );
        }
    } else if let Some(challenge) = &work.challenge {
        if unfinished && challenge.responder == participant {
            push(
                &mut actions,
                work,
                actor,
                "respond_challenge",
                json!(episode),
                true,
            );
        }
        if challenge.disposition.is_none()
            && challenge.deciders.contains(&participant)
            && (challenge.response.is_some() || work.state == "cancelled")
        {
            push(
                &mut actions,
                work,
                actor,
                "resolve_challenge",
                json!({"response":challenge.response.as_ref().map(|r|r.work_version),"deciders":challenge.deciders,"generation":work.claim_generation}),
                true,
            );
        }
        if challenge.author == participant {
            if let Some(response) = &challenge.response {
                push(
                    &mut actions,
                    work,
                    actor,
                    "challenge_answered",
                    json!(response.work_version),
                    false,
                );
            }
            if let Some(disposition) = &challenge.disposition {
                push(
                    &mut actions,
                    work,
                    actor,
                    "challenge_resolved",
                    json!(disposition.work_version),
                    false,
                );
            }
        }
    } else {
        if unfinished && work.assignee.as_ref() == Some(&participant) {
            push(
                &mut actions,
                work,
                actor,
                "execute_work",
                json!(episode),
                true,
            );
        }
        if work.created_by == json!(participant) {
            if let Some(output) = &work.output {
                push(
                    &mut actions,
                    work,
                    actor,
                    "output_published",
                    json!(output.work_version),
                    false,
                );
            }
            if ["done", "cancelled"].contains(&work.state.as_str()) {
                push(
                    &mut actions,
                    work,
                    actor,
                    "execution_finished",
                    json!({"state":work.state,"generation":work.claim_generation}),
                    false,
                );
            }
        }
    }
    if let Some(requirements) = &work.acceptance_requirements {
        let status = acceptance::status(conn, work)?;
        let satisfied = status["obligations"]
            .as_array()
            .is_some_and(|o| o.iter().all(|o| o["status"] == "satisfied"));
        let decided = status["decisions"].as_array().is_some_and(|d| {
            d.iter()
                .any(|d| d["author"] == json!(participant) && d["current"] == true)
        });
        let eligible = requirements.deciders.contains(&participant)
            && !(requirements.independent
                && work
                    .output
                    .as_ref()
                    .is_some_and(|o| o.producer == json!(participant)));
        if work.output.is_some() && eligible && satisfied && !decided {
            push(
                &mut actions,
                work,
                actor,
                "decide_acceptance",
                json!({"output":work.target_generation,"requirements":requirements.version,"obligations":status["obligations"]}),
                true,
            );
        }
        if work.output.is_some()
            && (work.created_by == json!(participant)
                || requirements.authorities.contains(&participant)
                || eligible && status["state"] == "conflicting")
        {
            push(
                &mut actions,
                work,
                actor,
                "acceptance_changed",
                status,
                false,
            );
        }
    }
    Ok(actions)
}

pub(super) fn for_source(
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    id: &str,
) -> Result<Vec<Action>, WorkError> {
    let work = current(conn, room, id)?;
    let root = work
        .check
        .as_ref()
        .map(|c| &c.subject.root_work_id)
        .or_else(|| work.challenge.as_ref().map(|c| &c.subject.root_work_id));
    let mut actions = for_work(conn, &work, actor)?;
    if let Some(root) = root
        && root != id
    {
        actions.extend(for_work(conn, &current(conn, room, root)?, actor)?);
    }
    Ok(actions)
}

pub(crate) fn read(
    conn: &mut Connection,
    room: &str,
    actor: Actor<'_>,
    id: &str,
    include_received: bool,
) -> Result<Value, WorkError> {
    let tx = conn.transaction()?;
    let room_id = authorize(&tx, room, actor, false)?;
    let mut items = Vec::new();
    for action in for_source(&tx, &room_id, actor, id)? {
        let received: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM coord_operations WHERE principal_kind=?1 AND principal_id=?2 AND operation_type='coord.work.receive_action' AND operation_id=?3)", params![actor.kind(),actor.id(),action.key], |r|r.get(0))?;
        if include_received || !received {
            items.push(action);
        }
    }
    Ok(json!({"room_id":room_id,"source_work_id":id,"actions":items}))
}
