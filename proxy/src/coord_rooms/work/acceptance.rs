//! Selected obligations and attributed decisions about an exact current output.
use super::*;
use subjects::Principal;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewReference {
    pub work_id: String,
    pub version: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReviewKind {
    Check,
    Challenge,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RequiredReview {
    pub work_id: String,
    pub selected_version: i64,
    pub definition: Value,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Requirements {
    pub version: i64,
    pub author: Principal,
    pub authorities: Vec<Principal>,
    pub deciders: Vec<Principal>,
    pub independent: bool,
    pub checks: Vec<RequiredReview>,
    pub challenges: Vec<RequiredReview>,
    pub reason: String,
    pub selected_at: i64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AcceptanceDecision {
    pub author: Principal,
    pub target_generation: i64,
    pub requirements_version: i64,
    pub review_basis: String,
    pub verdict: attestations::Verdict,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub work_version: i64,
    pub decided_at: i64,
}

fn definition(work: &Work, challenge: bool) -> Result<Value, WorkError> {
    let mut value = if challenge {
        serde_json::to_value(
            work.challenge
                .as_ref()
                .ok_or_else(|| invalid("required challenge must name challenge work"))?,
        )?
    } else {
        serde_json::to_value(
            work.check
                .as_ref()
                .ok_or_else(|| invalid("required check must name assigned check work"))?,
        )?
    };
    for field in ["answer", "response", "disposition", "recovery_reason"] {
        value.as_object_mut().unwrap().remove(field);
    }
    Ok(value)
}

pub(super) fn select(
    conn: &Connection,
    work: &Work,
    refs: Vec<ReviewReference>,
    challenge: bool,
) -> Result<Vec<RequiredReview>, WorkError> {
    let mut selected = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for reference in refs {
        if !ids.insert(reference.work_id.clone()) {
            return Err(invalid("required review IDs must be distinct"));
        }
        let review = current(conn, &work.room_id, &reference.work_id)?;
        if review.version != reference.version {
            return Err(conflict(
                "required review changed; read its current revision before selecting it",
            ));
        }
        let definition = definition(&review, challenge)?;
        let subject = if let Some(check) = &review.check {
            &check.subject
        } else {
            &review.challenge.as_ref().unwrap().subject
        };
        if definition["subject"]["root_work_id"] != work.work_id
            && subject.reference.work_id() != work.work_id
            && output_subject(conn, &work.room_id, subject)?
                .as_ref()
                .map(|(id, _)| id)
                != Some(&work.work_id)
        {
            return Err(invalid(
                "required review must concern this work or its reviews",
            ));
        }
        selected.push(RequiredReview {
            work_id: reference.work_id,
            selected_version: reference.version,
            definition,
        });
    }
    Ok(selected)
}

fn producer(work: &Work, actor: &Principal) -> bool {
    work.output
        .as_ref()
        .is_some_and(|o| o.producer == json!(actor))
}

fn requirements_authority(
    work: &Work,
    actor: Actor<'_>,
    expected_requirements_version: i64,
) -> Result<Principal, WorkError> {
    let previous = work.acceptance_requirements.as_ref();
    if previous.map_or(0, |r| r.version) != expected_requirements_version {
        return Err(conflict(
            "stale selected requirements; read current work before changing policy",
        ));
    }
    let principal = actor.principal();
    if !matches!(actor, Actor::Operator) {
        let authorized = previous.map_or_else(
            || work.created_by == json!(principal),
            |r| r.authorities.contains(&principal),
        );
        if !authorized {
            return Err(WorkError(403, "initial requirements require the work creator; amendments require a recorded authority".into()));
        }
    }
    Ok(principal)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn set_requirements(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    expected_requirements_version: i64,
    authorities: Vec<Principal>,
    deciders: Vec<Principal>,
    independent: bool,
    checks: Vec<ReviewReference>,
    challenges: Vec<ReviewReference>,
    reason: String,
    at: i64,
) -> Result<(), WorkError> {
    let principal = requirements_authority(work, actor, expected_requirements_version)?;
    subjects::evidence(&reason, &[])?;
    if deciders.is_empty() {
        return Err(invalid(
            "selected acceptance must name at least one eligible decider",
        ));
    }
    for principals in [&authorities, &deciders] {
        for (index, principal) in principals.iter().enumerate() {
            principal.validate(conn, &work.room_id)?;
            if principals[..index].contains(principal) {
                return Err(invalid(
                    "requirement authorities and deciders must be distinct within each list",
                ));
            }
        }
    }
    if independent && deciders.iter().any(|p| producer(work, p)) {
        return Err(WorkError(
            403,
            "output producer cannot decide its independent acceptance".into(),
        ));
    }
    let requirements = Requirements {
        version: expected_requirements_version
            .checked_add(1)
            .ok_or_else(|| conflict("requirements version cannot advance"))?,
        author: principal,
        authorities,
        deciders,
        independent,
        checks: select(conn, work, checks, false)?,
        challenges: select(conn, work, challenges, true)?,
        reason,
        selected_at: at,
    };
    subjects::record_bound(&requirements)?;
    // Removed participants remain in immutable revisions. Keeping their large
    // decisions in the effective array could otherwise exhaust the bound and
    // prevent a replacement decider from recording its recovery decision.
    work.acceptance_decisions
        .retain(|d| requirements.deciders.contains(&d.author));
    work.acceptance_requirements = Some(requirements);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn select_review(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    expected_requirements_version: i64,
    review_kind: ReviewKind,
    review: ReviewReference,
    replace_work_id: Option<String>,
    reason: String,
    at: i64,
) -> Result<(), WorkError> {
    let principal = requirements_authority(work, actor, expected_requirements_version)?;
    let requirements = work.acceptance_requirements.as_ref().ok_or_else(|| {
        invalid(
            "select initial acceptance policy with set_work_requirements before amending a review",
        )
    })?;
    subjects::evidence(&reason, &[])?;
    let challenge = matches!(review_kind, ReviewKind::Challenge);
    let selected = if challenge {
        &requirements.challenges
    } else {
        &requirements.checks
    };
    let replacement = replace_work_id
        .map(|id| {
            selected
                .iter()
                .position(|r| r.work_id == id)
                .ok_or_else(|| {
                    conflict("replacement target must be a selected review of the same kind")
                })
        })
        .transpose()?;
    if selected
        .iter()
        .enumerate()
        .any(|(i, r)| r.work_id == review.work_id && Some(i) != replacement)
    {
        return Err(invalid("required review IDs must be distinct"));
    }
    let review = select(conn, work, vec![review], challenge)?.pop().unwrap();
    let version = requirements
        .version
        .checked_add(1)
        .ok_or_else(|| conflict("requirements version cannot advance"))?;
    let requirements = work.acceptance_requirements.as_mut().unwrap();
    let selected = if challenge {
        &mut requirements.challenges
    } else {
        &mut requirements.checks
    };
    if let Some(index) = replacement {
        selected[index] = review;
    } else {
        selected.push(review);
    }
    // Retained entries keep their selected revisions and definitions, including
    // definitions that have since changed and must remain visibly inconsistent.
    requirements.version = version;
    requirements.author = principal;
    requirements.reason = reason;
    requirements.selected_at = at;
    subjects::record_bound(requirements)?;
    Ok(())
}

// Follow immutable review subjects, never current ownership or a supplied
// producer. Each reference predates its containing review, so this is acyclic.
fn output_subject(
    conn: &Connection,
    room: &str,
    subject: &subjects::Subject,
) -> Result<Option<(String, i64)>, WorkError> {
    let mut reference = subject.reference.clone();
    loop {
        if let subjects::SubjectRef::Output {
            work_id,
            target_generation,
        } = reference
        {
            return Ok(Some((work_id, target_generation)));
        }
        let version = match &reference {
            subjects::SubjectRef::Work { version, .. }
            | subjects::SubjectRef::Check { version, .. } => *version,
            _ => unreachable!(),
        };
        let review: Work =
            serde_json::from_value(revision(conn, room, reference.work_id(), version)?)?;
        if matches!(reference, subjects::SubjectRef::Work { .. }) && review.output.is_some() {
            return Ok(Some((review.work_id, review.target_generation)));
        }
        if let Some(check) = review.check {
            reference = check.subject.reference;
        } else if let Some(challenge) = review.challenge {
            reference = challenge.subject.reference;
        } else {
            return Ok(review
                .output
                .map(|_| (review.work_id, review.target_generation)));
        }
    }
}

fn obligations(
    conn: &Connection,
    work: &Work,
    requirements: &Requirements,
) -> Result<Vec<Value>, WorkError> {
    let mut observations = Vec::new();
    for (challenge, required) in requirements
        .checks
        .iter()
        .map(|r| (false, r))
        .chain(requirements.challenges.iter().map(|r| (true, r)))
    {
        let review = current(conn, &work.room_id, &required.work_id)?;
        let matches = definition(&review, challenge)? == required.definition;
        let mut observation = json!({"kind":if challenge {"challenge"} else {"check"},
            "work_id":required.work_id,"selected_version":required.selected_version});
        let status = if !matches {
            "assignment_changed"
        } else if let Some(check) = review.check.as_ref() {
            observation["answer_version"] = json!(check.answer.as_ref().map(|a| a.work_version));
            if output_subject(conn, &work.room_id, &check.subject)?
                != Some((work.work_id.clone(), work.target_generation))
            {
                "stale_subject"
            } else if check.independent && check.subject.producer.as_ref() == Some(&check.reviewer)
            {
                "ineligible_reviewer"
            } else if review.state == "cancelled" {
                "cancelled_check"
            } else if let Some(answer) = &check.answer
                && review.state == "done"
            {
                match answer.verdict {
                    attestations::Verdict::Approve => "satisfied",
                    attestations::Verdict::Reject => "rejected_check",
                    attestations::Verdict::Abstain => "uncertain_check",
                }
            } else {
                "pending_check"
            }
        } else {
            let challenge = review.challenge.as_ref().unwrap();
            observation["response_version"] =
                json!(challenge.response.as_ref().map(|r| r.work_version));
            observation["disposition_version"] =
                json!(challenge.disposition.as_ref().map(|d| d.work_version));
            observation["disposition"] = json!(challenge.disposition.as_ref().map(|d| &d.decision));
            match &challenge.disposition {
                None => "unresolved_challenge",
                Some(disposition)
                    if !(challenge.deciders.contains(&disposition.author)
                        || disposition.author.kind == "operator"
                            && disposition.author.id == "operator") =>
                {
                    "disposition_author_changed"
                }
                Some(_) => "satisfied",
            }
        };
        observation["status"] = json!(status);
        observations.push(observation);
    }
    Ok(observations)
}

fn basis(observations: &[Value]) -> String {
    hash(json!(observations).to_string().as_bytes())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn decide(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    expected_requirements_version: i64,
    expected_target_generation: i64,
    verdict: attestations::Verdict,
    summary: String,
    evidence_refs: Vec<String>,
    at: i64,
) -> Result<(), WorkError> {
    let requirements = work
        .acceptance_requirements
        .as_ref()
        .ok_or_else(|| conflict("no acceptance requirements selected"))?;
    if requirements.version != expected_requirements_version
        || work.target_generation != expected_target_generation
    {
        return Err(conflict("stale requirements or output generation"));
    }
    let author = actor.principal();
    if !requirements.deciders.contains(&author) {
        return Err(WorkError(
            403,
            "only a selected acceptance decider may record this decision".into(),
        ));
    }
    if requirements.independent && producer(work, &author) {
        return Err(WorkError(
            403,
            "output producer cannot decide its independent acceptance".into(),
        ));
    }
    if work.output.is_none() {
        return Err(conflict("acceptance decision requires a published output"));
    }
    let observations = obligations(conn, work, requirements)?;
    if matches!(verdict, attestations::Verdict::Approve)
        && observations.iter().any(|o| o["status"] != "satisfied")
    {
        return Err(conflict(
            "required review obligations are unmet; read current acceptance_status",
        ));
    }
    subjects::evidence(&summary, &evidence_refs)?;
    let decision = AcceptanceDecision {
        author: author.clone(),
        target_generation: work.target_generation,
        requirements_version: requirements.version,
        review_basis: basis(&observations),
        verdict,
        summary,
        evidence_refs,
        work_version: work
            .version
            .checked_add(1)
            .ok_or_else(|| conflict("work version cannot advance"))?,
        decided_at: at,
    };
    subjects::record_bound(&decision)?;
    work.acceptance_decisions.retain(|d| d.author != author);
    work.acceptance_decisions.push(decision);
    if serde_json::to_vec(&work.acceptance_decisions)?.len() > MAX_REQUEST_BYTES {
        return Err(invalid(
            "effective acceptance decisions exceed 262144 serialized UTF-8 bytes",
        ));
    }
    Ok(())
}

pub(super) fn status(conn: &Connection, work: &Work) -> Result<Value, WorkError> {
    let Some(requirements) = work.acceptance_requirements.as_ref() else {
        return Ok(
            json!({"state":"not_selected","target_generation":work.target_generation,
            "reason":"no acceptance requirements selected; execution and attestations do not imply acceptance"}),
        );
    };
    let observations = obligations(conn, work, requirements)?;
    let current_basis = basis(&observations);
    let satisfied = observations.iter().all(|o| o["status"] == "satisfied");
    let mut decisions = Vec::new();
    let (mut approve, mut reject, mut abstain) = (false, false, false);
    for decision in &work.acceptance_decisions {
        let eligible = requirements.deciders.contains(&decision.author)
            && !(requirements.independent && producer(work, &decision.author));
        let reason = if !eligible {
            Some("decider_not_eligible")
        } else if decision.requirements_version != requirements.version {
            Some("requirements_changed")
        } else if decision.target_generation != work.target_generation {
            Some("output_changed")
        } else if matches!(decision.verdict, attestations::Verdict::Approve)
            && (decision.review_basis != current_basis || !satisfied)
        {
            Some("required_review_changed")
        } else {
            None
        };
        if reason.is_none() {
            match decision.verdict {
                attestations::Verdict::Approve => approve = true,
                attestations::Verdict::Reject => reject = true,
                attestations::Verdict::Abstain => abstain = true,
            }
        }
        decisions.push(json!({"author":decision.author,"verdict":decision.verdict,"work_version":decision.work_version,
            "current":reason.is_none(),"stale_reason":reason}));
    }
    let (state, reason) = if work.output.is_none() {
        ("pending", "no_output")
    } else if approve && reject {
        (
            "conflicting",
            "eligible_deciders_disagree; an explicit corrected decision or authorized requirement amendment is needed",
        )
    } else if reject {
        ("rejected", "eligible_decider_rejected")
    } else if !satisfied {
        ("pending", "required_review_unmet")
    } else if approve {
        (
            "accepted",
            "eligible_approval_and_required_review_satisfied",
        )
    } else if abstain {
        ("uncertain", "eligible_decider_abstained")
    } else {
        ("pending", "no_current_approval")
    };
    Ok(
        json!({"state":state,"reason":reason,"target_generation":work.target_generation,
        "requirements_version":requirements.version,"obligations":observations,"decisions":decisions}),
    )
}
