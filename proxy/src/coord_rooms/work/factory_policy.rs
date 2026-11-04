//! Approved policy selection and its required checks share the work transaction.
use super::*;
use crate::factory::work::Reference;

pub(super) fn select(
    files: Option<(&std::path::Path, &std::path::Path)>,
    conn: &Connection,
    room: &str,
    actor: Actor<'_>,
    work: &mut Work,
    reference: Reference,
    at: i64,
) -> Result<(), WorkError> {
    let (root, policy_file) = files.ok_or_else(|| {
        invalid("Factory work requires its configured instance and identity policy")
    })?;
    let selected = crate::factory::work::resolve(root, policy_file, &reference)
        .map_err(|e| conflict(&e.to_string()))?;
    if selected.room != room {
        return Err(WorkError(
            403,
            "Factory work must use its approved room".into(),
        ));
    }
    if !matches!(actor, Actor::Operator) && !selected.creators.contains(&actor.principal()) {
        return Err(WorkError(
            403,
            "only an approved Factory creator or operator may select this work policy".into(),
        ));
    }
    for participant in selected
        .authorities
        .iter()
        .chain(&selected.deciders)
        .chain(selected.selection.checks.iter().map(|c| &c.reviewer))
    {
        participant.validate(conn, &work.room_id)?;
    }
    subjects::record_bound(&selected.selection)?;
    work.acceptance_requirements = Some(acceptance::Requirements {
        version: 1,
        author: actor.principal(),
        authorities: selected.authorities,
        deciders: selected.deciders,
        independent: selected.independent,
        checks: vec![],
        challenges: vec![],
        reason: format!(
            "Approved Factory {} snapshot {}",
            reference.name, reference.snapshot_id
        ),
        selected_at: at,
    });
    subjects::record_bound(&work.acceptance_requirements)?;
    work.factory = Some(selected.selection);
    Ok(())
}

pub(super) fn publication(
    conn: &Connection,
    work: &mut Work,
    actor: Actor<'_>,
    operation: &str,
    at: i64,
) -> Result<(), WorkError> {
    let Some(factory) = work.factory.as_ref() else {
        return Ok(());
    };
    if factory.checks.is_empty() {
        return Ok(());
    }
    let templates = factory.checks.clone();
    let previous_checks = factory.current_checks.clone();
    let mut required = Vec::new();
    let mut current_checks = Vec::new();
    for (index, template) in templates.into_iter().enumerate() {
        let mut check = new_work(
            &work.room_id,
            actor,
            template.criterion.clone(),
            work.external_ref.clone(),
            at,
        );
        // The pending publication is already fenced and attributed by publish.
        // It and these exact subjects become visible in the same transaction.
        check.check = Some(checks::Check {
            requester: actor.principal(),
            subject: subjects::Subject {
                reference: subjects::SubjectRef::Output {
                    work_id: work.work_id.clone(),
                    target_generation: work.target_generation,
                },
                root_work_id: work.work_id.clone(),
                work_version: work.version,
                target_ref: work.target_ref.clone(),
                producer: Some(serde_json::from_value(
                    work.output.as_ref().unwrap().producer.clone(),
                )?),
            },
            criterion: template.criterion,
            reviewer: template.reviewer,
            independent: template.independent,
            answer: None,
        });
        let op = format!("{operation}/factory-check/{index}");
        record_change(conn, &check, actor, &op, "factory_check", None)?;
        current_checks.push(check.work_id.clone());
        required.push(acceptance::ReviewReference {
            work_id: check.work_id,
            version: 1,
        });
    }
    let selected = acceptance::select(conn, work, required, false)?;
    let requirements = work.acceptance_requirements.as_mut().unwrap();
    requirements
        .checks
        .retain(|r| !previous_checks.contains(&r.work_id));
    requirements.checks.extend(selected);
    requirements.version = requirements
        .version
        .checked_add(1)
        .ok_or_else(|| conflict("requirements version cannot advance"))?;
    requirements.selected_at = at;
    // Policy author and authority stay attributable to the earlier selection.
    // Existing explicit checks and every selected challenge stay outstanding.
    subjects::record_bound(requirements)?;
    work.factory.as_mut().unwrap().current_checks = current_checks;
    Ok(())
}
