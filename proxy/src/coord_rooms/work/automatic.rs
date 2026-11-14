//! Automatic requirements live in Work and use its revisions, receipts and attention.
use super::*;
use crate::policy::{
    Policy,
    checks::{
        self, Evidence, FileVersion, Subject, Truth,
        work::{Binding, Boundary},
    },
};
use crate::{Runtime, RuntimeState};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLockReadGuard},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    Pending,
    Dispatching,
    Satisfied,
    Completed,
    Unavailable,
    Failed,
    Uncertain,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Obligation {
    pub id: String,
    pub binding: Binding,
    pub policy_hash: String,
    pub service_definitions_hash: Option<String>,
    pub subject: Subject,
    pub target_generation: i64,
    pub claim_generation: i64,
    pub state: State,
    pub evidence: Option<Evidence>,
    pub detail: String,
    pub source_version: Option<(PathBuf, FileVersion)>,
    pub updated_at: i64,
    pub resolution: Option<Value>,
}

pub(crate) struct Configuration {
    policy: Option<Arc<Policy>>,
    root: Option<PathBuf>,
}

// Constructed only by the trusted invocation path, never deserialized from a request.
pub(crate) struct Prepared {
    runtime: Arc<Runtime>,
    state: RuntimeState,
    request: Value,
    records: Vec<Obligation>,
    factories: Vec<crate::factory::work::Reference>,
    caller: Option<crate::agent_api::coord::CoordClient>,
}
impl Prepared {
    pub(super) fn current(&self) -> Result<RwLockReadGuard<'_, Arc<Runtime>>, WorkError> {
        let current = self
            .state
            .read()
            .map_err(|_| WorkError(503, "current work authority unavailable".into()))?;
        if !Arc::ptr_eq(&self.runtime, &current) {
            return Err(conflict(
                "work policy or authority changed while the check was pending; inspect current policy before retrying",
            ));
        }
        if let Some(caller) = &self.caller
            && current
                .policy
                .as_ref()
                .is_none_or(|policy| !caller.work_caller_current(policy))
        {
            return Err(WorkError(
                403,
                "requester run or federation authority changed while the check was pending".into(),
            ));
        }
        for record in &self.records {
            if let Some((path, version)) = &record.source_version
                && std::fs::metadata(path)
                    .ok()
                    .map(|m| FileVersion::from_metadata(&m))
                    .as_ref()
                    != Some(version)
            {
                return Err(conflict(
                    "adopted job definition changed while the requirement was pending",
                ));
            }
        }
        Ok(current)
    }
}

pub(crate) fn configuration(
    files: Option<(&Path, &Path)>,
    prepared: Option<&Prepared>,
) -> Result<Configuration, WorkError> {
    let policy = if let Some(prepared) = prepared {
        prepared.runtime.policy.clone()
    } else {
        files
            .map(|(_, path)| Policy::from_native_path(path).map(Arc::new))
            .transpose()
            .map_err(|e| WorkError(503, format!("work binding policy unavailable: {e}")))?
    };
    Ok(Configuration {
        policy,
        root: files.map(|(root, _)| root.to_owned()),
    })
}

#[derive(Default)]
pub(crate) struct Guard {
    pub factory: Option<crate::factory::work::Reference>,
    records: Vec<Obligation>,
}

fn issue(binding: &Binding, external_ref: Option<&str>) -> Option<String> {
    // These spellings identify the same GitHub issue. Optional metadata and
    // equivalent web/API URLs must not turn a protected admission into generic Work.
    let reference = external_ref?.split(['?', '#']).next()?;
    let uri: hyper::Uri = reference.parse().ok()?;
    let scheme = uri.scheme_str()?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let host = uri.host()?.trim_end_matches('.').to_ascii_lowercase();
    let port = uri
        .port_u16()
        .unwrap_or(if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        });
    if port
        != if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        }
    {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(uri.path())
        .decode_utf8()
        .ok()?;
    let mut parts = Vec::new();
    for part in decoded.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    let (owner, repo, number) = match (host.as_str(), parts.as_slice()) {
        ("github.com", [owner, repo, "issues", number]) => (*owner, *repo, *number),
        ("api.github.com", ["repos", owner, repo, "issues", number]) => (*owner, *repo, *number),
        _ => return None,
    };
    let repository = format!("{owner}/{repo}");
    if !repository.eq_ignore_ascii_case(binding.repository.as_ref()?) {
        return None;
    }
    let reference = github::Reference::parse(&format!(
        "https://github.com/{owner}/{repo}/issues/{number}"
    ))
    .ok()?;
    reference.url.rsplit('/').next().map(str::to_owned)
}

fn selected<'a>(configuration: &'a Configuration, room: &str) -> impl Iterator<Item = &'a Binding> {
    configuration
        .policy
        .iter()
        .flat_map(|p| &p.named_checks().work_bindings)
        .filter(move |b| b.room == room)
}

fn subject(binding: &Binding, work: &Work) -> Result<Subject, WorkError> {
    let value = match binding.boundary {
        Boundary::AdmitIssue => issue(binding, work.external_ref.as_deref())
            .ok_or_else(|| invalid("issue is outside the binding's configured repository"))?,
        Boundary::VerifyOutput => {
            let output = work.output.as_ref().ok_or_else(|| conflict("no output to verify"))?;
            let artifact = output.artifact_base64.as_ref()
                .ok_or_else(|| conflict("required verification needs artifact_base64 retained with the output"))?;
            json!({"work_id":work.work_id,"target_generation":work.target_generation,
                "target_ref":work.target_ref,"artifact_base64":artifact}).to_string()
        }
        Boundary::AfterComplete => json!({"work_id":work.work_id,"claim_generation":work.claim_generation,
            "target_generation":work.target_generation,"target_ref":work.target_ref,
            "short_result":work.short_result,
            "obligation_id":format!("{}/{}/{}/{}",work.work_id,work.claim_generation,work.target_generation,binding.name)}).to_string(),
    };
    Ok(Subject::Value { value })
}

fn current_work(
    conn: &Connection,
    room_id: &str,
    input: &Value,
) -> Result<Option<Work>, WorkError> {
    input["work_id"]
        .as_str()
        .map(|id| current(conn, room_id, id))
        .transpose()
}

fn admission_bindings<'a>(
    configuration: &'a Configuration,
    room: &str,
    input: &Value,
    work: Option<&Work>,
) -> Vec<&'a Binding> {
    if !matches!(
        input["action"].as_str(),
        Some("create" | "claim" | "reassign" | "continue")
    ) || work.is_some_and(|w| w.check.is_some() || w.challenge.is_some())
    {
        return vec![];
    }
    let reference = work
        .and_then(|w| w.external_ref.as_deref())
        .or_else(|| input["external_ref"].as_str());
    selected(configuration, room)
        .filter(|b| b.boundary == Boundary::AdmitIssue && issue(b, reference).is_some())
        .collect()
}

fn active_verifiers<'a>(
    configuration: &'a Configuration,
    room: &str,
    work: &Work,
) -> Vec<&'a Binding> {
    let factory = work.factory.as_ref().map(|f| f.reference.name.as_str());
    selected(configuration, room)
        .filter(|b| b.boundary == Boundary::VerifyOutput && Some(b.factory.as_str()) == factory)
        .collect()
}

pub(crate) fn guard(
    configuration: &Configuration,
    conn: &Connection,
    room: &str,
    room_id: &str,
    _actor: Actor<'_>,
    input: &Value,
    prepared: Option<&Prepared>,
) -> Result<Guard, WorkError> {
    let work = current_work(conn, room_id, input)?;
    let mut required = admission_bindings(configuration, room, input, work.as_ref());
    let approving = input["action"] == "decide_acceptance" && input["verdict"] == "approve";
    if approving && let Some(work) = &work {
        required.extend(active_verifiers(configuration, room, work));
    }
    let mut guard = Guard::default();
    if approving && let Some(work) = &work {
        for record in work.automatic.iter().filter(|r| {
            r.binding.boundary == Boundary::VerifyOutput
                && r.target_generation == work.target_generation
                && !matches!(r.state, State::Cancelled)
                && !required.iter().any(|b| b.name == r.binding.name)
        }) {
            let mut record = record.clone();
            record.state = State::Cancelled;
            record.detail =
                "current adopted operator policy no longer selects this verification requirement"
                    .into();
            record.updated_at = now();
            guard.records.push(record);
        }
    }
    if required.is_empty() && guard.records.is_empty() {
        return Ok(guard);
    }
    let prepared = prepared.ok_or_else(|| {
        conflict(
            "automatic work requirement needs the running proxy; use the authenticated work API",
        )
    })?;
    if prepared.request != *input {
        return Err(conflict(
            "automatic evidence belongs to a different work operation",
        ));
    }
    for binding in required {
        let policy = configuration.policy.as_ref().unwrap();
        let expected_subject = if binding.boundary == Boundary::AdmitIssue {
            let reference = work
                .as_ref()
                .and_then(|w| w.external_ref.as_deref())
                .or_else(|| input["external_ref"].as_str());
            Subject::Value {
                value: issue(binding, reference).unwrap(),
            }
        } else {
            subject(binding, work.as_ref().unwrap())?
        };
        let record = prepared
            .records
            .iter()
            .find(|r| {
                r.binding.name == binding.name
                    && json!(r.binding) == json!(binding)
                    && r.policy_hash == policy.work_authority_digest()
                    && r.service_definitions_hash.as_ref()
                        == Some(&policy.work_service_definitions_digest())
                    && r.subject == expected_subject
            })
            .ok_or_else(|| conflict("required automatic evidence is absent or substituted"))?;
        if record.evidence.as_ref().is_none_or(|e| {
            policy
                .named_checks()
                .work_truth(binding, &expected_subject, e.clone(), now() as u64)
                != Truth::True
        }) {
            return Err(conflict(&format!(
                "automatic requirement {} is unmet (job {}, factory {}, policy {}): {}; inspect ops.work_requirement for the operation ID and the current adopted check before retrying",
                binding.name, binding.job, binding.factory, record.policy_hash, record.detail
            )));
        }
        guard.records.push(record.clone());
        if binding.boundary == Boundary::AdmitIssue {
            let reference = crate::factory::work::current_reference(
                configuration
                    .root
                    .as_deref()
                    .ok_or_else(|| invalid("binding requires an instance root"))?,
                &binding.factory,
            )
            .map_err(|e| conflict(&e.to_string()))?;
            if !prepared
                .factories
                .iter()
                .any(|r| json!(r) == json!(reference))
            {
                return Err(conflict(
                    "approved Factory changed while admission was pending",
                ));
            }
            if guard
                .factory
                .as_ref()
                .is_some_and(|f| f.name != reference.name)
            {
                return Err(invalid("issue admission cannot select multiple factories"));
            }
            if input
                .get("factory")
                .is_some_and(|f| !f.is_null() && *f != json!(reference))
                || work
                    .as_ref()
                    .and_then(|w| w.factory.as_ref())
                    .is_some_and(|f| json!(f.reference) != json!(reference))
            {
                return Err(conflict(
                    "protected issue must use its configured approved factory",
                ));
            }
            guard.factory = Some(reference);
        }
    }
    Ok(guard)
}

pub(crate) fn apply(work: &mut Work, guard: &Guard) {
    for record in &guard.records {
        work.automatic.retain(|old| {
            old.binding.name != record.binding.name
                || old.binding.boundary != record.binding.boundary
        });
        let mut record = record.clone();
        record.id = format!(
            "{}/{}/{}/{}",
            work.work_id, work.claim_generation, work.target_generation, record.binding.name
        );
        work.automatic.push(record);
    }
}

pub(crate) fn retain(
    configuration: &Configuration,
    room: &str,
    work: &mut Work,
    guard: &Guard,
    action: &str,
    at: i64,
) -> Result<(), WorkError> {
    apply(work, guard);
    let Some(factory) = work.factory.as_ref() else {
        return Ok(());
    };
    let boundary = match action {
        "publish_output" => Boundary::VerifyOutput,
        "complete" if work.check.is_none() && work.challenge.is_none() => Boundary::AfterComplete,
        _ => return Ok(()),
    };
    if boundary == Boundary::VerifyOutput {
        work.automatic.retain(|r| r.binding.boundary != boundary);
    }
    for binding in selected(configuration, room)
        .filter(|b| b.boundary == boundary && b.factory == factory.reference.name)
    {
        let mapped = subject(binding, work);
        let (subject, state, detail) = match mapped {
            Ok(subject) => (
                subject,
                State::Pending,
                "automatic invocation pending".into(),
            ),
            Err(error) => (
                Subject::Value {
                    value: String::new(),
                },
                State::Unavailable,
                error.to_string(),
            ),
        };
        work.automatic.push(Obligation {
            id: format!(
                "{}/{}/{}/{}",
                work.work_id, work.claim_generation, work.target_generation, binding.name
            ),
            binding: binding.clone(),
            policy_hash: configuration
                .policy
                .as_ref()
                .unwrap()
                .work_authority_digest(),
            service_definitions_hash: None,
            subject,
            target_generation: work.target_generation,
            claim_generation: work.claim_generation,
            state,
            evidence: None,
            detail,
            source_version: None,
            updated_at: at,
            resolution: None,
        });
    }
    Ok(())
}

pub(crate) fn observations(
    conn: &Connection,
    work: &Work,
    policy: Option<&Policy>,
) -> Result<Vec<Value>, WorkError> {
    let authority = policy.map(Policy::work_authority_digest);
    let room: String = conn.query_row(
        "SELECT name FROM rooms WHERE room_id=?1",
        [&work.room_id],
        |r| r.get(0),
    )?;
    let active: Vec<&Binding> = policy
        .into_iter()
        .flat_map(|p| &p.named_checks().work_bindings)
        .filter(|b| {
            b.boundary == Boundary::VerifyOutput
                && b.room == room
                && work
                    .factory
                    .as_ref()
                    .is_some_and(|f| f.reference.name == b.factory)
        })
        .collect();
    let records: Vec<&Obligation> = work
        .automatic
        .iter()
        .filter(|r| {
            r.binding.boundary == Boundary::VerifyOutput
                && r.target_generation == work.target_generation
                && !matches!(r.state, State::Cancelled)
                && (policy.is_none() || active.iter().any(|b| b.name == r.binding.name))
        })
        .collect();
    let mut result: Vec<Value> = records.iter().map(|record| {
        let fresh = record.evidence.as_ref().is_some_and(|e| e.unavailable.is_none()
            && e.expires_at_ms.is_some_and(|until| now() >= 0 && (now() as u64) < until));
        let applicable = policy.is_none_or(|policy| authority.as_ref() == Some(&record.policy_hash)
            && record.service_definitions_hash.as_ref() == Some(&policy.work_service_definitions_digest())
            && policy.named_checks().work_bindings.iter().any(|b| json!(b) == json!(record.binding))
            && source_current(record)
            && record.evidence.as_ref().is_some_and(|e| policy.named_checks().work_truth(&record.binding, &record.subject, e.clone(), now() as u64) == Truth::True));
        let satisfied = applicable && matches!(record.state, State::Satisfied) && fresh && record.target_generation == work.target_generation;
        json!({"kind":"automatic_check","binding":record.binding.name,"job":record.binding.job,
            "status":if satisfied {"satisfied"}else{"pending"},"state":record.state,
            "authority":{"factory":record.binding.factory,"policy_hash":record.policy_hash},
            "target_generation":record.target_generation,"result":record.evidence,
            "detail":if !applicable {"adopted policy, service definition or job authority changed; re-evaluate under current authority"}else if !fresh {"required evidence is absent, stale or unavailable"}else{&record.detail},
            "recovery":"use the running proxy to inspect or re-evaluate the current output under current adopted authority"})
    }).collect();
    for binding in active
        .iter()
        .filter(|b| !records.iter().any(|r| r.binding.name == b.name))
    {
        result.push(json!({"kind":"automatic_check","binding":binding.name,"job":binding.job,
            "status":"pending","state":"pending","target_generation":work.target_generation,
            "authority":{"factory":binding.factory,"policy_hash":authority},
            "detail":"current adopted policy requires verification of this output; no applicable result is retained",
            "recovery":"use the running proxy to re-evaluate acceptance under current adopted authority"}));
    }
    Ok(result)
}

fn source_version(policy: &Policy, binding: &Binding) -> Option<(PathBuf, FileVersion)> {
    match &policy.named_checks().checks.get(&binding.job)?.source {
        checks::EvidenceSource::Job { spec, .. } => std::fs::metadata(spec)
            .ok()
            .map(|m| (spec.clone(), FileVersion::from_metadata(&m))),
        _ => None,
    }
}

fn source_current(record: &Obligation) -> bool {
    record
        .source_version
        .as_ref()
        .is_none_or(|(path, version)| {
            std::fs::metadata(path)
                .ok()
                .map(|m| FileVersion::from_metadata(&m))
                .as_ref()
                == Some(version)
        })
}

fn runtime(state: &RuntimeState) -> Result<Arc<Runtime>, WorkError> {
    state
        .read()
        .map(|r| r.clone())
        .map_err(|_| WorkError(503, "current work runtime unavailable".into()))
}

fn open(root: &Path) -> Result<Connection, WorkError> {
    crate::coord_rooms::open(root)
        .map_err(|e| WorkError(503, format!("work store unavailable: {e}")))
}

fn files(runtime: &Runtime) -> Option<(&Path, &Path)> {
    runtime
        .config
        .native_config_dir
        .as_deref()
        .zip(runtime.config.policy_file.as_deref())
}

async fn invoke(runtime: &Runtime, state: &RuntimeState, mut record: Obligation) -> Obligation {
    let action = record.binding.boundary == Boundary::AfterComplete;
    let Some(policy) = runtime.policy.as_ref() else {
        record.state = State::Unavailable;
        record.detail = "adopted job policy unavailable".into();
        return record;
    };
    record.source_version = source_version(policy, &record.binding);
    record.service_definitions_hash = Some(policy.work_service_definitions_digest());
    let result = policy
        .named_checks()
        .invoke_automatic(
            &record.binding.job,
            record.subject.clone(),
            runtime,
            state,
            action,
            record.binding.boundary == Boundary::AdmitIssue,
        )
        .await;
    match result {
        Ok(evidence) => {
            record.detail = evidence.unavailable.clone().unwrap_or_else(|| {
                if action {
                    "action execution completed; the preceding transition remains committed".into()
                } else {
                    "automatic check returned a typed finding".into()
                }
            });
            record.state = if action {
                if evidence.unavailable.is_none() && evidence.execution.is_some() {
                    State::Completed
                } else {
                    State::Uncertain
                }
            } else if policy.named_checks().work_truth(
                &record.binding,
                &record.subject,
                evidence.clone(),
                now() as u64,
            ) == Truth::True
                && source_current(&record)
            {
                State::Satisfied
            } else {
                State::Unavailable
            };
            record.evidence = Some(evidence);
        }
        Err(error) => {
            record.state = if action {
                State::Uncertain
            } else {
                State::Unavailable
            };
            record.detail = if action {
                format!(
                    "action outcome uncertain: {error}; inspect external authority using obligation_id before any further effect"
                )
            } else {
                error.to_string()
            };
        }
    }
    record.updated_at = now();
    record
}

/// All I/O and adopted execution precede the transactional admission guard.
/// The core still enforces bindings when called directly without this wrapper.
pub(crate) async fn mutate(
    state: &RuntimeState,
    root: &Path,
    room: &str,
    actor: Actor<'_>,
    mutation: Mutation,
    operation: Option<&str>,
    caller: Option<crate::agent_api::coord::CoordClient>,
) -> Result<Value, WorkError> {
    if matches!(actor, Actor::Machine(_)) {
        return Err(WorkError(
            403,
            "machine findings are not participant mutations".into(),
        ));
    }
    let runtime = runtime(state)?;
    // An unactivated saved policy never becomes live execution authority.
    let configuration = Configuration {
        policy: runtime.policy.clone(),
        root: Some(root.to_owned()),
    };
    let input = serde_json::to_value(&mutation)?;
    let mut replay = None;
    let work = {
        let conn = open(root)?;
        let room_id = authorize(&conn, room, actor, true)?;
        // Recover a committed operation before invoking a check or an action again.
        if let Some(operation) = operation {
            let prior: Option<(String, String)> = conn.query_row(
                "SELECT request_hash,outcome_json FROM coord_operations WHERE principal_kind=?1 AND principal_id=?2 AND operation_type=?3 AND operation_id=?4",
                params![actor.kind(),actor.id(),format!("coord.work.{}",input["action"].as_str().unwrap()),operation], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
            if let Some((original, result)) = prior {
                if original
                    != hash(
                        json!({"room_id":room_id,"mutation":input})
                            .to_string()
                            .as_bytes(),
                    )
                {
                    return Err(conflict(
                        "operation ID conflicts with the original canonical request",
                    ));
                }
                replay = Some(serde_json::from_str::<Value>(&result)?);
            }
        }
        if replay.is_none() {
            current_work(&conn, &room_id, &input)?
        } else {
            None
        }
    };
    if let Some(result) = replay {
        return Ok(run_retained_obligations(state, root, result).await);
    }
    let mut required = admission_bindings(&configuration, room, &input, work.as_ref());
    if input["action"] == "decide_acceptance"
        && input["verdict"] == "approve"
        && let Some(work) = &work
    {
        required.extend(active_verifiers(&configuration, room, work));
    }
    let mut prepared = Prepared {
        runtime: runtime.clone(),
        state: state.clone(),
        request: input.clone(),
        records: vec![],
        factories: vec![],
        caller,
    };
    for binding in required {
        if binding.boundary == Boundary::AdmitIssue {
            let policy_file = runtime
                .config
                .policy_file
                .clone()
                .ok_or_else(|| invalid("admission requires configured identity policy"))?;
            let factory_root = root.to_owned();
            let factory = binding.factory.clone();
            let (reference, selected) = tokio::task::spawn_blocking(move || {
                let reference = crate::factory::work::current_reference(&factory_root, &factory)
                    .map_err(|e| conflict(&e.to_string()))?;
                let selected =
                    crate::factory::work::resolve(&factory_root, &policy_file, &reference)
                        .map_err(|e| conflict(&e.to_string()))?;
                Ok::<_, WorkError>((reference, selected))
            })
            .await
            .map_err(|e| WorkError(503, format!("Factory admission inspection failed: {e}")))??;
            let creator = work
                .as_ref()
                .map_or_else(|| json!(actor.principal()), |w| w.created_by.clone());
            if !matches!(actor, Actor::Operator)
                && creator != json!({"kind":"operator","id":"operator"})
                && !selected.creators.iter().any(|p| json!(p) == creator)
            {
                return Err(WorkError(
                    403,
                    "protected issue requires an approved Factory creator or operator".into(),
                ));
            }
            prepared.factories.push(reference);
        }
        let mapped = if binding.boundary == Boundary::AdmitIssue {
            let reference = work
                .as_ref()
                .and_then(|w| w.external_ref.as_deref())
                .or_else(|| input["external_ref"].as_str());
            Subject::Value {
                value: issue(binding, reference).unwrap(),
            }
        } else {
            subject(binding, work.as_ref().unwrap())?
        };
        let policy = runtime.policy.as_ref().unwrap();
        if let Some(record) = work.as_ref().and_then(|w| {
            w.automatic.iter().find(|r| {
                binding.boundary != Boundary::AdmitIssue
                    && r.binding.name == binding.name
                    && json!(r.binding) == json!(binding)
                    && r.policy_hash == policy.work_authority_digest()
                    && r.service_definitions_hash.as_ref()
                        == Some(&policy.work_service_definitions_digest())
                    && r.subject == mapped
                    && source_current(r)
                    && r.evidence.as_ref().is_some_and(|e| {
                        policy
                            .named_checks()
                            .work_truth(binding, &mapped, e.clone(), now() as u64)
                            == Truth::True
                    })
            })
        }) {
            prepared.records.push(record.clone());
            continue;
        }
        let record = Obligation {
            id: binding.name.clone(),
            binding: binding.clone(),
            policy_hash: policy.work_authority_digest(),
            service_definitions_hash: None,
            subject: mapped,
            target_generation: work.as_ref().map_or(0, |w| w.target_generation),
            claim_generation: work.as_ref().map_or(0, |w| w.claim_generation),
            state: State::Pending,
            evidence: None,
            detail: "automatic invocation pending".into(),
            source_version: None,
            resolution: None,
            updated_at: now(),
        };
        let record = invoke(&runtime, state, record).await;
        let mut event = crate::audit::Event::new(
            "ops.work_requirement",
            crate::audit::Kind::Ops,
            crate::audit::Severity::Low,
            "Automatic work requirement evaluated",
        );
        event.details = json!({"requester":actor.principal(),"room":room,"operation_id":operation,"requirement":record}).into();
        runtime
            .audit
            .emit(event)
            .map_err(|e| WorkError(503, format!("automatic check audit unavailable: {e}")))?;
        prepared.records.push(record);
    }
    let commit_root = root.to_owned();
    let commit_room = room.to_owned();
    let commit_operation = operation.map(str::to_owned);
    let principal = actor.principal();
    let remote = match actor {
        Actor::Remote(remote) => Some(remote.clone()),
        _ => None,
    };
    let result = tokio::task::spawn_blocking(move || {
            let actor = remote.as_ref().map_or_else(|| {
                if principal.kind == "operator" { Actor::Operator } else { Actor::Agent(&principal.id) }
            }, Actor::Remote);
            let mut conn = open(&commit_root)?;
            mutate_prepared(
                files(&runtime),
                &mut conn,
                &commit_room,
                actor,
                mutation,
                commit_operation.as_deref(),
                Some(&prepared),
            )
        }).await.map_err(|e| WorkError(503, format!("work commit result unavailable; recover the original operation ID before another attempt: {e}")))??;
    Ok(run_retained_obligations(state, root, result).await)
}

async fn run_retained_obligations(state: &RuntimeState, root: &Path, mut result: Value) -> Value {
    // The receipt already proves the transition. A later record failure must
    // describe partial completion rather than claim that transition failed.
    if let Some(id) = result["work"]["work_id"].as_str()
        && let Err(error) = drain(state, root, Some(id)).await
    {
        result["automatic_error"] = json!({"transition":"committed","error":error.to_string(),
            "recovery":"read the original operation receipt and current Work; recover its retained obligation before any new external effect"});
    }
    result
}

fn update(
    root: &Path,
    room_id: &str,
    work_id: &str,
    record: &Obligation,
    expected: State,
    authority: Option<(&RuntimeState, &Arc<Runtime>)>,
) -> Result<bool, WorkError> {
    let mut conn = open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut work = current(&tx, room_id, work_id)?;
    let Some(existing) = work.automatic.iter_mut().find(|r| r.id == record.id) else {
        return Ok(false);
    };
    if std::mem::discriminant(&existing.state) != std::mem::discriminant(&expected) {
        return Ok(false);
    }
    *existing = record.clone();
    work.version = work
        .version
        .checked_add(1)
        .ok_or_else(|| conflict("work version cannot advance"))?;
    work.updated_at = now();
    record_change(
        &tx,
        &work,
        Actor::Machine(&record.binding.name),
        &record.id,
        "automatic_result",
        None,
    )?;
    let active = authority
        .map(|(state, expected)| {
            let current = state
                .read()
                .map_err(|_| WorkError(503, "action authority unavailable".into()))?;
            if !Arc::ptr_eq(&current, expected) {
                return Err(conflict("action authority changed before dispatch"));
            }
            Ok(current)
        })
        .transpose()?;
    tx.commit()?;
    drop(active);
    Ok(true)
}

/// A bounded pass through retained native obligations. It neither invents work
/// nor retries dispatching effectful actions after a crash.
fn retained(root: &Path, work_id: Option<&str>) -> Result<Vec<Work>, WorkError> {
    let conn = open(root)?;
    let mut query = conn.prepare("SELECT document_json FROM coord_work WHERE (?1 IS NULL OR work_id=?1) AND json_array_length(json_extract(document_json,'$.automatic'))>0")?;
    query
        .query_map([work_id], |r| r.get::<_, String>(0))?
        .map(|r| Ok(serde_json::from_str::<Work>(&r?)?))
        .collect()
}

pub(crate) async fn drain(
    state: &RuntimeState,
    root: &Path,
    work_id: Option<&str>,
) -> Result<(), WorkError> {
    let works = retained(root, work_id)?;
    for work in works {
        for mut record in work.automatic {
            if !matches!(record.state, State::Pending) {
                continue;
            }
            let runtime = runtime(state)?;
            let adopted = runtime.policy.as_ref().is_some_and(|p| {
                p.work_authority_digest() == record.policy_hash
                    && p.named_checks()
                        .work_bindings
                        .iter()
                        .any(|b| json!(b) == json!(record.binding))
            });
            if !adopted {
                record.state = if record.binding.boundary == Boundary::AfterComplete {
                    State::Failed
                } else {
                    State::Unavailable
                };
                record.detail = "selected requirement or job authority changed before dispatch; inspect current policy".into();
                update(
                    root,
                    &work.room_id,
                    &work.work_id,
                    &record,
                    State::Pending,
                    None,
                )?;
                continue;
            }
            record.state = State::Dispatching;
            record.detail = "dispatch retained; completion has not been established".into();
            record.updated_at = now();
            if !update(
                root,
                &work.room_id,
                &work.work_id,
                &record,
                State::Pending,
                Some((state, &runtime)),
            )? {
                continue;
            }
            let mut result = invoke(&runtime, state, record).await;
            if state
                .read()
                .ok()
                .is_none_or(|current| !Arc::ptr_eq(&runtime, &current))
            {
                result.state = if result.binding.boundary == Boundary::AfterComplete {
                    State::Uncertain
                } else {
                    State::Unavailable
                };
                result.detail = "authority changed during execution; the result cannot authorize progression; inspect any external effect".into();
            }
            update(
                root,
                &work.room_id,
                &work.work_id,
                &result,
                State::Dispatching,
                None,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn recover(state: &RuntimeState) {
    let Ok(runtime) = runtime(state) else { return };
    let Some(root) = runtime.config.native_config_dir.clone() else {
        return;
    };
    let Ok(directory) = crate::coord_rooms::directory(&root) else {
        return;
    };
    if !directory.join("v0.db").is_file() {
        return;
    }
    // Freeze and reconcile the interrupted set before listeners admit new work.
    // The asynchronous dispatcher must never label a new live action interrupted.
    let recovered = (|| -> Result<(), WorkError> {
        for work in retained(&root, None)? {
            for mut record in work.automatic {
                if !matches!(record.state, State::Dispatching) {
                    continue;
                }
                if record.binding.boundary == Boundary::AfterComplete {
                    record.state = State::Uncertain;
                    record.detail = "proxy restarted after action dispatch was retained; inspect external authority using obligation_id; automatic retry is forbidden".into();
                } else {
                    record.state = State::Pending;
                    record.detail = "recovering interrupted passive verification".into();
                }
                record.updated_at = now();
                update(
                    &root,
                    &work.room_id,
                    &work.work_id,
                    &record,
                    State::Dispatching,
                    None,
                )?;
            }
        }
        Ok(())
    })();
    if let Err(error) = recovered {
        eprintln!("automatic work recovery unavailable: {error}");
        return;
    }
    let state = state.clone();
    runtime
        .check_tasks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .spawn(async move {
            if let Err(error) = drain(&state, &root, None).await {
                eprintln!("automatic work recovery unavailable: {error}");
            }
        });
}

pub(crate) fn requires_runtime(
    files: Option<(&Path, &Path)>,
    conn: &Connection,
    room: &str,
    mutation: &Mutation,
) -> Result<bool, WorkError> {
    let configuration = configuration(files, None)?;
    let input = serde_json::to_value(mutation)?;
    let room_id = authorize(conn, room, Actor::Operator, true)?;
    let work = current_work(conn, &room_id, &input)?;
    if input["action"] == "decide_acceptance"
        && input["verdict"] == "approve"
        && work.as_ref().is_some_and(|w| {
            w.automatic.iter().any(|r| {
                r.binding.boundary == Boundary::VerifyOutput && !matches!(r.state, State::Cancelled)
            })
        })
    {
        return Ok(true);
    }
    if !admission_bindings(&configuration, room, &input, work.as_ref()).is_empty() {
        return Ok(true);
    }
    Ok(work.as_ref().is_some_and(|work| {
        let factory = work.factory.as_ref().map(|f| f.reference.name.as_str());
        selected(&configuration, room).any(|b| {
            Some(b.factory.as_str()) == factory
                && matches!(
                    input["action"].as_str(),
                    Some("complete" | "publish_output" | "decide_acceptance")
                )
        })
    }))
}

pub(crate) fn resolve(
    work: &mut Work,
    actor: Actor<'_>,
    id: &str,
    outcome: State,
    summary: String,
    evidence_refs: Vec<String>,
    at: i64,
) -> Result<(), WorkError> {
    if !matches!(actor, Actor::Operator) {
        return Err(WorkError(
            403,
            "only the operator may reconcile an action at its external authority".into(),
        ));
    }
    if !matches!(outcome, State::Completed | State::Failed | State::Uncertain) {
        return Err(invalid(
            "action reconciliation outcome must be completed, failed or uncertain",
        ));
    }
    subjects::evidence(&summary, &evidence_refs)?;
    if evidence_refs.is_empty() {
        return Err(invalid(
            "action reconciliation requires the external observation reference",
        ));
    }
    let record = work
        .automatic
        .iter_mut()
        .find(|r| r.id == id && r.binding.boundary == Boundary::AfterComplete)
        .ok_or_else(|| invalid("follow-up action obligation not found"))?;
    record.state = outcome;
    record.detail = "operator reconciled the follow-up at its external authority; original transition remains committed".into();
    record.resolution = Some(
        json!({"author":actor.principal(),"summary":summary,"evidence_refs":evidence_refs,"observed_at":at}),
    );
    record.updated_at = at;
    Ok(())
}
