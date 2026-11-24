//! Bounded questions and isolated findings before missing-route escalation.
use super::*;
use crate::{Runtime, RuntimeState, approvals::pending};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub field: String,
    pub question: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Positive {
    Deny,
    Question(Question),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    Question(Question),
    Check {
        check: String,
        on_positive: Positive,
    },
    TaskAction {
        check: String,
        on_concern: Positive,
        on_unavailable: Positive,
        max_attempts: u32,
        disclose_rationale: bool,
    },
}

impl Step {
    pub(crate) fn check_name(&self) -> Option<&str> {
        match self {
            Self::Check { check, .. } | Self::TaskAction { check, .. } => Some(check),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub agents: Vec<String>,
    pub service: String,
    pub capability: String,
    pub methods: Vec<String>,
    pub path: String,
    pub steps: Vec<Step>,
    /// Immutable content identity is included in every request/check subject.
    pub revision: String,
    /// Each activation has a new host-owned generation, including rollback.
    #[serde(default)]
    pub generation: u64,
}

fn question_valid(q: &Question, fields: &mut BTreeSet<String>) -> Result<()> {
    if q.field.is_empty()
        || q.field.len() > 120
        || q.question.trim().is_empty()
        || q.question.len() > pending::context::MAX_FIELD_BYTES
        || !fields.insert(q.field.clone())
    {
        return Err(invalid(
            "challenge questions need unique fields and bounded explanatory text",
        ));
    }
    Ok(())
}

pub(super) fn validate(checks: &Checks) -> Result<()> {
    for challenge in checks.route_challenges.values() {
        if challenge.agents.is_empty()
            || challenge.agents.iter().any(String::is_empty)
            || challenge.service.is_empty()
            || challenge.capability.is_empty()
            || challenge.methods.is_empty()
            || challenge.path.is_empty()
            || challenge.revision.is_empty()
            || challenge.steps.is_empty()
        {
            return Err(invalid(
                "route challenges need explicit selectors, revision and steps",
            ));
        }
        let mut fields = BTreeSet::new();
        for step in &challenge.steps {
            match step {
                Step::Question(q) => question_valid(q, &mut fields)?,
                Step::Check { check, on_positive } => {
                    let definition = checks
                        .checks
                        .get(check)
                        .ok_or_else(|| invalid("unknown challenge check"))?;
                    if definition.subject != SubjectKind::Value
                        || definition.result_type != ResultType::Finding
                        || !matches!(
                            definition.source,
                            EvidenceSource::Job { .. } | EvidenceSource::Service { .. }
                        )
                    {
                        return Err(invalid(
                            "challenge checks need adopted job/service findings over a host-bound value",
                        ));
                    }
                    if let Positive::Question(q) = on_positive {
                        question_valid(q, &mut fields)?;
                    }
                }
                Step::TaskAction {
                    check,
                    on_concern,
                    on_unavailable,
                    max_attempts,
                    ..
                } => {
                    let definition = checks
                        .checks
                        .get(check)
                        .ok_or_else(|| invalid("unknown task/action check"))?;
                    if definition.subject != SubjectKind::Value
                        || definition.result_type != ResultType::TaskAction
                        || !matches!(
                            &definition.source,
                            EvidenceSource::Job {
                                spec_sha256: Some(_),
                                ..
                            }
                        )
                        || *max_attempts == 0
                        || [
                            "service",
                            "endpoint",
                            "model",
                            "model_revision",
                            "input_revision",
                            "prompt_revision",
                        ]
                        .iter()
                        .any(|name| definition.inputs.get(*name).is_none_or(String::is_empty))
                    {
                        return Err(invalid(
                            "task/action steps need a pinned job, typed result, adopted model/input revisions and positive attempts",
                        ));
                    }
                    for outcome in [on_concern, on_unavailable] {
                        if let Positive::Question(q) = outcome {
                            question_valid(q, &mut fields)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

impl Challenge {
    pub(crate) fn applies(&self, action: &Value) -> bool {
        self.agents
            .iter()
            .any(|a| *a == action["agent"] || a == "*")
            && super::super::glob(action["service"].as_str().unwrap_or(""), &self.service)
            && super::super::glob(
                action["capability"].as_str().unwrap_or(""),
                &self.capability,
            )
            && self
                .methods
                .iter()
                .any(|m| *m == action["method"] || m == "*")
            && super::super::glob(action["path"].as_str().unwrap_or(""), &self.path)
    }
}

/// Bind the selected definitions as well as their immutable update revisions.
pub(crate) fn binding(policy: &Policy, action: &Value) -> Value {
    let checks = policy.named_checks();
    let selected = checks
        .route_challenges
        .iter()
        .filter(|(_, c)| c.applies(action))
        .map(|(name, c)| (name.clone(), c.clone()))
        .collect::<BTreeMap<_, _>>();
    let definitions = selected
        .values()
        .flat_map(|c| &c.steps)
        .filter_map(|s| {
            s.check_name()
                .map(|check| (check.to_owned(), checks.checks.get(check)))
        })
        .collect::<BTreeMap<_, _>>();
    let specifications = definitions
        .iter()
        .filter_map(|(name, definition)| {
            let definition = definition.as_ref()?;
            if let EvidenceSource::Job { spec, limits, .. } = &definition.source {
                let bytes = std::fs::File::open(spec).ok().and_then(|file| {
                    use std::io::Read;
                    let mut bytes = Vec::new();
                    file.take(limits.max_input_bytes.saturating_add(1) as u64)
                        .read_to_end(&mut bytes)
                        .ok()?;
                    (bytes.len() <= limits.max_input_bytes).then_some(bytes)
                });
                Some((name.clone(), bytes.map(|bytes| content_digest(&bytes))))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>();
    // The request needs identity bindings, not disclosure of host-selected
    // check inputs, endpoints or specification paths to the requesting agent.
    let definitions = definitions
        .iter()
        .map(|(name, check)| {
            (
                name,
                content_digest(&serde_json::to_vec(check).expect("serializable adopted check")),
            )
        })
        .collect::<BTreeMap<_, _>>();
    json!({"challenges":selected,"checks":definitions,"specifications":specifications})
}

pub(crate) fn current(policy: &Policy, action: &Value) -> bool {
    action["control_update"] == binding(policy, action)
}

pub(crate) fn evidence_current(policy: &Policy, record: &pending::Record) -> bool {
    let checks = policy.named_checks();
    for (name, challenge) in checks
        .route_challenges
        .iter()
        .filter(|(_, c)| c.applies(&record.authority.action))
    {
        for step in &challenge.steps {
            if let Some(check) = step.check_name() {
                let Some(definition) = checks.checks.get(check) else {
                    return false;
                };
                let Ok(mut entry) =
                    serde_json::from_value::<Evidence>(record.result["evidence"][check].clone())
                else {
                    return false;
                };
                if let Step::TaskAction {
                    disclose_rationale,
                    on_concern,
                    ..
                } = step
                {
                    let answers = record
                        .untrusted_reason_text
                        .as_ref()
                        .and_then(|text| serde_json::from_str::<Value>(text).ok())
                        .and_then(|value| {
                            serde_json::from_value::<BTreeMap<String, String>>(
                                value["answers"].clone(),
                            )
                            .ok()
                        })
                        .unwrap_or_default();
                    let key = task_action::budget_key(
                        &record.authority.action,
                        definition,
                        &challenge.revision,
                    );
                    let context = task_action::reconsideration_context(record, check, &key, true);
                    let expected = task_action::subject(
                        &record.authority.action,
                        &record.authority_digest,
                        definition,
                        name,
                        &challenge.revision,
                        &answers,
                        *disclose_rationale,
                    )
                    .and_then(|subject| task_action::reconsideration(subject, &context));
                    let acceptable = match entry.result.as_ref().map(|r| &r.finding) {
                        Some(Finding::TaskAction { assessment }) => match assessment.concern() {
                            Some(false) => true,
                            Some(true) => {
                                matches!(on_concern, Positive::Question(q) if answers.get(&q.field).is_some_and(|a| !a.trim().is_empty() && a.len() <= 2048))
                            }
                            None => false,
                        },
                        _ => false,
                    };
                    if expected.ok().as_ref() != entry.subject.as_ref() || !acceptable {
                        return false;
                    }
                }
                validate_evidence(
                    definition,
                    &mut entry,
                    crate::policy::current_time_ms() as u64,
                );
                if entry.unavailable.is_some() {
                    return false;
                }
            }
        }
    }
    true
}

pub(crate) struct Assessment {
    pub ready: bool,
    pub denied: bool,
    pub view: Value,
    pub evidence: BTreeMap<String, Evidence>,
}

/// Execute in authored order. Questions and findings remain untrusted context
/// and never create permission; normal approval/current-policy checks follow.
pub(crate) async fn assess(
    authority_digest: &str,
    action: &Value,
    answers: &BTreeMap<String, String>,
    runtime: &Runtime,
    state: &RuntimeState,
) -> std::result::Result<Assessment, crate::Error> {
    let policy = runtime
        .policy
        .as_ref()
        .ok_or("challenge policy unavailable")?;
    if !current(policy, action) {
        return Err("challenge requirements changed; obtain a new challenge".into());
    }
    let mut evidence = BTreeMap::new();
    let mut outcomes = Vec::new();
    let mut ready = true;
    let mut denied = false;
    'challenge: for (name, challenge) in &policy.named_checks().route_challenges {
        if !challenge.applies(action) {
            continue;
        }
        for step in &challenge.steps {
            let required = match step {
                Step::Question(q) => Some(q),
                Step::TaskAction {
                    check,
                    on_concern,
                    on_unavailable,
                    max_attempts,
                    disclose_rationale,
                } => {
                    let definition = &policy.named_checks().checks[check];
                    let subject = task_action::subject(
                        action,
                        authority_digest,
                        definition,
                        name,
                        &challenge.revision,
                        answers,
                        *disclose_rationale,
                    );
                    let key = task_action::budget_key(action, definition, &challenge.revision);
                    let mut iteration = None;
                    let result = if !runtime.audit.approvals().reserve_task_action_attempt(
                        authority_digest,
                        &key,
                        *max_attempts,
                    )? {
                        Err("adopted task/action attempt limit reached or canonical challenge unavailable".into())
                    } else {
                        let record = runtime
                            .audit
                            .approvals()
                            .list()?
                            .into_iter()
                            .find(|r| {
                                r.authority_digest == authority_digest && r.status == "challenged"
                            })
                            .ok_or("canonical task/action challenge changed")?;
                        let context =
                            task_action::reconsideration_context(&record, check, &key, false);
                        let subject = subject
                            .and_then(|subject| task_action::reconsideration(subject, &context));
                        iteration = Some((record.approval_id, context));
                        match subject {
                            Ok(subject) => {
                                policy
                                    .named_checks()
                                    .invoke_challenge(check, subject, runtime, state)
                                    .await
                            }
                            Err(error) => Err(error),
                        }
                    };
                    let (mut concern, mut view) = match result {
                        Ok(entry) => {
                            let concern = if entry.unavailable.is_none() {
                                entry.result.as_ref().and_then(|r| match &r.finding {
                                    Finding::TaskAction { assessment } => assessment.concern(),
                                    _ => None,
                                })
                            } else {
                                None
                            };
                            let view = json!({"check":check,"input_digest":entry.input_digest,
                                "finding":entry.result.as_ref().map(|r|&r.finding),"unavailable":entry.unavailable});
                            evidence.insert(check.clone(), entry);
                            (concern, view)
                        }
                        Err(error) => {
                            (None, json!({"check":check,"unavailable":error.to_string()}))
                        }
                    };
                    // Retain attempts/refusals with the canonical approval, including
                    // failed reconsideration. Agent answers cannot overwrite them.
                    let mut stale = iteration.is_some();
                    if let Some(record) = runtime.audit.approvals().list()?.into_iter().find(|r| {
                        r.authority_digest == authority_digest && r.status == "challenged"
                    }) {
                        runtime
                            .audit
                            .approvals()
                            .decide(&record.approval_id, |record| {
                                stale = iteration.as_ref().is_some_and(|(id,context)| *id != record.approval_id
                                    || *context != task_action::reconsideration_context(record, check, &key, false));
                                if record.status != "challenged" { stale = true; return Ok(()); }
                                if stale { concern = None; view["unavailable"] = json!("reconsideration history changed while the model was pending"); }
                                if !record.result.is_object() {
                                    record.result = json!({});
                                }
                                if !record.result["task_action_findings"].is_object() {
                                    record.result["task_action_findings"] = json!({});
                                }
                                if !record.result["task_action_findings"][check].is_array() {
                                    record.result["task_action_findings"][check] = json!([]);
                                }
                                record.result["task_action_findings"][check].as_array_mut().unwrap().push(json!({
                                    "input_digest":view["input_digest"],"result_digest":content_digest(view.to_string().as_bytes()),
                                    "concern":concern,"unavailable":!view["unavailable"].is_null(),
                                    "relevance":view["finding"]["assessment"]["relevance"],
                                    "proportionality":view["finding"]["assessment"]["proportionality"]}));
                                Ok(())
                            })?;
                    }
                    if stale {
                        concern = None;
                        view["unavailable"] =
                            json!("reconsideration history changed while the model was pending");
                        if let Some(entry) = evidence.get_mut(check) {
                            entry.unavailable = Some(
                                "reconsideration history changed while the model was pending"
                                    .into(),
                            );
                        }
                    }
                    outcomes.push(view);
                    let explained_concern = concern == Some(true)
                        && matches!(on_concern, Positive::Question(q)
                        if answers.get(&q.field).is_some_and(|a| !a.trim().is_empty() && a.len() <= 2048));
                    if explained_concern {
                        outcomes.push(json!({"check":check,"status":"requires_operator_decision",
                            "finding_remains":"concern","explanation_trust":"agent supplied; grants no authority"}));
                    }
                    if concern == Some(false) || explained_concern {
                        None
                    } else {
                        ready = false;
                        let response = if concern == Some(true) {
                            on_concern
                        } else {
                            on_unavailable
                        };
                        match response {
                            Positive::Deny => { denied = true; outcomes.push(json!({"check":check,"status":"denied"})); },
                            Positive::Question(q) => outcomes.push(json!({"check":check,"field":q.field,"question":q.question,
                                "status":"challenged","supplied":answers.contains_key(&q.field),
                                "next_action":"Provide relevant evidence or propose a narrower action. Missing evidence cannot satisfy escalation; a continuing concern remains visible to the operator."})),
                        }
                        break 'challenge;
                    }
                }
                Step::Check { check, on_positive } => {
                    // Trusted action and effect identities are generated by the
                    // owner. Only the explicitly labelled answers are agent data.
                    let subject = Subject::Value {
                        value: serde_json::to_string(&json!({
                            "authority_digest":authority_digest,"action":action,
                            "challenge":name,"revision":challenge.revision,"untrusted_answers":answers
                        }))?,
                    };
                    let result = policy
                        .named_checks()
                        .invoke_challenge(check, subject, runtime, state)
                        .await;
                    let positive = match result {
                        Ok(entry) => {
                            let finding = if entry.unavailable.is_none() {
                                entry.result.as_ref().and_then(|r| match r.finding {
                                    Finding::Finding { positive } => Some(positive),
                                    _ => None,
                                })
                            } else {
                                None
                            };
                            outcomes.push(json!({"check":check,"evidence":entry}));
                            evidence.insert(check.clone(), entry);
                            finding
                        }
                        Err(error) => {
                            outcomes.push(json!({"check":check,"unavailable":error.to_string()}));
                            None
                        }
                    };
                    match positive {
                        None => {
                            ready = false;
                            break 'challenge;
                        }
                        Some(false) => None,
                        Some(true) => match on_positive {
                            Positive::Deny => {
                                outcomes.push(json!({"check":check,"status":"denied"}));
                                ready = false;
                                break 'challenge;
                            }
                            Positive::Question(q) => Some(q),
                        },
                    }
                }
            };
            if let Some(q) = required {
                let supplied = answers.get(&q.field).is_some_and(|a| {
                    !a.trim().is_empty() && a.len() <= pending::context::MAX_FIELD_BYTES
                });
                outcomes.push(json!({"field":q.field,"question":q.question,"supplied":supplied}));
                if !supplied {
                    ready = false;
                    break 'challenge;
                }
            }
        }
    }
    Ok(Assessment {
        ready,
        denied,
        view: json!({"ready_for_escalation":ready,"steps":outcomes,"binding":action["control_update"]}),
        evidence,
    })
}
