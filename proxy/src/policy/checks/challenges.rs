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
        .filter_map(|s| match s {
            Step::Check { check, .. } => Some((check.clone(), checks.checks.get(check))),
            _ => None,
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
    for challenge in checks
        .route_challenges
        .values()
        .filter(|c| c.applies(&record.authority.action))
    {
        for step in &challenge.steps {
            if let Step::Check { check, .. } = step {
                let Some(definition) = checks.checks.get(check) else {
                    return false;
                };
                let Ok(mut entry) =
                    serde_json::from_value::<Evidence>(record.result["evidence"][check].clone())
                else {
                    return false;
                };
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
    'challenge: for (name, challenge) in &policy.named_checks().route_challenges {
        if !challenge.applies(action) {
            continue;
        }
        for step in &challenge.steps {
            let required = match step {
                Step::Question(q) => Some(q),
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
        view: json!({"ready_for_escalation":ready,"steps":outcomes,"binding":action["control_update"]}),
        evidence,
    })
}
