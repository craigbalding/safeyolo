//! Concrete automatic Coord requirements use the named-check result contract.
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    AdmitIssue,
    VerifyOutput,
    AfterComplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Input {
    GithubIssue,
    PublishedArtifact,
    CompletedWork,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Hold,
    Report,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Retry {
    Never,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub name: String,
    pub room: String,
    pub factory: String,
    pub boundary: Boundary,
    pub job: String,
    pub input: Input,
    pub on_failure: Failure,
    pub require: Option<Condition>,
    pub repository: Option<String>,
    pub retry: Option<Retry>,
}

pub(super) fn validate(checks: &Checks) -> Result<()> {
    let mut names = BTreeSet::new();
    for binding in &checks.work_bindings {
        if binding.name.is_empty()
            || binding.room.is_empty()
            || binding.factory.is_empty()
            || !names.insert(&binding.name)
        {
            return Err(invalid(
                "work bindings require distinct names, a room and a factory",
            ));
        }
        let check = checks
            .checks
            .get(&binding.job)
            .ok_or_else(|| invalid("work binding names an unknown adopted job"))?;
        let effects = match &check.source {
            EvidenceSource::Job { effects, .. } => effects,
            EvidenceSource::Service { operation, .. } => &operation.effects,
            _ => {
                return Err(invalid(
                    "automatic work bindings require an executable job or service",
                ));
            }
        };
        if check.subject != SubjectKind::Value {
            return Err(invalid("work binding jobs require a value subject"));
        }
        let expected_input = match binding.boundary {
            Boundary::AdmitIssue => Input::GithubIssue,
            Boundary::VerifyOutput => Input::PublishedArtifact,
            Boundary::AfterComplete => Input::CompletedWork,
        };
        if binding.input != expected_input {
            return Err(invalid("unsupported work binding input mapping"));
        }
        if binding.boundary == Boundary::AfterComplete {
            if binding.require.is_some()
                || binding.repository.is_some()
                || binding.on_failure != Failure::Report
                || binding.retry != Some(Retry::Never)
            {
                return Err(invalid(
                    "after_complete is an action: require on_failure=report and retry=never; no predicate",
                ));
            }
            continue;
        }
        if !matches!(effects, execution::Effects::Passive) {
            return Err(invalid(
                "required checks must declare passive effects; adopt effects as an explicit after_complete action",
            ));
        }
        if binding.retry.is_some() || binding.on_failure != Failure::Hold {
            return Err(invalid(
                "before and verification bindings require on_failure=hold",
            ));
        }
        let condition = binding
            .require
            .as_ref()
            .ok_or_else(|| invalid("a required check must name its qualifying predicate"))?;
        checks.validate_condition(condition)?;
        let mut used = BTreeSet::new();
        condition.names(&mut used);
        if used != BTreeSet::from([binding.job.clone()]) {
            return Err(invalid(
                "a work binding predicate must use only its adopted job",
            ));
        }
        if binding.boundary == Boundary::AdmitIssue {
            let repository = binding
                .repository
                .as_deref()
                .ok_or_else(|| invalid("issue admission requires an explicit GitHub repository"))?;
            let url = format!("https://github.com/{repository}/issues/1");
            if check.inputs.get("repository").map(String::as_str) != Some(repository) {
                return Err(invalid(
                    "issue admission repository must match the adopted job's repository input",
                ));
            }
            crate::coord_rooms::work::github::Reference::parse(&url)
                .map_err(|_| invalid("invalid issue admission repository"))?;
        } else if binding.repository.is_some() {
            return Err(invalid(
                "repository selection is supported only for issue admission",
            ));
        }
    }
    Ok(())
}

impl Checks {
    /// The boundary supplies the subject. Callers cannot submit authoritative evidence.
    pub(crate) fn work_truth(
        &self,
        binding: &Binding,
        subject: &Subject,
        mut evidence: Evidence,
        at: u64,
    ) -> Truth {
        let Some(check) = self.checks.get(&binding.job) else {
            return Truth::Unavailable;
        };
        if evidence.subject.as_ref() != Some(subject)
            || evidence.input_digest.as_ref() != check.input_digest(subject).ok().as_ref()
        {
            return Truth::Unavailable;
        }
        validate_evidence(check, &mut evidence, at);
        binding
            .require
            .as_ref()
            .map_or(Truth::Unavailable, |condition| {
                condition_truth(
                    condition,
                    &BTreeMap::from([(binding.job.clone(), evidence)]),
                    at,
                )
            })
    }
}

impl Policy {
    /// Full adopted authority identity, separate from the legacy summary hash.
    pub(crate) fn work_authority_digest(&self) -> String {
        #[derive(Serialize)]
        struct Authority<'a> {
            authored: Option<&'a Value>,
            checks: &'a Checks,
        }
        let authority = Authority {
            authored: self.native.as_ref().map(|n| &n.authored),
            checks: self.named_checks(),
        };
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&authority).expect("adopted work authority JSON"),
        );
        content_digest(&bytes)
    }

    pub(crate) fn work_service_definitions_digest(&self) -> String {
        let registry = self.gateway().and_then(|g| g.registry());
        let definitions: BTreeMap<&str, &Value> = registry
            .as_ref()
            .map(|r| {
                r.services
                    .iter()
                    .map(|(name, definition)| (name.as_str(), &definition.raw))
                    .collect()
            })
            .unwrap_or_default();
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&definitions).expect("work service definitions JSON"),
        );
        content_digest(&bytes)
    }
}
