//! Named evidence and composition shared by preview and network enforcement.
//! Evidence files are selected by the operator, outside the assessed workload.
//! A finding never grants service or credential authority.

use super::{Policy, Result, invalid};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use tokio::io::AsyncReadExt;

pub fn content_digest(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Connect,
    Request,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Hostname,
    Ip,
    HttpPath,
    Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Subject {
    Hostname {
        hostname: String,
    },
    Ip {
        address: IpAddr,
    },
    HttpPath {
        hostname: String,
        port: u16,
        scheme: String,
        method: String,
        path: String,
    },
    Value {
        value: String,
    },
}

fn hostname(host: &str) -> Result<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let address = host.trim_matches(['[', ']']);
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    // The transport accepts IPv6 zone IDs. They select an interface, not a
    // different IP evidence subject; scope rules and path subjects use the IP.
    if let Some((ip, scope)) = address.split_once('%')
        && !scope.is_empty()
        && !scope.contains('%')
        && let Ok(ip) = ip.parse::<std::net::Ipv6Addr>()
    {
        return Ok(ip.to_string());
    }
    let encoded = crate::host_names::encode_idna2003(host)
        .map_err(|_| invalid("invalid check hostname"))?
        .to_ascii_lowercase();
    crate::host_names::decode_idna2003(encoded.as_bytes())
        .map_err(|_| invalid("invalid check hostname"))?;
    if encoded.len() > 255
        || !encoded.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(invalid("invalid check hostname"));
    }
    Ok(encoded)
}

impl Subject {
    pub fn normalized(&self) -> Result<Self> {
        Ok(match self {
            Self::Hostname { hostname: host } => Self::Hostname {
                hostname: hostname(host)?,
            },
            Self::Ip { .. } | Self::Value { .. } => self.clone(),
            Self::HttpPath {
                hostname: host,
                port,
                scheme,
                method,
                path,
            } => {
                if *port == 0
                    || !matches!(scheme.as_str(), "http" | "https")
                    || !path.starts_with('/')
                    || path.contains(['?', '#'])
                {
                    return Err(invalid(
                        "HTTP path evidence requires a visible path without query or fragment",
                    ));
                }
                Self::HttpPath {
                    hostname: hostname(host)?,
                    port: *port,
                    scheme: scheme.clone(),
                    method: method.to_ascii_uppercase(),
                    path: path.clone(),
                }
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResultType {
    Finding,
    Score,
    Timestamp,
    Fact,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScoreScale {
    pub name: String,
    pub minimum: f64,
    pub maximum: f64,
    pub direction: ScoreDirection,
    /// Provider-defined confidence meaning; no universal confidence scale.
    pub confidence_meaning: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreDirection {
    Higher,
    Lower,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Finding {
    Finding { positive: bool },
    Score { value: f64, confidence: Option<f64> },
    Timestamp { unix_ms: u64 },
    Fact { value: String },
    NoMatch,
    Unknown { reason: String },
    Unsupported { reason: String },
    Failure { reason: String },
}
impl Finding {
    fn result_type(&self) -> Option<ResultType> {
        match self {
            Self::Finding { .. } => Some(ResultType::Finding),
            Self::Score { .. } => Some(ResultType::Score),
            Self::Timestamp { .. } => Some(ResultType::Timestamp),
            Self::Fact { .. } => Some(ResultType::Fact),
            _ => None,
        }
    }
}

/// Source absence is represented by null on serialization, never invented.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_id: String,
    pub source_revision: Option<String>,
    pub content_digest: Option<String>,
    pub source_observed_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub subject: Subject,
    pub input_digest: String,
    pub implementation_version: String,
    pub configuration_version: String,
    /// Written by the trusted collection adapter, not the assessed caller.
    pub collected_at_ms: u64,
    pub valid_until_ms: Option<u64>,
    pub source: Provenance,
    pub finding: Finding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceSource {
    /// Captured host evidence. Preview never invokes an acquisition operation.
    Recorded { path: PathBuf },
    /// A producer not installed yet may be named only with explicit fallback.
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub source_id: String,
    pub meaning: String,
    pub subject: SubjectKind,
    pub result_type: ResultType,
    pub influences: Vec<Influence>,
    pub implementation_version: String,
    pub configuration_version: String,
    pub max_age_seconds: u64,
    pub max_source_age_seconds: Option<u64>,
    pub scale: Option<ScoreScale>,
    /// Policy-owned extra inputs, such as an expected GitHub issue author.
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
    pub source: EvidenceSource,
}
impl Check {
    pub fn input_digest(&self, subject: &Subject) -> Result<String> {
        let subject = subject.normalized()?;
        Ok(content_digest(
            &serde_json::to_vec(&json!({"subject":subject,"inputs":self.inputs}))
                .expect("check input JSON"),
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}
impl Comparison {
    fn matches_u64(self, value: u64, threshold: u64) -> bool {
        match self {
            Self::Lt => value < threshold,
            Self::Le => value <= threshold,
            Self::Eq => value == threshold,
            Self::Ge => value >= threshold,
            Self::Gt => value > threshold,
        }
    }

    fn matches(self, value: f64, threshold: f64) -> bool {
        match self {
            Self::Lt => value < threshold,
            Self::Le => value <= threshold,
            Self::Eq => value == threshold,
            Self::Ge => value >= threshold,
            Self::Gt => value > threshold,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Aggregation {
    Mean,
    Minimum,
    Maximum,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Finding {
        check: String,
    },
    Fact {
        check: String,
        equals: String,
    },
    Score {
        check: String,
        comparison: Comparison,
        threshold: f64,
    },
    /// Registration creation time stays a timestamp. Age uses decision time.
    Age {
        check: String,
        comparison: Comparison,
        seconds: u64,
    },
    Aggregate {
        checks: Vec<String>,
        method: Aggregation,
        comparison: Comparison,
        threshold: f64,
    },
    All {
        conditions: Vec<Condition>,
    },
    Any {
        conditions: Vec<Condition>,
    },
    Not {
        condition: Box<Condition>,
    },
}
impl Condition {
    fn names(&self, names: &mut BTreeSet<String>) {
        match self {
            Self::Finding { check }
            | Self::Fact { check, .. }
            | Self::Score { check, .. }
            | Self::Age { check, .. } => {
                names.insert(check.clone());
            }
            Self::Aggregate { checks, .. } => names.extend(checks.iter().cloned()),
            Self::All { conditions } | Self::Any { conditions } => {
                for condition in conditions {
                    condition.names(names);
                }
            }
            Self::Not { condition } => condition.names(names),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Influence {
    HardExclusion,
    Advisory,
    Exception,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Approval,
    Unresolved,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    Continue,
    Deny,
    Approval,
    Unresolved,
}
impl Fallback {
    fn action(self) -> Option<Action> {
        match self {
            Self::Continue => None,
            Self::Deny => Some(Action::Deny),
            Self::Approval => Some(Action::Approval),
            Self::Unresolved => Some(Action::Unresolved),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub host: String,
    pub agent: Option<String>,
    pub stage: Stage,
    pub influence: Influence,
    pub priority: i64,
    pub required: bool,
    pub when: Condition,
    pub on_match: Action,
    pub on_unavailable: Fallback,
    #[serde(default)]
    pub overrides: Vec<String>,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct Checks {
    pub checks: BTreeMap<String, Check>,
    #[serde(rename = "check_rules")]
    pub rules: Vec<Rule>,
}

/// Candidate targets are simulation inputs and grant no runtime authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub agent: Option<String>,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub method: String,
    pub path: Option<String>,
    pub ip: Option<IpAddr>,
    pub value: Option<String>,
}
impl Candidate {
    pub fn request(&self) -> Request<'_> {
        Request {
            agent: self.agent.as_deref(),
            host: &self.host,
            port: self.port,
            scheme: &self.scheme,
            method: &self.method,
            path: self.path.as_deref(),
            ip: self.ip,
            value: self.value.as_deref(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request<'a> {
    pub agent: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub scheme: &'a str,
    pub method: &'a str,
    pub path: Option<&'a str>,
    /// Actual connected endpoint, not a separately resolved DNS answer.
    pub ip: Option<IpAddr>,
    pub value: Option<&'a str>,
}
impl Request<'_> {
    fn subject(&self, kind: SubjectKind, stage: Stage) -> Result<Option<Subject>> {
        let host = hostname(self.host)?;
        Ok(match kind {
            SubjectKind::Hostname => host
                .parse::<IpAddr>()
                .is_err()
                .then_some(Subject::Hostname { hostname: host }),
            SubjectKind::Ip => self.ip.map(|address| Subject::Ip { address }),
            SubjectKind::HttpPath => self
                .path
                .filter(|_| stage == Stage::Request && !self.method.eq_ignore_ascii_case("CONNECT"))
                .map(|path| Subject::HttpPath {
                    hostname: host,
                    port: self.port,
                    scheme: self.scheme.into(),
                    method: self.method.to_ascii_uppercase(),
                    path: path.split('?').next().unwrap_or("/").into(),
                }),
            SubjectKind::Value => self.value.map(|value| Subject::Value {
                value: value.into(),
            }),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FileVersion {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}
impl FileVersion {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }
}

async fn read_evidence_file(path: &Path) -> std::io::Result<(Vec<u8>, FileVersion)> {
    let mut file = tokio::fs::File::open(path).await?;
    let before = FileVersion::from_metadata(&file.metadata().await?);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    let after = FileVersion::from_metadata(&file.metadata().await?);
    if before != after {
        return Err(std::io::Error::other(
            "evidence file changed during collection",
        ));
    }
    Ok((bytes, after))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evidence {
    pub check: String,
    pub source_id: String,
    pub meaning: String,
    pub scale: Option<ScoreScale>,
    pub subject: Option<Subject>,
    pub input_digest: Option<String>,
    pub acquisition: String,
    pub file_digest: Option<String>,
    pub file_version: Option<FileVersion>,
    pub result: Option<CheckResult>,
    pub unavailable: Option<String>,
    pub expires_at_ms: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Truth {
    True,
    False,
    Unavailable,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleExplanation {
    pub rule: String,
    pub condition: Condition,
    pub on_unavailable: Fallback,
    pub influence: Influence,
    pub priority: i64,
    pub truth: Truth,
    pub action: Option<Action>,
    pub overridden_by: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Evaluation {
    pub stage: Stage,
    pub decision_time_ms: u64,
    pub valid_until_ms: Option<u64>,
    pub action: Action,
    pub rules: Vec<RuleExplanation>,
    pub evidence: BTreeMap<String, Evidence>,
}

impl Checks {
    pub(super) fn parse(
        document: &serde_json::Map<String, Value>,
        base: Option<&Path>,
    ) -> Result<Self> {
        let mut checks: Self = serde_json::from_value(json!({
            "checks": document.get("checks").cloned().unwrap_or_else(|| json!({})),
            "check_rules": document.get("check_rules").cloned().unwrap_or_else(|| json!([])),
        }))
        .map_err(|error| invalid(format!("named checks: {error}")))?;
        for (name, check) in &mut checks.checks {
            if check.meaning.is_empty()
                || check.source_id.is_empty()
                || name.is_empty()
                || check.implementation_version.is_empty()
                || check.configuration_version.is_empty()
                || check.max_age_seconds == 0
            {
                return Err(invalid(
                    "named checks require names, versions and a positive maximum age",
                ));
            }
            if check.result_type == ResultType::Score {
                let scale = check.scale.as_ref().ok_or_else(|| {
                    invalid(
                        "score checks require a declared scale, direction and confidence meaning",
                    )
                })?;
                if scale.name.is_empty()
                    || scale.confidence_meaning.is_empty()
                    || !scale.minimum.is_finite()
                    || !scale.maximum.is_finite()
                    || scale.minimum >= scale.maximum
                {
                    return Err(invalid("invalid check score scale"));
                }
            } else if check.scale.is_some() {
                return Err(invalid("only score checks have a score scale"));
            }
            if let EvidenceSource::Recorded { path } = &mut check.source
                && path.is_relative()
            {
                *path = base.unwrap_or(Path::new(".")).join(&path);
            }
        }
        for rule in &mut checks.rules {
            if rule.host != "*" {
                rule.host = if let Some(suffix) = rule.host.strip_prefix("*.") {
                    format!("*.{}", hostname(suffix)?)
                } else {
                    hostname(&rule.host)?
                };
            }
        }
        let mut names = BTreeSet::new();
        for rule in &checks.rules {
            if rule.name.is_empty() || rule.host.is_empty() || !names.insert(rule.name.clone()) {
                return Err(invalid(
                    "check rules require distinct names and an explicit host scope",
                ));
            }
            if rule.influence == Influence::HardExclusion
                && (rule.on_match != Action::Deny || !rule.overrides.is_empty())
            {
                return Err(invalid(
                    "hard exclusions must deny and cannot override another rule",
                ));
            }
            if rule.influence != Influence::Exception && !rule.overrides.is_empty() {
                return Err(invalid(
                    "only scoped exceptions may override advisory rules",
                ));
            }
            if rule.influence == Influence::Exception
                && (rule.overrides.is_empty() || rule.on_match != Action::Allow)
            {
                return Err(invalid(
                    "exceptions require named advisory overrides and on_match = 'allow'",
                ));
            }
            checks.validate_condition(&rule.when)?;
            let mut used = BTreeSet::new();
            rule.when.names(&mut used);
            for name in used {
                let check = &checks.checks[&name];
                if !check.influences.contains(&rule.influence) {
                    return Err(invalid(format!(
                        "check {name} does not permit this rule's influence"
                    )));
                }
                let supported = check.subject != SubjectKind::Value
                    && (rule.stage != Stage::Connect || check.subject != SubjectKind::HttpPath)
                    && !matches!(check.source, EvidenceSource::Unavailable { .. });
                if rule.required && !supported {
                    return Err(invalid(format!(
                        "required check {name} is unsupported at {:?}",
                        rule.stage
                    )));
                }
            }
        }
        for rule in &checks.rules {
            for name in &rule.overrides {
                if !checks.rules.iter().any(|target| {
                    target.name == *name
                        && target.influence == Influence::Advisory
                        && target.stage == rule.stage
                }) {
                    return Err(invalid(
                        "an exception must name an advisory rule at the same stage",
                    ));
                }
            }
        }
        Ok(checks)
    }

    fn validate_condition(&self, condition: &Condition) -> Result<()> {
        let expected = match condition {
            Condition::Finding { check } => Some((check, ResultType::Finding)),
            Condition::Fact { check, .. } => Some((check, ResultType::Fact)),
            Condition::Age { check, seconds, .. } => {
                if *seconds > u64::MAX / 1000 {
                    return Err(invalid("age threshold overflows milliseconds"));
                }
                Some((check, ResultType::Timestamp))
            }
            Condition::Score {
                check, threshold, ..
            } => {
                if !threshold.is_finite() {
                    return Err(invalid("score threshold must be finite"));
                }
                Some((check, ResultType::Score))
            }
            Condition::Aggregate {
                checks, threshold, ..
            } => {
                if checks.is_empty() || !threshold.is_finite() {
                    return Err(invalid(
                        "aggregation requires checks and a finite threshold",
                    ));
                }
                let mut scale = None;
                for name in checks {
                    let definition = self
                        .checks
                        .get(name)
                        .ok_or_else(|| invalid(format!("unknown check {name}")))?;
                    if definition.result_type != ResultType::Score
                        || scale
                            .as_ref()
                            .is_some_and(|old| Some(old) != definition.scale.as_ref())
                    {
                        return Err(invalid(
                            "aggregation requires compatible declared score scales",
                        ));
                    }
                    scale = definition.scale.clone();
                }
                None
            }
            Condition::All { conditions } | Condition::Any { conditions } => {
                if conditions.is_empty() {
                    return Err(invalid("boolean composition must not be empty"));
                }
                for child in conditions {
                    self.validate_condition(child)?;
                }
                None
            }
            Condition::Not { condition } => {
                self.validate_condition(condition)?;
                None
            }
        };
        if let Some((name, expected)) = expected {
            let definition = self
                .checks
                .get(name)
                .ok_or_else(|| invalid(format!("unknown check {name}")))?;
            if definition.result_type != expected {
                return Err(invalid(format!(
                    "check {name} has an incompatible result type"
                )));
            }
        }
        Ok(())
    }

    fn applicable<'a>(
        &'a self,
        request: &'a Request<'_>,
        stage: Stage,
    ) -> impl Iterator<Item = &'a Rule> {
        let host = hostname(request.host).ok();
        self.rules.iter().filter(move |rule| {
            rule.stage == stage
                && host
                    .as_ref()
                    // If scope cannot be determined, retain the rules and
                    // let unavailable evidence select their explicit fallback.
                    .is_none_or(|host| rule.host == "*" || super::host_matches(host, &rule.host))
                && rule
                    .agent
                    .as_ref()
                    .is_none_or(|agent| super::glob(request.agent.unwrap_or(""), agent))
        })
    }

    pub fn applies(&self, request: &Request<'_>, stage: Stage) -> bool {
        self.applicable(request, stage).next().is_some()
    }

    /// File reads happen without the runtime/policy lock. Fresh file snapshots
    /// also avoid a second cache with different authority/expiry semantics.
    pub async fn collect(
        &self,
        request: &Request<'_>,
        stage: Stage,
    ) -> Result<BTreeMap<String, Evidence>> {
        let mut names = BTreeSet::new();
        for rule in self.applicable(request, stage) {
            rule.when.names(&mut names);
        }
        let mut evidence = BTreeMap::new();
        for name in names {
            let check = &self.checks[&name];
            // Normalization failure is unavailable evidence, not permission
            // to skip a required rule or its configured fallback.
            let subject = request.subject(check.subject, stage).unwrap_or(None);
            let input_digest = subject
                .as_ref()
                .map(|subject| check.input_digest(subject))
                .transpose()?;
            let mut entry = Evidence {
                check: name.clone(),
                source_id: check.source_id.clone(),
                meaning: check.meaning.clone(),
                scale: check.scale.clone(),
                subject: subject.clone(),
                input_digest: input_digest.clone(),
                acquisition: "recorded_offline".into(),
                file_digest: None,
                file_version: None,
                result: None,
                unavailable: None,
                expires_at_ms: None,
            };
            if let (Some(subject), Some(input_digest)) = (subject, input_digest) {
                match &check.source {
                    EvidenceSource::Unavailable { reason } => {
                        entry.unavailable = Some(format!("unsupported: {reason}"))
                    }
                    EvidenceSource::Recorded { path } => match read_evidence_file(path).await {
                        Err(_) => entry.unavailable = Some("evidence file unavailable".into()),
                        Ok((bytes, version)) => {
                            entry.file_version = Some(version);
                            entry.file_digest = Some(content_digest(&bytes));
                            match serde_json::from_slice::<Vec<CheckResult>>(&bytes) {
                                Err(_) => {
                                    entry.unavailable = Some("malformed evidence file".into())
                                }
                                Ok(records) => {
                                    let mut matches = records.into_iter().filter(|record| {
                                        record.subject == subject
                                            && record.source.source_id == check.source_id
                                            && record.input_digest == input_digest
                                            && record.implementation_version
                                                == check.implementation_version
                                            && record.configuration_version
                                                == check.configuration_version
                                    });
                                    entry.result = matches.next();
                                    if matches.next().is_some() {
                                        entry.result = None;
                                        entry.unavailable = Some(
                                            "ambiguous evidence for subject/input/version".into(),
                                        );
                                    } else if entry.result.is_none() {
                                        entry.unavailable =
                                            Some("missing subject/input/version coverage".into());
                                    }
                                }
                            }
                        }
                    },
                }
            } else {
                entry.unavailable =
                    Some("subject unavailable at this enforcement stage or route".into());
            }
            evidence.insert(name, entry);
        }
        Ok(evidence)
    }

    /// Available file versions are checked after collection, before admission.
    /// Atomic replacement or an in-place change cancels this observation.
    pub async fn versions_current(&self, evidence: &BTreeMap<String, Evidence>) -> bool {
        for (name, entry) in evidence {
            if let Some(expected) = &entry.file_version {
                let Some(Check {
                    source: EvidenceSource::Recorded { path },
                    ..
                }) = self.checks.get(name)
                else {
                    return false;
                };
                match tokio::fs::metadata(path).await {
                    Ok(metadata) if FileVersion::from_metadata(&metadata) == *expected => {}
                    _ => return false,
                }
            }
        }
        true
    }

    /// Evaluate at the actual decision time, including captured timestamp ages.
    pub fn evaluate(
        &self,
        request: &Request<'_>,
        stage: Stage,
        mut evidence: BTreeMap<String, Evidence>,
        now_ms: u64,
    ) -> Evaluation {
        for (name, entry) in &mut evidence {
            let Some(check) = self.checks.get(name) else {
                entry.unavailable = Some("unknown check".into());
                continue;
            };
            match request.subject(check.subject, stage) {
                Ok(Some(subject))
                    if entry.subject.as_ref() == Some(&subject)
                        && check.input_digest(&subject).ok().as_ref()
                            == entry.input_digest.as_ref() => {}
                _ => {
                    entry.unavailable =
                        Some("evidence does not bind this request's subject/input".into());
                    continue;
                }
            }
            validate_evidence(check, entry, now_ms);
        }
        let mut rules: Vec<_> = self
            .applicable(request, stage)
            .map(|rule| {
                let truth = condition_truth(&rule.when, &evidence, now_ms);
                let action = match truth {
                    Truth::True => Some(rule.on_match),
                    Truth::False => None,
                    Truth::Unavailable => rule.on_unavailable.action(),
                };
                RuleExplanation {
                    rule: rule.name.clone(),
                    condition: rule.when.clone(),
                    on_unavailable: rule.on_unavailable,
                    influence: rule.influence,
                    priority: rule.priority,
                    truth,
                    action,
                    overridden_by: None,
                }
            })
            .collect();
        for rule in self
            .applicable(request, stage)
            .filter(|rule| rule.influence == Influence::Exception)
        {
            if rules
                .iter()
                .any(|result| result.rule == rule.name && result.truth == Truth::True)
            {
                for result in &mut rules {
                    if result.influence == Influence::Advisory
                        && rule.overrides.contains(&result.rule)
                    {
                        result.overridden_by = Some(rule.name.clone());
                    }
                }
            }
        }
        let hard = rules
            .iter()
            .filter(|rule| rule.influence == Influence::HardExclusion)
            .filter_map(|rule| rule.action)
            .max_by_key(|action| severity(*action));
        let action = hard.unwrap_or_else(|| {
            rules
                .iter()
                .filter(|rule| {
                    (rule.influence == Influence::Advisory
                        || (rule.influence == Influence::Exception
                            && rule.truth == Truth::Unavailable))
                        && rule.overridden_by.is_none()
                })
                .filter_map(|rule| {
                    rule.action
                        .map(|action| ((rule.priority, severity(action)), action))
                })
                .max_by_key(|(key, _)| *key)
                .map(|(_, action)| action)
                .unwrap_or(Action::Allow)
        });
        let valid_until_ms = evidence
            .values()
            .filter_map(|entry| entry.expires_at_ms)
            .chain(
                self.applicable(request, stage)
                    .filter_map(|rule| next_age_transition(&rule.when, &evidence, now_ms)),
            )
            .min();
        Evaluation {
            stage,
            decision_time_ms: now_ms,
            valid_until_ms,
            action,
            rules,
            evidence,
        }
    }
}

fn severity(action: Action) -> u8 {
    match action {
        Action::Allow => 0,
        Action::Approval => 1,
        Action::Unresolved => 2,
        Action::Deny => 3,
    }
}

fn validate_evidence(check: &Check, entry: &mut Evidence, now: u64) {
    let Some(record) = entry.result.as_ref() else {
        return;
    };
    let expires = record
        .collected_at_ms
        .saturating_add(check.max_age_seconds.saturating_mul(1000));
    let mut expires = record
        .valid_until_ms
        .map_or(expires, |until| until.min(expires));
    if let Some(age) = check.max_source_age_seconds {
        expires = expires.min(
            record
                .source
                .source_observed_at_ms
                .unwrap_or(record.collected_at_ms)
                .saturating_add(age.saturating_mul(1000)),
        );
    }
    let future_fact = match record.finding {
        Finding::Timestamp { unix_ms } if unix_ms > now => Some(unix_ms),
        _ => None,
    };
    let next_observation = [
        Some(expires),
        Some(record.collected_at_ms).filter(|time| *time > now),
        record
            .source
            .source_observed_at_ms
            .filter(|time| *time > now),
        future_fact,
    ]
    .into_iter()
    .flatten()
    .min();
    entry.expires_at_ms = next_observation;
    let problem = if record.subject.normalized().ok().as_ref() != Some(&record.subject)
        || entry.subject.as_ref() != Some(&record.subject)
        || entry.input_digest.as_ref() != Some(&record.input_digest)
        || record.implementation_version != check.implementation_version
        || record.configuration_version != check.configuration_version
        || record.source.source_id != check.source_id
    {
        Some("evidence binding mismatch")
    } else if record.collected_at_ms > now
        || record
            .source
            .source_observed_at_ms
            .is_some_and(|time| time > now)
    {
        Some("future evidence time")
    } else if now >= expires {
        Some("stale evidence")
    } else if record
        .finding
        .result_type()
        .is_some_and(|kind| kind != check.result_type)
    {
        Some("incompatible evidence result type")
    } else {
        match &record.finding {
            Finding::Score { value, confidence }
                if !value.is_finite()
                    || confidence.is_some_and(|value| !value.is_finite())
                    || check
                        .scale
                        .as_ref()
                        .is_none_or(|scale| *value < scale.minimum || *value > scale.maximum) =>
            {
                Some("score outside its declared scale")
            }
            Finding::Timestamp { unix_ms } if *unix_ms > now => Some("future fact timestamp"),
            Finding::NoMatch => Some("no match does not establish positive safety"),
            Finding::Unknown { .. } => Some("unknown evidence"),
            Finding::Unsupported { .. } => Some("unsupported evidence"),
            Finding::Failure { .. } => Some("check execution failed"),
            _ => None,
        }
    };
    if let Some(problem) = problem {
        entry.unavailable = Some(problem.into());
    }
}

fn condition_truth(
    condition: &Condition,
    evidence: &BTreeMap<String, Evidence>,
    now: u64,
) -> Truth {
    let finding = |name: &str| {
        evidence
            .get(name)
            .filter(|entry| entry.unavailable.is_none())
            .and_then(|entry| entry.result.as_ref())
            .map(|record| &record.finding)
    };
    let truth = |value: bool| if value { Truth::True } else { Truth::False };
    match condition {
        Condition::Finding { check } => match finding(check) {
            Some(Finding::Finding { positive }) => truth(*positive),
            _ => Truth::Unavailable,
        },
        Condition::Fact { check, equals } => match finding(check) {
            Some(Finding::Fact { value }) => truth(value == equals),
            _ => Truth::Unavailable,
        },
        Condition::Score {
            check,
            comparison,
            threshold,
        } => match finding(check) {
            Some(Finding::Score { value, .. }) => truth(comparison.matches(*value, *threshold)),
            _ => Truth::Unavailable,
        },
        Condition::Age {
            check,
            comparison,
            seconds,
        } => match finding(check) {
            Some(Finding::Timestamp { unix_ms }) => truth(
                comparison.matches_u64(now.saturating_sub(*unix_ms), seconds.saturating_mul(1000)),
            ),
            _ => Truth::Unavailable,
        },
        Condition::Aggregate {
            checks,
            method,
            comparison,
            threshold,
        } => {
            let values: Option<Vec<f64>> = checks
                .iter()
                .map(|check| match finding(check) {
                    Some(Finding::Score { value, .. }) => Some(*value),
                    _ => None,
                })
                .collect();
            match values {
                None => Truth::Unavailable,
                Some(values) => {
                    let value = match method {
                        Aggregation::Mean => {
                            values.iter().map(|value| value / values.len() as f64).sum()
                        }
                        Aggregation::Minimum => {
                            values.iter().copied().fold(f64::INFINITY, f64::min)
                        }
                        Aggregation::Maximum => {
                            values.iter().copied().fold(f64::NEG_INFINITY, f64::max)
                        }
                    };
                    if value.is_finite() {
                        truth(comparison.matches(value, *threshold))
                    } else {
                        Truth::Unavailable
                    }
                }
            }
        }
        Condition::Not { condition } => match condition_truth(condition, evidence, now) {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            Truth::Unavailable => Truth::Unavailable,
        },
        Condition::All { conditions } | Condition::Any { conditions } => {
            let all = matches!(condition, Condition::All { .. });
            let mut unknown = false;
            for child in conditions {
                match condition_truth(child, evidence, now) {
                    Truth::Unavailable => unknown = true,
                    Truth::False if all => return Truth::False,
                    Truth::True if !all => return Truth::True,
                    _ => {}
                }
            }
            if unknown {
                Truth::Unavailable
            } else {
                truth(all)
            }
        }
    }
}

fn next_age_transition(
    condition: &Condition,
    evidence: &BTreeMap<String, Evidence>,
    now: u64,
) -> Option<u64> {
    match condition {
        Condition::Age {
            check,
            comparison,
            seconds,
        } => {
            let Finding::Timestamp { unix_ms } = evidence.get(check)?.result.as_ref()?.finding
            else {
                return None;
            };
            let boundary = unix_ms.checked_add(seconds.checked_mul(1000)?)?;
            [
                Some(boundary),
                matches!(comparison, Comparison::Le | Comparison::Gt | Comparison::Eq)
                    .then(|| boundary.saturating_add(1)),
            ]
            .into_iter()
            .flatten()
            .filter(|time| *time > now)
            .min()
        }
        Condition::All { conditions } | Condition::Any { conditions } => conditions
            .iter()
            .filter_map(|child| next_age_transition(child, evidence, now))
            .min(),
        Condition::Not { condition } => next_age_transition(condition, evidence, now),
        _ => None,
    }
}

impl Policy {
    pub fn named_checks(&self) -> &Checks {
        &self.checks
    }
    /// Offline preview has no destination connector, provider operation or live
    /// budget owner. It uses exactly the enforcement composition function.
    pub async fn evaluate_candidate(&self, request: &Request<'_>, now_ms: u64) -> Result<Value> {
        let controls = self.native_controls();
        let options = crate::network_guard::Options {
            enabled: controls.is_none_or(|controls| controls.network.enabled),
            block: controls.is_none_or(|controls| {
                matches!(controls.network.action, super::native::Action::Block)
            }),
            homoglyph: controls.is_none_or(|controls| controls.network.homoglyph),
        };
        let base = crate::network_guard::NetworkGuard::new()
            .enforce(
                crate::network_guard::Pdp::Preview(self),
                crate::network_guard::Request {
                    identity: request.agent.map_or(
                        crate::network_guard::Identity::Unavailable,
                        crate::network_guard::Identity::Resolved,
                    ),
                    host: request.host,
                    decode_ace_for_inspection: true,
                    port: request.port,
                    method: request.method,
                    path: request.path.unwrap_or(""),
                    scheme: request.scheme,
                    request_id: None,
                    connection_id: "offline-candidate",
                    prior_response: false,
                },
                options,
                now_ms as f64,
            )
            .map_err(|_| invalid("candidate network policy evaluation failed"))?;
        let mut stages = Vec::new();
        for stage in [Stage::Connect, Stage::Request] {
            let mut evidence = self.checks.collect(request, stage).await?;
            if !self.checks.versions_current(&evidence).await {
                for entry in evidence.values_mut() {
                    entry.unavailable =
                        Some("evidence version changed during candidate evaluation".into());
                }
            }
            stages.push(self.checks.evaluate(request, stage, evidence, now_ms));
        }
        let checks = stages
            .iter()
            .map(|stage| stage.action)
            .max_by_key(|action| severity(*action))
            .unwrap_or(Action::Allow);
        let network = if base.kind != crate::network_guard::OutcomeKind::Blocked {
            Action::Allow
        } else if base.pdp.as_ref().is_some_and(|decision| {
            decision.effect == crate::network_guard::PdpEffect::RequireApproval
        }) {
            Action::Approval
        } else {
            Action::Deny
        };
        let action = [network, checks]
            .into_iter()
            .max_by_key(|action| severity(*action))
            .unwrap();
        Ok(
            json!({"action":action,"network_policy":base.pdp,"network_guard_outcome":base.kind,"stages":stages,"evidence_mode":"recorded_offline","destination_contact":false,"dependency_calls":[],"live_budgets_consumed":false,"authority":"network checks only; independent credential and service controls still apply"}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_000_000;
    fn request() -> Request<'static> {
        Request {
            agent: Some("alice"),
            host: "example.test",
            port: 443,
            scheme: "https",
            method: "GET",
            path: Some("/report?secret=redacted"),
            ip: Some("192.0.2.7".parse().unwrap()),
            value: None,
        }
    }
    fn definition(kind: ResultType) -> Value {
        json!({"source_id":"test-source","meaning":"controlled test finding or fact","subject":"hostname","result_type":kind,"influences":["hard_exclusion","advisory","exception"],"implementation_version":"collector-1","configuration_version":"config-1","max_age_seconds":60,"source":{"kind":"recorded","path":"evidence.json"},"scale":if kind==ResultType::Score {json!({"name":"provider-a","minimum":0,"maximum":100,"direction":"higher","confidence_meaning":"provider supplied confidence, not a risk score"})}else{Value::Null}})
    }
    fn rule(name: &str, influence: Influence, when: Value, action: Action) -> Value {
        json!({"name":name,"host":"*","stage":"connect","influence":influence,"priority":0,"required":true,"when":when,"on_match":action,"on_unavailable":"unresolved","overrides":[]})
    }
    fn parse(checks: Value, rules: Vec<Value>) -> Result<Checks> {
        Checks::parse(
            json!({"checks":checks,"check_rules":rules})
                .as_object()
                .unwrap(),
            None,
        )
    }
    fn evidence(checks: &Checks, findings: Vec<(&str, Finding)>) -> BTreeMap<String, Evidence> {
        findings
            .into_iter()
            .map(|(name, finding)| {
                let check = &checks.checks[name];
                let subject = request()
                    .subject(check.subject, Stage::Connect)
                    .unwrap()
                    .unwrap();
                let input_digest = check.input_digest(&subject).unwrap();
                let result = CheckResult {
                    subject: subject.clone(),
                    input_digest: input_digest.clone(),
                    implementation_version: check.implementation_version.clone(),
                    configuration_version: check.configuration_version.clone(),
                    collected_at_ms: NOW,
                    valid_until_ms: None,
                    source: Provenance {
                        source_id: check.source_id.clone(),
                        source_revision: None,
                        content_digest: None,
                        source_observed_at_ms: None,
                    },
                    finding,
                };
                (
                    name.into(),
                    Evidence {
                        check: name.into(),
                        source_id: check.source_id.clone(),
                        meaning: check.meaning.clone(),
                        scale: check.scale.clone(),
                        subject: Some(subject),
                        input_digest: Some(input_digest),
                        acquisition: "recorded_offline".into(),
                        file_digest: None,
                        file_version: None,
                        result: Some(result),
                        unavailable: None,
                        expires_at_ms: None,
                    },
                )
            })
            .collect()
    }
    fn finding(name: &str) -> Value {
        json!({"op":"finding","check":name})
    }

    #[tokio::test]
    async fn scoped_ipv6_keeps_required_checks_and_normalization_failure_uses_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let mut ip = definition(ResultType::Finding);
        ip["subject"] = json!("ip");
        let mut exclusion = rule(
            "never",
            Influence::HardExclusion,
            finding("ip"),
            Action::Deny,
        );
        exclusion["host"] = json!("[::1%0]");
        let mut check = parse(json!({"ip":ip}), vec![exclusion]).unwrap();
        let file = directory.path().join("ip.json");
        check.checks.get_mut("ip").unwrap().source =
            EvidenceSource::Recorded { path: file.clone() };
        let subject = Subject::Ip {
            address: "::1".parse().unwrap(),
        };
        let definition = &check.checks["ip"];
        let record = CheckResult {
            input_digest: definition.input_digest(&subject).unwrap(),
            subject: subject.clone(),
            implementation_version: definition.implementation_version.clone(),
            configuration_version: definition.configuration_version.clone(),
            collected_at_ms: NOW,
            valid_until_ms: None,
            source: Provenance {
                source_id: definition.source_id.clone(),
                source_revision: None,
                content_digest: None,
                source_observed_at_ms: None,
            },
            finding: Finding::Finding { positive: true },
        };
        std::fs::write(&file, serde_json::to_vec(&vec![record]).unwrap()).unwrap();
        for host in ["::1", "::1%0", "0:0:0:0:0:0:0:1%250", "[::1%lo]"] {
            let request = Request {
                host,
                ip: Some("::1".parse().unwrap()),
                ..request()
            };
            assert!(check.applies(&request, Stage::Connect), "{host}");
            assert_eq!(
                request
                    .subject(SubjectKind::Hostname, Stage::Connect)
                    .unwrap(),
                None
            );
            assert_eq!(
                request.subject(SubjectKind::Ip, Stage::Connect).unwrap(),
                Some(subject.clone())
            );
            let path = request
                .subject(SubjectKind::HttpPath, Stage::Request)
                .unwrap()
                .unwrap();
            assert!(matches!(path, Subject::HttpPath { hostname, .. } if hostname == "::1"));
            let evidence = check.collect(&request, Stage::Connect).await.unwrap();
            let evaluation = check.evaluate(&request, Stage::Connect, evidence, NOW);
            assert_eq!(evaluation.action, Action::Deny, "{host}");
            assert_eq!(evaluation.rules[0].truth, Truth::True, "{host}");
        }
        let invalid = Request {
            host: "bad%host",
            ..request()
        };
        assert!(check.applies(&invalid, Stage::Connect));
        let evidence = check.collect(&invalid, Stage::Connect).await.unwrap();
        let evaluation = check.evaluate(&invalid, Stage::Connect, evidence, NOW);
        assert_eq!(evaluation.action, Action::Unresolved);
        assert_eq!(evaluation.rules[0].truth, Truth::Unavailable);
    }

    #[test]
    fn validation_rejects_unknown_types_scales_stages_and_influence() {
        let checks =
            json!({"list":definition(ResultType::Finding),"score":definition(ResultType::Score)});
        for condition in [
            finding("missing"),
            json!({"op":"score","check":"list","comparison":"gt","threshold":10}),
            json!({"op":"all","conditions":[]}),
        ] {
            assert!(
                parse(
                    checks.clone(),
                    vec![rule("r", Influence::HardExclusion, condition, Action::Deny)]
                )
                .is_err()
            );
        }
        let mut bad = definition(ResultType::Score);
        bad["scale"]["name"] = json!("incompatible");
        assert!(parse(json!({"a":definition(ResultType::Score),"b":bad}),vec![rule("r",Influence::Advisory,json!({"op":"aggregate","checks":["a","b"],"method":"mean","comparison":"ge","threshold":50}),Action::Deny)]).is_err());
        for subject in ["http_path", "value", "full_url", "query", "tls", "opaque"] {
            let mut check = definition(ResultType::Finding);
            check["subject"] = json!(subject);
            assert!(
                parse(
                    json!({"a":check}),
                    vec![rule(
                        "r",
                        Influence::HardExclusion,
                        finding("a"),
                        Action::Deny
                    )]
                )
                .is_err(),
                "{subject}"
            );
        }
        let mut check = definition(ResultType::Finding);
        check["influences"] = json!(["advisory"]);
        assert!(
            parse(
                json!({"a":check}),
                vec![rule(
                    "r",
                    Influence::HardExclusion,
                    finding("a"),
                    Action::Deny
                )]
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn hard_exclusion_dominates_host_agent_and_positive_advisory_allows() {
        let directory = tempfile::tempdir().unwrap();
        let mut good = definition(ResultType::Finding);
        good["source_id"] = json!("favorable-provider");
        good["meaning"] = json!("positive is favorable advisory evidence");
        let checks = json!({"list":definition(ResultType::Finding),"good":good});
        let rules = vec![
            rule(
                "never",
                Influence::HardExclusion,
                finding("list"),
                Action::Deny,
            ),
            rule("good", Influence::Advisory, finding("good"), Action::Allow),
        ];
        let set = parse(checks.clone(), rules.clone()).unwrap();
        let records = evidence(
            &set,
            vec![
                ("list", Finding::Finding { positive: true }),
                ("good", Finding::Finding { positive: true }),
            ],
        );
        let file = directory.path().join("results.json");
        std::fs::write(
            &file,
            serde_json::to_vec(
                &records
                    .values()
                    .map(|entry| entry.result.as_ref().unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut checks = checks;
        for check in checks.as_object_mut().unwrap().values_mut() {
            check["source"]["path"] = json!(file);
        }
        let policy=Policy::parse(&json!({"hosts":{"*":{"egress":"allow"}},"agents":{"alice":{"hosts":{"example.test":{"egress":"allow"}}}},"checks":checks,"check_rules":rules}).to_string(),super::super::Format::Json).unwrap();
        let preview = policy.evaluate_candidate(&request(), NOW).await.unwrap();
        assert_eq!(preview["action"], "deny");
        assert_eq!(preview["network_policy"]["effect"], "allow");
        assert_eq!(preview["stages"][0]["rules"][0]["rule"], "never");
        assert_eq!(preview["destination_contact"], false);
        assert_eq!(preview["live_budgets_consumed"], false);
    }

    #[test]
    fn scoped_exception_only_overrides_its_named_advisory_rule() {
        let mut exception = rule(
            "exception",
            Influence::Exception,
            finding("good"),
            Action::Allow,
        );
        exception["overrides"] = json!(["advice"]);
        exception["host"] = json!("example.test");
        exception["agent"] = json!("alice");
        let checks = parse(
            json!({"list":definition(ResultType::Finding),"good":definition(ResultType::Finding)}),
            vec![
                rule("advice", Influence::Advisory, finding("list"), Action::Deny),
                exception,
            ],
        )
        .unwrap();
        let records = evidence(
            &checks,
            vec![
                ("list", Finding::Finding { positive: true }),
                ("good", Finding::Finding { positive: true }),
            ],
        );
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records.clone(), NOW)
                .action,
            Action::Allow
        );
        assert_eq!(
            checks
                .evaluate(
                    &Request {
                        agent: Some("bob"),
                        ..request()
                    },
                    Stage::Connect,
                    records,
                    NOW
                )
                .action,
            Action::Deny
        );
    }

    #[test]
    fn thresholds_aggregation_boolean_precedence_and_advisory_priority() {
        let condition = json!({"op":"all","conditions":[{"op":"aggregate","checks":["a","b"],"method":"mean","comparison":"ge","threshold":50},{"op":"not","condition":{"op":"finding","check":"flag"}}]});
        let checks=parse(json!({"a":definition(ResultType::Score),"b":definition(ResultType::Score),"flag":definition(ResultType::Finding)}),vec![rule("r",Influence::Advisory,condition,Action::Approval)]).unwrap();
        let records = evidence(
            &checks,
            vec![
                (
                    "a",
                    Finding::Score {
                        value: 40.,
                        confidence: None,
                    },
                ),
                (
                    "b",
                    Finding::Score {
                        value: 60.,
                        confidence: Some(0.7),
                    },
                ),
                ("flag", Finding::Finding { positive: false }),
            ],
        );
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records.clone(), NOW)
                .action,
            Action::Approval
        );
        let mut lower = records;
        lower.get_mut("b").unwrap().result.as_mut().unwrap().finding = Finding::Score {
            value: 59.,
            confidence: None,
        };
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, lower, NOW)
                .action,
            Action::Allow
        );
        let mut high = rule("high", Influence::Advisory, finding("flag"), Action::Allow);
        high["priority"] = json!(1);
        let checks = parse(
            json!({"flag":definition(ResultType::Finding)}),
            vec![
                rule("low", Influence::Advisory, finding("flag"), Action::Deny),
                high,
            ],
        )
        .unwrap();
        let records = evidence(&checks, vec![("flag", Finding::Finding { positive: true })]);
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records, NOW)
                .action,
            Action::Allow
        );
    }

    #[test]
    fn no_match_missing_stale_and_failure_never_become_positive_under_negation() {
        let checks = parse(
            json!({"a":definition(ResultType::Finding)}),
            vec![rule(
                "r",
                Influence::Advisory,
                json!({"op":"not","condition":finding("a")}),
                Action::Allow,
            )],
        )
        .unwrap();
        for finding in [
            Finding::NoMatch,
            Finding::Unknown {
                reason: "missing coverage".into(),
            },
            Finding::Unsupported {
                reason: "opaque".into(),
            },
            Finding::Failure {
                reason: "timeout".into(),
            },
        ] {
            let result = checks.evaluate(
                &request(),
                Stage::Connect,
                evidence(&checks, vec![("a", finding)]),
                NOW,
            );
            assert_eq!(result.action, Action::Unresolved);
            assert_eq!(result.rules[0].truth, Truth::Unavailable);
        }
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, BTreeMap::new(), NOW)
                .action,
            Action::Unresolved
        );
        let records = evidence(&checks, vec![("a", Finding::Finding { positive: false })]);
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records.clone(), NOW + 59_999)
                .action,
            Action::Allow
        );
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records, NOW + 60_000)
                .action,
            Action::Unresolved
        );
    }

    #[test]
    fn subject_input_version_type_source_time_and_validity_are_bound() {
        let checks = parse(
            json!({"a":definition(ResultType::Finding)}),
            vec![rule(
                "r",
                Influence::HardExclusion,
                finding("a"),
                Action::Deny,
            )],
        )
        .unwrap();
        for mutation in 0..8 {
            let mut records = evidence(&checks, vec![("a", Finding::Finding { positive: false })]);
            let record = records.get_mut("a").unwrap().result.as_mut().unwrap();
            match mutation {
                0 => {
                    record.subject = Subject::Hostname {
                        hostname: "different.test".into(),
                    }
                }
                1 => record.input_digest = "wrong".into(),
                2 => record.implementation_version = "wrong".into(),
                3 => record.configuration_version = "wrong".into(),
                4 => {
                    record.finding = Finding::Fact {
                        value: "PASS".into(),
                    }
                }
                5 => record.collected_at_ms = NOW + 1,
                6 => record.source.source_observed_at_ms = Some(NOW + 1),
                _ => record.valid_until_ms = Some(NOW),
            }
            assert_eq!(
                checks
                    .evaluate(&request(), Stage::Connect, records, NOW)
                    .action,
                Action::Unresolved,
                "mutation{mutation}"
            );
        }
        let mut check = definition(ResultType::Finding);
        check["max_source_age_seconds"] = json!(5);
        let checks = parse(
            json!({"a":check}),
            vec![rule(
                "r",
                Influence::HardExclusion,
                finding("a"),
                Action::Deny,
            )],
        )
        .unwrap();
        let mut records = evidence(&checks, vec![("a", Finding::Finding { positive: false })]);
        records
            .get_mut("a")
            .unwrap()
            .result
            .as_mut()
            .unwrap()
            .source
            .source_observed_at_ms = Some(NOW - 5_000);
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records, NOW)
                .action,
            Action::Unresolved,
            "retrieval does not refresh old source evidence"
        );
    }

    #[test]
    fn registration_age_uses_decision_time_and_expires_at_the_transition() {
        let checks = parse(
            json!({"created":definition(ResultType::Timestamp)}),
            vec![rule(
                "young",
                Influence::Advisory,
                json!({"op":"age","check":"created","comparison":"lt","seconds":30}),
                Action::Deny,
            )],
        )
        .unwrap();
        let records = evidence(
            &checks,
            vec![(
                "created",
                Finding::Timestamp {
                    unix_ms: NOW - 29_000,
                },
            )],
        );
        let before = checks.evaluate(&request(), Stage::Connect, records.clone(), NOW + 999);
        assert_eq!(before.action, Action::Deny);
        assert_eq!(before.valid_until_ms, Some(NOW + 1000));
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records.clone(), NOW + 1000)
                .action,
            Action::Allow
        );
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, records, NOW + 1001)
                .action,
            Action::Allow
        );
    }

    #[tokio::test]
    async fn direct_ip_opaque_and_unsupported_stage_use_the_selected_fallback() {
        let mut host_rule = rule(
            "hostname",
            Influence::HardExclusion,
            finding("host"),
            Action::Deny,
        );
        host_rule["on_unavailable"] = json!("approval");
        let checks = parse(
            json!({"host":definition(ResultType::Finding)}),
            vec![host_rule],
        )
        .unwrap();
        let direct = Request {
            host: "192.0.2.7",
            ..request()
        };
        let gathered = checks.collect(&direct, Stage::Connect).await.unwrap();
        assert_eq!(
            checks
                .evaluate(&direct, Stage::Connect, gathered, NOW)
                .action,
            Action::Approval
        );

        let mut path_check = definition(ResultType::Finding);
        path_check["subject"] = json!("http_path");
        let mut path_rule = rule(
            "path",
            Influence::HardExclusion,
            finding("path"),
            Action::Deny,
        );
        path_rule["stage"] = json!("request");
        path_rule["on_unavailable"] = json!("deny");
        let checks = parse(json!({"path":path_check.clone()}), vec![path_rule.clone()]).unwrap();
        let opaque = Request {
            method: "CONNECT",
            path: None,
            ..request()
        };
        let gathered = checks.collect(&opaque, Stage::Request).await.unwrap();
        let result = checks.evaluate(&opaque, Stage::Request, gathered, NOW);
        assert_eq!(result.action, Action::Deny);
        assert_eq!(result.rules[0].truth, Truth::Unavailable);

        path_rule["stage"] = json!("connect");
        path_rule["required"] = json!(false);
        let checks = parse(json!({"path":path_check}), vec![path_rule]).unwrap();
        let gathered = checks.collect(&request(), Stage::Connect).await.unwrap();
        assert!(
            gathered["path"].subject.is_none(),
            "preview cannot see an HTTP path at connect time"
        );
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, gathered, NOW)
                .action,
            Action::Deny
        );
    }

    #[test]
    fn unavailable_boolean_inputs_follow_three_valued_logic() {
        let checks = parse(
            json!({"a":definition(ResultType::Finding),"b":definition(ResultType::Finding)}),
            vec![],
        )
        .unwrap();
        for (positive, operator, expected) in [
            (false, "all", Truth::False),
            (true, "all", Truth::Unavailable),
            (false, "any", Truth::Unavailable),
            (true, "any", Truth::True),
        ] {
            let records = evidence(&checks, vec![("a", Finding::Finding { positive })]);
            let condition: Condition = serde_json::from_value(
                json!({"op":operator,"conditions":[finding("a"),finding("b")]}),
            )
            .unwrap();
            assert_eq!(condition_truth(&condition, &records, NOW), expected);
        }
    }

    #[tokio::test]
    async fn recorded_replacement_and_missing_versions_are_observed_without_result_cache() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.json");
        let mut check = definition(ResultType::Finding);
        check["source"]["path"] = json!(path);
        let checks = parse(
            json!({"a":check}),
            vec![rule(
                "r",
                Influence::HardExclusion,
                finding("a"),
                Action::Deny,
            )],
        )
        .unwrap();
        for positive in [true, false] {
            let records = evidence(&checks, vec![("a", Finding::Finding { positive })]);
            std::fs::write(
                &path,
                serde_json::to_vec(&vec![records["a"].result.as_ref().unwrap()]).unwrap(),
            )
            .unwrap();
            let gathered = checks.collect(&request(), Stage::Connect).await.unwrap();
            assert_eq!(
                checks
                    .evaluate(&request(), Stage::Connect, gathered, NOW)
                    .action,
                if positive {
                    Action::Deny
                } else {
                    Action::Allow
                }
            );
        }
        std::fs::write(&path, b"not provider evidence").unwrap();
        let gathered = checks.collect(&request(), Stage::Connect).await.unwrap();
        assert_eq!(
            checks
                .evaluate(&request(), Stage::Connect, gathered, NOW)
                .action,
            Action::Unresolved
        );
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;
    #[tokio::test]
    async fn reusable_fixture_preserves_allow_deny_unknown_and_expiry() {
        let file =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/named_checks/policy.toml");
        let policy = Policy::from_native_path(&file).unwrap();
        let mut candidate: Candidate = serde_json::from_str(include_str!(
            "../../tests/fixtures/named_checks/request.json"
        ))
        .unwrap();
        for (host, at, action) in [
            ("report.example.test", 1_000_000, "allow"),
            ("malware.example.test", 1_000_000, "deny"),
            ("missing.example.test", 1_000_000, "unresolved"),
            ("report.example.test", 1_060_000, "unresolved"),
        ] {
            candidate.host = host.into();
            let result = policy
                .evaluate_candidate(&candidate.request(), at)
                .await
                .unwrap();
            assert_eq!(result["action"], action, "{host} at {at}: {result}");
        }
        let saved = Policy::read_native_candidate(&file).unwrap();
        let document = super::super::parse_toml_document(&saved).unwrap();
        assert_eq!(
            document["checks"]["threat"]["source"]["path"],
            json!(file.parent().unwrap().join("evidence.json"))
        );
    }

    #[tokio::test]
    async fn preview_uses_native_warn_and_bypass_and_never_charges_network_budget() {
        for (control, outcome) in [
            ("enabled = false", "bypassed"),
            ("action = 'warn'", "warned"),
        ] {
            let source = format!(
                "[hosts.'*']\negress='deny'\n[controls.network]\nhomoglyph=false\n{control}\n"
            );
            let policy =
                Policy::native_source(&source, Path::new("/owned/policy.toml"), None, 1_000_000.)
                    .unwrap();
            let candidate = Candidate {
                agent: Some("alice".into()),
                host: "example.test".into(),
                port: 443,
                scheme: "https".into(),
                method: "GET".into(),
                path: Some("/".into()),
                ip: None,
                value: None,
            };
            let result = policy
                .evaluate_candidate(&candidate.request(), 1_000_000)
                .await
                .unwrap();
            assert_eq!(result["action"], "allow");
            assert_eq!(result["network_guard_outcome"], outcome);
        }
        let policy = Policy::native_source(
            "[hosts.'*']\negress='allow'\nrate=10\n",
            Path::new("/owned/policy.toml"),
            None,
            1_000_000.,
        )
        .unwrap();
        let before = policy.budget_stats(1_000_000.).unwrap();
        let candidate = Candidate {
            agent: Some("alice".into()),
            host: "example.test".into(),
            port: 443,
            scheme: "https".into(),
            method: "GET".into(),
            path: Some("/".into()),
            ip: None,
            value: None,
        };
        for _ in 0..5 {
            assert_eq!(
                policy
                    .evaluate_candidate(&candidate.request(), 1_000_000)
                    .await
                    .unwrap()["action"],
                "allow"
            );
        }
        assert_eq!(policy.budget_stats(1_000_000.).unwrap(), before);
    }
}

#[cfg(test)]
mod composition_edge_tests {
    use super::*;
    #[test]
    fn non_finite_aggregate_cannot_assert_a_positive_condition() {
        let mut checks = serde_json::Map::new();
        for name in ["a", "b", "c"] {
            checks.insert(name.into(),json!({"source_id":name,"meaning":"a provider score","subject":"hostname","result_type":"score","influences":["advisory"],"implementation_version":"1","configuration_version":"1","max_age_seconds":10,"source":{"kind":"recorded","path":"unused.json"},"scale":{"name":"declared finite quantity","minimum":-f64::MAX,"maximum":f64::MAX,"direction":"higher","confidence_meaning":"unavailable"}}));
        }
        let set=Checks::parse(json!({"checks":checks,"check_rules":[{"name":"aggregate","host":"*","stage":"connect","influence":"advisory","priority":0,"required":true,"when":{"op":"aggregate","checks":["a","b","c"],"method":"mean","comparison":"gt","threshold":f64::MAX},"on_match":"allow","on_unavailable":"unresolved"}]}).as_object().unwrap(),None).unwrap();
        let subject = Subject::Hostname {
            hostname: "example.test".into(),
        };
        let mut evidence = BTreeMap::new();
        for (name, check) in &set.checks {
            let input_digest = check.input_digest(&subject).unwrap();
            evidence.insert(
                name.clone(),
                Evidence {
                    check: name.clone(),
                    source_id: check.source_id.clone(),
                    meaning: check.meaning.clone(),
                    scale: check.scale.clone(),
                    subject: Some(subject.clone()),
                    input_digest: Some(input_digest.clone()),
                    acquisition: "recorded_offline".into(),
                    file_digest: None,
                    file_version: None,
                    result: Some(CheckResult {
                        subject: subject.clone(),
                        input_digest,
                        implementation_version: "1".into(),
                        configuration_version: "1".into(),
                        collected_at_ms: 1000,
                        valid_until_ms: None,
                        source: Provenance {
                            source_id: check.source_id.clone(),
                            source_revision: None,
                            content_digest: None,
                            source_observed_at_ms: None,
                        },
                        finding: Finding::Score {
                            value: f64::MAX,
                            confidence: None,
                        },
                    }),
                    unavailable: None,
                    expires_at_ms: None,
                },
            );
        }
        let request = Request {
            agent: Some("alice"),
            host: "example.test",
            port: 443,
            scheme: "https",
            method: "GET",
            path: Some("/"),
            ip: None,
            value: None,
        };
        assert_eq!(
            set.evaluate(&request, Stage::Connect, evidence, 1000)
                .action,
            Action::Unresolved
        );
    }
}
