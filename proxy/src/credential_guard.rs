//! Native HTTP credential guard over the shared policy and Python-regex adapter.
//!
//! The caller supplies already reconciled identity and mitmproxy-equivalent ordered,
//! combined header strings, after service injection. No secret header or match is
//! retained in outcomes, errors, traces or audit intents. Raw-header decoding and
//! The HTTP caller must adapt parser-owned bytes through `credential_text` and
//! contain an unsupported encoding before releasing application bytes.
//!
//! The historical PDP evaluates credential policy then NETWORK for every allowed
//! credential, with no agent context. That additional charge is intentional source
//! compatibility here; the caller must not repeat any of these evaluations.

use crate::{
    credentials::Secret,
    inspection::{PatternIssue, compile_python_pattern},
    network_guard::{AuditDecision, Identity, PdpEffect, Response, Severity, sanitize},
    policy::{Addon, CredentialRequest, Effect, NetworkRequest, Policy, python_whitespace},
};
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use fancy_regex::Regex;
use ring::hmac;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, RwLock},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidConfig,
    InvalidEvent,
    InvalidHeaderEncoding,
    RegexCompatibility,
    RegexRuntime,
    EntropyRuntime,
    State,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid credential detection configuration",
            Self::InvalidEvent => "invalid credential policy event",
            Self::InvalidHeaderEncoding => "security header text encoding is unsupported",
            Self::RegexCompatibility => "credential pattern requires Python regex compatibility",
            Self::RegexRuntime => "credential pattern evaluation failed",
            Self::EntropyRuntime => "credential entropy evaluation failed",
            Self::State => "credential guard state unavailable",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Values are borrowed only during inspection. This type deliberately has no
/// Debug or Serialize implementation, even when the caller owns secret strings.
///
/// ```compile_fail
/// use safeyolo_proxy::credential_guard::Header;
/// fn debug(header: &Header<'_>) { let _ = format!("{header:?}"); }
/// ```
/// ```compile_fail
/// use safeyolo_proxy::credential_guard::Header;
/// fn serialize(header: &Header<'_>) { let _ = serde_json::to_string(header); }
/// ```
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a Secret,
}
pub struct Request<'a> {
    pub identity: Identity<'a>,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
    pub scheme: &'a str,
    pub request_id: Option<&'a str>,
    pub connection_id: &'a str,
    pub prior_response: bool,
    pub headers: &'a [Header<'a>],
}
pub enum Pdp<'a> {
    Ready(&'a Policy),
    Unconfigured,
    Failed {
        policy: &'a Policy,
        exception_type: &'static str,
    },
}
impl Pdp<'_> {
    fn policy(&self) -> Option<&Policy> {
        match self {
            Self::Ready(policy) | Self::Failed { policy, .. } => Some(policy),
            Self::Unconfigured => None,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub block: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self { block: true }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub rule: String,
    /// None when the PDP is unconfigured: the second classifier did not run.
    pub credential_type: Option<String>,
    pub header: String,
    pub fingerprint: String,
    pub confidence: &'static str,
    pub tier: u8,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApprovalIntent {
    pub required: bool,
    pub approval_type: &'static str,
    pub key: String,
    pub target: String,
    pub scope_hint: Value,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AuditIntent {
    pub event: &'static str,
    pub kind: &'static str,
    pub addon: &'static str,
    pub decision: AuditDecision,
    pub severity: Severity,
    pub summary: String,
    pub host: String,
    pub agent: Option<String>,
    pub request_id: Option<String>,
    pub approval: Option<ApprovalIntent>,
    pub details: Value,
}

impl AuditIntent {
    /// Convert one guard intent at its source hook.  Attribution is supplied
    /// by the trusted transport owner; no HTTP header or secret value is used
    /// to construct the canonical event.
    pub fn event(&self, attribution: crate::audit::Attribution) -> crate::audit::Event {
        let mut event = crate::audit::Event::new(
            self.event,
            crate::audit::Kind::Security,
            match self.severity {
                Severity::Low => crate::audit::Severity::Low,
                Severity::Medium => crate::audit::Severity::Medium,
                Severity::High => crate::audit::Severity::High,
                Severity::Critical => crate::audit::Severity::Critical,
            },
            &self.summary,
        );
        event.addon = Some(self.addon.into());
        event.decision = Some(match self.decision {
            AuditDecision::Allow => crate::audit::Decision::Allow,
            AuditDecision::Deny => crate::audit::Decision::Deny,
            AuditDecision::Warn => crate::audit::Decision::Warn,
            AuditDecision::RequireApproval => crate::audit::Decision::RequireApproval,
            AuditDecision::BudgetExceeded => crate::audit::Decision::BudgetExceeded,
        });
        event.host = Some(self.host.clone());
        event.agent = self.agent.clone();
        event.request_id = self.request_id.clone();
        event.attribution = Some(attribution);
        event.approval = self
            .approval
            .as_ref()
            .map(|approval| crate::audit::Approval {
                required: approval.required,
                approval_type: crate::audit::ApprovalType::Credential,
                key: approval.key.clone(),
                target: approval.target.clone(),
                scope_hint: approval.scope_hint.clone().into(),
            });
        event.details = self.details.clone().into();
        event
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TraceIntent {
    pub hook: &'static str,
    pub state: &'static str,
    pub outcome: Option<&'static str>,
    pub reason: Option<&'static str>,
    pub detection_count: Option<usize>,
    pub status: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Evaluation {
    pub finding: Finding,
    pub effect: PdpEffect,
    pub reason: String,
    pub reason_codes: Vec<&'static str>,
    pub required_checks: Vec<&'static str>,
    pub budget_remaining: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Bypassed,
    NoDetection,
    Allowed,
    Warned,
    Blocked,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Outcome {
    pub kind: OutcomeKind,
    pub response: Option<Response>,
    pub metadata: Value,
    pub trace: Vec<TraceIntent>,
    pub audit: Vec<AuditIntent>,
    pub evaluations: Vec<Evaluation>,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Stats {
    pub violations_total: u64,
    pub violations_by_type: HashMap<String, u64>,
    pub rules_count: usize,
    pub checks: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub warned: u64,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LoadReport {
    pub rules_count: usize,
    pub invalid_patterns: usize,
    pub invalid_rules: usize,
}

struct Rule {
    name: String,
    patterns: Vec<Regex>,
    allowed_hosts: Vec<String>,
    headers: Vec<String>,
}
impl Rule {
    fn find<'a>(&self, value: &'a str) -> Result<Option<&'a str>> {
        for pattern in &self.patterns {
            if let Some(found) = pattern.find(value).map_err(|_| Error::RegexRuntime)? {
                return Ok(Some(found.as_str()));
            }
        }
        Ok(None)
    }
}
struct Snapshot {
    rules: Vec<Rule>,
    level: String,
    auth_headers: Vec<String>,
    safe: Vec<String>,
    min_length: f64,
    diversity: f64,
    entropy: f64,
    hash: String,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            rules: vec![],
            level: "standard".into(),
            auth_headers: [
                "authorization",
                "x-api-key",
                "api-key",
                "x-auth-token",
                "apikey",
                "x-goog-api-key",
            ]
            .map(str::to_owned)
            .into(),
            safe: vec![],
            min_length: 20.,
            diversity: 0.5,
            entropy: 3.5,
            hash: String::new(),
        }
    }
}
#[derive(Clone)]
pub struct CredentialGuard {
    key: Arc<hmac::Key>,
    snapshot: Arc<RwLock<Arc<Snapshot>>>,
    stats: Arc<Mutex<Stats>>,
}
impl CredentialGuard {
    /// The root owns loading/generating the existing HMAC key file. Its bytes
    /// never enter configuration, serialized evidence, or error messages here.
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: Arc::new(hmac::Key::new(hmac::HMAC_SHA256, key)),
            snapshot: Arc::new(RwLock::new(Arc::new(Snapshot::default()))),
            stats: Arc::new(Mutex::new(Stats::default())),
        }
    }
    pub fn stats(&self) -> Result<Stats> {
        let mut stats = self.stats.lock().map_err(|_| Error::State)?.clone();
        stats.rules_count = self.snapshot()?.rules.len();
        Ok(stats)
    }
    pub fn stats_json(&self) -> Result<Value> {
        let s = self.stats()?;
        Ok(
            json!({"violations_total":s.violations_total,"violations_by_type":s.violations_by_type,"rules_count":s.rules_count}),
        )
    }
    pub fn load_sensor_config(&self, source: &Value) -> Result<LoadReport> {
        let (snapshot, report) = compile(source)?;
        let mut current = self.snapshot.write().map_err(|_| Error::State)?;
        *current = Arc::new(snapshot);
        Ok(report)
    }
    /// Compile a policy generation without mutating the currently published
    /// detector. The caller publishes the returned guard only after all other
    /// runtime preparation succeeds; HMAC key and counters remain shared.
    pub fn prepare_policy(&self, policy: &Policy) -> Result<(Self, LoadReport)> {
        self.prepare_policy_with_key(policy, None)
    }
    /// Build a generation with a newly loaded HMAC key, retaining counters.
    /// The caller owns the source configure condition and key lifetime.
    pub(crate) fn prepare_policy_with_key(
        &self,
        policy: &Policy,
        key: Option<&[u8]>,
    ) -> Result<(Self, LoadReport)> {
        let (snapshot, report) = policy
            .with_credential_guard_config(compile)
            .map_err(|_| Error::InvalidConfig)??;
        Ok((
            Self {
                key: key.map_or_else(
                    || self.key.clone(),
                    |key| Arc::new(hmac::Key::new(hmac::HMAC_SHA256, key)),
                ),
                snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
                stats: self.stats.clone(),
            },
            report,
        ))
    }
    /// None represents the source config-cache unavailable path: retain current
    /// rules. Failed candidate compilation also preserves the entire snapshot.
    pub fn maybe_reload(&self, source: Option<&Value>) -> Result<Option<LoadReport>> {
        let Some(source) = source else {
            return Ok(None);
        };
        let hash = source
            .get("policy_hash")
            .and_then(Value::as_str)
            .unwrap_or("");
        if self.snapshot.read().map_err(|_| Error::State)?.hash == hash {
            return Ok(None);
        }
        self.load_sensor_config(source).map(Some)
    }
    fn snapshot(&self) -> Result<Arc<Snapshot>> {
        Ok(self.snapshot.read().map_err(|_| Error::State)?.clone())
    }
    /// Safe detection evidence; no match text escapes this method.
    pub fn classify_headers(&self, headers: &[Header<'_>]) -> Result<Vec<Finding>> {
        let snapshot = self.snapshot()?;
        self.detect(&snapshot, headers)?
            .into_iter()
            .map(|mut detection| {
                classify(&snapshot, &mut detection)?;
                Ok(detection.finding)
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Adapt parser-owned ordered/combined bytes and enforce one request in a
    /// single guard call.  This is the forwarding integration seam: it never
    /// consults the post-parser `HeaderMap`, so duplicate order and original
    /// spelling remain the source view.  A conversion error is distinct from
    /// no detection and must be contained by the caller before egress.
    #[allow(clippy::too_many_arguments)]
    pub fn enforce_ordered<'a, 'b>(
        &self,
        pdp: Pdp<'_>,
        identity: Identity<'a>,
        host: &'a str,
        port: u16,
        method: &'a str,
        path: &'a str,
        scheme: &'a str,
        request_id: Option<&'a str>,
        connection_id: &'a str,
        prior_response: bool,
        fields: impl IntoIterator<Item = (&'b [u8], &'b [u8])>,
        options: Options,
        now_ms: f64,
    ) -> Result<Outcome> {
        // Applicability decisions do not consume header text. Keep source
        // bypasses and identity containment independent of the strict text
        // adapter: an invalid value on a disabled/prior/conflict request must
        // not turn an already-established outcome into a decoder failure.
        let applicable = !prior_response
            && identity != Identity::Conflict
            && pdp.policy().is_none_or(|policy| {
                policy.is_addon_enabled(
                    Addon::CredentialGuard,
                    Some(host),
                    match identity {
                        Identity::Resolved(agent) => Some(agent),
                        _ => None,
                    },
                )
            });
        if !applicable {
            let headers = [];
            return self.enforce(
                pdp,
                Request {
                    identity,
                    host,
                    port,
                    method,
                    path,
                    scheme,
                    request_id,
                    connection_id,
                    prior_response,
                    headers: &headers,
                },
                options,
                now_ms,
            );
        }
        let adapted = crate::credential_text::Headers::from_ordered(fields)
            .map_err(|_| Error::InvalidHeaderEncoding)?;
        let headers = adapted.as_guard_headers();
        self.enforce(
            pdp,
            Request {
                identity,
                host,
                port,
                method,
                path,
                scheme,
                request_id,
                connection_id,
                prior_response,
                headers: &headers,
            },
            options,
            now_ms,
        )
    }
    fn fingerprint(&self, value: &str) -> String {
        hmac::sign(&self.key, value.as_bytes()).as_ref()[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    fn detect(&self, snapshot: &Snapshot, headers: &[Header<'_>]) -> Result<Vec<Detection>> {
        let mut detections = Vec::new();
        for header in headers {
            let name = header.name.to_lowercase();
            if snapshot
                .safe
                .iter()
                .any(|pattern| name.contains(&pattern.to_lowercase()))
            {
                continue;
            }
            let raw = header.value.expose_secret();
            let extracted = if name == "authorization" {
                extract(raw)
            } else {
                None
            };
            let value = extracted.as_ref().map_or(raw, |value| value.as_str());
            let standard = snapshot.auth_headers.contains(&name);
            let mut matched = None;
            if standard {
                for rule in &snapshot.rules {
                    if rule.headers.contains(&name)
                        && let Some(value) = rule.find(value)?.filter(|value| !value.is_empty())
                    {
                        matched = Some((value, rule.name.as_str(), "high", 1));
                        break;
                    }
                }
            }
            if matched.is_none()
                && ((standard && ["standard", "paranoid"].contains(&snapshot.level.as_str()))
                    || (!standard && snapshot.level == "paranoid"))
                && looks_secret(snapshot, value)?
            {
                matched = Some((
                    value,
                    "unknown_secret",
                    if standard { "medium" } else { "low" },
                    2,
                ));
            }
            if let Some((value, rule, confidence, tier)) = matched {
                detections.push(Detection {
                    classified: String::new(),
                    value: Secret::new(value),
                    finding: Finding {
                        rule: rule.into(),
                        credential_type: None,
                        header: header.name.into(),
                        fingerprint: self.fingerprint(value),
                        confidence,
                        tier,
                    },
                });
            }
        }
        Ok(detections)
    }
    pub fn enforce(
        &self,
        pdp: Pdp<'_>,
        request: Request<'_>,
        options: Options,
        now_ms: f64,
    ) -> Result<Outcome> {
        let mut output = Outcome {
            kind: OutcomeKind::Bypassed,
            response: None,
            metadata: json!({}),
            trace: vec![],
            audit: vec![],
            evaluations: vec![],
        };
        if request.prior_response {
            output.trace.push(trace(
                request.method,
                "bypassed",
                None,
                Some("prior_response"),
            ));
            return Ok(output);
        }
        if request.identity == Identity::Conflict {
            self.stats.lock().map_err(|_| Error::State)?.blocked += 1;
            output.kind = OutcomeKind::Blocked;
            output.metadata =
                json!({"blocked_by":"credential-guard","block_reason":"agent_identity_conflict"});
            let mut response = response(
                403,
                json!({"error":"Trusted agent identity sources disagree","reason":"agent_identity_conflict"}),
            );
            if let Some(id) = request.request_id.filter(|id| !id.is_empty()) {
                response
                    .headers
                    .push(("X-SafeYolo-Request-Id".into(), id.into()));
            }
            output.response = Some(response);
            let mut entry = trace(request.method, "evaluated", Some("blocked"), None);
            entry.status = Some(403);
            output.trace.push(entry);
            return Ok(output);
        }
        let agent = match request.identity {
            Identity::Resolved(agent) => Some(agent),
            _ => None,
        };
        let project = agent.unwrap_or("default");
        if pdp.policy().is_some_and(|policy| {
            !policy.is_addon_enabled(Addon::CredentialGuard, Some(request.host), Some(project))
        }) {
            output.trace.push(trace(
                request.method,
                "bypassed",
                None,
                Some("policy_disabled"),
            ));
            return Ok(output);
        }
        self.stats.lock().map_err(|_| Error::State)?.checks += 1;
        let snapshot = self.snapshot()?;
        let detections = self.detect(&snapshot, request.headers)?;
        if detections.is_empty() {
            output.kind = OutcomeKind::NoDetection;
            output.trace.push(trace(
                request.method,
                "evaluated",
                Some("no_detection"),
                None,
            ));
            return Ok(output);
        }
        let mut entry = trace(request.method, "evaluated", Some("detected"), None);
        entry.detection_count = Some(detections.len());
        output.trace.push(entry);
        output.kind = OutcomeKind::Allowed;
        let host = request.host.to_lowercase();
        for mut detection in detections {
            if !matches!(pdp, Pdp::Unconfigured) {
                classify(&snapshot, &mut detection)?;
                if request.port == 0 {
                    return Err(Error::InvalidEvent);
                }
            }
            let event_id = format!(
                "evt_{}",
                request
                    .request_id
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!(
                        "req_{}",
                        &uuid::Uuid::new_v4().simple().to_string()[..12]
                    ))
            );
            let decision = evaluate(&pdp, &request, &detection.finding, now_ms);
            let fingerprint = format!("hmac:{}", detection.finding.fingerprint);
            let expected = snapshot
                .rules
                .iter()
                .find(|rule| rule.name == detection.classified);
            let expected_hosts = expected
                .map(|rule| rule.allowed_hosts.clone())
                .unwrap_or_default();
            let mut details = json!({"rule":detection.finding.rule,"location":format!("header:{}",detection.finding.header),"fingerprint":fingerprint,"confidence":detection.finding.confidence,"tier":detection.finding.tier,"project_id":project,"reason_codes":decision.codes,"method":request.method,"port":request.port,"connection_id":request.connection_id});
            let (audit_decision, severity, summary, approval) = if decision.effect
                == PdpEffect::Allow
            {
                self.stats.lock().map_err(|_| Error::State)?.allowed += 1;
                (
                    AuditDecision::Allow,
                    Severity::Low,
                    format!(
                        "Credential {} allowed to {}",
                        detection.finding.rule,
                        sanitize(&host)
                    ),
                    None,
                )
            } else {
                let mut stats = self.stats.lock().map_err(|_| Error::State)?;
                stats.violations_total += 1;
                *stats
                    .violations_by_type
                    .entry(detection.finding.rule.clone())
                    .or_default() += 1;
                output.metadata["credential_fingerprint"] = json!(fingerprint);
                let (reason, audit_decision) = match decision.effect {
                    PdpEffect::Deny => ("destination_mismatch", AuditDecision::Deny),
                    PdpEffect::RequireApproval => {
                        ("requires_approval", AuditDecision::RequireApproval)
                    }
                    PdpEffect::BudgetExceeded => ("budget_exceeded", AuditDecision::BudgetExceeded),
                    _ => (decision.reason.as_str(), AuditDecision::Deny),
                };
                details["reason"] = json!(reason);
                if decision.effect == PdpEffect::Deny {
                    details["expected_hosts"] = json!(expected_hosts);
                }
                let approval=matches!(decision.effect,PdpEffect::Deny|PdpEffect::RequireApproval).then(||ApprovalIntent {required:true,approval_type:"credential",key:fingerprint.clone(),target:host.clone(),scope_hint:json!({"rule":detection.finding.rule,"expected_hosts":expected_hosts})});
                let mode = if options.block {
                    output.kind = OutcomeKind::Blocked;
                    if decision.effect != PdpEffect::BudgetExceeded {
                        stats.blocked += 1;
                    }
                    output.metadata["blocked_by"] = json!("credential-guard");
                    "blocked"
                } else {
                    output.kind = OutcomeKind::Warned;
                    stats.warned += 1;
                    output
                        .trace
                        .push(trace(request.method, "evaluated", Some("warned"), None));
                    "would be blocked"
                };
                (
                    if options.block {
                        audit_decision
                    } else {
                        AuditDecision::Warn
                    },
                    if options.block {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    format!(
                        "Credential {} {mode} to {}: {reason}",
                        detection.finding.rule,
                        sanitize(&host)
                    ),
                    approval,
                )
            };
            output.audit.push(AuditIntent {
                event: "security.credential_guard",
                kind: "security",
                addon: "credential-guard",
                decision: audit_decision,
                severity,
                summary,
                host: host.clone(),
                agent: agent.map(str::to_owned),
                request_id: request.request_id.map(str::to_owned),
                approval,
                details,
            });
            output.evaluations.push(Evaluation {
                finding: detection.finding.clone(),
                effect: decision.effect,
                reason: decision.reason.clone(),
                reason_codes: decision.codes.clone(),
                required_checks: decision.checks.clone(),
                budget_remaining: decision.remaining,
            });
            if decision.effect != PdpEffect::Allow && options.block {
                output.response = Some(if decision.legacy {
                    response(
                        428,
                        json!({"error":"Credential requires approval","type":"requires_approval","credential_type":detection.finding.rule,"destination":host,"credential_fingerprint":fingerprint,"reason":decision.reason,"action":"wait_for_approval","reflection":"This credential requires human approval before use."}),
                    )
                } else {
                    let status = match decision.effect {
                        PdpEffect::Deny => 403,
                        PdpEffect::RequireApproval => 428,
                        PdpEffect::BudgetExceeded => 429,
                        _ => 500,
                    };
                    response(
                        status,
                        if decision.internal_error {
                            json!({"error":"PDP evaluation failed","event_id":event_id,"reason_codes":decision.codes})
                        } else {
                            json!({"error":match decision.effect {PdpEffect::Deny=>"Deny",PdpEffect::RequireApproval=>"Require Approval",PdpEffect::BudgetExceeded=>"Budget Exceeded",_=>"Error"},"event_id":event_id,"reason":decision.raw_reason,"reason_codes":decision.codes})
                        },
                    )
                });
                break;
            }
        }
        Ok(output)
    }
}
struct Detection {
    value: Secret,
    classified: String,
    finding: Finding,
}
fn classify(snapshot: &Snapshot, detection: &mut Detection) -> Result<()> {
    let mut name = "unknown";
    for rule in &snapshot.rules {
        if rule
            .find(detection.value.expose_secret())?
            .is_some_and(|value| !value.is_empty())
        {
            name = &rule.name;
            break;
        }
    }
    detection.classified = name.into();
    detection.finding.credential_type = Some(if name.is_empty() {
        "unknown".into()
    } else {
        name.to_lowercase()
    });
    Ok(())
}
fn trace(
    method: &str,
    state: &'static str,
    outcome: Option<&'static str>,
    reason: Option<&'static str>,
) -> TraceIntent {
    TraceIntent {
        hook: if method == "CONNECT" {
            "http_connect"
        } else {
            "request"
        },
        state,
        outcome,
        reason,
        detection_count: None,
        status: None,
    }
}
fn response(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("X-Blocked-By".into(), "credential-guard".into()),
        ],
        body,
    }
}
fn extract(value: &str) -> Option<Zeroizing<String>> {
    if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
    {
        return Some(Zeroizing::new(
            value[7..].trim_matches(python_whitespace).into(),
        ));
    }
    if !value
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("basic "))
    {
        return None;
    }
    // The pinned Python validate=True accepts non-canonical pad bits, but
    // rejects missing/redundant padding and padding before subsequent data.
    let value = value[6..].trim_matches(python_whitespace);
    let first_pad = value.find('=').unwrap_or(value.len());
    if value[first_pad..].bytes().any(|byte| byte != b'=') {
        return None;
    }
    let tail = first_pad % 4;
    let padding = value.len() - first_pad;
    if !matches!((tail, padding), (0, 0) | (2, 2) | (3, 1)) {
        return None;
    }
    let config = GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let decoded = Zeroizing::new(
        GeneralPurpose::new(&alphabet::STANDARD, config)
            .decode(&value[..if tail == 0 { first_pad } else { value.len() }])
            .ok()?,
    );
    let decoded = std::str::from_utf8(&decoded).ok()?;
    decoded
        .split_once(':')
        .map(|(_, password)| Zeroizing::new(password.into()))
}
fn looks_secret(config: &Snapshot, value: &str) -> Result<bool> {
    let length = value.chars().count();
    if (length as f64) < config.min_length {
        return Ok(false);
    }
    if length == 0 {
        return Err(Error::EntropyRuntime);
    }
    // Preserve Python Counter insertion order and summation order.
    let mut counts = Vec::<(char, usize)>::new();
    let mut indices = HashMap::new();
    for ch in value.chars() {
        let index = *indices.entry(ch).or_insert_with(|| {
            counts.push((ch, 0));
            counts.len() - 1
        });
        counts[index].1 += 1;
    }
    if counts.len() as f64 / (length as f64) < config.diversity {
        return Ok(false);
    }
    let entropy = -counts
        .into_iter()
        .map(|(_, count)| {
            let p = count as f64 / length as f64;
            p * p.log2()
        })
        .sum::<f64>();
    Ok(entropy >= config.entropy)
}
fn strings(value: Option<&Value>, default: &[&str]) -> Result<Vec<String>> {
    match value {
        None => Ok(default.iter().map(|value| (*value).into()).collect()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Error::InvalidConfig)
            })
            .collect(),
        _ => Err(Error::InvalidConfig),
    }
}
fn compile(source: &Value) -> Result<(Snapshot, LoadReport)> {
    if !source.is_object() {
        return Err(Error::InvalidConfig);
    }
    let mut snapshot = Snapshot::default();
    if let Some(hash) = source.get("policy_hash") {
        snapshot.hash = hash.as_str().ok_or(Error::InvalidConfig)?.into();
    }
    let config = source
        .get("addons")
        .map(|addons| addons.as_object().ok_or(Error::InvalidConfig))
        .transpose()?
        .and_then(|addons| addons.get("credential_guard"))
        .map(|config| config.as_object().ok_or(Error::InvalidConfig))
        .transpose()?;
    if let Some(config) = config {
        if let Some(level) = config.get("detection_level") {
            snapshot.level = level.as_str().ok_or(Error::InvalidConfig)?.into();
        }
        if let Some(headers) = config.get("standard_auth_headers") {
            snapshot.auth_headers = strings(Some(headers), &[])?;
        }
        if let Some(safe) = config.get("safe_headers") {
            snapshot.safe = strings(
                safe.as_object()
                    .ok_or(Error::InvalidConfig)?
                    .get("safe_patterns"),
                &[],
            )?;
        }
        if let Some(entropy) = config.get("entropy") {
            let entropy = entropy.as_object().ok_or(Error::InvalidConfig)?;
            for (name, target) in [
                ("min_length", &mut snapshot.min_length),
                ("min_charset_diversity", &mut snapshot.diversity),
                ("min_shannon_entropy", &mut snapshot.entropy),
            ] {
                if let Some(value) = entropy.get(name) {
                    *target = if let Some(value) = value.as_bool() {
                        f64::from(value)
                    } else {
                        value.as_f64().ok_or(Error::InvalidConfig)?
                    };
                }
            }
        }
    }
    let defaults = config
        .and_then(|config| config.get("use_default_credential_rules"))
        .map_or(Ok(true), |value| {
            value.as_bool().ok_or(Error::InvalidConfig)
        })?;
    let builtin: Value =
        serde_json::from_str(include_str!("../data/credential_guard/catalogue.json"))
            .expect("generated catalogue");
    let mut configs = if defaults {
        builtin.as_array().unwrap().clone()
    } else {
        vec![]
    };
    if let Some(rules) = source.get("credential_rules") {
        configs.extend(
            rules
                .as_array()
                .ok_or(Error::InvalidConfig)?
                .iter()
                .cloned(),
        );
    }
    let mut report = LoadReport {
        rules_count: 0,
        invalid_patterns: 0,
        invalid_rules: 0,
    };
    for raw in configs {
        let parsed = (|| -> Result<Rule> {
            let raw = raw.as_object().ok_or(Error::InvalidConfig)?;
            let name = raw
                .get("name")
                .and_then(Value::as_str)
                .ok_or(Error::InvalidConfig)?
                .into();
            let patterns = strings(raw.get("patterns"), &[])?;
            let allowed_hosts = strings(raw.get("allowed_hosts"), &[])?;
            let headers = strings(
                raw.get("header_names").filter(|value| !value.is_null()),
                &["authorization", "x-api-key"],
            )?
            .into_iter()
            .map(|header| header.to_lowercase())
            .collect();
            let _suggested_url = raw
                .get("suggested_url")
                .map_or(Ok(""), |value| value.as_str().ok_or(Error::InvalidConfig))?;
            let mut compiled = vec![];
            for pattern in patterns {
                if [r"(.+)+", r"(.*)*", r"(.+)*", r"(.*)+", r"(\w+)+", r"(\d+)+"]
                    .iter()
                    .any(|indicator| pattern.contains(indicator))
                {
                    report.invalid_patterns += 1;
                    continue;
                }
                match compile_python_pattern(&pattern, false) {
                    Ok(pattern) => compiled.push(pattern),
                    Err(PatternIssue::Invalid) => report.invalid_patterns += 1,
                    Err(PatternIssue::Compatibility) => return Err(Error::RegexCompatibility),
                }
            }
            Ok(Rule {
                name,
                patterns: compiled,
                allowed_hosts,
                headers,
            })
        })();
        match parsed {
            Ok(rule) => snapshot.rules.push(rule),
            Err(Error::InvalidConfig) => report.invalid_rules += 1,
            Err(error) => return Err(error),
        }
    }
    report.rules_count = snapshot.rules.len();
    Ok((snapshot, report))
}
struct Decision {
    effect: PdpEffect,
    reason: String,
    raw_reason: String,
    codes: Vec<&'static str>,
    checks: Vec<&'static str>,
    remaining: Option<u64>,
    legacy: bool,
    internal_error: bool,
}
fn evaluate(pdp: &Pdp<'_>, request: &Request<'_>, finding: &Finding, now_ms: f64) -> Decision {
    let error = |reason: String, codes, legacy| Decision {
        effect: PdpEffect::Error,
        raw_reason: reason.clone(),
        reason,
        codes,
        checks: vec![],
        remaining: None,
        legacy,
        internal_error: !legacy,
    };
    let policy = match pdp {
        Pdp::Ready(policy) => policy,
        Pdp::Unconfigured => {
            return error(
                "Policy engine not configured (fail-closed)".into(),
                vec!["PDP_NOT_CONFIGURED"],
                true,
            );
        }
        Pdp::Failed { exception_type, .. } => {
            return error(
                format!("Policy evaluation failed: {exception_type}"),
                vec!["PDP_EVALUATION_FAILED"],
                true,
            );
        }
    };
    let failed = || {
        error(
            "Internal evaluation error: PolicyError".into(),
            vec!["PDP_ERROR", "INTERNAL_ERROR"],
            false,
        )
    };
    if request
        .host
        .eq_ignore_ascii_case("_safeyolo.probe.internal")
    {
        return Decision {
            effect: PdpEffect::Allow,
            reason: "Internal pipeline probe (system-reserved)".into(),
            raw_reason: String::new(),
            codes: vec!["INTERNAL_PIPELINE_PROBE"],
            checks: vec![],
            remaining: None,
            legacy: false,
            internal_error: false,
        };
    }
    let credential_type = finding.credential_type.as_deref().unwrap_or("unknown");
    let path = request.path.split('?').next().unwrap();
    let Ok(credential) = policy.evaluate_credential(
        CredentialRequest {
            credential_type,
            destination: request.host,
            path,
            credential_hmac: Some(&finding.fingerprint),
        },
        now_ms,
    ) else {
        return failed();
    };
    let network = credential.effect == Effect::Allow;
    let decision = if network {
        match policy.evaluate(
            NetworkRequest {
                agent: None,
                host: request.host,
                port: Some(request.port),
                method: request.method,
                path,
            },
            now_ms,
            true,
        ) {
            Ok(decision) => decision,
            Err(_) => return failed(),
        }
    } else {
        credential
    };
    let raw_reason = match decision.effect {
        Effect::Deny if network && decision.matched_resource.is_none() => {
            "No matching permission (default deny)".into()
        }
        Effect::Prompt if !network && decision.matched_resource.is_none() => format!(
            "No permission for '{}' credential to '{}'",
            credential_type, request.host
        ),
        Effect::BudgetExceeded => {
            if network {
                format!("Request budget exceeded for {}", request.host)
            } else {
                format!(
                    "Budget exceeded for {} to {}",
                    credential_type, request.host
                )
            }
        }
        _ => String::new(),
    };
    let (effect, fallback, mut codes) = match decision.effect {
        Effect::Allow => (
            PdpEffect::Allow,
            "allow",
            vec![
                "ALLOWED",
                if network {
                    "PERMISSION_NETWORK_REQUEST"
                } else {
                    "PERMISSION_CREDENTIAL_USE"
                },
            ],
        ),
        Effect::Deny => (PdpEffect::Deny, "deny", vec!["DENIED"]),
        Effect::Prompt => (
            PdpEffect::RequireApproval,
            "require_approval",
            vec!["REQUIRE_APPROVAL"],
        ),
        Effect::BudgetExceeded => (
            PdpEffect::BudgetExceeded,
            "budget_exceeded",
            vec!["BUDGET_EXCEEDED", "RATE_LIMITED"],
        ),
        Effect::Budget => (PdpEffect::Error, "error", vec![]),
    };
    if effect == PdpEffect::RequireApproval {
        if raw_reason.to_lowercase().contains("credential") {
            codes.push("CREDENTIAL_NOT_APPROVED");
        }
        if raw_reason.to_lowercase().contains("destination") {
            codes.push("CREDENTIAL_DESTINATION_MISMATCH");
        }
    }
    Decision {
        effect,
        reason: if raw_reason.is_empty() {
            format!("Decision: {fallback}")
        } else {
            raw_reason.clone()
        },
        raw_reason,
        codes,
        checks: vec![
            "rate_limit",
            "credential_detection",
            "credential_validation",
        ],
        remaining: decision.budget_remaining,
        legacy: false,
        internal_error: false,
    }
}
