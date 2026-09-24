//! Network guard presentation over the single native policy engine.
//!
//! The caller supplies request-boundary trusted identity and correlation IDs.
//! This module never reads identity headers, connects upstream, or persists
//! approvals. The runtime submits audit intents at the reached source hook.
//! An Allowed outcome authorizes only this guard;
//! the caller must still run the remaining pipeline and contain reserved hosts.

use std::{
    fmt,
    sync::{Arc, Mutex, OnceLock},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    approvals::{NetworkPrompt, NetworkScope},
    audit,
    policy::{Effect, NetworkRequest, Policy},
};

#[derive(Debug)]
pub struct GuardError(pub String);
impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for GuardError {}
type Result<T> = std::result::Result<T, GuardError>;

/// Already reconciled by the transport owner. Untrusted metadata is not a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity<'a> {
    Resolved(&'a str),
    Unavailable,
    Conflict,
}
impl<'a> Identity<'a> {
    fn agent(self) -> Option<&'a str> {
        match self {
            Self::Resolved(agent) => Some(agent),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub identity: Identity<'a>,
    /// Same decoded hostname supplied by the old HTTP sensor. No normalization
    /// happens here: transport must preserve its separate wire target.
    pub host: &'a str,
    /// Decode DNS ACE labels consistently after configured bypass checks.
    /// Policy matching and audit attribution keep the source host above.
    pub decode_ace_for_inspection: bool,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
    pub scheme: &'a str,
    pub request_id: Option<&'a str>,
    pub connection_id: &'a str,
    pub prior_response: bool,
}
impl<'a> Request<'a> {
    fn policy_request(self) -> NetworkRequest<'a> {
        NetworkRequest {
            agent: self.identity.agent(),
            host: self.host,
            port: Some(self.port),
            method: self.method,
            path: self.path.split('?').next().unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub enabled: bool,
    pub block: bool,
    pub homoglyph: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            enabled: true,
            block: true,
            homoglyph: true,
        }
    }
}

/// A configured evaluator failure remains distinct from a missing PDP. Failed
/// retains the policy snapshot so the preceding addon-enable query is unchanged.
pub enum Pdp<'a> {
    Ready(&'a Policy),
    Unconfigured,
    Failed { policy: &'a Policy, reason: &'a str },
}
impl Pdp<'_> {
    fn policy(&self) -> Option<&Policy> {
        match self {
            Self::Ready(policy) | Self::Failed { policy, .. } => Some(policy),
            Self::Unconfigured => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PdpEffect {
    Allow,
    Deny,
    RequireApproval,
    BudgetExceeded,
    Error,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PdpDecision {
    pub effect: PdpEffect,
    pub reason: String,
    pub reason_codes: Vec<&'static str>,
    pub required_checks: Vec<&'static str>,
    pub budget_remaining: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PolicyEvent {
    pub agent: Option<String>,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query_string: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Bypassed,
    Allowed,
    Warned,
    Blocked,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BypassReason {
    AddonDisabled,
    PriorResponse,
    PolicyDisabled,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
    Warn,
    RequireApproval,
    BudgetExceeded,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
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
    pub approval: Option<NetworkPrompt>,
    pub details: Value,
}

impl AuditIntent {
    /// Attribution comes from the trusted request snapshot, never HTTP headers.
    pub fn event(&self, attribution: audit::Attribution) -> audit::Event {
        let mut event = audit::Event::new(
            self.event,
            audit::Kind::Security,
            match self.severity {
                Severity::Low => audit::Severity::Low,
                Severity::Medium => audit::Severity::Medium,
                Severity::High => audit::Severity::High,
                Severity::Critical => audit::Severity::Critical,
            },
            &self.summary,
        );
        event.addon = Some(self.addon.into());
        event.decision = Some(match self.decision {
            AuditDecision::Allow => audit::Decision::Allow,
            AuditDecision::Deny => audit::Decision::Deny,
            AuditDecision::Warn => audit::Decision::Warn,
            AuditDecision::RequireApproval => audit::Decision::RequireApproval,
            AuditDecision::BudgetExceeded => audit::Decision::BudgetExceeded,
        });
        event.host = Some(self.host.clone());
        event.agent = self.agent.clone();
        event.request_id = self.request_id.clone();
        event.attribution = Some(attribution);
        event.approval = self.approval.as_ref().map(|approval| audit::Approval {
            required: true,
            approval_type: audit::ApprovalType::NetworkEgress,
            key: approval.key.clone(),
            target: approval.target.clone(),
            scope_hint: json!({"port": approval.scope_hint.port}).into(),
        });
        event.details = self.details.clone().into();
        event
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}
impl Response {
    /// Match json.dumps(body).encode(), including ASCII escaping and spacing.
    /// Content-Length derives from these bytes, never from the UTF-8 Value.
    pub fn body_bytes(&self) -> Vec<u8> {
        crate::python_json::encode(&self.body).into_bytes()
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TraceIntent {
    pub hook: &'static str,
    pub state: &'static str,
    pub outcome: Option<OutcomeKind>,
    pub reason: Option<BypassReason>,
    pub status: Option<u16>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Outcome {
    pub kind: OutcomeKind,
    pub response: Option<Response>,
    /// Merge these entries into existing metadata; absence does not delete
    /// metadata supplied by earlier pipeline stages.
    pub metadata: Value,
    pub trace: TraceIntent,
    pub audit: Option<AuditIntent>,
    pub policy_event: Option<PolicyEvent>,
    pub pdp: Option<PdpDecision>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Stats {
    pub checks: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub warned: u64,
    pub rate_limited: u64,
}
#[derive(Clone, Default)]
pub struct NetworkGuard {
    stats: Arc<Mutex<Stats>>,
}

impl NetworkGuard {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stats(&self) -> Result<Stats> {
        Ok(self
            .stats
            .lock()
            .map_err(|_| GuardError("network guard stats lock poisoned".into()))?
            .clone())
    }
    pub fn stats_json(&self, enabled: bool) -> Result<Value> {
        let mut value = serde_json::to_value(self.stats()?).expect("stats serialization");
        value["enabled"] = json!(enabled);
        Ok(value)
    }
    fn count(&self, update: impl FnOnce(&mut Stats)) -> Result<()> {
        update(
            &mut *self
                .stats
                .lock()
                .map_err(|_| GuardError("network guard stats lock poisoned".into()))?,
        );
        Ok(())
    }

    /// Side effects are explicit in Outcome, except shared policy budget charge
    /// and counters. No caller should evaluate the same event a second time.
    pub fn enforce(
        &self,
        pdp: Pdp<'_>,
        request: Request<'_>,
        options: Options,
        now_ms: f64,
    ) -> Result<Outcome> {
        self.enforce_with_audit(pdp, request, options, now_ms, |_| Ok(()))
    }

    /// Submit at the source's audit point. A synchronous submission exception
    /// stops the later effects; preceding counters remain applied. A reported
    /// queue drop or asynchronous sink failure does not fail this boundary.
    pub fn enforce_with_audit(
        &self,
        pdp: Pdp<'_>,
        request: Request<'_>,
        options: Options,
        now_ms: f64,
        submit: impl FnMut(&AuditIntent) -> Result<()>,
    ) -> Result<Outcome> {
        self.enforce_with_audit_and_trace(pdp, request, options, now_ms, submit, |_| {})
    }

    /// Observe only reached normal trace steps. The caller owns opt-in, timing,
    /// best-effort storage and any terminal error step. In particular, an allowed
    /// CONNECT is observed before its audit submission, which may still fail.
    /// The observer has no error result; no policy evaluation is repeated to
    /// construct the observation.
    pub fn enforce_with_audit_and_trace(
        &self,
        pdp: Pdp<'_>,
        request: Request<'_>,
        options: Options,
        now_ms: f64,
        mut submit: impl FnMut(&AuditIntent) -> Result<()>,
        mut observe: impl FnMut(&TraceIntent),
    ) -> Result<Outcome> {
        let mut output = Outcome {
            kind: OutcomeKind::Bypassed,
            response: None,
            metadata: json!({}),
            audit: None,
            trace: TraceIntent {
                hook: if request.method == "CONNECT" {
                    "http_connect"
                } else {
                    "request"
                },
                state: "bypassed",
                outcome: None,
                reason: None,
                status: None,
            },
            policy_event: None,
            pdp: None,
        };
        let bypass = if !options.enabled {
            Some(BypassReason::AddonDisabled)
        } else if request.prior_response {
            Some(BypassReason::PriorResponse)
        } else if request.identity != Identity::Conflict
            && pdp
                .policy()
                .is_some_and(|policy| !policy.network_guard_enabled(request.policy_request()))
        {
            Some(BypassReason::PolicyDisabled)
        } else {
            None
        };
        if let Some(reason) = bypass {
            output.trace.reason = Some(reason);
            observe(&output.trace);
            return Ok(output);
        }
        self.count(|stats| stats.checks += 1)?;
        let violation = if request.identity == Identity::Conflict {
            Some(Violation::Deny(
                "Trusted agent identity sources disagree (fail-closed)".into(),
            ))
        } else if let Some(violation) = hostname_violation(request, options.homoglyph) {
            Some(violation)
        } else if matches!(pdp, Pdp::Unconfigured) {
            Some(Violation::Deny("PDP not configured (fail-closed)".into()))
        } else {
            if request.port == 0 {
                return Err(GuardError("port must be from 1 to 65535".into()));
            }
            let (path, query) = request
                .path
                .split_once('?')
                .map_or((request.path, None), |(path, query)| {
                    (path, Some(query.to_owned()))
                });
            output.policy_event = Some(PolicyEvent {
                agent: request.identity.agent().map(str::to_owned),
                method: request.method.into(),
                scheme: request.scheme.into(),
                host: request.host.into(),
                port: request.port,
                path: path.into(),
                query_string: query,
            });
            let decision = match pdp {
                Pdp::Ready(policy) => evaluate_policy(policy, request, now_ms),
                Pdp::Failed { reason, .. } => pdp_error(reason.into()),
                Pdp::Unconfigured => unreachable!(),
            };
            let violation = match decision.effect {
                PdpEffect::Allow => None,
                PdpEffect::Deny => Some(Violation::Deny(decision.reason.clone())),
                PdpEffect::RequireApproval => Some(Violation::Prompt),
                PdpEffect::BudgetExceeded => Some(Violation::Budget(decision.reason.clone())),
                PdpEffect::Error => {
                    Some(Violation::Deny(format!("PDP error: {}", decision.reason)))
                }
            };
            output.pdp = Some(decision);
            violation
        };
        if let Some(violation) = violation {
            self.violation(request, options.block, violation, &mut output, &mut submit)?;
            output.trace.state = "evaluated";
            output.trace.outcome = Some(output.kind);
            output.trace.status = output.response.as_ref().map(|response| response.status);
            observe(&output.trace);
        } else {
            self.count(|stats| stats.allowed += 1)?;
            output.kind = OutcomeKind::Allowed;
            if let Some(remaining) = output
                .pdp
                .as_ref()
                .and_then(|decision| decision.budget_remaining)
            {
                output.metadata["ratelimit_remaining"] = json!(remaining);
            }
            output.trace.state = "evaluated";
            output.trace.outcome = Some(output.kind);
            observe(&output.trace);
            if request.method == "CONNECT" {
                let intent = audit(
                    request,
                    AuditDecision::Allow,
                    Severity::Low,
                    format!(
                        "CONNECT to {}:{} allowed",
                        sanitize(request.host),
                        request.port
                    ),
                    None,
                    json!({}),
                );
                submit(&intent)?;
                output.audit = Some(intent);
            }
        }
        Ok(output)
    }

    fn violation(
        &self,
        request: Request<'_>,
        block: bool,
        violation: Violation,
        output: &mut Outcome,
        submit: &mut impl FnMut(&AuditIntent) -> Result<()>,
    ) -> Result<()> {
        let domain = request.host;
        let safe = sanitize(domain);
        let (status, decision, severity, summary, body, details, approval, extra) = match violation
        {
            Violation::Deny(reason) => {
                let reason = if reason.is_empty() {
                    format!("Access denied to {domain}")
                } else {
                    reason
                };
                (
                    403,
                    AuditDecision::Deny,
                    Severity::High,
                    if block {
                        format!("Access denied to {safe}")
                    } else {
                        format!("Access would be denied to {safe}")
                    },
                    json!({"error":"Access denied by proxy","domain":domain,"reason":reason,"type":"access_denied","action":"self_correct","reflection":format!("Network access to {safe} is not in the security policy. If you need this domain, ask the operator to add it to policy.yaml.")}),
                    json!({"reason":reason,"decision_type":"access_denied"}),
                    None,
                    vec![],
                )
            }
            Violation::Homoglyph => {
                let reason =
                    format!("Homoglyph attack detected: Mixed scripts detected in '{domain}'");
                (
                    403,
                    AuditDecision::Deny,
                    Severity::Critical,
                    if block {
                        format!("Homoglyph attack: {safe}")
                    } else {
                        format!("Homoglyph attack (warn): {safe}")
                    },
                    json!({"error":"Domain blocked by proxy","domain":domain,"reason":reason,"attack_type":"homoglyph","type":"homoglyph_attack","action":"abort","reflection":"This domain contains mixed-script characters that may indicate a spoofing attack. Check the URL carefully — the domain may look similar to a legitimate one but use different character sets."}),
                    json!({"reason":reason,"attack_type":"homoglyph"}),
                    None,
                    vec![],
                )
            }
            Violation::Budget(reason) => {
                self.count(|stats| stats.rate_limited += 1)?;
                (
                    429,
                    AuditDecision::BudgetExceeded,
                    Severity::Medium,
                    if block {
                        format!("Rate limit exceeded for {safe}")
                    } else {
                        format!("Rate limit would be exceeded for {safe}")
                    },
                    json!({"error":"Rate limited by proxy","domain":domain,"reason":reason,"type":"rate_limit_exceeded","action":"retry_with_backoff","reflection":format!("Too many requests to {safe}. Wait for the rate limit window to reset, then retry.")}),
                    json!({"reason":reason,"decision_type":"rate_limited"}),
                    None,
                    vec![
                        ("Retry-After".into(), "60".into()),
                        ("X-RateLimit-Remaining".into(), "0".into()),
                    ],
                )
            }
            Violation::Prompt => {
                let scope = NetworkScope::new(domain, request.identity.agent(), Some(request.port))
                    .map_err(|error| GuardError(error.to_string()))?;
                let approval =
                    NetworkPrompt::new(&scope).map_err(|error| GuardError(error.to_string()))?;
                (
                    428,
                    AuditDecision::RequireApproval,
                    Severity::Medium,
                    if block {
                        format!("Egress to {} requires approval", sanitize(&approval.target))
                    } else {
                        format!("Egress to {safe} would require approval")
                    },
                    json!({"error":"Network access requires approval","type":"egress_approval_required","destination":domain,"port":request.port,"action":"wait_for_approval","reflection":format!("Access to {safe} is not in the allowed hosts list. Check if this is an expected destination, then approve or deny via safeyolo watch.")}),
                    json!({"decision_type":"egress_approval_required"}),
                    Some(approval),
                    vec![],
                )
            }
        };
        let intent = audit(
            request,
            if block { decision } else { AuditDecision::Warn },
            severity,
            summary,
            approval,
            details,
        );
        submit(&intent)?;
        output.audit = Some(intent);
        if block {
            self.count(|stats| stats.blocked += 1)?;
            output.kind = OutcomeKind::Blocked;
            output.metadata["blocked_by"] = json!("network-guard");
            if let Some(reason) = body
                .get("reason")
                .and_then(Value::as_str)
                .filter(|reason| !reason.is_empty())
            {
                output.metadata["block_reason"] = json!(reason);
            }
            let mut headers = vec![
                ("Content-Type".into(), "application/json".into()),
                ("X-Blocked-By".into(), "network-guard".into()),
            ];
            if let Some(id) = request.request_id.filter(|id| !id.is_empty()) {
                headers.push(("X-SafeYolo-Request-Id".into(), id.into()));
            }
            headers.extend(extra);
            let response = Response {
                status,
                headers,
                body,
            };
            output.response = Some(response);
        } else {
            self.count(|stats| stats.warned += 1)?;
            output.kind = OutcomeKind::Warned;
        }
        Ok(())
    }
}

enum Violation {
    Deny(String),
    Homoglyph,
    Budget(String),
    Prompt,
}

fn hostname_violation(request: Request<'_>, enabled: bool) -> Option<Violation> {
    if !enabled {
        return None;
    }
    let mut decoded = String::new();
    let domain = if request.decode_ace_for_inspection {
        // ACE case and HTTP request form do not change the represented Unicode
        // characters. This decoding never changes policy matching or routing.
        for (index, label) in request.host.split('.').enumerate() {
            if index != 0 {
                decoded.push('.');
            }
            if label
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
            {
                match crate::host_names::decode_punycode_label(&label[4..]) {
                    Ok(label) => decoded.push_str(&label),
                    Err(_) => return Some(Violation::Deny("Hostname inspection failed".into())),
                }
            } else {
                decoded.push_str(label);
            }
        }
        decoded.as_str()
    } else {
        request.host
    };
    dangerous_domain(domain).then_some(Violation::Homoglyph)
}

fn evaluate_policy(policy: &Policy, request: Request<'_>, now_ms: f64) -> PdpDecision {
    // Source and native policy both treat one DNS root dot as the same local probe.
    if crate::is_probe_host(request.host) {
        return PdpDecision {
            effect: PdpEffect::Allow,
            reason: "Internal pipeline probe (system-reserved)".into(),
            reason_codes: vec!["INTERNAL_PIPELINE_PROBE"],
            required_checks: vec![],
            budget_remaining: None,
        };
    }
    let decision = match policy.evaluate(request.policy_request(), now_ms, true) {
        Ok(decision) => decision,
        // Do not put parser/request text into a failure diagnostic. Native
        // PolicyError has no equivalent Python exception class.
        Err(_) => return pdp_error("Internal evaluation error: PolicyError".into()),
    };
    let (effect, reason, codes) = match decision.effect {
        Effect::Allow => (
            PdpEffect::Allow,
            "Decision: allow".into(),
            vec!["ALLOWED", "PERMISSION_NETWORK_REQUEST"],
        ),
        Effect::Deny => (
            PdpEffect::Deny,
            if decision.matched_resource.is_none() {
                "No matching permission (default deny)"
            } else {
                "Decision: deny"
            }
            .into(),
            vec!["DENIED"],
        ),
        Effect::Prompt => (
            PdpEffect::RequireApproval,
            "Decision: require_approval".into(),
            vec!["REQUIRE_APPROVAL"],
        ),
        Effect::BudgetExceeded => (
            PdpEffect::BudgetExceeded,
            format!("Request budget exceeded for {}", request.host),
            vec!["BUDGET_EXCEEDED", "RATE_LIMITED"],
        ),
        Effect::Budget => (PdpEffect::Error, "Decision: error".into(), vec![]),
    };
    PdpDecision {
        effect,
        reason,
        reason_codes: codes,
        required_checks: vec!["rate_limit"],
        budget_remaining: decision.budget_remaining,
    }
}
fn pdp_error(reason: String) -> PdpDecision {
    PdpDecision {
        effect: PdpEffect::Error,
        reason,
        reason_codes: vec!["PDP_ERROR", "INTERNAL_ERROR"],
        required_checks: vec![],
        budget_remaining: None,
    }
}

fn audit(
    request: Request<'_>,
    decision: AuditDecision,
    severity: Severity,
    summary: String,
    approval: Option<NetworkPrompt>,
    mut details: Value,
) -> AuditIntent {
    details["method"] = json!(request.method);
    details["port"] = json!(request.port);
    details["connection_id"] = json!(request.connection_id);
    AuditIntent {
        event: "security.network_guard",
        kind: "security",
        addon: "network-guard",
        decision,
        severity,
        summary,
        host: request.host.into(),
        agent: request.identity.agent().map(str::to_owned),
        request_id: request.request_id.map(str::to_owned),
        approval,
        details,
    }
}

#[derive(Deserialize)]
struct UnicodeData {
    common: u16,
    unknown: u16,
    scripts: Vec<(u32, u32, u16)>,
    confusables: Vec<(u32, u32)>,
    safe: Vec<(u32, u32)>,
}
fn unicode() -> &'static UnicodeData {
    static DATA: OnceLock<UnicodeData> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../data/network_guard/unicode.json"))
            .expect("validated generated Unicode tables")
    })
}
fn contains(ranges: &[(u32, u32)], character: char) -> bool {
    let point = character as u32;
    let index = ranges.partition_point(|(low, _)| *low <= point);
    index > 0 && point <= ranges[index - 1].1
}
fn alias(character: char) -> u16 {
    let data = unicode();
    let point = character as u32;
    let index = data.scripts.partition_point(|(low, _, _)| *low <= point);
    if index > 0 && point <= data.scripts[index - 1].1 {
        data.scripts[index - 1].2
    } else {
        data.unknown
    }
}

/// Exact is_dangerous(text) defaults from confusable-homoglyphs 3.3.1.
/// COMMON is ignored for script mixing, but can itself supply the confusable.
/// Unknown and inherited scripts participate; ASCII punycode stays ASCII.
pub fn dangerous_domain(domain: &str) -> bool {
    let mut first = None;
    let mut mixed = false;
    let mut confusable = false;
    for character in domain.chars() {
        let script = alias(character);
        if script != unicode().common {
            if let Some(first) = first {
                mixed |= script != first;
            } else {
                first = Some(script);
            }
        }
        confusable |= contains(&unicode().confusables, character);
    }
    mixed && confusable
}

/// Shipped audit_schema.sanitize_for_log for string inputs and max_len=200.
pub fn sanitize(value: &str) -> String {
    sanitize_with_limit(value, 200)
}

/// Reuse the source sanitizer for report fields with explicit display lengths.
pub(crate) fn sanitize_with_limit(value: &str, max_len: usize) -> String {
    static ANSI: OnceLock<regex::Regex> = OnceLock::new();
    let ansi = ANSI.get_or_init(|| regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap());
    let value = ansi.replace_all(value, "?");
    let mut output = String::new();
    let mut count = 0;
    let mut previous = None;
    for character in value.chars() {
        let safe = if contains(&unicode().safe, character) {
            character
        } else {
            '?'
        };
        if safe == '?' && previous == Some('?') {
            continue;
        }
        if count == max_len {
            output.push_str("...");
            break;
        }
        output.push(safe);
        count += 1;
        previous = Some(safe);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires existing Python production environment; set SAFEYOLO_POLICY_PYTHON"]
    fn unicode_tables_match_every_python_scalar() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let python =
            std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON");
        let script = r#"
import hashlib,json,struct,unicodedata
from confusable_homoglyphs import categories,confusables
from safeyolo.core.audit_schema import sanitize_for_log
assert unicodedata.unidata_version=='15.0.0'
aliases=categories.categories_data['iso_15924_aliases'];codes={name:index for index,name in enumerate(aliases)}
payload=bytearray();count=0
for point in range(0x110000):
 if 0xd800<=point<=0xdfff:continue
 character=chr(point)
 payload.extend(struct.pack('<HBB',codes.get(categories.alias(character),len(aliases)),bool(confusables.confusables_data.get(character)),sanitize_for_log(character)==character))
 count+=1
print(json.dumps({'sha256':hashlib.sha256(payload).hexdigest(),'count':count}))
"#;
        let output = std::process::Command::new(python)
            .arg("-c")
            .arg(script)
            .env(
                "PYTHONPATH",
                format!("{}:{}", root.join("cli/src").display(), root.display()),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut payload = Vec::new();
        let mut count = 0;
        for character in (0..=0x10ffff).filter_map(char::from_u32) {
            payload.extend_from_slice(&alias(character).to_le_bytes());
            payload.push(u8::from(contains(&unicode().confusables, character)));
            payload.push(u8::from(contains(&unicode().safe, character)));
            count += 1;
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, &payload)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(json!({"sha256":digest,"count":count}), expected);
        eprintln!(
            "network guard Unicode: {count} scalars match Python script, confusable membership and sanitizer classification"
        );
    }
}
