//! Development native Agent API reads, with one policy representation and no egress.
//!
//! The caller supplies reserved-host dispatch and reconciled transport identity.
//! This module owns method/auth/route ordering and reads the shared token anew
//! off the async worker. It returns local response and audit intent; the caller
//! owns actual audit persistence, response IDs and request scrubbing.
//!
//! `/policy` borrows the baseline published with the policy matcher and gateway
//! snapshot. Python surrogateescape query values cannot enter the
//! current scalar-string Policy API: these produce a typed compatibility failure,
//! never lossy replacement. This is an incomplete development API slice.

use std::{collections::HashMap, fs, path::Path};

use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

mod declarations;
mod discovery;
mod explain;
mod flows;
mod gateway;
mod memory;
mod trace;
pub use gateway::GatewayContext;
pub use memory::MemoryContext;

pub use declarations::{
    BodyObservation, Controls, DeclarationContext, RequestBody, TraceContext, respond_with_body,
    respond_with_body_and_audit_id,
};
pub use explain::ExplainFailure;
pub use flows::FlowFailure;

use crate::{
    network_guard::{Identity, sanitize},
    policy::{
        BudgetStatsError, Effect, EngineStatsError, NetworkRequest, Policy, python_whitespace,
    },
    python_text::{decimal, printable, uppercase},
};

const API_HOST: &str = "_safeyolo.proxy.internal";
const ENDPOINTS: &[&str] = &[
    "/health",
    "/status",
    "/policy",
    "/lookup",
    "/budgets",
    "/config",
    "/explain",
    "/trace",
    "/memory",
    "/agents",
    "/circuits",
    "/gateway/services",
    "/api/flows/search",
    "/api/test-context/current",
    "/api/flows/search",
    "/api/flows/endpoints",
    "/api/flows/facets",
    "/api/flows/body-search",
    "/api/flows/diff",
    "/api/flows/request-body-search",
    "/gateway/request-access",
    "/gateway/submit-binding",
    "/desktop/present",
    "/api/flows/{id}",
    "/api/flows/{id}/request-body",
    "/api/flows/{id}/response-body",
    "/api/flows/{id}/tag (POST)",
    "/api/flows/{id}/tag/{name} (DELETE)",
];

/// Authorization and query input are never exposed through Debug or Serialize.
/// The caller combines duplicate Authorization fields with `, `, as mitmproxy
/// does, and never obtains identity or the request ID from these headers.
///
/// ```compile_fail
/// use safeyolo_proxy::agent_api::Request;
/// fn cannot_log(request: Request<'_>) { println!("{request:?}"); }
/// ```
/// ```compile_fail
/// use safeyolo_proxy::agent_api::Request;
/// fn cannot_serialize(request: Request<'_>) { let _ = serde_json::to_string(&request); }
/// ```
#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub authorization: Option<&'a [u8]>,
    pub identity: Identity<'a>,
    pub client_ip: Option<&'a str>,
    pub request_id: &'a str,
}

/// A provider can report health without exposing a direct native engine.
/// NoEngine does not distinguish a remote client from a corrupted local client;
/// provider-specific status behavior remains a development compatibility gap.
pub enum PolicyState<'a> {
    Ready(&'a Policy),
    Unavailable,
    NoEngine { healthy: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    HandlerUnavailable,
    TokenEncoding,
    TokenTask,
    AuthenticationEncoding,
    AuditWrite,
    PolicyEvaluation,
    DevelopmentEndpoint,
    /// Source json.dumps cannot serialize a timestamp retained by the model.
    PolicySerialization,
    /// The source budget report failed during numeric conversion or key parsing.
    BudgetReporting,
    CircuitReporting(crate::circuits::ErrorKind),
    /// Native statistics failures retain their exact, content-free category.
    EngineReporting(EngineStatsError),
    TaskRegistry(crate::tasks::Error),
    /// A Python lone-surrogate query value cannot enter the current Policy API.
    QueryCompatibility,
    Declaration(crate::test_context::ContextErrorKind),
    ContentDecoding(crate::http_content::ContentError),
    FlowReporting(FlowFailure),
    ExplainReporting(ExplainFailure),
    DiscoveryReporting(crate::agent_discovery::ErrorKind),
    MemoryReporting(crate::memory_monitor::ErrorKind),
    TraceReporting(crate::trace::ErrorKind),
    GatewayReporting(crate::services::ServiceViewError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    AuthenticationFailed,
    HandlerUnavailable,
    TestContextDeclared,
    TestContextCleared,
}

/// Source event fields only. No token, Authorization or query is retained.
pub struct AuditIntent {
    pub kind: AuditKind,
    pub event: &'static str,
    pub severity: &'static str,
    pub addon: &'static str,
    pub summary: String,
    pub agent: Option<String>,
    pub request_id: Option<String>,
    pub host: Option<&'static str>,
    pub details: Value,
}

impl AuditIntent {
    /// Build only the four canonical Agent API producer envelopes. These source
    /// hooks supply neither an approval nor flow attribution. Declaration IDs
    /// are optional source-stage metadata, not the native ingress/backstop ID.
    pub fn to_event(&self) -> crate::audit::Event {
        use crate::audit::{Decision, Event, Kind, Severity};

        let (name, severity, addon, decision) = match self.kind {
            AuditKind::AuthenticationFailed => (
                "security.agent_auth_failed",
                Severity::High,
                "agent-api",
                Some(Decision::Deny),
            ),
            AuditKind::HandlerUnavailable => (
                "security.agent_api_unavailable",
                Severity::High,
                "agent-api-request-guard",
                Some(Decision::Deny),
            ),
            AuditKind::TestContextDeclared => (
                "security.test_context_declared",
                Severity::Low,
                "agent-api",
                None,
            ),
            AuditKind::TestContextCleared => (
                "security.test_context_cleared",
                Severity::Low,
                "agent-api",
                None,
            ),
        };
        let mut event = Event::new(name, Kind::Security, severity, self.summary.clone());
        event.addon = Some(addon.into());
        event.decision = decision;
        event.agent = self.agent.clone();
        event.request_id = self.request_id.clone();
        event.host = self.host.map(str::to_owned);
        event.details = self.details.clone().into();
        event
    }
}

/// Local API responses can contain authorized gateway tokens. Rendering is an
/// explicit operation; diagnostics and general serialization cannot expose them.
///
/// ```compile_fail
/// use safeyolo_proxy::agent_api::Response;
/// fn cannot_log(response: Response<'_>) { println!("{response:?}"); }
/// ```
/// ```compile_fail
/// use safeyolo_proxy::agent_api::Response;
/// fn cannot_serialize(response: Response<'_>) { let _ = serde_json::to_string(&response); }
/// ```
pub struct Response<'a> {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    body: ResponseBody<'a>,
}

enum ResponseBody<'a> {
    Json(Value),
    Policy(Option<&'a Value>),
    Circuit(Zeroizing<String>),
}

impl Drop for ResponseBody<'_> {
    fn drop(&mut self) {
        if let Self::Json(value) = self {
            crate::credentials::wipe_json(value);
        }
    }
}

impl Response<'_> {
    /// JSON bytes for the authorized local response. The Bytes owner zeroizes
    /// this allocation when its last body/frame reference is dropped. Hyper
    /// and the operating system may make their own transport copies.
    pub fn body_bytes(&self) -> bytes::Bytes {
        if let ResponseBody::Circuit(text) = &self.body {
            return bytes::Bytes::from_owner(Zeroizing::new(text.as_bytes().to_vec()));
        }
        let (value, wrapped) = match &self.body {
            ResponseBody::Json(value) => (value, false),
            ResponseBody::Policy(value) => (value.unwrap_or(&Value::Null), true),
            ResponseBody::Circuit(_) => unreachable!("typed circuit response handled above"),
        };
        let overhead = if wrapped { "{\"policy\": }".len() } else { 0 };
        let capacity = crate::python_json::encoded_len(value)
            .checked_add(overhead)
            .expect("JSON response length overflow");
        let mut output = Zeroizing::new(String::with_capacity(capacity));
        if wrapped {
            output.push_str("{\"policy\": ");
        }
        crate::python_json::write(value, &mut *output).expect("String writes cannot fail");
        if wrapped {
            output.push('}');
        }
        bytes::Bytes::from_owner(Zeroizing::new(std::mem::take(&mut *output).into_bytes()))
    }
}

/// Every outcome is a local terminal response, including compatibility failure.
pub struct Outcome<'a> {
    pub response: Response<'a>,
    pub audit: Option<AuditIntent>,
    pub blocked_by: &'static str,
    pub handler_owned: bool,
    /// Remove both auth headers and the query before any downstream observer.
    pub scrub_request: bool,
    pub failure: Option<Failure>,
    /// Source PolicyEngine increments its evaluation counter even for previews.
    pub policy_evaluations: u64,
    /// Status reads can transition stale circuits. The caller persists these
    /// intents without flow attribution, even if a later report operation fails.
    pub circuit_events: Vec<crate::circuits::Transition>,
}
impl Outcome<'_> {
    /// Native containment for an escaped authentication producer callback.
    /// The historical source fixture registered handler and guard separately;
    /// the production addon container may stop before its guard on that error.
    /// This helper does not claim that production dispatch behavior. Ordinary
    /// writer-thread sink failures must keep the original response. A failed
    /// containment audit cannot change its already local response.
    pub fn audit_failed(self, request: Request<'_>) -> Self {
        if self.audit.as_ref().map(|audit| audit.kind) == Some(AuditKind::AuthenticationFailed) {
            unavailable(request, Failure::AuditWrite)
        } else {
            self
        }
    }

    /// Apply a synchronous producer-submission failure before returning the
    /// local response. Declaration mutation is already committed: source's
    /// handler catches the exception and returns 500 without undoing it.
    /// Async file failures and successful queue-full/stopped results are not
    /// submission errors and must never call this method.
    pub fn audit_submission_failed(
        self,
        request: Request<'_>,
        error: crate::audit::ErrorKind,
    ) -> Self {
        match self.audit.as_ref().map(|audit| audit.kind) {
            Some(AuditKind::TestContextDeclared | AuditKind::TestContextCleared) => {
                let class = match error {
                    crate::audit::ErrorKind::Io => "OSError",
                    // Configuration/Encoding do not escape Writer::emit;
                    // retain a categorical native internal-error fallback.
                    crate::audit::ErrorKind::Configuration
                    | crate::audit::ErrorKind::Encoding
                    | crate::audit::ErrorKind::ThreadStart
                    | crate::audit::ErrorKind::Poisoned => "RuntimeError",
                };
                let mut outcome =
                    response(500, json!({"error":format!("Internal error: {class}")}));
                outcome.failure = Some(Failure::AuditWrite);
                outcome
            }
            _ => self.audit_failed(request),
        }
    }
}

fn agent(identity: Identity<'_>) -> Option<&str> {
    match identity {
        Identity::Resolved(value) => Some(value),
        _ => None,
    }
}
fn path_no_query(request: Request<'_>) -> &str {
    request.path_and_query.split('?').next().unwrap()
}
fn route(request: Request<'_>) -> &str {
    let path = path_no_query(request).trim_end_matches('/');
    if path.is_empty() { "/" } else { path }
}
fn response(status: u16, body: Value) -> Outcome<'static> {
    Outcome {
        response: Response {
            status,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("X-SafeYolo-Agent-API".into(), "true".into()),
            ],
            body: ResponseBody::Json(body),
        },
        audit: None,
        blocked_by: "agent-api",
        handler_owned: true,
        scrub_request: false,
        failure: None,
        policy_evaluations: 0,
        circuit_events: Vec::new(),
    }
}

/// Existing adjacent-guard response for an absent or failing API handler.
pub fn unavailable(request: Request<'_>, failure: Failure) -> Outcome<'static> {
    let path = path_no_query(request);
    let mut outcome = response(
        503,
        json!({
            "error":"SafeYolo Agent API handler unavailable",
            "reason_code":"agent_api_unavailable", "handler":"agent-api", "host":API_HOST,
            "path":path, "request_id":request.request_id,
        }),
    );
    outcome
        .response
        .headers
        .push(("X-SafeYolo-Request-Id".into(), request.request_id.into()));
    outcome.blocked_by = "agent-api-request-guard";
    outcome.handler_owned = false;
    outcome.scrub_request = true;
    outcome.failure = Some(failure);
    outcome.audit = Some(AuditIntent {
        kind: AuditKind::HandlerUnavailable,
        event: "security.agent_api_unavailable",
        severity: "high",
        addon: "agent-api-request-guard",
        summary: "Agent API handler unavailable; request contained locally".into(),
        agent: agent(request.identity).map(str::to_owned),
        request_id: Some(request.request_id.into()),
        host: Some(API_HOST),
        details: json!({"reason_code":"agent_api_unavailable", "handler":"agent-api",
                        "method":request.method, "path":path}),
    });
    outcome
}

enum Authentication {
    Accepted,
    Missing,
    Rejected,
    Failed(Failure),
}
async fn authenticate(path: &Path, supplied: &[u8]) -> Authentication {
    let path = path.to_owned();
    let supplied = Zeroizing::new(supplied.to_vec());
    tokio::task::spawn_blocking(move || {
        let bytes = match fs::read(path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return Authentication::Missing,
        };
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => return Authentication::Failed(Failure::TokenEncoding),
        };
        // Path.read_text uses universal newline conversion before str.strip.
        let mut token = Zeroizing::new(String::new());
        let mut chars = text.chars().peekable();
        while let Some(character) = chars.next() {
            if character == '\r' {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                token.push('\n');
            } else {
                token.push(character);
            }
        }
        let token = token.trim_matches(python_whitespace);
        if token.is_empty() {
            return Authentication::Missing;
        }
        if !token.is_ascii() || !supplied.is_ascii() {
            return Authentication::Failed(Failure::AuthenticationEncoding);
        }
        if bool::from(token.as_bytes().ct_eq(&supplied)) {
            Authentication::Accepted
        } else {
            Authentication::Rejected
        }
    })
    .await
    .unwrap_or(Authentication::Failed(Failure::TokenTask))
}

/// Method checks precede token I/O; authentication precedes route/identity/query.
/// The caller resolves a fresh policy snapshot and owns audit persistence. This
/// future has no outbound client and evaluates a request at most once.
pub async fn respond_read<'p>(
    request: Request<'_>,
    token_path: &Path,
    policy: PolicyState<'p>,
    tasks: &crate::tasks::Registry,
    now_ms: f64,
) -> Outcome<'p> {
    respond_read_with_circuits(request, token_path, policy, tasks, now_ms, None).await
}

/// A current borrowed circuit owner, with caller-owned time/randomness. Reading
/// its stats never refreshes settings from policy or increments request checks.
pub struct CircuitContext<'a> {
    pub audit: Option<&'a crate::audit::Writer>,
    pub breaker: &'a crate::circuits::CircuitBreaker,
    pub enabled: bool,
    pub random: &'a mut (dyn FnMut() -> f64 + Send),
}

pub async fn respond_read_with_circuits<'p>(
    request: Request<'_>,
    token_path: &Path,
    policy: PolicyState<'p>,
    tasks: &crate::tasks::Registry,
    now_ms: f64,
    circuits: Option<CircuitContext<'_>>,
) -> Outcome<'p> {
    if let Err(outcome) = authorize(request, token_path).await {
        return outcome;
    }
    if route(request) == "/explain" {
        return explain::respond(request, None).await;
    }
    if route(request) == "/trace" {
        return trace::respond(request, None);
    }
    if route(request) == "/gateway/services" {
        return gateway::respond(request, None);
    }
    authenticated_read(request, policy, tasks, now_ms, circuits)
}

fn valid_request_id(value: &str) -> bool {
    // Python's ^req-[a-f0-9]{32}$ accepts one terminal LF. Preserve it for
    // the exact retained-record lookup after validation.
    let value = value.strip_suffix('\n').unwrap_or(value);
    let Some(digits) = value.strip_prefix("req-") else {
        return false;
    };
    digits.len() == 32
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn authorize(request: Request<'_>, token_path: &Path) -> Result<(), Outcome<'static>> {
    let path = route(request);
    if !matches!(request.method, "GET" | "POST" | "DELETE") {
        return Err(response(
            405,
            json!({"error":"Method Not Allowed", "allowed":["GET","POST","DELETE"]}),
        ));
    }
    if matches!(request.method, "POST" | "DELETE")
        && !(path.starts_with("/api/flows")
            || path.starts_with("/gateway/")
            || path.starts_with("/plumb")
            || path.starts_with("/api/coord/")
            || path == "/api/test-context/current"
            || path == "/desktop/present")
    {
        return Err(response(
            405,
            json!({"error":"Method Not Allowed", "allowed":["GET"]}),
        ));
    }
    let Some(supplied) = request
        .authorization
        .and_then(|value| value.strip_prefix(b"Bearer "))
    else {
        return Err(response(
            401,
            json!({"error":"Authorization required", "hint":"Bearer <token>"}),
        ));
    };
    match authenticate(token_path, supplied).await {
        Authentication::Accepted => (),
        Authentication::Missing => {
            return Err(response(503, json!({"error":"Agent token not configured"})));
        }
        Authentication::Failed(failure) => return Err(unavailable(request, failure)),
        Authentication::Rejected => {
            let mut outcome = response(401, json!({"error":"Invalid agent token"}));
            outcome.audit = Some(AuditIntent {
                kind: AuditKind::AuthenticationFailed,
                event: "security.agent_auth_failed",
                severity: "high",
                addon: "agent-api",
                agent: None,
                request_id: None,
                host: None,
                summary: format!(
                    "Agent API auth failed from {}",
                    sanitize(request.client_ip.unwrap_or("unknown"))
                ),
                details: json!({"client_ip":request.client_ip.unwrap_or("unknown"), "path":sanitize(path)}),
            });
            return Err(outcome);
        }
    }
    Ok(())
}

fn authenticated_read<'p>(
    request: Request<'_>,
    policy: PolicyState<'p>,
    tasks: &crate::tasks::Registry,
    now_ms: f64,
    circuits: Option<CircuitContext<'_>>,
) -> Outcome<'p> {
    let path = route(request);
    if path == "/health" {
        let healthy = match policy {
            PolicyState::Ready(_) => true,
            PolicyState::Unavailable => false,
            PolicyState::NoEngine { healthy } => healthy,
        };
        return response(
            200,
            json!({"agent_api":"ok", "pdp":if healthy {"ok"} else {"unavailable"}}),
        );
    }
    if path == "/lookup" {
        return lookup(request, policy, now_ms);
    }
    if path == "/circuits" {
        return circuit_response(request, circuits, now_ms / 1000.0);
    }
    if path == "/status" {
        match policy {
            PolicyState::Ready(policy) => {
                // Preserve PDPCore.get_stats evaluation order. These reads use
                // the actual published policy and the operator's task registry;
                // they neither activate registered tasks nor evaluate requests.
                let policy_hash = policy.policy_hash();
                let task_policies = match tasks.count() {
                    Ok(count) => count,
                    Err(error) => return unavailable(request, Failure::TaskRegistry(error)),
                };
                return status_response(request, policy_hash, task_policies, policy.engine_stats());
            }
            PolicyState::Unavailable => {
                return response(503, json!({"error":"PDP not available"}));
            }
            PolicyState::NoEngine { .. } => (),
        }
    }
    if path == "/config" {
        match policy {
            PolicyState::Ready(policy) => {
                return match policy.sensor_config() {
                    Ok(config) => response(200, config),
                    Err(crate::policy::BaselineSerializationError::NonJsonTimestamp) => {
                        let mut outcome =
                            response(500, json!({"error":"Internal error: TypeError"}));
                        outcome.failure = Some(Failure::PolicySerialization);
                        outcome
                    }
                };
            }
            PolicyState::Unavailable => {
                return response(503, json!({"error":"PDP not available"}));
            }
            PolicyState::NoEngine { .. } => (),
        }
    }
    if path == "/budgets" {
        match policy {
            PolicyState::Ready(policy) => {
                return match policy.budget_stats(now_ms) {
                    Ok(stats) => response(200, stats),
                    Err(error @ (BudgetStatsError::Overflow | BudgetStatsError::InvalidKey)) => {
                        let error_type = match error {
                            BudgetStatsError::Overflow => "OverflowError",
                            _ => "ValueError",
                        };
                        let mut outcome = response(
                            500,
                            json!({"error":format!("Internal error: {error_type}")}),
                        );
                        outcome.failure = Some(Failure::BudgetReporting);
                        outcome
                    }
                    Err(BudgetStatsError::InvalidClock | BudgetStatsError::Poisoned) => {
                        unavailable(request, Failure::PolicyEvaluation)
                    }
                };
            }
            PolicyState::Unavailable => {
                return response(503, json!({"error":"PDP not available"}));
            }
            PolicyState::NoEngine { .. } => (),
        }
    }
    if path == "/policy" {
        match policy {
            PolicyState::Ready(policy) => match policy.baseline() {
                Ok(baseline) => {
                    let mut outcome: Outcome<'p> = response(200, Value::Null);
                    outcome.response.body = ResponseBody::Policy(baseline);
                    return outcome;
                }
                Err(crate::policy::BaselineSerializationError::NonJsonTimestamp) => {
                    let mut outcome = response(500, json!({"error":"Internal error: TypeError"}));
                    outcome.failure = Some(Failure::PolicySerialization);
                    return outcome;
                }
            },
            PolicyState::Unavailable => {
                return response(503, json!({"error":"PDP not available"}));
            }
            PolicyState::NoEngine { .. } => {
                let mut outcome = response(
                    503,
                    json!({"error":"Agent API endpoint unavailable in native development mode"}),
                );
                outcome.failure = Some(Failure::DevelopmentEndpoint);
                return outcome;
            }
        }
    }
    if ENDPOINTS.contains(&path)
        || path.starts_with("/api/flows/")
        || path.starts_with("/plumb")
        || path.starts_with("/api/coord/")
    {
        let mut outcome = response(
            503,
            json!({"error":"Agent API endpoint unavailable in native development mode"}),
        );
        outcome.failure = Some(Failure::DevelopmentEndpoint);
        return outcome;
    }
    response(404, json!({"error":"Not Found", "endpoints":ENDPOINTS}))
}

fn circuit_response(
    request: Request<'_>,
    context: Option<CircuitContext<'_>>,
    now: f64,
) -> Outcome<'static> {
    let Some(context) = context else {
        return response(503, json!({"error":"circuit-breaker addon not loaded"}));
    };
    let stats = if let Some(writer) = context.audit {
        context.breaker.stats_document_with_audit(
            context.enabled,
            now,
            &mut || (context.random)(),
            &crate::circuits::Audit::new(writer, None, None),
        )
    } else {
        context
            .breaker
            .stats_document(context.enabled, now, &mut || (context.random)())
    };
    let (rendered, events) = match stats {
        Ok(stats) => (stats.value.render_json(false), stats.events),
        Err(error) => {
            let events = error.events().to_vec();
            (Err(error), events)
        }
    };
    let mut outcome = match rendered {
        Ok(text) => {
            let mut outcome = response(200, Value::Null);
            outcome.response.body = ResponseBody::Circuit(Zeroizing::new(text));
            outcome
        }
        Err(error) => {
            use crate::circuits::ErrorKind;
            let name = match error.kind() {
                ErrorKind::Type => Some("TypeError"),
                ErrorKind::Value => Some("ValueError"),
                ErrorKind::Overflow => Some("OverflowError"),
                ErrorKind::ZeroDivision => Some("ZeroDivisionError"),
                ErrorKind::Audit(crate::audit::ErrorKind::Io) => Some("OSError"),
                ErrorKind::Audit(_) => Some("RuntimeError"),
                ErrorKind::Invalid | ErrorKind::Compatibility => None,
            };
            let failure = Failure::CircuitReporting(error.kind());
            if let Some(name) = name {
                let mut outcome = response(500, json!({"error":format!("Internal error: {name}")}));
                outcome.failure = Some(failure);
                outcome
            } else {
                unavailable(request, failure)
            }
        }
    };
    outcome.circuit_events = events;
    outcome
}

fn status_response(
    request: Request<'_>,
    policy_hash: String,
    task_policies: usize,
    engine_stats: Result<Value, EngineStatsError>,
) -> Outcome<'static> {
    match engine_stats {
        Ok(engine_stats) => response(
            200,
            json!({"engine_version":"pdp-0.1.0", "policy_hash":policy_hash,
                   "task_policies":task_policies, "engine_stats":engine_stats}),
        ),
        Err(error) => unavailable(request, Failure::EngineReporting(error)),
    }
}

enum Decoded {
    Scalar(String),
    SurrogateEscape,
}
impl Decoded {
    fn scalar(&self) -> Option<&str> {
        match self {
            Self::Scalar(value) => Some(value),
            Self::SurrogateEscape => None,
        }
    }
}
fn unquote(value: &str) -> Decoded {
    let source = value.as_bytes();
    let mut output = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        match source[index] {
            b'+' => output.push(b' '),
            b'%' if index + 2 < source.len() => {
                if let (Some(a), Some(b)) = (
                    (source[index + 1] as char).to_digit(16),
                    (source[index + 2] as char).to_digit(16),
                ) {
                    output.push((a * 16 + b) as u8);
                    index += 3;
                    continue;
                }
                output.push(source[index]);
            }
            _ => output.push(source[index]),
        }
        index += 1;
    }
    match String::from_utf8(output) {
        Ok(value) => Decoded::Scalar(value),
        Err(_) => Decoded::SurrogateEscape,
    }
}
fn query(request: Request<'_>) -> HashMap<String, Decoded> {
    // urllib.urlparse drops raw TAB/LF/CR globally and treats # as a fragment.
    let clean: String = request
        .path_and_query
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let query = clean
        .split('#')
        .next()
        .unwrap()
        .split_once('?')
        .map(|(_, tail)| tail)
        .unwrap_or("");
    let mut output = HashMap::new();
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        if let Decoded::Scalar(key) = unquote(key)
            && matches!(
                key.as_str(),
                "host" | "scheme" | "port" | "method" | "path" | "request_id"
            )
        {
            output.entry(key).or_insert_with(|| unquote(value));
        }
    }
    output
}
fn lookup(request: Request<'_>, policy: PolicyState<'_>, now_ms: f64) -> Outcome<'static> {
    let query = query(request);
    if query
        .get("host")
        .and_then(Decoded::scalar)
        .unwrap_or("surrogate")
        .is_empty()
        || !query.contains_key("host")
    {
        return response(
            400,
            json!({"error":"Missing 'host' parameter", "usage":"/lookup?host=example.com"}),
        );
    }
    let Some(agent) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let policy = match policy {
        PolicyState::Ready(policy) => policy,
        PolicyState::Unavailable => return response(503, json!({"error":"PDP not available"})),
        PolicyState::NoEngine { .. } => {
            return response(503, json!({"error":"Policy engine not available"}));
        }
    };
    let scheme = query
        .get("scheme")
        .map(|v| v.scalar())
        .unwrap_or(Some("https"));
    let scheme = scheme.map(str::to_ascii_lowercase);
    let Some(scheme) =
        scheme.filter(|value| matches!(value.as_str(), "http" | "https" | "ws" | "wss"))
    else {
        return response(
            400,
            json!({"error":"scheme must be http, https, ws or wss"}),
        );
    };
    let port = query.get("port").map(|v| v.scalar()).unwrap_or(Some(
        if matches!(scheme.as_str(), "http" | "ws") {
            "80"
        } else {
            "443"
        },
    ));
    let Some(port) = port else {
        return unavailable(request, Failure::QueryCompatibility);
    };
    let port = match parse_port(port) {
        Ok(port) => port,
        Err(error) => return response(400, json!({"error":error})),
    };
    let host = query.get("host").and_then(Decoded::scalar);
    let method = query
        .get("method")
        .map(|v| v.scalar())
        .unwrap_or(Some("GET"));
    let (Some(host), Some(method)) = (host, method) else {
        return unavailable(request, Failure::QueryCompatibility);
    };
    let method = uppercase(method);
    let path = query
        .get("path")
        .map(|v| v.scalar())
        .unwrap_or(Some(if method == "CONNECT" { "" } else { "/" }));
    let Some(path) = path else {
        return unavailable(request, Failure::QueryCompatibility);
    };
    let decision = policy.evaluate(
        NetworkRequest {
            agent: Some(agent),
            host,
            port: Some(port),
            method: &method,
            path,
        },
        now_ms,
        false,
    );
    let mut outcome = match decision {
        Ok(decision) => {
            let reason = if decision.effect == Effect::BudgetExceeded {
                format!("Request budget exceeded for {host}")
            } else if decision.matched_resource.is_none() {
                "No matching permission (default deny)".into()
            } else {
                String::new()
            };
            response(
                200,
                json!({"host":host,"port":port,"method":method,"path":path,"agent":agent,"effect":decision.effect,"reason":reason}),
            )
        }
        Err(_) => {
            let mut outcome = response(500, json!({"error":"Internal error: ValueError"}));
            outcome.failure = Some(Failure::PolicyEvaluation);
            outcome
        }
    };
    outcome.policy_evaluations = 1;
    outcome
}

// Shared Python string representation for API errors and circuit denial summaries.
pub(crate) fn repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut output = String::from(quote);
    for character in value.chars() {
        if character == quote || character == '\\' {
            output.push('\\');
            output.push(character);
        } else if matches!(character, '\t' | '\r' | '\n') {
            output.push_str(&character.escape_debug().to_string());
        } else if printable(character) {
            output.push(character);
        } else {
            let point = character as u32;
            output.push_str(&if point <= 255 {
                format!("\\x{point:02x}")
            } else if point <= 65535 {
                format!("\\u{point:04x}")
            } else {
                format!("\\U{point:08x}")
            });
        }
    }
    output.push(quote);
    output
}
fn parse_port(source: &str) -> Result<u16, String> {
    let invalid = || {
        format!(
            "invalid literal for int() with base 10: {}",
            repr(source).chars().take(200).collect::<String>()
        )
    };
    let value = source.trim_matches(char::is_whitespace);
    let negative = value.starts_with('-');
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let mut number = 0u32;
    let mut digits = 0usize;
    let mut previous_digit = false;
    for character in value.chars() {
        if let Some(digit) = decimal(character) {
            digits += 1;
            number = number.saturating_mul(10).saturating_add(digit);
            previous_digit = true;
        } else if character == '_' && previous_digit {
            previous_digit = false;
        } else {
            return Err(invalid());
        }
    }
    if !previous_digit {
        return Err(invalid());
    }
    // The pinned Python process uses its default integer-conversion limit.
    if digits > 4300 {
        return Err(format!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
        ));
    }
    if negative || number == 0 || number > 65535 {
        return Err("port must be an integer from 1 to 65535".into());
    }
    Ok(number as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reporting_failures_preserve_native_categories() {
        let request = Request {
            method: "GET",
            path_and_query: "/status?ignored=discarded",
            authorization: None,
            identity: Identity::Resolved("alice"),
            client_ip: None,
            request_id: "req-status-fixture",
        };
        for error in [EngineStatsError::PathEncoding, EngineStatsError::Poisoned] {
            let outcome = status_response(request, "synthetic-hash".into(), 2, Err(error));
            assert_eq!(outcome.response.status, 503);
            assert_eq!(outcome.failure, Some(Failure::EngineReporting(error)));
            assert_eq!(outcome.policy_evaluations, 0);
            assert!(!outcome.handler_owned && outcome.scrub_request);
            let body = outcome.response.body_bytes();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(!body.contains("synthetic-hash"));
            assert!(!body.contains("discarded"));
            assert!(!body.contains(&format!("{error:?}")));
        }
    }

    #[test]
    #[ignore = "requires pinned Python 3.12.14; set SAFEYOLO_POLICY_PYTHON"]
    fn scalar_upper_decimal_and_repr_match_every_python_scalar() {
        use ring::digest::{Context, SHA256};
        let mut upper = Context::new(&SHA256);
        let mut digit = Context::new(&SHA256);
        let mut representation = Context::new(&SHA256);
        let mut count = 0;
        for point in 0..=0x10ffff {
            let Some(character) = char::from_u32(point) else {
                continue;
            };
            upper.update(uppercase(&character.to_string()).as_bytes());
            upper.update(b"\0");
            digit.update(&[decimal(character).map_or(255, |value| value as u8)]);
            representation.update(repr(&character.to_string()).as_bytes());
            representation.update(b"\0");
            count += 1;
        }
        let hex = |context: Context| {
            context
                .finish()
                .as_ref()
                .iter()
                .map(|value| format!("{value:02x}"))
                .collect::<String>()
        };
        let actual = json!({"upper":hex(upper),"decimal":hex(digit),"repr":hex(representation),"count":count});
        let output = std::process::Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"))
            .args(["-c", r#"
import hashlib,json,platform,unicodedata
assert platform.python_version()=='3.12.14' and unicodedata.unidata_version=='15.0.0'
upper=hashlib.sha256();decimal=hashlib.sha256();representation=hashlib.sha256();count=0
for point in range(0x110000):
 if 0xd800<=point<=0xdfff: continue
 value=chr(point);count+=1
 upper.update(value.upper().encode());upper.update(b'\0')
 decimal.update(bytes([unicodedata.decimal(value,255)]))
 representation.update(repr(value).encode());representation.update(b'\0')
print(json.dumps({'upper':upper.hexdigest(),'decimal':decimal.hexdigest(),'repr':representation.hexdigest(),'count':count}))
"#]).output().unwrap();
        assert!(output.status.success());
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(count, 1_112_064);
    }
}
