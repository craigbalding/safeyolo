//! Authenticated operator operations on the management listener.
//!
//! The caller owns loopback binding, startup token loading, and transport
//! framing. The process owner retains admitted service mutation execution and
//! its audit attempt through shutdown. This facade neither activates tasks nor
//! accepts an agent identity. Other management routes remain unimplemented.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Frame},
    header::{self, HeaderMap},
};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Mutex as AsyncMutex, oneshot},
    task::JoinSet,
};
use zeroize::Zeroizing;

use crate::policy::{BudgetStatsError, Policy};
use crate::tasks::{self, Registry};

mod audit_events;
mod gateway;
mod services;
mod traffic;

/// These errors terminate the connection without a fabricated HTTP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    AuthenticationEncoding,
    NonObjectBody,
    BodyFraming,
    BodyRead,
    RegistryUnavailable,
    StatsReporting,
    TrafficReporting,
    ServiceMutation,
    ServiceRepresentation,
    BudgetReporting(BudgetStatsError),
    CircuitOperation(crate::circuits::ErrorKind),
    Audit(crate::audit::ErrorKind),
}

#[derive(Clone, Default)]
pub(crate) struct ServiceMutationOwner {
    state: Arc<AsyncMutex<ServiceMutationState>>,
}

#[derive(Default)]
struct ServiceMutationState {
    closing: bool,
    tasks: JoinSet<()>,
}

impl ServiceMutationOwner {
    /// Admit one blocking service mutation into the process owner. A caller
    /// may drop the receiver, but the owner retains and joins the work.
    pub(crate) async fn spawn_blocking(
        &self,
        work: impl FnOnce() -> Result<Outcome, Error> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<Outcome, Error>>, Error> {
        let (sender, receiver) = oneshot::channel();
        let mut state = self.state.lock().await;
        while state.tasks.try_join_next().is_some() {}
        if state.closing {
            return Err(Error::ServiceMutation);
        }
        state.tasks.spawn_blocking(move || {
            let _ = sender.send(work());
        });
        Ok(receiver)
    }

    /// Close admission before any process-owned mutation drain begins.
    pub(crate) async fn stop_admission(&self) {
        self.state.lock().await.closing = true;
    }

    /// Join every admitted mutation, including work whose request was
    /// canceled, before the process shuts down its audit writer.
    pub(crate) async fn drain(&self) {
        let mut state = self.state.lock().await;
        while let Some(result) = state.tasks.join_next().await {
            if let Err(error) = result {
                eprintln!("service mutation owner failed: {error}");
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::AuthenticationEncoding => "Operator authentication encoding failed",
            Self::NonObjectBody => "Operator request body is not an object",
            Self::BodyFraming => "Operator request framing failed",
            Self::BodyRead => "Operator request body read failed",
            Self::RegistryUnavailable => "Task registry unavailable",
            Self::StatsReporting => "Operator stats task failed",
            Self::TrafficReporting => "Operator traffic read failed",
            Self::ServiceMutation => "Operator service policy update failed",
            Self::ServiceRepresentation => "Operator service value is not representable",
            Self::BudgetReporting(_) => "Operator budget report unavailable",
            Self::CircuitOperation(_) => "Operator circuit operation failed",
            Self::Audit(_) => "Operator audit submission failed",
        })
    }
}

impl std::error::Error for Error {}

/// The caller supplies peer/path audit metadata. Reset retains only the selected
/// resource for authorized structured evidence; its owner wipes it on drop.
pub enum Audit {
    AuthenticationFailed,
    BudgetsReset(BudgetResetAudit),
    CircuitReset(CircuitResetAudit),
    TrafficScopeUpdated(TrafficScopeAudit),
    ServiceAuthorized(services::Authorization),
    ServiceRevoked(services::Revocation),
    TaskUpdated {
        task_id: String,
        permission_count: usize,
    },
    TaskCleared {
        task_id: String,
    },
    PolicyMutation(PolicyMutationAudit),
    PlumbMutation(PlumbMutationAudit),
    DesktopPresented(DesktopPresentationAudit),
    DesktopPresentationFailed(DesktopPresentationFailureAudit),
    ModeChanged {
        addon: String,
        mode: String,
        client_ip: String,
    },
}

/// Structured intent for one committed operator policy mutation. The details
/// are retained only until the canonical audit writer accepts the event.
pub struct PolicyMutationAudit {
    pub(super) event: &'static str,
    pub(super) summary: String,
    pub(super) details: Value,
}

/// A committed native plumb mutation. The details are retained only until the
/// canonical audit writer accepts the event.
pub struct PlumbMutationAudit {
    pub(super) event: &'static str,
    pub(super) summary: String,
    pub(super) details: Value,
    pub(super) agent: Option<String>,
    pub(super) decision: crate::audit::Decision,
}

pub struct DesktopPresentationAudit {
    pub(super) agent_id: String,
    pub(super) agent: String,
    pub(super) url: String,
    pub(super) reused: bool,
    pub(super) approval_request_id: Option<String>,
}

pub struct DesktopPresentationFailureAudit {
    pub(super) agent_id: String,
    pub(super) status: u16,
    pub(super) reason: &'static str,
    pub(super) approval_request_id: Option<String>,
}

impl Drop for PlumbMutationAudit {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.details);
    }
}

impl Drop for PolicyMutationAudit {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.details);
    }
}

/// The raw scope request is retained only for its canonical audit event.
pub struct TrafficScopeAudit {
    fields: Value,
}

impl Drop for TrafficScopeAudit {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.fields);
    }
}

/// A committed reset; evidence failure does not roll it back. No Debug or
/// Serialize implementation can accidentally reveal the selected resource.
pub struct BudgetResetAudit {
    resource: Value,
}

impl BudgetResetAudit {
    pub fn resource(&self) -> &Value {
        &self.resource
    }

    pub fn resets_all(&self) -> bool {
        !truthy(&self.resource)
    }

    pub fn safe_resource(&self) -> String {
        let text = match &self.resource {
            value if !truthy(value) => return "all".into(),
            Value::String(value) => return crate::network_guard::sanitize(value),
            Value::Bool(true) => "True".into(),
            // The shared renderer preserves Python float and arbitrary integer
            // presentation. Python str(infinity) differs from JSON's spelling.
            Value::Number(_) => {
                crate::python_json::encode(&self.resource).replace("Infinity", "inf")
            }
            _ => unreachable!("successful reset accepts only truthy scalars"),
        };
        crate::network_guard::sanitize(&Zeroizing::new(text))
    }
}

impl Drop for BudgetResetAudit {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.resource);
    }
}

/// A committed exact-key reset. The original scalar is needed for the source
/// response and audit; it is wiped when ownership ends and cannot be logged via
/// Debug or Serialize. Non-string hashable keys never match string state keys.
pub struct CircuitResetAudit {
    host: Value,
}

impl CircuitResetAudit {
    pub fn host(&self) -> &Value {
        &self.host
    }

    fn safe_host(&self) -> String {
        let text = Zeroizing::new(match &self.host {
            Value::String(value) => value.clone(),
            Value::Bool(true) => "True".into(),
            Value::Number(_) => crate::python_json::encode(&self.host)
                .replace("Infinity", "inf")
                .replace("NaN", "nan"),
            _ => unreachable!("only truthy hashable host keys commit"),
        });
        crate::network_guard::sanitize(&text)
    }

    pub fn events(&self, client_ip: &str) -> [Value; 2] {
        let safe_host = self.safe_host();
        // AuditEvent.host rejects non-string scalars. Source write_event then
        // preserves only its minimal fallback envelope for the reset event.
        let mut reset = json!({
            "event":"proxy.circuit", "audit_intent":"ops.circuit_breaker.reset",
            "kind":"ops", "severity":"medium", "summary":format!("Circuit reset for {safe_host}"),
        });
        if self.host.is_string() {
            reset["addon"] = json!("circuit-breaker");
            reset["host"] = self.host.clone();
            reset["details"] = json!({});
        }
        // The separate admin event accepts an Any host; Pydantic's JSON output
        // converts nonfinite numbers to null in this audit field only.
        let encoded = Zeroizing::new(crate::python_json::encode(&self.host));
        let audit_host = if matches!(encoded.as_str(), "NaN" | "Infinity" | "-Infinity") {
            Value::Null
        } else {
            self.host.clone()
        };
        [
            reset,
            json!({
                "event":"proxy.admin_api", "audit_intent":"admin.circuit_breaker_reset",
                "kind":"admin", "severity":"medium", "addon":"admin-api",
                "summary":format!("Circuit breaker reset: {safe_host}"),
                "details":{"client_ip":client_ip,"host":audit_host},
            }),
        ]
    }
}

impl Drop for CircuitResetAudit {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.host);
    }
}

/// Diagnostics cannot print the authorized raw response accidentally.
///
/// ```compile_fail
/// use safeyolo_proxy::admin_api::Outcome;
/// fn cannot_log(outcome: &Outcome) { println!("{outcome:?}"); }
/// ```
pub struct Outcome {
    response: Response<AdminBody>,
    audit: Option<Audit>,
}

pub(crate) type AdminBody = BoxBody<Bytes, Error>;

/// A bounded private export stream. The worker owns the source snapshot and
/// stops when the receiver is dropped; body errors abort the HTTP response
/// instead of claiming a complete artifact.
struct ExportBody {
    receiver: Mutex<tokio::sync::mpsc::Receiver<ExportEvent>>,
    terminal: bool,
}

enum ExportEvent {
    Chunk(Frame<Bytes>),
    Complete,
    Error(Error),
}

impl Body for ExportBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(None);
        }
        let event = {
            let mut receiver = this
                .receiver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Pin::new(&mut *receiver).poll_recv(cx)
        };
        match event {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(ExportEvent::Chunk(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(ExportEvent::Complete)) => {
                this.terminal = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(ExportEvent::Error(error))) => {
                this.terminal = true;
                Poll::Ready(Some(Err(error)))
            }
            // A producer panic, cancellation, or other abandonment closes the
            // channel without Complete. Treat that as truncation.
            Poll::Ready(None) => {
                this.terminal = true;
                Poll::Ready(Some(Err(Error::TrafficReporting)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::default()
    }
}

impl Outcome {
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }
    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }
    pub fn audit(&self) -> Option<&Audit> {
        self.audit.as_ref()
    }

    /// Explicitly hand the authorized bytes to the management transport.
    /// The allocation is wiped after its final Bytes owner drops; HTTP and OS
    /// transport copies are outside that owner. Do not log the returned body.
    pub fn into_response(self) -> Response<AdminBody> {
        self.response
    }
}

struct Json(Value);
impl Drop for Json {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.0);
    }
}

fn encoded(status: StatusCode, content_type: &'static str, body: String, head: bool) -> Outcome {
    let body = Zeroizing::new(body.into_bytes());
    let length = body.len();
    let bytes = if head {
        Bytes::new()
    } else {
        Bytes::from_owner(body)
    };
    Outcome {
        response: Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, length)
            .body(Full::new(bytes).map_err(|never| match never {}).boxed())
            .expect("fixed operator response fields"),
        audit: None,
    }
}

pub(super) fn export_response(plan: crate::traffic_view::ExportPlan) -> Outcome {
    let format = plan.format().name();
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    tokio::task::spawn_blocking(move || {
        let mut plan = plan;
        loop {
            match plan.next_chunk() {
                Ok(Some(chunk)) => {
                    let bytes = Bytes::from_owner(chunk);
                    if sender
                        .blocking_send(ExportEvent::Chunk(Frame::data(bytes)))
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = sender.blocking_send(ExportEvent::Complete);
                    break;
                }
                Err(_) => {
                    let _ = sender.blocking_send(ExportEvent::Error(Error::TrafficReporting));
                    break;
                }
            }
        }
    });
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"traffic.{}\"", format),
        )
        .body(
            ExportBody {
                receiver: Mutex::new(receiver),
                terminal: false,
            }
            .boxed(),
        )
        .expect("fixed export response fields");
    Outcome {
        response,
        audit: None,
    }
}

fn response(status: StatusCode, value: Value) -> Outcome {
    let value = Json(value);
    encoded(
        status,
        "application/json",
        crate::python_json::encode_indented(&value.0),
        false,
    )
}

fn plumb_response(mut value: Value) -> Outcome {
    let status = value
        .as_object_mut()
        .and_then(|object| object.remove("status"))
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response(status, value)
}

fn unsupported(method: &Method) -> Outcome {
    // BaseHTTPRequestHandler.send_error escapes the method in its HTML body.
    let method_text = method
        .as_str()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        <p>Error code: 501</p>\n        <p>Message: Unsupported method ('{method_text}').</p>\n        <p>Error code explanation: 501 - Server does not support this operation.</p>\n    </body>\n</html>\n"
    );
    let mut outcome = encoded(
        StatusCode::NOT_IMPLEMENTED,
        "text/html;charset=utf-8",
        body,
        method == Method::HEAD,
    );
    outcome.response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    outcome
}

fn path(uri: &hyper::Uri) -> &str {
    // BaseHTTPRequestHandler collapses leading slashes on origin-form request
    // targets before urlparse. An absolute target's path keeps its slashes.
    let path = uri.path();
    let path = if uri.scheme().is_none() && uri.authority().is_none() {
        let extra = path
            .bytes()
            .take_while(|byte| *byte == b'/')
            .count()
            .saturating_sub(1);
        &path[extra..]
    } else {
        path
    };
    // urlparse removes parameters only from the final path segment. It does
    // not decode percent escapes or remove a trailing slash from a task ID.
    // Absolute request targets use urllib.parse's existing uses_params table.
    // An unknown scheme keeps the semicolon in the path and therefore ID.
    if ![
        "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp", "rtsp", "rtsps", "rtspu",
        "sip", "sips", "mms", "sftp", "tel",
    ]
    .iter()
    .any(|scheme| uri.scheme_str().unwrap_or("").eq_ignore_ascii_case(scheme))
    {
        return path;
    }
    let segment = path.rfind('/').map_or(0, |index| index + 1);
    path[segment..]
        .find(';')
        .map_or(path, |index| &path[..segment + index])
}

pub(crate) fn authenticate(headers: &HeaderMap, expected: &str) -> Result<bool, Error> {
    if expected.is_empty() {
        return Ok(false);
    }
    // BaseHTTPRequestHandler's HTTPMessage.get selects the first occurrence.
    // This differs from the agent proxy facade's combined Authorization value.
    let Some(provided) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
    else {
        return Ok(false);
    };
    if !provided.is_ascii() || !expected.is_ascii() {
        return Err(Error::AuthenticationEncoding);
    }
    Ok(bool::from(provided.ct_eq(expected.as_bytes())))
}

pub(crate) fn unauthorized() -> Outcome {
    let mut outcome = response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error":"Unauthorized", "message":"Missing or invalid Bearer token",
            "hint":"Add header: Authorization: Bearer <token>"
        }),
    );
    outcome.audit = Some(Audit::AuthenticationFailed);
    outcome
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn mode_document(modes: &crate::OperatorModes) -> Value {
    let mut values = serde_json::Map::new();
    for addon in ["network-guard", "credential-guard", "pattern-scanner"] {
        let Some(options) = modes.options(addon) else {
            continue;
        };
        let any_blocking = options.iter().any(|(_, value)| *value);
        values.insert(
            addon.into(),
            Value::String(if any_blocking { "block" } else { "warn" }.into()),
        );
    }
    Value::Object(values)
}

fn operator_mode(modes: &crate::OperatorModes, addon: &str) -> Option<Outcome> {
    let options = modes.options(addon)?;
    let mode = if options.iter().any(|(_, value)| *value) {
        "block"
    } else {
        "warn"
    };
    let options = options
        .into_iter()
        .map(|(name, value)| (name.to_owned(), Value::Bool(value)))
        .collect::<serde_json::Map<_, _>>();
    Some(response(
        StatusCode::OK,
        json!({"addon":addon,"mode":mode,"options":options}),
    ))
}

fn parse_mode(data: &Value) -> Option<&str> {
    data.as_object()
        .and_then(|object| object.get("mode"))
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "warn" | "block"))
}

fn mutation(event: &'static str, summary: impl Into<String>, details: Value) -> Audit {
    Audit::PolicyMutation(PolicyMutationAudit {
        event,
        summary: summary.into(),
        details,
    })
}

fn desktop_failure(
    agent_id: &str,
    status: StatusCode,
    reason: &'static str,
    message: &'static str,
    approval_request_id: Option<&str>,
) -> Outcome {
    let mut outcome = response(status, json!({"error":message}));
    outcome.audit = Some(Audit::DesktopPresentationFailed(
        DesktopPresentationFailureAudit {
            agent_id: agent_id.to_owned(),
            status: status.as_u16(),
            reason,
            approval_request_id: approval_request_id.map(str::to_owned),
        },
    ));
    outcome
}
/// Build the canonical operator plumb events while the process-owned mailbox
/// worker still owns the committed projection and its audit responsibility.
pub(crate) fn plumb_events(
    event: &'static str,
    summary: String,
    details: Value,
    agent: Option<String>,
    decision: crate::audit::Decision,
) -> Vec<crate::audit::Event> {
    // PlumbMutation's retained event schema has no operator peer/path fields;
    // canonical_events intentionally ignores those two common arguments.
    Audit::PlumbMutation(PlumbMutationAudit {
        event,
        summary,
        details,
        agent,
        decision,
    })
    .canonical_events("", "")
}

fn require_policy_path(path: Option<&Path>) -> Result<&Path, Box<Outcome>> {
    path.ok_or_else(|| {
        Box::new(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"native policy path is unavailable"}),
        ))
    })
}

fn policy_error(error: impl std::fmt::Display) -> Outcome {
    // Policy parser diagnostics can contain authored values. Expose only the
    // stable operator-facing category; the canonical audit retains no input.
    let _ = error;
    response(StatusCode::BAD_REQUEST, json!({"error":"invalid policy"}))
}

async fn get_baseline(policy: Option<&Policy>, path: Option<&Path>) -> Outcome {
    let Some(policy) = policy else {
        return response(
            StatusCode::NOT_FOUND,
            json!({"error":"No baseline policy loaded"}),
        );
    };
    match policy.baseline() {
        Ok(Some(value)) => response(
            StatusCode::OK,
            json!({"baseline":value,"path":path.map(Path::display).map(|value| value.to_string())}),
        ),
        Ok(None) => response(
            StatusCode::NOT_FOUND,
            json!({"error":"No baseline policy loaded"}),
        ),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"baseline response unavailable"}),
        ),
    }
}

fn read_audit_events(path: &Path) -> Vec<Value> {
    let Ok(source) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    source
        .lines()
        .rev()
        .take(50_000)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn approval_key(event: &Value) -> Option<String> {
    let approval = event.get("approval")?.as_object()?;
    let key = approval.get("key")?.as_str()?;
    let target = approval.get("target")?.as_str()?;
    Some(format!("{key}:{target}"))
}

fn credential_resolution_key(credential: &str, destination: &str) -> String {
    if let Some(service) = destination.strip_prefix("gateway:") {
        let mut parts = credential.splitn(3, ':');
        if let (Some(agent), Some(method), Some(path)) = (parts.next(), parts.next(), parts.next())
        {
            return format!("gw:{agent}:{service}:{method}:{path}:{service}");
        }
    }
    format!("{credential}:{destination}")
}

fn resolved_approval_keys(event: &Value) -> Vec<String> {
    let Some(event_name) = event.get("event").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Some(details) = event.get("details").and_then(Value::as_object) else {
        return Vec::new();
    };
    match event_name {
        "admin.approval_added" | "admin.denial" => {
            let destination = details.get("destination").and_then(Value::as_str);
            let Some(destination) = destination else {
                return Vec::new();
            };
            match details.get("cred_id") {
                Some(Value::String(credential)) => {
                    vec![credential_resolution_key(credential, destination)]
                }
                Some(Value::Array(credentials)) => credentials
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|credential| credential_resolution_key(credential, destination))
                    .collect(),
                _ => Vec::new(),
            }
        }
        "admin.gateway_grant" => {
            let agent = details
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let service = details
                .get("service")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if agent.is_empty() || service.is_empty() {
                return Vec::new();
            }
            let method = details
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let path = details
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            vec![format!("gw:{agent}:{service}:{method}:{path}:{service}")]
        }
        "admin.agent_service_authorized" | "admin.agent_service_revoked" => {
            let agent = details
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let service = details
                .get("service")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if agent.is_empty() || service.is_empty() {
                Vec::new()
            } else {
                vec![format!("{agent}:{service}:{service}")]
            }
        }
        "admin.contract_binding_approved" => {
            let agent = details
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let service = details
                .get("service")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let capability = details
                .get("capability")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if agent.is_empty() || service.is_empty() || capability.is_empty() {
                Vec::new()
            } else {
                vec![format!("{agent}:{service}:{capability}:{service}")]
            }
        }
        "admin.host_allowed" | "admin.host_denied" => {
            let Some(host) = details.get("host").and_then(Value::as_str) else {
                return Vec::new();
            };
            let agent = details.get("agent").and_then(Value::as_str);
            let port = details
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok());
            crate::approvals::NetworkScope::new(host, agent, port)
                .ok()
                .and_then(|scope| scope.resolved_key().ok())
                .into_iter()
                .collect()
        }
        "plumb.approved" | "plumb.denied" => {
            let Some(request_id) = details.get("request_id").and_then(Value::as_str) else {
                return Vec::new();
            };
            let Some(participants) = details.get("participants").and_then(Value::as_array) else {
                return Vec::new();
            };
            let participants = participants
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if participants.is_empty() {
                Vec::new()
            } else {
                vec![format!("{request_id}:{}", participants.join(","))]
            }
        }
        "admin.desktop_presented" => details
            .get("agent_id")
            .and_then(Value::as_str)
            .filter(|agent_id| !agent_id.is_empty())
            .map(|agent_id| format!("desktop.present:desktop:{agent_id}"))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn pending_approvals(path: &Path) -> Value {
    let events = read_audit_events(path);
    let mut durable_resolutions = std::collections::HashSet::new();
    let mut pending: std::collections::HashMap<String, (usize, Value)> =
        std::collections::HashMap::new();
    // `read_audit_events` returns newest first. Walk it chronologically so the
    // same durable-resolution semantics as the retained Python watcher apply
    // to both an earlier prompt and a later retry.
    for (sequence, event) in events.iter().rev().enumerate() {
        for key in resolved_approval_keys(event) {
            let repeatable = key.starts_with("desktop.present:desktop:");
            if repeatable {
                let Some((_, prompt)) = pending.get(&key) else {
                    continue;
                };
                let request_matches = event
                    .get("details")
                    .and_then(Value::as_object)
                    .and_then(|details| details.get("approval_request_id"))
                    .and_then(Value::as_str)
                    .is_none_or(|request_id| {
                        prompt.get("request_id").and_then(Value::as_str) == Some(request_id)
                    });
                if request_matches {
                    pending.remove(&key);
                }
            } else {
                durable_resolutions.insert(key.clone());
                pending.remove(&key);
            }
        }
        let Some(approval) = event.get("approval") else {
            continue;
        };
        if !approval
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let Some(key) = approval_key(event) else {
            continue;
        };
        if durable_resolutions.contains(&key) {
            continue;
        }
        pending.insert(key, (sequence, event.clone()));
    }
    let mut pending = pending.into_values().collect::<Vec<_>>();
    pending.sort_unstable_by_key(|(sequence, _)| *sequence);
    Value::Array(pending.into_iter().map(|(_, event)| event).collect())
}

fn json_toml_value(value: &Value) -> std::result::Result<toml_edit::Value, ()> {
    Ok(match value {
        Value::String(value) => toml_edit::Value::from(value.clone()),
        Value::Bool(value) => toml_edit::Value::from(*value),
        Value::Number(value) if value.is_i64() => toml_edit::Value::from(value.as_i64().ok_or(())?),
        Value::Number(value) if value.is_u64() => {
            toml_edit::Value::from(i64::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?)
        }
        Value::Number(value) => toml_edit::Value::from(value.as_f64().ok_or(())?),
        Value::Array(values) => {
            let mut array = toml_edit::Array::new();
            for value in values {
                array.push(json_toml_value(value)?);
            }
            toml_edit::Value::Array(array)
        }
        Value::Object(values) => {
            let mut table = toml_edit::InlineTable::new();
            for (key, value) in values {
                table.insert(key.clone(), json_toml_value(value)?);
            }
            toml_edit::Value::InlineTable(table)
        }
        Value::Null => return Err(()),
    })
}

fn json_toml_document(value: &Value) -> std::result::Result<toml_edit::DocumentMut, ()> {
    let object = value.as_object().ok_or(())?;
    let mut document = toml_edit::DocumentMut::new();
    for (key, value) in object {
        document.insert(key, toml_edit::Item::Value(json_toml_value(value)?));
    }
    Ok(document)
}

enum ParsedBody {
    Absent,
    Value(Json),
    Terminal(Outcome),
}

async fn read_json<B: Body<Data = Bytes>>(request: Request<B>) -> Result<ParsedBody, Error> {
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(Error::BodyFraming)
        })
        .transpose()?
        .unwrap_or(0);
    if length == 0 {
        return Ok(ParsedBody::Absent);
    }
    let bytes = request
        .into_body()
        .collect()
        .await
        .map_err(|_| Error::BodyRead)?
        .to_bytes();
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(error) => {
            return Ok(ParsedBody::Terminal(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"Malformed JSON in request body","detail":error.to_string()}),
            )));
        }
    };
    let data = match crate::policy::parse_json(text, false) {
        Ok(value) => Json(value),
        Err(error) => {
            return Ok(ParsedBody::Terminal(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"Malformed JSON in request body","detail":error.to_string()}),
            )));
        }
    };
    Ok(ParsedBody::Value(data))
}

fn budget_report(policy: &Policy, now_ms: f64) -> Result<Outcome, Error> {
    policy
        .budget_stats(now_ms)
        .map(|value| response(StatusCode::OK, value))
        .map_err(Error::BudgetReporting)
}

async fn reset_budgets<B: Body<Data = Bytes>>(
    request: Request<B>,
    policy: &Policy,
) -> Result<Outcome, Error> {
    let mut data = match read_json(request).await? {
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => Json(Value::Null),
        ParsedBody::Value(data) => data,
    };
    let resource = if truthy(&data.0) {
        data.0
            .as_object_mut()
            .ok_or(Error::NonObjectBody)?
            .get_mut("resource")
            .map(Value::take)
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let audit = BudgetResetAudit { resource };
    if policy.reset_budgets(Some(audit.resource())).is_err() {
        return Ok(response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"Failed to reset budget counters"}),
        ));
    }
    let resource = if audit.resets_all() {
        Value::String("all".into())
    } else {
        audit.resource().clone()
    };
    let mut outcome = response(
        StatusCode::OK,
        json!({"status":"ok", "resource":resource, "reset_count":0}),
    );
    outcome.audit = Some(Audit::BudgetsReset(audit));
    Ok(outcome)
}

async fn reset_circuit<B: Body<Data = Bytes>>(
    request: Request<B>,
    circuits: Option<&crate::circuits::CircuitBreaker>,
) -> Result<Outcome, Error> {
    let mut data = match read_json(request).await? {
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => Json(Value::Null),
        ParsedBody::Value(data) => data,
    };
    if !truthy(&data.0) {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing request body"}),
        ));
    }
    let host = data
        .0
        .as_object_mut()
        .ok_or(Error::NonObjectBody)?
        .get_mut("host")
        .map(Value::take)
        .unwrap_or(Value::Null);
    let audit = CircuitResetAudit { host };
    if !truthy(audit.host()) {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing 'host' field"}),
        ));
    }
    let Some(circuits) = circuits else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"circuit breaker not available"}),
        ));
    };
    circuits
        .reset_json_key(audit.host())
        .map_err(|error| Error::CircuitOperation(error.kind()))?;
    let mut outcome = response(
        StatusCode::OK,
        json!({"status":"reset", "host":audit.host()}),
    );
    outcome.audit = Some(Audit::CircuitReset(audit));
    Ok(outcome)
}

/// HTTP framing is supplied by the listener. Unknown/negative/overflow lengths
/// rejected by Hyper are a separate transport compatibility difference.
/// Body parsing occurs only after method, authentication, route and empty-ID
/// checks. Startup token bytes are borrowed and never copied into an outcome.
pub async fn respond<B>(
    request: Request<B>,
    expected_token: &str,
    registry: &Registry,
    policy: Option<&Policy>,
) -> Result<Outcome, Error>
where
    B: Body<Data = Bytes>,
{
    respond_with_circuits(request, expected_token, registry, policy, None).await
}

pub async fn respond_with_circuits<B>(
    request: Request<B>,
    expected_token: &str,
    registry: &Registry,
    policy: Option<&Policy>,
    circuits: Option<&crate::circuits::CircuitBreaker>,
) -> Result<Outcome, Error>
where
    B: Body<Data = Bytes>,
{
    respond_with_stats(request, expected_token, registry, policy, circuits, None).await
}

/// The runtime reports its installed addon counters only after authentication.
/// Existing standalone callers need not install a statistics provider.
pub(crate) async fn respond_with_stats<B>(
    request: Request<B>,
    expected_token: &str,
    registry: &Registry,
    policy: Option<&Policy>,
    circuits: Option<&crate::circuits::CircuitBreaker>,
    stats: Option<&(dyn Fn() -> tokio::task::JoinHandle<crate::circuits::CircuitValue> + Sync)>,
) -> Result<Outcome, Error>
where
    B: Body<Data = Bytes>,
{
    respond_with_view(
        request,
        expected_token,
        registry,
        policy,
        circuits,
        stats,
        None,
    )
    .await
}

/// Accepted writer and request attribution copied into the service worker.
pub(crate) struct ServiceAudit<'a> {
    pub writer: &'a std::sync::Arc<crate::audit::Writer>,
    pub client_ip: &'a str,
    pub target: &'a str,
    pub mutation_owner: &'a ServiceMutationOwner,
    pub gateway_store: Option<&'a crate::grants::Store>,
}

/// Borrowed owners from one accepted runtime snapshot. Disk policy updates
/// persist configuration; the existing runtime watcher owns later activation.
pub(crate) struct OperatorContext<'a> {
    pub tasks: &'a Registry,
    pub policy: Option<&'a Policy>,
    pub circuits: Option<&'a crate::circuits::CircuitBreaker>,
    pub stats:
        Option<&'a (dyn Fn() -> tokio::task::JoinHandle<crate::circuits::CircuitValue> + Sync)>,
    pub view: Option<&'a std::sync::Arc<crate::traffic_view::TrafficView>>,
    pub policy_path: Option<&'a std::path::Path>,
    pub instance_id: Option<&'a str>,
    pub admin_address: Option<SocketAddr>,
    pub operator_modes: Option<&'a crate::OperatorModes>,
    pub agent_discovery: Option<&'a std::sync::Arc<crate::agent_discovery::AgentDiscovery>>,
    pub listeners: &'a [crate::AgentListener],
    pub audit: Option<&'a std::sync::Arc<crate::audit::Writer>>,
    pub client_ip: Option<&'a str>,
    pub passthrough: Option<&'a std::sync::RwLock<crate::tunnels::Passthrough>>,
    pub service_audit: Option<ServiceAudit<'a>>,
    pub plumb: Option<&'a crate::agent_api::plumb::PlumbOwner>,
    /// The listener supplies the outer state so task activation can publish a
    /// complete Runtime generation. Unit callers without it retain the raw
    /// registration-only behavior.
    pub task_state: Option<&'a crate::RuntimeState>,
}

/// The shared view uses the same operator authentication as other private reads.
pub(crate) async fn respond_with_view<B>(
    request: Request<B>,
    expected_token: &str,
    registry: &Registry,
    policy: Option<&Policy>,
    circuits: Option<&crate::circuits::CircuitBreaker>,
    stats: Option<&(dyn Fn() -> tokio::task::JoinHandle<crate::circuits::CircuitValue> + Sync)>,
    view: Option<&std::sync::Arc<crate::traffic_view::TrafficView>>,
) -> Result<Outcome, Error>
where
    B: Body<Data = Bytes>,
{
    respond_with_context(
        request,
        expected_token,
        OperatorContext {
            tasks: registry,
            policy,
            circuits,
            stats,
            view,
            policy_path: None,
            instance_id: None,
            admin_address: None,
            operator_modes: None,
            agent_discovery: None,
            listeners: &[],
            audit: None,
            client_ip: None,
            passthrough: None,
            service_audit: None,
            plumb: None,
            task_state: None,
        },
    )
    .await
}

pub(crate) async fn respond_with_context<B: Body<Data = Bytes>>(
    request: Request<B>,
    expected_token: &str,
    context: OperatorContext<'_>,
) -> Result<Outcome, Error> {
    let OperatorContext {
        tasks: registry,
        policy,
        circuits,
        stats,
        view,
        policy_path,
        instance_id,
        admin_address,
        operator_modes,
        agent_discovery,
        listeners,
        audit,
        client_ip,
        passthrough,
        service_audit,
        plumb,
        task_state,
    } = context;
    let method = request.method();
    if !matches!(
        *method,
        Method::GET | Method::PUT | Method::POST | Method::DELETE
    ) {
        return Ok(unsupported(method));
    }
    let path = path(request.uri()).to_owned();
    if method == Method::GET && path == "/health" {
        return Ok(response(StatusCode::OK, json!({"status":"ok"})));
    }
    if !authenticate(request.headers(), expected_token)? {
        let mut outcome = response(
            StatusCode::UNAUTHORIZED,
            json!({
                "error":"Unauthorized", "message":"Missing or invalid Bearer token",
                "hint":"Add header: Authorization: Bearer <token>"
            }),
        );
        outcome.audit = Some(Audit::AuthenticationFailed);
        return Ok(outcome);
    }
    if method == Method::GET && path == "/admin/runtime-identity" {
        let Some(instance_id) = instance_id else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"schema_version":1,"state":"unknown","error":"runtime identity was not initialised"}),
            ));
        };
        return Ok(response(
            StatusCode::OK,
            json!({"schema_version":1,"state":"active","instance_id":instance_id}),
        ));
    }
    if method == Method::PUT && path == "/admin/proxy/ignore-hosts" {
        let Some(passthrough) = passthrough else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"native passthrough configuration unavailable"}),
            ));
        };
        let data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"missing request body"}),
                ));
            }
            ParsedBody::Value(data) => data,
        };
        let Some(values) = data.0.get("hosts").and_then(Value::as_array) else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"hosts must be a list of HOST or HOST:PORT strings"}),
            ));
        };
        let mut hosts = Vec::with_capacity(values.len());
        for value in values {
            let Some(host) = value.as_str() else {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"hosts must be a list of HOST or HOST:PORT strings"}),
                ));
            };
            hosts.push(host.to_owned());
        }
        let normalized = match crate::tunnels::Passthrough::normalize_hosts(&hosts) {
            Ok(normalized) => normalized,
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"invalid passthrough host"}),
                ));
            }
        };
        let replacement = match crate::tunnels::Passthrough::new(
            &normalized,
            &std::env::var("SAFEYOLO_IGNORE_CIDRS").unwrap_or_default(),
        ) {
            Ok(replacement) => replacement,
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"invalid passthrough host"}),
                ));
            }
        };
        let active_pattern_count = passthrough
            .write()
            .map(|mut current| {
                *current = replacement;
                current.pattern_count()
            })
            .map_err(|_| Error::RegistryUnavailable)?;
        let operator_entry_count = normalized.len();
        let mut outcome = response(
            StatusCode::OK,
            json!({
                "status":"updated",
                "hosts":normalized.clone(),
                "operator_entry_count":operator_entry_count,
                "pattern_count":active_pattern_count
            }),
        );
        outcome.audit = Some(mutation(
            "admin.proxy_ignore_hosts_update",
            format!(
                "Proxy TLS passthrough list replaced ({operator_entry_count} operator entries, {active_pattern_count} active patterns)"
            ),
            json!({
                "hosts":normalized,
                "operator_entry_count":operator_entry_count,
                "pattern_count":active_pattern_count
            }),
        ));
        return Ok(outcome);
    }
    if method == Method::GET && path == "/admin/instance" {
        let Some(instance_id) = instance_id else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"operator instance identity unavailable"}),
            ));
        };
        return Ok(response(
            StatusCode::OK,
            json!({
                "schema_version":1,
                "safeyolo_instance_id":instance_id,
                "host_user":Value::Null,
                "host_python":Value::Null,
                "webmitm_url":Value::Null,
                "command_centre_events":{"enabled":audit.is_some(),"port":admin_address.map(|address| address.port())},
                "capabilities":{
                    "agent_inventory":agent_discovery.is_some(),
                    "agent_lifecycle":false,
                    "approvals":true,
                    "audit_events":audit.is_some(),
                    "desktop_present":crate::desktop_present::available()
                }
            }),
        ));
    }
    if method == Method::GET && path == "/admin/approvals" {
        return Ok(response(
            StatusCode::OK,
            json!({"approvals":audit.map(|writer| pending_approvals(writer.path())).unwrap_or_else(|| Value::Array(Vec::new()))}),
        ));
    }
    if method == Method::GET && path == "/admin/plumb/pending" {
        let Some(owner) = plumb else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"plumb backing state unavailable"}),
            ));
        };
        if !owner.available() {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"plumb backing state unavailable"}),
            ));
        }
        return Ok(plumb_response(owner.list_pending().await));
    }
    if method == Method::GET && path == "/admin/plumb/conversations" {
        let Some(owner) = plumb else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"plumb backing state unavailable"}),
            ));
        };
        if !owner.available() {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"plumb backing state unavailable"}),
            ));
        }
        return Ok(plumb_response(owner.admin_list_conversations().await));
    }
    if method == Method::POST
        && matches!(
            path.as_str(),
            "/admin/plumb/approve" | "/admin/plumb/deny" | "/admin/plumb/close"
        )
    {
        let data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Value::Null,
            ParsedBody::Value(data) => data.0.clone(),
        };
        let Some(fields) = data.as_object() else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"request body must be an object"}),
            ));
        };
        let Some(owner) = plumb else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"plumb backing state unavailable"}),
            ));
        };
        if !owner.available() {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"plumb backing state unavailable"}),
            ));
        }
        let writer = audit.cloned();
        let result = match path.as_str() {
            "/admin/plumb/approve" => {
                let Some(request_id) = fields
                    .get("request_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"missing 'request_id'"}),
                    ));
                };
                let operator_ttl = fields.get("ttl_seconds").and_then(|value| match value {
                    Value::Number(value) => value.as_i64(),
                    Value::String(value) => value.parse().ok(),
                    _ => None,
                });
                owner
                    .approve_owned(request_id.to_owned(), operator_ttl, writer.clone())
                    .await?
            }
            "/admin/plumb/deny" => {
                let Some(request_id) = fields
                    .get("request_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"missing 'request_id'"}),
                    ));
                };
                owner
                    .deny_owned(request_id.to_owned(), writer.clone())
                    .await?
            }
            _ => {
                let Some(conversation_id) = fields
                    .get("conversation_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"missing 'conversation_id'"}),
                    ));
                };
                owner
                    .close_owned(conversation_id.to_owned(), writer.clone())
                    .await?
            }
        };
        return Ok(plumb_response(result));
    }
    if method == Method::GET && path == "/admin/agents" {
        let (Some(discovery), Some(writer)) = (agent_discovery, audit) else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"agent inventory unavailable"}),
            ));
        };
        let agents = discovery
            .get_agents(writer, crate::circuit_runtime::now)
            .map_err(|_| Error::RegistryUnavailable)?
            .render_json(false)
            .map_err(|_| Error::RegistryUnavailable)?;
        let agents: Value =
            serde_json::from_str(&agents).map_err(|_| Error::RegistryUnavailable)?;
        let discovered = agents
            .get("agents")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let agents = Value::Array(
            listeners
                .iter()
                .map(|listener| {
                    let mut entry = serde_json::Map::new();
                    entry.insert("agent_id".into(), Value::String(listener.agent_id.clone()));
                    entry.insert(
                        "socket_path".into(),
                        Value::String(listener.socket_path.to_string_lossy().into_owned()),
                    );
                    entry.insert("status".into(), Value::String("configured".into()));
                    if let Value::Object(discovered) = &discovered
                        && let Some(Value::Object(info)) = discovered.get(&listener.agent_id)
                    {
                        if let Some(ip) = info.get("ip") {
                            entry.insert("ip".into(), ip.clone());
                        }
                        if let Some(last_seen) = info.get("last_seen") {
                            entry.insert("last_seen".into(), last_seen.clone());
                        }
                    }
                    Value::Object(entry)
                })
                .collect(),
        );
        return Ok(encoded(
            StatusCode::OK,
            "application/json",
            crate::python_json::encode_indented(&json!({"agents":agents})),
            false,
        ));
    }
    if method == Method::POST
        && let Some(agent_id) = path
            .strip_prefix("/admin/agents/")
            .and_then(|value| value.strip_suffix("/desktop/present"))
        && !agent_id.contains('/')
    {
        if !crate::desktop_present::valid_agent_id(agent_id) {
            return Ok(desktop_failure(
                agent_id,
                StatusCode::BAD_REQUEST,
                "invalid_agent_id",
                "invalid agent id",
                None,
            ));
        }
        if !listeners
            .iter()
            .any(|listener| listener.agent_id == agent_id)
        {
            return Ok(desktop_failure(
                agent_id,
                StatusCode::NOT_FOUND,
                "agent_not_found",
                "Agent not found",
                None,
            ));
        }
        let data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Value::Null,
            ParsedBody::Value(data) => data.0.clone(),
        };
        let approval_request_id = match data {
            Value::Null => None,
            Value::Object(fields) => match fields.get("approval_request_id") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.is_empty() && value.len() <= 128 => {
                    Some(value.clone())
                }
                Some(_) => {
                    return Ok(desktop_failure(
                        agent_id,
                        StatusCode::BAD_REQUEST,
                        "invalid_approval_request_id",
                        "approval_request_id must be a non-empty string",
                        None,
                    ));
                }
            },
            _ => {
                return Ok(desktop_failure(
                    agent_id,
                    StatusCode::BAD_REQUEST,
                    "invalid_body",
                    "request body must be an object",
                    None,
                ));
            }
        };
        let result = match crate::desktop_present::present(agent_id.to_owned()).await {
            Ok(value) => value,
            Err(crate::desktop_present::Error::NotFound) => {
                return Ok(desktop_failure(
                    agent_id,
                    StatusCode::NOT_FOUND,
                    "agent_not_found",
                    "Agent not found",
                    approval_request_id.as_deref(),
                ));
            }
            Err(crate::desktop_present::Error::Unavailable) => {
                return Ok(desktop_failure(
                    agent_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "desktop_presenter_unavailable",
                    "desktop presenter is unavailable",
                    approval_request_id.as_deref(),
                ));
            }
            Err(crate::desktop_present::Error::Failed) => {
                return Ok(desktop_failure(
                    agent_id,
                    StatusCode::CONFLICT,
                    "desktop_presentation_failed",
                    "Desktop presentation failed",
                    approval_request_id.as_deref(),
                ));
            }
            Err(crate::desktop_present::Error::Protocol) => {
                return Ok(desktop_failure(
                    agent_id,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "desktop_presenter_protocol",
                    "desktop presenter returned an invalid result",
                    approval_request_id.as_deref(),
                ));
            }
        };
        let Some(fields) = result.as_object() else {
            return Ok(desktop_failure(
                agent_id,
                StatusCode::INTERNAL_SERVER_ERROR,
                "desktop_presenter_protocol",
                "desktop presenter returned an invalid result",
                approval_request_id.as_deref(),
            ));
        };
        let audit = Audit::DesktopPresented(DesktopPresentationAudit {
            agent_id: agent_id.to_owned(),
            agent: fields
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or(agent_id)
                .to_owned(),
            url: fields
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            reused: fields
                .get("reused")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            approval_request_id,
        });
        let mut outcome = response(StatusCode::OK, result);
        outcome.audit = Some(audit);
        return Ok(outcome);
    }
    if method == Method::GET && path == "/modes" {
        let Some(modes) = operator_modes else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"operator mode state unavailable"}),
            ));
        };
        return Ok(response(
            StatusCode::OK,
            json!({"modes":mode_document(modes)}),
        ));
    }
    if method == Method::GET
        && let Some(addon) = path
            .strip_prefix("/plugins/")
            .and_then(|path| path.strip_suffix("/mode"))
    {
        let Some(modes) = operator_modes else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"operator mode state unavailable"}),
            ));
        };
        return Ok(operator_mode(modes, addon).unwrap_or_else(|| {
            response(
                StatusCode::NOT_FOUND,
                json!({"error":format!("addon '{addon}' not found or doesn't support mode switching")}),
            )
        }));
    }
    if (method == Method::PUT && path == "/modes")
        || (method == Method::PUT && path.starts_with("/plugins/") && path.ends_with("/mode"))
    {
        let Some(modes) = operator_modes else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"operator mode state unavailable"}),
            ));
        };
        let addon = if path == "/modes" {
            None
        } else {
            path.strip_prefix("/plugins/")
                .and_then(|path| path.strip_suffix("/mode"))
        };
        let data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        let Some(mode) = parse_mode(&data.0) else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"mode must be 'warn' or 'block'"}),
            ));
        };
        let mode = mode.to_owned();
        let block = mode == "block";
        let addons = addon.map_or_else(
            || vec!["network-guard", "credential-guard", "pattern-scanner"],
            |addon| vec![addon],
        );
        if addons.iter().any(|addon| modes.options(addon).is_none()) {
            return Ok(response(
                StatusCode::NOT_FOUND,
                json!({"error":"addon not found or doesn't support mode switching"}),
            ));
        }
        for addon in &addons {
            modes.set(addon, block);
        }
        let results = addons
            .iter()
            .map(|addon| ((*addon).to_owned(), Value::String("updated".into())))
            .collect::<serde_json::Map<_, _>>();
        let mut outcome = response(
            StatusCode::OK,
            if let Some(addon) = addon {
                let options = modes
                    .options(addon)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(name, _)| (name.to_owned(), Value::Bool(block)))
                    .collect::<serde_json::Map<_, _>>();
                json!({"addon":addon,"mode":mode,"options":options,"status":"updated"})
            } else {
                json!({"status":"updated","mode":mode,"results":results})
            },
        );
        // Keep the audit payload independent of the mutable response view.
        outcome.audit = Some(if let Some(addon) = addon {
            Audit::ModeChanged {
                addon: addon.into(),
                mode,
                client_ip: client_ip.unwrap_or_default().to_owned(),
            }
        } else {
            Audit::ModeChanged {
                addon: "all".into(),
                mode,
                client_ip: client_ip.unwrap_or_default().to_owned(),
            }
        });
        return Ok(outcome);
    }
    if method == Method::GET && path == "/admin/policy/baseline" {
        return Ok(get_baseline(policy, policy_path).await);
    }
    if method == Method::POST && path == "/admin/policy/validate" {
        let mut data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        let Some(content) = data
            .0
            .as_object_mut()
            .and_then(|object| object.remove("content"))
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'content' field"}),
            ));
        };
        let Some(content) = content.as_str() else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"content must be a string"}),
            ));
        };
        return Ok(match Policy::parse(content, crate::policy::Format::Yaml) {
            Ok(_) => response(StatusCode::OK, json!({"valid":true})),
            Err(error) => policy_error(error),
        });
    }
    if method == Method::POST && path == "/admin/policy/baseline/approve" {
        let mut data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        let fields = data.0.as_object_mut().ok_or(Error::NonObjectBody)?;
        let Some(destination) = fields
            .get("destination")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'destination' field"}),
            ));
        };
        let Some(credential_value) = fields.get("cred_id") else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'cred_id' field"}),
            ));
        };
        let credentials = match credential_value {
            Value::String(value) if !value.is_empty() => vec![value.clone()],
            Value::Array(values)
                if !values.is_empty()
                    && values
                        .iter()
                        .all(|value| value.as_str().is_some_and(|value| !value.is_empty())) =>
            {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }
            _ => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"'cred_id' must be a non-empty string or list of strings"}),
                ));
            }
        };
        let tier = fields
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("explicit");
        if !matches!(tier, "explicit" | "inferred") {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"tier must be 'explicit' or 'inferred'"}),
            ));
        }
        let path = match require_policy_path(policy_path) {
            Ok(path) => path,
            Err(outcome) => return Ok(*outcome),
        };
        let count = match crate::approvals::allow_credentials(
            path,
            destination,
            &credentials,
            |_| Ok(()),
        ) {
            Ok(count) => count,
            Err(error) => return Ok(policy_error(error)),
        };
        let mut outcome = response(
            StatusCode::OK,
            json!({"status":"added","destination":destination,"cred_id":credential_value,"tier":tier,"permission_count":count}),
        );
        outcome.audit = Some(mutation(
            "admin.approval_added",
            format!(
                "Baseline approval added for {}",
                crate::network_guard::sanitize(destination)
            ),
            json!({"client_ip":client_ip,"destination":destination,"cred_id":credential_value,"tier":tier}),
        ));
        return Ok(outcome);
    }
    if method == Method::POST && path == "/admin/policy/baseline/deny" {
        let mut data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        let fields = data.0.as_object_mut().ok_or(Error::NonObjectBody)?;
        let Some(destination) = fields
            .get("destination")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'destination' field"}),
            ));
        };
        let Some(credential) = fields
            .get("cred_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'cred_id' field"}),
            ));
        };
        let reason = fields
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("user_denied");
        let approval_request_id = fields
            .get("approval_request_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let mut outcome = response(
            StatusCode::OK,
            json!({"status":"logged","destination":destination,"cred_id":credential,"reason":reason}),
        );
        let mut details = json!({
            "client_ip":client_ip,
            "destination":destination,
            "cred_id":credential,
            "reason":reason
        });
        if let Some(approval_request_id) = approval_request_id {
            details["approval_request_id"] = Value::String(approval_request_id.to_owned());
        }
        outcome.audit = Some(mutation(
            "admin.denial",
            format!(
                "Credential denied for {}",
                crate::network_guard::sanitize(destination)
            ),
            details,
        ));
        return Ok(outcome);
    }
    if method == Method::PUT && path == "/admin/policy/baseline" {
        let mut data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        let Some(policy_data) = data
            .0
            .as_object_mut()
            .and_then(|object| object.remove("policy"))
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'policy' field in request body"}),
            ));
        };
        let path = match require_policy_path(policy_path) {
            Ok(path) => path,
            Err(outcome) => return Ok(*outcome),
        };
        let document = match json_toml_document(&policy_data) {
            Ok(document) => document,
            Err(()) => return Ok(policy_error("policy contains a TOML-incompatible value")),
        };
        let candidate = match Policy::parse(&document.to_string(), crate::policy::Format::Toml) {
            Ok(policy) => policy,
            Err(error) => return Ok(policy_error(error)),
        };
        let permission_count = candidate.baseline_permissions_count().unwrap_or(0);
        let saved = crate::approvals::update_policy(
            path,
            false,
            |current, _| {
                *current = document;
                Ok(())
            },
            |_| Ok(()),
        );
        if let Err(error) = saved {
            return Ok(policy_error(error));
        }
        let mut outcome = response(
            StatusCode::OK,
            json!({"status":"updated","permission_count":permission_count,"message":"Baseline policy updated"}),
        );
        outcome.audit = Some(mutation(
            "admin.baseline_update",
            format!("Baseline policy updated: {permission_count} permissions"),
            json!({"client_ip":client_ip,"permission_count":permission_count}),
        ));
        return Ok(outcome);
    }
    if method == Method::POST
        && matches!(
            path.as_str(),
            "/admin/policy/host/allow"
                | "/admin/policy/host/deny"
                | "/admin/policy/host/rate"
                | "/admin/policy/host/bypass"
        )
    {
        let mut data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        let fields = data.0.as_object_mut().ok_or(Error::NonObjectBody)?;
        let Some(host) = fields
            .get("host")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing 'host' field"}),
            ));
        };
        let port = match fields.get("port") {
            None | Some(Value::Null) => None,
            Some(Value::Number(value)) => match value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value > 0)
            {
                Some(value) => Some(value),
                None => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"port must be an integer from 1 to 65535"}),
                    ));
                }
            },
            _ => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"port must be an integer from 1 to 65535"}),
                ));
            }
        };
        let agent = fields.get("agent").and_then(Value::as_str);
        let scope = match crate::approvals::NetworkScope::new(host, agent, port) {
            Ok(scope) => scope,
            Err(error) => return Ok(policy_error(error)),
        };
        let policy_file = match require_policy_path(policy_path) {
            Ok(path) => path,
            Err(outcome) => return Ok(*outcome),
        };
        let (body, event, body_value) = match path.as_str() {
            "/admin/policy/host/allow" => {
                let rate = fields.get("rate").and_then(Value::as_u64);
                match crate::approvals::allow_host(policy_file, &scope, rate, |_| Ok(())) {
                    Ok(result) => (
                        response(
                            StatusCode::OK,
                            json!({"status":"added","host":result.host,"rate":result.rate,"agent":result.agent,"port":result.port}),
                        ),
                        "admin.host_allowed",
                        json!({"client_ip":client_ip,"host":result.host,"rate":result.rate,"agent":result.agent,"port":result.port}),
                    ),
                    Err(error) => return Ok(policy_error(error)),
                }
            }
            "/admin/policy/host/deny" => {
                let expires = fields.get("expires").and_then(Value::as_str);
                match crate::approvals::deny_host(policy_file, &scope, expires, |_| Ok(())) {
                    Ok(result) => (
                        response(
                            StatusCode::OK,
                            json!({"status":"denied","host":result.host,"expires":result.expires,"agent":result.agent,"port":result.port}),
                        ),
                        "admin.host_denied",
                        json!({"client_ip":client_ip,"host":result.host,"expires":result.expires,"agent":result.agent,"port":result.port}),
                    ),
                    Err(error) => return Ok(policy_error(error)),
                }
            }
            "/admin/policy/host/rate" => {
                let Some(rate) = fields
                    .get("rate")
                    .and_then(Value::as_u64)
                    .filter(|value| *value > 0)
                else {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"'rate' must be a positive integer"}),
                    ));
                };
                match crate::approvals::update_host_rate(policy_file, &scope, rate, |_| Ok(())) {
                    Ok(old) => (
                        response(
                            StatusCode::OK,
                            json!({"status":"updated","host":host,"old_rate":old,"new_rate":rate}),
                        ),
                        "admin.host_rate_updated",
                        json!({"client_ip":client_ip,"host":host,"old_rate":old,"new_rate":rate}),
                    ),
                    Err(error) => return Ok(policy_error(error)),
                }
            }
            _ => {
                let Some(addon) = fields
                    .get("addon")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"missing 'addon' field"}),
                    ));
                };
                match crate::approvals::add_host_bypass(policy_file, &scope, addon, |_| Ok(())) {
                    Ok(bypass) => (
                        response(
                            StatusCode::OK,
                            json!({"status":"updated","host":host,"bypass":bypass}),
                        ),
                        "admin.host_bypass_added",
                        json!({"client_ip":client_ip,"host":host,"addon":addon,"bypass":bypass}),
                    ),
                    Err(error) => return Ok(policy_error(error)),
                }
            }
        };
        let mut outcome = body;
        outcome.audit = Some(mutation(event, "Operator host policy updated", body_value));
        return Ok(outcome);
    }
    if method == Method::POST
        && let Some(agent) = services::agent_path(&path)
    {
        let agent = agent.to_owned();
        return services::authorize(request, agent, policy, policy_path, service_audit).await;
    }
    if method == Method::DELETE
        && let Some((agent, service)) = services::revocation_path(&path)
    {
        return services::revoke(
            request,
            agent.to_owned(),
            service.to_owned(),
            policy_path,
            service_audit,
        )
        .await;
    }
    if path == "/admin/gateway/grant"
        || path == "/admin/gateway/grants"
        || path == "/admin/gateway/contract-binding"
        || path.starts_with("/admin/gateway/grants/")
    {
        return gateway::respond(request, &path, service_audit.as_ref()).await;
    }
    if path.starts_with("/admin/traffic/") {
        let path = path.to_owned();
        return traffic::respond(request, &path, view).await;
    }
    if method == Method::GET
        && path == "/stats"
        && let Some(stats) = stats
    {
        let body = stats()
            .await
            .map_err(|_| Error::StatsReporting)?
            .render_json(true)
            .map_err(|error| Error::CircuitOperation(error.kind()))?;
        return Ok(encoded(StatusCode::OK, "application/json", body, false));
    }
    if method == Method::POST && path == "/admin/circuit-breaker/reset" {
        return reset_circuit(request, circuits).await;
    }
    if (method == Method::GET && path == "/admin/budgets")
        || (method == Method::POST && path == "/admin/budgets/reset")
    {
        let Some(policy) = policy else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"Operator budget endpoint unavailable with the temporary policy adapter"}),
            ));
        };
        return if method == Method::GET {
            budget_report(policy, crate::policy::current_time_ms())
        } else {
            reset_budgets(request, policy).await
        };
    }
    let task_path = path.strip_prefix("/admin/policy/task/");
    if !matches!(
        *method,
        Method::GET | Method::PUT | Method::POST | Method::DELETE
    ) || task_path.is_none()
    {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"not found"}),
        ));
    }
    let task_path = task_path.expect("task route checked");
    if method == Method::POST
        && let Some(task_id) = task_path.strip_suffix("/activate")
    {
        if task_id.is_empty() {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing task_id"}),
            ));
        }
        let Some(state) = task_state else {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"task activation unavailable"}),
            ));
        };
        let permission_count = match crate::activate_registered_task(state, task_id) {
            Ok(count) => count,
            Err(crate::TaskPolicyActivationError::Registry(tasks::Error::NotFound)) => {
                return Ok(response(
                    StatusCode::NOT_FOUND,
                    json!({"error":format!("Task policy '{task_id}' not found")}),
                ));
            }
            Err(crate::TaskPolicyActivationError::Registry(
                tasks::Error::InvalidId | tasks::Error::InvalidPolicy,
            ))
            | Err(crate::TaskPolicyActivationError::Invalid) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"invalid task policy"}),
                ));
            }
            Err(crate::TaskPolicyActivationError::Registry(tasks::Error::Poisoned))
            | Err(crate::TaskPolicyActivationError::Unavailable) => {
                return Err(Error::RegistryUnavailable);
            }
        };
        let mut outcome = response(
            StatusCode::OK,
            json!({
                "status":"activated", "task_id":task_id, "permission_count":permission_count,
                "message":"Task policy activated"
            }),
        );
        outcome.audit = Some(Audit::TaskUpdated {
            task_id: task_id.to_owned(),
            permission_count,
        });
        return Ok(outcome);
    }
    if method == Method::POST {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"not found"}),
        ));
    }
    let task_id = task_path;
    if task_id.is_empty() {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing task_id"}),
        ));
    }
    if method == Method::GET {
        let task = registry
            .get(task_id)
            .map_err(|_| Error::RegistryUnavailable)?;
        return Ok(match task {
            Some(task) => {
                let task_id = Value::String(task_id.into());
                let text = crate::python_json::encode_indented_fields(&[
                    ("task_id", &task_id),
                    ("policy", task.document()),
                ]);
                encoded(StatusCode::OK, "application/json", text, false)
            }
            None => response(
                StatusCode::NOT_FOUND,
                json!({"error":format!("Task policy '{task_id}' not found")}),
            ),
        });
    }
    if method == Method::DELETE {
        let removed = if let Some(state) = task_state {
            match crate::clear_registered_task(state, task_id) {
                Ok(removed) => removed,
                Err(crate::TaskPolicyActivationError::Registry(tasks::Error::InvalidId)) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"Invalid task ID"}),
                    ));
                }
                Err(crate::TaskPolicyActivationError::Registry(tasks::Error::Poisoned))
                | Err(crate::TaskPolicyActivationError::Unavailable) => {
                    return Err(Error::RegistryUnavailable);
                }
                Err(crate::TaskPolicyActivationError::Invalid) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid task policy"}),
                    ));
                }
                Err(crate::TaskPolicyActivationError::Registry(
                    tasks::Error::InvalidPolicy | tasks::Error::NotFound,
                )) => unreachable!("clear does not validate or look up a missing task"),
            }
        } else {
            registry
                .clear(task_id)
                .map_err(|_| Error::RegistryUnavailable)?
        };
        if !removed {
            return Ok(response(
                StatusCode::NOT_FOUND,
                json!({"error":format!("Task policy '{task_id}' not found")}),
            ));
        }
        let mut outcome = response(
            StatusCode::OK,
            json!({"status":"cleared","task_id":task_id,"message":"Task policy cleared"}),
        );
        outcome.audit = Some(Audit::TaskCleared {
            task_id: task_id.to_owned(),
        });
        return Ok(outcome);
    }
    let task_id = task_id.to_owned();
    let mut data = match read_json(request).await? {
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => Json(Value::Null),
        ParsedBody::Value(data) => data,
    };
    if !truthy(&data.0) {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing request body"}),
        ));
    }
    let object = data.0.as_object_mut().ok_or(Error::NonObjectBody)?;
    let Some(raw) = object.get_mut("policy").filter(|value| !value.is_null()) else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing 'policy' field in request body"}),
        ));
    };
    let upsert = match task_state {
        Some(state) => match crate::register_task(state, &task_id, raw.take()) {
            Ok(result) => result,
            Err(crate::TaskPolicyActivationError::Registry(
                error @ (tasks::Error::InvalidId | tasks::Error::InvalidPolicy),
            )) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":error.to_string()}),
                ));
            }
            Err(crate::TaskPolicyActivationError::Registry(tasks::Error::Poisoned))
            | Err(crate::TaskPolicyActivationError::Unavailable) => {
                return Err(Error::RegistryUnavailable);
            }
            Err(crate::TaskPolicyActivationError::Invalid)
            | Err(crate::TaskPolicyActivationError::Registry(tasks::Error::NotFound)) => {
                unreachable!("registration does not activate or look up tasks")
            }
        },
        None => match registry.upsert(&task_id, raw.take()) {
            Ok(result) => result,
            Err(error @ (tasks::Error::InvalidId | tasks::Error::InvalidPolicy)) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":error.to_string()}),
                ));
            }
            Err(tasks::Error::Poisoned) => return Err(Error::RegistryUnavailable),
            Err(tasks::Error::NotFound) => unreachable!("registration cannot miss a task"),
        },
    };
    let mut outcome = response(
        StatusCode::OK,
        json!({
            "status":"updated", "task_id":task_id, "permission_count":upsert.permission_count,
            "message":"Task policy updated"
        }),
    );
    outcome.audit = Some(Audit::TaskUpdated {
        task_id,
        permission_count: upsert.permission_count,
    });
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "synthetic-operator-fixture";

    #[test]
    fn source_final_segment_parameters_preserve_other_path_bytes() {
        for (target, expected) in [
            ("//health", "/health"),
            ("///health", "/health"),
            ("http://owned.invalid//health", "//health"),
            (
                "///admin/policy/task/a;ignored?unused=yes",
                "/admin/policy/task/a",
            ),
            (
                "//admin/policy/task/a;x/b?unused=yes",
                "/admin/policy/task/a;x/b",
            ),
            (
                "//admin/policy/task/%61;ignored?unused=yes",
                "/admin/policy/task/%61",
            ),
            ("/admin/policy/task/a;ignored", "/admin/policy/task/a"),
            ("/admin/policy/task/a;x/b", "/admin/policy/task/a;x/b"),
            ("/admin/policy/task/;x", "/admin/policy/task/"),
            ("/admin/policy/task/%61;foo", "/admin/policy/task/%61"),
            (
                "http://owned.invalid/admin/policy/task/a;ignored",
                "/admin/policy/task/a",
            ),
            (
                "FTP://owned.invalid/admin/policy/task/a;ignored",
                "/admin/policy/task/a",
            ),
            (
                "custom://owned.invalid/admin/policy/task/a;ignored",
                "/admin/policy/task/a;ignored",
            ),
        ] {
            assert_eq!(path(&target.parse().unwrap()), expected);
        }
    }

    fn request(method: &str, path: &str, body: &[u8]) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_LENGTH, body.len())
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap()
    }

    async fn body(outcome: Outcome) -> Bytes {
        let response = outcome.into_response();
        let length = response.headers()[header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), length);
        bytes
    }

    fn export_body(receiver: tokio::sync::mpsc::Receiver<ExportEvent>) -> ExportBody {
        ExportBody {
            receiver: Mutex::new(receiver),
            terminal: false,
        }
    }

    #[tokio::test]
    async fn export_body_publishes_eof_only_after_explicit_completion() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(ExportEvent::Chunk(Frame::data(Bytes::from_static(
                b"complete",
            ))))
            .await
            .unwrap();
        sender.send(ExportEvent::Complete).await.unwrap();
        drop(sender);

        let bytes = export_body(receiver).collect().await.unwrap().to_bytes();
        assert_eq!(bytes, Bytes::from_static(b"complete"));
    }

    #[tokio::test]
    async fn export_body_rejects_producer_disappearance_and_explicit_error() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(ExportEvent::Chunk(Frame::data(Bytes::from_static(
                b"partial",
            ))))
            .await
            .unwrap();
        drop(sender);
        assert!(matches!(
            export_body(receiver).collect().await,
            Err(Error::TrafficReporting)
        ));

        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(ExportEvent::Chunk(Frame::data(Bytes::from_static(
                b"partial",
            ))))
            .await
            .unwrap();
        sender
            .send(ExportEvent::Error(Error::TrafficReporting))
            .await
            .unwrap();
        assert!(matches!(
            export_body(receiver).collect().await,
            Err(Error::TrafficReporting)
        ));
    }

    #[tokio::test]
    async fn export_body_drop_closes_the_bounded_producer_channel() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        drop(export_body(receiver));
        assert!(sender.send(ExportEvent::Complete).await.is_err());
    }

    #[tokio::test]
    async fn stats_typed_provider_preserves_actual_source_json_bytes() {
        // This tests the facade boundary against real source response bytes.
        // Shared owner reads and state effects have separate runtime controls.
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/admin_stats_source.json")).unwrap();
        let registry = Registry::default();
        for row in fixture["rows"].as_array().unwrap() {
            let expected = row["body_text"].as_str().unwrap();
            let document = crate::circuits::CircuitValue::parse_json(expected).unwrap();
            let sampled = std::sync::atomic::AtomicUsize::new(0);
            let stats = || {
                sampled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let document = document.clone();
                tokio::task::spawn_blocking(move || document)
            };
            let outcome = respond_with_stats(
                request("GET", "/stats", b""),
                TOKEN,
                &registry,
                None,
                None,
                Some(&stats),
            )
            .await
            .unwrap();
            assert_eq!(outcome.response.status(), StatusCode::OK);
            assert_eq!(
                outcome.response.headers()[header::CONTENT_TYPE],
                "application/json"
            );
            assert_eq!(body(outcome).await, expected, "{}", row["name"]);
            assert_eq!(sampled.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn stats_serialization_error_is_terminal_after_the_provider_runs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.yaml");
        std::fs::write(
            &path,
            "addons:\n  circuit_breaker:\n    failure_threshold: 2001-02-03\n",
        )
        .unwrap();
        let policy = Policy::from_path(&path).unwrap();
        let view = policy.circuit_settings();
        let mut timestamps = crate::policy::TimestampPaths::default();
        timestamps.insert_value(
            &["failure_threshold"],
            view.temporal_value(&["failure_threshold"]).unwrap().clone(),
        );
        let document = crate::circuits::CircuitValue::from_annotated(
            json!({"failure_threshold":"2001-02-03"}),
            timestamps,
        );
        let sampled = std::sync::atomic::AtomicUsize::new(0);
        let stats = || {
            sampled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let document = document.clone();
            tokio::task::spawn_blocking(move || document)
        };
        let result = respond_with_stats(
            request("GET", "/stats", b""),
            TOKEN,
            &Registry::default(),
            None,
            None,
            Some(&stats),
        )
        .await;
        assert!(matches!(
            result,
            Err(Error::CircuitOperation(crate::circuits::ErrorKind::Type))
        ));
        assert_eq!(sampled.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stats_task_failure_is_terminal_after_authorized_invocation() {
        let stats = || tokio::task::spawn_blocking(|| panic!("owned stats worker failure"));
        let result = respond_with_stats(
            request("GET", "/stats", b""),
            TOKEN,
            &Registry::default(),
            None,
            None,
            Some(&stats),
        )
        .await;
        assert!(matches!(result, Err(Error::StatsReporting)));
    }

    #[tokio::test]
    async fn source_method_auth_and_empty_id_order_do_not_read_body() {
        struct MustNotRead;
        impl Body for MustNotRead {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>>
            {
                panic!("request body must not be polled");
            }
        }
        let registry = Registry::default();
        for (method, path, token, status, expected) in [
            ("GET", "/health", None, 200, json!({"status":"ok"})),
            ("GET", "//health", None, 200, json!({"status":"ok"})),
            ("GET", "///health", None, 200, json!({"status":"ok"})),
            (
                "GET",
                "http://owned.invalid//health",
                Some(TOKEN),
                404,
                json!({"error":"not found"}),
            ),
            (
                "PUT",
                "/admin/policy/task/",
                None,
                401,
                json!({"error":"Unauthorized","message":"Missing or invalid Bearer token","hint":"Add header: Authorization: Bearer <token>"}),
            ),
            (
                "PUT",
                "/admin/policy/task/",
                Some(TOKEN),
                400,
                json!({"error":"missing task_id"}),
            ),
            (
                "PUT",
                "/unknown",
                Some(TOKEN),
                404,
                json!({"error":"not found"}),
            ),
            (
                "POST",
                "/admin/policy/task/x",
                Some(TOKEN),
                404,
                json!({"error":"not found"}),
            ),
            (
                "DELETE",
                "/admin/policy/task/x",
                Some(TOKEN),
                404,
                json!({"error":"Task policy 'x' not found"}),
            ),
        ] {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_LENGTH, 1);
            if let Some(token) = token {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let outcome = respond(request.body(MustNotRead).unwrap(), TOKEN, &registry, None)
                .await
                .unwrap();
            assert_eq!(outcome.status().as_u16(), status);
            assert_eq!(outcome.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(outcome.audit().is_some(), status == 401);
            assert_eq!(
                serde_json::from_slice::<Value>(&body(outcome).await).unwrap(),
                expected
            );
        }
        for (method, length) in [("OPTIONS", 360), ("HEAD", 357)] {
            let request = Request::builder()
                .method(method)
                .uri("/health")
                .body(MustNotRead)
                .unwrap();
            let outcome = respond(request, "", &registry, None).await.unwrap();
            assert_eq!(outcome.status(), StatusCode::NOT_IMPLEMENTED);
            assert!(outcome.audit().is_none());
            assert_eq!(
                outcome.headers()[header::CONTENT_LENGTH],
                length.to_string()
            );
            assert_eq!(
                outcome.headers()[header::CONTENT_TYPE],
                "text/html;charset=utf-8"
            );
            let bytes = outcome
                .into_response()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            if method == "HEAD" {
                assert!(bytes.is_empty());
            } else {
                assert_eq!(bytes.len(), length);
                assert!(
                    std::str::from_utf8(&bytes)
                        .unwrap()
                        .contains("Unsupported method ('OPTIONS').")
                );
            }
        }
    }

    #[tokio::test]
    async fn first_authorization_case_and_ascii_failure_match_operator_source() {
        let registry = Registry::default();
        for (first, second, status) in [
            (format!("Bearer {TOKEN}"), "Bearer wrong".into(), 404),
            ("Bearer wrong".into(), format!("Bearer {TOKEN}"), 401),
            ("Basic fixture".into(), format!("Bearer {TOKEN}"), 401),
            (format!("bearer {TOKEN}"), format!("Bearer {TOKEN}"), 401),
        ] {
            let mut request = request("GET", "/admin/policy/task/absent", b"");
            request.headers_mut().remove(header::AUTHORIZATION);
            request
                .headers_mut()
                .append(header::AUTHORIZATION, first.parse().unwrap());
            request
                .headers_mut()
                .append(header::AUTHORIZATION, second.parse().unwrap());
            assert_eq!(
                respond(request, TOKEN, &registry, None)
                    .await
                    .unwrap()
                    .status()
                    .as_u16(),
                status
            );
        }
        let mut nonascii = request("GET", "/admin/policy/task/absent", b"");
        nonascii.headers_mut().insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert!(matches!(
            respond(nonascii, TOKEN, &registry, None).await,
            Err(Error::AuthenticationEncoding)
        ));
        assert!(matches!(
            respond(
                request("GET", "/admin/policy/task/absent", b""),
                "é",
                &registry,
                None
            )
            .await,
            Err(Error::AuthenticationEncoding)
        ));
        assert_eq!(
            respond(
                request("GET", "/admin/policy/task/absent", b""),
                "",
                &registry,
                None
            )
            .await
            .unwrap()
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn source_raw_roundtrip_replacement_and_invalid_update_use_one_registry() {
        let registry = Registry::default();
        let (raw_put, expected_get) = source_raw_fixture();
        let outcome = respond(
            request(
                "PUT",
                "///admin/policy/task/alpha;ignored?unused=yes",
                raw_put.as_bytes(),
            ),
            TOKEN,
            &registry,
            None,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome.audit(), Some(Audit::TaskUpdated { task_id, permission_count: 2 }) if task_id == "alpha")
        );
        assert_eq!(body(outcome).await, b"{\n  \"status\": \"updated\",\n  \"task_id\": \"alpha\",\n  \"permission_count\": 2,\n  \"message\": \"Task policy updated\"\n}".as_slice());
        for path in [
            "/admin/policy/task/alpha?agent=forged",
            "/admin/policy/task/alpha;ignored",
            "//admin/policy/task/alpha;ignored?agent=forged",
        ] {
            let mut request = request("GET", path, b"");
            request
                .headers_mut()
                .insert(header::ORIGIN, "http://synthetic.invalid".parse().unwrap());
            request
                .headers_mut()
                .insert("x-safeyolo-agent", "forged".parse().unwrap());
            let outcome = respond(request, TOKEN, &registry, None).await.unwrap();
            assert!(outcome.audit().is_none());
            assert_eq!(body(outcome).await, expected_get.as_bytes());
        }
        let old = registry.get("alpha").unwrap().unwrap();
        let outcome = respond(
            request(
                "PUT",
                "/admin/policy/task/alpha",
                br#"{"policy":{"permissions":false}}"#,
            ),
            TOKEN,
            &registry,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.status(), StatusCode::BAD_REQUEST);
        assert!(outcome.audit().is_none());
        assert!(std::sync::Arc::ptr_eq(
            &old,
            &registry.get("alpha").unwrap().unwrap()
        ));
        let outcome = respond(
            request("PUT", "/admin/policy/task/alpha", br#"{"policy":{}}"#),
            TOKEN,
            &registry,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome.audit(),
            Some(Audit::TaskUpdated {
                permission_count: 0,
                ..
            })
        ));
        assert_eq!(registry.count().unwrap(), 1);
        assert_eq!(
            registry.get("alpha").unwrap().unwrap().document(),
            &json!({})
        );
        assert!(old.document().get("unknown").is_some());
        for id in ["alpha/", "%61lpha", "../alpha"] {
            assert_eq!(
                respond(
                    request("GET", &format!("/admin/policy/task/{id}"), b""),
                    TOKEN,
                    &registry,
                    None
                )
                .await
                .unwrap()
                .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                respond(
                    request(
                        "PUT",
                        &format!("/admin/policy/task/{id}"),
                        br#"{"policy":{}}"#
                    ),
                    TOKEN,
                    &registry,
                    None
                )
                .await
                .unwrap()
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[tokio::test]
    async fn source_body_failures_are_terminal_and_leave_registry_unchanged() {
        let registry = Registry::default();
        registry.upsert("alpha", json!({"retained":true})).unwrap();
        for bytes in [b"null".as_slice(), b"{}", b"false", b"[]", b"0", b"\"\""] {
            let outcome = respond(
                request("PUT", "/admin/policy/task/alpha", bytes),
                TOKEN,
                &registry,
                None,
            )
            .await
            .unwrap();
            assert_eq!(outcome.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body(outcome).await,
                b"{\n  \"error\": \"missing request body\"\n}".as_slice()
            );
        }
        for bytes in [b"[1]".as_slice(), b"true", b"1", b"\"truthy\""] {
            assert!(matches!(
                respond(
                    request("PUT", "/admin/policy/task/alpha", bytes),
                    TOKEN,
                    &registry,
                    None
                )
                .await,
                Err(Error::NonObjectBody)
            ));
        }
        for bytes in [b"{".as_slice(), b"\xff"] {
            let outcome = respond(
                request("PUT", "/admin/policy/task/alpha", bytes),
                TOKEN,
                &registry,
                None,
            )
            .await
            .unwrap();
            assert_eq!(outcome.status(), StatusCode::BAD_REQUEST);
            let decoded: Value = serde_json::from_slice(&body(outcome).await).unwrap();
            assert_eq!(decoded["error"], "Malformed JSON in request body");
            assert!(!decoded["detail"].as_str().unwrap().is_empty());
        }
        assert_eq!(
            registry.get("alpha").unwrap().unwrap().document(),
            &json!({"retained":true})
        );
        assert_eq!(registry.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn structural_json_preserves_last_key_and_literal_number_object() {
        let registry = Registry::default();
        let raw = br#"{"policy":{"discarded":true},"policy":{"gateway":{"literal":{"$serde_json::private::Number":"17"}}}}"#;
        let outcome = respond(
            request("PUT", "/admin/policy/task/raw", raw),
            TOKEN,
            &registry,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.status(), StatusCode::OK);
        let retained = registry.get("raw").unwrap().unwrap();
        assert!(retained.document().get("discarded").is_none());
        assert!(retained.document()["gateway"]["literal"].is_object());
        assert_eq!(
            retained.document()["gateway"]["literal"]["$serde_json::private::Number"],
            "17"
        );
    }

    #[tokio::test]
    async fn plumb_resolution_events_remove_retained_pending_approval() {
        let directory = tempfile::tempdir().unwrap();
        let owner = crate::agent_api::plumb::PlumbOwner::for_data_dir(directory.path());
        let requested = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let request_id = requested["request_id"].as_str().unwrap().to_owned();
        let participants = requested["participants"].clone();
        let path = directory.path().join("approved.jsonl");
        let writer = crate::audit::Writer::new(path.clone(), crate::audit::Settings::default());
        let mut prompt = crate::audit::Event::new(
            "plumb.requested",
            crate::audit::Kind::Plumb,
            crate::audit::Severity::Critical,
            "Agent requested a plumb conversation",
        );
        prompt.addon = Some("plumb".into());
        prompt.decision = Some(crate::audit::Decision::RequireApproval);
        prompt.agent = Some("alice".into());
        prompt.approval = Some(crate::audit::Approval {
            required: true,
            approval_type: crate::audit::ApprovalType::Plumb,
            key: request_id.clone(),
            target: "alice,bob".into(),
            scope_hint: json!({"request_id":request_id,"participants":participants}).into(),
        });
        prompt.details = json!({
            "request_id": request_id,
            "participants": participants,
        })
        .into();
        writer.emit(prompt).unwrap();
        let approved = owner.approve(&request_id, None).await;
        assert_eq!(approved["status"], 200);
        let mutation = Audit::PlumbMutation(PlumbMutationAudit {
            event: "plumb.approved",
            summary: "chat approved: alice,bob".into(),
            details: json!({
                "request_id": request_id,
                "participants": approved["participants"],
                "conversation_id": approved["conversation_id"],
            }),
            agent: Some("alice".into()),
            decision: crate::audit::Decision::Allow,
        });
        for event in mutation.canonical_events("127.0.0.1", "/admin/plumb/approve") {
            writer.emit(event).unwrap();
        }
        assert!(writer.shutdown(std::time::Duration::from_secs(2)).unwrap());
        assert_eq!(pending_approvals(&path), json!([]));

        let denied_request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let denied_id = denied_request["request_id"].as_str().unwrap().to_owned();
        let denied_path = directory.path().join("denied.jsonl");
        let denied_writer =
            crate::audit::Writer::new(denied_path.clone(), crate::audit::Settings::default());
        let mut denied_prompt = crate::audit::Event::new(
            "plumb.requested",
            crate::audit::Kind::Plumb,
            crate::audit::Severity::Critical,
            "Agent requested a plumb conversation",
        );
        denied_prompt.addon = Some("plumb".into());
        denied_prompt.decision = Some(crate::audit::Decision::RequireApproval);
        denied_prompt.agent = Some("alice".into());
        denied_prompt.approval = Some(crate::audit::Approval {
            required: true,
            approval_type: crate::audit::ApprovalType::Plumb,
            key: denied_id.clone(),
            target: "alice,bob".into(),
            scope_hint: json!({"request_id":denied_id,"participants":["alice","bob"]}).into(),
        });
        denied_writer.emit(denied_prompt).unwrap();
        assert_eq!(owner.deny(&denied_id).await["status"], 200);
        let denied_mutation = Audit::PlumbMutation(PlumbMutationAudit {
            event: "plumb.denied",
            summary: format!("chat denied: {denied_id}"),
            details: json!({
                "request_id": denied_id,
                "participants": denied_request["participants"],
            }),
            agent: Some("alice".into()),
            decision: crate::audit::Decision::Deny,
        });
        for event in denied_mutation.canonical_events("127.0.0.1", "/admin/plumb/deny") {
            denied_writer.emit(event).unwrap();
        }
        assert!(
            denied_writer
                .shutdown(std::time::Duration::from_secs(2))
                .unwrap()
        );
        assert_eq!(pending_approvals(&denied_path), json!([]));
    }

    #[test]
    fn resolved_keys_match_retained_operator_consumers() {
        assert_eq!(
            resolved_approval_keys(&json!({
                "event":"admin.denial",
                "details":{"cred_id":"alice:POST:/send","destination":"gateway:gmail"}
            })),
            vec!["gw:alice:gmail:POST:/send:gmail"]
        );
        assert_eq!(
            resolved_approval_keys(&json!({
                "event":"admin.gateway_grant",
                "details":{"agent":"alice","service":"gmail","method":"POST","path":"/send"}
            })),
            vec!["gw:alice:gmail:POST:/send:gmail"]
        );
        assert_eq!(
            resolved_approval_keys(&json!({
                "event":"admin.agent_service_authorized",
                "details":{"agent":"alice","service":"gmail"}
            })),
            vec!["alice:gmail:gmail"]
        );
        assert_eq!(
            resolved_approval_keys(&json!({
                "event":"admin.agent_service_revoked",
                "details":{"agent":"alice","service":"gmail"}
            })),
            vec!["alice:gmail:gmail"]
        );
        assert_eq!(
            resolved_approval_keys(&json!({
                "event":"admin.contract_binding_approved",
                "details":{"agent":"alice","service":"gmail","capability":"mail"}
            })),
            vec!["alice:gmail:mail:gmail"]
        );
    }

    #[test]
    fn credential_denial_suppresses_a_later_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let prompt = json!({
            "event":"security.credential",
            "request_id":"first",
            "approval":{"required":true,"approval_type":"credential","key":"hmac:xyz","target":"api.openai.com"}
        });
        let denial = json!({
            "event":"admin.denial",
            "details":{"destination":"api.openai.com","cred_id":"hmac:xyz","reason":"user_denied"}
        });
        let retry = json!({
            "event":"security.credential",
            "request_id":"second",
            "approval":{"required":true,"approval_type":"credential","key":"hmac:xyz","target":"api.openai.com"}
        });
        std::fs::write(&path, format!("{}\n{}\n{}\n", prompt, denial, retry)).unwrap();
        assert_eq!(pending_approvals(&path), json!([]));
    }

    #[test]
    fn desktop_present_approvals_are_visible_and_resolve_repeatably() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("desktop.jsonl");
        let request = json!({
            "event": "agent.desktop_present_requested",
            "request_id": "req-one",
            "approval": {
                "required": true,
                "approval_type": "desktop_present",
                "key": "desktop.present",
                "target": "desktop:alice"
            }
        });
        std::fs::write(&path, format!("{}\n", request)).unwrap();
        assert_eq!(pending_approvals(&path), json!([request]));

        let presented = json!({
            "event": "admin.desktop_presented",
            "details": {
                "agent_id": "alice",
                "approval_request_id": "req-one"
            }
        });
        std::fs::write(&path, format!("{}\n{}\n", request, presented)).unwrap();
        assert_eq!(pending_approvals(&path), json!([]));

        let retry = json!({
            "event": "agent.desktop_present_requested",
            "request_id": "req-two",
            "approval": {
                "required": true,
                "approval_type": "desktop_present",
                "key": "desktop.present",
                "target": "desktop:alice"
            }
        });
        std::fs::write(&path, format!("{}\n{}\n{}\n", request, presented, retry)).unwrap();
        assert_eq!(pending_approvals(&path), json!([retry]));
    }

    // Source35 results SHA256: 6d86bb348eaf0657690a3221f59c149f47c3fba0c9bf1bc934d8f7279919be35.
    fn source_raw_fixture() -> (&'static str, &'static str) {
        (
            "{\"policy\": {\"metadata\": {\"description\": \"synthetic raw task\", \"task_id\": \"authored-other\"}, \"unknown\": {\"keep\": [\"raw\", \"order\"]}, \"permissions\": [{\"action\": \"network:request\", \"resource\": \"zeta.invalid/*\", \"effect\": \"deny\"}, {\"action\": \"file:read\", \"resource\": \"/workspace/metadata\"}]}}",
            "{\n  \"task_id\": \"alpha\",\n  \"policy\": {\n    \"metadata\": {\n      \"description\": \"synthetic raw task\",\n      \"task_id\": \"authored-other\"\n    },\n    \"unknown\": {\n      \"keep\": [\n        \"raw\",\n        \"order\"\n      ]\n    },\n    \"permissions\": [\n      {\n        \"action\": \"network:request\",\n        \"resource\": \"zeta.invalid/*\",\n        \"effect\": \"deny\"\n      },\n      {\n        \"action\": \"file:read\",\n        \"resource\": \"/workspace/metadata\"\n      }\n    ]\n  }\n}",
        )
    }
}
