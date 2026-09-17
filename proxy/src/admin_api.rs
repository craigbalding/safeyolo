//! Authenticated operator operations on the management listener.
//!
//! The caller owns loopback binding, startup token loading, and transport
//! framing. The process owner retains admitted service mutation execution and
//! its audit attempt through shutdown. This facade neither activates tasks nor
//! accepts an agent identity. Other management routes remain unimplemented.

use std::fmt;
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
    TaskUpdated {
        task_id: String,
        permission_count: usize,
    },
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

type AdminBody = BoxBody<Bytes, Error>;

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

fn authenticate(headers: &HeaderMap, expected: &str) -> Result<bool, Error> {
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
    pub service_audit: Option<ServiceAudit<'a>>,
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
            service_audit: None,
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
        service_audit,
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
    if method == Method::POST
        && let Some(agent) = services::agent_path(&path)
    {
        let agent = agent.to_owned();
        return services::authorize(request, agent, policy, policy_path, service_audit).await;
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
    let task_id = path.strip_prefix("/admin/policy/task/");
    if !matches!(*method, Method::GET | Method::PUT) || task_id.is_none() {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"not found"}),
        ));
    }
    let task_id = task_id.expect("task route checked");
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
    let upsert = match registry.upsert(&task_id, raw.take()) {
        Ok(result) => result,
        Err(error @ (tasks::Error::InvalidId | tasks::Error::InvalidPolicy)) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":error.to_string()}),
            ));
        }
        Err(tasks::Error::Poisoned) => return Err(Error::RegistryUnavailable),
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
                json!({"error":"not found"}),
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
    // Source35 results SHA256: 6d86bb348eaf0657690a3221f59c149f47c3fba0c9bf1bc934d8f7279919be35.
    fn source_raw_fixture() -> (&'static str, &'static str) {
        (
            "{\"policy\": {\"metadata\": {\"description\": \"synthetic raw task\", \"task_id\": \"authored-other\"}, \"unknown\": {\"keep\": [\"raw\", \"order\"]}, \"permissions\": [{\"action\": \"network:request\", \"resource\": \"zeta.invalid/*\", \"effect\": \"deny\"}, {\"action\": \"file:read\", \"resource\": \"/workspace/metadata\"}]}}",
            "{\n  \"task_id\": \"alpha\",\n  \"policy\": {\n    \"metadata\": {\n      \"description\": \"synthetic raw task\",\n      \"task_id\": \"authored-other\"\n    },\n    \"unknown\": {\n      \"keep\": [\n        \"raw\",\n        \"order\"\n      ]\n    },\n    \"permissions\": [\n      {\n        \"action\": \"network:request\",\n        \"resource\": \"zeta.invalid/*\",\n        \"effect\": \"deny\"\n      },\n      {\n        \"action\": \"file:read\",\n        \"resource\": \"/workspace/metadata\"\n      }\n    ]\n  }\n}",
        )
    }
}
