use std::{
    cell::Cell,
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use crate::connection_tasks::Executor;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::{Body as HttpBody, Frame, Incoming, SizeHint},
    header,
};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::request_trace::RequestTrace;
use crate::tunnels::{self, BoxStream, Protocol};
use crate::{ConnectionIdentity, Error, Runtime, RuntimeState, UpgradeTasks, is_reserved};

#[cfg(test)]
mod agent_audit_tests;
#[cfg(test)]
mod circuit_audit_tests;
mod circuit_completion;
mod codex_routing;
#[cfg(test)]
mod flow_lookup_tests;
mod flow_recording;
mod ignored_host;
#[cfg(test)]
mod ignored_host_tests;
mod live_view;
#[cfg(test)]
mod memory_tests;
mod network_trace;
mod probe;
mod request_body;
mod request_context;
mod selected_ip;
mod test_context;
#[cfg(test)]
mod trace_tests;
mod traffic;
mod traffic_url;
mod upstream_h2;

pub(crate) type Body = BoxBody<Bytes, Error>;

/// The request or body owner requests cancellation when dropped. The accepted
/// connection retains the actual driver until its task is joined.
struct HttpTask {
    task: tokio::task::AbortHandle,
    completion: Option<Arc<circuit_completion::Completion>>,
    _session: Option<Arc<upstream_h2::Lease>>,
}

impl HttpTask {
    fn unobserved(task: tokio::task::AbortHandle) -> Self {
        Self {
            task,
            completion: None,
            _session: None,
        }
    }
}

impl Drop for HttpTask {
    fn drop(&mut self) {
        if let Some(completion) = &self.completion {
            let _ = completion.try_finish();
        }
        self.task.abort();
    }
}

/// Set only for a response produced by local enforcement. Wire headers cannot
/// claim this classification or suppress an upstream failure observation.
#[derive(Clone)]
struct CircuitPriorBlock;

/// Keeps an asynchronous owner alive through scan-result publication. If the
/// service future is dropped by downstream cancellation, the blocking scanner
/// receives the same cooperative stop signal used by the WebSocket owner.
struct PatternScanLifetime {
    cancelled: Arc<AtomicBool>,
    publication: Mutex<()>,
}

impl PatternScanLifetime {
    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn publication(&self) -> Result<std::sync::MutexGuard<'_, ()>, Error> {
        self.publication
            .lock()
            .map_err(|_| "pattern inspection publication unavailable".into())
    }
}

impl Drop for PatternScanLifetime {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

fn prior_block(mut response: Response<Body>) -> Response<Body> {
    response.extensions_mut().insert(CircuitPriorBlock);
    response
}

struct UpstreamBody<B = Incoming> {
    body: B,
    _connection: HttpTask,
    completion: Option<Arc<circuit_completion::Completion>>,
    incomplete_reported: bool,
    live: Option<Arc<crate::traffic_view::Exchange>>,
}

/// Apply validated request effects before releasing its terminal bytes to the
/// origin. The parser observer supplies success; body frames only prompt a check.
struct ForwardedRequestBody {
    body: Body,
    completion: Arc<circuit_completion::Completion>,
    live: Option<Arc<crate::traffic_view::Exchange>>,
    _session: Option<Arc<upstream_h2::Lease>>,
}

impl HttpBody for ForwardedRequestBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        let _ = this.completion.try_finish();
        let frame = Pin::new(&mut this.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame
            && let Some(trailers) = frame.trailers_ref()
            && let Some(live) = &this.live
        {
            live.request_trailers(live_view::header_map(trailers));
        }
        let _ = this.completion.try_finish();
        if matches!(frame, Poll::Ready(None)) {
            return this
                .completion
                .poll_request_complete(cx)
                .map(|result| result.err().map(Err));
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream() && self.completion.request_complete()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl<B> HttpBody for UpstreamBody<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        let frame = Pin::new(&mut this.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame
            && let Some(trailers) = frame.trailers_ref()
            && let Some(live) = &this.live
        {
            live.response_trailers(live_view::header_map(trailers));
        }
        if matches!(&frame, Poll::Ready(None))
            && !this.incomplete_reported
            && this
                .completion
                .as_ref()
                .is_some_and(|completion| completion.response_incomplete())
        {
            this.incomplete_reported = true;
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "upstream response ended before protocol completion",
            )))));
        }
        frame.map(|frame| frame.map(|result| result.map_err(|error| -> Error { Box::new(error) })))
    }
    fn is_end_stream(&self) -> bool {
        // H2 Incoming maps RST_STREAM(NO_ERROR) to clean EOF. Keep the
        // downstream response in streaming mode until the application owner
        // polls that EOF and converts the parser-aborted result to an error.
        if self
            .completion
            .as_ref()
            .is_some_and(|completion| completion.response_incomplete())
        {
            false
        } else {
            self.body.is_end_stream()
        }
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn inspection_options(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    host: &str,
) -> Result<crate::inspection::Options, &'static str> {
    runtime.config.inspection.as_ref().ok_or("addon_disabled")?;
    if runtime.config.native_product
        && runtime.policy.as_ref().is_some_and(|policy| {
            !policy.is_addon_enabled(
                crate::policy::Addon::PatternScanner,
                Some(host),
                identity.request_agent(),
            )
        })
    {
        return Err("policy_disabled");
    }
    let flags = runtime.operator_modes.flags();
    Ok(crate::inspection::Options {
        block_request: flags[0],
        block_response: flags[1],
        block_websocket_request: Some(flags[2]),
        block_websocket_response: Some(flags[3]),
    })
}

fn record_pattern_decision(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    destination: &Destination,
    direction: crate::inspection::Direction,
    decision: &crate::inspection::Decision,
) -> Result<(), Error> {
    let denied = matches!(
        decision.outcome,
        crate::inspection::Outcome::MatchBlocked | crate::inspection::Outcome::InspectionError
    );
    let logged = matches!(decision.outcome, crate::inspection::Outcome::MatchLogged);
    let mut audit = crate::audit::Event::new(
        "security.pattern_scanner",
        crate::audit::Kind::Security,
        if denied {
            crate::audit::Severity::High
        } else {
            crate::audit::Severity::Medium
        },
        format!(
            "Pattern scanner {} inspection",
            match direction {
                crate::inspection::Direction::Request => "request",
                crate::inspection::Direction::Response => "response",
            }
        ),
    );
    audit.addon = Some("pattern-scanner".into());
    audit.decision = Some(if denied {
        crate::audit::Decision::Deny
    } else if logged {
        crate::audit::Decision::Log
    } else {
        crate::audit::Decision::Allow
    });
    audit.host = Some(destination.policy_host.clone());
    audit.agent = identity.request_agent().map(str::to_owned);
    audit.request_id = Some(request_id.to_owned());
    audit.attribution = Some(identity.audit_attribution());
    audit.details = json!({
        "direction": direction,
        "outcome": decision.outcome,
        "finding": decision.finding,
        "failure": decision.failure,
        "error_type": decision.error_type,
        "metadata": decision.metadata,
        "connection_id": identity.connection_id,
    })
    .into();
    runtime.audit.emit(audit)?;
    Ok(())
}

/// Attach the ordinary local-response completion marker after the request
/// owner has already consumed the parser observer. Callers must have reached
/// the request traffic hooks; taking a second observer would fail.
fn pattern_local_response(
    reply: &mut Response<Body>,
    traffic: &Arc<traffic::Traffic>,
    failure: Option<&'static str>,
) {
    let Some(size) = reply.body().size_hint().exact() else {
        return;
    };
    reply.extensions_mut().insert(traffic::LocalResponse {
        traffic: traffic.clone(),
        size,
        blocked_by: Some(json!("pattern-scanner").into()),
        block_reason: failure.map(|failure| json!(failure).into()),
    });
}

fn enforce_request_inspection(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    destination: &Destination,
    context: &request_context::RequestContext,
    response_traffic: &Arc<traffic::Traffic>,
) -> Result<Option<Response<Body>>, Error> {
    if let Some(result) = context.inspection_result() {
        let result = result?;
        if !matches!(result.outcome, crate::inspection::Outcome::NoRules) {
            record_pattern_decision(
                runtime,
                identity,
                request_id,
                destination,
                crate::inspection::Direction::Request,
                &result,
            )?;
        }
        if matches!(
            result.outcome,
            crate::inspection::Outcome::MatchBlocked | crate::inspection::Outcome::InspectionError
        ) {
            let status = StatusCode::from_u16(result.status.unwrap_or(403))?;
            let body = result
                .body
                .map(|body| body.to_string())
                .unwrap_or_else(|| "{\"error\":\"Request blocked by pattern policy\"}".into());
            let mut blocked = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-blocked-by", "pattern-scanner")
                .body(full(body))?;
            if context.request_hooks_completed() {
                pattern_local_response(&mut blocked, response_traffic, result.failure);
            }
            return Ok(Some(prior_block(blocked)));
        }
    }
    Ok(None)
}

fn enforce_response_decision(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    destination: &Destination,
    traffic: &Arc<traffic::Traffic>,
    inspected: &crate::inspection::Decision,
) -> Result<Option<Response<Body>>, Error> {
    if !matches!(inspected.outcome, crate::inspection::Outcome::NoRules) {
        record_pattern_decision(
            runtime,
            identity,
            request_id,
            destination,
            crate::inspection::Direction::Response,
            inspected,
        )?;
    }
    if matches!(
        inspected.outcome,
        crate::inspection::Outcome::MatchBlocked | crate::inspection::Outcome::InspectionError
    ) {
        let status = StatusCode::from_u16(inspected.status.unwrap_or(502))?;
        let body = inspected
            .body
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "{\"error\":\"Response blocked by pattern policy\"}".into());
        let mut blocked = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-blocked-by", "pattern-scanner")
            .body(full(body))?;
        pattern_local_response(&mut blocked, traffic, inspected.failure);
        return Ok(Some(prior_block(blocked)));
    }
    Ok(None)
}

async fn scan_response_with_lifetime(
    scanner: crate::inspection::Scanner,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Option<Arc<zeroize::Zeroizing<Vec<u8>>>>,
    options: crate::inspection::Options,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(crate::inspection::Decision, PatternScanLifetime), Error> {
    let cancel = Arc::new(AtomicBool::new(false));
    let lifetime = PatternScanLifetime {
        cancelled: cancel.clone(),
        publication: Mutex::new(()),
    };
    if *stop.borrow() {
        return Err("response inspection cancelled".into());
    }
    let worker_cancel = cancel.clone();
    let scan = tokio::task::spawn_blocking(move || {
        let headers = headers
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice()))
            .collect::<Vec<_>>();
        scanner.scan_http_response_bytes_cancellable(
            true,
            &headers,
            body.as_ref().map(|body| body.as_slice()),
            options,
            worker_cancel.as_ref(),
        )
    });
    tokio::pin!(scan);
    let inspected = tokio::select! {
        biased;
        _ = stop.changed() => {
            cancel.store(true, Ordering::Relaxed);
            let _ = scan.await;
            return Err("response inspection cancelled".into());
        }
        result = &mut scan => result
            .map_err(|_| -> Error { "pattern inspection task failed".into() })??,
    };
    if lifetime.cancelled() {
        return Err("response inspection cancelled".into());
    }
    Ok((inspected, lifetime))
}

pub(crate) fn response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(json!({"error": message}).to_string()))
        .unwrap()
}

#[derive(Clone, Serialize)]
struct PolicyRequest<'a> {
    agent_id: &'a str,
    connection_id: &'a str,
    request_id: &'a str,
    method: &'a str,
    scheme: &'a str,
    host: &'a str,
    port: u16,
    path: &'a str,
    header_names: Vec<&'a str>,
    body_present: bool,
    // Native event metadata is outside the temporary adapter protocol.
    #[serde(skip)]
    trace_requested: bool,
}

#[derive(Deserialize)]
struct PolicyDecision {
    allow: bool,
    decision: String,
    status: Option<u16>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body: Option<String>,
    #[serde(skip)]
    blocked_by: Option<serde_json::Value>,
    #[serde(skip)]
    block_reason: Option<serde_json::Value>,
}

/// Routing authority is separate from the request's original path and bytes.
#[derive(Clone)]
pub(crate) struct Destination {
    host: String,
    policy_host: String,
    port: u16,
    authority: String,
    uri_authority: String,
    scheme: String,
    path: String,
    selected_ip: Option<selected_ip::SelectedIp>,
}

/// CONNECT owns one admitted endpoint and its first destination connection.
/// Inner requests may consume that connection only after their own checks pass.
pub(crate) struct Tunnel {
    connect_request_id: String,
    destination: Destination,
    upstream: tokio::sync::Mutex<Option<Connected>>,
    sessions: upstream_h2::Sessions,
    connected_runtime: std::sync::Weak<Runtime>,
}

impl Destination {
    fn from_request<B>(request: &Request<B>, tunnel: Option<&Destination>) -> Result<Self, Error> {
        if request.headers().get_all(header::HOST).iter().count() > 1 {
            return Err("multiple Host headers are ambiguous".into());
        }
        let uri = request.uri();
        let (authority, source_host, wire_authority) = if let Some(authority) = uri.authority() {
            (
                authority.clone(),
                authority.host().trim_matches(['[', ']']).to_owned(),
                authority.to_string(),
            )
        } else {
            let value = request
                .headers()
                .get(header::HOST)
                .ok_or("missing request authority")?;
            let (authority, host) = host_header_authority(value)?;
            (
                authority,
                host,
                std::str::from_utf8(value.as_bytes())?.to_owned(),
            )
        };
        if authority.as_str().contains('@') {
            return Err("request authority cannot contain user information".into());
        }
        let mut policy_host = policy_hostname(
            &source_host,
            uri.authority().is_some(),
            request.version() != hyper::Version::HTTP_2 && uri.scheme().is_some(),
        )?;
        let host = authority
            .host()
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        if host.is_empty() {
            return Err("empty request hostname".into());
        }
        if request.method() == Method::CONNECT
            && (uri.authority().is_none() || authority.port_u16().is_none())
        {
            return Err("CONNECT needs an explicit destination port".into());
        }
        let scheme = uri
            .scheme_str()
            .unwrap_or(tunnel.map_or("http", |tunnel| tunnel.scheme.as_str()))
            .to_owned();
        if scheme.eq_ignore_ascii_case("ws") || scheme.eq_ignore_ascii_case("wss") {
            return Err("WebSocket proxy requests require an HTTP URL".into());
        }
        let port =
            crate::config::authority_port(&authority, if scheme == "https" { 443 } else { 80 })?;
        if let Some(tunnel) = tunnel
            && (host != tunnel.host || port != tunnel.port || scheme != tunnel.scheme)
        {
            return Err("inner authority differs from admitted CONNECT destination".into());
        }
        if let Some(tunnel) = tunnel
            && source_host.is_ascii()
            && source_host.eq_ignore_ascii_case(&tunnel.host)
        {
            // ASCII case does not change this admitted CONNECT hostname.
            // Keep other source spellings for their own hostname inspection.
            policy_host = tunnel.policy_host.clone();
        }
        if request.version() == hyper::Version::HTTP_2
            && let Some(host) = request.headers().get(header::HOST)
        {
            let (host, source_host) = host_header_authority(host)?;
            validate_hostname(&source_host)?;
            let host_port =
                crate::config::authority_port(&host, if scheme == "https" { 443 } else { 80 })?;
            if host.as_str().contains('@')
                || !host
                    .host()
                    .trim_matches(['[', ']'])
                    .eq_ignore_ascii_case(authority.host().trim_matches(['[', ']']))
                || host_port != port
            {
                return Err("HTTP/2 Host differs from request authority".into());
            }
        }
        Ok(Self {
            selected_ip: tunnel
                .and_then(|tunnel| tunnel.selected_ip.clone())
                .or_else(|| {
                    (request.method() == Method::CONNECT)
                        .then(|| host.parse().ok().map(selected_ip::SelectedIp::client))
                        .flatten()
                }),
            host,
            policy_host,
            port,
            authority: wire_authority,
            uri_authority: authority.to_string(),
            scheme,
            path: uri.path_and_query().map_or("/", |p| p.as_str()).to_owned(),
        })
    }
}

/// Origin-form Host fields accept UTF-8 in the source stack. Keep their wire
/// spelling while using IDNA bytes where the HTTP URI grammar requires ASCII.
fn host_header_authority(
    value: &header::HeaderValue,
) -> Result<(hyper::http::uri::Authority, String), Error> {
    let source = std::str::from_utf8(value.as_bytes())?;
    if source.is_ascii() {
        let authority = source.parse::<hyper::http::uri::Authority>()?;
        let host = authority.host().trim_matches(['[', ']']).to_owned();
        return Ok((authority, host));
    }
    // Unicode hostnames cannot be IPv6 literals. Hyper still validates the
    // encoded authority and its port after the source hostname is checked.
    let (host, suffix) = source
        .split_once(':')
        .map_or((source, ""), |(host, _)| (host, &source[host.len()..]));
    validate_hostname(host)?;
    let encoded = crate::host_names::encode_idna2003(host)?;
    let authority = format!("{encoded}{suffix}").parse()?;
    Ok((authority, host.to_owned()))
}

/// Match the source sensor's request-form distinction before routing folds case.
fn policy_hostname(host: &str, byte_authority: bool, absolute_form: bool) -> Result<String, Error> {
    let decoded = if byte_authority {
        crate::host_names::decode_idna2003(host.as_bytes())?
    } else {
        host.to_owned()
    };
    validate_hostname(&decoded)?;
    // Source absolute-URL parsing also validates urllib's lowercase hostname.
    if absolute_form {
        validate_hostname(&host.to_ascii_lowercase())?;
    }
    Ok(decoded)
}

pub(crate) fn validate_hostname(host: &str) -> Result<(), Error> {
    let encoded = crate::host_names::encode_idna2003(host)?;
    crate::host_names::decode_idna2003(encoded.as_bytes())?;
    let labels = encoded.strip_suffix('.').unwrap_or(&encoded);
    let dns = labels.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    let ip = encoded.parse::<std::net::IpAddr>().is_ok()
        || encoded.split_once('%').is_some_and(|(address, scope)| {
            !scope.is_empty()
                && !scope.contains('%')
                && address.parse::<std::net::Ipv6Addr>().is_ok()
        });
    if encoded.len() <= 255 && (dns || ip) {
        Ok(())
    } else {
        Err("invalid request hostname".into())
    }
}

/// Constructed only after the configured network guard permits this request.
struct AllowedRequest<'a> {
    tasks: &'a UpgradeTasks,
    destination: &'a Destination,
    identity: &'a ConnectionIdentity,
    request_id: &'a str,
    recording: Option<&'a flow_recording::Recording>,
}

impl AllowedRequest<'_> {
    fn observe_upstream(
        &self,
        observation: &mut crate::traffic_view::UpstreamConnectionObservation,
        live: Option<&crate::traffic_view::Exchange>,
        stage: &str,
        outcome: &str,
    ) {
        if observation.target.is_null() {
            return;
        }
        observation.target["stage"] = json!(stage);
        observation.target["outcome"] = json!(outcome);
        if let Some(recording) = self.recording {
            recording.connection(observation);
        }
        if let Some(live) = live {
            live.upstream_connection(observation.clone());
        }
    }
}

/// The target form for ordinary HTTP/1 requests on the selected stream.
/// CONNECT establishment and HTTP/2 pseudo-headers have separate rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum H1RequestForm {
    Origin,
    Absolute,
}

struct Outbound {
    stream: BoxStream,
    http2: bool,
    h1_request_form: H1RequestForm,
    observation: crate::traffic_view::UpstreamConnectionObservation,
    network: Option<crate::connection_events::Connection>,
}

fn request_uri(
    destination: &Destination,
    full_uri: &str,
    http2: bool,
    h1_request_form: H1RequestForm,
) -> Result<Uri, hyper::http::uri::InvalidUri> {
    if http2 || h1_request_form == H1RequestForm::Absolute {
        full_uri.parse()
    } else {
        destination.path.parse()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshPhase {
    Dns,
    Tcp,
    ParentTls,
    Connect,
    OriginTls,
    HttpHandshake,
    HttpSend,
    HttpBody,
}

#[derive(Debug)]
struct RefreshPhaseTimeout {
    phase: RefreshPhase,
}
impl std::fmt::Display for RefreshPhaseTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "refresh {:?} phase timed out", self.phase)
    }
}
impl std::error::Error for RefreshPhaseTimeout {}

async fn refresh_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
    phase: RefreshPhase,
) -> Result<T, Error> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| Box::new(RefreshPhaseTimeout { phase }) as Error)?,
        None => operation.await,
    }
}

// Keep each transport boundary explicit so timeout evidence describes the
// operation that actually stalled. These small boundaries are also the seams
// used by the native held-phase tests; they do not introduce another deadline.
async fn refresh_dns_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::Dns).await
}

async fn refresh_tcp_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::Tcp).await
}

async fn refresh_parent_tls_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::ParentTls).await
}

async fn refresh_connect_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::Connect).await
}

async fn refresh_origin_tls_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::OriginTls).await
}

async fn refresh_http_handshake_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::HttpHandshake).await
}

async fn refresh_http_send_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::HttpSend).await
}

async fn refresh_http_body_phase<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    refresh_phase(timeout, operation, RefreshPhase::HttpBody).await
}

/// Resolve and connect one egress route. The production path supplies the
/// platform resolver and TcpStream connector; keeping both futures as inputs
/// makes the actual call-site sequence deterministic to hold in native tests.
async fn resolve_and_connect_egress<
    T,
    Resolve,
    ResolveFuture,
    Connect,
    ConnectFuture,
    Permit,
    Attempt,
>(
    timeout: Option<Duration>,
    resolve: Resolve,
    mut connect: Connect,
    mut permit: Permit,
    mut attempt: Attempt,
) -> Result<T, Error>
where
    Resolve: FnOnce() -> ResolveFuture,
    ResolveFuture: Future<Output = Result<Vec<std::net::SocketAddr>, Error>>,
    Connect: FnMut(std::net::SocketAddr) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T, Error>>,
    Permit: FnMut(std::net::SocketAddr) -> bool,
    Attempt: FnMut() -> Result<(), Error>,
{
    let addresses = refresh_dns_phase(timeout, resolve()).await?;
    let mut last_error = None;
    let mut protected = false;
    let mut connected = None;
    for address in addresses {
        if !permit(address) {
            protected = true;
            continue;
        }
        attempt()?;
        match refresh_tcp_phase(timeout, connect(address)).await {
            Ok(value) => {
                connected = Some(value);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    match connected {
        Some(value) => Ok(value),
        None if protected => Err(AdminPortAccess.into()),
        None => match last_error {
            Some(error) => Err(error),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "egress route resolved no socket addresses",
            )
            .into()),
        },
    }
}

struct Connected {
    stream: BoxStream,
    h1_request_form: H1RequestForm,
    peer: Option<std::net::Ipv4Addr>,
    observation: crate::traffic_view::UpstreamConnectionObservation,
    network: Option<crate::connection_events::Connection>,
}

#[cfg(test)]
struct TestDialBarrier {
    target: String,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
static TEST_DIAL_BARRIER: std::sync::OnceLock<Mutex<Option<Arc<TestDialBarrier>>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
async fn wait_test_dial_barrier(host: &str, port: u16) {
    let barrier = TEST_DIAL_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if let Some(barrier) = barrier.filter(|barrier| barrier.target == format!("{host}:{port}")) {
        barrier.reached.notify_one();
        barrier.release.notified().await;
    }
}

pub(crate) fn parent_tls(config: &crate::Config) -> Result<Arc<ClientConfig>, Error> {
    client_tls(config.upstream_ca_file.as_deref())
}

pub(crate) fn client_tls(ca_file: Option<&std::path::Path>) -> Result<Arc<ClientConfig>, Error> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        roots.add(cert)?;
    }
    for error in native.errors {
        eprintln!("native TLS trust store: {error}");
    }
    if let Some(path) = ca_file {
        for cert in CertificateDer::pem_reader_iter(std::fs::File::open(path)?) {
            roots.add(cert?)?;
        }
    }
    if roots.is_empty() {
        return Err("HTTPS parent requires a usable system or configured CA trust store".into());
    }
    let mut tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

#[derive(Debug)]
struct AdminPortAccess;
impl std::fmt::Display for AdminPortAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(crate::admin_shield::REJECTION.transport_error)
    }
}
impl std::error::Error for AdminPortAccess {}

fn admin_rejection() -> Response<Body> {
    let rejection = crate::admin_shield::REJECTION;
    let mut response = Response::builder()
        .status(rejection.status)
        .header(header::CONTENT_LENGTH, rejection.body.len());
    for (name, value) in rejection.headers {
        response = response.header(*name, *value);
    }
    response
        .body(full(Bytes::from_static(rejection.body)))
        .unwrap()
}

fn parent_for_destination<'a>(
    runtime: &'a Runtime,
    identity: &ConnectionIdentity,
    destination: &Destination,
) -> Option<&'a crate::config::ParentProxy> {
    runtime.parent.as_ref().filter(|parent| {
        (runtime.config.parent_proxy_agents.is_empty()
            || runtime
                .config
                .parent_proxy_agents
                .contains(&identity.agent_id))
            && (parent.destination_hosts.is_empty()
                || parent.destination_hosts.iter().any(|host| {
                    host.eq_ignore_ascii_case(
                        destination
                            .host
                            .strip_suffix('.')
                            .unwrap_or(&destination.host),
                    )
                }))
    })
}

/// The only outbound DNS/socket path. Both routing modes enforce local containment.
async fn open_egress_for_flow(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    tunnel: bool,
    passthrough_matcher: Option<&crate::tunnels::Passthrough>,
    ignored: Option<crate::ignored_host_logger::SelectedDestination<'_>>,
    live: Option<&crate::traffic_view::Exchange>,
    phase_timeout: Option<Duration>,
) -> Result<Connected, Error> {
    let destination = allowed.destination;
    // A numeric selection through an ordinary parent must not be re-resolved
    // from an absolute HTTP request's logical hostname either.
    let tunnel = tunnel || destination.selected_ip.is_some();
    if probe::is_host(&destination.host) {
        return Err(probe::refuse_transport(
            runtime,
            allowed.identity,
            destination,
        ));
    }
    if is_reserved(&destination.host) {
        return Err("reserved destination cannot egress".into());
    }
    let parent = parent_for_destination(runtime, allowed.identity, destination);
    let parent_url = parent.and(runtime.config.parent_proxy.as_deref());
    let endpoint = destination
        .selected_ip
        .as_ref()
        .map_or_else(|| destination.host.clone(), |target| target.ip.to_string());
    let (host, port, tls, route_name) = match parent {
        Some(parent) => (parent.host.as_str(), parent.port, parent.tls, "parent"),
        None => (endpoint.as_str(), destination.port, false, "direct"),
    };
    if is_reserved(host) {
        return Err("reserved destination cannot be an egress route".into());
    }
    if runtime
        .admin_shield
        .blocks_host(&destination.host, destination.port)
        || runtime
            .admin_shield
            .blocks_request_destination(&endpoint, destination.port)
        || runtime.admin_shield.blocks_host(host, port)
    {
        return Err(AdminPortAccess.into());
    }
    let direct = parent.is_none();
    let route = if direct {
        crate::traffic_view::UpstreamRoute::Direct
    } else {
        crate::traffic_view::UpstreamRoute::Parent
    };
    let started = direct.then(crate::circuit_runtime::now);
    let mut observation = crate::traffic_view::UpstreamConnectionObservation::new(
        format!("upstream-{}", uuid::Uuid::new_v4().simple()),
        route,
        started,
    );
    let network = runtime.connection_events.as_ref().map(|events| {
        events.upstream(
            allowed.identity,
            &observation.id,
            &destination.authority,
            route_name,
            "tcp",
        )
    });
    if let Some(recording) = allowed.recording {
        recording.connection(&observation);
    }
    if destination.selected_ip.is_some() {
        observation.target = selected_ip::facts(destination);
        observation.target["route"] = json!(route_name);
        observation.target["parent"] = json!(parent_url);
    }
    allowed.observe_upstream(&mut observation, live, "connection_attempt", "pending");
    if let Some(live) = live {
        live.upstream_connection(observation.clone());
    }
    let record_egress = || {
        let mut details = json!({
            "host": destination.host, "port": destination.port, "route": route_name,
        });
        if destination.selected_ip.is_some() {
            details["target"] = selected_ip::facts(destination);
            details["parent"] = json!(parent_url);
            details["stage"] = json!("connection_attempt");
            details["outcome"] = json!("pending");
        }
        if let Err(error) = runtime.audit.emit(allowed.identity.request_event(
            "traffic.egress",
            crate::audit::Kind::Traffic,
            allowed.request_id,
            format!(
                "Egress attempt via {route_name} to {}:{}",
                crate::network_guard::sanitize(&destination.host),
                destination.port
            ),
            details,
        )) {
            // Route observation cannot revoke already-admitted transport.
            eprintln!("Egress audit submission failed: {error}");
        }
    };
    let mut connection_audit = ignored.map(|selected| {
        ignored_host::ConnectionAudit::new(runtime.audit.clone(), allowed.identity, selected)
    });
    #[cfg(test)]
    wait_test_dial_barrier(&destination.host, destination.port).await;
    let protect_addresses = runtime.admin_shield.protects_port(port)
        || runtime
            .admin_address
            .is_some_and(|bound| bound.port() == port);
    let mut recorded = false;
    let connecting: Result<TcpStream, Error> = resolve_and_connect_egress(
        phase_timeout,
        || async move {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                Ok(vec![std::net::SocketAddr::new(ip, port)])
            } else {
                tokio::net::lookup_host((host, port))
                    .await
                    .map(|addresses| addresses.collect())
                    .map_err(Into::into)
            }
        },
        |address| async move { TcpStream::connect(address).await.map_err(Into::into) },
        |address| {
            !(protect_addresses
                && (runtime.admin_shield.blocks_address(address)
                    || runtime.admin_address.is_some_and(|bound| {
                        crate::admin_shield::targets_listener(address, bound)
                    })))
        },
        || {
            if recorded {
                Ok(())
            } else {
                record_egress();
                recorded = true;
                Ok(())
            }
        },
    )
    .await;
    let socket = match connecting {
        Ok(socket) => socket,
        Err(error) => {
            if let Some(network) = &network {
                network.failed("connect_failed");
            }
            if destination.selected_ip.is_some() {
                observation.target["reason"] = json!(error.to_string());
            }
            allowed.observe_upstream(
                &mut observation,
                live,
                if direct {
                    "direct_connect"
                } else {
                    "parent_tcp"
                },
                "failed",
            );
            selected_ip::record(
                runtime,
                allowed.identity,
                allowed.request_id,
                destination,
                if direct {
                    "direct_connect"
                } else {
                    "parent_tcp"
                },
                "failed",
                json!({"route": route_name, "reason": error.to_string(), "outbound": if recorded { "attempted" } else { "not_attempted" }}),
            );
            if let Some(observation) = &mut connection_audit {
                observation.failed(&error.to_string());
            }
            return Err(error);
        }
    };
    if let Some(network) = &network {
        let peer = socket.peer_addr().ok();
        if let (Ok(local), Some(remote)) = (socket.local_addr(), peer) {
            network.wire_connected(local, remote);
        }
        network.connected(
            socket
                .local_addr()
                .ok()
                .map(crate::connection_events::ip_endpoint),
            peer.map(crate::connection_events::ip_endpoint),
            if direct { peer } else { None },
        );
    }
    selected_ip::record(
        runtime,
        allowed.identity,
        allowed.request_id,
        destination,
        if direct {
            "direct_connect"
        } else {
            "parent_tcp"
        },
        "complete",
        json!({"route": route_name, "direct_peer": if direct { Some(socket.peer_addr()?.to_string()) } else { None },
            "parent": parent_url,
            "outbound": "connected"}),
    );
    let peer = if direct {
        let setup = crate::circuit_runtime::now();
        observation.tcp_setup = Some(setup);
        if let Some(live) = live {
            live.upstream_connection(observation.clone());
        }
        let address = socket.peer_addr()?;
        observation.peer = Some(address);
        if destination.selected_ip.is_some() {
            observation.target["direct_peer"] = json!(address.to_string());
        }
        match address.ip() {
            std::net::IpAddr::V4(address) => Some(address),
            _ => None,
        }
    } else {
        None
    };
    // A configured IPv4 range can match only after DNS has selected the
    // physical peer. Create the lifecycle owner at that point, after the
    // successful TCP connect, while retaining the logical destination in the
    // canonical event. Parent routes pass no physical peer to this matcher;
    // a logical host/port match remains Connecting until parent CONNECT
    // acceptance, so a failed parent phase records one error instead.
    if connection_audit.is_none()
        && direct
        && passthrough_matcher
            .is_some_and(|matcher| matcher.matches(&destination.host, destination.port, peer))
    {
        connection_audit = Some(ignored_host::ConnectionAudit::new(
            runtime.audit.clone(),
            allowed.identity,
            crate::ignored_host_logger::SelectedDestination {
                host: &destination.host,
                port: destination.port,
            },
        ));
    }
    if direct && let Some(observation) = &mut connection_audit {
        observation.connected();
    }
    let socket: BoxStream = if direct {
        match connection_audit.take() {
            Some(observation) => ignored_host::observe(socket, observation),
            None => Box::new(socket),
        }
    } else {
        Box::new(socket)
    };
    let socket = crate::connection_events::observe(socket, network.clone());
    if let Some(live) = live {
        live.upstream_connection(observation.clone());
    }
    allowed.observe_upstream(
        &mut observation,
        live,
        if direct {
            "direct_connect"
        } else {
            "parent_tcp"
        },
        "complete",
    );
    let parent_connection: Result<BoxStream, Error> = async {
        let mut stream: BoxStream = if tls {
            let name = ServerName::try_from(host.to_owned())?;
            let tls = runtime
                .tls
                .clone()
                .ok_or("HTTPS parent TLS was not configured")?;
            selected_ip::record(runtime, allowed.identity, allowed.request_id, destination, "parent_tls", "pending", json!({"parent": parent_url, "verification_name": host}));
            let tls = refresh_parent_tls_phase(phase_timeout, async {
                    TlsConnector::from(tls)
                        .connect(name, socket)
                        .await
                        .map_err(Into::into)
                })
                .await;
            match tls {
                Ok(tls) => {
                    if let Some(network) = &network { network.tls_session("parent", host, tls.get_ref().1); }
                    selected_ip::record(runtime, allowed.identity, allowed.request_id, destination, "parent_tls", "complete", json!({"parent": parent_url, "verification_name": host, "certificate_verified": true}));
                    match &network {
                        Some(network) => network.observe_tls(Box::new(tls), crate::observations::Point::ParentTls),
                        None => Box::new(tls),
                    }
                }
                Err(error) => {
                    selected_ip::record(runtime, allowed.identity, allowed.request_id, destination, "parent_tls", "failed", json!({"parent": parent_url, "verification_name": host, "reason": error.to_string()}));
                    return Err(error);
                }
            }
        } else {
            socket
        };
        if tunnel && parent.is_some() {
            let (mut sender, connection) = refresh_connect_phase(phase_timeout, async {
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(Into::into)
            })
            .await?;
            let task = HttpTask::unobserved(allowed.tasks.spawn(async move {
                let _ = connection.with_upgrades().await;
            }));
            let target = if endpoint.contains(':') {
                format!("[{}]:{}", endpoint, destination.port)
            } else {
                format!("{}:{}", endpoint, destination.port)
            };
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(&target)
                .header(header::HOST, &target)
                .header(header::VIA, format!("1.1 {}", runtime.via_token))
                .body(full(Bytes::new()))?;
            let response = refresh_connect_phase(phase_timeout, async {
                sender.send_request(request).await.map_err(Into::into)
            })
            .await?;
            if destination.selected_ip.is_some() {
                observation.target["parent_requested_target"] = json!(target);
                observation.target["parent_connect_status"] = json!(response.status().as_u16());
            }
            allowed.observe_upstream(&mut observation, live, "parent_connect", if response.status().is_success() { "complete" } else { "failed" });
            selected_ip::record(runtime, allowed.identity, allowed.request_id, destination, "parent_connect",
                if response.status().is_success() { "complete" } else { "failed" },
                json!({"route": "parent", "parent": parent_url, "parent_requested_target": target,
                    "parent_connect_status": response.status().as_u16(), "direct_peer": null, "outbound": "attempted"}));
            if !response.status().is_success() {
                return Err("parent proxy refused CONNECT".into());
            }
            let upgraded = refresh_connect_phase(phase_timeout, async {
                hyper::upgrade::on(response).await.map_err(Into::into)
            })
            .await?;
            drop(task);
            stream = Box::new(TokioIo::new(upgraded));
        }
        Ok(stream)
    }
    .await;
    let mut stream = match parent_connection {
        Ok(stream) => stream,
        Err(error) => {
            if let Some(network) = &network {
                network.failed("parent_connection_failed");
            }
            if destination.selected_ip.is_some() {
                observation.target["reason"] = json!(error.to_string());
            }
            allowed.observe_upstream(&mut observation, live, "parent_connection", "failed");
            selected_ip::record(
                runtime,
                allowed.identity,
                allowed.request_id,
                destination,
                "parent_connection",
                "failed",
                json!({"route": route_name, "reason": error.to_string(), "outbound": "attempted"}),
            );
            if let Some(observation) = &mut connection_audit {
                observation.failed(&error.to_string());
            }
            return Err(error);
        }
    };
    if !direct && let Some(mut observation) = connection_audit {
        observation.connected();
        stream = ignored_host::observe_stream(stream, observation);
    }
    Ok(Connected {
        stream,
        h1_request_form: if direct || tunnel {
            H1RequestForm::Origin
        } else {
            H1RequestForm::Absolute
        },
        peer,
        observation,
        network,
    })
}

async fn open_outbound(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    provider: Option<&str>,
    offer_http2: bool,
    tunnel: Option<&Tunnel>,
    live: Option<&crate::traffic_view::Exchange>,
    phase_timeout: Option<Duration>,
) -> Result<Outbound, Error> {
    let destination = allowed.destination;
    let existing = if let Some(tunnel) = tunnel {
        let connection = tunnel.upstream.lock().await.take();
        // A reload may change parent routing or trust after CONNECT admission.
        // Retain its donated socket only for the snapshot that opened it.
        if std::ptr::eq(tunnel.connected_runtime.as_ptr(), runtime) {
            connection
        } else {
            None
        }
    } else {
        None
    };
    let mut connection = match (existing, provider) {
        (Some(_), Some(_)) => {
            // A provider route may appear after a CONNECT was admitted under an
            // earlier policy snapshot. Never reuse that ordinary connection.
            return Err("provider route cannot reuse an outbound tunnel".into());
        }
        (Some(connection), None) => connection,
        (None, Some(provider)) => {
            let observation = crate::traffic_view::UpstreamConnectionObservation::new(
                format!("upstream-{}", uuid::Uuid::new_v4().simple()),
                crate::traffic_view::UpstreamRoute::Provider,
                Some(crate::circuit_runtime::now()),
            );
            let network = runtime.connection_events.as_ref().map(|events| {
                events.upstream(
                    allowed.identity,
                    &observation.id,
                    &destination.authority,
                    "provider",
                    "stream",
                )
            });
            if let Some(recording) = allowed.recording {
                recording.connection(&observation);
            }
            let stream =
                match crate::provider_stream::open(&runtime.config, provider, destination.port)
                    .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        if let Some(network) = &network {
                            network.failed("provider_connect_failed");
                        }
                        return Err(error.into());
                    }
                };
            if let Some(network) = &network {
                network.connected(None, None, None);
            }
            Connected {
                stream: crate::connection_events::observe(stream, network.clone()),
                h1_request_form: H1RequestForm::Origin,
                peer: None,
                observation,
                network,
            }
        }
        (None, None) => {
            open_egress_for_flow(
                runtime,
                allowed,
                tunnel.is_some() || destination.scheme == "https",
                None,
                None,
                live,
                phase_timeout,
            )
            .await?
        }
    };
    if let Some(live) = live {
        live.upstream_connection(connection.observation.clone());
    }
    let mut stream = connection.stream;
    let mut http2 = false;
    if destination.scheme == "https" {
        let config = runtime.tls.as_ref().ok_or_else(|| {
            if let Some(network) = &connection.network {
                network.failed("origin_tls_unavailable");
            }
            "upstream TLS trust is not configured"
        })?;
        let mut config = (**config).clone();
        if offer_http2 {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        let name = ServerName::try_from(destination.host.clone())?;
        if destination.selected_ip.is_some() {
            connection.observation.target["tls_verification_name"] = json!(destination.host);
        }
        allowed.observe_upstream(&mut connection.observation, live, "origin_tls", "pending");
        selected_ip::record(
            runtime,
            allowed.identity,
            allowed.request_id,
            destination,
            "origin_tls",
            "pending",
            json!({"verification_name": destination.host}),
        );
        let tls = refresh_origin_tls_phase(phase_timeout, async {
            TlsConnector::from(Arc::new(config))
                .connect(name, stream)
                .await
                .map_err(Into::into)
        })
        .await;
        let tls = match tls {
            Ok(tls) => tls,
            Err(error) => {
                if let Some(network) = &connection.network {
                    network.failed("origin_tls_failed");
                }
                if destination.selected_ip.is_some() {
                    connection.observation.target["reason"] = json!(error.to_string());
                }
                allowed.observe_upstream(&mut connection.observation, live, "origin_tls", "failed");
                selected_ip::record(
                    runtime,
                    allowed.identity,
                    allowed.request_id,
                    destination,
                    "origin_tls",
                    "failed",
                    json!({"verification_name": destination.host, "reason": error.to_string()}),
                );
                return Err(error);
            }
        };
        if let Some(network) = &connection.network {
            network.tls_session("origin", &destination.host, tls.get_ref().1);
        }
        selected_ip::record(
            runtime,
            allowed.identity,
            allowed.request_id,
            destination,
            "origin_tls",
            "complete",
            json!({"verification_name": destination.host, "certificate_verified": true}),
        );
        http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        stream = match &connection.network {
            Some(network) => {
                network.observe_tls(Box::new(tls), crate::observations::Point::OriginTls)
            }
            None => Box::new(tls),
        };
        let completed = crate::circuit_runtime::now();
        connection.observation.tls_setup = Some(completed);
        if destination.selected_ip.is_some() {
            connection.observation.target["tls_verification_name"] = json!(destination.host);
            connection.observation.target["tls_result"] = json!("certificate_verified");
        }
        allowed.observe_upstream(&mut connection.observation, live, "origin_tls", "complete");
        if let Some(live) = live {
            live.upstream_connection(connection.observation.clone());
            live.upstream_tls(completed);
        }
    }
    Ok(Outbound {
        stream,
        http2,
        h1_request_form: connection.h1_request_form,
        observation: connection.observation,
        network: connection.network,
    })
}

async fn decide(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request: &PolicyRequest<'_>,
    trace: Option<&Arc<RequestTrace>>,
) -> Result<PolicyDecision, Error> {
    let policy = runtime.policy.as_ref().ok_or("policy is not configured")?;
    {
        use crate::network_guard::{Options, OutcomeKind, Pdp, Request};

        let trace = trace.and_then(|trace| {
            trace.hook(
                "network-guard",
                if request.method == "CONNECT" {
                    "http_connect"
                } else {
                    "request"
                },
            )
        });
        let deferred_approval = Cell::new(false);
        let mut approval_event = None;
        let mut approval_trace = None;
        let result = runtime.network_guard.enforce_with_audit_and_trace(
            Pdp::Ready(policy),
            Request {
                identity: identity.request_identity(),
                host: request.host,
                decode_ace_for_inspection: true,
                port: request.port,
                method: request.method,
                path: request.path,
                scheme: request.scheme,
                request_id: Some(request.request_id),
                connection_id: request.connection_id,
                prior_response: false,
            },
            Options {
                enabled: runtime.config.network_guard_enabled,
                block: runtime.operator_modes.network_block(),
                homoglyph: runtime.config.network_guard_homoglyph,
            },
            crate::policy::current_time_ms(),
            |intent| {
                let mut event = intent.event(identity.audit_attribution());
                crate::approvals::network_action::bind(&mut event, policy);
                if let crate::circuits::CircuitValue::Object(fields) = &mut event.details
                    && let Some(action) = fields
                        .get("network_action")
                        .and_then(|value| value.json().ok())
                {
                    let mut action = action;
                    if let Some(run) = &identity.run {
                        action["run"] = json!(run);
                    }
                    action["network_action"] =
                        json!(if request.method.eq_ignore_ascii_case("CONNECT") {
                            "connect"
                        } else {
                            "request"
                        });
                    fields.insert("network_action".into(), action.into());
                }
                if intent.decision == crate::network_guard::AuditDecision::RequireApproval {
                    // The synchronous guard callback cannot await the writer.
                    // Hold only approval evidence until the guard has returned.
                    deferred_approval.set(true);
                    approval_event = Some(event);
                    Ok(())
                } else {
                    runtime
                        .audit
                        .emit(event)
                        .map(|_| ())
                        .map_err(|error| crate::network_guard::GuardError(error.to_string()))
                }
            },
            |intent| {
                if deferred_approval.get() {
                    approval_trace = Some(intent.clone());
                } else {
                    network_trace::observe(trace.as_ref(), intent);
                }
            },
        );
        if result.is_err()
            && let Some(trace) = &trace
        {
            // GuardError erases native producer categories; its diagnostic
            // text cannot establish a corresponding source exception class.
            trace.error("GuardError");
        }
        let outcome = result?;
        let mut pending = None;
        if let Some(mut event) = approval_event {
            pending = crate::approvals::pending::bind_network(
                &runtime.audit,
                policy,
                &mut event,
                &crate::policy::NetworkRequest {
                    agent: identity.request_agent(),
                    host: request.host,
                    port: Some(request.port),
                    method: request.method,
                    path: request.path,
                },
                request.scheme,
                runtime.credential_guard.as_ref(),
            )
            .await?;
            if let Err(error) = runtime.audit.emit_confirmed(event).await {
                if let Some(trace) = &trace {
                    trace.error("AuditError");
                }
                return Err(error.into());
            }
            if let Some(record) = pending.as_ref() {
                crate::approvals::pending::delegation::notify(runtime, record).await;
            }
            if let Some(intent) = approval_trace.as_ref() {
                network_trace::observe(trace.as_ref(), intent);
            }
        }
        // Keep guard evaluation metadata without copying canonical audit intents.
        // URL queries and application bytes stay excluded.
        runtime.audit.emit(identity.request_event(
            "security.network_guard.evaluated",
            crate::audit::Kind::Security,
            request.request_id,
            "Network guard evaluated request",
            json!({
            "host": request.host,
            "port": request.port,
            "method": request.method,
            "scheme": request.scheme,
            "outcome": outcome.kind,
            "trace": outcome.trace,
            "trace_requested": request.trace_requested,
            "metadata": outcome.metadata,
            "pdp": outcome.pdp,
            "approval_id": (outcome.kind == OutcomeKind::Allowed).then(||
                policy.network_approval(identity.request_agent(), request.host, request.port)).flatten()
            }),
        ))?;
        let allow = outcome.kind != OutcomeKind::Blocked;
        let (status, headers, body) = match outcome.response {
            Some(response) => {
                let body = String::from_utf8(response.body_bytes())?;
                let mut headers = response.headers;
                if let Some(record) = &pending {
                    headers.push(("x-safeyolo-approval-id".into(), record.approval_id.clone()));
                }
                (Some(response.status), headers, Some(body))
            }
            None => (None, Vec::new(), None),
        };
        Ok(PolicyDecision {
            allow,
            decision: if allow { "allow" } else { "deny" }.into(),
            status,
            headers,
            body,
            blocked_by: outcome.metadata.get("blocked_by").cloned(),
            block_reason: outcome.metadata.get("block_reason").cloned(),
        })
    }
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let connection: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(|v| v.trim().to_ascii_lowercase()))
        .collect();
    for name in connection {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn loop_detected(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all(header::VIA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|entry| {
            entry
                .split_whitespace()
                .nth(1)
                .is_some_and(|v| v.eq_ignore_ascii_case(token))
        })
}

fn record_agent_api(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    outcome: &crate::agent_api::Outcome<'_>,
) -> Result<(), Error> {
    // Retain the response/handler result without copying the canonical intent.
    // An intent name on a failed submission is not a second event emission.
    runtime.audit.emit(identity.request_event(
        "agent.api_response",
        crate::audit::Kind::Agent,
        request_id,
        "Agent API response",
        json!({
            "status": outcome.response.status, "blocked_by": outcome.blocked_by,
            "handler_owned": outcome.handler_owned,
            "audit_event": outcome.audit.as_ref().map(|audit| audit.event),
            "failure": outcome.failure.map(|failure| format!("{failure:?}")),
            "policy_evaluations": outcome.policy_evaluations,
        }),
    ))?;
    Ok(())
}

// `Traffic` is only the request snapshot; retain connection identity,
// destination, and upgrade ownership explicitly, as `forward` does.
#[allow(clippy::too_many_arguments)]
async fn local_agent_api<B>(
    runtime: &Arc<Runtime>,
    state: &RuntimeState,
    traffic: Arc<traffic::Traffic>,
    identity: &ConnectionIdentity,
    request_id: &str,
    upgrades: &UpgradeTasks,
    request: &mut Request<B>,
    destination: &Destination,
    trace: Option<&Arc<RequestTrace>>,
) -> Result<Response<Body>, Error>
where
    B: HttpBody<Data = Bytes> + Unpin + Send + Sync + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    use crate::agent_api::{self, Failure, PolicyState};

    let mut ordered_headers = crate::request_headers::RequestHeaders::take(request)?;
    let observer = request_context::Observer::take(request)?;
    let mut local_observation = agent_api::BodyObservation::default();
    // mitmproxy combines repeated Authorization fields with a comma and space.
    // Hold that value only for authentication, outside diagnostic formatting.
    let mut authorization = zeroize::Zeroizing::new(Vec::new());
    let mut present = false;
    for value in request.headers().get_all(header::AUTHORIZATION) {
        if present {
            authorization.extend_from_slice(b", ");
        }
        present = true;
        authorization.extend_from_slice(value.as_bytes());
    }
    // Release parser metadata carrying duplicate bearer fields at this local
    // terminal boundary as well as removing the transport header values.
    request
        .extensions_mut()
        .remove::<hyper::ext::OriginalHeaderFields>();
    request
        .extensions_mut()
        .remove::<h2::ext::OriginalHeaderFields>();
    request.headers_mut().remove(header::AUTHORIZATION);
    request.headers_mut().remove(header::PROXY_AUTHORIZATION);
    let method = request.method().clone();
    let mut content_encoding = Vec::new();
    let mut encoding_present = false;
    for value in request.headers().get_all(header::CONTENT_ENCODING) {
        if encoding_present {
            content_encoding.extend_from_slice(b", ");
        }
        encoding_present = true;
        content_encoding.extend_from_slice(value.as_bytes());
    }
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let api_request = agent_api::Request {
        method: method.as_str(),
        path_and_query: &destination.path,
        authorization: present.then_some(authorization.as_slice()),
        identity: identity.request_identity(),
        client_ip: identity.source_id.as_deref(),
        request_id,
    };
    let mut outcome = if runtime.config.agent_api_enabled {
        let token_path = if runtime.config.native_product {
            runtime.config.data_dir()
        } else {
            std::env::var_os("SAFEYOLO_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| runtime.config.data_dir())
        }
        .join("agent_token");
        let policy = runtime
            .policy
            .as_ref()
            .map_or(PolicyState::Unavailable, PolicyState::Ready);
        let mut random = rand::random::<f64>;
        agent_api::respond_with_body_and_audit_id_with_plumb(
            api_request,
            &token_path,
            policy,
            &runtime.tasks,
            crate::policy::current_time_ms(),
            agent_api::Controls {
                gateway: Some(agent_api::GatewayContext {
                    snapshot: runtime
                        .policy
                        .as_ref()
                        .and_then(|policy| policy.gateway())
                        .filter(|snapshot| snapshot.registry().is_some()),
                }),
                memory: Some(agent_api::MemoryContext {
                    owner: &runtime.memory_monitor,
                    sample: crate::memory_runtime::sample,
                    now: crate::circuit_runtime::now,
                }),
                traces: Some(agent_api::TraceContext {
                    store: &runtime.traces,
                    now: &crate::circuit_runtime::now,
                }),
                agents: Some(agent_api::AgentReportContext {
                    activity: &runtime.agent_activity,
                    listeners: &runtime.config.listeners,
                }),
                audit: Some(&runtime.audit),
                flows: runtime.flow_recorder.store(),
                circuits: runtime.policy.as_ref().map(|_| agent_api::CircuitContext {
                    audit: Some(&runtime.audit),
                    breaker: &runtime.circuits,
                    enabled: runtime.config.circuit_breaker_enabled,
                    random: &mut random,
                }),
                declarations: runtime
                    .policy
                    .as_ref()
                    .map(|_| agent_api::DeclarationContext {
                        owner: &runtime.test_context,
                        now: declaration_time,
                    }),
                coord: Some(agent_api::CoordContext {
                    client: &runtime.coord,
                    cancellation: upgrades.cancellation_receiver.clone(),
                }),
            },
            agent_api::RequestBody {
                body: request.body_mut(),
                content_encoding: &content_encoding,
                content_length,
                observation: Some(&mut local_observation),
            },
            Some(request_id),
            Some(runtime.plumb.as_ref()),
            Some(state),
        )
        .await?
    } else {
        agent_api::unavailable(api_request, Failure::HandlerUnavailable)
    };
    // AgentAPI runs before the later request/response traffic hooks. An
    // approval claim waits for its own canonical audit write; other events
    // retain the source's asynchronous submission semantics.
    let mut evidence_failed = false;
    if !outcome.audit_owned
        && let Some(audit) = &outcome.audit
    {
        let mut event = audit.to_event();
        let pending =
            crate::approvals::pending::bind_agent_request(runtime, &mut event, request_id).await?;
        if let Some(record) = &pending {
            outcome
                .response
                .headers
                .push(("x-safeyolo-approval-id".into(), record.approval_id.clone()));
        }
        let submission = if audit.kind == agent_api::AuditKind::FlowReadAll
            || audit
                .approval
                .as_ref()
                .is_some_and(|approval| approval.required)
        {
            runtime.audit.emit_confirmed(event).await
        } else {
            runtime.audit.emit(event).map(|_| ())
        };
        if let Err(error) = submission {
            evidence_failed = true;
            let authentication_failed = audit.kind == agent_api::AuditKind::AuthenticationFailed;
            if audit.kind != agent_api::AuditKind::HandlerUnavailable {
                evidence_failed |=
                    record_agent_api(runtime, identity, request_id, &outcome).is_err();
            }
            outcome = outcome.audit_submission_failed(api_request, error.kind());
            if authentication_failed && let Some(guard) = &outcome.audit {
                // A single independent containment attempt. The guard catches a
                // second failure and its local response must remain intact.
                evidence_failed |= runtime.audit.emit(guard.to_event()).is_err();
            }
        }
    }
    evidence_failed |= record_agent_api(runtime, identity, request_id, &outcome).is_err();
    // The existing API reader supplies only a scalar observation. Its Body
    // terminal is insufficient on H2 NO_ERROR reset: require parser success.
    // Early routes never wait for an unread body merely to generate traffic.
    let terminal_body = request.body().is_end_stream();
    let eligible =
        (local_observation.decoded_size.is_some() || terminal_body) && observer.await.is_ok();
    let traffic = if eligible {
        // Use the existing reader's original-content observation. Memory
        // accounting must not decode headers after request-ID hygiene removed
        // a nominated Content-Encoding field, or reread the request body.
        if let Some(decoded) = local_observation.decoded_size {
            traffic.memory_request_size(|| decoded);
        } else {
            traffic.memory_request(Some(&[]));
        }
        let hygiene = ordered_headers.apply_hygiene(request.headers_mut());
        if let Some(trace) = trace {
            trace.enable(hygiene.trace_requested);
        }
        traffic.request_headers(request, destination);
        traffic.begin_request();
        let encoding = test_context::combined(request.headers(), header::CONTENT_ENCODING);
        evidence_failed |= traffic.request(|| {
            if !request.headers().contains_key(header::CONTENT_ENCODING)
                && let Some(size) = local_observation.encoded_size
            {
                return Ok(size);
            }
            local_observation.decoded_size.map_or_else(
                || {
                    traffic::decoded_size(
                        Some(&[]),
                        encoding
                            .as_deref()
                            .map(Vec::as_slice)
                            .map_err(|error| *error),
                    )
                },
                |result| {
                    result.map_err(|_| {
                        crate::request_logger::Error(crate::request_logger::ErrorKind::Decode)
                    })
                },
            )
        });
        Some(traffic)
    } else {
        None
    };
    drop(ordered_headers);
    if evidence_failed {
        // Source audit file failures are caught by its writer and preserve the
        // response. They differ from a callback exception escaping API auth.
        eprintln!("Agent API evidence write failed");
    }
    // This is terminal local dispatch: no remaining observer receives request
    // headers, query, or body, including when the handler is unavailable.
    if runtime.config.native_product && request.uri().path().trim_end_matches('/') == "/trace" {
        outcome.name_trace_controls();
    }
    let bytes = outcome.response.body_bytes();
    let size = bytes.len() as u64;
    let mut reply = Response::builder()
        .status(outcome.response.status)
        .body(full(bytes))?;
    if let Some(traffic) = traffic {
        reply.extensions_mut().insert(traffic::LocalResponse {
            traffic,
            size,
            blocked_by: Some(json!(outcome.blocked_by).into()),
            block_reason: None,
        });
    }
    for (name, value) in outcome.response.headers {
        reply
            .headers_mut()
            .append(header::HeaderName::try_from(name)?, value.parse()?);
    }
    if evidence_failed {
        reply
            .headers_mut()
            .insert("x-safeyolo-evidence-error", "true".parse()?);
    }
    Ok(reply)
}

pub(crate) fn declaration_time() -> f64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64()
}

/// Resolve policy and refresh circuit settings under current runtime ownership.
/// As in the source hook, an operation exception preserves prior mutations and
/// lets later request processing continue.
fn circuit_admission(
    state: &RuntimeState,
    identity: &ConnectionIdentity,
    request_id: &str,
    method: &str,
    destination: &Destination,
    trace: Option<&Arc<RequestTrace>>,
) -> (Option<Response<Body>>, bool, bool) {
    use crate::circuits::{CircuitValue, RequestDecision, RequestGate};
    let trace = trace.and_then(|trace| trace.hook("circuit-breaker", "request"));
    let Ok(runtime) = state.read() else {
        if let Some(trace) = &trace {
            trace.error("CircuitRuntimeUnavailable");
        }
        eprintln!("Circuit request runtime unavailable");
        return (None, true, true);
    };
    let Some(policy) = runtime.policy.as_ref() else {
        return (None, false, false);
    };
    let host = &destination.policy_host;
    let result = runtime.circuits.request_current_with_audit(
        policy,
        host,
        RequestGate {
            enabled: runtime.config.circuit_breaker_enabled,
            prior_response: false,
            policy_bypassed: !policy.is_addon_enabled(
                crate::policy::Addon::CircuitBreaker,
                Some(host),
                identity.request_agent(),
            ),
        },
        crate::circuit_runtime::now(),
        &mut rand::random::<f64>,
        &crate::circuits::Audit::new(&runtime.audit, None, None),
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            crate::circuit_runtime::trace_error(trace.as_ref(), &error);
            eprintln!("Circuit request operation failed: {:?}", error.kind());
            return (None, false, true);
        }
    };
    crate::circuit_runtime::trace_request_decision(trace.as_ref(), &outcome.value);
    let RequestDecision::Blocked {
        status,
        retry_after_seconds,
    } = outcome.value
    else {
        return (None, false, false);
    };
    let reply = (|| -> Result<Response<Body>, Error> {
        let state = serde_json::to_value(status.state)?
            .as_str()
            .unwrap()
            .to_owned();
        let count = crate::circuit_runtime::count_text(&status.failure_count)?;
        let details = indexmap::IndexMap::from([
            ("circuit_state".into(), json!(state).into()),
            ("failure_count".into(), status.failure_count.clone()),
            ("retry_after".into(), json!(retry_after_seconds).into()),
            ("path".into(), json!(destination.path).into()),
            ("method".into(), json!(method).into()),
            ("port".into(), json!(destination.port).into()),
            ("connection_id".into(), json!(identity.connection_id).into()),
        ]);
        let mut security = crate::audit::Event::new(
            "security.circuit_breaker",
            crate::audit::Kind::Security,
            crate::audit::Severity::High,
            format!(
                "Circuit breaker open for {} ({count} failures)",
                crate::network_guard::sanitize(host)
            ),
        );
        security.addon = Some("circuit-breaker".into());
        security.host = Some(host.to_owned());
        security.agent = identity.request_agent().map(str::to_owned);
        security.request_id = Some(request_id.to_owned());
        security.decision = Some(crate::audit::Decision::Deny);
        security.attribution = Some(identity.audit_attribution());
        security.details = CircuitValue::Object(details);
        runtime.audit.emit(security)?;
        let body = crate::python_json::encode(&json!({
            "error": format!("Service temporarily unavailable: {host}"),
            "domain": host,
            "circuit_state": state,
            "retry_after_seconds": retry_after_seconds,
            "message": format!("Circuit breaker open for {host}. Service has failed {count} times. Will retry in {retry_after_seconds} seconds."),
        }));
        let reply = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, body.len())
            .header("x-blocked-by", "circuit-breaker")
            .header("x-safeyolo-request-id", request_id)
            .header("x-circuit-state", state)
            .header(header::RETRY_AFTER, retry_after_seconds.to_string())
            .body(full(body))?;
        Ok(reply)
    })();
    match reply {
        Ok(reply) => {
            crate::circuit_runtime::trace_request_blocked(trace.as_ref());
            (Some(reply), false, false)
        }
        Err(error) => {
            if let Some(error) = error.downcast_ref::<crate::circuits::Error>() {
                crate::circuit_runtime::trace_error(trace.as_ref(), error);
            } else if let Some(error) = error.downcast_ref::<crate::audit::Error>() {
                crate::circuit_runtime::trace_audit_error(trace.as_ref(), error.kind());
            } else if let Some(trace) = &trace {
                trace.error("CircuitResponseError");
            }
            eprintln!("Circuit request response construction failed");
            (None, false, true)
        }
    }
}

/// Publish each guard intent as the corresponding shared trace step. Guard
/// outcomes are already source-shaped (including bypass reasons, counts and
/// local status); keep those fields intact instead of replacing the sequence
/// with one synthetic outcome for the whole request.
fn publish_credential_trace(
    hook: Option<&crate::request_trace::TraceHook>,
    intents: &[crate::credential_guard::TraceIntent],
) {
    for intent in intents {
        let Some(hook) = hook else {
            continue;
        };
        match intent.state {
            "evaluated" => {
                let details = match (intent.detection_count, intent.status) {
                    (None, None) => None,
                    (count, status) => {
                        let mut fields = indexmap::IndexMap::new();
                        if let Some(count) = count {
                            fields.insert("detection_count".into(), json!(count).into());
                        }
                        if let Some(status) = status {
                            fields.insert("status".into(), json!(status).into());
                        }
                        Some(crate::circuits::CircuitValue::Object(fields))
                    }
                };
                hook.evaluated(intent.outcome.unwrap_or("evaluated"), details);
            }
            "bypassed" => hook.bypassed(intent.reason.unwrap_or("bypassed")),
            "error" => hook.error(intent.reason.unwrap_or("CredentialGuardError")),
            _ => hook.error("CredentialGuardTraceState"),
        }
    }
}

fn publish_gateway_evidence(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    evidence: &crate::credential_injection::Evidence,
) -> Result<(), Error> {
    for intent in &evidence.audit {
        runtime
            .audit
            .emit(intent.event(identity.audit_attribution()))?;
    }
    runtime.audit.emit(identity.request_event(
        "gateway.evaluated",
        crate::audit::Kind::Gateway,
        request_id,
        "Gateway request observation",
        json!({
        "metadata": evidence.metadata,
        "trace": evidence.trace,
        "stats": evidence.stats,
        "body_scope": "contract_body_checked_when_buffered",
        "query_scope": "signed_query_preserved_in_full_url"
        }),
    ))?;
    Ok(())
}

/// Execute the host-owned OAuth token request through the same egress path as
/// ordinary upstream traffic. The endpoint is selected by the already
/// authorized vault credential; it is never passed through agent network
/// policy or gateway credential injection. No redirect is followed and the
/// response is bounded before it reaches the native refresh decoder.
async fn execute_refresh(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request_id: &str,
    tasks: &UpgradeTasks,
    refresh: &crate::oauth::RefreshRequest,
) -> std::result::Result<crate::oauth::RefreshResponse, crate::oauth::TransportFailure> {
    let endpoint = refresh.endpoint().expose_secret();
    let endpoint_uri: Uri = endpoint
        .parse()
        .map_err(|_| crate::oauth::TransportFailure::Protocol)?;
    let scheme = endpoint_uri.scheme_str().unwrap_or_default();
    if !matches!(scheme, "http" | "https") || endpoint_uri.authority().is_none() {
        return Err(crate::oauth::TransportFailure::Protocol);
    }
    let probe = Request::builder()
        .method(Method::POST)
        .uri(endpoint_uri.clone())
        .body(full(Bytes::new()))
        .map_err(|_| crate::oauth::TransportFailure::Protocol)?;
    let destination = Destination::from_request(&probe, None)
        .map_err(|_| crate::oauth::TransportFailure::Protocol)?;
    let phase_timeout = refresh.io_timeout();
    let outbound = open_outbound(
        runtime,
        &AllowedRequest {
            recording: None,
            tasks,
            destination: &destination,
            identity,
            request_id,
        },
        None,
        false,
        None,
        None,
        Some(phase_timeout),
    )
    .await
    .map_err(|error| {
        if is_refresh_phase_timeout(&error) {
            crate::oauth::TransportFailure::Timeout
        } else if destination.scheme == "https" {
            crate::oauth::TransportFailure::Tls
        } else {
            crate::oauth::TransportFailure::Connect
        }
    })?;
    let request_uri = request_uri(
        &destination,
        endpoint,
        outbound.http2,
        outbound.h1_request_form,
    )
    .map_err(|_| crate::oauth::TransportFailure::Protocol)?;
    let body = Bytes::copy_from_slice(refresh.body().expose_secret().as_bytes());
    let request = Request::builder()
        .method(Method::POST)
        .uri(request_uri)
        .header(header::HOST, destination.authority.as_str())
        .header(header::CONTENT_TYPE, refresh.content_type())
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::CONNECTION, "close")
        .header(header::VIA, format!("1.1 {}", runtime.via_token))
        .body(full(body))
        .map_err(|_| crate::oauth::TransportFailure::Protocol)?;
    let (mut sender, connection) = refresh_http_handshake_phase(Some(phase_timeout), async {
        hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(outbound.stream))
            .await
            .map_err(Into::into)
    })
    .await
    .map_err(|error| {
        if let Some(network) = &outbound.network {
            network.failed("http_handshake_failed");
        }
        if is_refresh_phase_timeout(&error) {
            crate::oauth::TransportFailure::Timeout
        } else {
            crate::oauth::TransportFailure::Protocol
        }
    })?;
    tasks.spawn(async move {
        if let Err(error) = connection.await
            && let Some(network) = outbound.network
        {
            network.http_error(&error);
        }
    });
    // Hyper's readiness boundary is separate from writing the request and
    // waiting for its response. Keep it under the handshake phase budget so
    // a client-side HTTP/1 state machine stall cannot be reported as a head
    // or body timeout.
    refresh_http_handshake_phase(Some(phase_timeout), async {
        sender.ready().await.map_err(Into::into)
    })
    .await
    .map_err(|error| {
        if is_refresh_phase_timeout(&error) {
            crate::oauth::TransportFailure::Timeout
        } else {
            crate::oauth::TransportFailure::Protocol
        }
    })?;
    let response = refresh_http_send_phase(Some(phase_timeout), async {
        sender.send_request(request).await.map_err(Into::into)
    })
    .await
    .map_err(|error| {
        if is_refresh_phase_timeout(&error) {
            crate::oauth::TransportFailure::Timeout
        } else {
            crate::oauth::TransportFailure::Protocol
        }
    })?;
    let status = response.status().as_u16();
    let bytes = refresh_http_body_phase(Some(phase_timeout), async {
        Limited::new(response.into_body(), 1024 * 1024)
            .collect()
            .await
    })
    .await
    .map_err(|error| {
        if is_refresh_phase_timeout(&error) {
            crate::oauth::TransportFailure::Timeout
        } else {
            crate::oauth::TransportFailure::Body
        }
    })?
    .to_bytes();
    Ok(crate::oauth::RefreshResponse::new(status, bytes.to_vec()))
}

fn is_refresh_phase_timeout(error: &Error) -> bool {
    error.downcast_ref::<RefreshPhaseTimeout>().is_some()
}

async fn resolve_refresh(
    runtime: &Runtime,
    oauth: Option<&crate::oauth::OAuthRefresh>,
    identity: &ConnectionIdentity,
    request_id: &str,
    tasks: &UpgradeTasks,
    pending: Box<crate::credential_injection::PendingInjection>,
) -> Result<crate::credential_injection::Start, Error> {
    let Some(oauth) = oauth else {
        return pending
            .resume_for_gateway(crate::oauth::RefreshOutcome::Rejected(
                crate::oauth::RefreshError::State,
            ))
            .map_err(Into::into);
    };
    let name = pending.credential_name().to_owned();
    let started = match oauth.begin(&name, time::OffsetDateTime::now_utc()) {
        Ok(started) => started,
        Err(error) => {
            return pending
                .resume_for_gateway(crate::oauth::RefreshOutcome::Rejected(error))
                .map_err(Into::into);
        }
    };
    let outcome = match started {
        crate::oauth::RefreshStart::NotNeeded(reason) => {
            return pending.not_needed_for_gateway(reason).map_err(Into::into);
        }
        crate::oauth::RefreshStart::Leader(attempt) => {
            let response =
                execute_refresh(runtime, identity, request_id, tasks, attempt.request()).await;
            attempt.complete_with_transactional_activation(
                response,
                time::OffsetDateTime::now_utc(),
                |phase, metadata| runtime.credential_activation.activate(phase, metadata),
            )
        }
        crate::oauth::RefreshStart::Follower(mut waiter) => {
            // This is a safe lifecycle observation: the request identity and
            // outcome contain no endpoint, form, response, or credential data.
            // It also makes the shared-flight boundary visible to the native
            // live workflow before its held leader is released.
            runtime.audit.emit(identity.request_event(
                "gateway.evaluated",
                crate::audit::Kind::Gateway,
                request_id,
                "Gateway request observation",
                json!({
                "outcome": "refresh_follower"
                }),
            ))?;
            waiter.wait().await
        }
    };
    pending.resume_for_gateway(outcome).map_err(Into::into)
}

fn gateway_response(
    status: u16,
    code: &str,
    request_id: &str,
    trace: Option<&crate::request_trace::TraceHook>,
) -> Result<Response<Body>, Error> {
    if let Some(trace) = trace {
        if status >= 500 {
            trace.error("GatewayError");
        } else {
            trace.evaluated("blocked", Some(json!({"status":status,"code":code}).into()));
        }
    }
    let status = StatusCode::from_u16(status)?;
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-blocked-by", "service-gateway")
        .header("x-safeyolo-request-id", request_id)
        .body(full(
            json!({"error":code,"addon":"service-gateway"}).to_string(),
        ))?;
    strip_hop_headers(response.headers_mut());
    Ok(response)
}

// Keep the immutable request snapshot separate from the reloadable state used
// by later requests inside CONNECT, and keep routing separate from identity.
#[allow(clippy::too_many_arguments)]
async fn forward<B>(
    runtime: Arc<Runtime>,
    state: RuntimeState,
    upgrades: UpgradeTasks,
    allow_upgrades: bool,
    identity: &ConnectionIdentity,
    request_id: &str,
    mut request: Request<B>,
    recording: Arc<flow_recording::Recording>,
    live: Option<Arc<crate::traffic_view::Exchange>>,
    destination: &Destination,
    tunnel: Option<&Tunnel>,
    trace: Option<Arc<RequestTrace>>,
) -> Result<(Response<Body>, String), Error>
where
    B: HttpBody<Data = Bytes> + Unpin + Send + Sync + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    if identity.run.as_ref().is_some_and(|run| {
        runtime
            .policy
            .as_ref()
            .is_none_or(|policy| !run.current(policy))
    }) {
        return Ok((
            prior_block(response(StatusCode::FORBIDDEN, "Current agent run changed")),
            "stale_agent_run".into(),
        ));
    }
    let pipeline_probe = probe::is_host(&destination.host);
    let client_version = request.version();
    // CONNECT has no ordinary traffic request hook. Observe its accepted
    // listener at admission, without consulting a second identity source.
    if request.method() == Method::CONNECT
        && let Some(agent) = identity.request_agent()
        && let Err(error) = runtime
            .agent_activity
            .observe(agent, crate::circuit_runtime::now())
    {
        eprintln!("Agent activity observation failed: {error}");
    }
    let traffic = (request.method() != Method::CONNECT)
        .then(|| traffic::Traffic::new(state.clone(), identity, request_id, &request, destination));
    let protected_parent =
        parent_for_destination(&runtime, identity, destination).is_some_and(|parent| {
            runtime
                .admin_shield
                .blocks_request_destination(&parent.host, parent.port)
        });
    if runtime
        .admin_shield
        .blocks_request_destination(&destination.host, destination.port)
    {
        let mut reply = prior_block(admin_rejection());
        traffic::local_reply(
            traffic.as_ref(),
            &mut request,
            &mut reply,
            Some(json!("admin-shield")),
            Some(json!("admin_port_access")),
            destination,
            false,
            trace.as_ref(),
        )?;
        return Ok((reply, "admin_port_access".into()));
    }
    if is_reserved(&destination.host) {
        if request.method() == Method::CONNECT {
            let mut reply = response(
                StatusCode::FORBIDDEN,
                "Reserved virtual host cannot accept CONNECT",
            );
            reply
                .headers_mut()
                .insert("x-blocked-by", "transport-guard".parse()?);
            return Ok((prior_block(reply), "local".into()));
        }
        if destination
            .host
            .trim_end_matches('.')
            .eq_ignore_ascii_case("_safeyolo.proxy.internal")
        {
            let reply = local_agent_api(
                &runtime,
                &state,
                traffic
                    .as_ref()
                    .expect("ordinary local HTTP traffic")
                    .clone(),
                identity,
                request_id,
                &upgrades,
                &mut request,
                destination,
                trace.as_ref(),
            )
            .await?;
            return Ok((prior_block(reply), "local".into()));
        }
        if !pipeline_probe {
            return Ok((
                response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Local endpoint is not implemented in the development proxy",
                ),
                "local".into(),
            ));
        }
    }
    if (request.method() == Method::CONNECT && (!allow_upgrades || tunnel.is_some()))
        || !matches!(destination.scheme.as_str(), "http" | "https")
        || (!pipeline_probe
            && destination.scheme == "https"
            && runtime.certificate_authority.is_none())
    {
        return Ok((
            response(
                StatusCode::NOT_IMPLEMENTED,
                "This transport is not implemented in the development proxy",
            ),
            "unsupported".into(),
        ));
    }
    if loop_detected(request.headers(), &runtime.via_token) {
        let mut response = response(
            StatusCode::LOOP_DETECTED,
            "Request would create a proxy loop",
        );
        response
            .headers_mut()
            .insert("x-blocked-by", "loop-guard".parse()?);
        traffic::local_reply(
            traffic.as_ref(),
            &mut request,
            &mut response,
            Some(json!("loop-guard")),
            Some(json!("proxy_loop")),
            destination,
            false,
            trace.as_ref(),
        )?;
        return Ok((prior_block(response), "deny".into()));
    }
    // Source request-ID hygiene precedes security addons. Keep inspection order
    // from the parser while applying the same removals to transport headers.
    // Framing/body ownership stays with Hyper; the bridge's body hint retains
    // its existing pre-removal interpretation.
    let body_present = request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|value| value != "0");
    // Request trailers are framing metadata owned by Hyper. Keep a transport
    // copy before source hygiene removes hop-by-hop fields from the policy and
    // recording view; the forwarded body still needs these declarations.
    let request_trailer = request.headers().get(header::TRAILER).cloned();
    let mut ordered_headers = crate::request_headers::RequestHeaders::take(&mut request)?;
    let hygiene = ordered_headers.apply_hygiene(request.headers_mut());
    if let Some(live) = &live {
        live.request_headers(live_view::pairs(ordered_headers.recording_pairs()));
    }
    if let Some(trace) = &trace {
        trace.enable(hygiene.trace_requested);
    }
    let policy_request = PolicyRequest {
        agent_id: identity.request_agent().unwrap_or(""),
        connection_id: &identity.connection_id,
        request_id,
        method: request.method().as_str(),
        // CONNECT carries an authority, without an HTTP scheme or path.
        // Routing defaults must not become path-condition policy inputs.
        scheme: if request.method() == Method::CONNECT {
            ""
        } else {
            &destination.scheme
        },
        host: &destination.policy_host,
        port: destination.port,
        path: if request.method() == Method::CONNECT {
            ""
        } else {
            &destination.path
        },
        header_names: ordered_headers
            .iter()
            .map(|(name, _)| std::str::from_utf8(name))
            .collect::<Result<_, _>>()?,
        body_present,
        trace_requested: hygiene.trace_requested,
    };
    let mut decision = decide(&runtime, identity, &policy_request, trace.as_ref()).await?;
    // Both identities use the existing guard and approval owner. Hostname
    // permission never suppresses a selected endpoint's applicable policy.
    if decision.allow
        && let Some(target) = &destination.selected_ip
    {
        let ip = target.ip.to_string();
        if destination.host != ip {
            decision = decide(
                &runtime,
                identity,
                &PolicyRequest {
                    host: &ip,
                    ..policy_request.clone()
                },
                trace.as_ref(),
            )
            .await?;
        }
    }
    if decision.allow != (decision.decision == "allow") {
        return Err("inconsistent policy decision".into());
    }
    if !decision.allow {
        let status = StatusCode::from_u16(decision.status.unwrap_or(403))?;
        if !status.is_client_error() && !status.is_server_error() {
            return Err("invalid policy denial status".into());
        }
        let mut denied = Response::builder()
            .status(status)
            .body(full(decision.body.unwrap_or_default()))?;
        for (name, value) in decision.headers {
            denied
                .headers_mut()
                .append(header::HeaderName::try_from(name)?, value.parse()?);
        }
        strip_hop_headers(denied.headers_mut());
        traffic::local_reply(
            traffic.as_ref(),
            &mut request,
            &mut denied,
            decision.blocked_by,
            decision.block_reason,
            destination,
            true,
            trace.as_ref(),
        )?;
        return Ok((prior_block(denied), decision.decision));
    }
    if request.method() == Method::CONNECT {
        if runtime
            .policy
            .as_ref()
            .and_then(crate::policy::Policy::gateway)
            .and_then(|gateway| gateway.provider_for_host(&destination.policy_host))
            .is_some()
        {
            // CONNECT has no authorized application route yet. Never open a
            // provider stream (or fall through to DNS) for opaque tunnel bytes.
            return Ok((
                prior_block(gateway_response(
                    403,
                    "GATEWAY_AUTH_REQUIRED",
                    request_id,
                    None,
                )?),
                "deny".into(),
            ));
        }
        if protected_parent {
            return Ok((prior_block(admin_rejection()), "admin_port_access".into()));
        }
        // Only a numeric CONNECT with hostname-dependent routing needs to wait.
        // Known routes retain their existing server-first establishment.
        let deferred = selected_ip::route_needs_name(&runtime, identity, destination);
        // Source logging selects a destination before DNS. Keep the existing
        // later transport matcher, including its resolved-peer behavior.
        // Freeze the generation used for admission before DNS/dial. The same
        // snapshot must decide the post-resolution peer and whether this
        // physical connection owns passthrough lifecycle events; an admin
        // update during the dial cannot change an admitted connection.
        let passthrough_matcher = runtime
            .passthrough
            .read()
            .map_err(|_| "passthrough configuration unavailable")?
            .clone();
        let ignored = passthrough_matcher
            .matches(&destination.host, destination.port, None)
            .then_some(crate::ignored_host_logger::SelectedDestination {
                host: &destination.host,
                port: destination.port,
            });
        let connected = if deferred {
            None
        } else {
            Some(
                open_egress_for_flow(
                    &runtime,
                    &AllowedRequest {
                        recording: Some(recording.as_ref()),
                        tasks: &upgrades,
                        destination,
                        identity,
                        request_id,
                    },
                    true,
                    Some(&passthrough_matcher),
                    ignored,
                    live.as_deref(),
                    None,
                )
                .await?,
            )
        };
        let passthrough = !deferred
            && passthrough_matcher.matches(
                &destination.host,
                destination.port,
                connected.as_ref().and_then(|connection| connection.peer),
            );
        let mut waiting = selected_ip::RouteWaitAudit::new(
            runtime.clone(),
            identity,
            request_id,
            destination,
            deferred,
        );
        let upgrade = hyper::upgrade::on(&mut request);
        let identity = identity.clone();
        let mut destination = destination.clone();
        let request_id = request_id.to_owned();
        if !allow_upgrades {
            return Err("nested CONNECT is unsupported".into());
        }
        let mut stop = upgrades.stop.clone();
        let descendants = upgrades.clone();
        upgrades.spawn_upgrade(async move {
            let mut outbound_attempted = !deferred;
            let result: Result<(), Error> = async {
                if *stop.borrow() {
                    return Ok(());
                }
                let client: BoxStream = tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    result = upgrade => Box::new(TokioIo::new(result?)),
                };
                let client = crate::tls_identity::observe_client(client, descendants.ingress.get().cloned());
                let (stream, connection_facts) = match connected {
                    Some(Connected { stream, h1_request_form, peer, observation, network }) => (Some(stream), Some((h1_request_form, peer, observation, network))),
                    None => (None, None),
                };
                let classification = if passthrough {
                    tunnels::Classification {
                        protocol: Protocol::Opaque,
                        client,
                        server: stream,
                        tls_server_name: None,
                    }
                } else {
                    match tunnels::classify(client, stream, &mut stop).await {
                        Ok(classification) => classification,
                        Err(error) => {
                            waiting.end(match error.downcast_ref::<tunnels::RouteWaitEnded>() {
                                Some(tunnels::RouteWaitEnded::Timeout) => "timeout",
                                Some(tunnels::RouteWaitEnded::Cancelled | tunnels::RouteWaitEnded::ClientClosed) => "cancelled",
                                None => "failed",
                            });
                            return Err(error);
                        }
                    }
                };
                let tunnels::Classification {
                    protocol: classified_protocol,
                    client,
                    server,
                    tls_server_name,
                } = classification;
                waiting.end("complete");
                if classified_protocol == Protocol::Tls && selected_ip::bind_tls_name(&mut destination, tls_server_name.as_deref())? {
                    selected_ip::apply_mapping(&mut destination, &runtime, &identity)?;
                    if is_reserved(&destination.host) || probe::is_host(&destination.host) {
                        return Err("reserved logical destination cannot use a selected IP".into());
                    }
                    if runtime.admin_shield.blocks_request_destination(&destination.host, destination.port) {
                        return Err(AdminPortAccess.into());
                    }
                    if runtime.policy.as_ref().and_then(crate::policy::Policy::gateway)
                        .and_then(|gateway| gateway.provider_for_host(&destination.policy_host)).is_some() {
                        return Err("provider destination cannot use an ordinary selected-IP tunnel".into());
                    }
                    let decision = decide(&runtime, &identity, &PolicyRequest {
                        agent_id: identity.request_agent().unwrap_or(""), connection_id: &identity.connection_id,
                        request_id: &request_id, method: "CONNECT", scheme: "", host: &destination.policy_host,
                        port: destination.port, path: "", header_names: Vec::new(), body_present: false, trace_requested: false,
                    }, None).await?;
                    if !decision.allow {
                        return Err("logical hostname policy refused CONNECT".into());
                    }
                    selected_ip::record(&runtime, &identity, &request_id, &destination, "logical_target", "allowed", json!({"outbound": if deferred { "not_attempted" } else { "connected" }}));
                }
                if *stop.borrow() {
                    return Err(tunnels::RouteWaitEnded::Cancelled.into());
                }
                let (mut server, h1_request_form, peer, mut observation, network) = match (server, connection_facts) {
                    (Some(server), Some((form, peer, observation, network))) => (server, form, peer, observation, network),
                    (None, None) => {
                        let ignored = passthrough_matcher.matches(&destination.host, destination.port, None)
                            .then_some(crate::ignored_host_logger::SelectedDestination { host: &destination.host, port: destination.port });
                        outbound_attempted = true;
                        let Connected { stream, h1_request_form, peer, observation, network } = open_egress_for_flow(
                            &runtime, &AllowedRequest { recording: Some(recording.as_ref()), tasks: &descendants, destination: &destination, identity: &identity, request_id: &request_id },
                            true, Some(&passthrough_matcher), ignored, None, None,
                        ).await?;
                        (stream, h1_request_form, peer, observation, network)
                    }
                    _ => unreachable!("CONNECT classification preserves its upstream owner"),
                };
                if destination.selected_ip.is_some() {
                    observation.target["logical_host"] = json!(destination.host);
                }
                let protocol = classified_protocol;
                let sni_passthrough = !passthrough
                    && protocol == Protocol::Tls
                    && tls_server_name.as_deref().is_some_and(|name| {
                        passthrough_matcher.matches(name, destination.port, None)
                    });
                if sni_passthrough {
                    let name = tls_server_name
                        .as_deref()
                        .expect("SNI passthrough requires a captured name");
                    let mut audit = ignored_host::ConnectionAudit::new(
                        runtime.audit.clone(),
                        &identity,
                        crate::ignored_host_logger::SelectedDestination {
                            host: name,
                            port: destination.port,
                        },
                    );
                    audit.connected();
                    server = ignored_host::observe_stream(server, audit);
                }
                let passthrough = passthrough || sni_passthrough;
                let protocol = if sni_passthrough {
                    Protocol::Opaque
                } else {
                    protocol
                };
                if protocol == Protocol::Opaque {
                    let started = std::time::Instant::now();
                    let result = tunnels::relay(client, server, stop).await;
                    runtime.audit.emit(identity.request_event(
                        "traffic.tunnel",
                        crate::audit::Kind::Traffic,
                        &request_id,
                        "Tunnel relay ended",
                        json!({
                        "host": destination.host,
                        "port": destination.port,
                        "coverage": if passthrough { "configured_passthrough" } else { "opaque" },
                        "uploaded_bytes": result.uploaded,
                        "downloaded_bytes": result.downloaded,
                        "duration_ms": started.elapsed().as_millis(),
                        "outcome": result.outcome
                        }),
                    ))?;
                    return Ok(());
                }
                let (client, http2, scheme): (BoxStream, bool, &str) = if protocol == Protocol::Tls
                {
                    let config = runtime
                        .certificate_authority
                        .as_ref()
                        .ok_or("TLS CA is not configured")?
                        .server_config(&destination.host, time::OffsetDateTime::now_utc())?;
                    selected_ip::record(&runtime, &identity, &request_id, &destination, "client_tls", "pending", json!({"verification_name": destination.host}));
                    let tls = tokio::select! {
                        _ = stop.changed() => Err("client TLS cancelled".into()),
                        result = TlsAcceptor::from(config).accept(client) => result.map_err(|error| -> Error { error.into() }),
                    };
                    let tls = match tls {
                        Ok(tls) => tls,
                        Err(error) => {
                            selected_ip::record(&runtime, &identity, &request_id, &destination, "client_tls", "failed", json!({"reason": error.to_string(), "verification_name": destination.host}));
                            return Err(error);
                        }
                    };
                    selected_ip::record(&runtime, &identity, &request_id, &destination, "client_tls", "complete", json!({"verification_name": destination.host}));
                    let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    if let Some(name) = tls.get_ref().1.server_name()
                        && let Some(connection) = descendants.ingress.get()
                    {
                        connection.tls(name);
                    }
                    let stream: BoxStream = match descendants.ingress.get() {
                        Some(network) => network.observe_tls(Box::new(tls), crate::observations::Point::ClientTls),
                        None => Box::new(tls),
                    };
                    (stream, http2, "https")
                } else {
                    (client, false, "http")
                };
                destination.scheme = scheme.into();
                let tunnel = Arc::new(Tunnel {
                    connect_request_id: request_id.clone(),
                    destination: destination.clone(),
                    sessions: upstream_h2::Sessions::default(),
                    connected_runtime: Arc::downgrade(&runtime),
                    upstream: tokio::sync::Mutex::new(Some(Connected {
                        stream: server,
                        h1_request_form,
                        peer,
                        observation,
                        network,
                    })),
                });
                serve_tunnel_http(state, identity.clone(), tunnel, client, http2, stop, descendants).await
            }
            .await;
            if let Err(error) = result {
                selected_ip::record(&runtime, &identity, &request_id, &destination, "connect_tunnel", "failed", json!({"reason": error.to_string(), "client_connect_status": 200, "outbound": if outbound_attempted { "attempted" } else { "not_attempted" }, "last_reached_stage": error.downcast_ref::<tunnels::RouteWaitEnded>().map(|_| "route_wait")}));
                eprintln!("CONNECT {request_id} ended: {error}");
                return Err(error);
            }
            Ok(())
        });
        return Ok((Response::new(full(Bytes::new())), decision.decision));
    }
    let (circuit_block, circuit_evidence_failed, circuit_hook_failed) = circuit_admission(
        &state,
        identity,
        request_id,
        request.method().as_str(),
        destination,
        trace.as_ref(),
    );
    if let Some(mut reply) = circuit_block {
        traffic::local_reply(
            traffic.as_ref(),
            &mut request,
            &mut reply,
            Some(json!("circuit-breaker")),
            None,
            destination,
            true,
            trace.as_ref(),
        )?;
        return Ok((prior_block(reply), "deny".into()));
    }
    if protected_parent {
        let mut reply = prior_block(admin_rejection());
        traffic::local_reply(
            traffic.as_ref(),
            &mut request,
            &mut reply,
            Some(json!("admin-shield")),
            Some(json!("admin_port_access")),
            destination,
            true,
            trace.as_ref(),
        )?;
        return Ok((reply, "admin_port_access".into()));
    }
    // Only the supported Codex token endpoint needs a bounded JSON credential
    // view. Other requests keep their original streaming body and trailers.
    let codex_endpoint = crate::credential_guard::codex::refresh_endpoint(
        &destination.scheme,
        &destination.host,
        destination.port,
        &destination.path,
    );
    let length = request.body().size_hint().exact();
    let (parts, body) = request.into_parts();
    let prepared = request_body::prepare_limited(
        body,
        length,
        !codex_endpoint,
        crate::credential_guard::codex::RESPONSE_LIMIT,
    )
    .await?;
    let codex_request_trailers = prepared.has_captured_trailers();
    let codex_refresh = prepared.unvalidated_content.as_ref().and_then(|body| {
        codex_endpoint
            .then(|| crate::credential_guard::codex::Refresh::parse(&parts.headers, body))
            .flatten()
    });
    let mut request = Request::from_parts(parts, prepared.body);
    // Only imported Codex authentication needs the convenience vault here.
    // Unlock on the blocking pool so independent traffic remains serviceable.
    let codex_vault = if codex_refresh.is_some()
        || (destination.scheme == "https"
            && destination.policy_host == "chatgpt.com"
            && destination.port == 443
            && request.headers().contains_key(header::AUTHORIZATION))
    {
        runtime
            .gateway_vault
            .load_async()
            .await?
            .map(|loaded| loaded.vault)
    } else {
        None
    };
    // Credential enforcement is deliberately after network and circuit
    // admission, but before test-context observation or any
    // outbound connection. The ordered parser view remains alive here so the
    // guard sees each original field. Combining repeated values can hide a
    // credential from entropy detection or change its approval fingerprint.
    if let Some(policy) = runtime.policy.as_ref() {
        let guard = runtime.credential_guard.as_ref().ok_or_else(|| {
            if let Some(hook) = trace
                .as_ref()
                .and_then(|trace| trace.hook("credential-guard", "request"))
            {
                hook.not_loaded();
            }
            "credential guard is unavailable"
        })?;
        let guard_trace = trace.as_ref().and_then(|trace| {
            trace.hook(
                "credential-guard",
                if request.method() == Method::CONNECT {
                    "http_connect"
                } else {
                    "request"
                },
            )
        });
        let guard = guard.clone().with_codex_vault(codex_vault.clone());
        let mut outcome = match guard.enforce_ordered(
            crate::credential_guard::Pdp::Ready(policy),
            identity.request_identity(),
            &destination.policy_host,
            destination.port,
            request.method().as_str(),
            &destination.path,
            &destination.scheme,
            Some(request_id),
            &identity.connection_id,
            false,
            ordered_headers.recording_pairs(),
            crate::credential_guard::Options {
                block: runtime.operator_modes.credential_block(),
            },
            crate::policy::current_time_ms(),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(hook) = &guard_trace {
                    hook.error("CredentialGuardError");
                }
                // A decoder, matcher, or policy observation error is a
                // terminal local failure. It cannot be interpreted as
                // no-detection and cannot reach open_outbound.
                return Err(error.into());
            }
        };
        if outcome.response.is_none()
            && let Some(refresh) = codex_refresh.as_ref()
        {
            let body = guard
                .enforce_codex_refresh(
                    crate::credential_guard::Pdp::Ready(policy),
                    crate::credential_guard::Request {
                        identity: identity.request_identity(),
                        host: &destination.policy_host,
                        port: destination.port,
                        method: request.method().as_str(),
                        path: &destination.path,
                        scheme: &destination.scheme,
                        request_id: Some(request_id),
                        connection_id: &identity.connection_id,
                        prior_response: false,
                        headers: &[],
                    },
                    refresh,
                    crate::credential_guard::Options {
                        block: runtime.operator_modes.credential_block(),
                    },
                    crate::policy::current_time_ms(),
                )
                .inspect_err(|_| {
                    if let Some(hook) = &guard_trace {
                        hook.error("CredentialGuardError");
                    }
                })?;
            outcome.audit.extend(body.audit);
            outcome.trace.extend(body.trace);
            outcome.evaluations.extend(body.evaluations);
            if !matches!(
                outcome.kind,
                crate::credential_guard::OutcomeKind::Blocked
                    | crate::credential_guard::OutcomeKind::Warned
            ) {
                outcome.kind = body.kind;
            }
            let refused = body.response.is_some();
            if refused || body.kind == crate::credential_guard::OutcomeKind::Warned {
                outcome.metadata = body.metadata;
            }
            if refused {
                outcome.kind = body.kind;
                outcome.response = body.response;
            }
        }
        publish_credential_trace(guard_trace.as_ref(), &outcome.trace);
        // Canonical audit is emitted exactly once per guard intent. The
        // attribution is trusted UDS identity; no credential value enters it.
        let mut events: Vec<_> = outcome
            .audit
            .iter()
            .map(|intent| intent.event(identity.audit_attribution()))
            .collect();
        let pending = crate::approvals::pending::bind_credentials(
            identity.run.as_ref(),
            &runtime.audit,
            policy,
            &mut events,
            &crate::policy::NetworkRequest {
                agent: identity.request_agent(),
                host: &destination.policy_host,
                port: Some(destination.port),
                method: request.method().as_str(),
                path: &destination.path,
            },
            &destination.scheme,
            outcome
                .response
                .as_ref()
                .is_some_and(|reply| reply.status == 428),
            &guard,
        )
        .await?;
        for mut event in events {
            crate::approvals::pending::correlate_credential(policy, &mut event);
            if event.decision == Some(crate::audit::Decision::RequireApproval)
                || (pending.is_some()
                    && event
                        .approval
                        .as_ref()
                        .is_some_and(|approval| approval.required))
            {
                runtime.audit.emit_confirmed(event).await?;
            } else {
                runtime.audit.emit(event)?;
            }
        }
        if let Some(record) = pending.as_ref() {
            crate::approvals::pending::delegation::notify(&runtime, record).await;
        }
        runtime.audit.emit(identity.request_event(
            "security.credential_guard.evaluated",
            crate::audit::Kind::Security,
            request_id,
            "Credential guard evaluated request",
            json!({
            "host": destination.policy_host,
            "port": destination.port,
            "outcome": outcome.kind,
            "trace": outcome.trace,
            "metadata": outcome.metadata,
            "evaluations": outcome.evaluations,
            "body_scope": if codex_refresh.is_some() { "codex_refresh_token" } else { "headers_only" },
            "query_scope": "policy_context_only"
            }),
        ))?;
        if codex_routing::routing_discovery(request.method(), &destination.path)
            && let Some(record) = pending.as_ref()
            && codex_routing::wait_for_decision(&state, &record.approval_id, upgrades.stop.clone())
                .await?
        {
            // Codex follows same-origin redirects for this GET. Its new request
            // goes through every current admission control and gets its own
            // request ID and budget charge. This GET has not reached the API.
            let mut retry = Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, &destination.path)
                .header(header::CACHE_CONTROL, "no-store")
                .header("x-safeyolo-approval-id", &record.approval_id)
                .body(full(Bytes::new()))?;
            traffic::local_reply(
                traffic.as_ref(),
                &mut request,
                &mut retry,
                None,
                None,
                destination,
                true,
                trace.as_ref(),
            )?;
            return Ok((prior_block(retry), "local".into()));
        }
        if let Some(enforcement) = outcome.response {
            let body = enforcement.body_bytes();
            let mut blocked = Response::builder()
                .status(StatusCode::from_u16(enforcement.status)?)
                .body(full(body))?;
            for (name, value) in enforcement.headers {
                blocked
                    .headers_mut()
                    .append(header::HeaderName::try_from(name)?, value.parse()?);
            }
            if let Some(record) = &pending {
                blocked
                    .headers_mut()
                    .insert("x-safeyolo-approval-id", record.approval_id.parse()?);
            }
            strip_hop_headers(blocked.headers_mut());
            traffic::local_reply(
                traffic.as_ref(),
                &mut request,
                &mut blocked,
                outcome.metadata.get("blocked_by").cloned(),
                outcome.metadata.get("block_reason").cloned(),
                destination,
                true,
                trace.as_ref(),
            )?;
            return Ok((prior_block(blocked), "deny".into()));
        }
    }
    // Applicable contracts and request-body rules retain pre-egress buffering.
    // Other intercepted H2 requests deliver headers and prefixes progressively.
    let gateway_headers: Vec<_> = ordered_headers
        .recording_pairs()
        .map(|(name, value)| {
            (
                crate::credential_text::source_text(name),
                crate::credential_text::source_text(value),
            )
        })
        .collect();
    let gateway_request = crate::services::GatewayRequest {
        identity: match identity.request_identity() {
            crate::network_guard::Identity::Resolved(agent) => {
                crate::services::TrustedIdentity::Agent(agent)
            }
            crate::network_guard::Identity::Current(run) => {
                crate::services::TrustedIdentity::Agent(&run.agent)
            }
            crate::network_guard::Identity::Conflict => crate::services::TrustedIdentity::Conflict,
            crate::network_guard::Identity::Unavailable => {
                crate::services::TrustedIdentity::Missing
            }
        },
        host: &destination.policy_host,
        request: crate::contracts::ContractRequest {
            method: request.method().as_str(),
            target: &destination.path,
            headers: &gateway_headers,
            body: &[],
        },
        route_mode: crate::services::RouteMode::LocalFallback,
    };
    let inspection_needs_body = inspection_options(&runtime, identity, &destination.policy_host)
        .is_ok()
        && runtime
            .scanner
            .has_scope(crate::inspection::Direction::Request, "body")?;
    let contract_needs_body = runtime
        .policy
        .as_ref()
        .and_then(crate::policy::Policy::gateway)
        .is_some_and(|gateway| gateway.requires_request_body(&gateway_request));
    let buffer_required = client_version != hyper::Version::HTTP_2
        || pipeline_probe
        || request.body().is_end_stream()
        || inspection_needs_body
        || contract_needs_body;
    let progressive = !buffer_required;
    let content_length = request.body().size_hint().exact();
    let (parts, body) = request.into_parts();
    let prepared = request_body::prepare(body, content_length, progressive).await?;
    let contract_body = prepared.unvalidated_content;
    let mut request = Request::from_parts(parts, prepared.body);
    let mut grant_lease = None;
    let mut gateway_injected_header = None;
    let mut gateway_recording_header = None;
    let mut gateway_evidence = None;
    let mut provider_route = None;
    let gateway_trace = trace
        .as_ref()
        .and_then(|trace| trace.hook("service-gateway", "request"));
    if let Some(policy) = runtime.policy.as_ref() {
        let snapshot = policy.gateway();
        let provider_name = snapshot
            .and_then(|snapshot| snapshot.provider_for_host(&destination.policy_host))
            .map(str::to_owned);
        if provider_name.is_some() && destination.selected_ip.is_some() {
            return Ok((
                prior_block(gateway_response(
                    403,
                    "GATEWAY_AUTH_REQUIRED",
                    request_id,
                    gateway_trace.as_ref(),
                )?),
                "deny".into(),
            ));
        }
        if ordered_headers
            .recording_pairs()
            .filter(|(_, value)| crate::services::has_gateway_token(value))
            .take(2)
            .count()
            > 1
        {
            let reply = gateway_response(403, "INVALID_TOKEN", request_id, gateway_trace.as_ref())?;
            return Ok((prior_block(reply), "deny".into()));
        }
        let gateway_decision = snapshot.map(|snapshot| {
            snapshot.select(crate::services::GatewayRequest {
                identity: match identity.request_identity() {
                    crate::network_guard::Identity::Resolved(agent) => {
                        crate::services::TrustedIdentity::Agent(agent)
                    }
                    crate::network_guard::Identity::Current(run) => {
                        crate::services::TrustedIdentity::Agent(&run.agent)
                    }
                    crate::network_guard::Identity::Conflict => {
                        crate::services::TrustedIdentity::Conflict
                    }
                    crate::network_guard::Identity::Unavailable => {
                        crate::services::TrustedIdentity::Missing
                    }
                },
                host: &destination.policy_host,
                request: crate::contracts::ContractRequest {
                    method: request.method().as_str(),
                    target: &destination.path,
                    headers: &gateway_headers,
                    // Contract selection runs only after request-body preparation;
                    // the prepared bytes remain owned by the replay body below.
                    body: contract_body
                        .as_ref()
                        .map_or(&[][..], |value| value.as_slice()),
                },
                route_mode: crate::services::RouteMode::CompiledPolicy(policy),
            })
        });
        let decision = match gateway_decision {
            Some(decision) => decision,
            None => {
                // A gateway token without an accepted catalog snapshot must
                // never become an ordinary upstream header.
                if ordered_headers
                    .recording_pairs()
                    .any(|(_, value)| crate::services::has_gateway_token(value))
                {
                    let reply = gateway_response(
                        503,
                        "GATEWAY_CONFIGURATION_ERROR",
                        request_id,
                        gateway_trace.as_ref(),
                    )?;
                    return Ok((prior_block(reply), "deny".into()));
                }
                crate::services::GatewayDecision::PassThrough
            }
        };
        match decision {
            crate::services::GatewayDecision::PassThrough => {
                if provider_name.is_some() {
                    let reply = gateway_response(
                        403,
                        "GATEWAY_AUTH_REQUIRED",
                        request_id,
                        gateway_trace.as_ref(),
                    )?;
                    return Ok((prior_block(reply), "deny".into()));
                }
                if let Some(hook) = &gateway_trace {
                    hook.evaluated("not_a_gateway_request", None);
                }
            }
            crate::services::GatewayDecision::Deny { status, code, .. } => {
                let reply = gateway_response(status, &code, request_id, gateway_trace.as_ref())?;
                return Ok((prior_block(reply), "deny".into()));
            }
            crate::services::GatewayDecision::Compatibility { .. } => {
                let reply = gateway_response(
                    503,
                    "GATEWAY_COMPATIBILITY_ERROR",
                    request_id,
                    gateway_trace.as_ref(),
                )?;
                return Ok((prior_block(reply), "deny".into()));
            }
            crate::services::GatewayDecision::Selected { credential } => {
                if let Some(hook) = &gateway_trace {
                    hook.evaluated("selected", None);
                }
                if let Some(provider) = provider_name {
                    let caller = identity.request_agent().expect("selected gateway identity");
                    let Some(caller_id) =
                        snapshot.and_then(|snapshot| snapshot.configured_agent_id(caller))
                    else {
                        let reply = gateway_response(
                            503,
                            "GATEWAY_IDENTITY_UNAVAILABLE",
                            request_id,
                            gateway_trace.as_ref(),
                        )?;
                        return Ok((prior_block(reply), "deny".into()));
                    };
                    provider_route = Some((provider, caller_id.to_owned(), caller.to_owned()));
                }
                if contract_needs_body && contract_body.is_none() {
                    // A streamed body cannot be checked against a contract
                    // without first owning its complete parser terminal. Do
                    // not inject or dial while its constraint is unknown.
                    let reply = gateway_response(
                        503,
                        "GATEWAY_BODY_UNAVAILABLE",
                        request_id,
                        gateway_trace.as_ref(),
                    )?;
                    return Ok((prior_block(reply), "deny".into()));
                }
                if let Some(risky) = credential.risky_route.as_ref() {
                    let risky_path = destination.path.split('?').next().unwrap_or("/");
                    let mut granted = None;
                    if let Some(store) = runtime.gateway_grants.as_ref() {
                        granted = store
                            .check_grant_authority(
                                crate::grants::RequestScope {
                                    agent: identity
                                        .request_agent()
                                        .expect("selected gateway identity"),
                                    service: &credential.service,
                                    method: request.method().as_str(),
                                    path: risky_path,
                                },
                                time::OffsetDateTime::now_utc(),
                                identity.run.as_ref().map(|run| {
                                    (
                                        policy,
                                        run,
                                        credential.capability.as_str(),
                                        credential.binding_id.as_deref(),
                                    )
                                }),
                                |_| Ok(()),
                            )
                            .map_err(|error| -> Error { Box::new(error) })?;
                    }
                    if granted.is_none() {
                        let risk = policy.evaluate_risky_route(crate::policy::RiskyRouteRequest {
                            service: &credential.service,
                            agent: identity.request_agent().expect("selected gateway identity"),
                            account: &credential.account,
                            tactics: &risky.tactics,
                            enables: &risky.enables,
                            irreversible: risky.irreversible,
                            method: request.method().as_str(),
                            path: risky_path,
                        });
                        if risk.effect != crate::policy::Effect::Allow {
                            let status = match risk.effect {
                                crate::policy::Effect::Deny => 403,
                                crate::policy::Effect::BudgetExceeded => 429,
                                _ => 428,
                            };
                            let agent =
                                identity.request_agent().expect("selected gateway identity");
                            let method = request.method().as_str();
                            let mut audit = crate::audit::Event::new(
                                "gateway.risky_route",
                                crate::audit::Kind::Gateway,
                                crate::audit::Severity::High,
                                format!(
                                    "Risky route {} {}{}",
                                    crate::network_guard::sanitize(method),
                                    crate::network_guard::sanitize(&credential.service),
                                    crate::network_guard::sanitize(risky_path),
                                ),
                            );
                            audit.addon = Some("service-gateway".into());
                            audit.decision = Some(match risk.effect {
                                crate::policy::Effect::Deny => crate::audit::Decision::Deny,
                                crate::policy::Effect::BudgetExceeded => {
                                    crate::audit::Decision::BudgetExceeded
                                }
                                _ => crate::audit::Decision::RequireApproval,
                            });
                            audit.host = Some(destination.policy_host.clone());
                            audit.agent = Some(agent.to_owned());
                            audit.request_id = Some(request_id.to_owned());
                            audit.attribution = Some(identity.audit_attribution());
                            if risk.effect == crate::policy::Effect::Prompt {
                                audit.approval = Some(crate::audit::Approval {
                                    required: true,
                                    approval_type: crate::audit::ApprovalType::GatewayRoute,
                                    key: format!(
                                        "gw:{agent}:{}:{method}:{risky_path}",
                                        credential.service
                                    ),
                                    target: credential.service.clone(),
                                    scope_hint: json!({"method":method,"path":risky_path}).into(),
                                });
                            }
                            audit.details = json!({
                                "service":credential.service,
                                "capability":credential.capability,
                                "method":method,
                                "path":risky_path,
                                "risky_route":risky.path,
                                "tactics":risky.tactics,
                                "enables":risky.enables,
                                "irreversible":risky.irreversible,
                                "description":risky.description,
                                "group":risky.group,
                                "effect":risk.effect,
                                "connection_id":identity.connection_id,
                            })
                            .into();
                            let pending = if risk.effect == crate::policy::Effect::Prompt {
                                let pending = crate::approvals::pending::bind_risky(
                                    &runtime,
                                    identity.run.as_ref(),
                                    &mut audit,
                                    crate::policy::NetworkRequest {
                                        agent: Some(agent),
                                        host: &destination.policy_host,
                                        port: Some(destination.port),
                                        method,
                                        path: &destination.path,
                                    },
                                    &destination.scheme,
                                    &credential,
                                )
                                .await?;
                                runtime.audit.emit_confirmed(audit).await?;
                                pending
                            } else {
                                runtime.audit.emit(audit)?;
                                None
                            };
                            let mut reply = gateway_response(
                                status,
                                "GATEWAY_RISKY_ROUTE",
                                request_id,
                                gateway_trace.as_ref(),
                            )?;
                            if let Some(record) = pending {
                                crate::approvals::pending::delegation::notify(&runtime, &record)
                                    .await;
                                reply
                                    .headers_mut()
                                    .insert("x-safeyolo-approval-id", record.approval_id.parse()?);
                            }
                            return Ok((prior_block(reply), "deny".into()));
                        }
                    }
                    grant_lease = granted;
                    runtime.audit.emit(identity.request_event("gateway.evaluated", crate::audit::Kind::Gateway, request_id, "Gateway request observation", json!({
"outcome": if grant_lease.is_some() { "grant_reserved" } else { "risky_route_allowed" },
"service": credential.service,
"capability": credential.capability,
"method": request.method().as_str(),
"path": risky_path
,"grant_id":grant_lease.as_ref().map(|lease| &lease.grant().grant_id)
})))?;
                }
                let full_url = crate::credentials::Secret::new(format!(
                    "{}://{}{}",
                    destination.scheme, destination.uri_authority, destination.path
                ));
                // The process-owned vault is the refresh coordinator's state
                // as well as the injection snapshot. Reconcile visible
                // external edits before selecting a credential. A malformed,
                // changed-salt, or unreadable reload deliberately retains the
                // last accepted snapshot; the subsequent snapshot check and
                // atomic refresh publication still fail closed on a visible
                // replacement.
                let loaded = if credential.auth_kind.is_some() {
                    runtime.gateway_vault.load_async().await?
                } else {
                    None
                };
                let vault = loaded.as_ref().map(|loaded| &loaded.vault);
                if let Some(vault) = vault {
                    let _ = vault.reload_if_changed();
                }
                let selected_model_request = crate::prompt_injection::is_claude_messages(
                    &credential,
                    identity.request_agent(),
                    &destination.scheme,
                    &destination.policy_host,
                    request.method().as_str(),
                    &destination.path,
                );
                let start = crate::credential_injection::prepare(
                    *credential,
                    vault,
                    crate::credential_injection::RequestInfo {
                        method: request.method().as_str(),
                        host: &destination.policy_host,
                        path: &destination.path,
                        scheme: &destination.scheme,
                        full_url: &full_url,
                        request_id: Some(request_id),
                    },
                    time::OffsetDateTime::now_utc(),
                );
                let start = match start {
                    Ok(start) => start,
                    Err(_) => {
                        let reply = gateway_response(
                            503,
                            "GATEWAY_INJECTION_ERROR",
                            request_id,
                            gateway_trace.as_ref(),
                        )?;
                        return Ok((prior_block(reply), "deny".into()));
                    }
                };
                let start =
                    match start {
                        crate::credential_injection::Start::External(pending) => {
                            pending
                                .resolve(runtime.config.native_settings.as_ref().and_then(
                                    |settings| settings.onepassword_executable.as_deref(),
                                ))
                                .await
                                .map_err(|error| Box::new(error) as Error)
                        }
                        crate::credential_injection::Start::Refresh(pending) => {
                            resolve_refresh(
                                &runtime,
                                loaded.as_ref().map(|loaded| &loaded.oauth),
                                identity,
                                request_id,
                                &upgrades,
                                pending,
                            )
                            .await
                        }
                        start => Ok(start),
                    };
                let start = match start {
                    Ok(start) => start,
                    Err(_) => {
                        let reply = gateway_response(
                            503,
                            "GATEWAY_INJECTION_ERROR",
                            request_id,
                            gateway_trace.as_ref(),
                        )?;
                        return Ok((prior_block(reply), "deny".into()));
                    }
                };
                match start {
                    crate::credential_injection::Start::Ready(replacement) => {
                        let name = replacement.name().clone();
                        let changed_headers: Vec<_> = replacement.changed_headers().collect();
                        gateway_recording_header = Some(name.clone());
                        let evidence = match replacement.apply(request.headers_mut()) {
                            Ok(evidence) => evidence,
                            Err(_) => {
                                let reply = gateway_response(
                                    503,
                                    "GATEWAY_INJECTION_ERROR",
                                    request_id,
                                    gateway_trace.as_ref(),
                                )?;
                                return Ok((prior_block(reply), "deny".into()));
                            }
                        };
                        for changed in changed_headers {
                            if let Some(value) = request.headers().get(&changed) {
                                ordered_headers.replace_value(&changed, value.as_bytes());
                            } else {
                                ordered_headers.remove(&changed);
                            }
                        }
                        if request.headers().contains_key(&name) {
                            gateway_injected_header = Some(name);
                        } else {
                            // A service without an auth stanza deliberately
                            // removes the gateway Authorization token. There
                            // is no materialized credential to re-evaluate in
                            // the final guard view.
                            gateway_injected_header = None;
                        }
                        gateway_evidence = Some(evidence);
                        if let Some(traffic) = &traffic {
                            traffic.selected_model_request(selected_model_request);
                        }
                        if let Some(hook) = &gateway_trace {
                            hook.evaluated("injected", None);
                        }
                    }
                    crate::credential_injection::Start::Blocked(blocked) => {
                        if let Some(hook) = &gateway_trace {
                            hook.evaluated("blocked", None);
                        }
                        publish_gateway_evidence(
                            &runtime,
                            identity,
                            request_id,
                            &blocked.evidence,
                        )?;
                        let body = blocked.response.body_bytes();
                        let mut reply = Response::builder()
                            .status(StatusCode::from_u16(blocked.response.status)?)
                            .body(full(body))?;
                        for (name, value) in blocked.response.headers {
                            reply
                                .headers_mut()
                                .append(header::HeaderName::try_from(name)?, value.parse()?);
                        }
                        strip_hop_headers(reply.headers_mut());
                        return Ok((prior_block(reply), "deny".into()));
                    }
                    crate::credential_injection::Start::Redirect(redirect) => {
                        if let Some(hook) = &gateway_trace {
                            hook.evaluated("redirected", None);
                        }
                        publish_gateway_evidence(
                            &runtime,
                            identity,
                            request_id,
                            &redirect.evidence,
                        )?;
                        let mut reply = Response::builder()
                            .status(StatusCode::from_u16(redirect.status())?)
                            .header(header::LOCATION, redirect.location().expose_secret())
                            .body(full(redirect.body()))?;
                        strip_hop_headers(reply.headers_mut());
                        return Ok((prior_block(reply), "deny".into()));
                    }
                    crate::credential_injection::Start::Refresh(_)
                    | crate::credential_injection::Start::External(_) => {
                        let reply = gateway_response(
                            503,
                            "GATEWAY_REFRESH_UNAVAILABLE",
                            request_id,
                            gateway_trace.as_ref(),
                        )?;
                        return Ok((prior_block(reply), "deny".into()));
                    }
                }
            }
        }
    }
    if let Some((_, caller_id, caller_name)) = &provider_route {
        let legacy_name = header::HeaderName::from_static("x-safeyolo-agent");
        request.headers_mut().remove(&legacy_name);
        ordered_headers.remove(&legacy_name);
        for (name, value) in [
            ("x-safeyolo-agent-id", caller_id.as_str()),
            ("x-safeyolo-agent-name", caller_name.as_str()),
        ] {
            let name = header::HeaderName::from_static(name);
            let value = match header::HeaderValue::from_str(value) {
                Ok(value) => value,
                Err(_) => {
                    let reply = gateway_response(
                        503,
                        "GATEWAY_IDENTITY_UNAVAILABLE",
                        request_id,
                        gateway_trace.as_ref(),
                    )?;
                    return Ok((prior_block(reply), "deny".into()));
                }
            };
            request.headers_mut().remove(&name);
            ordered_headers.remove(&name);
            request.headers_mut().insert(&name, value.clone());
            ordered_headers.replace_value(&name, value.as_bytes());
        }
    }
    // Gateway credentials are materialized only after the first request-hook
    // guard has run. Re-run the same process-owned guard over the final ordered
    // header view before dialing so a refreshed access token cannot bypass a
    // credential:use deny rule. This second observation is still header-only;
    // it does not inspect body bytes or create another guard owner.
    if let Some(name) = gateway_injected_header.as_ref()
        && let Some(policy) = runtime.policy.as_ref()
    {
        let guard = runtime.credential_guard.as_ref().ok_or_else(|| {
            if let Some(hook) = trace
                .as_ref()
                .and_then(|trace| trace.hook("credential-guard", "request"))
            {
                hook.not_loaded();
            }
            "credential guard is unavailable"
        })?;
        // The incoming request was already evaluated before gateway selection.
        // Re-evaluate only the header whose value the gateway replaced or
        // added. Replaying every incoming field here would charge budgets and
        // publish duplicate audit intents for unrelated credentials.
        let (field_name, field_value) = ordered_headers
            .iter()
            .find(|(field_name, _)| field_name.eq_ignore_ascii_case(name.as_str().as_bytes()))
            .ok_or("injected credential header disappeared")?;
        let guard_trace = trace.as_ref().and_then(|trace| {
            trace.hook(
                "credential-guard",
                if request.method() == Method::CONNECT {
                    "http_connect"
                } else {
                    "request"
                },
            )
        });
        let guard = guard.clone().with_codex_vault(codex_vault.clone());
        let outcome = match guard.enforce_ordered(
            crate::credential_guard::Pdp::Ready(policy),
            identity.request_identity(),
            &destination.policy_host,
            destination.port,
            request.method().as_str(),
            &destination.path,
            &destination.scheme,
            Some(request_id),
            &identity.connection_id,
            false,
            std::iter::once((field_name, field_value)),
            crate::credential_guard::Options {
                block: runtime.operator_modes.credential_block(),
            },
            crate::policy::current_time_ms(),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(hook) = &guard_trace {
                    hook.error("CredentialGuardError");
                }
                return Err(error.into());
            }
        };
        publish_credential_trace(guard_trace.as_ref(), &outcome.trace);
        let mut events: Vec<_> = outcome
            .audit
            .iter()
            .map(|intent| intent.event(identity.audit_attribution()))
            .collect();
        let pending = crate::approvals::pending::bind_credentials(
            identity.run.as_ref(),
            &runtime.audit,
            policy,
            &mut events,
            &crate::policy::NetworkRequest {
                agent: identity.request_agent(),
                host: &destination.policy_host,
                port: Some(destination.port),
                method: request.method().as_str(),
                path: &destination.path,
            },
            &destination.scheme,
            outcome
                .response
                .as_ref()
                .is_some_and(|reply| reply.status == 428),
            &guard,
        )
        .await?;
        for mut event in events {
            crate::approvals::pending::correlate_credential(policy, &mut event);
            if event.decision == Some(crate::audit::Decision::RequireApproval)
                || (pending.is_some()
                    && event
                        .approval
                        .as_ref()
                        .is_some_and(|approval| approval.required))
            {
                runtime.audit.emit_confirmed(event).await?;
            } else {
                runtime.audit.emit(event)?;
            }
        }
        if let Some(record) = pending.as_ref() {
            crate::approvals::pending::delegation::notify(&runtime, record).await;
        }
        runtime.audit.emit(identity.request_event(
            "security.credential_guard.evaluated",
            crate::audit::Kind::Security,
            request_id,
            "Credential guard evaluated request",
            json!({
            "host": destination.policy_host,
            "port": destination.port,
            "outcome": outcome.kind,
            "trace": outcome.trace,
            "metadata": outcome.metadata,
            "evaluations": outcome.evaluations,
            "body_scope": "headers_only",
            "query_scope": "policy_context_only"
            }),
        ))?;
        if let Some(enforcement) = outcome.response {
            let body = enforcement.body_bytes();
            let mut blocked = Response::builder()
                .status(StatusCode::from_u16(enforcement.status)?)
                .body(full(body))?;
            for (name, value) in enforcement.headers {
                blocked
                    .headers_mut()
                    .append(header::HeaderName::try_from(name)?, value.parse()?);
            }
            if let Some(record) = &pending {
                blocked
                    .headers_mut()
                    .insert("x-safeyolo-approval-id", record.approval_id.parse()?);
            }
            strip_hop_headers(blocked.headers_mut());
            traffic::local_reply(
                traffic.as_ref(),
                &mut request,
                &mut blocked,
                outcome.metadata.get("blocked_by").cloned(),
                outcome.metadata.get("block_reason").cloned(),
                destination,
                true,
                trace.as_ref(),
            )?;
            return Ok((prior_block(blocked), "deny".into()));
        }
    }
    if let Some(evidence) = gateway_evidence {
        publish_gateway_evidence(&runtime, identity, request_id, &evidence)?;
    }
    let admission = if circuit_hook_failed {
        // A prior request hook exception stops later source children. Reserved
        // context containment still applies before native forwarding (D55).
        request.headers_mut().remove(crate::test_context::HEADER);
        request_context::Admission::HookError
    } else {
        request_context::prepare(
            runtime.clone(),
            identity,
            request_id,
            &mut request,
            destination,
            trace.clone(),
        )?
    };
    if let Some(live) = &live {
        let context_header_present = request.headers().contains_key(crate::test_context::HEADER);
        live.request_headers(live_view::pairs(ordered_headers.recording_pairs().filter(
            |(name, _)| {
                context_header_present
                    || !name.eq_ignore_ascii_case(crate::test_context::HEADER.as_bytes())
            },
        )));
    }
    let inspection_admitted = !matches!(
        &admission,
        request_context::Admission::HookError | request_context::Admission::Block(_)
    );
    let mut context = match admission {
        request_context::Admission::Inactive => {
            request_context::RequestContext::traffic_only(&mut request, false, trace.clone())?
        }
        request_context::Admission::HookError => {
            request_context::RequestContext::traffic_only(&mut request, true, trace.clone())?
        }
        request_context::Admission::Block(mut response) => {
            traffic::local_reply(
                traffic.as_ref(),
                &mut request,
                &mut response,
                Some(json!("test-context")),
                None,
                destination,
                true,
                trace.as_ref(),
            )?;
            return Ok((prior_block(response), "deny".into()));
        }
        request_context::Admission::Pending(context) => context,
    };
    context.attach_stop(upgrades.stop.clone());
    let traffic = traffic.expect("CONNECT returned before ordinary HTTP hooks");
    traffic.request_headers(&request, destination);
    context.attach_traffic(traffic.clone());
    let response_traffic = traffic;
    context.attach_live(live.clone());
    if !circuit_hook_failed && inspection_admitted {
        match inspection_options(&runtime, identity, &destination.policy_host) {
            Ok(options) => context.attach_inspection(
                runtime.scanner.clone(),
                &destination.path,
                ordered_headers.iter(),
                options,
            ),
            Err(reason) => {
                if let Some(hook) = trace
                    .as_ref()
                    .and_then(|trace| trace.hook("pattern-scanner", "request"))
                {
                    hook.bypassed(reason);
                }
            }
        }
    }
    if let Some(provenance) = context.response_provenance() {
        recording.request(
            &request,
            destination,
            ordered_headers.recording_pairs(),
            hygiene.websocket,
            gateway_recording_header
                .as_ref()
                .map(|name| name.as_str().as_bytes()),
        );
        provenance.attach_recording(recording.clone());
    }
    // Retain only the recording projection after source hygiene/context removal;
    // credential and pattern inspection already consumed the ordered view.
    drop(ordered_headers);
    // The parser's initial size hint supplies source buffering classification,
    // including framing fields removed by header hygiene. It never proves EOM.
    let content_length = request.body().size_hint().exact();
    if pipeline_probe {
        let Some(mut context) = context
            .buffer_probe(request.into_body(), content_length)
            .await?
        else {
            return Err(probe::refuse_transport(&runtime, identity, destination));
        };
        // A source request-hook exception skips the later sink. Preserve that
        // failure boundary instead of publishing a successful probe receipt.
        if !context.request_hooks_completed() {
            return Err(probe::refuse_transport(&runtime, identity, destination));
        }
        if let Some(blocked) = enforce_request_inspection(
            &runtime,
            identity,
            request_id,
            destination,
            &context,
            &response_traffic,
        )? {
            return Ok((blocked, "deny".into()));
        }
        let mut reply = probe::response(state, &context, recording, request_id)?;
        if circuit_evidence_failed || context.try_finish().unwrap_or(false) {
            reply
                .headers_mut()
                .insert("x-safeyolo-evidence-error", "true".parse()?);
        }
        return Ok((reply, decision.decision));
    }
    let websocket = if hygiene.websocket {
        if !allow_upgrades {
            return Ok((
                response(
                    StatusCode::NOT_IMPLEMENTED,
                    "WebSocket upgrade is unavailable on this connection",
                ),
                "unsupported".into(),
            ));
        }
        match crate::websocket::Handshake::request(&mut request) {
            Ok(handshake) => Some((handshake, hyper::upgrade::on(&mut request))),
            Err(_) => {
                return Ok((
                    response(StatusCode::BAD_REQUEST, "Invalid WebSocket handshake"),
                    "invalid".into(),
                ));
            }
        }
    } else {
        None
    };
    // `Trailer` names the request body fields that follow the final chunk. It
    // is a hop-by-hop declaration, but the forwarded body is regenerated by
    // Hyper and still carries its trailer frame. Preserve the declaration so
    // the origin parser can associate that frame with the request instead of
    // silently dropping the fields at this handoff.
    strip_hop_headers(request.headers_mut());
    if let Some(trailer) = request_trailer {
        request.headers_mut().insert(header::TRAILER, trailer);
    }
    if websocket.is_some() {
        request
            .headers_mut()
            .insert(header::CONNECTION, "Upgrade".parse()?);
        request
            .headers_mut()
            .insert(header::UPGRADE, "websocket".parse()?);
    }
    for name in ["x-safeyolo-request-id", "x-safeyolo-trace"] {
        request.headers_mut().remove(name);
    }
    request
        .headers_mut()
        .insert(header::HOST, destination.authority.parse()?);
    request
        .headers_mut()
        .append(header::VIA, format!("1.1 {}", runtime.via_token).parse()?);
    let (parts, body) = request.into_parts();
    let (body, context) = if progressive {
        context.stream(body, content_length)?
    } else {
        context.buffer(body, content_length).await?
    };
    let mut request = Request::from_parts(parts, body);
    if let Some(blocked) = enforce_request_inspection(
        &runtime,
        identity,
        request_id,
        destination,
        &context,
        &response_traffic,
    )? {
        return Ok((blocked, "deny".into()));
    }
    let allowed = AllowedRequest {
        recording: Some(recording.as_ref()),
        tasks: &upgrades,
        destination,
        identity,
        request_id,
    };
    let provider = provider_route.as_ref().map(|(name, _, _)| name.as_str());
    let outbound = if client_version == hyper::Version::HTTP_2
        && let Some(tunnel) = tunnel
    {
        tunnel
            .sessions
            .select(&runtime, &allowed, provider, tunnel, live.as_deref())
            .await?
    } else {
        upstream_h2::Selected::Unshared(Box::new(
            open_outbound(
                &runtime,
                &allowed,
                provider,
                false,
                tunnel,
                live.as_deref(),
                None,
            )
            .await?,
        ))
    };
    let outbound_http2 = outbound.http2();
    recording.connection(outbound.observation());
    // A reused H2 connection's original TLS event belongs to another inner
    // request. Associate its observed facts with this request explicitly;
    // explain must not include that sibling to recover connection evidence.
    selected_ip::record(
        &runtime,
        identity,
        request_id,
        destination,
        "upstream_connection",
        "associated",
        json!({"upstream": outbound.observation().snapshot()}),
    );
    *request.uri_mut() = request_uri(
        destination,
        &format!(
            "{}://{}{}",
            destination.scheme, destination.uri_authority, destination.path
        ),
        outbound_http2,
        outbound.h1_request_form(),
    )?;
    // Select only after all request mutation, including gateway injection and
    // body preparation, and after verified upstream TLS. No redirect is followed
    // here; the response is bound to this exact request and destination.
    let ghcr_exchange = runtime
        .credential_guard
        .as_ref()
        .map(|guard| {
            guard.ghcr_exchange(
                &destination.scheme,
                &destination.host,
                destination.port,
                request.method(),
                &destination.path,
                request.headers(),
                // Select only the final head here. Progressive empty DATA can
                // finish later; registration also requires the parser-validated
                // empty body from this exchange's completion owner below.
                context.request_body_empty()
                    || (progressive && content_length.is_none_or(|length| length == 0)),
                gateway_injected_header.is_some(),
            )
        })
        .transpose()?
        .flatten();
    let codex_exchange = if codex_endpoint
        && request.method() == Method::POST
        && !codex_request_trailers
        && gateway_injected_header.is_none()
    {
        // Body preparation and inspection replay the captured bytes unchanged.
        // Recheck the final headers: hygiene may have removed Content-Type.
        match (&runtime.credential_guard, &runtime.policy, &codex_refresh) {
            (Some(guard), Some(policy), Some(refresh)) => guard
                .clone()
                .with_codex_vault(codex_vault.clone())
                .codex_exchange(
                    policy,
                    identity.request_identity(),
                    refresh,
                    request.headers(),
                )?,
            _ => None,
        }
    } else {
        None
    };
    request.extensions_mut().insert(recording.clone());
    let completion = circuit_completion::Completion::register(
        &mut request,
        outbound_http2,
        state.clone(),
        identity.clone(),
        request_id.to_owned(),
        destination.policy_host.clone(),
        Some(context),
        grant_lease.take(),
        runtime.gateway_grants.clone(),
    );
    let mut request = request.map(|body| ForwardedRequestBody {
        body,
        completion: completion.clone(),
        live: live.clone(),
        _session: None,
    });
    let (mut upstream, connection) = match outbound {
        upstream_h2::Selected::Http2(session) => {
            let session = Arc::new(session);
            // An origin can finish its response while an upload is still
            // gated. Keep the session active until both body owners drop.
            request.body_mut()._session = Some(session.clone());
            request.headers_mut().remove(header::HOST);
            *request.version_mut() = hyper::Version::HTTP_2;
            let mut sender = session.sender();
            let driver = completion.clone().observe();
            let connection = HttpTask {
                task: upgrades.spawn(async move {
                    let _ = driver.await;
                }),
                completion: Some(completion.clone()),
                _session: Some(session),
            };
            (sender.send_request(request).await?, connection)
        }
        upstream_h2::Selected::Unshared(outbound) => {
            let outbound = *outbound;
            let request = if progressive {
                // HTTP/1 Content-Length is itself the message boundary. In
                // particular, zero would complete at HEADERS before ingress
                // END_STREAM. Retain the original small-body parser barrier
                // for negotiated H1 fallback; large bodies still stream.
                let (parts, body) = request.into_parts();
                let prepared = request_body::prepare(body, content_length, false).await?;
                Request::from_parts(parts, prepared.body.boxed())
            } else {
                request.map(BodyExt::boxed)
            };
            let mut request = request;
            *request.version_mut() = hyper::Version::HTTP_11;
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .handshake(TokioIo::new(outbound.stream))
                .await
                .inspect_err(|_| {
                    if let Some(network) = &outbound.network {
                        network.failed("http_handshake_failed");
                    }
                })?;
            let driver = completion.clone().drive(connection.with_upgrades());
            let sender_network = outbound.network.clone();
            let connection = HttpTask {
                task: upgrades.spawn(async move {
                    if let Err(error) = driver.await {
                        if let Some(network) = outbound.network {
                            network.http_error(&error);
                        }
                        eprintln!("upstream HTTP connection: {error}");
                    }
                }),
                completion: Some(completion.clone()),
                _session: None,
            };
            (
                sender.send_request(request).await.inspect_err(|error| {
                    if let Some(network) = &sender_network {
                        network.http_error(error);
                    }
                })?,
                connection,
            )
        }
    };
    completion.headers_received();
    selected_ip::record(
        &runtime,
        identity,
        request_id,
        destination,
        "http_response",
        "received",
        json!({"http_status": upstream.status().as_u16()}),
    );
    let _ = completion.try_finish();
    if let Some(live) = &live {
        let version = format!("{:?}", upstream.version());
        let reason = upstream
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|reason| reason.as_bytes())
            // The reached H1 parser stores a ReasonPhrase only when the
            // accepted bytes differ from the status' canonical phrase. This
            // is a parser fact, rather than a status-derived export guess.
            .or_else(|| {
                if upstream.version() == hyper::Version::HTTP_2 {
                    Some(&[][..])
                } else {
                    upstream.status().canonical_reason().map(str::as_bytes)
                }
            });
        live.response_details(Some(&version), reason);
    }
    if completion.evidence_failed() || circuit_evidence_failed {
        upstream
            .headers_mut()
            .insert("x-safeyolo-evidence-error", "true".parse()?);
    }
    if upstream.status() == StatusCode::SWITCHING_PROTOCOLS {
        let reject_upgrade = |error: Error| {
            if let Some(live) = &live {
                live.websocket_rejected(&error.to_string());
            }
            error
        };
        let Some((handshake, client_upgrade)) = websocket else {
            return Err(reject_upgrade("unexpected upstream protocol switch".into()));
        };
        let negotiated = handshake.response(&upstream).map_err(reject_upgrade)?;
        let server_upgrade = hyper::upgrade::on(&mut upstream);
        let (mut parts, _) = upstream.into_parts();
        parts.extensions.insert(live_view::Upstream);
        strip_hop_headers(&mut parts.headers);
        parts.headers.insert(header::CONNECTION, "Upgrade".parse()?);
        parts.headers.insert(header::UPGRADE, "websocket".parse()?);
        if !allow_upgrades {
            return Err(reject_upgrade("WebSocket upgrade owner unavailable".into()));
        }
        let mut stop = upgrades.stop.clone();
        let session = crate::websocket_relay::Session {
            state,
            identity: identity.clone(),
            request_id: request_id.to_owned(),
            host: destination.host.clone(),
            port: destination.port,
            live: live.clone(),
        };
        let live_session = session.start_live();
        let memory_host = destination.policy_host.clone();
        let descendants = upgrades.clone();
        upgrades.spawn(async move {
            let _live_session = live_session;
            let _connection = connection;
            let result: Result<(), Error> = async {
                if *stop.borrow() {
                    return Ok(());
                }
                let (client, server) = tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    result = async { tokio::try_join!(client_upgrade, server_upgrade) } => result?,
                };
                let memory = crate::memory_runtime::WebSocket::new(
                    &runtime,
                    &session.identity.connection_id,
                    &memory_host,
                );
                runtime.audit.emit(session.identity.request_event(
                    "traffic.websocket.start",
                    crate::audit::Kind::Traffic,
                    &session.request_id,
                    "WebSocket relay started",
                    json!({
                    "host": session.host,
                    "port": session.port,
                    "subprotocol": negotiated.subprotocol,
                    "compressed_client": negotiated.client.is_some(),
                    "compressed_server": negotiated.server.is_some()
                    }),
                ))?;
                crate::websocket_relay::relay(
                    Box::new(TokioIo::new(client)),
                    Box::new(TokioIo::new(server)),
                    negotiated,
                    session,
                    stop,
                    memory,
                    descendants,
                )
                .await
            }
            .await;
            if result.is_err() {
                eprintln!("WebSocket connection ended with an error");
            }
        });
        return Ok((
            Response::from_parts(parts, full(Bytes::new())),
            decision.decision,
        ));
    }
    let response_scan = match inspection_options(&runtime, identity, &destination.policy_host) {
        Ok(options)
            if runtime
                .scanner
                .has_scope(crate::inspection::Direction::Response, "headers")?
                || runtime
                    .scanner
                    .has_scope(crate::inspection::Direction::Response, "body")? =>
        {
            Some(options)
        }
        _ => None,
    };
    let response_body_scan = match response_scan {
        Some(options)
            if runtime
                .scanner
                .has_scope(crate::inspection::Direction::Response, "body")? =>
        {
            Some(options)
        }
        _ => None,
    };
    let response_length = upstream
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .map_or(&b""[..], |value| value.as_bytes());
    let response_buffering = response_body_scan.is_some()
        && !test_context::source_streamed(&runtime, &destination.policy_host, content_type);
    // Keep the parser's response header view through hop-header cleanup. The
    // source response hook sees every header, while downstream transport must
    // still receive the existing stripped projection.
    let response_headers = upstream
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    // Hyper removes chunk framing while reading the upstream response, but it
    // leaves any earlier transfer codings in the body. Regenerate the final
    // chunk framing and retain the coding declaration for an HTTP/1.1 client.
    let transfer_coding = upstream
        .headers()
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let has_non_chunked_transfer_coding = transfer_coding.iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|coding| !coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
    });
    if has_non_chunked_transfer_coding && client_version != hyper::Version::HTTP_11 {
        return Err("upstream transfer coding cannot be relayed to this client protocol".into());
    }
    let (mut parts, body) = upstream.into_parts();
    let body = body.boxed();
    let ghcr_exchange = ghcr_exchange
        .filter(|_| parts.status == StatusCode::OK && !has_non_chunked_transfer_coding);
    let codex_exchange = codex_exchange
        .filter(|_| parts.status == StatusCode::OK && !has_non_chunked_transfer_coding);
    let observes_codex = codex_exchange.is_some();
    let body = if ghcr_exchange.is_some() || observes_codex {
        let prepared = request_body::prepare_limited(
            body,
            response_length,
            false,
            crate::credential_guard::ghcr::RESPONSE_LIMIT,
        )
        .await?;
        let mut codex_recorded = false;
        if let Some(content) = &prepared.unvalidated_content {
            // Body EOF alone is insufficient (notably H2 NO_ERROR reset).
            // Register before any buffered response bytes reach the client.
            if completion.response_complete()
                && if observes_codex {
                    completion.request_complete()
                } else {
                    completion.request_body_empty()
                }
            {
                let encoding = test_context::combined(&parts.headers, header::CONTENT_ENCODING)?;
                if let Ok(decoded) = crate::http_content::decode_prefix_with_size(
                    content,
                    &encoding,
                    crate::credential_guard::ghcr::RESPONSE_LIMIT,
                ) && decoded.total_bytes <= crate::credential_guard::ghcr::RESPONSE_LIMIT
                {
                    if let Some(exchange) = ghcr_exchange {
                        runtime
                            .credential_guard
                            .as_ref()
                            .expect("selected credential guard")
                            .observe_ghcr_response(
                                exchange,
                                &decoded.content,
                                crate::policy::current_time_ms(),
                            )?;
                    }
                    if let Some(exchange) = codex_exchange {
                        let guard = runtime
                            .credential_guard
                            .clone()
                            .expect("selected credential guard")
                            .with_codex_vault(codex_vault.clone());
                        let policy = runtime.policy.clone().expect("selected policy");
                        let bound_identity = identity.clone();
                        codex_recorded = tokio::task::spawn_blocking(move || {
                            guard.observe_codex_response(
                                exchange,
                                &policy,
                                bound_identity.request_identity(),
                                &decoded.content,
                            )
                        })
                        .await??;
                        if codex_recorded {
                            let mut event = identity.request_event(
                                "security.credential_guard.codex_refreshed", crate::audit::Kind::Security, request_id,
                                "Observed Codex refresh response from authorized issuer",
                                json!({"host":"auth.openai.com","client_id":crate::credential_guard::codex::CLIENT_ID}),
                            );
                            event.addon = Some("credential-guard".into());
                            event.decision = Some(crate::audit::Decision::Allow);
                            runtime.audit.emit_confirmed(event).await?;
                        }
                    }
                }
            }
        }
        if observes_codex && !codex_recorded {
            return Err("Codex refresh response did not establish trusted replacements".into());
        }
        prepared.body.boxed()
    } else {
        body
    };
    parts.extensions.insert(live_view::Upstream);
    strip_hop_headers(&mut parts.headers);
    if has_non_chunked_transfer_coding {
        for value in transfer_coding {
            parts.headers.append(header::TRANSFER_ENCODING, value);
        }
    }
    if response_buffering {
        let prepared = request_body::prepare(body, response_length, false).await?;
        if prepared.unvalidated_content.is_some() && completion.response_incomplete() {
            // A NO_ERROR reset can look like clean EOF to Hyper's H2 Incoming.
            // Never hand that captured prefix to the scanner or release it as
            // a complete buffered response.
            return Err("upstream response ended before protocol completion".into());
        }
        if let Some(body) = prepared.unvalidated_content {
            let body = Arc::new(body);
            let (inspected, scan_lifetime) = scan_response_with_lifetime(
                runtime.scanner.clone(),
                response_headers.clone(),
                Some(body.clone()),
                response_body_scan.expect("body scanner selected"),
                upgrades.stop.clone(),
            )
            .await?;
            let _publication = scan_lifetime.publication()?;
            if scan_lifetime.cancelled() || *upgrades.stop.borrow() {
                return Err("response inspection cancelled".into());
            }
            if let Some(blocked) = enforce_response_decision(
                &runtime,
                identity,
                request_id,
                destination,
                &response_traffic,
                &inspected,
            )? {
                return Ok((blocked, "deny".into()));
            }
            return Ok((
                Response::from_parts(parts, full(Bytes::copy_from_slice(body.as_slice()))),
                decision.decision,
            ));
        }
        if let Some(options) = response_scan {
            let (inspected, scan_lifetime) = scan_response_with_lifetime(
                runtime.scanner.clone(),
                response_headers.clone(),
                None,
                options,
                upgrades.stop.clone(),
            )
            .await?;
            let _publication = scan_lifetime.publication()?;
            if scan_lifetime.cancelled() || *upgrades.stop.borrow() {
                return Err("response inspection cancelled".into());
            }
            if let Some(blocked) = enforce_response_decision(
                &runtime,
                identity,
                request_id,
                destination,
                &response_traffic,
                &inspected,
            )? {
                return Ok((blocked, "deny".into()));
            }
        }
        return Ok((
            Response::from_parts(
                parts,
                UpstreamBody {
                    body: prepared.body,
                    _connection: connection,
                    completion: Some(completion.clone()),
                    incomplete_reported: false,
                    live: live.clone(),
                }
                .boxed(),
            ),
            decision.decision,
        ));
    }
    if let Some(options) = response_scan {
        let (inspected, scan_lifetime) = scan_response_with_lifetime(
            runtime.scanner.clone(),
            response_headers,
            None,
            options,
            upgrades.stop.clone(),
        )
        .await?;
        let _publication = scan_lifetime.publication()?;
        if scan_lifetime.cancelled() || *upgrades.stop.borrow() {
            return Err("response inspection cancelled".into());
        }
        if let Some(blocked) = enforce_response_decision(
            &runtime,
            identity,
            request_id,
            destination,
            &response_traffic,
            &inspected,
        )? {
            return Ok((blocked, "deny".into()));
        }
    }
    Ok((
        Response::from_parts(
            parts,
            UpstreamBody {
                body,
                _connection: connection,
                completion: Some(completion.clone()),
                incomplete_reported: false,
                live: live.clone(),
            }
            .boxed(),
        ),
        decision.decision,
    ))
}

async fn serve_tunnel_http(
    state: RuntimeState,
    identity: ConnectionIdentity,
    tunnel: Arc<Tunnel>,
    client: BoxStream,
    http2: bool,
    mut stop: tokio::sync::watch::Receiver<bool>,
    upgrades: UpgradeTasks,
) -> Result<(), Error> {
    let request_upgrades = upgrades.clone();
    let service = hyper::service::service_fn(move |request| {
        serve_request(
            state.clone(),
            identity.clone(),
            request,
            Some(tunnel.clone()),
            request_upgrades.clone(),
            !http2,
        )
    });
    let result = if http2 {
        let mut builder = hyper::server::conn::http2::Builder::new(Executor(upgrades.clone()));
        if let Some(connection) = upgrades.ingress.get() {
            let source = connection.source();
            builder.on_stream_parse_error(h2::ext::StreamParseErrorObserver::new(move |id| {
                source.http2_stream_parse_error(id);
            }));
        }
        let connection = builder.serve_connection(TokioIo::new(client), service);
        tokio::pin!(connection);
        if *stop.borrow() {
            connection.as_mut().graceful_shutdown();
        }
        tokio::select! {
            result = &mut connection => result,
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.await
            }
        }
    } else {
        let connection = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(TokioIo::new(client), service)
            .with_upgrades();
        tokio::pin!(connection);
        if *stop.borrow() {
            connection.as_mut().graceful_shutdown();
        }
        tokio::select! {
            result = &mut connection => result,
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.await
            }
        }
    };
    if let Err(error) = &result
        && let Some(connection) = upgrades.ingress.get()
    {
        connection.http_error(error);
    }
    result?;
    // The accepted connection is the sole drainer, including nested upgrades.
    Ok(())
}

pub(crate) fn serve_request(
    state: RuntimeState,
    identity: ConnectionIdentity,
    mut request: Request<Incoming>,
    tunnel: Option<Arc<Tunnel>>,
    upgrades: UpgradeTasks,
    allow_upgrades: bool,
) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>> {
    Box::pin(async move {
        let runtime = state.read().expect("runtime read lock").clone();
        let request_id = format!("req-{}", uuid::Uuid::new_v4().simple());
        if identity.request_agent().is_none() {
            let mut event = identity.request_event(
                "security.agent_identity_unavailable",
                crate::audit::Kind::Security,
                &request_id,
                "Traffic has no trusted agent identity",
                json!({"reason":"no_trusted_identity"}),
            );
            event.addon = Some("identity".into());
            event.severity = crate::audit::Severity::Medium;
            event.decision = Some(crate::audit::Decision::Log);
            if runtime.audit.emit(event).is_err() {
                return Ok(response(StatusCode::BAD_GATEWAY, "Proxy request failed"));
            }
        }
        if let Some(connection) = upgrades.ingress.get() {
            let stream_id = request
                .extensions()
                .get::<h2::StreamId>()
                .map(h2::StreamId::as_u32);
            let source = connection.source();
            // Plain CONNECT replays a prefix from the outer HTTP connection;
            // its new parser offsets cannot identify that older stream range.
            let parser_offsets_match_source =
                !(tunnel.is_some() && source.point == crate::observations::Point::AgentUds);
            let byte_range = request
                .extensions()
                .get::<hyper::ext::RequestByteRange>()
                .cloned();
            let application = source.application(
                &request_id,
                stream_id,
                byte_range,
                request.method() != Method::CONNECT,
                parser_offsets_match_source,
            );
            request.extensions_mut().insert(application);
        }
        let connect = request.method() == Method::CONNECT;
        let head = request.method() == Method::HEAD;
        let recording = flow_recording::Recording::new(
            runtime.flow_recorder.clone(),
            identity.clone(),
            request_id.clone(),
            !connect,
        );
        recording.observe_connections(&runtime);
        let _pending_recording = recording.pending();
        let destination =
            Destination::from_request(&request, tunnel.as_ref().map(|tunnel| &tunnel.destination))
                .and_then(|mut destination| {
                    if let Err(error) =
                        selected_ip::apply_mapping(&mut destination, &runtime, &identity)
                    {
                        selected_ip::record(
                            &runtime,
                            &identity,
                            &request_id,
                            &destination,
                            "target_selection",
                            "failed",
                            json!({"reason": error.to_string(), "outbound": "not_attempted"}),
                        );
                        return Err(error);
                    }
                    if destination.selected_ip.is_some() {
                        selected_ip::record(
                            &runtime,
                            &identity,
                            &request_id,
                            &destination,
                            "target_selection",
                            "pending_policy",
                            json!({"outbound": "not_attempted"}),
                        );
                    }
                    Ok(destination)
                });
        // A physical connection can carry unrelated requests. Link only the
        // requests parsed inside this selected-IP CONNECT, including refusals.
        let connect_link_failed = tunnel
            .as_ref()
            .filter(|tunnel| tunnel.destination.selected_ip.is_some())
            .is_some_and(|tunnel| {
                runtime
                    .audit
                    .emit(identity.request_event(
                        "traffic.connect_request",
                        crate::audit::Kind::Traffic,
                        &request_id,
                        "HTTP request belongs to CONNECT",
                        json!({
                            "host": tunnel.destination.host,
                            "port": tunnel.destination.port,
                            "connect_request_id": tunnel.connect_request_id,
                        }),
                    ))
                    .is_err()
            });
        if let Ok(destination) = &destination {
            recording.target(
                destination,
                tunnel
                    .as_ref()
                    .map(|tunnel| tunnel.connect_request_id.as_str()),
            );
        }
        let live = destination.as_ref().ok().and_then(|destination| {
            live_view::begin(&runtime, &identity, &request_id, &request, destination)
        });
        if let (Some(live), Some(tunnel)) = (
            &live,
            tunnel
                .as_ref()
                .filter(|tunnel| tunnel.destination.selected_ip.is_some()),
        ) {
            live.metadata(&serde_json::Map::from_iter([(
                "connect_request_id".into(),
                json!(tunnel.connect_request_id),
            )]));
        }
        if destination
            .as_ref()
            .is_ok_and(|destination| probe::is_host(&destination.host))
        {
            recording.mark_probe();
        }
        // Presence allocates an inert carrier; the existing ordered header
        // hygiene decides whether the opt-in is nonempty and actually reached.
        let trace = destination
            .as_ref()
            .ok()
            .filter(|_| request.headers().contains_key("x-safeyolo-trace"))
            .map(|destination| {
                Arc::new(RequestTrace::new(
                    runtime.traces.clone(),
                    &identity,
                    &request_id,
                    request.method().as_str(),
                    &destination.policy_host,
                    destination.port,
                ))
            });
        let result = match &destination {
            Ok(destination) => {
                forward(
                    runtime.clone(),
                    state.clone(),
                    upgrades,
                    allow_upgrades,
                    &identity,
                    &request_id,
                    request,
                    recording.clone(),
                    live.clone(),
                    destination,
                    tunnel.as_deref(),
                    trace.clone(),
                )
                .await
            }
            Err(_) => Ok((
                response(StatusCode::BAD_REQUEST, "Invalid request authority"),
                "invalid".into(),
            )),
        };
        if let Err(error) = &result {
            if let Some(live) = &live {
                live.finish(Some(&error.to_string()));
            }
            if error.is::<probe::TransportRefused>()
                && let Some(hook) = trace
                    .as_ref()
                    .and_then(|trace| trace.hook("transport-guard", "request"))
            {
                hook.untimed_error(
                    "probe_reached_upstream",
                    Some(json!({"error_type":"NativeProbeTransportRefused"}).into()),
                );
            }
            recording.producer_error(error);
            recording.finish(false, None, false);
        }
        let local_live_response = result
            .as_ref()
            .is_ok_and(|(reply, _)| reply.extensions().get::<live_view::Upstream>().is_none());
        let (mut reply, decision) = result.unwrap_or_else(|error| {
            if error.is::<AdminPortAccess>() {
                return (admin_rejection(), "admin_port_access".into());
            }
            // Errors contain no application headers/body. A transport/adapter error never retries another route.
            eprintln!("request {request_id} failed: {error}");
            (
                response(StatusCode::BAD_GATEWAY, "Proxy request failed"),
                "error".into(),
            )
        });
        // Hyper's HTTP/2 server can send DATA for a HEAD response. Local
        // refusals must end after the headers, while keeping their decision
        // and response metadata. Upstream HEAD completion keeps its own owner.
        if head && reply.extensions().get::<live_view::Upstream>().is_none() {
            *reply.body_mut() = full(Bytes::new());
        }
        if !connect
            && reply.extensions().get::<CircuitPriorBlock>().is_some()
            && let Some(trace) = &trace
        {
            trace.prior_response(
                reply
                    .headers()
                    .get("x-blocked-by")
                    .and_then(|value| value.to_str().ok()),
            );
        }
        if destination
            .as_ref()
            .is_ok_and(|destination| probe::is_host(&destination.host))
            && let Some(local) = reply.extensions().get::<traffic::LocalResponse>()
            && local.traffic.request_hooks_completed()
        {
            probe::preempted(trace.as_ref(), local.blocked_by.as_ref());
        }
        // Memory observes a completed local response before circuit and later
        // recording hooks. An arbitrary returned status does not prove that
        // this existing local completion marker was reached.
        if let Some(local) = reply.extensions().get::<traffic::LocalResponse>() {
            let current = state.read().map(|runtime| runtime.clone());
            match current {
                Ok(current) => {
                    // Generated local replies have one content-type field.
                    // Source SSE selection also applies to buffered JSON replies.
                    let content_type = reply
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .map_or(&b""[..], |value| value.as_bytes());
                    if !test_context::source_streamed(&current, &local.traffic.host, content_type) {
                        local.traffic.memory_response_size(|| Ok(local.size));
                    }
                }
                Err(_) => {
                    use std::io::Write as _;
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "Memory monitor runtime state unavailable"
                    );
                }
            }
        }
        let completed_probe = reply.extensions_mut().remove::<probe::Completed>();
        let circuit = if let Some(probe) = &completed_probe {
            probe.capture.completed_content();
            crate::circuit_runtime::completed_response(
                &state,
                &identity,
                &request_id,
                probe.source_metadata_reached,
                &destination
                    .as_ref()
                    .expect("completed probe has a destination")
                    .policy_host,
                reply.status().as_u16(),
                trace.as_ref(),
            )
        } else if !connect
            && reply
                .extensions_mut()
                .remove::<CircuitPriorBlock>()
                .is_some()
            && let Ok(destination) = &destination
        {
            crate::circuit_runtime::local_blocked_response(
                &state,
                &destination.policy_host,
                trace.as_ref(),
            )
        } else {
            crate::circuit_runtime::ResponseOutcome::Complete {
                evidence_failed: false,
            }
        };
        let mut local_evidence_failed = connect_link_failed || circuit.evidence_failed();
        if matches!(
            circuit,
            crate::circuit_runtime::ResponseOutcome::Exception { .. }
        ) {
            if let Some(probe) = &completed_probe {
                probe.capture.skip_response();
            } else {
                recording.skip_response();
            }
        } else if let Some(probe) = completed_probe {
            local_evidence_failed |= probe.capture.finish(true);
        } else {
            // Upstream/deferred recording stays with Completion. Local response
            // recording follows the same earlier circuit exception boundary.
            if reply.extensions().get::<traffic::LocalResponse>().is_some()
                && let Some(trace) = trace
                    .as_ref()
                    .and_then(|trace| trace.hook("test-context", "response"))
            {
                trace.evaluated("not_applicable", None);
            }
            recording.local_terminal(false);
        }
        if matches!(
            circuit,
            crate::circuit_runtime::ResponseOutcome::Complete { .. }
        ) && let Some(local) = reply.extensions_mut().remove::<traffic::LocalResponse>()
        {
            local_evidence_failed |= local.finish(reply.status().as_u16());
        }
        if local_evidence_failed {
            reply
                .headers_mut()
                .insert("x-safeyolo-evidence-error", "true".parse().unwrap());
        }
        // Upstream response headers cannot classify a local enforcement action.
        let admin_blocked = decision == "admin_port_access";
        let mut record = json!({
            "host": destination.as_ref().ok().map(|d| &d.policy_host),
            "port": destination.as_ref().ok().map(|d| d.port),
            "status": reply.status().as_u16(),
            "decision": if admin_blocked { "deny" } else { &decision },
            "coverage": if admin_blocked {
                "admin_shield_only"
            } else if destination.as_ref().is_ok_and(|d| is_reserved(&d.host)) {
                "local_endpoint"
            } else if runtime.policy.is_some() && !connect {
                "native_network_guard_circuits_and_test_context"
            } else if runtime.policy.is_some() {
                "native_network_guard_only"
            } else {
                "temporary_network_policy_only"
            },
        });
        if admin_blocked {
            record["blocked_by"] = json!(crate::admin_shield::REJECTION.blocked_by);
            record["block_reason"] = json!(crate::admin_shield::REJECTION.block_reason);
        }
        let mut event = identity.request_event(
            "traffic.request_outcome",
            crate::audit::Kind::Traffic,
            &request_id,
            "Proxy response prepared",
            record,
        );
        event.decision = match if admin_blocked { "deny" } else { &decision } {
            "allow" => Some(crate::audit::Decision::Allow),
            "deny" => Some(crate::audit::Decision::Deny),
            _ => None,
        };
        if let Err(error) = runtime.audit.emit(event) {
            eprintln!("request evidence write failed: {error}");
            reply
                .headers_mut()
                .insert("x-safeyolo-evidence-error", "true".parse().unwrap());
        }
        reply
            .headers_mut()
            .insert("x-safeyolo-request-id", request_id.parse().unwrap());
        if local_live_response && let Some(live) = &live {
            live_view::local_response(live, &reply);
        }
        Ok(reply)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UnixStream},
    };

    #[test]
    fn request_uri_uses_selected_form_and_preserves_http2_authority() {
        let full_uri = "http://logical.test:8088/signed?sig=%252F&tag=a&tag=b";
        let request = Request::builder().uri(full_uri).body(()).unwrap();
        let destination = Destination::from_request(&request, None).unwrap();
        for (http2, h1_request_form, expected) in [
            (
                false,
                H1RequestForm::Origin,
                "/signed?sig=%252F&tag=a&tag=b",
            ),
            (false, H1RequestForm::Absolute, full_uri),
            (true, H1RequestForm::Origin, full_uri),
            (true, H1RequestForm::Absolute, full_uri),
        ] {
            let uri = request_uri(&destination, full_uri, http2, h1_request_form).unwrap();
            assert_eq!(uri, expected, "HTTP/2={http2}, {h1_request_form:?}");
            if http2 {
                assert_eq!(uri.scheme_str(), Some("http"));
                assert_eq!(uri.authority().unwrap().as_str(), "logical.test:8088");
                assert_eq!(
                    uri.path_and_query().unwrap(),
                    "/signed?sig=%252F&tag=a&tag=b"
                );
            }
        }
    }

    async fn held_callsite_timeout<T>(
        operation: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let result = operation;
        tokio::pin!(result);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        result.await
    }

    fn assert_phase_timeout(error: Error, phase: RefreshPhase) {
        assert_eq!(
            error
                .downcast_ref::<RefreshPhaseTimeout>()
                .map(|value| value.phase),
            Some(phase)
        );
    }

    fn race_config(
        directory: &std::path::Path,
        token: &str,
        initial_ignore: &str,
    ) -> crate::Config {
        let policy = directory.join("policy.toml");
        std::fs::write(
            &policy,
            "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"allow\"\n",
        )
        .unwrap();
        std::fs::write(directory.join("operator-token"), token).unwrap();
        serde_json::from_value(json!({
            "listeners": [{
                "agent_id": "alice",
                "socket_path": directory.join("alice.sock")
            }],
            "policy_file": policy,
            "data_dir": directory.join("data"),
            "agent_api_enabled": false,
            "admin_port": 0,
            "admin_api_token_file": directory.join("operator-token"),
            "readiness_file": directory.join("ready.json"),
            "flow_store_enabled": false,
            "audit_log_path": directory.join("audit.jsonl"),
            "ignore_hosts": [initial_ignore]
        }))
        .unwrap()
    }

    fn race_admin_port(config: &crate::Config) -> u16 {
        let ready: Value =
            serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
        ready["admin_port"].as_u64().unwrap().try_into().unwrap()
    }

    async fn race_admin_update(port: u16, token: &str, hosts: &[String]) -> Value {
        let body = serde_json::to_vec(&json!({"hosts": hosts})).unwrap();
        let request = format!(
            "PUT /admin/proxy/ignore-hosts HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("admin response headers");
        assert!(response.starts_with(b"HTTP/1.1 200 "), "{response:?}");
        serde_json::from_slice(&response[split + 4..]).unwrap()
    }

    async fn race_connect(socket: std::path::PathBuf, authority: String) -> UnixStream {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(
                response.len() < 16_384,
                "CONNECT response headers too large"
            );
        }
        assert!(response.starts_with(b"HTTP/1.1 200 "), "{response:?}");
        stream
    }

    fn passthrough_events(path: &std::path::Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| {
                matches!(
                    event["event"].as_str(),
                    Some("traffic.passthrough_start") | Some("traffic.passthrough_end")
                )
            })
            .collect()
    }

    fn install_test_dial_barrier(barrier: Option<Arc<TestDialBarrier>>) {
        *TEST_DIAL_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = barrier;
    }

    // TEST_DIAL_BARRIER is process-global, so the two tests that install it
    // must not overlap when the default test harness runs in parallel.
    static TEST_DIAL_BARRIER_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    async fn dial_barrier_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        TEST_DIAL_BARRIER_TEST_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    struct TestDialBarrierGuard;

    impl Drop for TestDialBarrierGuard {
        fn drop(&mut self) {
            install_test_dial_barrier(None);
        }
    }

    #[tokio::test]
    async fn passthrough_snapshot_controls_real_connect_after_live_update() {
        let _barrier_test_lock = dial_barrier_test_lock().await;
        let _barrier_guard = TestDialBarrierGuard;
        let directory = tempfile::tempdir().unwrap();
        let token = "dial-race-admin";
        let origin_bytes = b"\x16\x03\x03\x00\x0eopaque-initial";
        let (origin, origin_addr) = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map(|listener| {
                let address = listener.local_addr().unwrap();
                (listener, address)
            })
            .unwrap();
        let first_authority = origin_addr.to_string();
        let first_received = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut received = vec![0; origin_bytes.len()];
            stream.read_exact(&mut received).await.unwrap();
            received
        });
        let config = race_config(directory.path(), token, &first_authority);
        let proxy = crate::Proxy::start(config.clone()).await.unwrap();
        let admin_port = race_admin_port(&config);
        let first_barrier = Arc::new(TestDialBarrier {
            target: first_authority.clone(),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        install_test_dial_barrier(Some(first_barrier.clone()));
        let first_client = tokio::spawn(race_connect(
            directory.path().join("alice.sock"),
            first_authority.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(2), first_barrier.reached.notified())
            .await
            .expect("CONNECT reaches production matcher barrier");
        let update = race_admin_update(admin_port, token, &[]).await;
        assert_eq!(update["operator_entry_count"], 0);
        first_barrier.release.notify_one();
        let mut first_client = tokio::time::timeout(Duration::from_secs(2), first_client)
            .await
            .expect("CONNECT completes after live removal")
            .unwrap();
        first_client.write_all(origin_bytes).await.unwrap();
        first_client.shutdown().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), first_received)
                .await
                .expect("origin receives opaque bytes")
                .unwrap(),
            origin_bytes
        );

        let (origin, origin_addr) = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map(|listener| {
                let address = listener.local_addr().unwrap();
                (listener, address)
            })
            .unwrap();
        let second_authority = origin_addr.to_string();
        let second_received = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut received))
                .await
                .expect("inspected origin closes")
                .unwrap();
            received
        });
        let second_barrier = Arc::new(TestDialBarrier {
            target: second_authority.clone(),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        install_test_dial_barrier(Some(second_barrier.clone()));
        let second_client = tokio::spawn(race_connect(
            directory.path().join("alice.sock"),
            second_authority.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(2), second_barrier.reached.notified())
            .await
            .expect("second CONNECT reaches production matcher barrier");
        let update =
            race_admin_update(admin_port, token, std::slice::from_ref(&second_authority)).await;
        assert_eq!(update["operator_entry_count"], 1);
        second_barrier.release.notify_one();
        let mut second_client = tokio::time::timeout(Duration::from_secs(2), second_client)
            .await
            .expect("CONNECT completes after live addition")
            .unwrap();
        // This TLS prefix selects the inspection classifier. Because the
        // pre-dial snapshot was empty, the update cannot turn it into opaque
        // passthrough; with no configured CA the production inspection path
        // closes before forwarding any client bytes to the origin.
        second_client.write_all(origin_bytes).await.unwrap();
        second_client.shutdown().await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), second_received)
            .await
            .expect("inspected origin task completes")
            .unwrap();
        assert!(
            received.is_empty(),
            "live addition must not admit passthrough"
        );
        proxy.shutdown().await;
        let events = passthrough_events(&directory.path().join("audit.jsonl"));
        assert_eq!(
            events
                .iter()
                .map(|event| event["event"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["traffic.passthrough_start", "traffic.passthrough_end"]
        );
    }

    #[tokio::test]
    async fn pending_passthrough_connect_cancellation_records_one_error() {
        let _barrier_test_lock = dial_barrier_test_lock().await;
        let _barrier_guard = TestDialBarrierGuard;
        let directory = tempfile::tempdir().unwrap();
        let closed = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let authority = closed.local_addr().unwrap().to_string();
        drop(closed);
        let config = race_config(directory.path(), "pending-cancel", &authority);
        let proxy = crate::Proxy::start(config.clone()).await.unwrap();
        let barrier = Arc::new(TestDialBarrier {
            target: authority.clone(),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        install_test_dial_barrier(Some(barrier.clone()));

        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        client
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), barrier.reached.notified())
            .await
            .expect("CONNECT reached the production pre-dial boundary");
        assert!(passthrough_events(&directory.path().join("audit.jsonl")).is_empty());

        tokio::time::timeout(Duration::from_secs(12), proxy.shutdown())
            .await
            .expect("proxy shutdown joined the cancelled pre-dial request");
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response)).await;
        let events = std::fs::read_to_string(directory.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["addon"] == "ignored-host-logger")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "unexpected passthrough events: {events:?}");
        assert_eq!(events[0]["event"], "traffic.passthrough_error");
        assert_eq!(events[0]["details"]["error"], "connection cancelled");
        assert_eq!(events[0]["host"], "127.0.0.1");
        assert_eq!(
            events[0]["details"]["port"],
            authority
                .rsplit(':')
                .next()
                .unwrap()
                .parse::<u16>()
                .unwrap()
        );
        assert!(
            events
                .iter()
                .all(|event| event["event"] != "traffic.passthrough_start")
        );
        assert!(
            events
                .iter()
                .all(|event| event["event"] != "traffic.passthrough_end")
        );

        if let Ok(path) = std::env::var("SAFEYOLO_D29_CANCELLATION_EVIDENCE") {
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&json!({
                    "authority": authority,
                    "pre_dial_boundary_reached": true,
                    "physical_connect_started": false,
                    "events": events,
                    "client_response_bytes": response,
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn parent_address_matchers_do_not_select_an_unrelated_logical_destination() {
        for cidr_matcher in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let parent = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let parent_address = parent.local_addr().unwrap();
            let configured_entry = if cidr_matcher {
                "unmatched.invalid".to_owned()
            } else {
                parent_address.to_string()
            };
            let mut config = race_config(directory.path(), "parent-address", &configured_entry);
            config.parent_proxy = Some(format!("http://{parent_address}"));

            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
            let certificate = params.self_signed(&key).unwrap();
            let ca_path = directory.path().join("interception-ca.pem");
            std::fs::write(
                &ca_path,
                format!("{}{}", key.serialize_pem(), certificate.pem()),
            )
            .unwrap();
            config.tls_ca_file = Some(ca_path);

            let authority = "unrelated.invalid:443".to_owned();
            let parent_authority = authority.clone();
            let parent_task = tokio::spawn(async move {
                let (mut socket, _) = parent.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(socket.read_u8().await.unwrap());
                }
                assert!(
                    head.starts_with(format!("CONNECT {parent_authority} HTTP/1.1\r\n").as_bytes())
                );
                socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let mut bytes = Vec::new();
                tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                (head, bytes)
            });

            let proxy = crate::Proxy::start(config.clone()).await.unwrap();
            let runtime = proxy.runtime.read().unwrap().clone();
            if cidr_matcher {
                *runtime.passthrough.write().unwrap() =
                    crate::tunnels::Passthrough::new(&[], "127.0.0.0/8").unwrap();
            }

            let mut client = UnixStream::connect(directory.path().join("alice.sock"))
                .await
                .unwrap();
            client
                .write_all(
                    format!(
                        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(client.read_u8().await.unwrap());
            }
            assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");

            let mut roots = RootCertStore::empty();
            roots.add(certificate.der().clone()).unwrap();
            let client_tls = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let intercepted = tokio::time::timeout(
                Duration::from_secs(2),
                TlsConnector::from(Arc::new(client_tls)).connect(
                    ServerName::try_from("unrelated.invalid".to_owned()).unwrap(),
                    client,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            drop(intercepted);

            let (head, bytes) = tokio::time::timeout(Duration::from_secs(2), parent_task)
                .await
                .unwrap()
                .unwrap();
            assert!(head.starts_with(format!("CONNECT {authority} HTTP/1.1\r\n").as_bytes()));
            assert!(
                bytes.is_empty(),
                "{} parent-address matcher forwarded opaque bytes: {bytes:?}",
                if cidr_matcher { "CIDR" } else { "exact" }
            );
            assert!(
                runtime
                    .audit
                    .wait_for_drain(Duration::from_secs(2))
                    .unwrap()
            );
            let lifecycle = std::fs::read_to_string(directory.path().join("audit.jsonl"))
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|event| event["addon"] == "ignored-host-logger")
                .collect::<Vec<_>>();
            assert!(
                lifecycle.is_empty(),
                "{} parent-address matcher created passthrough lifecycle: {lifecycle:?}",
                if cidr_matcher { "CIDR" } else { "exact" }
            );
            let egress = std::fs::read_to_string(config.audit_log_path.as_ref().unwrap())
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|event| event["event"] == "traffic.egress")
                .collect::<Vec<_>>();
            assert_eq!(egress.len(), 1);
            assert_eq!(egress[0]["host"], "unrelated.invalid");
            assert_eq!(egress[0]["details"]["port"], 443);
            assert_eq!(egress[0]["details"]["route"], "parent");
            proxy.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn held_refresh_callsite_phases_timeout_independently() {
        // These are the named production boundaries, each held at its own
        // callsite. They deliberately do not exercise a generic timeout loop:
        // a regression that removes a wrapper from one operation then fails
        // the corresponding boundary test.
        // Hold the resolver future supplied to the real egress sequence. The
        // connector is never entered while DNS is pending.
        let mut dns_attempts = 0;
        let error = held_callsite_timeout(resolve_and_connect_egress(
            Some(Duration::from_secs(10)),
            std::future::pending::<Result<Vec<std::net::SocketAddr>, Error>>,
            |_address| async { Ok::<(), Error>(()) },
            |_address| true,
            || {
                dns_attempts += 1;
                Ok(())
            },
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::Dns);
        assert_eq!(dns_attempts, 0);

        // Resolve succeeds through the seam, then the real connector future
        // is held at the TCP call site and cannot be mistaken for DNS.
        let tcp_address = "127.0.0.1:9".parse().unwrap();
        let mut tcp_attempts = 0;
        let error = held_callsite_timeout(resolve_and_connect_egress(
            Some(Duration::from_secs(10)),
            || async { Ok::<_, Error>(vec![tcp_address]) },
            |_address| std::future::pending::<Result<(), Error>>(),
            |_address| true,
            || {
                tcp_attempts += 1;
                Ok(())
            },
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::Tcp);
        assert_eq!(tcp_attempts, 1);

        let error = held_callsite_timeout(refresh_parent_tls_phase(
            Some(Duration::from_secs(10)),
            std::future::pending::<Result<(), Error>>(),
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::ParentTls);

        let error = held_callsite_timeout(refresh_connect_phase(
            Some(Duration::from_secs(10)),
            std::future::pending::<Result<(), Error>>(),
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::Connect);

        let error = held_callsite_timeout(refresh_origin_tls_phase(
            Some(Duration::from_secs(10)),
            std::future::pending::<Result<(), Error>>(),
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::OriginTls);

        // Hyper's handshake constructs a sender/connection pair without
        // touching the wire. Holding the real sender readiness future while
        // retaining (but not driving) its connection exercises the actual
        // HTTP state-machine boundary, rather than a response-head wait.
        let (client, _peer) = tokio::io::duplex(64);
        let (mut sender, _connection) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Full<Bytes>>(TokioIo::new(client))
            .await
            .unwrap();
        let error = held_callsite_timeout(refresh_http_handshake_phase(
            Some(Duration::from_secs(10)),
            async { sender.ready().await.map_err(Into::into) },
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::HttpHandshake);

        let error = held_callsite_timeout(refresh_http_send_phase(
            Some(Duration::from_secs(10)),
            std::future::pending::<Result<(), Error>>(),
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::HttpSend);

        let error = held_callsite_timeout(refresh_http_body_phase(
            Some(Duration::from_secs(10)),
            std::future::pending::<Result<(), Error>>(),
        ))
        .await
        .unwrap_err();
        assert_phase_timeout(error, RefreshPhase::HttpBody);
    }

    #[test]
    fn inner_authority_reuses_connect_policy_name_only_for_ascii_case() {
        let connect = Request::builder()
            .method(Method::CONNECT)
            .uri("ss.invalid:443")
            .body(())
            .unwrap();
        let mut tunnel = Destination::from_request(&connect, None).unwrap();
        tunnel.scheme = "https".into();

        let upper = Request::builder()
            .uri("/signed")
            .header(header::HOST, "SS.INVALID:443")
            .body(())
            .unwrap();
        assert_eq!(
            Destination::from_request(&upper, Some(&tunnel))
                .unwrap()
                .policy_host,
            "ss.invalid"
        );

        // IDNA2003 sends this spelling to the same socket, but the source
        // hostname still needs its own inspection and policy decision.
        let unicode = Request::builder()
            .uri("/signed")
            .header(header::HOST, "ß.invalid:443")
            .body(())
            .unwrap();
        let inner = Destination::from_request(&unicode, Some(&tunnel)).unwrap();
        assert_eq!(inner.host, "ss.invalid");
        assert_eq!(inner.policy_host, "ß.invalid");
    }

    #[test]
    fn request_hostnames_match_pinned_sensor_witnesses() {
        let witnesses: serde_json::Value = serde_json::from_str(include_str!(
            "../data/host_names/source-host-witnesses.json"
        ))
        .unwrap();
        let rows = witnesses["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 155);
        for row in rows {
            let hex = row["input_authority_hex"].as_str().unwrap();
            let bytes: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
                .collect();
            let output = (|| -> Result<Destination, Error> {
                let form = row["form"].as_str().unwrap();
                let mut builder = Request::builder();
                if form.starts_with("h2_") {
                    builder = builder.version(hyper::Version::HTTP_2);
                }
                builder = match form {
                    "absolute" | "h2_authority" => {
                        builder.uri(format!("http://{}/p", std::str::from_utf8(&bytes)?))
                    }
                    "connect" => builder
                        .method(Method::CONNECT)
                        .uri(std::str::from_utf8(&bytes)?),
                    "origin" | "h2_host_fallback" => builder
                        .uri("/p")
                        .header(header::HOST, header::HeaderValue::from_bytes(&bytes)?),
                    _ => panic!("unknown witness form"),
                };
                Destination::from_request(&builder.body(())?, None)
            })();
            assert_eq!(
                output.is_ok(),
                row["source_validation_passed"].as_bool().unwrap(),
                "{row}"
            );
            if let Ok(destination) = output {
                assert_eq!(
                    destination.policy_host,
                    row["policy_host"].as_str().unwrap(),
                    "{row}"
                );
                assert_eq!(
                    destination.port,
                    row["port"].as_u64().unwrap() as u16,
                    "{row}"
                );
                assert_eq!(destination.authority.as_bytes(), bytes, "{row}");
                assert!(destination.host.is_ascii());
                assert!(destination.uri_authority.is_ascii());
            }
        }
    }
}
