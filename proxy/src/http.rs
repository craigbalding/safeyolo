use std::{
    convert::Infallible,
    future::Future,
    io::BufReader,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
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
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::request_trace::RequestTrace;
use crate::tunnels::{self, BoxStream, Protocol};
use crate::{ConnectionIdentity, Error, Runtime, RuntimeState, UpgradeTasks, is_reserved};

#[cfg(test)]
mod agent_audit_tests;
#[cfg(test)]
mod circuit_audit_tests;
mod circuit_completion;
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
mod test_context;
#[cfg(test)]
mod trace_tests;
mod traffic;
mod traffic_url;

pub(crate) type Body = BoxBody<Bytes, Error>;

/// The request or body owner requests cancellation when dropped. The accepted
/// connection retains the actual driver until its task is joined.
struct HttpTask {
    task: tokio::task::AbortHandle,
    completion: Option<Arc<circuit_completion::Completion>>,
}

impl HttpTask {
    fn unobserved(task: tokio::task::AbortHandle) -> Self {
        Self {
            task,
            completion: None,
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

fn prior_block(mut response: Response<Body>) -> Response<Body> {
    response.extensions_mut().insert(CircuitPriorBlock);
    response
}

struct UpstreamBody {
    body: Incoming,
    _connection: HttpTask,
    live: Option<Arc<crate::traffic_view::Exchange>>,
}

/// Apply validated request effects before releasing its terminal bytes to the
/// origin. The parser observer supplies success; body frames only prompt a check.
struct ForwardedRequestBody {
    body: Body,
    completion: Arc<circuit_completion::Completion>,
    live: Option<Arc<crate::traffic_view::Exchange>>,
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
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl HttpBody for UpstreamBody {
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
        frame.map(|frame| frame.map(|result| result.map_err(|error| -> Error { Box::new(error) })))
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
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

pub(crate) fn response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(json!({"error": message}).to_string()))
        .unwrap()
}

#[derive(Serialize)]
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
}

/// CONNECT owns one admitted endpoint and its first destination connection.
/// Inner requests may consume that connection only after their own checks pass.
pub(crate) struct Tunnel {
    destination: Destination,
    upstream: tokio::sync::Mutex<Option<Connected>>,
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
        let policy_host = policy_hostname(
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

fn validate_hostname(host: &str) -> Result<(), Error> {
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
}

struct Outbound {
    stream: BoxStream,
    http2: bool,
}

struct Connected {
    stream: BoxStream,
    peer: Option<std::net::Ipv4Addr>,
    observation: crate::traffic_view::UpstreamConnectionObservation,
}

pub(crate) fn parent_tls(config: &crate::Config) -> Result<Arc<ClientConfig>, Error> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        roots.add(cert)?;
    }
    for error in native.errors {
        eprintln!("native TLS trust store: {error}");
    }
    if let Some(path) = &config.upstream_ca_file {
        for cert in rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(path)?)) {
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

/// The only outbound DNS/socket path. Both routing modes enforce local containment.
async fn open_egress_for_flow(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    tunnel: bool,
    ignored: Option<crate::ignored_host_logger::SelectedDestination<'_>>,
    live: Option<&crate::traffic_view::Exchange>,
) -> Result<Connected, Error> {
    let destination = allowed.destination;
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
    let (host, port, tls, route_name) = match &runtime.parent {
        Some(parent) => (parent.host.as_str(), parent.port, parent.tls, "parent"),
        None => (destination.host.as_str(), destination.port, false, "direct"),
    };
    if is_reserved(host) {
        return Err("reserved destination cannot be an egress route".into());
    }
    if runtime
        .admin_shield
        .blocks_host(&destination.host, destination.port)
        || runtime.admin_shield.blocks_host(host, port)
    {
        return Err(AdminPortAccess.into());
    }
    let direct = runtime.parent.is_none();
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
    if let Some(live) = live {
        live.upstream_connection(observation.clone());
    }
    let record_egress = || {
        runtime.record(json!({
            "event": "proxy.egress", "agent": allowed.identity.agent_id,
            "connection_id": allowed.identity.connection_id, "request_id": allowed.request_id,
            "host": destination.host, "port": destination.port, "route": route_name,
        }))
    };
    let mut connection_audit = ignored.map(|selected| {
        ignored_host::ConnectionAudit::new(runtime.audit.clone(), allowed.identity, selected)
    });
    let connecting: Result<TcpStream, Error> = async {
        let socket = if runtime.admin_shield.protects_port(port)
            || runtime
                .admin_address
                .is_some_and(|bound| bound.port() == port)
        {
            // Resolve this immediate route once before selecting a socket that
            // could reach the operator listener. Parent-origin DNS remains remote.
            let addresses = tokio::net::lookup_host((host, port)).await?;
            let mut socket = None;
            let mut last_error = None;
            let mut protected = false;
            let mut recorded = false;
            for address in addresses {
                if runtime.admin_shield.blocks_address(address)
                    || runtime
                        .admin_address
                        .is_some_and(|bound| crate::admin_shield::targets_listener(address, bound))
                {
                    protected = true;
                    continue;
                }
                if !recorded {
                    record_egress()?;
                    recorded = true;
                }
                match TcpStream::connect(address).await {
                    Ok(connected) => {
                        socket = Some(connected);
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            match socket {
                Some(socket) => socket,
                None => {
                    if protected {
                        return Err(AdminPortAccess.into());
                    }
                    if let Some(error) = last_error {
                        return Err(error.into());
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "egress route resolved no socket addresses",
                    )
                    .into());
                }
            }
        } else {
            record_egress()?;
            TcpStream::connect((host, port)).await?
        };
        Ok(socket)
    }
    .await;
    let socket = match connecting {
        Ok(socket) => socket,
        Err(error) => {
            if let Some(observation) = &mut connection_audit {
                observation.failed(&error.to_string());
            }
            return Err(error);
        }
    };
    if let Some(observation) = &mut connection_audit {
        observation.connected();
    }
    let peer = if direct {
        let setup = crate::circuit_runtime::now();
        observation.tcp_setup = Some(setup);
        if let Some(live) = live {
            live.upstream_connection(observation.clone());
        }
        let address = socket.peer_addr()?;
        observation.peer = Some(address);
        match address.ip() {
            std::net::IpAddr::V4(address) => Some(address),
            _ => None,
        }
    } else {
        None
    };
    let socket: BoxStream = match connection_audit {
        Some(observation) => ignored_host::observe(socket, observation),
        None => Box::new(socket),
    };
    if let Some(live) = live {
        live.upstream_connection(observation.clone());
    }
    let mut stream: BoxStream = if tls {
        let name = ServerName::try_from(host.to_owned())?;
        let tls = runtime
            .tls
            .clone()
            .ok_or("HTTPS parent TLS was not configured")?;
        Box::new(TlsConnector::from(tls).connect(name, socket).await?)
    } else {
        socket
    };
    if tunnel && runtime.parent.is_some() {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let task = HttpTask::unobserved(allowed.tasks.spawn(async move {
            let _ = connection.with_upgrades().await;
        }));
        let target = if destination.host.contains(':') {
            format!("[{}]:{}", destination.host, destination.port)
        } else {
            format!("{}:{}", destination.host, destination.port)
        };
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(&target)
            .header(header::HOST, &target)
            .header(header::VIA, format!("1.1 {}", runtime.via_token))
            .body(full(Bytes::new()))?;
        let response = sender.send_request(request).await?;
        if !response.status().is_success() {
            return Err("parent proxy refused CONNECT".into());
        }
        let upgraded = hyper::upgrade::on(response).await?;
        drop(task);
        stream = Box::new(TokioIo::new(upgraded));
    }
    Ok(Connected {
        stream,
        peer,
        observation,
    })
}

async fn open_outbound(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    offer_http2: bool,
    tunnel: Option<&Tunnel>,
    live: Option<&crate::traffic_view::Exchange>,
) -> Result<Outbound, Error> {
    let destination = allowed.destination;
    let existing = if let Some(tunnel) = tunnel {
        tunnel.upstream.lock().await.take()
    } else {
        None
    };
    let connection = match existing {
        Some(connection) => connection,
        None => {
            open_egress_for_flow(
                runtime,
                allowed,
                tunnel.is_some() || destination.scheme == "https",
                None,
                live,
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
        let config = runtime
            .tls
            .as_ref()
            .ok_or("upstream TLS trust is not configured")?;
        let mut config = (**config).clone();
        if offer_http2 {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        let name = ServerName::try_from(destination.host.clone())?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await?;
        http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        stream = Box::new(tls);
        if let Some(live) = live {
            live.upstream_tls(crate::circuit_runtime::now());
        }
    }
    Ok(Outbound { stream, http2 })
}

async fn decide(
    runtime: &Runtime,
    identity: &ConnectionIdentity,
    request: &PolicyRequest<'_>,
    trace: Option<&Arc<RequestTrace>>,
    tasks: &UpgradeTasks,
) -> Result<PolicyDecision, Error> {
    if let Some(policy) = &runtime.policy {
        use crate::network_guard::{Identity, Options, OutcomeKind, Pdp, Request};

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
        let result = runtime.network_guard.enforce_with_audit_and_trace(
            Pdp::Ready(policy),
            Request {
                identity: Identity::Resolved(request.agent_id),
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
                block: runtime.config.network_guard_block,
                homoglyph: runtime.config.network_guard_homoglyph,
            },
            crate::policy::current_time_ms(),
            |intent| {
                runtime
                    .audit
                    .emit(intent.event(identity.audit_attribution()))
                    .map(|_| ())
                    .map_err(|error| crate::network_guard::GuardError(error.to_string()))
            },
            |intent| network_trace::observe(trace.as_ref(), intent),
        );
        if result.is_err()
            && let Some(trace) = &trace
        {
            // GuardError erases native producer categories; its diagnostic
            // text cannot establish a corresponding source exception class.
            trace.error("GuardError");
        }
        let outcome = result?;
        // Development guard evidence excludes the URL query and application
        // bytes. Canonical security audit has its own process-owned writer.
        runtime.record(json!({
            "event": "proxy.network_guard", "agent": request.agent_id,
            "connection_id": request.connection_id, "request_id": request.request_id,
            "host": request.host, "port": request.port,
            "outcome": outcome.kind, "trace": outcome.trace,
            "trace_requested": request.trace_requested,
            "audit": outcome.audit, "metadata": outcome.metadata, "pdp": outcome.pdp,
        }))?;
        let allow = outcome.kind != OutcomeKind::Blocked;
        let (status, headers, body) = match outcome.response {
            Some(response) => {
                let body = String::from_utf8(response.body_bytes())?;
                (Some(response.status), response.headers, Some(body))
            }
            None => (None, Vec::new(), None),
        };
        return Ok(PolicyDecision {
            allow,
            decision: if allow { "allow" } else { "deny" }.into(),
            status,
            headers,
            body,
            blocked_by: outcome.metadata.get("blocked_by").cloned(),
            block_reason: outcome.metadata.get("block_reason").cloned(),
        });
    }
    // The temporary adapter has one policy/state owner. Queue here instead of
    // overflowing its Unix accept queue or replaying a charged decision. The
    // lock is shared across reload snapshots and released on cancellation.
    let _policy_guard = runtime.temporary_policy_lock.lock().await;
    let socket = UnixStream::connect(
        runtime
            .config
            .temporary_policy_socket
            .as_deref()
            .ok_or("policy is not configured")?,
    )
    .await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    let _task = HttpTask::unobserved(tasks.spawn(async move {
        let _ = connection.await;
    }));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/decision")
        .header(header::HOST, "temporary-policy")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONNECTION, "close")
        .body(full(serde_json::to_vec(request)?))?;
    async {
        let response = sender.send_request(request).await?;
        if response.status() != StatusCode::OK {
            return Err("temporary policy adapter failed".into());
        }
        // A decision is small control data; never buffer an application body here.
        let bytes = Limited::new(response.into_body(), 1024 * 1024)
            .collect()
            .await?
            .to_bytes();
        Ok(serde_json::from_slice::<PolicyDecision>(&bytes)?)
    }
    .await
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
    let audit = outcome.audit.as_ref().map(|audit| {
        let mut event = json!({
            "event": audit.event, "kind": "security",
            "severity": audit.severity, "addon": audit.addon,
            "summary": audit.summary, "agent": audit.agent,
            "request_id": audit.request_id, "host": audit.host,
            "details": audit.details,
        });
        if matches!(
            audit.kind,
            crate::agent_api::AuditKind::AuthenticationFailed
                | crate::agent_api::AuditKind::HandlerUnavailable
        ) {
            event["decision"] = json!("deny");
        }
        event
    });
    // Development evidence remains separate from the canonical writer. On a
    // synchronous submission failure, retain the attempted intent/status before
    // recording the changed terminal outcome; neither row is a second emission.
    runtime.record(json!({
        "event": "proxy.agent_api", "agent": identity.agent_id,
        "connection_id": identity.connection_id, "request_id": request_id,
        "status": outcome.response.status, "blocked_by": outcome.blocked_by,
        "handler_owned": outcome.handler_owned, "audit": audit,
        "failure": outcome.failure.map(|failure| format!("{failure:?}")),
        "policy_evaluations": outcome.policy_evaluations,
    }))
}

async fn local_agent_api(
    runtime: &Runtime,
    traffic: Arc<traffic::Traffic>,
    identity: &ConnectionIdentity,
    request_id: &str,
    request: &mut Request<Incoming>,
    destination: &Destination,
    trace: Option<&Arc<RequestTrace>>,
) -> Result<Response<Body>, Error> {
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
        identity: crate::network_guard::Identity::Resolved(&identity.agent_id),
        client_ip: identity.source_id.as_deref(),
        request_id,
    };
    let mut outcome = if runtime.config.agent_api_enabled {
        let token_path = std::env::var_os("SAFEYOLO_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/safeyolo/data".into())
            .join("agent_token");
        let policy = runtime
            .policy
            .as_ref()
            .map_or(PolicyState::Unavailable, PolicyState::Ready);
        let mut random = rand::random::<f64>;
        agent_api::respond_with_body(
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
                discovery: Some(&runtime.agent_discovery),
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
            },
            agent_api::RequestBody {
                body: request.body_mut(),
                content_encoding: &content_encoding,
                content_length,
                observation: Some(&mut local_observation),
            },
        )
        .await?
    } else {
        agent_api::unavailable(api_request, Failure::HandlerUnavailable)
    };
    // AgentAPI runs before the later request/response traffic hooks. Only a
    // synchronous producer error changes its outcome; queue drops and async
    // sink failures retain the already-established source response semantics.
    let mut evidence_failed = false;
    if let Some(audit) = &outcome.audit
        && let Err(error) = runtime.audit.emit(audit.to_event())
    {
        evidence_failed = true;
        let authentication_failed = audit.kind == agent_api::AuditKind::AuthenticationFailed;
        if audit.kind != agent_api::AuditKind::HandlerUnavailable {
            evidence_failed |= record_agent_api(runtime, identity, request_id, &outcome).is_err();
        }
        outcome = outcome.audit_submission_failed(api_request, error.kind());
        if authentication_failed && let Some(guard) = &outcome.audit {
            // A single independent containment attempt. The guard catches a
            // second failure and its local response must remain intact.
            evidence_failed |= runtime.audit.emit(guard.to_event()).is_err();
        }
    }
    evidence_failed |= record_agent_api(runtime, identity, request_id, &outcome).is_err()
        | crate::circuit_runtime::record_transitions(runtime, &outcome.circuit_events, None);
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
                Some(&identity.agent_id),
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
            let failed = crate::circuit_runtime::record_transitions(&runtime, error.events(), None);
            return (None, failed, true);
        }
    };
    crate::circuit_runtime::trace_request_decision(trace.as_ref(), &outcome.value);
    let mut failed = crate::circuit_runtime::record_transitions(&runtime, &outcome.events, None);
    let RequestDecision::Blocked {
        status,
        retry_after_seconds,
    } = outcome.value
    else {
        return (None, failed, false);
    };
    let reply = (|| -> Result<Response<Body>, Error> {
        let state = serde_json::to_value(status.state)?
            .as_str()
            .unwrap()
            .to_owned();
        let count = crate::circuit_runtime::count_text(&status.failure_count)?;
        let mut details = indexmap::IndexMap::from([
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
        security.agent = Some(identity.agent_id.clone());
        security.request_id = Some(request_id.to_owned());
        security.decision = Some(crate::audit::Decision::Deny);
        security.attribution = Some(identity.audit_attribution());
        security.details = CircuitValue::Object(details.clone());
        runtime.audit.emit(security)?;
        let audit = CircuitValue::Object(indexmap::IndexMap::from([
            ("event".into(), json!("proxy.circuit").into()),
            (
                "audit_intent".into(),
                json!("security.circuit_breaker").into(),
            ),
            ("kind".into(), json!("security").into()),
            ("severity".into(), json!("high").into()),
            ("addon".into(), json!("circuit-breaker").into()),
            ("decision".into(), json!("deny").into()),
            ("host".into(), json!(host).into()),
            ("agent".into(), json!(identity.agent_id).into()),
            ("request_id".into(), json!(request_id).into()),
            (
                "summary".into(),
                json!(format!(
                    "Circuit breaker open for {} ({count} failures)",
                    crate::network_guard::sanitize(host),
                ))
                .into(),
            ),
            (
                "details".into(),
                CircuitValue::Object(std::mem::take(&mut details)),
            ),
        ]));
        failed |= runtime
            .record_bytes(audit.render_audit_json()?.into_bytes())
            .is_err();
        let body = crate::python_json::encode(&json!({
            "error": format!("Service temporarily unavailable: {host}"),
            "domain": host,
            "circuit_state": state,
            "retry_after_seconds": retry_after_seconds,
            "message": format!("Circuit breaker open for {host}. Service has failed {count} times. Will retry in {retry_after_seconds} seconds."),
        }));
        let mut reply = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, body.len())
            .header("x-blocked-by", "circuit-breaker")
            .header("x-safeyolo-request-id", request_id)
            .header("x-circuit-state", state)
            .header(header::RETRY_AFTER, retry_after_seconds.to_string())
            .body(full(body))?;
        if failed {
            reply
                .headers_mut()
                .insert("x-safeyolo-evidence-error", "true".parse()?);
        }
        Ok(reply)
    })();
    match reply {
        Ok(reply) => {
            crate::circuit_runtime::trace_request_blocked(trace.as_ref());
            (Some(reply), failed, false)
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
            (None, failed, true)
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

// Keep the immutable request snapshot separate from the reloadable state used
// by later requests inside CONNECT, and keep routing separate from identity.
#[allow(clippy::too_many_arguments)]
async fn forward(
    runtime: Arc<Runtime>,
    state: RuntimeState,
    upgrades: UpgradeTasks,
    allow_upgrades: bool,
    identity: &ConnectionIdentity,
    request_id: &str,
    mut request: Request<Incoming>,
    recording: Arc<flow_recording::Recording>,
    live: Option<Arc<crate::traffic_view::Exchange>>,
    destination: &Destination,
    tunnel: Option<&Tunnel>,
    trace: Option<Arc<RequestTrace>>,
) -> Result<(Response<Body>, String), Error> {
    let pipeline_probe = probe::is_host(&destination.host);
    // CONNECT has its own source hook before destination policy and no
    // ordinary HTTP request body lifecycle. Observe each admission once.
    if request.method() == Method::CONNECT {
        runtime.observe_agent(&identity.agent_id, identity.source_id.as_deref());
    }
    let traffic = (request.method() != Method::CONNECT)
        .then(|| traffic::Traffic::new(state.clone(), identity, request_id, &request, destination));
    if runtime
        .admin_shield
        .blocks_host(&destination.host, destination.port)
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
                traffic
                    .as_ref()
                    .expect("ordinary local HTTP traffic")
                    .clone(),
                identity,
                request_id,
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
    let mut ordered_headers = crate::request_headers::RequestHeaders::take(&mut request)?;
    let hygiene = ordered_headers.apply_hygiene(request.headers_mut());
    if let Some(live) = &live {
        live.request_headers(live_view::pairs(ordered_headers.recording_pairs()));
    }
    if let Some(trace) = &trace {
        trace.enable(hygiene.trace_requested);
    }
    let decision = decide(
        &runtime,
        identity,
        &PolicyRequest {
            agent_id: &identity.agent_id,
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
        },
        trace.as_ref(),
        &upgrades,
    )
    .await?;
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
        // Admission precedes DNS/dial. Eager connection supports protocols whose
        // server greets the client before receiving any client bytes.
        // Source logging selects a destination before DNS. Keep the existing
        // later transport matcher, including its resolved-peer behavior.
        let ignored = (runtime.parent.is_none()
            && runtime
                .passthrough
                .matches(&destination.host, destination.port, None))
        .then_some(crate::ignored_host_logger::SelectedDestination {
            host: &destination.host,
            port: destination.port,
        });
        let connected = open_egress_for_flow(
            &runtime,
            &AllowedRequest {
                tasks: &upgrades,
                destination,
                identity,
                request_id,
            },
            true,
            ignored,
            live.as_deref(),
        )
        .await?;
        let Connected {
            stream,
            peer,
            observation,
        } = connected;
        let passthrough = runtime
            .passthrough
            .matches(&destination.host, destination.port, peer);
        let upgrade = hyper::upgrade::on(&mut request);
        let identity = identity.clone();
        let destination = destination.clone();
        let request_id = request_id.to_owned();
        if !allow_upgrades {
            return Err("nested CONNECT is unsupported".into());
        }
        let mut stop = upgrades.stop.clone();
        let descendants = upgrades.clone();
        upgrades.spawn_upgrade(async move {
            let result: Result<(), Error> = async {
                if *stop.borrow() {
                    return Ok(());
                }
                let client: BoxStream = tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    result = upgrade => Box::new(TokioIo::new(result?)),
                };
                let (protocol, client, server) = if passthrough {
                    (Protocol::Opaque, client, stream)
                } else {
                    tunnels::classify(client, stream, &mut stop).await?
                };
                if protocol == Protocol::Opaque {
                    let started = std::time::Instant::now();
                    let result = tunnels::relay(client, server, stop).await;
                    runtime.record(json!({
                        "event": "proxy.tunnel", "agent": identity.agent_id,
                        "connection_id": identity.connection_id, "request_id": request_id,
                        "host": destination.host, "port": destination.port,
                        "coverage": if passthrough { "configured_passthrough" } else { "opaque" },
                        "uploaded_bytes": result.uploaded, "downloaded_bytes": result.downloaded,
                        "duration_ms": started.elapsed().as_millis(), "outcome": result.outcome,
                    }))?;
                    return Ok(());
                }
                let (client, http2, scheme): (BoxStream, bool, &str) = if protocol == Protocol::Tls
                {
                    let config = runtime
                        .certificate_authority
                        .as_ref()
                        .ok_or("TLS CA is not configured")?
                        .server_config(&destination.host, time::OffsetDateTime::now_utc())?;
                    let tls = tokio::select! {
                        _ = stop.changed() => return Ok(()),
                        result = TlsAcceptor::from(config).accept(client) => result?,
                    };
                    let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    (Box::new(tls), http2, "https")
                } else {
                    (client, false, "http")
                };
                let mut destination = destination;
                destination.scheme = scheme.into();
                let tunnel = Arc::new(Tunnel {
                    destination,
                    upstream: tokio::sync::Mutex::new(Some(Connected {
                        stream: server,
                        peer,
                        observation,
                    })),
                });
                serve_tunnel_http(state, identity, tunnel, client, http2, stop, descendants).await
            }
            .await;
            if let Err(error) = result {
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
    // Credential enforcement is deliberately after network and circuit
    // admission, but before test-context observation, body buffering, or any
    // outbound connection. The ordered parser view remains alive here so the
    // guard sees first spelling and grouped duplicate values exactly once.
    if let Some(policy) = runtime.policy.as_ref() {
        let guard = runtime
            .credential_guard
            .as_ref()
            .ok_or("native credential guard is unavailable")?;
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
        let outcome = match guard.enforce_ordered(
            crate::credential_guard::Pdp::Ready(policy),
            crate::network_guard::Identity::Resolved(&identity.agent_id),
            &destination.policy_host,
            destination.port,
            request.method().as_str(),
            &destination.path,
            &destination.scheme,
            Some(request_id),
            &identity.connection_id,
            false,
            ordered_headers.iter(),
            crate::credential_guard::Options {
                block: runtime.config.credential_guard_block(),
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
        publish_credential_trace(guard_trace.as_ref(), &outcome.trace);
        // Canonical audit is emitted exactly once per guard intent. The
        // attribution is trusted UDS identity; no credential value enters it.
        for intent in &outcome.audit {
            runtime
                .audit
                .emit(intent.event(identity.audit_attribution()))?;
        }
        runtime.record(json!({
            "event": "proxy.credential_guard",
            "agent": identity.agent_id,
            "connection_id": identity.connection_id,
            "request_id": request_id,
            "host": destination.policy_host,
            "port": destination.port,
            "outcome": outcome.kind,
            "trace": outcome.trace,
            "audit": outcome.audit,
            "metadata": outcome.metadata,
            "evaluations": outcome.evaluations,
            "body_scope": "headers_only",
            "query_scope": "policy_context_only",
        }))?;
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
    let traffic = traffic.expect("CONNECT returned before ordinary HTTP hooks");
    traffic.request_headers(&request, destination);
    context.attach_traffic(traffic);
    context.attach_live(live.clone());
    if let Some(provenance) = context.response_provenance() {
        recording.request(
            &request,
            destination,
            ordered_headers.recording_pairs(),
            hygiene.websocket,
        );
        provenance.attach_recording(recording.clone());
    }
    // Retain only the recording projection after source hygiene/context removal.
    // Credential inspection is still inactive.
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
    strip_hop_headers(request.headers_mut());
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
    // Every ordinary HTTP exchange shares source buffering and the independent
    // request parser barrier; quiet rules decide whether decoding is needed.
    let (body, context) = context.buffer(body, content_length).await?;
    let mut request = Request::from_parts(parts, body);
    let outbound = open_outbound(
        &runtime,
        &AllowedRequest {
            tasks: &upgrades,
            destination,
            identity,
            request_id,
        },
        request.version() == hyper::Version::HTTP_2,
        tunnel,
        live.as_deref(),
    )
    .await?;
    *request.uri_mut() = if outbound.http2
        || (runtime.parent.is_some() && destination.scheme == "http" && tunnel.is_none())
    {
        format!(
            "{}://{}{}",
            destination.scheme, destination.uri_authority, destination.path
        )
        .parse::<Uri>()?
    } else {
        destination.path.parse::<Uri>()?
    };
    request.extensions_mut().insert(recording.clone());
    let completion = circuit_completion::Completion::register(
        &mut request,
        outbound.http2,
        state.clone(),
        identity.clone(),
        request_id.to_owned(),
        destination.policy_host.clone(),
        Some(context),
    );
    let mut request = request.map(|body| ForwardedRequestBody {
        body,
        completion: completion.clone(),
        live: live.clone(),
    });
    let (mut upstream, connection) = if outbound.http2 {
        // :authority carries the admitted destination. Avoid retaining a second
        // authority representation while translating a proxied request.
        request.headers_mut().remove(header::HOST);
        *request.version_mut() = hyper::Version::HTTP_2;
        let (mut sender, connection) = hyper::client::conn::http2::handshake(
            Executor(upgrades.clone()),
            TokioIo::new(outbound.stream),
        )
        .await?;
        let driver = completion.clone().drive(connection);
        let connection = HttpTask {
            task: upgrades.spawn(async move {
                if let Err(error) = driver.await {
                    eprintln!("upstream HTTP/2 connection: {error}");
                }
            }),
            completion: Some(completion.clone()),
        };
        (sender.send_request(request).await?, connection)
    } else {
        *request.version_mut() = hyper::Version::HTTP_11;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(outbound.stream))
            .await?;
        let driver = completion.clone().drive(connection.with_upgrades());
        let connection = HttpTask {
            task: upgrades.spawn(async move {
                if let Err(error) = driver.await {
                    eprintln!("upstream HTTP connection: {error}");
                }
            }),
            completion: Some(completion.clone()),
        };
        (sender.send_request(request).await?, connection)
    };
    completion.headers_received();
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
                if *stop.borrow() { return Ok(()); }
                let (client, server) = tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    result = async { tokio::try_join!(client_upgrade, server_upgrade) } => result?,
                };
                let memory = crate::memory_runtime::WebSocket::new(
                    &runtime, &session.identity.connection_id, &memory_host,
                );
                runtime.record(json!({
                    "event": "proxy.websocket.start", "agent": session.identity.agent_id,
                    "connection_id": session.identity.connection_id, "request_id": session.request_id,
                    "host": session.host, "port": session.port,
                    "subprotocol": negotiated.subprotocol,
                    "compressed_client": negotiated.client.is_some(), "compressed_server": negotiated.server.is_some(),
                }))?;
                crate::websocket_relay::relay(Box::new(TokioIo::new(client)), Box::new(TokioIo::new(server)), negotiated, session, stop, memory, descendants).await
            }.await;
            if result.is_err() { eprintln!("WebSocket connection ended with an error"); }
        });
        return Ok((
            Response::from_parts(parts, full(Bytes::new())),
            decision.decision,
        ));
    }
    let (mut parts, body) = upstream.into_parts();
    parts.extensions.insert(live_view::Upstream);
    strip_hop_headers(&mut parts.headers);
    Ok((
        Response::from_parts(
            parts,
            UpstreamBody {
                body,
                _connection: connection,
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
    if http2 {
        let connection = hyper::server::conn::http2::Builder::new(Executor(upgrades.clone()))
            .serve_connection(TokioIo::new(client), service);
        tokio::pin!(connection);
        if *stop.borrow() {
            connection.as_mut().graceful_shutdown();
        }
        tokio::select! {
            result = &mut connection => result?,
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.await?;
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
            result = &mut connection => result?,
            _ = stop.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.await?;
            }
        }
    }
    // The accepted connection is the sole drainer, including nested upgrades.
    Ok(())
}

pub(crate) fn serve_request(
    state: RuntimeState,
    identity: ConnectionIdentity,
    request: Request<Incoming>,
    tunnel: Option<Arc<Tunnel>>,
    upgrades: UpgradeTasks,
    allow_upgrades: bool,
) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>> {
    Box::pin(async move {
        let runtime = state.read().expect("runtime read lock").clone();
        let request_id = format!("req-{}", uuid::Uuid::new_v4().simple());
        let connect = request.method() == Method::CONNECT;
        let recording = flow_recording::Recording::new(
            runtime.flow_recorder.clone(),
            identity.clone(),
            request_id.clone(),
            !connect,
        );
        let _pending_recording = recording.pending();
        let destination =
            Destination::from_request(&request, tunnel.as_ref().map(|tunnel| &tunnel.destination));
        let live = destination.as_ref().ok().and_then(|destination| {
            live_view::begin(&runtime, &identity, &request_id, &request, destination)
        });
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
            probe.capture.memory_response();
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
        let mut local_evidence_failed = circuit.evidence_failed();
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
            "event": "proxy.request", "agent": identity.agent_id,
            "connection_id": identity.connection_id, "request_id": request_id,
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
        if let Err(error) = runtime.record(record) {
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
