use std::{
    convert::Infallible,
    future::Future,
    io::BufReader,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::{Body as HttpBody, Frame, Incoming, SizeHint},
    header,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::tunnels::{self, BoxStream, Protocol};
use crate::{ConnectionIdentity, Error, Runtime, RuntimeState, UpgradeTasks, is_reserved};

mod circuit_completion;
mod flow_recording;
mod request_body;
mod request_context;
mod test_context;
mod traffic;
mod traffic_url;

pub(crate) type Body = BoxBody<Bytes, Error>;

/// The HTTP driver exists exactly as long as its request or response body owner.
struct HttpTask {
    task: tokio::task::JoinHandle<()>,
    completion: Option<Arc<circuit_completion::Completion>>,
}

impl HttpTask {
    fn unobserved(task: tokio::task::JoinHandle<()>) -> Self {
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
}

/// Apply validated request effects before releasing its terminal bytes to the
/// origin. The parser observer supplies success; body frames only prompt a check.
struct ForwardedRequestBody {
    body: Body,
    completion: Arc<circuit_completion::Completion>,
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
        Pin::new(&mut self.get_mut().body)
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(|error| -> Error { Box::new(error) })))
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
    upstream: tokio::sync::Mutex<Option<BoxStream>>,
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
async fn open_egress(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    tunnel: bool,
) -> Result<Connected, Error> {
    let destination = allowed.destination;
    if is_reserved(&destination.host) {
        return Err("reserved destination cannot egress".into());
    }
    let (host, port, tls, route) = match &runtime.parent {
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
    let record_egress = || {
        runtime.record(json!({
            "event": "proxy.egress", "agent": allowed.identity.agent_id,
            "connection_id": allowed.identity.connection_id, "request_id": allowed.request_id,
            "host": destination.host, "port": destination.port, "route": route,
        }))
    };
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
    let peer = if runtime.parent.is_none() {
        match socket.peer_addr()?.ip() {
            std::net::IpAddr::V4(address) => Some(address),
            _ => None,
        }
    } else {
        None
    };
    let mut stream: BoxStream = if tls {
        let name = ServerName::try_from(host.to_owned())?;
        let tls = runtime
            .tls
            .clone()
            .ok_or("HTTPS parent TLS was not configured")?;
        Box::new(TlsConnector::from(tls).connect(name, socket).await?)
    } else {
        Box::new(socket)
    };
    if tunnel && runtime.parent.is_some() {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let task = HttpTask::unobserved(tokio::spawn(async move {
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
    Ok(Connected { stream, peer })
}

async fn open_outbound(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
    offer_http2: bool,
    tunnel: Option<&Tunnel>,
) -> Result<Outbound, Error> {
    let destination = allowed.destination;
    let existing = if let Some(tunnel) = tunnel {
        tunnel.upstream.lock().await.take()
    } else {
        None
    };
    let mut stream = match existing {
        Some(stream) => stream,
        None => {
            open_egress(
                runtime,
                allowed,
                tunnel.is_some() || destination.scheme == "https",
            )
            .await?
            .stream
        }
    };
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
    }
    Ok(Outbound { stream, http2 })
}

async fn decide(runtime: &Runtime, request: &PolicyRequest<'_>) -> Result<PolicyDecision, Error> {
    if let Some(policy) = &runtime.policy {
        use crate::network_guard::{Identity, Options, OutcomeKind, Pdp, Request};

        let outcome = runtime.network_guard.enforce(
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
        )?;
        // Development guard evidence excludes the URL query and application
        // bytes. Production audit persistence and approval consumption follow.
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
    let _task = HttpTask::unobserved(tokio::spawn(async move {
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
    // Development evidence uses the facade's audit fields, excluding request
    // headers and query. Production audit storage is not yet connected.
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
    state: RuntimeState,
    identity: &ConnectionIdentity,
    request_id: &str,
    request: &mut Request<Incoming>,
    destination: &Destination,
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
    let outcome = if runtime.config.agent_api_enabled {
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
                flows: runtime.flow_recorder.store(),
                circuits: runtime.policy.as_ref().map(|_| agent_api::CircuitContext {
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
    let mut evidence_failed = record_agent_api(runtime, identity, request_id, &outcome).is_err()
        | crate::circuit_runtime::record_transitions(runtime, &outcome.circuit_events, None);
    // The existing API reader supplies only a scalar observation. Its Body
    // terminal is insufficient on H2 NO_ERROR reset: require parser success.
    // Early routes never wait for an unread body merely to generate traffic.
    let terminal_body = request.body().is_end_stream();
    let eligible =
        (local_observation.decoded_size.is_some() || terminal_body) && observer.await.is_ok();
    let traffic = if eligible {
        ordered_headers.apply_hygiene(request.headers_mut());
        let traffic = traffic::Traffic::new(state, identity, request_id, request, destination);
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

fn declaration_time() -> f64 {
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
) -> (Option<Response<Body>>, bool, bool) {
    use crate::circuits::{CircuitValue, RequestDecision, RequestGate};
    let Ok(runtime) = state.read() else {
        eprintln!("Circuit request runtime unavailable");
        return (None, true, true);
    };
    let Some(policy) = runtime.policy.as_ref() else {
        return (None, false, false);
    };
    let host = &destination.policy_host;
    let result = runtime.circuits.request_current(
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
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("Circuit request operation failed: {:?}", error.kind());
            let failed = crate::circuit_runtime::record_transitions(&runtime, error.events(), None);
            return (None, failed, true);
        }
    };
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
        Ok(reply) => (Some(reply), failed, false),
        Err(_) => {
            eprintln!("Circuit request response construction failed");
            (None, failed, true)
        }
    }
}

// Keep the immutable request snapshot separate from the reloadable state used
// by later requests inside CONNECT, and keep routing separate from identity.
#[allow(clippy::too_many_arguments)]
async fn forward(
    runtime: Arc<Runtime>,
    state: RuntimeState,
    upgrades: Option<UpgradeTasks>,
    identity: &ConnectionIdentity,
    request_id: &str,
    mut request: Request<Incoming>,
    recording: Arc<flow_recording::Recording>,
    destination: &Destination,
    tunnel: Option<&Tunnel>,
) -> Result<(Response<Body>, String), Error> {
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
                state.clone(),
                identity,
                request_id,
                &mut request,
                destination,
            )
            .await?;
            return Ok((prior_block(reply), "local".into()));
        }
        return Ok((
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Local endpoint is not implemented in the development proxy",
            ),
            "local".into(),
        ));
    }
    if (request.method() == Method::CONNECT && (upgrades.is_none() || tunnel.is_some()))
        || !matches!(destination.scheme.as_str(), "http" | "https")
        || (destination.scheme == "https" && runtime.certificate_authority.is_none())
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
    let decision = decide(
        &runtime,
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
        )?;
        return Ok((prior_block(denied), decision.decision));
    }
    if request.method() == Method::CONNECT {
        // Admission precedes DNS/dial. Eager connection supports protocols whose
        // server greets the client before receiving any client bytes.
        let connected = open_egress(
            &runtime,
            &AllowedRequest {
                destination,
                identity,
                request_id,
            },
            true,
        )
        .await?;
        let passthrough =
            runtime
                .passthrough
                .matches(&destination.host, destination.port, connected.peer);
        let upgrade = hyper::upgrade::on(&mut request);
        let identity = identity.clone();
        let destination = destination.clone();
        let request_id = request_id.to_owned();
        let upgrades = upgrades.ok_or("nested CONNECT is unsupported")?;
        let mut stop = upgrades.stop.clone();
        upgrades.tasks.lock().await.spawn(async move {
            let result: Result<(), Error> = async {
                if *stop.borrow() {
                    return Ok(());
                }
                let client: BoxStream = tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    result = upgrade => Box::new(TokioIo::new(result?)),
                };
                let (protocol, client, server) = if passthrough {
                    (Protocol::Opaque, client, connected.stream)
                } else {
                    tunnels::classify(client, connected.stream, &mut stop).await?
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
                    upstream: tokio::sync::Mutex::new(Some(server)),
                });
                serve_tunnel_http(state, identity, tunnel, client, http2, stop).await
            }
            .await;
            if let Err(error) = result {
                eprintln!("CONNECT {request_id} ended: {error}");
            }
        });
        return Ok((Response::new(full(Bytes::new())), decision.decision));
    }
    let (circuit_block, circuit_evidence_failed, circuit_hook_failed) = circuit_admission(
        &state,
        identity,
        request_id,
        request.method().as_str(),
        destination,
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
        )?;
        return Ok((prior_block(reply), "deny".into()));
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
        )?
    };
    let mut context = match admission {
        request_context::Admission::Inactive => {
            request_context::RequestContext::traffic_only(&mut request, false)?
        }
        request_context::Admission::HookError => {
            request_context::RequestContext::traffic_only(&mut request, true)?
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
            )?;
            return Ok((prior_block(response), "deny".into()));
        }
        request_context::Admission::Pending(context) => context,
    };
    let traffic = traffic.expect("CONNECT returned before ordinary HTTP hooks");
    traffic.request_headers(&request, destination);
    context.attach_traffic(traffic);
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
    let websocket = if hygiene.websocket {
        if upgrades.is_none() {
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
            destination,
            identity,
            request_id,
        },
        request.version() == hyper::Version::HTTP_2,
        tunnel,
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
    });
    let (mut upstream, connection) = if outbound.http2 {
        // :authority carries the admitted destination. Avoid retaining a second
        // authority representation while translating a proxied request.
        request.headers_mut().remove(header::HOST);
        *request.version_mut() = hyper::Version::HTTP_2;
        let (mut sender, connection) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            TokioIo::new(outbound.stream),
        )
        .await?;
        let driver = completion.clone().drive(connection);
        let connection = HttpTask {
            task: tokio::spawn(async move {
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
            task: tokio::spawn(async move {
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
    if completion.evidence_failed() || circuit_evidence_failed {
        upstream
            .headers_mut()
            .insert("x-safeyolo-evidence-error", "true".parse()?);
    }
    if upstream.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some((handshake, client_upgrade)) = websocket else {
            return Err("unexpected upstream protocol switch".into());
        };
        let negotiated = handshake.response(&upstream)?;
        let server_upgrade = hyper::upgrade::on(&mut upstream);
        let (mut parts, _) = upstream.into_parts();
        strip_hop_headers(&mut parts.headers);
        parts.headers.insert(header::CONNECTION, "Upgrade".parse()?);
        parts.headers.insert(header::UPGRADE, "websocket".parse()?);
        let upgrades = upgrades.ok_or("WebSocket upgrade owner unavailable")?;
        let mut stop = upgrades.stop.clone();
        let session = crate::websocket_relay::Session {
            state,
            identity: identity.clone(),
            request_id: request_id.to_owned(),
            host: destination.host.clone(),
            port: destination.port,
        };
        upgrades.tasks.lock().await.spawn(async move {
            let _connection = connection;
            let result: Result<(), Error> = async {
                if *stop.borrow() { return Ok(()); }
                let (client, server) = tokio::select! {
                    _ = stop.changed() => return Ok(()),
                    result = async { tokio::try_join!(client_upgrade, server_upgrade) } => result?,
                };
                runtime.record(json!({
                    "event": "proxy.websocket.start", "agent": session.identity.agent_id,
                    "connection_id": session.identity.connection_id, "request_id": session.request_id,
                    "host": session.host, "port": session.port,
                    "subprotocol": negotiated.subprotocol,
                    "compressed_client": negotiated.client.is_some(), "compressed_server": negotiated.server.is_some(),
                }))?;
                crate::websocket_relay::relay(Box::new(TokioIo::new(client)), Box::new(TokioIo::new(server)), negotiated, session, stop).await
            }.await;
            if result.is_err() { eprintln!("WebSocket connection ended with an error"); }
        });
        return Ok((
            Response::from_parts(parts, full(Bytes::new())),
            decision.decision,
        ));
    }
    let (mut parts, body) = upstream.into_parts();
    strip_hop_headers(&mut parts.headers);
    Ok((
        Response::from_parts(
            parts,
            UpstreamBody {
                body,
                _connection: connection,
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
) -> Result<(), Error> {
    let upgrades: UpgradeTasks = Arc::new(crate::UpgradeState {
        tasks: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
        stop: stop.clone(),
    });
    let request_upgrades = upgrades.clone();
    let service = hyper::service::service_fn(move |request| {
        serve_request(
            state.clone(),
            identity.clone(),
            request,
            Some(tunnel.clone()),
            (!http2).then(|| request_upgrades.clone()),
        )
    });
    if http2 {
        let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
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
    let mut tasks = upgrades.tasks.lock().await;
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub(crate) fn serve_request(
    state: RuntimeState,
    identity: ConnectionIdentity,
    request: Request<Incoming>,
    tunnel: Option<Arc<Tunnel>>,
    upgrades: Option<UpgradeTasks>,
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
        let result = match &destination {
            Ok(destination) => {
                forward(
                    runtime.clone(),
                    state.clone(),
                    upgrades,
                    &identity,
                    &request_id,
                    request,
                    recording.clone(),
                    destination,
                    tunnel.as_deref(),
                )
                .await
            }
            Err(_) => Ok((
                response(StatusCode::BAD_REQUEST, "Invalid request authority"),
                "invalid".into(),
            )),
        };
        if let Err(error) = &result {
            recording.producer_error(error);
            recording.finish(false, None, false);
        }
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
        let circuit = if !connect
            && reply
                .extensions_mut()
                .remove::<CircuitPriorBlock>()
                .is_some()
            && let Ok(destination) = &destination
        {
            crate::circuit_runtime::local_blocked_response(&state, &destination.policy_host)
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
            recording.skip_response();
        } else {
            // Upstream/deferred recording stays with Completion. Local response
            // recording follows the same earlier circuit exception boundary.
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
