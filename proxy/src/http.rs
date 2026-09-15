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

pub(crate) type Body = BoxBody<Bytes, Error>;

/// The HTTP driver exists exactly as long as its request or response body owner.
struct HttpTask(tokio::task::JoinHandle<()>);

impl Drop for HttpTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct UpstreamBody {
    body: Incoming,
    _connection: HttpTask,
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
}

#[derive(Deserialize)]
struct PolicyDecision {
    allow: bool,
    decision: String,
    status: Option<u16>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body: Option<String>,
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
    runtime.record(json!({
        "event": "proxy.egress", "agent": allowed.identity.agent_id,
        "connection_id": allowed.identity.connection_id, "request_id": allowed.request_id,
        "host": destination.host, "port": destination.port, "route": route,
    }))?;
    let socket = TcpStream::connect((host, port)).await?;
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
        let task = HttpTask(tokio::spawn(async move {
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
    let _task = HttpTask(tokio::spawn(async move {
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
    destination: &Destination,
    tunnel: Option<&Tunnel>,
) -> Result<(Response<Body>, String), Error> {
    if is_reserved(&destination.host) {
        let status = if request.method() == Method::CONNECT {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        return Ok((
            response(
                status,
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
        return Ok((response, "deny".into()));
    }
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
            header_names: request.headers().keys().map(|name| name.as_str()).collect(),
            body_present: request.headers().contains_key(header::TRANSFER_ENCODING)
                || request
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .is_some_and(|v| v != "0"),
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
        return Ok((denied, decision.decision));
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
    let websocket = if request.headers().contains_key(header::UPGRADE) {
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
        let connection = HttpTask(tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("upstream HTTP/2 connection: {error}");
            }
        }));
        (sender.send_request(request).await?, connection)
    } else {
        *request.version_mut() = hyper::Version::HTTP_11;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(outbound.stream)).await?;
        let connection = HttpTask(tokio::spawn(async move {
            if let Err(error) = connection.with_upgrades().await {
                eprintln!("upstream HTTP connection: {error}");
            }
        }));
        (sender.send_request(request).await?, connection)
    };
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
        let destination =
            Destination::from_request(&request, tunnel.as_ref().map(|tunnel| &tunnel.destination));
        let result = match &destination {
            Ok(destination) => {
                forward(
                    runtime.clone(),
                    state,
                    upgrades,
                    &identity,
                    &request_id,
                    request,
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
        let (mut reply, decision) = result.unwrap_or_else(|error| {
            // Errors contain no application headers/body. A transport/adapter error never retries another route.
            eprintln!("request {request_id} failed: {error}");
            (
                response(StatusCode::BAD_GATEWAY, "Proxy request failed"),
                "error".into(),
            )
        });
        if let Err(error) = runtime.record(json!({
            "event": "proxy.request", "agent": identity.agent_id,
            "connection_id": identity.connection_id, "request_id": request_id,
            "host": destination.as_ref().ok().map(|d| &d.policy_host),
            "port": destination.as_ref().ok().map(|d| d.port),
            "status": reply.status().as_u16(), "decision": decision,
            "coverage": if runtime.policy.is_some() {
                "native_network_guard_only"
            } else {
                "temporary_network_policy_only"
            },
        })) {
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
