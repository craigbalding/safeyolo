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
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UnixStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    port: u16,
    authority: String,
    scheme: String,
    path: String,
}

impl Destination {
    fn from_request(
        request: &Request<Incoming>,
        tunnel: Option<&Destination>,
    ) -> Result<Self, Error> {
        if request.headers().get_all(header::HOST).iter().count() > 1 {
            return Err("multiple Host headers are ambiguous".into());
        }
        let uri = request.uri();
        let authority = if let Some(authority) = uri.authority() {
            authority.clone()
        } else {
            request
                .headers()
                .get(header::HOST)
                .ok_or("missing request authority")?
                .to_str()?
                .parse::<hyper::http::uri::Authority>()?
        };
        if authority.as_str().contains('@') {
            return Err("request authority cannot contain user information".into());
        }
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
            .unwrap_or(if tunnel.is_some() { "https" } else { "http" })
            .to_owned();
        let port =
            crate::config::authority_port(&authority, if scheme == "https" { 443 } else { 80 })?;
        if let Some(tunnel) = tunnel
            && (host != tunnel.host || port != tunnel.port || scheme != "https")
        {
            return Err("inner authority differs from admitted CONNECT destination".into());
        }
        Ok(Self {
            host,
            port,
            authority: authority.to_string(),
            scheme,
            path: uri.path_and_query().map_or("/", |p| p.as_str()).to_owned(),
        })
    }
}

/// Constructed only after the temporary production policy returns allow.
struct AllowedRequest<'a> {
    destination: &'a Destination,
    identity: &'a ConnectionIdentity,
    request_id: &'a str,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

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
async fn open_outbound(
    runtime: &Runtime,
    allowed: &AllowedRequest<'_>,
) -> Result<Box<dyn Stream>, Error> {
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
    let mut stream: Box<dyn Stream> = if tls {
        let name = ServerName::try_from(host.to_owned())?;
        let tls = runtime
            .tls
            .clone()
            .ok_or("HTTPS parent TLS was not configured")?;
        Box::new(TlsConnector::from(tls).connect(name, socket).await?)
    } else {
        Box::new(socket)
    };
    if destination.scheme == "https" {
        if runtime.parent.is_some() {
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
        let config = runtime
            .tls
            .clone()
            .ok_or("upstream TLS trust is not configured")?;
        let name = ServerName::try_from(destination.host.clone())?;
        stream = Box::new(TlsConnector::from(config).connect(name, stream).await?);
    }
    Ok(stream)
}

async fn decide(runtime: &Runtime, request: &PolicyRequest<'_>) -> Result<PolicyDecision, Error> {
    // The temporary adapter has one policy/state owner. Queue here instead of
    // overflowing its Unix accept queue or replaying a charged decision. The
    // lock is shared across reload snapshots and released on cancellation.
    let _policy_guard = runtime.temporary_policy_lock.lock().await;
    let socket = UnixStream::connect(&runtime.config.temporary_policy_socket).await?;
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

async fn forward(
    runtime: Arc<Runtime>,
    state: RuntimeState,
    upgrades: Option<UpgradeTasks>,
    identity: &ConnectionIdentity,
    request_id: &str,
    mut request: Request<Incoming>,
    destination: &Destination,
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
                "Local endpoint is not implemented in the Rust M2 slice",
            ),
            "local".into(),
        ));
    }
    if (request.method() == Method::CONNECT
        && (runtime.certificate_authority.is_none() || upgrades.is_none()))
        || !matches!(destination.scheme.as_str(), "http" | "https")
        || (destination.scheme == "https" && runtime.certificate_authority.is_none())
        || request.headers().contains_key(header::UPGRADE)
    {
        return Ok((
            response(
                StatusCode::NOT_IMPLEMENTED,
                "This development slice supports HTTP/1 forwarding only",
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
            scheme: &destination.scheme,
            host: &destination.host,
            port: destination.port,
            path: &destination.path,
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
        return Err("inconsistent temporary policy decision".into());
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
        let config = runtime
            .certificate_authority
            .as_ref()
            .ok_or("TLS CA is not configured")?
            .server_config(&destination.host, time::OffsetDateTime::now_utc())?;
        let upgrade = hyper::upgrade::on(&mut request);
        let identity = identity.clone();
        let destination = Arc::new(destination.clone());
        let request_id = request_id.to_owned();
        upgrades
            .ok_or("nested CONNECT is unsupported")?
            .lock()
            .await
            .spawn(async move {
                let result: Result<(), Error> = async {
                    let socket = TokioIo::new(upgrade.await?);
                    let tls = TlsAcceptor::from(config).accept(socket).await?;
                    let service = hyper::service::service_fn(move |request| {
                        serve_request(
                            state.clone(),
                            identity.clone(),
                            request,
                            Some(destination.clone()),
                            None,
                        )
                    });
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await?;
                    Ok(())
                }
                .await;
                if let Err(error) = result {
                    eprintln!("CONNECT {request_id} ended: {error}");
                }
            });
        return Ok((Response::new(full(Bytes::new())), decision.decision));
    }
    strip_hop_headers(request.headers_mut());
    for name in ["x-safeyolo-request-id", "x-safeyolo-trace"] {
        request.headers_mut().remove(name);
    }
    request
        .headers_mut()
        .insert(header::HOST, destination.authority.parse()?);
    request
        .headers_mut()
        .append(header::VIA, format!("1.1 {}", runtime.via_token).parse()?);
    *request.uri_mut() = if runtime.parent.is_some() && destination.scheme == "http" {
        format!("http://{}{}", destination.authority, destination.path).parse::<Uri>()?
    } else {
        destination.path.parse::<Uri>()?
    };
    let stream = open_outbound(
        &runtime,
        &AllowedRequest {
            destination,
            identity,
            request_id,
        },
    )
    .await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let connection = HttpTask(tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("upstream HTTP connection: {error}");
        }
    }));
    let upstream = sender.send_request(request).await?;
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

pub(crate) fn serve_request(
    state: RuntimeState,
    identity: ConnectionIdentity,
    request: Request<Incoming>,
    tunnel: Option<Arc<Destination>>,
    upgrades: Option<UpgradeTasks>,
) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>> {
    Box::pin(async move {
        let runtime = state.read().expect("runtime read lock").clone();
        let request_id = format!("req-{}", uuid::Uuid::new_v4().simple());
        let destination = Destination::from_request(&request, tunnel.as_deref());
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
            "host": destination.as_ref().ok().map(|d| &d.host),
            "port": destination.as_ref().ok().map(|d| d.port),
            "status": reply.status().as_u16(), "decision": decision,
            "coverage": "temporary_network_policy_only",
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
