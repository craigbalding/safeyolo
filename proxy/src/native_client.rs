//! Native operator and Helper transports. Caller credentials stay distinct.

use std::{io::Write, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{Error, native_config};

const TIMEOUT: Duration = Duration::from_secs(5);

struct Connection(tokio::task::JoinHandle<Result<(), hyper::Error>>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn send<IO>(
    socket: IO,
    host: &str,
    path: &str,
    token: &str,
    method: Method,
    body: Value,
) -> Result<(Response<Incoming>, Connection), Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    let driver = Connection(tokio::spawn(connection));
    let bytes = if method == Method::GET && body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body)?
    };
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(bytes)))?;
    let response = client.send_request(request).await?;
    Ok((response, driver))
}

async fn json(response: Response<Incoming>) -> Result<Value, Error> {
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let value: Value = serde_json::from_slice(&bytes)?;
    if !status.is_success() {
        let outcome = if value.get("send_outcome").and_then(Value::as_str) == Some("unknown") {
            "; send outcome unknown; inspect retained history before repeating"
        } else {
            ""
        };
        return Err(format!(
            "API {status}: {}{outcome}",
            value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("request failed")
        )
        .into());
    }
    Ok(value)
}

async fn operator_socket(
    config_path: &Path,
) -> Result<(tokio::net::TcpStream, String, Zeroizing<String>), Error> {
    let config = native_config::read(config_path)?;
    let configured_port = config.admin_port.ok_or("Admin API is disabled")?;
    let port = if configured_port == 0 {
        let readiness: Value = serde_json::from_slice(&std::fs::read(&config.readiness_file)?)?;
        readiness
            .get("admin_port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or("readiness does not name an Admin API port")?
    } else {
        configured_port
    };
    let token = Zeroizing::new(std::fs::read_to_string(
        config
            .admin_api_token_file
            .ok_or("Admin API token path is missing")?,
    )?);
    if token.trim().is_empty() {
        return Err("Admin API token is empty".into());
    }
    let socket = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(("127.0.0.1", port)))
        .await??;
    Ok((socket, format!("127.0.0.1:{port}"), token))
}

pub async fn admin(
    config_path: &Path,
    path: &str,
    method: Method,
    body: Value,
    timeout: Duration,
) -> Result<Value, Error> {
    let (socket, host, token) = operator_socket(config_path).await?;
    send_json(socket, &host, path, token.trim(), method, body, timeout).await
}

/// Stream into a same-directory temporary file. A missing or truncated export
/// cannot replace a previous file with an empty or partial successful result.
pub async fn export(config_path: &Path, path: &str, destination: &Path) -> Result<u64, Error> {
    let (socket, host, token) = operator_socket(config_path).await?;
    let (response, _connection) = tokio::time::timeout(
        TIMEOUT,
        send(socket, &host, path, token.trim(), Method::GET, Value::Null),
    )
    .await??;
    if !response.status().is_success() {
        tokio::time::timeout(TIMEOUT, json(response)).await??;
        return Err("export unavailable".into());
    }
    let destination = if std::fs::symlink_metadata(destination)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        destination.canonicalize()?
    } else {
        destination.to_owned()
    };
    let permissions = match std::fs::metadata(&destination) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o666))
        .tempfile_in(parent)?;
    let mut body = response.into_body();
    let mut written = 0;
    while let Some(frame) = tokio::time::timeout(TIMEOUT, body.frame()).await? {
        if let Ok(data) = frame?.into_data() {
            temporary.write_all(&data)?;
            written += data.len() as u64;
        }
    }
    if let Some(permissions) = permissions {
        temporary.as_file().set_permissions(permissions)?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist(&destination)?;
    Ok(written)
}

pub async fn send_json<IO>(
    socket: IO,
    host: &str,
    path: &str,
    token: &str,
    method: Method,
    body: Value,
    timeout: Duration,
) -> Result<Value, Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(timeout, async {
        let (response, _connection) = send(socket, host, path, token, method, body).await?;
        json(response).await
    })
    .await?
}

/// Host REST requests use the configured HTTPS proxy and the same native TLS
/// trust loader as upstream connections. No redirects or automatic retries:
/// callers own uncertain-write reconciliation. Credentials are header-only.
pub(crate) async fn https_json(
    url: &str,
    token: &str,
    method: Method,
    body: Value,
) -> Result<Value, Error> {
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let uri: hyper::Uri = url.parse()?;
    if uri.scheme_str() != Some("https") || uri.authority().is_none_or(|a| a.as_str().contains('@'))
    {
        return Err("REST destination must be HTTPS without credentials".into());
    }
    let host = uri
        .host()
        .ok_or("REST destination has no host")?
        .trim_matches(['[', ']'])
        .to_owned();
    let authority = uri
        .authority()
        .ok_or("REST destination has no authority")?
        .as_str()
        .to_owned();
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let ca = std::env::var_os("SSL_CERT_FILE").or_else(|| std::env::var_os("REQUESTS_CA_BUNDLE"));
    let tls = crate::http::client_tls(ca.as_deref().map(Path::new))?;
    tokio::time::timeout(Duration::from_secs(15), async {
        let proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
            .into_iter()
            .find_map(|key| std::env::var(key).ok().filter(|v| !v.is_empty()));
        let socket: crate::tunnels::BoxStream = if let Some(proxy) = proxy {
            let proxy: hyper::Uri = proxy.parse()?;
            let route = proxy.authority().ok_or("invalid HTTPS proxy route")?;
            let (credentials, route) = route
                .as_str()
                .rsplit_once('@')
                .map_or((None, route.as_str()), |(c, r)| (Some(c), r));
            let route: hyper::http::uri::Authority = route.parse()?;
            let proxy_host = route.host().trim_matches(['[', ']']).to_owned();
            let encrypted = match proxy.scheme_str() {
                Some("http") => false,
                Some("https") => true,
                _ => return Err("HTTPS proxy route must use HTTP or HTTPS".into()),
            };
            let stream = tokio::net::TcpStream::connect((
                proxy_host.as_str(),
                route.port_u16().unwrap_or(if encrypted { 443 } else { 80 }),
            ))
            .await?;
            let mut stream: crate::tunnels::BoxStream = if encrypted {
                Box::new(
                    tokio_rustls::TlsConnector::from(tls.clone())
                        .connect(ServerName::try_from(proxy_host)?, stream)
                        .await?,
                )
            } else {
                Box::new(stream)
            };
            let destination = if uri.port_u16().is_some() {
                authority.clone()
            } else {
                format!("{authority}:443")
            };
            let mut request = Zeroizing::new(format!(
                "CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n"
            ));
            if let Some(credentials) = credentials {
                use base64::Engine;
                let decoded = percent_encoding::percent_decode_str(credentials).decode_utf8()?;
                request.push_str(&format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes())
                ));
            }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes()).await?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() >= 16384 {
                    return Err("HTTPS proxy response headers exceed limit".into());
                }
                head.push(stream.read_u8().await?);
            }
            let mut status_line = std::str::from_utf8(&head)?
                .split("\r\n")
                .next()
                .ok_or("HTTPS proxy response is missing its status")?
                .split(' ');
            if !matches!(status_line.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                return Err("HTTPS proxy response is invalid".into());
            }
            let status = status_line.next().and_then(|v| v.parse::<u16>().ok());
            if !status.is_some_and(|v| (200..300).contains(&v)) {
                return Err("HTTPS proxy refused CONNECT".into());
            }
            stream
        } else {
            Box::new(
                tokio::net::TcpStream::connect((host.as_str(), uri.port_u16().unwrap_or(443)))
                    .await?,
            )
        };
        let socket = tokio_rustls::TlsConnector::from(tls)
            .connect(ServerName::try_from(host)?, socket)
            .await?;
        let (response, _connection) = send(socket, &authority, path, token, method, body).await?;
        let status = response.status();
        if !matches!(status.as_u16(), 200 | 201) {
            return Err(format!("REST request failed with HTTP {}", status.as_u16()).into());
        }
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await?
}

/// The guest uses its existing proxy route and Agent API token. It never reads
/// instance configuration or the operator token, even on an operator host.
pub async fn helper(
    socket: Option<&Path>,
    token_file: &Path,
    path: &str,
    method: Method,
    body: Value,
) -> Result<Value, Error> {
    helper_timeout(socket, token_file, path, method, body, TIMEOUT).await
}

/// Coord long polls use the same authenticated guest transport with their
/// explicit deadline. A failed write is never retried by this client.
pub async fn helper_timeout(
    socket: Option<&Path>,
    token_file: &Path,
    path: &str,
    method: Method,
    body: Value,
    timeout: Duration,
) -> Result<Value, Error> {
    let token = Zeroizing::new(std::fs::read_to_string(token_file)?);
    if token.trim().is_empty() {
        return Err("Agent API token is empty".into());
    }
    let host = "_safeyolo.proxy.internal";
    if let Some(socket) = socket {
        let stream =
            tokio::time::timeout(TIMEOUT, tokio::net::UnixStream::connect(socket)).await??;
        return send_json(stream, host, path, token.trim(), method, body, timeout).await;
    }
    let proxy: hyper::Uri = std::env::var("HTTP_PROXY")
        .or_else(|_| std::env::var("http_proxy"))
        .map_err(|_| "Helper requires the guest's configured HTTP_PROXY or --socket")?
        .parse()?;
    if proxy.scheme_str() != Some("http")
        || proxy
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err("Helper requires its existing plain HTTP proxy route".into());
    }
    let stream = tokio::time::timeout(
        TIMEOUT,
        tokio::net::TcpStream::connect((
            proxy.host().ok_or("proxy host is missing")?,
            proxy.port_u16().unwrap_or(80),
        )),
    )
    .await??;
    send_json(
        stream,
        host,
        &format!("http://{host}{path}"),
        token.trim(),
        method,
        body,
        timeout,
    )
    .await
}
