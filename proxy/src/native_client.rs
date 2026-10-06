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
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
    let response = tokio::time::timeout(TIMEOUT, client.send_request(request)).await??;
    Ok((response, driver))
}

async fn json(response: Response<Incoming>) -> Result<Value, Error> {
    let status = response.status();
    let bytes = tokio::time::timeout(TIMEOUT, response.into_body().collect())
        .await??
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes)?;
    if !status.is_success() {
        return Err(format!(
            "API {status}: {}",
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
) -> Result<Value, Error> {
    let (socket, host, token) = operator_socket(config_path).await?;
    let (response, _connection) = send(socket, &host, path, token.trim(), method, body).await?;
    json(response).await
}

/// Stream into a same-directory temporary file. A missing or truncated export
/// cannot replace a previous file with an empty or partial successful result.
pub async fn export(config_path: &Path, path: &str, destination: &Path) -> Result<u64, Error> {
    let (socket, host, token) = operator_socket(config_path).await?;
    let (response, _connection) =
        send(socket, &host, path, token.trim(), Method::GET, Value::Null).await?;
    if !response.status().is_success() {
        json(response).await?;
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
) -> Result<Value, Error>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (response, _connection) = send(socket, host, path, token, method, body).await?;
    json(response).await
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
    let token = Zeroizing::new(std::fs::read_to_string(token_file)?);
    if token.trim().is_empty() {
        return Err("Agent API token is empty".into());
    }
    let host = "_safeyolo.proxy.internal";
    if let Some(socket) = socket {
        let stream =
            tokio::time::timeout(TIMEOUT, tokio::net::UnixStream::connect(socket)).await??;
        return send_json(stream, host, path, token.trim(), method, body).await;
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
    )
    .await
}
