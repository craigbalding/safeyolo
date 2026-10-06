//! Native CLI requests to the operator and guest APIs, with distinct caller credentials.

use crate::{Error, native_config};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{path::Path, time::Duration};
use zeroize::Zeroizing;

pub async fn admin(
    config_path: &Path,
    path: &str,
    method: Method,
    body: Value,
    timeout: Duration,
) -> Result<Value, Error> {
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
    let token = token.trim();
    if token.is_empty() {
        return Err("Admin API token is empty".into());
    }
    let socket = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    send_json(
        socket,
        &format!("127.0.0.1:{port}"),
        path,
        token,
        method,
        body,
        timeout,
    )
    .await
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
    let (mut client, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
    let result = tokio::time::timeout(timeout, async {
        let response = client.send_request(request).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
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
        Ok::<_, Error>(value)
    })
    .await;
    driver.abort();
    let _ = driver.await;
    result?
}
