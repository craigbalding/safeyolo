//! OpenSSH ProxyCommand through the operator's configured HTTP(S) proxy.
//!
//! This replaces contrib's Python CONNECT relay. It grants no route: the
//! selected proxy makes the same network/approval decision as before.

use crate::Error;
use hyper::Uri;
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HELP: &str = "safeyolo ssh-proxy HOST PORT\nOpenSSH ProxyCommand through HTTPS_PROXY or HTTP_PROXY; no direct fallback. HTTPS uses system/configured CA trust.";

fn authority(host: &str, port: u16) -> Result<String, Error> {
    if host.is_empty()
        || host.starts_with('-')
        || port == 0
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err("SSH destination requires a DNS name/unbracketed IP and port 1–65535".into());
    }
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

fn proxy(value: &str) -> Result<(String, u16, bool), Error> {
    if value.contains('#') {
        return Err("proxy URL must have no fragment".into());
    }
    let uri: Uri = value.parse()?;
    let tls =
        match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err(
                "set HTTPS_PROXY or HTTP_PROXY to the approved HTTP(S) proxy; no direct fallback"
                    .into(),
            ),
        };
    let authority = uri.authority().ok_or("proxy URL has no host")?;
    if authority.as_str().contains('@') || uri.query().is_some() || !matches!(uri.path(), "" | "/")
    {
        return Err("proxy URL must have no credentials, path, query or fragment".into());
    }
    let raw_authority = authority.as_str();
    let explicit_port = if raw_authority.starts_with('[') {
        raw_authority
            .split_once(']')
            .map(|(_, rest)| rest)
            .unwrap_or("")
    } else {
        raw_authority.strip_prefix(authority.host()).unwrap_or("")
    };
    let port = match explicit_port.strip_prefix(':') {
        Some(port) => port.parse::<u16>()?,
        None if !explicit_port.is_empty() => return Err("invalid proxy port".into()),
        None => {
            if tls {
                443
            } else {
                80
            }
        }
    };
    if port == 0 {
        return Err("proxy port must be 1–65535".into());
    }
    Ok((
        authority.host().trim_matches(['[', ']']).to_owned(),
        port,
        tls,
    ))
}

async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authority: &str,
) -> Result<(), Error> {
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut header = Vec::new();
    // Never consume an SSH banner following CONNECT headers in the same packet.
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 32768 {
            return Err("oversized CONNECT response headers".into());
        }
        header.push(stream.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&header);
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or("missing CONNECT response")?;
    let fields: Vec<_> = status.split_whitespace().collect();
    if fields.len() < 2 || !matches!(fields[0], "HTTP/1.0" | "HTTP/1.1") || fields[1] != "200" {
        let details: Vec<_> = lines
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                lower.starts_with("x-blocked-by:") || lower.starts_with("x-safeyolo-request-id:")
            })
            .collect();
        let advice = if fields.get(1) == Some(&"428") {
            " Operator approval required: run safeyolo approvals list on the host, then retry once approved."
        } else {
            ""
        };
        return Err(format!("CONNECT rejected: {status:?}; {details:?}.{advice}").into());
    }
    Ok(())
}

async fn relay<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Result<(), Error> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (input, mut received) = tokio::sync::mpsc::channel(1);
    // A blocked stdin read must not keep the Tokio runtime alive after the SSH
    // peer closes. This ordinary detached I/O thread ends with this process.
    std::thread::Builder::new()
        .name("ssh-stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                let mut bytes = vec![0; 65536];
                let count = match stdin.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error) => {
                        let _ = input.blocking_send(Err(error));
                        break;
                    }
                };
                bytes.truncate(count);
                if input.blocking_send(Ok(bytes)).is_err() {
                    break;
                }
            }
        })?;
    let send = async {
        while let Some(bytes) = received.recv().await {
            writer.write_all(&bytes?).await?;
        }
        writer.shutdown().await
    };
    let output = async {
        let mut stdout = std::io::stdout().lock();
        let mut bytes = [0; 65536];
        loop {
            let count = match reader.read(&mut bytes).await {
                Ok(count) => count,
                // The replaced Python TLS socket accepted a closed tunnel
                // without close_notify. SSH itself checks framing/integrity;
                // keep those final bytes and expose EOF to OpenSSH.
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            if count == 0 {
                return Ok::<_, std::io::Error>(());
            }
            stdout.write_all(&bytes[..count])?;
            stdout.flush()?;
        }
    };
    tokio::pin!(send, output);
    tokio::select! {
        result = &mut output => result?,
        result = &mut send => {
            // Peer closure can race a pending write; receiving still drains its
            // final SSH bytes. Other input errors remain visible to the caller.
            if let Err(error) = result
                && !matches!(error.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset) {
                return Err(error.into());
            }
            output.await?;
        }
    }
    Ok(())
}

pub async fn run(host: &str, port: u16) -> Result<(), Error> {
    let destination = authority(host, port)?;
    let configured = std::env::var("HTTPS_PROXY")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("HTTP_PROXY").ok())
        .unwrap_or_default();
    let (proxy_host, proxy_port, tls) = proxy(&configured)?;
    let socket = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((proxy_host.as_str(), proxy_port)),
    )
    .await??;
    if tls {
        let ca = std::env::var_os("SSL_CERT_FILE")
            .or_else(|| std::env::var_os("REQUESTS_CA_BUNDLE"))
            .map(PathBuf::from);
        let config = crate::http::client_tls(ca.as_deref())?;
        let server = rustls::pki_types::ServerName::try_from(proxy_host)?;
        let mut stream = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_rustls::TlsConnector::from(config).connect(server, socket),
        )
        .await??;
        tokio::time::timeout(Duration::from_secs(15), connect(&mut stream, &destination)).await??;
        relay(stream).await
    } else {
        let mut stream = socket;
        tokio::time::timeout(Duration::from_secs(15), connect(&mut stream, &destination)).await??;
        relay(stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_and_proxy_preserve_transport_constraints() {
        assert_eq!(authority("2001:db8::1", 22).unwrap(), "[2001:db8::1]:22");
        assert_eq!(
            proxy("https://proxy.example:8443/").unwrap(),
            ("proxy.example".into(), 8443, true)
        );
        for host in ["", "-option", "a\r\nHost: b", "[::1]", "a/path"] {
            assert!(authority(host, 22).is_err());
        }
        for url in [
            "",
            "socks5://host",
            "http://user:secret@host",
            "http://host/path",
            "http://host?query",
            "http://host/#fragment",
            "http://host:wrong",
        ] {
            assert!(proxy(url).is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn connect_preserves_immediate_banner_and_block_diagnosis() {
        for status in [200, 403, 428] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let peer = tokio::spawn(async move {
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(server.read_u8().await.unwrap());
                }
                assert!(header.starts_with(b"CONNECT mac.example:22 HTTP/1.1\r\n"));
                server.write_all(format!("HTTP/1.1 {status} Result\r\nX-Blocked-By: network-guard\r\n\r\nSSH-banner").as_bytes()).await.unwrap();
            });
            let result = connect(&mut client, "mac.example:22").await;
            if status == 200 {
                result.unwrap();
                let mut banner = Vec::new();
                client.read_to_end(&mut banner).await.unwrap();
                assert_eq!(banner, b"SSH-banner");
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(&status.to_string()) && error.contains("network-guard"));
                assert_eq!(error.contains("safeyolo approvals list"), status == 428);
            }
            peer.await.unwrap();
        }
    }
}
