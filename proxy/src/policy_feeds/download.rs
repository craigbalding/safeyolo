//! Bound curl's existing host proxy/CA transport. Endpoint secrets go through
//! stdin, never argv; curlrc, URL globbing, automatic redirects and raw diagnostics are off.

use super::{Source, State, uri};
use crate::Error;
use std::{collections::BTreeMap, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

pub(super) struct Download {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
    pub(super) etag: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) endpoint: String,
}
fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
fn cache_header(value: Option<&String>) -> Option<&str> {
    value
        .filter(|value| value.len() <= 4096 && !value.contains(['\r', '\n', '\0']))
        .map(String::as_str)
}

pub(super) async fn fetch(
    root: &std::path::Path,
    name: &str,
    source: &Source,
    state: &State,
) -> Result<Download, Error> {
    tokio::time::timeout(Duration::from_secs(source.timeout_seconds), async {
        let mut endpoint = source.endpoint.clone();
        let mut visited = Vec::new();
        loop {
            if visited.contains(&endpoint) {
                return Err("feed redirect loop".into());
            }
            visited.push(endpoint.clone());
            if super::configuration(root)?
                .sources
                .get(name)
                .is_none_or(|adopted| adopted != source)
            {
                return Err("source configuration changed during acquisition".into());
            }
            let reply = request(source, state, &endpoint).await?;
            if matches!(reply.status, 301 | 302 | 303 | 307 | 308) {
                let target = reply
                    .headers
                    .get("location")
                    .ok_or("feed redirect has no destination")?;
                // Absolute adopted targets make both path/query and origin
                // restrictions explicit. No implicit cross-origin credential forwarding.
                uri(target).map_err(|_| "feed redirect requires an adopted absolute endpoint")?;
                if !source.redirect_endpoints.contains(target) {
                    return Err(
                        "feed redirect destination is outside the adopted source configuration"
                            .into(),
                    );
                }
                endpoint = target.clone();
                continue;
            }
            if !matches!(reply.status, 200 | 304) {
                return Err(format!("feed returned HTTP {}", reply.status).into());
            }
            if reply.status != 304
                && reply.headers.get("content-type").is_some_and(|value| {
                    let value = value.to_ascii_lowercase();
                    value.contains("html") || value.contains("json") || value.contains("xml")
                })
            {
                return Err("feed response has an unexpected content type".into());
            }
            return Ok(Download {
                status: reply.status,
                body: reply.body,
                etag: cache_header(reply.headers.get("etag")).map(str::to_owned),
                last_modified: cache_header(reply.headers.get("last-modified")).map(str::to_owned),
                endpoint,
            });
        }
    })
    .await
    .map_err(|_| "feed acquisition exceeded timeout")?
}
struct Reply {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
async fn request(source: &Source, state: &State, endpoint: &str) -> Result<Reply, Error> {
    uri(endpoint)?;
    let mut config = Zeroizing::new(format!("url = \"{}\"\n", quote(endpoint)));
    if state.cache_endpoint.as_deref() == Some(endpoint) {
        for (key, value) in [
            ("If-None-Match", &state.etag),
            ("If-Modified-Since", &state.last_modified),
        ] {
            if let Some(value) = cache_header(value.as_ref()) {
                config.push_str(&format!("header = \"{key}: {}\"\n", quote(value)));
            }
        }
    }
    let mut child = tokio::process::Command::new("curl")
        .args([
            "--disable",
            "--globoff",
            "--config",
            "-",
            "--silent",
            "--http1.1",
            "--include",
            "--suppress-connect-headers",
            "--proto",
            "=http,https",
            "--request",
            "GET",
            "--header",
            "Accept-Encoding: identity",
            "--user-agent",
            "safeyolo-policy-feeds",
        ])
        .arg("--max-time")
        .arg(source.timeout_seconds.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "cannot start host curl for feed acquisition")?;
    let mut input = child.stdin.take().ok_or("feed transport has no input")?;
    input
        .write_all(config.as_bytes())
        .await
        .map_err(|_| "cannot configure feed transport")?;
    drop(input);
    let mut output = BufReader::new(child.stdout.take().ok_or("feed transport has no output")?);
    let mut header_bytes = 0;
    let (status, headers) = loop {
        let mut line = Vec::new();
        read_line(&mut output, &mut line, &mut header_bytes).await?;
        let status = std::str::from_utf8(&line)
            .ok()
            .and_then(|line| {
                let mut fields = line.split_whitespace();
                matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0"))
                    .then(|| fields.next()?.parse::<u16>().ok())
                    .flatten()
            })
            .ok_or("feed response has invalid HTTP headers")?;
        let mut headers = BTreeMap::new();
        loop {
            line.clear();
            read_line(&mut output, &mut line, &mut header_bytes).await?;
            if line == b"\r\n" || line == b"\n" {
                break;
            }
            let line =
                std::str::from_utf8(&line).map_err(|_| "feed response headers are not UTF-8")?;
            let (key, value) = line
                .trim_end_matches(['\r', '\n'])
                .split_once(':')
                .ok_or("feed response has invalid HTTP headers")?;
            let key = key.to_ascii_lowercase();
            if matches!(
                key.as_str(),
                "location" | "content-type" | "content-length" | "etag" | "last-modified"
            ) && headers.insert(key, value.trim().to_owned()).is_some()
            {
                return Err("feed response has duplicate singleton HTTP headers".into());
            }
        }
        if (100..200).contains(&status) {
            continue;
        }
        break (status, headers);
    };
    // Reject by declared size before reading, and enforce the same bound on
    // streaming/chunked bodies. The child dies on rejection or cancellation.
    if headers.get("content-length").is_some_and(|value| {
        value
            .parse::<u64>()
            .map_or(true, |length| length > source.max_bytes)
    }) {
        return Err("feed response exceeds max_bytes or has invalid content length".into());
    }
    let mut body = Vec::new();
    output
        .take(source.max_bytes + 1)
        .read_to_end(&mut body)
        .await
        .map_err(|_| "feed response body could not be read")?;
    if body.len() as u64 > source.max_bytes {
        return Err("feed response exceeds max_bytes".into());
    }
    let exit = child
        .wait()
        .await
        .map_err(|_| "feed transport could not finish")?;
    if !exit.success() {
        return Err("feed transfer failed or was truncated".into());
    }
    if let Some(length) = headers
        .get("content-length")
        .and_then(|value| value.parse::<u64>().ok())
        && status != 304
        && length != body.len() as u64
    {
        return Err("feed response was truncated".into());
    }
    Ok(Reply {
        status,
        headers,
        body,
    })
}
async fn read_line(
    input: &mut (impl tokio::io::AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
    total: &mut usize,
) -> Result<(), Error> {
    // take() bounds an unterminated line as well as the complete header block.
    let count = input
        .take((65536usize.saturating_sub(*total) + 1) as u64)
        .read_until(b'\n', line)
        .await
        .map_err(|_| "feed headers could not be read")?;
    *total += count;
    if count == 0 || *total > 65536 {
        return Err("feed response headers are missing or exceed 64 KiB".into());
    }
    Ok(())
}
