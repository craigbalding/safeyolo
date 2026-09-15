//! Logging-only projection of Request.pretty_url and urllib.parse.urlparse.
//!
//! This does not choose a destination, validate a request, or decode escapes.
//! Source and finite compatibility boundaries are retained in the paired oracle.
//! The component split follows CPython 3.12 urllib.parse; its PSF license is
//! retained at proxy/data/agent_api/LICENSE-Python.txt. No URL crate normalization
//! is substituted for the observed source behavior.

use std::{fmt, net::Ipv6Addr};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub(super) struct Input<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    /// Already source-combined Host fields, before outgoing header rewrites.
    pub host_header: Option<&'a str>,
    /// Source HTTP/2 :authority, preferred when nonempty.
    pub authority: Option<&'a str>,
    pub http2: bool,
}

/// Payload-bearing fields are wiped on release and deliberately omit Debug.
pub(super) struct PrettyUrl {
    pub host: Zeroizing<String>,
    pub path: Zeroizing<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Parse,
    /// A reached scalar transform exceeds the pinned source Unicode version.
    Compatibility,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Parse => "invalid logging URL",
            Self::Compatibility => "logging URL compatibility unavailable",
        })
    }
}
impl std::error::Error for Error {}

pub(super) fn project(input: Input<'_>) -> Result<PrettyUrl, Error> {
    let selected = if input.http2 {
        input
            .authority
            .filter(|s| !s.is_empty())
            .or(input.host_header)
    } else {
        input.host_header
    };
    let (host, port) = if let Some(raw) = selected.filter(|s| !s.is_empty()) {
        let (host, port) = super::flow_recording::pretty_authority(raw);
        (
            host,
            port.filter(|p| *p != 0)
                .or(default_port(input.scheme))
                .unwrap_or(443),
        )
    } else {
        (input.host, input.port)
    };
    let path = if input.path == "*" { "" } else { input.path };
    // Do not bracket IPv6 here: source url.hostport does not do so either.
    let mut full = Zeroizing::new(format!("{}://{}", input.scheme, host));
    if default_port(input.scheme) != Some(port) {
        use std::fmt::Write;
        write!(&mut *full, ":{port}").expect("String write is infallible");
    }
    full.push_str(path);
    split(&full)
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn split(full: &str) -> Result<PrettyUrl, Error> {
    let cleaned = Zeroizing::new(
        full.trim_start_matches(|c: char| c <= '\u{20}')
            .chars()
            .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
            .collect::<String>(),
    );
    let (scheme, rest) = match cleaned.split_once(':') {
        Some((scheme, rest))
            if scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) =>
        {
            (scheme.to_ascii_lowercase(), rest)
        }
        _ => (String::new(), cleaned.as_str()),
    };
    let (netloc, rest) = if let Some(rest) = rest.strip_prefix("//") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    } else {
        ("", rest)
    };
    if netloc.contains(['[', ']']) {
        check_brackets(netloc)?;
    }
    // urllib removes these existing separators before its NFKC hazard check.
    if !netloc.is_ascii() {
        let checked = Zeroizing::new(
            netloc
                .chars()
                .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
                .collect::<String>(),
        );
        let normalized = Zeroizing::new(checked.nfkc().collect::<String>());
        if *checked != *normalized && normalized.contains(['/', '?', '#', '@', ':']) {
            return Err(Error::Parse);
        }
    }
    let rest = rest
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    let path = if matches!(
        scheme.as_str(),
        "" | "ftp"
            | "hdl"
            | "prospero"
            | "http"
            | "imap"
            | "https"
            | "shttp"
            | "rtsp"
            | "rtsps"
            | "rtspu"
            | "sip"
            | "sips"
            | "mms"
            | "sftp"
            | "tel"
    ) {
        let segment = rest.rfind('/').unwrap_or(0);
        rest[segment..]
            .find(';')
            .map_or(rest, |index| &rest[..segment + index])
    } else {
        rest
    };
    let info = netloc.rsplit('@').next().unwrap_or("");
    let host = if let Some((_, bracketed)) = info.split_once('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        info.split(':').next().unwrap_or("")
    };
    let (name, zone) = host
        .split_once('%')
        .map_or((host, None), |(name, zone)| (name, Some(zone)));
    // The crate's Unicode version can exceed pinned Python 3.12. Do not forge a
    // source lowercase for newly assigned cased scalars (for example U+A7CB).
    if name
        .chars()
        .any(|c| !crate::python_text::printable(c) && (c.is_uppercase() || c.is_lowercase()))
    {
        return Err(Error::Compatibility);
    }
    let mut host = Zeroizing::new(name.to_lowercase());
    if let Some(zone) = zone {
        host.push('%');
        host.push_str(zone);
    }
    Ok(PrettyUrl {
        host,
        path: Zeroizing::new(path.to_owned()),
    })
}

fn check_brackets(netloc: &str) -> Result<(), Error> {
    if !netloc.contains('[') || !netloc.contains(']') {
        return Err(Error::Parse);
    }
    let info = netloc.rsplit('@').next().unwrap_or("");
    let host = if let Some((before, bracketed)) = info.split_once('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or(Error::Parse)?;
        if !before.is_empty() || (!suffix.is_empty() && !suffix.starts_with(':')) {
            return Err(Error::Parse);
        }
        host
    } else {
        info.split(':').next().unwrap_or("")
    };
    if let Some(future) = host.strip_prefix('v') {
        let (version, address) = future.split_once('.').ok_or(Error::Parse)?;
        if version.is_empty()
            || !version.bytes().all(|b| b.is_ascii_hexdigit())
            || address.is_empty()
        {
            return Err(Error::Parse);
        }
    } else {
        let address = if let Some((address, zone)) = host.split_once('%') {
            if zone.is_empty() || zone.contains('%') {
                return Err(Error::Parse);
            }
            address
        } else {
            host
        };
        address.parse::<Ipv6Addr>().map_err(|_| Error::Parse)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn actual_scalar_source_projection_and_shared_authority() {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("../../tests/traffic_url_source.json")).unwrap();
        for row in rows {
            let input = &row["input"];
            let selected = row["selected_header"].as_str();
            if let Some(raw) = selected.filter(|s| !s.is_empty()) {
                let (host, port) = super::super::flow_recording::pretty_authority(raw);
                assert_eq!(
                    serde_json::json!([host, port]),
                    row["parsed_authority"],
                    "authority {}",
                    row["name"]
                );
            }
            let result = project(Input {
                scheme: input["scheme"].as_str().unwrap(),
                host: input["host"].as_str().unwrap(),
                port: input["port"].as_u64().unwrap() as u16,
                path: input["path"].as_str().unwrap(),
                host_header: input["host_header"].as_str(),
                authority: input["authority"].as_str(),
                http2: input["http2"].as_bool().unwrap(),
            });
            if row["native_gap"] == "Compatibility" {
                assert!(
                    matches!(result, Err(Error::Compatibility)),
                    "{}",
                    row["name"]
                );
            } else if row["error"] == "Parse" {
                assert!(matches!(result, Err(Error::Parse)), "{}", row["name"]);
            } else {
                let result = result.unwrap_or_else(|e| panic!("{}: {e}", row["name"]));
                assert_eq!(
                    serde_json::json!({"host": &*result.host, "path": &*result.path}),
                    row["result"],
                    "{}",
                    row["name"]
                );
            }
        }
    }

    #[test]
    fn live_source_oracle() {
        let Some(python) = std::env::var_os("SAFEYOLO_PYTHON") else {
            return;
        };
        let status = std::process::Command::new(python)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/traffic_url_oracle.py"
            ))
            .arg("--check")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
