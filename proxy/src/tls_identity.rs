//! Connection-scoped TLS observations. Wire bytes are transient and never
//! serialized. Fingerprints describe client behavior, not executable identity.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{connection_events::Connection, tunnels::BoxStream};

mod md5;

const LIST_LIMIT: usize = 64;
const ALPN_LIMIT: usize = 16;
const NAME_LIMIT: usize = 253;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientHello {
    pub ja3: String,
    pub ja4: String,
    pub sni: Option<String>,
    pub alpn_offers: Vec<String>,
    pub legacy_version: u16,
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub cipher_suite_count: usize,
    pub extension_types: Vec<u16>,
    pub extension_count: usize,
    pub truncated: bool,
}

impl ClientHello {
    pub(crate) fn valid(&self) -> bool {
        hex_hash(&self.ja3, 32)
            && self.ja4.len() == 36
            && self
                .ja4
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && self.sni.as_ref().is_none_or(|s| s.len() <= NAME_LIMIT)
            && self.alpn_offers.len() <= ALPN_LIMIT
            && self.alpn_offers.iter().all(|s| s.len() <= 256)
            && self.supported_versions.len() <= LIST_LIMIT
            && self.cipher_suites.len() <= LIST_LIMIT
            && self.extension_types.len() <= LIST_LIMIT
            && self.cipher_suite_count >= self.cipher_suites.len()
            && self.extension_count >= self.extension_types.len()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsSession {
    pub peer: String,
    pub sni: Option<String>,
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub handshake_kind: Option<String>,
    pub leaf_certificate: Option<Certificate>,
}

impl TlsSession {
    pub(crate) fn observed(peer: &str, name: &str, session: &rustls::ClientConnection) -> Self {
        Self {
            peer: peer.into(),
            // Match rustls's SNI encoding, including RFC 6066's removal of
            // the DNS root dot. The verification target retains its spelling.
            sni: match rustls::pki_types::ServerName::try_from(name).ok() {
                Some(rustls::pki_types::ServerName::DnsName(name)) => {
                    Some(name.as_ref().trim_end_matches('.').to_owned())
                }
                _ => None,
            },
            version: session.protocol_version().map(|v| format!("{v:?}")),
            cipher: session
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite())),
            alpn: session.alpn_protocol().map(alpn_display),
            handshake_kind: session.handshake_kind().map(|kind| format!("{kind:?}")),
            leaf_certificate: certificate(session.peer_certificates().unwrap_or_default()),
        }
    }

    pub(crate) fn valid(&self) -> bool {
        matches!(self.peer.as_str(), "parent" | "origin")
            && self.sni.as_ref().is_none_or(|s| s.len() <= NAME_LIMIT)
            && [
                &self.version,
                &self.cipher,
                &self.alpn,
                &self.handshake_kind,
            ]
            .into_iter()
            .all(|s| s.as_ref().is_none_or(|s| s.len() <= 1024))
            && self
                .leaf_certificate
                .as_ref()
                .is_none_or(Certificate::valid)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub cert_sha256: String,
    pub spki_sha256: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_bits: Option<usize>,
    pub san: Vec<String>,
    pub san_count: usize,
    pub truncated: bool,
}

impl Certificate {
    fn valid(&self) -> bool {
        hex_hash(&self.cert_sha256, 64)
            && self.spki_sha256.as_ref().is_none_or(|s| hex_hash(s, 64))
            && [
                &self.subject,
                &self.issuer,
                &self.serial,
                &self.not_before,
                &self.not_after,
                &self.key_algorithm,
            ]
            .into_iter()
            .all(|s| s.as_ref().is_none_or(|s| s.len() <= 512))
            && self.san.len() <= ALPN_LIMIT
            && self.san_count >= self.san.len()
            && self.san.iter().all(|s| s.len() <= NAME_LIMIT)
    }
}

fn hex_hash(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn bounded(s: &str, limit: usize, truncated: &mut bool) -> String {
    let mut end = s.len().min(limit);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    *truncated |= end < s.len();
    s[..end].into()
}

pub(crate) fn certificate(chain: &[rustls::pki_types::CertificateDer<'_>]) -> Option<Certificate> {
    let der = chain.first()?;
    let mut identity = Certificate {
        cert_sha256: sha256(der),
        spki_sha256: None,
        subject: None,
        issuer: None,
        serial: None,
        not_before: None,
        not_after: None,
        key_algorithm: None,
        key_bits: None,
        san: Vec::new(),
        san_count: 0,
        truncated: false,
    };
    let Ok(([], parsed)) = x509_parser::parse_x509_certificate(der) else {
        return Some(identity);
    };
    let spki = parsed.public_key();
    identity.spki_sha256 = Some(sha256(spki.raw));
    identity.subject = Some(bounded(
        &parsed.subject().to_string(),
        512,
        &mut identity.truncated,
    ));
    identity.issuer = Some(bounded(
        &parsed.issuer().to_string(),
        512,
        &mut identity.truncated,
    ));
    identity.serial = Some(bounded(
        &parsed.raw_serial_as_string(),
        512,
        &mut identity.truncated,
    ));
    identity.not_before = parsed
        .validity()
        .not_before
        .to_datetime()
        .format(&time::format_description::well_known::Rfc3339)
        .ok();
    identity.not_after = parsed
        .validity()
        .not_after
        .to_datetime()
        .format(&time::format_description::well_known::Rfc3339)
        .ok();
    identity.key_algorithm = Some(spki.algorithm.algorithm.to_id_string());
    // Unknown algorithms have an OID but no invented key size.
    identity.key_bits = spki
        .parsed()
        .ok()
        .map(|key| key.key_size())
        .filter(|bits| *bits > 0);
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        identity.san_count = san.value.general_names.len();
        for name in &san.value.general_names {
            let value = match name {
                x509_parser::extensions::GeneralName::DNSName(s) => Some((*s).to_owned()),
                x509_parser::extensions::GeneralName::IPAddress(bytes) => match bytes.len() {
                    4 => Some(
                        std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string(),
                    ),
                    16 => Some(
                        std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string(),
                    ),
                    _ => None,
                },
                _ => None,
            };
            if let Some(value) = value {
                if identity.san.len() < ALPN_LIMIT {
                    identity
                        .san
                        .push(bounded(&value, NAME_LIMIT, &mut identity.truncated));
                } else {
                    identity.truncated = true;
                }
            }
        }
    }
    Some(identity)
}

fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value.to_be_bytes()[0] == value.to_be_bytes()[1]
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(value)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn word(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let len = self.byte()? as usize;
        self.take(len)
    }
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let len = self.word()? as usize;
        self.take(len)
    }
}
fn words(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .chunks_exact(2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .collect(),
    )
}
fn word_vector(bytes: &[u8]) -> Option<Vec<u16>> {
    let mut input = Reader(bytes);
    let values = words(input.vector16()?)?;
    input.0.is_empty().then_some(values)
}
fn decimal_list(values: impl Iterator<Item = u16>) -> String {
    values
        .filter(|v| !grease(*v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}
fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}
fn short_hash(values: &[u16], suffix: &[u16]) -> String {
    if values.is_empty() {
        return "000000000000".into();
    }
    let mut text = hex_list(values);
    if !suffix.is_empty() {
        text.push('_');
        text.push_str(&hex_list(suffix));
    }
    sha256(text.as_bytes())[..12].into()
}
fn alpn_code(value: &[u8]) -> String {
    let (Some(first), Some(last)) = (value.first(), value.last()) else {
        return "00".into();
    };
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", *first as char, *last as char)
    } else {
        format!("{:x}{:x}", first >> 4, last & 15)
    }
}
fn alpn_display(value: &[u8]) -> String {
    value
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() && *b != b'\\' {
                (*b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

/// Parse the ClientHello body, not the TLS record version or negotiated session.
fn client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut input = Reader(body);
    let legacy_version = input.word()?;
    input.take(32)?;
    input.vector8()?;
    let ciphers = words(input.vector16()?)?;
    input.vector8()?;
    let mut extensions = Vec::new();
    let mut seen_extensions = [0_u64; 1024];
    let mut groups = Vec::new();
    let mut points = Vec::new();
    let mut signatures = Vec::new();
    let mut versions = Vec::new();
    let mut sni = None;
    let mut alpn = Vec::new();
    if !input.0.is_empty() {
        let mut ext = Reader(input.vector16()?);
        while !ext.0.is_empty() {
            let kind = ext.word()?;
            let bytes = ext.vector16()?;
            // Duplicate types are malformed; do not invent fingerprint semantics.
            let (word, bit) = (kind as usize / 64, 1_u64 << (kind % 64));
            if seen_extensions[word] & bit != 0 {
                return None;
            }
            seen_extensions[word] |= bit;
            extensions.push(kind);
            let mut value = Reader(bytes);
            match kind {
                0 => {
                    let mut names = Reader(value.vector16()?);
                    if !value.0.is_empty() {
                        return None;
                    }
                    while !names.0.is_empty() {
                        let kind = names.byte()?;
                        let name = names.vector16()?;
                        if kind == 0 && sni.is_none() {
                            sni = Some(std::str::from_utf8(name).ok()?.to_owned());
                        }
                    }
                }
                10 => groups = word_vector(bytes)?,
                11 => {
                    points = value.vector8()?.to_vec();
                    if !value.0.is_empty() {
                        return None;
                    }
                }
                13 => signatures = word_vector(bytes)?,
                16 => {
                    let mut offers = Reader(value.vector16()?);
                    if !value.0.is_empty() {
                        return None;
                    }
                    while !offers.0.is_empty() {
                        alpn.push(offers.vector8()?.to_vec());
                    }
                }
                43 => {
                    versions = words(value.vector8()?)?;
                    if !value.0.is_empty() {
                        return None;
                    }
                }
                _ => {}
            }
        }
    }
    if !input.0.is_empty() {
        return None;
    }
    let ja3_text = format!(
        "{legacy_version},{},{},{},{}",
        decimal_list(ciphers.iter().copied()),
        decimal_list(extensions.iter().copied()),
        decimal_list(groups.into_iter()),
        points
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    );
    let version = if extensions.contains(&43) {
        versions
            .iter()
            .copied()
            .filter(|v| !grease(*v))
            .max()
            .unwrap_or(0)
    } else {
        legacy_version
    };
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let mut sorted_ciphers: Vec<_> = ciphers.iter().copied().filter(|v| !grease(*v)).collect();
    sorted_ciphers.sort_unstable();
    let ext_count = extensions.iter().filter(|v| !grease(**v)).count();
    let mut sorted_extensions: Vec<_> = extensions
        .iter()
        .copied()
        .filter(|v| !grease(*v) && !matches!(*v, 0 | 16))
        .collect();
    sorted_extensions.sort_unstable();
    signatures.retain(|v| !grease(*v));
    let ja4 = format!(
        "t{version}{}{:02}{:02}{}_{}_{}",
        if extensions.contains(&0) { 'd' } else { 'i' },
        sorted_ciphers.len().min(99),
        ext_count.min(99),
        alpn_code(alpn.first().map(Vec::as_slice).unwrap_or_default()),
        short_hash(&sorted_ciphers, &[]),
        short_hash(&sorted_extensions, &signatures)
    );
    let mut truncated = ciphers.len() > LIST_LIMIT
        || extensions.len() > LIST_LIMIT
        || versions.len() > LIST_LIMIT
        || alpn.len() > ALPN_LIMIT;
    Some(ClientHello {
        ja3: md5::hex(ja3_text.as_bytes()),
        ja4,
        sni: sni.map(|name| bounded(&name, NAME_LIMIT, &mut truncated)),
        alpn_offers: alpn
            .iter()
            .take(ALPN_LIMIT)
            .map(|offer| bounded(&alpn_display(offer), 256, &mut truncated))
            .collect(),
        legacy_version,
        supported_versions: versions.into_iter().take(LIST_LIMIT).collect(),
        cipher_suite_count: ciphers.len(),
        cipher_suites: ciphers.into_iter().take(LIST_LIMIT).collect(),
        extension_count: extensions.len(),
        extension_types: extensions.into_iter().take(LIST_LIMIT).collect(),
        truncated,
    })
}

/// Reassemble the first handshake across TLS records and arbitrary read splits.
/// The maximum covers the ClientHello's two u16 vectors and fixed fields. The
/// observer never rejects traffic, including when observation is unavailable.
#[derive(Default)]
struct Capture {
    header: Vec<u8>,
    remaining: usize,
    hello: Vec<u8>,
    done: bool,
}
impl Capture {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && !self.done {
            if self.remaining == 0 {
                let count = (5 - self.header.len()).min(bytes.len());
                self.header.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if self.header[0] != 22 {
                    self.done = true;
                    break;
                }
                if self.header.len() < 5 {
                    break;
                }
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                self.header.clear();
                if self.remaining == 0 {
                    continue;
                }
            }
            let target = if self.hello.len() < 4 {
                4
            } else {
                4 + ((self.hello[1] as usize) << 16
                    | (self.hello[2] as usize) << 8
                    | self.hello[3] as usize)
            };
            if target > 132 * 1024
                || (self.hello.len() >= 4 && target <= 4)
                || self.hello.first().is_some_and(|b| *b != 1)
            {
                self.done = true;
                break;
            }
            let count = self
                .remaining
                .min(bytes.len())
                .min(target - self.hello.len());
            self.hello.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            self.remaining -= count;
            if self.hello.len() >= 4 && target > 4 && self.hello.len() == target {
                self.done = true;
            }
        }
    }
    fn parsed(&self) -> Option<ClientHello> {
        if !self.done || self.hello.len() < 4 || self.hello[0] != 1 {
            return None;
        }
        let length =
            (self.hello[1] as usize) << 16 | (self.hello[2] as usize) << 8 | self.hello[3] as usize;
        (length == self.hello.len() - 4)
            .then(|| client_hello(&self.hello[4..]))
            .flatten()
    }
}

struct ObservedClient {
    stream: BoxStream,
    connection: Connection,
    upstream: Option<Connection>,
    capture: Option<Capture>,
}

pub(crate) fn observe_client(
    stream: BoxStream,
    connection: Option<Connection>,
    upstream: Option<Connection>,
) -> BoxStream {
    match connection {
        Some(connection) => Box::new(ObservedClient {
            stream,
            connection,
            upstream,
            capture: Some(Capture::default()),
        }),
        None => stream,
    }
}
impl AsyncRead for ObservedClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
        if let Some(capture) = &mut self.capture {
            capture.feed(&buffer.filled()[start..]);
            if capture.done {
                let hello = capture.parsed();
                let upstream = self.upstream.take();
                if let Some(hello) = hello {
                    self.connection.client_hello(hello);
                    if let Some(upstream) = upstream {
                        upstream.observe_client_destination();
                    }
                }
                self.capture = None;
            }
        }
        result
    }
}
impl AsyncWrite for ObservedClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
