//! Metadata from the bytes read immediately below the origin TLS handshake.
//! This observer never changes traffic or retains extension payloads.

use super::*;

// The largest ServerHello has a u16 extension vector and 72 fixed bytes.
const HELLO_LIMIT: usize = 4 + 72 + u16::MAX as usize;
const RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerHello {
    pub legacy_version: u16,
    pub supported_version: Option<u16>,
    pub alpn: Option<String>,
    pub cipher_suite: u16,
    pub extension_types: Vec<u16>,
    pub extension_count: usize,
    pub truncated: bool,
    pub ja3s: String,
    pub ja4s: String,
}

impl ServerHello {
    fn valid(&self) -> bool {
        hex_hash(&self.ja3s, 32)
            && self.alpn.as_ref().is_none_or(|s| s.len() <= 255 * 4)
            && self.ja4s.is_ascii()
            && self.ja4s.len() == 25
            && self.ja4s.starts_with(&format!(
                "t{}{:02}",
                version_code(self.supported_version.unwrap_or(self.legacy_version)),
                self.extension_count.min(99)
            ))
            && self.ja4s.as_bytes()[7] == b'_'
            && self.ja4s[8..12] == format!("{:04x}", self.cipher_suite)
            && self.ja4s.as_bytes()[12] == b'_'
            && hex_hash(&self.ja4s[13..], 12)
            && self.extension_types.len() == self.extension_count.min(LIST_LIMIT)
            && self.extension_count <= u16::MAX as usize / 4
            && self.truncated == (self.extension_count > LIST_LIMIT)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    #[default]
    Incomplete,
    Complete,
    Invalid,
    Unavailable,
    LimitExceeded,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerHelloObservation {
    status: Status,
    hello: Option<ServerHello>,
    hello_retry_request: Option<ServerHello>,
}

impl ServerHelloObservation {
    pub(crate) fn valid(&self) -> bool {
        (self.status == Status::Complete) == self.hello.is_some()
            && self.hello.as_ref().is_none_or(ServerHello::valid)
            && self
                .hello_retry_request
                .as_ref()
                .is_none_or(ServerHello::valid)
    }
}

/// JA4S follows FoxIO's ordered server-extension algorithm. JA4S is subject to
/// FoxIO License 1.1, not SafeYolo's MIT license. See
/// proxy/licenses/ja4s-FoxIO-1.1.txt and proxy/licenses/ja4s-NOTICE.txt.
/// No upstream implementation source is copied.
fn ja4s(version: u16, cipher: u16, extensions: &[u16], alpn: Option<&[u8]>) -> String {
    // FoxIO's JA4S Rust/Python implementations use the first/last ASCII
    // characters and replace non-ASCII endpoints with '9'. This differs from
    // the JA4 client algorithm's hexadecimal fallback.
    let alpn = alpn.filter(|bytes| !bytes.is_empty()).map_or_else(
        || "00".to_owned(),
        |bytes| {
            [bytes[0], bytes[bytes.len() - 1]]
                .into_iter()
                .map(|b| if b.is_ascii() { b as char } else { '9' })
                .collect::<String>()
        },
    );
    format!(
        "t{}{:02}{alpn}_{cipher:04x}_{}",
        version_code(version),
        extensions.len().min(99),
        short_hash(extensions, &[])
    )
}

/// JA3S is MD5 over decimal version,cipher,ordered-extension-types. Unlike
/// JA3's client list helper, Salesforce's JA3S implementation retains all types.
/// No implementation source is copied from Salesforce.
fn parse(body: &[u8]) -> Option<(ServerHello, bool)> {
    let mut input = Reader(body);
    let legacy_version = input.word()?;
    let retry = input.take(32)? == RETRY_RANDOM;
    if input.vector8()?.len() > 32 {
        return None;
    }
    let cipher_suite = input.word()?;
    input.byte()?; // compression method is not part of JA3S
    let mut extensions = Vec::new();
    let mut supported_version = None;
    let mut alpn = None;
    let mut seen = [0_u64; 1024];
    if !input.0.is_empty() {
        let mut ext = Reader(input.vector16()?);
        while !ext.0.is_empty() {
            let kind = ext.word()?;
            let bytes = ext.vector16()?;
            match kind {
                43 => {
                    let mut value = Reader(bytes);
                    supported_version = Some(value.word()?);
                    if !value.0.is_empty() {
                        return None;
                    }
                }
                16 => {
                    let mut value = Reader(bytes);
                    let mut protocols = Reader(value.vector16()?);
                    let selected = protocols.vector8()?;
                    if selected.is_empty() || !protocols.0.is_empty() || !value.0.is_empty() {
                        return None;
                    }
                    alpn = Some(selected);
                }
                _ => {}
            }
            let (word, bit) = (kind as usize / 64, 1_u64 << (kind % 64));
            if seen[word] & bit != 0 {
                return None;
            }
            seen[word] |= bit;
            extensions.push(kind);
        }
    }
    if !input.0.is_empty() {
        return None;
    }
    let extension_text = extensions
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-");
    let text = format!("{legacy_version},{cipher_suite},{extension_text}");
    Some((
        ServerHello {
            legacy_version,
            supported_version,
            alpn: alpn.map(alpn_display),
            cipher_suite,
            ja4s: ja4s(
                supported_version.unwrap_or(legacy_version),
                cipher_suite,
                &extensions,
                alpn,
            ),
            extension_count: extensions.len(),
            truncated: extensions.len() > LIST_LIMIT,
            extension_types: extensions.into_iter().take(LIST_LIMIT).collect(),
            ja3s: md5::hex(text.as_bytes()),
        },
        retry,
    ))
}

#[derive(Default)]
struct Capture {
    header: Vec<u8>,
    remaining: usize,
    record_type: u8,
    hello: Vec<u8>,
    observation: ServerHelloObservation,
}

impl Capture {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.observation.status == Status::Incomplete {
            if self.remaining == 0 {
                let count = (5 - self.header.len()).min(bytes.len());
                self.header.extend_from_slice(&bytes[..count]);
                bytes = &bytes[count..];
                if self.header.len() < 5 {
                    break;
                }
                self.record_type = self.header[0];
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                self.header.clear();
                if self.record_type == 20
                    && self.remaining == 1
                    && self.hello.is_empty()
                    && self.observation.hello_retry_request.is_some()
                {
                    // TLS 1.3's compatibility ChangeCipherSpec can separate the
                    // retry from the final ServerHello. It is not a handshake.
                } else if self.record_type != 22 {
                    self.observation.status = Status::Unavailable;
                    break;
                }
                if self.remaining > 16384 {
                    self.observation.status = Status::Invalid;
                    break;
                }
                if self.remaining == 0 {
                    continue;
                }
            }
            if self.record_type == 20 {
                if bytes.is_empty() {
                    break;
                }
                if bytes[0] != 1 {
                    self.observation.status = Status::Invalid;
                    break;
                }
                bytes = &bytes[1..];
                self.remaining = 0;
                continue;
            }
            let target = if self.hello.len() < 4 {
                4
            } else {
                4 + ((self.hello[1] as usize) << 16
                    | (self.hello[2] as usize) << 8
                    | self.hello[3] as usize)
            };
            let count = self
                .remaining
                .min(bytes.len())
                .min(target - self.hello.len());
            self.hello.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            self.remaining -= count;
            if self.hello.first().is_some_and(|b| *b != 2) {
                self.observation.status = Status::Invalid;
            } else if self.hello.len() == 4 {
                let length = (self.hello[1] as usize) << 16
                    | (self.hello[2] as usize) << 8
                    | self.hello[3] as usize;
                if length == 0 {
                    self.observation.status = Status::Invalid;
                } else if length + 4 > HELLO_LIMIT {
                    self.observation.status = Status::LimitExceeded;
                }
            }
            if target > 4 && self.hello.len() == target {
                match parse(&self.hello[4..]) {
                    Some((hello, false)) => {
                        self.observation.hello = Some(hello);
                        self.observation.status = Status::Complete;
                    }
                    Some((hello, true)) if self.observation.hello_retry_request.is_none() => {
                        self.observation.hello_retry_request = Some(hello);
                        self.hello.clear();
                    }
                    _ => self.observation.status = Status::Invalid,
                }
            }
        }
    }
}

struct ObservedServer {
    stream: BoxStream,
    connection: Connection,
    capture: Option<Capture>,
}

pub(crate) fn observe_server(stream: BoxStream, connection: Option<Connection>) -> BoxStream {
    match connection {
        Some(connection) => Box::new(ObservedServer {
            stream,
            connection,
            capture: Some(Capture::default()),
        }),
        None => stream,
    }
}

impl ObservedServer {
    fn finish(&mut self) {
        if let Some(capture) = self.capture.take() {
            self.connection.server_hello(capture.observation);
        }
    }
}

impl Drop for ObservedServer {
    fn drop(&mut self) {
        self.finish();
    }
}

impl AsyncRead for ObservedServer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = buffer.filled().len();
        let can_read = buffer.remaining() > 0;
        let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
        if let Some(capture) = &mut self.capture {
            capture.feed(&buffer.filled()[start..]);
            if capture.observation.status != Status::Incomplete
                || matches!(result, Poll::Ready(Err(_)))
                || can_read && result.is_ready() && buffer.filled().len() == start
            {
                self.finish();
            }
        }
        result
    }
}

impl AsyncWrite for ObservedServer {
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
pub(super) mod tests;
