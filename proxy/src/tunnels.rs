//! CONNECT protocol selection and bounded duplex relay.
//!
//! Selection happens once, before HTTP/TLS parsing. Incomplete prefixes remain
//! undecided; neither a timer nor a parser failure grants opaque forwarding.

use std::{
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::watch,
    time::Instant,
};

use crate::Error;

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub(crate) type BoxStream = Box<dyn Stream>;

/// The production CLI already applies normalize_ignore_hosts before launch.
/// This boundary accepts its canonical ASCII host or host:port output.
#[derive(Clone)]
pub(crate) struct Passthrough {
    hosts: Vec<(String, Option<u16>)>,
    networks: Vec<(u32, u32)>,
}

impl Passthrough {
    pub(crate) fn normalize_hosts(values: &[String]) -> Result<Vec<String>, Error> {
        let mut normalized = Vec::with_capacity(values.len());
        for value in values {
            let (host, port) = Self::parse_host(value)?;
            let value = port.map_or(host.clone(), |port| format!("{host}:{port}"));
            if !normalized.iter().any(|entry| entry == &value) {
                normalized.push(value);
            }
        }
        Ok(normalized)
    }

    fn parse_host(value: &str) -> Result<(String, Option<u16>), Error> {
        // Match the existing CLI boundary: surrounding operator whitespace is
        // discarded and Unicode hostnames are stored in their IDNA2003 ASCII
        // form.  The wire authority keeps its own spelling; this value is
        // only the canonical configured matcher key.
        let value = value.trim();
        let (host, port) = if let Some((host, port)) = value.rsplit_once(':') {
            let port = port.parse::<u16>()?;
            if port == 0 {
                return Err("ignore host port must be between 1 and 65535".into());
            }
            (host, Some(port))
        } else {
            (value, None)
        };
        let host = crate::host_names::encode_idna2003(host)
            .map_err(|_| "ignore_hosts requires canonical exact hostname or IPv4 entries")?
            .to_ascii_lowercase();
        if host.len() > 253
            || host.is_empty()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.starts_with(|c: char| c.is_ascii_alphanumeric())
                    || !label.ends_with(|c: char| c.is_ascii_alphanumeric())
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
            || (host.bytes().all(|c| c.is_ascii_digit() || c == b'.')
                && host.parse::<Ipv4Addr>().is_err())
        {
            return Err("ignore_hosts requires canonical exact hostname or IPv4 entries".into());
        }
        Ok((host.to_ascii_lowercase(), port))
    }

    pub(crate) fn new(hosts: &[String], cidrs: &str) -> Result<Self, Error> {
        let mut result = Self {
            hosts: vec![("api.asterfold.ai".into(), Some(7000))],
            networks: Vec::new(),
        };
        for value in Self::normalize_hosts(hosts)? {
            let (host, port) = Self::parse_host(&value)?;
            if !result
                .hosts
                .iter()
                .any(|(entry, entry_port)| entry == &host && *entry_port == port)
            {
                result.hosts.push((host, port));
            }
        }
        for cidr in cidrs
            .split(',')
            .map(|v| v.trim_matches(crate::policy::python_whitespace))
            .filter(|v| !v.is_empty())
        {
            let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
            let address = u32::from(address.parse::<Ipv4Addr>()?);
            let prefix = if prefix.contains('.') {
                let mask = u32::from(prefix.parse::<Ipv4Addr>()?);
                // ipaddress accepts dotted netmasks and hostmasks too.
                let mask = if mask != 0 && mask >> 24 == 0 {
                    !mask
                } else {
                    mask
                };
                let prefix = mask.leading_ones();
                if mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) {
                    return Err("ignore CIDR has a non-contiguous netmask".into());
                }
                prefix
            } else {
                prefix.parse::<u32>()?
            };
            if !(8..=32).contains(&prefix) {
                return Err("ignore CIDRs require an IPv4 prefix between /8 and /32".into());
            }
            let mask = u32::MAX << (32 - prefix);
            let network = (address & mask, mask);
            if !result.networks.contains(&network) {
                result.networks.push(network);
            }
        }
        Ok(result)
    }

    pub(crate) fn pattern_count(&self) -> usize {
        self.hosts.len() + self.networks.len()
    }

    pub(crate) fn matches(&self, host: &str, port: u16, peer: Option<Ipv4Addr>) -> bool {
        // The source logger considers both the logical address and the
        // resolved peer address.  Keep the logical authority as the event
        // identity, but do not lose an exact configured address when DNS
        // resolves a name to that address.  CIDRs retain their existing
        // resolved-peer behavior below.
        let exact_host = |candidate: &str| {
            // Trim operator entries at configuration time only. A wire
            // candidate containing surrounding whitespace is not a canonical
            // authority and must not inherit a configured exemption.
            let normalized = (candidate == candidate.trim())
                .then(|| Self::parse_host(candidate).ok().map(|(host, _)| host))
                .flatten();
            self.hosts.iter().any(|(entry, entry_port)| {
                entry_port.is_none_or(|entry| entry == port)
                    && (entry.eq_ignore_ascii_case(candidate)
                        || normalized.as_deref() == Some(entry.as_str()))
            })
        };
        exact_host(host)
            || peer.is_some_and(|address| exact_host(&address.to_string()))
            || host
                .parse::<Ipv4Addr>()
                .ok()
                .into_iter()
                .chain(peer)
                .any(|address| {
                    let address = u32::from(address);
                    self.networks
                        .iter()
                        .any(|(network, mask)| address & mask == *network)
                })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Protocol {
    Tls,
    Http,
    Opaque,
}

fn protocol(prefix: &[u8]) -> Option<Protocol> {
    let first = *prefix.first()?;
    // Origins may accept leading request-line whitespace as well as empty
    // lines. Keep all evidenced spellings on the HTTP parser's path even when
    // Hyper rejects them; rejection never grants uninspected forwarding.
    if method_separator(first) {
        return Some(Protocol::Http);
    }
    if first == 0x16 {
        if prefix.len() < 3 {
            return None;
        }
        // A TLS handshake content type stays on the inspected path even when
        // its record version is invalid. The TLS terminator owns that failure;
        // malformed handshake bytes must not gain opaque forwarding.
        return Some(Protocol::Tls);
    }
    // An HTTP method is a token, including extension methods. Wait for its
    // delimiter instead of treating an incomplete method as opaque bytes.
    for (index, byte) in prefix.iter().enumerate() {
        if method_separator(*byte) && index > 0 {
            // SSH is also a valid HTTP method prefix. A complete identification
            // line with a comment can share an HTTP method's first token, so
            // keep it undecided until the line distinguishes the two. HTTP
            // request-line syntax always takes precedence over a banner.
            let mut identification = prefix[..index].splitn(3, |byte| *byte == b'-');
            if identification.next() == Some(b"SSH")
                && identification.next().is_some_and(|version| {
                    version.contains(&b'.')
                        && version
                            .iter()
                            .all(|byte| byte.is_ascii_digit() || *byte == b'.')
                })
                && identification
                    .next()
                    .is_some_and(|software| !software.is_empty())
            {
                let end = prefix.iter().position(|byte| *byte == b'\n')?;
                let line = prefix[..end].strip_suffix(b"\r").unwrap_or(&prefix[..end]);
                let version = line
                    .rsplit(|byte| method_separator(*byte))
                    .find(|part| !part.is_empty());
                return Some(
                    if version.is_some_and(|value| value.starts_with(b"HTTP/")) {
                        Protocol::Http
                    } else {
                        Protocol::Opaque
                    },
                );
            }
            return Some(Protocol::Http);
        }
        if !byte.is_ascii_alphanumeric() && !b"!#$%&'*+-.^_`|~".contains(byte) {
            return Some(Protocol::Opaque);
        }
    }
    None
}

// HTTP origins may split the request line on more than SP: Python's HTTP
// server, for example, decodes Latin-1 and uses str.split(). Keep these
// spellings on the HTTP parser's path, even when Hyper rejects them. A parser
// rejection must never confer the admitted tunnel's opaque permission.
fn method_separator(byte: u8) -> bool {
    matches!(byte, 0x09..=0x0d | 0x1c..=0x20 | 0x85 | 0xa0)
}

pub(crate) struct Prefixed {
    stream: BoxStream,
    prefix: Vec<u8>,
    offset: usize,
}

/// Classification preserves the buffered bytes and the SNI observed in a
/// complete ClientHello. The caller still receives prefixed streams, so no
/// handshake bytes are consumed by the matcher.
pub(crate) struct Classification {
    pub(crate) protocol: Protocol,
    pub(crate) client: BoxStream,
    pub(crate) server: BoxStream,
    pub(crate) tls_server_name: Option<String>,
}
impl Prefixed {
    pub(crate) fn new(stream: BoxStream, prefix: Vec<u8>) -> Self {
        Self {
            stream,
            prefix,
            offset: 0,
        }
    }
}
impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = buf.remaining().min(self.prefix.len() - self.offset);
            buf.put_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Matches Hyper's current HTTP/1 header buffer limit. Once a possible method
/// reaches that bound, its HTTP parser owns the rejection; never select raw.
const PREFIX_LIMIT: usize = 8192 + 4096 * 100;
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

pub(crate) async fn classify(
    mut client: BoxStream,
    mut server: BoxStream,
    stop: &mut watch::Receiver<bool>,
) -> Result<Classification, Error> {
    let mut prefix = Vec::new();
    let mut client_bytes = [0; 8192];
    let mut server_bytes = [0; 8192];
    let mut server_prefix = Vec::new();
    let mut last_activity = Instant::now();
    loop {
        if let Some(protocol) =
            protocol(&prefix).or_else(|| (prefix.len() >= PREFIX_LIMIT).then_some(Protocol::Http))
        {
            let tls_name = if protocol == Protocol::Tls {
                Some(client_hello_server_name(&prefix))
            } else {
                None
            };
            let tls_incomplete = matches!(tls_name.as_ref(), Some(&ClientHelloName::Incomplete))
                && prefix.len() < PREFIX_LIMIT;
            if !tls_incomplete {
                let tls_server_name = match tls_name {
                    Some(ClientHelloName::Incomplete | ClientHelloName::Complete(None)) | None => {
                        None
                    }
                    Some(ClientHelloName::Complete(name)) => name,
                };
                return Ok(Classification {
                    protocol,
                    client: Box::new(Prefixed::new(client, prefix)),
                    server: Box::new(Prefixed::new(server, server_prefix)),
                    tls_server_name,
                });
            }
        }
        if !server_prefix.is_empty() && prefix.is_empty() {
            return Ok(Classification {
                protocol: Protocol::Opaque,
                client,
                server: Box::new(Prefixed::new(server, server_prefix)),
                tls_server_name: None,
            });
        }
        if *stop.borrow() {
            return Err("proxy shutdown during CONNECT classification".into());
        }
        let room = client_bytes.len().min(PREFIX_LIMIT - prefix.len());
        tokio::select! {
            biased;
            _ = stop.changed() => return Err("proxy shutdown during CONNECT classification".into()),
            _ = tokio::time::sleep_until(last_activity + IDLE_TIMEOUT) => return Err("CONNECT classification idle timeout".into()),
            read = client.read(&mut client_bytes[..room]) => {
                let count = read?;
                if count == 0 {
                    return Err("client closed before CONNECT protocol selection".into());
                }
                prefix.extend_from_slice(&client_bytes[..count]);
                last_activity = Instant::now();
            }
            read = server.read(&mut server_bytes), if server_prefix.is_empty() => {
                let count = read?;
                if count == 0 {
                    return Err("destination closed before CONNECT protocol selection".into());
                }
                server_prefix.extend_from_slice(&server_bytes[..count]);
                last_activity = Instant::now();
            }
        }
    }
}

enum ClientHelloName {
    Incomplete,
    Complete(Option<String>),
}

/// Read a DNS SNI from a buffered ClientHello without terminating TLS.
/// Malformed or non-ClientHello records stay on the normal inspected path.
fn client_hello_server_name(prefix: &[u8]) -> ClientHelloName {
    let mut offset = 0;
    let mut handshake = Vec::new();
    while offset + 5 <= prefix.len() {
        let content_type = prefix[offset];
        let length = u16::from_be_bytes([prefix[offset + 3], prefix[offset + 4]]) as usize;
        let end = offset + 5 + length;
        if end > prefix.len() {
            return ClientHelloName::Incomplete;
        }
        if content_type != 22 {
            return ClientHelloName::Complete(None);
        }
        handshake.extend_from_slice(&prefix[offset + 5..end]);
        offset = end;
        if handshake.len() < 4 {
            continue;
        }
        let message_length = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        if handshake.len() < 4 + message_length {
            continue;
        }
        if handshake[0] != 1 {
            return ClientHelloName::Complete(None);
        }
        let body = &handshake[4..4 + message_length];
        if body.len() < 34 {
            return ClientHelloName::Complete(None);
        }
        let mut cursor = 34;
        let session_length = body[cursor] as usize;
        cursor = cursor.saturating_add(1 + session_length);
        if cursor + 2 > body.len() {
            return ClientHelloName::Complete(None);
        }
        let cipher_length = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
        cursor = cursor.saturating_add(2 + cipher_length);
        if cursor >= body.len() {
            return ClientHelloName::Complete(None);
        }
        let compression_length = body[cursor] as usize;
        cursor = cursor.saturating_add(1 + compression_length);
        if cursor + 2 > body.len() {
            return ClientHelloName::Complete(None);
        }
        let extensions_length = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
        cursor += 2;
        let extensions_end = cursor.saturating_add(extensions_length);
        if extensions_end > body.len() {
            return ClientHelloName::Complete(None);
        }
        while cursor + 4 <= extensions_end {
            let extension_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            let extension_length =
                u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]) as usize;
            cursor += 4;
            let extension_end = cursor.saturating_add(extension_length);
            if extension_end > extensions_end {
                return ClientHelloName::Complete(None);
            }
            if extension_type == 0 {
                let extension = &body[cursor..extension_end];
                if extension.len() < 5 {
                    return ClientHelloName::Complete(None);
                }
                let list_length = u16::from_be_bytes([extension[0], extension[1]]) as usize;
                if list_length + 2 > extension.len() || extension[2] != 0 {
                    return ClientHelloName::Complete(None);
                }
                let name_length = u16::from_be_bytes([extension[3], extension[4]]) as usize;
                if 5 + name_length > extension.len() {
                    return ClientHelloName::Complete(None);
                }
                let name = &extension[5..5 + name_length];
                return ClientHelloName::Complete(
                    std::str::from_utf8(name).ok().map(str::to_owned),
                );
            }
            cursor = extension_end;
        }
        return ClientHelloName::Complete(None);
    }
    ClientHelloName::Incomplete
}

pub(crate) struct RelayResult {
    pub uploaded: u64,
    pub downloaded: u64,
    pub outcome: &'static str,
}

pub(crate) async fn relay(
    mut client: BoxStream,
    mut server: BoxStream,
    mut stop: watch::Receiver<bool>,
) -> RelayResult {
    let uploaded = AtomicU64::new(0);
    let downloaded = AtomicU64::new(0);
    let activity = std::sync::Mutex::new(Instant::now());
    let (client_read, client_write) = tokio::io::split(&mut client);
    let (server_read, server_write) = tokio::io::split(&mut server);
    let transfers = async {
        tokio::try_join!(
            copy_half(client_read, server_write, &uploaded, &activity),
            copy_half(server_read, client_write, &downloaded, &activity),
        )
    };
    let idle = async {
        loop {
            let deadline = *activity.lock().unwrap() + IDLE_TIMEOUT;
            tokio::time::sleep_until(deadline).await;
            if activity.lock().unwrap().elapsed() >= IDLE_TIMEOUT {
                return;
            }
        }
    };
    let outcome = if *stop.borrow() {
        "shutdown"
    } else {
        tokio::select! {
            result = transfers => if result.is_ok() { "completed" } else { "error" },
            _ = stop.changed() => "shutdown",
            _ = idle => "idle_timeout",
        }
    };
    RelayResult {
        uploaded: uploaded.load(Ordering::Relaxed),
        downloaded: downloaded.load(Ordering::Relaxed),
        outcome,
    }
}

async fn copy_half(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    count: &AtomicU64,
    activity: &std::sync::Mutex<Instant>,
) -> io::Result<()> {
    let mut bytes = [0; 8192];
    loop {
        let read = reader.read(&mut bytes).await?;
        if read == 0 {
            return writer.shutdown().await;
        }
        *activity.lock().unwrap() = Instant::now();
        let mut offset = 0;
        while offset < read {
            let written = writer.write(&bytes[offset..read]).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            offset += written;
            count.fetch_add(written as u64, Ordering::Relaxed);
            *activity.lock().unwrap() = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello_with_sni(name: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session ID length
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[1, 0]); // one null compression method

        let mut server_name = Vec::with_capacity(name.len() + 5);
        server_name.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name.extend_from_slice(name);
        let mut extensions = Vec::with_capacity(server_name.len() + 4);
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![
            1,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        handshake.extend_from_slice(&body);
        let mut record = vec![
            22,
            3,
            3,
            (handshake.len() >> 8) as u8,
            handshake.len() as u8,
        ];
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn client_hello_sni_requires_complete_record_and_preserves_name() {
        let hello = client_hello_with_sni(b"SNI.ALIAS.INVALID");
        for split in [0, 1, 4, 20, hello.len() - 1] {
            assert!(matches!(
                client_hello_server_name(&hello[..split]),
                ClientHelloName::Incomplete
            ));
        }
        assert!(matches!(
            client_hello_server_name(&hello),
            ClientHelloName::Complete(Some(name)) if name == "SNI.ALIAS.INVALID"
        ));
    }

    #[test]
    fn fragmented_http_tls_and_extension_methods_never_select_opaque() {
        for bytes in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"PATCH / HTTP/1.1\r\n",
            b"CUSTOM-METHOD / HTTP/1.1\r\n",
            b"SSH / HTTP/1.1\r\n",
            b"SSHGET / HTTP/1.1\r\n",
            b"SSH-EXT / HTTP/1.1\r\n",
            b"SSH-2.0-test / HTTP/1.1\r\n",
            b"\x16\x03\x01\0\xff",
            b"\x16\x03\x04\0\x04\x02\0\0\0",
        ] {
            for end in 0..=bytes.len() {
                assert_ne!(protocol(&bytes[..end]), Some(Protocol::Opaque));
            }
        }
        assert_eq!(protocol(b"SSH-2.0-test\r\n"), Some(Protocol::Opaque));
        let banner = b"SSH-2.0-test identification comment\r\n";
        for end in 0..banner.len() {
            assert_eq!(protocol(&banner[..end]), None);
        }
        assert_eq!(protocol(banner), Some(Protocol::Opaque));
        assert_eq!(protocol(b"\0\xffraw"), Some(Protocol::Opaque));
        assert_eq!(protocol(b"\r\nGET / HTTP/1.1\r\n"), Some(Protocol::Http));
        for separator in [9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 0x85, 0xa0] {
            let leading = [&[separator], b"GET /forbidden HTTP/1.1\r\n".as_slice()].concat();
            for end in 1..=leading.len() {
                assert_eq!(protocol(&leading[..end]), Some(Protocol::Http));
            }
            for method in ["GET", "SSH", "SSH-2.0-test"] {
                let bytes = [
                    method.as_bytes(),
                    &[separator],
                    b"/forbidden",
                    &[separator],
                    b"HTTP/1.1\r\n",
                ]
                .concat();
                for end in 0..=bytes.len() {
                    // LF within an identification line ends the banner. Other
                    // request-line whitespace cannot select opaque transport.
                    if separator != b'\n' || method != "SSH-2.0-test" {
                        assert_ne!(
                            protocol(&bytes[..end]),
                            Some(Protocol::Opaque),
                            "method={method} separator={separator} end={end}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn silence_closes_undecided_and_opaque_connections_without_reclassification() {
        let (mut peer, client) = tokio::io::duplex(1024);
        let (mut origin, server) = tokio::io::duplex(1024);
        let (_stop, mut receiver) = watch::channel(false);
        peer.write_all(b"G").await.unwrap();
        origin.write_all(b"server greeting").await.unwrap();
        let result = classify(Box::new(client), Box::new(server), &mut receiver).await;
        assert!(matches!(result, Err(error) if error.to_string().contains("idle timeout")));
        // Undecided bytes were never forwarded in either direction.
        let mut received = Vec::new();
        origin.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
        let (_peer, client) = tokio::io::duplex(1024);
        let (_origin, server) = tokio::io::duplex(1024);
        let result = relay(Box::new(client), Box::new(server), receiver).await;
        assert_eq!(result.outcome, "idle_timeout");
        assert_eq!((result.uploaded, result.downloaded), (0, 0));
    }

    #[test]
    fn passthrough_is_scoped_and_does_not_become_a_network_grant() {
        let config = Passthrough::new(
            &["EXAMPLE.test:443".into(), "all.test".into()],
            "10.2.9.1/16, 192.168.1.4",
        )
        .unwrap();
        assert!(config.matches("example.test", 443, None));
        assert!(!config.matches("example.test", 8443, None));
        assert!(!config.matches("child.example.test", 443, None));
        assert!(config.matches("all.test", 9876, None));
        assert!(config.matches("api.asterfold.ai", 7000, None));
        assert!(!config.matches("api.asterfold.ai", 443, None));
        assert!(config.matches("10.2.255.255", 443, None));
        assert!(!config.matches("10.3.0.0", 443, None));
        assert!(config.matches("named.test", 443, Some("192.168.1.4".parse().unwrap())));
        for entry in [
            "*.test",
            "example.test.",
            "https://example.test",
            "127.0.0.999",
            "[::1]",
            "example.test:0",
        ] {
            assert!(Passthrough::new(&[entry.into()], "").is_err());
        }
        assert!(Passthrough::new(&[], "10.0.0.0/7").is_err());
    }

    #[test]
    fn passthrough_pattern_count_deduplicates_builtin_and_cidr_entries() {
        let config = Passthrough::new(
            &[
                "API.ASTERFOLD.AI:7000".into(),
                "example.test".into(),
                "EXAMPLE.TEST".into(),
            ],
            "10.2.9.1/16, 10.2.0.0/16",
        )
        .unwrap();
        assert_eq!(config.pattern_count(), 3);
    }

    #[test]
    fn passthrough_case_table_matches_source_supported_representations() {
        // These rows mirror the source logger's candidate dimensions: the
        // configured address, a connected peer address, and explicit port
        // scope.  SNI/inner-Host and parent-route selection are deliberately
        // kept outside this direct matcher; the native CONNECT owner must not
        // turn a later TLS/HTTP value into a new policy destination.
        let config = Passthrough::new(
            &[" Service.Example.Test:443 ".into(), "10.2.9.1".into()],
            "192.168.1.0/24",
        )
        .unwrap();

        // Normalized exact host:port.
        assert!(config.matches("service.example.test", 443, None));
        assert!(!config.matches("service.example.test", 8443, None));
        // Host-only address and constrained CIDR are port agnostic.
        assert!(config.matches("10.2.9.1", 1, None));
        assert!(config.matches("named.example", 9443, Some("192.168.1.25".parse().unwrap())));
        // The same host at a different port and an unrelated logical host do
        // not inherit an exact configured entry.
        assert!(!config.matches("service.example.test", 8443, None));
        assert!(!config.matches("unrelated.example", 443, None));
        // A resolved peer can select the existing CIDR transport path, while
        // lifecycle ownership remains pre-dial and is tested separately.
        assert!(config.matches(
            "unresolved.example",
            443,
            Some("192.168.1.8".parse().unwrap())
        ));
        // An exact configured address is also a source candidate after DNS
        // resolution, even when the logical CONNECT authority is an alias.
        assert!(config.matches("unresolved.example", 443, Some("10.2.9.1".parse().unwrap())));
        let port_limited = Passthrough::new(&["10.2.9.1:443".into()], "").unwrap();
        assert!(port_limited.matches("unresolved.example", 443, Some("10.2.9.1".parse().unwrap())));
        assert!(!port_limited.matches(
            "unresolved.example",
            8443,
            Some("10.2.9.1".parse().unwrap())
        ));
        // SNI/inner-Host values are not alternate destinations for this
        // matcher, and a configured parent disables direct passthrough at the
        // CONNECT owner (covered by the parent wire control).
    }

    #[test]
    fn passthrough_runtime_candidates_use_cli_idna_normalization() {
        let config = Passthrough::new(&["bücher.example:443".into()], "").unwrap();

        assert!(config.matches("BÜCHER.EXAMPLE", 443, None));
        assert!(config.matches("xn--bcher-kva.example", 443, None));
        assert!(!config.matches("bücher.example", 8443, None));
        assert!(!config.matches("bücher.example.", 443, None));
    }

    #[test]
    fn passthrough_normalization_matches_cli_entry_forms() {
        let values = vec![
            " SERVICE.Example.Test:443 ".into(),
            "service.example.test:443".into(),
            "bücher.example".into(),
        ];
        assert_eq!(
            Passthrough::normalize_hosts(&values).unwrap(),
            ["service.example.test:443", "xn--bcher-kva.example"]
        );
        for value in [
            "*.example.test",
            "example.test.",
            "https://example.test",
            "example.test:0",
            "[::1]",
        ] {
            assert!(
                Passthrough::normalize_hosts(&[value.into()]).is_err(),
                "{value}"
            );
        }
    }
}
