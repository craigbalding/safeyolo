//! WebSocket messages and compression, pending HTTP upgrade integration.
//!
//! Tungstenite parses/formats frame headers; flate2 owns DEFLATE state. Message
//! assembly spills to an anonymous private file instead of reducing accepted
//! message sizes to a library default. Fragment lengths spill separately, so a
//! message made of many tiny fragments does not retain an unbounded index.
//! Callers inspect a complete message before giving it to `Writer::message`.
//! Reads/writes may be canceled only when the whole connection is discarded.

use std::{fs::File, io::Cursor, os::unix::fs::FileExt, sync::Arc};

use flate2::{Compress, Decompress, FlushCompress, FlushDecompress};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tungstenite::protocol::frame::{
    FrameHeader,
    coding::{CloseCode, Control, Data, OpCode},
};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

const MEMORY_BYTES: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;

/// Content-free failures for the connection owner. Transport failures cannot
/// send a close on the failed leg. Storage failures are local errors, never a
/// reason to forward a partially assembled or uninspected message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    Protocol,
    InvalidPayload,
    Transport(std::io::ErrorKind),
    Storage,
}
impl ReceiveError {
    pub fn close_code(self) -> Option<u16> {
        match self {
            Self::Protocol => Some(1002),
            Self::InvalidPayload => Some(1007),
            Self::Transport(_) => None,
            Self::Storage => Some(1011),
        }
    }
    fn transport(error: std::io::Error) -> Self {
        Self::Transport(error.kind())
    }
}
impl std::fmt::Display for ReceiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Protocol => "invalid WebSocket frame sequence",
            Self::InvalidPayload => "invalid WebSocket message payload",
            Self::Transport(_) => "WebSocket receive transport failed",
            Self::Storage => "WebSocket message storage failed",
        })
    }
}
impl std::error::Error for ReceiveError {}
fn receive_error(error: Error) -> ReceiveError {
    error
        .downcast_ref::<ReceiveError>()
        .copied()
        .unwrap_or(ReceiveError::Storage)
}

/// Each direction has its own negotiated receive/send compression state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compression {
    window_bits: u8,
    no_context_takeover: bool,
}
impl Compression {
    /// The shipped wsproto extension supports window sizes 9 through 15.
    pub fn new(window_bits: u8, no_context_takeover: bool) -> Result<Self, Error> {
        if !(9..=15).contains(&window_bits) {
            return Err("unsupported WebSocket compression window".into());
        }
        Ok(Self {
            window_bits,
            no_context_takeover,
        })
    }
}

/// A checked client offer. The caller preserves the original target, headers
/// and trusted identity while running HTTP policy, before opening an origin.
pub struct Handshake {
    accept: hyper::header::HeaderValue,
    protocols: Vec<String>,
    offers: Vec<DeflateParameters>,
}
pub struct Negotiated {
    pub client: Option<Compression>,
    pub server: Option<Compression>,
    pub subprotocol: Option<String>,
}
#[derive(Default)]
struct DeflateParameters {
    client_window: Option<Option<u8>>,
    server_window: Option<u8>,
    client_reset: bool,
    server_reset: bool,
}

fn header_tokens(headers: &hyper::HeaderMap, name: &str) -> Result<Vec<String>, Error> {
    let mut values = Vec::new();
    for header in headers.get_all(name) {
        for part in split_header(header.to_str()?, b',')? {
            values.push(part.trim().to_owned());
        }
    }
    Ok(values)
}
fn split_header(value: &str, separator: u8) -> Result<Vec<&str>, Error> {
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    let mut parts = Vec::new();
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            byte if byte == separator && !quoted => {
                parts.push(&value[start..index]);
                start = index + 1;
            }
            _ => (),
        }
    }
    if quoted || escaped {
        return Err("unterminated WebSocket extension quoted string".into());
    }
    parts.push(&value[start..]);
    Ok(parts)
}
fn one_header<'a>(
    headers: &'a hyper::HeaderMap,
    name: &str,
) -> Result<Option<&'a hyper::header::HeaderValue>, Error> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err("ambiguous WebSocket handshake header".into());
    }
    Ok(value)
}
fn deflate_parameters(extension: &str, response: bool) -> Result<DeflateParameters, Error> {
    let mut parts = split_header(extension, b';')?.into_iter();
    if parts.next().map(str::trim) != Some("permessage-deflate") {
        return Err("unsupported negotiated WebSocket extension".into());
    }
    let mut result = DeflateParameters::default();
    let mut names = std::collections::HashSet::new();
    for part in parts {
        let part = part.trim();
        let (name, value) = part.split_once('=').map_or((part, None), |(name, value)| {
            (name.trim(), Some(value.trim()))
        });
        if !names.insert(name) {
            return Err("duplicate WebSocket extension parameter".into());
        }
        let number = |value: Option<&str>| -> Result<u8, Error> {
            let value = value.ok_or("missing WebSocket extension window")?;
            let mut unescaped = String::new();
            if let Some(quoted) = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            {
                let mut characters = quoted.chars();
                while let Some(character) = characters.next() {
                    unescaped.push(if character == '\\' {
                        characters
                            .next()
                            .ok_or("invalid WebSocket quoted parameter")?
                    } else {
                        character
                    });
                }
            } else {
                unescaped.push_str(value);
            }
            let value = unescaped.as_str();
            if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid WebSocket compression window".into());
            }
            let bits = value.parse::<u8>()?;
            Compression::new(bits, false)?;
            Ok(bits)
        };
        match name {
            "client_no_context_takeover" if value.is_none() => result.client_reset = true,
            "server_no_context_takeover" if value.is_none() => result.server_reset = true,
            "client_max_window_bits" if value.is_none() && !response => {
                result.client_window = Some(None)
            }
            "client_max_window_bits" => result.client_window = Some(Some(number(value)?)),
            "server_max_window_bits" => result.server_window = Some(number(value)?),
            _ => return Err("invalid WebSocket extension parameter".into()),
        }
    }
    Ok(result)
}
impl Handshake {
    /// Unsupported extension offers are removed before contacting the origin.
    /// A server cannot negotiate an extension this process cannot inspect.
    pub fn request<B>(request: &mut hyper::Request<B>) -> Result<Self, Error> {
        if request.version() != hyper::Version::HTTP_11 {
            return Err("WebSocket upgrade requires HTTP/1.1".into());
        }
        for name in ["upgrade", "sec-websocket-key", "sec-websocket-version"] {
            one_header(request.headers(), name)?;
        }
        let mut validation = hyper::Request::new(());
        *validation.method_mut() = request.method().clone();
        *validation.version_mut() = request.version();
        *validation.headers_mut() = request.headers().clone();
        let connection = header_tokens(request.headers(), "connection")?.join(", ");
        validation
            .headers_mut()
            .insert("connection", connection.parse()?);
        let response = tungstenite::handshake::server::create_response(&validation)?;
        let protocols = header_tokens(request.headers(), "sec-websocket-protocol")?;
        if protocols.iter().any(|protocol| {
            protocol.is_empty()
                || !protocol
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        }) {
            return Err("invalid WebSocket subprotocol offer".into());
        }
        let mut offers = Vec::new();
        let mut advertised = Vec::new();
        for offer in header_tokens(request.headers(), "sec-websocket-extensions")? {
            if offer.split(';').next().map(str::trim) == Some("permessage-deflate")
                && let Ok(parameters) = deflate_parameters(&offer, false)
            {
                offers.push(parameters);
                advertised.push(offer);
            }
        }
        request.headers_mut().remove("sec-websocket-extensions");
        if !advertised.is_empty() {
            request
                .headers_mut()
                .insert("sec-websocket-extensions", advertised.join(", ").parse()?);
        }
        Ok(Self {
            accept: response.headers()["sec-websocket-accept"].clone(),
            protocols,
            offers,
        })
    }
    pub fn response<B>(&self, response: &hyper::Response<B>) -> Result<Negotiated, Error> {
        if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS
            || !header_tokens(response.headers(), "connection")?
                .iter()
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
            || !one_header(response.headers(), "upgrade")?
                .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
            || one_header(response.headers(), "sec-websocket-accept")? != Some(&self.accept)
        {
            return Err("invalid origin WebSocket handshake".into());
        }
        let selected = one_header(response.headers(), "sec-websocket-protocol")?
            .map(|value| value.to_str())
            .transpose()?;
        if selected.is_some_and(|value| !self.protocols.iter().any(|offered| value == offered)) {
            return Err("origin selected an unoffered WebSocket subprotocol".into());
        }
        let extensions = header_tokens(response.headers(), "sec-websocket-extensions")?;
        let (client, server) = match extensions.as_slice() {
            [] => (None, None),
            [extension] => {
                let parameters = deflate_parameters(extension, true)?;
                let matched = self.offers.iter().any(|offer| {
                    // The server may restrict its own window and request no
                    // context takeover. Client window negotiation requires an
                    // offer; its value is a hint, not a bound (RFC 7692 7.1.2.2).
                    (parameters.client_window.is_none() || offer.client_window.is_some())
                        && offer
                            .server_window
                            .is_none_or(|maximum| parameters.server_window.unwrap_or(15) <= maximum)
                        && (!offer.server_reset || parameters.server_reset)
                });
                if !matched {
                    return Err("origin selected unoffered WebSocket compression parameters".into());
                }
                (
                    Some(Compression::new(
                        parameters.client_window.flatten().unwrap_or(15),
                        parameters.client_reset,
                    )?),
                    Some(Compression::new(
                        parameters.server_window.unwrap_or(15),
                        parameters.server_reset,
                    )?),
                )
            }
            _ => return Err("multiple negotiated WebSocket extensions".into()),
        };
        Ok(Negotiated {
            client,
            server,
            subprotocol: selected.map(str::to_owned),
        })
    }
}

/// Contents are deliberately absent from Debug and serialization.
enum StoredBytes {
    Memory(Vec<u8>),
    File { file: File, len: u64 },
}
impl StoredBytes {
    fn len(&self) -> u64 {
        match self {
            Self::Memory(bytes) => bytes.len() as u64,
            Self::File { len, .. } => *len,
        }
    }
    async fn reader(&self) -> Result<Box<dyn AsyncRead + Unpin + Send + '_>, Error> {
        match self {
            Self::Memory(bytes) => Ok(Box::new(Cursor::new(bytes))),
            Self::File { file, .. } => {
                let mut reader = tokio::fs::File::from_std(file.try_clone()?);
                reader.seek(std::io::SeekFrom::Start(0)).await?;
                Ok(Box::new(reader))
            }
        }
    }
    // The caller runs inspection on a blocking worker. File mappings allow
    // borrowed complete text without a second allocation proportional to size.
    // Resident mapped pages are managed by the OS; this is not a hard RSS cap.
    fn with_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> Result<T, Error> {
        match self {
            Self::Memory(bytes) => Ok(inspect(bytes)),
            Self::File { file, len } => {
                if *len == 0 {
                    return Ok(inspect(&[]));
                }
                // SAFETY: the anonymous file is owned exclusively by this
                // module, never published, and cannot be mutated after finish.
                // The borrowed mapping cannot escape this function.
                let mapping = unsafe { memmap2::MmapOptions::new().map(file)? };
                #[cfg(unix)]
                mapping.advise(memmap2::Advice::Sequential)?;
                Ok(inspect(&mapping))
            }
        }
    }
}

#[derive(Default)]
struct PendingBytes {
    memory: Vec<u8>,
    file: Option<tokio::fs::File>,
    len: u64,
}
impl PendingBytes {
    async fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or("WebSocket storage overflow")?;
        if self.file.is_none() && len <= MEMORY_BYTES as u64 {
            self.memory.extend_from_slice(bytes);
        } else {
            if self.file.is_none() {
                let file = tokio::task::spawn_blocking(tempfile::tempfile).await??;
                let mut file = tokio::fs::File::from_std(file);
                file.write_all(&self.memory).await?;
                self.memory = Vec::new();
                self.file = Some(file);
            }
            self.file.as_mut().unwrap().write_all(bytes).await?;
        }
        self.len = len;
        Ok(())
    }
    async fn remove_tail(&mut self, count: u64) -> Result<(), Error> {
        self.len = self
            .len
            .checked_sub(count)
            .ok_or("incomplete WebSocket deflate trailer")?;
        if let Some(file) = &mut self.file {
            file.flush().await?;
            file.set_len(self.len).await?;
        } else {
            self.memory.truncate(self.len as usize);
        }
        Ok(())
    }
    async fn finish(mut self) -> Result<StoredBytes, Error> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
            Ok(StoredBytes::File {
                file: file.into_std().await,
                len: self.len,
            })
        } else {
            Ok(StoredBytes::Memory(self.memory))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Text,
    Binary,
}

pub struct Message {
    pub kind: MessageType,
    body: Arc<MessageContent>,
    fragments: StoredBytes,
}

/// Complete decoded payload shared by forwarding and retained observation.
/// The anonymous spill file remains immutable; range reads never move the
/// forwarding reader's file offset. Contents have no Debug/serialization form.
pub(crate) struct MessageContent {
    bytes: StoredBytes,
}

impl MessageContent {
    pub(crate) fn len(&self) -> u64 {
        self.bytes.len()
    }

    /// Call on a blocking worker. Allocation is bounded by the requested range
    /// and actual remaining bytes; no complete spilled payload is materialized.
    pub(crate) fn read_range(
        &self,
        offset: u64,
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let count = self.len().saturating_sub(offset).min(length as u64) as usize;
        let mut bytes = Zeroizing::new(vec![0; count]);
        match &self.bytes {
            StoredBytes::Memory(content) => {
                if count != 0 {
                    bytes.copy_from_slice(&content[offset as usize..offset as usize + count]);
                }
            }
            StoredBytes::File { file, .. } => {
                let mut read = 0;
                while read < count {
                    match file.read_at(&mut bytes[read..], offset + read as u64) {
                        Ok(0) => {
                            return Err(
                                std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()
                            );
                        }
                        Ok(count) => read += count,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(bytes: Vec<u8>) -> Self {
        Self {
            bytes: StoredBytes::Memory(bytes),
        }
    }
}

impl Drop for MessageContent {
    fn drop(&mut self) {
        if let StoredBytes::Memory(bytes) = &mut self.bytes {
            bytes.zeroize();
        }
    }
}

impl Message {
    pub fn len(&self) -> u64 {
        self.body.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn fragment_count(&self) -> u64 {
        self.fragments.len() / 8
    }
    pub fn spilled(&self) -> bool {
        matches!(self.body.bytes, StoredBytes::File { .. })
            || matches!(self.fragments, StoredBytes::File { .. })
    }
    pub(crate) fn content(&self) -> Arc<MessageContent> {
        self.body.clone()
    }
    /// Execute on a blocking worker. Text is already valid UTF-8; binary uses
    /// the scanner's Latin-1 interpretation. Conversion also uses private disk
    /// storage, without changing the bytes subsequently delivered to the peer.
    pub fn with_text<T>(&self, inspect: impl FnOnce(&str) -> T) -> Result<T, Error> {
        self.body.bytes.with_bytes(|bytes| -> Result<T, Error> {
            if self.kind == MessageType::Text || bytes.is_ascii() {
                return Ok(inspect(std::str::from_utf8(bytes)?));
            }
            use std::io::Write;
            let mut file = tempfile::tempfile()?;
            let mut buffer = [0u8; CHUNK * 2];
            for chunk in bytes.chunks(CHUNK) {
                let mut len = 0;
                for byte in chunk {
                    if *byte < 128 {
                        buffer[len] = *byte;
                        len += 1;
                    } else {
                        buffer[len] = 0xc0 | (*byte >> 6);
                        buffer[len + 1] = 0x80 | (*byte & 0x3f);
                        len += 2;
                    }
                }
                file.write_all(&buffer[..len])?;
            }
            // SAFETY: this anonymous file has no external handles or writers;
            // all writes are finished, and the mapping stays inside this call.
            let mapping = unsafe { memmap2::MmapOptions::new().map(&file)? };
            #[cfg(unix)]
            mapping.advise(memmap2::Advice::Sequential)?;
            Ok(inspect(std::str::from_utf8(&mapping)?))
        })?
    }
}

#[derive(Default)]
struct Utf8 {
    pending: Vec<u8>,
}
impl Utf8 {
    fn check(&mut self, mut bytes: &[u8]) -> Result<(), ReceiveError> {
        if !self.pending.is_empty() {
            while self.pending.len() < 4 && !bytes.is_empty() {
                self.pending.push(bytes[0]);
                bytes = &bytes[1..];
                match std::str::from_utf8(&self.pending) {
                    Ok(_) => {
                        self.pending.clear();
                        break;
                    }
                    Err(error) if error.error_len().is_none() => (),
                    Err(_) => return Err(ReceiveError::InvalidPayload),
                }
            }
            if !self.pending.is_empty() {
                return Ok(());
            }
        }
        match std::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.error_len().is_none() => {
                self.pending
                    .extend_from_slice(&bytes[error.valid_up_to()..]);
                Ok(())
            }
            Err(_) => Err(ReceiveError::InvalidPayload),
        }
    }
}

struct PendingMessage {
    kind: MessageType,
    compressed: bool,
    body: PendingBytes,
    fragments: PendingBytes,
    utf8: Utf8,
}
impl PendingMessage {
    async fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.kind == MessageType::Text {
            self.utf8.check(bytes)?;
        }
        self.body.append(bytes).await
    }
    async fn finish(self) -> Result<Message, Error> {
        if !self.utf8.pending.is_empty() {
            return Err(ReceiveError::InvalidPayload.into());
        }
        Ok(Message {
            kind: self.kind,
            body: Arc::new(MessageContent {
                bytes: self.body.finish().await?,
            }),
            fragments: self.fragments.finish().await?,
        })
    }
}

/// Control payloads are limited by RFC 6455 to 125 bytes, independently of
/// configured inspection. Control events do not finish a pending data message.
pub enum Event {
    Message(Message),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Vec<u8>),
}

pub struct Reader<R> {
    stream: R,
    from_client: bool,
    compression: Option<Compression>,
    inflater: Option<Inflater>,
    pending: Option<PendingMessage>,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(stream: R, from_client: bool, compression: Option<Compression>) -> Self {
        Self {
            stream,
            from_client,
            compression,
            inflater: None,
            pending: None,
        }
    }
    pub async fn read(&mut self) -> Result<Event, ReceiveError> {
        loop {
            let mut bytes = [0u8; 14];
            self.stream
                .read_exact(&mut bytes[..2])
                .await
                .map_err(ReceiveError::transport)?;
            let extra = match bytes[1] & 127 {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let length = 2 + extra + if bytes[1] & 128 != 0 { 4 } else { 0 };
            self.stream
                .read_exact(&mut bytes[2..length])
                .await
                .map_err(ReceiveError::transport)?;
            let (header, payload_len) = FrameHeader::parse(&mut Cursor::new(&bytes[..length]))
                .map_err(|_| ReceiveError::Protocol)?
                .ok_or(ReceiveError::Protocol)?;
            if payload_len >= (1 << 63)
                || (extra == 2 && payload_len < 126)
                || (extra == 8 && payload_len <= 65535)
                || header.mask.is_some() != self.from_client
                || header.rsv2
                || header.rsv3
            {
                return Err(ReceiveError::Protocol);
            }
            if let OpCode::Control(control) = header.opcode {
                if !header.is_final || payload_len > 125 || header.rsv1 {
                    return Err(ReceiveError::Protocol);
                }
                let mut payload = vec![0; payload_len as usize];
                self.stream
                    .read_exact(&mut payload)
                    .await
                    .map_err(ReceiveError::transport)?;
                mask(&mut payload, header.mask, 0);
                return match control {
                    Control::Ping => Ok(Event::Ping(payload)),
                    Control::Pong => Ok(Event::Pong(payload)),
                    Control::Close => {
                        validate_close(&payload)?;
                        Ok(Event::Close(payload))
                    }
                    Control::Reserved(_) => Err(ReceiveError::Protocol),
                };
            }
            match header.opcode {
                OpCode::Data(Data::Text | Data::Binary) if self.pending.is_none() => {
                    if header.rsv1 && self.compression.is_none() {
                        return Err(ReceiveError::Protocol);
                    }
                    if header.rsv1 && self.inflater.is_none() {
                        self.inflater = Some(Inflater::new(self.compression.unwrap().window_bits));
                    }
                    self.pending = Some(PendingMessage {
                        kind: if header.opcode == OpCode::Data(Data::Text) {
                            MessageType::Text
                        } else {
                            MessageType::Binary
                        },
                        compressed: header.rsv1,
                        body: PendingBytes::default(),
                        fragments: PendingBytes::default(),
                        utf8: Utf8::default(),
                    });
                }
                OpCode::Data(Data::Continue) if self.pending.is_some() && !header.rsv1 => (),
                _ => return Err(ReceiveError::Protocol),
            }
            let pending = self.pending.as_mut().unwrap();
            let start = pending.body.len;
            let mut offset = 0;
            let mut buffer = [0u8; CHUNK];
            while offset < payload_len {
                let count = (payload_len - offset).min(CHUNK as u64) as usize;
                self.stream
                    .read_exact(&mut buffer[..count])
                    .await
                    .map_err(ReceiveError::transport)?;
                mask(&mut buffer[..count], header.mask, offset);
                if pending.compressed {
                    inflate(self.inflater.as_mut().unwrap(), &buffer[..count], pending)
                        .await
                        .map_err(receive_error)?;
                } else {
                    pending
                        .append(&buffer[..count])
                        .await
                        .map_err(receive_error)?;
                }
                offset += count as u64;
            }
            if header.is_final && pending.compressed {
                inflate(self.inflater.as_mut().unwrap(), &[0, 0, 255, 255], pending)
                    .await
                    .map_err(receive_error)?;
                if self.compression.unwrap().no_context_takeover {
                    self.inflater = None;
                }
            }
            pending
                .fragments
                .append(&(pending.body.len - start).to_be_bytes())
                .await
                .map_err(receive_error)?;
            if header.is_final {
                return Ok(Event::Message(
                    self.pending
                        .take()
                        .unwrap()
                        .finish()
                        .await
                        .map_err(receive_error)?,
                ));
            }
        }
    }
}

fn mask(bytes: &mut [u8], key: Option<[u8; 4]>, offset: u64) {
    if let Some(key) = key {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte ^= key[(index + (offset % 4) as usize) % 4];
        }
    }
}
fn validate_close(bytes: &[u8]) -> Result<(), ReceiveError> {
    if bytes.len() == 1 {
        return Err(ReceiveError::Protocol);
    }
    if bytes.len() >= 2 {
        let code = CloseCode::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if !code.is_allowed() {
            return Err(ReceiveError::Protocol);
        }
        std::str::from_utf8(&bytes[2..]).map_err(|_| ReceiveError::InvalidPayload)?;
    }
    Ok(())
}

struct Inflater {
    decoder: Decompress,
    history: Vec<u8>,
    window: usize,
}
impl Inflater {
    fn new(bits: u8) -> Self {
        Self {
            decoder: Decompress::new_with_window_bits(false, bits),
            history: Vec::new(),
            window: 1 << bits,
        }
    }
    fn remember(&mut self, bytes: &[u8]) {
        let bytes = &bytes[bytes.len().saturating_sub(self.window)..];
        let discard = (self.history.len() + bytes.len()).saturating_sub(self.window);
        self.history.drain(..discard);
        self.history.extend_from_slice(bytes);
    }
}

async fn inflate(
    inflater: &mut Inflater,
    mut bytes: &[u8],
    message: &mut PendingMessage,
) -> Result<(), Error> {
    loop {
        let (input, output) = (inflater.decoder.total_in(), inflater.decoder.total_out());
        let mut buffer = [0u8; CHUNK];
        let status = inflater
            .decoder
            .decompress(bytes, &mut buffer, FlushDecompress::Sync)
            .map_err(|_| ReceiveError::InvalidPayload)?;
        let read = (inflater.decoder.total_in() - input) as usize;
        let written = (inflater.decoder.total_out() - output) as usize;
        inflater.remember(&buffer[..written]);
        message.append(&buffer[..written]).await?;
        if status == flate2::Status::StreamEnd {
            // RFC 7692 permits BFINAL=1 followed by more byte-aligned blocks.
            // Resume raw inflation while retaining the negotiated LZ77 window.
            inflater.decoder.reset(false);
            inflater
                .decoder
                .set_dictionary(&inflater.history)
                .map_err(|_| ReceiveError::InvalidPayload)?;
        }
        bytes = &bytes[read..];
        if bytes.is_empty() && written < CHUNK {
            return Ok(());
        }
        if read == 0 && written == 0 {
            return Err(ReceiveError::InvalidPayload.into());
        }
    }
}

pub struct Writer<W> {
    stream: W,
    to_server: bool,
    compression: Option<Compression>,
    deflater: Option<Compress>,
}
impl<W: AsyncWrite + Unpin> Writer<W> {
    pub fn new(stream: W, to_server: bool, compression: Option<Compression>) -> Self {
        Self {
            stream,
            to_server,
            compression,
            deflater: None,
        }
    }
    /// Sending only allowed messages keeps the outgoing dictionary independent
    /// from received/dropped messages, including context-takeover connections.
    pub async fn message(&mut self, message: Message) -> Result<(), Error> {
        let mut body = message.body.bytes.reader().await?;
        let mut fragments = message.fragments.reader().await?;
        let count = message.fragment_count();
        let mut consumed = 0;
        for index in 0..count {
            let mut length = [0; 8];
            fragments.read_exact(&mut length).await?;
            let length = u64::from_be_bytes(length);
            consumed += length;
            let last = index + 1 == count;
            let opcode = if index != 0 {
                Data::Continue
            } else if message.kind == MessageType::Text {
                Data::Text
            } else {
                Data::Binary
            };
            let header = FrameHeader {
                opcode: OpCode::Data(opcode),
                is_final: last,
                rsv1: index == 0 && self.compression.is_some(),
                ..FrameHeader::default()
            };
            if let Some(compression) = self.compression {
                if self.deflater.is_none() {
                    self.deflater = Some(Compress::new_with_window_bits(
                        flate2::Compression::default(),
                        false,
                        compression.window_bits,
                    ));
                }
                let mut encoded = PendingBytes::default();
                let mut remaining = length;
                let mut buffer = [0; CHUNK];
                while remaining > 0 {
                    let count = remaining.min(CHUNK as u64) as usize;
                    body.read_exact(&mut buffer[..count]).await?;
                    deflate(
                        self.deflater.as_mut().unwrap(),
                        &buffer[..count],
                        FlushCompress::None,
                        &mut encoded,
                    )
                    .await?;
                    remaining -= count as u64;
                }
                if last {
                    deflate(
                        self.deflater.as_mut().unwrap(),
                        &[],
                        FlushCompress::Sync,
                        &mut encoded,
                    )
                    .await?;
                    encoded.remove_tail(4).await?;
                    if compression.no_context_takeover {
                        self.deflater = None;
                    }
                }
                let encoded = encoded.finish().await?;
                self.frame(header, encoded.len(), &mut encoded.reader().await?)
                    .await?;
            } else {
                self.frame(header, length, &mut body).await?;
            }
        }
        if consumed != message.len() {
            return Err("WebSocket fragment storage mismatch".into());
        }
        self.stream.flush().await?;
        Ok(())
    }
    pub async fn control(&mut self, control: Control, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > 125 || matches!(control, Control::Reserved(_)) {
            return Err("invalid outgoing WebSocket control".into());
        }
        if control == Control::Close {
            validate_close(payload)?;
        }
        let header = FrameHeader {
            opcode: OpCode::Control(control),
            ..FrameHeader::default()
        };
        self.frame(header, payload.len() as u64, &mut Cursor::new(payload))
            .await?;
        self.stream.flush().await?;
        Ok(())
    }
    pub(crate) async fn shutdown(&mut self) -> Result<(), Error> {
        self.stream.shutdown().await?;
        Ok(())
    }
    async fn frame(
        &mut self,
        mut header: FrameHeader,
        len: u64,
        body: &mut (impl AsyncRead + Unpin),
    ) -> Result<(), Error> {
        if self.to_server {
            use ring::rand::SecureRandom;
            let mut key = [0; 4];
            ring::rand::SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| "WebSocket mask generation failed")?;
            header.mask = Some(key);
        }
        let mut formatted = Vec::with_capacity(14);
        header.format(len, &mut formatted)?;
        self.stream.write_all(&formatted).await?;
        let mut offset = 0;
        let mut buffer = [0; CHUNK];
        while offset < len {
            let count = (len - offset).min(CHUNK as u64) as usize;
            body.read_exact(&mut buffer[..count]).await?;
            mask(&mut buffer[..count], header.mask, offset);
            self.stream.write_all(&buffer[..count]).await?;
            offset += count as u64;
        }
        Ok(())
    }
}

async fn deflate(
    deflater: &mut Compress,
    mut bytes: &[u8],
    flush: FlushCompress,
    encoded: &mut PendingBytes,
) -> Result<(), Error> {
    loop {
        let (input, output) = (deflater.total_in(), deflater.total_out());
        let mut buffer = [0u8; CHUNK];
        deflater.compress(bytes, &mut buffer, flush)?;
        let read = (deflater.total_in() - input) as usize;
        let written = (deflater.total_out() - output) as usize;
        encoded.append(&buffer[..written]).await?;
        bytes = &bytes[read..];
        if bytes.is_empty() && written < CHUNK {
            return Ok(());
        }
        if read == 0 && written == 0 {
            return Err("stalled WebSocket compression".into());
        }
    }
}
