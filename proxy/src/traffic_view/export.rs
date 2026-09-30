//! Bounded source-shaped selected-flow export.
//!
//! The parent view only snapshots owners under its mutex. Rendering and retained
//! message reads happen after that lock has been released.

use std::{fmt::Write as _, sync::Arc};

use encoding_rs::{DecoderResult, Encoding};
use zeroize::{Zeroize, Zeroizing};

use super::codec_tables::{big5_correction, python_codec_is_registered};
use super::{Body, Row};

mod har;

const EXPORT_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportFormat {
    Raw,
    RawRequest,
    RawResponse,
    Curl,
    Httpie,
    Har,
    Zhar,
}

impl ExportFormat {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "raw" => Self::Raw,
            "raw_request" => Self::RawRequest,
            "raw_response" => Self::RawResponse,
            "curl" => Self::Curl,
            "httpie" => Self::Httpie,
            "har" => Self::Har,
            "zhar" => Self::Zhar,
            _ => return None,
        })
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::RawRequest => "raw_request",
            Self::RawResponse => "raw_response",
            Self::Curl => "curl",
            Self::Httpie => "httpie",
            Self::Har => "har",
            Self::Zhar => "zhar",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportError {
    MissingFlow,
    MissingRequest,
    MissingResponse,
    MissingBody,
    Decode,
    Unsupported,
    Storage,
    Allocation,
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::MissingFlow => "flow not found",
            Self::MissingRequest => "request is unavailable",
            Self::MissingResponse => "response is unavailable",
            Self::MissingBody => "HTTP content is missing",
            Self::Decode => "HTTP content cannot be decoded for export",
            Self::Unsupported => "HTTP export representation is unavailable",
            Self::Storage => "retained export content could not be read",
            Self::Allocation => "HTTP export allocation failed",
        })
    }
}

struct ExportHttp {
    method: Zeroizing<String>,
    url: Zeroizing<String>,
    target: Option<Zeroizing<String>>,
    version: Option<Zeroizing<String>>,
    headers: Vec<(Zeroizing<String>, Zeroizing<String>)>,
    body: Option<Arc<Zeroizing<Vec<u8>>>>,
    status: Option<u16>,
    reason: Option<Zeroizing<Vec<u8>>>,
    trailers: Vec<(Zeroizing<String>, Zeroizing<String>)>,
}

struct ExportWebsocket {
    messages: Vec<ExportWebsocketMessage>,
}

struct ExportWebsocketMessage {
    kind: crate::websocket::MessageType,
    from_client: bool,
    timestamp: f64,
    content: Arc<crate::websocket::MessageContent>,
}

pub(super) struct ExportSnapshot {
    request: ExportHttp,
    response: Option<ExportHttp>,
    websocket: Option<ExportWebsocket>,
    started: f64,
    request_completed: Option<f64>,
    response_head_observed: Option<f64>,
    response_completed: Option<f64>,
    upstream: Option<super::UpstreamConnectionObservation>,
    error: Option<Zeroizing<String>>,
}

enum ExportPart {
    Bytes {
        data: Zeroizing<Vec<u8>>,
        offset: usize,
    },
    Message {
        content: Arc<crate::websocket::MessageContent>,
        offset: u64,
    },
    HarMessage(har::MessagePart),
}

struct ZlibState {
    encoder: flate2::Compress,
    input: Zeroizing<Vec<u8>>,
    offset: usize,
    input_done: bool,
    stream_done: bool,
}

/// A preflighted source-shaped export. Parts retain immutable content owners;
/// no complete transcript or rendered archive is held in one response buffer.
pub(crate) struct ExportPlan {
    format: ExportFormat,
    parts: Vec<ExportPart>,
    position: usize,
    zlib: Option<ZlibState>,
}

impl ExportPlan {
    pub(crate) fn format(&self) -> ExportFormat {
        self.format
    }

    /// Called by the private response worker. A storage failure after headers
    /// have been sent becomes a body error, so the response cannot claim a
    /// successfully completed artifact.
    pub(crate) fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, ExportError> {
        if self.zlib.is_some() {
            return self.next_compressed_chunk();
        }
        self.next_raw_chunk()
    }

    fn next_raw_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, ExportError> {
        loop {
            let Some(part) = self.parts.get_mut(self.position) else {
                return Ok(None);
            };
            match part {
                ExportPart::Bytes { data, offset } => {
                    if *offset >= data.len() {
                        self.position += 1;
                        continue;
                    }
                    let remaining = data.len() - *offset;
                    if *offset == 0 && remaining <= EXPORT_CHUNK {
                        let data = std::mem::take(data);
                        self.position += 1;
                        return Ok(Some(data));
                    }
                    let end = (*offset).saturating_add(EXPORT_CHUNK).min(data.len());
                    let mut chunk = Zeroizing::new(Vec::new());
                    chunk
                        .try_reserve(end - *offset)
                        .map_err(|_| ExportError::Allocation)?;
                    chunk.extend_from_slice(&data[*offset..end]);
                    *offset = end;
                    return Ok(Some(chunk));
                }
                ExportPart::Message { content, offset } => {
                    let total = content.len();
                    if *offset >= total {
                        self.position += 1;
                        continue;
                    }
                    let chunk = content
                        .read_range(*offset, EXPORT_CHUNK)
                        .map_err(|_| ExportError::Storage)?;
                    if chunk.is_empty() {
                        return Err(ExportError::Storage);
                    }
                    *offset = offset.saturating_add(chunk.len() as u64);
                    return Ok(Some(chunk));
                }
                ExportPart::HarMessage(message) => match har::message_chunk(message)? {
                    Some(chunk) => return Ok(Some(chunk)),
                    None => {
                        self.position += 1;
                    }
                },
            }
        }
    }

    fn next_compressed_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, ExportError> {
        const CHUNK: usize = 16 * 1024;
        loop {
            let need_input = {
                let zlib = self.zlib.as_ref().expect("compression state");
                !zlib.input_done && zlib.offset >= zlib.input.len()
            };
            if need_input {
                let input = self.next_raw_chunk()?;
                let zlib = self.zlib.as_mut().expect("compression state");
                match input {
                    Some(input) => {
                        zlib.input = input;
                        zlib.offset = 0;
                    }
                    None => zlib.input_done = true,
                }
            }
            let has_input = {
                let zlib = self.zlib.as_ref().expect("compression state");
                zlib.offset < zlib.input.len()
            };
            if has_input {
                let zlib = self.zlib.as_mut().expect("compression state");
                let before_in = zlib.encoder.total_in();
                let before_out = zlib.encoder.total_out();
                let mut output = Zeroizing::new([0u8; CHUNK]);
                zlib.encoder
                    .compress(
                        &zlib.input[zlib.offset..],
                        &mut *output,
                        flate2::FlushCompress::None,
                    )
                    .map_err(|_| ExportError::Unsupported)?;
                let consumed = (zlib.encoder.total_in() - before_in) as usize;
                let written = (zlib.encoder.total_out() - before_out) as usize;
                zlib.offset = zlib.offset.saturating_add(consumed);
                if consumed == 0 && written == 0 {
                    return Err(ExportError::Unsupported);
                }
                if written != 0 {
                    return Ok(Some(copy_bytes(&output[..written])));
                }
                continue;
            }
            let should_finish = {
                let zlib = self.zlib.as_ref().expect("compression state");
                zlib.input_done && !zlib.stream_done
            };
            if !should_finish {
                return Ok(None);
            }
            let zlib = self.zlib.as_mut().expect("compression state");
            let before = zlib.encoder.total_out();
            let mut output = Zeroizing::new([0u8; CHUNK]);
            let status = zlib
                .encoder
                .compress(&[], &mut *output, flate2::FlushCompress::Finish)
                .map_err(|_| ExportError::Unsupported)?;
            let written = (zlib.encoder.total_out() - before) as usize;
            if status == flate2::Status::StreamEnd {
                zlib.stream_done = true;
            }
            if written != 0 {
                return Ok(Some(copy_bytes(&output[..written])));
            }
            if !zlib.stream_done {
                return Err(ExportError::Unsupported);
            }
            return Ok(None);
        }
    }

    pub(super) fn build(
        mut snapshot: ExportSnapshot,
        format: ExportFormat,
    ) -> Result<Self, ExportError> {
        let mut parts = Vec::new();
        match format {
            ExportFormat::Curl | ExportFormat::Httpie => {
                let body = prepare_http(&mut snapshot.request, false)?;
                let command = match format {
                    ExportFormat::Curl => {
                        curl_command(&snapshot.request, body.as_deref().map(|v| &**v))?
                    }
                    ExportFormat::Httpie => {
                        httpie_command(&snapshot.request, body.as_deref().map(|v| &**v))?
                    }
                    _ => unreachable!("command format checked"),
                };
                parts.push(ExportPart::Bytes {
                    data: command,
                    offset: 0,
                });
            }
            ExportFormat::RawRequest => {
                let body = prepare_http(&mut snapshot.request, true)?;
                add_http(&mut parts, &snapshot.request, body, true)?;
            }
            ExportFormat::RawResponse => {
                let response = snapshot
                    .response
                    .as_mut()
                    .ok_or(ExportError::MissingResponse)?;
                let body = prepare_http(response, true)?;
                add_http(&mut parts, response, body, false)?;
            }
            ExportFormat::Raw => {
                let request_present = snapshot.request.body.is_some();
                let response_present = snapshot
                    .response
                    .as_ref()
                    .is_some_and(|response| response.body.is_some());
                if !request_present && !response_present {
                    return Err(ExportError::MissingBody);
                }
                let request_body = request_present
                    .then(|| prepare_http(&mut snapshot.request, true))
                    .transpose()?
                    .flatten();
                let response_body = response_present
                    .then(|| {
                        snapshot
                            .response
                            .as_mut()
                            .ok_or(ExportError::MissingResponse)
                            .and_then(|response| prepare_http(response, true))
                    })
                    .transpose()?
                    .flatten();
                if let Some(body) = request_body {
                    add_http(&mut parts, &snapshot.request, Some(body), true)?;
                }
                if request_present && response_present {
                    push_static(&mut parts, b"\r\n\r\n");
                }
                if let (Some(response), Some(body)) = (snapshot.response.as_ref(), response_body) {
                    add_http(&mut parts, response, Some(body), false)?;
                }
                if request_present
                    && response_present
                    && let Some(websocket) = snapshot.websocket
                {
                    push_static(&mut parts, b"\r\n\r\n");
                    add_websocket(&mut parts, websocket);
                }
            }
            ExportFormat::Har | ExportFormat::Zhar => {
                parts = har::build(snapshot)?;
            }
        }
        Ok(Self {
            format,
            parts,
            position: 0,
            zlib: (format == ExportFormat::Zhar).then(|| ZlibState {
                encoder: flate2::Compress::new(flate2::Compression::best(), true),
                input: Zeroizing::new(Vec::new()),
                offset: 0,
                input_done: false,
                stream_done: false,
            }),
        })
    }
}

impl Row {
    pub(super) fn export_snapshot(&self) -> ExportSnapshot {
        ExportSnapshot {
            request: ExportHttp {
                method: Zeroizing::new(self.request.method.clone()),
                url: Zeroizing::new(self.request.url.clone()),
                target: self.request_target.clone(),
                version: self.request_version.clone(),
                headers: export_headers(&self.request.headers),
                body: body_owner(&self.request_body),
                status: None,
                reason: None,
                trailers: export_headers(&self.request_trailers),
            },
            response: self.status.map(|status| ExportHttp {
                method: Zeroizing::new(String::new()),
                url: Zeroizing::new(String::new()),
                target: None,
                version: self.response_version.clone(),
                headers: export_headers(&self.response_headers),
                body: body_owner(&self.response_body),
                status: Some(status),
                reason: self.response_reason.clone(),
                trailers: export_headers(&self.response_trailers),
            }),
            // Request trailers are observed on the forwarded body wrapper,
            // after the parser-owned body has crossed its completion barrier.
            // Keep them distinct from response trailers for raw request and
            // combined raw framing.
            websocket: self.websocket.as_ref().map(|session| ExportWebsocket {
                messages: session
                    .export_messages()
                    .into_iter()
                    .map(|message| ExportWebsocketMessage {
                        kind: message.kind,
                        from_client: message.from_client,
                        timestamp: message.timestamp,
                        content: message.content,
                    })
                    .collect(),
            }),
            started: self.request.started,
            request_completed: self.request_completed,
            response_head_observed: self.response_head_observed,
            response_completed: self.response_completed,
            upstream: self.upstream.clone(),
            error: self.error.clone(),
        }
    }
}

fn export_headers(headers: &[(String, String)]) -> Vec<(Zeroizing<String>, Zeroizing<String>)> {
    headers
        .iter()
        .map(|(name, value)| (Zeroizing::new(name.clone()), Zeroizing::new(value.clone())))
        .collect()
}

fn body_owner(body: &Body) -> Option<Arc<Zeroizing<Vec<u8>>>> {
    match body {
        Body::Bytes(bytes) => Some(Arc::clone(bytes)),
        Body::Pending | Body::Unavailable => None,
    }
}

fn prepare_http(
    side: &mut ExportHttp,
    require_body: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, ExportError> {
    let Some(body) = &side.body else {
        if require_body {
            return Err(ExportError::MissingBody);
        }
        return Ok(None);
    };
    let raw = body.as_slice();
    if raw.is_empty() {
        return Ok(Some(Zeroizing::new(Vec::new())));
    }
    let encoding = header_value(&side.headers, "content-encoding")
        .unwrap_or_else(|| Zeroizing::new(String::new()));
    let decoded = match crate::http_content::decode(raw, encoding.as_bytes()) {
        Ok(decoded) => decoded,
        // mitmproxy's decode(strict=False) removes an invalid encoding and
        // falls back to the retained raw content.
        Err(crate::http_content::ContentError::Value) => Zeroizing::new(raw.to_vec()),
        Err(crate::http_content::ContentError::Type) => return Err(ExportError::Decode),
        Err(crate::http_content::ContentError::Allocation) => return Err(ExportError::Allocation),
    };
    remove_header(&mut side.headers, "content-encoding");
    if !has_header(&side.headers, "transfer-encoding") {
        set_header(
            &mut side.headers,
            "content-length",
            decoded.len().to_string(),
        );
    }
    Ok(Some(decoded))
}

fn add_http(
    parts: &mut Vec<ExportPart>,
    side: &ExportHttp,
    body: Option<Zeroizing<Vec<u8>>>,
    request: bool,
) -> Result<(), ExportError> {
    let mut head = Zeroizing::new(Vec::new());
    if request {
        let version = side.version.as_ref().ok_or(ExportError::MissingRequest)?;
        let target = side.target.as_ref().ok_or(ExportError::MissingRequest)?;
        append_latin1(&mut head, &side.method)?;
        head.extend_from_slice(b" ");
        append_latin1(&mut head, target)?;
        head.extend_from_slice(b" ");
        append_latin1(&mut head, version)?;
    } else {
        let version = side.version.as_ref().ok_or(ExportError::Unsupported)?;
        let status = side.status.ok_or(ExportError::MissingResponse)?;
        let reason = side.reason.as_ref().ok_or(ExportError::Unsupported)?;
        append_latin1(&mut head, version)?;
        head.extend_from_slice(b" ");
        append_latin1(&mut head, &status.to_string())?;
        head.extend_from_slice(b" ");
        head.extend_from_slice(reason);
    }
    head.extend_from_slice(b"\r\n");
    append_headers(&mut head, &side.headers)?;
    head.extend_from_slice(b"\r\n");
    parts.push(ExportPart::Bytes {
        data: head,
        offset: 0,
    });
    add_body(parts, side, body)
}

fn add_body(
    parts: &mut Vec<ExportPart>,
    side: &ExportHttp,
    body: Option<Zeroizing<Vec<u8>>>,
) -> Result<(), ExportError> {
    let body = body.ok_or(ExportError::MissingBody)?;
    let chunked = header_value(&side.headers, "transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    });
    if !side.trailers.is_empty() && !chunked {
        return Err(ExportError::Unsupported);
    }
    if chunked {
        if !body.is_empty() {
            let prefix = Zeroizing::new(format!("{:x}\r\n", body.len()).into_bytes());
            parts.push(ExportPart::Bytes {
                data: prefix,
                offset: 0,
            });
            parts.push(ExportPart::Bytes {
                data: body,
                offset: 0,
            });
            push_static(parts, b"\r\n");
        }
        let mut end = Zeroizing::new(Vec::new());
        end.extend_from_slice(b"0\r\n");
        append_headers(&mut end, &side.trailers)?;
        end.extend_from_slice(b"\r\n");
        parts.push(ExportPart::Bytes {
            data: end,
            offset: 0,
        });
    } else {
        parts.push(ExportPart::Bytes {
            data: body,
            offset: 0,
        });
    }
    Ok(())
}

fn add_websocket(parts: &mut Vec<ExportPart>, websocket: ExportWebsocket) {
    for (position, message) in websocket.messages.into_iter().enumerate() {
        if position != 0 {
            push_static(parts, b"\n");
        }
        push_static(
            parts,
            if message.from_client {
                b"[OUTGOING] "
            } else {
                b"[INCOMING] "
            },
        );
        parts.push(ExportPart::Message {
            content: message.content,
            offset: 0,
        });
    }
}

fn push_static(parts: &mut Vec<ExportPart>, bytes: &'static [u8]) {
    parts.push(ExportPart::Bytes {
        data: Zeroizing::new(bytes.to_vec()),
        offset: 0,
    });
}

fn copy_bytes(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut copy = Zeroizing::new(Vec::with_capacity(bytes.len()));
    copy.extend_from_slice(bytes);
    copy
}

fn append_latin1(output: &mut Vec<u8>, value: &str) -> Result<(), ExportError> {
    for character in value.chars() {
        let value = character as u32;
        if value > u8::MAX as u32 {
            return Err(ExportError::Unsupported);
        }
        output.push(value as u8);
    }
    Ok(())
}

fn append_headers(
    output: &mut Vec<u8>,
    headers: &[(Zeroizing<String>, Zeroizing<String>)],
) -> Result<(), ExportError> {
    for (name, value) in headers {
        append_latin1(output, name)?;
        output.extend_from_slice(b": ");
        append_latin1(output, value)?;
        output.extend_from_slice(b"\r\n");
    }
    Ok(())
}

fn has_header(headers: &[(Zeroizing<String>, Zeroizing<String>)], wanted: &str) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
}

fn header_value(
    headers: &[(Zeroizing<String>, Zeroizing<String>)],
    wanted: &str,
) -> Option<Zeroizing<String>> {
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.as_str())
        .collect();
    (!values.is_empty()).then(|| Zeroizing::new(values.join(", ")))
}

fn remove_header(headers: &mut Vec<(Zeroizing<String>, Zeroizing<String>)>, wanted: &str) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(wanted));
}

fn set_header(
    headers: &mut Vec<(Zeroizing<String>, Zeroizing<String>)>,
    wanted: &str,
    value: String,
) {
    let first = headers
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case(wanted));
    if let Some(first) = first {
        headers[first].1 = Zeroizing::new(value);
        let mut index = first + 1;
        while index < headers.len() {
            if headers[index].0.eq_ignore_ascii_case(wanted) {
                headers.remove(index);
            } else {
                index += 1;
            }
        }
    } else {
        headers.push((Zeroizing::new(wanted.into()), Zeroizing::new(value)));
    }
}

fn curl_command(side: &ExportHttp, body: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let mut command = Zeroizing::new(b"curl".to_vec());
    let mut headers = side.headers.clone();
    remove_header(&mut headers, "content-length");
    let url = command_url(side.url.as_str());
    let host = url_host(url.as_str());
    headers.retain(|(name, value)| {
        let same_host = host.as_ref().map(|host| host.as_str()) == Some(value.as_str());
        !(same_host
            && (name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case(":authority")))
    });
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("accept-encoding") {
            command_arg(&mut command, b"--compressed");
        } else {
            command_arg(&mut command, b"-H");
            let mut header = Zeroizing::new(Vec::new());
            append_latin1(&mut header, name)?;
            header.extend_from_slice(b": ");
            append_latin1(&mut header, value)?;
            command_arg(&mut command, &header);
        }
    }
    let has_content = body.is_some_and(|body| !body.is_empty());
    if side.method.as_str() != "GET" {
        if !has_content {
            command_arg(&mut command, b"-H");
            command_arg(&mut command, b"content-length: 0");
        }
        command_arg(&mut command, b"-X");
        command_arg(&mut command, side.method.as_bytes());
    }
    command_arg(&mut command, url.as_bytes());
    if has_content {
        let text = request_content_for_console(body.unwrap(), &headers)?;
        command.extend_from_slice(b" -d ");
        command.extend_from_slice(&text);
    }
    Ok(command)
}

fn httpie_command(
    side: &ExportHttp,
    body: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let mut command = Zeroizing::new(b"http".to_vec());
    command_arg(&mut command, side.method.as_bytes());
    let mut headers = side.headers.clone();
    remove_header(&mut headers, "content-length");
    let url = command_url(side.url.as_str());
    let host = url_host(url.as_str());
    headers.retain(|(name, value)| {
        let same_host = host.as_ref().map(|host| host.as_str()) == Some(value.as_str());
        !(same_host
            && (name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case(":authority")))
    });
    command_arg(&mut command, url.as_bytes());
    for (name, value) in &headers {
        let mut header = Zeroizing::new(Vec::new());
        append_latin1(&mut header, name)?;
        header.extend_from_slice(b": ");
        append_latin1(&mut header, value)?;
        command_arg(&mut command, &header);
    }
    if body.is_some_and(|body| !body.is_empty()) {
        let text = request_content_for_console(body.unwrap(), &headers)?;
        command.extend_from_slice(b" <<< ");
        command.extend_from_slice(&text);
    }
    Ok(command)
}

fn request_content_for_console(
    body: &[u8],
    headers: &[(Zeroizing<String>, Zeroizing<String>)],
) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let content_type = header_value(headers, "content-type");
    let text = decode_text(body, content_type.as_ref().map(|value| value.as_str()))?;
    let mut escaped = Zeroizing::new(String::new());
    let mut controls = false;
    for character in text.chars() {
        if character.is_ascii() && character < ' ' {
            controls = true;
            write!(escaped, "\\x{:02x}", character as u8).expect("String writes cannot fail");
        } else {
            escaped.push(character);
        }
    }
    let quoted = shell_quote(escaped.as_bytes());
    let mut output = Zeroizing::new(Vec::new());
    if controls {
        output.extend_from_slice(b"\"$(printf ");
        output.extend_from_slice(&quoted);
        output.extend_from_slice(b")\"");
    } else {
        output.extend_from_slice(&quoted);
    }
    Ok(output)
}

#[cfg(test)]
mod har_tests;

pub(crate) fn decode_text(
    body: &[u8],
    content_type: Option<&str>,
) -> Result<Zeroizing<String>, ExportError> {
    let encoding = infer_text_encoding(content_type, body);
    let source_gb18030 =
        encoding.eq_ignore_ascii_case("gbk") || encoding.eq_ignore_ascii_case("gb2312");
    let normalized = normalize_python_codec_label(&encoding);
    match normalized.as_str() {
        "utf" | "utf-8" | "utf8" => decode_utf8(body),
        "utf-8-sig" => decode_utf8(body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body)),
        "ascii" | "us-ascii" | "646" | "ansi-x3.4-1968" | "ansi-x3.4-1986" | "ansi-x3-4-1968"
        | "cp367" | "csascii" | "ibm367" | "iso646-us" | "iso-646.irv-1991" | "iso-ir-6" | "us" => {
            if body.iter().any(|byte| !byte.is_ascii()) {
                return Err(ExportError::Decode);
            }
            decode_utf8(body)
        }
        "utf-16" | "utf16" => {
            if body.starts_with(b"\xff\xfe") {
                decode_utf16(&body[2..], true)
            } else if body.starts_with(b"\xfe\xff") {
                decode_utf16(&body[2..], false)
            } else {
                Err(ExportError::Decode)
            }
        }
        "utf-16le" | "utf16le" | "utf-16-le" => decode_utf16(body, true),
        "utf-16be" | "utf16be" | "utf-16-be" => decode_utf16(body, false),
        "utf-32" | "utf32" => {
            if body.starts_with(b"\xff\xfe\x00\x00") {
                decode_utf32(&body[4..], true)
            } else if body.starts_with(b"\x00\x00\xfe\xff") {
                decode_utf32(&body[4..], false)
            } else {
                Err(ExportError::Decode)
            }
        }
        "utf-32le" | "utf32le" | "utf-32-le" => decode_utf32(body, true),
        "utf-32be" | "utf32be" | "utf-32-be" => decode_utf32(body, false),
        "latin" | "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "cp819" | "ibm819"
        | "iso-ir-100" | "csisolatin1" | "l1" | "8859" | "iso8859" | "iso-8859-1-1987" => Ok(
            Zeroizing::new(body.iter().map(|byte| char::from(*byte)).collect()),
        ),
        _ => decode_legacy_text(&normalized, body, source_gb18030),
    }
}

fn normalize_python_codec_label(label: &str) -> Zeroizing<String> {
    let mut normalized = Zeroizing::new(String::new());
    let mut separator = false;
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            if separator && !normalized.is_empty() {
                normalized.push('-');
            }
            normalized.push(byte.to_ascii_lowercase() as char);
            separator = false;
        } else if byte == b'.' {
            if separator && !normalized.is_empty() {
                normalized.push('-');
            }
            normalized.push('.');
            separator = false;
        } else if byte.is_ascii() {
            separator = true;
        } else {
            normalized.push('\u{fffd}');
            separator = false;
        }
    }
    normalized
}

fn decode_legacy_text(
    label: &str,
    body: &[u8],
    source_gb18030: bool,
) -> Result<Zeroizing<String>, ExportError> {
    if let Some(result) = decode_python_single_byte(label, body) {
        return result;
    }
    if matches!(
        label,
        "shift-jis" | "shiftjis" | "sjis" | "s-jis" | "csshiftjis" | "x-mac-japanese"
    ) {
        return decode_python_shift_jis(body);
    }
    if matches!(label, "932" | "cp932" | "ms932" | "ms-kanji" | "mskanji") {
        return decode_python_cp932(body);
    }
    if matches!(label, "euc-jp" | "eucjp" | "u-jis" | "ujis") {
        return decode_python_euc_jp(body);
    }
    if matches!(label, "gbk" | "gb2312") {
        return if source_gb18030 {
            decode_python_gb18030(body)
        } else {
            decode_python_gbk(body)
        };
    }
    if matches!(label, "gb2312-80" | "gb2312-1980" | "iso-ir-58") {
        return decode_python_gb2312(body);
    }
    if matches!(label, "gb-2312" | "gb-2312-80") {
        // These spellings are not registered by the Python codec registry.
        return Err(ExportError::Decode);
    }
    if matches!(label, "gb18030" | "gb18030-2000") {
        return decode_python_gb18030(body);
    }
    if matches!(label, "936" | "cp936" | "ms936") {
        return decode_python_gbk(body);
    }
    if matches!(label, "big5" | "big5-tw" | "csbig5" | "x-mac-trad-chinese") {
        return decode_python_big5(body);
    }
    // These labels are accepted by encoding_rs through WHATWG aliases whose
    // tables are known to differ from CPython's codecs (or are not CPython
    // labels at all). Returning unavailable is safer than silently changing
    // the captured body text.
    if matches!(
        label,
        "big5-hkscs"
            | "euc-kr"
            | "hz-gb-2312"
            | "iso-2022-jp"
            | "iso-2022-kr"
            | "iso-8859-9"
            | "iso8859-9"
            | "iso-8859-11"
            | "iso8859-11"
    ) {
        return Err(ExportError::Unsupported);
    }
    if let Some(encoding) = encoding_rs_for_python_label(label) {
        return decode_with_encoding(encoding, body);
    }
    if python_codec_is_registered(label) {
        return Err(ExportError::Unsupported);
    }
    Err(ExportError::Decode)
}

const CP874_UNDEFINED: &[u8] = &[
    0x81, 0x82, 0x83, 0x84, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x98,
    0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xdb, 0xdc, 0xdd, 0xde, 0xfc, 0xfd, 0xfe, 0xff,
];
const CP1250_UNDEFINED: &[u8] = &[0x81, 0x83, 0x88, 0x90, 0x98];
const CP1251_UNDEFINED: &[u8] = &[0x98];
const CP1252_UNDEFINED: &[u8] = &[0x81, 0x8d, 0x8f, 0x90, 0x9d];
const CP1253_UNDEFINED: &[u8] = &[
    0x81, 0x88, 0x8a, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x98, 0x9a, 0x9c, 0x9d, 0x9e, 0x9f, 0xaa, 0xd2,
    0xff,
];
const CP1254_UNDEFINED: &[u8] = &[0x81, 0x8d, 0x8e, 0x8f, 0x90, 0x9d, 0x9e];
const CP1255_UNDEFINED: &[u8] = &[
    0x81, 0x8a, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9c, 0x9d, 0x9e, 0x9f, 0xca, 0xd9, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0xfb, 0xfc, 0xff,
];
const CP1257_UNDEFINED: &[u8] = &[
    0x81, 0x83, 0x88, 0x8a, 0x8c, 0x90, 0x98, 0x9a, 0x9c, 0x9f, 0xa1, 0xa5,
];
const CP1258_UNDEFINED: &[u8] = &[0x81, 0x8a, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9d, 0x9e];
const ISO8859_3_UNDEFINED: &[u8] = &[0xa5, 0xae, 0xbe, 0xc3, 0xd0, 0xe3, 0xf0];
const ISO8859_6_UNDEFINED: &[u8] = &[
    0xa1, 0xa2, 0xa3, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
    0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbc, 0xbd, 0xbe, 0xc0, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];
const ISO8859_7_UNDEFINED: &[u8] = &[0xae, 0xd2, 0xff];
const ISO8859_8_UNDEFINED: &[u8] = &[
    0xa1, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
    0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
    0xde, 0xfb, 0xfc, 0xff,
];
const KOI8_U_CORRECTIONS: &[(u8, char)] = &[(0xae, '\u{255d}'), (0xbe, '\u{256c}')];

fn decode_python_single_byte(
    label: &str,
    body: &[u8],
) -> Option<Result<Zeroizing<String>, ExportError>> {
    let (encoding_label, undefined, corrections): (&[u8], &[u8], &[(u8, char)]) = match label {
        "cp874" => (b"windows-874", CP874_UNDEFINED, &[]),
        "cp866" | "866" | "csibm866" | "ibm866" => (b"ibm866", &[], &[]),
        "mac-roman" | "macintosh" | "macroman" => (b"macintosh", &[], &[]),
        "mac-cyrillic" | "maccyrillic" => (b"x-mac-cyrillic", &[], &[]),
        "koi8-r" | "cskoi8r" => (b"koi8-r", &[], &[]),
        "koi8-u" => (b"koi8-u", &[], KOI8_U_CORRECTIONS),
        "cp1250" | "1250" | "windows-1250" => (b"windows-1250", CP1250_UNDEFINED, &[]),
        "cp1251" | "1251" | "windows-1251" => (b"windows-1251", CP1251_UNDEFINED, &[]),
        "cp1252" | "1252" | "windows-1252" => (b"windows-1252", CP1252_UNDEFINED, &[]),
        "cp1253" | "1253" | "windows-1253" => (b"windows-1253", CP1253_UNDEFINED, &[]),
        "cp1254" | "1254" | "windows-1254" => (b"windows-1254", CP1254_UNDEFINED, &[]),
        "cp1255" | "1255" | "windows-1255" => (b"windows-1255", CP1255_UNDEFINED, &[]),
        "cp1256" | "1256" | "windows-1256" => (b"windows-1256", &[], &[]),
        "cp1257" | "1257" | "windows-1257" => (b"windows-1257", CP1257_UNDEFINED, &[]),
        "cp1258" | "1258" | "windows-1258" => (b"windows-1258", CP1258_UNDEFINED, &[]),
        "iso-8859-2" | "iso8859-2" | "iso-8859-2-1987" | "iso-ir-101" | "csisolatin2" | "l2"
        | "latin2" => (b"iso-8859-2", &[], &[]),
        "iso-8859-3" | "iso8859-3" | "iso-8859-3-1988" | "iso-ir-109" | "csisolatin3" | "l3"
        | "latin3" => (b"iso-8859-3", ISO8859_3_UNDEFINED, &[]),
        "iso-8859-4" | "iso8859-4" | "iso-8859-4-1988" | "iso-ir-110" | "csisolatin4" | "l4"
        | "latin4" => (b"iso-8859-4", &[], &[]),
        "iso-8859-5" | "iso8859-5" | "iso-8859-5-1988" | "iso-ir-144" | "csisolatincyrillic"
        | "cyrillic" => (b"iso-8859-5", &[], &[]),
        "iso-8859-6" | "iso8859-6" | "iso-8859-6-1987" | "iso-ir-127" | "arabic" | "asmo-708"
        | "csisolatinarabic" | "ecma-114" => (b"iso-8859-6", ISO8859_6_UNDEFINED, &[]),
        "iso-8859-7" | "iso8859-7" | "iso-8859-7-1987" | "iso-ir-126" | "csisolatingreek"
        | "ecma-118" | "elot-928" | "greek" | "greek8" => (b"iso-8859-7", ISO8859_7_UNDEFINED, &[]),
        "iso-8859-8" | "iso8859-8" | "iso-8859-8-1988" | "iso-ir-138" | "csisolatinhebrew"
        | "hebrew" => (b"iso-8859-8", ISO8859_8_UNDEFINED, &[]),
        "iso-8859-10" | "iso8859-10" | "iso-8859-10-1992" | "iso-ir-157" | "csisolatin6" | "l6"
        | "latin6" => (b"iso-8859-10", &[], &[]),
        "iso-8859-13" | "iso8859-13" | "l7" | "latin7" => (b"iso-8859-13", &[], &[]),
        "iso-8859-14" | "iso8859-14" | "iso-8859-14-1998" | "iso-ir-199" | "iso-celtic" | "l8"
        | "latin8" => (b"iso-8859-14", &[], &[]),
        "iso-8859-15" | "iso8859-15" | "l9" | "latin9" => (b"iso-8859-15", &[], &[]),
        "iso-8859-16" | "iso8859-16" | "iso-8859-16-2001" | "iso-ir-226" | "l10" | "latin10" => {
            (b"iso-8859-16", &[], &[])
        }
        _ => return None,
    };
    let encoding = match Encoding::for_label_no_replacement(encoding_label) {
        Some(encoding) => encoding,
        None => return Some(Err(ExportError::Unsupported)),
    };
    if body.iter().any(|byte| undefined.contains(byte)) {
        return Some(Err(ExportError::Decode));
    }
    if corrections.is_empty() {
        return Some(decode_with_encoding(encoding, body));
    }
    let capacity = match encoding
        .new_decoder_without_bom_handling()
        .max_utf8_buffer_length_without_replacement(body.len())
    {
        Some(capacity) => capacity,
        None => return Some(Err(ExportError::Allocation)),
    };
    let mut decoded = Zeroizing::new(String::new());
    if decoded.try_reserve(capacity).is_err() {
        return Some(Err(ExportError::Allocation));
    }
    for byte in body {
        if let Some((_, character)) = corrections.iter().find(|(source, _)| source == byte) {
            decoded.push(*character);
        } else {
            let segment = match decode_with_encoding(encoding, std::slice::from_ref(byte)) {
                Ok(segment) => segment,
                Err(error) => return Some(Err(error)),
            };
            decoded.push_str(&segment);
        }
    }
    Some(Ok(decoded))
}

fn decode_python_gbk(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            offset += 1;
            continue;
        }
        if !(0x81..=0xfe).contains(&byte) {
            return Err(ExportError::Decode);
        }
        let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
        if !gbk_pair_is_defined(byte, trail) {
            return Err(ExportError::Decode);
        }
        offset += 2;
    }
    let encoding = Encoding::for_label_no_replacement(b"gbk").ok_or(ExportError::Unsupported)?;
    decode_with_encoding(encoding, body)
}

fn decode_python_big5(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    let encoding = Encoding::for_label_no_replacement(b"big5").ok_or(ExportError::Unsupported)?;
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(
            encoding
                .new_decoder_without_bom_handling()
                .max_utf8_buffer_length_without_replacement(body.len())
                .ok_or(ExportError::Allocation)?,
        )
        .map_err(|_| ExportError::Allocation)?;
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            decoded.push(byte as char);
            offset += 1;
            continue;
        }
        let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
        if !big5_pair_is_defined(byte, trail) {
            return Err(ExportError::Decode);
        }
        let character = big5_correction(byte, trail);
        if let Some(character) = character {
            decoded.push(character);
        } else {
            let segment = decode_with_encoding(encoding, &body[offset..offset + 2])?;
            decoded.push_str(&segment);
        }
        offset += 2;
    }
    Ok(decoded)
}

fn big5_pair_is_defined(lead: u8, trail: u8) -> bool {
    if !(0xa1..=0xf9).contains(&lead) || lead == 0xc8 {
        return false;
    }
    if (0x40..=0x7e).contains(&trail) {
        return true;
    }
    let last = match lead {
        0xa3 => 0xbf,
        0xc7 => 0xfc,
        0xf9 => 0xd5,
        _ => 0xfe,
    };
    (0xa1..=last).contains(&trail)
}

fn decode_python_gb2312(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    let encoding = Encoding::for_label_no_replacement(b"gbk").ok_or(ExportError::Unsupported)?;
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(
            encoding
                .new_decoder_without_bom_handling()
                .max_utf8_buffer_length_without_replacement(body.len())
                .ok_or(ExportError::Allocation)?,
        )
        .map_err(|_| ExportError::Allocation)?;
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            decoded.push(byte as char);
            offset += 1;
            continue;
        }
        let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
        if !gb2312_pair_is_defined(byte, trail) {
            return Err(ExportError::Decode);
        }
        let pair = &body[offset..offset + 2];
        let character = match pair {
            [0xa1, 0xa4] => '\u{30fb}',
            [0xa1, 0xaa] => '\u{2015}',
            _ => {
                let segment = decode_with_encoding(encoding, pair)?;
                decoded.push_str(&segment);
                offset += 2;
                continue;
            }
        };
        decoded.push(character);
        offset += 2;
    }
    Ok(decoded)
}

fn decode_python_gb18030(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    reject_standalone_chinese_80(body)?;
    let encoding =
        Encoding::for_label_no_replacement(b"gb18030").ok_or(ExportError::Unsupported)?;
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(
            encoding
                .new_decoder_without_bom_handling()
                .max_utf8_buffer_length_without_replacement(body.len())
                .ok_or(ExportError::Allocation)?,
        )
        .map_err(|_| ExportError::Allocation)?;
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            decoded.push(byte as char);
            offset += 1;
            continue;
        }
        if (0x81..=0xfe).contains(&byte) {
            if let Some(sequence) = body.get(offset..offset + 4).filter(|sequence| {
                (0x30..=0x39).contains(&sequence[1])
                    && (0x81..=0xfe).contains(&sequence[2])
                    && (0x30..=0x39).contains(&sequence[3])
            }) {
                let replacement = match sequence {
                    [0x81, 0x35, 0xf4, 0x37] => Some('\u{1e3f}'),
                    _ => None,
                };
                if let Some(character) = replacement {
                    decoded.push(character);
                } else {
                    let segment = decode_with_encoding(encoding, sequence)?;
                    decoded.push_str(&segment);
                }
                offset += 4;
                continue;
            }
            let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
            if !(0x40..=0x7e).contains(&trail) && !(0x80..=0xfe).contains(&trail) {
                return Err(ExportError::Decode);
            }
            let pair = &body[offset..offset + 2];
            let replacement = match pair {
                [0xa3, 0xa0] => Some('\u{e5e5}'),
                [0xa6, 0xd9] => Some('\u{e78d}'),
                [0xa6, 0xda] => Some('\u{e78e}'),
                [0xa6, 0xdb] => Some('\u{e78f}'),
                [0xa6, 0xdc] => Some('\u{e790}'),
                [0xa6, 0xdd] => Some('\u{e791}'),
                [0xa6, 0xde] => Some('\u{e792}'),
                [0xa6, 0xdf] => Some('\u{e793}'),
                [0xa6, 0xec] => Some('\u{e794}'),
                [0xa6, 0xed] => Some('\u{e795}'),
                [0xa6, 0xf3] => Some('\u{e796}'),
                [0xa8, 0xbc] => Some('\u{e7c7}'),
                [0xfe, 0x59] => Some('\u{e81e}'),
                [0xfe, 0x61] => Some('\u{e826}'),
                [0xfe, 0x66] => Some('\u{e82b}'),
                [0xfe, 0x67] => Some('\u{e82c}'),
                [0xfe, 0x6d] => Some('\u{e832}'),
                [0xfe, 0x7e] => Some('\u{e843}'),
                [0xfe, 0x90] => Some('\u{e854}'),
                [0xfe, 0xa0] => Some('\u{e864}'),
                _ => None,
            };
            if let Some(character) = replacement {
                decoded.push(character);
            } else {
                let segment = decode_with_encoding(encoding, pair)?;
                decoded.push_str(&segment);
            }
            offset += 2;
        } else {
            return Err(ExportError::Decode);
        }
    }
    Ok(decoded)
}

fn reject_standalone_chinese_80(body: &[u8]) -> Result<(), ExportError> {
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte == 0x80 {
            return Err(ExportError::Decode);
        }
        if byte <= 0x7f {
            offset += 1;
        } else if (0x81..=0xfe).contains(&byte)
            && body
                .get(offset + 1)
                .is_some_and(|trail| (0x40..=0x7e).contains(trail) || (0x80..=0xfe).contains(trail))
        {
            offset += 2;
        } else {
            offset += 1;
        }
    }
    Ok(())
}

fn matches_byte_ranges(byte: u8, ranges: &[(u8, u8)]) -> bool {
    ranges
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&byte))
}

fn gbk_pair_is_defined(lead: u8, trail: u8) -> bool {
    if !(0x81..=0xfe).contains(&lead) {
        return false;
    }
    match lead {
        0x81..=0xa0 | 0xb0..=0xd6 | 0xd8..=0xf7 => {
            matches_byte_ranges(trail, &[(0x40, 0x7e), (0x80, 0xfe)])
        }
        0xa1 | 0xa3 => (0xa1..=0xfe).contains(&trail),
        0xa2 => matches_byte_ranges(
            trail,
            &[(0xa1, 0xaa), (0xb1, 0xe2), (0xe5, 0xee), (0xf1, 0xfc)],
        ),
        0xa4 => (0xa1..=0xf3).contains(&trail),
        0xa5 => (0xa1..=0xf6).contains(&trail),
        0xa6 => matches_byte_ranges(
            trail,
            &[
                (0xa1, 0xb8),
                (0xc1, 0xd8),
                (0xe0, 0xeb),
                (0xee, 0xf2),
                (0xf4, 0xf5),
            ],
        ),
        0xa7 => matches_byte_ranges(trail, &[(0xa1, 0xc1), (0xd1, 0xf1)]),
        0xa8 => matches_byte_ranges(
            trail,
            &[
                (0x40, 0x7e),
                (0x80, 0x95),
                (0xa1, 0xbb),
                (0xbd, 0xbe),
                (0xc0, 0xc0),
                (0xc5, 0xe9),
            ],
        ),
        0xa9 => matches_byte_ranges(
            trail,
            &[
                (0x40, 0x57),
                (0x59, 0x5a),
                (0x5c, 0x5c),
                (0x60, 0x7e),
                (0x80, 0x88),
                (0x96, 0x96),
                (0xa4, 0xef),
            ],
        ),
        0xaa..=0xaf => matches_byte_ranges(trail, &[(0x40, 0x7e), (0x80, 0xa0)]),
        0xd7 => matches_byte_ranges(trail, &[(0x40, 0x7e), (0x80, 0xf9)]),
        0xf8..=0xfd => matches_byte_ranges(trail, &[(0x40, 0x7e), (0x80, 0xa0)]),
        0xfe => (0x40..=0x4f).contains(&trail),
        _ => false,
    }
}

fn gb2312_pair_is_defined(lead: u8, trail: u8) -> bool {
    if !(0xa1..=0xf7).contains(&lead) || !(0xa1..=0xfe).contains(&trail) {
        return false;
    }
    match lead {
        0xa1 | 0xa3 | 0xb0..=0xd6 | 0xd8..=0xf7 => true,
        0xa2 => matches_byte_ranges(trail, &[(0xb1, 0xe2), (0xe5, 0xee), (0xf1, 0xfc)]),
        0xa4 => (0xa1..=0xf3).contains(&trail),
        0xa5 => (0xa1..=0xf6).contains(&trail),
        0xa6 => matches_byte_ranges(trail, &[(0xa1, 0xb8), (0xc1, 0xd8)]),
        0xa7 => matches_byte_ranges(trail, &[(0xa1, 0xc1), (0xd1, 0xf1)]),
        0xa8 => matches_byte_ranges(trail, &[(0xa1, 0xba), (0xc5, 0xe9)]),
        0xa9 => (0xa4..=0xef).contains(&trail),
        0xd7 => (0xa1..=0xf9).contains(&trail),
        _ => false,
    }
}

fn decode_with_encoding(
    encoding: &'static Encoding,
    body: &[u8],
) -> Result<Zeroizing<String>, ExportError> {
    let mut decoder = encoding.new_decoder_without_bom_handling();
    let capacity = decoder
        .max_utf8_buffer_length_without_replacement(body.len())
        .ok_or(ExportError::Allocation)?;
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(capacity)
        .map_err(|_| ExportError::Allocation)?;
    let (result, read) = decoder.decode_to_string_without_replacement(body, &mut decoded, true);
    match result {
        DecoderResult::InputEmpty if read == body.len() => Ok(decoded),
        DecoderResult::OutputFull => Err(ExportError::Allocation),
        DecoderResult::Malformed(..) | DecoderResult::InputEmpty => Err(ExportError::Decode),
    }
}

fn decode_python_shift_jis(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    let encoding =
        Encoding::for_label_no_replacement(b"shift_jis").ok_or(ExportError::Unsupported)?;
    let mut decoded = Zeroizing::new(String::new());
    let capacity = encoding
        .new_decoder_without_bom_handling()
        .max_utf8_buffer_length_without_replacement(body.len())
        .ok_or(ExportError::Allocation)?;
    decoded
        .try_reserve(capacity)
        .map_err(|_| ExportError::Allocation)?;

    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            decoded.push(byte as char);
            offset += 1;
            continue;
        }
        if (0xa1..=0xdf).contains(&byte) {
            decoded
                .push(char::from_u32(0xff61 + u32::from(byte - 0xa1)).ok_or(ExportError::Decode)?);
            offset += 1;
            continue;
        }
        if !matches!(byte, 0x81..=0x9f | 0xe0..=0xef) || matches!(byte, 0x85..=0x87 | 0xeb..=0xef) {
            return Err(ExportError::Decode);
        }
        let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
        if !(0x40..=0x7e).contains(&trail) && !(0x80..=0xfc).contains(&trail) {
            return Err(ExportError::Decode);
        }
        let pair = &body[offset..offset + 2];
        let replacement = match pair {
            [0x81, 0x60] => Some('\u{301c}'),
            [0x81, 0x61] => Some('\u{2016}'),
            [0x81, 0x7c] => Some('\u{2212}'),
            [0x81, 0x91] => Some('\u{00a2}'),
            [0x81, 0x92] => Some('\u{00a3}'),
            [0x81, 0xca] => Some('\u{00ac}'),
            _ => None,
        };
        if let Some(character) = replacement {
            decoded.push(character);
        } else {
            let segment = decode_with_encoding(encoding, pair)?;
            decoded.push_str(&segment);
        }
        offset += 2;
    }
    Ok(decoded)
}

fn decode_python_cp932(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    let encoding =
        Encoding::for_label_no_replacement(b"windows-31j").ok_or(ExportError::Unsupported)?;
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(
            encoding
                .new_decoder_without_bom_handling()
                .max_utf8_buffer_length_without_replacement(body.len())
                .ok_or(ExportError::Allocation)?,
        )
        .map_err(|_| ExportError::Allocation)?;
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            decoded.push(byte as char);
            offset += 1;
            continue;
        }
        if byte == 0x80 {
            decoded.push('\u{80}');
            offset += 1;
            continue;
        }
        if (0xa1..=0xdf).contains(&byte) {
            decoded
                .push(char::from_u32(0xff61 + u32::from(byte - 0xa1)).ok_or(ExportError::Decode)?);
            offset += 1;
            continue;
        }
        if byte == 0xa0 {
            decoded.push('\u{f8f0}');
            offset += 1;
            continue;
        }
        if (0xfd..=0xff).contains(&byte) {
            decoded.push(char::from_u32(0xf8f1 + u32::from(byte - 0xfd)).unwrap());
            offset += 1;
            continue;
        }
        if !matches!(byte, 0x81..=0x9f | 0xe0..=0xfc) {
            return Err(ExportError::Decode);
        }
        let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
        if !(0x40..=0x7e).contains(&trail) && !(0x80..=0xfc).contains(&trail) {
            return Err(ExportError::Decode);
        }
        let segment = decode_with_encoding(encoding, &body[offset..offset + 2])?;
        decoded.push_str(&segment);
        offset += 2;
    }
    Ok(decoded)
}

const EUC_JP_CORRECTIONS: &[(&[u8], char)] = &[
    (b"\x8f\xa2\xb7", '~'),
    (b"\xa1\xc1", '\u{301c}'),
    (b"\xa1\xc2", '\u{2016}'),
    (b"\xa1\xdd", '\u{2212}'),
    (b"\xa1\xf1", '\u{00a2}'),
    (b"\xa1\xf2", '\u{00a3}'),
    (b"\xa2\xcc", '\u{00ac}'),
];

fn euc_jp_pair_is_defined(lead: u8, trail: u8) -> bool {
    if !(0xa1..=0xfe).contains(&lead) || !(0xa1..=0xfe).contains(&trail) {
        return false;
    }
    match lead {
        0xa1 | 0xb0..=0xce | 0xd0..=0xf3 => true,
        0xa2 => matches_byte_ranges(
            trail,
            &[
                (0xa1, 0xae),
                (0xba, 0xc1),
                (0xca, 0xd0),
                (0xdc, 0xea),
                (0xf2, 0xf9),
                (0xfe, 0xfe),
            ],
        ),
        0xa3 => matches_byte_ranges(trail, &[(0xb0, 0xb9), (0xc1, 0xda), (0xe1, 0xfa)]),
        0xa4 => (0xa1..=0xf3).contains(&trail),
        0xa5 => (0xa1..=0xf6).contains(&trail),
        0xa6 => matches_byte_ranges(trail, &[(0xa1, 0xb8), (0xc1, 0xd8)]),
        0xa7 => matches_byte_ranges(trail, &[(0xa1, 0xc1), (0xd1, 0xf1)]),
        0xa8 => (0xa1..=0xc0).contains(&trail),
        0xcf => (0xa1..=0xd3).contains(&trail),
        0xf4 => (0xa1..=0xa6).contains(&trail),
        _ => false,
    }
}

fn decode_python_euc_jp(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    let encoding = Encoding::for_label_no_replacement(b"euc-jp").ok_or(ExportError::Unsupported)?;
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(
            encoding
                .new_decoder_without_bom_handling()
                .max_utf8_buffer_length_without_replacement(body.len())
                .ok_or(ExportError::Allocation)?,
        )
        .map_err(|_| ExportError::Allocation)?;
    let mut offset = 0;
    while offset < body.len() {
        let byte = body[offset];
        if byte <= 0x7f {
            decoded.push(byte as char);
            offset += 1;
            continue;
        }
        let length = if byte == 0x8e {
            let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
            if !(0xa1..=0xdf).contains(&trail) {
                return Err(ExportError::Decode);
            }
            2
        } else if byte == 0x8f {
            let first = *body.get(offset + 1).ok_or(ExportError::Decode)?;
            let second = *body.get(offset + 2).ok_or(ExportError::Decode)?;
            if !(0xa1..=0xfe).contains(&first) || !(0xa1..=0xfe).contains(&second) {
                return Err(ExportError::Decode);
            }
            3
        } else if (0xa1..=0xfe).contains(&byte) {
            let trail = *body.get(offset + 1).ok_or(ExportError::Decode)?;
            if !euc_jp_pair_is_defined(byte, trail) {
                return Err(ExportError::Decode);
            }
            2
        } else {
            return Err(ExportError::Decode);
        };
        let sequence = &body[offset..offset + length];
        if let Some((_, character)) = EUC_JP_CORRECTIONS
            .iter()
            .find(|(source, _)| *source == sequence)
        {
            decoded.push(*character);
        } else {
            let segment = decode_with_encoding(encoding, sequence)?;
            decoded.push_str(&segment);
        }
        offset += length;
    }
    Ok(decoded)
}

fn encoding_rs_for_python_label(label: &str) -> Option<&'static Encoding> {
    // Keep this table explicit. encoding_rs also accepts web-only aliases and
    // aliases whose WHATWG tables differ from the CPython codec named by the
    // installed source. Single-byte codecs are handled by the table above,
    // which additionally enforces Python's undefined-byte rules.
    let canonical = match label {
        "932" | "cp932" | "ms932" | "ms-kanji" | "mskanji" => "windows-31j",
        "cp949" | "949" => "windows-949",
        "euc-jp" | "eucjp" | "u-jis" | "ujis" => "euc-jp",
        _ => return None,
    };
    Encoding::for_label_no_replacement(canonical.as_bytes())
}

fn infer_text_encoding(content_type: Option<&str>, body: &[u8]) -> Zeroizing<String> {
    let encoding = if body.starts_with(b"\x00\x00\xfe\xff") {
        "utf-32be".into()
    } else if body.starts_with(b"\xff\xfe\x00\x00") {
        "utf-32le".into()
    } else if body.starts_with(b"\xfe\xff") {
        "utf-16be".into()
    } else if body.starts_with(b"\xff\xfe") {
        "utf-16le".into()
    } else if body.starts_with(b"\xef\xbb\xbf") {
        "utf-8-sig".into()
    } else if let Some(content_type) = content_type {
        let lowered = Zeroizing::new(content_type.to_ascii_lowercase());
        let charset = content_type.split(';').skip(1).find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("charset")
                .then(|| value.trim().trim_matches('"').to_owned())
        });
        charset.unwrap_or_else(|| {
            if lowered.contains("json") {
                "utf8".into()
            } else if lowered.contains("html") {
                markup_charset(body, MarkupKind::Html).unwrap_or_else(|| "utf8".into())
            } else if lowered.contains("xml") {
                markup_charset(body, MarkupKind::Xml).unwrap_or_else(|| "utf8".into())
            } else if lowered.contains("javascript") || lowered.contains("ecmascript") {
                "utf8".into()
            } else if lowered.contains("text/css") {
                markup_charset(body, MarkupKind::Css).unwrap_or_else(|| "utf8".into())
            } else {
                "latin-1".into()
            }
        })
    } else {
        "latin-1".into()
    };
    Zeroizing::new(encoding)
}

enum MarkupKind {
    Html,
    Xml,
    Css,
}

fn markup_charset(body: &[u8], kind: MarkupKind) -> Option<String> {
    let pattern: &[u8] = match kind {
        MarkupKind::Html => br#"(?i)<meta[^>]+charset=['\"]?([^'\">]+)"#,
        MarkupKind::Xml => br#"(?i)<\?xml[^\?>]+encoding=['\"]([^'\"\?>]+)"#,
        MarkupKind::Css => br#"(?i)^@charset \"([^\"]+)\";"#,
    };
    regex::bytes::Regex::new(std::str::from_utf8(pattern).unwrap())
        .ok()?
        .captures(body)
        .and_then(|captures| captures.get(1))
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn decode_utf16(body: &[u8], little: bool) -> Result<Zeroizing<String>, ExportError> {
    if !body.len().is_multiple_of(2) {
        return Err(ExportError::Decode);
    }
    let units = Zeroizing::new(
        body.chunks_exact(2)
            .map(|chunk| {
                if little {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                }
            })
            .collect::<Vec<_>>(),
    );
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(units.len().saturating_mul(4))
        .map_err(|_| ExportError::Allocation)?;
    for character in char::decode_utf16(units.iter().copied()) {
        decoded.push(character.map_err(|_| ExportError::Decode)?);
    }
    Ok(decoded)
}

fn decode_utf8(body: &[u8]) -> Result<Zeroizing<String>, ExportError> {
    match String::from_utf8(body.to_vec()) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(ExportError::Decode)
        }
    }
}

fn decode_utf32(body: &[u8], little: bool) -> Result<Zeroizing<String>, ExportError> {
    if !body.len().is_multiple_of(4) {
        return Err(ExportError::Decode);
    }
    let codepoints = Zeroizing::new(
        body.chunks_exact(4)
            .map(|chunk| {
                if little {
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                } else {
                    u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                }
            })
            .collect::<Vec<_>>(),
    );
    let mut decoded = Zeroizing::new(String::new());
    decoded
        .try_reserve(codepoints.len().saturating_mul(4))
        .map_err(|_| ExportError::Allocation)?;
    for codepoint in codepoints.iter().copied() {
        decoded.push(char::from_u32(codepoint).ok_or(ExportError::Decode)?);
    }
    Ok(decoded)
}

fn command_arg(command: &mut Vec<u8>, value: &[u8]) {
    command.push(b' ');
    command.extend_from_slice(&shell_quote(value));
}

fn shell_quote(value: &[u8]) -> Zeroizing<Vec<u8>> {
    if !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(byte))
    {
        return Zeroizing::new(value.to_vec());
    }
    let mut quoted = Zeroizing::new(Vec::with_capacity(value.len() + 2));
    quoted.push(b'\'');
    for byte in value {
        if *byte == b'\'' {
            quoted.extend_from_slice(b"'\"'\"'");
        } else {
            quoted.push(*byte);
        }
    }
    quoted.push(b'\'');
    quoted
}

fn url_host(url: &str) -> Option<Zeroizing<String>> {
    let authority = url.split_once("://")?.1.split('/').next()?;
    Some(Zeroizing::new(
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
            .to_owned(),
    ))
}

fn command_url(url: &str) -> Zeroizing<String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Zeroizing::new(url.to_owned());
    };
    let slash = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(slash);
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        Some(":80")
    } else if scheme.eq_ignore_ascii_case("https") {
        Some(":443")
    } else {
        None
    };
    let Some(port) = default_port.filter(|port| authority.ends_with(port)) else {
        return Zeroizing::new(url.to_owned());
    };
    Zeroizing::new(format!(
        "{scheme}://{}{}",
        &authority[..authority.len() - port.len()],
        path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_export_big5_pair_domain_accepts_every_source_defined_pair() {
        let encoding = Encoding::for_label_no_replacement(b"big5").unwrap();
        let mut defined = 0;
        let mut source_sequences = 0;
        let mut corrected = 0;
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                if first <= 0x7f {
                    if second <= 0x7f {
                        source_sequences += 1;
                    }
                    continue;
                }
                if !big5_pair_is_defined(first, second) {
                    continue;
                }
                source_sequences += 1;
                defined += 1;
                if big5_correction(first, second).is_some() {
                    corrected += 1;
                } else {
                    assert!(decode_with_encoding(encoding, &[first, second]).is_ok());
                }
            }
        }
        assert_eq!(defined, 13_710);
        assert_eq!(source_sequences, 30_094);
        assert_eq!(corrected, 260);
    }
}
