//! Bounded source-shaped selected-flow export.
//!
//! The parent view only snapshots owners under its mutex. Rendering and retained
//! message reads happen after that lock has been released.

use std::{fmt::Write as _, sync::Arc};

use zeroize::{Zeroize, Zeroizing};

use super::{Body, Row};

const EXPORT_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportFormat {
    Raw,
    RawRequest,
    RawResponse,
    Curl,
    Httpie,
}

impl ExportFormat {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "raw" => Self::Raw,
            "raw_request" => Self::RawRequest,
            "raw_response" => Self::RawResponse,
            "curl" => Self::Curl,
            "httpie" => Self::Httpie,
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
    messages: Vec<(bool, Arc<crate::websocket::MessageContent>)>,
}

pub(super) struct ExportSnapshot {
    request: ExportHttp,
    response: Option<ExportHttp>,
    websocket: Option<ExportWebsocket>,
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
}

/// A preflighted source-shaped export. Parts retain immutable content owners;
/// no complete transcript or rendered archive is held in one response buffer.
pub(crate) struct ExportPlan {
    format: ExportFormat,
    parts: Vec<ExportPart>,
    position: usize,
}

impl ExportPlan {
    pub(crate) fn format(&self) -> ExportFormat {
        self.format
    }

    /// Called by the private response worker. A storage failure after headers
    /// have been sent becomes a body error, so the response cannot claim a
    /// successfully completed artifact.
    pub(crate) fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, ExportError> {
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
            }
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
        }
        Ok(Self {
            format,
            parts,
            position: 0,
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
                messages: session.filter_messages(),
            }),
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
    for (position, (from_client, content)) in websocket.messages.into_iter().enumerate() {
        if position != 0 {
            push_static(parts, b"\n");
        }
        push_static(
            parts,
            if from_client {
                b"[OUTGOING] "
            } else {
                b"[INCOMING] "
            },
        );
        parts.push(ExportPart::Message { content, offset: 0 });
    }
}

fn push_static(parts: &mut Vec<ExportPart>, bytes: &'static [u8]) {
    parts.push(ExportPart::Bytes {
        data: Zeroizing::new(bytes.to_vec()),
        offset: 0,
    });
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

fn decode_text(body: &[u8], content_type: Option<&str>) -> Result<Zeroizing<String>, ExportError> {
    let encoding = infer_text_encoding(content_type, body);
    let normalized = Zeroizing::new(encoding.to_ascii_lowercase());
    match normalized.as_str() {
        "utf-8" | "utf8" => decode_utf8(body),
        "utf-8-sig" => decode_utf8(body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body)),
        "ascii" | "us-ascii" => {
            if body.iter().any(|byte| !byte.is_ascii()) {
                return Err(ExportError::Decode);
            }
            decode_utf8(body)
        }
        "utf-16" => {
            if body.starts_with(b"\xff\xfe") {
                decode_utf16(&body[2..], true)
            } else if body.starts_with(b"\xfe\xff") {
                decode_utf16(&body[2..], false)
            } else {
                Err(ExportError::Decode)
            }
        }
        "utf-16le" | "utf16le" => decode_utf16(body, true),
        "utf-16be" | "utf16be" => decode_utf16(body, false),
        "utf-32" => {
            if body.starts_with(b"\xff\xfe\x00\x00") {
                decode_utf32(&body[4..], true)
            } else if body.starts_with(b"\x00\x00\xfe\xff") {
                decode_utf32(&body[4..], false)
            } else {
                Err(ExportError::Decode)
            }
        }
        "utf-32le" | "utf32le" => decode_utf32(body, true),
        "utf-32be" | "utf32be" => decode_utf32(body, false),
        "latin-1" | "latin1" | "iso-8859-1" => Ok(Zeroizing::new(
            body.iter().map(|byte| char::from(*byte)).collect(),
        )),
        _ => Err(ExportError::Unsupported),
    }
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
