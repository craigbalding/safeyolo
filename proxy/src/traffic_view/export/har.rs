//! Selected-flow HAR serialization with incremental retained-message reads.

use std::{str, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    http_content::ContentError,
    websocket::{MessageContent, MessageType},
};

use super::{ExportError, ExportHttp, ExportPart, ExportSnapshot};

const MESSAGE_CHUNK: usize = 4096;

pub(super) struct MessagePart {
    content: Arc<MessageContent>,
    offset: u64,
    pending: Zeroizing<Vec<u8>>,
    binary: bool,
    finished: bool,
}

impl MessagePart {
    fn new(content: Arc<MessageContent>, binary: bool) -> Self {
        Self {
            content,
            offset: 0,
            pending: Zeroizing::new(Vec::new()),
            binary,
            finished: false,
        }
    }
}

pub(super) fn message_chunk(
    part: &mut MessagePart,
) -> Result<Option<Zeroizing<Vec<u8>>>, ExportError> {
    if part.finished {
        return Ok(None);
    }
    loop {
        let total = part.content.len();
        if part.offset < total {
            let chunk = Zeroizing::new(
                part.content
                    .read_range(part.offset, MESSAGE_CHUNK)
                    .map_err(|_| ExportError::Storage)?,
            );
            if chunk.is_empty() {
                return Err(ExportError::Storage);
            }
            part.offset = part.offset.saturating_add(chunk.len() as u64);
            if part.binary {
                let mut input = std::mem::take(&mut part.pending);
                input.extend_from_slice(&chunk);
                let complete = input.len() / 3 * 3;
                part.pending.extend_from_slice(&input[complete..]);
                let mut output = Zeroizing::new(Vec::new());
                output
                    .try_reserve(complete.div_ceil(3) * 4)
                    .map_err(|_| ExportError::Allocation)?;
                output.resize(complete.div_ceil(3) * 4, 0);
                STANDARD
                    .encode_slice(&input[..complete], &mut output)
                    .map_err(|_| ExportError::Unsupported)?;
                input.zeroize();
                if !output.is_empty() {
                    return Ok(Some(output));
                }
            } else {
                let mut input = std::mem::take(&mut part.pending);
                input.extend_from_slice(&chunk);
                let (valid, pending) = match str::from_utf8(&input) {
                    Ok(text) => {
                        let mut output = Zeroizing::new(Vec::new());
                        append_json_chars(&mut output, text);
                        (output, Zeroizing::new(Vec::new()))
                    }
                    Err(error) => {
                        let valid_up_to = error.valid_up_to();
                        let mut output = Zeroizing::new(Vec::new());
                        append_json_chars(
                            &mut output,
                            str::from_utf8(&input[..valid_up_to]).expect("valid UTF-8 prefix"),
                        );
                        if error.error_len().is_none() {
                            (output, super::copy_bytes(&input[valid_up_to..]))
                        } else {
                            input.zeroize();
                            return Err(ExportError::Decode);
                        }
                    }
                };
                part.pending = pending;
                input.zeroize();
                if !valid.is_empty() {
                    return Ok(Some(valid));
                }
            }
            continue;
        }
        if part.binary {
            if !part.pending.is_empty() {
                let pending = std::mem::take(&mut part.pending);
                let mut output = Zeroizing::new(Vec::with_capacity(pending.len().div_ceil(3) * 4));
                output.resize(pending.len().div_ceil(3) * 4, 0);
                STANDARD
                    .encode_slice(&pending, &mut output)
                    .map_err(|_| ExportError::Unsupported)?;
                part.finished = true;
                return Ok(Some(output));
            }
        } else if !part.pending.is_empty() {
            part.pending.zeroize();
            return Err(ExportError::Decode);
        }
        part.finished = true;
        return Ok(None);
    }
}

struct Builder {
    parts: Vec<ExportPart>,
    stack: Vec<Frame>,
}

struct Frame {
    depth: usize,
    first: bool,
    array: bool,
}

impl Builder {
    fn new() -> Self {
        Self {
            parts: Vec::new(),
            stack: Vec::new(),
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.parts.push(ExportPart::Bytes {
                data: Zeroizing::new(bytes.to_vec()),
                offset: 0,
            });
        }
    }

    fn object(&mut self) {
        self.raw(b"{");
        self.stack.push(Frame {
            depth: self.stack.len(),
            first: true,
            array: false,
        });
    }

    fn array(&mut self) {
        self.raw(b"[");
        self.stack.push(Frame {
            depth: self.stack.len(),
            first: true,
            array: true,
        });
    }

    fn item_prefix(&mut self) {
        let (depth, first) = {
            let frame = self.stack.last_mut().expect("JSON container");
            let first = frame.first;
            frame.first = false;
            (frame.depth, first)
        };
        if !first {
            self.raw(b",");
        }
        self.raw(b"\n");
        self.indent(depth + 1);
    }

    fn field(&mut self, name: &str) {
        let frame = self.stack.last().expect("JSON object");
        assert!(!frame.array, "field in JSON array");
        self.item_prefix();
        self.text(name);
        self.raw(b": ");
    }

    fn value_item(&mut self) {
        let frame = self.stack.last().expect("JSON array");
        assert!(frame.array, "array item in JSON object");
        self.item_prefix();
    }

    fn indent(&mut self, depth: usize) {
        self.raw(b"    ".repeat(depth).as_slice());
    }

    fn end(&mut self, close: &[u8]) {
        let frame = self.stack.pop().expect("JSON container");
        if !frame.first {
            self.raw(b"\n");
            self.indent(frame.depth);
        }
        self.raw(close);
    }

    fn text(&mut self, value: &str) {
        let mut output = Zeroizing::new(Vec::new());
        append_json_text(&mut output, value).expect("owned JSON string cannot fail");
        self.raw(&output);
    }

    fn source_bytes(&mut self, value: &[u8]) {
        let mut output = Zeroizing::new(Vec::new());
        append_source_bytes(&mut output, value).expect("owned JSON string cannot fail");
        self.raw(&output);
    }

    fn latin1(&mut self, value: &[u8]) {
        let mut output = Zeroizing::new(Vec::new());
        append_latin1(&mut output, value);
        self.raw(&output);
    }

    fn base64(&mut self, value: &[u8]) -> Result<(), ExportError> {
        let mut output = Zeroizing::new(Vec::with_capacity(value.len().div_ceil(3) * 4));
        output.resize(value.len().div_ceil(3) * 4, 0);
        STANDARD
            .encode_slice(value, &mut output)
            .map_err(|_| ExportError::Unsupported)?;
        self.raw(b"\"");
        self.raw(&output);
        self.raw(b"\"");
        Ok(())
    }

    fn number(&mut self, value: impl std::fmt::Display) {
        self.raw(value.to_string().as_bytes());
    }

    fn null(&mut self) {
        self.raw(b"null");
    }

    fn boolean(&mut self, value: bool) {
        self.raw(if value { b"true" } else { b"false" });
    }

    fn body_text(&mut self, body: &[u8], mime: Option<&[u8]>) -> Result<(), ExportError> {
        match decoded_text(body, mime)? {
            Some(text) => self.text(&text),
            None => self.source_bytes(body),
        }
        Ok(())
    }

    fn streamed_message(&mut self, message: &ExportWebsocketMessage) {
        self.raw(b"\"");
        self.parts.push(ExportPart::HarMessage(MessagePart::new(
            Arc::clone(&message.content),
            message.kind == MessageType::Binary,
        )));
        self.raw(b"\"");
    }
}

struct ExportWebsocketMessage {
    kind: MessageType,
    from_client: bool,
    timestamp: f64,
    content: Arc<MessageContent>,
}

type HeaderPair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);
type CookiePair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

// Live header capture stores each original byte as one Latin-1 code point;
// recover those bytes before applying the source UTF-8/surrogateescape rules.
fn har_headers(side: &ExportHttp) -> Result<Vec<HeaderPair>, ExportError> {
    side.headers
        .iter()
        .map(|(name, value)| Ok((latin1_bytes(name)?, latin1_bytes(value)?)))
        .collect()
}

fn latin1_bytes(value: &str) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let mut output = Zeroizing::new(Vec::with_capacity(value.len()));
    for character in value.chars() {
        let codepoint = character as u32;
        if codepoint > u8::MAX as u32 {
            return Err(ExportError::Unsupported);
        }
        output.push(codepoint as u8);
    }
    Ok(output)
}

fn pretty_url(request: &ExportHttp) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let original = source_string_bytes(&request.url);
    let Some(scheme_end) = original.windows(3).position(|part| part == b"://") else {
        return Ok(original);
    };
    let authority_start = scheme_end + 3;
    let path_start = original[authority_start..]
        .iter()
        .position(|byte| *byte == b'/')
        .map_or(original.len(), |position| authority_start + position);
    let scheme = &original[..scheme_end];
    let original_authority = &original[authority_start..path_start];
    let request_headers = har_headers(request)?;
    let host = header_text(&request_headers, "host");
    let authority = host
        .as_deref()
        .filter(|value| !value.is_empty())
        .map_or(original_authority, |value| value);
    let authority = omit_default_port(authority, scheme);
    let mut output = Zeroizing::new(Vec::with_capacity(original.len()));
    output.extend_from_slice(scheme);
    output.extend_from_slice(b"://");
    output.extend_from_slice(authority);
    output.extend_from_slice(&original[path_start..]);
    Ok(output)
}

fn omit_default_port<'a>(authority: &'a [u8], scheme: &[u8]) -> &'a [u8] {
    let port = if scheme.eq_ignore_ascii_case(b"http") {
        b":80".as_slice()
    } else if scheme.eq_ignore_ascii_case(b"https") {
        b":443".as_slice()
    } else {
        return authority;
    };
    authority
        .strip_suffix(port)
        .filter(|value| !value.is_empty())
        .unwrap_or(authority)
}

fn is_form_mime(value: &[u8]) -> bool {
    value
        .split(|byte| *byte == b';')
        .next()
        .is_some_and(|value| {
            ascii_eq_ignore_case(trim_ascii(value), b"application/x-www-form-urlencoded")
        })
}

fn decoded_text(
    body: &[u8],
    mime: Option<&[u8]>,
) -> Result<Option<Zeroizing<String>>, ExportError> {
    let content_type = mime.and_then(decodable_content_type);
    if mime.is_some() && content_type.is_none() {
        return Ok(None);
    }
    match super::decode_text(body, content_type.as_ref().map(|value| value.as_str())) {
        Ok(text) => Ok(Some(text)),
        Err(ExportError::Decode) => Ok(None),
        Err(error) => Err(error),
    }
}

fn decodable_content_type(mime: &[u8]) -> Option<Zeroizing<String>> {
    if let Ok(text) = str::from_utf8(mime) {
        return Some(Zeroizing::new(text.to_owned()));
    }
    let charset = mime.split(|byte| *byte == b';').skip(1).find_map(|part| {
        let (name, value) = split_byte_option(part, b'=')?;
        if !ascii_eq_ignore_case(trim_ascii(name), b"charset") {
            return None;
        }
        let value = trim_ascii(value);
        let value = value
            .strip_prefix(b"\"")
            .and_then(|value| value.strip_suffix(b"\""))
            .unwrap_or(value);
        value
            .iter()
            .all(u8::is_ascii)
            .then(|| Zeroizing::new(value.iter().copied().map(char::from).collect::<String>()))
    })?;
    let mut content_type = Zeroizing::new(String::from("charset="));
    content_type.push_str(&charset);
    Some(content_type)
}

pub(super) fn build(snapshot: ExportSnapshot) -> Result<Vec<ExportPart>, ExportError> {
    let websocket = snapshot.websocket.as_ref().map(|session| {
        session
            .messages
            .iter()
            .map(|message| ExportWebsocketMessage {
                kind: message.kind,
                from_client: message.from_client,
                timestamp: message.timestamp,
                content: Arc::clone(&message.content),
            })
            .collect::<Vec<_>>()
    });
    let mut builder = Builder::new();
    builder.object();
    builder.field("log");
    builder.object();
    builder.field("version");
    builder.text("1.2");
    builder.field("creator");
    builder.object();
    builder.field("name");
    builder.text("SafeYolo");
    builder.field("version");
    builder.text(env!("CARGO_PKG_VERSION"));
    builder.field("comment");
    builder.text("");
    builder.end(b"}");
    builder.field("pages");
    builder.array();
    builder.end(b"]");
    builder.field("entries");
    builder.array();
    builder.value_item();
    write_entry(&mut builder, &snapshot, websocket.as_deref())?;
    builder.end(b"]");
    builder.end(b"}");
    builder.end(b"}");
    Ok(builder.parts)
}

fn write_entry(
    builder: &mut Builder,
    snapshot: &ExportSnapshot,
    websocket: Option<&[ExportWebsocketMessage]>,
) -> Result<(), ExportError> {
    let request = &snapshot.request;
    let phases = phases(snapshot);
    builder.object();
    builder.field("startedDateTime");
    builder.text(&timestamp(snapshot.started)?);
    builder.field("time");
    builder.number(format_ms(
        phases.iter().copied().filter(|value| *value >= 0.0).sum(),
    ));
    builder.field("request");
    write_request(builder, request)?;
    builder.field("response");
    if let Some(response) = &snapshot.response {
        write_response(builder, response)?;
    } else {
        write_missing_response(builder, snapshot.error.as_ref().map(|error| error.as_str()));
    }
    builder.field("cache");
    builder.object();
    builder.end(b"}");
    builder.field("timings");
    write_timings(builder, phases);
    if let Some(upstream) = snapshot.upstream.as_ref()
        && upstream.route == crate::traffic_view::UpstreamRoute::Direct
        && let Some(peer) = upstream.peer
    {
        builder.field("serverIPAddress");
        builder.text(&peer.ip().to_string());
    }
    if let Some(messages) = websocket {
        builder.field("_resourceType");
        builder.text("websocket");
        builder.field("_webSocketMessages");
        builder.array();
        for message in messages {
            builder.value_item();
            builder.object();
            builder.field("type");
            builder.text(if message.from_client {
                "send"
            } else {
                "receive"
            });
            builder.field("time");
            builder.number(format_ms(message.timestamp));
            builder.field("opcode");
            builder.number(match message.kind {
                MessageType::Text => 1,
                MessageType::Binary => 2,
            });
            builder.field("data");
            builder.streamed_message(message);
            builder.end(b"}");
        }
        builder.end(b"]");
    }
    builder.end(b"}");
    Ok(())
}

fn write_request(builder: &mut Builder, request: &ExportHttp) -> Result<(), ExportError> {
    let raw_body = request.body.as_ref().map(|body| body.as_slice());
    let headers = har_headers(request)?;
    builder.object();
    builder.field("method");
    builder.text(&request.method);
    builder.field("url");
    let url = pretty_url(request)?;
    builder.source_bytes(&url);
    builder.field("httpVersion");
    builder.text(request.version.as_deref().map_or("", |value| value));
    builder.field("cookies");
    write_request_cookies(builder, &headers)?;
    builder.field("headers");
    write_headers(builder, &headers)?;
    builder.field("queryString");
    write_query(builder, &request.url);
    builder.field("headersSize");
    builder.number(header_size(&headers)?);
    builder.field("bodySize");
    builder.number(raw_body.map_or(0, <[u8]>::len));
    if matches!(request.method.as_str(), "POST" | "PUT" | "PATCH") {
        builder.field("postData");
        builder.object();
        let mime = header_text(&headers, "content-type");
        builder.field("mimeType");
        builder.source_bytes(mime.as_deref().map_or(&[][..], |value| value));
        builder.field("text");
        if let Some(body) = raw_body {
            let decoded = decoded_body(&headers, body)?;
            let text = decoded_text(&decoded, mime.as_deref().map(|value| &**value))?;
            if let Some(text) = text.as_ref() {
                builder.text(text);
            } else {
                builder.source_bytes(&decoded);
            }
            builder.field("params");
            if mime.as_ref().is_some_and(|mime| is_form_mime(mime)) {
                let form_body = text
                    .as_ref()
                    .map_or(decoded.as_slice(), |text| text.as_bytes());
                write_form_params(builder, form_body);
            } else {
                builder.array();
                builder.end(b"]");
            }
        } else {
            builder.null();
            builder.field("params");
            builder.array();
            builder.end(b"]");
        }
        builder.end(b"}");
    }
    builder.end(b"}");
    Ok(())
}

fn write_response(builder: &mut Builder, response: &ExportHttp) -> Result<(), ExportError> {
    let raw_body = response.body.as_ref().map(|body| body.as_slice());
    let headers = har_headers(response)?;
    let mime = header_text(&headers, "content-type");
    builder.object();
    builder.field("status");
    builder.number(response.status.ok_or(ExportError::MissingResponse)?);
    builder.field("statusText");
    if let Some(reason) = response.reason.as_ref() {
        builder.latin1(reason);
    } else {
        builder.text("");
    }
    builder.field("httpVersion");
    builder.text(response.version.as_deref().map_or("", |value| value));
    builder.field("cookies");
    write_response_cookies(builder, &headers)?;
    builder.field("headers");
    write_headers(builder, &headers)?;
    builder.field("content");
    builder.object();
    let decoded = raw_body
        .map(|body| decoded_body(&headers, body))
        .transpose()?;
    builder.field("size");
    builder.number(raw_body.map_or(0, <[u8]>::len));
    builder.field("compression");
    builder.number(
        decoded.as_ref().map_or(0, |body| body.len() as i64)
            - raw_body.map_or(0, <[u8]>::len) as i64,
    );
    builder.field("mimeType");
    builder.source_bytes(mime.as_deref().map_or(&[][..], |value| value));
    builder.field("text");
    match decoded.as_deref() {
        None => builder.text(""),
        Some(body) if is_mostly_bin(body) => {
            builder.base64(body)?;
            builder.field("encoding");
            builder.text("base64");
        }
        Some(body) => builder.body_text(body, mime.as_deref().map(|value| &**value))?,
    }
    builder.end(b"}");
    builder.field("redirectURL");
    let location = header_text(&headers, "location");
    builder.source_bytes(location.as_deref().map_or(&[][..], |value| value));
    builder.field("headersSize");
    builder.number(header_size(&headers)?);
    builder.field("bodySize");
    builder.number(raw_body.map_or(0, <[u8]>::len));
    builder.end(b"}");
    Ok(())
}

fn write_missing_response(builder: &mut Builder, error: Option<&str>) {
    builder.object();
    builder.field("status");
    builder.number(0);
    builder.field("statusText");
    builder.text("");
    builder.field("httpVersion");
    builder.text("");
    builder.field("headers");
    builder.array();
    builder.end(b"]");
    builder.field("cookies");
    builder.array();
    builder.end(b"]");
    builder.field("content");
    builder.object();
    builder.end(b"}");
    builder.field("redirectURL");
    builder.text("");
    builder.field("headersSize");
    builder.number(-1);
    builder.field("bodySize");
    builder.number(-1);
    builder.field("_transferSize");
    builder.number(0);
    builder.field("_error");
    if let Some(error) = error {
        builder.text(error);
    } else {
        builder.null();
    }
    builder.end(b"}");
}

fn write_headers(builder: &mut Builder, headers: &[HeaderPair]) -> Result<(), ExportError> {
    builder.array();
    for (name, value) in headers {
        builder.value_item();
        builder.object();
        builder.field("name");
        builder.source_bytes(name);
        builder.field("value");
        builder.source_bytes(value);
        builder.end(b"}");
    }
    builder.end(b"]");
    Ok(())
}

fn write_request_cookies(builder: &mut Builder, headers: &[HeaderPair]) -> Result<(), ExportError> {
    builder.array();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| ascii_eq_ignore_case(name, b"cookie"))
    {
        for (name, value) in cookie_pairs(value) {
            builder.value_item();
            builder.object();
            builder.field("name");
            builder.source_bytes(&name);
            builder.field("value");
            builder.source_bytes(&value);
            builder.end(b"}");
        }
    }
    builder.end(b"]");
    Ok(())
}

fn write_response_cookies(
    builder: &mut Builder,
    headers: &[HeaderPair],
) -> Result<(), ExportError> {
    builder.array();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| ascii_eq_ignore_case(name, b"set-cookie"))
    {
        let pieces = cookie_segments(value);
        let Some(first) = pieces.first() else {
            continue;
        };
        let (name, cookie_value) = split_byte(first, b'=');
        let name = trim_ascii(name);
        let cookie_value = cookie_field(cookie_value);
        let mut path = super::copy_bytes(b"/");
        let mut domain = super::copy_bytes(b"");
        let mut http_only = false;
        let mut secure = false;
        let mut same_site: Option<Zeroizing<Vec<u8>>> = None;
        for attribute in pieces.iter().skip(1) {
            let attribute = trim_ascii(attribute);
            let (key, value) = split_byte_option(attribute, b'=')
                .map_or((attribute, None), |(key, value)| (key, Some(value)));
            if ascii_eq_ignore_case(key, b"path") {
                path = value.map_or_else(|| super::copy_bytes(b"/"), cookie_field);
            } else if ascii_eq_ignore_case(key, b"domain") {
                domain = value.map_or_else(|| super::copy_bytes(b""), cookie_field);
            } else if ascii_eq_ignore_case(key, b"httponly") {
                http_only = true;
            } else if ascii_eq_ignore_case(key, b"secure") {
                secure = true;
            } else if ascii_eq_ignore_case(key, b"samesite") {
                same_site = value.map(cookie_field);
            }
        }
        builder.value_item();
        builder.object();
        builder.field("name");
        builder.source_bytes(name);
        builder.field("value");
        builder.source_bytes(&cookie_value);
        builder.field("path");
        builder.source_bytes(&path);
        builder.field("domain");
        builder.source_bytes(&domain);
        builder.field("httpOnly");
        builder.boolean(http_only);
        builder.field("secure");
        builder.boolean(secure);
        if let Some(same_site) = same_site {
            builder.field("sameSite");
            builder.source_bytes(&same_site);
        }
        builder.end(b"}");
    }
    builder.end(b"]");
    Ok(())
}

fn cookie_pairs(bytes: &[u8]) -> Vec<CookiePair> {
    let mut pairs = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let name_start = offset;
        while offset < bytes.len() && !matches!(bytes[offset], b'=' | b';') {
            offset += 1;
        }
        let name = trim_ascii(&bytes[name_start..offset]);
        let mut cookie_value = Zeroizing::new(Vec::new());
        if bytes.get(offset) == Some(&b'=') {
            offset += 1;
            if bytes.get(offset) == Some(&b'"') {
                offset += 1;
                while offset < bytes.len() {
                    match bytes[offset] {
                        b'"' => {
                            offset += 1;
                            break;
                        }
                        b'\\' if offset + 1 < bytes.len() => {
                            offset += 1;
                            cookie_value.push(bytes[offset]);
                            offset += 1;
                        }
                        byte => {
                            cookie_value.push(byte);
                            offset += 1;
                        }
                    }
                }
            } else {
                let value_start = offset;
                while offset < bytes.len() && bytes[offset] != b';' {
                    offset += 1;
                }
                cookie_value.extend_from_slice(&bytes[value_start..offset]);
            }
        }
        if !name.is_empty() || !cookie_value.is_empty() {
            pairs.push((super::copy_bytes(name), cookie_value));
        }
        while offset < bytes.len() && bytes[offset] != b';' {
            offset += 1;
        }
        if bytes.get(offset) == Some(&b';') {
            offset += 1;
        }
    }
    pairs
}

fn cookie_field(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let value = trim_ascii(value);
    if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
        let mut output = Zeroizing::new(Vec::with_capacity(value.len() - 2));
        let mut offset = 1;
        while offset + 1 < value.len() {
            if value[offset] == b'\\' && offset + 2 < value.len() {
                offset += 1;
            }
            output.push(value[offset]);
            offset += 1;
        }
        output
    } else {
        super::copy_bytes(value)
    }
}

fn cookie_segments(value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let bytes = value;
    let mut segments = Vec::new();
    let mut start = 0;
    let mut offset = 0;
    let mut quoted = false;
    let mut escaped = false;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if escaped {
            escaped = false;
        } else if byte == b'\\' && quoted {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b';' && !quoted {
            segments.push(super::copy_bytes(trim_ascii(&bytes[start..offset])));
            start = offset + 1;
        }
        offset += 1;
    }
    segments.push(super::copy_bytes(trim_ascii(&bytes[start..])));
    segments
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &value[start..end]
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn split_byte(value: &[u8], separator: u8) -> (&[u8], &[u8]) {
    split_byte_option(value, separator).map_or((value, &[][..]), |(left, right)| (left, right))
}

fn split_byte_option(value: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let offset = value.iter().position(|byte| *byte == separator)?;
    Some((&value[..offset], &value[offset + 1..]))
}

fn write_query(builder: &mut Builder, url: &str) {
    builder.array();
    let Some(query) = url
        .split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or(query))
    else {
        builder.end(b"]");
        return;
    };
    if query.is_empty() {
        builder.end(b"]");
        return;
    }
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        builder.value_item();
        builder.object();
        builder.field("name");
        builder.source_bytes(&url_decode(name.as_bytes()));
        builder.field("value");
        builder.source_bytes(&url_decode(value.as_bytes()));
        builder.end(b"}");
    }
    builder.end(b"]");
}

fn write_form_params(builder: &mut Builder, body: &[u8]) {
    builder.array();
    for pair in body
        .split(|byte| *byte == b'&')
        .filter(|pair| !pair.is_empty())
    {
        let (name, value) = pair
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((pair, &[][..]), |index| {
                (&pair[..index], &pair[index + 1..])
            });
        builder.value_item();
        builder.object();
        builder.field("name");
        builder.source_bytes(&url_decode(name));
        builder.field("value");
        builder.source_bytes(&url_decode(value));
        builder.end(b"}");
    }
    builder.end(b"]");
}

fn write_timings(builder: &mut Builder, phases: [f64; 5]) {
    builder.object();
    for (name, value) in [
        ("connect", phases[0]),
        ("ssl", phases[1]),
        ("send", phases[2]),
        ("receive", phases[3]),
        ("wait", phases[4]),
    ] {
        builder.field(name);
        builder.number(format_ms(value));
    }
    builder.end(b"}");
}

fn phases(snapshot: &ExportSnapshot) -> [f64; 5] {
    let connect = snapshot
        .upstream
        .as_ref()
        .filter(|upstream| upstream.route == crate::traffic_view::UpstreamRoute::Direct)
        .and_then(|upstream| {
            upstream
                .started
                .zip(upstream.tcp_setup)
                .map(|(started, setup)| normalize_ms((setup - started) * 1000.0))
        })
        .unwrap_or(-1.0);
    let ssl = snapshot
        .upstream
        .as_ref()
        .filter(|upstream| upstream.route == crate::traffic_view::UpstreamRoute::Direct)
        .and_then(|upstream| {
            upstream
                .tcp_setup
                .zip(upstream.tls_setup)
                .map(|(setup, tls)| normalize_ms((tls - setup) * 1000.0))
        })
        .unwrap_or(-1.0);
    let send = snapshot.request_completed.map_or(0.0, |completed| {
        normalize_ms((completed - snapshot.started) * 1000.0)
    });
    let wait = snapshot
        .response
        .as_ref()
        .zip(snapshot.request_completed)
        .zip(snapshot.response_head_observed)
        .map_or(0.0, |((_, request), head)| {
            normalize_ms((head - request) * 1000.0)
        });
    let receive = snapshot
        .response_completed
        .zip(snapshot.response_head_observed)
        .map_or(0.0, |(completed, head)| {
            normalize_ms((completed - head) * 1000.0)
        });
    [connect, ssl, send, receive, wait]
}

fn timestamp(seconds: f64) -> Result<String, ExportError> {
    let nanos = (seconds * 1_000_000_000.0).round() as i128;
    let value = time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| ExportError::Unsupported)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| ExportError::Unsupported)?;
    Ok(if let Some(prefix) = value.strip_suffix('Z') {
        format!("{prefix}+00:00")
    } else {
        value
    })
}

fn normalize_ms(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}

fn format_ms(value: f64) -> String {
    let value = normalize_ms(value);
    if value.is_finite() && value.fract() == 0.0 {
        format!("{value:.1}")
    } else {
        value.to_string()
    }
}

fn decoded_body(headers: &[HeaderPair], body: &[u8]) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let encoding = header_bytes(headers, "content-encoding");
    match crate::http_content::decode(body, &encoding) {
        Ok(decoded) => Ok(decoded),
        Err(ContentError::Value) => Ok(super::copy_bytes(body)),
        Err(ContentError::Type) => Err(ExportError::Decode),
        Err(ContentError::Allocation) => Err(ExportError::Allocation),
    }
}

fn header_bytes(headers: &[HeaderPair], wanted: &str) -> Zeroizing<Vec<u8>> {
    let mut result = Zeroizing::new(Vec::new());
    let mut found = false;
    for (name, value) in headers {
        if ascii_eq_ignore_case(name, wanted.as_bytes()) {
            if found {
                result.extend_from_slice(b", ");
            }
            result.extend_from_slice(value);
            found = true;
        }
    }
    result
}

fn header_text(headers: &[HeaderPair], wanted: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut result = Zeroizing::new(Vec::new());
    let mut found = false;
    for (name, value) in headers {
        if ascii_eq_ignore_case(name, wanted.as_bytes()) {
            if found {
                result.extend_from_slice(b", ");
            }
            result.extend_from_slice(value);
            found = true;
        }
    }
    found.then_some(result)
}

fn url_decode(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'+' => output.push(b' '),
            b'%' if index + 2 < value.len() => {
                let hex = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                };
                if let (Some(high), Some(low)) = (hex(value[index + 1]), hex(value[index + 2])) {
                    output.push(high * 16 + low);
                    index += 2;
                } else {
                    output.push(b'%');
                }
            }
            byte => output.push(byte),
        }
        index += 1;
    }
    output
}

fn source_string_bytes(value: &str) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(value.len()));
    for character in value.chars() {
        let codepoint = character as u32;
        if (0xdc80..=0xdcff).contains(&codepoint) {
            output.push((codepoint - 0xdc00) as u8);
        } else {
            let mut encoded = Zeroizing::new([0u8; 4]);
            output.extend_from_slice(character.encode_utf8(&mut *encoded).as_bytes());
        }
    }
    output
}

fn header_size(headers: &[HeaderPair]) -> Result<i64, ExportError> {
    let mut size = 9usize;
    for (position, (name, value)) in headers.iter().enumerate() {
        if position != 0 {
            size = size.saturating_add(2);
        }
        size = size
            .saturating_add(1)
            .saturating_add(bytes_repr_len(name))
            .saturating_add(2)
            .saturating_add(bytes_repr_len(value))
            .saturating_add(1);
    }
    i64::try_from(size).map_err(|_| ExportError::Allocation)
}

fn bytes_repr_len(value: &[u8]) -> usize {
    let quote = if value.contains(&b'\'') && !value.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    3 + value
        .iter()
        .map(|byte| match *byte {
            byte if byte == quote || byte == b'\\' => 2,
            b'\n' | b'\r' | b'\t' => 2,
            8 | 12 => 4,
            0x20..=0x7e => 1,
            _ => 4,
        })
        .sum::<usize>()
}

fn append_latin1(output: &mut Vec<u8>, value: &[u8]) {
    output.push(b'"');
    for byte in value {
        append_json_char(output, char::from(*byte));
    }
    output.push(b'"');
}

fn append_source_bytes(output: &mut Vec<u8>, mut value: &[u8]) -> Result<(), ExportError> {
    output.push(b'"');
    while !value.is_empty() {
        match str::from_utf8(value) {
            Ok(text) => {
                for character in text.chars() {
                    append_json_char(output, character);
                }
                value = &[];
            }
            Err(error) => {
                let valid = error.valid_up_to();
                for character in str::from_utf8(&value[..valid])
                    .expect("valid prefix")
                    .chars()
                {
                    append_json_char(output, character);
                }
                let byte = value[valid];
                output.extend_from_slice(b"\\udc");
                output.push(hex_digit(byte >> 4));
                output.push(hex_digit(byte & 0x0f));
                value = &value[valid + 1..];
            }
        }
    }
    output.push(b'"');
    Ok(())
}

fn append_json_text(output: &mut Vec<u8>, value: &str) -> Result<(), ExportError> {
    output.push(b'"');
    append_json_chars(output, value);
    output.push(b'"');
    Ok(())
}

fn append_json_chars(output: &mut Vec<u8>, value: &str) {
    for character in value.chars() {
        append_json_char(output, character);
    }
}

fn append_json_char(output: &mut Vec<u8>, character: char) {
    match character {
        '"' => output.extend_from_slice(b"\\\""),
        '\\' => output.extend_from_slice(b"\\\\"),
        '\u{8}' => output.extend_from_slice(b"\\b"),
        '\u{c}' => output.extend_from_slice(b"\\f"),
        '\n' => output.extend_from_slice(b"\\n"),
        '\r' => output.extend_from_slice(b"\\r"),
        '\t' => output.extend_from_slice(b"\\t"),
        ' '..='~' => output.push(character as u8),
        _ => {
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                let unit = *unit;
                output.extend_from_slice(b"\\u");
                output.push(hex_digit((unit >> 12) as u8));
                output.push(hex_digit((unit >> 8) as u8));
                output.push(hex_digit((unit >> 4) as u8));
                output.push(hex_digit(unit as u8));
            }
        }
    }
}

fn hex_digit(value: u8) -> u8 {
    match value & 0x0f {
        0..=9 => b'0' + (value & 0x0f),
        digit => b'a' + (digit - 10),
    }
}

fn is_mostly_bin(mut value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    if value.len() > 100 {
        let mut boundary_found = false;
        for cut in 100..value.len().min(104) {
            if value[cut] >> 6 != 0b10 {
                value = &value[..cut];
                boundary_found = true;
                break;
            }
        }
        if !boundary_found {
            value = &value[..100];
        }
    }
    let low = value
        .iter()
        .filter(|byte| **byte < 9 || (14..32).contains(*byte))
        .count();
    let high = value.iter().filter(|byte| **byte > 126).count();
    let ascii = value.len() - low - high;
    if (ascii as f64) / (value.len() as f64) > 0.7 {
        return false;
    }
    if ((ascii + high) as f64) / (value.len() as f64) > 0.95 && str::from_utf8(value).is_ok() {
        return false;
    }
    true
}
