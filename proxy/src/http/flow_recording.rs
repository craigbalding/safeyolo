//! One terminal recording attempt per HTTP exchange. Parser callbacks copy only
//! head bytes; decoding and the existing writer submission run on application
//! completion, after the source provenance hook. No origin response is inferred
//! from the proxy's generated error response.

use std::{
    fmt::Write as _,
    sync::{Arc, Mutex},
};

use hyper::{Request, StatusCode};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::{
    ConnectionIdentity,
    flow_recorder::FlowRecorder,
    flow_store::{FlowStore, Side},
    flow_writer::QueuedRecord,
    http_content::{self, ContentError, DecodedContent},
    python_json,
    test_context::AppliedContext,
};

type Pairs = Vec<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>;

struct Head {
    status: StatusCode,
    pairs: Pairs,
    reason: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Default)]
struct Record {
    metadata: Map<String, Value>,
    applied: bool,
    started: f64,
    body: Option<Zeroizing<Vec<u8>>>,
    encoding: Zeroizing<Vec<u8>>,
    failure: Option<ContentError>,
    head: Option<Head>,
    error: Option<Zeroizing<String>>,
    metadata_encoding_error: bool,
}

impl Drop for Record {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut Value::Object(std::mem::take(&mut self.metadata)));
    }
}

struct State {
    record: Option<Record>,
    deferred: bool,
}

/// Contains no transport owner or callback, so keeping it through response body
/// teardown cannot retain a connection or form a cycle.
pub(super) struct Recording {
    recorder: Arc<FlowRecorder>,
    identity: ConnectionIdentity,
    request_id: String,
    enabled_exchange: bool,
    state: Mutex<State>,
}

/// The service future owns this guard until a connection driver takes over.
/// Its drop runs on the application boundary, never in a parser callback.
pub(super) struct PendingRecording(Arc<Recording>);

impl Drop for PendingRecording {
    fn drop(&mut self) {
        self.0.cancel_before_driver();
    }
}

impl Recording {
    pub(super) fn new(
        recorder: Arc<FlowRecorder>,
        identity: ConnectionIdentity,
        request_id: String,
        enabled_exchange: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            recorder,
            identity,
            request_id,
            enabled_exchange,
            state: Mutex::new(State {
                record: Some(Record::default()),
                deferred: false,
            }),
        })
    }

    pub(super) fn pending(self: &Arc<Self>) -> PendingRecording {
        PendingRecording(self.clone())
    }

    fn cancel_before_driver(&self) {
        let record = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.deferred {
                return;
            }
            state.record.take()
        };
        let Some(mut record) = record else {
            return;
        };
        // A native application cancellation, not a protocol/Python diagnostic.
        record.error = Some(Zeroizing::new(
            "native request cancelled before upstream driver".into(),
        ));
        self.submit(record, false, None, false, crate::circuit_runtime::now());
    }

    /// Copy the source hook's header view before transport rewrites Host/Via.
    /// Only a potentially eligible context reaches here. No credential hook or
    /// operator replay producer is synthesized by this capture.
    pub(super) fn request<'a, B>(
        &self,
        request: &Request<B>,
        destination: &super::Destination,
        fields: impl Iterator<Item = (&'a [u8], &'a [u8])>,
        websocket: bool,
    ) {
        if self.recorder.store().is_none() {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = state.record.as_mut() else {
            return;
        };
        let pairs: Pairs = fields
            .filter(|(name, _)| !name.eq_ignore_ascii_case(crate::test_context::HEADER.as_bytes()))
            .map(|(name, value)| {
                (
                    Zeroizing::new(name.to_vec()),
                    Zeroizing::new(value.to_vec()),
                )
            })
            .collect();
        let raw_host = combined(&pairs, b"host");
        let host = if raw_host.is_empty() {
            destination.policy_host.clone()
        } else {
            match std::str::from_utf8(&raw_host) {
                Ok(raw) => pretty_host(raw).to_owned(),
                Err(_) => {
                    record.metadata_encoding_error = true;
                    String::new()
                }
            }
        };
        let authority = if (destination.scheme == "http" && destination.port == 80)
            || (destination.scheme == "https" && destination.port == 443)
        {
            destination.policy_host.clone()
        } else {
            format!("{}:{}", destination.policy_host, destination.port)
        };
        let path = if destination.path == "*" {
            ""
        } else {
            &destination.path
        };
        let full_url = format!("{}://{authority}{path}", destination.scheme);
        let content_type = match scalar_header(&pairs, b"content-type") {
            Ok(value) => value,
            Err(_) => {
                record.metadata_encoding_error = true;
                String::new()
            }
        };
        record.metadata = object(json!({
            "scheme": destination.scheme, "host": host, "port": destination.port,
            "method": request.method().as_str(), "path": destination.path.split('?').next().unwrap_or(""),
            "query_string": query_json(&destination.path), "full_url": full_url,
            "request_content_type": content_type, "is_websocket": websocket,
            "request_headers_json": headers_json(&pairs, None),
        }));
    }

    /// Metadata precedes source snippet decoding, including a decoding error.
    /// Encoded content is retained only for source-buffered, validated requests;
    /// streaming supplies None and remains absent at the recording hook.
    pub(super) fn applied(
        &self,
        context: &AppliedContext,
        content: Option<&[u8]>,
        encoding: Result<&[u8], ContentError>,
        started: f64,
    ) {
        if self.recorder.store().is_none() {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = state.record.as_mut() else {
            return;
        };
        record.applied = true;
        record.started = started;
        let context = serde_json::to_value(&context.context).expect("context strings serialize");
        for (column, key) in [
            ("run", "run"),
            ("test", "test"),
            ("role", "role"),
            ("test_agent", "agent"),
            ("suite", "suite"),
            ("subject", "subject"),
            ("step", "step"),
            ("intent", "intent"),
            ("expect", "expect"),
        ] {
            record.metadata.insert(
                column.into(),
                context.get(key).cloned().unwrap_or(Value::Null),
            );
        }
        record
            .metadata
            .insert("context_json".into(), python_json::encode(&context).into());
        let mut context = context;
        crate::credentials::wipe_json(&mut context);
        match encoding {
            Ok(encoding) => record.encoding = Zeroizing::new(encoding.to_vec()),
            Err(error) => record.failure = Some(error),
        }
        if let Some(content) = content {
            let mut bytes = Zeroizing::new(Vec::new());
            if bytes.try_reserve(content.len()).is_err() {
                record.failure = Some(ContentError::Allocation);
            } else {
                bytes.extend_from_slice(content);
                record.body = Some(bytes);
            }
        }
    }

    pub(super) fn head<'a>(
        &self,
        status: StatusCode,
        fields: Option<impl Iterator<Item = (&'a [u8], &'a [u8])>>,
        reason: Option<&[u8]>,
    ) {
        if self.recorder.store().is_none() {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = state.record.as_mut().filter(|record| record.head.is_none()) else {
            return;
        };
        let Some(fields) = fields else {
            // Missing parser metadata must not silently reconstruct duplicate
            // order from HeaderMap or invent an upstream reason phrase.
            record.failure = Some(ContentError::Type);
            return;
        };
        record.head = Some(Head {
            status,
            pairs: fields
                .map(|(name, value)| {
                    (
                        Zeroizing::new(name.to_vec()),
                        Zeroizing::new(value.to_vec()),
                    )
                })
                .collect(),
            reason: reason.map(|value| Zeroizing::new(value.to_vec())),
        });
    }

    pub(super) fn defer(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .deferred = true;
    }

    pub(super) fn producer_error(&self, error: &dyn std::fmt::Display) {
        if let Some(record) = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record
            .as_mut()
        {
            record.error = Some(Zeroizing::new(error.to_string()));
        }
    }

    /// Before an outbound observer exists, the application result owns the
    /// terminal attempt. CONNECT has no source FlowRecorder response hook.
    pub(super) fn local_terminal(&self, error: bool) {
        if !self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .deferred
        {
            self.finish(!error, None, false);
        }
    }

    /// An earlier child in the production response hook raised. Release this
    /// terminal's private evidence without invoking or counting the recorder.
    pub(super) fn skip_response(&self) {
        let record = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record
            .take();
        drop(record);
    }

    pub(super) fn finish(&self, success: bool, content: Option<&[u8]>, capture_failed: bool) {
        self.finish_at(
            success,
            content,
            capture_failed,
            crate::circuit_runtime::now(),
        );
    }

    fn finish_at(&self, success: bool, content: Option<&[u8]>, capture_failed: bool, now: f64) {
        let record = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record
            .take();
        let Some(record) = record else {
            return;
        };
        self.submit(record, success, content, capture_failed, now);
    }

    fn submit(
        &self,
        record: Record,
        success: bool,
        content: Option<&[u8]>,
        capture_failed: bool,
        now: f64,
    ) {
        if !self.enabled_exchange {
            return;
        }
        self.recorder
            .record(|store| self.build(record, store, success, content, capture_failed, now));
    }

    fn build(
        &self,
        mut record: Record,
        store: &FlowStore,
        success: bool,
        content: Option<&[u8]>,
        capture_failed: bool,
        now: f64,
    ) -> Result<Option<QueuedRecord>, ContentError> {
        if !record.applied || record.metadata.is_empty() {
            return Ok(None);
        }
        if let Some(error) = record.failure {
            return Err(error);
        }
        if capture_failed {
            return Err(ContentError::Allocation);
        }
        let request_body = decode(
            record.body.as_deref().map(Vec::as_slice),
            &record.encoding,
            store.capture_limit(Side::Request),
        )?;
        let response_body = match record.head.as_ref() {
            Some(head) if success => decode(
                content,
                &combined(&head.pairs, b"content-encoding"),
                store.capture_limit(Side::Response),
            )?,
            _ => empty_body(),
        };
        let ts_start = ((if record.started == 0. {
            now
        } else {
            record.started
        }) * 1000.)
            .trunc() as i64;
        let ts_end = (now * 1000.).trunc() as i64;
        let response_content_type = match record.head.as_ref() {
            Some(head) => match scalar_header(&head.pairs, b"content-type") {
                Ok(value) => value,
                Err(_) => {
                    record.metadata_encoding_error = true;
                    String::new()
                }
            },
            None => String::new(),
        };
        let agent = &self.identity.agent_id;
        let fields = &mut record.metadata;
        fields.extend(object(json!({
            "request_id": self.request_id, "ts_start": ts_start, "ts_end": ts_end,
            "duration_ms": ts_end - ts_start, "engagement_id": agent, "agent_id": agent,
            "evidence_owner": agent, "trusted_transport_identity": agent, "initiator": "unknown",
            "attribution_status": "resolved", "attribution_provenance_json": python_json::encode(&json!({
                "transport_source": "uds", "uds_agent": agent.chars().take(128).collect::<String>() })),
            "source_id": self.identity.source_id.as_deref().unwrap_or("unknown"), "source_type": null,
            "flow_state": if success { "completed" } else { "error" },
            "status_code": record.head.as_ref().map(|head| head.status.as_u16()),
            "reason": if !success { record.error.as_deref().map(|v| v.to_string()) } else {
                record.head.as_ref().and_then(|head| head.reason.as_ref().map(|bytes| bytes.trim_ascii_start().iter().copied().map(char::from).collect::<String>())) },
            "response_content_type": response_content_type,
            "response_headers_json": match record.head.as_ref() { Some(head) => headers_json(&head.pairs, success.then_some(self.request_id.as_str())), None => "[]".into() },
        })));
        Ok(Some(QueuedRecord {
            metadata_encoding_error: record.metadata_encoding_error,
            metadata: std::mem::take(fields),
            request_body,
            response_body,
        }))
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(fields) => fields,
        _ => unreachable!("object literal"),
    }
}

fn empty_body() -> DecodedContent {
    DecodedContent {
        content: Zeroizing::new(Vec::new()),
        total_bytes: 0,
    }
}
fn decode(
    content: Option<&[u8]>,
    encoding: &[u8],
    limit: Option<usize>,
) -> Result<DecodedContent, ContentError> {
    match content {
        Some(content) => {
            http_content::decode_prefix_with_size(content, encoding, limit.unwrap_or(usize::MAX))
        }
        None => Ok(empty_body()),
    }
}
fn combined(pairs: &Pairs, name: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut first = true;
    for (_, value) in pairs
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
    {
        if !first {
            bytes.extend_from_slice(b", ");
        }
        first = false;
        bytes.extend_from_slice(value);
    }
    bytes
}
fn scalar_header(pairs: &Pairs, name: &[u8]) -> Result<String, ContentError> {
    // Unlike headers_json's source replacement decoding, scalar header values
    // use surrogateescape. Such invalid UTF-8 values fail SQLite encoding on
    // the writer thread; a categorical queued failure retains that phase.
    String::from_utf8(combined(pairs, name).to_vec()).map_err(|_| ContentError::Type)
}
fn headers_json(pairs: &Pairs, request_id: Option<&str>) -> String {
    let mut found = false;
    let mut values = Vec::new();
    for (name, value) in pairs {
        let replacement = if let Some(request_id) =
            request_id.filter(|_| name.eq_ignore_ascii_case(b"x-safeyolo-request-id"))
        {
            if found {
                continue;
            }
            found = true;
            Some(request_id)
        } else {
            None
        };
        values.push(json!([
            String::from_utf8_lossy(name),
            replacement.map_or_else(
                || String::from_utf8_lossy(value),
                std::borrow::Cow::Borrowed
            )
        ]));
    }
    if let Some(request_id) = request_id.filter(|_| !found) {
        values.push(json!(["X-SafeYolo-Request-Id", request_id]));
    }
    let mut value = Value::Array(values);
    let encoded = python_json::encode(&value);
    crate::credentials::wipe_json(&mut value);
    encoded
}
/// Source parse_authority(check=False) for the informational Host projection.
/// Reuse the validated hostname primitive; a malformed authority returns its
/// original spelling. This never participates in routing or admission.
fn pretty_host(raw: &str) -> &str {
    pretty_authority(raw).0
}

/// Share the source authority projection with traffic logging. Invalid input
/// returns its complete original spelling and no port; this is presentation.
pub(super) fn pretty_authority(raw: &str) -> (&str, Option<u16>) {
    // Python's regex `$` also accepts a single terminal LF. The non-colon
    // branch greedily includes it in a host, but the decimal port branch does not.
    let (host, port) = if !raw.contains(':') {
        (raw, None)
    } else if raw.starts_with('[') {
        let Some(end) = raw.rfind(']') else {
            return (raw, None);
        };
        let suffix = &raw[end + 1..];
        let port = if suffix.is_empty() || suffix == "\n" {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(port.strip_suffix('\n').unwrap_or(port))
        } else {
            return (raw, None);
        };
        let host = &raw[..=end];
        // The regex's bracket alternative uses '.', which excludes LF.
        if host.contains('\n') {
            return (raw, None);
        }
        (host, port)
    } else {
        let (host, port) = raw.split_once(':').expect("colon present");
        (host, Some(port.strip_suffix('\n').unwrap_or(port)))
    };
    let host = host
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host);
    if super::validate_hostname(host).is_err() {
        return (raw, None);
    }
    let port = if let Some(port) = port {
        if port.is_empty() {
            return (raw, None);
        }
        let mut value = 0u16;
        for character in port.chars() {
            let Some(digit) = crate::python_text::decimal(character) else {
                return (raw, None);
            };
            let Some(next) = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit as u16))
            else {
                return (raw, None);
            };
            value = next;
        }
        Some(value)
    } else {
        None
    };
    (host, port)
}

/// Query values are stored as serialized JSON text, not general Rust strings.
/// Match urllib's percent decoding + surrogateescape only at this column seam.
fn query_json(path: &str) -> Option<String> {
    let query = path.split_once('?')?.1.split('#').next().unwrap_or("");
    let mut entries: Pairs = Vec::new();
    for field in query.split('&').filter(|field| !field.is_empty()) {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        let key = unquote(key.as_bytes());
        if entries.iter().any(|(prior, _)| **prior == *key) {
            continue;
        }
        entries.push((key, unquote(value.as_bytes())));
    }
    if entries.is_empty() {
        return None;
    }
    let mut output = String::from("{");
    for (index, (key, value)) in entries.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        query_string(key, &mut output);
        output.push_str(": ");
        query_string(value, &mut output);
    }
    output.push('}');
    Some(output)
}
fn unquote(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::new());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%'
            && index + 2 < input.len()
            && let (Some(hi), Some(lo)) = (
                (input[index + 1] as char).to_digit(16),
                (input[index + 2] as char).to_digit(16),
            )
        {
            output.push((hi * 16 + lo) as u8);
            index += 3;
            continue;
        }
        output.push(if input[index] == b'+' {
            b' '
        } else {
            input[index]
        });
        index += 1;
    }
    output
}
fn query_string(mut input: &[u8], output: &mut String) {
    output.push('"');
    while !input.is_empty() {
        let (valid, invalid) = match std::str::from_utf8(input) {
            Ok(_) => (input.len(), 0),
            Err(error) => (
                error.valid_up_to(),
                error
                    .error_len()
                    .unwrap_or(input.len() - error.valid_up_to()),
            ),
        };
        if valid != 0 {
            let mut value = Value::String(std::str::from_utf8(&input[..valid]).unwrap().to_owned());
            let encoded = Zeroizing::new(python_json::encode(&value));
            output.push_str(&encoded[1..encoded.len() - 1]);
            crate::credentials::wipe_json(&mut value);
        }
        for byte in &input[valid..valid + invalid] {
            write!(output, "\\udc{byte:02x}").expect("string writing");
        }
        input = &input[valid + invalid..];
    }
    output.push('"');
}

#[cfg(test)]
mod tests;
