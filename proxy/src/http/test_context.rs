//! Request provenance and bounded response capture. Protocol completion supplies
//! the terminal result; neither a header claim nor dropping a body supplies it.

use std::sync::{Arc, Mutex};

use hyper::{HeaderMap, StatusCode, header};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    ConnectionIdentity, Runtime, RuntimeState, audit,
    http_content::{self, BufferedContent, ContentError},
    policy::Addon,
    request_trace::RequestTrace,
    test_context::{AppliedContext, Reason},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HookError {
    Content(ContentError),
    Audit(audit::Error),
}

impl HookError {
    pub(super) fn trace_reason(self) -> &'static str {
        match self {
            Self::Content(ContentError::Value) => "ValueError",
            Self::Content(ContentError::Type) => "TypeError",
            Self::Content(ContentError::Allocation) => "ContentAllocationError",
            Self::Audit(error) => match error.kind() {
                audit::ErrorKind::Configuration => "AuditConfiguration",
                audit::ErrorKind::ThreadStart => "AuditThreadStart",
                audit::ErrorKind::Poisoned => "AuditPoisoned",
                audit::ErrorKind::Encoding => "AuditEncoding",
                audit::ErrorKind::Io => "AuditIo",
            },
        }
    }

    pub(super) fn evidence_failed(self) -> bool {
        matches!(
            self,
            Self::Content(ContentError::Allocation) | Self::Audit(_)
        )
    }
}
impl std::fmt::Display for HookError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Content(error) => error.fmt(formatter),
            Self::Audit(error) => error.fmt(formatter),
        }
    }
}
impl From<ContentError> for HookError {
    fn from(error: ContentError) -> Self {
        Self::Content(error)
    }
}
impl From<audit::Error> for HookError {
    fn from(error: audit::Error) -> Self {
        Self::Audit(error)
    }
}

struct Applied {
    context: AppliedContext,
    started: f64,
}

enum ResponseOutcome {
    NotApplicable,
    Recorded,
}

/// Metadata becomes visible only when the request parser has completed. It is
/// installed before decoding so a request content error does not suppress a
/// later valid response event. Optional recording retains source-buffered
/// request bytes separately from the short provenance snippet.
pub(super) struct Provenance {
    runtime: Arc<Runtime>,
    identity: ConnectionIdentity,
    request_id: String,
    method: String,
    host: String,
    path: String,
    applied: Mutex<Option<Applied>>,
    recording: Mutex<Option<Arc<super::flow_recording::Recording>>>,
    live: Mutex<Option<Arc<crate::traffic_view::Exchange>>>,
}

impl Provenance {
    pub(super) fn new(
        runtime: Arc<Runtime>,
        identity: ConnectionIdentity,
        request_id: String,
        method: String,
        host: String,
        path: String,
    ) -> Self {
        Self {
            runtime,
            identity,
            request_id,
            method,
            host,
            path,
            applied: Mutex::new(None),
            recording: Mutex::new(None),
            live: Mutex::new(None),
        }
    }

    pub(super) fn attach_recording(&self, recording: Arc<super::flow_recording::Recording>) {
        *self.recording.lock().unwrap_or_else(|e| e.into_inner()) = Some(recording);
    }

    pub(super) fn attach_live(&self, live: Option<Arc<crate::traffic_view::Exchange>>) {
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) = live;
    }

    fn recording(&self) -> Option<Arc<super::flow_recording::Recording>> {
        self.recording
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The caller consumes its single-use request application before this call.
    /// Ok reports completed canonical submission; true marks a separate
    /// diagnostic write failure. Content or synchronous submission errors leave
    /// metadata installed but skip the allowed counter.
    pub(super) fn apply_request(
        &self,
        context: AppliedContext,
        content: Option<&[u8]>,
        encoding: Result<&[u8], ContentError>,
        started: f64,
    ) -> Result<bool, HookError> {
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = Some(Applied {
            context: context.clone(),
            started,
        });
        if let Some(live) = self.live.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            live.metadata(&context.live_metadata);
        }
        if let Some(recording) = self.recording() {
            recording.applied(&context, content, encoding, started);
        }
        let snippet = body_snippet(content, encoding?)?;
        let summary = format!(
            "Test context request: {} {}{}",
            self.method,
            crate::network_guard::sanitize(&self.host),
            crate::network_guard::sanitize(&self.path)
        );
        let details = json!({
            "phase": "request", "method": self.method, "path": self.path,
            "context": context.context, "trusted_agent": context.trusted_agent,
            "test_agent_match": context.test_agent_match,
            "test_context_source": context.source, "request_body_snippet": snippet,
        });
        let mut event = audit::Event::new(
            "security.test_context",
            audit::Kind::Security,
            audit::Severity::Low,
            &summary,
        );
        event.addon = Some("test-context".into());
        event.host = Some(self.host.clone());
        event.agent = self.identity.request_agent().map(str::to_owned);
        event.request_id = Some(self.request_id.clone());
        event.attribution = Some(self.identity.audit_attribution());
        event.details = details.clone().into();
        self.runtime.audit.emit(event)?;
        Ok(self
            .runtime
            .record(json!({
                "event": "security.test_context", "kind": "security", "severity": "low",
                "addon": "test-context", "host": self.host,
                "agent": self.identity.request_agent(), "request_id": self.request_id,
                "summary": summary, "details": details,
            }))
            .is_err())
    }

    /// Source warn/block audits resolve attribution from this request's trusted
    /// ingress. An annotation cannot replace that owner or establish initiator.
    pub(super) fn decision(
        &self,
        reason: Reason,
        blocked: bool,
        port: u16,
    ) -> Result<bool, HookError> {
        let reason_name = match reason {
            Reason::MissingContext => "missing_context",
            Reason::MalformedContext => "malformed_context",
            Reason::MalformedOptionalContext => "malformed_optional_context",
        };
        let optional = reason == Reason::MalformedOptionalContext;
        let summary = if optional {
            format!(
                "Malformed optional test context for {}",
                crate::network_guard::sanitize(&self.host)
            )
        } else {
            format!(
                "Test context {reason_name} for {}{}",
                crate::network_guard::sanitize(&self.host),
                if blocked { "" } else { " (warn)" }
            )
        };
        let details = json!({ "reason": reason_name, "path": self.path, "method": self.method,
            "port": port, "connection_id": self.identity.connection_id });
        let mut event = audit::Event::new(
            "security.test_context",
            audit::Kind::Security,
            if optional {
                audit::Severity::Medium
            } else {
                audit::Severity::High
            },
            &summary,
        );
        event.addon = Some("test-context".into());
        event.decision = Some(if blocked {
            audit::Decision::Deny
        } else {
            audit::Decision::Warn
        });
        event.host = Some(self.host.clone());
        event.agent = self.identity.request_agent().map(str::to_owned);
        event.request_id = Some(self.request_id.clone());
        let attribution = self.identity.audit_attribution();
        event.attribution = Some(attribution.clone());
        event.details = details.clone().into();
        let attribution_provenance = attribution
            .provenance
            .as_ref()
            .and_then(|value| value.render_json(false).ok())
            .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
            .unwrap_or_else(|| json!({}));
        self.runtime.audit.emit(event)?;
        Ok(self
            .runtime
            .record(json!({
                "event": "security.test_context", "kind": "security",
                "severity": if optional { "medium" } else { "high" },
                "addon": "test-context", "decision": if blocked { "deny" } else { "warn" },
                "summary": summary, "host": self.host, "request_id": self.request_id,
                "agent": self.identity.request_agent(),
                "evidence_owner": attribution.evidence_owner,
                "trusted_transport_identity": attribution.trusted_transport_identity,
                "initiator": "unknown",
                "attribution_status": attribution.status.map(audit::AttributionStatus::as_str),
                "attribution_provenance": attribution_provenance,
                "details": details,
            }))
            .is_err())
    }

    fn response(
        &self,
        head: &Head,
        content: Option<&[u8]>,
        now: f64,
    ) -> Result<(bool, ResponseOutcome), HookError> {
        let (context, started) = {
            let applied = self.applied.lock().unwrap_or_else(|e| e.into_inner());
            let Some(applied) = applied.as_ref() else {
                return Ok((false, ResponseOutcome::NotApplicable));
            };
            (applied.context.clone(), applied.started)
        };
        let snippet = body_snippet(content, &head.encoding)?;
        // Source uses signed wall-clock elapsed time, truncated toward zero.
        let duration = if started == 0. {
            0.
        } else {
            ((now - started) * 1000.).trunc()
        };
        let duration_ms: serde_json::Number = format!("{duration:.0}")
            .parse()
            .expect("finite wall-clock duration");
        let summary = format!(
            "Test context response: {} {}{}",
            head.status.as_u16(),
            crate::network_guard::sanitize(&self.host),
            crate::network_guard::sanitize(&self.path)
        );
        let details = json!({
            "phase": "response", "method": self.method, "path": self.path,
            "context": context.context, "trusted_agent": context.trusted_agent,
            "test_agent_match": context.test_agent_match,
            "test_context_source": context.source, "status_code": head.status.as_u16(),
            "response_body_snippet": snippet, "duration_ms": duration_ms,
        });
        let mut event = audit::Event::new(
            "security.test_context",
            audit::Kind::Security,
            audit::Severity::Low,
            &summary,
        );
        event.addon = Some("test-context".into());
        event.host = Some(self.host.clone());
        event.agent = self.identity.request_agent().map(str::to_owned);
        event.request_id = Some(self.request_id.clone());
        event.attribution = Some(self.identity.audit_attribution());
        event.details = details.clone().into();
        self.runtime.audit.emit(event)?;
        Ok((
            self.runtime
                .record(json!({
                    "event": "security.test_context", "kind": "security", "severity": "low",
                    "addon": "test-context", "host": self.host,
                    "agent": self.identity.request_agent(), "request_id": self.request_id,
                    "summary": summary, "details": details,
                }))
                .is_err(),
            ResponseOutcome::Recorded,
        ))
    }
}

fn body_snippet(content: Option<&[u8]>, encoding: &[u8]) -> Result<String, ContentError> {
    let Some(content) = content else {
        return Ok(String::new());
    };
    let decoded = http_content::decode_prefix(content, encoding, 4096)?;
    Ok(String::from_utf8_lossy(&decoded)
        .chars()
        .take(512)
        .collect())
}

struct Head {
    status: StatusCode,
    encoding: Zeroizing<Vec<u8>>,
    content_type: Zeroizing<Vec<u8>>,
    end_stream_at_head: bool,
}

pub(super) fn combined(
    headers: &HeaderMap,
    name: header::HeaderName,
) -> Result<Zeroizing<Vec<u8>>, ContentError> {
    let mut bytes = Zeroizing::new(Vec::new());
    for (index, value) in headers.get_all(name).iter().enumerate() {
        bytes
            .try_reserve(
                value
                    .as_bytes()
                    .len()
                    .checked_add(2)
                    .ok_or(ContentError::Allocation)?,
            )
            .map_err(|_| ContentError::Allocation)?;
        if index != 0 {
            bytes.extend_from_slice(b", ");
        }
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(bytes)
}

struct Capture {
    head: Option<Head>,
    body: BufferedContent,
    memory_streamed: bool,
    classified: bool,
    failed: bool,
}

/// Parser callbacks only copy selected head facts and bounded encoded DATA.
/// Application methods resolve policy and decode outside the capture mutex.
/// This owner holds no protocol producer/observer and cannot form an Arc cycle.
pub(super) struct ResponseCapture {
    capture: Mutex<Option<Capture>>,
    state: RuntimeState,
    provenance: Option<Arc<Provenance>>,
    traffic: Option<Arc<super::traffic::Traffic>>,
    recording: Option<Arc<super::flow_recording::Recording>>,
    method: String,
    host: String,
    trace: Option<Arc<RequestTrace>>,
    live: Option<Arc<crate::traffic_view::Exchange>>,
}

impl ResponseCapture {
    pub(super) fn new(
        state: RuntimeState,
        provenance: Option<Arc<Provenance>>,
        traffic: Option<Arc<super::traffic::Traffic>>,
        recording: Option<Arc<super::flow_recording::Recording>>,
        trace: Option<Arc<RequestTrace>>,
    ) -> Self {
        let (method, host) = if let Some(traffic) = &traffic {
            (traffic.method.clone(), traffic.host.clone())
        } else {
            let provenance = provenance
                .as_ref()
                .expect("response capture has a consumer");
            (provenance.method.clone(), provenance.host.clone())
        };
        let recording = recording.or_else(|| {
            provenance
                .as_ref()
                .and_then(|provenance| provenance.recording())
        });
        Self {
            capture: Mutex::new(Some(Capture {
                head: None,
                body: BufferedContent::new(None, false),
                memory_streamed: false,
                classified: false,
                failed: false,
            })),
            state,
            provenance,
            traffic,
            recording,
            method,
            host,
            trace,
            live: None,
        }
    }

    pub(super) fn attach_live(&mut self, live: Option<Arc<crate::traffic_view::Exchange>>) {
        self.live = live;
    }

    /// Observe the validated transport result before later addon hooks can
    /// discard their evidence buffer. This does not execute those hooks.
    pub(super) fn finish_live(&self, success: bool, error: Option<&str>) {
        let Some(live) = &self.live else {
            return;
        };
        let capture = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        let content = capture
            .as_ref()
            .filter(|capture| success && !capture.failed)
            .and_then(|capture| capture.body.content());
        if success {
            live.response_body_complete(content);
        } else {
            live.response_body(content);
        }
        live.finish((!success).then_some(error.unwrap_or("upstream response incomplete")));
    }

    fn live_head<'a>(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        fields: Option<impl Iterator<Item = (&'a [u8], &'a [u8])>>,
    ) {
        if let Some(live) = &self.live {
            live.response_head(
                status.as_u16(),
                fields
                    .map(super::live_view::pairs)
                    .unwrap_or_else(|| super::live_view::header_map(headers)),
            );
        }
    }

    fn recording(&self) -> Option<Arc<super::flow_recording::Recording>> {
        self.recording.clone()
    }

    /// Supply a response that the local probe sink has constructed in full.
    /// No upstream parser observation is inferred. Source SSE selection skips
    /// memory accounting but retains an inline local body's provenance/logging.
    pub(super) fn local_probe(&self, status: StatusCode, headers: &HeaderMap, body: &[u8]) {
        self.head(status, headers, false);
        self.data(body);
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .map_or(&b""[..], |value| value.as_bytes());
        let streamed = self
            .state
            .read()
            .map(|runtime| source_streamed(&runtime, &self.host, content_type));
        if let Some(capture) = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
        {
            capture.classified = true;
            match streamed {
                Ok(streamed) => capture.memory_streamed = streamed,
                Err(_) => capture.failed = true,
            }
        }
    }

    fn head(&self, status: StatusCode, headers: &HeaderMap, end_stream_at_head: bool) {
        let mut guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        let Some(capture) = guard.as_mut() else {
            return;
        };
        if capture.failed || capture.head.is_some() {
            return;
        }
        let result = (|| {
            let encoding = combined(headers, header::CONTENT_ENCODING)?;
            let content_type = combined(headers, header::CONTENT_TYPE)?;
            Ok::<_, ContentError>(Head {
                status,
                encoding,
                content_type,
                end_stream_at_head,
            })
        })();
        match result {
            Ok(head) => {
                // Expected payload size and the actual head's terminal flag
                // differ for H2 HEAD/204/304 followed by empty DATA or trailers.
                // Only the latter suppresses source SSE streaming selection.
                let zero_length = end_stream_at_head
                    || self.method.eq_ignore_ascii_case("HEAD")
                    || status.is_informational()
                    || matches!(status.as_u16(), 204 | 304)
                    || (self.method.eq_ignore_ascii_case("CONNECT") && status.is_success());
                let length = (!zero_length)
                    .then(|| {
                        headers
                            .get(header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse().ok())
                    })
                    .flatten();
                capture.body = BufferedContent::new(length, false);
                capture.head = Some(head);
            }
            Err(_) => {
                capture.failed = true;
                capture.body = BufferedContent::new(None, true);
            }
        }
    }

    fn data(&self, payload: &[u8]) {
        let mut guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        let Some(capture) = guard.as_mut() else {
            return;
        };
        if !capture.failed && capture.body.try_push(payload).is_err() {
            capture.failed = true;
            capture.body = BufferedContent::new(None, true);
        }
    }

    /// Serialized by the existing completion application's observation mutex.
    /// Called at normal header receipt and before applying an earlier EOM.
    pub(super) fn apply_head(&self) {
        let facts = {
            let guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());
            let Some(capture) = guard.as_ref().filter(|c| !c.classified && !c.failed) else {
                return;
            };
            let Some(head) = capture.head.as_ref() else {
                return;
            };
            (head.end_stream_at_head, head.content_type.clone())
        };
        let streamed = if facts.0 {
            false
        } else {
            let runtime = self.state.read().map(|runtime| runtime.clone());
            match runtime {
                Ok(runtime) => source_streamed(&runtime, &self.host, &facts.1),
                Err(_) => {
                    let mut guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(capture) = guard.as_mut() {
                        capture.failed = true;
                    }
                    return;
                }
            }
        };
        let mut guard = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(capture) = guard.as_mut().filter(|c| !c.classified) {
            capture.classified = true;
            if streamed {
                capture.body = BufferedContent::new(None, true);
            }
        }
    }

    /// Called once after successful upstream completion or local construction,
    /// before CircuitBreaker. Preserve this same buffer for later consumers.
    pub(super) fn memory_response(&self) {
        let Some(traffic) = &self.traffic else {
            return;
        };
        let capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let Some(capture) = capture else {
            return;
        };
        if !capture.failed
            && !capture.memory_streamed
            && !capture.body.is_streamed()
            && let Some(head) = &capture.head
        {
            traffic.memory_response_size(|| {
                super::traffic::memory_decoded_size(capture.body.content(), Ok(&head.encoding))
            });
        }
        *self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(capture);
    }

    /// An earlier production response hook raised. Release captured bytes and
    /// pending recording without applying provenance or recorder counters.
    pub(super) fn skip_response(&self) {
        let capture = self
            .capture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        drop(capture);
        if let Some(recording) = self.recording() {
            recording.skip_response();
        }
    }

    /// Called after protocol completion or construction of a complete local probe.
    /// Take and release the buffer mutex before decoding or evidence writes.
    pub(super) fn finish(&self, success: bool) -> bool {
        if success {
            self.apply_head();
        }
        let capture = self
            .capture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(capture) = capture else {
            return false;
        };
        if !success {
            if let Some(recording) = self.recording() {
                recording.finish(false, None, false);
            }
            return false;
        }
        if capture.failed {
            if let Some(recording) = self.recording() {
                recording.finish(true, None, true);
            }
            return true;
        }
        let Some(head) = capture.head else {
            return true;
        };
        let content = capture.body.into_content();
        let content = content.as_deref().map(Vec::as_slice);
        let hook = self
            .trace
            .as_ref()
            .and_then(|trace| trace.hook("test-context", "response"));
        let provenance = self
            .provenance
            .as_ref()
            .map_or(Ok((false, ResponseOutcome::NotApplicable)), |provenance| {
                provenance.response(&head, content, crate::circuit_runtime::now())
            });
        match provenance {
            Ok((mut failed, outcome)) => {
                if let Some(hook) = &hook {
                    match outcome {
                        ResponseOutcome::NotApplicable => hook.evaluated("not_applicable", None),
                        ResponseOutcome::Recorded => hook.evaluated(
                            "response_recorded",
                            Some(json!({"status_code":head.status.as_u16()}).into()),
                        ),
                    }
                }
                if let Some(recording) = self.recording() {
                    recording.finish(true, content, false);
                }
                if let Some(traffic) = &self.traffic {
                    failed |= traffic.response(head.status.as_u16(), None, None, || {
                        super::traffic::decoded_size(content, Ok(&head.encoding))
                    });
                }
                failed
            }
            Err(error) => {
                if let Some(hook) = &hook {
                    hook.error(error.trace_reason());
                }
                // ProductionAddons shares one dispatcher exception boundary.
                // A failed TestContext response hook skips the later recorder;
                // no recorder counter or retry belongs to this response.
                if let Some(recording) = self.recording() {
                    recording.skip_response();
                }
                eprintln!("Test context response hook failed: {error}");
                error.evidence_failed()
            }
        }
    }
}

pub(super) fn source_streamed(runtime: &Runtime, host: &str, content_type: &[u8]) -> bool {
    runtime.config.sse_streaming_enabled
        && runtime
            .policy
            .as_ref()
            .is_none_or(|policy| policy.is_addon_enabled(Addon::SseStreaming, Some(host), None))
        && (content_type.starts_with(b"text/event-stream")
            || content_type.starts_with(b"application/x-ndjson")
            || (runtime.config.sse_stream_json && content_type.starts_with(b"application/json")))
}

impl hyper::ext::ResponseBodyCapture for ResponseCapture {
    fn head_with_fields(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        end_stream_at_head: bool,
        fields: Option<&hyper::ext::OriginalHeaderFields>,
        reason: Option<&[u8]>,
    ) {
        Self::head(self, status, headers, end_stream_at_head);
        self.live_head(status, headers, fields.map(|fields| fields.iter()));
        if let Some(live) = &self.live {
            live.response_details(None, reason);
        }
        if let Some(recording) = self.recording() {
            recording.head(status, fields.map(|fields| fields.iter()), reason);
        }
    }

    fn head(&self, status: StatusCode, headers: &HeaderMap, end_stream_at_head: bool) {
        Self::head(self, status, headers, end_stream_at_head);
        self.live_head(status, headers, None::<std::iter::Empty<(&[u8], &[u8])>>);
    }

    fn data(&self, payload: &[u8]) {
        Self::data(self, payload);
    }
}

impl h2::ext::ResponseBodyCapture for ResponseCapture {
    fn head_with_fields(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        end_stream_at_head: bool,
        fields: Option<&h2::ext::OriginalHeaderFields>,
        reason: Option<&[u8]>,
    ) {
        Self::head(self, status, headers, end_stream_at_head);
        self.live_head(status, headers, fields.map(|fields| fields.iter()));
        if let Some(live) = &self.live {
            live.response_details(None, reason);
        }
        if let Some(recording) = self.recording() {
            recording.head(status, fields.map(|fields| fields.iter()), reason);
        }
    }

    fn head(&self, status: StatusCode, headers: &HeaderMap, end_stream_at_head: bool) {
        Self::head(self, status, headers, end_stream_at_head);
        self.live_head(status, headers, None::<std::iter::Empty<(&[u8], &[u8])>>);
    }

    fn data(&self, payload: &[u8]) {
        Self::data(self, payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_context::{Context, ContextSource};
    use serde_json::Value;
    use std::sync::RwLock;
    use tempfile::TempDir;

    struct Fixture {
        directory: TempDir,
        state: RuntimeState,
    }

    impl Fixture {
        fn new(read_only_event_log: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let policy = directory.path().join("policy.json");
            let event_log = directory.path().join("events.jsonl");
            std::fs::write(&policy, "{}").unwrap();
            let config = serde_json::from_value(json!({
                "listeners": [], "policy_file": policy, "data_dir": directory.path().join("data"),
                "readiness_file": directory.path().join("ready"),
                "flow_store_enabled": false,
                "audit_log_path": directory.path().join("audit.jsonl"),
                "event_log": event_log.clone(),
            }))
            .unwrap();
            let mut runtime = Runtime::new(
                config,
                "capture-fixture",
                Arc::new(tokio::sync::Mutex::new(())),
                None,
                None,
            )
            .unwrap();
            if read_only_event_log {
                // Fail only the completed-response evidence write. The owned
                // log opens normally, then this read-only handle makes the
                // real writer fail on both Linux and macOS.
                runtime.events = Arc::new(Mutex::new(std::fs::File::open(event_log).unwrap()));
            }
            Self {
                directory,
                state: Arc::new(RwLock::new(Arc::new(runtime))),
            }
        }

        fn provenance(&self) -> Arc<Provenance> {
            self.provenance_for_method("POST")
        }

        fn provenance_for_method(&self, method: &str) -> Arc<Provenance> {
            Arc::new(Provenance::new(
                self.state.read().unwrap().clone(),
                ConnectionIdentity {
                    agent_id: "alice".into(),
                    connection_id: "connection".into(),
                    source_id: None,
                    reconciled: None,
                },
                "request".into(),
                method.into(),
                "owned.invalid".into(),
                "/body".into(),
            ))
        }

        fn capture(
            &self,
            provenance: Arc<Provenance>,
            headers: &[(&str, &str)],
            bodyless: bool,
        ) -> ResponseCapture {
            let capture =
                ResponseCapture::new(self.state.clone(), Some(provenance), None, None, None);
            let mut fields = HeaderMap::new();
            for (name, value) in headers {
                fields.append(
                    header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            capture.head(StatusCode::OK, &fields, bodyless);
            capture
        }

        fn events(&self) -> Vec<Value> {
            std::fs::read_to_string(self.directory.path().join("events.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|event: &Value| event["event"] == "security.test_context")
                .collect()
        }

        fn reload(&self, enabled: bool, policy: Value) {
            let mut state = self.state.write().unwrap();
            let old = state.clone();
            let mut config = old.config.clone();
            config.sse_streaming_enabled = enabled;
            std::fs::write(config.policy_file.as_ref().unwrap(), policy.to_string()).unwrap();
            *state = Arc::new(
                Runtime::new(
                    config,
                    "capture-fixture",
                    Arc::new(tokio::sync::Mutex::new(())),
                    Some(&old),
                    None,
                )
                .unwrap(),
            );
        }
    }

    fn context() -> AppliedContext {
        AppliedContext {
            context: Context::parse("run=run1;agent=claimed;test=T1").unwrap(),
            source: ContextSource::Header,
            trusted_agent: Some("alice".into()),
            test_agent_match: Some(false),
            live_metadata: Default::default(),
        }
    }

    #[test]
    fn request_content_failure_keeps_response_provenance_and_trusted_identity() {
        let fixture = Fixture::new(false);
        let provenance = fixture.provenance();
        assert_eq!(
            provenance.apply_request(context(), Some(b"invalid"), Ok(b"gzip"), 100.),
            Err(HookError::Content(ContentError::Value))
        );
        assert!(fixture.events().is_empty());
        let capture = fixture.capture(provenance, &[], false);
        capture.data(b"normal ");
        capture.data(b"response");
        assert!(!capture.finish(true));
        assert!(!capture.finish(true));
        let events = fixture.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["agent"], "alice");
        assert_eq!(events[0]["details"]["context"]["agent"], "claimed");
        assert_eq!(events[0]["details"]["trusted_agent"], "alice");
        assert_eq!(events[0]["details"]["test_agent_match"], false);
        assert_eq!(
            events[0]["details"]["response_body_snippet"],
            "normal response"
        );
        assert!(
            events[0]["details"]["duration_ms"]
                .as_number()
                .unwrap()
                .to_string()
                .bytes()
                .all(|c| c.is_ascii_digit())
        );
    }

    #[test]
    fn early_response_abort_and_late_decode_error_do_not_create_events() {
        let fixture = Fixture::new(false);
        let provenance = fixture.provenance();
        let early = fixture.capture(provenance.clone(), &[], false);
        early.data(b"early");
        assert!(!early.finish(true));
        assert!(fixture.events().is_empty());
        assert!(
            !provenance
                .apply_request(context(), Some(b"request"), Ok(b""), 100.)
                .unwrap()
        );
        let aborted = fixture.capture(provenance.clone(), &[], false);
        aborted.data(b"partial");
        assert!(!aborted.finish(false));
        aborted.data(b"after abort");
        assert!(!aborted.finish(true));
        let corrupt = fixture.capture(provenance, &[("content-encoding", "gzip")], false);
        corrupt.data(b"invalid");
        assert!(!corrupt.finish(true));
        assert_eq!(fixture.events().len(), 1);
        assert_eq!(fixture.events()[0]["details"]["phase"], "request");
    }

    #[test]
    fn streamed_bodies_skip_decoding_but_bodyless_headers_keep_buffered_empty() {
        let fixture = Fixture::new(false);
        let provenance = fixture.provenance();
        provenance
            .apply_request(context(), None, Ok(b"invalid"), 100.)
            .unwrap();
        let sse = fixture.capture(
            provenance.clone(),
            &[
                ("content-type", "text/event-stream"),
                ("content-encoding", "invalid"),
            ],
            false,
        );
        sse.data(b"data: sample\n\n");
        assert!(!sse.finish(true));
        let large = fixture.capture(
            provenance.clone(),
            &[
                ("content-length", "10485761"),
                ("content-encoding", "invalid"),
            ],
            false,
        );
        large.data(b"body");
        assert!(!large.finish(true));
        let bodyless = fixture.capture(
            provenance,
            &[
                ("content-length", "10485761"),
                ("content-type", "text/event-stream"),
                ("content-encoding", "invalid"),
            ],
            true,
        );
        assert!(!bodyless.finish(true));
        let events = fixture.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1]["details"]["response_body_snippet"], "");
        assert_eq!(events[2]["details"]["response_body_snippet"], "");
    }

    #[test]
    fn response_head_retains_sse_choice_over_reload_and_uses_domain_only_query() {
        let fixture = Fixture::new(false);
        let provenance = fixture.provenance();
        provenance
            .apply_request(context(), Some(b""), Ok(b""), 100.)
            .unwrap();
        let held = fixture.capture(
            provenance.clone(),
            &[("content-type", "text/event-stream")],
            false,
        );
        held.apply_head();
        fixture.reload(false, json!({}));
        held.data(b"held");
        assert!(!held.finish(true));
        let disabled = fixture.capture(
            provenance.clone(),
            &[("content-type", "text/event-stream")],
            false,
        );
        disabled.data(b"disabled");
        assert!(!disabled.finish(true));
        fixture.reload(
            true,
            json!({"clients":{"alice":{"addons":{"sse_streaming":{"enabled":false}}}}}),
        );
        let agent_setting = fixture.capture(
            provenance.clone(),
            &[("content-type", "text/event-stream")],
            false,
        );
        agent_setting.data(b"agent override ignored");
        assert!(!agent_setting.finish(true));
        fixture.reload(
            true,
            json!({"domains":{"owned.invalid":{"addons":{"sse_streaming":{"enabled":false}}}}}),
        );
        let domain_setting =
            fixture.capture(provenance, &[("content-type", "text/event-stream")], false);
        domain_setting.data(b"domain disabled");
        assert!(!domain_setting.finish(true));
        let snippets: Vec<_> = fixture
            .events()
            .into_iter()
            .skip(1)
            .map(|event| event["details"]["response_body_snippet"].clone())
            .collect();
        assert_eq!(
            snippets,
            vec![
                json!(""),
                json!("disabled"),
                json!(""),
                json!("domain disabled")
            ]
        );
    }

    #[test]
    fn snippet_uses_decoded_utf8_prefix_and_preserves_write_failure() {
        let text = "é".repeat(600);
        assert_eq!(
            body_snippet(Some(text.as_bytes()), b"").unwrap(),
            "é".repeat(512)
        );
        assert_eq!(body_snippet(Some(b"\xffx"), b"").unwrap(), "�x");
        assert_eq!(body_snippet(None, b"unknown").unwrap(), "");
        assert_eq!(
            body_snippet(Some(b""), b"unknown"),
            Err(ContentError::Value)
        );
        let fixture = Fixture::new(true);
        let provenance = fixture.provenance();
        assert!(
            provenance
                .apply_request(context(), Some(b"body"), Ok(b""), 100.)
                .unwrap()
        );
        let capture = fixture.capture(provenance, &[], true);
        assert!(
            capture.finish(true),
            "a successful response must report the injected evidence-write failure"
        );
        assert!(
            fixture.events().is_empty(),
            "a failed evidence write must not be reported as durable"
        );
    }

    #[tokio::test]
    async fn h2_parser_completion_records_all_unread_data() {
        h2_unread("POST", false, Some("first second")).await;
        // HEAD's advertised size must not select absent content and hide the
        // invalid encoding. An actual nonfinal head still permits source SSE.
        h2_unread("HEAD", false, None).await;
        h2_unread("HEAD", true, Some("")).await;
    }

    async fn h2_unread(method: &'static str, sse: bool, snippet: Option<&str>) {
        use bytes::Bytes;
        use http_body_util::Empty;
        use hyper::{Request, Response};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use std::time::Duration;

        let fixture = Fixture::new(false);
        let provenance = fixture.provenance_for_method(method);
        provenance
            .apply_request(context(), Some(b"request"), Ok(b""), 100.)
            .unwrap();
        let capture = Arc::new(ResponseCapture::new(
            fixture.state.clone(),
            Some(provenance),
            None,
            None,
            None,
        ));
        let (client, server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut response = Response::builder().status(200);
            if method == "HEAD" {
                response = response
                    .header("content-length", "10485761")
                    .header("content-encoding", "invalid");
                if sse {
                    response = response.header("content-type", "text/event-stream");
                }
            } else {
                response = response.header("content-length", "12");
            }
            let mut send = respond
                .send_response(response.body(()).unwrap(), false)
                .unwrap();
            if method == "HEAD" {
                send.send_data(Bytes::new(), true).unwrap();
            } else {
                send.send_data(Bytes::from_static(b"first "), false)
                    .unwrap();
                send.send_data(Bytes::from_static(b"second"), true).unwrap();
            }
            while connection.accept().await.is_some() {}
        });
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                .await
                .unwrap();
        let driver = tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri("http://owned.invalid/body")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let completion = h2::ext::on_response_complete_with_capture(&mut request, capture.clone());
        let response = sender.send_request(request);
        let terminal = tokio::time::timeout(Duration::from_secs(3), completion).await;
        // Keep both drivers alive until the terminal result, then cancel/join
        // only these owned in-memory fixtures even if the assertion will fail.
        let success = matches!(terminal, Ok(Ok(StatusCode::OK)));
        let terminal_head = capture
            .capture
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|capture| capture.head.as_ref())
            .map(|head| head.end_stream_at_head);
        let evidence_failed = capture.finish(success);
        drop(response); // Neither response headers nor Incoming DATA were polled.
        driver.abort();
        peer.abort();
        let _ = driver.await;
        let _ = peer.await;
        assert!(success, "unread response did not complete: {terminal:?}");
        assert_eq!(terminal_head, Some(false), "test requires a nonfinal head");
        assert!(!evidence_failed);
        let events = fixture.events();
        assert_eq!(events.len(), 1 + usize::from(snippet.is_some()));
        if let Some(snippet) = snippet {
            assert_eq!(events[1]["details"]["response_body_snippet"], snippet);
        }
        assert!(!capture.finish(true));
        assert_eq!(fixture.events().len(), events.len());
    }
}
