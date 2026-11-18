//! Bounded failure evidence from the existing authenticated own-request reader.

use std::{path::Path, time::Duration};

use hyper::{Method, StatusCode};
use serde_json::{Value, json};

use super::{ApiResponseHead, Error, helper_reply};

pub(super) const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 32 * 1024;
const COLLECTION_TIME: Duration = Duration::from_secs(2);

/// Canonical refusal details also let guided operator edits refresh a stale
/// preview. An HTTP failure remains distinct from an absent response.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub status: u16,
    pub body: Value,
    request_id: Option<String>,
    correlation: &'static str,
    body_state: &'static str,
    details_limited: bool,
    timed_out: bool,
    headers: [Option<String>; 2],
    message: String,
    pub(super) diagnostic: Option<Value>,
}

impl ApiError {
    pub(super) fn new(
        head: ApiResponseHead,
        mut body: Value,
        body_state: &'static str,
        read_error: Option<(String, bool)>,
        token: &str,
    ) -> Self {
        let ApiResponseHead {
            status,
            request_id,
            correlation,
            blocked_by,
            retry_after,
        } = head;
        let details_limited = protect(&mut body, token);
        let timed_out = read_error.as_ref().is_some_and(|(_, timed_out)| *timed_out);
        let read_error = read_error.as_ref().map(|(message, _)| message.as_str());
        let reason = status.canonical_reason().unwrap_or("request failed");
        let message = if status.is_success() {
            clean(read_error.unwrap_or("invalid JSON response"), token)
        } else {
            let detail = body["error"].as_str().unwrap_or(reason);
            let mut message = format!("API {status}: {detail}");
            if body["send_outcome"] == "unknown" {
                message
                    .push_str("; send outcome unknown; inspect retained history before repeating");
            }
            if let Some(error) = read_error {
                message.push_str(&format!(
                    "; could not read response body: {}",
                    clean(error, token)
                ));
            }
            message
        };
        Self {
            status: status.as_u16(),
            body,
            request_id,
            correlation,
            body_state,
            details_limited,
            timed_out,
            headers: [blocked_by, retry_after].map(|h| h.map(|s| clean(&s, token))),
            message,
            diagnostic: None,
        }
    }

    fn details(&self) -> Value {
        json!({
            "message": self.message, "response_received": true,
            "http_status": self.status,
            "http_reason": StatusCode::from_u16(self.status).ok().and_then(|s| s.canonical_reason()),
            "request_id": self.request_id, "correlation": self.correlation,
            "diagnostic_reference": self.request_id.as_ref().map(|id| format!("http://_safeyolo.proxy.internal/explain?request_id={id}")),
            "blocked_by": self.headers[0], "retry_after": self.headers[1],
            "body_state": self.body_state, "error_details": self.body,
            "details_limited": self.details_limited, "diagnostic": self.diagnostic,
            "timed_out": self.timed_out,
        })
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        if let Some(identifier) = &self.request_id {
            write!(f, "; request_id={identifier}")?;
        }
        if let Some(reference) = self
            .diagnostic
            .as_ref()
            .and_then(|d| d["reference"].as_str())
        {
            write!(f, "; diagnostic={reference}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ApiError {}
impl Drop for ApiError {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.body);
        if let Some(value) = &mut self.diagnostic {
            crate::credentials::wipe_json(value);
        }
    }
}

pub(crate) fn tool_failure(error: &Error) -> Value {
    if let Some(error) = error.downcast_ref::<ApiError>() {
        return error.details();
    }
    json!({"message":clean(&error.to_string(), ""), "response_received":false,
        "http_status":null, "request_id":null, "correlation":"unavailable",
        "timed_out":error.is::<tokio::time::error::Elapsed>()})
}

fn clean(text: &str, token: &str) -> String {
    let text = if token.is_empty() {
        text.to_owned()
    } else {
        text.replace(token, "<redacted>")
    };
    crate::network_guard::sanitize_with_limit(&crate::coord_timeline::redact_text(&text), 1024)
}

/// Reuse the existing secret-pattern display protection, also removing named
/// credential values and any echo of the caller's bearer. Do not copy headers,
/// raw malformed bodies, arbitrary depth or unbounded event content to MCP.
pub(super) fn protect(value: &mut Value, token: &str) -> bool {
    fn visit(
        value: &mut Value,
        token: &str,
        depth: usize,
        remaining: &mut usize,
        limited: &mut bool,
    ) {
        if depth > 12 || *remaining == 0 {
            crate::credentials::wipe_json(value);
            *value = json!("<omitted: diagnostic limit>");
            *limited = true;
            return;
        }
        *remaining -= 1;
        match value {
            Value::String(text) => {
                *limited |= text.chars().count() > 1024;
                let safe = clean(text, token);
                use zeroize::Zeroize;
                text.zeroize();
                *text = safe;
            }
            Value::Array(values) => {
                if values.len() > 128 {
                    for value in &mut values[128..] {
                        crate::credentials::wipe_json(value);
                    }
                    values.truncate(128);
                    *limited = true;
                }
                for value in values {
                    visit(value, token, depth + 1, remaining, limited);
                }
            }
            Value::Object(values) => {
                let mut safe_values = serde_json::Map::new();
                let mut pending = std::mem::take(values);
                let mut ordered = Vec::new();
                // Padding must not consume the projection budget before the
                // endpoint's outcome, correlation and reader status survive.
                if depth == 0 {
                    for key in [
                        "send_outcome",
                        "request_id",
                        "status",
                        "error",
                        "reason",
                        "action",
                        "retry_after",
                        "searched_lines_per_file",
                    ] {
                        if let Some(value) = pending.remove(key) {
                            ordered.push((key.to_owned(), value));
                        }
                    }
                }
                ordered.extend(pending);
                for (key, mut value) in ordered {
                    let safe_key = clean(&key, token);
                    *limited |= key.chars().count() > 1024;
                    let key = key.to_ascii_lowercase().replace('-', "_");
                    if matches!(
                        key.as_str(),
                        "authorization"
                            | "proxy_authorization"
                            | "password"
                            | "passphrase"
                            | "secret"
                            | "client_secret"
                            | "token"
                            | "access_token"
                            | "refresh_token"
                            | "api_key"
                            | "cookie"
                            | "set_cookie"
                            | "private_key"
                            | "credentials"
                    ) {
                        crate::credentials::wipe_json(&mut value);
                        value = json!("<redacted>");
                    } else {
                        visit(&mut value, token, depth + 1, remaining, limited);
                    }
                    safe_values.insert(safe_key, value);
                }
                *values = safe_values;
            }
            _ => {}
        }
    }
    let mut limited = false;
    visit(value, token, 0, &mut 512, &mut limited);
    if value.to_string().len() > MAX_OUTPUT_BYTES {
        // Preserve actionable refusal and unknown-publication fields even if
        // the rest of an otherwise valid document exceeds the output budget.
        let mut small = json!({});
        for key in [
            "error",
            "send_outcome",
            "action",
            "reason",
            "request_id",
            "status",
            "searched_lines_per_file",
        ] {
            if (value[key].is_string() || value[key].is_number())
                && value[key].to_string().len() <= MAX_OUTPUT_BYTES / 16
            {
                small[key] = value[key].clone();
            }
        }
        if value["events"].is_array() {
            small["events"] = json!([]);
        }
        crate::credentials::wipe_json(value);
        *value = small;
        limited = true;
    }
    limited
}

pub(super) async fn collect(
    socket: Option<&Path>,
    token_file: &Path,
    original: &ApiError,
) -> Value {
    let mut result = json!({
        "collection_state":"missing_correlation", "original_request_id":original.request_id,
        "reference":null, "reads":[], "evidence":null,
        "limits":{"timeout_ms":2000,"max_reads":2,"max_response_bytes":MAX_RESPONSE_BYTES,"max_output_bytes":MAX_OUTPUT_BYTES},
        "interpretation":"Retained events describe reached observations. A complete search or blocked_by: agent-api does not identify a root cause. Diagnosis does not replay the original operation or authorize recovery.",
    });
    let Some(identifier) = &original.request_id else {
        return result;
    };
    let path = format!("/explain?request_id={identifier}");
    result["reference"] = json!(format!("http://_safeyolo.proxy.internal{path}"));
    let deadline = tokio::time::Instant::now() + COLLECTION_TIME;
    for _ in 0..2 {
        let reply = tokio::time::timeout_at(
            deadline,
            helper_reply(
                socket,
                token_file,
                &path,
                Method::GET,
                Value::Null,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                MAX_RESPONSE_BYTES,
            ),
        )
        .await;
        match reply {
            Err(_) => {
                result["collection_state"] = json!("timeout");
                result["reads"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"http_status":null,"request_id":null,"timed_out":true}));
                break;
            }
            Ok(Err(error)) => {
                let failure = tool_failure(&error);
                result["collection_state"] = json!(if failure["timed_out"] == true {
                    "timeout"
                } else if failure["http_status"] == 401 || failure["http_status"] == 403 {
                    "denied"
                } else {
                    "unavailable"
                });
                result["reads"].as_array_mut().unwrap().push(json!({"http_status":failure["http_status"],"request_id":failure["request_id"],"body_state":failure["body_state"],"message":failure["message"],"timed_out":failure["timed_out"]}));
                break;
            }
            Ok(Ok(mut reply)) => {
                result["reads"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"http_status":reply.status,"request_id":reply.request_id}));
                if reply.value["request_id"] != *identifier
                    || !matches!(
                        reply.value["status"].as_str(),
                        Some("complete" | "pending" | "incomplete_search" | "error")
                    )
                    || !reply.value["events"].is_array()
                {
                    result["collection_state"] = json!("invalid_response");
                    crate::credentials::wipe_json(&mut reply.value);
                    break;
                }
                // Success bodies also need bounded disclosure before entering
                // an error result. The authenticated reader owns agent scope.
                let limited = reply.details_limited;
                let pending = reply.value["status"] == "pending";
                result["collection_state"] = json!("collected");
                result["evidence_limited"] = json!(limited);
                result["evidence"] = reply.value;
                if !pending || limited {
                    break;
                }
            }
        }
    }
    if result.to_string().len() > MAX_OUTPUT_BYTES {
        crate::credentials::wipe_json(&mut result["evidence"]);
        result["evidence"] = Value::Null;
        result["evidence_limited"] = json!(true);
    }
    result
}
