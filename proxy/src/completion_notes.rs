//! Optional terminal nominations. Authored JSON never supplies provenance.

use crate::{Error, coord_tools::text};
use serde::Serialize;
use serde_json::{Value, json};

pub const TRAILER_START: &str = "<<<SAFEYOLO_COMPLETION_NOTES_V1>>>";
pub const TRAILER_END: &str = "<<<END_SAFEYOLO_COMPLETION_NOTES_V1>>>";
const MAX_TRAILER_BYTES: usize = 32 * 1024;
const MAX_CANDIDATES: usize = 8;
const MAX_EVIDENCE: usize = 8;
const MAX_SUMMARY_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 2 * 1024;
const MAX_SNIPPET_BYTES: usize = 4 * 1024;
const MAX_EVIDENCE_REF_BYTES: usize = 512;

#[derive(Debug, Serialize)]
pub(crate) struct Parsed {
    pub delivery_state: Option<String>,
    pub delivery_body: String,
    pub trailer_status: &'static str,
    pub candidates: Vec<Value>,
    pub error: Option<String>,
}

pub(crate) fn hex_id(value: &str, prefix: &str, digits: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|tail| {
        tail.len() == digits
            && tail
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn provenance(envelope: &Value) -> Result<Value, Error> {
    if !hex_id(text(envelope, "msg_id")?, "msg-", 32)
        || envelope["sequence"].as_u64().is_none_or(|v| v == 0)
        || envelope["sent_at"].as_u64().is_none()
        || !text(envelope, "origin_instance_id")?.starts_with("sy-")
        || !matches!(
            text(envelope, "content_type")?,
            "text/plain" | "text/markdown"
        )
    {
        return Err("invalid canonical completion envelope".into());
    }
    match text(envelope, "sender_kind")? {
        "agent"
            if envelope["sender_agent_id"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
                && (envelope["sender_agent_name"].is_null()
                    || envelope["sender_agent_name"].is_string()) => {}
        "operator"
            if envelope["sender_agent_id"].is_null() && envelope["sender_agent_name"].is_null() => {
        }
        _ => return Err("invalid canonical completion sender".into()),
    }
    Ok(json!({
        "msg_id":envelope["msg_id"], "coord_sequence":envelope["sequence"],
        "sent_at":envelope["sent_at"], "sender_kind":envelope["sender_kind"],
        "sender_agent_id":envelope["sender_agent_id"], "sender_agent_name":envelope["sender_agent_name"],
        "origin_instance_id":envelope["origin_instance_id"]
    }))
}

fn delivery_state(body: &str) -> Option<String> {
    let line = body.split('\n').next().unwrap_or("");
    ["DONE", "READY", "CHANGES_REQUIRED", "BLOCKED", "FAILED"]
        .into_iter()
        .find(|state| {
            line.strip_prefix(state)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with([' ', '\t']))
        })
        .map(str::to_owned)
}

pub(crate) fn evidence_kind(value: &str) -> bool {
    matches!(
        value,
        "issue" | "pr" | "commit" | "head" | "tree" | "test" | "runtime" | "coord" | "document"
    )
}
fn note_text(value: &Value, maximum: usize) -> bool {
    value.as_str().is_some_and(|s| {
        !s.trim().is_empty()
            && s.len() <= maximum
            && !s.chars().any(|c| c < ' ' && !matches!(c, '\n' | '\t'))
    })
}
fn token(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 64
            && s.as_bytes()[0].is_ascii_lowercase()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
    })
}
fn candidate(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type"
                | "attribution"
                | "summary"
                | "kind"
                | "interest"
                | "why_interesting"
                | "evidence"
                | "snippet"
                | "outcome"
                | "area"
                | "problem"
                | "impact"
                | "suggestion"
                | "confidence"
        )
    }) || !matches!(
        value["type"].as_str(),
        Some("DISPATCH_CANDIDATE" | "FACTORY_CANDIDATE")
    ) || !matches!(
        value["attribution"].as_str(),
        Some(
            "lens_review_finding"
                | "forge_implementation_discovery"
                | "preexisting_bug_exposed_by_testing"
                | "infrastructure_environment_problem"
                | "factory_process_observation"
        )
    ) || !note_text(&value["summary"], MAX_SUMMARY_BYTES)
    {
        return false;
    }
    for field in ["kind", "interest", "confidence"] {
        if object.contains_key(field) && !token(&value[field]) {
            return false;
        }
    }
    for field in [
        "why_interesting",
        "outcome",
        "area",
        "problem",
        "impact",
        "suggestion",
    ] {
        if object.contains_key(field) && !note_text(&value[field], MAX_TEXT_BYTES) {
            return false;
        }
    }
    if object.contains_key("snippet") && !note_text(&value["snippet"], MAX_SNIPPET_BYTES) {
        return false;
    }
    if let Some(evidence) = object.get("evidence") {
        let Some(items) = evidence.as_array() else {
            return false;
        };
        if items.len() > MAX_EVIDENCE
            || items.iter().any(|item| {
                !item.as_object().is_some_and(|o| {
                    o.len() == 2 && o.contains_key("kind") && o.contains_key("ref")
                }) || !item["kind"].as_str().is_some_and(evidence_kind)
                    || !note_text(&item["ref"], MAX_EVIDENCE_REF_BYTES)
            })
        {
            return false;
        }
    }
    true
}

pub(crate) fn parse(envelope: &Value) -> Result<Parsed, Error> {
    let provenance = provenance(envelope)?;
    let body = text(envelope, "body")?;
    let mut result = Parsed {
        delivery_state: delivery_state(body),
        delivery_body: body.into(),
        trailer_status: "absent",
        candidates: Vec::new(),
        error: None,
    };
    let has_marker = |s: &str| {
        s.contains("<<<SAFEYOLO_COMPLETION_NOTES_")
            || s.contains("<<<END_SAFEYOLO_COMPLETION_NOTES_")
    };
    if !has_marker(body) {
        return Ok(result);
    }
    result.trailer_status = "invalid";
    // Fixed diagnostics never reflect untrusted candidate text or controls.
    result.error = Some("invalid completion-notes trailer".into());
    let Some((delivery, suffix)) = body.split_once(&format!("\n\n{TRAILER_START}\n")) else {
        return Ok(result);
    };
    let Some(payload) = suffix.strip_suffix(&format!("\n{TRAILER_END}")) else {
        return Ok(result);
    };
    if has_marker(delivery)
        || delivery_state(delivery).is_none()
        || payload.len() > MAX_TRAILER_BYTES
        || payload.contains(['\r', '\n'])
    {
        return Ok(result);
    }
    let Ok(document) = crate::policy::parse_json(payload, true) else {
        return Ok(result);
    };
    let Some(values) = document["candidates"].as_array() else {
        return Ok(result);
    };
    if document.as_object().is_none_or(|o| o.len() != 1)
        || values.is_empty()
        || values.len() > MAX_CANDIDATES
        || values.iter().any(|v| !candidate(v))
    {
        return Ok(result);
    }
    result.candidates = values
        .iter()
        .map(|value| {
            let mut value = value.clone();
            value["provenance"] = provenance.clone();
            value
        })
        .collect();
    result.delivery_body = delivery.into();
    result.trailer_status = "valid";
    result.error = None;
    Ok(result)
}
