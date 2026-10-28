//! Shared indicator submission through the transport-owned NSM namespace.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{ConnectionIdentity, audit, connection_events::ConnectionEvents};

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Request,
    Response,
}

impl Direction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Request => "client_to_server",
            Self::Response => "server_to_client",
        }
    }
}

pub(crate) struct ContentMetadata {
    pub(crate) content_type: &'static str,
    pub(crate) inspected_bytes: usize,
    pub(crate) prefix_truncated: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceEvidence {
    pub(crate) request_id: String,
    pub(crate) connection_id: String,
    pub(crate) host: String,
    pub(crate) evidence_hash: String,
    pub(crate) matched_fingerprints: usize,
    pub(crate) source_fingerprints: usize,
}

/// Sensors supply observations, never an enforcement decision or attribution.
pub(crate) struct Indicator<'a> {
    pub(crate) indicator_type: &'static str,
    pub(crate) sensor: &'static str,
    pub(crate) rule: &'static str,
    pub(crate) confidence: f64,
    pub(crate) severity: audit::Severity,
    pub(crate) summary: &'static str,
    pub(crate) connection_id: Option<&'a str>,
    pub(crate) direction: Option<Direction>,
    pub(crate) evidence_hash: Option<&'a str>,
    pub(crate) content: Option<&'a ContentMetadata>,
    pub(crate) source: Option<&'a SourceEvidence>,
}

pub(crate) fn emit(
    events: &ConnectionEvents,
    identity: &ConnectionIdentity,
    request_id: Option<&str>,
    host: Option<&str>,
    indicator: Indicator<'_>,
) {
    let mut event = audit::Event::new(
        "security.indicator",
        audit::Kind::Security,
        indicator.severity,
        indicator.summary,
    );
    event.request_id = request_id.map(str::to_owned);
    event.host = host.map(str::to_owned);
    let mut details = json!({
        "indicator_type":indicator.indicator_type, "sensor":indicator.sensor,
        "rule":indicator.rule, "confidence":indicator.confidence,
    });
    if let Some(connection) = indicator.connection_id {
        details["connection_id"] = json!(connection);
    }
    if let Some(direction) = indicator.direction {
        details["direction"] = json!(direction.as_str());
    }
    if let Some(hash) = indicator.evidence_hash {
        details["evidence_hash"] = json!(hash);
    }
    if let Some(content) = indicator.content {
        details["content_type"] = json!(content.content_type);
        details["inspected_bytes"] = json!(content.inspected_bytes);
        details["prefix_truncated"] = json!(content.prefix_truncated);
    }
    if let Some(source) = indicator.source {
        details["source"] = json!(source);
    }
    events.emit(identity, event, details);
}
