//! Sparse Network Security Monitoring contracts. Lifecycle producers live at
//! the transport owners; this module validates their shared audit representation.

use std::net::SocketAddr;

use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Error, ErrorKind, Result};

pub(super) const SCHEMA_VERSION: i64 = 2;

pub(super) fn is_event(name: &str) -> bool {
    matches!(
        name,
        "network.connection" | "traffic.flow" | "security.indicator"
    )
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Endpoint {
    Ip { address: SocketAddr },
    Unix { path: Option<String> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    instance_id: String,
    runtime_id: String,
    connection_id: String,
    leg: String,
    transport: String,
    started_at: String,
    ended_at: Option<String>,
    local_endpoint: Option<Endpoint>,
    remote_endpoint: Option<Endpoint>,
    state: String,
    error: Option<String>,
    requested_target: Option<String>,
    resolved_peer: Option<SocketAddr>,
    resolved_origin_peer: Option<SocketAddr>,
    client_connection_id: Option<String>,
    route: Option<String>,
    tls_server_name: Option<String>,
    tls_client_hello: Option<crate::tls_identity::ClientHello>,
    tls_sessions: Option<Vec<crate::tls_identity::TlsSession>>,
    ingress: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Flow {
    instance_id: String,
    runtime_id: String,
    client_connection_id: String,
    server_connection_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Indicator {
    instance_id: String,
    runtime_id: String,
    indicator_type: String,
    sensor: String,
    rule: String,
    confidence: f64,
    connection_id: Option<String>,
    direction: Option<String>,
    evidence_hash: Option<String>,
    content_type: Option<String>,
    inspected_bytes: Option<u64>,
    prefix_truncated: Option<bool>,
    source: Option<crate::security_indicators::SourceEvidence>,
    novelty: Option<crate::connection_events::novelty::Evidence>,
}

fn invalid() -> Error {
    Error(ErrorKind::Encoding)
}

fn required(values: &[&str]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}

fn optional(value: Option<&str>) -> bool {
    value.is_none_or(|value| required(&[value]))
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| invalid())
}

impl Connection {
    fn valid(&self) -> bool {
        let Ok(start) = OffsetDateTime::parse(&self.started_at, &Rfc3339) else {
            return false;
        };
        let end = match self.ended_at.as_deref() {
            Some(value) => match OffsetDateTime::parse(value, &Rfc3339) {
                Ok(value) if value >= start => Some(value),
                _ => return false,
            },
            None => None,
        };
        required(&[
            &self.instance_id,
            &self.runtime_id,
            &self.connection_id,
            &self.ingress,
        ]) && matches!(self.leg.as_str(), "client_to_proxy" | "proxy_to_upstream")
            && matches!(
                (self.state.as_str(), end),
                ("open" | "updated", None) | ("closed" | "failed", Some(_))
            )
            && optional(self.error.as_deref())
            && optional(self.requested_target.as_deref())
            && optional(self.client_connection_id.as_deref())
            && optional(self.tls_server_name.as_deref())
            && self
                .tls_client_hello
                .as_ref()
                .is_none_or(|hello| self.leg == "client_to_proxy" && hello.valid())
            && self.tls_sessions.as_ref().is_none_or(|sessions| {
                self.leg == "proxy_to_upstream"
                    && sessions.len() <= 2
                    && sessions.iter().all(crate::tls_identity::TlsSession::valid)
            })
            && self
                .route
                .as_deref()
                .is_none_or(|route| matches!(route, "direct" | "parent" | "provider"))
            && [&self.local_endpoint, &self.remote_endpoint]
                .into_iter()
                .all(|endpoint| match (self.transport.as_str(), endpoint) {
                    ("tcp", Some(Endpoint::Ip { .. })) | ("tcp" | "unix" | "stream", None) => true,
                    ("unix", Some(Endpoint::Unix { path })) => optional(path.as_deref()),
                    _ => false,
                })
            && self.resolved_peer.is_none_or(|peer| {
                self.transport == "tcp"
                    && match &self.remote_endpoint {
                        Some(Endpoint::Ip { address }) => peer == *address,
                        None => true,
                        _ => false,
                    }
            })
            && self.resolved_origin_peer.is_none_or(|peer| {
                self.transport == "tcp"
                    && self.route.as_deref() != Some("parent")
                    && self.resolved_peer == Some(peer)
            })
    }
}

pub(super) fn validate(record: &Value) -> Result<()> {
    let name = record["event"].as_str().ok_or_else(invalid)?;
    let expected_kind = match name {
        "network.connection" => "network",
        "traffic.flow" => "traffic",
        "security.indicator" => "security",
        _ => return Err(invalid()),
    };
    if record["kind"] != expected_kind
        || record["ts"]
            .as_str()
            .is_none_or(|ts| OffsetDateTime::parse(ts, &Rfc3339).is_err())
        || record.as_object().ok_or_else(invalid)?.keys().any(|key| {
            !matches!(
                key.as_str(),
                "schema_version"
                    | "event_id"
                    | "ts"
                    | "event"
                    | "kind"
                    | "severity"
                    | "summary"
                    | "request_id"
                    | "agent"
                    | "addon"
                    | "control"
                    | "decision"
                    | "host"
                    | "approval"
                    | "details"
            )
        })
    {
        return Err(invalid());
    }
    let mut details = record["details"].as_object().ok_or_else(invalid)?.clone();
    // Attribution has one authority and one wire location for both versions.
    if let Some(attribution) = details.remove("attribution")
        && !attribution.is_object()
    {
        return Err(invalid());
    }
    let details = Value::Object(details);
    let valid = match name {
        "network.connection" => decode::<Connection>(details)?.valid(),
        "traffic.flow" => {
            let flow: Flow = decode(details)?;
            required(&[
                &flow.instance_id,
                &flow.runtime_id,
                &flow.client_connection_id,
            ]) && optional(flow.server_connection_id.as_deref())
                && record["request_id"]
                    .as_str()
                    .is_some_and(|id| required(&[id]))
        }
        "security.indicator" => {
            let indicator: Indicator = decode(details)?;
            required(&[
                &indicator.instance_id,
                &indicator.runtime_id,
                &indicator.indicator_type,
                &indicator.sensor,
                &indicator.rule,
            ]) && indicator.confidence.is_finite()
                && (0.0..=1.0).contains(&indicator.confidence)
                && optional(indicator.connection_id.as_deref())
                && indicator
                    .novelty
                    .as_ref()
                    .is_none_or(|novelty| novelty.valid(indicator.connection_id.as_deref()))
                && indicator.source.as_ref().is_none_or(|source| {
                    required(&[&source.request_id, &source.connection_id, &source.host])
                        && source.matched_fingerprints > 0
                        && source.matched_fingerprints <= source.source_fingerprints
                        && evidence_hash(&source.evidence_hash)
                })
                && indicator
                    .content_type
                    .as_deref()
                    .is_none_or(|value| !value.trim().is_empty() && value.len() <= 128)
                && (indicator.inspected_bytes.is_none() && indicator.prefix_truncated.is_none()
                    || indicator.evidence_hash.is_some())
                && optional(record.get("request_id").and_then(Value::as_str))
                && indicator.direction.as_deref().is_none_or(|direction| {
                    matches!(direction, "client_to_server" | "server_to_client")
                })
                && indicator.evidence_hash.as_deref().is_none_or(evidence_hash)
                && record.get("decision").is_none()
                && record.get("approval").is_none()
        }
        _ => false,
    };
    if valid { Ok(()) } else { Err(invalid()) }
}

fn evidence_hash(hash: &str) -> bool {
    hash.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

#[cfg(test)]
mod tests;
