//! Join operator-selected compatibility metadata to the pivot's existing audit
//! scope. Capture selection and schema checks do not authenticate its producer.
use std::{collections::VecDeque, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Query;
use crate::observations::Layer;

#[derive(Deserialize, Serialize, PartialEq)]
struct Id {
    instance_id: String,
    runtime_id: String,
    sequence: u64,
}
#[derive(Deserialize, Serialize)]
struct Timestamp {
    wall_unix_ns: i128,
    monotonic_ns: u64,
}
#[derive(Deserialize, Serialize)]
struct Resolution {
    wall_ns: Option<u64>,
    monotonic_ns: Option<u64>,
}
#[derive(Deserialize, Serialize)]
struct Attribution {
    evidence_owner: Option<String>,
    trusted_transport_identity: Option<String>,
    status: Option<String>,
    initiator: Option<String>,
    provenance: Option<Value>,
}
#[derive(Deserialize, Serialize)]
struct Span {
    point: String,
    layer: Layer,
    direction: String,
    observed_from: Id,
    observed_through: Id,
    start_offset: u64,
    end_offset: u64,
    parser_consumed: bool,
}
// Project known metadata fields. Unknown input fields (including anything named
// payload) cannot be copied into the read-only audit view.
#[derive(Deserialize, Serialize)]
struct Observation {
    id: Id,
    timestamp: Timestamp,
    timestamp_resolution: Resolution,
    point: String,
    layer: Layer,
    direction: String,
    transport: String,
    connection_id: String,
    request_id: Option<String>,
    protocol_stream_id: Option<u32>,
    agent: Option<String>,
    attribution: Attribution,
    input_span: Option<Span>,
    parent_observation: Option<Id>,
    transformed: bool,
    stream_offset: Option<u64>,
    observed_length: Option<u64>,
    captured_length: u64,
    state: String,
}

fn same_namespace(a: &Id, b: &Id) -> bool {
    a.instance_id == b.instance_id && a.runtime_id == b.runtime_id
}
fn point(value: &str) -> bool {
    matches!(
        value,
        "agent_uds"
            | "external_ingress"
            | "upstream"
            | "client_tls"
            | "parent_tls"
            | "origin_tls"
            | "request_parser"
            | "request_content"
            | "host_packet"
    )
}
fn direction(value: &str) -> bool {
    matches!(value, "to_proxy" | "from_proxy" | "both")
}

fn observation(value: &Value) -> Result<Observation, &'static str> {
    let o: Observation = serde_json::from_value(value["observation"].clone())
        .map_err(|_| "malformed observation metadata")?;
    let source = &value["source"];
    if value["representation"] != "reconstructed"
        || value["compat_flow_id"]
            .as_str()
            .is_none_or(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
        || value["payload_truncated"] != (o.observed_length.is_some_and(|n| n > o.captured_length))
        || source["instance_id"] != o.id.instance_id
        || source["runtime_id"] != o.id.runtime_id
        || source["connection_id"] != o.connection_id
        || source["observation_point"] != o.point
        || source["observation_layer"] != o.layer.name()
        || source["direction"] != o.direction
        || source["transport"] != o.transport
        || [
            o.id.instance_id.as_str(),
            o.id.runtime_id.as_str(),
            &o.connection_id,
        ]
        .iter()
        .any(|id| id.trim().is_empty())
        || !point(&o.point)
        || !direction(&o.direction)
        || !matches!(o.transport.as_str(), "unix" | "tcp" | "provider")
        || !matches!(
            o.state.as_str(),
            "connected"
                | "closed"
                | "failed"
                | "chunk"
                | "parsed_head"
                | "complete"
                | "eof"
                | "half_close"
                | "read_error"
                | "write_error"
                | "parse_error"
                | "dropped"
        )
        || o.parent_observation.as_ref().is_some_and(|parent| {
            !same_namespace(&o.id, parent) || parent.sequence >= o.id.sequence
        })
        || o.input_span.as_ref().is_some_and(|span| {
            !same_namespace(&o.id, &span.observed_from)
                || !same_namespace(&o.id, &span.observed_through)
                || span.observed_from.sequence > span.observed_through.sequence
                || span.observed_through.sequence >= o.id.sequence
                || span.start_offset > span.end_offset
                || !point(&span.point)
                || !direction(&span.direction)
        })
    {
        return Err("inconsistent observation metadata");
    }
    Ok(o)
}

fn owner_matches(o: &Observation, row: &Value) -> bool {
    let attribution = &row["details"]["attribution"];
    o.agent.as_deref() == row["agent"].as_str()
        && o.attribution.evidence_owner.as_deref() == attribution["evidence_owner"].as_str()
        && o.attribution.trusted_transport_identity.as_deref()
            == attribution["trusted_transport_identity"].as_str()
        && o.attribution.status.as_deref() == attribution["attribution_status"].as_str()
        && o.attribution.initiator.as_deref() == attribution["initiator"].as_str()
}

struct Located {
    packet: u64,
    byte_offset: u64,
    flow: Value,
    observation: Observation,
}

fn retain<T>(rows: &mut VecDeque<T>, row: T, limit: usize, omitted: &mut usize) {
    rows.push_back(row);
    if rows.len() > limit {
        rows.pop_front();
        *omitted += 1;
    }
}

fn ancestry(parent: &Observation, candidate: &Observation) -> bool {
    if parent.connection_id != candidate.connection_id
        || parent.agent != candidate.agent
        || (candidate.request_id.is_some() && candidate.request_id != parent.request_id)
    {
        return false;
    }
    if parent.parent_observation.as_ref() == Some(&candidate.id) {
        return true;
    }
    parent.input_span.as_ref().is_some_and(|span| {
        span.observed_from.sequence <= candidate.id.sequence
            && candidate.id.sequence <= span.observed_through.sequence
            && span.point == candidate.point
            && span.layer == candidate.layer
            && span.direction == candidate.direction
            && candidate
                .stream_offset
                .zip(candidate.observed_length)
                .is_some_and(|(start, length)| {
                    start < span.end_offset && start.saturating_add(length) > span.start_offset
                })
    })
}

pub(crate) fn read(path: &Path, pivot: &Value, query: &Query<'_>) -> Value {
    let anchors: Vec<_> = pivot["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["conflicting"] != true)
        .filter(|entry| {
            let row = &entry["record"];
            if query.kind == "request" {
                row["request_id"] == query.id
            } else {
                super::direct_connections(row).any(|id| id == query.id)
            }
        })
        .collect();
    let mut session = None;
    let mut observations = VecDeque::new();
    let mut loss = VecDeque::new();
    let mut omitted = 0;
    let mut omitted_loss = 0;
    let scan = crate::packet_capture::compat::read::scan(path, |packet, byte_offset, value| {
        if packet == 1 {
            let current = &value["session"];
            if value["type"] != "session"
                || value["profile"] != "pcap:compat"
                || value["schema_version"] != 1
                || value["representation"] != "reconstructed"
                || value["pcap_timestamp_unit"] != "nanoseconds"
                || current["schema_version"] != 1
                || current["instance_id"].as_str().is_none_or(|s| s.is_empty())
                || current["runtime_id"].as_str().is_none_or(|s| s.is_empty())
                || current["sink_session_id"]
                    .as_str()
                    .is_none_or(|s| s.is_empty())
                || current["first_sequence"].as_u64().is_none()
            {
                return Err("unsupported or malformed compatibility session");
            }
            session = Some(current.clone());
            return Ok(());
        }
        let current = session
            .as_ref()
            .ok_or("capture session metadata is absent")?;
        match value["type"].as_str() {
            Some("observation") => {
                let o = observation(&value)?;
                if current["instance_id"] != o.id.instance_id
                    || current["runtime_id"] != o.id.runtime_id
                {
                    return Err("observation namespace differs from capture session");
                }
                if o.id.instance_id == query.instance
                    && o.id.runtime_id == query.runtime
                    && anchors.iter().any(|entry| {
                        let row = &entry["record"];
                        owner_matches(&o, row)
                            && super::direct_connections(row).any(|id| id == o.connection_id)
                    })
                    && (query.kind == "request" || o.connection_id == query.id)
                {
                    retain(
                        &mut observations,
                        Located {
                            packet,
                            byte_offset,
                            flow: value["compat_flow_id"].clone(),
                            observation: o,
                        },
                        query.lines,
                        &mut omitted,
                    );
                }
            }
            Some("sink_gap") | None if value["type"] == "sink_gap" || value["record"] == "gap" => {
                let first = value["first_sequence"]
                    .as_u64()
                    .ok_or("malformed capture loss range")?;
                let last = value["last_sequence"]
                    .as_u64()
                    .ok_or("malformed capture loss range")?;
                if last.checked_sub(first).and_then(|n| n.checked_add(1)) != value["count"].as_u64()
                    || value["reason"].as_str().is_none()
                    || value["instance_id"] != current["instance_id"]
                    || value["runtime_id"] != current["runtime_id"]
                    || (value["type"] == "sink_gap"
                        && value["sink_session_id"] != current["sink_session_id"])
                {
                    return Err("inconsistent capture loss metadata");
                }
                if value["instance_id"] == query.instance && value["runtime_id"] == query.runtime {
                    retain(
                        &mut loss,
                        json!({"packet":packet,"byte_offset":byte_offset,
                        "scope":"runtime","connection_request_attribution":"unavailable",
                        "first_sequence":first,"last_sequence":last,"count":value["count"],"reason":value["reason"],
                        "kind":if value["type"] == "sink_gap" { "sink_gap" } else { "canonical_gap" }}),
                        query.lines,
                        &mut omitted_loss,
                    );
                }
            }
            _ => return Err("unsupported compatibility metadata record"),
        }
        Ok(())
    });
    let direct: Vec<_> = observations
        .iter()
        .filter(|entry| {
            query.kind == "connection" || entry.observation.request_id.as_deref() == Some(query.id)
        })
        .collect();
    let selected: Vec<_> = observations
        .iter()
        .filter(|entry| {
            direct
                .iter()
                .any(|d| d.packet == entry.packet || ancestry(&d.observation, &entry.observation))
        })
        .collect();
    let mut partial =
        scan["status"] != "available" || omitted > 0 || omitted_loss > 0 || !loss.is_empty();
    let rows: Vec<_> = selected.iter().map(|entry| {
        let o = &entry.observation;
        let references: Vec<_> = selected.iter().filter(|candidate| ancestry(o, &candidate.observation)).map(|candidate| json!({"packet":candidate.packet,"byte_offset":candidate.byte_offset,"observation_id":candidate.observation.id})).collect();
        let lineage = if references.is_empty() { "unavailable" } else { "partial" };
        // A set of retained references cannot establish complete input coverage:
        // a prefix may include parser read-ahead and intermediate records may be lost.
        if query.kind == "request" && o.request_id.as_deref() == Some(query.id) && lineage == "unavailable" { partial = true; }
        let audit: Vec<_> = anchors.iter().filter(|anchor| owner_matches(o, &anchor["record"]) && super::direct_connections(&anchor["record"]).any(|id| id == o.connection_id)).map(|anchor| anchor["line"].clone()).collect();
        json!({"packet":entry.packet,"byte_offset":entry.byte_offset,"compat_flow_id":entry.flow,
            "selection":if direct.iter().any(|d| d.packet == entry.packet) {"direct"} else {"input_ancestry"},
            "audit_record_lines":audit,"observation":o,"lineage":{"status":lineage,"references":references}})
    }).collect();
    json!({"file":path,"profile":"pcap:compat","representation":"reconstructed",
        "status":if direct.is_empty() {"unavailable"} else if partial {"partial"} else {"available"},
        "reason":if anchors.is_empty() {Some("no unconflicted selected audit scope")} else if direct.is_empty() {Some("no matching retained connection/request observations")} else {None},
        "scan":scan,"line_limit":query.lines,"omitted_connection_observations":omitted,"omitted_runtime_loss_records":omitted_loss,
        "observations":rows,"loss":loss,
        "limits":"Only selected current pcap:compat metadata is read. Packet numbers are one-based; byte offsets point to PCAP packet headers. Synthetic addresses, TCP headers and checksums are representation, never measured wire behaviour. Request IDs select direct observations; lower-layer input ancestry can be shared or include read-ahead, not exclusive request bytes. Lineage references are limited to retained matching observations and do not establish complete coverage. Loss ranges cover the runtime; their connection/request owner is unknown. No payload is returned, capture enabled, content recovered, or process/task provenance inferred. Audit run context comes only from the selected audit records. Selection and validation do not authenticate a producer. EOF and absence of recorded loss do not prove complete evidence."})
}
