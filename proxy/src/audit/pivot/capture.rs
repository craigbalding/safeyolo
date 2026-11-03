//! Join operator-selected compatibility metadata to the pivot's existing audit
//! scope. Capture selection and schema checks do not authenticate its producer.
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
};

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

fn transport_lines(transport: &Value) -> impl Iterator<Item = &Value> {
    ["flow_lines", "client_record_lines", "server_record_lines"]
        .into_iter()
        .flat_map(|field| transport[field].as_array().into_iter().flatten())
}

fn supports(o: &Observation, anchor: &Value) -> bool {
    owner_matches(o, &anchor["record"])
        && super::direct_connections(&anchor["record"]).any(|id| id == o.connection_id)
}

fn behaviour(
    observations: &VecDeque<Located>,
    anchors: &[&Value],
    transport: &Value,
    partial: bool,
) -> Value {
    let mut groups = BTreeMap::<_, Vec<&Located>>::new();
    if transport["status"] != "unavailable" {
        for entry in observations {
            let o = &entry.observation;
            // Match the current fixed metrics: stream chunks, never synthetic
            // packet sizes or genuine wire-packet segmentation.
            if o.state == "chunk"
                && o.layer != Layer::WirePacket
                && ["client_connection_id", "server_connection_id"]
                    .iter()
                    .any(|field| transport[field] == o.connection_id)
                && anchors.iter().any(|anchor| {
                    transport_lines(transport).any(|line| *line == anchor["line"])
                        && supports(o, anchor)
                })
            {
                groups
                    .entry((
                        o.connection_id.as_str(),
                        o.point.as_str(),
                        o.layer.name(),
                        o.direction.as_str(),
                    ))
                    .or_default()
                    .push(entry);
            }
        }
    }
    let groups: Vec<_> = groups.into_iter().map(|((connection, point, layer, direction), entries)| {
        let lengths: Vec<_> = entries.iter().filter_map(|e| e.observation.observed_length).collect();
        let mut previous: Option<&Observation> = None;
        let mut intervals = Vec::new();
        let chunks: Vec<_> = entries.iter().map(|entry| {
            let o = &entry.observation;
            let interval = previous.and_then(|p| {
                (p.id.sequence < o.id.sequence)
                    .then(|| o.timestamp.monotonic_ns.checked_sub(p.timestamp.monotonic_ns)).flatten()
            });
            intervals.extend(interval);
            let audit: Vec<_> = anchors.iter().filter(|anchor| transport_lines(transport).any(|line| *line == anchor["line"]) && supports(o, anchor)).map(|anchor| &anchor["line"]).collect();
            let chunk = json!({"packet":entry.packet,"byte_offset":entry.byte_offset,
                "observation_id":o.id,"stream_offset":o.stream_offset,"observed_length":o.observed_length,
                "timestamp":o.timestamp,"timestamp_resolution":o.timestamp_resolution,"audit_record_lines":audit,
                "previous_observation_id":previous.map(|p| &p.id),"interval_from_previous_ns":interval});
            previous = Some(o);
            chunk
        }).collect();
        json!({"connection_id":connection,"point":point,"layer":layer,"direction":direction,
            "retained_chunks":entries.len(),"chunks_with_observed_length":lengths.len(),
            "observed_bytes":lengths.iter().map(|n| u128::from(*n)).sum::<u128>(),
            "min_chunk_bytes":lengths.iter().min(),"max_chunk_bytes":lengths.iter().max(),
            "retained_inter_chunk_intervals_ns":{"count":intervals.len(),
                "sum":intervals.iter().map(|n| u128::from(*n)).sum::<u128>(),
                "min":intervals.iter().min(),"max":intervals.iter().max(),
                "unavailable":entries.len().saturating_sub(1) - intervals.len()},
            "chunks":chunks})
    }).collect();
    json!({"status":if groups.is_empty() {"unavailable"} else if partial {"partial"} else {"available"},
        "scope":"retained_connection_chunks","groups":groups,
        "limits":"Descriptive retained stream measurements use canonical observed lengths and runtime monotonic timestamps. Null intervals lack ordered monotonic timing. Unknown clock resolution remains null without discarding same-runtime durations. Intervals can span missing chunks. Each point/layer/direction stays separate; do not add layers as application bytes. Connections can serve multiple requests and include shared input/read-ahead; these are not exclusive request totals, anomaly scores or causal timing. Capture scan, omissions and runtime-wide loss are reported in capture; loss ownership and complete coverage remain unknown. File selection does not authenticate the producer."})
}

pub(crate) fn read(path: &Path, pivot: &mut Value, query: &Query<'_>) -> Value {
    let direct_anchors: Vec<_> = pivot["records"]
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
    let mut anchors = direct_anchors.clone();
    let mut correlated_connections = Vec::new();
    for correlation in pivot["correlations"].as_array().into_iter().flatten() {
        for side in ["source_transport", "model_transport"] {
            let transport = &correlation[side];
            if transport["status"] != "unavailable" {
                correlated_connections.extend(
                    ["client_connection_id", "server_connection_id"]
                        .into_iter()
                        .filter_map(|field| transport[field].as_str()),
                );
                for anchor in pivot["records"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|anchor| {
                        anchor["conflicting"] != true
                            && transport_lines(transport).any(|line| *line == anchor["line"])
                    })
                {
                    if !anchors
                        .iter()
                        .any(|existing| existing["line"] == anchor["line"])
                    {
                        anchors.push(anchor);
                    }
                }
            }
        }
    }
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
                    && anchors.iter().any(|entry| supports(&o, entry))
                    && (query.kind == "request"
                        || o.connection_id == query.id
                        || correlated_connections.contains(&o.connection_id.as_str()))
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
            direct_anchors
                .iter()
                .any(|anchor| supports(&entry.observation, anchor))
                && if query.kind == "connection" {
                    entry.observation.connection_id == query.id
                } else {
                    entry.observation.request_id.as_deref() == Some(query.id)
                }
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
    let behaviours: Vec<_> = pivot["correlations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|correlation| {
            ["source_transport", "model_transport"]
                .map(|side| behaviour(&observations, &anchors, &correlation[side], partial))
        })
        .collect();
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
    let result = json!({"file":path,"profile":"pcap:compat","representation":"reconstructed",
        "status":if direct.is_empty() {"unavailable"} else if partial {"partial"} else {"available"},
        "reason":if anchors.is_empty() {Some("no unconflicted selected audit scope")} else if direct.is_empty() {Some("no matching retained connection/request observations")} else {None},
        "scan":scan,"line_limit":query.lines,"omitted_connection_observations":omitted,"omitted_runtime_loss_records":omitted_loss,
        "observations":rows,"loss":loss,
        "limits":"Only selected current pcap:compat metadata is read. Packet numbers are one-based; byte offsets point to PCAP packet headers. Synthetic addresses, TCP headers and checksums are representation, never measured wire behaviour. Request IDs select direct observations; lower-layer input ancestry can be shared or include read-ahead, not exclusive request bytes. The observation limit covers selected and correlated source/model connections together. Lineage references are limited to retained matching observations and do not establish complete coverage. Loss ranges cover the runtime; their connection/request owner is unknown. No payload is returned, capture enabled, content recovered, or process/task provenance inferred. Audit run context comes only from the selected audit records. Selection and validation do not authenticate a producer. EOF and absence of recorded loss do not prove complete evidence."});
    for (correlation, sides) in pivot["correlations"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .zip(behaviours)
    {
        for (side, summary) in ["source_transport", "model_transport"]
            .into_iter()
            .zip(sides)
        {
            correlation[side]["behaviour"] = summary;
        }
    }
    result
}
