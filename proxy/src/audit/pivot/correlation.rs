//! Derived explanations over retained records; nothing here emits an event.

use super::*;

fn trusted_agent(row: &Value) -> Option<&str> {
    let agent = row["agent"]
        .as_str()
        .filter(|agent| !agent.trim().is_empty())?;
    let attribution = &row["details"]["attribution"];
    (attribution["attribution_status"] == "resolved"
        && attribution["trusted_transport_identity"] == agent
        && attribution["evidence_owner"] == agent)
        .then_some(agent)
}

fn lines(rows: &[&(RecordLine, Value)], matches: impl Fn(&Value) -> bool) -> Vec<RecordLine> {
    rows.iter()
        .filter(|(_, row)| matches(row))
        .map(|(line, _)| *line)
        .collect()
}

fn novelty(
    rows: &[&(RecordLine, Value)],
    query: &Query<'_>,
    connection: &str,
    client: &str,
    role: &str,
) -> Vec<Value> {
    rows.iter()
        .filter(|(_, row)| {
            row["event"] == "security.indicator"
                && row["details"]["sensor"] == "connection-history.v1"
                && row["details"]["novelty"]["current"]["connection_id"] == connection
        })
        .map(|(line, row)| {
            let support: Vec<_> = links(*line, row, query)
                .into_iter()
                .filter(|link| link.field.starts_with("details.novelty."))
                .map(|mut link| {
                    link.record_lines = lines(rows, |candidate| {
                        if !link.matches(candidate) {
                            return false;
                        }
                        // A client/destination pair must reference this flow's
                        // actual client, and the current upstream must own it.
                        if link.field == "details.novelty.client" {
                            candidate["details"]["connection_id"] == client
                                && candidate["details"]["leg"] == "client_to_proxy"
                        } else if link.field == "details.novelty.current" {
                            if role == "client" {
                                candidate["details"]["leg"] == "client_to_proxy"
                            } else {
                                candidate["details"]["leg"] == "proxy_to_upstream"
                                    && candidate["details"]["client_connection_id"] == client
                            }
                        } else {
                            true
                        }
                    });
                    if !link.record_lines.is_empty() {
                        link.status = "available";
                    }
                    link
                })
                .collect();
            let available = !support.is_empty()
                && support.iter().all(|link| link.status == "available");
            json!({
                "indicator_line":line,"event_id":row["event_id"],
                "connection_id":connection,"connection_role":role,
                "status":if available {"available"} else {"unavailable"},
                "reason":if available {
                    "The flow owns this connection and every recorded novelty observation resolves to its exact connection/event ID. This is connection-wide evidence, which may predate or serve multiple requests."
                } else {
                    "The indicator names this flow's connection, but at least one exact supporting connection/event or client ownership link is unavailable. The novelty combination is incomplete."
                },
                "support":support
            })
        })
        .collect()
}

fn transport(
    rows: &[&(RecordLine, Value)],
    query: &Query<'_>,
    request: Option<&str>,
    client: Option<&str>,
    permitted: bool,
) -> Value {
    let mut result = json!({
        "request_id":request,"client_connection_id":client,"server_connection_id":null,
        "status":"unavailable","flow_lines":[],"client_record_lines":[],
        "server_record_lines":[],"novelty":[],
        "reason":"The exposure or exact source indication lacks usable trusted references; no transport correlation is established."
    });
    let (Some(request), Some(client)) = (request, client) else {
        return result;
    };
    if !permitted {
        return result;
    }
    let flows: Vec<_> = rows
        .iter()
        .copied()
        .filter(|(_, row)| row["event"] == "traffic.flow" && row["request_id"] == request)
        .collect();
    result["flow_lines"] = json!(flows.iter().map(|(line, _)| *line).collect::<Vec<_>>());
    let Some((_, flow)) = flows.first() else {
        result["reason"] = json!(
            "The request's traffic.flow is unavailable in the searched window; connection IDs alone cannot establish transport ownership."
        );
        return result;
    };
    if flow["details"]["client_connection_id"] != client
        || flows.iter().any(|(_, candidate)| {
            candidate["details"]["client_connection_id"] != flow["details"]["client_connection_id"]
                || candidate["details"]["server_connection_id"]
                    != flow["details"]["server_connection_id"]
        })
    {
        result["reason"] = json!(
            "Retained flow ownership conflicts with the exposure reference or with another flow for this request; no transport correlation is established."
        );
        return result;
    }
    let client_lines = lines(rows, |row| {
        row["event"] == "network.connection"
            && row["details"]["connection_id"] == client
            && row["details"]["leg"] == "client_to_proxy"
    });
    let server = flow["details"]["server_connection_id"].as_str();
    let server_lines = lines(rows, |row| {
        row["event"] == "network.connection"
            && server.is_some_and(|server| row["details"]["connection_id"] == server)
            && row["details"]["leg"] == "proxy_to_upstream"
            && row["details"]["client_connection_id"] == client
    });
    let mut indications = Vec::new();
    if !client_lines.is_empty() {
        indications.extend(novelty(rows, query, client, client, "client"));
    }
    if let Some(server) = server.filter(|_| !server_lines.is_empty()) {
        indications.extend(novelty(rows, query, server, client, "server"));
    }
    result["status"] = json!(if !client_lines.is_empty() && !server_lines.is_empty() {
        "available"
    } else {
        "partial"
    });
    result["reason"] = json!(
        "The request's traffic.flow names these client/server connections. Connection records require the matching leg and upstream client owner; missing connection evidence remains unavailable. Novelty concerns these transports, not an observation unique to this request."
    );
    result["server_connection_id"] = json!(server);
    result["client_record_lines"] = json!(client_lines);
    result["server_record_lines"] = json!(server_lines);
    result["novelty"] = json!(indications);
    result
}

fn include_evidence(value: &Value, included: &mut HashSet<RecordLine>) {
    let mut add = |value: &Value| {
        included.extend(
            value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|line| serde_json::from_value::<RecordLine>(line.clone()).ok()),
        );
    };
    add(&value["source"]["record_lines"]);
    for side in ["source_transport", "model_transport"] {
        for field in ["flow_lines", "client_record_lines", "server_record_lines"] {
            add(&value[side][field]);
        }
        for indication in value[side]["novelty"].as_array().into_iter().flatten() {
            add(&json!([indication["indicator_line"]]));
            for support in indication["support"].as_array().into_iter().flatten() {
                add(&support["record_lines"]);
            }
        }
    }
}

pub(super) fn exposures(
    rows: &[&(RecordLine, Value)],
    related: &HashSet<RecordLine>,
    query: &Query<'_>,
    conflicts: &HashSet<RecordLine>,
    included: &mut HashSet<RecordLine>,
) -> Vec<Value> {
    rows.iter().filter(|(line, row)| related.contains(line)
        && row["event"] == "security.indicator"
        && row["details"]["indicator_type"] == "prompt_injection_exposure")
    .map(|(line, exposure)| {
        let agent = trusted_agent(exposure);
        let scoped: Vec<_> = rows.iter().copied().filter(|(line, row)| {
            !conflicts.contains(line) && agent.is_some() && trusted_agent(row) == agent
        }).collect();
        let usable = !conflicts.contains(line) && agent.is_some()
            && exposure["details"]["sensor"] == "prompt-injection.v1"
            && exposure["details"]["rule"] == "prompt.source_text_overlap.v1"
            && exposure["details"]["direction"] == "client_to_server";
        let source = &exposure["details"]["source"];
        let source_lines = lines(&scoped, |row| usable
            && row["event"] == "security.indicator"
            && row["details"]["sensor"] == "prompt-injection.v1"
            && row["details"]["direction"] == "server_to_client"
            && row["request_id"].as_str().is_some_and(|id| source["request_id"] == id)
            && row["details"]["connection_id"].as_str().is_some_and(|id| source["connection_id"] == id)
            && row["details"]["evidence_hash"] == source["evidence_hash"]
            && row["host"] == source["host"]);
        let source_available = !source_lines.is_empty();
        let source_transport = transport(&scoped, query, source["request_id"].as_str(), source["connection_id"].as_str(), source_available);
        let model_transport = transport(&scoped, query, exposure["request_id"].as_str(), exposure["details"]["connection_id"].as_str(), usable);
        let novelty_available = [&source_transport, &model_transport].into_iter().any(|side| {
            side["novelty"].as_array().into_iter().flatten().any(|entry| entry["status"] == "available")
        });
        let novelty_complete = [&source_transport, &model_transport].into_iter().all(|side| {
            side["novelty"].as_array().into_iter().flatten().all(|entry| entry["status"] == "available")
        });
        let complete = source_available && novelty_available && novelty_complete
            && source_transport["status"] == "available" && model_transport["status"] == "available";
        let result = json!({
            "exposure_line":line,"event_id":exposure["event_id"],"request_id":exposure["request_id"],"agent":agent,
            "status":if complete {"linked"} else if usable {"partial"} else {"unavailable"},
            "reason":if complete {"The exact prompt source indication, source/model flows and supporting connection-wide novelty evidence are linked."} else {"The retained exposure remains visible, but trusted attribution, exact source, flow, connection or novelty support is incomplete or unavailable. Absence is not a clean verdict."},
            "meaning":"Observed source text overlap and connection relationships do not prove malicious intent, request-level novelty, model receipt or causal compromise.",
            "source":{"reference":source,"status":if source_available {"available"} else {"unavailable"},
                "record_lines":source_lines,"reason":"A source indication must match request ID, client connection ID, response direction, host and evidence hash within the same instance/runtime and resolved trusted agent."},
            "source_transport":source_transport,"model_transport":model_transport,
            "novelty_status":if novelty_available {"available"} else {"unavailable"}
        });
        include_evidence(&result, included);
        result
    }).collect()
}
