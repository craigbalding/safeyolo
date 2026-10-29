//! Read-only local NSM pivots over the ordinary logs reader's retained window.

use std::{collections::HashSet, path::Path};

use serde::Serialize;
use serde_json::{Value, json};

pub(crate) struct Query<'a> {
    pub(crate) instance: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) id: &'a str,
    pub(crate) agent: Option<&'a str>,
    pub(crate) lines: usize,
}

#[derive(Serialize)]
struct Link<'a> {
    from_line: usize,
    field: &'static str,
    event: &'static str,
    instance_id: &'a str,
    runtime_id: &'a str,
    connection_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_hash: Option<&'a str>,
    status: &'static str,
    record_lines: Vec<usize>,
}

impl Link<'_> {
    fn matches(&self, row: &Value) -> bool {
        if row["event"] != self.event || row["details"]["connection_id"] != self.connection_id {
            return false;
        }
        if self.event_id.is_some_and(|id| row["event_id"] != id) {
            return false;
        }
        if let Some(request) = self.request_id {
            // A prompt source names an observed response indication, not an
            // invented event with the source request's ID and copied content.
            return row["request_id"] == request
                && row["details"]["direction"] == "server_to_client"
                && row["details"]["evidence_hash"].as_str() == self.evidence_hash;
        }
        true
    }
}

fn links<'a>(line: usize, row: &'a Value, query: &Query<'a>) -> Vec<Link<'a>> {
    let mut result = Vec::new();
    let mut add = |field,
                   connection: Option<&'a str>,
                   event_id,
                   request_id: Option<&'a str>,
                   evidence_hash| {
        if let Some(connection_id) = connection {
            result.push(Link {
                from_line: line,
                field,
                event: if request_id.is_some() {
                    "security.indicator"
                } else {
                    "network.connection"
                },
                instance_id: query.instance,
                runtime_id: query.runtime,
                connection_id,
                request_id,
                event_id,
                evidence_hash,
                status: "unavailable",
                record_lines: Vec::new(),
            });
        }
    };
    let details = &row["details"];
    match row["event"].as_str() {
        Some("network.connection") => add(
            "details.client_connection_id",
            details["client_connection_id"].as_str(),
            None,
            None,
            None,
        ),
        Some("traffic.flow") => {
            add(
                "details.client_connection_id",
                details["client_connection_id"].as_str(),
                None,
                None,
                None,
            );
            add(
                "details.server_connection_id",
                details["server_connection_id"].as_str(),
                None,
                None,
                None,
            );
        }
        Some("security.indicator") => {
            add(
                "details.connection_id",
                details["connection_id"].as_str(),
                None,
                None,
                None,
            );
            let source = &details["source"];
            add(
                "details.source",
                source["connection_id"].as_str(),
                None,
                source["request_id"].as_str(),
                source["evidence_hash"].as_str(),
            );
            for (name, field) in [
                ("current", "details.novelty.current"),
                ("previous", "details.novelty.previous"),
                ("client", "details.novelty.client"),
            ] {
                let observation = &details["novelty"][name];
                add(
                    field,
                    observation["connection_id"].as_str(),
                    observation["event_id"].as_str(),
                    None,
                    None,
                );
            }
        }
        _ => {}
    }
    result
}

fn direct_connections(row: &Value) -> impl Iterator<Item = &str> {
    let details = &row["details"];
    [
        "connection_id",
        "client_connection_id",
        "server_connection_id",
    ]
    .into_iter()
    .filter_map(|key| details[key].as_str())
}

pub(crate) fn read(path: &Path, query: &Query<'_>) -> Result<Value, crate::Error> {
    if !matches!(query.kind, "connection" | "request")
        || [query.instance, query.runtime, query.id]
            .iter()
            .any(|id| id.trim().is_empty())
    {
        return Err("logs pivot requires connection|request ID --instance ID --runtime ID".into());
    }
    let tail = super::local_tail(path, query.agent, query.lines)?;
    // Only validated v2 NSM records can supply either side of a join.
    // Filter attribution before discovering links or testing availability.
    let rows: Vec<_> = tail
        .rows
        .iter()
        .filter(|(_, row)| {
            row["schema_version"] == super::nsm::SCHEMA_VERSION
                && row["details"]["instance_id"] == query.instance
                && row["details"]["runtime_id"] == query.runtime
        })
        .collect();
    let seeds: HashSet<_> = rows
        .iter()
        .filter(|(line, row)| {
            if query.kind == "request" {
                row["request_id"] == query.id || row["details"]["source"]["request_id"] == query.id
            } else {
                row["details"]["connection_id"] == query.id
                    || links(*line, row, query)
                        .iter()
                        .any(|link| link.connection_id == query.id)
            }
        })
        .map(|(line, _)| *line)
        .collect();
    let connections: HashSet<_> = rows
        .iter()
        .filter(|(line, _)| seeds.contains(line))
        .flat_map(|(_, row)| direct_connections(row))
        .collect();
    // One bounded expansion adds connection context and its indications.
    // Supporting records are resolved below without recursive traversal.
    let related: HashSet<_> = rows
        .iter()
        .filter(|(line, row)| {
            seeds.contains(line)
                || (matches!(
                    row["event"].as_str(),
                    Some("network.connection" | "security.indicator")
                ) && row["details"]["connection_id"]
                    .as_str()
                    .is_some_and(|id| connections.contains(id)))
        })
        .map(|(line, _)| *line)
        .collect();
    let mut included = related.clone();
    let mut evidence = Vec::new();
    for (line, row) in rows.iter().filter(|(line, _)| related.contains(line)) {
        for mut link in links(*line, row, query) {
            link.record_lines = rows
                .iter()
                .filter(|(_, candidate)| link.matches(candidate))
                .map(|(line, _)| *line)
                .collect();
            if !link.record_lines.is_empty() {
                link.status = "available";
                included.extend(link.record_lines.iter().copied());
            }
            evidence.push(link);
        }
    }
    let records: Vec<_> = rows.iter().filter(|(line, _)| included.contains(line))
        .map(|(line, row)| json!({"line":line,"selection":if related.contains(line) {"related"} else {"supporting"},"record":row}))
        .collect();
    Ok(json!({
        "file":path,
        "query":{"instance_id":query.instance,"runtime_id":query.runtime,"kind":query.kind,"id":query.id,"agent":query.agent},
        "search":{
            "lines_read":tail.lines_read,"agent_rows":tail.agent_rows,"line_limit":query.lines,
            "retained_rows":tail.rows.len(),"omitted_rows":tail.agent_rows-tail.rows.len(),
            "first_line":tail.rows.front().map(|(line,_)| line),"last_line":tail.rows.back().map(|(line,_)| line),
            "files":"configured_file_only", "output_limited":false,
            "limits":"Only the retained window of the opened local audit file was searched. Rotated files are not searched. Queued, dropped, rotated-away, outside-window or agent-filtered evidence may be unavailable. No event is reconstructed; absence is not proof that nothing occurred. Supporting links are followed once; retained bodies require the existing traffic commands."
        },
        "records":records,"links":evidence
    }))
}
