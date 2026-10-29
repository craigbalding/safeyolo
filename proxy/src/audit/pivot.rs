//! Read-only local NSM pivots over the ordinary logs reader's retained window.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod correlation;
mod listing;

pub(crate) use listing::read as list;

pub(crate) struct Query<'a> {
    pub(crate) instance: &'a str,
    pub(crate) runtime: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) id: &'a str,
    pub(crate) agent: Option<&'a str>,
    pub(crate) sandbox_run: Option<&'a str>,
    pub(crate) lines: usize,
}

/// Installed views keep their physical-line references. Selected files need
/// an input number as well; equal physical line numbers must never alias.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(untagged)]
enum RecordLine {
    Local(usize),
    Selected { input: usize, line: usize },
}

#[derive(Serialize)]
struct Link<'a> {
    from_line: RecordLine,
    field: &'static str,
    event: &'static str,
    instance_id: &'a str,
    runtime_id: &'a str,
    agent: Option<&'a str>,
    sandbox_run: &'a Value,
    connection_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_hash: Option<&'a str>,
    status: &'static str,
    record_lines: Vec<RecordLine>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conflicting_record_lines: Vec<RecordLine>,
}

impl Link<'_> {
    fn matches(&self, row: &Value) -> bool {
        if row["event"] != self.event
            || row["agent"].as_str() != self.agent
            || row["details"]["sandbox_run"] != *self.sandbox_run
        {
            return false;
        }
        if self.event == "traffic.flow" {
            return row["request_id"].as_str() == self.request_id
                && row["details"]["client_connection_id"] == self.connection_id;
        }
        if row["details"]["connection_id"] != self.connection_id {
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

fn links<'a>(line: RecordLine, row: &'a Value, query: &Query<'a>) -> Vec<Link<'a>> {
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
                agent: row["agent"].as_str(),
                sandbox_run: &row["details"]["sandbox_run"],
                connection_id,
                request_id,
                event_id,
                evidence_hash,
                status: "unavailable",
                record_lines: Vec::new(),
                conflicting_record_lines: Vec::new(),
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
        Some(name) if super::nsm::is_request_decision(name) => add(
            "details.client_connection_id",
            details["client_connection_id"].as_str(),
            None,
            None,
            None,
        ),
        _ => {}
    }
    if super::nsm::is_request_decision(row["event"].as_str().unwrap_or_default()) {
        result.push(Link {
            from_line: line,
            field: "request_id",
            event: "traffic.flow",
            instance_id: query.instance,
            runtime_id: query.runtime,
            agent: row["agent"].as_str(),
            sandbox_run: &details["sandbox_run"],
            connection_id: details["client_connection_id"]
                .as_str()
                .expect("validated scope"),
            request_id: row["request_id"].as_str(),
            event_id: None,
            evidence_hash: None,
            status: "unavailable",
            record_lines: Vec::new(),
            conflicting_record_lines: Vec::new(),
        });
    }
    result
}

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

fn sandbox_run_key(row: &Value) -> Option<(&str, &str)> {
    let run = &row["details"]["sandbox_run"];
    Some((run["agent_id"].as_str()?, run["run_id"].as_str()?))
}

fn direct_connections(row: &Value) -> impl Iterator<Item = &str> {
    let details = &row["details"];
    let decision = super::nsm::is_request_decision(row["event"].as_str().unwrap_or_default());
    [
        "connection_id",
        "client_connection_id",
        "server_connection_id",
    ]
    .into_iter()
    .filter(move |key| !decision || *key == "client_connection_id")
    .filter_map(|key| details[key].as_str())
}

/// Conflicting copies of an event, or incompatible owners of the same local
/// transport/request, cannot establish a join. Lifecycle snapshots with the
/// same owner remain usable. Agent-local IDs are compared within each agent.
fn conflicting_lines(rows: &[&(RecordLine, Value)]) -> HashSet<RecordLine> {
    let mut groups: HashMap<String, Vec<(RecordLine, String)>> = HashMap::new();
    for (line, row) in rows {
        let mut canonical = row.clone();
        canonical.sort_all_objects();
        if let Some(event) = row["event_id"].as_str() {
            groups
                .entry(
                    json!([
                        "event",
                        row["details"]["instance_id"],
                        row["details"]["runtime_id"],
                        event
                    ])
                    .to_string(),
                )
                .or_default()
                .push((*line, canonical.to_string()));
        }
        let details = &row["details"];
        let ownership = match row["event"].as_str() {
            Some("network.connection") => Some((
                json!([
                    "connection",
                    details["instance_id"],
                    details["runtime_id"],
                    row["agent"],
                    details["connection_id"]
                ]),
                json!([
                    details["leg"],
                    details["client_connection_id"],
                    details["sandbox_run"]
                ]),
            )),
            Some("traffic.flow") => Some((
                json!([
                    "request",
                    details["instance_id"],
                    details["runtime_id"],
                    row["agent"],
                    row["request_id"]
                ]),
                json!([
                    details["client_connection_id"],
                    details["server_connection_id"],
                    details["sandbox_run"]
                ]),
            )),
            _ => None,
        };
        if let Some((key, owner)) = ownership {
            groups
                .entry(key.to_string())
                .or_default()
                .push((*line, owner.to_string()));
        }
        if row["event"] == "traffic.flow"
            || super::nsm::is_request_decision(row["event"].as_str().unwrap_or_default())
        {
            groups
                .entry(
                    json!([
                        "request-client",
                        details["instance_id"],
                        details["runtime_id"],
                        row["agent"],
                        row["request_id"]
                    ])
                    .to_string(),
                )
                .or_default()
                .push((
                    *line,
                    json!([details["client_connection_id"], details["sandbox_run"]]).to_string(),
                ));
        }
    }
    groups
        .values()
        .filter(|group| group.iter().any(|(_, value)| value != &group[0].1))
        .flat_map(|group| group.iter().map(|(line, _)| *line))
        .collect()
}

fn search_window(
    paths: &[PathBuf],
    tails: &[super::reader::LocalTail],
    explicit: bool,
    lines: usize,
) -> (Vec<Value>, Value) {
    let inputs: Vec<_> = paths.iter().zip(tails).enumerate().map(|(index, (path, tail))| json!({
        "input":index + 1,"file":path,"lines_read":tail.lines_read,"agent_rows":tail.agent_rows,
        "retained_rows":tail.rows.len(),"omitted_rows":tail.agent_rows - tail.rows.len(),
        "first_line":tail.rows.front().map(|(line,_)| line),"last_line":tail.rows.back().map(|(line,_)| line)
    })).collect();
    let mut search = json!({
        "lines_read":tails.iter().map(|tail| tail.lines_read).sum::<usize>(),
        "agent_rows":tails.iter().map(|tail| tail.agent_rows).sum::<usize>(),
        "line_limit":lines,"retained_rows":tails.iter().map(|tail| tail.rows.len()).sum::<usize>(),
        "omitted_rows":tails.iter().map(|tail| tail.agent_rows - tail.rows.len()).sum::<usize>(),
        "output_limited":false
    });
    if explicit {
        search["files"] = json!("explicit_inputs_only");
        search["line_limit_per_input"] = json!(lines);
        search["input_count"] = json!(paths.len());
        search["limits"] = json!(
            "Each selected file is validated to EOF and retains at most --lines selected-agent rows before namespace/pivot selection. Totals include all input copies; evidence deduplicates equal records. Input order and wall timestamps do not establish a global chronology. Only the selected files/windows are searched. Queued, dropped, unselected, outside-window or agent-filtered evidence may be unavailable. Supporting links are followed once. No event is reconstructed or content fetched. Selection and schema validation do not authenticate a producer."
        );
    } else {
        search["files"] = json!("configured_file_only");
        search["first_line"] = inputs[0]["first_line"].clone();
        search["last_line"] = inputs[0]["last_line"].clone();
        search["limits"] = json!(
            "Only the retained window of the opened local audit file was searched. Rotated files are not searched. Queued, dropped, rotated-away, outside-window or agent-filtered evidence may be unavailable. No event is reconstructed; absence is not proof that nothing occurred. Supporting links are followed once; retained bodies require the existing traffic commands."
        );
    }
    (inputs, search)
}

struct RetainedRows {
    records: Vec<(RecordLine, Value)>,
    copies: HashMap<RecordLine, Vec<RecordLine>>,
}

fn retained_rows(
    tails: Vec<super::reader::LocalTail>,
    explicit: bool,
    deduplicate: bool,
    include: impl Fn(&Value) -> bool,
) -> RetainedRows {
    let mut retained = Vec::new();
    let mut copies: HashMap<RecordLine, Vec<RecordLine>> = HashMap::new();
    let mut seen = HashMap::new();
    for (index, tail) in tails.into_iter().enumerate() {
        for (line, row) in tail.rows {
            // Historical rows stay readable in raw logs, never NSM choices.
            if row["schema_version"] != super::nsm::SCHEMA_VERSION || !include(&row) {
                continue;
            }
            let line = if explicit {
                RecordLine::Selected {
                    input: index + 1,
                    line,
                }
            } else {
                RecordLine::Local(line)
            };
            if deduplicate {
                let mut canonical = row.clone();
                canonical.sort_all_objects();
                let key = canonical.to_string();
                if let Some(first) = seen.get(&key) {
                    copies
                        .get_mut(first)
                        .expect("first copy retained")
                        .push(line);
                    continue;
                }
                seen.insert(key, line);
            }
            copies.insert(line, vec![line]);
            retained.push((line, row));
        }
    }
    RetainedRows {
        records: retained,
        copies,
    }
}

pub(crate) fn read(
    paths: &[PathBuf],
    tails: Vec<super::reader::LocalTail>,
    explicit: bool,
    query: &Query<'_>,
) -> Result<Value, crate::Error> {
    if query.sandbox_run.is_some_and(|id| id.trim().is_empty()) {
        return Err("--sandbox-run requires a nonempty ID".into());
    }
    if !matches!(query.kind, "connection" | "request")
        || [query.instance, query.runtime, query.id]
            .iter()
            .any(|id| id.trim().is_empty())
    {
        return Err("logs pivot requires connection|request ID --instance ID --runtime ID".into());
    }
    let (inputs, mut search) = search_window(paths, &tails, explicit, query.lines);
    let RetainedRows {
        records: retained,
        copies,
    } = retained_rows(tails, explicit, explicit, |row| {
        row["details"]["instance_id"] == query.instance
            && row["details"]["runtime_id"] == query.runtime
    });
    let rows: Vec<_> = retained.iter().collect();
    let conflicts = conflicting_lines(&rows);
    if explicit {
        search["unique_namespace_rows"] = json!(rows.len());
        search["duplicate_namespace_rows"] = json!(
            copies
                .values()
                .map(|locations| locations.len() - 1)
                .sum::<usize>()
        );
        search["conflicting_namespace_rows"] = json!(conflicts.len());
    }
    // Detect conflicts before selection: choosing one claim cannot make an
    // incompatible owner of the same namespace/local ID disappear.
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|(_, row)| {
            query
                .sandbox_run
                .is_none_or(|id| row["details"]["sandbox_run"]["run_id"] == id)
        })
        .collect();
    let seeds: HashSet<_> = rows
        .iter()
        .filter(|(line, row)| {
            if query.kind == "request" {
                row["request_id"] == query.id
                    || (row["event"] == "security.indicator"
                        && row["details"]["source"]["request_id"] == query.id)
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
        .filter(|(line, row)| {
            seeds.contains(line)
                && !conflicts.contains(line)
                && (!super::nsm::is_request_decision(row["event"].as_str().unwrap_or_default())
                    || trusted_agent(row).is_some())
        })
        .flat_map(|(_, row)| {
            direct_connections(row)
                .map(|connection| (row["agent"].as_str(), sandbox_run_key(row), connection))
        })
        .collect();
    let requests: HashSet<_> = rows
        .iter()
        .filter(|(line, row)| {
            seeds.contains(line)
                && !conflicts.contains(line)
                && row["event"] == "traffic.flow"
                && trusted_agent(row).is_some()
        })
        .map(|(_, row)| {
            (
                trusted_agent(row),
                sandbox_run_key(row),
                row["request_id"].as_str(),
                row["details"]["client_connection_id"].as_str(),
            )
        })
        .collect();
    // One bounded expansion adds same-agent connection context and indications.
    let related: HashSet<_> = rows
        .iter()
        .filter(|(line, row)| {
            seeds.contains(line)
                || (super::nsm::is_request_decision(row["event"].as_str().unwrap_or_default())
                    && trusted_agent(row).is_some()
                    && requests.contains(&(
                        trusted_agent(row),
                        sandbox_run_key(row),
                        row["request_id"].as_str(),
                        row["details"]["client_connection_id"].as_str(),
                    )))
                || (matches!(
                    row["event"].as_str(),
                    Some("network.connection" | "security.indicator")
                ) && row["details"]["connection_id"].as_str().is_some_and(|id| {
                    connections.contains(&(row["agent"].as_str(), sandbox_run_key(row), id))
                }))
        })
        .map(|(line, _)| *line)
        .collect();
    let mut included = related.clone();
    let mut evidence = Vec::new();
    for (line, row) in rows.iter().filter(|(line, _)| related.contains(line)) {
        for mut link in links(*line, row, query) {
            let decision =
                super::nsm::is_request_decision(row["event"].as_str().unwrap_or_default());
            link.record_lines = rows
                .iter()
                .filter(|(_, candidate)| {
                    link.matches(candidate)
                        && (!decision
                            || (trusted_agent(row).is_some()
                                && trusted_agent(candidate) == trusted_agent(row)
                                && (link.event != "network.connection"
                                    || candidate["details"]["leg"] == "client_to_proxy")))
                })
                .map(|(line, _)| *line)
                .collect();
            link.conflicting_record_lines = link
                .record_lines
                .iter()
                .filter(|line| conflicts.contains(line))
                .copied()
                .collect();
            if !conflicts.contains(line)
                && !link.record_lines.is_empty()
                && link.conflicting_record_lines.is_empty()
            {
                link.status = "available";
            }
            included.extend(link.record_lines.iter().copied());
            evidence.push(link);
        }
    }
    let correlations = correlation::exposures(&rows, &related, query, &conflicts, &mut included);
    let records: Vec<_> = rows.iter().filter(|(line, _)| included.contains(line)).map(|(line, row)| {
        let run_context = if sandbox_run_key(row).is_none() { "unavailable" }
            else if conflicts.contains(line) { "conflicting" }
            else if trusted_agent(row).is_some() { "recorded" } else { "unknown" };
        let mut entry = json!({"line":line,"selection":if related.contains(line) {"related"} else {"supporting"},"record":row,
            "sandbox_run":row["details"]["sandbox_run"],"run_context":run_context});
        if explicit {
            entry["locations"] = json!(copies[line]);
            entry["conflicting"] = json!(conflicts.contains(line));
        }
        entry
    }).collect();
    let mut result = json!({
        "query":{"instance_id":query.instance,"runtime_id":query.runtime,"kind":query.kind,"id":query.id,"agent":query.agent,"sandbox_run_id":query.sandbox_run},
        "search":search,"records":records,"links":evidence,"correlations":correlations
    });
    if explicit {
        result["inputs"] = json!(inputs);
    } else {
        result["file"] = json!(paths[0]);
    }
    Ok(result)
}
