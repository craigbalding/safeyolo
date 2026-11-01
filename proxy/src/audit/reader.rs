use serde_json::Value;

use super::{Error, ErrorKind, Result, nsm};

pub(crate) struct LocalTail {
    pub(crate) rows: std::collections::VecDeque<(usize, Value)>,
    pub(crate) lines_read: usize,
    pub(crate) agent_rows: usize,
}

/// Validate the whole supplied file, retaining the last selected-agent rows.
/// Diagnostics must not echo retained bytes, paths or decoding errors.
pub(crate) fn local_tail(
    path: &std::path::Path,
    agent: Option<&str>,
    limit: usize,
) -> std::result::Result<LocalTail, crate::Error> {
    use std::io::BufRead;
    let file = std::fs::File::open(path).map_err(|_| "local audit file could not be opened")?;
    let mut tail = LocalTail {
        rows: std::collections::VecDeque::new(),
        lines_read: 0,
        agent_rows: 0,
    };
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|_| "local audit file could not be read as UTF-8")?;
        let row = parse_record(&line)
            .map_err(|_| "local audit record is invalid; raw log remains inspectable")?;
        tail.lines_read += 1;
        if agent.is_some_and(|agent| row["agent"] != agent) {
            continue;
        }
        tail.agent_rows += 1;
        tail.rows.push_back((tail.lines_read, row));
        if tail.rows.len() > limit {
            tail.rows.pop_front();
        }
    }
    Ok(tail)
}

/// Validate the current audit envelope, then any scoped NSM contract.
pub fn parse_record(line: &str) -> Result<Value> {
    let invalid = || Error(ErrorKind::Encoding);
    let value: Value = serde_json::from_str(line).map_err(|_| invalid())?;
    if value["schema_version"].as_i64() != Some(super::SCHEMA_VERSION) {
        return Err(invalid());
    }
    let event = value["event"].as_str().ok_or_else(invalid)?;
    let kind = value["kind"].as_str().ok_or_else(invalid)?;
    if value.as_object().ok_or_else(invalid)?.keys().any(|key| {
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
    }) {
        return Err(invalid());
    }
    if !matches!(
        kind,
        "security"
            | "gateway"
            | "traffic"
            | "ops"
            | "admin"
            | "agent"
            | "plumb"
            | "coord"
            | "network"
    ) || !event.starts_with(&format!("{kind}."))
        || !matches!(
            value["severity"].as_str(),
            Some("critical" | "high" | "medium" | "low")
        )
        || value["summary"].as_str().is_none_or(str::is_empty)
        || value["ts"].as_str().is_none_or(|ts| {
            time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339).is_err()
        })
        || !value["details"].is_object()
    {
        return Err(invalid());
    }
    for name in [
        "event_id",
        "request_id",
        "agent",
        "addon",
        "control",
        "decision",
        "host",
    ] {
        if let Some(field) = value.get(name)
            && !field.is_string()
        {
            return Err(invalid());
        }
    }
    if value
        .get("event_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !(1..=128).contains(&id.chars().count()))
    {
        return Err(invalid());
    }
    if value.get("decision").is_some_and(|decision| {
        !matches!(
            decision.as_str(),
            Some("allow" | "deny" | "warn" | "require_approval" | "budget_exceeded" | "log")
        )
    }) {
        return Err(invalid());
    }
    if let Some(approval) = value.get("approval")
        && (!approval["required"].is_boolean()
            || !matches!(
                approval["approval_type"].as_str(),
                Some(
                    "credential"
                        | "network_egress"
                        | "gateway_route"
                        | "service"
                        | "contract_binding"
                        | "plumb"
                        | "desktop_present"
                )
            )
            || !approval["key"].is_string()
            || !approval["target"].is_string()
            || !approval["scope_hint"].is_object())
    {
        return Err(invalid());
    }
    if kind == "network" || nsm::is_scoped(&value) {
        nsm::validate(&value)?;
    }
    Ok(value)
}

/// A selected input failure aborts the view rather than silently omitting a file.
/// The input number identifies the argument without echoing its path or content.
pub(crate) fn selected_tails(
    paths: &[std::path::PathBuf],
    agent: Option<&str>,
    limit: usize,
) -> std::result::Result<Vec<LocalTail>, crate::Error> {
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            local_tail(path, agent, limit)
                .map_err(|error| format!("audit input {}: {error}", index + 1).into())
        })
        .collect()
}
