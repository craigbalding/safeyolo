use serde_json::Value;

use super::{Error, ErrorKind, Result, nsm};

pub(crate) struct LocalTail {
    pub(crate) rows: std::collections::VecDeque<(usize, Value)>,
    pub(crate) lines_read: usize,
    pub(crate) agent_rows: usize,
}

/// Validate the whole configured file, retaining the last selected-agent rows.
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

/// Read mixed historical and current JSONL without upgrading stored records.
/// Unversioned writer fallbacks remain inspectable, but are not validated events.
pub fn parse_record(line: &str) -> Result<Value> {
    let invalid = || Error(ErrorKind::Encoding);
    let value: Value = serde_json::from_str(line).map_err(|_| invalid())?;
    let Some(version) = value.get("schema_version") else {
        return Ok(value);
    };
    let version = version.as_i64().ok_or_else(invalid)?;
    if !matches!(version, 1 | nsm::SCHEMA_VERSION) {
        return Err(invalid());
    }
    let event = value["event"].as_str().ok_or_else(invalid)?;
    let kind = value["kind"].as_str().ok_or_else(invalid)?;
    if version == 1 {
        // Preserve the native log reader's historical JSON representation.
        // These newly defined contracts cannot masquerade as version 1.
        return if kind == "network" || nsm::is_event(event) {
            Err(invalid())
        } else {
            Ok(value)
        };
    }
    // NSM validation below checks the exact event/kind pairing.
    if !matches!(
        value["severity"].as_str(),
        Some("critical" | "high" | "medium" | "low")
    ) || value["summary"].as_str().is_none_or(str::is_empty)
        || !value["ts"].is_string()
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
    nsm::validate(&value)?;
    Ok(value)
}
