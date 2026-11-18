//! Scoped reads of the canonical retained audit files, shared with host readers.
use crate::policy::{delegation::Agent, support::diagnostics::Scope};
use serde_json::{Value, json};

pub(crate) fn read(
    writer: &super::Writer,
    instance: &str,
    subjects: &[Agent],
    scope: &Scope,
) -> Value {
    let (path, settings) = writer.log_source();
    let pending = writer.wait_for_drain(std::time::Duration::from_millis(500));
    let mut rows = Vec::new();
    let mut limitations = Vec::new();
    if !matches!(pending, Ok(true)) {
        limitations.push("audit queue freshness could not be established");
    }
    let files = match super::explain::retained(&path, &settings.backups) {
        Ok(files) => files,
        Err(_) => {
            return json!({"source":"audit","status":"unavailable","rows":[],"limitations":["retained audit sources could not be enumerated"]});
        }
    };
    if files.is_empty() {
        return json!({"source":"audit","status":"unavailable","rows":[],"limitations":["the configured retained audit source is absent; no replacement window was collected"]});
    }
    let mut ambiguous = 0;
    let mut omitted = 0;
    let mut retained_bytes = 0;
    // Each file uses the same validated, bounded tail as the operator reader.
    for path in files.into_iter().rev() {
        let tail = match super::local_tail(&path, None, 10_000) {
            Ok(tail) => tail,
            Err(_) => {
                limitations.push("a selected audit source was lost, unreadable or invalid");
                continue;
            }
        };
        if tail.lines_read > tail.rows.len() {
            limitations.push("audit search was limited to the retained tail");
        }
        for (_, row) in tail.rows {
            if !scope.contains_time(row["ts"].as_str().unwrap_or("")) {
                continue;
            }
            let run = &row["details"]["sandbox_run"];
            let subject = subjects.iter().find(|subject| {
                row["agent"] == subject.name
                    && run["agent"] == subject.name
                    && run["agent_id"] == subject.agent_id
                    && row["details"]["instance_id"] == instance
                    && scope.runs.get(&subject.agent_id).is_none_or(|runs| {
                        runs.is_empty()
                            || run["run_id"]
                                .as_str()
                                .is_some_and(|id| runs.iter().any(|run| run == id))
                    })
            });
            let selected = if scope.audit
                && let Some(subject) = subject
            {
                Some(json!({"source":"audit","subject_id":subject.agent_id,"record":row}))
            } else if row.get("agent").is_some() {
                if subjects.iter().any(|a| row["agent"] == a.name) && run["agent_id"].is_null() {
                    ambiguous += 1;
                }
                None
            } else {
                system_record(&row, scope)
            };
            if let Some(selected) = selected {
                retained_bytes += selected.to_string().len();
                rows.push(selected);
                while rows.len() > 2000 || retained_bytes > 3 * 1024 * 1024 {
                    retained_bytes -= rows.remove(0).to_string().len();
                    omitted += 1;
                }
            }
        }
    }
    if ambiguous > 0 {
        limitations.push(
            "name-only historical records were excluded; durable ownership cannot be established",
        );
    }
    if omitted > 0 {
        limitations.push("authorized results exceeded the collection row or byte limit");
    }
    limitations.sort();
    limitations.dedup();
    json!({"source":"audit","status":if limitations.is_empty(){"complete_retained_search"}else{"incomplete_search"},
        "rows":rows,"limitations":limitations,"ambiguous_name_only_records":ambiguous,"omitted":omitted,
        "retention":"Only currently retained configured audit files were searched. Absence cannot establish that an event never occurred."})
}

// System sources disclose a typed health projection. Never follow references
// or copy arbitrary nested payloads, paths, credentials or policy content.
fn system_record(row: &Value, scope: &Scope) -> Option<Value> {
    let event = row["event"].as_str()?;
    let category = match event {
        "ops.audit_validation_failed" => "audit_health",
        _ => return None,
    };
    if !scope.system_categories.iter().any(|c| c == category) {
        return None;
    }
    let mut details = json!({});
    for key in [
        "available",
        "connected",
        "pending",
        "failed",
        "sequence",
        "last_success_at",
    ] {
        if let Some(value) = row["details"].get(key)
            && (value.is_boolean() || value.is_number() || value.is_null())
        {
            details[key] = value.clone();
        }
    }
    for key in ["state", "source", "component"] {
        if let Some(value) = row["details"][key].as_str()
            && matches!(
                value,
                "running"
                    | "stopped"
                    | "unknown"
                    | "unavailable"
                    | "degraded"
                    | "available"
                    | "nats"
                    | "outbox"
                    | "audit"
                    | "attention"
                    | "projection"
            )
        {
            details[key] = json!(value);
        }
    }
    if let Some(id) = row["details"]["agent_id"].as_str()
        && crate::desktop_present::valid_agent_id(id)
    {
        details["agent_id"] = json!(id);
    }
    Some(
        json!({"source":category,"record":{"event_id":row["event_id"],"event":event,"ts":row["ts"],"details":details},
        "projection":"Selected component-health facts only; references and unselected payload fields are omitted."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn system_payloads_cannot_smuggle_references_or_credentials() {
        let scope:Scope=serde_json::from_value(json!({"audit":false,"runtime":false,"rooms":[],"system_categories":["audit_health"],"history":{"since":null,"until":"2026-11-18T00:00:00Z","future":false},"snapshot":true})).unwrap();
        let row = json!({"event":"ops.audit_validation_failed","ts":"2026-11-17T00:00:00Z","details":{"connected":false,"state":"degraded","component":"audit","admin_token":"secret","reference":{"raw":"secret"},"source":"secret"}});
        let output = system_record(&row, &scope).unwrap();
        assert_eq!(output["record"]["details"]["connected"], false);
        assert!(!output.to_string().contains("secret"));
        assert!(system_record(&json!({"event":"coord.message_blocked"}), &scope).is_none());
    }
}
