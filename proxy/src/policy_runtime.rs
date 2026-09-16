//! Baseline load evidence at the Runtime's rejected or accepted boundary.

use std::{io::Write, path::Path, sync::Arc};

use serde_json::json;

use crate::{
    Error,
    audit::{Event, Kind, Severity, Writer},
    policy::{self, Policy, PolicyLoadError, PolicyLoadStage},
    services::Registry,
};

pub(crate) fn load(
    path: &Path,
    registry: Option<Arc<Registry>>,
    previous: Option<&Policy>,
    writer: &Writer,
) -> Result<Policy, Error> {
    let result = match previous {
        Some(policy) => policy.reload_baseline_at(path, registry, policy::current_time_ms()),
        None => Policy::load_baseline_at(path, registry, policy::current_time_ms()),
    };
    result.map_err(|failure| {
        if writer.emit(rejected(&failure)).is_err() {
            evidence_failure("rejected");
        }
        // Evidence failure must not replace the rejected configuration's cause.
        Box::new(failure.error) as Error
    })
}

pub(crate) fn accepted(policy: Option<&Policy>, writer: &Writer) {
    let Some(count) = policy.and_then(Policy::baseline_permissions_count) else {
        return;
    };
    let mut event = Event::new(
        "ops.policy_reload",
        Kind::Ops,
        Severity::Medium,
        format!("Baseline policy reloaded: {count} permissions"),
    );
    event.addon = Some("policy-loader".into());
    event.details = json!({"policy_type":"baseline", "permissions_count":count}).into();
    if let Err(error) = writer.emit(event) {
        // Source attempts one policy_error after a success submission fails.
        // Retain that event, but keep the already accepted native snapshot and
        // load result. Audit availability cannot roll back only its catalog.
        let _ = writer.emit(failed(&error.to_string()));
        evidence_failure("accepted");
    }
}

fn rejected(failure: &PolicyLoadError) -> Event {
    if matches!(
        failure.stage,
        PolicyLoadStage::Read | PolicyLoadStage::Decode(_) | PolicyLoadStage::JsonNull
    ) && failure.error.kind != policy::ErrorKind::Unsupported
    {
        let mut event = Event::new(
            "ops.policy_error",
            Kind::Ops,
            Severity::High,
            "Baseline policy file not found or invalid",
        );
        event.addon = Some("policy-loader".into());
        event.details =
            json!({"policy_type":"baseline", "error":"File not found or invalid"}).into();
        event
    } else {
        failed(&failure.error.message)
    }
}

fn failed(message: &str) -> Event {
    let mut event = Event::new(
        "ops.policy_error",
        Kind::Ops,
        Severity::High,
        format!("Baseline policy load failed: {message}"),
    );
    event.addon = Some("policy-loader".into());
    event.details = json!({"policy_type":"baseline", "error":message}).into();
    event
}

fn evidence_failure(outcome: &str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "Baseline policy {outcome}; policy audit submission failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::time::Duration;

    #[test]
    fn eight_actual_source_loads_match_complete_canonical_event_envelopes() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/policy_reload_source.json")).unwrap();
        let names = [
            "iam_success",
            "host_centric_count_excludes_pre_simple",
            "empty_yaml_is_empty_policy",
            "null_yaml_is_empty_policy",
            "empty_toml_is_empty_policy",
            "missing_file_fixed_error",
            "invalid_json_fixed_error",
            "null_json_fixed_error",
        ];
        for name in names {
            let row = fixture["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["input"]["name"] == name)
                .unwrap();
            let directory = tempfile::tempdir().unwrap();
            let file = &row["input"]["file"];
            let path = directory.path().join(file["path"].as_str().unwrap());
            if file["missing"] != true {
                let content = file["text"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| file["document"].to_string());
                std::fs::write(&path, content).unwrap();
            }
            let audit_path = directory.path().join("audit.jsonl");
            let writer = Writer::new(audit_path.clone(), Default::default());
            let policy = load(&path, None, None, &writer);
            assert_eq!(policy.is_ok(), row["return"] == true, "{name}");
            if let Ok(policy) = policy {
                accepted(Some(&policy), &writer);
            }
            assert!(writer.shutdown(Duration::from_secs(5)).unwrap());
            let actual: Vec<Value> = std::fs::read_to_string(audit_path)
                .unwrap()
                .lines()
                .map(|line| {
                    let mut value: Value = serde_json::from_str(line).unwrap();
                    value["ts"] = "<canonical timestamp>".into();
                    value
                })
                .collect();
            let expected: Vec<Value> = row["attempts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|attempt| attempt["event"].clone())
                .collect();
            assert_eq!(actual, expected, "{name}");
            for (actual, expected) in actual.iter().zip(&expected) {
                assert_eq!(
                    actual["details"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .collect::<Vec<_>>(),
                    expected["details"]
                        .as_object()
                        .unwrap()
                        .keys()
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}
