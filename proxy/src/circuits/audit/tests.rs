use std::{path::Path, process::Command, time::Duration};

use serde_json::{Value, json};

use super::*;
use crate::{
    audit::{ErrorKind as AuditErrorKind, Settings, Writer},
    circuits::{CircuitBreaker, RequestGate, ResponseInput, TransitionKind},
    policy::{Format, Policy},
};

const WAIT: Duration = Duration::from_secs(5);
const HOST: &str = "owned.invalid";

fn source() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/circuit_audit_order_source.json"
    ))
    .unwrap()
}

fn writer(path: &Path) -> Writer {
    Writer::new(
        path.to_owned(),
        Settings::from_environment_values(None, None, None).unwrap(),
    )
}

fn records(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let mut value: Value = serde_json::from_str(line).unwrap();
            value.as_object_mut().unwrap().shift_remove("ts");
            value
        })
        .collect()
}

#[test]
fn live_source_submission_oracle_matches_frozen_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON")
        .expect("set SAFEYOLO_POLICY_PYTHON to the source Python environment");
    let result = Command::new(python)
        .arg(root.join("proxy/tests/circuit_audit_order_source.py"))
        .arg("--check")
        .arg(root.join("proxy/tests/circuit_audit_order_source.json"))
        .env(
            "PYTHONPATH",
            std::env::join_paths([root.join("cli/src"), root.to_owned()]).unwrap(),
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "source circuit audit oracle failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn submission_failure_preserves_source_partial_effects_and_success_envelopes() {
    let fixture = source();
    let policy = Policy::parse(
        &json!({"addons":{"circuit_breaker": fixture["settings"]}}).to_string(),
        Format::Json,
    )
    .unwrap();
    for row in fixture["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let cb = CircuitBreaker::new();
        cb.apply_sensor_config(&json!({
            "policy_hash":"owned-fixture", "addons":{"circuit_breaker": fixture["settings"]}
        }))
        .unwrap();
        {
            let mut inner = cb.lock().unwrap();
            for (domain, record) in row["initial_states"].as_object().unwrap() {
                inner.states.insert(
                    domain.clone(),
                    record
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| (key.clone(), CircuitValue::from(value.clone())))
                        .collect(),
                );
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("audit.jsonl");
        let writer = writer(&path);
        if row["submission_error"] == true {
            // A real Writer::emit error, with no production callback/fault API.
            // Python's controlled queue callback raises RuntimeError; the
            // native-only lock failure remains categorically Poisoned.
            writer.poison_for_test();
        }
        let audit = Audit::new(&writer, Some("req-circuit-owned"), Some("alice"));
        let result = match row["operation"].as_str().unwrap() {
            "open" | "reopen" | "close" => cb
                .response_current_with_audit(
                    &policy,
                    HOST,
                    ResponseInput {
                        enabled: true,
                        prior_block: false,
                        status: Some(if row["operation"] == "close" {
                            200
                        } else {
                            503
                        }),
                    },
                    fixture["now"].as_f64().unwrap(),
                    &mut || 0.5,
                    &audit,
                )
                .map(|outcome| outcome.events),
            "half_request" => cb
                .request_current_with_audit(
                    &policy,
                    HOST,
                    RequestGate {
                        enabled: true,
                        prior_response: false,
                        policy_bypassed: false,
                    },
                    fixture["now"].as_f64().unwrap(),
                    &mut || 0.5,
                    &audit,
                )
                .map(|outcome| outcome.events),
            "half_stats" => cb
                .stats_document_with_audit(
                    true,
                    fixture["now"].as_f64().unwrap(),
                    &mut || 0.5,
                    &audit,
                )
                .map(|outcome| outcome.events),
            _ => panic!("unknown owned source case"),
        };
        if row["submission_error"] == true {
            let error = result.unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::Audit(AuditErrorKind::Poisoned),
                "{name}"
            );
            assert_eq!(
                error.to_string(),
                "circuit audit submission failed",
                "{name}"
            );
            assert!(
                error.events().is_empty(),
                "failed submission is not an emitted intent: {name}"
            );
            assert!(!path.exists(), "{name}");
        } else {
            assert_eq!(
                result.unwrap().len(),
                row["submitted"].as_array().unwrap().len(),
                "{name}"
            );
            assert!(writer.wait_for_drain(WAIT).unwrap(), "{name}");
            assert!(writer.shutdown(WAIT).unwrap(), "{name}");
            assert_eq!(
                serde_json::to_string(&records(&path)).unwrap(),
                serde_json::to_string(&row["submitted"]).unwrap(),
                "fields and source insertion order: {name}"
            );
        }
        // Observe without get_status/get_stats: those would mutate the fixture.
        let inner = cb.lock().unwrap();
        let states = super::super::states_document(inner.states.clone())
            .json()
            .unwrap();
        assert_eq!(states, row["states"], "{name}");
        assert_eq!(
            json!({
                "checks": inner.counters.checks.to_string().parse::<u64>().unwrap(),
                "opens": inner.counters.opens.to_string().parse::<u64>().unwrap(),
                "half_opens": inner.counters.half_opens.to_string().parse::<u64>().unwrap(),
                "recoveries": inner.counters.recoveries.to_string().parse::<u64>().unwrap(),
            }),
            row["counters"],
            "{name}"
        );
    }
}

#[test]
fn transition_constructor_reuses_existing_source_envelopes_and_optional_scope() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/circuit_audit_source.json")).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("audit.jsonl");
    let writer = writer(&path);
    let rows: Vec<_> = fixture["source_rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["stage"] != "actual_request_hook")
        .collect();
    assert_eq!(rows.len(), 10);
    for row in &rows {
        let event = match row["source_event"].as_str().unwrap() {
            "ops.circuit_breaker.open" => TransitionKind::Open,
            "ops.circuit_breaker.reopen" => TransitionKind::Reopen,
            "ops.circuit_breaker.close" => TransitionKind::Close,
            "ops.circuit_breaker.half_open" => TransitionKind::HalfOpen,
            _ => panic!("unknown source transition"),
        };
        let details =
            match CircuitValue::parse_json(row["input_details_json"].as_str().unwrap()).unwrap() {
                CircuitValue::Object(ref details) => Some(details.clone()),
                CircuitValue::Other(Value::Null) => None,
                _ => panic!("unexpected source details"),
            };
        let transition = Transition {
            event,
            domain: HOST.into(),
            details,
        };
        let (id, agent) = if event == TransitionKind::HalfOpen {
            // The source never correlates half_open even during a flow hook.
            (Some("discarded-correlation"), Some("discarded-agent"))
        } else {
            (row["request_id"].as_str(), row["agent"].as_str())
        };
        Audit::new(&writer, id, agent).submit(&transition).unwrap();
    }
    assert!(writer.wait_for_drain(WAIT).unwrap());
    assert!(writer.shutdown(WAIT).unwrap());
    let output = records(&path);
    assert_eq!(output.len(), rows.len());
    for (record, row) in output.iter().zip(rows) {
        assert_eq!(record["schema_version"], 1);
        assert_eq!(record["event"], row["source_event"]);
        assert_eq!(record["summary"], row["source_summary"]);
        assert_eq!(record["kind"], "ops");
        assert_eq!(record["severity"], "medium");
        assert_eq!(record["addon"], "circuit-breaker");
        assert_eq!(record["host"], HOST);
        assert_eq!(
            record.get("agent"),
            row["agent"].as_str().map(|_| &row["agent"])
        );
        assert_eq!(
            record.get("request_id"),
            row["request_id"].as_str().map(|_| &row["request_id"])
        );
        assert_eq!(
            record["details"],
            serde_json::from_str::<Value>(row["audit_details_json"].as_str().unwrap()).unwrap()
        );
        assert!(record.get("decision").is_none());
        assert!(record["details"].get("attribution").is_none());
    }
}

#[test]
fn stopped_submission_is_not_a_hook_error_and_pure_callers_keep_intents() {
    let cb = CircuitBreaker::new();
    let policy = Policy::parse(
        "{\"addons\":{\"circuit_breaker\":{\"failure_threshold\":1}}}",
        Format::Json,
    )
    .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("audit.jsonl");
    let writer = writer(&path);
    assert!(writer.shutdown(WAIT).unwrap());
    let result = cb
        .response_current_with_audit(
            &policy,
            HOST,
            ResponseInput {
                enabled: true,
                prior_block: false,
                status: Some(503),
            },
            1000.0,
            &mut || 0.5,
            &Audit::new(&writer, None, None),
        )
        .unwrap();
    assert_eq!(result.events.len(), 1);
    assert_eq!(
        cb.snapshot(1000.0).unwrap()["states"][HOST]["state"],
        "open"
    );
    assert!(!path.exists());

    let pure = CircuitBreaker::new();
    pure.apply_sensor_config(
        &json!({"policy_hash":"pure", "addons":{"circuit_breaker":{"failure_threshold":1}}}),
    )
    .unwrap();
    let outcome = pure
        .record_failure(HOST, Some("HTTP 503"), 1000.0, &mut || 0.5)
        .unwrap();
    assert_eq!(outcome.events.len(), 1);
    assert_eq!(outcome.events[0].event, TransitionKind::Open);
}
