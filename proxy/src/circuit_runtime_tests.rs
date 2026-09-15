//! Finite actual-source audit and Python counter presentation specimens.
//! The source writer adds attribution to its envelope; these comparisons keep
//! its original detail fields and test the development envelope separately.

use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{Value, json};

use super::{count_text, record_transition};
use crate::{
    Config, ConnectionIdentity, Runtime,
    circuits::{CircuitValue, Transition, TransitionKind},
};

fn source() -> Value {
    serde_json::from_str(include_str!("../tests/circuit_audit_source.json")).unwrap()
}

fn runtime(directory: &std::path::Path) -> Runtime {
    let policy = directory.join("policy.toml");
    std::fs::write(&policy, "[hosts]\n\"*\" = {egress = \"allow\"}\n").unwrap();
    let config: Config = serde_json::from_value(json!({
        "listeners": [{"agent_id": "alice", "socket_path": directory.join("alice.sock")}],
        "policy_file": policy,
        "readiness_file": directory.join("ready.json"),
        "flow_store_enabled": false,
        "audit_log_path": directory.join("audit.jsonl"),
        "event_log": directory.join("events.jsonl"),
        "admin_port": 0,
        "circuit_state_file": ""
    }))
    .unwrap();
    // Prepare only: this constructor binds no listener and starts no worker.
    Runtime::new(config, "owned-audit-test", Arc::default(), None, None).unwrap()
}

#[test]
fn actual_source_audit_details_match_typed_writer_and_transition_sink() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path());
    let identity = ConnectionIdentity {
        agent_id: "alice".into(),
        connection_id: "owned-audit-connection".into(),
        source_id: None,
    };
    let fixture = source();
    let rows = fixture["source_rows"].as_array().unwrap();
    assert_eq!(rows.len(), 28);
    let mut transition_rows = Vec::new();
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let input = CircuitValue::parse_json(row["input_details_json"].as_str().unwrap()).unwrap();
        let expected = row["audit_details_json"].as_str().unwrap();
        if row["stage"] == "actual_request_hook" {
            // This is the exact writer used by circuit_admission. Keep the
            // original details (including source correlation) byte-for-byte.
            assert_eq!(input.render_audit_json().unwrap(), expected, "{name}");
        } else {
            let event = match row["source_event"].as_str().unwrap() {
                "ops.circuit_breaker.open" => TransitionKind::Open,
                "ops.circuit_breaker.reopen" => TransitionKind::Reopen,
                "ops.circuit_breaker.close" => TransitionKind::Close,
                "ops.circuit_breaker.half_open" => TransitionKind::HalfOpen,
                other => panic!("unexpected source transition {other}"),
            };
            let details = match &input {
                CircuitValue::Object(details) => Some(details.clone()),
                CircuitValue::Other(Value::Null) => None,
                _ => panic!("unexpected source detail type: {name}"),
            };
            // Supplying a scope for half_open proves the writer removes it.
            let scope = if row["agent"].is_string() || event == TransitionKind::HalfOpen {
                Some((&identity, "req-synthetic-circuit-audit"))
            } else {
                None
            };
            record_transition(
                &runtime,
                &Transition {
                    event,
                    domain: "owned.invalid".into(),
                    details,
                },
                scope,
            )
            .unwrap();
            transition_rows.push(row);
        }
    }
    assert_eq!(transition_rows.len(), 10);
    let output = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), transition_rows.len());
    for (line, row) in lines.into_iter().zip(transition_rows) {
        let name = row["name"].as_str().unwrap();
        // Strict JSON rejects a bare NaN/Infinity here. The substring check
        // additionally preserves exact source detail ordering and spelling.
        let event: Value = serde_json::from_str(line).unwrap();
        let expected_details = row["audit_details_json"].as_str().unwrap();
        assert!(
            line.contains(&format!("\"details\": {expected_details},")),
            "{name}"
        );
        assert_eq!(event["event"], "proxy.circuit", "{name}");
        assert_eq!(event["audit_intent"], row["source_event"], "{name}");
        assert_eq!(event["summary"], row["source_summary"], "{name}");
        assert_eq!(event["agent"], row["agent"], "{name}");
        assert_eq!(event["request_id"], row["request_id"], "{name}");
    }
}

#[test]
fn actual_source_counter_str_matches_existing_formatter() {
    let fixture = source();
    let mut checked = 0;
    for row in fixture["source_rows"].as_array().unwrap() {
        let Some(input) = row["count_json"].as_str() else {
            continue;
        };
        let value = CircuitValue::parse_json(input).unwrap();
        assert_eq!(
            count_text(&value).unwrap(),
            row["python_count_text"].as_str().unwrap(),
            "{}",
            row["name"].as_str().unwrap()
        );
        checked += 1;
    }
    assert_eq!(checked, 18);
}

#[test]
fn audit_mode_handles_plain_overflow_recursively_without_changing_api_or_cache() {
    let huge = format!("1{}", "0".repeat(400));
    let raw = format!(
        "{{\"nested\": [1e400, {{\"negative\": -1e400, \"integer\": {huge}}}], \
         \"finite\": [-0.0, 1.25], \"literal\": \"NaN\"}}"
    );
    let plain = CircuitValue::Other(serde_json::from_str(&raw).unwrap());
    let expected = format!(
        "{{\"nested\": [null, {{\"negative\": null, \"integer\": {huge}}}], \
         \"finite\": [-0.0, 1.25], \"literal\": \"NaN\"}}"
    );
    let values = [plain, CircuitValue::parse_json(&raw).unwrap()];
    for value in values {
        let before = [
            value.render_json(false).unwrap(),
            value.render_json(true).unwrap(),
        ];
        assert!(before[0].contains("[Infinity, {\"negative\": -Infinity,"));
        assert_eq!(value.render_audit_json().unwrap(), expected);
        assert_eq!(value.render_json(false).unwrap(), before[0]);
        assert_eq!(value.render_json(true).unwrap(), before[1]);
    }
    let nested = CircuitValue::Object(IndexMap::from([(
        "typed".into(),
        CircuitValue::Array(vec![
            CircuitValue::Float(f64::NAN),
            CircuitValue::Float(f64::INFINITY),
            CircuitValue::Float(f64::NEG_INFINITY),
        ]),
    )]));
    assert_eq!(
        nested.render_audit_json().unwrap(),
        "{\"typed\": [null, null, null]}"
    );
    assert_eq!(
        nested.render_json(false).unwrap(),
        "{\"typed\": [NaN, Infinity, -Infinity]}"
    );
}
