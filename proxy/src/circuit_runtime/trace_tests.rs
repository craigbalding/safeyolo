//! Reached circuit decisions and failure continuation using the real owners.

use std::sync::{Arc, RwLock};

use serde_json::{Value, json};

use super::*;
use crate::{
    Config, audit,
    trace::{Settings, TraceStore},
};

const HOST: &str = "owned.invalid";
const RID: &str = "req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn make_runtime(directory: &std::path::Path, settings: Value, enabled: bool) -> Runtime {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"circuit_breaker":settings},
        })
        .to_string(),
    )
    .unwrap();
    let config: Config = serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,"event_log":directory.join("diagnostics.jsonl"),
        "audit_log_path":directory.join("audit.jsonl"),"readiness_file":directory.join("ready"),
        "agent_map_file":directory.join("absent-map.json"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_state_file":"","circuit_breaker_enabled":enabled,
    }))
    .unwrap();
    let mut runtime =
        Runtime::new(config, "owned-circuit-trace", Arc::default(), None, None).unwrap();
    runtime.traces = Arc::new(TraceStore::new(Settings::default()));
    runtime
}

fn context(store: &Arc<TraceStore>) -> Arc<RequestTrace> {
    let trace = Arc::new(RequestTrace::new(
        store.clone(),
        &ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: "owned-connection".into(),
            source_id: None,
        },
        RID,
        "GET",
        HOST,
        443,
    ));
    trace.enable(true);
    trace
}

fn steps(store: &TraceStore) -> Vec<Value> {
    store
        .get(RID, Some("alice"), now())
        .unwrap()
        .map_or_else(Vec::new, |report| {
            report["steps"].as_array().unwrap().clone()
        })
}

#[test]
fn response_outcome_is_observed_only_after_the_reached_operation() {
    for (enabled, prior, status, settings, expected) in [
        (
            false,
            false,
            Some(500),
            json!({}),
            Some(("bypassed", "addon_disabled", None)),
        ),
        (
            true,
            true,
            None,
            json!({}),
            Some(("evaluated", "prior_block", None)),
        ),
        (true, false, None, json!({}), None),
        (
            true,
            false,
            Some(500),
            json!({"excluded_domains":[HOST]}),
            Some(("evaluated", "excluded_domain", None)),
        ),
        (
            true,
            false,
            Some(200),
            json!({}),
            Some(("evaluated", "success_recorded", Some(200))),
        ),
        (
            true,
            false,
            Some(500),
            json!({}),
            Some(("evaluated", "failure_recorded", Some(500))),
        ),
        (
            true,
            false,
            Some(429),
            json!({}),
            Some(("evaluated", "failure_recorded", Some(429))),
        ),
        (
            true,
            false,
            Some(404),
            json!({}),
            Some(("evaluated", "status_no_action", Some(404))),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Arc::new(make_runtime(directory.path(), settings, enabled));
        let trace = context(&runtime.traces);
        let state = Arc::new(RwLock::new(runtime.clone()));
        let result = response_operation(&state, None, false, HOST, status, prior, Some(&trace));
        assert!(matches!(
            result,
            ResponseOutcome::Complete {
                evidence_failed: false
            }
        ));
        let rows = steps(&runtime.traces);
        if let Some((kind, value, status)) = expected {
            assert_eq!(rows.len(), 1);
            let step = &rows[0];
            assert_eq!(step["addon"], "circuit-breaker");
            assert_eq!(step["hook"], "response");
            assert_eq!(step["state"], kind);
            assert_eq!(
                step[if kind == "bypassed" {
                    "reason"
                } else {
                    "outcome"
                }],
                value
            );
            assert_eq!(step.get("duration_us").is_some(), kind != "bypassed");
            assert_eq!(
                step.get("details").cloned(),
                status.map(|status| json!({"status_code":status}))
            );
        } else {
            assert!(rows.is_empty(), "no-response is not an evaluated outcome");
        }
    }
}

#[test]
fn refresh_and_audit_errors_keep_exception_continuation_and_partial_effects() {
    // Refresh precedes prior_block; malformed exclusions fail even without a response.
    let directory = tempfile::tempdir().unwrap();
    let runtime = Arc::new(make_runtime(
        directory.path(),
        json!({"excluded_domains":1}),
        true,
    ));
    let trace = context(&runtime.traces);
    let state = Arc::new(RwLock::new(runtime.clone()));
    let result = local_blocked_response(&state, HOST, Some(&trace));
    assert!(matches!(
        result,
        ResponseOutcome::Exception {
            evidence_failed: false
        }
    ));
    assert_eq!(steps(&runtime.traces)[0]["reason"], "TypeError");
    assert!(steps(&runtime.traces)[0].get("outcome").is_none());

    let directory = tempfile::tempdir().unwrap();
    let runtime = Arc::new(make_runtime(
        directory.path(),
        json!({"failure_threshold":1}),
        true,
    ));
    runtime.audit.poison_for_test();
    let trace = context(&runtime.traces);
    let state = Arc::new(RwLock::new(runtime.clone()));
    let result = response_operation(&state, None, false, HOST, Some(500), false, Some(&trace));
    assert!(matches!(
        result,
        ResponseOutcome::Exception {
            evidence_failed: false
        }
    ));
    let rows = steps(&runtime.traces);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["state"], "error");
    assert_eq!(rows[0]["reason"], "AuditError");
    assert_eq!(
        runtime.circuits.snapshot(now()).unwrap()["states"],
        json!({})
    );
    assert_eq!(
        runtime
            .circuits
            .stats(true, now(), &mut || 0.5)
            .unwrap()
            .value["opens_total"],
        1
    );
}

#[test]
fn request_block_trace_waits_for_completed_reply_and_failed_audit_has_only_error() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = make_runtime(directory.path(), json!({}), true);
    let policy = runtime.policy.as_ref().unwrap();
    runtime.circuits.force_open(HOST, now()).unwrap();
    let decision = runtime
        .circuits
        .request_current_with_audit(
            policy,
            HOST,
            circuits::RequestGate::default(),
            now(),
            &mut || 0.5,
            &circuits::Audit::new(&runtime.audit, None, None),
        )
        .unwrap()
        .value;
    assert!(matches!(
        decision,
        circuits::RequestDecision::Blocked { .. }
    ));
    let trace = context(&runtime.traces);
    let hook = trace.hook("circuit-breaker", "request").unwrap();
    trace_request_decision(Some(&hook), &decision);
    assert!(steps(&runtime.traces).is_empty());
    trace_request_blocked(Some(&hook));
    assert_eq!(steps(&runtime.traces)[0]["details"], json!({"status":503}));

    let store = Arc::new(TraceStore::new(Settings::default()));
    let trace = context(&store);
    let hook = trace.hook("circuit-breaker", "request").unwrap();
    runtime.audit.poison_for_test();
    let error = runtime
        .audit
        .emit(audit::Event::new(
            "security.circuit_breaker",
            audit::Kind::Security,
            audit::Severity::High,
            "owned denial",
        ))
        .unwrap_err();
    trace_audit_error(Some(&hook), error.kind());
    let rows = steps(&store);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["reason"], "AuditError");
    assert!(rows[0].get("outcome").is_none());
}

#[test]
fn trace_failure_and_opt_out_do_not_change_response_effects() {
    for enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut runtime = make_runtime(directory.path(), json!({"failure_threshold":1}), true);
        runtime.traces = Arc::new(TraceStore::new(Settings {
            ttl_s: json!("invalid synthetic ttl").into(),
            ..Settings::default()
        }));
        let trace = Arc::new(RequestTrace::new(
            runtime.traces.clone(),
            &ConnectionIdentity {
                agent_id: "alice".into(),
                connection_id: "owned-connection".into(),
                source_id: None,
            },
            RID,
            "GET",
            HOST,
            443,
        ));
        trace.enable(enabled);
        let runtime = Arc::new(runtime);
        let state = Arc::new(RwLock::new(runtime.clone()));
        let result = response_operation(&state, None, false, HOST, Some(500), false, Some(&trace));
        assert!(matches!(
            result,
            ResponseOutcome::Complete {
                evidence_failed: false
            }
        ));
        let stats = runtime
            .circuits
            .stats(true, now(), &mut || 0.5)
            .unwrap()
            .value;
        assert_eq!(stats["opens_total"], 1);
        assert_eq!(stats["domains"][HOST]["failure_count"], 1);
    }
}

fn normalized(mut value: Value) -> Value {
    let object = value.as_object_mut().unwrap();
    object.retain(|key, value| key != "ts" && !value.is_null());
    if let Some(duration) = object.get_mut("duration_us")
        && duration != "<measured>"
    {
        assert!(duration.as_u64().is_some());
        *duration = json!("<measured>");
    }
    value
}

#[test]
fn selected_source_hooks_match_decisions_and_retained_state() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/security_trace_source.json")).unwrap();
    let mut compared = (0, 0);
    for row in fixture["rows"].as_array().unwrap() {
        let input = &row["input"];
        if input["component"] != "circuit" {
            continue;
        }
        let name = input["name"].as_str().unwrap();
        // The raw malformed cache is not an accepted canonical Policy view.
        // The separate real-store failure test covers observational failure
        // without equating native typed errors to a synthetic Python exception.
        if matches!(
            name,
            "response_reload_error_precedes_prior_block"
                | "request_record_failure_is_observational"
        ) {
            continue;
        }
        compared.0 += 1;
        let directory = tempfile::tempdir().unwrap();
        let runtime = make_runtime(
            directory.path(),
            input["sensor"]["addons"]["circuit_breaker"].clone(),
            input["options"]["enabled"].as_bool().unwrap(),
        );
        let host = input["flow"]["host"].as_str().unwrap_or(HOST);
        runtime
            .circuits
            .restore(
                &json!({"states":row["initial"]["state"]["states"]}),
                0.,
                &mut || 0.5,
            )
            .unwrap();
        assert_eq!(
            runtime.circuits.snapshot(0.).unwrap()["states"],
            row["initial"]["state"]["states"],
            "{name}: seed must not reconcile supplied state"
        );
        let trace = Arc::new(RequestTrace::new(
            runtime.traces.clone(),
            &ConnectionIdentity {
                agent_id: "alice".into(),
                connection_id: "owned-connection".into(),
                source_id: None,
            },
            RID,
            "POST",
            host,
            8123,
        ));
        trace.enable(true);
        let mut status = input["flow"]["response_status"].as_u64().map(|v| v as u16);
        let mut prior_block = input["flow"]["blocked_by"].as_str().is_some();
        for (recipe, observed) in input["hooks"]
            .as_array()
            .unwrap()
            .iter()
            .zip(row["hooks"].as_array().unwrap())
        {
            compared.1 += 1;
            let hook_name = recipe["hook"].as_str().unwrap();
            let clock = recipe["now"].as_f64().unwrap();
            if let Some(value) = recipe.get("response_status") {
                status = value.as_u64().map(|v| v as u16);
            }
            let audit_failure = recipe["audit_error"] == true;
            if audit_failure {
                runtime.audit.poison_for_test();
            }
            let hook = trace.hook(
                "circuit-breaker",
                if hook_name == "request" {
                    "request"
                } else {
                    "response"
                },
            );
            let policy = runtime.policy.as_ref().unwrap();
            let audit = circuits::Audit::new(&runtime.audit, None, None);
            if hook_name == "request" {
                match runtime.circuits.request_current_with_audit(
                    policy,
                    host,
                    circuits::RequestGate {
                        enabled: runtime.config.circuit_breaker_enabled,
                        prior_response: status.is_some(),
                        policy_bypassed: input["options"]["policy_enabled"] == false,
                    },
                    clock,
                    &mut || 0.5,
                    &audit,
                ) {
                    Ok(result) => {
                        trace_request_decision(hook.as_ref(), &result.value);
                        if matches!(result.value, circuits::RequestDecision::Blocked { .. }) {
                            // This helper's contract begins after the caller's
                            // concrete denial emission. HTTP reply construction
                            // and the event fields belong to the root wire test.
                            let emitted = runtime.audit.emit(audit::Event::new(
                                "security.circuit_breaker",
                                audit::Kind::Security,
                                audit::Severity::High,
                                "owned denial",
                            ));
                            match emitted {
                                Ok(_) => {
                                    status = Some(503);
                                    prior_block = true;
                                    trace_request_blocked(hook.as_ref());
                                }
                                Err(error) => {
                                    assert_eq!(error.kind(), audit::ErrorKind::Poisoned);
                                    trace_audit_error(hook.as_ref(), error.kind());
                                }
                            }
                        }
                    }
                    Err(error) => {
                        assert_eq!(
                            error.kind(),
                            circuits::ErrorKind::Audit(audit::ErrorKind::Poisoned)
                        );
                        trace_error(hook.as_ref(), &error);
                    }
                }
            } else {
                match runtime.circuits.response_current_with_audit(
                    policy,
                    host,
                    circuits::ResponseInput {
                        enabled: runtime.config.circuit_breaker_enabled,
                        prior_block,
                        status,
                    },
                    clock,
                    &mut || 0.5,
                    &audit,
                ) {
                    Ok(result) => trace_response_decision(hook.as_ref(), result.value, status),
                    Err(error) => {
                        assert_eq!(
                            error.kind(),
                            if audit_failure {
                                circuits::ErrorKind::Audit(audit::ErrorKind::Poisoned)
                            } else {
                                assert_eq!(observed["error_class"], "TypeError");
                                circuits::ErrorKind::Type
                            },
                            "{name}"
                        );
                        trace_error(hook.as_ref(), &error);
                    }
                }
            }
            let mut expected: Vec<_> = observed["trace"]
                .as_array()
                .unwrap()
                .first()
                .map(|report| report["steps"].as_array().unwrap().clone())
                .unwrap_or_default()
                .into_iter()
                .map(normalized)
                .collect();
            if audit_failure {
                assert_eq!(observed["error_class"], "RuntimeError");
                let last = expected.last_mut().unwrap();
                assert_eq!(last["reason"], "RuntimeError");
                // Explicit native-only writer poisoning is not Python's
                // RuntimeError. Every other trace field is compared exactly.
                last["reason"] = json!("AuditError");
            }
            let actual: Vec<_> = steps(&runtime.traces).into_iter().map(normalized).collect();
            assert_eq!(actual, expected, "{name}/{hook_name}");
            assert_eq!(
                runtime.circuits.snapshot(clock).unwrap()["states"],
                observed["state"]["states"],
                "{name}/{hook_name}: retained state"
            );
        }
    }
    assert_eq!(compared, (16, 20));
}
