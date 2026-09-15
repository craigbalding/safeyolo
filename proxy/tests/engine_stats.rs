use std::{path::Path, process::Command, thread};

use safeyolo_proxy::policy::{
    CredentialRequest, Effect, EngineStatsError, Format, GatewayRequest, NetworkRequest, Policy,
    RiskyRouteRequest,
};
use serde_json::{Value, json};

const NOW: f64 = 1_000_000.;

fn fixture() -> Value {
    serde_json::from_str(include_str!("engine_stats_source.json")).unwrap()
}

fn network(host: &str) -> NetworkRequest<'_> {
    NetworkRequest {
        agent: None,
        host,
        port: None,
        method: "GET",
        path: "/",
    }
}

fn normalized_stats(policy: &Policy, root: &Path) -> Value {
    let mut value = policy.engine_stats().unwrap();
    for field in ["baseline_path", "task_policy_path"] {
        if let Some(path) = value[field].as_str() {
            value[field] = json!(path.replacen(root.to_str().unwrap(), "$ROOT", 1));
        }
    }
    value
}

fn compare_trace(source: &Value, reload_from_source: bool) {
    let directory = tempfile::tempdir().unwrap();
    let baseline = directory.path().join("./baseline.json");
    let task = directory.path().join("./task.json");
    std::fs::write(&baseline, source["baseline"].to_string()).unwrap();
    let mut policy = Policy::from_path_at(&baseline, NOW).unwrap();
    assert_eq!(
        normalized_stats(&policy, directory.path()).to_string(),
        source["initial"].to_string()
    );
    assert_eq!(
        Policy::unconfigured().engine_stats().unwrap(),
        source["unconfigured"]
    );
    for (index, row) in source["rows"].as_array().unwrap().iter().enumerate() {
        let operation = &row["operation"];
        let kind = operation["kind"].as_str().unwrap();
        let before = policy.engine_stats().unwrap()["evaluations"]
            .as_u64()
            .unwrap();
        let now = if operation["clock_error"] == true {
            f64::NAN
        } else {
            NOW
        };
        let decision = match kind {
            "network" => Some(
                policy.evaluate(
                    NetworkRequest {
                        port: operation
                            .get("port")
                            .map(|value| u16::try_from(value.as_u64().unwrap()).unwrap()),
                        method: operation["method"].as_str().unwrap_or("GET"),
                        ..network(operation["host"].as_str().unwrap())
                    },
                    now,
                    operation["consume"].as_bool().unwrap_or(true),
                ),
            ),
            "credential" => Some(policy.evaluate_credential(
                CredentialRequest {
                    credential_type: "fixture",
                    destination: operation["host"].as_str().unwrap(),
                    path: "/",
                    credential_hmac: None,
                },
                now,
            )),
            "risk" => Some(Ok(policy.evaluate_risky_route(RiskyRouteRequest {
                service: operation["service"].as_str().unwrap(),
                agent: "alice",
                account: "account",
                tactics: &[],
                enables: &[],
                irreversible: false,
                method: "GET",
                path: "/",
            }))),
            "gateway" => Some(Ok(policy.evaluate_gateway_request(GatewayRequest {
                service: "fixture",
                capability: "reader",
                agent: "alice",
                method: "GET",
                path: operation["path"].as_str().unwrap(),
            }))),
            "reload" | "task" => {
                let input = if operation["invalid"] == true {
                    "{".into()
                } else {
                    operation["document"].to_string()
                };
                let path = if kind == "reload" { &baseline } else { &task };
                std::fs::write(path, &input).unwrap();
                let next = if kind == "task" {
                    policy.with_task_path(path)
                } else if reload_from_source {
                    policy.reload_from_source_at(&input, Format::Json, NOW)
                } else {
                    policy.reload_from_path_at(path, NOW)
                };
                assert_eq!(
                    next.is_ok(),
                    row["outcome"]["value"].as_bool().unwrap(),
                    "operation {index}"
                );
                if let Ok(next) = next {
                    policy = next;
                }
                None
            }
            "clear_task" => {
                policy = policy.without_task();
                None
            }
            "read" => {
                policy.engine_stats().unwrap();
                policy.budget_stats(NOW).unwrap();
                policy.policy_hash();
                None
            }
            _ => panic!("unknown source operation"),
        };
        if let Some(result) = decision {
            if row["outcome"].get("error").is_some() {
                assert!(result.is_err(), "operation {index}");
            } else {
                assert_eq!(
                    serde_json::to_value(result.unwrap().effect).unwrap(),
                    row["outcome"]["value"],
                    "operation {index}"
                );
            }
        }
        let actual = normalized_stats(&policy, directory.path());
        assert_eq!(
            actual["evaluations"].as_u64().unwrap() - before,
            row["count_delta"].as_u64().unwrap(),
            "operation {index}"
        );
        assert_eq!(
            actual.to_string(),
            row["after"].to_string(),
            "operation {index}"
        );
    }
}

#[test]
fn source_counter_effects_failures_reads_and_file_lifecycle_match() {
    let source = fixture();
    assert_eq!(source["rows"].as_array().unwrap().len(), 35);
    compare_trace(&source, false);
}

#[test]
fn source_only_reload_retains_original_file_path_and_all_shared_counts() {
    compare_trace(&fixture(), true);
}

#[test]
fn clone_task_route_and_reload_snapshots_share_one_atomic_counter() {
    let original = Policy::parse(
        r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
        Format::Json,
    )
    .unwrap();
    let task = original.with_task_source("{}", Format::Json).unwrap();
    let reloaded = task.reload_from_source_at("{}", Format::Json, NOW).unwrap();
    let routes = reloaded.with_gateway_routes(&[]);
    let without_task = routes.without_task();
    let snapshots = [original.clone(), task, reloaded, routes, without_task];
    let workers: Vec<_> = snapshots
        .into_iter()
        .map(|policy| {
            thread::spawn(move || {
                for index in 0..100 {
                    match index % 4 {
                        0 => {
                            policy
                                .evaluate(network("fixture.invalid"), NOW, false)
                                .unwrap();
                        }
                        1 => {
                            policy
                                .evaluate_credential(
                                    CredentialRequest {
                                        credential_type: "fixture",
                                        destination: "fixture.invalid",
                                        path: "/",
                                        credential_hmac: None,
                                    },
                                    NOW,
                                )
                                .unwrap();
                        }
                        2 => {
                            policy.evaluate_risky_route(RiskyRouteRequest {
                                service: "fixture",
                                agent: "alice",
                                account: "account",
                                tactics: &[],
                                enables: &[],
                                irreversible: false,
                                method: "GET",
                                path: "/",
                            });
                        }
                        _ => {
                            policy.evaluate_gateway_request(GatewayRequest {
                                service: "fixture",
                                capability: "reader",
                                agent: "alice",
                                method: "GET",
                                path: "/",
                            });
                        }
                    }
                }
                policy
            })
        })
        .collect();
    let returned: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(original.engine_stats().unwrap()["evaluations"], 500);
    for policy in returned {
        assert_eq!(policy.engine_stats().unwrap()["evaluations"], 500);
    }
    assert_eq!(
        Policy::parse("{}", Format::Json)
            .unwrap()
            .engine_stats()
            .unwrap()["evaluations"],
        0
    );
}

#[test]
fn failed_file_reload_and_task_reload_preserve_observed_state() {
    let directory = tempfile::tempdir().unwrap();
    let baseline = directory.path().join("baseline.json");
    let task = directory.path().join("task.json");
    std::fs::write(&baseline, "{}").unwrap();
    std::fs::write(
        &task,
        r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
    )
    .unwrap();
    let original = Policy::from_path_at(&baseline, NOW)
        .unwrap()
        .with_task_path(&task)
        .unwrap();
    assert_eq!(
        original
            .evaluate(network("fixture.invalid"), NOW, false)
            .unwrap()
            .effect,
        Effect::Allow
    );
    let reloaded = original.reload_task().unwrap();
    assert_eq!(reloaded.engine_stats().unwrap()["evaluations"], 1);
    std::fs::write(&task, "invalid json").unwrap();
    assert!(reloaded.reload_task().is_err());
    std::fs::write(&baseline, "invalid json").unwrap();
    assert!(reloaded.reload_from_path_at(&baseline, NOW).is_err());
    assert_eq!(
        reloaded.engine_stats().unwrap(),
        original.engine_stats().unwrap()
    );
    original
        .evaluate(network("fixture.invalid"), NOW, false)
        .unwrap();
    assert_eq!(reloaded.engine_stats().unwrap()["evaluations"], 2);
}

#[cfg(unix)]
#[test]
fn admitted_non_unicode_file_path_has_explicit_reporting_failure() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join(OsString::from_vec(b"policy-\xff.json".to_vec()));
    std::fs::write(&path, "{}").unwrap();
    let policy = Policy::from_path_at(&path, NOW).unwrap();
    assert_eq!(policy.engine_stats(), Err(EngineStatsError::PathEncoding));
    assert_eq!(
        policy
            .evaluate(network("fixture.invalid"), NOW, false)
            .unwrap()
            .effect,
        Effect::Deny
    );
}

#[test]
#[ignore = "requires the pinned source Python environment"]
fn live_python_stats_and_lexical_path_oracle() {
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON");
    let output = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/engine_stats_oracle.py"))
        .arg("--emit")
        .output()
        .unwrap();
    assert!(output.status.success(), "source stats oracle failed");
    let live: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(live, fixture());
    compare_trace(&live, false);
}
