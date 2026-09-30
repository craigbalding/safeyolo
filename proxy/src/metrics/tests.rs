use super::*;
use std::cell::Cell;

fn encoded(value: &C) -> String {
    value.render_json(false).unwrap()
}
fn stat(owner: &Metrics, key: &str) -> BigInt {
    owner.get_stats().unwrap().as_object().unwrap()[key]
        .integer()
        .unwrap()
}

#[test]
fn reached_clock_sees_request_effects_and_response_creation_before_classification() {
    let owner = Metrics::new(|| 10.0);
    let first = owner
        .request("owned.invalid", || {
            assert_eq!(stat(&owner, "requests_total"), 1.into());
            assert_eq!(
                owner.lock().unwrap().domains["owned.invalid"].requests,
                1.into()
            );
            20.0
        })
        .unwrap();
    let second = owner.request("owned.invalid", || 21.0).unwrap();
    assert_eq!(first, 20.0);
    assert_eq!(second, 21.0);
    let blocked = text("agent-api");
    owner
        .response(
            "response-only.invalid",
            Some(second),
            Some(&blocked),
            Some(200),
            || {
                let state = owner.lock().unwrap();
                assert_eq!(state.domains["response-only.invalid"].requests, 0.into());
                assert_eq!(state.blocked, 0.into());
                22.0
            },
        )
        .unwrap();
    assert_eq!(stat(&owner, "requests_blocked"), 1.into());
    assert_eq!(stat(&owner, "requests_success"), 0.into());
    assert_eq!(owner.lock().unwrap().sources["agent-api"], 1.into());
}

#[test]
fn metadata_failure_keeps_reached_block_count_without_inventing_source_key() {
    let owner = Metrics::new(|| 0.0);
    let calls = Cell::new(0);
    let array = C::Array(vec![1.into()]);
    let error = owner
        .response("owned.invalid", Some(1.0), Some(&array), None, || {
            calls.set(calls.get() + 1);
            2.0
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Type);
    assert_eq!(calls.get(), 1);
    assert_eq!(stat(&owner, "requests_blocked"), 1.into());
    assert!(owner.lock().unwrap().sources.is_empty());
    assert_eq!(
        owner
            .response(
                "owned.invalid",
                None,
                Some(&1.into()),
                Some(200),
                || panic!("no clock without start")
            )
            .unwrap_err()
            .kind(),
        ErrorKind::Compatibility
    );
    assert_eq!(stat(&owner, "requests_blocked"), 2.into());
    assert!(owner.lock().unwrap().sources.is_empty());
    let empty = C::Array(Vec::new());
    owner
        .response("owned.invalid", Some(0.0), Some(&empty), Some(200), || {
            panic!("zero start is false")
        })
        .unwrap();
    assert_eq!(stat(&owner, "requests_success"), 1.into());
}

#[test]
fn no_data_equal_negative_and_nonfinite_latencies_preserve_number_kinds() {
    let owner = Metrics::new(|| 0.0);
    owner
        .response("owned.invalid", None, None, None, || panic!("no clock"))
        .unwrap();
    let before = owner.lock().unwrap().domains["owned.invalid"]
        .document()
        .unwrap();
    assert!(encoded(&before).ends_with(r#""latency_ms": {"avg": 0, "max": 0}}"#));
    owner
        .response("owned.invalid", None, None, Some(200), || {
            panic!("no clock")
        })
        .unwrap();
    let zero = owner.lock().unwrap().domains["owned.invalid"]
        .document()
        .unwrap();
    assert!(encoded(&zero).ends_with(r#""latency_ms": {"avg": 0.0, "max": 0}}"#));
    owner
        .response("owned.invalid", Some(1.0), None, Some(200), || 0.0)
        .unwrap();
    let negative = owner.lock().unwrap().domains["owned.invalid"]
        .document()
        .unwrap();
    assert!(encoded(&negative).ends_with(r#""latency_ms": {"avg": -500.0, "max": 0}}"#));
    owner
        .response("owned.invalid", Some(1.0), None, Some(200), || f64::NAN)
        .unwrap();
    let nan = owner.lock().unwrap().domains["owned.invalid"]
        .document()
        .unwrap();
    assert!(encoded(&nan).ends_with(r#""latency_ms": {"avg": NaN, "max": 0}}"#));
    assert!(
        owner
            .get_prometheus(|| 1.0)
            .unwrap()
            .ends_with("safeyolo_domain_latency_avg_ms{domain=\"owned.invalid\"} nan\n")
    );
}

#[test]
fn callback_failure_does_not_poison_prior_effects_and_reporting_overflow_is_categorical() {
    let owner = Metrics::new(|| 0.0);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = owner.request("owned.invalid", || panic!("owned clock failure"));
    }));
    assert!(failed.is_err());
    assert_eq!(stat(&owner, "requests_total"), 1.into());
    {
        let mut state = owner.lock().unwrap();
        state.success = BigInt::from(10).pow(400);
    }
    assert_eq!(
        owner.get_json(|| 1.0).unwrap_err().kind(),
        ErrorKind::Overflow
    );
    assert_eq!(stat(&owner, "requests_total"), 1.into());
    assert_eq!(
        Error(ErrorKind::Overflow).to_string(),
        "metrics operation failed"
    );
}

fn number(value: &BigInt) -> Value {
    serde_json::from_str(&value.to_string()).unwrap()
}
fn snapshot(owner: &Metrics) -> Value {
    let state = owner.lock().unwrap();
    let domains: serde_json::Map<_,_> = state.domains.iter().map(|(host,stats)| {
        (host.clone(),serde_json::json!({
            "requests":number(&stats.requests),"successes":number(&stats.successes),
            "blocked_credential":number(&stats.credential),"blocked_yara":number(&stats.yara),
            "blocked_pattern":number(&stats.pattern),"blocked_injection":number(&stats.injection),
            "upstream_429s":number(&stats.upstream_429),"upstream_5xx":number(&stats.upstream_5xx),
            "timeouts":number(&stats.timeouts),
            "latency_sum_ms":stats.latency_sum.map_or(serde_json::json!(0), |n| serde_json::json!(n)),
            "latency_count":number(&stats.latency_count),
            "latency_max_ms":stats.latency_max.map_or(serde_json::json!(0), |n| serde_json::json!(n)),
        }))
    }).collect();
    let sources: serde_json::Map<_, _> = state
        .sources
        .iter()
        .map(|(name, count)| (name.clone(), number(count)))
        .collect();
    serde_json::json!({"requests_total":number(&state.total),"requests_success":number(&state.success),
        "requests_blocked":number(&state.blocked),"requests_error":number(&state.error),
        "domains":domains,"blocks_by_source":sources})
}
fn seed(owner: &Metrics, spec: &Value) {
    let mut state = owner.lock().unwrap();
    if let Some(values) = spec["counters"].as_object() {
        for (name, value) in values {
            let count = value.to_string().parse().unwrap();
            match name.as_str() {
                "requests_total" => state.total = count,
                "requests_success" => state.success = count,
                "requests_blocked" => state.blocked = count,
                "requests_error" => state.error = count,
                _ => panic!("fixture counter"),
            }
        }
    }
    for (host, fields) in spec["domains"].as_object().unwrap() {
        let mut stats = Domain::default();
        for (name, value) in fields.as_object().unwrap() {
            match name.as_str() {
                "latency_sum_ms" => stats.latency_sum = Some(value.as_f64().unwrap()),
                "latency_max_ms" => stats.latency_max = Some(value.as_f64().unwrap()),
                _ => {
                    let count = value.to_string().parse().unwrap();
                    match name.as_str() {
                        "requests" => stats.requests = count,
                        "successes" => stats.successes = count,
                        "blocked_credential" => stats.credential = count,
                        "blocked_yara" => stats.yara = count,
                        "blocked_pattern" => stats.pattern = count,
                        "blocked_injection" => stats.injection = count,
                        "upstream_429s" => stats.upstream_429 = count,
                        "upstream_5xx" => stats.upstream_5xx = count,
                        "timeouts" => stats.timeouts = count,
                        "latency_count" => stats.latency_count = count,
                        _ => panic!("fixture domain field"),
                    }
                }
            }
        }
        state.domains.insert(host.clone(), stats);
    }
    if let Some(sources) = spec["blocks"].as_object() {
        state.sources.extend(
            sources
                .iter()
                .map(|(name, value)| (name.clone(), value.to_string().parse().unwrap())),
        );
    }
}
fn exact(value: &Value) -> String {
    encoded(&C::from(value.clone()))
}

#[test]
fn actual_source_eighteen_workflows_preserve_reports_and_clock_order() {
    use serde_json::json;
    use std::cell::RefCell;
    let source: Value =
        serde_json::from_str(include_str!("../../tests/metrics_source.json")).unwrap();
    let rows = source["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 18);
    for row in rows {
        let spec = &row["input"];
        let name = spec["name"].as_str().unwrap();
        let init = RefCell::new(Vec::new());
        let owner = Metrics::new(|| {
            init.borrow_mut().push(json!({"time":spec["start_time"]}));
            spec["start_time"].as_f64().unwrap()
        });
        assert_eq!(*init.borrow(), *row["init_timeline"].as_array().unwrap());
        let mut flows = serde_json::Map::<String, Value>::new();
        for (index, step) in spec["steps"].as_array().unwrap().iter().enumerate() {
            let expected = &row["steps"][index];
            let hook = step["hook"].as_str().unwrap();
            let flow_name = step["flow"].as_str().unwrap_or("flow");
            if matches!(hook, "request" | "response") {
                let flow = flows
                    .entry(flow_name)
                    .or_insert_with(|| json!({"host":"owned.invalid","metadata":{},"status":null}));
                if let Some(host) = step.get("host") {
                    flow["host"] = host.clone();
                }
                if let Some(start) = step.get("start") {
                    flow["metadata"]["metrics_start_time"] = start.clone();
                }
                if let Some(blocked) = step.get("blocked_by") {
                    flow["metadata"]["blocked_by"] = blocked.clone();
                }
                if hook == "response" {
                    flow["status"] = step["status"].clone();
                }
            }
            let observations = RefCell::new(Vec::new());
            let clock = || {
                assert!(
                    !step["forbid_clock"].as_bool().unwrap_or(false),
                    "forbidden clock {name}/{index}"
                );
                observations
                    .borrow_mut()
                    .push(json!({"time":step["now"],"state":snapshot(&owner),"flows":flows}));
                step["now"].as_f64().unwrap()
            };
            let mut output = None;
            let result = match hook {
                "request" => {
                    let flow = &flows[flow_name];
                    owner
                        .request(flow["host"].as_str().unwrap(), clock)
                        .map(|start| {
                            flows.get_mut(flow_name).unwrap()["metadata"]["metrics_start_time"] =
                                json!(start);
                        })
                }
                "response" => {
                    let flow = &flows[flow_name];
                    let blocked = flow["metadata"].get("blocked_by").cloned().map(C::from);
                    owner.response(
                        flow["host"].as_str().unwrap(),
                        flow["metadata"]["metrics_start_time"].as_f64(),
                        blocked.as_ref(),
                        flow["status"].as_u64().map(|status| status as u16),
                        clock,
                    )
                }
                "seed_report" => {
                    seed(&owner, step);
                    Ok(())
                }
                "get_stats" => owner
                    .get_stats()
                    .map(|value| output = Some(encoded(&value))),
                "get_json" => owner
                    .get_json(clock)
                    .map(|value| output = Some(encoded(&value))),
                "get_prometheus" => owner
                    .get_prometheus(clock)
                    .map(|value| output = Some(value)),
                other => panic!("unexpected hook {other}"),
            };
            assert!(result.is_ok(), "{name}/{index} {result:?}");
            assert!(expected["error_class"].is_null());
            assert_eq!(
                output.as_deref(),
                expected["result_text"].as_str(),
                "{name}/{index} report"
            );
            assert_eq!(
                exact(&json!(*observations.borrow())),
                exact(&expected["clock_observations"]),
                "{name}/{index} clock order"
            );
            assert_eq!(
                exact(&snapshot(&owner)),
                exact(&expected["state_after"]),
                "{name}/{index} state"
            );
            assert_eq!(
                exact(&Value::Object(flows.clone())),
                exact(&expected["flows_after"]),
                "{name}/{index} flow"
            );
        }
    }
}
