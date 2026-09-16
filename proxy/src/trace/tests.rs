use super::*;

fn step(ts: f64) -> Step {
    Step::new("network-guard", "request", "evaluated", ts)
}

#[test]
fn environment_defaults_and_python_integer_forms_do_not_add_clamps() {
    let settings = Settings::from_environment_values(None, None, None, None, None);
    assert_eq!(settings.ttl_s, 300);
    assert_eq!(settings.global_max, 1000.into());
    assert_eq!(settings.per_agent_max, 200.into());
    assert_eq!(settings.steps_max, 128.into());
    assert_eq!(settings.details_max_bytes, 4096.into());
    let oversized = "1".repeat(4301);
    let settings = Settings::from_environment_values(
        Some("\u{2003}+1_2\u{2003}"),
        Some("-2"),
        Some("٣"),
        Some("1.5"),
        Some(&oversized),
    );
    assert_eq!(settings.ttl_s, 12);
    assert_eq!(settings.global_max, (-2).into());
    assert_eq!(settings.per_agent_max, 3.into());
    assert_eq!(settings.steps_max, 128.into());
    assert_eq!(settings.details_max_bytes, 4096.into());
    let huge = "1".to_owned() + &"0".repeat(400);
    let store = TraceStore::new(Settings::from_environment_values(
        Some(&huge),
        None,
        None,
        None,
        None,
    ));
    assert_eq!(
        store
            .append("r", Some("alice"), step(1.0), 1.0)
            .unwrap_err()
            .kind(),
        ErrorKind::Overflow
    );
    assert!(store.state.lock().unwrap().records.is_empty());
}

#[test]
fn malformed_details_and_unrepresentable_snapshot_fail_without_losing_record() {
    let store = TraceStore::new(Settings::default());
    let mut wrong = step(1.0);
    wrong.details = Some(C::Array(vec![1.into()]));
    store.append("wrong", Some("alice"), wrong, 1.0).unwrap();
    assert_eq!(
        store.get("wrong", Some("alice"), 1.0).unwrap_err().kind(),
        ErrorKind::Attribute
    );
    assert!(store.state.lock().unwrap().records.contains_key("wrong"));
    store
        .append("nonfinite", Some("alice"), step(1.0), f64::NAN)
        .unwrap();
    assert_eq!(
        store
            .get("nonfinite", Some("alice"), 1.0)
            .unwrap_err()
            .kind(),
        ErrorKind::Compatibility
    );
    assert!(store.get("nonfinite", Some("bob"), 1.0).unwrap().is_none());
    assert_eq!(
        Error(ErrorKind::Attribute).to_string(),
        "trace store operation failed"
    );
}

#[test]
fn details_keep_scalar_kinds_and_source_dumps_failure_truncates_only_report() {
    let store = TraceStore::new(Settings {
        details_max_bytes: 10000.into(),
        ..Settings::default()
    });
    let mut floats = step(1.0);
    floats.details = Some(C::Object(IndexMap::from([
        ("not_finite".into(), C::Float(f64::NAN)),
        ("negative_zero".into(), C::Float(-0.0)),
        ("integer".into(), BigInt::from(10).pow(100).into()),
        ("empty".into(), Value::Null.into()),
    ])));
    store.append("scalars", Some("alice"), floats, 1.0).unwrap();
    let report = store.get("scalars", Some("alice"), 1.0).unwrap().unwrap();
    assert_eq!(report["steps"][0]["details"]["not_finite"], "<float>");
    assert_eq!(report["steps"][0]["details"]["negative_zero"], "<float>");
    assert_eq!(
        report["steps"][0]["details"]["integer"].to_string(),
        "1".to_owned() + &"0".repeat(100)
    );
    let mut giant = step(2.0);
    giant.details = Some(C::Object(IndexMap::from([(
        "too_many_digits".into(),
        BigInt::from(10).pow(4300).into(),
    )])));
    store.append("giant", Some("alice"), giant, 2.0).unwrap();
    assert_eq!(
        store.get("giant", Some("alice"), 2.0).unwrap().unwrap()["steps"][0]["details"],
        json!({"_truncated":true})
    );
    let state = store.state.lock().unwrap();
    assert!(matches!(
        state.records["giant"].steps[0]
            .details
            .as_ref()
            .unwrap()
            .as_object()
            .unwrap()["too_many_digits"],
        C::Integer(_)
    ));
}

#[test]
fn returned_report_is_owned_and_poison_is_categorical() {
    let store = TraceStore::new(Settings::default());
    store.append("r", Some("alice"), step(1.0), 1.0).unwrap();
    let mut report = store.get("r", Some("alice"), 1.0).unwrap().unwrap();
    report["steps"][0]["addon"] = json!("caller-changed");
    assert_eq!(
        store.get("r", Some("alice"), 1.0).unwrap().unwrap()["steps"][0]["addon"],
        "network-guard"
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = store.state.lock().unwrap();
        panic!("owned trace mutex poison");
    }));
    assert!(result.is_err());
    assert_eq!(
        store
            .append("later", Some("alice"), step(1.0), 1.0)
            .unwrap_err()
            .kind(),
        ErrorKind::Poisoned
    );
    assert_eq!(
        store.get("r", Some("alice"), 1.0).unwrap_err().kind(),
        ErrorKind::Poisoned
    );
}

fn state(store: &TraceStore) -> Value {
    let state = store.state.lock().unwrap();
    let records: Vec<_> = state
        .records
        .iter()
        .map(|(id, record)| {
            let steps: Vec<_> = record
                .steps
                .iter()
                .map(|step| {
                    json!({"addon":step.addon,"hook":step.hook,"state":step.state,
                "outcome":step.outcome,"reason":step.reason,
                "duration_us":step.duration_us.as_ref().map(integer_json),
                "details":step.details.as_ref().map(|details| details.json().unwrap()),
                "ts":step.ts,"connection_id":step.connection_id,"method":step.method,
                "host":step.host,"port":step.port.as_ref().map(integer_json)})
                })
                .collect();
            json!({"request_id":id,"agent_id":record.agent_id,"created_at":record.created_at,
            "steps":steps,"truncated":record.truncated})
        })
        .collect();
    let agents: Vec<_> = state
        .by_agent
        .iter()
        .map(|(agent, ids)| json!([agent, ids]))
        .collect();
    json!({"records":records,"by_agent":agents})
}

fn settings(value: &Value) -> Settings {
    let mut settings = Settings::default();
    if let Some(ttl) = value.get("ttl_s") {
        settings.ttl_s = ttl.clone().into();
    }
    for (key, target) in [
        ("global_max", &mut settings.global_max),
        ("per_agent_max", &mut settings.per_agent_max),
        ("steps_max", &mut settings.steps_max),
        ("details_max_bytes", &mut settings.details_max_bytes),
    ] {
        if let Some(value) = value.get(key) {
            *target = value.to_string().parse().unwrap();
        }
    }
    settings
}

fn fixture_step(value: &Value, now: f64) -> Step {
    let mut step = Step::new(
        value["addon"].as_str().unwrap(),
        value["hook"].as_str().unwrap(),
        value["state"].as_str().unwrap(),
        value["ts"].as_f64().unwrap_or(now),
    );
    for (key, target) in [
        ("outcome", &mut step.outcome),
        ("reason", &mut step.reason),
        ("connection_id", &mut step.connection_id),
        ("method", &mut step.method),
        ("host", &mut step.host),
    ] {
        *target = value[key].as_str().map(str::to_owned);
    }
    step.duration_us = value
        .get("duration_us")
        .filter(|value| !value.is_null())
        .map(|value| value.to_string().parse().unwrap());
    step.port = value
        .get("port")
        .filter(|value| !value.is_null())
        .map(|value| value.to_string().parse().unwrap());
    step.details = value
        .get("details")
        .filter(|value| !value.is_null())
        .cloned()
        .map(C::from);
    step
}

fn error_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Index => "IndexError",
        ErrorKind::StopIteration => "StopIteration",
        ErrorKind::Type => "TypeError",
        ErrorKind::Attribute => "AttributeError",
        ErrorKind::Overflow => "OverflowError",
        ErrorKind::Poisoned => "NativePoisoned",
        ErrorKind::Compatibility => "NativeCompatibility",
    }
}

#[test]
fn actual_source_store_workflows_preserve_order_reports_and_partial_errors() {
    #[derive(serde::Deserialize)]
    struct Source {
        rows: Vec<Row>,
    }
    #[derive(serde::Deserialize)]
    struct Row {
        input: Value,
        // API-only source outcomes contain Python surrogateescaped strings.
        // Keep those excluded rows opaque rather than changing the fixture.
        steps: Box<serde_json::value::RawValue>,
    }
    let source: Source =
        serde_json::from_str(include_str!("../../tests/trace_source.json")).unwrap();
    let mut replayed = 0;
    for row in source.rows {
        let input = &row.input;
        let operations = input["steps"].as_array().unwrap();
        if operations
            .iter()
            .any(|op| !matches!(op["op"].as_str(), Some("append" | "get")))
        {
            continue;
        }
        let name = input["name"].as_str().unwrap();
        let store = TraceStore::new(settings(&input["settings"]));
        let outcomes: Vec<Value> = serde_json::from_str(row.steps.get()).unwrap();
        replayed += 1;
        for (index, operation) in operations.iter().enumerate() {
            let expected = &outcomes[index];
            let now = operation["now"].as_f64().unwrap();
            let rid = operation["rid"]
                .as_str()
                .unwrap_or("req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let agent = operation.get("agent").map_or(Some("alice"), Value::as_str);
            let result = if operation["op"] == "append" {
                store
                    .append(rid, agent, fixture_step(&operation["step"], now), now)
                    .map(|_| None)
            } else {
                store.get(rid, agent, now)
            };
            let expected_error = expected["error_class"]
                .as_str()
                .or_else(|| expected["serialise_error"].as_str());
            match result {
                Err(error) => assert_eq!(
                    Some(error_name(error.kind())),
                    expected_error,
                    "{name}/{index}"
                ),
                Ok(report) => {
                    assert!(expected_error.is_none(), "{name}/{index}");
                    if operation["op"] == "get" {
                        assert_eq!(
                            report.is_some(),
                            expected["found"].as_bool().unwrap(),
                            "{name}/{index}"
                        );
                        if let Some(report) = report {
                            assert_eq!(
                                crate::python_json::encode(&report),
                                expected["report_json"].as_str().unwrap(),
                                "{name}/{index}"
                            );
                        }
                    }
                }
            }
            assert_eq!(
                crate::python_json::encode(&state(&store)),
                crate::python_json::encode(&expected["state"]),
                "{name}/{index} state"
            );
        }
    }
    assert_eq!(replayed, 15, "source core workflow selection changed");
}
