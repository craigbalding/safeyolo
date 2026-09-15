use super::*;

fn fixture() -> Value {
    crate::policy::parse_json(
        include_str!("../../tests/test_context_targets_source.json"),
        false,
    )
    .unwrap()
}

// Error class is observed at the actual source operation. Rust keeps the
// existing content-free ContextError surface, without pretending to execute a
// Python exception hook or deciding transport's error response.
fn source_error(error: ContextError) -> Value {
    json!(match error.0.as_str() {
        "target_hosts has no length" | "target_hosts is not iterable" => "TypeError",
        "target pattern has no string lower method" => "AttributeError",
        _ => panic!("unexpected categorical target error"),
    })
}

fn observe(row: &Value) -> Vec<Value> {
    let owner = TestContext::default();
    let mut current: Option<Value> = None;
    row["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            let action = step["action"].as_str().unwrap();
            let now = step["now"].as_f64().unwrap_or(0.);
            let mut result = json!({"action":action,"error":null});
            if matches!(action, "configure" | "declare") {
                current = (!step["sensor"].is_null()).then(|| step["sensor"].clone());
            }
            let outcome = match action {
                "configure" => owner.configure(current.as_ref(), Options::default()),
                "declare" => owner
                    .configure_declarations(current.as_ref(), Options::default())
                    .and_then(|()| {
                        let identity = TrustedIdentity::new("owned-source", "alice").unwrap();
                        owner.set_declaration(
                            &identity,
                            Context::parse("run=r;agent=a").unwrap(),
                            None,
                            0.,
                        )
                    })
                    .map(|ttl| result["ttl"] = json!(ttl)),
                "stats" => owner.stats(now).map(|stats| result["stats"] = json!(stats)),
                "request" => {
                    let prior_response = step["prior"].as_bool().unwrap();
                    let mut headers = step["header"]
                        .as_str()
                        .map(|value| vec![(HEADER.into(), value.as_bytes().to_vec())])
                        .unwrap_or_default();
                    let refreshed = if prior_response {
                        Ok(())
                    } else {
                        owner.configure(current.as_ref(), Options::default())
                    };
                    let outcome = refreshed.and_then(|()| {
                        owner.request(
                            Request {
                                host: step["host"].as_str().unwrap(),
                                prior_response,
                                identity: None,
                                metadata_agent: None,
                            },
                            &mut headers,
                            0.,
                        )
                    });
                    result["status"] = json!(match &outcome {
                        Ok(RequestOutcome::PriorResponse) => 200,
                        Ok(RequestOutcome::Block { status, .. }) => *status,
                        _ => 0,
                    });
                    result["header_retained"] = json!(
                        headers
                            .iter()
                            .any(|(name, _)| name.eq_ignore_ascii_case(HEADER))
                    );
                    outcome.map(|_| ())
                }
                _ => panic!("unknown fixture operation"),
            };
            if let Err(error) = outcome {
                result["error"] = source_error(error);
            }
            let state = owner.lock().unwrap();
            result["declaration_records"] = json!(state.declarations.len());
            result["targets"] = state.config.targets.clone();
            result["hash"] = state.config.last_hash.clone();
            result["counts"] = json!({
                "checks":state.stats.checks_total,"allowed":state.stats.allowed_total,
                "blocked":state.stats.blocked_total,"warned":state.stats.warned_total
            });
            result
        })
        .collect()
}

#[test]
fn target_configuration_and_request_effects_match_source_traces() {
    let fixture = fixture();
    let rows = fixture["rows"].as_array().unwrap();
    let mut operations = 0;
    for row in rows {
        let observations = observe(row);
        operations += observations.len();
        assert_eq!(json!(observations), row["observations"], "{}", row["case"]);
    }
    assert_eq!(rows.len(), fixture["trace_count"]);
    assert_eq!(operations, fixture["operation_count"]);
    eprintln!(
        "Compared {} source traces / {operations} operations",
        rows.len()
    );
}

#[test]
fn declaration_refresh_preserves_targets_hash_and_existing_expiry() {
    let owner = TestContext::default();
    let initial = json!({"policy_hash":"old","addons":{"test_context":{
        "target_hosts":["target.invalid"],"declared_ttl_max":20
    }}});
    owner.configure(Some(&initial), Options::default()).unwrap();
    let identity = TrustedIdentity::new("owned-source", "alice").unwrap();
    owner
        .set_declaration(
            &identity,
            Context::parse("run=r;agent=a").unwrap(),
            None,
            0.,
        )
        .unwrap();
    let changed = json!({"policy_hash":"new","addons":{"test_context":{
        "target_hosts":true,"declared_ttl_max":2,"inject_declared":true
    }}});
    owner
        .configure_declarations(Some(&changed), Options::default())
        .unwrap();
    let state = owner.lock().unwrap();
    assert_eq!(state.config.last_hash, "old");
    assert_eq!(state.config.targets, json!(["target.invalid"]));
    assert!(state.config.inject);
    assert_eq!(state.config.ttl_max, Number::from(2));
    assert_eq!(state.declarations["owned-source"].expires_at, 20.);
    drop(state);
    assert_eq!(
        owner
            .get_declaration(&identity, 5.)
            .unwrap()
            .unwrap()
            .expires_in,
        Number::from(15)
    );
    // A later request-side reload still reaches and retains the malformed target
    // assignment; declaration-only refresh neither hid nor eagerly reached it.
    assert!(owner.configure(Some(&changed), Options::default()).is_err());
    assert_eq!(owner.lock().unwrap().config.last_hash, "new");
}

#[test]
#[ignore = "Actual Python TestContext target config hooks; set SAFEYOLO_POLICY_PYTHON"]
fn live_python_target_configuration_oracle() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let fixture = fixture();
    let rows = fixture["rows"].as_array().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child =
        Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("source Python path"))
            .arg(root.join("proxy/tests/test_context_targets_oracle.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(rows).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "source oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual =
        crate::policy::parse_json(std::str::from_utf8(&output.stdout).unwrap(), false).unwrap();
    assert_eq!(actual, fixture);
    for row in actual["rows"].as_array().unwrap() {
        assert_eq!(json!(observe(row)), row["observations"], "{}", row["case"]);
    }
}
