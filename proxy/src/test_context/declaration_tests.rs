use super::*;
use crate::circuits::CircuitValue;

fn fixture() -> Value {
    crate::policy::parse_json(
        include_str!("../../tests/test_context_declaration_source.json"),
        false,
    )
    .unwrap()
}
fn error_class(error: ContextError) -> &'static str {
    match error.kind() {
        ContextErrorKind::Value => "ValueError",
        ContextErrorKind::Overflow => "OverflowError",
        ContextErrorKind::Poisoned => "Poisoned",
    }
}
fn observe(row: &Value) -> Vec<Value> {
    let owner = TestContext::default();
    let identity = TrustedIdentity::new("owned-source", "alice").unwrap();
    owner
        .set_declaration(
            &identity,
            Context::parse("run=prior;agent=alice").unwrap(),
            Some(&json!(7)),
            0.,
        )
        .unwrap();
    row["actions"].as_array().unwrap().iter().map(|spec| {
        let now = spec["now"].as_str().unwrap().parse::<f64>().unwrap();
        let config = json!({"addons":{"test_context":{"declared_ttl_max":spec["limit"]}}});
        owner.configure_declarations(Some(&config), Options::default()).unwrap();
        let body = spec["body"].as_str().map(|body| CircuitValue::parse_json(body).unwrap());
        let mut result = json!({"error":null,"audit":null});
        let outcome = if spec["method"] == "stats" {
            owner.stats(now).map(|stats| result["stats"] = json!(stats))
        } else {
            api_current_typed(Some(&owner), Some("owned-source"), Some("alice"), spec["method"].as_str().unwrap(), body.as_ref(), now)
                .map(|outcome| {
                    result["status"] = json!(outcome.status);
                    result["body"] = outcome.body;
                    result["audit"] = json!(outcome.audit);
                })
        };
        if let Err(error) = outcome { result["error"] = json!(error_class(error)); }
        result["record"] = owner.lock().unwrap().declarations.get("owned-source").map_or(Value::Null, |record| {
            json!({"agent":record.agent,"context":record.context,"expiry_bits":format!("{:016x}",record.expires_at.to_bits())})
        });
        result
    }).collect()
}

#[test]
fn typed_api_and_clock_effects_match_actual_source() {
    let fixture = fixture();
    let rows = fixture["rows"].as_array().unwrap();
    let mut count = 0;
    for row in rows {
        let actual = observe(row);
        count += actual.len();
        assert_eq!(json!(actual), row["observations"], "{}", row["case"]);
    }
    assert_eq!(rows.len(), fixture["trace_count"]);
    assert_eq!(count, fixture["operation_count"]);
    eprintln!(
        "Compared {} source declaration traces / {count} operations",
        rows.len()
    );
}

#[test]
fn ordinary_value_and_typed_facades_share_outcomes_and_identity_order() {
    let cases = [
        json!({"context":"run=r;agent=a","ttl":2}),
        json!({"context":"broken","ttl":false}),
        json!({"context":false,"ttl":0}),
        json!({"context":"run=r;agent=a","ttl":1.0}),
        json!({"context":"run=r;agent=a","unused":{"nested":[false,null]}}),
        Value::Null,
        json!([]),
    ];
    for body in cases {
        let typed = CircuitValue::from(body.clone());
        for (source, agent, method, available) in [
            (Some("slot"), Some("alice"), "POST", true),
            (None, Some("alice"), "POST", true),
            (Some("slot"), None, "POST", true),
            (Some("slot"), Some("alice"), "POST", false),
            (Some("slot"), Some("alice"), "GET", true),
            (Some("slot"), Some("alice"), "DELETE", true),
            (Some("slot"), Some("alice"), "PATCH", true),
        ] {
            let left = TestContext::default();
            let right = TestContext::default();
            assert_eq!(
                api_current(
                    available.then_some(&left),
                    source,
                    agent,
                    method,
                    Some(&body),
                    0.
                )
                .unwrap(),
                api_current_typed(
                    available.then_some(&right),
                    source,
                    agent,
                    method,
                    Some(&typed),
                    0.
                )
                .unwrap()
            );
        }
    }
}

#[test]
fn poisoned_store_propagates_categorical_failure_without_success_audit() {
    let owner = TestContext::default();
    let other = owner.clone();
    assert!(
        std::thread::spawn(move || {
            let _lock = other.state.lock().unwrap();
            panic!("owned poison fixture");
        })
        .join()
        .is_err()
    );
    let body = CircuitValue::parse_json(r#"{"context":"run=r;agent=a"}"#).unwrap();
    let error = api_current_typed(
        Some(&owner),
        Some("slot"),
        Some("alice"),
        "POST",
        Some(&body),
        0.,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ContextErrorKind::Poisoned);
    assert_eq!(error.to_string(), "test-context state lock poisoned");
    // Earlier context/TTL validation remains authoritative even if the store is poisoned.
    let invalid = CircuitValue::parse_json(r#"{"context":null,"ttl":NaN}"#).unwrap();
    assert_eq!(
        api_current_typed(
            Some(&owner),
            Some("slot"),
            Some("alice"),
            "POST",
            Some(&invalid),
            0.
        )
        .unwrap()
        .status,
        400
    );
}

#[test]
#[ignore = "Actual Python inner declaration handler and clock oracle; set SAFEYOLO_POLICY_PYTHON"]
fn live_python_declaration_clock_oracle() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let fixture = fixture();
    let mut child =
        Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("source Python path"))
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/test_context_declaration_oracle.py"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&fixture["rows"]).unwrap())
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
