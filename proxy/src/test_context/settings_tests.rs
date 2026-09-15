use super::*;
use crate::policy::{Format, Policy};

fn fixture() -> Value {
    crate::policy::parse_json(
        include_str!("../../tests/test_context_settings_source.json"),
        false,
    )
    .unwrap()
}
fn options() -> Options {
    Options {
        block: false,
        inject_declared: true,
        declared_ttl: json!(11),
    }
}
fn apply_case(row: &Value) {
    let format = match row["format"].as_str().unwrap() {
        "yaml" => Format::Yaml,
        "toml" => Format::Toml,
        "json" => Format::Json,
        _ => unreachable!(),
    };
    let policy = row["source"]
        .as_str()
        .map_or_else(Policy::unconfigured, |source| {
            Policy::parse_at(source, format, 0.).unwrap()
        });
    let policy = row["task"].as_str().map_or_else(
        || policy.clone(),
        |task| policy.with_task_source(task, Format::Json).unwrap(),
    );
    let owner = TestContext::default();
    owner.configure(Some(&json!({"policy_hash":"held","addons":{"test_context":{"target_hosts":["held.invalid"]}}})),Options::default()).unwrap();
    let identity = TrustedIdentity::new("slot", "alice").unwrap();
    owner
        .set_declaration(
            &identity,
            Context::parse("run=r;agent=a").unwrap(),
            Some(&json!(7)),
            0.,
        )
        .unwrap();
    let before = (
        policy.policy_hash(),
        policy.engine_stats().unwrap(),
        policy.budget_stats(0.).unwrap(),
    );
    policy
        .configure_test_context_declarations(&owner, options())
        .unwrap();
    assert_eq!(
        before,
        (
            policy.policy_hash(),
            policy.engine_stats().unwrap(),
            policy.budget_stats(0.).unwrap()
        )
    );
    assert_eq!(policy.sensor_config().is_ok(), row["sensor_json_ok"]);
    let state = owner.lock().unwrap();
    assert_eq!(
        json!({"ttl":state.config.ttl_max,"inject":state.config.inject}),
        row["settings"],
        "{}",
        row["case"]
    );
    assert_eq!(state.config.targets, json!(["held.invalid"]));
    assert_eq!(state.config.last_hash, "held");
    assert_eq!(state.declarations["slot"].expires_at, 7.);
    assert!(!state.config.options.block);
}

#[test]
fn borrowed_canonical_settings_match_source_without_serialization() {
    let fixture = fixture();
    let rows = fixture["rows"].as_array().unwrap();
    for row in rows {
        apply_case(row);
    }
    assert_eq!(rows.len(), fixture["case_count"]);
}

#[test]
fn declaration_reload_changes_defaults_without_mutating_target_or_old_expiry() {
    let initial = Policy::parse_at(
        r#"{"addons":{"test_context":{"declared_ttl_max":11}}}"#,
        Format::Json,
        0.,
    )
    .unwrap();
    let owner = TestContext::default();
    let identity = TrustedIdentity::new("slot", "alice").unwrap();
    initial
        .configure_test_context_declarations(&owner, Options::default())
        .unwrap();
    owner
        .set_declaration(
            &identity,
            Context::parse("run=r;agent=a").unwrap(),
            None,
            0.,
        )
        .unwrap();
    let changed=initial.reload_from_source_at("addons:\n  test_context:\n    declared_ttl_max: 3\n    target_hosts: [2030-01-02]\n  other:\n    settings: {date: 2030-01-02}\n",Format::Yaml,0.).unwrap();
    changed
        .configure_test_context_declarations(&owner, Options::default())
        .unwrap();
    assert_eq!(
        owner
            .get_declaration(&identity, 0.)
            .unwrap()
            .unwrap()
            .expires_in,
        Number::from(11)
    );
    assert_eq!(owner.lock().unwrap().config.targets, json!([]));
    assert_eq!(owner.lock().unwrap().config.last_hash, "");
    assert!(
        changed
            .reload_from_source_at(r#"{"permissions":false}"#, Format::Json, 0.)
            .is_err()
    );
    assert_eq!(
        owner
            .set_declaration(
                &identity,
                Context::parse("run=new;agent=a").unwrap(),
                None,
                0.
            )
            .unwrap(),
        Number::from(3)
    );
}

#[test]
fn preflight_returns_existing_guards_in_order_without_touching_store() {
    let owner = TestContext::default();
    let identity = TrustedIdentity::new("slot", "alice").unwrap();
    owner
        .set_declaration(
            &identity,
            Context::parse("run=r;agent=a").unwrap(),
            Some(&json!(1)),
            0.,
        )
        .unwrap();
    for agent in [
        None,
        Some(""),
        Some("unknown"),
        Some("default"),
        Some("alice"),
    ] {
        for source in [
            None,
            Some(""),
            Some("unknown"),
            Some("default"),
            Some("slot"),
        ] {
            for available in [false, true] {
                let owner_ref = available.then_some(&owner);
                let outcome = api_current_preflight(owner_ref, source, agent);
                if let Some(expected) = outcome {
                    assert!(expected.audit.is_none());
                    assert_eq!(
                        api_current_typed(owner_ref, source, agent, "POST", None, 100.).unwrap(),
                        expected
                    );
                } else {
                    assert!(
                        available
                            && agent == Some("alice")
                            && matches!(source, Some("default" | "slot"))
                    );
                }
            }
        }
    }
    assert_eq!(owner.lock().unwrap().declarations["slot"].expires_at, 1.);
    let other = owner.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = other.state.lock().unwrap();
            panic!("owned preflight lock fixture");
        })
        .join()
        .is_err()
    );
    assert!(api_current_preflight(Some(&owner), Some("slot"), Some("alice")).is_none());
}

#[test]
#[ignore = "Actual LocalPolicyClient declaration options; set SAFEYOLO_POLICY_PYTHON"]
fn live_python_settings_oracle() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let fixture = fixture();
    let mut child =
        Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("source Python path"))
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/test_context_settings_oracle.py"),
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
        "source settings oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual =
        crate::policy::parse_json(std::str::from_utf8(&output.stdout).unwrap(), false).unwrap();
    assert_eq!(actual, fixture);
    for row in actual["rows"].as_array().unwrap() {
        apply_case(row);
    }
}
