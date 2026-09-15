use super::*;
use crate::policy::Format;

fn fixture() -> Value {
    crate::policy::parse_json(
        include_str!("../../tests/test_context_typed_targets_source.json"),
        false,
    )
    .unwrap()
}
fn format(row: &Value) -> Format {
    match row["format"].as_str().unwrap() {
        "yaml" => Format::Yaml,
        "toml" => Format::Toml,
        "json" => Format::Json,
        _ => unreachable!(),
    }
}
fn error_class(error: ContextError) -> Value {
    json!(match error.kind() {
        ContextErrorKind::Type => "TypeError",
        ContextErrorKind::Attribute => "AttributeError",
        _ => panic!("unexpected target error category"),
    })
}
fn observe(row: &Value) -> Vec<Value> {
    let owner = TestContext::default();
    let mut policy = Policy::parse_at(row["source"].as_str().unwrap(), format(row), 0.).unwrap();
    if let Some(task) = row["task"].as_str() {
        policy = policy.with_task_source(task, Format::Json).unwrap();
    }
    row["steps"].as_array().unwrap().iter().map(|step| {
        if let Some(source) = step["source"].as_str() {
            policy = policy.reload_from_source_at(source, format(row), 0.).unwrap();
        }
        let before = (policy.engine_stats().unwrap(), policy.budget_stats(0.).unwrap(), policy.policy_hash());
        let mut headers = step["header"].as_str().map(|value| vec![(HEADER.to_owned(), value.as_bytes().to_vec())]).unwrap_or_default();
        let result = owner.request_current(
            step["available"].as_bool().unwrap_or(true).then_some(&policy),
            Request { host: step["host"].as_str().unwrap(), prior_response: step["prior"].as_bool().unwrap(), identity: None, metadata_agent: None },
            &mut headers, 0.,
        );
        let status = match &result { Ok(RequestOutcome::PriorResponse) => 200, Ok(RequestOutcome::Block { status, .. }) => *status, _ => 0 };
        let mut out = json!({"error":result.err().map(error_class),"status":status,"header_retained":headers.iter().any(|(name,_)|name.eq_ignore_ascii_case(HEADER)),"stats":null,"stats_error":null});
        match owner.stats(0.) { Ok(stats) => out["stats"] = json!(stats), Err(error) => out["stats_error"] = error_class(error) }
        let state = owner.lock().unwrap();
        out["hash"] = state.config.last_hash.clone();
        out["counts"] = json!({"checks":state.stats.checks_total,"allowed":state.stats.allowed_total,"blocked":state.stats.blocked_total,"warned":state.stats.warned_total});
        assert_eq!(before, (policy.engine_stats().unwrap(),policy.budget_stats(0.).unwrap(),policy.policy_hash()), "target projection must not evaluate or mutate policy");
        out
    }).collect()
}
#[test]
fn successfully_loaded_temporal_targets_match_source_order_and_partial_effects() {
    let fixture = fixture();
    let mut count = 0;
    let mut traces = 0;
    for row in fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["native_gap"].is_null())
    {
        traces += 1;
        let actual = observe(row);
        count += actual.len();
        assert_eq!(json!(actual), row["observations"], "{}", row["case"]);
    }
    let admitted = fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["native_gap"].is_null());
    assert_eq!(
        count,
        admitted
            .map(|row| row["steps"].as_array().unwrap().len())
            .sum::<usize>()
    );
    eprintln!(
        "Compared {traces} loaded-source traces / {count} operations (frontend gap rows excluded)"
    );
}
#[test]
fn current_target_refresh_preserves_declarations_and_legacy_refresh_clears_annotations() {
    let owner = TestContext::default();
    let initial = json!({"policy_hash":"held","addons":{"test_context":{"target_hosts":["held.invalid"],"declared_ttl_max":20,"inject_declared":false}}});
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
    let policy = Policy::parse_at("addons:\n  test_context:\n    target_hosts: 2030-01-02\n    declared_ttl_max: 1\n    inject_declared: true\n", Format::Yaml, 0.).unwrap();
    let mut headers = vec![(HEADER.to_owned(), b"run=r;agent=a".to_vec())];
    let request = || Request {
        host: "target.invalid",
        prior_response: false,
        identity: None,
        metadata_agent: None,
    };
    let error = owner
        .request_current(Some(&policy), request(), &mut headers, 0.)
        .unwrap_err();
    assert_eq!(error.kind(), ContextErrorKind::Type);
    assert_eq!(error.0, "target_hosts has no length");
    {
        let state = owner.lock().unwrap();
        assert_eq!(state.config.last_hash, policy.policy_hash());
        assert_eq!(state.config.ttl_max, Number::from(20));
        assert!(!state.config.inject);
        assert_eq!(state.declarations["owned-source"].expires_at, 20.);
        assert!(state.config.target_timestamps.value_at(&[]).is_some());
    }
    let error = owner
        .request_current(Some(&policy), request(), &mut headers, 0.)
        .unwrap_err();
    assert_eq!(error.0, "target_hosts is not iterable");
    owner.configure(Some(&initial), Options::default()).unwrap();
    assert!(
        owner
            .lock()
            .unwrap()
            .config
            .target_timestamps
            .value_at(&[])
            .is_none()
    );
    assert!(matches!(
        owner.request(request(), &mut headers, 0.).unwrap(),
        RequestOutcome::Applied { .. }
    ));
    assert_eq!(
        owner
            .get_declaration(&identity, 5.)
            .unwrap()
            .unwrap()
            .expires_in,
        Number::from(15)
    );
}
#[test]
fn unchanged_hash_skips_target_replacement_and_prior_response_skips_projection() {
    let policy = Policy::parse_at(
        "addons:\n  test_context:\n    target_hosts: 2030-01-02\n",
        Format::Yaml,
        0.,
    )
    .unwrap();
    let owner = TestContext::default();
    owner.configure(Some(&json!({"policy_hash":policy.policy_hash(),"addons":{"test_context":{"target_hosts":["target.invalid"]}}})), Options::default()).unwrap();
    let mut headers = Vec::new();
    let request = || Request {
        host: "target.invalid",
        prior_response: false,
        identity: None,
        metadata_agent: None,
    };
    assert!(matches!(
        owner
            .request_current(Some(&policy), request(), &mut headers, 0.)
            .unwrap(),
        RequestOutcome::Block { status: 428, .. }
    ));
    let other = Policy::parse_at("{}", Format::Json, 0.).unwrap();
    assert!(matches!(
        owner
            .request_current(
                Some(&other),
                Request {
                    prior_response: true,
                    ..request()
                },
                &mut headers,
                f64::NAN
            )
            .unwrap(),
        RequestOutcome::PriorResponse
    ));
    assert_eq!(owner.lock().unwrap().config.last_hash, policy.policy_hash());
}
#[test]
#[ignore = "Actual Python loaded TestContext targets; set SAFEYOLO_POLICY_PYTHON"]
fn live_python_typed_target_oracle() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let fixture = fixture();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child =
        Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("source Python path"))
            .arg(root.join("proxy/tests/test_context_typed_targets_oracle.py"))
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
    for row in actual["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["native_gap"].is_null())
    {
        assert_eq!(json!(observe(row)), row["observations"], "{}", row["case"]);
    }
}

#[test]
fn source_accepted_nonstring_keys_remain_explicit_frontend_gaps() {
    let fixture = fixture();
    for row in fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| !row["native_gap"].is_null())
    {
        assert!(Policy::parse_at(row["source"].as_str().unwrap(), format(row), 0.).is_err());
        // Actual source retains the valid prefix and only fails when it reaches
        // the later nonstring key. These are not native parity passing rows.
        assert_eq!(row["observations"][0]["status"], 428);
        assert_eq!(row["observations"][1]["error"], "AttributeError");
    }
}
