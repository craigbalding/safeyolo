use safeyolo_proxy::policy::{
    BudgetStatsError, CredentialRequest, Effect, Format, NetworkRequest, Policy,
};
use serde_json::{Value, json};

const NOW: f64 = 1_000_000.;

fn source() -> Value {
    serde_json::from_str(include_str!("budgets_source.json")).unwrap()
}

fn row(name: &str) -> Value {
    source()["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == name)
        .unwrap()
        .clone()
}

fn permission(effect: &str, budget: Value, condition: Value) -> Value {
    json!({"action":"network:request", "resource":"alpha.invalid/*", "effect":effect,
        "budget":budget, "condition":condition})
}

fn policy(permission: Value, global: Option<u64>) -> Policy {
    let mut document = json!({"permissions":[permission]});
    if let Some(global) = global {
        document["budgets"] = json!({"network:request":global});
    }
    Policy::parse_at(&document.to_string(), Format::Json, NOW).unwrap()
}

fn request(host: &str) -> NetworkRequest<'_> {
    NetworkRequest {
        agent: None,
        host,
        port: None,
        method: "GET",
        path: "/",
    }
}

fn consume(policy: &Policy, host: &str) {
    assert_eq!(
        policy.evaluate(request(host), NOW, true).unwrap().effect,
        Effect::Allow
    );
}

fn assert_source(policy: &Policy, name: &str) {
    let source = row(name);
    let actual = policy.budget_stats(source["now_ms"].as_f64().unwrap());
    if source["error"] == "OverflowError" {
        assert_eq!(actual, Err(BudgetStatsError::Overflow), "{name}");
    } else {
        // Preserve object insertion order as well as arbitrary integer values.
        assert_eq!(
            actual.unwrap().to_string(),
            source["body"].to_string(),
            "{name}"
        );
    }
}

#[test]
fn retained_counter_reports_all_effects_and_exact_large_integer_arithmetic() {
    let initial = policy(permission("budget", json!(20), json!({})), None);
    consume(&initial, "alpha.invalid");
    let before = initial.budget_stats(NOW).unwrap();
    let rows = source();
    for source in &rows["rows"].as_array().unwrap()[..13] {
        let document = json!({"permissions":[source["permission"]]});
        let replacement = initial.reload_from_source_at(&document.to_string(), Format::Json, NOW);
        let name = source["case"].as_str().unwrap();
        if matches!(name, "budget_zero_read" | "budget_negative_read") {
            // Retained admission gap: source permits these Budget-effect rates;
            // native charging still requires positive u64. Do not claim parity.
            assert!(replacement.is_err());
        } else {
            let replacement = replacement.unwrap();
            assert_source(&replacement, name);
            assert_source(&replacement, name);
        }
        assert_eq!(initial.budget_stats(NOW).unwrap(), before);
    }
}

#[test]
fn simple_standins_hide_the_retained_budget_but_wildcards_keep_it() {
    let initial = policy(permission("budget", json!(20), json!({})), None);
    consume(&initial, "alpha.invalid");
    let mut simple = permission("allow", json!(30), Value::Null);
    simple.as_object_mut().unwrap().remove("condition");
    let raw = permission("allow", json!(30), json!({}));
    let mut wildcard = simple.clone();
    wildcard["resource"] = json!("*.invalid/*");
    for (name, document) in [
        (
            "iam_simple_allow_drops_reporting_budget",
            json!({"permissions":[simple]}),
        ),
        (
            "host_raw_simple_extract_drops_reporting_budget",
            json!({"hosts":{"alpha.invalid":{"rules":[raw]}}}),
        ),
        (
            "wildcard_allow_keeps_reporting_budget",
            json!({"permissions":[wildcard]}),
        ),
    ] {
        let replacement = initial
            .reload_from_source_at(&document.to_string(), Format::Json, NOW)
            .unwrap();
        assert_source(&replacement, name);
    }
}

#[test]
fn reporting_uses_no_consuming_agent_path_or_method_context() {
    for (name, condition, agent, path, method) in [
        (
            "agent_scoped_invisible",
            json!({"agent":"alice"}),
            Some("alice"),
            "/",
            "GET",
        ),
        (
            "path_scoped_invisible",
            json!({"path_prefix":"/private"}),
            None,
            "/private/metadata",
            "GET",
        ),
        (
            "post_scoped_invisible",
            json!({"method":"POST"}),
            None,
            "/",
            "POST",
        ),
    ] {
        let policy = policy(permission("budget", json!(20), condition), None);
        assert_eq!(
            policy
                .evaluate(
                    NetworkRequest {
                        agent,
                        path,
                        method,
                        ..request("alpha.invalid")
                    },
                    NOW,
                    true,
                )
                .unwrap()
                .effect,
            Effect::Allow
        );
        assert_source(&policy, name);
    }
}

#[test]
fn file_tasks_change_effective_ceiling_without_changing_authored_global_map() {
    let initial = policy(permission("budget", json!(20), json!({})), Some(100));
    consume(&initial, "alpha.invalid");
    let directory = tempfile::tempdir().unwrap();
    let task = directory.path().join("task.json");
    for (name, rate) in [("task_lower_ceiling", 5), ("task_higher_ceiling", 200)] {
        std::fs::write(
            &task,
            json!({"budgets":{"network:request":rate}}).to_string(),
        )
        .unwrap();
        let current = initial.with_task_path(&task).unwrap();
        assert_source(&current, name);
        std::fs::write(&task, "invalid json").unwrap();
        assert!(current.reload_task().is_err());
        assert_source(&current, name);
    }
}

#[test]
fn host_and_global_share_charge_order_and_one_credential_survives_visibility_reload() {
    let mut network = permission("budget", json!(20), json!({}));
    network["resource"] = json!("*.invalid/*");
    let ordered = policy(network.clone(), Some(100));
    consume(&ordered, "zeta.invalid");
    consume(&ordered, "alpha.invalid");
    assert_source(&ordered, "ordered_new_host_and_global_keys");

    // Create the source credential witness's global/alpha/zeta timestamps via
    // real charges. Exact reset remains outside the native product API.
    let initial = Policy::parse_at(
        r#"{"budgets":{"network:request":100},"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
        Format::Json,
        NOW,
    ).unwrap();
    consume(&initial, "bootstrap.invalid");
    let mut document = json!({"budgets":{"network:request":100},"permissions":[network,
        {"action":"credential:use","resource":"*","effect":"budget","budget":20,
        "condition":{"credential":"fixture:*"}}]});
    let current = initial
        .reload_from_source_at(&document.to_string(), Format::Json, NOW)
        .unwrap();
    consume(&current, "alpha.invalid");
    consume(&current, "zeta.invalid");
    assert_eq!(
        current
            .evaluate_credential(
                CredentialRequest {
                    credential_type: "fixture",
                    destination: "credential.invalid",
                    path: "/",
                    credential_hmac: None
                },
                NOW
            )
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_source(&current, "credential_scoped_key_invisible_and_appended");
    document["permissions"][1]["condition"]["credential"] = json!(":*");
    let visible = current
        .reload_from_source_at(&document.to_string(), Format::Json, NOW)
        .unwrap();
    assert_source(
        &visible,
        "credential_empty_context_match_exposes_retained_key",
    );
    assert_source(&current, "credential_scoped_key_invisible_and_appended");
    let yaml = format!(
        "budgets: {}\npermissions: {}\naddons:\n  synthetic:\n    settings:\n      observed: 2001-02-03\n",
        document["budgets"], document["permissions"]
    );
    let temporal = visible
        .reload_from_source_at(&yaml, Format::Yaml, NOW)
        .unwrap();
    assert_source(
        &temporal,
        "unrelated_temporal_baseline_still_reports_budgets",
    );
    assert!(
        temporal
            .reload_from_source_at("invalid json", Format::Json, NOW)
            .is_err()
    );
    assert_source(
        &temporal,
        "unrelated_temporal_baseline_still_reports_budgets",
    );
}

#[test]
fn read_and_preview_do_not_charge_and_old_snapshots_share_atomic_ordered_state() {
    let mut rule = permission("budget", json!(1_000), json!({}));
    rule["resource"] = json!("*");
    let initial = policy(rule, Some(1_000));
    initial
        .evaluate(request("alpha.invalid"), NOW, false)
        .unwrap();
    assert_eq!(initial.budget_stats(NOW).unwrap()["tracked_keys"], 0);
    let reloaded = initial
        .reload_from_source_at(
            r#"{"budgets":{"network:request":1000},"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1000}]}"#,
            Format::Json,
            NOW,
        )
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let shared = &reloaded;
            scope.spawn(move || {
                for _ in 0..10 {
                    consume(shared, "alpha.invalid");
                }
            });
        }
        for _ in 0..100 {
            let report = initial.budget_stats(NOW).unwrap();
            let visible = report["budgets"].as_object().unwrap();
            assert!(visible.is_empty() || visible.len() == 2);
            if !visible.is_empty() {
                assert_eq!(
                    visible.keys().map(String::as_str).collect::<Vec<_>>(),
                    [
                        "network:request:alpha.invalid",
                        "network:request:__global__"
                    ]
                );
                assert_eq!(
                    visible["network:request:alpha.invalid"]["remaining"],
                    visible["network:request:__global__"]["remaining"]
                );
            }
        }
    });
    let final_report = reloaded.budget_stats(NOW).unwrap();
    assert_eq!(final_report, initial.budget_stats(NOW).unwrap());
    assert_eq!(
        final_report["budgets"]["network:request:alpha.invalid"]["remaining"],
        60
    );
}

#[test]
fn unconfigured_clock_and_current_core_created_invalid_destination() {
    assert_eq!(
        Policy::unconfigured()
            .budget_stats(NOW)
            .unwrap()
            .to_string(),
        r#"{"tracked_keys":0,"budgets":{},"global_budgets":{}}"#
    );
    assert_eq!(
        Policy::unconfigured().budget_stats(f64::NAN),
        Err(BudgetStatsError::InvalidClock)
    );
    let policy = Policy::parse(
        r#"{"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":20}]}"#,
        Format::Json,
    )
    .unwrap();
    // This public core input is accepted by the source engine too. It is not
    // evidence that the HTTP authority parser admits this malformed endpoint.
    consume(&policy, "bad:port");
    assert_eq!(policy.budget_stats(NOW), Err(BudgetStatsError::InvalidKey));
}

#[test]
#[ignore = "actual Python oracle; set SAFEYOLO_POLICY_PYTHON to the existing environment"]
fn source_engine_matches_numeric_conversion_and_destination_rematching() {
    use num_bigint::BigInt;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let mut cases = Vec::new();
    let initial = json!({"permissions":[{"action":"network:request","resource":"*",
        "effect":"budget","budget":20}]});
    for bits in [0_usize, 1, 5, 52, 53, 54, 63, 64, 1022, 1023, 1024, 1330] {
        for offset in [-1_i64, 0, 1, 7] {
            for sign in [-1_i64, 1] {
                let rate = ((BigInt::from(1) << bits) + offset) * sign;
                let rate: Value = serde_json::from_str(&rate.to_string()).unwrap();
                for now_ms in [NOW, NOW + 500., 1_600_000.] {
                    cases.push(json!({"name":format!("rate-{bits}-{offset}-{sign}-{now_ms}"),
                        "host":"alpha.invalid","method":"GET","port":null,"now_ms":now_ms,
                        "initial":initial,"reporting":{"permissions":[permission("allow",rate.clone(),json!({}))]}}));
                }
            }
        }
    }
    for (host, resource, port, method) in [
        ("alpha.invalid", "alpha.invalid/*", Some(8443), "GET"),
        ("alpha.invalid", "alpha.invalid/*", Some(8443), "CONNECT"),
        ("2001:db8::1", "2001:db8::1/*", Some(8443), "CONNECT"),
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1/*", None, "GET"),
        ("FE80:0:0:0:0:0:0:1%eth0", "fe80::1%eth0/*", None, "GET"),
        (
            "FE80:0:0:0:0:0:0:1%eth0",
            "fe80::1%eth0/*",
            Some(8443),
            "CONNECT",
        ),
        ("::ffff:192.0.2.1", "::ffff:c000:201/*", None, "GET"),
        ("::ffff:192.0.2.1", "::ffff:c000:201/*", Some(8443), "GET"),
        ("bad:port", "*", None, "GET"),
    ] {
        let mut initial = initial.clone();
        let mut reporting = permission("allow", json!(30), json!({"method":method}));
        reporting["resource"] = json!(resource);
        if let Some(port) = port {
            initial["permissions"][0]["condition"] = json!({"port":port});
            reporting["condition"]["port"] = json!(port);
        }
        cases.push(
            json!({"name":format!("destination-{host}-{port:?}-{method}"),
            "initial":initial,"reporting":{"permissions":[reporting]},
            "host":host,"port":port,"method":method,"now_ms":NOW}),
        );
    }
    for (configured, host, port) in [
        ("2001:0DB8:0:0:0:0:0:1", "2001:0DB8:0:0:0:0:0:1", None),
        ("[2001:0DB8:0:0:0:0:0:1]:8443", "2001:db8::1", Some(8443)),
        ("FE80:0:0:0:0:0:0:1%eth0", "FE80:0:0:0:0:0:0:1%eth0", None),
        ("[FE80:0:0:0:0:0:0:1%eth0]:8443", "fe80::1%eth0", Some(8443)),
        ("::FFFF:C000:201", "::FFFF:C000:201", None),
        ("[::FFFF:C000:201]:8443", "::ffff:192.0.2.1", Some(8443)),
    ] {
        let document = json!({"hosts":{configured:{"rate_limit":20}}});
        cases.push(json!({"name":format!("host-compiler-{configured}"),
            "initial":document,"reporting":document,"host":host,"port":port,"method":"GET","now_ms":NOW}));
    }
    let native = cases
        .iter()
        .map(|case| {
            let initial =
                Policy::parse_at(&case["initial"].to_string(), Format::Json, NOW).unwrap();
            assert_eq!(
                initial
                    .evaluate(
                        NetworkRequest {
                            host: case["host"].as_str().unwrap(),
                            method: case["method"].as_str().unwrap(),
                            port: case["port"].as_u64().map(|port| port as u16),
                            ..request("")
                        },
                        NOW,
                        true
                    )
                    .unwrap()
                    .effect,
                Effect::Allow,
                "{}",
                case["name"]
            );
            let current = initial
                .reload_from_source_at(&case["reporting"].to_string(), Format::Json, NOW)
                .unwrap();
            let before = initial.budget_stats(NOW);
            let output = match current.budget_stats(case["now_ms"].as_f64().unwrap()) {
                Ok(body) => json!({"body":body}),
                Err(BudgetStatsError::Overflow) => json!({"error":"OverflowError"}),
                Err(BudgetStatsError::InvalidKey) => json!({"error":"ValueError"}),
                other => panic!("unexpected report {other:?}"),
            };
            assert_eq!(initial.budget_stats(NOW), before);
            output
        })
        .collect::<Vec<_>>();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child =
        Command::new(std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set source Python path"))
            .arg("-B")
            .arg(root.join("proxy/tests/budgets_oracle.py"))
            .env(
                "PYTHONPATH",
                format!("{}:{}", root.join("cli/src").display(), root.display()),
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
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let python: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    if let Some(path) = std::env::var_os("SAFEYOLO_BUDGET_ORACLE_EVIDENCE") {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&json!({"cases":cases,"native":native,"python":python}))
                .unwrap(),
        )
        .unwrap();
    }
    assert_eq!(python.len(), native.len());
    for ((native, python), case) in native.iter().zip(&python).zip(&cases) {
        assert_eq!(native.to_string(), python.to_string(), "{}", case["name"]);
    }
}
