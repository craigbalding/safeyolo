use safeyolo_proxy::policy::{
    BudgetResetError, CredentialRequest, Effect, Format, NetworkRequest, Policy,
};
use serde_json::{Value, json};
use std::sync::Barrier;

const NOW: f64 = 1_000_000.;

fn fixture() -> Value {
    serde_json::from_str(include_str!("budget_reset_source.json")).unwrap()
}

fn policy() -> Policy {
    Policy::parse_at(&fixture()["policy"].to_string(), Format::Json, NOW).unwrap()
}

fn request(host: &str) -> NetworkRequest<'_> {
    NetworkRequest {
        agent: Some("alice"),
        host,
        port: None,
        method: "GET",
        path: "/",
    }
}

fn charge(policy: &Policy, request: NetworkRequest<'_>) {
    assert_eq!(
        policy.evaluate(request, NOW, true).unwrap().effect,
        Effect::Allow
    );
}

fn seed(policy: &Policy) {
    charge(policy, request("zeta.invalid"));
    charge(policy, request("alpha.invalid"));
    charge(
        policy,
        NetworkRequest {
            method: "CONNECT",
            port: Some(8443),
            ..request("zeta.invalid")
        },
    );
    assert_eq!(
        policy
            .evaluate_credential(
                CredentialRequest {
                    credential_type: "fixture",
                    destination: "credential.invalid",
                    path: "/",
                    credential_hmac: None,
                },
                NOW
            )
            .unwrap()
            .effect,
        Effect::Allow
    );
}

fn keys(policy: &Policy) -> Value {
    policy.engine_stats().unwrap()["budget_stats"]["keys"].clone()
}

#[test]
fn source_reset_scope_scalars_and_real_reinsertion_order() {
    let fixture = fixture();
    for (case, expected) in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(fixture["rows"].as_array().unwrap())
    {
        assert_eq!(case["name"], expected["name"]);
        let policy = policy();
        seed(&policy);
        let hash = policy.policy_hash();
        let before = policy.engine_stats().unwrap();
        let parsed = case
            .get("resource_json")
            .map(|value| serde_json::from_str::<Value>(value.as_str().unwrap()).unwrap());
        let reset = policy.reset_budgets(parsed.as_ref().or_else(|| case.get("resource")));
        let error = expected["result"]["status"] == "error";
        assert_eq!(
            reset,
            if error {
                Err(BudgetResetError::InvalidResource)
            } else {
                Ok(())
            },
            "{}",
            case["name"]
        );
        assert_eq!(
            policy.engine_stats().unwrap()["evaluations"],
            before["evaluations"]
        );
        assert_eq!(policy.policy_hash(), hash);
        if case["recharge"] == true {
            charge(&policy, request("zeta.invalid"));
        }
        assert_eq!(keys(&policy), expected["keys"], "{}", case["name"]);
        assert_eq!(
            policy.budget_stats(NOW).unwrap().to_string(),
            expected["report"].to_string(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn exact_host_reset_leaves_global_limit_and_cannot_partially_charge() {
    let policy = Policy::parse_at(
        r#"{"budgets":{"network:request":1},"permissions":[
        {"action":"network:request","resource":"*","effect":"budget","budget":1}] }"#,
        Format::Json,
        NOW,
    )
    .unwrap();
    charge(&policy, request("limited.invalid"));
    charge(&policy, request("limited.invalid"));
    assert_eq!(
        policy
            .evaluate(request("limited.invalid"), NOW, true)
            .unwrap()
            .effect,
        Effect::BudgetExceeded
    );
    policy
        .reset_budgets(Some(&json!("network:request:limited.invalid")))
        .unwrap();
    let before = policy.budget_stats(NOW).unwrap();
    assert_eq!(keys(&policy), json!(["network:request:__global__"]));
    assert_eq!(
        policy
            .evaluate(
                NetworkRequest {
                    agent: Some("bob"),
                    ..request("limited.invalid")
                },
                NOW,
                true
            )
            .unwrap()
            .effect,
        Effect::BudgetExceeded
    );
    assert_eq!(policy.budget_stats(NOW).unwrap(), before);
    policy
        .reset_budgets(Some(&json!("network:request:__global__")))
        .unwrap();
    charge(&policy, request("limited.invalid"));
    assert_eq!(
        keys(&policy),
        json!([
            "network:request:limited.invalid",
            "network:request:__global__"
        ])
    );
}

#[test]
fn old_task_and_reloaded_snapshots_share_reset_without_changing_models() {
    let initial = policy();
    seed(&initial);
    let fixture = fixture();
    let yaml = format!(
        "permissions: {}\nbudgets: {}\naddons:\n  synthetic:\n    settings:\n      observed: 2001-02-03\n",
        fixture["policy"]["permissions"], fixture["policy"]["budgets"]
    );
    let current = initial
        .reload_from_source_at(&yaml, Format::Yaml, NOW)
        .unwrap();
    let task = current
        .with_task_source(r#"{"budgets":{"network:request":500}}"#, Format::Json)
        .unwrap();
    let cleared = task.without_task();
    let hashes = [
        initial.policy_hash(),
        current.policy_hash(),
        task.policy_hash(),
        cleared.policy_hash(),
    ];
    let count = initial.engine_stats().unwrap()["evaluations"].clone();
    let before = keys(&initial);
    assert!(
        current
            .reload_from_source_at("invalid json", Format::Json, NOW)
            .is_err()
    );
    assert_eq!(keys(&initial), before);
    task.reset_budgets(Some(&json!(["invalid-resource"])))
        .unwrap_err();
    assert_eq!(keys(&initial), before);
    initial
        .reset_budgets(Some(&json!("credential:use:credential.invalid:fixture")))
        .unwrap();
    assert_eq!(keys(&initial), keys(&current));
    assert_eq!(keys(&initial), keys(&task));
    cleared.reset_budgets(None).unwrap();
    for (policy, hash) in [&initial, &current, &task, &cleared]
        .into_iter()
        .zip(hashes)
    {
        assert_eq!(keys(policy), json!([]));
        assert_eq!(policy.budget_stats(NOW).unwrap()["tracked_keys"], 0);
        assert_eq!(policy.engine_stats().unwrap()["evaluations"], count);
        assert_eq!(policy.policy_hash(), hash);
    }
}

#[test]
fn reset_and_multikey_charge_share_one_atomic_state_across_threads() {
    let initial = policy();
    let reloaded = initial
        .reload_from_source_at(&fixture()["policy"].to_string(), Format::Json, NOW)
        .unwrap();
    let barrier = Barrier::new(4);
    std::thread::scope(|scope| {
        for policy in [&initial, &reloaded] {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..256 {
                    let result = policy
                        .evaluate(request("concurrent.invalid"), NOW, true)
                        .unwrap();
                    assert!(matches!(
                        result.effect,
                        Effect::Allow | Effect::BudgetExceeded
                    ));
                    std::thread::yield_now();
                }
            });
        }
        let barrier = &barrier;
        let reset = &initial;
        scope.spawn(move || {
            barrier.wait();
            for _ in 0..256 {
                reset.reset_budgets(None).unwrap();
                std::thread::yield_now();
            }
        });
        barrier.wait();
        for _ in 0..256 {
            let report = reloaded.budget_stats(NOW).unwrap();
            let entries = report["budgets"].as_object().unwrap();
            assert!(entries.is_empty() || entries.len() == 2);
            if !entries.is_empty() {
                assert_eq!(
                    entries.keys().map(String::as_str).collect::<Vec<_>>(),
                    [
                        "network:request:concurrent.invalid",
                        "network:request:__global__"
                    ]
                );
                assert_eq!(
                    entries["network:request:concurrent.invalid"]["remaining"],
                    entries["network:request:__global__"]["remaining"]
                );
            }
            std::thread::yield_now();
        }
    });
    assert_eq!(initial.engine_stats().unwrap()["evaluations"], 512);
    assert_eq!(
        initial.budget_stats(NOW).unwrap(),
        reloaded.budget_stats(NOW).unwrap()
    );
}

#[test]
#[ignore = "actual Python oracle; set SAFEYOLO_POLICY_PYTHON to the existing environment"]
fn frozen_reset_rows_match_actual_local_policy_client() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child =
        Command::new(std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set source Python path"))
            .arg("-B")
            .arg(root.join("proxy/tests/budget_reset_oracle.py"))
            .env(
                "PYTHONPATH",
                format!("{}:{}", root.join("cli/src").display(), root.display()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(fixture().to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "source reset oracle failed");
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual.to_string(), fixture()["rows"].to_string());
}
