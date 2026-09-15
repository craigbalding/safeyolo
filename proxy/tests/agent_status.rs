use std::{path::Path, process::Command};

use safeyolo_proxy::{
    agent_api::{Failure, PolicyState, Request, respond_read},
    network_guard::Identity,
    policy::{Effect, EngineStatsError, NetworkRequest, Policy},
    tasks::Registry,
};
use serde_json::{Value, json};

const TOKEN: &[u8] = b"synthetic-agent-status-fixture";
const AUTH: &[u8] = b"Bearer synthetic-agent-status-fixture";
const NOW: f64 = 1_000_000.;

fn request(path: &str) -> Request<'_> {
    Request {
        method: "GET",
        path_and_query: path,
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: None,
        request_id: "req-status-fixture",
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("agent_status_source.json")).unwrap()
}

fn network() -> NetworkRequest<'static> {
    NetworkRequest {
        agent: None,
        host: "allowed.invalid",
        port: Some(80),
        method: "GET",
        path: "/",
    }
}

async fn compare_source(source: &Value) {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    let baseline = directory.path().join("baseline.json");
    std::fs::write(&token, TOKEN).unwrap();
    std::fs::write(&baseline, source["baseline"].to_string()).unwrap();
    let mut policy = Policy::from_path_at(&baseline, NOW).unwrap();
    let tasks = Registry::default();
    for row in source["rows"].as_array().unwrap() {
        let step = &row["step"];
        match step["kind"].as_str().unwrap() {
            "upsert" => {
                let result = tasks.upsert(step["id"].as_str().unwrap(), step["policy"].clone());
                assert_eq!(
                    result.is_err(),
                    matches!(step["id"].as_str().unwrap(), "../invalid" | "gamma")
                );
            }
            "task" => {
                let path = directory.path().join("task.json");
                std::fs::write(&path, source["task"].to_string()).unwrap();
                policy = policy.with_task_path(&path).unwrap();
            }
            "lookup" => {
                let before = policy.budget_stats(NOW).unwrap();
                let lookup = respond_read(
                    request("/lookup?host=allowed.invalid"),
                    &token,
                    PolicyState::Ready(&policy),
                    &tasks,
                    NOW,
                )
                .await;
                assert_eq!(lookup.response.status, 200);
                assert_eq!(lookup.policy_evaluations, 1);
                assert_eq!(policy.budget_stats(NOW).unwrap(), before);
            }
            "network" => assert_eq!(
                policy.evaluate(network(), NOW, true).unwrap().effect,
                Effect::Allow
            ),
            "reads" => {
                for path in ["/config", "/policy", "/budgets", "/health"] {
                    let reply = respond_read(
                        request(path),
                        &token,
                        PolicyState::Ready(&policy),
                        &tasks,
                        NOW,
                    )
                    .await;
                    assert_eq!(reply.response.status, 200);
                    assert_eq!(reply.policy_evaluations, 0);
                }
            }
            "status" => (),
            _ => panic!("unknown source operation"),
        }
        let req = Request {
            method: step["method"].as_str().unwrap_or("GET"),
            authorization: if step["auth"] == "missing" {
                None
            } else {
                Some(AUTH)
            },
            identity: Identity::Resolved(step["agent"].as_str().unwrap_or("alice")),
            ..request(step["path"].as_str().unwrap_or("/status"))
        };
        let before = policy.engine_stats().unwrap();
        let state = if step["state"] == "missing" {
            PolicyState::Unavailable
        } else {
            PolicyState::Ready(&policy)
        };
        // Status does not consult the request clock.
        let outcome = respond_read(req, &token, state, &tasks, f64::NAN).await;
        assert_eq!(
            outcome.response.status,
            row["response"]["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            serde_json::to_value(&outcome.response.headers).unwrap(),
            row["response"]["headers"]
        );
        let bytes = outcome.response.body_bytes();
        let normalized = std::str::from_utf8(&bytes)
            .unwrap()
            .replace(directory.path().to_str().unwrap(), "$ROOT");
        let hex: String = normalized
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, row["response"]["body_hex"]);
        assert_eq!(
            outcome.blocked_by,
            row["response"]["blocked_by"].as_str().unwrap()
        );
        assert_eq!(
            outcome.handler_owned,
            row["response"]["handler_owned"].as_bool().unwrap()
        );
        assert_eq!(outcome.policy_evaluations, 0);
        assert_eq!(policy.engine_stats().unwrap(), before);
        assert_eq!(before["evaluations"], row["evaluations"]);
    }
}

#[tokio::test]
async fn authenticated_status_bytes_follow_real_registry_and_policy_operations() {
    let source = fixture();
    assert_eq!(source["rows"].as_array().unwrap().len(), 15);
    compare_source(&source).await;
}

#[tokio::test]
async fn status_is_shared_across_identities_ignores_queries_and_tracks_reload_hash() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, TOKEN).unwrap();
    let initial = Policy::unconfigured();
    let tasks = Registry::default();
    let mut expected = None;
    for identity in [
        Identity::Resolved("alice"),
        Identity::Resolved("bob"),
        Identity::Unavailable,
        Identity::Conflict,
    ] {
        let outcome = respond_read(
            Request {
                identity,
                ..request("/status///?agent=forged&task_id=unregistered&ignored=%ff")
            },
            &token,
            PolicyState::Ready(&initial),
            &tasks,
            f64::NAN,
        )
        .await;
        assert_eq!(outcome.response.status, 200);
        let bytes = outcome.response.body_bytes();
        if let Some(expected) = &expected {
            assert_eq!(&bytes, expected);
        } else {
            expected = Some(bytes.clone());
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["policy_hash"],
            initial.policy_hash()
        );
    }
    let fresh = Registry::default();
    tasks.upsert("registered", json!({})).unwrap();
    let policy = initial
        .reload_from_source_at(
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
            safeyolo_proxy::policy::Format::Json,
            NOW,
        )
        .unwrap();
    policy.evaluate(network(), NOW, false).unwrap();
    let response = respond_read(
        request("/status"),
        &token,
        PolicyState::Ready(&policy),
        &tasks,
        NOW,
    )
    .await;
    let body: Value = serde_json::from_slice(&response.response.body_bytes()).unwrap();
    assert_eq!(body["policy_hash"], policy.policy_hash());
    assert_ne!(body["policy_hash"], initial.policy_hash());
    assert_eq!(body["task_policies"], 1);
    assert_eq!(body["engine_stats"]["evaluations"], 1);
    assert_eq!(body["engine_stats"]["task_permissions"], 0);
    assert_eq!(fresh.count().unwrap(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn method_and_auth_precede_typed_stats_failure_without_leaking_path() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, TOKEN).unwrap();
    let baseline = directory
        .path()
        .join(OsString::from_vec(b"private-policy-\xff.json".to_vec()));
    std::fs::write(&baseline, "{}").unwrap();
    let policy = Policy::from_path_at(&baseline, NOW).unwrap();
    let tasks = Registry::default();
    for (method, authorization, status) in
        [("HEAD", None, 405), ("POST", None, 405), ("GET", None, 401)]
    {
        let outcome = respond_read(
            Request {
                method,
                authorization,
                ..request("/status")
            },
            &token,
            PolicyState::Ready(&policy),
            &tasks,
            NOW,
        )
        .await;
        assert_eq!(outcome.response.status, status);
        assert!(outcome.failure.is_none());
    }
    let outcome = respond_read(
        request("/status?private_query=discarded"),
        &token,
        PolicyState::Ready(&policy),
        &tasks,
        NOW,
    )
    .await;
    assert_eq!(outcome.response.status, 503);
    assert_eq!(
        outcome.failure,
        Some(Failure::EngineReporting(EngineStatsError::PathEncoding))
    );
    assert!(!outcome.handler_owned);
    assert!(outcome.scrub_request);
    let bytes = outcome.response.body_bytes();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("private-policy") && !text.contains("private_query"));
    assert!(text.contains("req-status-fixture"));
}

#[tokio::test]
async fn unavailable_and_generic_no_engine_remain_distinct() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, TOKEN).unwrap();
    let tasks = Registry::default();
    let missing = respond_read(
        request("/status"),
        &token,
        PolicyState::Unavailable,
        &tasks,
        NOW,
    )
    .await;
    assert_eq!(missing.response.status, 503);
    assert_eq!(
        missing.response.body_bytes(),
        b"{\"error\": \"PDP not available\"}".as_slice()
    );
    assert!(missing.failure.is_none());
    for healthy in [true, false] {
        let remote = respond_read(
            request("/status"),
            &token,
            PolicyState::NoEngine { healthy },
            &tasks,
            NOW,
        )
        .await;
        assert_eq!(remote.response.status, 503);
        assert_eq!(remote.failure, Some(Failure::DevelopmentEndpoint));
        assert_eq!(remote.policy_evaluations, 0);
    }
}

#[tokio::test]
#[ignore = "requires the pinned source Python environment"]
async fn live_python_authenticated_status_oracle() {
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON");
    let output = Command::new(python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/agent_status_oracle.py"))
        .arg("--emit")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "source status facade oracle failed"
    );
    let live: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(live, fixture());
    compare_source(&live).await;
}
