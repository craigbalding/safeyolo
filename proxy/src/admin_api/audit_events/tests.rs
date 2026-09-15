use super::*;
use crate::{
    admin_api,
    audit::{ErrorKind, Settings},
    circuits::CircuitBreaker,
    policy::{Effect, Format, NetworkRequest, Policy},
    tasks::Registry,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, header};
use serde_json::Value;
use std::time::Duration;

const TOKEN: &str = "owned-operator-audit-fixture";
const HOST: &str = "owned.invalid";

#[tokio::test]
async fn synchronous_submission_errors_preserve_mutations_and_stop_later_events() {
    let budgets: Value =
        serde_json::from_str(include_str!("../../../tests/admin_budgets_source.json")).unwrap();
    let circuits: Value =
        serde_json::from_str(include_str!("../../../tests/circuit_api_source.json")).unwrap();
    let auth: Value = serde_json::from_str(include_str!(
        "../../../tests/admin_audit_failures_source.json"
    ))
    .unwrap();
    for (route, failure_index) in [
        ("budget", 0),
        ("budget", 1),
        ("circuit", 0),
        ("circuit", 1),
        ("task", 0),
        ("auth", 0),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accepted.jsonl");
        let writer = Writer::new(path.clone(), Settings::default());
        let failed_writer = Writer::new(directory.path().join("failed.jsonl"), Settings::default());
        failed_writer.poison_for_test();
        let policy = Policy::parse(r#"{"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}]}"#, Format::Json).unwrap();
        for expected in [Effect::Allow, Effect::Allow, Effect::BudgetExceeded] {
            assert_eq!(
                policy
                    .evaluate(
                        NetworkRequest {
                            agent: Some("alice"),
                            host: "alpha.invalid",
                            port: None,
                            method: "GET",
                            path: "/",
                        },
                        1000.,
                        true
                    )
                    .unwrap()
                    .effect,
                expected
            );
        }
        let breaker = CircuitBreaker::new();
        breaker.force_open(HOST, 1000.).unwrap();
        let tasks = Registry::default();
        let evaluations = policy.engine_stats().unwrap()["evaluations"].clone();
        let source = match route {
            "budget" => Some(&budgets["failure_rows"][failure_index]),
            "circuit" => Some(&circuits["failure_rows"][failure_index]),
            "auth" => Some(&auth["failure_rows"][0]),
            _ => None,
        };
        let (method, target, payload) = match route {
            "budget" => (
                "POST",
                "/admin/budgets/reset",
                r#"{"resource":"network:request:alpha.invalid"}"#,
            ),
            "circuit" => (
                "POST",
                "/admin/circuit-breaker/reset",
                r#"{"host":"owned.invalid"}"#,
            ),
            "task" => (
                "PUT",
                "/admin/policy/task/owned",
                r#"{"policy":{"permissions":[]}}"#,
            ),
            _ => ("GET", "/unknown?query=value", ""),
        };
        let mut request = Request::builder()
            .method(method)
            .uri(target)
            .header(header::CONTENT_LENGTH, payload.len());
        if route != "auth" {
            request = request.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
        }
        let outcome = admin_api::respond_with_circuits(
            request
                .body(Full::new(Bytes::from_static(payload.as_bytes())))
                .unwrap(),
            TOKEN,
            &tasks,
            Some(&policy),
            Some(&breaker),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.status().as_u16(),
            if route == "auth" { 401 } else { 200 }
        );
        let mut attempted = Vec::new();
        let result = outcome.submit_audit_with("127.0.0.1", target, |event| {
            let fail = attempted.len() == failure_index;
            attempted.push(event.event.clone());
            if fail {
                failed_writer.emit(event)
            } else {
                writer.emit(event)
            }
            .map(|_| ())
        });
        assert_eq!(attempted.len(), failure_index + 1, "{route}");
        if let Some(source) = source {
            let expected: Vec<&str> = source["attempted"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["event"].as_str().unwrap())
                .collect();
            assert_eq!(attempted, expected, "{route}");
        }
        if route == "budget" && failure_index == 0 {
            let reply = result.unwrap().into_response();
            assert_eq!(reply.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = reply.into_body().collect().await.unwrap().to_bytes();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value, json!({"error":"Failed to reset budget counters"}));
            assert_eq!(
                std::str::from_utf8(&body).unwrap(),
                source.unwrap()["replies"][0]["text"].as_str().unwrap()
            );
        } else {
            assert!(
                matches!(result, Err(Error::Audit(ErrorKind::Poisoned))),
                "{route}"
            );
            if let Some(source) = source {
                assert_eq!(source["exception"], "RuntimeError");
                assert_eq!(source["replies"], json!([]));
            }
        }
        assert_eq!(policy.engine_stats().unwrap()["evaluations"], evaluations);
        assert_eq!(
            policy.budget_stats(1000.).unwrap()["tracked_keys"],
            if route == "budget" { 0 } else { 1 }
        );
        assert_eq!(
            breaker.snapshot(1000.).unwrap()["states"]
                .as_object()
                .unwrap()
                .contains_key(HOST),
            route != "circuit"
        );
        assert_eq!(tasks.count().unwrap(), usize::from(route == "task"));
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
        let accepted: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let mut event: Value = serde_json::from_str(line).unwrap();
                assert!(event.as_object_mut().unwrap().remove("ts").is_some());
                event
            })
            .collect();
        assert_eq!(accepted.len(), failure_index);
        if let Some(source) = source {
            assert_eq!(json!(accepted), source["accepted"], "{route}");
        }
        if failure_index == 1 {
            assert_eq!(
                accepted[0]["event"],
                if route == "budget" {
                    "admin.budget_reset"
                } else {
                    "ops.circuit_breaker.reset"
                }
            );
        }
        assert!(!directory.path().join("failed.jsonl").exists());
    }
}
