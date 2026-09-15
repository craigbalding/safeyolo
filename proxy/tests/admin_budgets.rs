//! Actual source hooks; owned binary tests cover listener and audit I/O.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, body::Body, header};
use safeyolo_proxy::{
    admin_api::{self, Audit, Error, Outcome},
    policy::{BudgetStatsError, Effect, Format, NetworkRequest, Policy},
    tasks::Registry,
};
use serde_json::{Value, json};

const TOKEN: &str = "synthetic-operator-fixture";
const NOW: f64 = 1_000_000.;
fn fixture() -> Value {
    serde_json::from_str(include_str!("admin_budgets_source.json")).unwrap()
}
fn network() -> NetworkRequest<'static> {
    NetworkRequest {
        agent: Some("alice"),
        host: "alpha.invalid",
        port: None,
        method: "GET",
        path: "/",
    }
}
fn prepared() -> Policy {
    let policy = Policy::parse_at(&fixture()["policy"].to_string(), Format::Json, NOW).unwrap();
    for expected in [Effect::Allow, Effect::Allow, Effect::BudgetExceeded] {
        assert_eq!(
            policy.evaluate(network(), NOW, true).unwrap().effect,
            expected
        );
    }
    policy
}
fn request(method: &str, path: &str, body: &[u8]) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_LENGTH, body.len())
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap()
}
async fn text(outcome: Outcome) -> String {
    assert_eq!(outcome.headers()[header::CONTENT_TYPE], "application/json");
    let length = outcome.headers()[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let bytes = outcome
        .into_response()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(bytes.len(), length);
    String::from_utf8(bytes.to_vec()).unwrap()
}
fn decode_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn source_reset_bytes_audit_and_state_with_two_explicit_repairs() {
    let fixture = fixture();
    let registry = Registry::default();
    registry
        .upsert("retained", json!({"permissions":[]}))
        .unwrap();
    for row in fixture["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let policy = prepared();
        let before = policy.engine_stats().unwrap();
        let hash = policy.policy_hash();
        let bytes = decode_hex(row["input_hex"].as_str().unwrap());
        let outcome = admin_api::respond(
            request("POST", "/admin/budgets/reset", &bytes),
            TOKEN,
            &registry,
            Some(&policy),
        )
        .await;
        if row["exception"] == "AttributeError" {
            assert!(matches!(outcome, Err(Error::NonObjectBody)), "{name}");
        } else {
            let outcome = outcome.unwrap();
            if row["intentional_repair"] == true {
                assert_eq!(outcome.status(), StatusCode::BAD_REQUEST, "{name}");
                assert!(outcome.audit().is_none(), "{name}");
                let body: Value = serde_json::from_str(&text(outcome).await).unwrap();
                assert_eq!(body["error"], "Malformed JSON in request body");
                assert!(
                    body["detail"]
                        .as_str()
                        .is_some_and(|detail| !detail.is_empty())
                );
            } else {
                let reply = &row["replies"][0];
                assert_eq!(
                    outcome.status().as_u16(),
                    reply["status"].as_u64().unwrap() as u16,
                    "{name}"
                );
                let events = row["events"].as_array().unwrap();
                if events.is_empty() {
                    assert!(outcome.audit().is_none(), "{name}");
                } else {
                    let Some(Audit::BudgetsReset(reset)) = outcome.audit() else {
                        panic!("missing reset intent: {name}")
                    };
                    assert_eq!(reset.safe_resource(), events[1]["safe_resource"], "{name}");
                    assert_eq!(
                        reset.resets_all(),
                        events[1]["resource_falsy"].as_bool().unwrap(),
                        "{name}"
                    );
                    assert_eq!(events[0]["name"], "admin.budget_reset");
                    assert_eq!(events[1]["name"], "admin.budgets_reset");
                }
                assert_eq!(
                    text(outcome).await,
                    reply["text"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
        assert_eq!(
            policy.budget_stats(NOW).unwrap()["tracked_keys"],
            if row["intentional_repair"] == true {
                json!(1)
            } else {
                row["tracked_keys"].clone()
            },
            "{name}"
        );
        assert_eq!(
            policy.engine_stats().unwrap()["evaluations"],
            before["evaluations"],
            "{name}"
        );
        assert_eq!(policy.policy_hash(), hash, "{name}");
        assert_eq!(registry.count().unwrap(), 1, "{name}");
    }
}

#[tokio::test]
async fn auth_method_route_and_unavailable_provider_precede_body_reads() {
    struct MustNotRead;
    impl Body for MustNotRead {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            panic!("body read before terminal routing decision")
        }
    }
    let policy = prepared();
    let registry = Registry::default();
    let before = policy.budget_stats(NOW).unwrap();
    for (method, path, auth, native, status) in [
        ("OPTIONS", "/admin/budgets/reset", false, false, 501),
        ("POST", "/admin/budgets/reset", false, true, 401),
        ("GET", "/admin/budgets", false, false, 401),
        ("GET", "/admin/budgets", true, false, 503),
        ("POST", "/admin/budgets/reset", true, false, 503),
        ("PUT", "/admin/budgets/reset", true, false, 404),
        ("GET", "/admin/budgets/reset", true, true, 404),
        ("POST", "/admin/budgets", true, true, 404),
        ("POST", "/admin/budgets/reset/", true, true, 404),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_LENGTH, 1);
        if auth {
            request = request.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
        }
        let outcome = admin_api::respond(
            request.body(MustNotRead).unwrap(),
            TOKEN,
            &registry,
            native.then_some(&policy),
        )
        .await
        .unwrap();
        assert_eq!(outcome.status().as_u16(), status);
        assert_eq!(outcome.audit().is_some(), status == 401);
        if status == 503 {
            assert_eq!(
                text(outcome).await,
                "{\n  \"error\": \"Operator budget endpoint unavailable with the temporary policy adapter\"\n}"
            );
        }
    }
    assert_eq!(policy.budget_stats(NOW).unwrap(), before);
}

#[tokio::test]
async fn get_reads_same_state_without_evaluation_or_identity_selection() {
    let policy = prepared();
    let registry = Registry::default();
    policy.reset_budgets(None).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        * 1000.;
    for _ in 0..2 {
        policy.evaluate(network(), now, true).unwrap();
    }
    let count = policy.engine_stats().unwrap()["evaluations"].clone();
    for path in [
        "/admin/budgets",
        "//admin/budgets;ignored?agent=bob&resource=missing",
    ] {
        let mut request = request("GET", path, b"not-json-and-unread");
        request
            .headers_mut()
            .insert("x-safeyolo-agent", "forged".parse().unwrap());
        let outcome = admin_api::respond(request, TOKEN, &registry, Some(&policy))
            .await
            .unwrap();
        assert_eq!(outcome.status(), StatusCode::OK);
        assert!(outcome.audit().is_none());
        assert_eq!(text(outcome).await, fixture()["get"]["replies"][0]["text"]);
    }
    assert_eq!(policy.engine_stats().unwrap()["evaluations"], count);
    assert_eq!(count, 5);
}

#[tokio::test]
async fn get_reporting_failure_terminates_with_a_categorical_error() {
    let initial = prepared();
    // Source conversion of admitted raw integer reporting budget overflows.
    let source = format!(
        r#"{{"permissions":[{{"action":"network:request","resource":"alpha.invalid/*","effect":"allow","budget":1{},"condition":{{}}}}]}}"#,
        "0".repeat(400)
    );
    let policy = initial
        .reload_from_source_at(&source, Format::Json, NOW)
        .unwrap();
    let registry = Registry::default();
    let outcome = admin_api::respond(
        request("GET", "/admin/budgets", b""),
        TOKEN,
        &registry,
        Some(&policy),
    )
    .await;
    assert!(matches!(
        outcome,
        Err(Error::BudgetReporting(BudgetStatsError::Overflow))
    ));
    assert_eq!(
        Error::BudgetReporting(BudgetStatsError::Overflow).to_string(),
        "Operator budget report unavailable"
    );
    assert_eq!(policy.engine_stats().unwrap()["evaluations"], 3);
}

#[test]
#[ignore = "actual Python oracle; set SAFEYOLO_POLICY_PYTHON to the existing environment"]
fn frozen_facade_rows_match_actual_source_hooks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let output_path = temporary.path().join("source.json");
    let status = std::process::Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set source Python path"),
    )
    .arg("-B")
    .arg(root.join("proxy/tests/admin_budgets_oracle.py"))
    .arg(&output_path)
    .env("SAFEYOLO_SOURCE_ROOT", root)
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .status()
    .unwrap();
    assert!(status.success(), "source budget facade oracle failed");
    let actual: Value = serde_json::from_slice(&std::fs::read(output_path).unwrap()).unwrap();
    for key in ["rows", "get", "network_attempts", "tokens_read_or_minted"] {
        assert_eq!(actual[key], fixture()[key], "{key}");
    }
}
