//! Actual-source circuit API bodies, transition ownership and reset keys.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, header};
use safeyolo_proxy::{
    admin_api::{self, Audit, Error as AdminError},
    agent_api::{self, CircuitContext, PolicyState},
    circuits::{CircuitBreaker, CircuitValue, ErrorKind},
    network_guard::Identity,
    policy::{Format, Policy},
    tasks::Registry,
};
use serde_json::{Value, json};

const TOKEN: &str = "synthetic-circuit-api-token";
const AUTH: &[u8] = b"Bearer synthetic-circuit-api-token";
const HOST: &str = "owned.invalid";
const NOW: f64 = 1000.;

#[test]
#[ignore = "actual Python oracle; set SAFEYOLO_POLICY_PYTHON to the existing environment"]
fn frozen_circuit_api_rows_match_actual_source_hooks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let python_path = std::env::join_paths([root.join("cli/src"), root.to_owned()]).unwrap();
    let result = std::process::Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set source Python path"),
    )
    .current_dir(root)
    .env("PYTHONPATH", python_path)
    .arg("-B")
    .arg(root.join("proxy/tests/circuit_api_source.py"))
    .arg("--check")
    .arg(root.join("proxy/tests/circuit_api_source.json"))
    .output()
    .unwrap();
    assert!(result.status.success(), "source circuit API oracle failed");
}

fn source() -> Value {
    serde_json::from_str(include_str!("circuit_api_source.json")).unwrap()
}
fn request(path: &str) -> agent_api::Request<'_> {
    agent_api::Request {
        method: "GET",
        path_and_query: path,
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: Some("127.0.0.1"),
        request_id: "req-fixture",
    }
}
fn token() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent_token");
    std::fs::write(&path, TOKEN).unwrap();
    (dir, path)
}
fn middle() -> f64 {
    0.5
}

#[tokio::test]
async fn source_agent_reads_keep_typed_bytes_and_partial_transition_intents() {
    let (_dir, token) = token();
    let tasks = Registry::default();
    for row in source()["agent"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let cb = CircuitBreaker::new();
        match name {
            "nan" | "infinity" => {
                let value = if name == "nan" { "NaN" } else { "Infinity" };
                let snapshot = CircuitValue::parse_json(&format!(
                    "{{\"states\":{{\"owned.invalid\":{{\"state\":\"closed\",\"failure_count\":{value}}}}}}}"
                )).unwrap();
                cb.restore_document(&snapshot, NOW, &mut middle).unwrap();
            }
            "date" => {
                let policy = Policy::parse(
                    "addons:\n  circuit_breaker:\n    failure_threshold: 2001-02-03\n",
                    Format::Yaml,
                )
                .unwrap();
                cb.apply_policy_config(&policy).unwrap();
            }
            "half_open" | "partial_error" => {
                let snapshot =
                    json!({"states":{HOST:{"state":"open", "opened_at":0, "failure_count":5}}});
                if name == "partial_error" {
                    let policy = Policy::parse(
                        "addons:\n  circuit_breaker:\n    failure_threshold: 2001-02-03\n",
                        Format::Yaml,
                    )
                    .unwrap();
                    cb.apply_policy_config(&policy).unwrap();
                }
                cb.restore(&snapshot, 0., &mut middle).unwrap();
            }
            _ => {}
        }
        let before = cb
            .snapshot_document(NOW)
            .unwrap()
            .render_json(false)
            .unwrap();
        let mut random = middle;
        let context = (name != "absent").then_some(CircuitContext {
            breaker: &cb,
            enabled: name != "disabled",
            random: &mut random,
        });
        let outcome = agent_api::respond_read_with_circuits(
            request("/circuits///?agent=forged"),
            &token,
            PolicyState::Unavailable,
            &tasks,
            NOW * 1000.,
            context,
        )
        .await;
        assert_eq!(
            outcome.response.status,
            row["status"].as_u64().unwrap() as u16,
            "{name}"
        );
        assert_eq!(
            outcome.response.body_bytes().as_ref(),
            row["text"].as_str().unwrap().as_bytes(),
            "{name}"
        );
        assert!(outcome.handler_owned && outcome.audit.is_none());
        assert_eq!(outcome.policy_evaluations, 0);
        assert_eq!(
            outcome.circuit_events.len(),
            row["events"].as_array().unwrap().len(),
            "{name}"
        );
        for (event, expected) in outcome
            .circuit_events
            .iter()
            .zip(row["events"].as_array().unwrap())
        {
            assert_eq!(
                format!("ops.circuit_breaker.{}", event.event.as_str()),
                expected["event"]
            );
            assert_eq!(event.domain, expected["host"]);
            assert!(!event.event.response_scoped());
        }
        if matches!(name, "date" | "partial_error") {
            assert_eq!(
                outcome.failure,
                Some(agent_api::Failure::CircuitReporting(ErrorKind::Type))
            );
        }
        if !matches!(name, "half_open" | "partial_error") {
            assert_eq!(
                cb.snapshot_document(NOW)
                    .unwrap()
                    .render_json(false)
                    .unwrap(),
                before
            );
        }
    }
}

#[tokio::test]
async fn agent_method_and_auth_failures_do_not_observe_stale_circuits() {
    let (_dir, token) = token();
    let cb = CircuitBreaker::new();
    cb.force_open(HOST, 0.).unwrap();
    let before = cb.snapshot(NOW).unwrap();
    let tasks = Registry::default();
    for (method, auth, status) in [
        ("POST", None, 405),
        ("HEAD", None, 405),
        ("GET", None, 401),
        ("GET", Some(b"Bearer wrong".as_slice()), 401),
    ] {
        let mut random = || panic!("No status observation before authorization");
        let outcome = agent_api::respond_read_with_circuits(
            agent_api::Request {
                method,
                authorization: auth,
                ..request("/circuits")
            },
            &token,
            PolicyState::Unavailable,
            &tasks,
            NOW * 1000.,
            Some(CircuitContext {
                breaker: &cb,
                enabled: true,
                random: &mut random,
            }),
        )
        .await;
        assert_eq!(outcome.response.status, status);
        assert!(outcome.circuit_events.is_empty());
        assert_eq!(cb.snapshot(NOW).unwrap(), before);
    }
}

fn admin_request(method: &str, path: &str, payload: &[u8], auth: bool) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_LENGTH, payload.len());
    if auth {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(payload)))
        .unwrap()
}
async fn admin_text(outcome: admin_api::Outcome) -> String {
    assert_eq!(outcome.headers()[header::CONTENT_TYPE], "application/json");
    let length: usize = outcome.headers()[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
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
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn source_operator_exact_and_typed_reset_keys_preserve_state_and_audit() {
    let tasks = Registry::default();
    for row in source()["admin"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let cb = CircuitBreaker::new();
        cb.force_open(HOST, NOW).unwrap();
        let input = unhex(row["input_hex"].as_str().unwrap());
        let outcome = admin_api::respond_with_circuits(
            admin_request("POST", "/admin/circuit-breaker/reset", &input, true),
            TOKEN,
            &tasks,
            None,
            Some(&cb),
        )
        .await;
        match row["exception"].as_str() {
            Some("AttributeError") => assert!(matches!(outcome, Err(AdminError::NonObjectBody))),
            Some("TypeError") => assert!(matches!(
                outcome,
                Err(AdminError::CircuitOperation(ErrorKind::Type))
            )),
            _ => {
                let outcome = outcome.unwrap();
                let reply = &row["replies"][0];
                assert_eq!(
                    outcome.status().as_u16(),
                    reply["status"].as_u64().unwrap() as u16,
                    "{name}"
                );
                if row["events"].as_array().unwrap().is_empty() {
                    assert!(outcome.audit().is_none());
                } else {
                    let Some(Audit::CircuitReset(audit)) = outcome.audit() else {
                        panic!("reset intent missing")
                    };
                    for (mut actual, expected) in audit
                        .events("127.0.0.1")
                        .into_iter()
                        .zip(row["events"].as_array().unwrap())
                    {
                        let mut expected = expected.clone();
                        assert_eq!(actual["audit_intent"], expected["event"], "{name}");
                        assert_eq!(
                            actual["event"],
                            if expected["kind"] == "ops" {
                                "proxy.circuit"
                            } else {
                                "proxy.admin_api"
                            }
                        );
                        actual.as_object_mut().unwrap().remove("audit_intent");
                        actual.as_object_mut().unwrap().remove("event");
                        expected.as_object_mut().unwrap().remove("event");
                        expected.as_object_mut().unwrap().remove("schema_version");
                        assert_eq!(actual, expected, "{name}");
                    }
                }
                let text = admin_text(outcome).await;
                if matches!(name, "malformed" | "invalid_utf8") {
                    assert_eq!(row["replies"].as_array().unwrap().len(), 2);
                    let body: Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(body["error"], "Malformed JSON in request body");
                    assert!(
                        body["detail"]
                            .as_str()
                            .is_some_and(|detail| !detail.is_empty())
                    );
                } else {
                    assert_eq!(text, reply["text"].as_str().unwrap(), "{name}");
                }
            }
        }
        let keys: Vec<_> = cb.snapshot(NOW).unwrap()["states"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(json!(keys), row["retained"], "{name}");
    }
}

#[tokio::test]
async fn operator_route_auth_and_missing_addon_follow_source_order() {
    let tasks = Registry::default();
    let cb = CircuitBreaker::new();
    cb.force_open(HOST, NOW).unwrap();
    let before = cb.snapshot(NOW).unwrap();
    for (method, path, auth, payload, available, status) in [
        (
            "HEAD",
            "/admin/circuit-breaker/reset",
            false,
            b"{".as_slice(),
            true,
            501,
        ),
        (
            "POST",
            "/admin/circuit-breaker/reset",
            false,
            b"{",
            true,
            401,
        ),
        ("GET", "/admin/circuit-breaker/reset", true, b"{", true, 404),
        (
            "POST",
            "/admin/circuit-breaker/reset/",
            true,
            b"{",
            true,
            404,
        ),
        (
            "POST",
            "/admin/circuit-breaker/reset",
            true,
            b"{}",
            false,
            400,
        ),
        (
            "POST",
            "/admin/circuit-breaker/reset",
            true,
            b"{\"host\":[1]}",
            false,
            503,
        ),
        (
            "POST",
            "/admin/circuit-breaker/reset",
            true,
            b"{\"host\":\"owned.invalid\"}",
            false,
            503,
        ),
    ] {
        let outcome = admin_api::respond_with_circuits(
            admin_request(method, path, payload, auth),
            TOKEN,
            &tasks,
            None,
            available.then_some(&cb),
        )
        .await
        .unwrap();
        assert_eq!(outcome.status(), StatusCode::from_u16(status).unwrap());
        assert_eq!(cb.snapshot(NOW).unwrap(), before);
        assert!(!matches!(outcome.audit(), Some(Audit::CircuitReset(_))));
    }
}
