use safeyolo_proxy::{
    agent_api::*,
    network_guard::Identity,
    policy::{Effect, Format, NetworkRequest, Policy},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

fn body(response: &Response<'_>) -> Value {
    serde_json::from_slice(&response.body_bytes()).unwrap()
}

const TOKEN: &str = "synthetic-agent-api-fixture";
const AUTH: &[u8] = b"Bearer synthetic-agent-api-fixture";
const RID: &str = "req-00000000000000000000000000000001";
fn request(path: &str) -> Request<'_> {
    Request {
        method: "GET",
        path_and_query: path,
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: Some("10.0.0.5"),
        request_id: RID,
    }
}
fn policy(document: Value) -> Policy {
    Policy::parse(&document.to_string(), Format::Json).unwrap()
}
fn allow() -> Policy {
    policy(json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}))
}
fn token() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent_token");
    std::fs::write(&path, TOKEN).unwrap();
    (dir, path)
}

#[tokio::test]
async fn sensor_config_reads_the_shared_authorized_snapshot_with_source_bytes() {
    let (_dir, token_path) = token();
    let policy = policy(json!({
        "permissions":[],
        "credential_rules":[{"name":"base","patterns":["fixture-[0-9]+"],"allowed_hosts":["api.fixture.invalid"]}],
        "scan_patterns":[{"name":"base","pattern":"fixture-é"}],
        "addons":{"credential_guard":{"enabled":false,"settings":{"use_default_credential_rules":false},"custom":"preserved"}}
    }));
    let source: Value = serde_json::from_str(include_str!("sensor_config_source.json")).unwrap();
    let expected = source["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == "configured_defaults_disabled_addon_shared_scope")
        .unwrap();
    for identity in [
        Identity::Resolved("alice"),
        Identity::Resolved("bob"),
        Identity::Unavailable,
        Identity::Conflict,
    ] {
        let outcome = respond_read(
            Request {
                identity,
                ..request("/config///?agent=forged&host=other.invalid")
            },
            &token_path,
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        assert_eq!(outcome.response.status, 200);
        assert_eq!(body(&outcome.response), expected["response"]["body"]);
        let actual_hex = outcome
            .response
            .body_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual_hex,
            expected["response"]["body_hex"].as_str().unwrap()
        );
        assert_eq!(outcome.policy_evaluations, 0);
        assert!(outcome.handler_owned && outcome.audit.is_none() && outcome.failure.is_none());
    }
    let unauthenticated = respond_read(
        Request {
            authorization: None,
            ..request("/config")
        },
        &token_path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(unauthenticated.response.status, 401);
    assert_eq!(
        body(&unauthenticated.response),
        json!({"error":"Authorization required","hint":"Bearer <token>"})
    );
    let unavailable = respond_read(
        request("/config"),
        &token_path,
        PolicyState::Unavailable,
        1000.,
    )
    .await;
    assert_eq!(unavailable.response.status, 503);
    assert_eq!(
        body(&unavailable.response),
        json!({"error":"PDP not available"})
    );
    let remote = respond_read(
        request("/config"),
        &token_path,
        PolicyState::NoEngine { healthy: true },
        1000.,
    )
    .await;
    assert_eq!(remote.response.status, 503);
    assert_eq!(remote.failure, Some(Failure::DevelopmentEndpoint));
    let unconfigured = Policy::unconfigured();
    let empty = respond_read(
        request("/config"),
        &token_path,
        PolicyState::Ready(&unconfigured),
        1000.,
    )
    .await;
    assert_eq!(empty.response.status, 200);
    assert_eq!(empty.response.body_bytes(), b"{\"credential_rules\": [], \"scan_patterns\": [], \"addons\": {}, \"policy_hash\": \"sha256:e3b0c44298fc1c14\"}".as_slice());
}

#[tokio::test]
async fn sensor_config_temporal_errors_follow_the_projection_and_preserve_enforcement() {
    let (_dir, token_path) = token();
    for (extra, status) in [
        ("gateway: {unused: 2024-01-01}\n", 200),
        (
            "addons: {credential_guard: {settings: {unused: 2024-01-01}}}\n",
            500,
        ),
    ] {
        let source = format!(
            "permissions:\n  - {{action: 'network:request', resource: '*', effect: budget, budget: 1}}\n{extra}"
        );
        let policy = Policy::parse(&source, Format::Yaml).unwrap();
        let charge = NetworkRequest {
            agent: Some("alice"),
            host: "alpha.invalid",
            port: Some(443),
            method: "GET",
            path: "/",
        };
        assert_eq!(
            policy.evaluate(charge, 1000., true).unwrap().effect,
            Effect::Allow
        );
        let before = policy.budget_stats(1000.).unwrap();
        for identity in [Identity::Resolved("alice"), Identity::Resolved("bob")] {
            let outcome = respond_read(
                Request {
                    identity,
                    ..request("/config")
                },
                &token_path,
                PolicyState::Ready(&policy),
                1000.,
            )
            .await;
            assert_eq!(outcome.response.status, status);
            assert_eq!(outcome.policy_evaluations, 0);
            assert!(outcome.handler_owned && outcome.audit.is_none());
            if status == 500 {
                assert_eq!(
                    outcome.response.body_bytes(),
                    b"{\"error\": \"Internal error: TypeError\"}".as_slice()
                );
                assert_eq!(outcome.failure, Some(Failure::PolicySerialization));
            } else {
                assert_eq!(body(&outcome.response)["addons"], json!({}));
                assert!(outcome.failure.is_none());
            }
            assert_eq!(policy.budget_stats(1000.).unwrap(), before);
        }
        assert_eq!(
            policy.evaluate(charge, 1000., true).unwrap().effect,
            Effect::Allow
        );
        assert_eq!(
            policy.evaluate(charge, 1000., true).unwrap().effect,
            Effect::BudgetExceeded
        );
    }
}

#[tokio::test]
async fn budgets_read_shared_counters_after_auth_without_evaluating_or_charging() {
    let (_dir, token_path) = token();
    let policy = policy(json!({
        "permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":20}],
        "budgets":{"network:request":100}
    }));
    let charge = NetworkRequest {
        agent: Some("alice"),
        host: "alpha.invalid",
        port: Some(443),
        method: "GET",
        path: "/",
    };
    assert_eq!(
        policy.evaluate(charge, 1000., true).unwrap().effect,
        Effect::Allow
    );
    let expected = b"{\"tracked_keys\": 2, \"budgets\": {\"network:request:alpha.invalid\": {\"budget_per_minute\": 20, \"remaining\": 1, \"resource\": \"alpha.invalid\"}, \"network:request:__global__\": {\"budget_per_minute\": 100, \"remaining\": 9, \"resource\": \"__global__\"}}, \"global_budgets\": {\"network:request\": 100}}";
    for identity in [
        Identity::Resolved("alice"),
        Identity::Resolved("bob"),
        Identity::Unavailable,
        Identity::Conflict,
    ] {
        let outcome = respond_read(
            Request {
                identity,
                ..request("/budgets/?agent=forged&host=other.invalid")
            },
            &token_path,
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        assert_eq!(outcome.response.status, 200);
        assert_eq!(outcome.response.body_bytes(), expected.as_slice());
        assert_eq!(outcome.policy_evaluations, 0);
        assert!(outcome.handler_owned && outcome.audit.is_none() && outcome.failure.is_none());
    }
    let unauthenticated = respond_read(
        Request {
            authorization: None,
            ..request("/budgets")
        },
        &token_path,
        PolicyState::Ready(&policy),
        f64::NAN,
    )
    .await;
    assert_eq!(unauthenticated.response.status, 401);
    assert!(unauthenticated.failure.is_none());
    let invalid_clock = respond_read(
        request("/budgets"),
        &token_path,
        PolicyState::Ready(&policy),
        f64::NAN,
    )
    .await;
    assert_eq!(invalid_clock.response.status, 503);
    assert_eq!(invalid_clock.failure, Some(Failure::PolicyEvaluation));
    assert!(!invalid_clock.handler_owned && invalid_clock.scrub_request);
    assert_eq!(
        policy.budget_stats(1000.).unwrap(),
        serde_json::from_slice::<Value>(expected).unwrap()
    );

    let unavailable = respond_read(
        request("/budgets"),
        &token_path,
        PolicyState::Unavailable,
        1000.,
    )
    .await;
    assert_eq!(unavailable.response.status, 503);
    assert_eq!(
        body(&unavailable.response),
        json!({"error":"PDP not available"})
    );
    let remote = respond_read(
        request("/budgets"),
        &token_path,
        PolicyState::NoEngine { healthy: true },
        1000.,
    )
    .await;
    assert_eq!(remote.response.status, 503);
    assert_eq!(remote.failure, Some(Failure::DevelopmentEndpoint));
    let unconfigured = Policy::unconfigured();
    let empty = respond_read(
        request("/budgets"),
        &token_path,
        PolicyState::Ready(&unconfigured),
        1000.,
    )
    .await;
    assert_eq!(empty.response.status, 200);
    assert_eq!(
        empty.response.body_bytes(),
        b"{\"tracked_keys\": 0, \"budgets\": {}, \"global_budgets\": {}}".as_slice()
    );
}

#[tokio::test]
async fn budget_report_errors_are_local_handler_responses_and_leave_counters_intact() {
    use num_bigint::BigInt;
    let (_dir, token_path) = token();
    let policy = policy(
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":20}]}),
    );
    let charge = NetworkRequest {
        agent: Some("alice"),
        host: "alpha.invalid",
        port: Some(443),
        method: "GET",
        path: "/",
    };
    assert_eq!(
        policy.evaluate(charge, 1_000_000., true).unwrap().effect,
        Effect::Allow
    );
    let original = policy.budget_stats(1_000_000.).unwrap();
    for (rate, now) in [
        (BigInt::from(10u8).pow(400), 1_000_000.),
        (BigInt::from(2u8).pow(1023), 1_600_000.),
    ] {
        let source = format!(
            r#"{{"permissions":[{{"action":"network:request","resource":"*","effect":"allow","budget":{rate},"condition":{{}}}}]}}"#
        );
        let replacement = policy
            .reload_from_source_at(&source, Format::Json, 1_000_000.)
            .unwrap();
        let outcome = respond_read(
            request("/budgets"),
            &token_path,
            PolicyState::Ready(&replacement),
            now,
        )
        .await;
        assert_eq!(outcome.response.status, 500);
        assert_eq!(
            outcome.response.body_bytes(),
            b"{\"error\": \"Internal error: OverflowError\"}".as_slice()
        );
        assert_eq!(outcome.failure, Some(Failure::BudgetReporting));
        assert_eq!(outcome.blocked_by, "agent-api");
        assert_eq!(outcome.policy_evaluations, 0);
        assert!(outcome.handler_owned && outcome.audit.is_none());
        assert_eq!(policy.budget_stats(1_000_000.).unwrap(), original);
    }
    // Both policy cores accept this direct input and fail while rematching its
    // retained key. This does not assert HTTP authority parser admission.
    assert_eq!(
        policy
            .evaluate(
                NetworkRequest {
                    host: "bad:port",
                    ..charge
                },
                1_000_000.,
                true
            )
            .unwrap()
            .effect,
        Effect::Allow
    );
    let invalid_key = respond_read(
        request("/budgets"),
        &token_path,
        PolicyState::Ready(&policy),
        1_000_000.,
    )
    .await;
    assert_eq!(invalid_key.response.status, 500);
    assert_eq!(
        invalid_key.response.body_bytes(),
        b"{\"error\": \"Internal error: ValueError\"}".as_slice()
    );
    assert_eq!(invalid_key.failure, Some(Failure::BudgetReporting));
    assert!(invalid_key.handler_owned && invalid_key.audit.is_none());
    // A request preview reports the allowance after its hypothetical charge.
    assert_eq!(
        policy
            .evaluate(charge, 1_000_000., false)
            .unwrap()
            .budget_remaining,
        Some(0)
    );
}

#[tokio::test]
async fn budgets_do_not_serialize_unrelated_temporal_baseline_values() {
    let (_dir, token_path) = token();
    let policy = Policy::parse(
        "addons:\n  fixture:\n    settings:\n      observed: 2001-02-03\n",
        Format::Yaml,
    )
    .unwrap();
    let outcome = respond_read(
        request("/budgets"),
        &token_path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(outcome.response.status, 200);
    assert_eq!(
        outcome.response.body_bytes(),
        b"{\"tracked_keys\": 0, \"budgets\": {}, \"global_budgets\": {}}".as_slice()
    );
    assert!(outcome.failure.is_none());
    let policy_read = respond_read(
        request("/policy"),
        &token_path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(policy_read.response.status, 500);
    assert_eq!(policy_read.failure, Some(Failure::PolicySerialization));
}

#[tokio::test]
async fn policy_reads_borrow_the_loaded_baseline_without_identity_filter_or_budget_charge() {
    let (_dir, token_path) = token();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.json");
    let document = json!({
        "permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}],
        "addons":{"fixture":{"settings":{"float":1e16,"unicode":"é😀"}}},
        "gateway":{"token_map":{"synthetic-display-only":{"agent":"alice"}}},
    });
    std::fs::write(&path, document.to_string()).unwrap();
    let policy = Policy::from_path(&path).unwrap();
    // Reads use the loaded view even after its source has become unavailable.
    std::fs::remove_file(&path).unwrap();
    for identity in [
        Identity::Resolved("alice"),
        Identity::Resolved("bob"),
        Identity::Unavailable,
        Identity::Conflict,
    ] {
        let outcome = respond_read(
            Request {
                identity,
                ..request("/policy?agent=forged")
            },
            &token_path,
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        assert_eq!(outcome.response.status, 200);
        assert_eq!(outcome.policy_evaluations, 0);
        assert!(outcome.audit.is_none() && outcome.failure.is_none());
        let actual = body(&outcome.response);
        assert!(
            actual["policy"]["gateway"] == document["gateway"],
            "response must preserve the authorized gateway view"
        );
        assert_eq!(actual["policy"]["permissions"][0]["budget"], 1);
        assert_eq!(
            actual["policy"]["addons"]["fixture"]["settings"],
            document["addons"]["fixture"]["settings"]
        );
        let bytes = outcome.response.body_bytes();
        assert!(bytes.windows(b"1e+16".len()).any(|bytes| bytes == b"1e+16"));
        assert!(
            bytes
                .windows(b"synthetic-display-only".len())
                .any(|bytes| bytes == b"synthetic-display-only")
        );
    }
    let lookup = respond_read(
        request("/lookup?host=api.invalid"),
        &token_path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(body(&lookup.response)["effect"], "allow");
    let unconfigured = Policy::unconfigured();
    let null_baseline = respond_read(
        request("/policy"),
        &token_path,
        PolicyState::Ready(&unconfigured),
        1000.,
    )
    .await;
    assert_eq!(null_baseline.response.status, 200);
    assert_eq!(body(&null_baseline.response), json!({"policy":null}));
    let missing = respond_read(
        request("/policy"),
        &token_path,
        PolicyState::Unavailable,
        1000.,
    )
    .await;
    assert_eq!(missing.response.status, 503);
    assert_eq!(
        body(&missing.response),
        json!({"error":"PDP not available"})
    );
    let no_auth = respond_read(
        Request {
            authorization: None,
            ..request("/policy")
        },
        &token_path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(no_auth.response.status, 401);
    assert!(
        !no_auth
            .response
            .body_bytes()
            .windows(b"synthetic-display-only".len())
            .any(|bytes| bytes == b"synthetic-display-only")
    );
}

#[tokio::test]
async fn policy_yaml_timestamps_preserve_source_load_and_response_failures() {
    let (_dir, path) = token();
    for (source, expected) in [
        (
            "addons:\n  fixture:\n    settings:\n      observed: 2001-02-03\n",
            500,
        ),
        (
            "addons:\n  fixture:\n    settings:\n      observed: 2001-02-03T04:05:06Z\n",
            500,
        ),
        (
            "addons:\n  fixture:\n    settings:\n      observed: {2001-02-03: public}\n",
            500,
        ),
        (
            "addons:\n  fixture:\n    settings:\n      observed: '2001-02-03'\n",
            200,
        ),
        (
            "addons:\n  fixture:\n    settings:\n      observed: {yaml_date: '2001-02-03'}\n",
            200,
        ),
        ("ignored: 2001-02-03\n", 200),
    ] {
        let policy = Policy::parse(source, Format::Yaml).unwrap();
        let outcome = respond_read(
            request("/policy"),
            &path,
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        assert_eq!(outcome.response.status, expected);
        assert!(outcome.handler_owned && outcome.audit.is_none());
        assert_eq!(outcome.policy_evaluations, 0);
        if expected == 500 {
            assert_eq!(
                outcome.response.body_bytes(),
                b"{\"error\": \"Internal error: TypeError\"}".as_slice()
            );
            assert_eq!(outcome.failure, Some(Failure::PolicySerialization));
        } else {
            assert!(outcome.failure.is_none());
        }
    }
    for source in [
        "metadata: {created: 2001-02-03}\n",
        "metadata: {created: 2001-02-03T04:05:06Z}\n",
    ] {
        assert!(Policy::parse(source, Format::Yaml).is_err());
    }
}

#[tokio::test]
async fn token_reads_rotate_preserve_source_whitespace_and_auth_failure_containment() {
    let (_dir, path) = token();
    let policy = allow();
    for (method, authorization, status, allowed) in [
        ("HEAD", None, 405, json!(["GET", "POST", "DELETE"])),
        ("POST", None, 405, json!(["GET"])),
        ("DELETE", None, 405, json!(["GET"])),
    ] {
        let outcome = respond_read(
            Request {
                method,
                authorization,
                ..request("/health")
            },
            Path::new("/nonexistent-fixture-path"),
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        assert_eq!(outcome.response.status, status);
        assert_eq!(body(&outcome.response)["allowed"], allowed);
    }
    let outcome = respond_read(
        Request {
            authorization: None,
            ..request("/health")
        },
        &path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(outcome.response.status, 401);
    assert!(outcome.audit.is_none());
    for (bytes, auth, status, failure) in [
        (
            format!("\x1f \r\n{TOKEN}\u{2003}\x1c").into_bytes(),
            AUTH.to_vec(),
            200,
            None,
        ),
        (b"synthetic-new-token".to_vec(), AUTH.to_vec(), 401, None),
        (
            b"synthetic-new-token".to_vec(),
            b"Bearer synthetic-new-token".to_vec(),
            200,
            None,
        ),
        (b" \n".to_vec(), AUTH.to_vec(), 503, None),
        (vec![255], AUTH.to_vec(), 503, Some(Failure::TokenEncoding)),
        (
            TOKEN.as_bytes().to_vec(),
            "Bearer é".as_bytes().to_vec(),
            503,
            Some(Failure::AuthenticationEncoding),
        ),
        (
            TOKEN.as_bytes().to_vec(),
            [AUTH, b", ", AUTH].concat(),
            401,
            None,
        ),
        (
            b"synthetic\r\ntoken".to_vec(),
            b"Bearer synthetic\ntoken".to_vec(),
            200,
            None,
        ),
    ] {
        std::fs::write(&path, bytes).unwrap();
        let req = Request {
            authorization: Some(&auth),
            ..request("/health?ignored=private-query-placeholder")
        };
        let outcome = respond_read(req, &path, PolicyState::Ready(&policy), 1000.).await;
        assert_eq!(outcome.response.status, status);
        assert_eq!(outcome.failure, failure);
        if status == 401 {
            assert_eq!(
                outcome.audit.as_ref().unwrap().kind,
                AuditKind::AuthenticationFailed
            );
            let outcome = outcome.audit_failed(req);
            assert_eq!(outcome.response.status, 503);
            assert_eq!(outcome.failure, Some(Failure::AuditWrite));
            assert!(outcome.scrub_request);
            assert!(!outcome.handler_owned);
            assert_eq!(body(&outcome.response)["path"], "/health");
            assert!(
                !outcome
                    .response
                    .body_bytes()
                    .windows(TOKEN.len())
                    .any(|bytes| bytes == TOKEN.as_bytes())
            );
            assert_eq!(outcome.audit_failed(req).response.status, 503);
        }
    }
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        respond_read(
            request("/health"),
            &path,
            PolicyState::Ready(&policy),
            1000.
        )
        .await
        .response
        .status,
        503
    );
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        respond_read(
            request("/health"),
            &path,
            PolicyState::Ready(&policy),
            1000.
        )
        .await
        .response
        .body_bytes(),
        br#"{"error": "Agent token not configured"}"#.as_slice()
    );
}

#[tokio::test]
async fn trusted_identity_and_route_query_contracts_use_the_shared_policy() {
    let (_dir, path) = token();
    let policy = policy(json!({"permissions":[
        {"action":"network:request","resource":"*","effect":"deny","condition":{"agent":"bob"}},
        {"action":"network:request","resource":"*","effect":"allow"}]}));
    for (identity, expected) in [
        (Identity::Resolved("alice"), Some("allow")),
        (Identity::Resolved("bob"), Some("deny")),
        (Identity::Unavailable, None),
        (Identity::Conflict, None),
    ] {
        let outcome = respond_read(
            Request {
                identity,
                ..request("/lookup?host=api.invalid&agent=alice&client=alice")
            },
            &path,
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        if let Some(expected) = expected {
            assert_eq!(body(&outcome.response)["effect"], expected);
            assert_eq!(outcome.policy_evaluations, 1);
        } else {
            assert_eq!(outcome.response.status, 403);
            assert_eq!(outcome.policy_evaluations, 0);
        }
        let outcome = respond_read(
            Request {
                identity,
                ..request("/health///?unused=1")
            },
            &path,
            PolicyState::Ready(&policy),
            1000.,
        )
        .await;
        assert_eq!(
            outcome.response.body_bytes(),
            br#"{"agent_api": "ok", "pdp": "ok"}"#.as_slice()
        );
    }
    for (query, port, method, expected_path) in [
        ("host=api.invalid&method=connect", 443, "CONNECT", ""),
        ("host=api.invalid&method=&path=", 443, "", ""),
        (
            "host=api.invalid&scheme=ws&path=%2Fa%3Fx%3D%252F%26q%3D1",
            80,
            "GET",
            "/a?x=%2F&q=1",
        ),
        (
            "host=api.invalid&port=1_000&method=stra%C3%9Fe",
            1000,
            "STRASSE",
            "/",
        ),
        (
            "host=api.invalid&port=%EF%BC%94%EF%BC%94%EF%BC%93",
            443,
            "GET",
            "/",
        ),
    ] {
        let raw = format!("/lookup?{query}");
        let outcome = respond_read(request(&raw), &path, PolicyState::Ready(&policy), 1000.).await;
        assert_eq!(outcome.response.status, 200);
        assert_eq!(body(&outcome.response)["port"], port);
        assert_eq!(body(&outcome.response)["method"], method);
        assert_eq!(body(&outcome.response)["path"], expected_path);
    }
    let outcome = respond_read(
        request("/lookup?host=&host=api.invalid"),
        &path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(outcome.response.status, 400);
    let outcome = respond_read(
        request("/status"),
        &path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(outcome.failure, Some(Failure::DevelopmentEndpoint));
    let outcome = respond_read(
        request("/%68ealth"),
        &path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(outcome.response.status, 404);
}

#[tokio::test]
async fn source_surrogate_queries_are_explicit_and_unused_fields_do_not_poison_lookup() {
    let (_dir, path) = token();
    let policy = allow();
    for query in [
        "host=%ff.invalid",
        "host=api.invalid&method=%ff",
        "host=api.invalid&path=%ff",
        "host=api.invalid&port=%ff",
    ] {
        let raw = format!("/lookup?{query}");
        let outcome = respond_read(request(&raw), &path, PolicyState::Ready(&policy), 1000.).await;
        assert_eq!(outcome.failure, Some(Failure::QueryCompatibility));
        assert_eq!(outcome.response.status, 503);
        assert_eq!(outcome.policy_evaluations, 0);
        assert!(outcome.scrub_request);
    }
    for query in [
        "host=api.invalid&unknown=%ff",
        "host=api.invalid&%ff=ignored",
        "host=api.invalid&host=%ff",
    ] {
        let raw = format!("/lookup?{query}");
        let outcome = respond_read(request(&raw), &path, PolicyState::Ready(&policy), 1000.).await;
        assert_eq!(outcome.response.status, 200);
        assert_eq!(body(&outcome.response)["host"], "api.invalid");
    }
    let outcome = respond_read(
        Request {
            identity: Identity::Unavailable,
            ..request("/lookup?host=%ff.invalid")
        },
        &path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(outcome.response.status, 403);
    assert_eq!(outcome.failure, None);
}

#[tokio::test]
async fn policy_method_conditions_share_pinned_uppercase() {
    let (_dir, path) = token();
    let policy = policy(json!({"permissions":[
        {"action":"network:request","resource":"*","effect":"allow","condition":{"method":["GET","STRASSE","\u{1c89}"]}},
        {"action":"network:request","resource":"*","effect":"deny"}
    ]}));
    for (method, expected_method, effect) in [
        ("get", "GET", "allow"),
        ("stra%C3%9Fe", "STRASSE", "allow"),
        ("%E1%B2%89", "\u{1c89}", "allow"),
        ("%E1%B2%8A", "\u{1c8a}", "deny"),
        ("post", "POST", "deny"),
    ] {
        let raw = format!("/lookup?host=api.invalid&method={method}");
        let outcome = respond_read(request(&raw), &path, PolicyState::Ready(&policy), 1000.).await;
        assert_eq!(body(&outcome.response)["method"], expected_method);
        assert_eq!(body(&outcome.response)["effect"], effect);
    }
}

#[tokio::test]
async fn concurrent_previews_do_not_charge_and_reload_keeps_consumed_budget() {
    let (_dir, path) = token();
    let document = json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1}],"budgets":{"network:request":1}});
    let policy = Arc::new(policy(document.clone()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..40 {
        let path = path.clone();
        let policy = policy.clone();
        tasks.spawn(async move {
            let outcome = respond_read(
                request("/lookup?host=limited.invalid"),
                &path,
                PolicyState::Ready(&policy),
                1000.,
            )
            .await;
            assert_eq!(body(&outcome.response)["effect"], "allow");
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let charge = NetworkRequest {
        agent: Some("alice"),
        host: "limited.invalid",
        port: Some(443),
        method: "GET",
        path: "/",
    };
    assert_eq!(
        policy.evaluate(charge, 1000., true).unwrap().effect,
        Effect::Allow
    );
    assert_eq!(
        policy.evaluate(charge, 1000., true).unwrap().effect,
        Effect::Allow
    );
    assert_eq!(
        policy.evaluate(charge, 1000., true).unwrap().effect,
        Effect::BudgetExceeded
    );
    let reloaded = policy
        .reload_from_source_at(&document.to_string(), Format::Json, 1000.)
        .unwrap();
    let outcome = respond_read(
        request("/lookup?host=limited.invalid"),
        &path,
        PolicyState::Ready(&reloaded),
        1000.,
    )
    .await;
    assert_eq!(body(&outcome.response)["effect"], "budget_exceeded");
    assert_eq!(
        body(&outcome.response)["reason"],
        "Request budget exceeded for limited.invalid"
    );
    let outcome = respond_read(
        request("/lookup?host=limited.invalid&method=CONNECT"),
        &path,
        PolicyState::Ready(&reloaded),
        1000.,
    )
    .await;
    assert_eq!(body(&outcome.response)["effect"], "allow");
    let reloaded = reloaded
        .reload_from_source_at(r#"{"permissions":[]}"#, Format::Json, 1000.)
        .unwrap();
    let outcome = respond_read(
        request("/lookup?host=limited.invalid"),
        &path,
        PolicyState::Ready(&reloaded),
        1000.,
    )
    .await;
    assert_eq!(body(&outcome.response)["effect"], "deny");
    assert_eq!(
        body(&outcome.response)["reason"],
        "No matching permission (default deny)"
    );
}

fn oracle_cases() -> Vec<Value> {
    let mut rows = Vec::new();
    for path in [
        "/health",
        "/health///?ignored=1",
        "/Health",
        "/%68ealth",
        "/",
        "//health",
        "/unknown",
    ] {
        for auth in [
            "valid",
            "missing",
            "invalid",
            "lowercase",
            "unicode",
            "duplicate",
        ] {
            rows.push(json!({"path":path,"auth":auth}));
        }
    }
    for method in ["HEAD", "POST", "DELETE", "PUT", "OPTIONS"] {
        rows.push(json!({"path":"/health","method":method,"auth":"missing"}));
    }
    for state in [
        "missing",
        "empty",
        "directory",
        "whitespace",
        "invalid_utf8",
        "rotated",
    ] {
        rows.push(json!({"path":"/health","token_state":state}));
    }
    for state in ["missing", "no_engine", "unhealthy"] {
        for route in ["health", "lookup"] {
            rows.push(json!({"path":format!("/{route}?host=api.invalid"),"state":state}));
        }
    }
    for agent in ["alice", "bob", "unavailable", "conflict"] {
        for query in [
            "host=scoped.invalid&agent=alice",
            "host=",
            "host=api.invalid&port=bad",
        ] {
            rows.push(json!({"path":format!("/lookup?{query}"),"agent":agent}));
        }
    }
    for query in [
        "",
        "host",
        "host=&host=allowed.invalid",
        "host=allowed.invalid&host=denied.invalid",
        "host=prompt.invalid",
        "host=allowed.invalid&method=connect",
        "host=allowed.invalid&method=&path=",
        "host=allowed.invalid&method=stra%C3%9Fe",
        "host=%D0%B0pi.invalid",
        "host=+",
        "host=https%3A%2F%2Fallowed.invalid%2F",
        "host=allowed.invalid&path=%2Fa%3Fq%3D%252F%26x%3D1",
        "host=allowed.invalid&path=%GG%2",
        "host=allowed.invalid&ignored=%ff",
        "host=allowed.invalid&host=%ff",
        "host=allowed.invalid&scheme=HTTP",
        "host=allowed.invalid&scheme=ws",
        "host=allowed.invalid&scheme=wss",
        "host=allowed.invalid&scheme=ftp",
        "host=allowed.invalid&port=0",
        "host=allowed.invalid&port=65536",
        "host=allowed.invalid&port=-1",
        "host=allowed.invalid&port=abc",
        "host=allowed.invalid&port=",
        "host=allowed.invalid&port=1.0",
        "host=allowed.invalid&port=1_000",
        "host=allowed.invalid&port=%2B443",
        "host=allowed.invalid&port=%20%20443%20",
        "host=allowed.invalid&port=%EF%BC%94%EF%BC%94%EF%BC%93",
        "host=allowed.invalid&port=%D9%A1%D9%A2",
        "host=allowed.invalid&port=443%1f",
        "host=allowed.invalid&port=%27%22%5C%00",
        "host=allowed.invalid&port=%E0%A4%BF", // printable combining mark
        "host=allowed.invalid&port=%E2%80%83%34%34%33%E2%80%83",
        "host=allowed.invalid#ignored=fragment",
    ] {
        rows.push(json!({"path":format!("/lookup?{query}")}));
    }
    for n in [200, 4300, 4301] {
        rows.push(json!({"path":format!("/lookup?host=allowed.invalid&port={}","1".repeat(n))}));
    }
    rows.push(json!({"path":"/health","auth":"invalid","audit_failure":true}));
    rows
}

#[tokio::test]
#[ignore = "requires existing Python production environment; set SAFEYOLO_POLICY_PYTHON"]
async fn exact_read_responses_match_actual_python_handlers() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let rows = oracle_cases();
    let document = json!({"permissions":[
        {"action":"network:request","resource":"scoped.invalid/*","effect":"allow","condition":{"agent":"alice"}},
        {"action":"network:request","resource":"scoped.invalid/*","effect":"deny","condition":{"agent":"bob"}},
        {"action":"network:request","resource":"allowed.invalid/*","effect":"allow"},
        {"action":"network:request","resource":"prompt.invalid/*","effect":"prompt"},
        {"action":"network:request","resource":"*","effect":"deny"}]});
    let script = r#"
import asyncio,json,logging,os,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mitmproxy.test import taddons,tflow
from pdp.client import LocalPolicyClient,PolicyClientConfig
from safeyolo.mitm_addons import agent_api,agent_api_guard
from safeyolo.policy.loader import PolicyLoader
from safeyolo.proxy_modes.unix_listener import UnixMode
logging.disable(logging.CRITICAL)
data=json.load(sys.stdin); output=[]
async def run():
 with tempfile.TemporaryDirectory() as temp, patch.object(PolicyLoader,'start_watcher'), patch.object(agent_api_guard,'write_event'):
  os.environ['SAFEYOLO_DATA_DIR']=temp; os.environ['SAFEYOLO_LOG_PATH']=temp+'/audit'
  baseline=Path(temp)/'policy.json'; baseline.write_text(json.dumps(data['document']))
  with patch('safeyolo.policy.loader.write_event'):
   client=LocalPolicyClient(PolicyClientConfig(baseline_path=baseline))
  api=agent_api.AgentAPI()
  with taddons.context(api) as ctx:
   for row in data['rows']:
    token=Path(temp)/'agent_token'; state=row.get('token_state','valid')
    if token.is_dir(): token.rmdir()
    else: token.unlink(missing_ok=True)
    if state=='directory': token.mkdir()
    elif state!='missing': token.write_bytes({'valid':b'synthetic-agent-api-fixture','empty':b' \n','whitespace':b'\x1f synthetic-agent-api-fixture\xe2\x80\x83\x1c','invalid_utf8':b'\xff','rotated':b'synthetic-new-token'}[state])
    flow=tflow.tflow(); flow.request.method=row.get('method','GET'); flow.request.url='http://_safeyolo.proxy.internal/'
    # The native seam receives parsed request.path, not Request.url setter input.
    flow.request.path=row['path']
    flow.request.headers.clear(); flow.client_conn.peername=('10.0.0.5',45678)
    flow.metadata['request_id']='req-00000000000000000000000000000001'
    who=row.get('agent','alice')
    if who!='unavailable': flow.client_conn.proxy_mode=UnixMode.parse('unix:/tmp/10.0.0.5_'+('alice' if who=='conflict' else who)+'/proxy.sock')
    if who=='conflict': flow.metadata['agent']='bob'
    auth=row.get('auth','valid'); headers={'valid':['Bearer synthetic-agent-api-fixture'],'invalid':['Bearer synthetic-invalid'],'missing':[],'lowercase':['bearer synthetic-agent-api-fixture'],'unicode':['Bearer é'],'duplicate':['Bearer synthetic-agent-api-fixture']*2}
    flow.request.headers.set_all('authorization',headers[auth]); events=[]
    dependency={'ready':client,'missing':None,'no_engine':SimpleNamespace(health_check=lambda:True),'unhealthy':SimpleNamespace(health_check=lambda:False)}[row.get('state','ready')]
    def audit(event,**fields):
     if row.get('audit_failure'): raise OSError('synthetic failure')
     events.append({'event':event,'details':fields['details']})
    with patch.object(api,'_get_policy_client',return_value=dependency),patch.object(api,'_find_addon',return_value=None),patch.object(agent_api,'write_event',side_effect=audit),patch.object(agent_api_guard,'write_event',side_effect=lambda e,**f:events.append({'event':e,'details':f['details']})):
     try: await api.request(flow)
     except (TypeError,UnicodeDecodeError,OSError): pass
     agent_api_guard.AgentAPIRequestGuard().request(flow)
    output.append({'status':flow.response.status_code,'body_hex':flow.response.content.hex(),'blocked_by':flow.metadata['blocked_by'],'owned':flow.metadata.get('safeyolo_agent_api_response') is True,'events':events})
  client.shutdown()
asyncio.run(run()); print(json.dumps(output))
"#;
    let mut child =
        Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"))
            .current_dir(root)
            .env("PYTHONPATH", "cli/src:.")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({"document":document,"rows":rows})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let expected: Vec<Value> = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(expected.len(), rows.len());
    let (_dir, path) = token();
    let policy = policy(document);
    for (row, expected) in rows.iter().zip(expected) {
        if path.is_dir() {
            std::fs::remove_dir(&path).unwrap();
        } else {
            let _ = std::fs::remove_file(&path);
        }
        match row["token_state"].as_str().unwrap_or("valid") {
            "missing" => (),
            "directory" => std::fs::create_dir(&path).unwrap(),
            state => std::fs::write(
                &path,
                match state {
                    "empty" => b" \n".to_vec(),
                    "whitespace" => format!("\x1f {TOKEN}\u{2003}\x1c").into_bytes(),
                    "invalid_utf8" => vec![255],
                    "rotated" => b"synthetic-new-token".to_vec(),
                    _ => TOKEN.as_bytes().to_vec(),
                },
            )
            .unwrap(),
        }
        let auth = match row["auth"].as_str().unwrap_or("valid") {
            "missing" => None,
            "invalid" => Some(b"Bearer synthetic-invalid".to_vec()),
            "lowercase" => Some(b"bearer synthetic-agent-api-fixture".to_vec()),
            "unicode" => Some("Bearer é".as_bytes().to_vec()),
            "duplicate" => Some([AUTH, b", ", AUTH].concat()),
            _ => Some(AUTH.to_vec()),
        };
        let req = Request {
            method: row["method"].as_str().unwrap_or("GET"),
            authorization: auth.as_deref(),
            identity: match row["agent"].as_str().unwrap_or("alice") {
                "unavailable" => Identity::Unavailable,
                "conflict" => Identity::Conflict,
                agent => Identity::Resolved(agent),
            },
            ..request(row["path"].as_str().unwrap())
        };
        let state = match row["state"].as_str().unwrap_or("ready") {
            "missing" => PolicyState::Unavailable,
            "no_engine" => PolicyState::NoEngine { healthy: true },
            "unhealthy" => PolicyState::NoEngine { healthy: false },
            _ => PolicyState::Ready(&policy),
        };
        let mut outcome = respond_read(req, &path, state, 1000.).await;
        if row["audit_failure"].as_bool() == Some(true) {
            outcome = outcome.audit_failed(req);
        }
        let events: Vec<Value> = outcome
            .audit
            .as_ref()
            .map(|audit| json!({"event":audit.event,"details":audit.details}))
            .into_iter()
            .collect();
        let actual = json!({"status":outcome.response.status,"body_hex":outcome.response.body_bytes().iter().map(|byte|format!("{byte:02x}")).collect::<String>(),"blocked_by":outcome.blocked_by,"owned":outcome.handler_owned,"events":events});
        assert_eq!(actual, expected, "case={row}");
    }
    eprintln!(
        "Compared {} source AgentAPI method/auth/query/response cases",
        rows.len()
    );
}

#[tokio::test]
#[ignore = "requires existing Python production environment; set SAFEYOLO_POLICY_PYTHON"]
async fn policy_method_unicode_version_matches_source() {
    // Unicode 16 added Cyrillic Tje case pairs. Source Python 3.12/Unicode 15
    // treats both code points as distinct unassigned characters. The facade's
    // returned method and the one shared Policy matcher must both preserve that
    // behavior. Newer Rust uppercase previously changed this denial to allow.
    let document = json!({"permissions":[
        {"action":"network:request","resource":"*","effect":"allow","condition":{"method":"\u{1c89}"}},
        {"action":"network:request","resource":"*","effect":"deny"}
    ]});
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let script = r#"
import json,os,tempfile
from pathlib import Path
from unittest.mock import patch
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.loader import PolicyLoader
with tempfile.TemporaryDirectory() as temp,patch.object(PolicyLoader,'start_watcher'),patch('safeyolo.policy.loader.write_event'):
 os.environ['SAFEYOLO_LOG_PATH']=temp+'/audit'
 path=Path(temp)/'policy.json'
 path.write_text(json.dumps({'permissions':[{'action':'network:request','resource':'*','effect':'allow','condition':{'method':'\u1c89'}},{'action':'network:request','resource':'*','effect':'deny'}]}))
 engine=PolicyEngine(baseline_path=path)
 print(json.dumps({'effect':engine.evaluate_request('api.invalid',agent='alice',port=443,method='\u1c8a',consume_budget=False).effect,'method':'\u1c8a'.upper()}))
 engine.done()
"#;
    let output = std::process::Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").unwrap())
        .current_dir(root)
        .env("PYTHONPATH", "cli/src:.")
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(output.status.success());
    let source: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(source, json!({"effect":"deny","method":"\u{1c8a}"}));
    let (_dir, path) = token();
    let policy = policy(document);
    let outcome = respond_read(
        request("/lookup?host=api.invalid&method=%E1%B2%8A"),
        &path,
        PolicyState::Ready(&policy),
        1000.,
    )
    .await;
    assert_eq!(body(&outcome.response)["method"], source["method"]);
    assert_eq!(
        body(&outcome.response)["effect"],
        source["effect"],
        "the shared matcher must preserve pinned Python case semantics"
    );
    eprintln!(
        "Policy Unicode regression: source/native deny for method U+1C8A vs condition U+1C89; API method bytes agree"
    );
}
