//! The authenticated trace route uses the same store as reached request steps.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{
        self, BodyObservation, Controls, Outcome, PolicyState, Request, RequestBody, TraceContext,
    },
    circuits::CircuitValue,
    network_guard::Identity,
    tasks::Registry,
    trace::{Settings, Step, TraceStore},
};
use serde::Deserialize;
use serde_json::{Value, json};

const RID: &str = "req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN: &str = "synthetic-trace-api";
const AUTH: &[u8] = b"Bearer synthetic-trace-api";

// The source's diagnostic query_pairs can contain Python lone surrogates.
// Keep only the real API response fields needed here; the fixture stays intact.
#[derive(Deserialize)]
struct SourceFixture {
    rows: Vec<SourceRow>,
}
#[derive(Deserialize)]
struct SourceRow {
    input: Value,
    steps: Vec<SourceStep>,
}
#[derive(Deserialize)]
struct SourceStep {
    api: Option<SourceResponse>,
}
#[derive(Deserialize)]
struct SourceResponse {
    status: u16,
    body_text: String,
}

struct Unread;
impl Body for Unread {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        panic!("trace reads must not poll request content");
    }
}

async fn call(
    input: Request<'_>,
    token: &std::path::Path,
    store: Option<&TraceStore>,
    now: f64,
) -> Outcome<'static> {
    call_with_clock(input, token, store, now * 1000.0, &|| now).await
}

async fn call_with_clock(
    input: Request<'_>,
    token: &std::path::Path,
    store: Option<&TraceStore>,
    admission_ms: f64,
    now: &(dyn Fn() -> f64 + Sync),
) -> Outcome<'static> {
    let mut body = Unread;
    let mut observation = BodyObservation::default();
    let outcome = agent_api::respond_with_body(
        input,
        token,
        PolicyState::Unavailable,
        &Registry::default(),
        admission_ms,
        Controls {
            gateway: None,
            memory: None,
            traces: store.map(|store| TraceContext { store, now }),
            discovery: None,
            audit: None,
            flows: None,
            circuits: None,
            declarations: None,
        },
        RequestBody {
            body: &mut body,
            content_encoding: b"invalid-coding",
            content_length: Some(50),
            observation: Some(&mut observation),
        },
    )
    .await
    .unwrap();
    assert!(observation.encoded_size.is_none() && observation.decoded_size.is_none());
    assert_eq!(outcome.policy_evaluations, 0);
    outcome
}

fn request(path: &str) -> Request<'_> {
    Request {
        method: "GET",
        path_and_query: path,
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: None,
        request_id: "native-query-id",
    }
}

fn step(value: &Value, now: f64) -> Step {
    let string = |key| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let integer = |key| {
        value
            .get(key)
            .filter(|value| !value.is_null())
            .map(|value| value.to_string().parse().unwrap())
    };
    Step {
        addon: string("addon").unwrap(),
        hook: string("hook").unwrap(),
        state: string("state").unwrap(),
        outcome: string("outcome"),
        reason: string("reason"),
        duration_us: integer("duration_us"),
        details: value
            .get("details")
            .filter(|value| !value.is_null())
            .map(|value| CircuitValue::from(value.clone())),
        ts: value.get("ts").and_then(Value::as_f64).unwrap_or(now),
        connection_id: string("connection_id"),
        method: string("method"),
        host: string("host"),
        port: integer("port"),
    }
}

fn settings(value: &Value) -> Settings {
    let mut settings = Settings::default();
    if let Some(value) = value.get("ttl_s") {
        settings.ttl_s = value.clone().into();
    }
    for (key, target) in [
        ("global_max", &mut settings.global_max),
        ("per_agent_max", &mut settings.per_agent_max),
        ("steps_max", &mut settings.steps_max),
        ("details_max_bytes", &mut settings.details_max_bytes),
    ] {
        if let Some(value) = value.get(key) {
            *target = value.to_string().parse().unwrap();
        }
    }
    settings
}

#[tokio::test]
async fn expiry_samples_at_lookup_after_auth_id_and_owner_guards() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, TOKEN).unwrap();
    let store = TraceStore::new(Settings::default());
    store
        .append(
            RID,
            Some("alice"),
            Step::new("network-guard", "request", "evaluated", 1000.0),
            1000.0,
        )
        .unwrap();
    let samples = AtomicUsize::new(0);
    let clock = || {
        samples.fetch_add(1, Ordering::Relaxed);
        1301.0
    };
    let path = format!("/trace?request_id={RID}");
    for (input, status) in [
        (
            Request {
                authorization: None,
                ..request(&path)
            },
            401,
        ),
        (request("/trace"), 400),
        (
            Request {
                identity: Identity::Unavailable,
                ..request(&path)
            },
            403,
        ),
    ] {
        assert_eq!(
            call_with_clock(input, &token, Some(&store), 1_000_000.0, &clock)
                .await
                .response
                .status,
            status
        );
        assert_eq!(samples.load(Ordering::Relaxed), 0);
    }
    // Admission's old clock would retain this record. Lookup's reached clock expires it.
    assert_eq!(
        call_with_clock(request(&path), &token, Some(&store), 1_000_000.0, &clock)
            .await
            .response
            .status,
        404
    );
    assert_eq!(samples.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn actual_source_api_cases_preserve_order_ownership_query_and_error_bytes() {
    let fixture: SourceFixture = serde_json::from_str(include_str!("trace_source.json")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, TOKEN).unwrap();
    let mut calls = 0;
    for row in &fixture.rows {
        let input = &row.input;
        let operations = input["steps"].as_array().unwrap();
        if !operations.iter().any(|operation| operation["op"] == "api") {
            continue;
        }
        let store = TraceStore::new(settings(&input["settings"]));
        for (operation, expected) in operations.iter().zip(&row.steps) {
            let now = operation["now"].as_f64().unwrap();
            let agent = operation.get("agent").map_or(Some("alice"), Value::as_str);
            let rid = operation["rid"].as_str().unwrap_or(RID);
            match operation["op"].as_str().unwrap() {
                "append" => {
                    store
                        .append(rid, agent, step(&operation["step"], now), now)
                        .unwrap();
                }
                "api" => {
                    let expected = expected.api.as_ref().unwrap();
                    let default_path = format!("/trace?request_id={RID}");
                    let path = operation["path"].as_str().unwrap_or(&default_path);
                    let authorization = match operation["auth"].as_str().unwrap_or("valid") {
                        "valid" => Some(AUTH),
                        "missing" => None,
                        "invalid" => Some(b"Bearer wrong-synthetic-token".as_slice()),
                        other => panic!("unexpected source auth {other}"),
                    };
                    let outcome = call(
                        Request {
                            method: operation["method"].as_str().unwrap_or("GET"),
                            authorization,
                            identity: if operation.get("metadata_conflict").is_some() {
                                Identity::Conflict
                            } else {
                                agent.map_or(Identity::Unavailable, Identity::Resolved)
                            },
                            ..request(path)
                        },
                        &token,
                        Some(&store),
                        now,
                    )
                    .await;
                    assert_eq!(
                        outcome.response.status, expected.status,
                        "{} {operation}",
                        input["name"]
                    );
                    assert_eq!(
                        std::str::from_utf8(&outcome.response.body_bytes()).unwrap(),
                        expected.body_text,
                        "{} {operation}",
                        input["name"]
                    );
                    calls += 1;
                }
                other => panic!("unhandled operation in API row: {other}"),
            }
        }
    }
    assert_eq!(calls, 23, "source API controls were omitted");
}

#[tokio::test]
async fn absent_owner_and_store_checks_follow_method_auth_and_request_id_validation() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, TOKEN).unwrap();
    let path = format!("/trace?request_id={RID}");
    for (input, status, error) in [
        (
            Request {
                method: "POST",
                authorization: None,
                ..request(&path)
            },
            405,
            "Method Not Allowed",
        ),
        (
            Request {
                authorization: None,
                ..request("/trace")
            },
            401,
            "Authorization required",
        ),
        (
            Request {
                identity: Identity::Unavailable,
                ..request("/trace")
            },
            400,
            "Invalid or missing request_id",
        ),
        (
            Request {
                identity: Identity::Conflict,
                ..request(&path)
            },
            403,
            "Could not identify agent",
        ),
        (
            request(&path),
            503,
            "Agent API endpoint unavailable in native development mode",
        ),
    ] {
        let outcome = call(input, &token, None, 1000.0).await;
        assert_eq!(outcome.response.status, status);
        let body: Value = serde_json::from_slice(&outcome.response.body_bytes()).unwrap();
        assert_eq!(body["error"], error);
    }
    let owner = TraceStore::new(Settings::default());
    let path = format!("/trace?request_id={RID}&agent=alice");
    owner.append(RID, Some("alice"), step(&json!({"addon":"network-guard", "hook":"request", "state":"evaluated", "outcome":"allowed"}), 1000.0), 1000.0).unwrap();
    let foreign = call(
        Request {
            identity: Identity::Resolved("bob"),
            ..request(&path)
        },
        &token,
        Some(&owner),
        1000.0,
    )
    .await;
    let empty = TraceStore::new(Settings::default());
    let missing = call(request(&path), &token, Some(&empty), 1000.0).await;
    assert_eq!(foreign.response.status, 404);
    assert_eq!(foreign.response.status, missing.response.status);
    assert_eq!(foreign.response.body_bytes(), missing.response.body_bytes());
}
