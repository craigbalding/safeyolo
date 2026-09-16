//! Concrete source envelopes and submission ordering; no network or real token.

use bytes::Bytes;
use http_body_util::Full;
use safeyolo_proxy::{
    agent_api::{self, Controls, DeclarationContext, Failure, PolicyState, Request, RequestBody},
    audit::{ErrorKind, Settings, Submission, Writer},
    network_guard::Identity,
    tasks::Registry,
    test_context::{self, TestContext},
};
use serde_json::{Value, json};
use std::{path::PathBuf, process::Command, time::Duration};
use time::OffsetDateTime;

const BODY: &[u8] = br#"{"context":"run=R;agent=claimed;test=T","ttl":7}"#;

fn state(owner: &TestContext) -> Value {
    let mut body = test_context::api_current(
        Some(owner),
        Some("10.0.0.2"),
        Some("alice"),
        "GET",
        None,
        1000.,
    )
    .unwrap()
    .body;
    if body["context"].is_null() {
        Value::Null
    } else {
        body.as_object_mut().unwrap().shift_remove("agent");
        body
    }
}

#[test]
fn live_source_producer_oracle_is_unchanged() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output =
        Command::new(std::env::var_os("SAFEYOLO_PYTHON").unwrap_or_else(|| "python3".into()))
            .arg(root.join("tests/agent_api_audit_oracle.py"))
            .arg("--check")
            .arg(root.join("tests/agent_api_audit_source.json"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
    assert!(
        output.status.success(),
        "source producer oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report, json!({"source_rows":13,"matched":true}));
}

#[tokio::test]
async fn native_envelopes_and_committed_mutations_match_actual_source() {
    let source: Value = serde_json::from_str(include_str!("agent_api_audit_source.json")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, b"synthetic-producer-fixture").unwrap();
    let path = directory.path().join("audit.jsonl");
    let writer = Writer::new(path.clone(), Settings::default());
    let now = OffsetDateTime::parse(
        "2026-01-02T03:04:05.123456Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut expected_lines = String::new();
    for row in source["rows"].as_array().unwrap() {
        let input = &row["input"];
        let result = &row["result"];
        let owner = TestContext::default();
        if input["prime"] == true {
            test_context::api_current(
                Some(&owner),
                Some("10.0.0.2"),
                Some("alice"),
                "POST",
                Some(&json!({"context":"run=prior;agent=alice","ttl":9})),
                1000.,
            )
            .unwrap();
        }
        assert_eq!(state(&owner), result["before"], "{}", input["name"]);
        let request = Request {
            method: input["method"].as_str().unwrap(),
            path_and_query: "/api/test-context/current///?agent=forged",
            authorization: Some(if input["wrong_auth"] == true {
                b"Bearer wrong"
            } else {
                b"Bearer synthetic-producer-fixture"
            }),
            identity: Identity::Resolved("alice"),
            client_ip: Some("10.0.0.2"),
            request_id: "native-backstop-fixture",
        };
        let tasks = Registry::default();
        let mut body = Full::new(Bytes::from_static(BODY));
        let controls = Controls {
            traces: None,
            discovery: None,
            audit: None,
            flows: None,
            circuits: None,
            declarations: Some(DeclarationContext {
                owner: &owner,
                now: || 1000.,
            }),
        };
        let body = RequestBody {
            body: &mut body,
            content_encoding: b"identity",
            content_length: Some(BODY.len() as u64),
            observation: None,
        };
        let outcome = if input["guard"] == true {
            agent_api::unavailable(request, Failure::HandlerUnavailable)
        } else if let Some(id) = input["source_id"].as_str() {
            agent_api::respond_with_body_and_audit_id(
                request,
                &token,
                PolicyState::Unavailable,
                &tasks,
                0.,
                controls,
                body,
                Some(id),
            )
            .await
            .unwrap()
        } else {
            // Existing callers deliberately default to no source-stage ID.
            agent_api::respond_with_body(
                request,
                &token,
                PolicyState::Unavailable,
                &tasks,
                0.,
                controls,
                body,
            )
            .await
            .unwrap()
        };
        let intent = outcome.audit.as_ref().unwrap();
        assert_eq!(state(&owner), result["attempts"][0]["state"]);
        let event = intent.to_event();
        assert!(event.attribution.is_none() && event.approval.is_none());
        assert_eq!(writer.emit_at(event, now).unwrap(), Submission::Queued);
        expected_lines.push_str(result["attempts"][0]["line"].as_str().unwrap());
        let outcome = match input["failure"].as_str() {
            Some("RuntimeError") => {
                outcome.audit_submission_failed(request, ErrorKind::ThreadStart)
            }
            Some("OSError") => outcome.audit_submission_failed(request, ErrorKind::Io),
            None => outcome,
            _ => unreachable!("finite source cases"),
        };
        assert_eq!(
            outcome.response.status,
            result["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            outcome.response.body_bytes().as_ref(),
            result["body"].as_str().unwrap().as_bytes(),
            "{}",
            input["name"]
        );
        assert_eq!(state(&owner), result["after"]);
        if !input["failure"].is_null() && input["guard"] != true {
            assert_eq!(outcome.failure, Some(Failure::AuditWrite));
            assert!(
                outcome.audit.is_none(),
                "failed success audit cannot be retried"
            );
            assert!(outcome.handler_owned && !outcome.scrub_request);
            assert_eq!(outcome.blocked_by, "agent-api");
        }
    }
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    assert_eq!(std::fs::read_to_string(path).unwrap(), expected_lines);
}
