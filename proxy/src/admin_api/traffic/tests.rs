use super::*;
use crate::{admin_api, tasks::Registry, traffic_view::RequestInfo};
use http_body_util::{BodyExt, Full};
use std::sync::Arc;

const TOKEN: &str = "owned-traffic-view-fixture";

async fn call(
    view: Option<&TrafficView>,
    method: &str,
    target: &str,
    body: &str,
    auth: bool,
) -> Outcome {
    let mut request = Request::builder()
        .method(method)
        .uri(target)
        .header("Content-Length", body.len());
    if auth {
        request = request.header("Authorization", format!("Bearer {TOKEN}"));
    }
    admin_api::respond_with_view(
        request
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap(),
        TOKEN,
        &Registry::default(),
        None,
        None,
        None,
        view,
    )
    .await
    .unwrap()
}

async fn document(outcome: Outcome) -> Value {
    serde_json::from_slice(
        &outcome
            .into_response()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap()
}

#[tokio::test]
async fn authentication_precedes_scope_mutation_and_private_reads() {
    let view = TrafficView::new(5000, 1024);
    for (method, target, body) in [
        ("PUT", "/admin/traffic/scope", r#"{"agent":"alice"}"#),
        ("PUT", "/admin/traffic/scope", "malformed"),
        ("GET", "/admin/traffic/flows", ""),
        ("GET", "/admin/traffic/flows/owned/body?side=request", ""),
        ("GET", "/admin/traffic/facets", ""),
    ] {
        let outcome = call(Some(&view), method, target, body, false).await;
        assert_eq!(outcome.status(), StatusCode::UNAUTHORIZED);
        assert!(matches!(outcome.audit(), Some(Audit::AuthenticationFailed)));
        assert!(view.scope()["agent"].is_null());
    }
    assert_eq!(
        call(None, "GET", "/admin/traffic/scope", "", true)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn shared_scope_validates_before_commit_and_audits_raw_request() {
    let view = TrafficView::new(5000, 1024);
    let outcome = call(
        Some(&view),
        "PUT",
        "/admin/traffic/scope",
        r#"{"agent":"Alice","test_id":"CASE-1"}"#,
        true,
    )
    .await;
    assert_eq!(outcome.status(), StatusCode::OK);
    let events = outcome
        .audit()
        .unwrap()
        .canonical_events("127.0.0.1", "/admin/traffic/scope");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "admin.traffic_scope_update");
    let value: Value =
        serde_json::from_str(&events[0].details.render_json(false).unwrap()).unwrap();
    assert_eq!(
        value,
        json!({"client_ip":"127.0.0.1", "agent":"Alice", "test_id":"CASE-1"})
    );
    let accepted = document(outcome).await;
    assert_eq!(accepted["status"], "updated");
    assert_eq!(accepted["agent"], "Alice");
    for (body, error) in [
        ("[]", "request body must be a JSON object"),
        (r#"{"z":1,"a":2}"#, "unknown scope field(s): a, z"),
        (
            r#"{"agent":"Alice","unattributed":[1]}"#,
            "agent and unattributed are mutually exclusive",
        ),
        (r#"{"role":""}"#, "role must be a non-empty string or null"),
    ] {
        let outcome = call(Some(&view), "PUT", "/admin/traffic/scope", body, true).await;
        assert_eq!(outcome.status(), StatusCode::BAD_REQUEST);
        assert!(outcome.audit().is_none());
        assert_eq!(document(outcome).await["error"], error);
        assert_eq!(view.scope()["agent"], "Alice");
    }
    let cleared = call(Some(&view), "PUT", "/admin/traffic/scope", "{}", true).await;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert!(view.scope()["agent"].is_null());
    assert!(view.scope()["test_id"].is_null());
}

#[tokio::test]
async fn audit_enqueue_failure_does_not_undo_committed_scope() {
    let view = TrafficView::new(5000, 1024);
    let outcome = call(
        Some(&view),
        "PUT",
        "/admin/traffic/scope",
        r#"{"agent":"alice"}"#,
        true,
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let writer =
        crate::audit::Writer::new(directory.path().join("unused.jsonl"), Default::default());
    writer.poison_for_test();
    assert!(matches!(
        outcome.submit_audit(&writer, "127.0.0.1", "/admin/traffic/scope"),
        Err(Error::Audit(_))
    ));
    assert_eq!(view.scope()["agent"], "alice");
}

#[tokio::test]
async fn live_reads_preserve_ordered_headers_and_empty_versus_absent_body() {
    let view = Arc::new(TrafficView::new(5000, 1024));
    let exchange = view.begin(RequestInfo {
        id: "owned/id".into(),
        connection_id: "connection".into(),
        agent: Some("alice".into()),
        method: "GET".into(),
        url: "http://owned.invalid/path".into(),
        headers: vec![
            ("X-Duplicate".into(), "one".into()),
            ("X-Duplicate".into(), "two".into()),
        ],
        started: 1.,
    });
    exchange.request_body(Some(b""));
    exchange.response_head(200, vec![("Content-Type".into(), "text/plain".into())]);
    exchange.response_body(None);
    exchange.finish(None);
    let list = document(call(Some(&view), "GET", "/admin/traffic/flows", "", true).await).await;
    assert_eq!(list["flows"][0]["id"], "owned/id");
    let detail = document(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/owned%2Fid",
            "",
            true,
        )
        .await,
    )
    .await;
    assert_eq!(
        detail["request_headers"],
        json!([["X-Duplicate", "one"], ["X-Duplicate", "two"]])
    );
    let request = document(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/owned%2Fid/body?side=request",
            "",
            true,
        )
        .await,
    )
    .await;
    assert_eq!(request["available"], true);
    assert_eq!(request["data_base64"], "");
    assert_eq!(request["size"], 0);
    let response = document(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/owned%2Fid/body?side=response",
            "",
            true,
        )
        .await,
    )
    .await;
    assert_eq!(response["available"], false);
    assert_eq!(response["reason"], "streamed_or_unavailable");
    for (target, status) in [
        ("/admin/traffic/flows/missing", StatusCode::NOT_FOUND),
        (
            "/admin/traffic/flows/owned%2Fid/body?side=invalid",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            call(Some(&view), "GET", target, "", true).await.status(),
            status
        );
    }
    assert_eq!(view.detail("owned/id").unwrap()["state"], "complete");
}
