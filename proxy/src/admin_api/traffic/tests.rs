use super::*;
use crate::{admin_api, tasks::Registry, traffic_view::RequestInfo};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use std::sync::Arc;

const TOKEN: &str = "owned-traffic-view-fixture";

async fn call(
    view: Option<&Arc<TrafficView>>,
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
    let view = Arc::new(TrafficView::new(5000, 1024));
    for (method, target, body) in [
        ("PUT", "/admin/traffic/scope", r#"{"agent":"alice"}"#),
        ("PUT", "/admin/traffic/scope", "malformed"),
        (
            "PUT",
            "/admin/traffic/filter",
            r#"{"user_filter":"~m GET"}"#,
        ),
        ("PUT", "/admin/traffic/filter", "malformed"),
        ("GET", "/admin/traffic/flows", ""),
        ("GET", "/admin/traffic/flows/owned/body?side=request", ""),
        ("GET", "/admin/traffic/flows/owned/websocket/messages", ""),
        (
            "GET",
            "/admin/traffic/flows/owned/websocket/messages/0/body?offset=invalid",
            "",
        ),
        ("GET", "/admin/traffic/facets", ""),
    ] {
        let outcome = call(Some(&view), method, target, body, false).await;
        assert_eq!(outcome.status(), StatusCode::UNAUTHORIZED);
        assert!(matches!(outcome.audit(), Some(Audit::AuthenticationFailed)));
        assert!(view.scope()["agent"].is_null());
        assert_eq!(view.scope()["user_filter"], "");
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
    let view = Arc::new(TrafficView::new(5000, 1024));
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
    let view = Arc::new(TrafficView::new(5000, 1024));
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

fn websocket_exchange(view: &Arc<TrafficView>) -> Arc<crate::traffic_view::Exchange> {
    let exchange = view.begin(RequestInfo {
        id: "owned/id".into(),
        connection_id: "connection".into(),
        agent: Some("alice".into()),
        method: "GET".into(),
        url: "http://owned.invalid/socket".into(),
        headers: vec![],
        started: 1.,
    });
    exchange.response_head(101, vec![]);
    exchange.finish(None);
    exchange.websocket_start(2.);
    exchange
}

#[tokio::test]
async fn websocket_pages_reconstruct_all_retained_bytes_without_changing_scope() {
    use crate::websocket::{MessageContent, MessageType};

    let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
    let exchange = websocket_exchange(&view);
    let payload: Vec<u8> = (0..(MESSAGE_PAGE_BYTES * 2 + 7))
        .map(|index| (index % 256) as u8)
        .collect();
    let message = exchange
        .websocket_message(
            MessageType::Binary,
            true,
            3.,
            Arc::new(MessageContent::from_bytes_for_test(payload.clone())),
        )
        .unwrap();
    exchange.websocket_message_dropped(message, true);
    let empty = exchange
        .websocket_message(
            MessageType::Text,
            false,
            4.,
            Arc::new(MessageContent::from_bytes_for_test(vec![])),
        )
        .unwrap();
    // Scope selects the shared list, not access to retained operator evidence.
    view.set_scope(&json!({"agent":"bob"})).unwrap();
    assert_eq!(view.flows().unwrap()["flows"], json!([]));
    let base = "/admin/traffic/flows/owned%2Fid/websocket/messages";
    let transcript = document(call(Some(&view), "GET", base, "", true).await).await;
    assert_eq!(transcript["websocket"]["state"], "open");
    assert_eq!(transcript["websocket"]["messages_meta"]["count"], 2);
    assert_eq!(transcript["messages"][0]["type"], "binary");
    assert_eq!(transcript["messages"][0]["from_client"], true);
    assert_eq!(transcript["messages"][0]["dropped"], true);
    assert!(
        transcript["messages"][0]["body"]
            .get("data_base64")
            .is_none()
    );
    let mut reconstructed = vec![];
    for offset in [0, MESSAGE_PAGE_BYTES, MESSAGE_PAGE_BYTES * 2] {
        let target = format!("{base}/{message}/body?offset={offset}");
        let page = document(call(Some(&view), "GET", &target, "", true).await).await;
        assert_eq!(page["available"], true);
        assert_eq!(page["offset"], offset);
        assert_eq!(page["total_size"], payload.len());
        let data = STANDARD
            .decode(page["data_base64"].as_str().unwrap())
            .unwrap();
        assert!(data.len() <= MESSAGE_PAGE_BYTES);
        assert_eq!(page["size"], data.len());
        assert_eq!(page["end"], offset + data.len() == payload.len());
        reconstructed.extend(data);
    }
    assert_eq!(reconstructed, payload);
    for (id, offset, total) in [(empty, 0, 0), (message, payload.len() + 99, payload.len())] {
        let target = format!("{base}/{id}/body?offset={offset}");
        let page = document(call(Some(&view), "GET", &target, "", true).await).await;
        assert_eq!(page["available"], true);
        assert_eq!(page["offset"], total);
        assert_eq!(page["size"], 0);
        assert_eq!(page["data_base64"], "");
        assert_eq!(page["end"], true);
    }
    assert_eq!(view.scope()["agent"], "bob");
}

#[tokio::test]
async fn websocket_reads_distinguish_invalid_queries_and_trimmed_messages() {
    use crate::websocket::{MessageContent, MessageType};

    let view = Arc::new(TrafficView::new(5000, 4));
    let exchange = websocket_exchange(&view);
    let first = exchange
        .websocket_message(
            MessageType::Text,
            true,
            3.,
            Arc::new(MessageContent::from_bytes_for_test(b"first".to_vec())),
        )
        .unwrap();
    let last = exchange
        .websocket_message(
            MessageType::Text,
            true,
            4.,
            Arc::new(MessageContent::from_bytes_for_test(b"last".to_vec())),
        )
        .unwrap();
    let base = "/admin/traffic/flows/owned%2Fid/websocket/messages";
    let trimmed = format!("{base}/{first}/body");
    for (target, status) in [
        (trimmed.as_str(), StatusCode::NOT_FOUND),
        (
            "/admin/traffic/flows/missing/websocket/messages",
            StatusCode::NOT_FOUND,
        ),
        (
            "/admin/traffic/flows/%FF/websocket/messages",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/admin/traffic/flows/owned%2Fid/websocket/messages/no-id/body",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/admin/traffic/flows/owned%2Fid/websocket/messages/1/body?offset=-1",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/admin/traffic/flows/owned%2Fid/websocket/messages/1/body?offset=%FF",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/admin/traffic/flows/owned%2Fid/websocket/messages/1/body?offset=18446744073709551616",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/admin/traffic/flows/owned%2Fid/websocket/messages/1/unknown",
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            call(Some(&view), "GET", target, "", true).await.status(),
            status,
            "{target}"
        );
    }
    let transcript = document(call(Some(&view), "GET", base, "", true).await).await;
    assert_eq!(transcript["websocket"]["trimmed_messages"], 1);
    assert_eq!(transcript["messages"].as_array().unwrap().len(), 1);
    assert_eq!(transcript["messages"][0]["id"], last);
    let page =
        document(call(Some(&view), "GET", &format!("{base}/{last}/body"), "", true).await).await;
    assert_eq!(
        STANDARD
            .decode(page["data_base64"].as_str().unwrap())
            .unwrap(),
        b"last"
    );
}

#[tokio::test]
async fn shared_user_filter_combines_with_scope_and_rejected_edits_preserve_it() {
    let view = Arc::new(TrafficView::new(5000, 1024));
    let mut handles = Vec::new();
    for (id, agent, method) in [
        ("alice-get", "alice", "GET"),
        ("alice-post", "alice", "POST"),
        ("bob-get", "bob", "GET"),
        ("bob-post", "bob", "POST"),
    ] {
        let exchange = view.begin(RequestInfo {
            id: id.into(),
            connection_id: "connection".into(),
            agent: Some(agent.into()),
            method: method.into(),
            url: "http://owned.invalid/path".into(),
            headers: vec![],
            started: 1.,
        });
        exchange.response_head(200, vec![]);
        exchange.finish(None);
        handles.push(exchange);
    }
    view.set_scope(&json!({"agent":"alice"})).unwrap();
    let outcome = call(
        Some(&view),
        "PUT",
        "/admin/traffic/filter",
        r#"{"user_filter":"  ~m GET  "}"#,
        true,
    )
    .await;
    assert_eq!(outcome.status(), StatusCode::OK);
    // Source console filter editing has no payload-bearing admin audit event.
    assert!(outcome.audit().is_none());
    let accepted = document(outcome).await;
    assert_eq!(accepted["status"], "updated");
    assert_eq!(accepted["agent"], "alice");
    assert_eq!(accepted["user_filter"], "  ~m GET  ");
    assert!(
        accepted["effective_filter"]
            .as_str()
            .unwrap()
            .ends_with(" & (~m GET)")
    );
    let listed = document(call(Some(&view), "GET", "/admin/traffic/flows", "", true).await).await;
    assert_eq!(listed["flows"].as_array().unwrap().len(), 1);
    assert_eq!(listed["flows"][0]["id"], "alice-get");
    // Direct reads and global facets retain their existing access/selection rules.
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/bob-post",
            "",
            true
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        view.facets()["agent"],
        json!([
            {"value":"alice","count":2}, {"value":"bob","count":2}
        ])
    );

    let accepted_scope = view.scope();
    for (body, status) in [
        (r#"{"user_filter":"("}"#, StatusCode::BAD_REQUEST),
        (
            r#"{"user_filter":"~src owned"}"#,
            StatusCode::NOT_IMPLEMENTED,
        ),
        (
            r#"{"user_filter":"~m POST","agent":"bob"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (r#"{"user_filter":null}"#, StatusCode::BAD_REQUEST),
        (r#"{"user_filter":false}"#, StatusCode::BAD_REQUEST),
        ("{}", StatusCode::BAD_REQUEST),
        ("[]", StatusCode::BAD_REQUEST),
    ] {
        let outcome = call(Some(&view), "PUT", "/admin/traffic/filter", body, true).await;
        assert_eq!(outcome.status(), status, "{body}");
        assert!(outcome.audit().is_none());
        assert_eq!(view.scope(), accepted_scope);
    }
    let switched = document(
        call(
            Some(&view),
            "PUT",
            "/admin/traffic/scope",
            r#"{"agent":"bob"}"#,
            true,
        )
        .await,
    )
    .await;
    assert_eq!(switched["user_filter"], "  ~m GET  ");
    let listed = document(call(Some(&view), "GET", "/admin/traffic/flows", "", true).await).await;
    assert_eq!(listed["flows"].as_array().unwrap().len(), 1);
    assert_eq!(listed["flows"][0]["id"], "bob-get");
    let cleared = document(
        call(
            Some(&view),
            "PUT",
            "/admin/traffic/filter",
            r#"{"user_filter":""}"#,
            true,
        )
        .await,
    )
    .await;
    assert_eq!(cleared["agent"], "bob");
    assert_eq!(cleared["user_filter"], "");
    let listed = document(call(Some(&view), "GET", "/admin/traffic/flows", "", true).await).await;
    assert_eq!(listed["flows"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn filter_evaluation_failure_is_reported_and_clearing_recovers() {
    let view = Arc::new(TrafficView::new(5000, 1024));
    let exchange = view.begin(RequestInfo {
        id: "owned-decode-failure".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/".into(),
        headers: vec![("Content-Encoding".into(), "rot_13".into())],
        started: 1.,
    });
    exchange.request_body(Some(b"owned-private-marker"));
    exchange.finish(None);
    let original_body = view.body("owned-decode-failure", Side::Request).unwrap();

    let accepted = call(
        Some(&view),
        "PUT",
        "/admin/traffic/filter",
        r#"{"user_filter":"! ~b owned-private-marker"}"#,
        true,
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(
        document(accepted).await["user_filter"],
        "! ~b owned-private-marker"
    );
    let failed = call(Some(&view), "GET", "/admin/traffic/flows", "", true).await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(failed.audit().is_none());
    assert_eq!(
        document(failed).await,
        json!({"error": FilterError::DecodeType.to_string()})
    );
    assert_eq!(view.scope()["user_filter"], "! ~b owned-private-marker");
    assert_eq!(
        view.body("owned-decode-failure", Side::Request).unwrap(),
        original_body
    );

    let cleared = call(
        Some(&view),
        "PUT",
        "/admin/traffic/filter",
        r#"{"user_filter":""}"#,
        true,
    )
    .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    let recovered = call(Some(&view), "GET", "/admin/traffic/flows", "", true).await;
    assert_eq!(recovered.status(), StatusCode::OK);
    assert_eq!(
        document(recovered).await["flows"][0]["id"],
        "owned-decode-failure"
    );
}
