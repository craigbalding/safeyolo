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

async fn export_bytes(outcome: Outcome) -> Result<Bytes, Error> {
    outcome
        .into_response()
        .into_body()
        .collect()
        .await
        .map(|body| body.to_bytes())
}

fn fixture_bytes(value: &Value) -> Vec<u8> {
    if let Some(hex) = value.get("hex").and_then(Value::as_str) {
        return hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
    }
    let text = value.get("text").and_then(Value::as_str).unwrap_or("");
    let repeat = value.get("repeat").and_then(Value::as_u64).unwrap_or(1);
    let suffix = value
        .get("suffix_text")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut bytes = text.repeat(repeat as usize).into_bytes();
    bytes.extend_from_slice(suffix.as_bytes());
    if value.get("gzip").and_then(Value::as_bool).unwrap_or(false) {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&bytes).unwrap();
        encoder.finish().unwrap()
    } else {
        bytes
    }
}

fn fixture_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_fixture_output(output: &Value, actual: &[u8], context: &str) {
    assert_eq!(output["kind"].as_str(), Some("bytes"), "{context}");
    if let Some(expected_hex) = output.get("hex").and_then(Value::as_str) {
        assert_eq!(actual, fixture_hex(expected_hex), "{context}");
        return;
    }
    assert_eq!(
        actual.len(),
        output["length"].as_u64().unwrap() as usize,
        "{context}"
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, actual);
    assert_eq!(
        hex_bytes(digest.as_ref()),
        output["sha256"].as_str().unwrap(),
        "{context}"
    );
    if let Some(prefix) = output.get("prefix_hex").and_then(Value::as_str) {
        assert!(actual.starts_with(&fixture_hex(prefix)), "{context}");
    }
    if let Some(suffix) = output.get("suffix_hex").and_then(Value::as_str) {
        assert!(actual.ends_with(&fixture_hex(suffix)), "{context}");
    }
}

fn fixture_optional_bytes(value: &Value) -> Option<Vec<u8>> {
    value.is_object().then(|| fixture_bytes(value))
}

fn fixture_pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (fixture_header_text(&pair[0]), fixture_header_text(&pair[1])))
        .collect()
}

fn fixture_header_text(value: &Value) -> String {
    let bytes = value.as_str().map(str::as_bytes).map_or_else(
        || fixture_hex(value["hex"].as_str().unwrap()),
        <[u8]>::to_vec,
    );
    bytes.into_iter().map(char::from).collect()
}

fn fixture_url(url: &str, request: &Value) -> String {
    let mut result = url.to_owned();
    if request.get("http_version").and_then(Value::as_str) == Some("HTTP/2.0")
        && let Some(authority) = request.get("authority").and_then(Value::as_str)
        && let Some((scheme, rest)) = result.split_once("://")
        && let Some((_, path)) = rest.split_once('/')
    {
        result = format!("{scheme}://{authority}/{path}");
    }
    result
}

fn fixture_target(url: &str, request: &Value) -> String {
    if request.get("http_version").and_then(Value::as_str) == Some("HTTP/2.0")
        && request.get("authority").is_some()
    {
        return fixture_url(url, request);
    }
    url.split_once("://")
        .and_then(|(_, rest)| rest.split_once('/').map(|(_, path)| format!("/{path}")))
        .unwrap_or_else(|| "/".into())
}

fn fixture_export_bytes(
    view: &TrafficView,
    id: &str,
    format: ExportFormat,
) -> Result<Vec<u8>, ExportError> {
    let mut plan = view.export(id, format)?;
    let mut output = Vec::new();
    while let Some(chunk) = plan.next_chunk()? {
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

fn replay_fixture_row(row: &Value) -> Arc<TrafficView> {
    use crate::websocket::{MessageContent, MessageType};

    let input = &row["input"];
    let request = &input["request"];
    let url = fixture_url(request["url"].as_str().unwrap(), request);
    let view = Arc::new(TrafficView::new(5000, 2 * 1024 * 1024));
    let exchange = view.begin(RequestInfo {
        id: row["name"].as_str().unwrap().into(),
        connection_id: "fixture".into(),
        agent: None,
        method: request["method"].as_str().unwrap().into(),
        url,
        headers: fixture_pairs(&request["headers"]),
        started: 1.,
    });
    let version = request
        .get("http_version")
        .and_then(Value::as_str)
        .unwrap_or("HTTP/1.1");
    exchange.request_line(
        version,
        &fixture_target(request["url"].as_str().unwrap(), request),
    );
    let request_body = fixture_optional_bytes(&request["body"]);
    exchange.request_body(request_body.as_deref());
    if request.get("trailers").is_some() {
        exchange.request_trailers(fixture_pairs(&request["trailers"]));
    }
    if let Some(response) = input.get("response").filter(|response| !response.is_null()) {
        let response_body = fixture_optional_bytes(&response["body"]);
        let reason = response
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .as_bytes()
            .to_owned();
        exchange.response_head_observed(
            response["status"].as_u64().unwrap() as u16,
            Some(
                response
                    .get("http_version")
                    .and_then(Value::as_str)
                    .unwrap_or("HTTP/1.1"),
            ),
            fixture_pairs(&response["headers"]),
            Some(&reason),
        );
        exchange.response_body(response_body.as_deref());
        if response.get("trailers").is_some() {
            exchange.response_trailers(fixture_pairs(&response["trailers"]));
        }
    }
    exchange.finish(None);
    if let Some(messages) = input
        .get("websocket")
        .filter(|messages| !messages.is_null())
    {
        exchange.websocket_start(2.);
        for (position, message) in messages.as_array().unwrap().iter().enumerate() {
            let kind = match message["type"].as_str().unwrap() {
                "text" => MessageType::Text,
                "binary" => MessageType::Binary,
                other => panic!("unknown fixture WebSocket type {other}"),
            };
            let body = Arc::new(MessageContent::from_bytes_for_test(fixture_bytes(
                &message["body"],
            )));
            let id = exchange
                .websocket_message(
                    kind,
                    message["from_client"].as_bool().unwrap(),
                    3. + position as f64,
                    body,
                )
                .unwrap();
            if message["dropped"].as_bool().unwrap_or(false) {
                exchange.websocket_message_dropped(id, true);
            }
        }
        exchange.finish(None);
    }
    view
}

fn expected_fixture_error(name: &str, format: ExportFormat) -> Option<ExportError> {
    let raw_response = format == ExportFormat::RawResponse;
    Some(match name {
        "get_absent_encoded_body" | "request_and_response_bodies_absent" => {
            if raw_response {
                ExportError::MissingResponse
            } else {
                ExportError::MissingBody
            }
        }
        "get_nonempty_body"
        | "shell_quote_text_body"
        | "shell_control_text_body"
        | "trailers_without_chunked_raw_value_error" => {
            if raw_response {
                ExportError::MissingResponse
            } else if name == "trailers_without_chunked_raw_value_error"
                && matches!(format, ExportFormat::Raw | ExportFormat::RawRequest)
            {
                ExportError::Unsupported
            } else {
                ExportError::MissingResponse
            }
        }
        "duplicate_headers_host_removal_accept_encoding" => {
            if format == ExportFormat::RawRequest {
                ExportError::MissingBody
            } else {
                return None;
            }
        }
        "response_only_raw_body" => {
            if format == ExportFormat::RawRequest {
                ExportError::MissingBody
            } else {
                return None;
            }
        }
        "existing_response_body_absent_raw_fallback" => {
            if raw_response {
                ExportError::MissingBody
            } else {
                return None;
            }
        }
        "invalid_content_encoding_type_error" => {
            if raw_response {
                ExportError::MissingResponse
            } else {
                ExportError::Decode
            }
        }
        "binary_body_command_text_error_raw_available" => {
            if raw_response {
                ExportError::MissingResponse
            } else if matches!(format, ExportFormat::Curl | ExportFormat::Httpie) {
                ExportError::Decode
            } else {
                return None;
            }
        }
        "charset_decode_error_raw_available" => {
            if raw_response {
                ExportError::MissingResponse
            } else if matches!(format, ExportFormat::Curl | ExportFormat::Httpie) {
                ExportError::Decode
            } else {
                return None;
            }
        }
        _ => return None,
    })
}

#[test]
fn native_export_replays_frozen_source_schema3_observations() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/traffic_export_source.json")).unwrap();
    assert_eq!(fixture["schema"], 3);
    assert_eq!(fixture["rows"].as_array().unwrap().len(), 31);
    let formats = [
        ("curl", ExportFormat::Curl),
        ("httpie", ExportFormat::Httpie),
        ("raw", ExportFormat::Raw),
        ("raw_request", ExportFormat::RawRequest),
        ("raw_response", ExportFormat::RawResponse),
    ];
    let mut compared = 0;
    let mut excluded = 0;
    for row in fixture["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let view = replay_fixture_row(row);
        for (format_name, format) in formats {
            if name == "preserve_original_ip_true_source_control" && format == ExportFormat::Curl {
                excluded += 1;
                continue;
            }
            let actual = fixture_export_bytes(&view, name, format);
            let expected = &row["formats"][format_name];
            if let Some(output) = expected.get("output").filter(|output| !output.is_null()) {
                let actual = actual.unwrap();
                match output["kind"].as_str().unwrap() {
                    "bytes" => {
                        assert_fixture_output(output, &actual, &format!("{name}/{format_name}"))
                    }
                    "text" => assert_eq!(
                        actual,
                        fixture_hex(output["utf8_hex"].as_str().unwrap()),
                        "{name}/{format_name}"
                    ),
                    kind => panic!("unknown fixture output kind {kind}"),
                }
            } else {
                assert!(
                    actual.is_err(),
                    "{name}/{format_name} unexpectedly exported"
                );
                if let Some(error) = expected_fixture_error(name, format) {
                    assert_eq!(actual.unwrap_err(), error, "{name}/{format_name}");
                }
            }
            compared += 1;
        }
    }
    assert_eq!(compared, 154);
    assert_eq!(excluded, 1);
}

#[tokio::test]
async fn selected_export_replays_native_http_formats_and_categories() {
    let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
    let exchange = view.begin(RequestInfo {
        id: "flow/id".into(),
        connection_id: "connection".into(),
        agent: Some("alice".into()),
        method: "POST".into(),
        url: "http://owned.invalid/export-target".into(),
        headers: vec![
            ("Host".into(), "owned.invalid".into()),
            ("X-Duplicate".into(), "one".into()),
            ("x-duplicate".into(), "two".into()),
            ("Content-Length".into(), "14".into()),
        ],
        started: 1.,
    });
    exchange.request_line("HTTP/1.1", "/export-target");
    exchange.request_body(Some(b"native request"));
    exchange.response_head_observed(
        299,
        Some("HTTP/1.0"),
        vec![
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Trailer".into(), "X-Response-Trailer".into()),
            ("X-Response".into(), "yes".into()),
        ],
        Some(b"Synthetic Reason"),
    );
    exchange.response_body(Some(b"native response"));
    exchange.response_trailers(vec![("X-Response-Trailer".into(), "response-final".into())]);
    exchange.finish(None);

    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/flow%2Fid/export?format=raw",
            "",
            false,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/flow%2Fid/export?format=unknown",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    for target in [
        "/admin/traffic/flows/flow%2Fid/export?format=invalid&format=raw",
        "/admin/traffic/flows/flow%2Fid/export?format=raw&format=httpie",
    ] {
        assert_eq!(
            call(Some(&view), "GET", target, "", true).await.status(),
            StatusCode::BAD_REQUEST,
            "{target}"
        );
    }
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/missing/export?format=raw",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    let raw = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/flow%2Fid/export?format=raw",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        raw.as_ref(),
        b"POST /export-target HTTP/1.1\r\nHost: owned.invalid\r\nX-Duplicate: one\r\nx-duplicate: two\r\nContent-Length: 14\r\n\r\nnative request\r\n\r\nHTTP/1.0 299 Synthetic Reason\r\nTransfer-Encoding: chunked\r\nTrailer: X-Response-Trailer\r\nX-Response: yes\r\n\r\nf\r\nnative response\r\n0\r\nX-Response-Trailer: response-final\r\n\r\n"
    );
    let raw_request = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/flow%2Fid/export?format=raw_request",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    assert!(raw_request.starts_with(b"POST /export-target HTTP/1.1\r\n"));
    assert!(raw_request.ends_with(b"native request"));
    let raw_response = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/flow%2Fid/export?format=raw_response",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    assert!(raw_response.starts_with(b"HTTP/1.0 299 Synthetic Reason\r\n"));
    assert!(raw_response.ends_with(b"X-Response-Trailer: response-final\r\n\r\n"));

    let curl = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/flow%2Fid/export?format=curl",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        curl,
        "curl -H 'X-Duplicate: one' -H 'x-duplicate: two' -X POST http://owned.invalid/export-target -d 'native request'"
    );
    let httpie = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/flow%2Fid/export?format=httpie",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        httpie,
        "http POST http://owned.invalid/export-target 'X-Duplicate: one' 'x-duplicate: two' <<< 'native request'"
    );

    // The response owns a preflighted snapshot. A later row mutation cannot
    // alter bytes retained by the already-created export plan.
    let pending = call(
        Some(&view),
        "GET",
        "/admin/traffic/flows/flow%2Fid/export?format=raw_request",
        "",
        true,
    )
    .await;
    exchange.request_body(Some(b"mutated"));
    let stable = export_bytes(pending).await.unwrap();
    assert!(stable.ends_with(b"native request"));
}

#[test]
fn selected_export_preserves_explicit_default_ports_and_header_bytes() {
    for (id, url, expected_url) in [
        (
            "explicit-http-port",
            "http://owned.invalid:80/path?x=1",
            "http://owned.invalid/path?x=1",
        ),
        (
            "explicit-https-port",
            "https://owned.invalid:443/path?x=1",
            "https://owned.invalid/path?x=1",
        ),
    ] {
        let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
        let exchange = view.begin(RequestInfo {
            id: id.into(),
            connection_id: "connection".into(),
            agent: None,
            method: "GET".into(),
            url: url.into(),
            headers: vec![],
            started: 1.,
        });
        exchange.request_line("HTTP/1.1", "/path?x=1");
        exchange.request_body(Some(b""));
        let curl = fixture_export_bytes(&view, id, ExportFormat::Curl).unwrap();
        assert_eq!(
            curl,
            format!("curl '{}'", expected_url).into_bytes(),
            "{id} curl"
        );
        let httpie = fixture_export_bytes(&view, id, ExportFormat::Httpie).unwrap();
        assert_eq!(
            httpie,
            format!("http GET '{}'", expected_url).into_bytes(),
            "{id} httpie"
        );
    }

    let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
    let exchange = view.begin(RequestInfo {
        id: "header-bytes".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/header".into(),
        headers: vec![
            (
                "X-UTF8".into(),
                String::from_iter([char::from(0xc3), char::from(0xa9)]),
            ),
            ("X-Byte".into(), char::from(0xff).to_string()),
        ],
        started: 1.,
    });
    exchange.request_line("HTTP/1.1", "/header");
    exchange.request_body(Some(b""));
    assert_eq!(
        fixture_export_bytes(&view, "header-bytes", ExportFormat::Curl).unwrap(),
        b"curl -H 'X-UTF8: \xc3\xa9' -H 'X-Byte: \xff' http://owned.invalid/header"
    );
    assert_eq!(
        fixture_export_bytes(&view, "header-bytes", ExportFormat::Httpie).unwrap(),
        b"http GET http://owned.invalid/header 'X-UTF8: \xc3\xa9' 'X-Byte: \xff'"
    );
}

#[test]
fn selected_export_supports_source_text_codecs_and_markup_inference() {
    let cases = [
        (
            "ascii",
            vec![
                ("Content-Type".into(), "text/plain; charset=ascii".into()),
            ],
            b"hello".to_vec(),
            b"curl -H 'Content-Type: text/plain; charset=ascii' -X POST http://owned.invalid/ascii -d hello"
                .as_slice(),
        ),
        (
            "utf16-bom",
            vec![],
            vec![0xff, 0xfe, b'h', 0, b'i', 0],
            b"curl -X POST http://owned.invalid/utf16-bom -d '\xef\xbb\xbfhi'".as_slice(),
        ),
        (
            "utf32-bom",
            vec![],
            vec![0xff, 0xfe, 0, 0, b'h', 0, 0, 0, b'i', 0, 0, 0],
            b"curl -X POST http://owned.invalid/utf32-bom -d '\xef\xbb\xbfhi'".as_slice(),
        ),
        (
            "html-inferred",
            vec![("Content-Type".into(), "text/html".into())],
            b"<meta charset=\"utf-8\"><p>hi</p>".to_vec(),
            b"curl -H 'Content-Type: text/html' -X POST http://owned.invalid/html-inferred -d '<meta charset=\"utf-8\"><p>hi</p>'"
                .as_slice(),
        ),
        (
            "xml-inferred",
            vec![("Content-Type".into(), "application/xml".into())],
            b"<?xml version=\"1.0\" encoding=\"utf-8\"?><x>hi</x>".to_vec(),
            b"curl -H 'Content-Type: application/xml' -X POST http://owned.invalid/xml-inferred -d '<?xml version=\"1.0\" encoding=\"utf-8\"?><x>hi</x>'"
                .as_slice(),
        ),
        (
            "css-inferred",
            vec![("Content-Type".into(), "text/css".into())],
            b"@charset \"utf-8\";body{color:red}".to_vec(),
            b"curl -H 'Content-Type: text/css' -X POST http://owned.invalid/css-inferred -d '@charset \"utf-8\";body{color:red}'"
                .as_slice(),
        ),
    ];
    for (id, headers, body, expected) in cases {
        let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
        let exchange = view.begin(RequestInfo {
            id: id.into(),
            connection_id: "connection".into(),
            agent: None,
            method: "POST".into(),
            url: format!("http://owned.invalid/{id}"),
            headers,
            started: 1.,
        });
        exchange.request_line("HTTP/1.1", &format!("/{id}"));
        exchange.request_body(Some(&body));
        assert_eq!(
            fixture_export_bytes(&view, id, ExportFormat::Curl).unwrap(),
            expected,
            "{id}"
        );
    }
}

#[test]
fn selected_export_rejects_malformed_unicode_after_valid_prefix() {
    let mut utf16 = Vec::new();
    for unit in [0x0073_u16, 0x0065, 0xd800] {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let mut utf32 = Vec::new();
    for codepoint in [b's' as u32, b'e' as u32, 0x11_0000] {
        utf32.extend_from_slice(&codepoint.to_le_bytes());
    }
    for (id, content_type, body) in [
        ("malformed-utf16", "text/plain; charset=utf-16le", utf16),
        ("malformed-utf32", "text/plain; charset=utf-32le", utf32),
    ] {
        let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
        let exchange = view.begin(RequestInfo {
            id: id.into(),
            connection_id: "connection".into(),
            agent: None,
            method: "POST".into(),
            url: format!("http://owned.invalid/{id}"),
            headers: vec![("Content-Type".into(), content_type.into())],
            started: 1.,
        });
        exchange.request_line("HTTP/1.1", &format!("/{id}"));
        exchange.request_body(Some(&body));
        assert!(matches!(
            view.export(id, ExportFormat::Curl),
            Err(ExportError::Decode)
        ));
        assert!(fixture_export_bytes(&view, id, ExportFormat::RawRequest).is_ok());
    }
}

#[tokio::test]
async fn selected_export_replays_observed_request_trailers_with_chunk_framing() {
    let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
    let exchange = view.begin(RequestInfo {
        id: "request-trailers".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/chunked".into(),
        headers: vec![
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Trailer".into(), "X-Req-Trailer".into()),
        ],
        started: 1.,
    });
    exchange.request_line("HTTP/1.1", "/chunked");
    exchange.request_body(Some(b"chunk-body"));
    // This is the same reached observation callback used by the forwarded
    // request body wrapper after its parser-owned trailer frame.
    exchange.request_trailers(vec![("X-Req-Trailer".into(), "request-final".into())]);
    exchange.response_head_observed(
        200,
        Some("HTTP/1.1"),
        vec![
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Trailer".into(), "X-Resp-Trailer".into()),
        ],
        Some(b""),
    );
    exchange.response_body(Some(b"response-chunk"));
    exchange.response_trailers(vec![("X-Resp-Trailer".into(), "response-final".into())]);
    exchange.finish(None);

    let raw_request = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/request-trailers/export?format=raw_request",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        raw_request.as_ref(),
        b"POST /chunked HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTrailer: X-Req-Trailer\r\n\r\na\r\nchunk-body\r\n0\r\nX-Req-Trailer: request-final\r\n\r\n"
    );

    let raw_response = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/request-trailers/export?format=raw_response",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        raw_response.as_ref(),
        b"HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\nTrailer: X-Resp-Trailer\r\n\r\ne\r\nresponse-chunk\r\n0\r\nX-Resp-Trailer: response-final\r\n\r\n"
    );

    let raw = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/request-trailers/export?format=raw",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    let mut expected = raw_request.to_vec();
    expected.extend_from_slice(b"\r\n\r\n");
    expected.extend_from_slice(&raw_response);
    assert_eq!(raw, expected);

    let curl = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/request-trailers/export?format=curl",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        curl,
        "curl -H 'Transfer-Encoding: chunked' -H 'Trailer: X-Req-Trailer' -X POST http://owned.invalid/chunked -d chunk-body"
    );

    let httpie = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/request-trailers/export?format=httpie",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        httpie,
        "http POST http://owned.invalid/chunked 'Transfer-Encoding: chunked' 'Trailer: X-Req-Trailer' <<< chunk-body"
    );
}

#[tokio::test]
async fn selected_export_preserves_gzip_binary_and_missing_body_rules() {
    use std::io::Write;

    let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
    let gzip = {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"decoded native").unwrap();
        encoder.finish().unwrap()
    };
    let encoded = view.begin(RequestInfo {
        id: "encoded".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/encoded".into(),
        headers: vec![
            ("Content-Encoding".into(), "gzip".into()),
            ("Content-Type".into(), "text/plain".into()),
        ],
        started: 1.,
    });
    encoded.request_line("HTTP/1.1", "/encoded");
    encoded.request_body(Some(&gzip));
    encoded.finish(None);
    let decoded = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/encoded/export?format=raw_request",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    assert!(
        decoded
            .windows(b"Content-Encoding".len())
            .all(|window| window != b"Content-Encoding")
    );
    assert!(decoded.ends_with(b"decoded native"));

    let encoded_empty = view.begin(RequestInfo {
        id: "encoded-empty".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/encoded-empty".into(),
        headers: vec![
            ("Content-Encoding".into(), "gzip".into()),
            ("Content-Length".into(), "7".into()),
        ],
        started: 1.5,
    });
    encoded_empty.request_line("HTTP/1.1", "/encoded-empty");
    encoded_empty.request_body(Some(&[]));
    encoded_empty.response_head_observed(201, Some("HTTP/1.1"), vec![], Some(b""));
    encoded_empty.response_body(Some(b"created"));
    encoded_empty.finish(None);
    assert_eq!(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-empty/export?format=raw_request",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .as_ref(),
        b"POST /encoded-empty HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\n\r\n"
    );
    let encoded_empty_curl = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-empty/export?format=curl",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        encoded_empty_curl,
        "curl -H 'Content-Encoding: gzip' -H 'content-length: 0' -X POST http://owned.invalid/encoded-empty"
    );
    let encoded_empty_httpie = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-empty/export?format=httpie",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        encoded_empty_httpie,
        "http POST http://owned.invalid/encoded-empty 'Content-Encoding: gzip'"
    );
    assert_eq!(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-empty/export?format=raw_response",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .as_ref(),
        b"HTTP/1.1 201 \r\ncontent-length: 7\r\n\r\ncreated"
    );
    assert_eq!(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-empty/export?format=raw",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .as_ref(),
        b"POST /encoded-empty HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\n\r\n\r\n\r\nHTTP/1.1 201 \r\ncontent-length: 7\r\n\r\ncreated"
    );

    let encoded_absent = view.begin(RequestInfo {
        id: "encoded-absent".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/encoded-absent".into(),
        headers: vec![
            ("Content-Encoding".into(), "gzip".into()),
            ("Content-Length".into(), "0".into()),
        ],
        started: 1.6,
    });
    encoded_absent.request_line("HTTP/1.1", "/encoded-absent");
    encoded_absent.finish(None);
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/encoded-absent/export?format=raw_request",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let encoded_absent_curl = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-absent/export?format=curl",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        encoded_absent_curl,
        "curl -H 'Content-Encoding: gzip' http://owned.invalid/encoded-absent"
    );
    let encoded_absent_httpie = String::from_utf8(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/encoded-absent/export?format=httpie",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .to_vec(),
    )
    .unwrap();
    assert_eq!(
        encoded_absent_httpie,
        "http GET http://owned.invalid/encoded-absent 'Content-Encoding: gzip'"
    );

    let binary = view.begin(RequestInfo {
        id: "binary".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/binary".into(),
        headers: vec![("Content-Type".into(), "application/json".into())],
        started: 2.,
    });
    binary.request_line("HTTP/1.1", "/binary");
    binary.request_body(Some(&[0xff, 0, 1]));
    binary.finish(None);
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/binary/export?format=curl",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/binary/export?format=raw_request",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .as_ref(),
        b"POST /binary HTTP/1.1\r\nContent-Type: application/json\r\ncontent-length: 3\r\n\r\n\xff\x00\x01"
    );

    let missing = view.begin(RequestInfo {
        id: "missing-body".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/missing".into(),
        headers: vec![],
        started: 3.,
    });
    missing.request_line("HTTP/1.1", "/missing");
    missing.finish(None);
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/missing-body/export?format=raw_request",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let response_absent = view.begin(RequestInfo {
        id: "response-absent".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/response-absent".into(),
        headers: vec![],
        started: 3.5,
    });
    response_absent.request_line("HTTP/1.1", "/response-absent");
    response_absent.request_body(Some(b"request-only"));
    response_absent.response_head_observed(
        204,
        Some("HTTP/1.1"),
        vec![("X-Response".into(), "body-absent".into())],
        Some(b""),
    );
    response_absent.response_body(None);
    response_absent.finish(None);
    assert_eq!(
        export_bytes(
            call(
                Some(&view),
                "GET",
                "/admin/traffic/flows/response-absent/export?format=raw",
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap()
        .as_ref(),
        b"POST /response-absent HTTP/1.1\r\ncontent-length: 12\r\n\r\nrequest-only"
    );
    assert_eq!(
        String::from_utf8(
            export_bytes(
                call(
                    Some(&view),
                    "GET",
                    "/admin/traffic/flows/response-absent/export?format=curl",
                    "",
                    true,
                )
                .await,
            )
            .await
            .unwrap()
            .to_vec(),
        )
        .unwrap(),
        "curl -X POST http://owned.invalid/response-absent -d request-only"
    );
    assert_eq!(
        String::from_utf8(
            export_bytes(
                call(
                    Some(&view),
                    "GET",
                    "/admin/traffic/flows/response-absent/export?format=httpie",
                    "",
                    true,
                )
                .await,
            )
            .await
            .unwrap()
            .to_vec(),
        )
        .unwrap(),
        "http POST http://owned.invalid/response-absent <<< request-only"
    );
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/response-absent/export?format=raw_response",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/missing-body/export?format=raw_response",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let empty = view.begin(RequestInfo {
        id: "empty-body".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/empty".into(),
        headers: vec![],
        started: 4.,
    });
    empty.request_line("HTTP/1.1", "/empty");
    empty.request_body(Some(&[]));
    empty.finish(None);
    assert_eq!(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/empty-body/export?format=raw_request",
            "",
            true,
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn selected_export_preserves_canonical_empty_and_http2_reason_bytes() {
    for (id, request_version, response_version, reason, expected) in [
        (
            "canonical-reason",
            "HTTP/1.1",
            "HTTP/1.1",
            b"OK".as_slice(),
            b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nx".as_slice(),
        ),
        (
            "empty-reason",
            "HTTP/1.1",
            "HTTP/1.1",
            b"".as_slice(),
            b"HTTP/1.1 200 \r\ncontent-length: 1\r\n\r\nx".as_slice(),
        ),
        (
            "http2-empty-reason",
            "HTTP/2.0",
            "HTTP/2.0",
            b"".as_slice(),
            b"HTTP/2.0 200 \r\ncontent-length: 1\r\n\r\nx".as_slice(),
        ),
    ] {
        let view = Arc::new(TrafficView::new(5000, 1024 * 1024));
        let exchange = view.begin(RequestInfo {
            id: id.into(),
            connection_id: "connection".into(),
            agent: None,
            method: "GET".into(),
            url: format!("http://owned.invalid/{id}"),
            headers: vec![],
            started: 1.,
        });
        exchange.request_line(request_version, &format!("/{id}"));
        exchange.request_body(Some(&[]));
        exchange.response_head_observed(200, Some(response_version), vec![], Some(reason));
        exchange.response_body(Some(b"x"));
        exchange.finish(None);
        let response = export_bytes(
            call(
                Some(&view),
                "GET",
                &format!("/admin/traffic/flows/{id}/export?format=raw_response"),
                "",
                true,
            )
            .await,
        )
        .await
        .unwrap();
        assert_eq!(response, expected, "{id}");
    }
}

#[tokio::test]
async fn selected_export_snapshot_survives_row_prune() {
    let view = Arc::new(TrafficView::new(1, 1024 * 1024));
    let evicted = view.begin(RequestInfo {
        id: "evicted".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "POST".into(),
        url: "http://owned.invalid/pruned".into(),
        headers: vec![],
        started: 1.,
    });
    evicted.request_line("HTTP/1.1", "/pruned");
    evicted.request_body(Some(b"retained by export"));
    evicted.finish(None);
    let mut plan = view
        .export("evicted", ExportFormat::RawRequest)
        .expect("row is present before prune");
    drop(evicted);

    let retained = view.begin(RequestInfo {
        id: "retained".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/new".into(),
        headers: vec![],
        started: 2.,
    });
    retained.request_line("HTTP/1.1", "/new");
    retained.request_body(Some(b"new"));
    retained.finish(None);
    assert!(view.detail("evicted").is_none());

    let mut output = Vec::new();
    while let Some(chunk) = plan.next_chunk().unwrap() {
        output.extend_from_slice(&chunk);
    }
    assert_eq!(
        output,
        b"POST /pruned HTTP/1.1\r\ncontent-length: 18\r\n\r\nretained by export"
    );
}

#[tokio::test]
async fn selected_export_includes_large_dropped_websocket_messages() {
    use crate::websocket::{MessageContent, MessageType};

    let view = Arc::new(TrafficView::new(5000, 2 * 1024 * 1024));
    let exchange = view.begin(RequestInfo {
        id: "websocket/id".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/socket".into(),
        headers: vec![],
        started: 1.,
    });
    exchange.request_line("HTTP/1.1", "/socket");
    exchange.request_body(Some(b"handshake"));
    exchange.response_head_observed(101, Some("HTTP/1.1"), vec![], Some(b"Switching Protocols"));
    exchange.response_body(Some(b"handshake"));
    exchange.finish(None);
    exchange.websocket_start(2.);
    let payload = vec![b'w'; 70 * 1024];
    let id = exchange
        .websocket_message(
            MessageType::Binary,
            true,
            3.,
            Arc::new(MessageContent::from_bytes_for_test(payload.clone())),
        )
        .unwrap();
    exchange.websocket_message_dropped(id, true);
    exchange
        .websocket_message(
            MessageType::Text,
            false,
            4.,
            Arc::new(MessageContent::from_bytes_for_test(b"done".to_vec())),
        )
        .unwrap();
    exchange.finish(None);

    let exported = export_bytes(
        call(
            Some(&view),
            "GET",
            "/admin/traffic/flows/websocket%2Fid/export?format=raw",
            "",
            true,
        )
        .await,
    )
    .await
    .unwrap();
    let mut expected = b"GET /socket HTTP/1.1\r\ncontent-length: 9\r\n\r\nhandshake\r\n\r\nHTTP/1.1 101 Switching Protocols\r\ncontent-length: 9\r\n\r\nhandshake\r\n\r\n[OUTGOING] ".to_vec();
    expected.extend_from_slice(&payload);
    expected.extend_from_slice(b"\n[INCOMING] done");
    assert_eq!(exported.as_ref(), expected.as_slice());
}

#[test]
fn selected_export_reads_spilled_websocket_storage_and_releases_failed_owner() {
    use crate::websocket::{MessageContent, MessageType};

    let view = Arc::new(TrafficView::new(1, 2 * 1024 * 1024));
    let exchange = view.begin(RequestInfo {
        id: "spilled-websocket".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/spilled".into(),
        headers: vec![],
        started: 1.,
    });
    exchange.request_line("HTTP/1.1", "/spilled");
    exchange.request_body(Some(b"handshake"));
    exchange.response_head_observed(101, Some("HTTP/1.1"), vec![], Some(b"Switching Protocols"));
    exchange.response_body(Some(b"handshake"));
    exchange.finish(None);
    exchange.websocket_start(2.);

    let payload = vec![b's'; 70 * 1024];
    let owner = Arc::new(MessageContent::from_file_for_test(
        &payload,
        payload.len() as u64,
    ));
    let weak_owner = Arc::downgrade(&owner);
    exchange
        .websocket_message(MessageType::Binary, true, 3., owner.clone())
        .unwrap();
    let mut plan = view.export("spilled-websocket", ExportFormat::Raw).unwrap();
    let mut output = Vec::new();
    while let Some(chunk) = plan.next_chunk().unwrap() {
        output.extend_from_slice(&chunk);
    }
    assert!(
        output
            .windows(payload.len())
            .any(|window| window == payload)
    );
    drop(plan);
    drop(owner);
    assert!(
        weak_owner.upgrade().is_some(),
        "row retains the immutable owner"
    );

    let failed = Arc::new(MessageContent::from_file_for_test(b"short", 6));
    let weak_failed = Arc::downgrade(&failed);
    exchange
        .websocket_message(MessageType::Binary, false, 4., failed.clone())
        .unwrap();
    let mut failed_plan = view.export("spilled-websocket", ExportFormat::Raw).unwrap();
    let mut storage_error = None;
    while let Some(chunk) = failed_plan.next_chunk().unwrap_or_else(|error| {
        storage_error = Some(error);
        None
    }) {
        drop(chunk);
    }
    assert_eq!(storage_error, Some(ExportError::Storage));
    drop(failed_plan);
    drop(failed);

    // Dropping an in-flight export and then canceling/pruning its row must
    // release the snapshot's final storage owner as well.
    let canceled = Arc::new(MessageContent::from_file_for_test(b"cancel me", 9));
    let weak_canceled = Arc::downgrade(&canceled);
    exchange
        .websocket_message(MessageType::Text, true, 4.5, canceled.clone())
        .unwrap();
    let canceled_plan = view.export("spilled-websocket", ExportFormat::Raw).unwrap();
    drop(canceled);
    drop(exchange);

    let replacement = view.begin(RequestInfo {
        id: "replacement".into(),
        connection_id: "connection".into(),
        agent: None,
        method: "GET".into(),
        url: "http://owned.invalid/replacement".into(),
        headers: vec![],
        started: 5.,
    });
    replacement.request_line("HTTP/1.1", "/replacement");
    replacement.request_body(Some(b""));
    replacement.finish(None);
    assert!(view.detail("spilled-websocket").is_none());
    assert!(weak_owner.upgrade().is_some());
    assert!(weak_failed.upgrade().is_some());
    assert!(weak_canceled.upgrade().is_some());
    drop(canceled_plan);
    assert!(weak_owner.upgrade().is_none());
    assert!(weak_failed.upgrade().is_none());
    assert!(weak_canceled.upgrade().is_none());
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
