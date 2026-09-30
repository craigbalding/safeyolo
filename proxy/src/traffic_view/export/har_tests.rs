use std::{io::Read, net::SocketAddr, sync::Arc};

use base64::Engine as _;
use flate2::read::ZlibDecoder;
use serde_json::Value;

use super::super::{
    Exchange, ExportError, ExportFormat, RequestInfo, TrafficView, UpstreamConnectionObservation,
    UpstreamRoute,
};
use crate::websocket::{MessageContent, MessageType};

fn export(view: &TrafficView, id: &str, format: ExportFormat) -> Result<Vec<u8>, ExportError> {
    let mut plan = view.export(id, format)?;
    let mut output = Vec::new();
    while let Some(chunk) = plan.next_chunk()? {
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

fn begin(view: &Arc<TrafficView>, id: &str, method: &str, url: &str) -> Arc<Exchange> {
    view.begin(RequestInfo {
        id: id.into(),
        connection_id: "har-test-connection".into(),
        agent: Some("har-test-agent".into()),
        method: method.into(),
        url: url.into(),
        headers: vec![],
        started: 10.0,
    })
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().copied().map(char::from).collect()
}

fn json_export(view: &TrafficView, id: &str) -> Value {
    let bytes = export(view, id, ExportFormat::Har).unwrap();
    assert!(!bytes.ends_with(b"\n"));
    serde_json::from_slice(&bytes).unwrap()
}

fn input_bytes(value: &Value) -> Option<Vec<u8>> {
    value
        .as_str()
        .map(|value| hex_bytes(value).expect("input hex"))
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("odd input hex length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0])
                .to_digit(16)
                .ok_or("invalid input hex")?;
            let low = char::from(pair[1])
                .to_digit(16)
                .ok_or("invalid input hex")?;
            Ok((high * 16 + low) as u8)
        })
        .collect()
}

fn input_latin1(value: &Value) -> String {
    input_bytes(value)
        .unwrap_or_default()
        .into_iter()
        .map(char::from)
        .collect()
}

fn input_pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .expect("input header list")
        .iter()
        .map(|pair| (input_latin1(&pair[0]), input_latin1(&pair[1])))
        .collect()
}

fn replay_input_flow(flow: &Value) -> Arc<TrafficView> {
    use crate::websocket::{MessageContent, MessageType};

    let request = &flow["request"];
    let id = flow["name"].as_str().expect("input flow name");
    let view = Arc::new(TrafficView::new(2_000, 2 << 20));
    let exchange = view.begin(super::super::RequestInfo {
        id: id.into(),
        connection_id: "source-replay".into(),
        agent: None,
        method: input_latin1(&request["method_hex"]),
        url: request["url"].as_str().expect("input URL").into(),
        headers: input_pairs(&request["headers_hex"]),
        started: request["timestamp_start"].as_f64().expect("request start"),
    });
    exchange.request_line(
        &input_latin1(&request["version_hex"]),
        &input_latin1(&request["target_hex"]),
    );
    let request_body = input_bytes(&request["body_hex"]);
    if let Some(completed) = request["timestamp_end"].as_f64() {
        exchange.request_body_at(request_body.as_deref(), completed);
    } else {
        exchange.update(|row| {
            row.request_body = super::super::Body::observe(request_body.as_deref());
        });
    }

    let response_end = flow
        .get("response")
        .filter(|response| !response.is_null())
        .and_then(|response| response["timestamp_end"].as_f64());
    let request_end = request["timestamp_end"].as_f64();
    if let Some(response) = flow.get("response").filter(|response| !response.is_null()) {
        let reason = input_bytes(&response["reason_hex"]).expect("response reason");
        exchange.response_head_observed_at(
            response["status"].as_u64().expect("response status") as u16,
            Some(&input_latin1(&response["version_hex"])),
            input_pairs(&response["headers_hex"]),
            Some(&reason),
            response["timestamp_start"]
                .as_f64()
                .expect("response start"),
        );
        let response_body = input_bytes(&response["body_hex"]);
        if let Some(completed) = response_end {
            exchange.response_body_complete_at(response_body.as_deref(), completed);
        } else {
            exchange.response_body(response_body.as_deref());
        }
    }

    if let Some(server) = flow.get("server") {
        let mut observation = super::super::UpstreamConnectionObservation::new(
            server["id"].as_str().expect("server id").into(),
            super::super::UpstreamRoute::Direct,
            server["timestamp_start"].as_f64(),
        );
        observation.peer = server["peername"].as_array().map(|peer| {
            let host = peer[0].as_str().expect("server peer host");
            let port = peer[1].as_u64().expect("server peer port") as u16;
            format!("{host}:{port}")
                .parse()
                .expect("server peer address")
        });
        observation.tcp_setup = server["timestamp_tcp_setup"].as_f64();
        observation.tls_setup = server["timestamp_tls_setup"].as_f64();
        exchange.upstream_connection(observation);
    }

    let error = flow
        .get("error")
        .filter(|error| !error.is_null())
        .and_then(|error| error["msg"].as_str());
    exchange.finish_at(
        error,
        response_end
            .or(request_end)
            .unwrap_or(request["timestamp_start"].as_f64().unwrap()),
    );

    if let Some(websocket) = flow
        .get("websocket")
        .filter(|websocket| !websocket.is_null())
    {
        exchange
            .websocket_start(response_end.unwrap_or(request["timestamp_start"].as_f64().unwrap()));
        for message in websocket["messages"]
            .as_array()
            .expect("WebSocket messages")
        {
            let kind = match message["opcode"].as_u64().expect("WebSocket opcode") {
                1 => MessageType::Text,
                2 => MessageType::Binary,
                opcode => panic!("unsupported input WebSocket opcode {opcode}"),
            };
            let id = exchange
                .websocket_message(
                    kind,
                    message["from_client"].as_bool().expect("message direction"),
                    message["timestamp"].as_f64().expect("message timestamp"),
                    Arc::new(MessageContent::from_bytes_for_test(
                        hex_bytes(message["content_hex"].as_str().expect("message bytes"))
                            .expect("message input hex"),
                    )),
                )
                .expect("open WebSocket session");
            if message["dropped"].as_bool().unwrap_or(false) {
                exchange.websocket_message_dropped(id, true);
            }
        }
    }
    view
}

fn hex_output(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

#[test]
fn har_retains_ordered_http_facts_and_reached_direct_timing() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(
        &view,
        "rich",
        "POST",
        "https://owned.invalid:8443/submit?a=one&a=two&blank=",
    );
    exchange.request_headers(vec![
        ("X-Duplicate".into(), "one".into()),
        ("x-duplicate".into(), "two".into()),
        ("Cookie".into(), "sid=abc; theme=dark".into()),
        (
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ),
    ]);
    exchange.request_line("HTTP/2", "/submit?a=one&a=two&blank=");
    exchange.request_body_at(Some(b"name=alice&empty="), 11.0);
    exchange.response_head_observed_at(
        201,
        Some("HTTP/1.1"),
        vec![
            ("Content-Type".into(), "text/plain".into()),
            ("Set-Cookie".into(), "sid=xyz; Path=/; Secure".into()),
            ("Set-Cookie".into(), "theme=light".into()),
        ],
        Some(b"Created"),
        12.0,
    );
    exchange.response_body_complete_at(Some(b"created"), 13.0);
    let mut upstream = UpstreamConnectionObservation::new(
        "direct-har-connection".into(),
        UpstreamRoute::Direct,
        Some(10.0),
    );
    upstream.peer = Some("192.0.2.44:8443".parse::<SocketAddr>().unwrap());
    upstream.tcp_setup = Some(10.5);
    exchange.upstream_connection(upstream);
    exchange.upstream_tls(11.0);
    exchange.finish_at(None, 14.0);

    let document = json_export(&view, "rich");
    let entry = &document["log"]["entries"][0];
    assert_eq!(document["log"]["creator"]["name"], "SafeYolo");
    assert_eq!(entry["request"]["httpVersion"], "HTTP/2");
    assert_eq!(
        entry["request"]["headers"][0],
        serde_json::json!({"name":"X-Duplicate","value":"one"})
    );
    assert_eq!(
        entry["request"]["headers"][1],
        serde_json::json!({"name":"x-duplicate","value":"two"})
    );
    assert_eq!(
        entry["request"]["cookies"],
        serde_json::json!([
            {"name":"sid","value":"abc"}, {"name":"theme","value":"dark"}
        ])
    );
    assert_eq!(
        entry["request"]["queryString"][0],
        serde_json::json!({"name":"a","value":"one"})
    );
    assert_eq!(
        entry["request"]["queryString"][2],
        serde_json::json!({"name":"blank","value":""})
    );
    assert_eq!(entry["request"]["postData"]["text"], "name=alice&empty=");
    assert_eq!(
        entry["request"]["postData"]["params"][1],
        serde_json::json!({"name":"empty","value":""})
    );
    assert_eq!(entry["response"]["status"], 201);
    assert_eq!(entry["response"]["statusText"], "Created");
    assert_eq!(entry["response"]["cookies"][0]["secure"], true);
    assert_eq!(
        entry["response"]["headers"][1],
        serde_json::json!({"name":"Set-Cookie","value":"sid=xyz; Path=/; Secure"})
    );
    assert_eq!(entry["response"]["content"]["text"], "created");
    assert_eq!(entry["serverIPAddress"], "192.0.2.44");
    assert_eq!(
        entry["timings"],
        serde_json::json!({
            "connect": 500.0, "ssl": 500.0, "send": 1000.0,
            "receive": 1000.0, "wait": 1000.0
        })
    );
    assert_eq!(entry["time"], 4000.0);
}

#[test]
fn zhar_is_level_nine_stream_of_the_same_har_document() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(&view, "compressed", "GET", "http://owned.invalid/");
    exchange.request_body_at(Some(&[]), 10.0);
    exchange.response_head_observed_at(204, Some("HTTP/1.1"), vec![], None, 10.0);
    exchange.response_body_complete_at(Some(&[]), 10.0);
    exchange.finish_at(None, 10.0);

    let har = export(&view, "compressed", ExportFormat::Har).unwrap();
    let compressed = export(&view, "compressed", ExportFormat::Zhar).unwrap();
    assert!(compressed.starts_with(&[0x78, 0xDA]));
    let mut decoder = flate2::read::ZlibDecoder::new(compressed.as_slice());
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, har);
}

#[test]
fn har_retains_websocket_kind_direction_and_stream_boundaries() {
    let view = Arc::new(TrafficView::new(10, 2 << 20));
    let exchange = begin(&view, "socket", "GET", "http://owned.invalid/socket");
    exchange.request_body_at(Some(b"handshake"), 11.0);
    exchange.response_head_observed_at(101, Some("HTTP/1.1"), vec![], Some(b"Switching"), 12.0);
    exchange.response_body_complete_at(Some(b"handshake"), 12.0);
    exchange.finish_at(None, 12.0);
    exchange.websocket_start(13.0);
    let mut text = vec![b'a'; 4095];
    text.extend_from_slice("é".as_bytes());
    exchange
        .websocket_message(
            MessageType::Text,
            true,
            4.0,
            Arc::new(MessageContent::from_bytes_for_test(text.clone())),
        )
        .unwrap();
    let binary: Vec<u8> = (0..5000).map(|index| index as u8).collect();
    exchange
        .websocket_message(
            MessageType::Binary,
            false,
            5.0,
            Arc::new(MessageContent::from_bytes_for_test(binary.clone())),
        )
        .unwrap();

    let document = json_export(&view, "socket");
    let messages = document["log"]["entries"][0]["_webSocketMessages"]
        .as_array()
        .unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["type"], "send");
    assert_eq!(messages[0]["opcode"], 1);
    assert_eq!(messages[0]["time"], 4.0);
    assert_eq!(messages[0]["data"].as_str().unwrap().as_bytes(), text);
    assert_eq!(messages[1]["type"], "receive");
    assert_eq!(messages[1]["opcode"], 2);
    assert_eq!(messages[1]["time"], 5.0);
    assert_eq!(
        messages[1]["data"],
        base64::engine::general_purpose::STANDARD.encode(binary)
    );
    let har = export(&view, "socket", ExportFormat::Har).unwrap();
    let compressed = export(&view, "socket", ExportFormat::Zhar).unwrap();
    let mut decoder = flate2::read::ZlibDecoder::new(compressed.as_slice());
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, har);
}

#[test]
fn har_keeps_missing_response_and_storage_errors_distinct() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(&view, "missing", "GET", "http://owned.invalid/missing");
    exchange.finish_at(Some("upstream failed"), 12.0);
    let document = json_export(&view, "missing");
    let response = &document["log"]["entries"][0]["response"];
    assert_eq!(response["status"], 0);
    assert_eq!(response["content"], serde_json::json!({}));
    assert_eq!(response["headersSize"], -1);
    assert_eq!(response["bodySize"], -1);
    assert_eq!(response["_error"], "upstream failed");

    let unavailable = begin(
        &view,
        "unavailable-body",
        "GET",
        "http://owned.invalid/body",
    );
    unavailable.request_body_at(Some(&[]), 10.0);
    unavailable.response_head_observed_at(200, None, vec![], None, 10.0);
    unavailable.response_body(None);
    unavailable.finish_at(None, 10.0);
    let response = &json_export(&view, "unavailable-body")["log"]["entries"][0]["response"];
    assert_eq!(response["status"], 200);
    assert_eq!(response["content"]["size"], 0);
    assert_eq!(response["content"]["text"], "");

    let binary = begin(&view, "binary-body", "GET", "http://owned.invalid/binary");
    binary.request_body_at(Some(&[]), 10.0);
    binary.response_head_observed_at(
        200,
        Some("HTTP/1.1"),
        vec![("Content-Type".into(), "application/octet-stream".into())],
        None,
        10.0,
    );
    binary.response_body_complete_at(Some(&[0, 255, 1, b'a']), 10.0);
    binary.finish_at(None, 10.0);
    let response = &json_export(&view, "binary-body")["log"]["entries"][0]["response"];
    assert_eq!(response["content"]["encoding"], "base64");
    assert_eq!(response["content"]["text"], "AP8BYQ==");

    let failed = begin(&view, "truncated", "GET", "http://owned.invalid/truncated");
    failed.request_body_at(Some(&[]), 10.0);
    failed.response_head_observed_at(200, None, vec![], None, 11.0);
    failed.response_body_complete_at(Some(&[]), 11.0);
    failed.finish_at(None, 11.0);
    failed.websocket_start(11.0);
    failed
        .websocket_message(
            MessageType::Text,
            true,
            12.0,
            Arc::new(MessageContent::from_file_for_test(b"short", 6)),
        )
        .unwrap();
    let mut plan = view.export("truncated", ExportFormat::Har).unwrap();
    loop {
        match plan.next_chunk() {
            Ok(Some(chunk)) => drop(chunk),
            Ok(None) => panic!("truncated WebSocket content exported successfully"),
            Err(error) => {
                assert_eq!(error, ExportError::Storage);
                break;
            }
        }
    }
}

#[test]
fn har_omits_unreached_peer_and_connection_phases() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(&view, "tls-without-tcp", "GET", "https://owned.invalid/");
    exchange.request_body_at(Some(&[]), 10.0);
    exchange.response_head_observed_at(200, Some("HTTP/1.1"), vec![], None, 10.0);
    exchange.response_body_complete_at(Some(&[]), 10.0);
    exchange.finish_at(None, 10.0);
    let mut upstream = UpstreamConnectionObservation::new(
        "target-tls-only".into(),
        UpstreamRoute::Direct,
        Some(10.0),
    );
    upstream.tls_setup = Some(11.0);
    exchange.upstream_connection(upstream);

    let entry = &json_export(&view, "tls-without-tcp")["log"]["entries"][0];
    assert_eq!(entry["timings"]["connect"], -1.0);
    assert_eq!(entry["timings"]["ssl"], -1.0);
    assert!(entry.get("serverIPAddress").is_none());

    let parent = begin(&view, "parent-route", "GET", "https://owned.invalid/");
    parent.request_body_at(Some(&[]), 10.0);
    parent.response_head_observed_at(200, Some("HTTP/1.1"), vec![], None, 10.0);
    parent.response_body_complete_at(Some(&[]), 10.0);
    parent.finish_at(None, 10.0);
    let mut parent_observation = UpstreamConnectionObservation::new(
        "parent-connection".into(),
        UpstreamRoute::Parent,
        Some(10.0),
    );
    parent_observation.peer = Some("198.51.100.9:8080".parse().unwrap());
    parent_observation.tcp_setup = Some(10.5);
    parent_observation.tls_setup = Some(11.0);
    parent.upstream_connection(parent_observation);
    let entry = &json_export(&view, "parent-route")["log"]["entries"][0];
    assert_eq!(entry["timings"]["connect"], -1.0);
    assert_eq!(entry["timings"]["ssl"], -1.0);
    assert!(entry.get("serverIPAddress").is_none());
}

#[test]
fn har_applies_source_default_port_url_projection() {
    for (id, url, expected) in [
        (
            "http-default-port",
            "http://owned.invalid:80/path?x=1",
            "http://owned.invalid/path?x=1",
        ),
        (
            "https-default-port",
            "https://owned.invalid:443/path?x=1",
            "https://owned.invalid/path?x=1",
        ),
    ] {
        let view = Arc::new(TrafficView::new(10, 1 << 20));
        let exchange = begin(&view, id, "GET", url);
        exchange.request_body_at(Some(&[]), 10.0);
        exchange.finish_at(None, 10.0);
        let document = json_export(&view, id);
        assert_eq!(document["log"]["entries"][0]["request"]["url"], expected);
    }
}

#[test]
fn har_source_selection_fixture_identity_remains_pinned() {
    let fixture = include_str!("../../../tests/traffic_har_source.json");
    assert!(fixture.contains("\"schema\": 1"));
    assert!(fixture.contains("\"source\": \"installed_mitmproxy_savehar\""));
    assert!(fixture.contains("\"mitmproxy\": \"12.2.3\""));
    assert_eq!(fixture.matches("\"entry_count\"").count(), 23);
    assert!(fixture.contains("\"formatter_errors\": {"));
}

#[test]
fn har_replays_owned_source_input_recipes_for_full_entry_comparison() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/traffic_har_inputs.json"))
            .expect("owned HAR input recipes");
    assert_eq!(fixture["schema"], 1);
    let flows = fixture["flows"].as_array().expect("HAR input flows");
    let mut exported = 0;
    let mut unknown_exported = false;
    for flow in flows {
        if flow["kind"] != "http" {
            continue;
        }
        let name = flow["name"].as_str().expect("input flow name");
        let view = replay_input_flow(flow);
        match export(&view, name, ExportFormat::Har) {
            Ok(bytes) => {
                assert!(bytes.starts_with(b"{"), "{name} is not a HAR document");
                assert!(!bytes.ends_with(b"\n"), "{name} has a trailing newline");
                unknown_exported |= name == "unknown_charset_fallback";
                println!("HAR_REPLAY_OK\t{name}\t{}", hex_output(&bytes));
                exported += 1;
            }
            Err(error) => panic!("{name} replay failed: {error:?}"),
        }
    }
    assert_eq!(
        flows.iter().filter(|flow| flow["kind"] == "http").count(),
        27
    );
    assert_eq!(exported, 27);
    assert!(
        unknown_exported,
        "joined codec must replay the unknown label"
    );
}

#[test]
fn har_escapes_invalid_percent_encoded_query_bytes_without_lossy_text() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(
        &view,
        "invalid-query",
        "GET",
        "http://owned.invalid/?bad=%ff",
    );
    exchange.request_body_at(Some(&[]), 10.0);
    exchange.finish_at(None, 10.0);
    let bytes = export(&view, "invalid-query", ExportFormat::Har).unwrap();
    assert!(
        bytes
            .windows(b"\\udcff".len())
            .any(|window| window == b"\\udcff")
    );
}

#[test]
fn har_matches_source_byte_and_parser_edge_controls() {
    let view = Arc::new(TrafficView::new(30, 2 << 20));

    let boundary = begin(&view, "boundary", "GET", "http://owned.invalid/boundary");
    boundary.request_body_at(Some(&[]), 10.0);
    boundary.response_head_observed_at(
        200,
        Some("HTTP/1.1"),
        vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
        None,
        10.0,
    );
    let mut sampled = "€".repeat(34).into_bytes();
    sampled.push(b'x');
    boundary.response_body_complete_at(Some(&sampled), 10.0);
    boundary.finish_at(None, 10.0);
    let sampled_content =
        &json_export(&view, "boundary")["log"]["entries"][0]["response"]["content"];
    assert_eq!(sampled_content["text"], format!("{}x", "€".repeat(34)));
    assert!(sampled_content.get("encoding").is_none());

    let sized = begin(&view, "sized", "GET", "http://owned.invalid/sized");
    sized.request_headers(vec![("X".into(), "y".into())]);
    sized.request_body_at(Some(&[]), 10.0);
    sized.response_head_observed_at(
        200,
        Some("HTTP/1.1"),
        vec![("X".into(), latin1(&[8, 12]))],
        None,
        10.0,
    );
    sized.response_body_complete_at(Some(&[]), 10.0);
    sized.finish_at(None, 10.0);
    let sized_entry = &json_export(&view, "sized")["log"]["entries"][0];
    assert_eq!(sized_entry["request"]["headersSize"], 21);
    assert_eq!(sized_entry["response"]["headersSize"], 28);

    let folded = begin(
        &view,
        "folded",
        "GET",
        "http://owned.invalid/folded?skip=1&&keep=&flag&",
    );
    folded.request_headers(vec![
        ("X-Text".into(), latin1(b"\xc3\xa9")),
        ("X-Invalid".into(), latin1(b"\xff")),
    ]);
    folded.request_body_at(Some(&[]), 10.0);
    folded.response_head_observed_at(
        200,
        Some("HTTP/1.1"),
        vec![
            ("Content-Type".into(), latin1(b"text/\xc3\xa9")),
            ("content-type".into(), latin1(b"application/\xff")),
            ("Location".into(), latin1(b"/caf\xc3\xa9")),
            ("location".into(), latin1(b"/\xff")),
        ],
        None,
        10.0,
    );
    folded.response_body_complete_at(Some(&[]), 10.0);
    folded.finish_at(None, 10.0);
    let folded_bytes = export(&view, "folded", ExportFormat::Har).unwrap();
    assert!(
        folded_bytes
            .windows(b"\"value\": \"\\u00e9\"".len())
            .any(|window| window == b"\"value\": \"\\u00e9\"")
    );
    assert!(
        folded_bytes
            .windows(b"\\udcff".len())
            .any(|window| window == b"\\udcff")
    );
    assert!(
        folded_bytes
            .windows(b"text/\\u00e9, application/\\udcff".len())
            .any(|window| window == b"text/\\u00e9, application/\\udcff")
    );
    assert!(
        folded_bytes
            .windows(b"/caf\\u00e9, /\\udcff".len())
            .any(|window| window == b"/caf\\u00e9, /\\udcff")
    );
    let folded_document = String::from_utf8(folded_bytes).unwrap();
    assert!(folded_document.contains("\"name\": \"keep\""));
    assert!(folded_document.contains("\"name\": \"flag\""));
    assert!(!folded_document.contains("\"name\": \"\""));

    let form = begin(
        &view,
        "form",
        "POST",
        "http://owned.invalid/form?a=1&&b=&=empty&flag&",
    );
    form.request_headers(vec![(
        "Content-Type".into(),
        "application/x-www-form-urlencoded; charset=utf-8".into(),
    )]);
    form.request_body_at(Some(b"a=1&&b=&=empty&flag&"), 10.0);
    form.finish_at(None, 10.0);
    let form_request = &json_export(&view, "form")["log"]["entries"][0]["request"];
    assert_eq!(
        form_request["queryString"],
        serde_json::json!([
            {"name":"a","value":"1"},
            {"name":"b","value":""},
            {"name":"","value":"empty"},
            {"name":"flag","value":""}
        ])
    );
    assert_eq!(
        form_request["postData"]["params"],
        form_request["queryString"]
    );

    let empty_form = begin(&view, "empty-form", "POST", "http://owned.invalid/form");
    empty_form.request_headers(vec![(
        "Content-Type".into(),
        "application/x-www-form-urlencoded; charset=utf-8".into(),
    )]);
    empty_form.request_body_at(Some(&[]), 10.0);
    empty_form.finish_at(None, 10.0);
    let empty_request = &json_export(&view, "empty-form")["log"]["entries"][0]["request"];
    assert_eq!(empty_request["postData"]["params"], serde_json::json!([]));

    let unknown = begin(&view, "unknown", "POST", "http://owned.invalid/unknown");
    unknown.request_headers(vec![(
        "Content-Type".into(),
        "text/plain; charset=owned-unknown".into(),
    )]);
    unknown.request_body_at(Some(b"aaaaaaaaa\xff"), 10.0);
    unknown.finish_at(None, 10.0);
    let unknown_bytes = export(&view, "unknown", ExportFormat::Har).unwrap();
    assert!(
        unknown_bytes
            .windows(b"aaaaaaaaa\\udcff".len())
            .any(|window| window == b"aaaaaaaaa\\udcff")
    );

    let invalid_parameter = begin(
        &view,
        "mime-invalid-parameter",
        "POST",
        "http://owned.invalid/mime",
    );
    let invalid_mime = latin1(b"text/plain; charset=latin-1; x=\xff");
    invalid_parameter.request_headers(vec![("Content-Type".into(), invalid_mime.clone())]);
    invalid_parameter.request_body_at(Some(&[0xff]), 10.0);
    invalid_parameter.response_head_observed_at(
        200,
        Some("HTTP/1.1"),
        vec![("Content-Type".into(), invalid_mime)],
        None,
        10.0,
    );
    invalid_parameter.response_body_complete_at(Some(&[0xff]), 10.0);
    invalid_parameter.finish_at(None, 10.0);
    let invalid_bytes = export(&view, "mime-invalid-parameter", ExportFormat::Har).unwrap();
    assert!(
        invalid_bytes
            .windows(b"\\u00ff".len())
            .any(|window| window == b"\\u00ff")
    );
    assert!(
        invalid_bytes
            .windows(b"\"encoding\": \"base64\"".len())
            .any(|window| window == b"\"encoding\": \"base64\"")
    );
    assert!(
        invalid_bytes
            .windows(b"\"text\": \"/w==\"".len())
            .any(|window| window == b"\"text\": \"/w==\"")
    );

    let declared_form = begin(&view, "declared-form", "POST", "http://owned.invalid/form");
    declared_form.request_headers(vec![(
        "Content-Type".into(),
        "application/x-www-form-urlencoded; charset=latin-1".into(),
    )]);
    declared_form.request_body_at(Some(b"x=\xe9&escaped=%E9"), 10.0);
    declared_form.finish_at(None, 10.0);
    let declared_bytes = export(&view, "declared-form", ExportFormat::Har).unwrap();
    assert!(
        declared_bytes
            .windows(b"x=\\u00e9&escaped=%E9".len())
            .any(|window| window == b"x=\\u00e9&escaped=%E9")
    );
    assert!(
        declared_bytes
            .windows(b"\"name\": \"x\"".len())
            .any(|window| window == b"\"name\": \"x\"")
    );
    assert!(
        declared_bytes
            .windows(b"\"value\": \"\\u00e9\"".len())
            .any(|window| window == b"\"value\": \"\\u00e9\"")
    );
    assert!(
        declared_bytes
            .windows(b"\"name\": \"escaped\"".len())
            .any(|window| window == b"\"name\": \"escaped\"")
    );
    assert!(
        declared_bytes
            .windows(b"\\udce9".len())
            .any(|window| window == b"\\udce9")
    );

    let empty_encoding = begin(
        &view,
        "empty-encoding",
        "POST",
        "http://owned.invalid/encoded",
    );
    let encoded_body = [
        0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0x04, 0xff, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49, 0x4d,
        0x51, 0x28, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x01, 0, 0x5e, 0xaf, 0x12, 0x81, 0x0f, 0,
        0, 0,
    ];
    let response_encoded_body = [
        0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0x04, 0xff, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49, 0x4d,
        0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x05, 0x00, 0xfd, 0x7c, 0xa2, 0xd2,
        0x10, 0, 0, 0,
    ];
    let encoding_headers = vec![
        ("Content-Encoding".into(), String::new()),
        ("content-encoding".into(), "gzip".into()),
        ("Content-Type".into(), "text/plain".into()),
    ];
    empty_encoding.request_headers(encoding_headers.clone());
    empty_encoding.request_body_at(Some(&encoded_body), 10.0);
    empty_encoding.response_head_observed_at(200, Some("HTTP/1.1"), encoding_headers, None, 10.0);
    empty_encoding.response_body_complete_at(Some(&response_encoded_body), 10.0);
    empty_encoding.finish_at(None, 10.0);
    let encoded_bytes = export(&view, "empty-encoding", ExportFormat::Har).unwrap();
    assert!(
        encoded_bytes
            .windows(b"\"value\": \"\"".len())
            .any(|window| window == b"\"value\": \"\"")
    );
    assert!(
        encoded_bytes
            .windows(b"\"encoding\": \"base64\"".len())
            .any(|window| window == b"\"encoding\": \"base64\"")
    );
    assert!(
        encoded_bytes
            .windows(b"H4sIAAAAAAAE/0vNS85PSU1RKEotLsjPK04FAP18otIQAAAA".len())
            .any(|window| window == b"H4sIAAAAAAAE/0vNS85PSU1RKEotLsjPK04FAP18otIQAAAA")
    );

    let big5 = begin(&view, "big5", "POST", "http://owned.invalid/big5");
    big5.request_headers(vec![(
        "Content-Type".into(),
        "text/plain; charset=big5".into(),
    )]);
    big5.request_body_at(Some(b"prefix\xa4\x40suffix"), 10.0);
    big5.finish_at(None, 10.0);
    let big5_entry = &json_export(&view, "big5")["log"]["entries"][0];
    assert_eq!(big5_entry["request"]["postData"]["text"], "prefix一suffix");

    let cookies = begin(
        &view,
        "cookies",
        "GET",
        "http://admitted.invalid:80/a?keep=1",
    );
    cookies.request_headers(vec![
        ("Host".into(), "visible.invalid:80".into()),
        ("Cookie".into(), "a=\"one;two\"; b=three".into()),
    ]);
    cookies.request_body_at(Some(&[]), 10.0);
    cookies.response_head_observed_at(
        200,
        Some("HTTP/1.1"),
        vec![(
            "Set-Cookie".into(),
            "a=\"one;two\"; Path=\"/a;b\"; SameSite=Lax; HttpOnly".into(),
        )],
        None,
        10.0,
    );
    cookies.response_body_complete_at(Some(&[]), 10.0);
    cookies.finish_at(None, 10.0);
    let cookies_entry = &json_export(&view, "cookies")["log"]["entries"][0];
    assert_eq!(
        cookies_entry["request"]["url"],
        "http://visible.invalid/a?keep=1"
    );
    assert_eq!(
        cookies_entry["request"]["cookies"],
        serde_json::json!([{"name":"a","value":"one;two"},{"name":"b","value":"three"}])
    );
    assert_eq!(cookies_entry["response"]["cookies"][0]["value"], "one;two");
    assert_eq!(cookies_entry["response"]["cookies"][0]["path"], "/a;b");
}

#[test]
fn har_rejects_invalid_websocket_text_without_replacement() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(&view, "invalid-ws", "GET", "http://owned.invalid/socket");
    exchange.request_body_at(Some(&[]), 10.0);
    exchange.response_head_observed_at(101, Some("HTTP/1.1"), vec![], None, 10.0);
    exchange.response_body_complete_at(Some(&[]), 10.0);
    exchange.finish_at(None, 10.0);
    exchange.websocket_start(10.0);
    exchange
        .websocket_message(
            MessageType::Text,
            true,
            11.0,
            Arc::new(MessageContent::from_bytes_for_test(vec![0xff])),
        )
        .unwrap();
    let mut plan = view.export("invalid-ws", ExportFormat::Har).unwrap();
    loop {
        match plan.next_chunk() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("invalid WebSocket text exported successfully"),
            Err(error) => {
                assert_eq!(error, ExportError::Decode);
                break;
            }
        }
    }
}

#[test]
fn har_and_zhar_read_spilled_websocket_content_to_completion() {
    let view = Arc::new(TrafficView::new(10, 1 << 20));
    let exchange = begin(&view, "spilled-har", "GET", "http://owned.invalid/socket");
    exchange.request_body_at(Some(&[]), 10.0);
    exchange.response_head_observed_at(101, Some("HTTP/1.1"), vec![], None, 10.0);
    exchange.response_body_complete_at(Some(&[]), 10.0);
    exchange.finish_at(None, 10.0);
    exchange.websocket_start(10.0);
    let mut text = vec![b'a'; 4095];
    text.extend_from_slice("é".as_bytes());
    exchange
        .websocket_message(
            MessageType::Text,
            true,
            11.0,
            Arc::new(MessageContent::from_file_for_test(&text, text.len() as u64)),
        )
        .unwrap();
    let binary: Vec<u8> = (0..5000).map(|index| index as u8).collect();
    exchange
        .websocket_message(
            MessageType::Binary,
            false,
            12.0,
            Arc::new(MessageContent::from_file_for_test(
                &binary,
                binary.len() as u64,
            )),
        )
        .unwrap();

    let har = export(&view, "spilled-har", ExportFormat::Har).unwrap();
    let document: Value = serde_json::from_slice(&har).unwrap();
    let messages = document["log"]["entries"][0]["_webSocketMessages"]
        .as_array()
        .unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["data"].as_str().unwrap().as_bytes(), text);
    let binary_encoded = base64::engine::general_purpose::STANDARD.encode(&binary);
    assert_eq!(messages[1]["data"], binary_encoded);
    let zhar = export(&view, "spilled-har", ExportFormat::Zhar).unwrap();
    let mut decoded = Vec::new();
    ZlibDecoder::new(zhar.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, har);
}

#[test]
fn har_and_zhar_report_spool_read_failure_without_success() {
    for format in [ExportFormat::Har, ExportFormat::Zhar] {
        let view = Arc::new(TrafficView::new(10, 1 << 20));
        let exchange = begin(&view, "spool-failure", "GET", "http://owned.invalid/socket");
        exchange.request_body_at(Some(&[]), 10.0);
        exchange.response_head_observed_at(101, Some("HTTP/1.1"), vec![], None, 10.0);
        exchange.response_body_complete_at(Some(&[]), 10.0);
        exchange.finish_at(None, 10.0);
        exchange.websocket_start(10.0);
        exchange
            .websocket_message(
                MessageType::Binary,
                false,
                11.0,
                Arc::new(MessageContent::from_file_for_test(b"short", 6)),
            )
            .unwrap();
        let mut plan = view.export("spool-failure", format).unwrap();
        let mut saw_error = None;
        while let Some(chunk) = plan.next_chunk().unwrap_or_else(|error| {
            saw_error = Some(error);
            None
        }) {
            drop(chunk);
        }
        assert_eq!(saw_error, Some(ExportError::Storage));
    }
}

#[test]
fn har_plan_release_after_row_prune_releases_spilled_owner() {
    let view = Arc::new(TrafficView::new(1, 1 << 20));
    let exchange = begin(&view, "pruned-har", "GET", "http://owned.invalid/socket");
    exchange.request_body_at(Some(&[]), 10.0);
    exchange.response_head_observed_at(101, Some("HTTP/1.1"), vec![], None, 10.0);
    exchange.response_body_complete_at(Some(&[]), 10.0);
    exchange.finish_at(None, 10.0);
    exchange.websocket_start(10.0);
    let owner = Arc::new(MessageContent::from_file_for_test(b"cancelled", 9));
    let weak_owner = Arc::downgrade(&owner);
    exchange
        .websocket_message(MessageType::Text, true, 11.0, Arc::clone(&owner))
        .unwrap();
    let plan = view.export("pruned-har", ExportFormat::Har).unwrap();
    drop(owner);
    drop(exchange);
    view.configure(0, 1 << 20);

    let replacement = begin(&view, "replacement-har", "GET", "http://owned.invalid/new");
    replacement.request_body_at(Some(&[]), 12.0);
    replacement.finish_at(None, 12.0);
    assert!(view.detail("pruned-har").is_none());
    assert!(weak_owner.upgrade().is_some());
    drop(plan);
    assert!(weak_owner.upgrade().is_none());
}
