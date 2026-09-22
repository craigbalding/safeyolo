use super::*;
use crate::{
    Config, Proxy, Runtime,
    test_context::{Context as TestContext, ContextSource},
};
use std::{io::Write, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const ID: &str = "req-00000000000000000000000000000000";
fn identity(agent: &str) -> ConnectionIdentity {
    ConnectionIdentity {
        agent_id: agent.into(),
        connection_id: "owned-connection".into(),
        source_id: Some("192.0.2.20".into()),
        reconciled: None,
    }
}

#[test]
fn gateway_header_redaction_matches_existing_flow_recorder_contract() {
    let pairs: Pairs = vec![
        (
            zeroize::Zeroizing::new(b"Authorization".to_vec()),
            zeroize::Zeroizing::new(b"Bearer exact-synthetic-origin-credential".to_vec()),
        ),
        (
            zeroize::Zeroizing::new(b"Content-Type".to_vec()),
            zeroize::Zeroizing::new(b"application/json".to_vec()),
        ),
    ];
    let encoded = super::headers_json(&pairs, None, Some(b"authorization"));
    let headers: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        headers,
        serde_json::json!([
            ["Authorization", "[GATEWAY:...tial]"],
            ["Content-Type", "application/json"]
        ])
    );
    assert!(!encoded.contains("exact-synthetic-origin-credential"));

    let invalid = vec![(
        zeroize::Zeroizing::new(b"X-Auth".to_vec()),
        zeroize::Zeroizing::new(b"\xffab".to_vec()),
    )];
    let encoded = super::headers_json(&invalid, None, Some(b"x-auth"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
        serde_json::json!([["X-Auth", "[GATEWAY:...?]"]])
    );
}

fn context() -> AppliedContext {
    AppliedContext {
        context: TestContext::from_pairs(
            [
                ("run", "owned-run"),
                ("agent", "declared-tool"),
                ("test", "t1"),
                ("role", "tester"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into())),
        )
        .unwrap(),
        source: ContextSource::Header,
        trusted_agent: Some("alice".into()),
        test_agent_match: Some(false),
        live_metadata: Map::new(),
    }
}
fn destination(path: &str, port: u16) -> super::super::Destination {
    super::super::Destination {
        host: "127.0.0.2".into(),
        policy_host: "127.0.0.2".into(),
        port,
        authority: format!("127.0.0.2:{port}"),
        uri_authority: format!("127.0.0.2:{port}"),
        scheme: "http".into(),
        path: path.into(),
    }
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn request_pairs() -> Vec<(&'static [u8], &'static [u8])> {
    vec![
        (b"Host", b"logical.invalid:12345"),
        (b"X-Repeat", b"first"),
        (b"X-Middle", b"middle"),
        (b"x-repeat", b"second"),
        (b"Content-Type", b"text/plain"),
    ]
}
fn response_pairs() -> Vec<(&'static [u8], &'static [u8])> {
    vec![
        (b"X-Repeat", b"one"),
        (b"x-safeyolo-request-ID", b"upstream-id"),
        (b"X-Middle", b"middle"),
        (b"x-repeat", b"two"),
        (b"X-SAFEYOLO-REQUEST-ID", b"second-id"),
        (b"X-Bytes", b"\xff"),
        (b"Content-Type", b"text/plain"),
    ]
}

#[test]
fn record_builder_matches_fourteen_actual_source_projections() {
    let source: Value = serde_json::from_str(include_str!(
        "../../../tests/http_flow_recording_source.json"
    ))
    .unwrap();
    assert_eq!(source["cases"].as_array().unwrap().len(), 14);
    for row in source["cases"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let recorder = Arc::new(FlowRecorder::start(
            true,
            &directory.path().join("flows"),
            None,
        ));
        let recording = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
        let path = if name.starts_with("ipv6_") {
            "/a"
        } else if name == "query_surrogate" {
            "/a?bad=%FF&%FF=first&%ff=second&%FE=last&bad=ignored"
        } else {
            "/a;v?x=first&x=second&blank=&snow=%E2%98%83"
        };
        let mut request_fields = request_pairs();
        let mut response_fields = response_pairs();
        if name == "invalid_authority_host" {
            request_fields[0] = (b"Host", b"logical.invalid:badport");
        }
        let mut req = b"request body".to_vec();
        let mut resp = b"response body".to_vec();
        if name == "gzip_both" {
            request_fields.push((b"Content-Encoding", b"gzip"));
            response_fields.push((b"Content-Encoding", b"gzip"));
            req = gzip(&req);
            resp = gzip(&resp);
        }
        if name == "request_decode_error" {
            request_fields.push((b"Content-Encoding", b"gzip"));
            req = b"invalid gzip".to_vec();
        }
        if name == "response_decode_error" {
            response_fields.push((b"Content-Encoding", b"gzip"));
            resp = b"invalid gzip".to_vec();
        }
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://127.0.0.2:12345{path}"))
            .header("host", "logical.invalid:12345")
            .body(())
            .unwrap();
        let mut selected = destination(
            path,
            if name == "ipv6_default_port" {
                80
            } else {
                12345
            },
        );
        if name.starts_with("ipv6_") {
            selected.policy_host = "::1".into();
        }
        recording.request(
            &request,
            &selected,
            request_fields.iter().copied(),
            false,
            None,
        );
        if name != "no_context" {
            recording.applied(
                &context(),
                (name != "streamed_absence").then_some(req.as_slice()),
                Ok(
                    if request_fields
                        .iter()
                        .any(|(k, _)| *k == b"Content-Encoding")
                    {
                        b"gzip"
                    } else {
                        b""
                    },
                ),
                1000.5,
            );
        }
        if name != "upstream_error_no_head" {
            recording.head(
                StatusCode::OK,
                Some(response_fields.into_iter()),
                Some(match name {
                    "h2_empty_reason" => b"",
                    "h1_latin1_reason" => b"Owned \xff\xe9",
                    _ => b"Owned reason",
                }),
            );
        }
        let success = !name.starts_with("upstream_error");
        if !success {
            recording.producer_error(&"owned native error witness");
        }
        let record = recording.state.lock().unwrap().record.take().unwrap();
        let built = recording.build(
            record,
            recorder.store().unwrap(),
            success,
            (name != "streamed_absence" && success).then_some(resp.as_slice()),
            false,
            1001.25,
        );
        let expected = &row["records"];
        if row["stats"]["errors"] == 1 {
            assert!(built.is_err(), "{name}");
            continue;
        }
        let built = built.unwrap();
        if expected.as_array().unwrap().is_empty() {
            assert!(built.is_none(), "{name}");
            continue;
        }
        let mut actual = built.unwrap();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        actual.metadata.insert(
            "request_body_hex".into(),
            hex(&actual.request_body.content).into(),
        );
        actual.metadata.insert(
            "response_body_hex".into(),
            hex(&actual.response_body.content).into(),
        );
        assert_eq!(
            Value::Object(actual.metadata.clone()),
            expected[0],
            "{name}"
        );
        assert!(recorder.shutdown());
    }
}

fn config(directory: &Path, target_host: &str) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy,json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"}],"addons":{"test_context":{"target_hosts":[target_host]},"flow_store":{"max_request_body_bytes":5,"max_response_body_bytes":6,"compress_bodies":false}}}).to_string()).unwrap();
    serde_json::from_value(json!({"listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock"),"source_id":"192.0.2.20"},{"agent_id":"bob","socket_path":directory.join("bob.sock"),"source_id":"192.0.2.21"}],"policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),"audit_log_path":directory.join("audit.jsonl"),"event_log":directory.join("events"),"flow_store_enabled":true,"flow_store_db_path":directory.join("flows.sqlite3"),"test_context_block":true,"circuit_breaker_enabled":false})).unwrap()
}
async fn send(
    path: &Path,
    origin: std::net::SocketAddr,
    route: &str,
    claim: bool,
    body: &[u8],
    encoding: &str,
) -> Vec<u8> {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let context = if claim {
        "X-SafeYolo-Test-Context: run=owned-run;agent=declared-tool;test=t1;role=tester\r\n"
    } else {
        ""
    };
    let head = format!(
        "POST http://{origin}{route} HTTP/1.1\r\nHost: logical.invalid:{}\r\nX-Repeat: first\r\nX-Middle: middle\r\nx-repeat: second\r\nConnection: close, X-Remove\r\nX-Remove: private-hop\r\nContent-Type: text/plain\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\n{context}\r\n",
        origin.port(),
        body.len(),
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
async fn origin_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&request);
    let length = head
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    request.extend_from_slice(&body);
    request
}

#[tokio::test]
async fn real_uds_http_records_owned_rows_full_decoded_sizes_and_error_without_origin_status() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let host = address.ip().to_string();
    let configuration = config(directory.path(), &host);
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let recorder = runtime.flow_recorder.clone();
    let store = recorder.store().unwrap().clone();
    let peer = tokio::spawn(async move {
        let mut observed = Vec::new();
        for index in 0..6 {
            let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            observed.push(origin_request(&mut stream).await);
            let body = if index == 0 {
                gzip(b"response body")
            } else {
                b"streamed response".to_vec()
            };
            let content_type = if index == 1 {
                "text/event-stream"
            } else {
                "text/plain"
            };
            let encoding = if matches!(index, 0 | 4 | 5) {
                "gzip"
            } else {
                "identity"
            };
            let mut head = b"HTTP/1.1 200 \tOwned ".to_vec();
            head.extend_from_slice(b"\xff\xe9 \t\r\n");
            head.extend_from_slice(format!("X-Repeat: one\r\nx-safeyolo-request-ID: upstream-id\r\nX-Middle: middle\r\nx-repeat: two\r\nX-SAFEYOLO-REQUEST-ID: other-id\r\nContent-Type: {content_type}\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes());
            stream.write_all(&head).await.unwrap();
            // Header-time SSE selection is meaningful before terminal DATA.
            tokio::task::yield_now().await;
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        observed
    });
    let alice = directory.path().join("alice.sock");
    let bob = directory.path().join("bob.sock");
    assert!(
        send(
            &alice,
            address,
            "/a?bad=%FF",
            true,
            &gzip(b"request body"),
            "gzip"
        )
        .await
        .starts_with(b"HTTP/1.1 200")
    );
    assert!(
        send(&bob, address, "/sse", true, b"request body", "identity")
            .await
            .starts_with(b"HTTP/1.1 200")
    );
    assert!(
        send(
            &alice,
            address,
            "/invalid-gzip",
            true,
            b"invalid gzip",
            "gzip"
        )
        .await
        .starts_with(b"HTTP/1.1 200")
    );
    let streamed = vec![b'x'; 10 * 1024 * 1024 + 1];
    assert!(
        send(
            &bob,
            address,
            "/streamed-request",
            true,
            &streamed,
            "identity"
        )
        .await
        .starts_with(b"HTTP/1.1 200")
    );
    // Production dispatch stops at TestContext's response decode error. The
    // later recorder is not called, even when request decoding also failed.
    for (route, body, encoding) in [
        ("/invalid-response", b"request body".as_slice(), "identity"),
        ("/both-invalid", b"invalid gzip".as_slice(), "gzip"),
    ] {
        let response = send(&alice, address, route, true, body, encoding).await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"streamed response"));
    }
    let observed = peer.await.unwrap();
    for raw in observed {
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text
                .to_ascii_lowercase()
                .contains("x-safeyolo-test-context")
        );
        assert!(!text.contains("private-hop"));
    }
    // This owned listener is now closed. A valid buffered request has applied
    // context before the real failed dial, so it records a status-less error.
    assert!(
        send(
            &alice,
            address,
            "/refused",
            true,
            b"request body",
            "identity"
        )
        .await
        .starts_with(b"HTTP/1.1 502")
    );
    assert!(
        send(
            &alice,
            address,
            "/missing",
            false,
            b"request body",
            "identity"
        )
        .await
        .starts_with(b"HTTP/1.1 428")
    );
    proxy.shutdown().await;
    assert!(!alice.exists() && !bob.exists() && !directory.path().join("ready").exists());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":4,"errors":1,"skipped":1,"queue_dropped":0,"write_errors":0})
    );
    let events: Vec<Value> = std::fs::read_to_string(directory.path().join("events"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let egress: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), 7);
    assert!(
        egress
            .iter()
            .all(|event| event["host"] == host && event["port"] == address.port())
    );
    assert!(runtime.policy.is_some() && runtime.config.temporary_policy_socket.is_none());

    let first = store.get_flow(1).unwrap().unwrap();
    let second = store.get_flow(2).unwrap().unwrap();
    let third = store.get_flow(3).unwrap().unwrap();
    let fourth = store.get_flow(4).unwrap().unwrap();
    assert_eq!(first["evidence_owner"], "alice");
    assert_eq!(first["test_agent"], "declared-tool");
    assert_eq!(first["source_id"], "192.0.2.20");
    assert_eq!(first["host"], "logical.invalid");
    assert_eq!(first["reason"], "Owned ÿé \t");
    assert_eq!(first["query_string"], "{\"bad\": \"\\udcff\"}");
    assert_eq!(first["request_body_size"], 12);
    assert_eq!(first["response_body_size"], 13);
    assert_eq!(
        store
            .body(1, Side::Request)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"reque"
    );
    assert_eq!(
        store
            .body(1, Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"respon"
    );
    let headers: Value =
        serde_json::from_str(first["request_headers_json"].as_str().unwrap()).unwrap();
    assert_eq!(
        &headers.as_array().unwrap()[1..4],
        &[
            json!(["X-Repeat", "first"]),
            json!(["X-Middle", "middle"]),
            json!(["x-repeat", "second"])
        ]
    );
    assert!(
        !first["request_headers_json"]
            .as_str()
            .unwrap()
            .contains("Via")
    );
    let headers: Value =
        serde_json::from_str(first["response_headers_json"].as_str().unwrap()).unwrap();
    assert_eq!(
        headers[1],
        json!(["x-safeyolo-request-ID", first["request_id"]])
    );
    assert!(!headers.to_string().contains("other-id"));
    assert_eq!(second["evidence_owner"], "bob");
    assert_eq!(second["response_body_size"], 0);
    assert_eq!(third["flow_state"], "completed");
    assert_eq!(third["request_body_size"], 0);
    assert_eq!(third["evidence_owner"], "bob");
    assert_eq!(fourth["flow_state"], "error");
    assert!(fourth["status_code"].is_null());
    assert!(fourth["reason"].as_str().unwrap().contains("refused"));
    assert!(store.get_flow(5).unwrap().is_none());
    assert_eq!(
        runtime
            .test_context
            .stats(super::super::declaration_time())
            .unwrap()
            .checks_total,
        8
    );
}

#[test]
fn gateway_injected_header_is_redacted_in_stored_flow() {
    let directory = tempfile::tempdir().unwrap();
    let recorder = Arc::new(FlowRecorder::start(
        true,
        &directory.path().join("flows.sqlite3"),
        None,
    ));
    let recording = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.2:12345/canary")
        .body(())
        .unwrap();
    recording.request(
        &request,
        &destination("/canary", 12345),
        [
            (b"Host".as_slice(), b"logical.invalid:12345".as_slice()),
            (
                b"Authorization".as_slice(),
                b"Bearer exact-synthetic-origin-credential".as_slice(),
            ),
            (b"X-Canary".as_slice(), b"ordinary-header-canary".as_slice()),
        ]
        .into_iter(),
        false,
        Some(b"authorization"),
    );
    recording.applied(&context(), Some(b"request-secret-canary"), Ok(b""), 1000.0);
    recording.head(
        StatusCode::OK,
        Some(response_pairs().into_iter()),
        Some(b"OK"),
    );
    recording.finish_at(true, Some(b"response-secret-canary"), false, 1001.0);
    assert!(recorder.shutdown());

    let row = recorder.store().unwrap().get_flow(1).unwrap().unwrap();
    let headers = row["request_headers_json"].as_str().unwrap();
    assert!(headers.contains("[GATEWAY:...tial]"));
    assert!(headers.contains("ordinary-header-canary"));
    assert!(!headers.contains("exact-synthetic-origin-credential"));
    assert_eq!(
        recorder
            .store()
            .unwrap()
            .body(1, Side::Request)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"request-secret-canary".as_slice()
    );
    assert_eq!(
        recorder
            .store()
            .unwrap()
            .body(1, Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"response-secret-canary".as_slice()
    );
}

#[tokio::test]
async fn h2_unread_response_terminal_records_all_data_and_early_metadata_stays_ineligible() {
    use super::super::test_context::{Provenance, ResponseCapture};
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper::Response;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    for (applied_before_response, response_error) in [(true, false), (false, false), (true, true)] {
        let directory = tempfile::tempdir().unwrap();
        let mut configuration = config(directory.path(), "127.0.0.2");
        configuration.listeners.clear();
        let runtime = Arc::new(
            Runtime::new(
                configuration,
                "recording-h2",
                Arc::new(tokio::sync::Mutex::new(())),
                None,
                None,
            )
            .unwrap(),
        );
        let recorder = runtime.flow_recorder.clone();
        let store = recorder.store().unwrap().clone();
        let recording = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.2:12345/body")
            .header("host", "logical.invalid:12345")
            .body(())
            .unwrap();
        recording.request(
            &request,
            &destination("/body", 12345),
            request_pairs().into_iter(),
            false,
            None,
        );
        let provenance = Arc::new(Provenance::new(
            runtime.clone(),
            identity("alice"),
            ID.into(),
            "POST".into(),
            "127.0.0.2".into(),
            "/body".into(),
        ));
        provenance.attach_recording(recording.clone());
        if applied_before_response {
            provenance
                .apply_request(context(), Some(b"request body"), Ok(b""), 1000.5)
                .unwrap();
        }
        let state = Arc::new(std::sync::RwLock::new(runtime));
        let capture = Arc::new(ResponseCapture::new(
            state,
            Some(provenance.clone()),
            None,
            None,
            None,
        ));
        let (client, server) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(
                    Response::builder()
                        .status(200)
                        .header("content-length", "12")
                        .header(
                            "content-encoding",
                            if response_error { "gzip" } else { "identity" },
                        )
                        .header("content-type", "text/plain")
                        .header("x-proof", "retained")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            send.send_data(Bytes::from_static(b"first "), false)
                .unwrap();
            send.send_data(Bytes::from_static(b"second"), true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                .await
                .unwrap();
        let driver = tokio::spawn(connection);
        let mut request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.2/body")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let completion = h2::ext::on_response_complete_with_capture(&mut request, capture.clone());
        let response = sender.send_request(request);
        let terminal = timeout(LIMIT, completion).await;
        let success = matches!(terminal, Ok(Ok(StatusCode::OK)));
        let failed = capture.finish(success);
        if !applied_before_response {
            provenance
                .apply_request(context(), Some(b"request body"), Ok(b""), 1000.5)
                .unwrap();
        }
        drop(response);
        driver.abort();
        peer.abort();
        let _ = driver.await;
        let _ = peer.await;
        assert!(success);
        assert!(!failed);
        assert!(!capture.finish(true));
        assert!(recorder.shutdown());
        if response_error {
            // A later teardown cannot retry a hook the production container
            // skipped after an earlier child failed.
            recording.finish(false, None, false);
            assert!(store.get_flow(1).unwrap().is_none());
            let source: Value = serde_json::from_str(include_str!(
                "../../../tests/production_dispatch_source.json"
            ))
            .unwrap();
            let source_case = source["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| {
                    row["mode"] == "production_container" && row["case"] == "response_content_error"
                })
                .unwrap();
            assert_eq!(recorder.stats(), source_case["recorder"]);
        } else if applied_before_response {
            let row = store.get_flow(1).unwrap().unwrap();
            assert_eq!(row["reason"], "");
            assert_eq!(row["response_body_size"], 12);
            assert_eq!(row["request_body_size"], 12);
            assert_eq!(
                store
                    .body(1, Side::Response)
                    .unwrap()
                    .unwrap()
                    .body
                    .as_slice(),
                b"first "
            );
            let headers: Value =
                serde_json::from_str(row["response_headers_json"].as_str().unwrap()).unwrap();
            assert!(
                headers
                    .as_array()
                    .unwrap()
                    .contains(&json!(["x-proof", "retained"]))
            );
            assert_eq!(recorder.stats()["recorded"], 1);
            assert_eq!(recorder.stats()["skipped"], 0);
        } else {
            assert!(store.get_flow(1).unwrap().is_none());
            assert_eq!(recorder.stats()["recorded"], 0);
            assert_eq!(recorder.stats()["skipped"], 1);
        }
    }
}

#[test]
fn scalar_encoding_failure_stays_a_writer_error_after_both_body_decodes() {
    for (request_error, response_error, host) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let recorder = Arc::new(FlowRecorder::start(
            true,
            &directory.path().join("flows"),
            None,
        ));
        let recording = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.2/body")
            .body(())
            .unwrap();
        let mut pairs = request_pairs();
        if host {
            pairs[0] = (b"Host", b"\xff.invalid");
        } else {
            pairs.retain(|(name, _)| *name != b"Content-Type");
            pairs.push((b"Content-Type", b"text/\xff"));
        }
        recording.request(
            &request,
            &destination("/body", 80),
            pairs.into_iter(),
            false,
            None,
        );
        recording.applied(
            &context(),
            Some(b"request body"),
            Ok(if request_error { b"gzip" } else { b"" }),
            1000.5,
        );
        let mut fields = response_pairs();
        if response_error {
            fields.push((b"content-encoding", b"gzip"));
        }
        recording.head(
            StatusCode::OK,
            Some(fields.into_iter()),
            Some(b"Owned reason"),
        );
        recording.finish_at(true, Some(b"response body"), false, 1001.25);
        assert!(recorder.shutdown());
        assert!(recorder.store().unwrap().get_flow(1).unwrap().is_none());
        assert_eq!(
            recorder.stats(),
            if request_error || response_error {
                json!({"recorded":0,"errors":1,"skipped":0,"queue_dropped":0,"write_errors":0})
            } else {
                json!({"recorded":1,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":1})
            }
        );
    }
}

#[tokio::test]
async fn cancelled_buffered_request_before_driver_records_one_error() {
    let directory = tempfile::tempdir().unwrap();
    let (parent, parent_address) = crate::test_owned_endpoint::bind().await;
    let (origin, origin_address) = crate::test_owned_endpoint::bind().await;
    let origin_host = origin_address.ip().to_string();
    let mut configuration = config(directory.path(), &origin_host);
    configuration.parent_proxy = Some(format!("https://{parent_address}"));
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let recorder = runtime.flow_recorder.clone();
    let store = recorder.store().unwrap().clone();
    let (head_sent, head_seen) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = parent.accept().await.unwrap();
        let mut first = [0];
        socket.read_exact(&mut first).await.unwrap();
        // The parent receives a TLS ClientHello but sends no handshake reply.
        // No outbound HTTP driver exists during this real suspended interval.
        head_sent.send(()).unwrap();
        tokio::io::copy(&mut socket, &mut tokio::io::sink())
            .await
            .unwrap();
    });
    let alice = directory.path().join("alice.sock");
    let mut client = UnixStream::connect(&alice).await.unwrap();
    let request = format!(
        "POST http://{origin_address}/held HTTP/1.1\r\nHost: logical.invalid\r\nContent-Length: 4\r\nContent-Type: text/plain\r\nX-SafeYolo-Test-Context: run=owned-run;agent=declared-tool;test=t1\r\n\r\nbody"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    timeout(LIMIT, head_seen).await.unwrap().unwrap();
    assert_eq!(
        runtime
            .test_context
            .stats(super::super::declaration_time())
            .unwrap()
            .allowed_total,
        1
    );
    drop(client);
    let recorded = timeout(LIMIT, async {
        while recorder.stats()["recorded"] != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    proxy.shutdown().await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    let origin_contact = timeout(Duration::from_millis(25), origin.accept())
        .await
        .is_ok();
    drop(origin);
    assert!(!alice.exists() && !directory.path().join("ready").exists());
    assert!(!origin_contact);
    let events: Vec<Value> = std::fs::read_to_string(directory.path().join("events"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let egress: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0]["route"], "parent");
    assert_eq!(egress[0]["host"], origin_host);
    assert_eq!(egress[0]["port"], origin_address.port());
    assert!(
        recorded.is_ok(),
        "cancelled applied request lost its recording terminal"
    );
    assert_eq!(
        recorder.stats(),
        json!({"recorded":1,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":0})
    );
    let row = store.get_flow(1).unwrap().unwrap();
    assert_eq!(row["flow_state"], "error");
    assert!(row["status_code"].is_null());
    assert_eq!(
        row["reason"],
        "native request cancelled before upstream driver"
    );
    assert_eq!(row["evidence_owner"], "alice");
    assert_eq!(row["request_body_size"], 4);
    assert_eq!(
        store
            .body(1, Side::Request)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"body"
    );
    assert!(store.get_flow(2).unwrap().is_none());
}

#[test]
#[ignore = "requires the retained Python 3.12 mitmproxy environment"]
fn production_container_source_dispatch_stays_reproducible() {
    let python = std::env::var_os("SAFEYOLO_SOURCE_PYTHON")
        .expect("set SAFEYOLO_SOURCE_PYTHON to the retained source environment");
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let output = std::process::Command::new(python)
        .arg(tests.join("production_dispatch.py"))
        .arg("--check")
        .arg(tests.join("production_dispatch_source.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn circuit_response_exception_stops_later_hooks_but_keeps_wire_and_committed_state() {
    for (name, settings, skips_hooks, committed, fail_audit) in [
        ("normal", json!({"failure_threshold":1}), false, true, false),
        (
            "comparison_error",
            json!({"failure_threshold":"invalid"}),
            true,
            false,
            false,
        ),
        (
            "after_commit_error",
            json!({"failure_threshold":1,"timeout_seconds":"invalid"}),
            true,
            true,
            false,
        ),
        (
            "audit_failure",
            json!({"failure_threshold":1}),
            false,
            true,
            true,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let (listener, address) = crate::test_owned_endpoint::bind().await;
        let host = address.ip().to_string();
        let mut configuration = config(directory.path(), &host);
        configuration.circuit_breaker_enabled = true;
        let policy_path = configuration.policy_file.as_ref().unwrap();
        let mut policy: Value =
            serde_json::from_slice(&std::fs::read(policy_path).unwrap()).unwrap();
        policy["addons"]["circuit_breaker"] = settings;
        std::fs::write(policy_path, policy.to_string()).unwrap();
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let peer_runtime = runtime.clone();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            let request = origin_request(&mut stream).await;
            if fail_audit {
                // Fail only response-phase writes to the owned diagnostic file.
                // The failure cannot prevent admission or origin delivery.
                *peer_runtime.events.lock().unwrap() =
                    std::fs::File::open(&peer_runtime.config.event_log).unwrap();
            }
            stream
                .write_all(
                    b"HTTP/1.1 500 Owned\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
                )
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            request
        });
        let reply = send(
            &directory.path().join("alice.sock"),
            address,
            "/circuit-error",
            true,
            b"request",
            "identity",
        )
        .await;
        let observed = timeout(LIMIT, peer).await.unwrap().unwrap();
        proxy.shutdown().await;
        assert!(reply.starts_with(b"HTTP/1.1 500"), "{name}");
        assert!(reply.ends_with(b"body"), "{name}");
        assert!(observed.ends_with(b"request"), "{name}");
        assert!(!directory.path().join("alice.sock").exists());
        assert!(!directory.path().join("ready").exists());
        let expected_recorded = usize::from(!skips_hooks);
        assert_eq!(
            runtime.flow_recorder.stats(),
            json!({"recorded":expected_recorded,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":0}),
            "{name}"
        );
        let store = runtime.flow_recorder.store().unwrap();
        assert_eq!(store.get_flow(1).unwrap().is_some(), !skips_hooks, "{name}");
        assert!(store.get_flow(2).unwrap().is_none(), "{name}");
        assert_eq!(
            runtime
                .test_context
                .stats(super::super::declaration_time())
                .unwrap()
                .allowed_total,
            1,
            "{name}"
        );
        let snapshot = runtime
            .circuits
            .snapshot(crate::circuit_runtime::now())
            .unwrap();
        if committed {
            assert_eq!(snapshot["states"][host.as_str()]["state"], "open", "{name}");
            assert_eq!(
                snapshot["states"][host.as_str()]["failure_count"],
                1,
                "{name}"
            );
        } else {
            assert!(snapshot["states"].as_object().unwrap().is_empty(), "{name}");
        }
        let events: Vec<Value> = std::fs::read_to_string(directory.path().join("events"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let response_provenance = events
            .iter()
            .filter(|event| {
                event["event"] == "security.test_context" && event["details"]["phase"] == "response"
            })
            .count();
        assert_eq!(
            response_provenance,
            usize::from(!skips_hooks && !fail_audit),
            "{name}"
        );
        let circuit_events = events
            .iter()
            .filter(|event| {
                event["event"] == "proxy.circuit"
                    && event["audit_intent"] == "ops.circuit_breaker.open"
            })
            .count();
        assert_eq!(
            circuit_events,
            usize::from(committed && !fail_audit),
            "{name}"
        );
    }
}

#[test]
fn probe_reached_terminals_skip_once_without_capturing_evidence() {
    struct UnreadError;
    impl std::fmt::Display for UnreadError {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("probe error text must not be copied")
        }
    }
    for terminal in ["success", "error", "cancel"] {
        let directory = tempfile::tempdir().unwrap();
        let recorder = Arc::new(FlowRecorder::start(
            true,
            &directory.path().join("flows.sqlite3"),
            None,
        ));
        let recording = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
        recording.mark_probe();
        let pending = recording.pending();
        let request = Request::builder().method("POST").body(()).unwrap();
        let fields = || {
            request_pairs().into_iter().inspect(|_| {
                panic!("probe headers must not be copied");
            })
        };
        recording.request(&request, &destination("/probe", 80), fields(), false, None);
        recording.applied(
            &context(),
            Some(b"invalid gzip"),
            Err(ContentError::Allocation),
            1000.5,
        );
        recording.head(StatusCode::OK, Some(fields()), Some(b"owned reason"));
        recording.producer_error(&UnreadError);
        {
            let state = recording.state.lock().unwrap();
            let record = state.record.as_ref().unwrap();
            assert!(record.probe);
            assert!(record.metadata.is_empty());
            assert!(!record.applied);
            assert!(record.body.is_none());
            assert!(record.encoding.is_empty());
            assert!(record.head.is_none());
            assert!(record.failure.is_none());
            assert!(record.error.is_none());
        }
        if terminal != "cancel" {
            recording.finish_at(terminal == "success", Some(b"invalid gzip"), true, 1001.25);
        }
        drop(pending);
        recording.finish_at(true, Some(b"must not retry"), true, 1002.0);
        recording.local_terminal(true);
        assert!(recorder.shutdown());
        assert!(recorder.store().unwrap().get_flow(1).unwrap().is_none());
        assert_eq!(
            recorder.stats(),
            json!({"recorded":0,"errors":0,"skipped":1,"queue_dropped":0,"write_errors":0}),
            "{terminal}"
        );
    }
}

#[test]
fn probe_build_exclusion_precedes_poison_and_unreached_response_stays_uncounted() {
    let directory = tempfile::tempdir().unwrap();
    let recorder = Arc::new(FlowRecorder::start(
        true,
        &directory.path().join("flows.sqlite3"),
        None,
    ));
    for poison in ["decode", "stored_failure", "capture_failure"] {
        let recording = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
        recording.mark_probe();
        {
            // Independently prove the final gate, even if a prior producer
            // retained metadata or failed capture before this terminal.
            let mut state = recording.state.lock().unwrap();
            let record = state.record.as_mut().unwrap();
            record.applied = true;
            record.metadata.insert("run".into(), "owned".into());
            record.metadata_encoding_error = true;
            if poison == "stored_failure" {
                record.failure = Some(ContentError::Allocation);
            }
            record.body = Some(Zeroizing::new(b"invalid gzip".to_vec()));
            record.encoding = Zeroizing::new(b"gzip".to_vec());
        }
        recording.finish_at(
            true,
            Some(b"invalid gzip"),
            poison == "capture_failure",
            1001.25,
        );
    }
    assert_eq!(recorder.stats()["skipped"], 3);
    assert_eq!(recorder.stats()["errors"], 0);

    let unreached = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
    unreached.mark_probe();
    let pending = unreached.pending();
    unreached.skip_response();
    unreached.finish_at(false, None, false, 1001.25);
    drop(pending);
    assert!(recorder.shutdown());
    assert!(recorder.store().unwrap().get_flow(1).unwrap().is_none());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":0,"errors":0,"skipped":3,"queue_dropped":0,"write_errors":0})
    );
}

#[test]
fn probe_marker_keeps_connect_inactive_and_ordinary_context_recording_active() {
    let directory = tempfile::tempdir().unwrap();
    let recorder = Arc::new(FlowRecorder::start(
        true,
        &directory.path().join("flows.sqlite3"),
        None,
    ));
    let connect = Recording::new(recorder.clone(), identity("alice"), ID.into(), false);
    connect.mark_probe();
    connect.finish_at(false, None, true, 1001.25);
    assert_eq!(recorder.stats()["skipped"], 0);

    let ordinary = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
    let request = Request::builder()
        .method("POST")
        .header("safeyolo_probe", "true") // Caller bytes never set the private marker.
        .body(())
        .unwrap();
    let mut ordinary_fields = request_pairs();
    ordinary_fields.push((b"safeyolo_probe", b"true"));
    ordinary.request(
        &request,
        &destination("/ordinary", 80),
        ordinary_fields.into_iter(),
        false,
        None,
    );
    ordinary.applied(&context(), Some(b"request body"), Ok(b""), 1000.5);
    ordinary.head(
        StatusCode::OK,
        Some(response_pairs().into_iter()),
        Some(b"OK"),
    );
    ordinary.finish_at(true, Some(b"response body"), false, 1001.25);
    let malformed = Recording::new(recorder.clone(), identity("alice"), ID.into(), true);
    malformed.request(
        &request,
        &destination("/malformed", 80),
        request_pairs().into_iter(),
        false,
        None,
    );
    malformed.applied(&context(), Some(b"invalid gzip"), Ok(b"gzip"), 1000.5);
    malformed.finish_at(true, Some(b"response body"), false, 1001.25);
    assert!(recorder.shutdown());
    let row = recorder.store().unwrap().get_flow(1).unwrap().unwrap();
    assert_eq!(row["evidence_owner"], "alice");
    assert_eq!(row["run"], "owned-run");
    assert_eq!(row["path"], "/ordinary");
    assert!(recorder.store().unwrap().get_flow(2).unwrap().is_none());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":1,"errors":1,"skipped":0,"queue_dropped":0,"write_errors":0})
    );
}
