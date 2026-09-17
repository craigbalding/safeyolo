use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Uri, body::Incoming, service::service_fn};
use hyper_util::{rt::TokioExecutor, rt::TokioIo};
use safeyolo_proxy::{AgentListener, Config, Inspection, Proxy};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

#[test]
fn native_http_body_adapter_skips_decode_without_body_scope() {
    let scanner = safeyolo_proxy::inspection::Scanner::default();
    scanner
        .load_policy_config(&json!({
            "scan_patterns": [{
                "name": "header-only",
                "pattern": "X-Trace",
                "scope": ["headers"],
                "target": "request",
                "action": "block"
            }]
        }))
        .unwrap();
    let decision = scanner
        .scan_http_request_bytes(
            safeyolo_proxy::inspection::UrlInput::Text("/path"),
            &[(b"content-encoding".as_slice(), b"gzip".as_slice())],
            Some(b"not-gzip"),
            safeyolo_proxy::inspection::Options::default(),
        )
        .unwrap();
    assert_eq!(
        decision.outcome,
        safeyolo_proxy::inspection::Outcome::NoMatch
    );
}

#[test]
fn native_http_scan_honors_cancellation_before_work_or_publication() {
    let scanner = safeyolo_proxy::inspection::Scanner::default();
    scanner
        .load_policy_config(&json!({
            "scan_patterns": [{
                "name": "body",
                "pattern": "SECRET",
                "scope": ["body"],
                "target": "request",
                "action": "block"
            }]
        }))
        .unwrap();
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    let result = scanner.scan_http_request_bytes_cancellable(
        safeyolo_proxy::inspection::UrlInput::Text("/path"),
        &[],
        Some(b"SECRET"),
        safeyolo_proxy::inspection::Options {
            block_request: true,
            ..Default::default()
        },
        &cancelled,
    );
    assert_eq!(
        result.unwrap_err().kind,
        safeyolo_proxy::inspection::ErrorKind::Cancelled
    );
}
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::Notify,
};

fn config(
    directory: &TempDir,
    policy: &std::path::Path,
    socket: &std::path::Path,
    block: bool,
) -> Config {
    let token = directory.path().join("admin-token");
    std::fs::write(token, b"credential-http-admin").unwrap();
    Config {
        listeners: vec![
            AgentListener {
                agent_id: "alice".into(),
                socket_path: socket.to_owned(),
                source_id: None,
            },
            AgentListener {
                agent_id: "bob".into(),
                socket_path: directory.path().join("bob.sock"),
                source_id: None,
            },
        ],
        agent_map_file: String::new(),
        data_dir: Some(directory.path().join("data")),
        temporary_policy_socket: None,
        policy_file: Some(policy.to_owned()),
        gateway_builtin_services_dir: None,
        gateway_services_dir: None,
        network_guard_enabled: true,
        network_guard_block: true,
        network_guard_homoglyph: true,
        credential_guard_block: block,
        circuit_breaker_enabled: true,
        circuit_state_file: None,
        agent_api_enabled: false,
        test_context_block: true,
        test_context_inject_declared: false,
        test_context_declared_ttl: json!(900),
        sse_streaming_enabled: true,
        sse_stream_json: false,
        flow_store_enabled: false,
        flow_store_db_path: directory.path().join("flows.sqlite3"),
        flow_pruner_max: 5000,
        flow_pruner_max_body_bytes: 1024 * 1024 * 1024,
        admin_port: Some(0),
        admin_api_token_file: Some(directory.path().join("admin-token")),
        admin_shield_extra_ports: String::new(),
        readiness_file: directory.path().join("ready.json"),
        reload_id: None,
        audit_log_path: Some(directory.path().join("audit.jsonl")),
        event_log: directory.path().join("events.jsonl"),
        parent_proxy: None,
        upstream_ca_file: None,
        tls_ca_file: None,
        ignore_hosts: Vec::new(),
        via_token: Some("credential-http-test".into()),
        inspection: None,
    }
}

async fn stats(directory: &TempDir) -> Value {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("ready.json")).unwrap())
            .unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(
            b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer credential-http-admin\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let split = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    assert!(
        std::str::from_utf8(&bytes[..split])
            .unwrap()
            .contains(" 200 ")
    );
    serde_json::from_slice(&bytes[split + 4..]).unwrap()
}

async fn origin(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>, ready: Arc<Notify>) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let Ok(size) = socket.read(&mut buffer).await else {
                    return;
                };
                if size == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..size]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let chunked = request
                .windows(b"/chunked".len())
                .any(|window| window == b"/chunked");
            seen.lock().unwrap().push(request);
            ready.notify_one();
            let body = b"origin-ok";
            if chunked {
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n8\r\norigin-ok\r\n0\r\n\r\n",
                    )
                    .await;
            } else {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(body).await;
            }
        });
    }
}

async fn wait_for_seen(seen: &Arc<Mutex<Vec<Vec<u8>>>>, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while seen.lock().unwrap().len() < count {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

async fn send(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    uri: Uri,
    credential: &str,
) -> hyper::Response<hyper::body::Incoming> {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", credential)
        .header("authorization", "Bearer duplicate")
        .header("Connection", "keep-alive, x-remove")
        .header("X-Remove", "header-canary")
        .header("X-SafeYolo-Trace", "1")
        .body(Empty::new())
        .unwrap();
    sender.send_request(request).await.unwrap()
}

async fn raw_exchange(socket: &std::path::Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

async fn raw_round_trip(socket: &std::path::Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut buffer = [0_u8; 4096];
            let size = stream.read(&mut buffer).await.unwrap();
            if size == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..size]);
            if response
                .windows(b"origin-ok".len())
                .any(|window| window == b"origin-ok")
                || response.starts_with(b"HTTP/1.1 403")
                || response.starts_with(b"HTTP/1.1 502")
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    response
}

fn invalid_h1_request(port: u16, path: &str, byte: u8) -> Vec<u8> {
    let mut request = format!(
        "GET http://127.0.0.1:{port}/{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer key-"
    )
    .into_bytes();
    request.push(byte);
    request.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
    request
}

fn h1_request_with_value(port: u16, path: &str, value: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "GET http://127.0.0.1:{port}/{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: "
    )
    .into_bytes();
    request.extend_from_slice(value);
    request.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
    request
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn native_parser_to_guard_invalid_utf8_matches_source_detector() {
    let source: Value = serde_json::from_str(include_str!("credential_guard_source.json")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"deny"}
            ],
            "credential_rules": [{
                "name":"synthetic-invalid-byte",
                "patterns":[source["pattern"].as_str().unwrap()],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    for row in source["rows"].as_array().unwrap() {
        let value = hex_bytes(row["fields"][0][1].as_str().unwrap());
        let path = row["id"].as_str().unwrap();
        let request = h1_request_with_value(origin_port, path, &value);
        let response = raw_round_trip(&socket, &request).await;
        if row["detected"].as_bool().unwrap() {
            assert!(response.starts_with(b"HTTP/1.1 403"), "{path}");
            assert!(seen.lock().unwrap().is_empty(), "{path}");
        } else {
            assert!(response.starts_with(b"HTTP/1.1 200"), "{path}");
            tokio::time::timeout(Duration::from_secs(2), ready.notified())
                .await
                .unwrap();
            let requests = seen.lock().unwrap();
            assert_eq!(requests.len(), 1, "{path}");
            assert!(
                requests[0]
                    .windows(value.len())
                    .any(|window| window == value),
                "{path}"
            );
            drop(requests);
            seen.lock().unwrap().clear();
        }
    }
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_pattern_scanner_http_request_and_response_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [{"action":"network:request", "resource":"*", "effect":"allow"}],
            "scan_patterns": [{"name":"request-secret","pattern":"SECRET","scope":["body"],"target":"request","action":"block"},
                {"name":"response-marker","pattern":"origin-ok","scope":["body"],"target":"response","action":"block"}]
        })
        .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy_config = config(&directory, &policy_path, &socket, false);
    proxy_config.inspection = Some(Inspection {
        policy_file: policy_path.clone(),
        block_request: true,
        block_response: false,
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let mut proxy = Proxy::start(proxy_config.clone()).await.unwrap();
    let matching_request = format!(
        "POST http://127.0.0.1:{origin_port}/scan HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECRET"
    );
    let blocked = raw_round_trip(&socket, matching_request.as_bytes()).await;
    assert!(blocked.starts_with(b"HTTP/1.1 403"), "{blocked:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "blocked request reached origin"
    );

    proxy_config.inspection.as_mut().unwrap().block_request = false;
    proxy_config.inspection.as_mut().unwrap().block_response = true;
    proxy.reload(proxy_config).await.unwrap();
    let allowed_request = format!(
        "POST http://127.0.0.1:{origin_port}/scan HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\nsafe"
    );
    let blocked_response = raw_round_trip(&socket, allowed_request.as_bytes()).await;
    assert!(
        blocked_response.starts_with(b"HTTP/1.1 502"),
        "{blocked_response:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    // H1 chunked responses do not carry Content-Length. They still use the
    // existing bounded replay owner and must reach the body scanner.
    let chunked_request = format!(
        "GET http://127.0.0.1:{origin_port}/chunked HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    );
    let blocked_chunked = raw_round_trip(&socket, chunked_request.as_bytes()).await;
    assert!(
        blocked_chunked.starts_with(b"HTTP/1.1 502"),
        "{blocked_chunked:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 2);
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    let pattern_events = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "security.pattern_scanner")
        .collect::<Vec<_>>();
    let mut response_events_by_request = std::collections::HashMap::new();
    for event in &pattern_events {
        if event["details"]["direction"] == "response" {
            *response_events_by_request
                .entry(event["request_id"].as_str().unwrap().to_owned())
                .or_insert(0usize) += 1;
        }
    }
    assert!(
        response_events_by_request.values().all(|count| *count == 1),
        "response inspection published more than once: {response_events_by_request:?}"
    );
    assert!(
        pattern_events
            .iter()
            .any(|event| event["details"]["direction"] == "request" && event["decision"] == "deny"),
        "request pattern audit missing: {pattern_events:?}"
    );
    assert!(
        pattern_events.iter().any(|event| event["details"]["direction"] == "response"
            && event["decision"] == "deny"),
        "response pattern audit missing: {pattern_events:?}"
    );
    origin_task.abort();
}

#[tokio::test]
async fn native_http_client_disconnect_cancels_scan_without_late_publication() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [{"action":"network:request", "resource":"*", "effect":"allow"}],
            "scan_patterns": [{"name":"cancellation","pattern":"^(a|aa)*\\1$","scope":["body"],"target":"request","action":"log"}]
        })
        .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready));
    let mut proxy_config = config(&directory, &policy_path, &socket, false);
    proxy_config.inspection = Some(Inspection {
        policy_file: policy_path.clone(),
        block_request: false,
        block_response: false,
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let proxy = Proxy::start(proxy_config).await.unwrap();
    let mut peer = UnixStream::connect(&socket).await.unwrap();
    let body = vec![b'a'; 4096];
    let head = format!(
        "POST http://127.0.0.1:{origin_port}/cancel HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len() + 1
    );
    peer.write_all(head.as_bytes()).await.unwrap();
    peer.write_all(&body).await.unwrap();
    peer.write_all(b"b").await.unwrap();
    // Give the scanner a chance to start, then close the client while its
    // backtracking VM is active. Shutdown must not wait for the old scan.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(peer);

    // Keep a second scan active while the connection owner's stop signal is
    // raised. This exercises Proxy::shutdown itself rather than only the
    // request-completion observer cancellation above.
    let mut active_peer = UnixStream::connect(&socket).await.unwrap();
    let active_head = format!(
        "POST http://127.0.0.1:{origin_port}/shutdown HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len() + 1
    );
    active_peer.write_all(active_head.as_bytes()).await.unwrap();
    active_peer.write_all(&body).await.unwrap();
    active_peer.write_all(b"b").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(3), proxy.shutdown())
        .await
        .expect("shutdown left active HTTP inspection worker running");
    drop(active_peer);
    assert!(
        seen.lock().unwrap().is_empty(),
        "disconnected request reached origin"
    );
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap_or_default();
    assert!(!audit.lines().any(|line| {
        serde_json::from_str::<Value>(line)
            .ok()
            .is_some_and(|event| event["event"] == "security.pattern_scanner")
    }));
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_invalid_utf8_h1_warn_block_and_origin_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let pattern = r"key-\uDCFF";
    let write_policy = |pattern: &str| {
        std::fs::write(
            &policy_path,
            json!({
                "permissions": [
                    {"action":"network:request", "resource":"*", "effect":"allow"},
                    {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"deny"}
                ],
                "credential_rules": [{
                    "name":"invalid-byte",
                    "patterns":[pattern],
                    "allowed_hosts":["127.0.0.1"],
                    "header_names":["authorization"]
                }],
                "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
            })
            .to_string(),
        )
        .unwrap();
    };
    write_policy(pattern);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, false))
        .await
        .unwrap();
    let matching = invalid_h1_request(origin_port, "invalid-match", 0xff);
    let warned = raw_round_trip(&socket, &matching).await;
    assert!(warned.starts_with(b"HTTP/1.1 200"), "{warned:?}");
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert!(
        seen.lock().unwrap()[0]
            .windows(b"key-\xff".len())
            .any(|window| window == b"key-\xff")
    );

    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let blocked = raw_round_trip(&socket, &matching).await;
    assert!(blocked.starts_with(b"HTTP/1.1 403"), "{blocked:?}");
    assert_eq!(seen.lock().unwrap().len(), 1);

    // An even backslash run makes the source spelling literal.  The same
    // malformed value must therefore pass through instead of matching the
    // true surrogateescape pattern above.
    write_policy(r"key-\\uDCFF");
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let escaped_literal = raw_round_trip(&socket, &matching).await;
    assert!(
        escaped_literal.starts_with(b"HTTP/1.1 200"),
        "{escaped_literal:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let nonmatching = invalid_h1_request(origin_port, "invalid-nonmatch", 0xfe);
    let allowed = raw_round_trip(&socket, &nonmatching).await;
    assert!(allowed.starts_with(b"HTTP/1.1 200"), "{allowed:?}");
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(
            requests[1]
                .windows(b"key-\xff".len())
                .any(|window| window == b"key-\xff")
        );
        assert!(
            requests[2]
                .windows(b"key-\xfe".len())
                .any(|window| window == b"key-\xfe")
        );
    }
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_invalid_utf8_h2_warn_block_and_origin_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::create_dir_all(directory.path().join("data")).unwrap();
    std::fs::write(directory.path().join("data/hmac_secret"), b"invalid-h2-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.2/*", "effect":"deny"}
            ],
            "credential_rules": [{
                "name":"invalid-byte-h2",
                "patterns":[r"key-\uDCFF"],
                "allowed_hosts":["127.0.0.2"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    let mut proxy_config = config(&directory, &policy_path, &socket, false);
    let proxy_ca = {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&key).unwrap();
        std::fs::write(
            directory.path().join("mitmproxy-ca.pem"),
            format!("{}{}", key.serialize_pem(), ca.pem()),
        )
        .unwrap();
        proxy_config.tls_ca_file = Some(directory.path().join("mitmproxy-ca.pem"));
        ca.der().clone()
    };
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.2".into()]).unwrap();
    std::fs::write(directory.path().join("upstream.pem"), cert.pem()).unwrap();
    proxy_config.upstream_ca_file = Some(directory.path().join("upstream.pem"));
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let authority = format!("127.0.0.2:{}", listener.local_addr().unwrap().port());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let origin_seen = seen.clone();
    let origin_task = tokio::spawn(async move {
        let tls = Arc::new(tls);
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = tls.clone();
            let origin_seen = origin_seen.clone();
            tokio::spawn(async move {
                let socket = tokio_rustls::TlsAcceptor::from(tls)
                    .accept(socket)
                    .await
                    .unwrap();
                assert_eq!(socket.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                let service = service_fn(move |request: Request<Incoming>| {
                    if let Some(value) = request.headers().get("authorization") {
                        origin_seen.lock().unwrap().push(value.as_bytes().to_vec());
                    }
                    async move {
                        Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from_static(b"h2-origin-ok")))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let mut proxy = Proxy::start(proxy_config.clone()).await.unwrap();
    let mut upstream = UnixStream::connect(&socket).await.unwrap();
    upstream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut connect_reply = Vec::new();
    while !connect_reply.ends_with(b"\r\n\r\n") {
        connect_reply.push(upstream.read_u8().await.unwrap());
    }
    assert!(
        connect_reply.starts_with(b"HTTP/1.1 200"),
        "{connect_reply:?}"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(proxy_ca).unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_stream = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(
            rustls::pki_types::ServerName::try_from("127.0.0.2".to_owned()).unwrap(),
            upstream,
        )
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .unwrap();
    let connection_task = tokio::spawn(connection);
    let nonmatching = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/nonmatching"))
                .header("authorization", "Bearer key-h2")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonmatching.status(), 200);
    let _ = nonmatching.collect().await.unwrap();
    let invalid = hyper::header::HeaderValue::from_bytes(b"Bearer key-\xff").unwrap();
    let warned = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/matching"))
                .header("authorization", invalid.clone())
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(warned.status(), 200);
    let _ = warned.collect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(seen.lock().unwrap()[1], b"Bearer key-\xff");

    proxy_config.credential_guard_block = true;
    proxy.reload(proxy_config.clone()).await.unwrap();
    let blocked = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/blocked"))
                .header("authorization", invalid)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.status(), 403);
    let _ = blocked.collect().await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 2);
    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_allows_origin_bytes_blocks_forbidden_host_and_reuses_h1() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-test-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"synthetic",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let local_uri: Uri = "http://_safeyolo.proxy.internal/status".parse().unwrap();
    let local = send(&mut sender, local_uri, "Bearer key-allowed").await;
    assert_eq!(local.status(), 503);
    assert!(
        !local
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .windows(b"key-allowed".len())
            .any(|window| window == b"key-allowed")
    );
    let allowed_uri: Uri = format!("http://127.0.0.1:{origin_port}/allowed?Q=%252F")
        .parse()
        .unwrap();
    let allowed = send(&mut sender, allowed_uri, "Bearer key-allowed").await;
    assert_eq!(allowed.status(), 200);
    assert_eq!(
        allowed.collect().await.unwrap().to_bytes(),
        b"origin-ok".as_slice()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    // Two independent trusted UDS identities exercise concurrent native H1
    // admission while Alice's connection is also reused for later requests.
    let bob_stream = UnixStream::connect(directory.path().join("bob.sock"))
        .await
        .unwrap();
    let (mut bob_sender, bob_connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(bob_stream))
            .await
            .unwrap();
    let bob_connection_task = tokio::spawn(bob_connection);
    let (alice_again, bob_again) = tokio::join!(
        send(
            &mut sender,
            format!("http://127.0.0.1:{origin_port}/alice-again")
                .parse()
                .unwrap(),
            "Bearer key-allowed",
        ),
        send(
            &mut bob_sender,
            format!("http://127.0.0.1:{origin_port}/bob")
                .parse()
                .unwrap(),
            "Bearer key-allowed",
        )
    );
    assert_eq!(alice_again.status(), 200);
    assert_eq!(bob_again.status(), 200);
    let _ = alice_again.collect().await.unwrap();
    let _ = bob_again.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    wait_for_seen(&seen, 3).await;

    let blocked_uri: Uri = "http://blocked.invalid/private".parse().unwrap();
    let blocked = send(&mut sender, blocked_uri, "Bearer key-allowed").await;
    assert_eq!(blocked.status(), 428);
    let blocked_body = blocked.collect().await.unwrap().to_bytes();
    assert!(
        !blocked_body
            .windows(b"key-allowed".len())
            .any(|window| window == b"key-allowed")
    );
    assert_eq!(seen.lock().unwrap().len(), 3);
    let delivered = String::from_utf8(seen.lock().unwrap()[0].clone()).unwrap();
    assert!(delivered.contains("authorization: Bearer key-allowed\r\n"));
    assert!(delivered.contains("authorization: Bearer duplicate\r\n"));
    assert!(!delivered.contains("header-canary"));
    assert!(delivered.contains("GET /allowed?Q=%252F HTTP/1.1\r\n"));

    let initial_stats = stats(&directory).await;
    assert_eq!(
        initial_stats["credential-guard"],
        json!({
            "violations_total": 1,
            "violations_by_type": {"synthetic": 1},
            "rules_count": 1
        })
    );

    // Feed a raw mixed-case duplicate H1 request with a chunked streaming
    // upload through the actual UDS parser. The receiver is a controlled
    // listener, but a denied credential must stop before accept, header
    // delivery, or body delivery.
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"deny"}
            ],
            "credential_rules": [{
                "name":"synthetic",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let forbidden_receiver = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forbidden_port = forbidden_receiver.local_addr().unwrap().port();
    let forbidden_body = b"forbidden-upload-canary";
    let mut forbidden_request = format!(
        "POST http://127.0.0.1:{forbidden_port}/forbidden HTTP/1.1\r\nHost: 127.0.0.1:{forbidden_port}\r\nAuthorization: Bearer key-forbidden\r\naUtHoRiZaTiOn: Bearer duplicate\r\nConnection: close, X-Remove\r\nX-Remove: header-canary\r\nX-SafeYolo-Trace: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    forbidden_request.extend_from_slice(format!("{:x}\r\n", forbidden_body.len()).as_bytes());
    forbidden_request.extend_from_slice(forbidden_body);
    forbidden_request.extend_from_slice(b"\r\n0\r\n\r\n");
    let forbidden = raw_exchange(&socket, &forbidden_request).await;
    assert!(forbidden.starts_with(b"HTTP/1.1 403"));
    assert!(
        !forbidden
            .windows(forbidden_body.len())
            .any(|window| window == forbidden_body)
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            forbidden_receiver.accept()
        )
        .await
        .is_err(),
        "credential denial reached the controlled receiver"
    );
    let forbidden_request_id = String::from_utf8_lossy(&forbidden)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-safeyolo-request-id")
                .then(|| value.trim().to_owned())
        })
        .unwrap();
    let denied_stats = stats(&directory).await;
    assert_eq!(denied_stats["credential-guard"]["violations_total"], 2);

    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"synthetic-reloaded",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let blocked_after_reload = send(
        &mut sender,
        "http://blocked.invalid/reloaded".parse().unwrap(),
        "Bearer key-allowed",
    )
    .await;
    assert_eq!(blocked_after_reload.status(), 428);
    let _ = blocked_after_reload.collect().await.unwrap();
    let reloaded_stats = stats(&directory).await;
    assert_eq!(reloaded_stats["credential-guard"]["violations_total"], 3);
    assert_eq!(reloaded_stats["credential-guard"]["rules_count"], 1);

    drop(sender);
    let _ = connection_task.await;
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    assert_eq!(events.matches("proxy.credential_guard").count(), 6);
    assert!(!events.contains("key-allowed"));
    assert!(!events.contains("header-canary"));
    let guard_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    let fingerprints = guard_events
        .iter()
        .map(|event| event["evaluations"][0]["finding"]["fingerprint"].clone())
        .collect::<Vec<_>>();
    assert_eq!(fingerprints.len(), 6);
    assert_eq!(fingerprints[0], fingerprints[1]);
    assert_eq!(fingerprints[1], fingerprints[2]);
    assert_eq!(fingerprints[2], fingerprints[3]);
    assert_ne!(fingerprints[3], fingerprints[4]);
    assert_ne!(fingerprints[4], fingerprints[5]);
    assert_eq!(fingerprints[0], fingerprints[5]);
    assert_eq!(
        guard_events[0]["evaluations"][0]["finding"]["header"],
        "authorization"
    );
    let forbidden_event = guard_events
        .iter()
        .find(|event| event["request_id"] == forbidden_request_id)
        .unwrap();
    assert_eq!(
        forbidden_event["evaluations"][0]["finding"]["header"],
        "Authorization"
    );
    assert_eq!(
        guard_events[5]["evaluations"][0]["finding"]["rule"],
        "synthetic-reloaded"
    );
    assert_eq!(guard_events[0]["trace"][0]["state"], "evaluated");
    assert_eq!(guard_events[0]["trace"][0]["outcome"], "detected");
    assert_eq!(guard_events[1]["trace"][0]["outcome"], "detected");
    drop(bob_sender);
    let _ = bob_connection_task.await;
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("security.credential_guard"));
    assert!(!audit.contains("key-allowed"));
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_warn_mode_delivers_and_reports_trace_audit_and_stats() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-warn-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"blocked.invalid/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"warn-rule",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["blocked.invalid"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, false))
        .await
        .unwrap();

    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let response = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/warn")
            .parse()
            .unwrap(),
        "Bearer key-warn",
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.collect().await.unwrap().to_bytes(),
        b"origin-ok".as_slice()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    let report = stats(&directory).await;
    assert_eq!(report["credential-guard"]["violations_total"], 1);
    assert_eq!(
        report["credential-guard"]["violations_by_type"]["warn-rule"],
        1
    );
    assert_eq!(report["credential-guard"]["rules_count"], 1);

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let event = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["event"] == "proxy.credential_guard")
        .unwrap();
    assert_eq!(event["outcome"], "warned");
    assert_eq!(event["trace"][0]["outcome"], "detected");
    assert_eq!(event["trace"][1]["outcome"], "warned");
    assert!(!events.contains("key-warn"));
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"decision\": \"warn\""));
    assert!(!audit.contains("key-warn"));
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_hmac_exception_survives_reload_and_rejects_other_credential() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-hmac-key").unwrap();
    let policy = |credential: Value| {
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                credential
            ],
            "credential_rules": [{
                "name":"hmac-rule",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
    };
    std::fs::write(
        &policy_path,
        policy(json!({"action":"credential:use", "resource":"*", "effect":"allow"})).to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);

    let first = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/hmac")
            .parse()
            .unwrap(),
        "Bearer key-exception",
    )
    .await;
    assert_eq!(first.status(), 200);
    let _ = first.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    let first_event = std::fs::read_to_string(directory.path().join("events.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["event"] == "proxy.credential_guard")
        .unwrap();
    let fingerprint = first_event["evaluations"][0]["finding"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(fingerprint.len(), 16);
    let hmac_exception = format!("hmac:{fingerprint}");

    std::fs::write(
        &policy_path,
        policy(json!({
            "action":"credential:use",
            "resource":"127.0.0.1/*",
            "effect":"allow",
            "condition":{"credential":[hmac_exception]}
        }))
        .to_string(),
    )
    .unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let exact = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/hmac-exact")
            .parse()
            .unwrap(),
        "Bearer key-exception",
    )
    .await;
    assert_eq!(exact.status(), 200);
    let _ = exact.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let other = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/hmac-other")
            .parse()
            .unwrap(),
        "Bearer key-other",
    )
    .await;
    assert_eq!(other.status(), 428);
    let _ = other.collect().await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 2);
    let reloaded = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_events = reloaded
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(guard_events.len(), 3);
    assert_eq!(
        guard_events[0]["evaluations"][0]["finding"]["fingerprint"],
        guard_events[1]["evaluations"][0]["finding"]["fingerprint"]
    );
    assert_eq!(guard_events[2]["outcome"], "blocked");
    assert_eq!(
        stats(&directory).await["credential-guard"]["violations_total"],
        1
    );

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_policy_disabled_domain_and_client_bypasses_forward() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-bypass-key").unwrap();
    let base = || {
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"deny"}
            ],
            "credential_rules": [{
                "name":"bypass-rule",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }]
        })
    };
    let mut initial = base();
    initial["addons"] = json!({
        "credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}
    });
    std::fs::write(&policy_path, initial.to_string()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);

    let mut domain_bypass = base();
    domain_bypass["addons"] = initial["addons"].clone();
    domain_bypass["domains"] = json!({"127.0.0.1":{"bypass":["credential_guard"]}});
    std::fs::write(&policy_path, domain_bypass.to_string()).unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let domain = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/domain-bypass")
            .parse()
            .unwrap(),
        "Bearer key-domain",
    )
    .await;
    assert_eq!(domain.status(), 200);
    let _ = domain.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let mut client_bypass = base();
    client_bypass["addons"] = initial["addons"].clone();
    client_bypass["clients"] = json!({"alice":{"bypass":["credential_guard"]}});
    std::fs::write(&policy_path, client_bypass.to_string()).unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let client = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/client-bypass")
            .parse()
            .unwrap(),
        "Bearer key-client",
    )
    .await;
    assert_eq!(client.status(), 200);
    let _ = client.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let mut disabled = base();
    disabled["addons"] = json!({
        "credential_guard":{"enabled":false,"settings":{"use_default_credential_rules":false}}
    });
    std::fs::write(&policy_path, disabled.to_string()).unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let disabled = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/disabled")
            .parse()
            .unwrap(),
        "Bearer key-disabled",
    )
    .await;
    assert_eq!(disabled.status(), 200);
    let _ = disabled.collect().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 3);
    let report = stats(&directory).await;
    assert_eq!(report["credential-guard"]["violations_total"], 0);

    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(guard_events.len(), 3);
    assert!(guard_events.iter().all(|event| {
        event["outcome"] == "bypassed" && event["audit"].as_array().unwrap().is_empty()
    }));
    assert_eq!(guard_events[0]["trace"][0]["reason"], "policy_disabled");
    assert_eq!(guard_events[1]["trace"][0]["reason"], "policy_disabled");
    assert_eq!(guard_events[2]["trace"][0]["reason"], "policy_disabled");
    origin_task.abort();
}
