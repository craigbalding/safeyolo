use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Uri, body::Incoming, service::service_fn};
use hyper_util::{rt::TokioExecutor, rt::TokioIo};
use safeyolo_proxy::{AgentListener, Config, Inspection, Proxy};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    io::Write,
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
        plumb: Default::default(),
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

async fn raw_admin_exchange(directory: &TempDir, request: &[u8]) -> Vec<u8> {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("ready.json")).unwrap())
            .unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    bytes
}

async fn set_mode(config: &Config, addon: &str, mode: &str) {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;
    let body = format!(r#"{{"mode":"{mode}"}}"#);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!(
        "PUT /plugins/{addon}/mode HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer credential-http-admin\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let status = std::str::from_utf8(&response)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    assert_eq!(status, "200", "operator mode update failed: {response:?}");
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

/// Capture a complete ordinary HTTP/1 request at the controlled origin. The
/// existing origin helper intentionally stops at the head because most guard
/// cases have no body; this owner is used where the forwarding assertion must
/// compare the application bytes exactly.
async fn full_origin(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>, ready: Arc<Notify>) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let Ok(size) = socket.read(&mut buffer).await else {
                    return;
                };
                if size == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..size]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let content_length = std::str::from_utf8(&request[..header_end])
                .ok()
                .and_then(|headers| {
                    headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let Ok(size) = socket.read(&mut buffer).await else {
                    return;
                };
                if size == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..size]);
            }
            seen.lock().unwrap().push(request);
            ready.notify_one();
            let body = b"origin-ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
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

/// Keep a real TCP receiver active while a request is evaluated.  An entry in
/// `seen` means that the proxy opened the forbidden connection; the captured
/// bytes distinguish a connection with no application data from one that
/// received request headers or a body.
async fn live_receiver(
    listener: TcpListener,
    seen: Arc<Mutex<Option<Vec<u8>>>>,
    ready: Arc<Notify>,
) {
    ready.notify_one();
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    if let Ok(Ok(size)) =
        tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buffer)).await
    {
        bytes.extend_from_slice(&buffer[..size]);
    }
    *seen.lock().unwrap() = Some(bytes);
}

async fn response_head(stream: &mut UnixStream) -> Vec<u8> {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut buffer = [0_u8; 4096];
            let size = stream.read(&mut buffer).await.unwrap();
            if size == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..size]);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .unwrap();
    response
}

fn response_header(response: &[u8], name: &str) -> String {
    String::from_utf8_lossy(response)
        .lines()
        .find_map(|line| {
            let (field, value) = line.split_once(':')?;
            field
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
        .unwrap()
}

fn single_credential_h1_request(port: u16, path: &str, credential: &str) -> Vec<u8> {
    format!(
        "GET http://127.0.0.1:{port}/{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {credential}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn response_request_id(response: &hyper::Response<Incoming>) -> String {
    response
        .headers()
        .get("x-safeyolo-request-id")
        .expect("native response request identity missing")
        .to_str()
        .unwrap()
        .to_owned()
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn native_guard_allowed_h1_forwarding_preserves_headers_and_body_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-exact-key").unwrap();
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
    let origin_task = tokio::spawn(full_origin(listener, seen.clone(), ready.clone()));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    // This is an actual UDS-to-TCP wire request. The credential guard may
    // inspect it, but every allowed application byte must reach the origin in
    // the same order, including duplicate header fields and binary body data.
    let body = b"raw-body\0with-ff-\xff\n";
    let mut request = format!(
        "POST http://127.0.0.1:{origin_port}/exact?Q=%252F HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nAuthorization: Bearer key-clean\r\naUtHoRiZaTiOn: auxiliary\r\nX-Dup: one\r\nx-dup: two\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    let response = raw_round_trip(&socket, &request).await;
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let wire = seen.lock().unwrap().first().cloned().unwrap();
    let split = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    assert_eq!(
        &wire[split..],
        body,
        "allowed body bytes changed in transit"
    );
    let head = std::str::from_utf8(&wire[..split]).unwrap();
    assert!(head.contains("POST /exact?Q=%252F HTTP/1.1\r\n"));
    assert!(
        head.contains("Authorization: Bearer key-clean\r\n"),
        "{head:?}"
    );
    assert!(head.contains("aUtHoRiZaTiOn: auxiliary\r\n"), "{head:?}");
    assert!(head.contains("X-Dup: one\r\n"), "{head:?}");
    assert!(head.contains("x-dup: two\r\n"), "{head:?}");
    let first_dup = head.find("X-Dup: one\r\n").unwrap();
    let second_dup = head.find("x-dup: two\r\n").unwrap();
    assert!(first_dup < second_dup, "{head:?}");
    assert!(!head.contains("Connection:"), "{head:?}");

    let live_stats = stats(&directory).await;
    assert_eq!(live_stats["credential-guard"]["violations_total"], 0);
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_event = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["event"] == "proxy.credential_guard")
        .unwrap();
    assert_eq!(guard_event["outcome"], "allowed");
    assert_eq!(
        guard_event["evaluations"][0]["finding"]["rule"],
        "synthetic"
    );
    assert_eq!(guard_event["evaluations"][0]["effect"], "allow");

    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_parser_boundary_preserves_signed_target_duplicates_and_body() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"parser-boundary-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"signed-target",
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
    let origin_task = tokio::spawn(full_origin(listener, seen.clone(), ready.clone()));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, false))
        .await
        .unwrap();

    // This is one raw UDS request through the actual H1 parser, credential
    // guard, hygiene step, and TCP origin. The target is kept in the signed
    // URL form used by the source witnesses; duplicate query keys and escaped
    // octets must remain in the forwarded request target.
    let body = b"signed-body\0with-ff-\xff\n";
    let mut request = format!(
        "POST http://127.0.0.1:{origin_port}/signed/%2F?Q=a%2Bb&Q=%252F HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nAuthorization: Bearer key-clean\r\naUtHoRiZaTiOn: auxiliary\r\nConnection: "
    )
    .into_bytes();
    request.push(0xff);
    request.extend_from_slice(
        format!(
            ", X-Remove\r\nX-Remove: nominated-canary\r\nX-Duplicate: first\r\nx-duplicate: second\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    request.extend_from_slice(body);

    let response = raw_round_trip(&socket, &request).await;
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();

    let wire = seen.lock().unwrap().first().cloned().unwrap();
    let split = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    let head = std::str::from_utf8(&wire[..split]).unwrap();
    assert!(
        head.starts_with("POST /signed/%2F?Q=a%2Bb&Q=%252F HTTP/1.1\r\n"),
        "{head:?}"
    );
    assert!(
        head.contains("Authorization: Bearer key-clean\r\n"),
        "{head:?}"
    );
    assert!(head.contains("aUtHoRiZaTiOn: auxiliary\r\n"), "{head:?}");
    let first_authorization = head.find("Authorization: Bearer key-clean\r\n").unwrap();
    let second_authorization = head.find("aUtHoRiZaTiOn: auxiliary\r\n").unwrap();
    assert!(first_authorization < second_authorization, "{head:?}");
    assert!(head.contains("X-Duplicate: first\r\n"), "{head:?}");
    assert!(head.contains("x-duplicate: second\r\n"), "{head:?}");
    assert!(
        head.find("X-Duplicate: first\r\n").unwrap()
            < head.find("x-duplicate: second\r\n").unwrap(),
        "{head:?}"
    );
    assert!(
        !head.contains("Connection:"),
        "nominated connection leaked: {head:?}"
    );
    assert!(
        !head.contains("X-Remove:"),
        "nominated header leaked: {head:?}"
    );
    assert_eq!(&wire[split..], body, "body bytes changed in transit");
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_event = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["event"] == "proxy.credential_guard")
        .unwrap();
    assert_eq!(guard_event["outcome"], "allowed");
    assert_eq!(guard_event["evaluations"][0]["finding"]["rule"], "signed-target");
    assert_eq!(guard_event["evaluations"][0]["effect"], "allow");

    proxy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn native_guard_classifies_unknown_entropy_and_keeps_ordinary_headers_uninspected() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-classification-key").unwrap();
    let initial_policy = json!({
        "permissions": [
            {"action":"network:request", "resource":"*", "effect":"allow"},
            {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
        ],
        "credential_rules": [{
            "name":"known",
            "patterns":["key-[a-z]+"],
            "allowed_hosts":["127.0.0.1"],
            "header_names":["authorization"]
        }],
        "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
    });
    std::fs::write(&policy_path, initial_policy.to_string()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready.clone()));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    // The first request establishes the configured rule and supplies the
    // keyed value used by the later explicit exception. It is sent over the
    // real trusted UDS and is observed byte-for-byte by the controlled origin.
    let known = raw_round_trip(
        &socket,
        &single_credential_h1_request(origin_port, "known", "key-known"),
    )
    .await;
    assert!(known.starts_with(b"HTTP/1.1 200"), "{known:?}");
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(
        seen.lock().unwrap()[0]
            .windows(b"key-known".len())
            .any(|window| { window == b"key-known" })
    );

    let first_event = std::fs::read_to_string(directory.path().join("events.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| event["event"] == "proxy.credential_guard")
        .unwrap();
    assert_eq!(first_event["evaluations"][0]["finding"]["rule"], "known");
    assert_eq!(
        first_event["evaluations"][0]["finding"]["credential_type"],
        "known"
    );
    assert_eq!(first_event["evaluations"][0]["effect"], "allow");
    let known_hmac = first_event["evaluations"][0]["finding"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();

    // Retain only this exact credential by HMAC and prompt for a different
    // high-entropy value. This exercises the unknown classifier at the actual
    // parser-to-guard boundary, while proving that the value does not reach
    // the origin when approval is required.
    let exception_policy = json!({
        "permissions": [
            {"action":"network:request", "resource":"*", "effect":"allow"},
            {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow", "condition":{"credential":[format!("hmac:{known_hmac}")]}},
            {"action":"credential:use", "resource":"*", "effect":"prompt"}
        ],
        "credential_rules": [{
            "name":"known",
            "patterns":["key-[a-z]+"],
            "allowed_hosts":["127.0.0.1"],
            "header_names":["authorization"]
        }],
        "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
    });
    std::fs::write(&policy_path, exception_policy.to_string()).unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    let unknown_value = "A9f-7kP2-xQ4m-Z8rT-3vN6";
    let unknown = raw_round_trip(
        &socket,
        &single_credential_h1_request(origin_port, "unknown", unknown_value),
    )
    .await;
    assert!(unknown.starts_with(b"HTTP/1.1 428"), "{unknown:?}");
    assert!(
        !unknown
            .windows(unknown_value.len())
            .any(|window| window == unknown_value.as_bytes())
    );
    assert_eq!(seen.lock().unwrap().len(), 1);

    // A short ordinary value is not a credential detection and therefore
    // remains usable without a policy exception. The origin sees it exactly.
    let ordinary = raw_round_trip(
        &socket,
        &single_credential_h1_request(origin_port, "ordinary", "ordinary"),
    )
    .await;
    assert!(ordinary.starts_with(b"HTTP/1.1 200"), "{ordinary:?}");
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    wait_for_seen(&seen, 2).await;
    assert!(
        seen.lock().unwrap()[1]
            .windows(b"ordinary".len())
            .any(|window| window == b"ordinary")
    );

    proxy.shutdown().await;
    origin_task.abort();

    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(guard_events.len(), 3);
    assert_eq!(guard_events[0]["outcome"], "allowed");
    assert_eq!(guard_events[1]["outcome"], "blocked");
    assert_eq!(
        guard_events[1]["evaluations"][0]["finding"]["rule"],
        "unknown_secret"
    );
    assert_eq!(
        guard_events[1]["evaluations"][0]["finding"]["credential_type"],
        "unknown"
    );
    assert_eq!(
        guard_events[1]["evaluations"][0]["effect"],
        "require_approval"
    );
    assert_eq!(guard_events[2]["outcome"], "no_detection");
    assert!(
        guard_events[2]["evaluations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!events.contains(unknown_value));
}

#[tokio::test]
async fn native_guard_concurrent_identities_retain_approval_scope_and_audit_owner() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-identity-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"*", "effect":"prompt"}
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
    let origin_task = tokio::spawn(origin(listener, seen.clone(), ready));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    let alice_stream = UnixStream::connect(&socket).await.unwrap();
    let (mut alice_sender, alice_connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(alice_stream))
            .await
            .unwrap();
    let alice_connection_task = tokio::spawn(alice_connection);
    let bob_stream = UnixStream::connect(directory.path().join("bob.sock"))
        .await
        .unwrap();
    let (mut bob_sender, bob_connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(bob_stream))
            .await
            .unwrap();
    let bob_connection_task = tokio::spawn(bob_connection);
    let (alice, bob) = tokio::join!(
        send(
            &mut alice_sender,
            format!("http://127.0.0.1:{origin_port}/alice-approval")
                .parse()
                .unwrap(),
            "Bearer key-alice",
        ),
        send(
            &mut bob_sender,
            format!("http://127.0.0.1:{origin_port}/bob-approval")
                .parse()
                .unwrap(),
            "Bearer key-bob",
        )
    );
    assert_eq!(alice.status(), 428);
    assert_eq!(bob.status(), 428);
    let alice_id = response_request_id(&alice);
    let bob_id = response_request_id(&bob);
    assert_ne!(alice_id, bob_id);
    let _ = alice.collect().await.unwrap();
    let _ = bob.collect().await.unwrap();
    assert!(seen.lock().unwrap().is_empty(), "approval reached origin");

    let live_stats = stats(&directory).await;
    assert_eq!(live_stats["credential-guard"]["violations_total"], 2);
    assert_eq!(
        live_stats["policy-engine"]["engine_stats"]["evaluations"],
        4,
        "concurrent Alice/Bob requests must charge one network and one credential evaluation each: {live_stats}"
    );
    assert_eq!(
        live_stats["policy-engine"]["engine_stats"]["budget_stats"],
        json!({"tracked_keys": 0, "keys": []}),
        "prompted credentials must not create budget state: {live_stats}"
    );
    assert_eq!(
        live_stats["network-guard"],
        json!({"enabled": true, "checks": 2, "allowed": 2, "blocked": 0, "warned": 0, "rate_limited": 0}),
        "each concurrent request must have one network admission: {live_stats}"
    );

    drop(alice_sender);
    drop(bob_sender);
    let _ = alice_connection_task.await;
    let _ = bob_connection_task.await;
    proxy.shutdown().await;
    origin_task.abort();

    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    for (request_id, agent) in [(alice_id, "alice"), (bob_id, "bob")] {
        let event = events
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|event| {
                event["event"] == "proxy.credential_guard" && event["request_id"] == request_id
            })
            .unwrap();
        assert_eq!(event["agent"], agent);
        assert!(
            event["connection_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        assert_eq!(event["evaluations"].as_array().unwrap().len(), 1);
        assert_eq!(event["evaluations"][0]["effect"], "require_approval");
        assert_eq!(
            event["evaluations"][0]["required_checks"],
            json!(["rate_limit", "credential_detection", "credential_validation"])
        );
        assert_eq!(event["evaluations"][0]["budget_remaining"], Value::Null);
        assert_eq!(event["audit"][0]["approval"]["approval_type"], "credential");
        assert_eq!(event["audit"][0]["approval"]["target"], "127.0.0.1");
        assert_eq!(event["audit"][0]["agent"], agent);
        assert_eq!(
            event["audit"][0]["approval"]["scope_hint"]["expected_hosts"],
            json!(["127.0.0.1"])
        );

        let canonical = audit
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|event| {
                event["event"] == "security.credential_guard" && event["request_id"] == request_id
            })
            .unwrap();
        assert_eq!(canonical["agent"], agent);
        assert_eq!(canonical["approval"]["required"], true);
        assert_eq!(
            canonical["approval"]["scope_hint"]["expected_hosts"],
            json!(["127.0.0.1"])
        );
    }
}

#[tokio::test]
async fn native_guard_live_budget_counts_credential_and_network_charges() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-budget-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"budget", "budget":1},
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
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);

    let first = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/budget-first")
            .parse()
            .unwrap(),
        "Bearer key-budget",
    )
    .await;
    assert_eq!(first.status(), 200);
    let first_id = response_request_id(&first);
    let _ = first.collect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), ready.notified())
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    let second = send(
        &mut sender,
        format!("http://127.0.0.1:{origin_port}/budget-second")
            .parse()
            .unwrap(),
        "Bearer key-budget",
    )
    .await;
    assert_eq!(second.status(), 429);
    let _ = second.collect().await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    origin_task.abort();

    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(guard_events.len(), 1);
    assert_eq!(guard_events[0]["request_id"], first_id);
    assert_eq!(guard_events[0]["evaluations"][0]["effect"], "allow");
    assert_eq!(guard_events[0]["evaluations"][0]["budget_remaining"], 0);
    let network_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.network_guard")
        .collect::<Vec<_>>();
    assert_eq!(network_events.len(), 2);
    assert_eq!(network_events[1]["outcome"], "blocked");
    assert_eq!(network_events[1]["metadata"]["blocked_by"], "network-guard");
    assert_eq!(
        network_events[1]["metadata"]["block_reason"],
        "Request budget exceeded for 127.0.0.1"
    );
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
    let proxy = Proxy::start(proxy_config.clone()).await.unwrap();
    let matching_request = format!(
        "POST http://127.0.0.1:{origin_port}/scan HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECRET"
    );
    let blocked = raw_round_trip(&socket, matching_request.as_bytes()).await;
    assert!(blocked.starts_with(b"HTTP/1.1 403"), "{blocked:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "blocked request reached origin"
    );

    // Operator mode is process-owned. Change it through retained admin control
    // instead of expecting serialized config fields to overwrite a live mode.
    set_mode(&proxy_config, "pattern-scanner", "block").await;
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
async fn native_pattern_scanner_decodes_gzip_request_and_response_on_real_h1() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [{"action":"network:request", "resource":"*", "effect":"allow"}],
            "scan_patterns": [{"name":"compressed-secret","pattern":"SECRET","scope":["body"],"target":"both","action":"block"}]
        })
        .to_string(),
    )
    .unwrap();
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let origin_seen = seen.clone();
    let response_body = gzip_bytes(b"response-SECRET");
    let origin_response_body = response_body.clone();
    let origin_task = tokio::spawn(async move {
        for response_body in [b"origin-ok".to_vec(), origin_response_body] {
            let (mut stream, _) = origin_listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let size = stream.read(&mut buffer).await.unwrap();
                assert!(size > 0, "origin ended before request headers");
                request.extend_from_slice(&buffer[..size]);
                if let Some(position) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }
            };
            let content_length = std::str::from_utf8(&request[..header_end])
                .unwrap()
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let size = stream.read(&mut buffer).await.unwrap();
                assert!(size > 0, "origin ended before request body");
                request.extend_from_slice(&buffer[..size]);
            }
            origin_seen.lock().unwrap().push(request);
            let encoding = if response_body.starts_with(&[0x1f, 0x8b]) {
                "Content-Encoding: gzip\r\n"
            } else {
                ""
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{encoding}Connection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&response_body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let mut proxy_config = config(&directory, &policy_path, &socket, false);
    proxy_config.inspection = Some(Inspection {
        policy_file: policy_path.clone(),
        block_request: true,
        block_response: true,
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let proxy = Proxy::start(proxy_config).await.unwrap();

    let blocked_body = gzip_bytes(b"request-SECRET");
    let blocked_request = format!(
        "POST http://127.0.0.1:{origin_port}/request-block HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        blocked_body.len()
    );
    let mut blocked_wire = blocked_request.into_bytes();
    blocked_wire.extend_from_slice(&blocked_body);
    let blocked = raw_round_trip(&socket, &blocked_wire).await;
    assert!(blocked.starts_with(b"HTTP/1.1 403"), "{blocked:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "blocked request reached origin"
    );

    let allowed_body = gzip_bytes(b"request-clear");
    let allowed_request = format!(
        "POST http://127.0.0.1:{origin_port}/request-clear HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        allowed_body.len()
    );
    let mut allowed_wire = allowed_request.into_bytes();
    allowed_wire.extend_from_slice(&allowed_body);
    let allowed = raw_round_trip(&socket, &allowed_wire).await;
    assert!(allowed.starts_with(b"HTTP/1.1 200"), "{allowed:?}");

    let response_request = format!(
        "GET http://127.0.0.1:{origin_port}/response-block HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_round_trip(&socket, response_request.as_bytes()).await;
    assert!(response.starts_with(b"HTTP/1.1 502"), "{response:?}");

    tokio::time::timeout(Duration::from_secs(2), origin_task)
        .await
        .unwrap()
        .unwrap();
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0]
            .windows(b"POST /request-clear HTTP/1.1".len())
            .any(|window| { window == b"POST /request-clear HTTP/1.1" })
    );
    let first_body = requests[0]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    assert_eq!(&requests[0][first_body..], allowed_body.as_slice());
    assert!(
        requests[1]
            .windows(b"GET /response-block HTTP/1.1".len())
            .any(|window| { window == b"GET /response-block HTTP/1.1" })
    );
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    let pattern_events = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "security.pattern_scanner")
        .collect::<Vec<_>>();
    assert!(pattern_events.iter().any(|event| {
        event["details"]["direction"] == "request" && event["decision"] == "deny"
    }));
    assert!(pattern_events.iter().any(|event| {
        event["details"]["direction"] == "response" && event["decision"] == "deny"
    }));
    eprintln!(
        "gzip production observer: blocked_status=403 allowed_status=200 response_status=502 origin_requests={} allowed_origin_request_hex={} response_body_hex={}",
        requests.len(),
        hex_encode(&requests[0]),
        hex_encode(&response_body)
    );
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
async fn native_guard_precedes_observation_failure_and_reserved_api_stays_local() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-observation-key").unwrap();
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
            "scan_patterns": [{
                "name":"request-body-observation",
                "pattern":"body-canary",
                "scope":["body"],
                "target":"request",
                "action":"block"
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_seen = Arc::new(Mutex::new(Vec::new()));
    let origin_ready = Arc::new(Notify::new());
    let origin_task = tokio::spawn(origin(
        origin_listener,
        origin_seen.clone(),
        origin_ready,
    ));
    let mut proxy_config = config(&directory, &policy_path, &socket, true);
    proxy_config.inspection = Some(Inspection {
        policy_file: policy_path.clone(),
        block_request: true,
        block_response: false,
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let proxy = Proxy::start(proxy_config).await.unwrap();

    // The invalid gzip is an observation failure after the request header has
    // already crossed the credential guard.  The guard must publish its
    // allowed decision before the scanner returns its local 403, and the
    // failure must not turn into an outbound request.
    let body = b"body-canary";
    let request = format!(
        "POST http://127.0.0.1:{origin_port}/observation-failure HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nAuthorization: Bearer key-observation\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut wire = request.into_bytes();
    wire.extend_from_slice(body);
    let failed = raw_round_trip(&socket, &wire).await;
    assert!(failed.starts_with(b"HTTP/1.1 403"), "{failed:?}");
    assert!(!failed.windows(body.len()).any(|window| window == body));
    let failed_request_id = response_header(&failed, "x-safeyolo-request-id");
    assert!(!failed_request_id.is_empty(), "failed request ID missing");
    assert!(origin_seen.lock().unwrap().is_empty());

    // Reserved Agent API traffic is dispatched locally before ordinary
    // credential logging or egress.  It must remain local even after the
    // preceding request's scanner observation failed.
    let local = raw_exchange(
        &socket,
        b"GET http://_safeyolo.proxy.internal/status HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer key-local-only\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(local.starts_with(b"HTTP/1.1 503"), "{local:?}");
    let local_request_id = response_header(&local, "x-safeyolo-request-id");
    assert!(!local_request_id.is_empty(), "local request ID missing");
    assert_ne!(failed_request_id, local_request_id);
    assert!(origin_seen.lock().unwrap().is_empty());

    proxy.shutdown().await;
    origin_task.abort();

    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let rows = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    let guard_rows = rows
        .iter()
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(guard_rows.len(), 1);
    assert_eq!(guard_rows[0]["request_id"], failed_request_id);
    assert_ne!(guard_rows[0]["request_id"], local_request_id);
    let credential = rows
        .iter()
        .position(|event| event["event"] == "proxy.credential_guard")
        .expect("credential guard event missing before observation failure");
    let pattern = rows
        .iter()
        .position(|event| event["event"] == "security.pattern_scanner")
        .expect("pattern observation failure event missing");
    assert!(
        credential < pattern,
        "observation ran before credential guard"
    );
    let guard = &rows[credential];
    assert_eq!(guard["outcome"], "allowed");
    assert_eq!(guard["agent"], "alice");
    assert_eq!(guard["evaluations"][0]["effect"], "allow");
    let scanner = &rows[pattern];
    assert_eq!(scanner["decision"], "deny");
    assert_eq!(scanner["direction"], "request");
    assert_eq!(scanner["failure"], "content_decode");
    assert!(!events.contains("key-observation"));
    assert!(!events.contains("key-local-only"));
    assert!(!events.contains("proxy.egress"));

    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("key-observation"));
    assert!(!audit.contains("key-local-only"));
    let audit_guard_rows = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "security.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(audit_guard_rows.len(), 1);
    assert_eq!(audit_guard_rows[0]["request_id"], failed_request_id);
    assert_ne!(audit_guard_rows[0]["request_id"], local_request_id);
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
    let proxy_config = config(&directory, &policy_path, &socket, false);
    let mut proxy = Proxy::start(proxy_config.clone()).await.unwrap();
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

    set_mode(&proxy_config, "credential-guard", "block").await;
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
            "scan_patterns":[{
                "name":"h2-observation-failure",
                "pattern":"body-canary",
                "scope":["body"],
                "target":"request",
                "action":"block"
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
                    // Record every origin stream, including one with no
                    // Authorization header. A denied sibling must leave no
                    // stream behind, even if its application body was ready.
                    origin_seen.lock().unwrap().push(
                        request
                            .headers()
                            .get("authorization")
                            .map_or_else(Vec::new, |value| value.as_bytes().to_vec()),
                    );
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
    proxy_config.inspection = Some(Inspection {
        policy_file: policy_path.clone(),
        block_request: true,
        block_response: false,
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let proxy = Proxy::start(proxy_config.clone()).await.unwrap();
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

    // H2 request-body decoding fails after the matching credential has
    // crossed the guard. The failed observation must produce one local 403,
    // preserve the guard event before its scanner event, and leave no origin
    // stream or body canary behind.
    let body = Bytes::from_static(b"body-canary");
    let failed = sender
        .send_request(
            Request::builder()
                .uri(format!("https://{authority}/h2-observation-failure"))
                .header(
                    "authorization",
                    hyper::header::HeaderValue::from_bytes(b"Bearer key-\xff").unwrap(),
                )
                .header("content-encoding", "gzip")
                .header("content-length", body.len())
                .body(Full::new(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed.status(), 403);
    let failed_request_id = response_request_id(&failed);
    let _ = failed.collect().await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 2);

    // An unauthenticated operator view is still local and cannot disclose the
    // request's raw credential or observation body.
    let unauthorized = raw_admin_exchange(
        &directory,
        b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-admin-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        unauthorized.starts_with(b"HTTP/1.1 401"),
        "{unauthorized:?}"
    );
    assert!(
        !unauthorized
            .windows(b"key-\xff".len())
            .any(|window| { window == b"key-\xff" })
    );
    assert!(
        !unauthorized
            .windows(b"body-canary".len())
            .any(|window| window == b"body-canary")
    );
    let unauthorized_events = raw_admin_exchange(
        &directory,
        b"GET /admin/events HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-admin-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        unauthorized_events.starts_with(b"HTTP/1.1 401"),
        "{unauthorized_events:?}"
    );
    assert!(
        !unauthorized_events
            .windows(b"key-\xff".len())
            .any(|window| { window == b"key-\xff" })
    );
    assert!(
        !unauthorized_events
            .windows(b"body-canary".len())
            .any(|window| window == b"body-canary")
    );

    set_mode(&proxy_config, "credential-guard", "block").await;
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

    // The denied stream and an allowed stream share the same owned TLS/H2
    // connection. A stream-local credential decision must not cancel or alter
    // its sibling, and the denied application bytes must never reach origin.
    let mut blocked_sender = sender.clone();
    let mut allowed_sender = sender.clone();
    let (blocked, allowed) = tokio::join!(
        blocked_sender.send_request(
            Request::builder()
                .uri(format!("https://{authority}/blocked-concurrent"))
                .header(
                    "authorization",
                    hyper::header::HeaderValue::from_bytes(b"Bearer key-\xff").unwrap(),
                )
                .body(Full::new(Bytes::from_static(b"forbidden-h2-body")))
                .unwrap(),
        ),
        allowed_sender.send_request(
            Request::builder()
                .uri(format!("https://{authority}/allowed-concurrent"))
                .header("authorization", "Bearer clear-h2")
                .body(Full::new(Bytes::from_static(b"allowed-h2-body")))
                .unwrap(),
        ),
    );
    let blocked = blocked.unwrap();
    let allowed = allowed.unwrap();
    assert_eq!(blocked.status(), 403);
    assert_eq!(allowed.status(), 200);
    let _ = blocked.collect().await.unwrap();
    let _ = allowed.collect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.lock().unwrap().len() < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 3);
    assert_eq!(seen.lock().unwrap()[2], b"Bearer clear-h2");
    drop(blocked_sender);
    drop(allowed_sender);
    drop(sender);
    let _ = connection_task.await;
    proxy.shutdown().await;
    origin_task.abort();

    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let rows = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    let credential = rows
        .iter()
        .position(|event| {
            event["event"] == "proxy.credential_guard" && event["request_id"] == failed_request_id
        })
        .expect("H2 credential guard event missing before observation failure");
    let scanner = rows
        .iter()
        .position(|event| {
            event["event"] == "security.pattern_scanner" && event["request_id"] == failed_request_id
        })
        .expect("H2 observation failure event missing");
    assert!(
        credential < scanner,
        "observation ran before credential guard"
    );
    assert_eq!(rows[credential]["outcome"], "warned");
    assert_eq!(rows[scanner]["decision"], "deny");
    assert_eq!(rows[scanner]["failure"], "content_decode");
    assert!(!events.contains("key-\\xff"));
    assert!(!events.contains("body-canary"));
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("key-\\xff"));
    assert!(!audit.contains("body-canary"));
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
async fn native_guard_allowed_then_forbidden_live_receiver_no_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-egress-key").unwrap();
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

    let allowed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let allowed_port = allowed_listener.local_addr().unwrap().port();
    let allowed_seen = Arc::new(Mutex::new(Vec::new()));
    let allowed_ready = Arc::new(Notify::new());
    let allowed_task = tokio::spawn(full_origin(
        allowed_listener,
        allowed_seen.clone(),
        allowed_ready.clone(),
    ));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    let allowed_body = b"allowed-body\0with-invalid-ff-\xff";
    let mut allowed_request = format!(
        "POST http://127.0.0.1:{allowed_port}/same-credential HTTP/1.1\r\nHost: 127.0.0.1:{allowed_port}\r\nAuthorization: Bearer key-authorized\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        allowed_body.len()
    )
    .into_bytes();
    allowed_request.extend_from_slice(allowed_body);
    let allowed_response = raw_round_trip(&socket, &allowed_request).await;
    assert!(
        allowed_response.starts_with(b"HTTP/1.1 200"),
        "{allowed_response:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), allowed_ready.notified())
        .await
        .unwrap();
    let allowed_wire = allowed_seen.lock().unwrap().first().cloned().unwrap();
    let allowed_split = allowed_wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    assert_eq!(&allowed_wire[allowed_split..], allowed_body);
    let allowed_head = std::str::from_utf8(&allowed_wire[..allowed_split]).unwrap();
    assert!(allowed_head.contains("POST /same-credential HTTP/1.1\r\n"));
    assert!(allowed_head.contains("Authorization: Bearer key-authorized\r\n"));

    // The same detected credential is sent to a host outside the rule's
    // allowed host set.  The receiver is already accepting connections before
    // this request starts, so an attempted dial or any first byte is visible.
    let forbidden_listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let forbidden_port = forbidden_listener.local_addr().unwrap().port();
    let forbidden_seen = Arc::new(Mutex::new(None));
    let forbidden_ready = Arc::new(Notify::new());
    let forbidden_task = tokio::spawn(live_receiver(
        forbidden_listener,
        forbidden_seen.clone(),
        forbidden_ready.clone(),
    ));
    forbidden_ready.notified().await;

    let forbidden_body = b"forbidden-application-canary";
    let mut forbidden_request = format!(
        "POST http://127.0.0.2:{forbidden_port}/forbidden HTTP/1.1\r\nHost: 127.0.0.2:{forbidden_port}\r\nAuthorization: Bearer key-authorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        forbidden_body.len()
    )
    .into_bytes();
    forbidden_request.extend_from_slice(forbidden_body);
    let forbidden_response = raw_round_trip(&socket, &forbidden_request).await;
    assert!(
        forbidden_response.starts_with(b"HTTP/1.1 428"),
        "{forbidden_response:?}"
    );
    assert!(
        !forbidden_response
            .windows(forbidden_body.len())
            .any(|window| { window == forbidden_body })
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        forbidden_seen.lock().unwrap().is_none(),
        "forbidden receiver observed a connection or application bytes"
    );
    let request_id = response_header(&forbidden_response, "x-safeyolo-request-id");
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let event = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| {
            event["event"] == "proxy.credential_guard" && event["request_id"] == request_id
        })
        .unwrap();
    assert_eq!(event["outcome"], "blocked");
    assert_eq!(event["body_scope"], "headers_only");
    assert_eq!(event["query_scope"], "policy_context_only");
    assert!(!events.contains("key-authorized"));

    forbidden_task.abort();
    proxy.shutdown().await;
    allowed_task.abort();
}

#[tokio::test]
async fn native_guard_reused_h1_decisions_keep_counter_and_identity() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"reused-h1-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"allow"}
            ],
            "credential_rules": [{
                "name":"reused",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();

    let allowed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let allowed_port = allowed_listener.local_addr().unwrap().port();
    let allowed_seen = Arc::new(Mutex::new(Vec::new()));
    let allowed_ready = Arc::new(Notify::new());
    let allowed_task = tokio::spawn(origin(
        allowed_listener,
        allowed_seen.clone(),
        allowed_ready.clone(),
    ));
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let stream = UnixStream::connect(&socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let allowed_uri: Uri = format!("http://127.0.0.1:{allowed_port}/reuse-first")
        .parse()
        .unwrap();

    // The first request is admitted on this H1 connection and reaches the
    // controlled origin. A later denial must not poison its reusable state.
    let first = send(&mut sender, allowed_uri.clone(), "Bearer key-reuse").await;
    assert_eq!(first.status(), 200);
    let first_id = response_request_id(&first);
    let _ = first.collect().await.unwrap();
    allowed_ready.notified().await;

    let forbidden_listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let forbidden_port = forbidden_listener.local_addr().unwrap().port();
    let forbidden_seen = Arc::new(Mutex::new(None));
    let forbidden_ready = Arc::new(Notify::new());
    let forbidden_task = tokio::spawn(live_receiver(
        forbidden_listener,
        forbidden_seen.clone(),
        forbidden_ready.clone(),
    ));
    forbidden_ready.notified().await;
    let denied = send(
        &mut sender,
        format!("http://127.0.0.2:{forbidden_port}/reuse-denied")
            .parse()
            .unwrap(),
        "Bearer key-reuse",
    )
    .await;
    assert_eq!(denied.status(), 428);
    let denied_id = response_request_id(&denied);
    let _ = denied.collect().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        forbidden_seen.lock().unwrap().is_none(),
        "reused H1 denial reached the forbidden receiver"
    );

    // The same sender remains usable after the local denial. This third
    // decision also gives the reviewer an exact allow/deny/allow sequence.
    let third = send(&mut sender, allowed_uri, "Bearer key-reuse").await;
    assert_eq!(third.status(), 200);
    let third_id = response_request_id(&third);
    let _ = third.collect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while allowed_seen.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    let live_stats = stats(&directory).await;
    assert_eq!(live_stats["credential-guard"]["violations_total"], 1);
    assert_eq!(
        live_stats["policy-engine"]["engine_stats"]["evaluations"],
        8,
        "reused allow/deny/allow must charge network admission plus guard evaluation for every request: {live_stats}"
    );
    assert_eq!(
        live_stats["policy-engine"]["engine_stats"]["budget_stats"],
        json!({"tracked_keys": 0, "keys": []}),
        "the reusable sequence has no configured budget: {live_stats}"
    );
    assert_eq!(
        live_stats["network-guard"],
        json!({"enabled": true, "checks": 3, "allowed": 3, "blocked": 0, "warned": 0, "rate_limited": 0}),
        "each reused request must have one network admission: {live_stats}"
    );
    drop(sender);
    let _ = connection_task.await;
    forbidden_task.abort();
    proxy.shutdown().await;
    allowed_task.abort();

    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let guard_events = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event"] == "proxy.credential_guard")
        .collect::<Vec<_>>();
    assert_eq!(guard_events.len(), 3);
    let event = |request_id: &str| {
        guard_events
            .iter()
            .find(|event| event["request_id"] == request_id)
            .unwrap()
    };
    let first_event = event(&first_id);
    let denied_event = event(&denied_id);
    let third_event = event(&third_id);
    assert_eq!(first_event["outcome"], "allowed");
    assert_eq!(denied_event["outcome"], "blocked");
    assert_eq!(third_event["outcome"], "allowed");
    for event in [first_event, denied_event, third_event] {
        assert_eq!(event["evaluations"].as_array().unwrap().len(), 1);
        assert_eq!(
            event["evaluations"][0]["required_checks"],
            json!(["rate_limit", "credential_detection", "credential_validation"])
        );
        assert_eq!(event["evaluations"][0]["budget_remaining"], Value::Null);
    }
    assert_eq!(first_event["agent"], "alice");
    assert_eq!(denied_event["agent"], "alice");
    assert_eq!(third_event["agent"], "alice");
    let connection_id = first_event["connection_id"].as_str().unwrap();
    assert!(!connection_id.is_empty());
    assert_eq!(denied_event["connection_id"], connection_id);
    assert_eq!(third_event["connection_id"], connection_id);
    assert!(guard_events.iter().all(|event| {
        event["evaluations"]
            .as_array()
            .is_some_and(|evaluations| !evaluations.is_empty())
    }));
    assert!(!events.contains("key-reuse"));
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("key-reuse"));
}

#[tokio::test]
async fn native_guard_header_match_blocks_streaming_chunked_upload_before_live_receiver() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("hmac_secret"), b"wire-stream-key").unwrap();
    std::fs::write(
        &policy_path,
        json!({
            "permissions": [
                {"action":"network:request", "resource":"*", "effect":"allow"},
                {"action":"credential:use", "resource":"127.0.0.1/*", "effect":"deny"}
            ],
            "credential_rules": [{
                "name":"streaming",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":true,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
    )
    .unwrap();

    let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_port = receiver_listener.local_addr().unwrap().port();
    let receiver_seen = Arc::new(Mutex::new(None));
    let receiver_ready = Arc::new(Notify::new());
    let receiver_task = tokio::spawn(live_receiver(
        receiver_listener,
        receiver_seen.clone(),
        receiver_ready.clone(),
    ));
    receiver_ready.notified().await;
    let proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();

    let initial_body = b"streaming-body-canary";
    let mut peer = UnixStream::connect(&socket).await.unwrap();
    let head = format!(
        "POST http://127.0.0.1:{receiver_port}/stream HTTP/1.1\r\nHost: 127.0.0.1:{receiver_port}\r\nAuthorization: Bearer key-streaming\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    peer.write_all(head.as_bytes()).await.unwrap();
    peer.write_all(format!("{:x}\r\n", initial_body.len()).as_bytes())
        .await
        .unwrap();
    peer.write_all(initial_body).await.unwrap();
    peer.write_all(b"\r\n").await.unwrap();

    // The guard runs after parsed headers and before body preparation.  The
    // request intentionally has no terminating zero chunk: receiving a local
    // 403 at this point proves the streamed upload was not needed to decide.
    let response = response_head(&mut peer).await;
    assert!(response.starts_with(b"HTTP/1.1 403"), "{response:?}");
    assert!(
        !response
            .windows(initial_body.len())
            .any(|window| { window == initial_body })
    );
    let request_id = response_header(&response, "x-safeyolo-request-id");
    drop(peer);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        receiver_seen.lock().unwrap().is_none(),
        "streaming credential denial reached the live receiver"
    );
    let events = std::fs::read_to_string(directory.path().join("events.jsonl")).unwrap();
    let event = events
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|event| {
            event["event"] == "proxy.credential_guard" && event["request_id"] == request_id
        })
        .unwrap();
    assert_eq!(event["outcome"], "blocked");
    assert_eq!(event["body_scope"], "headers_only");
    assert_eq!(event["query_scope"], "policy_context_only");
    assert_eq!(event["evaluations"][0]["finding"]["rule"], "streaming");
    assert!(!events.contains("key-streaming"));
    assert!(!events.contains("streaming-body-canary"));
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("key-streaming"));
    assert!(!audit.contains("streaming-body-canary"));

    receiver_task.abort();
    proxy.shutdown().await;
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
