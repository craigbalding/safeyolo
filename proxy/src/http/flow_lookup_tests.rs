use crate::{Config, Proxy, flow_store::FlowRecord};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{sleep, timeout},
};

const LIMIT: Duration = Duration::from_secs(5);
const AGENT_TOKEN: &str = "synthetic-flow-agent-token";
const READ_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROTATED_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ADMIN_TOKEN: &str = "synthetic-host-admin-token";
const UNKNOWN: &str = "req-00000000000000000000000000000000";
const SPOOF: &str = "req-cccccccccccccccccccccccccccccccc";
const OWNERLESS: &str = "req-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn config(directory: &Path, target_host: &str) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, json!({
        "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
        "addons":{
            "test_context":{"target_hosts":[target_host]},
            "flow_store":{"max_request_body_bytes":5,"max_response_body_bytes":6,"compress_bodies":false}
        }
    }).to_string()).unwrap();
    serde_json::from_value(json!({
        "listeners":[
            {"agent_id":"alice","socket_path":directory.join("alice.sock"),"source_id":"192.0.2.20"},
            {"agent_id":"bob","socket_path":directory.join("bob.sock"),"source_id":"192.0.2.21"}
        ],
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),
        "audit_log_path":directory.join("audit.jsonl"),"event_log":directory.join("events.jsonl"),
        "admin_api_token_file":directory.join("data/admin_token"),
        "flow_store_enabled":true,"flow_store_db_path":directory.join("flows.sqlite3"),
        "test_context_block":true,"circuit_breaker_enabled":false
    })).unwrap()
}

async fn exchange(socket: &Path, head: String, body: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn response_body(response: &[u8]) -> &[u8] {
    &response[response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4..]
}

fn response_id(response: &[u8]) -> String {
    let head =
        std::str::from_utf8(&response[..response.len() - response_body(response).len()]).unwrap();
    let values: Vec<&str> = head
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-safeyolo-request-id")
                .then_some(value.trim())
        })
        .collect();
    assert_eq!(values.len(), 1, "{head}");
    values[0].to_owned()
}

async fn api(
    directory: &Path,
    agent: &str,
    method: &str,
    path: &str,
    token: &str,
    content: &[u8],
) -> (u16, Value) {
    let head = format!(
        "{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {token}\r\nX-SafeYolo-Agent: forged-owner\r\nX-SafeYolo-Request-Id: {SPOOF}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    );
    let response = exchange(&directory.join(format!("{agent}.sock")), head, content).await;
    let status = std::str::from_utf8(&response[..12]).unwrap()[9..12]
        .parse()
        .unwrap();
    (
        status,
        serde_json::from_slice(response_body(&response)).unwrap(),
    )
}

async fn traffic(
    directory: &Path,
    agent: &str,
    origin: std::net::SocketAddr,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let head = format!(
        "POST http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nX-SafeYolo-Test-Context: run=owned-run;agent=declared-tool;test=lookup;role=tester\r\nX-SafeYolo-Request-Id: {SPOOF}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    exchange(&directory.join(format!("{agent}.sock")), head, body).await
}

async fn read_origin_request(stream: &mut tokio::net::TcpStream) {
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
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
}

#[tokio::test]
async fn response_header_lookup_scopes_bodies_search_and_read_all_token() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("agent_token"), AGENT_TOKEN).unwrap();
    std::fs::write(data.join("admin_token"), ADMIN_TOKEN).unwrap();
    let read_token = data.join("flow_read_token");
    std::fs::write(&read_token, READ_TOKEN).unwrap();
    std::fs::set_permissions(&read_token, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let proxy = Proxy::start(config(directory.path(), &address.ip().to_string()))
        .await
        .unwrap();
    let origin = tokio::spawn(async move {
        for (content_type, payload) in [
            ("text/plain", b"response text".as_slice()),
            ("application/octet-stream", b"\xff\x00BINARY".as_slice()),
        ] {
            let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            read_origin_request(&mut stream).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nX-SafeYolo-Request-Id: {SPOOF}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(payload).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    let alice_response =
        traffic(directory.path(), "alice", address, "/text", b"request text").await;
    assert!(alice_response.starts_with(b"HTTP/1.1 200"));
    let alice_id = response_id(&alice_response);
    assert!(alice_id.starts_with("req-"));
    assert_ne!(alice_id, SPOOF);
    let bob_response = traffic(
        directory.path(),
        "bob",
        address,
        "/binary",
        b"binary request",
    )
    .await;
    assert!(bob_response.starts_with(b"HTTP/1.1 200"));
    let bob_id = response_id(&bob_response);
    origin.await.unwrap();

    let blocked = exchange(
        &directory.path().join("alice.sock"),
        format!("POST http://{address}/missing-context HTTP/1.1\r\nHost: {address}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        b"",
    ).await;
    assert!(blocked.starts_with(b"HTTP/1.1 428"));
    let blocked_id = response_id(&blocked);
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &format!("/api/flows/by-request-id/{blocked_id}"),
            AGENT_TOKEN,
            b""
        )
        .await,
        (404, json!({"error":"Flow not found"}))
    );

    // Local health responses have proxy-issued IDs but no retained flow.
    let health = exchange(
        &directory.path().join("alice.sock"),
        format!("GET http://_safeyolo.proxy.internal/health HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {AGENT_TOKEN}\r\nConnection: close\r\n\r\n"),
        b"",
    ).await;
    assert!(health.starts_with(b"HTTP/1.1 200"));
    let unretained_id = response_id(&health);
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &format!("/api/flows/by-request-id/{unretained_id}"),
            AGENT_TOKEN,
            b""
        )
        .await,
        (404, json!({"error":"Flow not found"}))
    );

    let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
    assert_eq!(recorder.stats()["recorded"], 2);
    let store = recorder.store().unwrap().clone();
    // The response completes before the asynchronous flow writer commits.
    // Establish the retained-flow precondition before the one-call lookup.
    for id in [&alice_id, &bob_id] {
        timeout(LIMIT, async {
            while store.get_flow_by_request_id(id).unwrap().is_none() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    store
        .record(
            FlowRecord {
                metadata: json!({
                    "request_id":OWNERLESS,"ts_start":10,"engagement_id":"operator-owned",
                    "host":"ownerless.invalid","full_url":"http://ownerless.invalid/",
                    "flow_state":"complete","method":"GET","status_code":204
                })
                .as_object()
                .unwrap(),
                request_body: None,
                response_body: None,
            },
            1000,
        )
        .unwrap();

    let path = format!("/api/flows/by-request-id/{alice_id}");
    let (status, alice) = api(directory.path(), "alice", "GET", &path, AGENT_TOKEN, b"").await;
    assert_eq!(status, 200);
    assert_eq!(alice["flow"]["request_id"], alice_id);
    assert_eq!(alice["flow"]["method"], "POST");
    assert_eq!(alice["flow"]["status_code"], 200);
    assert!(
        alice["flow"]["full_url"]
            .as_str()
            .unwrap()
            .ends_with("/text")
    );
    assert_eq!(alice["request_body"]["body_text"], "reque");
    assert_eq!(alice["request_body"]["body_base64"], "cmVxdWU=");
    assert_eq!(alice["request_body"]["body_length"], 5);
    assert_eq!(alice["request_body"]["request_body_size"], 12);
    assert_eq!(alice["request_body"]["request_body_truncated"], 1);
    assert_eq!(alice["request_body"]["capture_state"], "captured");
    assert_eq!(alice["response_body"]["body_text"], "respon");
    assert_eq!(alice["response_body"]["response_body_size"], 13);
    assert_eq!(alice["response_body"]["response_body_truncated"], 1);

    let unknown_path = format!("/api/flows/by-request-id/{UNKNOWN}");
    let (unknown_status, unknown) = api(
        directory.path(),
        "alice",
        "GET",
        &unknown_path,
        AGENT_TOKEN,
        b"",
    )
    .await;
    let (foreign_status, foreign) =
        api(directory.path(), "bob", "GET", &path, AGENT_TOKEN, b"").await;
    assert_eq!((unknown_status, &unknown), (foreign_status, &foreign));
    assert_eq!(unknown, json!({"error":"Flow not found"}));
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &format!("/api/flows/by-request-id/{SPOOF}"),
            AGENT_TOKEN,
            b""
        )
        .await
        .0,
        404
    );

    for (method, content, suffix) in [
        ("GET", b"".as_slice(), format!("?request_id={alice_id}")),
        (
            "POST",
            format!("{{\"request_id\":\"{alice_id}\"}}").as_bytes(),
            String::new(),
        ),
    ] {
        let (status, found) = api(
            directory.path(),
            "alice",
            method,
            &format!("/api/flows/search{suffix}"),
            AGENT_TOKEN,
            content,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(found["count"], 1);
        assert_eq!(found["flows"][0]["id"], alice["flow"]["id"]);
    }
    assert_eq!(
        api(
            directory.path(),
            "bob",
            "GET",
            &format!("/api/flows/search?request_id={alice_id}"),
            AGENT_TOKEN,
            b""
        )
        .await
        .1["count"],
        0
    );
    assert_eq!(
        api(
            directory.path(),
            "bob",
            "POST",
            "/api/flows/search",
            AGENT_TOKEN,
            format!("{{\"request_id\":\"{alice_id}\"}}").as_bytes(),
        )
        .await
        .1["count"],
        0
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            "/api/flows/search?q=%2Ftext",
            AGENT_TOKEN,
            b""
        )
        .await
        .1["count"],
        1
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &format!("/api/flows/search?request_id={alice_id}x"),
            AGENT_TOKEN,
            b""
        )
        .await
        .1["count"],
        0
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "POST",
            "/api/flows/search",
            AGENT_TOKEN,
            b"{\"request_id\":7}"
        )
        .await
        .0,
        400
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            "/api/flows/search?request_id=",
            AGENT_TOKEN,
            b""
        )
        .await
        .0,
        400
    );

    let bob_path = format!("/api/flows/by-request-id/{bob_id}");
    let (status, bob) = api(directory.path(), "alice", "GET", &bob_path, READ_TOKEN, b"").await;
    assert_eq!(status, 200);
    assert_eq!(bob["flow"]["evidence_owner"], "bob");
    assert_eq!(bob["response_body"]["capture_state"], "captured");
    assert_eq!(bob["response_body"]["body_length"], 6);
    assert_eq!(bob["response_body"]["response_body_size"], 8);
    assert_eq!(bob["response_body"]["response_body_truncated"], 1);
    assert!(bob["response_body"].get("body_text").is_none());
    let ownerless_path = format!("/api/flows/by-request-id/{OWNERLESS}");
    let (status, ownerless) = api(
        directory.path(),
        "alice",
        "GET",
        &ownerless_path,
        READ_TOKEN,
        b"",
    )
    .await;
    assert_eq!(status, 200);
    assert!(ownerless["flow"]["evidence_owner"].is_null());
    assert_eq!(ownerless["request_body"]["capture_state"], "absent");
    assert_eq!(ownerless["response_body"]["capture_state"], "absent");
    assert_eq!(ownerless["request_body"]["body_base64"], "");
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &ownerless_path,
            AGENT_TOKEN,
            b""
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &bob_path,
            AGENT_TOKEN,
            b""
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &format!("{bob_path}?agent=bob&evidence_owner=bob"),
            AGENT_TOKEN,
            b""
        )
        .await,
        (404, json!({"error":"Flow not found"}))
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &bob_path,
            ADMIN_TOKEN,
            b""
        )
        .await
        .0,
        401
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &unknown_path,
            READ_TOKEN,
            b""
        )
        .await,
        (404, unknown)
    );

    for (method, route, content) in [
        ("GET", "/health".to_owned(), b"".as_slice()),
        ("GET", "/api/flows/search".to_owned(), b""),
        ("POST", bob_path.clone(), b""),
        ("POST", "/api/flows/search".to_owned(), b"{}"),
        ("GET", format!("/api/flows/{}", alice["flow"]["id"]), b""),
        (
            "GET",
            format!("/api/flows/{}/response-body", alice["flow"]["id"]),
            b"",
        ),
        (
            "POST",
            format!("/api/flows/{}/tag", alice["flow"]["id"]),
            b"{\"tag\":\"secret\"}",
        ),
    ] {
        assert_eq!(
            api(
                directory.path(),
                "alice",
                method,
                &route,
                READ_TOKEN,
                content
            )
            .await
            .0,
            401,
            "{route}"
        );
    }
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &format!("/api/flows/{}", alice["flow"]["id"]),
            AGENT_TOKEN,
            b""
        )
        .await
        .0,
        200
    );

    // The privileged event is confirmed before the response and carries only
    // the trusted caller and IDs. Rotation takes effect without proxy restart.
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    let lookups: Vec<Value> = audit
        .lines()
        .filter_map(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            (row["event"] == "security.flow_read_all_lookup").then_some(row)
        })
        .collect();
    assert_eq!(lookups.len(), 3);
    assert_eq!(lookups[0]["agent"], "alice");
    assert_eq!(lookups[0]["details"]["lookup_request_id"], bob_id);
    assert_eq!(lookups[0]["details"]["client_ip"], "192.0.2.20");
    assert_eq!(lookups[0]["decision"], "log");
    assert!(
        lookups
            .iter()
            .all(|row| row["request_id"].as_str().unwrap().starts_with("req-"))
    );
    assert!(
        !audit.contains(READ_TOKEN),
        "read-all token reached audit log"
    );
    let privileged = serde_json::to_string(&lookups).unwrap();
    assert!(!privileged.contains("response text") && !privileged.contains("request text"));

    let replacement = data.join("flow_read_token.new");
    std::fs::write(&replacement, ROTATED_TOKEN).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(replacement, &read_token).unwrap();
    assert_eq!(
        api(directory.path(), "alice", "GET", &bob_path, READ_TOKEN, b"")
            .await
            .0,
        401
    );
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &bob_path,
            ROTATED_TOKEN,
            b""
        )
        .await
        .0,
        200
    );
    std::fs::set_permissions(&read_token, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &bob_path,
            ROTATED_TOKEN,
            b""
        )
        .await
        .0,
        401
    );
    std::fs::remove_file(&read_token).unwrap();
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &bob_path,
            ROTATED_TOKEN,
            b""
        )
        .await
        .0,
        401
    );
    let target = data.join("private-flow-token");
    std::fs::write(&target, ROTATED_TOKEN).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, &read_token).unwrap();
    assert_eq!(
        api(
            directory.path(),
            "alice",
            "GET",
            &bob_path,
            ROTATED_TOKEN,
            b""
        )
        .await
        .0,
        401
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn read_all_lookup_does_not_release_a_body_when_audit_append_fails() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("agent_token"), AGENT_TOKEN).unwrap();
    let token_path = data.join("flow_read_token");
    std::fs::write(&token_path, READ_TOKEN).unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let sink = directory.path().join("audit-sink");
    std::fs::create_dir(&sink).unwrap();
    let mut configuration = config(directory.path(), "127.0.0.1");
    configuration.audit_log_path = Some(sink);
    let proxy = Proxy::start(configuration).await.unwrap();
    let store = proxy
        .runtime
        .read()
        .unwrap()
        .flow_recorder
        .store()
        .unwrap()
        .clone();
    let metadata = json!({
        "request_id":OWNERLESS,"ts_start":10,"engagement_id":"operator-owned",
        "host":"ownerless.invalid","flow_state":"complete","method":"GET",
        "response_content_type":"text/plain"
    });
    store
        .record(
            FlowRecord {
                metadata: metadata.as_object().unwrap(),
                request_body: None,
                response_body: Some(crate::flow_store::BodyInput::complete(b"private response")),
            },
            1000,
        )
        .unwrap();
    let (status, result) = api(
        directory.path(),
        "alice",
        "GET",
        &format!("/api/flows/by-request-id/{OWNERLESS}"),
        READ_TOKEN,
        b"",
    )
    .await;
    assert_eq!(status, 500);
    assert!(result.get("flow").is_none());
    assert!(!result.to_string().contains("private response"));
    proxy.shutdown().await;
}
