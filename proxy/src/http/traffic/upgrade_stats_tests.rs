//! Owned-wire checks for WebSocket handshake counters, recursive upgrade
//! shutdown, and the authenticated operator's view of shared counters.
use crate::{
    Config, Proxy, Runtime,
    websocket::{Event, Reader, Writer},
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    time::timeout,
};
use tungstenite::protocol::frame::{
    FrameHeader,
    coding::{Control, Data, OpCode},
};

const LIMIT: Duration = Duration::from_secs(5);

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]})
            .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,"readiness_file":directory.join("ready"),
        "audit_log_path":directory.join("audit.jsonl"),"event_log":directory.join("events"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("flows.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":""
    }))
    .unwrap()
}
fn stats(runtime: &Runtime) -> Value {
    runtime
        .request_logger
        .stats()
        .unwrap()
        .document()
        .json()
        .unwrap()
}
fn expected_stats(count: u64) -> Value {
    json!({"requests_total":count,"requests_quieted":0,"responses_total":count,"blocks_total":0})
}
fn expected_metrics(count: u64) -> Value {
    json!({"requests_total":count,"requests_success":count,"requests_blocked":0,
        "blocks_by_source":{},"domains_tracked":u64::from(count != 0)})
}
fn all_records(directory: &Path) -> Vec<Value> {
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn records(directory: &Path) -> Vec<Value> {
    // Memory lifetimes are asserted separately below. Keep every other
    // producer event and its original order in the logger/API controls.
    all_records(directory)
        .into_iter()
        .filter(|row| {
            !(row["addon"] == "memory-monitor"
                && matches!(
                    row["event"].as_str(),
                    Some("ops.startup" | "ops.memory.conn_closed" | "ops.memory.ws_closed")
                ))
        })
        .collect()
}
fn drained_records(runtime: &Runtime, directory: &Path) -> Vec<Value> {
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    records(directory)
}
fn cleanup(directory: &Path) {
    assert!(!directory.join("alice.sock").exists());
    assert!(!directory.join("ready").exists());
}
fn diagnostic_events(directory: &Path) -> Vec<Value> {
    std::fs::read_to_string(directory.join("events"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
async fn origin() -> TcpListener {
    TcpListener::bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap()
}
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        head
    })
    .await
    .unwrap()
}
fn client_frame(opcode: OpCode, payload: &[u8]) -> Vec<u8> {
    let key = [13, 17, 23, 31];
    let header = FrameHeader {
        opcode,
        is_final: true,
        mask: Some(key),
        ..FrameHeader::default()
    };
    let mut bytes = Vec::new();
    header.format(payload.len() as u64, &mut bytes).unwrap();
    bytes.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ key[i % 4]),
    );
    bytes
}
async fn frame<R: AsyncRead + Unpin>(reader: &mut Reader<R>) -> Event {
    timeout(LIMIT, reader.read()).await.unwrap().unwrap()
}

#[tokio::test]
async fn websocket_handshake_logs_once_before_frames_and_relay_close() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let listener = origin().await;
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let head = read_head(&mut stream).await;
        assert!(head.starts_with(b"GET /socket?private=query HTTP/1.1\r\n"));
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
        let (read, write) = tokio::io::split(stream);
        let mut reader = Reader::new(read, true, None);
        let mut writer = Writer::new(write, false, None);
        let Event::Message(message) = frame(&mut reader).await else {
            panic!("owned text message expected")
        };
        message
            .with_text(|text| assert_eq!(text, "owned frame"))
            .unwrap();
        writer.message(message).await.unwrap();
        let Event::Ping(payload) = frame(&mut reader).await else {
            panic!("owned Ping expected")
        };
        assert_eq!(payload, b"ping");
        writer.control(Control::Pong, &payload).await.unwrap();
        let Event::Close(payload) = frame(&mut reader).await else {
            panic!("relay Close expected")
        };
        assert_eq!(payload, 1000u16.to_be_bytes());
    });
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client.write_all(format!("GET http://127.0.0.2:{port}/socket?private=query HTTP/1.1\r\nHost: logical.invalid:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
    let head = read_head(&mut client).await;
    assert!(head.starts_with(b"HTTP/1.1 101"));
    let initial = drained_records(&runtime, directory.path());
    assert_eq!(initial.len(), 2);
    assert_eq!(initial[0]["event"], "traffic.request");
    assert_eq!(initial[0]["summary"], "GET logical.invalid/socket");
    assert_eq!(initial[0]["details"]["size"], 0);
    assert_eq!(initial[1]["event"], "traffic.response");
    assert_eq!(initial[1]["summary"], "101 logical.invalid/socket");
    assert_eq!(initial[1]["details"]["status"], 101);
    assert_eq!(initial[1]["details"]["size"], 0);
    assert_eq!(initial[0]["request_id"], initial[1]["request_id"]);
    assert_eq!(stats(&runtime), expected_stats(1));
    assert_eq!(super::metrics_stats(&runtime), expected_metrics(1));
    let (read, mut write) = tokio::io::split(client);
    let mut reader = Reader::new(read, false, None);
    write
        .write_all(&client_frame(OpCode::Data(Data::Text), b"owned frame"))
        .await
        .unwrap();
    let Event::Message(message) = frame(&mut reader).await else {
        panic!("echo text expected")
    };
    message
        .with_text(|text| assert_eq!(text, "owned frame"))
        .unwrap();
    write
        .write_all(&client_frame(OpCode::Control(Control::Ping), b"ping"))
        .await
        .unwrap();
    let Event::Pong(payload) = frame(&mut reader).await else {
        panic!("echo Pong expected")
    };
    assert_eq!(payload, b"ping");
    assert_eq!(drained_records(&runtime, directory.path()), initial);
    assert_eq!(stats(&runtime), expected_stats(1));
    assert_eq!(super::metrics_stats(&runtime), expected_metrics(1));
    write
        .write_all(&client_frame(
            OpCode::Control(Control::Close),
            &1000u16.to_be_bytes(),
        ))
        .await
        .unwrap();
    let Event::Close(payload) = frame(&mut reader).await else {
        panic!("relay Close expected")
    };
    assert_eq!(payload, 1000u16.to_be_bytes());
    drop(reader);
    drop(write);
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(records(directory.path()), initial);
    assert_eq!(stats(&runtime), expected_stats(1));
    assert_eq!(super::metrics_stats(&runtime), expected_metrics(1));
    let events = diagnostic_events(directory.path());
    let egress: Vec<_> = events
        .iter()
        .filter(|row| row["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0]["host"], "127.0.0.2");
    assert_eq!(egress[0]["port"], port);
    assert_eq!(
        events
            .iter()
            .filter(|row| row["event"] == "proxy.websocket.message")
            .count(),
        2
    );
    let end: Vec<_> = events
        .iter()
        .filter(|row| row["event"] == "proxy.websocket.end")
        .collect();
    assert_eq!(end.len(), 1);
    assert_eq!(end[0]["close_code"], 1000);
    assert_eq!(end[0]["drained"], true);
}

// No Debug implementation: diagnostics should not print an authorized request.
struct Reply {
    status: u16,
    body: Vec<u8>,
}
async fn exchange(mut stream: impl AsyncRead + AsyncWrite + Unpin, request: &[u8]) -> Reply {
    timeout(LIMIT, async {
        stream.write_all(request).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        let head = std::str::from_utf8(&bytes[..split]).unwrap();
        Reply {
            status: head
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap(),
            body: bytes[split + 4..].to_vec(),
        }
    })
    .await
    .unwrap()
}
async fn operator_stats(port: u16, token: Option<&str>) -> Reply {
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request =
        format!("GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\r\n");
    exchange(
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap(),
        request.as_bytes(),
    )
    .await
}
fn assert_stats(reply: Reply, count: u64) {
    assert_eq!(reply.status, 200);
    let value: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(value["proxy"], "safeyolo");
    assert_eq!(value["request-logger"], expected_stats(count));
    assert_eq!(value["metrics"], expected_metrics(count));
    assert_eq!(
        serde_json::to_string(&value["request-logger"]).unwrap(),
        serde_json::to_string(&expected_stats(count)).unwrap()
    );
    assert_eq!(
        value["flow-recorder"],
        json!({"recorded":0,"errors":0,"skipped":count})
    );
}
fn assert_unauthorized(reply: Reply) {
    assert_eq!(reply.status, 401);
    let value: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(
        value,
        json!({"error":"Unauthorized","message":"Missing or invalid Bearer token","hint":"Add header: Authorization: Bearer <token>"})
    );
    assert!(
        !reply
            .body
            .windows(b"request-logger".len())
            .any(|window| window == b"request-logger")
    );
}

#[tokio::test]
async fn authenticated_operator_stats_exposes_shared_counters_without_public_leak() {
    let directory = tempfile::tempdir().unwrap();
    let token = uuid::Uuid::new_v4().simple().to_string();
    let token_path = directory.path().join("operator-token");
    std::fs::write(&token_path, &token).unwrap();
    let mut configuration = config(directory.path());
    configuration.admin_port = Some(0);
    configuration.admin_api_token_file = Some(token_path);
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("ready")).unwrap()).unwrap();
    let admin_port: u16 = ready["admin_port"].as_u64().unwrap().try_into().unwrap();
    assert_ne!(admin_port, 0);
    assert_unauthorized(operator_stats(admin_port, None).await);
    assert_unauthorized(operator_stats(admin_port, Some("wrong-owned-fixture-token")).await);
    assert_stats(operator_stats(admin_port, Some(&token)).await, 0);
    let listener = origin().await;
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let _ = read_head(&mut stream).await;
        let mut body = [0; 3];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"req");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let request = format!(
        "POST http://127.0.0.2:{port}/stats-control HTTP/1.1\r\nHost: logical.invalid\r\nContent-Length: 3\r\nConnection: close\r\n\r\nreq"
    );
    let reply = exchange(
        UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap(),
        request.as_bytes(),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"ok");
    timeout(LIMIT, peer).await.unwrap().unwrap();
    assert_stats(operator_stats(admin_port, Some(&token)).await, 1);
    assert_unauthorized(operator_stats(admin_port, None).await);
    assert_stats(operator_stats(admin_port, Some(&token)).await, 1);
    assert_eq!(stats(&runtime), expected_stats(1));
    proxy.shutdown().await;
    cleanup(directory.path());
    assert!(
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, admin_port))
            .await
            .is_err()
    );
    let rows = records(directory.path());
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0]["event"], "admin.auth_failure");
    assert_eq!(rows[1]["event"], "admin.auth_failure");
    assert_eq!(rows[2]["event"], "traffic.request");
    assert_eq!(rows[3]["event"], "traffic.response");
    assert_eq!(rows[4]["event"], "admin.auth_failure");
    let events = diagnostic_events(directory.path());
    let egress: Vec<_> = events
        .iter()
        .filter(|row| row["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0]["host"], "127.0.0.2");
    assert_eq!(egress[0]["port"], port);
    assert_eq!(
        events
            .iter()
            .filter(|row| row["audit_intent"] == "admin.auth_failure")
            .count(),
        3
    );
    let token_hex = token
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    for name in ["events", "audit.jsonl"] {
        let bytes = std::fs::read_to_string(directory.path().join(name)).unwrap();
        assert!(
            !bytes.contains(&token),
            "synthetic token leaked into evidence"
        );
        assert!(
            !bytes.contains(&token_hex),
            "hex synthetic token leaked into evidence"
        );
    }
}

#[tokio::test]
async fn active_websocket_shutdown_joins_direct_and_connect_owners_across_reload() {
    for nested in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let configuration = config(directory.path());
        let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let listener = origin().await;
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            let head = read_head(&mut stream).await;
            assert!(head.starts_with(b"GET /shutdown HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
            let (read, write) = tokio::io::split(&mut stream);
            let mut reader = Reader::new(read, true, None);
            let mut writer = Writer::new(write, false, None);
            let Event::Message(message) = frame(&mut reader).await else {
                panic!("message expected")
            };
            message
                .with_text(|text| assert_eq!(text, "before shutdown"))
                .unwrap();
            writer.message(message).await.unwrap();
            let Event::Close(payload) = frame(&mut reader).await else {
                panic!("shutdown Close expected")
            };
            assert_eq!(payload, 1001u16.to_be_bytes());
            drop(reader);
            drop(writer);
            let mut rest = Vec::new();
            timeout(LIMIT, stream.read_to_end(&mut rest))
                .await
                .unwrap()
                .unwrap();
            assert!(rest.is_empty(), "no frame after shutdown close");
        });
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        if nested {
            client
                .write_all(
                    format!("CONNECT 127.0.0.2:{port} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let head = read_head(&mut client).await;
            assert!(head.starts_with(b"HTTP/1.1 200"));
        }
        let target = if nested {
            "/shutdown".to_owned()
        } else {
            format!("http://127.0.0.2:{port}/shutdown")
        };
        client.write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 101"));
        client
            .write_all(&client_frame(OpCode::Data(Data::Text), b"before shutdown"))
            .await
            .unwrap();
        let Event::Message(message) = frame(&mut Reader::new(&mut client, false, None)).await
        else {
            panic!("echo expected")
        };
        message
            .with_text(|text| assert_eq!(text, "before shutdown"))
            .unwrap();
        let snapshot = || {
            runtime
                .memory_monitor
                .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
                .unwrap()
                .json()
                .unwrap()
        };
        let before = snapshot();
        assert_eq!(before["active_connections"], 1, "nested={nested}");
        assert_eq!(before["active_websockets"], 1);
        assert_eq!(
            before["total_flows"], 1,
            "only the WS HTTP handshake is a flow"
        );
        assert_eq!(before["websockets"][0]["messages"], 2);
        proxy.reload(configuration).await.unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &runtime.memory_monitor,
            &proxy.runtime.read().unwrap().memory_monitor
        ));
        let shutdown = tokio::spawn(proxy.shutdown());
        let Event::Close(payload) = frame(&mut Reader::new(&mut client, false, None)).await else {
            panic!("client shutdown Close expected")
        };
        assert_eq!(payload, 1001u16.to_be_bytes());
        let mut rest = Vec::new();
        timeout(LIMIT, client.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.is_empty());
        timeout(LIMIT, peer).await.unwrap().unwrap();
        timeout(LIMIT, shutdown).await.unwrap().unwrap();
        let after = snapshot();
        assert_eq!(after["active_connections"], 0);
        assert_eq!(after["active_websockets"], 0);
        assert_eq!(after["total_flows"], before["total_flows"]);
        cleanup(directory.path());
        let rows = all_records(directory.path());
        let memory: Vec<_> = rows
            .iter()
            .filter(|row| row["addon"] == "memory-monitor")
            .collect();
        assert_eq!(
            memory
                .iter()
                .map(|row| row["event"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "ops.startup",
                "ops.memory.ws_closed",
                "ops.memory.conn_closed"
            ]
        );
        assert_eq!(memory[1]["details"]["message_count"], 2);
        assert_eq!(memory[2]["details"]["flow_count"], 1);
        assert_eq!(memory[1]["host"], "127.0.0.2");
        assert_eq!(memory[2]["host"], "127.0.0.2");
        assert_eq!(runtime.audit.pending_count().unwrap(), 0);
        assert_eq!(
            runtime
                .audit
                .emit(crate::audit::Event::new(
                    "ops.owned_after_shutdown",
                    crate::audit::Kind::Ops,
                    crate::audit::Severity::Low,
                    "Owned stopped-writer control"
                ))
                .unwrap(),
            crate::audit::Submission::Stopped
        );
        let events = diagnostic_events(directory.path());
        let messages: Vec<_> = events
            .iter()
            .filter(|row| row["event"] == "proxy.websocket.message")
            .collect();
        assert_eq!(messages.len(), 2);
        let ended: Vec<_> = events
            .iter()
            .filter(|row| row["event"] == "proxy.websocket.end")
            .collect();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0]["outcome"], "shutdown");
        assert_eq!(ended[0]["drained"], true);
        assert_eq!(ended[0]["agent"], "alice");
        for message in messages {
            assert_eq!(message["connection_id"], ended[0]["connection_id"]);
        }
        assert_eq!(
            events
                .iter()
                .filter(|row| row["event"] == "proxy.egress")
                .count(),
            1,
            "CONNECT must reuse its admitted socket"
        );
    }
}

#[tokio::test]
async fn shutdown_drains_active_connect_response_before_client_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let listener = origin().await;
    let port = listener.local_addr().unwrap().port();
    let (release, released) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        assert!(
            read_head(&mut stream)
                .await
                .starts_with(b"GET /drain HTTP/1.1\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfirs")
            .await
            .unwrap();
        timeout(LIMIT, released).await.unwrap().unwrap();
        stream.write_all(b"t---").await.unwrap();
    });
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client
        .write_all(
            format!("CONNECT 127.0.0.2:{port} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    client
        .write_all(
            format!("GET /drain HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let mut first = [0; 4];
    timeout(LIMIT, client.read_exact(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&first, b"firs");
    let mut shutdown = tokio::spawn(proxy.shutdown());
    // Readiness is cleared first by shutdown. Observe that effect before
    // checking that the held response still prevents completed cleanup.
    timeout(LIMIT, async {
        while directory.path().join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_millis(20), &mut shutdown)
            .await
            .is_err(),
        "shutdown returned before the held response completed"
    );
    release.send(()).unwrap();
    let mut rest = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rest, b"t---");
    timeout(LIMIT, peer).await.unwrap().unwrap();
    timeout(LIMIT, shutdown).await.unwrap().unwrap();
    cleanup(directory.path());
    let report = runtime
        .memory_monitor
        .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(report["active_connections"], 0);
    assert_eq!(report["active_websockets"], 0);
    let memory: Vec<_> = all_records(directory.path())
        .into_iter()
        .filter(|row| row["addon"] == "memory-monitor")
        .collect();
    assert_eq!(
        memory
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["ops.startup", "ops.memory.conn_closed"]
    );
    assert_eq!(memory[1]["details"]["flow_count"], 1);
    assert_eq!(memory[1]["details"]["bytes_received"], 8);
}

#[tokio::test]
async fn immediate_shutdown_joins_listener_before_its_first_poll() {
    let directory = tempfile::tempdir().unwrap();
    // On this current-thread runtime, start spawns the listener without
    // yielding again. Shutdown must retain that first stop notification.
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    timeout(LIMIT, proxy.shutdown()).await.unwrap();
    cleanup(directory.path());
    let report = runtime
        .memory_monitor
        .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(report["active_connections"], 0);
    assert_eq!(report["active_websockets"], 0);
    assert_eq!(report["total_flows"], 0);
    assert_eq!(runtime.audit.pending_count().unwrap(), 0);
    let rows = all_records(directory.path());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event"], "ops.startup");
    assert_eq!(rows[0]["addon"], "memory-monitor");
}

#[tokio::test]
async fn dropping_listener_stops_its_unpolled_task() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = std::sync::Arc::new(
        Runtime::new(
            config(directory.path()),
            "owned-listener-drop",
            std::sync::Arc::default(),
            None,
            None,
        )
        .unwrap(),
    );
    let (socket, path) = crate::SocketPath::bind(&directory.path().join("alice.sock")).unwrap();
    let listener = crate::RunningListener::start(
        socket,
        path,
        "alice".into(),
        None,
        std::sync::Arc::new(std::sync::RwLock::new(runtime.clone())),
    );
    let task = listener.task.abort_handle();
    // Directly dropping the listener closes its stop channel. The task must
    // observe sender loss even when it has not yet been polled.
    drop(listener);
    assert!(!directory.path().join("alice.sock").exists());
    let stopped = timeout(LIMIT, async {
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if stopped.is_err() {
        task.abort();
    }
    assert!(stopped.is_ok(), "dropped listener task retained itself");
    assert_eq!(runtime.audit.pending_count().unwrap(), 0);
    assert!(runtime.audit.shutdown(LIMIT).unwrap());
}
