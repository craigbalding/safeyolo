//! Installed native process proof: proxy response header to one retained-flow GET.

use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::{sleep, timeout},
};

const LIMIT: Duration = Duration::from_secs(5);
const TOKEN: &str = "synthetic-installed-flow-token";
const SPOOF: &str = "req-dddddddddddddddddddddddddddddddd";

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn send(socket: &Path, head: String, body: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    reply
}

fn split(reply: &[u8]) -> (&str, &[u8]) {
    let end = reply
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    (std::str::from_utf8(&reply[..end]).unwrap(), &reply[end..])
}

#[tokio::test]
async fn installed_native_response_header_opens_retained_owned_flow() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let data = root.join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("agent_token"), TOKEN).unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let policy = root.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"test_context":{"target_hosts":["127.0.0.1"]}}
        })
        .to_string(),
    )
    .unwrap();
    let db = root.join("flows.sqlite3");
    let ready = root.join("ready.json");
    let socket = root.join("alice.sock");
    let config = root.join("native.json");
    std::fs::write(
        &config,
        json!({
            "listeners":[{"agent_id":"alice","socket_path":socket,"source_id":"192.0.2.20"}],
            "policy_file":policy,"data_dir":data,"readiness_file":ready,
            "audit_log_path":root.join("audit.jsonl"),"event_log":root.join("events.jsonl"),
            "flow_store_enabled":true,"flow_store_db_path":db,
            "test_context_block":true,"circuit_breaker_enabled":false
        })
        .to_string(),
    )
    .unwrap();
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
            .arg("--config")
            .arg(&config)
            .env("SAFEYOLO_DATA_DIR", &data)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    timeout(LIMIT, async {
        while !ready.exists() || !socket.exists() {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "native proxy exited before readiness"
            );
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let mut body = vec![0; 12];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"request text");
        stream.write_all(format!("HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nX-SafeYolo-Request-Id: {SPOOF}\r\nContent-Length: 13\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        stream.write_all(b"response text").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let reply = send(&socket, format!(
        "POST http://{address}/owned HTTP/1.1\r\nHost: {address}\r\nX-SafeYolo-Test-Context: run=installed;agent=alice;test=lookup;role=tester\r\nX-SafeYolo-Request-Id: {SPOOF}\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\n"
    ), b"request text").await;
    peer.await.unwrap();
    let (head, _) = split(&reply);
    assert!(head.starts_with("HTTP/1.1 201"), "{head}");
    let ids: Vec<&str> = head
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-safeyolo-request-id")
                .then_some(value.trim())
        })
        .collect();
    assert_eq!(ids.len(), 1);
    let request_id = ids[0];
    assert!(request_id.starts_with("req-") && request_id != SPOOF);

    // The writer is asynchronous. Wait only for the retained-record boundary;
    // the testing agent then needs exactly one authenticated API GET.
    timeout(LIMIT, async {
        loop {
            let connection = rusqlite::Connection::open(&db).unwrap();
            let retained: Option<i64> = connection
                .query_row(
                    "SELECT id FROM flows WHERE request_id = ?",
                    [request_id],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();
            if retained.is_some() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let api = send(&socket, format!(
        "GET http://_safeyolo.proxy.internal/api/flows/by-request-id/{request_id} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    ), b"").await;
    let (head, content) = split(&api);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let value: Value = serde_json::from_slice(content).unwrap();
    assert_eq!(value["flow"]["request_id"], request_id);
    assert_eq!(value["flow"]["method"], "POST");
    assert_eq!(value["flow"]["status_code"], 201);
    assert_eq!(value["request_body"]["body_text"], "request text");
    assert_eq!(value["response_body"]["body_text"], "response text");
}
