//! Real loopback operator-consumer witnesses for the retained #627 facade.
//! The bearer and policy values are synthetic; responses are observed over the
//! bound admin TCP listener and the event stream is a real WebSocket upgrade.

use std::{net::Ipv4Addr, path::Path, time::Duration};

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const POLICY: &str = r#"
budget = 10

[[permissions]]
action = "network:request"
resource = "*"
effect = "allow"
"#;

#[tokio::test]
async fn native_operator_consumer_controls_and_event_stream_are_live() {
    let directory = TempDir::new().unwrap();
    let token = "operator-controls-synthetic";
    let config = config(directory.path(), token);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);

    let instance = admin(port, token, "GET", "/admin/instance", b"").await;
    assert_eq!(instance.status, 200);
    let instance_json = instance.json();
    assert_eq!(instance_json["schema_version"], 1);
    assert!(instance_json["safeyolo_instance_id"].is_string());
    assert_eq!(instance_json["capabilities"]["approvals"], true);

    let identity = admin(port, token, "GET", "/admin/runtime-identity", b"").await;
    assert_eq!(identity.status, 200);
    assert_eq!(identity.json()["state"], "active");

    let modes = admin(port, token, "GET", "/modes", b"").await;
    assert_eq!(modes.status, 200);
    assert_eq!(modes.json()["modes"]["network-guard"], "block");
    let changed = admin(
        port,
        token,
        "PUT",
        "/plugins/network-guard/mode",
        br#"{"mode":"warn"}"#,
    )
    .await;
    assert_eq!(changed.status, 200);
    assert_eq!(
        admin(port, token, "GET", "/plugins/network-guard/mode", b"")
            .await
            .json()["mode"],
        "warn"
    );
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(
        admin(port, token, "GET", "/plugins/network-guard/mode", b"")
            .await
            .json()["mode"],
        "warn"
    );

    let baseline = admin(port, token, "GET", "/admin/policy/baseline", b"").await;
    assert_eq!(baseline.status, 200);
    assert!(baseline.json()["baseline"]["permissions"].is_array());

    let validation = admin(
        port,
        token,
        "POST",
        "/admin/policy/validate",
        br#"{"content":"permissions:\n  - action: network:request\n    resource: '*'\n    effect: allow\n"}"#,
    )
    .await;
    assert_eq!(validation.status, 200);
    assert_eq!(validation.json()["valid"], true);

    let replaced = admin(
        port,
        token,
        "PUT",
        "/admin/policy/baseline",
        br#"{"policy":{"budget":10,"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}}"#,
    )
    .await;
    assert_eq!(replaced.status, 200);
    assert!(proxy.reload_policy_if_changed().await.unwrap());

    let allowed = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/allow",
        br#"{"host":"approved.example","rate":5}"#,
    )
    .await;
    assert_eq!(allowed.status, 200);
    assert!(
        std::fs::read_to_string(config.policy_file.as_ref().unwrap())
            .unwrap()
            .contains("approved.example")
    );
    let rate = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/rate",
        br#"{"host":"approved.example","rate":4}"#,
    )
    .await;
    assert_eq!(rate.status, 200);
    let bypass = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/bypass",
        br#"{"host":"approved.example","addon":"network-guard"}"#,
    )
    .await;
    assert_eq!(bypass.status, 200);
    let host_denied = admin(
        port,
        token,
        "POST",
        "/admin/policy/host/deny",
        br#"{"host":"blocked.example","expires":"2030-01-01T00:00:00Z"}"#,
    )
    .await;
    assert_eq!(host_denied.status, 200);
    let credential_approval = admin(
        port,
        token,
        "POST",
        "/admin/policy/baseline/approve",
        br#"{"destination":"approved.example","cred_id":["synthetic:one","synthetic:two"],"tier":"explicit"}"#,
    )
    .await;
    assert_eq!(credential_approval.status, 200);
    let policy_text = std::fs::read_to_string(config.policy_file.as_ref().unwrap()).unwrap();
    assert!(policy_text.contains("network-guard"));
    assert!(policy_text.contains("synthetic:one"));

    let denied = admin(
        port,
        token,
        "POST",
        "/admin/policy/baseline/deny",
        br#"{"destination":"approved.example","cred_id":"synthetic:fingerprint","reason":"fixture"}"#,
    )
    .await;
    assert_eq!(denied.status, 200);
    let approvals = admin(port, token, "GET", "/admin/approvals", b"").await;
    assert_eq!(approvals.status, 200);
    assert!(approvals.json()["approvals"].is_array());

    let agents = admin(port, token, "GET", "/admin/agents", b"").await;
    assert_eq!(agents.status, 200);
    assert_eq!(agents.json()["agents"].as_array().unwrap().len(), 1);

    let mut events = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    events
        .write_all(
            format!(
                "GET /admin/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
                 Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Authorization: Bearer {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let handshake = read_headers(&mut events).await;
    assert!(handshake.starts_with(b"HTTP/1.1 101"));

    let live_event = admin(
        port,
        token,
        "POST",
        "/admin/policy/baseline/deny",
        br#"{"destination":"stream.example","cred_id":"synthetic:stream","reason":"fixture"}"#,
    )
    .await;
    assert_eq!(live_event.status, 200);
    let (header, body) = read_ws_frame(&mut events).await;
    assert_eq!(header[0] & 0x0f, 1);
    let event: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(event["event"], "admin.denial");
    assert_eq!(event["details"]["destination"], "stream.example");

    // Invalid credentials are rejected before any event upgrade.
    let unauthorized = admin(port, "wrong-synthetic-token", "GET", "/admin/events", b"").await;
    assert_eq!(unauthorized.status, 401);
    events.shutdown().await.unwrap();
    proxy.shutdown().await;
}

fn config(directory: &Path, token: &str) -> Config {
    std::fs::write(directory.join("policy.toml"), POLICY).unwrap();
    std::fs::write(directory.join("operator-token"), token).unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":directory.join("policy.toml"),
        "data_dir":directory.join("data"),
        "agent_api_enabled":false,
        "admin_port":0,
        "admin_api_token_file":directory.join("operator-token"),
        "readiness_file":directory.join("ready.json"),
        "flow_store_enabled":false,
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl")
    }))
    .unwrap()
}

fn admin_port(config: &Config) -> u16 {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
    ready["admin_port"].as_u64().unwrap().try_into().unwrap()
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn admin(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let split = bytes
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .unwrap();
    let status = std::str::from_utf8(&bytes[..split])
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    Reply {
        status,
        body: bytes[split + 4..].to_vec(),
    }
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut one = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut one).await.unwrap();
        bytes.push(one[0]);
    }
    bytes
}

async fn read_ws_frame(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    let mut header = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let mut length = usize::from(header[1] & 0x7f);
    if length == 126 {
        let mut extended = [0u8; 2];
        stream.read_exact(&mut extended).await.unwrap();
        length = usize::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0u8; 8];
        stream.read_exact(&mut extended).await.unwrap();
        length = u64::from_be_bytes(extended).try_into().unwrap();
    }
    assert_eq!(header[1] & 0x80, 0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (header.to_vec(), body)
}
