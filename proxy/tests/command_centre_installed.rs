//! Installed host Command Centre boundary: durable identity, real host inventory,
//! authenticated lifecycle routes, and the configured live event socket.

use std::{
    io::Write,
    net::{Ipv4Addr, TcpListener as StdTcpListener},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};

const TOKEN: &str = "command-centre-synthetic-token";
const AGENT_ID: &str = "ag-11111111111111111111111111111111";
const HOST_ID: &str = "sy-22222222222222222222222222222222";

#[tokio::test]
async fn installed_command_centre_keeps_host_identity_and_serves_client_shapes() {
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let python = std::env::var_os("SAFEYOLO_PYTHON")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.venv/bin/python"));
    assert!(python.is_file(), "installed CLI test Python is required");
    std::fs::write(root.join("instance_id"), format!("{HOST_ID}\n")).unwrap();
    std::fs::write(root.join("token"), TOKEN).unwrap();
    std::fs::write(
        root.join("policy.toml"),
        format!("[agents.probe]\nagent_id = \"{AGENT_ID}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("native-policy.toml"),
        "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"allow\"\n",
    )
    .unwrap();
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let runsc = bin.join("runsc");
    std::fs::write(&runsc, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&runsc, std::fs::Permissions::from_mode(0o755)).unwrap();
    let tailscale = bin.join("tailscale");
    std::fs::write(
        &tailscale,
        r#"#!/usr/bin/env python3
import json, os, pathlib, signal, sys, time
root = pathlib.Path(os.environ['FAKE_TAILSCALE_STATE_DIR'])
root.mkdir(exist_ok=True)
args = sys.argv[1:]
if args == ['status', '--json']:
    print(json.dumps({'BackendState': 'Running', 'Self': {'DNSName': 'host.test.ts.net.'}}))
elif args == ['serve', 'status', '--json']:
    targets = {path.name: path.read_text() for path in root.glob('*.target')}
    print(json.dumps({'TCP': {port[:-7]: {'HTTPS': True} for port in targets},
                      'Web': {port: {'Handlers': {'/': {'Proxy': target}}}
                              for port, target in targets.items()}}))
elif len(args) == 4 and args[:2] == ['serve', '--yes'] and args[2].startswith('--https='):
    port = args[2].split('=', 1)[1]
    marker = root / (port + '.target')
    marker.write_text(args[3])
    def close(_signal, _frame):
        marker.unlink(missing_ok=True)
        sys.exit(0)
    signal.signal(signal.SIGTERM, close)
    while True:
        time.sleep(0.1)
else:
    sys.exit(2)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&tailscale, std::fs::Permissions::from_mode(0o755)).unwrap();
    let reserved = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let events_port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let root_str = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cli/src");
    unsafe {
        std::env::set_var("SAFEYOLO_OPERATOR_HOST_PYTHON", &python);
        std::env::set_var("SAFEYOLO_OPERATOR_HOST_USER", "operator");
        std::env::set_var(
            "SAFEYOLO_OPERATOR_INSTANCE_ID_FILE",
            root.join("instance_id"),
        );
        std::env::set_var(
            "SAFEYOLO_COMMAND_CENTRE_EVENTS_PORT",
            events_port.to_string(),
        );
        std::env::set_var("SAFEYOLO_CONFIG_DIR", root);
        std::env::set_var("SAFEYOLO_LOGS_DIR", root.join("logs"));
        std::env::set_var("PYTHONPATH", root_str);
        std::env::set_var(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        );
        std::env::set_var("FAKE_TAILSCALE_STATE_DIR", root.join("tailnet"));
    }
    let config: Config = serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":root.join("alice.sock")}],
        "policy_file":root.join("native-policy.toml"),
        "data_dir":root.join("data"),
        "agent_api_enabled":false,
        "admin_port":0,
        "admin_api_token_file":root.join("token"),
        "readiness_file":root.join("ready.json"),
        "flow_store_enabled":false,
        "audit_log_path":root.join("audit.jsonl"),
        "event_log":root.join("native-events.jsonl")
    }))
    .unwrap();

    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    assert_agent_cannot_reach_events(&config, events_port).await;
    proxy.reload(config.clone()).await.unwrap();
    assert_agent_cannot_reach_events(&config, events_port).await;
    let port = admin_port(&config);
    let identity = admin(port, TOKEN, "GET", "/admin/instance", b"").await;
    assert_eq!(identity.0, 200);
    let identity = identity.1;
    assert_eq!(identity["safeyolo_instance_id"], HOST_ID);
    assert_eq!(identity["host_user"], "operator");
    assert_eq!(identity["host_python"], python.to_str().unwrap());
    assert_eq!(
        identity["command_centre_events"],
        json!({"enabled":true,"port":events_port})
    );
    assert_eq!(identity["capabilities"]["agent_lifecycle"], true);
    let runtime = admin(port, TOKEN, "GET", "/admin/runtime-identity", b"")
        .await
        .1;
    assert_ne!(runtime["instance_id"], HOST_ID);

    let inventory = admin(port, TOKEN, "GET", "/admin/agents", b"").await;
    assert_eq!(inventory.0, 200);
    let agent = &inventory.1["agents"][0];
    assert_eq!(agent["agent_id"], AGENT_ID);
    assert_eq!(agent["name"], "probe");
    for field in ["sandbox_state", "agent_state"] {
        assert!(agent[field].is_string(), "missing {field}");
    }
    assert!(agent["attachable"].is_boolean());
    assert_eq!(
        admin(port, "wrong", "GET", "/admin/instance", b"").await.0,
        401
    );
    assert_eq!(
        admin(port, "wrong", "GET", "/admin/agents", b"").await.0,
        401
    );
    assert_eq!(
        admin(
            port,
            "wrong",
            "POST",
            &format!("/admin/agents/{AGENT_ID}/stop"),
            b""
        )
        .await
        .0,
        401
    );
    assert_eq!(
        admin(port, TOKEN, "POST", "/admin/agents/ag-missing/stop", b"")
            .await
            .0,
        404
    );
    assert_eq!(
        admin(
            port,
            TOKEN,
            "POST",
            &format!("/admin/agents/{AGENT_ID}/launch"),
            b""
        )
        .await
        .0,
        404
    );
    assert_eq!(
        admin(
            port,
            TOKEN,
            "POST",
            &format!("/admin/agents/{AGENT_ID}/stop"),
            br#"{"command":"arbitrary"}"#
        )
        .await
        .0,
        400
    );
    assert_eq!(
        admin(port, TOKEN, "POST", "/admin/agents/%2e%2e/stop", b"")
            .await
            .0,
        400
    );
    let stopped = admin(
        port,
        TOKEN,
        "POST",
        &format!("/admin/agents/{AGENT_ID}/stop"),
        b"",
    )
    .await;
    assert_eq!(stopped.0, 200, "{:?}", stopped.1);
    assert_eq!(stopped.1["agent_id"], AGENT_ID);
    assert_eq!(stopped.1["sandbox_state"], "stopped");

    let mut events = TcpStream::connect((Ipv4Addr::LOCALHOST, events_port))
        .await
        .unwrap();
    events.write_all(format!("GET /admin/events HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {TOKEN}\r\n\r\n").as_bytes()).await.unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(events.read_u8().await.unwrap());
    }
    assert!(headers.starts_with(b"HTTP/1.1 101"));
    assert!(
        String::from_utf8(headers.clone())
            .unwrap()
            .to_ascii_lowercase()
            .contains("\r\nconnection: upgrade\r\n"),
        "a reverse proxy must receive Connection: Upgrade with the 101"
    );
    std::fs::OpenOptions::new().append(true).open(root.join("audit.jsonl")).unwrap()
        .write_all(b"{\"event\":\"agent.started\",\"kind\":\"agent\",\"severity\":\"low\",\"summary\":\"Agent probe started\",\"agent\":\"probe\"}\n").unwrap();
    let mut frame = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), events.read_exact(&mut frame))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame[0] & 0x0f, 1);
    assert!(frame[1] < 126);
    let mut body = vec![0u8; usize::from(frame[1])];
    events.read_exact(&mut body).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["event"],
        "agent.started"
    );
    assert_eq!(
        admin(events_port, "wrong", "GET", "/admin/events", b"")
            .await
            .0,
        401
    );
    assert_eq!(
        admin(events_port, TOKEN, "GET", "/admin/agents", b"")
            .await
            .0,
        404
    );

    proxy.shutdown().await;
    let restarted = Proxy::start(config.clone()).await.unwrap();
    let restarted_port = admin_port(&config);
    assert_eq!(
        admin(restarted_port, TOKEN, "GET", "/admin/instance", b"")
            .await
            .1["safeyolo_instance_id"],
        HOST_ID
    );
    assert_ne!(
        admin(restarted_port, TOKEN, "GET", "/admin/runtime-identity", b"")
            .await
            .1["instance_id"],
        runtime["instance_id"]
    );
    restarted.shutdown().await;

    let tailnet_state = root.join("command-centre-tailnet-status.json");
    unsafe {
        std::env::set_var("SAFEYOLO_COMMAND_CENTRE_TAILNET_ADMIN_PORT", "10443");
        std::env::set_var("SAFEYOLO_COMMAND_CENTRE_TAILNET_EVENTS_PORT", "10444");
        std::env::set_var(
            "SAFEYOLO_COMMAND_CENTRE_TAILNET_STATUS_FILE",
            &tailnet_state,
        );
    }
    let published = Proxy::start(config.clone()).await.unwrap();
    let status: Value = serde_json::from_slice(&std::fs::read(&tailnet_state).unwrap()).unwrap();
    assert_eq!(status["state"], "healthy");
    assert_eq!(status["admin_url"], "https://host.test.ts.net:10443/");
    assert_eq!(
        status["events_url"],
        "wss://host.test.ts.net:10444/admin/events"
    );
    let published_port = admin_port(&config);
    assert_eq!(
        std::fs::read_to_string(root.join("tailnet/10443.target")).unwrap(),
        format!("http://127.0.0.1:{published_port}")
    );
    assert_eq!(
        std::fs::read_to_string(root.join("tailnet/10444.target")).unwrap(),
        format!("http://127.0.0.1:{events_port}")
    );
    published.shutdown().await;
    assert!(!tailnet_state.exists());
    assert!(!root.join("tailnet/10443.target").exists());
    assert!(!root.join("tailnet/10444.target").exists());
    let republished = Proxy::start(config.clone()).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&tailnet_state).unwrap()).unwrap()["state"],
        "healthy"
    );
    republished.shutdown().await;
    assert!(!root.join("tailnet/10443.target").exists());
    assert!(!root.join("tailnet/10444.target").exists());
    std::fs::write(root.join("tailnet/10443.target"), "http://127.0.0.1:9999").unwrap();
    assert!(
        Proxy::start(config).await.is_err(),
        "an existing Tailnet mapping must not be replaced"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("tailnet/10443.target")).unwrap(),
        "http://127.0.0.1:9999"
    );
}

fn admin_port(config: &Config) -> u16 {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
    ready["admin_port"].as_u64().unwrap().try_into().unwrap()
}

async fn assert_agent_cannot_reach_events(config: &Config, events_port: u16) {
    let mut stream = UnixStream::connect(&config.listeners[0].socket_path)
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "GET http://127.0.0.1:{events_port}/admin/events HTTP/1.1\r\nHost: 127.0.0.1:{events_port}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let head = std::str::from_utf8(
        &response[..response.windows(4).position(|w| w == b"\r\n\r\n").unwrap()],
    )
    .unwrap();
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("x-blocked-by: admin-shield"),
        "{head}"
    );
}

async fn admin(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let status = std::str::from_utf8(&response[..end])
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let document = serde_json::from_slice(&response[end + 4..]).unwrap();
    (status, document)
}
