//! Real Admin desktop route through the native preview and guest transport.
#![cfg(target_os = "linux")]

use std::{fs, net::Ipv4Addr, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TOKEN: &str = "desktop-native-token";
const ID: &str = "ag-11111111111111111111111111111111";

fn fixture(root: &Path, guest_port: u16) {
    fs::write(
        root.join("policy.toml"),
        format!("[agents.alice]\nagent_id = \"{ID}\"\n"),
    )
    .unwrap();
    fs::write(
        root.join("native-policy.toml"),
        "[[permissions]]\naction=\"network:request\"\nresource=\"*\"\neffect=\"allow\"\n",
    )
    .unwrap();
    fs::write(root.join("token"), TOKEN).unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let script = bin.join("runsc");
    fs::write(&script, r#"#!/bin/sh
case "$3" in
  state)
    if [ -e "$SAFEYOLO_CONFIG_DIR/agent-stopped" ]; then exit 1; fi
    printf '{"status":"running"}\n'
    ;;
  exec)
    case "$*" in
      *"guest-desktop status"*) [ -e "$SAFEYOLO_CONFIG_DIR/desktop-ready" ];;
      *"guest-desktop start"*)
        if [ -e "$SAFEYOLO_CONFIG_DIR/start-fails" ]; then exit 1; fi
        : > "$SAFEYOLO_CONFIG_DIR/desktop-ready"
        ;;
      *"guest-desktop stop"*)
        rm -f "$SAFEYOLO_CONFIG_DIR/desktop-ready"
        : > "$SAFEYOLO_CONFIG_DIR/desktop-stopped"
        ;;
      *) exit 2;;
    esac
    ;;
  port-forward)
    if [ -e "$SAFEYOLO_CONFIG_DIR/guest-port-closed" ]; then
      echo "connection was refused" >&2
      exit 1
    fi
    /usr/bin/socat "UNIX-CONNECT:$5" "TCP:127.0.0.1:$FAKE_GUEST_PORT" </dev/null >/dev/null 2>/dev/null &
    ;;
  *) exit 2;;
esac
"#).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    unsafe {
        std::env::set_var("SAFEYOLO_CONFIG_DIR", root);
        std::env::set_var("FAKE_GUEST_PORT", guest_port.to_string());
        std::env::set_var(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        );
        std::env::remove_var("SAFEYOLO_DESKTOP_PRESENTER_PYTHON");
    }
}

fn config(root: &Path) -> Config {
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":root.join("alice.sock")}],
        "policy_file":root.join("native-policy.toml"),
        "data_dir":root.join("data"),
        "admin_port":0,
        "admin_api_token_file":root.join("token"),
        "readiness_file":root.join("ready.json"),
        "flow_store_enabled":false,
        "audit_log_path":root.join("audit.jsonl"),
        "event_log":root.join("events.jsonl")
    }))
    .unwrap()
}

async fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn body(response: &[u8]) -> Value {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    serde_json::from_slice(&response[end + 4..]).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_admin_desktop_starts_reuses_unlocks_and_closes() {
    let root = TempDir::new().unwrap();
    let guest = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    fixture(root.path(), guest.local_addr().unwrap().port());
    let origin = tokio::spawn(async move {
        let (mut stream, _) = guest.accept().await.unwrap();
        let mut incoming = vec![0u8; 4096];
        let size = stream.read(&mut incoming).await.unwrap();
        let received = &incoming[..size];
        assert!(received.starts_with(b"GET /vnc.html HTTP/1.1\r\n"));
        assert!(
            received
                .windows(b"X-SafeYolo-Preview: 1".len())
                .any(|part| part == b"X-SafeYolo-Preview: 1")
        );
        assert!(
            !received
                .windows(b"safeyolo_preview_token_".len())
                .any(|part| part == b"safeyolo_preview_token_")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nalive")
            .await
            .unwrap();
    });
    let proxy = Proxy::start(config(root.path())).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let admin_headers = [("Authorization", format!("Bearer {TOKEN}"))];
    let first = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&first), 200, "{}", String::from_utf8_lossy(&first));
    let first = body(&first);
    assert_eq!(first["agent_id"], ID);
    assert_eq!(first["reused"], false);
    assert!(root.path().join("desktop-ready").exists());
    assert!(
        root.path()
            .join("agents/alice/config-share/guest-desktop")
            .exists()
    );
    let url = first["url"].as_str().unwrap();
    let preview_port: u16 = url
        .split(':')
        .nth(2)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let locked = request(preview_port, "GET", "/vnc.html", &[], b"").await;
    assert_eq!(status(&locked), 200);
    assert!(String::from_utf8_lossy(&locked).contains("Unlock Preview"));
    let code = first["unlock_code"].as_str().unwrap();
    let unlock = request(
        preview_port,
        "POST",
        "/_safeyolo_preview/unlock",
        &[
            ("Content-Type", "application/x-www-form-urlencoded".into()),
            ("Origin", format!("http://127.0.0.1:{preview_port}")),
        ],
        format!("code={code}").as_bytes(),
    )
    .await;
    assert_eq!(status(&unlock), 303, "{}", String::from_utf8_lossy(&unlock));
    let cookie = String::from_utf8_lossy(&unlock)
        .lines()
        .find_map(|line| line.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let opened = request(preview_port, "GET", "/vnc.html", &[("Cookie", cookie)], b"").await;
    assert_eq!(status(&opened), 200);
    assert!(opened.ends_with(b"alive"));
    origin.await.unwrap();
    let second = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&second), 200);
    let second = body(&second);
    assert_eq!(second["reused"], true);
    assert_eq!(second["url"], first["url"]);
    assert_ne!(second["unlock_code"], first["unlock_code"]);
    proxy.shutdown().await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, preview_port))
            .await
            .is_err()
    );
}
