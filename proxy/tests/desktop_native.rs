//! Real Admin desktop route through the native preview and guest transport.
#![cfg(target_os = "linux")]

use std::{fs, net::Ipv4Addr, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
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
    fs::create_dir(root.join("data")).unwrap();
    fs::write(root.join("data/agent_token"), "native-desktop-agent-token").unwrap();
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
        /bin/rm -f "$SAFEYOLO_CONFIG_DIR/desktop-ready"
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
        // An interpreter name is unavailable in the proxy's executable path.
        std::env::set_var("PATH", bin);
        std::env::set_var("SAFEYOLO_CLI_PYTHON", "/no/python/interpreter");
        std::env::set_var("SAFEYOLO_LOG_PATH", root.join("audit.jsonl"));
    }
}

fn config(root: &Path) -> Config {
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":root.join("alice.sock")}],
        "policy_file":root.join("native-policy.toml"),
        "data_dir":root.join("data"),
        "agent_api_enabled":true,
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
        for attempt in 0..2 {
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
            if attempt == 1 {
                assert!(received.windows(11).any(|part| part == b"X-Byte: \xff\r\n"));
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nalive",
                )
                .await
                .unwrap();
        }
    });
    let proxy = Proxy::start(config(root.path())).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let admin_headers = [("Authorization", format!("Bearer {TOKEN}"))];
    let mut agent = UnixStream::connect(root.path().join("alice.sock"))
        .await
        .unwrap();
    agent
        .write_all(b"POST http://_safeyolo.proxy.internal/desktop/present HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer native-desktop-agent-token\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        .await
        .unwrap();
    let mut requested = Vec::new();
    agent.read_to_end(&mut requested).await.unwrap();
    assert_eq!(status(&requested), 202);
    let request_id = body(&requested)["request_id"].as_str().unwrap().to_owned();
    let pending = request(admin_port, "GET", "/admin/approvals", &admin_headers, b"").await;
    assert_eq!(status(&pending), 200);
    assert_eq!(body(&pending)["approvals"][0]["request_id"], request_id);
    let first = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        serde_json::to_string(&json!({"approval_request_id":request_id}))
            .unwrap()
            .as_bytes(),
    )
    .await;
    assert_eq!(status(&first), 200, "{}", String::from_utf8_lossy(&first));
    let first = body(&first);
    assert_eq!(first["agent_id"], ID);
    assert_eq!(first["reused"], false);
    let resolved = request(admin_port, "GET", "/admin/approvals", &admin_headers, b"").await;
    assert_eq!(body(&resolved)["approvals"], json!([]));
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
    let mut oversized = TcpStream::connect((Ipv4Addr::LOCALHOST, preview_port))
        .await
        .unwrap();
    oversized.write_all(format!(
        "POST /_safeyolo_preview/unlock HTTP/1.1\r\nHost: 127.0.0.1:{preview_port}\r\nOrigin: http://127.0.0.1:{preview_port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut oversized_reply = Vec::new();
    oversized.read_to_end(&mut oversized_reply).await.unwrap();
    assert_eq!(status(&oversized_reply), 413);
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
    let opened = request(
        preview_port,
        "GET",
        "/vnc.html",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&opened), 200);
    assert!(opened.ends_with(b"alive"));
    let mut raw = TcpStream::connect((Ipv4Addr::LOCALHOST, preview_port))
        .await
        .unwrap();
    raw.write_all(format!("GET /vnc.html HTTP/1.1\r\nHost: 127.0.0.1:{preview_port}\r\nCookie: {cookie}\r\nConnection: close\r\nX-Byte: ").as_bytes()).await.unwrap();
    raw.write_all(b"\xff\r\n\r\n").await.unwrap();
    let mut raw_reply = Vec::new();
    raw.read_to_end(&mut raw_reply).await.unwrap();
    assert_eq!(status(&raw_reply), 200);
    assert!(raw_reply.ends_with(b"alive"));
    origin.await.unwrap();
    let ambiguous = request(
        preview_port,
        "GET",
        "/vnc.html",
        &[("Cookie", cookie), ("Content-Length", "0".into())],
        b"",
    )
    .await;
    assert_eq!(status(&ambiguous), 502);
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
    let audit = fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    for event in [
        "agent.preview_open",
        "agent.preview_unlock",
        "traffic.preview_request",
        "traffic.preview_response",
        "agent.preview_close",
    ] {
        assert!(
            audit.contains(event),
            "missing {event} from native preview audit"
        );
    }
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, preview_port))
            .await
            .is_err()
    );

    // An installed Commander request uses the durable ID returned by list,
    // even though the agent listener is named alice. Tailnet share must give
    // the remote Commander a reachable URL and own the Serve mapping.
    fs::write(
        root.path().join("instance_id"),
        "sy-22222222222222222222222222222222\n",
    )
    .unwrap();
    let tailscale = root.path().join("bin/tailscale");
    fs::write(
        &tailscale,
        r#"#!/bin/sh
root=$FAKE_TAILSCALE_STATE_DIR
/bin/mkdir -p "$root"
if [ "$1" = status ] && [ "$2" = --json ]; then
    if [ -e "$root/disconnected" ]; then
        printf '{"BackendState":"Stopped"}\n'
    else
        printf '{"BackendState":"Running","Self":{"DNSName":"host.test.ts.net."}}\n'
    fi
elif [ "$1" = serve ] && [ "$2" = status ] && [ "$3" = --json ]; then
    if [ -f "$root/8443.target" ]; then
        target=$(/bin/cat "$root/8443.target")
        printf '{"TCP":{"8443":{"HTTPS":true}},"Web":{"8443":{"Handlers":{"/":{"Proxy":"%s"}}}}}\n' "$target"
    else
        printf '{}\n'
    fi
elif [ "$1" = serve ] && [ "$2" = --yes ]; then
    marker=$root/${3#--https=}.target
    trap '/bin/rm -f "$marker"; exit 0' TERM
    printf '%s' "$4" > "$marker"
    while :; do /bin/sleep 0.1; done
else
    exit 2
fi
"#,
    )
    .unwrap();
    fs::set_permissions(&tailscale, fs::Permissions::from_mode(0o755)).unwrap();
    unsafe {
        std::env::set_var(
            "SAFEYOLO_OPERATOR_INSTANCE_ID_FILE",
            root.path().join("instance_id"),
        );
        std::env::set_var("SAFEYOLO_COMMAND_CENTRE_SHARE", "tailnet");
        std::env::set_var("FAKE_TAILSCALE_STATE_DIR", root.path().join("tailnet"));
    }
    let installed = Proxy::start(config(root.path())).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let listed = request(admin_port, "GET", "/admin/agents", &admin_headers, b"").await;
    assert_eq!(status(&listed), 200);
    let listed_id = body(&listed)["agents"][0]["agent_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(listed_id, ID);
    let unknown = request(
        admin_port,
        "POST",
        "/admin/agents/ag-99999999999999999999999999999999/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&unknown), 404);
    let listener_name = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&listener_name), 404);
    let presented = request(
        admin_port,
        "POST",
        &format!("/admin/agents/{listed_id}/desktop/present"),
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(
        status(&presented),
        200,
        "{}",
        String::from_utf8_lossy(&presented)
    );
    assert_eq!(body(&presented)["agent_id"], listed_id);
    assert!(
        body(&presented)["url"]
            .as_str()
            .unwrap()
            .starts_with("https://host.test.ts.net:8443/vnc.html")
    );
    let reused = request(
        admin_port,
        "POST",
        &format!("/admin/agents/{listed_id}/desktop/present"),
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&reused), 200);
    assert_eq!(body(&reused)["reused"], true);
    assert_eq!(body(&reused)["url"], body(&presented)["url"]);
    assert!(root.path().join("tailnet/8443.target").exists());
    installed.shutdown().await;
    assert!(!root.path().join("tailnet/8443.target").exists());

    fs::remove_file(root.path().join("desktop-ready")).unwrap();
    fs::write(root.path().join("tailnet/disconnected"), "").unwrap();
    let disconnected = Proxy::start(config(root.path())).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let failed_tailnet = request(
        admin_port,
        "POST",
        &format!("/admin/agents/{listed_id}/desktop/present"),
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&failed_tailnet), 409);
    assert!(root.path().join("desktop-stopped").exists());
    assert!(!root.path().join("desktop-ready").exists());
    assert!(!root.path().join("tailnet/8443.target").exists());
    disconnected.shutdown().await;
    unsafe {
        std::env::remove_var("SAFEYOLO_OPERATOR_INSTANCE_ID_FILE");
        std::env::remove_var("SAFEYOLO_COMMAND_CENTRE_SHARE");
        std::env::remove_var("FAKE_TAILSCALE_STATE_DIR");
    }

    // A preview bind failure after the guest desktop starts must roll back
    // that newly started desktop and leave no owned presentation behind.
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    fs::write(
        root.path().join("config.yaml"),
        format!(
            "desktop:\n  present_host_port: {}\n",
            occupied.local_addr().unwrap().port()
        ),
    )
    .unwrap();
    let proxy = Proxy::start(config(root.path())).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin_port = ready["admin_port"].as_u64().unwrap() as u16;
    let failed = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&failed), 409);
    assert_eq!(body(&failed)["error"], "Desktop presentation failed");
    assert!(root.path().join("desktop-stopped").is_file());
    assert!(!root.path().join("desktop-ready").exists());
    drop(occupied);
    fs::remove_file(root.path().join("config.yaml")).unwrap();

    fs::write(root.path().join("agent-stopped"), b"").unwrap();
    let stopped = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&stopped), 409);
    fs::remove_file(root.path().join("agent-stopped")).unwrap();
    fs::write(root.path().join("policy.toml"), "").unwrap();
    let missing = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&missing), 404);
    proxy.shutdown().await;
}
