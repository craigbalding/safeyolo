//! Real Admin desktop route through the native preview and guest transport.
#![cfg(target_os = "linux")]

use std::{
    fs,
    net::Ipv4Addr,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};

const TOKEN: &str = "desktop-native-token";
const ID: &str = "ag-11111111111111111111111111111111";

#[path = "support/owned_run.rs"]
mod owned_run;
use owned_run::OwnedRun;

fn fixture(root: &Path) {
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
printf 'runsc=%s uid=%s gid=%s userns=%s netns=%s\n' "$0" "$(/usr/bin/id -u)" "$(/usr/bin/id -g)" "$(/usr/bin/readlink /proc/self/ns/user)" "$(/usr/bin/readlink /proc/self/ns/net)" >> "$SAFEYOLO_CONFIG_DIR/desktop-child.trace"
printf 'argv <%s>\n' "$@" >> "$SAFEYOLO_CONFIG_DIR/desktop-child.trace"
trap 'printf "runsc exit=%s\n" "$?" >> "$SAFEYOLO_CONFIG_DIR/desktop-child.trace"' EXIT
case "$3" in
  state)
    if [ -e "$SAFEYOLO_CONFIG_DIR/agent-stopped" ]; then exit 1; fi
    [ "$4" = "$FAKE_RUN_ID" ] || exit 2
    printf '{"id":"%s","status":"%s"}\n' "${FAKE_STATE_ID:-$FAKE_RUN_ID}" "${FAKE_STATE_STATUS:-running}"
    ;;
  exec)
    [ "$8" = "$FAKE_RUN_ID" ] || exit 2
    case "$*" in
      *"desktop-probe"*)
        if [ -n "$SAFEYOLO_DESKTOP_GUEST" ]; then exec "$SAFEYOLO_DESKTOP_GUEST" desktop-probe; fi
        printf '%s\n' '{"schema_version":1,"tcp":"refused","greeting":"not_checked","duration_ms":0}'
        ;;
      *"guest-desktop status"*) [ -e "$SAFEYOLO_CONFIG_DIR/desktop-ready" ];;
      *"guest-desktop start"*)
        if [ -e "$SAFEYOLO_CONFIG_DIR/start-fails" ]; then exit 1; fi
        printf '%s\n' "$*" > "$SAFEYOLO_CONFIG_DIR/desktop-start-command"
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
    [ "$6" = "$FAKE_RUN_ID" ] && [ "$7" = 6080 ] || exit 2
    if [ -e "$SAFEYOLO_CONFIG_DIR/guest-port-closed" ]; then
      echo "connection was refused" >&2
      exit 1
    fi
    /usr/bin/socat "UNIX-CONNECT:$5" "UNIX-CONNECT:$SAFEYOLO_CONFIG_DIR/guest.sock" </dev/null >/dev/null 2>/dev/null &
    ;;
  *) exit 2;;
esac
"#).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    unsafe {
        std::env::set_var("SAFEYOLO_CONFIG_DIR", root);
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
        "audit_log_path":root.join("audit.jsonl"),}))
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

fn unverified_runs(root: &Path) -> Vec<Option<Value>> {
    let run: Value =
        serde_json::from_slice(&fs::read(root.join("agents/alice/runtime.json")).unwrap()).unwrap();
    let mut wrong_generation = run.clone();
    wrong_generation["run_id"] = "99999999999999999999999999999999".into();
    let mut wrong_birth = run.clone();
    wrong_birth["holder_token"] = "different-birth".into();
    wrong_birth["backend_token"] = "different-birth".into();
    let mut unrelated = run;
    unrelated["holder_pid"] = std::process::id().into();
    unrelated["backend_pid"] = std::process::id().into();
    let token = owned_run::process_token(std::process::id());
    unrelated["holder_token"] = token.clone().into();
    unrelated["backend_token"] = token.into();
    vec![
        None,
        Some(wrong_generation),
        Some(wrong_birth),
        Some(unrelated),
    ]
}

fn save_run(root: &Path, run: &Option<Value>) {
    let path = root.join("agents/alice/runtime.json");
    if let Some(run) = run {
        fs::write(path, serde_json::to_vec(run).unwrap()).unwrap();
    } else {
        fs::remove_file(path).unwrap();
    }
}

fn assert_staged_desktop_size(root: &Path, expected: &str) {
    let share = root.join("agents/alice/config-share");
    assert_eq!(
        fs::read_to_string(share.join("desktop-size")).unwrap(),
        format!("{expected}\n")
    );
    // Relocate the guest share and observe the parsed size at the capability
    // check, before starting graphical processes. The staged Bash consumer
    // really reads desktop-size; explicit arguments must still take precedence.
    let launcher = root.join("consume-guest-desktop");
    let source = fs::read_to_string(share.join("guest-desktop")).unwrap();
    fs::write(
        &launcher,
        source
            .replace("/safeyolo/", &format!("{}/", share.display()))
            .replace(
                "action=\"${1:-start}\"",
                "_check_capability() { printf '%s\\n' \"${width}x${height}x${depth}\"; exit 0; }\naction=\"${1:-start}\"",
            ),
    )
    .unwrap();
    for (args, geometry) in [
        (vec!["start"], Some(expected)),
        (vec!["start", "800x600"], Some("800x600")),
        (vec!["start", "invalid"], None),
    ] {
        let output = Command::new("/bin/bash")
            .arg(&launcher)
            .args(args)
            .env_clear()
            .env("PATH", root.join("bin"))
            .env("HOME", root)
            .output()
            .unwrap();
        if let Some(geometry) = geometry {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{geometry}x24\n")
            );
        } else {
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&output.stderr).contains("usage: guest-desktop start"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_admin_desktop_starts_reuses_unlocks_and_closes() {
    let root = TempDir::new().unwrap();
    let guest = UnixListener::bind(root.path().join("guest.sock")).unwrap();
    fixture(root.path());
    symlink("/usr/bin/head", root.path().join("bin/head")).unwrap();
    unsafe {
        std::env::set_var("SAFEYOLO_PREVIEW_SCREEN_SIZE", "1920x1080");
    }
    let mut run = OwnedRun::start(root.path());
    // Keep the real namespace entry and pass its stderr through while also
    // recording it for a missing desktop marker.
    fs::write(
        root.path().join("bin/nsenter"),
        r#"#!/bin/bash
printf 'nsenter argv <%s>\n' "$@" >> "$SAFEYOLO_CONFIG_DIR/desktop-child.trace"
exec /usr/bin/nsenter --preserve-credentials "$@" 2> >(/usr/bin/tee -a "$SAFEYOLO_CONFIG_DIR/desktop-child.trace" >&2)
"#,
    )
    .unwrap();
    // A stale launch projection must not deny an independently live runtime.
    fs::write(
        root.path().join("agents/alice/current-launch.json"),
        serde_json::to_vec(&json!({
            "agent_id":ID,"name":"alice","state":"exited"
        }))
        .unwrap(),
    )
    .unwrap();
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
    let saved_run = Some(
        serde_json::from_slice(&fs::read(root.path().join("agents/alice/runtime.json")).unwrap())
            .unwrap(),
    );
    let refused_runs = unverified_runs(root.path());
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
    assert!(
        root.path().join("desktop-ready").exists(),
        "desktop start missing: host UID/GID={}/{}, account={:?}, helper={:?}, observations={:?}",
        unsafe { libc::getuid() },
        unsafe { libc::getgid() },
        Command::new("/usr/bin/getent")
            .args(["passwd", &unsafe { libc::getuid() }.to_string()])
            .output()
            .map(|output| (
                output.status,
                String::from_utf8_lossy(&output.stdout).into_owned()
            )),
        std::env::var_os("SAFEYOLO_DESKTOP_GUEST"),
        [
            PathBuf::from("/etc/subuid"),
            PathBuf::from("/etc/subgid"),
            PathBuf::from(format!("/proc/{}/uid_map", run.child.id())),
            PathBuf::from(format!("/proc/{}/gid_map", run.child.id())),
            root.path().join("desktop-child.trace"),
        ]
        .map(|path| {
            let observed =
                fs::read_to_string(&path).map(|text| text.chars().take(4096).collect::<String>());
            (path, observed)
        }),
    );
    assert!(
        root.path()
            .join("agents/alice/config-share/guest-desktop")
            .exists()
    );
    assert_staged_desktop_size(root.path(), "1760x900");
    let original_start = fs::read(root.path().join("desktop-start-command")).unwrap();
    assert!(String::from_utf8_lossy(&original_start).ends_with("guest-desktop start 1760x900\n"));
    assert!(!root.path().join("config.toml").exists());
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
    let page = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&page), 200);
    assert!(String::from_utf8_lossy(&page).contains("Show diagnostics"));
    let denied = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[],
        b"",
    )
    .await;
    assert_eq!(status(&denied), 401);
    let cross = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[
            ("Cookie", cookie.clone()),
            ("Origin", "https://other.test".into()),
        ],
        b"",
    )
    .await;
    assert_eq!(status(&cross), 403);
    let legacy_cross_agent = request(
        preview_port,
        "GET",
        "/websockify",
        &[
            ("Cookie", cookie.clone()),
            ("Origin", "http://127.0.0.1:9".into()),
            ("Upgrade", "websocket".into()),
            ("Connection", "Upgrade".into()),
        ],
        b"",
    )
    .await;
    assert_eq!(status(&legacy_cross_agent), 403);
    let diagnosis = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&diagnosis), 200);
    assert_eq!(body(&diagnosis)["recorded_agent_state"], "exited");
    assert_eq!(body(&diagnosis)["runtime"]["state"], "running");
    assert_eq!(body(&diagnosis)["runtime"]["disagreement"], false);
    for saved in &refused_runs {
        save_run(root.path(), saved);
        let presented = request(
            admin_port,
            "POST",
            "/admin/agents/alice/desktop/present",
            &admin_headers,
            b"",
        )
        .await;
        assert_eq!(
            status(&presented),
            200,
            "authorized diagnosis must survive suspect readiness"
        );
        let page = request(
            preview_port,
            "GET",
            "/_safeyolo_desktop/",
            &[("Cookie", cookie.clone())],
            b"",
        )
        .await;
        assert_eq!(status(&page), 200);
        save_run(root.path(), &saved_run);
    }
    save_run(root.path(), &None);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let missing_record = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(body(&missing_record)["saved_run"], "missing_or_unreadable");
    assert_eq!(body(&missing_record)["runtime"]["disagreement"], false);
    save_run(root.path(), &saved_run);
    unsafe {
        std::env::set_var("FAKE_STATE_ID", "safeyolo-99999999999999999999999999999999");
    }
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let diagnosis = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&diagnosis), 200);
    assert_eq!(body(&diagnosis)["runtime"]["state"], "unknown");
    assert_ne!(body(&diagnosis)["runtime"]["state"], "stopped");
    unsafe {
        std::env::remove_var("FAKE_STATE_ID");
        std::env::set_var("FAKE_STATE_STATUS", "stopped");
    }
    fs::write(
        root.path().join("agents/alice/current-launch.json"),
        serde_json::to_vec(&json!({
            "agent_id":ID,"name":"alice","state":"running"
        }))
        .unwrap(),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let stopped_runtime = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&stopped_runtime), 200);
    assert_eq!(body(&stopped_runtime)["runtime"]["state"], "stopped");
    assert_eq!(body(&stopped_runtime)["recorded_agent_state"], "running");
    assert_eq!(body(&stopped_runtime)["runtime"]["disagreement"], false);
    unsafe {
        std::env::remove_var("FAKE_STATE_STATUS");
    }
    // The unlocked preview still consults native ownership before opening a
    // guest stream. No refused request should reach the two-response origin.
    for refused in &refused_runs {
        save_run(root.path(), refused);
        let refused = request(
            preview_port,
            "GET",
            "/vnc.html",
            &[("Cookie", cookie.clone())],
            b"",
        )
        .await;
        assert_eq!(status(&refused), 502);
        save_run(root.path(), &saved_run);
    }
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
        &[("Cookie", cookie.clone()), ("Content-Length", "0".into())],
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

    // An authenticated operator can diagnose a separate configured target.
    // Alice's preview credential must not unlock Bob's diagnostic endpoint.
    fs::write(root.path().join("policy.toml"), format!("[agents.alice]\nagent_id='{ID}'\n[agents.bob]\nagent_id='ag-22222222222222222222222222222222'\n")).unwrap();
    let bob = request(
        admin_port,
        "POST",
        "/admin/agents/bob/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(status(&bob), 200);
    let bob_port: u16 = body(&bob)["url"]
        .as_str()
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let cross_agent = request(
        bob_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&cross_agent), 401);
    fs::write(
        root.path().join("policy.toml"),
        format!("[agents.alice]\nagent_id='{ID}'\n"),
    )
    .unwrap();

    // A different generation is terminal for this page. It cannot retarget.
    let context_path = root
        .path()
        .join("agents/alice/config-share/host-launch-context.json");
    let context = fs::read(&context_path).unwrap();
    fs::write(
        &context_path,
        b"{\"generation\":\"99999999999999999999999999999999\"}",
    )
    .unwrap();
    let replaced = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie.clone())],
        b"",
    )
    .await;
    assert_eq!(status(&replaced), 410);
    fs::write(context_path, context).unwrap();
    fs::write(root.path().join("policy.toml"), "").unwrap();
    let deleted = request(
        preview_port,
        "GET",
        "/_safeyolo_desktop/diagnostics",
        &[("Cookie", cookie)],
        b"",
    )
    .await;
    assert_eq!(status(&deleted), 410);
    fs::write(
        root.path().join("policy.toml"),
        format!("[agents.alice]\nagent_id='{ID}'\n"),
    )
    .unwrap();
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
        root.path().join("data/instance_id"),
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
    fs::write(
        root.path().join("config.toml"),
        "[command_centre]\nshare='tailnet'\n[desktop]\nsize=' 1920X1080 '\n",
    )
    .unwrap();
    unsafe {
        std::env::set_var(
            "SAFEYOLO_OPERATOR_INSTANCE_ID_FILE",
            root.path().join("data/instance_id"),
        );
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
    assert_staged_desktop_size(root.path(), "1920x1080");
    // #1040 forbids automatic desktop restarts. Stage the configured size for
    // the next start, and preserve the desktop already running for a viewer.
    assert_eq!(
        fs::read(root.path().join("desktop-start-command")).unwrap(),
        original_start
    );
    assert!(
        fs::read_to_string(root.path().join("config.toml"))
            .unwrap()
            .contains("size=' 1920X1080 '")
    );
    assert!(
        body(&presented)["url"]
            .as_str()
            .unwrap()
            .starts_with("https://host.test.ts.net:8443/_safeyolo_desktop/")
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

    // This failure case needs an absent desktop to exercise rollback of only
    // a newly started service. Removing this owned fixture marker models that.
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
    fs::remove_file(root.path().join("config.toml")).unwrap();
    unsafe {
        std::env::remove_var("SAFEYOLO_OPERATOR_INSTANCE_ID_FILE");
        std::env::remove_var("FAKE_TAILSCALE_STATE_DIR");
    }

    // A preview bind failure after the guest desktop starts must roll back
    // that newly started desktop and leave no owned presentation behind.
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    fs::write(
        root.path().join("config.toml"),
        format!(
            "[desktop]\npresent_host_port = {}\n",
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
    fs::remove_file(root.path().join("config.toml")).unwrap();

    let staged = fs::read(root.path().join("agents/alice/config-share/desktop-size")).unwrap();
    for size in ["639x480", "640x479", "01280x800", "1280x800x24", "invalid"] {
        fs::write(
            root.path().join("config.toml"),
            format!("[desktop]\nsize='{size}'\n"),
        )
        .unwrap();
        let refused = request(
            admin_port,
            "POST",
            "/admin/agents/alice/desktop/present",
            &admin_headers,
            b"",
        )
        .await;
        assert_eq!(status(&refused), 409, "size={size}");
        assert_eq!(
            fs::read(root.path().join("agents/alice/config-share/desktop-size")).unwrap(),
            staged
        );
        assert!(!root.path().join("desktop-ready").exists());
    }
    fs::remove_file(root.path().join("config.toml")).unwrap();

    fs::write(root.path().join("agent-stopped"), b"").unwrap();
    let stopped = request(
        admin_port,
        "POST",
        "/admin/agents/alice/desktop/present",
        &admin_headers,
        b"",
    )
    .await;
    assert_eq!(
        status(&stopped),
        200,
        "known target must keep diagnostic access"
    );
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
    drop(run.child.stdin.take());
    run.assert_exited();
}

/// Real browser/noVNC/native bridge/X11 evidence with controlled runsc control.
/// The installed platform witness separately proves the real runtime leg.
#[tokio::test]
#[ignore = "needs Playwright Python, noVNC 1.6 assets, native guest helper, Xvfb and x11vnc"]
async fn native_desktop_real_browser() {
    let storage = std::env::var("SAFEYOLO_DESKTOP_STORAGE").unwrap();
    let root = TempDir::new_in(storage).unwrap();
    fixture(root.path());
    let mut run = OwnedRun::start(root.path());
    // These real X11/bridge/probe processes share this test's loopback.
    // Only the controlled runsc adapter skips entering the fixture network
    // namespace for the fixed guest probe. Production ownership checks still
    // run; this test does not claim an installed runsc guest journey.
    fs::write(
        root.path().join("bin/nsenter"),
        r#"#!/bin/sh
case "$*" in
  *"desktop-probe"*) exec "$SAFEYOLO_DESKTOP_GUEST" desktop-probe;;
  *) exec /usr/bin/nsenter --preserve-credentials "$@";;
esac
"#,
    )
    .unwrap();
    let guest = UnixListener::bind(root.path().join("guest.sock")).unwrap();
    let blackhole = root.path().join("blackhole");
    let forwarder = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        let mut viewers = 0;
        loop {
            tokio::select! {
                accepted = guest.accept() => {
                    let (mut client, _) = accepted.unwrap();
                    let mut prefix = [0; 8192];
                    let count = client.read(&mut prefix).await.unwrap();
                    let upgrade = String::from_utf8_lossy(&prefix[..count]).to_ascii_lowercase().contains("upgrade: websocket");
                    let faultable_viewer = upgrade && viewers != 1;
                    if upgrade { viewers += 1; }
                    let prefix = prefix[..count].to_vec();
                    let blackhole = blackhole.clone();
                    peers.spawn(async move {
                        let Ok(mut origin) = TcpStream::connect((Ipv4Addr::LOCALHOST, 6080)).await else { return; };
                        origin.write_all(&prefix).await.unwrap();
                        let transfer = tokio::io::copy_bidirectional(&mut client, &mut origin);
                        tokio::pin!(transfer);
                        loop {
                            // Hold both sockets open while only the first
                            // established stream loses transport progress.
                            if faultable_viewer && blackhole.exists() {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                            tokio::select! {
                                _ = &mut transfer => break,
                                _ = tokio::time::sleep(Duration::from_millis(100)) => (),
                            }
                        }
                    });
                }
                Some(_) = peers.join_next() => (),
            }
        }
    });
    let proxy = Proxy::start(config(root.path())).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let port = ready["admin_port"].as_u64().unwrap();
    // The actual CLI needs only this disposable instance's Admin configuration.
    fs::write(
        root.path().join("config.toml"),
        format!("admin_port={port}\nadmin_api_token_file='token'\npolicy_file='policy.toml'\n"),
    )
    .unwrap();
    let cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .args([
            "--root",
            root.path().to_str().unwrap(),
            "agent",
            "present",
            "alice",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let presented: Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert!(
        presented["url"]
            .as_str()
            .unwrap()
            .contains("/_safeyolo_desktop/")
    );
    let python = std::env::var("SAFEYOLO_DESKTOP_BROWSER_PYTHON").unwrap();
    let result = tokio::process::Command::new(python)
        .args(["-c", "from tests.proxy_contracts.test_desktop_waiting_page import native_browser_journey; native_browser_journey()"])
        .env("PYTHONPATH", std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .env("SAFEYOLO_DESKTOP_URL", presented["url"].as_str().unwrap())
        .env("SAFEYOLO_DESKTOP_CODE", presented["unlock_code"].as_str().unwrap())
        .env("SAFEYOLO_DESKTOP_FIXTURE", root.path())
        .kill_on_drop(true).output().await.unwrap();
    proxy.shutdown().await;
    forwarder.abort();
    let _ = forwarder.await;
    drop(run.child.stdin.take());
    run.assert_exited();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    print!("{}", String::from_utf8_lossy(&result.stdout));
}
