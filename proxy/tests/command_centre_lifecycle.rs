//! Admin agent lifecycle through native host state with Python unavailable.
#![cfg(target_os = "linux")]

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const TOKEN: &str = "native-lifecycle-token";
const ID: &str = "ag-11111111111111111111111111111111";

fn setup(root: &Path) -> Config {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir_all(root.join("agents/alice/config-share")).unwrap();
    fs::write(root.join("token"), TOKEN).unwrap();
    fs::write(
        root.join("instance_id"),
        "sy-22222222222222222222222222222222\n",
    )
    .unwrap();
    fs::write(
        root.join("policy.toml"),
        format!(
            "[agents.alice]\nagent_id = \"{ID}\"\nfolder = \"{}\"\nlauncher = \"supervisor\"\n",
            workspace.display()
        ),
    )
    .unwrap();
    fs::write(
        root.join("native-policy.toml"),
        "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"allow\"\n",
    )
    .unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let runsc = bin.join("runsc");
    fs::write(
        &runsc,
        r#"#!/bin/sh
case "$3" in
    state)
        [ ! -e "$SAFEYOLO_CONFIG_DIR/stopped" ] || exit 1
        printf '{"status":"running"}\n'
        ;;
    kill)
        : > "$SAFEYOLO_CONFIG_DIR/stopped"
        ;;
    exec)
        while [ ! -e "$SAFEYOLO_CONFIG_DIR/stopped" ]; do /bin/sleep 0.1; done
        ;;
    delete) ;;
    *) exit 2 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&runsc, fs::Permissions::from_mode(0o755)).unwrap();
    unsafe {
        std::env::set_var("SAFEYOLO_CONFIG_DIR", root);
        std::env::set_var("SAFEYOLO_LOG_PATH", root.join("audit.jsonl"));
        std::env::set_var(
            "SAFEYOLO_OPERATOR_INSTANCE_ID_FILE",
            root.join("instance_id"),
        );
        std::env::set_var("SAFEYOLO_CLI_PYTHON", "/no/python/interpreter");
        std::env::set_var("PATH", &bin);
    }
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

async fn admin(port: u16, method: &str, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let end = reply
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let status = std::str::from_utf8(&reply[..end])
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = serde_json::from_slice(&reply[end + 4..]).unwrap();
    (status, body)
}

#[tokio::test]
async fn admin_lists_starts_observes_and_stops_without_python() {
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let config = setup(root);
    let proxy = Proxy::start(config).await.unwrap();
    let ready: Value = serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;

    let (code, list) = admin(port, "GET", "/admin/agents").await;
    assert_eq!(code, 200);
    assert_eq!(list["agents"][0]["agent_id"], ID);
    assert_eq!(list["agents"][0]["sandbox_state"], "ready");
    assert_eq!(list["agents"][0]["agent_state"], "stopped");

    let (code, started) = admin(port, "POST", &format!("/admin/agents/{ID}/start")).await;
    assert_eq!(code, 200, "{started}");
    assert_eq!(started["agent_state"], "starting");
    assert!(
        root.join("agents/alice/config-share/command-supervisor-enabled")
            .is_file()
    );
    let launch: Value =
        serde_json::from_slice(&fs::read(root.join("agents/alice/current-launch.json")).unwrap())
            .unwrap();
    assert_eq!(launch["launcher"]["kind"], "supervisor");
    assert_eq!(launch["state"], "managed");

    let (code, observed) = admin(port, "GET", "/admin/agents").await;
    assert_eq!(code, 200);
    assert_eq!(observed["agents"][0]["agent_state"], "starting");
    assert_eq!(
        admin(port, "POST", &format!("/admin/agents/{ID}/start"))
            .await
            .0,
        409
    );

    let (code, stopped) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    assert_eq!(code, 200, "{stopped}");
    assert_eq!(stopped["sandbox_state"], "stopped");
    assert_eq!(stopped["agent_state"], "stopped");
    assert!(
        root.join("agents/alice/home/.safeyolo-command-supervisor.stop")
            .is_file()
    );
    assert!(
        !root
            .join("agents/alice/config-share/command-supervisor-enabled")
            .exists()
    );
    assert!(root.join("stopped").exists());
    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert!(audit.contains("agent.started"));
    assert!(audit.contains("agent.stopped"));

    // Guest-owned supervisor state cannot turn a forged, correctly tokened
    // host PID into authority for the native proxy to signal that process.
    fs::remove_file(root.join("stopped")).unwrap();
    let mut unrelated = Command::new("/bin/sleep").arg("15").spawn().unwrap();
    let pid = unrelated.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let start_ticks = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let token = format!("linux:{}:{pid}:{start_ticks}", boot.trim());
    fs::write(
        root.join("agents/alice/home/.safeyolo-command-supervisor.json"),
        serde_json::to_vec(&json!({
            "schema_version":1,"name":"alice","command":"sleep",
            "state":"running","runtime_owner":"host",
            "supervisor_pid":pid,"supervisor_start_token":token
        }))
        .unwrap(),
    )
    .unwrap();
    let (code, rejected) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    assert_eq!(code, 500, "{rejected}");
    assert!(
        unrelated.try_wait().unwrap().is_none(),
        "unrelated host process was signaled"
    );
    assert!(
        !root.join("stopped").exists(),
        "sandbox stopped without supervisor acknowledgement"
    );
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();

    // A custom host launcher for Alice must also be rejected when it lives
    // under Bob's writable mount. Both launch and stop validate that path.
    let bob = root.join("bob-writable");
    fs::create_dir(&bob).unwrap();
    let script = bob.join("host-launch.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\n", root.join("ran-script").display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("policy.toml"),
        format!(
            "[agents.alice]\nagent_id = \"{ID}\"\nfolder = \"{}\"\nlauncher = \"{}\"\n\n[agents.bob]\nagent_id = \"ag-33333333333333333333333333333333\"\nmounts = [\"{}:/mnt/shared\"]\n",
            root.join("workspace").display(), script.display(), bob.display()
        ),
    ).unwrap();
    fs::remove_file(root.join("agents/alice/home/.safeyolo-command-supervisor.json")).unwrap();
    let launch_path = root.join("agents/alice/current-launch.json");
    let mut launch: Value = serde_json::from_slice(&fs::read(&launch_path).unwrap()).unwrap();
    launch["state"] = "failed".into();
    fs::write(&launch_path, serde_json::to_vec(&launch).unwrap()).unwrap();
    let (code, rejected) = admin(port, "POST", &format!("/admin/agents/{ID}/start")).await;
    assert_eq!(code, 500, "{rejected}");
    assert!(rejected.to_string().contains("agent-writable mount"));
    assert!(!root.join("ran-script").exists());
    let (code, rejected) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    assert_eq!(code, 500, "{rejected}");
    assert!(rejected.to_string().contains("agent-writable mount"));
    assert!(!root.join("ran-script").exists());

    if Path::new("/usr/bin/tmux").is_file() {
        // The normal launcher runs this same proxy binary in an isolated
        // tmux server and keeps the guest command live until Admin stop.
        fs::write(root.join("policy.toml"), format!(
            "[agents.alice]\nagent_id = \"{ID}\"\nfolder = \"{}\"\nlauncher = \"tmux-window\"\n",
            root.join("workspace").display()
        )).unwrap();
        fs::remove_file(&launch_path).unwrap();
        let session = format!("safeyolo-894-{}", std::process::id());
        fs::write(
            root.join("config.yaml"),
            format!("agent_launcher:\n  tmux_session: {session}\n"),
        )
        .unwrap();
        let tmux_dir = root.join("tmux");
        fs::create_dir(&tmux_dir).unwrap();
        std::os::unix::fs::symlink("/usr/bin/tmux", root.join("bin/tmux")).unwrap();
        unsafe {
            std::env::set_var("TMUX_TMPDIR", &tmux_dir);
            std::env::set_var(
                "SAFEYOLO_NATIVE_PROXY_BINARY",
                env!("CARGO_BIN_EXE_safeyolo-proxy"),
            );
        }
        let (code, started) = admin(port, "POST", &format!("/admin/agents/{ID}/start")).await;
        assert_eq!(code, 200, "{started}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let (code, observed) = admin(port, "GET", "/admin/agents").await;
            assert_eq!(code, 200);
            if observed["agents"][0]["agent_state"] == "running" {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "{observed}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (code, stopped) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
        assert_eq!(code, 200, "{stopped}");
        assert_eq!(stopped["sandbox_state"], "stopped");
        assert!(root.join("stopped").exists());
        let _ = Command::new("/usr/bin/tmux")
            .env("TMUX_TMPDIR", &tmux_dir)
            .args(["kill-session", "-t", &format!("={session}")])
            .status();
    }

    proxy.shutdown().await;
}
