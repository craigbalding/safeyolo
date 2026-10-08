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

#[path = "support/owned_run.rs"]
mod owned_run;
use owned_run::OwnedRun;

fn setup(root: &Path) -> Config {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir_all(root.join("agents/alice/config-share")).unwrap();
    fs::create_dir(root.join("agents/alice/home")).unwrap();
    fs::create_dir(root.join("data")).unwrap();
    fs::write(root.join("config.toml"), "audit_log_path='audit.jsonl'\n").unwrap();
    fs::write(root.join("token"), TOKEN).unwrap();
    fs::write(
        root.join("data/instance_id"),
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
        [ "$4" = "$FAKE_RUN_ID" ] || exit 2
        printf '{"id":"%s","status":"running"}\n' "$FAKE_RUN_ID"
        ;;
    kill)
        : > "$SAFEYOLO_CONFIG_DIR/stopped"
        /bin/rm -f "$SAFEYOLO_CONFIG_DIR/coding-agent-running"
        ;;
    exec)
        [ "$8" = "$FAKE_RUN_ID" ] || exit 2
        case "$*" in
            *"safeyolo-guest observe check"*)
                if [ -e "$SAFEYOLO_CONFIG_DIR/coding-agent-running" ]; then
                    printf 'running\n'
                else
                    printf 'stopped\n'
                fi
                ;;
            *)
                : > "$SAFEYOLO_CONFIG_DIR/coding-agent-running"
                while [ ! -e "$SAFEYOLO_CONFIG_DIR/stopped" ]; do /bin/sleep 0.1; done
                ;;
        esac
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
            root.join("data/instance_id"),
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

async fn start_tmux_agent_and_check_env(port: u16, root: &Path) {
    let mut run = OwnedRun::start(root);
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
    let launch: Value =
        serde_json::from_slice(&fs::read(root.join("agents/alice/current-launch.json")).unwrap())
            .unwrap();
    let runner = launch["runner_pid"].as_i64().unwrap();
    let environment = fs::read(format!("/proc/{runner}/environ")).unwrap();
    let expected_config = format!("SAFEYOLO_CONFIG_DIR={}", root.display());
    assert!(
        environment
            .split(|byte| *byte == 0)
            .any(|entry| entry == expected_config.as_bytes()),
        "agent child did not receive the current config directory"
    );
    assert!(
        !environment
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"SAFEYOLO_RUNSC_ROOT=")),
        "agent child retained the old runsc root"
    );
    let (code, stopped) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    assert_eq!(code, 200, "{stopped}");
    assert_eq!(stopped["sandbox_state"], "stopped");
    assert!(root.join("stopped").exists());
    run.assert_exited();
    assert!(!root.join("agents/alice/userns.pid").exists());
    assert!(!root.join("agents/alice/container.pid").exists());
}

struct TmuxServerGuard(std::path::PathBuf);

impl Drop for TmuxServerGuard {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/tmux")
            .arg("-S")
            .arg(&self.0)
            .env_remove("TMUX")
            .arg("kill-server")
            .output();
    }
}

#[tokio::test]
async fn admin_lists_starts_observes_and_stops_without_python() {
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let config = setup(root);
    let mut run = OwnedRun::start(root);
    let proxy = Proxy::start(config).await.unwrap();
    let ready: Value = serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;

    let (code, list) = admin(port, "GET", "/admin/agents").await;
    assert_eq!(code, 200);
    assert_eq!(list["agents"][0]["agent_id"], ID);
    assert_eq!(list["agents"][0]["sandbox_state"], "running");
    assert_eq!(list["agents"][0]["control_state"], "ready");
    assert_eq!(list["agents"][0]["exec"], true);
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
    let (code, reused) = admin(port, "POST", &format!("/admin/agents/{ID}/start")).await;
    assert_eq!(code, 200, "{reused}");
    assert_eq!(reused["launch_id"], started["launch_id"]);
    assert_eq!(reused["agent_state"], "starting");

    // Emulate the guest owner's acknowledgement of the native stop fence.
    let home = root.join("agents/alice/home");
    let acknowledgement = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !home.join(".safeyolo-command-supervisor.stop").exists() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let path = home.join(".safeyolo-command-supervisor.json");
        let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let fence: Value = serde_json::from_slice(
            &fs::read(home.join(".safeyolo-command-supervisor.stop")).unwrap(),
        )
        .unwrap();
        assert_eq!(fence["supervision_id"], state["supervision_id"]);
        state["state"] = "stopped".into();
        state["command_pid"] = Value::Null;
        state["command_start_token"] = Value::Null;
        let temporary = tempfile::NamedTempFile::new_in(&home).unwrap();
        serde_json::to_writer(temporary.as_file(), &state).unwrap();
        temporary.persist(path).unwrap();
    });
    let (code, stopped) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    acknowledgement.await.unwrap();
    assert_eq!(code, 200, "{stopped}");
    assert_eq!(stopped["sandbox_state"], "stopped");
    assert_eq!(stopped["agent_state"], "stopped");
    assert!(stopped["command_stop_warning"].is_null());
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
    run.assert_exited();
    assert!(!root.join("agents/alice/userns.pid").exists());
    assert!(!root.join("agents/alice/container.pid").exists());
    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert!(audit.contains("agent.started"));
    assert!(audit.contains("agent.stopped"));

    // Guest-owned supervisor state cannot turn a forged, correctly tokened
    // host PID into authority for the native proxy to signal that process.
    fs::remove_file(root.join("stopped")).unwrap();
    let mut forged_run = OwnedRun::start(root);
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
    let (code, stopped) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    assert_eq!(code, 200, "{stopped}");
    assert!(
        stopped["command_stop_warning"]
            .as_str()
            .unwrap()
            .contains("ownership is unverified")
    );
    assert!(
        unrelated.try_wait().unwrap().is_none(),
        "unrelated host process was signaled"
    );
    // The operator's stop still owns this backend. Untrusted guest command
    // state contributes a warning, never authority over the unrelated PID.
    assert_eq!(stopped["sandbox_state"], "stopped");
    forged_run.assert_exited();
    assert!(!root.join("agents/alice/userns.pid").exists());
    assert!(!root.join("agents/alice/container.pid").exists());
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    fs::remove_file(root.join("stopped")).unwrap();
    let hostile_run = OwnedRun::start(root);

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
    // Stop consumes the retained launch, not the rejected next-start setting.
    launch["launcher"] = json!({"kind":"script","script":script});
    fs::write(&launch_path, serde_json::to_vec(&launch).unwrap()).unwrap();
    let (code, rejected) = admin(port, "POST", &format!("/admin/agents/{ID}/stop")).await;
    assert_eq!(code, 500, "{rejected}");
    assert!(rejected.to_string().contains("agent-writable mount"));
    assert!(!root.join("ran-script").exists());
    drop(hostile_run);

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
            root.join("config.toml"),
            format!("[agent_launcher]\ntmux_session = \"{session}\"\n"),
        )
        .unwrap();
        let tmux_socket = root.join("data/tmux.sock");
        let _server = TmuxServerGuard(tmux_socket.clone());
        std::os::unix::fs::symlink("/usr/bin/tmux", root.join("bin/tmux")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/dirname", root.join("bin/dirname")).unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_safeyolo"), root.join("bin/safeyolo"))
            .unwrap();
        let launchers = root.join("assets/launchers");
        fs::create_dir_all(&launchers).unwrap();
        for name in ["tmux-window.sh", "tmux-pane.sh", "tmux-common.sh"] {
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../cli/src/safeyolo/launchers")
                    .join(name),
                launchers.join(name),
            )
            .unwrap();
        }
        let previous_runsc_root = std::env::var_os("SAFEYOLO_RUNSC_ROOT");
        let previous_tmux = std::env::var_os("TMUX");
        unsafe {
            std::env::remove_var("TMUX");
            std::env::remove_var("SAFEYOLO_RUNSC_ROOT");
        }
        // First launch starts a fresh server. The following launches reuse an
        // older server with stale settings and exercise both transfer routes.
        start_tmux_agent_and_check_env(port, root).await;
        let _ = Command::new("/usr/bin/tmux")
            .arg("-S")
            .arg(&tmux_socket)
            .arg("kill-server")
            .output();
        let stale = Command::new("/usr/bin/tmux")
            .arg("-S")
            .arg(&tmux_socket)
            .env("SAFEYOLO_CONFIG_DIR", "/old-instance")
            .env("SAFEYOLO_RUNSC_ROOT", "/old-runsc")
            .args(["new-session", "-d", "-s", &session, "/bin/sleep", "60"])
            .status()
            .unwrap();
        assert!(stale.success());
        for (name, expected) in [
            ("SAFEYOLO_CONFIG_DIR", "SAFEYOLO_CONFIG_DIR=/old-instance\n"),
            ("SAFEYOLO_RUNSC_ROOT", "SAFEYOLO_RUNSC_ROOT=/old-runsc\n"),
        ] {
            let server_env = Command::new("/usr/bin/tmux")
                .arg("-S")
                .arg(&tmux_socket)
                .args(["show-environment", "-g", name])
                .output()
                .unwrap();
            assert!(server_env.status.success());
            assert_eq!(server_env.stdout, expected.as_bytes());
        }
        let original_update = Command::new("/usr/bin/tmux")
            .arg("-S")
            .arg(&tmux_socket)
            .args(["show-options", "-gqv", "update-environment"])
            .output()
            .unwrap();
        assert!(original_update.status.success());
        for launcher in ["tmux-window", "tmux-pane"] {
            fs::remove_file(root.join("stopped")).unwrap();
            fs::remove_file(&launch_path).unwrap();
            fs::write(
                root.join("policy.toml"),
                format!(
                    "[agents.alice]\nagent_id = \"{ID}\"\nfolder = \"{}\"\nlauncher = \"{launcher}\"\n",
                    root.join("workspace").display()
                ),
            )
            .unwrap();
            start_tmux_agent_and_check_env(port, root).await;
            let restored_update = Command::new("/usr/bin/tmux")
                .arg("-S")
                .arg(&tmux_socket)
                .args(["show-options", "-gqv", "update-environment"])
                .output()
                .unwrap();
            assert!(restored_update.status.success());
            assert_eq!(restored_update.stdout, original_update.stdout);
            let sessions = Command::new("/usr/bin/tmux")
                .arg("-S")
                .arg(&tmux_socket)
                .arg("list-sessions")
                .output()
                .unwrap();
            assert!(sessions.status.success());
            assert!(!String::from_utf8_lossy(&sessions.stdout).contains("safeyolo-agent-"));
        }
        unsafe {
            if let Some(previous) = previous_runsc_root {
                std::env::set_var("SAFEYOLO_RUNSC_ROOT", previous);
            }
            if let Some(previous) = previous_tmux {
                std::env::set_var("TMUX", previous);
            }
        }
    }

    proxy.shutdown().await;
}
