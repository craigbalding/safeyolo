//! Native operator configuration and instance isolation at the installed CLI.

use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}
fn value(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn initialize(root: &Path) {
    let output = cli(root, &["init"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::create_dir(root.join("bin")).unwrap();
    symlink(env!("CARGO_BIN_EXE_safeyolo"), root.join("bin/safeyolo")).unwrap();
    symlink(
        env!("CARGO_BIN_EXE_safeyolo-proxy"),
        root.join("bin/safeyolo-proxy"),
    )
    .unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn dead_vz_handle_and_stale_socket_can_be_cleaned_without_signalling_a_live_pid() {
    use std::os::unix::net::UnixListener;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let directory = root.join("agents/marker");
    fs::create_dir_all(&directory).unwrap();
    fs::create_dir_all(root.join("data/vm-control")).unwrap();
    let socket = root.join("data/vm-control/marker.sock");
    drop(UnixListener::bind(&socket).unwrap());
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    fs::write(
        directory.join("runtime.json"),
        serde_json::to_vec(&serde_json::json!({
            "run_id":"0123456789abcdef0123456789abcdef",
            "backend_pid":child.id(), "backend_token":"unrelated-fixture"
        }))
        .unwrap(),
    )
    .unwrap();
    let live = value(cli(&root, &["agent", "status", "marker"]));
    let stop = cli(&root, &["agent", "stop", "marker"]);
    let survived = child.try_wait().unwrap().is_none();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(live["runtime_state"], "unknown");
    assert!(!stop.status.success());
    assert!(survived, "an unrelated live PID was signalled");
    assert!(socket.exists());
    let dead = value(cli(&root, &["agent", "status", "marker"]));
    assert_eq!(dead["runtime_state"], "stopped");
    fs::create_dir_all(root.join("data/shell-sockets")).unwrap();
    let shell_path = root.join("data/shell-sockets/marker.sock");
    let listener = UnixListener::bind(&shell_path).unwrap();
    assert!(!cli(&root, &["agent", "cleanup", "marker"]).status.success());
    assert!(socket.exists());
    assert!(directory.join("runtime.json").exists());
    drop(listener);
    let cleaned = value(cli(&root, &["agent", "cleanup", "marker"]));
    assert_eq!(cleaned["runtime_state"], "stopped");
    assert!(!socket.exists());
    assert!(!shell_path.exists());
    assert!(!directory.join("runtime.json").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn an_unrelated_live_pid_is_not_a_backend_or_signal_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            temp.path().to_str().unwrap(),
        ],
    ));
    let directory = root.join("agents/marker");
    fs::create_dir_all(directory.join("config-share")).unwrap();
    let run_id = "0123456789abcdef0123456789abcdef";
    fs::write(
        directory.join("config-share/host-launch-context.json"),
        serde_json::to_vec(&serde_json::json!({"generation":run_id})).unwrap(),
    )
    .unwrap();
    let mut unrelated = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = unrelated.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let started = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    fs::write(directory.join("runtime.json"), serde_json::to_vec(&serde_json::json!({
        "run_id":run_id,"backend_pid":pid,"backend_token":format!("linux:{}:{pid}:{started}",boot.trim())
    })).unwrap()).unwrap();
    let status = cli(&root, &["agent", "status", "marker"]);
    let stop = cli(&root, &["agent", "stop", "marker"]);
    let survived = unrelated.try_wait().unwrap().is_none();
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    let observed = value(status);
    assert_eq!(observed["runtime_state"], "unknown");
    assert!(
        observed["runtime_error"]
            .as_str()
            .unwrap()
            .contains("unrelated process")
    );
    assert!(!stop.status.success());
    assert!(survived, "the unrelated process was signalled");
}

#[test]
fn configuration_rejection_is_atomic_and_current_run_is_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let first = temp.path().join("first");
    let next = temp.path().join("next");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&next).unwrap();
    let created = value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            first.to_str().unwrap(),
            "--memory",
            "512",
            "--command",
            "printf marker",
        ],
    ));
    let id = created["configuration"]["id"].clone();
    let directory = root.join("agents/marker");
    fs::create_dir_all(&directory).unwrap();
    let runtime =
        br#"{"run_id":"0123456789abcdef0123456789abcdef","state":"running","workspace":"old"}"#;
    fs::write(directory.join("runtime.json"), runtime).unwrap();
    let policy = fs::read(root.join("policy.toml")).unwrap();
    for args in [
        vec!["--memory", "0"],
        vec!["--memory", "true"],
        vec!["--workspace", "/missing-817-workspace"],
        vec!["--mount", "/:/safeyolo"],
        vec!["--mount", "/://"],
        vec!["--mount", "/:/workspace:rw"],
    ] {
        let mut command = vec!["agent", "configure", "marker"];
        command.extend(args);
        assert!(!cli(&root, &command).status.success());
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
        assert_eq!(fs::read(directory.join("runtime.json")).unwrap(), runtime);
    }
    let changed = value(cli(
        &root,
        &[
            "agent",
            "configure",
            "marker",
            "--workspace",
            next.to_str().unwrap(),
            "--memory",
            "768",
        ],
    ));
    assert_eq!(changed["configuration"]["id"], id);
    assert_eq!(changed["configuration"]["folder"], next.to_str().unwrap());
    assert_eq!(
        changed["scope"],
        "next sandbox start; current run is unchanged"
    );
    assert_eq!(fs::read(directory.join("runtime.json")).unwrap(), runtime);
    let output = cli(&root, &["agent", "create", "unowned", "--workspace", "/"]);
    if unsafe { libc::geteuid() } != 0 {
        assert!(!output.status.success());
        let allowed = cli(
            &root,
            &[
                "agent",
                "create",
                "unowned",
                "--workspace",
                "/",
                "--dangerously-allow-unowned",
            ],
        );
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
    }
}

#[test]
fn host_scripts_cannot_execute_from_the_proposed_writable_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let script = workspace.join("hook");
    fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let policy = fs::read(root.join("policy.toml")).unwrap();
    for setting in ["--host-script", "--launcher"] {
        let output = cli(
            &root,
            &[
                "agent",
                "create",
                "unsafe",
                "--workspace",
                workspace.to_str().unwrap(),
                setting,
                script.to_str().unwrap(),
            ],
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("agent-writable"));
        assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
    }
}

#[test]
fn host_setup_keeps_the_explicit_config_and_failed_setup_does_not_publish() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let selected = root.join("selected.toml");
    fs::copy(root.join("config.toml"), &selected).unwrap();
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let hook = temp.path().join("setup-hook.sh");
    fs::write(&hook, b"#!/bin/sh\nprintf '%s\\n' \"$SAFEYOLO_NATIVE_CONFIG_PATH\" > \"$SAFEYOLO_AGENT_HOME/source\"\nexit 41\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let call = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--config")
            .arg(&selected)
            .args(args)
            .output()
            .unwrap()
    };
    value(call(&[
        "agent",
        "create",
        "marker",
        "--workspace",
        workspace.to_str().unwrap(),
    ]));
    let saved = fs::read(root.join("policy.toml")).unwrap();
    let failed = call(&[
        "agent",
        "configure",
        "marker",
        "--host-script",
        hook.to_str().unwrap(),
    ]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("saved configuration is unchanged"));
    assert_eq!(fs::read(root.join("policy.toml")).unwrap(), saved);
    assert_eq!(
        fs::read_to_string(root.join("agents/marker/home/source"))
            .unwrap()
            .trim(),
        selected.to_str().unwrap()
    );
}

#[test]
fn same_named_agents_have_separate_native_state_and_read_only_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    initialize(&a);
    initialize(&b);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    for root in [&a, &b] {
        value(cli(
            root,
            &[
                "agent",
                "create",
                "marker",
                "--workspace",
                workspace.to_str().unwrap(),
            ],
        ));
    }
    let a_id = value(cli(&a, &["agent", "status", "marker"]))["agent_id"].clone();
    let b_id = value(cli(&b, &["agent", "status", "marker"]))["agent_id"].clone();
    assert_ne!(a_id, b_id);
    let b_policy = fs::read(b.join("policy.toml")).unwrap();
    let b_instance = fs::read(b.join("data/instance_id")).unwrap();
    let dir = a.join("agents/marker");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("runtime.json"), b"corrupt").unwrap();
    let observed = value(cli(&a, &["agent", "status", "marker"]));
    assert_eq!(observed["runtime_state"], "unknown");
    let doctor = value(cli(&a, &["doctor"]));
    assert_eq!(doctor["agents"][0]["runtime_state"], "unknown");
    assert_eq!(fs::read(dir.join("runtime.json")).unwrap(), b"corrupt");
    assert_eq!(fs::read(b.join("policy.toml")).unwrap(), b_policy);
    assert_eq!(fs::read(b.join("data/instance_id")).unwrap(), b_instance);
    assert_eq!(
        value(cli(&b, &["agent", "status", "marker"]))["runtime_state"],
        "stopped"
    );
    assert!(!cli(&b, &["agent", "attach", "marker"]).status.success());
    assert!(!dir.join("launch.json").exists());
}

#[test]
fn help_uses_native_lifecycle_and_has_no_old_aliases() {
    let root = tempfile::tempdir().unwrap();
    initialize(root.path());
    let output = cli(root.path(), &["agent", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for required in [
        "create|configure",
        "start NAME",
        "attach",
        "diagnostics",
        "--foreground",
        "--sandbox-only",
    ] {
        assert!(help.contains(required));
    }
    for alias in [
        "agent up",
        "agent down",
        "agent check",
        "python -m",
        "hostPython",
    ] {
        assert!(!help.contains(alias));
    }
}

#[test]
fn fresh_proxy_uses_the_explicit_toml_and_keeps_the_other_instance_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    initialize(&a);
    initialize(&b);
    let selected = a.join("selected.toml");
    let source = fs::read_to_string(a.join("config.toml"))
        .unwrap()
        .replace("admin_port = 9090", "admin_port = 0");
    fs::write(&selected, source).unwrap();
    let a_default = fs::read(a.join("config.toml")).unwrap();
    let b_default = fs::read(b.join("config.toml")).unwrap();
    let selected_cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .env("SAFEYOLO_NATIVE_CONFIG_PATH", &selected)
            .env("SAFEYOLO_CONFIG_DIR", &b)
            .args(args)
            .output()
            .unwrap()
    };
    struct StopOnDrop<'a>(&'a Path);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            let _ = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
                .arg("--config")
                .arg(self.0)
                .arg("stop")
                .output();
        }
    }
    let _stop = StopOnDrop(&selected);
    value(selected_cli(&["start"]));
    assert!(a.join("data/ready.json").is_file());
    assert!(!b.join("data/ready.json").exists());
    assert!(fs::read_to_string(&selected).unwrap().contains("reload_id"));
    assert_eq!(fs::read(a.join("config.toml")).unwrap(), a_default);
    assert_eq!(fs::read(b.join("config.toml")).unwrap(), b_default);
    value(selected_cli(&[
        "agent",
        "create",
        "marker",
        "--workspace",
        temp.path().to_str().unwrap(),
    ]));
    assert_eq!(
        value(selected_cli(&["agent", "status", "marker"]))["name"],
        "marker"
    );
    assert!(
        !fs::read_to_string(b.join("policy.toml"))
            .unwrap()
            .contains("[agents.marker]")
    );
    value(selected_cli(&["stop"]));
    fs::write(&selected, "agent_launcher = false\n").unwrap();
    let failed = selected_cli(&["agent", "status", "marker"]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("config.toml settings"));
    assert_eq!(fs::read(a.join("config.toml")).unwrap(), a_default);
    assert_eq!(fs::read(b.join("config.toml")).unwrap(), b_default);
}

#[cfg(target_os = "linux")]
#[test]
fn native_tmux_launch_uses_current_environment_on_the_owned_socket() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("a");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let created = value(cli(
        &root,
        &[
            "agent",
            "create",
            "marker",
            "--workspace",
            workspace.to_str().unwrap(),
        ],
    ));
    let dir = root.join("agents/marker");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("current-launch.json"),
        serde_json::to_vec(&serde_json::json!({
            "name":"marker", "agent_id":created["configuration"]["id"], "launch_id":"launch-env",
            "launcher":{"kind":"tmux-window"}, "state":"starting", "tmux_session":"fixture"
        }))
        .unwrap(),
    )
    .unwrap();
    let socket = root.join("data/tmux.sock");
    struct OwnedServer<'a>(&'a Path);
    impl Drop for OwnedServer<'_> {
        fn drop(&mut self) {
            let _ = Command::new("tmux")
                .arg("-S")
                .arg(self.0)
                .arg("kill-server")
                .output();
        }
    }
    let _server = OwnedServer(&socket);
    let old = Command::new("tmux")
        .arg("-S")
        .arg(&socket)
        .env("SAFEYOLO_RUNSC_ROOT", "old-server-root")
        .env("SAFEYOLO_CONFIG_DIR", "old-server-config")
        .args(["new-session", "-d", "-s", "control", "sleep", "30"])
        .output()
        .unwrap();
    assert!(
        old.status.success(),
        "{}",
        String::from_utf8_lossy(&old.stderr)
    );
    // This harmless terminal fixture records selected nonsecret values. It
    // supplies no sandbox or coding-agent acceptance.
    fs::remove_file(root.join("bin/safeyolo")).unwrap();
    fs::write(root.join("bin/safeyolo"), b"#!/bin/sh\nprintf '%s\\n' \"$SAFEYOLO_CONFIG_DIR\" \"${SAFEYOLO_RUNSC_ROOT-unset}\" > \"$SAFEYOLO_CONFIG_DIR/environment-marker\"\nexec sleep 30\n").unwrap();
    fs::set_permissions(root.join("bin/safeyolo"), fs::Permissions::from_mode(0o755)).unwrap();
    let started = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(&root)
        .args(["agent", "launcher-session", "marker", "launch-env"])
        .env("SAFEYOLO_CONFIG_DIR", &root)
        .env_remove("SAFEYOLO_RUNSC_ROOT")
        .output()
        .unwrap();
    let target = value(started);
    assert_eq!(target["tmux_socket"], socket.to_str().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !root.join("environment-marker").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        fs::read_to_string(root.join("environment-marker")).unwrap(),
        format!("{}\nunset\n", root.display())
    );
    assert!(
        Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .args(["has-session", "-t", "=control"])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn custom_launchers_can_delegate_to_the_shipped_tmux_presets() {
    for (kind, preset) in [("script", "tmux-window"), ("manager", "tmux-pane")] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("instance");
        initialize(&root);
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let created = value(cli(
            &root,
            &[
                "agent",
                "create",
                "marker",
                "--workspace",
                workspace.to_str().unwrap(),
            ],
        ));
        let directory = root.join("agents/marker");
        fs::create_dir_all(&directory).unwrap();
        let record = serde_json::json!({
            "name":"marker", "agent_id":created["configuration"]["id"],
            "launch_id":"launch-custom", "launcher":{"kind":kind},
            "state":"starting", "tmux_session":"custom"
        });
        fs::write(
            directory.join("current-launch.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        // A terminal-only control records entry. The real preset and native
        // CLI arrange it; this fixture does not claim guest/runtime proof.
        fs::remove_file(root.join("bin/safeyolo")).unwrap();
        fs::write(
            root.join("bin/safeyolo"),
            b"#!/bin/sh\nprintf entered > \"$SAFEYOLO_CONFIG_DIR/custom-entry\"\nexec sleep 30\n",
        )
        .unwrap();
        fs::set_permissions(root.join("bin/safeyolo"), fs::Permissions::from_mode(0o755)).unwrap();
        let socket = root.join("data/tmux.sock");
        struct OwnedServer<'a>(&'a Path);
        impl Drop for OwnedServer<'_> {
            fn drop(&mut self) {
                let _ = Command::new("tmux")
                    .arg("-S")
                    .arg(self.0)
                    .arg("kill-server")
                    .output();
            }
        }
        let _server = OwnedServer(&socket);
        let invalid = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&root)
            .args(["agent", "launcher-session", "marker", "launch-custom"])
            .env("SAFEYOLO_TMUX_LAYOUT", "invalid")
            .output()
            .unwrap();
        assert!(!invalid.status.success());
        assert!(!root.join("custom-entry").exists());
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cli/src/safeyolo/launchers")
            .join(format!("{preset}.sh"));
        let started = Command::new("bash")
            .arg(script)
            .arg("launch")
            .env("SAFEYOLO_EXECUTABLE", env!("CARGO_BIN_EXE_safeyolo"))
            .env("SAFEYOLO_NATIVE_CONFIG_PATH", root.join("config.toml"))
            .env("SAFEYOLO_CONFIG_DIR", &root)
            .env("SAFEYOLO_AGENT_NAME", "marker")
            .env("SAFEYOLO_LAUNCH_ID", "launch-custom")
            .env("SAFEYOLO_TMUX_SESSION", "custom")
            .env("SAFEYOLO_TMUX_SOCKET", &socket)
            .output()
            .unwrap();
        assert!(
            started.status.success(),
            "{kind} / {preset}: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        let target: Value = serde_json::from_slice(&started.stdout).unwrap();
        assert_eq!(target["tmux_socket"], socket.to_str().unwrap());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !root.join("custom-entry").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(fs::read(root.join("custom-entry")).unwrap(), b"entered");
        let saved: Value =
            serde_json::from_slice(&fs::read(directory.join("current-launch.json")).unwrap())
                .unwrap();
        assert_eq!(
            saved, record,
            "delegation replaced the custom hook identity"
        );
    }
}
