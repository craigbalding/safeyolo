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
