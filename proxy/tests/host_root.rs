//! Creating an instance and running the proxy as root need an explicit override.
//! CI runs as an ordinary account; the root cases run where tests run as root.

use safeyolo_proxy::host_root::{ENVIRONMENT, FLAG};
use std::process::Command;

fn safeyolo(root: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--instance-dir")
        .arg(root)
        .args(extra)
        .env_remove("SAFEYOLO_DANGEROUSLY_ALLOW_ROOT")
        .output()
        .unwrap()
}

#[test]
fn global_override_preserves_literal_option_values_and_forwarded_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let literal_root = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .current_dir(directory.path())
        .args(["--instance-dir", FLAG, "init"])
        .env_remove(ENVIRONMENT)
        .output()
        .unwrap();
    if is_root() {
        assert!(!literal_root.status.success());
        assert!(String::from_utf8_lossy(&literal_root.stderr).contains("Refusing to create"));
        assert!(!directory.path().join(FLAG).exists());
    } else {
        assert!(literal_root.status.success(), "{literal_root:?}");
        assert!(directory.path().join(FLAG).join("config.toml").is_file());
    }

    // A literal context value and arguments after -- must not grant root access
    // or disappear before the command's own parser receives them.
    let output = safeyolo(
        directory.path(),
        &["test-context", "--run", FLAG, "--agent", "builder"],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(FLAG));
    let output = safeyolo(
        directory.path(),
        &["test-context", "--run", "--", "--agent", FLAG],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(FLAG));

    let root = directory.path().join("selected instance");
    assert!(safeyolo(&root, &[FLAG, "init"]).status.success());
    let configured = safeyolo(
        &root,
        &[
            FLAG,
            "agent",
            "create",
            "builder",
            "--workspace",
            directory.path().to_str().unwrap(),
            "--command",
            FLAG,
        ],
    );
    assert!(configured.status.success(), "{configured:?}");
    let policy = std::fs::read_to_string(root.join("policy.toml")).unwrap();
    assert!(policy.contains(FLAG));
}

fn snapshot(root: &std::path::Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            entries.push((path.clone(), None));
            entries.extend(snapshot(&path));
        } else {
            entries.push((path.clone(), Some(std::fs::read(path).unwrap())));
        }
    }
    entries.sort();
    entries
}

#[test]
fn root_start_paths_refuse_before_changing_saved_state() {
    if !is_root() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("selected instance");
    assert!(safeyolo(&root, &[FLAG, "init"]).status.success());
    let configured = safeyolo(
        &root,
        &[
            "agent",
            "create",
            "builder",
            "--workspace",
            directory.path().to_str().unwrap(),
        ],
    );
    assert!(configured.status.success(), "{configured:?}");
    let before = snapshot(&root);
    let workspace = directory.path().join("new demo workspace");
    for args in [
        vec!["start"],
        vec!["agent", "start", "builder"],
        vec!["agent", "start", "builder", "--", FLAG],
        vec!["agent", "start", "builder", "--foreground"],
        vec!["agent", "start", "builder", "--sandbox-only"],
        vec![
            "agent",
            "launch",
            "--name",
            "builder",
            "--authentication",
            "host-vault",
        ],
        vec!["agent", "launch", "--name", "new-agent"],
        vec![
            "demo",
            "--task",
            "tiny-web-app",
            "--workspace",
            workspace.to_str().unwrap(),
        ],
    ] {
        let output = safeyolo(&root, &args);
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?}");
        assert!(message.contains("as root."), "{args:?}: {message}");
        assert!(message.contains(ENVIRONMENT), "{message}");
        assert_eq!(snapshot(&root), before, "{args:?}");
        assert!(!workspace.exists());
    }
    for args in [
        vec!["status"],
        vec!["stop"],
        vec!["--help"],
        vec!["agent", "launch", "--help"],
        vec!["demo", "--help"],
    ] {
        let output = safeyolo(&root, &args);
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
}

#[test]
fn environment_override_is_explicit_and_flag_can_precede_instance_selection() {
    let directory = tempfile::tempdir().unwrap();
    for (index, value) in ["1", "0", "true"].into_iter().enumerate() {
        let root = directory.path().join(format!("environment-{index}"));
        let output = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--instance-dir")
            .arg(&root)
            .arg("init")
            .env(ENVIRONMENT, value)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            !is_root() || value == "1",
            "{output:?}"
        );
        assert_eq!(root.exists(), !is_root() || value == "1");
    }
    let root = directory.path().join("flag before selection");
    let output = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .args(["--json", FLAG, "--instance-dir"])
        .arg(&root)
        .args([FLAG, "--json", "init"])
        .env_remove(ENVIRONMENT)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(root.join("config.toml").is_file());
}

fn is_root() -> bool {
    // SAFETY: geteuid has no arguments and only reads the process identity.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn init_as_root_needs_the_override_and_changes_nothing_without_it() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("instance");
    let plain = safeyolo(&root, &["init"]);
    if !is_root() {
        assert!(plain.status.success(), "{plain:?}");
        return;
    }
    assert!(!plain.status.success());
    let message = String::from_utf8_lossy(&plain.stderr);
    assert!(
        message.contains("Refusing to create an instance as root"),
        "{message}"
    );
    assert!(message.contains("--dangerously-allow-root"), "{message}");
    assert!(!root.exists());
    let allowed = safeyolo(&root, &["--dangerously-allow-root", "init"]);
    assert!(allowed.status.success(), "{allowed:?}");
    assert!(root.join("config.toml").is_file());
}

#[test]
fn proxy_as_root_refuses_before_reading_configuration() {
    if !is_root() {
        return;
    }
    // The path does not exist: a refusal must come before any configuration read.
    let output = Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
        .args(["--config", "/nonexistent/config.toml"])
        .env_remove("SAFEYOLO_DANGEROUSLY_ALLOW_ROOT")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("Refusing to run the proxy as root"),
        "{message}"
    );
    for (flag, environment) in [(Some("--dangerously-allow-root"), None), (None, Some("1"))] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"));
        command
            .args(["--config", "/nonexistent/config.toml"])
            .args(flag);
        command.env_remove("SAFEYOLO_DANGEROUSLY_ALLOW_ROOT");
        if let Some(value) = environment {
            command.env("SAFEYOLO_DANGEROUSLY_ALLOW_ROOT", value);
        }
        let output = command.output().unwrap();
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            !message.contains("Refusing to run the proxy as root"),
            "{message}"
        );
    }
}
