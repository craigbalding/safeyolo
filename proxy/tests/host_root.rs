//! Creating an instance and running the proxy as root need an explicit override.
//! CI runs as an ordinary account; the root cases run where tests run as root.

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
