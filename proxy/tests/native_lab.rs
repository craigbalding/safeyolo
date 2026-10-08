//! Lab ownership and failure behavior through the real native CLI.

use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .args(args)
        .env_remove("PYTHONPATH")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}
fn initialize(root: &Path) {
    let result = cli(root, &["init"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn agents(root: &Path) -> toml::Value {
    toml::from_str(&fs::read_to_string(root.join("policy.toml")).unwrap()).unwrap()
}

#[test]
fn help_retains_lab_factory_and_operator_coord() {
    let temp = tempfile::tempdir().unwrap();
    let result = cli(temp.path(), &["--help"]);
    assert!(result.status.success());
    let help = String::from_utf8(result.stdout).unwrap();
    for command in ["lab [--objective TEXT]", "factory check FILE", "coord send"] {
        assert!(help.contains(command), "missing {command}: {help}");
    }
    assert!(!temp.path().join("config.toml").exists());
}

#[test]
fn unrelated_agents_and_cancelled_creation_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("marker"), "peer").unwrap();
    assert!(
        cli(
            &root,
            &[
                "agent",
                "create",
                "peer",
                "--workspace",
                workspace.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
    let policy = fs::read(root.join("policy.toml")).unwrap();
    let result = cli(
        &root,
        &[
            "lab",
            "--agent",
            "peer",
            "--objective",
            "compare a request",
            "--yes",
        ],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("not owned"));
    assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
    let cancelled = cli(
        &root,
        &[
            "lab",
            "--workspace",
            workspace.to_str().unwrap(),
            "--objective",
            "compare a request",
        ],
    );
    assert!(!cancelled.status.success());
    assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
    assert_eq!(
        fs::read_to_string(workspace.join("marker")).unwrap(),
        "peer"
    );
    assert!(!root.join("labs/safeyolo-lab").exists());
}

#[test]
fn failed_preparation_retains_one_lab_and_truthful_stopped_status() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let result = cli(
        &root,
        &[
            "lab",
            "--agent",
            "experiment",
            "--workspace",
            workspace.to_str().unwrap(),
            "--objective",
            "compare $(literal) request",
            "--yes",
        ],
    );
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("Runtime: ready"));
    let before = agents(&root);
    let id = before["agents"]["experiment"]["agent_id"].as_str().unwrap();
    assert_eq!(before["agents"].as_table().unwrap().len(), 1);
    let command = fs::read(root.join("agents/experiment/home/.safeyolo-command")).unwrap();
    assert!(command.starts_with(b"#!/usr/bin/env bash"));
    // Missing checked guest assets must not create a second agent on retry.
    assert!(!cli(&root, &["lab"]).status.success());
    let after = agents(&root);
    assert_eq!(after["agents"]["experiment"]["agent_id"].as_str(), Some(id));
    assert_eq!(after["agents"].as_table().unwrap().len(), 1);
    let status = cli(&root, &["lab", "--status", "--json"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["lab"]["objective"], "compare $(literal) request");
    assert_eq!(status["runtime"]["runtime_state"], "stopped");
    assert!(status["guest"].is_null());
    let evidence = root.join("agents/experiment/home/.safeyolo/lab-evidence");
    fs::create_dir(&evidence).unwrap();
    fs::write(evidence.join("marker"), "retained").unwrap();
    let result = cli(&root, &["lab", "--teardown"]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("No live session was inspected"));
    assert_eq!(
        fs::read_to_string(evidence.join("marker")).unwrap(),
        "retained"
    );
    assert_eq!(agents(&root), after);
}

#[test]
fn missing_recovery_and_conflicting_modes_do_not_provision_anything() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    initialize(&root);
    let policy = fs::read(root.join("policy.toml")).unwrap();
    for args in [
        vec!["lab", "--recover"],
        vec!["lab", "--status", "--teardown"],
        vec!["lab", "--json"],
        vec!["lab", "--keep-agent"],
        vec![
            "lab",
            "--objective",
            "compare a request",
            "--workspace",
            temp.path().to_str().unwrap(),
            "--nested-assets",
            temp.path().join("missing-inputs").to_str().unwrap(),
            "--yes",
        ],
    ] {
        assert!(!cli(&root, &args).status.success());
    }
    assert_eq!(fs::read(root.join("policy.toml")).unwrap(), policy);
    assert!(!root.join("labs").exists());
    let result = cli(&root, &["lab", "--status", "--json"]);
    assert!(result.status.success());
    let status: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["managed"], false);
}
