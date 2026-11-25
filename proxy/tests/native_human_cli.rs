//! Ordinary operator discovery and output through the real native executable.

use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
};

fn executable() -> OsString {
    std::env::var_os("SAFEYOLO_NATIVE_CLI").unwrap_or_else(|| env!("CARGO_BIN_EXE_safeyolo").into())
}

fn cli(root: &Path, arguments: &[&str]) -> Output {
    Command::new(executable())
        .arg("--instance-dir")
        .arg(root)
        .args(arguments)
        .env("SAFEYOLO_CONFIG_DIR", root.join("conflicting selection"))
        .output()
        .unwrap()
}

fn stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn discovery_precedes_instance_access_and_does_not_create_state() {
    let scratch = tempfile::tempdir().unwrap();
    let absent = scratch.path().join("absent parent/instance");
    for arguments in [
        vec![],
        vec!["--help"],
        vec!["agent"],
        vec!["agent", "list", "--help"],
        vec!["agent", "launch", "--help"],
        vec!["agent", "publish", "--help"],
        vec!["policy"],
        vec!["coord"],
        vec!["tls", "--help"],
    ] {
        let output = stdout(cli(&absent, &arguments));
        assert!(!output.trim().is_empty());
        assert!(!absent.exists(), "help created state for {arguments:?}");
        assert!(
            output.lines().count() < 90,
            "help should be scoped: {arguments:?}"
        );
    }
    let overview = stdout(cli(&absent, &[]));
    for action in [
        "agent list",
        "agent launch",
        "status",
        "watch",
        "--instance-dir",
        "--json",
    ] {
        assert!(
            overview.contains(action),
            "missing discoverable action {action}"
        );
    }
    let retired = cli(&absent, &["--root", "/unselected", "status"]);
    assert!(!retired.status.success());
    assert!(!absent.exists());
}

#[test]
fn empty_inventory_and_redirected_status_are_human_and_json_is_explicit() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("selected instance");
    stdout(cli(&root, &["init"]));
    let inventory = stdout(cli(&root, &["agent", "list"]));
    assert!(inventory.contains("No agents configured"));
    assert!(inventory.contains("agent launch"));
    assert!(!inventory.trim_start().starts_with('{'));
    let report: Value =
        serde_json::from_str(&stdout(cli(&root, &["agent", "list", "--json"]))).unwrap();
    assert_eq!(report["root"], root.to_str().unwrap());
    assert_eq!(report["agents"], serde_json::json!([]));
    let status = stdout(cli(&root, &["status"]));
    assert!(status.contains(&*root.to_string_lossy()));
    assert!(status.contains("not verified running"));
    assert!(!status.contains("diagnostic_commands"));
    let status: Value = serde_json::from_str(&stdout(cli(&root, &["--json", "status"]))).unwrap();
    assert_eq!(status["proxy_state"], "unavailable");
}

#[test]
fn stopped_agent_recovery_keeps_the_executable_and_selected_config() {
    let scratch = tempfile::tempdir().unwrap();
    let a = scratch.path().join("old instance");
    let b = scratch.path().join("selected 'instance");
    let workspace = scratch.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    for root in [&a, &b] {
        stdout(cli(root, &["init"]));
        stdout(cli(
            root,
            &[
                "agent",
                "create",
                "work",
                "--workspace",
                workspace.to_str().unwrap(),
            ],
        ));
    }
    let selected_config = b.join("selected config.toml");
    fs::rename(b.join("config.toml"), &selected_config).unwrap();
    let old_policy = fs::read(a.join("policy.toml")).unwrap();
    let output = stdout(
        Command::new(executable())
            .arg("--config")
            .arg(&selected_config)
            .args(["agent", "status", "work"])
            .env("SAFEYOLO_NATIVE_CONFIG_PATH", a.join("config.toml"))
            .env("SAFEYOLO_CONFIG_DIR", &a)
            .env("SAFEYOLO_HOME", &a)
            .output()
            .unwrap(),
    );
    let resume = output.split("Resume: ").nth(1).unwrap().trim();
    assert!(resume.ends_with(" agent launch --name work"), "{output}");
    // Follow the emitted executable/config prefix through the actual shell,
    // inspecting the same agent before any launch or authentication effect.
    let inspect = resume.replace(" agent launch --name work", " agent status work --json");
    let selected: Value = serde_json::from_str(&stdout(
        Command::new("sh")
            .args(["-c", &inspect])
            .env("SAFEYOLO_NATIVE_CONFIG_PATH", a.join("config.toml"))
            .env("SAFEYOLO_CONFIG_DIR", &a)
            .env("SAFEYOLO_HOME", &a)
            .output()
            .unwrap(),
    ))
    .unwrap();
    let old: Value =
        serde_json::from_str(&stdout(cli(&a, &["agent", "status", "work", "--json"]))).unwrap();
    assert_ne!(selected["agent_id"], old["agent_id"]);
    assert_eq!(selected["runtime_state"], "stopped");
    assert_eq!(fs::read(a.join("policy.toml")).unwrap(), old_policy);
    assert!(!a.join("data/proxy-process.json").exists());
    assert!(!b.join("data/proxy-process.json").exists());
}

#[test]
fn doctor_explains_failed_prerequisites_and_counts_skips_without_starting() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("uninstalled instance");
    let output = cli(&root, &["doctor", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["checks"][0]["name"], "Configuration");
    assert_eq!(value["checks"][0]["status"], "fail");
    let checks = value["checks"].as_array().unwrap();
    for status in ["pass", "warn", "fail", "skip", "unknown"] {
        assert_eq!(
            value["counts"][status].as_u64().unwrap(),
            checks
                .iter()
                .filter(|check| check["status"] == status)
                .count() as u64
        );
    }
    assert!(
        checks
            .iter()
            .filter(|check| check["name"] != "Configuration")
            .all(|check| check["status"] == "skip")
    );
    assert!(!root.exists());
    let human = cli(&root, &["doctor"]);
    let output = String::from_utf8(human.stdout).unwrap();
    assert!(output.contains("FAIL") && output.contains("SKIP") && output.contains("failed"));
    assert!(!output.contains("\"checks\""));
}

#[test]
fn cooperative_umask_cannot_make_new_host_state_unsafe_and_existing_unsafe_state_is_refused() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("state");
    stdout(cli(&root, &["init"]));
    let command = |name: &str| {
        Command::new("bash")
            .args([
                "-c",
                "umask 002; exec \"$1\" --instance-dir \"$2\" agent configure \"$3\" --memory 8192",
                "probe",
            ])
            .arg(executable())
            .arg(&root)
            .arg(name)
            .output()
            .unwrap()
    };
    for _ in 0..2 {
        let output = command("new-agent");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("agent not found"), "{error}");
        assert_eq!(
            fs::metadata(root.join("agents/new-agent"))
                .unwrap()
                .permissions()
                .mode()
                & 0o022,
            0
        );
    }
    let unsafe_path = root.join("agents/unsafe-agent");
    fs::create_dir(&unsafe_path).unwrap();
    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o775)).unwrap();
    let output = command("unsafe-agent");
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("unsafe host state directory") && error.contains("0775"));
    assert_eq!(
        fs::metadata(&unsafe_path).unwrap().permissions().mode() & 0o777,
        0o775
    );
    symlink(&unsafe_path, root.join("agents/linked-agent")).unwrap();
    assert!(!command("linked-agent").status.success());
}

#[test]
fn tls_settings_preserve_other_configuration_and_report_activation() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("state");
    stdout(cli(&root, &["init"]));
    let before = fs::read_to_string(root.join("config.toml")).unwrap();
    let output = stdout(cli(
        &root,
        &["tls", "passthrough", "add", "EXAMPLE.COM:443"],
    ));
    assert!(output.contains("Restart the proxy"));
    let list = stdout(cli(&root, &["tls", "passthrough", "list"]));
    assert!(list.contains("example.com:443"));
    let after = fs::read_to_string(root.join("config.toml")).unwrap();
    assert!(after.starts_with(&before));
    stdout(cli(
        &root,
        &["tls", "passthrough", "remove", "example.com:443"],
    ));
    assert!(stdout(cli(&root, &["tls", "passthrough", "list"])).contains("No saved"));
    let invalid = cli(&root, &["tls", "upstream", "/missing-certificate"]);
    assert!(!invalid.status.success());
    assert!(!root.join("data/proxy-process.json").exists());
    let public = stdout(cli(&root, &["tls", "ca", "--pem"]));
    assert!(public.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(!public.contains("PRIVATE KEY"));
    let original = fs::read_to_string(root.join("config.toml")).unwrap();
    fs::rename(
        root.join("certs/mitmproxy-ca.pem"),
        root.join("certs/selected-ca.pem"),
    )
    .unwrap();
    fs::write(
        root.join("config.toml"),
        original.replace("certs/mitmproxy-ca.pem", "certs/selected-ca.pem"),
    )
    .unwrap();
    assert_eq!(stdout(cli(&root, &["tls", "ca", "--pem"])), public);
}

#[test]
fn saved_policy_remains_useful_when_proxy_is_down_and_storage_listing_creates_nothing() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("selected instance");
    stdout(cli(&root, &["init"]));
    let policy = stdout(cli(&root, &["policy", "show"]));
    assert!(policy.contains("saved_only") && policy.contains("api.openai.com"));
    let record: Value =
        serde_json::from_str(&stdout(cli(&root, &["policy", "show", "--json"]))).unwrap();
    assert!(record.get("effective").is_none());
    assert!(record["saved"].is_object());
    let credentials = stdout(cli(&root, &["credentials", "list"]));
    assert!(credentials.contains("storage is not configured"));
    assert!(!root.join("data/credentials.enc").exists());
}

#[test]
fn explicit_authentication_json_reads_state_without_entering_setup() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().join("selected instance");
    stdout(cli(&root, &["init"]));
    let scripts = root.join("assets/contrib");
    fs::create_dir_all(&scripts).unwrap();
    let setup = scripts.join("codex-host-setup.sh");
    fs::write(&setup, "#!/bin/sh\nexit 99\n").unwrap();
    fs::set_permissions(&setup, fs::Permissions::from_mode(0o755)).unwrap();
    let policy = root.join("policy.toml");
    let mut source = fs::read_to_string(&policy).unwrap();
    source.push_str(&format!("\n[agents.work]\nagent_id='ag-11111111111111111111111111111111'\nfolder='{}'\nhost_script='{}'\n",root.display(), setup.display()));
    fs::write(policy, source).unwrap();
    for arguments in [
        vec!["agent", "auth", "work", "--json"],
        vec!["--json", "agent", "auth", "work"],
    ] {
        let value: Value = serde_json::from_str(&stdout(cli(&root, &arguments))).unwrap();
        assert_eq!(value["agent"], "work");
        assert_eq!(value["provider_validity"], "unknown");
        assert_eq!(value["local_login"]["state"], "missing");
        assert!(value["next_action"].as_str().unwrap().contains("--config"));
        assert!(
            value["next_action"]
                .as_str()
                .unwrap()
                .contains(root.to_str().unwrap())
        );
        assert!(
            value["next_action"]
                .as_str()
                .unwrap()
                .ends_with("agent launch --name work")
        );
        assert!(
            value["recovery"]
                .as_str()
                .unwrap()
                .contains("inspect prior task effects")
        );
    }
    assert!(!root.join("data/credentials.enc").exists());
    assert!(!root.join("agents/work/home/.codex/auth.json").exists());
}
