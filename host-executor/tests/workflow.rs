//! Exercise the installed command surface with actual files and executable pins.
#![cfg(unix)]
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn call(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_safeyolo-host-executor"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn save(path: &Path, value: Value) {
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn standalone_preparation_keeps_saved_authority_activation_and_observation_distinct() {
    let root = std::env::temp_dir().join(format!(
        "host-workflow-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.canonicalize().unwrap();
    let case = root.join("case");
    assert_eq!(call(&["demo", "--directory", text(&case)])["snapshots"], 0);
    let package = root.join("package.json");
    let result = call(&[
        "starter",
        "--root",
        text(&case),
        "--service",
        if cfg!(target_os = "macos") {
            "user/501/com.example.demo"
        } else {
            "demo.service"
        },
        "--output",
        text(&package),
    ]);
    assert_eq!(result["permission_granted"], false);
    let document: Value = serde_json::from_slice(&fs::read(&package).unwrap()).unwrap();
    let actual = safeyolo_host_executor::revision(&document);
    assert_eq!(result["package_sha256"], actual);
    for name in [
        "service-start",
        "service-stop",
        "service-restart",
        "service-status",
        "bundle-metadata",
        "application-log",
        "system-log",
        "snapshot-list",
    ] {
        assert!(document["operations"][name].is_object(), "{name}");
    }
    let selection = root.join("selection.json");
    save(
        &selection,
        json!({"bundle-metadata":{"resources":["evidence:bundle-metadata"],"arguments":{"limit":[50]},"budgets":{"calls":20,"concurrent":1,"timeout_seconds":10,"output_bytes":65536}}}),
    );
    let scopes = root.join("scopes.json");
    call(&[
        "scopes",
        "--package",
        text(&package),
        "--selection",
        text(&selection),
        "--output",
        text(&scopes),
    ]);
    let keys = root.join("keys");
    fs::create_dir(&keys).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    let key = call(&["key-create", "--directory", text(&keys)]);
    assert_eq!(key["permission_granted"], false);
    assert_eq!(
        fs::metadata(keys.join("issuer-key.base64"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let issuer_settings = root.join("issuer-settings.json");
    let now = safeyolo_host_executor::now();
    save(
        &issuer_settings,
        json!({"issuer_id":"issuer","key_id":"key","public_key_file":keys.join("issuer-public.base64"),"grant_id":"grant",
        "principal":{"run":{"agent":"alice","agent_id":"ag-fixture","run_id":"1".repeat(32)},"task_id":"investigation"},
        "operations":scopes,"verbs":["discover","propose","invoke","job","output","cancel"],"not_before":now-1,"expires_at":now+600,
        "authority_valid_until":now+600,"assessment_revision":"operator-reviewed-inputs"}),
    );
    let issuers = root.join("issuers.json");
    assert_eq!(
        call(&[
            "prepare-issuer",
            "--settings",
            text(&issuer_settings),
            "--output",
            text(&issuers)
        ])["activated"],
        false
    );
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let certificate = call(&[
        "tls-create",
        "--name",
        "localhost",
        "--directory",
        text(&state),
    ]);
    assert_eq!(certificate["permission_granted"], false);
    let settings = root.join("settings.json");
    let native = if cfg!(target_os = "linux") {
        json!({"platform":"linux","bubblewrap":"/not-installed","bubblewrap_sha256":"a".repeat(64),"cgroup":"/not-delegated","executable_bytes":67108864})
    } else {
        json!({"platform":"macos","executable_bytes":67108864})
    };
    save(
        &settings,
        json!({"target_id":"case-target","package":package,"issuers":issuers,"ceiling":scopes,"native":native,
        "allowed_verbs":["discover","propose","invoke","job","output","cancel"],"max_authority_age_seconds":600,
        "connections":2,"connection_timeout_seconds":5,"ledger":{"jobs":100,"mutation_records":200,"output_bytes":1048576,"database_bytes":16777216,"request_bytes":131072},
        "https":{"listen":"127.0.0.1:0","certificate":state.join("target.pem"),"private_key":state.join("target-key.pem")}}),
    );
    let config = root.join("target.json");
    assert_eq!(
        call(&[
            "prepare",
            "--settings",
            text(&settings),
            "--output",
            text(&config)
        ])["activated"],
        false
    );
    let status = call(&["status", "--config", text(&config), "--state", text(&state)]);
    assert_eq!(status["running_target_observed"], false);
    #[cfg(target_os = "linux")]
    assert_eq!(
        status["configuration_valid"], false,
        "unavailable native delegation must remain explicit"
    );
    let again = Command::new(env!("CARGO_BIN_EXE_safeyolo-host-executor"))
        .args([
            "prepare",
            "--settings",
            text(&settings),
            "--output",
            text(&config),
        ])
        .output()
        .unwrap();
    assert!(
        !again.status.success(),
        "a preparation must not overwrite the selected target configuration"
    );
    assert!(!state.join("control.sock").exists());
    let observed = call(&[
        "inspect",
        "--root",
        text(&case.join("logs/application.jsonl")),
        "--kind",
        "content",
        "--limit",
        "12",
    ]);
    assert_eq!(observed["status"], "partial");
    assert_eq!(observed["limit_unit"], "bytes");
    fs::remove_dir_all(root).unwrap();
}
