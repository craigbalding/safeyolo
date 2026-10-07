use super::*;

#[test]
fn empty_supervisor_stderr_is_not_a_role_lifecycle_failure() {
    for state in ["running", "stopped"] {
        for observation in [
            json!({"agent_state":state}),
            json!({"agent_state":state,"error":null}),
            json!({"agent_state":state,"error":""}),
        ] {
            assert!(
                role_lifecycle_error(&observation).is_none(),
                "{observation}"
            );
        }
    }
}

#[test]
fn role_lifecycle_failures_keep_their_original_diagnostic() {
    for error in [
        json!("supervisor failed to start"),
        json!(" "),
        json!({"message":"launcher failed"}),
        json!(false),
    ] {
        let observation = json!({"error":error});
        assert_eq!(role_lifecycle_error(&observation), Some(&error));
    }
}

fn fixture(root: &Path) -> PathBuf {
    fs::write(
        root.join("role.md"),
        "Role contract: repair the assigned fixture.\n",
    )
    .unwrap();
    let file = root.join("factory.toml");
    fs::write(
        &file,
        r#"schema="safeyolo.factory/v1"
name="fixture"
room="fixture-work"
[roles.coordinator]
agent="fixture-relay"
contract="role.md"
args=["--model","approved-model"]
[roles.owner]
agent="fixture-forge"
contract="role.md"
[roles.reviewer]
agent="fixture-lens"
contract="role.md"
[operator_input]
to="coordinator"
types=["ACTIVATE","RESUME"]
[[handoffs]]
request="TASK"
from="coordinator"
to="owner"
responses=["DONE","BLOCKED","FAILED"]
[[handoffs]]
request="REVIEW_READY"
from="owner"
to="reviewer"
responses=["READY","CHANGES_REQUIRED","BLOCKED"]
"#,
    )
    .unwrap();
    file
}
#[test]
fn approval_freezes_role_text_and_is_not_runtime_readiness() {
    let temp = tempfile::tempdir().unwrap();
    let file = fixture(temp.path());
    let snapshot = load_file(&file).unwrap();
    let path = approve(temp.path(), &snapshot).unwrap();
    assert!(!temp.path().join("agents").exists());
    fs::write(temp.path().join("role.md"), "New unapproved instructions").unwrap();
    let (loaded, loaded_path) = approved(temp.path(), "fixture").unwrap();
    assert_eq!(loaded_path, path);
    assert_eq!(loaded.id().unwrap(), snapshot.id().unwrap());
    assert!(
        loaded.roles["owner"]
            .contract_text
            .starts_with("Role contract:")
    );
    assert_ne!(
        load_file(&file).unwrap().id().unwrap(),
        loaded.id().unwrap()
    );
    let config = coord_setup::factory_config(
        &serde_json::to_value(loaded).unwrap(),
        "fixture-forge",
        "owner",
        "codex",
    )
    .unwrap();
    assert_eq!(config.factory.unwrap().snapshot_id, snapshot.id().unwrap());
}
#[test]
fn tampered_snapshot_and_path_names_fail_without_touching_state() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot = load_file(&fixture(temp.path())).unwrap();
    let path = approve(temp.path(), &snapshot).unwrap();
    let pointer = fs::read(temp.path().join("factories/fixture/approved")).unwrap();
    let mut payload = serde_json::to_value(&snapshot).unwrap();
    payload["roles"]["owner"]["contract_text"] = json!("unapproved");
    fs::write(&path, payload.to_string()).unwrap();
    assert!(approved(temp.path(), "fixture").is_err());
    assert!(approved(temp.path(), "../fixture").is_err());
    assert_eq!(
        fs::read(temp.path().join("factories/fixture/approved")).unwrap(),
        pointer
    );
}
#[test]
fn graph_rejects_unknown_ambiguous_and_unreachable_bindings() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot = load_file(&fixture(temp.path())).unwrap();
    let mut unknown = snapshot.clone();
    unknown.handoffs[0].source = "unknown".into();
    assert!(unknown.validate().is_err());
    let mut ambiguous = snapshot.clone();
    ambiguous.handoffs.push(ambiguous.handoffs[0].clone());
    assert!(ambiguous.validate().is_err());
    let mut unreachable = snapshot.clone();
    unreachable.handoffs.pop();
    assert!(unreachable.validate().is_err());
    let mut alias = snapshot.clone();
    alias.roles.get_mut("owner").unwrap().agent = "fixture-relay".into();
    assert!(alias.validate().is_err());
    let mut changed = snapshot.clone();
    changed.roles.get_mut("reviewer").unwrap().harness = "unknown".into();
    assert!(changed.validate().is_err());
    let mut invalid = snapshot.clone();
    invalid.name = "..".into();
    assert!(invalid.validate().is_err());
    let mut collision = snapshot.clone();
    collision.room = "fixture-forge-agent".into();
    assert!(collision.validate().is_err());
}
#[test]
fn preparation_checks_workspace_choices_before_mutating_roles() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot = load_file(&fixture(temp.path())).unwrap();
    assert!(preparation(&snapshot, &["--workspace".into(), "missing=/".into()]).is_err());
    assert!(
        preparation(
            &snapshot,
            &["--workspace".into(), "owner=missing-path".into()]
        )
        .is_err()
    );
    let valid = preparation(
        &snapshot,
        &[
            "--workspace".into(),
            format!("owner={}", temp.path().display()),
        ],
    )
    .unwrap();
    assert_eq!(
        valid.workspaces["owner"],
        temp.path().canonicalize().unwrap()
    );
    assert!(!temp.path().join("agents").exists());
}
#[test]
fn missing_room_permission_names_the_prerequisite_without_regranting() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("data")).unwrap();
    fs::write(temp.path().join("data/instance_id"), "fixture").unwrap();
    fs::write(temp.path().join("config.toml"), "data_dir=\"data\"\n").unwrap();
    crate::coord_rooms::bootstrap(temp.path()).unwrap();
    let db = temp.path().join("data/coord/v0.db");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute(
            "INSERT INTO rooms(room_id,name,created_at) VALUES('rm-one','fixture-work',1)",
            [],
        )
        .unwrap();
    for (kind, id, permissions) in [
        ("operator", "operator", "send,receive"),
        ("agent", "ag-fixture", "send"),
    ] {
        connection.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-one',?1,?2,?3,1)",rusqlite::params![kind,id,permissions]).unwrap();
    }
    let error = crate::coord_rooms::factory_access(temp.path(), "fixture-work", "ag-fixture")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("fixture-work") && error.contains("ag-fixture") && error.contains("receive"),
        "{error}"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT permissions FROM memberships WHERE principal_kind='agent'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "send"
    );
    connection
        .execute(
            "UPDATE memberships SET permissions='send,receive' WHERE principal_kind='agent'",
            [],
        )
        .unwrap();
    crate::coord_rooms::factory_access(temp.path(), "fixture-work", "ag-fixture").unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn guest_staging_copies_installed_skills_before_boot_and_preserves_failed_preparation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("instance");
    let workspace = temp.path().join("repository");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir_all(root.join("assets/guest")).unwrap();
    fs::create_dir_all(root.join("assets/skills/safeyolo")).unwrap();
    fs::create_dir_all(root.join("certs")).unwrap();
    fs::write(root.join("config.toml"), "data_dir='data'\n").unwrap();
    fs::write(
        root.join("certs/mitmproxy-ca-cert.pem"),
        "fixture public certificate",
    )
    .unwrap();
    fs::write(
        root.join("assets/skills/safeyolo/SKILL.md"),
        "Installed source fixture\n",
    )
    .unwrap();
    for name in [
        "guest-init",
        "guest-init-static",
        "guest-init-per-run",
        "guest-proxy-forwarder",
        "guest-shell-bridge",
        "guest-desktop",
    ] {
        fs::write(root.join("assets/guest").join(name), "#!/bin/sh\n").unwrap();
    }
    let mut header = [0u8; 20];
    header[..4].copy_from_slice(b"\x7fELF");
    fs::write(root.join("assets/guest/safeyolo-guest"), header).unwrap();
    host_platform::in_instance(root.clone(), async {
        let agent = host_agents::configure(
            "fixture",
            &[("folder".into(), workspace.to_str().unwrap().into())],
            true,
            None,
        )
        .await
        .unwrap();
        let error = host_boot::stage(&agent, "10.0.0.2", "fixture-run")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("installed rootfs tree is missing"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(root.join("agents/fixture/config-share/skills/safeyolo/SKILL.md"))
                .unwrap(),
            "Installed source fixture\n"
        );
        assert!(
            root.join("agents/fixture/config-share/host-launch-context.json")
                .is_file()
        );
        assert!(!root.join("agents/fixture/runtime.json").exists());
    })
    .await;
}
