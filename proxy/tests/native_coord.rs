//! Fresh native Coord ownership and real Agent API/NATS boundaries for #818.
//! Run with SAFEYOLO_COORD_NATS_BINARY pointing at the pinned local NATS binary.
use safeyolo_proxy::{Proxy, coord_rooms, coord_tools::Client, native_config};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "native_coord/inventory.rs"]
mod inventory;
#[path = "native_coord/signals.rs"]
mod signals;
#[path = "native_coord/stage0.rs"]
mod stage0;
#[path = "native_coord/work.rs"]
mod work;

struct NatsCleanup(PathBuf);
impl Drop for NatsCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .args(["coord", "stop"])
            .stdout(Stdio::null())
            .status();
    }
}

async fn coord_cli(root: &Path, arguments: &[&str]) -> std::process::Output {
    coord_cli_from(root, arguments, &std::env::current_dir().unwrap()).await
}

async fn coord_cli_from(
    root: &Path,
    arguments: &[&str],
    working_directory: &Path,
) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .current_dir(working_directory)
            .arg("--root")
            .arg(root)
            .arg("coord")
            .args(arguments)
            .env_remove("SAFEYOLO_NATS_TEST_INSTANCE")
            .env_remove("SAFEYOLO_NATS_TEST_PORTS")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn coord_json(root: &Path, arguments: &[&str]) -> Value {
    let output = coord_cli(root, arguments).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct RestoreNatsRecord(PathBuf, Vec<u8>);
impl Drop for RestoreNatsRecord {
    fn drop(&mut self) {
        fs::write(&self.0, &self.1).unwrap();
    }
}

fn host_command(root: &Path, arguments: &[&str]) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"));
    command
        .arg("--root")
        .arg(root)
        .args(arguments)
        .env("SAFEYOLO_NATS_TEST_INSTANCE", root)
        .env_remove("SAFEYOLO_NATS_TEST_PORTS")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command
}

async fn host_cli(root: &Path, arguments: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        host_command(root, arguments).output(),
    )
    .await
    .unwrap()
    .unwrap()
}

struct HostCleanup(PathBuf);
impl Drop for HostCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .arg("stop")
            .output();
    }
}

#[tokio::test]
async fn brief_input_requires_an_explicit_revision_and_exactly_one_source() {
    let temp = tempfile::Builder::new()
        .prefix("brief-input-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path().join("missing-instance");
    let invalid_file = temp.path().join("invalid.md");
    fs::write(&invalid_file, [0xff]).unwrap();
    for arguments in [
        vec!["brief", "set", "shared", "text"],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--expected-revision",
            "-1",
        ],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--expected-revision",
            "18446744073709551616",
        ],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--expected-revision",
            "one",
        ],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--expected-revision",
            "0",
            "--expected-revision",
            "0",
        ],
        vec!["brief", "set", "shared", "--expected-revision", "0"],
        vec!["brief", "set", "shared", " ", "--expected-revision", "0"],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--stdin",
            "--expected-revision",
            "0",
        ],
        vec![
            "brief",
            "set",
            "shared",
            "--file",
            invalid_file.to_str().unwrap(),
            "--expected-revision",
            "0",
        ],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--expected-revision",
            "0",
            "--to",
            "alice",
        ],
        vec![
            "brief",
            "set",
            "shared",
            "text",
            "--expected-revision",
            "0",
            "--since",
            "0",
        ],
    ] {
        let output = coord_cli(&root, &arguments).await;
        assert!(!output.status.success(), "accepted {arguments:?}");
        assert!(!root.exists(), "invalid input created state: {arguments:?}");
    }
    let help = coord_cli(&root, &["brief", "--help"]).await;
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--expected-revision"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("--operation-id"));
    assert!(!root.exists());
    assert!(host_cli(&root, &["init"]).await.status.success());
    coord_rooms::bootstrap(&root).unwrap();
    let db = rusqlite::Connection::open(root.join("data/coord/v0.db")).unwrap();
    db.execute(
        "INSERT INTO rooms(room_id,name,created_at) VALUES('rm-input','shared',1)",
        [],
    )
    .unwrap();
    // A real room and exact diagnostics distinguish parser refusal from an
    // incidental failure to open the missing instance used by the matrix above.
    for (suffix, diagnostic) in [
        (vec!["--operation-id"], "--operation-id requires a value"),
        (
            vec!["--operation-id", "one", "--operation-id", "two"],
            "duplicate --operation-id option",
        ),
        (vec!["--operation-id", " "], "operation ID must be nonempty"),
    ] {
        let mut arguments = vec!["brief", "set", "shared", "text", "--expected-revision", "0"];
        arguments.extend(suffix);
        let output = coord_cli(&root, &arguments).await;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic));
        assert_eq!(
            db.query_row("SELECT count(*) FROM coord_brief_revisions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM coord_operations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    // The retained limit counts encoded bytes rather than Unicode characters.
    let limit = "é".repeat(32 * 1024);
    let file = temp.path().join("limit.md");
    fs::write(&file, &limit).unwrap();
    let first = coord_json(
        &root,
        &[
            "brief",
            "set",
            "shared",
            "--file",
            file.to_str().unwrap(),
            "--expected-revision",
            "0",
        ],
    )
    .await;
    assert_eq!(first["revision"], 1);
    assert_eq!(first["attention_count"], 0);
    assert_eq!(
        coord_json(&root, &["brief", "show", "shared"]).await["markdown"],
        limit
    );
    fs::write(&file, format!("{limit}é")).unwrap();
    let too_large = coord_cli(
        &root,
        &[
            "brief",
            "set",
            "shared",
            "--file",
            file.to_str().unwrap(),
            "--expected-revision",
            "1",
        ],
    )
    .await;
    assert!(!too_large.status.success());
    assert!(String::from_utf8_lossy(&too_large.stderr).contains("65536 UTF-8 bytes"));
    assert_eq!(
        coord_json(&root, &["brief", "show", "shared"]).await["revision"],
        1
    );
    let missing = coord_cli(&root, &["brief", "show", "unknown"]).await;
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("does not exist"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn native_brief_commands_preserve_revision_authority_attention_and_doctor_identity() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    let temp = tempfile::Builder::new()
        .prefix("coord513-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n[[listeners]]\nagent_id='dave'\nsocket_path='dave.sock'\n").unwrap();
    fs::write(root.join("policy.toml"), "[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n[agents.dave]\nagent_id='ag-dddddddddddddddddddddddddddddddd'\n").unwrap();
    let _cleanup = NatsCleanup(root.into());
    let started = host_cli(
        root,
        &["coord", "start", "--binary", binary.to_str().unwrap()],
    )
    .await;
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let room = coord_json(root, &["room", "create", "shared"]).await;
    let other_room = coord_json(root, &["room", "create", "other"]).await;
    coord_json(root, &["grant", "shared", "alice"]).await;
    coord_json(root, &["grant", "shared", "bob", "receive"]).await;
    coord_json(root, &["grant", "shared", "carol", "receive"]).await;
    coord_json(root, &["grant", "shared", "carol", "send"]).await;
    coord_json(root, &["grant", "shared", "dave"]).await;
    coord_json(root, &["revoke", "shared", "dave"]).await;
    let absent = coord_json(root, &["brief", "show", "shared"]).await;
    assert_eq!(absent["state"], "none");
    assert_eq!(absent["revision"], 0);
    assert!(absent["markdown"].is_null() && absent["content_hash"].is_null());
    assert_eq!(absent["room_id"], room["room_id"]);

    // The ordinary doctor reader must report identity without exposing prose.
    fs::write(root.join("role.md"), "Fixture role contract.\n").unwrap();
    fs::write(
        root.join("factory.toml"),
        r#"schema='safeyolo.factory/v1'
name='brief-test'
room='shared'
[roles.coordinator]
agent='alice'
contract='role.md'
[roles.owner]
agent='bob'
contract='role.md'
[operator_input]
to='coordinator'
types=['ACTIVATE']
[[handoffs]]
request='TASK'
from='coordinator'
to='owner'
responses=['DONE','BLOCKED','FAILED']
"#,
    )
    .unwrap();
    let approved = host_cli(
        root,
        &[
            "factory",
            "approve",
            root.join("factory.toml").to_str().unwrap(),
            "--yes",
        ],
    )
    .await;
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    let doctor = |output: std::process::Output| -> Value {
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Standing context"));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["component"] == "room-brief")
            .unwrap()
            .clone()
    };
    let none = doctor(host_cli(root, &["factory", "doctor", "brief-test"]).await);
    assert_eq!(none["status"], "PASS");
    assert_eq!(none["observation"], json!({"state":"none"}));

    let db = rusqlite::Connection::open(root.join("data/coord/v0.db")).unwrap();
    let counts = || -> (i64, i64, i64, i64) {
        db.query_row("SELECT (SELECT count(*) FROM coord_brief_revisions), (SELECT count(*) FROM coord_attention_edges), (SELECT count(*) FROM coord_outbox), (SELECT count(*) FROM coord_operations)", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap()
    };
    // Room creation and grants already have immutable outcomes and audit rows.
    let initial = counts();
    let proxy = Proxy::start(native_config::read(&root.join("config.toml")).unwrap())
        .await
        .unwrap();
    let client = |name: &str| Client {
        socket: Some(root.join(format!("{name}.sock"))),
        token_file: root.join("data/agent_token"),
    };
    let alice = client("alice");
    let bob = client("bob");
    let waiting = bob.clone();
    let wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_attention",
                &json!({"since_sequence":0,"timeout_seconds":10}),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let markdown = "TASK target=https://example.test/context\r\n\nStanding context: π 🦀\n";
    let input = root.join("brief.md");
    fs::write(&input, markdown).unwrap();
    let first = coord_json(
        root,
        &[
            "brief",
            "set",
            "shared",
            "--file",
            input.to_str().unwrap(),
            "--expected-revision",
            "0",
        ],
    )
    .await;
    assert_eq!(first["revision"], 1);
    assert_eq!(first["attention_count"], 2);
    assert!(first.get("markdown").is_none());
    let expected_hash = ring::digest::digest(&ring::digest::SHA256, markdown.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(first["content_hash"], expected_hash);
    let present = coord_json(root, &["brief", "show", "shared"]).await;
    assert_eq!(present["state"], "present");
    assert_eq!(present["markdown"], markdown);
    assert_eq!(present["content_hash"], expected_hash);
    let page = tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(page["edges"].as_array().unwrap().len(), 1);
    let edge = &page["edges"][0];
    assert_eq!(edge["kind"], "brief_changed");
    assert_eq!(edge["revision_or_sequence"], 1);
    let object = bob
        .call(
            "read_attention",
            &json!({"attention_id":edge["attention_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(object["object"]["markdown"], markdown);
    assert_eq!(object["object"]["content_hash"], expected_hash);
    assert_eq!(
        alice
            .call("read_brief", &json!({"room_name":"shared"}))
            .await
            .unwrap()["markdown"],
        markdown
    );
    for name in ["carol", "dave"] {
        let denied = client(name);
        assert!(
            denied
                .call("read_brief", &json!({"room_name":"shared"}))
                .await
                .is_err()
        );
        assert!(
            denied
                .call(
                    "wait_for_attention",
                    &json!({"since_sequence":0,"timeout_seconds":0})
                )
                .await
                .unwrap()["edges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let actor: (String, String, String) = db
        .query_row(
            "SELECT actor_kind,actor_id,operation_id FROM coord_briefs WHERE room_id=?1",
            [room["room_id"].as_str().unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((&*actor.0, &*actor.1), ("operator", "operator"));
    let history_actor: (String,String,String) = db.query_row("SELECT actor_kind,actor_id,operation_id FROM coord_brief_revisions WHERE room_id=?1 AND revision=1",[room["room_id"].as_str().unwrap()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(actor, history_actor);
    assert_eq!(
        counts(),
        (initial.0 + 1, initial.1 + 2, initial.2 + 3, initial.3 + 1)
    );
    let payloads:Vec<String>=db.prepare("SELECT payload_json FROM coord_outbox UNION ALL SELECT outcome_json FROM coord_operations").unwrap().query_map([],|row|row.get(0)).unwrap().collect::<Result<_,_>>().unwrap();
    assert!(
        payloads
            .iter()
            .all(|payload| !payload.contains("Standing context"))
    );
    let identity = doctor(host_cli(root, &["factory", "doctor", "brief-test"]).await);
    assert_eq!(
        identity["observation"],
        json!({"state":"present","revision":1,"content_hash":expected_hash})
    );
    assert!(!identity.to_string().contains("Standing context"));

    let before = counts();
    let stale = coord_cli(
        root,
        &[
            "brief",
            "set",
            "shared",
            "stale",
            "--expected-revision",
            "0",
        ],
    )
    .await;
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("current revision is 1"));
    assert_eq!(counts(), before);
    assert_eq!(
        coord_json(root, &["brief", "show", "shared"]).await,
        present
    );
    for method in [hyper::Method::POST, hyper::Method::PUT] {
        let error = alice
            .request(
                method,
                "/api/coord/rooms/shared/brief",
                json!({"markdown":"forged","expected_revision":1,"actor_kind":"operator"}),
                Duration::from_secs(5),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("405"), "{error}");
    }
    assert_eq!(counts(), before);
    assert!(
        alice
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .unwrap()["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let other = coord_json(root, &["brief", "show", "other"]).await;
    assert_eq!(other["room_id"], other_room["room_id"]);
    assert_eq!(other["state"], "none");

    let mut piped = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .args([
            "coord",
            "brief",
            "set",
            "shared",
            "--stdin",
            "--expected-revision",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = piped.stdin.take().unwrap();
    stdin.write_all(b"updated context").await.unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(15), piped.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let second: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(second["revision"], 2);
    assert_eq!(
        bob.call(
            "read_attention",
            &json!({"attention_id":edge["attention_id"]})
        )
        .await
        .unwrap()["object"]["markdown"],
        markdown
    );
    // A downstream attention failure must roll back projection and history too.
    let before = counts();
    db.execute_batch("CREATE TRIGGER fail_brief_attention BEFORE INSERT ON coord_attention_edges BEGIN SELECT RAISE(ABORT,'fixture edge failure'); END;").unwrap();
    let failed = coord_cli(
        root,
        &[
            "brief",
            "set",
            "shared",
            "must roll back",
            "--expected-revision",
            "2",
        ],
    )
    .await;
    assert!(!failed.status.success());
    assert_eq!(counts(), before);
    assert_eq!(
        coord_json(root, &["brief", "show", "shared"]).await["markdown"],
        "updated context"
    );
    db.execute_batch("DROP TRIGGER fail_brief_attention;")
        .unwrap();
    let (a, b) = tokio::join!(
        coord_cli(
            root,
            &[
                "brief",
                "set",
                "shared",
                "race A",
                "--expected-revision",
                "2"
            ]
        ),
        coord_cli(
            root,
            &[
                "brief",
                "set",
                "shared",
                "race B",
                "--expected-revision",
                "2"
            ]
        ),
    );
    assert_ne!(a.status.success(), b.status.success());
    assert_eq!(
        coord_json(root, &["brief", "show", "shared"]).await["revision"],
        3
    );
    assert_eq!(
        counts(),
        (initial.0 + 3, initial.1 + 6, initial.2 + 9, initial.3 + 3)
    );

    proxy.shutdown().await;
    coord_json(root, &["stop"]).await;
    assert_eq!(
        coord_json(root, &["brief", "show", "shared"]).await["revision"],
        3
    );
    db.execute_batch("ALTER TABLE coord_briefs RENAME TO fixture_held_briefs;")
        .unwrap();
    let unavailable = doctor(host_cli(root, &["factory", "doctor", "brief-test"]).await);
    assert_eq!(unavailable["status"], "WARN");
    assert_eq!(unavailable["observation"], json!({"state":"unavailable"}));
    db.execute_batch("ALTER TABLE fixture_held_briefs RENAME TO coord_briefs;")
        .unwrap();
    assert_eq!(coord_json(root, &["status"]).await["state"], "stopped");
}

async fn prepare_host_services(root: &Path) {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::create_dir(root.join("bin")).unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_safeyolo-proxy"),
        root.join("bin/safeyolo-proxy"),
    )
    .unwrap();
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(root.join("policy.toml"), "[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[[permissions]]\naction='network:request'\nresource='*'\neffect='allow'\n").unwrap();
    // Acquire and verify the supplied pin once, then use only ordinary start.
    let seeded = host_cli(
        root,
        &["coord", "start", "--binary", binary.to_str().unwrap()],
    )
    .await;
    assert!(
        seeded.status.success(),
        "{}",
        String::from_utf8_lossy(&seeded.stderr)
    );
    coord_json(root, &["stop"]).await;
}

fn hold_nats_start(root: &Path) -> fs::File {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("data/coord/nats/runtime.lock"))
        .unwrap();
    lock.lock().unwrap();
    lock
}

async fn wait_for_file(path: &Path) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = fs::read(path)
                && let Ok(record) = serde_json::from_slice(&bytes)
            {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("startup did not publish {}", path.display()))
}

async fn check_proxy(root: &Path) {
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        "/admin/instance",
        hyper::Method::GET,
        Value::Null,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn cold_host_start_overlaps_services_and_serializes_reentry() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path();
    let _cleanup = HostCleanup(root.into());
    prepare_host_services(root).await;
    let lock = hold_nats_start(root);
    let mut first = host_command(root, &["start"]).spawn().unwrap();
    let proxy = wait_for_file(&root.join("data/proxy-process.json")).await;
    check_proxy(root).await;
    assert!(!root.join("data/coord/nats/process.json").exists());
    assert!(first.try_wait().unwrap().is_none());
    let instance_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("data/proxy-start.lock"))
        .unwrap();
    assert!(instance_lock.try_lock().is_err());
    // A second ordinary start must stay behind the first instance lock.
    let mut second = host_command(root, &["start"]).spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(second.try_wait().unwrap().is_none());
    drop(lock);
    for child in [first, second] {
        let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        wait_for_file(&root.join("data/proxy-process.json")).await,
        proxy
    );
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    assert!(host_cli(root, &["stop"]).await.status.success());
    fs::remove_file(root.join("data/proxy-process.json")).unwrap();

    // Delay the other service without changing the managed NATS executable.
    let retained = root.join("versions/initial/host/bin");
    fs::create_dir_all(&retained).unwrap();
    fs::rename(
        root.join("bin/safeyolo-proxy"),
        retained.join("safeyolo-proxy"),
    )
    .unwrap();
    let wrapper = root.join("bin/safeyolo-proxy");
    fs::write(&wrapper, "#!/bin/sh\nwhile [ ! -f \"$SAFEYOLO_CONFIG_DIR/release-proxy\" ]; do [ -d \"$SAFEYOLO_CONFIG_DIR\" ] || exit 1; sleep 0.01; done\nexec \"$SAFEYOLO_CONFIG_DIR/versions/initial/host/bin/safeyolo-proxy\" \"$@\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let mut starting = host_command(root, &["start"]).spawn().unwrap();
    wait_for_file(&root.join("data/coord/nats/process.json")).await;
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    assert!(!root.join("data/proxy-process.json").exists());
    assert!(starting.try_wait().unwrap().is_none());
    fs::write(root.join("release-proxy"), "").unwrap();
    let started = tokio::time::timeout(Duration::from_secs(15), starting.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    check_proxy(root).await;
    assert!(host_cli(root, &["stop"]).await.status.success());
    fs::remove_file(&wrapper).unwrap();
    fs::rename(retained.join("safeyolo-proxy"), &wrapper).unwrap();
    fs::remove_file(root.join("data/proxy-process.json")).unwrap();

    // Native fresh-process timing excludes fixture setup and pin acquisition.
    let start = std::time::Instant::now();
    let ((started, combined), (proxy, coord)) = tokio::join!(
        async {
            let output = host_cli(root, &["start"]).await;
            (output, start.elapsed())
        },
        async {
            let (proxy, coord) = tokio::join!(
                async {
                    wait_for_file(&root.join("data/proxy-process.json")).await;
                    check_proxy(root).await;
                    start.elapsed()
                },
                async {
                    wait_for_file(&root.join("data/coord/nats/process.json")).await;
                    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
                    start.elapsed()
                }
            );
            (proxy, coord)
        }
    );
    assert!(started.status.success());
    println!(
        "native fresh-process readiness with prepared NATS: proxy={proxy:?}, Coord={coord:?}, combined caller={combined:?}; observations include 5ms polling and health checks"
    );
    let proxy = fs::read(root.join("data/proxy-process.json")).unwrap();
    let nats = coord_json(root, &["status"]).await["process"].clone();
    let reuse_start = std::time::Instant::now();
    assert!(host_cli(root, &["start"]).await.status.success());
    println!(
        "native healthy service reuse caller: {:?}",
        reuse_start.elapsed()
    );
    assert_eq!(
        fs::read(root.join("data/proxy-process.json")).unwrap(),
        proxy
    );
    assert_eq!(coord_json(root, &["status"]).await["process"], nats);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn cold_host_start_rejects_proxy_exit_while_coord_is_pending() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path();
    let _cleanup = HostCleanup(root.into());
    prepare_host_services(root).await;
    let lock = hold_nats_start(root);
    let mut starting = host_command(root, &["start"]).spawn().unwrap();
    let proxy = wait_for_file(&root.join("data/proxy-process.json")).await;
    wait_for_file(&root.join("data/ready.json")).await;
    check_proxy(root).await;
    // Let the proxy branch consume readiness while Coord remains blocked.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let pid = i32::try_from(proxy["pid"].as_i64().unwrap()).unwrap();
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = host_cli(root, &["status"]).await;
            assert!(status.status.success());
            let status: Value = serde_json::from_slice(&status.stdout).unwrap();
            if status["proxy_state"] == "unavailable" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(starting.try_wait().unwrap().is_none());
    assert!(!root.join("data/coord/nats/process.json").exists());
    let instance_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("data/proxy-start.lock"))
        .unwrap();
    assert!(instance_lock.try_lock().is_err());
    drop(lock);
    let failed = tokio::time::timeout(Duration::from_secs(15), starting.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !failed.status.success(),
        "start reported success after the owned proxy exited: {}",
        String::from_utf8_lossy(&failed.stdout)
    );
    assert!(String::from_utf8_lossy(&failed.stderr).contains("proxy exited during startup"));
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("running"));
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    assert!(host_cli(root, &["stop"]).await.status.success());
    assert_eq!(coord_json(root, &["status"]).await["state"], "stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn cold_host_start_keeps_failures_separate_and_resumes_after_cancellation() {
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = temp.path();
    let _cleanup = HostCleanup(root.into());
    prepare_host_services(root).await;
    {
        let path = root.join("data/coord/nats/creds");
        let _restore = RestoreNatsRecord(path.clone(), fs::read(&path).unwrap());
        fs::write(&path, "").unwrap();
        let started = host_cli(root, &["start"]).await;
        assert!(started.status.success());
        let diagnostics = String::from_utf8_lossy(&started.stderr);
        assert!(diagnostics.contains("Coord unavailable: NATS credential file is empty"));
        assert!(diagnostics.contains("run coord status"));
        assert!(!diagnostics.contains("Coord ready") && !diagnostics.contains("Coord restored"));
        check_proxy(root).await;
        assert_eq!(coord_json(root, &["status"]).await["state"], "stopped");
    }
    assert!(host_cli(root, &["stop"]).await.status.success());
    fs::remove_file(root.join("data/proxy-process.json")).unwrap();
    let proxy = root.join("bin/safeyolo-proxy");
    fs::remove_file(&proxy).unwrap();
    let lock = hold_nats_start(root);
    let mut failed = host_command(root, &["start"]).spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        failed.try_wait().unwrap().is_none(),
        "proxy failure cancelled the Coord attempt"
    );
    drop(lock);
    let failed = failed.wait_with_output().await.unwrap();
    assert!(!failed.status.success());
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_safeyolo-proxy"), &proxy).unwrap();
    assert!(host_cli(root, &["stop"]).await.status.success());

    // Cancellation while NATS waits for its lock must not detach its startup.
    let lock = hold_nats_start(root);
    let mut cancelled = host_command(root, &["start"]).spawn().unwrap();
    let record = wait_for_file(&root.join("data/proxy-process.json")).await;
    check_proxy(root).await;
    cancelled.kill().await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!root.join("data/coord/nats/process.json").exists());
    assert!(host_cli(root, &["start"]).await.status.success());
    assert_eq!(
        wait_for_file(&root.join("data/proxy-process.json")).await,
        record
    );
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");

    // Exercise the unchanged real proxy-readiness timeout and owned child kill.
    assert!(host_cli(root, &["stop"]).await.status.success());
    fs::remove_file(&proxy).unwrap();
    fs::write(&proxy, "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$SAFEYOLO_CONFIG_DIR/timed-out-pid\"\nexec sleep 30\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&proxy, fs::Permissions::from_mode(0o700)).unwrap();
    let failed = tokio::time::timeout(
        Duration::from_secs(20),
        host_command(root, &["start"]).output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stderr)
            .contains("proxy did not publish readiness within fifteen seconds")
    );
    let pid: i32 = fs::read_to_string(root.join("timed-out-pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "timed-out proxy child is still alive"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    let nats = coord_json(root, &["status"]).await;
    assert_eq!(nats["state"], "running");
    fs::remove_file(&proxy).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_safeyolo-proxy"), &proxy).unwrap();
    assert!(host_cli(root, &["start"]).await.status.success());
    check_proxy(root).await;
    assert_eq!(
        coord_json(root, &["status"]).await["process"],
        nats["process"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn repeated_host_start_recovers_coord_without_replacing_the_proxy_or_state() {
    let temp = tempfile::Builder::new()
        .prefix("coord509-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    let _nats_cleanup = NatsCleanup(root.into());
    let _host_cleanup = HostCleanup(root.into());
    prepare_host_services(root).await;
    let started = host_cli(root, &["start"]).await;
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&started.stdout).unwrap()["proxy_state"],
        "running"
    );
    let proxy_path = root.join("data/proxy-process.json");
    let proxy_record = fs::read(&proxy_path).unwrap();
    let nats_path = root.join("data/coord/nats/process.json");
    let first_nats = coord_json(root, &["status"]).await["process"].clone();
    let room = coord_json(root, &["room", "create", "shared"]).await;
    for name in ["alice", "bob"] {
        coord_json(root, &["grant", "shared", name]).await;
    }
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
    };
    let bob = Client {
        socket: Some(root.join("bob.sock")),
        ..alice.clone()
    };
    let mut joined = alice
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(joined["room_id"], room["room_id"]);
    // The observation timestamp changes; the durable room and member state must not.
    joined["state"]
        .as_object_mut()
        .unwrap()
        .remove("generated_at");
    alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"before-recovery","notify":["bob"]}),
        )
        .await
        .unwrap();
    let mut history = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let attention = bob
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    let attention_id = attention["edges"][0]["attention_id"].as_str().unwrap();
    let object = bob
        .call("read_attention", &json!({"attention_id":attention_id}))
        .await
        .unwrap();
    assert_eq!(object["object"]["body"], "before-recovery");
    safeyolo_proxy::credentials::open(&root.join("data"))
        .unwrap()
        .store(safeyolo_proxy::credentials::Credential::new(
            "retained",
            "api_key",
            safeyolo_proxy::credentials::Secret::new("fixture-secret"),
        ))
        .unwrap();
    let credential_paths = [
        "data/instance_id",
        "data/admin_token",
        "data/agent_token",
        "data/credentials.key",
        "data/credentials.enc",
        "data/coord/instance_id",
        "data/coord/nats/creds",
    ];
    let credentials: Vec<_> = credential_paths
        .iter()
        .map(|path| fs::read(root.join(path)).unwrap())
        .collect();
    let (port, origin_task) = origin().await;
    traffic(&alice, port).await;
    for _ in 0..2 {
        let healthy = host_cli(root, &["start"]).await;
        assert!(healthy.status.success());
        assert!(
            String::from_utf8_lossy(&healthy.stderr)
                .contains("Coord ready: existing managed NATS is healthy")
        );
        assert_eq!(fs::read(&proxy_path).unwrap(), proxy_record);
        assert_eq!(coord_json(root, &["status"]).await["process"], first_nats);
    }
    // Stop the dependency independently of the healthy proxy, twice.
    for _ in 0..2 {
        coord_json(root, &["stop"]).await;
        let repaired = host_cli(root, &["start"]).await;
        assert!(
            repaired.status.success(),
            "{}",
            String::from_utf8_lossy(&repaired.stderr)
        );
        assert!(
            String::from_utf8_lossy(&repaired.stderr)
                .contains("Coord restored: managed NATS is ready")
        );
        assert_eq!(fs::read(&proxy_path).unwrap(), proxy_record);
        let status = coord_json(root, &["status"]).await;
        assert_eq!(status["state"], "running");
        assert_ne!(status["process"], first_nats);
        let mut rejoined = alice
            .call("join_room", &json!({"room_name":"shared"}))
            .await
            .unwrap();
        rejoined["state"]
            .as_object_mut()
            .unwrap()
            .remove("generated_at");
        assert_eq!(rejoined, joined);
        assert_eq!(
            alice
                .call("read_room", &json!({"room_name":"shared"}))
                .await
                .unwrap(),
            history
        );
        assert_eq!(
            bob.call(
                "wait_for_attention",
                &json!({"since_sequence":0,"timeout_seconds":0})
            )
            .await
            .unwrap(),
            attention
        );
        assert_eq!(
            bob.call("read_attention", &json!({"attention_id":attention_id}))
                .await
                .unwrap(),
            object
        );
        for (path, saved) in credential_paths.iter().zip(&credentials) {
            assert!(
                fs::read(root.join(path)).unwrap() == *saved,
                "{path} changed"
            );
        }
        traffic(&alice, port).await;
    }
    let fresh = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"after-recovery"}),
        )
        .await
        .unwrap();
    assert!(fresh["sequence"].as_u64().unwrap() > history["next_cursor"].as_u64().unwrap());
    let retained = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(retained["messages"][0], history["messages"][0]);
    assert_eq!(retained["messages"][1]["body"], "after-recovery");
    history = retained;
    // An unusable prerequisite must not turn proxy health into Coord success.
    coord_json(root, &["stop"]).await;
    {
        let path = root.join("data/coord/nats/creds");
        let _restore = RestoreNatsRecord(path.clone(), fs::read(&path).unwrap());
        fs::write(&path, "").unwrap();
        for _ in 0..2 {
            let failed = host_cli(root, &["start"]).await;
            assert!(failed.status.success());
            let diagnostics = String::from_utf8_lossy(&failed.stderr);
            assert!(
                diagnostics.contains("Coord unavailable: NATS credential file is empty"),
                "{diagnostics}"
            );
            assert!(diagnostics.contains("run coord status"));
            assert!(
                !diagnostics.contains("Coord ready") && !diagnostics.contains("Coord restored")
            );
            assert_eq!(fs::read(&proxy_path).unwrap(), proxy_record);
            assert_eq!(coord_json(root, &["status"]).await["state"], "stopped");
            let error = alice
                .call("send", &json!({"room_name":"shared","body":"unavailable"}))
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("unavailable"), "{error}");
            traffic(&alice, port).await;
        }
    }
    assert!(host_cli(root, &["start"]).await.status.success());
    let verified_nats = coord_json(root, &["status"]).await["process"].clone();
    {
        let _restore = RestoreNatsRecord(nats_path.clone(), fs::read(&nats_path).unwrap());
        let mut unverified = verified_nats.clone();
        unverified["server_name"] = "unverified-owner".into();
        let bytes = serde_json::to_vec(&unverified).unwrap();
        fs::write(&nats_path, &bytes).unwrap();
        let refused = host_cli(root, &["start"]).await;
        assert!(refused.status.success());
        let diagnostics = String::from_utf8_lossy(&refused.stderr);
        assert!(
            diagnostics.contains("Coord unavailable")
                && diagnostics.contains("ownership is unverified"),
            "{diagnostics}"
        );
        assert_eq!(fs::read(&nats_path).unwrap(), bytes);
        assert_eq!(coord_json(root, &["status"]).await["state"], "unknown");
        assert_eq!(fs::read(&proxy_path).unwrap(), proxy_record);
        traffic(&alice, port).await;
    }
    assert_eq!(
        coord_json(root, &["status"]).await["process"],
        verified_nats
    );
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    assert!(host_cli(root, &["stop"]).await.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&host_cli(root, &["status"]).await.stdout).unwrap()["proxy_state"],
        "unavailable"
    );
    assert!(host_cli(root, &["start"]).await.status.success());
    assert_ne!(fs::read(&proxy_path).unwrap(), proxy_record);
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    assert_eq!(
        alice
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .unwrap(),
        history
    );
    let final_nats = coord_json(root, &["status"]).await["process"].clone();
    assert!(host_cli(root, &["stop"]).await.status.success());
    assert_eq!(coord_json(root, &["status"]).await["state"], "stopped");
    for key in ["client_port", "monitor_port"] {
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", final_nats[key].as_u64().unwrap() as u16))
                .await
                .is_err()
        );
    }
    assert!(!root.join("alice.sock").exists());
    assert!(!root.join("bob.sock").exists());
    origin_task.abort();
    println!(
        "ordinary native start: healthy reuse, repeated NATS recovery, retained history/identity/credentials/membership/attention, failed recovery, live unverified ownership, full startup and owned cleanup observed"
    );
}

#[tokio::test]
async fn malformed_listener_options_fail_before_creating_coord_state() {
    let parent = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = parent.path().join("absent");
    for arguments in [
        vec!["start", "--client-port"],
        vec!["start", "--monitor-port", "0"],
        vec!["start", "--client-port", "-1"],
        vec!["start", "--client-port", "65536"],
        vec!["start", "--monitor-port", "text"],
        vec!["start", "--monitor-port", "1.5"],
        vec!["start", "--client-port", "4222", "--client-port", "4223"],
        vec!["start", "--client-port", "65535", "--monitor-port", "65535"],
        vec!["start", "--binary"],
        vec!["start", "--unknown", "4222"],
    ] {
        let output = coord_cli(&root, &arguments).await;
        assert!(!output.status.success(), "accepted {arguments:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("port") || error.contains("--binary") || error.contains("--unknown"),
            "{error}"
        );
        assert!(
            !root.exists(),
            "invalid input created state for {arguments:?}"
        );
    }
    let help = coord_cli(&root, &["--help"]).await;
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    for token in [
        "--client-port",
        "--monitor-port",
        "4222/8222",
        "SAFEYOLO_NATS_TEST_INSTANCE",
    ] {
        assert!(help.contains(token), "{help}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn explicit_listener_ports_isolate_instances_and_refuse_conflicts() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    let binary = binary.to_str().unwrap();
    let parent = tempfile::Builder::new()
        .prefix("coord817-ports-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let make_root = |name: &str, agent_id: &str| {
        let root = parent.path().join(name);
        fs::create_dir_all(root.join("data")).unwrap();
        fs::create_dir(root.join("builtin-services")).unwrap();
        fs::write(root.join("data/instance_id"), format!("si-817-{name}")).unwrap();
        fs::write(root.join("data/admin_token"), "fixture-operator-token").unwrap();
        fs::write(root.join("data/agent_token"), "fixture-agent-token").unwrap();
        fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n").unwrap();
        fs::write(
            root.join("policy.toml"),
            format!("[controls.network]\nenabled=false\n[agents.alice]\nagent_id='{agent_id}'\n"),
        )
        .unwrap();
        fs::create_dir(root.join("workspace")).unwrap();
        fs::write(root.join("workspace/marker"), name).unwrap();
        root
    };
    let a = make_root("a", "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let b = make_root("b", "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let a_link = parent.path().join("a-link");
    std::os::unix::fs::symlink(&a, &a_link).unwrap();
    let a_aliases = [
        a.strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .to_owned(),
        a.join("../a"),
        a_link,
    ];
    let c = make_root("c", "ag-cccccccccccccccccccccccccccccccc");
    let default_root = make_root("defaults", "ag-dddddddddddddddddddddddddddddddd");
    let reservations: Vec<_> = (0..6)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<_> = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().port().to_string())
        .collect();
    drop(reservations);
    let _a_cleanup = NatsCleanup(a.clone());
    let _b_cleanup = NatsCleanup(b.clone());
    let _c_cleanup = NatsCleanup(c.clone());
    let _default_cleanup = NatsCleanup(default_root.clone());
    let start_a = [
        "start",
        "--binary",
        binary,
        "--client-port",
        &ports[0],
        "--monitor-port",
        &ports[1],
    ];
    let start_b = [
        "start",
        "--monitor-port",
        &ports[3],
        "--client-port",
        &ports[2],
        "--binary",
        binary,
    ];
    let a_process = coord_json(&a, &start_a).await;
    let b_process = coord_json(&b, &start_b).await;
    assert_eq!(
        a_process["client_port"].as_u64().unwrap().to_string(),
        ports[0]
    );
    assert_eq!(
        a_process["monitor_port"].as_u64().unwrap().to_string(),
        ports[1]
    );
    assert_eq!(
        b_process["client_port"].as_u64().unwrap().to_string(),
        ports[2]
    );
    assert_eq!(
        b_process["monitor_port"].as_u64().unwrap().to_string(),
        ports[3]
    );
    assert_ne!(a_process["pid"], b_process["pid"]);
    assert_ne!(a_process["server_name"], b_process["server_name"]);
    assert!(!a.join("data/coord/nats/test-endpoints.json").exists());
    assert!(!b.join("data/coord/nats/test-endpoints.json").exists());
    for alias in &a_aliases {
        assert_eq!(coord_json(alias, &["status"]).await["state"], "running");
        assert_eq!(coord_json(alias, &start_a).await, a_process);
    }
    let a_record_path = a.join("data/coord/nats/process.json");
    let a_record = fs::read(&a_record_path).unwrap();
    let a_config = fs::read(a.join("data/coord/nats/server.conf")).unwrap();
    let a_credential = fs::read(a.join("data/coord/nats/creds")).unwrap();
    let b_files = [
        "config.toml",
        "policy.toml",
        "workspace/marker",
        "data/coord/nats/process.json",
        "data/coord/nats/server.conf",
        "data/coord/nats/creds",
    ];
    let b_before: Vec<_> = b_files
        .iter()
        .map(|path| fs::read(b.join(path)).unwrap())
        .collect();
    let a_room = coord_json(&a, &["room", "create", "shared"]).await;
    let b_room = coord_json(&b, &["room", "create", "shared"]).await;
    assert_ne!(a_room["room_id"], b_room["room_id"]);
    coord_json(&a, &["grant", "shared", "alice"]).await;
    coord_json(&b, &["grant", "shared", "alice"]).await;
    let a_proxy = Proxy::start(native_config::read(&a.join("config.toml")).unwrap())
        .await
        .unwrap();
    let b_proxy = Proxy::start(native_config::read(&b.join("config.toml")).unwrap())
        .await
        .unwrap();
    let client = |root: &Path| Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
    };
    let a_client = client(&a);
    let b_client = client(&b);
    let a_sent = a_client
        .call("send", &json!({"room_name":"shared","body":"a-marker"}))
        .await
        .unwrap();
    let b_sent = b_client
        .call("send", &json!({"room_name":"shared","body":"b-marker"}))
        .await
        .unwrap();
    assert_eq!(a_sent["envelope"]["origin_instance_id"], "si-817-a");
    assert_eq!(b_sent["envelope"]["origin_instance_id"], "si-817-b");
    assert_eq!(coord_json(&a, &start_a).await, a_process);
    assert_eq!(coord_json(&a, &["start"]).await, a_process);
    assert_eq!(
        coord_json(&a, &["start", "--monitor-port", &ports[1]]).await,
        a_process
    );
    for arguments in [
        vec!["start", "--client-port", &ports[2]],
        vec!["start", "--monitor-port", &ports[3]],
        vec![
            "start",
            "--client-port",
            &ports[2],
            "--monitor-port",
            &ports[3],
        ],
    ] {
        let refused = coord_cli(&a, &arguments).await;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("already running"));
        assert_eq!(fs::read(&a_record_path).unwrap(), a_record);
        assert!(fs::read(a.join("data/coord/nats/server.conf")).unwrap() == a_config);
        assert!(fs::read(a.join("data/coord/nats/creds")).unwrap() == a_credential);
    }
    {
        let _restore = RestoreNatsRecord(a_record_path.clone(), a_record.clone());
        let mut crossed = a_process.clone();
        for key in ["server_name", "client_port", "monitor_port"] {
            crossed[key] = b_process[key].clone();
        }
        fs::write(&a_record_path, serde_json::to_vec(&crossed).unwrap()).unwrap();
        for root in std::iter::once(&a).chain(&a_aliases) {
            assert_eq!(coord_json(root, &["status"]).await["state"], "unknown");
            assert!(!coord_cli(root, &["stop"]).await.status.success());
            assert!(!coord_cli(root, &start_a).await.status.success());
        }
        assert_eq!(
            fs::read(&a_record_path).unwrap(),
            serde_json::to_vec(&crossed).unwrap()
        );
        let mut wrong_owner = a_process.clone();
        wrong_owner["pid"] = b_process["pid"].clone();
        wrong_owner["token"] = b_process["token"].clone();
        fs::write(&a_record_path, serde_json::to_vec(&wrong_owner).unwrap()).unwrap();
        for root in std::iter::once(&a).chain(&a_aliases) {
            assert!(!coord_cli(root, &["stop"]).await.status.success());
            assert!(!coord_cli(root, &start_a).await.status.success());
        }
        assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    }
    assert_eq!(coord_json(&a, &["status"]).await["state"], "running");
    assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    {
        let ports_path = a.join(format!(
            "data/coord/nats/nats-server_{}.ports",
            a_process["pid"]
        ));
        let _restore = RestoreNatsRecord(ports_path.clone(), fs::read(&ports_path).unwrap());
        fs::remove_file(&ports_path).unwrap();
        assert_eq!(coord_json(&a, &["status"]).await["state"], "unknown");
        assert!(!coord_cli(&a, &["stop"]).await.status.success());
        assert!(!coord_cli(&a, &start_a).await.status.success());
        assert_eq!(fs::read(&a_record_path).unwrap(), a_record);
    }
    for arguments in [
        vec!["start", "--client-port", "8222"],
        vec!["start", "--monitor-port", "4222"],
    ] {
        let refused = coord_cli(&c, &arguments).await;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ports must differ"));
        assert!(!c.join("data/coord/nats/server.conf").exists());
    }
    for arguments in [
        vec![
            "start",
            "--binary",
            binary,
            "--client-port",
            &ports[2],
            "--monitor-port",
            &ports[5],
        ],
        vec![
            "start",
            "--binary",
            binary,
            "--client-port",
            &ports[4],
            "--monitor-port",
            &ports[3],
        ],
    ] {
        let refused = coord_cli(&c, &arguments).await;
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("NATS exited"),
            "{}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(!c.join("data/coord/nats/process.json").exists());
        assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    }
    // Stopping/restarting A must not redirect a cached B client or B's store.
    coord_json(&a_aliases[0], &["stop"]).await;
    for key in ["client_port", "monitor_port"] {
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", a_process[key].as_u64().unwrap() as u16))
                .await
                .is_err()
        );
    }
    let b_history = b_client
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(b_history["messages"].as_array().unwrap().len(), 1);
    assert_eq!(b_history["messages"][0]["body"], "b-marker");
    b_client
        .call("send", &json!({"room_name":"shared","body":"b-fresh"}))
        .await
        .unwrap();
    // Resolve a live relative config argument against NATS's launch directory,
    // even when the next CLI caller is in a different directory.
    let output = coord_cli_from(Path::new("a"), &start_a, parent.path()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut restarted_a: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(restarted_a["server_name"], a_process["server_name"]);
    assert_eq!(restarted_a["client_port"], a_process["client_port"]);
    assert_eq!(restarted_a["monitor_port"], a_process["monitor_port"]);
    for alias in &a_aliases[1..] {
        assert_eq!(coord_json(alias, &["status"]).await["state"], "running");
        assert_eq!(coord_json(alias, &start_a).await, restarted_a);
        coord_json(alias, &["stop"]).await;
        assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
        let next = coord_json(alias, &start_a).await;
        assert_ne!(next["server_name"], restarted_a["server_name"]);
        assert_eq!(coord_json(&a, &start_a).await, next);
        restarted_a = next;
    }
    let a_history = a_client
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(a_history["messages"].as_array().unwrap().len(), 1);
    assert_eq!(a_history["messages"][0]["body"], "a-marker");
    a_client
        .call("send", &json!({"room_name":"shared","body":"a-restarted"}))
        .await
        .unwrap();
    assert!(fs::read(a.join("data/coord/nats/creds")).unwrap() == a_credential);
    for (path, before) in b_files.iter().zip(&b_before) {
        assert!(
            fs::read(b.join(path)).unwrap() == *before,
            "B file changed: {path}"
        );
    }
    assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    a_proxy.shutdown().await;
    b_proxy.shutdown().await;
    coord_json(&a, &["stop"]).await;
    coord_json(&b, &["stop"]).await;
    for process in [&restarted_a, &b_process] {
        for key in ["client_port", "monitor_port"] {
            assert!(
                tokio::net::TcpStream::connect((
                    "127.0.0.1",
                    process[key].as_u64().unwrap() as u16
                ))
                .await
                .is_err()
            );
        }
    }
    // Exercise actual ordinary defaults and per-option defaults as well.
    let defaults = coord_json(&default_root, &["start", "--binary", binary]).await;
    assert_eq!(defaults["client_port"], 4222);
    assert_eq!(defaults["monitor_port"], 8222);
    coord_json(&default_root, &["stop"]).await;
    let partial = coord_json(
        &default_root,
        &["start", "--binary", binary, "--client-port", &ports[4]],
    )
    .await;
    assert_eq!(
        partial["client_port"].as_u64().unwrap().to_string(),
        ports[4]
    );
    assert_eq!(partial["monitor_port"], 8222);
    coord_json(&default_root, &["stop"]).await;
    let swapped = coord_json(
        &default_root,
        &[
            "start",
            "--client-port",
            "8222",
            "--monitor-port",
            &ports[5],
        ],
    )
    .await;
    assert_eq!(
        coord_json(&default_root, &["start", "--client-port", "8222"]).await,
        swapped
    );
    coord_json(&default_root, &["stop"]).await;
    println!(
        "native Coord explicit ports: isolated A/B endpoints and messages, root-alias startup/reuse/stop across working directories, conflicting/occupied listeners and unrelated-owner refusals, A restart with unchanged live B, and ordinary/partial defaults observed"
    );
}
async fn mcp(root: &Path, socket: &Path, requests: &str) -> Value {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"))
        .arg("mcp")
        .env("SAFEYOLO_COORD_SOCKET", socket)
        .env("SAFEYOLO_COORD_TOKEN_PATH", root.join("data/agent_token"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
async fn origin() -> (u16, tokio::task::JoinHandle<()>) {
    let (port, task, _) = response_origin(
        "200 OK",
        b"{\"marker\":\"permitted-origin\"}",
        None,
        Duration::ZERO,
        false,
    )
    .await;
    (port, task)
}
async fn response_origin(
    status: &str,
    body: &[u8],
    content_length: Option<usize>,
    header_delay: Duration,
    stall_body: bool,
) -> (
    u16,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = requests.clone();
    let status = status.to_owned();
    let content_length = content_length.unwrap_or(body.len());
    let body = body.to_vec();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let status = status.clone();
            let body = body.clone();
            connections.spawn(async move {
                let mut request = [0u8; 8192];
                let _ = socket.read(&mut request).await;
                tokio::time::sleep(header_delay).await;
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                if stall_body {
                    let mut remaining = [0u8; 1024];
                    while socket.read(&mut remaining).await.is_ok_and(|read| read > 0) {}
                }
            });
        }
    });
    (port, task, requests)
}

#[tokio::test]
async fn native_response_failures_keep_http_diagnostics_without_repeating_writes() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/agent_token"), "fixture-token").unwrap();
    for (status, body, content_length, expected) in [
        (
            "502 Bad Gateway",
            "",
            None,
            "API 502 Bad Gateway: Bad Gateway",
        ),
        (
            "502 Bad Gateway",
            "upstream unavailable",
            None,
            "API 502 Bad Gateway: Bad Gateway",
        ),
        (
            "503 Service Unavailable",
            "<html>unavailable</html>",
            None,
            "API 503 Service Unavailable: Service Unavailable",
        ),
        (
            "502 Bad Gateway",
            "{broken",
            None,
            "API 502 Bad Gateway: Bad Gateway",
        ),
        (
            "409 Conflict",
            r#"{"error":"room is closed"}"#,
            None,
            "API 409 Conflict: room is closed",
        ),
        (
            "503 Service Unavailable",
            r#"{"error":"publication uncertain","send_outcome":"unknown"}"#,
            None,
            "API 503 Service Unavailable: publication uncertain; send outcome unknown; inspect retained history before repeating",
        ),
        (
            "502 Bad Gateway",
            "null",
            None,
            "API 502 Bad Gateway: Bad Gateway",
        ),
        ("200 OK", "{", None, "EOF while parsing an object"),
        (
            "502 Bad Gateway",
            "",
            Some(10),
            "API 502 Bad Gateway: Bad Gateway; could not read response body: error reading a body from connection",
        ),
        (
            "503 Service Unavailable",
            r#"{"error":"#,
            Some(100),
            "API 503 Service Unavailable: Service Unavailable; could not read response body: error reading a body from connection",
        ),
        (
            "200 OK",
            "",
            Some(10),
            "safeyolo-coord: error reading a body from connection",
        ),
    ] {
        let (port, server, requests) = response_origin(
            status,
            body.as_bytes(),
            content_length,
            Duration::ZERO,
            false,
        )
        .await;
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"))
            .args(["call", "send"])
            .env_remove("SAFEYOLO_COORD_SOCKET")
            .env(
                "SAFEYOLO_COORD_TOKEN_PATH",
                root.path().join("data/agent_token"),
            )
            .env("HTTP_PROXY", format!("http://127.0.0.1:{port}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(
            br#"{"room_name":"shared","body":"fixture write","declared_content_type":"text/plain","notify":"none"}"#
        ).await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        server.abort();
        let _ = server.await;
        assert!(!output.status.success(), "{status}: {body}");
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{status}: {body}: {error}");
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "failed write was repeated: {status}: {body}"
        );
    }
}

#[tokio::test]
async fn native_response_body_timeouts_keep_http_diagnostics_and_total_deadline() {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let token = root.path().join("agent_token");
    fs::write(&token, "fixture-token").unwrap();
    for (status, expected) in [
        (
            "502 Bad Gateway",
            "safeyolo: API 502 Bad Gateway: Bad Gateway; could not read response body: deadline has elapsed",
        ),
        ("200 OK", "safeyolo: deadline has elapsed"),
    ] {
        let (port, server, requests) =
            response_origin(status, b"", Some(10), Duration::from_secs(1), true).await;
        let started = std::time::Instant::now();
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
                .args([
                    "helper",
                    "show",
                    "req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "--token-file",
                ])
                .arg(&token)
                .env("HTTP_PROXY", format!("http://127.0.0.1:{port}"))
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        let elapsed = started.elapsed();
        server.abort();
        let _ = server.await;
        eprintln!(
            "stalled {status}: {elapsed:?}; {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        assert!(!output.status.success(), "{status}");
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), expected);
        assert!(
            elapsed < Duration::from_secs(6),
            "the five-second deadline restarted after delayed headers: {status}: {elapsed:?}"
        );
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "request was repeated: {status}"
        );
    }

    let (port, server, requests) = response_origin(
        "503 Service Unavailable",
        br#"{"error":"#,
        Some(100),
        Duration::from_millis(50),
        true,
    )
    .await;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        safeyolo_proxy::native_client::send_json(
            stream,
            &format!("127.0.0.1:{port}"),
            "/coord/send",
            "fixture-token",
            hyper::Method::POST,
            json!({"room_name":"shared","body":"fixture write"}),
            Duration::from_millis(250),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    server.abort();
    let _ = server.await;
    assert_eq!(
        error.to_string(),
        "API 503 Service Unavailable: Service Unavailable; could not read response body: deadline has elapsed"
    );
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "timed-out write was repeated"
    );

    let (port, server, requests) = response_origin(
        "200 OK",
        br#"{"marker":"permitted-origin"}"#,
        None,
        Duration::ZERO,
        false,
    )
    .await;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let value = tokio::time::timeout(
        Duration::from_secs(2),
        safeyolo_proxy::native_client::send_json(
            stream,
            &format!("127.0.0.1:{port}"),
            "/marker",
            "fixture-token",
            hyper::Method::GET,
            Value::Null,
            Duration::MAX,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    server.abort();
    let _ = server.await;
    assert_eq!(value["marker"], "permitted-origin");
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}
async fn traffic(alice: &Client, port: u16) {
    let stream = tokio::net::UnixStream::connect(alice.socket.as_ref().unwrap())
        .await
        .unwrap();
    let result = safeyolo_proxy::native_client::send_json(
        stream,
        &format!("127.0.0.1:{port}"),
        &format!("http://127.0.0.1:{port}/marker"),
        // Application traffic needs no Agent API bearer credential.
        "",
        hyper::Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(result["marker"], "permitted-origin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn send_receipt_identifies_each_recipient_request() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    unsafe {
        std::env::set_var(
            "SAFEYOLO_NATS_TEST_INSTANCE",
            format!("receipt-{}", uuid::Uuid::new_v4().simple()),
        );
    }
    let temp = tempfile::Builder::new()
        .prefix("coord-receipt-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    fs::create_dir(root.join("data")).unwrap();
    fs::create_dir(root.join("builtin-services")).unwrap();
    fs::write(root.join("data/instance_id"), "si-receipt").unwrap();
    fs::write(root.join("data/agent_token"), "fixture-token").unwrap();
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(
        root.join("policy.toml"),
        "[agents.alice]\nagent_id='ag-alice'\n[agents.bob]\nagent_id='ag-bob'\n",
    )
    .unwrap();
    coord_rooms::start(root, Some(&binary), None, None)
        .await
        .unwrap();
    let _cleanup = NatsCleanup(root.into());
    coord_rooms::create_room(root, "shared").await.unwrap();
    for agent in ["alice", "bob"] {
        coord_rooms::grant(&root.join("config.toml"), "shared", agent, &[], false, None).unwrap();
    }
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
    };
    let bob = Client {
        socket: Some(root.join("bob.sock")),
        token_file: root.join("data/agent_token"),
    };
    let proxy = Proxy::start(native_config::read(&root.join("config.toml")).unwrap())
        .await
        .unwrap();
    let mut cursor = 0;
    let mut request_ids = Vec::new();
    for _ in 0..2 {
        let receipt = alice.call("send", &json!({"room_name":"shared","body":"TASK target=https://example.test/issue assignee=bob","notify":["bob"]})).await.unwrap();
        let delivered = bob
            .call(
                "wait_for_coord",
                &json!({"since_sequence":cursor,"timeout_seconds":1}),
            )
            .await
            .unwrap();
        let resolved = &delivered["objects"][0];
        assert_eq!(resolved["object"]["msg_id"], receipt["envelope"]["msg_id"]);
        assert_eq!(receipt["attention_status"], "ready");
        assert_eq!(
            receipt["attention_recipients"],
            json!([{
                "agent_id":"ag-bob", "attention_id":resolved["edge"]["attention_id"],
            }])
        );
        request_ids.push(resolved["edge"]["attention_id"].clone());
        cursor = delivered["next_cursor"].as_u64().unwrap();
    }
    assert_ne!(request_ids[0], request_ids[1]);
    let receipt = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"information only","notify":"none"}),
        )
        .await
        .unwrap();
    assert_eq!(receipt["attention_recipients"], json!([]));
    proxy.shutdown().await;
    coord_rooms::stop(root).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn fresh_rooms_restart_authorization_mcp_and_nats_failure() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    // These variables affect only this dedicated test binary and its owned
    // dynamic NATS ports. Production/factory state is never selected.
    unsafe {
        std::env::set_var(
            "SAFEYOLO_NATS_TEST_INSTANCE",
            format!("coord818-{}", uuid::Uuid::new_v4().simple()),
        );
    }
    let root = tempfile::Builder::new()
        .prefix("coord818-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = root.path();
    fs::create_dir_all(root.join("data")).unwrap();
    fs::create_dir(root.join("builtin-services")).unwrap();
    fs::write(root.join("data/instance_id"), "si-818-native").unwrap();
    fs::write(root.join("data/admin_token"), "fixture-operator-token").unwrap();
    fs::write(root.join("data/agent_token"), "fixture-token").unwrap();
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),"[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[[permissions]]\naction='network:request'\nresource='*'\neffect='allow'\n").unwrap();
    let config_path = root.join("config.toml");
    let dynamic = coord_rooms::start(root, Some(&binary), None, None)
        .await
        .unwrap();
    let _cleanup = NatsCleanup(root.into());
    coord_rooms::stop(root).await.unwrap();
    // Explicit ports also override the dynamic selection in a test instance.
    let first_nats = coord_rooms::start(
        root,
        Some(&binary),
        Some(dynamic["client_port"].as_u64().unwrap() as u16),
        Some(dynamic["monitor_port"].as_u64().unwrap() as u16),
    )
    .await
    .unwrap();
    assert_eq!(first_nats["client_port"], dynamic["client_port"]);
    assert_eq!(first_nats["monitor_port"], dynamic["monitor_port"]);
    let test_endpoints: Value = serde_json::from_slice(
        &fs::read(root.join("data/coord/nats/test-endpoints.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(test_endpoints, first_nats);
    let room = coord_rooms::create_room(root, "shared").await.unwrap();
    coord_rooms::create_room(root, "private").await.unwrap();
    for agent in ["alice", "bob"] {
        coord_rooms::grant(&config_path, "shared", agent, &[], false, None).unwrap();
    }
    coord_rooms::grant(&config_path, "private", "bob", &[], false, None).unwrap();
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
    };
    let bob = Client {
        socket: Some(root.join("bob.sock")),
        token_file: root.join("data/agent_token"),
    };
    let proxy = Proxy::start(native_config::read(&config_path).unwrap())
        .await
        .unwrap();
    let alice_join = alice
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let bob_join = bob
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(alice_join["room_id"], room["room_id"]);
    assert_eq!(alice_join["state"]["origin_instance_id"], "si-818-native");
    assert_eq!(
        bob_join["state"]["origin_instance_id"],
        alice_join["state"]["origin_instance_id"]
    );
    let waiting = bob.clone();
    let wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_coord",
                &json!({"since_sequence":0,"timeout_seconds":10}),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let first=alice.request(hyper::Method::POST,"/api/coord/rooms/shared/send",json!({"body":"alice-marker","sender_agent_name":"bob","sender_agent_id":"forged","notify":["bob"]}),Duration::from_secs(10)).await.unwrap();
    assert_eq!(first["envelope"]["sender_agent_name"], "alice");
    assert_eq!(
        first["envelope"]["sender_agent_id"],
        "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let woken = tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        woken["objects"][0]["object"]["msg_id"],
        first["envelope"]["msg_id"]
    );
    let second = bob
        .call("send", &json!({"room_name":"shared","body":"bob-marker"}))
        .await
        .unwrap();
    let history = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(history["messages"].as_array().unwrap().len(), 2);
    assert_eq!(history["messages"][0]["body"], "alice-marker");
    assert_eq!(history["messages"][1]["body"], "bob-marker");
    assert_eq!(history["messages"][1]["sender_agent_name"], "bob");
    assert_eq!(
        history["messages"][0]["attention_intent"],
        json!({"mode":"targeted","agent_ids":["ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]})
    );
    assert_eq!(
        history["messages"][1]["attention_intent"],
        json!({"mode":"none","agent_ids":[]})
    );
    assert!(
        bob.call("join_room", &json!({"room_name":"private"}))
            .await
            .is_ok()
    );
    for tool in ["join_room", "read_room", "send"] {
        let args = if tool == "send" {
            json!({"room_name":"private","body":"forbidden"})
        } else {
            json!({"room_name":"private"})
        };
        let error = alice.call(tool, &args).await.unwrap_err().to_string();
        assert!(error.contains("403") || error.contains("404"), "{error}");
    }
    let denied=mcp(root,alice.socket.as_ref().unwrap(),"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_room\",\"arguments\":{\"room_name\":\"private\"}}}\n").await;
    assert_eq!(denied["result"]["isError"], true);
    assert!(denied["result"]["structuredContent"].is_null());
    let malformed = mcp(root, alice.socket.as_ref().unwrap(), "{broken}\n").await;
    assert_eq!(malformed["error"]["code"], -32700);
    let (port, origin_task) = origin().await;
    traffic(&alice, port).await;
    let waiting = alice.clone();
    let cursor = history["next_cursor"].as_u64().unwrap();
    let old_wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_message",
                &json!({"room_name":"shared","since_sequence":cursor,"timeout_seconds":30}),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    proxy.shutdown().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), old_wait)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    coord_rooms::stop(root).await.unwrap();
    for key in ["client_port", "monitor_port"] {
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", first_nats[key].as_u64().unwrap() as u16))
                .await
                .is_err()
        );
    }
    coord_rooms::start(root, Some(&binary), None, None)
        .await
        .unwrap();
    let proxy = Proxy::start(native_config::read(&config_path).unwrap())
        .await
        .unwrap();
    let joined = alice
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    for key in ["room_id", "room_name", "permissions", "history_visibility"] {
        assert_eq!(joined[key], alice_join[key]);
    }
    assert_eq!(
        joined["state"]["origin_instance_id"],
        alice_join["state"]["origin_instance_id"]
    );
    assert_eq!(joined["state"]["members"], alice_join["state"]["members"]);
    let bob_rejoined = bob
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(
        bob_rejoined["state"]["members"],
        bob_join["state"]["members"]
    );
    let retained = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(retained["messages"], history["messages"]);
    let fresh = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"after-restart"}),
        )
        .await
        .unwrap();
    assert!(fresh["sequence"].as_u64().unwrap() > second["sequence"].as_u64().unwrap());
    coord_rooms::stop(root).await.unwrap();
    let failure = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"must-not-report-success"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        failure.contains("unavailable") || failure.contains("unknown"),
        "{failure}"
    );
    let unavailable=mcp(root,alice.socket.as_ref().unwrap(),"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"send\",\"arguments\":{\"room_name\":\"shared\",\"body\":\"unavailable-mcp\"}}}\n").await;
    assert_eq!(unavailable["result"]["isError"], true);
    traffic(&alice, port).await;
    proxy.shutdown().await;
    origin_task.abort();
    println!(
        "native Coord: two identities, targeted wake, member scope, fresh-store restart, MCP refusal/malformed/unavailable and independent proxy traffic observed; no model invoked"
    );
}
