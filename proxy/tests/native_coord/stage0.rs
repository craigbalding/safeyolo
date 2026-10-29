//! Current-native source boundary, real processes, authenticated API and NATS.
use super::*;
use futures_util::StreamExt;
use rusqlite::Connection;

async fn base(root: &Path, args: &[&str]) -> Value {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(
            std::env::var_os("SAFEYOLO_COORD_BASE_BINARY")
                .expect("set the retained current-master CLI"),
        )
        .arg("--root")
        .arg(root)
        .args(args)
        .env("SAFEYOLO_NATS_TEST_INSTANCE", root)
        .env_remove("SAFEYOLO_NATS_TEST_PORTS")
        .kill_on_drop(true)
        .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        let rows: Result<Vec<Value>, _> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(serde_json::from_str)
            .collect();
        rows.map(Value::Array).unwrap_or(Value::Null)
    })
}

fn count(root: &Path, sql: &str) -> i64 {
    Connection::open(root.join("data/coord/v0.db"))
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Stage0 observable boundary timed out");
}

async fn start_proxy(root: &Path) -> tokio::process::Child {
    let config = native_config::read(&root.join("config.toml")).unwrap();
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
        .args(["--config"])
        .arg(root.join("config.toml"))
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("proxy-diagnostics.log"))
                .unwrap(),
        ))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    until(|| {
        fs::read(&config.readiness_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .is_some_and(|v| v["pid"] == pid)
    })
    .await;
    child
}

async fn crash(mut child: tokio::process::Child) {
    child.kill().await.unwrap();
    assert!(!child.wait().await.unwrap().success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the pinned NATS binary and retained current-master CLI"]
async fn native_stage0_replay_and_delivery_survive_current_master_and_process_crashes() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary"),
    );
    let temp = tempfile::Builder::new()
        .prefix("coord-stage0-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    base(root, &["init"]).await;
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"), "[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n").unwrap();
    let first_nats = base(
        root,
        &["coord", "start", "--binary", binary.to_str().unwrap()],
    )
    .await;
    let _cleanup = NatsCleanup(root.to_owned());
    let room = base(root, &["coord", "room", "create", "shared"]).await;
    for name in ["alice", "bob", "carol"] {
        base(root, &["coord", "grant", "shared", name]).await;
    }
    base(
        root,
        &[
            "coord",
            "brief",
            "set",
            "shared",
            "Private canonical Stage0 brief",
            "--expected-revision",
            "0",
        ],
    )
    .await;
    base(
        root,
        &[
            "coord",
            "send",
            "shared",
            "Retained current-master message",
            "--to",
            "bob",
        ],
    )
    .await;
    assert_eq!(count(root, "PRAGMA user_version"), 5);
    let db = Connection::open(root.join("data/coord/v0.db")).unwrap();
    let staged: Vec<String> = db
        .prepare("SELECT event_id FROM coord_outbox WHERE destination='audit-jsonl'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!staged.is_empty());
    // One immutable result for two concurrent CLI callers using equivalent input.
    let args = &["grant", "shared", "alice", "--operation-id", "grant-retry"];
    let (a, b) = tokio::join!(coord_json(root, args), coord_json(root, args));
    assert_eq!(a, b);
    let conflicted = coord_cli(
        root,
        &[
            "grant",
            "shared",
            "alice",
            "send",
            "--operation-id",
            "grant-retry",
        ],
    )
    .await;
    assert!(!conflicted.status.success());
    assert!(String::from_utf8_lossy(&conflicted.stderr).contains("conflicts"));
    for options in [
        vec!["grant", "shared", "alice", "--operation-id"],
        vec![
            "grant",
            "shared",
            "alice",
            "--operation-id",
            "one",
            "--operation-id",
            "two",
        ],
        vec!["grant", "shared", "alice", "--operation-id", ""],
        vec!["grant", "shared", "alice", "admin"],
        vec!["revoke", "shared", "alice", "receive"],
    ] {
        assert!(!coord_cli(root, &options).await.status.success());
    }
    let revoked = coord_json(
        root,
        &[
            "revoke",
            "shared",
            "alice",
            "--operation-id",
            "revoke-retry",
        ],
    )
    .await;
    assert_eq!(coord_json(root, args).await, a);
    assert_eq!(
        count(
            root,
            "SELECT count(*) FROM memberships WHERE principal_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AND revoked_at IS NULL"
        ),
        0
    );
    coord_json(
        root,
        &["grant", "shared", "alice", "--operation-id", "later-grant"],
    )
    .await;
    assert_eq!(
        coord_json(
            root,
            &[
                "revoke",
                "shared",
                "alice",
                "--operation-id",
                "revoke-retry"
            ]
        )
        .await,
        revoked
    );

    let config = native_config::read(&root.join("config.toml")).unwrap();
    let audit_path = config.audit_log_path.unwrap();
    if audit_path.exists() {
        fs::rename(&audit_path, root.join("base-audit.jsonl")).unwrap();
    }
    fs::create_dir_all(&audit_path).unwrap();
    let creds = fs::read_to_string(root.join("data/coord/nats/creds")).unwrap();
    let nats = async_nats::ConnectOptions::new()
        .user_and_password("safeyolo".into(), creds.trim().into())
        .connect(format!("127.0.0.1:{}", first_nats["client_port"]))
        .await
        .unwrap();
    let mut hints = nats.subscribe("coord.attention.>").await.unwrap();
    nats.flush().await.unwrap();
    let proxy = start_proxy(root).await;
    until(||count(root,"SELECT count(*) FROM coord_outbox WHERE destination='attention-nats' AND delivered_at IS NULL")==0).await;
    assert!(
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE destination='audit-jsonl' AND delivered_at IS NULL"
        ) > 0
    );
    let hint = tokio::time::timeout(Duration::from_secs(2), hints.next())
        .await
        .unwrap()
        .unwrap();
    let hint: Value = serde_json::from_slice(&hint.payload).unwrap();
    assert_eq!(
        count(
            root,
            &format!(
                "SELECT count(*) FROM coord_outbox WHERE event_id='{}' AND delivered_at IS NOT NULL",
                hint["event_id"].as_str().unwrap()
            )
        ),
        1
    );
    crash(proxy).await;
    fs::remove_dir(&audit_path).unwrap();

    while matches!(
        tokio::time::timeout(Duration::from_millis(20), hints.next()).await,
        Ok(Some(_))
    ) {}
    coord_json(
        root,
        &[
            "brief",
            "set",
            "shared",
            "Private canonical Stage0 brief updated",
            "--expected-revision",
            "1",
        ],
    )
    .await;
    let pending_hints: Vec<String> = db.prepare("SELECT event_id FROM coord_outbox WHERE destination='attention-nats' AND delivered_at IS NULL").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<Result<_,_>>().unwrap();
    assert_eq!(pending_hints.len(), 3);

    // Stop between durable append and delivery marking. The trigger is a
    // test-local fault at the actual SQLite commit boundary, not a product API.
    db.execute_batch("CREATE TRIGGER reject_delivery BEFORE UPDATE ON coord_outbox WHEN NEW.delivered_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected delivery marker failure'); END;").unwrap();
    let proxy = start_proxy(root).await;
    let mut observed = std::collections::HashSet::new();
    while observed.len() < pending_hints.len() {
        let hint = tokio::time::timeout(Duration::from_secs(10), hints.next())
            .await
            .unwrap()
            .unwrap();
        let hint: Value = serde_json::from_slice(&hint.payload).unwrap();
        let id = hint["event_id"].as_str().unwrap().to_owned();
        if pending_hints.contains(&id) {
            observed.insert(id);
        }
    }
    until(|| {
        fs::read_to_string(&audit_path)
            .ok()
            .is_some_and(|text| staged.iter().all(|id| text.contains(id)))
    })
    .await;
    crash(proxy).await;
    assert!(
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE destination='audit-jsonl' AND delivered_at IS NULL"
        ) > 0
    );
    // Model a process dying during its last append, before the line delimiter.
    // The next owner must preserve complete rows and recover the partial tail.
    std::io::Write::write_all(
        &mut fs::OpenOptions::new()
            .append(true)
            .open(&audit_path)
            .unwrap(),
        b"{\"schema_version\":2,\"event_id\":\"interrupted",
    )
    .unwrap();
    db.execute_batch("DROP TRIGGER reject_delivery").unwrap();
    coord_rooms::stop(root).await.unwrap();
    unsafe {
        std::env::set_var("SAFEYOLO_NATS_TEST_INSTANCE", root);
    }
    let restarted_nats = coord_rooms::start(root, Some(&binary), None, None)
        .await
        .unwrap();
    let nats = async_nats::ConnectOptions::new()
        .user_and_password("safeyolo".into(), creds.trim().into())
        .connect(format!("127.0.0.1:{}", restarted_nats["client_port"]))
        .await
        .unwrap();
    let mut hints = nats.subscribe("coord.attention.>").await.unwrap();
    nats.flush().await.unwrap();
    let proxy = start_proxy(root).await;
    let mut observed = std::collections::HashSet::new();
    while observed.len() < pending_hints.len() {
        let hint = tokio::time::timeout(Duration::from_secs(10), hints.next())
            .await
            .unwrap()
            .unwrap();
        let hint: Value = serde_json::from_slice(&hint.payload).unwrap();
        let id = hint["event_id"].as_str().unwrap().to_owned();
        if pending_hints.contains(&id) {
            observed.insert(id);
        }
    }
    until(|| {
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE delivered_at IS NULL",
        ) == 0
    })
    .await;
    assert_eq!(coord_json(root, args).await, a);
    assert_eq!(
        coord_json(
            root,
            &[
                "revoke",
                "shared",
                "alice",
                "--operation-id",
                "revoke-retry"
            ]
        )
        .await,
        revoked
    );
    let clients: Vec<_> = ["alice", "bob", "carol"]
        .map(|name| Client {
            socket: Some(root.join(format!("{name}.sock"))),
            token_file: root.join("data/agent_token"),
        })
        .into();
    for client in &clients {
        let history = client
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .unwrap();
        assert_eq!(
            history["messages"][0]["body"],
            "Retained current-master message"
        );
        assert_eq!(
            client
                .call("read_brief", &json!({"room_name":"shared"}))
                .await
                .unwrap()["markdown"],
            "Private canonical Stage0 brief updated"
        );
    }
    // Three distinct authenticated clients use the changed common path in a
    // targeted round trip. This is a transport witness, not model-driven dogfood.
    for (sender, recipient, name) in [(0, 1, "bob"), (1, 2, "carol"), (2, 0, "alice")] {
        let sent = clients[sender]
            .call(
                "send",
                &json!({"room_name":"shared","body":"Stage0 retained-state check","notify":[name]}),
            )
            .await
            .unwrap();
        let resolved = clients[recipient]
            .call(
                "wait_for_coord",
                &json!({"since_sequence":0,"timeout_seconds":1,"limit":200}),
            )
            .await
            .unwrap();
        assert!(
            resolved["objects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["object"]["msg_id"] == sent["envelope"]["msg_id"])
        );
    }
    // Revocation still controls every read after retrying an old grant.
    coord_json(
        root,
        &[
            "revoke",
            "shared",
            "carol",
            "--operation-id",
            "revoke-carol",
        ],
    )
    .await;
    assert!(
        clients[2]
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    until(|| {
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE delivered_at IS NULL",
        ) == 0
    })
    .await;
    let audit = fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains("Private canonical Stage0 brief"));
    assert!(!audit.contains("Retained current-master message"));
    assert!(!audit.contains("Stage0 retained-state check"));
    let records: Vec<_> = audit
        .lines()
        .map(|line| safeyolo_proxy::audit::parse_record(line).unwrap())
        .collect();
    for id in &staged {
        assert!(records.iter().filter(|r| r["event_id"] == *id).count() >= 2);
    }
    let watched = coord_cli(
        root,
        &["watch", "--jsonl", audit_path.to_str().unwrap(), "--json"],
    )
    .await;
    assert!(
        watched.status.success(),
        "{}",
        String::from_utf8_lossy(&watched.stderr)
    );
    assert!(!String::from_utf8_lossy(&watched.stderr).contains("drift"));
    crash(proxy).await;
    assert_eq!(
        base(root, &["coord", "brief", "show", "shared"]).await["markdown"],
        "Private canonical Stage0 brief updated"
    );
    base(
        root,
        &[
            "coord",
            "send",
            "shared",
            "Current-master rollback message",
            "--to",
            "bob",
        ],
    )
    .await;
    let rollback_history = base(root, &["coord", "history", "shared"]).await;
    assert_eq!(
        rollback_history.as_array().unwrap().last().unwrap()["body"],
        "Current-master rollback message"
    );
    let proxy = start_proxy(root).await;
    assert_eq!(
        clients[0]
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .unwrap()["messages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["body"],
        "Current-master rollback message"
    );
    until(|| {
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE delivered_at IS NULL",
        ) == 0
    })
    .await;
    crash(proxy).await;
    db.execute_batch("PRAGMA user_version=999").unwrap();
    let refused = coord_cli(root, &["room", "list"]).await;
    assert!(!refused.status.success());
    assert_eq!(count(root, "PRAGMA user_version"), 999);
    db.execute_batch("PRAGMA user_version=5").unwrap();
    assert_eq!(
        coord_json(root, &["room", "list"]).await["rooms"][0]["room_id"],
        room["room_id"]
    );
}
