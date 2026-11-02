use super::*;
use safeyolo_proxy::coord_rooms;

fn room_store(f: &Fixture) {
    let root = f.root.path();
    fs::write(root.join("config.toml"), "admin_port=0\n").unwrap();
    fs::write(root.join("data/instance_id"), "sy-coord-approval-fixture").unwrap();
    coord_rooms::bootstrap(root).unwrap();
}

fn rooms(f: &Fixture) {
    room_store(f);
    let conn = db(f);
    conn.execute("INSERT INTO rooms VALUES('rm-delegated','delegated',0)", [])
        .unwrap();
    conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-delegated','operator','operator','page_operator,receive,send',1)",[]).unwrap();
}

fn envelope() -> Value {
    json!({"expected_revision":null,"delegation":{
        "reviewers":[{"name":"helper","agent_id":HELPER_ID}],
        "beneficiaries":[{"name":"worker","agent_id":WORKER_ID}],
        "scopes":[{"type":"coord_room","room_id":"rm-delegated","permissions":["receive","send","page_operator"],"participants":[
            {"principal_kind":"operator","principal_id":"operator","permissions":["page_operator","receive","send"]},
            {"principal_kind":"agent","principal_id":WORKER_ID,"permissions":["receive","send","page_operator"]}]}],
        "expires_at":null,"grant_seconds":null,"gateway_once":false,"acknowledgment":null}})
}

fn db(f: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(f.root.path().join("data/coord/v0.db")).unwrap()
}

async fn approve(f: &Fixture, rights: &[&str], operation: &str) -> String {
    let request = access(f, rights, operation).await;
    assert_eq!(request.status, 200, "{}", request.json());
    assert!(
        request.json().get("action").is_none(),
        "nonmember receipt must not disclose the room audience"
    );
    let id = request.json()["approval_id"].as_str().unwrap().to_owned();
    let decision = decide(f, "helper", &id, "approve", "run").await;
    assert_eq!(decision.status, 200, "{}", decision.json());
    id
}

async fn joined(f: &Fixture) -> Reply {
    f.agent("worker", "POST", "/api/coord/rooms/delegated/join", None)
        .await
}

async fn assert_objects_denied(f: &Fixture) {
    for path in [
        "/join",
        "/messages",
        "/members",
        "/state",
        "/brief",
        "/work",
        "/signals",
    ] {
        let response = f
            .agent(
                "worker",
                if path == "/join" { "POST" } else { "GET" },
                &format!("/api/coord/rooms/delegated{path}"),
                None,
            )
            .await;
        assert!(
            matches!(response.status, 403 | 404),
            "{path}: {} {}",
            response.status,
            response.json()
        );
    }
}

#[tokio::test]
async fn whole_room_effect_previews_and_hostile_requests() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    rooms(&f);
    // An unchanged independent reviewer member is allowed. It receives no
    // additional right through another worker's request.
    coord_rooms::grant(
        &f.root.path().join("config.toml"),
        "delegated",
        "helper",
        &["receive".into()],
        false,
        Some("reviewer-independent"),
    )
    .unwrap();
    let mut input = envelope();
    input["delegation"]["scopes"][0]["participants"]
        .as_array_mut()
        .unwrap()
        .push(json!({"principal_kind":"agent","principal_id":HELPER_ID,"permissions":["receive"]}));
    for bad in [
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["permissions"] = json!(["admin"]);
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["room_id"] = json!("rm-foreign");
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["wildcard"] = json!("*");
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["beneficiaries"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"helper","agent_id":HELPER_ID}));
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["participants"] = json!([]);
            v
        },
    ] {
        let response = f
            .admin(
                "POST",
                "/admin/approval-delegations/local/preview",
                Some(bad),
            )
            .await;
        assert!(matches!(response.status, 400 | 409), "{}", response.json());
    }
    // Two independently complete receive/send envelopes cannot be combined
    // into a single send+receive decision.
    let mut send = input["delegation"]["scopes"][0].clone();
    send["permissions"] = json!(["send"]);
    input["delegation"]["scopes"][0]["permissions"] = json!(["receive"]);
    input["delegation"]["scopes"]
        .as_array_mut()
        .unwrap()
        .push(send);
    let (mut applied, revision) = delegate(&f, input).await;
    db(&f)
        .execute("INSERT INTO rooms VALUES('rm-other','other',0)", [])
        .unwrap();
    let other = f
        .agent(
            "worker",
            "POST",
            "/api/coord/request-access",
            Some(
                json!({"room_name":"other","permissions":["receive"],"operation_id":"other-room"}),
            ),
        )
        .await
        .json();
    let other_id = other["approval_id"].as_str().unwrap();
    assert_eq!(
        f.agent("helper", "GET", &format!("/approvals/{other_id}"), None)
            .await
            .status,
        404
    );
    assert_eq!(
        decide(&f, "helper", other_id, "approve", "run")
            .await
            .status,
        409
    );
    let request = access(&f, &["send", "receive"], "split").await.json();
    let id = request["approval_id"].as_str().unwrap();
    assert_eq!(
        f.agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        404
    );
    assert_eq!(decide(&f, "helper", id, "approve", "run").await.status, 409);
    for body in [
        json!({"room_name":"delegated","permissions":["receive"],"operation_id":"forged","agent":"helper"}),
        json!({"room_name":"delegated","permissions":["receive"],"operation_id":"forged","run":{"agent":"helper"}}),
        json!({"room_name":"delegated","permissions":["admin"],"operation_id":"forged"}),
        json!({"room_name":"delegated","permissions":[],"operation_id":"forged"}),
    ] {
        assert_eq!(
            f.agent("worker", "POST", "/api/coord/request-access", Some(body))
                .await
                .status,
            400
        );
    }
    let pending = access(&f, &["receive"], "safe").await.json();
    let id = pending["approval_id"].as_str().unwrap();
    let canonical = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(canonical["observed"]["new_permissions"], json!(["receive"]));
    assert_eq!(
        canonical["choices"][0]["room_envelopes"][0]["permissions"],
        json!(["receive"])
    );
    assert!(canonical.to_string().contains("retained history"));
    applied["expected_revision"] = json!(revision);
    applied["delegation"]["definition_revisions"] = json!({});
    applied["delegation"]["grant_seconds"] = json!(2);
    for scope in applied["delegation"]["scopes"].as_array_mut().unwrap() {
        scope["permissions"] = json!(["send"]);
    }
    delegate(&f, applied).await;
    assert_eq!(
        decide(&f, "helper", id, "approve", "run").await.status,
        409,
        "old delegation revision must not authorize a decision"
    );
    assert_objects_denied(&f).await;
    f.proxy.shutdown().await;
}

#[tokio::test]
async fn separate_sources_refusal_lifetime_and_run_turnover() {
    let mut f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    rooms(&f);
    let (mut input, revision) = delegate(&f, envelope()).await;
    let first = approve(&f, &["receive"], "receive-source").await;
    let second = approve(&f, &["send"], "send-source").await;
    assert_eq!(
        joined(&f).await.json()["permissions"],
        json!(["receive", "send"])
    );
    let denied = access(&f, &["page_operator"], "refused").await.json();
    let refused = decide(
        &f,
        "helper",
        denied["approval_id"].as_str().unwrap(),
        "reject",
        "run",
    )
    .await;
    assert_eq!(refused.status, 200, "{}", refused.json());
    assert_eq!(
        joined(&f).await.json()["permissions"],
        json!(["receive", "send"])
    );
    // Removing one source leaves the other source's receive permission.
    db(&f)
        .execute(
            "UPDATE coord_membership_grants SET revoked_at=1 WHERE approval_id=?1",
            [&second],
        )
        .unwrap();
    assert_eq!(joined(&f).await.json()["permissions"], json!(["receive"]));
    f = f.restart().await;
    assert_eq!(joined(&f).await.status, 200);
    fs::write(
        f.root.path().join("other-policy.toml"),
        "[agents.worker]\nagent_id='ag-11111111111111111111111111111111'\n",
    )
    .unwrap();
    fs::write(
        f.root.path().join("config.toml"),
        "admin_port=0\npolicy_file='other-policy.toml'\n",
    )
    .unwrap();
    assert_objects_denied(&f).await;
    fs::write(f.root.path().join("config.toml"), "admin_port=0\n").unwrap();
    assert_eq!(joined(&f).await.status, 200);
    let path = f.root.path().join("agents/worker/runtime.json");
    let original = fs::read(&path).unwrap();
    let mut run: Value = serde_json::from_slice(&original).unwrap();
    run["state"] = json!("stopped");
    fs::write(&path, run.to_string()).unwrap();
    assert_objects_denied(&f).await;
    run["state"] = json!("running");
    run["run_id"] = json!("abcdef0123456789abcdef0123456789");
    fs::write(&path, run.to_string()).unwrap();
    assert_objects_denied(&f).await;
    // Restore the controlled run only to test narrowing and real clock expiry.
    fs::write(&path, original).unwrap();
    input["expected_revision"] = json!(revision);
    input["delegation"]["grant_seconds"] = json!(1);
    input["delegation"]["definition_revisions"] = json!({});
    input["delegation"]["scopes"][0]["permissions"] = json!(["receive"]);
    delegate(&f, input).await;
    assert_objects_denied(&f).await;
    let fresh = approve(&f, &["receive"], "expiring").await;
    assert_ne!(first, fresh);
    assert_eq!(joined(&f).await.status, 200);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_objects_denied(&f).await;
    let inspected = f
        .admin("GET", &format!("/admin/approvals/{fresh}"), None)
        .await;
    assert_eq!(inspected.status, 200, "{}", inspected.json());
    assert_eq!(inspected.json()["grant_active"], false);
    f.proxy.shutdown().await;
}

#[tokio::test]
async fn canonical_races_and_interrupted_publication_are_recoverable_without_renewal() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    rooms(&f);
    let mut input = envelope();
    input["delegation"]["grant_seconds"] = json!(60);
    delegate(&f, input).await;
    let id = access(&f, &["receive"], "race").await.json()["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let operator_path = format!("/admin/approvals/{id}");
    let (reviewer, operator) = tokio::join!(
        decide(&f, "helper", &id, "approve", "run"),
        f.admin(
            "POST",
            &operator_path,
            Some(json!({"decision":"approve","option":"run"}))
        )
    );
    assert_eq!(reviewer.status, 200, "{}", reviewer.json());
    assert_eq!(operator.status, 200, "{}", operator.json());
    assert_eq!(reviewer.json()["status"], operator.json()["status"]);
    assert_eq!(
        db(&f)
            .query_row("SELECT count(*) FROM coord_membership_grants", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );

    let id = access(&f, &["send"], "interrupted-policy").await.json()["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let permissions = fs::metadata(f.root.path()).unwrap().permissions();
    fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let failed = decide(&f, "helper", &id, "approve", "run").await;
    fs::set_permissions(f.root.path(), permissions).unwrap();
    assert_eq!(failed.status, 409, "{}", failed.json());
    assert_eq!(
        joined(&f).await.json()["permissions"],
        json!(["receive"]),
        "prepared but uncommitted send source must be inert"
    );
    let prepared: String = db(&f)
        .query_row(
            "SELECT issued_json FROM coord_membership_grants WHERE approval_id=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    let canonical =
        rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    canonical.execute_batch("CREATE TRIGGER fail_canonical_result BEFORE UPDATE ON approvals WHEN json_extract(NEW.record,'$.status')='approved' BEGIN SELECT RAISE(FAIL,'controlled canonical write failure'); END;").unwrap();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    let view = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(view["status"], "approved");
    assert_eq!(view["grant_active"], true);
    assert_eq!(
        view["result"]["issued_access"],
        serde_json::from_str::<Value>(&prepared).unwrap()
    );
    assert_eq!(
        joined(&f).await.json()["permissions"],
        json!(["receive", "send"])
    );
    let saved = f.source();
    canonical
        .execute_batch("DROP TRIGGER fail_canonical_result")
        .unwrap();
    drop(canonical);
    let f = f.restart().await;
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    assert_eq!(
        f.source(),
        saved,
        "lost response recovery must reuse the exact receipt and expiry"
    );
    assert_eq!(
        db(&f)
            .query_row("SELECT count(*) FROM coord_membership_grants", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    // Source deletion is surfaced honestly; an approval receipt by itself
    // cannot replace the membership owner's missing publication.
    db(&f)
        .execute(
            "DELETE FROM coord_membership_grants WHERE approval_id=?1",
            [&id],
        )
        .unwrap();
    assert_eq!(
        f.admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json()["grant_active"],
        false
    );
    assert_eq!(joined(&f).await.json()["permissions"], json!(["receive"]));
    f.proxy.shutdown().await;
}

struct NatsCleanup(std::path::PathBuf);
impl Drop for NatsCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .args(["coord", "stop"])
            .stdout(std::process::Stdio::null())
            .status();
    }
}

async fn start_wait(f: &Fixture, since: u64) -> tokio::net::UnixStream {
    start_request_wait(
        f,
        &format!("/api/coord/rooms/delegated/wait?since={since}&timeout=2"),
    )
    .await
}

async fn start_request_wait(f: &Fixture, path: &str) -> tokio::net::UnixStream {
    let mut stream = tokio::net::UnixStream::connect(f.root.path().join("worker.sock"))
        .await
        .unwrap();
    stream.write_all(format!("GET http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer synthetic-agent-token\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream
}

async fn finish_wait(mut stream: tokio::net::UnixStream) -> String {
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; real message, attention, native-object and connection boundaries"]
async fn real_nats_room_approval_attention_objects_and_pending_connections() {
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    // Run this focused witness alone; the dynamic listener selector is scoped
    // to this disposable instance, never the installed factory.
    unsafe {
        std::env::set_var(
            "SAFEYOLO_NATS_TEST_INSTANCE",
            format!("approval-{}", uuid::Uuid::new_v4().simple()),
        );
    }
    let mut f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    room_store(&f);
    coord_rooms::start(
        f.root.path(),
        Some(std::path::Path::new(&binary)),
        None,
        None,
    )
    .await
    .unwrap();
    let _cleanup = NatsCleanup(f.root.path().into());
    let room = coord_rooms::create_room(f.root.path(), "delegated")
        .await
        .unwrap();
    coord_rooms::create_room(f.root.path(), "helper-agent")
        .await
        .unwrap();
    for (room, name) in [("delegated", "peer"), ("helper-agent", "helper")] {
        coord_rooms::grant(
            &f.root.path().join("config.toml"),
            room,
            name,
            &[],
            false,
            None,
        )
        .unwrap();
    }
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(f.root.path())
        .args([
            "coord",
            "brief",
            "set",
            "delegated",
            "Trusted retained brief",
            "--expected-revision",
            "0",
        ])
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let mut input = envelope();
    input["delegation"]["scopes"][0]["room_id"] = room["room_id"].clone();
    input["delegation"]["scopes"][0]["participants"].as_array_mut().unwrap().push(json!({"principal_kind":"agent","principal_id":PEER_ID,"permissions":["send","receive","page_operator"]}));
    let (_, revision) = delegate(&f, input.clone()).await;
    let prior = f
        .agent(
            "peer",
            "POST",
            "/api/coord/rooms/delegated/send",
            Some(json!({"body":"retained-before-grant","notify":"none"})),
        )
        .await;
    assert_eq!(prior.status, 200, "{}", prior.json());
    assert_objects_denied(&f).await;
    let client = safeyolo_proxy::coord_tools::Client {
        socket: Some(f.root.path().join("worker.sock")),
        token_file: f.root.path().join("data/agent_token"),
        home: None,
    };
    let pending = client.call("request_room_access", &json!({"room_name":"delegated","permissions":["receive"],"operation_id":"native-producer"})).await.unwrap();
    let id = pending["approval_id"].as_str().unwrap();
    let references = f
        .agent(
            "helper",
            "GET",
            "/api/coord/rooms/helper-agent/messages?since=0",
            None,
        )
        .await;
    assert_eq!(references.status, 200, "{}", references.json());
    let reference = references.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["body"].as_str().is_some_and(|b| b.contains(id)))
        .cloned()
        .expect("reviewer receives canonical reference");
    assert!(
        !reference["body"]
            .as_str()
            .unwrap()
            .contains(room["room_id"].as_str().unwrap())
    );
    assert!(!reference["body"].as_str().unwrap().contains(WORKER_ID));
    let canonical = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(canonical.json()["observed"]["room_id"], room["room_id"]);
    assert_eq!(
        f.agent("helper", "POST", "/api/coord/rooms/delegated/join", None)
            .await
            .status,
        404
    );
    assert_eq!(decide(&f, "helper", id, "approve", "run").await.status, 200);
    let history = f
        .agent(
            "worker",
            "GET",
            "/api/coord/rooms/delegated/messages?since=0",
            None,
        )
        .await;
    assert_eq!(history.status, 200, "{}", history.json());
    assert_eq!(
        history.json()["messages"][0]["body"],
        "retained-before-grant"
    );
    for operation in ["send", "work", "signals"] {
        let body = match operation {
            "send" => json!({"body":"forbidden","notify":"none"}),
            "work" => json!({"action":"create","title":"forbidden"}),
            _ => {
                json!({"action":"create","kind":"result","summary":"forbidden","basis":"observed"})
            }
        };
        assert_eq!(
            f.agent(
                "worker",
                "POST",
                &format!("/api/coord/rooms/delegated/{operation}"),
                Some(body)
            )
            .await
            .status,
            403
        );
    }
    approve(&f, &["send", "receive", "page_operator"], "full-rights").await;
    let work = f
        .agent(
            "worker",
            "POST",
            "/api/coord/rooms/delegated/work",
            Some(json!({"action":"create","title":"Native work","operation_id":"native-work"})),
        )
        .await;
    assert_eq!(work.status, 200, "{}", work.json());
    let signal = f.agent("worker", "POST", "/api/coord/rooms/delegated/signals", Some(json!({"action":"create","kind":"blocker","summary":"Operator input needed","basis":"observed","operation_id":"native-page"}))).await;
    assert_eq!(signal.status, 200, "{}", signal.json());
    assert_eq!(signal.json()["signal"]["needs_operator"], true);
    for operation in ["state", "brief", "work", "signals"] {
        let read = f
            .agent(
                "worker",
                "GET",
                &format!("/api/coord/rooms/delegated/{operation}"),
                None,
            )
            .await;
        assert_eq!(read.status, 200, "{operation}: {}", read.json());
    }
    assert_eq!(
        f.agent(
            "worker",
            "POST",
            "/api/coord/rooms/delegated/send",
            Some(json!({"body":"worker-message","notify":["peer"]}))
        )
        .await
        .status,
        200
    );
    let sent = f
        .agent(
            "peer",
            "POST",
            "/api/coord/rooms/delegated/send",
            Some(json!({"body":"targeted-reply","notify":["worker"]})),
        )
        .await;
    assert_eq!(sent.status, 200, "{}", sent.json());
    let attention = f
        .agent(
            "worker",
            "GET",
            "/api/coord/attention/wait?since=0&limit=20&timeout=0",
            None,
        )
        .await
        .json();
    let edge = attention["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["kind"] == "message")
        .unwrap();
    let attention_path = format!(
        "/api/coord/attention/{}/object",
        edge["attention_id"].as_str().unwrap()
    );
    assert_eq!(
        f.agent("worker", "GET", &attention_path, None).await.status,
        200
    );
    let last = sent.json()["sequence"].as_u64().unwrap();
    let wait = start_wait(&f, last).await;
    revoke(&f, &revision).await;
    assert_objects_denied(&f).await;
    assert!(matches!(
        f.agent("worker", "GET", &attention_path, None).await.status,
        403 | 404
    ));
    let hidden = f
        .agent(
            "peer",
            "POST",
            "/api/coord/rooms/delegated/send",
            Some(json!({"body":"after-revoke-hidden","notify":"none"})),
        )
        .await;
    assert_eq!(hidden.status, 200, "{}", hidden.json());
    assert!(!finish_wait(wait).await.contains("after-revoke-hidden"));
    let feed = f
        .agent(
            "worker",
            "GET",
            "/api/coord/attention/wait?since=0&limit=20&timeout=0",
            None,
        )
        .await;
    assert_eq!(feed.json()["edges"], json!([]));
    f = f.restart().await;
    assert_objects_denied(&f).await;
    let (mut current, mut current_revision) = delegate(&f, input).await;
    approve(&f, &["send", "receive"], "regrant").await;
    let history = f
        .agent(
            "worker",
            "GET",
            "/api/coord/rooms/delegated/messages?since=0",
            None,
        )
        .await;
    assert!(
        history.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["body"] == "after-revoke-hidden"),
        "regrant exposes currently retained history"
    );
    let mut last = hidden.json()["sequence"].as_u64().unwrap();
    for cause in ["narrowing", "expiry"] {
        if cause == "expiry" {
            current["expected_revision"] = json!(current_revision);
            current["delegation"]["definition_revisions"] = json!({});
            current["delegation"]["grant_seconds"] = json!(1);
            (current, current_revision) = delegate(&f, current).await;
            approve(&f, &["receive"], "before-expiry").await;
        }
        let cutoff = f
            .agent(
                "worker",
                "GET",
                "/api/coord/attention/wait?since=0&limit=100&timeout=0",
                None,
            )
            .await
            .json()["next_cursor"]
            .as_u64()
            .unwrap();
        let message_wait = start_wait(&f, last).await;
        let attention_wait = start_request_wait(
            &f,
            &format!("/api/coord/attention/wait?since={cutoff}&limit=100&timeout=2"),
        )
        .await;
        if cause == "narrowing" {
            current["expected_revision"] = json!(current_revision);
            current["delegation"]["definition_revisions"] = json!({});
            current["delegation"]["scopes"][0]["permissions"] = json!(["receive"]);
            (current, current_revision) = delegate(&f, current).await;
        } else {
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        assert_objects_denied(&f).await;
        let marker = format!("after-{cause}-hidden");
        let sent = f
            .agent(
                "peer",
                "POST",
                "/api/coord/rooms/delegated/send",
                Some(json!({"body":marker,"notify":"none"})),
            )
            .await;
        assert_eq!(sent.status, 200, "{}", sent.json());
        last = sent.json()["sequence"].as_u64().unwrap();
        assert!(!finish_wait(message_wait).await.contains(&marker));
        let feed = finish_wait(attention_wait).await;
        let body: Value = serde_json::from_str(feed.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["edges"], json!([]), "{cause}: {feed}");
        assert!(matches!(
            f.agent("worker", "GET", &attention_path, None).await.status,
            403 | 404
        ));
    }
    // Restore a standing envelope for the independent old-connection/run test.
    current["expected_revision"] = json!(current_revision);
    current["delegation"]["definition_revisions"] = json!({});
    current["delegation"]["grant_seconds"] = Value::Null;
    delegate(&f, current).await;
    approve(&f, &["receive"], "before-run-replacement").await;
    let wait = start_wait(&f, last).await;
    let _new_backend = Backend(bound_runs(
        &f,
        "abcdef0123456789abcdef0123456789",
        &[("worker", WORKER_ID)],
    ));
    assert_objects_denied(&f).await;
    approve(&f, &["receive"], "replacement-run").await;
    let response = finish_wait(wait).await;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "old wait must not inherit a replacement run's membership: {response}"
    );
    assert_eq!(joined(&f).await.json()["permissions"], json!(["receive"]));
    f.proxy.shutdown().await;
    coord_rooms::stop(f.root.path()).await.unwrap();
}

async fn access(f: &Fixture, permissions: &[&str], operation: &str) -> Reply {
    f.agent(
        "worker",
        "POST",
        "/api/coord/request-access",
        Some(json!({"room_name":"delegated","permissions":permissions,"operation_id":operation})),
    )
    .await
}
async fn revoke(f: &Fixture, revision: &str) {
    let revoked = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
}

#[tokio::test]
async fn room_grant_revoke_preserves_independent_rights_and_original_receipt() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    rooms(&f);
    let (_, revision) = delegate(&f, envelope()).await;
    assert_eq!(
        f.agent("worker", "POST", "/api/coord/rooms/delegated/join", None)
            .await
            .status,
        404
    );
    let pending = access(&f, &["receive"], "first").await;
    assert_eq!(pending.status, 200, "{}", pending.json());
    let id = pending.json()["approval_id"].as_str().unwrap().to_owned();
    assert_eq!(
        access(&f, &["receive"], "first").await.json()["approval_id"],
        id
    );
    let read = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(read.status, 200, "{}", read.json());
    assert_eq!(read.json()["observed"]["permissions"], json!(["receive"]));
    // Deciding authority requires no worker room rights for the reviewer.
    assert_eq!(
        f.agent("helper", "POST", "/api/coord/rooms/delegated/join", None)
            .await
            .status,
        404
    );
    let approved = decide(&f, "helper", &id, "approve", "run").await;
    assert_eq!(approved.status, 200, "{}", approved.json());
    let joined = f
        .agent("worker", "POST", "/api/coord/rooms/delegated/join", None)
        .await;
    assert_eq!(joined.status, 200, "{}", joined.json());
    assert_eq!(joined.json()["permissions"], json!(["receive"]));
    assert_eq!(
        f.agent(
            "worker",
            "POST",
            "/api/coord/rooms/delegated/send",
            Some(json!({"body":"forbidden"}))
        )
        .await
        .status,
        403
    );
    let retry = access(&f, &["receive"], "first").await;
    assert_eq!(retry.status, 200, "{}", retry.json());
    assert_eq!(retry.json()["approval_id"], id);
    assert_eq!(retry.json()["status"], "approved");
    // An independent source survives removal of the derived membership.
    coord_rooms::grant(
        &f.root.path().join("config.toml"),
        "delegated",
        "worker",
        &["send".into()],
        false,
        Some("independent"),
    )
    .unwrap();
    revoke(&f, &revision).await;
    let joined = f
        .agent("worker", "POST", "/api/coord/rooms/delegated/join", None)
        .await;
    assert_eq!(joined.status, 200, "{}", joined.json());
    assert_eq!(joined.json()["permissions"], json!(["send"]));
    f.proxy.shutdown().await;
}
