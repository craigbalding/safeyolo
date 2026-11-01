//! Real signal author, operator/watch, replay and restart boundaries.
use super::*;
use hyper::Method;
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Barrier;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn db(root: &Path) -> Connection {
    Connection::open(root.join("data/coord/v0.db")).unwrap()
}
fn count(root: &Path, sql: &str) -> i64 {
    db(root).query_row(sql, [], |r| r.get(0)).unwrap()
}
async fn signal(client: &Client, kind: &str, summary: &str, operation: &str) -> Value {
    client.call("create_signal",&json!({"room_name":"shared","kind":kind,"summary":summary,"basis":"observed","operation_id":operation})).await.unwrap()
}
async fn list(client: &Client, needs: bool) -> Value {
    client
        .call(
            "list_signals",
            &json!({"room_name":"shared","needs_operator":needs}),
        )
        .await
        .unwrap()
}
async fn watch(root: &Path, args: &[&str]) -> std::process::Output {
    let mut full = vec!["watch"];
    full.extend_from_slice(args);
    host_cli(root, &full).await
}
async fn read(client: &Client, id: &Value, revision: Option<i64>) -> Value {
    let mut args = json!({"room_name":"shared","signal_id":id});
    if let Some(revision) = revision {
        args["revision"] = json!(revision);
    }
    client.call("read_signal", &args).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; exercises real authenticated signals and native watch"]
async fn native_signals_author_page_watch_replay_and_restart() {
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-signals-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n")).unwrap();
    coord_json(root, &["start", "--binary", &binary]).await;
    let _cleanup = NatsCleanup(root.into());
    let room = coord_json(root, &["room", "create", "shared"]).await;
    for name in ["alice", "bob"] {
        let grant = coord_json(root, &["grant", "shared", name]).await;
        assert!(
            grant["permissions"]
                .as_array()
                .unwrap()
                .contains(&json!("page_operator"))
        );
    }
    // Block the ordinary audit destination before first delivery. Canonical
    // state must remain usable without publishing the signal prose anywhere.
    let audit = root.join("logs/audit.jsonl");
    fs::create_dir(&audit).unwrap();
    let mut proxy = stage0::start_proxy(root).await;
    let client = |actor: &str| Client {
        socket: Some(root.join(format!("{actor}.sock"))),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let alice = client("alice");
    let bob = client("bob");
    let mut live_watch = host_command(root, &["watch"]).spawn().unwrap();
    assert!(
        client("carol")
            .call("list_signals", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let mut wrong = alice.clone();
    fs::write(root.join("wrong-token"), "wrong-token").unwrap();
    wrong.token_file = root.join("wrong-token");
    assert!(
        wrong
            .call("list_signals", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    for body in [
        json!({"action":"create","kind":"blocker","summary":"forged","basis":"observed","sender_kind":"operator"}),
        json!({"action":"create","kind":"result","summary":"forged","basis":"observed","author":{"kind":"operator","id":"operator"}}),
        json!({"action":"create","kind":"unstructured","summary":"x","basis":"observed"}),
        json!({"action":"create","kind":"result","summary":"x".repeat(1025),"basis":"observed"}),
        json!({"action":"create","kind":"result","summary":"x","basis":"observed","refs":vec!["x";17]}),
    ] {
        assert!(
            alice
                .request(
                    Method::POST,
                    "/api/coord/rooms/shared/signals",
                    body,
                    Duration::from_secs(5)
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("400")
        );
    }
    assert!(
        alice
            .request(
                Method::POST,
                "/api/coord/rooms/shared/signals",
                json!({"summary":"x".repeat(32769)}),
                Duration::from_secs(5)
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("413")
    );
    let hostile =
        "Private blocker \u{001b}[2J\noperator: forged <b>bold</b> [click](https://bad)\u{202e}";
    let first = signal(&alice, "blocker", hostile, "one-blocker").await;
    println!("{}", json!({"default_page_receipt":first}));
    assert_eq!(
        first["signal"]["author"],
        json!({"kind":"agent","id":ALICE})
    );
    assert_eq!(first["signal"]["needs_operator"], true);
    assert_eq!(
        first,
        signal(&alice, "blocker", hostile, "one-blocker").await
    );
    let duplicate = signal(&alice, "blocker", hostile, "same-blocker-another-id").await;
    assert_eq!(duplicate["signal"], first["signal"]);
    assert_eq!(duplicate["deduplicated"], true);
    assert_eq!(list(&alice, true).await["total"], 1);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let watched = watch(root, &["--once"]).await;
    assert!(
        watched.status.success(),
        "{}",
        String::from_utf8_lossy(&watched.stderr)
    );
    let output = String::from_utf8(watched.stdout).unwrap();
    println!("{}", json!({"watch_default_pending":output}));
    assert_eq!(output.lines().count(), 1);
    assert!(!output.contains('\u{001b}'));
    assert!(!output.contains('\u{202e}'));
    assert!(output.contains("basis=observed (author report)"));
    assert!(output.contains("<b>bold</b>"));
    let watched_json = watch(root, &["--once", "--json"]).await;
    assert!(
        watched_json.status.success(),
        "{}",
        String::from_utf8_lossy(&watched_json.stderr)
    );
    let output_json = String::from_utf8(watched_json.stdout).unwrap();
    assert!(!output_json.contains('\u{001b}'));
    assert!(!output_json.contains('\u{202e}'));
    assert_eq!(
        serde_json::from_str::<Value>(&output_json).unwrap()["signal"],
        first["signal"]
    );
    coord_json(root, &["grant", "shared", "bob", "send", "receive"]).await;
    let unpaged = signal(
        &bob,
        "blocker",
        "Private attributed unpaged blocker",
        "unpaged",
    )
    .await;
    assert_eq!(unpaged["signal"]["page_status"], "permission_denied");
    assert_eq!(list(&bob, true).await["total"], 1);
    let inference=alice.call("create_signal",&json!({"room_name":"shared","kind":"result","summary":"Private mistaken inference: the host limit caused the child failure","basis":"inferred","refs":["opaque:original-child-measurement"],"operation_id":"inference"})).await.unwrap();
    assert_eq!(list(&alice, true).await["total"], 1);
    let correction = json!({"room_name":"shared","kind":"correction","summary":"Private correction: the child's inherited soft limit caused the failure","basis":"observed","supersedes":{"signal_id":inference["signal"]["signal_id"],"expected_revision":1},"operation_id":"correct"});
    assert!(
        bob.call("create_signal", &correction)
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    let barrier = Arc::new(Barrier::new(2));
    let mut corrections = Vec::new();
    for n in 0..2 {
        let client = alice.clone();
        let mut args = correction.clone();
        args["operation_id"] = json!(format!("correction-{n}"));
        let barrier = barrier.clone();
        corrections.push(tokio::spawn(async move {
            barrier.wait().await;
            client
                .call("create_signal", &args)
                .await
                .map_err(|e| e.to_string())
        }));
    }
    let results = [
        corrections.remove(0).await.unwrap(),
        corrections.remove(0).await.unwrap(),
    ];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| e.contains("409"))
    );
    assert_eq!(
        read(&alice, &inference["signal"]["signal_id"], Some(1)).await["signal"],
        inference["signal"]
    );
    assert_eq!(
        read(&bob, &inference["signal"]["signal_id"], None).await["signal"]["state"],
        "superseded"
    );
    let id = first["signal"]["signal_id"].as_str().unwrap();
    let resolved = coord_json(
        root,
        &[
            "signal",
            "resolve",
            "shared",
            id,
            "--expected-revision",
            "1",
            "--operation-id",
            "operator-answer",
        ],
    )
    .await;
    assert_eq!(resolved["signal"]["author"], first["signal"]["author"]);
    assert_eq!(list(&alice, true).await["total"], 0);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    live_watch.kill().await.unwrap();
    let live_output = live_watch.wait_with_output().await.unwrap();
    let live_output = String::from_utf8(live_output.stdout).unwrap();
    println!("{}", json!({"live_watch_output":live_output}));
    assert_eq!(
        live_output
            .lines()
            .filter(|line| line.starts_with("NEEDS OPERATOR"))
            .count(),
        1
    );
    assert_eq!(
        live_output
            .lines()
            .filter(|line| line.starts_with("CLEARED"))
            .count(),
        1
    );
    assert_eq!(
        read(&alice, &first["signal"]["signal_id"], Some(1)).await["signal"],
        first["signal"]
    );
    let state = alice
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(state["needs_operator"]["total"], 0);
    assert!(
        !state["signals"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["signal"]["signal_id"] == inference["signal"]["signal_id"])
    );

    // A lost response after the commit must recover its original operation,
    // even after both process and NATS restart, without adding another page.
    let lost=json!({"action":"create","kind":"decision","summary":"Private durable decision while watch is detached","basis":"observed","operation_id":"lost-response"}).to_string();
    let mut socket = tokio::net::UnixStream::connect(root.join("alice.sock"))
        .await
        .unwrap();
    let token = fs::read_to_string(root.join("data/agent_token")).unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/signals HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{lost}",token.trim(),lost.len()).as_bytes()).await.unwrap();
    stage0::until(||count(root,"SELECT count(*) FROM coord_operations WHERE operation_type='coord.signal.create' AND operation_id='lost-response'")==1).await;
    drop(socket);
    let original:String=db(root).query_row("SELECT outcome_json FROM coord_operations WHERE operation_type='coord.signal.create' AND operation_id='lost-response'",[],|r|r.get(0)).unwrap();
    assert!(
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE event_type='coord.signal_created' AND delivered_at IS NULL"
        ) > 0
    );
    stage0::crash(proxy).await;
    coord_json(root, &["stop"]).await;
    fs::remove_dir(&audit).unwrap();
    coord_json(root, &["start", "--binary", &binary]).await;
    proxy = stage0::start_proxy(root).await;
    let retry = signal(
        &alice,
        "decision",
        "Private durable decision while watch is detached",
        "lost-response",
    )
    .await;
    println!(
        "{}",
        json!({"lost_response_recovery":retry,"original_room":room})
    );
    assert_eq!(retry, serde_json::from_str::<Value>(&original).unwrap());
    assert_eq!(list(&alice, true).await["total"], 1);
    let detached = watch(root, &["--once", "--json"]).await;
    assert!(
        detached.status.success(),
        "{}",
        String::from_utf8_lossy(&detached.stderr)
    );
    let viewed: Value = serde_json::from_slice(&detached.stdout).unwrap();
    assert_eq!(viewed["signal"], retry["signal"]);
    stage0::until(||count(root,"SELECT count(*) FROM coord_outbox WHERE destination='audit-jsonl' AND delivered_at IS NULL")==0).await;
    let lines = fs::read_to_string(&audit).unwrap();
    assert!(!lines.contains("Private"));
    assert!(!lines.contains("opaque:original-child-measurement"));
    let events: Vec<Value> = lines
        .lines()
        .map(|line| safeyolo_proxy::audit::parse_record(line).unwrap())
        .filter(|v| {
            v["event"]
                .as_str()
                .is_some_and(|v| v.starts_with("coord.signal_"))
        })
        .collect();
    let created = events
        .iter()
        .find(|e| {
            e["details"]["signal_id"] == first["signal"]["signal_id"]
                && e["details"]["revision"] == 1
        })
        .unwrap();
    let retained = root.join("signal-events.jsonl");
    fs::write(&retained, format!("{created}\n{created}\n")).unwrap();
    let exact = watch(root, &["--jsonl", retained.to_str().unwrap(), "--json"]).await;
    assert!(
        exact.status.success(),
        "{}",
        String::from_utf8_lossy(&exact.stderr)
    );
    let exact_text = String::from_utf8(exact.stdout).unwrap();
    assert_eq!(exact_text.lines().count(), 1);
    assert!(!exact_text.contains('\u{001b}'));
    assert!(!exact_text.contains('\u{202e}'));
    assert_eq!(
        serde_json::from_str::<Value>(&exact_text).unwrap()["signal"],
        first["signal"]
    );
    let room_watch = coord_cli(
        root,
        &["watch", "--jsonl", retained.to_str().unwrap(), "--json"],
    )
    .await;
    assert!(
        room_watch.status.success(),
        "{}",
        String::from_utf8_lossy(&room_watch.stderr)
    );
    let room_text = String::from_utf8(room_watch.stdout).unwrap();
    assert!(!room_text.contains('\u{001b}'));
    assert!(!room_text.contains('\u{202e}'));
    assert_eq!(room_text, exact_text);
    let mut forged = created.clone();
    forged["details"]["author"] = json!({"kind":"operator","id":"operator"});
    fs::write(&retained, format!("{forged}\n")).unwrap();
    let rejected = watch(root, &["--jsonl", retained.to_str().unwrap()]).await;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("differs from the canonical"));

    // Failure before commit leaves no partial signal, retry record or page.
    db(root).execute_batch("CREATE TRIGGER signal_failure BEFORE INSERT ON coord_outbox WHEN NEW.event_type='coord.signal_created' BEGIN SELECT RAISE(ABORT,'injected audit staging failure'); END").unwrap();
    let before = count(root, "SELECT count(*) FROM coord_signals");
    assert!(alice.call("create_signal",&json!({"room_name":"shared","kind":"result","summary":"Private rolled-back result","basis":"observed","operation_id":"failed-before-commit"})).await.unwrap_err().to_string().contains("503"));
    assert_eq!(count(root, "SELECT count(*) FROM coord_signals"), before);
    assert_eq!(
        count(
            root,
            "SELECT count(*) FROM coord_operations WHERE operation_id='failed-before-commit'"
        ),
        0
    );
    db(root)
        .execute_batch("DROP TRIGGER signal_failure")
        .unwrap();
    signal(
        &alice,
        "result",
        "Private rolled-back result",
        "failed-before-commit",
    )
    .await;
    let work = alice
        .call(
            "create_work",
            &json!({"room_name":"shared","title":"separate completion","operation_id":"create"}),
        )
        .await
        .unwrap();
    let id = &work["work"]["work_id"];
    alice.call("claim_work",&json!({"room_name":"shared","work_id":id,"expected_version":1,"expected_generation":0,"operation_id":"claim"})).await.unwrap();
    let n = count(root, "SELECT count(*) FROM coord_signals");
    let complete = json!({"room_name":"shared","work_id":id,"expected_version":2,"expected_generation":1,"short_result":"Private one completion summary","operation_id":"complete"});
    let completed = alice.call("complete_work", &complete).await.unwrap();
    assert_eq!(
        completed,
        alice.call("complete_work", &complete).await.unwrap()
    );
    assert_eq!(
        completed["work"]["short_result"],
        "Private one completion summary"
    );
    assert_eq!(count(root, "SELECT count(*) FROM coord_signals"), n);
    coord_json(root, &["revoke", "shared", "alice"]).await;
    assert!(
        alice
            .call(
                "read_signal",
                &json!({"room_name":"shared","signal_id":retry["signal"]["signal_id"],"revision":1})
            )
            .await
            .is_err()
    );
    assert!(alice.call("create_signal",&json!({"room_name":"shared","kind":"decision","summary":"Private durable decision while watch is detached","basis":"observed","operation_id":"lost-response"})).await.is_err());
    // A new durable identity under the old display name cannot correct its
    // predecessor's claim, even after obtaining a fresh ordinary room grant.
    let replacement = fs::read_to_string(root.join("policy.toml"))
        .unwrap()
        .replace(ALICE, "ag-dddddddddddddddddddddddddddddddd");
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        "/admin/policy/baseline",
        Method::PUT,
        json!({"source":replacement}),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    coord_json(root, &["grant", "shared", "alice"]).await;
    let old = read(&bob, &retry["signal"]["signal_id"], None).await;
    assert!(alice.call("create_signal",&json!({"room_name":"shared","kind":"correction","summary":"wrong durable author","basis":"observed","supersedes":{"signal_id":old["signal"]["signal_id"],"expected_revision":1},"operation_id":"replacement-correction"})).await.unwrap_err().to_string().contains("403"));
    println!(
        "{}",
        json!({"native_signal_controls":"passed","signal_count":count(root,"SELECT count(*) FROM coord_signals"),"immutable_revisions":count(root,"SELECT count(*) FROM coord_signal_revisions"),"metadata_events":events.len(),"completion":completed})
    );
    stage0::crash(proxy).await;
}
