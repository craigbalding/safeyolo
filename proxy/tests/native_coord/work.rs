//! Real authenticated work mutations, process crashes and retained ownership.
use super::*;
use hyper::Method;
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Barrier;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
async fn change(
    client: &Client,
    action: &str,
    work: &Value,
    operation: &str,
) -> Result<Value, safeyolo_proxy::Error> {
    client.call(&format!("{action}_work"),&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"operation_id":operation})).await
}
async fn read(client: &Client, work: &Value) -> Value {
    client
        .call(
            "read_work",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap()
}
async fn create(client: &Client, title: &str) -> Value {
    client.call("create_work",&json!({"room_name":"shared","title":title,"external_ref":"github://unavailable/changed-description","operation_id":title})).await.unwrap()["work"].clone()
}
fn db(root: &Path) -> Connection {
    Connection::open(root.join("data/coord/v0.db")).unwrap()
}
fn count(root: &Path, sql: &str) -> i64 {
    db(root).query_row(sql, [], |r| r.get(0)).unwrap()
}
async fn baseline(root: &Path, source: &str) {
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        "/admin/policy/baseline",
        Method::PUT,
        json!({"source":source}),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; set SAFEYOLO_WORK_RETAIN_SECONDS=1800 for real duration proof"]
async fn native_work_claims_replay_identity_revocation_and_crash_recovery() {
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-work-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    let config = "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n";
    let original = format!(
        "[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n"
    );
    fs::write(root.join("config.toml"), config).unwrap();
    fs::write(root.join("policy.toml"), &original).unwrap();
    coord_json(root, &["start", "--binary", &binary]).await;
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    for actor in ["alice", "bob"] {
        coord_json(root, &["grant", "shared", actor]).await;
    }
    let mut proxy = stage0::start_proxy(root).await;
    let client = |actor: &str| Client {
        socket: Some(root.join(format!("{actor}.sock"))),
        token_file: root.join("data/agent_token"),
    };
    let alice = client("alice");
    let bob = client("bob");
    for body in [
        json!({"action":"create","title":"forged","created_by":{"kind":"operator","id":"operator"}}),
        json!({"action":"create","title":"forged","claim_agent_id":BOB}),
        json!({"action":"create","title":"forged","operation_id":3}),
    ] {
        assert!(
            alice
                .request(
                    Method::POST,
                    "/api/coord/rooms/shared/work",
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
        client("carol")
            .call("list_work", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let mut wrong_token = alice.clone();
    fs::write(root.join("wrong-token"), "not-the-instance-token").unwrap();
    wrong_token.token_file = root.join("wrong-token");
    assert!(
        wrong_token
            .call("list_work", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    for attempts in [2, 100] {
        let open = create(&alice, &format!("concurrent-{attempts}")).await;
        let barrier = Arc::new(Barrier::new(attempts));
        let futures: Vec<_> = (0..attempts)
            .map(|n| {
                let client = if n % 2 == 0 {
                    alice.clone()
                } else {
                    bob.clone()
                };
                let open = open.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    change(&client, "claim", &open, &format!("claim-{attempts}-{n}"))
                        .await
                        .map_err(|e| e.to_string())
                })
            })
            .collect();
        let mut receipts = Vec::new();
        let mut failures = Vec::new();
        for future in futures {
            match future.await.unwrap() {
                Ok(value) => receipts.push(value),
                Err(error) => failures.push(error),
            }
        }
        assert_eq!(receipts.len(), 1, "{failures:?}");
        assert_eq!(failures.len(), attempts - 1);
        assert!(failures.iter().all(|e| e.contains("409")), "{failures:?}");
        let work = read(&alice, &open).await;
        assert_eq!(work, receipts[0]["work"]);
        println!(
            "{}",
            json!({"concurrent_attempts":attempts,"successes":receipts,"conflicts":failures.len()})
        );
    }
    let open = create(&alice, "retained-owner").await;
    let held = change(&bob, "claim", &open, "retain-claim").await.unwrap();
    let retained_at = std::time::Instant::now();
    println!(
        "{}",
        json!({"retention_started":time::OffsetDateTime::now_utc().unix_timestamp(),"receipt":held})
    );
    assert_eq!(held["work"]["claim_agent_id"], BOB);
    assert_eq!(held["work"]["claim_expires_at"], Value::Null);
    assert_eq!(
        change(&bob, "claim", &open, "retain-claim").await.unwrap(),
        held
    );
    assert!(
        change(&bob, "claim", &held["work"], "retain-claim")
            .await
            .unwrap_err()
            .to_string()
            .contains("409")
    );
    assert!(
        change(&alice, "release", &held["work"], "non-holder")
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );

    // An accepted response is deliberately left unread, as with a lost client response.
    let ambiguous = create(&alice, "ambiguous-response").await;
    let body=json!({"action":"claim","work_id":ambiguous["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"lost-response"}).to_string();
    let mut socket = tokio::net::UnixStream::connect(root.join("alice.sock"))
        .await
        .unwrap();
    let token = fs::read_to_string(root.join("data/agent_token")).unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/work HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",token.trim(),body.len()).as_bytes()).await.unwrap();
    stage0::until(|| {
        count(
            root,
            "SELECT count(*) FROM coord_operations WHERE operation_id='lost-response'",
        ) == 1
    })
    .await;
    drop(socket);
    let original_result: String = db(root)
        .query_row(
            "SELECT outcome_json FROM coord_operations WHERE operation_id='lost-response'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    stage0::crash(proxy).await;
    coord_json(root, &["stop"]).await;
    coord_json(root, &["start", "--binary", &binary]).await;
    proxy = stage0::start_proxy(root).await;
    assert_eq!(
        change(&alice, "claim", &ambiguous, "lost-response")
            .await
            .unwrap(),
        serde_json::from_str::<Value>(&original_result).unwrap()
    );
    assert_eq!(read(&alice, &open).await, held["work"]);

    // The real write transaction is blocked before mutation, then its process dies.
    let interrupted = create(&alice, "before-commit-interruption").await;
    let lock = db(root);
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let pending = {
        let alice = alice.clone();
        let work = interrupted.clone();
        tokio::spawn(async move {
            change(&alice, "claim", &work, "interrupted")
                .await
                .map_err(|e| e.to_string())
        })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    stage0::crash(proxy).await;
    lock.execute_batch("ROLLBACK").unwrap();
    assert!(pending.await.unwrap().is_err());
    assert_eq!(
        count(
            root,
            "SELECT count(*) FROM coord_operations WHERE operation_id='interrupted'"
        ),
        0
    );
    proxy = stage0::start_proxy(root).await;
    let committed = change(&alice, "claim", &interrupted, "interrupted")
        .await
        .unwrap();
    assert_eq!(committed["work"]["claim_generation"], 1);
    let first = change(&alice, "release", &committed["work"], "release")
        .await
        .unwrap()["work"]
        .clone();
    let second = change(&bob, "claim", &first, "new-generation")
        .await
        .unwrap()["work"]
        .clone();
    assert_eq!(second["claim_generation"], 2);
    for action in ["release", "complete"] {
        assert!(
            change(&alice, action, &committed["work"], "former-holder")
                .await
                .unwrap_err()
                .to_string()
                .contains("409")
        );
    }
    coord_json(root, &["revoke", "shared", "bob"]).await;
    for action in ["release", "complete"] {
        assert!(change(&bob, action, &second, "revoked").await.is_err());
    }
    let version = second["version"].as_i64().unwrap().to_string();
    let id = second["work_id"].as_str().unwrap();
    let recovered = coord_json(
        root,
        &[
            "work",
            "reassign",
            "shared",
            id,
            "--agent-id",
            ALICE,
            "--expected-version",
            &version,
            "--expected-generation",
            "2",
            "--operation-id",
            "operator-recover",
        ],
    )
    .await;
    assert_eq!(recovered["work"]["claim_generation"], 3);
    coord_json(root, &["grant", "shared", "bob"]).await;
    // Current rename and native identity replacement retain the original holder ID.
    baseline(root, &original.replace("agents.bob", "agents.robert")).await;
    stage0::crash(proxy).await;
    fs::write(
        root.join("config.toml"),
        config.replace("agent_id='bob'", "agent_id='robert'"),
    )
    .unwrap();
    proxy = stage0::start_proxy(root).await;
    assert_eq!(read(&bob, &open).await["claim_agent_id"], BOB);
    assert_eq!(
        change(&bob, "claim", &open, "retain-claim").await.unwrap(),
        held
    );
    baseline(root, &original).await;
    stage0::crash(proxy).await;
    fs::write(root.join("config.toml"), config).unwrap();
    proxy = stage0::start_proxy(root).await;
    let mut document = original.parse::<toml_edit::DocumentMut>().unwrap();
    document["agents"]
        .as_table_like_mut()
        .unwrap()
        .remove("bob");
    baseline(root, &document.to_string()).await;
    let created = host_cli(
        root,
        &[
            "agent",
            "create",
            "bob",
            "--workspace",
            root.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let replacement: Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_ne!(replacement["configuration"]["id"], BOB);
    coord_json(root, &["grant", "shared", "bob"]).await;
    assert!(
        change(&bob, "release", &held["work"], "replacement")
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    assert_eq!(read(&bob, &open).await["claim_agent_id"], BOB);

    // Canonical external content is independent of the opaque ownership reference.
    fs::write(
        root.join("external-description.md"),
        "external description v1",
    )
    .unwrap();
    // This failing HTTP fixture stands in for an unavailable external issue host.
    // The direct control observes 503, then the listener is removed completely.
    let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = unavailable.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = unavailable.accept().await.unwrap();
        let mut request = [0; 1024];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let mut control = tokio::net::TcpStream::connect(address).await.unwrap();
    control
        .write_all(b"GET /issue HTTP/1.1\r\nHost: external-issue\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut failure = String::new();
    control.read_to_string(&mut failure).await.unwrap();
    assert!(failure.starts_with("HTTP/1.1 503"));
    server.await.unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    let reference = format!("http://{address}/issue");
    let external=alice.call("create_work",&json!({"room_name":"shared","title":"external-system-unavailable","external_ref":reference})).await.unwrap()["work"].clone();
    let claimed = change(&alice, "claim", &external, "external-claim")
        .await
        .unwrap()["work"]
        .clone();
    fs::write(
        root.join("external-description.md"),
        "external description v2; different assignee",
    )
    .unwrap();
    assert_eq!(read(&alice, &external).await, claimed);
    let released = change(&alice, "release", &claimed, "external-release")
        .await
        .unwrap()["work"]
        .clone();
    let claimed = change(&alice, "claim", &released, "external-reclaim")
        .await
        .unwrap()["work"]
        .clone();
    let done=alice.call("complete_work",&json!({"room_name":"shared","work_id":claimed["work_id"],"expected_version":claimed["version"],"expected_generation":claimed["claim_generation"],"short_result":"Private result: external service stayed unavailable"})).await.unwrap();
    assert_eq!(done["work"]["state"], "done");
    println!(
        "{}",
        json!({"external_failure_control":"HTTP 503 followed by refused connection","reference":reference,"description_changed":true,"completion_receipt":done})
    );
    let attention = alice
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"limit":200,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    let edge = attention["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["object_id"] == open["work_id"] && e["revision_or_sequence"] == 2)
        .unwrap();
    let resolved = alice
        .call(
            "read_attention",
            &json!({"attention_id":edge["attention_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(resolved["object"], held["work"]);
    // Restart after a committed work update while publication is unavailable.
    coord_json(root, &["stop"]).await;
    let offline = change(&alice, "release", &recovered["work"], "offline-release")
        .await
        .unwrap();
    stage0::crash(proxy).await;
    let pending: Vec<(String, String)> = db(root)
        .prepare("SELECT event_id,payload_json FROM coord_outbox WHERE delivered_at IS NULL")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!pending.is_empty());
    coord_json(root, &["start", "--binary", &binary]).await;
    proxy = stage0::start_proxy(root).await;
    stage0::until(|| {
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE delivered_at IS NULL",
        ) == 0
    })
    .await;
    for (id, payload) in pending {
        assert_eq!(
            db(root)
                .query_row(
                    "SELECT payload_json FROM coord_outbox WHERE event_id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            payload
        );
    }
    assert_eq!(
        change(&alice, "release", &recovered["work"], "offline-release")
            .await
            .unwrap(),
        offline
    );
    let audit_path = native_config::read(&root.join("config.toml"))
        .unwrap()
        .audit_log_path
        .unwrap();
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(!audit.contains("Private result"));
    assert!(!audit.contains("github://unavailable"));
    let seconds = std::env::var("SAFEYOLO_WORK_RETAIN_SECONDS")
        .unwrap_or("0".into())
        .parse::<u64>()
        .unwrap();
    let remaining = Duration::from_secs(seconds).saturating_sub(retained_at.elapsed());
    println!(
        "{}",
        json!({"retention_wait_seconds":remaining.as_secs(),"holder_process":"no persistent model/MCP process","work":held["work"]})
    );
    tokio::time::sleep(remaining).await;
    stage0::crash(proxy).await;
    coord_json(root, &["stop"]).await;
    coord_json(root, &["start", "--binary", &binary]).await;
    proxy = stage0::start_proxy(root).await;
    assert_eq!(read(&alice, &open).await, held["work"]);
    let elapsed = retained_at.elapsed().as_secs_f64();
    assert!(elapsed >= seconds as f64);
    let final_held = read(&alice, &open).await;
    let forced = coord_json(
        root,
        &[
            "work",
            "release",
            "shared",
            open["work_id"].as_str().unwrap(),
            "--expected-version",
            "2",
            "--expected-generation",
            "1",
            "--operation-id",
            "abandoned-holder-recovery",
        ],
    )
    .await;
    assert_eq!(forced["work"]["state"], "open");
    assert_eq!(
        change(&alice, "claim", &forced["work"], "after-duration")
            .await
            .unwrap()["work"]["claim_generation"],
        2
    );
    println!(
        "{}",
        json!({"retained_seconds":elapsed,"thirty_minutes_observed":elapsed>=1800.0,"original_receipt":held,"final_work_before_explicit_recovery":final_held,"replacement_id":replacement["configuration"]["id"],"forced_release":forced})
    );
    stage0::crash(proxy).await;
}
