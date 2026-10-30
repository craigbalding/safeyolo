//! Exact candidate evidence through authenticated Agent API, real NATS and CLI.
use super::*;
use hyper::Method;
use rusqlite::Connection;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CAROL: &str = "ag-cccccccccccccccccccccccccccccccc";

fn db(root: &Path) -> Connection {
    Connection::open(root.join("data/coord/v0.db")).unwrap()
}
fn count(root: &Path, sql: &str) -> i64 {
    db(root).query_row(sql, [], |r| r.get(0)).unwrap()
}
fn target(work: &Value) -> Value {
    json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],
        "expected_target_generation":work["target_generation"],"target_ref":"https://github.com/craigbalding/safeyolo/pull/1311"})
}
fn evidence(work: &Value, operation: &str) -> Value {
    json!({"room_name":"shared","work_id":work["work_id"],"target_generation":work["target_generation"],"kind":"acceptance","verdict":"approve",
        "summary":"Private evidence π\n\u{001b}[2J\u{202e}","evidence_refs":["https://untrusted.invalid/private-evidence"],"operation_id":operation})
}
async fn state(client: &Client) -> Value {
    client
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap()
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
async fn change(client: &Client, work: &Value, operation: &str) -> Value {
    let mut input = target(work);
    input["operation_id"] = json!(operation);
    client.call("change_work_target", &input).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; exact-target identity, authenticated evidence and interruption controls"]
async fn native_attestations_exact_candidate_authorship_replay_and_recovery() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-attestations-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.carol]\nagent_id='{CAROL}'\n")).unwrap();
    coord_json(root, &["start", "--binary", &nats]).await;
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    for actor in ["alice", "bob", "carol"] {
        coord_json(root, &["grant", "shared", actor]).await;
    }
    let mut proxy = stage0::start_proxy(root).await;
    let client = |actor: &str| Client {
        socket: Some(root.join(format!("{actor}.sock"))),
        token_file: root.join("data/agent_token"),
    };
    let alice = client("alice");
    let bob = client("bob");
    let carol = client("carol");
    let open=alice.call("create_work",&json!({"room_name":"shared","title":"Review the real Stage6 room status candidate","external_ref":"https://github.com/craigbalding/safeyolo/issues/1310","operation_id":"create"})).await.unwrap();
    let mut work=alice.call("claim_work",&json!({"room_name":"shared","work_id":open["work"]["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"claim"})).await.unwrap()["work"].clone();
    for n in 1..=3 {
        work = change(&alice, &work, &format!("candidate-{n}")).await["work"].clone();
    }
    let old_input = evidence(&work, "bob-3");
    let old = bob.call("attest_work", &old_input).await.unwrap();
    assert_eq!(old["attestation"]["author"]["id"], BOB);
    let mut forged = old_input.clone();
    forged.as_object_mut().unwrap().remove("room_name");
    forged["action"] = json!("attest");
    forged["author"] = json!({"kind":"agent","id":BOB});
    assert!(
        alice
            .request(
                Method::POST,
                "/api/coord/rooms/shared/work",
                forged,
                Duration::from_secs(5)
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("400")
    );
    // The owning-host target operation uses the same core and advances a reused PR ref.
    work = coord_json(
        root,
        &[
            "work",
            "change-target",
            "shared",
            work["work_id"].as_str().unwrap(),
            "--expected-version",
            &old["work"]["version"].to_string(),
            "--expected-target-generation",
            "3",
            "--target-ref",
            work["target_ref"].as_str().unwrap(),
            "--operation-id",
            "squash",
        ],
    )
    .await["work"]
        .clone();
    assert_eq!(work["target_generation"], 4);
    let stale_state = state(&alice).await;
    let stale = &stale_state["active_work"]["items"][0]["attestations"];
    assert_eq!(
        stale["current_acceptance"],
        json!({"approve":0,"reject":0,"abstain":0})
    );
    assert_eq!(stale["items"][0]["current"], false);
    let text = coord_cli(root, &["status", "shared"]).await;
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("no current acceptance attestations")
    );
    assert_eq!(bob.call("attest_work", &old_input).await.unwrap(), old);
    let input = evidence(&work, "bob-4");
    let mut reject = evidence(&work, "carol-4");
    reject["verdict"] = json!("reject");
    let (approval, rejection) = tokio::join!(
        bob.call("attest_work", &input),
        carol.call("attest_work", &reject)
    );
    let approval = approval.unwrap();
    let rejection = rejection.unwrap();
    assert_eq!(approval["attestation"]["target_generation"], 4);
    assert_eq!(rejection["attestation"]["author"]["id"], CAROL);
    let current = state(&alice).await;
    let projected = &current["active_work"]["items"][0];
    assert_eq!(
        projected["attestations"]["current_acceptance"],
        json!({"approve":1,"reject":1,"abstain":0})
    );
    assert_eq!(projected["claim_agent_id"], ALICE);
    assert_eq!(projected["claim_generation"], 1);
    assert_eq!(projected["state"], "claimed");
    assert_eq!(
        coord_json(root, &["status", "shared", "--json"]).await,
        current
    );
    let text = String::from_utf8(coord_cli(root, &["status", "shared"]).await.stdout).unwrap();
    assert!(
        text.contains("approve=1 reject=1 abstain=0") && text.contains(BOB) && text.contains(CAROL)
    );
    assert!(!text.contains('\u{001b}') && !text.contains('\u{202e}'));
    let listed = bob
        .call(
            "list_work_attestations",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 3);
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["attestation"] == old["attestation"] && item["current"] == false)
    );
    assert_eq!(
        coord_json(
            root,
            &[
                "work",
                "attestations",
                "shared",
                work["work_id"].as_str().unwrap()
            ]
        )
        .await,
        listed
    );
    assert!(
        bob.call(
            "list_work_attestations",
            &json!({"room_name":"shared","work_id":work["work_id"],"limit":0})
        )
        .await
        .is_err()
    );
    assert!(
        bob.request(
            Method::GET,
            "/api/coord/rooms/shared/work?attestations=true",
            Value::Null,
            Duration::from_secs(5)
        )
        .await
        .is_err()
    );
    let mut wrong_token = alice.clone();
    fs::write(root.join("wrong-token"), "wrong").unwrap();
    wrong_token.token_file = root.join("wrong-token");
    assert!(
        wrong_token
            .call(
                "list_work_attestations",
                &json!({"room_name":"shared","work_id":work["work_id"]})
            )
            .await
            .is_err()
    );
    println!(
        "{}",
        json!({"generation3":old,"stale_generation4":stale_state,"generation4_approve":approval,"generation4_reject":rejection,"current_state":current})
    );

    // Interrupt each new mutation while SQLite prevents entry to its transaction.
    for action in ["change_work_target", "attest_work"] {
        work = read(&alice, &work).await;
        let mut input = if action == "attest_work" {
            evidence(&work, action)
        } else {
            target(&work)
        };
        input["operation_id"] = json!(action);
        let lock = db(root);
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        let pending = {
            let client = alice.clone();
            let input = input.clone();
            tokio::spawn(
                async move { client.call(action, &input).await.map_err(|e| e.to_string()) },
            )
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        stage0::crash(proxy).await;
        lock.execute_batch("ROLLBACK").unwrap();
        assert!(pending.await.unwrap().is_err());
        assert_eq!(
            db(root)
                .query_row(
                    "SELECT count(*) FROM coord_operations WHERE operation_id=?1",
                    [action],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        proxy = stage0::start_proxy(root).await;
        let receipt = alice.call(action, &input).await.unwrap();
        assert_eq!(alice.call(action, &input).await.unwrap(), receipt);
        println!(
            "{}",
            json!({"before_commit_recovered":action,"input":input,"receipt":receipt})
        );
    }
    // Revoke while an attestation waits for the writer lock. Authorization must
    // happen after that lock, not carry a prior membership into the transaction.
    work = read(&alice, &work).await;
    let revoked_input = evidence(&work, "revocation-race");
    let lock = db(root);
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let pending = {
        let bob = bob.clone();
        let input = revoked_input.clone();
        tokio::spawn(async move {
            bob.call("attest_work", &input)
                .await
                .map_err(|e| e.to_string())
        })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    lock.execute(
        "UPDATE memberships SET revoked_at=1 WHERE principal_id=?1",
        [BOB],
    )
    .unwrap();
    lock.execute_batch("COMMIT").unwrap();
    assert!(pending.await.unwrap().unwrap_err().contains("404"));
    assert_eq!(
        count(
            root,
            "SELECT count(*) FROM coord_operations WHERE operation_id='revocation-race'"
        ),
        0
    );
    assert!(bob.call("attest_work", &input).await.is_err());
    assert!(
        bob.call(
            "list_work_attestations",
            &json!({"room_name":"shared","work_id":work["work_id"]})
        )
        .await
        .is_err()
    );

    // Commit without a readable response and while NATS publication is unavailable.
    coord_json(root, &["stop"]).await;
    let offline_input = evidence(&work, "lost-response-offline");
    let mut body = offline_input.clone();
    body.as_object_mut().unwrap().remove("room_name");
    body["action"] = json!("attest");
    let body = body.to_string();
    let mut socket = tokio::net::UnixStream::connect(root.join("carol.sock"))
        .await
        .unwrap();
    let token = fs::read_to_string(root.join("data/agent_token")).unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/work HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",token.trim(),body.len()).as_bytes()).await.unwrap();
    stage0::until(|| {
        count(
            root,
            "SELECT count(*) FROM coord_operations WHERE operation_id='lost-response-offline'",
        ) == 1
    })
    .await;
    drop(socket);
    stage0::crash(proxy).await;
    let saved: String = db(root)
        .query_row(
            "SELECT outcome_json FROM coord_operations WHERE operation_id='lost-response-offline'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let saved: Value = serde_json::from_str(&saved).unwrap();
    let pending: Vec<(String, String)> = db(root)
        .prepare("SELECT event_id,payload_json FROM coord_outbox WHERE delivered_at IS NULL")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!pending.is_empty());
    coord_json(root, &["start", "--binary", &nats]).await;
    proxy = stage0::start_proxy(root).await;
    let advanced = change(&alice, &saved["work"], "candidate-after-restart").await;
    assert_eq!(
        carol.call("attest_work", &offline_input).await.unwrap(),
        saved
    );
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
        assert!(!payload.contains("Private evidence") && !payload.contains("untrusted.invalid"));
    }
    let attention:String=db(root).query_row("SELECT attention_id FROM coord_attention_edges WHERE recipient_agent_id=?1 AND object_id=?2 AND revision_or_sequence=?3",rusqlite::params![ALICE,work["work_id"].as_str(),saved["work"]["version"].as_i64()],|r|r.get(0)).unwrap();
    let resolved = alice
        .call("read_attention", &json!({"attention_id":attention}))
        .await
        .unwrap();
    assert_eq!(resolved["object"]["attestation"], saved["attestation"]);
    assert_eq!(resolved["object"]["target_generation"], 5);
    let final_page = carol
        .call(
            "list_work_attestations",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap();
    assert!(
        final_page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["current"] == false)
    );
    let stable = state(&alice).await;
    assert_eq!(stable["active_work"]["items"][0]["target_generation"], 6);
    assert_eq!(stable["active_work"]["items"][0]["claim_agent_id"], ALICE);
    assert_eq!(
        stable["active_work"]["items"][0]["attestations"]["current_total"],
        0
    );
    stage0::crash(proxy).await;
    coord_json(root, &["stop"]).await;
    coord_json(root, &["start", "--binary", &nats]).await;
    proxy = stage0::start_proxy(root).await;
    assert_eq!(state(&alice).await, stable);
    let audit_path = native_config::read(&root.join("config.toml"))
        .unwrap()
        .audit_log_path
        .unwrap();
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(!audit.contains("Private evidence") && !audit.contains("untrusted.invalid"));
    println!(
        "{}",
        json!({"lost_response_input":offline_input,"recovered":saved,"advanced_target":advanced,"canonical_attention":resolved,"restarted_status":stable})
    );
    stage0::crash(proxy).await;
}
