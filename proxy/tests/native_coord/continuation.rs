//! Explicit retained-participant attempts through the authenticated native clients.
use super::reviews::{claim, publish, read};
use super::supervision::ReviewRun;
use super::*;
use rusqlite::Connection;

const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn continuation(work: &Value, op: &str) -> Value {
    json!({"room_name":"shared", "work_id":work["work_id"],
        "expected_version":work["version"], "expected_generation":work["claim_generation"],
        "reason":"Continue the retained finding with the newly available input",
        "evidence_refs":["signal:unmet-need", "artifact:new-observation"], "operation_id":op})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; real commit interruption, discarded response and restart delivery"]
async fn continuation_recovers_once_and_retains_delivery_across_restart() {
    let mut run = ReviewRun::start().await;
    let work = run.alice.call("create_work", &json!({"room_name":"shared", "title":"Retained report", "assignee":{"kind":"agent","id":BOB}, "operation_id":"create"})).await.unwrap()["work"].clone();
    let work = claim(&run.bob, &work, "claim").await;
    let artifact = run.retained.join("report-r1.md");
    fs::write(&artifact, "Observation retained. New input is needed.\n").unwrap();
    let work = publish(&run.bob, &work, &artifact, "publish").await;
    let work = run.bob.call("complete_work", &json!({"room_name":"shared", "work_id":work["work_id"], "expected_version":work["version"], "expected_generation":1, "operation_id":"finish"})).await.unwrap()["work"].clone();
    let args = continuation(&work, "continue-report");
    let db_path = run.root.join("data/coord/v0.db");
    let lock = Connection::open(&db_path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let pending = {
        let alice = run.alice.clone();
        let args = args.clone();
        tokio::spawn(async move {
            alice
                .call("continue_work", &args)
                .await
                .map_err(|e| e.to_string())
        })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    stage0::crash(run.proxy).await;
    lock.execute_batch("ROLLBACK").unwrap();
    assert!(pending.await.unwrap().is_err());
    run.proxy = stage0::start_proxy(&run.root).await;
    assert_eq!(read(&run.bob, &work).await["state"], "done");
    assert_eq!(read(&run.bob, &work).await["claim_generation"], 1);

    // The caller loses the committed response while wake publication is offline.
    // The existing operation receipt, history and attention commit atomically.
    coord_json(&run.root, &["stop"]).await;
    let mut body = args.clone();
    body.as_object_mut().unwrap().remove("room_name");
    body["action"] = json!("continue");
    let body = body.to_string();
    let token = fs::read_to_string(run.root.join("data/agent_token")).unwrap();
    let mut socket = tokio::net::UnixStream::connect(run.root.join("alice.sock"))
        .await
        .unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/work HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", token.trim(), body.len()).as_bytes()).await.unwrap();
    let mut first = [0];
    assert_eq!(socket.read(&mut first).await.unwrap(), 1);
    drop(socket);
    stage0::crash(run.proxy).await;
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    coord_json(&run.root, &["start", "--binary", &nats]).await;
    run.proxy = stage0::start_proxy(&run.root).await;
    let receipt = run.alice.call("continue_work", &args).await.unwrap();
    assert_eq!(
        run.alice.call("continue_work", &args).await.unwrap(),
        receipt
    );
    let next = &receipt["work"];
    assert_eq!(next["output"], work["output"]);
    assert_eq!(next["claim_generation"], 2);
    let count: i64 = lock
        .query_row(
            "SELECT count(*) FROM coord_operations WHERE operation_type='coord.work.continue'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    let actions = run
        .bob
        .call(
            "read_work_actions",
            &json!({"room_name":"shared", "work_id":work["work_id"]}),
        )
        .await
        .unwrap();
    let action = &actions["actions"][0];
    assert_eq!(action["kind"], "execute_work");
    assert_eq!(action["claim_generation"], 2);
    let delivery =
        json!({"room_name":"shared", "work_id":work["work_id"], "action_key":action["key"]});
    let delivered = run
        .bob
        .call("receive_work_action", &delivery)
        .await
        .unwrap();
    stage0::crash(run.proxy).await;
    run.proxy = stage0::start_proxy(&run.root).await;
    assert_eq!(
        run.bob
            .call("receive_work_action", &delivery)
            .await
            .unwrap(),
        delivered
    );
    assert_eq!(read(&run.bob, next).await["state"], "claimed");
    let current = run
        .bob
        .call(
            "read_work_actions",
            &json!({"room_name":"shared", "work_id":work["work_id"], "include_received":true}),
        )
        .await
        .unwrap();
    assert_eq!(current["actions"][0]["key"], action["key"]);
    let done = run.bob.call("complete_work", &json!({"room_name":"shared", "work_id":next["work_id"], "expected_version":next["version"], "expected_generation":2, "short_result":"New input still cannot establish the finding; retained uncertainty", "operation_id":"finish-uncertain"})).await.unwrap()["work"].clone();
    assert_eq!(
        read(&run.bob, &done).await["acceptance_status"]["state"],
        "not_selected"
    );
    // Exercise the host surface with the same expectations and context.
    let selected = coord_json(
        &run.root,
        &[
            "work",
            "continue",
            "shared",
            done["work_id"].as_str().unwrap(),
            "--expected-version",
            &done["version"].to_string(),
            "--expected-generation",
            "2",
            "--reason",
            "Inspect another available observation",
            "--evidence-refs",
            "[\"artifact:observation-2\"]",
            "--operation-id",
            "host-continue",
        ],
    )
    .await;
    assert_eq!(selected["work"]["claim_agent_id"], BOB);
    assert_eq!(selected["work"]["claim_generation"], 3);
    let refused = run
        .alice
        .call(
            "continue_work",
            &continuation(&selected["work"], "duplicate-active"),
        )
        .await;
    assert!(refused.is_err());
    stage0::crash(run.proxy).await;
}
