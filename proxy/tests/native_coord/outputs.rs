//! Retain external artifacts before publication; interrupt the real Agent API.
use super::*;
use hyper::Method;
use rusqlite::Connection;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn db(root: &Path) -> Connection {
    Connection::open(root.join("data/coord/v0.db")).unwrap()
}

fn count(root: &Path, sql: &str) -> i64 {
    db(root).query_row(sql, [], |r| r.get(0)).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; isolated real publication, cancellation and restart boundaries"]
async fn retained_external_outputs_recover_once_or_reject_stale_publication() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    // TMPDIR can select disk-backed acceptance storage outside the checkout.
    let retained = tempfile::Builder::new()
        .prefix("coord-outputs-")
        .tempdir()
        .unwrap()
        .keep();
    let root = retained.join("instance");
    fs::create_dir(&root).unwrap();
    let root = root.as_path();
    println!("output fixture: {}", retained.display());
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n")).unwrap();
    coord_json(root, &["start", "--binary", &nats]).await;
    let cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    for name in ["alice", "bob"] {
        coord_json(root, &["grant", "shared", name]).await;
    }
    let mut proxy = stage0::start_proxy(root).await;
    let client = |name: &str| Client {
        socket: Some(root.join(format!("{name}.sock"))),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let alice = client("alice");
    let bob = client("bob");
    let artifacts = retained.join("artifacts");
    fs::create_dir(&artifacts).unwrap();

    for (case, content) in [
        (
            "code",
            "diff --git a/result.txt b/result.txt\n+retained code correction\n",
        ),
        (
            "reassigned-report",
            "Report revision 1: original evidence retained before reassignment.\n",
        ),
        (
            "cancelled-report",
            "Report revision 1: original evidence retained before cancellation.\n",
        ),
    ] {
        // This is the application's artifact store. Coord neither creates nor
        // fetches the bytes and cannot make a mutable external URL immutable.
        let hash = digest(content.as_bytes());
        let artifact = artifacts.join(&hash);
        fs::write(&artifact, content).unwrap();
        let target_ref = format!("file://{}#sha256={hash}", artifact.display());
        let created=alice.call("create_work",&json!({"room_name":"shared","title":case,"external_ref":format!("opaque:run-{case}"),"operation_id":format!("create-{case}")})).await.unwrap();
        let work=alice.call("claim_work",&json!({"room_name":"shared","work_id":created["work"]["work_id"],"expected_version":1,"expected_generation":0,"operation_id":format!("claim-{case}")})).await.unwrap()["work"].clone();
        let input = json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":1,"expected_target_generation":0,
            "target_ref":target_ref,"execution_outcome":"succeeded","summary":"Procedure completed; acceptance remains separate","evidence_refs":[format!("sha256:{hash}")],"operation_id":format!("publish-{case}")});

        // The external artifact already exists while SQLite prevents the
        // publication from committing. Kill the serving process in that window.
        let lock = db(root);
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        let pending = {
            let client = alice.clone();
            let input = input.clone();
            tokio::spawn(async move {
                client
                    .call("publish_work_output", &input)
                    .await
                    .map_err(|e| e.to_string())
            })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        stage0::crash(proxy).await;
        lock.execute_batch("ROLLBACK").unwrap();
        assert!(pending.await.unwrap().is_err());
        assert_eq!(digest(&fs::read(&artifact).unwrap()), hash);
        assert_eq!(
            db(root)
                .query_row(
                    "SELECT version FROM coord_work WHERE work_id=?1",
                    [work["work_id"].as_str().unwrap()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        proxy = stage0::start_proxy(root).await;

        if case == "code" {
            // Commit with NATS down and deliberately discard the HTTP response.
            // The durable operation receipt is the recovery authority.
            coord_json(root, &["stop"]).await;
            let mut body = input.clone();
            body.as_object_mut().unwrap().remove("room_name");
            body["action"] = json!("publish_output");
            let body = body.to_string();
            let mut socket = tokio::net::UnixStream::connect(root.join("alice.sock"))
                .await
                .unwrap();
            let token = fs::read_to_string(root.join("data/agent_token")).unwrap();
            socket.write_all(format!("POST /api/coord/rooms/shared/work HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",token.trim(),body.len()).as_bytes()).await.unwrap();
            stage0::until(|| {
                count(
                    root,
                    "SELECT count(*) FROM coord_operations WHERE operation_id='publish-code'",
                ) == 1
            })
            .await;
            drop(socket);
            stage0::crash(proxy).await;
            coord_json(root, &["start", "--binary", &nats]).await;
            proxy = stage0::start_proxy(root).await;
            let receipt = alice.call("publish_work_output", &input).await.unwrap();
            assert_eq!(
                alice.call("publish_work_output", &input).await.unwrap(),
                receipt
            );
            assert_eq!(receipt["work"]["target_ref"], target_ref);
            assert_eq!(receipt["work"]["output"]["producer"]["id"], ALICE);
            assert_eq!(receipt["work"]["output"]["execution_outcome"], "succeeded");
            assert_eq!(receipt["work"]["state"], "claimed");
            let outputs = bob
                .call(
                    "list_work_outputs",
                    &json!({"room_name":"shared","work_id":work["work_id"]}),
                )
                .await
                .unwrap();
            assert_eq!(outputs["items"].as_array().unwrap().len(), 1);
            assert_eq!(outputs["items"][0]["output"], receipt["work"]["output"]);
            assert_eq!(
                count(
                    root,
                    "SELECT count(*) FROM coord_operations WHERE operation_id='publish-code'"
                ),
                1
            );
            // An explicit completed-output correction preserves the producer and
            // does not carry acceptance evidence to the replacement generation.
            let attested=bob.call("attest_work",&json!({"room_name":"shared","work_id":work["work_id"],"target_generation":1,"kind":"acceptance","verdict":"approve","summary":"Fixture observation, not issue acceptance","operation_id":"check-code"})).await.unwrap();
            let done=alice.call("complete_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":attested["work"]["version"],"expected_generation":1,"operation_id":"finish-code"})).await.unwrap();
            let corrected = artifacts.join("corrected-code");
            fs::write(
                &corrected,
                "diff --git a/result.txt b/result.txt\n+corrected result\n",
            )
            .unwrap();
            let mut correction = input.clone();
            correction["expected_version"] = done["work"]["version"].clone();
            correction["expected_target_generation"] = json!(1);
            correction["target_ref"] = json!(format!(
                "file://{}#sha256={}",
                corrected.display(),
                digest(&fs::read(&corrected).unwrap())
            ));
            correction["operation_id"] = json!("correct-code");
            let replacement = alice
                .call("publish_work_output", &correction)
                .await
                .unwrap();
            assert_eq!(replacement["work"]["target_generation"], 2);
            assert_eq!(replacement["work"]["state"], "done");
            assert_eq!(
                alice.call("publish_work_output", &input).await.unwrap(),
                receipt
            );
            let evidence = bob
                .call(
                    "list_work_attestations",
                    &json!({"room_name":"shared","work_id":work["work_id"]}),
                )
                .await
                .unwrap();
            assert_eq!(evidence["items"][0]["current"], false);
            let history = coord_json(
                root,
                &[
                    "work",
                    "outputs",
                    "shared",
                    work["work_id"].as_str().unwrap(),
                ],
            )
            .await;
            assert_eq!(history["items"].as_array().unwrap().len(), 2);
            println!(
                "code output recovered once after discarded response; completed-output correction retained both publications and stale review evidence"
            );
        } else {
            let recovered = if case == "reassigned-report" {
                coord_json(
                    root,
                    &[
                        "work",
                        "reassign",
                        "shared",
                        work["work_id"].as_str().unwrap(),
                        "--expected-version",
                        "2",
                        "--expected-generation",
                        "1",
                        "--agent-id",
                        BOB,
                        "--operation-id",
                        "recover-report",
                    ],
                )
                .await
            } else {
                alice.call("cancel_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":2,"expected_generation":1,"reason":"This run was cancelled","operation_id":"cancel-report"})).await.unwrap()
            };
            assert!(
                alice
                    .call("publish_work_output", &input)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("409")
            );
            let history = bob
                .call(
                    "list_work_outputs",
                    &json!({"room_name":"shared","work_id":work["work_id"]}),
                )
                .await
                .unwrap();
            assert!(history["items"].as_array().unwrap().is_empty());
            assert_eq!(
                recovered["work"]["external_ref"],
                format!("opaque:run-{case}")
            );
            let mut forged = input.clone();
            forged.as_object_mut().unwrap().remove("room_name");
            forged["action"] = json!("publish_output");
            forged["producer"] = json!({"kind":"agent","id":ALICE});
            assert!(
                bob.request(
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
            println!(
                "{case}: stale publication refused; retained external artifact unchanged; supplied producer rejected"
            );
            if case == "reassigned-report" {
                let cancelled = coord_json(
                    root,
                    &[
                        "work",
                        "cancel",
                        "shared",
                        work["work_id"].as_str().unwrap(),
                        "--expected-version",
                        &recovered["work"]["version"].to_string(),
                        "--expected-generation",
                        &recovered["work"]["claim_generation"].to_string(),
                        "--reason",
                        "Operator cancels the unavailable holder's attempt",
                        "--operation-id",
                        "operator-cancel-report",
                    ],
                )
                .await;
                assert_eq!(
                    cancelled["work"]["cancellation"]["author"]["kind"],
                    "operator"
                );
            }
        }
        assert_eq!(digest(&fs::read(&artifact).unwrap()), hash);
    }
    let state = bob
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(state["cancelled_work"]["total"], 2);
    assert_eq!(state["completed_work"]["total"], 1);
    assert_eq!(state["active_work"]["total"], 0);
    stage0::crash(proxy).await;
    drop(cleanup);
    fs::remove_dir_all(retained).unwrap();
}
