//! Approved Factory selection and actual interactive/supervised native participants.
use super::reviews::{claim, publish, read};
use super::supervision::ReviewRun;
use super::*;

async fn selected_work(run: &ReviewRun) -> (Value, PathBuf) {
    let contract = run.retained.join("reviewer.md");
    fs::write(&contract, "Use native_in_flight and current Work. Independently inspect exact digest-verified artifacts. Claim assigned checks and answer approve/reject from the requested criterion. Explicitly dispose of challenges only after inspecting the response and correction. When selected acceptance is ready, decide it from current evidence. Never change policy or fabricate outcomes. Do not send text protocol messages.\n").unwrap();
    let source = run.retained.join("factory.toml");
    fs::write(&source, r#"schema="safeyolo.factory/v1"
name="native"
room="shared"
[roles.reviewer]
agent="bob"
contract="reviewer.md"
[operator_input]
to="reviewer"
types=["DIRECTION"]
[work]
authorities=["reviewer"]
deciders=["reviewer"]
independent=true
[[work.checks]]
reviewer="reviewer"
criterion="Verify the retained report contains the exact line: The required result is recorded here."
independent=true
"#).unwrap();
    let output = host_cli(
        &run.root,
        &["factory", "approve", source.to_str().unwrap(), "--yes"],
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot_id = fs::read_to_string(run.root.join("factories/native/approved")).unwrap();
    let snapshot = run.root.join(format!(
        "factories/native/snapshots/{}.json",
        snapshot_id.trim()
    ));
    let factory = json!({"name":"native","snapshot_id":snapshot_id.trim()}).to_string();
    let assignee = json!({"kind":"agent","id":"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}).to_string();
    let output = host_cli(
        &run.root,
        &[
            "coord",
            "work",
            "create",
            "shared",
            "Retain and publish the requested report",
            "--factory",
            &factory,
            "--assignee",
            &assignee,
            "--operation-id",
            "create",
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    (result["work"].clone(), snapshot)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; real approved Factory and authenticated public API"]
async fn factory_selection_enforces_native_obligations_for_direct_callers() {
    let mut run = ReviewRun::start().await;
    let (work, _) = selected_work(&run).await;
    let reference = work["factory"]["reference"].clone();
    assert!(run.alice.call("create_work",&json!({"room_name":"shared","title":"Unauthorized Factory creation","factory":reference,"operation_id":"not-creator"})).await.is_err());
    let work = claim(&run.alice, &work, "claim").await;
    let first = run.retained.join("retained-report.md");
    fs::write(&first, "The required result is recorded here.\n").unwrap();
    let before_publication = work;
    let work = publish(&run.alice, &before_publication, &first, "publish").await;
    stage0::crash(run.proxy).await;
    run.proxy = stage0::start_proxy(&run.root).await;
    let replay = publish(&run.alice, &before_publication, &first, "publish").await;
    assert_eq!(
        replay, work,
        "publication replay preserves its generated check IDs after restart"
    );
    let check = run
        .alice
        .call(
            "read_work",
            &json!({"room_name":"shared","work_id":work["factory"]["current_checks"][0]}),
        )
        .await
        .unwrap();
    assert_eq!(
        check["check"]["subject"]["producer"]["id"],
        "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        check["check"]["subject"]["reference"]["target_generation"],
        1
    );
    let mut policy = super::reviews::requirements(&work, &[], &[], "worker-relaxation");
    policy["authorities"] = json!([]);
    assert!(
        run.alice
            .call("set_work_requirements", &policy)
            .await
            .is_err()
    );
    assert!(
        run.bob
            .call(
                "decide_work_acceptance",
                &super::reviews::acceptance(&work, "approve", "premature")
            )
            .await
            .is_err()
    );
    let check = claim(&run.bob, &check, "claim-check").await;
    run.bob
        .call(
            "answer_check",
            &super::reviews::answer(&check, "approve", "answer"),
        )
        .await
        .unwrap();
    let work = read(&run.alice, &work).await;
    run.bob
        .call(
            "decide_work_acceptance",
            &super::reviews::acceptance(&work, "approve", "accept"),
        )
        .await
        .unwrap();
    assert_eq!(
        read(&run.alice, &work).await["acceptance_status"]["state"],
        "accepted"
    );
    stage0::crash(run.proxy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS and separate private SAFEYOLO_COORD_INTERACTIVE_HOME / SAFEYOLO_COORD_MODEL_HOME native Codex homes"]
async fn interactive_coding_client_and_factory_supervisor_share_native_work() {
    let alice = std::env::var_os("SAFEYOLO_COORD_INTERACTIVE_HOME")
        .expect("set private interactive native Codex role home");
    let bob = std::env::var_os("SAFEYOLO_COORD_MODEL_HOME")
        .expect("set private supervised native Codex role home");
    assert_ne!(alice, bob, "participants require separate role homes");
    let run = ReviewRun::start().await;
    let (work, snapshot) = selected_work(&run).await;
    for args in [
        vec!["room", "create", "bob-agent"],
        vec!["grant", "bob-agent", "bob"],
    ] {
        coord_json(&run.root, &args).await;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(1200),
        tokio::process::Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/native_coord/factory_interactive.py"),
            )
            .arg(&run.root)
            .arg(&run.retained)
            .arg(env!("CARGO_BIN_EXE_safeyolo-coord"))
            .arg(alice)
            .arg(bob)
            .arg(&snapshot)
            .arg(work["work_id"].as_str().unwrap())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("bounded actual client journey timed out")
    .unwrap();
    // Preserve canonical fixture and native client sessions. No additional
    // conversation transcript or writable workflow record is created here.
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    assert_eq!(
        read(&run.alice, &work).await["acceptance_status"]["state"],
        "accepted"
    );
    stage0::crash(run.proxy).await;
}
