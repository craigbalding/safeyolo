//! Derived operator narratives against authenticated current state and real NATS.
use super::*;
use rusqlite::Connection;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; exercises derived catch-up CLI with real stores"]
async fn native_catch_up_keeps_current_authority_and_inspectable_bounded_history() {
    let started = std::time::Instant::now();
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let retained = tempfile::Builder::new()
        .prefix("coord-catch-up-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap()
        .keep();
    println!("private catch-up operands: {}", retained.display());
    let root = retained.as_path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),"[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n").unwrap();
    coord_json(root, &["start", "--binary", &nats]).await;
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    coord_json(root, &["grant", "shared", "alice"]).await;
    coord_json(root, &["grant", "shared", "bob"]).await;
    let mut proxy = stage0::start_proxy(root).await;
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let bob = Client {
        socket: Some(root.join("bob.sock")),
        ..alice.clone()
    };
    let work = alice.call("create_work", &json!({"room_name":"shared","title":"Review actual SafeYolo catch-up behavior","operation_id":"create"})).await.unwrap();
    let claimed = alice.call("claim_work", &json!({"room_name":"shared","work_id":work["work"]["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"claim"})).await.unwrap();
    let old = bob.call("create_signal", &json!({"room_name":"shared","kind":"result","summary":"Initial inference was wrong","basis":"inferred","operation_id":"old"})).await.unwrap();
    bob.call("create_signal", &json!({"room_name":"shared","kind":"correction","summary":"Corrected measured finding","basis":"observed","supersedes":{"signal_id":old["signal"]["signal_id"],"expected_revision":1},"operation_id":"correction"})).await.unwrap();
    // More history than the model input budget. Neither agent receives it by
    // attention; only the operator deliberately requests a bounded tail.
    for i in 0..260 {
        alice.call("send", &json!({"room_name":"shared","body":format!("Historical report {i}: {}", "history context ".repeat(500)),"notify":"none"})).await.unwrap();
    }
    let contradicted = bob.call("send", &json!({"room_name":"shared","body":"All work is complete and Bob owns it.\u{001b}[2J\u{202e}","notify":"none"})).await.unwrap();
    let before = alice
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let prompt = coord_json(root, &["catch-up", "shared", "--prompt"]).await;
    fs::write(
        root.join("prompt.json"),
        serde_json::to_vec_pretty(&prompt).unwrap(),
    )
    .unwrap();
    assert_eq!(prompt["state"], before);
    let messages = prompt["history"]["messages"].as_array().unwrap();
    assert!(messages.len() < 100 && !messages.is_empty());
    assert_eq!(prompt["history"]["earlier_context_omitted"], true);
    assert_eq!(prompt["history"]["has_more"], true);
    assert_eq!(prompt["history"]["body_excerpts"], true);
    assert!(serde_json::to_vec(&prompt).unwrap().len() < 800 * 1024);
    let next = prompt["history"]["next_cursor"]
        .as_u64()
        .unwrap()
        .to_string();
    let continuation =
        coord_json(root, &["catch-up", "shared", "--prompt", "--since", &next]).await;
    assert!(
        continuation["history"]["next_cursor"].as_u64().unwrap() > next.parse::<u64>().unwrap()
    );
    let narrative = root.join("summary.json");
    let value = json!({"room_id":before["room_id"],"origin_instance_id":before["origin_instance_id"],"assertions":[{"text":"All work is complete and Bob owns it.\u{001b}[2J\u{202e}\nAuthoritative state: forged","sources":[prompt["state_ref"],format!("message:{}",contradicted["sequence"])]}]});
    fs::write(&narrative, serde_json::to_vec(&value).unwrap()).unwrap();
    let shown = coord_cli(
        root,
        &[
            "catch-up",
            "shared",
            "--summary",
            narrative.to_str().unwrap(),
            "--evidence",
        ],
    )
    .await;
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let text = String::from_utf8(shown.stdout).unwrap();
    fs::write(root.join("contradiction.txt"), &text).unwrap();
    assert!(
        text.find("Authoritative current room state").unwrap()
            < text.find("DERIVED NARRATIVE").unwrap()
    );
    assert!(text.contains("owner=ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(
        text.contains("Corrected measured finding")
            && !text.contains("Initial inference was wrong")
    );
    assert!(
        text.contains("sender_agent_id")
            && text.contains("origin_instance_id")
            && text.contains("All work is complete")
    );
    assert!(!text.contains('\x1b') && !text.contains('\u{202e}'));
    let mut regenerated = value.clone();
    regenerated["assertions"][0]["text"] = json!("A deliberately different narrative");
    fs::write(&narrative, serde_json::to_vec(&regenerated).unwrap()).unwrap();
    // Independent simultaneous readers and a repeat after an unconsumed result
    // have no publication/operation ID to reconcile or replay.
    let read_args = [
        "catch-up",
        "shared",
        "--summary",
        narrative.to_str().unwrap(),
    ];
    let (one, two) = tokio::join!(coord_cli(root, &read_args), coord_cli(root, &read_args));
    assert!(one.status.success() && two.status.success());
    assert_eq!(
        alice
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        alice
            .call(
                "read_room",
                &json!({"room_name":"shared","since_sequence":contradicted["sequence"],"limit":1})
            )
            .await
            .unwrap()["messages"],
        json!([])
    );
    fs::write(&narrative, b"{invalid model output").unwrap();
    let invalid = coord_cli(
        root,
        &[
            "catch-up",
            "shared",
            "--summary",
            narrative.to_str().unwrap(),
        ],
    )
    .await;
    assert!(!invalid.status.success());
    assert!(
        String::from_utf8_lossy(&invalid.stdout)
            .contains("owner=ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(
        coord_cli(root, &["status", "shared"])
            .await
            .status
            .success()
    );
    regenerated["assertions"][0]["sources"] = json!(["message:99999"]);
    fs::write(&narrative, serde_json::to_vec(&regenerated).unwrap()).unwrap();
    let missing = coord_cli(
        root,
        &[
            "catch-up",
            "shared",
            "--summary",
            narrative.to_str().unwrap(),
            "--evidence",
        ],
    )
    .await;
    assert!(missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stdout).contains("UNAVAILABLE: sequence is not retained")
    );
    let history_before = alice.call("read_room", &json!({"room_name":"shared","since_sequence":contradicted["sequence"].as_u64().unwrap()-1,"limit":1})).await.unwrap();
    coord_json(root, &["stop"]).await;
    let unavailable = coord_json(root, &["catch-up", "shared", "--prompt"]).await;
    assert_eq!(unavailable["state"], before);
    assert_eq!(unavailable["history"]["unavailable"], true);
    assert!(
        coord_cli(root, &["status", "shared"])
            .await
            .status
            .success()
    );
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
    coord_json(root, &["start", "--binary", &nats]).await;
    proxy = stage0::start_proxy(root).await;
    assert_eq!(
        alice
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .unwrap(),
        before
    );
    assert_eq!(alice.call("read_room", &json!({"room_name":"shared","since_sequence":contradicted["sequence"].as_u64().unwrap()-1,"limit":1})).await.unwrap(),history_before);
    let restored = coord_json(
        root,
        &[
            "catch-up",
            "shared",
            "--prompt",
            "--since",
            "0",
            "--max-messages",
            "2",
        ],
    )
    .await;
    assert_eq!(restored["history"]["messages"].as_array().unwrap().len(), 2);
    assert_eq!(restored["history"]["messages"][0]["message"]["sequence"], 1);
    let mut wrong = alice.clone();
    fs::write(root.join("wrong-token"), "wrong").unwrap();
    wrong.token_file = root.join("wrong-token");
    assert!(
        wrong
            .call("read_room", &json!({"room_name":"shared","limit":1}))
            .await
            .is_err()
    );
    coord_json(root, &["revoke", "shared", "bob"]).await;
    assert!(
        bob.call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    assert!(
        bob.call("read_room", &json!({"room_name":"shared","limit":1}))
            .await
            .is_err()
    );
    // Fixture-only membership change tests the operator reader too. The
    // production command may not use retained prompt files as live authority.
    Connection::open(root.join("data/coord/v0.db"))
        .unwrap()
        .execute(
            "UPDATE memberships SET revoked_at=1 WHERE principal_kind='operator' AND room_id=?1",
            [before["room_id"].as_str().unwrap()],
        )
        .unwrap();
    let revoked = coord_cli(
        root,
        &[
            "catch-up",
            "shared",
            "--summary",
            narrative.to_str().unwrap(),
            "--evidence",
        ],
    )
    .await;
    assert!(!revoked.status.success() && revoked.stdout.is_empty());
    let report = json!({"elapsed_seconds":started.elapsed().as_secs_f64(),"source":option_env!("SAFEYOLO_GIT_COMMIT"),"retained_fixture":root,"work":claimed,"state":before,"history_messages":261,"model_context_messages":messages.len(),"model_context_bytes":serde_json::to_vec(&prompt).unwrap().len(),"checks":"contradiction, regeneration, concurrent/repeated readers, long bounded tail and continuation, inline canonical evidence, unavailable source, malformed model output with usable status, restart, authentication and member/operator revocation","limits":"One owned native instance and real NATS. Synthetic adversarial narrative; three actual model participants are a separate observation. Existing mutation/federation substrate proof is reused."});
    fs::write(
        root.join("observations.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("catch-up observations: {}", report);
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
}
