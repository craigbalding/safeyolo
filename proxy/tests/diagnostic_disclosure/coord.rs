//! Real source-owner projections with pinned NATS; not installed-agent proof.
use super::*;
use safeyolo_proxy::{coord_rooms, coord_supervisor, coord_tools::Client};

struct StopCoord(std::path::PathBuf);
impl Drop for StopCoord {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .args(["coord", "stop"])
            .stdout(std::process::Stdio::null())
            .status();
    }
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY and SAFEYOLO_NATS_TEST_INSTANCE=1"]
async fn empty_history_is_complete_and_real_message_loss_remains_incomplete() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    let root = f.root.path();
    let _stop = StopCoord(root.to_owned());
    let binary = std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("pinned NATS");
    coord_rooms::start(root, Some(std::path::Path::new(&binary)), None, None)
        .await
        .unwrap();
    let room = coord_rooms::create_room(root, "empty").await.unwrap();
    coord_rooms::grant(
        &root.join("config.toml"),
        "empty",
        "worker",
        &["send".into()],
        false,
        None,
    )
    .unwrap();
    let mut input = request("empty-history", false, vec!["worker"]);
    input["scope"]["audit"] = json!(false);
    input["scope"]["rooms"] =
        json!([{"room_id":room["room_id"],"history":true,"membership":false,"attention":false}]);
    let pending = submit(&f, input).await;
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let output = query(&f, json!({"operation_id":"empty","grant":id}))
        .await
        .json();
    assert_eq!(
        output["result"], "no_matching_retained_evidence",
        "{output}"
    );
    assert!(output["rows"].as_array().unwrap().is_empty());
    assert_eq!(output["sources"][0]["status"], "complete_retained_search");
    assert_eq!(output["sources"][0]["limitations"], json!([]));

    for marker in ["first", "deleted", "last"] {
        let sent = f
            .agent(
                "worker",
                "POST",
                "/api/coord/rooms/empty/send",
                Some(json!({"body":marker,"notify":"none","declared_content_type":"text/plain"})),
            )
            .await;
        assert_eq!(sent.status, 200, "{}", sent.json());
    }
    let retained = query(&f, json!({"operation_id":"retained","grant":id}))
        .await
        .json();
    assert_eq!(retained["result"], "retained_evidence", "{retained}");
    assert_eq!(retained["rows"].as_array().unwrap().len(), 3);

    // Delete an interior message at this fixture's real source owner, keeping
    // first/last sequences so the collector must expose the missing record.
    let password =
        zeroize::Zeroizing::new(fs::read_to_string(root.join("data/coord/nats/creds")).unwrap());
    let endpoint: Value = serde_json::from_slice(
        &fs::read(root.join("data/coord/nats/local-endpoint.json")).unwrap(),
    )
    .unwrap();
    let connection = async_nats::ConnectOptions::new()
        .user_and_password("safeyolo".into(), password.trim().into())
        .connect(endpoint["url"].as_str().unwrap())
        .await
        .unwrap();
    let mut stream = async_nats::jetstream::new(connection)
        .get_stream(format!("ROOM_{}", room["room_id"].as_str().unwrap()))
        .await
        .unwrap();
    assert!(
        stream
            .delete_message(retained["rows"][1]["record"]["sequence"].as_u64().unwrap())
            .await
            .unwrap()
    );
    let lost = query(&f, json!({"operation_id":"lost","grant":id}))
        .await
        .json();
    assert_eq!(lost["result"], "incomplete_search", "{lost}");
    assert_eq!(lost["rows"].as_array().unwrap().len(), 2);
    assert!(
        lost["sources"][0]["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "a selected room message was lost during collection")
    );
    assert!(!lost.to_string().contains("\"body\":\"deleted\""));

    stream.purge().await.unwrap();
    let state = &stream.info().await.unwrap().state;
    assert_eq!(state.messages, 0);
    let pruned = query(&f, json!({"operation_id":"pruned","grant":id}))
        .await
        .json();
    assert_eq!(pruned["result"], "incomplete_search", "{pruned}");
    assert!(pruned["rows"].as_array().unwrap().is_empty());
    assert_eq!(
        pruned["sources"][0]["limitations"],
        json!(["room retention has pruned earlier history"])
    );
    coord_rooms::stop(root).await.unwrap();
    let unavailable = query(&f, json!({"operation_id":"unavailable","grant":id}))
        .await
        .json();
    assert_eq!(unavailable["result"], "source_unavailable", "{unavailable}");
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY and SAFEYOLO_NATS_TEST_INSTANCE=1"]
async fn selected_coord_runtime_and_private_results_survive_notification_outage() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    let root = f.root.path();
    let _stop = StopCoord(root.to_owned());
    let binary = std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("pinned NATS");
    coord_rooms::start(root, Some(std::path::Path::new(&binary)), None, None)
        .await
        .unwrap();
    let room = coord_rooms::create_room(root, "shared").await.unwrap();
    coord_rooms::create_room(root, "private").await.unwrap();
    for (selected, name) in [
        ("shared", "worker"),
        ("shared", "peer"),
        ("private", "worker"),
    ] {
        coord_rooms::grant(
            &root.join("config.toml"),
            selected,
            name,
            &["send".into(), "receive".into()],
            false,
            None,
        )
        .unwrap();
    }
    let sent = f
        .agent(
            "worker",
            "POST",
            "/api/coord/rooms/shared/send",
            Some(json!({
        "body":"selected-room-marker","notify":["peer"],"declared_content_type":"text/plain"})),
        )
        .await;
    assert_eq!(sent.status, 200, "{}", sent.json());
    let hidden = f
        .agent(
            "worker",
            "POST",
            "/api/coord/rooms/private/send",
            Some(json!({
        "body":"unselected-room-marker","notify":"none","declared_content_type":"text/plain"})),
        )
        .await;
    assert_eq!(hidden.status, 200, "{}", hidden.json());
    assert_eq!(
        f.agent("helper", "GET", "/api/coord/rooms/shared/messages", None)
            .await
            .status,
        404
    );

    let supervisor = root.join("agents/peer/home/.safeyolo");
    fs::create_dir_all(&supervisor).unwrap();
    let config = coord_supervisor::Config {
        agent_name: "peer".into(),
        rooms: vec!["shared".into()],
        coordinators: vec!["worker".into()],
        ..Default::default()
    };
    fs::write(
        supervisor.join("coord-supervisor.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let mut checkpoint = coord_supervisor::State::default();
    checkpoint.safe_cursor = 7;
    checkpoint.thread_id = Some("unselected-checkpoint-marker".into());
    fs::write(
        supervisor.join("coord-supervisor-state.json"),
        serde_json::to_vec(&checkpoint).unwrap(),
    )
    .unwrap();

    let mut selected = request("coord-sources", false, vec!["worker", "peer"]);
    selected["scope"]["audit"] = json!(false);
    selected["scope"]["runtime"] = json!(true);
    selected["scope"]["rooms"] =
        json!([{"room_id":room["room_id"],"history":true,"membership":true,"attention":true}]);
    selected["scope"]["system_categories"] = json!(["coord_health"]);
    let pending = submit(&f, selected).await;
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let output = query(&f, json!({"operation_id":"coord","grant":id})).await;
    assert_eq!(output.status, 200, "{}", output.json());
    let output = output.json();
    assert!(
        output.to_string().contains("selected-room-marker"),
        "{output}"
    );
    assert!(!output.to_string().contains("unselected-room-marker"));
    assert!(!output.to_string().contains("unselected-checkpoint-marker"));
    let rows = output["rows"].as_array().unwrap();
    assert!(
        !output["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["source"] == "audit"),
        "{output}"
    );
    assert!(rows.iter().any(|r| r["source"] == "coord_membership"));
    assert!(
        output["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["source"] == "runtime")
    );
    assert!(
        rows.iter().any(|r| r["source"] == "coord_attention"
            && r["subject_id"] == PEER_ID
            && r["record"]["recipient_cursor"]["safe_cursor"] == 7),
        "{output}"
    );
    assert!(
        rows.iter().any(|r| r["source"] == "coord_attention"
            && r["record"]["delivery"]["attention_id"].is_string()),
        "{output}"
    );
    assert!(
        rows.iter().any(|r| r["source"] == "coord_health"),
        "{output}"
    );
    assert_eq!(
        f.agent(
            "helper",
            "POST",
            "/api/coord/rooms/shared/send",
            Some(json!({"body":"forbidden"}))
        )
        .await
        .status,
        404
    );
    assert_eq!(
        query(
            &f,
            json!({"operation_id":"no-audit","grant":id,"filter":{"sources":["audit"]}})
        )
        .await
        .status,
        403
    );

    let client = Client {
        socket: Some(root.join("helper.sock")),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    // Inspect the canonical private projection without waiting for an application.
    let attention=tokio::time::timeout(Duration::from_secs(10),async {
        loop {
            let db=rusqlite::Connection::open(root.join("data/coord/v0.db")).unwrap();
            if let Ok(id)=db.query_row("SELECT attention_id FROM coord_attention_edges WHERE object_id=?1 AND recipient_agent_id=?2 AND kind='approval_result'",rusqlite::params![id,HELPER_ID],|r|r.get::<_,String>(0)){break id;}
            drop(db);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("private approval result projection");
    let notification = client
        .call("read_attention", &json!({"attention_id":attention}))
        .await
        .unwrap();
    assert!(notification.to_string().contains(id), "{notification}");
    assert!(!notification.to_string().contains("selected-room-marker"));
    assert!(
        !notification
            .to_string()
            .contains("synthetic-operator-token")
    );

    coord_rooms::stop(root).await.unwrap();
    // Broker notification/history is now unavailable; local approvals/audit work.
    let pending = submit(&f, request("offline-decision", false, vec!["helper"])).await;
    let offline = pending["approval_id"].as_str().unwrap();
    approve(&f, offline).await;
    let decision = f
        .agent("helper", "GET", &format!("/approvals/{offline}"), None)
        .await;
    assert_eq!(decision.status, 200, "{}", decision.json());
    assert_eq!(decision.json()["status"], "approved");
    let direct = query(&f, json!({"operation_id":"offline-read","grant":offline})).await;
    assert_eq!(direct.status, 200, "{}", direct.json());
    assert!(
        direct.json()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["subject_id"] == HELPER_ID),
        "{}",
        direct.json()
    );
    let unavailable = query(&f, json!({"operation_id":"offline-coord","grant":id})).await;
    assert_eq!(unavailable.status, 200, "{}", unavailable.json());
    assert_eq!(unavailable.json()["result"], "source_unavailable");
    f.stop().await;
}
