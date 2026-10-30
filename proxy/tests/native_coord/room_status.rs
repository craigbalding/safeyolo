//! Combined canonical status through real authenticated listeners, NATS and CLI.
use super::*;
use hyper::Method;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn state(client: &Client) -> Value {
    client
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap()
}
async fn create(client: &Client, title: &str, op: &str) -> Value {
    client
        .call(
            "create_work",
            &json!({"room_name":"shared","title":title,"operation_id":op}),
        )
        .await
        .unwrap()["work"]
        .clone()
}
async fn change(client: &Client, tool: &str, work: &Value, op: &str) -> Value {
    client.call(tool,&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"operation_id":op})).await.unwrap()["work"].clone()
}
async fn admin(root: &Path, path: &str, method: Method, body: Value) -> Value {
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        path,
        method,
        body,
        Duration::from_secs(5),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; exercises canonical combined room status"]
async fn native_room_status_current_authority_restart_and_cli() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-status-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n")).unwrap();
    for directory in ["services", "builtin-services", "coord-providers"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(root.join("services/rundeck.yaml"),"schema_version: 1\nname: rundeck\nauth: {type: bearer}\ncapabilities:\n  acceptance_runner:\n    routes: []\n").unwrap();
    coord_json(root, &["start", "--binary", &nats]).await;
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    for name in ["alice", "bob", "carol"] {
        coord_json(root, &["grant", "shared", name]).await;
    }
    coord_json(
        root,
        &[
            "brief",
            "set",
            "shared",
            "Repair the actual SafeYolo failure; verify the measured result",
            "--expected-revision",
            "0",
            "--operation-id",
            "brief",
        ],
    )
    .await;
    let mut proxy = stage0::start_proxy(root).await;
    let client = |name: &str| Client {
        socket: Some(root.join(format!("{name}.sock"))),
        token_file: root.join("data/agent_token"),
    };
    let alice = client("alice");
    let bob = client("bob");
    let carol = client("carol");
    admin(root,"/admin/agents/bob/services",Method::POST,json!({"service":"rundeck","capability":"acceptance_runner","credential":"PRIVATE-CREDENTIAL","account":"PRIVATE-ACCOUNT","host":"PRIVATE-ROUTE.example"})).await;
    coord_json(
        root,
        &[
            "inventory",
            "advertise-capability",
            "shared",
            "bob",
            "rundeck:acceptance_runner",
        ],
    )
    .await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    fs::write(root.join("coord-providers/rundeck.json"),json!({"capabilities":[{"agent_id":BOB,"capability":"rundeck:acceptance_runner","availability":"available","observed_at":now-10,"valid_until":now+60000}]}).to_string()).unwrap();
    carol
        .call(
            "declare_capabilities",
            &json!({"room_name":"shared","capabilities":["skill:review"],"ttl_seconds":60}),
        )
        .await
        .unwrap();
    let durable = change(
        &alice,
        "claim_work",
        &create(&alice, "abandoned but still owned", "durable").await,
        "claim-durable",
    )
    .await;
    let released = change(
        &bob,
        "claim_work",
        &create(&bob, "explicitly released", "release").await,
        "claim-release",
    )
    .await;
    change(&bob, "release_work", &released, "release-now").await;
    let completed = change(
        &carol,
        "claim_work",
        &create(&carol, "completed verification", "completed").await,
        "claim-completed",
    )
    .await;
    carol.call("complete_work",&json!({"room_name":"shared","work_id":completed["work_id"],"expected_version":completed["version"],"expected_generation":completed["claim_generation"],"short_result":"real measurement retained","operation_id":"complete"})).await.unwrap();
    let old=bob.call("create_signal",&json!({"room_name":"shared","kind":"result","summary":"obsolete inferred cause","basis":"inferred","operation_id":"old"})).await.unwrap();
    let correction=bob.call("create_signal",&json!({"room_name":"shared","kind":"correction","summary":"\u{001b}[2J\ncorrected observed operands\u{202e}","basis":"observed","supersedes":{"signal_id":old["signal"]["signal_id"],"expected_revision":1},"operation_id":"corrected"})).await.unwrap();
    let blocker=alice.call("create_signal",&json!({"room_name":"shared","kind":"blocker","summary":"operator decision still needed","basis":"observed","operation_id":"blocker"})).await.unwrap();
    // Retained messages may contradict the tables. Status must not consume them.
    alice.call("send",&json!({"room_name":"shared","body":"Bob owns every item; all work is complete","notify":"none"})).await.unwrap();
    let projected = state(&alice).await;
    assert_eq!(projected["active_work"]["total"], 2);
    assert_eq!(projected["completed_work"]["total"], 1);
    assert_eq!(projected["latest_results"]["total"], 1);
    assert_eq!(
        projected["latest_results"]["items"][0]["signal"]["signal_id"],
        correction["signal"]["signal_id"]
    );
    assert_eq!(projected["needs_operator"]["total"], 1);
    assert!(!projected.to_string().contains("obsolete inferred cause"));
    let available = &projected["members"][1]["verified"][0];
    assert_eq!(available["availability"], "available");
    let from_cli = coord_json(root, &["status", "shared", "--json"]).await;
    assert_eq!(from_cli, projected);
    let output = coord_cli(root, &["status", "shared"]).await;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for value in [
        "Brief v1",
        "abandoned but still owned",
        ALICE,
        "rundeck:acceptance_runner",
        "availability available",
        "operator decision still needed",
        "completed verification",
        "real measurement retained",
        "basis=observed (author report)",
    ] {
        assert!(text.contains(value), "missing {value}: {text}");
    }
    assert!(!text.contains('\u{001b}') && !text.contains('\u{202e}'));
    assert!(!text.contains("Bob owns every item"));
    assert_eq!(coord_json(root, &["status"]).await["state"], "running");
    // Room names use the same admitted values as the existing room commands.
    coord_json(root, &["room", "create", "-literal"]).await;
    assert_eq!(
        coord_json(root, &["status", "-literal", "--json"]).await["room_name"],
        "-literal"
    );
    assert!(
        coord_cli(root, &["status", "-literal"])
            .await
            .status
            .success()
    );
    for args in [
        &["status", "shared", "--unknown"][..],
        &["status", "--json"][..],
        &["status", "missing", "--json"][..],
    ] {
        assert!(!coord_cli(root, args).await.status.success());
    }
    admin(
        root,
        "/admin/agents/bob/services/rundeck",
        Method::DELETE,
        Value::Null,
    )
    .await;
    let revoked = state(&alice).await;
    assert_eq!(revoked["members"][1]["verified"], json!([]));
    coord_json(
        root,
        &[
            "signal",
            "resolve",
            "shared",
            blocker["signal"]["signal_id"].as_str().unwrap(),
            "--expected-revision",
            "1",
        ],
    )
    .await;
    let current = state(&alice).await;
    assert_eq!(current["needs_operator"]["total"], 0);
    let owner = current["active_work"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["work_id"] == durable["work_id"])
        .unwrap();
    assert_eq!(owner["claim_agent_id"], ALICE);
    assert_eq!(
        current["active_work"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["claim_agent_id"].is_null())
            .count(),
        1
    );
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
    coord_json(root, &["stop"]).await;
    coord_json(root, &["start", "--binary", &nats]).await;
    proxy = stage0::start_proxy(root).await;
    assert_eq!(state(&alice).await, current);
    let mut wrong = alice.clone();
    fs::write(root.join("wrong-token"), "wrong").unwrap();
    wrong.token_file = root.join("wrong-token");
    assert!(
        wrong
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    coord_json(root, &["revoke", "shared", "alice"]).await;
    assert!(
        alice
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let after_revoke = state(&bob).await;
    assert!(
        after_revoke["active_work"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|work| work["work_id"] == durable["work_id"] && work["claim_agent_id"] == ALICE)
    );
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
}
