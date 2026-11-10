//! Native assignments reach the existing supervisor; a real model reads and answers.
use super::reviews::{claim, publish, read, subject};
use super::*;
use std::os::unix::fs::PermissionsExt;

const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn requirements(work: &Value, checks: &[Value], challenges: &[Value], op: &str) -> Value {
    let mut selection = super::reviews::requirements(work, checks, challenges, op);
    selection["authorities"] = json!([{"kind":"agent","id":"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]);
    selection
}

pub(super) struct ReviewRun {
    pub(super) retained: PathBuf,
    pub(super) root: PathBuf,
    pub(super) alice: Client,
    pub(super) bob: Client,
    pub(super) proxy: tokio::process::Child,
    _cleanup: NatsCleanup,
}
impl ReviewRun {
    pub(super) async fn start() -> Self {
        let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
        let retained = tempfile::Builder::new()
            .prefix("coord-native-supervision-")
            .tempdir()
            .unwrap()
            .keep();
        let root = retained.join("instance");
        fs::create_dir(&root).unwrap();
        assert!(host_cli(&root, &["init"]).await.status.success());
        fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
        fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='{BOB}'\n")).unwrap();
        coord_json(&root, &["start", "--binary", &nats]).await;
        let cleanup = NatsCleanup(root.clone());
        coord_json(&root, &["room", "create", "shared"]).await;
        for name in ["alice", "bob"] {
            coord_json(&root, &["grant", "shared", name]).await;
        }
        let proxy = stage0::start_proxy(&root).await;
        let client = |name: &str| Client {
            socket: Some(root.join(format!("{name}.sock"))),
            token_file: root.join("data/agent_token"),
            home: None,
        };
        println!("native supervision fixture: {}", retained.display());
        Self {
            alice: client("alice"),
            bob: client("bob"),
            root,
            retained,
            proxy,
            _cleanup: cleanup,
        }
    }

    async fn supervise(&self, role_home: &Path, fake: Option<&Path>) -> std::process::Output {
        let configuration = self.retained.join("supervisor.json");
        fs::write(&configuration,json!({"agent_name":"bob","rooms":["shared"],"coordinators":[],"native_work":true,
            "workspace":self.retained,"wait_seconds":1,"startup_timeout_seconds":90,"work_timeout_seconds":300}).to_string()).unwrap();
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"));
        command
            .args([
                "supervise",
                "--once",
                "--confirm-fresh-identity",
                "--config",
            ])
            .arg(&configuration)
            .arg("--state")
            .arg(self.retained.join("supervisor-state.json"))
            .args([
                "--",
                "--sandbox",
                "danger-full-access",
                "--ask-for-approval",
                "never",
            ])
            .env("HOME", role_home)
            .env("CODEX_HOME", role_home.join(".codex"))
            .env("SAFEYOLO_COORD_SOCKET", self.root.join("bob.sock"))
            .env(
                "SAFEYOLO_COORD_TOKEN_PATH",
                self.root.join("data/agent_token"),
            )
            .kill_on_drop(true);
        if let Some(fake) = fake {
            command.env("SAFEYOLO_CODEX_BIN", fake);
        } else {
            command.env_remove("SAFEYOLO_CODEX_BIN");
            // Native clients sanitize stdio MCP child environments. Bind this
            // owned fixture's nonsecret socket/token paths explicitly, without
            // altering the selected provider or private login configuration.
            for (key, value) in [
                (
                    "command",
                    json!(env!("CARGO_BIN_EXE_safeyolo-coord")).to_string(),
                ),
                ("args", "[\"mcp\"]".into()),
                (
                    "env.SAFEYOLO_COORD_SOCKET",
                    json!(self.root.join("bob.sock")).to_string(),
                ),
                (
                    "env.SAFEYOLO_COORD_TOKEN_PATH",
                    json!(self.root.join("data/agent_token")).to_string(),
                ),
            ] {
                command
                    .arg("-c")
                    .arg(format!("mcp_servers.safeyolo-coord.{key}={value}"));
            }
        }
        let output = tokio::time::timeout(Duration::from_secs(420), command.output())
            .await
            .expect("bounded supervisor turn timed out")
            .unwrap();
        let name = if fake.is_some() { "seam" } else { "model" };
        let log = self
            .retained
            .join(format!("{name}-{}.log", uuid::Uuid::new_v4().simple()));
        fs::write(
            log,
            [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
        )
        .unwrap();
        output
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; deliberately discards an authenticated delivery response"]
async fn native_action_receipt_recovers_after_lost_response_and_proxy_restart() {
    let mut run = ReviewRun::start().await;
    let work = run.alice.call("create_work", &json!({"room_name":"shared","title":"Recover delivery","assignee":{"kind":"agent","id":BOB},"operation_id":"create"})).await.unwrap()["work"].clone();
    let actions = run
        .bob
        .call(
            "read_work_actions",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap();
    let action = &actions["actions"][0];
    assert_eq!(action["kind"], "execute_work");
    let body =
        json!({"action":"receive_action","work_id":work["work_id"],"action_key":action["key"]})
            .to_string();
    let token = fs::read_to_string(run.root.join("data/agent_token")).unwrap();
    let mut socket = tokio::net::UnixStream::connect(run.root.join("bob.sock"))
        .await
        .unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/work HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", token.trim(), body.len()).as_bytes()).await.unwrap();
    let mut first_byte = [0];
    assert_eq!(socket.read(&mut first_byte).await.unwrap(), 1);
    drop(socket); // The committed receipt body never reaches the caller.
    stage0::crash(run.proxy).await;
    run.proxy = stage0::start_proxy(&run.root).await;
    let args = json!({"room_name":"shared","work_id":work["work_id"],"action_key":action["key"]});
    let receipt = run.bob.call("receive_work_action", &args).await.unwrap();
    assert_eq!(receipt["operation_id"], action["key"]);
    assert_eq!(receipt["action"], *action);
    assert_eq!(
        run.bob.call("receive_work_action", &args).await.unwrap(),
        receipt
    );
    assert_eq!(read(&run.bob, &work).await["state"], "open");
    let remaining = run
        .bob
        .call(
            "read_work_actions",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap();
    assert!(remaining["actions"].as_array().unwrap().is_empty());
    let conn = rusqlite::Connection::open(run.root.join("data/coord/v0.db")).unwrap();
    let count: i64 = conn.query_row("SELECT count(*) FROM coord_operations WHERE operation_type='coord.work.receive_action'", [], |r| r.get(0)).unwrap();
    assert_eq!(
        count, 1,
        "recovery must retain one original logical delivery"
    );
    stage0::crash(run.proxy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; native API and deterministic model event seam"]
async fn native_delivery_is_not_completed_by_narration_and_restart_uses_current_work() {
    let run = ReviewRun::start().await;
    let role_home = run.retained.join("seam-home");
    fs::create_dir_all(role_home.join(".codex")).unwrap();
    fs::write(role_home.join(".codex/config.toml"),format!("forced_chatgpt_auth=false\nmodel_provider='fixture'\nmodel='fixture-model'\n[mcp_servers.safeyolo-coord]\ncommand={:?}\n[model_providers.fixture.auth]\ncommand='/usr/bin/true'\nargs=[]\n",env!("CARGO_BIN_EXE_safeyolo-coord"))).unwrap();
    let seam = run.retained.join("completed-without-work");
    let marker = run.retained.join("model-invocations");
    fs::write(&seam,format!("#!/bin/sh\nif [ \"$1\" = '--version' ]; then exit 0; fi\ncat >/dev/null\nprintf 'invoked\\n' >> '{}'\nprintf '%s\\n' '{{\"type\":\"turn.started\"}}' '{{\"type\":\"turn.completed\"}}'\n",marker.display())).unwrap();
    fs::set_permissions(&seam, fs::Permissions::from_mode(0o700)).unwrap();
    let work=run.alice.call("create_work",&json!({"room_name":"shared","title":"Explicit assignment","assignee":{"kind":"agent","id":BOB},"operation_id":"assignment"})).await.unwrap()["work"].clone();
    let result = run.supervise(&role_home, Some(&seam)).await;
    assert!(
        !result.status.success(),
        "narration must leave native execution pending"
    );
    let state: Value =
        serde_json::from_slice(&fs::read(run.retained.join("supervisor-state.json")).unwrap())
            .unwrap();
    assert_eq!(state["native_in_flight"].as_array().unwrap().len(), 1);
    assert_eq!(read(&run.bob, &work).await["state"], "open");
    let work = claim(&run.bob, &work, "interactive-claim").await;
    // Recover after a completed native effect whose harness result was absent.
    run.bob.call("complete_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":1,"short_result":"Actual execution settled through its native authority","operation_id":"interactive-completion"})).await.unwrap();
    let result = run.supervise(&role_home, Some(&seam)).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&marker).unwrap().lines().count(),
        1,
        "restart must retire settled work without another model turn"
    );
    let state: Value =
        serde_json::from_slice(&fs::read(run.retained.join("supervisor-state.json")).unwrap())
            .unwrap();
    assert!(
        state
            .get("native_in_flight")
            .is_none_or(|v| v.as_array().unwrap().is_empty())
    );
    // Interleaved creation lets one page derive more than sixteen actions.
    // This explicitly non-independent policy is a transport capacity control;
    // the real model journey below keeps independent production and review.
    let mut works = Vec::new();
    for n in 0..5 {
        works.push(run.bob.call("create_work",&json!({"room_name":"shared","title":format!("Capacity control {n}"),"assignee":{"kind":"agent","id":BOB},"operation_id":format!("capacity-{n}")})).await.unwrap()["work"].clone());
    }
    for (n, work) in works.iter_mut().enumerate() {
        *work = claim(&run.bob, work, &format!("capacity-claim-{n}")).await;
        let artifact = run.retained.join(format!("capacity-{n}.txt"));
        fs::write(&artifact, "Retained capacity control").unwrap();
        *work = publish(&run.bob, work, &artifact, &format!("capacity-output-{n}")).await;
        let mut selected = requirements(work, &[], &[], &format!("capacity-select-{n}"));
        selected["authorities"] = json!([]);
        selected["deciders"] = json!([{"kind":"agent","id":BOB}]);
        selected["independent"] = json!(false);
        *work = run
            .bob
            .call("set_work_requirements", &selected)
            .await
            .unwrap()["work"]
            .clone();
    }
    let before: Value =
        serde_json::from_slice(&fs::read(run.retained.join("supervisor-state.json")).unwrap())
            .unwrap();
    let result = run.supervise(&role_home, Some(&seam)).await;
    assert!(!result.status.success());
    let pending: Value =
        serde_json::from_slice(&fs::read(run.retained.join("supervisor-state.json")).unwrap())
            .unwrap();
    assert_eq!(
        pending["safe_cursor"], before["safe_cursor"],
        "partial page must retain its source cursor"
    );
    assert_eq!(
        pending["native_in_flight"].as_array().unwrap().len(),
        8,
        "informational deliveries retire; execution and acceptance stay pending"
    );
    for (n, work) in works.iter_mut().enumerate() {
        *work=run.bob.call("complete_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"operation_id":format!("capacity-complete-{n}")})).await.unwrap()["work"].clone();
        run.bob
            .call(
                "decide_work_acceptance",
                &super::reviews::acceptance(work, "approve", &format!("capacity-accept-{n}")),
            )
            .await
            .unwrap();
    }
    let result = run.supervise(&role_home, Some(&seam)).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let count = fs::read_to_string(&marker).unwrap().lines().count();
    run.alice.call("create_work", &json!({"room_name":"shared","title":"Unassigned work must not wake Bob","operation_id":"irrelevant"})).await.unwrap();
    let result = run.supervise(&role_home, Some(&seam)).await;
    assert!(result.status.success());
    assert_eq!(
        fs::read_to_string(&marker).unwrap().lines().count(),
        count,
        "remaining updates and unrelated work cannot launch another model turn"
    );
    stage0::crash(run.proxy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS and SAFEYOLO_COORD_MODEL_HOME with private native Codex login and current Coord MCP registration"]
async fn real_model_wakes_for_report_check_challenge_disposition_and_acceptance() {
    let role_home = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_MODEL_HOME")
            .expect("set prepared private native Codex role home"),
    );
    let run = ReviewRun::start().await;
    fs::write(run.retained.join("AGENTS.md"),"You are Bob, the independent native Coord reviewer in a disposable proof. Work only from native_in_flight. Read each current Work and its exact referenced local artifact before answering. file:// artifact refs end with a #sha256 digest; verify that digest. Use the supplied native Coord MCP tools. Claim your assigned checks and answer_check with approve or reject based on the requested criterion, then stop that check's execution. When a challenge response is ready, inspect the original objection and named correction, then resolve_challenge explicitly with dismissed if the correction addresses it, or upheld otherwise. A response alone never resolves it. When selected acceptance is ready, independently inspect the retained current output and selected obligations, then decide_work_acceptance. Do not change requirement policy, fabricate results or send protocol messages. Pick operation_id before each native mutation; recover uncertain writes by their original ID. Do not read credentials or any other role's home.\n").unwrap();
    let first = run.retained.join("report-v1.md");
    let corrected = run.retained.join("report-v2.md");
    fs::write(&first, "# Observation\nThe required result is absent.\n").unwrap();
    fs::write(
        &corrected,
        "# Observation\nThe required result is recorded here.\n",
    )
    .unwrap();
    let work = run
        .alice
        .call(
            "create_work",
            &json!({"room_name":"shared","title":"Verify report content","operation_id":"create"}),
        )
        .await
        .unwrap()["work"]
        .clone();
    let work = claim(&run.alice, &work, "claim").await;
    let work = publish(&run.alice, &work, &first, "publish-1").await;
    let check=run.alice.call("request_check",&json!({"room_name":"shared","subject":subject(&work),"criterion":"Verify the retained report contains the exact line: The required result is recorded here.","reviewer":{"kind":"agent","id":BOB},"independent":true,"operation_id":"request-1"})).await.unwrap()["work"].clone();
    let work = run
        .alice
        .call(
            "set_work_requirements",
            &requirements(&work, std::slice::from_ref(&check), &[], "select-1"),
        )
        .await
        .unwrap()["work"]
        .clone();
    let result = run.supervise(&role_home, None).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let check = read(&run.alice, &check).await;
    assert_eq!(check["check"]["answer"]["verdict"], "reject");
    assert_eq!(check["check"]["answer"]["author"]["id"], BOB);
    let objection=run.alice.call("raise_challenge",&json!({"room_name":"shared","subject":subject(&work),"assertion":"The report omits the required result","grounds":"The original report states that the result is absent","responder":{"kind":"agent","id":"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"deciders":[{"kind":"agent","id":BOB}],"independent":true,"operation_id":"challenge"})).await.unwrap()["work"].clone();
    let work = publish(&run.alice, &work, &corrected, "publish-2").await;
    let objection = claim(&run.alice, &objection, "claim-response").await;
    let objection=run.alice.call("respond_challenge",&json!({"room_name":"shared","work_id":objection["work_id"],"expected_version":objection["version"],"expected_generation":1,"summary":"Retained report revision 2 includes the required result","correction":subject(&work),"operation_id":"response"})).await.unwrap()["work"].clone();
    let check=run.alice.call("request_check",&json!({"room_name":"shared","subject":subject(&work),"criterion":"Verify the retained report contains the exact line: The required result is recorded here.","reviewer":{"kind":"agent","id":BOB},"independent":true,"operation_id":"request-2"})).await.unwrap()["work"].clone();
    let work = run
        .alice
        .call(
            "set_work_requirements",
            &requirements(
                &work,
                std::slice::from_ref(&check),
                std::slice::from_ref(&objection),
                "select-2",
            ),
        )
        .await
        .unwrap()["work"]
        .clone();
    // One native response handoff wakes the selected independent participant.
    // Answering the check and explicitly disposing of the objection may make a
    // new acceptance action ready; another bounded cycle receives that action.
    for _ in 0..3 {
        let result = run.supervise(&role_home, None).await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        if read(&run.alice, &work).await["acceptance_status"]["state"] == "accepted" {
            break;
        }
    }
    let final_work = read(&run.alice, &work).await;
    assert_eq!(final_work["acceptance_status"]["state"], "accepted");
    let objection = read(&run.alice, &objection).await;
    assert_eq!(
        objection["challenge"]["disposition"]["decision"],
        "dismissed"
    );
    assert_eq!(objection["challenge"]["disposition"]["author"]["id"], BOB);
    assert_eq!(
        read(&run.alice, &check).await["check"]["answer"]["verdict"],
        "approve"
    );
    // This check was performed by the actual model. The controller only reads
    // canonical outcomes and supplies Alice's separate interactive mutations.
    println!(
        "real supervised native journey passed: work={} check={} challenge={} producer={} decider={BOB}",
        work["work_id"], check["work_id"], objection["work_id"], final_work["output"]["producer"]
    );
    stage0::crash(run.proxy).await;
}
