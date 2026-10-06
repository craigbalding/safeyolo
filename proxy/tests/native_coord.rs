//! Fresh native Coord ownership and real Agent API/NATS boundaries for #818.
//! Run with SAFEYOLO_COORD_NATS_BINARY pointing at the pinned local NATS binary.
use safeyolo_proxy::{Proxy, coord_rooms, coord_tools::Client, native_config};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct NatsCleanup(PathBuf);
impl Drop for NatsCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .args(["coord", "stop"])
            .stdout(Stdio::null())
            .status();
    }
}

async fn coord_cli(root: &Path, arguments: &[&str]) -> std::process::Output {
    coord_cli_from(root, arguments, &std::env::current_dir().unwrap()).await
}

async fn coord_cli_from(
    root: &Path,
    arguments: &[&str],
    working_directory: &Path,
) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .current_dir(working_directory)
            .arg("--root")
            .arg(root)
            .arg("coord")
            .args(arguments)
            .env_remove("SAFEYOLO_NATS_TEST_INSTANCE")
            .env_remove("SAFEYOLO_NATS_TEST_PORTS")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn coord_json(root: &Path, arguments: &[&str]) -> Value {
    let output = coord_cli(root, arguments).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct RestoreNatsRecord(PathBuf, Vec<u8>);
impl Drop for RestoreNatsRecord {
    fn drop(&mut self) {
        fs::write(&self.0, &self.1).unwrap();
    }
}

#[tokio::test]
async fn malformed_listener_options_fail_before_creating_coord_state() {
    let parent = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = parent.path().join("absent");
    for arguments in [
        vec!["start", "--client-port"],
        vec!["start", "--monitor-port", "0"],
        vec!["start", "--client-port", "-1"],
        vec!["start", "--client-port", "65536"],
        vec!["start", "--monitor-port", "text"],
        vec!["start", "--monitor-port", "1.5"],
        vec!["start", "--client-port", "4222", "--client-port", "4223"],
        vec!["start", "--client-port", "65535", "--monitor-port", "65535"],
        vec!["start", "--binary"],
        vec!["start", "--unknown", "4222"],
    ] {
        let output = coord_cli(&root, &arguments).await;
        assert!(!output.status.success(), "accepted {arguments:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("port") || error.contains("--binary") || error.contains("--unknown"),
            "{error}"
        );
        assert!(
            !root.exists(),
            "invalid input created state for {arguments:?}"
        );
    }
    let help = coord_cli(&root, &["--help"]).await;
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    for token in [
        "--client-port",
        "--monitor-port",
        "4222/8222",
        "SAFEYOLO_NATS_TEST_INSTANCE",
    ] {
        assert!(help.contains(token), "{help}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn explicit_listener_ports_isolate_instances_and_refuse_conflicts() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    let binary = binary.to_str().unwrap();
    let parent = tempfile::Builder::new()
        .prefix("coord817-ports-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let make_root = |name: &str, agent_id: &str| {
        let root = parent.path().join(name);
        fs::create_dir_all(root.join("data")).unwrap();
        fs::write(root.join("data/instance_id"), format!("si-817-{name}")).unwrap();
        fs::write(root.join("data/admin_token"), "fixture-operator-token").unwrap();
        fs::write(root.join("data/agent_token"), "fixture-agent-token").unwrap();
        fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n").unwrap();
        fs::write(
            root.join("policy.toml"),
            format!("[controls.network]\nenabled=false\n[agents.alice]\nagent_id='{agent_id}'\n"),
        )
        .unwrap();
        fs::create_dir(root.join("workspace")).unwrap();
        fs::write(root.join("workspace/marker"), name).unwrap();
        root
    };
    let a = make_root("a", "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let b = make_root("b", "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let a_link = parent.path().join("a-link");
    std::os::unix::fs::symlink(&a, &a_link).unwrap();
    let a_aliases = [
        a.strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .to_owned(),
        a.join("../a"),
        a_link,
    ];
    let c = make_root("c", "ag-cccccccccccccccccccccccccccccccc");
    let default_root = make_root("defaults", "ag-dddddddddddddddddddddddddddddddd");
    let reservations: Vec<_> = (0..6)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<_> = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().port().to_string())
        .collect();
    drop(reservations);
    let _a_cleanup = NatsCleanup(a.clone());
    let _b_cleanup = NatsCleanup(b.clone());
    let _c_cleanup = NatsCleanup(c.clone());
    let _default_cleanup = NatsCleanup(default_root.clone());
    let start_a = [
        "start",
        "--binary",
        binary,
        "--client-port",
        &ports[0],
        "--monitor-port",
        &ports[1],
    ];
    let start_b = [
        "start",
        "--monitor-port",
        &ports[3],
        "--client-port",
        &ports[2],
        "--binary",
        binary,
    ];
    let a_process = coord_json(&a, &start_a).await;
    let b_process = coord_json(&b, &start_b).await;
    assert_eq!(
        a_process["client_port"].as_u64().unwrap().to_string(),
        ports[0]
    );
    assert_eq!(
        a_process["monitor_port"].as_u64().unwrap().to_string(),
        ports[1]
    );
    assert_eq!(
        b_process["client_port"].as_u64().unwrap().to_string(),
        ports[2]
    );
    assert_eq!(
        b_process["monitor_port"].as_u64().unwrap().to_string(),
        ports[3]
    );
    assert_ne!(a_process["pid"], b_process["pid"]);
    assert_ne!(a_process["server_name"], b_process["server_name"]);
    assert!(!a.join("data/coord/nats/test-endpoints.json").exists());
    assert!(!b.join("data/coord/nats/test-endpoints.json").exists());
    for alias in &a_aliases {
        assert_eq!(coord_json(alias, &["status"]).await["state"], "running");
        assert_eq!(coord_json(alias, &start_a).await, a_process);
    }
    let a_record_path = a.join("data/coord/nats/process.json");
    let a_record = fs::read(&a_record_path).unwrap();
    let a_config = fs::read(a.join("data/coord/nats/server.conf")).unwrap();
    let a_credential = fs::read(a.join("data/coord/nats/creds")).unwrap();
    let b_files = [
        "config.toml",
        "policy.toml",
        "workspace/marker",
        "data/coord/nats/process.json",
        "data/coord/nats/server.conf",
        "data/coord/nats/creds",
    ];
    let b_before: Vec<_> = b_files
        .iter()
        .map(|path| fs::read(b.join(path)).unwrap())
        .collect();
    let a_room = coord_json(&a, &["room", "create", "shared"]).await;
    let b_room = coord_json(&b, &["room", "create", "shared"]).await;
    assert_ne!(a_room["room_id"], b_room["room_id"]);
    coord_json(&a, &["grant", "shared", "alice"]).await;
    coord_json(&b, &["grant", "shared", "alice"]).await;
    let a_proxy = Proxy::start(native_config::read(&a.join("config.toml")).unwrap())
        .await
        .unwrap();
    let b_proxy = Proxy::start(native_config::read(&b.join("config.toml")).unwrap())
        .await
        .unwrap();
    let client = |root: &Path| Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
    };
    let a_client = client(&a);
    let b_client = client(&b);
    let a_sent = a_client
        .call("send", &json!({"room_name":"shared","body":"a-marker"}))
        .await
        .unwrap();
    let b_sent = b_client
        .call("send", &json!({"room_name":"shared","body":"b-marker"}))
        .await
        .unwrap();
    assert_eq!(a_sent["envelope"]["origin_instance_id"], "si-817-a");
    assert_eq!(b_sent["envelope"]["origin_instance_id"], "si-817-b");
    assert_eq!(coord_json(&a, &start_a).await, a_process);
    assert_eq!(coord_json(&a, &["start"]).await, a_process);
    assert_eq!(
        coord_json(&a, &["start", "--monitor-port", &ports[1]]).await,
        a_process
    );
    for arguments in [
        vec!["start", "--client-port", &ports[2]],
        vec!["start", "--monitor-port", &ports[3]],
        vec![
            "start",
            "--client-port",
            &ports[2],
            "--monitor-port",
            &ports[3],
        ],
    ] {
        let refused = coord_cli(&a, &arguments).await;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("already running"));
        assert_eq!(fs::read(&a_record_path).unwrap(), a_record);
        assert!(fs::read(a.join("data/coord/nats/server.conf")).unwrap() == a_config);
        assert!(fs::read(a.join("data/coord/nats/creds")).unwrap() == a_credential);
    }
    {
        let _restore = RestoreNatsRecord(a_record_path.clone(), a_record.clone());
        let mut crossed = a_process.clone();
        for key in ["server_name", "client_port", "monitor_port"] {
            crossed[key] = b_process[key].clone();
        }
        fs::write(&a_record_path, serde_json::to_vec(&crossed).unwrap()).unwrap();
        for root in std::iter::once(&a).chain(&a_aliases) {
            assert_eq!(coord_json(root, &["status"]).await["state"], "unknown");
            assert!(!coord_cli(root, &["stop"]).await.status.success());
            assert!(!coord_cli(root, &start_a).await.status.success());
        }
        assert_eq!(
            fs::read(&a_record_path).unwrap(),
            serde_json::to_vec(&crossed).unwrap()
        );
        let mut wrong_owner = a_process.clone();
        wrong_owner["pid"] = b_process["pid"].clone();
        wrong_owner["token"] = b_process["token"].clone();
        fs::write(&a_record_path, serde_json::to_vec(&wrong_owner).unwrap()).unwrap();
        for root in std::iter::once(&a).chain(&a_aliases) {
            assert!(!coord_cli(root, &["stop"]).await.status.success());
            assert!(!coord_cli(root, &start_a).await.status.success());
        }
        assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    }
    assert_eq!(coord_json(&a, &["status"]).await["state"], "running");
    assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    {
        let ports_path = a.join(format!(
            "data/coord/nats/nats-server_{}.ports",
            a_process["pid"]
        ));
        let _restore = RestoreNatsRecord(ports_path.clone(), fs::read(&ports_path).unwrap());
        fs::remove_file(&ports_path).unwrap();
        assert_eq!(coord_json(&a, &["status"]).await["state"], "unknown");
        assert!(!coord_cli(&a, &["stop"]).await.status.success());
        assert!(!coord_cli(&a, &start_a).await.status.success());
        assert_eq!(fs::read(&a_record_path).unwrap(), a_record);
    }
    for arguments in [
        vec!["start", "--client-port", "8222"],
        vec!["start", "--monitor-port", "4222"],
    ] {
        let refused = coord_cli(&c, &arguments).await;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ports must differ"));
        assert!(!c.join("data/coord/nats/server.conf").exists());
    }
    for arguments in [
        vec![
            "start",
            "--binary",
            binary,
            "--client-port",
            &ports[2],
            "--monitor-port",
            &ports[5],
        ],
        vec![
            "start",
            "--binary",
            binary,
            "--client-port",
            &ports[4],
            "--monitor-port",
            &ports[3],
        ],
    ] {
        let refused = coord_cli(&c, &arguments).await;
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("NATS exited"),
            "{}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(!c.join("data/coord/nats/process.json").exists());
        assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    }
    // Stopping/restarting A must not redirect a cached B client or B's store.
    coord_json(&a_aliases[0], &["stop"]).await;
    for key in ["client_port", "monitor_port"] {
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", a_process[key].as_u64().unwrap() as u16))
                .await
                .is_err()
        );
    }
    let b_history = b_client
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(b_history["messages"].as_array().unwrap().len(), 1);
    assert_eq!(b_history["messages"][0]["body"], "b-marker");
    b_client
        .call("send", &json!({"room_name":"shared","body":"b-fresh"}))
        .await
        .unwrap();
    // Resolve a live relative config argument against NATS's launch directory,
    // even when the next CLI caller is in a different directory.
    let output = coord_cli_from(Path::new("a"), &start_a, parent.path()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut restarted_a: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_ne!(restarted_a["server_name"], a_process["server_name"]);
    assert_eq!(restarted_a["client_port"], a_process["client_port"]);
    assert_eq!(restarted_a["monitor_port"], a_process["monitor_port"]);
    for alias in &a_aliases[1..] {
        assert_eq!(coord_json(alias, &["status"]).await["state"], "running");
        assert_eq!(coord_json(alias, &start_a).await, restarted_a);
        coord_json(alias, &["stop"]).await;
        assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
        let next = coord_json(alias, &start_a).await;
        assert_ne!(next["server_name"], restarted_a["server_name"]);
        assert_eq!(coord_json(&a, &start_a).await, next);
        restarted_a = next;
    }
    let a_history = a_client
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(a_history["messages"].as_array().unwrap().len(), 1);
    assert_eq!(a_history["messages"][0]["body"], "a-marker");
    a_client
        .call("send", &json!({"room_name":"shared","body":"a-restarted"}))
        .await
        .unwrap();
    assert!(fs::read(a.join("data/coord/nats/creds")).unwrap() == a_credential);
    for (path, before) in b_files.iter().zip(&b_before) {
        assert!(
            fs::read(b.join(path)).unwrap() == *before,
            "B file changed: {path}"
        );
    }
    assert_eq!(coord_json(&b, &["status"]).await["process"], b_process);
    a_proxy.shutdown().await;
    b_proxy.shutdown().await;
    coord_json(&a, &["stop"]).await;
    coord_json(&b, &["stop"]).await;
    for process in [&restarted_a, &b_process] {
        for key in ["client_port", "monitor_port"] {
            assert!(
                tokio::net::TcpStream::connect((
                    "127.0.0.1",
                    process[key].as_u64().unwrap() as u16
                ))
                .await
                .is_err()
            );
        }
    }
    // Exercise actual ordinary defaults and per-option defaults as well.
    let defaults = coord_json(&default_root, &["start", "--binary", binary]).await;
    assert_eq!(defaults["client_port"], 4222);
    assert_eq!(defaults["monitor_port"], 8222);
    coord_json(&default_root, &["stop"]).await;
    let partial = coord_json(
        &default_root,
        &["start", "--binary", binary, "--client-port", &ports[4]],
    )
    .await;
    assert_eq!(
        partial["client_port"].as_u64().unwrap().to_string(),
        ports[4]
    );
    assert_eq!(partial["monitor_port"], 8222);
    coord_json(&default_root, &["stop"]).await;
    let swapped = coord_json(
        &default_root,
        &[
            "start",
            "--client-port",
            "8222",
            "--monitor-port",
            &ports[5],
        ],
    )
    .await;
    assert_eq!(
        coord_json(&default_root, &["start", "--client-port", "8222"]).await,
        swapped
    );
    coord_json(&default_root, &["stop"]).await;
    println!(
        "native Coord explicit ports: isolated A/B endpoints and messages, root-alias startup/reuse/stop across working directories, conflicting/occupied listeners and unrelated-owner refusals, A restart with unchanged live B, and ordinary/partial defaults observed"
    );
}
async fn mcp(root: &Path, socket: &Path, requests: &str) -> Value {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"))
        .arg("mcp")
        .env("SAFEYOLO_COORD_SOCKET", socket)
        .env("SAFEYOLO_COORD_TOKEN_PATH", root.join("data/agent_token"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
async fn origin() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 8192];
                let _ = socket.read(&mut request).await;
                let body = b"{\"marker\":\"permitted-origin\"}";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body).await;
            });
        }
    });
    (port, task)
}
async fn traffic(alice: &Client, port: u16) {
    let stream = tokio::net::UnixStream::connect(alice.socket.as_ref().unwrap())
        .await
        .unwrap();
    let result = safeyolo_proxy::native_client::send_json(
        stream,
        &format!("127.0.0.1:{port}"),
        &format!("http://127.0.0.1:{port}/marker"),
        "fixture-token",
        hyper::Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(result["marker"], "permitted-origin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the reviewed NATS binary; run the focused native Coord witness"]
async fn fresh_rooms_restart_authorization_mcp_and_nats_failure() {
    let binary = PathBuf::from(
        std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary"),
    );
    // These variables affect only this dedicated test binary and its owned
    // dynamic NATS ports. Production/factory state is never selected.
    unsafe {
        std::env::set_var(
            "SAFEYOLO_NATS_TEST_INSTANCE",
            format!("coord818-{}", uuid::Uuid::new_v4().simple()),
        );
    }
    let root = tempfile::Builder::new()
        .prefix("coord818-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = root.path();
    fs::create_dir_all(root.join("data")).unwrap();
    fs::write(root.join("data/instance_id"), "si-818-native").unwrap();
    fs::write(root.join("data/admin_token"), "fixture-operator-token").unwrap();
    fs::write(root.join("data/agent_token"), "fixture-token").unwrap();
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),"[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[[permissions]]\naction='network:request'\nresource='*'\neffect='allow'\n").unwrap();
    let config_path = root.join("config.toml");
    let dynamic = coord_rooms::start(root, Some(&binary), None, None)
        .await
        .unwrap();
    let _cleanup = NatsCleanup(root.into());
    coord_rooms::stop(root).await.unwrap();
    // Explicit ports also override the dynamic selection in a test instance.
    let first_nats = coord_rooms::start(
        root,
        Some(&binary),
        Some(dynamic["client_port"].as_u64().unwrap() as u16),
        Some(dynamic["monitor_port"].as_u64().unwrap() as u16),
    )
    .await
    .unwrap();
    assert_eq!(first_nats["client_port"], dynamic["client_port"]);
    assert_eq!(first_nats["monitor_port"], dynamic["monitor_port"]);
    let test_endpoints: Value = serde_json::from_slice(
        &fs::read(root.join("data/coord/nats/test-endpoints.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(test_endpoints, first_nats);
    let room = coord_rooms::create_room(root, "shared").await.unwrap();
    coord_rooms::create_room(root, "private").await.unwrap();
    for agent in ["alice", "bob"] {
        coord_rooms::grant(&config_path, "shared", agent, &[], false).unwrap();
    }
    coord_rooms::grant(&config_path, "private", "bob", &[], false).unwrap();
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
    };
    let bob = Client {
        socket: Some(root.join("bob.sock")),
        token_file: root.join("data/agent_token"),
    };
    let proxy = Proxy::start(native_config::read(&config_path).unwrap())
        .await
        .unwrap();
    let alice_join = alice
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let bob_join = bob
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(alice_join["room_id"], room["room_id"]);
    assert_eq!(alice_join["state"]["origin_instance_id"], "si-818-native");
    assert_eq!(
        bob_join["state"]["origin_instance_id"],
        alice_join["state"]["origin_instance_id"]
    );
    let waiting = bob.clone();
    let wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_coord",
                &json!({"since_sequence":0,"timeout_seconds":10}),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let first=alice.request(hyper::Method::POST,"/api/coord/rooms/shared/send",json!({"body":"alice-marker","sender_agent_name":"bob","sender_agent_id":"forged","notify":["bob"]}),Duration::from_secs(10)).await.unwrap();
    assert_eq!(first["envelope"]["sender_agent_name"], "alice");
    assert_eq!(
        first["envelope"]["sender_agent_id"],
        "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let woken = tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        woken["objects"][0]["object"]["msg_id"],
        first["envelope"]["msg_id"]
    );
    let second = bob
        .call("send", &json!({"room_name":"shared","body":"bob-marker"}))
        .await
        .unwrap();
    let history = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(history["messages"].as_array().unwrap().len(), 2);
    assert_eq!(history["messages"][0]["body"], "alice-marker");
    assert_eq!(history["messages"][1]["body"], "bob-marker");
    assert_eq!(history["messages"][1]["sender_agent_name"], "bob");
    assert_eq!(
        history["messages"][0]["attention_intent"],
        json!({"mode":"targeted","agent_ids":["ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]})
    );
    assert_eq!(
        history["messages"][1]["attention_intent"],
        json!({"mode":"none","agent_ids":[]})
    );
    assert!(
        bob.call("join_room", &json!({"room_name":"private"}))
            .await
            .is_ok()
    );
    for tool in ["join_room", "read_room", "send"] {
        let args = if tool == "send" {
            json!({"room_name":"private","body":"forbidden"})
        } else {
            json!({"room_name":"private"})
        };
        let error = alice.call(tool, &args).await.unwrap_err().to_string();
        assert!(error.contains("403") || error.contains("404"), "{error}");
    }
    let denied=mcp(root,alice.socket.as_ref().unwrap(),"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_room\",\"arguments\":{\"room_name\":\"private\"}}}\n").await;
    assert_eq!(denied["result"]["isError"], true);
    assert!(denied["result"]["structuredContent"].is_null());
    let malformed = mcp(root, alice.socket.as_ref().unwrap(), "{broken}\n").await;
    assert_eq!(malformed["error"]["code"], -32700);
    let (port, origin_task) = origin().await;
    traffic(&alice, port).await;
    let waiting = alice.clone();
    let cursor = history["next_cursor"].as_u64().unwrap();
    let old_wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_message",
                &json!({"room_name":"shared","since_sequence":cursor,"timeout_seconds":30}),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    proxy.shutdown().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), old_wait)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    coord_rooms::stop(root).await.unwrap();
    for key in ["client_port", "monitor_port"] {
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", first_nats[key].as_u64().unwrap() as u16))
                .await
                .is_err()
        );
    }
    coord_rooms::start(root, Some(&binary), None, None)
        .await
        .unwrap();
    let proxy = Proxy::start(native_config::read(&config_path).unwrap())
        .await
        .unwrap();
    let joined = alice
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    for key in ["room_id", "room_name", "permissions", "history_visibility"] {
        assert_eq!(joined[key], alice_join[key]);
    }
    assert_eq!(
        joined["state"]["origin_instance_id"],
        alice_join["state"]["origin_instance_id"]
    );
    assert_eq!(joined["state"]["members"], alice_join["state"]["members"]);
    let bob_rejoined = bob
        .call("join_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(
        bob_rejoined["state"]["members"],
        bob_join["state"]["members"]
    );
    let retained = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(retained["messages"], history["messages"]);
    let fresh = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"after-restart"}),
        )
        .await
        .unwrap();
    assert!(fresh["sequence"].as_u64().unwrap() > second["sequence"].as_u64().unwrap());
    coord_rooms::stop(root).await.unwrap();
    let failure = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"must-not-report-success"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        failure.contains("unavailable") || failure.contains("unknown"),
        "{failure}"
    );
    let unavailable=mcp(root,alice.socket.as_ref().unwrap(),"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"send\",\"arguments\":{\"room_name\":\"shared\",\"body\":\"unavailable-mcp\"}}}\n").await;
    assert_eq!(unavailable["result"]["isError"], true);
    traffic(&alice, port).await;
    proxy.shutdown().await;
    origin_task.abort();
    println!(
        "native Coord: two identities, targeted wake, member scope, fresh-store restart, MCP refusal/malformed/unavailable and independent proxy traffic observed; no model invoked"
    );
}
