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
    let first_nats = coord_rooms::start(root, Some(&binary)).await.unwrap();
    let _cleanup = NatsCleanup(root.into());
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
    coord_rooms::start(root, Some(&binary)).await.unwrap();
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
