//! Actual native clients consume one controlled approval/evidence fixture.

use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::fd::FromRawFd,
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

#[path = "support/shared_approvals.rs"]
mod shared_approval_fixture;
mod test_owned_endpoint;
use shared_approval_fixture::*;

fn configure(fixture: &Fixture) {
    fs::write(fixture.root.path().join("config.toml"), format!(
        "admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n", fixture.admin)).unwrap();
    fs::write(
        fixture.root.path().join("data/instance_id"),
        "sy-44444444444444444444444444444444\n",
    )
    .unwrap();
}

async fn cli(root: &Path, args: &[&str]) -> std::process::Output {
    timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(root)
            .args(args)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn success(root: &Path, args: &[&str]) -> Value {
    let output = cli(root, args).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_helper_reads_prepares_and_human_resolves_without_evidence_copying() {
    let fixture = Fixture::new().await;
    configure(&fixture);
    let blocked = fixture.network("worker", fixture.address).await;
    assert_eq!(blocked.status, 428);
    let id = blocked.id();
    let foreign = fixture.network("peer", fixture.address).await.id();
    let root = fixture.root.path();
    let helper_socket = root.join("helper.sock");
    let token = root.join("data/agent_token");
    let socket = helper_socket.to_str().unwrap();
    let token = token.to_str().unwrap();
    let denied = cli(
        root,
        &[
            "helper",
            "show",
            &id,
            "--socket",
            socket,
            "--token-file",
            token,
        ],
    )
    .await;
    assert!(!denied.status.success());
    let before: Value = toml::from_str(&fixture.source()).unwrap();
    for payload in [
        json!({"helper":"helper","helper_id":WORKER_ID}),
        json!({"helper":"helper","helper_id":HELPER_ID,"host":"other-origin","port":1}),
        json!({"helper":"helper","helper_id":HELPER_ID,"argv":["touch","untrusted"]}),
    ] {
        let rejected = fixture
            .admin(
                "POST",
                &format!("/admin/approvals/{id}/readers"),
                Some(payload),
            )
            .await;
        assert!(matches!(rejected.status, 400 | 409));
        assert_eq!(before, toml::from_str::<Value>(&fixture.source()).unwrap());
    }
    assert!(matches!(
        fixture
            .agent(
                "helper",
                "POST",
                &format!("/admin/approvals/{id}/readers"),
                Some(json!({"helper":"helper","helper_id":HELPER_ID}))
            )
            .await
            .status,
        404 | 405
    ));
    let shared = success(
        root,
        &[
            "approvals",
            "share",
            &id,
            "--helper",
            "helper",
            "--agent",
            "worker",
        ],
    )
    .await;
    assert_eq!(shared["reads"], json!(["diagnostic", "approval"]));
    assert!(
        shared["effect"]
            .as_str()
            .unwrap()
            .contains("No network permission")
    );
    let shared_source = fixture.source();
    success(root, &["approvals", "share", &id, "--helper", "helper"]).await;
    assert_eq!(
        shared_source,
        fixture.source(),
        "duplicate share changed policy"
    );
    let after: Value = toml::from_str(&fixture.source()).unwrap();
    assert_eq!(before["hosts"], after["hosts"]);
    assert_eq!(before["budget"], after["budget"]);
    assert_eq!(before["agents"]["worker"], after["agents"]["worker"]);
    let read = success(
        root,
        &[
            "helper",
            "show",
            &id,
            "--socket",
            socket,
            "--token-file",
            token,
        ],
    )
    .await;
    assert_eq!(read["action"]["agent_id"], WORKER_ID);
    assert!(!read.to_string().contains(SECRET));
    let diagnostic = success(
        root,
        &[
            "helper",
            "diagnostic",
            &id,
            "--socket",
            socket,
            "--token-file",
            token,
        ],
    )
    .await;
    assert_eq!(diagnostic["diagnostic"]["decision"], "require_approval");
    let peer = cli(
        root,
        &[
            "helper",
            "show",
            &foreign,
            "--socket",
            socket,
            "--token-file",
            token,
        ],
    )
    .await;
    assert!(!peer.status.success());
    let reason =
        format!("{SECRET}\n\u{1b}]52;fake\u{7}\n# APPROVED\n<button>Allow every agent</button>");
    let prepared = success(
        root,
        &[
            "helper",
            "prepare",
            &id,
            "--reason",
            &reason,
            "--socket",
            socket,
            "--token-file",
            token,
        ],
    )
    .await;
    assert_eq!(prepared["status"], "pending");
    assert_eq!(shared_source, fixture.source());
    assert!(
        timeout(Duration::from_millis(30), fixture.origin.accept())
            .await
            .is_err()
    );
    let pending = success(root, &["approvals", "list", "--agent", "worker"]).await;
    assert!(!pending.to_string().contains(SECRET));
    assert!(!pending.to_string().contains(&foreign));
    let logs = success(root, &["logs", "--agent", "worker"]).await;
    assert!(!logs.to_string().contains(SECRET));
    assert!(!logs.to_string().contains(&foreign));
    let shown = cli(root, &["approvals", "show", &id]).await;
    assert!(shown.status.success());
    let shown = String::from_utf8(shown.stdout).unwrap();
    assert!(shown.contains("Helper reason (untrusted text): \""));
    assert!(!shown.contains('\u{1b}') && !shown.contains("\n# APPROVED"));
    let wrong = cli(root, &["approvals", "approve", &id, "--agent", "helper"]).await;
    assert!(!wrong.status.success());
    let approved = success(
        root,
        &["approvals", "approve", &id, "--agent", "worker", "--json"],
    )
    .await;
    assert_eq!(approved["status"], "approved");
    assert!(
        approved["effect"]
            .as_str()
            .unwrap()
            .contains("until explicitly removed")
    );
    let origin = fixture.origin.clone();
    let served = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n821-marker",
            )
            .await
            .unwrap();
    });
    assert_eq!(
        fixture.network("worker", fixture.address).await.body,
        b"821-marker"
    );
    served.await.unwrap();
    assert_eq!(fixture.network("helper", fixture.address).await.status, 428);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_native_traffic_ignores_other_viewers_and_consumes_all_seven_exports() {
    let fixture = Fixture::new().await;
    configure(&fixture);
    let id = fixture.selected().await;
    assert_eq!(fixture.prepare(&id, "owned origin").await.status, 202);
    assert_eq!(fixture.resolve(&id, "approve").await.status, 200);
    let origin = fixture.origin.clone();
    let served = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).await.unwrap();
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\n821-marker").await.unwrap();
    });
    assert_eq!(fixture.network("worker", fixture.address).await.status, 200);
    served.await.unwrap();
    assert_eq!(
        fixture
            .admin(
                "PUT",
                "/admin/traffic/scope",
                Some(json!({"agent":"helper"}))
            )
            .await
            .status,
        200
    );
    assert_eq!(
        fixture
            .admin(
                "PUT",
                "/admin/traffic/filter",
                Some(json!({"user_filter":"~u never-matches"}))
            )
            .await
            .status,
        200
    );
    let root = fixture.root.path();
    let flows = success(
        root,
        &[
            "traffic", "list", "--agent", "worker", "--filter", "~c 200", "--json",
        ],
    )
    .await;
    let rows = flows["flows"].as_array().unwrap();
    assert_eq!(flows["scope"]["agent"], "worker");
    assert_eq!(flows["scope"]["user_filter"], "~c 200");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["agent"], "worker");
    let flow_id = rows[0]["id"].as_str().unwrap();
    let detail = success(
        root,
        &["traffic", "show", flow_id, "--agent", "worker", "--json"],
    )
    .await;
    assert!(
        detail["response_headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pair| pair[0]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("content-type")))
    );
    let body = success(
        root,
        &["traffic", "body", flow_id, "response", "--agent", "worker"],
    )
    .await;
    assert!(body.to_string().contains("821-marker"));
    for format in [
        "raw",
        "raw_request",
        "raw_response",
        "curl",
        "httpie",
        "har",
        "zhar",
    ] {
        let destination = root.join(format);
        let value = success(
            root,
            &[
                "traffic",
                "export",
                flow_id,
                format,
                destination.to_str().unwrap(),
                "--agent",
                "worker",
            ],
        )
        .await;
        assert_eq!(value["generated_commands_executed"], false);
        let bytes = fs::read(destination).unwrap();
        assert!(!bytes.is_empty());
        match format {
            "har" => {
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                assert!(value["log"]["entries"].is_array());
            }
            "zhar" => {
                let mut decoder = flate2::read::ZlibDecoder::new(&bytes[..]);
                let mut decoded = Vec::new();
                decoder.read_to_end(&mut decoded).unwrap();
                let value: Value = serde_json::from_slice(&decoded).unwrap();
                assert!(value["log"]["entries"].is_array());
            }
            "raw" | "raw_response" => {
                assert!(String::from_utf8_lossy(&bytes).contains("821-marker"))
            }
            _ => assert!(String::from_utf8_lossy(&bytes).contains("/marker")),
        }
    }
    let scope = fixture
        .admin("GET", "/admin/traffic/scope", None)
        .await
        .json();
    assert_eq!(scope["agent"], "helper");
    assert_eq!(scope["user_filter"], "~u never-matches");
    let foreign = cli(root, &["traffic", "show", flow_id, "--agent", "helper"]).await;
    assert!(!foreign.status.success());
    // Selection must also be applied to the export's actual byte read.
    let wrong = fixture
        .admin(
            "GET",
            &format!("/admin/traffic/flows/{flow_id}/export?format=raw&agent=helper"),
            None,
        )
        .await;
    assert_eq!(wrong.status, 404);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruned_selection_keeps_prior_export_and_local_diagnosis_survives_api_stop() {
    let fixture = Fixture::with_retention(1).await;
    configure(&fixture);
    let first = fixture.network("worker", fixture.address).await;
    assert_eq!(first.status, 428);
    let flows = success(
        fixture.root.path(),
        &["traffic", "list", "--agent", "worker", "--json"],
    )
    .await;
    let id = flows["flows"][0]["id"].as_str().unwrap();
    let second = fixture.network("peer", fixture.address).await;
    assert_eq!(second.status, 428);
    let destination = fixture.root.path().join("prior-export");
    fs::write(&destination, "prior bytes").unwrap();
    let output = cli(
        fixture.root.path(),
        &[
            "traffic",
            "export",
            id,
            "raw",
            destination.to_str().unwrap(),
        ],
    )
    .await;
    assert!(!output.status.success());
    assert_eq!(fs::read(destination).unwrap(), b"prior bytes");
    let root = fixture.root.path().to_owned();
    fixture.proxy.shutdown().await;
    let diagnosis = success(&root, &["diagnose", "--agent", "worker"]).await;
    assert_eq!(diagnosis["admin"]["available"], false);
    assert_eq!(diagnosis["local_policy"], "valid");
    assert!(
        !success(&root, &["logs", "--agent", "worker"]).await["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_resolution_reply_reads_canonical_outcome_without_reposting() {
    let fixture = Fixture::new().await;
    configure(&fixture);
    let id = fixture.selected().await;
    let bridge = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = bridge.local_addr().unwrap().port();
    fs::write(
        fixture.root.path().join("config.toml"),
        format!("admin_port={port}\nadmin_api_token_file='admin_token'\n"),
    )
    .unwrap();
    let effect = format!(
        "Allow reusable network access for worker ({WORKER_ID}) to {} port {} until explicitly removed.",
        fixture.address.ip(),
        fixture.address.port()
    );
    let record = json!({"request_id":id,"status":"pending","action":{"agent":"worker","agent_id":WORKER_ID},"effect":effect});
    let target = id.clone();
    let server = tokio::spawn(async move {
        let mut posts = 0;
        for _ in 0..3 {
            let (mut stream, _) = bridge.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                bytes.push(byte[0]);
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let header = String::from_utf8(bytes).unwrap();
            assert!(header.contains(&format!("/admin/approvals/{target}")));
            if header.starts_with("POST ") {
                posts += 1;
                continue;
            }
            let mut record = record.clone();
            if posts == 1 {
                record["status"] = json!("approved");
            }
            let body = record.to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
        posts
    });
    let output = success(
        fixture.root.path(),
        &["approvals", "approve", &id, "--json"],
    )
    .await;
    assert_eq!(output["status"], "approved");
    assert_eq!(server.await.unwrap(), 1);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pseudo_terminal_retains_workflow_target_through_navigation_and_unavailability() {
    let fixture = Fixture::new().await;
    configure(&fixture);
    let blocked = fixture.network("worker", fixture.address).await;
    assert_eq!(blocked.status, 428);
    let request_id = blocked.id();
    let root = fixture.root.path();
    let factory = root.join("factories/operator/snapshots");
    fs::create_dir_all(&factory).unwrap();
    let snapshot = "a".repeat(64);
    fs::write(factory.parent().unwrap().join("approved"), &snapshot).unwrap();
    fs::write(factory.join(format!("{snapshot}.json")),json!({"schema":"safeyolo.factory/v1","name":"operator","roles":{"worker":{"agent":"worker"},"helper":{"agent":"helper"}}}).to_string()).unwrap();
    let path = root.to_owned();
    let output = tokio::task::spawn_blocking(move || {
        let mut master=-1;let mut slave=-1;
        assert_eq!(unsafe {libc::openpty(&mut master,&mut slave,std::ptr::null_mut(),std::ptr::null(),std::ptr::null())},0);
        let mut terminal = unsafe {fs::File::from_raw_fd(master)};
        let slave = unsafe {fs::File::from_raw_fd(slave)};
        let mut child=std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root").arg(path).args(["inspect","--factory","operator"])
            .stdin(slave.try_clone().unwrap()).stdout(slave.try_clone().unwrap()).stderr(slave).spawn().unwrap();
        terminal.write_all(b"select worker\nstate\npending\nlogs\nattach\nback\nselect helper\npending\nquit\n").unwrap();
        // The owned child has a bounded external timeout in the test command.
        let mut output=Vec::new();
        loop {let mut buffer=[0;4096];match terminal.read(&mut buffer){Ok(0)=>break,Ok(n)=>output.extend_from_slice(&buffer[..n]),Err(error) if error.raw_os_error()==Some(libc::EIO)=>break,Err(error)=>panic!("pty read: {error}")}}
        assert!(child.wait().unwrap().success());
        String::from_utf8(output).unwrap()
    }).await.unwrap();
    assert!(output.contains("Workflow: operator | Agent: worker"));
    assert!(output.contains("Returned to workflow operator; selected agent retained."));
    assert!(output.contains("Workflow: operator | Agent: helper"));
    assert!(
        output.contains("Unavailable:"),
        "fixture has no installed host terminal owner"
    );
    let explicit = success(root, &["approvals", "list", "--agent", "worker", "--json"]).await;
    assert_eq!(explicit["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(explicit["approvals"][0]["request_id"], request_id);
    assert!(
        explicit["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["agent"] == "worker")
    );
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_model_does_not_block_manual_resolution_or_grant_permission() {
    let fixture = Fixture::new().await;
    configure(&fixture);
    let blocked = fixture.network("worker", fixture.address).await;
    assert_eq!(blocked.status, 428);
    let id = blocked.id();
    let original: Value = toml::from_str(&fixture.source()).unwrap();
    // No model executable, authentication or model process exists in this
    // client environment. Native inspection and human decisions remain usable.
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .env("PATH", "")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENAI_ACCESS_TOKEN")
        .arg("--root")
        .arg(fixture.root.path())
        .args([
            "approvals",
            "share",
            &id,
            "--helper",
            "helper",
            "--agent",
            "worker",
            "--json",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let shared: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shared["helper_session"]["available"], false);
    assert!(
        shared["helper_session"]["guidance"]
            .as_str()
            .unwrap()
            .contains("direct approval controls")
    );
    let selected = fixture.source();
    assert_eq!(
        toml::from_str::<Value>(&selected).unwrap()["hosts"],
        original["hosts"]
    );
    let pending = success(
        fixture.root.path(),
        &["approvals", "list", "--agent", "worker", "--json"],
    )
    .await;
    assert_eq!(pending["approvals"][0]["request_id"], id);
    let rejected = success(fixture.root.path(), &["approvals", "reject", &id, "--json"]).await;
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(selected, fixture.source());
    assert!(
        timeout(Duration::from_millis(30), fixture.origin.accept())
            .await
            .is_err()
    );
    fixture.stop().await;
}

async fn http_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192);
        head.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_selection_opens_one_existing_websocket_transcript() {
    use safeyolo_proxy::websocket::{Event, Message, Reader, Writer};
    use tungstenite::protocol::frame::coding::Control;
    let fixture = Fixture::new().await;
    configure(&fixture);
    let id = fixture.selected().await;
    assert_eq!(fixture.resolve(&id, "approve").await.status, 200);
    let origin = fixture.origin.clone();
    let served = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        assert!(
            http_head(&mut stream)
                .await
                .starts_with("GET /socket HTTP/1.1")
        );
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
        let (read, write) = tokio::io::split(stream);
        let mut reader = Reader::new(read, true, None);
        let mut writer = Writer::new(write, false, None);
        let Event::Message(message) = reader.read().await.unwrap() else {
            panic!("client message")
        };
        assert_eq!(
            message.with_text(str::to_owned).unwrap(),
            "client transcript"
        );
        writer
            .message(Message::text_for_send("server transcript"))
            .await
            .unwrap();
        assert!(matches!(reader.read().await.unwrap(), Event::Close(_)));
        writer
            .control(Control::Close, &1000_u16.to_be_bytes())
            .await
            .unwrap();
    });
    let mut socket = tokio::net::UnixStream::connect(fixture.root.path().join("worker.sock"))
        .await
        .unwrap();
    socket.write_all(format!("GET http://{}/socket HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",fixture.address,fixture.address).as_bytes()).await.unwrap();
    assert!(http_head(&mut socket).await.starts_with("HTTP/1.1 101"));
    let (read, write) = tokio::io::split(socket);
    let mut reader = Reader::new(read, false, None);
    let mut writer = Writer::new(write, true, None);
    writer
        .message(Message::text_for_send("client transcript"))
        .await
        .unwrap();
    assert!(matches!(reader.read().await.unwrap(), Event::Message(_)));
    writer
        .control(Control::Close, &1000_u16.to_be_bytes())
        .await
        .unwrap();
    assert!(matches!(reader.read().await.unwrap(), Event::Close(_)));
    served.await.unwrap();
    let root = fixture.root.path();
    let flows = success(
        root,
        &[
            "traffic", "list", "--agent", "worker", "--filter", "~c 101", "--json",
        ],
    )
    .await;
    assert_eq!(flows["flows"].as_array().unwrap().len(), 1);
    let flow_id = flows["flows"][0]["id"].as_str().unwrap();
    let detail = success(
        root,
        &["traffic", "show", flow_id, "--agent", "worker", "--json"],
    )
    .await;
    assert!(detail["websocket"].is_object());
    let transcript = success(
        root,
        &["traffic", "websocket", flow_id, "--agent", "worker"],
    )
    .await;
    assert_eq!(transcript["messages"].as_array().unwrap().len(), 2);
    for (row, expected, from_client) in [
        (0, "client transcript", true),
        (1, "server transcript", false),
    ] {
        assert_eq!(transcript["messages"][row]["from_client"], from_client);
        let message_id = transcript["messages"][row]["id"]
            .as_u64()
            .unwrap()
            .to_string();
        let body = success(
            root,
            &[
                "traffic",
                "message",
                flow_id,
                &message_id,
                "--agent",
                "worker",
            ],
        )
        .await;
        assert_eq!(body["text"], expected);
        assert_eq!(body["end"], true);
    }
    let offset = success(root, &["traffic", "message", flow_id, "1", "--agent", "worker", "--offset", "7"]).await;
    assert_eq!(offset["offset"], 7);
    assert_eq!(offset["text"], "transcript");
    fixture.stop().await;
}
