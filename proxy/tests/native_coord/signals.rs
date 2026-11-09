//! Real signal author, operator/watch, replay and restart boundaries.
use super::*;
use hyper::Method;
use rusqlite::Connection;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tokio::sync::Barrier;

#[path = "../support/operator_pty.rs"]
mod operator_pty;
#[path = "../test_owned_endpoint/mod.rs"]
mod test_owned_endpoint;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn db(root: &Path) -> Connection {
    Connection::open(root.join("data/coord/v0.db")).unwrap()
}
fn count(root: &Path, sql: &str) -> i64 {
    db(root).query_row(sql, [], |r| r.get(0)).unwrap()
}
async fn signal(client: &Client, kind: &str, summary: &str, operation: &str) -> Value {
    client.call("create_signal",&json!({"room_name":"shared","kind":kind,"summary":summary,"basis":"observed","operation_id":operation})).await.unwrap()
}
async fn list(client: &Client, needs: bool) -> Value {
    client
        .call(
            "list_signals",
            &json!({"room_name":"shared","needs_operator":needs}),
        )
        .await
        .unwrap()
}
async fn watch(root: &Path, args: &[&str]) -> std::process::Output {
    let mut full = vec!["watch"];
    full.extend_from_slice(args);
    host_cli(root, &full).await
}
async fn read(client: &Client, id: &Value, revision: Option<i64>) -> Value {
    let mut args = json!({"room_name":"shared","signal_id":id});
    if let Some(revision) = revision {
        args["revision"] = json!(revision);
    }
    client.call("read_signal", &args).await.unwrap()
}

/// Count actual viewer HTTP requests and cut its connections for reconnect
/// proof. The upstream remains the real authenticated Admin listener.
#[derive(Default)]
struct ViewerRecords {
    offline: std::sync::atomic::AtomicBool,
    drop_final: std::sync::atomic::AtomicBool,
    controls: std::sync::atomic::AtomicUsize,
    completed_snapshots: std::sync::atomic::AtomicUsize,
    dropped_signals: std::sync::Mutex<std::collections::BTreeSet<String>>,
    dropped_approvals: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

async fn forward_viewer_records(
    mut viewer: tokio::net::TcpStream,
    mut host: tokio::net::TcpStream,
    records: Arc<ViewerRecords>,
) {
    use safeyolo_proxy::websocket::{Event, Reader, Writer};
    use std::sync::atomic::Ordering;
    use tungstenite::protocol::frame::coding::Control;

    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(host.read_u8().await.unwrap());
        assert!(header.len() < 8192);
    }
    assert!(header.starts_with(b"HTTP/1.1 101"));
    viewer.write_all(&header).await.unwrap();
    let (mut viewer_read, viewer_write) = viewer.into_split();
    let (host_read, mut host_write) = host.into_split();
    let mut read = Reader::new(host_read, false, None);
    let mut write = Writer::new(viewer_write, false, None);
    let forward = async {
        loop {
            match read.read().await? {
                Event::Message(message) => {
                    let event = message.with_text(|text| serde_json::from_str::<Value>(text))??;
                    if event["type"] == "operator_state" {
                        records.controls.fetch_add(1, Ordering::SeqCst);
                    }
                    let dropped = match event["event"].as_str() {
                        Some("coord.signal_resolved") => {
                            Some((&records.dropped_signals, "signal_id"))
                        }
                        Some("admin.approval_decided") => {
                            Some((&records.dropped_approvals, "approval_id"))
                        }
                        _ => None,
                    };
                    if let Some((dropped, id_field)) = dropped
                        && records.drop_final.load(Ordering::SeqCst)
                    {
                        dropped
                            .lock()
                            .unwrap()
                            .insert(event["details"][id_field].as_str().unwrap().to_owned());
                        continue;
                    }
                    write.message(message).await?;
                }
                Event::Ping(bytes) => write.control(Control::Ping, &bytes).await?,
                Event::Pong(bytes) => write.control(Control::Pong, &bytes).await?,
                Event::Close(bytes) => {
                    write.control(Control::Close, &bytes).await?;
                    return Ok::<_, safeyolo_proxy::Error>(());
                }
            }
        }
    };
    tokio::select! {
        _ = forward => {},
        _ = tokio::io::copy(&mut viewer_read, &mut host_write) => {},
    }
}

async fn viewer_relay(
    port: u16,
    requests: Arc<std::sync::atomic::AtomicUsize>,
    cuts: tokio::sync::broadcast::Sender<()>,
    fail_approval_read: Arc<std::sync::atomic::AtomicBool>,
    records: Arc<ViewerRecords>,
) -> (
    u16,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().port();
    let snapshot_started = Arc::new(tokio::sync::Notify::new());
    let snapshot_release = Arc::new(tokio::sync::Notify::new());
    let started = snapshot_started.clone();
    let release = snapshot_release.clone();
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                connection=listener.accept() => {
                    let (mut viewer,_)=connection.unwrap();let requests=requests.clone();let mut cut=cuts.subscribe();
                    let started=started.clone();let release=release.clone();let first=first.clone();let fail_approval_read=fail_approval_read.clone();let records=records.clone();
                    connections.spawn(async move {
                        let mut header=Vec::new();
                        while !header.ends_with(b"\r\n\r\n") {header.push(viewer.read_u8().await.unwrap());assert!(header.len()<8192);}
                        if records.offline.load(std::sync::atomic::Ordering::SeqCst) { return; }
                        if !header.starts_with(b"GET /admin/events ") {requests.fetch_add(1,std::sync::atomic::Ordering::SeqCst);}
                        if header.starts_with(b"GET /admin/approvals ") && fail_approval_read.swap(false,std::sync::atomic::Ordering::SeqCst) {
                            viewer.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                            return;
                        }
                        if header.starts_with(b"GET /admin/coord/signals?") && first.swap(false,std::sync::atomic::Ordering::SeqCst) {
                            started.notify_one();release.notified().await;
                        }
                        let Ok(mut host)=tokio::net::TcpStream::connect(("127.0.0.1",port)).await else {return;};
                        host.write_all(&header).await.unwrap();
                        if header.starts_with(b"GET /admin/events ") {
                            tokio::select! {_=forward_viewer_records(viewer,host,records)=>{},_=cut.recv()=>{}}
                        } else {
                            tokio::select! {_=tokio::io::copy_bidirectional(&mut viewer,&mut host)=>{},_=cut.recv()=>{}}
                            if header.starts_with(b"GET /admin/coord/signals?") || header.starts_with(b"GET /admin/approvals ") {
                                records.completed_snapshots.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    });
                },
                Some(_)=connections.join_next(),if !connections.is_empty()=>{},
            }
        }
    });
    (address, task, snapshot_started, snapshot_release)
}
async fn next_watch(
    output: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
) -> Value {
    let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .expect("pending work did not converge within five seconds")
        .unwrap()
        .expect("watch exited");
    serde_json::from_str(&line).unwrap()
}
async fn pending_network(root: &Path, address: std::net::SocketAddr, path: &str) -> String {
    let mut socket = tokio::net::UnixStream::connect(root.join("alice.sock"))
        .await
        .unwrap();
    socket.write_all(format!("GET http://{address}/{path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await.unwrap();
    let reply = String::from_utf8(bytes).unwrap();
    assert!(
        reply.starts_with("HTTP/1.1 428")
            || (root.join("logs/audit.jsonl").is_dir() && reply.starts_with("HTTP/1.1 502")),
        "{reply}\n{}",
        fs::read_to_string(root.join("proxy-diagnostics.log")).unwrap_or_default()
    );
    reply
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-safeyolo-request-id")
                .then(|| value.trim().to_owned())
        })
        .unwrap()
}

async fn resolve_signal(root: &Path, signal: &Value, operation: &str) {
    let resolved = coord_json(
        root,
        &[
            "signal",
            "resolve",
            "shared",
            signal["signal"]["signal_id"].as_str().unwrap(),
            "--expected-revision",
            "1",
            "--operation-id",
            operation,
        ],
    )
    .await;
    assert_eq!(resolved["signal"]["state"], "resolved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS for setup; attachment runs with audit and broker unavailable"]
async fn native_watch_clears_signal_attached_between_host_checks_during_audit_outage() {
    attachment_during_audit_outage(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS for setup; attachment runs with audit and broker unavailable"]
async fn native_watch_clears_approval_attached_between_host_checks_during_audit_outage() {
    attachment_during_audit_outage(true).await;
}

async fn attachment_during_audit_outage(approval: bool) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("operator-outage-attachment-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n").unwrap();
    let (_origin, address) = test_owned_endpoint::bind().await;
    fs::write(root.join("policy.toml"), format!("[controls.network]\nenabled=true\n[hosts.'{address}']\negress='prompt'\n[agents.alice]\nagent_id='{ALICE}'\n")).unwrap();
    assert!(
        host_cli(root, &["coord", "start", "--binary", &binary])
            .await
            .status
            .success()
    );
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    coord_json(root, &["grant", "shared", "alice"]).await;
    let mut proxy = stage0::start_proxy(root).await;
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let audit = root.join("logs/audit.jsonl");
    if audit.exists() {
        fs::rename(&audit, root.join("retained-audit")).unwrap();
    }
    fs::create_dir(&audit).unwrap();
    assert!(host_cli(root, &["coord", "stop"]).await.status.success());

    // Establish a host-observed clock, let its initial controls settle, then
    // use its clear to align immediately after a shared read of the empty set.
    let mut clock_watcher = host_command(root, &["watch", "--json"]).spawn().unwrap();
    let mut clock_output = tokio::io::BufReader::new(clock_watcher.stdout.take().unwrap()).lines();
    let clock = signal(
        &alice,
        "blocker",
        "Align the empty host check",
        "outage-clock",
    )
    .await;
    assert_eq!(
        next_watch(&mut clock_output).await["signal"],
        clock["signal"]
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    resolve_signal(root, &clock, "outage-clock-clear").await;
    assert_eq!(
        next_watch(&mut clock_output).await["signal_id"],
        clock["signal"]["signal_id"]
    );
    clock_watcher.kill().await.unwrap();

    let config = fs::read_to_string(root.join("config.toml")).unwrap();
    let ready: Value = serde_json::from_slice(
        &fs::read(
            native_config::read(&root.join("config.toml"))
                .unwrap()
                .readiness_file,
        )
        .unwrap(),
    )
    .unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let records = Arc::new(ViewerRecords::default());
    let (cuts, _) = tokio::sync::broadcast::channel(8);
    let (port, relay, snapshot_started, snapshot_release) = viewer_relay(
        ready["admin_port"].as_u64().unwrap() as u16,
        requests.clone(),
        cuts,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        records.clone(),
    )
    .await;
    fs::write(
        root.join("config.toml"),
        config.replace("admin_port=0", &format!("admin_port={port}")),
    )
    .unwrap();
    let mut watcher = host_command(root, &["watch", "--json"]).spawn().unwrap();
    let mut output = tokio::io::BufReader::new(watcher.stdout.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(1), snapshot_started.notified())
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let created = if approval {
        json!(pending_network(root, address, "outage-attach").await)
    } else {
        signal(
            &alice,
            "decision",
            "Visible only in attachment snapshots",
            "outage-attach",
        )
        .await
    };
    snapshot_release.notify_one();
    let seen = next_watch(&mut output).await;
    let id = if approval {
        assert_eq!(seen["approval"]["request_id"], created);
        seen["approval"]["approval_id"].as_str().unwrap().to_owned()
    } else {
        assert_eq!(seen["signal"], created["signal"]);
        created["signal"]["signal_id"].as_str().unwrap().to_owned()
    };
    // Both the attachment snapshots AND the refresh caused by the initial
    // stream control must finish while the request is still pending. Leaving
    // that initial control queued until after resolution would hide the bug.
    tokio::time::timeout(Duration::from_millis(500), async {
        while records.completed_snapshots.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    if approval {
        let _ = host_cli(root, &["approvals", "reject", &id, "--json"]).await;
        let resolved: Value = serde_json::from_slice(
            &host_cli(root, &["approvals", "show", &id, "--json"])
                .await
                .stdout,
        )
        .unwrap();
        assert_eq!(resolved["status"], "rejected");
    } else {
        resolve_signal(root, &created, "outage-attach-clear").await;
    }
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "request crossed the next host check"
    );
    assert_eq!(
        records.controls.load(Ordering::SeqCst),
        1,
        "host observed the request before resolution"
    );
    let lifetime = started.elapsed();
    println!(
        "outage attachment approval={approval}: committed resolution after {lifetime:?}; initial control and all four snapshot responses consumed; no host control observed the brief request; awaiting clear without another business event"
    );
    let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .expect("resolved request stayed visible after outage attachment")
        .unwrap()
        .expect("watch exited");
    let cleared: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        cleared[if approval { "approval_id" } else { "signal_id" }],
        id
    );
    assert_eq!(cleared["needs_operator"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
    println!(
        "outage attachment approval={approval}: lifetime={lifetime:?}, clear={:?}; initial control fully consumed before resolution; no later business event",
        started.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let idle = requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        idle,
        "idle viewer polled state"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), output.next_line())
            .await
            .is_err()
    );
    watcher.kill().await.unwrap();
    proxy.kill().await.unwrap();
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS for canonical room setup; operator recovery runs with it stopped"]
async fn native_watch_recovers_final_signal_and_approval_changes_without_a_later_event() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("operator-recovery-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n").unwrap();
    let (_origin, address) = test_owned_endpoint::bind().await;
    let (_second_origin, second_address) = test_owned_endpoint::bind().await;
    let (_approval_clock_origin, approval_clock_address) = test_owned_endpoint::bind().await;
    let (_fast_approval_origin, fast_approval_address) = test_owned_endpoint::bind().await;
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=true\n[hosts.'{address}']\negress='prompt'\n[hosts.'{second_address}']\negress='prompt'\n[hosts.'{approval_clock_address}']\negress='prompt'\n[hosts.'{fast_approval_address}']\negress='prompt'\n[agents.alice]\nagent_id='{ALICE}'\n")).unwrap();
    assert!(
        host_cli(root, &["coord", "start", "--binary", &binary])
            .await
            .status
            .success()
    );
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    coord_json(root, &["grant", "shared", "alice"]).await;
    let mut proxy = stage0::start_proxy(root).await;
    let alice = Client {
        socket: Some(root.join("alice.sock")),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let first = signal(&alice, "blocker", "Pending before attachment", "first").await;
    let first_request = pending_network(root, address, "before-attachment").await;
    let before: Value = serde_json::from_slice(
        &host_cli(root, &["approvals", "list", "--json"])
            .await
            .stdout,
    )
    .unwrap();
    let first_approval = before["approvals"][0]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(before["approvals"][0]["request_id"], first_request);
    let ready: Value = serde_json::from_slice(
        &fs::read(
            native_config::read(&root.join("config.toml"))
                .unwrap()
                .readiness_file,
        )
        .unwrap(),
    )
    .unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let (cuts, _) = tokio::sync::broadcast::channel(8);
    let fail_approval_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let records = Arc::new(ViewerRecords::default());
    let (viewer_port, relay, snapshot_started, snapshot_release) = viewer_relay(
        ready["admin_port"].as_u64().unwrap() as u16,
        requests.clone(),
        cuts.clone(),
        fail_approval_read.clone(),
        records.clone(),
    )
    .await;
    // Only the viewer uses the relay. The running host and author retain their
    // real configuration and authenticated routes.
    let original_config = fs::read_to_string(root.join("config.toml")).unwrap();
    fs::write(
        root.join("config.toml"),
        original_config.replace("admin_port=0", &format!("admin_port={viewer_port}")),
    )
    .unwrap();
    let mut watcher = host_command(root, &["watch", "--json"]).spawn().unwrap();
    let mut output = tokio::io::BufReader::new(watcher.stdout.take().unwrap()).lines();
    let mut errors = tokio::io::BufReader::new(watcher.stderr.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(5), snapshot_started.notified())
        .await
        .unwrap();
    let during_attach = signal(
        &alice,
        "blocker",
        "Created between subscription and snapshot",
        "attach-boundary",
    )
    .await;
    snapshot_release.notify_one();
    let mut attached_signals = std::collections::BTreeSet::new();
    let mut attached_approvals = Vec::new();
    for _ in 0..3 {
        let row = next_watch(&mut output).await;
        if let Some(id) = row["signal"]["signal_id"].as_str() {
            attached_signals.insert(id.to_owned());
        }
        if let Some(id) = row["approval"]["approval_id"].as_str() {
            attached_approvals.push(id.to_owned());
        }
    }
    assert_eq!(
        attached_signals,
        std::collections::BTreeSet::from([
            first["signal"]["signal_id"].as_str().unwrap().to_owned(),
            during_attach["signal"]["signal_id"]
                .as_str()
                .unwrap()
                .to_owned()
        ])
    );
    assert_eq!(attached_approvals, vec![first_approval.clone()]);
    coord_json(
        root,
        &[
            "signal",
            "resolve",
            "shared",
            during_attach["signal"]["signal_id"].as_str().unwrap(),
            "--expected-revision",
            "1",
            "--operation-id",
            "resolve-attach-boundary",
        ],
    )
    .await;
    let cleared = next_watch(&mut output).await;
    assert_eq!(cleared["signal_id"], during_attach["signal"]["signal_id"]);
    assert_eq!(cleared["needs_operator"], false);

    // Align just after the shared host read by waiting for a clear delivered
    // only through its state control. The next item's entire lifetime must fit
    // between host checks, with creation observed from JSONL and its final
    // resolution frame actually discarded on this healthy viewer connection.
    records.drop_final.store(true, Ordering::SeqCst);
    let clock = signal(
        &alice,
        "decision",
        "Align the signal host check",
        "signal-clock",
    )
    .await;
    assert_eq!(next_watch(&mut output).await["signal"], clock["signal"]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    resolve_signal(root, &clock, "signal-clock-clear").await;
    assert_eq!(
        next_watch(&mut output).await["signal_id"],
        clock["signal"]["signal_id"]
    );
    let controls = records.controls.load(Ordering::SeqCst);
    let started = std::time::Instant::now();
    let fast = signal(
        &alice,
        "blocker",
        "Fast signal seen from JSONL",
        "fast-signal",
    )
    .await;
    assert_eq!(next_watch(&mut output).await["signal"], fast["signal"]);
    resolve_signal(root, &fast, "fast-signal-clear").await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "signal lifetime crossed a host check"
    );
    assert_eq!(
        records.controls.load(Ordering::SeqCst),
        controls,
        "creation was rescued by a host control"
    );
    let lifetime = started.elapsed();
    println!(
        "signal created and resolved between host checks in {lifetime:?}; waiting for its clear with the final resolution frame dropped"
    );
    let cleared = next_watch(&mut output).await;
    assert_eq!(cleared["signal_id"], fast["signal"]["signal_id"]);
    assert_eq!(cleared["needs_operator"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        records
            .dropped_signals
            .lock()
            .unwrap()
            .contains(fast["signal"]["signal_id"].as_str().unwrap())
    );
    println!(
        "fast signal clear recovered in {:?} without a later business event",
        started.elapsed()
    );

    let request = pending_network(root, approval_clock_address, "approval-clock").await;
    let clock = next_watch(&mut output).await;
    assert_eq!(clock["approval"]["request_id"], request);
    let clock_id = clock["approval"]["approval_id"].as_str().unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        host_cli(root, &["approvals", "reject", clock_id, "--json"])
            .await
            .status
            .success()
    );
    assert_eq!(next_watch(&mut output).await["approval_id"], clock_id);
    let controls = records.controls.load(Ordering::SeqCst);
    let started = std::time::Instant::now();
    let request = pending_network(root, fast_approval_address, "fast-approval").await;
    let fast = next_watch(&mut output).await;
    assert_eq!(fast["approval"]["request_id"], request);
    let fast_id = fast["approval"]["approval_id"].as_str().unwrap();
    assert!(
        host_cli(root, &["approvals", "reject", fast_id, "--json"])
            .await
            .status
            .success()
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "approval lifetime crossed a host check"
    );
    assert_eq!(
        records.controls.load(Ordering::SeqCst),
        controls,
        "creation was rescued by a host control"
    );
    let lifetime = started.elapsed();
    println!(
        "approval created and resolved between host checks in {lifetime:?}; waiting for its clear with the final decision frame dropped"
    );
    let cleared = next_watch(&mut output).await;
    assert_eq!(cleared["approval_id"], fast_id);
    assert_eq!(cleared["needs_operator"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(records.dropped_approvals.lock().unwrap().contains(fast_id));
    println!(
        "fast approval clear recovered in {:?} without a later business event",
        started.elapsed()
    );
    records.drop_final.store(false, Ordering::SeqCst);

    // No state changes means no periodic network fetches by this viewer.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let idle = requests.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        idle,
        "idle viewer repeatedly fetched state"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), output.next_line())
            .await
            .is_err(),
        "unchanged pending work repeated alerts"
    );
    // Lose every final audit notification. Do not emit a later business event
    // to rescue any of the four transitions below. Shared local checks own it.
    let audit = root.join("logs/audit.jsonl");
    fs::rename(&audit, root.join("retained-audit")).unwrap();
    fs::create_dir(&audit).unwrap();
    assert!(host_cli(root, &["coord", "stop"]).await.status.success());
    let started = std::time::Instant::now();
    let second = signal(
        &alice,
        "decision",
        "Created with final notification missing",
        "second",
    )
    .await;
    assert_eq!(next_watch(&mut output).await["signal"], second["signal"]);
    assert!(started.elapsed() < Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    fail_approval_read.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let second_request = pending_network(root, second_address, "missing-final-approval").await;
    let approval = next_watch(&mut output).await;
    assert_eq!(approval["approval"]["request_id"], second_request);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        !fail_approval_read.load(Ordering::SeqCst),
        "the final invalidation did not encounter the deliberate API read failure"
    );
    let second_approval = approval["approval"]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let started = std::time::Instant::now();
    let resolved = coord_json(
        root,
        &[
            "signal",
            "resolve",
            "shared",
            second["signal"]["signal_id"].as_str().unwrap(),
            "--expected-revision",
            "1",
            "--operation-id",
            "resolve-final",
        ],
    )
    .await;
    assert_eq!(resolved["signal"]["state"], "resolved");
    let cleared = next_watch(&mut output).await;
    assert_eq!(cleared["signal_id"], second["signal"]["signal_id"]);
    assert_eq!(cleared["needs_operator"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
    let started = std::time::Instant::now();
    let _ = host_cli(root, &["approvals", "reject", &second_approval, "--json"]).await;
    let cleared = next_watch(&mut output).await;
    assert_eq!(cleared["approval_id"], second_approval);
    assert_eq!(cleared["needs_operator"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
    // A failed canonical read is stale/unavailable, never an empty set.
    db(root)
        .execute_batch("ALTER TABLE coord_signals RENAME TO unavailable_signals")
        .unwrap();
    let approvals_db = Connection::open(root.join("data/approvals.sqlite3")).unwrap();
    approvals_db
        .execute_batch("ALTER TABLE approvals RENAME TO unavailable_approvals")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut signals = false;
        let mut approvals = false;
        while !(signals && approvals) {
            let line = errors
                .next_line()
                .await
                .unwrap()
                .expect("watch exited during unavailable state");
            signals |= line.contains("Pending signals unavailable");
            approvals |= line.contains("Pending approvals unavailable");
        }
    })
    .await
    .expect("failed state reads were not reported as stale");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), output.next_line())
            .await
            .is_err(),
        "unavailable state cleared or repeated existing work"
    );
    db(root)
        .execute_batch("ALTER TABLE unavailable_signals RENAME TO coord_signals")
        .unwrap();
    approvals_db
        .execute_batch("ALTER TABLE unavailable_approvals RENAME TO approvals")
        .unwrap();
    drop(approvals_db);
    // Cut only the viewer's TCP paths. Reconnect re-reads the canonical set
    // while the broker and audit sink remain unavailable; no repeat alerts.
    let attached = requests.load(Ordering::SeqCst);
    let _ = cuts.send(());
    tokio::time::timeout(Duration::from_secs(5), async {
        while requests.load(Ordering::SeqCst) == attached {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), output.next_line())
            .await
            .is_err()
    );
    let current: Value = serde_json::from_slice(
        &host_cli(root, &["watch", "--once", "--json"])
            .await
            .stdout
            .iter()
            .copied()
            .take_while(|b| *b != b'\n')
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(current["signal"], first["signal"]);
    let approvals: Value = serde_json::from_slice(
        &host_cli(root, &["approvals", "list", "--json"])
            .await
            .stdout,
    )
    .unwrap();
    assert_eq!(approvals["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(approvals["approvals"][0]["approval_id"], first_approval);
    println!(
        "missed final signal/approval create and clear each converged within five seconds; broker stopped; idle request count stable at {idle}; reconnect retained unchanged current work"
    );
    watcher.kill().await.unwrap();
    proxy.kill().await.unwrap();
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS for setup; live PTY recovery runs with it stopped"]
async fn native_watch_pty_recovers_complete_pending_state_while_a_choice_is_unfinished() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("operator-pty-recovery-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n").unwrap();
    let mut origins = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..4 {
        let (origin, address) = test_owned_endpoint::bind().await;
        origins.push(origin);
        addresses.push(address);
    }
    let hosts: String = addresses
        .iter()
        .map(|address| format!("[hosts.'{address}']\negress='prompt'\n"))
        .collect();
    fs::write(
        root.join("policy.toml"),
        format!("[controls.network]\nenabled=true\n{hosts}[agents.alice]\nagent_id='{ALICE}'\n"),
    )
    .unwrap();
    assert!(
        host_cli(root, &["coord", "start", "--binary", &binary])
            .await
            .status
            .success()
    );
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    coord_json(root, &["grant", "shared", "alice"]).await;
    let mut proxy = stage0::start_proxy(root).await;
    pending_network(root, addresses[0], "before-attachment").await;
    let config_path = root.join("config.toml");
    let ready: Value = serde_json::from_slice(
        &fs::read(native_config::read(&config_path).unwrap().readiness_file).unwrap(),
    )
    .unwrap();
    let records = Arc::new(ViewerRecords::default());
    let failures = Arc::new(AtomicBool::new(false));
    let (cuts, _) = tokio::sync::broadcast::channel(8);
    let (port, relay, started, release) = viewer_relay(
        ready["admin_port"].as_u64().unwrap() as u16,
        Arc::new(AtomicUsize::new(0)),
        cuts.clone(),
        failures.clone(),
        records.clone(),
    )
    .await;
    let source = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        source.replace("admin_port=0", &format!("admin_port={port}")),
    )
    .unwrap();
    let mut terminal = operator_pty::Terminal::start(root, &["watch", "--no-color"]);
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    pending_network(root, addresses[1], "during-attachment").await;
    release.notify_one();
    let attached = terminal
        .until(0, "PENDING APPROVALS: 2 (current state refreshed)")
        .await;
    let number = attached
        .lines()
        .find_map(|line| {
            if !line.contains(&addresses[0].to_string()) {
                return None;
            }
            line.split_once('#')?
                .1
                .split_whitespace()
                .next()?
                .parse::<usize>()
                .ok()
        })
        .expect("first request retained during attachment");
    terminal.send(&format!("{number}\n"));
    terminal
        .until(0, &format!("Request #{number}: approve"))
        .await;
    terminal.send("lat");
    let disconnected = terminal.mark();
    records.offline.store(true, Ordering::SeqCst);
    cuts.send(()).unwrap();
    terminal.until(disconnected, "STALE / UNAVAILABLE").await;
    pending_network(root, addresses[2], "arrived-offline").await;
    records.offline.store(false, Ordering::SeqCst);
    terminal
        .until(
            disconnected,
            "PENDING APPROVALS: 3 (current state refreshed)",
        )
        .await;
    terminal.send("er\nlist\n");
    terminal
        .until(
            disconnected,
            &format!("#{number} [left pending] agent=alice"),
        )
        .await;

    // Lose the final audit notification and fail its pending read once. With
    // no later mutation, the same live terminal must regain all four requests.
    assert!(host_cli(root, &["coord", "stop"]).await.status.success());
    let audit = root.join("logs/audit.jsonl");
    fs::rename(&audit, root.join("retained-audit")).unwrap();
    fs::create_dir(&audit).unwrap();
    let failed_read = terminal.mark();
    failures.store(true, Ordering::SeqCst);
    let timer = std::time::Instant::now();
    pending_network(root, addresses[3], "missing-final-notification").await;
    terminal
        .until(failed_read, "Pending approvals unavailable")
        .await;
    let recovered = terminal
        .until(
            failed_read,
            "PENDING APPROVALS: 4 (current state refreshed)",
        )
        .await;
    assert!(timer.elapsed() < Duration::from_secs(5));
    assert!(!failures.load(Ordering::SeqCst));
    for address in &addresses {
        assert!(
            recovered[failed_read..].contains(&address.to_string()),
            "{recovered}"
        );
    }
    let listed: Value = serde_json::from_slice(
        &host_cli(root, &["approvals", "list", "--json"])
            .await
            .stdout,
    )
    .unwrap();
    assert_eq!(listed["approvals"].as_array().unwrap().len(), 4);
    let id = listed["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["action"]["host"].as_str() == Some(&addresses[0].ip().to_string())
                && item["action"]["port"] == json!(addresses[0].port())
        })
        .map(|item| item["approval_id"].as_str().unwrap().to_owned())
        .expect("canonical first approval");
    // Select from the terminal's stable number; canonical API state is checked
    // independently of the rendered count and text.
    let review = terminal.mark();
    terminal.send(&format!("{number}\n"));
    terminal
        .until(review, &format!("Request #{number}: approve"))
        .await;
    terminal.send("reject\n");
    terminal
        .until(
            review,
            &format!("CANONICAL OUTCOME Request #{number}: rejected"),
        )
        .await;
    terminal
        .until(review, "PENDING APPROVALS: 3 (current state refreshed)")
        .await;
    let pending: Value = serde_json::from_slice(
        &host_cli(root, &["approvals", "list", "--json"])
            .await
            .stdout,
    )
    .unwrap();
    assert_eq!(pending["approvals"].as_array().unwrap().len(), 3);
    assert!(
        !pending["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["approval_id"] == id)
    );
    terminal.finish().await;
    proxy.kill().await.unwrap();
    relay.abort();
    drop(origins);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; exercises real authenticated signals and native watch"]
async fn native_signals_author_page_watch_replay_and_restart() {
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-signals-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n")).unwrap();
    coord_json(root, &["start", "--binary", &binary]).await;
    let _cleanup = NatsCleanup(root.into());
    let room = coord_json(root, &["room", "create", "shared"]).await;
    for name in ["alice", "bob"] {
        let grant = coord_json(root, &["grant", "shared", name]).await;
        assert!(
            grant["permissions"]
                .as_array()
                .unwrap()
                .contains(&json!("page_operator"))
        );
    }
    // Block the ordinary audit destination before first delivery. Canonical
    // state must remain usable without publishing the signal prose anywhere.
    let audit = root.join("logs/audit.jsonl");
    fs::create_dir(&audit).unwrap();
    let mut proxy = stage0::start_proxy(root).await;
    let client = |actor: &str| Client {
        socket: Some(root.join(format!("{actor}.sock"))),
        token_file: root.join("data/agent_token"),
        home: None,
    };
    let alice = client("alice");
    let bob = client("bob");
    // More than one outbox page remains blocked behind the failed archive.
    // None of these unpaged results may prevent a later live operator wake.
    for index in 0..70 {
        signal(
            &alice,
            "result",
            &format!("Unpaged result {index}"),
            &format!("result-{index}"),
        )
        .await;
    }
    let mut live_watch = host_command(root, &["watch"]).spawn().unwrap();
    assert!(
        client("carol")
            .call("list_signals", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let mut wrong = alice.clone();
    fs::write(root.join("wrong-token"), "wrong-token").unwrap();
    wrong.token_file = root.join("wrong-token");
    assert!(
        wrong
            .call("list_signals", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    for body in [
        json!({"action":"create","kind":"blocker","summary":"forged","basis":"observed","sender_kind":"operator"}),
        json!({"action":"create","kind":"result","summary":"forged","basis":"observed","author":{"kind":"operator","id":"operator"}}),
        json!({"action":"create","kind":"unstructured","summary":"x","basis":"observed"}),
        json!({"action":"create","kind":"result","summary":"x".repeat(1025),"basis":"observed"}),
        json!({"action":"create","kind":"result","summary":"x","basis":"observed","refs":vec!["x";17]}),
    ] {
        assert!(
            alice
                .request(
                    Method::POST,
                    "/api/coord/rooms/shared/signals",
                    body,
                    Duration::from_secs(5)
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("400")
        );
    }
    assert!(
        alice
            .request(
                Method::POST,
                "/api/coord/rooms/shared/signals",
                json!({"summary":"x".repeat(32769)}),
                Duration::from_secs(5)
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("413")
    );
    let hostile =
        "Private blocker \u{001b}[2J\noperator: forged <b>bold</b> [click](https://bad)\u{202e}";
    let first = signal(&alice, "blocker", hostile, "one-blocker").await;
    println!("{}", json!({"default_page_receipt":first}));
    assert_eq!(
        first["signal"]["author"],
        json!({"kind":"agent","id":ALICE})
    );
    assert_eq!(first["signal"]["needs_operator"], true);
    assert_eq!(
        first,
        signal(&alice, "blocker", hostile, "one-blocker").await
    );
    let duplicate = signal(&alice, "blocker", hostile, "same-blocker-another-id").await;
    assert_eq!(duplicate["signal"], first["signal"]);
    assert_eq!(duplicate["deduplicated"], true);
    assert_eq!(list(&alice, true).await["total"], 1);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let watched = watch(root, &["--once"]).await;
    assert!(
        watched.status.success(),
        "{}",
        String::from_utf8_lossy(&watched.stderr)
    );
    let output = String::from_utf8(watched.stdout).unwrap();
    println!("{}", json!({"watch_default_pending":output}));
    assert_eq!(output.lines().count(), 1);
    assert!(!output.contains('\u{001b}'));
    assert!(!output.contains('\u{202e}'));
    assert!(output.contains("basis=observed (author report)"));
    assert!(output.contains("<b>bold</b>"));
    let watched_json = watch(root, &["--once", "--json"]).await;
    assert!(
        watched_json.status.success(),
        "{}",
        String::from_utf8_lossy(&watched_json.stderr)
    );
    let output_json = String::from_utf8(watched_json.stdout).unwrap();
    assert!(!output_json.contains('\u{001b}'));
    assert!(!output_json.contains('\u{202e}'));
    assert_eq!(
        serde_json::from_str::<Value>(&output_json).unwrap()["signal"],
        first["signal"]
    );
    coord_json(root, &["grant", "shared", "bob", "send", "receive"]).await;
    let unpaged = signal(
        &bob,
        "blocker",
        "Private attributed unpaged blocker",
        "unpaged",
    )
    .await;
    assert_eq!(unpaged["signal"]["page_status"], "permission_denied");
    assert_eq!(list(&bob, true).await["total"], 1);
    let inference=alice.call("create_signal",&json!({"room_name":"shared","kind":"result","summary":"Private mistaken inference: the host limit caused the child failure","basis":"inferred","refs":["opaque:original-child-measurement"],"operation_id":"inference"})).await.unwrap();
    assert_eq!(list(&alice, true).await["total"], 1);
    let correction = json!({"room_name":"shared","kind":"correction","summary":"Private correction: the child's inherited soft limit caused the failure","basis":"observed","supersedes":{"signal_id":inference["signal"]["signal_id"],"expected_revision":1},"operation_id":"correct"});
    assert!(
        bob.call("create_signal", &correction)
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    let barrier = Arc::new(Barrier::new(2));
    let mut corrections = Vec::new();
    for n in 0..2 {
        let client = alice.clone();
        let mut args = correction.clone();
        args["operation_id"] = json!(format!("correction-{n}"));
        let barrier = barrier.clone();
        corrections.push(tokio::spawn(async move {
            barrier.wait().await;
            client
                .call("create_signal", &args)
                .await
                .map_err(|e| e.to_string())
        }));
    }
    let results = [
        corrections.remove(0).await.unwrap(),
        corrections.remove(0).await.unwrap(),
    ];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| e.contains("409"))
    );
    assert_eq!(
        read(&alice, &inference["signal"]["signal_id"], Some(1)).await["signal"],
        inference["signal"]
    );
    assert_eq!(
        read(&bob, &inference["signal"]["signal_id"], None).await["signal"]["state"],
        "superseded"
    );
    let id = first["signal"]["signal_id"].as_str().unwrap();
    let resolved = coord_json(
        root,
        &[
            "signal",
            "resolve",
            "shared",
            id,
            "--expected-revision",
            "1",
            "--operation-id",
            "operator-answer",
        ],
    )
    .await;
    assert_eq!(resolved["signal"]["author"], first["signal"]["author"]);
    assert_eq!(list(&alice, true).await["total"], 0);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    live_watch.kill().await.unwrap();
    let live_output = live_watch.wait_with_output().await.unwrap();
    println!(
        "{}",
        json!({"live_watch_status":live_output.status.to_string(),"live_watch_stderr":String::from_utf8_lossy(&live_output.stderr)})
    );
    let live_output = String::from_utf8(live_output.stdout).unwrap();
    println!("{}", json!({"live_watch_output":live_output}));
    assert_eq!(
        live_output
            .lines()
            .filter(|line| line.starts_with("NEEDS OPERATOR"))
            .count(),
        1
    );
    assert_eq!(
        live_output
            .lines()
            .filter(|line| line.starts_with("CLEARED"))
            .count(),
        1
    );
    assert_eq!(
        read(&alice, &first["signal"]["signal_id"], Some(1)).await["signal"],
        first["signal"]
    );
    let state = alice
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(state["needs_operator"]["total"], 0);
    assert!(
        !state["signals"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["signal"]["signal_id"] == inference["signal"]["signal_id"])
    );

    // A lost response after the commit must recover its original operation,
    // even after both process and NATS restart, without adding another page.
    let lost=json!({"action":"create","kind":"decision","summary":"Private durable decision while watch is detached","basis":"observed","operation_id":"lost-response"}).to_string();
    let mut socket = tokio::net::UnixStream::connect(root.join("alice.sock"))
        .await
        .unwrap();
    let token = fs::read_to_string(root.join("data/agent_token")).unwrap();
    socket.write_all(format!("POST /api/coord/rooms/shared/signals HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{lost}",token.trim(),lost.len()).as_bytes()).await.unwrap();
    stage0::until(||count(root,"SELECT count(*) FROM coord_operations WHERE operation_type='coord.signal.create' AND operation_id='lost-response'")==1).await;
    drop(socket);
    let original:String=db(root).query_row("SELECT outcome_json FROM coord_operations WHERE operation_type='coord.signal.create' AND operation_id='lost-response'",[],|r|r.get(0)).unwrap();
    assert!(
        count(
            root,
            "SELECT count(*) FROM coord_outbox WHERE event_type='coord.signal_created' AND delivered_at IS NULL"
        ) > 0
    );
    stage0::crash(proxy).await;
    coord_json(root, &["stop"]).await;
    fs::remove_dir(&audit).unwrap();
    coord_json(root, &["start", "--binary", &binary]).await;
    proxy = stage0::start_proxy(root).await;
    let retry = signal(
        &alice,
        "decision",
        "Private durable decision while watch is detached",
        "lost-response",
    )
    .await;
    println!(
        "{}",
        json!({"lost_response_recovery":retry,"original_room":room})
    );
    assert_eq!(retry, serde_json::from_str::<Value>(&original).unwrap());
    assert_eq!(list(&alice, true).await["total"], 1);
    let detached = watch(root, &["--once", "--json"]).await;
    assert!(
        detached.status.success(),
        "{}",
        String::from_utf8_lossy(&detached.stderr)
    );
    let viewed: Value = serde_json::from_slice(&detached.stdout).unwrap();
    assert_eq!(viewed["signal"], retry["signal"]);
    // Broker loss does not interrupt operator attachment or canonical reads.
    // Reading the first line establishes the authenticated attachment.
    let mut attached = host_command(root, &["watch", "--json"]).spawn().unwrap();
    let mut output = tokio::io::BufReader::new(attached.stdout.take().unwrap()).lines();
    let initial = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&initial).unwrap()["signal"],
        retry["signal"]
    );
    coord_json(root, &["stop"]).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), output.next_line())
            .await
            .is_err()
    );
    assert!(attached.try_wait().unwrap().is_none());
    attached.kill().await.unwrap();
    let offline = watch(root, &["--once", "--json"]).await;
    assert!(
        offline.status.success(),
        "{}",
        String::from_utf8_lossy(&offline.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&offline.stdout).unwrap()["signal"],
        retry["signal"]
    );
    coord_json(root, &["start", "--binary", &binary]).await;
    let mut reattached = host_command(root, &["watch", "--json"]).spawn().unwrap();
    let mut output = tokio::io::BufReader::new(reattached.stdout.take().unwrap()).lines();
    let initial = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&initial).unwrap()["signal"],
        retry["signal"]
    );
    let recovered = signal(
        &alice,
        "blocker",
        "Private live signal after reconnect",
        "post-reconnect",
    )
    .await;
    let revision = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&revision).unwrap()["signal"],
        recovered["signal"]
    );
    reattached.kill().await.unwrap();
    reattached.wait().await.unwrap();
    stage0::until(||count(root,"SELECT count(*) FROM coord_outbox WHERE destination='audit-jsonl' AND delivered_at IS NULL")==0).await;
    let lines = fs::read_to_string(&audit).unwrap();
    assert!(!lines.contains("Private"));
    assert!(!lines.contains("opaque:original-child-measurement"));
    let events: Vec<Value> = lines
        .lines()
        .map(|line| safeyolo_proxy::audit::parse_record(line).unwrap())
        .filter(|v| {
            v["event"]
                .as_str()
                .is_some_and(|v| v.starts_with("coord.signal_"))
        })
        .collect();
    let created = events
        .iter()
        .find(|e| {
            e["details"]["signal_id"] == first["signal"]["signal_id"]
                && e["details"]["revision"] == 1
        })
        .unwrap();
    let retained = root.join("signal-events.jsonl");
    fs::write(&retained, format!("{created}\n{created}\n")).unwrap();
    let exact = watch(root, &["--jsonl", retained.to_str().unwrap(), "--json"]).await;
    assert!(
        exact.status.success(),
        "{}",
        String::from_utf8_lossy(&exact.stderr)
    );
    let exact_text = String::from_utf8(exact.stdout).unwrap();
    assert_eq!(exact_text.lines().count(), 1);
    assert!(!exact_text.contains('\u{001b}'));
    assert!(!exact_text.contains('\u{202e}'));
    assert_eq!(
        serde_json::from_str::<Value>(&exact_text).unwrap()["signal"],
        first["signal"]
    );
    let room_watch = coord_cli(
        root,
        &["watch", "--jsonl", retained.to_str().unwrap(), "--json"],
    )
    .await;
    assert!(
        room_watch.status.success(),
        "{}",
        String::from_utf8_lossy(&room_watch.stderr)
    );
    let room_text = String::from_utf8(room_watch.stdout).unwrap();
    assert!(!room_text.contains('\u{001b}'));
    assert!(!room_text.contains('\u{202e}'));
    assert_eq!(room_text, exact_text);
    let mut forged = created.clone();
    forged["details"]["author"] = json!({"kind":"operator","id":"operator"});
    fs::write(&retained, format!("{forged}\n")).unwrap();
    let rejected = watch(root, &["--jsonl", retained.to_str().unwrap()]).await;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("differs from the canonical"));

    // Failure before commit leaves no partial signal, retry record or page.
    db(root).execute_batch("CREATE TRIGGER signal_failure BEFORE INSERT ON coord_outbox WHEN NEW.event_type='coord.signal_created' BEGIN SELECT RAISE(ABORT,'injected audit staging failure'); END").unwrap();
    let before = count(root, "SELECT count(*) FROM coord_signals");
    assert!(alice.call("create_signal",&json!({"room_name":"shared","kind":"result","summary":"Private rolled-back result","basis":"observed","operation_id":"failed-before-commit"})).await.unwrap_err().to_string().contains("503"));
    assert_eq!(count(root, "SELECT count(*) FROM coord_signals"), before);
    assert_eq!(
        count(
            root,
            "SELECT count(*) FROM coord_operations WHERE operation_id='failed-before-commit'"
        ),
        0
    );
    db(root)
        .execute_batch("DROP TRIGGER signal_failure")
        .unwrap();
    signal(
        &alice,
        "result",
        "Private rolled-back result",
        "failed-before-commit",
    )
    .await;
    let work = alice
        .call(
            "create_work",
            &json!({"room_name":"shared","title":"separate completion","operation_id":"create"}),
        )
        .await
        .unwrap();
    let id = &work["work"]["work_id"];
    alice.call("claim_work",&json!({"room_name":"shared","work_id":id,"expected_version":1,"expected_generation":0,"operation_id":"claim"})).await.unwrap();
    let n = count(root, "SELECT count(*) FROM coord_signals");
    let complete = json!({"room_name":"shared","work_id":id,"expected_version":2,"expected_generation":1,"short_result":"Private one completion summary","operation_id":"complete"});
    let completed = alice.call("complete_work", &complete).await.unwrap();
    assert_eq!(
        completed,
        alice.call("complete_work", &complete).await.unwrap()
    );
    assert_eq!(
        completed["work"]["short_result"],
        "Private one completion summary"
    );
    assert_eq!(count(root, "SELECT count(*) FROM coord_signals"), n);
    coord_json(root, &["revoke", "shared", "alice"]).await;
    assert!(
        alice
            .call(
                "read_signal",
                &json!({"room_name":"shared","signal_id":retry["signal"]["signal_id"],"revision":1})
            )
            .await
            .is_err()
    );
    assert!(alice.call("create_signal",&json!({"room_name":"shared","kind":"decision","summary":"Private durable decision while watch is detached","basis":"observed","operation_id":"lost-response"})).await.is_err());
    // A new durable identity under the old display name cannot correct its
    // predecessor's claim, even after obtaining a fresh ordinary room grant.
    let replacement = fs::read_to_string(root.join("policy.toml"))
        .unwrap()
        .replace(ALICE, "ag-dddddddddddddddddddddddddddddddd");
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        "/admin/policy/baseline",
        Method::PUT,
        json!({"source":replacement}),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    coord_json(root, &["grant", "shared", "alice"]).await;
    let old = read(&bob, &retry["signal"]["signal_id"], None).await;
    assert!(alice.call("create_signal",&json!({"room_name":"shared","kind":"correction","summary":"wrong durable author","basis":"observed","supersedes":{"signal_id":old["signal"]["signal_id"],"expected_revision":1},"operation_id":"replacement-correction"})).await.unwrap_err().to_string().contains("403"));
    println!(
        "{}",
        json!({"native_signal_controls":"passed","signal_count":count(root,"SELECT count(*) FROM coord_signals"),"immutable_revisions":count(root,"SELECT count(*) FROM coord_signal_revisions"),"metadata_events":events.len(),"completion":completed})
    );
    stage0::crash(proxy).await;
}
