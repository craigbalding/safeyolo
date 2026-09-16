//! Owned in-memory lifecycle controls; no process sampling or network peers.

use std::{io::Cursor, panic::AssertUnwindSafe, path::Path, sync::RwLock};

use serde_json::Value;
use tungstenite::protocol::frame::{
    FrameHeader,
    coding::{Data, OpCode},
};

use super::*;
use crate::connection_tasks::ConnectionTasks;
use crate::{Config, Runtime, audit, memory_runtime};
use tokio::task::JoinSet;

const ID: &str = "owned-client";
const HOST: &str = "Owned.invalid";

fn runtime(directory: &Path) -> Runtime {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, "{}").unwrap();
    let scanner = directory.join("scanner.json");
    std::fs::write(&scanner, r#"{"scan_patterns":[{"name":"owned-marker","pattern":"PROJ-12345","scope":"body","action":"block"}]}"#).unwrap();
    let config: Config = serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,"event_log":directory.join("diagnostics.jsonl"),
        "audit_log_path":directory.join("audit.jsonl"),"readiness_file":directory.join("ready"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_state_file":"","agent_map_file":"",
        "inspection":{"policy_file":scanner,"block_websocket_request":true,"block_websocket_response":true},
    }))
    .unwrap();
    let mut runtime = Runtime::new(config, "owned-memory", Arc::default(), None, None).unwrap();
    // Avoid ambient queue/rotation settings affecting these synthetic records.
    runtime.audit = Arc::new(audit::Writer::new(
        directory.join("audit.jsonl"),
        audit::Settings::default(),
    ));
    runtime
}

fn stats(monitor: &MemoryMonitor) -> Value {
    monitor
        .get_stats(memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap()
}

fn records(runtime: &Runtime, directory: &Path) -> Vec<Value> {
    assert!(runtime.audit.shutdown(Duration::from_secs(1)).unwrap());
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn session(runtime: &Arc<Runtime>) -> Session {
    Session {
        state: Arc::new(RwLock::new(runtime.clone())),
        identity: ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: ID.into(),
            source_id: None,
        },
        request_id: "req-owned".into(),
        host: "owned.invalid".into(),
        port: 443,
    }
}

#[test]
fn accepted_guard_counts_one_client_and_removes_before_submission_error() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path());
    memory_runtime::running(&runtime);
    let client = memory_runtime::Client::new(&runtime, ID);
    assert_eq!(stats(&runtime.memory_monitor)["active_connections"], 1);
    runtime
        .memory_monitor
        .request(
            ID,
            HOST,
            &runtime.audit,
            || Ok(7),
            crate::circuit_runtime::now,
            memory_runtime::sample,
        )
        .unwrap();
    runtime
        .memory_monitor
        .response(ID, true, false, || Ok(11))
        .unwrap();
    let before = stats(&runtime.memory_monitor);
    assert_eq!(before["connections"][0]["domain"], HOST);
    assert_eq!(before["connections"][0]["bytes_sent"], 7);
    assert_eq!(before["connections"][0]["bytes_received"], 11);
    let second_handle = runtime.memory_monitor.clone();
    drop(client);
    assert_eq!(stats(&second_handle)["active_connections"], 0);
    let events = records(&runtime, directory.path());
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "ops.startup");
    assert_eq!(events[0]["details"]["rss_start_mb"], 0.0);
    assert_eq!(events[1]["event"], "ops.memory.conn_closed");
    assert_eq!(events[1]["details"]["flow_count"], 1);

    let directory = tempfile::tempdir().unwrap();
    let failed = self::runtime(directory.path());
    let client = memory_runtime::Client::new(&failed, ID);
    let websocket = memory_runtime::WebSocket::new(&failed, ID, HOST);
    failed
        .memory_monitor
        .request(
            ID,
            HOST,
            &failed.audit,
            || Ok(0),
            || 0.,
            memory_runtime::sample,
        )
        .unwrap();
    failed.audit.poison_for_test();
    drop(websocket);
    drop(client);
    let after = stats(&failed.memory_monitor);
    assert_eq!(after["active_connections"], 0);
    assert_eq!(after["active_websockets"], 0);
}

#[tokio::test]
async fn unpolled_accepted_task_cancellation_releases_both_owned_guards() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path());
    let client = memory_runtime::Client::new(&runtime, ID);
    let websocket = memory_runtime::WebSocket::new(&runtime, ID, HOST);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _client = client;
        let _websocket = websocket;
        std::future::pending::<()>().await;
    });
    // Current-thread runtime: no yield occurred, so the task has not been polled.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let report = stats(&runtime.memory_monitor);
    assert_eq!(report["active_connections"], 0);
    assert_eq!(report["active_websockets"], 0);
    let events = records(&runtime, directory.path());
    assert_eq!(events.len(), 1, "no-flow client emits no close event");
    assert_eq!(events[0]["event"], "ops.memory.ws_closed");
    assert_eq!(events[0]["details"]["message_count"], 0);
}

fn frame(opcode: OpCode, final_frame: bool, masked: bool, body: &[u8]) -> Vec<u8> {
    let key = masked.then_some([13, 17, 23, 31]);
    let mut bytes = Vec::new();
    FrameHeader {
        opcode,
        is_final: final_frame,
        mask: key,
        ..Default::default()
    }
    .format(body.len() as u64, &mut bytes)
    .unwrap();
    bytes.extend(
        body.iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key.map_or(0, |key| key[index % 4])),
    );
    bytes
}

#[tokio::test]
async fn complete_messages_count_before_drop_and_monitor_error_preserves_scanner() {
    for poisoned in [false, true] {
        for from_client in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let runtime = Arc::new(runtime(directory.path()));
            let memory = memory_runtime::WebSocket::new(&runtime, ID, HOST);
            if poisoned {
                let monitor = runtime.memory_monitor.clone();
                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    let _ =
                        monitor.client_connected("owned-poison", || panic!("owned clock fault"));
                }));
            }
            let mut wire = frame(OpCode::Control(Control::Ping), true, from_client, b"ping");
            wire.extend(frame(
                OpCode::Data(Data::Text),
                false,
                from_client,
                b"PROJ-",
            ));
            wire.extend(frame(
                OpCode::Data(Data::Continue),
                true,
                from_client,
                b"12345",
            ));
            wire.extend(frame(
                OpCode::Data(Data::Binary),
                true,
                from_client,
                b"allowed",
            ));
            wire.extend(frame(
                OpCode::Control(Control::Close),
                true,
                from_client,
                &1000_u16.to_be_bytes(),
            ));
            let (sender, mut messages) = mpsc::channel(4);
            let (_closing, close) = watch::channel(None);
            let owner = ConnectionTasks::new(watch::channel(false).1);
            let result = read_messages(
                Reader::new(Cursor::new(wire), from_client, None),
                from_client,
                sender,
                close,
                Arc::new(session(&runtime)),
                Arc::new(InspectionLifetime {
                    cancelled: AtomicBool::new(false),
                    publication: Mutex::new(()),
                }),
                memory.monitor(),
                owner.clone(),
            )
            .await;
            owner.run(async { Ok(()) }).await;
            assert!(matches!(
                result,
                Finished::Reader(Closing {
                    code: 1000,
                    outcome: "peer_close",
                    ..
                })
            ));
            assert!(matches!(messages.recv().await, Some(Event::Ping(_))));
            let Some(Event::Message(allowed)) = messages.recv().await else {
                panic!("allowed binary missing")
            };
            assert_eq!(allowed.with_text(str::to_owned).unwrap(), "allowed");
            assert!(
                messages.recv().await.is_none(),
                "scanner-dropped message must stay dropped"
            );
            if !poisoned {
                let report = stats(&runtime.memory_monitor);
                assert_eq!(report["websockets"][0]["messages"], 2);
                assert_eq!(report["websockets"][0]["domain"], HOST);
            }
            let rows: Vec<Value> =
                std::fs::read_to_string(directory.path().join("diagnostics.jsonl"))
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["dropped"], true);
            assert_eq!(rows[1]["dropped"], false);
            drop(memory);
            if !poisoned {
                assert_eq!(stats(&runtime.memory_monitor)["active_websockets"], 0);
            }
            // Keep the owned directory alive until its asynchronous writer
            // has finished, including terminal records emitted by the guard.
            assert!(runtime.audit.shutdown(Duration::from_secs(1)).unwrap());
        }
    }
}

#[tokio::test]
async fn relay_diagnostic_error_still_ends_the_session() {
    let directory = tempfile::tempdir().unwrap();
    let mut runtime = runtime(directory.path());
    runtime.events =
        Mutex::new(std::fs::File::open(directory.path().join("diagnostics.jsonl")).unwrap());
    let runtime = Arc::new(runtime);
    let memory = memory_runtime::WebSocket::new(&runtime, ID, HOST);
    let (client, _client_peer) = tokio::io::duplex(1024);
    let (server, _server_peer) = tokio::io::duplex(1024);
    let (_stop, stop) = watch::channel(true);
    let owner = ConnectionTasks::new(stop.clone());
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        relay(
            Box::new(client),
            Box::new(server),
            Negotiated {
                client: None,
                server: None,
                subprotocol: None,
            },
            session(&runtime),
            stop,
            memory,
            owner.clone(),
        ),
    )
    .await
    .unwrap();
    owner.run(async { Ok(()) }).await;
    assert!(
        result.is_err(),
        "owned read-only diagnostic file cannot be written"
    );
    assert_eq!(stats(&runtime.memory_monitor)["active_websockets"], 0);
    let events = records(&runtime, directory.path());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "ops.memory.ws_closed");
}

#[tokio::test]
async fn canceled_relay_cleans_session_without_waiting_for_messages() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Arc::new(runtime(directory.path()));
    let memory = memory_runtime::WebSocket::new(&runtime, ID, HOST);
    let (client, _client_peer) = tokio::io::duplex(1024);
    let (server, _server_peer) = tokio::io::duplex(1024);
    let (_stop, stop) = watch::channel(false);
    let owner = ConnectionTasks::new(stop.clone());
    let mut tasks = JoinSet::new();
    tasks.spawn(relay(
        Box::new(client),
        Box::new(server),
        Negotiated {
            client: None,
            server: None,
            subprotocol: None,
        },
        session(&runtime),
        stop,
        memory,
        owner.clone(),
    ));
    tokio::task::yield_now().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    owner.abort_all();
    owner.run(async { Ok(()) }).await;
    assert_eq!(stats(&runtime.memory_monitor)["active_websockets"], 0);
    let events = records(&runtime, directory.path());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "ops.memory.ws_closed");
}
