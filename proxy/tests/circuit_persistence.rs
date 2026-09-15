//! Actual Proxy lifecycle with owned cache, policy, readiness and socket paths.
//! Live counter/settings observations belong to the separately isolated wire
//! fixtures; these tests use neither operational tokens nor private Runtime state.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use safeyolo_proxy::{Config, Proxy, circuits::CircuitValue};
use serde_json::json;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
};

fn config(directory: &Path, state_file: Option<PathBuf>) -> Config {
    let policy = directory.join("policy.toml");
    std::fs::write(
        &policy,
        "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"allow\"\n",
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,
        "agent_api_enabled":false,
        "circuit_state_file":state_file,
        "readiness_file":directory.join("ready.json"),
        "flow_store_enabled": false,
        "event_log":directory.join("events.jsonl")
    }))
    .unwrap()
}

fn snapshot(path: &Path) -> CircuitValue {
    CircuitValue::parse_json(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn domains(value: &CircuitValue) -> Vec<String> {
    value.as_object().unwrap()["states"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}
fn field<'a>(value: &'a CircuitValue, domain: &str, name: &str) -> &'a CircuitValue {
    &value.as_object().unwrap()["states"].as_object().unwrap()[domain]
        .as_object()
        .unwrap()[name]
}
fn saved_at(value: &CircuitValue) -> f64 {
    match &value.as_object().unwrap()["saved_at"] {
        CircuitValue::Float(value) => *value,
        _ => panic!("proxy snapshots retain a floating seconds timestamp"),
    }
}
fn no_temporary_files(directory: &Path) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().ends_with(".tmp"),
            "temporary writer file remains"
        );
    }
}
fn stopped(config: &Config) {
    assert!(!config.readiness_file.exists());
    assert!(
        config
            .listeners
            .iter()
            .all(|listener| !listener.socket_path.exists())
    );
    no_temporary_files(config.readiness_file.parent().unwrap());
}
async fn shutdown(proxy: Proxy, config: &Config) {
    tokio::time::timeout(Duration::from_secs(5), proxy.shutdown())
        .await
        .expect("owned idle proxy must join shutdown writers");
    stopped(config);
}

async fn request(config: &Config, host: &str) -> (String, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut socket = UnixStream::connect(&config.listeners[0].socket_path)
            .await
            .unwrap();
        socket
            .write_all(
                format!(
                    "GET http://{host}/owned HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        let split = bytes
            .windows(4)
            .position(|value| value == b"\r\n\r\n")
            .expect("complete response head");
        (
            String::from_utf8(bytes[..split].to_vec()).unwrap(),
            bytes[split + 4..].to_vec(),
        )
    })
    .await
    .expect("owned proxy response must complete")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_reconciliation_final_save_and_restart_use_the_actual_proxy() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("state.json");
    std::fs::write(&path, r#"{"states":{"stale.invalid":{"state":"open","opened_at":0,"failure_streak":4,"success_count":9,"half_open_requests":2,"metadata":{"owned":true}},"closed.invalid":{"state":"closed","failure_count":2}},"saved_at":0.0}"#).unwrap();
    let config = config(directory.path(), Some(path.clone()));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    assert!(config.readiness_file.exists());
    shutdown(proxy, &config).await;
    let first = snapshot(&path);
    assert_eq!(domains(&first), ["stale.invalid", "closed.invalid"]);
    assert_eq!(
        field(&first, "stale.invalid", "state")
            .render_json(false)
            .unwrap(),
        "\"half_open\""
    );
    assert_eq!(
        field(&first, "stale.invalid", "failure_streak"),
        &CircuitValue::from(1)
    );
    assert_eq!(
        field(&first, "stale.invalid", "success_count"),
        &CircuitValue::from(0)
    );
    assert_eq!(
        field(&first, "stale.invalid", "half_open_requests"),
        &CircuitValue::from(0)
    );
    assert_eq!(
        field(&first, "stale.invalid", "metadata")
            .render_json(false)
            .unwrap(),
        "{\"owned\": true}"
    );
    assert!(saved_at(&first) > 0.0);

    let restarted = Proxy::start(config.clone()).await.unwrap();
    shutdown(restarted, &config).await;
    let second = snapshot(&path);
    assert_eq!(
        first.as_object().unwrap()["states"],
        second.as_object().unwrap()["states"]
    );
    assert!(saved_at(&second) >= saved_at(&first));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_and_empty_paths_leave_no_persistence_artifacts() {
    for path in [None, Some(PathBuf::new())] {
        let directory = TempDir::new().unwrap();
        let config = config(directory.path(), path);
        let proxy = Proxy::start(config.clone()).await.unwrap();
        shutdown(proxy, &config).await;
        let mut names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["events.jsonl", "policy.toml"]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_selects_file_states_and_disabling_persistence_clears_live_state() {
    let directory = TempDir::new().unwrap();
    let a = directory.path().join("a.json");
    let b = directory.path().join("b.json");
    std::fs::write(&a, r#"{"states":{"from-a.invalid":{"state":"open","opened_at":0,"failure_streak":3}},"saved_at":0.0}"#).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    std::fs::write(&b, json!({"states":{"from-b.invalid":{"state":"open","opened_at":now+3600.0,"failure_count":7}},"saved_at":0.0}).to_string()).unwrap();
    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut initial = config(directory.path(), None);
    initial.parent_proxy = Some(format!("http://{}", parent.local_addr().unwrap()));
    let mut proxy = Proxy::start(initial.clone()).await.unwrap();
    let mut selected = initial.clone();
    selected.circuit_state_file = Some(a.clone());
    proxy.reload(selected.clone()).await.unwrap();
    selected.circuit_state_file = Some(b.clone());
    proxy.reload(selected.clone()).await.unwrap();
    let (blocked, _) = request(&selected, "from-b.invalid").await;
    assert!(blocked.starts_with("HTTP/1.1 503"));
    assert!(
        blocked
            .to_ascii_lowercase()
            .contains("x-circuit-state: open")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), parent.accept())
            .await
            .is_err(),
        "the retained open circuit must prevent parent contact"
    );

    selected.circuit_state_file = None;
    proxy.reload(selected.clone()).await.unwrap();
    let former_b = std::fs::read(&b).unwrap();
    let serve = tokio::spawn(async move {
        let (mut stream, _) = parent.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let byte = stream.read_u8().await.unwrap();
            head.push(byte);
        }
        assert!(head.starts_with(b"GET http://from-b.invalid/owned HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (forwarded, body) = request(&selected, "from-b.invalid").await;
    assert!(
        forwarded.starts_with("HTTP/1.1 200"),
        "Some→None must discard B's open state"
    );
    assert_eq!(body, b"ok", "observe a complete real upstream response");
    serve.await.unwrap();
    shutdown(proxy, &selected).await;
    assert_eq!(
        std::fs::read(&b).unwrap(),
        former_b,
        "disabled persistence must not write the newly selected state to the former file"
    );

    // Python configure replaces state without explicitly stopping its former
    // worker. Native ownership deliberately flushes the old path on selection;
    // each file must keep its own domains rather than later selected state.
    let final_a = snapshot(&a);
    let final_b = snapshot(&b);
    assert_eq!(domains(&final_a), ["from-a.invalid"]);
    assert_eq!(
        field(&final_a, "from-a.invalid", "state")
            .render_json(false)
            .unwrap(),
        "\"half_open\"",
        "None→file must load and reconcile A before the next path change"
    );
    assert!(
        saved_at(&final_a) > 0.0,
        "file A must receive its final old-state save"
    );
    assert_eq!(domains(&final_b), ["from-b.invalid"]);
    assert_eq!(
        field(&final_b, "from-b.invalid", "failure_count"),
        &CircuitValue::from(7)
    );
    assert!(
        saved_at(&final_b) > 0.0,
        "switching persistence off must finish B's old-state save"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn periodic_snapshot_and_shutdown_final_publication_finish_without_temporary_files() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("state.json");
    let config = config(directory.path(), Some(path.clone()));
    let proxy = Proxy::start(config.clone()).await.unwrap();
    assert!(
        !path.exists(),
        "startup alone does not fabricate a saved snapshot"
    );
    // Exactly one real production interval. This wait observes std-thread work;
    // advancing Tokio's clock would not exercise the persistence worker.
    tokio::time::timeout(Duration::from_secs(15), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the production ten-second worker must publish a snapshot");
    let periodic = snapshot(&path);
    assert!(domains(&periodic).is_empty());
    no_temporary_files(directory.path());
    // Require a new final publication, not merely the file from the periodic run.
    std::fs::remove_file(&path).unwrap();
    shutdown(proxy, &config).await;
    let final_save = snapshot(&path);
    assert!(domains(&final_save).is_empty());
    assert!(saved_at(&final_save) >= saved_at(&periodic));
    no_temporary_files(directory.path());
}
