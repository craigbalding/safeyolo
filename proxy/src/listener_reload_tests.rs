//! Readiness correlation and listener publication with owned files/UDS only.

use super::*;

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, "{}").unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock"),
                      "source_id":"192.0.2.1"}],
        "policy_file":policy,"data_dir":directory.join("data"),"flow_store_enabled":false,
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl"),
        "readiness_file":directory.join("ready.json"),
    }))
    .unwrap()
}

#[tokio::test]
async fn rejected_reload_preserves_published_plumb_limits() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.plumb.max_message_bytes = 4;
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let owner = proxy.runtime.read().unwrap().plumb.clone();
    let request = owner
        .request_chat("alice", &[serde_json::json!("bob")], None, None, None)
        .await;
    let approved = owner
        .approve(request["request_id"].as_str().unwrap(), None)
        .await;
    let conversation_id = approved["conversation_id"].as_str().unwrap();
    assert_eq!(
        owner
            .post_message("bob", conversation_id, "12345", serde_json::json!([]))
            .await["status"],
        413
    );

    let occupied = directory.path().join("occupied.sock");
    std::fs::write(&occupied, b"owned ordinary file").unwrap();
    let mut rejected = config.clone();
    rejected.plumb.max_message_bytes = 0;
    rejected.listeners[0].socket_path = occupied;
    assert!(proxy.reload(rejected).await.is_err());
    assert_eq!(
        owner
            .post_message("bob", conversation_id, "12345", serde_json::json!([]))
            .await["status"],
        413
    );
    proxy.shutdown().await;
}

fn marker(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn same_count_replacement_requires_accepted_correlation() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let before = marker(&config.readiness_file);
    assert!(before.get("reload_id").is_none());
    let old_path = config.listeners[0].socket_path.clone();
    config.listeners[0].socket_path = directory.path().join("replacement.sock");
    config.reload_id = Some("owned-reload-1".into());
    proxy.reload(config.clone()).await.unwrap();
    let after = marker(&config.readiness_file);
    assert_eq!(after["listeners"], before["listeners"]);
    assert_eq!(after["instance_id"], before["instance_id"]);
    assert_eq!(after["pid"], before["pid"]);
    assert_eq!(after["reload_id"], "owned-reload-1");
    assert!(!old_path.exists());
    assert!(config.listeners[0].socket_path.exists());
    proxy.shutdown().await;
}

#[tokio::test]
async fn failed_addition_preserves_marker_identity_and_cleans_staged_socket() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.reload_id = Some("accepted-before".into());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let before = std::fs::read(&config.readiness_file).unwrap();
    let current = proxy.runtime.read().unwrap().clone();
    let old_path = config.listeners[0].socket_path.clone();
    let inode = std::fs::metadata(&old_path).unwrap().ino();
    config.listeners[0].agent_id = "replacement-identity".into();
    let staged = directory.path().join("staged.sock");
    let occupied = directory.path().join("occupied.sock");
    std::fs::write(&occupied, b"owned ordinary file").unwrap();
    for path in [&staged, &occupied] {
        config.listeners.push(AgentListener {
            agent_id: "bob".into(),
            socket_path: path.clone(),
            source_id: None,
        });
    }
    config.reload_id = Some("must-not-acknowledge".into());
    assert!(proxy.reload(config.clone()).await.is_err());
    assert_eq!(std::fs::read(&config.readiness_file).unwrap(), before);
    assert_eq!(std::fs::metadata(&old_path).unwrap().ino(), inode);
    assert_eq!(proxy.listeners[&old_path].agent_id, "alice");
    assert!(Arc::ptr_eq(&current, &proxy.runtime.read().unwrap()));
    assert!(!staged.exists());
    assert_eq!(std::fs::read(occupied).unwrap(), b"owned ordinary file");
    proxy.shutdown().await;
}

#[tokio::test]
async fn same_path_transfer_keeps_inode_and_stops_old_accept_owner() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let path = config.listeners[0].socket_path.clone();
    let old_socket = proxy.listeners[&path].listener.clone();
    let old_task = proxy.listeners[&path].task.abort_handle();
    let old_stop = proxy.listeners[&path].stop.subscribe();
    let inode = std::fs::metadata(&path).unwrap().ino();
    config.listeners[0].agent_id = "bob".into();
    config.listeners[0].source_id = Some("192.0.2.2".into());
    config.reload_id = Some("new-identity".into());
    proxy.reload(config.clone()).await.unwrap();
    assert!(*old_stop.borrow());
    assert!(Arc::ptr_eq(&old_socket, &proxy.listeners[&path].listener));
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(proxy.listeners[&path].agent_id, "bob");
    assert_eq!(
        proxy.listeners[&path].source_id.as_deref(),
        Some("192.0.2.2")
    );
    assert_eq!(marker(&config.readiness_file)["reload_id"], "new-identity");
    // The old task has the captured old identity and stops under its own watch;
    // the new task's sender cannot extend that old task's lifetime.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !old_task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(old_socket);
    proxy.shutdown().await;
    assert!(!path.exists());
}

#[tokio::test]
async fn late_circuit_failure_preserves_listener_and_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let before = std::fs::read(&config.readiness_file).unwrap();
    let old_path = config.listeners[0].socket_path.clone();
    let inode = std::fs::metadata(&old_path).unwrap().ino();
    let current = proxy.runtime.read().unwrap().clone();
    // A real existing synchronous circuit callback poisons the owner while
    // holding its lock. Reload reaches this owner only after staging the binds.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = current.circuits.restore(
            &json!({"states":{"owned.invalid":{
                "state":"open","opened_at":0,"failure_streak":1,
            }}}),
            1.,
            &mut || panic!("owned jitter failure"),
        );
    }));
    assert!(result.is_err());
    config.circuit_state_file = Some(directory.path().join("new-state.json"));
    config.listeners[0].agent_id = "bob".into();
    let staged = directory.path().join("staged.sock");
    config.listeners.push(AgentListener {
        agent_id: "bob".into(),
        socket_path: staged.clone(),
        source_id: None,
    });
    config.reload_id = Some("rejected-late".into());
    assert!(proxy.reload(config.clone()).await.is_err());
    assert_eq!(std::fs::read(&config.readiness_file).unwrap(), before);
    assert_eq!(std::fs::metadata(&old_path).unwrap().ino(), inode);
    assert_eq!(proxy.listeners[&old_path].agent_id, "alice");
    assert!(Arc::ptr_eq(&current, &proxy.runtime.read().unwrap()));
    assert!(!staged.exists());
    proxy.shutdown().await;
}

#[tokio::test]
async fn marker_failure_after_commit_is_unconfirmed_and_can_be_reconciled() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let old_ready = config.readiness_file.clone();
    config.listeners[0].agent_id = "bob".into();
    config.readiness_file = directory.path().join("missing-parent/ready.json");
    config.reload_id = Some("unconfirmed".into());
    assert!(proxy.reload(config.clone()).await.is_err());
    assert!(!old_ready.exists());
    assert!(!config.readiness_file.exists());
    assert_eq!(
        proxy.listeners[&config.listeners[0].socket_path].agent_id,
        "bob"
    );
    assert_eq!(
        proxy.runtime.read().unwrap().config.reload_id.as_deref(),
        Some("unconfirmed")
    );
    config.readiness_file = old_ready;
    config.reload_id = Some("reconciled".into());
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(marker(&config.readiness_file)["reload_id"], "reconciled");
    proxy.shutdown().await;
}

#[tokio::test]
async fn missing_socket_path_is_rebound_before_identity_transfer() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let path = config.listeners[0].socket_path.clone();
    let old_socket = proxy.listeners[&path].listener.clone();
    let old_stop = proxy.listeners[&path].stop.subscribe();
    std::fs::remove_file(&path).unwrap();
    config.listeners[0].agent_id = "bob".into();
    config.reload_id = Some("restored-path".into());
    proxy.reload(config.clone()).await.unwrap();
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket()
    );
    assert!(!Arc::ptr_eq(&old_socket, &proxy.listeners[&path].listener));
    assert!(*old_stop.borrow());
    assert_eq!(proxy.listeners[&path].agent_id, "bob");
    assert_eq!(marker(&config.readiness_file)["reload_id"], "restored-path");
    drop(old_socket);
    proxy.shutdown().await;
    assert!(!path.exists());
}

#[tokio::test]
async fn occupied_replacement_path_rejects_transfer_without_new_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let before = std::fs::read(&config.readiness_file).unwrap();
    let current = proxy.runtime.read().unwrap().clone();
    let path = config.listeners[0].socket_path.clone();
    let old_socket = proxy.listeners[&path].listener.clone();
    let old_stop = proxy.listeners[&path].stop.subscribe();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"owned replacement file").unwrap();
    config.listeners[0].agent_id = "bob".into();
    config.reload_id = Some("must-not-transfer".into());
    assert!(proxy.reload(config.clone()).await.is_err());
    assert_eq!(std::fs::read(&config.readiness_file).unwrap(), before);
    assert!(Arc::ptr_eq(&current, &proxy.runtime.read().unwrap()));
    assert!(Arc::ptr_eq(&old_socket, &proxy.listeners[&path].listener));
    assert!(!*old_stop.borrow());
    assert_eq!(proxy.listeners[&path].agent_id, "alice");
    assert_eq!(std::fs::read(&path).unwrap(), b"owned replacement file");
    drop(old_socket);
    proxy.shutdown().await;
    // Neither the rejected candidate nor the old inode owner removes the
    // replacement file during cleanup.
    assert_eq!(std::fs::read(&path).unwrap(), b"owned replacement file");
}

#[tokio::test]
async fn closing_agent_socket_cancels_connection_coordination_waits() {
    let (server, client) = UnixStream::pair().unwrap();
    let (_stop, receiver) = watch::channel(false);
    let tasks = connection_tasks::ConnectionTasks::new(receiver);
    let monitor = monitor_agent_disconnect(&server, &tasks).unwrap();
    let mut cancellation = tasks.cancellation_receiver.clone();

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !*cancellation.borrow(),
        "an open peer must not cancel the wait"
    );
    drop(client);
    tokio::time::timeout(Duration::from_secs(1), cancellation.changed())
        .await
        .expect("peer close should wake the connection monitor")
        .unwrap();
    assert!(*cancellation.borrow());

    monitor.abort();
    let _ = monitor.await;
    drop(server);
}
