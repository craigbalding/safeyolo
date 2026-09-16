//! Actual process-owner controls, independent of HTTP logger activation.

#![cfg(target_os = "linux")]

use super::*;
use crate::{
    audit::{Attribution, AttributionStatus, Event, Initiator, Kind, Severity, Submission},
    request_logger::{Exchange, PrettyUrl, Request},
};
use std::{
    collections::BTreeSet,
    ffi::CString,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
};

/// The child owns its environment and all audit destinations. In particular,
/// ambient rotation/queue settings cannot make this lifecycle proof flaky.
fn isolated(name: &str, test: impl FnOnce(&Path)) {
    const CHILD: &str = "SAFEYOLO_AUDIT_RUNTIME_TEST_DIRECTORY";
    if let Some(directory) = std::env::var_os(CHILD) {
        test(Path::new(&directory));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("audit_runtime_tests::{name}"),
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path().join("data"))
        .env(
            "SAFEYOLO_LOG_PATH",
            directory.path().join("unused-fallback.jsonl"),
        )
        .env_remove("SAFEYOLO_AUDIT_QUEUE_MAX")
        .env_remove("SAFEYOLO_LOG_MAX_MB")
        .env_remove("SAFEYOLO_LOG_BACKUPS")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "owned child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!directory.path().join("ready").exists());
    assert!(!directory.path().join("alice.sock").exists());
    assert!(!directory.path().join("unused-fallback.jsonl").exists());
}

fn config(directory: &Path, sink: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, "{}").unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,"flow_store_enabled":false,"audit_log_path":sink,
        "event_log":directory.join("diagnostics.jsonl"),"readiness_file":directory.join("ready"),
    }))
    .unwrap()
}

fn event(index: usize) -> Event {
    let mut event = Event::new(
        "ops.owned_lifecycle",
        Kind::Ops,
        Severity::Low,
        "Owned lifecycle control",
    );
    event.details = json!({"index":index}).into();
    event
}

fn assert_policy_reload(row: &Value) {
    let mut event = row.clone();
    assert!(
        event
            .as_object_mut()
            .unwrap()
            .remove("ts")
            .unwrap()
            .is_string()
    );
    assert_eq!(
        event,
        json!({
            "schema_version":1,"event":"ops.policy_reload","kind":"ops",
            "severity":"medium","summary":"Baseline policy reloaded: 0 permissions",
            "addon":"policy-loader","details":{"policy_type":"baseline","permissions_count":0}
        })
    );
}

fn logger_request(runtime: &Runtime, host: &str, size: impl FnOnce() -> u64) -> bool {
    let mut exchange = Exchange::new(
        Attribution {
            evidence_owner: Some("alice".into()),
            trusted_transport_identity: Some("alice".into()),
            initiator: Some(Initiator::Unknown),
            status: Some(AttributionStatus::Resolved),
            ..Default::default()
        },
        Some("alice".into()),
    );
    runtime
        .request_logger
        .request(
            runtime.policy.as_ref(),
            &mut exchange,
            &Request {
                method: "GET",
                parsed: Ok(PrettyUrl {
                    host,
                    path: "/owned",
                }),
                request_id: Some("req-00000000000000000000000000000000"),
                client: Some("192.0.2.10"),
            },
            || Ok(size()),
            &runtime.audit,
        )
        .unwrap();
    exchange.quieted()
}

fn writer_threads() -> BTreeSet<String> {
    // Owned child process only. Linux task names truncate the writer's name;
    // no debugger attach or cross-process inspection is involved.
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let name = std::fs::read_to_string(entry.path().join("comm"));
            match name {
                Ok(name) if name.starts_with("safeyolo-audit") => {
                    Some(entry.file_name().to_string_lossy().into_owned())
                }
                Ok(_) => None,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("owned task observation failed: {error}"),
            }
        })
        .collect()
}

#[test]
fn audit_writer_stays_inert_until_emit_and_proxy_shutdown_joins_it() {
    isolated(
        "audit_writer_stays_inert_until_emit_and_proxy_shutdown_joins_it",
        |directory| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let sink = directory.join("lazy-parent/audit.jsonl");
                    let inert = Runtime::new(
                        config(directory, &sink),
                        "owned-lazy",
                        Arc::new(tokio::sync::Mutex::new(())),
                        None,
                        None,
                    )
                    .unwrap();
                    let writer = inert.audit.clone();
                    assert!(writer_threads().is_empty());
                    assert!(!sink.parent().unwrap().exists());
                    assert_eq!(writer.pending_count().unwrap(), 0);
                    assert!(writer.wait_for_drain(Duration::ZERO).unwrap());
                    drop(writer);
                    drop(inert);
                    let proxy = Proxy::start(config(directory, &sink)).await.unwrap();
                    let runtime = proxy.runtime.read().unwrap().clone();
                    let writer = runtime.audit.clone();
                    assert!(!logger_request(&runtime, "owned.invalid", || 9));
                    for index in 0..32 {
                        assert_eq!(writer.emit(event(index)).unwrap(), Submission::Queued);
                    }
                    proxy.shutdown().await;
                    assert!(writer_threads().is_empty());
                    assert_eq!(writer.pending_count().unwrap(), 0);
                    assert_eq!(writer.dropped_count().unwrap(), 0.into());
                    assert!(writer.shutdown(Duration::ZERO).unwrap());
                    assert_eq!(writer.emit(event(99)).unwrap(), Submission::Stopped);
                    let rows: Vec<Value> = std::fs::read_to_string(&sink)
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect();
                    assert_eq!(rows.len(), 35);
                    assert_policy_reload(&rows[0]);
                    assert_eq!(rows[1]["event"], "ops.startup");
                    assert_eq!(rows[1]["addon"], "memory-monitor");
                    assert_eq!(rows[2]["event"], "traffic.request");
                    assert_eq!(rows[2]["details"]["size"], 9);
                    assert_eq!(rows[2]["details"]["attribution"]["evidence_owner"], "alice");
                    for (index, row) in rows[3..].iter().enumerate() {
                        assert_eq!(row["event"], "ops.owned_lifecycle");
                        assert_eq!(row["details"]["index"], index);
                    }
                    assert_eq!(
                        runtime.request_logger.stats().unwrap().requests_total,
                        1.into()
                    );
                });
        },
    );
}

#[test]
fn reload_preserves_queued_audit_startup_sink_and_logger_state() {
    isolated(
        "reload_preserves_queued_audit_startup_sink_and_logger_state",
        |directory| {
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            executor.block_on(async {
                let sink = directory.join("owned-fifo");
                let name = CString::new(sink.as_os_str().as_bytes()).unwrap();
                // A real owned FIFO holds the first append until this test
                // supplies its reader, without an internal writer test hook.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                let mut configuration = config(directory, &sink);
                let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
                let initial = proxy.runtime.read().unwrap().clone();
                assert!(!logger_request(&initial, "owned.invalid", || 7));
                assert_eq!(initial.audit.emit(event(1)).unwrap(), Submission::Queued);
                assert_eq!(initial.audit.pending_count().unwrap(), 4);
                assert!(!initial.audit.wait_for_drain(Duration::ZERO).unwrap());

                configuration.audit_log_path = Some(directory.join("not-selected/audit.jsonl"));
                let quiet_policy = json!({"addons":{"request_logger":{"quiet_hosts":{"hosts":["quiet.invalid"]}}}});
                std::fs::write(configuration.policy_file.as_ref().unwrap(), quiet_policy.to_string()).unwrap();
                proxy.reload(configuration.clone()).await.unwrap();
                let current = proxy.runtime.read().unwrap().clone();
                assert!(Arc::ptr_eq(&initial.audit, &current.audit));
                assert!(Arc::ptr_eq(&initial.request_logger, &current.request_logger));
                assert_eq!(current.request_logger.stats().unwrap().requests_total, 1.into());
                assert!(logger_request(&current, "quiet.invalid", || panic!("quiet request decoded a body")));
                assert_eq!(current.audit.pending_count().unwrap(), 5);

                let mut invalid = configuration.clone();
                invalid.policy_file = Some(directory.join("failed-candidate-policy.json"));
                let failed_policy = json!({"addons":{"request_logger":{"quiet_hosts":{"hosts":["owned.invalid"]}}}});
                std::fs::write(invalid.policy_file.as_ref().unwrap(), failed_policy.to_string()).unwrap();
                // Fail after both owners have been cloned into the candidate;
                // dropping that candidate must not close the shared queue.
                invalid.event_log = directory.to_owned();
                assert!(proxy.reload(invalid).await.is_err());
                let retained = proxy.runtime.read().unwrap().clone();
                assert!(Arc::ptr_eq(&current, &retained));
                assert_eq!(retained.audit.pending_count().unwrap(), 5);
                assert!(!logger_request(&retained, "owned.invalid", || 11));
                assert_eq!(initial.audit.emit(event(2)).unwrap(), Submission::Queued);
                assert_eq!(retained.audit.pending_count().unwrap(), 7);
                let later_path = configuration.audit_log_path.as_ref().unwrap();
                assert!(!later_path.parent().unwrap().exists());

                let mut shutdown = tokio::spawn(proxy.shutdown());
                assert!(tokio::time::timeout(Duration::from_millis(30), &mut shutdown).await.is_err(),
                    "Proxy shutdown returned while admitted audit events were blocked");
                let mut reader = OpenOptions::new().read(true).write(true)
                    .custom_flags(libc::O_NONBLOCK).open(&sink).unwrap();
                tokio::time::timeout(Duration::from_secs(2), shutdown).await.unwrap().unwrap();
                assert_eq!(retained.audit.pending_count().unwrap(), 0);
                assert_eq!(retained.audit.dropped_count().unwrap(), 0.into());
                assert!(writer_threads().is_empty());
                assert_eq!(initial.audit.emit(event(99)).unwrap(), Submission::Stopped);

                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("owned FIFO read failed: {error}"),
                    }
                }
                let rows: Vec<Value> = std::str::from_utf8(&bytes).unwrap().lines()
                    .map(|line| serde_json::from_str(line).unwrap()).collect();
                assert_eq!(rows.len(), 7);
                assert_policy_reload(&rows[0]);
                assert_eq!(rows[1]["event"], "ops.startup");
                assert_eq!(rows[1]["addon"], "memory-monitor");
                assert_eq!(rows[2]["event"], "traffic.request");
                assert_eq!(rows[2]["details"]["size"], 7);
                assert_eq!(rows[3]["event"], "ops.owned_lifecycle");
                assert_eq!(rows[3]["details"]["index"], 1);
                assert_policy_reload(&rows[4]);
                assert_eq!(rows[5]["event"], "traffic.request");
                assert_eq!(rows[5]["details"]["size"], 11);
                assert_eq!(rows[6]["event"], "ops.owned_lifecycle");
                assert_eq!(rows[6]["details"]["index"], 2);
                let stats = retained.request_logger.stats().unwrap();
                assert_eq!(stats.requests_total, 3.into());
                assert_eq!(stats.requests_quieted, 1.into());
                assert_eq!(stats.responses_total, 0.into());
                assert_eq!(stats.blocks_total, 0.into());
                assert!(!later_path.exists());
        });
        },
    );
}
