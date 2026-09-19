//! Owned startup/reload/shutdown controls for the process's single flow store.

use super::*;
use crate::{flow_writer::QueuedRecord, http_content::decode_prefix_with_size};

fn config(directory: &Path, enabled: bool) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        r#"{"addons":{"flow_store":{"max_request_body_bytes":3}}}"#,
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[], "policy_file":policy, "data_dir":directory.join("data"), "flow_store_enabled":enabled,
        "flow_store_db_path":directory.join("flows.sqlite3"),
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl"),
        "readiness_file":directory.join("ready.json"),
    }))
    .unwrap()
}

fn submit(recorder: &flow_recorder::FlowRecorder, id: &str) {
    recorder.record(|store| {
        Ok(Some(QueuedRecord {
            metadata_encoding_error: false,
            metadata: json!({
                "request_id":id, "ts_start":1, "engagement_id":"alice", "agent_id":"alice",
                "evidence_owner":"alice", "host":"owned.invalid", "flow_state":"completed",
                "request_content_type":"text/plain", "response_content_type":"text/plain",
            })
            .as_object()
            .unwrap()
            .clone(),
            request_body: decode_prefix_with_size(
                b"request",
                b"",
                store.capture_limit(flow_store::Side::Request).unwrap(),
            )?,
            response_body: decode_prefix_with_size(b"response", b"", usize::MAX)?,
        }))
    });
}

#[tokio::test]
async fn reload_keeps_startup_store_settings_and_shutdown_drains() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), true);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let initial = proxy.runtime.read().unwrap().flow_recorder.clone();
    let store = initial.store().unwrap().clone();
    submit(&initial, "first");

    config.flow_store_db_path = directory.path().join("later-option.sqlite3");
    let later_policy_path = directory.path().join("later-policy.sqlite3");
    std::fs::write(
        config.policy_file.as_ref().unwrap(),
        json!({"addons":{"flow_store":{
            "db_path":later_policy_path, "max_request_body_bytes":99,
        }}})
        .to_string(),
    )
    .unwrap();
    config.flow_store_enabled = false;
    proxy.reload(config.clone()).await.unwrap();
    let after = proxy.runtime.read().unwrap().flow_recorder.clone();
    assert!(Arc::ptr_eq(&initial, &after));
    assert!(Arc::ptr_eq(&store, after.store().unwrap()));
    assert_eq!(store.capture_limit(flow_store::Side::Request), Some(3));
    after.record(|_| panic!("disabled hook must not build"));
    assert!(!config.flow_store_db_path.exists());
    assert!(!later_policy_path.exists());

    config.flow_store_enabled = true;
    proxy.reload(config.clone()).await.unwrap();
    submit(&after, "second");
    let mut failed_config = config.clone();
    failed_config.flow_store_enabled = false;
    failed_config.policy_file = Some(directory.path().join("missing-policy.json"));
    assert!(proxy.reload(failed_config).await.is_err());
    submit(&initial, "after-failed-reload");
    proxy.shutdown().await;
    assert!(!config.readiness_file.exists());
    assert_eq!(
        initial.stats(),
        json!({"recorded":3,"errors":0,"skipped":1,"queue_dropped":0,"write_errors":0})
    );
    drop(store);
    drop(after);
    drop(initial);
    let reopened =
        flow_store::FlowStore::open(&directory.path().join("flows.sqlite3"), Default::default())
            .unwrap();
    for id in 1..=3 {
        let body = reopened
            .body(id, flow_store::Side::Request)
            .unwrap()
            .unwrap();
        assert_eq!(body.body.as_slice(), b"req");
        assert_eq!(body.metadata["request_body_size"], 7);
    }
    assert!(reopened.get_flow(4).unwrap().is_none());
}

#[tokio::test]
async fn enabling_after_disabled_startup_does_not_create_a_store() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), false);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    config.flow_store_enabled = true;
    proxy.reload(config.clone()).await.unwrap();
    let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
    recorder.record(|_| panic!("startup skipped initialization"));
    assert!(recorder.store().is_none());
    assert!(!config.flow_store_db_path.exists());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":0,"errors":0,"skipped":1})
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn operator_statistics_are_read_only_and_authenticate_before_sampling() {
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, body::Bytes};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let sampled = AtomicUsize::new(0);
    let stats = || {
        sampled.fetch_add(1, Ordering::Relaxed);
        tokio::task::spawn_blocking(|| {
            json!({"proxy":"safeyolo","flow-recorder":{"recorded":2,"errors":1,"skipped":3,"queue_dropped":4,"write_errors":5}}).into()
        })
    };
    let registry = tasks::Registry::default();
    for (method, auth, expected) in [
        ("GET", false, 401),
        ("HEAD", true, 501),
        ("POST", true, 404),
        ("GET", true, 200),
    ] {
        let mut request = Request::builder().method(method).uri("/stats");
        if auth {
            request = request.header("Authorization", "Bearer owned-stats-token");
        }
        let outcome = admin_api::respond_with_stats(
            request.body(Empty::<Bytes>::new()).unwrap(),
            "owned-stats-token",
            &registry,
            None,
            None,
            Some(&stats),
        )
        .await
        .unwrap();
        assert_eq!(outcome.status().as_u16(), expected);
        if expected == 200 {
            let bytes = outcome
                .into_response()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["flow-recorder"]["recorded"], 2);
            assert_eq!(body["flow-recorder"]["write_errors"], 5);
        } else {
            assert_eq!(sampled.load(Ordering::Relaxed), 0);
        }
    }
    assert_eq!(sampled.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn failed_initialization_keeps_the_proxy_and_partial_read_surface() {
    use flow_store::{BodyInput, ErrorKind, FlowRecord, FlowStore, Side};
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), true);
    let store = FlowStore::open(&config.flow_store_db_path, Default::default()).unwrap();
    let metadata = json!({"request_id":"existing", "ts_start":1, "engagement_id":"alice", "agent_id":"alice", "host":"owned.invalid", "flow_state":"completed"});
    store
        .record(
            FlowRecord {
                metadata: metadata.as_object().unwrap(),
                request_body: None,
                response_body: Some(BodyInput::complete(b"retained")),
            },
            1,
        )
        .unwrap();
    drop(store);
    let db = rusqlite::Connection::open(&config.flow_store_db_path).unwrap();
    db.execute_batch("DROP TABLE flow_fts; DROP TABLE flow_request_fts; DROP TABLE flow_tags; CREATE TABLE marker(value); CREATE INDEX flow_request_fts ON marker(value);").unwrap();
    drop(db);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    assert!(config.readiness_file.exists());
    let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
    let store = recorder.store().unwrap();
    assert_eq!(
        store.get_flow(1).unwrap_err().kind(),
        ErrorKind::Operational
    );
    assert_eq!(
        store
            .body(1, Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"retained"
    );
    assert_eq!(
        store
            .search_flows(&json!({"evidence_owner":"alice"}).into())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    submit(&recorder, "no-writer");
    assert!(store.get_flow(2).unwrap().is_none());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":1,"errors":0,"skipped":0})
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn missing_parent_and_invalid_policy_path_keep_assigned_unopened_store() {
    use flow_store::ErrorKind;
    for invalid_type in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path(), true);
        if invalid_type {
            std::fs::write(
                config.policy_file.as_ref().unwrap(),
                r#"{"addons":{"flow_store":{"db_path":true}}}"#,
            )
            .unwrap();
        } else {
            config.flow_store_db_path = directory.path().join("missing/flows.sqlite3");
        }
        let proxy = Proxy::start(config.clone()).await.unwrap();
        let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
        let store = recorder.store().expect("source assigns before opening");
        assert_eq!(store.get_flow(1).unwrap_err().kind(), ErrorKind::Attribute);
        submit(&recorder, "dropped-without-writer");
        assert_eq!(
            recorder.stats(),
            json!({"recorded":1,"errors":0,"skipped":0})
        );
        assert!(!config.flow_store_db_path.exists());
        assert!(!directory.path().join("missing").exists());
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn live_operator_listener_reports_the_same_recorder_owner() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), true);
    let token_file = directory.path().join("owned-admin-token");
    std::fs::write(&token_file, b"owned-flow-stats-token").unwrap();
    config.admin_port = Some(0);
    config.admin_api_token_file = Some(token_file);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let address = proxy.admin.as_ref().unwrap().address();
    let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
    recorder.record(|_| Ok(None));
    let response = tokio::time::timeout(Duration::from_secs(3),async {
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owned-flow-stats-token\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        bytes
    }).await.unwrap();
    let text = std::str::from_utf8(&response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"));
    let body: Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["proxy"], "safeyolo");
    assert_eq!(body["flow-recorder"], recorder.stats());
    assert_eq!(body["flow-recorder"]["skipped"], 1);
    proxy.shutdown().await;
    assert!(!config.readiness_file.exists());
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[test]
fn live_agent_flow_api_reads_the_runtime_store_with_ingress_ownership() {
    const CHILD_DIRECTORY: &str = "SAFEYOLO_FLOW_API_TEST_DIRECTORY";
    let Ok(directory) = std::env::var(CHILD_DIRECTORY) else {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("agent_token"),
            b"owned-flow-api-token",
        )
        .unwrap();
        // A child process supplies the actual HTTP token lookup's data directory
        // without changing process-global environment beneath parallel tests.
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "flow_runtime_tests::live_agent_flow_api_reads_the_runtime_store_with_ingress_ownership", "--nocapture"])
            .env(CHILD_DIRECTORY, directory.path())
            .env("SAFEYOLO_DATA_DIR", directory.path())
            .output().unwrap();
        assert!(
            result.status.success(),
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!directory.path().join("ready.json").exists());
        assert!(!directory.path().join("alice.sock").exists());
        return;
    };
    let directory = Path::new(&directory);
    let mut config = config(directory, true);
    std::fs::write(config.policy_file.as_ref().unwrap(), json!({
        "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
        "addons":{"test_context":{"target_hosts":["127.0.0.2"]},"flow_store":{"max_request_body_bytes":3}}
    }).to_string()).unwrap();
    config.listeners = ["alice", "bob"]
        .into_iter()
        .map(|agent| AgentListener {
            agent_id: agent.into(),
            socket_path: directory.join(format!("{agent}.sock")),
            source_id: None,
        })
        .collect();
    let store =
        flow_store::FlowStore::open(&config.flow_store_db_path, Default::default()).unwrap();
    for owner in ["alice", "bob"] {
        let metadata = json!({"request_id":owner, "ts_start":1, "engagement_id":owner,
            "agent_id":owner, "evidence_owner":owner, "host":"owned.invalid", "flow_state":"completed",
            "request_content_type":"text/plain", "response_content_type":"text/plain"});
        store
            .record(
                flow_store::FlowRecord {
                    metadata: metadata.as_object().unwrap(),
                    request_body: Some(flow_store::BodyInput::complete(b"owned request")),
                    response_body: Some(flow_store::BodyInput::complete(b"owned response")),
                },
                1,
            )
            .unwrap();
    }
    drop(store);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let proxy = Proxy::start(config.clone()).await.unwrap();
            assert_eq!(
                agent_flow_request(directory, "alice", "GET", "/api/flows/1", "", false)
                    .await
                    .0,
                401
            );
            let (status, search) = agent_flow_request(
                directory,
                "alice",
                "GET",
                "/api/flows/search?evidence_owner=bob",
                "",
                true,
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(search["count"], 1);
            assert_eq!(search["flows"][0]["evidence_owner"], "alice");
            let (status, detail) =
                agent_flow_request(directory, "alice", "GET", "/api/flows/1", "", true).await;
            assert_eq!(status, 200);
            assert_eq!(detail["request_id"], "alice");
            let (status, body) = agent_flow_request(
                directory,
                "alice",
                "GET",
                "/api/flows/1/response-body",
                "",
                true,
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(body["body_text"], "owned response");
            assert_eq!(body["body_length"], 14);
            for path in [
                "/api/flows/1",
                "/api/flows/1/response-body",
                "/api/flows/999",
            ] {
                assert_eq!(
                    agent_flow_request(directory, "bob", "GET", path, "", true).await,
                    (404, json!({"error":"Flow not found"}))
                );
            }
            assert_eq!(
                agent_flow_request(
                    directory,
                    "bob",
                    "GET",
                    "/api/flows/2/request-body",
                    "",
                    true
                )
                .await
                .1["body_text"],
                "owned request"
            );

            let tag = r#"{"tag":"review","value":true}"#;
            assert_eq!(
                agent_flow_request(directory, "bob", "POST", "/api/flows/1/tag", tag, true)
                    .await
                    .0,
                404
            );
            let (status, added) =
                agent_flow_request(directory, "alice", "POST", "/api/flows/1/tag", tag, true).await;
            assert_eq!(status, 200);
            assert_eq!(added["value"], true);
            let (_, detail) =
                agent_flow_request(directory, "alice", "GET", "/api/flows/1", "", true).await;
            assert!(
                detail["tags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|tag| tag["tag"] == "review" && tag["value"] == "1")
            );
            assert_eq!(
                agent_flow_request(
                    directory,
                    "alice",
                    "POST",
                    "/api/flows/diff",
                    r#"{"flow_id_a":1,"flow_id_b":2}"#,
                    true
                )
                .await,
                (404, json!({"error":"One or both flows not found"}))
            );
            let (status, diff) = agent_flow_request(
                directory,
                "alice",
                "POST",
                "/api/flows/diff",
                r#"{"flow_id_a":1,"flow_id_b":1}"#,
                true,
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(diff["identical"], true);
            assert_eq!(diff["size_a"], 14);
            assert_eq!(
                agent_flow_request(
                    directory,
                    "alice",
                    "DELETE",
                    "/api/flows/1/tag/review",
                    "",
                    true
                )
                .await,
                (200, json!({"deleted":true,"flow_id":1,"tag":"review"}))
            );
            assert_eq!(
                agent_flow_request(
                    directory,
                    "alice",
                    "POST",
                    "/api/flows/1/tag",
                    r#"{"tag":"retained","value":"after reopen"}"#,
                    true
                )
                .await
                .0,
                200
            );
            record_wire_flow(directory).await;
            let (status, recorded) = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let found =
                        agent_flow_request(directory, "alice", "GET", "/api/flows/3", "", true)
                            .await;
                    if found.0 != 404 {
                        break found;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(status, 200);
            assert_eq!(recorded["run"], "wire-run");
            assert_eq!(recorded["evidence_owner"], "alice");
            assert_eq!(recorded["request_body_size"], 7);
            let (status, search) = agent_flow_request(
                directory,
                "alice",
                "GET",
                "/api/flows/search?run=wire-run",
                "",
                true,
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(search["count"], 1);
            assert_eq!(search["flows"][0]["id"], 3);
            assert_eq!(
                agent_flow_request(
                    directory,
                    "alice",
                    "GET",
                    "/api/flows/3/request-body",
                    "",
                    true
                )
                .await
                .1["body_text"],
                "wir"
            );
            assert_eq!(
                agent_flow_request(
                    directory,
                    "alice",
                    "GET",
                    "/api/flows/3/response-body",
                    "",
                    true
                )
                .await
                .1["body_text"],
                "wire result"
            );
            assert_eq!(
                agent_flow_request(
                    directory,
                    "bob",
                    "GET",
                    "/api/flows/3/response-body",
                    "",
                    true
                )
                .await
                .0,
                404
            );
            proxy.shutdown().await;
            assert!(
                tokio::net::UnixStream::connect(directory.join("bob.sock"))
                    .await
                    .is_err()
            );
        });
    let reopened =
        flow_store::FlowStore::open(&config.flow_store_db_path, Default::default()).unwrap();
    assert_eq!(
        reopened.get_flow(2).unwrap().unwrap()["evidence_owner"],
        "bob"
    );
    assert_eq!(reopened.get_flow(3).unwrap().unwrap()["run"], "wire-run");
    assert!(reopened.get_flow(4).unwrap().is_none());
    let tags = reopened.get_flow_tags(1).unwrap();
    assert!(
        tags.as_array()
            .unwrap()
            .iter()
            .any(|tag| tag["tag"] == "retained" && tag["value"] == "after reopen")
    );
    assert!(
        !tags
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag["tag"] == "review")
    );
}

#[tokio::test]
async fn live_storage_write_failure_keeps_transport_success_separate_from_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), true);
    std::fs::write(
        config.policy_file.as_ref().unwrap(),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"test_context":{"target_hosts":["127.0.0.2"]}}
        })
        .to_string(),
    )
    .unwrap();
    config.listeners = vec![AgentListener {
        agent_id: "alice".into(),
        socket_path: directory.path().join("alice.sock"),
        source_id: None,
    }];

    let proxy = Proxy::start(config.clone()).await.unwrap();
    let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
    let store = recorder.store().unwrap().clone();

    // Positive control: a real native request reaches the origin and is
    // durably visible before the failure trigger is installed.
    record_wire_flow_case(
        directory.path(),
        "/durable-success",
        b"635-persisted-request",
        b"635-persisted-response",
    )
    .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if store.get_flow(1).unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    // Negative control: only the exact synthetic path fails at the SQLite
    // row boundary. The trigger preserves earlier rows and makes the failure
    // independent of filesystem fullness or process timing.
    let db = rusqlite::Connection::open(&config.flow_store_db_path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_635_storage BEFORE INSERT ON flows WHEN NEW.path = '/storage-failure' BEGIN SELECT RAISE(ABORT, 'synthetic 635 storage failure'); END;",
    )
    .unwrap();
    drop(db);
    record_wire_flow_case(
        directory.path(),
        "/storage-failure",
        b"635-discarded-request",
        b"635-discarded-response",
    )
    .await;

    // The origin completed both requests with HTTP 200. The recorder's
    // asynchronous stats expose that the second row was only queued, while
    // the worker reports the durable write failure separately.
    proxy.shutdown().await;
    assert_eq!(
        recorder.stats(),
        json!({"recorded":2,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":1})
    );

    // Remove only the synthetic trigger, then use the real reopen path. The
    // successful row remains; the failed row and its tags are absent.
    let db = rusqlite::Connection::open(&config.flow_store_db_path).unwrap();
    db.execute_batch("DROP TRIGGER fail_635_storage;").unwrap();
    drop(db);
    drop(store);
    drop(recorder);
    let reopened =
        flow_store::FlowStore::open(&config.flow_store_db_path, Default::default()).unwrap();
    assert_eq!(
        reopened.get_flow(1).unwrap().unwrap()["path"],
        "/durable-success"
    );
    assert_eq!(
        reopened
            .body(1, flow_store::Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"635-persisted-response"
    );
    assert!(reopened.get_flow(2).unwrap().is_none());
    assert_eq!(reopened.get_flow_tags(2).unwrap(), json!([]));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn live_evidence_sink_failure_keeps_transport_and_capture_distinct_from_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let mut healthy = config(directory.path(), true);
    std::fs::write(
        healthy.policy_file.as_ref().unwrap(),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"test_context":{"target_hosts":["127.0.0.2"]}}
        })
        .to_string(),
    )
    .unwrap();
    healthy.listeners = vec![AgentListener {
        agent_id: "alice".into(),
        socket_path: directory.path().join("alice.sock"),
        source_id: None,
    }];

    // Replace the event-evidence sink only after the request has reached the
    // origin. This isolates the response-phase sink failure from admission,
    // while still using the real native writer and a real native request.
    let mut proxy = Proxy::start(healthy.clone()).await.unwrap();
    let recorder = proxy.runtime.read().unwrap().flow_recorder.clone();
    let store = recorder.store().unwrap().clone();
    let event_owner = proxy.runtime.read().unwrap().clone();
    let failed_response = record_wire_flow_case_observe_with_hook(
        directory.path(),
        "/audit-sink-failure",
        b"635-audit-failure-request",
        b"635-audit-failure-response",
        move || {
            *event_owner.events.lock().unwrap() = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap();
        },
    )
    .await;
    println!(
        "635.evidence.failed_response={:?}",
        String::from_utf8_lossy(&failed_response)
    );
    assert!(failed_response.starts_with(b"HTTP/1.1 200"));
    assert!(failed_response.ends_with(b"635-audit-failure-response"));
    assert!(
        failed_response
            .windows(b"x-safeyolo-evidence-error: true".len())
            .any(|window| window.eq_ignore_ascii_case(b"x-safeyolo-evidence-error: true"))
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while store.get_flow(1).unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    // Restore only the event-evidence destination. The same process and flow
    // recorder continue, so a later successful write proves recovery rather
    // than a new isolated store accidentally hiding the first failure.
    proxy.reload(healthy.clone()).await.unwrap();
    let recovered_response = record_wire_flow_case_observe_with_hook(
        directory.path(),
        "/after-audit-recovery",
        b"635-recovered-request",
        b"635-recovered-response",
        || {},
    )
    .await;
    println!(
        "635.evidence.recovered_response={:?}",
        String::from_utf8_lossy(&recovered_response)
    );
    assert!(recovered_response.starts_with(b"HTTP/1.1 200"));
    assert!(recovered_response.ends_with(b"635-recovered-response"));
    assert!(
        !recovered_response
            .windows(b"x-safeyolo-evidence-error: true".len())
            .any(|window| window.eq_ignore_ascii_case(b"x-safeyolo-evidence-error: true"))
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while store.get_flow(2).unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    proxy.shutdown().await;
    let stats = recorder.stats();
    println!("635.evidence.recorder_stats={stats}");
    assert_eq!(
        stats,
        json!({"recorded":2,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":0})
    );
    let event_rows = std::fs::read_to_string(&healthy.event_log).unwrap();
    let recovered_event_count = event_rows
        .lines()
        .filter(|line| line.contains("\"event\":\"proxy.request\""))
        .count();
    println!("635.evidence.recovered_event_rows={recovered_event_count}");
    assert!(
        event_rows
            .lines()
            .any(|line| line.contains("\"event\":\"proxy.request\"")),
        "recovered event sink must retain a later request-evidence row"
    );

    // Reopen the existing flow database and prove capture survived the audit
    // sink failure. The first row is durable even though its evidence status
    // was explicitly failed; neither request was falsely reported as a
    // transport failure.
    drop(store);
    drop(recorder);
    let reopened =
        flow_store::FlowStore::open(&healthy.flow_store_db_path, Default::default()).unwrap();
    println!(
        "635.evidence.reopened_paths={:?}",
        [
            reopened.get_flow(1).unwrap().unwrap()["path"].as_str(),
            reopened.get_flow(2).unwrap().unwrap()["path"].as_str(),
        ]
    );
    assert_eq!(
        reopened.get_flow(1).unwrap().unwrap()["path"],
        "/audit-sink-failure"
    );
    assert_eq!(
        reopened.get_flow(2).unwrap().unwrap()["path"],
        "/after-audit-recovery"
    );
    assert_eq!(
        reopened
            .body(1, flow_store::Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"635-audit-failure-response"
    );
    assert_eq!(
        reopened
            .body(2, flow_store::Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"635-recovered-response"
    );
}

async fn record_wire_flow_case(
    directory: &Path,
    route: &str,
    request_body: &[u8],
    response_body: &[u8],
) {
    let response =
        record_wire_flow_case_observe(directory, route, request_body, response_body).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(response_body));
    assert!(
        !response
            .windows(b"x-safeyolo-evidence-error: true".len())
            .any(|window| window.eq_ignore_ascii_case(b"x-safeyolo-evidence-error: true"))
    );
}

async fn record_wire_flow_case_observe(
    directory: &Path,
    route: &str,
    request_body: &[u8],
    response_body: &[u8],
) -> Vec<u8> {
    record_wire_flow_case_observe_with_hook(directory, route, request_body, response_body, || {})
        .await
}

async fn record_wire_flow_case_observe_with_hook<F>(
    directory: &Path,
    route: &str,
    request_body: &[u8],
    response_body: &[u8],
    before_response: F,
) -> Vec<u8>
where
    F: FnOnce() + Send + 'static,
{
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UnixStream},
    };
    let listener = TcpListener::bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let route = route.to_owned();
    let request_body = request_body.to_vec();
    let response_body = response_body.to_vec();
    let origin_route = route.clone();
    let origin_request_body = request_body.clone();
    let origin_response_body = response_body.clone();
    let origin = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        assert!(
            !String::from_utf8_lossy(&head)
                .to_ascii_lowercase()
                .contains("x-safeyolo-test-context")
        );
        assert!(String::from_utf8_lossy(&head).contains(&format!("POST {origin_route} HTTP/1.1")));
        let content_length = String::from_utf8_lossy(&head)
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .unwrap();
        let mut body = vec![0; content_length];
        socket.read_exact(&mut body).await.unwrap();
        assert_eq!(body, origin_request_body);
        before_response();
        let response_head = format!(
            "HTTP/1.1 200 Owned\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            origin_response_body.len()
        );
        socket.write_all(response_head.as_bytes()).await.unwrap();
        socket.write_all(&origin_response_body).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        let mut socket = UnixStream::connect(directory.join("alice.sock")).await.unwrap();
        socket
            .write_all(
                format!(
                    "POST http://127.0.0.2:{port}{route} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-SafeYolo-Test-Context: run=wire-run;agent=declared-tool;test=wire;role=tester\r\nConnection: close\r\n\r\n",
                    request_body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(&request_body).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), origin)
        .await
        .unwrap()
        .unwrap();
    response
}

async fn record_wire_flow(directory: &Path) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UnixStream},
    };
    let listener = TcpListener::bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        assert!(
            !String::from_utf8_lossy(&head)
                .to_ascii_lowercase()
                .contains("x-safeyolo-test-context")
        );
        let mut body = [0; 7];
        socket.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"wire in");
        socket.write_all(b"HTTP/1.1 200 Owned\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nwire result").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut socket = UnixStream::connect(directory.join("alice.sock")).await.unwrap();
        socket.write_all(format!("POST http://127.0.0.2:{port}/recorded HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nX-SafeYolo-Test-Context: run=wire-run;agent=declared-tool;test=wire;role=tester\r\nConnection: close\r\n\r\nwire in").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"wire result"));
    }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), origin)
        .await
        .unwrap()
        .unwrap();
}

async fn agent_flow_request(
    directory: &Path,
    agent: &str,
    method: &str,
    path: &str,
    body: &str,
    authorized: bool,
) -> (u16, Value) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut socket = UnixStream::connect(directory.join(format!("{agent}.sock"))).await.unwrap();
        let auth = if authorized { "Authorization: Bearer owned-flow-api-token\r\n" } else { "" };
        let request = format!("{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        let response = std::str::from_utf8(&response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap())
    }).await.unwrap()
}
