//! Retention publication and live HTTP observations with owned fixture state.

use super::*;
use traffic_view::RequestInfo;

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, "{}").unwrap();
    serde_json::from_value(json!({
        "listeners":[], "policy_file":policy, "data_dir":directory.join("data"), "flow_store_enabled":false,
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl"),
        "readiness_file":directory.join("ready.json"),
    }))
    .unwrap()
}

#[test]
fn retention_defaults_are_source_soft_targets_and_zero_is_invalid() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    assert_eq!(config.flow_pruner_max, 5000);
    assert_eq!(config.flow_pruner_max_body_bytes, 1024 * 1024 * 1024);
    config.flow_pruner_max = 0;
    assert!(config.validate().is_err());
    config.flow_pruner_max = 1;
    config.flow_pruner_max_body_bytes = 0;
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn accepted_reload_preserves_view_scope_and_filter_and_publishes_retention() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.flow_pruner_max = 3;
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let initial = proxy.runtime.read().unwrap().traffic_view.clone();
    initial.set_scope(&json!({"agent":"alice"})).unwrap();
    initial.set_user_filter("  ~m GET  ").unwrap();
    for id in ["first", "second"] {
        let exchange = initial.begin(RequestInfo {
            id: id.into(),
            connection_id: "owned".into(),
            agent: Some("alice".into()),
            method: "GET".into(),
            url: "http://owned.invalid/".into(),
            headers: vec![],
            started: 1.,
        });
        exchange.finish(None);
    }
    assert_eq!(
        initial.flows().unwrap()["flows"].as_array().unwrap().len(),
        2
    );
    config.flow_pruner_max = 1;
    let mut failed = config.clone();
    failed.policy_file = Some(directory.path().join("missing-policy.json"));
    assert!(proxy.reload(failed).await.is_err());
    assert_eq!(initial.scope()["user_filter"], "  ~m GET  ");
    assert!(initial.detail("first").is_some());
    assert!(initial.detail("second").is_some());
    proxy.reload(config.clone()).await.unwrap();
    let current = proxy.runtime.read().unwrap().traffic_view.clone();
    assert!(Arc::ptr_eq(&initial, &current));
    assert_eq!(current.scope()["agent"], "alice");
    assert_eq!(current.scope()["user_filter"], "  ~m GET  ");
    assert!(current.detail("first").is_none());
    assert!(current.detail("second").is_some());
    proxy.shutdown().await;
    assert!(!config.readiness_file.exists());
}

#[tokio::test]
async fn ordinary_http_is_visible_while_pending_and_completes_across_reload() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use traffic_view::Side;

    tokio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        std::fs::write(config.policy_file.as_ref().unwrap(),
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#).unwrap();
        // This fixture owns its loopback origin; private-address protection is
        // exercised elsewhere and is not the contract under test here.
        config.network_guard_enabled = false;
        let socket_path = directory.path().join("alice.sock");
        config.listeners.push(AgentListener {
            agent_id: "alice".into(), socket_path: socket_path.clone(), source_id: None,
        });
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let (request_seen, request_ready) = tokio::sync::oneshot::channel();
        let (release_response, response_ready) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut received = Vec::new();
            loop {
                let mut block = [0; 1024];
                let size = stream.read(&mut block).await.unwrap();
                assert!(size > 0);
                received.extend_from_slice(&block[..size]);
                if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    && received.len() >= end + 8 {
                    assert_eq!(&received[end + 4..end + 8], b"body");
                    break;
                }
            }
            request_seen.send(()).unwrap();
            response_ready.await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ndone").await.unwrap();
        });
        let mut proxy = Proxy::start(config.clone()).await.unwrap();
        let view = proxy.runtime.read().unwrap().traffic_view.clone();
        assert!(proxy.runtime.read().unwrap().flow_recorder.store().is_none());
        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client.write_all(format!("POST http://{address}/owned?x=1&x=2 HTTP/1.1\r\nHost: {address}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody").as_bytes()).await.unwrap();
        request_ready.await.unwrap();
        let flows = view.flows().unwrap();
        let rows = flows["flows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let id = rows[0]["id"].as_str().unwrap().to_owned();
        assert_eq!(rows[0]["agent"], "alice");
        assert_eq!(rows[0]["state"], "pending");
        let pending = view.detail(&id).unwrap();
        assert!(pending["metadata"].get("test_context").is_none());
        assert!(pending["request_completed"].as_f64().is_some());
        assert!(pending["response_head_observed"].is_null());
        assert!(pending["response_completed"].is_null());
        assert!(pending["ended"].is_null());
        let upstream = pending["upstream"].clone();
        assert!(!upstream["id"].as_str().unwrap().is_empty());
        assert_eq!(upstream["route"], "direct");
        assert_eq!(upstream["peer"], address.to_string());
        let connection_started = upstream["started"].as_f64().unwrap();
        let tcp_setup = upstream["tcp_setup"].as_f64().unwrap();
        assert!(connection_started <= tcp_setup);
        assert!(upstream["tls_setup"].is_null());
        assert_eq!(view.body(&id, Side::Request).unwrap()["data_base64"], STANDARD.encode(b"body"));
        view.set_scope(&json!({"agent":"alice"})).unwrap();
        config.flow_pruner_max = 2;
        proxy.reload(config.clone()).await.unwrap();
        assert!(Arc::ptr_eq(&view, &proxy.runtime.read().unwrap().traffic_view));
        release_response.send(()).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200"));
        assert!(reply.ends_with(b"done"));
        origin_task.await.unwrap();
        let row = view.detail(&id).unwrap();
        assert_eq!(row["state"], "complete");
        assert_eq!(row["status"], 200);
        assert_eq!(row["upstream"], upstream);
        assert_eq!(row["request_completed"], pending["request_completed"]);
        let response_head = row["response_head_observed"].as_f64().unwrap();
        let response_completed = row["response_completed"].as_f64().unwrap();
        assert!(tcp_setup <= response_head);
        assert!(response_head <= response_completed);
        assert!(response_completed <= row["ended"].as_f64().unwrap());
        assert_eq!(view.body(&id, Side::Response).unwrap()["data_base64"], STANDARD.encode(b"done"));
        assert_eq!(view.scope()["agent"], "alice");
        proxy.shutdown().await;
        assert!(!socket_path.exists());
        assert!(!config.readiness_file.exists());
    }).await.expect("owned HTTP view fixture must finish");
}
