//! Owned runtime observations with synthetic process samples and ordinary H1.

use std::{io::Write, path::Path, sync::Arc, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

use crate::{Config, Proxy};

const LIMIT: Duration = Duration::from_secs(5);

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}]
        })
        .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),
        "event_log":directory.join("events.jsonl"),"audit_log_path":directory.join("audit.jsonl"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":"",
    }))
    .unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

async fn head(stream: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        head
    })
    .await
    .unwrap()
}

async fn reply(stream: &mut UnixStream) -> Vec<u8> {
    let headers = head(stream).await;
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    let length: usize = String::from_utf8_lossy(&headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    timeout(LIMIT, stream.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    body
}

#[tokio::test]
async fn original_body_accounting_survives_hygiene_and_runtime_reload() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let host = address.ip().to_string();
    let request_plain = b"owned request content";
    let request_encoded = gzip(request_plain);
    let response_plain = b"owned response content";
    let response_encoded = gzip(response_plain);
    let peer_request = request_encoded.clone();
    let peer_response = response_encoded.clone();
    let peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = timeout(LIMIT, origin.accept()).await.unwrap().unwrap();
            let headers = head(&mut stream).await;
            // Memory uses original encoding; later source hygiene removes the
            // nominated header without changing the delivered encoded bytes.
            assert!(
                !String::from_utf8_lossy(&headers)
                    .to_ascii_lowercase()
                    .contains("content-encoding:")
            );
            let mut body = vec![0; peer_request.len()];
            timeout(LIMIT, stream.read_exact(&mut body))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(body, peer_request);
            stream.write_all(format!("HTTP/1.1 200 Owned\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",peer_response.len()).as_bytes()).await.unwrap();
            stream.write_all(&peer_response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let configuration = config(directory.path());
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    for round in 0..2 {
        if round == 1 {
            proxy.reload(configuration.clone()).await.unwrap();
            assert!(Arc::ptr_eq(
                &runtime.memory_monitor,
                &proxy.runtime.read().unwrap().memory_monitor
            ));
        }
        let connection = if round == 0 { "keep-alive" } else { "close" };
        client.write_all(format!("POST http://{address}/owned HTTP/1.1\r\nHost: {address}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: {connection}, Content-Encoding\r\n\r\n",request_encoded.len()).as_bytes()).await.unwrap();
        client.write_all(&request_encoded).await.unwrap();
        assert_eq!(reply(&mut client).await, response_encoded);
    }
    let mut remaining = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    assert!(remaining.is_empty());
    drop(client);
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let report = runtime
        .memory_monitor
        .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(report["total_flows"], 2);
    assert_eq!(report["active_connections"], 0);
    assert_eq!(report["active_websockets"], 0);
    assert_eq!(report["connections"], json!([]));
    let events: Vec<Value> = std::fs::read_to_string(directory.path().join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &Value| event["addon"] == "memory-monitor")
        .collect();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0]["event"], "ops.startup");
    assert_eq!(events[0]["details"], json!({"rss_start_mb":0.0}));
    assert_eq!(events[1]["event"], "ops.memory.conn_closed");
    assert_eq!(events[1]["host"], host);
    assert_eq!(events[1]["details"]["flow_count"], 2);
    assert_eq!(events[1]["details"]["bytes_sent"], request_plain.len() * 2);
    assert_eq!(
        events[1]["details"]["bytes_received"],
        response_plain.len() * 2
    );
}

const CHILD: &str = "SAFEYOLO_MEMORY_REPORT_HTTP_FIXTURE";
const TOKEN: &str = "synthetic-memory-report-token";

#[test]
fn authenticated_memory_reports_share_prior_observations_across_reload() {
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(report_workflow(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact","http::memory_tests::authenticated_memory_reports_share_prior_observations_across_reload","--nocapture"])
        .env(CHILD,directory.path()).env("SAFEYOLO_DATA_DIR",directory.path())
        .output().unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    for path in ["alice.sock", "bob.sock", "ready", "unused.sqlite3"] {
        assert!(!directory.path().join(path).exists(), "{path}");
    }
    for path in ["events.jsonl", "audit.jsonl"] {
        assert!(
            !std::fs::read_to_string(directory.path().join(path))
                .unwrap()
                .contains(TOKEN)
        );
    }
}

async fn report_workflow(directory: &Path) {
    let mut configuration = config(directory);
    configuration.listeners.push(crate::AgentListener {
        agent_id: "bob".into(),
        socket_path: directory.join("bob.sock"),
        source_id: None,
    });
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut lengths = Vec::new();
    for (prior, agent) in ["alice", "bob", "alice"].into_iter().enumerate() {
        if prior > 0 {
            // Source SSE classification also excludes local JSON response
            // bytes. Toggle it on and off through the actual runtime reload.
            configuration.sse_stream_json = prior == 1;
            proxy.reload(configuration.clone()).await.unwrap();
            assert!(Arc::ptr_eq(
                &runtime.memory_monitor,
                &proxy.runtime.read().unwrap().memory_monitor
            ));
        }
        let mut client = UnixStream::connect(directory.join(format!("{agent}.sock")))
            .await
            .unwrap();
        client.write_all(format!("GET http://_safeyolo.proxy.internal/memory?agent=forged HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let bytes = reply(&mut client).await;
        lengths.push(if prior == 1 { 0 } else { bytes.len() });
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        // The current native local handler precedes its existing request
        // observation. This is the documented self-counting gap, not source
        // parity: each next agent sees all earlier agents' completed calls.
        assert_eq!(report["total_flows"], prior);
        assert_eq!(report["rss_mb"], 0.0);
        assert_eq!(report["rss_hwm_mb"], 0.0);
        assert_eq!(report["rss_start_mb"], 0.0);
        assert!(!report.to_string().contains("forged"));
        let mut rest = Vec::new();
        timeout(LIMIT, client.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.is_empty());
    }
    proxy.shutdown().await;
    let report = runtime
        .memory_monitor
        .get_stats(crate::memory_runtime::sample, crate::circuit_runtime::now)
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(report["total_flows"], 3);
    assert_eq!(report["active_connections"], 0);
    let events: Vec<Value> = std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &Value| event["addon"] == "memory-monitor")
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "ops.startup")
            .count(),
        1
    );
    let closed: Vec<_> = events
        .iter()
        .filter(|event| event["event"] == "ops.memory.conn_closed")
        .collect();
    assert_eq!(closed.len(), 3);
    let mut actual_sizes: Vec<_> = closed
        .iter()
        .map(|event| {
            assert_eq!(event["host"], "_safeyolo.proxy.internal");
            assert_eq!(event["details"]["flow_count"], 1);
            assert_eq!(event["details"]["bytes_sent"], 0);
            event["details"]["bytes_received"].as_u64().unwrap() as usize
        })
        .collect();
    actual_sizes.sort_unstable();
    lengths.sort_unstable();
    assert_eq!(actual_sizes, lengths);
}
