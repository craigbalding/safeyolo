//! Owned H1 local API exchanges prove canonical producer order and omissions.

use crate::{Config, Proxy};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const CHILD: &str = "SAFEYOLO_AGENT_AUDIT_HTTP_FIXTURE";
const TOKEN: &str = "synthetic-agent-audit-http-fixture";

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(&policy, "{}").unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock"),"source_id":"192.0.2.10"}],
        "policy_file":policy,"readiness_file":directory.join("ready"),
        "event_log":directory.join("diagnostics.jsonl"),"audit_log_path":directory.join("audit.jsonl"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":"",
    })).unwrap()
}

async fn send(
    directory: &Path,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = UnixStream::connect(directory.join("alice.sock"))
        .await
        .unwrap();
    let authorization = token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    let head = format!(
        "{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\n{authorization}X-SafeYolo-Request-Id: caller-id-must-not-be-trusted\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    reply
}
fn body(reply: &[u8]) -> &[u8] {
    &reply[reply
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4..]
}
fn records(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn drained(proxy: &Proxy, directory: &Path) -> Vec<Value> {
    assert!(
        proxy
            .runtime
            .read()
            .unwrap()
            .audit
            .wait_for_drain(LIMIT)
            .unwrap()
    );
    records(&directory.join("audit.jsonl"))
}
fn names(rows: &[Value]) -> Vec<&str> {
    rows.iter()
        .map(|row| row["event"].as_str().unwrap())
        .collect()
}
fn canonical(row: &Value, expected: &str, decision: Option<&str>) {
    assert_eq!(row["schema_version"], 1);
    assert_eq!(row["event"], expected);
    assert_eq!(row["kind"], "security");
    assert_eq!(
        row.get("decision"),
        decision.map(|decision| json!(decision)).as_ref()
    );
    assert!(row.get("approval").is_none());
    assert!(row["details"].get("attribution").is_none());
}

#[test]
fn canonical_agent_events_precede_traffic_and_preserve_local_responses() {
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(owned_child(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact","http::agent_audit_tests::canonical_agent_events_precede_traffic_and_preserve_local_responses","--nocapture"])
        .env(CHILD,directory.path()).env("SAFEYOLO_DATA_DIR",directory.path())
        .env("SAFEYOLO_LOG_PATH",directory.path().join("unused-fallback.jsonl"))
        .env_remove("SAFEYOLO_AUDIT_QUEUE_MAX").env_remove("SAFEYOLO_LOG_MAX_MB").env_remove("SAFEYOLO_LOG_BACKUPS")
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for name in [
        "alice.sock",
        "ready",
        "unused.sqlite3",
        "unused-fallback.jsonl",
    ] {
        assert!(!directory.path().join(name).exists(), "{name}");
    }
    for name in ["audit.jsonl", "diagnostics.jsonl"] {
        let content = std::fs::read_to_string(directory.path().join(name)).unwrap();
        assert!(!content.contains(TOKEN));
        let encoded = TOKEN
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!content.contains(&encoded));
    }
}

async fn owned_child(directory: &Path) {
    let mut configuration = config(directory);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let writer = proxy.runtime.read().unwrap().audit.clone();
    let path = "/api/test-context/current///?agent=forged&private=not-an-audit-field";
    let declaration = br#"{"context":"run=R;agent=claimed;test=T","ttl":7}"#;
    let mut previous = 0;
    for (method,token,content,status,event,expected_body) in [
        ("GET",Some("wrong"),b"".as_slice(),401,Some("security.agent_auth_failed"),Some(br#"{"error": "Invalid agent token"}"#.as_slice())),
        ("POST",Some(TOKEN),declaration.as_slice(),200,Some("security.test_context_declared"),Some(br#"{"status": "set", "agent": "alice", "expires_in": 7, "context": {"run": "R", "agent": "claimed", "test": "T"}}"#.as_slice())),
        ("GET",Some(TOKEN),b"".as_slice(),200,None,None),
        ("DELETE",Some(TOKEN),b"".as_slice(),200,Some("security.test_context_cleared"),Some(br#"{"status": "cleared"}"#.as_slice())),
        ("GET",None,b"".as_slice(),401,None,Some(br#"{"error": "Authorization required", "hint": "Bearer <token>"}"#.as_slice())),
    ] {
        let reply=send(directory,method,path,token,content).await;
        assert!(reply.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
        assert!(!String::from_utf8_lossy(&reply).contains("x-safeyolo-evidence-error"));
        if let Some(expected)=expected_body {assert_eq!(body(&reply),expected);}
        else {
            let value:Value=serde_json::from_slice(body(&reply)).unwrap();
            assert_eq!(value["agent"],"alice");
            assert_eq!(value["context"],json!({"run":"R","agent":"claimed","test":"T"}));
            assert!(value["expires_in"].as_u64().is_some_and(|ttl|(1..=7).contains(&ttl)));
        }
        let all=drained(&proxy,directory);let rows=&all[previous..];previous=all.len();
        if let Some(event)=event {
            assert_eq!(names(rows),vec![event,"traffic.request","traffic.response"]);
            let auth=event=="security.agent_auth_failed";
            canonical(&rows[0],event,auth.then_some("deny"));
            assert_eq!(rows[0]["severity"],if auth {"high"}else{"low"});
            assert_eq!(rows[0]["addon"],"agent-api");
            assert!(rows[0].get("request_id").is_none());
            if auth {
                assert!(rows[0].get("agent").is_none()&&rows[0].get("host").is_none());
                assert_eq!(rows[0]["details"],json!({"client_ip":"192.0.2.10","path":"/api/test-context/current"}));
            } else {
                assert_eq!(rows[0]["agent"],"alice");assert_eq!(rows[0]["host"],"_safeyolo.proxy.internal");
                assert_eq!(rows[0]["details"]["source_id"],"192.0.2.10");
                assert_eq!(rows[0]["details"]["trusted_agent"],"alice");
            }
        } else {assert_eq!(names(rows),vec!["traffic.request","traffic.response"]);}
        let response=rows.last().unwrap();
        assert_eq!(response["details"]["blocked_by"],"agent-api");
        assert_eq!(response["details"]["size"],body(&reply).len());
        assert_eq!(response["details"]["status"],status);
        let request=&rows[rows.len()-2];
        assert_eq!(request["details"]["size"],content.len());
        assert_eq!(response["request_id"],request["request_id"]);
        assert_ne!(request["request_id"],"caller-id-must-not-be-trusted");
    }
    configuration.agent_api_enabled = false;
    proxy.reload(configuration).await.unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &writer,
        &proxy.runtime.read().unwrap().audit
    ));
    let reply = send(directory, "GET", path, Some(TOKEN), b"").await;
    assert!(reply.starts_with(b"HTTP/1.1 503"));
    let value: Value = serde_json::from_slice(body(&reply)).unwrap();
    assert_eq!(value["reason_code"], "agent_api_unavailable");
    let all = drained(&proxy, directory);
    let rows = &all[previous..];
    assert_eq!(
        names(rows),
        vec![
            "security.agent_api_unavailable",
            "traffic.request",
            "traffic.response"
        ]
    );
    canonical(&rows[0], "security.agent_api_unavailable", Some("deny"));
    assert_eq!(rows[0]["request_id"], value["request_id"]);
    assert_eq!(rows[0]["agent"], "alice");
    assert_eq!(rows[0]["details"]["path"], "/api/test-context/current///");
    assert_eq!(rows[0]["addon"], "agent-api-request-guard");
    proxy.shutdown().await;
    let diagnostics = records(&directory.join("diagnostics.jsonl"));
    assert_eq!(
        diagnostics
            .iter()
            .filter(|row| row["event"] == "proxy.agent_api")
            .count(),
        6
    );
    assert!(!diagnostics.iter().any(|row| row["event"] == "proxy.egress"));
}
