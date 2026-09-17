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
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),
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
    send_as(directory, "alice", method, path, token, body).await
}

async fn send_as(
    directory: &Path,
    agent: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = UnixStream::connect(directory.join(format!("{agent}.sock")))
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
    // Connection-close memory events have a separate runtime test. Keep the
    // process startup policy publication here so this test consumes it at the
    // lifecycle boundary instead of globally hiding the event.
    records(&directory.join("audit.jsonl"))
        .into_iter()
        .filter(|row| {
            !(row["addon"] == "memory-monitor" && row["event"] == "ops.memory.conn_closed")
        })
        .collect()
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
    let startup = drained(&proxy, directory);
    assert_eq!(names(&startup), ["ops.policy_reload", "ops.startup"]);
    assert_eq!(startup[0]["addon"], "policy-loader");
    assert_eq!(startup[0]["details"]["policy_type"], "baseline");
    assert_eq!(startup[1]["addon"], "memory-monitor");
    let path = "/api/test-context/current///?agent=forged&private=not-an-audit-field";
    let declaration = br#"{"context":"run=R;agent=claimed;test=T","ttl":7}"#;
    let mut previous = startup.len();
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
            if auth {
                assert!(rows[0].get("request_id").is_none());
                assert!(rows[0].get("agent").is_none()&&rows[0].get("host").is_none());
                assert_eq!(rows[0]["details"],json!({"client_ip":"192.0.2.10","path":"/api/test-context/current"}));
            } else {
                assert_eq!(rows[0]["request_id"], rows[1]["request_id"]);
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
    let reload = drained(&proxy, directory);
    assert_eq!(names(&reload[previous..]), ["ops.policy_reload"]);
    assert_eq!(reload[previous]["addon"], "policy-loader");
    previous = reload.len();
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

#[test]
fn explain_uses_trusted_owner_and_shared_writer_after_reload() {
    const CHILD: &str = "SAFEYOLO_EXPLAIN_HTTP_FIXTURE";
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(explain_child(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "http::agent_audit_tests::explain_uses_trusted_owner_and_shared_writer_after_reload",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path())
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
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for name in [
        "alice.sock",
        "bob.sock",
        "ready",
        "unused.sqlite3",
        "unused-fallback.jsonl",
        "unused-reload.jsonl",
    ] {
        assert!(!directory.path().join(name).exists(), "{name}");
    }
    for name in ["audit.jsonl", "diagnostics.jsonl"] {
        let text = std::fs::read_to_string(directory.path().join(name)).unwrap();
        assert!(!text.contains(TOKEN));
        let encoded = TOKEN
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!text.contains(&encoded));
    }
}

fn correlation(reply: &[u8]) -> String {
    let split = reply
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let value = std::str::from_utf8(&reply[..split])
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("x-safeyolo-request-id"))
        .unwrap()
        .1
        .trim()
        .to_owned();
    assert!(value.starts_with("req-") && value.len() == 36);
    value
}

async fn explained(directory: &Path, agent: &str, request_id: &str, suffix: &str) -> Value {
    let reply = send_as(
        directory,
        agent,
        "GET",
        &format!("/explain?request_id={request_id}{suffix}"),
        Some(TOKEN),
        b"",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    let value: Value = serde_json::from_slice(body(&reply)).unwrap();
    assert_eq!(value["request_id"], request_id);
    assert_eq!(value["status"], "complete");
    value
}

async fn explain_child(directory: &Path) {
    let mut configuration = config(directory);
    let mut bob = configuration.listeners[0].clone();
    bob.agent_id = "bob".into();
    bob.socket_path = directory.join("bob.sock");
    bob.source_id = Some("192.0.2.11".into());
    configuration.listeners.push(bob);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let writer = proxy.runtime.read().unwrap().audit.clone();
    let alice = send_as(directory, "alice", "GET", "/health", Some(TOKEN), b"").await;
    let bob = send_as(directory, "bob", "GET", "/health", Some(TOKEN), b"").await;
    assert!(alice.starts_with(b"HTTP/1.1 200") && bob.starts_with(b"HTTP/1.1 200"));
    let alice_id = correlation(&alice);
    let bob_id = correlation(&bob);
    assert_ne!(alice_id, bob_id);
    // No explicit test drain: /explain itself must make completed exchanges
    // visible through the same process writer before performing its scan.
    let alice_events = explained(directory, "alice", &alice_id, "").await;
    let bob_events = explained(directory, "bob", &bob_id, "").await;
    for (value, agent) in [(&alice_events, "alice"), (&bob_events, "bob")] {
        let events = value["events"].as_array().unwrap();
        assert_eq!(names(events), ["traffic.request", "traffic.response"]);
        assert!(events.iter().all(|event| event["agent"] == agent));
    }
    for (agent, request_id, suffix) in [
        ("bob", alice_id.as_str(), ""),
        ("alice", bob_id.as_str(), ""),
        (
            "bob",
            alice_id.as_str(),
            "&agent=alice&client_ip=192.0.2.10",
        ),
        ("bob", "req-00000000000000000000000000000000", ""),
    ] {
        let value = explained(directory, agent, request_id, suffix).await;
        assert_eq!(value["events"], json!([]));
    }
    configuration.audit_log_path = Some(directory.join("unused-reload.jsonl"));
    proxy.reload(configuration).await.unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &writer,
        &proxy.runtime.read().unwrap().audit
    ));
    assert_eq!(
        explained(directory, "alice", &alice_id, "").await,
        alice_events
    );
    proxy.shutdown().await;
    assert!(
        !records(&directory.join("diagnostics.jsonl"))
            .iter()
            .any(|row| row["event"] == "proxy.egress")
    );
}

#[test]
fn discovery_reports_prior_observations_and_survives_reload() {
    const CHILD: &str = "SAFEYOLO_DISCOVERY_HTTP_FIXTURE";
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(discovery_child(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "http::agent_audit_tests::discovery_reports_prior_observations_and_survives_reload",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path())
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
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for name in [
        "alice.sock",
        "bob.sock",
        "ready",
        "unused.sqlite3",
        "unused-fallback.jsonl",
    ] {
        assert!(!directory.path().join(name).exists(), "{name}");
    }
}

fn discovery_map(path: &Path, value: Value, seconds: u64) {
    use std::fs::{File, FileTimes};
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            FileTimes::new().set_modified(std::time::UNIX_EPOCH + Duration::from_secs(seconds)),
        )
        .unwrap();
}

fn discovery_document(runtime: &crate::Runtime) -> Value {
    serde_json::from_str(
        &runtime
            .agent_discovery
            .get_agents(&runtime.audit, crate::circuit_runtime::now)
            .unwrap()
            .render_json(false)
            .unwrap(),
    )
    .unwrap()
}

async fn discovered(directory: &Path, agent: &str) -> Value {
    let reply = send_as(
        directory,
        agent,
        "GET",
        "/agents?agent=forged-identity",
        Some(TOKEN),
        b"",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    serde_json::from_slice(body(&reply)).unwrap()
}

async fn discovery_child(directory: &Path) {
    let mut configuration = config(directory);
    configuration.listeners.push(crate::config::AgentListener {
        agent_id: "bob".into(),
        socket_path: directory.join("bob.sock"),
        source_id: Some("192.0.2.11".into()),
    });
    configuration.agent_map_file = directory
        .join("agent-map.json")
        .to_str()
        .unwrap()
        .to_owned();
    discovery_map(
        Path::new(&configuration.agent_map_file),
        json!({
            "alice":{"ip":"192.0.2.10"}, "bob":{"ip":"192.0.2.11"}, "unseen":{}
        }),
        100,
    );
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let first = discovered(directory, "alice").await;
    assert_eq!(
        first,
        json!({"agents":{"alice":{"ip":"192.0.2.10"},"bob":{"ip":"192.0.2.11"},"unseen":{"ip":null}},"count":3})
    );
    let after_alice = discovery_document(&runtime);
    assert!(after_alice["agents"]["alice"]["last_seen"].is_number());
    assert!(after_alice["agents"]["bob"].get("last_seen").is_none());
    let from_bob = discovered(directory, "bob").await;
    assert_eq!(
        from_bob["agents"]["alice"]["last_seen"],
        after_alice["agents"]["alice"]["last_seen"]
    );
    assert!(from_bob["agents"]["bob"].get("last_seen").is_none());
    let both = discovery_document(&runtime);
    assert!(both["agents"]["bob"]["last_seen"].is_number());
    assert!(both["agents"].get("forged-identity").is_none());

    // CONNECT admission has a separate observation even when containment
    // responds locally. The reserved target cannot resolve or open a socket.
    runtime
        .agent_discovery
        .observe_trusted("bob", || 1.)
        .unwrap();
    let mut stream = UnixStream::connect(directory.join("bob.sock"))
        .await
        .unwrap();
    stream.write_all(b"CONNECT _safeyolo.proxy.internal:80 HTTP/1.1\r\nHost: _safeyolo.proxy.internal:80\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut denied = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut denied))
        .await
        .unwrap()
        .unwrap();
    assert!(denied.starts_with(b"HTTP/1.1 403"));
    assert!(
        discovery_document(&runtime)["agents"]["bob"]["last_seen"]
            .as_f64()
            .unwrap()
            > 1.
    );

    // A different configured file publishes new metadata but retains observed
    // history and the shared owner used by the API and operator statistics.
    configuration.agent_map_file = directory.join("next-map.json").to_str().unwrap().to_owned();
    discovery_map(
        Path::new(&configuration.agent_map_file),
        json!({
            "alice":{"ip":"192.0.2.10"}, "bob":{"ip":"192.0.2.11"}, "new-agent":{}
        }),
        200,
    );
    proxy.reload(configuration.clone()).await.unwrap();
    let current = proxy.runtime.read().unwrap().clone();
    assert!(std::sync::Arc::ptr_eq(
        &runtime.agent_discovery,
        &current.agent_discovery
    ));
    let after_reload = discovery_document(&current);
    assert_eq!(
        after_reload["agents"]["alice"]["last_seen"],
        both["agents"]["alice"]["last_seen"]
    );
    assert!(after_reload["agents"].get("unseen").is_none());
    assert_eq!(after_reload["agents"]["new-agent"], json!({"ip":null}));
    let stats = crate::operator_stats::document(&current);
    let stats: Value = serde_json::from_str(&stats.render_json(false).unwrap()).unwrap();
    assert_eq!(
        stats["service-discovery"]["map_file"],
        configuration.agent_map_file
    );
    assert_eq!(stats["service-discovery"]["known_ips"], 2);
    assert_eq!(stats["service-discovery"]["agents_seen"], 3);
    assert_eq!(
        stats["service-discovery"]["agents"]["bob"]["last_seen"],
        after_reload["agents"]["bob"]["last_seen"]
    );

    let mut broken = configuration.clone();
    broken.agent_map_file = directory
        .join("broken-map.json")
        .to_str()
        .unwrap()
        .to_owned();
    discovery_map(Path::new(&broken.agent_map_file), json!([]), 300);
    proxy.reload(broken.clone()).await.unwrap();
    assert!(
        runtime
            .agent_discovery
            .matches_path(&broken.agent_map_file)
            .unwrap()
    );
    let invalid_report = send(directory, "GET", "/agents", Some(TOKEN), b"").await;
    assert!(invalid_report.starts_with(b"HTTP/1.1 500"));
    assert_eq!(
        serde_json::from_slice::<Value>(body(&invalid_report)).unwrap()["error"],
        "Internal error: AttributeError"
    );
    proxy.reload(configuration.clone()).await.unwrap();
    assert!(
        runtime
            .agent_discovery
            .matches_path(&configuration.agent_map_file)
            .unwrap()
    );

    // A later listener-bind failure keeps the published config but can occur
    // after discovery configured its shared path. Restoring the old config
    // must compare the owner's actual path rather than the published config.
    let occupied = directory.join("occupied.sock");
    std::fs::write(&occupied, b"owned regular file must survive").unwrap();
    broken.listeners.push(crate::config::AgentListener {
        agent_id: "unused".into(),
        socket_path: occupied.clone(),
        source_id: None,
    });
    assert!(proxy.reload(broken.clone()).await.is_err());
    assert!(
        runtime
            .agent_discovery
            .matches_path(&broken.agent_map_file)
            .unwrap()
    );
    proxy.reload(configuration.clone()).await.unwrap();
    assert!(
        runtime
            .agent_discovery
            .matches_path(&configuration.agent_map_file)
            .unwrap()
    );
    assert_eq!(
        std::fs::read(&occupied).unwrap(),
        b"owned regular file must survive"
    );

    let records = drained(&proxy, directory);
    assert_eq!(
        records
            .iter()
            .filter(|record| record["event"] == "agent.discovered")
            .count(),
        2
    );
    discovery_map(
        Path::new(&configuration.agent_map_file),
        json!({
            "alice":{"ip":"192.0.2.10"}, "bob":{"ip":"192.0.2.11"}, "charlie":{"ip":"192.0.2.12"}
        }),
        400,
    );
    runtime
        .agent_discovery
        .observe_trusted("alice", || 1.)
        .unwrap();
    runtime.audit.poison_for_test();
    let health = send(directory, "GET", "/health", Some(TOKEN), b"").await;
    assert!(health.starts_with(b"HTTP/1.1 200"));
    let after_failure = discovery_document(&runtime);
    assert_eq!(after_failure["agents"]["charlie"]["ip"], "192.0.2.12");
    assert!(
        after_failure["agents"]["alice"]["last_seen"]
            .as_f64()
            .unwrap()
            > 1.
    );

    configuration.agent_map_file.clear();
    proxy.reload(configuration).await.unwrap();
    assert_eq!(
        discovery_document(&runtime)["agents"]["alice"]["last_seen"],
        after_failure["agents"]["alice"]["last_seen"]
    );
    proxy.shutdown().await;
    assert!(
        !self::records(&directory.join("diagnostics.jsonl"))
            .iter()
            .any(|row| row["event"] == "proxy.egress")
    );
    assert!(
        !std::fs::read_to_string(directory.join("audit.jsonl"))
            .unwrap()
            .contains(TOKEN)
    );
}

#[test]
fn conflicted_request_snapshot_quarantines_scoped_consumers() {
    const CHILD: &str = "SAFEYOLO_IDENTITY_CONSUMER_FIXTURE";
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(conflicted_child(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "http::agent_audit_tests::conflicted_request_snapshot_quarantines_scoped_consumers",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path())
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
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn conflicted_child(directory: &Path) {
    let mut configuration = config(directory);
    configuration.agent_map_file = directory
        .join("agent-map.json")
        .to_str()
        .unwrap()
        .to_owned();
    discovery_map(
        Path::new(&configuration.agent_map_file),
        json!({"bob":{"ip":"192.0.2.10"}}),
        100,
    );
    let proxy = Proxy::start(configuration).await.unwrap();
    let startup = drained(&proxy, directory);
    assert_eq!(
        names(&startup),
        ["agent.discovered", "ops.policy_reload", "ops.startup"]
    );

    // A malformed body and a forged query value must not be read or become
    // an owner when the listener/map sources disagree.
    let declaration = send_as(
        directory,
        "alice",
        "POST",
        "/api/test-context/current?agent=forged",
        Some(TOKEN),
        b"not-json",
    )
    .await;
    assert!(declaration.starts_with(b"HTTP/1.1 403"));
    assert!(String::from_utf8_lossy(body(&declaration)).contains("Could not identify agent"));

    // Flow, trace and gateway access routes all consume the same ownerless
    // snapshot before scoped providers or request-body decoding.
    for (method, path, content) in [
        (
            "GET",
            "/api/flows/search?evidence_owner=bob&agent=forged",
            b"".as_slice(),
        ),
        (
            "GET",
            "/trace?request_id=req-00000000000000000000000000000000&agent=bob",
            b"".as_slice(),
        ),
        (
            "POST",
            "/gateway/request-access?agent=bob",
            b"[]".as_slice(),
        ),
    ] {
        let reply = send_as(directory, "alice", method, path, Some(TOKEN), content).await;
        assert!(reply.starts_with(b"HTTP/1.1 403"), "{method} {path}");
    }

    // Discovery reporting remains a local administrative read, but it must
    // show no last-seen owner for either side of the conflict.
    let report = send_as(
        directory,
        "alice",
        "GET",
        "/agents?agent=forged",
        Some(TOKEN),
        b"",
    )
    .await;
    assert!(report.starts_with(b"HTTP/1.1 200"));
    let report: Value = serde_json::from_slice(body(&report)).unwrap();
    assert!(report["agents"]["bob"].get("last_seen").is_none());
    assert!(!serde_json::to_string(&report).unwrap().contains("forged"));

    let records = drained(&proxy, directory);
    let conflicts: Vec<&Value> = records
        .iter()
        .filter(|record| record["event"] == "security.agent_identity_conflict")
        .collect();
    assert_eq!(conflicts.len(), 5);
    for record in conflicts {
        assert!(record.get("agent").is_none());
        assert_eq!(record["details"]["uds_agent"], "alice");
        assert_eq!(record["details"]["mapped_agent"], "bob");
        assert_eq!(
            record["details"]["attribution"]["attribution_status"],
            "conflict"
        );
        assert!(
            record["details"]["attribution"]
                .get("evidence_owner")
                .is_none()
        );
    }
    assert!(!records.iter().any(|record| {
        record.to_string().contains("forged") || record.to_string().contains("agent\\\":\\\"bob")
    }));
}
