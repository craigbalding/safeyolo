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
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),"audit_log_path":directory.join("audit.jsonl"),
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

/// Read exactly one framed response from a persistent H1 connection. The
/// ordinary helper above deliberately closes the socket; this helper keeps
/// the listener-owned identity alive across request boundaries so discovery
/// replacement can be observed without reconnecting.
async fn read_response(stream: &mut UnixStream) -> Vec<u8> {
    let mut reply = Vec::new();
    loop {
        let read = stream.read_buf(&mut reply).await.unwrap();
        assert!(read > 0, "persistent local API connection closed early");
        let Some(separator) = reply.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let content_length = std::str::from_utf8(&reply[..separator])
            .unwrap()
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let end = separator + 4 + content_length;
        if reply.len() >= end {
            reply.truncate(end);
            return reply;
        }
    }
}

async fn keepalive_request(stream: &mut UnixStream, method: &str, path: &str) -> Vec<u8> {
    let head = format!(
        "{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nX-SafeYolo-Agent: forged\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    read_response(stream).await
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
            assert_eq!(row["schema_version"], 1);
            !(row["addon"] == "memory-monitor" && row["event"] == "ops.memory.conn_closed")
        })
        .filter(|row| {
            !matches!(
                row["event"].as_str(),
                Some(
                    "agent.api_response"
                        | "traffic.request_outcome"
                        | "traffic.egress"
                        | "security.network_guard.evaluated"
                        | "security.credential_guard.evaluated"
                        | "gateway.evaluated"
                )
            )
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
    {
        let name = "audit.jsonl";
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
    let diagnostics = records(&directory.join("audit.jsonl"));
    assert_eq!(
        diagnostics
            .iter()
            .filter(|row| row["event"] == "agent.api_response")
            .count(),
        6
    );
    assert!(
        !diagnostics
            .iter()
            .any(|row| row["event"] == "traffic.egress")
    );
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
    {
        let name = "audit.jsonl";
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
        assert_eq!(
            names(events),
            [
                "agent.api_response",
                "traffic.request",
                "traffic.response",
                "traffic.request_outcome"
            ]
        );
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
        !records(&directory.join("audit.jsonl"))
            .iter()
            .any(|row| row["event"] == "traffic.egress")
    );
}

#[test]
fn listener_reports_and_scoped_consumers_ignore_claimed_identity() {
    const CHILD: &str = "SAFEYOLO_LISTENER_IDENTITY_FIXTURE";
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(listener_child(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "http::agent_audit_tests::listener_reports_and_scoped_consumers_ignore_claimed_identity", "--nocapture"])
        .env(CHILD, directory.path()).env("SAFEYOLO_DATA_DIR", directory.path())
        .env("SAFEYOLO_LOG_PATH", directory.path().join("unused-fallback.jsonl"))
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
        "bob.sock",
        "unknown.sock",
        "ready",
        "unused.sqlite3",
        "unused-fallback.jsonl",
    ] {
        assert!(!directory.path().join(name).exists(), "{name}");
    }
}

async fn listener_child(directory: &Path) {
    let mut configuration = config(directory);
    configuration.flow_store_enabled = true;
    configuration.flow_store_db_path = directory.join("flows.sqlite3");
    std::fs::write(
        configuration.policy_file.as_ref().unwrap(),
        json!({"permissions":[
            {"action":"network:request", "resource":"*", "effect":"allow"}
        ]})
        .to_string(),
    )
    .unwrap();
    for agent in ["bob", "unknown"] {
        configuration.listeners.push(crate::AgentListener {
            agent_id: agent.into(),
            socket_path: directory.join(format!("{agent}.sock")),
            // Identical claimed source slots cannot select another listener's owner.
            source_id: Some("192.0.2.10".into()),
        });
    }
    // An old or agent-written map and metadata are no longer identity inputs.
    let map = directory.join("data/agent_map.json");
    std::fs::create_dir_all(map.parent().unwrap()).unwrap();
    std::fs::write(
        &map,
        br#"{"bob":{"ip":"192.0.2.10"},"intruder":{"ip":"192.0.2.11"}}"#,
    )
    .unwrap();
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let initial = send(directory, "GET", "/agents?agent=forged", Some(TOKEN), b"").await;
    assert!(initial.starts_with(b"HTTP/1.1 200"));
    let initial: Value = serde_json::from_slice(body(&initial)).unwrap();
    assert_eq!(initial["count"], 3);
    assert_eq!(initial["agents"]["alice"], json!({"ip":"192.0.2.10"}));
    assert_eq!(initial["agents"]["bob"], json!({"ip":"192.0.2.10"}));
    assert!(initial["agents"].get("intruder").is_none());
    assert!(!initial.to_string().contains("socket"));

    let mut alice = UnixStream::connect(directory.join("alice.sock"))
        .await
        .unwrap();
    let mut bob = UnixStream::connect(directory.join("bob.sock"))
        .await
        .unwrap();
    for stream in [&mut alice, &mut bob] {
        let reply =
            keepalive_request(stream, "POST", "/api/test-context/current?agent=forged").await;
        // No JSON body was supplied. Reaching body validation proves that a
        // stale map no longer removes the accepted listener's authority.
        assert!(
            reply.starts_with(b"HTTP/1.1 400"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }
    let declaration = br#"{"context":"run=R;agent=bob;test=claimed","ttl":60}"#;
    let reply = send(
        directory,
        "POST",
        "/api/test-context/current?agent=bob",
        Some(TOKEN),
        declaration,
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        serde_json::from_slice::<Value>(body(&reply)).unwrap()["agent"],
        "alice"
    );
    let reply = send_as(
        directory,
        "bob",
        "GET",
        "/api/test-context/current?agent=alice",
        Some(TOKEN),
        b"",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        serde_json::from_slice::<Value>(body(&reply)).unwrap()["agent"],
        "bob"
    );

    // A listener with no usable owner cannot gain Alice's scope from a body,
    // query, header or the old map. Keep global reports bearer protected.
    for (method, path, content) in [
        (
            "POST",
            "/api/test-context/current?agent=alice",
            declaration.as_slice(),
        ),
        (
            "GET",
            "/api/flows/search?evidence_owner=alice",
            b"".as_slice(),
        ),
        (
            "GET",
            "/trace?request_id=req-00000000000000000000000000000000&agent=alice",
            b"".as_slice(),
        ),
        (
            "POST",
            "/gateway/request-access?agent=alice",
            br#"{"service":"demo","capability":"read","agent":"alice"}"#.as_slice(),
        ),
    ] {
        let reply = send_as(directory, "unknown", method, path, Some(TOKEN), content).await;
        assert!(
            reply.starts_with(b"HTTP/1.1 403"),
            "{method} {path}: {}",
            String::from_utf8_lossy(&reply)
        );
    }
    let rejected = send(directory, "GET", "/agents", None, b"").await;
    assert!(rejected.starts_with(b"HTTP/1.1 401"));
    let before = proxy.runtime.read().unwrap().agent_activity.clone();
    std::fs::write(&map, b"not-json").unwrap();
    proxy.reload(configuration.clone()).await.unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &before,
        &proxy.runtime.read().unwrap().agent_activity
    ));
    for (stream, agent) in [(&mut alice, "alice"), (&mut bob, "bob")] {
        let reply =
            keepalive_request(stream, "GET", "/api/test-context/current?agent=forged").await;
        assert!(reply.starts_with(b"HTTP/1.1 200"));
        assert_eq!(
            serde_json::from_slice::<Value>(body(&reply)).unwrap()["agent"],
            agent
        );
    }
    drop(alice);
    drop(bob);
    // FlowStore requires applied test context and ordinary proxy traffic.
    // Reach a real origin with contradictory context claims on both listeners.
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    for agent in ["alice", "bob", "unknown"] {
        let mut stream = UnixStream::connect(directory.join(format!("{agent}.sock")))
            .await
            .unwrap();
        stream.write_all(format!("GET http://{address}/owned-flow HTTP/1.1\r\nHost: {address}\r\nX-SafeYolo-Agent: alice\r\nX-Forwarded-For: 192.0.2.11\r\nX-SafeYolo-Test-Context: run=listener;agent=claimed;test=identity\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        timeout(LIMIT, stream.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        // The existing global allow also permits an ownerless request. Its
        // claimed agent must still gain neither scoped API access nor a row.
        let status = "200";
        assert!(
            reply.starts_with(format!("HTTP/1.1 {status}").as_bytes()),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }
    timeout(LIMIT, origin_task).await.unwrap().unwrap();
    let report = send(directory, "GET", "/agents", Some(TOKEN), b"").await;
    let report: Value = serde_json::from_slice(body(&report)).unwrap();
    for agent in ["alice", "bob"] {
        assert!(report["agents"][agent]["last_seen"].is_number());
        assert!(report["agents"][agent]["idle_seconds"].as_f64().unwrap() >= 0.);
    }
    assert!(report["agents"]["unknown"].get("last_seen").is_none());
    configuration
        .listeners
        .retain(|listener| listener.agent_id != "bob");
    proxy.reload(configuration).await.unwrap();
    assert!(
        UnixStream::connect(directory.join("bob.sock"))
            .await
            .is_err()
    );
    let report = send(directory, "GET", "/agents", Some(TOKEN), b"").await;
    let report: Value = serde_json::from_slice(body(&report)).unwrap();
    assert_eq!(report["count"], 2);
    assert!(report["agents"].get("bob").is_none());
    let rows = drained(&proxy, directory);
    assert!(
        rows.iter()
            .any(|row| row["event"] == "security.test_context_declared" && row["agent"] == "alice")
    );
    let unavailable: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "security.agent_identity_unavailable")
        .collect();
    assert_eq!(unavailable.len(), 5);
    assert!(unavailable.iter().all(|row| row.get("agent").is_none()));
    assert!(
        !rows
            .iter()
            .any(|row| row["event"] == "security.agent_identity_conflict"
                || row["event"] == "agent.discovered")
    );
    assert!(
        !std::fs::read_to_string(directory.join("audit.jsonl"))
            .unwrap()
            .contains(TOKEN)
    );
    proxy.shutdown().await;
    let database = rusqlite::Connection::open(directory.join("flows.sqlite3")).unwrap();
    for agent in ["alice", "bob"] {
        let count: i64 = database.query_row(
            "SELECT count(*) FROM flows WHERE evidence_owner=?1 AND agent_id=?1 AND trusted_transport_identity=?1 AND attribution_status='resolved'",
            [agent], |row| row.get(0),
        ).unwrap();
        assert!(count > 0, "no listener-owned stored flow for {agent}");
    }
    let invalid: i64 = database.query_row(
        "SELECT count(*) FROM flows WHERE evidence_owner IS NULL OR evidence_owner NOT IN ('alice','bob')",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(invalid, 0);
}
