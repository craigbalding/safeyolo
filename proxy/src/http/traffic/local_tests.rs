use crate::{Config, Proxy};
use serde_json::{Value, json};
use std::{io::Write, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const TOKEN: &str = "owned-local-traffic-fixture";

fn config(directory: &Path) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"test_context":{"target_hosts":["127.0.0.2"]}},
        })
        .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock"),"source_id":"192.0.2.10"}],
        "policy_file":policy,"data_dir":directory.join("data"),"readiness_file":directory.join("ready"),
        "event_log":directory.join("events"),"audit_log_path":directory.join("audit.jsonl"),
        "flow_store_enabled":false,"test_context_block":true,
        "circuit_breaker_enabled":false,"via_token":"owned-loop-marker",
    })).unwrap()
}

async fn send(directory: &Path, target: &str, method: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(directory.join("alice.sock"))
        .await
        .unwrap();
    let head = format!("{method} {target} HTTP/1.1\r\n{headers}\r\n");
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
    let start = reply
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    &reply[start..]
}
fn gzip(content: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(content).unwrap();
    encoder.finish().unwrap()
}
fn counters(proxy: &Proxy) -> Value {
    proxy
        .runtime
        .read()
        .unwrap()
        .request_logger
        .stats()
        .unwrap()
        .document()
        .json()
        .unwrap()
}
fn events(directory: &Path) -> Vec<Value> {
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        // Preserve all other producer events and their original order.
        .filter(|row: &Value| {
            !(row["addon"] == "memory-monitor"
                && matches!(
                    row["event"].as_str(),
                    Some("ops.startup" | "ops.memory.conn_closed")
                ))
        })
        .collect()
}

#[test]
fn local_api_and_validated_empty_denials_emit_source_hooks() {
    if std::env::var_os("SAFEYOLO_TRAFFIC_LOCAL_FIXTURE").is_some() {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(owned_local_child());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "http::traffic::local_tests::local_api_and_validated_empty_denials_emit_source_hooks",
            "--nocapture",
        ])
        .env("SAFEYOLO_TRAFFIC_LOCAL_FIXTURE", directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn owned_local_child() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("SAFEYOLO_TRAFFIC_LOCAL_FIXTURE").expect("private child fixture"),
    );
    let shield_peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let shield_port = shield_peer.local_addr().unwrap().port();
    let mut configuration = config(&directory);
    configuration.admin_shield_extra_ports = shield_port.to_string();
    let proxy = Proxy::start(configuration).await.unwrap();
    let admin_target = format!("http://127.0.0.1:{shield_port}/admin");
    let mut sizes = Vec::new();
    let reply = send(
        &directory,
        "http://_safeyolo.proxy.internal/health",
        "GET",
        &format!(
            "Host: displayed.invalid\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n"
        ),
        b"",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    sizes.push((0, body(&reply).len(), "displayed.invalid", "/health"));
    let plain = br#"{"context":"run=owned;agent=alice;test=local;role=tester"}"#;
    let encoded = gzip(plain);
    for nominated in [false, true] {
        let connection = if nominated {
            "close, Content-Encoding"
        } else {
            "close"
        };
        let reply = send(&directory, "http://_safeyolo.proxy.internal/api/test-context/current", "POST", &format!("Host: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: {connection}\r\n",encoded.len()), &encoded).await;
        assert!(
            reply.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        sizes.push((
            if nominated {
                encoded.len()
            } else {
                plain.len()
            },
            body(&reply).len(),
            "_safeyolo.proxy.internal",
            "/api/test-context/current",
        ));
    }
    let reply = send(
        &directory,
        "http://_safeyolo.proxy.internal/health",
        "GET",
        &format!(
            "Host: erased.invalid\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close, Host\r\n"
        ),
        b"",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    sizes.push((0, body(&reply).len(), "_safeyolo.proxy.internal", "/health"));
    assert_eq!(
        counters(&proxy),
        json!({"requests_total":4,"requests_quieted":0,"responses_total":0,"blocks_total":4})
    );
    proxy
        .runtime
        .read()
        .unwrap()
        .test_context
        .clear_declaration(
            &crate::test_context::TrustedIdentity::new("192.0.2.10", "alice").unwrap(),
        )
        .unwrap();
    // A head denial must not wait for the advertised but deliberately unsent body.
    let reply = send(&directory, "http://127.0.0.2/unsent", "POST", "Host: owned.invalid\r\nVia: 1.1 owned-loop-marker\r\nContent-Length: 3\r\nConnection: close\r\n", b"").await;
    assert!(reply.starts_with(b"HTTP/1.1 508"));
    assert_eq!(counters(&proxy)["requests_total"], 4);
    assert_eq!(counters(&proxy)["blocks_total"], 4);
    // Independent head EOM permits a genuinely empty local request hook.
    for (target, extra, expected, cause, reason) in [
        (
            "http://127.0.0.2/loop",
            "Via: 1.1 owned-loop-marker\r\n",
            508,
            "loop-guard",
            Some("proxy_loop"),
        ),
        ("http://127.0.0.2/context", "", 428, "test-context", None),
        (
            admin_target.as_str(),
            "",
            403,
            "admin-shield",
            Some("admin_port_access"),
        ),
    ] {
        let reply = send(
            &directory,
            target,
            "GET",
            &format!("Host: presented.invalid\r\nConnection: close\r\n{extra}"),
            b"",
        )
        .await;
        assert!(
            reply.starts_with(format!("HTTP/1.1 {expected}").as_bytes()),
            "{cause}: {}",
            String::from_utf8_lossy(
                &reply[..reply
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .unwrap_or(reply.len())]
            )
        );
        assert!(
            proxy
                .runtime
                .read()
                .unwrap()
                .audit
                .wait_for_drain(LIMIT)
                .unwrap()
        );
        let latest = events(&directory).pop().unwrap();
        assert_eq!(latest["details"]["blocked_by"], cause);
        assert_eq!(latest["details"]["block_reason"], json!(reason));
        assert_eq!(latest["details"]["size"], body(&reply).len());
    }
    assert_eq!(
        counters(&proxy),
        json!({"requests_total":7,"requests_quieted":0,"responses_total":0,"blocks_total":7})
    );
    assert_eq!(
        super::metrics_stats(&proxy.runtime.read().unwrap()),
        json!({
            "requests_total":7,"requests_success":0,"requests_blocked":7,
            "blocks_by_source":{"agent-api":4,"loop-guard":1,"test-context":1,"admin-shield":1},
            "domains_tracked":3
        })
    );
    proxy.shutdown().await;
    let rows = events(&directory);
    let context: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "security.test_context")
        .collect();
    assert_eq!(context.len(), 1);
    assert_eq!(context[0]["decision"], "deny");
    let declarations: Vec<_> = rows
        .iter()
        .filter(|row| row["event"] == "security.test_context_declared")
        .collect();
    assert_eq!(declarations.len(), 2);
    assert!(declarations.iter().all(|row| {
        row["request_id"]
            .as_str()
            .is_some_and(|request_id| request_id.starts_with("req-"))
    }));
    let rows: Vec<_> = rows.iter().filter(|row| row["kind"] == "traffic").collect();
    assert_eq!(rows.len(), 14);
    for (index, (request_size, response_size, host, path)) in sizes.into_iter().enumerate() {
        let request = &rows[index * 2];
        let response = &rows[index * 2 + 1];
        assert_eq!(request["event"], "traffic.request");
        assert_eq!(request["host"], host);
        assert_eq!(request["details"]["path"], path);
        assert_eq!(request["details"]["size"], request_size);
        assert_eq!(request["details"]["client"], "192.0.2.10");
        assert_eq!(request["details"]["attribution"]["evidence_owner"], "alice");
        assert_eq!(response["event"], "traffic.response");
        assert_eq!(response["details"]["size"], response_size);
        assert_eq!(response["details"]["blocked_by"], "agent-api");
        assert_eq!(response["request_id"], request["request_id"]);
        assert!(response["details"]["ms"].is_number());
    }
    assert!(!directory.join("alice.sock").exists());
    assert!(!directory.join("ready").exists());
}

#[tokio::test]
async fn circuit_request_exception_skips_later_request_hooks_but_allows_response() {
    for (invalid, explicit) in [(false, true), (true, true), (true, false)] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        config.circuit_breaker_enabled = true;
        config.flow_store_enabled = true;
        config.flow_store_db_path = directory.path().join("flows.sqlite3");
        std::fs::write(config.policy_file.as_ref().unwrap(), json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"test_context":{"target_hosts":["127.0.0.2"]},"circuit_breaker":{
                "failure_threshold":1,"half_open_max_requests":if invalid {json!("invalid")}else{json!(3)},
            }},
        }).to_string()).unwrap();
        let origin = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(
                !String::from_utf8_lossy(&request)
                    .to_ascii_lowercase()
                    .contains("x-safeyolo-test-context")
            );
            stream
                .write_all(
                    b"HTTP/1.1 500 Owned\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
                )
                .await
                .unwrap();
        });
        let proxy = Proxy::start(config).await.unwrap();
        {
            let runtime = proxy.runtime.read().unwrap();
            runtime.circuits.restore(&json!({"states":{"127.0.0.2":{
                "state":"half_open","failure_count":0,"success_count":0,"failure_streak":0,"half_open_requests":0,
            }}}),crate::circuit_runtime::now(),&mut ||0.5).unwrap();
        }
        let claim = if explicit {
            "X-SafeYolo-Test-Context: run=owned;agent=alice;test=order;role=tester\r\n"
        } else {
            ""
        };
        let reply = send(
            directory.path(),
            &format!("http://127.0.0.2:{port}/circuit-error"),
            "GET",
            &format!("Host: 127.0.0.2:{port}\r\nConnection: close\r\n{claim}"),
            b"",
        )
        .await;
        assert!(reply.starts_with(b"HTTP/1.1 500"));
        assert_eq!(body(&reply), b"body");
        timeout(LIMIT, peer).await.unwrap().unwrap();
        assert_eq!(
            counters(&proxy)["requests_total"],
            if invalid { 0 } else { 1 }
        );
        assert_eq!(counters(&proxy)["responses_total"], 1);
        assert_eq!(
            super::metrics_stats(&proxy.runtime.read().unwrap()),
            json!({
                "requests_total":if invalid { 0 } else { 1 },
                "requests_success":0,"requests_blocked":0,
                "blocks_by_source":{},"domains_tracked":1
            })
        );
        assert_eq!(
            proxy
                .runtime
                .read()
                .unwrap()
                .test_context
                .stats(crate::http::declaration_time())
                .unwrap()
                .checks_total,
            if invalid { 0 } else { 1 }
        );
        let recorder = proxy.runtime.read().unwrap().flow_recorder.stats();
        assert_eq!(recorder["skipped"], if invalid { 1 } else { 0 });
        assert_eq!(recorder["recorded"], if invalid { 0 } else { 1 });
        proxy.shutdown().await;
        let rows = events(directory.path());
        assert_eq!(rows.len(), if invalid { 3 } else { 6 });
        let transitions: Vec<_> = rows
            .iter()
            .filter(|row| row["event"] == "ops.circuit_breaker.reopen")
            .collect();
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0]["agent"], "alice");
        assert!(transitions[0]["request_id"].is_string());
        let contexts: Vec<_> = rows
            .iter()
            .filter(|row| row["event"] == "security.test_context")
            .collect();
        assert_eq!(contexts.len(), if invalid { 0 } else { 2 });
        if !invalid {
            assert_eq!(contexts[0]["details"]["phase"], "request");
            assert_eq!(contexts[1]["details"]["phase"], "response");
        }
        assert_eq!(rows.last().unwrap()["event"], "traffic.response");
        assert!(rows.last().unwrap()["request_id"].is_string());
    }
}

#[tokio::test]
async fn local_response_circuit_exception_skips_later_recorder_and_logger() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(directory.path());
    configuration.circuit_breaker_enabled = true;
    configuration.flow_store_enabled = true;
    configuration.flow_store_db_path = directory.path().join("flows.sqlite3");
    std::fs::write(
        configuration.policy_file.as_ref().unwrap(),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"deny"}],
            "addons":{"circuit_breaker":{"excluded_domains":[{}]}},
        })
        .to_string(),
    )
    .unwrap();
    let proxy = Proxy::start(configuration).await.unwrap();
    let reply = send(
        directory.path(),
        "http://127.0.0.2/denied",
        "GET",
        "Host: 127.0.0.2\r\nConnection: close\r\n",
        b"",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 403"));
    assert_eq!(
        counters(&proxy),
        json!({"requests_total":1,"requests_quieted":0,"responses_total":0,"blocks_total":0})
    );
    assert_eq!(
        proxy.runtime.read().unwrap().flow_recorder.stats()["skipped"],
        0
    );
    assert_eq!(
        super::metrics_stats(&proxy.runtime.read().unwrap()),
        json!({
            "requests_total":1,"requests_success":0,"requests_blocked":0,
            "blocks_by_source":{},"domains_tracked":1
        })
    );
    proxy.shutdown().await;
    let rows = events(directory.path());
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["event"], "ops.policy_reload");
    assert_eq!(rows[1]["event"], "security.network_guard");
    assert_eq!(rows[2]["event"], "traffic.request");
}
