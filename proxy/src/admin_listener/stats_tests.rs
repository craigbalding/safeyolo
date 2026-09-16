//! Owned operator requests exercise shared statistics owners and read effects.

use crate::{Config, Proxy, Runtime, test_context};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);
const TOKEN: &str = "owned-operator-stats-fixture";

fn config(directory: &Path) -> Config {
    std::fs::write(directory.join("token"), TOKEN).unwrap();
    std::fs::write(directory.join("policy.json"),
        r#"{"permissions":[{"action":"network:request","resource":"*","effect":"deny"}],"addons":{"test_context":{"target_hosts":["new.invalid"]}}}"#).unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")}],
        "policy_file":directory.join("policy.json"),"readiness_file":directory.join("ready"),
        "admin_port":0,"admin_api_token_file":directory.join("token"),
        "audit_log_path":directory.join("audit.jsonl"),"event_log":directory.join("events.jsonl"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_state_file":""
    }))
    .unwrap()
}

fn seed(runtime: &Runtime) {
    for host in ["first.invalid", "second.invalid"] {
        runtime.circuits.force_open(host, 0.).unwrap();
    }
    runtime
        .test_context
        .configure(
            Some(&json!({
                "policy_hash":"owned-prior-config",
                "addons":{"test_context":{"target_hosts":["one.invalid","two.invalid"]}}
            })),
            test_context::Options::default(),
        )
        .unwrap();
    runtime
        .test_context
        .set_declaration(
            &test_context::TrustedIdentity::new("owned-source", "alice").unwrap(),
            test_context::Context::parse("run=stats;agent=alice").unwrap(),
            Some(&json!(1)),
            -1000.,
        )
        .unwrap();
    runtime
        .test_context
        .set_declaration(
            &test_context::TrustedIdentity::new("owned-live-source", "alice").unwrap(),
            test_context::Context::parse("run=live;agent=alice").unwrap(),
            Some(&json!(300)),
            crate::http::declaration_time(),
        )
        .unwrap();
}

async fn exchange(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &[u8],
) -> (u16, Vec<u8>) {
    timeout(WAIT, async {
        stream.write_all(request).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        let head = std::str::from_utf8(&bytes[..split]).unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, bytes[split + 4..].to_vec())
    })
    .await
    .unwrap()
}

async fn stats(runtime: &Runtime, authorized: bool) -> (u16, Value) {
    let auth = if authorized {
        format!("Authorization: Bearer {TOKEN}\r\n")
    } else {
        String::new()
    };
    let request =
        format!("GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\r\n");
    let (status, body) = exchange(
        TcpStream::connect(runtime.admin_address.unwrap())
            .await
            .unwrap(),
        request.as_bytes(),
    )
    .await;
    (status, serde_json::from_slice(&body).unwrap())
}

fn states(runtime: &Runtime) -> Value {
    runtime
        .circuits
        .snapshot(crate::circuit_runtime::now())
        .unwrap()["states"]
        .clone()
}

fn records(directory: &Path) -> Vec<Value> {
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn authenticated_stats_share_counters_and_reached_read_effects_across_reload() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(directory.path());
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    seed(&runtime);
    let before = states(&runtime);
    assert_eq!(
        runtime.test_context.stats(-1000.).unwrap().declared_active,
        2
    );
    let (status, denied) = stats(&runtime, false).await;
    assert_eq!(status, 401);
    assert!(denied.get("network-guard").is_none());
    assert_eq!(states(&runtime), before);
    assert_eq!(
        runtime.test_context.stats(-1000.).unwrap().declared_active,
        2
    );

    let request = b"GET http://127.0.0.2:1/owned-denial HTTP/1.1\r\nHost: 127.0.0.2:1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (status, _) = exchange(
        UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap(),
        request,
    )
    .await;
    assert_eq!(status, 403);
    let evaluations =
        runtime.policy.as_ref().unwrap().engine_stats().unwrap()["evaluations"].clone();
    let (status, first) = stats(&runtime, true).await;
    assert_eq!(status, 200);
    assert_eq!(
        first
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "proxy",
            "memory-monitor",
            "service-discovery",
            "policy-engine",
            "network-guard",
            "circuit-breaker",
            "test-context",
            "flow-recorder",
            "request-logger",
            "metrics"
        ]
    );
    assert_eq!(
        first["network-guard"],
        json!({"enabled":true,"checks":1,"allowed":0,"blocked":1,"warned":0,"rate_limited":0})
    );
    assert_eq!(first["test-context"]["target_hosts"], 2);
    assert_eq!(first["test-context"]["declared_active"], 1);
    assert_eq!(
        runtime.test_context.stats(-1000.).unwrap().declared_active,
        1
    );
    assert_eq!(first["circuit-breaker"]["half_opens_total"], 2);
    for host in ["first.invalid", "second.invalid"] {
        assert_eq!(
            first["circuit-breaker"]["domains"][host]["state"],
            "half_open"
        );
    }
    assert_eq!(first["request-logger"]["requests_total"], 1);
    assert_eq!(first["request-logger"]["responses_total"], 0);
    assert_eq!(first["request-logger"]["blocks_total"], 1);
    assert_eq!(
        first["metrics"],
        json!({"requests_total":1,"requests_success":0,"requests_blocked":1,
            "blocks_by_source":{"network-guard":1},"domains_tracked":1})
    );
    assert_eq!(first["flow-recorder"]["skipped"], 1);
    assert_eq!(
        first["policy-engine"]["engine_stats"]["evaluations"],
        evaluations
    );
    assert_eq!(
        runtime.policy.as_ref().unwrap().engine_stats().unwrap()["evaluations"],
        evaluations
    );
    assert!(runtime.audit.wait_for_drain(WAIT).unwrap());
    let initial = records(directory.path());
    let transitions: Vec<_> = initial
        .iter()
        .filter(|row| row["event"] == "ops.circuit_breaker.half_open")
        .collect();
    assert_eq!(transitions.len(), 2);
    for row in transitions {
        assert!(row.get("request_id").is_none() && row.get("agent").is_none());
    }

    configuration.network_guard_enabled = false;
    configuration.circuit_breaker_enabled = false;
    proxy.reload(configuration).await.unwrap();
    let current = proxy.runtime.read().unwrap().clone();
    let (status, second) = stats(&current, true).await;
    assert_eq!(status, 200);
    assert_eq!(second["network-guard"]["enabled"], false);
    assert_eq!(second["network-guard"]["checks"], 1);
    assert_eq!(second["circuit-breaker"]["enabled"], false);
    assert_eq!(second["circuit-breaker"]["half_opens_total"], 2);
    assert_eq!(
        second["test-context"]["target_hosts"], 2,
        "stats must not refresh request-stage targets"
    );
    assert_eq!(second["request-logger"], first["request-logger"]);
    assert_eq!(second["metrics"], first["metrics"]);
    assert!(std::sync::Arc::ptr_eq(&runtime.metrics, &current.metrics));
    assert!(current.audit.wait_for_drain(WAIT).unwrap());
    assert_eq!(records(directory.path()), initial);
    proxy.shutdown().await;
    assert!(!directory.path().join("alice.sock").exists());
    assert!(!directory.path().join("ready").exists());
    assert!(
        !std::fs::read_to_string(directory.path().join("audit.jsonl"))
            .unwrap()
            .contains(TOKEN)
    );
    assert!(
        !std::fs::read_to_string(directory.path().join("events.jsonl"))
            .unwrap()
            .contains(TOKEN)
    );
    for line in std::fs::read_to_string(directory.path().join("events.jsonl"))
        .unwrap()
        .lines()
    {
        let event: Value = serde_json::from_str(line).unwrap();
        assert_ne!(event["event"], "proxy.egress");
    }
}

#[tokio::test]
async fn circuit_audit_failure_preserves_partial_state_and_later_stats() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path())).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    seed(&runtime);
    assert!(runtime.audit.wait_for_drain(WAIT).unwrap());
    let startup = records(directory.path());
    assert_eq!(startup.len(), 1);
    assert_eq!(startup[0]["event"], "ops.startup");
    assert_eq!(startup[0]["addon"], "memory-monitor");
    runtime.audit.poison_for_test();
    let (status, report) = stats(&runtime, true).await;
    assert_eq!(status, 200);
    assert!(
        report["circuit-breaker"]["error"]
            .as_str()
            .unwrap()
            .starts_with("RuntimeError:")
    );
    assert_eq!(states(&runtime)["first.invalid"]["state"], "half_open");
    assert_eq!(states(&runtime)["second.invalid"]["state"], "open");
    assert_eq!(report["test-context"]["declared_active"], 1);
    assert_eq!(
        runtime.test_context.stats(-1000.).unwrap().declared_active,
        1
    );
    assert_eq!(
        report["flow-recorder"],
        json!({"recorded":0,"errors":0,"skipped":0})
    );
    assert_eq!(report["request-logger"]["requests_total"], 0);
    assert_eq!(report["network-guard"]["checks"], 0);
    assert_eq!(records(directory.path()), startup);
    proxy.shutdown().await;
    assert!(!directory.path().join("alice.sock").exists());
}
