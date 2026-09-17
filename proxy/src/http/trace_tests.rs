//! Owned HTTP/CONNECT exchanges and failed producer seams for request tracing.

use std::{path::Path, sync::Arc, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::timeout,
};

use super::{PolicyRequest, decide, publish_credential_trace};
use crate::{
    Config, ConnectionIdentity, Proxy, Runtime,
    credential_guard::{CredentialGuard, Options as CredentialOptions, Pdp as CredentialPdp},
    network_guard::Identity,
    policy::{Format, Policy},
    trace::{Settings, TraceStore},
};

const HOST: &str = "127.0.0.2";
const LIMIT: Duration = Duration::from_secs(5);
const CHILD: &str = "SAFEYOLO_TRACE_HTTP_FIXTURE";
const TOKEN: &str = "synthetic-trace-http-token";

fn config(directory: &Path, effect: &str) -> Config {
    std::fs::write(
        directory.join("policy.json"),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":effect}]})
            .to_string(),
    )
    .unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice", "source_id":"192.0.2.10", "socket_path":directory.join("alice.sock")},
            {"agent_id":"bob", "source_id":"192.0.2.11", "socket_path":directory.join("bob.sock")}],
        "policy_file":directory.join("policy.json"), "data_dir":directory.join("data"), "readiness_file":directory.join("ready"),
        "event_log":directory.join("events.jsonl"), "audit_log_path":directory.join("audit.jsonl"),
        "agent_map_file":directory.join("missing-agent-map.json"),
        "flow_store_enabled":false, "flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_breaker_enabled":false, "circuit_state_file":""
    })).unwrap()
}

async fn head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        bytes
    })
    .await
    .unwrap()
}

async fn remainder(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut bytes = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

async fn exchange(directory: &Path, agent: &str, request: &str) -> Vec<u8> {
    let mut stream = UnixStream::connect(directory.join(format!("{agent}.sock")))
        .await
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    remainder(&mut stream).await
}

fn request_id(response: &[u8]) -> String {
    String::from_utf8_lossy(response)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-safeyolo-request-id")
                .then(|| value.trim().to_owned())
        })
        .unwrap()
}

fn body(response: &[u8]) -> &[u8] {
    &response[response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4..]
}

async fn trace(directory: &Path, agent: &str, request_id: &str) -> (u16, Value) {
    let response = exchange(directory, agent, &format!(
        "GET http://_safeyolo.proxy.internal/trace?request_id={request_id}&agent=alice HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nX-SafeYolo-Agent: alice\r\nConnection: close\r\n\r\n"
    )).await;
    let status = std::str::from_utf8(&response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, serde_json::from_slice(body(&response)).unwrap())
}

async fn origin() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((HOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (
        port,
        tokio::spawn(async move {
            let (mut stream, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            let request = head(&mut stream).await;
            let headers = String::from_utf8_lossy(&request).to_ascii_lowercase();
            for internal in ["x-safeyolo-trace", "x-safeyolo-request-id"] {
                assert!(!headers.contains(internal), "{internal}");
            }
            stream.write_all(b"HTTP/1.1 200 Owned\r\nContent-Length: 10\r\nConnection: close\r\n\r\nowned-body").await.unwrap();
        }),
    )
}

async fn fetch(directory: &Path, port: u16, traced: bool) -> Vec<u8> {
    let marker = if traced {
        "X-SafeYolo-Trace: 0\r\n"
    } else {
        ""
    };
    exchange(directory, "alice", &format!(
        "GET http://{HOST}:{port}/owned?trace-secret-query HTTP/1.1\r\nHost: {HOST}:{port}\r\n{marker}X-SafeYolo-Agent: forged\r\nX-SafeYolo-Request-Id: forged-id\r\nConnection: close\r\n\r\n"
    )).await
}

fn steps(report: &Value) -> Vec<Value> {
    report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            let bypass = step["state"] == "bypassed";
            assert_eq!(step.get("duration_us").is_some(), !bypass);
            json!([
                step["addon"],
                step["hook"],
                step["state"],
                step.get("outcome").or_else(|| step.get("reason")).unwrap()
            ])
        })
        .collect()
}

fn ordinary_step(report: &Value, outcome: &str) {
    assert_eq!(report["agent_id"], "alice");
    let mut expected = vec![json!(["network-guard", "request", "evaluated", outcome])];
    if outcome != "blocked" {
        expected.extend([
            json!(["circuit-breaker", "request", "bypassed", "addon_disabled"]),
            json!(["credential-guard", "request", "evaluated", "no_detection"]),
            json!(["test-context", "request", "evaluated", "not_target_host"]),
        ]);
    }
    expected.extend([
        json!(["circuit-breaker", "response", "bypassed", "addon_disabled"]),
        json!(["test-context", "response", "evaluated", "not_applicable"]),
    ]);
    assert_eq!(steps(report), expected);
    let step = &report["steps"][0];
    assert_eq!(step["addon"], "network-guard");
    assert_eq!(step["hook"], "request");
    assert_eq!(step["outcome"], outcome);
    assert_eq!(step["host"], HOST);
    assert!(step["duration_us"].as_u64().is_some());
    let expected_not_loaded = if outcome == "blocked" {
        json!([
            {"addon":"service-gateway", "state":"not_loaded"},
            {"addon":"credential-guard", "state":"not_loaded"},
            {"addon":"pattern-scanner", "state":"not_loaded"}
        ])
    } else {
        json!([
            {"addon":"service-gateway", "state":"not_loaded"},
            {"addon":"pattern-scanner", "state":"not_loaded"}
        ])
    };
    assert_eq!(report["not_loaded"], expected_not_loaded);
    for absent in ["trace-secret-query", "forged", "owned-body", TOKEN] {
        assert!(!report.to_string().contains(absent));
    }
}

fn trace_guard_policy(effect: &str, enabled: bool) -> Policy {
    Policy::parse(
        &json!({
            "permissions":[
                {"action":"credential:use","resource":"127.0.0.1/*","effect":effect},
                {"action":"network:request","resource":"*","effect":"allow"}
            ],
            "credential_rules":[{
                "name":"trace-rule",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }],
            "addons":{"credential_guard":{"enabled":enabled,"settings":{"use_default_credential_rules":false}}}
        })
        .to_string(),
        Format::Json,
    )
    .unwrap()
}

fn trace_guard() -> CredentialGuard {
    let guard = CredentialGuard::new(b"trace-hmac-key");
    guard
        .load_sensor_config(&json!({
            "addons":{"credential_guard":{"use_default_credential_rules":false}},
            "credential_rules":[{
                "name":"trace-rule",
                "patterns":["key-[a-z]+"],
                "allowed_hosts":["127.0.0.1"],
                "header_names":["authorization"]
            }]
        }))
        .unwrap();
    guard
}

fn append_guard_trace(
    store: &Arc<TraceStore>,
    guard: &CredentialGuard,
    policy: &Policy,
    request_id: &str,
    identity: Identity<'_>,
    prior_response: bool,
    block: bool,
) -> Value {
    let agent_id = match identity {
        Identity::Resolved(agent) => agent.to_owned(),
        _ => "unknown".to_owned(),
    };
    let identity_for_trace = ConnectionIdentity {
        agent_id,
        connection_id: format!("trace-connection-{request_id}"),
        source_id: None,
        reconciled: None,
    };
    let request = Arc::new(crate::request_trace::RequestTrace::new(
        store.clone(),
        &identity_for_trace,
        request_id,
        "GET",
        "127.0.0.1",
        443,
    ));
    request.enable(true);
    let hook = request.hook("credential-guard", "request");
    let fields = [(
        b"Authorization".as_slice(),
        b"Bearer key-synthetic".as_slice(),
    )];
    let outcome = guard
        .enforce_ordered(
            CredentialPdp::Ready(policy),
            identity,
            "127.0.0.1",
            443,
            "GET",
            "/trace",
            "https",
            Some(request_id),
            &identity_for_trace.connection_id,
            prior_response,
            fields,
            CredentialOptions { block },
            1000.,
        )
        .unwrap();
    publish_credential_trace(hook.as_ref(), &outcome.trace);
    store
        .get(request_id, Some(&identity_for_trace.agent_id), 1000.)
        .unwrap()
        .unwrap()
}

#[test]
fn credential_trace_replays_each_intent_on_one_timer_and_keeps_bypasses_untimed() {
    let store = Arc::new(TraceStore::new(Settings::default()));
    let guard = trace_guard();

    let allowed = append_guard_trace(
        &store,
        &guard,
        &trace_guard_policy("allow", true),
        "trace-allowed",
        Identity::Resolved("alice"),
        false,
        true,
    );
    assert_eq!(allowed["steps"].as_array().unwrap().len(), 1);
    assert_eq!(allowed["steps"][0]["state"], "evaluated");
    assert_eq!(allowed["steps"][0]["outcome"], "detected");
    assert_eq!(allowed["steps"][0]["details"]["detection_count"], 1);
    assert!(allowed["steps"][0]["duration_us"].as_u64().is_some());

    let warned = append_guard_trace(
        &store,
        &guard,
        &trace_guard_policy("deny", true),
        "trace-warned",
        Identity::Resolved("alice"),
        false,
        false,
    );
    assert_eq!(
        warned["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["outcome"].clone())
            .collect::<Vec<_>>(),
        vec![json!("detected"), json!("warned")]
    );
    assert_eq!(warned["steps"][0]["details"]["detection_count"], 1);
    assert!(warned["steps"][0]["duration_us"].as_u64().is_some());
    assert!(warned["steps"][1]["duration_us"].as_u64().is_some());

    let bypassed = append_guard_trace(
        &store,
        &guard,
        &trace_guard_policy("deny", false),
        "trace-bypassed",
        Identity::Resolved("alice"),
        false,
        true,
    );
    assert_eq!(bypassed["steps"][0]["state"], "bypassed");
    assert_eq!(bypassed["steps"][0]["reason"], "policy_disabled");
    assert!(bypassed["steps"][0].get("duration_us").is_none());

    let prior = append_guard_trace(
        &store,
        &guard,
        &trace_guard_policy("deny", true),
        "trace-prior",
        Identity::Resolved("alice"),
        true,
        true,
    );
    assert_eq!(prior["steps"][0]["state"], "bypassed");
    assert_eq!(prior["steps"][0]["reason"], "prior_response");
    assert!(prior["steps"][0].get("duration_us").is_none());

    let conflict = append_guard_trace(
        &store,
        &guard,
        &trace_guard_policy("allow", true),
        "trace-conflict",
        Identity::Conflict,
        false,
        true,
    );
    assert_eq!(conflict["steps"][0]["state"], "evaluated");
    assert_eq!(conflict["steps"][0]["outcome"], "blocked");
    assert_eq!(conflict["steps"][0]["details"]["status"], 403);
    assert!(conflict["steps"][0]["duration_us"].as_u64().is_some());
}

#[test]
fn credential_trace_store_failure_does_not_change_guard_outcome() {
    let store = Arc::new(TraceStore::new(Settings {
        ttl_s: json!("owned-invalid-ttl").into(),
        ..Settings::default()
    }));
    let guard = trace_guard();
    let policy = trace_guard_policy("allow", true);
    let identity = ConnectionIdentity {
        agent_id: "alice".into(),
        connection_id: "trace-observation-failure".into(),
        source_id: None,
        reconciled: None,
    };
    let request = Arc::new(crate::request_trace::RequestTrace::new(
        store,
        &identity,
        "trace-observation-failure",
        "GET",
        "127.0.0.1",
        443,
    ));
    request.enable(true);
    let hook = request.hook("credential-guard", "request");
    let outcome = guard
        .enforce_ordered(
            CredentialPdp::Ready(&policy),
            Identity::Resolved("alice"),
            "127.0.0.1",
            443,
            "GET",
            "/trace",
            "https",
            Some("trace-observation-failure"),
            &identity.connection_id,
            false,
            [(
                b"Authorization".as_slice(),
                b"Bearer key-synthetic".as_slice(),
            )],
            CredentialOptions { block: true },
            1000.,
        )
        .unwrap();
    publish_credential_trace(hook.as_ref(), &outcome.trace);
    assert_eq!(outcome.kind, crate::credential_guard::OutcomeKind::Allowed);
    assert_eq!(guard.stats().unwrap().violations_total, 0);
}

#[test]
fn traced_http_and_connect_remain_owned_across_reload() {
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(owned_workflow(Path::new(&directory)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "http::trace_tests::traced_http_and_connect_remain_owned_across_reload",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path());
    for setting in [
        "TTL_S",
        "GLOBAL_MAX",
        "PER_AGENT_MAX",
        "STEPS_MAX",
        "DETAILS_MAX_BYTES",
    ] {
        command.env_remove(format!("SAFEYOLO_TRACE_{setting}"));
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    for removed in ["alice.sock", "bob.sock", "ready", "unused.sqlite3"] {
        assert!(!directory.path().join(removed).exists(), "{removed}");
    }
}

async fn owned_workflow(directory: &Path) {
    let mut configured = config(directory, "allow");
    let mut proxy = Proxy::start(configured.clone()).await.unwrap();
    let store = proxy.runtime.read().unwrap().traces.clone();
    let (port, peer) = origin().await;
    let response = fetch(directory, port, true).await;
    assert!(response.starts_with(b"HTTP/1.1 200") && response.ends_with(b"owned-body"));
    timeout(LIMIT, peer).await.unwrap().unwrap();
    let rid = request_id(&response);
    let (status, first) = trace(directory, "alice", &rid).await;
    assert_eq!(status, 200);
    ordinary_step(&first, "allowed");
    assert_eq!(trace(directory, "bob", &rid).await.0, 404);
    let (port, peer) = origin().await;
    let untraced = fetch(directory, port, false).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    assert_eq!(
        trace(directory, "alice", &request_id(&untraced)).await.0,
        404
    );

    // A fresh native snapshot keeps the old store and its startup settings.
    proxy.reload(configured.clone()).await.unwrap();
    assert!(Arc::ptr_eq(&store, &proxy.runtime.read().unwrap().traces));
    assert_eq!(trace(directory, "alice", &rid).await, (200, first));

    let (port, peer) = origin().await;
    let mut client = UnixStream::connect(directory.join("alice.sock"))
        .await
        .unwrap();
    client.write_all(format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}:{port}\r\nX-SafeYolo-Trace: 1\r\n\r\n").as_bytes()).await.unwrap();
    let connect = head(&mut client).await;
    assert!(connect.starts_with(b"HTTP/1.1 200"));
    client.write_all(format!("GET /inner HTTP/1.1\r\nHost: {HOST}:{port}\r\nX-SafeYolo-Trace: 1\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let inner = remainder(&mut client).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    assert!(inner.starts_with(b"HTTP/1.1 200"));
    let (connect_status, outer) = trace(directory, "alice", &request_id(&connect)).await;
    let (inner_status, inside) = trace(directory, "alice", &request_id(&inner)).await;
    assert_eq!((connect_status, inner_status), (200, 200));
    assert_ne!(outer["request_id"], inside["request_id"]);
    assert_eq!(
        outer["steps"][0]["connection_id"],
        inside["steps"][0]["connection_id"]
    );
    assert_eq!(outer["steps"][0]["hook"], "http_connect");
    assert_eq!(outer["not_loaded"], json!([]));
    ordinary_step(&inside, "allowed");

    // An owned, uncontacted destination proves denial creates no egress.
    configured = config(directory, "deny");
    proxy.reload(configured.clone()).await.unwrap();
    let listener = TcpListener::bind((HOST, 0)).await.unwrap();
    let denied = fetch(directory, listener.local_addr().unwrap().port(), true).await;
    assert!(denied.starts_with(b"HTTP/1.1 403"));
    let (status, report) = trace(directory, "alice", &request_id(&denied)).await;
    assert_eq!(status, 200);
    ordinary_step(&report, "blocked");
    assert_eq!(report["steps"][0]["details"], json!({"status":403}));
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    configured.network_guard_block = false;
    proxy.reload(configured.clone()).await.unwrap();
    let (port, peer) = origin().await;
    let warned = fetch(directory, port, true).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    assert!(warned.starts_with(b"HTTP/1.1 200"));
    ordinary_step(
        &trace(directory, "alice", &request_id(&warned)).await.1,
        "warned",
    );
    configured.network_guard_enabled = false;
    proxy.reload(configured).await.unwrap();
    let (port, peer) = origin().await;
    let bypassed = fetch(directory, port, true).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    let report = trace(directory, "alice", &request_id(&bypassed)).await.1;
    assert_eq!(report["steps"][0]["state"], "bypassed");
    assert_eq!(report["steps"][0]["reason"], "addon_disabled");
    assert!(report["steps"][0].get("duration_us").is_none());
    // A present but empty marker remains opted out after source hygiene.
    let (port, peer) = origin().await;
    let empty = exchange(directory, "alice", &format!(
        "GET http://{HOST}:{port}/empty HTTP/1.1\r\nHost: {HOST}:{port}\r\nX-SafeYolo-Trace:\r\nConnection: close\r\n\r\n"
    )).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    assert_eq!(trace(directory, "alice", &request_id(&empty)).await.0, 404);

    // Context application and its response audit use the same request owner.
    configured = config(directory, "allow");
    std::fs::write(
        directory.join("policy.json"),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"test_context":{"target_hosts":[HOST]}},
        })
        .to_string(),
    )
    .unwrap();
    configured.test_context_block = true;
    proxy.reload(configured).await.unwrap();
    let (port, peer) = origin().await;
    let applied = exchange(directory, "alice", &format!(
        "GET http://{HOST}:{port}/context HTTP/1.1\r\nHost: {HOST}:{port}\r\nX-SafeYolo-Trace: 1\r\nX-SafeYolo-Test-Context: run=owned;agent=alice;test=wire\r\nConnection: close\r\n\r\n"
    )).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    assert!(applied.starts_with(b"HTTP/1.1 200"));
    let applied = trace(directory, "alice", &request_id(&applied)).await.1;
    assert_eq!(
        steps(&applied),
        vec![
            json!(["network-guard", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "request", "bypassed", "addon_disabled"]),
            json!(["credential-guard", "request", "evaluated", "no_detection"]),
            json!(["test-context", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "response", "bypassed", "addon_disabled"]),
            json!(["test-context", "response", "evaluated", "response_recorded"]),
        ]
    );
    assert_eq!(
        applied["steps"][3]["details"],
        json!({"context_source":"header"})
    );
    assert_eq!(applied["steps"][5]["details"], json!({"status_code":200}));
    let denied = fetch(directory, port, true).await;
    assert!(denied.starts_with(b"HTTP/1.1 428"));
    let denied = trace(directory, "alice", &request_id(&denied)).await.1;
    assert_eq!(
        steps(&denied),
        vec![
            json!(["network-guard", "request", "evaluated", "allowed"]),
            json!(["circuit-breaker", "request", "bypassed", "addon_disabled"]),
            json!(["credential-guard", "request", "evaluated", "no_detection"]),
            json!(["test-context", "request", "evaluated", "blocked"]),
            json!(["circuit-breaker", "response", "bypassed", "addon_disabled"]),
            json!(["test-context", "response", "evaluated", "not_applicable"]),
        ]
    );
    assert_eq!(denied["steps"][3]["details"], json!({"status":428}));

    let local = exchange(directory, "alice", &format!(
        "GET http://_safeyolo.proxy.internal/health HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nX-SafeYolo-Trace: 1\r\nConnection: close\r\n\r\n"
    )).await;
    assert!(local.starts_with(b"HTTP/1.1 200"));
    let local = trace(directory, "alice", &request_id(&local)).await.1;
    assert_eq!(
        steps(&local),
        vec![
            json!(["circuit-breaker", "response", "bypassed", "addon_disabled"]),
            json!(["test-context", "response", "evaluated", "not_applicable"]),
        ]
    );
    assert!(!local.to_string().contains(TOKEN));
    proxy.shutdown().await;
}

#[tokio::test]
async fn failed_network_audit_retains_only_reached_trace_steps() {
    for (method, effect, states) in [
        ("CONNECT", "allow", vec!["evaluated", "error"]),
        ("GET", "deny", vec!["error"]),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(
            config(directory.path(), effect),
            "owned",
            Arc::new(tokio::sync::Mutex::new(())),
            None,
            None,
        )
        .unwrap();
        runtime.audit.poison_for_test();
        let identity = ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: "owned-connection".into(),
            source_id: None,
            reconciled: None,
        };
        let request = PolicyRequest {
            agent_id: "alice",
            connection_id: &identity.connection_id,
            request_id: "req-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            method,
            scheme: "http",
            host: HOST,
            port: 12345,
            path: "/",
            header_names: vec![],
            body_present: false,
            trace_requested: true,
        };
        let trace = Arc::new(crate::request_trace::RequestTrace::new(
            runtime.traces.clone(),
            &identity,
            request.request_id,
            request.method,
            request.host,
            request.port,
        ));
        trace.enable(true);
        assert!(
            decide(
                &runtime,
                &identity,
                &request,
                Some(&trace),
                &crate::connection_tasks::ConnectionTasks::new(
                    tokio::sync::watch::channel(false).1
                )
            )
            .await
            .is_err()
        );
        let report = runtime
            .traces
            .get(
                request.request_id,
                Some("alice"),
                crate::circuit_runtime::now(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            report["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|step| step["state"].as_str().unwrap())
                .collect::<Vec<_>>(),
            states
        );
        assert_eq!(
            report["steps"].as_array().unwrap().last().unwrap()["reason"],
            "GuardError"
        );
        assert!(!report.to_string().contains("poison"));
    }
}

#[tokio::test]
async fn trace_store_failure_does_not_change_guard_decision_or_counts() {
    for effect in ["allow", "deny"] {
        let directory = tempfile::tempdir().unwrap();
        let mut runtime = Runtime::new(
            config(directory.path(), effect),
            "owned",
            Arc::new(tokio::sync::Mutex::new(())),
            None,
            None,
        )
        .unwrap();
        runtime.traces = Arc::new(TraceStore::new(Settings {
            ttl_s: json!("owned-invalid-ttl").into(),
            ..Settings::default()
        }));
        let identity = ConnectionIdentity {
            agent_id: "alice".into(),
            connection_id: "owned-connection".into(),
            source_id: None,
            reconciled: None,
        };
        let request = PolicyRequest {
            agent_id: "alice",
            connection_id: &identity.connection_id,
            request_id: "req-cccccccccccccccccccccccccccccccc",
            method: "GET",
            scheme: "http",
            host: HOST,
            port: 12345,
            path: "/",
            header_names: vec![],
            body_present: false,
            trace_requested: true,
        };
        let trace = Arc::new(crate::request_trace::RequestTrace::new(
            runtime.traces.clone(),
            &identity,
            request.request_id,
            request.method,
            request.host,
            request.port,
        ));
        trace.enable(true);
        let outcome = decide(
            &runtime,
            &identity,
            &request,
            Some(&trace),
            &crate::connection_tasks::ConnectionTasks::new(tokio::sync::watch::channel(false).1),
        )
        .await
        .unwrap();
        assert_eq!(outcome.allow, effect == "allow");
        assert_eq!(outcome.status, (effect == "deny").then_some(403));
        assert_eq!(runtime.network_guard.stats().unwrap().checks, 1);
        assert_eq!(
            runtime.network_guard.stats().unwrap().allowed,
            u64::from(effect == "allow")
        );
        assert_eq!(
            runtime.network_guard.stats().unwrap().blocked,
            u64::from(effect == "deny")
        );
    }
}
