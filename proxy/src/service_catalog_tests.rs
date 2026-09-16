//! Owned Runtime publication and authenticated H1 catalog reads. No injection.

mod diagnostics;
mod metadata;
mod policy_events;
mod policy_watch;
mod reload;

use super::*;
use crate::{
    contracts::ContractRequest,
    policy::{Effect, NetworkRequest},
    services::{GatewayDecision, GatewayRequest, RouteMode, TrustedIdentity},
};
use std::{future::Future, process::Command};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

const CHILD: &str = "SAFEYOLO_SERVICE_CATALOG_TEST_CHILD";
const TOKEN: &str = "synthetic-owned-catalog-api-auth";
const LIMIT: Duration = Duration::from_secs(5);

fn config(directory: &Path) -> Config {
    serde_json::from_value(json!({
        "listeners":[
            {"agent_id":"alice","source_id":"192.0.2.10","socket_path":directory.join("alice.sock")},
            {"agent_id":"bob","source_id":"192.0.2.11","socket_path":directory.join("bob.sock")}
        ],
        "policy_file":directory.join("policy.json"),
        "readiness_file":directory.join("ready"),
        "event_log":directory.join("events.jsonl"),
        "audit_log_path":directory.join("audit.jsonl"),
        "flow_store_db_path":directory.join("flows.sqlite3"),
        "flow_store_enabled":true,"circuit_state_file":""
    })).unwrap()
}

#[test]
fn catalog_configuration_requires_a_pair_and_native_policy() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path());
    settings.validate().unwrap();
    settings.gateway_builtin_services_dir = Some(directory.path().join("builtin"));
    assert_eq!(
        settings.validate().unwrap_err().to_string(),
        "configure both gateway_builtin_services_dir and gateway_services_dir"
    );
    settings.gateway_services_dir = settings.gateway_builtin_services_dir.take();
    assert_eq!(
        settings.validate().unwrap_err().to_string(),
        "configure both gateway_builtin_services_dir and gateway_services_dir"
    );
    settings.gateway_builtin_services_dir = Some(directory.path().join("builtin"));
    settings.validate().unwrap();
    settings.policy_file = None;
    settings.temporary_policy_socket = Some(directory.path().join("unused-adapter.sock"));
    assert_eq!(
        settings.validate().unwrap_err().to_string(),
        "service catalog requires native policy_file"
    );
    settings.gateway_builtin_services_dir = None;
    settings.gateway_services_dir = None;
    settings.validate().unwrap();
}

// Authentication reads its environment only in a selected unit-test child.
// This keeps parallel tests and operational environment/token paths untouched.
fn owned_child(test: &str, workflow: impl Future<Output = ()>) {
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(workflow);
        std::fs::write(Path::new(&directory).join("completed"), b"complete").unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path())
        .env(
            "SAFEYOLO_LOG_PATH",
            directory.path().join("unused-default-audit"),
        )
        .output()
        .unwrap();
    // Never print a leaked generated token as part of a failing test receipt.
    for output in [&result.stdout, &result.stderr] {
        assert!(
            !output.windows(4).any(|part| part == b"sgw_"),
            "catalog token reached child diagnostics"
        );
        assert!(
            !output
                .windows(TOKEN.len())
                .any(|part| part == TOKEN.as_bytes()),
            "synthetic API auth reached child diagnostics"
        );
    }
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(directory.path().join("completed")).unwrap(),
        b"complete"
    );
}

#[test]
fn initial_reader_is_empty_without_a_catalog_in_both_policy_modes() {
    owned_child(
        "service_catalog_tests::initial_reader_is_empty_without_a_catalog_in_both_policy_modes",
        empty_reader_workflow(),
    );
}

async fn empty_reader_workflow() {
    for native in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = config(directory.path());
        // Canonical tokens can exist without an accepted registry. The read
        // owner must not mistake those policy data for active catalog bindings.
        let policy = json!({"permissions":[],"gateway":{
            "host_map":{"catalog.invalid":"demo"},
            "token_map":{"sgw_owned_canonical_token":{
                "agent":"alice","service":"demo","token":"synthetic-vault-reference",
                "capability":"reader","account":"owned"}},
            "agent_env":{"alice":{"demo":"sgw_owned_canonical_token"}}
        }});
        write_json(&directory.path().join("policy.json"), &policy);
        if !native {
            settings.policy_file = None;
            settings.temporary_policy_socket = Some(directory.path().join("absent-adapter.sock"));
        }
        let fixture = Fixture::start(directory, settings).await;
        let runtime = fixture.runtime();
        if native {
            let snapshot = runtime.policy.as_ref().unwrap().gateway().unwrap();
            assert!(snapshot.registry().is_none());
            assert!(
                snapshot
                    .agent_services_json("alice")
                    .unwrap()
                    .expose_secret()
                    .contains("sgw_owned_canonical_token")
            );
        } else {
            assert!(runtime.policy.is_none());
        }
        let reply = fixture.read("alice", "GET", TOKEN).await;
        assert_eq!(reply.status, 200);
        assert!(reply.value() == json!({"agent":"alice","authorized":{},"available":[]}));
        fixture.stop().await;
    }
}

#[test]
fn catalog_reads_and_reload_publish_one_scoped_snapshot() {
    owned_child(
        "service_catalog_tests::catalog_reads_and_reload_publish_one_scoped_snapshot",
        catalog_workflow(),
    );
}

async fn catalog_workflow() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path());
    let builtin = directory.path().join("builtin");
    let user = directory.path().join("user");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&user).unwrap();
    settings.gateway_builtin_services_dir = Some(builtin.clone());
    settings.gateway_services_dir = Some(user.clone());
    install_catalog(&builtin, false);
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(false),
    );
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    let first = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&first, &initial, "alice");
    let alice = first.value();
    assert_eq!(alice["authorized"]["demo"]["capability"], "reader");
    assert_eq!(alice["authorized"]["demo"]["host"], "old.catalog.invalid");
    assert_eq!(
        alice["available"],
        json!([{"name":"spare","description":"Spare catalog entry",
        "capabilities":[{"name":"inspect","description":"Inspect only"}]}])
    );
    let alice_token = alice["authorized"]["demo"]["token"].as_str().unwrap();
    assert!(alice_token.starts_with("sgw_") && alice_token.len() == 68);
    let bob_reply = fixture.read("bob", "GET", TOKEN).await;
    assert_projection(&bob_reply, &initial, "bob");
    let bob = bob_reply.value();
    assert_eq!(bob["agent"], "bob");
    assert_eq!(bob["authorized"]["demo"]["capability"], "writer");
    assert!(bob["authorized"]["demo"]["token"] != alice["authorized"]["demo"]["token"]);
    // Reads use the listener identity despite an Alice query/header on every
    // request, and source-compatible POST/DELETE retain the same token/view.
    for method in ["POST", "DELETE", "GET"] {
        assert!(fixture.read("alice", method, TOKEN).await.body == first.body);
    }
    let unauthorized = fixture.read("alice", "GET", "wrong-owned-auth").await;
    assert_eq!(unauthorized.status, 401);
    assert!(!unauthorized.body.contains("sgw_"));
    assert_selected(
        &initial,
        "alice",
        alice_token,
        "old.catalog.invalid",
        "GET",
        "/read",
    );
    let now = policy::current_time_ms();
    let policy = initial.policy.as_ref().unwrap();
    assert_eq!(
        policy.evaluate(budget_request(), now, true).unwrap().effect,
        Effect::Allow
    );
    let budget = policy.budget_stats(now).unwrap();
    assert_ne!(
        budget,
        policy::Policy::from_path(settings.policy_file.as_ref().unwrap())
            .unwrap()
            .budget_stats(now)
            .unwrap()
    );

    // Each rejected candidate has a valid changed policy/catalog peer, so the
    // exact Arc/view assertion catches publication of only half the candidate.
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(true),
    );
    std::fs::write(user.join("bad.yaml"), "schema_version: [").unwrap();
    assert!(fixture.proxy.reload(settings.clone()).await.is_err());
    assert_retained(&fixture, &initial, &budget, now);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == first.body);
    std::fs::remove_file(user.join("bad.yaml")).unwrap();

    install_catalog(&builtin, true);
    std::fs::write(settings.policy_file.as_ref().unwrap(), b"{ invalid policy").unwrap();
    assert!(fixture.proxy.reload(settings.clone()).await.is_err());
    assert_retained(&fixture, &initial, &budget, now);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == first.body);

    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(true),
    );
    let mut bad_tls = settings.clone();
    let pem = fixture.directory.path().join("invalid-owned-ca.pem");
    std::fs::write(&pem, b"owned invalid PEM without a key").unwrap();
    bad_tls.tls_ca_file = Some(pem);
    assert!(fixture.proxy.reload(bad_tls).await.is_err());
    assert_retained(&fixture, &initial, &budget, now);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == first.body);

    fixture.proxy.reload(settings.clone()).await.unwrap();
    let changed = fixture.runtime();
    assert!(!Arc::ptr_eq(&initial, &changed));
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &changed, "alice");
    let replacement = reply.value();
    assert_eq!(replacement["authorized"]["demo"]["capability"], "writer");
    assert_eq!(
        replacement["authorized"]["demo"]["host"],
        "new.catalog.invalid"
    );
    assert_eq!(
        replacement["available"][0]["description"],
        "Changed spare catalog entry"
    );
    let changed_token = replacement["authorized"]["demo"]["token"].as_str().unwrap();
    assert!(changed_token != alice_token);
    assert_selected(
        &changed,
        "alice",
        changed_token,
        "new.catalog.invalid",
        "POST",
        "/v2-write",
    );
    assert!(matches!(
        select(
            &changed,
            "alice",
            alice_token,
            "new.catalog.invalid",
            "POST",
            "/v2-write"
        ),
        GatewayDecision::Deny { .. }
    ));
    assert_eq!(
        changed
            .policy
            .as_ref()
            .unwrap()
            .evaluate_gateway_request(policy::GatewayRequest {
                service: "demo",
                capability: "writer",
                agent: "alice",
                method: "GET",
                path: "/read"
            })
            .effect,
        Effect::Deny
    );
    assert_eq!(
        changed.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    // An in-flight holder still sees its old coherent catalog/routes/token.
    assert_selected(
        &initial,
        "alice",
        alice_token,
        "old.catalog.invalid",
        "GET",
        "/read",
    );
    assert!(
        initial
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .agent_services_json("alice")
            .unwrap()
            .expose_secret()
            .contains(alice_token)
    );

    let mut absent = settings.clone();
    absent.gateway_builtin_services_dir = None;
    absent.gateway_services_dir = None;
    fixture.proxy.reload(absent).await.unwrap();
    let empty = fixture.runtime();
    let snapshot = empty.policy.as_ref().unwrap().gateway().unwrap();
    assert!(snapshot.registry().is_none());
    assert!(snapshot.compiled_routes().is_empty());
    assert!(
        fixture.read("alice", "GET", TOKEN).await.value()
            == json!({"agent":"alice","authorized":{},"available":[]})
    );
    assert_eq!(
        empty.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    fixture.proxy.reload(settings).await.unwrap();
    let recovered = fixture.runtime();
    assert!(!Arc::ptr_eq(&empty, &recovered));
    assert_projection(
        &fixture.read("alice", "GET", TOKEN).await,
        &recovered,
        "alice",
    );
    assert_eq!(
        recovered
            .policy
            .as_ref()
            .unwrap()
            .budget_stats(now)
            .unwrap(),
        budget
    );
    fixture.stop().await;
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn policy_document(changed: bool) -> Value {
    let host = if changed {
        "new.catalog.invalid"
    } else {
        "old.catalog.invalid"
    };
    json!({"global_budget":10,"hosts":{
    host:{"service":"demo","egress":"allow"},
    "meter.invalid":{"egress":"allow","rate_limit":10}},
    "agents":{
        "alice":{"services":{"demo":{"capability":if changed {"writer"} else {"reader"},
            "token":"synthetic-vault-alice","account":"owned-alice"}}},
        "bob":{"services":{"demo":{"capability":"writer",
            "token":"synthetic-vault-bob","account":"owned-bob"}}}
    }})
}

fn install_catalog(directory: &Path, changed: bool) {
    write_json(
        &directory.join("01-demo.yaml"),
        &json!({"schema_version":1,"name":"demo",
        "description":"Owned demo","auth":{"type":"bearer"},"capabilities":{
            "reader":{"description":"Read only","routes":[{"methods":["GET"],"path":"/read"}]},
            "writer":{"description":"Write only","routes":[{"methods":["POST"],
                "path":if changed {"/v2-write"} else {"/write"}}]}}}),
    );
    write_json(
        &directory.join("02-spare.yaml"),
        &json!({"schema_version":1,"name":"spare",
        "description":if changed {"Changed spare catalog entry"} else {"Spare catalog entry"},
        "auth":{"type":"bearer"},"capabilities":{"inspect":{"description":"Inspect only",
            "routes":[{"methods":["GET"],"path":"/inspect"}]}}}),
    );
}

fn budget_request() -> NetworkRequest<'static> {
    NetworkRequest {
        agent: Some("alice"),
        host: "meter.invalid",
        port: Some(443),
        method: "GET",
        path: "/",
    }
}

fn assert_retained(fixture: &Fixture, previous: &Arc<Runtime>, budget: &Value, now: f64) {
    let current = fixture.runtime();
    assert!(Arc::ptr_eq(previous, &current));
    assert_eq!(
        current.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        *budget
    );
}

fn select(
    runtime: &Runtime,
    agent: &str,
    token: &str,
    host: &str,
    method: &str,
    path: &str,
) -> GatewayDecision {
    let policy = runtime.policy.as_ref().unwrap();
    let headers = vec![("Authorization".into(), format!("Bearer {token}"))];
    policy.gateway().unwrap().select(GatewayRequest {
        identity: TrustedIdentity::Agent(agent),
        host,
        route_mode: RouteMode::CompiledPolicy(policy),
        request: ContractRequest {
            method,
            target: path,
            headers: &headers,
            body: b"",
        },
    })
}

fn assert_selected(
    runtime: &Runtime,
    agent: &str,
    token: &str,
    host: &str,
    method: &str,
    path: &str,
) {
    assert!(matches!(
        select(runtime, agent, token, host, method, path),
        GatewayDecision::Selected { .. }
    ));
}

fn assert_projection(reply: &Reply, runtime: &Runtime, owner: &str) {
    assert_eq!(reply.status, 200);
    let snapshot = runtime.policy.as_ref().unwrap().gateway().unwrap();
    let authorized = snapshot.agent_services_json(owner).unwrap();
    let available = snapshot.available_services(owner);
    let expected = format!(
        "{{\"agent\": {}, \"authorized\": {}, \"available\": {}}}",
        crate::python_json::encode(&Value::from(owner)),
        authorized.expose_secret(),
        crate::python_json::encode(&available)
    );
    assert!(
        reply.body == expected,
        "wire catalog differs from its published snapshot"
    );
}

struct Reply {
    status: u16,
    body: String,
}
impl Reply {
    fn value(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    proxy: Proxy,
}
impl Fixture {
    async fn start(directory: tempfile::TempDir, settings: Config) -> Self {
        Self {
            directory,
            proxy: Proxy::start(settings).await.unwrap(),
        }
    }
    fn runtime(&self) -> Arc<Runtime> {
        self.proxy.runtime.read().unwrap().clone()
    }
    async fn read(&self, agent: &str, method: &str, token: &str) -> Reply {
        let mut stream = UnixStream::connect(self.directory.path().join(format!("{agent}.sock")))
            .await
            .unwrap();
        let request = format!(
            "{method} http://_safeyolo.proxy.internal/gateway/services?agent=alice HTTP/1.0\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {token}\r\nX-SafeYolo-Agent: alice\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        timeout(LIMIT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        Reply {
            status: head.split_whitespace().nth(1).unwrap().parse().unwrap(),
            body: body.into(),
        }
    }
    async fn stop(self) {
        let runtime = self.runtime();
        timeout(LIMIT, self.proxy.shutdown()).await.unwrap();
        assert!(
            runtime
                .flow_recorder
                .store()
                .unwrap()
                .get_flow(1)
                .unwrap()
                .is_none()
        );
        for name in ["audit.jsonl", "events.jsonl"] {
            let bytes = std::fs::read(self.directory.path().join(name)).unwrap();
            assert!(
                !bytes.windows(4).any(|part| part == b"sgw_"),
                "catalog token reached routine evidence"
            );
            assert!(
                !bytes
                    .windows(TOKEN.len())
                    .any(|part| part == TOKEN.as_bytes()),
                "synthetic API auth reached routine evidence"
            );
            let text = std::str::from_utf8(&bytes).unwrap();
            for line in text.lines() {
                let event: Value = serde_json::from_str(line).unwrap();
                assert_ne!(event["event"], "proxy.egress");
            }
        }
    }
}
