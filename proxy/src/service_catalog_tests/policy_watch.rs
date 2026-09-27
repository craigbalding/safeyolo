//! Owned baseline watcher publication and scheduling, independent of catalog checks.

use super::*;
use std::{
    task::{Context, Poll, Waker},
    time::UNIX_EPOCH,
};
use tokio::time::{Instant, advance};

fn stamp(path: &Path, seconds: u64) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)),
        )
        .unwrap();
}

fn write_policy(path: &Path, document: &Value, seconds: u64) {
    write_json(path, document);
    stamp(path, seconds);
}

fn poll_policy(proxy: &Proxy) -> Poll<()> {
    let mut wait = std::pin::pin!(proxy.wait_for_policy_check());
    wait.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

fn policy_events(runtime: &Runtime) -> Vec<Value> {
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    std::fs::read_to_string(runtime.config.audit_log_path.as_ref().unwrap())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| {
            matches!(
                row["event"].as_str(),
                Some("ops.policy_reload" | "ops.policy_error" | "ops.config_error")
            )
        })
        .collect()
}

#[test]
fn authorization_during_policy_load_and_publication_reaches_the_agent_gateway() {
    owned_child(
        "service_catalog_tests::policy_watch::authorization_during_policy_load_and_publication_reaches_the_agent_gateway",
        authorization_during_publication(),
    );
}

async fn authorization_during_publication() {
    use crate::credentials::{Credential, Secret, Vault};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut settings = config(root);
    settings.policy_file = Some(root.join("policy.toml"));
    settings.admin_port = Some(0);
    settings.admin_api_token_file = Some(root.join("admin-token"));
    let builtin = root.join("builtin");
    let services = root.join("services");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&services).unwrap();
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(services.clone());
    std::fs::write(root.join("admin-token"), "owned-admin-token").unwrap();
    std::fs::create_dir(root.join("data")).unwrap();
    std::fs::write(root.join("data/vault.key"), "owned-vault-passphrase").unwrap();
    Vault::unlock(
        root.join("data/vault.yaml.enc"),
        &Secret::new("owned-vault-passphrase"),
    )
    .unwrap()
    .store(Credential::new(
        "owned-vault-ref",
        "bearer",
        Secret::new("owned-origin-secret"),
    ))
    .unwrap();
    std::fs::write(
        services.join("basic.yaml"),
        r#"schema_version: 1
name: basic
default_host: basic.test
auth: {type: bearer, allow_http: true}
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /p3/read
"#,
    )
    .unwrap();
    std::fs::write(
        services.join("contract.yaml"),
        r#"schema_version: 1
name: contract
default_host: contract.test
auth: {type: bearer, allow_http: true}
risky_routes:
  - path: /p3/write
    methods: [POST]
    tactics: [impact]
capabilities:
  writer:
    routes:
      - methods: [POST]
        path: /p3/write
    contract:
      template: p3.write.v1
      bindings:
        project: {source: operator, type: enum, options: [alpha, beta]}
        ticket: {source: operator, type: string}
      operations:
        - name: write
          request:
            method: POST
            path: /p3/write
            query:
              allow:
                ticket: {equals_var: ticket}
            body:
              allow:
                project: {equals_var: project}
      enforcement: {request_shape: enforced, transport_hygiene: enforced, state_capture: declared, state_enforcement: declared, response_validators: declared}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("policy.toml"),
        r#"version = '2.0'
[hosts]
'basic.test' = {egress='allow', service='basic'}
'contract.test' = {egress='allow', service='contract'}
[agents.alice]
image='owned'
[agents.bob]
image='owned'
[[risk]]
account='agent'
tactics=['impact']
decision='require_approval'
approval_default='once'
"#,
    )
    .unwrap();
    let path = root.join("policy.toml");
    let mut fixture = Fixture::start(directory, settings).await;
    let original = fixture.runtime();
    let port = fixture.proxy.admin.as_ref().unwrap().address().port();
    assert_eq!(
        fixture.read("alice", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );

    let socket = fixture.directory.path().join("alice.sock");
    let challenge = agent_post(
        &socket,
        "http://_safeyolo.proxy.internal/gateway/request-access",
        TOKEN,
        json!({"service":"contract","capability":"writer","reason":"p3 handoff"}),
    )
    .await;
    assert_eq!(challenge.status, 200);
    assert_eq!(challenge.value()["decision"], "needs_contract_binding");
    let submitted = agent_post(
        &socket,
        "http://_safeyolo.proxy.internal/gateway/submit-binding",
        TOKEN,
        json!({"service":"contract","capability":"writer",
               "bindings":{"project":"alpha","ticket":"T-1"},"purpose_code":"write"}),
    )
    .await;
    assert_eq!(submitted.status, 202);
    authorize_service(port, "basic", "reader").await;
    let binding = admin_post(
        port,
        "/admin/gateway/contract-binding",
        json!({"agent":"alice","service":"contract","capability":"writer",
               "template":"p3.write.v1","bindings":{"project":"alpha","ticket":"T-1"},
               "grantable_operations":["write"]}),
    )
    .await;
    assert_eq!(binding.status, 200);
    // This candidate has read the basic authorization but has not yet been
    // published. The second admin write must remain visible to the watcher.
    let candidate = crate::policy_runtime::load(
        &path,
        original
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry(),
        original.policy.as_ref(),
        &original.audit,
    )
    .unwrap();
    authorize_service(port, "contract", "writer").await;
    fixture.proxy.publish_policy(&original, candidate).unwrap();
    let first = fixture.read("alice", "GET", TOKEN).await.value();
    assert!(
        first["authorized"]["basic"]["token"]
            .as_str()
            .unwrap()
            .starts_with("sgw_")
    );
    assert!(first["authorized"].get("contract").is_none());
    assert_eq!(
        fixture.read("bob", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );
    assert_eq!(policy_events(&original).len(), 2);

    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let second = fixture.read("alice", "GET", TOKEN).await.value();
    assert!(
        second["authorized"]["basic"]["token"]
            .as_str()
            .unwrap()
            .starts_with("sgw_")
    );
    let contract_token = second["authorized"]["contract"]["token"].as_str().unwrap();
    assert!(contract_token.starts_with("sgw_"));
    assert_eq!(
        fixture.read("bob", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );
    assert_eq!(policy_events(&original).len(), 3);
    let prompt = agent_post(
        &socket,
        "http://contract.test/p3/write?ticket=T-1",
        contract_token,
        json!({"project":"alpha"}),
    )
    .await;
    assert_eq!(prompt.status, 428);
    let peer = agent_post(
        &fixture.directory.path().join("bob.sock"),
        "http://contract.test/p3/write?ticket=T-1",
        contract_token,
        json!({"project":"alpha"}),
    )
    .await;
    assert_eq!(peer.status, 403);
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());

    // Remove basic, then reauthorize it after the next loader has read the
    // baseline but before compilation/observation completes. The accepted
    // candidate cannot claim the later admin write in its watermark.
    let revoked = admin_delete(port, "/admin/agents/alice/services/basic").await;
    assert_eq!(revoked.status, 200);
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert!(
        fixture.read("alice", "GET", TOKEN).await.value()["authorized"]
            .get("basic")
            .is_none()
    );
    let before = fixture.runtime();
    let (sent, done) = std::sync::mpsc::sync_channel(1);
    let runtime = tokio::runtime::Handle::current();
    crate::policy::after_next_baseline_read(move || {
        runtime.spawn(async move {
            authorize_service(port, "basic", "reader").await;
            sent.send(()).unwrap();
        });
        done.recv_timeout(LIMIT).unwrap();
    });
    let candidate = crate::policy_runtime::load(
        &path,
        before
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry(),
        before.policy.as_ref(),
        &before.audit,
    )
    .unwrap();
    fixture.proxy.publish_policy(&before, candidate).unwrap();
    assert!(
        fixture.read("alice", "GET", TOKEN).await.value()["authorized"]
            .get("basic")
            .is_none()
    );
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let restored = fixture.read("alice", "GET", TOKEN).await.value();
    assert!(
        restored["authorized"]["basic"]["token"]
            .as_str()
            .unwrap()
            .starts_with("sgw_")
    );
    assert_eq!(
        fixture.read("bob", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    fixture.stop().await;
}

#[test]
fn expiry_prune_serializes_service_authorization_and_revocation() {
    owned_child(
        "service_catalog_tests::policy_watch::expiry_prune_serializes_service_authorization_and_revocation",
        expiry_prune_and_admin_workflow(),
    );
}

async fn expiry_prune_and_admin_workflow() {
    use crate::credentials::{Credential, Secret, Vault};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut settings = config(root);
    let path = root.join("policy.toml");
    settings.policy_file = Some(path.clone());
    settings.admin_port = Some(0);
    settings.admin_api_token_file = Some(root.join("admin-token"));
    let builtin = root.join("builtin");
    let services = root.join("services");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&services).unwrap();
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(services.clone());
    std::fs::write(root.join("admin-token"), "owned-admin-token").unwrap();
    std::fs::create_dir(root.join("data")).unwrap();
    std::fs::write(root.join("data/vault.key"), "owned-vault-passphrase").unwrap();
    Vault::unlock(
        root.join("data/vault.yaml.enc"),
        &Secret::new("owned-vault-passphrase"),
    )
    .unwrap()
    .store(Credential::new(
        "owned-vault-ref",
        "bearer",
        Secret::new("owned-origin-secret"),
    ))
    .unwrap();
    std::fs::write(
        services.join("basic.yaml"),
        r#"schema_version: 1
name: basic
default_host: basic.test
auth: {type: bearer, allow_http: true}
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /p3/read
"#,
    )
    .unwrap();
    std::fs::write(
        &path,
        r#"version = '2.0'
[hosts]
'basic.test' = {egress='allow', service='basic'}
[agents.alice]
image='owned'
[agents.bob]
image='owned'
"#,
    )
    .unwrap();
    let mut fixture = Fixture::start(directory, settings).await;
    let port = fixture.proxy.admin.as_ref().unwrap().address().port();
    assert_eq!(
        fixture.read("alice", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );

    // The admin request reaches the shared lock after expiry has reread the
    // baseline. The expiry deletion and later authorization must both persist.
    insert_expired_host(&path, "first-expired.invalid");
    let authorized = prune_while_admin_waits(
        &fixture,
        &path,
        admin_post(
            port,
            "/admin/agents/alice/services",
            json!({"service":"basic","capability":"reader","credential":"owned-vault-ref"}),
        ),
    );
    assert_eq!(authorized.status, 200);
    assert_eq!(authorized.value()["status"], "authorized");
    let saved: toml_edit::DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    assert!(saved["hosts"].get("first-expired.invalid").is_none());
    assert!(saved["agents"]["alice"]["services"].get("basic").is_some());
    assert!(
        fixture.read("alice", "GET", TOKEN).await.value()["authorized"]
            .get("basic")
            .is_none()
    );
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let allowed = fixture.read("alice", "GET", TOKEN).await.value();
    let token = allowed["authorized"]["basic"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(token.starts_with("sgw_"));
    assert_eq!(
        fixture.read("bob", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );
    assert_eq!(
        agent_get(&fixture.directory.path().join("bob.sock"), &token)
            .await
            .status,
        403
    );

    // The opposite admin mutation must stay gone after a concurrent prune and
    // the next watcher publication, including an already issued gateway token.
    insert_expired_host(&path, "second-expired.invalid");
    let revoked = prune_while_admin_waits(
        &fixture,
        &path,
        admin_delete(port, "/admin/agents/alice/services/basic"),
    );
    assert_eq!(revoked.status, 200);
    let saved: toml_edit::DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    assert!(saved["hosts"].get("second-expired.invalid").is_none());
    assert!(saved["agents"]["alice"].get("services").is_none());
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert_eq!(
        fixture.read("alice", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );
    assert_eq!(
        fixture.read("bob", "GET", TOKEN).await.value()["authorized"],
        json!({})
    );
    assert_eq!(
        agent_get(&fixture.directory.path().join("alice.sock"), &token)
            .await
            .status,
        403
    );
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    fixture.stop().await;
}

fn insert_expired_host(path: &Path, host: &str) {
    let source = std::fs::read_to_string(path).unwrap();
    assert!(source.contains("[hosts]\n"));
    let updated = source.replacen(
        "[hosts]\n",
        &format!("[hosts]\n'{host}'={{egress='deny',expires=2001-01-01T00:00:00Z}}\n"),
        1,
    );
    std::fs::write(path, updated).unwrap();
}

fn prune_while_admin_waits(
    fixture: &Fixture,
    path: &Path,
    admin: impl std::future::Future<Output = Reply> + Send + 'static,
) -> Reply {
    let before = fixture.runtime();
    let (at_lock_tx, at_lock_rx) = std::sync::mpsc::sync_channel(1);
    let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
    let handle = tokio::runtime::Handle::current();
    let policy_path = path.to_owned();
    crate::policy::after_next_expiry_read(move || {
        let independent = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(policy_path.parent().unwrap().join(".policy.toml.lock"))
            .unwrap();
        assert!(matches!(
            independent.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        crate::approvals::before_next_policy_lock(policy_path, move || {
            at_lock_tx.send(()).unwrap();
        });
        handle.spawn(async move {
            reply_tx.send(admin.await).unwrap();
        });
        at_lock_rx.recv_timeout(LIMIT).unwrap();
    });
    let candidate = crate::policy_runtime::load(
        path,
        before
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry(),
        before.policy.as_ref(),
        &before.audit,
    )
    .unwrap();
    let reply = reply_rx.recv_timeout(LIMIT).unwrap();
    fixture.proxy.publish_policy(&before, candidate).unwrap();
    reply
}

async fn agent_get(socket: &Path, token: &str) -> Reply {
    let request = format!(
        "GET http://basic.test/p3/read HTTP/1.1\r\nHost: basic.test\r\n\
         Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    reply(response)
}

async fn authorize_service(port: u16, service: &str, capability: &str) {
    let reply = admin_post(
        port,
        "/admin/agents/alice/services",
        json!({"service":service,"capability":capability,"credential":"owned-vault-ref"}),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.value()["status"], "authorized");
}

async fn admin_post(port: u16, path: &str, payload: Value) -> Reply {
    use tokio::net::TcpStream;
    let body = payload.to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer owned-admin-token\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    reply(response)
}

async fn admin_delete(port: u16, path: &str) -> Reply {
    use tokio::net::TcpStream;
    let request = format!(
        "DELETE {path} HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer owned-admin-token\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    reply(response)
}

async fn agent_post(socket: &Path, target: &str, token: &str, payload: Value) -> Reply {
    let body = payload.to_string();
    let host = target
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let request = format!(
        "POST {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    reply(response)
}

fn reply(response: Vec<u8>) -> Reply {
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    Reply {
        status: head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body: body.into(),
    }
}

#[tokio::test(start_paused = true)]
async fn standalone_policy_checks_retry_newer_failures_and_rearm_without_a_catalog() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path());
    settings.listeners.clear(); // No API/token access for the scheduler control.
    let path = settings.policy_file.as_ref().unwrap().clone();
    let allow =
        json!({"hosts":{"meter.invalid":{"rate_limit":10},"toggle.invalid":{"egress":"allow"}}});
    let deny =
        json!({"hosts":{"meter.invalid":{"rate_limit":10},"toggle.invalid":{"egress":"deny"}}});
    write_policy(&path, &allow, 1000);
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    assert!(fixture.proxy.service_files.is_none());
    assert!(fixture.proxy.policy_check_at.unwrap() <= Instant::now());
    assert!(poll_policy(&fixture.proxy).is_ready());
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert_eq!(
        fixture.proxy.policy_check_at,
        Some(Instant::now() + Duration::from_secs(2))
    );
    assert!(poll_policy(&fixture.proxy).is_pending());
    advance(Duration::from_millis(1999)).await;
    assert!(poll_policy(&fixture.proxy).is_pending());
    advance(Duration::from_millis(1)).await;
    assert!(poll_policy(&fixture.proxy).is_ready());
    let now = policy::current_time_ms();
    assert_eq!(
        initial
            .policy
            .as_ref()
            .unwrap()
            .evaluate(budget_request(), now, true)
            .unwrap()
            .effect,
        Effect::Allow
    );
    let budget = initial.policy.as_ref().unwrap().budget_stats(now).unwrap();

    std::fs::write(&path, "{ invalid newer policy").unwrap();
    stamp(&path, 1001);
    for _ in 0..2 {
        let error = fixture
            .proxy
            .reload_policy_if_changed()
            .await
            .err()
            .unwrap();
        assert!(error.downcast_ref::<policy::PolicyError>().is_some());
        assert_retained(&fixture, &initial, &budget, now);
        assert_eq!(
            fixture.proxy.policy_check_at,
            Some(Instant::now() + Duration::from_secs(2))
        );
        assert!(poll_policy(&fixture.proxy).is_pending());
    }
    let events = policy_events(&initial);
    assert_eq!(
        events
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["ops.policy_reload", "ops.policy_error", "ops.policy_error"]
    );
    // Repair at the same failed mtime: rejection did not consume a watermark.
    write_policy(&path, &deny, 1001);
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let denied = fixture.runtime();
    assert!(!Arc::ptr_eq(&initial, &denied));
    assert_eq!(
        denied
            .policy
            .as_ref()
            .unwrap()
            .evaluate(list_request("toggle.invalid"), now, false)
            .unwrap()
            .effect,
        Effect::Deny
    );
    assert_eq!(
        denied.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    write_policy(&path, &allow, 1000);
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert!(Arc::ptr_eq(&denied, &fixture.runtime()));
    stamp(&path, 1002);
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let allowed = fixture.runtime();
    assert_eq!(
        allowed
            .policy
            .as_ref()
            .unwrap()
            .evaluate(list_request("toggle.invalid"), now, false)
            .unwrap()
            .effect,
        Effect::Allow
    );

    let deadline = fixture.proxy.policy_check_at;
    write_policy(&path, &allow, 1003);
    fixture.proxy.reload(settings.clone()).await.unwrap();
    assert_eq!(fixture.proxy.policy_check_at, deadline);
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    let replacement = fixture.directory.path().join("replacement.json");
    write_policy(&replacement, &allow, 1004);
    settings.policy_file = Some(replacement);
    fixture.proxy.reload(settings.clone()).await.unwrap();
    assert_eq!(fixture.proxy.policy_check_at, Some(Instant::now()));
    assert!(poll_policy(&fixture.proxy).is_ready());
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    let configured = settings.clone();
    settings.policy_file = None;
    settings.temporary_policy_socket = Some(fixture.directory.path().join("unused-adapter.sock"));
    fixture.proxy.reload(settings).await.unwrap();
    assert!(fixture.proxy.policy_check_at.is_none());
    assert!(poll_policy(&fixture.proxy).is_pending());
    advance(Duration::from_secs(3600)).await;
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert!(fixture.proxy.policy_check_at.is_none());
    fixture.proxy.reload(configured).await.unwrap();
    assert_eq!(fixture.proxy.policy_check_at, Some(Instant::now()));
    let retained = fixture.runtime();
    let state = fixture.proxy.runtime.clone();
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _write = state.write().unwrap();
        panic!("synthetic baseline watcher runtime lock poison");
    }));
    assert!(poison.is_err());
    assert!(fixture.proxy.reload_policy_if_changed().await.is_err());
    assert_eq!(
        fixture.proxy.policy_check_at,
        Some(Instant::now() + Duration::from_secs(2))
    );
    assert!(poll_policy(&fixture.proxy).is_pending());
    // Each wait was polled once and dropped; no canceled wait owns a producer.
    tokio::time::resume();
    let Fixture { directory, proxy } = fixture;
    timeout(LIMIT, proxy.shutdown()).await.unwrap();
    assert!(!directory.path().join("ready").exists());
    assert!(retained.audit.shutdown(Duration::ZERO).unwrap());
}

fn listed_policy(changed: bool) -> Value {
    let mut document = policy_document(changed);
    document["lists"] = json!({"owned":"hosts.list"});
    document["hosts"]["$owned"] = json!({"egress":"allow"});
    document
}

fn list_request(host: &str) -> NetworkRequest<'_> {
    NetworkRequest {
        agent: Some("alice"),
        host,
        port: Some(443),
        method: "GET",
        path: "/",
    }
}

#[test]
fn baseline_addon_and_list_checks_reuse_accepted_catalog_and_runtime_owners() {
    owned_child(
        "service_catalog_tests::policy_watch::baseline_addon_and_list_checks_reuse_accepted_catalog_and_runtime_owners",
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
    install_catalog(&builtin, false);
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(user.clone());
    let path = settings.policy_file.as_ref().unwrap().clone();
    let addons = directory.path().join("addons.yaml");
    let list = directory.path().join("hosts.list");
    std::fs::write(&list, "old.listed.invalid\n").unwrap();
    stamp(&list, 1000);
    write_policy(&addons, &json!({}), 1000);
    write_policy(&path, &listed_policy(false), 1000);
    let inspection = directory.path().join("inspection.json");
    write_json(&inspection, &json!({}));
    settings.inspection = Some(Inspection {
        policy_file: inspection.clone(),
        block_request: false,
        block_response: false,
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let ca = directory.path().join("owned-ca.pem");
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let certificate = params.self_signed(&key).unwrap();
    let pem = format!("{}{}", key.serialize_pem(), certificate.pem());
    std::fs::write(&ca, &pem).unwrap();
    settings.tls_ca_file = Some(ca.clone());
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    let registry = initial
        .policy
        .as_ref()
        .unwrap()
        .gateway()
        .unwrap()
        .registry()
        .unwrap();
    let service_key = fixture.proxy.service_files.clone();
    let service_deadline = fixture.proxy.service_check_at;
    let now = policy::current_time_ms();
    assert_eq!(
        initial
            .policy
            .as_ref()
            .unwrap()
            .evaluate(budget_request(), now, true)
            .unwrap()
            .effect,
        Effect::Allow
    );
    let budget = initial.policy.as_ref().unwrap().budget_stats(now).unwrap();
    let original_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&original_reply, &initial, "alice");
    let mut post_compile_failure = listed_policy(false);
    post_compile_failure["lists"]["unused"] = Value::from("unused\0hosts");
    write_policy(&path, &post_compile_failure, 1001);
    let deadline = fixture.proxy.policy_check_at;
    // This unreferenced list compiles normally but fails the later raw-list
    // observation. D66 keeps the complete prior accepted snapshot/watermarks.
    assert!(fixture.proxy.reload(settings.clone()).await.is_err());
    assert_retained(&fixture, &initial, &budget, now);
    assert!(fixture.proxy.service_files == service_key);
    assert_eq!(fixture.proxy.policy_check_at, deadline);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == original_reply.body);
    let failed_events = policy_events(&initial);
    assert_eq!(failed_events.len(), 2);
    assert_eq!(failed_events[1]["event"], "ops.policy_error");
    write_policy(&path, &listed_policy(false), 1000);
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    // A baseline check must not reload any of these accepted owners from disk.
    let bad_catalog = user.join("broken.yaml");
    std::fs::write(&bad_catalog, "schema_version: [").unwrap();
    std::fs::write(&ca, "owned invalid PEM").unwrap();
    std::fs::write(&inspection, "{ invalid inspection").unwrap();
    let retained_log = fixture.directory.path().join("retained-events.jsonl");
    std::fs::rename(&settings.event_log, &retained_log).unwrap();
    std::fs::create_dir(&settings.event_log).unwrap();

    write_policy(&path, &listed_policy(true), 1001);
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let baseline = fixture.runtime();
    assert!(Arc::ptr_eq(
        &registry,
        &baseline
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry()
            .unwrap()
    ));
    assert!(Arc::ptr_eq(
        initial.tls.as_ref().unwrap(),
        baseline.tls.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(&initial.events, &baseline.events));
    assert!(Arc::ptr_eq(&initial.audit, &baseline.audit));
    assert!(fixture.proxy.service_files == service_key);
    assert_eq!(fixture.proxy.service_check_at, service_deadline);
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &baseline, "alice");
    let view = reply.value();
    assert_eq!(view["authorized"]["demo"]["host"], "new.catalog.invalid");
    assert_eq!(view["authorized"]["demo"]["capability"], "writer");
    assert_selected(
        &baseline,
        "alice",
        view["authorized"]["demo"]["token"].as_str().unwrap(),
        "new.catalog.invalid",
        "POST",
        "/write",
    );

    write_policy(
        &addons,
        &json!({"addons":{"request_logger":{"quiet_hosts":{"hosts":["quiet.owned.invalid"]}}}}),
        1002,
    );
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let addon = fixture.runtime();
    assert_eq!(
        addon.policy.as_ref().unwrap().baseline().unwrap().unwrap()["addons"]["request_logger"]["quiet_hosts"]
            ["hosts"],
        json!(["quiet.owned.invalid"])
    );
    assert!(!Arc::ptr_eq(&baseline, &addon));
    std::fs::write(&list, "new.listed.invalid\n").unwrap();
    stamp(&list, 1003);
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let listed = fixture.runtime();
    assert!(!Arc::ptr_eq(&addon, &listed));
    assert_eq!(
        listed
            .policy
            .as_ref()
            .unwrap()
            .evaluate(list_request("new.listed.invalid"), now, false)
            .unwrap()
            .effect,
        Effect::Allow
    );
    assert_eq!(
        listed.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    assert!(Arc::ptr_eq(
        &registry,
        &listed
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry()
            .unwrap()
    ));
    assert_projection(&fixture.read("alice", "GET", TOKEN).await, &listed, "alice");
    let events = policy_events(&listed);
    assert_eq!(events.len(), 5);
    assert_eq!(events[1], failed_events[1]);
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(index, row)| index == 1 || row["event"] == "ops.policy_reload")
    );

    std::fs::remove_file(bad_catalog).unwrap();
    std::fs::write(&ca, pem).unwrap();
    write_json(&inspection, &json!({}));
    std::fs::remove_dir(&settings.event_log).unwrap();
    std::fs::rename(retained_log, &settings.event_log).unwrap();
    write_policy(&path, &listed_policy(false), 1004);
    let deadline = fixture.proxy.policy_check_at;
    fixture.proxy.reload(settings.clone()).await.unwrap();
    assert_eq!(fixture.proxy.policy_check_at, deadline);
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    let explicit = fixture.runtime();
    assert_eq!(policy_events(&explicit).len(), 6);

    install_catalog(&user, true);
    write_policy(&path, &listed_policy(true), 1005);
    let deadline = fixture.proxy.policy_check_at;
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let catalog = fixture.runtime();
    assert_eq!(fixture.proxy.policy_check_at, deadline);
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert_eq!(policy_events(&catalog).len(), 7);
    let registry = catalog
        .policy
        .as_ref()
        .unwrap()
        .gateway()
        .unwrap()
        .registry()
        .unwrap();
    catalog.audit.poison_for_test();
    write_policy(
        &addons,
        &json!({"addons":{"request_logger":{"quiet_hosts":{"hosts":["later.quiet.invalid"]}}}}),
        1006,
    );
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let accepted = fixture.runtime();
    assert!(!Arc::ptr_eq(&catalog, &accepted));
    assert!(Arc::ptr_eq(
        &registry,
        &accepted
            .policy
            .as_ref()
            .unwrap()
            .gateway()
            .unwrap()
            .registry()
            .unwrap()
    ));
    assert_eq!(
        accepted.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert_projection(
        &fixture.read("alice", "GET", TOKEN).await,
        &accepted,
        "alice",
    );
    fixture.stop().await;
}
