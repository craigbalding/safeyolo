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
