//! Automatic catalog checks use the existing Runtime and authenticated reader.

use super::*;
use std::task::{Context, Poll, Waker};
use tokio::time::{Instant, advance};

fn catalog_settings(directory: &Path) -> Config {
    let mut settings = config(directory);
    let builtin = directory.join("builtin");
    let user = directory.join("user");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&user).unwrap();
    install_catalog(&builtin, false);
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(false),
    );
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(user);
    settings
}

fn write_extra(path: &Path, description: &str) {
    write_json(
        path,
        &json!({"schema_version":1,"name":"extra","description":description,
        "capabilities":{"inspect":{"description":"Owned metadata change","routes":[]}}}),
    );
}

#[test]
fn automatic_checks_keep_h1_catalog_and_policy_publication_coherent() {
    owned_child(
        "service_catalog_tests::reload::automatic_checks_keep_h1_catalog_and_policy_publication_coherent",
        automatic_workflow(),
    );
}

async fn automatic_workflow() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = catalog_settings(directory.path());
    let inspection = directory.path().join("inspection.json");
    write_json(&inspection, &json!({}));
    settings.inspection = Some(Inspection {
        policy_file: inspection.clone(),
        block_websocket_request: false,
        block_websocket_response: false,
    });
    let user = settings.gateway_services_dir.as_ref().unwrap();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    let initial_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&initial_reply, &initial, "alice");
    let now = policy::current_time_ms();
    let policy = initial.policy.as_ref().unwrap();
    assert_eq!(
        policy.evaluate(budget_request(), now, true).unwrap().effect,
        Effect::Allow
    );
    let budget = policy.budget_stats(now).unwrap();
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(Arc::ptr_eq(&initial, &fixture.runtime()));
    assert!(fixture.read("alice", "GET", TOKEN).await.body == initial_reply.body);

    let extra = user.join("03-extra.yaml");
    write_extra(&extra, "Added entry");
    // A service check reloads the baseline/catalog, not accepted transport,
    // scanner or evidence configuration. Keep the real open log, but make its
    // configured pathname invalid, and independently corrupt scanner config.
    let retained_log = fixture.directory.path().join("retained-events.jsonl");
    std::fs::rename(&settings.event_log, &retained_log).unwrap();
    std::fs::create_dir(&settings.event_log).unwrap();
    std::fs::write(&inspection, b"{ invalid inspection").unwrap();
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let added = fixture.runtime();
    let added_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&added_reply, &added, "alice");
    assert_eq!(added_reply.value()["available"][1]["name"], "extra");
    assert!(!Arc::ptr_eq(&initial, &added));
    assert!(Arc::ptr_eq(&initial.events, &added.events));
    assert!(fixture.proxy.reload(settings.clone()).await.is_err());
    assert!(Arc::ptr_eq(&added, &fixture.runtime()));
    write_json(&inspection, &json!({}));
    assert!(fixture.proxy.reload(settings.clone()).await.is_err());
    assert!(Arc::ptr_eq(&added, &fixture.runtime()));
    std::fs::remove_dir(&settings.event_log).unwrap();
    std::fs::rename(retained_log, &settings.event_log).unwrap();

    // User overrides plus the baseline are published by the same reached check.
    install_catalog(user, true);
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(true),
    );
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let changed = fixture.runtime();
    let changed_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&changed_reply, &changed, "alice");
    let view = changed_reply.value();
    assert_eq!(view["authorized"]["demo"]["host"], "new.catalog.invalid");
    assert_eq!(view["authorized"]["demo"]["capability"], "writer");
    assert_eq!(
        view["available"][0]["description"],
        "Changed spare catalog entry"
    );
    let token = view["authorized"]["demo"]["token"].as_str().unwrap();
    assert_selected(
        &changed,
        "alice",
        token,
        "new.catalog.invalid",
        "POST",
        "/v2-write",
    );
    assert_projection(&fixture.read("bob", "GET", TOKEN).await, &changed, "bob");

    std::fs::remove_file(user.join("01-demo.yaml")).unwrap();
    std::fs::remove_file(user.join("02-spare.yaml")).unwrap();
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let removed = fixture.runtime();
    let removed_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&removed_reply, &removed, "alice");
    let view = removed_reply.value();
    assert_eq!(view["available"][0]["description"], "Spare catalog entry");
    let token = view["authorized"]["demo"]["token"].as_str().unwrap();
    assert_selected(
        &removed,
        "alice",
        token,
        "new.catalog.invalid",
        "POST",
        "/write",
    );
    assert!(matches!(
        select(
            &removed,
            "alice",
            token,
            "new.catalog.invalid",
            "POST",
            "/v2-write"
        ),
        GatewayDecision::Deny { .. }
    ));

    let accepted_key = fixture.proxy.service_files.clone();
    write_extra(&extra, "Changed catalog while policy is invalid");
    std::fs::write(settings.policy_file.as_ref().unwrap(), b"{ invalid policy").unwrap();
    assert!(fixture.proxy.reload_services_if_changed().await.is_err());
    assert_retained(&fixture, &removed, &budget, now);
    assert!(fixture.proxy.service_files != accepted_key);
    let attempted_key = fixture.proxy.service_files.clone();
    assert!(fixture.read("alice", "GET", TOKEN).await.body == removed_reply.body);
    // Source consumes the attempted service metadata even after policy failure.
    // Repairing only the policy cannot retry that unchanged service candidate.
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(false),
    );
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(fixture.proxy.service_files == attempted_key);
    assert!(Arc::ptr_eq(&removed, &fixture.runtime()));
    write_extra(&extra, "A later changed valid catalog recovers the policy");
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let recovered = fixture.runtime();
    let recovered_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&recovered_reply, &recovered, "alice");
    assert_eq!(
        recovered
            .policy
            .as_ref()
            .unwrap()
            .budget_stats(now)
            .unwrap(),
        budget
    );
    assert_eq!(
        recovered_reply.value()["authorized"]["demo"]["capability"],
        "reader"
    );

    let accepted_key = fixture.proxy.service_files.clone();
    std::fs::write(&extra, b"schema_version: [").unwrap();
    assert!(fixture.proxy.reload_services_if_changed().await.is_err());
    assert!(fixture.proxy.service_files != accepted_key);
    assert_retained(&fixture, &recovered, &budget, now);
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(fixture.read("alice", "GET", TOKEN).await.body == recovered_reply.body);
    write_extra(
        &extra,
        "Recovered from malformed YAML with changed metadata",
    );
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());

    // Explicit rejected replacement must not select the replacement's watch key.
    let before_replacement = fixture.runtime();
    let old_key = fixture.proxy.service_files.clone();
    let old_deadline = fixture.proxy.service_check_at;
    let builtin = fixture.directory.path().join("replacement-builtin");
    let replacement_user = fixture.directory.path().join("replacement-user");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&replacement_user).unwrap();
    install_catalog(&builtin, true);
    let mut replacement = settings.clone();
    replacement.gateway_builtin_services_dir = Some(builtin.clone());
    replacement.gateway_services_dir = Some(replacement_user);
    let invalid_pem = fixture.directory.path().join("invalid-owned-ca.pem");
    std::fs::write(&invalid_pem, b"owned invalid PEM").unwrap();
    let mut rejected = replacement.clone();
    rejected.tls_ca_file = Some(invalid_pem);
    assert!(fixture.proxy.reload(rejected).await.is_err());
    assert!(Arc::ptr_eq(&before_replacement, &fixture.runtime()));
    assert!(fixture.proxy.service_files == old_key);
    assert_eq!(fixture.proxy.service_check_at, old_deadline);
    write_extra(
        &extra,
        "Old configured directory still drives a later check after rejected replacement",
    );
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());

    fixture.proxy.reload(replacement.clone()).await.unwrap();
    let replaced = fixture.runtime();
    let replaced_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&replaced_reply, &replaced, "alice");
    assert_eq!(
        replaced_reply.value()["available"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        replaced_reply.value()["available"][0]["description"],
        "Changed spare catalog entry"
    );
    let replacement_key = fixture.proxy.service_files.clone();
    write_extra(
        &extra,
        "An obsolete source must not publish over the accepted replacement directory",
    );
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(fixture.proxy.service_files == replacement_key);
    assert!(Arc::ptr_eq(&replaced, &fixture.runtime()));
    assert!(fixture.read("alice", "GET", TOKEN).await.body == replaced_reply.body);

    replacement.gateway_builtin_services_dir = None;
    replacement.gateway_services_dir = None;
    fixture.proxy.reload(replacement).await.unwrap();
    let empty = fixture.runtime();
    assert!(fixture.proxy.service_files.is_none());
    assert!(fixture.proxy.service_check_at.is_none());
    install_catalog(&builtin, false);
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(Arc::ptr_eq(&empty, &fixture.runtime()));
    assert_eq!(
        empty.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    assert!(
        fixture.read("alice", "GET", TOKEN).await.value()
            == json!({"agent":"alice","authorized":{},"available":[]})
    );
    fixture.stop().await;
}

// Poll once and drop the actual wait, as an explicit reload/shutdown branch
// does. No helper replaces the scheduler's timer or mutates its deadline.
fn poll_wait(proxy: &Proxy) -> Poll<()> {
    let mut wait = std::pin::pin!(proxy.wait_for_service_catalog_check());
    wait.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

#[tokio::test(start_paused = true)]
async fn catalog_deadlines_delay_after_each_attempt_and_cancel_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = catalog_settings(directory.path());
    // No listener or API/token read is needed for the actual Proxy scheduler.
    settings.listeners.clear();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let started = Instant::now();
    assert!(fixture.proxy.service_check_at.unwrap() <= started);
    assert!(poll_wait(&fixture.proxy).is_ready());
    assert_eq!(Instant::now(), started);
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert_eq!(
        fixture.proxy.service_check_at,
        Some(Instant::now() + Duration::from_secs(2))
    );
    let deadline = fixture.proxy.service_check_at;
    assert!(poll_wait(&fixture.proxy).is_pending());
    assert_eq!(fixture.proxy.service_check_at, deadline);
    advance(Duration::from_millis(1999)).await;
    assert!(poll_wait(&fixture.proxy).is_pending());
    advance(Duration::from_millis(1)).await;
    assert!(poll_wait(&fixture.proxy).is_ready());
    // A late driver performs one check, then waits two fresh seconds.
    advance(Duration::from_secs(20)).await;
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert_eq!(
        fixture.proxy.service_check_at,
        Some(Instant::now() + Duration::from_secs(2))
    );
    assert!(poll_wait(&fixture.proxy).is_pending());

    let user = settings.gateway_services_dir.as_ref().unwrap();
    let invalid = user.join("bad.yaml");
    std::fs::write(&invalid, b"schema_version: [").unwrap();
    advance(Duration::from_secs(2)).await;
    assert!(poll_wait(&fixture.proxy).is_ready());
    assert!(fixture.proxy.reload_services_if_changed().await.is_err());
    assert_eq!(
        fixture.proxy.service_check_at,
        Some(Instant::now() + Duration::from_secs(2))
    );
    assert!(poll_wait(&fixture.proxy).is_pending());
    std::fs::remove_file(invalid).unwrap();
    fixture.proxy.reload(settings.clone()).await.unwrap();
    assert_eq!(fixture.proxy.service_check_at, Some(Instant::now()));
    assert!(poll_wait(&fixture.proxy).is_ready());
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(poll_wait(&fixture.proxy).is_pending());

    let configured = settings.clone();
    settings.gateway_builtin_services_dir = None;
    settings.gateway_services_dir = None;
    fixture.proxy.reload(settings).await.unwrap();
    assert!(fixture.proxy.service_check_at.is_none());
    assert!(poll_wait(&fixture.proxy).is_pending());
    advance(Duration::from_secs(3600)).await;
    assert!(poll_wait(&fixture.proxy).is_pending());
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(fixture.proxy.service_check_at.is_none());
    // A failed initial Runtime read is still an attempted configured check.
    // It must rearm instead of leaving an already-ready deadline spinning.
    fixture.proxy.reload(configured).await.unwrap();
    let retained = fixture.runtime();
    let state = fixture.proxy.runtime.clone();
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _write = state.write().unwrap();
        panic!("synthetic catalog runtime lock poison");
    }));
    assert!(poison.is_err());
    assert!(fixture.proxy.reload_services_if_changed().await.is_err());
    assert_eq!(
        fixture.proxy.service_check_at,
        Some(Instant::now() + Duration::from_secs(2))
    );
    assert!(poll_wait(&fixture.proxy).is_pending());
    // Every pending wait above was dropped; none owns a producer or prevents stop.
    // Scheduling assertions are complete; drain real owned I/O using the
    // inherited fixture's ordinary wall-clock shutdown timeout.
    tokio::time::resume();
    let Fixture { directory, proxy } = fixture;
    timeout(LIMIT, proxy.shutdown()).await.unwrap();
    assert!(!directory.path().join("ready").exists());
    assert!(retained.audit.shutdown(Duration::ZERO).unwrap());
}
