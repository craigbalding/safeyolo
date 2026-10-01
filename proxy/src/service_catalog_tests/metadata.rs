//! Directory stat failure precedes catalog attempts, policy loads and publication.

use super::*;
use std::{
    os::unix::fs::symlink,
    task::{Context, Waker},
};
use tokio::time::Instant;

fn unreadable_directory(directory: &Path, link: &Path) {
    // One oversized component makes following this owned symlink fail with
    // ENAMETOOLONG, independent of uid or permission-bypass capabilities.
    symlink(directory.join("x".repeat(256)), link).unwrap();
}

fn assert_metadata_error(error: Error) {
    let error = error
        .downcast_ref::<std::io::Error>()
        .expect("directory metadata failure lost its original io::Error");
    assert_eq!(error.raw_os_error(), Some(libc::ENAMETOOLONG));
}

fn catalog_events(fixture: &Fixture) -> Vec<Value> {
    let runtime = fixture.runtime();
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
fn directory_metadata_errors_preserve_publication_and_remain_retryable() {
    owned_child(
        "service_catalog_tests::metadata::directory_metadata_errors_preserve_publication_and_remain_retryable",
        workflow(),
    );
}

async fn workflow() {
    let directory = tempfile::tempdir().unwrap();
    let builtin = directory.path().join("builtin");
    let user = directory.path().join("user");
    std::fs::create_dir(&builtin).unwrap();
    install_catalog(&builtin, false);
    unreadable_directory(directory.path(), &user);
    let mut settings = config(directory.path());
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(user.clone());
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(false),
    );

    assert_metadata_error(Proxy::start(settings.clone()).await.err().unwrap());
    // Scanning precedes file diagnostics, baseline loading and memory startup.
    assert!(!settings.audit_log_path.as_ref().unwrap().exists());
    assert!(!settings.readiness_file.exists());
    assert!(!directory.path().join("alice.sock").exists());
    std::fs::remove_file(&user).unwrap();
    std::fs::create_dir(&user).unwrap();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let accepted = fixture.runtime();
    let accepted_key = fixture.proxy.service_files.clone();
    assert!(accepted_key.is_some());
    let now = policy::current_time_ms();
    let policy = accepted.policy.as_ref().unwrap();
    assert_eq!(
        policy.evaluate(budget_request(), now, true).unwrap().effect,
        Effect::Allow
    );
    let budget = policy.budget_stats(now).unwrap();
    let alice = fixture.read("alice", "GET", TOKEN).await;
    let bob = fixture.read("bob", "GET", TOKEN).await;
    assert_projection(&alice, &accepted, "alice");
    assert_projection(&bob, &accepted, "bob");
    let alice_view = alice.value();
    let accepted_token = alice_view["authorized"]["demo"]["token"].as_str().unwrap();
    assert_selected(
        &accepted,
        "alice",
        accepted_token,
        "old.catalog.invalid",
        "GET",
        "/read",
    );
    let initial_events = catalog_events(&fixture);
    assert_eq!(initial_events.len(), 1);
    assert_eq!(initial_events[0]["event"], "ops.policy_reload");

    // Preserve the exact files/inodes to prove restoration produces the same
    // metadata key. Only the configured path temporarily becomes a bad symlink.
    let saved = fixture.directory.path().join("saved-user");
    std::fs::rename(&user, &saved).unwrap();
    unreadable_directory(fixture.directory.path(), &user);
    let explicit_deadline = fixture.proxy.service_check_at;
    assert_metadata_error(fixture.proxy.reload(settings.clone()).await.err().unwrap());
    assert_retained(&fixture, &accepted, &budget, now);
    assert!(fixture.proxy.service_files == accepted_key);
    assert_eq!(fixture.proxy.service_check_at, explicit_deadline);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == alice.body);
    assert!(fixture.read("bob", "GET", TOKEN).await.body == bob.body);

    // A pre-scan error never consumes a new attempted key. A second reached
    // check therefore encounters the same original error, not an unchanged skip.
    for _ in 0..2 {
        let before = Instant::now();
        assert_metadata_error(
            fixture
                .proxy
                .reload_services_if_changed()
                .await
                .err()
                .unwrap(),
        );
        let after = Instant::now();
        let deadline = fixture.proxy.service_check_at.unwrap();
        assert!(deadline >= before + Duration::from_secs(2));
        assert!(deadline <= after + Duration::from_secs(2));
        {
            let mut wait = std::pin::pin!(fixture.proxy.wait_for_service_catalog_check());
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        assert_retained(&fixture, &accepted, &budget, now);
        assert!(fixture.proxy.service_files == accepted_key);
    }
    assert_eq!(catalog_events(&fixture), initial_events);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == alice.body);
    assert!(fixture.read("bob", "GET", TOKEN).await.body == bob.body);

    std::fs::remove_file(&user).unwrap();
    std::fs::rename(&saved, &user).unwrap();
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert_retained(&fixture, &accepted, &budget, now);
    assert!(fixture.proxy.service_files == accepted_key);
    assert_eq!(catalog_events(&fixture), initial_events);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == alice.body);

    install_catalog(&user, true);
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(true),
    );
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let recovered = fixture.runtime();
    assert!(!Arc::ptr_eq(&accepted, &recovered));
    assert!(fixture.proxy.service_files != accepted_key);
    assert_eq!(
        recovered
            .policy
            .as_ref()
            .unwrap()
            .budget_stats(now)
            .unwrap(),
        budget
    );
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &recovered, "alice");
    let view = reply.value();
    assert_eq!(view["authorized"]["demo"]["host"], "new.catalog.invalid");
    assert_eq!(view["authorized"]["demo"]["capability"], "writer");
    let new_token = view["authorized"]["demo"]["token"].as_str().unwrap();
    assert!(new_token != accepted_token);
    assert_selected(
        &recovered,
        "alice",
        new_token,
        "new.catalog.invalid",
        "POST",
        "/v2-write",
    );
    assert!(matches!(
        select(
            &recovered,
            "alice",
            new_token,
            "new.catalog.invalid",
            "GET",
            "/read"
        ),
        GatewayDecision::Deny { .. }
    ));
    let events = catalog_events(&fixture);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], initial_events[0]);
    assert_eq!(events[1]["event"], "ops.policy_reload");
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(Arc::ptr_eq(&recovered, &fixture.runtime()));
    assert_eq!(catalog_events(&fixture), events);
    fixture.stop().await;
}
