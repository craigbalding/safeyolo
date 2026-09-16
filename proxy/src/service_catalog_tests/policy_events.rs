//! Baseline evidence follows accepted publication; audit failure cannot undo it.

use super::*;

fn settings(directory: &Path) -> Config {
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

fn read_audit(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn drained_audit(fixture: &Fixture) -> Vec<Value> {
    let runtime = fixture.runtime();
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    read_audit(runtime.config.audit_log_path.as_ref().unwrap())
}

fn policy_events(rows: &[Value]) -> Vec<&Value> {
    rows.iter()
        .filter(|row| {
            matches!(
                row["event"].as_str(),
                Some("ops.policy_reload" | "ops.policy_error")
            )
        })
        .collect()
}

fn assert_event(row: &Value, event: &str, severity: &str, summary: &str, details: Value) {
    let mut projected = row.clone();
    assert!(
        projected
            .as_object_mut()
            .unwrap()
            .remove("ts")
            .unwrap()
            .is_string()
    );
    // Exact remaining fields prove the absence of identity, request, decision,
    // attribution, and accidentally serialized policy/token content.
    assert_eq!(
        projected,
        json!({"schema_version":1,"event":event,"kind":"ops",
        "severity":severity,"summary":summary,"addon":"policy-loader","details":details})
    );
    assert_eq!(
        row["details"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        details
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

fn assert_reload(row: &Value, runtime: &Runtime) {
    // Compare with the actual accepted canonical permissions, not a new audit
    // accessor or the number of service definitions/simple host entries.
    let baseline = runtime
        .policy
        .as_ref()
        .unwrap()
        .baseline()
        .unwrap()
        .unwrap();
    let count = baseline["permissions"].as_array().unwrap().len();
    assert!(count > 0);
    assert_event(
        row,
        "ops.policy_reload",
        "medium",
        &format!("Baseline policy reloaded: {count} permissions"),
        json!({"policy_type":"baseline","permissions_count":count}),
    );
}

fn assert_failure(row: &Value, message: Option<&str>) {
    let (summary, error) = match message {
        Some(message) => (format!("Baseline policy load failed: {message}"), message),
        None => (
            "Baseline policy file not found or invalid".into(),
            "File not found or invalid",
        ),
    };
    assert_event(
        row,
        "ops.policy_error",
        "high",
        &summary,
        json!({"policy_type":"baseline","error":error}),
    );
}

fn charge(runtime: &Runtime, now: f64) -> Value {
    let policy = runtime.policy.as_ref().unwrap();
    assert_eq!(
        policy.evaluate(budget_request(), now, true).unwrap().effect,
        Effect::Allow
    );
    policy.budget_stats(now).unwrap()
}

#[test]
fn accepted_policy_events_follow_startup_and_published_h1_snapshots() {
    owned_child(
        "service_catalog_tests::policy_events::accepted_policy_events_follow_startup_and_published_h1_snapshots",
        accepted_workflow(),
    );
}

async fn accepted_workflow() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings(directory.path());
    let user = settings.gateway_services_dir.as_ref().unwrap();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    let rows = drained_audit(&fixture);
    assert_eq!(rows.len(), 2);
    assert_reload(&rows[0], &initial);
    assert_eq!(rows[1]["event"], "ops.startup");
    assert_eq!(rows[1]["addon"], "memory-monitor");
    let now = policy::current_time_ms();
    let budget = charge(&initial, now);
    assert_projection(
        &fixture.read("alice", "GET", TOKEN).await,
        &initial,
        "alice",
    );

    install_catalog(user, true);
    write_json(
        settings.policy_file.as_ref().unwrap(),
        &policy_document(true),
    );
    fixture.proxy.reload(settings.clone()).await.unwrap();
    let explicit = fixture.runtime();
    assert!(!Arc::ptr_eq(&initial, &explicit));
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &explicit, "alice");
    let view = reply.value();
    assert_eq!(view["authorized"]["demo"]["host"], "new.catalog.invalid");
    assert_eq!(view["authorized"]["demo"]["capability"], "writer");
    assert_selected(
        &explicit,
        "alice",
        view["authorized"]["demo"]["token"].as_str().unwrap(),
        "new.catalog.invalid",
        "POST",
        "/v2-write",
    );
    let rows = drained_audit(&fixture);
    let events = policy_events(&rows);
    assert_eq!(events.len(), 2);
    assert_reload(events[1], &explicit);

    install_catalog(user, false);
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let automatic = fixture.runtime();
    assert!(!Arc::ptr_eq(&explicit, &automatic));
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &automatic, "alice");
    let view = reply.value();
    assert_selected(
        &automatic,
        "alice",
        view["authorized"]["demo"]["token"].as_str().unwrap(),
        "new.catalog.invalid",
        "POST",
        "/write",
    );
    let accepted_rows = drained_audit(&fixture);
    let events = policy_events(&accepted_rows);
    assert_eq!(events.len(), 3);
    assert_reload(events[2], &automatic);
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert!(Arc::ptr_eq(&automatic, &fixture.runtime()));

    let invalid_catalog = user.join("03-invalid.yaml");
    std::fs::write(&invalid_catalog, b"schema_version: [").unwrap();
    assert!(fixture.proxy.reload_services_if_changed().await.is_err());
    assert_retained(&fixture, &automatic, &budget, now);
    let rows = drained_audit(&fixture);
    assert!(rows.iter().any(|row| row["event"] == "ops.config_error"));
    assert_eq!(policy_events(&rows), events);
    std::fs::remove_file(invalid_catalog).unwrap();

    let invalid_ca = fixture.directory.path().join("invalid-owned-ca.pem");
    std::fs::write(&invalid_ca, b"owned invalid PEM").unwrap();
    let mut late_failure = settings.clone();
    late_failure.tls_ca_file = Some(invalid_ca);
    assert!(fixture.proxy.reload(late_failure).await.is_err());
    assert_retained(&fixture, &automatic, &budget, now);
    assert_eq!(policy_events(&drained_audit(&fixture)), events);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == reply.body);
    fixture.stop().await;
}

#[test]
fn rejected_policy_events_drain_and_preserve_accepted_state_and_budget() {
    owned_child(
        "service_catalog_tests::policy_events::rejected_policy_events_drain_and_preserve_accepted_state_and_budget",
        rejected_workflow(),
    );
}

async fn rejected_workflow() {
    // Failed startup must drain the error before returning: no Runtime remains
    // available to call wait_for_drain, and memory startup was never reached.
    for invalid in [None, Some(r#"{"permissions":0}"#)] {
        let directory = tempfile::tempdir().unwrap();
        let settings = config(directory.path());
        if let Some(body) = invalid {
            std::fs::write(settings.policy_file.as_ref().unwrap(), body).unwrap();
        }
        let error = Proxy::start(settings.clone()).await.err().unwrap();
        let policy_error = error.downcast_ref::<policy::PolicyError>().unwrap();
        assert_eq!(
            policy_error.kind,
            if invalid.is_some() {
                policy::ErrorKind::Invalid
            } else {
                policy::ErrorKind::Read
            }
        );
        let rows = read_audit(settings.audit_log_path.as_ref().unwrap());
        assert_eq!(rows.len(), 1);
        assert_failure(&rows[0], invalid.map(|_| policy_error.message.as_str()));
        assert!(!settings.readiness_file.exists());
        assert!(!directory.path().join("alice.sock").exists());
    }

    let directory = tempfile::tempdir().unwrap();
    let settings = settings(directory.path());
    let path = settings.policy_file.as_ref().unwrap();
    let user = settings.gateway_services_dir.as_ref().unwrap();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    let now = policy::current_time_ms();
    let budget = charge(&initial, now);
    let original_reply = fixture.read("alice", "GET", TOKEN).await;
    let mut expected_count = 1;
    for (body, kind, processing) in [
        (None, policy::ErrorKind::Read, false),
        (Some("{ invalid policy"), policy::ErrorKind::Invalid, false),
        (
            Some(r#"{"permissions":0}"#),
            policy::ErrorKind::Invalid,
            true,
        ),
    ] {
        if let Some(body) = body {
            std::fs::write(path, body).unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
        let original_error = policy::Policy::from_path(path).err().unwrap();
        let error = fixture.proxy.reload(settings.clone()).await.err().unwrap();
        let policy_error = error.downcast_ref::<policy::PolicyError>().unwrap();
        assert_eq!(policy_error.kind, kind);
        assert_eq!(policy_error.message, original_error.message);
        assert_retained(&fixture, &initial, &budget, now);
        assert!(fixture.read("alice", "GET", TOKEN).await.body == original_reply.body);
        expected_count += 1;
        let rows = drained_audit(&fixture);
        let events = policy_events(&rows);
        assert_eq!(events.len(), expected_count);
        assert_failure(
            events.last().unwrap(),
            processing.then_some(policy_error.message.as_str()),
        );
    }

    std::fs::write(path, b"{ invalid automatic policy").unwrap();
    install_catalog(user, true);
    let error = fixture
        .proxy
        .reload_services_if_changed()
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.downcast_ref::<policy::PolicyError>().unwrap().kind,
        policy::ErrorKind::Invalid
    );
    assert_retained(&fixture, &initial, &budget, now);
    expected_count += 1;
    let rows = drained_audit(&fixture);
    let events = policy_events(&rows);
    assert_eq!(events.len(), expected_count);
    assert_failure(events.last().unwrap(), None);
    write_json(path, &policy_document(true));
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert_eq!(policy_events(&drained_audit(&fixture)), events);
    install_catalog(user, false);
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let recovered = fixture.runtime();
    assert!(!Arc::ptr_eq(&initial, &recovered));
    assert_eq!(
        recovered
            .policy
            .as_ref()
            .unwrap()
            .budget_stats(now)
            .unwrap(),
        budget
    );
    assert_projection(
        &fixture.read("alice", "GET", TOKEN).await,
        &recovered,
        "alice",
    );
    let rows = drained_audit(&fixture);
    let events = policy_events(&rows);
    assert_eq!(events.len(), expected_count + 1);
    assert_reload(events.last().unwrap(), &recovered);
    fixture.stop().await;
}

#[test]
fn poisoned_policy_audit_keeps_successful_publication_and_original_rejection() {
    owned_child(
        "service_catalog_tests::policy_events::poisoned_policy_audit_keeps_successful_publication_and_original_rejection",
        poisoned_workflow(),
    );
}

async fn poisoned_workflow() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings(directory.path());
    let path = settings.policy_file.as_ref().unwrap();
    let user = settings.gateway_services_dir.as_ref().unwrap();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    let now = policy::current_time_ms();
    let budget = charge(&initial, now);
    let before_poison = drained_audit(&fixture);
    initial.audit.poison_for_test();
    install_catalog(user, true);
    write_json(path, &policy_document(true));
    fixture.proxy.reload(settings.clone()).await.unwrap();
    let explicit = fixture.runtime();
    assert!(!Arc::ptr_eq(&initial, &explicit));
    assert!(Arc::ptr_eq(&initial.audit, &explicit.audit));
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &explicit, "alice");
    let view = reply.value();
    assert_eq!(view["authorized"]["demo"]["host"], "new.catalog.invalid");
    assert_eq!(view["authorized"]["demo"]["capability"], "writer");
    assert_selected(
        &explicit,
        "alice",
        view["authorized"]["demo"]["token"].as_str().unwrap(),
        "new.catalog.invalid",
        "POST",
        "/v2-write",
    );

    install_catalog(user, false);
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let automatic = fixture.runtime();
    assert!(!Arc::ptr_eq(&explicit, &automatic));
    assert!(Arc::ptr_eq(&initial.audit, &automatic.audit));
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &automatic, "alice");
    let view = reply.value();
    assert_selected(
        &automatic,
        "alice",
        view["authorized"]["demo"]["token"].as_str().unwrap(),
        "new.catalog.invalid",
        "POST",
        "/write",
    );
    assert_eq!(
        automatic
            .policy
            .as_ref()
            .unwrap()
            .budget_stats(now)
            .unwrap(),
        budget
    );
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());

    std::fs::write(path, b"{ rejected while audit is poisoned").unwrap();
    let original_error = policy::Policy::from_path(path).err().unwrap();
    let error = fixture.proxy.reload(settings.clone()).await.err().unwrap();
    let policy_error = error.downcast_ref::<policy::PolicyError>().unwrap();
    assert_eq!(policy_error.kind, original_error.kind);
    assert_eq!(policy_error.message, original_error.message);
    assert_retained(&fixture, &automatic, &budget, now);
    assert_eq!(
        read_audit(settings.audit_log_path.as_ref().unwrap()),
        before_poison
    );
    // The real writer error is contained; no substitute event producer was
    // installed. Attempt ordering itself is covered by the selected source seam.
    fixture.stop().await;
}
