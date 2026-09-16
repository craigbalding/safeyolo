//! Runtime expiry writes precede publication and refresh accepted watch times.

use super::*;
use std::{os::unix::fs::MetadataExt, time::UNIX_EPOCH};

fn document(expired: Option<&str>, capability: &str, invalid: bool) -> String {
    let expired_host = expired.map_or_else(String::new, |host| {
        format!("'{host}'={{egress='deny',expires=2001-01-01T00:00:00Z}}\n")
    });
    let agent_host = if expired.is_some() {
        "'agent-expired.invalid'={egress='deny',expires=2001-01-01T00:00:00Z}\n"
    } else {
        ""
    };
    let invalid_host = if invalid {
        "'broken.invalid:443'={egress='invalid-owned-effect'}\n"
    } else {
        ""
    };
    format!(
        "# Keep operator heading\nbudget=10\n[hosts]\n\
         '*'={{egress='allow'}}\n\
         'meter.invalid'={{egress='allow',rate=10}}\n\
         'old.catalog.invalid'={{egress='allow',service='demo'}}\n\
         # Keep future denial\n\
         'future.invalid'={{egress='deny',expires=3000-01-01T00:00:00Z}}\n\
         {expired_host}{invalid_host}\
         [agents.alice.hosts]\n{agent_host}\
         [agents.alice.services.demo]\ncapability='{capability}'\n\
         token='synthetic-vault-alice'\naccount='owned-alice'\n"
    )
}

fn stamp(path: &Path, modified: std::time::SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
}

fn assert_pruned(path: &Path, host: &str) {
    let saved = std::fs::read_to_string(path).unwrap();
    assert!(saved.starts_with("# Keep operator heading\n"));
    assert!(saved.contains("# Keep future denial\n"));
    assert!(saved.contains("future.invalid"));
    assert!(!saved.contains(host));
    // D15 is an intentional native correction: source only prunes globals.
    assert!(!saved.contains("agent-expired.invalid"));
}

fn effect(runtime: &Runtime, host: &str, now: f64) -> Effect {
    runtime
        .policy
        .as_ref()
        .unwrap()
        .evaluate(
            NetworkRequest {
                agent: Some("alice"),
                host,
                port: Some(443),
                method: "GET",
                path: "/",
            },
            now,
            false,
        )
        .unwrap()
        .effect
}

fn policy_events(runtime: &Runtime) -> Vec<Value> {
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    std::fs::read_to_string(runtime.config.audit_log_path.as_ref().unwrap())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["addon"] == "policy-loader")
        .collect()
}

#[test]
fn runtime_expiry_persists_before_validation_and_observes_its_own_replacement() {
    owned_child(
        "service_catalog_tests::policy_expiry::runtime_expiry_persists_before_validation_and_observes_its_own_replacement",
        workflow(),
    );
}

async fn workflow() {
    let directory = tempfile::tempdir().unwrap();
    let mut settings = config(directory.path());
    let path = directory.path().join("policy.toml");
    settings.policy_file = Some(path.clone());
    let builtin = directory.path().join("builtin");
    let user = directory.path().join("user");
    std::fs::create_dir(&builtin).unwrap();
    std::fs::create_dir(&user).unwrap();
    install_catalog(&builtin, false);
    settings.gateway_builtin_services_dir = Some(builtin);
    settings.gateway_services_dir = Some(user.clone());
    let addons = directory.path().join("addons.yaml");
    let addon_text =
        r#"{"addons":{"request_logger":{"quiet_hosts":{"hosts":["quiet.owned.invalid"]}}}}"#;
    std::fs::write(&addons, addon_text).unwrap();
    stamp(&addons, UNIX_EPOCH + Duration::from_secs(500));
    std::fs::write(
        &path,
        document(Some("startup-expired.invalid"), "reader", false),
    )
    .unwrap();
    let mut fixture = Fixture::start(directory, settings.clone()).await;
    let initial = fixture.runtime();
    assert_pruned(&path, "startup-expired.invalid");
    assert_eq!(std::fs::read_to_string(&addons).unwrap(), addon_text);
    assert_eq!(
        initial
            .policy
            .as_ref()
            .unwrap()
            .baseline()
            .unwrap()
            .unwrap()["addons"]["request_logger"]["quiet_hosts"]["hosts"],
        json!(["quiet.owned.invalid"])
    );
    let now = policy::current_time_ms();
    for host in ["startup-expired.invalid", "agent-expired.invalid"] {
        assert_eq!(effect(&initial, host, now), Effect::Allow);
    }
    assert_eq!(effect(&initial, "future.invalid", now), Effect::Deny);
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
    assert_projection(
        &fixture.read("alice", "GET", TOKEN).await,
        &initial,
        "alice",
    );
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    let service_key = fixture.proxy.service_files.clone();

    // A newer authored file reaches the watcher. Successful pruning writes a
    // current mtime, and the accepted policy observes that exact replacement.
    let newer = std::fs::metadata(&path).unwrap().modified().unwrap() + Duration::from_secs(2);
    std::fs::write(
        &path,
        document(Some("watch-expired.invalid"), "writer", false),
    )
    .unwrap();
    stamp(&path, newer);
    assert!(fixture.proxy.reload_policy_if_changed().await.unwrap());
    let watched = fixture.runtime();
    assert!(!Arc::ptr_eq(&initial, &watched));
    assert_pruned(&path, "watch-expired.invalid");
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert!(Arc::ptr_eq(&watched, &fixture.runtime()));
    assert!(fixture.proxy.service_files == service_key);
    for retained in [
        Arc::ptr_eq(&initial.audit, &watched.audit),
        Arc::ptr_eq(&initial.events, &watched.events),
        Arc::ptr_eq(&initial.traces, &watched.traces),
        Arc::ptr_eq(&initial.memory_monitor, &watched.memory_monitor),
        Arc::ptr_eq(&initial.flow_recorder, &watched.flow_recorder),
    ] {
        assert!(retained);
    }
    assert_eq!(
        watched.policy.as_ref().unwrap().budget_stats(now).unwrap(),
        budget
    );
    let watched_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&watched_reply, &watched, "alice");
    assert_eq!(
        watched_reply.value()["authorized"]["demo"]["capability"],
        "writer"
    );

    // An accepted explicit no-op expiry load retains bytes/inode/mtime. A
    // deliberately old accepted watermark makes the later retry proof finite.
    let authored = document(None, "writer", false);
    std::fs::write(&path, &authored).unwrap();
    stamp(&path, UNIX_EPOCH + Duration::from_secs(1000));
    let metadata = std::fs::metadata(&path).unwrap();
    fixture.proxy.reload(settings.clone()).await.unwrap();
    let accepted = fixture.runtime();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), authored);
    let unchanged = std::fs::metadata(&path).unwrap();
    assert_eq!(unchanged.ino(), metadata.ino());
    assert_eq!(unchanged.modified().unwrap(), metadata.modified().unwrap());
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    let accepted_reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&accepted_reply, &accepted, "alice");
    let accepted_key = fixture.proxy.service_files.clone();
    let deadline = fixture.proxy.policy_check_at;

    // The real disk prune precedes the deliberately invalid endpoint effect.
    // Preparation failure retains the old complete runtime and observation.
    std::fs::write(
        &path,
        document(Some("rejected-expired.invalid"), "reader", true),
    )
    .unwrap();
    stamp(&path, UNIX_EPOCH + Duration::from_secs(2000));
    let error = fixture.proxy.reload(settings.clone()).await.err().unwrap();
    let error = error.downcast_ref::<policy::PolicyError>().unwrap();
    assert_eq!(error.kind, policy::ErrorKind::Invalid);
    let message = error.message.clone();
    assert_pruned(&path, "rejected-expired.invalid");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("broken.invalid:443")
    );
    assert_retained(&fixture, &accepted, &budget, now);
    assert!(fixture.proxy.service_files == accepted_key);
    assert_eq!(fixture.proxy.policy_check_at, deadline);
    assert!(fixture.read("alice", "GET", TOKEN).await.body == accepted_reply.body);
    let rejected_disk = std::fs::read_to_string(&path).unwrap();
    let rejected_metadata = std::fs::metadata(&path).unwrap();
    for _ in 0..2 {
        assert!(fixture.proxy.reload_policy_if_changed().await.is_err());
        assert_retained(&fixture, &accepted, &budget, now);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), rejected_disk);
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.ino(), rejected_metadata.ino());
        assert_eq!(
            metadata.modified().unwrap(),
            rejected_metadata.modified().unwrap()
        );
    }
    let rows = policy_events(&accepted);
    assert_eq!(
        rows.iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "ops.policy_reload",
            "ops.policy_reload",
            "ops.policy_reload",
            "ops.policy_error",
            "ops.policy_error",
            "ops.policy_error"
        ]
    );
    for row in &rows[3..] {
        assert_eq!(
            row["details"],
            json!({"policy_type":"baseline","error":message})
        );
    }

    // A changed catalog reaches the same runtime-only loader, repairs the
    // policy, and captures its new replacement mtime before publication.
    install_catalog(&user, true);
    std::fs::write(
        &path,
        document(Some("catalog-expired.invalid"), "writer", false),
    )
    .unwrap();
    assert!(fixture.proxy.reload_services_if_changed().await.unwrap());
    let recovered = fixture.runtime();
    assert_pruned(&path, "catalog-expired.invalid");
    assert!(!Arc::ptr_eq(&accepted, &recovered));
    assert_eq!(
        recovered
            .policy
            .as_ref()
            .unwrap()
            .budget_stats(now)
            .unwrap(),
        budget
    );
    assert!(Arc::ptr_eq(&accepted.audit, &recovered.audit));
    assert!(Arc::ptr_eq(&accepted.events, &recovered.events));
    let reply = fixture.read("alice", "GET", TOKEN).await;
    assert_projection(&reply, &recovered, "alice");
    let view = reply.value();
    assert_selected(
        &recovered,
        "alice",
        view["authorized"]["demo"]["token"].as_str().unwrap(),
        "old.catalog.invalid",
        "POST",
        "/v2-write",
    );
    assert!(!fixture.proxy.reload_policy_if_changed().await.unwrap());
    assert!(!fixture.proxy.reload_services_if_changed().await.unwrap());
    assert_eq!(policy_events(&recovered).len(), 7);
    assert_eq!(policy_events(&recovered)[6]["event"], "ops.policy_reload");
    assert_eq!(std::fs::read_to_string(&addons).unwrap(), addon_text);
    fixture.stop().await;
}
