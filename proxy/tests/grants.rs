use ring::digest::{SHA256, digest};
use safeyolo_proxy::{approvals::ErrorKind, contracts::ContractBinding, grants::*};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier},
};
use time::{Duration, OffsetDateTime};

const SOURCE: &str = "# operator heading\n[hosts]\n'*'={egress='prompt'} # keep host comment\n[agents.alice]\nfolder='/work/alice' # keep agent comment\n[agents.alice.services.gmail]\ncapability='read_messages' # keep service comment\n[agents.bob]\nfolder='/work/bob'\n";
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1704067200).unwrap()
}
fn validate(source: &str) -> Result<(), String> {
    source
        .parse::<toml_edit::DocumentMut>()
        .map(|_| ())
        .map_err(|error| error.to_string())
}
fn setup(source: &str) -> (tempfile::TempDir, PathBuf, Store) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    fs::write(&path, source).unwrap();
    let store = Store::open(path.clone(), now()).unwrap();
    (directory, path, store)
}

#[test]
fn unchanged_reload_skips_activation_and_policy_rewrite() {
    let (_directory, path, store) = setup(SOURCE);
    let before = fs::metadata(&path).unwrap();
    let original = fs::read(&path).unwrap();
    let mut activations = 0;

    store
        .reload(now(), |_| {
            activations += 1;
            Ok(())
        })
        .unwrap();

    assert_eq!(activations, 0);
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
}

fn request(agent: &str, scope: GrantScope) -> GrantRequest {
    GrantRequest {
        agent: agent.into(),
        service: "gmail".into(),
        method: "DELETE".into(),
        path: "/messages/*".into(),
        scope,
    }
}
fn scope(agent: &str) -> RequestScope<'_> {
    RequestScope {
        agent,
        service: "gmail",
        method: "delete",
        path: "/messages/42",
    }
}
fn binding(agent: &str) -> ContractBinding {
    serde_json::from_value(json!({"agent":agent,"service":"gmail","capability":"read_messages","template":"gmail.read_messages.v1","bound_values":{"approved_category":"CATEGORY_PROMOTIONS"},"grantable_operations":["list_messages"]})).unwrap()
}

#[test]
fn legacy_optional_fields_get_stable_durable_identity_before_admission() {
    for inline in [false, true] {
        for omitted in 0..16 {
            let mut fields = vec!["service='gmail'", "method='DELETE'", "path='/messages/*'"];
            for (bit, field) in [
                "grant_id='fixed'",
                "created='2024-01-01T00:00:00Z'",
                "expires='2024-01-01T01:00:00Z'",
                "scope='once'",
            ]
            .into_iter()
            .enumerate()
            {
                if omitted & (1 << bit) == 0 {
                    fields.push(field);
                }
            }
            let source = if inline {
                format!(
                    "# keep\n[agents.alice]\ngrants=[{{{}}}]\n",
                    fields.join(",")
                )
            } else {
                format!("# keep\n[[agents.alice.grants]]\n{}\n", fields.join("\n"))
            };
            let (_directory, path, store) = setup(&source);
            let normalized = fs::read_to_string(&path).unwrap();
            assert!(normalized.starts_with("# keep"));
            let listed = store.list_grants_for_agent("alice", now()).unwrap();
            assert_eq!(listed.len(), 1);
            let id = listed[0].grant.grant_id.clone();
            assert!(normalized.contains(&id));
            let lease = store
                .check_grant(scope("alice"), now(), validate)
                .unwrap()
                .unwrap();
            assert_eq!(lease.grant().grant_id, id);
            store
                .reload(now() + Duration::milliseconds(1), validate)
                .unwrap();
            assert!(
                store
                    .check_grant(scope("alice"), now() + Duration::milliseconds(2), validate)
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .check_grant(scope("bob"), now(), validate)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                store
                    .finish_response(
                        lease,
                        Some(200),
                        now() + Duration::milliseconds(3),
                        validate
                    )
                    .unwrap(),
                ResponseOutcome::Consumed
            );
            assert!(
                store
                    .check_grant(scope("alice"), now() + Duration::milliseconds(4), validate)
                    .unwrap()
                    .is_none()
            );
            assert!(
                Store::open(path, now())
                    .unwrap()
                    .list_grants_for_agent("alice", now())
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn failed_legacy_normalization_does_not_publish_a_lease_or_partial_metadata() {
    let (_directory, path, store) = setup(SOURCE);
    let original = format!(
        "{SOURCE}\n[[agents.alice.grants]]\nservice='gmail'\nmethod='DELETE'\npath='/messages/*'\n"
    );
    fs::write(&path, &original).unwrap();
    let mut activations = 0;
    let error = store
        .check_grant(scope("alice"), now(), |_| {
            activations += 1;
            if activations == 1 {
                Err("synthetic activation failure".into())
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
    assert_eq!(error.kind, ErrorKind::Activation);
    assert_eq!(activations, 2);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    assert!(
        store
            .list_grants_for_agent("alice", now())
            .unwrap()
            .is_empty()
    );
    let lease = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    let id = lease.grant().grant_id.clone();
    drop(lease);
    assert!(store.revoke_grant("alice", &id, now(), validate).unwrap());
    assert!(
        Store::open(path, now())
            .unwrap()
            .list_grants_for_agent("alice", now())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn legacy_binding_ids_remain_revocable_across_restart() {
    let source = "[agents.alice]\ncontract_bindings=[{service='gmail',capability='read_messages',bound_values={label='approved'}}]\n";
    let (_directory, path, store) = setup(source);
    let first = store
        .binding_for_agent("alice", "gmail", "read_messages")
        .unwrap()
        .unwrap();
    let restarted = Store::open(&path, now() + Duration::seconds(1)).unwrap();
    let next = restarted
        .binding_for_agent("alice", "gmail", "read_messages")
        .unwrap()
        .unwrap();
    assert_eq!(first.binding.binding_id, next.binding.binding_id);
    assert_eq!(first.created, next.created);
    assert!(
        restarted
            .revoke_binding("alice", &first.binding.binding_id, now(), validate)
            .unwrap()
    );
    assert!(
        Store::open(path, now())
            .unwrap()
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .is_none()
    );
}

#[test]
fn scopes_have_default_ttl_and_explicit_durability() {
    let (_directory, path, store) = setup(SOURCE);
    for scope in [
        GrantScope::Once,
        GrantScope::Session,
        GrantScope::Remembered,
    ] {
        let added = store
            .add_grant(request("alice", scope), now(), validate)
            .unwrap();
        assert_eq!(
            added.persistence,
            if scope == GrantScope::Session {
                Persistence::SessionOnly
            } else {
                Persistence::Durable
            }
        );
        assert!(!added.grant.is_expired(now() + Duration::seconds(3599)));
        assert!(added.grant.is_expired(now() + Duration::hours(1)));
    }
    assert_eq!(
        store.list_grants_for_agent("alice", now()).unwrap().len(),
        3
    );
    let restarted = Store::open(&path, now()).unwrap();
    assert_eq!(
        restarted
            .list_grants_for_agent("alice", now())
            .unwrap()
            .len(),
        2
    );
    assert!(
        restarted
            .list_grants_for_agent("bob", now())
            .unwrap()
            .is_empty()
    );
    let unknown = store
        .add_grant(request("unknown", GrantScope::Remembered), now(), validate)
        .unwrap();
    assert_eq!(unknown.persistence, Persistence::AgentNotConfigured);
    assert!(!fs::read_to_string(&path).unwrap().contains("unknown"));
    assert_eq!(
        GrantScope::from_admin_lifetime(&json!(300)).unwrap(),
        GrantScope::Session
    );
    assert_eq!(
        GrantScope::from_admin_lifetime(&json!(true)).unwrap(),
        GrantScope::Session
    );
    assert!(GrantScope::from_admin_lifetime(&json!(300.5)).is_err());
}

#[test]
fn configured_ttl_and_matching_preserve_current_method_and_path_rules() {
    let (_directory, _path, store) = setup(&format!("[gateway]\ngrant_ttl_seconds=2.9\n{SOURCE}"));
    let grant = store
        .add_grant(request("alice", GrantScope::Remembered), now(), validate)
        .unwrap()
        .grant;
    assert!(grant.matches(scope("alice"), now()));
    assert!(!grant.matches(scope("bob"), now()));
    for (service, method, path) in [
        ("other", "DELETE", "/messages/42"),
        ("gmail", "GET", "/messages/42"),
        ("gmail", "DELETE", "/MESSAGES/42"),
        ("gmail", "DELETE", "/messages"),
    ] {
        assert!(!grant.matches(
            RequestScope {
                agent: "alice",
                service,
                method,
                path
            },
            now()
        ));
    }
    assert!(grant.is_expired(now() + Duration::seconds(2)));
    let mut star = grant.clone();
    star.method = "*".into();
    assert!(!star.matches(scope("alice"), now()));
    star.expires = "malformed".into();
    assert!(star.is_expired(now()));
}

#[test]
fn once_lease_consumes_only_success_and_cancellation_releases_its_own_reservation() {
    let (_directory, path, store) = setup(SOURCE);
    let added = store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let first = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .check_grant(scope("bob"), now(), validate)
            .unwrap()
            .is_none()
    );
    drop(first);
    for status in [None, Some(199), Some(300), Some(403), Some(500)] {
        let lease = store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .unwrap();
        assert_eq!(lease.grant().grant_id, added.grant.grant_id);
        assert_eq!(
            store
                .finish_response(lease, status, now(), validate)
                .unwrap(),
            ResponseOutcome::Retained
        );
    }
    let lease = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .finish_response(lease, Some(299), now(), validate)
            .unwrap(),
        ResponseOutcome::Consumed
    );
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
    assert!(
        !fs::read_to_string(&path)
            .unwrap()
            .contains(&added.grant.grant_id)
    );
}

#[test]
fn two_concurrent_requests_cannot_use_one_once_approval() {
    let (_directory, _path, store) = setup(SOURCE);
    store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let lease = store.check_grant(scope("alice"), now(), validate).unwrap();
                barrier.wait();
                lease
            })
        })
        .collect();
    let leases: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(leases.len(), 1);
    drop(leases);
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_some()
    );
}

#[test]
fn old_lease_cannot_consume_or_release_replacement_after_revoke_or_reload() {
    let (_directory, path, store) = setup(SOURCE);
    let first = store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let old = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    assert!(
        store
            .revoke_grant("alice", &first.grant.grant_id, now(), validate)
            .unwrap()
    );
    let replacement = store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let current = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .finish_response(old, Some(200), now(), validate)
            .unwrap(),
        ResponseOutcome::Stale
    );
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
    assert_eq!(current.grant().grant_id, replacement.grant.grant_id);
    store.reload(now(), validate).unwrap();
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
    drop(current);
    let old = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    // A changed persisted record with the same ID is a different approval.
    let mut document = fs::read_to_string(&path)
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    document["agents"]["alice"]["grants"]
        .as_array_of_tables_mut()
        .unwrap()
        .get_mut(0)
        .unwrap()["expires"] = toml_edit::value("2099-01-01T00:00:00Z");
    fs::write(&path, document.to_string()).unwrap();
    store.reload(now(), validate).unwrap();
    let newer = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    drop(old);
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .finish_response(newer, Some(204), now(), validate)
            .unwrap(),
        ResponseOutcome::Consumed
    );
}

#[test]
fn rollback_restores_exact_text_and_successful_action_does_not_regain_a_once_grant() {
    let (_directory, path, store) = setup(SOURCE);
    let original = fs::read_to_string(&path).unwrap();
    let mut calls = 0;
    let error = store
        .add_grant(request("alice", GrantScope::Once), now(), |_| {
            calls += 1;
            if calls == 1 {
                Err("candidate rejected".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Activation);
    assert_eq!(calls, 2);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    assert!(
        store
            .list_grants_for_agent("alice", now())
            .unwrap()
            .is_empty()
    );
    store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let lease = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    let mut calls = 0;
    let error = store
        .finish_response(lease, Some(200), now(), |_| {
            calls += 1;
            if calls == 1 {
                Err("consume rejected".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Activation);
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
    store.reload(now(), validate).unwrap();
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );
}

#[test]
fn successful_admitted_request_consumes_after_expiry_but_new_requests_cannot_match() {
    let (_directory, path, store) = setup(SOURCE);
    store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let lease = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    assert!(
        store
            .check_grant(scope("alice"), now() + Duration::hours(2), validate)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .finish_response(lease, Some(200), now() + Duration::hours(2), validate)
            .unwrap(),
        ResponseOutcome::Consumed
    );
    assert!(
        Store::open(&path, now())
            .unwrap()
            .list_grants_for_agent("alice", now())
            .unwrap()
            .is_empty()
    );
    let grant = store
        .add_grant(request("alice", GrantScope::Remembered), now(), validate)
        .unwrap()
        .grant;
    assert!(
        store
            .list_grants_for_agent("alice", now() + Duration::hours(2))
            .unwrap()[0]
            .expired
    );
    assert!(
        store
            .check_grant(scope("alice"), now() + Duration::hours(2), validate)
            .unwrap()
            .is_none()
    );
    assert!(!fs::read_to_string(&path).unwrap().contains(&grant.grant_id));
}

#[test]
fn expired_snapshot_cannot_delete_an_externally_renewed_grant() {
    let (_directory, path, store) = setup(SOURCE);
    store
        .add_grant(request("alice", GrantScope::Remembered), now(), validate)
        .unwrap();
    let source = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        source.replace("2024-01-01T01:00:00Z", "2024-01-01T03:00:00Z"),
    )
    .unwrap();
    let lease = store
        .check_grant(scope("alice"), now() + Duration::hours(2), validate)
        .unwrap()
        .unwrap();
    assert_eq!(lease.grant().expires, "2024-01-01T03:00:00Z");
    assert!(
        fs::read_to_string(path)
            .unwrap()
            .contains("2024-01-01T03:00:00Z")
    );
}

#[test]
fn binding_numbers_keep_types_and_unsupported_toml_integers_fail_before_publication() {
    let (_directory, path, store) = setup(SOURCE);
    let mut input = binding("alice");
    input.bound_values = json!({
        "integer":137,"minimum":i64::MIN,"maximum":i64::MAX,
        "float":2.5,"array":[1,2.5,true,{"nested":3}],
        "authored_object":{"$serde_json::private::Number":"123"}
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(input.bound_values["authored_object"].is_object());
    assert_eq!(
        input.bound_values["authored_object"]["$serde_json::private::Number"],
        json!("123")
    );
    store
        .approve_binding(input.clone(), now(), validate)
        .unwrap();
    let saved = fs::read_to_string(&path).unwrap();
    assert!(saved.contains("integer = 137"));
    let restarted = Store::open(&path, now()).unwrap();
    assert!(
        restarted
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .unwrap()
            .binding
            .bound_values["authored_object"]
            .is_object()
    );
    assert_eq!(
        restarted
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .unwrap()
            .binding
            .bound_values,
        input.bound_values
    );
    for unsupported in ["9223372036854775808", "18446744073709551617"] {
        let mut too_big = input.clone();
        too_big
            .bound_values
            .insert("integer".into(), serde_json::from_str(unsupported).unwrap());
        assert_eq!(
            store
                .approve_binding(too_big, now(), validate)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), saved);
        assert_eq!(
            store
                .binding_for_agent("alice", "gmail", "read_messages")
                .unwrap()
                .unwrap()
                .binding
                .bound_values,
            input.bound_values
        );
        // Python tomlkit persists these integers exactly. Their authored reload
        // remains a retained-workflow gap until the shared TOML parser is lossless.
        fs::write(
            &path,
            saved.replace("integer = 137", &format!("integer = {unsupported}")),
        )
        .unwrap();
        assert!(store.reload(now(), validate).is_err());
        assert_eq!(
            store
                .binding_for_agent("alice", "gmail", "read_messages")
                .unwrap()
                .unwrap()
                .binding
                .bound_values,
            input.bound_values
        );
        fs::write(&path, &saved).unwrap();
        assert_eq!(
            GrantScope::from_admin_lifetime(&serde_json::from_str(unsupported).unwrap()).unwrap(),
            GrantScope::Session
        );
    }
    let mut null = input;
    null.bound_values.insert("invalid".into(), Value::Null);
    assert_eq!(
        store
            .approve_binding(null, now(), validate)
            .unwrap_err()
            .kind,
        ErrorKind::Invalid
    );
    assert_eq!(fs::read_to_string(path).unwrap(), saved);
}

#[test]
fn binding_upsert_revoke_reload_and_comments_remain_scoped() {
    let (_directory, path, store) = setup(SOURCE);
    let first = store
        .approve_binding(binding("alice"), now(), validate)
        .unwrap();
    assert_eq!(first.persistence, Persistence::Durable);
    assert!(
        store
            .binding_for_agent("bob", "gmail", "read_messages")
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .binding_for_agent("alice", "slack", "read_messages")
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .revoke_binding("bob", &first.binding.binding.binding_id, now(), validate)
            .unwrap()
    );
    let mut changed = binding("alice");
    changed.template = "updated-template".into();
    changed
        .bound_values
        .insert("approved_category".into(), json!("CATEGORY_SOCIAL"));
    let replacement = store.approve_binding(changed, now(), validate).unwrap();
    assert_ne!(
        first.binding.binding.binding_id,
        replacement.binding.binding.binding_id
    );
    let source = fs::read_to_string(&path).unwrap();
    for comment in [
        "# operator heading",
        "# keep host comment",
        "# keep agent comment",
        "# keep service comment",
    ] {
        assert!(source.contains(comment));
    }
    assert!(!source.contains(&first.binding.binding.binding_id));
    let restarted = Store::open(&path, now()).unwrap();
    let current = restarted
        .binding_for_agent("alice", "gmail", "read_messages")
        .unwrap()
        .unwrap();
    assert_eq!(current.binding.template, "updated-template");
    assert!(
        restarted
            .revoke_binding("alice", &current.binding.binding_id, now(), validate)
            .unwrap()
    );
    store.reload(now(), validate).unwrap();
    assert!(
        store
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .is_none()
    );
    let session = store
        .add_grant(request("alice", GrantScope::Session), now(), validate)
        .unwrap();
    store.reload(now(), validate).unwrap();
    assert!(
        store
            .list_grants_for_agent("alice", now())
            .unwrap()
            .iter()
            .any(|grant| grant.grant.grant_id == session.grant.grant_id)
    );
}

#[test]
fn invalid_binding_reload_and_activation_do_not_publish_partial_state() {
    let (_directory, path, store) = setup(SOURCE);
    let original = store
        .approve_binding(binding("alice"), now(), validate)
        .unwrap();
    let before = fs::read_to_string(&path).unwrap();
    let mut changed = binding("alice");
    changed
        .bound_values
        .insert("approved_category".into(), json!("CATEGORY_SOCIAL"));
    let mut calls = 0;
    assert!(
        store
            .approve_binding(changed, now(), |_| {
                calls += 1;
                if calls == 1 {
                    Err("bad candidate".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    fs::write(&path,format!("{before}\n[[agents.alice.contract_bindings]]\nservice='gmail'\ncapability='read_messages'\nbound_values='invalid'\n")).unwrap();
    assert!(store.reload(now(), validate).is_err());
    assert_eq!(
        store
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .unwrap()
            .binding
            .binding_id,
        original.binding.binding.binding_id
    );
}

#[test]
fn inline_tables_and_concurrent_writers_preserve_unrelated_edits() {
    let (_directory, path, store) =
        setup("# inline policy\n[agents]\nalice={folder='/alice'}\nbob={folder='/bob'}\n");
    store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    store
        .approve_binding(binding("alice"), now(), validate)
        .unwrap();
    assert_eq!(
        Store::open(&path, now())
            .unwrap()
            .list_grants_for_agent("alice", now())
            .unwrap()
            .len(),
        1
    );
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(path, now()).unwrap();
                barrier.wait();
                store
                    .add_grant(
                        request(
                            if index % 2 == 0 { "alice" } else { "bob" },
                            GrantScope::Remembered,
                        ),
                        now(),
                        validate,
                    )
                    .unwrap()
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let fresh = Store::open(&path, now()).unwrap();
    assert_eq!(
        fresh.list_grants_for_agent("alice", now()).unwrap().len(),
        5
    );
    assert_eq!(fresh.list_grants_for_agent("bob", now()).unwrap().len(), 4);
    assert!(
        fresh
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .is_some()
    );
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("# inline policy")
    );
}

fn python_command(script: &str) -> std::process::Command {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut command = std::process::Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    );
    command.args(["-c", script]).env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    );
    command
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn differential_persisted_lifecycle_and_controlled_once_reuse() {
    use std::{io::Write, process::Stdio};
    let mut cases = Vec::new();
    let mut native_matches = Vec::new();
    for pattern in [
        "/messages/*",
        "/messages/**",
        "/messages/{id}",
        "/MESSAGES/*",
        "/messages/x",
        "*",
    ] {
        for agent in ["alice", "bob"] {
            for service in ["gmail", "Gmail"] {
                for method in ["DELETE", "delete", "GET", "*"] {
                    for path in [
                        "/messages/x",
                        "/messages/x/y",
                        "/messages",
                        "/MESSAGES/x",
                        "/messages/%78",
                        "/messages/../x",
                    ] {
                        let grant = Grant {
                            grant_id: "grt_synthetic".into(),
                            agent: "alice".into(),
                            service: "gmail".into(),
                            method: "DELETE".into(),
                            path: pattern.into(),
                            scope: GrantScope::Once,
                            created: "2024-01-01T00:00:00Z".into(),
                            expires: "2024-01-01T01:00:00Z".into(),
                        };
                        native_matches.push(grant.matches(
                            RequestScope {
                                agent,
                                service,
                                method,
                                path,
                            },
                            now(),
                        ));
                        cases.push(json!({"grant":grant,"request":[agent,service,method,path]}));
                    }
                }
            }
        }
    }
    let statuses = [
        None,
        Some(199),
        Some(200),
        Some(204),
        Some(299),
        Some(300),
        Some(403),
        Some(500),
    ];
    let mut native_responses = Vec::new();
    for lifetime in [
        GrantScope::Once,
        GrantScope::Session,
        GrantScope::Remembered,
    ] {
        for status in statuses {
            let (_directory, _path, store) = setup(SOURCE);
            store
                .add_grant(request("alice", lifetime), now(), validate)
                .unwrap();
            let lease = store
                .check_grant(scope("alice"), now(), validate)
                .unwrap()
                .unwrap();
            store
                .finish_response(lease, status, now(), validate)
                .unwrap();
            native_responses.push(
                !store
                    .list_grants_for_agent("alice", now())
                    .unwrap()
                    .is_empty(),
            );
        }
    }
    let expiries = [
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:01Z",
        "2023-12-31T23:59:59Z",
        "2024-01-01T00:00:01",
        "2024-01-01T01:00:00+01:00",
        "2024-01-01",
        "malformed",
        "2024-W01-1T00:00:01",
    ];
    let native_expiries: Vec<_> = expiries
        .iter()
        .map(|expires| {
            let mut grant: Grant = serde_json::from_value(cases[0]["grant"].clone()).unwrap();
            grant.expires = (*expires).into();
            grant.is_expired(now())
        })
        .collect();
    let input = json!({"cases":cases,"statuses":statuses,"source":SOURCE,"expiries":expiries});
    let script = r#"
import json,sys,tempfile
from pathlib import Path
from datetime import datetime,UTC
from types import SimpleNamespace
from unittest.mock import patch
import tomlkit
from mitmproxy import http
from mitmproxy.test import tflow
import safeyolo.mitm_addons.service_gateway as module
from safeyolo.policy import toml_roundtrip
x=json.load(sys.stdin)
class Frozen(datetime):
 @classmethod
 def now(cls,tz=None): return cls(2024,1,1,tzinfo=UTC)
module.datetime=Frozen
module.write_event=lambda *a,**kw:None
module.ctx=SimpleNamespace(options=SimpleNamespace(gateway_enabled=True))
def gateway(path):
 g=module.ServiceGateway();g._get_policy_path=lambda:path;return g
def respond(g,grant,status):
 flow=tflow.tflow();flow.metadata['gateway_grant_id']=grant.grant_id
 flow.response=http.Response.make(status) if status is not None else None
 g.response(flow)
def add_binding(g,agent='alice',number=137):
 return g.add_contract_binding(agent,'gmail','read_messages','gmail.read_messages.v1',{'number':number},['list_messages'])
out={'matches':[module.GrantEntry(**case['grant']).matches(*case['request']) for case in x['cases']]}
out['expiries']=[module.GrantEntry(**{**x['cases'][0]['grant'],'expires':expiry}).is_expired() for expiry in x['expiries']]
with tempfile.TemporaryDirectory(prefix='safeyolo-grants-oracle-') as directory:
 path=Path(directory)/'policy.toml'
 responses=[]
 for lifetime in ['once','session','remembered']:
  for status in x['statuses']:
   path.write_text(x['source']);g=gateway(path)
   grant=g.add_grant('alice','gmail','DELETE','/messages/*',lifetime)
   respond(g,grant,status);responses.append(bool(g._grants))
 out['responses']=responses
 path.write_text(x['source']);g=gateway(path)
 grant=g.add_grant('alice','gmail','DELETE','/messages/*','once')
 first=g._check_grant('alice','gmail','DELETE','/messages/1')
 second=g._check_grant('alice','gmail','DELETE','/messages/2')
 out['old_once_reuse']={'admissions':int(first is not None)+int(second is not None),'same_id':first.grant_id==second.grant_id}
 respond(g,first,200);out['old_once_reuse']['remaining_after_first_2xx']=len(g._grants)
 respond(g,second,200);out['old_once_reuse']['remaining_after_second_2xx']=len(g._grants)
 path.write_text(x['source']);g=gateway(path)
 grants=[g.add_grant('alice','gmail','DELETE','/messages/'+scope,scope) for scope in ['once','session','remembered']]
 unknown=g.add_grant('unknown','gmail','DELETE','/messages/*','remembered')
 add_binding(g);current=add_binding(g,number=138);add_binding(g,'bob',139)
 fresh=gateway(path);fresh._load_grants_from_policy();fresh._load_contract_bindings_from_policy()
 out['workflow']={'ttls':[(datetime.fromisoformat(v.expires)-datetime.fromisoformat(v.created)).total_seconds() for v in grants], 'restarted_scopes':sorted(v.scope for v in fresh._grants.values()), 'unknown_persisted':unknown.grant_id in fresh._grants,'alice_number':fresh.get_contract_binding('alice','gmail','read_messages').bound_values['number'],'bob_number':fresh.get_contract_binding('bob','gmail','read_messages').bound_values['number'],'other_capability':fresh.get_contract_binding('alice','gmail','other') is not None}
 # Existing loaders accumulate stale records. Native reload intentionally treats
 # the persisted document as authoritative, while retaining live sessions.
 path.write_text(x['source']);g._load_grants_from_policy();g._load_contract_bindings_from_policy()
 out['old_reload_retains_revoked']={'grant':grants[0].grant_id in g._grants,'binding':g.get_contract_binding('alice','gmail','read_messages') is not None}
 out['old_big_integer_roundtrips']=[]
 for number in [2**63,2**64+1]:
  add_binding(g,number=number);fresh=gateway(path);fresh._load_contract_bindings_from_policy()
  out['old_big_integer_roundtrips'].append(fresh.get_contract_binding('alice','gmail','read_messages').bound_values['number'])
 path.write_text(x['source']);g=gateway(path)
 with patch.object(toml_roundtrip,'save_roundtrip',side_effect=OSError('synthetic write failure')):
  try:g.add_grant('alice','gmail','DELETE','/messages/*')
  except OSError:out['failed_save_keeps_memory_empty']=not g._grants
json.dump(out,sys.stdout)
"#;
    let mut child = python_command(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        serde_json::to_value(native_matches).unwrap(),
        expected["matches"]
    );
    assert_eq!(
        serde_json::to_value(native_responses).unwrap(),
        expected["responses"]
    );
    assert_eq!(
        serde_json::to_value(native_expiries).unwrap(),
        expected["expiries"]
    );
    assert_eq!(
        expected["old_once_reuse"],
        json!({"admissions":2,"same_id":true,"remaining_after_first_2xx":0,"remaining_after_second_2xx":0})
    );
    let (_directory, _path, store) = setup(SOURCE);
    store
        .add_grant(request("alice", GrantScope::Once), now(), validate)
        .unwrap();
    let first = store
        .check_grant(scope("alice"), now(), validate)
        .unwrap()
        .unwrap();
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none(),
        "intentional fix: a pending once request reserves the approval"
    );
    store
        .finish_response(first, Some(200), now(), validate)
        .unwrap();
    assert!(
        store
            .check_grant(scope("alice"), now(), validate)
            .unwrap()
            .is_none()
    );

    let (_directory, path, store) = setup(SOURCE);
    let mut ttls = Vec::new();
    for lifetime in [
        GrantScope::Once,
        GrantScope::Session,
        GrantScope::Remembered,
    ] {
        let added = store
            .add_grant(request("alice", lifetime), now(), validate)
            .unwrap();
        let created = OffsetDateTime::parse(
            &added.grant.created,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let expires = OffsetDateTime::parse(
            &added.grant.expires,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        ttls.push((expires - created).whole_seconds() as f64);
    }
    store
        .add_grant(request("unknown", GrantScope::Remembered), now(), validate)
        .unwrap();
    for (agent, number) in [("alice", 137), ("alice", 138), ("bob", 139)] {
        let mut value = binding(agent);
        value.bound_values = serde_json::from_value(json!({"number":number})).unwrap();
        store.approve_binding(value, now(), validate).unwrap();
    }
    let fresh = Store::open(&path, now()).unwrap();
    let mut scopes: Vec<_> = fresh
        .list_grants_for_agent("alice", now())
        .unwrap()
        .into_iter()
        .map(|grant| serde_json::to_value(grant.grant.scope).unwrap())
        .collect();
    scopes.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    let native_workflow = json!({"ttls":ttls,"restarted_scopes":scopes,"unknown_persisted":!fresh.list_grants_for_agent("unknown", now()).unwrap().is_empty(),"alice_number":fresh.binding_for_agent("alice","gmail","read_messages").unwrap().unwrap().binding.bound_values["number"],"bob_number":fresh.binding_for_agent("bob","gmail","read_messages").unwrap().unwrap().binding.bound_values["number"],"other_capability":fresh.binding_for_agent("alice","gmail","other").unwrap().is_some()});
    assert_eq!(native_workflow, expected["workflow"]);
    assert_eq!(
        expected["old_reload_retains_revoked"],
        json!({"grant":true,"binding":true})
    );
    fs::write(path, SOURCE).unwrap();
    store.reload(now(), validate).unwrap();
    let remaining = store.list_grants_for_agent("alice", now()).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].grant.scope, GrantScope::Session);
    assert!(
        store
            .binding_for_agent("alice", "gmail", "read_messages")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        expected["old_big_integer_roundtrips"],
        serde_json::from_str::<Value>("[9223372036854775808,18446744073709551617]").unwrap()
    );
    assert_eq!(expected["failed_save_keeps_memory_empty"], json!(true));
    println!(
        "Python differential: {} scope/path cases, 8 expiry cases, 24 response outcomes; persisted lifecycle agrees. Intentional repairs: once admissions old=2/native=1; authoritative reload removes revoked grants/bindings. Unresolved TOML range gap: old exactly reloads 2^63 and 2^64+1; native rejects before publication.",
        cases.len()
    );
}

#[test]
#[ignore = "historical Python flock interoperability; set SAFEYOLO_POLICY_PYTHON"]
fn production_python_flock_serializes_native_writer_and_preserves_latest_edit() {
    use std::{
        io::{BufRead, BufReader, Write},
        process::Stdio,
        sync::mpsc,
        time::Duration,
    };
    let (_directory, path, store) = setup(SOURCE);
    let script = r#"
from pathlib import Path
import sys
from safeyolo.policy.toml_roundtrip import locked_policy_mutate
def mutate(doc):
 print('locked',flush=True)
 assert sys.stdin.readline()=='release\n'
 doc['external_writer']='preserved'
locked_policy_mutate(Path(sys.argv[1]),mutate)
"#;
    let mut child = python_command(script)
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "locked");
    let (send, receive) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        send.send(store.add_grant(request("alice", GrantScope::Remembered), now(), validate))
            .unwrap();
    });
    assert!(matches!(
        receive.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        receive
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap()
            .persistence,
        Persistence::Durable
    );
    writer.join().unwrap();
    let source = fs::read_to_string(&path).unwrap();
    assert!(source.contains("external_writer = \"preserved\""));
    assert!(source.contains("# operator heading"));
    assert_eq!(
        Store::open(path, now())
            .unwrap()
            .list_grants_for_agent("alice", now())
            .unwrap()
            .len(),
        1
    );
}

const COMPARATOR_COMMIT: &str = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a";

fn state_hash(path: &Path) -> String {
    digest(&SHA256, &fs::read(path).unwrap())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn state_mode(path: &Path) -> String {
    format!(
        "{:04o}",
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    )
}

fn git_output_for_state(repository: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn comparator_grants_stage(
    policy: &Path,
    operation: &str,
    expected_primary_binding: Option<&str>,
    expected_legacy_grant: Option<&str>,
    expected_legacy_binding: Option<&str>,
) -> Value {
    let source = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("SAFEYOLO_STATE_PYTHON_SOURCE must name the comparator checkout"),
    );
    let executable = PathBuf::from(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON")
            .expect("SAFEYOLO_POLICY_PYTHON must name the comparator interpreter"),
    );
    assert_eq!(
        git_output_for_state(&source, &["rev-parse", "HEAD"]),
        COMPARATOR_COMMIT
    );
    assert!(
        git_output_for_state(&source, &["status", "--porcelain"]).is_empty(),
        "selected Python comparator must be clean"
    );
    assert!(
        executable.is_file(),
        "selected Python comparator is missing"
    );
    let primary = expected_primary_binding.unwrap_or("");
    let legacy_grant = expected_legacy_grant.unwrap_or("");
    let legacy_binding = expected_legacy_binding.unwrap_or("");
    let script = r#"
import hashlib
import importlib.metadata
import json
import pathlib
import stat
import sys

from safeyolo.mitm_addons.service_gateway import ServiceGateway
from safeyolo.policy.toml_roundtrip import (
    load_agents,
    load_roundtrip,
    locked_policy_mutate,
    upsert_agent,
)

root = pathlib.Path(sys.argv[1])
operation = sys.argv[2]
expected_executable = pathlib.Path(sys.argv[3])
source = pathlib.Path(sys.argv[4])
expected_primary = sys.argv[5]
expected_legacy_grant = sys.argv[6]
expected_legacy_binding = sys.argv[7]
assert pathlib.Path(sys.executable).resolve() == expected_executable.resolve()
policy = root / 'policy.toml'

def snapshot(loaded=False):
    document = load_roundtrip(policy)
    agents = load_agents(document)
    alice = agents.get('alice', {})
    grants = []
    for value in alice.get('grants', []):
        grants.append({
            'grant_id': value.get('grant_id'),
            'service': value.get('service'),
            'method': value.get('method'),
            'path': value.get('path'),
            'scope': value.get('scope'),
            'created': value.get('created'),
            'expires': value.get('expires'),
        })
    bindings = []
    for value in alice.get('contract_bindings', []):
        bound = value.get('bound_values', {})
        bindings.append({
            'binding_id': value.get('binding_id'),
            'service': value.get('service'),
            'capability': value.get('capability'),
            'template': value.get('template'),
            'created': value.get('created'),
            'grantable_operations': value.get('grantable_operations', []),
            'bound_value_keys': sorted(bound),
            'limit': bound.get('limit'),
        })
    result = {
        'policy': {
            'path': str(policy),
            'sha256': hashlib.sha256(policy.read_bytes()).hexdigest(),
            'mode': format(stat.S_IMODE(policy.stat().st_mode), '04o'),
        },
        'grants': grants,
        'bindings': bindings,
    }
    if loaded:
        active_grants = {
            grant['grant_id']: grant
            for grant in gateway.list_grants()
        }
        for grant in grants:
            active = active_grants.get(grant['grant_id'])
            if active is not None:
                for field in ('created', 'expires', 'scope'):
                    grant[field] = active[field]
        for binding in bindings:
            active = gateway.get_contract_binding(
                'alice', binding['service'], binding['capability']
            )
            if active is not None:
                binding.update({
                    'binding_id': active.binding_id,
                    'template': active.template,
                    'created': active.created,
                })
    return result

gateway = ServiceGateway()
gateway._get_policy_path = lambda: policy
ids = {}
if operation == 'write-and-consume-python':
    policy.write_text('[agents]\nalice = {}\n')
    python_consumed = gateway.add_grant(
        'alice', 'mail', 'POST', '/v1/python', 'once'
    )
    native_grant = gateway.add_grant(
        'alice', 'mail', 'POST', '/v1/native', 'once'
    )
    primary = gateway.add_contract_binding(
        'alice',
        'mail',
        'send',
        'mail.v1',
        {'tenant': 'tenant-alpha', 'limit': 9223372036854775807},
        ['send'],
    )
    candidate = gateway._check_grant('alice', 'mail', 'POST', '/v1/python')
    assert candidate is not None
    gateway._consume_grant(candidate)
    def add_legacy(document):
        agents = load_agents(document)
        alice = agents['alice']
        alice['grants'].append({
            'service': 'mail',
            'method': 'POST',
            'path': '/v1/legacy',
            'scope': 'once',
        })
        alice['contract_bindings'].append({
            'service': 'mail',
            'capability': 'legacy',
            'bound_values': {'tenant': 'tenant-legacy', 'limit': 9223372036854775807},
            'grantable_operations': ['read'],
        })
        upsert_agent(document, 'alice', alice)
    locked_policy_mutate(policy, add_legacy)
    ids = {
        'python_consumed_grant_id': python_consumed.grant_id,
        'native_grant_id': native_grant.grant_id,
        'primary_binding_id': primary.binding_id,
    }
elif operation == 'reload-and-write-roundtrip':
    gateway._load_grants_from_policy()
    gateway._load_contract_bindings_from_policy()
    primary = gateway.get_contract_binding('alice', 'mail', 'send')
    assert primary is not None
    assert primary.binding_id == expected_primary
    assert primary.bound_values['limit'] == 9223372036854775807
    assert any(
        grant['grant_id'] == expected_legacy_grant
        for grant in gateway.list_grants()
    )
    legacy = gateway.get_contract_binding('alice', 'mail', 'legacy')
    assert legacy is not None
    assert legacy.binding_id == expected_legacy_binding
    roundtrip = gateway.add_grant(
        'alice', 'mail', 'POST', '/v1/roundtrip', 'once'
    )
    ids = {
        'primary_binding_id': primary.binding_id,
        'roundtrip_grant_id': roundtrip.grant_id,
        'legacy_grant_id_seen': expected_legacy_grant,
        'legacy_binding_id_seen': expected_legacy_binding,
    }
else:
    raise AssertionError(operation)

print(json.dumps({
    'backend': 'python-comparator',
    'operation': operation,
    'runtime': {
        'source': str(source),
        'commit': '7e934a5470f1aa9b74052fea08c6bae9b5f32e8a',
        'launcher': str(expected_executable),
        'program': sys.executable,
        'python_version': '.'.join(map(str, sys.version_info[:3])),
        'safeyolo': importlib.metadata.version('safeyolo'),
        'mitmproxy': importlib.metadata.version('mitmproxy'),
        'tomlkit': importlib.metadata.version('tomlkit'),
        'safeyolo_file': str(pathlib.Path(__import__('safeyolo').__file__).resolve()),
        'service_gateway_file': str(pathlib.Path(__import__('safeyolo.mitm_addons.service_gateway', fromlist=['__file__']).__file__).resolve()),
    },
    'ids': ids,
    'state': snapshot(loaded=operation == 'reload-and-write-roundtrip'),
    'effective': {
        'legacy_fields_missing': operation == 'write-and-consume-python',
        'legacy_defaults_observed': operation == 'reload-and-write-roundtrip',
        'supported_limit': 9223372036854775807,
        'source_consumer_action': (
            'python_grant_consumed'
            if operation == 'write-and-consume-python'
            else 'native_state_reloaded_and_roundtrip_grant_written'
        ),
    },
}))
"#;
    let output = Command::new(&executable)
        .arg("-c")
        .arg(script)
        .arg(policy.parent().unwrap())
        .arg(operation)
        .arg(&executable)
        .arg(&source)
        .arg(primary)
        .arg(legacy_grant)
        .arg(legacy_binding)
        .env(
            "PYTHONPATH",
            format!("{}:{}", source.join("cli/src").display(), source.display()),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Python grants stage {operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "Python grants stage {operation} returned invalid JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn native_grants_snapshot(store: &Store, policy: &Path, now: OffsetDateTime) -> Value {
    json!({
        "policy": {
            "path": policy,
            "sha256": state_hash(policy),
            "mode": state_mode(policy),
        },
        "grants": store.list_grants(now).unwrap(),
        "primary_binding": store
            .binding_for_agent("alice", "mail", "send")
            .unwrap()
            .map(|binding| serde_json::to_value(binding).unwrap()),
        "legacy_binding": store
            .binding_for_agent("alice", "mail", "legacy")
            .unwrap()
            .map(|binding| serde_json::to_value(binding).unwrap()),
    })
}

fn native_grant_id_for_path(store: &Store, path: &str, now: OffsetDateTime) -> String {
    store
        .list_grants(now)
        .unwrap()
        .into_iter()
        .find(|grant| grant.grant.path == path)
        .map(|grant| grant.grant.grant_id)
        .unwrap()
}

fn snapshot_grant<'a>(snapshot: &'a Value, grant_id: &str) -> &'a Value {
    snapshot["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["grant_id"].as_str() == Some(grant_id))
        .unwrap_or_else(|| panic!("missing grant {grant_id} in snapshot"))
}

fn snapshot_binding<'a>(snapshot: &'a Value, binding_id: &str) -> &'a Value {
    snapshot["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["binding_id"].as_str() == Some(binding_id))
        .unwrap_or_else(|| panic!("missing binding {binding_id} in snapshot"))
}

fn native_binding<'a>(snapshot: &'a Value, key: &str) -> &'a Value {
    let binding = &snapshot[key];
    assert!(!binding.is_null(), "missing native {key} binding");
    binding
}

fn assert_grant_metadata_preserved(expected: &Value, actual: &Value, grant_id: &str) {
    let expected = snapshot_grant(expected, grant_id);
    let actual = snapshot_grant(actual, grant_id);
    for field in ["grant_id", "created", "expires", "scope"] {
        assert_eq!(
            expected[field], actual[field],
            "normalized grant {grant_id} field {field} changed"
        );
    }
}

fn assert_binding_metadata_preserved(
    expected: &Value,
    actual: &Value,
    native_key: &str,
    binding_id: &str,
) {
    let expected = native_binding(expected, native_key);
    let actual = snapshot_binding(actual, binding_id);
    for field in ["binding_id", "created", "template"] {
        assert_eq!(
            expected[field], actual[field],
            "normalized binding {binding_id} field {field} changed"
        );
    }
}

fn assert_native_binding_metadata_preserved(
    expected: &Value,
    actual: &Value,
    native_key: &str,
    binding_id: &str,
) {
    let expected = native_binding(expected, native_key);
    let actual = native_binding(actual, native_key);
    for field in ["binding_id", "created", "template"] {
        assert_eq!(
            expected[field], actual[field],
            "normalized binding {binding_id} field {field} changed"
        );
    }
}

#[test]
#[ignore = "selected Python→Rust→Python→Rust grants/bindings state transition"]
fn selected_python_native_python_native_grants_bindings_transition() {
    let root = tempfile::tempdir().unwrap();
    let policy = root.path().join("policy.toml");
    let initial = comparator_grants_stage(&policy, "write-and-consume-python", None, None, None);

    let native_now = OffsetDateTime::now_utc();
    let store = Store::open(&policy, native_now).unwrap();
    let initial_native = native_grants_snapshot(&store, &policy, native_now);
    let python_native_grant_id = initial["ids"]["native_grant_id"].as_str().unwrap();
    let native_grant_id = native_grant_id_for_path(&store, "/v1/native", native_now);
    assert_eq!(python_native_grant_id, native_grant_id);
    let legacy_grant_id = native_grant_id_for_path(&store, "/v1/legacy", native_now);
    let primary = store
        .binding_for_agent("alice", "mail", "send")
        .unwrap()
        .unwrap();
    assert_eq!(primary.binding.bound_values["limit"], json!(i64::MAX));
    let primary_binding_id = primary.binding.binding_id.clone();
    assert_eq!(
        primary_binding_id,
        initial["ids"]["primary_binding_id"].as_str().unwrap()
    );
    let legacy_binding_id = store
        .binding_for_agent("alice", "mail", "legacy")
        .unwrap()
        .unwrap()
        .binding
        .binding_id
        .clone();
    assert!(!legacy_binding_id.is_empty());

    let lease = store
        .check_grant(
            RequestScope {
                agent: "alice",
                service: "mail",
                method: "POST",
                path: "/v1/native",
            },
            native_now,
            validate,
        )
        .unwrap()
        .unwrap();
    assert_eq!(lease.grant().grant_id, native_grant_id);
    assert_eq!(
        store
            .finish_response(lease, Some(204), native_now, validate)
            .unwrap(),
        ResponseOutcome::Consumed
    );
    assert!(
        store
            .check_grant(
                RequestScope {
                    agent: "alice",
                    service: "mail",
                    method: "POST",
                    path: "/v1/native",
                },
                native_now,
                validate,
            )
            .unwrap()
            .is_none()
    );
    let before_failed_write = fs::read(&policy).unwrap();
    let mut activation_calls = 0;
    let failed = store
        .add_grant(
            GrantRequest {
                agent: "alice".into(),
                service: "mail".into(),
                method: "POST".into(),
                path: "/v1/failed".into(),
                scope: GrantScope::Once,
            },
            native_now,
            |_| {
                activation_calls += 1;
                if activation_calls == 1 {
                    Err("synthetic activation rejection".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(failed.kind, ErrorKind::Activation);
    assert_eq!(activation_calls, 2);
    assert_eq!(fs::read(&policy).unwrap(), before_failed_write);
    assert!(
        !store
            .list_grants(native_now)
            .unwrap()
            .iter()
            .any(|grant| grant.grant.path == "/v1/failed")
    );
    let native_failure = json!({
        "backend": "rust-native",
        "operation": "failed-add-rollback",
        "policy": {
            "path": &policy,
            "sha256": state_hash(&policy),
            "mode": state_mode(&policy),
        },
        "effective": {
            "activation": "rejected",
            "policy_unchanged": true,
            "failed_grant_published": false,
        },
    });

    let after_native = native_grants_snapshot(&store, &policy, native_now);
    let python_reload = comparator_grants_stage(
        &policy,
        "reload-and-write-roundtrip",
        Some(&primary_binding_id),
        Some(&legacy_grant_id),
        Some(&legacy_binding_id),
    );
    assert_eq!(
        python_reload["ids"]["primary_binding_id"],
        primary_binding_id
    );
    assert_eq!(
        python_reload["ids"]["legacy_grant_id_seen"],
        legacy_grant_id
    );
    assert_eq!(
        python_reload["ids"]["legacy_binding_id_seen"],
        legacy_binding_id
    );
    assert!(
        python_reload["effective"]["legacy_defaults_observed"]
            .as_bool()
            .unwrap()
    );
    assert_grant_metadata_preserved(&initial_native, &python_reload["state"], &legacy_grant_id);
    assert_binding_metadata_preserved(
        &initial_native,
        &python_reload["state"],
        "primary_binding",
        &primary_binding_id,
    );
    assert_binding_metadata_preserved(
        &initial_native,
        &python_reload["state"],
        "legacy_binding",
        &legacy_binding_id,
    );
    let roundtrip_grant_id = python_reload["ids"]["roundtrip_grant_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let final_now = OffsetDateTime::now_utc();
    let final_store = Store::open(&policy, final_now).unwrap();
    let mut reloaded_native = native_grants_snapshot(&final_store, &policy, final_now);
    reloaded_native["backend"] = json!("rust-native");
    reloaded_native["operation"] = json!("reopen-before-final-cleanup");
    assert_grant_metadata_preserved(&initial_native, &reloaded_native, &legacy_grant_id);
    assert_native_binding_metadata_preserved(
        &initial_native,
        &reloaded_native,
        "primary_binding",
        &primary_binding_id,
    );
    assert_native_binding_metadata_preserved(
        &initial_native,
        &reloaded_native,
        "legacy_binding",
        &legacy_binding_id,
    );
    let final_primary = final_store
        .binding_for_agent("alice", "mail", "send")
        .unwrap()
        .unwrap();
    assert_eq!(final_primary.binding.binding_id, primary_binding_id);
    assert_eq!(final_primary.binding.bound_values["limit"], json!(i64::MAX));
    let final_lease = final_store
        .check_grant(
            RequestScope {
                agent: "alice",
                service: "mail",
                method: "POST",
                path: "/v1/roundtrip",
            },
            final_now,
            validate,
        )
        .unwrap()
        .unwrap();
    assert_eq!(final_lease.grant().grant_id, roundtrip_grant_id);
    assert_eq!(
        final_store
            .finish_response(final_lease, Some(200), final_now, validate)
            .unwrap(),
        ResponseOutcome::Consumed
    );
    assert!(
        final_store
            .revoke_grant("alice", &legacy_grant_id, final_now, validate)
            .unwrap()
    );
    assert!(
        final_store
            .revoke_binding("alice", &legacy_binding_id, final_now, validate)
            .unwrap()
    );
    assert!(
        final_store
            .revoke_binding("alice", &primary_binding_id, final_now, validate)
            .unwrap()
    );
    let final_native = native_grants_snapshot(&final_store, &policy, final_now);
    assert!(final_store.list_grants(final_now).unwrap().is_empty());
    assert!(
        final_store
            .binding_for_agent("alice", "mail", "send")
            .unwrap()
            .is_none()
    );
    assert!(
        final_store
            .binding_for_agent("alice", "mail", "legacy")
            .unwrap()
            .is_none()
    );

    let native_source = git_output_for_state(
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(),
        &["rev-parse", "HEAD"],
    );
    let manifest = json!({
        "schema": 1,
        "family": "service-grants-and-contract-bindings",
        "comparator": initial["runtime"],
        "native": {
            "source": native_source,
            "package": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "test": "selected_python_native_python_native_grants_bindings_transition",
        },
        "commands": {
            "python": format!(
                "{} -c <embedded-grants-fixture> ROOT OP EXPECTED_PRIMARY EXPECTED_LEGACY_GRANT EXPECTED_LEGACY_BINDING",
                std::env::var_os("SAFEYOLO_POLICY_PYTHON")
                    .map(|value| PathBuf::from(value).display().to_string())
                    .unwrap_or_default()
            ),
            "native": "cargo test --test grants selected_python_native_python_native_grants_bindings_transition -- --ignored --exact --nocapture",
        },
        "files": {
            "policy": {
                "path": policy,
                "sha256": state_hash(&policy),
                "mode": state_mode(&policy),
            }
        },
        "stable_ids": {
            "python_consumed_grant_id": initial["ids"]["python_consumed_grant_id"],
            "native_grant_id": native_grant_id,
            "legacy_grant_id": legacy_grant_id,
            "primary_binding_id": primary_binding_id,
            "legacy_binding_id": legacy_binding_id,
            "roundtrip_grant_id": roundtrip_grant_id,
        },
        "supported_large_value": i64::MAX,
        "actions": {
            "python_consumed": initial["ids"]["python_consumed_grant_id"],
            "native_consumed": native_grant_id,
            "legacy_binding_revoked": legacy_binding_id,
            "roundtrip_consumed": roundtrip_grant_id,
            "primary_binding_revoked": primary_binding_id,
            "legacy_grant_revoked": legacy_grant_id,
        },
        "stages": [
            initial,
            initial_native,
            native_failure,
            after_native,
            python_reload,
            reloaded_native,
            final_native
        ],
        "secret_free": true,
    });
    let evidence_dir = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR")
            .expect("SAFEYOLO_STATE_EVIDENCE_DIR must retain evidence"),
    );
    fs::create_dir_all(&evidence_dir).unwrap();
    let evidence_path = evidence_dir.join("grants-python-rust-python-rust.json");
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!(
        "grants/bindings transition manifest: {}",
        serde_json::to_string_pretty(&manifest).unwrap()
    );
}
