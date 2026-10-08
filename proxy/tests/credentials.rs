use safeyolo_proxy::credentials::{Credential, ErrorKind, Secret, Vault};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Barrier},
};
use time::OffsetDateTime;

fn password() -> Secret {
    Secret::new("synthetic vault passphrase — not an operator key")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1704067200).unwrap()
}
fn credential(name: &str) -> Credential {
    Credential::new(
        name,
        "bearer",
        Secret::new(format!("synthetic-private-value-for-{name}")),
    )
}
fn setup() -> (tempfile::TempDir, PathBuf, Vault) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("credentials.enc");
    let vault = Vault::unlock(&path, &password()).unwrap();
    (directory, path, vault)
}

#[test]
fn native_open_ignores_old_vault_files_and_persists_only_an_external_reference() {
    use safeyolo_proxy::credentials::{ExternalReference, open};
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("vault.yaml.enc"),
        "unusable old vault",
    )
    .unwrap();
    fs::write(directory.path().join("vault.key"), "unusable old key").unwrap();
    let store = open(directory.path()).unwrap();
    assert!(store.list_names().unwrap().is_empty());
    let mut external = Credential::new("external", "bearer", Secret::new(""));
    external.reference = Some(ExternalReference::Onepassword(
        "op://synthetic/item/field".into(),
    ));
    store.store(external).unwrap();
    let reopened = open(directory.path()).unwrap();
    let credential = reopened.get("external").unwrap().unwrap();
    assert_eq!(
        credential.reference,
        Some(ExternalReference::Onepassword(
            "op://synthetic/item/field".into()
        ))
    );
    assert!(credential.value.expose_secret().is_empty());
    assert!(
        serde_json::to_string(&reopened.metadata().unwrap())
            .unwrap()
            .contains("op://synthetic/item/field")
    );
    assert_eq!(
        fs::read_to_string(directory.path().join("vault.key")).unwrap(),
        "unusable old key"
    );
    for name in ["credentials.key", "credentials.enc", "credentials.lock"] {
        assert_eq!(
            fs::metadata(directory.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn independent_native_command_writers_keep_each_others_edits() {
    let (_directory, path, first) = setup();
    let second = Vault::unlock(&path, &password()).unwrap();
    first.store(credential("one")).unwrap();
    second.store(credential("two")).unwrap();
    assert!(first.remove("one").unwrap());
    let third = Vault::unlock(&path, &password()).unwrap();
    assert_eq!(third.list_names().unwrap(), ["two"]);
    assert_eq!(
        third.get("two").unwrap().unwrap().value.expose_secret(),
        "synthetic-private-value-for-two"
    );
}

#[test]
fn store_restart_remove_and_metadata_keep_secret_access_explicit() {
    let (_directory, path, vault) = setup();
    assert!(vault.list_names().unwrap().is_empty());
    let mut oauth = credential("mail");
    oauth.credential_type = "oauth2".into();
    oauth.refresh_token = Some(Secret::new("synthetic-refresh"));
    oauth.token_url = Some("https://example.invalid/token".into());
    oauth.client_id = Some("synthetic-client".into());
    oauth.client_secret = Some(Secret::new("synthetic-client-secret"));
    oauth.expires_at = Some("2099-01-01T00:00:00+00:00".into());
    vault.store(oauth).unwrap();
    vault.store(credential("second")).unwrap();
    let metadata = serde_json::to_string(&vault.metadata().unwrap()).unwrap();
    assert!(metadata.contains("mail"));
    for private in [
        "synthetic-private-value",
        "synthetic-refresh",
        "synthetic-client-secret",
        "example.invalid",
    ] {
        assert!(!metadata.contains(private));
    }
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(b"synthetic-private-value".len())
            .any(|value| value == b"synthetic-private-value")
    );
    let restarted = Vault::unlock(&path, &password()).unwrap();
    assert_eq!(restarted.list_names().unwrap(), ["mail", "second"]);
    let loaded = restarted.get("mail").unwrap().unwrap();
    assert_eq!(
        loaded.value.expose_secret(),
        "synthetic-private-value-for-mail"
    );
    assert_eq!(
        loaded.refresh_token.as_ref().unwrap().expose_secret(),
        "synthetic-refresh"
    );
    assert_eq!(
        loaded.client_secret.as_ref().unwrap().expose_secret(),
        "synthetic-client-secret"
    );
    assert_eq!(loaded.client_id.as_deref(), Some("synthetic-client"));
    assert_eq!(
        loaded.token_url.as_deref(),
        Some("https://example.invalid/token")
    );
    assert_eq!(
        loaded.expires_at.as_deref(),
        Some("2099-01-01T00:00:00+00:00")
    );
    assert!(!loaded.is_expired(now()).unwrap());
    assert!(restarted.remove("mail").unwrap());
    assert!(!restarted.remove("missing").unwrap());
    assert!(vault.has_changes().unwrap());
    assert!(vault.reload_if_changed().unwrap());
    assert!(!vault.reload_if_changed().unwrap());
    assert!(vault.get("mail").unwrap().is_none());
    assert_eq!(vault.list_names().unwrap(), ["second"]);
}

#[test]
fn wrong_password_corruption_and_truncation_never_replace_active_credentials() {
    use base64::{Engine, engine::general_purpose::URL_SAFE};
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let original = fs::read(&path).unwrap();
    assert_eq!(
        Vault::unlock(&path, &Secret::new("wrong synthetic password"))
            .err()
            .unwrap()
            .kind,
        ErrorKind::Authentication
    );
    let decoded = URL_SAFE.decode(&original[16..]).unwrap();
    for position in [0, 1, 9, 25, decoded.len() - 1] {
        let mut tampered = decoded.clone();
        tampered[position] ^= 1;
        let mut bytes = original[..16].to_vec();
        bytes.extend_from_slice(URL_SAFE.encode(tampered).as_bytes());
        fs::write(&path, bytes).unwrap();
        let failure = vault.reload().unwrap_err();
        assert_eq!(failure.kind, ErrorKind::Authentication);
        assert_eq!(failure.to_string(), "wrong passphrase or corrupted vault");
        assert_eq!(
            vault.get("kept").unwrap().unwrap().value.expose_secret(),
            "synthetic-private-value-for-kept"
        );
    }
    for length in [0, 1, 15, 16, 17, original.len() - 3] {
        fs::write(&path, &original[..length]).unwrap();
        assert_eq!(
            Vault::unlock(&path, &password()).err().unwrap().kind,
            ErrorKind::Authentication
        );
    }
    let mut changed_salt = original.clone();
    changed_salt[0] ^= 1;
    fs::write(&path, changed_salt).unwrap();
    assert_eq!(vault.reload().unwrap_err().kind, ErrorKind::KeyChanged);
    assert_eq!(
        Vault::unlock(&path, &password()).err().unwrap().kind,
        ErrorKind::Authentication
    );
    fs::write(&path, &original).unwrap();
    vault.reload().unwrap();
    assert_eq!(vault.list_names().unwrap(), ["kept"]);
}

#[test]
fn write_activation_rollback_restores_exact_encrypted_file_and_snapshot() {
    let (directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let original = fs::read(&path).unwrap();
    let mut calls = Vec::new();
    let failure = vault
        .store_with_activation(credential("rejected"), |metadata| {
            calls.push(
                metadata
                    .iter()
                    .map(|value| value.name.clone())
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            if calls.len() == 1 { Err(()) } else { Ok(()) }
        })
        .unwrap_err();
    assert_eq!(failure.kind, ErrorKind::Activation);
    assert_eq!(
        calls,
        [
            vec!["kept".to_owned(), "rejected".to_owned()],
            vec!["kept".to_owned()]
        ]
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(vault.get("rejected").unwrap().is_none());
    assert_eq!(
        Vault::unlock(&path, &password())
            .unwrap()
            .list_names()
            .unwrap(),
        ["kept"]
    );
    assert_eq!(
        vault
            .remove_with_activation("kept", |_| Err(()))
            .unwrap_err()
            .kind,
        ErrorKind::Rollback
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(vault.get("kept").unwrap().is_some());
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        2,
        "private temporary files are cleaned after success and rollback"
    );
}

#[test]
fn reload_activation_is_atomic_and_missing_file_retains_previous_snapshot() {
    let (_directory, path, vault) = setup();
    vault.store(credential("kept")).unwrap();
    let external = Vault::unlock(&path, &password()).unwrap();
    external.store(credential("external")).unwrap();
    let changed = fs::read(&path).unwrap();
    let mut calls = 0;
    assert_eq!(
        vault
            .reload_with_activation(|_| {
                calls += 1;
                if calls == 1 { Err(()) } else { Ok(()) }
            })
            .unwrap_err()
            .kind,
        ErrorKind::Activation
    );
    assert_eq!(calls, 2);
    assert!(vault.get("external").unwrap().is_none());
    assert_eq!(fs::read(&path).unwrap(), changed);
    assert!(vault.reload_if_changed().unwrap());
    assert!(vault.get("external").unwrap().is_some());
    fs::remove_file(&path).unwrap();
    assert!(!vault.has_changes().unwrap());
    assert_eq!(vault.reload().unwrap_err().kind, ErrorKind::Io);
    assert_eq!(vault.list_names().unwrap(), ["kept", "external"]);
    assert_eq!(
        vault.store(credential("failed")).unwrap_err().kind,
        ErrorKind::Io
    );
    assert!(vault.get("failed").unwrap().is_none());
}

#[test]
fn shared_writers_publish_complete_credentials_without_lost_local_updates() {
    let (_directory, path, vault) = setup();
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let vault = vault.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for item in 0..4 {
                    let name = format!("worker-{worker}-{item}");
                    vault.store(credential(&name)).unwrap();
                    assert!(vault.get(&name).unwrap().is_some());
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(vault.list_names().unwrap().len(), 32);
    assert_eq!(
        Vault::unlock(&path, &password())
            .unwrap()
            .list_names()
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn simultaneous_refresh_publication_has_one_winner_and_no_lost_unrelated_edit() {
    let (_directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|index| {
            let vault = vault.clone();
            let snapshot = vault.snapshot("mail").unwrap().unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut replacement = snapshot.credential().clone();
                replacement.value = Secret::new(format!("synthetic-refresh-{index}"));
                vault
                    .replace_if_current(&snapshot, replacement, |_| Ok(()))
                    .unwrap()
            })
        })
        .collect();
    vault.store(credential("other")).unwrap();
    barrier.wait();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let current = vault.get("mail").unwrap().unwrap();
    let loaded = Vault::unlock(path, &password()).unwrap();
    assert!(loaded.get("other").unwrap().is_some());
    assert_eq!(
        loaded.get("mail").unwrap().unwrap().value.expose_secret(),
        current.value.expose_secret()
    );
}

#[test]
fn current_snapshot_observation_detects_file_removal_without_mutation() {
    let (directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    let snapshot = vault.snapshot("mail").unwrap().unwrap();
    let original = fs::read(&path).unwrap();
    assert!(vault.is_current(&snapshot).unwrap());
    assert_eq!(fs::read(&path).unwrap(), original);

    let moved = directory.path().join("vault-moved.enc");
    fs::rename(&path, &moved).unwrap();
    assert!(!vault.is_current(&snapshot).unwrap());
    assert!(!path.exists(), "observation must not recreate the vault");
    fs::rename(&moved, &path).unwrap();
    assert!(vault.is_current(&snapshot).unwrap());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn conditional_publication_rejects_stores_removal_and_name_recreation() {
    let (_directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    assert!(vault.snapshot("missing").unwrap().is_none());
    for mutation in 0..3 {
        let snapshot = vault.snapshot("mail").unwrap().unwrap();
        assert!(vault.clone().is_current(&snapshot).unwrap());
        match mutation {
            0 => vault.store(credential("mail")).unwrap(),
            1 => assert!(vault.remove("mail").unwrap()),
            2 => {
                assert!(vault.remove("mail").unwrap());
                vault.store(credential("mail")).unwrap();
            }
            _ => unreachable!(),
        }
        let original = fs::read(&path).unwrap();
        assert!(!vault.is_current(&snapshot).unwrap());
        assert!(
            !vault
                .replace_if_current(&snapshot, credential("mail"), |_| {
                    panic!("stale publication must not activate")
                })
                .unwrap()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        if mutation == 1 {
            assert!(vault.get("mail").unwrap().is_none());
            vault.store(credential("mail")).unwrap();
        }
    }
}

#[test]
fn conditional_publication_is_bound_to_the_vault_and_credential_name() {
    let (_directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    let snapshot = vault.snapshot("mail").unwrap().unwrap();
    let other = Vault::unlock(&path, &password()).unwrap();
    let original = fs::read(&path).unwrap();
    assert!(vault.is_current(&snapshot).unwrap());
    assert!(!other.is_current(&snapshot).unwrap());
    assert!(
        !other
            .replace_if_current(&snapshot, credential("mail"), |_| {
                panic!("foreign snapshot must not activate")
            })
            .unwrap()
    );
    assert_eq!(
        vault
            .replace_if_current(&snapshot, credential("renamed"), |_| {
                panic!("renamed publication must not activate")
            })
            .unwrap_err()
            .kind,
        ErrorKind::Format
    );
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn changed_reload_and_visible_external_edits_supersede_refresh() {
    let (_directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    let external = Vault::unlock(&path, &password()).unwrap();
    for field in 0..8 {
        let snapshot = vault.snapshot("mail").unwrap().unwrap();
        let mut edited = snapshot.credential().clone();
        match field {
            0 => edited.value = Secret::new("synthetic-edited-access"),
            1 => edited.credential_type = "oauth2".into(),
            2 => edited.refresh_token = Some(Secret::new("synthetic-edited-refresh")),
            3 => edited.token_url = Some("https://example.invalid/changed-token".into()),
            4 => edited.client_id = Some("edited-client".into()),
            5 => edited.client_secret = Some(Secret::new("synthetic-edited-secret")),
            6 => edited.expires_at = Some("2099-01-01T00:00:00+00:00".into()),
            7 => {
                external.remove("mail").unwrap();
            }
            _ => unreachable!(),
        }
        if field != 7 {
            external.store(edited).unwrap();
        }
        let original = fs::read(&path).unwrap();
        for reloaded in [false, true] {
            if reloaded {
                vault.reload().unwrap();
            }
            assert!(!vault.is_current(&snapshot).unwrap());
            assert!(
                !vault
                    .replace_if_current(&snapshot, credential("mail"), |_| {
                        panic!("external edit must not activate refresh")
                    })
                    .unwrap()
            );
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }
    assert!(vault.get("mail").unwrap().is_none());
}

#[test]
fn unchanged_save_reload_and_unrelated_edits_preserve_pending_refresh() {
    let (_directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    let snapshot = vault.snapshot("mail").unwrap().unwrap();
    vault.save().unwrap();
    vault.reload().unwrap();
    assert!(vault.is_current(&snapshot).unwrap());
    let external = Vault::unlock(&path, &password()).unwrap();
    external.store(credential("other")).unwrap();
    assert!(!vault.is_current(&snapshot).unwrap());
    vault.reload().unwrap();
    assert!(vault.is_current(&snapshot).unwrap());
    let mut refreshed = snapshot.credential().clone();
    refreshed.value = Secret::new("synthetic-refreshed-value");
    assert!(
        vault
            .replace_if_current(&snapshot, refreshed, |_| Ok(()))
            .unwrap()
    );
    let restarted = Vault::unlock(path, &password()).unwrap();
    assert!(restarted.get("other").unwrap().is_some());
    assert_eq!(
        restarted
            .get("mail")
            .unwrap()
            .unwrap()
            .value
            .expose_secret(),
        "synthetic-refreshed-value"
    );
}

#[test]
fn rollback_of_external_bytes_does_not_revalidate_a_stale_snapshot() {
    for removed in [false, true] {
        let (_directory, path, vault) = setup();
        vault.store(credential("mail")).unwrap();
        let snapshot = vault.snapshot("mail").unwrap().unwrap();
        let external = Vault::unlock(&path, &password()).unwrap();
        if removed {
            assert!(external.remove("mail").unwrap());
        } else {
            let mut edited = credential("mail");
            edited.value = Secret::new("synthetic-external-edit");
            external.store(edited).unwrap();
        }
        let external_bytes = fs::read(&path).unwrap();
        assert!(!vault.is_current(&snapshot).unwrap());

        let mut calls = 0;
        let failure = vault
            .store_with_activation(credential("unrelated"), |_| {
                calls += 1;
                if calls == 1 { Err(()) } else { Ok(()) }
            })
            .unwrap_err();
        assert_eq!(failure.kind, ErrorKind::Activation);
        assert_eq!(calls, 2);
        assert_eq!(fs::read(&path).unwrap(), external_bytes);
        assert!(vault.get("unrelated").unwrap().is_none());

        let appeared_current = vault.is_current(&snapshot).unwrap();
        let replaced = vault
            .replace_if_current(&snapshot, credential("mail"), |_| Ok(()))
            .unwrap();
        assert!(
            !replaced,
            "rollback permitted a stale publication over an external edit"
        );
        assert!(!appeared_current);
        // Native writes first reconcile another command's saved state under
        // the cross-process lock. Rollback keeps that latest accepted state.
        assert!(!vault.has_changes().unwrap());
        assert_eq!(fs::read(&path).unwrap(), external_bytes);
        vault.reload().unwrap();
        assert!(!vault.is_current(&snapshot).unwrap());
        assert_eq!(vault.get("mail").unwrap().is_none(), removed);
    }
}

#[test]
fn failed_refresh_activation_restores_bytes_and_revision_for_retry() {
    let (_directory, path, vault) = setup();
    vault.store(credential("mail")).unwrap();
    let snapshot = vault.snapshot("mail").unwrap().unwrap();
    let original = fs::read(&path).unwrap();
    let mut refreshed = snapshot.credential().clone();
    refreshed.value = Secret::new("synthetic-refreshed-value");
    let mut calls = 0;
    assert_eq!(
        vault
            .replace_if_current(&snapshot, refreshed.clone(), |_| {
                calls += 1;
                if calls == 1 { Err(()) } else { Ok(()) }
            })
            .unwrap_err()
            .kind,
        ErrorKind::Activation
    );
    assert_eq!(calls, 2);
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(
        vault.get("mail").unwrap().unwrap().value.expose_secret(),
        snapshot.credential().value.expose_secret()
    );
    assert!(
        vault
            .replace_if_current(&snapshot, refreshed, |_| Ok(()))
            .unwrap()
    );
}

#[test]
fn empty_values_unknown_types_and_optional_empty_fields_keep_existing_vault_semantics() {
    let (_directory, path, vault) = setup();
    let mut value = Credential::new("", "operator-custom-type", Secret::new(""));
    value.refresh_token = Some(Secret::new(""));
    value.token_url = Some("".into());
    value.client_id = Some("".into());
    value.client_secret = Some(Secret::new(""));
    value.expires_at = Some("".into());
    vault.store(value).unwrap();
    let loaded = Vault::unlock(path, &password())
        .unwrap()
        .get("")
        .unwrap()
        .unwrap();
    assert_eq!(loaded.credential_type, "operator-custom-type");
    assert!(loaded.value.expose_secret().is_empty());
    assert!(loaded.refresh_token.is_none());
    assert!(loaded.token_url.is_none());
    assert!(loaded.client_id.is_none());
    assert!(loaded.client_secret.is_none());
    assert!(loaded.expires_at.is_none());
}

#[test]
fn expiry_and_refresh_eligibility_keep_naive_timestamp_errors_explicit() {
    let cases = [
        (None, Ok(false)),
        (Some(""), Ok(false)),
        (Some("malformed"), Ok(true)),
        (Some("2024-01-01T00:00:00Z"), Ok(true)),
        (Some("2024-01-01T00:00:01Z"), Ok(false)),
        (Some("2024-01-01T01:00:00+01:00"), Ok(true)),
        (Some("2024-01-01T00:00:00"), Err(ErrorKind::InvalidExpiry)),
        (Some("2024-01-01"), Err(ErrorKind::InvalidExpiry)),
    ];
    for (expiry, expected) in cases {
        let mut value = credential("synthetic");
        value.expires_at = expiry.map(str::to_owned);
        assert_eq!(
            value.is_expired(now()).map_err(|failure| failure.kind),
            expected
        );
        assert!(!value.needs_oauth_refresh(now()).unwrap());
        value.credential_type = "oauth2".into();
        value.refresh_token = Some(Secret::new("synthetic-refresh"));
        value.token_url = Some("https://example.invalid/token".into());
        assert_eq!(
            value
                .needs_oauth_refresh(now())
                .map_err(|failure| failure.kind),
            expected
        );
    }
}
