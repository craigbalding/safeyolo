use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
};

use super::persist_expired_hosts;
use crate::policy::ErrorKind;

fn entries() -> Vec<(Option<String>, String)> {
    vec![
        (None, "remove.invalid".into()),
        (Some("alice".into()), "scoped.invalid".into()),
        (Some("inline".into()), "inline.invalid".into()),
        (Some("missing".into()), "missing.invalid".into()),
    ]
}

#[test]
fn supplied_top_and_agent_names_are_removed_without_recomputing_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    let source = r#"# owned policy comment
title = "keep the document"

[hosts]
"remove.invalid" = { egress = "allow", expires = "2999-01-01" }
"keep.invalid" = { egress = "deny", expires = "2000-01-01" } # keep this comment

[agents.alice]
description = "keep the agent"
[agents.alice.hosts]
"scoped.invalid" = { egress = "allow" }
"other.invalid" = { egress = "deny" }

[agents]
inline = { hosts = { "inline.invalid" = { egress = "allow" }, "retained.invalid" = { egress = "deny" } } }
"#;
    fs::write(&path, source).unwrap();
    persist_expired_hosts(&path, &entries(), None).unwrap();
    let saved = fs::read_to_string(&path).unwrap();
    assert!(saved.starts_with("# owned policy comment\n"));
    assert!(saved.contains("# keep this comment"));
    assert!(saved.contains("title = \"keep the document\""));
    assert!(saved.contains("description = \"keep the agent\""));
    let parsed = saved.parse::<toml_edit::DocumentMut>().unwrap();
    assert!(parsed["hosts"].get("remove.invalid").is_none());
    assert!(parsed["hosts"].get("keep.invalid").is_some());
    assert!(
        parsed["agents"]["alice"]["hosts"]
            .get("scoped.invalid")
            .is_none()
    );
    assert!(
        parsed["agents"]["alice"]["hosts"]
            .get("other.invalid")
            .is_some()
    );
    assert!(
        parsed["agents"]["inline"]["hosts"]
            .get("inline.invalid")
            .is_none()
    );
    assert!(
        parsed["agents"]["inline"]["hosts"]
            .get("retained.invalid")
            .is_some()
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(directory.path().join(".policy.toml.lock").exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn absent_names_do_not_replace_or_reformat_the_document() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    let source = "# retain exact bytes\n[hosts]\n'other.invalid'={egress='allow'}\n";
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let before = fs::metadata(&path).unwrap();
    persist_expired_hosts(&path, &entries(), None).unwrap();
    let after = fs::metadata(&path).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
    assert_eq!(after.ino(), before.ino());
    assert_eq!(after.permissions().mode() & 0o777, 0o640);
    assert!(directory.path().join(".policy.toml.lock").exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn admin_replacement_of_the_expired_host_is_not_removed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    let loaded = "[hosts]\n'changed.invalid'={egress='deny',expires=2001-01-01T00:00:00Z}\n'old.invalid'={egress='deny',expires=2001-01-01T00:00:00Z}\n";
    let newer = loaded.replace(
        "'changed.invalid'={egress='deny',expires=2001-01-01T00:00:00Z}",
        "'changed.invalid'={egress='allow'}",
    );
    fs::write(&path, newer).unwrap();
    persist_expired_hosts(
        &path,
        &[
            (None, "changed.invalid".into()),
            (None, "old.invalid".into()),
        ],
        Some(loaded),
    )
    .unwrap();
    let saved: toml_edit::DocumentMut = fs::read_to_string(&path).unwrap().parse().unwrap();
    assert_eq!(
        saved["hosts"]["changed.invalid"]["egress"].as_str(),
        Some("allow")
    );
    assert!(saved["hosts"].get("old.invalid").is_none());
}

#[test]
fn unavailable_policy_lock_leaves_the_document_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.toml");
    let source = "[hosts]\n'remove.invalid'={egress='deny',expires=2001-01-01T00:00:00Z}\n";
    fs::write(&path, source).unwrap();
    fs::create_dir(directory.path().join(".policy.toml.lock")).unwrap();
    assert!(
        persist_expired_hosts(&path, &entries(), Some(source))
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn read_io_is_contained_but_decoding_and_parse_failures_propagate() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.toml");
    persist_expired_hosts(&missing, &entries(), None).unwrap();
    let as_directory = directory.path().join("as-directory.toml");
    fs::create_dir(&as_directory).unwrap();
    persist_expired_hosts(&as_directory, &entries(), None).unwrap();
    assert!(!missing.exists());
    let invalid = directory.path().join("invalid.toml");
    for (bytes, message) in [
        (b"[hosts".as_slice(), "policy expiry TOML is invalid"),
        (b"\xff".as_slice(), "policy expiry TOML is not UTF-8"),
    ] {
        fs::write(&invalid, bytes).unwrap();
        let error = persist_expired_hosts(&invalid, &entries(), None).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Invalid);
        assert_eq!(error.message, message);
        assert_eq!(fs::read(&invalid).unwrap(), bytes);
    }
    assert!(directory.path().join(".policy.toml.lock").exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn configured_symlink_is_replaced_and_its_target_is_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.toml");
    let path = directory.path().join("policy.toml");
    let source = "[hosts]\n'remove.invalid'={egress='allow'}\n";
    fs::write(&target, source).unwrap();
    symlink(&target, &path).unwrap();
    persist_expired_hosts(&path, &entries(), None).unwrap();
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
    assert_eq!(fs::read_to_string(&target).unwrap(), source);
    assert!(
        !fs::read_to_string(&path)
            .unwrap()
            .contains("remove.invalid")
    );
    assert!(directory.path().join(".policy.toml.lock").exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}

#[test]
fn actual_save_rename_failure_cleans_up_its_temporary_file() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("directory.toml");
    fs::create_dir(&destination).unwrap();
    let result = crate::approvals::save_policy(&destination, "[hosts]\n");
    assert!(result.is_err());
    assert!(destination.is_dir());
    let remaining: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(remaining, vec![destination.file_name().unwrap().to_owned()]);
    assert_eq!(fs::read_dir(destination).unwrap().count(), 0);
}
