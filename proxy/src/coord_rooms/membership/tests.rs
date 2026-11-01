use super::*;
use crate::coord_rooms::{bootstrap, grant, open};
use std::{
    fs,
    path::Path,
    sync::{Arc, Barrier},
};

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/instance_id"), "si-owned").unwrap();
    fs::write(root.path().join("config.toml"), "admin_port=0\n").unwrap();
    fs::write(root.path().join("policy.toml"), "[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.bob]\nagent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n").unwrap();
    bootstrap(root.path()).unwrap();
    open(root.path())
        .unwrap()
        .execute("INSERT INTO rooms VALUES('rm-owned','owned',0)", [])
        .unwrap();
    root
}

fn mutate(
    root: &Path,
    agent: &str,
    permissions: &[&str],
    revoke: bool,
    operation: &str,
) -> Result<Value, Error> {
    grant(
        &root.join("config.toml"),
        "owned",
        agent,
        &permissions.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
        revoke,
        Some(operation),
    )
}

#[test]
fn canonical_replay_conflict_and_immutable_history_survive_later_changes() {
    let root = fixture();
    let first = mutate(
        root.path(),
        "alice",
        &["send", "receive", "send", "page_operator"],
        false,
        "same",
    )
    .unwrap();
    assert_eq!(
        first,
        mutate(root.path(), "alice", &[], false, "same").unwrap()
    );
    assert_eq!(
        first,
        mutate(
            root.path(),
            "alice",
            &["receive", "send", "page_operator"],
            false,
            "same"
        )
        .unwrap()
    );
    for (agent, permissions) in [("alice", vec!["send"]), ("bob", vec![])] {
        assert!(
            mutate(root.path(), agent, &permissions, false, "same")
                .unwrap_err()
                .to_string()
                .contains("conflicts")
        );
    }
    // Operation types have independent ID scopes. A replay after revocation
    // returns the old result without restoring the revoked grant.
    let revoked = mutate(root.path(), "alice", &[], true, "same").unwrap();
    assert_eq!(
        first,
        mutate(root.path(), "alice", &[], false, "same").unwrap()
    );
    let db = open(root.path()).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM memberships WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let next = mutate(root.path(), "alice", &[], false, "next").unwrap();
    assert_ne!(
        first["membership_granted_at"],
        next["membership_granted_at"]
    );
    assert_eq!(
        revoked,
        mutate(root.path(), "alice", &[], true, "same").unwrap()
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM memberships WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    bootstrap(root.path()).unwrap();
    assert_eq!(
        first,
        mutate(root.path(), "alice", &[], false, "same").unwrap()
    );
    for sql in [
        "UPDATE coord_operations SET outcome_json='{}'",
        "DELETE FROM coord_operations",
    ] {
        assert!(
            db.execute(sql, [])
                .unwrap_err()
                .to_string()
                .contains("immutable")
        );
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM coord_operations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM coord_outbox", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert!(mutate(root.path(), "alice", &[], false, " ").is_err());
    assert!(mutate(root.path(), "alice", &["admin"], false, "bad").is_err());
}

#[test]
fn concurrent_retries_commit_one_transition_and_outbox_row() {
    let root = fixture();
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let root = root.path().to_owned();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                mutate(&root, "alice", &[], false, "concurrent").unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(results.iter().all(|r| r == &results[0]));
    let db = open(root.path()).unwrap();
    for table in ["memberships", "coord_operations", "coord_outbox"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn failed_audit_enqueue_rolls_back_grant_revoke_and_operation() {
    let root = fixture();
    let db = open(root.path()).unwrap();
    db.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON coord_outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END;").unwrap();
    assert!(mutate(root.path(), "alice", &[], false, "retry").is_err());
    for table in ["memberships", "coord_operations", "coord_outbox"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    db.execute_batch("DROP TRIGGER reject_outbox").unwrap();
    mutate(root.path(), "alice", &[], false, "retry").unwrap();
    db.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON coord_outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END;").unwrap();
    assert!(mutate(root.path(), "alice", &[], true, "revoke").is_err());
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM memberships WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM coord_operations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    db.execute_batch("DROP TRIGGER reject_outbox").unwrap();
    mutate(root.path(), "alice", &[], true, "revoke").unwrap();
}
