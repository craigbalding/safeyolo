use super::*;
use std::{
    fs,
    sync::{Arc, Barrier},
};
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/instance_id"), "sy-inventory").unwrap();
    fs::write(root.path().join("config.toml"), "admin_port=0\n").unwrap();
    fs::write(
        root.path().join("policy.toml"),
        format!("[agents.bob]\nagent_id='{BOB}'\n"),
    )
    .unwrap();
    super::super::bootstrap(root.path()).unwrap();
    let conn = open(root.path()).unwrap();
    conn.execute("INSERT INTO rooms VALUES('rm-inventory','shared',0)", [])
        .unwrap();
    conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-inventory','agent',?1,'receive,send',1)",[BOB]).unwrap();
    root
}
fn call(root: &Path, action: &str, subject: &str, label: &str, id: &str) -> Result<Value, Error> {
    run(
        root,
        &[action, "shared", subject, label, "--operation-id", id].map(str::to_owned),
    )
}
fn count(root: &Path, table: &str) -> i64 {
    open(root)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn concurrent_identical_mutations_commit_one_advertisement_operation_and_audit() {
    let root = fixture();
    let barrier = Arc::new(Barrier::new(3));
    let results = std::thread::scope(|scope| {
        let threads = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let path = root.path();
                scope.spawn(move || {
                    barrier.wait();
                    call(
                        path,
                        "advertise-capability",
                        "bob",
                        "rundeck:acceptance_runner",
                        "same",
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results[0], results[1]);
    assert_eq!(count(root.path(), "coord_capability_advertisements"), 1);
    assert_eq!(count(root.path(), "coord_operations"), 1);
    assert_eq!(count(root.path(), "coord_outbox"), 1);
    call(
        root.path(),
        "unadvertise-capability",
        "bob",
        "rundeck:acceptance_runner",
        "remove",
    )
    .unwrap();
    assert_eq!(
        results[0],
        call(
            root.path(),
            "advertise-capability",
            "bob",
            "rundeck:acceptance_runner",
            "same"
        )
        .unwrap()
    );
    assert_eq!(count(root.path(), "coord_capability_advertisements"), 0);
    assert!(
        call(
            root.path(),
            "unadvertise-capability",
            "bob",
            "rundeck:acceptance_runner",
            "same"
        )
        .unwrap_err()
        .to_string()
        .contains("conflicts")
    );
    let audit: String = open(root.path())
        .unwrap()
        .query_row("SELECT payload_json FROM coord_outbox LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let audit: Value = serde_json::from_str(&audit).unwrap();
    assert_eq!(audit["details"]["label"], "rundeck:acceptance_runner");
    assert_eq!(audit["details"]["actor"], "operator");
}

#[test]
fn refused_write_rolls_back_advertisement_and_operation_before_any_audit() {
    let root = fixture();
    open(root.path()).unwrap().execute_batch("CREATE TRIGGER fail_inventory_audit BEFORE INSERT ON coord_outbox BEGIN SELECT RAISE(ABORT,'owned failure'); END").unwrap();
    assert!(
        call(
            root.path(),
            "advertise-resource",
            "rundeck",
            "runner",
            "fault"
        )
        .is_err()
    );
    for table in [
        "coord_resource_advertisements",
        "coord_operations",
        "coord_outbox",
    ] {
        assert_eq!(count(root.path(), table), 0);
    }
    open(root.path())
        .unwrap()
        .execute_batch("DROP TRIGGER fail_inventory_audit")
        .unwrap();
    let first = call(
        root.path(),
        "advertise-resource",
        "rundeck",
        "runner",
        "fault",
    )
    .unwrap();
    assert_eq!(
        first,
        call(
            root.path(),
            "advertise-resource",
            "rundeck",
            "runner",
            "fault"
        )
        .unwrap()
    );
    for label in [
        "rundeck:token",
        "rundeck:runner/path",
        "rundeck:acceptance_runner:secret",
        "",
    ] {
        assert!(call(root.path(), "advertise-capability", "bob", label, "bad").is_err());
    }
    assert!(call(root.path(), "advertise-resource", "rundeck", "runner", "").is_err());
    assert_eq!(count(root.path(), "coord_operations"), 1);
}

#[test]
fn provider_advertisement_bounds_are_atomic_and_removed_id_can_be_unadvertised() {
    let root = fixture();
    for n in 0..MAX_PROVIDERS {
        call(
            root.path(),
            "advertise-resource",
            &format!("provider{n}"),
            "runner",
            &format!("op{n}"),
        )
        .unwrap();
    }
    assert!(
        call(
            root.path(),
            "advertise-resource",
            "excess",
            "runner",
            "excess"
        )
        .is_err()
    );
    assert_eq!(
        count(root.path(), "coord_resource_advertisements"),
        MAX_PROVIDERS as i64
    );
    assert_eq!(count(root.path(), "coord_operations"), MAX_PROVIDERS as i64);
    call(
        root.path(),
        "unadvertise-resource",
        "provider0",
        "runner",
        "remove",
    )
    .unwrap();
    call(
        root.path(),
        "advertise-resource",
        "rundeck",
        "runner",
        "replace",
    )
    .unwrap();
    call(
        root.path(),
        "advertise-capability",
        "bob",
        "rundeck:acceptance_runner",
        "ad",
    )
    .unwrap();
    fs::write(root.path().join("policy.toml"), "").unwrap();
    call(
        root.path(),
        "unadvertise-capability",
        BOB,
        "rundeck:acceptance_runner",
        "removed",
    )
    .unwrap();
    assert_eq!(count(root.path(), "coord_capability_advertisements"), 0);
}
