use std::path::Path;
use std::process::Command;

use rusqlite::Connection;
use safeyolo_proxy::flow_store::{ErrorKind, FlowStore, Settings};

#[test]
fn failed_initialization_preserves_source_v1_and_v2_ddl_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    for version in [1, 2] {
        let path = directory.path().join(format!("v{version}.db"));
        let db = Connection::open(&path).unwrap();
        db.execute_batch(&format!("CREATE TABLE marker(value); CREATE INDEX flow_request_fts ON marker(value); PRAGMA user_version={version};")).unwrap();
        drop(db);
        let error = FlowStore::open(&path, Settings::default()).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::Operational);
        let db = Connection::open(&path).unwrap();
        let exists = |name: &str| {
            db.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                [name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        assert_eq!(exists("flows"), 1);
        assert_eq!(
            exists("flow_fts"),
            i64::from(version == 2),
            "version {version}"
        );
        assert_eq!(exists("flow_tags"), 0);
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            version
        );
    }
}

#[test]
fn filename_semantics_child() {
    let Ok(name) = std::env::var("FLOW_STORE_FILENAME_TEST") else {
        return;
    };
    let result = FlowStore::open(Path::new(&name), Settings::default());
    if name == "missing/child.sqlite3" {
        assert_eq!(result.err().unwrap().kind(), ErrorKind::Operational);
        assert!(!Path::new("missing").exists());
    } else {
        drop(result.unwrap());
        assert_eq!(
            Path::new(&name).is_file(),
            !name.is_empty() && name != ":memory:"
        );
    }
}

#[test]
fn filenames_are_relative_or_literal_without_invented_parent_creation() {
    for name in [
        "relative.sqlite3",
        "missing/child.sqlite3",
        "",
        ":memory:",
        "file:owned.sqlite3?mode=memory",
        "file:literal.sqlite3?mode=rwc",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "filename_semantics_child", "--nocapture"])
            .env("FLOW_STORE_FILENAME_TEST", name)
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owned filename case {name}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn recorder_start_retains_missing_and_partial_connections() {
    use safeyolo_proxy::flow_store::{FlowRecord, Side};
    use serde_json::json;
    let (store, error) = FlowStore::start(Err(ErrorKind::Type), Settings::default());
    assert_eq!(error.unwrap().kind(), ErrorKind::Type);
    assert_eq!(store.capture_limit(Side::Request), Some(1_048_576));
    assert_eq!(store.get_flow(1).unwrap_err().kind(), ErrorKind::Attribute);
    assert_eq!(
        store.body(1, Side::Response).err().unwrap().kind(),
        ErrorKind::Attribute
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let metadata = json!({"request_id":"before","ts_start":1,"engagement_id":"alice","agent_id":"alice","host":"owned.invalid","flow_state":"completed"});
    store
        .record(
            FlowRecord {
                metadata: metadata.as_object().unwrap(),
                request_body: None,
                response_body: None,
            },
            1,
        )
        .unwrap();
    drop(store);
    let db = Connection::open(&path).unwrap();
    db.execute_batch("DROP TABLE flow_fts; DROP TABLE flow_request_fts; DROP TABLE flow_tags; CREATE TABLE marker(value); CREATE INDEX flow_request_fts ON marker(value);").unwrap();
    drop(db);
    let (store, error) = FlowStore::start(Ok(&path), Settings::default());
    assert_eq!(error.unwrap().kind(), ErrorKind::Operational);
    assert_eq!(
        store.get_flow(1).unwrap_err().kind(),
        ErrorKind::Operational
    );
    assert!(store.body(1, Side::Response).unwrap().is_some());
    assert!(store.get_flow(9).unwrap().is_none());
}
