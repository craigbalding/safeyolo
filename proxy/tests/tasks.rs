use std::sync::{Arc, Barrier};

use safeyolo_proxy::{
    policy::{Format, Policy},
    tasks::{Error, Registry},
};
use serde_json::{Value, json};

const SOURCE: &str = include_str!("tasks_source.json");

#[test]
fn registration_admission_and_raw_get_match_actual_source_schema() {
    let source: Value = serde_json::from_str(SOURCE).unwrap();
    let cases = source["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let registry = Registry::default();
        let task_id = case["task_id"].as_str().unwrap();
        let document: Value = serde_json::from_str(case["document"].as_str().unwrap()).unwrap();
        let actual = registry.upsert(task_id, document);
        let expected = &case["source"];
        if expected["result"]["status"] == "ok" {
            let actual = actual.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                actual.permission_count,
                expected["result"]["permissions"].as_u64().unwrap() as usize,
                "{name}"
            );
            let retained = registry.get(task_id).unwrap().unwrap();
            assert_eq!(retained.document(), &expected["retained"], "{name}");
        } else {
            let error = if expected["result"]["error"] == "Invalid task ID" {
                Error::InvalidId
            } else {
                Error::InvalidPolicy
            };
            assert_eq!(actual, Err(error), "{name}");
            assert!(registry.get(task_id).unwrap().is_none(), "{name}");
        }
        assert_eq!(
            registry.count().unwrap(),
            expected["count"].as_u64().unwrap() as usize,
            "{name}"
        );
        assert_eq!(expected["active_task"], false);
        assert_eq!(expected["hash_unchanged"], true);
    }
    assert_eq!(cases.len(), 56);
}

#[test]
fn replacement_keeps_raw_owners_and_failed_updates_keep_the_last_entry() {
    let registry = Registry::default();
    let raw = json!({
        "metadata":{"task_id":"authored-id"},
        "permissions":[{"action":"network:request","resource":"*"}],
        "unknown":{"private":"synthetic-value"}
    });
    assert_eq!(
        registry
            .upsert("registered-id", raw.clone())
            .unwrap()
            .permission_count,
        1
    );
    let old = registry.get("registered-id").unwrap().unwrap();
    assert_eq!(old.document(), &raw);
    assert!(old.document().get("addons").is_none());
    let clone = registry.clone();
    assert!(Arc::ptr_eq(
        &old,
        &clone.get("registered-id").unwrap().unwrap()
    ));
    assert_eq!(
        clone
            .upsert("registered-id", json!({}))
            .unwrap()
            .permission_count,
        0
    );
    assert_eq!(registry.count().unwrap(), 1);
    assert_eq!(
        registry.get("registered-id").unwrap().unwrap().document(),
        &json!({})
    );
    assert_eq!(old.document(), &raw);
    for (id, value, error) in [
        (
            "../unsafe",
            json!({"private":"synthetic-value"}),
            Error::InvalidId,
        ),
        (
            "registered-id",
            json!({"permissions":false,"private":"synthetic-value"}),
            Error::InvalidPolicy,
        ),
    ] {
        assert_eq!(registry.upsert(id, value), Err(error));
        assert!(!error.to_string().contains("synthetic"));
        assert!(!format!("{error:?}").contains("synthetic"));
    }
    assert_eq!(
        registry.get("registered-id").unwrap().unwrap().document(),
        &json!({})
    );
    assert_eq!(registry.count().unwrap(), 1);
    drop(registry);
    assert_eq!(clone.count().unwrap(), 1);
    drop(clone);
    assert_eq!(old.document(), &raw);
    assert_eq!(Registry::default().count().unwrap(), 0);
}

#[test]
fn schema_registration_accepts_values_that_the_native_matcher_cannot_compile() {
    for raw in [
        json!({"budgets":{"network:request":0}}),
        json!({"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":-1}]}),
    ] {
        let policy = Policy::parse("{}", Format::Json).unwrap();
        assert!(
            policy
                .with_task_source(&raw.to_string(), Format::Json)
                .is_err()
        );
        let hash = policy.policy_hash();
        let registry = Registry::default();
        registry.upsert("schema-valid", raw.clone()).unwrap();
        assert_eq!(
            registry.get("schema-valid").unwrap().unwrap().document(),
            &raw
        );
        assert_eq!(policy.policy_hash(), hash);
    }
}

#[test]
fn literal_marker_objects_and_raw_numeric_types_survive_registration() {
    let mut literal = serde_json::Map::new();
    literal.insert(
        "$serde_json::private::Number".into(),
        Value::String("17".into()),
    );
    let mut gateway = serde_json::Map::new();
    gateway.insert("literal".into(), Value::Object(literal));
    let mut raw = serde_json::Map::new();
    raw.insert("gateway".into(), Value::Object(gateway));
    raw.insert("budgets".into(), json!({"network:request":"0007"}));
    let raw = Value::Object(raw);
    let registry = Registry::default();
    registry.upsert("literal", raw.clone()).unwrap();
    let retained = registry.get("literal").unwrap().unwrap();
    assert_eq!(retained.document(), &raw);
    assert!(retained.document()["gateway"]["literal"].is_object());
    assert_eq!(
        retained.document()["gateway"]["literal"]["$serde_json::private::Number"],
        "17"
    );
    assert_eq!(retained.document()["budgets"]["network:request"], "0007");
}

#[test]
fn concurrent_writers_publish_complete_entries_and_reads_keep_stable_owners() {
    let registry = Registry::default();
    let start = Arc::new(Barrier::new(9));
    let mut writers = Vec::new();
    for worker in 0..8 {
        let registry = registry.clone();
        let start = start.clone();
        writers.push(std::thread::spawn(move || {
            start.wait();
            for revision in 0..64 {
                let raw = json!({"revision":[worker,revision],"echo":[worker,revision]});
                registry.upsert("shared", raw.clone()).unwrap();
                registry.upsert(&format!("worker-{worker}"), raw).unwrap();
                let read = registry.get("shared").unwrap().unwrap();
                assert_eq!(read.document()["revision"], read.document()["echo"]);
                let snapshot = read.document()["revision"].clone();
                std::thread::yield_now();
                assert_eq!(read.document()["revision"], snapshot);
            }
        }));
    }
    start.wait();
    for writer in writers {
        writer.join().unwrap();
    }
    assert_eq!(registry.count().unwrap(), 9);
    for worker in 0..8 {
        assert_eq!(
            registry
                .get(&format!("worker-{worker}"))
                .unwrap()
                .unwrap()
                .document()["revision"],
            json!([worker, 63])
        );
    }
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn live_registration_schema_matches_frozen_source() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let source: Value = serde_json::from_str(SOURCE).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg(root.join("proxy/tests/tasks_oracle.py"))
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "source registration oracle failed");
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected = source["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["source"].clone())
        .collect::<Vec<_>>();
    assert_eq!(actual["rows"], Value::Array(expected));
    assert_eq!(actual["attempts"], json!({"network":0,"mint":0}));
}
