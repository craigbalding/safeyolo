use std::path::Path;
use std::process::Command;

use rusqlite::{Connection, params};
use safeyolo_proxy::{
    circuits::CircuitValue,
    flow_store::{BodyInput, ErrorKind, FlowRecord, FlowStore, Settings},
};
use serde_json::{Value, json};

fn record(store: &FlowStore, name: &str, body: &[u8], content_type: &str) {
    let metadata = json!({"request_id":name,"ts_start":1,"engagement_id":"owned","agent_id":"alice","host":"owned.invalid","flow_state":"completed","response_content_type":content_type});
    store
        .record(
            FlowRecord {
                metadata: metadata.as_object().unwrap(),
                request_body: None,
                response_body: Some(BodyInput::complete(body)),
            },
            1,
        )
        .unwrap();
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn body(recipe: &Value) -> Vec<u8> {
    if let Some(value) = recipe.get("hex") {
        return unhex(value.as_str().unwrap());
    }
    if recipe["kind"] == "prefix" {
        return format!(
            "{}{}",
            recipe["character"].as_str().unwrap().repeat(100_000),
            recipe["tail"].as_str().unwrap()
        )
        .into_bytes();
    }
    (0..recipe["lines"].as_u64().unwrap())
        .map(|index| format!("{}{index}\n", recipe["prefix"].as_str().unwrap()))
        .collect::<String>()
        .into_bytes()
}
fn summary(value: &Value) -> Value {
    let encoded = serde_json::to_vec(value).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, &encoded);
    let hash = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if value.is_null() {
        return json!({"sha256":hash,"missing":true});
    }
    json!({"sha256":hash,"identical":value["identical"],"size_a":value["size_a"],"size_b":value["size_b"],
        "chars_a":value["body_text_a"].as_str().map(|text|text.chars().count()),"chars_b":value["body_text_b"].as_str().map(|text|text.chars().count()),
        "line_count":value["diff_lines"].as_array().unwrap().len(),"truncated":value["diff_truncated"]})
}
fn class(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Integrity => "IntegrityError",
        ErrorKind::Programming => "ProgrammingError",
        ErrorKind::Overflow => "OverflowError",
        ErrorKind::BadGzip => "BadGzipFile",
        ErrorKind::Attribute => "AttributeError",
        _ => "unexpected",
    }
}
fn compare(fixture: &Value) {
    let directory = tempfile::tempdir().unwrap();
    let store = FlowStore::open(&directory.path().join("tags.db"), Settings::default()).unwrap();
    record(&store, "tagged", b"", "text/plain");
    assert_eq!(fixture["tags"].as_array().unwrap().len(), 26);
    for row in fixture["tags"].as_array().unwrap() {
        let tag = CircuitValue::parse_json(row["tag_json"].as_str().unwrap()).unwrap();
        let result = if row["delete"] == true {
            store
                .untag_flow(row["id"].as_i64().unwrap(), &tag)
                .map(|deleted| json!(deleted))
        } else {
            let value = CircuitValue::parse_json(row["value_json"].as_str().unwrap()).unwrap();
            store
                .tag_flow(
                    row["id"].as_i64().unwrap(),
                    &tag,
                    &value,
                    row["now"].as_i64().unwrap(),
                )
                .map(|value| Value::String(value.render_json(false).unwrap()))
        };
        if let Some(expected) = row.get("error").and_then(Value::as_str) {
            assert_eq!(
                class(result.unwrap_err().kind()),
                expected,
                "{}",
                row["name"]
            );
        } else {
            assert_eq!(
                result.unwrap(),
                if row["delete"] == true {
                    row["deleted"].clone()
                } else {
                    row["immediate_json"].clone()
                },
                "{}",
                row["name"]
            );
        }
        assert_eq!(
            store.get_flow_tags(1).unwrap(),
            row["tags"],
            "{}",
            row["name"]
        );
        assert_eq!(store.get_flow(1).unwrap().unwrap()["tags"], row["tags"]);
    }
    assert_eq!(store.get_flow_tags(99).unwrap(), json!([]));
    assert_eq!(fixture["diff"].as_array().unwrap().len(), 146);
    for (index, case) in fixture["diff"].as_array().unwrap().iter().enumerate() {
        let path = directory.path().join(format!("diff{index}.db"));
        let settings = Settings {
            max_response_body_bytes: CircuitValue::from(
                case.get("limit")
                    .cloned()
                    .unwrap_or_else(|| json!(4_194_304)),
            ),
            ..Settings::default()
        };
        let store = FlowStore::open(&path, settings).unwrap();
        record(
            &store,
            "a",
            &body(&case["a"]),
            case["ct_a"].as_str().unwrap_or("text/plain"),
        );
        record(
            &store,
            "b",
            &body(&case["b"]),
            case["ct_b"].as_str().unwrap_or("text/plain"),
        );
        if let Some(corrupt) = case.get("corrupt") {
            Connection::open(&path).unwrap().execute("UPDATE flows SET response_body_blob=?,response_body_encoding='gzip' WHERE id=?",params![b"not gzip".as_slice(),if corrupt=="a" {1}else{2}]).unwrap();
        }
        let result = store.diff_flows(
            if case["missing"] == "a" { 9 } else { 1 },
            if case["missing"] == "b" { 9 } else { 2 },
        );
        if let Some(expected) = case.get("error").and_then(Value::as_str) {
            assert_eq!(
                class(result.unwrap_err().kind()),
                expected,
                "{}",
                case["name"]
            );
        } else {
            assert_eq!(
                summary(&result.unwrap().unwrap_or(Value::Null)),
                case["summary"],
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn retained_tags_and_diff_match_frozen_source() {
    compare(&serde_json::from_str(include_str!("flow_store_details_source.json")).unwrap());
}

#[test]
#[ignore = "requires actual source Python environment"]
fn retained_tags_and_diff_match_live_source() {
    let python = std::env::var("SAFEYOLO_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/flow_store_details_oracle.py"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "source fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    compare(&serde_json::from_slice(&output.stdout).unwrap());
}

#[test]
fn committed_tag_survives_reopen_and_error_does_not_discard_other_tags() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tags.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    record(&store, "owned", b"response", "text/plain");
    let tag = CircuitValue::from(json!("label"));
    store
        .tag_flow(1, &tag, &CircuitValue::from(json!("first")), 1000)
        .unwrap();
    store
        .tag_flow(1, &tag, &CircuitValue::from(json!("second")), 2000)
        .unwrap();
    assert_eq!(
        store
            .tag_flow(99, &tag, &CircuitValue::from(json!("foreign")), 3000)
            .unwrap_err()
            .kind(),
        ErrorKind::Integrity
    );
    drop(store);
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    assert_eq!(
        store.get_flow_tags(1).unwrap(),
        json!([{"tag":"label","value":"second","created_at":2000}])
    );
    assert!(store.untag_flow(1, &tag).unwrap());
    assert!(!store.untag_flow(1, &tag).unwrap());
}

#[test]
fn missing_connection_error_precedes_consuming_tag_values() {
    let (store, error) = FlowStore::start(Err(ErrorKind::Type), Settings::default());
    assert!(error.is_some());
    let malformed = CircuitValue::from(json!([]));
    assert_eq!(
        store
            .tag_flow(1, &malformed, &malformed, 0)
            .unwrap_err()
            .kind(),
        ErrorKind::Attribute
    );
    assert_eq!(
        store.untag_flow(1, &malformed).unwrap_err().kind(),
        ErrorKind::Attribute
    );
    assert_eq!(
        store.get_flow_tags(1).unwrap_err().kind(),
        ErrorKind::Attribute
    );
    assert_eq!(
        store.diff_flows(1, 2).unwrap_err().kind(),
        ErrorKind::Attribute
    );
}

fn pending_schema(path: &Path) {
    let store = FlowStore::open(path, Settings::default()).unwrap();
    record(&store, "owned", b"response", "text/plain");
    drop(store);
    Connection::open(path).unwrap().execute_batch("DROP TABLE flow_fts; DROP TABLE flow_request_fts; CREATE TABLE marker(value); CREATE INDEX flow_request_fts ON marker(value); PRAGMA user_version=1;").unwrap();
}

#[test]
fn tag_commit_releases_existing_pending_initialization_like_source() {
    let fixture: Value =
        serde_json::from_str(include_str!("flow_store_details_source.json")).unwrap();
    let expected = &fixture["pending"];
    assert_eq!(expected["error"], "OperationalError");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial.db");
    pending_schema(&path);
    let (store, error) = FlowStore::start(Ok(&path), Settings::default());
    assert_eq!(error.unwrap().kind(), ErrorKind::Operational);
    let external = Connection::open(&path).unwrap();
    assert_eq!(
        external
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        expected["before"].as_i64().unwrap()
    );
    store
        .tag_flow(
            1,
            &CircuitValue::from(json!("ready")),
            &CircuitValue::from(json!("yes")),
            4000,
        )
        .unwrap();
    assert_eq!(
        external
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        expected["after"].as_i64().unwrap()
    );
    assert_eq!(store.get_flow_tags(1).unwrap(), expected["tags"]);
}
