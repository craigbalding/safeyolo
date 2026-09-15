use std::path::Path;
use std::process::Command;

use rusqlite::{Connection, params};
use safeyolo_proxy::circuits::CircuitValue;
use safeyolo_proxy::flow_store::{
    BodyInput, ErrorKind, FlowRecord, FlowStore, Settings, Side, is_text_like_content_type,
};
use serde_json::{Map, Value, json};

const NOW: i64 = 1_000_123;
fn metadata(id: &str) -> Map<String, Value> {
    json!({"request_id":id,"ts_start":100,"engagement_id":"owned-test","agent_id":"alice","host":"owned.invalid","flow_state":"complete","path":"/plain","method":"POST","status_code":200,"request_content_type":"application/json","response_content_type":"text/plain","request_headers_json":"[[\"X-Proof\", \"one\"], [\"X-Proof\", \"two\"]]","context_json":"{\"run\": \"synthetic\"}","provenance_tags":{"z-last":"z","a-first":"a"}}).as_object().unwrap().clone()
}
fn record(
    store: &FlowStore,
    metadata: &Map<String, Value>,
    request: &[u8],
    response: &[u8],
) -> safeyolo_proxy::flow_store::Result<safeyolo_proxy::flow_store::Recorded> {
    store.record(
        FlowRecord {
            metadata,
            request_body: Some(BodyInput::complete(request)),
            response_body: Some(BodyInput::complete(response)),
        },
        NOW,
    )
}
fn settings(raw: &str) -> Settings {
    let CircuitValue::Object(ref mut values) = CircuitValue::parse_json(raw).unwrap() else {
        panic!("settings object");
    };
    let mut settings = Settings::default();
    for (key, slot) in [
        (
            "max_request_body_bytes",
            &mut settings.max_request_body_bytes,
        ),
        (
            "max_response_body_bytes",
            &mut settings.max_response_body_bytes,
        ),
        ("preview_text_chars", &mut settings.preview_text_chars),
        ("compress_bodies", &mut settings.compress_bodies),
    ] {
        if let Some(value) = values.shift_remove(key) {
            *slot = value;
        }
    }
    settings
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}
fn view(store: &FlowStore, path: &Path, id: i64) -> Value {
    let mut output = json!({"flow":store.get_flow(id).unwrap().unwrap()});
    for (name, side) in [("request", Side::Request), ("response", Side::Response)] {
        let body = store.body(id, side).unwrap().unwrap();
        let mut fields = body.metadata.clone();
        fields.insert("body_hex".into(), Value::String(hex(&body.body)));
        output[name] = Value::Object(fields);
    }
    let db = Connection::open(path).unwrap();
    output["indexes"] = db.query_row("SELECT request_body_text_index,response_body_text_index,request_body_blob IS NULL,response_body_blob IS NULL FROM flows WHERE id=?", [id], |row| Ok(json!([row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?]))).unwrap();
    for (field, table) in [
        ("request_match", "flow_request_fts"),
        ("response_match", "flow_fts"),
    ] {
        let mut statement = db.prepare(&format!("SELECT f.request_id FROM {table} t JOIN flows f ON f.id=t.flow_id WHERE {table} MATCH 'needle'")).unwrap();
        output[field] = json!(
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        );
    }
    output
}

#[test]
fn row_tags_bodies_and_fts_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let recorded = record(
        &store,
        &metadata("roundtrip"),
        b"needle request",
        b"needle response",
    )
    .unwrap();
    assert_eq!(recorded.id, 1);
    assert!(!recorded.response_fts_failed && !recorded.request_fts_failed);
    let before = view(&store, &path, 1);
    assert_eq!(before["flow"]["evidence_owner"], "alice");
    assert_eq!(before["flow"]["tags"][0]["tag"], "a-first");
    assert_eq!(before["response"]["response_body_encoding"], "gzip");
    assert_eq!(before["response"]["response_body_size"], 15);
    assert_eq!(before["response"]["body_hex"], hex(b"needle response"));
    assert_eq!(before["request_match"], json!(["roundtrip"]));
    assert_eq!(before["response_match"], json!(["roundtrip"]));
    drop(store);
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    assert_eq!(view(&store, &path, 1), before);
    assert!(store.get_flow(99).unwrap().is_none());
    assert!(store.body(99, Side::Request).unwrap().is_none());
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
}

#[test]
fn failed_row_and_tags_never_publish_on_later_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let mut failed = metadata("failed");
    failed.insert("provenance_tags".into(), json!({"first":"kept","bad":[]}));
    assert_eq!(
        record(&store, &failed, b"request", b"response")
            .unwrap_err()
            .kind(),
        ErrorKind::Programming
    );
    let success = record(&store, &metadata("success"), b"request", b"response").unwrap();
    assert_eq!(success.id, 1);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM flow_tags WHERE tag='first'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        record(&store, &metadata("success"), b"x", b"x")
            .unwrap_err()
            .kind(),
        ErrorKind::Integrity
    );
    assert_eq!(store.get_flow(1).unwrap().unwrap()["request_id"], "success");
}

#[test]
fn fts_failures_are_independent_and_do_not_undo_flow_or_tags() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute("DROP TABLE flow_fts", []).unwrap();
    let result = record(
        &store,
        &metadata("response-fts-fail"),
        b"needle request",
        b"needle response",
    )
    .unwrap();
    assert!(result.response_fts_failed);
    assert!(!result.request_fts_failed);
    assert_eq!(
        store.get_flow(result.id).unwrap().unwrap()["tags"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM flow_request_fts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    db.execute("DROP TABLE flow_request_fts", []).unwrap();
    let result = record(
        &store,
        &metadata("both-fts-fail"),
        b"needle request",
        b"needle response",
    )
    .unwrap();
    assert!(result.response_fts_failed && result.request_fts_failed);
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn caps_preview_and_raw_setting_errors_are_lazy() {
    let directory = tempfile::tempdir().unwrap();
    let store=FlowStore::open(&directory.path().join("negative.db"),settings(r#"{"max_request_body_bytes":-2,"max_response_body_bytes":0,"preview_text_chars":2,"compress_bodies":false}"#)).unwrap();
    record(
        &store,
        &metadata("negative"),
        "é😀abcd".as_bytes(),
        b"response",
    )
    .unwrap();
    let row = store.get_flow(1).unwrap().unwrap();
    assert_eq!(row["request_body_text_preview"], "é😀");
    assert_eq!(row["request_body_size"], 10);
    assert_eq!(row["request_body_truncated"], 1);
    assert_eq!(row["response_body_size"], 8);
    assert_eq!(row["response_body_stored"], 0);
    let body = store.body(1, Side::Request).unwrap().unwrap();
    assert_eq!(body.body.as_slice(), "é😀ab".as_bytes());
    assert_eq!(body.metadata["request_body_encoding"], "identity");
    let store = FlowStore::open(
        &directory.path().join("float.db"),
        settings(r#"{"max_request_body_bytes":2.0}"#),
    )
    .unwrap();
    record(&store, &metadata("short"), b"ab", b"").unwrap();
    assert_eq!(
        record(&store, &metadata("long"), b"abc", b"")
            .unwrap_err()
            .kind(),
        ErrorKind::Type
    );
    assert!(is_text_like_content_type(&json!("APPLİCATİON/JſON")).unwrap());
    assert!(is_text_like_content_type(&json!("\u{1f}text/plain\u{1f}; charset=utf8")).unwrap());
    assert_eq!(
        is_text_like_content_type(&json!(3)).unwrap_err().kind(),
        ErrorKind::Attribute
    );
}

fn create_legacy(path: &Path) {
    let store = FlowStore::open(path, Settings::default()).unwrap();
    record(
        &store,
        &metadata("legacy"),
        b"needle request",
        b"needle response",
    )
    .unwrap();
    drop(store);
    let db = Connection::open(path).unwrap();
    // Reproduce the historical table shape while keeping bodies/FTS/tags.
    for index in [
        "idx_flows_evidence_owner_ts",
        "idx_flows_attribution_status_ts",
        "idx_flows_agent_test_intent_ts",
    ] {
        db.execute(&format!("DROP INDEX {index}"), []).unwrap();
    }
    for column in [
        "test_agent",
        "suite",
        "subject",
        "step",
        "intent",
        "expect",
        "evidence_owner",
        "trusted_transport_identity",
        "initiator",
        "attribution_status",
        "attribution_provenance_json",
    ] {
        db.execute(&format!("ALTER TABLE flows DROP COLUMN {column}"), [])
            .unwrap();
    }
    db.execute_batch("PRAGMA user_version=1;").unwrap();
    drop(db);
}

#[test]
fn legacy_migration_preserves_evidence_and_v2_quarantine_is_not_repaired() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.db");
    create_legacy(&path);
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let row = store.get_flow(1).unwrap().unwrap();
    assert_eq!(row["evidence_owner"], "alice");
    assert_eq!(row["initiator"], "unknown");
    assert_eq!(
        row["attribution_provenance_json"],
        "{\"migration\":\"flow_store_v1\",\"transport_identity\":\"unknown\"}"
    );
    assert_eq!(
        store
            .body(1, Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"needle response"
    );
    drop(store);
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE flows SET evidence_owner=NULL,attribution_status='conflict'",
        [],
    )
    .unwrap();
    drop(db);
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let row = store.get_flow(1).unwrap().unwrap();
    assert_eq!(row["evidence_owner"], Value::Null);
    assert_eq!(row["agent_id"], "alice");
    assert_eq!(row["attribution_status"], "conflict");
    drop(store);
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA user_version=3").unwrap();
    drop(db);
    assert_eq!(
        FlowStore::open(&path, Settings::default())
            .err()
            .unwrap()
            .kind(),
        ErrorKind::SchemaVersion
    );
}

#[test]
fn reads_python_compatible_concatenated_gzip_and_fails_corruption_categorically() {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gzip.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    record(&store, &metadata("gzip"), b"first", b"second").unwrap();
    let mut blob = Vec::new();
    for body in [b"first".as_slice(), b"second"] {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(body).unwrap();
        blob.extend(encoder.finish().unwrap());
    }
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE flows SET response_body_blob=?", params![blob])
        .unwrap();
    assert_eq!(
        store
            .body(1, Side::Response)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"firstsecond"
    );
    db.execute(
        "UPDATE flows SET response_body_blob=?",
        params![b"invalid gzip".as_slice()],
    )
    .unwrap();
    let error = store.body(1, Side::Response).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::BadGzip);
    assert!(!format!("{error:?} {error}").contains("invalid gzip"));
}

fn source(mode: &str, path: &Path) -> Value {
    let python = std::env::var("SAFEYOLO_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/flow_store_oracle.py"
        ))
        .arg(mode)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "owned source fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "requires actual source Python environment"]
fn differential_storage_and_bidirectional_database_interoperability() {
    let directory = tempfile::tempdir().unwrap();
    let cases = source("matrix", directory.path());
    assert_eq!(cases.as_array().unwrap().len(), 32);
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let original = directory.path().join(format!("{name}.sqlite3"));
        let path = directory.path().join(format!("native-{name}.sqlite3"));
        let store =
            FlowStore::open(&path, settings(case["settings_json"].as_str().unwrap())).unwrap();
        let result = record(
            &store,
            case["metadata"].as_object().unwrap(),
            &unhex(case["request_hex"].as_str().unwrap()),
            &unhex(case["response_hex"].as_str().unwrap()),
        );
        if let Some(expected) = case.get("error").and_then(Value::as_str) {
            let error = result.unwrap_err();
            let class = match error.kind() {
                ErrorKind::Type => "TypeError",
                ErrorKind::Attribute => "AttributeError",
                ErrorKind::Overflow => "OverflowError",
                ErrorKind::Programming => "ProgrammingError",
                ErrorKind::Integrity => "IntegrityError",
                _ => "unexpected",
            };
            assert_eq!(class, expected, "case {name}");
        } else {
            let result = result.unwrap();
            assert!(
                !result.response_fts_failed && !result.request_fts_failed,
                "case {name}"
            );
            assert_eq!(
                view(&store, &path, result.id),
                case["result"],
                "native write case {name}"
            );
            let from_source = FlowStore::open(&original, Settings::default()).unwrap();
            assert_eq!(
                view(&from_source, &original, 1),
                case["result"],
                "source database case {name}"
            );
            assert_eq!(
                source("inspect", &path),
                case["result"],
                "Python native database case {name}"
            );
        }
    }
}

#[test]
#[ignore = "requires actual source Python environment"]
fn differential_schema_legacy_migration_and_quarantine_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let native = directory.path().join("native.db");
    let python = directory.path().join("python.db");
    create_legacy(&native);
    std::fs::copy(&native, &python).unwrap();
    let expected = source("inspect", &python);
    let store = FlowStore::open(&native, Settings::default()).unwrap();
    assert_eq!(view(&store, &native, 1), expected);
    let schema = source("schema", &python);
    let db = Connection::open(&native).unwrap();
    let mut statement = db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name IN ('flows','flow_fts','flow_request_fts','flow_tags') OR name LIKE 'idx_flow%' ORDER BY name").unwrap();
    let actual = statement
        .query_map([], |row| {
            Ok(json!([
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?
            ]))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(json!(actual), schema);
    drop(store);
    for path in [&native, &python] {
        Connection::open(path)
            .unwrap()
            .execute(
                "UPDATE flows SET evidence_owner=NULL,attribution_status='conflict'",
                [],
            )
            .unwrap();
    }
    let expected = source("inspect", &python);
    let store = FlowStore::open(&native, Settings::default()).unwrap();
    assert_eq!(view(&store, &native, 1), expected);
    assert_eq!(expected["flow"]["evidence_owner"], Value::Null);
    assert_eq!(expected["flow"]["agent_id"], "alice");
}

#[test]
fn decoded_prefix_preserves_original_sizes_and_source_slice_without_full_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let full_path = directory.path().join("full.db");
    let prefix_path = directory.path().join("prefix.db");
    let raw = r#"{"max_request_body_bytes":3,"max_response_body_bytes":0}"#;
    let full = FlowStore::open(&full_path, settings(raw)).unwrap();
    let prefix = FlowStore::open(&prefix_path, settings(raw)).unwrap();
    assert_eq!(prefix.capture_limit(Side::Request), Some(3));
    assert_eq!(prefix.capture_limit(Side::Response), Some(0));
    let metadata = metadata("prefix");
    record(&full, &metadata, b"abcdefgh", b"response").unwrap();
    prefix
        .record(
            FlowRecord {
                metadata: &metadata,
                request_body: Some(BodyInput::decoded_prefix(b"abc", 8)),
                response_body: Some(BodyInput::decoded_prefix(b"", 8)),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(view(&full, &full_path, 1), view(&prefix, &prefix_path, 1));
    let mut metadata = metadata.clone();
    metadata.insert("request_id".into(), json!("incomplete"));
    assert_eq!(
        prefix
            .record(
                FlowRecord {
                    metadata: &metadata,
                    request_body: Some(BodyInput::decoded_prefix(b"ab", 8)),
                    response_body: None,
                },
                NOW
            )
            .unwrap_err()
            .kind(),
        ErrorKind::Value
    );
    assert!(prefix.get_flow(2).unwrap().is_none());
    for (index, raw) in [
        "-1",
        "1.0",
        "NaN",
        "100000000000000000000000000000",
        "null",
        "[]",
    ]
    .into_iter()
    .enumerate()
    {
        let store = FlowStore::open(
            &directory.path().join(format!("fallback{index}.db")),
            settings(&format!("{{\"max_request_body_bytes\":{raw}}}")),
        )
        .unwrap();
        assert_eq!(store.capture_limit(Side::Request), None, "{raw}");
    }
}
