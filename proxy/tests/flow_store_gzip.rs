use std::process::Command;

use rusqlite::{Connection, params};
use safeyolo_proxy::flow_store::{ErrorKind, FlowRecord, FlowStore, Settings, Side};
use serde_json::{Value, json};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn stored_gzip_frozen_source_framing_and_error_classes() {
    compare(serde_json::from_str(include_str!("flow_store_gzip_source.json")).unwrap());
}

#[test]
#[ignore = "requires actual source Python environment"]
fn stored_gzip_live_source_framing_and_error_classes() {
    let python = std::env::var("SAFEYOLO_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/flow_store_gzip_oracle.py"
        ))
        .output()
        .unwrap();
    assert!(output.status.success());
    compare(serde_json::from_slice(&output.stdout).unwrap());
}

fn compare(rows: Value) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gzip.db");
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    let metadata = json!({"request_id":"owned","ts_start":1,"engagement_id":"alice","agent_id":"alice","host":"owned.invalid","flow_state":"completed"});
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
    let connection = Connection::open(path).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 59);
    for row in rows.as_array().unwrap() {
        let compressed = unhex(row["compressed_hex"].as_str().unwrap());
        connection.execute("UPDATE flows SET response_body_blob=?,response_body_encoding='gzip',response_body_stored=1",params![compressed]).unwrap();
        let result = store.body(1, Side::Response);
        if let Some(expected) = row.get("error").and_then(Value::as_str) {
            let error = result.err().unwrap();
            let class = match error.kind() {
                ErrorKind::BadGzip => "BadGzipFile",
                ErrorKind::UnexpectedEof => "EOFError",
                ErrorKind::Deflate => "error",
                _ => "unexpected",
            };
            assert_eq!(class, expected, "{}", row["name"]);
        } else {
            let body = result.unwrap().unwrap();
            assert_eq!(
                body.body.as_slice(),
                unhex(row["body_hex"].as_str().unwrap()),
                "{}",
                row["name"]
            );
        }
    }
}
