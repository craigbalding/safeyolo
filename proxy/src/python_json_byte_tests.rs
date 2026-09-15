//! The frozen source inputs contain only synthetic context strings. The strict
//! byte codec is separate from JSON syntax and Python's surrogatepass behavior.

use super::{JsonEncodingError, decode_json_text};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/python_json_bytes_source.json")).unwrap()
}

fn compare(row: &Value) {
    let bytes: Vec<u8> = row["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| u8::try_from(value.as_u64().unwrap()).unwrap())
        .collect();
    let decoded: Result<Zeroizing<String>, JsonEncodingError> = decode_json_text(&bytes);
    let actual = match decoded {
        Ok(text) => json!({"ok":true, "text":text.as_str()}),
        Err(JsonEncodingError) => json!({"ok":false}),
    };
    assert_eq!(actual, row["strict"], "{}", row["name"]);
}

#[test]
fn byte_decoder_matches_frozen_python_encoding_boundaries() {
    let fixture = fixture();
    let rows = fixture["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 35);
    for row in rows {
        compare(row);
    }
    // These are inherited strict-Unicode gaps, not new decoder restrictions.
    let gaps: Vec<_> = rows
        .iter()
        .filter(|row| row["strict"]["ok"] == false && row["loads"]["ok"] == true)
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        gaps,
        [
            "utf16_unpaired_high",
            "utf16_unpaired_low",
            "utf32_surrogate",
            "utf8_encoded_surrogate"
        ]
    );
}

#[test]
#[ignore = "actual Python byte-codec oracle; set SAFEYOLO_POLICY_PYTHON"]
fn byte_decoder_matches_live_python_without_changing_json_admission() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let fixture = fixture();
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON")
        .expect("set SAFEYOLO_POLICY_PYTHON to the existing Python executable");
    let mut child = Command::new(python)
        .arg("-c")
        .arg(
            r#"
import json,sys
rows=[]
for case in json.load(sys.stdin):
    raw=bytes(case['bytes'])
    try:
        strict={'ok':True,'text':raw.decode(json.detect_encoding(raw))}
    except UnicodeDecodeError:
        strict={'ok':False}
    try:
        json.loads(raw)
        loaded={'ok':True}
    except (UnicodeDecodeError,json.JSONDecodeError) as error:
        loaded={'ok':False,'exception':type(error).__name__}
    rows.append({'strict':strict,'loads':loaded})
json.dump(rows,sys.stdout)
"#,
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
        .write_all(&serde_json::to_vec(&fixture["rows"]).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "actual Python byte-codec probe failed"
    );
    let live: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    assert_eq!(live.len(), rows.len());
    for (row, live) in rows.iter().zip(live) {
        assert_eq!(
            live,
            json!({"strict":row["strict"], "loads":row["loads"]}),
            "{}",
            row["name"]
        );
        compare(row);
    }
    eprintln!(
        "Compared 35 actual Python byte-codec cases; four strict surrogate gaps remain explicit"
    );
}
