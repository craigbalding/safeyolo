use std::{io, sync::Arc};

use serde_json::Value;
use zeroize::Zeroizing;

use super::{Policy, write_baseline, write_float};
use crate::policy::{BaselineSerializationError, Format};

const SOURCE: &str = include_str!("../../../tests/policy_model_json_source.json");
const NUMBERS: &str = include_str!("../../../tests/policy_model_json_numbers.json");

fn format(value: &Value) -> Format {
    match value.as_str().unwrap() {
        "json" => Format::Json,
        "yaml" => Format::Yaml,
        "toml" => Format::Toml,
        _ => panic!("fixture format"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn load(row: &Value) -> crate::policy::Result<Policy> {
    let policy = match row["source"].as_str() {
        Some(source) => Policy::parse_at(source, format(&row["format"]), 0.)?,
        None => Policy::unconfigured(),
    };
    match row["task"].as_str() {
        Some(source) => policy.with_task_source(source, format(&row["task_format"])),
        None => Ok(policy),
    }
}

#[test]
fn exact_source_model_bytes_then_hash_with_explicit_frontend_gaps() {
    let fixture: Value = serde_json::from_str(SOURCE).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    let gaps = [
        "json_nonfinite",
        "yaml_nonstrings_as_any_keys",
        "yaml_binary_utf8",
        "yaml_binary_invalid_utf8",
        "yaml_set",
        "toml_nonfinite",
        "json_lone_surrogate_any",
    ];
    let mut compared = 0;
    let mut unsupported = 0;
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let loaded = load(row);
        if gaps.contains(&name) {
            assert!(loaded.is_err(), "gap unexpectedly admitted: {name}");
            unsupported += 1;
            continue;
        }
        let policy =
            loaded.unwrap_or_else(|_| panic!("source-supported native row failed: {name}"));
        for (model, label) in [
            (policy.baseline.as_deref(), "baseline_hex"),
            (policy.task.as_ref().map(|task| &*task.baseline), "task_hex"),
        ] {
            let mut bytes = Zeroizing::new(Vec::new());
            if let Some(model) = model {
                write_baseline(model, &mut *bytes).unwrap();
            }
            // Do not round-trip expected JSON: distinct typed and quoted
            // temporal keys deliberately have duplicate serialized spellings.
            assert!(
                hex(&bytes) == row[label].as_str().unwrap(),
                "model bytes differ: {name}/{label}"
            );
        }
        let mut bytes = Zeroizing::new(Vec::new());
        policy.write_model_json(&mut *bytes).unwrap();
        assert!(
            hex(&bytes) == row["combined_hex"].as_str().unwrap(),
            "concatenated bytes differ: {name}"
        );
        assert!(
            policy.policy_hash() == row["policy_hash"].as_str().unwrap(),
            "hash differs: {name}"
        );
        compared += 1;
    }
    assert_eq!((rows.len(), compared, unsupported), (30, 23, 7));
}

#[test]
fn pinned_finite_float_bytes_match_all_1015_source_samples() {
    let fixture: Value = serde_json::from_str(NUMBERS).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    for row in rows {
        let bits = u64::from_str_radix(row["bits"].as_str().unwrap(), 16).unwrap();
        let mut bytes = Vec::new();
        write_float(f64::from_bits(bits), &mut bytes).unwrap();
        assert_eq!(
            bytes,
            row["source"].as_str().unwrap().as_bytes(),
            "f64 {bits:016x}"
        );
    }
    assert_eq!(rows.len(), 1015);
    for nonfinite in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
        let mut bytes = Vec::new();
        write_float(nonfinite, &mut bytes).unwrap();
        assert_eq!(bytes, b"null");
    }
}

#[test]
fn canonical_task_owner_is_shared_and_replaced_without_mutating_old_snapshots() {
    let baseline = Policy::parse("{}", Format::Json).unwrap();
    let absent_hash = Policy::unconfigured().policy_hash();
    assert_ne!(absent_hash, baseline.policy_hash());
    let with_task = baseline.with_task_source("{}", Format::Json).unwrap();
    let task = &with_task.task.as_ref().unwrap().baseline;
    let clone = with_task.clone();
    assert!(Arc::ptr_eq(task, &clone.task.as_ref().unwrap().baseline));
    assert!(Arc::ptr_eq(
        baseline.baseline.as_ref().unwrap(),
        with_task.baseline.as_ref().unwrap()
    ));
    assert_ne!(with_task.policy_hash(), baseline.policy_hash());
    assert_eq!(
        with_task.without_task().policy_hash(),
        baseline.policy_hash()
    );
    assert_eq!(clone.policy_hash(), with_task.policy_hash());
    assert!(with_task.with_task_source("{", Format::Json).is_err());
    assert_eq!(clone.policy_hash(), with_task.policy_hash());
    let replacement = with_task
        .with_task_source(r#"{"metadata":{"task_id":"replacement"}}"#, Format::Json)
        .unwrap();
    assert!(!Arc::ptr_eq(
        task,
        &replacement.task.as_ref().unwrap().baseline
    ));
    assert_ne!(replacement.policy_hash(), with_task.policy_hash());
}

#[test]
fn typed_hash_does_not_change_ordinary_baseline_serialization_or_debug() {
    let policy = Policy::parse("gateway: {private_fixture: 2024-01-01}\n", Format::Yaml).unwrap();
    assert_eq!(
        policy.baseline().err(),
        Some(BaselineSerializationError::NonJsonTimestamp)
    );
    let before = policy.policy_hash();
    assert_eq!(policy.policy_hash(), before);
    assert_eq!(
        policy.baseline().err(),
        Some(BaselineSerializationError::NonJsonTimestamp)
    );
    let debug = format!("{policy:?}");
    assert!(!debug.contains("private_fixture"));
    assert!(!debug.contains("2024"));
}

#[test]
fn partial_sink_failures_propagate_without_model_content() {
    struct FailsAfter(usize);
    impl io::Write for FailsAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let count = self.0.min(bytes.len());
            self.0 -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let policy = Policy::parse(
        r#"{"gateway":{"private_fixture":"synthetic-value"}}"#,
        Format::Json,
    )
    .unwrap();
    let mut full = Zeroizing::new(Vec::new());
    policy.write_model_json(&mut *full).unwrap();
    for limit in 0..full.len() {
        let error = policy.write_model_json(&mut FailsAfter(limit)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!error.to_string().contains("private_fixture"));
        assert!(!error.to_string().contains("synthetic-value"));
    }
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON"]
fn live_loaded_models_and_float_bytes_match_pinned_source() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let fixture: Value = serde_json::from_str(SOURCE).unwrap();
    let numbers: Value = serde_json::from_str(NUMBERS).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let request = serde_json::json!({
        "rows": fixture["rows"],
        "bits": numbers["rows"].as_array().unwrap().iter().map(|row| &row["bits"]).collect::<Vec<_>>()
    });
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg(root.join("proxy/tests/policy_model_json_oracle.py"))
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .env("PYTHONHASHSEED", "0")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "source model oracle failed");
    let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        actual["attempts"],
        serde_json::json!({"network":0,"mint":0})
    );
    let actual_rows = actual["rows"].as_array().unwrap();
    let expected_rows = fixture["rows"].as_array().unwrap();
    assert_eq!(actual_rows.len(), expected_rows.len());
    for (actual, expected) in actual_rows.iter().zip(expected_rows) {
        let name = expected["name"].as_str().unwrap();
        for field in [
            "name",
            "baseline_hex",
            "baseline_error",
            "task_hex",
            "task_error",
            "policy_hash",
            "hash_error",
        ] {
            assert!(
                actual[field] == expected[field],
                "live source mismatch: {name}/{field}"
            );
        }
        if let Ok(policy) = load(expected) {
            let mut bytes = Zeroizing::new(Vec::new());
            policy.write_model_json(&mut *bytes).unwrap();
            let expected_hex = format!(
                "{}{}",
                actual["baseline_hex"].as_str().unwrap(),
                actual["task_hex"].as_str().unwrap()
            );
            assert!(
                hex(&bytes) == expected_hex,
                "live model bytes differ: {name}"
            );
            assert!(
                policy.policy_hash() == actual["policy_hash"].as_str().unwrap(),
                "live hash differs: {name}"
            );
        }
    }
    assert_eq!(actual["numbers"].as_array().unwrap().len(), 1015);
    for (actual, expected) in actual["numbers"]
        .as_array()
        .unwrap()
        .iter()
        .zip(numbers["rows"].as_array().unwrap())
    {
        assert_eq!(actual, &expected["source"]);
        let bits = u64::from_str_radix(expected["bits"].as_str().unwrap(), 16).unwrap();
        let mut bytes = Vec::new();
        write_float(f64::from_bits(bits), &mut bytes).unwrap();
        assert_eq!(bytes, actual.as_str().unwrap().as_bytes());
    }
}
