use safeyolo_proxy::circuits::*;
use serde_json::Value;
use std::{fmt, fs};

fn source() -> Value {
    serde_json::from_str(include_str!("circuit_json_source.json")).unwrap()
}
fn state_document() -> CircuitValue {
    CircuitValue::parse_json(&format!(
        "{{\"states\":{}}}",
        source()["state"].as_str().unwrap()
    ))
    .unwrap()
}

#[test]
fn python_json_constants_order_escaping_and_malformed_inputs() {
    let source = source();
    for case in source["cases"].as_array().unwrap() {
        let parsed = CircuitValue::parse_json(case["source"].as_str().unwrap());
        assert_eq!(
            parsed.is_ok(),
            case["accepted"].as_bool().unwrap(),
            "{case}"
        );
        if let Ok(value) = parsed {
            assert_eq!(value.render_json(false).unwrap(), case["compact"], "{case}");
            assert_eq!(value.render_json(true).unwrap(), case["pretty"], "{case}");
            // Reparse the emitted genuine constants; NaN intentionally is not Eq.
            assert_eq!(
                CircuitValue::parse_json(&value.render_json(true).unwrap())
                    .unwrap()
                    .render_json(false)
                    .unwrap(),
                case["compact"]
            );
        }
    }
    // The existing Rust scalar string owner cannot represent a lone surrogate.
    // Keep the source-admitted gap explicit, rather than claiming full JSON parity.
    assert!(CircuitValue::parse_json(source["inherited_gap"]["source"].as_str().unwrap()).is_err());
}

#[test]
fn typed_status_stats_transition_and_snapshot_match_actual_source() {
    let cb = CircuitBreaker::new();
    cb.restore_document(&state_document(), 100., &mut || 0.5)
        .unwrap();
    let result = cb.record_failure("api", None, 100., &mut || 0.5).unwrap();
    let expected = source();
    let expected = &expected["workflow"];
    assert_eq!(
        result.value.document().render_json(false).unwrap(),
        expected["status"]
    );
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.document().render_json(false).unwrap())
            .collect::<Vec<_>>(),
        expected["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    let stats = cb.stats_document(true, 100., &mut || 0.5).unwrap();
    assert_eq!(stats.value.render_json(false).unwrap(), expected["stats"]);
    assert_eq!(
        cb.snapshot_document(100.)
            .unwrap()
            .render_json(false)
            .unwrap(),
        expected["snapshot"]
    );
    assert_eq!(
        cb.snapshot(100.).unwrap_err().kind(),
        ErrorKind::Compatibility
    );
    assert_eq!(
        cb.stats(true, 100., &mut || 0.5).unwrap_err().kind(),
        ErrorKind::Compatibility
    );
    assert!(serde_json::to_value(&result.value).is_err());
    assert!(serde_json::to_value(&result.events).is_err());
}

#[test]
fn nonfinite_files_restart_failed_publication_and_rejected_reload_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("state.json");
    let cb = CircuitBreaker::new();
    cb.restore_document(&state_document(), 100., &mut || 0.5)
        .unwrap();
    cb.save_file(&file, 100.).unwrap();
    let saved = fs::read_to_string(&file).unwrap();
    assert!(saved.contains("NaN") && saved.contains("Infinity") && saved.contains("-Infinity"));
    let restarted = CircuitBreaker::new();
    assert_eq!(
        restarted.load_file(&file, 100., &mut || 0.5).unwrap().value,
        LoadDisposition::Loaded
    );
    assert_eq!(
        restarted
            .snapshot_document(100.)
            .unwrap()
            .render_json(true)
            .unwrap(),
        saved
    );

    let obstructed = directory.path().join("is-directory");
    fs::create_dir(&obstructed).unwrap();
    fs::write(obstructed.join("owned"), b"preserve").unwrap();
    assert!(cb.save_file(&obstructed, 100.).is_err());
    assert_eq!(fs::read(obstructed.join("owned")).unwrap(), b"preserve");
    assert_eq!(fs::read_to_string(&file).unwrap(), saved);
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".circuit-")
    }));

    fs::write(
        &file,
        r#"{"states":{"bad":{"state":"open","failure_streak":{},"opened_at":NaN}}}"#,
    )
    .unwrap();
    assert_eq!(
        restarted
            .load_file(&file, 100., &mut || 0.5)
            .unwrap_err()
            .kind(),
        ErrorKind::Type
    );
    assert_eq!(
        restarted
            .snapshot_document(100.)
            .unwrap()
            .render_json(true)
            .unwrap(),
        saved
    );
    fs::write(&file, r#"{"states":{"value":NaNx}}"#).unwrap();
    assert_eq!(
        restarted.load_file(&file, 100., &mut || 0.5).unwrap().value,
        LoadDisposition::DiscardedInvalidJson
    );
    assert!(
        restarted
            .snapshot_document(100.)
            .unwrap()
            .as_object()
            .unwrap()["states"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deep_typed_documents_use_stack_traversal_and_cleanup_without_a_depth_cap() {
    // Beyond both the former shared reader's 128 limit and the source reader's
    // default recursion depth. This is a native resource witness, not parity.
    let depth = 5000;
    let input = format!("{}NaN{}", "[".repeat(depth), "]".repeat(depth));
    let value = CircuitValue::parse_json(&input).unwrap();
    let cloned = value.clone();
    assert_eq!(cloned.render_json(false).unwrap(), input);
    drop(value);
    drop(cloned);
    assert!(CircuitValue::parse_json(&format!("{input} trailing")).is_err());
    let finite = format!("{}0{}", "{\"a\":".repeat(depth), "}".repeat(depth));
    let value = CircuitValue::parse_json(&finite).unwrap();
    assert_eq!(value, value.clone());
    assert_eq!(value.render_json(false).unwrap(), finite.replace(":", ": "));

    struct Reject;
    impl fmt::Write for Reject {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            Err(fmt::Error)
        }
    }
    assert!(value.write_json(&mut Reject, false).is_err());
}

fn python(args: &[&std::ffi::OsStr]) -> std::process::Output {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let output = std::process::Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .arg(root.join("proxy/tests/circuit_json_oracle.py"))
    .args(args)
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "actual source circuit JSON oracle failed"
    );
    output
}

#[test]
#[ignore = "actual source JSON/file oracle; set SAFEYOLO_POLICY_PYTHON"]
fn actual_python_fixture_and_bidirectional_file_interchange() {
    assert_eq!(
        serde_json::from_slice::<Value>(&python(&[]).stdout).unwrap(),
        source()
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("python-created.json");
    python(&[std::ffi::OsStr::new("create"), path.as_os_str()]);
    let source_bytes = fs::read(&path).unwrap();
    let cb = CircuitBreaker::new();
    assert_eq!(
        cb.load_file(&path, 100., &mut || 0.5).unwrap().value,
        LoadDisposition::Loaded
    );
    let rust_path = directory.path().join("rust-created.json");
    cb.save_file(&rust_path, 100.).unwrap();
    assert_eq!(fs::read(&rust_path).unwrap(), source_bytes);
    assert_eq!(
        python(&[std::ffi::OsStr::new("inspect"), rust_path.as_os_str()]).stdout,
        source_bytes
    );
    // A later failed publication cannot damage the prior file Python restarts from.
    let blocked = directory.path().join("blocked");
    fs::create_dir(&blocked).unwrap();
    cb.record_failure("api", None, 100., &mut || 0.5).unwrap();
    assert!(cb.save_file(&blocked, 100.).is_err());
    assert_eq!(
        python(&[std::ffi::OsStr::new("inspect"), rust_path.as_os_str()]).stdout,
        source_bytes
    );
}
