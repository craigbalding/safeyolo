use safeyolo_proxy::audit::{Event, Kind, Settings, Severity, Submission, Writer};
use std::{path::PathBuf, process::Command, time::Duration};

fn python() -> std::ffi::OsString {
    std::env::var_os("SAFEYOLO_PYTHON").unwrap_or_else(|| "python3".into())
}

#[test]
fn live_source_oracle_and_consumer_accept_native_records() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let directory = tempfile::tempdir().unwrap();
    let script = root.join("tests/audit_oracle.py");
    let output = Command::new(python())
        .arg(&script)
        .arg("--check")
        .arg(root.join("tests/audit_source.json"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("SAFEYOLO_LOG_PATH", directory.path().join("unused"))
        .env(
            "MITMPROXY_LOG_PATH",
            directory.path().join("unused-diagnostic"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "actual source oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = directory.path().join("native.jsonl");
    let writer = Writer::new(path.clone(), Settings::default());
    for name in ["request", "response"] {
        let mut event = Event::new(
            format!("traffic.{name}"),
            Kind::Traffic,
            Severity::Low,
            "owned fixture",
        );
        event.agent = Some("alice".into());
        event.request_id = Some(format!("req-{}", "0".repeat(32)));
        assert_eq!(writer.emit(event).unwrap(), Submission::Queued);
    }
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    let output = Command::new(python())
        .arg(script)
        .arg("--consume")
        .arg(path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("SAFEYOLO_LOG_PATH", directory.path().join("unused"))
        .env(
            "MITMPROXY_LOG_PATH",
            directory.path().join("unused-diagnostic"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "source reader rejected native JSONL"
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["native_records"], 2);
    assert_eq!(result["schema_drift"], 0);
}

#[test]
fn asynchronous_sink_failure_echoes_owned_event_without_failing_emission() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "sink_failure_child", "--nocapture"])
        .env("SAFEYOLO_AUDIT_TEST_DIRECTORY", directory.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("audit writer flush failed (1 entries)"));
    let event = stderr
        .lines()
        .find_map(|line| line.strip_prefix("[safeyolo] Event: "))
        .expect("source-shaped stderr fallback");
    let event: serde_json::Value = serde_json::from_str(event).unwrap();
    assert_eq!(event["event"], "traffic.fixture");
    assert_eq!(event["details"]["owned"], true);
}

#[test]
fn sink_failure_child() {
    let Some(path) = std::env::var_os("SAFEYOLO_AUDIT_TEST_DIRECTORY") else {
        return;
    };
    let path = PathBuf::from(path);
    assert!(path.is_dir());
    let writer = Writer::new(path, Settings::default());
    let mut event = Event::new(
        "traffic.fixture",
        Kind::Traffic,
        Severity::Low,
        "owned fixture",
    );
    event.details = serde_json::json!({"owned":true}).into();
    assert_eq!(writer.emit(event).unwrap(), Submission::Queued);
    assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
}
