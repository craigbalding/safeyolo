use safeyolo_proxy::audit::{Event, Kind, Settings, Severity, Submission, Writer};
use std::{path::PathBuf, process::Command, time::Duration};

#[test]
fn current_writer_output_is_accepted_by_the_native_reader() {
    let directory = tempfile::tempdir().unwrap();
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
    let bytes = std::fs::read_to_string(path).unwrap();
    let rows: Vec<_> = bytes
        .lines()
        .map(|line| safeyolo_proxy::audit::parse_record(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    for (row, name) in rows.iter().zip(["request", "response"]) {
        assert_eq!(row["schema_version"], 2);
        assert_eq!(row["event"], format!("traffic.{name}"));
        assert_eq!(row["agent"], "alice");
        assert!(row["details"].get("sandbox_run").is_none());
    }
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
        .expect("current stderr event");
    let event = safeyolo_proxy::audit::parse_record(event).unwrap();
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
