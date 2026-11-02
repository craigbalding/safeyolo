use safeyolo_proxy::audit::{Event, Kind, Settings, Severity, Submission, Writer};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

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

#[cfg(unix)]
#[test]
fn writer_survives_failed_audit_and_stderr_destinations() {
    let directory = tempfile::tempdir().unwrap();
    let (stderr, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(peer);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "failed_stderr_child", "--nocapture"])
        .env("SAFEYOLO_AUDIT_TEST_DIRECTORY", directory.path())
        // A disconnected socket makes the real worker's stderr fallback fail
        // without changing this process's diagnostics or filling a filesystem.
        .stderr(Stdio::from(std::os::fd::OwnedFd::from(stderr)))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn failed_stderr_child() {
    let Some(directory) = std::env::var_os("SAFEYOLO_AUDIT_TEST_DIRECTORY") else {
        return;
    };
    // This child intentionally has no writable stderr; keep assertion failures
    // visible in the parent's captured stdout.
    std::panic::set_hook(Box::new(|info| println!("{info}")));
    let path = PathBuf::from(directory).join("audit.jsonl");
    fs::create_dir(&path).unwrap();
    let writer = Writer::new(path.clone(), Settings::default());
    let event = |name| Event::new(name, Kind::Admin, Severity::Low, "owned fixture");
    assert!(writer.emit_confirmed(event("admin.failed")).await.is_err());
    assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());

    fs::remove_dir(&path).unwrap();
    writer
        .emit_confirmed(event("admin.recovered"))
        .await
        .unwrap();
    assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
    assert_eq!(writer.pending_count().unwrap(), 0);
    // Recovery does not erase the earlier fallback failure or replay its event.
    assert!(!writer.shutdown(Duration::from_secs(2)).unwrap());
    let rows: Vec<_> = fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| safeyolo_proxy::audit::parse_record(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event"], "admin.recovered");
}
