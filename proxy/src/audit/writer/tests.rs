use super::*;
use crate::audit::{Kind, Severity};

fn event(index: usize) -> Event {
    let mut event = Event::new(
        "traffic.fixture",
        Kind::Traffic,
        Severity::Low,
        "owned fixture",
    );
    event.details = serde_json::json!({"index":index}).into();
    event
}
fn values(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn lazy_file_creation_order_and_close_drain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("created/deep/events.jsonl");
    let writer = Writer::new(path.clone(), Settings::default());
    assert!(!path.exists());
    assert!(writer.worker.lock().unwrap().task.is_none());
    assert_eq!(writer.pending_count().unwrap(), 0);
    for index in 0..40 {
        assert_eq!(writer.emit(event(index)).unwrap(), Submission::Queued);
    }
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    assert_eq!(writer.pending_count().unwrap(), 0);
    assert_eq!(writer.dropped_count().unwrap(), 0.into());
    let rows = values(&path);
    assert_eq!(rows.len(), 40);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["details"]["index"], index);
    }
    assert_eq!(writer.emit(event(41)).unwrap(), Submission::Stopped);
    assert!(writer.shutdown(Duration::ZERO).unwrap());
}

#[test]
fn rotation_uses_source_suffix_and_runs_before_whole_batch() {
    for name in ["events.jsonl", "events."] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        let writer = Writer::new(
            path.clone(),
            Settings {
                max_bytes: 0.into(),
                backups: 2.into(),
                ..Settings::default()
            },
        );
        for index in 0..3 {
            writer.emit(event(index)).unwrap();
            assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
        }
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
        assert_eq!(values(&path)[0]["details"]["index"], 2);
        assert_eq!(values(&backup(&path, &1.into()))[0]["details"]["index"], 1);
        assert_eq!(values(&backup(&path, &2.into()))[0]["details"]["index"], 0);
        assert!(!backup(&path, &3.into()).exists());
        if name.ends_with('.') {
            assert!(directory.path().join("events..jsonl.1").exists());
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("batch");
    let settings = Settings {
        max_bytes: 1.into(),
        ..Settings::default()
    };
    let batch: Vec<_> = (0..3)
        .map(|index| event(index).record(OffsetDateTime::UNIX_EPOCH))
        .collect();
    append(&path, &settings, &batch).unwrap();
    assert!(path.metadata().unwrap().len() > 1);
    assert_eq!(values(&path).len(), 3);
    assert!(!backup(&path, &1.into()).exists());
}

#[test]
fn settings_keep_source_integer_modes_without_allocating_capacity() {
    for queue in ["0", "-1", "+１２_３", "1\u{001c}", "", "x"] {
        let settings = Settings::from_environment_values(Some(queue), None, None).unwrap();
        let expected = match queue {
            "0" => 0,
            "-1" => -1,
            "+１２_３" => 123,
            _ => 10000,
        };
        assert_eq!(settings.max_queue, expected.into());
    }
    assert!(Settings::from_environment_values(None, Some("bad"), None).is_err());
    assert!(Settings::from_environment_values(None, None, Some("1.0")).is_err());
    for queue in [
        "0".to_owned(),
        "-2".to_owned(),
        format!("1{}", "0".repeat(400)),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit");
        let settings =
            Settings::from_environment_values(Some(&queue), Some("0"), Some("-1")).unwrap();
        let writer = Writer::new(path.clone(), settings);
        assert_eq!(writer.emit(event(0)).unwrap(), Submission::Queued);
        assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
        assert_eq!(values(&path).len(), 1);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pending_includes_blocked_flush_full_queue_and_shutdown_fallback() {
    use std::{
        ffi::CString,
        io::Read,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owned-fifo");
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let writer = Writer::new(
        path.clone(),
        Settings {
            max_queue: 1.into(),
            ..Settings::default()
        },
    );
    writer.emit(event(0)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if writer.queue.pending.lock().unwrap().items.is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "owned writer did not dequeue");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(writer.pending_count().unwrap(), 1);
    assert!(!writer.wait_for_drain(Duration::from_millis(10)).unwrap());
    assert_eq!(writer.emit(event(1)).unwrap(), Submission::Queued);
    assert_eq!(writer.emit(event(2)).unwrap(), Submission::QueueFull);
    assert_eq!(writer.dropped_count().unwrap(), 1.into());
    assert_eq!(writer.pending_count().unwrap(), 2);
    assert!(!writer.shutdown(Duration::from_millis(10)).unwrap());
    // Source leaves this at 2, then permanently at 1 after the first flush.
    assert_eq!(writer.pending_count().unwrap(), 1);
    let mut reader = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
    assert_eq!(writer.pending_count().unwrap(), 0);
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    let mut bytes = [0; 4096];
    let count = reader.read(&mut bytes).unwrap();
    let retained: Value = serde_json::from_slice(&bytes[..count]).unwrap();
    assert_eq!(retained["details"]["index"], 0);
}

#[test]
fn ordinary_sink_failure_completes_attempt_without_claiming_persistence() {
    let directory = tempfile::tempdir().unwrap();
    let writer = Writer::new(directory.path().to_owned(), Settings::default());
    assert_eq!(writer.emit(event(0)).unwrap(), Submission::Queued);
    assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
    assert_eq!(writer.pending_count().unwrap(), 0);
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    assert!(directory.path().is_dir());
}

#[tokio::test]
async fn confirmed_write_rejects_failed_destination_and_recovers_in_same_writer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    fs::create_dir(&path).unwrap();
    let writer = Writer::new(path.clone(), Settings::default());
    assert_eq!(
        writer.emit_confirmed(event(0)).await.unwrap_err().kind(),
        ErrorKind::Io
    );
    assert!(path.is_dir());
    fs::remove_dir(&path).unwrap();
    writer.emit_confirmed(event(1)).await.unwrap();
    assert_eq!(values(&path).len(), 1);
    assert_eq!(values(&path)[0]["details"]["index"], 1);
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirmed_write_rejects_full_and_stopped_queue() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocked-fifo");
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let writer = Writer::new(
        path.clone(),
        Settings {
            max_queue: 1.into(),
            ..Settings::default()
        },
    );
    writer.emit(event(0)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !writer.queue.pending.lock().unwrap().items.is_empty() {
        assert!(Instant::now() < deadline, "writer did not dequeue");
        tokio::task::yield_now().await;
    }
    writer.emit(event(1)).unwrap();
    assert_eq!(
        writer.emit_confirmed(event(2)).await.unwrap_err().kind(),
        ErrorKind::Io
    );
    let _reader = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(writer.shutdown(Duration::from_secs(2)).unwrap());
    assert_eq!(
        writer.emit_confirmed(event(3)).await.unwrap_err().kind(),
        ErrorKind::Io
    );
}

#[test]
fn encoder_failure_cannot_claim_successful_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit");
    let writer = Writer::new(path.clone(), Settings::default());
    let mut record = event(0);
    record.details = CircuitValue::Object(indexmap::IndexMap::from([(
        "n".into(),
        CircuitValue::Integer(format!("1{}", "0".repeat(4300)).parse().unwrap()),
    )]));
    assert_eq!(writer.emit(record).unwrap(), Submission::Queued);
    assert!(writer.wait_for_drain(Duration::from_secs(2)).unwrap());
    assert!(!writer.shutdown(Duration::from_secs(2)).unwrap());
    assert!(!writer.shutdown(Duration::ZERO).unwrap());
    assert!(!path.exists());
}
