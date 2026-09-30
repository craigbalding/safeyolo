use super::*;
use crate::flow_store::Settings;
use serde_json::json;
use zeroize::Zeroizing;

fn record(id: &str) -> QueuedRecord {
    QueuedRecord {
        metadata_encoding_error: false,
        metadata: json!({
            "request_id":id,"ts_start":1000,"engagement_id":"alice",
            "agent_id":"alice","evidence_owner":"alice",
            "host":"owned.invalid","flow_state":"completed",
            "request_content_type":"text/plain","response_content_type":"text/plain",
        })
        .as_object()
        .unwrap()
        .clone(),
        request_body: DecodedContent {
            content: Zeroizing::new(b"owned request".to_vec()),
            total_bytes: 13,
        },
        response_body: DecodedContent {
            content: Zeroizing::new(b"owned response".to_vec()),
            total_bytes: 14,
        },
    }
}

#[test]
fn queued_records_drain_before_shutdown_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.sqlite3");
    let store = Arc::new(FlowStore::open(&path, Settings::default()).unwrap());
    let writer = FlowWriter::new(store.clone(), 500);
    assert!(writer.worker.lock().unwrap().task.is_none());
    for id in ["one", "two", "three"] {
        assert_eq!(writer.submit(record(id)).unwrap(), Submission::Queued);
    }
    assert!(writer.shutdown(Duration::from_secs(3)));
    assert!(writer.shutdown(Duration::ZERO));
    assert_eq!(writer.stats(), Stats::default());
    assert_eq!(
        writer.submit(record("after-stop")).unwrap(),
        Submission::Stopped
    );
    drop(writer);
    drop(store);
    let store = FlowStore::open(&path, Settings::default()).unwrap();
    for id in 1..=3 {
        assert!(store.get_flow(id).unwrap().is_some());
    }
    assert!(store.get_flow(4).unwrap().is_none());
}

#[test]
fn huge_source_queue_capacity_allocates_only_for_pending_records() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FlowStore::open(&directory.path().join("flows.sqlite3"), Settings::default()).unwrap(),
    );
    let writer = FlowWriter::new(store.clone(), usize::MAX);
    assert_eq!(
        writer.submit(record("large-capacity")).unwrap(),
        Submission::Queued
    );
    assert!(writer.shutdown(Duration::from_secs(3)));
    assert_eq!(writer.stats(), Stats::default());
    assert_eq!(
        store.get_flow(1).unwrap().unwrap()["request_id"],
        "large-capacity"
    );
}

#[test]
fn full_queue_drops_without_waiting_for_a_locked_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.sqlite3");
    let store = Arc::new(FlowStore::open(&path, Settings::default()).unwrap());
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let writer = FlowWriter::new(store.clone(), 1);
    let mut queued = 0;
    let mut dropped = 0;
    for id in ["one", "two", "three"] {
        match writer.submit(record(id)).unwrap() {
            Submission::Queued => queued += 1,
            Submission::QueueFull => dropped += 1,
            Submission::Stopped => panic!("writer unexpectedly stopped"),
        }
    }
    // At most one write can be in flight and one record can be waiting.
    // All producer calls above completed while the database remained locked.
    assert!(dropped >= 1);
    assert_eq!(writer.stats().queue_dropped, dropped);
    blocker.execute_batch("COMMIT").unwrap();
    assert!(writer.shutdown(Duration::from_secs(3)));
    assert_eq!(writer.stats().write_errors, 0);
    let stored: i64 = blocker
        .query_row("SELECT COUNT(*) FROM flows", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored as u64, queued);
}

#[test]
fn failed_write_is_counted_and_does_not_stop_later_records() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FlowStore::open(&directory.path().join("flows.sqlite3"), Settings::default()).unwrap(),
    );
    let writer = FlowWriter::new(store.clone(), 0);
    for id in ["duplicate", "duplicate", "after-error"] {
        assert_eq!(writer.submit(record(id)).unwrap(), Submission::Queued);
    }
    assert!(writer.shutdown(Duration::from_secs(3)));
    assert_eq!(
        writer.stats(),
        Stats {
            queue_dropped: 0,
            write_errors: 1
        }
    );
    assert_eq!(
        store.get_flow(1).unwrap().unwrap()["request_id"],
        "duplicate"
    );
    assert_eq!(
        store.get_flow(2).unwrap().unwrap()["request_id"],
        "after-error"
    );
    assert!(store.get_flow(3).unwrap().is_none());
}

#[test]
fn stopping_an_unused_writer_does_not_start_a_thread() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FlowStore::open(&directory.path().join("flows.sqlite3"), Settings::default()).unwrap(),
    );
    let writer = FlowWriter::new(store, 500);
    assert!(writer.shutdown(Duration::ZERO));
    assert!(writer.worker.lock().unwrap().task.is_none());
    assert_eq!(
        writer.submit(record("unused")).unwrap(),
        Submission::Stopped
    );
}

#[test]
fn shutdown_timeout_retains_the_store_until_the_accepted_record_drains() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("flows.sqlite3");
    let store = Arc::new(FlowStore::open(&path, Settings::default()).unwrap());
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let writer = FlowWriter::new(store.clone(), 1);
    assert_eq!(
        writer.submit(record("drain-after-timeout")).unwrap(),
        Submission::Queued
    );
    assert!(!writer.shutdown(Duration::ZERO));
    assert_eq!(writer.submit(record("late")).unwrap(), Submission::Stopped);
    blocker.execute_batch("COMMIT").unwrap();
    assert!(writer.shutdown(Duration::from_secs(3)));
    assert_eq!(writer.stats(), Stats::default());
    assert_eq!(
        store.get_flow(1).unwrap().unwrap()["request_id"],
        "drain-after-timeout"
    );
    assert!(store.get_flow(2).unwrap().is_none());
}
