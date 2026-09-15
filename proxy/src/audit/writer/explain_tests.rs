use super::*;

#[test]
fn freshness_observation_failure_still_reads_retained_events() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    fs::write(
        &path,
        br#"{"request_id":"owned","agent":"alice","event":"available"}"#,
    )
    .unwrap();
    let writer = Writer::new(path, Settings::default());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _pending = writer.queue.pending.lock().unwrap();
        panic!("synthetic pending observation failure");
    }));
    assert!(writer.pending_count().is_err());
    let mut report = writer.explain("owned", "alice").unwrap();
    let value: Value = serde_json::from_str(&report.render_json(false).unwrap()).unwrap();
    assert_eq!(value["status"], "complete");
    assert_eq!(value["events"].as_array().unwrap().len(), 1);
    crate::audit::wipe(&mut report);
}
