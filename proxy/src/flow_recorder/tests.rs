use super::*;
use crate::{
    flow_store::{BodyInput, FlowRecord, Side},
    http_content,
};

#[test]
fn direct_startup_settings_keep_lazy_limits_and_real_body_size() {
    let directory = tempfile::tempdir().unwrap();
    let selected = directory.path().join("selected.sqlite3");
    let unused = directory.path().join("unused.sqlite3");
    let policy = Policy::parse_at(
        &json!({"addons":{"flow_store":{
            "enabled":false,"db_path":selected,"max_request_body_bytes":3,
            "max_response_body_bytes":false,"preview_text_chars":2,"compress_bodies":false,
            "settings":{"max_request_body_bytes":100}
        }}})
        .to_string(),
        crate::policy::Format::Json,
        0.,
    )
    .unwrap();
    let recorder = FlowRecorder::start(true, &unused, Some(&policy));
    assert!(selected.exists());
    assert!(!unused.exists());
    let store = recorder.store().unwrap();
    assert_eq!(store.capture_limit(Side::Request), Some(3));
    assert_eq!(store.capture_limit(Side::Response), Some(0));
    recorder.record(|store| Ok(Some(QueuedRecord {
        metadata_encoding_error: false,
        metadata: json!({"request_id":"sized","ts_start":1,"engagement_id":"alice","host":"owned.invalid","flow_state":"completed","request_content_type":"text/plain","response_content_type":"text/plain"}).as_object().unwrap().clone(),
        request_body: http_content::decode_prefix_with_size(b"abcdef", b"", store.capture_limit(Side::Request).unwrap()).unwrap(),
        response_body: http_content::decode_prefix_with_size(b"response", b"", store.capture_limit(Side::Response).unwrap()).unwrap(),
    })));
    assert!(recorder.shutdown());
    let detail = store.get_flow(1).unwrap().unwrap();
    assert_eq!(detail["request_body_size"], 6);
    assert_eq!(detail["response_body_size"], 8);
    assert_eq!(detail["request_body_truncated"], 1);
    assert_eq!(
        store
            .body(1, Side::Request)
            .unwrap()
            .unwrap()
            .body
            .as_slice(),
        b"abc"
    );
    assert!(
        store
            .body(1, Side::Response)
            .unwrap()
            .unwrap()
            .body
            .is_empty()
    );
    assert_eq!(
        recorder.stats(),
        json!({"recorded":1,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":0})
    );
}

#[test]
fn eligibility_build_errors_and_writer_errors_have_distinct_counts() {
    let directory = tempfile::tempdir().unwrap();
    let recorder = FlowRecorder::start(true, &directory.path().join("flows"), None);
    recorder.record(|_| Ok(None));
    recorder.record(|_| Err(ContentError::Value));
    let metadata = json!({"request_id":"same","ts_start":1,"engagement_id":"alice","host":"owned.invalid","flow_state":"completed"}).as_object().unwrap().clone();
    recorder
        .store()
        .unwrap()
        .record(
            FlowRecord {
                metadata: &metadata,
                request_body: Some(BodyInput::complete(b"")),
                response_body: None,
            },
            1,
        )
        .unwrap();
    recorder.record(|_| {
        Ok(Some(QueuedRecord {
            metadata_encoding_error: false,
            metadata,
            request_body: http_content::decode_prefix_with_size(b"", b"", 0)?,
            response_body: http_content::decode_prefix_with_size(b"", b"", 0)?,
        }))
    });
    recorder.set_enabled(false);
    recorder.record(|_| panic!("disabled recorder must not build"));
    assert!(recorder.shutdown());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":1,"errors":1,"skipped":2,"queue_dropped":0,"write_errors":1})
    );
}

#[test]
fn unencodable_metadata_fails_in_writer_after_recording_and_allows_next_row() {
    let directory = tempfile::tempdir().unwrap();
    let recorder = FlowRecorder::start(true, &directory.path().join("flows"), None);
    for (id, metadata_encoding_error) in [("unencodable", true), ("valid", false)] {
        recorder.record(|_| Ok(Some(QueuedRecord {
            metadata: json!({"request_id":id,"ts_start":1,"engagement_id":"alice","host":"owned.invalid","flow_state":"completed"}).as_object().unwrap().clone(),
            metadata_encoding_error,
            request_body: http_content::decode_prefix_with_size(b"", b"", 0)?,
            response_body: http_content::decode_prefix_with_size(b"", b"", 0)?,
        })));
    }
    assert!(recorder.shutdown());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":2,"errors":0,"skipped":0,"queue_dropped":0,"write_errors":1})
    );
    let store = recorder.store().unwrap();
    assert_eq!(store.get_flow(1).unwrap().unwrap()["request_id"], "valid");
    assert!(store.get_flow(2).unwrap().is_none());
}

#[test]
fn disabled_startup_stays_without_store_after_enable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("not-created");
    let recorder = FlowRecorder::start(false, &path, None);
    recorder.set_enabled(true);
    recorder.record(|_| panic!("no store means no build"));
    assert!(recorder.store().is_none());
    assert!(!path.exists());
    assert_eq!(
        recorder.stats(),
        json!({"recorded":0,"errors":0,"skipped":1})
    );
}

#[test]
fn python_queue_integer_forms_keep_unbounded_and_fallback_meaning() {
    for (value, expected) in [
        ("-1", 0),
        ("0", 0),
        ("+１２", 12),
        ("\u{2003}1_000\u{2003}", 1000),
        ("\u{1c}1", 500),
        ("1\u{1f}", 500),
        ("1__0", 500),
        ("1_", 500),
        ("1.0", 500),
        ("", 500),
        ("-0", 0),
    ] {
        assert_eq!(queue_capacity(Some(value)), expected);
    }
    assert_eq!(queue_capacity(Some(&"9".repeat(4301))), 500);
}
