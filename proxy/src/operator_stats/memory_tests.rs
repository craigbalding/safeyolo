//! Synthetic report integration; never calls the serving-process sampler.

use super::*;
use crate::memory_monitor::{MemorySample, SampleError};
use std::sync::Arc;

const SAMPLE: fn() -> Result<MemorySample, SampleError> = || {
    Ok(MemorySample {
        rss_kb: 1280.into(),
        peak_kb: 2560.into(),
    })
};

fn runtime(directory: &std::path::Path) -> Runtime {
    let config = serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("unused.sock")}],
        "temporary_policy_socket":directory.join("unused-policy.sock"),
        "readiness_file":directory.join("ready"),
        "audit_log_path":directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl"),
        "flow_store_enabled":false,
        "flow_store_db_path":directory.join("unused.sqlite3"),
        "circuit_state_file":""
    }))
    .unwrap();
    Runtime::new(
        config,
        "owned",
        Arc::new(tokio::sync::Mutex::new(())),
        None,
        None,
    )
    .unwrap()
}

#[test]
fn memory_is_first_in_the_temporary_lane_and_reports_the_shared_owner() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path());
    runtime
        .memory_monitor
        .client_connected("owned", || 10.)
        .unwrap();
    runtime
        .memory_monitor
        .request(
            "owned",
            "first.invalid",
            &runtime.audit,
            || Ok(3),
            || 11.,
            SAMPLE,
        )
        .unwrap();
    runtime
        .memory_monitor
        .response("owned", true, false, || Ok(5))
        .unwrap();
    runtime
        .memory_monitor
        .request(
            "owned",
            "second.invalid",
            &runtime.audit,
            || Ok(1),
            || 13.,
            SAMPLE,
        )
        .unwrap();
    let expected = runtime
        .memory_monitor
        .get_stats(SAMPLE, || 15.9)
        .unwrap()
        .render_json(false)
        .unwrap();
    for _ in 0..2 {
        let report = document_with_memory(&runtime, SAMPLE, || 15.9);
        let fields = report.as_object().unwrap();
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "proxy",
                "memory-monitor",
                "service-discovery",
                "policy-engine",
                "flow-recorder",
                "request-logger",
                "metrics"
            ]
        );
        assert_eq!(
            fields["memory-monitor"].render_json(false).unwrap(),
            expected
        );
        assert_eq!(fields["policy-engine"].render_json(false).unwrap(), "{}");
    }
    assert!(!directory.path().join("audit.jsonl").exists());
    assert!(!directory.path().join("unused.sqlite3").exists());
}

#[test]
fn failed_memory_report_is_contained_and_later_owner_reports_remain() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path());
    let report = document_with_memory(
        &runtime,
        || Err(SampleError::Index),
        || panic!("sample failure must precede clock"),
    );
    let fields = report.as_object().unwrap();
    assert_eq!(
        fields["memory-monitor"].render_json(false).unwrap(),
        r#"{"error": "IndexError: memory monitor operation failed"}"#
    );
    assert_eq!(
        fields["service-discovery"].render_json(false).unwrap(),
        runtime
            .agent_discovery
            .get_stats(&runtime.audit, crate::circuit_runtime::now)
            .unwrap()
            .render_json(false)
            .unwrap()
    );
    assert!(
        fields.contains_key("flow-recorder")
            && fields.contains_key("request-logger")
            && fields.contains_key("metrics")
    );
    assert!(!directory.path().join("audit.jsonl").exists());
}
