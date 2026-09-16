//! Opt-in source-consumer proof over the actual owned native probe and trace API.

use super::*;
use std::{
    io::Write,
    process::{Command, Stdio},
};

const CHILD: &str = "SAFEYOLO_PROBE_DOCTOR_API_FIXTURE";
const TOKEN: &str = "synthetic-probe-doctor-api-token";
const TEST: &str = "http::probe::tests::doctor_api::native_probe_trace_remains_owned_and_doctor_reports_missing_stages";
const CLASSIFY: &str = r#"
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(os.environ["SAFEYOLO_SOURCE_ROOT"]) / "cli" / "src"))
from safeyolo.commands.doctor import _classify_trace_steps
from safeyolo.core.trace import EXPECTED_ADDONS

expected = ["service-gateway", "network-guard", "circuit-breaker", "credential-guard", "pattern-scanner", "test-context"]
assert EXPECTED_ADDONS == expected
payload = json.load(sys.stdin)
verdict, findings, detail = _classify_trace_steps(payload)
json.dump({"expected_addons": EXPECTED_ADDONS, "verdict": verdict, "findings": findings, "detail": detail}, sys.stdout)
"#;

#[test]
#[ignore = "requires SAFEYOLO_SOURCE_PYTHON and SAFEYOLO_SOURCE_ROOT for actual source doctor"]
fn native_probe_trace_remains_owned_and_doctor_reports_missing_stages() {
    let python = std::env::var_os("SAFEYOLO_SOURCE_PYTHON")
        .expect("set SAFEYOLO_SOURCE_PYTHON to the retained source environment");
    let source = std::env::var_os("SAFEYOLO_SOURCE_ROOT")
        .expect("set SAFEYOLO_SOURCE_ROOT to the source checkout");
    assert!(
        Path::new(&source)
            .join("cli/src/safeyolo/commands/doctor.py")
            .is_file()
    );
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(owned_workflow(&python));
        std::fs::write(
            Path::new(&directory).join("completed"),
            b"owned source classification completed",
        )
        .unwrap();
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("agent_token"), TOKEN).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args(["--ignored", "--exact", TEST, "--nocapture"])
        .env(CHILD, directory.path())
        .env("SAFEYOLO_DATA_DIR", directory.path())
        .env(
            "SAFEYOLO_LOG_PATH",
            directory.path().join("source-unused-audit"),
        )
        .env("PYTHONPYCACHEPREFIX", directory.path().join("pycache"));
    for setting in [
        "TTL_S",
        "GLOBAL_MAX",
        "PER_AGENT_MAX",
        "STEPS_MAX",
        "DETAILS_MAX_BYTES",
    ] {
        child.env_remove(format!("SAFEYOLO_TRACE_{setting}"));
    }
    let result = child.output().unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(directory.path().join("completed")).unwrap(),
        b"owned source classification completed"
    );
}

async fn owned_workflow(python: &std::ffi::OsStr) {
    let fixture = Fixture::new(false, false).await;
    // Doctor's ordinary empty, origin-form HTTP/1.0 probe. The annotation is
    // context metadata; ownership is supplied by the accepted Alice listener.
    let probe = format!(
        "GET /__pipeline_probe HTTP/1.0\r\nHost: {HOST}\r\nX-SafeYolo-Trace: 1\r\nX-SafeYolo-Test-Context: run=owned-doctor;agent=alice;test=pipeline-probe\r\nConnection: close\r\n\r\n"
    );
    let reply = fixture.exchange(&probe).await;
    assert_eq!(status(&reply), 200);
    let rid = request_id(&reply);
    let probe_body: Value = serde_json::from_slice(body(&reply)).unwrap();
    assert_eq!(
        probe_body,
        json!({"probe_ok":true,"host":HOST,"request_id":rid})
    );

    // The identical request is sent through both trusted listeners. Neither
    // query hints, context annotations nor an identity header can claim Alice.
    let trace_request = format!(
        "GET http://_safeyolo.proxy.internal/trace?request_id={rid}&agent=alice HTTP/1.0\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {TOKEN}\r\nX-SafeYolo-Agent: alice\r\nX-SafeYolo-Test-Context: run=owned-doctor;agent=alice;test=pipeline-probe\r\nConnection: close\r\n\r\n"
    );
    let alice = exchange(fixture.directory.path(), "alice", &trace_request).await;
    assert_eq!(status(&alice), 200);
    let report: Value = serde_json::from_slice(body(&alice)).unwrap();
    assert_eq!(report["request_id"], rid);
    assert_eq!(report["agent_id"], "alice");
    assert_eq!(report["truncated"], false);
    let request_steps: Vec<_> = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| step["hook"] == "request")
        .collect();
    assert_eq!(
        request_steps
            .iter()
            .map(|step| step["addon"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "network-guard",
            "circuit-breaker",
            "test-context",
            "probe-sink"
        ]
    );
    assert!(
        request_steps
            .iter()
            .all(|step| step["state"] == "evaluated")
    );
    assert_eq!(request_steps[3]["outcome"], "probe_terminated");
    let missing = ["service-gateway", "credential-guard", "pattern-scanner"];
    assert_eq!(
        report["not_loaded"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["addon"].as_str().unwrap())
            .collect::<Vec<_>>(),
        missing
    );
    let bob = exchange(fixture.directory.path(), "bob", &trace_request).await;
    assert_eq!(status(&bob), 404);
    assert_eq!(
        serde_json::from_slice::<Value>(body(&bob)).unwrap(),
        json!({"error":"No trace for request_id","request_id":rid})
    );
    let audit = fixture.stop().await;
    assert!(!serde_json::to_string(&audit).unwrap().contains(TOKEN));

    // Feed the exact body fetched through the API, not a replacement trace or
    // manually constructed manifest, to the actual Python consumer.
    let mut classifier = Command::new(python)
        .args(["-c", CLASSIFY])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    classifier
        .stdin
        .take()
        .unwrap()
        .write_all(body(&alice))
        .unwrap();
    let classified = classifier.wait_with_output().unwrap();
    assert!(
        classified.status.success(),
        "{}",
        String::from_utf8_lossy(&classified.stderr)
    );
    let verdict: Value = serde_json::from_slice(&classified.stdout).unwrap();
    assert_eq!(verdict["verdict"], "fail");
    assert_eq!(
        verdict["expected_addons"],
        json!([
            "service-gateway",
            "network-guard",
            "circuit-breaker",
            "credential-guard",
            "pattern-scanner",
            "test-context"
        ])
    );
    let absent: Vec<_> = verdict["detail"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["state"] == "not_loaded")
        .map(|entry| {
            assert_eq!(entry["verdict"], "fail");
            entry["addon"].as_str().unwrap()
        })
        .collect();
    assert_eq!(absent, missing);
    for name in missing {
        assert!(
            verdict["findings"]
                .as_array()
                .unwrap()
                .contains(&json!(format!(
                    "{name}: not_loaded — expected addon did not run"
                )))
        );
    }
    assert!(
        !verdict["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding.as_str().unwrap().starts_with("probe-sink:"))
    );
}
