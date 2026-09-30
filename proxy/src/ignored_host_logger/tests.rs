use super::*;
use crate::audit::Settings;
use serde_json::json;
use std::{
    cell::RefCell,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    time::Duration,
};

struct Sink {
    _directory: tempfile::TempDir,
    path: PathBuf,
    writer: Writer,
}

impl Sink {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owned-audit.jsonl");
        let writer = Writer::new(path.clone(), Settings::default());
        Self {
            _directory: directory,
            path,
            writer,
        }
    }

    fn records(&self) -> Vec<Value> {
        assert!(self.writer.wait_for_drain(Duration::from_secs(3)).unwrap());
        fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn poisoned(&self) -> Writer {
        let writer = Writer::new(
            self._directory.path().join("never-written.jsonl"),
            Settings::default(),
        );
        writer.poison_for_test();
        writer
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        assert!(self.writer.shutdown(Duration::from_secs(3)).unwrap());
    }
}

fn facts() -> Facts<'static> {
    Facts {
        agent: Some("alice"),
        client: Some("192.0.2.10"),
        transport: "tcp",
    }
}

fn connect(owner: &mut IgnoredHostConnection, now: f64) {
    owner.connect(
        Some(SelectedDestination {
            host: "service.owned.invalid",
            port: 443,
        }),
        || now,
    );
}

fn state(owners: &IndexMap<String, IgnoredHostConnection>) -> Value {
    Value::Array(
        owners
            .iter()
            .filter_map(|(id, owner)| {
                owner.session.as_ref().map(|session| {
                    json!({"id":id,"host":session.host.as_str(),"port":session.port,
            "started_at":session.started_at,"connected":session.connected})
                })
            })
            .collect(),
    )
}

fn optional<'a>(spec: &'a Value, key: &str, default: &'a str) -> Option<&'a str> {
    spec.get(key).map_or(Some(default), Value::as_str)
}

fn without_timestamp(value: &Value) -> String {
    let mut value = value.clone();
    value.as_object_mut().unwrap().shift_remove("ts");
    serde_json::to_string(&value).unwrap()
}

#[test]
fn actual_source_lifecycle_rows_with_matching_kept_as_supplied_input() {
    let source: Value =
        serde_json::from_str(include_str!("../../tests/ignored_host_source.json")).unwrap();
    assert_eq!(source["rows"].as_array().unwrap().len(), 18);
    let mut lifecycle_rows = 0;
    let mut lifecycle_steps = 0;
    let mut matching_steps = 0;
    for row in source["rows"].as_array().unwrap() {
        let name = row["input"]["name"].as_str().unwrap();
        let sink = Sink::new();
        let poisoned = sink.poisoned();
        // Fixture IDs dispatch to per-connection handles. This is test input
        // bookkeeping, not a native process-wide session registry.
        let mut owners = IndexMap::<String, IgnoredHostConnection>::new();
        let mut reached = false;
        for (index, spec) in row["input"]["steps"].as_array().unwrap().iter().enumerate() {
            let expected = &row["steps"][index];
            let hook = spec["hook"].as_str().unwrap();
            if hook == "match" {
                matching_steps += 1;
                continue;
            }
            reached = true;
            lifecycle_steps += 1;
            let id = spec["id"].as_str().unwrap_or("conn");
            let owner = owners.entry(id.to_owned()).or_default();
            let calls = RefCell::new(Vec::new());
            let clock = || {
                calls.borrow_mut().push(spec["now"].clone());
                assert!(
                    !spec["clock_error"].as_bool().unwrap_or(false),
                    "owned monotonic failure"
                );
                spec["now"].as_f64().unwrap()
            };
            let writer = if spec.get("audit_error").is_some() {
                &poisoned
            } else {
                &sink.writer
            };
            let facts = Facts {
                agent: optional(spec, "agent", "alice"),
                client: optional(spec, "client_ip", "192.0.2.10"),
                transport: spec["transport"].as_str().unwrap_or("tcp"),
            };
            let result = catch_unwind(AssertUnwindSafe(|| match hook {
                "server_connect" => {
                    // This selected destination is an observation of the real
                    // source matcher, not a second matcher implemented here.
                    let selected = expected["selected_destination"].as_array().map(|value| {
                        SelectedDestination {
                            host: value[0].as_str().unwrap(),
                            port: u16::try_from(value[1].as_u64().unwrap()).unwrap(),
                        }
                    });
                    owner.connect(selected, clock);
                    Ok(())
                }
                "server_connected" => owner.connected(facts, writer),
                "server_connect_error" => {
                    owner.connect_error(facts, spec["error"].as_str(), writer)
                }
                "server_disconnected" => owner.disconnected(facts, clock, writer),
                _ => panic!("unknown source hook"),
            }));
            match result {
                Err(_) => {
                    assert_eq!(spec["clock_error"], true, "{name}/{index}");
                    assert_eq!(expected["error_class"], "RuntimeError", "{name}/{index}");
                }
                Ok(Err(error)) => {
                    assert!(spec.get("audit_error").is_some(), "{name}/{index}");
                    assert_eq!(error.kind(), ErrorKind::Audit(audit::ErrorKind::Poisoned));
                    assert_eq!(
                        expected["error_class"], spec["audit_error"],
                        "{name}/{index}"
                    );
                }
                Ok(Ok(())) => assert!(expected["error_class"].is_null(), "{name}/{index}"),
            }
            if owner.session.is_none() {
                owners.shift_remove(id);
            }
            assert_eq!(state(&owners), expected["state_after"], "{name}/{index}");
            let expected_clocks = expected["timeline"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|item| item.get("monotonic").cloned())
                .collect::<Vec<_>>();
            assert_eq!(*calls.borrow(), expected_clocks, "{name}/{index}");
        }
        lifecycle_rows += usize::from(reached);
        let accepted = row["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|attempt| attempt["accepted"] == true)
            .map(|attempt| without_timestamp(&attempt["event"]))
            .collect::<Vec<_>>();
        let records = sink.records();
        assert_eq!(
            records.iter().map(without_timestamp).collect::<Vec<_>>(),
            accepted,
            "{name}"
        );
    }
    // The source-only regex/candidate rows remain explicitly outside this core.
    assert_eq!(lifecycle_rows, 16);
    assert_eq!(lifecycle_steps, 71);
    assert_eq!(matching_steps, 10);
}

#[test]
fn failed_submission_keeps_connected_and_consumes_each_terminal_transition() {
    let sink = Sink::new();
    let poisoned = sink.poisoned();
    let mut owner = IgnoredHostConnection::new();
    connect(&mut owner, 1.0);
    assert_eq!(
        owner.connected(facts(), &poisoned).unwrap_err().kind(),
        ErrorKind::Audit(audit::ErrorKind::Poisoned)
    );
    assert!(owner.session.as_ref().unwrap().connected);
    owner.disconnected(facts(), || 1.125, &sink.writer).unwrap();
    assert!(owner.session.is_none());
    assert_eq!(sink.records()[0]["event"], "traffic.passthrough_end");

    connect(&mut owner, 2.0);
    let failure = owner
        .connect_error(facts(), Some("owned private socket text"), &poisoned)
        .unwrap_err();
    assert!(owner.session.is_none());
    assert!(!format!("{failure:?} {failure}").contains("private"));
    owner
        .disconnected(facts(), || panic!("already removed"), &sink.writer)
        .unwrap();

    connect(&mut owner, 3.0);
    owner.connected(facts(), &sink.writer).unwrap();
    assert_eq!(
        owner
            .disconnected(facts(), || 4.0, &poisoned)
            .unwrap_err()
            .kind(),
        ErrorKind::Audit(audit::ErrorKind::Poisoned)
    );
    assert!(owner.session.is_none());
    owner.connected(facts(), &sink.writer).unwrap();
    assert_eq!(sink.records().len(), 2);
}

#[test]
fn clocks_and_drop_preserve_reached_effects_without_terminal_inference() {
    let sink = Sink::new();
    let mut owner = IgnoredHostConnection::new();
    owner.connect(None, || panic!("no matching destination"));
    owner
        .disconnected(facts(), || panic!("no session"), &sink.writer)
        .unwrap();
    connect(&mut owner, 10.0);
    let error = catch_unwind(AssertUnwindSafe(|| {
        owner.connect(
            Some(SelectedDestination {
                host: "replacement.invalid",
                port: 8443,
            }),
            || panic!("owned clock failure"),
        )
    }));
    assert!(error.is_err());
    assert_eq!(
        owner.session.as_ref().unwrap().host.as_str(),
        "service.owned.invalid"
    );
    owner.connected(facts(), &sink.writer).unwrap();
    let error = catch_unwind(AssertUnwindSafe(|| {
        owner.disconnected(facts(), || panic!("owned clock failure"), &sink.writer)
    }));
    assert!(error.is_err());
    assert!(owner.session.is_none());
    connect(&mut owner, 11.0);
    owner
        .disconnected(facts(), || panic!("unconnected session"), &sink.writer)
        .unwrap();
    connect(&mut owner, 12.0);
    owner.connected(facts(), &sink.writer).unwrap();
    drop(owner);
    assert_eq!(
        sink.records()
            .iter()
            .map(|r| r["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["traffic.passthrough_start", "traffic.passthrough_start"]
    );
}

#[test]
fn duration_has_python_integer_rounding_and_errors_after_pop() {
    let sink = Sink::new();
    for (now, expected) in [(0.0005, 0), (0.0015, 2), (0.0025, 2), (-1.0, 0), (-0.0, 0)] {
        let mut owner = IgnoredHostConnection::new();
        connect(&mut owner, 0.0);
        owner.connected(facts(), &sink.writer).unwrap();
        owner.disconnected(facts(), || now, &sink.writer).unwrap();
        assert_eq!(
            sink.records().last().unwrap()["details"]["duration_ms"],
            expected
        );
    }
    let mut owner = IgnoredHostConnection::new();
    connect(&mut owner, 0.0);
    owner.connected(facts(), &sink.writer).unwrap();
    owner
        .disconnected(facts(), || 2.0_f64.powi(70), &sink.writer)
        .unwrap();
    let expected: BigInt = BigInt::from(1000) << 70;
    assert_eq!(
        sink.records().last().unwrap()["details"]["duration_ms"].to_string(),
        expected.to_string()
    );

    for (start, end, kind) in [
        (0.0, f64::NAN, ErrorKind::Value),
        (0.0, f64::INFINITY, ErrorKind::Overflow),
        (0.0, f64::NEG_INFINITY, ErrorKind::Overflow),
        (-f64::MAX, f64::MAX, ErrorKind::Overflow),
    ] {
        connect(&mut owner, start);
        owner.connected(facts(), &sink.writer).unwrap();
        let before = sink.records().len();
        assert_eq!(
            owner
                .disconnected(facts(), || end, &sink.writer)
                .unwrap_err()
                .kind(),
            kind
        );
        assert!(owner.session.is_none());
        owner
            .disconnected(
                facts(),
                || panic!("removed before round error"),
                &sink.writer,
            )
            .unwrap();
        assert_eq!(sink.records().len(), before);
    }
}
