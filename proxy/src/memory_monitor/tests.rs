use super::*;
use crate::{audit::Settings, http_content};
use flate2::{Compression, write::GzEncoder};
use serde_json::json;
use std::{
    cell::{Cell, RefCell},
    fs,
    io::Write,
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
}
impl Drop for Sink {
    fn drop(&mut self) {
        assert!(self.writer.shutdown(Duration::from_secs(3)).unwrap());
    }
}
fn number(value: &BigInt) -> Value {
    serde_json::from_str(&value.to_string()).unwrap()
}
fn state(monitor: &MemoryMonitor) -> Value {
    let state = monitor.lock().unwrap();
    json!({
        "rss_start_kb":number(&state.rss_start_kb),"started":state.started,
        "last_event_time":state.last_event_time,"total_flows":number(&state.total_flows),
        "connections":state.connections.iter().map(|(id,item)| json!({
            "id":id,"domain":item.domain,"started":item.started,"flow_count":number(&item.flows),
            "bytes_sent":number(&item.sent),"bytes_received":number(&item.received)
        })).collect::<Vec<_>>(),
        "websockets":state.websockets.iter().map(|(id,item)| json!({
            "id":id,"domain":item.domain,"started":item.started,"message_count":number(&item.messages)
        })).collect::<Vec<_>>()
    })
}
// Fixed source recipes sometimes supply integer-valued clocks, although the
// real time.time() API and this component's clock seam return f64. Normalize
// only those private timestamp slots; counters/event/stats bytes stay exact.
fn clock_state(value: &Value) -> Value {
    let mut value = value.clone();
    for key in ["started", "last_event_time"] {
        value[key] = json!(value[key].as_f64().unwrap());
    }
    for key in ["connections", "websockets"] {
        for entry in value[key].as_array_mut().unwrap() {
            entry["started"] = json!(entry["started"].as_f64().unwrap());
        }
    }
    value
}
fn memory() -> std::result::Result<MemorySample, SampleError> {
    Ok(MemorySample {
        rss_kb: 1280.into(),
        peak_kb: 2560.into(),
    })
}
fn decoded(
    spec: &Value,
    trace: &RefCell<Vec<Value>>,
    label: &str,
) -> std::result::Result<u64, ContentError> {
    trace.borrow_mut().push(json!(format!("{label}.content")));
    let body = spec
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .as_bytes();
    let mut encoded = Vec::new();
    let coding = match spec["encoding"].as_str() {
        Some("invalid_gzip") => {
            encoded.extend_from_slice(b"owned invalid gzip");
            b"gzip".as_slice()
        }
        Some("gzip") => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(body).unwrap();
            encoded = encoder.finish().unwrap();
            b"gzip".as_slice()
        }
        _ => {
            encoded.extend_from_slice(body);
            b"identity".as_slice()
        }
    };
    http_content::decode(&encoded, coding).map(|body| body.len() as u64)
}

#[test]
fn actual_source_twenty_four_hook_workflows() {
    let source: Value =
        serde_json::from_str(include_str!("../../tests/memory_monitor_source.json")).unwrap();
    assert_eq!(source["rows"].as_array().unwrap().len(), 24);
    for row in source["rows"].as_array().unwrap() {
        let monitor = MemoryMonitor::new();
        let sink = Sink::new();
        // A real synchronous Writer error proves the same committed-effect
        // boundary as source put_event exceptions. Its native category differs
        // from the source fixture's injected RuntimeError/OSError text.
        let poisoned = Writer::new(
            sink._directory.path().join("never-written.jsonl"),
            Settings::default(),
        );
        poisoned.poison_for_test();
        let name = row["input"]["name"].as_str().unwrap();
        for (index, spec) in row["input"]["steps"].as_array().unwrap().iter().enumerate() {
            let expected = &row["steps"][index];
            let trace = RefCell::new(Vec::new());
            let times: Vec<f64> = match spec["now"].as_array() {
                Some(values) => values.iter().map(|v| v.as_f64().unwrap()).collect(),
                None => vec![spec["now"].as_f64().unwrap()],
            };
            let tick = Cell::new(0_usize);
            let clock = || {
                let value = times[tick.get().min(times.len() - 1)];
                tick.set(tick.get() + 1);
                let supplied = if let Some(times) = spec["now"].as_array() {
                    times[(tick.get() - 1).min(times.len() - 1)].clone()
                } else {
                    spec["now"].clone()
                };
                trace.borrow_mut().push(json!({"time":supplied}));
                value
            };
            let sample = || {
                let values = spec.get("memory").cloned().unwrap_or(json!([1280, 2560]));
                trace.borrow_mut().push(json!({"sample_kb":values}));
                if spec.get("memory_error").is_some() {
                    return Err(SampleError::Index);
                }
                Ok(MemorySample {
                    rss_kb: values[0].as_i64().unwrap().into(),
                    peak_kb: values[1].as_i64().unwrap().into(),
                })
            };
            let writer = if spec.get("audit_error").is_some() {
                &poisoned
            } else {
                &sink.writer
            };
            let id = spec["client"].as_str().unwrap_or("conn");
            let host = spec["host"].as_str().unwrap_or("owned.invalid");
            let before_events = sink.records().len();
            let mut stats = None;
            let result = match spec["hook"].as_str().unwrap() {
                "running" => monitor.running(writer, sample, clock),
                "client_connected" => monitor.client_connected(id, clock),
                "client_disconnected" => monitor.client_disconnected(id, writer, clock),
                "request" => monitor.request(
                    id,
                    host,
                    writer,
                    || decoded(spec, &trace, "request"),
                    clock,
                    sample,
                ),
                "response" => monitor.response(
                    id,
                    !spec["absent"].as_bool().unwrap_or(false),
                    spec["stream"].as_bool().unwrap_or(false) || spec["stream"].is_string(),
                    || decoded(spec, &trace, "response"),
                ),
                "websocket_start" => monitor.websocket_start(id, host, clock),
                "websocket_message" => monitor.websocket_message(id),
                "websocket_end" => monitor.websocket_end(id, writer, clock),
                "get_stats" => monitor.get_stats(sample, clock).map(|value| {
                    stats = Some(value.render_json(false).unwrap());
                }),
                "populate" => {
                    for (i, count) in spec["counts"].as_array().unwrap().iter().enumerate() {
                        let id = format!("c{i}");
                        let host = format!("h{i}.invalid");
                        monitor.client_connected(&id, clock).unwrap();
                        for _ in 0..count.as_u64().unwrap() {
                            monitor
                                .request(
                                    &id,
                                    &host,
                                    writer,
                                    || decoded(&json!({}), &trace, "request"),
                                    clock,
                                    sample,
                                )
                                .unwrap();
                        }
                        monitor.websocket_start(&id, &host, clock).unwrap();
                    }
                    Ok(())
                }
                other => panic!("unknown fixture hook {other}"),
            };
            let error_class = result.err().map(|error| match error.kind() {
                ErrorKind::Content(ContentError::Value) => "ValueError",
                ErrorKind::Sample(SampleError::Index) => "IndexError",
                ErrorKind::Audit(audit::ErrorKind::Poisoned) => spec["audit_error"]
                    .as_str()
                    .expect("source submission failure"),
                other => panic!("unexpected {other:?}"),
            });
            assert_eq!(
                error_class,
                expected["error_class"].as_str(),
                "{name} step {index}"
            );
            assert_eq!(
                state(&monitor),
                clock_state(&expected["state_after"]),
                "{name} step {index}"
            );
            assert_eq!(
                stats.as_deref(),
                expected["stats_json"].as_str(),
                "{name} step {index}"
            );
            let reached: Vec<_> = expected["timeline"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| !v.as_str().is_some_and(|s| s.starts_with("put_event:")))
                .cloned()
                .collect();
            assert_eq!(*trace.borrow(), reached, "{name} step {index}");
            let actual = sink.records();
            let attempts: Vec<_> = row["attempts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["step"].as_u64() == Some(index as u64))
                .collect();
            // No callback fake is installed in Writer. The source records its
            // state at submission; these hooks perform no subsequent mutations,
            // so after-hook state checks also prove retained submission effects.
            for attempt in &attempts {
                assert_eq!(
                    state(&monitor),
                    clock_state(&attempt["state_at_submit"]),
                    "{name}"
                );
            }
            let accepted: Vec<_> = attempts
                .into_iter()
                .filter(|a| a["accepted"] == true)
                .collect();
            assert_eq!(
                actual.len() - before_events,
                accepted.len(),
                "{name} step {index}"
            );
            for (actual, expected) in actual[before_events..].iter().zip(accepted) {
                let mut actual = actual.clone();
                actual["ts"] = expected["event"]["ts"].clone();
                assert_eq!(
                    crate::python_json::encode(&actual),
                    crate::python_json::encode(&expected["event"]),
                    "{name} step {index}"
                );
            }
        }
        assert!(!sink._directory.path().join("never-written.jsonl").exists());
    }
}

#[test]
fn uncapped_counters_floor_and_binary_rounding() {
    let monitor = MemoryMonitor::new();
    let sink = Sink::new();
    monitor
        .running(
            &sink.writer,
            || {
                Ok(MemorySample {
                    rss_kb: (-1).into(),
                    peak_kb: 0.into(),
                })
            },
            || 10.,
        )
        .unwrap();
    assert_eq!(
        sink.records()[0]["summary"],
        "Memory monitor started (baseline RSS: -1 MB)"
    );
    monitor.client_connected("c", || 10.).unwrap();
    monitor
        .websocket_start("c", "owned.invalid", || 10.)
        .unwrap();
    let huge = BigInt::from(1_u8) << 80_usize;
    {
        let mut state = monitor.lock().unwrap();
        state.total_flows = huge.clone();
        let conn = state.connections.get_mut("c").unwrap();
        conn.flows = huge.clone();
        conn.sent = huge.clone();
        conn.received = huge.clone();
        state.websockets.get_mut("c").unwrap().messages = huge.clone();
    }
    monitor
        .request("c", "owned.invalid", &sink.writer, || Ok(7), || 11., memory)
        .unwrap();
    monitor.response("c", true, false, || Ok(9)).unwrap();
    monitor.websocket_message("c").unwrap();
    let stats = monitor.get_stats(memory, || 9.5).unwrap().json().unwrap();
    assert_eq!(stats["total_flows"], number(&(&huge + 1)));
    assert_eq!(stats["connections"][0]["bytes_sent"], number(&(&huge + 7)));
    assert_eq!(
        stats["connections"][0]["bytes_received"],
        number(&(&huge + 9))
    );
    assert_eq!(stats["websockets"][0]["messages"], number(&(&huge + 1)));
    assert_eq!(stats["connections"][0]["age_s"], 0);
    for (kb, expected) in [(-1280, -1.2), (1280, 1.2), (3840, 3.8), (0, 0.)] {
        assert_eq!(
            megabytes(&kb.into()).unwrap().to_bits(),
            f64::to_bits(expected)
        );
    }
    assert_eq!(
        megabytes(&(-1).into()).unwrap().to_bits(),
        (-0.0_f64).to_bits()
    );
    assert_eq!(
        age(1., f64::NAN).unwrap_err().kind(),
        ErrorKind::Numeric(NumericError::Value)
    );
    assert_eq!(
        age(f64::INFINITY, 1.).unwrap_err().kind(),
        ErrorKind::Numeric(NumericError::Overflow)
    );
}

#[test]
fn stats_reaches_all_ages_but_periodic_only_top_ten_and_close_pops_before_error() {
    let monitor = MemoryMonitor::new();
    let sink = Sink::new();
    for i in 0..11 {
        monitor
            .client_connected(&format!("c{i}"), || if i == 10 { f64::NAN } else { 0. })
            .unwrap();
    }
    // All equal counts, stable insertion order: bad eleventh age is excluded
    // only from periodic conversion, never from get_stats conversion.
    monitor
        .request(
            "untracked",
            "unused",
            &sink.writer,
            || panic!("unknown decode"),
            || 60.,
            memory,
        )
        .unwrap();
    assert_eq!(sink.records().len(), 1);
    assert_eq!(
        monitor.get_stats(memory, || 61.).unwrap_err().kind(),
        ErrorKind::Numeric(NumericError::Value)
    );
    monitor
        .lock()
        .unwrap()
        .connections
        .get_mut("c10")
        .unwrap()
        .flows = 1.into();
    assert_eq!(
        monitor
            .client_disconnected("c10", &sink.writer, || 61.)
            .unwrap_err()
            .kind(),
        ErrorKind::Numeric(NumericError::Value)
    );
    assert!(!monitor.lock().unwrap().connections.contains_key("c10"));
    assert_eq!(sink.records().len(), 1);
    monitor
        .websocket_start("ws", "owned.invalid", || f64::INFINITY)
        .unwrap();
    assert_eq!(
        monitor
            .websocket_end("ws", &sink.writer, || 61.)
            .unwrap_err()
            .kind(),
        ErrorKind::Numeric(NumericError::Overflow)
    );
    assert!(monitor.lock().unwrap().websockets.is_empty());
}
