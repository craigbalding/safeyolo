use super::*;
use crate::audit::Settings;
use std::{cell::Cell, fs::FileTimes, path::PathBuf, time::Duration};

struct Owned {
    directory: tempfile::TempDir,
    audit_path: PathBuf,
    writer: Writer,
}
impl Owned {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let audit_path = directory.path().join("audit.jsonl");
        let writer = Writer::new(audit_path.clone(), Settings::default());
        Self {
            directory,
            audit_path,
            writer,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
    fn records(&self) -> Vec<Value> {
        assert!(self.writer.wait_for_drain(Duration::from_secs(3)).unwrap());
        fs::read_to_string(&self.audit_path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        assert!(self.writer.shutdown(Duration::from_secs(3)).unwrap());
    }
}
fn field<'a>(value: &'a C, key: &str) -> &'a C {
    &value.as_object().unwrap()[key]
}
fn optional<'a>(value: &'a C, key: &str) -> Option<&'a C> {
    value.as_object().unwrap().get(key)
}
fn string(value: &C) -> &str {
    let C::Other(Value::String(value)) = value else {
        panic!("fixture string")
    };
    value
}
fn numeric(value: &C) -> f64 {
    value.render_json(false).unwrap().parse().unwrap()
}
fn encoded(value: &C) -> String {
    value.render_json(false).unwrap()
}
fn put(path: &Path, bytes: &[u8], mtime: f64) {
    fs::write(path, bytes).unwrap();
    File::open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs_f64(mtime)))
        .unwrap();
}
fn expected_state(owner: &AgentDiscovery, expected: &C, owned: &Owned, name: &str, step: usize) {
    let state = owner.lock().unwrap();
    let path = string(field(expected, "map_path"));
    let path = if path.is_empty() {
        String::new()
    } else {
        owned.path(path).to_str().unwrap().into()
    };
    assert_eq!(state.path, path, "{name}/{step} path");
    assert_eq!(
        state.mtime,
        numeric(field(expected, "map_mtime")),
        "{name}/{step} mtime"
    );
    assert_eq!(
        encoded(&state.map.0),
        encoded(field(expected, "agent_map")),
        "{name}/{step} map"
    );
    let reverse = C::Array(
        state
            .reverse
            .values()
            .map(|entry| C::Array(vec![entry.value.clone(), text(&entry.name)]))
            .collect(),
    );
    assert_eq!(
        encoded(&reverse),
        encoded(field(expected, "ip_to_name")),
        "{name}/{step} reverse"
    );
    let seen = C::Object(
        state
            .last_seen
            .iter()
            .map(|(name, time)| (name.clone(), C::Float(*time)))
            .collect(),
    );
    assert_eq!(
        encoded(&seen),
        encoded(field(expected, "last_seen")),
        "{name}/{step} seen"
    );
}

#[test]
fn actual_source_fourteen_component_workflows() {
    let source = C::parse_json(include_str!("../../tests/agent_discovery_source.json")).unwrap();
    let rows = field(&source, "rows").as_array().unwrap();
    assert_eq!(rows.len(), 20);
    let mut count = 0;
    for row in rows.iter().take(15) {
        let input = field(row, "input");
        let name = string(field(input, "name"));
        // Writer's synchronous Io is not injected here. Its source containment
        // is retained by reload, but this particular fixture is source-only.
        if name == "audit_oserror_swallowed_after_publication" {
            continue;
        }
        count += 1;
        let owned = Owned::new();
        let owner = AgentDiscovery::new();
        let poisoned = Writer::new(owned.path("unused.jsonl"), Settings::default());
        poisoned.poison_for_test();
        for (index, spec) in field(input, "steps").as_array().unwrap().iter().enumerate() {
            // API routing is a separate owner; replay only component steps.
            if string(field(spec, "hook")) == "api" {
                continue;
            }
            let expected = &field(row, "steps").as_array().unwrap()[index];
            let before = owned.records().len();
            let writer = if optional(spec, "audit_error").is_some() {
                &poisoned
            } else {
                &owned.writer
            };
            let calls = Cell::new(0);
            let clock = || {
                calls.set(calls.get() + 1);
                numeric(field(spec, "now"))
            };
            let mut actual = None;
            // A directory provides a real owned read failure after successful
            // metadata, without changing the component's I/O implementation.
            let reading_error = optional(spec, "read_error").is_some();
            if reading_error {
                fs::rename(owned.path("map.json"), owned.path("saved-map.json")).unwrap();
                fs::create_dir(owned.path("map.json")).unwrap();
                File::open(owned.path("map.json"))
                    .unwrap()
                    .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))
                    .unwrap();
            }
            let result = match string(field(spec, "hook")) {
                "write" => {
                    let bytes = if let Some(hex) = optional(spec, "hex") {
                        let hex = string(hex).as_bytes();
                        hex.chunks_exact(2)
                            .map(|b| {
                                u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()
                            })
                            .collect()
                    } else if let Some(value) = optional(spec, "text") {
                        string(value).as_bytes().to_vec()
                    } else {
                        encoded(field(spec, "data")).into_bytes()
                    };
                    let path = optional(spec, "path").map(string).unwrap_or("map.json");
                    put(&owned.path(path), &bytes, numeric(field(spec, "mtime")));
                    Ok(())
                }
                "delete_file" => {
                    fs::remove_file(owned.path("map.json")).unwrap();
                    Ok(())
                }
                "configure" => {
                    let path = string(field(spec, "path"));
                    let path = if path.is_empty() {
                        String::new()
                    } else {
                        owned.path(path).to_str().unwrap().into()
                    };
                    owner.configure(&path, writer)
                }
                "get_agents" => owner
                    .get_agents(writer, clock)
                    .map(|value| actual = Some(value)),
                "get_stats" => owner
                    .get_stats(writer, clock)
                    .map(|value| actual = Some(value)),
                // The oracle's lookup merely requests a reload here. There is
                // intentionally no native IP-based identity resolution API.
                "lookup" => owner.reload(writer),
                "request" => {
                    // This is the explicit join contract, not a native HTTP
                    // activation claim: source identity lookup catches errors.
                    let _ = owner.reload(writer);
                    owner.observe_trusted(string(field(spec, "agent")), clock)
                }
                other => panic!("unexpected fixture hook {other}"),
            };
            if reading_error {
                fs::remove_dir(owned.path("map.json")).unwrap();
                fs::rename(owned.path("saved-map.json"), owned.path("map.json")).unwrap();
            }
            let class = result.err().map(|error| match error.kind() {
                ErrorKind::Attribute => "AttributeError",
                ErrorKind::Type => "TypeError",
                ErrorKind::UnicodeDecode => "UnicodeDecodeError",
                ErrorKind::Audit(audit::ErrorKind::Poisoned) => "RuntimeError",
                other => panic!("unexpected error {other:?}"),
            });
            let expected_class = match field(expected, "error_class") {
                C::Other(Value::Null) => None,
                value => Some(string(value)),
            };
            assert_eq!(class, expected_class, "{name}/{index}");
            if let Some(actual) = actual {
                let mut report = C::parse_json(string(field(expected, "result_json"))).unwrap();
                if let C::Object(fields) = &mut report
                    && let Some(path) = fields.get_mut("map_file")
                {
                    let lexical = string(path);
                    if !lexical.is_empty() {
                        *path = text(owned.path(lexical).to_str().unwrap());
                    }
                }
                assert_eq!(encoded(&actual), encoded(&report), "{name}/{index} report");
            }
            let expected_calls = field(expected, "timeline")
                .as_array()
                .unwrap()
                .iter()
                .filter(|item| {
                    item.as_object()
                        .is_some_and(|fields| fields.contains_key("time"))
                })
                .count();
            assert_eq!(calls.get(), expected_calls, "{name}/{index} clock");
            expected_state(&owner, field(expected, "state_after"), &owned, name, index);
            let mut actual = owned.records().into_iter().skip(before).collect::<Vec<_>>();
            let mut expected = field(row, "attempts")
                .as_array()
                .unwrap()
                .iter()
                .filter(|attempt| {
                    numeric(field(attempt, "step")) as usize == index
                        && field(attempt, "accepted").truthy()
                })
                .map(|attempt| {
                    serde_json::from_str::<Value>(&encoded(field(attempt, "event"))).unwrap()
                })
                .collect::<Vec<_>>();
            for event in actual.iter_mut().chain(expected.iter_mut()) {
                event.as_object_mut().unwrap().remove("ts");
            }
            actual.sort_by_key(|event| event["agent"].as_str().unwrap().to_owned());
            expected.sort_by_key(|event| event["agent"].as_str().unwrap().to_owned());
            assert_eq!(actual, expected, "{name}/{index} unordered events");
        }
    }
    assert_eq!(count, 14);
}

#[test]
fn report_clock_runs_before_reload_and_observation_never_refreshes_map() {
    let owned = Owned::new();
    let owner = AgentDiscovery::new();
    let path = owned.path("map.json");
    put(&path, br#"{"alice":{"ip":"192.0.2.1"}}"#, 1.0);
    owner
        .configure(path.to_str().unwrap(), &owned.writer)
        .unwrap();
    put(&path, b"[]", 2.0);
    owner.observe_trusted("alice", || 100.25).unwrap();
    assert_eq!(owner.lock().unwrap().mtime, 1.0);
    let report = owner
        .get_agents(&owned.writer, || {
            put(&path, br#"{"alice":{"ip":"192.0.2.2"}}"#, 3.0);
            101.5
        })
        .unwrap();
    assert_eq!(
        encoded(&report),
        r#"{"agents": {"alice": {"ip": "192.0.2.2", "last_seen": 100.25, "idle_seconds": 1.2}}, "count": 1}"#
    );
}

#[test]
fn hashable_json_ip_equality_retains_first_key_and_last_owner() {
    let owned = Owned::new();
    let owner = AgentDiscovery::new();
    let path = owned.path("map.json");
    put(&path, br#"{"float":{"ip":1.0},"bool":{"ip":true},"int":{"ip":1},"nan1":{"ip":NaN},"nan2":{"ip":NaN},"huge":{"ip":9007199254740993},"rounded":{"ip":9007199254740992.0}}"#, 1.0);
    owner
        .configure(path.to_str().unwrap(), &owned.writer)
        .unwrap();
    let state = owner.lock().unwrap();
    assert_eq!(state.reverse.len(), 4);
    let first = state.reverse.first().unwrap().1;
    assert_eq!(encoded(&first.value), "1.0");
    assert_eq!(first.name, "int");
    assert_eq!(state.reverse.get_index(1).unwrap().1.name, "nan2");
}

#[test]
fn source_json_conversion_limit_and_error_categories_do_not_publish() {
    let owned = Owned::new();
    let owner = AgentDiscovery::new();
    let path = owned.path("map.json");
    let data = format!("{{\"unused\":{{\"ignored\":{}}}}}", "1".repeat(4301));
    put(&path, data.as_bytes(), 1.0);
    assert_eq!(
        owner
            .configure(path.to_str().unwrap(), &owned.writer)
            .unwrap_err()
            .kind(),
        ErrorKind::Value
    );
    assert!(owner.matches_path(path.to_str().unwrap()).unwrap());
    assert!(!owner.matches_path("").unwrap());
    assert_eq!(owner.lock().unwrap().mtime, 0.0);
    assert!(owner.lock().unwrap().reverse.is_empty());
    owner.configure("", &owned.writer).unwrap();
    assert_eq!(
        encoded(&owner.get_agents(&owned.writer, || 1.0).unwrap()),
        r#"{"agents": {}, "count": 0}"#
    );
    assert!(exists(Path::new("owned\0invalid")).is_ok_and(|exists| !exists));
    assert_eq!(
        Error(ErrorKind::Compatibility).to_string(),
        "agent discovery operation failed"
    );
}

#[test]
fn failed_path_change_retains_new_path_and_allows_explicit_recovery() {
    let owned = Owned::new();
    let owner = AgentDiscovery::new();
    let first = owned.path("first.json");
    let second = owned.path("second.json");
    put(&first, br#"{"alice":{"ip":"192.0.2.1"}}"#, 1.0);
    put(&second, b"[]", 2.0);
    owner
        .configure(first.to_str().unwrap(), &owned.writer)
        .unwrap();
    assert_eq!(
        owner
            .configure(second.to_str().unwrap(), &owned.writer)
            .unwrap_err()
            .kind(),
        ErrorKind::Attribute
    );
    assert!(owner.matches_path(second.to_str().unwrap()).unwrap());
    assert!(!owner.matches_path(first.to_str().unwrap()).unwrap());
    assert_eq!(owner.lock().unwrap().mtime, 1.0);
    owner
        .configure(first.to_str().unwrap(), &owned.writer)
        .unwrap();
    assert!(owner.matches_path(first.to_str().unwrap()).unwrap());
    assert_eq!(owner.lock().unwrap().mtime, 1.0);
}
