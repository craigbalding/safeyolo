use super::*;
use crate::policy::{Format, Policy, TimestampPaths};

#[test]
fn cleanup_of_deep_typed_objects_and_arrays_uses_an_owned_worklist() {
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| {
            let mut value = CircuitValue::Other(Value::String("owned private fixture".into()));
            for depth in 0..10_000 {
                value = if depth % 2 == 0 {
                    CircuitValue::Array(vec![value])
                } else {
                    CircuitValue::Object([("owned private key".into(), value)].into())
                };
            }
            wipe(&mut value);
            assert!(value.as_object().unwrap().is_empty());
        })
        .unwrap()
        .join()
        .unwrap();
}

fn kind(value: &str) -> Kind {
    match value {
        "security" => Kind::Security,
        "gateway" => Kind::Gateway,
        "traffic" => Kind::Traffic,
        "ops" => Kind::Ops,
        "admin" => Kind::Admin,
        "agent" => Kind::Agent,
        "plumb" => Kind::Plumb,
        "coord" => Kind::Coord,
        _ => panic!("fixture kind"),
    }
}
fn temporal_details(source: &str) -> CircuitValue {
    let yaml = format!(
        "addons:\n  circuit_breaker:\n    details:\n{}",
        source
            .lines()
            .map(|line| format!("      {line}\n"))
            .collect::<String>()
    );
    let policy = Policy::parse_at(&yaml, Format::Yaml, 0.).unwrap();
    let view = policy.circuit_settings();
    let raw = view.values().unwrap()["details"].clone();
    let mut types = TimestampPaths::default();
    let mut pending = vec![(&raw, Vec::<String>::new())];
    while let Some((value, path)) = pending.pop() {
        let relative: Vec<_> = path.iter().map(String::as_str).collect();
        let absolute: Vec<_> = std::iter::once("details")
            .chain(relative.iter().copied())
            .collect();
        if let Some(value) = view.temporal_value(&absolute) {
            types.insert_value(&relative, value.clone());
            continue;
        }
        if let Some(value) = view.temporal_key(&absolute) {
            types.insert_key(&relative, value.clone());
        }
        match value {
            Value::Object(values) => {
                for (key, value) in values {
                    let mut next = path.clone();
                    next.push(key.clone());
                    pending.push((value, next));
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    let mut next = path.clone();
                    next.push(index.to_string());
                    pending.push((value, next));
                }
            }
            _ => {}
        }
    }
    CircuitValue::from_annotated(raw, types)
}

#[test]
fn envelope_matches_actual_source_bytes_and_schema_consumer() {
    let fixtures: Value =
        serde_json::from_str(include_str!("../../../tests/audit_source.json")).unwrap();
    let now = OffsetDateTime::parse(
        "2026-01-02T03:04:05.123456Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    for row in fixtures["rows"].as_array().unwrap() {
        let input = &row["input"];
        let mut event = Event::new(
            input["event"].as_str().unwrap(),
            kind(input["kind"].as_str().unwrap()),
            Severity::Low,
            input["summary"].as_str().unwrap(),
        );
        let optional = |name: &str| input.get(name).and_then(Value::as_str).map(str::to_owned);
        event.request_id = optional("request_id");
        event.agent = optional("agent");
        event.addon = optional("addon");
        event.host = optional("host");
        if input.get("decision").is_some() {
            event.decision = Some(Decision::RequireApproval);
        }
        if let Some(approval) = input.get("approval") {
            event.approval = Some(Approval {
                required: approval["required"].as_bool().unwrap(),
                approval_type: ApprovalType::NetworkEgress,
                key: approval["key"].as_str().unwrap().into(),
                target: approval["target"].as_str().unwrap().into(),
                scope_hint: approval["scope_hint"].clone().into(),
            });
        }
        event.attribution = Some(Attribution {
            evidence_owner: optional("evidence_owner"),
            trusted_transport_identity: optional("trusted_transport_identity"),
            initiator: input.get("initiator").map(|_| Initiator::Unknown),
            status: input
                .get("attribution_status")
                .map(|_| AttributionStatus::Resolved),
            provenance: input
                .get("attribution_provenance")
                .cloned()
                .map(CircuitValue::from),
        });
        if let Some(text) = row["details_json"].as_str() {
            event.details = CircuitValue::parse_json(text).unwrap();
        }
        if let Some(source) = row["details_yaml"].as_str() {
            event.details = temporal_details(source);
        }
        if let Some(depth) = row["depth"].as_u64() {
            let mut value = CircuitValue::Other(Value::Null);
            for _ in 0..depth {
                value = CircuitValue::Object(IndexMap::from([("nested".into(), value)]));
            }
            event.details = value;
        }
        let record = event.record(now);
        let mut encoded = record.encode().unwrap().to_string();
        encoded.push('\n');
        let hex = encoded
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            hex == row["line_hex"].as_str().unwrap(),
            "source bytes differ: case {}",
            row["name"]
        );
    }
}

#[test]
fn optional_event_id_and_timestamp_are_construction_time_fields() {
    let now = OffsetDateTime::parse(
        "2026-01-02T03:04:05+05:30",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut event = Event::new("ops.fixture", Kind::Ops, Severity::Medium, "fixture");
    event.event_id = Some("logical-event".into());
    let bytes = event.record(now).encode().unwrap();
    let value: Value = serde_json::from_str(&bytes).unwrap();
    assert_eq!(value["ts"], "2026-01-02T03:04:05+05:30");
    assert_eq!(value["event_id"], "logical-event");
    assert!(!value.as_object().unwrap().contains_key("agent"));
    for (seconds, expected) in [(1, "+00:00"), (-1, "-00:00"), (61, "+00:01")] {
        let at = OffsetDateTime::UNIX_EPOCH
            .to_offset(time::UtcOffset::from_whole_seconds(seconds).unwrap());
        assert!(timestamp(at, true).ends_with(expected));
        assert!(timestamp(at, false).ends_with(&format!("{expected}:01")));
    }
}

#[test]
fn oversized_integer_fails_at_worker_encoding_after_model_construction() {
    let mut event = Event::new("ops.fixture", Kind::Ops, Severity::Medium, "fixture");
    event.details = CircuitValue::Object(IndexMap::from([(
        "n".into(),
        CircuitValue::Integer(format!("1{}", "0".repeat(4300)).parse().unwrap()),
    )]));
    let record = event.record(OffsetDateTime::UNIX_EPOCH);
    assert!(matches!(record.encode(), Err(Error(ErrorKind::Encoding))));
}
