use super::*;

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

#[test]
fn current_ordinary_families_round_trip_their_owned_fields() {
    for kind in [
        Kind::Security,
        Kind::Gateway,
        Kind::Traffic,
        Kind::Ops,
        Kind::Admin,
        Kind::Agent,
        Kind::Plumb,
        Kind::Coord,
    ] {
        let mut event = Event::new(
            format!("{}.fixture", kind.as_str()),
            kind,
            Severity::Low,
            "owned fixture",
        );
        event.event_id = Some("event-1".into());
        event.request_id = Some("request-1".into());
        event.agent = Some("alice".into());
        event.decision = Some(Decision::RequireApproval);
        event.approval = Some(Approval {
            required: true,
            approval_type: ApprovalType::NetworkEgress,
            key: "owned-key".into(),
            target: "owned.invalid".into(),
            scope_hint: serde_json::json!({"host":"owned.invalid"}).into(),
        });
        event.details = serde_json::json!({"count":7,"attribution":{
            "evidence_owner":"forged", "trusted_transport_identity":"forged"}})
        .into();
        event.attribution = Some(Attribution {
            evidence_owner: Some("alice".into()),
            status: Some(AttributionStatus::Resolved),
            ..Default::default()
        });
        let bytes = event.record(OffsetDateTime::UNIX_EPOCH).encode().unwrap();
        let row = crate::audit::parse_record(&bytes).unwrap();
        assert_eq!(row["schema_version"], 2);
        assert_eq!(row["kind"], kind.as_str());
        assert_eq!(row["request_id"], "request-1");
        assert_eq!(row["decision"], "require_approval");
        assert_eq!(row["approval"]["scope_hint"]["host"], "owned.invalid");
        assert_eq!(row["details"]["count"], 7);
        assert_eq!(row["details"]["attribution"]["evidence_owner"], "alice");
        assert!(
            row["details"]["attribution"]
                .get("trusted_transport_identity")
                .is_none()
        );
        assert!(!crate::audit::nsm::is_scoped(&row));
        for (pointer, value) in [
            ("/kind", serde_json::json!("invented")),
            ("/event", serde_json::json!("other.fixture")),
            ("/ts", serde_json::json!("not a timestamp")),
            ("/summary", serde_json::json!("")),
            ("/severity", serde_json::json!("invented")),
            ("/details", serde_json::json!([])),
            ("/agent", serde_json::json!(5)),
            ("/decision", serde_json::json!("invented")),
            ("/approval/required", serde_json::json!("yes")),
            ("/approval/approval_type", serde_json::json!("invented")),
            ("/approval/scope_hint", Value::Null),
        ] {
            let mut invalid = row.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                crate::audit::parse_record(&invalid.to_string()).is_err(),
                "{pointer}"
            );
        }
        let mut extra = row.clone();
        extra["payload"] = serde_json::json!("not an envelope field");
        assert!(crate::audit::parse_record(&extra.to_string()).is_err());
        for version in [Value::Null, serde_json::json!(1), serde_json::json!(99)] {
            let mut invalid = row.clone();
            if version.is_null() {
                invalid.as_object_mut().unwrap().remove("schema_version");
            } else {
                invalid["schema_version"] = version;
            }
            assert!(crate::audit::parse_record(&invalid.to_string()).is_err());
        }
    }
    for invalid in ["[]", "null", "42", "{}", "not json"] {
        assert!(crate::audit::parse_record(invalid).is_err());
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
        assert!(timestamp(at).ends_with(expected));
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
