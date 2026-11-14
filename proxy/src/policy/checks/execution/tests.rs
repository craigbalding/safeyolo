use super::*;

#[test]
fn returned_job_metadata_does_not_disclose_host_retained_dependency_bodies() {
    let mut evidence: Evidence = serde_json::from_value(json!({
        "check":"author","source_id":"adopted","meaning":"issue author","scale":null,
        "subject":{"kind":"value","value":"123"},"input_digest":"bound-input","acquisition":"live",
        "file_digest":null,"file_version":null,"result":null,"unavailable":null,"expires_at_ms":null,
        "feed_version":null,"execution":{"kind":"job","run_id":"job-owned",
        "service_evidence":[{"id":"capture","response_sha256":"bound-evidence","retained_base64":"private-response","request_body_base64":"private-input"}]}
    })).unwrap();
    let retained = evidence.clone();
    redact_captured_bodies(&mut evidence);
    let capture = &evidence.execution.as_ref().unwrap()["service_evidence"][0];
    assert_eq!(capture["id"], "capture");
    assert_eq!(capture["response_sha256"], "bound-evidence");
    assert!(capture.get("retained_base64").is_none());
    assert!(capture.get("request_body_base64").is_none());
    assert_eq!(
        retained.execution.as_ref().unwrap()["service_evidence"][0]["retained_base64"],
        "private-response"
    );
    // A service producer has a separate response schema; do not rewrite it by
    // matching a field name that happens to occur in the job capture schema.
    let mut service = retained;
    service.execution.as_mut().unwrap()["kind"] = json!("service");
    let original = service.execution.clone();
    redact_captured_bodies(&mut service);
    assert_eq!(service.execution, original);
}

const CAPTURE: &[u8] = include_bytes!("../../../../tests/fixtures/policy-check-github-issue.json");

#[test]
fn admission_consumes_one_complete_host_capture_not_caller_normalized_facts() {
    let url = "https://api.github.com/repos/craigbalding/safeyolo/issues/1544";
    let inputs = BTreeMap::from([("repository".into(), "craigbalding/safeyolo".into())]);
    let subject = Subject::Value {
        value: "1544".into(),
    };
    let capture = json!({"service":"github","method":"GET","url":url,"status":200,
        "error":null,"response_bytes":CAPTURE.len(),"response_sha256":content_digest(CAPTURE),
        "retained_base64":STANDARD.encode(CAPTURE)});
    let execution = json!({"kind":"job","service_evidence":[capture]});
    let snapshot = checked_github_input(&execution, &inputs, &subject).unwrap();
    assert_eq!(snapshot["sha256"], content_digest(CAPTURE));
    assert_eq!(
        STANDARD
            .decode(snapshot["content_base64"].as_str().unwrap())
            .unwrap(),
        CAPTURE
    );
    for (field, value) in [
        (
            "url",
            json!("https://api.github.com/repos/other/repo/issues/1544"),
        ),
        ("service", json!("another-service")),
        ("method", json!("POST")),
        ("status", json!(403)),
        ("error", json!("policy_denied")),
        ("response_bytes", json!(CAPTURE.len() - 1)),
        ("response_sha256", json!("substituted")),
        ("retained_base64", Value::Null),
    ] {
        let mut changed = execution.clone();
        changed["service_evidence"][0][field] = value;
        assert!(
            checked_github_input(&changed, &inputs, &subject).is_err(),
            "{field}"
        );
    }
    let duplicate = json!({"service_evidence":[capture.clone(),capture]});
    assert!(checked_github_input(&duplicate, &inputs, &subject).is_err());
    let mut changed: Value = serde_json::from_slice(CAPTURE).unwrap();
    changed["body"] = json!("Refreshed relevant issue revision");
    changed["updated_at"] = json!("2026-11-14T03:00:00Z");
    let bytes = serde_json::to_vec(&changed).unwrap();
    let mut refreshed = execution;
    refreshed["service_evidence"][0]["retained_base64"] = json!(STANDARD.encode(&bytes));
    refreshed["service_evidence"][0]["response_bytes"] = json!(bytes.len());
    refreshed["service_evidence"][0]["response_sha256"] = json!(content_digest(&bytes));
    let next = checked_github_input(&refreshed, &inputs, &subject).unwrap();
    assert_ne!(next["sha256"], snapshot["sha256"]);
    assert_eq!(
        STANDARD
            .decode(next["content_base64"].as_str().unwrap())
            .unwrap(),
        bytes
    );
}

#[test]
fn captured_authoritative_github_issue_reports_identity_match_mismatch_and_missing_evidence() {
    // Captured with gh api repos/craigbalding/safeyolo/issues/1544 on
    // 2026-11-13. Identity expectations are policy inputs, not adapter constants.
    let path = "/repos/craigbalding/safeyolo/issues/1544";
    let mut inputs = BTreeMap::from([
        ("expected_author".into(), "craigbalding".into()),
        ("expected_repository_owner".into(), "craigbalding".into()),
    ]);
    let result = github_issue(CAPTURE, path, &inputs).unwrap();
    assert!(matches!(
        result.finding,
        Finding::Finding { positive: true }
    ));
    assert_eq!(
        result.source_revision.as_deref(),
        Some("issue:6368529154:2026-11-13T13:45:58Z")
    );
    inputs.insert("expected_author".into(), "another-author".into());
    assert!(matches!(
        github_issue(CAPTURE, path, &inputs).unwrap().finding,
        Finding::Finding { positive: false }
    ));
    inputs.insert("expected_author".into(), "craigbalding".into());
    inputs.insert("expected_repository_owner".into(), "another-owner".into());
    assert!(matches!(
        github_issue(CAPTURE, path, &inputs).unwrap().finding,
        Finding::Finding { positive: false }
    ));
    assert!(github_issue(CAPTURE, "/repos/craigbalding/safeyolo/issues/1545", &inputs).is_err());
    assert!(github_issue(CAPTURE, path, &BTreeMap::new()).is_err());
    let mut captured: Value = serde_json::from_slice(CAPTURE).unwrap();
    for key in ["id", "url", "user", "updated_at", "title", "body"] {
        let mut missing = captured.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            github_issue(&serde_json::to_vec(&missing).unwrap(), path, &inputs).is_err(),
            "{key}"
        );
    }
    let digest = content_digest(CAPTURE);
    captured["body"] = json!("different content at the same advertised revision");
    assert_ne!(
        digest,
        content_digest(&serde_json::to_vec(&captured).unwrap())
    );
}

#[test]
fn adopted_path_mapping_preserves_gateway_canonical_paths_and_escapes_caller_values() {
    let subject = Subject::Hostname {
        hostname: "example.test".into(),
    };
    assert_eq!(
        render_path("/check/{subject}", &subject, &BTreeMap::new()).unwrap(),
        "/check/example.test"
    );
    let subject = Subject::Value {
        value: "/scan?active=true&other=x".into(),
    };
    assert_eq!(
        render_path("/check/{subject}", &subject, &BTreeMap::new()).unwrap(),
        "/check/%2Fscan%3Factive%3Dtrue%26other%3Dx"
    );
    assert!(render_path("/check/{input.expected}", &subject, &BTreeMap::new()).is_err());
    assert_eq!(
        render_path(
            "/check/{input.expected}",
            &subject,
            &BTreeMap::from([("expected".into(), "owned.test".into())])
        )
        .unwrap(),
        "/check/owned.test"
    );
}

#[test]
fn typed_results_cannot_supply_host_binding_fields_or_promote_pass_text() {
    for bytes in [b"PASS".as_slice(),br#"{"finding":"PASS"}"#,
        br#"{"finding":{"kind":"finding","positive":false},"collected_at_ms":0}"#,
        br#"{"finding":{"kind":"finding","positive":false},"subject":{"kind":"hostname","hostname":"forged.test"}}"#] {
        assert!(serde_json::from_slice::<ProviderResult>(bytes).is_err());
    }
    let result: ProviderResult =
        serde_json::from_slice(br#"{"finding":{"kind":"failure","reason":"source unavailable"}}"#)
            .unwrap();
    assert!(matches!(result.finding, Finding::Failure { .. }));
}

#[test]
fn rdap_registration_uses_only_exact_domain_creation_and_preserves_unknowns() {
    let bytes = include_bytes!(
        "../../../../../cli/src/safeyolo/agent_context/skills/policy-authoring/assets/rdap-synthetic.json"
    );
    let subject = Subject::Hostname {
        hostname: "example.com".into(),
    };
    let result = rdap_registration(bytes, &subject).unwrap();
    assert!(matches!(
        result.finding,
        Finding::Timestamp {
            unix_ms: 808372800000
        }
    ));
    assert!(result.source_observed_at_ms.is_none());
    assert!(result.source_revision.is_none());
    let captured: Value = serde_json::from_slice(bytes).unwrap();
    for action in [
        "last changed",
        "transfer",
        "certificate issued",
        "reregistration",
    ] {
        let mut record = captured.clone();
        record["events"] = json!([{"eventAction":action,"eventDate":"2026-11-10T00:00:00Z"}]);
        assert!(rdap_registration(&serde_json::to_vec(&record).unwrap(), &subject).is_err());
    }
    for date in [
        "invalid",
        "1969-12-31T23:59:59.999999999Z",
        "2999-01-01T00:00:00Z",
    ] {
        let mut record = captured.clone();
        record["events"][0]["eventDate"] = json!(date);
        assert!(
            rdap_registration(&serde_json::to_vec(&record).unwrap(), &subject).is_err(),
            "{date}"
        );
    }
    let mut ambiguous = captured.clone();
    ambiguous["events"]
        .as_array_mut()
        .unwrap()
        .push(captured["events"][0].clone());
    assert!(rdap_registration(&serde_json::to_vec(&ambiguous).unwrap(), &subject).is_err());
    for name in ["example.co.uk", "tenant.hosted.example.com"] {
        let subject = Subject::Hostname {
            hostname: name.into(),
        };
        assert!(rdap_registration(bytes, &subject).is_err());
        let mut exact = captured.clone();
        exact["ldhName"] = json!(name);
        assert!(rdap_registration(&serde_json::to_vec(&exact).unwrap(), &subject).is_ok());
    }
    for key in ["ldhName", "objectClassName", "events"] {
        let mut record = captured.clone();
        record.as_object_mut().unwrap().remove(key);
        assert!(rdap_registration(&serde_json::to_vec(&record).unwrap(), &subject).is_err());
    }
    assert!(
        rdap_registration(
            bytes,
            &Subject::Ip {
                address: "192.0.2.1".parse().unwrap()
            }
        )
        .is_err()
    );
}
