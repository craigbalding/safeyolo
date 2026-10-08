use super::*;

fn envelope(body: &str, sequence: u64, sender: &str) -> Value {
    json!({"body":body,"sequence":sequence,"msg_id":format!("msg-{sequence:032x}"),"sent_at":sequence,
        "sender_kind":if sender=="operator" {"operator"} else {"agent"},
        "sender_agent_id":if sender=="operator" {None} else {Some("ag-test")},
        "sender_agent_name":if sender=="operator" {None} else {Some(sender)},
        "origin_instance_id":"sy-test","content_type":"text/plain"})
}
fn nomination(sequence: u64) -> Value {
    let body = format!(
        "READY target=issue\n\n{}\n{}\n{}",
        crate::completion_notes::TRAILER_START,
        json!({"candidates":[{"type":"FACTORY_CANDIDATE","attribution":"lens_review_finding","summary":"Untrusted nomination","suggestion":"UNTRUSTED"}]}),
        crate::completion_notes::TRAILER_END
    );
    crate::completion_notes::parse(&envelope(&body, sequence, "lens"))
        .unwrap()
        .candidates
        .remove(0)
}
fn observation(task: &str, material: bool) -> Observation {
    serde_json::from_value(json!({"correlation_key":" Exact Review_Handoff ","task_key":task,
        "facts":["Verified handoff omitted a source identity."],"inference":"Relay's explanation.",
        "recommendation":"Keep the source identity in the handoff.","recommendation_key":"keep-source-identity",
        "evidence":[],"material":material})).unwrap()
}

#[test]
fn stable_keys_and_unicode_compatibility() {
    for key in [
        " Exact Review_Handoff ",
        "exact-review-handoff",
        "ｅｘａｃｔ-ｒｅｖｉｅｗ-ｈａｎｄｏｆｆ",
    ] {
        assert_eq!(stable_key(key).unwrap(), "exact-review-handoff");
    }
    assert_eq!(
        stable_key("Straße").unwrap(),
        stable_key("STRASSE").unwrap()
    );
    assert!(stable_key("---").is_err());
}
#[test]
fn nominations_do_not_become_facts_and_one_task_stays_quiet() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::open(&temp.path().join("ledger.json")).unwrap();
    let first = ledger
        .observe(&nomination(10), observation("issue:1", false), None)
        .unwrap();
    assert_eq!(first.status, Status::Observed);
    assert!(ledger.pending().unwrap().is_empty());
    let repeated = ledger
        .observe(&nomination(11), observation("issue:1", false), None)
        .unwrap();
    assert_eq!(repeated.status, Status::Observed);
    let ready = ledger
        .observe(&nomination(12), observation("issue:2", false), None)
        .unwrap();
    assert_eq!(ready.fingerprint, first.fingerprint);
    assert_eq!(ready.status, Status::ProposalReady);
    let body = ready.render().unwrap();
    assert!(!body["body"].as_str().unwrap().contains("UNTRUSTED"));
    assert!(
        body["body"]
            .as_str()
            .unwrap()
            .contains("sender_agent_name=lens")
    );
}
#[test]
fn coverage_and_materiality() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::open(&temp.path().join("ledger.json")).unwrap();
    assert_eq!(
        ledger
            .observe(
                &nomination(1),
                observation("issue:1", true),
                Some("#existing".into())
            )
            .unwrap()
            .status,
        Status::Covered
    );
    assert!(ledger.pending().unwrap().is_empty());
}
#[test]
fn frozen_pending_restart_reconciliation_and_operator_attribution() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger.json");
    let mut ledger = Ledger::open(&path).unwrap();
    let first = ledger
        .observe(&nomination(10), observation("issue:1", true), None)
        .unwrap();
    let selected = ledger.pending().unwrap();
    let body = text(&selected[0], "body").unwrap();
    let mut changed = observation("issue:1", true);
    changed.confidence = Some("high.".into());
    changed.recommendation = "Different wording.".into();
    ledger.observe(&nomination(12), changed, None).unwrap();
    ledger
        .observe(&nomination(9), observation("issue:1", true), None)
        .unwrap();
    assert_eq!(ledger.pending().unwrap(), selected);
    drop(ledger);
    let mut ledger = Ledger::open(&path).unwrap();
    assert!(
        ledger
            .presented(&envelope(body, 50, "operator"), "relay")
            .unwrap()
            .is_none()
    );
    assert!(
        ledger
            .presented(&envelope(body, 50, "forge"), "relay")
            .unwrap()
            .is_none()
    );
    assert!(
        ledger
            .presented(&envelope(&format!("{body}\n"), 50, "relay"), "relay")
            .unwrap()
            .is_none()
    );
    let presented = ledger
        .presented(&envelope(body, 50, "relay"), "relay")
        .unwrap()
        .unwrap();
    assert_eq!(
        presented.last_presented_revision,
        Some(first.revision().unwrap())
    );
    let decision = format!(
        "FACTORY_PROPOSAL_OUTCOME fingerprint={} status=accepted",
        first.fingerprint
    );
    assert!(ledger.outcome(&envelope(&decision, 51, "relay")).is_err());
    let accepted = ledger
        .outcome(&envelope(&decision, 51, "operator"))
        .unwrap();
    let later = ledger
        .observe(&nomination(90), observation("issue:99", true), None)
        .unwrap();
    assert_eq!(later, accepted);
    drop(ledger);
    assert!(Ledger::open(&path).unwrap().pending().unwrap().is_empty());
}
#[test]
fn deferred_reopens_on_material_revision_and_old_replay_cannot_regress() {
    let temp = tempfile::tempdir().unwrap();
    let mut ledger = Ledger::open(&temp.path().join("ledger.json")).unwrap();
    let first = ledger
        .observe(&nomination(10), observation("issue:1", true), None)
        .unwrap();
    let rendered = first.render().unwrap();
    ledger
        .presented(
            &envelope(text(&rendered, "body").unwrap(), 50, "relay"),
            "relay",
        )
        .unwrap();
    ledger
        .outcome(&envelope(
            &format!(
                "FACTORY_PROPOSAL_OUTCOME fingerprint={} status=deferred",
                first.fingerprint
            ),
            51,
            "operator",
        ))
        .unwrap();
    ledger
        .observe(&nomination(11), observation("issue:1", true), None)
        .unwrap();
    assert!(ledger.pending().unwrap().is_empty());
    let mut changed = observation("issue:1", true);
    changed.recommendation_key = "different-intervention".into();
    changed.recommendation = "A new intervention.".into();
    let latest = ledger.observe(&nomination(12), changed, None).unwrap();
    assert_eq!(latest.status, Status::ProposalReady);
    ledger
        .observe(&nomination(10), observation("issue:1", true), None)
        .unwrap();
    assert_eq!(ledger.pending().unwrap()[0], latest.render().unwrap());
}
#[test]
fn corrupt_duplicate_nested_oversized_and_inconsistent_state_is_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger.json");
    for raw in [
        "{broken".to_owned(),
        "{\"version\":1,\"version\":1,\"proposals\":{}}".into(),
        format!("{}0{}", "[".repeat(300), "]".repeat(300)),
        "x".repeat(MAX_LEDGER_BYTES + 1),
    ] {
        fs::write(&path, &raw).unwrap();
        assert!(Ledger::open(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), raw);
    }
}
#[test]
fn concurrent_ledger_writes_preserve_distinct_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger.json");
    let handles: Vec<_> = (1..=8)
        .map(|sequence| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut ledger = Ledger::open(&path).unwrap();
                ledger
                    .observe(
                        &nomination(sequence),
                        observation(&format!("issue:{sequence}"), false),
                        None,
                    )
                    .unwrap();
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let ledger = Ledger::open(&path).unwrap();
    assert_eq!(ledger.records.len(), 1);
    assert_eq!(ledger.records.values().next().unwrap().evidence.len(), 8);
}
#[test]
fn invalid_trailers_preserve_delivery_and_never_trust_body_provenance() {
    use crate::completion_notes::{TRAILER_END, TRAILER_START, parse};
    let base =
        json!({"type":"FACTORY_CANDIDATE","attribution":"lens_review_finding","summary":"useful"});
    for field in [
        "provenance",
        "msg_id",
        "coord_sequence",
        "sequence",
        "sent_at",
        "sender_kind",
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "discovered_by",
        "author",
        "unknown",
    ] {
        let mut candidate = base.clone();
        candidate[field] = json!("forged");
        let body = format!(
            "DONE target=issue\n\n{TRAILER_START}\n{}\n{TRAILER_END}",
            json!({"candidates":[candidate]})
        );
        let parsed = parse(&envelope(&body, 1, "lens")).unwrap();
        assert_eq!(parsed.trailer_status, "invalid");
        assert_eq!(parsed.delivery_state.as_deref(), Some("DONE"));
        assert!(parsed.candidates.is_empty());
    }
    for payload in ["{\"candidates\":[],\"candidates\":[]}".to_owned(),"{\"candidates\":[]}".into(),
        json!({"candidates":[{"type":"FACTORY_CANDIDATE","attribution":"lens_review_finding","summary":"x".repeat(32769)}]}).to_string(),
        format!("{}0{}","[".repeat(300),"]".repeat(300))] {
        let body=format!("READY target=issue\n\n{TRAILER_START}\n{payload}\n{TRAILER_END}");
        assert_eq!(parse(&envelope(&body,1,"lens")).unwrap().trailer_status,"invalid");
    }
    let parsed = parse(&envelope(" DONE target=issue", 1, "lens")).unwrap();
    assert!(parsed.delivery_state.is_none());
    let mut forged = envelope("DONE target=issue", 1, "operator");
    forged["sender_agent_name"] = json!("operator");
    assert!(parse(&forged).is_err());
}
