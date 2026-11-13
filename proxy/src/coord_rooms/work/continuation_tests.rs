use super::*;

fn setup() -> (tempfile::TempDir, Connection) {
    let root = fixture();
    let conn = db(&root);
    for id in ["carol", "dave"] {
        conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-owned','agent',?1,'send,receive',1)", [id]).unwrap();
    }
    (root, conn)
}

fn completed(conn: &mut Connection) -> Value {
    let work = submit(
        conn,
        Actor::Agent("carol"),
        json!({"action":"create", "title":"Retained investigation", "assignee":principal("alice")}),
        "create",
    )
    .unwrap()["work"]
        .clone();
    let work =
        change(conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = publish(conn, &work, "report-r1");
    change(conn, Actor::Agent("alice"), "complete", &work, "complete").unwrap()["work"].clone()
}

fn continuation(work: &Value) -> Value {
    let mut value = input(work, "continue");
    value["reason"] = json!("Address the recorded evidence gap using the new observation");
    value["evidence_refs"] = json!(["signal:existing-unmet-need", "artifact:new-observation"]);
    value
}

fn actionable(conn: &mut Connection, work: &Value, who: &str, received: bool) -> Vec<Value> {
    actions::read(
        conn,
        "owned",
        Actor::Agent(who),
        work["work_id"].as_str().unwrap(),
        received,
    )
    .unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["requires_action"] == true && a["work_id"] == work["work_id"])
        .cloned()
        .collect()
}

#[test]
fn ordinary_continuation_preserves_output_acceptance_and_context_until_replacement() {
    let (root, mut conn) = setup();
    let work = completed(&mut conn);
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, &[], &[]),
        "requirements",
    )
    .unwrap()["work"]
        .clone();
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "accept-r1",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let continuation_input = continuation(&work);
    let receipt = submit(
        &mut conn,
        Actor::Agent("carol"),
        continuation_input.clone(),
        "continue-r1",
    )
    .unwrap();
    let next = &receipt["work"];
    assert_eq!(next["state"], "claimed");
    assert_eq!(next["claim_generation"], 2);
    for field in [
        "work_id",
        "assignee",
        "claim_agent_id",
        "output",
        "target_ref",
        "target_generation",
        "acceptance_decisions",
    ] {
        assert_eq!(next[field], work[field], "preserve {field}");
    }
    assert_eq!(next["continuation"]["author"], principal("carol"));
    assert_eq!(next["continuation"]["participant"], principal("alice"));
    assert_eq!(
        next["continuation"]["evidence_refs"],
        continuation_input["evidence_refs"]
    );
    assert_eq!(
        next["continuation"]["previous_work_version"],
        work["version"]
    );
    assert_eq!(receipt["operation_id"], "continue-r1");
    assert_eq!(
        current_work(&mut conn, next)["acceptance_status"]["state"],
        "accepted"
    );
    let before = counts(&conn);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            continuation_input.clone(),
            "continue-r1"
        )
        .unwrap(),
        receipt
    );
    assert_eq!(counts(&conn), before);
    let mut changed = continuation_input.clone();
    changed["reason"] = json!("Different input under the same ID");
    assert_eq!(
        submit(&mut conn, Actor::Agent("carol"), changed, "continue-r1")
            .unwrap_err()
            .0,
        409
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            continuation(next),
            "duplicate-active"
        )
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "complete",
            &work,
            "stale-completion"
        )
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(
        read_at_version(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            work["work_id"].as_str().unwrap(),
            work["version"].as_i64().unwrap()
        )
        .unwrap(),
        work
    );
    let action = actionable(&mut conn, next, "alice", false).remove(0);
    mutate(None, &mut conn, "owned", Actor::Agent("alice"), serde_json::from_value(json!({"action":"receive_action", "work_id":next["work_id"], "action_key":action["key"]})).unwrap(), None).unwrap();
    drop(conn);
    let mut conn = db(&root);
    assert!(actionable(&mut conn, next, "alice", false).is_empty());
    assert_eq!(
        actionable(&mut conn, next, "alice", true)[0]["key"],
        action["key"]
    );
    assert_eq!(current_work(&mut conn, next)["state"], "claimed");
    let next = publish(&mut conn, next, "report-r2");
    assert_eq!(
        current_work(&mut conn, &next)["acceptance_status"]["decisions"][0]["stale_reason"],
        "output_changed"
    );
    let done = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &next,
        "finish-r2",
    )
    .unwrap()["work"]
        .clone();
    assert!(actionable(&mut conn, &done, "alice", true).is_empty());
    assert_ne!(
        current_work(&mut conn, &done)["acceptance_status"]["state"],
        "accepted"
    );
    let next = submit(
        &mut conn,
        Actor::Agent("carol"),
        continuation(&done),
        "investigate-new-input",
    )
    .unwrap()["work"]
        .clone();
    let mut blocked = input(&next, "publish_output");
    blocked["expected_target_generation"] = next["target_generation"].clone();
    blocked["target_ref"] = json!("artifact:retained-unmet-need");
    blocked["execution_outcome"] = json!("uncertain");
    blocked["summary"] = json!("The new observation still cannot establish the finding");
    blocked["evidence_refs"] = json!(["signal:existing-unmet-need"]);
    let blocked = submit(
        &mut conn,
        Actor::Agent("alice"),
        blocked,
        "publish-uncertainty",
    )
    .unwrap()["work"]
        .clone();
    let done = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &blocked,
        "finish-uncertain",
    )
    .unwrap()["work"]
        .clone();
    assert!(actionable(&mut conn, &done, "alice", true).is_empty());
    let current = current_work(&mut conn, &done);
    assert_eq!(current["output"]["execution_outcome"], "uncertain");
    assert_eq!(current["acceptance_status"]["state"], "pending");
}

#[test]
fn required_check_renewal_is_pending_and_old_approval_never_revives() {
    let (_root, mut conn) = setup();
    let work = completed(&mut conn);
    // Dave requests the check but Carol alone receives amendment authority.
    let check = submit(&mut conn, Actor::Agent("dave"), json!({"action":"request_check", "subject":{"kind":"output", "work_id":work["work_id"], "target_generation":1}, "criterion":"Check the retained finding", "reviewer":principal("bob"), "independent":true}), "request").unwrap()["work"].clone();
    let check = change(
        &mut conn,
        Actor::Agent("bob"),
        "claim",
        &check,
        "review-claim",
    )
    .unwrap()["work"]
        .clone();
    let check = answer(&mut conn, &check, "approve", "answer-r1");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, std::slice::from_ref(&check), &[]),
        "select",
    )
    .unwrap()["work"]
        .clone();
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "accept-r1",
    )
    .unwrap()["work"]
        .clone();
    let input = continuation(&check);
    for who in ["alice", "bob", "dave"] {
        assert_eq!(
            submit(
                &mut conn,
                Actor::Agent(who),
                input.clone(),
                &format!("forbidden-{who}")
            )
            .unwrap_err()
            .0,
            403
        );
    }
    let next =
        submit(&mut conn, Actor::Agent("carol"), input, "renew-check").unwrap()["work"].clone();
    assert_eq!(
        next["check"], check["check"],
        "subject, reviewer and historical answer survive"
    );
    let current = current_work(&mut conn, &next);
    assert_eq!(current["review_status"]["state"], "pending");
    let status = current_work(&mut conn, &work)["acceptance_status"].clone();
    assert_eq!(status["obligations"][0]["status"], "pending_check");
    assert_eq!(
        status["decisions"][0]["stale_reason"],
        "required_review_changed"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&work, "approve"),
            "early-reaccept"
        )
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("bob"),
            "complete",
            &next,
            "wrong-settlement"
        )
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(
        actionable(&mut conn, &next, "bob", true)[0]["kind"],
        "answer_check"
    );
    let answered = answer(&mut conn, &next, "approve", "answer-r1-again");
    assert_eq!(answered["check"]["answer"]["claim_generation"], 2);
    let current = current_work(&mut conn, &work);
    assert_eq!(current["acceptance_status"]["state"], "pending");
    assert_eq!(
        current["acceptance_status"]["obligations"][0]["status"],
        "satisfied"
    );
    assert_eq!(
        current["acceptance_status"]["decisions"][0]["stale_reason"],
        "required_review_changed"
    );
    submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "fresh-acceptance",
    )
    .unwrap();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let historical = read_at_version(
        &mut conn,
        "owned",
        Actor::Agent("bob"),
        check["work_id"].as_str().unwrap(),
        check["version"].as_i64().unwrap(),
    )
    .unwrap();
    assert_eq!(historical["check"]["answer"], check["check"]["answer"]);
}

#[test]
fn continuation_uses_current_authority_and_retained_participant_without_reassignment() {
    let (_root, mut conn) = setup();
    let work = completed(&mut conn);
    for who in ["alice", "bob"] {
        assert_eq!(
            submit(
                &mut conn,
                Actor::Agent(who),
                continuation(&work),
                &format!("not-creator-{who}")
            )
            .unwrap_err()
            .0,
            403
        );
    }
    let check = request(&mut conn, &work, "advisory");
    let check = answer(&mut conn, &check, "abstain", "missing-input");
    // A former authority loses the ability to renew a now-required check.
    let mut selection = requirements(&work, std::slice::from_ref(&check), &[]);
    selection["authorities"] = json!([principal("dave")]);
    let work =
        submit(&mut conn, Actor::Agent("carol"), selection, "delegate").unwrap()["work"].clone();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            continuation(&check),
            "former-authority"
        )
        .unwrap_err()
        .0,
        403
    );
    let mut selection = requirements(&work, &[], &[]);
    selection["authorities"] = json!([principal("dave")]);
    submit(&mut conn, Actor::Agent("dave"), selection, "make-advisory").unwrap();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("dave"),
            continuation(&check),
            "not-requester"
        )
        .unwrap_err()
        .0,
        403
    );
    let next = submit(
        &mut conn,
        Actor::Agent("carol"),
        continuation(&check),
        "requester-renews",
    )
    .unwrap()["work"]
        .clone();
    let done = answer(&mut conn, &next, "abstain", "still-missing-input");
    assert!(actionable(&mut conn, &done, "bob", true).is_empty());
    assert_eq!(current_work(&mut conn, &done)["state"], "done");
    // Revocation is checked for the caller and retained recipient at commit.
    conn.execute(
        "UPDATE memberships SET permissions='receive' WHERE principal_id='carol'",
        [],
    )
    .unwrap();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            continuation(&done),
            "revoked-caller"
        )
        .unwrap_err()
        .0,
        403
    );
    conn.execute(
        "UPDATE memberships SET permissions='receive' WHERE principal_id='bob'",
        [],
    )
    .unwrap();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Operator,
            continuation(&done),
            "revoked-recipient"
        )
        .unwrap_err()
        .0,
        403
    );
}

#[test]
fn continuation_rejects_invalid_state_inputs_and_recipient_substitution() {
    let (_root, mut conn) = setup();
    let work = completed(&mut conn);
    let valid = continuation(&work);
    for field in ["agent_id", "assignee", "reviewer", "participant", "author"] {
        let mut value = valid.clone();
        value[field] = principal("bob");
        assert!(serde_json::from_value::<Mutation>(value).is_err());
    }
    assert_eq!(
        mutate(
            None,
            &mut conn,
            "owned",
            Actor::Operator,
            serde_json::from_value(valid.clone()).unwrap(),
            None
        )
        .unwrap_err()
        .0,
        400
    );
    for (field, field_value) in [
        ("reason", json!(" ")),
        ("reason", json!("x".repeat(1025))),
        ("evidence_refs", json!([])),
        ("evidence_refs", json!([" "])),
        ("evidence_refs", json!(["x".repeat(1025)])),
        ("evidence_refs", json!(vec!["ref"; 17])),
        ("expected_version", json!(1)),
        ("expected_generation", json!(0)),
    ] {
        let mut value = valid.clone();
        value[field] = field_value;
        // Each invalid mutation must leave every canonical store unchanged.
        let before = counts(&conn);
        let error = submit(&mut conn, Actor::Operator, value, "invalid").unwrap_err();
        assert!([400, 409].contains(&error.0));
        assert_eq!(counts(&conn), before);
    }
    let unassigned = submit(
        &mut conn,
        Actor::Agent("carol"),
        json!({"action":"create", "title":"Unassigned"}),
        "unassigned",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Operator,
            continuation(&unassigned),
            "unassigned-open"
        )
        .unwrap_err()
        .0,
        409
    );
    let claimed = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &unassigned,
        "unassigned-claim",
    )
    .unwrap()["work"]
        .clone();
    let done = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &claimed,
        "unassigned-done",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Operator,
            continuation(&done),
            "unassigned-done-refused"
        )
        .unwrap_err()
        .0,
        409
    );
    let next = submit(
        &mut conn,
        Actor::Operator,
        continuation(&work),
        "operator-renews",
    )
    .unwrap()["work"]
        .clone();
    let mut cancel = input(&next, "cancel");
    cancel["reason"] = json!("Stop this attempt");
    let cancelled = submit(&mut conn, Actor::Operator, cancel, "cancel").unwrap()["work"].clone();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Operator,
            continuation(&cancelled),
            "cancelled"
        )
        .unwrap_err()
        .0,
        409
    );
    let mut recovery = input(&cancelled, "reassign");
    recovery["agent_id"] = json!("bob");
    let recovered =
        submit(&mut conn, Actor::Operator, recovery, "recover-cancelled").unwrap()["work"].clone();
    assert!(
        recovered["continuation"].is_null(),
        "another assignment must not inherit the previous participant's continuation"
    );
}

#[test]
fn continuation_serializes_races_and_rolls_back_receipt_history_and_attention_together() {
    let (root, mut conn) = setup();
    let work = completed(&mut conn);
    let value = continuation(&work);
    // A failure after the work write cannot leave a half-selected attempt.
    conn.execute_batch("CREATE TRIGGER fail_continuation_receipt BEFORE INSERT ON coord_operations WHEN new.operation_type='coord.work.continue' BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END;").unwrap();
    let before = counts(&conn);
    assert_eq!(
        submit(&mut conn, Actor::Agent("carol"), value.clone(), "renew")
            .unwrap_err()
            .0,
        503
    );
    assert_eq!(counts(&conn), before);
    assert_eq!(canonical_record(current_work(&mut conn, &work)), work);
    conn.execute_batch("DROP TRIGGER fail_continuation_receipt")
        .unwrap();
    drop(conn);
    let barrier = Arc::new(Barrier::new(12));
    let threads: Vec<_> = (0..12)
        .map(|n| {
            let path = root.path().to_path_buf();
            let value = value.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut conn = super::super::super::super::open(&path).unwrap();
                barrier.wait();
                submit(
                    &mut conn,
                    Actor::Agent("carol"),
                    value,
                    &format!("race-{n}"),
                )
                .map_err(|e| e.0)
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| *e == 409)
    );
    let receipt = results.into_iter().find_map(Result::ok).unwrap();
    let mut conn = db(&root);
    let current = current_work(&mut conn, &work);
    assert_eq!(current["claim_generation"], 2);
    assert_eq!(
        current["version"].as_i64().unwrap(),
        work["version"].as_i64().unwrap() + 1
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            value,
            receipt["operation_id"].as_str().unwrap()
        )
        .unwrap(),
        receipt
    );
    assert_eq!(actionable(&mut conn, &current, "alice", false).len(), 1);
}

#[test]
fn continuation_keeps_an_operator_assigned_check_with_the_operator() {
    let (_root, mut conn) = setup();
    let work = completed(&mut conn);
    let check = submit(&mut conn, Actor::Operator, json!({"action":"request_check", "subject":{"kind":"output", "work_id":work["work_id"], "target_generation":1}, "criterion":"Inspect the retained finding", "reviewer":{"kind":"operator", "id":"operator"}, "independent":true}), "operator-check").unwrap()["work"].clone();
    let mut value = input(&check, "answer_check");
    value["verdict"] = json!("abstain");
    value["summary"] = json!("Need a new observation");
    let check =
        submit(&mut conn, Actor::Operator, value, "operator-answer").unwrap()["work"].clone();
    let next = submit(
        &mut conn,
        Actor::Operator,
        continuation(&check),
        "operator-continue",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(next["state"], "open");
    assert!(next["claim_agent_id"].is_null());
    assert_eq!(next["claim_generation"], 1);
    assert_eq!(next["check"], check["check"]);
    let actions = actions::read(
        &mut conn,
        "owned",
        Actor::Operator,
        next["work_id"].as_str().unwrap(),
        true,
    )
    .unwrap();
    assert!(
        actions["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["kind"] == "answer_check" && a["requires_action"] == true)
    );
    let mut value = input(&next, "answer_check");
    value["verdict"] = json!("approve");
    value["summary"] = json!("Inspected the new observation");
    let answered =
        submit(&mut conn, Actor::Operator, value, "operator-reanswer").unwrap()["work"].clone();
    assert_eq!(answered["state"], "done");
    assert_eq!(answered["check"]["answer"]["claim_generation"], 1);
}
