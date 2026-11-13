use super::*;

#[path = "selection_tests.rs"]
mod selection_tests;

fn principal(id: &str) -> Value {
    json!({"kind":"agent","id":id})
}
fn submit(
    conn: &mut Connection,
    actor: Actor<'_>,
    input: Value,
    op: &str,
) -> Result<Value, WorkError> {
    mutate(
        None,
        conn,
        "owned",
        actor,
        serde_json::from_value(input).unwrap(),
        Some(op),
    )
}
fn current_work(conn: &mut Connection, work: &Value) -> Value {
    read(
        conn,
        "owned",
        Actor::Agent("carol"),
        work["work_id"].as_str().unwrap(),
    )
    .unwrap()
}
fn input(work: &Value, action: &str) -> Value {
    json!({"action":action,"work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"]})
}
fn requirements(work: &Value, checks: &[Value], challenges: &[Value]) -> Value {
    let mut value = input(work, "set_requirements");
    value["expected_requirements_version"] = json!(
        work["acceptance_requirements"]["version"]
            .as_i64()
            .unwrap_or(0)
    );
    value["authorities"] = json!([principal("carol")]);
    value["deciders"] = json!([principal("bob"), principal("carol")]);
    value["independent"] = json!(true);
    value["checks"] = checks
        .iter()
        .map(|w| json!({"work_id":w["work_id"],"version":w["version"]}))
        .collect();
    value["challenges"] = challenges
        .iter()
        .map(|w| json!({"work_id":w["work_id"],"version":w["version"]}))
        .collect();
    value["reason"] = json!("Select independent verification of the requested outcome");
    value
}
fn decide(work: &Value, verdict: &str) -> Value {
    let mut value = input(work, "decide_acceptance");
    value["expected_requirements_version"] = work["acceptance_requirements"]["version"].clone();
    value["expected_target_generation"] = work["target_generation"].clone();
    value["verdict"] = json!(verdict);
    value["summary"] = json!("Inspected the exact output and selected obligations");
    value
}
fn publish(conn: &mut Connection, work: &Value, op: &str) -> Value {
    let mut value = input(work, "publish_output");
    value["expected_target_generation"] = work["target_generation"].clone();
    value["target_ref"] = json!(format!("artifact:immutable:{op}"));
    value["execution_outcome"] = json!("succeeded");
    value["summary"] = json!("Artifact retained before publication");
    submit(conn, Actor::Agent("alice"), value, op).unwrap()["work"].clone()
}
fn answer(conn: &mut Connection, check: &Value, verdict: &str, op: &str) -> Value {
    let mut value = input(check, "answer_check");
    value["verdict"] = json!(verdict);
    value["summary"] = json!("Observed the exact subject");
    submit(conn, Actor::Agent("bob"), value, op).unwrap()["work"].clone()
}
fn request(conn: &mut Connection, work: &Value, op: &str) -> Value {
    let review = submit(conn, Actor::Agent("carol"), json!({"action":"request_check",
        "subject":{"kind":"output","work_id":work["work_id"],"target_generation":work["target_generation"]},
        "criterion":"Artifact includes required result","reviewer":principal("bob"),"independent":true}), op).unwrap()["work"].clone();
    change(
        conn,
        Actor::Agent("bob"),
        "claim",
        &review,
        &format!("{op}-claim"),
    )
    .unwrap()["work"]
        .clone()
}
fn fixture_output() -> (tempfile::TempDir, Connection, Value) {
    let root = fixture();
    let mut conn = db(&root);
    conn.execute(
        "INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-owned','agent','carol','send,receive',1)",
        [],
    )
    .unwrap();
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        json!({"action":"create","title":"Independent output acceptance"}),
        "create",
    )
    .unwrap()["work"]
        .clone();
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, &[], &[]),
        "select-policy",
    )
    .unwrap()["work"]
        .clone();
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = publish(&mut conn, &work, "first-output");
    (root, conn, work)
}

#[test]
fn required_checks_gate_acceptance_but_execution_and_advisory_attestations_remain_separate() {
    let (root, mut conn, work) = fixture_output();
    let check = request(&mut conn, &work, "check");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, std::slice::from_ref(&check), &[]),
        "require-check",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&work, "approve"),
            "early-approval"
        )
        .unwrap_err()
        .0,
        409
    );
    let work = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &work,
        "execution-finished",
    )
    .unwrap()["work"]
        .clone();
    let check = answer(&mut conn, &check, "reject", "reject");
    let current = current_work(&mut conn, &work);
    assert_eq!(current["state"], "done");
    assert_eq!(
        current["acceptance_status"]["obligations"][0]["status"],
        "rejected_check"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&current, "approve"),
            "bypass-rejection"
        )
        .unwrap_err()
        .0,
        409
    );
    let attested = submit(&mut conn,Actor::Agent("alice"),json!({"action":"attest","work_id":work["work_id"],"target_generation":1,"kind":"acceptance","verdict":"approve","summary":"Producer's advisory claim"}),"advisory-approval").unwrap()["work"].clone();
    assert_eq!(
        current_work(&mut conn, &attested)["acceptance_status"]["state"],
        "pending"
    );
    let check = answer(&mut conn, &check, "approve", "correct-check");
    let approved = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&attested, "approve"),
        "accept",
    )
    .unwrap();
    assert_eq!(
        current_work(&mut conn, &approved["work"])["acceptance_status"]["state"],
        "accepted"
    );
    // Unselected rejection never becomes a hidden gate.
    let advisory = request(&mut conn, &work, "advisory");
    answer(&mut conn, &advisory, "reject", "advisory-reject");
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let corrected = answer(&mut conn, &check, "reject", "later-defect");
    let current = current_work(&mut conn, &work);
    assert_eq!(current["acceptance_status"]["state"], "pending");
    assert_eq!(
        current["acceptance_status"]["decisions"][0]["stale_reason"],
        "required_review_changed"
    );
    answer(&mut conn, &corrected, "approve", "repair-check");
    // Repaired review does not resurrect the old approval.
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "pending"
    );
    drop(conn);
    let mut conn = db(&root);
    let current = current_work(&mut conn, &work);
    let accepted = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&current, "approve"),
        "accept-repair",
    )
    .unwrap();
    assert_eq!(
        current_work(&mut conn, &accepted["work"])["acceptance_status"]["state"],
        "accepted"
    );
    let historic = read_at_version(
        &mut conn,
        "owned",
        Actor::Agent("carol"),
        work["work_id"].as_str().unwrap(),
        approved["work"]["version"].as_i64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        historic["acceptance_decisions"][0]["work_version"],
        approved["work"]["version"]
    );
}

#[test]
fn requirement_authority_independence_recovery_and_changed_definitions_are_enforced() {
    let (_root, mut conn, work) = fixture_output();
    let before = counts(&conn);
    let mut relaxed = requirements(&work, &[], &[]);
    relaxed["independent"] = json!(false);
    relaxed["authorities"] = json!([principal("alice")]);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            relaxed.clone(),
            "worker-relax"
        )
        .unwrap_err()
        .0,
        403
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            relaxed.clone(),
            "decider-is-not-authority"
        )
        .unwrap_err()
        .0,
        403
    );
    assert_eq!(counts(&conn), before);
    let mut selected = requirements(&work, &[], &[]);
    selected["deciders"] = json!([principal("alice")]);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            selected,
            "self-independent"
        )
        .unwrap_err()
        .0,
        403
    );
    // The operator can explicitly delegate policy authority to a worker.
    // Ownership alone never grants that authority; an explicit delegation does.
    let next = submit(
        &mut conn,
        Actor::Operator,
        relaxed.clone(),
        "recover-authority",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            requirements(&next, &[], &[]),
            "removed-authority"
        )
        .unwrap_err()
        .0,
        403
    );
    let delegated = submit(
        &mut conn,
        Actor::Agent("alice"),
        requirements(&next, &[], &[]),
        "explicitly-delegated-worker-policy",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        delegated["acceptance_requirements"]["author"],
        principal("alice")
    );
    assert_eq!(delegated["acceptance_requirements"]["version"], 3);
    let restored = submit(
        &mut conn,
        Actor::Operator,
        requirements(&delegated, &[], &[]),
        "restore-policy",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        submit(&mut conn, Actor::Operator, relaxed, "stale-policy")
            .unwrap_err()
            .0,
        409
    );
    let check = request(&mut conn, &restored, "selected-check");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&restored, std::slice::from_ref(&check), &[]),
        "require",
    )
    .unwrap()["work"]
        .clone();
    let reassigned = submit(
        &mut conn,
        Actor::Operator,
        {
            let mut value = input(&check, "reassign");
            value["agent_id"] = json!("carol");
            value
        },
        "recover-check",
    )
    .unwrap()["work"]
        .clone();
    let mut value = input(&reassigned, "answer_check");
    value["verdict"] = json!("approve");
    value["summary"] = json!("New reviewer");
    submit(&mut conn, Actor::Agent("carol"), value, "new-answer").unwrap();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["obligations"][0]["status"],
        "assignment_changed"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&work, "approve"),
            "changed-reviewer"
        )
        .unwrap_err()
        .0,
        409
    );
    // Reassignment does not relabel the original producer for independence.
    let mut reassign = input(&work, "reassign");
    reassign["agent_id"] = json!("bob");
    let integrated =
        submit(&mut conn, Actor::Operator, reassign, "integrate").unwrap()["work"].clone();
    let mut forged = requirements(&integrated, &[], &[]);
    forged["deciders"] = json!([principal("alice")]);
    assert_eq!(
        submit(&mut conn, Actor::Operator, forged, "bridge-is-not-producer")
            .unwrap_err()
            .0,
        403
    );
}

#[test]
fn conflicting_decisions_need_explicit_correction_and_retries_do_not_reset_current_state() {
    let (_root, mut conn, work) = fixture_output();
    let original = decide(&work, "approve");
    let accepted = submit(&mut conn, Actor::Agent("bob"), original.clone(), "accept").unwrap();
    let rejected = submit(
        &mut conn,
        Actor::Agent("carol"),
        decide(&accepted["work"], "reject"),
        "reject",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "conflicting"
    );
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), original.clone(), "accept").unwrap(),
        accepted
    );
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "conflicting"
    );
    let corrected = submit(
        &mut conn,
        Actor::Agent("carol"),
        decide(&rejected, "approve"),
        "correct-decision",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        corrected["acceptance_decisions"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let changed = publish(&mut conn, &corrected, "correct-output");
    let status = current_work(&mut conn, &work)["acceptance_status"].clone();
    assert_eq!(status["state"], "pending");
    assert!(
        status["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["stale_reason"] == "output_changed")
    );
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), original, "accept").unwrap(),
        accepted
    );
    assert_eq!(current_work(&mut conn, &work)["target_generation"], 2);
    let selected = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&changed, &[], &[]),
        "amend",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["decisions"][0]["stale_reason"],
        "requirements_changed"
    );
    let mut stale = decide(&selected, "approve");
    stale["expected_target_generation"] = json!(1);
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), stale, "old-output-approve")
            .unwrap_err()
            .0,
        409
    );
    let mut forged = decide(&selected, "approve");
    forged["author"] = principal("carol");
    assert!(serde_json::from_value::<Mutation>(forged).is_err());
    let mut recovery = requirements(&selected, &[], &[]);
    recovery["deciders"] = json!([principal("bob")]);
    let recovered = submit(
        &mut conn,
        Actor::Agent("carol"),
        recovery,
        "recover-decider",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        recovered["acceptance_decisions"].as_array().unwrap().len(),
        1
    );
    let history = read_at_version(
        &mut conn,
        "owned",
        Actor::Agent("carol"),
        selected["work_id"].as_str().unwrap(),
        selected["version"].as_i64().unwrap(),
    )
    .unwrap();
    assert_eq!(history["acceptance_decisions"].as_array().unwrap().len(), 2);
    let recovered = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&recovered, "approve"),
        "recovered-decision",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &recovered)["acceptance_status"]["state"],
        "accepted"
    );
}

#[test]
fn selected_challenges_survive_correction_until_explicit_disposition() {
    let (_root, mut conn, work) = fixture_output();
    let challenge = submit(&mut conn,Actor::Agent("bob"),json!({"action":"raise_challenge",
        "subject":{"kind":"output","work_id":work["work_id"],"target_generation":1},
        "assertion":"Result is missing","grounds":"Inspected artifact","responder":principal("alice"),
        "deciders":[principal("bob")],"independent":true}),"raise").unwrap()["work"].clone();
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, &[], std::slice::from_ref(&challenge)),
        "require-objection",
    )
    .unwrap()["work"]
        .clone();
    let challenge = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &challenge,
        "respond-claim",
    )
    .unwrap()["work"]
        .clone();
    let output = publish(&mut conn, &work, "retained-correction");
    let mut response = input(&challenge, "respond_challenge");
    response["summary"] = json!("Retained correction");
    response["correction"] =
        json!({"kind":"output","work_id":work["work_id"],"target_generation":2});
    let challenge =
        submit(&mut conn, Actor::Agent("alice"), response, "response").unwrap()["work"].clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["obligations"][0]["status"],
        "unresolved_challenge"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&output, "approve"),
            "repair-is-not-acceptance"
        )
        .unwrap_err()
        .0,
        409
    );
    let mut disposition = input(&challenge, "resolve_challenge");
    disposition["expected_response_version"] =
        challenge["challenge"]["response"]["work_version"].clone();
    disposition["decision"] = json!("upheld");
    disposition["reason"] = json!("Original omission confirmed; corrected output inspected");
    let challenge =
        submit(&mut conn, Actor::Agent("bob"), disposition, "uphold").unwrap()["work"].clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["obligations"][0]["status"],
        "satisfied"
    );
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["obligations"][0]["disposition"],
        "upheld"
    );
    let output = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&output, "approve"),
        "accept-with-explicit-disposition",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &output)["acceptance_status"]["state"],
        "accepted"
    );
    let mut disposition = input(&challenge, "resolve_challenge");
    disposition["expected_response_version"] =
        challenge["challenge"]["response"]["work_version"].clone();
    disposition["decision"] = json!("dismissed");
    disposition["reason"] = json!("Verified exact correction");
    let challenge =
        submit(&mut conn, Actor::Agent("bob"), disposition, "dispose").unwrap()["work"].clone();
    assert_eq!(
        current_work(&mut conn, &output)["acceptance_status"]["state"],
        "pending"
    );
    let accepted = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&output, "approve"),
        "accept-correction",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let mut recovery = input(&challenge, "recover_challenge_deciders");
    recovery["deciders"] = json!([principal("carol")]);
    recovery["reason"] = json!("Replace the unavailable deciding participant");
    let challenge = submit(
        &mut conn,
        Actor::Operator,
        recovery,
        "recover-challenge-decider",
    )
    .unwrap()["work"]
        .clone();
    let selected = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&accepted, &[], std::slice::from_ref(&challenge)),
        "select-recovered-challenge",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &selected)["acceptance_status"]["obligations"][0]["status"],
        "disposition_author_changed"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&selected, "approve"),
            "old-decider-disposition"
        )
        .unwrap_err()
        .0,
        409
    );
    let mut disposition = input(&challenge, "resolve_challenge");
    disposition["expected_response_version"] =
        challenge["challenge"]["response"]["work_version"].clone();
    disposition["decision"] = json!("dismissed");
    disposition["reason"] = json!("Replacement decider independently verified the correction");
    let challenge = submit(
        &mut conn,
        Actor::Agent("carol"),
        disposition,
        "replacement-disposition",
    )
    .unwrap()["work"]
        .clone();
    let accepted = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&selected, "approve"),
        "accept-recovered-review",
    )
    .unwrap()["work"]
        .clone();
    let mut response = input(&challenge, "respond_challenge");
    response["summary"] = json!("Correct the evidence");
    submit(
        &mut conn,
        Actor::Agent("alice"),
        response,
        "response-correction",
    )
    .unwrap();
    let current = current_work(&mut conn, &accepted);
    assert_eq!(current["acceptance_status"]["state"], "pending");
    assert_eq!(
        current["acceptance_status"]["obligations"][0]["status"],
        "unresolved_challenge"
    );
}

#[test]
fn acceptance_writes_serialize_and_rollback_with_history_receipts_and_attention() {
    for table in [
        "coord_work_revisions",
        "coord_work",
        "coord_operations",
        "coord_attention_edges",
        "coord_outbox",
    ] {
        let (_root, mut conn, work) = fixture_output();
        let before = counts(&conn);
        conn.execute_batch(&format!("CREATE TRIGGER fail BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
        assert!(
            submit(
                &mut conn,
                Actor::Agent("bob"),
                decide(&work, "approve"),
                "decision"
            )
            .is_err()
        );
        assert_eq!(counts(&conn), before);
        assert!(
            current_work(&mut conn, &work)["acceptance_decisions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        conn.execute_batch("DROP TRIGGER fail").unwrap();
        assert!(
            submit(
                &mut conn,
                Actor::Agent("bob"),
                decide(&work, "approve"),
                "decision"
            )
            .is_ok()
        );
    }
    let (root, mut conn, work) = fixture_output();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [decide(&work, "approve"), requirements(&work, &[], &[])]
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let root = root.path().to_owned();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut conn = super::super::super::open(&root).unwrap();
                barrier.wait();
                submit(
                    &mut conn,
                    Actor::Agent(if index == 0 { "bob" } else { "carol" }),
                    value,
                    &format!("race-{index}"),
                )
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results.iter().find_map(|r| r.as_ref().err()).unwrap().0,
        409
    );
    let current = current_work(&mut conn, &work);
    assert!(
        current["acceptance_status"]["state"] == "accepted"
            || current["acceptance_status"]["state"] == "pending"
    );
}

#[test]
fn nested_review_requirements_bind_the_original_output_and_selection_cannot_be_forged() {
    let (_root, mut conn, work) = fixture_output();
    let check = request(&mut conn, &work, "first-check");
    let check = answer(&mut conn, &check, "approve", "first-answer");
    let nested = submit(&mut conn, Actor::Agent("bob"), json!({"action":"request_check",
        "subject":{"kind":"check","work_id":check["work_id"],"version":check["version"]},
        "criterion":"Verify the first check considered the retained evidence", "reviewer":principal("carol"),"independent":true}), "nested-check").unwrap()["work"].clone();
    let claimed = change(
        &mut conn,
        Actor::Agent("carol"),
        "claim",
        &nested,
        "claim-nested",
    )
    .unwrap()["work"]
        .clone();
    let mut stale = requirements(&work, std::slice::from_ref(&nested), &[]);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            stale.clone(),
            "stale-selection"
        )
        .unwrap_err()
        .0,
        409
    );
    stale["checks"][0]["reviewer"] = principal("bob");
    assert!(serde_json::from_value::<Mutation>(stale).is_err());
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, std::slice::from_ref(&claimed), &[]),
        "select-nested",
    )
    .unwrap()["work"]
        .clone();
    let mut value = input(&claimed, "answer_check");
    value["verdict"] = json!("approve");
    value["summary"] = json!("Inspected the first check and its original artifact");
    submit(&mut conn, Actor::Agent("carol"), value, "answer-nested").unwrap();
    let accepted = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "accept-nested",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let replaced = publish(&mut conn, &accepted, "replace-nested-output");
    assert_eq!(
        current_work(&mut conn, &replaced)["acceptance_status"]["obligations"][0]["status"],
        "stale_subject"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&replaced, "approve"),
            "bypass-nested-version"
        )
        .unwrap_err()
        .0,
        409
    );
}

#[test]
fn unselected_work_and_explicit_nonindependent_policy_do_not_gain_universal_gates() {
    let root = fixture();
    let mut conn = db(&root);
    let work = create(&mut conn)["work"].clone();
    let current = read(
        &mut conn,
        "owned",
        Actor::Operator,
        work["work_id"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(current["acceptance_status"]["state"], "not_selected");
    let mut initial = requirements(&work, &[], &[]);
    initial["authorities"] = json!([]);
    initial["deciders"] = json!([principal("alice")]);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            initial.clone(),
            "noncreator-policy"
        )
        .unwrap_err()
        .0,
        403
    );
    let work = submit(
        &mut conn,
        Actor::Operator,
        initial,
        "independent-before-producer",
    )
    .unwrap()["work"]
        .clone();
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = publish(&mut conn, &work, "produced");
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            decide(&work, "approve"),
            "self-review"
        )
        .unwrap_err()
        .0,
        403
    );
    // A required producer-run deterministic check can be paired with an
    // independently attributed acceptance decision; it needs no extra agent.
    let check=submit(&mut conn,Actor::Agent("bob"),json!({"action":"request_check",
        "subject":{"kind":"output","work_id":work["work_id"],"target_generation":1},
        "criterion":"Run the deterministic artifact check","reviewer":principal("alice"),"independent":false}),"producer-check").unwrap()["work"].clone();
    let check = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &check,
        "claim-producer-check",
    )
    .unwrap()["work"]
        .clone();
    let mut answer = input(&check, "answer_check");
    answer["verdict"] = json!("approve");
    answer["summary"] = json!("Deterministic procedure passed");
    let check = submit(
        &mut conn,
        Actor::Agent("alice"),
        answer,
        "producer-check-result",
    )
    .unwrap()["work"]
        .clone();
    let mut mixed = requirements(&work, std::slice::from_ref(&check), &[]);
    mixed["authorities"] = json!([]);
    mixed["deciders"] = json!([principal("bob")]);
    let work = submit(
        &mut conn,
        Actor::Operator,
        mixed,
        "select-independent-acceptance",
    )
    .unwrap()["work"]
        .clone();
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "independent-decision-after-producer-check",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap()
        )
        .unwrap()["acceptance_status"]["state"],
        "accepted"
    );
    let mut explicit = requirements(&work, &[], &[]);
    explicit["authorities"] = json!([]);
    explicit["deciders"] = json!([principal("alice")]);
    explicit["independent"] = json!(false);
    let work = submit(
        &mut conn,
        Actor::Operator,
        explicit,
        "select-nonindependent",
    )
    .unwrap()["work"]
        .clone();
    let work = submit(
        &mut conn,
        Actor::Agent("alice"),
        decide(&work, "approve"),
        "permitted-decision",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap()
        )
        .unwrap()["acceptance_status"]["state"],
        "accepted"
    );
    let mut cancel = input(&work, "cancel");
    cancel["reason"] = json!("This assignment was cancelled");
    let work = submit(&mut conn, Actor::Agent("alice"), cancel, "cancel").unwrap()["work"].clone();
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap()
        )
        .unwrap()["acceptance_status"]["state"],
        "accepted"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            decide(&work, "approve"),
            "cancelled-acceptance"
        )
        .unwrap()["work"]["state"],
        "cancelled"
    );
}

#[test]
fn a_checkers_report_with_the_same_generation_cannot_substitute_for_the_parent_output() {
    let (_root, mut conn, work) = fixture_output();
    let check = request(&mut conn, &work, "check-output");
    let check = answer(&mut conn, &check, "approve", "answer-output");
    let mut publication = input(&check, "publish_output");
    publication["expected_target_generation"] = json!(0);
    publication["target_ref"] = json!("report:immutable:checker");
    publication["execution_outcome"] = json!("succeeded");
    publication["summary"] = json!("Retained checker report");
    let report = submit(
        &mut conn,
        Actor::Agent("bob"),
        publication,
        "checker-report",
    )
    .unwrap()["work"]
        .clone();
    let check_report = submit(
        &mut conn,
        Actor::Agent("bob"),
        json!({"action":"request_check",
        "subject":{"kind":"output","work_id":report["work_id"],"target_generation":1},
        "criterion":"Verify the checker report","reviewer":principal("carol"),"independent":true}),
        "review-report",
    )
    .unwrap()["work"]
        .clone();
    let checking = change(
        &mut conn,
        Actor::Agent("carol"),
        "claim",
        &check_report,
        "claim-report",
    )
    .unwrap()["work"]
        .clone();
    let mut value = input(&checking, "answer_check");
    value["verdict"] = json!("approve");
    value["summary"] = json!("Verified checker report");
    let verified =
        submit(&mut conn, Actor::Agent("carol"), value, "verified-report").unwrap()["work"].clone();
    let parent = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, std::slice::from_ref(&verified), &[]),
        "require-related",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &parent)["acceptance_status"]["obligations"][0]["status"],
        "stale_subject"
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&parent, "approve"),
            "substitute-report"
        )
        .unwrap_err()
        .0,
        409
    );
    // The same check is applicable when acceptance actually concerns that report.
    let mut selected = requirements(&report, std::slice::from_ref(&verified), &[]);
    selected["deciders"] = json!([principal("carol")]);
    let report =
        submit(&mut conn, Actor::Agent("carol"), selected, "select-report").unwrap()["work"]
            .clone();
    let report = submit(
        &mut conn,
        Actor::Agent("carol"),
        decide(&report, "approve"),
        "accept-report",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &report)["acceptance_status"]["state"],
        "accepted"
    );
}
