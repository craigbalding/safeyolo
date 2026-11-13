use super::*;

fn selection(work: &Value, review: &Value, kind: &str, replace: Option<&Value>) -> Value {
    let mut value = input(work, "select_review");
    value["expected_requirements_version"] = work["acceptance_requirements"]["version"].clone();
    value["review_kind"] = json!(kind);
    value["review"] = json!({"work_id":review["work_id"],"version":review["version"]});
    if let Some(replace) = replace {
        value["replace_work_id"] = replace["work_id"].clone();
    }
    value["reason"] = json!("Select this review while retaining the remaining acceptance policy");
    value
}

fn challenge(conn: &mut Connection, work: &Value, op: &str) -> Value {
    submit(conn, Actor::Agent("bob"), json!({"action":"raise_challenge",
        "subject":{"kind":"output","work_id":work["work_id"],"target_generation":work["target_generation"]},
        "assertion":"Coverage needs review","grounds":"Inspected retained output",
        "responder":principal("alice"),"deciders":[principal("bob")],"independent":true}), op)
        .unwrap()["work"].clone()
}

#[test]
fn amendment_preserves_unrelated_challenge_and_changed_review_definition_verbatim() {
    let (_root, mut conn, work) = fixture_output();
    let old = request(&mut conn, &work, "old-check");
    let retained = request(&mut conn, &work, "retained-check");
    let objection = challenge(&mut conn, &work, "coverage");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(
            &work,
            &[old.clone(), retained.clone()],
            std::slice::from_ref(&objection),
        ),
        "initial-reviews",
    )
    .unwrap()["work"]
        .clone();
    let before = work["acceptance_requirements"].clone();
    let mut reassign = input(&retained, "reassign");
    reassign["agent_id"] = json!("carol");
    let changed =
        submit(&mut conn, Actor::Operator, reassign, "changed-reviewer").unwrap()["work"].clone();
    let next = request(&mut conn, &work, "corrected-check");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        selection(&work, &next, "check", Some(&old)),
        "replace-check",
    )
    .unwrap()["work"]
        .clone();
    let after = &work["acceptance_requirements"];
    assert_eq!(after["checks"][0]["work_id"], next["work_id"]);
    assert_eq!(after["checks"][1], before["checks"][1]);
    for field in ["challenges", "authorities", "deciders", "independent"] {
        assert_eq!(after[field], before[field], "{field}");
    }
    let current = current_work(&mut conn, &work);
    assert_eq!(
        current["acceptance_status"]["obligations"][1]["status"],
        "assignment_changed"
    );
    assert_eq!(
        current["acceptance_status"]["obligations"][2]["status"],
        "unresolved_challenge"
    );
    assert_eq!(
        after["version"].as_i64(),
        Some(before["version"].as_i64().unwrap() + 1)
    );
    assert_eq!(after["author"], principal("carol"));
    // Only explicit reselection refreshes that same review's stored definition.
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        selection(&work, &changed, "check", Some(&retained)),
        "reselect-changed",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        work["acceptance_requirements"]["checks"][1]["selected_version"],
        changed["version"]
    );
    assert_eq!(
        work["acceptance_requirements"]["challenges"],
        before["challenges"]
    );
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["obligations"][1]["status"],
        "pending_check"
    );
}

#[test]
fn add_and_replace_require_existing_policy_and_actual_amendment_authority() {
    let (_root, mut conn, work) = fixture_output();
    let check = request(&mut conn, &work, "check");
    // Creator, producer/holder and selected decider are not amendment authorities.
    let mut delegated = requirements(&work, &[], &[]);
    delegated["authorities"] = json!([principal("bob")]);
    let work =
        submit(&mut conn, Actor::Agent("carol"), delegated, "delegate").unwrap()["work"].clone();
    for actor in [Actor::Agent("alice"), Actor::Agent("carol")] {
        let before = counts(&conn);
        assert_eq!(
            submit(
                &mut conn,
                actor,
                selection(&work, &check, "check", None),
                "unauthorized"
            )
            .unwrap_err()
            .0,
            403
        );
        assert_eq!(counts(&conn), before);
    }
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        selection(&work, &check, "check", None),
        "add-check",
    )
    .unwrap()["work"]
        .clone();
    let first = challenge(&mut conn, &work, "first-challenge");
    let work = submit(
        &mut conn,
        Actor::Operator,
        selection(&work, &first, "challenge", None),
        "add-challenge",
    )
    .unwrap()["work"]
        .clone();
    let before = work["acceptance_requirements"].clone();
    let next = challenge(&mut conn, &work, "next-challenge");
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        selection(&work, &next, "challenge", Some(&first)),
        "replace-challenge",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(work["acceptance_requirements"]["checks"], before["checks"]);
    assert_eq!(
        work["acceptance_requirements"]["challenges"][0]["work_id"],
        next["work_id"]
    );
    let unselected = submit(
        &mut conn,
        Actor::Agent("carol"),
        json!({"action":"create","title":"No policy yet"}),
        "unselected",
    )
    .unwrap()["work"]
        .clone();
    let mut add = selection(&unselected, &check, "check", None);
    add["expected_requirements_version"] = json!(0);
    for actor in [Actor::Agent("carol"), Actor::Operator] {
        assert_eq!(
            submit(
                &mut conn,
                actor,
                add.clone(),
                "cannot-manufacture-initial-policy"
            )
            .unwrap_err()
            .0,
            400
        );
    }
    assert_eq!(
        current_work(&mut conn, &unselected)["acceptance_requirements"],
        Value::Null
    );
}

#[test]
fn stale_duplicate_wrong_kind_and_unrelated_selections_are_atomic() {
    let (_root, mut conn, work) = fixture_output();
    let old = request(&mut conn, &work, "old");
    let other = request(&mut conn, &work, "other");
    let next = request(&mut conn, &work, "next");
    let objection = challenge(&mut conn, &work, "objection");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        requirements(&work, &[old.clone(), other.clone()], &[]),
        "select-two",
    )
    .unwrap()["work"]
        .clone();
    let base = selection(&work, &next, "check", Some(&old));
    let mut cases = Vec::new();
    for field in [
        "expected_version",
        "expected_generation",
        "expected_requirements_version",
    ] {
        let mut stale = base.clone();
        stale[field] = json!(stale[field].as_i64().unwrap() + 1);
        cases.push((stale, 409));
    }
    let mut stale = base.clone();
    stale["review"]["version"] = json!(next["version"].as_i64().unwrap() + 1);
    cases.push((stale, 409));
    cases.push((selection(&work, &old, "check", None), 400));
    cases.push((selection(&work, &other, "check", Some(&old)), 400));
    cases.push((selection(&work, &next, "check", Some(&objection)), 409));
    cases.push((selection(&work, &objection, "check", Some(&old)), 400));
    cases.push((selection(&work, &next, "challenge", None), 400));
    let unrelated = submit(
        &mut conn,
        Actor::Agent("carol"),
        json!({"action":"create","title":"Unrelated"}),
        "unrelated",
    )
    .unwrap()["work"]
        .clone();
    let unrelated = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &unrelated,
        "claim-unrelated",
    )
    .unwrap()["work"]
        .clone();
    let unrelated = publish(&mut conn, &unrelated, "unrelated-output");
    let unrelated = request(&mut conn, &unrelated, "unrelated-review");
    cases.push((selection(&work, &unrelated, "check", Some(&old)), 400));
    let mut empty_reason = base.clone();
    empty_reason["reason"] = json!("");
    cases.push((empty_reason, 400));
    let before = counts(&conn);
    for (i, (input, status)) in cases.into_iter().enumerate() {
        assert_eq!(
            submit(
                &mut conn,
                Actor::Agent("carol"),
                input,
                &format!("invalid-{i}")
            )
            .unwrap_err()
            .0,
            status,
            "case {i}"
        );
        assert_eq!(counts(&conn), before);
        assert_eq!(
            current_work(&mut conn, &work)["acceptance_requirements"],
            work["acceptance_requirements"]
        );
    }
}

#[test]
fn selection_race_retry_recovery_and_failed_writes_use_existing_transaction() {
    let (root, mut conn, work) = fixture_output();
    let check = request(&mut conn, &work, "check");
    let objection = challenge(&mut conn, &work, "objection");
    let barrier = Arc::new(Barrier::new(2));
    let inputs = [
        selection(&work, &check, "check", None),
        selection(&work, &objection, "challenge", None),
    ];
    let threads: Vec<_> = inputs
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, input)| {
            let path = root.path().to_owned();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut conn = super::super::super::super::open(&path).unwrap();
                barrier.wait();
                submit(
                    &mut conn,
                    Actor::Agent("carol"),
                    input,
                    &format!("race-{i}"),
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
    let winner = results.iter().position(|r| r.is_ok()).unwrap();
    drop(conn);
    let mut conn = db(&root);
    let before = counts(&conn);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            inputs[winner].clone(),
            &format!("race-{winner}")
        )
        .unwrap(),
        *results[winner].as_ref().unwrap()
    );
    assert_eq!(counts(&conn), before);
    let mut changed = inputs[winner].clone();
    changed["reason"] = json!("Conflicting retry input");
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("carol"),
            changed,
            &format!("race-{winner}")
        )
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(counts(&conn), before);
    let work = current_work(&mut conn, &work);
    let input = if winner == 0 {
        selection(&work, &objection, "challenge", None)
    } else {
        selection(&work, &check, "check", None)
    };
    for table in [
        "coord_work_revisions",
        "coord_work",
        "coord_operations",
        "coord_attention_edges",
        "coord_outbox",
    ] {
        conn.execute_batch(&format!("CREATE TRIGGER fail BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
        assert!(
            submit(
                &mut conn,
                Actor::Agent("carol"),
                input.clone(),
                "interrupted"
            )
            .is_err()
        );
        assert_eq!(counts(&conn), before);
        assert_eq!(
            current_work(&mut conn, &work)["acceptance_requirements"],
            work["acceptance_requirements"]
        );
        conn.execute_batch("DROP TRIGGER fail").unwrap();
    }
    let committed = submit(
        &mut conn,
        Actor::Agent("carol"),
        input.clone(),
        "interrupted",
    )
    .unwrap();
    assert_eq!(
        committed["work"]["acceptance_requirements"]["checks"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        committed["work"]["acceptance_requirements"]["challenges"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    conn.execute("DELETE FROM memberships WHERE principal_id='carol'", [])
        .unwrap();
    assert_eq!(
        submit(&mut conn, Actor::Agent("carol"), input, "interrupted")
            .unwrap_err()
            .0,
        404 // Room existence is hidden after membership removal, including retries.
    );
}

#[test]
fn amendments_stale_acceptance_without_resolving_challenges_or_refreshing_old_output_checks() {
    let (_root, mut conn, work) = fixture_output();
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "accept-first",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        current_work(&mut conn, &work)["acceptance_status"]["state"],
        "accepted"
    );
    let check = request(&mut conn, &work, "check");
    let check = answer(&mut conn, &check, "approve", "check-approved");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        selection(&work, &check, "check", None),
        "require-check",
    )
    .unwrap()["work"]
        .clone();
    let current = current_work(&mut conn, &work);
    assert_eq!(current["acceptance_status"]["state"], "pending");
    assert_eq!(
        current["acceptance_status"]["obligations"][0]["status"],
        "satisfied"
    );
    assert_eq!(
        current["acceptance_status"]["decisions"][0]["stale_reason"],
        "requirements_changed"
    );
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        decide(&work, "approve"),
        "accept-selected",
    )
    .unwrap()["work"]
        .clone();
    let objection = challenge(&mut conn, &work, "open-challenge");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        selection(&work, &objection, "challenge", None),
        "require-challenge",
    )
    .unwrap()["work"]
        .clone();
    let work = publish(&mut conn, &work, "next-output");
    let next = request(&mut conn, &work, "next-check");
    let work = submit(
        &mut conn,
        Actor::Agent("carol"),
        selection(&work, &next, "check", None),
        "add-next-check",
    )
    .unwrap()["work"]
        .clone();
    let status = current_work(&mut conn, &work)["acceptance_status"].clone();
    assert_eq!(status["state"], "pending");
    assert_eq!(status["obligations"][0]["status"], "stale_subject");
    assert_eq!(status["obligations"][2]["status"], "unresolved_challenge");
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            decide(&work, "approve"),
            "cannot-bypass"
        )
        .unwrap_err()
        .0,
        409
    );
}
