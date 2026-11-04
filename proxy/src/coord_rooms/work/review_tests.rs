use super::*;

fn agent(id: &str) -> Value {
    json!({"kind":"agent","id":id})
}
fn submit(
    conn: &mut Connection,
    actor: Actor<'_>,
    input: Value,
    op: &str,
) -> Result<Value, WorkError> {
    mutate(
        conn,
        "owned",
        actor,
        serde_json::from_value(input).unwrap(),
        Some(op),
    )
}
fn owned() -> (tempfile::TempDir, Connection, Value) {
    let root = fixture();
    let mut conn = db(&root);
    conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-owned','agent','carol','send,receive',1)",[]).unwrap();
    let work = create(&mut conn)["work"].clone();
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = publish(&mut conn, &work, "output-1");
    (root, conn, work)
}
fn publish(conn: &mut Connection, work: &Value, op: &str) -> Value {
    submit(conn,Actor::Agent("alice"),json!({"action":"publish_output","work_id":work["work_id"],"expected_version":work["version"],
        "expected_generation":work["claim_generation"],"expected_target_generation":work["target_generation"],"target_ref":format!("urn:sha256:{op}"),
        "execution_outcome":"succeeded","summary":"Retained artifact"}),op).unwrap()["work"].clone()
}
fn subject(work: &Value) -> Value {
    json!({"kind":"output","work_id":work["work_id"],"target_generation":work["target_generation"]})
}
fn request(work: &Value) -> Value {
    json!({"action":"request_check","subject":subject(work),"criterion":"Check the retained artifact","reviewer":agent("bob"),"independent":true})
}
fn answer(work: &Value, verdict: &str) -> Value {
    json!({"action":"answer_check","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],
        "verdict":verdict,"summary":"Measured check result","evidence_refs":["urn:sha256:evidence"]})
}
fn challenge(work: &Value) -> Value {
    json!({"action":"raise_challenge","subject":subject(work),"assertion":"The artifact omits a required result","grounds":"Observed omission",
        "responder":agent("alice"),"deciders":[agent("bob")],"independent":true})
}
fn response(work: &Value) -> Value {
    json!({"action":"respond_challenge","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"summary":"Retained correction"})
}
fn resolve(work: &Value) -> Value {
    json!({"action":"resolve_challenge","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],
        "expected_response_version":work["challenge"]["response"]["work_version"].as_i64().unwrap_or(0),"decision":"dismissed","reason":"Verified the identified correction"})
}
fn read_current(conn: &mut Connection, work: &Value) -> Value {
    read(
        conn,
        "owned",
        Actor::Operator,
        work["work_id"].as_str().unwrap(),
    )
    .unwrap()
}

#[test]
fn checks_settle_correct_and_recover_without_extra_votes_or_subject_retargeting() {
    let (_root, mut conn, output) = owned();
    let created = submit(&mut conn, Actor::Agent("alice"), request(&output), "check").unwrap();
    let check = &created["work"];
    assert_eq!(
        read_current(&mut conn, check)["review_status"]["state"],
        "pending"
    );
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "claim",
            check,
            "wrong-reviewer"
        )
        .unwrap_err()
        .0,
        403
    );
    let claimed = change(
        &mut conn,
        Actor::Agent("bob"),
        "claim",
        check,
        "review-claim",
    )
    .unwrap()["work"]
        .clone();
    assert!(
        change(
            &mut conn,
            Actor::Operator,
            "complete",
            &claimed,
            "bypass-answer"
        )
        .is_err()
    );
    let input = answer(&claimed, "reject");
    let rejected = submit(&mut conn, Actor::Agent("bob"), input.clone(), "answer").unwrap();
    assert_eq!(rejected["work"]["state"], "done");
    assert_eq!(rejected["work"]["check"]["answer"]["author"], agent("bob"));
    let corrected = submit(
        &mut conn,
        Actor::Agent("bob"),
        answer(&rejected["work"], "approve"),
        "correct-answer",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        read_at_version(
            &mut conn,
            "owned",
            Actor::Agent("reader"),
            check["work_id"].as_str().unwrap(),
            3
        )
        .unwrap()["check"]["answer"]["verdict"],
        "reject"
    );
    assert_eq!(
        read_current(&mut conn, &corrected)["check"]["answer"]["verdict"],
        "approve"
    );
    let next = publish(&mut conn, &output, "output-2");
    assert_eq!(
        read_current(&mut conn, &corrected)["review_status"]["subject_current"],
        false
    );
    let late = submit(
        &mut conn,
        Actor::Agent("bob"),
        answer(&corrected, "abstain"),
        "late-answer",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(late["check"]["subject"]["reference"], subject(&output));
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), input, "answer").unwrap(),
        rejected
    );
    let reassigned=submit(&mut conn,Actor::Operator,json!({"action":"reassign","work_id":late["work_id"],"expected_version":late["version"],"expected_generation":1,"agent_id":"carol"}),"recover-reviewer").unwrap()["work"].clone();
    assert!(reassigned["check"]["answer"].is_null());
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            answer(&reassigned, "approve"),
            "former-reviewer"
        )
        .unwrap_err()
        .0,
        403
    );
    let recovered = submit(
        &mut conn,
        Actor::Agent("carol"),
        answer(&reassigned, "reject"),
        "recovered-answer",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(recovered["check"]["answer"]["claim_generation"], 2);
    assert_eq!(recovered["check"]["subject"]["producer"], agent("alice"));
    let page = reviews::list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        output["work_id"].as_str().unwrap(),
        "",
        200,
    )
    .unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        page["items"][0]["check"]["answer"]["author"],
        agent("carol")
    );
    // Optional review cannot invent a completion gate on unrelated execution.
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "complete",
            &next,
            "root-complete"
        )
        .unwrap()["work"]["state"],
        "done"
    );
}

#[test]
fn independence_uses_actual_producer_and_operator_checks_can_correct_their_answers() {
    let (_root, mut conn, output) = owned();
    let reassign=submit(&mut conn,Actor::Operator,json!({"action":"reassign","work_id":output["work_id"],"expected_version":output["version"],"expected_generation":1,"agent_id":"bob"}),"integrate").unwrap()["work"].clone();
    let mut input = request(&reassign);
    input["reviewer"] = agent("alice");
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), input.clone(), "self-review")
            .unwrap_err()
            .0,
        403
    );
    input["independent"] = json!(false);
    assert!(submit(&mut conn, Actor::Agent("bob"), input, "optional-self-check").is_ok());
    let mut input = request(&output);
    input["reviewer"] = json!({"kind":"operator","id":"operator"});
    let human = submit(&mut conn, Actor::Operator, input, "human-check").unwrap()["work"].clone();
    let answered = submit(
        &mut conn,
        Actor::Operator,
        answer(&human, "reject"),
        "human-answer",
    )
    .unwrap()["work"]
        .clone();
    let corrected = submit(
        &mut conn,
        Actor::Operator,
        answer(&answered, "approve"),
        "human-correction",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(corrected["state"], "done");
    assert_eq!(corrected["check"]["answer"]["author"]["kind"], "operator");
    let mut forged = answer(&corrected, "approve");
    forged["author"] = agent("alice");
    assert!(serde_json::from_value::<Mutation>(forged).is_err());
    let mut forged = request(&output);
    forged["subject"]["producer"] = agent("bob");
    assert!(serde_json::from_value::<Mutation>(forged).is_err());
    let mut read_only = request(&output);
    read_only["reviewer"] = agent("reader");
    assert!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            read_only,
            "read-only-reviewer"
        )
        .is_err()
    );
}

#[test]
fn challenge_response_correction_and_disposition_preserve_the_original_objection() {
    let (_root, mut conn, output) = owned();
    let raised =
        submit(&mut conn, Actor::Agent("bob"), challenge(&output), "raise").unwrap()["work"]
            .clone();
    let claimed = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &raised,
        "response-claim",
    )
    .unwrap()["work"]
        .clone();
    assert!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "complete",
            &claimed,
            "bypass-response"
        )
        .is_err()
    );
    let initial = submit(
        &mut conn,
        Actor::Agent("alice"),
        response(&claimed),
        "response",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(initial["state"], "done");
    assert_eq!(
        read_current(&mut conn, &initial)["review_status"]["state"],
        "unresolved"
    );
    let correction = publish(&mut conn, &output, "corrected-output");
    assert_eq!(
        read_current(&mut conn, &initial)["challenge"]["subject"]["reference"],
        subject(&output)
    );
    let mut update = response(&initial);
    update["correction"] = subject(&correction);
    let corrected = submit(
        &mut conn,
        Actor::Agent("alice"),
        update,
        "corrected-response",
    )
    .unwrap()["work"]
        .clone();
    for actor in [Actor::Agent("alice"), Actor::Agent("carol")] {
        assert_eq!(
            submit(&mut conn, actor, resolve(&corrected), "not-decider")
                .unwrap_err()
                .0,
            403
        );
    }
    let mut stale = resolve(&corrected);
    stale["expected_response_version"] = initial["challenge"]["response"]["work_version"].clone();
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), stale, "stale-response")
            .unwrap_err()
            .0,
        409
    );
    let input = resolve(&corrected);
    let disposed = submit(&mut conn, Actor::Agent("bob"), input.clone(), "dispose").unwrap();
    assert_eq!(
        read_current(&mut conn, &disposed["work"])["review_status"]["state"],
        "resolved"
    );
    assert_eq!(
        disposed["work"]["challenge"]["disposition"]["correction"]["reference"],
        subject(&correction)
    );
    let reopened = submit(
        &mut conn,
        Actor::Agent("alice"),
        response(&disposed["work"]),
        "new-evidence",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(
        read_current(&mut conn, &reopened)["review_status"]["state"],
        "unresolved"
    );
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), input, "dispose").unwrap(),
        disposed
    );
    assert_eq!(
        read_at_version(
            &mut conn,
            "owned",
            Actor::Agent("reader"),
            raised["work_id"].as_str().unwrap(),
            disposed["work"]["version"].as_i64().unwrap()
        )
        .unwrap()["challenge"]["disposition"],
        disposed["work"]["challenge"]["disposition"]
    );
}

#[test]
fn cancellation_is_not_resolution_and_unavailable_participants_have_operator_recovery() {
    let (_root, mut conn, output) = owned();
    let raised =
        submit(&mut conn, Actor::Agent("bob"), challenge(&output), "raise").unwrap()["work"]
            .clone();
    let claimed = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &raised,
        "claim-response",
    )
    .unwrap()["work"]
        .clone();
    let cancelled=submit(&mut conn,Actor::Agent("alice"),json!({"action":"cancel","work_id":claimed["work_id"],"expected_version":claimed["version"],"expected_generation":1,"reason":"Responder stopped"}),"cancel").unwrap()["work"].clone();
    assert_eq!(
        read_current(&mut conn, &cancelled)["review_status"]["state"],
        "unresolved"
    );
    let input = json!({"action":"recover_challenge_deciders","work_id":cancelled["work_id"],"expected_version":cancelled["version"],"expected_generation":cancelled["claim_generation"],"deciders":[agent("carol")],"reason":"Original decider unavailable"});
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            input.clone(),
            "worker-recovery"
        )
        .unwrap_err()
        .0,
        403
    );
    let recovered =
        submit(&mut conn, Actor::Operator, input, "recover-decider").unwrap()["work"].clone();
    assert!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            resolve(&recovered),
            "former-decider"
        )
        .is_err()
    );
    let disposed = submit(
        &mut conn,
        Actor::Agent("carol"),
        resolve(&recovered),
        "withdraw-unanswered",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(disposed["state"], "cancelled");
    assert_eq!(
        read_current(&mut conn, &disposed)["review_status"]["state"],
        "resolved"
    );
    assert!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            response(&disposed),
            "cancelled-response"
        )
        .is_err()
    );
    let another = submit(
        &mut conn,
        Actor::Agent("bob"),
        challenge(&output),
        "another-objection",
    )
    .unwrap()["work"]
        .clone();
    let claimed = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &another,
        "another-response",
    )
    .unwrap()["work"]
        .clone();
    let disposed = submit(
        &mut conn,
        Actor::Agent("bob"),
        resolve(&claimed),
        "dispose-before-response",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(disposed["state"], "cancelled");
    assert_eq!(disposed["claim_generation"], 2);
    assert!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            response(&claimed),
            "crossed-response"
        )
        .is_err()
    );
}

#[test]
fn exact_check_subjects_and_related_pages_include_objections_to_check_answers() {
    let (_root, mut conn, output) = owned();
    let check =
        submit(&mut conn, Actor::Agent("alice"), request(&output), "check").unwrap()["work"]
            .clone();
    let mut objection = challenge(&output);
    objection["subject"] = json!({"kind":"check","work_id":check["work_id"],"version":1});
    assert!(
        submit(
            &mut conn,
            Actor::Agent("bob"),
            objection.clone(),
            "unfinished-subject"
        )
        .is_err()
    );
    let claimed = change(
        &mut conn,
        Actor::Agent("bob"),
        "claim",
        &check,
        "claim-check",
    )
    .unwrap()["work"]
        .clone();
    let answered = submit(
        &mut conn,
        Actor::Agent("bob"),
        answer(&claimed, "approve"),
        "answer-check",
    )
    .unwrap()["work"]
        .clone();
    objection["subject"]["version"] = answered["version"].clone();
    objection["deciders"] = json!([agent("carol")]);
    let challenged = submit(
        &mut conn,
        Actor::Agent("bob"),
        objection,
        "challenge-answer",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(challenged["challenge"]["subject"]["producer"], agent("bob"));
    let first = reviews::list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        output["work_id"].as_str().unwrap(),
        "",
        1,
    )
    .unwrap();
    let last = reviews::list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        output["work_id"].as_str().unwrap(),
        first["next_after"].as_str().unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(
        first["items"].as_array().unwrap().len() + last["items"].as_array().unwrap().len(),
        2
    );
    assert!(last["next_after"].is_null());
    assert!(
        reviews::list(
            &mut conn,
            "other",
            Actor::Operator,
            output["work_id"].as_str().unwrap(),
            "",
            50
        )
        .is_err()
    );
    assert!(
        read_at_version(
            &mut conn,
            "owned",
            Actor::Agent("sender"),
            check["work_id"].as_str().unwrap(),
            1
        )
        .is_err()
    );
    assert_eq!(
        read_at_version(
            &mut conn,
            "owned",
            Actor::Agent("reader"),
            check["work_id"].as_str().unwrap(),
            999
        )
        .unwrap_err()
        .0,
        404
    );
}

#[test]
fn racing_review_transitions_and_failures_leave_one_coherent_answer_or_disposition() {
    for decision_race in [false, true] {
        let (root, mut conn, output) = owned();
        let created = submit(
            &mut conn,
            Actor::Agent("bob"),
            if decision_race {
                challenge(&output)
            } else {
                request(&output)
            },
            "create-review",
        )
        .unwrap()["work"]
            .clone();
        let claimed = change(
            &mut conn,
            if decision_race {
                Actor::Agent("alice")
            } else {
                Actor::Agent("bob")
            },
            "claim",
            &created,
            "claim-review",
        )
        .unwrap()["work"]
            .clone();
        let first = if decision_race {
            response(&claimed)
        } else {
            answer(&claimed, "approve")
        };
        let second = if decision_race {
            resolve(&claimed)
        } else {
            json!({"action":"reassign","work_id":claimed["work_id"],"expected_version":claimed["version"],"expected_generation":1,"agent_id":"carol"})
        };
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [first, second]
            .into_iter()
            .enumerate()
            .map(|(n, input)| {
                let path = root.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut conn = super::super::super::open(&path).unwrap();
                    barrier.wait();
                    let actor = if n == 0 {
                        if decision_race {
                            Actor::Agent("alice")
                        } else {
                            Actor::Agent("bob")
                        }
                    } else if decision_race {
                        Actor::Agent("bob")
                    } else {
                        Actor::Operator
                    };
                    submit(&mut conn, actor, input, &format!("race-{n}"))
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results.iter().find_map(|r| r.as_ref().err()).unwrap().0,
            409
        );
    }
    for table in [
        "coord_work_revisions",
        "coord_work",
        "coord_operations",
        "coord_attention_edges",
        "coord_outbox",
    ] {
        let (_root, mut conn, output) = owned();
        let raised =
            submit(&mut conn, Actor::Agent("bob"), challenge(&output), "raise").unwrap()["work"]
                .clone();
        let claimed = change(
            &mut conn,
            Actor::Agent("alice"),
            "claim",
            &raised,
            "response-claim",
        )
        .unwrap()["work"]
            .clone();
        let input = resolve(&claimed);
        let before = counts(&conn);
        conn.execute_batch(&format!("CREATE TRIGGER fail BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
        assert!(submit(&mut conn, Actor::Agent("bob"), input.clone(), "resolve").is_err());
        assert_eq!(counts(&conn), before);
        let current = read_current(&mut conn, &claimed);
        assert_eq!(current["state"], "claimed");
        assert!(current["challenge"]["disposition"].is_null());
        conn.execute_batch("DROP TRIGGER fail").unwrap();
        assert_eq!(
            submit(&mut conn, Actor::Agent("bob"), input, "resolve").unwrap()["work"]["state"],
            "cancelled"
        );
    }
}
