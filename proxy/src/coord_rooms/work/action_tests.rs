use super::*;

fn submit(conn: &mut Connection, actor: Actor<'_>, value: Value, op: &str) -> Value {
    mutate(
        conn,
        "owned",
        actor,
        serde_json::from_value(value).unwrap(),
        Some(op),
    )
    .unwrap()["work"]
        .clone()
}
fn actions(conn: &mut Connection, who: &str, work: &Value, received: bool) -> Vec<Value> {
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
        .clone()
}
fn receive(conn: &mut Connection, who: &str, action: &Value) -> Result<Value, WorkError> {
    mutate(
        conn,
        "owned",
        Actor::Agent(who),
        Mutation::ReceiveAction {
            work_id: action["work_id"].as_str().unwrap().into(),
            action_key: action["key"].as_str().unwrap().into(),
        },
        None,
    )
}

#[test]
fn assignment_delivery_survives_claim_and_restart_without_becoming_execution() {
    let root = fixture();
    let mut conn = db(&root);
    let before = counts(&conn);
    assert_eq!(mutate(&mut conn,"owned",Actor::Operator,serde_json::from_value(json!({"action":"create","title":"Host cannot hold an execution claim","assignee":{"kind":"operator","id":"operator"}})).unwrap(),None).unwrap_err().0,400);
    assert_eq!(counts(&conn), before);
    let work = submit(
        &mut conn,
        Actor::Operator,
        json!({"action":"create","title":"Run this assignment","assignee":{"kind":"agent","id":"alice"}}),
        "assigned",
    );
    assert!(actions(&mut conn, "bob", &work, false).is_empty());
    assert!(actions(&mut conn, "reader", &work, false).is_empty());
    assert_eq!(
        change(&mut conn, Actor::Agent("bob"), "claim", &work, "wrong")
            .unwrap_err()
            .0,
        403
    );
    let action = actions(&mut conn, "alice", &work, false).remove(0);
    assert_eq!(action["kind"], "execute_work");
    assert_eq!(receive(&mut conn, "reader", &action).unwrap_err().0, 403);
    let before = counts(&conn);
    let receipt = receive(&mut conn, "alice", &action).unwrap();
    let after = counts(&conn);
    for i in 0..before.len() {
        assert_eq!(after[i] - before[i], if i == 3 { 1 } else { 0 });
    }
    let claimed =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    assert!(actions(&mut conn, "alice", &claimed, false).is_empty());
    assert_eq!(
        actions(&mut conn, "alice", &claimed, true)[0]["key"],
        action["key"]
    );
    drop(conn);
    let mut conn = db(&root);
    assert_eq!(receive(&mut conn, "alice", &action).unwrap(), receipt);
    let done = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &claimed,
        "finish",
    )
    .unwrap()["work"]
        .clone();
    assert!(actions(&mut conn, "alice", &done, true).is_empty());
    // Old original receipts do not resurrect a settled assignment.
    assert_eq!(receive(&mut conn, "alice", &action).unwrap(), receipt);
    let reassigned = submit(
        &mut conn,
        Actor::Operator,
        json!({"action":"reassign","work_id":done["work_id"],"expected_version":done["version"],"expected_generation":done["claim_generation"],"agent_id":"bob"}),
        "recovery",
    );
    assert!(actions(&mut conn, "alice", &reassigned, true).is_empty());
    let new = actions(&mut conn, "bob", &reassigned, false).remove(0);
    assert_ne!(action["key"], new["key"]);
    assert_eq!(receive(&mut conn, "bob", &action).unwrap_err().0, 409);
    let cancelled = submit(
        &mut conn,
        Actor::Operator,
        json!({"action":"cancel","work_id":reassigned["work_id"],"expected_version":reassigned["version"],"expected_generation":reassigned["claim_generation"],"reason":"Stop this assignment"}),
        "cancel",
    );
    assert!(actions(&mut conn, "bob", &cancelled, true).is_empty());
    assert_eq!(receive(&mut conn, "bob", &new).unwrap_err().0, 409);
    conn.execute("DELETE FROM memberships WHERE principal_id='alice'", [])
        .unwrap();
    assert_eq!(receive(&mut conn, "alice", &action).unwrap_err().0, 404);
}

#[test]
fn concurrent_action_receipts_commit_one_logical_delivery() {
    let root = fixture();
    let mut conn = db(&root);
    let work = submit(
        &mut conn,
        Actor::Operator,
        json!({"action":"create","title":"One logical execution delivery","assignee":{"kind":"agent","id":"alice"}}),
        "assigned",
    );
    let action = actions(&mut conn, "alice", &work, false).remove(0);
    let before = counts(&conn);
    let gate = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                let action = &action;
                let root = &root;
                scope.spawn(move || {
                    let mut conn = db(root);
                    gate.wait();
                    receive(&mut conn, "alice", action).unwrap()
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results[0], results[1]);
    let after = counts(&conn);
    for i in 0..before.len() {
        assert_eq!(after[i] - before[i], if i == 3 { 1 } else { 0 });
    }
    assert!(actions(&mut conn, "alice", &work, false).is_empty());
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap()
        )
        .unwrap()["state"],
        "open"
    );
}

#[test]
fn own_informational_results_do_not_create_attention() {
    let root = fixture();
    let mut conn = db(&root);
    let work = submit(
        &mut conn,
        Actor::Agent("alice"),
        json!({"action":"create","title":"Interactive unassigned work"}),
        "create",
    );
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let count = |conn: &Connection| {
        conn.query_row(
            "SELECT count(*) FROM coord_attention_edges WHERE recipient_agent_id='alice'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert_eq!(count(&conn), 0);
    let work = submit(
        &mut conn,
        Actor::Agent("alice"),
        json!({"action":"publish_output","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":1,"expected_target_generation":0,"target_ref":"urn:retained:own-result","execution_outcome":"succeeded","summary":"Retained result"}),
        "publish",
    );
    assert!(
        actions(&mut conn, "alice", &work, true)
            .iter()
            .all(|a| a["requires_action"] == false)
    );
    let _ = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &work,
        "complete",
    )
    .unwrap();
    assert_eq!(
        count(&conn),
        0,
        "own output and completion are not another model job"
    );
}

#[test]
fn answered_child_makes_parent_acceptance_ready_and_corrections_create_new_actions() {
    let root = fixture();
    let mut conn = db(&root);
    let work = create(&mut conn)["work"].clone();
    assert!(actions(&mut conn, "alice", &work, false).is_empty());
    let work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    let work = submit(
        &mut conn,
        Actor::Agent("alice"),
        json!({"action":"publish_output","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":1,"expected_target_generation":0,"target_ref":"urn:retained:1","execution_outcome":"succeeded","summary":"Retained output"}),
        "publish",
    );
    let check = submit(
        &mut conn,
        Actor::Operator,
        json!({"action":"request_check","subject":{"kind":"output","work_id":work["work_id"],"target_generation":1},"criterion":"Inspect result","reviewer":{"kind":"agent","id":"bob"},"independent":true}),
        "check",
    );
    let work = submit(
        &mut conn,
        Actor::Operator,
        json!({"action":"set_requirements","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":1,"expected_requirements_version":0,"authorities":[],"deciders":[{"kind":"agent","id":"bob"}],"independent":true,"checks":[{"work_id":check["work_id"],"version":1}],"reason":"Require this independent check"}),
        "requirements",
    );
    assert!(actions(&mut conn, "bob", &work, false).is_empty());
    let action = actions(&mut conn, "bob", &check, false).remove(0);
    receive(&mut conn, "bob", &action).unwrap();
    let check = change(
        &mut conn,
        Actor::Agent("bob"),
        "claim",
        &check,
        "claim-check",
    )
    .unwrap()["work"]
        .clone();
    let check = submit(
        &mut conn,
        Actor::Agent("bob"),
        json!({"action":"answer_check","work_id":check["work_id"],"expected_version":check["version"],"expected_generation":1,"verdict":"approve","summary":"Observed result"}),
        "answer",
    );
    let decision = actions(&mut conn, "bob", &check, false)
        .into_iter()
        .find(|a| a["kind"] == "decide_acceptance")
        .unwrap();
    assert_eq!(decision["work_id"], work["work_id"]);
    receive(&mut conn, "bob", &decision).unwrap();
    let work = read(
        &mut conn,
        "owned",
        Actor::Operator,
        work["work_id"].as_str().unwrap(),
    )
    .unwrap();
    let work = submit(
        &mut conn,
        Actor::Agent("bob"),
        json!({"action":"decide_acceptance","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":1,"expected_requirements_version":1,"expected_target_generation":1,"verdict":"approve","summary":"Check satisfied"}),
        "accept",
    );
    assert!(actions(&mut conn, "bob", &work, true).is_empty());
    // A restored corrected check cannot revive the earlier approval. It routes a
    // fresh exact-basis decision rather than counting the original receipt again.
    let check = submit(
        &mut conn,
        Actor::Agent("bob"),
        json!({"action":"answer_check","work_id":check["work_id"],"expected_version":check["version"],"expected_generation":1,"verdict":"reject","summary":"Corrected observation"}),
        "reject",
    );
    assert!(actions(&mut conn, "bob", &check, false).is_empty());
    let check = submit(
        &mut conn,
        Actor::Agent("bob"),
        json!({"action":"answer_check","work_id":check["work_id"],"expected_version":check["version"],"expected_generation":1,"verdict":"approve","summary":"New verified observation"}),
        "restore",
    );
    let new = actions(&mut conn, "bob", &check, false).remove(0);
    assert_eq!(new["kind"], "decide_acceptance");
    assert_ne!(new["key"], decision["key"]);
}
