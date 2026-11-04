use super::*;

fn owned(conn: &mut Connection) -> Value {
    let work = create(conn)["work"].clone();
    change(conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone()
}

fn publication(work: &Value) -> Value {
    json!({"action":"publish_output","work_id":work["work_id"],"expected_version":work["version"],
        "expected_generation":work["claim_generation"],"expected_target_generation":work["target_generation"],
        "target_ref":"urn:sha256:retained-artifact","execution_outcome":"succeeded","summary":"Executed the requested procedure",
        "evidence_refs":["urn:sha256:retained-evidence"]})
}

fn submit(
    conn: &mut Connection,
    actor: Actor<'_>,
    input: &Value,
    operation: &str,
) -> Result<Value, WorkError> {
    mutate(
        conn,
        "owned",
        actor,
        serde_json::from_value(input.clone()).unwrap(),
        Some(operation),
    )
}

#[test]
fn publication_fences_ownership_generations_and_producer_attribution() {
    let root = fixture();
    let mut conn = db(&root);
    let work = owned(&mut conn);
    let input = publication(&work);
    let before = counts(&conn);
    for actor in [Actor::Agent("bob"), Actor::Operator] {
        assert_eq!(
            submit(&mut conn, actor, &input, "not-producer")
                .unwrap_err()
                .0,
            403
        );
    }
    for (field, value) in [
        ("expected_version", json!(1)),
        ("expected_generation", json!(0)),
        ("expected_target_generation", json!(1)),
    ] {
        let mut stale = input.clone();
        stale[field] = value;
        assert_eq!(
            submit(&mut conn, Actor::Agent("alice"), &stale, "stale")
                .unwrap_err()
                .0,
            409
        );
    }
    for field in [
        "producer",
        "actor",
        "created_by",
        "published_at",
        "work_version",
    ] {
        let mut forged = input.clone();
        forged[field] = json!({"kind":"agent","id":"bob"});
        assert!(serde_json::from_value::<Mutation>(forged).is_err());
    }
    assert_eq!(counts(&conn), before);
    let saved = submit(&mut conn, Actor::Agent("alice"), &input, "lost-response").unwrap();
    assert_eq!(saved["work"]["target_generation"], 1);
    assert_eq!(saved["work"]["state"], "claimed");
    assert_eq!(
        saved["work"]["output"]["producer"],
        json!({"kind":"agent","id":"alice"})
    );
    assert_eq!(saved["work"]["output"]["claim_generation"], 1);
    assert_eq!(saved["work"]["output"]["work_version"], 3);
    let mut stale_output = publication(&saved["work"]);
    stale_output["expected_target_generation"] = json!(0);
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            &stale_output,
            "stale-output"
        )
        .unwrap_err()
        .0,
        409
    );
    let done = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &saved["work"],
        "complete",
    )
    .unwrap()["work"]
        .clone();
    let mut correction = publication(&done);
    correction["target_ref"] = json!("urn:sha256:corrected-artifact");
    correction["execution_outcome"] = json!("failed");
    let corrected =
        submit(&mut conn, Actor::Agent("alice"), &correction, "correction").unwrap()["work"]
            .clone();
    assert_eq!(corrected["state"], "done");
    assert_eq!(corrected["target_generation"], 2);
    assert_eq!(corrected["output"]["execution_outcome"], "failed");
    let before = counts(&conn);
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &input, "lost-response").unwrap(),
        saved
    );
    assert_eq!(counts(&conn), before);
    let page = outputs::list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        work["work_id"].as_str().unwrap(),
        0,
        1,
    )
    .unwrap();
    assert_eq!(page["items"][0]["output"], saved["work"]["output"]);
    assert_eq!(page["next_after_version"], 3);
    let next = outputs::list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        work["work_id"].as_str().unwrap(),
        3,
        200,
    )
    .unwrap();
    assert_eq!(next["items"].as_array().unwrap().len(), 1);
    assert_eq!(next["items"][0]["output"], corrected["output"]);
    assert!(next["next_after_version"].is_null());
    // Returning the old receipt is never a claim that it remains current.
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap()
        )
        .unwrap(),
        corrected
    );
}

#[test]
fn cancellation_reassignment_and_completion_do_not_erase_prior_outputs() {
    let root = fixture();
    let mut conn = db(&root);
    let work = owned(&mut conn);
    let published = submit(
        &mut conn,
        Actor::Agent("alice"),
        &publication(&work),
        "publish",
    )
    .unwrap()["work"]
        .clone();
    let cancel = json!({"action":"cancel","work_id":work["work_id"],"expected_version":published["version"],"expected_generation":1,"reason":"Operator selected another run"});
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), &cancel, "not-owner")
            .unwrap_err()
            .0,
        403
    );
    let cancel_receipt = submit(&mut conn, Actor::Agent("alice"), &cancel, "cancel").unwrap();
    let cancelled = cancel_receipt["work"].clone();
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["claim_generation"], 2);
    assert!(cancelled["claim_agent_id"].is_null());
    assert_eq!(cancelled["output"], published["output"]);
    assert_eq!(cancelled["cancellation"]["author"]["id"], "alice");
    assert!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            &publication(&cancelled),
            "cancelled-publish"
        )
        .is_err()
    );
    assert!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "complete",
            &cancelled,
            "cancelled-complete"
        )
        .is_err()
    );
    let reassign = json!({"action":"reassign","work_id":work["work_id"],"expected_version":cancelled["version"],"expected_generation":2,"agent_id":"bob"});
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &reassign, "self-reassign")
            .unwrap_err()
            .0,
        403
    );
    let recovered =
        submit(&mut conn, Actor::Operator, &reassign, "operator-reassign").unwrap()["work"].clone();
    assert_eq!(recovered["claim_generation"], 3);
    assert_eq!(recovered["external_ref"], work["external_ref"]);
    assert_eq!(recovered["output"]["producer"]["id"], "alice");
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &cancel, "cancel").unwrap(),
        cancel_receipt
    );
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Agent("bob"),
            work["work_id"].as_str().unwrap()
        )
        .unwrap(),
        recovered
    );
    assert_eq!(
        submit(
            &mut conn,
            Actor::Agent("alice"),
            &publication(&published),
            "late"
        )
        .unwrap_err()
        .0,
        409
    );
    let replaced = submit(
        &mut conn,
        Actor::Agent("bob"),
        &publication(&recovered),
        "replacement",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(replaced["target_generation"], 2);
    assert_eq!(replaced["output"]["producer"]["id"], "bob");
    let done = change(
        &mut conn,
        Actor::Agent("bob"),
        "complete",
        &replaced,
        "done",
    )
    .unwrap()["work"]
        .clone();
    let mut reassign = reassign;
    reassign["expected_version"] = done["version"].clone();
    reassign["expected_generation"] = done["claim_generation"].clone();
    reassign["agent_id"] = json!("alice");
    assert_eq!(
        submit(&mut conn, Actor::Operator, &reassign, "reopen-done").unwrap()["work"]["state"],
        "claimed"
    );
}

#[test]
fn concurrent_publication_cancellation_and_reassignment_have_one_commit() {
    for other in ["publish_output", "cancel", "reassign"] {
        for _ in 0..4 {
            let root = fixture();
            let mut conn = db(&root);
            let work = owned(&mut conn);
            let first = publication(&work);
            let mut second = first.clone();
            if other != "publish_output" {
                second = json!({"action":other,"work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"]});
                second[if other == "cancel" {
                    "reason"
                } else {
                    "agent_id"
                }] = json!(if other == "cancel" {
                    "stop this attempt"
                } else {
                    "bob"
                });
            }
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
                        submit(
                            &mut conn,
                            if n == 1 && other == "reassign" {
                                Actor::Operator
                            } else {
                                Actor::Agent("alice")
                            },
                            &input,
                            &format!("race-{n}"),
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
            assert_eq!(
                conn.query_row("SELECT count(*) FROM coord_work_revisions", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                3
            );
        }
    }
}

#[test]
fn cancelled_work_has_its_own_status_and_open_work_needs_creator_authority() {
    let root = fixture();
    let mut conn = db(&root);
    let work = create(&mut conn)["work"].clone();
    let input = json!({"action":"cancel","work_id":work["work_id"],"expected_version":1,"expected_generation":0,"reason":"No longer required"});
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), &input, "stranger")
            .unwrap_err()
            .0,
        403
    );
    let result = submit(&mut conn, Actor::Operator, &input, "operator-cancel").unwrap();
    assert_eq!(result["work"]["state"], "cancelled");
    assert_eq!(
        super::super::super::room_status::work_page(&conn, "rm-owned", None).unwrap()["total"],
        0
    );
    assert_eq!(
        super::super::super::room_status::work_page(&conn, "rm-owned", Some("done")).unwrap()["total"],
        0
    );
    assert_eq!(
        super::super::super::room_status::work_page(&conn, "rm-owned", Some("cancelled")).unwrap()
            ["total"],
        1
    );
    let created = mutate(
        &mut conn,
        "owned",
        Actor::Agent("bob"),
        Mutation::Create {
            title: "My open work".into(),
            external_ref: None,
        },
        Some("bob-create"),
    )
    .unwrap();
    let input = json!({"action":"cancel","work_id":created["work"]["work_id"],"expected_version":1,"expected_generation":0,"reason":"Withdraw my unclaimed work"});
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), &input, "bob-cancel").unwrap()["work"]["state"],
        "cancelled"
    );
}

#[test]
fn publication_bounds_and_output_read_permissions_fail_without_writes() {
    let root = fixture();
    let mut conn = db(&root);
    let work = owned(&mut conn);
    let input = publication(&work);
    let before = counts(&conn);
    for (field, value) in [
        ("summary", json!(" ")),
        ("summary", json!("🦀".repeat(257))),
        ("target_ref", json!("")),
        ("target_ref", json!("a".repeat(1025))),
        ("evidence_refs", json!(vec!["a"; 17])),
        ("evidence_refs", json!(["a".repeat(1025)])),
        ("evidence_refs", json!(vec!["\u{001b}".repeat(1024); 16])),
    ] {
        let mut invalid = input.clone();
        invalid[field] = value;
        assert_eq!(
            submit(&mut conn, Actor::Agent("alice"), &invalid, "invalid")
                .unwrap_err()
                .0,
            400
        );
    }
    assert_eq!(counts(&conn), before);
    assert!(
        outputs::list(
            &mut conn,
            "owned",
            Actor::Agent("sender"),
            work["work_id"].as_str().unwrap(),
            0,
            50
        )
        .is_err()
    );
    assert!(
        outputs::list(
            &mut conn,
            "other",
            Actor::Operator,
            work["work_id"].as_str().unwrap(),
            0,
            50
        )
        .is_err()
    );
    assert!(
        outputs::list(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap(),
            -1,
            50
        )
        .is_err()
    );
}

#[test]
fn current_native_store_upgrade_keeps_claims_original_receipts_and_unknown_producers() {
    let root = fixture();
    let mut conn = db(&root);
    // Native schema 5 had the same ownership contract, with no output receipt.
    conn.execute_batch("DROP TABLE coord_work;
        CREATE TABLE coord_work (work_id TEXT PRIMARY KEY,room_id TEXT NOT NULL REFERENCES rooms(room_id),version INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('open','claimed','done')),document_json TEXT NOT NULL,FOREIGN KEY(work_id,version) REFERENCES coord_work_revisions(work_id,version) DEFERRABLE INITIALLY DEFERRED);
        CREATE INDEX coord_work_room ON coord_work(room_id,work_id);
        PRAGMA user_version=5;").unwrap();
    let old = json!({"work_id":"work-retained","room_id":"rm-owned","title":"retained native work","external_ref":"opaque:original-run",
        "target_ref":"opaque:retained-candidate","target_generation":1,"state":"claimed","claim_agent_id":"alice","claim_generation":1,
        "claimed_at":1,"claim_expires_at":null,"created_by":{"kind":"operator","id":"operator"},"short_result":null,"created_at":0,"updated_at":1,"version":2});
    let document = old.to_string();
    conn.execute("INSERT INTO coord_work_revisions VALUES('work-retained','rm-owned',2,?1,?2,'agent','alice','old-claim',1)",params![document,hash(document.as_bytes())]).unwrap();
    conn.execute(
        "INSERT INTO coord_work VALUES('work-retained','rm-owned',2,'claimed',?1)",
        [&document],
    )
    .unwrap();
    let input = Mutation::Claim {
        work_id: "work-retained".into(),
        expected_version: 1,
        expected_generation: 0,
    };
    let receipt = json!({"work":old,"operation_id":"old-claim"});
    let request_hash = hash(
        json!({"room_id":"rm-owned","mutation":serde_json::to_value(&input).unwrap()})
            .to_string()
            .as_bytes(),
    );
    conn.execute("INSERT INTO coord_operations VALUES('agent','alice','coord.work.claim','old-claim',?1,'success',?2,1)",params![request_hash,receipt.to_string()]).unwrap();
    let before = counts(&conn);
    // An interrupted/failed schema transaction leaves the old state usable for
    // recovery; it must not publish a partially upgraded schema version.
    conn.execute_batch("CREATE TABLE coord_work_upgrade(fixture INTEGER)")
        .unwrap();
    assert!(super::super::super::bootstrap(root.path()).is_err());
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(counts(&conn), before);
    conn.execute_batch("DROP TABLE coord_work_upgrade").unwrap();
    super::super::super::bootstrap(root.path()).unwrap();
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(
        revision(&conn, "rm-owned", "work-retained", 2)
            .unwrap()
            .to_string(),
        document
    );
    assert_eq!(counts(&conn), before);
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            input,
            Some("old-claim")
        )
        .unwrap(),
        receipt
    );
    let work = read(&mut conn, "owned", Actor::Agent("alice"), "work-retained").unwrap();
    assert_eq!(work["claim_generation"], 1);
    assert!(work["output"].is_null());
    assert_eq!(
        outputs::list(
            &mut conn,
            "owned",
            Actor::Agent("bob"),
            "work-retained",
            0,
            200
        )
        .unwrap()["items"],
        json!([])
    );
    let current = submit(
        &mut conn,
        Actor::Agent("alice"),
        &publication(&work),
        "first-attributed-output",
    )
    .unwrap();
    assert_eq!(current["work"]["output"]["producer"]["id"], "alice");
    super::super::super::bootstrap(root.path()).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
}
