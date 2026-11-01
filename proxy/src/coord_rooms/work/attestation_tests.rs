use super::*;
use crate::coord_rooms::room_status;

fn target(work: &Value, reference: &str) -> Value {
    json!({"action":"change_target","work_id":work["work_id"],"expected_version":work["version"],
        "expected_target_generation":work["target_generation"],"target_ref":reference})
}
fn attest(work: &Value) -> Value {
    json!({"action":"attest","work_id":work["work_id"],"target_generation":work["target_generation"],
        "kind":"acceptance","verdict":"approve","summary":"Private review π\n\u{001b}[2J", "evidence_refs":["https://untrusted.invalid/evidence"]})
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
fn page(conn: &Connection) -> Value {
    room_status::work_page(conn, "rm-owned", false).unwrap()["items"][0].clone()
}

#[test]
fn exact_targets_retain_stale_conflicting_evidence_without_deciding_policy() {
    let root = fixture();
    let mut conn = db(&root);
    let mut work = create(&mut conn)["work"].clone();
    assert_eq!(work["target_generation"], 0);
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), &attest(&work), "unset")
            .unwrap_err()
            .0,
        400
    );
    work =
        change(&mut conn, Actor::Agent("alice"), "claim", &work, "claim").unwrap()["work"].clone();
    for generation in 1..=3 {
        work = submit(
            &mut conn,
            Actor::Agent("alice"),
            &target(&work, &format!("commit:{generation}")),
            &format!("target-{generation}"),
        )
        .unwrap()["work"]
            .clone();
    }
    let input = attest(&work);
    let approval = submit(&mut conn, Actor::Agent("bob"), &input, "bob-3").unwrap();
    assert_eq!(
        approval["attestation"]["author"],
        json!({"kind":"agent","id":"bob"})
    );
    assert_eq!(approval["attestation"]["target_ref"], "commit:3");
    assert_eq!(
        page(&conn)["attestations"]["current_acceptance"]["approve"],
        1
    );
    // Reusing a branch/PR ref still requires an explicit change after squash/rebase.
    let change_input = target(&approval["work"], "commit:3");
    let next = submit(&mut conn, Actor::Agent("alice"), &change_input, "squash").unwrap();
    assert_eq!(next["work"]["target_generation"], 4);
    assert_eq!(next["work"]["claim_generation"], 1);
    assert_eq!(next["work"]["claim_agent_id"], "alice");
    let status = page(&conn);
    assert_eq!(status["attestations"]["current_total"], 0);
    assert_eq!(status["attestations"]["stale_total"], 1);
    assert_eq!(
        status["attestations"]["current_acceptance"],
        json!({"approve":0,"reject":0,"abstain":0})
    );
    assert_eq!(status["attestations"]["items"][0]["current"], false);
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), &input, "late-3")
            .unwrap_err()
            .0,
        409
    );
    let before = counts(&conn);
    assert_eq!(
        submit(&mut conn, Actor::Agent("bob"), &input, "bob-3").unwrap(),
        approval
    );
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &change_input, "squash").unwrap(),
        next
    );
    assert_eq!(counts(&conn), before);
    assert_eq!(
        revision(
            &conn,
            "rm-owned",
            work["work_id"].as_str().unwrap(),
            approval["work"]["version"].as_i64().unwrap()
        )
        .unwrap()["attestation"],
        approval["attestation"]
    );
    let current_input = attest(&next["work"]);
    let approved = submit(&mut conn, Actor::Agent("bob"), &current_input, "bob-4").unwrap();
    let mut reject_input = current_input.clone();
    reject_input["verdict"] = json!("reject");
    let rejected = submit(&mut conn, Actor::Agent("alice"), &reject_input, "alice-4").unwrap();
    assert_ne!(
        approved["attestation"]["attestation_id"],
        rejected["attestation"]["attestation_id"]
    );
    let status = page(&conn);
    assert_eq!(status["state"], "claimed");
    assert_eq!(
        status["attestations"]["current_acceptance"],
        json!({"approve":1,"reject":1,"abstain":0})
    );
    assert_eq!(status["attestations"]["total"], 3);
    assert_eq!(status["attestations"]["items"][0]["current"], true);
    assert_eq!(status["attestations"]["items"][1]["current"], true);
    let listed = attestations::list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        work["work_id"].as_str().unwrap(),
        "",
        200,
    )
    .unwrap();
    assert_eq!(listed["target_generation"], 4);
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["attestation"] == approval["attestation"] && item["current"] == false)
    );
    assert!(
        conn.execute("UPDATE coord_work_attestations SET verdict='reject'", [])
            .is_err()
    );
    assert!(
        conn.execute("DELETE FROM coord_work_attestations", [])
            .is_err()
    );
    let audit: String = conn
        .query_row(
            "SELECT group_concat(payload_json) FROM coord_outbox",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        !audit.contains("Private review")
            && !audit.contains("untrusted.invalid")
            && !audit.contains("commit:3")
    );
    for event in conn
        .prepare("SELECT payload_json FROM coord_outbox WHERE destination='audit-jsonl'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
    {
        crate::audit::parse_record(&event.unwrap()).unwrap();
    }
}

#[test]
fn attestation_authorization_validation_and_retry_authority() {
    let root = fixture();
    let mut conn = db(&root);
    let open = create(&mut conn)["work"].clone();
    let work = submit(
        &mut conn,
        Actor::Operator,
        &target(&open, "opaque:target"),
        "target",
    )
    .unwrap()["work"]
        .clone();
    let input = attest(&work);
    let before = counts(&conn);
    for actor in [
        Actor::Agent("reader"),
        Actor::Agent("sender"),
        Actor::Agent("absent"),
    ] {
        assert!(submit(&mut conn, actor, &input, "unauthorized").is_err());
        assert!(submit(&mut conn, actor, &target(&work, "new"), "unauthorized").is_err());
    }
    for (field, value) in [
        ("author", json!({"kind":"agent","id":"bob"})),
        ("work_version", json!(10)),
        ("attestation_id", json!("chosen")),
        ("created_at", json!(1)),
    ] {
        let mut forged = input.clone();
        forged[field] = value;
        assert!(serde_json::from_value::<Mutation>(forged).is_err());
    }
    for (field, value) in [
        ("kind", json!(" ")),
        ("kind", json!("x".repeat(129))),
        ("summary", json!("")),
        ("summary", json!("🦀".repeat(257))),
        ("evidence_refs", json!(["x".repeat(1025)])),
        ("evidence_refs", json!(vec!["x"; 17])),
        ("target_generation", json!(-1)),
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
    for reference in ["".to_owned(), " ".to_owned(), "🦀".repeat(257)] {
        assert_eq!(
            submit(
                &mut conn,
                Actor::Operator,
                &target(&work, &reference),
                "invalid"
            )
            .unwrap_err()
            .0,
            400
        );
    }
    let mut invalid = input.clone();
    invalid["target_generation"] = json!(2);
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &invalid, "future")
            .unwrap_err()
            .0,
        409
    );
    assert_eq!(counts(&conn), before);
    let receipt = submit(&mut conn, Actor::Agent("alice"), &input, "retry").unwrap();
    let mut changed = input.clone();
    changed["summary"] = json!("changed");
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &changed, "retry")
            .unwrap_err()
            .0,
        409
    );
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &input, "retry").unwrap(),
        receipt
    );
    conn.execute(
        "UPDATE memberships SET revoked_at=2 WHERE principal_id='alice'",
        [],
    )
    .unwrap();
    assert_eq!(
        submit(&mut conn, Actor::Agent("alice"), &input, "retry")
            .unwrap_err()
            .0,
        404
    );
    assert_eq!(
        attestations::list(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            work["work_id"].as_str().unwrap(),
            "",
            50
        )
        .unwrap_err()
        .0,
        404
    );
    assert_eq!(
        attestations::list(
            &mut conn,
            "other",
            Actor::Operator,
            work["work_id"].as_str().unwrap(),
            "",
            50
        )
        .unwrap_err()
        .0,
        404
    );
}

#[test]
fn target_attestation_races_and_independent_submissions_preserve_identity() {
    for _ in 0..8 {
        let root = fixture();
        let mut conn = db(&root);
        let open = create(&mut conn)["work"].clone();
        let work = submit(
            &mut conn,
            Actor::Operator,
            &target(&open, "candidate-1"),
            "target",
        )
        .unwrap()["work"]
            .clone();
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [target(&work, "candidate-2"), attest(&work)]
            .into_iter()
            .map(|input| {
                let path = root.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut conn = super::super::super::open(&path).unwrap();
                    barrier.wait();
                    submit(&mut conn, Actor::Agent("bob"), &input, "racing")
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results.iter().find_map(|r| r.as_ref().err()).unwrap().0,
            409
        );
        let listed = attestations::list(
            &mut conn,
            "owned",
            Actor::Operator,
            work["work_id"].as_str().unwrap(),
            "",
            50,
        )
        .unwrap();
        for item in listed["items"].as_array().unwrap() {
            assert_eq!(item["attestation"]["target_ref"], "candidate-1");
        }
    }
    let root = fixture();
    let mut conn = db(&root);
    let open = create(&mut conn)["work"].clone();
    let work = submit(
        &mut conn,
        Actor::Operator,
        &target(&open, "candidate"),
        "target",
    )
    .unwrap()["work"]
        .clone();
    let barrier = Arc::new(Barrier::new(20));
    let threads: Vec<_> = (0..20)
        .map(|n| {
            let path = root.path().to_owned();
            let barrier = barrier.clone();
            let mut input = attest(&work);
            input["verdict"] = json!(if n % 2 == 0 { "approve" } else { "reject" });
            std::thread::spawn(move || {
                let mut conn = super::super::super::open(&path).unwrap();
                barrier.wait();
                submit(
                    &mut conn,
                    Actor::Agent(if n % 2 == 0 { "alice" } else { "bob" }),
                    &input,
                    &format!("parallel-{n}"),
                )
                .unwrap()
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        page(&conn)["attestations"]["current_acceptance"],
        json!({"approve":10,"reject":10,"abstain":0})
    );
    assert_eq!(page(&conn)["state"], "open");
}

#[test]
fn failures_roll_back_target_and_attestation_with_all_delivery_records() {
    for action in ["change_target", "attest"] {
        for table in [
            "coord_work_revisions",
            "coord_work",
            "coord_work_attestations",
            "coord_operations",
            "coord_attention_edges",
            "coord_outbox",
        ] {
            if action == "change_target" && table == "coord_work_attestations" {
                continue;
            }
            let root = fixture();
            let mut conn = db(&root);
            let open = create(&mut conn)["work"].clone();
            let work = submit(
                &mut conn,
                Actor::Operator,
                &target(&open, "first"),
                "target",
            )
            .unwrap()["work"]
                .clone();
            let input = if action == "attest" {
                attest(&work)
            } else {
                target(&work, "second")
            };
            let before = counts(&conn);
            conn.execute_batch(&format!("CREATE TRIGGER fail BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
            assert!(submit(&mut conn, Actor::Agent("bob"), &input, "retry").is_err());
            assert_eq!(counts(&conn), before);
            assert_eq!(
                read(
                    &mut conn,
                    "owned",
                    Actor::Operator,
                    work["work_id"].as_str().unwrap()
                )
                .unwrap(),
                work
            );
            conn.execute_batch("DROP TRIGGER fail").unwrap();
            let result = submit(&mut conn, Actor::Agent("bob"), &input, "retry").unwrap();
            assert_eq!(result["work"]["version"], 3);
            assert_eq!(
                submit(&mut conn, Actor::Agent("bob"), &input, "retry").unwrap(),
                result
            );
        }
    }
}

#[test]
fn bounded_status_prefers_current_and_full_evidence_pages_remain_accessible() {
    let root = fixture();
    let mut conn = db(&root);
    let open = create(&mut conn)["work"].clone();
    let work = submit(
        &mut conn,
        Actor::Operator,
        &target(&open, "opaque"),
        "target",
    )
    .unwrap()["work"]
        .clone();
    for n in 0..12 {
        let mut input = attest(&work);
        input["summary"] = json!("\u{001b}".repeat(1024));
        input["evidence_refs"] = json!(vec!["\u{001b}".repeat(256); 16]);
        // Input is inside field bounds but escapes also count towards record bytes.
        if n == 0 {
            input["evidence_refs"] = json!(vec!["\u{001b}".repeat(1024); 16]);
            assert_eq!(
                submit(&mut conn, Actor::Agent("bob"), &input, "oversized")
                    .unwrap_err()
                    .0,
                400
            );
            input["evidence_refs"] = json!(vec!["\u{001b}".repeat(256); 16]);
        }
        submit(&mut conn, Actor::Agent("bob"), &input, &format!("old-{n}")).unwrap();
    }
    let latest = read(
        &mut conn,
        "owned",
        Actor::Operator,
        work["work_id"].as_str().unwrap(),
    )
    .unwrap();
    let work =
        submit(&mut conn, Actor::Operator, &target(&latest, "new"), "new").unwrap()["work"].clone();
    submit(
        &mut conn,
        Actor::Agent("alice"),
        &attest(&work),
        "new-acceptance",
    )
    .unwrap();
    let page = page(&conn);
    assert_eq!(page["attestations"]["total"], 13);
    assert_eq!(page["attestations"]["truncated"], true);
    assert_eq!(page["attestations"]["items"][0]["current"], true);
    assert_eq!(page["attestations"]["current_acceptance"]["approve"], 1);
    assert!(page["attestations"]["items"].to_string().len() <= 4096);
    let mut after = String::new();
    let mut ids = std::collections::BTreeSet::new();
    loop {
        let page = attestations::list(
            &mut conn,
            "owned",
            Actor::Agent("reader"),
            work["work_id"].as_str().unwrap(),
            &after,
            200,
        )
        .unwrap();
        assert!(page["items"].to_string().len() <= 64 * 1024);
        for item in page["items"].as_array().unwrap() {
            assert!(
                ids.insert(
                    item["attestation"]["attestation_id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                )
            );
        }
        let Some(next) = page["next_after"].as_str() else {
            break;
        };
        after = next.to_owned();
    }
    assert_eq!(ids.len(), 13);
}
