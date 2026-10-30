use super::*;
use std::{
    fs,
    sync::{Arc, Barrier},
};

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/instance_id"), "owned-instance").unwrap();
    fs::write(
        root.path().join("config.toml"),
        format!("data_dir={:?}\n", root.path().join("data")),
    )
    .unwrap();
    super::super::bootstrap(root.path()).unwrap();
    let conn = db(&root);
    conn.execute("INSERT INTO rooms VALUES('rm-owned','owned',0)", [])
        .unwrap();
    conn.execute("INSERT INTO rooms VALUES('rm-other','other',0)", [])
        .unwrap();
    for (id, permissions) in [
        ("alice", "send,receive"),
        ("bob", "send,receive"),
        ("reader", "receive"),
        ("sender", "send"),
    ] {
        conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-owned','agent',?1,?2,1)",params![id,permissions]).unwrap();
    }
    root
}
fn db(root: &tempfile::TempDir) -> Connection {
    super::super::open(root.path()).unwrap()
}
fn create(conn: &mut Connection) -> Value {
    mutate(
        conn,
        "owned",
        Actor::Operator,
        Mutation::Create {
            title: "Private title π".into(),
            external_ref: Some("opaque:external-description".into()),
        },
        Some("create"),
    )
    .unwrap()
}
fn change(
    conn: &mut Connection,
    actor: Actor<'_>,
    action: &str,
    work: &Value,
    operation: &str,
) -> Result<Value, WorkError> {
    let input = json!({"action":action,"work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"]});
    mutate(
        conn,
        "owned",
        actor,
        serde_json::from_value(input).unwrap(),
        Some(operation),
    )
}
fn counts(conn: &Connection) -> Vec<i64> {
    [
        "coord_work",
        "coord_work_revisions",
        "coord_operations",
        "coord_attention_edges",
        "coord_attention_feeds",
        "coord_outbox",
    ]
    .into_iter()
    .map(|table| {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    })
    .collect()
}

#[test]
fn ownership_replay_generations_revocation_and_operator_recovery() {
    let root = fixture();
    let mut conn = db(&root);
    let open = create(&mut conn)["work"].clone();
    let before = counts(&conn);
    assert_eq!(create(&mut conn)["work"], open);
    assert_eq!(counts(&conn), before);
    assert_eq!(
        change(&mut conn, Actor::Agent("reader"), "claim", &open, "r")
            .unwrap_err()
            .0,
        403
    );
    assert_eq!(
        read(
            &mut conn,
            "owned",
            Actor::Agent("sender"),
            open["work_id"].as_str().unwrap()
        )
        .unwrap_err()
        .0,
        403
    );
    let claim = change(
        &mut conn,
        Actor::Agent("alice"),
        "claim",
        &open,
        "ambiguous",
    )
    .unwrap();
    let claimed = claim["work"].clone();
    assert_eq!(claimed["claim_agent_id"], "alice");
    assert_eq!(claimed["claim_generation"], 1);
    assert_eq!(claimed["claim_expires_at"], Value::Null);
    assert_eq!(
        change(&mut conn, Actor::Agent("bob"), "release", &claimed, "b")
            .unwrap_err()
            .0,
        403
    );
    let released = change(
        &mut conn,
        Actor::Agent("alice"),
        "release",
        &claimed,
        "release",
    )
    .unwrap()["work"]
        .clone();
    let next = change(
        &mut conn,
        Actor::Agent("bob"),
        "claim",
        &released,
        "reclaim",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(next["claim_generation"], 2);
    for action in ["release", "complete"] {
        assert_eq!(
            change(&mut conn, Actor::Agent("alice"), action, &claimed, "stale")
                .unwrap_err()
                .0,
            409
        );
    }
    let before = counts(&conn);
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "claim",
            &open,
            "ambiguous"
        )
        .unwrap(),
        claim
    );
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("alice"),
            "claim",
            &released,
            "ambiguous"
        )
        .unwrap_err()
        .0,
        409
    );
    assert_eq!(counts(&conn), before);
    conn.execute(
        "UPDATE memberships SET revoked_at=2 WHERE principal_id='bob'",
        [],
    )
    .unwrap();
    for action in ["release", "complete"] {
        assert_eq!(
            change(&mut conn, Actor::Agent("bob"), action, &next, "revoked")
                .unwrap_err()
                .0,
            404
        );
    }
    assert_eq!(
        change(
            &mut conn,
            Actor::Agent("bob"),
            "claim",
            &released,
            "reclaim"
        )
        .unwrap_err()
        .0,
        404
    );
    let reassigned = mutate(
        &mut conn,
        "owned",
        Actor::Operator,
        Mutation::Reassign {
            work_id: next["work_id"].as_str().unwrap().into(),
            expected_version: next["version"].as_i64().unwrap(),
            expected_generation: 2,
            agent_id: "alice".into(),
        },
        Some("recover"),
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(reassigned["claim_generation"], 3);
    let done = change(
        &mut conn,
        Actor::Agent("alice"),
        "complete",
        &reassigned,
        "done",
    )
    .unwrap()["work"]
        .clone();
    assert_eq!(done["state"], "done");
    assert!(change(&mut conn, Actor::Operator, "release", &done, "reopen").is_err());
    let original = revision(&conn, "rm-owned", open["work_id"].as_str().unwrap(), 1).unwrap();
    assert_eq!(original, open);
    assert!(
        conn.execute("UPDATE coord_work_revisions SET content_hash='changed'", [])
            .is_err()
    );
    assert!(
        conn.execute("DELETE FROM coord_work_revisions", [])
            .is_err()
    );
    let audit: String = conn
        .query_row(
            "SELECT group_concat(payload_json) FROM coord_outbox",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!audit.contains("Private title"));
    assert!(!audit.contains("external-description"));
    for record in conn
        .prepare("SELECT payload_json FROM coord_outbox WHERE destination='audit-jsonl'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
    {
        crate::audit::parse_record(&record.unwrap()).unwrap();
    }
}

#[test]
fn simultaneous_claims_have_one_owner_for_two_and_one_hundred_attempts() {
    for attempts in [2, 100] {
        let root = fixture();
        let open = create(&mut db(&root))["work"].clone();
        let barrier = Arc::new(Barrier::new(attempts));
        let threads: Vec<_> = (0..attempts)
            .map(|n| {
                let path = root.path().to_owned();
                let open = open.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut conn = super::super::open(&path).unwrap();
                    barrier.wait();
                    change(
                        &mut conn,
                        Actor::Agent(if n % 2 == 0 { "alice" } else { "bob" }),
                        "claim",
                        &open,
                        &format!("claim-{n}"),
                    )
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| e.0 == 409),
            "{:?}",
            results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .collect::<Vec<_>>()
        );
        let conn = db(&root);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM coord_work_revisions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}

#[test]
fn failure_at_each_write_rolls_back_projection_history_retry_audit_and_attention() {
    for table in [
        "coord_work_revisions",
        "coord_work",
        "coord_operations",
        "coord_attention_edges",
        "coord_outbox",
    ] {
        let root = fixture();
        let mut conn = db(&root);
        let open = create(&mut conn)["work"].clone();
        let before = counts(&conn);
        // The projection takes INSERT .. ON CONFLICT for both create and update.
        conn.execute_batch(&format!("CREATE TRIGGER fail BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
        assert!(change(&mut conn, Actor::Agent("alice"), "claim", &open, "retry").is_err());
        assert_eq!(counts(&conn), before);
        assert_eq!(
            read(
                &mut conn,
                "owned",
                Actor::Operator,
                open["work_id"].as_str().unwrap()
            )
            .unwrap(),
            open
        );
        conn.execute_batch("DROP TRIGGER fail").unwrap();
        assert_eq!(
            change(&mut conn, Actor::Agent("alice"), "claim", &open, "retry").unwrap()["work"]["claim_generation"],
            1
        );
    }
}

#[test]
fn bounded_reads_cross_room_refusal_and_untrusted_inputs() {
    let root = fixture();
    let mut conn = db(&root);
    let open = create(&mut conn)["work"].clone();
    let id = open["work_id"].as_str().unwrap();
    assert_eq!(
        read(&mut conn, "other", Actor::Operator, id).unwrap_err().0,
        404
    );
    assert!(
        mutate(
            &mut conn,
            "owned",
            Actor::Operator,
            Mutation::Create {
                title: " ".into(),
                external_ref: None
            },
            None
        )
        .is_err()
    );
    assert!(
        mutate(
            &mut conn,
            "owned",
            Actor::Operator,
            Mutation::Create {
                title: "x".repeat(MAX_REQUEST_BYTES),
                external_ref: None
            },
            None
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<Mutation>(
            json!({"action":"create","title":"x","created_by":"operator"})
        )
        .is_err()
    );
    assert!(list(&mut conn, "owned", Actor::Operator, "", 201, None).is_err());
    assert!(
        list(
            &mut conn,
            "owned",
            Actor::Operator,
            "",
            1,
            Some("cancelled")
        )
        .is_err()
    );
    for n in 0..3 {
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            Mutation::Create {
                title: format!("item {n}"),
                external_ref: None,
            },
            None,
        )
        .unwrap();
    }
    let page = list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        "",
        2,
        Some("open"),
    )
    .unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    let next = list(
        &mut conn,
        "owned",
        Actor::Agent("reader"),
        page["next_after"].as_str().unwrap(),
        2,
        Some("open"),
    )
    .unwrap();
    assert_eq!(next["items"].as_array().unwrap().len(), 2);
    assert_eq!(next["next_after"], Value::Null);
    assert_ne!(page["items"][0]["work_id"], next["items"][0]["work_id"]);
}
