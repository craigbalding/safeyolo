use super::*;
use std::{
    fs,
    sync::{Arc, Barrier},
};

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/instance_id"), "owned-instance").unwrap();
    fs::write(root.path().join("config.toml"), "admin_port=0\n").unwrap();
    super::super::bootstrap(root.path()).unwrap();
    let conn = db(&root);
    conn.execute("INSERT INTO rooms VALUES('rm-owned','owned',0)", [])
        .unwrap();
    conn.execute("INSERT INTO rooms VALUES('rm-other','other',0)", [])
        .unwrap();
    for (id, permissions) in [
        ("alice", "receive,send,page_operator"),
        ("bob", "receive,send"),
        ("reader", "receive"),
    ] {
        conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-owned','agent',?1,?2,1)",params![id,permissions]).unwrap();
    }
    root
}
fn db(root: &tempfile::TempDir) -> Connection {
    super::super::open(root.path()).unwrap()
}
fn create(summary: &str, kind: &str) -> Mutation {
    serde_json::from_value(
        json!({"action":"create","summary":summary,"kind":kind,"basis":"observed"}),
    )
    .unwrap()
}
fn correction(signal: &Value) -> Mutation {
    serde_json::from_value(json!({"action":"create","kind":"correction","summary":"The prior inference was wrong: the child inherited the lower soft limit","basis":"observed","supersedes":{"signal_id":signal["signal_id"],"expected_revision":signal["revision"]}})).unwrap()
}
fn pending(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT count(*) FROM coord_signals WHERE needs_operator=1",
        [],
        |r| r.get(0),
    )
    .unwrap()
}
fn rows(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn attributed_creation_dedup_replay_and_independent_page_permission() {
    let root = fixture();
    let mut conn = db(&root);
    let first = mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        create("Observed fork refusal", "blocker"),
        Some("first"),
    )
    .unwrap();
    assert_eq!(
        first["signal"]["author"],
        json!({"kind":"agent","id":"alice"})
    );
    assert_eq!(first["signal"]["page_status"], "paged");
    assert_eq!(pending(&conn), 1);
    assert_eq!(
        first,
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            create("Observed fork refusal", "blocker"),
            Some("first")
        )
        .unwrap()
    );
    let duplicate = mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        create("Observed fork refusal", "blocker"),
        Some("another-operation"),
    )
    .unwrap();
    assert_eq!(duplicate["signal"], first["signal"]);
    assert_eq!(duplicate["deduplicated"], true);
    assert_eq!(rows(&conn, "coord_signal_revisions"), 1);
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            create("changed", "blocker"),
            Some("first")
        )
        .unwrap_err()
        .0,
        409
    );
    let bob = mutate(
        &mut conn,
        "owned",
        Actor::Agent("bob"),
        create("Another attributed blocker", "blocker"),
        Some("first"),
    )
    .unwrap();
    assert_eq!(bob["signal"]["page_status"], "permission_denied");
    assert_eq!(pending(&conn), 1);
    super::super::membership::change(
        &conn,
        "rm-owned",
        "agent",
        "alice",
        &["send".into(), "receive".into()],
        false,
        "revoke-page",
    )
    .unwrap();
    let no_page = mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        create("Creation still works", "decision"),
        Some("unpaged"),
    )
    .unwrap();
    assert_eq!(no_page["signal"]["needs_operator"], false);
    assert_eq!(no_page["signal"]["page_status"], "permission_denied");
    // Revoking interruption does not erase an already pending claim.
    assert_eq!(pending(&conn), 1);
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("reader"),
            create("not a writer", "result"),
            None
        )
        .unwrap_err()
        .0,
        403
    );
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("stranger"),
            create("not a member", "result"),
            None
        )
        .unwrap_err()
        .0,
        404
    );
    conn.execute(
        "UPDATE memberships SET revoked_at=10 WHERE principal_id='alice'",
        [],
    )
    .unwrap();
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            create("Observed fork refusal", "blocker"),
            Some("first")
        )
        .unwrap_err()
        .0,
        404
    );
}

#[test]
fn corrections_preserve_history_and_resolution_never_changes_the_author() {
    let root = fixture();
    let mut conn = db(&root);
    let result=mutate(&mut conn,"owned",Actor::Agent("alice"),serde_json::from_value(json!({"action":"create","kind":"result","summary":"I infer that host RLIMIT_NPROC is low","basis":"inferred","refs":["opaque:original-symptom"]})).unwrap(),Some("result")).unwrap();
    assert_eq!(pending(&conn), 0);
    let signal = &result["signal"];
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("bob"),
            correction(signal),
            Some("peer")
        )
        .unwrap_err()
        .0,
        403
    );
    assert_eq!(
        mutate(
            &mut conn,
            "other",
            Actor::Operator,
            correction(signal),
            None
        )
        .unwrap_err()
        .0,
        404
    );
    let corrected = mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        correction(signal),
        Some("correct"),
    )
    .unwrap();
    let id = signal["signal_id"].as_str().unwrap();
    assert_eq!(
        read(&mut conn, "owned", Actor::Agent("alice"), id, Some(1)).unwrap()["signal"],
        *signal
    );
    let old = read(&mut conn, "owned", Actor::Agent("bob"), id, None).unwrap();
    assert_eq!(old["signal"]["state"], "superseded");
    assert_eq!(old["signal"]["revision"], 2);
    assert_eq!(
        old["signal"]["superseded_by"],
        corrected["signal"]["signal_id"]
    );
    assert_eq!(
        list(&mut conn, "owned", Actor::Agent("bob"), "", 50, None, false).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            correction(signal),
            Some("stale")
        )
        .unwrap_err()
        .0,
        409
    );
    let blocker = mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        create("Needs operator answer", "decision"),
        Some("page"),
    )
    .unwrap();
    let resolve = || Mutation::Resolve {
        signal_id: blocker["signal"]["signal_id"].as_str().unwrap().into(),
        expected_revision: 1,
    };
    assert_eq!(
        mutate(&mut conn, "owned", Actor::Agent("alice"), resolve(), None)
            .unwrap_err()
            .0,
        403
    );
    let resolved = mutate(
        &mut conn,
        "owned",
        Actor::Operator,
        resolve(),
        Some("resolve"),
    )
    .unwrap();
    assert_eq!(resolved["signal"]["author"], blocker["signal"]["author"]);
    assert_eq!(resolved["signal"]["state"], "resolved");
    assert_eq!(pending(&conn), 0);
    assert_eq!(
        resolved,
        mutate(
            &mut conn,
            "owned",
            Actor::Operator,
            resolve(),
            Some("resolve")
        )
        .unwrap()
    );
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Operator,
            resolve(),
            Some("stale-resolution")
        )
        .unwrap_err()
        .0,
        409
    );
    assert!(
        conn.execute("UPDATE coord_signal_revisions SET document_json='{}'", [])
            .is_err()
    );
    assert!(
        conn.execute("DELETE FROM coord_signal_revisions", [])
            .is_err()
    );
    let events: Vec<String> = conn
        .prepare("SELECT payload_json FROM coord_outbox")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!events.iter().any(|e| e.contains("RLIMIT_NPROC")
        || e.contains("Needs operator answer")
        || e.contains("original-symptom")));
    assert!(events.iter().all(|e| crate::audit::parse_record(e).is_ok()));
}

#[test]
fn bounds_pagination_and_rates_keep_claims_without_unbounded_pages() {
    let root = fixture();
    let mut conn = db(&root);
    for n in 0..6 {
        let value = mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            create(&format!("blocker-{n}"), "blocker"),
            None,
        )
        .unwrap();
        assert_eq!(value["signal"]["needs_operator"], n < 5);
        if n == 5 {
            assert_eq!(value["signal"]["page_status"], "rate_limited");
        }
    }
    assert_eq!(rows(&conn, "coord_signals"), 6);
    assert_eq!(pending(&conn), 5);
    assert!(
        !page_limited(
            &conn,
            "rm-owned",
            Actor::Agent("alice"),
            now() + PAGE_WINDOW_MS + 1
        )
        .unwrap()
    );
    for id in ["bob", "carol", "dave", "erin"] {
        super::super::membership::change(
            &conn,
            "rm-owned",
            "agent",
            id,
            &[],
            false,
            &format!("default-{id}"),
        )
        .unwrap();
        for n in 0..5 {
            mutate(
                &mut conn,
                "owned",
                Actor::Agent(id),
                create(&format!("{id}-{n}"), "decision"),
                None,
            )
            .unwrap();
        }
    }
    assert_eq!(pending(&conn), 20);
    assert_eq!(
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("bob"),
            create(&"π".repeat(513), "result"),
            None
        )
        .unwrap_err()
        .0,
        400
    );
    for payload in [
        json!({"action":"create","kind":"result","summary":"forged","basis":"observed","author":{"kind":"operator"}}),
        json!({"action":"create","kind":"free-form","summary":"x","basis":"observed"}),
        json!({"action":"create","kind":"result","summary":"x","basis":"truth"}),
    ] {
        assert!(serde_json::from_value::<Mutation>(payload).is_err());
    }
    let oversized=serde_json::from_value(json!({"action":"create","kind":"result","summary":"x","basis":"observed","refs":vec!["x";17]})).unwrap();
    assert_eq!(
        mutate(&mut conn, "owned", Actor::Agent("bob"), oversized, None)
            .unwrap_err()
            .0,
        400
    );
    for n in 0..12 {
        let value=serde_json::from_value(json!({"action":"create","kind":"result","summary":format!("large-{n}"),"basis":"observed","refs":vec!["x".repeat(1024);16]})).unwrap();
        mutate(&mut conn, "owned", Actor::Agent("bob"), value, None).unwrap();
    }
    let mut after = String::new();
    let mut ids = Vec::new();
    loop {
        let p = list(
            &mut conn,
            "owned",
            Actor::Agent("bob"),
            &after,
            100,
            None,
            false,
        )
        .unwrap();
        assert!(p.to_string().len() < MAX_PAGE_BYTES + 1024);
        ids.extend(
            p["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["signal"]["signal_id"].as_str().unwrap().to_owned()),
        );
        match p["next_after"].as_str() {
            Some(next) => {
                assert!(next > after.as_str());
                after = next.into();
            }
            None => break,
        }
    }
    assert_eq!(ids.len() as i64, rows(&conn, "coord_signals"));
    let unique = ids.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), ids.len());
}

#[test]
fn completion_retains_one_result_without_manufacturing_a_signal() {
    let root = fixture();
    let mut conn = db(&root);
    let work = work::mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        work::Mutation::Create {
            title: "Real work".into(),
            external_ref: None,
        },
        Some("create"),
    )
    .unwrap();
    let id = work["work"]["work_id"].as_str().unwrap().to_owned();
    work::mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        work::Mutation::Claim {
            work_id: id.clone(),
            expected_version: 1,
            expected_generation: 0,
        },
        Some("claim"),
    )
    .unwrap();
    let complete = || work::Mutation::Complete {
        work_id: id.clone(),
        expected_version: 2,
        expected_generation: 1,
        short_result: Some("one concise completion".into()),
    };
    let result = work::mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        complete(),
        Some("done"),
    )
    .unwrap();
    assert_eq!(
        result,
        work::mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            complete(),
            Some("done")
        )
        .unwrap()
    );
    assert_eq!(result["work"]["short_result"], "one concise completion");
    assert_eq!(rows(&conn, "coord_signals"), 0);
    assert_eq!(rows(&conn, "coord_signal_revisions"), 0);
    let linked=serde_json::from_value(json!({"action":"create","kind":"result","summary":"Separately material finding","basis":"observed","work_id":id})).unwrap();
    let signal = mutate(&mut conn, "owned", Actor::Agent("alice"), linked, None).unwrap();
    assert_eq!(signal["signal"]["work_id"], id);
    let wrong=serde_json::from_value(json!({"action":"create","kind":"result","summary":"cross room","basis":"observed","work_id":id})).unwrap();
    assert_eq!(
        mutate(&mut conn, "other", Actor::Operator, wrong, None)
            .unwrap_err()
            .0,
        404
    );
}

#[test]
fn every_write_failure_rolls_back_correction_history_projection_retry_and_audit() {
    for table in [
        "coord_signal_revisions",
        "coord_signals",
        "coord_operations",
        "coord_outbox",
    ] {
        let root = fixture();
        let mut conn = db(&root);
        let original = mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            create("Initial claim", "result"),
            Some("original"),
        )
        .unwrap();
        let counts = [
            rows(&conn, "coord_signal_revisions"),
            rows(&conn, "coord_signals"),
            rows(&conn, "coord_operations"),
            rows(&conn, "coord_outbox"),
        ];
        conn.execute_batch(&format!("CREATE TRIGGER inject_failure BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected write failure'); END;")).unwrap();
        assert!(
            mutate(
                &mut conn,
                "owned",
                Actor::Agent("alice"),
                correction(&original["signal"]),
                Some("repair")
            )
            .is_err()
        );
        assert_eq!(
            counts,
            [
                rows(&conn, "coord_signal_revisions"),
                rows(&conn, "coord_signals"),
                rows(&conn, "coord_operations"),
                rows(&conn, "coord_outbox")
            ]
        );
        assert_eq!(
            read(
                &mut conn,
                "owned",
                Actor::Agent("alice"),
                original["signal"]["signal_id"].as_str().unwrap(),
                None
            )
            .unwrap()["signal"],
            original["signal"]
        );
        conn.execute_batch("DROP TRIGGER inject_failure").unwrap();
        let corrected = mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            correction(&original["signal"]),
            Some("repair"),
        )
        .unwrap();
        assert_eq!(corrected["signal"]["revision"], 1);
    }
}

#[test]
fn concurrent_corrections_choose_one_revision_and_revoke_wins_before_waiting_write() {
    let root = fixture();
    let mut conn = db(&root);
    let original = mutate(
        &mut conn,
        "owned",
        Actor::Agent("alice"),
        create("Mistaken inference", "result"),
        Some("original"),
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|n| {
            let path = root.path().to_owned();
            let barrier = barrier.clone();
            let signal = original["signal"].clone();
            std::thread::spawn(move || {
                let mut conn = super::super::open(&path).unwrap();
                barrier.wait();
                mutate(
                    &mut conn,
                    "owned",
                    Actor::Agent("alice"),
                    correction(&signal),
                    Some(&format!("correction-{n}")),
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
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let path = root.path().to_owned();
    let waiter = std::thread::spawn(move || {
        let mut conn = super::super::open(&path).unwrap();
        mutate(
            &mut conn,
            "owned",
            Actor::Agent("alice"),
            create("after revoke", "blocker"),
            Some("waiting"),
        )
    });
    tx.execute(
        "UPDATE memberships SET revoked_at=42 WHERE principal_id='alice'",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(waiter.join().unwrap().unwrap_err().0, 404);
}
