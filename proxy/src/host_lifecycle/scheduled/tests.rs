use super::*;

#[test]
fn configured_limits_do_not_become_continuous_defaults() {
    let continuous = configuration(&json!({"mode":"continuous"})).unwrap();
    assert_eq!(cutoff(&continuous, 1000, 2000).unwrap(), None);
    let scheduled = configuration(&json!({"mode":"scheduled","schedule":"0 0 2 * * *",
        "timezone":"Europe/Budapest","window_seconds":14400,"stop_after_seconds":7200}))
    .unwrap();
    assert_eq!(cutoff(&scheduled, 1000, 2000).unwrap(), Some(7_202_000));
    assert!(configuration(&json!({"mode":"scheduled","schedule":"0 0 2 * * *"})).is_err());
    assert!(configuration(&json!({"mode":"on_demand","completion_check":"done"})).is_err());
    assert!(configuration(&json!({"mode":"continuous","host_command":"shutdown"})).is_err());
}

#[test]
fn expired_boundaries_and_overflow_are_explicit() {
    let config =
        configuration(&json!({"mode":"on_demand","stop_by":"2026-11-20T02:00:00Z"})).unwrap();
    assert_eq!(
        cutoff(&config, 0, 0).unwrap(),
        Some(timestamp("2026-11-20T02:00:00Z").unwrap())
    );
    assert!(configuration(&json!({"mode":"continuous","stop_after_seconds":u64::MAX})).is_err());
}

#[test]
fn cutoff_is_exact_and_never_replays_an_uncertain_effect() {
    let event = json!({"activation_id":"activation-a","run_id":"run-a",
        "configuration_revision":"revision-a","stop_by":70000});
    let mut state = event.clone();
    state["phase"] = json!("active");
    assert!(current_cutoff(&state, &event));
    for (key, replacement) in [
        ("activation_id", json!("activation-b")),
        ("run_id", json!("run-b")),
        ("configuration_revision", json!("revision-b")),
        ("stop_by", json!(80000)),
        ("phase", json!("stopped")),
        ("cutoff_attempted_at", json!(60000)),
    ] {
        let mut changed = state.clone();
        changed[key] = replacement;
        assert!(!current_cutoff(&changed, &event), "{key}");
    }
}

pub(super) fn work_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("data")).unwrap();
    std::fs::write(root.path().join("config.toml"), "").unwrap();
    std::fs::write(root.path().join("data/instance_id"), "sy-lifecycle-proof").unwrap();
    coord_rooms::bootstrap(root.path()).unwrap();
    let conn = coord_rooms::open(root.path()).unwrap();
    conn.execute("INSERT INTO rooms VALUES('rm-work','work',0)", [])
        .unwrap();
    conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-work','agent','worker','send,receive',1)",[]).unwrap();
    root
}

pub(super) fn change(conn: &mut Connection, input: Value, op: &str) -> Value {
    crate::coord_rooms::work::mutate(
        None,
        conn,
        "work",
        crate::coord_rooms::work::Actor::Agent("worker"),
        serde_json::from_value(input).unwrap(),
        Some(op),
    )
    .unwrap()
}

#[test]
fn self_assignment_delivery_output_and_shutdown_arrivals_retain_canonical_work() {
    use crate::coord_rooms::work::{self, Actor};
    let root = work_fixture();
    let mut conn = coord_rooms::open(root.path()).unwrap();
    let work = change(
        &mut conn,
        json!({"action":"create","title":"Useful follow-up",
        "assignee":{"kind":"agent","id":"worker"}}),
        "create",
    )["work"]
        .clone();
    assert_eq!(work["created_by"], json!({"kind":"agent","id":"worker"}));
    let id = work["work_id"].as_str().unwrap();
    let actions =
        work::actions::read(&mut conn, "work", Actor::Agent("worker"), id, false).unwrap();
    assert_eq!(actions["actions"][0]["kind"], "execute_work");
    let attention:i64=conn.query_row("SELECT count(*) FROM coord_attention_edges WHERE recipient_agent_id='worker' AND object_id=?1",[id],|r|r.get(0)).unwrap();
    assert!(
        attention > 0,
        "self-create must deliver attention to its creator/assignee"
    );
    let mut current = change(
        &mut conn,
        json!({"action":"claim","work_id":id,
        "expected_version":1,"expected_generation":0}),
        "claim",
    )["work"]
        .clone();
    // Reopen the same durable store after an interrupted model turn.
    drop(conn);
    let mut conn = coord_rooms::open(root.path()).unwrap();
    assert_eq!(
        work::read(&mut conn, "work", Actor::Agent("worker"), id).unwrap()["state"],
        "claimed"
    );
    current = change(
        &mut conn,
        json!({"action":"publish_output","work_id":id,
        "expected_version":current["version"],"expected_generation":current["claim_generation"],
        "expected_target_generation":0,"target_ref":"sha256:retained-artifact",
        "execution_outcome":"succeeded","summary":"Useful retained result","evidence_refs":[]}),
        "output",
    )["work"]
        .clone();
    assert_eq!(
        current["state"], "claimed",
        "publication must not complete execution"
    );
    current = change(
        &mut conn,
        json!({"action":"complete","work_id":id,
        "expected_version":current["version"],"expected_generation":current["claim_generation"],
        "short_result":"Result retained"}),
        "complete",
    )["work"]
        .clone();
    assert_eq!(current["state"], "done");
    save(
        &conn,
        "worker",
        &json!({"phase":"closing","completion_room_id":"rm-work"}),
    )
    .unwrap();
    let next = change(
        &mut conn,
        json!({"action":"create","title":"Arrival after closure",
        "assignee":{"kind":"agent","id":"worker"}}),
        "arrival",
    )["work"]
        .clone();
    let next_id = next["work_id"].as_str().unwrap();
    assert_eq!(
        work::actions::read(&mut conn, "work", Actor::Agent("worker"), next_id, false).unwrap()["actions"]
            [0]["kind"],
        "execute_work"
    );
    let claim =
        json!({"action":"claim","work_id":next_id,"expected_version":1,"expected_generation":0});
    assert!(
        work::mutate(
            None,
            &mut conn,
            "work",
            Actor::Agent("worker"),
            serde_json::from_value(claim.clone()).unwrap(),
            Some("closed-claim")
        )
        .unwrap_err()
        .to_string()
        .contains("scope is closed")
    );
    save(
        &conn,
        "worker",
        &json!({"phase":"active","completion_room_id":"rm-work"}),
    )
    .unwrap();
    assert_eq!(
        change(&mut conn, claim, "next-activation-claim")["work"]["state"],
        "claimed"
    );
    assert_eq!(
        work::read(&mut conn, "work", Actor::Agent("worker"), id).unwrap()["target_ref"],
        "sha256:retained-artifact"
    );
}
