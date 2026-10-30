use super::*;
use crate::coord_rooms::{signals, work};
use std::{fs, sync::mpsc, time::Instant};

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/instance_id"), "sy-inventory").unwrap();
    fs::write(root.path().join("config.toml"), "admin_port=0\n").unwrap();
    fs::write(root.path().join("policy.toml"), format!("[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.bob.services]\nrundeck={{capability='acceptance_runner',token='PRIVATE-CREDENTIAL',account='PRIVATE-ACCOUNT'}}\ngithub='writer'\nother={{role='reader'}}\n")).unwrap();
    crate::coord_rooms::bootstrap(root.path()).unwrap();
    let conn = open_db(&root.path().join("data/coord/v0.db"), true).unwrap();
    conn.execute("INSERT INTO rooms VALUES('rm-inventory','shared',0)", [])
        .unwrap();
    for id in [ALICE, BOB] {
        conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-inventory','agent',?1,'receive,send',1)",[id]).unwrap();
    }
    conn.execute("INSERT INTO coord_capability_advertisements VALUES('rm-inventory',?1,'rundeck:acceptance_runner','advertisement',1)",[BOB]).unwrap();
    conn.execute("INSERT INTO coord_resource_advertisements VALUES('rm-inventory','rundeck','runner','resource',1)",[]).unwrap();
    fs::create_dir(root.path().join("coord-providers")).unwrap();
    root
}

fn observation(now: i64) -> Value {
    json!({"capabilities":[{"agent_id":BOB,"capability":"rundeck:acceptance_runner","availability":"available","observed_at":now-10,"valid_until":now+1000,"token":"PRIVATE-RAW-TOKEN","route":"PRIVATE-ROUTE"}],"leases":[{"resource":"runner","state":"held","holder_agent_id":BOB,"observed_at":now-10,"valid_until":now+1000,"account":"PRIVATE-LEASE-ACCOUNT"}],"error":"PRIVATE-RAW-ERROR"})
}
fn write(root: &Path, value: &Value) {
    let temp = root.join("coord-providers/new.json");
    fs::write(&temp, value.to_string()).unwrap();
    fs::rename(temp, root.join("coord-providers/rundeck.json")).unwrap();
}
fn read(root: &Path) -> Inventory {
    read_inventory(
        &root.join("data/coord/v0.db"),
        Some(&root.join("policy.toml")),
        "shared",
        "agent",
        ALICE,
    )
    .unwrap()
}
fn member(state: &Value, id: &str) -> Value {
    state["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["agent_id"] == id)
        .unwrap()
        .clone()
}

fn pause_provider(client: &CoordClient) -> (tokio::sync::oneshot::Receiver<()>, mpsc::Sender<()>) {
    let (entered, started) = tokio::sync::oneshot::channel();
    let entered = Mutex::new(Some(entered));
    let (release, blocked) = mpsc::channel();
    let blocked = Mutex::new(blocked);
    *client.owner.snapshot_reads.before_read.lock().unwrap() = Some(Arc::new(move |provider| {
        if provider == "rundeck" {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            blocked
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
    }));
    (started, release)
}

fn work_mutation(
    conn: &mut rusqlite::Connection,
    actor: work::Actor<'_>,
    input: Value,
    op: &str,
) -> Value {
    work::mutate(
        conn,
        "shared",
        actor,
        serde_json::from_value(input).unwrap(),
        Some(op),
    )
    .unwrap()["work"]
        .clone()
}
fn signal_mutation(
    conn: &mut rusqlite::Connection,
    actor: work::Actor<'_>,
    input: Value,
    op: &str,
) -> Value {
    signals::mutate(
        conn,
        "shared",
        actor,
        serde_json::from_value(input).unwrap(),
        Some(op),
    )
    .unwrap()
}
fn signal_input(kind: &str, summary: &str) -> Value {
    json!({"action":"create","kind":kind,"summary":summary,"basis":"inferred"})
}

#[test]
fn combined_status_uses_current_claims_corrections_and_brief_without_chat() {
    let root = fixture();
    let mut conn = open_db(&root.path().join("data/coord/v0.db"), true).unwrap();
    let created = work_mutation(
        &mut conn,
        work::Actor::Agent(BOB),
        json!({"action":"create","title":"repair failure"}),
        "create",
    );
    let owned = work_mutation(
        &mut conn,
        work::Actor::Agent(BOB),
        json!({"action":"claim","work_id":created["work_id"],"expected_version":1,"expected_generation":0}),
        "claim",
    );
    let reassigned = work_mutation(
        &mut conn,
        work::Actor::Operator,
        json!({"action":"reassign","work_id":owned["work_id"],"agent_id":ALICE,"expected_version":2,"expected_generation":1}),
        "reassign",
    );
    // A crossed completion from the former holder cannot become current fact.
    assert!(work::mutate(&mut conn,"shared",work::Actor::Agent(BOB),serde_json::from_value(json!({"action":"complete","work_id":owned["work_id"],"expected_version":2,"expected_generation":1})).unwrap(),Some("stale-complete")).is_err());
    let released = work_mutation(
        &mut conn,
        work::Actor::Agent(ALICE),
        json!({"action":"release","work_id":reassigned["work_id"],"expected_version":3,"expected_generation":2}),
        "release",
    );
    let initial = read(root.path());
    assert_eq!(initial.active_work["items"][0]["state"], "open");
    assert!(initial.active_work["items"][0]["claim_agent_id"].is_null());
    let reclaimed = work_mutation(
        &mut conn,
        work::Actor::Agent(ALICE),
        json!({"action":"claim","work_id":released["work_id"],"expected_version":4,"expected_generation":2}),
        "reclaim",
    );
    work_mutation(
        &mut conn,
        work::Actor::Agent(ALICE),
        json!({"action":"complete","work_id":reclaimed["work_id"],"expected_version":5,"expected_generation":3,"short_result":"measured repair passed"}),
        "complete",
    );
    let old = signal_mutation(
        &mut conn,
        work::Actor::Agent(BOB),
        signal_input("result", "obsolete hypothesis"),
        "old",
    );
    let mut correction = signal_input(
        "correction",
        "\u{001b}[2J\nforged row\u{202e} measured correction",
    );
    correction["supersedes"] =
        json!({"signal_id":old["signal"]["signal_id"],"expected_revision":1});
    let corrected = signal_mutation(&mut conn, work::Actor::Agent(BOB), correction, "correction");
    crate::coord_rooms::brief::set(
        root.path(),
        "shared",
        &format!("Repair the failure. {}", "🦀".repeat(1000)),
        0,
        Some("brief"),
    )
    .unwrap();
    let at = now_ms();
    let current = read(root.path());
    let state = project(current, &initial, &BTreeMap::new(), at).unwrap();
    let again = project(read(root.path()), &initial, &BTreeMap::new(), at + 1).unwrap();
    assert_eq!(state, again);
    assert_eq!(state["active_work"]["total"], 0);
    assert_eq!(
        state["completed_work"]["items"][0]["short_result"],
        "measured repair passed"
    );
    assert_eq!(state["latest_results"]["total"], 1);
    assert_eq!(
        state["latest_results"]["items"][0]["signal"]["signal_id"],
        corrected["signal"]["signal_id"]
    );
    assert_eq!(state["brief"]["revision"], 1);
    assert_eq!(state["brief"]["truncated"], true);
    assert!(state.get("goal").is_none() && state.get("priority").is_none());
    let output = room_status::render(&state);
    for title in [
        "Brief v1",
        "Members",
        "Active work",
        "Completed work",
        "Needs operator",
        "Latest material results",
    ] {
        assert!(output.contains(title));
    }
    assert!(!output.contains("obsolete hypothesis"));
    assert!(!output.contains('\u{001b}') && !output.contains('\u{202e}'));
    assert!(output.contains("\\nforged row"));
}

#[tokio::test]
async fn combined_status_refreshes_work_and_brief_during_provider_io() {
    let root = fixture();
    write(root.path(), &observation(now_ms()));
    let client = Arc::new(CoordClient::new(
        Some(root.path().join("policy.toml")),
        Some(root.path().join("data/coord")),
    ));
    let (started, release) = pause_provider(&client);
    let request = tokio::spawn({
        let client = client.clone();
        async move { room_state(&client, "shared", "agent", ALICE, None).await }
    });
    started.await.unwrap();
    let mut conn = open_db(&root.path().join("data/coord/v0.db"), true).unwrap();
    work_mutation(
        &mut conn,
        work::Actor::Agent(BOB),
        json!({"action":"create","title":"created during provider read"}),
        "during-io",
    );
    signal_mutation(
        &mut conn,
        work::Actor::Agent(BOB),
        signal_input("result", "current result during provider read"),
        "during-io",
    );
    crate::coord_rooms::brief::set(
        root.path(),
        "shared",
        "Latest objective during provider read",
        0,
        Some("during-io"),
    )
    .unwrap();
    release.send(()).unwrap();
    let state = request.await.unwrap().unwrap();
    assert_eq!(state["active_work"]["total"], 1);
    assert_eq!(state["latest_results"]["total"], 1);
    assert_eq!(
        state["brief"]["excerpt"],
        "Latest objective during provider read"
    );
}

#[test]
fn large_combined_state_reports_bounds_and_stable_order() {
    let root = fixture();
    let mut conn = open_db(&root.path().join("data/coord/v0.db"), true).unwrap();
    for n in (0..75).rev() {
        conn.execute("INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at) VALUES('rm-inventory','agent',?1,'receive',1)",[format!("ag-{n:032x}")]).unwrap();
        work_mutation(
            &mut conn,
            work::Actor::Operator,
            json!({"action":"create","title":"\u{001b}".repeat(20000)}),
            &format!("work-{n}"),
        );
        signal_mutation(
            &mut conn,
            work::Actor::Operator,
            signal_input("result", &format!("{n} {}", "\u{001b}".repeat(1000))),
            &format!("result-{n}"),
        );
    }
    let initial = read(root.path());
    let at = now_ms();
    let state = project(read(root.path()), &initial, &BTreeMap::new(), at).unwrap();
    assert!(state.to_string().len() <= MAX_STATE_BYTES);
    assert_eq!(state["bounds"]["members"]["total"], 77);
    assert_eq!(state["bounds"]["members"]["shown"], 50);
    assert_eq!(state["bounds"]["members"]["truncated"], true);
    assert_eq!(state["active_work"]["total"], 75);
    assert_eq!(state["active_work"]["truncated"], true);
    assert_eq!(state["latest_results"]["total"], 75);
    assert_eq!(state["latest_results"]["truncated"], true);
    let results = state["latest_results"]["items"].as_array().unwrap();
    assert!(results.windows(2).all(|pair| {
        let a = &pair[0]["signal"];
        let b = &pair[1]["signal"];
        a["updated_at"].as_i64() > b["updated_at"].as_i64()
            || (a["updated_at"] == b["updated_at"]
                && a["signal_id"].as_str() < b["signal_id"].as_str())
    }));
    let ids = state["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["agent_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        state,
        project(read(root.path()), &initial, &BTreeMap::new(), at).unwrap()
    );
}

#[tokio::test]
async fn state_rechecks_authority_and_advertisements_after_paused_provider_io() {
    for change in [
        "caller_receive_revoked",
        "caller_identity_replaced",
        "peer_grant_revoked",
        "capability_removed",
        "resource_removed",
        "holder_removed",
        "capability_added",
        "resource_added",
    ] {
        let root = fixture();
        write(root.path(), &observation(now_ms()));
        let client = Arc::new(CoordClient::new(
            Some(root.path().join("policy.toml")),
            Some(root.path().join("data/coord")),
        ));
        let conn = open_db(&root.path().join("data/coord/v0.db"), true).unwrap();
        if change == "capability_added" {
            conn.execute("DELETE FROM coord_capability_advertisements", [])
                .unwrap();
        } else if change == "resource_added" {
            conn.execute("DELETE FROM coord_resource_advertisements", [])
                .unwrap();
        }
        let (started, release) = pause_provider(&client);
        let request = tokio::spawn({
            let client = client.clone();
            async move { room_state(&client, "shared", "agent", ALICE, None).await }
        });
        tokio::time::timeout(Duration::from_secs(1), started)
            .await
            .unwrap()
            .unwrap();
        match change {
            "caller_receive_revoked" => {
                conn.execute(
                    "UPDATE memberships SET permissions='send' WHERE principal_id=?1",
                    [ALICE],
                )
                .unwrap();
            }
            "caller_identity_replaced" | "peer_grant_revoked" => {
                let policy = root.path().join("policy.toml");
                let source = fs::read_to_string(&policy).unwrap();
                fs::write(
                    &policy,
                    if change == "caller_identity_replaced" {
                        source.replace(ALICE, "ag-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                    } else {
                        source.replace("capability='acceptance_runner'", "capability='reader'")
                    },
                )
                .unwrap();
            }
            "capability_removed" => {
                conn.execute("DELETE FROM coord_capability_advertisements", [])
                    .unwrap();
            }
            "resource_removed" => {
                conn.execute("DELETE FROM coord_resource_advertisements", [])
                    .unwrap();
            }
            "holder_removed" => {
                conn.execute(
                    "UPDATE memberships SET revoked_at=2 WHERE principal_id=?1",
                    [BOB],
                )
                .unwrap();
            }
            "capability_added" => {
                conn.execute("INSERT INTO coord_capability_advertisements VALUES('rm-inventory',?1,'rundeck:acceptance_runner','during-io',2)", [BOB]).unwrap();
            }
            "resource_added" => {
                conn.execute("INSERT INTO coord_resource_advertisements VALUES('rm-inventory','rundeck','runner','during-io',2)", []).unwrap();
            }
            _ => unreachable!(),
        }
        release.send(()).unwrap();
        let result = request.await.unwrap();
        client
            .owner
            .snapshot_reads
            .before_read
            .lock()
            .unwrap()
            .take();
        match change {
            "caller_receive_revoked" => assert!(matches!(result, Err(CoordError::Forbidden))),
            "caller_identity_replaced" => assert!(matches!(result, Err(CoordError::NotFound))),
            _ => {
                let state = result.unwrap();
                match change {
                    "peer_grant_revoked" | "capability_removed" => {
                        assert_eq!(member(&state, BOB)["verified"], json!([]))
                    }
                    "resource_removed" => assert_eq!(state["resource_leases"], json!([])),
                    "holder_removed" | "resource_added" => {
                        assert_eq!(state["resource_leases"][0]["state"], "unknown");
                        assert!(state["resource_leases"][0]["holder_agent_id"].is_null());
                    }
                    "capability_added" => assert_eq!(
                        member(&state, BOB)["verified"][0]["availability"],
                        "unknown"
                    ),
                    _ => unreachable!(),
                }
                if matches!(change, "capability_added" | "resource_added") {
                    let next = room_state(&client, "shared", "agent", ALICE, None)
                        .await
                        .unwrap();
                    assert_eq!(
                        member(&next, BOB)["verified"][0]["availability"],
                        "available"
                    );
                    assert_eq!(next["resource_leases"][0]["holder_agent_id"], BOB);
                }
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn production_observation_timeout_retains_worker_permit_and_recovers() {
    let root = fixture();
    write(root.path(), &observation(now_ms()));
    let client = Arc::new(CoordClient::new(
        Some(root.path().join("policy.toml")),
        Some(root.path().join("data/coord")),
    ));
    let (started, release) = pause_provider(&client);
    let request = tokio::spawn({
        let client = client.clone();
        async move { room_state(&client, "shared", "agent", ALICE, None).await }
    });
    started.await.unwrap();
    // The actual one-second observation wait leaves the event loop and the
    // independent current-state reader usable while the provider is blocked.
    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(500),
            read_current(&client, "shared", "agent", ALICE)
        )
        .await
        .unwrap()
        .unwrap()
        .access
        .room_name,
        "shared"
    );
    let state = tokio::time::timeout(READ_TIMEOUT + Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        member(&state, BOB)["verified"][0]["availability"],
        "unknown"
    );
    assert!(state["resource_leases"][0]["holder_agent_id"].is_null());
    assert_eq!(
        client
            .owner
            .snapshot_reads
            .providers
            .lock()
            .unwrap()
            .get("rundeck"),
        Some(&1)
    );
    client
        .owner
        .snapshot_reads
        .before_read
        .lock()
        .unwrap()
        .take();
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while client
            .owner
            .snapshot_reads
            .providers
            .lock()
            .unwrap()
            .contains_key("rundeck")
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    write(root.path(), &observation(now_ms()));
    let state = room_state(&client, "shared", "agent", ALICE, None)
        .await
        .unwrap();
    assert_eq!(
        member(&state, BOB)["verified"][0]["availability"],
        "available"
    );
    assert_eq!(state["resource_leases"][0]["holder_agent_id"], BOB);
}

#[test]
fn lease_freshness_boundaries_hide_noncurrent_holders() {
    let root = fixture();
    let now = 1_000_000;
    let initial = read(root.path());
    for (observed, until, freshness, state) in [
        (now - MAX_TTL_MS + 1, now + 1, "fresh", "held"),
        (now - MAX_TTL_MS, now + 1, "unknown", "unknown"),
        (now + 1, now + 2, "unknown", "unknown"),
        (now, now, "unknown", "unknown"),
        (now, now - 1, "unknown", "unknown"),
        (now - 1000, now, "stale", "unknown"),
    ] {
        let mut value = observation(now);
        value["leases"][0]["observed_at"] = json!(observed);
        value["leases"][0]["valid_until"] = json!(until);
        let evidence = BTreeMap::from([("rundeck".into(), serde_json::from_value(value).unwrap())]);
        let result = project(read(root.path()), &initial, &evidence, now).unwrap();
        let lease = &result["resource_leases"][0];
        assert_eq!(lease["freshness"], freshness);
        assert_eq!(lease["state"], state);
        if state == "held" {
            assert_eq!(lease["holder_agent_id"], BOB);
        } else {
            assert!(lease["holder_agent_id"].is_null());
        }
    }
}

#[tokio::test]
async fn current_grant_advertisement_provider_intersection_never_serializes_private_fields() {
    let root = fixture();
    write(root.path(), &observation(now_ms()));
    let client = CoordClient::new(
        Some(root.path().join("policy.toml")),
        Some(root.path().join("data/coord")),
    );
    let state = room_state(&client, "shared", "agent", ALICE, None)
        .await
        .unwrap();
    assert_eq!(
        member(&state, BOB)["verified"][0]["availability"],
        "available"
    );
    assert_eq!(member(&state, BOB)["verified"].as_array().unwrap().len(), 1);
    assert_eq!(state["resource_leases"][0]["holder_agent_id"], BOB);
    for private in [
        "PRIVATE", "github", "other", "token", "account", "route", "error",
    ] {
        assert!(!state.to_string().contains(private), "{private}");
    }
    // The same client re-reads source grants without a restart or reload cache.
    let policy = root.path().join("policy.toml");
    fs::write(
        &policy,
        fs::read_to_string(&policy)
            .unwrap()
            .replace("capability='acceptance_runner'", "capability='reader'"),
    )
    .unwrap();
    assert!(
        member(
            &room_state(&client, "shared", "agent", ALICE, None)
                .await
                .unwrap(),
            BOB
        )["verified"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fs::write(
        &policy,
        fs::read_to_string(&policy)
            .unwrap()
            .replace("capability='reader'", "capability='acceptance_runner'"),
    )
    .unwrap();
    assert_eq!(
        member(
            &room_state(&client, "shared", "agent", ALICE, None)
                .await
                .unwrap(),
            BOB
        )["verified"][0]["authorized"],
        true
    );
    fs::remove_file(root.path().join("coord-providers/rundeck.json")).unwrap();
    assert_eq!(
        member(
            &room_state(&client, "shared", "agent", ALICE, None)
                .await
                .unwrap(),
            BOB
        )["verified"][0]["availability"],
        "unknown"
    );
}

#[test]
fn recheck_removes_revoked_authority_and_holder_and_does_not_promote_declarations() {
    let root = fixture();
    let now = now_ms();
    write(root.path(), &observation(now));
    let initial = read(root.path());
    let evidence = BTreeMap::from([(
        "rundeck".into(),
        read_snapshot(&root.path().join("coord-providers"), "rundeck").unwrap(),
    )]);
    let conn = open_db(&root.path().join("data/coord/v0.db"), true).unwrap();
    conn.execute("DELETE FROM coord_capability_advertisements", [])
        .unwrap();
    conn.execute(
        "UPDATE memberships SET revoked_at=2 WHERE principal_id=?1",
        [BOB],
    )
    .unwrap();
    conn.execute("INSERT INTO coord_capability_declarations VALUES('rm-inventory',?1,'rundeck:acceptance_runner',?2,?3)",params![ALICE,now,now+1000]).unwrap();
    let state = project(read(root.path()), &initial, &evidence, now).unwrap();
    assert_eq!(state["members"].as_array().unwrap().len(), 1);
    assert_eq!(
        member(&state, ALICE)["declared"][0]["capability"],
        "rundeck:acceptance_runner"
    );
    assert_eq!(member(&state, ALICE)["verified"], json!([]));
    assert_eq!(state["resource_leases"][0]["state"], "unknown");
    assert!(state["resource_leases"][0]["holder_agent_id"].is_null());
    conn.execute(
        "UPDATE memberships SET revoked_at=2 WHERE principal_id=?1",
        [ALICE],
    )
    .unwrap();
    assert!(matches!(
        read_inventory(
            &root.path().join("data/coord/v0.db"),
            Some(&root.path().join("policy.toml")),
            "shared",
            "agent",
            ALICE
        ),
        Err(CoordError::NotFound)
    ));
}

#[tokio::test]
async fn provider_failure_expiry_malformed_and_special_files_are_unknown_without_cached_positive() {
    let root = fixture();
    let now = now_ms();
    let client = CoordClient::new(
        Some(root.path().join("policy.toml")),
        Some(root.path().join("data/coord")),
    );
    for (observed, until, expected) in [
        (now - 10, now + 1000, "available"),
        (now - 1000, now - 1, "unknown"),
        (now + 1000, now + 2000, "unknown"),
        (now - 1, now + MAX_TTL_MS + 1, "unknown"),
    ] {
        let mut value = observation(now);
        value["capabilities"][0]["observed_at"] = json!(observed);
        value["capabilities"][0]["valid_until"] = json!(until);
        write(root.path(), &value);
        let state = room_state(&client, "shared", "agent", ALICE, None)
            .await
            .unwrap();
        assert_eq!(member(&state, BOB)["verified"][0]["availability"], expected);
        if until < now {
            assert_eq!(member(&state, BOB)["verified"][0]["freshness"], "stale");
        }
    }
    let path = root.path().join("coord-providers/rundeck.json");
    for source in [
        "not JSON",
        "{\"capabilities\":{}}",
        "{\"capabilities\":[],\"capabilities\":[]}",
        "[]",
    ] {
        fs::write(&path, source).unwrap();
        assert_eq!(
            member(
                &room_state(&client, "shared", "agent", ALICE, None)
                    .await
                    .unwrap(),
                BOB
            )["verified"][0]["availability"],
            "unknown"
        );
    }
    let mut bad = observation(now);
    bad["capabilities"][0]["observed_at"] = json!(true);
    write(root.path(), &bad);
    assert!(read_snapshot(path.parent().unwrap(), "rundeck").is_none());
    bad = observation(now);
    let duplicate = bad["capabilities"][0].clone();
    bad["capabilities"].as_array_mut().unwrap().push(duplicate);
    write(root.path(), &bad);
    assert!(read_snapshot(path.parent().unwrap(), "rundeck").is_none());
    fs::write(&path, vec![b' '; MAX_SNAPSHOT_BYTES as usize + 1]).unwrap();
    assert!(read_snapshot(path.parent().unwrap(), "rundeck").is_none());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(root.path().join("policy.toml"), &path).unwrap();
    assert!(read_snapshot(path.parent().unwrap(), "rundeck").is_none());
    fs::remove_file(&path).unwrap();
    let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let before = Instant::now();
    assert!(read_snapshot(path.parent().unwrap(), "rundeck").is_none());
    assert!(before.elapsed() < Duration::from_millis(500));
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_provider_reads_are_bounded_and_do_not_block_the_event_loop_or_ledger() {
    let root = fixture();
    let reads = Arc::new(SnapshotReads::default());
    let mut releases = Vec::new();
    let mut results = Vec::new();
    for _ in 0..MAX_PROVIDER_INFLIGHT {
        let (release, blocked) = mpsc::channel();
        releases.push(release);
        results.push(
            reads
                .start("rundeck", move || {
                    blocked.recv().unwrap();
                    None
                })
                .unwrap(),
        );
    }
    assert!(reads.start("rundeck", || None).is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut results[0])
            .await
            .is_err()
    );
    // Waiting timed out without releasing either worker's admission permit.
    assert!(reads.start("rundeck", || None).is_none());
    let ledger = tokio::task::spawn_blocking({
        let path = root.path().to_owned();
        move || read(&path).access.room_name
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), ledger)
            .await
            .unwrap()
            .unwrap(),
        "shared"
    );
    assert!(
        reads
            .start("healthy", || Some(Observations {
                capabilities: vec![],
                leases: vec![]
            }))
            .unwrap()
            .await
            .unwrap()
            .is_some()
    );
    for release in releases {
        release.send(()).unwrap();
    }
    for result in results {
        assert!(result.await.unwrap().is_none());
    }
    // Fill remaining global slots with distinct providers, then demonstrate
    // that an additional read is refused instead of spawning another worker.
    let mut releases = Vec::new();
    let mut results = Vec::new();
    let mut rejected = false;
    for n in 0..=MAX_INFLIGHT {
        let (release, blocked) = mpsc::channel();
        let Some(result) = reads.start(&format!("blocked-{n}"), move || {
            let _ = blocked.recv();
            None
        }) else {
            rejected = true;
            break;
        };
        releases.push(release);
        results.push(result);
    }
    assert!(!results.is_empty());
    assert!(rejected);
    assert!(results.len() <= MAX_INFLIGHT);
    for release in releases {
        release.send(()).unwrap();
    }
    for result in results {
        assert!(result.await.unwrap().is_none());
    }
}

#[test]
fn configured_identity_is_rename_stable_and_duplicate_or_readded_ids_inherit_no_grants() {
    let root = fixture();
    let policy = root.path().join("policy.toml");
    let source = fs::read_to_string(&policy).unwrap();
    let renamed = source.replace("agents.bob", "agents.robert");
    fs::write(&policy, &renamed).unwrap();
    assert_eq!(read(root.path()).configured[BOB].name, "robert");
    fs::write(
        &policy,
        format!("{renamed}\n[agents.forged]\nagent_id='{BOB}'\n"),
    )
    .unwrap();
    assert!(!read(root.path()).configured.contains_key(BOB));
    fs::write(
        &policy,
        source.replace(BOB, "ag-dddddddddddddddddddddddddddddddd"),
    )
    .unwrap();
    assert!(read(root.path()).capabilities.is_empty());
    fs::write(
        &policy,
        source.replace(ALICE, "ag-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    )
    .unwrap();
    assert!(matches!(
        read_inventory(
            &root.path().join("data/coord/v0.db"),
            Some(&policy),
            "shared",
            "agent",
            ALICE
        ),
        Err(CoordError::NotFound)
    ));
}
