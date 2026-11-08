//! Real destination owners and scoped NATS; controlled guest execution retains
//! the already accepted backend boundary rather than replaying installed guests.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn audit_path(root: &Path) -> PathBuf {
    native_config::read(&root.join("config.toml"))
        .unwrap()
        .audit_log_path
        .unwrap()
}

pub(super) fn refusals(root: &Path) -> Vec<Value> {
    fs::read_to_string(audit_path(root))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| event["event"] == "coord.federation_refused")
        .collect()
}

fn lock(path: &Path) -> fs::File {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
    file
}

fn unavailable_operation(owner: &str, id: &str) -> Value {
    let mut request = wire(
        owner,
        json!({"operation_id":id,"command":"untrusted-secret-command","output":"untrusted-secret-output"}),
    );
    request["path"] = json!("/admin/untrusted-secret-path");
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; direct authenticated destination refusal audit"]
async fn direct_nats_refusals_record_destination_trust_principal_operation_and_phase() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("support-refusal-audit-")
        .tempdir()
        .unwrap()
        .keep();
    println!("destination refusal roots: {}", retained.display());
    let (a, b) = (retained.join("a"), retained.join("b"));
    initialize(&a, &nats).await;
    initialize(&b, &nats).await;
    let (_clean_a, _clean_b) = (NatsCleanup(a.clone()), NatsCleanup(b.clone()));
    let (a_id, b_id) = (instance(&a), instance(&b));
    coord_json(
        &a,
        &[
            "federation",
            "credential",
            a.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    trust_broker(&b, &a, &a_id, &nats).await;
    let proxy = stage0::start_proxy(&b).await;
    apply(&b, "incident", proposal(&b_id, Some(&a_id))).await;
    let conn = connection(&b, &a, &a_id).await;
    assert_eq!(
        raw(
            &conn,
            &b_id,
            &a_id,
            wire(&b_id, inspect(&b_id, "ordinary-delivery"))
        )
        .await["status"],
        200
    );

    let wrong = raw(
        &conn,
        &b_id,
        &a_id,
        wire(
            "sy-00000000000000000000000000000000",
            inspect(&b_id, "destination-refusal"),
        ),
    )
    .await;
    assert_eq!(wrong["status"], 403);
    assert!(wrong["body"]["audit_status"].is_null());
    assert_eq!(
        raw(
            &conn,
            &b_id,
            &a_id,
            wire(
                "untrusted-secret-destination",
                inspect(&b_id, "invalid-destination-claim")
            )
        )
        .await["status"],
        403
    );
    let mut unregistered = wire(&b_id, inspect(&b_id, "principal-refusal"));
    unregistered["source_run"]["agent_id"] = json!(CAROL);
    assert_eq!(raw(&conn, &b_id, &a_id, unregistered).await["status"], 403);
    assert_eq!(
        raw(
            &conn,
            &b_id,
            &a_id,
            unavailable_operation(&b_id, "operation-refusal")
        )
        .await["status"],
        404
    );
    // Malformed inputs do not allocate receipts or persistent refusal work.
    for _ in 0..16 {
        assert_eq!(
            raw(
                &conn,
                &b_id,
                &a_id,
                json!({"unexpected":"untrusted-secret-body"})
            )
            .await["status"],
            400
        );
    }

    let setup = lock(&b.join("agents/alice/host-setup.lock"));
    let request = wire(&b_id, inspect(&b_id, "post-dispatch-refusal"));
    let refused = {
        let pending = raw(&conn, &b_id, &a_id, request);
        tokio::pin!(pending);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while receipt(&b, "post-dispatch-refusal").is_none() {
            tokio::select! {
                response = &mut pending => panic!("request escaped the held owner: {response}"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            assert!(tokio::time::Instant::now() < deadline);
        }
        coord_json(&b, &["federation", "revoke", &a_id]).await;
        drop(setup);
        pending.await
    };
    assert_eq!(refused["status"], 403);
    assert_eq!(refused["body"]["error"], "federation access changed");
    assert_eq!(
        raw(
            &conn,
            &b_id,
            &a_id,
            wire(&b_id, inspect(&b_id, "trust-refusal"))
        )
        .await["status"],
        403
    );
    let events = refusals(&b);
    for reason in [
        "destination_mismatch",
        "qualified_principal_unavailable",
        "operation_unavailable",
        "peer_trust_changed",
        "peer_trust_unavailable",
    ] {
        let event = events
            .iter()
            .find(|event| event["details"]["reason"] == reason)
            .unwrap_or_else(|| panic!("missing {reason}: {events:?}"));
        assert_eq!(event["details"]["source_instance_id"], a_id);
        assert_eq!(event["details"]["instance_id"], b_id);
        assert!(event["request_id"].as_str().unwrap().starts_with("req-"));
        assert!(event.to_string().len() < 4096);
    }
    let destination = events
        .iter()
        .find(|event| event["details"]["reason"] == "destination_mismatch")
        .unwrap();
    assert_eq!(destination["request_id"], wrong["body"]["request_id"]);
    assert_eq!(
        destination["details"]["qualified_principal"]["instance_id"],
        a_id
    );
    assert_eq!(
        destination["details"]["untrusted_claims"]["destination_instance_id"],
        "sy-00000000000000000000000000000000"
    );
    let principal = events
        .iter()
        .find(|event| event["details"]["reason"] == "qualified_principal_unavailable")
        .unwrap();
    assert!(principal["details"]["qualified_principal"].is_null());
    assert_eq!(principal["details"]["untrusted_claims"]["agent_id"], CAROL);
    let withheld = events
        .iter()
        .find(|event| event["details"]["phase"] == "post_dispatch")
        .unwrap();
    assert_eq!(withheld["details"]["mutation_outcome"], "response_withheld");
    assert!(
        !events
            .iter()
            .any(|event| event.to_string().contains("untrusted-secret"))
    );
    for id in [
        "destination-refusal",
        "principal-refusal",
        "operation-refusal",
        "trust-refusal",
    ] {
        assert!(receipt(&b, id).is_none());
    }
    assert_eq!(
        fs::read_dir(b.join("data/support-grant-audit"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|part| part == "json"))
            .count(),
        0
    );
    stage0::crash(proxy).await;
}

#[test]
#[ignore = "requires pinned NATS; queue exhaustion and real owner termination"]
fn remote_final_audit_recovers_after_queue_failure_and_owner_termination() {
    if std::env::var_os("SAFEYOLO_REMOTE_AUDIT_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","federation::support::audit::remote_final_audit_recovers_after_queue_failure_and_owner_termination","--ignored","--nocapture"])
            .env("SAFEYOLO_REMOTE_AUDIT_CHILD","1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(remote_queue_recovery());
}

async fn remote_queue_recovery() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("support-queue-recovery-")
        .tempdir()
        .unwrap()
        .keep();
    println!("remote queue recovery roots: {}", retained.display());
    let (a, b) = (retained.join("a"), retained.join("b"));
    initialize(&a, &nats).await;
    initialize(&b, &nats).await;
    let (_clean_a, _clean_b) = (NatsCleanup(a.clone()), NatsCleanup(b.clone()));
    let (a_id, b_id) = (instance(&a), instance(&b));
    coord_json(
        &a,
        &[
            "federation",
            "credential",
            a.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    trust_broker(&b, &a, &a_id, &nats).await;
    let config = fs::read_to_string(b.join("config.toml")).unwrap();
    fs::write(
        b.join("config.toml"),
        format!("{config}\n[audit]\nqueue_max=1\n"),
    )
    .unwrap();
    fs::create_dir(b.join("bin")).unwrap();
    let _target = super::super::super::owned_run::OwnedRun::start_agent(&b, "alice");
    let runtime_path = b.join("agents/alice/runtime.json");
    let mut runtime: Value = serde_json::from_slice(&fs::read(&runtime_path).unwrap()).unwrap();
    runtime["agent_id"] = json!(ALICE);
    fs::write(&runtime_path, runtime.to_string()).unwrap();
    let generation = runtime["run_id"].as_str().unwrap();
    fs::write(
        b.join("agents/alice/config-share/host-launch-context.json"),
        json!({"agent_id":ALICE,"generation":generation}).to_string(),
    )
    .unwrap();
    fs::write(
        b.join("bin/runsc"),
        format!(
            r#"#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = state ]; then
        printf '%s\n' '{{"id":"safeyolo-{generation}","status":"running"}}'
        exit 0
    fi
done
touch '{root}/at-command'
flock '{root}/command.lock' true
printf 'effect\n' >> '{root}/guest-effects'
printf 'untrusted-secret-output\n'
"#,
            root = b.display()
        ),
    )
    .unwrap();
    fs::set_permissions(b.join("bin/runsc"), fs::Permissions::from_mode(0o755)).unwrap();
    let original = std::env::var_os("PATH").unwrap();
    // This entire test is an isolated harness child; sibling tests do not
    // inherit the controlled guest adapter.
    unsafe {
        std::env::set_var(
            "PATH",
            std::env::join_paths(
                std::iter::once(b.join("bin")).chain(std::env::split_paths(&original)),
            )
            .unwrap(),
        );
    }
    let mut proxy = stage0::start_proxy(&b).await;
    let mut selected = proposal(&b_id, Some(&a_id));
    selected["grant"]["guest_admin"] = json!(true);
    apply(&b, "incident", selected).await;
    let policy = fs::read(b.join("policy.toml")).unwrap();
    let conn = connection(&b, &a, &a_id).await;
    let control = lock(&b.join("command.lock"));
    let mut input = inspect(&b_id, "completed-before-audit");
    input["expected_run"] = json!(generation);
    input["operation"] =
        json!({"action":"guest_command","command":"untrusted-secret-command","timeout_seconds":5});
    let completed = {
        let pending = raw(&conn, &b_id, &a_id, wire(&b_id, input.clone()));
        tokio::pin!(pending);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !b.join("at-command").exists() {
            tokio::select! {
                response=&mut pending=>panic!("guest adapter was not reached: {response}"),
                ()=tokio::time::sleep(Duration::from_millis(10))=>{}
            }
            assert!(tokio::time::Instant::now() < deadline);
        }
        assert!(
            fs::read_to_string(audit_path(&b))
                .unwrap()
                .contains("agent.support_operation_started")
        );
        let mut sink_lock = audit_path(&b).into_os_string();
        sink_lock.push(".lock");
        let sink = lock(Path::new(&sink_lock));
        let mut blocked = tokio::task::JoinSet::new();
        for id in ["full-1", "full-2", "full-3"] {
            let (conn, owner, source) = (conn.clone(), b_id.clone(), a_id.clone());
            blocked.spawn(async move {
                raw(&conn, &owner, &source, unavailable_operation(&owner, id)).await
            });
        }
        let full = tokio::time::timeout(Duration::from_secs(1), blocked.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(full["status"], 404);
        assert!(
            full["body"]["audit_status"].is_string(),
            "the existing queue must actually refuse admission: {full}"
        );
        drop(control);
        let completed = pending.await;
        assert_eq!(completed["status"], 200, "{completed}");
        assert_eq!(completed["body"]["state"], "completed", "{completed}");
        assert!(completed["body"]["audit_status"].is_string());
        let saved = receipt(&b, "completed-before-audit").unwrap();
        assert!(saved["audit_pending"].is_string());
        let staged: Value = serde_json::from_str(saved["audit_pending"].as_str().unwrap()).unwrap();
        assert!(!staged.to_string().contains("untrusted-secret"));
        assert_eq!(staged["details"]["execution_started"], true);
        assert_eq!(staged["details"]["completion_verified"], true);
        stage0::crash(proxy).await;
        drop(sink);
        blocked.abort_all();
        while blocked.join_next().await.is_some() {}
        (completed["body"].clone(), staged)
    };
    proxy = stage0::start_proxy(&b).await;
    stage0::until(|| {
        receipt(&b, "completed-before-audit").is_some_and(|value| value["audit_delivered"] == true)
    })
    .await;
    assert_eq!(fs::read(b.join("policy.toml")).unwrap(), policy);
    let restored = receipt(&b, "completed-before-audit").unwrap();
    assert!(restored["audit_pending"].is_null());
    assert!(restored["audit_status"].is_null());
    assert_eq!(restored["audit_event_id"], completed.0["audit_event_id"]);
    let canonical = fs::read_to_string(audit_path(&b)).unwrap();
    assert!(
        canonical
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .any(|event| event == completed.1)
    );
    let conn = connection(&b, &a, &a_id).await;
    let reused = raw(&conn, &b_id, &a_id, wire(&b_id, input)).await;
    assert_eq!(reused["body"]["state"], "completed");
    assert!(reused["body"]["audit_status"].is_null());
    assert_eq!(
        fs::read_to_string(b.join("guest-effects")).unwrap(),
        "effect\n"
    );

    // Terminate an admitted operation before its checked start boundary. Its
    // execution was never verified, so recovery and retry must remain unknown.
    let setup = lock(&b.join("agents/alice/host-setup.lock"));
    {
        let pending = raw(
            &conn,
            &b_id,
            &a_id,
            wire(&b_id, inspect(&b_id, "unverified-before-crash")),
        );
        tokio::pin!(pending);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while receipt(&b, "unverified-before-crash").is_none() {
            tokio::select! {
                response=&mut pending=>panic!("operation escaped the held setup: {response}"),
                ()=tokio::time::sleep(Duration::from_millis(10))=>{}
            }
            assert!(tokio::time::Instant::now() < deadline);
        }
        assert_eq!(
            receipt(&b, "unverified-before-crash").unwrap()["state"],
            "queued"
        );
        stage0::crash(proxy).await;
    }
    drop(setup);
    proxy = stage0::start_proxy(&b).await;
    stage0::until(|| {
        receipt(&b, "unverified-before-crash").is_some_and(|value| value["audit_delivered"] == true)
    })
    .await;
    let conn = connection(&b, &a, &a_id).await;
    let unknown = raw(
        &conn,
        &b_id,
        &a_id,
        wire(&b_id, inspect(&b_id, "unverified-before-crash")),
    )
    .await;
    assert_eq!(unknown["body"]["state"], "outcome_unknown");
    assert_eq!(unknown["body"]["completion_verified"], false);
    let audit = fs::read_to_string(audit_path(&b)).unwrap();
    let unknown_event = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["event_id"] == unknown["body"]["audit_event_id"])
        .unwrap();
    assert_eq!(unknown_event["details"]["last_recorded_state"], "queued");
    assert_eq!(unknown_event["details"]["completion_verified"], false);
    assert_eq!(
        fs::read_to_string(b.join("guest-effects")).unwrap(),
        "effect\n"
    );
    stage0::crash(proxy).await;
}
