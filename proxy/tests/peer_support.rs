//! Real Agent/Admin HTTP boundaries with controlled ingress-run records.
//! Installed backend execution and model-led diagnosis require separate proof.
#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    process::{Child, Command},
    time::Duration,
};

#[allow(dead_code)]
#[path = "support/shared_approvals.rs"]
mod shared_approval_fixture;
mod test_owned_endpoint;
use shared_approval_fixture::*;

const INSTANCE: &str = "sy-11111111111111111111111111111111";
const RUN: &str = "0123456789abcdef0123456789abcdef";

struct Backend(Child);
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn support_run(fixture: &Fixture, generation: &str) -> Backend {
    agent_run(fixture, "helper", HELPER_ID, generation)
}

fn agent_run(fixture: &Fixture, name: &str, agent_id: &str, generation: &str) -> Backend {
    let mut command = Command::new("python3");
    let child = command
        .arg0("runsc-sandbox")
        .args([
            "-c",
            "import time; time.sleep(300)",
            "boot",
            &format!("safeyolo-{generation}"),
            "--root",
        ])
        .arg(fixture.root.path().join("run"))
        .spawn()
        .unwrap();
    let pid = child.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let birth = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let token = format!(
        "linux:{}:{pid}:{birth}",
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
    );
    let directory = fixture.root.path().join("agents").join(name);
    fs::create_dir_all(directory.join("config-share")).unwrap();
    fs::write(directory.join("runtime.json"), json!({"name":name,"agent_id":agent_id,"run_id":generation,"state":"running","backend_pid":pid,"backend_token":token}).to_string()).unwrap();
    fs::write(
        directory.join("config-share/host-launch-context.json"),
        json!({"agent_id":agent_id,"generation":generation}).to_string(),
    )
    .unwrap();
    Backend(child)
}

#[tokio::test]
async fn guest_probe_rechecks_grant_and_run_after_waiting_for_the_launch_lock() {
    for change in ["revoke", "target-run"] {
        let f = fixture().await;
        let _support = support_run(&f, RUN);
        let _target = agent_run(&f, "worker", WORKER_ID, RUN);
        let mut selected = proposal();
        selected["grant"]["guest_admin"] = json!(true);
        let applied = grant(&f, selected).await;
        let directory = f.root.path().join("agents/worker");
        fs::create_dir(directory.join("home")).unwrap();
        fs::write(directory.join("config-share/safeyolo-guest"), b"fixture").unwrap();
        let path = directory.join("home/.safeyolo-command-supervisor.json");
        let mut original = json!({"schema_version":1,"name":"worker","generation":RUN,
            "supervision_id":"launch-original","command":"exec worker","state":"failed",
            "runtime_owner":"guest-pid1","command_pid":null,"command_start_token":null});
        fs::write(&path, original.to_string()).unwrap();
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(directory.join("current-launch.lock"))
            .unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        let mut input = inspect("probe-after-lock");
        input["expected_run"] = json!(RUN);
        input["operation"] = json!({"action":"guest_probe","timeout_seconds":3});
        let response = {
            let pending = f.agent("helper", "POST", "/support/operations", Some(input));
            tokio::pin!(pending);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                tokio::select! {
                    response = &mut pending => panic!("probe escaped held launch lock: {}", response.json()),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
                let receipt = f
                    .agent(
                        "helper",
                        "GET",
                        "/support/operations/probe-after-lock",
                        None,
                    )
                    .await;
                if receipt.status == 200 && receipt.json()["execution_started"] == true {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "probe did not reach the launch lock"
                );
            }
            let _replacement = if change == "revoke" {
                assert_eq!(
                    f.admin(
                        "POST",
                        "/admin/support-grants/incident/revoke",
                        Some(json!({"expected_revision":applied["revision"]}))
                    )
                    .await
                    .status,
                    200
                );
                None
            } else {
                let next = "fedcba9876543210fedcba9876543210";
                let replacement = agent_run(&f, "worker", WORKER_ID, next);
                original["generation"] = json!(next);
                fs::write(&path, original.to_string()).unwrap();
                Some(replacement)
            };
            drop(lock);
            pending.await
        };
        assert_eq!(response.status, 200, "{}", response.json());
        // The operation was admitted, but cannot publish after authority changed.
        assert_ne!(
            response.json()["state"],
            "completed",
            "{change}: {}",
            response.json()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            original,
            "{change}"
        );
        assert!(
            !directory
                .join("config-share/command-supervisor-enabled")
                .exists()
        );
        f.stop().await;
    }
}

async fn fixture() -> Fixture {
    let fixture = Fixture::new().await;
    fs::write(
        fixture.root.path().join("config.toml"),
        "policy_file='policy.toml'\n",
    )
    .unwrap();
    fs::write(fixture.root.path().join("data/instance_id"), INSTANCE).unwrap();
    fixture
}

fn proposal() -> Value {
    json!({"expected_revision":null,"grant":{
        "instance_id":INSTANCE,"support":{"name":"helper","agent_id":HELPER_ID},
        "targets":[{"name":"worker","agent_id":WORKER_ID}],
        "guest_admin":false,"guest_logs":[],"lifecycle":[],"expires_at":null,"acknowledgment":null}})
}

async fn grant(fixture: &Fixture, mut input: Value) -> Value {
    let preview = fixture
        .admin(
            "POST",
            "/admin/support-grants/incident/preview",
            Some(input.clone()),
        )
        .await;
    assert_eq!(preview.status, 200, "{}", preview.json());
    input["grant"] = preview.json()["after"].clone();
    input["grant"]["acknowledgment"] = preview.json()["acknowledgment"].clone();
    let applied = fixture
        .admin("POST", "/admin/support-grants/incident/apply", Some(input))
        .await;
    assert_eq!(applied.status, 200, "{}", applied.json());
    applied.json()
}

fn inspect(id: &str) -> Value {
    json!({"operation_id":id,"grant":"incident","target_id":WORKER_ID,"expected_run":null,"operation":{"action":"inspect"}})
}

fn lock_target_setup(fixture: &Fixture) -> fs::File {
    let target = fixture.root.path().join("agents/worker");
    fs::create_dir_all(&target).unwrap();
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(target.join("host-setup.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    lock
}

#[tokio::test]
async fn standing_inspection_is_target_scoped_and_receipts_never_replay() {
    let f = fixture().await;
    let backend = support_run(&f, RUN);
    let applied = grant(&f, proposal()).await;
    assert_eq!(applied["lifetime"], "standing");
    let discovered = f.agent("helper", "GET", "/support/grants", None).await;
    assert_eq!(discovered.status, 200, "{}", discovered.json());
    assert_eq!(discovered.json()["instance_id"], INSTANCE);
    assert_eq!(discovered.json()["grants"].as_array().unwrap().len(), 1);
    // This fixture has no Coord room, NATS client or participating target.
    let input = inspect("diagnose-1");
    let first = f
        .agent("helper", "POST", "/support/operations", Some(input.clone()))
        .await;
    assert_eq!(first.status, 200, "{}", first.json());
    let receipt = first.json();
    assert_eq!(receipt["state"], "completed");
    assert_eq!(receipt["result"]["runtime_state"], "stopped");
    assert_eq!(receipt["result"]["guest_exec_state"], "unavailable");
    assert!(receipt.get("owner_token").is_none());
    assert!(receipt.get("permission").is_none());
    assert_eq!(
        f.agent("helper", "POST", "/support/operations", Some(input.clone()))
            .await
            .json(),
        receipt
    );
    assert_eq!(
        f.agent("helper", "GET", "/support/operations/diagnose-1", None)
            .await
            .json(),
        receipt
    );
    let mcp = safeyolo_proxy::coord_tools::Client {
        socket: Some(f.root.path().join("helper.sock")),
        token_file: f.root.path().join("data/agent_token"),
        home: None,
    };
    let mut through_mcp = inspect("mcp-logical-id-π");
    through_mcp["instance_id"] = json!(INSTANCE);
    assert_eq!(
        mcp.call("support_grants", &json!({})).await.unwrap()["instance_id"],
        INSTANCE
    );
    let mcp_receipt = mcp.call("support_operation", &through_mcp).await.unwrap();
    assert_eq!(mcp_receipt["state"], "completed");
    assert_eq!(
        mcp.call(
            "read_support_operation",
            &json!({"operation_id":"mcp-logical-id-π"})
        )
        .await
        .unwrap(),
        mcp_receipt
    );
    // A task can unwind while the proxy process stays live. Its abandoned
    // running receipt must become uncertain, rather than inherit that process.
    let private = fs::read_dir(f.root.path().join("data/support-operations"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .find(|path| {
            serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["operation_id"]
                == "mcp-logical-id-π"
        })
        .unwrap();
    let mut abandoned: Value = serde_json::from_slice(&fs::read(&private).unwrap()).unwrap();
    abandoned["state"] = json!("running");
    abandoned["result"] = Value::Null;
    fs::write(private, abandoned.to_string()).unwrap();
    let unknown = mcp
        .call(
            "read_support_operation",
            &json!({"operation_id":"mcp-logical-id-π"}),
        )
        .await
        .unwrap();
    assert_eq!(unknown["state"], "outcome_unknown");
    assert_eq!(unknown["completion_verified"], false);
    assert_eq!(
        mcp.call("support_operation", &through_mcp).await.unwrap()["state"],
        "outcome_unknown"
    );

    for operation in [
        json!({"action":"guest_command","command":"sudo -n true","timeout_seconds":3}),
        json!({"action":"guest_log","path":"/app/agent_token"}),
        json!({"action":"guest_probe","timeout_seconds":15}),
        json!({"action":"lifecycle","operation":"start_sandbox"}),
    ] {
        let mut forbidden = inspect("forbidden");
        forbidden["operation"] = operation;
        assert_eq!(
            f.agent("helper", "POST", "/support/operations", Some(forbidden))
                .await
                .status,
            403
        );
    }
    for field in ["target_id", "instance_id"] {
        let mut forged = inspect("foreign");
        forged[field] = json!("ag-33333333333333333333333333333333");
        assert_eq!(
            f.agent("helper", "POST", "/support/operations", Some(forged))
                .await
                .status,
            403
        );
    }
    let mut forged = inspect("forged-initiator");
    forged["initiator"] = json!({"agent":"helper","agent_id":HELPER_ID,"run_id":RUN});
    assert_eq!(
        f.agent("helper", "POST", "/support/operations", Some(forged))
            .await
            .status,
        400
    );
    assert_eq!(
        f.agent("peer", "POST", "/support/operations", Some(input.clone()))
            .await
            .status,
        403
    );
    assert_ne!(
        f.agent("helper", "GET", "/admin/support-grants", None)
            .await
            .status,
        200
    );
    assert_eq!(
        f.admin_with_token(
            "synthetic-agent-token",
            "POST",
            "/admin/support-grants/incident/revoke",
            Some(json!({"expected_revision":applied["revision"]}))
        )
        .await
        .status,
        401
    );
    let mut conflicting = input;
    conflicting["expected_run"] = json!("different-input");
    assert_eq!(
        f.agent("helper", "POST", "/support/operations", Some(conflicting))
            .await
            .status,
        409
    );

    let target = f.root.path().join("agents/worker");
    fs::write(target.join("current-launch.json"), json!({"name":"worker","agent_id":WORKER_ID,"launch_id":"previous-launch","state":"exited","exit_code":7,"launcher":{"kind":"supervisor"},"command":SECRET,"error":SECRET,"hook_errors":[SECRET]}).to_string()).unwrap();
    let safe = f
        .agent(
            "helper",
            "POST",
            "/support/operations",
            Some(inspect("private-host-evidence")),
        )
        .await
        .json();
    assert_eq!(safe["result"]["exit_code"], 7);
    assert!(!safe.to_string().contains(SECRET));
    fs::write(target.join("runtime.json"), "corrupt retained handle").unwrap();
    let degraded = f
        .agent(
            "helper",
            "POST",
            "/support/operations",
            Some(inspect("degraded")),
        )
        .await
        .json();
    assert_eq!(degraded["result"]["runtime_state"], "unknown");
    fs::remove_file(target.join("runtime.json")).unwrap();

    let audit = fs::read_to_string(f.root.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("ops.audit_validation_failed"));
    assert!(!audit.contains(SECRET));
    let events: Vec<Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for phase in ["started", "finished"] {
        let selected: Vec<_> = events
            .iter()
            .filter(|event| {
                event["event"] == format!("agent.support_operation_{phase}")
                    && event["details"]["operation_id"] == "diagnose-1"
            })
            .collect();
        assert_eq!(
            selected.len(),
            1,
            "duplicate requests emitted another execution: {audit}"
        );
        assert_eq!(selected[0]["details"]["initiator"]["agent_id"], HELPER_ID);
        assert_eq!(selected[0]["details"]["target_id"], WORKER_ID);
        assert_eq!(
            selected[0]["details"]["grant_revision"],
            applied["revision"]
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "agent.support_operation_denied")
    );
    drop(backend);
    let _replacement = support_run(&f, "fedcba9876543210fedcba9876543210");
    let recovered = f
        .agent("helper", "GET", "/support/operations/diagnose-1", None)
        .await;
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.json()["initiator"]["run_id"], RUN);
    let restarted = f.restart().await;
    assert_eq!(
        restarted
            .agent(
                "helper",
                "POST",
                "/support/operations",
                Some(inspect("after-proxy-restart"))
            )
            .await
            .status,
        200
    );
    let revision = restarted
        .admin("GET", "/admin/support-grants", None)
        .await
        .json()["grants"][0]["revision"]
        .clone();
    let revoked = restarted
        .admin(
            "POST",
            "/admin/support-grants/incident/revoke",
            Some(json!({"expected_revision":revision})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
    assert_eq!(
        restarted
            .agent("helper", "GET", "/support/operations/diagnose-1", None)
            .await
            .status,
        403
    );
    restarted.stop().await;
}

#[test]
fn support_inspection_keeps_the_blocking_pool_available() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        // The existing connection-disconnect monitor occupies one worker.
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        let f = fixture().await;
        let _backend = support_run(&f, RUN);
        grant(&f, proposal()).await;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            f.agent(
                "helper",
                "POST",
                "/support/operations",
                Some(inspect("one-blocking-owner")),
            ),
        )
        .await;
        if result.is_ok() {
            f.stop().await;
        }
        result
    });
    // Bound shutdown even when a regression strands a blocking admission.
    runtime.shutdown_timeout(Duration::from_secs(1));
    let response =
        response.expect("support nested a second blocking job inside its blocking owner");
    assert_eq!(response.status, 200, "{}", response.json());
    assert_eq!(response.json()["state"], "completed");
}

#[tokio::test]
async fn current_authority_and_target_are_checked_after_the_lifecycle_lock() {
    for change in ["narrow", "revoke", "expire", "rebind"] {
        let f = fixture().await;
        let _backend = support_run(&f, RUN);
        let mut input = proposal();
        input["grant"]["lifecycle"] = json!(["stop_sandbox"]);
        if change == "expire" {
            input["grant"]["expires_at"] = json!(
                (time::OffsetDateTime::now_utc() + time::Duration::seconds(2))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap()
            );
        }
        let applied = grant(&f, input).await;
        let target = f.root.path().join("agents/worker");
        let lock = lock_target_setup(&f);
        let mut operation = inspect("queued-operation");
        operation["operation"] = json!({"action":"lifecycle","operation":"stop_sandbox"});
        let response = {
            let pending = f.agent("helper", "POST", "/support/operations", Some(operation));
            tokio::pin!(pending);
            let directory = f.root.path().join("data/support-operations");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                tokio::select! {
                    response = &mut pending => panic!("operation escaped held lifecycle lock: {}", response.json()),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
                if directory.is_dir()
                    && fs::read_dir(&directory)
                        .unwrap()
                        .flatten()
                        .any(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "operation did not reach the lock"
                );
            }
            match change {
                "narrow" => {
                    let mut next =
                        json!({"expected_revision":applied["revision"],"grant":applied["after"]});
                    next["grant"]["lifecycle"] = json!([]);
                    next["grant"]["acknowledgment"] = Value::Null;
                    grant(&f, next).await;
                }
                "revoke" => {
                    assert_eq!(
                        f.admin(
                            "POST",
                            "/admin/support-grants/incident/revoke",
                            Some(json!({"expected_revision":applied["revision"]}))
                        )
                        .await
                        .status,
                        200
                    );
                }
                "rebind" => {
                    // A human can move a durable ID and amend its grant while
                    // this call waits. The old directory's lock must not
                    // authorize operating on the replacement directory.
                    f.apply(&f.source().replace("[agents.worker]", "[agents.rebound]"))
                        .await;
                    let mut next =
                        json!({"expected_revision":applied["revision"],"grant":applied["after"]});
                    next["grant"]["targets"][0]["name"] = json!("rebound");
                    next["grant"]["acknowledgment"] = Value::Null;
                    grant(&f, next).await;
                }
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
            drop(lock);
            pending.await
        };
        assert_eq!(response.status, 200, "{}", response.json());
        assert_eq!(
            response.json()["state"],
            "refused",
            "{change}: {}",
            response.json()
        );
        assert_eq!(response.json()["completion_verified"], false);
        assert!(
            !target.join("runtime.json").exists(),
            "{change} caused a runtime mutation"
        );
        assert!(!f.root.path().join("agents/rebound/runtime.json").exists());
        f.stop().await;
    }
}

#[tokio::test]
async fn a_lost_http_reply_preserves_the_admitted_operation_without_replay() {
    let f = fixture().await;
    let _backend = support_run(&f, RUN);
    let mut selected = proposal();
    selected["grant"]["lifecycle"] = json!(["stop_sandbox"]);
    grant(&f, selected).await;
    let lock = lock_target_setup(&f);
    let mut input = inspect("lost-reply");
    input["operation"] = json!({"action":"lifecycle","operation":"stop_sandbox"});
    {
        let pending = f.agent("helper", "POST", "/support/operations", Some(input.clone()));
        tokio::pin!(pending);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            tokio::select! {
                response = &mut pending => panic!("operation escaped held lifecycle lock: {}", response.json()),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            let queued = f
                .agent("helper", "GET", "/support/operations/lost-reply", None)
                .await;
            if queued.status == 200 && queued.json()["state"] == "queued" {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "operation was not admitted"
            );
        }
        // Drop the actual HTTP client while its admitted operation is waiting.
    }
    drop(lock);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let receipt = loop {
        let response = f
            .agent("helper", "GET", "/support/operations/lost-reply", None)
            .await;
        assert_eq!(response.status, 200, "{}", response.json());
        let receipt = response.json();
        if !matches!(receipt["state"].as_str(), Some("queued" | "running")) {
            break receipt;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "operation lost its owner: {receipt}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(receipt["state"], "completed", "{receipt}");
    assert_eq!(receipt["result"]["runtime_state"], "stopped");
    assert_eq!(
        f.agent("helper", "POST", "/support/operations", Some(input))
            .await
            .json(),
        receipt
    );
    assert!(!f.root.path().join("agents/worker/runtime.json").exists());
    let events = fs::read_to_string(f.root.path().join("audit.jsonl")).unwrap();
    let finished = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| {
            event["event"] == "agent.support_operation_finished"
                && event["details"]["operation_id"] == "lost-reply"
        })
        .count();
    assert_eq!(finished, 1);
    f.stop().await;
}

#[tokio::test]
async fn same_name_recreation_and_unacknowledged_or_stale_edits_cannot_grant_authority() {
    let f = fixture().await;
    let _backend = support_run(&f, RUN);
    assert_eq!(
        f.admin(
            "POST",
            "/admin/support-grants/incident/apply",
            Some(proposal())
        )
        .await
        .status,
        409
    );
    let mut selected = proposal();
    selected["grant"]["lifecycle"] = json!(["start_sandbox"]);
    let applied = grant(&f, selected).await;
    let mut stale_run = inspect("stale-run");
    stale_run["expected_run"] = json!(RUN);
    stale_run["operation"] = json!({"action":"lifecycle","operation":"start_sandbox"});
    let refused = f
        .agent("helper", "POST", "/support/operations", Some(stale_run))
        .await;
    assert_eq!(refused.status, 200, "{}", refused.json());
    assert_eq!(refused.json()["state"], "refused");
    assert!(!f.root.path().join("agents/worker/runtime.json").exists());
    let mut stale = proposal();
    stale["grant"]["guest_admin"] = json!(true);
    assert_eq!(
        f.admin(
            "POST",
            "/admin/support-grants/incident/preview",
            Some(stale)
        )
        .await
        .status,
        409
    );
    assert_eq!(
        f.admin(
            "POST",
            "/admin/support-grants/incident/revoke",
            Some(json!({"expected_revision":"stale"}))
        )
        .await
        .status,
        409
    );
    let mut document = f.source().parse::<toml_edit::DocumentMut>().unwrap();
    document["agents"]["worker"]["agent_id"] =
        toml_edit::value("ag-44444444444444444444444444444444");
    f.apply(&document.to_string()).await;
    assert_eq!(
        f.agent(
            "helper",
            "POST",
            "/support/operations",
            Some(inspect("old-target"))
        )
        .await
        .status,
        403
    );
    let mut new_target = inspect("new-target");
    new_target["target_id"] = json!("ag-44444444444444444444444444444444");
    assert_eq!(
        f.agent("helper", "POST", "/support/operations", Some(new_target))
            .await
            .status,
        403
    );
    assert_eq!(
        f.admin("GET", "/admin/support-grants", None).await.json()["grants"][0]["active"],
        false
    );
    assert_eq!(
        f.admin(
            "POST",
            "/admin/support-grants/incident/revoke",
            Some(json!({"expected_revision":applied["revision"]}))
        )
        .await
        .status,
        200
    );
    f.stop().await;
}
