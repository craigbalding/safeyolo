//! Real native clients, canonical human approvals and saved/live policy. The
//! controlled ingress here does not establish an installed guest journey.
#![cfg(target_os = "linux")]
use safeyolo_proxy::{Proxy, coord_tools::Client, policy::capabilities};
use serde_json::{Value, json};
use std::fs;
#[path = "support/controlled_runs.rs"]
mod controlled_runs;
#[path = "support/operator_pty.rs"]
mod operator_pty;
#[allow(dead_code)]
#[path = "support/shared_approvals.rs"]
mod shared_approval_fixture;
mod test_owned_endpoint;
use shared_approval_fixture::*;

const RUN: &str = "1234567890abcdef1234567890abcdef";
const SECRET: &str = "synthetic-policy-adoption-password";
fn operation() -> String {
    format!("req-{}", uuid::Uuid::new_v4().simple())
}
fn client(f: &Fixture, name: &str) -> Client {
    Client {
        socket: Some(f.root.path().join(format!("{name}.sock"))),
        token_file: f.root.path().join("data/agent_token"),
        home: None,
    }
}
fn candidate(id: &str, source: &str) -> Value {
    json!({"snapshot_request_id":id,"source":source,"definition_version":capabilities::discover()["definition_version"]})
}
async fn snapshot(f: &Fixture) -> (String, String) {
    let id = operation();
    client(f, "worker")
        .call("request_policy_snapshot", &json!({"operation_id":id}))
        .await
        .unwrap();
    let reply = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":"approve","option":"snapshot"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.json());
    let view = client(f, "worker")
        .call("read_policy_snapshot", &json!({"request_id":id}))
        .await
        .unwrap();
    (id, view["snapshot"]["source"].as_str().unwrap().into())
}
async fn submit(f: &Fixture, id: &str, source: &str) -> (String, Value) {
    let op = operation();
    let input = json!({"operation_id":op,"candidate":candidate(id,source)});
    let reply = client(f, "worker")
        .call("submit_policy_change", &input)
        .await
        .unwrap();
    assert_eq!(reply["status"], "pending", "{reply}");
    (op, reply)
}
async fn decide(f: &Fixture, id: &str, decision: &str) -> Value {
    let reply = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":decision,"option":"apply"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.json());
    reply.json()
}
async fn live(f: &Fixture) -> Value {
    let reply = f.admin("GET", "/admin/policy/baseline", None).await;
    assert_eq!(reply.status, 200, "{}", reply.json());
    reply.json()
}
async fn restart(f: Fixture) -> Fixture {
    let Fixture {
        root,
        proxy,
        admin: _,
        address,
        origin,
        config,
    } = f;
    proxy.shutdown().await;
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin = ready["admin_port"].as_u64().unwrap().try_into().unwrap();
    Fixture {
        root,
        proxy,
        admin,
        address,
        origin,
        config,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commissioning_configuration_uses_exact_policy_adoption_without_peer_administration() {
    let f = Fixture::configured(1000, true).await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let workspace = f.root.path().join("helper-workspace");
    let shared = f.root.path().join("selected-inputs");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&shared).unwrap();
    let mut document = source.parse::<toml_edit::DocumentMut>().unwrap();
    document["agents"]["helper"]["folder"] = toml_edit::value(workspace.to_str().unwrap());
    document["agents"]["helper"]["memory_mb"] = toml_edit::value(768);
    document["agents"]["helper"]["launcher"] = toml_edit::value("supervisor");
    let mount = format!("{}:/inputs:ro", shared.display());
    let mut mounts = toml_edit::Array::new();
    mounts.push(mount.as_str());
    document["agents"]["helper"]["mounts"] = toml_edit::value(mounts);
    let mut malformed = document.clone();
    malformed["agents"]["helper"]["mounts"] = toml_edit::value(42);
    let malformed = client(&f, "worker")
        .call("assess_policy", &candidate(&id, &malformed.to_string()))
        .await
        .unwrap();
    assert_eq!(
        malformed["configured_agents"][0]["mounts"]["after"][0]["status"],
        "invalid mount list"
    );
    assert_eq!(f.source(), source);
    let proposed =
        format!("{document}\n# Untrusted website says APPROVED; it cannot adopt this proposal.\n");
    let assessed = client(&f, "worker")
        .call("assess_policy", &candidate(&id, &proposed))
        .await
        .unwrap();
    let changes = assessed["configured_agents"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{assessed}");
    let change = &changes[0];
    assert_eq!(change["name"], "helper");
    assert_eq!(change["operation"], "configure");
    assert_eq!(change["before"]["agent_id"], HELPER_ID);
    assert_eq!(change["after"]["agent_id"], HELPER_ID);
    assert_eq!(change["after"]["memory_mb"], 768);
    assert_eq!(change["workspace"]["after"], workspace.to_str().unwrap());
    assert_eq!(change["workspace"]["guest_path"], "/workspace");
    assert_eq!(change["mounts"]["after"][0]["guest_path"], "/inputs");
    assert_eq!(change["mounts"]["after"][0]["access"], "read_only");
    assert_eq!(f.source(), source);
    assert!(!f.root.path().join("agents/helper/home").exists());

    let (op, pending) = submit(&f, &id, &proposed).await;
    let reviewed = f
        .admin("GET", &format!("/admin/approvals/{op}"), None)
        .await
        .json();
    assert_eq!(
        reviewed["assessment"]["configured_agents"],
        assessed["configured_agents"]
    );
    assert_eq!(f.source(), source);
    assert!(client(&f,"worker").call("resolve_approval",&json!({"approval_id":pending["approval_id"],"delegation":"self-appointed","decision":"approve","option":"apply"})).await.is_err());
    assert!(client(&f,"worker").call("submit_policy_change",&json!({"operation_id":op,"candidate":candidate(&id,&proposed.replace("memory_mb = 768","memory_mb = 1024"))})).await.is_err());
    assert_eq!(f.source(), source);

    let outcome = decide(&f, &op, "approve").await;
    assert_eq!(outcome["result"]["status"], "active", "{outcome}");
    assert_eq!(f.source(), proposed);
    assert_eq!(live(&f).await["saved_matches_active"], true);
    let status = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .args(["--instance-dir", f.root.path().to_str().unwrap(), "status"])
        .output()
        .await
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    let configured = status["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "helper")
        .unwrap();
    assert_eq!(configured["agent_id"], HELPER_ID);
    assert_eq!(
        configured["next_start_configuration"]["workspace"],
        workspace.to_str().unwrap()
    );
    assert_eq!(configured["next_start_configuration"]["memory_mb"], 768);
    assert_eq!(
        configured["next_start_configuration"]["mounts"],
        json!([mount])
    );
    assert_eq!(configured["runtime_state"], "stopped");
    assert!(!f.root.path().join("agents/helper/home").exists());
    let denied = f
        .agent(
            "worker",
            "POST",
            "/support/operations",
            Some(json!({
        "operation_id":operation(),"grant":"not-granted","target_id":HELPER_ID,
        "expected_run":null,"operation":{"action":"inspect"}})),
        )
        .await;
    assert_eq!(denied.status, 403, "{}", denied.json());
    let receipt = client(&f, "worker")
        .call("read_policy_change", &json!({"request_id":op}))
        .await
        .unwrap();
    assert_eq!(receipt["result"], outcome["result"]);
    assert_eq!(
        decide(&f, &op, "approve").await["result"],
        outcome["result"]
    );
    f.stop().await;
}

#[tokio::test]
async fn changed_worker_configuration_or_identity_cannot_reuse_a_pending_commissioning_decision() {
    for target_change in ["configuration", "identity"] {
        let f = Fixture::new().await;
        let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
        let (id, source) = snapshot(&f).await;
        let proposed = source.replace("[agents.helper]", "[agents.helper]\nmemory_mb=768");
        let (op, _) = submit(&f, &id, &proposed).await;
        let intervening = if target_change == "identity" {
            source.replace(HELPER_ID, "ag-44444444444444444444444444444444")
        } else {
            source.replace("[agents.helper]", "[agents.helper]\nmemory_mb=2048")
        };
        f.apply(&intervening).await;
        let before = live(&f).await;
        let outcome = decide(&f, &op, "approve").await;
        assert_eq!(outcome["status"], "stale", "{target_change}: {outcome}");
        assert_eq!(f.source(), intervening);
        assert_eq!(live(&f).await, before);
        f.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_multisection_adoption_preserves_secrets_and_replays_without_overwriting() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let original = format!(
        "{}\n# retained authored text\n[private]\npassword='{SECRET}'\n",
        f.source()
    );
    f.apply(&original).await;
    let (id, source) = snapshot(&f).await;
    assert!(!source.contains(SECRET));
    let changed = format!(
        "{}\n[logging.quiet_hosts]\nhosts=['quiet.invalid']\n[controls.network]\naction='warn'\n",
        source.replace("budget=40", "budget=57")
    );
    let private = client(&f, "worker")
        .call("assess_policy", &candidate(&id, &changed))
        .await
        .unwrap();
    assert_eq!(private["operator_notified"], false);
    let (op, pending) = submit(&f, &id, &changed).await;
    assert_eq!(f.source(), original);
    let inspected = f
        .admin("GET", &format!("/admin/approvals/{op}"), None)
        .await
        .json();
    assert_eq!(
        inspected["assessment"]["candidate_revision"],
        private["candidate_revision"]
    );
    assert!(
        inspected["assessment"]["exact_diff"]["after"]
            .as_str()
            .unwrap()
            .contains("quiet.invalid")
    );
    assert!(!inspected.to_string().contains(SECRET));
    assert!(
        pending["assessment"].is_null(),
        "operator-only inputs reached the agent"
    );
    let outcome = decide(&f, &op, "approve").await;
    assert_eq!(outcome["status"], "approved", "{outcome}");
    assert_eq!(outcome["result"]["status"], "active");
    let expected = format!(
        "{}\n[logging.quiet_hosts]\nhosts=['quiet.invalid']\n[controls.network]\naction='warn'\n",
        original.replace("budget=40", "budget=57")
    );
    assert_eq!(f.source(), expected);
    assert_eq!(live(&f).await["saved_matches_active"], true);
    let receipt = client(&f, "worker")
        .call("read_policy_change", &json!({"request_id":op}))
        .await
        .unwrap();
    assert_eq!(receipt["result"], outcome["result"]);
    assert!(receipt["assessment"].is_null());
    let later = expected.replace("budget=57", "budget=61");
    f.apply(&later).await;
    let replay = decide(&f, &op, "approve").await;
    assert_eq!(replay["result"], outcome["result"]);
    assert_eq!(f.source(), later);
    let f = restart(f).await;
    assert_eq!(
        decide(&f, &op, "approve").await["result"],
        outcome["result"]
    );
    assert_eq!(f.source(), later);
    f.stop().await;
}

#[tokio::test]
async fn absent_declined_and_substituted_decisions_leave_saved_and_active_unchanged() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let _helper = controlled_runs::agent_run(f.root.path(), "helper", HELPER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let before = live(&f).await;
    let changed = source.replace("budget=40", "budget=58");
    let (op, pending) = submit(&f, &id, &changed).await;
    let repeated = client(&f, "worker")
        .call(
            "submit_policy_change",
            &json!({"operation_id":operation(),"candidate":candidate(&id,&changed)}),
        )
        .await
        .unwrap();
    assert_eq!(
        repeated["approval_id"], pending["approval_id"],
        "equivalent pending authority was not deduplicated"
    );
    assert!(
        client(&f, "worker")
            .call(
                "submit_policy_change",
                &json!({"operation_id":op,"candidate":candidate(&id,&changed.replace("58","59"))})
            )
            .await
            .is_err()
    );
    assert!(
        client(&f, "helper")
            .call("read_policy_change", &json!({"request_id":op}))
            .await
            .is_err()
    );
    assert!(client(&f,"worker").call("resolve_approval",&json!({"approval_id":pending["approval_id"],"delegation":"unrelated","decision":"approve","option":"apply"})).await.is_err());
    let forged = f
        .agent(
            "worker",
            "POST",
            &format!("/approvals/{op}"),
            Some(json!({"decision":"approve","option":"apply","operator":true})),
        )
        .await;
    assert_ne!(forged.status, 200);
    assert_eq!(decide(&f, &op, "reject").await["status"], "rejected");
    assert_eq!(decide(&f, &op, "approve").await["status"], "rejected");
    assert_eq!(f.source(), source);
    assert_eq!(live(&f).await, before);
    f.stop().await;
}

#[tokio::test]
async fn saved_active_and_requester_changes_stale_the_exact_candidate() {
    for change in ["saved", "active", "requester"] {
        let f = Fixture::new().await;
        let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
        let (id, source) = snapshot(&f).await;
        let (op, _) = submit(&f, &id, &source.replace("budget=40", "budget=58")).await;
        let intervening = source.replace("budget=40", "budget=62");
        let mut _replacement = None;
        if change == "saved" {
            fs::write(f.root.path().join("policy.toml"), &intervening).unwrap();
        }
        if change == "active" {
            f.apply(&intervening).await;
        }
        if change == "requester" {
            _replacement = Some(controlled_runs::agent_run(
                f.root.path(),
                "worker",
                WORKER_ID,
                "abcdef1234567890abcdef1234567890",
            ));
        }
        let saved = f.source();
        let active = live(&f).await;
        let result = decide(&f, &op, "approve").await;
        assert_eq!(result["status"], "stale", "{change}: {result}");
        assert_eq!(f.source(), saved, "{change}");
        assert_eq!(live(&f).await, active, "{change}");
        f.stop().await;
    }
}

#[tokio::test]
async fn restore_explains_intervening_work_and_never_overwrites_a_newer_base() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let (op, _) = submit(&f, &id, &source.replace("budget=40", "budget=58")).await;
    assert_eq!(decide(&f, &op, "approve").await["status"], "approved");
    let changed = f.source().replace("budget=58", "budget=62");
    f.apply(&changed).await;
    let restore_op = operation();
    let input = json!({"operation_id":restore_op,"approval_id":op});
    let prepared = f
        .admin("POST", "/admin/policy/restore", Some(input.clone()))
        .await;
    assert_eq!(prepared.status, 200, "{}", prepared.json());
    let review = prepared.json();
    assert!(
        review["assessment"]["exact_diff"]["before"]
            .as_str()
            .unwrap()
            .contains("budget=62")
    );
    assert!(
        review["assessment"]["exact_diff"]["after"]
            .as_str()
            .unwrap()
            .contains("budget=40")
    );
    assert_eq!(f.source(), changed);
    let newer = changed.replace("budget=62", "budget=63");
    f.apply(&newer).await;
    assert_eq!(decide(&f, &restore_op, "approve").await["status"], "stale");
    assert_eq!(f.source(), newer);
    // A new explicit restore presents the intervening diff to a new decision.
    let next = operation();
    let prepared = f
        .admin(
            "POST",
            "/admin/policy/restore",
            Some(json!({"operation_id":next,"approval_id":op})),
        )
        .await;
    assert_eq!(prepared.status, 200, "{}", prepared.json());
    assert_eq!(decide(&f, &next, "approve").await["status"], "approved");
    assert_eq!(f.source(), source);
    assert_eq!(live(&f).await["saved_matches_active"], true);
    f.stop().await;
}

#[tokio::test]
async fn hidden_candidate_values_keep_distinct_canonical_identities() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let mut requests = Vec::new();
    for value in ["synthetic-first-new-value", "synthetic-second-new-value"] {
        let changed = format!("{source}\n[private]\npassword='{value}'\n");
        let (op, pending) = submit(&f, &id, &changed).await;
        let inspected = f
            .admin("GET", &format!("/admin/approvals/{op}"), None)
            .await
            .json();
        assert!(!inspected.to_string().contains(value));
        let read = client(&f, "worker")
            .call("read_policy_change", &json!({"request_id":op}))
            .await;
        assert!(read.is_ok(), "immediate scoped read failed: {read:?}");
        requests.push((op, pending));
    }
    assert_ne!(requests[0].1["approval_id"], requests[1].1["approval_id"]);
    assert_eq!(
        decide(&f, &requests[0].0, "reject").await["status"],
        "rejected"
    );
    assert_eq!(
        client(&f, "worker")
            .call("read_policy_change", &json!({"request_id":requests[1].0}))
            .await
            .unwrap()["status"],
        "pending"
    );
    assert_eq!(f.source(), source);
    f.stop().await;
}

#[tokio::test]
async fn only_material_service_models_and_grants_stale_the_review() {
    for change in ["model", "grant", "unrelated_model"] {
        let mut f = Fixture::new().await;
        let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
        let model = f.root.path().join("builtin-services/demo.yaml");
        let mut definition = json!({"schema_version":1,"name":"demo","description":"Controlled adoption model",
            "default_host":"models.example.invalid","auth":{"type":"bearer"},
            "capabilities":{"reader":{"routes":[{"methods":["GET"],"path":"/**"}]}}});
        fs::write(&model, definition.to_string()).unwrap();
        assert!(f.proxy.reload_services_if_changed().await.unwrap());
        let source = format!(
            "{}\n[agents.worker.services.demo]\ncapability='reader'\ntoken='synthetic-vault-reference'\naccount='owned'\n",
            f.source()
        );
        f.apply(&source).await;
        let (id, source) = snapshot(&f).await;
        let proposed = source.replace("budget=40", "budget=58");
        let (op, _) = submit(&f, &id, &proposed).await;
        if change == "grant" {
            let reply=f.admin("POST","/admin/gateway/grant",Some(json!({"agent":"worker","service":"demo","method":"GET","path":"/selected","lifetime":"session"}))).await;
            assert_eq!(reply.status, 200, "{}", reply.json());
        } else {
            if change == "model" {
                definition["description"] = json!("Changed reviewed service definition");
                fs::write(&model, definition.to_string()).unwrap();
            } else {
                definition["name"] = json!("unrelated");
                fs::write(
                    f.root.path().join("builtin-services/unrelated.yaml"),
                    definition.to_string(),
                )
                .unwrap();
            }
            assert!(f.proxy.reload_services_if_changed().await.unwrap());
        }
        assert_eq!(
            f.source(),
            source,
            "this control must isolate changes outside the saved source"
        );
        let before = live(&f).await;
        let result = decide(&f, &op, "approve").await;
        if change == "unrelated_model" {
            assert_eq!(result["status"], "approved", "{result}");
            assert_eq!(f.source(), proposed);
        } else {
            assert_eq!(result["status"], "stale", "{change}: {result}");
            assert_eq!(f.source(), source);
            assert_eq!(live(&f).await, before);
        }
        f.stop().await;
    }
}

#[tokio::test]
async fn unused_external_reference_is_refused_without_pending_attention() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let private = f.root.path().join("unapproved-host-input");
    fs::write(&private, "private input must not be used as a list").unwrap();
    let proposed = format!("{source}\n[lists]\nunused='{}'\n", private.display());
    let assessment = client(&f, "worker")
        .call("assess_policy", &candidate(&id, &proposed))
        .await
        .unwrap();
    assert_eq!(assessment["valid"], true);
    let result = client(&f, "worker")
        .call(
            "submit_policy_change",
            &json!({"operation_id":operation(),"candidate":candidate(&id,&proposed)}),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(f.source(), source);
    assert_eq!(live(&f).await["saved_matches_active"], true);
    assert!(
        f.admin("GET", "/admin/approvals", None).await.json()["approvals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.stop().await;
}

#[tokio::test]
async fn actual_save_failure_retains_a_failed_receipt_and_unchanged_policy() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::with_policy_path(1000, false, "policy/policy.toml").await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let before = live(&f).await;
    let (op, _) = submit(&f, &id, &source.replace("budget=40", "budget=58")).await;
    let directory = f.root.path().join("policy");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    let result = decide(&f, &op, "approve").await;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result["status"], "failed", "{result}");
    assert_eq!(result["result"]["policy_changed"], false);
    assert_eq!(f.source(), source);
    assert_eq!(live(&f).await, before);
    assert_eq!(decide(&f, &op, "approve").await["status"], "failed");
    assert_eq!(f.source(), source);
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_edit_while_adoption_waits_for_the_lock_is_not_overwritten() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let (op, _) = submit(&f, &id, &source.replace("budget=40", "budget=58")).await;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.root.path().join(".policy.toml.lock"))
        .unwrap();
    lock.lock().unwrap();
    let approvals = rusqlite::Connection::open_with_flags(
        f.root.path().join("data/approvals.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let intervening = source.replace("budget=40", "budget=63");
    let edit = async {
        let mut observed = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                // A pending HTTP review takes the grant-store lock too. The
                // adoption can hold it while waiting for our file lock, so
                // observe only the canonical decision status for this barrier.
                observed = approvals.query_row(
                    "SELECT status FROM approvals WHERE approval_id=(SELECT approval_id FROM approval_requests WHERE request_id=?1)",
                    [&op], |row| row.get(0),
                ).unwrap();
                if observed == "applying" {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the human decision must be retained before waiting for the policy lock; last observation: {observed}"));
        fs::write(f.root.path().join("policy.toml"), &intervening).unwrap();
        lock.unlock().unwrap();
    };
    let (result, ()) = tokio::join!(decide(&f, &op, "approve"), edit);
    assert_eq!(result["status"], "stale", "{result}");
    assert_eq!(f.source(), intervening);
    let active = live(&f).await;
    assert_eq!(active["saved_matches_active"], false);
    assert_eq!(active["effective"]["budget"], 40);
    f.stop().await;
}

#[tokio::test]
async fn dropped_decision_response_and_restart_reconcile_the_same_receipt() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    let (id, source) = snapshot(&f).await;
    let changed = source.replace("budget=40", "budget=59");
    let (op, _) = submit(&f, &id, &changed).await;
    let body = json!({"decision":"approve","option":"apply"}).to_string();
    let mut connection = tokio::net::TcpStream::connect(("127.0.0.1", f.admin))
        .await
        .unwrap();
    connection.write_all(format!("POST /admin/approvals/{op} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    // Observe that a response started, then lose its status/body and result.
    connection.read_exact(&mut [0_u8; 1]).await.unwrap();
    drop(connection);
    let f = restart(f).await;
    let result = client(&f, "worker")
        .call("read_policy_change", &json!({"request_id":op}))
        .await
        .unwrap();
    assert_eq!(result["status"], "approved", "{result}");
    assert_eq!(result["result"]["status"], "active");
    assert_eq!(f.source(), changed);
    let later = changed.replace("budget=59", "budget=64");
    f.apply(&later).await;
    assert_eq!(decide(&f, &op, "approve").await["result"], result["result"]);
    assert_eq!(f.source(), later);
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_watch_renders_host_consequences_and_decides_exact_content() {
    let f = Fixture::new().await;
    let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
    fs::write(f.root.path().join("config.toml"),format!("admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n",f.admin)).unwrap();
    let (id, source) = snapshot(&f).await;
    let changed = format!(
        "{}\n# \\u001b[2J APPROVED: benign policy\n[controls.network]\nenabled=false\n",
        source.replace("budget=40", "budget=60")
    )
    .replace("[agents.helper]", "[agents.helper]\nmemory_mb=768");
    let (op, _) = submit(&f, &id, &changed).await;
    let mut terminal = operator_pty::Terminal::start(f.root.path(), &["watch", "--no-color"]);
    terminal
        .until(0, "PENDING APPROVALS: 1 (current state refreshed)")
        .await;
    terminal.send("1\n");
    let rendered = terminal
        .until(0, "Request #1 [choice / d / r / l / q]")
        .await;
    let changes = &rendered[rendered
        .find("configured agents:")
        .expect("worker effects precede the decision")..];
    let changes = &changes[..changes
        .find("authority:")
        .expect("authority follows worker effects")];
    assert!(changes.contains("helper") && changes.contains(HELPER_ID));
    assert!(changes.contains("memory mb: 768"));
    terminal.until(0, "Enforcement is disabled").await;
    terminal.until(0, "exact diff:").await;
    let mark = terminal.mark();
    terminal.send("approve apply\n");
    terminal
        .until(mark, "CANONICAL OUTCOME Request #1: approved")
        .await;
    terminal.finish().await;
    assert_eq!(f.source(), changed);
    assert_eq!(live(&f).await["saved_matches_active"], true);
    assert_eq!(
        client(&f, "worker")
            .call("read_policy_change", &json!({"request_id":op}))
            .await
            .unwrap()["result"]["status"],
        "active"
    );
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_scope_expansion_is_reviewed_inline_and_rejection_or_staleness_cannot_dispatch() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use safeyolo_proxy::{
        credentials::{Credential, Secret},
        host_execution::*,
    };
    for decision in ["reject", "stale"] {
        let f = Fixture::new().await;
        let _run = controlled_runs::agent_run(f.root.path(), "worker", WORKER_ID, RUN);
        let task = json!({"permissions":[]});
        assert_eq!(
            f.admin(
                "PUT",
                "/admin/policy/task/host-task",
                Some(json!({"policy":task}))
            )
            .await
            .status,
            200
        );
        assert_eq!(
            f.admin(
                "POST",
                "/admin/policy/task/host-task/activate",
                Some(json!({}))
            )
            .await
            .status,
            200
        );
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        safeyolo_proxy::credentials::open(&f.root.path().join("data"))
            .unwrap()
            .store(Credential::new(
                "host-key",
                "ed25519",
                Secret::new(STANDARD.encode(pkcs8.as_ref())),
            ))
            .unwrap();
        let package: Package =
            serde_json::from_str(include_str!("fixtures/host_execution/package.json")).unwrap();
        let scope = json!({"implementation_sha256":package.operations["restart"].implementation_sha256(),
            "resources":["service:demo"],"arguments":{"wait":[5],"mode":["normal","quiet"]},
            "budgets":{"calls":2,"concurrent":1,"timeout_seconds":15,"output_bytes":512}});
        let issuer = "sy-11111111111111111111111111111111";
        let grant = json!({"principal":{"run":{"agent":"worker","agent_id":WORKER_ID,"run_id":RUN},"task_id":"host-task"},
            "not_before":now()-1,"expires_at":now()+600,"verbs":["discover","propose","invoke"],
            "operations":{"restart":scope},"families":[],"allow_run_refresh":false});
        let mut ceiling = scope.clone();
        ceiling["arguments"]["wait"] = json!([5, 6]);
        let target = json!({"target_id":"owned-review-target","ceiling_revision":"1","allowed_verbs":["discover","propose","invoke"],
            "max_authority_age_seconds":600,"issuers":{issuer:{"revision":"1","public_keys":{"key":STANDARD.encode(key.public_key().as_ref())},
                "authority":{"revision":"1","assessment_revision":"1","observed_at":now()-1,"valid_until":now()+600,"grants":{"task":grant}}}},
            "ceiling":{"restart":ceiling},"package":package,"families":[],"catalogue":null});
        let socket = f.root.path().join("no-dispatch.sock");
        let target_listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        target_listener.set_nonblocking(true).unwrap();
        let binding = json!({"target":target,"issuer_id":issuer,"grant_id":"task","key_id":"key","credential":"host-key",
            "service":"owned-host","endpoint":{"transport":"unix","socket":socket,"executor_uid":unsafe{libc::geteuid()}},
            "task_revision":revision(&task),"timeout_ms":1000,"request_bytes":131072,"response_bytes":1048576});
        let mut document = f.source().parse::<toml_edit::DocumentMut>().unwrap();
        document["host_bindings"]["owned"] = toml_edit::value(binding.to_string());
        let mut rule = toml_edit::Table::new();
        rule["action"] = toml_edit::value("gateway:request");
        rule["resource"] = toml_edit::value("owned-host:/v1/host-execution/*");
        rule["effect"] = toml_edit::value("allow");
        let mut condition = toml_edit::InlineTable::new();
        condition.insert("agent", "worker".into());
        rule["condition"] = toml_edit::value(condition);
        let mut rules = toml_edit::Array::new();
        rules.push(rule.into_inline_table());
        document["hosts"]["*"]["rules"] = toml_edit::value(rules);
        f.apply(&document.to_string()).await;
        let native_policy = safeyolo_proxy::policy::Policy::from_native_path(
            f.config.policy_file.as_ref().unwrap(),
        )
        .unwrap();
        let gateway_permission =
            native_policy.evaluate_gateway_request(safeyolo_proxy::policy::GatewayRequest {
                agent: "worker",
                service: "owned-host",
                capability: "host_execution",
                method: "POST",
                path: Verb::Propose.path(),
            });
        assert_eq!(
            gateway_permission.effect,
            safeyolo_proxy::policy::Effect::Allow,
            "generated fixture rules: {}",
            document["hosts"]["*"].to_string()
        );
        let (id, source) = snapshot(&f).await;
        let mut expanded = binding.clone();
        expanded["target"]["issuers"][issuer]["authority"]["grants"]["task"]["operations"]["restart"]
            ["arguments"]["wait"] = json!([5, 6]);
        document["host_bindings"]["owned"] = toml_edit::value(expanded.to_string());
        let changed = document.to_string();
        let assessment = client(&f, "worker")
            .call("assess_policy", &candidate(&id, &changed))
            .await
            .unwrap();
        assert_eq!(
            assessment["host_operations"]["before"][0]["full_grant"]["operations"]["restart"]["arguments"]
                ["wait"],
            json!([5])
        );
        assert_eq!(
            assessment["host_operations"]["after"][0]["full_grant"]["operations"]["restart"]["arguments"]
                ["wait"],
            json!([5, 6])
        );
        let (op, _) = submit(&f, &id, &changed).await;
        fs::write(f.root.path().join("config.toml"),format!("admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n",f.admin)).unwrap();
        if decision == "reject" {
            let mut terminal =
                operator_pty::Terminal::start(f.root.path(), &["watch", "--no-color"]);
            terminal
                .until(0, "PENDING APPROVALS: 1 (current state refreshed)")
                .await;
            terminal.send("1\n");
            let rendered = terminal
                .until(0, "Request #1 [choice / d / r / l / q]")
                .await;
            assert!(rendered.contains("owned-review-target") && rendered.contains("uid:1000"));
            assert!(rendered.contains("full grant:") && rendered.contains("target ceiling:"));
            // A later arrival cannot replace the request already under review.
            let (other, _) = submit(&f, &id, &source.replace("budget=40", "budget=41")).await;
            let mark = terminal.mark();
            terminal.send("r\n");
            terminal
                .until(mark, "CANONICAL OUTCOME Request #1: rejected")
                .await;
            terminal.finish().await;
            assert_eq!(
                client(&f, "worker")
                    .call("read_policy_change", &json!({"request_id":other}))
                    .await
                    .unwrap()["status"],
                "pending"
            );
        } else {
            f.apply(&source.replace("budget=40", "budget=42")).await;
            let executable = std::env::var_os("SAFEYOLO_NATIVE_CLI")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_safeyolo").into());
            let output = tokio::process::Command::new(executable)
                .args([
                    "--instance-dir",
                    f.root.path().to_str().unwrap(),
                    "approvals",
                    "approve",
                    &op,
                    "--option",
                    "apply",
                    "--json",
                ])
                .stdin(std::process::Stdio::null())
                .output()
                .await
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("Approval is stale"));
        }
        let retained = client(&f, "worker")
            .call("read_policy_change", &json!({"request_id":op}))
            .await
            .unwrap();
        assert_eq!(
            retained["status"],
            if decision == "reject" {
                "rejected"
            } else {
                // CLI preflight refuses the stale selection without POSTing
                // a decision. The original request is still recorded pending.
                "pending"
            }
        );
        if decision == "stale" {
            let current = f
                .admin("GET", &format!("/admin/approvals/{op}"), None)
                .await
                .json();
            assert_eq!(current["status"], "stale");
            assert_eq!(current["reviewed_inputs_match_current"], false);
        }
        let target: Target = serde_json::from_value(target).unwrap();
        let invocation = json!({"operation_id":"restart","resource_id":"service:demo",
            "operation_sha256":package.operation_sha256("restart").unwrap(),"implementation_sha256":package.operations["restart"].implementation_sha256(),
            "arguments":{"wait":6},"expected_assessment_sha256":null});
        let action: Action =
            serde_json::from_value(json!({"kind":"propose","invocation":invocation})).unwrap();
        let refused = f
            .agent(
                "worker",
                "POST",
                "/gateway/host/owned",
                Some(json!({"request_id":"outside-scope","action":action,
            "expected":target.request_revisions(issuer,"task",&action).unwrap()})),
            )
            .await;
        assert_eq!(refused.status, 403, "{}", refused.json());
        assert!(
            refused.json()["refusal"]["message"]
                .as_str()
                .unwrap()
                .contains("outside effective authority"),
            "unexpected refusal: {}",
            refused.json()
        );
        assert_eq!(
            target_listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        f.stop().await;
    }
}
