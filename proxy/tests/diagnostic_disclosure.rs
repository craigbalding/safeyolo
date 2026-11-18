//! Real local HTTP source/approval boundaries with controlled ingress runs.
//! This fixture does not establish the separate installed model-led journey.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{fs, time::Duration};

#[path = "support/controlled_runs.rs"]
mod controlled_runs;
#[path = "diagnostic_disclosure/coord.rs"]
mod coord;
#[path = "support/shared_approvals.rs"]
#[allow(dead_code)]
mod fixture;
mod test_owned_endpoint;
use fixture::{Fixture, HELPER_ID, WORKER_ID};
const PEER_ID: &str = "ag-33333333333333333333333333333333";
const RUN: &str = "0123456789abcdef0123456789abcdef";

fn timestamp(seconds: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
fn request(id: &str, snapshot: bool, subjects: Vec<&str>) -> Value {
    json!({"operation_id":id,"instance_id":"sy-11111111111111111111111111111111","subjects":subjects,
        "scope":{"audit":true,"runtime":false,"rooms":[],"system_categories":[],"history":{"since":null,"until":if snapshot {Some(timestamp(60))}else{None},"future":!snapshot},"snapshot":snapshot},
        "expires_at":null,"reason":"Investigate communication between selected peers"})
}
async fn submit(f: &Fixture, value: Value) -> Value {
    let response = f
        .agent(
            "helper",
            "POST",
            "/support/diagnostics/requests",
            Some(value),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.json());
    response.json()
}
async fn approve(f: &Fixture, id: &str) -> Value {
    let response = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":"approve","option":"diagnostics"})),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.json());
    response.json()
}
async fn query(f: &Fixture, input: Value) -> fixture::Reply {
    f.agent("helper", "POST", "/support/diagnostics/query", Some(input))
        .await
}
fn runs(f: &Fixture) -> Vec<controlled_runs::Backend> {
    [
        ("helper", HELPER_ID),
        ("worker", WORKER_ID),
        ("peer", PEER_ID),
    ]
    .iter()
    .map(|(name, id)| controlled_runs::agent_run(f.root.path(), name, id, RUN))
    .collect()
}

#[tokio::test]
async fn snapshot_pages_retries_and_source_loss_keep_the_original_records() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    for name in ["worker", "worker", "peer", "helper"] {
        assert_eq!(f.network(name, f.address).await.status, 428);
    }
    let discovered = f.agent("helper", "GET", "/support/diagnostics", None).await;
    assert_eq!(discovered.status, 200);
    let pending = submit(&f, request("fixed", true, vec!["helper", "worker"])).await;
    let id = pending["approval_id"].as_str().unwrap();
    let input = json!({"operation_id":"collection","grant":id,"limit":1,"page_token":null});
    assert_eq!(
        query(&f, input.clone()).await.status,
        403,
        "pending request disclosed evidence"
    );
    let approved = approve(&f, id).await;
    assert_eq!(approved["status"], "approved", "{approved}");
    let first = query(&f, input.clone()).await;
    assert_eq!(first.status, 200, "{}", first.json());
    let first = first.json();
    assert!(first["total_matches"].as_u64().unwrap() > 1, "{first}");
    assert_eq!(first["rows"].as_array().unwrap().len(), 1);
    let original_total = first["total_matches"].clone();
    assert!(
        first["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["subject_id"] != PEER_ID)
    );
    assert_eq!(f.network("worker", f.address).await.status, 428);
    let retry = query(&f, input.clone()).await.json();
    assert_eq!(retry["rows"], first["rows"]);
    assert_eq!(retry["collection_id"], first["collection_id"]);
    assert_eq!(retry["total_matches"], first["total_matches"]);
    assert_eq!(retry["total_matches"], original_total);
    let mut next = input.clone();
    next["page_token"] = first["next_page_token"].clone();
    // Ignore one completed response, then retry its original continuation.
    let lost = query(&f, next.clone()).await;
    assert_eq!(lost.status, 200);
    assert_eq!(
        query(&f, next.clone()).await.json()["rows"],
        lost.json()["rows"]
    );
    let mut hostile = next.clone();
    hostile["filter"] = json!({"subject_ids":[PEER_ID]});
    assert_eq!(query(&f, hostile).await.status, 400);
    let mut forged = next.clone();
    forged["filter"] = json!({"events":["traffic.request_completed"]});
    assert_eq!(query(&f, forged).await.status, 403);
    fs::rename(
        f.root.path().join("audit.jsonl"),
        f.root.path().join("pruned.jsonl"),
    )
    .unwrap();
    let after_pruning = query(&f, next.clone()).await;
    assert_eq!(after_pruning.status, 200, "{}", after_pruning.json());
    assert_eq!(after_pruning.json()["rows"], lost.json()["rows"]);
    // The canonical snapshot marker prevents replacing a lost private result.
    for entry in fs::read_dir(f.root.path().join("data/support-operations")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            fs::remove_file(path).unwrap();
        }
    }
    assert_eq!(query(&f, input).await.status, 410);
    f.stop().await;
}

#[tokio::test]
async fn live_disclosure_rechecks_restarts_expiry_replacement_and_read_only_scope() {
    let f = Fixture::with_installed_settings().await;
    let mut backends = runs(&f);
    for name in ["worker", "peer", "helper"] {
        assert_eq!(f.network(name, f.address).await.status, 428);
    }
    let pending = submit(
        &f,
        request("standing", false, vec!["helper", "worker", "peer"]),
    )
    .await;
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let input = json!({"operation_id":"all-selected","grant":id});
    let result = query(&f, input.clone()).await;
    assert_eq!(result.status, 200, "{}", result.json());
    for subject in [HELPER_ID, WORKER_ID, PEER_ID] {
        assert!(
            result.json()["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["subject_id"] == subject),
            "{}",
            result.json()
        );
    }
    assert!(
        result.json()["rows"].as_array().unwrap().iter().any(|row| {
            row["record"]["event"] == "traffic.response"
                && row["record"]["details"]["status"] == 428
                && row["record"]["details"]["sandbox_run"]["run_id"] == RUN
        }),
        "complete response fields were not disclosed: {}",
        result.json()
    );
    assert_eq!(
        f.agent(
            "peer",
            "POST",
            "/support/diagnostics/query",
            Some(input.clone())
        )
        .await
        .status,
        403
    );
    assert_eq!(f.agent("helper","POST","/support/operations",Some(json!({"operation_id":"no-admin","grant":id,"target_id":WORKER_ID,"expected_run":null,"operation":{"action":"inspect"}}))).await.status,403);
    let invalid=query(&f,json!({"operation_id":"invalid","grant":id,"filter":{"request_id":"req-00000000000000000000000000000000"}})).await;
    assert_eq!(invalid.status, 400);
    let unsupported = query(
        &f,
        json!({"operation_id":"invalid2","grant":id,"filter":{"unknown":true}}),
    )
    .await;
    assert_eq!(unsupported.status, 400);
    // A current run of the same durable requester retains standing disclosure.
    drop(backends.remove(0));
    let _new = controlled_runs::agent_run(
        f.root.path(),
        "helper",
        HELPER_ID,
        "fedcba9876543210fedcba9876543210",
    );
    assert_eq!(query(&f, input.clone()).await.status, 200);
    let mut changed = f.source().parse::<toml_edit::DocumentMut>().unwrap();
    changed["agents"]["worker"]["agent_id"] =
        toml_edit::value("ag-44444444444444444444444444444444");
    f.apply(&changed.to_string()).await;
    assert_eq!(
        query(&f, input).await.status,
        403,
        "recreated same-name subject inherited evidence"
    );
    let replaced = submit(&f, request("replacement-history", false, vec!["worker"])).await;
    let replaced = replaced["approval_id"].as_str().unwrap();
    approve(&f, replaced).await;
    let replaced = query(
        &f,
        json!({"operation_id":"replacement-history","grant":replaced}),
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.json());
    assert!(
        replaced.json()["rows"].as_array().unwrap().is_empty(),
        "predecessor records were relabelled: {}",
        replaced.json()
    );
    let mut temporary = request("temporary", false, vec!["helper"]);
    temporary["expires_at"] = json!(timestamp(1));
    let pending = submit(&f, temporary).await;
    let temporary = pending["approval_id"].as_str().unwrap();
    approve(&f, temporary).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        query(&f, json!({"operation_id":"expired","grant":temporary}))
            .await
            .status,
        403
    );
    f.stop().await;
}

#[tokio::test]
async fn filters_keep_instance_run_and_correlation_authority_and_project_system_fields() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    let blocked = f.network("worker", f.address).await;
    assert_eq!(blocked.status, 428);
    let pending = submit(&f, request("hostile", false, vec!["helper", "worker"])).await;
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let baseline = query(&f, json!({"operation_id":"baseline", "grant":id}))
        .await
        .json();
    let worker = baseline["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["subject_id"] == WORKER_ID && row["record"]["event"] == "traffic.response")
        .expect("actual worker response");
    let runtime = worker["record"]["details"]["runtime_id"].clone();
    let correlated = query(
        &f,
        json!({"operation_id":"correlated","grant":id,
        "filter":{"runtime_id":runtime,"request_id":blocked.id()}}),
    )
    .await
    .json();
    assert!(
        !correlated["rows"].as_array().unwrap().is_empty(),
        "{correlated}"
    );
    assert!(
        correlated["rows"].as_array().unwrap().iter().all(
            |row| row["subject_id"] == WORKER_ID && row["record"]["request_id"] == blocked.id()
        )
    );
    for (name, filter) in [
        (
            "wrong-runtime",
            json!({"runtime_id":"another-runtime", "request_id":blocked.id()}),
        ),
        (
            "wrong-run",
            json!({"run_id":"ffffffffffffffffffffffffffffffff"}),
        ),
    ] {
        let result = query(&f, json!({"operation_id":name,"grant":id,"filter":filter})).await;
        assert_eq!(result.status, 200);
        assert!(
            result.json()["rows"].as_array().unwrap().is_empty(),
            "{}",
            result.json()
        );
    }
    for field in ["agent_id", "instance_id", "run_id"] {
        let mut forged = request(&format!("forged-{field}"), false, vec!["helper"]);
        forged[field] = json!("attacker-selected");
        assert_eq!(
            f.agent(
                "helper",
                "POST",
                "/support/diagnostics/requests",
                Some(forged)
            )
            .await
            .status,
            400
        );
    }
    let mut retained = String::new();
    // Valid current envelopes with hostile nested values at the source boundary.
    for (event, details) in [
        (
            "ops.audit_validation_failed",
            json!({"connected":false,"component":"audit",
            "admin_token":"synthetic-sensitive-marker","reference":{"raw":"synthetic-sensitive-marker"}}),
        ),
        (
            "ops.unselected",
            json!({"secret":"unselected-category-marker"}),
        ),
    ] {
        let row = json!({"schema_version":2,"event_id":"synthetic-sensitive-marker","ts":timestamp(-1),"event":event,"kind":"ops",
            "severity":"high","summary":"Controlled system event","details":details})
        .to_string();
        safeyolo_proxy::audit::parse_record(&row).unwrap();
        retained.push_str(&row);
        retained.push('\n');
    }
    // An immutable retained file avoids interleaving with the live writer.
    fs::write(f.root.path().join("audit.jsonl.1"), retained).unwrap();
    let mut system = request("system", true, vec!["helper"]);
    system["scope"]["audit"] = json!(false);
    system["scope"]["system_categories"] = json!(["audit_health"]);
    let pending = submit(&f, system).await;
    let system_id = pending["approval_id"].as_str().unwrap();
    approve(&f, system_id).await;
    let system = query(&f, json!({"operation_id":"system","grant":system_id}))
        .await
        .json();
    assert!(
        system["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["record"]["details"]["connected"] == false),
        "{system}"
    );
    assert!(!system.to_string().contains("synthetic-sensitive-marker"));
    assert!(!system.to_string().contains("unselected-category-marker"));
    assert_eq!(
        query(
            &f,
            json!({"operation_id":"unselected","grant":id,"filter":{"sources":["coord_health"]}})
        )
        .await
        .status,
        403
    );
    let other = f.agent("peer", "POST", "/support/diagnostics/query",
        Some(json!({"operation_id":"stolen","grant":system_id,"page_token":baseline["next_page_token"]}))).await;
    assert_eq!(other.status, 403);
    fs::write(
        f.root.path().join("data/instance_id"),
        "sy-55555555555555555555555555555555",
    )
    .unwrap();
    assert_eq!(
        query(
            &f,
            json!({"operation_id":"changed-owner","grant":system_id})
        )
        .await
        .status,
        403
    );
    f.stop().await;
}

#[tokio::test]
async fn standing_grant_narrowing_revocation_and_snapshot_retention_apply_to_every_page() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    for name in ["worker", "helper"] {
        assert_eq!(f.network(name, f.address).await.status, 428);
    }
    let pending = submit(
        &f,
        request("standing-pages", false, vec!["helper", "worker"]),
    )
    .await;
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let input = json!({"operation_id":"pages","grant":id,"limit":1});
    let first = query(&f, input.clone()).await.json();
    assert!(first["next_page_token"].is_string(), "{first}");
    let mut proposal = json!({"expected_revision":first["applied_scope"]["acknowledgment"],
        "grant":first["applied_scope"]});
    proposal["grant"]["targets"] = json!([{"name":"helper","agent_id":HELPER_ID}]);
    let preview = f
        .admin(
            "POST",
            &format!("/admin/support-grants/{id}/preview"),
            Some(proposal.clone()),
        )
        .await;
    assert_eq!(preview.status, 200, "{}", preview.json());
    proposal["grant"] = preview.json()["after"].clone();
    proposal["grant"]["acknowledgment"] = preview.json()["acknowledgment"].clone();
    proposal["authority"] = preview.json()["authority"].clone();
    let applied = f
        .admin(
            "POST",
            &format!("/admin/support-grants/{id}/apply"),
            Some(proposal),
        )
        .await;
    assert_eq!(applied.status, 200, "{}", applied.json());
    assert!(applied.json()["error"].is_null(), "{}", applied.json());
    let mut next = input.clone();
    next["page_token"] = first["next_page_token"].clone();
    assert_eq!(query(&f, next).await.status, 403);
    let narrowed = query(&f, input.clone()).await;
    assert_eq!(narrowed.status, 200, "{}", narrowed.json());
    assert!(
        narrowed.json()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["subject_id"] == HELPER_ID)
    );
    let revoked = f
        .admin(
            "POST",
            &format!("/admin/support-grants/{id}/revoke"),
            Some(json!({"expected_revision":narrowed.json()["applied_scope"]["acknowledgment"]})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
    assert_eq!(query(&f, input).await.status, 403);
    let pending = submit(&f, request("retention", true, vec!["helper"])).await;
    let id = pending["approval_id"].as_str().unwrap();
    approve(&f, id).await;
    let input = json!({"operation_id":"retention","grant":id,"limit":1});
    let first = query(&f, input.clone()).await;
    assert_eq!(first.status, 200, "{}", first.json());
    for entry in fs::read_dir(f.root.path().join("data/support-operations")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if receipt["grant"] == id {
                receipt["retain_until"] = json!(0);
                fs::write(path, receipt.to_string()).unwrap();
            }
        }
    }
    assert_eq!(query(&f, input).await.status, 410);
    f.stop().await;
}

#[tokio::test]
async fn operator_narrows_the_canonical_request_and_sources_fail_honestly_without_coord() {
    let f = Fixture::with_installed_settings().await;
    let _runs = runs(&f);
    let mut selected = request("narrow", false, vec!["helper", "worker"]);
    selected["scope"]["system_categories"] = json!(["audit_health", "coord_health"]);
    let pending = submit(&f, selected.clone()).await;
    let id = pending["approval_id"].as_str().unwrap();
    selected["scope"]["system_categories"] = json!(["audit_health"]);
    let narrowed=f.admin("POST",&format!("/admin/approvals/{id}/diagnostic-selection"),Some(json!({"expected_authority_digest":pending["authority_digest"],"expected_selection_revision":null,"subject_ids":[HELPER_ID],"scope":selected["scope"],"expires_at":null}))).await;
    assert_eq!(narrowed.status, 200, "{}", narrowed.json());
    assert_eq!(
        query(&f, json!({"operation_id":"still-pending","grant":id}))
            .await
            .status,
        403
    );
    approve(&f, id).await;
    let result = query(&f, json!({"operation_id":"narrowed","grant":id})).await;
    assert_eq!(result.status, 200, "{}", result.json());
    assert_eq!(
        result.json()["applied_scope"]["targets"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        result.json()["applied_scope"]["targets"][0]["agent_id"],
        HELPER_ID
    );
    assert!(
        !result.json()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["subject_id"] == WORKER_ID)
    );
    let mut bad = request("forged", false, vec!["helper"]);
    bad["instance_id"] = json!("sy-wrong-instance");
    assert_ne!(
        f.agent("helper", "POST", "/support/diagnostics/requests", Some(bad))
            .await
            .status,
        200
    );
    let rejected = submit(&f, request("reject", false, vec!["worker"])).await;
    let rejected = rejected["approval_id"].as_str().unwrap();
    assert_eq!(
        f.admin(
            "POST",
            &format!("/admin/approvals/{rejected}"),
            Some(json!({"decision":"reject"}))
        )
        .await
        .status,
        200
    );
    assert_eq!(
        query(&f, json!({"operation_id":"rejected","grant":rejected}))
            .await
            .status,
        403
    );
    let mut source_loss = request("loss", true, vec!["helper"]);
    source_loss["scope"]["system_categories"] = json!(["audit_health"]);
    let missing = submit(&f, source_loss).await;
    let missing = missing["approval_id"].as_str().unwrap();
    approve(&f, missing).await;
    f.make_audit_unavailable();
    let loss = query(&f, json!({"operation_id":"lost-source","grant":missing})).await;
    assert_eq!(loss.status, 200, "{}", loss.json());
    assert_eq!(loss.json()["sources"][0]["status"], "unavailable");
    f.stop().await;
}
