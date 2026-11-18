//! Real local HTTP source/approval boundaries with controlled ingress runs.
//! This fixture does not establish the separate installed model-led journey.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{fs, time::Duration};

#[path = "support/controlled_runs.rs"]
mod controlled_runs;
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
    let f = Fixture::new().await;
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
    let f = Fixture::new().await;
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
    assert_eq!(
        f.agent(
            "helper",
            "POST",
            "/api/coord/rooms/forbidden/send",
            Some(json!({"body":"not authorized"}))
        )
        .await
        .status,
        403
    );
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
    let changed = f
        .source()
        .replace(WORKER_ID, "ag-44444444444444444444444444444444");
    f.apply(&changed).await;
    assert_eq!(
        query(&f, input).await.status,
        403,
        "recreated same-name subject inherited evidence"
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
async fn operator_narrows_the_canonical_request_and_sources_fail_honestly_without_coord() {
    let f = Fixture::new().await;
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
