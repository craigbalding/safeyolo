//! Private terminal results use real pinned JetStream and authenticated UDS.
//! The requester client is disconnected during decisions and expiry. Controlled
//! backend records exercise identity; these tests do not assert guest isolation.
use super::*;
use futures_util::StreamExt;
use operator_nats::Nats;
use safeyolo_proxy::{coord_rooms, coord_tools::Client};

pub(super) fn prepare(f: &Fixture) {
    fs::write(f.root.path().join("config.toml"), "admin_port=0\n").unwrap();
    fs::write(
        f.root.path().join("data/instance_id"),
        "sy-private-result-test",
    )
    .unwrap();
    coord_rooms::bootstrap(f.root.path()).unwrap();
}

fn client(f: &Fixture, agent: &str) -> Client {
    Client {
        socket: Some(f.root.path().join(format!("{agent}.sock"))),
        token_file: f.root.path().join("data/agent_token"),
        home: None,
    }
}

async fn blocked(f: &Fixture) -> String {
    let response = f.network("worker", f.address).await;
    assert_eq!(response.status, 428);
    no_origin(f).await;
    response.id()
}

pub(super) async fn canonical_id(f: &Fixture, request: &str) -> String {
    f.admin("GET", &format!("/admin/approvals/{request}"), None)
        .await
        .json()["approval_id"]
        .as_str()
        .unwrap()
        .into()
}

pub(super) async fn resolve(f: &Fixture, id: &str, decision: &str, option: &str) {
    let result = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":decision,"option":option})),
        )
        .await;
    assert_eq!(result.status, 200, "{}", result.json());
}

pub(super) async fn result(f: &Fixture, id: &str, outcome: &str) -> Value {
    timeout(Duration::from_secs(20), async {
        loop {
            let page = client(f, "worker")
                .call(
                    "wait_for_coord",
                    &json!({"since_sequence":0,"limit":200,"timeout_seconds":1}),
                )
                .await
                .unwrap();
            for item in page["objects"].as_array().unwrap() {
                if item["object"]["approval_id"] == id {
                    assert_eq!(item["edge"]["kind"], "approval_result");
                    assert!(item["edge"]["room_id"].is_null());
                    assert_eq!(item["object"]["status"], outcome, "{item}");
                    let attention = item["edge"]["attention_id"].as_str().unwrap();
                    assert!(
                        client(f, "helper")
                            .call("read_attention", &json!({"attention_id":attention}))
                            .await
                            .is_err()
                    );
                    return item.clone();
                }
            }
        }
    })
    .await
    .expect("private result must reach the authenticated requester")
}

pub(super) async fn projected(f: &Fixture, id: &str) -> String {
    timeout(Duration::from_secs(20), async {
        loop {
            let db=rusqlite::Connection::open(f.root.path().join("data/coord/v0.db")).unwrap();
            if let Ok(id) = db.query_row("SELECT attention_id FROM coord_attention_edges WHERE object_id=?1 AND kind='approval_result'",[id],|r|r.get::<_,String>(0)) { return id; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("reference must be retained before the requester connects")
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn private_results_survive_offline_decisions_and_broker_proxy_requester_restart() {
    let f = Fixture::new().await;
    prepare(&f);
    let nats = Nats::start_jetstream(f.root.path()).await;
    let backend = Backend(runs(&f));
    let publisher = Nats::publisher(f.root.path()).await;
    let mut rooms = publisher.subscribe("rooms.>").await.unwrap();
    publisher.flush().await.unwrap();
    let rejected = canonical_id(&f, &blocked(&f).await).await;
    // No requester attention client is connected during this terminal write.
    resolve(&f, &rejected, "reject", "run").await;
    projected(&f, &rejected).await;
    let approved = canonical_id(&f, &blocked(&f).await).await;
    resolve(&f, &approved, "approve", "persistent").await;
    projected(&f, &approved).await;
    no_origin(&f).await;
    assert!(
        timeout(Duration::from_millis(100), rooms.next())
            .await
            .is_err(),
        "private results entered a shared room"
    );
    drop(rooms);
    drop(publisher);
    drop(nats);
    assert!(
        client(&f, "worker")
            .call(
                "wait_for_coord",
                &json!({"since_sequence":0,"limit":200,"timeout_seconds":0})
            )
            .await
            .is_err(),
        "unavailable result resolution exposed a later cursor"
    );
    drop(backend);
    let _nats = Nats::start_jetstream(f.root.path()).await;
    let _new_backend = Backend(bound_runs(
        &f,
        "1123456789abcdef0123456789abcdef",
        &[
            ("worker", WORKER_ID),
            ("helper", HELPER_ID),
            ("peer", PEER_ID),
        ],
    ));
    let f = f.restart().await;
    let rejection = result(&f, &rejected, "rejected").await;
    result(&f, &approved, "approved").await;
    // Exercise the supervisor against the real producer's roomless references,
    // after broker/proxy/requester restart, without granting room authority.
    let page = client(&f, "worker")
        .call(
            "wait_for_coord",
            &json!({"since_sequence":0,"limit":16,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    let mut supervisor = safeyolo_proxy::coord_supervisor::Supervisor {
        config: safeyolo_proxy::coord_supervisor::Config::default(),
        state: safeyolo_proxy::coord_supervisor::State::default(),
        state_path: f.root.path().join("supervisor-state.json"),
        client: client(&f, "worker"),
        harness_args: vec![],
        initial_preflight_complete: false,
    };
    let rooms = std::collections::BTreeMap::new();
    assert_eq!(supervisor.accept_page(&page, &rooms).unwrap(), 2);
    supervisor.state =
        safeyolo_proxy::coord_supervisor::State::load(&supervisor.state_path).unwrap();
    assert_eq!(
        supervisor.state.safe_cursor,
        page["next_cursor"].as_u64().unwrap()
    );
    assert_eq!(
        &supervisor.state.approval_notifications,
        page["objects"].as_array().unwrap()
    );
    assert_eq!(supervisor.accept_page(&page, &rooms).unwrap(), 0);
    assert_eq!(supervisor.state.approval_notifications.len(), 2);
    assert!(supervisor.state.in_flight.is_empty());
    assert!(supervisor.state.recent_attention_ids.is_empty());
    // Repeating an outcome is harmless and cannot execute the original traffic.
    let repeated = client(&f, "worker")
        .call(
            "read_attention",
            &json!({"attention_id":rejection["edge"]["attention_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(repeated["edge"], rejection["edge"]);
    assert_eq!(repeated["object"], rejection["object"]);
    // The resolved wait also qualifies its source; that context is not part
    // of the canonical object returned by a direct attention read.
    assert_eq!(rejection["instance_id"], "sy-private-result-test");
    no_origin(&f).await;
    let unrelated = client(&f, "helper")
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"limit":200,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    assert_eq!(unrelated["edges"], json!([]));
    let audit = fs::read_to_string(f.root.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains("\"kind\":\"approval_result\""));
    assert!(!audit.contains("This result grants no authority"));
    let db = rusqlite::Connection::open(f.root.path().join("data/coord/v0.db")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM coord_attention_edges WHERE kind='approval_result'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn private_accepted_results_stay_withheld_after_revoke_regrant_and_projection_recreation() {
    let f = Fixture::new().await;
    prepare(&f);
    let nats = Nats::start_jetstream(f.root.path()).await;
    let id = canonical_id(&f, &blocked(&f).await).await;
    resolve(&f, &id, "reject", "persistent").await;
    let attention = projected(&f, &id).await;
    drop(nats);
    let original = f.source();
    // Revoke even while the broker is unavailable. Restore the same stable ID
    // deliberately: the durable tombstone must survive that stronger case too.
    f.apply(&original.replace(WORKER_ID, "ag-44444444444444444444444444444444"))
        .await;
    f.apply(&original).await;
    let _nats = Nats::start_jetstream(f.root.path()).await;
    let f = f.restart().await;
    assert!(
        client(&f, "worker")
            .call("read_attention", &json!({"attention_id":attention}))
            .await
            .is_err()
    );
    let own = f
        .agent("worker", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(
        own.status, 200,
        "canonical requester read was revoked with delivery"
    );
    assert_eq!(own.json()["status"], "rejected");
    assert_eq!(own.json()["result_delivery"]["status"], "withheld");
    let db = rusqlite::Connection::open(f.root.path().join("data/coord/v0.db")).unwrap();
    db.execute(
        "DELETE FROM coord_attention_edges WHERE kind='approval_result'",
        [],
    )
    .unwrap();
    drop(db);
    let f = f.restart().await;
    let page = client(&f, "worker")
        .call(
            "wait_for_coord",
            &json!({"since_sequence":0,"limit":200,"timeout_seconds":1}),
        )
        .await
        .unwrap();
    assert_eq!(page["objects"], json!([]));
    // A different stable identity with the reused human name inherits neither
    // the private edge nor the existing canonical own-read authority.
    f.apply(&original.replace(WORKER_ID, "ag-55555555555555555555555555555555"))
        .await;
    assert_ne!(
        f.agent("worker", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        200
    );
    assert!(
        client(&f, "worker")
            .call("read_attention", &json!({"attention_id":attention}))
            .await
            .is_err()
    );
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn private_result_retention_expiry_is_irreversible_and_pressure_preserves_canonical_controls()
{
    let f = Fixture::new().await;
    prepare(&f);
    let nats = Nats::start_jetstream(f.root.path()).await;
    let id = canonical_id(&f, &blocked(&f).await).await;
    resolve(&f, &id, "reject", "persistent").await;
    let attention = projected(&f, &id).await;
    // Advance the canonical delivery deadline, without waiting seven days.
    let db = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    db.execute("UPDATE approvals SET record=json_set(record,'$.result_delivery.expires_at',0) WHERE approval_id=?1",[&id]).unwrap();
    assert!(
        client(&f, "worker")
            .call("read_attention", &json!({"attention_id":attention}))
            .await
            .is_err()
    );
    // Restoring the deadline and reconstructing attention cannot undo expiry.
    db.execute("UPDATE approvals SET record=json_set(record,'$.result_delivery.expires_at',4102444800) WHERE approval_id=?1",[&id]).unwrap();
    drop(db);
    let connection = Nats::publisher(f.root.path()).await;
    let js = async_nats::jetstream::new(connection);
    let mut stream = js.get_stream("APPROVAL_RESULTS").await.unwrap();
    let mut config = stream.info().await.unwrap().config.clone();
    config.max_bytes = 1;
    js.update_stream(config).await.unwrap();
    let second = canonical_id(&f, &blocked(&f).await).await;
    resolve(&f, &second, "reject", "persistent").await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let count = rusqlite::Connection::open(f.root.path().join("data/coord/v0.db"))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM coord_attention_edges WHERE object_id=?1",
            [&second],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "broker rejection was reported as retained delivery"
    );
    let read = f
        .agent("worker", "GET", &format!("/approvals/{second}"), None)
        .await;
    assert_eq!(read.status, 200);
    assert_eq!(read.json()["status"], "rejected");
    assert_eq!(read.json()["result_delivery"]["status"], "pending");
    let denied = f.network("worker", f.address).await;
    assert_eq!(denied.status, 428);
    no_origin(&f).await;
    assert!(
        fs::read_to_string(f.root.path().join("audit.jsonl"))
            .unwrap()
            .contains("admin.approval_decided")
    );
    assert!(
        fs::metadata(f.root.path().join("flows.sqlite3"))
            .unwrap()
            .len()
            > 0
    );
    drop(nats);
    let _nats = Nats::start_jetstream(f.root.path()).await;
    let f = f.restart().await;
    assert!(
        client(&f, "worker")
            .call("read_attention", &json!({"attention_id":attention}))
            .await
            .is_err()
    );
    // The previous connection reconnects only to its original dynamic endpoint;
    // use the restarted broker's current authenticated endpoint.
    let current = async_nats::jetstream::new(Nats::publisher(f.root.path()).await);
    let mut config = current
        .get_stream("APPROVAL_RESULTS")
        .await
        .unwrap()
        .info()
        .await
        .unwrap()
        .config
        .clone();
    config.max_bytes = 4 * 1024 * 1024;
    current.update_stream(config).await.unwrap();
    result(&f, &second, "rejected").await;
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn private_service_credential_expiry_uses_its_canonical_owner() {
    let (f, _backend, vault) = service_authorization::setup().await;
    prepare(&f);
    let _nats = Nats::start_jetstream(f.root.path()).await;
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::seconds(3);
    let mut credential = safeyolo_proxy::credentials::Credential::new(
        "provider",
        "api_key",
        safeyolo_proxy::credentials::Secret::new(SECRET),
    );
    credential.expires_at = Some(
        expiry
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    );
    vault.store(credential).unwrap();
    let request=f.agent("worker","POST","/gateway/request-access",Some(json!({"service":"scoped","capability":"reader","account":"work-account","credential":"provider","resources":["/data/*"]}))).await;
    assert_eq!(request.status, 202, "{}", request.json());
    let id = canonical_id(&f, &request.id()).await;
    let remaining = expiry - time::OffsetDateTime::now_utc();
    if remaining.is_positive() {
        tokio::time::sleep(remaining.unsigned_abs() + Duration::from_millis(50)).await;
    }
    result(&f, &id, "expired").await;
    assert_eq!(
        f.agent("worker", "GET", &format!("/approvals/{id}"), None)
            .await
            .json()["status"],
        "expired"
    );
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn private_results_recover_acknowledgement_and_projection_gaps_without_reissuing_decisions() {
    let f = Fixture::new().await;
    prepare(&f);
    let id = canonical_id(&f, &blocked(&f).await).await;
    // Canonical mutation, reads, audit and enforcement remain usable with no
    // broker at all. No requester is connected during this decision.
    resolve(&f, &id, "reject", "persistent").await;
    assert_eq!(
        f.agent("worker", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        200
    );
    let second = canonical_id(&f, &blocked(&f).await).await;
    resolve(&f, &second, "reject", "persistent").await;
    let approvals =
        rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    approvals.execute_batch(&format!("CREATE TRIGGER fail_result_receipt BEFORE UPDATE ON approvals WHEN NEW.approval_id='{id}' AND json_extract(NEW.record,'$.result_delivery.stream_sequence') IS NOT NULL BEGIN SELECT RAISE(FAIL,'controlled receipt failure'); END;")).unwrap();
    let nats = Nats::start_jetstream(f.root.path()).await;
    let js = async_nats::jetstream::new(Nats::publisher(f.root.path()).await);
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(mut stream) = js.get_stream("APPROVAL_RESULTS").await
                && stream.info().await.unwrap().state.messages > 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    projected(&f, &second).await;
    result(&f, &second, "rejected").await;
    let coord = rusqlite::Connection::open(f.root.path().join("data/coord/v0.db")).unwrap();
    coord.execute_batch("CREATE TRIGGER fail_result_projection BEFORE INSERT ON coord_attention_edges WHEN NEW.kind='approval_result' BEGIN SELECT RAISE(FAIL,'controlled projection failure'); END;").unwrap();
    approvals
        .execute_batch("DROP TRIGGER fail_result_receipt")
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            let sequence: Option<i64> = approvals.query_row("SELECT json_extract(record,'$.result_delivery.stream_sequence') FROM approvals WHERE approval_id=?1",[&id],|r|r.get(0)).unwrap();
            if sequence.is_some() { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.unwrap();
    assert_eq!(
        coord
            .query_row(
                "SELECT count(*) FROM coord_attention_edges WHERE kind='approval_result'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    drop(nats);
    let _nats = Nats::start_jetstream(f.root.path()).await;
    let f = f.restart().await;
    coord
        .execute_batch("DROP TRIGGER fail_result_projection")
        .unwrap();
    let item = result(&f, &id, "rejected").await;
    let current = async_nats::jetstream::new(Nats::publisher(f.root.path()).await);
    assert_eq!(
        current
            .get_stream("APPROVAL_RESULTS")
            .await
            .unwrap()
            .info()
            .await
            .unwrap()
            .state
            .messages,
        2,
        "ambiguous acknowledgement duplicated the retained result"
    );
    assert_eq!(
        coord
            .query_row(
                "SELECT count(*) FROM coord_attention_edges WHERE attention_id=?1",
                [item["edge"]["attention_id"].as_str().unwrap()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        f.agent("worker", "GET", &format!("/approvals/{id}"), None)
            .await
            .json()["status"],
        "rejected"
    );
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn private_credential_and_service_decisions_reach_only_the_original_requester() {
    let (f, _backend, _vault) = service_authorization::setup().await;
    prepare(&f);
    let _nats = Nats::start_jetstream(f.root.path()).await;
    f.apply(&f.source().replace("enabled=false", "enabled=true"))
        .await;
    let credential = f
        .request(
            "worker",
            f.address,
            "GET",
            "/credential",
            &format!("Authorization: Bearer {SECRET}\r\n"),
        )
        .await;
    assert_eq!(credential.status, 428);
    let id = canonical_id(&f, &credential.id()).await;
    assert_eq!(
        f.admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json()["action"]["kind"],
        "credential_allow"
    );
    resolve(&f, &id, "reject", "persistent").await;
    result(&f, &id, "rejected").await;
    let service = f.agent("worker", "POST", "/gateway/request-access", Some(json!({"service":"scoped","capability":"reader","account":"work-account","credential":"provider","resources":["/data/*"]}))).await;
    assert_eq!(service.status, 202, "{}", service.json());
    let id = canonical_id(&f, &service.id()).await;
    resolve(&f, &id, "approve", "run").await;
    result(&f, &id, "approved").await;
    assert_eq!(
        f.admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json()["grant_active"],
        true
    );
    no_origin(&f).await;
    f.stop().await;
}
