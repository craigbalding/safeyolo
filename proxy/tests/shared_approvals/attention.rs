use super::*;

async fn notice(fixture: &Fixture, id: &str) -> Value {
    let result = fixture
        .admin(
            "POST",
            &format!("/admin/approvals/{id}/attention"),
            Some(json!({})),
        )
        .await;
    assert_eq!(result.status, 200, "{}", result.json());
    result.json()
}

#[tokio::test]
async fn plumb_notices_share_canonical_requester_budget_without_copying_approval_authority() {
    let fixture = Fixture::new().await;
    let source = fixture.source().replace(
        &format!("'{0}'={{egress='prompt'}}", fixture.address),
        "'*'={egress='prompt'}",
    );
    fixture.apply(&source).await;
    let first = fixture.network("worker", fixture.address).await;
    assert_eq!(notice(&fixture, &first.id()).await["notify"], true);
    let plumb = fixture
        .agent(
            "worker",
            "POST",
            "/plumb/request-chat",
            Some(json!({"participants":["helper"],"reason":"A conversation may help."})),
        )
        .await;
    assert_eq!(plumb.status, 202, "{}", plumb.json());
    let listed = fixture.admin("GET", "/admin/approvals", None).await.json();
    let prompt = listed["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|view| view["event"] == "plumb.requested")
        .unwrap();
    let id = prompt["request_id"].as_str().unwrap();
    assert_eq!(notice(&fixture, id).await["notify"], true);
    assert_eq!(notice(&fixture, id).await["notify"], false);
    for (i, expected) in (0..4).zip([true, true, true, false]) {
        let target = std::net::SocketAddr::new(fixture.address.ip(), 14000 + i);
        let blocked = fixture.network("worker", target).await;
        assert_eq!(blocked.status, 428);
        assert_eq!(notice(&fixture, &blocked.id()).await["notify"], expected);
    }
    let fixture = fixture.restart().await;
    assert_eq!(notice(&fixture, id).await["notify"], false);
    fixture.stop().await;
}

#[tokio::test]
async fn bursts_refusals_reconnect_and_changed_authority_keep_requests_discoverable() {
    let fixture = Fixture::new().await;
    let source = fixture.source().replace(
        &format!("'{0}'={{egress='prompt'}}", fixture.address),
        "'*'={egress='prompt'}",
    );
    fixture.apply(&source).await;
    let first = fixture.network("worker", fixture.address).await;
    assert_eq!(first.status, 428);
    let id = first.id();
    assert_eq!(notice(&fixture, &id).await["notify"], true);
    let mut tasks = Vec::new();
    for _ in 0..12 {
        tasks.push(fixture.network("worker", fixture.address));
    }
    for reply in futures_util::future::join_all(tasks).await {
        assert_eq!(reply.status, 428);
        assert_eq!(notice(&fixture, &reply.id()).await["notify"], false);
    }
    let view = fixture
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(view["request_history"]["equivalent_request_count"], 13);
    assert_eq!(view["request_history"]["approval_count"], 1);
    assert_eq!(
        fixture.resolve(&id, "reject").await.json()["status"],
        "rejected"
    );
    assert_eq!(notice(&fixture, &id).await["notify"], false);
    let retry = fixture.network("worker", fixture.address).await;
    let retried = fixture
        .admin("GET", &format!("/admin/approvals/{}", retry.id()), None)
        .await
        .json();
    assert_ne!(retried["approval_id"], view["approval_id"]);
    assert_eq!(retried["status"], "pending");
    assert_eq!(retried["request_history"]["equivalent_request_count"], 14);
    assert_eq!(
        retried["request_history"]["last_refusal"]["approval_id"],
        view["approval_id"]
    );
    assert!(retried["request_history"]["last_refusal"]["decided_at"].is_i64());
    assert_eq!(notice(&fixture, &retry.id()).await["notify"], false);

    let mut distinct = vec![];
    let mut admitted = 1;
    for port in 12000..12008 {
        let target = std::net::SocketAddr::new(fixture.address.ip(), port);
        let reply = fixture.network("worker", target).await;
        assert_eq!(reply.status, 428);
        let new_id = reply.id();
        admitted += usize::from(notice(&fixture, &new_id).await["notify"] == true);
        distinct.push(new_id);
    }
    assert_eq!(admitted, 5);
    // The same origin requested by another transport identity has its own
    // authority and requester budget; it cannot inherit Worker's approval.
    let peer = fixture.network("peer", fixture.address).await;
    assert_eq!(notice(&fixture, &peer.id()).await["notify"], true);
    assert_eq!(
        fixture.admin("GET", "/admin/approvals", None).await.json()["approvals"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
    let fixture = fixture.restart().await;
    assert_eq!(notice(&fixture, &retry.id()).await["notify"], false);
    let suppressed = fixture
        .admin(
            "GET",
            &format!("/admin/approvals/{}", distinct.last().unwrap()),
            None,
        )
        .await
        .json();
    assert!(
        suppressed["attention"]["operator"]["status"]
            .as_str()
            .unwrap()
            .contains("limit")
    );
    assert_eq!(suppressed["status"], "pending");
    assert_eq!(
        fixture.resolve(&retry.id(), "approve").await.json()["status"],
        "approved"
    );
    assert_eq!(fixture.network("peer", fixture.address).await.status, 428);
    assert_eq!(
        fixture
            .admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json()["status"],
        "rejected"
    );
    let audit = fs::read_to_string(fixture.root.path().join("audit.jsonl")).unwrap();
    let events: Vec<Value> = audit
        .lines()
        .map(|line| safeyolo_proxy::audit::parse_record(line).unwrap())
        .filter(|row| row["event"] == "security.approval_attention")
        .collect();
    assert!(events.iter().any(|row| {
        row["details"]["delivery"]["status"]
            .as_str()
            .is_some_and(|s| s.contains("limit"))
    }));
    assert!(
        timeout(Duration::from_millis(30), fixture.origin.accept())
            .await
            .is_err(),
        "requests reached origin without approval or replayed after approval"
    );
    fixture.stop().await;
}
