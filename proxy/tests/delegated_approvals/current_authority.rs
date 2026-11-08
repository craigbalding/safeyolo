//! Direct policy edits precede watcher activation in this in-process fixture.
use super::*;

fn canonical(f: &Fixture, id: &str) -> String {
    rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT record FROM approvals WHERE approval_id=?1",
            [id],
            |row| row.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn saved_deciding_authority_refuses_every_variant_without_changing_pending() {
    for change in ["revoke", "narrow"] {
        let f = Fixture::new().await;
        let _backend = Backend(runs(&f));
        let (_, revision) = delegate(&f, proposal(&f)).await;
        let blocked = f.network("worker", f.address).await;
        assert_eq!(blocked.status, 428);
        let id = f
            .admin("GET", &format!("/admin/approvals/{}", blocked.id()), None)
            .await
            .json()["approval_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let before = canonical(&f, &id);
        let source = f.source();
        let mut document: toml_edit::DocumentMut = source.parse().unwrap();
        if change == "revoke" {
            document["approval_delegations"]
                .as_table_like_mut()
                .unwrap()
                .remove("local");
        } else {
            let mut input = proposal(&f);
            input["expected_revision"] = json!(revision);
            input["delegation"]["reviewers"] = json!([{"name":"peer","agent_id":PEER_ID}]);
            let preview = f
                .admin(
                    "POST",
                    "/admin/approval-delegations/local/preview",
                    Some(input),
                )
                .await;
            assert_eq!(preview.status, 200, "{}", preview.json());
            let mut narrowed = preview.json()["after"].clone();
            narrowed["acknowledgment"] = preview.json()["revision"].clone();
            document["approval_delegations"]["local"] = toml_edit::value(narrowed.to_string());
        }
        fs::write(f.root.path().join("policy.toml"), document.to_string()).unwrap();
        // The old runtime still offers this choice. Only the saved-authority
        // check at the canonical decision owner can prevent its mutation.
        assert_eq!(
            f.agent("helper", "GET", &format!("/approvals/{id}"), None)
                .await
                .status,
            200
        );
        for decision in ["reject", "approve", "defer"] {
            let refused = decide(&f, "helper", &id, decision, "run").await;
            assert_eq!(
                refused.status,
                409,
                "{change}/{decision}: {}",
                refused.json()
            );
            assert_eq!(canonical(&f, &id), before, "{change}/{decision}");
        }
        no_origin(&f).await;
        fs::write(f.root.path().join("policy.toml"), source).unwrap();
        assert_eq!(decide(&f, "helper", &id, "defer", "run").await.status, 200);
        assert_eq!(canonical(&f, &id), before);
        let allowed = decide(&f, "helper", &id, "reject", "run").await;
        assert_eq!(allowed.status, 200, "{}", allowed.json());
        assert_eq!(
            serde_json::from_str::<Value>(&canonical(&f, &id)).unwrap()["status"],
            "rejected"
        );
        f.stop().await;
    }
}
