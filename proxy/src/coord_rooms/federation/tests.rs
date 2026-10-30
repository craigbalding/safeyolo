use super::*;
use crate::coord_rooms::work::{self, Actor, Mutation};

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("data/instance_id"), "sy-home").unwrap();
    fs::write(root.path().join("config.toml"), "admin_port=0\n").unwrap();
    fs::write(
        root.path().join("policy.toml"),
        "[agents.alice]\nagent_id='ag-alice'\n",
    )
    .unwrap();
    bootstrap(root.path()).unwrap();
    open(root.path())
        .unwrap()
        .execute("INSERT INTO rooms VALUES('rm-shared','shared',0)", [])
        .unwrap();
    root
}

async fn command(root: &Path, args: &[&str]) -> Result<Value, Error> {
    run(root, &args.iter().map(|s| (*s).into()).collect::<Vec<_>>()).await
}

#[tokio::test]
async fn qualified_identity_peer_epochs_and_membership_replay_preserve_authority() {
    let root = fixture();
    let path = root.path();
    let credential = path.join("peer-secret");
    command(path, &["credential", credential.to_str().unwrap()])
        .await
        .unwrap();
    command(path, &["trust", "sy-peer", credential.to_str().unwrap()])
        .await
        .unwrap();
    assert!(
        command(path, &["trust", "sy-other", credential.to_str().unwrap()])
            .await
            .is_err()
    );
    assert!(
        command(path, &["member", "shared", "sy-peer", "ag-bob", "alice"])
            .await
            .is_err()
    );
    let args = &[
        "member",
        "shared",
        "sy-peer",
        "ag-bob",
        "remote-bob",
        "--operation-id",
        "grant-once",
    ];
    let first = command(path, args).await.unwrap();
    assert_eq!(command(path, args).await.unwrap(), first);
    assert!(
        command(
            path,
            &[
                "member",
                "shared",
                "sy-peer",
                "ag-bob",
                "renamed",
                "--operation-id",
                "grant-once"
            ]
        )
        .await
        .is_err()
    );
    command(
        path,
        &[
            "member",
            "shared",
            "sy-peer",
            "ag-bob",
            "renamed",
            "--operation-id",
            "rename",
        ],
    )
    .await
    .unwrap();
    assert_eq!(command(path, args).await.unwrap(), first);
    assert_eq!(
        open(path)
            .unwrap()
            .query_row(
                "SELECT display_name FROM coord_federation_agents",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "renamed"
    );
    let secret = token(&credential).unwrap();
    let mut conn = open(path).unwrap();
    let remote = authenticate(&conn, secret.trim().as_bytes(), "ag-bob").unwrap();
    assert_eq!(remote.principal_id, principal("sy-peer", "ag-bob"));
    assert_ne!(remote.principal_id, "ag-bob");
    assert_ne!(remote.principal_id, principal("sy-other", "ag-bob"));
    assert_ne!(principal("ab", "c"), principal("a", "bc"));
    assert!(authenticate(&conn, secret.trim().as_bytes(), "ag-alice").is_err());
    let create = || Mutation::Create {
        title: "home-owned".into(),
        external_ref: None,
    };
    let created = work::mutate(
        &mut conn,
        "shared",
        Actor::Remote(&remote),
        create(),
        Some("ambiguous"),
    )
    .unwrap();
    assert_eq!(
        created,
        work::mutate(
            &mut conn,
            "shared",
            Actor::Remote(&remote),
            create(),
            Some("ambiguous")
        )
        .unwrap()
    );
    conn.execute_batch("CREATE TRIGGER refuse_federation_audit BEFORE INSERT ON coord_outbox WHEN NEW.event_type='coord.federation_changed' BEGIN SELECT RAISE(ABORT,'test interruption'); END;").unwrap();
    assert!(command(path, &["revoke", "sy-peer"]).await.is_err());
    authorize(&conn, &remote).unwrap();
    assert!(
        work::read(
            &mut conn,
            "shared",
            Actor::Remote(&remote),
            created["work"]["work_id"].as_str().unwrap()
        )
        .is_ok()
    );
    conn.execute_batch("DROP TRIGGER refuse_federation_audit")
        .unwrap();
    let audit:String=conn.query_row("SELECT group_concat(payload_json) FROM coord_outbox WHERE event_type='coord.federation_changed'",[],|r|r.get(0)).unwrap();
    assert!(!audit.contains(secret.trim()));
    command(path, &["revoke", "sy-peer"]).await.unwrap();
    assert!(authenticate(&conn, secret.trim().as_bytes(), "ag-bob").is_err());
    assert_eq!(
        work::mutate(
            &mut conn,
            "shared",
            Actor::Remote(&remote),
            create(),
            Some("revoked")
        )
        .unwrap_err()
        .0,
        403
    );
    command(path, &["trust", "sy-peer", credential.to_str().unwrap()])
        .await
        .unwrap();
    // An old membership retry cannot resurrect a revoked grant.
    assert_eq!(command(path, args).await.unwrap(), first);
    let renewed = authenticate(&conn, secret.trim().as_bytes(), "ag-bob").unwrap();
    assert_eq!(renewed.principal_id, remote.principal_id);
    assert_eq!(
        work::read(
            &mut conn,
            "shared",
            Actor::Remote(&renewed),
            created["work"]["work_id"].as_str().unwrap()
        )
        .unwrap_err()
        .0,
        404
    );
    command(
        path,
        &[
            "member",
            "shared",
            "sy-peer",
            "ag-bob",
            "remote-bob",
            "--operation-id",
            "grant-again",
        ],
    )
    .await
    .unwrap();
    assert!(renewed.epoch > remote.epoch);
    // Regranting cannot authorize a request authenticated in the old epoch.
    assert_eq!(
        work::mutate(
            &mut conn,
            "shared",
            Actor::Remote(&remote),
            create(),
            Some("stale-in-flight")
        )
        .unwrap_err()
        .0,
        403
    );
    assert_eq!(
        work::read(
            &mut conn,
            "shared",
            Actor::Remote(&renewed),
            created["work"]["work_id"].as_str().unwrap()
        )
        .unwrap(),
        created["work"]
    );
}
