//! Four separately initialized owners and TLS brokers. Discovery never starts
//! an agent or executes a guest command.
use super::*;

async fn admin(root: &Path, path: &str, value: Value) -> Value {
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        path,
        Method::POST,
        value,
        Duration::from_secs(15),
    )
    .await
    .unwrap()
}

async fn configure_broker(root: &Path, peers: &[&Path], nats: &str) -> String {
    coord_json(root, &["stop"]).await;
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    fs::write(root.join("peer.pem"), certificate.cert.pem()).unwrap();
    fs::write(
        root.join("peer.key"),
        certificate.signing_key.serialize_pem(),
    )
    .unwrap();
    let mut configured = Vec::new();
    for peer in peers {
        let id = instance(peer);
        let path = root.join(format!("{id}.credential"));
        fs::copy(peer.join("federation-secret"), &path).unwrap();
        coord_json(root, &["federation", "trust", &id, path.to_str().unwrap()]).await;
        configured.push(json!({"instance_id":id,"credential_file":path}));
    }
    fs::write(root.join("coord-federation.json"), json!({"listen":"127.0.0.1","cert_file":root.join("peer.pem"),"key_file":root.join("peer.key"),"ca_file":root.join("peer.pem"),"local_server_name":"127.0.0.1","peers":configured}).to_string()).unwrap();
    let record = host_json(root, &["coord", "start", "--binary", nats]).await;
    format!("tls://127.0.0.1:{}", record["client_port"])
}

fn disclose(root: &Path, source: &str, agent: Option<&str>, all: bool, subjects: &[&str]) {
    let conn = rusqlite::Connection::open(root.join("data/coord/v0.db")).unwrap();
    let epoch: i64 = conn
        .query_row(
            "SELECT epoch FROM coord_federation_peers WHERE instance_id=?1",
            [source],
            |row| row.get(0),
        )
        .unwrap();
    let mut document = fs::read_to_string(root.join("policy.toml")).unwrap();
    document.push_str(&format!("\n[[authority_readers]]\ninstance_id={source:?}\npeer_epoch={epoch}\nall_agents={all}\nagent_ids={}\n", json!(subjects)));
    if let Some(agent) = agent {
        document.push_str(&format!("agent_id={agent:?}\n"));
    }
    fs::write(root.join("policy.toml"), document).unwrap();
}

fn grant(
    owner: &str,
    holder_owner: &str,
    holder: &str,
    targets: &[(&str, &str)],
    control: bool,
) -> Value {
    json!({"expected_revision":null,"grant":{"instance_id":owner,"support_instance_id":holder_owner,
        "support":{"name":format!("remote-{holder}"),"agent_id":holder},
        "targets":targets.iter().map(|(name,id)|json!({"name":name,"agent_id":id})).collect::<Vec<_>>(),
        "guest_admin":control,"guest_logs":["/var/log/selected.log"],"lifecycle":["restart_harness"],
        "expires_at":null,"acknowledgment":null}})
}

fn has_effect(report: &Value, field: &str, controller: &str, holder: &str, kind: &str) -> bool {
    let facts: Vec<_> = report["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|snapshot| snapshot["facts"].as_array().unwrap())
        .chain(report["proposed_facts"].as_array().unwrap())
        .collect();
    report[field].as_array().unwrap().iter().any(|effect| {
        effect["controller"]["instance_id"] == controller
            && facts.iter().any(|fact| {
                fact["fact_id"] == effect["fact_id"]
                    && fact["holder"]["instance_id"] == holder
                    && fact["capability"]["type"] == kind
            })
    })
}

async fn metadata_guards(owner: &Path, source: &Path, source_id: &str) {
    let conn = connection(owner, source, source_id).await;
    let owner_id = instance(owner);
    let base = json!({"destination_instance_id":owner_id,"source_run":null,"method":"POST","path":"/support/authority/metadata","body":{"after":0,"revision":null}});
    let first = raw(&conn, &owner_id, source_id, base.clone()).await;
    assert_eq!(first["status"], 200);
    for field in ["destination_instance_id", "origin_instance_id"] {
        let mut forged = base.clone();
        forged[field] = json!("sy-forged");
        assert_ne!(
            raw(&conn, &owner_id, source_id, forged).await["status"],
            200
        );
    }
    let mut forged = base.clone();
    forged["source_run"] = json!({"agent":"carol","agent_id":"ag-dddddddddddddddddddddddddddddddd","run_id":"0123456789abcdef0123456789abcdef"});
    assert_eq!(
        raw(&conn, &owner_id, source_id, forged).await["status"],
        403
    );
    let mut mutation = base.clone();
    mutation["path"] = json!("/support/operations");
    mutation["body"] = json!({"operation_id":"discovery-cannot-execute","operation":{"action":"guest_command","command":"touch forbidden"}});
    assert_eq!(
        raw(&conn, &owner_id, source_id, mutation).await["status"],
        403
    );
    let saved = fs::read_to_string(owner.join("policy.toml")).unwrap();
    let mut document: toml_edit::DocumentMut = saved.parse().unwrap();
    let reader = document["authority_readers"]
        .as_array_of_tables_mut()
        .unwrap()
        .get_mut(0)
        .unwrap();
    reader["all_agents"] = toml_edit::value(false);
    reader["agent_ids"] = toml_edit::value([ALICE].into_iter().collect::<toml_edit::Array>());
    fs::write(owner.join("policy.toml"), document.to_string()).unwrap();
    let selected = raw(&conn, &owner_id, source_id, base.clone()).await;
    assert_eq!(selected["status"], 200);
    assert_eq!(selected["body"]["snapshot"]["all_agents"], false);
    assert_eq!(
        selected["body"]["snapshot"]["bindings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        selected["body"]["snapshot"]["facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fact| fact["source_id"] == "c-to-d" && fact["current"] == true)
    );
    document.remove("authority_readers");
    fs::write(owner.join("policy.toml"), document.to_string()).unwrap();
    assert_eq!(
        raw(&conn, &owner_id, source_id, base.clone()).await["status"],
        403
    );
    fs::write(owner.join("policy.toml"), &saved).unwrap();
    // A metadata reader can be authorized without an unrelated room or repair
    // grant. The source host asserts its own current reader, never another peer.
    disclose(owner, source_id, Some(BOB), false, &[ALICE]);
    let mut reader = base.clone();
    reader["source_run"] =
        json!({"agent":"bob","agent_id":BOB,"run_id":"0123456789abcdef0123456789abcdef"});
    assert_eq!(
        raw(&conn, &owner_id, source_id, reader).await["status"],
        200
    );
    fs::write(owner.join("policy.toml"), &saved).unwrap();
    assert!(
        !first.to_string().contains(
            fs::read_to_string(source.join("federation-secret"))
                .unwrap()
                .trim()
        )
    );
    assert!(!owner.join("data/support-operations").exists());
}

async fn pagination_guards(owner: &Path, source: &Path, source_id: &str) {
    let saved = fs::read_to_string(owner.join("policy.toml")).unwrap();
    let mut document: toml_edit::DocumentMut = saved.parse().unwrap();
    let grant = document["support_grants"]["forgotten"].clone();
    for index in 0..12 {
        document["support_grants"][&format!("page-{index}")] = grant.clone();
    }
    fs::write(owner.join("policy.toml"), document.to_string()).unwrap();
    let conn = connection(owner, source, source_id).await;
    let owner_id = instance(owner);
    let mut request = json!({"destination_instance_id":owner_id,"source_run":null,"method":"POST","path":"/support/authority/metadata","body":{"after":0,"revision":null}});
    let page = raw(&conn, &owner_id, source_id, request.clone()).await;
    assert_eq!(page["status"], 200);
    assert!(page["body"]["next_after"].as_u64().is_some());
    document["support_grants"]["concurrent-change"] = grant.clone();
    fs::write(owner.join("policy.toml"), document.to_string()).unwrap();
    request["body"] =
        json!({"after":page["body"]["next_after"],"revision":page["body"]["snapshot"]["revision"]});
    assert_eq!(
        raw(&conn, &owner_id, source_id, request.clone()).await["status"],
        409
    );
    for index in 12..710 {
        document["support_grants"][&format!("page-{index}")] = grant.clone();
    }
    fs::write(owner.join("policy.toml"), document.to_string()).unwrap();
    request["body"] = json!({"after":0,"revision":null});
    let bounded = raw(&conn, &owner_id, source_id, request).await;
    assert_eq!(bounded["status"], 200);
    assert_eq!(bounded["body"]["snapshot"]["truncated"], true);
    assert!(bounded.to_string().len() <= 64 * 1024 + 256);
    fs::write(owner.join("policy.toml"), saved).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; four independently initialized roots, identities, TLS roots and brokers"]
async fn four_owner_report_discovers_typed_upstream_downstream_and_destination_owned_authority() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("support-authority-")
        .tempdir()
        .unwrap()
        .keep();
    println!("authority operands: {}", retained.display());
    let roots: Vec<_> = ["a", "b", "c", "d"]
        .iter()
        .map(|name| retained.join(name))
        .collect();
    let mut cleanup = Vec::new();
    for root in &roots {
        initialize(root, &nats).await;
        cleanup.push(NatsCleanup(root.clone()));
        coord_json(
            root,
            &[
                "federation",
                "credential",
                root.join("federation-secret").to_str().unwrap(),
            ],
        )
        .await;
    }
    let [a, b, c, d] = <&[_; 4]>::try_from(roots.as_slice()).unwrap();
    let ids: Vec<_> = roots.iter().map(|root| instance(root)).collect();
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        4
    );
    let endpoints = [
        configure_broker(a, &[b, c], &nats).await,
        configure_broker(b, &[a, c], &nats).await,
        configure_broker(c, &[b], &nats).await,
        configure_broker(d, &[c], &nats).await,
    ];
    for index in [0, 1, 3] {
        coord_json(
            c,
            &[
                "federation",
                "home",
                ["a", "b", "c", "d"][index],
                &ids[index],
                &endpoints[index],
                roots[index].join("peer.pem").to_str().unwrap(),
                c.join("federation-secret").to_str().unwrap(),
            ],
        )
        .await;
    }
    let mut proxies = Vec::new();
    for root in &roots {
        proxies.push(stage0::start_proxy(root).await);
    }
    let a_to_b = apply(
        b,
        "a-to-b",
        grant(&ids[1], &ids[0], ALICE, &[("bob", BOB)], true),
    )
    .await;
    let c_to_d = apply(
        d,
        "c-to-d",
        grant(
            &ids[3],
            &ids[2],
            CAROL,
            &[("alice", ALICE), ("carol", CAROL)],
            true,
        ),
    )
    .await;
    for (name, holder, holder_id, target, target_id) in [
        ("local-forward", "carol", CAROL, "alice", ALICE),
        ("local-cycle", "alice", ALICE, "carol", CAROL),
    ] {
        apply(d, name, json!({"expected_revision":null,"grant":{"instance_id":ids[3],"support":{"name":holder,"agent_id":holder_id},"targets":[{"name":target,"agent_id":target_id}],"guest_admin":true,"guest_logs":[],"lifecycle":[],"expires_at":null,"acknowledgment":null}})).await;
    }
    // B has no outbound route or local grant inventory naming A.
    apply(
        a,
        "forgotten",
        grant(&ids[0], &ids[1], BOB, &[("carol", CAROL)], false),
    )
    .await;
    let deciding = json!({"expected_revision":null,"delegation":{"reviewers":[{"name":"alice","agent_id":ALICE}],"beneficiaries":[{"name":"carol","agent_id":CAROL}],"scopes":[{"type":"network_egress","host":"example.com","ports":[443],"all_ports":false,"actions":["request"]}],"expires_at":null,"grant_seconds":30,"gateway_once":false,"acknowledgment":null}});
    let mut delegation = deciding;
    let preview = admin(
        d,
        "/admin/approval-delegations/deciding/preview",
        delegation.clone(),
    )
    .await;
    delegation["delegation"] = preview["after"].clone();
    delegation["delegation"]["acknowledgment"] = preview["acknowledgment"].clone();
    if let Some(authority) = preview.get("authority") {
        delegation["authority"] = authority.clone();
    }
    admin(d, "/admin/approval-delegations/deciding/apply", delegation).await;
    let inventory = json!([{"instance_id":ids[0],"home":"a"},{"instance_id":ids[1],"home":"b"},{"instance_id":ids[2],"home":null},{"instance_id":ids[3],"home":"d"}]);
    let mut proposed = grant(&ids[2], &ids[1], BOB, &[("carol", CAROL)], true);
    proposed["authority"] = json!({"owners":inventory});
    let denied = admin(c, "/admin/support-grants/b-to-c/preview", proposed.clone()).await;
    assert!(
        denied["authority"]["considered"]["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|owner| owner["status"] == "disclosure_refused")
    );
    for root in [a, b, d] {
        disclose(root, &ids[2], None, true, &[]);
    }
    let before_policies: Vec<_> = roots
        .iter()
        .map(|root| fs::read(root.join("policy.toml")).unwrap())
        .collect();
    let proposal_file = c.join("support-proposal.json");
    fs::write(&proposal_file, proposed.to_string()).unwrap();
    let preview = host_json(
        c,
        &[
            "support",
            "preview",
            "b-to-c",
            "--file",
            proposal_file.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    let plain = host_cli(
        c,
        &[
            "support",
            "preview",
            "b-to-c",
            "--file",
            proposal_file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    let plain = String::from_utf8(plain.stdout).unwrap();
    assert!(
        plain.contains("Authority impact:")
            && plain.contains("Added or changed effect for")
            && plain.contains("Report:")
    );
    let report = &preview["authority"]["considered"];
    fs::write(
        retained.join("preview.json"),
        serde_json::to_vec_pretty(&preview).unwrap(),
    )
    .unwrap();
    assert!(
        report["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .all(|owner| owner["status"] == "current"),
        "{report}"
    );
    assert!(has_effect(report, "added", &ids[0], &ids[2], "guest_admin"));
    assert!(has_effect(
        report,
        "added",
        &ids[1],
        &ids[3],
        "approval_decision"
    ));
    assert!(has_effect(
        report,
        "remaining",
        &ids[1],
        &ids[1],
        "guest_logs"
    ));
    assert!(
        report["after"]["common_control"]
            .as_array()
            .unwrap()
            .iter()
            .any(|common| common["controller"]["instance_id"] == ids[0]
                && common["reviewer"]["instance_id"] == ids[3])
    );
    assert!(report["snapshots"].as_array().unwrap().iter().any(|owner| {
        owner["facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|fact| fact["source_id"] == "forgotten")
    }));
    for (index, root) in roots.iter().enumerate() {
        assert_eq!(
            fs::read(root.join("policy.toml")).unwrap(),
            before_policies[index]
        );
        assert!(!root.join("data/support-operations").exists());
        assert!(!root.join("agents/carol/runtime.json").exists());
    }
    assert!(
        report["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .all(|snapshot| snapshot["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|binding| binding["execution"]
                    .as_str()
                    .unwrap()
                    .contains("no_verified_live_run")))
    );
    metadata_guards(d, c, &ids[2]).await;
    pagination_guards(a, c, &ids[2]).await;
    // A known change after preview returns the new evidence for acknowledgment.
    revoke(b, "a-to-b", a_to_b["revision"].clone()).await;
    proposed["grant"] = preview["after"].clone();
    proposed["grant"]["acknowledgment"] = preview["acknowledgment"].clone();
    proposed["authority"] = preview["authority"].clone();
    let changed = safeyolo_proxy::native_client::admin(
        &c.join("config.toml"),
        "/admin/support-grants/b-to-c/apply",
        Method::POST,
        proposed,
        Duration::from_secs(15),
    )
    .await
    .unwrap_err();
    assert!(changed.to_string().contains("409"));
    let current = admin(
        c,
        "/admin/support-grants/b-to-c/preview",
        grant(&ids[2], &ids[1], BOB, &[("carol", CAROL)], true),
    )
    .await;
    assert!(
        current["authority"]["considered"]["unresolved_frontier"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().contains("unselected"))
    );
    // Restore the upstream edge and apply the four-owner decision context.
    apply(
        b,
        "a-to-b",
        grant(&ids[1], &ids[0], ALICE, &[("bob", BOB)], true),
    )
    .await;
    let mut candidate = grant(&ids[2], &ids[1], BOB, &[("carol", CAROL)], true);
    candidate["authority"] = json!({"owners":inventory});
    let selected = admin(c, "/admin/support-grants/b-to-c/preview", candidate.clone()).await;
    candidate["grant"] = selected["after"].clone();
    candidate["grant"]["acknowledgment"] = selected["acknowledgment"].clone();
    candidate["authority"] = selected["authority"].clone();
    let applied = admin(c, "/admin/support-grants/b-to-c/apply", candidate).await;
    assert_eq!(
        applied["authority"]["considered"]["report_id"],
        selected["authority"]["considered"]["report_id"]
    );
    let audit = fs::read_to_string(c.join("logs/audit.jsonl")).unwrap();
    let events: Vec<Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "admin.support_authority_preview"
                && event["details"]["report"] == selected["authority"]["considered"])
    );
    assert!(events.iter().any(|event| {
        event["event_id"] == applied["audit_event_id"]
            && event["details"]["considered_report"] == selected["authority"]["considered"]
            && event["details"]["authority_recheck"]["coverage"]
                .as_array()
                .unwrap()
                .len()
                == 4
    }));
    let mut narrowed = json!({"expected_revision":c_to_d["revision"],"grant":c_to_d["after"]});
    narrowed["grant"]["targets"] = json!([{"name":"carol","agent_id":CAROL}]);
    let narrowed = apply(d, "c-to-d", narrowed).await;
    let refresh = || json!({"owners":inventory});
    let inventory_file = c.join("support-inventory.json");
    fs::write(&inventory_file, refresh().to_string()).unwrap();
    let alternative = host_json(
        c,
        &[
            "support",
            "report",
            "b-to-c",
            "--file",
            inventory_file.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    assert!(
        alternative["authority"]["considered"]["after"]["effects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|effect| effect["controller"]["instance_id"] == ids[1]
                && effect["path"].as_array().unwrap().len() >= 4)
    );
    // Recreated same-name targets and sources do not inherit the old identity.
    for (root, name) in [(d, "alice"), (b, "bob")] {
        let original = fs::read_to_string(root.join("policy.toml")).unwrap();
        let mut document: toml_edit::DocumentMut = original.parse().unwrap();
        document["agents"][name]["agent_id"] =
            toml_edit::value("ag-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        fs::write(root.join("policy.toml"), document.to_string()).unwrap();
        let rebound = admin(c, "/admin/support-grants/b-to-c/report", refresh()).await;
        assert!(!has_effect(
            &rebound["authority"]["considered"],
            "remaining",
            &ids[1],
            &ids[3],
            "approval_decision"
        ));
        fs::write(root.join("policy.toml"), original).unwrap();
    }
    let mut expired = json!({"expected_revision":narrowed["revision"],"grant":narrowed["after"]});
    expired["grant"]["expires_at"] = json!("2000-01-01T00:00:00Z");
    let expired = apply(d, "c-to-d", expired).await;
    let no_deciding = admin(c, "/admin/support-grants/b-to-c/report", refresh()).await;
    assert!(!has_effect(
        &no_deciding["authority"]["considered"],
        "remaining",
        &ids[1],
        &ids[3],
        "approval_decision"
    ));
    let mut restored = json!({"expected_revision":expired["revision"],"grant":expired["after"]});
    restored["grant"]["expires_at"] = Value::Null;
    apply(d, "c-to-d", restored).await;
    coord_json(d, &["federation", "revoke", &ids[2]]).await;
    coord_json(
        d,
        &[
            "federation",
            "trust",
            &ids[2],
            d.join(format!("{}.credential", ids[2])).to_str().unwrap(),
        ],
    )
    .await;
    let undisclosed = admin(c, "/admin/support-grants/b-to-c/report", refresh()).await;
    assert!(
        undisclosed["authority"]["considered"]["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|owner| owner["owner"]["instance_id"] == ids[3]
                && owner["status"] == "disclosure_refused")
    );
    disclose(d, &ids[2], None, true, &[]);
    let old_epoch = admin(c, "/admin/support-grants/b-to-c/report", refresh()).await;
    assert!(!has_effect(
        &old_epoch["authority"]["considered"],
        "remaining",
        &ids[1],
        &ids[3],
        "approval_decision"
    ));
    // An interrupted source read and an unavailable owner do not erase grants.
    let link = Link::new(endpoints[0].trim_start_matches("tls://").into()).await;
    link.partition(true);
    coord_json(
        c,
        &[
            "federation",
            "home",
            "a",
            &ids[0],
            &format!("tls://{}", link.endpoint),
            a.join("peer.pem").to_str().unwrap(),
            c.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    let _ = tokio::time::timeout(
        Duration::from_millis(1),
        admin(c, "/admin/support-grants/b-to-c/report", refresh()),
    )
    .await;
    let partial = admin(c, "/admin/support-grants/b-to-c/report", refresh()).await;
    assert!(
        partial["authority"]["considered"]["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|owner| owner["owner"]["instance_id"] == ids[0] && owner["status"] != "current")
    );
    assert!(partial["authority"]["considered"].to_string().len() <= 512 * 1024);
    assert!(
        fs::read_to_string(c.join("policy.toml"))
            .unwrap()
            .contains("b-to-c")
    );
    let revocation = admin(
        c,
        "/admin/support-grants/b-to-c/report",
        json!({"owners":inventory,"remove":true}),
    )
    .await;
    assert!(
        !revocation["authority"]["considered"]["removed"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for proxy in &mut proxies {
        let _ = proxy.kill().await;
        let _ = proxy.wait().await;
    }
}
