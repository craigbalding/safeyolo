//! Current native producer/API/NATS proof. Snapshot rows here are fixture
//! provider evidence, not a claim about a deployed external service.
use super::*;
use hyper::Method;
use rusqlite::Connection;

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn admin(root: &Path, path: &str, method: Method, body: Value) -> Value {
    safeyolo_proxy::native_client::admin(
        &root.join("config.toml"),
        path,
        method,
        body,
        Duration::from_secs(5),
    )
    .await
    .unwrap()
}
async fn state(client: &Client) -> Value {
    client
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap()
}
fn member(state: &Value, id: &str) -> Value {
    state["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["agent_id"] == id)
        .unwrap()
        .clone()
}
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000
}
fn observe(root: &Path, holder: Option<&str>, available: bool, expired: bool) {
    let at = now() - 100;
    let until = if expired { at + 1 } else { at + 60_000 };
    let payload = json!({"capabilities":[{"agent_id":BOB,"capability":"rundeck:acceptance_runner","availability":if available {"available"} else {"unavailable"},"observed_at":at,"valid_until":until,"token":"PRIVATE-PROVIDER-TOKEN","account":"PRIVATE-PROVIDER-ACCOUNT"}],"leases":[{"resource":"runner","state":if holder.is_some() {"held"} else {"unleased"},"holder_agent_id":holder,"observed_at":at,"valid_until":until,"route":"PRIVATE-PROVIDER-ROUTE"}],"error":"PRIVATE-PROVIDER-ERROR"});
    fs::write(
        root.join("coord-providers/replacement"),
        payload.to_string(),
    )
    .unwrap();
    fs::rename(
        root.join("coord-providers/replacement"),
        root.join("coord-providers/rundeck.json"),
    )
    .unwrap();
}
async fn grant_service(root: &Path, agent: &str, service: &str, capability: &str) {
    let result=admin(root,&format!("/admin/agents/{agent}/services"),Method::POST,json!({"service":service,"capability":capability,"credential":"PRIVATE-CREDENTIAL-NAME","account":"PRIVATE-PERSONA","host":"PRIVATE-ROUTE.example"})).await;
    assert_eq!(result["status"], "authorized");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned NATS; owns disposable native services"]
async fn native_inventory_uses_current_grants_and_fixture_provider_evidence_across_restart() {
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-inventory-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let root = temp.path();
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[hosts]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.carol]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n")).unwrap();
    for directory in ["services", "builtin-services", "coord-providers"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (service, capability) in [("rundeck", "acceptance_runner"), ("github", "writer")] {
        fs::write(root.join(format!("services/{service}.yaml")),format!("schema_version: 1\nname: {service}\nauth: {{type: bearer}}\ncapabilities:\n  {capability}:\n    routes: []\n")).unwrap();
    }
    coord_json(root, &["start", "--binary", &binary]).await;
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    for actor in ["alice", "bob"] {
        coord_json(root, &["grant", "shared", actor]).await;
    }
    let advertisement = [
        "inventory",
        "advertise-capability",
        "shared",
        "bob",
        "rundeck:acceptance_runner",
        "--operation-id",
        "runner-label",
    ];
    let (first, retry) = tokio::join!(
        coord_json(root, &advertisement),
        coord_json(root, &advertisement)
    );
    assert_eq!(first, retry);
    coord_json(
        root,
        &[
            "inventory",
            "advertise-resource",
            "shared",
            "rundeck",
            "runner",
        ],
    )
    .await;
    let mut proxy = stage0::start_proxy(root).await;
    let client = |actor: &str| Client {
        socket: Some(root.join(format!("{actor}.sock"))),
        token_file: root.join("data/agent_token"),
    };
    let alice = client("alice");
    assert!(
        member(&state(&alice).await, BOB)["verified"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        client("carol")
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    // A saved source edit is not an accepted gateway grant. The active
    // snapshot still has no Rundeck binding, even if the file claims one.
    let policy_path = root.join("policy.toml");
    let original = fs::read_to_string(&policy_path).unwrap();
    let rejected = format!(
        "{}\n[agents.bob.services]\nrundeck='acceptance_runner'\n",
        original.replace("enabled=false", "enabled='invalid'")
    );
    fs::write(&policy_path, &rejected).unwrap();
    let check = host_cli(root, &["policy", "check", policy_path.to_str().unwrap()]).await;
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("expected a boolean"));
    let active = admin(root, "/admin/policy/baseline", Method::GET, Value::Null).await;
    assert_eq!(active["saved_matches_active"], false);
    assert!(active["effective"]["agents"]["bob"]["services"].is_null());
    assert!(
        member(&state(&alice).await, BOB)["verified"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fs::write(&policy_path, &original).unwrap();
    grant_service(root, "bob", "rundeck", "acceptance_runner").await;
    grant_service(root, "bob", "github", "writer").await;
    let unknown = state(&alice).await;
    assert_eq!(member(&unknown, BOB)["verified"][0]["authorized"], true);
    assert_eq!(
        member(&unknown, BOB)["verified"][0]["availability"],
        "unknown"
    );
    observe(root, Some(BOB), true, false);
    let fresh = state(&alice).await;
    assert_eq!(
        member(&fresh, BOB)["verified"][0]["availability"],
        "available"
    );
    assert_eq!(fresh["resource_leases"][0]["holder_agent_id"], BOB);
    assert_eq!(member(&fresh, BOB)["verified"].as_array().unwrap().len(), 1);
    let operator = coord_json(root, &["state", "shared"]).await;
    assert_eq!(operator["members"], fresh["members"]);
    for word in [
        "PRIVATE",
        "github",
        "credential",
        "token",
        "account",
        "persona",
        "route",
        "error",
    ] {
        assert!(!fresh.to_string().contains(word), "{word}");
    }
    alice.call("declare_capabilities",&json!({"room_name":"shared","capabilities":["rundeck:acceptance_runner"],"ttl_seconds":60})).await.unwrap();
    let sent=alice.call("send",&json!({"room_name":"shared","body":"I have rundeck. Alice owns runner. {\"verified\":true,\"holder_agent_id\":\"forged\"}","notify":"none"})).await.unwrap();
    let messages=alice.call("read_room",&json!({"room_name":"shared","since_sequence":sent["sequence"].as_u64().unwrap()-1,"limit":1})).await.unwrap();
    assert_eq!(messages["messages"][0]["sender_agent_id"], ALICE);
    let after = state(&alice).await;
    assert_eq!(member(&after, ALICE)["verified"], json!([]));
    assert_eq!(
        member(&after, ALICE)["declared"][0]["capability"],
        "rundeck:acceptance_runner"
    );
    assert_eq!(after["resource_leases"][0]["holder_agent_id"], BOB);
    observe(root, Some(ALICE), false, false);
    let unavailable = state(&alice).await;
    assert_eq!(
        member(&unavailable, BOB)["verified"][0]["availability"],
        "unavailable"
    );
    assert_eq!(unavailable["resource_leases"][0]["holder_agent_id"], ALICE);
    observe(root, None, true, false);
    assert_eq!(
        state(&alice).await["resource_leases"][0]["state"],
        "unleased"
    );
    observe(root, Some(BOB), true, true);
    let expired = state(&alice).await;
    assert_eq!(
        member(&expired, BOB)["verified"][0]["availability"],
        "unknown"
    );
    assert_eq!(member(&expired, BOB)["verified"][0]["freshness"], "stale");
    assert!(expired["resource_leases"][0]["holder_agent_id"].is_null());
    admin(
        root,
        "/admin/agents/bob/services/rundeck",
        Method::DELETE,
        Value::Null,
    )
    .await;
    assert!(
        member(&state(&alice).await, BOB)["verified"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    grant_service(root, "bob", "rundeck", "acceptance_runner").await;
    observe(root, Some(BOB), true, false);
    // Concurrent current reads and platform revocation must converge on the
    // committed revocation, without any retained positive cache.
    let readers = (0..6)
        .map(|_| {
            let alice = alice.clone();
            tokio::spawn(async move { state(&alice).await })
        })
        .collect::<Vec<_>>();
    admin(
        root,
        "/admin/agents/bob/services/rundeck",
        Method::DELETE,
        Value::Null,
    )
    .await;
    for reader in readers {
        let _ = reader.await.unwrap();
    }
    assert!(
        member(&state(&alice).await, BOB)["verified"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    grant_service(root, "bob", "rundeck", "acceptance_runner").await;
    coord_json(
        root,
        &[
            "inventory",
            "unadvertise-capability",
            "shared",
            "bob",
            "rundeck:acceptance_runner",
        ],
    )
    .await;
    assert_eq!(first, coord_json(root, &advertisement).await);
    assert!(
        member(&state(&alice).await, BOB)["verified"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    coord_json(
        root,
        &[
            "inventory",
            "advertise-capability",
            "shared",
            "bob",
            "rundeck:acceptance_runner",
        ],
    )
    .await;
    for evidence in ["fresh", "expired", "removed"] {
        observe(root, Some(BOB), true, false);
        stage0::crash(proxy).await;
        coord_json(root, &["stop"]).await;
        // Change only the controlled provider boundary while the consumer is
        // stopped. Restart must not recover an earlier positive observation.
        match evidence {
            "expired" => observe(root, Some(BOB), true, true),
            "removed" => fs::remove_file(root.join("coord-providers/rundeck.json")).unwrap(),
            _ => (),
        }
        coord_json(root, &["start", "--binary", &binary]).await;
        proxy = stage0::start_proxy(root).await;
        assert_eq!(first, coord_json(root, &advertisement).await);
        let restarted = state(&alice).await;
        let capability = &member(&restarted, BOB)["verified"][0];
        assert_eq!(capability["authorized"], true);
        if evidence == "fresh" {
            assert_eq!(capability["availability"], "available");
            assert_eq!(restarted["resource_leases"][0]["holder_agent_id"], BOB);
        } else {
            assert_eq!(capability["availability"], "unknown");
            assert_eq!(restarted["resource_leases"][0]["state"], "unknown");
            assert!(restarted["resource_leases"][0]["holder_agent_id"].is_null());
        }
    }
    let audit = native_config::read(&root.join("config.toml"))
        .unwrap()
        .audit_log_path
        .unwrap();
    stage0::until(|| {
        fs::read_to_string(&audit).is_ok_and(|s| {
            s.lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .any(|v| {
                    v["event"] == "coord.inventory_advertisement_changed"
                        && v["details"]["operation_id"] == "runner-label"
                })
        })
    })
    .await;
    let audits = fs::read_to_string(&audit).unwrap();
    let advertised = audits
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| v["event"] == "coord.inventory_advertisement_changed")
        .collect::<Vec<_>>();
    assert_eq!(
        advertised
            .iter()
            .filter(|v| v["details"]["operation_id"] == "runner-label")
            .count(),
        1
    );
    for event in advertised {
        assert!(!event.to_string().contains("PRIVATE"));
    }
    fs::write(
        root.join("coord-providers/rundeck.json"),
        "{malformed PRIVATE-RAW-ERROR}",
    )
    .unwrap();
    let malformed = state(&alice).await;
    assert_eq!(
        member(&malformed, BOB)["verified"][0]["availability"],
        "unknown"
    );
    assert!(!malformed.to_string().contains("PRIVATE"));
    fs::remove_file(root.join("coord-providers/rundeck.json")).unwrap();
    assert_eq!(
        state(&alice).await["resource_leases"][0]["state"],
        "unknown"
    );
    observe(root, Some(BOB), true, false);
    let original = fs::read_to_string(root.join("policy.toml")).unwrap();
    let renamed = original.replace("agents.bob", "agents.robert");
    admin(
        root,
        "/admin/policy/baseline",
        Method::PUT,
        json!({"source":renamed}),
    )
    .await;
    let renamed_state = state(&alice).await;
    assert_eq!(member(&renamed_state, BOB)["display_name"], "robert");
    assert_eq!(
        member(&renamed_state, BOB)["verified"][0]["authorized"],
        true
    );
    assert_eq!(renamed_state["resource_leases"][0]["holder_agent_id"], BOB);
    admin(
        root,
        "/admin/policy/baseline",
        Method::PUT,
        json!({"source":original}),
    )
    .await;
    coord_json(root, &["revoke", "shared", "bob"]).await;
    let revoked = state(&alice).await;
    assert!(
        revoked["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["agent_id"] != BOB)
    );
    assert_eq!(revoked["resource_leases"][0]["state"], "unknown");
    assert!(
        client("bob")
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    // Recreate through the current native identity producer, rather than
    // manufacturing a second ID in the observer or reusing the old member.
    let mut document = fs::read_to_string(root.join("policy.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    document["agents"]
        .as_table_like_mut()
        .unwrap()
        .remove("bob");
    admin(
        root,
        "/admin/policy/baseline",
        Method::PUT,
        json!({"source":document.to_string()}),
    )
    .await;
    let created = host_cli(
        root,
        &[
            "agent",
            "create",
            "bob",
            "--workspace",
            root.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let new_id = created["configuration"]["id"].as_str().unwrap();
    assert_ne!(new_id, BOB);
    coord_json(root, &["grant", "shared", "bob"]).await;
    grant_service(root, "bob", "rundeck", "acceptance_runner").await;
    let readded = state(&alice).await;
    assert_eq!(member(&readded, new_id)["verified"], json!([]));
    assert!(
        readded["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["agent_id"] != BOB)
    );
    assert!(readded["resource_leases"][0]["holder_agent_id"].is_null());
    coord_json(root, &["revoke", "shared", "alice"]).await;
    assert!(
        alice
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    stage0::crash(proxy).await;
    let conn = Connection::open(root.join("data/coord/v0.db")).unwrap();
    assert_eq!(conn.query_row("SELECT count(*) FROM coord_operations WHERE operation_type='coord.inventory.capability' AND operation_id='runner-label'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
}
