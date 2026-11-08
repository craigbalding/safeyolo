//! The new permissions cross real NATS into the existing canonical owners.
//! Controlled run records do not establish an installed guest/model journey.
use super::support::{apply, instance, proposal, revoke, trust_broker};
use super::*;

async fn delegation(root: &Path, mut proposal: Value) -> Value {
    let file = root.join("deciding.json");
    fs::write(&file, proposal.to_string()).unwrap();
    let preview = host_json(
        root,
        &[
            "approvals",
            "delegation",
            "check",
            "deciding",
            "--file",
            file.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    proposal["delegation"] = preview["after"].clone();
    proposal["delegation"]["acknowledgment"] = preview["acknowledgment"].clone();
    fs::write(&file, proposal.to_string()).unwrap();
    host_json(
        root,
        &[
            "approvals",
            "delegation",
            "apply",
            "deciding",
            "--file",
            file.to_str().unwrap(),
            "--json",
        ],
    )
    .await
}

async fn denied(client: &Client, tool: &str, args: Value, status: &str) {
    let error = client.call(tool, &args).await.unwrap_err().to_string();
    assert!(error.contains(status), "{tool}: {error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; two independently initialized native owners"]
async fn remote_saved_deciding_authority_preserves_the_canonical_pending_record() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("saved-reviewer-")
        .tempdir()
        .unwrap();
    let (a, b) = (retained.path().join("a"), retained.path().join("b"));
    initialize(&a, &nats).await;
    initialize(&b, &nats).await;
    let (_clean_a, _clean_b) = (NatsCleanup(a.clone()), NatsCleanup(b.clone()));
    let (a_id, b_id) = (instance(&a), instance(&b));
    coord_json(
        &a,
        &[
            "federation",
            "credential",
            a.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    let endpoint = trust_broker(&b, &a, &a_id, &nats).await;
    configure_home(&b, &a, &b_id, &endpoint).await;
    let room = coord_json(&b, &["room", "create", "target"]).await;
    let generation = "0123456789abcdef0123456789abcdef";
    let _source = super::super::controlled_runs::agent_run(&a, "bob", BOB, generation);
    let _worker = super::super::controlled_runs::agent_run(&b, "alice", ALICE, generation);
    // In-process owners do not drive the executable's policy watcher. Saved
    // edits therefore deterministically precede cached-policy activation,
    // while authenticated calls still cross the real scoped NATS transport.
    let mut proxies = Vec::new();
    for root in [&a, &b] {
        let mut config = native_config::read(&root.join("config.toml")).unwrap();
        safeyolo_proxy::host_commands::prepare_proxy(&mut config)
            .await
            .unwrap();
        proxies.push(safeyolo_proxy::Proxy::start(config).await.unwrap());
    }
    let remote = client(&a, "bob", true);
    let alice = client(&b, "alice", false);
    let pending = alice.call("request_room_access", &json!({"room_name":"target","permissions":["receive"],"operation_id":"saved-authority"})).await.unwrap();
    let id = pending["approval_id"].as_str().unwrap();
    let room_id: String = rusqlite::Connection::open(b.join("data/coord/v0.db"))
        .unwrap()
        .query_row("SELECT room_id FROM rooms WHERE name='target'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(room.to_string().contains(&room_id));
    let proposal = json!({"expected_revision":null,"delegation":{
        "reviewers":[{"name":"remote.bob","agent_id":BOB,"instance_id":a_id}],
        "beneficiaries":[{"name":"alice","agent_id":ALICE}],
        "scopes":[{"type":"coord_room","room_id":room_id,"participants":[{"principal_kind":"operator","principal_id":"operator","permissions":["page_operator","receive","send"]},{"principal_kind":"agent","principal_id":ALICE,"permissions":["receive"]}],"permissions":["receive"]}],
        "expires_at":null,"grant_seconds":null,"gateway_once":false,"acknowledgment":null}});
    let deciding = delegation(&b, proposal.clone()).await;
    assert_eq!(
        remote
            .call("read_approval", &json!({"approval_id":id}))
            .await
            .unwrap()["status"],
        "pending"
    );
    let canonical = || -> String {
        rusqlite::Connection::open(b.join("data/approvals.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT record FROM approvals WHERE approval_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap()
    };
    let before = canonical();
    let source = fs::read_to_string(b.join("policy.toml")).unwrap();
    let mut narrow = proposal;
    narrow["expected_revision"] = deciding["revision"].clone();
    // A valid deciding scope for another room no longer contains this request.
    let other = coord_json(&b, &["room", "create", "other"]).await;
    let other_id: String = rusqlite::Connection::open(b.join("data/coord/v0.db"))
        .unwrap()
        .query_row("SELECT room_id FROM rooms WHERE name='other'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(other.to_string().contains(&other_id));
    narrow["delegation"]["scopes"][0]["room_id"] = json!(other_id);
    let file = b.join("narrow.json");
    fs::write(&file, narrow.to_string()).unwrap();
    let preview = host_json(
        &b,
        &[
            "approvals",
            "delegation",
            "check",
            "deciding",
            "--file",
            file.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    let mut narrowed = preview["after"].clone();
    narrowed["acknowledgment"] = preview["acknowledgment"].clone();
    for change in ["revoke", "narrow"] {
        let mut document: toml_edit::DocumentMut = source.parse().unwrap();
        if change == "revoke" {
            document["approval_delegations"]
                .as_table_like_mut()
                .unwrap()
                .remove("deciding");
        } else {
            document["approval_delegations"]["deciding"] = toml_edit::value(narrowed.to_string());
        }
        fs::write(b.join("policy.toml"), document.to_string()).unwrap();
        for decision in ["reject", "approve", "defer"] {
            let error = remote.call("resolve_approval", &json!({"approval_id":id,"delegation":"deciding","option":"run","decision":decision})).await.unwrap_err().to_string();
            assert!(error.contains("409"), "{change}/{decision}: {error}");
            assert_eq!(canonical(), before, "{change}/{decision}");
        }
    }
    fs::write(b.join("policy.toml"), source).unwrap();
    assert_eq!(
        remote
            .call(
                "resolve_approval",
                &json!({"approval_id":id,"delegation":"deciding","option":"run","decision":"defer"})
            )
            .await
            .unwrap()["status"],
        "pending"
    );
    assert_eq!(canonical(), before);
    assert_eq!(remote.call("resolve_approval", &json!({"approval_id":id,"delegation":"deciding","option":"run","decision":"reject"})).await.unwrap()["status"], "rejected");
    for proxy in proxies {
        proxy.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; two independently initialized native owners"]
async fn qualified_operator_direction_and_approval_keep_b_ownership_and_independent_checks() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("operator-permissions-")
        .tempdir()
        .unwrap()
        .keep();
    println!("operator permission operands: {}", retained.display());
    let (a, b) = (retained.join("a"), retained.join("b"));
    initialize(&a, &nats).await;
    initialize(&b, &nats).await;
    let (_clean_a, _clean_b) = (NatsCleanup(a.clone()), NatsCleanup(b.clone()));
    let (a_id, b_id) = (instance(&a), instance(&b));
    coord_json(
        &a,
        &[
            "federation",
            "credential",
            a.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    let endpoint = trust_broker(&b, &a, &a_id, &nats).await;
    configure_home(&b, &a, &b_id, &endpoint).await;
    for room in ["shared", "artifacts", "human-only"] {
        coord_json(&b, &["room", "create", room]).await;
    }
    for agent in ["alice", "carol"] {
        coord_json(&b, &["grant", "shared", agent]).await;
    }
    fs::write(
        b.join("role.md"),
        "Use current canonical work and preserve all required checks.\n",
    )
    .unwrap();
    fs::write(
        b.join("factory.toml"),
        r#"schema="safeyolo.factory/v1"
name="selected"
room="shared"
[roles.director]
agent="alice"
contract="role.md"
[roles.reviewer]
agent="carol"
contract="role.md"
[operator_input]
to="director"
types=["DIRECTION","PAUSE"]
[[handoffs]]
request="TASK"
from="director"
to="reviewer"
responses=["DONE","BLOCKED","FAILED"]
[work]
creators=["director"]
authorities=["reviewer"]
deciders=["reviewer"]
independent=true
[[work.checks]]
reviewer="reviewer"
criterion="Inspect the exact retained report"
independent=true
"#,
    )
    .unwrap();
    let approved = host_cli(
        &b,
        &[
            "factory",
            "approve",
            b.join("factory.toml").to_str().unwrap(),
            "--yes",
        ],
    )
    .await;
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    let snapshot = fs::read_to_string(b.join("factories/selected/approved"))
        .unwrap()
        .trim()
        .to_owned();
    let generation = "0123456789abcdef0123456789abcdef";
    let mut run_a = super::super::controlled_runs::agent_run(&a, "bob", BOB, generation);
    let _attacker = super::super::controlled_runs::agent_run(&a, "carol", CAROL, generation);
    let _worker = super::super::controlled_runs::agent_run(&b, "alice", ALICE, generation);
    let _decider = super::super::controlled_runs::agent_run(&b, "carol", CAROL, generation);
    let _same_local_id = super::super::controlled_runs::agent_run(&b, "bob", BOB, generation);
    let (mut proxy_a, proxy_b) = (stage0::start_proxy(&a).await, stage0::start_proxy(&b).await);
    let remote = client(&a, "bob", true);
    let alice = client(&b, "alice", false);
    let carol = client(&b, "carol", false);
    let factory_action = |id: &str, action: Value| {
        json!({"operation_id":id,"grant":"incident","instance_id":b_id,
        "target_id":ALICE,"expected_run":generation,"operation":action})
    };
    let direction = json!({"action":"factory_direction","factory":"selected","snapshot_id":snapshot,"kind":"DIRECTION","text":"Progress the original assigned task and preserve independent review."});
    denied(&remote, "support_grants", json!({}), "403").await;
    let first = apply(&b, "incident", proposal(&b_id, Some(&a_id))).await;
    denied(
        &remote,
        "support_operation",
        factory_action("repair-is-not-direction", direction.clone()),
        "403",
    )
    .await;
    let mut grant = proposal(&b_id, Some(&a_id));
    grant["expected_revision"] = first["revision"].clone();
    grant["grant"]["factory_directions"] =
        json!([{"factory":"selected","snapshot_id":snapshot,"types":["DIRECTION"]}]);
    let granted = apply(&b, "incident", grant.clone()).await;
    assert!(
        granted["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("not room history"))
    );
    let sent = remote
        .call(
            "support_operation",
            &factory_action("direction-1", direction.clone()),
        )
        .await
        .unwrap();
    assert_eq!(sent["state"], "completed", "{sent}");
    let envelope = &sent["result"]["publication"]["envelope"];
    assert_eq!(envelope["sender_kind"], "agent");
    assert_eq!(envelope["origin_instance_id"], a_id);
    assert_eq!(envelope["origin_agent_id"], BOB);
    assert_eq!(
        envelope["factory_direction"]["initiator"]["run_id"],
        generation
    );
    assert_eq!(envelope["factory_direction"]["snapshot_id"], snapshot);
    let replay = remote
        .call(
            "support_operation",
            &factory_action("direction-1", direction.clone()),
        )
        .await
        .unwrap();
    assert_eq!(replay["result"], sent["result"]);
    let history = alice
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(
        history["messages"].as_array().unwrap().len(),
        1,
        "same operation must publish only once"
    );
    denied(&remote, "read_room", json!({"room_name":"shared"}), "404").await;
    let mut outside = direction.clone();
    outside["factory"] = json!("unrelated");
    denied(
        &remote,
        "support_operation",
        factory_action("other-factory", outside),
        "403",
    )
    .await;
    let mut outside = direction.clone();
    outside["kind"] = json!("PAUSE");
    denied(
        &remote,
        "support_operation",
        factory_action("other-type", outside),
        "403",
    )
    .await;
    let mut outside = direction.clone();
    outside["snapshot_id"] = json!("0".repeat(64));
    denied(
        &remote,
        "support_operation",
        factory_action("old-snapshot", outside),
        "403",
    )
    .await;
    denied(
        &client(&a, "carol", true),
        "support_operation",
        factory_action("ungranted-agent", direction),
        "403",
    )
    .await;
    let state = remote
        .call(
            "support_operation",
            &factory_action(
                "factory-state",
                json!({"action":"factory_state","factory":"selected","snapshot_id":snapshot}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        state["result"]["factory"]["roles"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Membership enables observation. An explicit assignment lets A execute
    // this work; required checks and acceptance still belong to B's reviewer.
    coord_json(
        &b,
        &["federation", "member", "shared", &a_id, BOB, "remote-bob"],
    )
    .await;
    let work = coord_json(
        &b,
        &[
            "work",
            "create",
            "shared",
            "Retain the report",
            "--factory",
            &json!({"name":"selected","snapshot_id":snapshot}).to_string(),
            "--assignee",
            &json!({"kind":"agent","id":envelope["sender_agent_id"]}).to_string(),
            "--operation-id",
            "original-assignment",
        ],
    )
    .await["work"]
        .clone();
    let observed = remote
        .call(
            "read_work",
            &json!({"room_name":"shared","work_id":work["work_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(observed["work_id"], work["work_id"]);
    denied(&alice, "claim_work", json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"operation_id":"take-manager-assignment"}), "403").await;
    let claimed = super::super::reviews::claim(&remote, &work, "manager-claim").await;
    let report = b.join("report.md");
    fs::write(&report, "The requested report.\n").unwrap();
    let published =
        super::super::reviews::publish(&remote, &claimed, &report, "manager-publish").await;
    let check_id = published["factory"]["current_checks"][0].clone();
    let check = carol
        .call(
            "read_work",
            &json!({"room_name":"shared","work_id":check_id}),
        )
        .await
        .unwrap();
    assert_eq!(check["check"]["reviewer"]["id"], CAROL);
    assert_ne!(check["check"]["reviewer"]["id"], ALICE);
    denied(
        &remote,
        "decide_work_acceptance",
        super::super::reviews::acceptance(&published, "approve", "manager-cannot-accept"),
        "403",
    )
    .await;
    let check = super::super::reviews::claim(&carol, &check, "independent-check").await;
    carol
        .call(
            "answer_check",
            &super::super::reviews::answer(&check, "approve", "independent-answer"),
        )
        .await
        .unwrap();
    let current = super::super::reviews::read(&carol, &published).await;
    carol
        .call(
            "decide_work_acceptance",
            &super::super::reviews::acceptance(&current, "approve", "independent-acceptance"),
        )
        .await
        .unwrap();
    let accepted = super::super::reviews::read(&remote, &published).await;
    assert_eq!(accepted["acceptance_status"]["state"], "accepted");
    let completed = remote.call("complete_work", &json!({"room_name":"shared","work_id":accepted["work_id"],
        "expected_version":accepted["version"],"expected_generation":accepted["claim_generation"],
        "short_result":"Retained the requested report with B's required independent check", "operation_id":"manager-complete"})).await.unwrap();
    assert_eq!(completed["work"]["work_id"], work["work_id"]);
    assert_eq!(completed["work"]["state"], "done");

    let room: String = rusqlite::Connection::open(b.join("data/coord/v0.db"))
        .unwrap()
        .query_row(
            "SELECT room_id FROM rooms WHERE name='artifacts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let pending = alice.call("request_room_access", &json!({"room_name":"artifacts","permissions":["receive"],"operation_id":"worker-access"})).await.unwrap();
    let id = pending["approval_id"].as_str().unwrap();
    denied(&remote, "read_approval", json!({"approval_id":id}), "404").await;
    let deciding = delegation(&b, json!({"expected_revision":null,"delegation":{
        "reviewers":[{"name":"remote.bob","agent_id":BOB,"instance_id":a_id}],
        "beneficiaries":[{"name":"alice","agent_id":ALICE}],
        "scopes":[{"type":"coord_room","room_id":room,"participants":[{"principal_kind":"operator","principal_id":"operator","permissions":["page_operator","receive","send"]},{"principal_kind":"agent","principal_id":ALICE,"permissions":["receive"]}],"permissions":["receive"]}],
        "expires_at":null,"grant_seconds":null,"gateway_once":false,"acknowledgment":null}})).await;
    assert_eq!(deciding["after"]["reviewers"][0]["instance_id"], a_id);
    let list = remote.call("list_approvals", &json!({})).await.unwrap();
    assert_eq!(list["approvals"].as_array().unwrap().len(), 1);
    let mut cursor = 0;
    let attention = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let page = remote
                .call(
                    "wait_for_coord",
                    &json!({"since_sequence":cursor,"timeout_seconds":1.0}),
                )
                .await
                .unwrap();
            cursor = page["next_cursor"].as_u64().unwrap();
            if let Some(object) = page["objects"]
                .as_array()
                .unwrap()
                .iter()
                .find(|object| object["object"]["kind"] == "approval_review")
            {
                break object.clone();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(attention["object"]["approval_id"], id);
    let stream = async_nats::jetstream::new(local_nats(&b).await)
        .get_stream("APPROVAL_RESULTS")
        .await
        .unwrap();
    assert!(
        stream
            .delete_message(attention["edge"]["revision_or_sequence"].as_u64().unwrap())
            .await
            .unwrap()
    );
    let retained = remote
        .call(
            "read_attention",
            &json!({"attention_id":attention["edge"]["attention_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(
        retained["object"]["approval_id"], id,
        "broker retention must not lose a canonical pending review"
    );

    denied(
        &client(&b, "bob", false),
        "read_approval",
        json!({"approval_id":id}),
        "404",
    )
    .await;
    stage0::crash(proxy_a).await;
    drop(run_a);
    run_a = super::super::controlled_runs::agent_run(
        &a,
        "bob",
        BOB,
        "1123456789abcdef0123456789abcdef",
    );
    proxy_a = stage0::start_proxy(&a).await;
    revoke(&b, "incident", granted["revision"].clone()).await;
    let canonical = remote
        .call("read_approval", &json!({"approval_id":id}))
        .await
        .unwrap();
    assert_eq!(canonical["approval_id"], id);
    let decision = remote
        .call(
            "resolve_approval",
            &json!({"approval_id":id,"delegation":"deciding","option":"run","decision":"approve"}),
        )
        .await
        .unwrap();
    assert_eq!(decision["status"], "approved", "{decision}");
    let receipt = host_json(&b, &["approvals", "show", id, "--json"]).await;
    assert_eq!(
        receipt["result"]["issued_access"]["reviewer"]["instance_id"],
        a_id
    );
    assert_eq!(
        receipt["result"]["decider"]["run"]["run_id"],
        "1123456789abcdef0123456789abcdef"
    );
    alice
        .call("join_room", &json!({"room_name":"artifacts"}))
        .await
        .unwrap();
    let exception = alice.call("request_room_access", &json!({"room_name":"human-only","permissions":["receive"],"operation_id":"human-exception"})).await.unwrap();
    denied(
        &remote,
        "read_approval",
        json!({"approval_id":exception["approval_id"]}),
        "404",
    )
    .await;
    let human = host_json(
        &b,
        &[
            "approvals",
            "show",
            exception["approval_id"].as_str().unwrap(),
            "--json",
        ],
    )
    .await;
    assert_eq!(human["status"], "pending");
    coord_json(&b, &["federation", "revoke", &a_id]).await;
    denied(&alice, "join_room", json!({"room_name":"artifacts"}), "404").await;
    coord_json(
        &b,
        &[
            "federation",
            "trust",
            &a_id,
            b.join("peer-secret").to_str().unwrap(),
        ],
    )
    .await;
    denied(&remote, "read_approval", json!({"approval_id":id}), "404").await;
    denied(&alice, "join_room", json!({"room_name":"artifacts"}), "404").await;
    assert_eq!(
        client(&a, "bob", false)
            .call("list_approvals", &json!({}))
            .await
            .unwrap()["approvals"],
        json!([])
    );
    assert_eq!(
        count(&b, "SELECT count(*) FROM rooms"),
        3,
        "deciding delegation must not create another room"
    );
    println!(
        "qualified operator source={a_id} owner={b_id}; exact factory direction, permission denials, preserved independent check, canonical approval reference/decision and requester access verified; cursor={cursor}"
    );
    stage0::crash(proxy_a).await;
    stage0::crash(proxy_b).await;
    drop(run_a);
}
