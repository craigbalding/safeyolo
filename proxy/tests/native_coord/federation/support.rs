//! Real broker and API controls; actual guest repair remains installed proof.
use super::*;
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

fn instance(root: &Path) -> String {
    fs::read_to_string(root.join("data/instance_id"))
        .unwrap()
        .trim()
        .into()
}

fn receipt(root: &Path, id: &str) -> Option<Value> {
    let entries = match fs::read_dir(root.join("data/support-operations")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("receipt directory: {error}"),
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            if value["operation_id"] == id {
                return Some(value);
            }
        }
    }
    None
}

async fn apply(root: &Path, name: &str, mut proposal: Value) -> Value {
    let path = root.join(format!("{name}.json"));
    fs::write(&path, proposal.to_string()).unwrap();
    let preview = host_json(
        root,
        &[
            "support",
            "preview",
            name,
            "--file",
            path.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    proposal["grant"] = preview["after"].clone();
    proposal["grant"]["acknowledgment"] = preview["acknowledgment"].clone();
    fs::write(&path, proposal.to_string()).unwrap();
    host_json(
        root,
        &[
            "support",
            "apply",
            name,
            "--file",
            path.to_str().unwrap(),
            "--json",
        ],
    )
    .await
}

async fn revoke(root: &Path, name: &str, revision: Value) {
    let path = root.join("revoke.json");
    fs::write(&path, json!({"expected_revision":revision}).to_string()).unwrap();
    host_json(
        root,
        &[
            "support",
            "revoke",
            name,
            "--file",
            path.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
}

fn proposal(owner: &str, source: Option<&str>) -> Value {
    let mut grant = json!({"instance_id":owner,"support":{"name":if source.is_some(){"remote-bob"}else{"bob"},"agent_id":BOB},
        "targets":[{"name":"alice","agent_id":ALICE}],"guest_admin":false,"guest_logs":[],
        "lifecycle":["start_sandbox"],"notifications":["control_availability","sandbox_availability"],
        "signal_rooms":[],"expires_at":null,"acknowledgment":null});
    if let Some(source) = source {
        grant["support_instance_id"] = json!(source);
    }
    json!({"expected_revision":null,"grant":grant})
}

fn inspect(owner: &str, id: &str) -> Value {
    json!({"operation_id":id,"grant":"incident","instance_id":owner,"target_id":ALICE,"expected_run":null,"operation":{"action":"inspect"}})
}

fn hash(value: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn connection(home: &Path, peer: &Path, source: &str) -> async_nats::Client {
    let record: Value =
        serde_json::from_slice(&fs::read(home.join("data/coord/nats/process.json")).unwrap())
            .unwrap();
    let connection = async_nats::ConnectOptions::new()
        .require_tls(true)
        .add_root_certificates(home.join("peer.pem"))
        .user_and_password(
            hash(source),
            fs::read_to_string(peer.join("federation-secret"))
                .unwrap()
                .trim()
                .into(),
        )
        .custom_inbox_prefix(format!("SY_FED.reply.{}", hash(source)))
        .request_timeout(Some(Duration::from_secs(3)))
        .connect(format!("tls://127.0.0.1:{}", record["client_port"]))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if connection
                .request(
                    format!("SY_FED.request.{}.{}", hash(&instance(home)), hash(source)),
                    b"{}".to_vec().into(),
                )
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    connection
}

async fn raw(connection: &async_nats::Client, owner: &str, source: &str, body: Value) -> Value {
    let reply = connection
        .request(
            format!("SY_FED.request.{}.{}", hash(owner), hash(source)),
            body.to_string().into(),
        )
        .await
        .unwrap();
    serde_json::from_slice(&reply.payload).unwrap()
}

async fn trust_broker(owner: &Path, source: &Path, source_id: &str, nats: &str) -> String {
    fs::copy(source.join("federation-secret"), owner.join("peer-secret")).unwrap();
    coord_json(
        owner,
        &[
            "federation",
            "trust",
            source_id,
            owner.join("peer-secret").to_str().unwrap(),
        ],
    )
    .await;
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    fs::write(owner.join("peer.pem"), certificate.cert.pem()).unwrap();
    fs::write(
        owner.join("peer.key"),
        certificate.signing_key.serialize_pem(),
    )
    .unwrap();
    broker(owner, source, source_id, nats).await
}

fn wire(owner: &str, body: Value) -> Value {
    json!({"destination_instance_id":owner,"source_run":{"agent":"bob","agent_id":BOB,"run_id":"0123456789abcdef0123456789abcdef"},"method":"POST","path":"/support/operations","body":body})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; deliberately route a mutation to another trusted owner"]
async fn authenticated_mutation_misrouted_to_another_trusted_instance_has_no_effect() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("support-misroute-")
        .tempdir()
        .unwrap()
        .keep();
    println!("misroute operands: {}", retained.display());
    let (a, b, c) = (retained.join("a"), retained.join("b"), retained.join("c"));
    for root in [&a, &b, &c] {
        initialize(root, &nats).await;
    }
    let (_clean_a, _clean_b, _clean_c) = (
        NatsCleanup(a.clone()),
        NatsCleanup(b.clone()),
        NatsCleanup(c.clone()),
    );
    let (a_id, b_id, c_id) = (instance(&a), instance(&b), instance(&c));
    coord_json(
        &a,
        &[
            "federation",
            "credential",
            a.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    trust_broker(&b, &a, &a_id, &nats).await;
    trust_broker(&c, &a, &a_id, &nats).await;
    let (proxy_b, proxy_c) = (stage0::start_proxy(&b).await, stage0::start_proxy(&c).await);
    apply(&b, "incident", proposal(&b_id, Some(&a_id))).await;
    apply(&c, "incident", proposal(&c_id, Some(&a_id))).await;
    let conn = connection(&c, &a, &a_id).await;
    // No body-level destination guard: the transport envelope alone must
    // prevent this otherwise granted mutation from reaching C's owner.
    let mut operation = inspect(&c_id, "misrouted-start");
    operation["instance_id"] = Value::Null;
    operation["operation"] = json!({"action":"lifecycle","operation":"start_sandbox"});
    let reply = raw(&conn, &c_id, &a_id, wire(&b_id, operation)).await;
    assert_eq!(reply["status"], 403, "{reply}");
    assert_eq!(
        reply["body"]["error"],
        "destination instance mismatch; no operation attempted"
    );
    assert!(receipt(&c, "misrouted-start").is_none());
    assert!(
        !fs::read_to_string(c.join("audit.jsonl"))
            .unwrap_or_default()
            .contains("misrouted-start")
    );
    let correct = raw(
        &conn,
        &c_id,
        &a_id,
        wire(&c_id, inspect(&c_id, "correct-owner")),
    )
    .await;
    assert_eq!(correct["status"], 200, "{correct}");
    assert_eq!(correct["body"]["instance_id"], c_id);
    stage0::crash(proxy_b).await;
    stage0::crash(proxy_c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; independently fail JetStream and Core"]
async fn core_support_survives_notification_outage_and_local_owner_can_restore_core() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("support-outage-")
        .tempdir()
        .unwrap()
        .keep();
    println!("outage operands: {}", retained.display());
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
    let _run_a = super::super::controlled_runs::agent_run(
        &a,
        "bob",
        BOB,
        "0123456789abcdef0123456789abcdef",
    );
    let _run_b = super::super::controlled_runs::agent_run(
        &b,
        "bob",
        BOB,
        "0123456789abcdef0123456789abcdef",
    );
    let (proxy_a, mut proxy_b) = (stage0::start_proxy(&a).await, stage0::start_proxy(&b).await);
    apply(&b, "incident", proposal(&b_id, Some(&a_id))).await;
    apply(&b, "onsite", proposal(&b_id, None)).await;
    let remote = client(&a, "bob", true);
    let conn = connection(&b, &a, &a_id).await;
    let before = remote
        .call("support_operation", &inspect(&b_id, "before-outage"))
        .await
        .unwrap();
    // Create the actual retained-notification consumer before the outage.
    let mut subscribe = wire(&b_id, Value::Null);
    subscribe["path"] = json!("/api/coord/attention/subscribe");
    assert_eq!(raw(&conn, &b_id, &a_id, subscribe).await["status"], 200);
    let config = b.join("data/coord/nats/server.conf");
    let original = fs::read_to_string(&config).unwrap();
    let record: Value =
        serde_json::from_slice(&fs::read(b.join("data/coord/nats/process.json")).unwrap()).unwrap();
    fs::write(
        &config,
        original.replace("jetstream {", "jetstream { enabled:false, "),
    )
    .unwrap();
    assert_eq!(
        unsafe { libc::kill(record["pid"].as_i64().unwrap() as i32, libc::SIGHUP) },
        0
    );
    let stream = format!("$JS.API.STREAM.INFO.SY_FED_{}", hash(&a_id));
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if conn
                .request(stream.clone(), b"{}".to_vec().into())
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        remote
            .call(
                "support_operation",
                &inspect(&b_id, "core-during-js-outage")
            )
            .await
            .unwrap()["state"],
        "completed"
    );
    let wait = remote
        .call(
            "wait_for_coord",
            &json!({"timeout_seconds":1,"since_sequence":0}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(wait.contains("503"), "{wait}");
    fs::write(&config, &original).unwrap();
    assert_eq!(
        unsafe { libc::kill(record["pid"].as_i64().unwrap() as i32, libc::SIGHUP) },
        0
    );
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if let Ok(message) = conn.request(stream.clone(), b"{}".to_vec().into()).await
                && let Ok(info) = serde_json::from_slice::<Value>(&message.payload)
                && info["config"]["name"] == format!("SY_FED_{}", hash(&a_id))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // The owning proxy can restart without replacing grants or receipts.
    stage0::crash(proxy_b).await;
    proxy_b = stage0::start_proxy(&b).await;
    let _ready = connection(&b, &a, &a_id).await;
    assert_eq!(
        remote
            .call(
                "read_support_operation",
                &json!({"operation_id":"before-outage"})
            )
            .await
            .unwrap(),
        before
    );
    coord_json(&b, &["stop"]).await;
    let unavailable = remote
        .call("support_operation", &inspect(&b_id, "core-unreachable"))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        unavailable.contains("503") && unavailable.contains("unreachable"),
        "{unavailable}"
    );
    assert!(receipt(&b, "core-unreachable").is_none());
    let mut onsite = inspect(&b_id, "onsite-during-core-outage");
    onsite["grant"] = json!("onsite");
    assert_eq!(
        client(&b, "bob", false)
            .call("support_operation", &onsite)
            .await
            .unwrap()["state"],
        "completed"
    );
    // Existing local owner CLI restores its own broker on the original route.
    let port = record["client_port"].to_string();
    host_json(
        &b,
        &["coord", "start", "--binary", &nats, "--client-port", &port],
    )
    .await;
    let _ready = connection(&b, &a, &a_id).await;
    assert_eq!(
        remote
            .call("support_operation", &inspect(&b_id, "core-restored"))
            .await
            .unwrap()["state"],
        "completed"
    );
    stage0::crash(proxy_a).await;
    stage0::crash(proxy_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; independent roots and controlled ingress runs"]
async fn remote_support_uses_owner_grants_receipts_and_independent_attention_sources() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let retained = tempfile::Builder::new()
        .prefix("remote-support-")
        .tempdir()
        .unwrap()
        .keep();
    println!("remote support operands: {}", retained.display());
    let (a, b) = (retained.join("a"), retained.join("b"));
    initialize(&a, &nats).await;
    initialize(&b, &nats).await;
    let (_clean_a, _clean_b) = (NatsCleanup(a.clone()), NatsCleanup(b.clone()));
    let (a_id, b_id) = (instance(&a), instance(&b));
    assert_ne!(a_id, b_id);
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
    let link = Link::new(endpoint).await;
    configure_home(&b, &a, &b_id, &link.endpoint).await;
    let mut run_a = super::super::controlled_runs::agent_run(
        &a,
        "bob",
        BOB,
        "0123456789abcdef0123456789abcdef",
    );
    let _run_b = super::super::controlled_runs::agent_run(
        &b,
        "bob",
        BOB,
        "0123456789abcdef0123456789abcdef",
    );
    let _run_carol = super::super::controlled_runs::agent_run(
        &a,
        "carol",
        CAROL,
        "0123456789abcdef0123456789abcdef",
    );
    let (proxy_a, proxy_b) = (stage0::start_proxy(&a).await, stage0::start_proxy(&b).await);
    let (local, remote) = (client(&a, "bob", false), client(&a, "bob", true));
    let conn = connection(&b, &a, &a_id).await;
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let result = conn
                .request(
                    format!("SY_FED.request.{}.{}", hash(&b_id), hash(&a_id)),
                    b"{}".to_vec().into(),
                )
                .await;
            if result.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        remote
            .call("support_grants", &json!({}))
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    let granted = apply(&b, "incident", proposal(&b_id, Some(&a_id))).await;
    assert_eq!(
        count(&b, "SELECT count(*) FROM rooms"),
        0,
        "support must not create a dummy room"
    );
    assert_eq!(count(&b, "SELECT count(*) FROM coord_federation_agents"), 1);
    assert_eq!(
        remote.call("support_grants", &json!({})).await.unwrap()["instance_id"],
        b_id
    );
    let first = remote
        .call("support_operation", &inspect(&b_id, "inspect-1"))
        .await
        .unwrap();
    assert_eq!(first["instance_id"], b_id);
    assert_eq!(first["target_id"], ALICE);
    assert_eq!(first["initiator"]["remote"]["instance_id"], a_id);
    assert!(!a.join("data/support-operations").exists());
    assert_eq!(
        remote
            .call("support_operation", &inspect(&b_id, "inspect-1"))
            .await
            .unwrap(),
        first
    );
    let mut wrong = inspect(&b_id, "wrong-target");
    wrong["target_id"] = json!(CAROL);
    assert!(
        remote
            .call("support_operation", &wrong)
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    wrong = inspect(&b_id, "wrong-action");
    wrong["operation"] =
        json!({"action":"guest_command","command":"touch /never","timeout_seconds":1});
    assert!(
        remote
            .call("support_operation", &wrong)
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    assert!(
        client(&a, "carol", true)
            .call("support_operation", &inspect(&b_id, "ungranted"))
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    let wire = json!({"destination_instance_id":"sy-wrong-owner","source_run":{"agent":"bob","agent_id":BOB,"run_id":"0123456789abcdef0123456789abcdef"},"method":"POST","path":"/support/operations","body":inspect(&b_id,"misroute")});
    assert_eq!(raw(&conn, &b_id, &a_id, wire.clone()).await["status"], 403);
    assert!(
        !fs::read_to_string(b.join("audit.jsonl"))
            .unwrap_or_default()
            .contains("misroute")
    );
    let mut forged = wire;
    forged["destination_instance_id"] = json!(b_id);
    forged["origin_instance_id"] = json!("sy-forged");
    assert_eq!(raw(&conn, &b_id, &a_id, forged).await["status"], 400);
    // Publish and subscribe denials are enforced by the actual broker. The
    // client reports asynchronous permission errors through its callback.
    let denied = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let events = denied.clone();
    let record: Value =
        serde_json::from_slice(&fs::read(b.join("data/coord/nats/process.json")).unwrap()).unwrap();
    let scoped = async_nats::ConnectOptions::new()
        .require_tls(true)
        .add_root_certificates(b.join("peer.pem"))
        .user_and_password(
            hash(&a_id),
            fs::read_to_string(a.join("federation-secret"))
                .unwrap()
                .trim()
                .into(),
        )
        .event_callback(move |event| {
            let events = events.clone();
            async move {
                if matches!(event, async_nats::Event::ServerError(_)) {
                    events.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .connect(format!("tls://127.0.0.1:{}", record["client_port"]))
        .await
        .unwrap();
    for subject in [
        "coord.private".to_owned(),
        "SY_LOCAL.private".to_owned(),
        "$JS.API.STREAM.LIST".to_owned(),
        format!("SY_FED.request.{}.{}", hash(&b_id), hash("sy-forged")),
    ] {
        let _subscription = scoped.subscribe(subject.clone()).await.unwrap();
        scoped
            .publish(subject, b"denied".to_vec().into())
            .await
            .unwrap();
        scoped.flush().await.unwrap();
    }
    stage0::until(|| denied.load(Ordering::SeqCst) >= 8).await;
    // Independent local and remote attention, with no shared room.
    apply(&a, "local", proposal(&a_id, None)).await;
    stage0::until(|| {
        a.join("agents/alice/operational-observation.json").exists()
            && b.join("agents/alice/operational-observation.json").exists()
    })
    .await;
    let target_a = super::super::controlled_runs::agent_run(
        &a,
        "alice",
        ALICE,
        "00112233445566778899aabbccddeeff",
    );
    let target_b = super::super::controlled_runs::agent_run(
        &b,
        "alice",
        ALICE,
        "00112233445566778899aabbccddeeff",
    );
    stage0::until(|| {
        count(&a, "SELECT count(*) FROM coord_operational_references") >= 2
            && count(&b, "SELECT count(*) FROM coord_operational_references") >= 2
    })
    .await;
    let multi=local.call("wait_for_coord",&json!({"sources":[{"instance_id":a_id,"since_sequence":0},{"home":"primary","instance_id":b_id,"since_sequence":0}],"timeout_seconds":6,"limit":50})).await.unwrap();
    assert!(
        multi["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["objects"]
                .as_array()
                .is_some_and(|objects| !objects.is_empty())),
        "{multi}"
    );
    let mut cursors = multi["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| source["next_cursor"].as_u64().unwrap())
        .collect::<Vec<_>>();
    let resumed=local.call("wait_for_coord",&json!({"sources":[{"instance_id":a_id,"since_sequence":cursors[0]},{"home":"primary","instance_id":b_id,"since_sequence":cursors[1]}],"timeout_seconds":6,"limit":50})).await.unwrap();
    for (index, source) in resumed["sources"].as_array().unwrap().iter().enumerate() {
        cursors[index] = source["next_cursor"].as_u64().unwrap();
    }
    for index in 0..2 {
        let seen = [&multi, &resumed]
            .iter()
            .flat_map(|page| page["sources"][index]["objects"].as_array().unwrap())
            .any(|object| {
                object["instance_id"].as_str()
                    == Some(if index == 0 {
                        a_id.as_str()
                    } else {
                        b_id.as_str()
                    })
            });
        assert!(seen, "source {index} was not delivered: {multi} {resumed}");
    }
    let rebound=local.call("wait_for_coord",&json!({"sources":[{"home":"primary","instance_id":a_id,"since_sequence":cursors[0]}],"timeout_seconds":0})).await.unwrap();
    assert_eq!(rebound["sources"][0]["availability"], "unavailable");
    assert_eq!(rebound["sources"][0]["next_cursor"], cursors[0]);
    // A disconnected source keeps its position. A still supplies useful
    // work, and B's independently retained references resume after reconnect.
    link.partitioned.store(true, Ordering::SeqCst);
    let before_a = count(&a, "SELECT count(*) FROM coord_operational_references");
    let before_b = count(&b, "SELECT count(*) FROM coord_operational_references");
    drop(target_a);
    drop(target_b);
    stage0::until(|| {
        count(&a, "SELECT count(*) FROM coord_operational_references") > before_a
            && count(&b, "SELECT count(*) FROM coord_operational_references") > before_b
    })
    .await;
    let cut=local.call("wait_for_coord",&json!({"sources":[{"instance_id":a_id,"since_sequence":cursors[0]},{"home":"primary","instance_id":b_id,"since_sequence":cursors[1]}],"timeout_seconds":2,"limit":50})).await.unwrap();
    assert_eq!(cut["sources"][0]["availability"], "available", "{cut}");
    assert!(
        !cut["sources"][0]["objects"].as_array().unwrap().is_empty(),
        "{cut}"
    );
    assert_eq!(cut["sources"][1]["availability"], "unavailable", "{cut}");
    assert_eq!(cut["sources"][1]["next_cursor"], cursors[1]);
    // Healthy-source diagnosis is permitted while B's route is disconnected.
    let mut healthy = inspect(&a_id, "healthy-during-partition");
    healthy["grant"] = json!("local");
    assert_eq!(
        local.call("support_operation", &healthy).await.unwrap()["instance_id"],
        a_id
    );
    link.partitioned.store(false, Ordering::SeqCst);
    let resumed=local.call("wait_for_coord",&json!({"sources":[{"home":"primary","instance_id":b_id,"since_sequence":cursors[1]}],"timeout_seconds":3,"limit":50})).await.unwrap();
    assert_eq!(
        resumed["sources"][0]["availability"], "available",
        "{resumed}"
    );
    assert!(
        resumed["sources"][0]["next_cursor"].as_u64().unwrap() > cursors[1],
        "{resumed}"
    );
    // An unavailable backend retains its last run identity. A deliberately
    // different expected run must refuse a start before any execution.
    let mut stale = inspect(&b_id, "stale-target-run");
    stale["expected_run"] = json!("ffeeddccbbaa99887766554433221100");
    stale["operation"] = json!({"action":"lifecycle","operation":"start_sandbox"});
    assert_eq!(
        remote.call("support_operation", &stale).await.unwrap()["state"],
        "refused"
    );
    assert!(receipt(&b, "stale-target-run").unwrap()["execution_started"].is_null());
    // Drop the guest-facing reply after the actual owner saved completion.
    // Reading and retrying the original ID must disclose the one saved result.
    let mut lost = tokio::net::UnixStream::connect(a.join("bob.sock"))
        .await
        .unwrap();
    let token = zeroize::Zeroizing::new(fs::read_to_string(a.join("data/agent_token")).unwrap());
    let body = inspect(&b_id, "lost-support-reply").to_string();
    lost.write_all(format!("POST http://_safeyolo.proxy.internal/support/operations?home=primary HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",token.trim(),body.len()).as_bytes()).await.unwrap();
    stage0::until(|| receipt(&b, "lost-support-reply").is_some_and(|r| r["state"] == "completed"))
        .await;
    drop(lost);
    let recorded = remote
        .call(
            "read_support_operation",
            &json!({"operation_id":"lost-support-reply"}),
        )
        .await
        .unwrap();
    assert_eq!(recorded["completion_verified"], true);
    assert_eq!(
        remote
            .call("support_operation", &inspect(&b_id, "lost-support-reply"))
            .await
            .unwrap(),
        recorded
    );
    let _replacement_target = super::super::controlled_runs::agent_run(
        &b,
        "alice",
        ALICE,
        "fedcba9876543210fedcba9876543210",
    );
    let replacement = remote
        .call(
            "support_operation",
            &inspect(&b_id, "replacement-target-run"),
        )
        .await
        .unwrap();
    assert_eq!(
        replacement["target_run"],
        "fedcba9876543210fedcba9876543210"
    );
    assert_eq!(
        remote
            .call(
                "read_support_operation",
                &json!({"operation_id":"lost-support-reply"})
            )
            .await
            .unwrap()["target_run"],
        "00112233445566778899aabbccddeeff"
    );
    // Narrowing and expiry independently remove result disclosure authority.
    let narrowed = apply(&b, "narrowed", proposal(&b_id, Some(&a_id))).await;
    let mut selected = inspect(&b_id, "before-narrowing");
    selected["grant"] = json!("narrowed");
    remote.call("support_operation", &selected).await.unwrap();
    let mut change = proposal(&b_id, Some(&a_id));
    change["expected_revision"] = narrowed["revision"].clone();
    change["grant"]["targets"] = json!([{"name":"carol","agent_id":CAROL}]);
    apply(&b, "narrowed", change).await;
    assert!(
        remote
            .call(
                "read_support_operation",
                &json!({"operation_id":"before-narrowing"})
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(2);
    let mut temporary = proposal(&b_id, Some(&a_id));
    temporary["grant"]["expires_at"] = json!(
        expires
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    apply(&b, "temporary", temporary).await;
    selected = inspect(&b_id, "before-expiry");
    selected["grant"] = json!("temporary");
    remote.call("support_operation", &selected).await.unwrap();
    while time::OffsetDateTime::now_utc() < expires {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        remote
            .call(
                "read_support_operation",
                &json!({"operation_id":"before-expiry"})
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    // Revocation while the operation is queued at B's actual target lock.
    fs::create_dir_all(b.join("agents/alice")).unwrap();
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(b.join("agents/alice/host-setup.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let operation = inspect(&b_id, "queued-revoke");
    let pending = remote.call("support_operation", &operation);
    tokio::pin!(pending);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        tokio::select! {result=&mut pending=>panic!("escaped owner lock: {result:?}"),_=tokio::time::sleep(Duration::from_millis(10))=>{}}
        if receipt(&b, "queued-revoke").is_some_and(|receipt| receipt["state"] == "queued") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "request did not reach the owner lock"
        );
    }
    revoke(&b, "incident", granted["revision"].clone()).await;
    drop(lock);
    assert!(pending.await.unwrap_err().to_string().contains("403"));
    let restored = apply(&b, "incident", proposal(&b_id, Some(&a_id))).await;
    let queued = remote
        .call(
            "read_support_operation",
            &json!({"operation_id":"queued-revoke"}),
        )
        .await
        .unwrap();
    assert_eq!(queued["state"], "refused");
    drop(run_a);
    assert!(
        remote
            .call("support_operation", &inspect(&b_id, "stale-source"))
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    run_a = super::super::controlled_runs::agent_run(
        &a,
        "bob",
        BOB,
        "fedcba9876543210fedcba9876543210",
    );
    let old = remote
        .call(
            "read_support_operation",
            &json!({"operation_id":"inspect-1"}),
        )
        .await
        .unwrap();
    assert_eq!(
        old["initiator"]["run_id"],
        "0123456789abcdef0123456789abcdef"
    );
    assert!(
        remote
            .call(
                "support_operation",
                &inspect(&b_id, "standing-after-restart")
            )
            .await
            .is_ok()
    );
    coord_json(&b, &["federation", "revoke", &a_id]).await;
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
    assert!(
        remote
            .call("support_operation", &inspect(&b_id, "retrust-old-grant"))
            .await
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    println!(
        "qualified support: source={a_id} destination={b_id}; room-independent grant={}, restored={}; scoped denials={}, independent cursor positions={cursors:?}",
        granted["revision"],
        restored["revision"],
        denied.load(Ordering::SeqCst)
    );
    drop(run_a);
    stage0::crash(proxy_a).await;
    stage0::crash(proxy_b).await;
}
