//! Two owned native SafeYolos, real Agent API/NATS and a separate TLS relay.
use super::*;
use hyper::Method;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CAROL: &str = "ag-cccccccccccccccccccccccccccccccc";

async fn host_json(root: &Path, args: &[&str]) -> Value {
    let output = host_cli(root, args).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

async fn initialize(root: &Path, nats: &str) -> Value {
    fs::create_dir(root).unwrap();
    host_json(root, &["init"]).await;
    fs::write(root.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
    fs::write(root.join("policy.toml"),format!("[controls.network]\nenabled=false\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.carol]\nagent_id='{CAROL}'\n")).unwrap();
    host_json(root, &["coord", "start", "--binary", nats]).await
}

fn client(root: &Path, agent: &str, home: bool) -> Client {
    Client {
        socket: Some(root.join(format!("{agent}.sock"))),
        token_file: root.join("data/agent_token"),
        home: home.then(|| "primary".into()),
    }
}

async fn relay(root: &Path) -> (tokio::process::Child, String) {
    let mut command = host_command(
        root,
        &[
            "coord",
            "federation",
            "serve",
            "127.0.0.1:0",
            root.join("peer.pem").to_str().unwrap(),
            root.join("peer.key").to_str().unwrap(),
        ],
    );
    command.stderr(Stdio::from(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("relay-private.log"))
            .unwrap(),
    ));
    let mut process = command.spawn().unwrap();
    let mut reader = BufReader::new(process.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let ready: Value = serde_json::from_str(&line).expect("federation readiness");
    (process, ready["federation_listen"].as_str().unwrap().into())
}

/// This is a TCP fault injector, never a peer or claim authority. Normal
/// traffic, including TLS authentication, reaches the actual home SafeYolo.
struct Link {
    endpoint: String,
    partitioned: Arc<AtomicBool>,
    accepted: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Link {
    async fn new(home: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let partitioned = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(Notify::new());
        let (cut, seen) = (partitioned.clone(), accepted.clone());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result=listener.accept()=> {
                        let (mut source,_)=result.unwrap();
                        if cut.load(Ordering::SeqCst) {
                            seen.notify_one();
                            // A mutation is in flight at the source when the
                            // link disappears. No request reaches a second store.
                            drop(source);
                            continue;
                        }
                        let home=home.clone();
                        connections.spawn(async move {
                            let Ok(mut destination)=TcpStream::connect(home).await else { return; };
                            let _=tokio::io::copy_bidirectional(&mut source,&mut destination).await;
                        });
                    }
                    _=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        Self {
            endpoint,
            partitioned,
            accepted,
            task,
        }
    }
}

async fn configure_home(home: &Path, peer: &Path, home_id: &str, endpoint: &str) {
    coord_json(
        peer,
        &[
            "federation",
            "home",
            "primary",
            home_id,
            &format!("https://{endpoint}"),
            home.join("peer.pem").to_str().unwrap(),
            peer.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
}

fn count(root: &Path, sql: &str) -> i64 {
    rusqlite::Connection::open(root.join("data/coord/v0.db"))
        .unwrap()
        .query_row(sql, [], |r| r.get(0))
        .unwrap()
}

async fn owned_stream(root: &Path) -> async_nats::jetstream::stream::Stream {
    let record: Value =
        serde_json::from_slice(&fs::read(root.join("data/coord/nats/process.json")).unwrap())
            .unwrap();
    let password =
        zeroize::Zeroizing::new(fs::read_to_string(root.join("data/coord/nats/creds")).unwrap());
    let connection = async_nats::ConnectOptions::new()
        .user_and_password("safeyolo".into(), password.trim().into())
        .connection_timeout(Duration::from_secs(2))
        .request_timeout(Some(Duration::from_secs(2)))
        .connect(format!("nats://127.0.0.1:{}", record["client_port"]))
        .await
        .unwrap();
    let room: String = rusqlite::Connection::open(root.join("data/coord/v0.db"))
        .unwrap()
        .query_row("SELECT room_id FROM rooms WHERE name='shared'", [], |r| {
            r.get(0)
        })
        .unwrap();
    async_nats::jetstream::new(connection)
        .get_stream(format!("ROOM_{room}"))
        .await
        .unwrap()
}

async fn armed(stream: &mut async_nats::jetstream::stream::Stream, baseline: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if stream.info().await.unwrap().state.consumer_count > baseline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the actual home NATS consumer did not become armed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; two real owned native SafeYolo instances"]
async fn two_safeyolos_share_only_home_authority_across_partition_restart_and_revocation() {
    use std::os::unix::fs::PermissionsExt;
    let started = std::time::Instant::now();
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let retained = tempfile::Builder::new()
        .prefix("coord-federation-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap()
        .keep();
    fs::set_permissions(&retained, fs::Permissions::from_mode(0o700)).unwrap();
    println!("private two-instance operands: {}", retained.display());
    let (home, peer) = (retained.join("home"), retained.join("peer"));
    let home_nats = initialize(&home, &nats).await;
    let _home_cleanup = NatsCleanup(home.clone());
    let peer_nats = initialize(&peer, &nats).await;
    let _peer_cleanup = NatsCleanup(peer.clone());
    assert_ne!(home_nats["client_port"], peer_nats["client_port"]);
    let home_id = fs::read_to_string(home.join("data/instance_id"))
        .unwrap()
        .trim()
        .to_owned();
    let peer_id = fs::read_to_string(peer.join("data/instance_id"))
        .unwrap()
        .trim()
        .to_owned();
    assert_ne!(home_id, peer_id);
    coord_json(&home, &["room", "create", "shared"]).await;
    coord_json(&home, &["room", "create", "local-only"]).await;
    coord_json(&peer, &["room", "create", "shared"]).await;
    for room in ["shared", "local-only"] {
        coord_json(&home, &["grant", room, "alice"]).await;
    }
    coord_json(&peer, &["grant", "shared", "bob"]).await;
    coord_json(
        &home,
        &[
            "federation",
            "credential",
            peer.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    coord_json(
        &home,
        &[
            "federation",
            "trust",
            &peer_id,
            peer.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    for (id, name) in [(BOB, "remote-bob"), (CAROL, "remote-carol")] {
        coord_json(
            &home,
            &["federation", "member", "shared", &peer_id, id, name],
        )
        .await;
    }
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    fs::write(home.join("peer.pem"), certificate.cert.pem()).unwrap();
    fs::write(
        home.join("peer.key"),
        certificate.signing_key.serialize_pem(),
    )
    .unwrap();
    let (mut relay_process, endpoint) = relay(&home).await;
    let link = Link::new(endpoint).await;
    configure_home(&home, &peer, &home_id, &link.endpoint).await;
    let mut home_proxy = stage0::start_proxy(&home).await;
    let mut peer_proxy = stage0::start_proxy(&peer).await;
    let (alice, bob, carol) = (
        client(&home, "alice", false),
        client(&peer, "bob", true),
        client(&peer, "carol", true),
    );
    let brief = coord_json(
        &home,
        &[
            "brief",
            "set",
            "shared",
            "Home-owned version one",
            "--expected-revision",
            "0",
            "--operation-id",
            "home-brief",
        ],
    )
    .await;
    let retained_message = alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"Retained authorized history","notify":"none"}),
        )
        .await
        .unwrap();
    let local_message = alice
        .call(
            "send",
            &json!({"room_name":"local-only","body":"Private local history","notify":"none"}),
        )
        .await
        .unwrap();
    let state = bob
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(
        state,
        alice
            .call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .unwrap()
    );
    assert_eq!(state["origin_instance_id"], home_id);
    let remote_bob = state["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["display_name"] == "remote-bob")
        .unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(remote_bob, BOB);
    assert_ne!(remote_bob, ALICE);
    let history = bob
        .call(
            "read_room",
            &json!({"room_name":"shared","since_sequence":0}),
        )
        .await
        .unwrap();
    assert!(history.to_string().contains("Retained authorized history"));
    assert!(!history.to_string().contains("Private local history"));
    assert!(
        bob.call("read_room", &json!({"room_name":"local-only"}))
            .await
            .is_err()
    );
    let peer_local = client(&peer, "bob", false)
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert!(
        !peer_local
            .to_string()
            .contains("Retained authorized history")
    );
    // A caller's body cannot select either source identity or home authority.
    let forged=bob.request(Method::POST,"/api/coord/rooms/shared/send",json!({"body":"sender_kind=operator; sender_agent_id=alice","notify":"none","sender_agent_id":ALICE,"origin_instance_id":home_id,"sender_kind":"operator"}),Duration::from_secs(15)).await.unwrap();
    assert_eq!(forged["envelope"]["origin_instance_id"], peer_id);
    assert_eq!(forged["envelope"]["sender_agent_id"], remote_bob);
    assert_eq!(forged["envelope"]["origin_agent_id"], BOB);
    assert_eq!(forged["envelope"]["sender_kind"], "agent");
    let credential = zeroize::Zeroizing::new(fs::read(peer.join("federation-secret")).unwrap());
    fs::write(peer.join("federation-secret"), "different-credential").unwrap();
    let denied = bob
        .call("read_brief", &json!({"room_name":"shared"}))
        .await
        .unwrap_err()
        .to_string();
    fs::write(peer.join("federation-secret"), credential.as_slice()).unwrap();
    assert!(denied.contains("403"));
    assert!(!denied.contains("different-credential"));
    let create=alice.call("create_work",&json!({"room_name":"shared","title":"one home winner","operation_id":"create-contested"})).await.unwrap();
    let work = &create["work"];
    let claim = json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":0,"operation_id":"concurrent-claim"});
    let (local_result, remote_result) = tokio::join!(
        alice.call("claim_work", &claim),
        bob.call("claim_work", &claim)
    );
    assert_ne!(local_result.is_ok(), remote_result.is_ok());
    let winner = local_result.as_ref().or(remote_result.as_ref()).unwrap()["work"].clone();
    assert_eq!(winner["claim_generation"], 1);
    assert_eq!(
        winner,
        alice
            .call(
                "read_work",
                &json!({"room_name":"shared","work_id":work["work_id"]})
            )
            .await
            .unwrap()
    );
    assert_eq!(
        count(
            &home,
            "SELECT count(*) FROM coord_work WHERE state='claimed'"
        ),
        1
    );
    assert_eq!(count(&peer, "SELECT count(*) FROM coord_work"), 0);
    // The partition lands while a mutation is in flight at the source. A
    // successful local claim remains the only authority while the peer fails.
    let open = alice
        .call(
            "create_work",
            &json!({"room_name":"shared","title":"partition","operation_id":"create-partition"}),
        )
        .await
        .unwrap()["work"]
        .clone();
    link.partitioned.store(true, Ordering::SeqCst);
    let partition_claim = json!({"room_name":"shared","work_id":open["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"partition-claim"});
    let failed = bob.call("claim_work", &partition_claim);
    let (failure, _) = tokio::join!(failed, async {
        tokio::time::timeout(Duration::from_secs(10), link.accepted.notified())
            .await
            .unwrap();
    });
    assert!(failure.unwrap_err().to_string().contains("503"));
    let claimed=alice.call("claim_work",&json!({"room_name":"shared","work_id":open["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"home-during-partition"})).await.unwrap()["work"].clone();
    assert_eq!(count(&peer, "SELECT count(*) FROM coord_work"), 0);
    link.partitioned.store(false, Ordering::SeqCst);
    assert_eq!(
        bob.call(
            "read_work",
            &json!({"room_name":"shared","work_id":open["work_id"]})
        )
        .await
        .unwrap(),
        claimed
    );
    // Import remains home-owned; GitHub access remains on each caller's own
    // instance. Neither fixture has a GitHub service grant.
    let import = json!({"room_name":"shared","url":"https://github.com/craigbalding/safeyolo/issues/1315","operation_id":"same-reference"});
    let local_import = alice.call("import_github_work", &import).await.unwrap();
    let remote_import = bob.call("import_github_work", &import).await.unwrap();
    // Imports seed work and scope retries to the authenticated principal;
    // they do not deduplicate a URL across different authors.
    assert_ne!(
        local_import["work"]["work_id"],
        remote_import["work"]["work_id"]
    );
    assert_eq!(
        local_import["work"]["external_ref"],
        remote_import["work"]["external_ref"]
    );
    assert_eq!(
        local_import["work"]["title"],
        remote_import["work"]["title"]
    );
    assert_eq!(remote_import["work"]["created_by"]["id"], remote_bob);
    let external = json!({"room_name":"shared","work_id":local_import["work"]["work_id"]});
    let local_external = alice.call("read_github_work", &external).await.unwrap();
    let remote_external = bob.call("read_github_work", &external).await.unwrap();
    assert_eq!(local_external, remote_external);
    assert_eq!(remote_external["external"]["status"], "unavailable");
    let remote_claim=bob.call("claim_work",&json!({"room_name":"shared","work_id":local_import["work"]["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"remote-holder"})).await.unwrap()["work"].clone();
    assert_eq!(remote_claim["claim_agent_id"], remote_bob);
    let completion = json!({"room_name":"shared","work_id":remote_claim["work_id"],"expected_version":remote_claim["version"],"expected_generation":remote_claim["claim_generation"],"operation_id":"remote-completion"});
    assert!(alice.call("complete_work", &completion).await.is_err());
    assert_eq!(
        bob.call("complete_work", &completion).await.unwrap()["work"]["state"],
        "done"
    );
    let feed = |reader: Client| async move {
        reader
            .call(
                "wait_for_attention",
                &json!({"since_sequence":0,"limit":200,"timeout_seconds":0}),
            )
            .await
            .unwrap()
    };
    let bob_cursor = feed(bob.clone()).await["next_cursor"].as_u64().unwrap();
    let carol_cursor = feed(carol.clone()).await["next_cursor"].as_u64().unwrap();
    let notice=alice.call("send",&json!({"room_name":"shared","body":"Remote intended recipient","notify":["remote-bob"]})).await.unwrap();
    let attention = bob
        .call(
            "wait_for_coord",
            &json!({"since_sequence":bob_cursor,"limit":20,"timeout_seconds":2}),
        )
        .await
        .unwrap();
    assert_eq!(attention["objects"].as_array().unwrap().len(), 1);
    assert_eq!(
        attention["objects"][0]["object"]["body"],
        "Remote intended recipient"
    );
    let unrelated = carol
        .call(
            "wait_for_attention",
            &json!({"since_sequence":carol_cursor,"limit":20,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    assert!(unrelated["edges"].as_array().unwrap().is_empty());
    let update = coord_json(
        &home,
        &[
            "brief",
            "set",
            "shared",
            "Home-owned version two",
            "--expected-revision",
            "1",
            "--operation-id",
            "home-brief-two",
        ],
    )
    .await;
    assert_eq!(update["revision"], 2);
    assert_eq!(
        bob.call("read_brief", &json!({"room_name":"shared"}))
            .await
            .unwrap(),
        alice
            .call("read_brief", &json!({"room_name":"shared"}))
            .await
            .unwrap()
    );
    let mut stream = owned_stream(&home).await;
    let baseline = stream.info().await.unwrap().state.consumer_count;
    let waiting = carol.clone();
    let since = notice["sequence"].as_u64().unwrap();
    let outgoing_wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_message",
                &json!({"room_name":"shared","since_sequence":since,"timeout_seconds":5}),
            )
            .await
    });
    armed(&mut stream, baseline).await;
    coord_json(&peer, &["federation", "unhome", "primary"]).await;
    alice.call("send",&json!({"room_name":"shared","body":"Removed route cannot deliver this","notify":"room"})).await.unwrap();
    assert!(
        outgoing_wait
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("403")
    );
    configure_home(&home, &peer, &home_id, &link.endpoint).await;
    // Deliberately discard a response after observing the home commit. The
    // original operation ID is the only retry identity across actual crashes.
    let mut raw = tokio::net::UnixStream::connect(peer.join("bob.sock"))
        .await
        .unwrap();
    let token = zeroize::Zeroizing::new(fs::read_to_string(peer.join("data/agent_token")).unwrap());
    let mutation=json!({"action":"create","title":"response deliberately unconsumed","operation_id":"interrupted-response"}).to_string();
    raw.write_all(format!("POST http://_safeyolo.proxy.internal/api/coord/rooms/shared/work?home=primary HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{mutation}",token.trim(),mutation.len()).as_bytes()).await.unwrap();
    stage0::until(|| {
        count(
            &home,
            "SELECT count(*) FROM coord_operations WHERE operation_id='interrupted-response'",
        ) == 1
    })
    .await;
    drop(raw);
    stage0::crash(peer_proxy).await;
    stage0::crash(home_proxy).await;
    stage0::crash(relay_process).await;
    coord_json(&home, &["stop"]).await;
    host_json(&home, &["coord", "start", "--binary", &nats]).await;
    // The old link's destination was the crashed endpoint. Select the new
    // listener explicitly; no remote state or claim history is merged.
    let (restarted, actual_endpoint) = relay(&home).await;
    relay_process = restarted;
    configure_home(&home, &peer, &home_id, &actual_endpoint).await;
    home_proxy = stage0::start_proxy(&home).await;
    peer_proxy = stage0::start_proxy(&peer).await;
    let replay=bob.call("create_work",&json!({"room_name":"shared","title":"response deliberately unconsumed","operation_id":"interrupted-response"})).await.unwrap();
    assert_eq!(
        count(
            &home,
            "SELECT count(*) FROM coord_operations WHERE operation_id='interrupted-response'"
        ),
        1
    );
    assert_eq!(
        bob.call(
            "read_work",
            &json!({"room_name":"shared","work_id":work["work_id"]})
        )
        .await
        .unwrap(),
        winner
    );
    assert_eq!(count(&peer, "SELECT count(*) FROM coord_work"), 0);
    // Both revocation boundaries must deny subsequent reads and an armed read.
    let mut stream = owned_stream(&home).await;
    let baseline = stream.info().await.unwrap().state.consumer_count;
    let waiting = bob.clone();
    let wait = tokio::spawn(async move {
        waiting
            .call(
                "wait_for_message",
                &json!({"room_name":"shared","since_sequence":10000,"timeout_seconds":5}),
            )
            .await
    });
    armed(&mut stream, baseline).await;
    coord_json(
        &home,
        &[
            "federation",
            "unmember",
            "shared",
            &peer_id,
            BOB,
            "--operation-id",
            "revoke-bob",
        ],
    )
    .await;
    alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"Revoked agent cannot read this","notify":"room"}),
        )
        .await
        .unwrap();
    let revoked_wait = tokio::time::timeout(Duration::from_secs(8), wait)
        .await
        .unwrap()
        .unwrap();
    assert!(
        revoked_wait.is_err()
            || revoked_wait.unwrap()["messages"]
                .as_array()
                .is_some_and(Vec::is_empty)
    );
    assert!(
        bob.call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    assert!(bob.call("read_work", &external).await.is_err());
    assert!(
        bob.call(
            "read_attention",
            &json!({"attention_id":attention["objects"][0]["edge"]["attention_id"]})
        )
        .await
        .is_err()
    );
    let restored_bob = coord_json(
        &home,
        &[
            "federation",
            "member",
            "shared",
            &peer_id,
            BOB,
            "remote-bob",
            "--operation-id",
            "restore-bob",
        ],
    )
    .await;
    assert!(
        bob.call("read_room", &json!({"room_name":"shared"}))
            .await
            .unwrap()
            .to_string()
            .contains("Revoked agent cannot read this")
    );
    // An active grant in any room keeps the current name unambiguous. Once
    // all grants are revoked, another durable ID may use that human name.
    coord_json(&home, &["room", "create", "also-shared"]).await;
    coord_json(
        &home,
        &[
            "federation",
            "member",
            "also-shared",
            &peer_id,
            BOB,
            "remote-bob",
            "--operation-id",
            "other-room-bob",
        ],
    )
    .await;
    coord_json(
        &home,
        &[
            "federation",
            "unmember",
            "shared",
            &peer_id,
            BOB,
            "--operation-id",
            "retire-shared-bob",
        ],
    )
    .await;
    let replacement_args = [
        "federation",
        "member",
        "shared",
        &peer_id,
        CAROL,
        "remote-bob",
        "--operation-id",
        "replace-retired-bob",
    ];
    assert!(!coord_cli(&home, &replacement_args).await.status.success());
    assert!(
        bob.call("read_room", &json!({"room_name":"also-shared"}))
            .await
            .is_ok()
    );
    coord_json(
        &home,
        &[
            "federation",
            "unmember",
            "also-shared",
            &peer_id,
            BOB,
            "--operation-id",
            "retire-other-bob",
        ],
    )
    .await;
    let replacement = coord_json(&home, &replacement_args).await;
    assert_ne!(replacement["agent_id"], remote_bob);
    assert!(
        bob.call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let retained_history = carol
        .call("read_room", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let old_message = retained_history["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["msg_id"] == forged["envelope"]["msg_id"])
        .unwrap();
    for field in [
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "origin_agent_id",
        "body",
    ] {
        assert_eq!(old_message[field], forged["envelope"][field]);
    }
    let old_work = json!({"room_name":"shared","work_id":remote_import["work"]["work_id"]});
    assert_eq!(
        carol.call("read_work", &old_work).await.unwrap(),
        remote_import["work"]
    );
    assert_eq!(
        coord_json(
            &home,
            &[
                "federation",
                "member",
                "shared",
                &peer_id,
                BOB,
                "remote-bob",
                "--operation-id",
                "restore-bob"
            ]
        )
        .await,
        restored_bob
    );
    assert!(
        bob.call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    coord_json(&home, &["federation", "revoke", &peer_id]).await;
    assert!(
        bob.call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    assert!(
        carol
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    // Re-trusting restores no grants or old name reservation. A replacement
    // grant is explicit; replaying the former grant cannot steal it back.
    coord_json(
        &home,
        &[
            "federation",
            "trust",
            &peer_id,
            peer.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        carol
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let replacement_after_trust = coord_json(
        &home,
        &[
            "federation",
            "member",
            "shared",
            &peer_id,
            BOB,
            "remote-bob",
            "--operation-id",
            "replace-after-retrust",
        ],
    )
    .await;
    assert_eq!(replacement_after_trust["agent_id"], remote_bob);
    assert_eq!(
        bob.call("read_work", &old_work).await.unwrap(),
        remote_import["work"]
    );
    assert_eq!(coord_json(&home, &replacement_args).await, replacement);
    assert!(
        carol
            .call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let current_state = bob
        .call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let current_names = current_state["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["display_name"] == "remote-bob")
        .collect::<Vec<_>>();
    assert_eq!(current_names.len(), 1);
    assert_eq!(current_names[0]["agent_id"], remote_bob);
    coord_json(&home, &["federation", "revoke", &peer_id]).await;
    coord_json(&peer, &["federation", "unhome", "primary"]).await;
    assert!(
        bob.call("read_room", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    let local_after = alice
        .call("read_room", &json!({"room_name":"local-only"}))
        .await
        .unwrap();
    assert!(local_after.to_string().contains("Private local history"));
    let report = json!({"home_instance_id":home_id,"peer_instance_id":peer_id,"remote_principal_id":remote_bob,"contested_winner":winner,"partition_home_claim":claimed,"replayed_creation":replay["work"],"retained_message":retained_message,"local_only_message_id":local_message["envelope"]["msg_id"],"brief_revisions":[brief["revision"].clone(),update["revision"].clone()],"targeted_attention":attention,"github":remote_external,"name_reuse":{"after_unmember":replacement,"after_peer_retrust":replacement_after_trust},"peer_work_rows":count(&peer,"SELECT count(*) FROM coord_work"),"seconds":started.elapsed().as_secs_f64(),"limits":"Two independent native roots, proxy processes, NATS processes and a real TLS home relay on one owned host. TCP link interruption during a source mutation; discarded response after observed durable commit. No second physical host, real WAN performance, GitHub external access or model participation is inferred by this test."});
    fs::write(
        retained.join("observations.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("two-instance observations: {}", report);
    stage0::crash(peer_proxy).await;
    stage0::crash(home_proxy).await;
    stage0::crash(relay_process).await;
}
