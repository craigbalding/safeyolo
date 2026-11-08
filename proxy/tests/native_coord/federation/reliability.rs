//! Actual independent brokers; faults never touch the running factory.
use super::*;
use futures_util::StreamExt;

fn binary(name: &str) -> PathBuf {
    std::env::var_os("SAFEYOLO_COORD_RELIABILITY_BASE_BIN")
        .map(|directory| PathBuf::from(directory).join(name))
        .unwrap_or_else(|| {
            PathBuf::from(match name {
                "safeyolo" => env!("CARGO_BIN_EXE_safeyolo"),
                _ => env!("CARGO_BIN_EXE_safeyolo-proxy"),
            })
        })
}

async fn host(root: &Path, args: &[&str]) -> Value {
    let output = tokio::process::Command::new(binary("safeyolo"))
        .arg("--root")
        .arg(root)
        .args(args)
        .env("SAFEYOLO_NATS_TEST_INSTANCE", root)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

async fn start(root: &Path) -> tokio::process::Child {
    let child = tokio::process::Command::new(binary("safeyolo-proxy"))
        .arg("--config")
        .arg(root.join("config.toml"))
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("proxy-diagnostics.log"))
                .unwrap(),
        ))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let config = native_config::read(&root.join("config.toml")).unwrap();
    stage0::until(|| {
        fs::read(&config.readiness_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .is_some_and(|record| record["pid"] == child.id().unwrap())
    })
    .await;
    child
}

struct Three {
    root: PathBuf,
    roots: [PathBuf; 3],
    ids: [String; 3],
    _cleanup: Vec<NatsCleanup>,
    _runs: Vec<crate::controlled_runs::Backend>,
    proxies: Vec<tokio::process::Child>,
}

impl Three {
    async fn new() -> Self {
        let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
        let root = tempfile::Builder::new()
            .prefix("coord-reliability-")
            .tempdir()
            .unwrap()
            .keep();
        println!("three independent native roots: {}", root.display());
        let roots = [root.join("a"), root.join("b"), root.join("c")];
        let mut cleanup = Vec::new();
        for path in &roots {
            fs::create_dir(path).unwrap();
            host(path, &["init"]).await;
            fs::write(path.join("config.toml"),"admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n[[listeners]]\nagent_id='carol'\nsocket_path='carol.sock'\n").unwrap();
            fs::write(path.join("policy.toml"),format!("[controls.network]\nenabled=false\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n[agents.carol]\nagent_id='{CAROL}'\n")).unwrap();
            host(path, &["coord", "start", "--binary", &nats]).await;
            cleanup.push(NatsCleanup(path.clone()));
            host(path, &["coord", "room", "create", "shared"]).await;
            for name in ["alice", "bob", "carol"] {
                host(path, &["coord", "grant", "shared", name]).await;
            }
            host(
                path,
                &[
                    "coord",
                    "federation",
                    "credential",
                    path.join("federation-secret").to_str().unwrap(),
                ],
            )
            .await;
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            fs::write(path.join("peer.pem"), cert.cert.pem()).unwrap();
            fs::write(path.join("peer.key"), cert.signing_key.serialize_pem()).unwrap();
        }
        let ids = roots.each_ref().map(|root| support::instance(root));
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
        for (index, path) in roots.iter().enumerate() {
            host(path, &["coord", "stop"]).await;
            let mut peers = Vec::new();
            if index == 1 {
                for other in [0, 2] {
                    host(
                        path,
                        &[
                            "coord",
                            "federation",
                            "trust",
                            &ids[other],
                            roots[other].join("federation-secret").to_str().unwrap(),
                        ],
                    )
                    .await;
                    host(
                        path,
                        &[
                            "coord",
                            "federation",
                            "member",
                            "shared",
                            &ids[other],
                            BOB,
                            if other == 0 {
                                "remote-bob"
                            } else {
                                "other-bob"
                            },
                        ],
                    )
                    .await;
                    peers.push(json!({"instance_id":ids[other],"credential_file":roots[other].join("federation-secret")}));
                }
            }
            fs::write(path.join("coord-federation.json"),json!({"listen":"127.0.0.1","cert_file":path.join("peer.pem"),"key_file":path.join("peer.key"),"ca_file":path.join("peer.pem"),"local_server_name":"127.0.0.1","peers":peers}).to_string()).unwrap();
            let ready = host(path, &["coord", "start", "--binary", &nats]).await;
            if index == 1 {
                for other in [0, 2] {
                    host(
                        &roots[other],
                        &[
                            "coord",
                            "federation",
                            "home",
                            "primary",
                            &ids[1],
                            &format!("tls://127.0.0.1:{}", ready["client_port"]),
                            path.join("peer.pem").to_str().unwrap(),
                            roots[other].join("federation-secret").to_str().unwrap(),
                        ],
                    )
                    .await;
                }
            }
        }
        let runs = roots
            .iter()
            .map(|root| {
                crate::controlled_runs::agent_run(
                    root,
                    "bob",
                    BOB,
                    "0123456789abcdef0123456789abcdef",
                )
            })
            .collect();
        let mut proxies = Vec::new();
        for path in &roots {
            proxies.push(start(path).await);
        }
        let fixture = Self {
            root,
            roots,
            ids,
            _cleanup: cleanup,
            _runs: runs,
            proxies,
        };
        for source in [0, 2] {
            let remote = client(&fixture.roots[source], "bob", true);
            // Wait for the actual federation subscription, not just proxy readiness.
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    if remote
                        .call("get_room_state", &json!({"room_name":"shared"}))
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
        }
        fixture
    }

    async fn finish(mut self) {
        for proxy in self.proxies.drain(..) {
            stage0::crash(proxy).await;
        }
        self._cleanup.clear();
        for root in &self.roots {
            let binaries = root.join("data/coord/nats/bin");
            assert!(!root.join("data/coord/nats/process.json").exists());
            fs::remove_dir_all(binaries).unwrap();
        }
    }

    async fn owner(&self) -> async_nats::Client {
        let root = &self.roots[1];
        let record: Value =
            serde_json::from_slice(&fs::read(root.join("data/coord/nats/process.json")).unwrap())
                .unwrap();
        let secret = zeroize::Zeroizing::new(
            fs::read_to_string(root.join("data/coord/nats/federation-creds")).unwrap(),
        );
        async_nats::ConnectOptions::new()
            .require_tls(true)
            .add_root_certificates(root.join("peer.pem"))
            .user_and_password("safeyolo-federation".into(), secret.trim().into())
            .request_timeout(Some(Duration::from_secs(2)))
            .connect(format!("tls://127.0.0.1:{}", record["client_port"]))
            .await
            .unwrap()
    }

    async fn stream(&self, source: usize) -> async_nats::jetstream::stream::Stream {
        let js = async_nats::jetstream::new(self.owner().await);
        let name = format!("SY_FED_{}", support::hash(&self.ids[source]));
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Ok(stream) = js.get_stream(&name).await {
                    return stream;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }

    async fn diagnostic(&self, index: usize) -> Value {
        safeyolo_proxy::native_client::admin(
            &self.roots[index].join("config.toml"),
            "/admin/coord/diagnostics",
            Method::GET,
            Value::Null,
            Duration::from_secs(3),
        )
        .await
        .unwrap()
    }
}

async fn connection_total(root: &Path) -> u64 {
    let record: Value =
        serde_json::from_slice(&fs::read(root.join("data/coord/nats/process.json")).unwrap())
            .unwrap();
    let port = record["monitor_port"].as_u64().unwrap() as u16;
    let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    safeyolo_proxy::native_client::send_json(
        socket,
        &format!("127.0.0.1:{port}"),
        "/varz",
        "",
        Method::GET,
        Value::Null,
        Duration::from_secs(2),
    )
    .await
    .unwrap()["total_connections"]
        .as_u64()
        .unwrap()
}

fn wait(
    root: &Path,
    since: u64,
    seconds: f64,
) -> tokio::task::JoinHandle<Result<Value, safeyolo_proxy::Error>> {
    let client = client(root, "bob", true);
    tokio::spawn(async move {
        client
            .call(
                "wait_for_attention",
                &json!({"since_sequence":since,"timeout_seconds":seconds,"limit":100}),
            )
            .await
    })
}

async fn consumers(stream: &mut async_nats::jetstream::stream::Stream, wanted: usize) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if stream.info().await.unwrap().state.consumer_count == wanted {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("wait consumers did not reach the expected count");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; three independent instance roots and brokers"]
async fn failed_peer_publication_does_not_hold_local_or_other_peer_hints() {
    let mut f = Three::new().await;
    let stalled = wait(&f.roots[0], 0, 30.0);
    let healthy = wait(&f.roots[2], 0, 30.0);
    let (mut a_stream, mut c_stream) = (f.stream(0).await, f.stream(2).await);
    consumers(&mut a_stream, 1).await;
    consumers(&mut c_stream, 1).await;
    let js = async_nats::jetstream::new(f.owner().await);
    let mut config = a_stream.info().await.unwrap().config.clone();
    config.sealed = true;
    js.update_stream(config).await.unwrap();
    let local = local_nats(&f.roots[1]).await;
    let mut hints = local
        .subscribe(format!("coord.attention.{CAROL}"))
        .await
        .unwrap();
    local.flush().await.unwrap();
    let alice = client(&f.roots[1], "alice", false);
    alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"failed peer first","notify":["remote-bob"]}),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let began = std::time::Instant::now();
    alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"healthy local","notify":["carol"]}),
        )
        .await
        .unwrap();
    alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"healthy peer","notify":["other-bob"]}),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), hints.next())
        .await
        .expect("healthy local hint stalled behind failed federation publication")
        .unwrap();
    let page = tokio::time::timeout(Duration::from_secs(5), healthy)
        .await
        .expect("other peer hint stalled")
        .unwrap()
        .unwrap();
    assert_eq!(page["edges"].as_array().unwrap().len(), 1);
    assert!(began.elapsed() < Duration::from_secs(5));
    println!(
        "healthy local and other peer progressed in {:.3}s",
        began.elapsed().as_secs_f64()
    );
    stalled.abort();
    let _ = stalled.await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let db = rusqlite::Connection::open(f.roots[1].join("data/coord/v0.db")).unwrap();
    let failed:i64=db.query_row("SELECT max(attempt_count) FROM coord_outbox WHERE destination='federation-nats' AND delivered_at IS NULL",[],|row|row.get(0)).unwrap();
    assert!((1..=4).contains(&failed), "retry hot loop: {failed}");
    assert_eq!(
        count(
            &f.roots[1],
            "SELECT count(*) FROM coord_outbox WHERE destination='attention-nats' AND attempt_count>1"
        ),
        0,
        "remote retry duplicated the local hint"
    );
    // Removing the failed hint stream is a test fault reset. Canonical attention survives.
    js.delete_stream(a_stream.cached_info().config.name.clone())
        .await
        .unwrap();
    stage0::crash(f.proxies.remove(0)).await;
    alice
        .call(
            "send",
            &json!({"room_name":"shared","body":"disconnected recipient","notify":["remote-bob"]}),
        )
        .await
        .unwrap();
    stage0::until(|| count(&f.roots[1],"SELECT count(*) FROM coord_outbox WHERE destination='federation-nats' AND delivered_at IS NOT NULL")>=2).await;
    assert!(
        f.diagnostic(1).await["outbox"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["destination"] == "federation-nats")
    );
    println!("disconnected recipient did not prevent owner publication; retry attempts={failed}");
    f.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; three independent instance roots and brokers"]
async fn repeated_calls_reuse_connections_and_waits_release_consumers() {
    let f = Three::new().await;
    let before = connection_total(&f.roots[1]).await;
    let bob = client(&f.roots[0], "bob", true);
    for _ in 0..20 {
        bob.call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .unwrap();
    }
    let after = connection_total(&f.roots[1]).await;
    let delta = after - before;
    println!("twenty repeated calls opened {delta} connections");
    assert!(delta <= 1, "repeated RPC opened new TLS connections");
    bob.call(
        "wait_for_attention",
        &json!({"since_sequence":0,"timeout_seconds":0.05}),
    )
    .await
    .unwrap();
    let mut stream = f.stream(0).await;
    let mut config = stream.info().await.unwrap().config.clone();
    config.max_consumers = -1;
    async_nats::jetstream::new(f.owner().await)
        .update_stream(config)
        .await
        .unwrap();
    for _ in 0..6 {
        bob.call(
            "wait_for_attention",
            &json!({"since_sequence":0,"timeout_seconds":0.05}),
        )
        .await
        .unwrap();
    }
    assert_eq!(stream.info().await.unwrap().config.max_consumers, 64);
    consumers(&mut stream, 0).await;
    let mut waits = Vec::new();
    for index in 0..32 {
        waits.push(wait(&f.roots[0], 0, 30.0));
        consumers(&mut stream, index + 1).await;
    }
    consumers(&mut stream, 32).await;
    let rejected = bob
        .request(
            Method::GET,
            "/api/coord/attention/wait?since=0&limit=1&timeout=30",
            Value::Null,
            Duration::from_secs(3),
        )
        .await
        .unwrap_err();
    assert!(rejected.to_string().contains("429"), "{rejected}");
    let began = std::time::Instant::now();
    bob.call("create_work",&json!({"room_name":"shared","title":"command during long waits","operation_id":"fair-command"})).await.unwrap();
    bob.call(
        "wait_for_attention",
        &json!({"since_sequence":0,"timeout_seconds":0.05}),
    )
    .await
    .unwrap();
    client(&f.roots[2], "bob", true)
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"timeout_seconds":0.05}),
        )
        .await
        .unwrap();
    assert!(began.elapsed() < Duration::from_secs(3));
    for wait in waits {
        wait.abort();
        let _ = wait.await;
    }
    consumers(&mut stream, 0).await;
    let stats = f.diagnostic(0).await;
    assert_eq!(stats["federation"]["connection_count"], 1);
    assert_eq!(stats["federation"]["active_waits"], 0);
    assert!(stats["federation"]["rejected_admission"].as_u64().unwrap() >= 1);
    assert_eq!(
        count(
            &f.roots[1],
            "SELECT count(*) FROM coord_operations WHERE operation_id='fair-command'"
        ),
        1
    );
    println!(
        "32 long waits, commands, other-peer short wait and cancellations: {:.3}s; consumers=0",
        began.elapsed().as_secs_f64()
    );
    let mut room = owned_stream(&f.roots[1]).await;
    let mut messages = Vec::new();
    for index in 0..8 {
        let bob = bob.clone();
        messages.push(tokio::spawn(async move {
            bob.call(
                "wait_for_message",
                &json!({"room_name":"shared","since_sequence":10000,"timeout_seconds":30}),
            )
            .await
        }));
        consumers(&mut room, index + 1).await;
    }
    let refused = bob
        .call(
            "wait_for_message",
            &json!({"room_name":"shared","since_sequence":10000,"timeout_seconds":30}),
        )
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("429"), "{refused}");
    bob.call("create_work",&json!({"room_name":"shared","title":"command while message waits are full","operation_id":"message-wait-fair-command"})).await.unwrap();
    for message in messages {
        message.abort();
        let _ = message.await;
    }
    consumers(&mut room, 0).await;
    assert_eq!(f.diagnostic(1).await["federation"]["active_read_waits"], 0);
    println!(
        "eight owner-side message waits rejected excess admission, preserved commands and retired consumers after cancellation"
    );
    let credential = f.roots[0].join("federation-secret");
    let saved = zeroize::Zeroizing::new(fs::read(&credential).unwrap());
    fs::write(&credential, "deliberately-invalid-credential").unwrap();
    assert!(
        bob.call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    fs::write(&credential, &*saved).unwrap();
    bob.call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let ca = f.roots[1].join("peer.pem");
    let saved = fs::read(&ca).unwrap();
    fs::write(&ca, fs::read(f.roots[2].join("peer.pem")).unwrap()).unwrap();
    assert!(
        bob.call("get_room_state", &json!({"room_name":"shared"}))
            .await
            .is_err()
    );
    fs::write(&ca, saved).unwrap();
    bob.call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    let before = connection_total(&f.roots[1]).await;
    let ready: Value =
        serde_json::from_slice(&fs::read(f.roots[1].join("data/coord/nats/process.json")).unwrap())
            .unwrap();
    host(
        &f.roots[0],
        &[
            "coord",
            "federation",
            "home",
            "primary",
            &f.ids[1],
            &format!("tls://127.0.0.1:{}", ready["client_port"]),
            ca.to_str().unwrap(),
            credential.to_str().unwrap(),
        ],
    )
    .await;
    bob.call("get_room_state", &json!({"room_name":"shared"}))
        .await
        .unwrap();
    assert_eq!(
        connection_total(&f.roots[1]).await - before,
        1,
        "route revision did not invalidate reuse"
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "child helper for actual publisher exit immediately after JetStream acknowledgement"]
async fn accepted_publisher_exits_before_projection() {
    let Some(root) = std::env::var_os("SAFEYOLO_RELIABILITY_PUBLISH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let prepared: Value =
        serde_json::from_slice(&fs::read(root.join("accepted-publish.json")).unwrap()).unwrap();
    let connection = local_nats(&root).await;
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(
        "Nats-Msg-Id",
        prepared["envelope"]["msg_id"].as_str().unwrap(),
    );
    headers.insert("SafeYolo-Coord-Attention", prepared["manifest"].to_string());
    let ack = async_nats::jetstream::new(connection)
        .publish_with_headers(
            format!("rooms.{}", prepared["room_id"].as_str().unwrap()),
            headers,
            prepared["envelope"].to_string().into(),
        )
        .await
        .unwrap()
        .await
        .unwrap();
    println!("JetStream accepted sequence {}", ack.sequence);
    std::process::exit(73);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; three independent instance roots and brokers"]
async fn owner_repairs_after_publisher_exit_without_remote_polling() {
    let f = Three::new().await;
    let waiting = wait(&f.roots[2], 0, 30.0);
    let mut stream = f.stream(2).await;
    consumers(&mut stream, 1).await;
    let db = rusqlite::Connection::open(f.roots[1].join("data/coord/v0.db")).unwrap();
    let (room,principal,generation):(String,String,i64)=db.query_row("SELECT m.room_id,m.principal_id,m.granted_at FROM memberships m JOIN coord_federation_agents a ON a.principal_id=m.principal_id WHERE a.instance_id=?1 AND m.revoked_at IS NULL",[&f.ids[2]],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    let message = format!("msg-{}", uuid::Uuid::new_v4().simple());
    let attention = format!("attn-{}", uuid::Uuid::new_v4().simple());
    let prepared = json!({"room_id":room,"envelope":{"msg_id":message,"sent_at":1234,"sender_kind":"agent","sender_agent_id":ALICE,"sender_agent_name":"alice","origin_instance_id":f.ids[1],"content_type":"text/plain","body":"accepted before publisher exit"},"manifest":{"version":1,"msg_id":message,"mode":"agents","recipients":[{"attention_id":attention,"agent_id":principal,"membership_granted_at":generation}]}});
    fs::write(
        f.roots[1].join("accepted-publish.json"),
        prepared.to_string(),
    )
    .unwrap();
    db.execute_batch("CREATE TRIGGER hold_projection BEFORE INSERT ON coord_attention_edges WHEN NEW.kind='message' BEGIN SELECT RAISE(FAIL,'controlled projection interruption'); END;").unwrap();
    let status = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "federation::reliability::accepted_publisher_exits_before_projection",
            "--ignored",
            "--nocapture",
        ])
        .env("SAFEYOLO_RELIABILITY_PUBLISH_ROOT", &f.roots[1])
        .status()
        .await
        .unwrap();
    assert_eq!(status.code(), Some(73));
    assert_eq!(
        count(
            &f.roots[1],
            "SELECT count(*) FROM coord_attention_edges WHERE kind='message'"
        ),
        0
    );
    let began = std::time::Instant::now();
    db.execute_batch("DROP TRIGGER hold_projection").unwrap();
    let page = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("remote waited for its deadline instead of owner repair")
        .unwrap()
        .unwrap();
    assert_eq!(page["edges"][0]["attention_id"], attention);
    consumers(&mut stream, 0).await;
    println!(
        "owner projection repair woke remote in {:.3}s after publisher exit; remote deadline=30s",
        began.elapsed().as_secs_f64()
    );
    // A replacement consumer starts from the caller's own canonical source cursor.
    let resumed = client(&f.roots[0], "bob", true)
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    assert_eq!(resumed["next_cursor"], 0);
    assert_eq!(
        count(
            &f.roots[1],
            "SELECT count(*) FROM coord_attention_edges WHERE kind='message'"
        ),
        1
    );
    assert!(f.root.exists());
    f.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; selected observer health and current disclosure grants"]
async fn selected_sources_keep_independent_health_and_stop_disclosing_after_revoke() {
    let f = Three::new().await;
    let _target = crate::controlled_runs::agent_run(
        &f.roots[1],
        "alice",
        ALICE,
        "00112233445566778899aabbccddeeff",
    );
    let mut proposal = support::proposal(&f.ids[1], None);
    proposal["grant"]["notifications"] =
        json!(["launch_failed", "command_exit", "control_availability"]);
    let applied = support::apply(&f.roots[1], "health", proposal).await;
    stage0::until(|| count(&f.roots[1],"SELECT count(*) FROM coord_observation_health WHERE source='host_start' AND last_success_at IS NOT NULL")>0).await;
    // Hold the actual observer record lock through its next probe. The
    // asynchronous lock must honor the probe deadline and leave delivery live.
    use std::os::fd::AsRawFd;
    let blocked = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.roots[1].join("agents/alice/operational-observation.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(blocked.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    stage0::until(||count(&f.roots[1],"SELECT count(*) FROM coord_observation_health WHERE source='host_runtime' AND unavailable_reason='probe_timeout'")>0).await;
    let remote = wait(&f.roots[2], 0, 10.0);
    let mut notices = f.stream(2).await;
    consumers(&mut notices, 1).await;
    let local = local_nats(&f.roots[1]).await;
    let mut hints = local
        .subscribe(format!("coord.attention.{BOB}"))
        .await
        .unwrap();
    local.flush().await.unwrap();
    let began = std::time::Instant::now();
    let sent=client(&f.roots[1],"alice",false).call("send",&json!({"room_name":"shared","body":"delivery while an observer is blocked","notify":["bob","other-bob"]})).await.unwrap();
    let wanted:String=rusqlite::Connection::open(f.roots[1].join("data/coord/v0.db")).unwrap().query_row("SELECT attention_id FROM coord_attention_edges WHERE recipient_agent_id=?1 AND object_id=?2",rusqlite::params![BOB,sent["envelope"]["msg_id"].as_str().unwrap()],|row|row.get(0)).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let hint = hints.next().await.unwrap();
            let value: Value = serde_json::from_slice(&hint.payload).unwrap();
            if value["attention_id"] == wanted {
                break;
            }
        }
    })
    .await
    .unwrap();
    let page = tokio::time::timeout(Duration::from_secs(3), remote)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(page["edges"].as_array().unwrap().len(), 1);
    println!(
        "a timed-out observer lock left local and other-peer delivery live in {:.3}s",
        began.elapsed().as_secs_f64()
    );
    drop(blocked);
    let path = f.roots[1].join("agents/alice/last-start-failure.json");
    fs::create_dir(&path).unwrap();
    stage0::until(|| count(&f.roots[1],"SELECT count(*) FROM coord_observation_health WHERE source='host_start' AND unavailable_reason='source_unreadable'")>0).await;
    let second = f.roots[1].join("agents/alice/home/.safeyolo-command-supervisor.json");
    fs::create_dir_all(&second).unwrap();
    stage0::until(|| count(&f.roots[1],"SELECT count(*) FROM coord_observation_health WHERE source IN ('host_start','guest_command_supervisor') AND unavailable_reason='source_unreadable'")==2).await;
    let bob = client(&f.roots[1], "bob", false);
    let edges = bob
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"timeout_seconds":0,"limit":100}),
        )
        .await
        .unwrap();
    let mut health = Vec::new();
    for edge in edges["edges"].as_array().unwrap() {
        let object = bob
            .call(
                "read_attention",
                &json!({"attention_id":edge["attention_id"]}),
            )
            .await
            .unwrap();
        if object["object"]["reference"]["kind"] == "observation_health"
            && object["object"]["reference"]["state"]["reason"] == "source_unreadable"
        {
            assert!(object["object"]["evidence"]["current"]["last_success_at"].is_i64());
            health.push(edge["attention_id"].clone());
        }
    }
    assert_eq!(
        health.len(),
        2,
        "a second failed source was hidden by the first"
    );
    fs::remove_dir(&path).unwrap();
    stage0::until(|| count(&f.roots[1],"SELECT count(*) FROM coord_observation_health WHERE source='host_start' AND unavailable_reason IS NULL")>0).await;
    stage0::until(||count(&f.roots[1],"SELECT count(*) FROM coord_operational_references WHERE json_extract(reference_json,'$.kind')='observation_health' AND json_extract(reference_json,'$.source_id')='host_start' AND json_extract(reference_json,'$.state.availability')='available'")==1).await;
    let recovered = count(
        &f.roots[1],
        "SELECT count(*) FROM coord_operational_references WHERE json_extract(reference_json,'$.kind')='observation_health' AND json_extract(reference_json,'$.source_id')='host_start' AND json_extract(reference_json,'$.state.availability')='available'",
    );
    assert_eq!(recovered, 1);
    support::revoke(&f.roots[1], "health", applied["revision"].clone()).await;
    for attention in &health {
        assert!(
            bob.call("read_attention", &json!({"attention_id":attention}))
                .await
                .is_err()
        );
    }
    let retained = count(
        &f.roots[1],
        "SELECT count(*) FROM coord_operational_references",
    );
    fs::remove_dir(&second).unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        count(
            &f.roots[1],
            "SELECT count(*) FROM coord_operational_references"
        ),
        retained
    );
    let mut expiring = support::proposal(&f.ids[1], None);
    expiring["grant"]["notifications"] =
        json!(["launch_failed", "command_exit", "control_availability"]);
    expiring["grant"]["expires_at"] = json!(
        (time::OffsetDateTime::now_utc() + time::Duration::seconds(3))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    support::apply(&f.roots[1], "expiring-health", expiring).await;
    bob.call("read_attention", &json!({"attention_id":health[0]}))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        bob.call("read_attention", &json!({"attention_id":health[0]}))
            .await
            .is_err()
    );
    let diagnostics = f.diagnostic(1).await;
    assert!(diagnostics["observations"].as_array().unwrap().len() >= 5);
    println!(
        "two selected source failures remained independent; recovery delivered once; revoke blocked retained reads and new disclosure"
    );
    f.finish().await;
}
