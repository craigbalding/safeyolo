//! Installed previous generated configuration -> current private NATS account.
use super::*;
use futures_util::StreamExt;

fn canonical_rows(root: &Path) -> Value {
    let db = rusqlite::Connection::open(root.join("data/coord/v0.db")).unwrap();
    assert!(
        !db.prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap()
    );
    let mut tables = serde_json::Map::new();
    for table in [
        "rooms",
        "coord_work",
        "coord_work_revisions",
        "coord_operations",
        "coord_attention_feeds",
        "coord_attention_edges",
        "coord_message_attention_projection",
    ] {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        let rows: Vec<Vec<String>> = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| {
                        row.get::<_, rusqlite::types::Value>(column)
                            .map(|value| format!("{value:?}"))
                    })
                    .collect()
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        tables.insert(table.into(), json!(rows));
    }
    Value::Object(tables)
}

async fn nats(root: &Path, port: &Value, federation: bool, owner: bool) -> async_nats::Client {
    let name = if owner {
        "safeyolo-federation"
    } else {
        "safeyolo"
    };
    let file = if owner { "federation-creds" } else { "creds" };
    let credential = zeroize::Zeroizing::new(
        fs::read_to_string(root.join("data/coord/nats").join(file)).unwrap(),
    );
    let mut options = async_nats::ConnectOptions::new()
        .user_and_password(name.into(), credential.trim().into())
        .request_timeout(Some(Duration::from_secs(2)));
    if federation {
        options = options
            .require_tls(true)
            .add_root_certificates(root.join("peer.pem"));
    }
    options.connect(format!("127.0.0.1:{port}")).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned NATS and SAFEYOLO_COORD_BASE_BINARY from e138ebefba90919311e9e60cc272b140e78b5d61"]
async fn previous_generated_store_upgrades_with_and_without_federation() {
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let retained = tempfile::Builder::new()
        .prefix("coord-upgrade-")
        .tempdir()
        .unwrap()
        .keep();
    println!("installed upgrade roots: {}", retained.display());
    for federation in [false, true] {
        let root = retained.join(if federation { "enabled" } else { "disabled" });
        fs::create_dir(&root).unwrap();
        stage0::base(&root, &["init"]).await;
        fs::write(root.join("config.toml"), "admin_port=0\nflow_store_enabled=false\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n").unwrap();
        fs::write(root.join("policy.toml"), "[controls.network]\nenabled=false\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n").unwrap();
        let first = stage0::base(&root, &["coord", "start", "--binary", &binary]).await;
        let _cleanup = NatsCleanup(root.clone());
        let room = stage0::base(&root, &["coord", "room", "create", "shared"]).await;
        stage0::base(&root, &["coord", "grant", "shared", "alice"]).await;
        for body in ["first retained message", "second retained message"] {
            stage0::base(&root, &["coord", "send", "shared", body, "--to", "alice"]).await;
        }
        let created = stage0::base(
            &root,
            &[
                "coord",
                "work",
                "create",
                "shared",
                "retained work",
                "--operation-id",
                "upgrade-work",
            ],
        )
        .await;
        let work = &created["work"];
        assert!(work["work_id"].is_string(), "{created}");
        stage0::base(
            &root,
            &[
                "coord",
                "work",
                "reassign",
                "shared",
                work["work_id"].as_str().unwrap(),
                "--agent-id",
                "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--expected-version",
                "1",
                "--expected-generation",
                "0",
                "--operation-id",
                "upgrade-claim",
            ],
        )
        .await;
        let stream_name = format!("ROOM_{}", room["room_id"].as_str().unwrap());
        let connection = nats(&root, &first["client_port"], false, false).await;
        let js = async_nats::jetstream::new(connection);
        let stream = js.get_stream(&stream_name).await.unwrap();
        let consumer: async_nats::jetstream::consumer::PullConsumer = stream
            .create_consumer(async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("upgrade-reader".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut messages = consumer.fetch().max_messages(1).messages().await.unwrap();
        messages
            .next()
            .await
            .unwrap()
            .unwrap()
            .double_ack()
            .await
            .unwrap();
        drop(messages);
        stage0::base(&root, &["coord", "stop"]).await;
        assert!(
            root.join("data/coord/nats/jetstream/jetstream/$G/streams")
                .is_dir()
        );
        let before = canonical_rows(&root);
        assert!(
            !before["coord_attention_edges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let credentials = fs::read(root.join("data/coord/nats/creds")).unwrap();
        if federation {
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            fs::write(root.join("peer.pem"), cert.cert.pem()).unwrap();
            fs::write(root.join("peer.key"), cert.signing_key.serialize_pem()).unwrap();
            fs::write(root.join("peer-secret"), "test-peer-host-held-secret").unwrap();
            fs::write(root.join("coord-federation.json"), json!({"listen":"127.0.0.1", "cert_file":"peer.pem", "key_file":"peer.key", "ca_file":"peer.pem", "local_server_name":"127.0.0.1", "peers":[{"instance_id":"sy-upgrade-peer", "credential_file":"peer-secret"}]}).to_string()).unwrap();
        }
        // Fail activation after the account move, without another broker
        // acquiring this store. Repeating start must resume, not initialise it.
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port().to_string();
        let failed = host_cli(
            &root,
            &[
                "coord",
                "start",
                "--binary",
                &binary,
                "--client-port",
                &port,
            ],
        )
        .await;
        assert!(!failed.status.success());
        assert!(
            root.join("data/coord/nats/jetstream/jetstream/SY_LOCAL/streams")
                .is_dir()
        );
        assert!(!root.join("data/coord/nats/jetstream/jetstream/$G").exists());
        assert_eq!(canonical_rows(&root), before);
        drop(occupied);
        let output = host_cli(&root, &["coord", "start", "--binary", &binary]).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let ready: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            fs::read(root.join("data/coord/nats/creds")).unwrap(),
            credentials
        );
        assert_eq!(canonical_rows(&root), before);
        let js =
            async_nats::jetstream::new(nats(&root, &ready["client_port"], federation, false).await);
        let stream = js.get_stream(&stream_name).await.unwrap();
        let mut consumer: async_nats::jetstream::consumer::PullConsumer =
            stream.get_consumer("upgrade-reader").await.unwrap();
        assert_eq!(consumer.info().await.unwrap().ack_floor.stream_sequence, 1);
        let mut messages = consumer.fetch().max_messages(1).messages().await.unwrap();
        let second = tokio::time::timeout(Duration::from_secs(3), messages.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(second.info().unwrap().stream_sequence, 2);
        second.double_ack().await.unwrap();
        drop(messages);
        if federation {
            let peer =
                async_nats::jetstream::new(nats(&root, &ready["client_port"], true, true).await);
            assert!(
                peer.get_stream(&stream_name).await.is_err(),
                "private rooms crossed into SY_FED"
            );
        }
        let proxy = stage0::start_proxy(&root).await;
        let alice = Client {
            socket: Some(root.join("alice.sock")),
            token_file: root.join("data/agent_token"),
            home: None,
        };
        let history = alice
            .call(
                "read_room",
                &json!({"room_name":"shared", "since_sequence":0}),
            )
            .await
            .unwrap();
        assert_eq!(history["messages"].as_array().unwrap().len(), 2);
        assert_eq!(history["messages"][0]["body"], "first retained message");
        assert_eq!(history["messages"][1]["body"], "second retained message");
        let cursor = history["next_cursor"].as_u64().unwrap();
        let read = alice
            .call(
                "read_work",
                &json!({"room_name":"shared", "work_id":work["work_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(read["title"], "retained work");
        assert_eq!(
            read["claim_agent_id"],
            "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let attention = alice
            .call(
                "wait_for_attention",
                &json!({"since_sequence":0, "timeout_seconds":0, "limit":100}),
            )
            .await
            .unwrap();
        let edges = attention["edges"].as_array().unwrap();
        assert!(!edges.is_empty());
        for edge in edges {
            alice
                .call(
                    "read_attention",
                    &json!({"attention_id":edge["attention_id"]}),
                )
                .await
                .unwrap();
        }
        let after_attention = alice
            .call(
                "wait_for_attention",
                &json!({"since_sequence":attention["next_cursor"], "timeout_seconds":0}),
            )
            .await
            .unwrap();
        assert_eq!(after_attention["edges"], json!([]));
        alice
            .call(
                "send",
                &json!({"room_name":"shared", "body":"after upgrade", "notify":["alice"]}),
            )
            .await
            .unwrap();
        let continued = alice
            .call(
                "read_room",
                &json!({"room_name":"shared", "since_sequence":cursor}),
            )
            .await
            .unwrap();
        assert_eq!(continued["messages"].as_array().unwrap().len(), 1);
        assert_eq!(continued["messages"][0]["body"], "after upgrade");
        assert!(continued["next_cursor"].as_u64().unwrap() > cursor);
        stage0::crash(proxy).await;
        coord_rooms::stop(&root).await.unwrap();
        println!(
            "federation={federation}: installed previous producer, retained SQL/message/work/attention and consumer cursors, failed activation/recovery, current read/write passed"
        );
    }
}
