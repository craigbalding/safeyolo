//! Owned native traffic reaches the actual operator CLI with content disabled.

use super::*;
use safeyolo_proxy::{Config, Proxy, native_client, native_config};
use tokio::net::UnixStream;

const INSTANCE: &str = "sy-11111111111111111111111111111111";
const OTHER: &str = "sy-22222222222222222222222222222222";
const TOKEN: &str = "synthetic-observation-operator-token";

fn configure(root: &Path, instance: &str, extra: &str) -> Config {
    for dir in ["data", "logs", "services", "builtin-services"] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    fs::write(root.join("data/instance_id"), instance).unwrap();
    fs::write(root.join("data/admin_token"), TOKEN).unwrap();
    fs::write(root.join("policy.toml"), format!(
        "[hosts]\n'*'={{egress='allow'}}\n[agents.worker]\nagent_id='{WORKER_ID}'\n[controls.credentials]\nenabled=false\n[controls.circuits]\nenabled=false\n"
    )).unwrap();
    fs::write(root.join("config.toml"), format!(
        "admin_port=0\nflow_store_enabled=false\nlisteners=[{{agent_id='worker',socket_path='worker.sock'}}]\n{extra}"
    )).unwrap();
    native_config::read(&root.join("config.toml")).unwrap()
}

async fn stats(config: &Path) -> Value {
    native_client::admin(config, "/stats", hyper::Method::GET, Value::Null, LIMIT)
        .await
        .unwrap()
}

fn total(observations: &Value, metric: &str) -> u64 {
    observations["behaviour"]["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|series| series[metric].as_u64().unwrap())
        .sum()
}

#[tokio::test]
async fn observations_live_metadata_matches_stats_and_keeps_reload_restart_scope() {
    let root = tempfile::tempdir().unwrap();
    let mut config = configure(root.path(), INSTANCE, "");
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let before = success(root.path(), &["observations", "--json"]).await;
    assert_eq!(before["scope"], "current_runtime_aggregate");
    assert_eq!(before["source"]["instance_id"], INSTANCE);
    let ready: Value = serde_json::from_slice(&fs::read(&config.readiness_file).unwrap()).unwrap();
    assert_eq!(before["source"]["runtime_id"], ready["instance_id"]);
    assert_eq!(before["source"]["capture"]["state"], "not_running");
    assert_eq!(before["source"]["payload_layers"], json!([]));
    assert_eq!(before["source"]["wire_source_active"], false);
    assert_eq!(
        total(&before["observations"], "observation_chunks_total"),
        0
    );

    let (origin, address) = test_owned_endpoint::bind().await;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = timeout(LIMIT, origin.accept()).await.unwrap().unwrap();
        let head = http_head(&mut socket).await;
        assert!(head.starts_with("POST /metadata-only "));
        let mut body = [0; 3];
        socket.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"req");
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
            .await
            .unwrap();
    });
    let mut client = UnixStream::connect(root.path().join("worker.sock"))
        .await
        .unwrap();
    client.write_all(format!("POST http://{address}/metadata-only HTTP/1.1\r\nHost: {address}\r\nContent-Length: 3\r\nConnection: close\r\n\r\nreq").as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    assert!(reply.ends_with(b"body"));
    drop(client);
    peer.await.unwrap();
    let owner = timeout(LIMIT, async {
        loop {
            let owner = stats(&root.path().join("config.toml")).await;
            let lifetimes: u64 = owner["observations"]["behaviour"]["series"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["connection_lifetime_seconds"]["count"].as_u64().unwrap())
                .sum();
            if lifetimes >= 2 {
                break owner;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let view = success(root.path(), &["observations", "--json"]).await;
    assert_eq!(view["observations"], owner["observations"]);
    assert_eq!(
        view["observations"],
        stats(&root.path().join("config.toml")).await["observations"]
    );
    assert!(total(&view["observations"], "application_messages_total") > 0);
    assert!(total(&view["observations"], "observation_chunks_total") > 0);
    assert!(total(&view["observations"], "observation_bytes_total") > 0);
    assert!(
        view["observations"]["layers"]
            .as_object()
            .unwrap()
            .values()
            .all(|layer| layer["observation_payload_bytes_total"] == 0)
    );
    assert!(
        view["observations"]["sinks"]
            .as_object()
            .unwrap()
            .values()
            .all(|sink| sink["sink_bytes_total"] == 0)
    );
    assert!(!config.flow_store_db_path.exists());
    assert!(
        config
            .native_settings
            .as_ref()
            .unwrap()
            .packet_capture
            .file
            .is_none()
    );
    assert!(
        config
            .native_settings
            .as_ref()
            .unwrap()
            .packet_capture
            .tcp
            .is_none()
    );
    assert!(!config.native_settings.as_ref().unwrap().packet_capture.wss);
    let ordinary = cli(root.path(), &["observations"]).await;
    assert!(ordinary.status.success());
    let ordinary = String::from_utf8(ordinary.stdout).unwrap();
    for expected in [
        INSTANCE,
        "Scope: current runtime aggregates",
        "Canonical admission",
        "Sink capture",
        "observation_bus_dropped_total",
        "observation_chunk_bytes: count=",
        "connection_lifetime_seconds: count=",
        "cumulative finite buckets=[<=",
        "point=agent_uds",
        "Payload capture layers: []",
        "not_running",
    ] {
        assert!(
            ordinary.contains(expected),
            "missing {expected}: {ordinary}"
        );
    }
    let previous_runtime = view["source"]["runtime_id"].as_str().unwrap();
    let scoped = success(
        root.path(),
        &[
            "observations",
            "--instance",
            INSTANCE,
            "--runtime",
            previous_runtime,
            "--json",
        ],
    )
    .await;
    assert_eq!(scoped, view);

    // A reload changes configured limits but preserves the existing owner.
    let path = root.path().join("config.toml");
    let configured = fs::read_to_string(&path).unwrap() + "[observations]\nitems=0\n";
    fs::write(&path, configured).unwrap();
    config = native_config::read(&path).unwrap();
    proxy.reload(config.clone()).await.unwrap();
    let reloaded = success(root.path(), &["observations", "--json"]).await;
    assert_eq!(reloaded, view);
    proxy.shutdown().await;
    let unavailable = cli(root.path(), &["observations", "--json"]).await;
    assert!(!unavailable.status.success());
    assert!(unavailable.stdout.is_empty());

    let proxy = Proxy::start(config).await.unwrap();
    let restarted = success(root.path(), &["observations", "--json"]).await;
    assert_eq!(restarted["source"]["instance_id"], INSTANCE);
    assert_ne!(restarted["source"]["runtime_id"], previous_runtime);
    assert_eq!(restarted["source"]["queue_limits"]["items"], 0);
    assert_eq!(
        total(&restarted["observations"], "application_messages_total"),
        0
    );
    let historical = cli(
        root.path(),
        &["observations", "--runtime", previous_runtime, "--json"],
    )
    .await;
    assert!(!historical.status.success());
    assert!(historical.stdout.is_empty());
    assert!(String::from_utf8_lossy(&historical.stderr).contains("does not match --runtime"));
    proxy.shutdown().await;
}

#[tokio::test]
async fn observations_explicit_configs_and_wrong_readiness_do_not_cross_instances() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let proxy_a = Proxy::start(configure(a.path(), INSTANCE, ""))
        .await
        .unwrap();
    let proxy_b = Proxy::start(configure(b.path(), OTHER, "")).await.unwrap();
    let selected = b.path().join("selected-\u{1b}[31m.toml");
    fs::rename(b.path().join("config.toml"), &selected).unwrap();
    fs::write(b.path().join("config.toml"), "admin_port=1\n").unwrap();
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .env("SAFEYOLO_NATIVE_CONFIG_PATH", a.path().join("config.toml"))
        .env("SAFEYOLO_CONFIG_DIR", a.path())
        .arg("--config")
        .arg(&selected)
        .args(["observations", "--json"])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.contains(&0x1b));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"]["instance_id"], OTHER);
    assert_eq!(report["source"]["config"], json!(selected));
    let ordinary = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--config")
        .arg(&selected)
        .arg("observations")
        .output()
        .await
        .unwrap();
    assert!(ordinary.status.success());
    assert!(!ordinary.stdout.contains(&0x1b));
    assert_eq!(
        success(a.path(), &["observations", "--json"]).await["source"]["instance_id"],
        INSTANCE
    );
    let wrong_namespace = cli(a.path(), &["observations", "--instance", OTHER]).await;
    assert!(!wrong_namespace.status.success());
    // Both instances deliberately use the same fixture token. A stale port
    // therefore needs the selected durable identity check as well as auth.
    fs::copy(
        b.path().join("data/ready.json"),
        a.path().join("data/ready.json"),
    )
    .unwrap();
    let cross = cli(a.path(), &["observations", "--json"]).await;
    assert!(!cross.status.success());
    assert!(cross.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&cross.stderr).contains("does not match the selected installation")
    );
    proxy_a.shutdown().await;
    proxy_b.shutdown().await;
}

#[tokio::test]
async fn observations_loss_and_failed_capture_stay_distinct_from_healthy_zero() {
    let root = tempfile::tempdir().unwrap();
    let config = configure(
        root.path(),
        INSTANCE,
        "[observations]\nitems=0\nbytes=0\n[packet_capture]\nfile='missing-parent/capture.pcap'\n",
    );
    let proxy = Proxy::start(config).await.unwrap();
    let owner = timeout(LIMIT, async {
        loop {
            let owner = stats(&root.path().join("config.toml")).await;
            if owner["observations"]["sinks"]["file"]["sink_errors_total"]
                .as_u64()
                .unwrap()
                > 0
            {
                break owner;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        owner["observation_source"]["capture"]["outputs"]["file"],
        json!({"configured":true,"subscribed":false})
    );
    let mut client = UnixStream::connect(root.path().join("worker.sock"))
        .await
        .unwrap();
    // Malformed input cannot reach any external origin.
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: bad\r\nContent-Length: invalid\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    let report = success(root.path(), &["observations", "--json"]).await;
    assert!(
        report["observations"]["layers"]
            .as_object()
            .unwrap()
            .values()
            .any(|layer| layer["observation_bus_dropped_total"].as_u64().unwrap() > 0)
    );
    assert_eq!(
        total(&report["observations"], "observation_chunks_total"),
        0
    );
    assert!(!root.path().join("missing-parent/capture.pcap").exists());
    proxy.shutdown().await;
}

#[tokio::test]
async fn observations_missing_data_auth_and_interrupted_reply_fail_without_disclosure() {
    let root = tempfile::tempdir().unwrap();
    let config = configure(root.path(), INSTANCE, "");
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let original = stats(&root.path().join("config.toml")).await;
    fs::write(root.path().join("data/admin_token"), "wrong-token").unwrap();
    let auth = cli(root.path(), &["observations", "--json"]).await;
    assert!(!auth.status.success());
    assert!(auth.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&auth.stderr).contains("wrong-token"));
    proxy.shutdown().await;
    fs::write(root.path().join("data/admin_token"), TOKEN).unwrap();
    for (field, member) in [
        ("observations", None),
        ("observation_source", None),
        ("observations", Some("behaviour")),
        ("observations", Some("layers")),
        ("observation_source", Some("runtime_id")),
        ("observation_source", Some("capture")),
    ] {
        let mut broken = original.clone();
        if let Some(member) = member {
            broken[field].as_object_mut().unwrap().shift_remove(member);
        } else {
            broken.as_object_mut().unwrap().shift_remove(field);
        }
        fake_reply(root.path(), 200, &broken.to_string(), false).await;
    }
    fake_reply(
        root.path(),
        503,
        &json!({"error":format!("{TOKEN}\u{1b}[31mprivate-content")}).to_string(),
        false,
    )
    .await;
    fake_reply(root.path(), 200, &original.to_string(), true).await;
    fs::remove_file(root.path().join("data/instance_id")).unwrap();
    let missing = cli(root.path(), &["observations", "--json"]).await;
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("identity unavailable"));
    for option in ["--agent", "--file", "--filter"] {
        let unsupported = cli(root.path(), &["observations", option, "worker"]).await;
        assert!(!unsupported.status.success());
        assert!(unsupported.stdout.is_empty());
    }
}

async fn fake_reply(root: &Path, status: u16, body: &str, interrupted: bool) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    fs::write(
        root.join("data/ready.json"),
        json!({"admin_port":listener.local_addr().unwrap().port()}).to_string(),
    )
    .unwrap();
    let body = body.to_owned();
    let server = tokio::spawn(async move {
        let (mut socket, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let head = http_head(&mut socket).await;
        assert!(head.starts_with("GET /stats "));
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("authorization: bearer {TOKEN}"))
        );
        socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
        let bytes = if interrupted {
            &body.as_bytes()[..body.len() / 2]
        } else {
            body.as_bytes()
        };
        socket.write_all(bytes).await.unwrap();
    });
    let output = cli(root, &["observations", "--json"]).await;
    server.await.unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    for private in [TOKEN, "private-content", "\u{1b}"] {
        assert!(!diagnostic.contains(private), "{diagnostic}");
    }
}
