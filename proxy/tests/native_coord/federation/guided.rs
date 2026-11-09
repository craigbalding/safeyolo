//! Real CLI prompts and native owners; this is not installed GUI/guest proof.
use super::*;
use std::os::unix::fs::PermissionsExt;

struct HostCleanup(PathBuf);
impl Drop for HostCleanup {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .arg("stop")
            .stdout(Stdio::null())
            .status();
    }
}

async fn guide(root: &Path, args: &[&str], input: &str) -> std::process::Output {
    let mut command = super::super::host_command(root, args);
    let mut child = command.stdin(Stdio::piped()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}

fn success(output: &std::process::Output) -> String {
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(
        output.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

async fn configure_broker(
    owner: &Path,
    source: &Path,
    mode: &str,
    tls: &str,
    port: u16,
    handoff: &Path,
) -> String {
    let input = format!(
        "broker\n{}\nyes\n{mode}\n127.0.0.1\n{tls}{port}\n\nyes\n{}\n",
        source.display(),
        handoff.display()
    );
    success(&guide(owner, &["configure", "connection"], &input).await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; real guided CLI across independently initialized roots"]
async fn guided_connection_material_and_addressed_handoffs_use_existing_checks() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let (a, b, c) = (
        temp.path().join("a"),
        temp.path().join("b"),
        temp.path().join("c"),
    );
    for root in [&a, &b, &c] {
        initialize(root, &nats).await;
    }
    let (_a, _b, _c) = (
        NatsCleanup(a.clone()),
        NatsCleanup(b.clone()),
        NatsCleanup(c.clone()),
    );
    let ids: std::collections::BTreeSet<_> = [&a, &b, &c]
        .into_iter()
        .map(|root| support::instance(root))
        .collect();
    assert_eq!(ids.len(), 3);
    let export = temp.path().join("source.json");
    host_cli(&a, &["configure", "identity", export.to_str().unwrap()]).await;
    let identity: Value = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
    assert_eq!(identity["instance_id"], support::instance(&a));
    assert!(!fs::read_to_string(&export).unwrap().contains("PRIVATE KEY"));
    let record: Value =
        serde_json::from_slice(&fs::read(b.join("data/coord/nats/process.json")).unwrap()).unwrap();
    let port = record["client_port"].as_u64().unwrap() as u16;
    let handoff = temp.path().join("loopback-handoff");
    let output = configure_broker(&b, &a, "loopback", "", port, &handoff).await;
    assert!(!output.contains("TLS material:"));
    assert!(output.contains("Source route has not been installed"));
    let saved: Value =
        serde_json::from_slice(&fs::read(b.join("coord-federation.json")).unwrap()).unwrap();
    assert_eq!(saved["mode"], "loopback");
    assert!(saved.get("cert_file").is_none());
    let secret = fs::read_to_string(handoff.join("credential")).unwrap();
    assert!(!output.contains(&secret));
    assert_eq!(
        fs::metadata(handoff.join("credential"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let wrong = guide(
        &c,
        &["configure", "connection"],
        &format!("import\n{}\n", handoff.display()),
    )
    .await;
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("not addressed"));
    fs::create_dir(b.join("bin")).unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_safeyolo-proxy"),
        b.join("bin/safeyolo-proxy"),
    )
    .unwrap();
    let _host_cleanup = HostCleanup(b.clone());
    let activated = success(
        &guide(
            &b,
            &["configure", "connection"],
            &format!("activate\n{port}\n{}\nyes\n", record["monitor_port"]),
        )
        .await,
    );
    assert!(
        activated.contains("Configured settings active: true"),
        "{activated}"
    );
    let imported = success(
        &guide(
            &a,
            &["configure", "connection"],
            &format!("import\n{}\nprimary\nyes\n", handoff.display()),
        )
        .await,
    );
    assert!(imported.contains("Source route saved"));
    assert!(imported.contains("Broker authentication: \"authenticated\""));
    success(&host_cli(&b, &["stop"]).await);
    // Create dedicated material through the human path, then import the same
    // owner-held files and renew under that CA without credential rotation.
    let generated = temp.path().join("tls-handoff");
    let out = configure_broker(
        &c,
        &a,
        "tls",
        "127.0.0.1\n127.0.0.1\ngenerate\n3650\n365\n",
        port + 2,
        &generated,
    )
    .await;
    assert!(out.contains("Certificate valid from"));
    let original: Value =
        serde_json::from_slice(&fs::read(c.join("coord-federation.json")).unwrap()).unwrap();
    let imported = temp.path().join("tls-imported");
    let tls = format!(
        "127.0.0.1\n127.0.0.1\nimport\n{}\n{}\n{}\nno\n",
        original["cert_file"].as_str().unwrap(),
        original["key_file"].as_str().unwrap(),
        original["ca_file"].as_str().unwrap()
    );
    configure_broker(&c, &a, "tls", &tls, port + 2, &imported).await;
    let renewed = temp.path().join("tls-renewed");
    configure_broker(
        &c,
        &a,
        "tls",
        "127.0.0.1\n127.0.0.1\nrenew\n\n365\nno\n",
        port + 2,
        &renewed,
    )
    .await;
    let after: Value =
        serde_json::from_slice(&fs::read(c.join("coord-federation.json")).unwrap()).unwrap();
    assert_eq!(original["ca_file"], after["ca_file"]);
    assert_eq!(original["peers"], after["peers"]);
    assert_ne!(original["cert_file"], after["cert_file"]);
    let handoff_json = fs::read_to_string(renewed.join("connection.json")).unwrap();
    assert!(!handoff_json.contains("PRIVATE KEY"));
    // Incomplete source import has no route write. EOF never accepts a preview.
    let cancelled = guide(
        &a,
        &["configure", "connection"],
        &format!("import\n{}\nsecond\n", renewed.display()),
    )
    .await;
    assert!(!cancelled.status.success());
    let conn = rusqlite::Connection::open(a.join("data/coord/v0.db")).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM coord_federation_homes WHERE name='second'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; real guided policy previews and application"]
async fn guided_support_and_approval_selection_keep_distinct_authority() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("owner");
    initialize(&root, &nats).await;
    let _cleanup = NatsCleanup(root.clone());
    #[cfg(target_os = "linux")]
    let _support_run = super::super::controlled_runs::agent_run(
        &root,
        "bob",
        BOB,
        "0123456789abcdef0123456789abcdef",
    );
    let proxy = super::super::stage0::start_proxy(&root).await;
    let support_input = format!(
        "{}\nyes\nbob\nalice\nno\nnone\nstart_sandbox\nlaunch_failed, observation_health\n8h\nyes\n",
        root.display()
    );
    let output =
        success(&guide(&root, &["configure", "support", "incident"], &support_input).await);
    assert!(output.contains("Support grant saved"));
    assert!(!output.contains("Independent access after revocation: null"));
    let listing = host_json(&root, &["support", "grants", "--json"]).await;
    let grant = &listing["grants"][0]["grant"];
    assert_eq!(grant["guest_admin"], false);
    assert_eq!(grant["lifecycle"], json!(["start_sandbox"]));
    assert_eq!(
        grant["notifications"],
        json!(["launch_failed", "observation_health"])
    );
    assert!(grant["expires_at"].is_string());
    assert!(grant.get("factory_directions").is_none());
    #[cfg(target_os = "linux")]
    {
        let inspected = client(&root, "bob", false).call("support_operation", &json!({"operation_id":"guided-inspection","grant":"incident","target_id":ALICE,"expected_run":null,"operation":{"action":"inspect"}})).await.unwrap();
        assert_eq!(inspected["operation_id"], "guided-inspection");
    }
    let approval_input = format!(
        "{}\nyes\ncarol\nalice\nnetwork\nbuild.example.test\n443\nrequest\nno\nstanding\nrun\nyes\nyes\n",
        root.display()
    );
    success(
        &guide(
            &root,
            &["configure", "approvals", "builds"],
            &approval_input,
        )
        .await,
    );
    let delegations = host_json(&root, &["approvals", "delegations", "--json"]).await;
    assert_eq!(
        delegations["delegations"][0]["delegation"]["scopes"][0]["host"],
        "build.example.test"
    );
    assert!(delegations["delegations"][0]["delegation"]["expires_at"].is_null());
    let human = success(&host_cli(&root, &["support", "grants"]).await);
    assert!(human.contains("incident: active"));
    assert!(human.contains("Guest administration: false"));
    success(&guide(&root, &["configure", "revoke-support", "incident"], "yes\n").await);
    assert!(
        host_json(&root, &["support", "grants", "--json"]).await["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    success(&guide(&root, &["configure", "revoke-approvals", "builds"], "yes\n").await);
    assert!(
        host_json(&root, &["approvals", "delegations", "--json"]).await["delegations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    super::super::stage0::crash(proxy).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; concurrent real guided edit and exact factory binding"]
async fn guided_stale_preview_is_refused_and_factory_binding_is_not_inherited() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("owner");
    initialize(&root, &nats).await;
    let _cleanup = NatsCleanup(root.clone());
    fs::write(
        root.join("role.md"),
        "Keep the current assigned work and independent review.\n",
    )
    .unwrap();
    fs::write(
        root.join("factory.toml"),
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
"#,
    )
    .unwrap();
    coord_json(&root, &["room", "create", "shared"]).await;
    success(
        &host_cli(
            &root,
            &[
                "factory",
                "approve",
                root.join("factory.toml").to_str().unwrap(),
                "--yes",
            ],
        )
        .await,
    );
    let proxy = super::super::stage0::start_proxy(&root).await;
    let input = format!(
        "{}\nyes\nbob\nalice\nno\nnone\nnone\nnone\nDIRECTION\nstanding\n",
        root.display()
    );
    let mut child = super::super::host_command(&root, &["configure", "support", "directions"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    stdin.write_all(input.as_bytes()).await.unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !String::from_utf8_lossy(&output).contains("Apply this complete proposal") {
            let mut byte = [0];
            assert_eq!(
                stdout.read(&mut byte).await.unwrap(),
                1,
                "{}",
                String::from_utf8_lossy(&output)
            );
            output.push(byte[0]);
        }
    })
    .await
    .unwrap();
    // A separate explicit CLI creates the same name while the first operator
    // is looking at the old preview. No test mutates the proposal internals.
    let concurrent = format!(
        "{}\nyes\nbob\nalice\nno\nnone\nnone\nnone\nPAUSE\n8h\nyes\n",
        root.display()
    );
    success(&guide(&root, &["configure", "support", "directions"], &concurrent).await);
    stdin.write_all(b"yes\nyes\nyes\n").await.unwrap();
    drop(stdin);
    stdout.read_to_end(&mut output).await.unwrap();
    let result = child.wait_with_output().await.unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output),
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Apply not confirmed"));
    assert!(output.contains("Current saved authority"));
    let configured = host_json(&root, &["support", "grants", "--json"]).await;
    assert_eq!(
        configured["grants"][0]["grant"]["factory_directions"][0]["types"],
        json!(["DIRECTION"])
    );
    let old = configured["grants"][0]["grant"]["factory_directions"][0]["snapshot_id"].clone();
    fs::write(
        root.join("role.md"),
        "A different current approved contract.\n",
    )
    .unwrap();
    success(
        &host_cli(
            &root,
            &[
                "factory",
                "approve",
                root.join("factory.toml").to_str().unwrap(),
                "--yes",
            ],
        )
        .await,
    );
    let current = fs::read_to_string(root.join("factories/selected/approved")).unwrap();
    assert_ne!(old.as_str().unwrap(), current.trim());
    let unchanged = host_json(&root, &["support", "grants", "--json"]).await;
    assert_eq!(
        unchanged["grants"][0]["grant"]["factory_directions"][0]["snapshot_id"],
        old
    );
    super::super::stage0::crash(proxy).await;
}
