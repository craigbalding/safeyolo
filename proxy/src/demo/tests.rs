use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn instance() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for name in ["data", "logs"] {
        fs::create_dir(root.path().join(name)).unwrap();
    }
    fs::write(
        root.path().join("data/admin_token"),
        "synthetic-demo-operator",
    )
    .unwrap();
    fs::write(root.path().join("config.toml"), "admin_port=0\nadmin_api_token_file='data/admin_token'\npolicy_file='policy.toml'\nreadiness_file='data/ready.json'\naudit_log_path='logs/audit.jsonl'\nflow_store_db_path='data/flows.sqlite3'\n").unwrap();
    fs::write(
        root.path().join("policy.toml"),
        "budget=100\n[hosts]\n'*'={egress='allow'}\n[controls.credentials]\nenabled=false\n",
    )
    .unwrap();
    root
}

async fn request(socket: &Path, url: &str) -> (u16, String, Value) {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {url} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                url.parse::<hyper::Uri>().unwrap().authority().unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let boundary = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = String::from_utf8(bytes[..boundary].into()).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = serde_json::from_slice(&bytes[boundary..]).unwrap();
    (status, head, body)
}

#[tokio::test]
async fn owned_json_requires_real_native_approval_and_cleanup_preserves_peer() {
    let root = instance();
    host_platform::in_instance(root.path().into(), async {
        let peer = root.path().join("peer");
        fs::create_dir(&peer).unwrap();
        let marker = peer.join("marker");
        fs::write(&marker, "independent peer").unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o640)).unwrap();
        let peer_agent = host_agents::configure(
            "peer",
            &[("folder".into(), peer.to_string_lossy().into_owned())],
            true,
        )
        .await
        .unwrap();
        let mut process = tokio::process::Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let peer_before: DocumentMut = fs::read_to_string(root.path().join("policy.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let mut demo = Demo::prepare(&Options::default()).await.unwrap();
        let socket = root.path().join("demo.sock");
        let mut source: DocumentMut = fs::read_to_string(root.path().join("config.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let mut listener = toml_edit::Table::new();
        listener["agent_id"] = value(&demo.agent.name);
        listener["socket_path"] = value(socket.to_string_lossy().as_ref());
        let mut listeners = toml_edit::ArrayOfTables::new();
        listeners.push(listener);
        source["listeners"] = Item::ArrayOfTables(listeners);
        fs::write(root.path().join("config.toml"), source.to_string()).unwrap();
        let mut proxy = crate::Proxy::start(
            crate::native_config::read(&root.path().join("config.toml")).unwrap(),
        )
        .await
        .unwrap();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let proxy_owner = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = proxy.wait_for_policy_check() => { proxy.reload_policy_if_changed().await.unwrap(); }
                    _ = &mut stopped => break,
                }
            }
            proxy.shutdown().await;
        });
        let fixture = Fixture::start(root.path(), "owned-marker".into())
            .await
            .unwrap();
        demo.fixture_permission(&fixture).await.unwrap();
        let blocked = request(&socket, &fixture.url()).await;
        assert_eq!(blocked.0, 428);
        assert!(fixture.delivered().unwrap().is_empty());
        let pending = operator_commands::pending(root.path(), Some(&demo.agent.name))
            .await
            .unwrap();
        assert_eq!(pending["approvals"][0]["target"], fixture.destination());
        let id = pending["approvals"][0]["request_id"].as_str().unwrap();
        let view = operator_commands::approval(root.path(), id, Some(&demo.agent.name))
            .await
            .unwrap();
        assert_eq!(view["action"]["agent_id"], demo.agent.id);
        assert_eq!(view["action"]["port"], fixture.port);
        let flow = operator_commands::flow(root.path(), id, Some(&demo.agent.name))
            .await
            .unwrap();
        assert_eq!(flow["status"], 428);
        assert!(
            operator_commands::resolve(root.path(), id, "approve", Some("peer"))
                .await
                .is_err()
        );
        assert!(fixture.delivered().unwrap().is_empty());
        let resolved =
            operator_commands::resolve(root.path(), id, "approve", Some(&demo.agent.name))
                .await
                .unwrap();
        assert_eq!(resolved["status"], "approved");
        let allowed = request(&socket, &fixture.url()).await;
        assert_eq!(allowed.0, 200);
        assert_eq!(allowed.2["marker"], fixture.marker);
        assert_eq!(fixture.delivered().unwrap().len(), 1);
        let record: Value =
            serde_json::from_str(fs::read_to_string(&fixture.record_path).unwrap().trim()).unwrap();
        assert_eq!(record["marker"], allowed.2["marker"]);
        symlink(&peer, demo.workspace.join("peer-link")).unwrap();
        demo.cleanup().await.unwrap();
        assert!(!demo.workspace.exists());
        assert!(process.try_wait().unwrap().is_none());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "independent peer");
        assert_eq!(marker.metadata().unwrap().mode() & 0o777, 0o640);
        let peer_after: DocumentMut = fs::read_to_string(root.path().join("policy.toml"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            peer_before["agents"][&peer_agent.name].to_string(),
            peer_after["agents"][&peer_agent.name].to_string()
        );
        assert!(
            host_agents::list()
                .unwrap()
                .iter()
                .all(|agent| agent.id != demo.agent.id)
        );
        process.kill().await.unwrap();
        process.wait().await.unwrap();
        fixture.stop().await.unwrap();
        stop.send(()).unwrap();
        proxy_owner.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn keep_stops_cleanup_at_owned_files_and_restores_reused_workspace() {
    let root = instance();
    host_platform::in_instance(root.path().into(), async {
        let prior = root.path().join("prior");
        fs::create_dir(&prior).unwrap();
        let original = host_agents::configure(
            "demo-authenticated",
            &[("folder".into(), prior.to_string_lossy().into_owned())],
            true,
        )
        .await
        .unwrap();
        let options = Options {
            agent: Some(original.name.clone()),
            keep: true,
            ..Options::default()
        };
        let demo = Demo::prepare(&options).await.unwrap();
        fs::write(demo.workspace.join("app.py"), "retained app source").unwrap();
        let home = root.path().join("agents/demo-authenticated/home");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("existing-auth-marker"), "unchanged").unwrap();
        demo.cleanup().await.unwrap();
        assert_eq!(
            host_agents::refresh(&original).unwrap().folder,
            original.folder
        );
        assert_eq!(
            fs::read_to_string(demo.workspace.join("app.py")).unwrap(),
            "retained app source"
        );
        assert_eq!(
            fs::read_to_string(home.join("existing-auth-marker")).unwrap(),
            "unchanged"
        );
    })
    .await;
}

#[tokio::test]
async fn replaced_workspace_is_preserved_and_fresh_demo_can_start() {
    let root = instance();
    host_platform::in_instance(root.path().into(), async {
        let demo = Demo::prepare(&Options::default()).await.unwrap();
        let retained = root.path().join("retained");
        fs::rename(&demo.workspace, &retained).unwrap();
        fs::create_dir(&demo.workspace).unwrap();
        fs::write(demo.workspace.join("operator-file"), "do not delete").unwrap();
        assert!(
            demo.cleanup()
                .await
                .unwrap_err()
                .to_string()
                .contains("workspace was replaced")
        );
        assert_eq!(
            fs::read_to_string(demo.workspace.join("operator-file")).unwrap(),
            "do not delete"
        );
        let fresh = Demo::prepare(&Options::default()).await.unwrap();
        assert_ne!(fresh.agent.id, demo.agent.id);
        fresh.cleanup().await.unwrap();
    })
    .await;
}

#[test]
fn credentials_are_metadata_only_and_require_the_existing_adoption() {
    let home = tempfile::tempdir().unwrap();
    assert!(!codex_auth(home.path()).unwrap());
    let directory = home.path().join(".codex");
    fs::create_dir(&directory).unwrap();
    let auth = directory.join("auth.json");
    // Deliberately not JSON: readiness must not open credential bytes.
    fs::write(&auth, "synthetic private fixture").unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        codex_auth(home.path())
            .unwrap_err()
            .to_string()
            .contains("not been explicitly adopted")
    );
    crate::guest_commands::write_json(
        &directory.join(".safeyolo-provenance.json"),
        &json!({"schema":"safeyolo.codex-provenance/v1", "state":"agent-local"}),
    )
    .unwrap();
    assert!(codex_auth(home.path()).unwrap());
    let private = home.path().join("private");
    fs::rename(&auth, &private).unwrap();
    symlink(&private, &auth).unwrap();
    assert!(codex_auth(home.path()).is_err());
    assert_eq!(
        fs::read_to_string(&private).unwrap(),
        "synthetic private fixture"
    );
}

#[test]
fn app_source_cannot_read_a_host_symlink() {
    let workspace = tempfile::tempdir().unwrap();
    let private = tempfile::NamedTempFile::new().unwrap();
    symlink(private.path(), workspace.path().join("app.py")).unwrap();
    assert!(app_code(workspace.path()).is_err());
    fs::remove_file(workspace.path().join("app.py")).unwrap();
    fs::write(workspace.path().join("app.py"), "real app source").unwrap();
    app_code(workspace.path()).unwrap();
}
