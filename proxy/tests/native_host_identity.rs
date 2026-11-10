//! Native installation discovery through the authenticated instance endpoint.

use std::{fs, net::TcpListener, os::unix::fs::symlink, process::Command, time::Duration};

use safeyolo_proxy::{Proxy, coord_rooms, native_config};
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
};

fn install_configuration() -> TempDir {
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let initialized = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .arg("init")
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    fs::create_dir(root.join("bin")).unwrap();
    symlink(env!("CARGO_BIN_EXE_safeyolo"), root.join("bin/safeyolo")).unwrap();
    let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let events_port = reservation.local_addr().unwrap().port();
    let source = fs::read_to_string(root.join("config.toml"))
        .unwrap()
        .replace("admin_port = 9090", "admin_port = 0");
    fs::write(
        root.join("config.toml"),
        format!("{source}\n[command_centre]\nenabled = true\nevents_port = {events_port}\n"),
    )
    .unwrap();
    directory
}

async fn identity(directory: &TempDir) -> Value {
    let root = directory.path();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.join("data/ready.json")).unwrap()).unwrap();
    let token = fs::read_to_string(root.join("data/admin_token")).unwrap();
    let mut stream =
        TcpStream::connect(("127.0.0.1", ready["admin_port"].as_u64().unwrap() as u16))
            .await
            .unwrap();
    stream.write_all(format!(
        "GET /admin/instance HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", token.trim()
    ).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 "));
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    serde_json::from_slice(&response[header_end..]).unwrap()
}

#[tokio::test]
async fn native_discovery_keeps_two_roots_separate_and_has_no_interpreter_fallback() {
    let a = install_configuration();
    let b = install_configuration();
    let proxy_a = Proxy::start(native_config::read(&a.path().join("config.toml")).unwrap())
        .await
        .unwrap();
    let proxy_b = Proxy::start(native_config::read(&b.path().join("config.toml")).unwrap())
        .await
        .unwrap();
    let id_a = identity(&a).await;
    let id_b = identity(&b).await;
    for (directory, value) in [(&a, &id_a), (&b, &id_b)] {
        assert_eq!(
            value["host_root"],
            directory.path().canonicalize().unwrap().to_str().unwrap()
        );
        assert_eq!(
            value["host_executable"],
            directory
                .path()
                .canonicalize()
                .unwrap()
                .join("bin/safeyolo")
                .to_str()
                .unwrap()
        );
        assert!(value.get("host_python").is_none());
    }
    assert_ne!(id_a["safeyolo_instance_id"], id_b["safeyolo_instance_id"]);

    fs::remove_file(a.path().join("bin/safeyolo")).unwrap();
    assert!(identity(&a).await["host_executable"].is_null());
    assert_eq!(identity(&b).await, id_b);
    fs::write(a.path().join("bin/safeyolo"), b"non-executable fixture").unwrap();
    assert!(identity(&a).await["host_executable"].is_null());
    fs::remove_file(a.path().join("bin/safeyolo")).unwrap();
    symlink(
        env!("CARGO_BIN_EXE_safeyolo"),
        a.path().join("bin/safeyolo"),
    )
    .unwrap();
    assert_eq!(identity(&a).await, id_a);
    proxy_a.shutdown().await;
    proxy_b.shutdown().await;
}

fn coord_fixture(directory: &TempDir, marker: &str) {
    let root = directory.path();
    let created = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .args(["agent", "create", "probe", "--workspace"])
        .arg(root)
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let principal = created["configuration"]["id"].as_str().unwrap();
    let mut document: toml_edit::DocumentMut = fs::read_to_string(root.join("config.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let mut listener = toml_edit::Table::new();
    listener["agent_id"] = toml_edit::value("probe");
    listener["socket_path"] = toml_edit::value(root.join("probe.sock").to_str().unwrap());
    let mut listeners = toml_edit::ArrayOfTables::new();
    listeners.push(listener);
    document["listeners"] = toml_edit::Item::ArrayOfTables(listeners);
    fs::write(root.join("config.toml"), document.to_string()).unwrap();
    coord_rooms::bootstrap(root).unwrap();
    let conn = rusqlite::Connection::open(root.join("data/coord/v0.db")).unwrap();
    conn.execute(
        "INSERT INTO rooms(room_id,name,created_at) VALUES ('rm-shared','shared',1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO memberships(room_id,principal_kind,principal_id,permissions,granted_at)
         VALUES ('rm-shared','agent',?1,'receive',1)",
        [principal],
    )
    .unwrap();
    let brief = Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(root)
        .args([
            "coord",
            "brief",
            "set",
            "shared",
            marker,
            "--expected-revision",
            "0",
        ])
        .output()
        .unwrap();
    assert!(
        brief.status.success(),
        "{}",
        String::from_utf8_lossy(&brief.stderr)
    );
}

async fn coord_brief(directory: &TempDir, token: &str) -> (u16, Value) {
    let mut socket = UnixStream::connect(directory.path().join("probe.sock"))
        .await
        .unwrap();
    socket.write_all(format!(
        "GET http://_safeyolo.proxy.internal/api/coord/rooms/shared/brief HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let status = std::str::from_utf8(&response[..header_end])
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (
        status,
        serde_json::from_slice(&response[header_end..]).unwrap(),
    )
}

#[tokio::test]
async fn native_coord_reads_only_the_connected_instances_store_and_token() {
    let a = install_configuration();
    let b = install_configuration();
    coord_fixture(&a, "instance A");
    coord_fixture(&b, "instance B");
    let proxy_a = Proxy::start(native_config::read(&a.path().join("config.toml")).unwrap())
        .await
        .unwrap();
    let proxy_b = Proxy::start(native_config::read(&b.path().join("config.toml")).unwrap())
        .await
        .unwrap();
    let token_a = fs::read_to_string(a.path().join("data/agent_token")).unwrap();
    let token_b = fs::read_to_string(b.path().join("data/agent_token")).unwrap();
    let brief_a = coord_brief(&a, token_a.trim()).await;
    let brief_b = coord_brief(&b, token_b.trim()).await;
    assert_eq!(brief_a.0, 200, "{}", brief_a.1);
    assert_eq!(brief_b.0, 200, "{}", brief_b.1);
    assert_eq!(brief_a.1["markdown"], "instance A");
    assert_eq!(brief_b.1["markdown"], "instance B");
    assert_eq!(coord_brief(&b, token_a.trim()).await.0, 401);
    proxy_a.shutdown().await;
    assert_eq!(coord_brief(&b, token_b.trim()).await, brief_b);
    proxy_b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_centre_handoffs_export_three_pinned_owners_without_printing_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let roots = [
        install_configuration(),
        install_configuration(),
        install_configuration(),
    ];
    let mut proxies = Vec::new();
    let mut identities = std::collections::BTreeSet::new();
    for directory in &roots {
        proxies.push(
            Proxy::start(native_config::read(&directory.path().join("config.toml")).unwrap())
                .await
                .unwrap(),
        );
        let destination = directory.path().join("operator-connection.json");
        let run = || {
            tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
                .arg("--root")
                .arg(directory.path())
                .args(["configure", "command-centre"])
                .arg(&destination)
                .output()
        };
        let output = run().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&destination).unwrap();
        let profile: Value = serde_json::from_slice(&bytes).unwrap();
        let owner = identity(directory).await;
        assert_eq!(profile["instance_id"], owner["safeyolo_instance_id"]);
        assert_eq!(profile["owner_root"], owner["host_root"]);
        assert_eq!(profile["schema"], "safeyolo.command-centre-connection/v1");
        assert_eq!(profile["transport"], "loopback");
        assert_eq!(
            profile["token"],
            fs::read_to_string(directory.path().join("data/admin_token"))
                .unwrap()
                .trim()
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(profile["token"].as_str().unwrap())
        );
        assert!(
            profile["admin_url"]
                .as_str()
                .unwrap()
                .starts_with("http://127.0.0.1:")
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !run().await.unwrap().status.success(),
            "Existing private handoffs must not be overwritten"
        );
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        identities.insert(profile["instance_id"].as_str().unwrap().to_owned());
    }
    assert_eq!(identities.len(), 3);
    // Point the first root at another owner's authenticated endpoint. Its local
    // durable identity still has to match before any credential can be exported.
    let target = &roots[1];
    let source = &roots[0];
    let ready: Value =
        serde_json::from_slice(&fs::read(target.path().join("data/ready.json")).unwrap()).unwrap();
    let config_path = source.path().join("config.toml");
    let config = fs::read_to_string(&config_path).unwrap().replace(
        "admin_port = 0",
        &format!("admin_port = {}", ready["admin_port"]),
    );
    fs::write(&config_path, config).unwrap();
    fs::copy(
        target.path().join("data/admin_token"),
        source.path().join("data/admin_token"),
    )
    .unwrap();
    let refused_file = source.path().join("wrong-owner.json");
    let refused = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(source.path())
        .args(["configure", "command-centre"])
        .arg(&refused_file)
        .output()
        .await
        .unwrap();
    assert!(!refused.status.success() && !refused_file.exists());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("differs from this root"));
    for proxy in proxies {
        proxy.shutdown().await;
    }
}
