//! Native installation discovery through the authenticated instance endpoint.

use std::{fs, net::TcpListener, os::unix::fs::symlink, process::Command, time::Duration};

use safeyolo_proxy::{Proxy, native_config};
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
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
