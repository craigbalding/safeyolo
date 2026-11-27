//! Source-built foreground operator workflow, using real signals and curl.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            unsafe {
                libc::kill(self.0.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(15);
            while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if self.0.try_wait().unwrap().is_none() {
                self.0.kill().unwrap();
            }
            self.0.wait().unwrap();
        }
    }
}
fn write_config(root: &Path, reload: &str, listen: Option<&str>) {
    let mut source = format!(
        r#"admin_port=0
flow_store_enabled=false
circuit_state_file=''
reload_id='{reload}'
[[listeners]]
agent_id='mobile'
socket_path='mobile.sock'
"#
    );
    if let Some(listen) = listen {
        source.push_str(&format!(
            r#"
[[ingress_bindings]]
name='mobile-test'
listen='{listen}'
agent='mobile'
"#
        ));
    }
    fs::write(root.join("config.toml"), source).unwrap();
}
fn ready(root: &Path, process: &mut Process, reload: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(bytes) = fs::read(root.join("data/ready.json"))
            && let Ok(marker) = serde_json::from_slice::<Value>(&bytes)
            && marker["reload_id"] == reload
        {
            return marker;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "proxy exited: {}",
            fs::read_to_string(root.join("proxy.log")).unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "proxy readiness timed out: {}",
            fs::read_to_string(root.join("proxy.log")).unwrap()
        );
        thread::sleep(Duration::from_millis(20));
    }
}
fn health(address: &str) -> Value {
    let output = Command::new("curl")
        .args(["--silent", "--show-error", "--max-time", "3", "--proxy"])
        .arg(format!("http://{address}"))
        .args([
            "--header",
            "Authorization: Bearer owned-foreground-token",
            "http://_safeyolo.proxy.internal/health",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn named_foreground_binding_reloads_stops_and_restarts_on_the_same_address() {
    check_foreground_binding_reload(false);
}

#[test]
fn named_foreground_binding_reloads_stops_and_restarts_through_a_directory_alias() {
    check_foreground_binding_reload(true);
}

fn check_foreground_binding_reload(through_alias: bool) {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let config_path = if through_alias {
        let alias = root.join("config-alias");
        std::os::unix::fs::symlink(root, &alias).unwrap();
        alias.join("config.toml")
    } else {
        root.join("config.toml")
    };
    for path in ["data", "logs", "services", "builtin-services"] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    fs::write(
        root.join("data/instance_id"),
        "sy-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    fs::write(
        root.join("data/admin_token"),
        "owned-foreground-admin-token",
    )
    .unwrap();
    fs::write(root.join("data/agent_token"), "owned-foreground-token").unwrap();
    fs::write(root.join("policy.toml"), "[hosts.'*']\negress='deny'\n").unwrap();
    write_config(root, "initial", Some("127.0.0.1:0"));
    let log = fs::File::create(root.join("proxy.log")).unwrap();
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
            .env(safeyolo_proxy::host_root::ENVIRONMENT, "1")
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let initial = ready(root, &mut process, "initial");
    let socket = fs::metadata(root.join("mobile.sock")).unwrap();
    let socket_identity = (socket.dev(), socket.ino());
    assert_eq!(initial["ingress_bindings"][0]["name"], "mobile-test");
    assert_eq!(initial["ingress_bindings"][0]["agent"], "mobile");
    let address = initial["ingress_bindings"][0]["address"].as_str().unwrap();
    assert_eq!(health(address)["agent_api"], "ok");
    write_config(root, "removed", None);
    assert_eq!(
        unsafe { libc::kill(process.0.id() as i32, libc::SIGHUP) },
        0
    );
    assert_eq!(
        ready(root, &mut process, "removed")["ingress_bindings"],
        json!([])
    );
    assert!(std::net::TcpStream::connect(address).is_err());
    let socket = fs::metadata(root.join("mobile.sock")).unwrap();
    assert_eq!((socket.dev(), socket.ino()), socket_identity);
    assert!(std::os::unix::net::UnixStream::connect(root.join("mobile.sock")).is_ok());
    write_config(root, "restarted", Some(address));
    assert_eq!(
        unsafe { libc::kill(process.0.id() as i32, libc::SIGHUP) },
        0
    );
    assert_eq!(
        ready(root, &mut process, "restarted")["ingress_bindings"][0]["address"],
        address
    );
    assert_eq!(health(address)["agent_api"], "ok");
    let socket = fs::metadata(root.join("mobile.sock")).unwrap();
    assert_eq!((socket.dev(), socket.ino()), socket_identity);
    assert_eq!(
        unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "proxy shutdown timed out");
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!root.join("data/ready.json").exists());
    assert!(!root.join("mobile.sock").exists());
    assert!(std::net::TcpListener::bind(address).is_ok());
}
