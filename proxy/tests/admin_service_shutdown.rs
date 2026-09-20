//! Process-level lifecycle witness for an authenticated service mutation.
//!
//! The service request is sent over the real operator TCP listener while a
//! separate process holds the policy lock.  The client is then dropped and a
//! graceful SIGTERM is sent. Both revisions remain alive while the lock is
//! held, but the pre-owner revision loses the canonical audit after the lock
//! is released because its detached worker outlives the audit writer. The
//! owner revision joins the worker before stopping that writer. Set
//! `SAFEYOLO_LIFECYCLE_EXPECT_MISSING_AUDIT=1` when running this same witness
//! against the pre-owner revision to retain the before evidence.

use std::{
    fs::{self, OpenOptions},
    os::unix::{fs::MetadataExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::{sleep, timeout},
};

const TOKEN: &str = "lifecycle-634-authenticated-token";
const BODY: &[u8] = br#"{"service":"mail","capability":"read","credential":"vault-entry"}"#;
const INITIAL: &str = "version = '2.0'\n# retained comment\n[hosts]\n'*' = {rate=600}\n[agents.alice]\nimage = 'owned-image'\n";
const WAIT_FOR_READY: Duration = Duration::from_secs(5);
const WAIT_FOR_EARLY_EXIT: Duration = Duration::from_millis(500);

/// A test panic must not leave a real proxy process behind.  The child is
/// moved into a wait task after SIGTERM; this guard retains its PID until that
/// task has observed exit.
struct ChildGuard {
    pid: i32,
    active: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: the PID came from the child owned by this test.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_canceled_service_shutdown_drains_held_policy_lock() {
    let directory = tempfile::tempdir().unwrap();
    let paths = Paths::new(&directory);
    paths.write_inputs();

    let mut child = Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
        .arg("--config")
        .arg(&paths.config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("native proxy process must start");
    let mut guard = ChildGuard {
        pid: child.id() as i32,
        active: true,
    };
    let readiness = wait_for_readiness(&paths.readiness).await;
    let admin_port = readiness["admin_port"]
        .as_u64()
        .expect("readiness must publish the bound admin port") as u16;

    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&paths.lock)
        .unwrap();
    lock.lock().unwrap();

    // A valid bearer request which receives no response while the lock is
    // held demonstrates authentication and admission into the mutation path.
    // Dropping this stream models client cancellation before the write can
    // complete.  An auth or route failure would return an HTTP response here.
    submit_and_cancel(admin_port).await;

    // SIGTERM is the same graceful path used by the shipped binary's signal
    // loop. Both revisions remain alive while the lock is held; after release
    // the old detached worker can finish after its audit writer, while the
    // process-owned owner joins the worker before stopping that writer.
    // SAFETY: the PID is the child process spawned above.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let wait = tokio::task::spawn_blocking(move || child.wait());
    tokio::pin!(wait);
    let expect_missing_audit =
        std::env::var_os("SAFEYOLO_LIFECYCLE_EXPECT_MISSING_AUDIT").is_some();
    let status_before_unlock = match timeout(WAIT_FOR_EARLY_EXIT, &mut wait).await {
        Ok(Ok(status)) => Some(status),
        Ok(Err(error)) => panic!("child wait task failed: {error}"),
        Err(_) => None,
    };
    let early_exit = status_before_unlock.is_some();
    assert!(
        !early_exit,
        "graceful shutdown must remain bounded by the held mutation, not exit early"
    );

    lock.unlock().unwrap();
    let status = match status_before_unlock {
        Some(status) => status.expect("proxy process must report exit status"),
        None => timeout(Duration::from_secs(5), &mut wait)
            .await
            .expect("owned shutdown must finish after lock release")
            .expect("child wait task must join")
            .expect("proxy process must report exit status"),
    };
    guard.active = false;

    let policy = fs::read_to_string(&paths.policy).unwrap();
    let audit_rows = read_audit(&paths.audit);
    let authorization_events = audit_rows
        .iter()
        .filter(|row| row["event"] == "admin.agent_service_authorized")
        .count();
    let readiness_removed = !paths.readiness.exists();
    let persisted_binding = policy.contains("[agents.alice.services]")
        && policy.contains("mail = { capability = \"read\", token = \"vault-entry\" }");
    assert!(status.success(), "proxy should exit cleanly: {status}");
    assert!(
        persisted_binding,
        "held mutation must persist its authenticated binding: {policy}"
    );
    if expect_missing_audit {
        assert_eq!(
            authorization_events, 0,
            "baseline records the audit loss after writer shutdown"
        );
    } else {
        assert_eq!(
            authorization_events, 1,
            "owned shutdown must retain exactly one canonical authorization audit"
        );
    }
    assert!(
        readiness_removed,
        "shutdown must remove readiness independently"
    );

    let evidence = json!({
        "expected_missing_audit": expect_missing_audit,
        "authenticated_request": true,
        "client_cancelled": true,
        "shutdown_signal": "SIGTERM",
        "held_policy_lock": true,
        "process_exit_before_lock_release": early_exit,
        "process_exit_success": status.success(),
        "persisted_binding": persisted_binding,
        "authorization_audit_events": authorization_events,
        "readiness_removed": readiness_removed,
    });
    println!("lifecycle-634 observation: {evidence}");
    if let Some(path) = std::env::var_os("SAFEYOLO_LIFECYCLE_EVIDENCE") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_shutdown_reopens_same_agent_socket_and_readiness_paths() {
    let directory = tempfile::tempdir().unwrap();
    let paths = Paths::new(&directory);
    paths.write_inputs();

    let (first, mut first_guard) = start_proxy(&paths);
    let first_ready = wait_for_readiness(&paths.readiness).await;
    let first_instance = first_ready["instance_id"]
        .as_str()
        .expect("first readiness must publish an instance identity")
        .to_owned();
    let first_admin_port = first_ready["admin_port"]
        .as_u64()
        .expect("first readiness must publish the operator port") as u16;
    wait_for_path(&paths.agent_socket()).await;
    probe_agent_socket(&paths.agent_socket(), first_admin_port).await;
    stop_proxy(first, &mut first_guard).await;
    wait_for_absent(&paths.readiness).await;
    wait_for_absent(&paths.agent_socket()).await;

    // A second native process gets the same configured state and socket paths.
    // Requiring the old marker and inode to disappear first prevents a stale
    // readiness file or socket from making this a false-positive launch.
    let (second, mut second_guard) = start_proxy(&paths);
    let second_ready = wait_for_readiness(&paths.readiness).await;
    let second_instance = second_ready["instance_id"]
        .as_str()
        .expect("second readiness must publish an instance identity");
    assert_ne!(second_instance, first_instance);
    let second_admin_port = second_ready["admin_port"]
        .as_u64()
        .expect("second readiness must publish the operator port")
        as u16;
    wait_for_path(&paths.agent_socket()).await;
    probe_agent_socket(&paths.agent_socket(), second_admin_port).await;
    stop_proxy(second, &mut second_guard).await;
    wait_for_absent(&paths.readiness).await;
    wait_for_absent(&paths.agent_socket()).await;

    let evidence = json!({
        "first_instance_id": first_instance,
        "second_instance_id": second_instance,
        "same_configured_agent_socket": true,
        "first_agent_probe": "handled",
        "second_agent_probe": "handled",
        "first_readiness_removed": true,
        "first_socket_removed": true,
        "second_readiness_removed": true,
        "second_socket_removed": true,
    });
    println!("lifecycle-634 restart observation: {evidence}");
    if let Some(path) = std::env::var_os("SAFEYOLO_LIFECYCLE_RESTART_EVIDENCE") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abrupt_kill_restarts_over_stale_paths_and_retains_completed_audit() {
    let directory = tempfile::tempdir().unwrap();
    let paths = Paths::new(&directory);
    paths.write_inputs();

    let (mut first, mut first_guard) = start_proxy(&paths);
    let first_ready = wait_for_readiness(&paths.readiness).await;
    let first_instance = first_ready["instance_id"]
        .as_str()
        .expect("first readiness must publish an instance identity")
        .to_owned();
    let first_admin_port = first_ready["admin_port"]
        .as_u64()
        .expect("first readiness must publish the operator port") as u16;
    wait_for_path(&paths.agent_socket()).await;

    let response = submit_completed_service(first_admin_port).await;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "authenticated service mutation must complete before the crash: {}",
        String::from_utf8_lossy(&response)
    );
    let before_rows = wait_for_authorized_audit(&paths.audit).await;
    let completed_event = before_rows
        .iter()
        .find(|row| row["event"] == "admin.agent_service_authorized")
        .cloned()
        .expect("completed service mutation must have one canonical audit event");
    let first_socket = fs::metadata(paths.agent_socket()).unwrap();

    // SIGKILL deliberately skips Drop. The next native start must reclaim the
    // stale Unix socket and replace the stale readiness marker before serving.
    let first_pid = u64::from(first.id());
    unsafe {
        libc::kill(first_pid as i32, libc::SIGKILL);
    }
    let first_status = tokio::task::spawn_blocking(move || first.wait())
        .await
        .expect("first child wait task must join")
        .expect("first proxy must report an exit status");
    first_guard.active = false;
    assert_eq!(first_status.signal(), Some(libc::SIGKILL));
    assert!(
        paths.readiness.exists(),
        "SIGKILL must leave stale readiness"
    );
    assert!(
        paths.agent_socket().exists(),
        "SIGKILL must leave the stale agent socket for startup cleanup"
    );
    let stale_ready: Value = serde_json::from_slice(&fs::read(&paths.readiness).unwrap()).unwrap();
    assert_eq!(stale_ready["instance_id"], first_instance);
    assert_eq!(stale_ready["pid"], first_pid);

    let (second, mut second_guard) = start_proxy(&paths);
    let second_ready =
        wait_for_restarted_readiness(&paths.readiness, &first_instance, first_pid).await;
    let second_instance = second_ready["instance_id"]
        .as_str()
        .expect("restarted readiness must publish an instance identity");
    let second_pid = second_ready["pid"].as_u64().unwrap();
    assert_ne!(second_instance, first_instance);
    assert_ne!(second_pid, first_pid);
    wait_for_path(&paths.agent_socket()).await;
    let second_socket = fs::metadata(paths.agent_socket()).unwrap();
    assert!(
        first_socket.ino() != second_socket.ino() || first_socket.dev() != second_socket.dev(),
        "restart must replace the stale socket inode"
    );
    let second_admin_port = second_ready["admin_port"]
        .as_u64()
        .expect("restarted readiness must publish the operator port")
        as u16;
    probe_agent_socket(&paths.agent_socket(), second_admin_port).await;

    let after_rows = read_audit(&paths.audit);
    assert_eq!(
        after_rows
            .iter()
            .filter(|row| row["event"] == "admin.agent_service_authorized")
            .count(),
        1,
        "restart must retain exactly one completed authorization event"
    );
    assert!(
        after_rows.iter().any(|row| row == &completed_event),
        "restart must retain the completed authorization event verbatim"
    );
    stop_proxy(second, &mut second_guard).await;
    wait_for_absent(&paths.readiness).await;
    wait_for_absent(&paths.agent_socket()).await;
    assert!(
        !paths.fallback_audit().exists(),
        "explicit audit destination must not silently fall back after crash/restart"
    );

    let evidence = json!({
        "first_instance_id": first_instance,
        "second_instance_id": second_instance,
        "first_pid": first_pid,
        "second_pid": second_pid,
        "first_exit_signal": first_status.signal(),
        "stale_readiness_observed": true,
        "stale_agent_socket_observed": true,
        "stale_readiness_replaced": true,
        "stale_socket_replaced": true,
        "completed_mutation_response": "HTTP/1.1 200",
        "completed_authorization_events_after_restart": 1,
        "completed_authorization_event_retained": true,
        "agent_probe_after_restart": "handled",
        "fallback_audit_absent": true,
        "final_readiness_removed": !paths.readiness.exists(),
        "final_agent_socket_removed": !paths.agent_socket().exists(),
        "limits": [
            "SIGKILL is used only to exercise stale path recovery; it cannot prove durability of an in-flight mutation.",
            "The completed mutation and its audit row are observed before SIGKILL; no producer is claimed to survive an arbitrary crash.",
            "This covers one authenticated service producer and does not establish the full #626/#628/#629 worker matrix.",
        ],
    });
    println!("lifecycle-634 crash/restart observation: {evidence}");
    if let Some(path) = std::env::var_os("SAFEYOLO_LIFECYCLE_CRASH_EVIDENCE") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

struct Paths {
    root: PathBuf,
    config: PathBuf,
    policy: PathBuf,
    lock: PathBuf,
    services: PathBuf,
    builtin: PathBuf,
    token: PathBuf,
    readiness: PathBuf,
    audit: PathBuf,
    events: PathBuf,
}

impl Paths {
    fn new(directory: &TempDir) -> Self {
        let root = directory.path().to_owned();
        Self {
            config: root.join("config.json"),
            policy: root.join("policy.toml"),
            lock: root.join(".policy.toml.lock"),
            services: root.join("services"),
            builtin: root.join("builtin"),
            token: root.join("admin-token"),
            readiness: root.join("ready.json"),
            audit: root.join("audit.jsonl"),
            events: root.join("events.jsonl"),
            root,
        }
    }

    fn write_inputs(&self) {
        fs::write(&self.policy, INITIAL).unwrap();
        fs::create_dir(&self.services).unwrap();
        fs::create_dir(&self.builtin).unwrap();
        fs::write(
            self.services.join("mail.yaml"),
            "schema_version: 1\nname: mail\nauth: {type: bearer}\ncapabilities:\n  read:\n    routes: []\n",
        )
        .unwrap();
        fs::write(&self.token, TOKEN).unwrap();
        let config = json!({
            "listeners": [{"agent_id":"alice","socket_path":self.root.join("alice.sock")}],
            "policy_file": self.policy,
            "data_dir": self.root.join("data"),
            "gateway_builtin_services_dir": self.builtin,
            "gateway_services_dir": self.services,
            "agent_api_enabled": false,
            "admin_port": 0,
            "admin_api_token_file": self.token,
            "readiness_file": self.readiness,
            "flow_store_enabled": false,
            "circuit_breaker_enabled": false,
            "audit_log_path": self.audit,
            "event_log": self.events,
        });
        fs::write(&self.config, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    }

    fn agent_socket(&self) -> PathBuf {
        self.root.join("alice.sock")
    }

    fn fallback_audit(&self) -> PathBuf {
        self.root.join("unexpected-fallback-audit.jsonl")
    }
}

fn start_proxy(paths: &Paths) -> (std::process::Child, ChildGuard) {
    let child = Command::new(env!("CARGO_BIN_EXE_safeyolo-proxy"))
        .arg("--config")
        .arg(&paths.config)
        .env("SAFEYOLO_LOG_PATH", paths.fallback_audit())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("native proxy process must start");
    let guard = ChildGuard {
        pid: child.id() as i32,
        active: true,
    };
    (child, guard)
}

async fn stop_proxy(mut child: std::process::Child, guard: &mut ChildGuard) {
    // SAFETY: the PID belongs to the process spawned by this test.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .expect("child wait task must join")
        .expect("proxy process must report exit status");
    guard.active = false;
    assert!(
        status.success(),
        "proxy process must exit cleanly: {status}"
    );
}

async fn wait_for_path(path: &Path) {
    timeout(WAIT_FOR_READY, async {
        loop {
            if path.exists() {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("proxy must publish the configured socket");
}

async fn wait_for_absent(path: &Path) {
    timeout(WAIT_FOR_READY, async {
        loop {
            if !path.exists() {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("proxy must remove its lifecycle marker and socket");
}

async fn probe_agent_socket(path: &Path, admin_port: u16) {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("reopened agent socket must accept connections");
    let request = format!(
        "GET http://127.0.0.1:{admin_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{admin_port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .expect("reopened agent socket must return an HTTP response")
        .expect("agent response must be readable");
    assert!(
        response.starts_with(b"HTTP/1.1 403") || response.starts_with(b"HTTP/1.1 502"),
        "agent probe must be handled by the proxy: {}",
        String::from_utf8_lossy(&response)
    );
}

async fn wait_for_readiness(path: &Path) -> Value {
    timeout(WAIT_FOR_READY, async {
        loop {
            if let Ok(bytes) = fs::read(path)
                && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                && value["ready"] == true
                && value["admin_port"].is_number()
            {
                return value;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("proxy must publish readiness")
}

async fn wait_for_restarted_readiness(path: &Path, old_instance: &str, old_pid: u64) -> Value {
    timeout(WAIT_FOR_READY, async {
        loop {
            if let Ok(bytes) = fs::read(path)
                && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                && value["ready"] == true
                && value["admin_port"].is_number()
                && value["instance_id"].as_str() != Some(old_instance)
                && value["pid"].as_u64() != Some(old_pid)
            {
                return value;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("proxy must replace stale readiness before restart is accepted")
}

async fn submit_and_cancel(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("authenticated admin listener must accept TCP");
    let request = format!(
        "POST /admin/agents/alice/services HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(BODY).await.unwrap();
    let mut response = Vec::new();
    match timeout(
        Duration::from_millis(200),
        stream.read_to_end(&mut response),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(_)) => panic!("authenticated mutation returned before held lock release"),
        Ok(Err(error)) => panic!("authenticated mutation connection failed: {error}"),
    }
    drop(stream);
}

async fn submit_completed_service(port: u16) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("authenticated admin listener must accept TCP");
    let request = format!(
        "POST /admin/agents/alice/services HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(BODY).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("completed service response must arrive")
        .expect("completed service response must be readable");
    response
}

async fn wait_for_authorized_audit(path: &Path) -> Vec<Value> {
    timeout(WAIT_FOR_READY, async {
        loop {
            if let Ok(text) = fs::read_to_string(path) {
                let parsed: Result<Vec<_>, _> =
                    text.lines().map(serde_json::from_str::<Value>).collect();
                if let Ok(rows) = parsed
                    && rows
                        .iter()
                        .any(|row| row["event"] == "admin.agent_service_authorized")
                {
                    return rows;
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("completed service audit must be published")
}

fn read_audit(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit rows must be JSON"))
        .collect()
}
