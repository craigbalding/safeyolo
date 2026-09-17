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
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
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

fn read_audit(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit rows must be JSON"))
        .collect()
}
