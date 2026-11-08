//! Faults at the real local Admin/Agent owners; no installed backend replay.
use super::*;
use safeyolo_proxy::{Config, Proxy};
use std::{
    ffi::CString,
    io::Read,
    os::{fd::FromRawFd, unix::ffi::OsStrExt},
    path::Path,
    process::{Child, Command, Stdio},
};

async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(8), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owner did not reach the audit boundary");
}

fn pending_grants(root: &Path) -> Vec<Value> {
    let entries = match fs::read_dir(root.join("data/support-grant-audit")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return vec![],
        Err(error) => panic!("support grant obligations: {error}"),
    };
    entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|part| part == "json"))
        .map(|path| serde_json::from_slice(&fs::read(path).unwrap()).unwrap())
        .collect()
}

#[tokio::test]
async fn support_grant_audit_recovers_write_failure_without_repeating_policy_changes() {
    let f = fixture().await;
    f.make_audit_unavailable();
    let applied = grant(&f, proposal()).await;
    assert!(applied["audit_status"].is_string());
    let revoked = f
        .admin(
            "POST",
            "/admin/support-grants/incident/revoke",
            Some(json!({"expected_revision":applied["revision"]})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
    let revoked = revoked.json();
    assert!(revoked["audit_status"].is_string());
    let pending = pending_grants(f.root.path());
    assert_eq!(pending.len(), 2);
    assert!(
        pending
            .iter()
            .all(|event| event["details"]["state"] == "completed")
    );
    let saved = f.source();
    assert!(!saved.contains("support_grants.incident"));
    f.proxy.shutdown().await;
    fs::remove_file(f.root.path().join("audit.jsonl")).unwrap();
    let restarted = Proxy::start(f.config.clone()).await.unwrap();
    until(|| pending_grants(f.root.path()).is_empty()).await;
    assert_eq!(
        fs::read_to_string(f.root.path().join("policy.toml")).unwrap(),
        saved
    );
    let events = fs::read_to_string(f.root.path().join("audit.jsonl")).unwrap();
    let events = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    for id in [&applied["audit_event_id"], &revoked["audit_event_id"]] {
        let found = events
            .iter()
            .filter(|event| &event["event_id"] == id)
            .collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["details"]["initiator"]["kind"], "operator");
        assert_eq!(found[0]["details"]["instance_id"], INSTANCE);
    }
    restarted.shutdown().await;
}

#[tokio::test]
async fn support_grant_cannot_save_without_a_durable_audit_obligation() {
    let f = fixture().await;
    fs::write(
        f.root.path().join("data/support-grant-audit"),
        "owned obstruction",
    )
    .unwrap();
    let saved = f.source();
    let mut input = proposal();
    let preview = f
        .admin(
            "POST",
            "/admin/support-grants/incident/preview",
            Some(input.clone()),
        )
        .await
        .json();
    input["grant"] = preview["after"].clone();
    input["grant"]["acknowledgment"] = preview["acknowledgment"].clone();
    let result = f
        .admin("POST", "/admin/support-grants/incident/apply", Some(input))
        .await;
    assert_eq!(result.status, 409, "{}", result.json());
    assert_eq!(f.source(), saved);
    f.stop().await;
}

struct TestOwner(Child);
impl Drop for TestOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn support_grant_audit_survives_owner_termination_before_delivery() {
    if let Some(marker) = std::env::var_os("SAFEYOLO_SUPPORT_AUDIT_CHILD") {
        let f = fixture().await;
        let mut input = proposal();
        let preview = f
            .admin(
                "POST",
                "/admin/support-grants/incident/preview",
                Some(input.clone()),
            )
            .await
            .json();
        input["grant"] = preview["after"].clone();
        input["grant"]["acknowledgment"] = preview["acknowledgment"].clone();
        let audit_lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(f.root.path().join("audit.jsonl.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(audit_lock.as_raw_fd(), libc::LOCK_EX) },
            0
        );
        let pending = f.admin("POST", "/admin/support-grants/incident/apply", Some(input));
        tokio::pin!(pending);
        loop {
            tokio::select! {
                response = &mut pending => panic!("audit delivery escaped the held sink: {}", response.json()),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            let staged = pending_grants(f.root.path());
            if staged.len() == 1 && staged[0]["details"]["state"] == "completed" {
                assert!(f.source().contains("support_grants"));
                fs::write(&marker, json!({"config":f.config,"root":f.root.path(),"event":staged[0],"policy":f.source()}).to_string()).unwrap();
                std::future::pending::<()>().await;
            }
        }
    }
    let control = tempfile::tempdir().unwrap();
    let marker = control.path().join("persisted.json");
    let mut child = TestOwner(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit_delivery::support_grant_audit_survives_owner_termination_before_delivery",
                "--nocapture",
            ])
            .env("SAFEYOLO_SUPPORT_AUDIT_CHILD", &marker)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    until(|| marker.exists() || child.0.try_wait().unwrap().is_some()).await;
    let recorded: Value =
        serde_json::from_slice(&fs::read(&marker).expect("child exited before saving authority"))
            .unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let root = Path::new(recorded["root"].as_str().unwrap());
    let mut config: Config = serde_json::from_value(recorded["config"].clone()).unwrap();
    config.native_config_dir = Some(root.to_owned());
    assert_eq!(pending_grants(root).len(), 1);
    let restarted = Proxy::start(config).await.unwrap();
    until(|| pending_grants(root).is_empty()).await;
    assert_eq!(
        fs::read_to_string(root.join("policy.toml")).unwrap(),
        recorded["policy"].as_str().unwrap()
    );
    let events = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert!(
        events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .any(|event| event == recorded["event"])
    );
    restarted.shutdown().await;
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn support_post_lock_refusal_is_audited_without_an_operation_receipt() {
    let f = fixture().await;
    let _support = support_run(&f, RUN);
    let applied = grant(&f, proposal()).await;
    let directory = f.root.path().join("data/support-operations");
    fs::create_dir_all(&directory).unwrap();
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        json!([HELPER_ID, "after-lock"]).to_string().as_bytes(),
    );
    let id = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = directory.join(format!("{id}.lock"));
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(descriptor >= 0);
    let mut opens = unsafe { fs::File::from_raw_fd(descriptor) };
    let watched = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert!(unsafe { libc::inotify_add_watch(descriptor, watched.as_ptr(), libc::IN_OPEN) } >= 0);
    let response = {
        let pending = f.agent(
            "helper",
            "POST",
            "/support/operations",
            Some(inspect("after-lock")),
        );
        tokio::pin!(pending);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            tokio::select! {
                response = &mut pending => panic!("operation escaped its lock: {}", response.json()),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            let mut events = [0u8; 512];
            if opens.read(&mut events).is_ok_and(|count| count > 0) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "owner did not reach the operation lock"
            );
        }
        assert_eq!(
            f.admin(
                "POST",
                "/admin/support-grants/incident/revoke",
                Some(json!({"expected_revision":applied["revision"]}))
            )
            .await
            .status,
            200
        );
        drop(lock);
        pending.await
    };
    assert_eq!(response.status, 403, "{}", response.json());
    assert!(!path.with_extension("json").exists());
    let audit = fs::read_to_string(f.root.path().join("audit.jsonl")).unwrap();
    let denial = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| {
            event["event"] == "agent.support_operation_denied"
                && event["details"]["operation_id"] == "after-lock"
        })
        .unwrap();
    assert_eq!(denial["details"]["phase"], "operation_lock");
    assert_eq!(denial["details"]["state"], "refused");
    assert_eq!(denial["details"]["initiator"]["agent_id"], HELPER_ID);
    f.stop().await;
}
