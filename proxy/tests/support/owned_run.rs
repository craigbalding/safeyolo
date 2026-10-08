//! A controlled runsc backend with real, mapped user/network namespace ownership.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::json;

pub struct OwnedRun {
    pub child: Child,
    directory: PathBuf,
}

pub fn process_token(pid: u32) -> String {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let ticks = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    format!("linux:{}:{pid}:{ticks}", boot.trim())
}

impl OwnedRun {
    pub fn start(root: &Path) -> Self {
        let directory = root.join("agents/alice");
        fs::create_dir_all(directory.join("config-share")).unwrap();
        let generation = uuid::Uuid::new_v4().simple().to_string();
        let id = format!("safeyolo-{generation}");
        let child = Command::new("/usr/bin/unshare")
            .args([
                "--user",
                "--net",
                "/bin/bash",
                "-c",
                "exec -a runsc-sandbox /bin/sh -c 'read -r finish' \"$@\"",
                "fixture",
            ])
            .arg(format!("--root={}", root.join("run").display()))
            .args(["boot", &id])
            .stdin(Stdio::piped())
            .spawn()
            .expect("native fixture requires unshare user/network namespaces");
        let mut run = Self { child, directory };
        let proc = PathBuf::from(format!("/proc/{}", run.child.id()));
        let deadline = Instant::now() + Duration::from_secs(3);
        while ["user", "net"].iter().any(|kind| {
            fs::metadata(proc.join("ns").join(kind)).unwrap().ino()
                == fs::metadata(Path::new("/proc/self/ns").join(kind))
                    .unwrap()
                    .ino()
        }) {
            assert!(
                run.child.try_wait().unwrap().is_none(),
                "namespace fixture exited"
            );
            assert!(
                Instant::now() < deadline,
                "namespace fixture did not enter its namespaces"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // Use direct mapping when CAP_SETUID/CAP_SETGID permits it. Ordinary
        // rootless hosts use the same ID helpers as native sandbox startup.
        for (kind, identity) in [
            ("uid", unsafe { libc::getuid() }),
            ("gid", unsafe { libc::getgid() }),
        ] {
            if kind == "gid" {
                fs::write(proc.join("setgroups"), "deny").unwrap();
            }
            let mapping = format!("0 100000 1000\n1000 {identity} 1\n1001 101001 64534\n");
            if let Err(error) = fs::write(proc.join(format!("{kind}_map")), &mapping) {
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "{error}"
                );
                let status = Command::new(format!("/usr/bin/new{kind}map"))
                    .args([
                        run.child.id().to_string(),
                        "0".into(),
                        "100000".into(),
                        "1000".into(),
                        "1000".into(),
                        identity.to_string(),
                        "1".into(),
                        "1001".into(),
                        "101001".into(),
                        "64534".into(),
                    ])
                    .status()
                    .expect("native fixture requires uidmap and subordinate IDs 100000–165535");
                assert!(status.success(), "{kind} mapping failed");
            }
        }
        let token = process_token(run.child.id());
        fs::write(
            run.directory.join("config-share/host-launch-context.json"),
            serde_json::to_vec(&json!({"generation":generation})).unwrap(),
        )
        .unwrap();
        fs::write(
            run.directory.join("runtime.json"),
            serde_json::to_vec(&json!({
                "run_id":generation, "holder_pid":run.child.id(), "holder_token":token,
                "backend_pid":run.child.id(), "backend_token":token
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(run.directory.join("userns.pid"), run.child.id().to_string()).unwrap();
        // The fake runsc commands manipulate test-owned host files. Enter the
        // verified namespaces but retain their mapped operator credentials.
        // Production namespace and process checks run unchanged before this.
        let nsenter = root.join("bin/nsenter");
        fs::write(
            &nsenter,
            "#!/bin/sh\nexec /usr/bin/nsenter --preserve-credentials \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(nsenter, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("FAKE_RUN_ID", id);
        }
        run
    }

    pub fn assert_exited(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "owned namespace backend survived teardown"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedRun {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
