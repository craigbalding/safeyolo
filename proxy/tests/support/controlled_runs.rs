//! Controlled ingress ownership records; this is not an installed guest proof.
use std::{
    fs,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command},
};

pub struct Backend(Child);
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn agent_run(root: &Path, name: &str, agent_id: &str, generation: &str) -> Backend {
    // A shim dispatches by argv[0]. Resolve its selected interpreter before
    // supplying the controlled backend command name.
    let selected = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(selected.status.success());
    let python = std::str::from_utf8(&selected.stdout).unwrap().trim();
    let child = Command::new(python)
        .arg0("runsc-sandbox")
        .args([
            "-c",
            "import time; time.sleep(600)",
            "boot",
            &format!("safeyolo-{generation}"),
            "--root",
        ])
        .arg(root.join("run"))
        .spawn()
        .unwrap();
    let pid = child.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let birth = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let token = format!(
        "linux:{}:{pid}:{birth}",
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
    );
    let directory = root.join("agents").join(name);
    fs::create_dir_all(directory.join("config-share")).unwrap();
    fs::write(directory.join("runtime.json"),serde_json::json!({"name":name,"agent_id":agent_id,"run_id":generation,"state":"running","backend_pid":pid,"backend_token":token}).to_string()).unwrap();
    fs::write(
        directory.join("config-share/host-launch-context.json"),
        serde_json::json!({"agent_id":agent_id,"generation":generation}).to_string(),
    )
    .unwrap();
    Backend(child)
}
