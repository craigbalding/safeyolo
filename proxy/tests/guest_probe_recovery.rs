//! Host probe ownership and return of the borrowed idle supervisor slot.
//! Installed Linux/VZ proof separately exercises PID 1 and managed recovery.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    thread,
    time::{Duration, Instant},
};

const NAME: &str = "worker";
const AGENT: &str = "ag-11111111111111111111111111111111";
const RUN: &str = "0123456789abcdef0123456789abcdef";

fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write(path: &Path, value: &Value) {
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
    serde_json::to_writer(&mut temporary, value).unwrap();
    temporary.persist(path).unwrap();
}

fn prepare(root: &Path) -> (std::path::PathBuf, Value) {
    let directory = root.join("agents/worker");
    fs::create_dir_all(directory.join("home")).unwrap();
    fs::create_dir(directory.join("config-share")).unwrap();
    fs::write(directory.join("config-share/safeyolo-guest"), b"fixture").unwrap();
    write(
        &directory.join("config-share/host-launch-context.json"),
        &json!({"agent_id":AGENT,"generation":RUN}),
    );
    let launch = json!({"name":NAME,"agent_id":AGENT,"launch_id":"launch-original",
        "state":"managed","command":"exec configured-worker","launcher":{"kind":"supervisor"}});
    write(&directory.join("current-launch.json"), &launch);
    let supervisor = json!({"schema_version":1,"name":NAME,"generation":RUN,
        "supervision_id":launch["launch_id"],"command":launch["command"],
        "runtime_owner":"guest-pid1","state":"failed","last_exit_code":7,
        "command_pid":null,"command_start_token":null});
    write(
        &directory.join("home/.safeyolo-command-supervisor.json"),
        &supervisor,
    );
    (directory, supervisor)
}

#[test]
fn successful_probe_returns_the_original_terminal_harness_without_replaying_it() {
    let root = tempfile::tempdir().unwrap();
    let (directory, original) = prepare(root.path());
    let guest_directory = directory.clone();
    let guest = thread::spawn(move || {
        let path = guest_directory.join("home/.safeyolo-command-supervisor.json");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut state = read(&path);
            if state["supervision_id"] != "launch-original" {
                assert!(
                    state["command"]
                        .as_str()
                        .unwrap()
                        .starts_with("exec /safeyolo/safeyolo-guest probe ")
                );
                state["state"] = json!("stopped");
                state["last_exit_code"] = json!(0);
                state["last_stderr"] =
                    json!(json!({"probe_id":state["supervision_id"],"uid":1000}).to_string());
                write(&path, &state);
                return state;
            }
            assert!(Instant::now() < deadline, "probe was not published");
            thread::sleep(Duration::from_millis(5));
        }
    });
    let result =
        safeyolo_proxy::recover_guest_probe(root.path(), NAME, Duration::from_secs(2)).unwrap();
    let probe = guest.join().unwrap();
    assert_eq!(result["state"], probe);
    assert_eq!(result["result"]["probe_id"], probe["supervision_id"]);
    assert_eq!(
        read(&directory.join("home/.safeyolo-command-supervisor.json")),
        original
    );
    assert_eq!(
        read(&directory.join("current-launch.json"))["launch_id"],
        "launch-original"
    );
    assert!(
        !directory
            .join("config-share/command-supervisor-enabled")
            .exists()
    );
    assert_eq!(
        read(&directory.join("home/.safeyolo-command-supervisor.stop"))["supervision_id"],
        probe["supervision_id"]
    );
}

#[test]
fn probe_preserves_wrong_stale_and_occupied_harness_ownership() {
    for (field, wrong) in [
        ("generation", json!("old-run")),
        ("name", json!("different-worker")),
        ("supervision_id", json!("different-launch")),
        ("command", json!("exec other-command")),
        ("runtime_owner", json!("other-owner")),
        ("state", json!("running")),
        ("command_pid", json!(123)),
        ("command_start_token", json!("occupied")),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (directory, mut state) = prepare(root.path());
        state[field] = wrong;
        let path = directory.join("home/.safeyolo-command-supervisor.json");
        write(&path, &state);
        assert!(
            safeyolo_proxy::recover_guest_probe(root.path(), NAME, Duration::from_millis(50))
                .is_err(),
            "{field}"
        );
        assert_eq!(read(&path), state, "{field}");
        assert!(
            !directory
                .join("config-share/command-supervisor-enabled")
                .exists()
        );
    }
}

#[test]
fn probe_timeout_keeps_its_uncertain_state_and_does_not_restore_a_stopped_harness() {
    let root = tempfile::tempdir().unwrap();
    let (directory, _) = prepare(root.path());
    let error = safeyolo_proxy::recover_guest_probe(root.path(), NAME, Duration::from_millis(50))
        .unwrap_err();
    assert!(
        error.to_string().contains("completion is unverified"),
        "{error}"
    );
    let state = read(&directory.join("home/.safeyolo-command-supervisor.json"));
    assert_ne!(state["supervision_id"], "launch-original");
    assert_eq!(state["state"], "starting");
    assert_eq!(
        read(&directory.join("home/.safeyolo-command-supervisor.stop"))["supervision_id"],
        state["supervision_id"]
    );
}
