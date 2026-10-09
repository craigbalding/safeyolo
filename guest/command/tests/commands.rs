//! Real process checks for the Linux guest executable; systrap proof is separate.

use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Output},
    thread,
    time::{Duration, Instant},
};

struct Guest {
    directory: tempfile::TempDir,
    state: PathBuf,
    stop: PathBuf,
    context: PathBuf,
    records: PathBuf,
}

impl Guest {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let context = directory.path().join("context.json");
        fs::write(
            &context,
            json!({"generation":"command-fixture-run"}).to_string(),
        )
        .unwrap();
        Self {
            state: directory.path().join("state.json"),
            stop: directory.path().join("stop"),
            records: directory.path().join("records"),
            context,
            directory,
        }
    }

    fn command(&self) -> Command {
        self.command_at(env!("CARGO_BIN_EXE_safeyolo-guest"))
    }

    fn command_at(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command
            .args(["--context"])
            .arg(&self.context)
            .arg("--state")
            .arg(&self.state)
            .arg("--stop")
            .arg(&self.stop)
            .arg("--records")
            .arg(&self.records)
            .arg("--workspace")
            .arg(self.directory.path());
        command
    }

    fn publish(&self, command: &str) {
        fs::write(
            &self.state,
            json!({"schema_version":1,"name":"fixture","command":command,
            "generation":"command-fixture-run","supervision_id":"fixture-command",
            "started_at":1,"state":"starting","restart_count":0,"consecutive_failures":0})
            .to_string(),
        )
        .unwrap();
    }

    fn read(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.state).unwrap()).unwrap()
    }

    fn wait(&self, predicate: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = self.read();
            if predicate(&state) {
                return state;
            }
            assert!(
                Instant::now() < deadline,
                "guest state did not converge: {state}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

struct Supervisor(Child, PathBuf);

impl Supervisor {
    fn start(guest: &Guest) -> Self {
        Self(
            // Keep fixture stop/continue signals out of Cargo's process group.
            guest
                .command()
                .arg("supervise")
                .process_group(0)
                .spawn()
                .unwrap(),
            guest.stop.clone(),
        )
    }
    fn stop(&mut self) {
        fs::write(&self.1, "intentional-stop").unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(Instant::now() < deadline, "supervisor did not stop");
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn pause(&self) -> ResumeSupervisor {
        let pid = self.0.id() as i32;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
        ResumeSupervisor(pid)
    }
}

struct ResumeSupervisor(i32);

impl Drop for ResumeSupervisor {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0, libc::SIGCONT) };
    }
}

struct ForeignCommands(Child);

impl Drop for ForeignCommands {
    fn drop(&mut self) {
        if !self.0.try_wait().is_ok_and(|status| status.is_none()) {
            return;
        }
        // This shell traps TERM, stops its child and waits for it. The group
        // fallback is confined to the process group created by this fixture.
        unsafe { libc::kill(self.0.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.0.try_wait().is_ok_and(|status| status.is_none()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        }
        let _ = self.0.wait();
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        // Only this test's child is signalled. Give its native cleanup a chance
        // to retire its command group even when a test assertion fails.
        let _ = fs::write(&self.1, "test-cleanup");
        let deadline = Instant::now() + Duration::from_secs(4);
        while self.0.try_wait().is_ok_and(|status| status.is_none()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn marker_crash_replacement_and_intentional_stop() {
    let guest = Guest::new();
    guest.publish("n=0; test ! -f attempts || n=$(cat attempts); n=$((n+1)); echo $n > attempts; \
        if test $n = 1; then echo configured-crash >&2; exit 37; fi; echo marker > marker; exec sleep 60");
    let mut supervisor = Supervisor::start(&guest);
    let running = guest.wait(|state| {
        state["state"] == "running"
            && state["restart_count"] == 1
            && guest.directory.path().join("marker").exists()
    });
    assert_eq!(
        fs::read_to_string(guest.directory.path().join("attempts")).unwrap(),
        "2\n"
    );
    assert!(guest.directory.path().join("marker").is_file());
    assert_eq!(running["last_exit_code"], 37);
    assert_eq!(running["last_stderr"], "configured-crash\n");
    assert_eq!(
        success(
            guest
                .command()
                .args(["supervise", "check"])
                .output()
                .unwrap()
        )["command_start_token"],
        running["command_start_token"]
    );
    let pid = running["command_pid"].as_i64().unwrap();
    supervisor.stop();
    let stopped = guest.read();
    assert_eq!(stopped["state"], "stopped");
    assert!(stopped["command_pid"].is_null());
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    // The policy's maximum restart delay is ten seconds. Re-invoking the
    // owner must remain fenced throughout that full interval.
    assert!(guest.command().arg("supervise").status().unwrap().success());
    thread::sleep(Duration::from_secs(10));
    assert_eq!(guest.read(), stopped);
    assert_eq!(
        fs::read_to_string(guest.directory.path().join("attempts")).unwrap(),
        "2\n"
    );
}

#[test]
fn supervisor_check_uses_the_writer_clock_under_both_host_offsets() {
    let build = tempfile::tempdir().unwrap();
    let source = build.path().join("clock.c");
    let library = build.path().join("clock.so");
    fs::write(
        &source,
        r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>
int clock_gettime(clockid_t id, struct timespec *value) {
    int (*real_clock)(clockid_t, struct timespec *) = dlsym(RTLD_NEXT, "clock_gettime");
    int result = real_clock(id, value);
    if (result == 0 && id == CLOCK_REALTIME) {
        const char *offset = getenv("SAFEYOLO_TEST_GUEST_CLOCK_OFFSET");
        if (offset) value->tv_sec += strtoll(offset, NULL, 10);
    }
    return result;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .arg("-ldl")
            .status()
            .unwrap()
            .success()
    );
    for offset in [-600, 600] {
        let guest = Guest::new();
        guest.publish("exec /bin/sleep 60");
        // Only the writer and checker use the shifted clock. This test and
        // host callers retain their ordinary host clock.
        let command = || {
            let mut command = guest.command();
            command
                .env("LD_PRELOAD", &library)
                .env("SAFEYOLO_TEST_GUEST_CLOCK_OFFSET", offset.to_string());
            command
        };
        let mut supervisor = Supervisor(
            command().arg("supervise").process_group(0).spawn().unwrap(),
            guest.stop.clone(),
        );
        let running = guest.wait(|state| state["state"] == "running");
        let host_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(
            (running["heartbeat_at"].as_f64().unwrap() - host_time - offset as f64).abs() < 5.0
        );
        let checked = success(command().args(["supervise", "check"]).output().unwrap());
        assert_eq!(checked["state"], "running");
        assert_eq!(
            checked["command_start_token"],
            running["command_start_token"]
        );
        let resume = supervisor.pause();
        let mut host_timestamp = running.clone();
        host_timestamp["heartbeat_at"] = json!(host_time);
        let original = serde_json::to_vec(&host_timestamp).unwrap();
        fs::write(&guest.state, &original).unwrap();
        let rejected = command().args(["supervise", "check"]).output().unwrap();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("heartbeat"));
        assert_eq!(fs::read(&guest.state).unwrap(), original);
        fs::write(&guest.state, running.to_string()).unwrap();
        drop(resume);
        supervisor.stop();
    }
}

#[test]
fn supervisor_check_refuses_stale_future_foreign_and_dead_running_records() {
    let guest = Guest::new();
    let name = OsString::from_vec(b"sleep\xff".to_vec());
    std::os::unix::fs::symlink("/bin/sleep", guest.directory.path().join(name)).unwrap();
    guest.publish("exec $'./sleep\\xff' 60");
    let mut supervisor = Supervisor::start(&guest);
    let mut running = guest.wait(|state| state["state"] == "running");
    assert_eq!(
        success(
            guest
                .command()
                .args(["supervise", "check"])
                .output()
                .unwrap()
        )["state"],
        "running"
    );
    let supervisor_pid = supervisor.0.id() as i32;
    let resume = supervisor.pause();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    running["heartbeat_at"] = json!(current_time);
    for (key, value) in [
        ("heartbeat_at", json!(current_time - 60.0)),
        ("heartbeat_at", json!(current_time + 60.0)),
        ("heartbeat_at", Value::Null),
        ("heartbeat_at", json!("malformed")),
        ("heartbeat_at", json!([])),
        ("heartbeat_at", json!(false)),
        ("generation", json!("foreign-run")),
        ("runtime_owner", json!("host")),
        ("supervisor_start_token", json!("reused-birth")),
        ("supervisor_pid", json!(i32::MAX)),
        (
            "supervisor_uid",
            json!(u64::from(unsafe { libc::getuid() }) + 1),
        ),
        ("supervisor_uid", Value::Null),
        ("supervisor_parent_pid", json!(supervisor_pid)),
        ("command_start_token", json!("reused-birth")),
        ("command_pid", json!(i32::MAX)),
    ] {
        let mut invalid = running.clone();
        invalid[key] = value;
        let original = serde_json::to_vec(&invalid).unwrap();
        fs::write(&guest.state, &original).unwrap();
        let refused = guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap();
        assert!(!refused.status.success(), "accepted {invalid}");
        assert!(refused.stdout.is_empty());
        assert_eq!(fs::read(&guest.state).unwrap(), original);
        assert!(supervisor.0.try_wait().unwrap().is_none());
    }
    // A live same-UID process with a genuine birth still is not this
    // supervisor's child. Only the fixture-owned process is stopped below.
    let mut foreign = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    let stat = fs::read_to_string(format!("/proc/{}/stat", foreign.id())).unwrap();
    let ticks = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let mut wrong_child = running.clone();
    wrong_child["command_pid"] = json!(foreign.id());
    wrong_child["command_start_token"] = json!(format!("{}:{ticks}", boot.trim()));
    fs::write(&guest.state, wrong_child.to_string()).unwrap();
    let refused = guest
        .command()
        .args(["supervise", "check"])
        .output()
        .unwrap();
    let foreign_live = foreign.try_wait().unwrap().is_none();
    foreign.kill().unwrap();
    foreign.wait().unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ancestry"));
    assert!(foreign_live);
    let mut missing = running.clone();
    missing.as_object_mut().unwrap().remove("heartbeat_at");
    fs::write(&guest.state, missing.to_string()).unwrap();
    assert!(
        !guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::write(&guest.state, running.to_string()).unwrap();
    let command_pid = running["command_pid"].as_i64().unwrap() as i32;
    assert_eq!(unsafe { libc::kill(command_pid, libc::SIGKILL) }, 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !fs::read(format!("/proc/{command_pid}/stat"))
        .unwrap()
        .rsplit(|byte| *byte == b')')
        .next()
        .unwrap()
        .starts_with(b" Z ")
    {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::write(&guest.stop, "intentional-stop").unwrap();
    drop(resume);
    supervisor.stop();
}

#[test]
fn supervisor_check_refuses_a_foreign_parent_and_its_real_child() {
    let guest = Guest::new();
    guest.publish("exec /bin/sleep 120");
    let mut supervisor = Supervisor::start(&guest);
    let running = guest.wait(|state| state["state"] == "running");
    let resume = supervisor.pause();
    let mut foreign = ForeignCommands(
        Command::new("/bin/sh")
            .args([
                "-c",
                "trap 'kill \"$child\"; wait \"$child\"; exit 0' TERM; \
                /bin/sleep 120 & child=$!; printf '%s' \"$child\" > foreign-child; wait \"$child\"",
            ])
            .current_dir(guest.directory.path())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let child_path = guest.directory.path().join("foreign-child");
    let deadline = Instant::now() + Duration::from_secs(2);
    let child: i32 = loop {
        if let Ok(value) = fs::read_to_string(&child_path)
            && let Ok(pid) = value.parse()
        {
            break pid;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    };
    let birth = |pid: i32| {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let ticks = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        format!("{}:{ticks}", boot.trim())
    };
    let parent = foreign.0.id() as i32;
    let mut substituted = running.clone();
    substituted["supervisor_pid"] = json!(parent);
    substituted["supervisor_start_token"] = json!(birth(parent));
    substituted["supervisor_uid"] = json!(unsafe { libc::getuid() });
    substituted["supervisor_parent_pid"] = json!(std::process::id());
    substituted["command_pid"] = json!(child);
    substituted["command_start_token"] = json!(birth(child));
    substituted["heartbeat_at"] = json!(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    );
    let original = serde_json::to_vec(&substituted).unwrap();
    fs::write(&guest.state, &original).unwrap();
    let refused = guest
        .command()
        .args(["supervise", "check"])
        .output()
        .unwrap();
    let unchanged = fs::read(&guest.state).unwrap() == original;
    let foreign_live =
        foreign.0.try_wait().unwrap().is_none() && unsafe { libc::kill(child, 0) } == 0;
    assert!(supervisor.0.try_wait().unwrap().is_none());
    // Complete owned cleanup even when the checked refusal fails below.
    drop(foreign);
    fs::write(&guest.state, running.to_string()).unwrap();
    drop(resume);
    supervisor.stop();
    assert!(
        !refused.status.success(),
        "accepted foreign parent/child: {}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("native helper"));
    assert!(unchanged && foreign_live);
}

#[test]
fn supervisor_check_accepts_native_copies_and_refuses_another_state_owner() {
    for staging in ["run/safeyolo", "safeyolo"] {
        let guest = Guest::new();
        let directory = guest.directory.path().join(staging);
        fs::create_dir_all(&directory).unwrap();
        let helper = directory.join("safeyolo-guest");
        fs::copy(env!("CARGO_BIN_EXE_safeyolo-guest"), &helper).unwrap();
        guest.publish("exec /bin/sleep 120");
        let mut supervisor = Supervisor(
            guest
                .command_at(&helper)
                .arg("supervise")
                .process_group(0)
                .spawn()
                .unwrap(),
            guest.stop.clone(),
        );
        let running = guest.wait(|state| state["state"] == "running");
        assert_eq!(
            success(
                guest
                    .command()
                    .args(["supervise", "check"])
                    .output()
                    .unwrap()
            )["state"],
            "running"
        );
        let resume = supervisor.pause();
        let foreign = Guest::new();
        foreign.publish("exec /bin/sleep 120");
        let mut other = Supervisor::start(&foreign);
        let other_running = foreign.wait(|state| state["state"] == "running");
        let mut substituted = running.clone();
        for key in [
            "supervisor_pid",
            "supervisor_start_token",
            "supervisor_uid",
            "supervisor_parent_pid",
            "command_pid",
            "command_start_token",
            "heartbeat_at",
        ] {
            substituted[key] = other_running[key].clone();
        }
        let original = serde_json::to_vec(&substituted).unwrap();
        fs::write(&guest.state, &original).unwrap();
        let refused = guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap();
        let unchanged = fs::read(&guest.state).unwrap() == original;
        let other_live = other.0.try_wait().unwrap().is_none()
            && unsafe { libc::kill(other_running["command_pid"].as_i64().unwrap() as i32, 0) } == 0;
        fs::write(&guest.state, running.to_string()).unwrap();
        drop(resume);
        supervisor.stop();
        other.stop();
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("invocation"));
        assert!(unchanged && other_live);
    }
}

#[test]
fn supervisor_check_binds_the_owners_environment_selected_state() {
    let guest = Guest::new();
    guest.publish("exec /bin/sleep 120");
    let invocation = |owner: &Guest| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_safeyolo-guest"));
        command
            .arg("--context")
            .arg(&guest.context)
            .arg("--workspace")
            .arg(owner.directory.path())
            .env("SAFEYOLO_COMMAND_SUPERVISOR_STATE", &owner.state)
            .env("SAFEYOLO_COMMAND_SUPERVISOR_STOP", &owner.stop);
        command
    };
    let mut supervisor = Supervisor(
        invocation(&guest)
            .arg("supervise")
            .process_group(0)
            .spawn()
            .unwrap(),
        guest.stop.clone(),
    );
    let running = guest.wait(|state| state["state"] == "running");
    let check = || {
        let mut command = guest.command();
        command
            .env("SAFEYOLO_COMMAND_SUPERVISOR_STATE", &guest.state)
            .args(["supervise", "check"]);
        command
    };
    assert_eq!(success(check().output().unwrap())["state"], "running");
    let resume = supervisor.pause();
    let foreign = Guest::new();
    foreign.publish("exec /bin/sleep 120");
    let mut other = Supervisor(
        invocation(&foreign)
            .arg("supervise")
            .process_group(0)
            .spawn()
            .unwrap(),
        foreign.stop.clone(),
    );
    let other_running = foreign.wait(|state| state["state"] == "running");
    let mut substituted = running.clone();
    for key in [
        "supervisor_pid",
        "supervisor_start_token",
        "supervisor_uid",
        "supervisor_parent_pid",
        "command_pid",
        "command_start_token",
        "heartbeat_at",
    ] {
        substituted[key] = other_running[key].clone();
    }
    let original = serde_json::to_vec(&substituted).unwrap();
    fs::write(&guest.state, &original).unwrap();
    let refused = check().output().unwrap();
    let unchanged = fs::read(&guest.state).unwrap() == original;
    let other_live = other.0.try_wait().unwrap().is_none()
        && unsafe { libc::kill(other_running["command_pid"].as_i64().unwrap() as i32, 0) } == 0;
    fs::write(&guest.state, running.to_string()).unwrap();
    drop(resume);
    supervisor.stop();
    other.stop();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("invocation"));
    assert!(unchanged && other_live);
}

#[test]
fn occupied_supervisor_preserves_the_running_command() {
    let guest = Guest::new();
    guest.publish("exec sleep 60");
    let mut supervisor = Supervisor::start(&guest);
    let original = guest.wait(|state| state["state"] == "running");
    let rejected = guest.command().arg("supervise").output().unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("occupied"));
    assert_eq!(
        guest.read()["command_start_token"],
        original["command_start_token"]
    );
    supervisor.stop();
}

#[test]
fn restart_fences_an_orphan_before_starting_a_replacement() {
    let guest = Guest::new();
    guest.publish("exec sleep 60");
    let mut first = Supervisor::start(&guest);
    let original = guest.wait(|state| state["state"] == "running");
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    let mut replacement = Supervisor::start(&guest);
    let running = guest.wait(|state| {
        state["state"] == "running" && state["supervisor_pid"] != original["supervisor_pid"]
    });
    assert_ne!(running["command_pid"], original["command_pid"]);
    let pid = original["command_pid"].as_i64().unwrap();
    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
        assert_eq!(
            stat.rsplit_once(')').unwrap().1.split_whitespace().next(),
            Some("Z")
        );
    }
    replacement.stop();
}

#[test]
fn stale_process_identity_does_not_signal_an_unrelated_session() {
    use std::os::unix::process::CommandExt;
    let guest = Guest::new();
    let mut command = Command::new("/bin/sleep");
    command.arg("60");
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut unrelated = command.spawn().unwrap();
    guest.publish("touch unexpected-launch");
    let mut state = guest.read();
    state["state"] = json!("running");
    state["command_pid"] = json!(unrelated.id());
    state["command_start_token"] = json!("stale-start-token");
    fs::write(&guest.state, state.to_string()).unwrap();
    let rejected = guest.command().arg("supervise").output().unwrap();
    let alive = unrelated.try_wait().unwrap().is_none();
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    assert!(alive);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("identity cannot be verified"));
    assert_eq!(guest.read(), state);
    assert!(!guest.directory.path().join("unexpected-launch").exists());
}

#[test]
fn missing_process_identity_preserves_state_and_does_not_launch() {
    let guest = Guest::new();
    for (pid, token, state_name) in [
        (json!(std::process::id()), Value::Null, "running"),
        (Value::Null, Value::Null, "running"),
        (json!(-1), json!("some-token"), "running"),
        (json!(std::process::id()), json!("some-token"), "failed"),
    ] {
        guest.publish("touch unexpected-launch");
        let mut state = guest.read();
        state["state"] = json!(state_name);
        state["command_pid"] = pid;
        state["command_start_token"] = token;
        fs::write(&guest.state, state.to_string()).unwrap();
        let rejected = guest.command().arg("supervise").output().unwrap();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("unverified"));
        assert_eq!(guest.read(), state);
        assert!(!guest.directory.path().join("unexpected-launch").exists());
    }
}

#[test]
fn terminal_command_identity_must_be_empty_before_check_or_launch() {
    let guest = Guest::new();
    let invalid_fields = [
        json!(0),
        json!(-1),
        json!(i64::from(i32::MAX) + 1),
        json!(u64::MAX),
        json!(1.5),
        json!(true),
        json!(""),
        json!("123"),
        json!([]),
        json!({}),
    ];
    let mut retained = vec![
        (Value::Null, json!("retained-start-token")),
        (json!(std::process::id()), Value::Null),
        (json!(std::process::id()), json!("retained-start-token")),
    ];
    for value in invalid_fields {
        retained.push((value.clone(), json!("retained-start-token")));
        retained.push((Value::Null, value.clone()));
        retained.push((json!(std::process::id()), value));
    }
    for label in ["stopped", "failed", "exited"] {
        for (pid, token) in &retained {
            guest.publish("touch unexpected-launch");
            let mut state = guest.read();
            state["state"] = json!(label);
            state["command_pid"] = pid.clone();
            state["command_start_token"] = token.clone();
            let original = serde_json::to_vec(&state).unwrap();
            fs::write(&guest.state, &original).unwrap();
            for arguments in [&["supervise", "check"][..], &["supervise"][..]] {
                let rejected = guest.command().args(arguments).output().unwrap();
                assert!(!rejected.status.success(), "accepted {state}");
                assert!(rejected.stdout.is_empty());
                assert!(String::from_utf8_lossy(&rejected.stderr).contains("unverified"));
                assert_eq!(fs::read(&guest.state).unwrap(), original);
                assert!(!guest.stop.exists());
                assert!(!guest.directory.path().join("unexpected-launch").exists());
            }
        }
        guest.publish("touch unexpected-launch");
        let mut clean = guest.read();
        clean["state"] = json!(label);
        clean["command_pid"] = Value::Null;
        clean["command_start_token"] = Value::Null;
        fs::write(&guest.state, clean.to_string()).unwrap();
        assert_eq!(
            success(
                guest
                    .command()
                    .args(["supervise", "check"])
                    .output()
                    .unwrap()
            ),
            clean
        );
        assert!(guest.command().arg("supervise").status().unwrap().success());
        assert_eq!(guest.read(), clean);
    }
}

#[test]
fn partial_terminal_identity_does_not_hide_the_live_managed_command() {
    let guest = Guest::new();
    guest.publish("exec /bin/sleep 60");
    let mut supervisor = Supervisor::start(&guest);
    let running = guest.wait(|state| state["state"] == "running");
    let resume = supervisor.pause();
    for label in ["stopped", "failed", "exited"] {
        let mut partial = running.clone();
        partial["state"] = json!(label);
        partial["command_pid"] = Value::Null;
        let original = serde_json::to_vec(&partial).unwrap();
        fs::write(&guest.state, &original).unwrap();
        let rejected = guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert_eq!(fs::read(&guest.state).unwrap(), original);
        assert!(supervisor.0.try_wait().unwrap().is_none());
        let pid = running["command_pid"].as_i64().unwrap();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        assert_ne!(
            stat.rsplit_once(')').unwrap().1.split_whitespace().next(),
            Some("Z")
        );
    }
    fs::write(&guest.state, running.to_string()).unwrap();
    drop(resume);
    supervisor.stop();
}

#[test]
fn failed_observation_and_another_run_do_not_claim_running() {
    let guest = Guest::new();
    fs::create_dir(&guest.records).unwrap();
    let corrupt = guest.records.join("corrupt.json");
    fs::write(&corrupt, "{").unwrap();
    let output = guest.command().args(["observe", "check"]).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(corrupt.exists());
    fs::remove_file(corrupt).unwrap();
    guest.publish("touch unexpected-launch");
    let mut state = guest.read();
    state["generation"] = json!("another-run");
    fs::write(&guest.state, state.to_string()).unwrap();
    assert!(!guest.command().arg("supervise").status().unwrap().success());
    assert!(!guest.directory.path().join("unexpected-launch").exists());
}

#[test]
fn observed_exec_keeps_argv_and_cleans_a_failed_exec_record() {
    let guest = Guest::new();
    let output = guest
        .command()
        .args([
            "observe",
            "exec",
            "--",
            "/bin/printf",
            "%s",
            "literal $(value) ' spaces",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"literal $(value) ' spaces");
    let output = guest
        .command()
        .args(["observe", "exec", "--", "/missing-fixture-program"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let checked = guest.command().args(["observe", "check"]).output().unwrap();
    assert!(checked.status.success());
    assert_eq!(checked.stdout, b"stopped\n");
}

#[test]
fn observed_exec_preserves_non_utf8_paths_arguments_and_script_fallback() {
    let mut guest = Guest::new();
    let argument = OsString::from_vec(vec![0x80]);
    let output = guest
        .command()
        .args(["observe", "exec", "--", "/bin/printf", "%s"])
        .arg(&argument)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, [0x80]);
    guest.records = guest
        .directory
        .path()
        .join(OsString::from_vec(b"records-\xff".to_vec()));
    let executable = guest
        .directory
        .path()
        .join(OsString::from_vec(b"printf-\xff".to_vec()));
    std::os::unix::fs::symlink("/bin/printf", &executable).unwrap();
    let output = guest
        .command()
        .args(["observe", "exec", "--"])
        .arg(&executable)
        .arg("%s")
        .arg(&argument)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, [0x80]);

    fs::remove_file(&executable).unwrap();
    fs::write(&executable, b"printf '%s' \"$1\"\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let output = guest
        .command()
        .args(["observe", "exec", "--"])
        .arg(&executable)
        .arg(&argument)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, [0x80]);

    fs::remove_file(&executable).unwrap();
    let missing = guest
        .command()
        .args(["observe", "exec", "--"])
        .arg(&executable)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let checked = guest.command().args(["observe", "check"]).output().unwrap();
    assert!(checked.status.success());
    assert_eq!(checked.stdout, b"stopped\n");
    let invalid_id = guest.command().arg("probe").arg(argument).output().unwrap();
    assert_eq!(invalid_id.status.code(), Some(2));
}
