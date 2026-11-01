//! Real process checks for the Linux guest executable; systrap proof is separate.

use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
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

#[test]
fn extra_mount_pin_holds_native_directory_descriptors_and_preserves_names() {
    use std::io::{BufRead, BufReader, Write};
    let guest = Guest::new();
    for name in [
        "ordinary",
        "\r",
        "a\nb",
        "trailing\n",
        "\n\n",
        "quoted '\" \\\t",
    ] {
        let directory = guest.directory.path().join(name);
        fs::create_dir(&directory).unwrap();
        let alias = guest.directory.path().join("source-alias");
        std::os::unix::fs::symlink(&directory, &alias).unwrap();
        for path in [&directory, &alias] {
            let mut child = guest
                .command()
                .args(["extra-mount", "command-fixture-run", "pin"])
                .arg(path)
                .arg("create")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut reader = BufReader::new(child.stdout.take().unwrap());
            let mut fields = Vec::new();
            for _ in 0..3 {
                let mut field = Vec::new();
                reader.read_until(0, &mut field).unwrap();
                assert_eq!(field.pop(), Some(0));
                fields.push(String::from_utf8(field).unwrap());
            }
            assert_eq!(fields[0], child.id().to_string());
            assert_eq!(PathBuf::from(&fields[1]), directory.canonicalize().unwrap());
            let pinned = fs::metadata(format!("/proc/{}/fd/{}", fields[0], fields[2])).unwrap();
            let original = fs::metadata(&directory).unwrap();
            assert_eq!(
                (pinned.dev(), pinned.ino()),
                (original.dev(), original.ino())
            );
            child.stdin.take().unwrap().write_all(b"release\n").unwrap();
            assert!(child.wait().unwrap().success());
        }
        fs::remove_file(alias).unwrap();
    }
}

#[test]
fn extra_mount_refuses_stale_generation_and_resolved_control_paths() {
    let guest = Guest::new();
    let target = guest.directory.path().join("future-directory");
    let refused = guest
        .command()
        .args(["extra-mount", "old-run", "prepare"])
        .arg(&target)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("generation changed"));
    assert!(!target.exists());
    std::os::unix::fs::symlink("/proc", guest.directory.path().join("control-alias")).unwrap();
    let refused = guest
        .command()
        .args(["extra-mount", "command-fixture-run", "prepare"])
        .arg(
            guest
                .directory
                .path()
                .join("control-alias/extra-mount-refusal"),
        )
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("reserved"));
    let result = success(
        guest
            .command()
            .args(["extra-mount", "command-fixture-run", "inspect"])
            .arg(guest.directory.path())
            .output()
            .unwrap(),
    );
    assert!(result["mount"].is_null());
    let result = success(
        guest
            .command()
            .args(["extra-mount", "command-fixture-run", "unmount"])
            .arg(guest.directory.path())
            .arg(u64::MAX.to_string())
            .output()
            .unwrap(),
    );
    assert!(result["expected_mount"].is_null());
    assert!(guest.directory.path().is_dir());
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
fn live_stderr_snapshots_preserve_the_command_and_terminal_diagnostics() {
    let guest = Guest::new();
    let first = b"\x1b[31mlive diagnostic\x1b[0m\n";
    let suffix = b"\x1b]0;hidden-title\x07second diagnostic\x01\n";
    let mut second = vec![b'x'; 20_000];
    second.extend_from_slice(suffix);
    let final_bytes = b"terminal diagnostic\n";
    fs::write(guest.directory.path().join("first"), first).unwrap();
    fs::write(guest.directory.path().join("second"), &second).unwrap();
    fs::write(guest.directory.path().join("final"), final_bytes).unwrap();
    guest.publish(
        "cat first >&2; while test ! -f append; do sleep 0.02; done; \
         cat second >&2; while test ! -f finish; do sleep 0.02; done; \
         cat final >&2; exit 23",
    );
    let mut supervisor = Supervisor::start(&guest);
    let original = guest.wait(|state| state["state"] == "running");
    let mut raw = Vec::from(first);
    for (expected, length) in [
        ("live diagnostic\n".to_owned(), first.len()),
        (
            "x".repeat(16 * 1024 - suffix.len()) + "second diagnostic\\x01\n",
            first.len() + second.len(),
        ),
    ] {
        guest.wait(|state| state["last_stderr_bytes"] == length);
        let checked = success(
            guest
                .command()
                .args(["supervise", "check"])
                .output()
                .unwrap(),
        );
        assert_eq!(checked["state"], "running");
        for key in [
            "command_pid",
            "command_start_token",
            "supervisor_pid",
            "supervisor_start_token",
            "supervision_id",
            "generation",
            "restart_count",
        ] {
            assert_eq!(checked[key], original[key], "changed {key}");
        }
        assert!(supervisor.0.try_wait().unwrap().is_none());
        assert_eq!(fs::metadata(&guest.state).unwrap().mode() & 0o777, 0o600);
        assert_eq!(checked["last_stderr"], expected);
        assert_eq!(checked["last_stderr_truncated"], length > 16 * 1024);
        assert_eq!(
            checked["last_stderr_sha256"],
            ring::digest::digest(&ring::digest::SHA256, &raw)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        if length == first.len() {
            raw.extend_from_slice(&second);
            fs::write(guest.directory.path().join("append"), b"").unwrap();
        }
    }
    fs::write(guest.directory.path().join("finish"), b"").unwrap();
    guest.wait(|state| state["state"] == "restarting" && state["last_exit_code"] == 23);
    supervisor.stop();
    let stopped = success(
        guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap(),
    );
    raw.extend_from_slice(final_bytes);
    assert_eq!(stopped["restart_count"], 1);
    assert_eq!(stopped["last_exit_code"], 23);
    assert_eq!(stopped["last_exit_reason"], "command-exit-nonzero");
    assert_eq!(stopped["last_stderr_bytes"], raw.len());
    assert_eq!(stopped["last_stderr_truncated"], true);
    assert_eq!(
        stopped["last_stderr"],
        "x".repeat(16 * 1024 - suffix.len() - final_bytes.len())
            + "second diagnostic\\x01\nterminal diagnostic\n"
    );
    assert_eq!(
        stopped["last_stderr_sha256"],
        ring::digest::digest(&ring::digest::SHA256, &raw)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
}

#[test]
fn live_stderr_does_not_overwrite_replacement_supervision_or_run() {
    for key in ["supervision_id", "generation"] {
        let guest = Guest::new();
        guest.publish("echo owned-diagnostic >&2; exec sleep 60");
        let mut supervisor = Supervisor::start(&guest);
        let mut replacement = guest.wait(|state| state["last_stderr"] == "owned-diagnostic\n");
        replacement[key] = json!("replacement");
        replacement["last_stderr"] = json!("replacement-diagnostic");
        let original = serde_json::to_vec(&replacement).unwrap();
        let temporary = guest.state.with_extension("replacement");
        fs::write(&temporary, &original).unwrap();
        fs::rename(temporary, &guest.state).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = supervisor.0.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(Instant::now() < deadline, "old supervisor did not stop");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read(&guest.state).unwrap(), original);
    }
}

#[test]
#[ignore = "requires guest root to check a different UID with the real diagnostic reader"]
fn live_stderr_refuses_another_uid() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let guest = Guest::new();
    // Allow the other UID to traverse the fixture and execute the helper.
    // Only the supervisor state should prevent the diagnostic read.
    fs::set_permissions(guest.directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let helper = guest.directory.path().join("safeyolo-guest");
    fs::copy(env!("CARGO_BIN_EXE_safeyolo-guest"), &helper).unwrap();
    guest.publish("echo private-diagnostic >&2; exec sleep 60");
    let mut supervisor = Supervisor::start(&guest);
    let running = guest.wait(|state| state["last_stderr"] == "private-diagnostic\n");
    let refused = guest
        .command_at(&helper)
        .args(["supervise", "check"])
        .uid(65534)
        .gid(65534)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("Permission denied"));
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("private-diagnostic"));
    let checked = success(
        guest
            .command()
            .args(["supervise", "check"])
            .output()
            .unwrap(),
    );
    assert_eq!(checked["last_stderr"], running["last_stderr"]);
    assert_eq!(
        checked["command_start_token"],
        running["command_start_token"]
    );
    assert_eq!(checked["restart_count"], 0);
    supervisor.stop();
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
    // A quiet replacement keeps the prior failure diagnostic across heartbeats.
    let heartbeat = running["heartbeat_at"].as_f64().unwrap();
    let later = guest.wait(|state| state["heartbeat_at"].as_f64().unwrap() > heartbeat);
    assert_eq!(later["last_stderr"], running["last_stderr"]);
    assert_eq!(later["last_stderr_bytes"], running["last_stderr_bytes"]);
    assert_eq!(later["last_stderr_sha256"], running["last_stderr_sha256"]);
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
    assert!(String::from_utf8_lossy(&refused.stderr).contains(
        "guest supervisor executable is not the installed guest helper; command state is unknown"
    ));
    assert!(unchanged && foreign_live);
}

#[test]
fn supervisor_check_accepts_native_copies_and_refuses_another_state_owner() {
    for staging in ["run/safeyolo", "safeyolo"] {
        let guest = Guest::new();
        let directory = guest.directory.path().join(staging);
        fs::create_dir_all(&directory).unwrap();
        let helper = directory.join("safeyolo-guest");
        // Copy in a child so concurrent test forks cannot inherit a writable
        // destination descriptor and keep Linux exec busy after copying returns.
        let copied = Command::new("/bin/cp")
            .arg(env!("CARGO_BIN_EXE_safeyolo-guest"))
            .arg(&helper)
            .output()
            .unwrap();
        assert!(
            copied.status.success(),
            "cannot stage native helper: {}",
            String::from_utf8_lossy(&copied.stderr)
        );
        let source = fs::metadata(env!("CARGO_BIN_EXE_safeyolo-guest")).unwrap();
        let copy = fs::metadata(&helper).unwrap();
        assert_ne!((source.dev(), source.ino()), (copy.dev(), copy.ino()));
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
    let executable_directory = guest
        .directory
        .path()
        .join(OsString::from_vec(b"bin-\xff".to_vec()));
    fs::create_dir(&executable_directory).unwrap();
    // Multicall implementations dispatch by basename; keep printf while
    // exercising a non-UTF8 executable path.
    let executable = executable_directory.join("printf");
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
    let executable = guest
        .directory
        .path()
        .join(OsString::from_vec(b"printf-\xff".to_vec()));
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
