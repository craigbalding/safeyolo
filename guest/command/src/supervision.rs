use crate::{
    Error, Paths, command_paths, generation, live_token, now, process, read_json, write_json,
};
use ring::digest::{Context, Digest, SHA256};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, OpenOptionsExt},
            process::{CommandExt, ExitStatusExt},
        },
    },
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const MAX_FAILURES: u64 = 5;
const STABLE_SECONDS: f64 = 60.0;
const INITIAL_BACKOFF: f64 = 0.25;
const MAX_BACKOFF: f64 = 10.0;
const TAIL_BYTES: usize = 16 * 1024;
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

fn stopping(paths: &Paths) -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst) || paths.stop.exists()
}

fn state(paths: &Paths) -> Result<Value, Error> {
    let value = read_json(&paths.state, 128 * 1024)?;
    if value["schema_version"] != 1
        || value["supervision_id"].as_str().is_none_or(str::is_empty)
        || value["started_at"].is_null()
        || value["command"]
            .as_str()
            .is_none_or(|command| command.trim().is_empty())
        || !matches!(
            value["state"].as_str(),
            Some("starting" | "running" | "restarting" | "stopped" | "failed" | "exited")
        )
    {
        return Err("unsupported or invalid command supervisor state".into());
    }
    Ok(value)
}

fn command_identity(value: &Value) -> Result<Option<(i32, &str)>, Error> {
    if value["command_pid"].is_null()
        && value["command_start_token"].is_null()
        && value["state"] != "running"
    {
        return Ok(None);
    }
    Ok(Some((
        value["command_pid"]
            .as_i64()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("saved command PID is missing or invalid; termination is unverified")?,
        value["command_start_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or("saved command identity is missing or invalid; termination is unverified")?,
    )))
}

fn save(paths: &Paths, value: &mut Value) -> Result<(), Error> {
    let current = state(paths)?;
    if current["command"] != value["command"]
        || current["started_at"] != value["started_at"]
        || current["supervision_id"] != value["supervision_id"]
        || current["generation"] != value["generation"]
    {
        return Err("supervisor ownership changed; replacement state was left intact".into());
    }
    value["updated_at"] = json!(now());
    write_json(&paths.state, value)
}

struct Tail {
    data: Vec<u8>,
    total: u64,
    digest: Context,
}

impl Tail {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            total: 0,
            digest: Context::new(&SHA256),
        }
    }
    fn add(&mut self, bytes: &[u8]) {
        self.digest.update(bytes);
        self.total += bytes.len() as u64;
        self.data.extend_from_slice(bytes);
        if self.data.len() > TAIL_BYTES {
            self.data.drain(..self.data.len() - TAIL_BYTES);
        }
    }
    fn finish(self, value: &mut Value) {
        value["last_stderr"] = json!(sanitize(&String::from_utf8_lossy(&self.data)));
        value["last_stderr_bytes"] = json!(self.total);
        value["last_stderr_truncated"] = json!(self.total > TAIL_BYTES as u64);
        value["last_stderr_sha256"] = json!(
            self.digest
                .finish()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
    }
}

// Strip CSI and OSC escapes before diagnostics reach an operator terminal.
fn sanitize(text: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            match chars.next() {
                Some('[') => {
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(next) = chars.next() {
                        if next == '\u{7}'
                            || (next == '\u{1b}' && chars.next_if_eq(&'\\').is_some())
                        {
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if character < ' ' && !matches!(character, '\n' | '\t' | '\r') {
            result.push_str(&format!("\\x{:02x}", character as u32));
        } else {
            result.push(character);
        }
    }
    result
}

fn signal_group(pid: i32, token: &str, signal: i32) -> Result<(), Error> {
    let Some((current, _, group)) = process(pid)? else {
        return Ok(());
    };
    if current != token || group != pid || unsafe { libc::getsid(pid) } != pid {
        return Ok(());
    }
    if unsafe { libc::kill(-pid, signal) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn group_live(group: i32) -> Result<bool, Error> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        if let Some((_, state, current)) = process(pid)?
            && current == group
            && !matches!(state, 'Z' | 'X')
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn clean_group(pid: i32, token: &str) -> Result<(), Error> {
    // Check the leader's identity and session before using a saved group.
    if process(pid)?.is_none_or(|(current, _, group)| current != token || group != pid)
        || unsafe { libc::getsid(pid) } != pid
    {
        if group_live(pid)? {
            return Err("command group is occupied but its saved identity cannot be verified; active work was left intact".into());
        }
        return Ok(());
    }
    signal_group(pid, token, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    while group_live(pid)? && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if group_live(pid)? {
        signal_group(pid, token, libc::SIGKILL)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while group_live(pid)? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if group_live(pid)? {
            return Err("owned command group did not stop before the cleanup deadline".into());
        }
    }
    Ok(())
}

fn drain(child: &mut Child, tail: &mut Tail) -> Result<(), Error> {
    let stream = child.stderr.as_mut().ok_or("command stderr is missing")?;
    let mut bytes = [0; 4096];
    // A continuously writing child must not starve stop/heartbeat checks.
    for _ in 0..16 {
        match stream.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => tail.add(&bytes[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn attempt(paths: &Paths, value: &mut Value) -> Result<std::process::ExitStatus, Error> {
    let command = value["command"].as_str().ok_or("command is missing")?;
    let mut executable = Command::new("/bin/bash");
    executable
        .args(["-lc", command])
        .current_dir(&paths.workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    unsafe {
        executable.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = executable.spawn()?;
    let pid = child.id() as i32;
    let token = process(pid)?
        .map(|(token, _, _)| token)
        .ok_or("cannot identify supervised command")?;
    let result = (|| {
        let descriptor = child
            .stderr
            .as_ref()
            .ok_or("command stderr is missing")?
            .as_raw_fd();
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        value["state"] = json!("running");
        value["command_pid"] = json!(pid);
        value["command_start_token"] = json!(token);
        value["attempt_started_at"] = json!(now());
        value["heartbeat_at"] = json!(now());
        value["next_restart_at"] = Value::Null;
        save(paths, value)?;
        let mut tail = Tail::new();
        let mut heartbeat = Instant::now();
        loop {
            drain(&mut child, &mut tail)?;
            if stopping(paths) {
                clean_group(pid, &token)?;
            }
            // Leave an exited leader unreaped until its owned descendants stop.
            if process(pid)?.is_some_and(|(_, state, _)| matches!(state, 'Z' | 'X')) {
                clean_group(pid, &token)?;
            }
            if let Some(status) = child.try_wait()? {
                drain(&mut child, &mut tail)?;
                tail.finish(value);
                return Ok(status);
            }
            if heartbeat.elapsed() >= Duration::from_secs(1) {
                value["heartbeat_at"] = json!(now());
                save(paths, value)?;
                heartbeat = Instant::now();
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        clean_group(pid, &token)?;
        let _ = child.try_wait()?;
        value["command_pid"] = Value::Null;
        value["command_start_token"] = Value::Null;
    }
    result
}

pub(super) fn run(paths: &Paths) -> Result<i32, Error> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(paths.state.with_extension("lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("command supervisor is occupied; active work was left intact".into());
    }
    unsafe {
        libc::signal(
            libc::SIGTERM,
            request_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            request_stop as *const () as libc::sighandler_t,
        );
    }
    let mut value = state(paths)?;
    let generation = generation(paths)?;
    if value["generation"].as_str() != Some(&generation) {
        return Err(
            "command supervisor belongs to another run; publish fresh command state".into(),
        );
    }
    let saved_command = command_identity(&value)?;
    if matches!(
        value["state"].as_str(),
        Some("stopped" | "failed" | "exited")
    ) {
        if saved_command.is_some() {
            return Err(
                "terminal command state retains a process identity; termination is unverified"
                    .into(),
            );
        }
        return Ok(0);
    }
    let mut failures = value["consecutive_failures"].as_u64().unwrap_or(0);
    let mut restarts = value["restart_count"].as_u64().unwrap_or(0);
    if let Some((pid, token)) = saved_command {
        clean_group(pid, token)?;
    }
    if value["state"] == "running" {
        if now() - value["attempt_started_at"].as_f64().unwrap_or(now()) >= STABLE_SECONDS {
            failures = 0;
        }
        failures += 1;
        value["last_exit_reason"] = json!("supervisor-restarted");
    }
    value["runtime_owner"] = json!("guest-pid1");
    value["guest_helper_version"] = json!(crate::version());
    value["supervisor_parent_pid"] = json!(unsafe { libc::getppid() });
    value["supervisor_uid"] = json!(unsafe { libc::getuid() });
    value["supervisor_pid"] = json!(std::process::id());
    value["supervisor_start_token"] =
        json!(live_token(std::process::id() as i32)?.ok_or("cannot identify supervisor")?);
    loop {
        value["command_pid"] = Value::Null;
        value["command_start_token"] = Value::Null;
        value["consecutive_failures"] = json!(failures);
        value["restart_count"] = json!(restarts);
        if stopping(paths) || failures >= MAX_FAILURES {
            value["state"] = json!(if stopping(paths) { "stopped" } else { "failed" });
            value["next_restart_at"] = Value::Null;
            save(paths, &mut value)?;
            return Ok(if stopping(paths) { 0 } else { 1 });
        }
        let started = Instant::now();
        let status = match attempt(paths, &mut value) {
            Ok(status) => status,
            Err(error) => {
                value["state"] = json!("failed");
                value["last_exit_reason"] = json!("supervisor-error");
                value["last_stderr"] = json!(sanitize(&error.to_string()));
                // Keep the saved process identity when cleanup failed. A
                // failed owner is not proof that its command group stopped.
                value["next_restart_at"] = Value::Null;
                save(paths, &mut value)?;
                return Err(error);
            }
        };
        let uptime = started.elapsed().as_secs_f64();
        if uptime >= STABLE_SECONDS {
            failures = 0;
        }
        let intentional = stopping(paths);
        if !intentional {
            failures += 1;
            restarts += 1;
        }
        value["last_exit_code"] = json!(status.code());
        value["last_exit_signal"] = json!(status.signal());
        value["last_exit_reason"] = json!(if intentional {
            "intentional-stop"
        } else if status.success() {
            "command-exit-clean"
        } else if status.signal().is_some() {
            "command-signal"
        } else {
            "command-exit-nonzero"
        });
        value["last_uptime_seconds"] = json!(uptime);
        if intentional || failures >= MAX_FAILURES {
            continue;
        }
        let delay = (INITIAL_BACKOFF * 2_f64.powi((failures - 1) as i32)).min(MAX_BACKOFF);
        value["state"] = json!("restarting");
        value["command_pid"] = Value::Null;
        value["command_start_token"] = Value::Null;
        value["restart_count"] = json!(restarts);
        value["consecutive_failures"] = json!(failures);
        value["next_restart_at"] = json!(now() + delay);
        save(paths, &mut value)?;
        let deadline = Instant::now() + Duration::from_secs_f64(delay);
        while Instant::now() < deadline && !stopping(paths) {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn check_process_owner(pid: i32, uid: Option<u64>, parent: i64) -> Result<(), Error> {
    let bytes = fs::read(format!("/proc/{pid}/status"))?;
    // Name may contain arbitrary filename bytes; only UID/PPid are compared.
    let status = String::from_utf8_lossy(&bytes);
    let actual_parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse::<i64>().ok());
    let actual_uid = status.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .ok()
    });
    if actual_parent != Some(parent)
        || uid.is_some_and(|uid| actual_uid.as_deref() != Some(&[uid, uid, uid, uid]))
    {
        return Err("guest process ownership or ancestry changed; command state is unknown".into());
    }
    Ok(())
}

fn executable_digest(mut file: fs::File) -> Result<Digest, Error> {
    let mut digest = Context::new(&SHA256);
    let mut bytes = [0; 64 * 1024];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            return Ok(digest.finish());
        }
        digest.update(&bytes[..count]);
    }
}

fn check_native_supervisor(paths: &Paths, pid: i32) -> Result<(), Error> {
    let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
    let executable = fs::File::open(proc.join("exe"))?;
    let helper = fs::File::open("/proc/self/exe")?;
    let actual = executable.metadata()?;
    let expected = helper.metadata()?;
    // PID 1 can run a tmpfs copy at /run/safeyolo while the checker uses the
    // host-staged /safeyolo helper. Compare images when file identity differs.
    if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
        && (actual.len() != expected.len()
            || executable_digest(executable)?.as_ref() != executable_digest(helper)?.as_ref())
    {
        return Err(
            "guest supervisor executable is not the native helper; command state is unknown".into(),
        );
    }
    let cmdline = fs::read(proc.join("cmdline"))?;
    let mut arguments: Vec<_> = cmdline
        .strip_suffix(&[0])
        .ok_or("guest supervisor invocation is missing; command state is unknown")?
        .split(|byte| *byte == 0)
        .skip(1)
        .map(|argument| std::ffi::OsString::from_vec(argument.to_vec()))
        .collect();
    let owner_paths = command_paths(&mut arguments)?;
    let directory = fs::read_link(proc.join("cwd"))?;
    if arguments.len() != 1
        || arguments[0] != "supervise"
        || fs::canonicalize(directory.join(owner_paths.state))? != fs::canonicalize(&paths.state)?
        || fs::canonicalize(directory.join(owner_paths.context))?
            != fs::canonicalize(&paths.context)?
    {
        return Err(
            "guest supervisor invocation does not own this command state; command state is unknown"
                .into(),
        );
    }
    Ok(())
}

fn check_heartbeat(value: &Value, current_time: f64) -> Result<(), Error> {
    let heartbeat = value["heartbeat_at"]
        .as_f64()
        .ok_or("guest command heartbeat is missing or invalid; command state is unknown")?;
    if !(0.0..=5.0).contains(&(current_time - heartbeat)) {
        return Err(
            "guest command heartbeat is stale or in the future; command state is unknown".into(),
        );
    }
    Ok(())
}

/// Check identities and freshness in the guest PID and clock domains. A host
/// transport PID or an old heartbeat cannot establish a running command.
pub(super) fn check(paths: &Paths) -> Result<i32, Error> {
    let value = state(paths)?;
    if value["generation"].as_str() != Some(&generation(paths)?) {
        return Err("command supervisor belongs to another run; command state is unknown".into());
    }
    let saved_command = command_identity(&value)?;
    if matches!(
        value["state"].as_str(),
        Some("stopped" | "failed" | "exited")
    ) && saved_command.is_some()
    {
        return Err(
            "terminal command state retains a process identity; termination is unverified".into(),
        );
    }
    if matches!(value["state"].as_str(), Some("running" | "restarting")) {
        if value["runtime_owner"] != "guest-pid1" {
            return Err("guest supervisor owner is unverified; command state is unknown".into());
        }
        let pid = value["supervisor_pid"]
            .as_i64()
            .and_then(|pid| i32::try_from(pid).ok())
            .unwrap_or(0);
        let token = value["supervisor_start_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or("guest supervisor identity is missing; command state is unknown")?;
        if live_token(pid)?.as_deref() != Some(token) || pid <= 0 {
            return Err(
                "guest supervisor identity is stale or missing; command state is unknown".into(),
            );
        }
        check_process_owner(
            pid,
            Some(
                value["supervisor_uid"]
                    .as_u64()
                    .ok_or("guest supervisor UID is missing; command state is unknown")?,
            ),
            value["supervisor_parent_pid"]
                .as_i64()
                .ok_or("guest supervisor parent is missing; command state is unknown")?,
        )?;
        check_native_supervisor(paths, pid)?;
    }
    if value["state"] == "running" {
        let (pid, token) = saved_command.ok_or("guest command identity is missing")?;
        if live_token(pid)?.as_deref() != Some(token) {
            return Err(
                "guest command identity is stale or missing; command state is unknown".into(),
            );
        }
        check_process_owner(
            pid,
            // A supervised command may legitimately change UID (guest sudo).
            // Its birth and parent bind it to the verified supervisor.
            None,
            value["supervisor_pid"]
                .as_i64()
                .ok_or("guest supervisor PID is missing")?,
        )?;
        // The supervisor writes this timestamp with guest SystemTime. Check
        // its freshness here, rather than comparing it with the host clock.
        check_heartbeat(&value, now())?;
    } else if let Some((pid, _)) = saved_command
        && group_live(pid)?
    {
        return Err("guest command group remains occupied; command state is unknown".into());
    }
    println!("{}", serde_json::to_string(&value)?);
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn heartbeat_uses_only_the_writer_clock_with_the_retained_bound() {
        use serde_json::{Value, json};
        for guest_time in [100.0, 10_000_000_000.0] {
            for age in [0.0, 1.0, 5.0] {
                assert!(
                    super::check_heartbeat(&json!({"heartbeat_at":guest_time - age}), guest_time)
                        .is_ok()
                );
            }
            for heartbeat in [
                json!(guest_time + 0.125),
                json!(guest_time - 5.125),
                Value::Null,
                json!("100"),
                json!(false),
                json!([]),
                json!({}),
            ] {
                assert!(
                    super::check_heartbeat(&json!({"heartbeat_at":heartbeat}), guest_time).is_err()
                );
            }
            assert!(super::check_heartbeat(&json!({}), guest_time).is_err());
        }
    }

    #[test]
    fn sanitizes_terminal_controls() {
        assert_eq!(
            super::sanitize("a\u{1b}[31mb\u{1b}]0;title\u{7}\u{1}c"),
            "ab\\x01c"
        );
    }
}
