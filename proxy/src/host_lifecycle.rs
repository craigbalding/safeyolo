//! Installed Command Centre agent state and fixed lifecycle operations.

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

use crate::{Error, host_agents::Agent};

static LISTENER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn agent_dir(name: &str) -> PathBuf {
    crate::host_platform::config_dir().join("agents").join(name)
}

fn launch_path(name: &str) -> PathBuf {
    agent_dir(name).join("current-launch.json")
}

fn supervisor_path(name: &str) -> PathBuf {
    agent_dir(name).join("home/.safeyolo-command-supervisor.json")
}

pub(crate) struct SetupLock(File);

impl SetupLock {
    pub(crate) fn acquire_in(
        directory: &std::path::Path,
        deadline: Option<std::time::Instant>,
    ) -> Result<Self, Error> {
        // Agent home is writable by the guest UID. Keeping this host lock
        // there lets the guest unlink it and make concurrent host callers
        // lock different inodes while the first sandbox is still starting.
        std::fs::create_dir_all(directory)?;
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(directory)?;
        let metadata = opened.metadata()?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("unsafe host state directory for agent".into());
        }
        let name = std::ffi::CString::new("host-setup.lock")?;
        let descriptor = unsafe {
            libc::openat(
                opened.as_raw_fd(),
                name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("unsafe host setup lock".into());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        lock_until(&file, deadline)?;
        Ok(Self(file))
    }
}

impl Drop for SetupLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

struct LaunchLock(File);

impl LaunchLock {
    fn acquire(name: &str) -> Result<Self, Error> {
        Self::acquire_in(&agent_dir(name), None)
    }

    fn acquire_in(
        directory: &std::path::Path,
        deadline: Option<std::time::Instant>,
    ) -> Result<Self, Error> {
        let path = directory.join("current-launch.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .truncate(false)
            .open(path)?;
        lock_until(&file, deadline)?;
        Ok(Self(file))
    }
}

fn lock_until(file: &File, deadline: Option<std::time::Instant>) -> Result<(), Error> {
    loop {
        let flags = libc::LOCK_EX | if deadline.is_some() { libc::LOCK_NB } else { 0 };
        if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err("host recovery deadline expired while acquiring the agent lock; guest completion is unverified".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Use the existing PID-1 supervisor through the shared home, independent of
/// SSH, host transport liveness, the Admin API and a coding-agent model.
pub(crate) fn recover_guest_probe(
    root: &std::path::Path,
    name: &str,
    timeout: std::time::Duration,
) -> Result<Value, Error> {
    if !crate::host_platform::valid_agent_name(name) || timeout.is_zero() {
        return Err("recovery needs a valid agent name and positive deadline".into());
    }
    let deadline = std::time::Instant::now() + timeout;
    let directory = root.join("agents").join(name);
    let home = directory.join("home");
    let share = directory.join("config-share");
    if !home.is_dir() || !share.join("safeyolo-guest").is_file() {
        return Err("required native guest helper/home is missing; stage the installed guest assets and boot this agent first".into());
    }
    let _setup = SetupLock::acquire_in(&directory, Some(deadline))?;
    let _launch = LaunchLock::acquire_in(&directory, Some(deadline))?;
    if let Some(launch) = crate::guest_commands::read_state(&directory.join("current-launch.json"))?
        && matches!(
            launch["state"].as_str(),
            Some("starting" | "launching" | "stopping" | "finishing")
        )
    {
        return Err("a launcher is active or transitioning; its state was left intact".into());
    }
    let context = crate::guest_commands::read_state(&share.join("host-launch-context.json"))?
        .ok_or("host launch context is missing")?;
    let generation = context["generation"]
        .as_str()
        .filter(|generation| !generation.is_empty())
        .ok_or("current-run generation is missing")?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let command = format!("exec {} probe {}", crate::guest_commands::HELPER, id);
    crate::guest_commands::publish(&home, &share, name, &command, &id, generation)?;
    let state_path = home.join(".safeyolo-command-supervisor.json");
    let result = (|| {
        loop {
            let state = crate::guest_commands::read_state(&state_path)?
                .ok_or("supervisor ownership disappeared; completion is unverified")?;
            if state["supervision_id"] != id
                || state["command"] != command
                || state["generation"] != generation
            {
                return Err(
                    "supervisor ownership changed; replacement state was left intact".into(),
                );
            }
            if matches!(
                state["state"].as_str(),
                Some("stopped" | "failed" | "exited")
            ) {
                if !state["command_pid"].is_null() || !state["command_start_token"].is_null() {
                    return Err(
                        "guest command identity remains occupied; completion is unverified".into(),
                    );
                }
                let result: Value =
                    serde_json::from_str(state["last_stderr"].as_str().unwrap_or("")).map_err(
                        |error| format!("guest did not record a complete probe result: {error}"),
                    )?;
                if result["probe_id"] != id
                    || state["last_stderr_truncated"] == true
                    || state["last_exit_code"] != 0
                {
                    return Err("guest probe result or exit status is incomplete; inspect the command supervisor state".into());
                }
                return Ok(
                    json!({"generation":generation,"supervision_id":id,"result":result,"state":state}),
                );
            }
            if std::time::Instant::now() >= deadline {
                return Err("host recovery deadline expired; guest completion is unverified; inspect the command supervisor state".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    })();
    // A fence prevents replay but does not claim termination. Never alter a
    // replacement command or signal a host PID copied from guest-writable state.
    if let Some(current) = crate::guest_commands::read_state(&state_path)?
        && current["supervision_id"] == id
    {
        crate::guest_commands::request_stop(&home, &share, &id)?;
    }
    result
}

impl Drop for LaunchLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn write_json(path: &std::path::Path, value: &Value) -> Result<(), Error> {
    let parent = path.parent().ok_or("state has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn update_launch(
    name: &str,
    launch_id: &str,
    changes: &serde_json::Map<String, Value>,
) -> Result<(), Error> {
    let _lock = LaunchLock::acquire(name)?;
    let path = launch_path(name);
    let mut record = read_json(&path)?.ok_or("No matching coding-agent launch")?;
    if record.get("launch_id").and_then(Value::as_str) != Some(launch_id) {
        return Err("The coding-agent launch changed; refusing to update another run".into());
    }
    if matches!(
        record.get("state").and_then(Value::as_str),
        Some("stopping" | "stopped")
    ) && changes
        .get("state")
        .and_then(Value::as_str)
        .is_some_and(|state| !matches!(state, "finishing" | "exited" | "stopped"))
    {
        return Err("The coding-agent launch is stopping".into());
    }
    let fields = record
        .as_object_mut()
        .ok_or("invalid coding-agent launch record")?;
    fields.extend(changes.clone());
    fields.insert(
        "updated_at".into(),
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?
            .into(),
    );
    write_json(&path, &record)
}

/// Native terminal entrypoint used by the shipped host launchers. The stable
/// launch ID and host-owned record fence the guest command to one run.
pub(crate) async fn run_entrypoint(name: &str, launch_id: &str) -> Result<i32, Error> {
    if !crate::host_platform::valid_agent_name(name) || !launch_id.starts_with("launch-") {
        return Err("invalid host agent entrypoint".into());
    }
    let result = run_entrypoint_inner(name, launch_id).await;
    if let Err(error) = &result
        && read_json(&launch_path(name))
            .ok()
            .flatten()
            .is_some_and(|record| {
                record["runner_pid"].as_u64() == Some(u64::from(std::process::id()))
                    && process_matches(&record, "runner_pid", "runner_token")
            })
    {
        let _ = update_launch(
            name,
            launch_id,
            &serde_json::Map::from_iter([
                ("state".to_owned(), "failed".into()),
                ("error".to_owned(), error.to_string().into()),
            ]),
        );
    }
    result
}

async fn run_entrypoint_inner(name: &str, launch_id: &str) -> Result<i32, Error> {
    // Claim the launch in the same lock as the state check. A second
    // entrypoint must neither spawn a second command nor rewrite its result.
    let record = {
        let _lock = LaunchLock::acquire(name)?;
        let mut record = read_json(&launch_path(name))?.ok_or("No matching coding-agent launch")?;
        if record["launch_id"] != launch_id
            || !matches!(record["state"].as_str(), Some("starting" | "unknown"))
        {
            return Err("No matching unclaimed coding-agent launch is ready".into());
        }
        record["state"] = "launching".into();
        record["runner_pid"] = std::process::id().into();
        record["runner_token"] = process_token(i64::from(std::process::id())).into();
        write_json(&launch_path(name), &record)?;
        record
    };
    let command = record
        .get("command")
        .and_then(Value::as_str)
        .ok_or("agent launch command is missing")?
        .to_owned();
    let mut changes = serde_json::Map::new();
    if let Ok(pane) = std::env::var("TMUX_PANE") {
        let output = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(crate::host_platform::config_dir().join("data/tmux.sock"))
            .args(["display-message", "-p", "-t", &pane, "#{socket_path}"])
            .output()
            .await?;
        if !output.status.success() {
            return Err("Could not identify agent tmux socket".into());
        }
        let socket = String::from_utf8(output.stdout)?.trim().to_owned();
        let status = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .args([
                "set-option",
                "-p",
                "-t",
                &pane,
                "@safeyolo_launch_id",
                launch_id,
            ])
            .status()
            .await?;
        if !status.success() {
            return Err("Could not identify agent tmux pane".into());
        }
        changes.insert("pane_id".into(), pane.into());
        changes.insert("tmux_socket".into(), socket.into());
    }
    update_launch(name, launch_id, &changes)?;
    if !crate::host_platform::guest_exec_available(name).await {
        update_launch(
            name,
            launch_id,
            &serde_json::Map::from_iter([
                ("state".to_owned(), "failed".into()),
                ("error".to_owned(), "The sandbox is not ready".into()),
            ]),
        )?;
        return Err("The sandbox is not ready".into());
    }
    if !run_hook(name, &record, "pre_launch").await {
        return Err("pre-launch hook failed; the coding-agent command was not started".into());
    }
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut child = crate::host_platform::spawn_guest_command(name, &command).await?;
    let child_pid = i64::from(child.id().ok_or("guest transport has no PID")?);
    let child_token = process_token(child_pid);
    if let Err(error) = update_launch(
        name,
        launch_id,
        &serde_json::Map::from_iter([
            ("state".to_owned(), "running".into()),
            ("pid".to_owned(), child_pid.into()),
            ("process_token".to_owned(), child_token.clone().into()),
        ]),
    ) {
        let _ = child.kill().await;
        return Err(error);
    }
    run_hook(name, &record, "post_launch").await;
    // Remain alive to record actual completion and run the exit hook when a
    // caller closes or interrupts its terminal. The transport owns delivery
    // of these signals to the guest command.
    let status = loop {
        let signal = tokio::select! {
            result = child.wait() => break result?,
            _ = interrupt.recv() => libc::SIGINT,
            _ = terminate.recv() => libc::SIGTERM,
            _ = hangup.recv() => libc::SIGHUP,
        };
        if let Some(token) = &child_token
            && process_token(child_pid).as_deref() == Some(token.as_str())
        {
            unsafe {
                libc::kill(child_pid as i32, signal);
            }
        }
    };
    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    update_launch(
        name,
        launch_id,
        &serde_json::Map::from_iter([
            ("state".to_owned(), "finishing".into()),
            ("exit_code".to_owned(), code.into()),
            ("exit_reason".to_owned(), "command exited".into()),
        ]),
    )?;
    if let Some(record) = read_json(&launch_path(name))? {
        run_hook(name, &record, "on_exit").await;
    }
    update_launch(
        name,
        launch_id,
        &serde_json::Map::from_iter([("state".to_owned(), "exited".into())]),
    )?;
    Ok(code)
}

async fn run_hook(name: &str, record: &Value, action: &str) -> bool {
    let Some(script) = record.pointer("/launcher/script").and_then(Value::as_str) else {
        return true;
    };
    let mut exit_code = 1;
    let result = async {
        let path = std::path::Path::new(script).canonicalize()?;
        validate_host_script(&path)?;
        let status = script_command(&path, action, record).status().await?;
        exit_code = status.code().unwrap_or(1);
        if !status.success() {
            return Err(format!("{action} hook failed: {status}").into());
        }
        Ok::<(), Error>(())
    }
    .await;
    if let Err(error) = result {
        let current = read_json(&launch_path(name))
            .ok()
            .flatten()
            .unwrap_or_else(|| record.clone());
        let mut errors = current
            .get("hook_errors")
            .cloned()
            .unwrap_or_else(|| json!([]));
        if let Some(errors) = errors.as_array_mut() {
            errors.push(json!({"hook":action,"detail":error.to_string(),"exit_code":exit_code}));
        }
        if let Some(id) = record["launch_id"].as_str() {
            let _ = update_launch(
                name,
                id,
                &serde_json::Map::from_iter([("hook_errors".into(), errors)]),
            );
        }
        return false;
    }
    true
}

/// A recorded live pane must still carry this launch's identity. Never select
/// a new launcher or create a replacement from an attach command.
pub(crate) async fn attach(agent: &Agent) -> Result<i32, Error> {
    let record = read_json(&launch_path(&agent.name))?
        .ok_or("no recorded coding-agent terminal; use agent start")?;
    if record["agent_id"] != agent.id {
        return Err("terminal belongs to another agent".into());
    }
    if !matches!(
        record["state"].as_str(),
        Some("starting" | "launching" | "running" | "unknown")
    ) {
        return Err("coding-agent terminal is absent; attach did not launch an agent".into());
    }
    match record.pointer("/launcher/kind").and_then(Value::as_str) {
        Some("tmux-window" | "tmux-pane") => attach_pane(&record).await,
        Some("script" | "manager") => {
            let path = std::path::Path::new(
                record
                    .pointer("/launcher/script")
                    .and_then(Value::as_str)
                    .ok_or("launcher path missing")?,
            )
            .canonicalize()?;
            validate_host_script(&path)?;
            Ok(script_command(&path, "attach", &record)
                .status()
                .await?
                .code()
                .unwrap_or(1))
        }
        _ => Err("this launch has no attachable host terminal; use agent shell".into()),
    }
}

async fn terminal_live(record: &Value) -> bool {
    let Some(socket) = record["tmux_socket"].as_str() else {
        return false;
    };
    let Some(pane) = record["pane_id"].as_str() else {
        return false;
    };
    let Some(id) = record["launch_id"].as_str() else {
        return false;
    };
    let output = tokio::process::Command::new("tmux")
        .args([
            "-S",
            socket,
            "display-message",
            "-p",
            "-t",
            pane,
            "#{@safeyolo_launch_id}:#{pane_dead}",
        ])
        .output()
        .await;
    output.is_ok_and(|output| {
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == format!("{id}:0")
    })
}

async fn attach_pane(record: &Value) -> Result<i32, Error> {
    let socket = record["tmux_socket"]
        .as_str()
        .ok_or("recorded tmux socket is absent")?;
    let pane = record["pane_id"]
        .as_str()
        .ok_or("recorded tmux pane is absent")?;
    let id = record["launch_id"]
        .as_str()
        .ok_or("recorded launch ID is absent")?;
    let observed = tokio::process::Command::new("tmux")
        .args([
            "-S",
            socket,
            "show-options",
            "-pqv",
            "-t",
            pane,
            "@safeyolo_launch_id",
        ])
        .output()
        .await?;
    if !observed.status.success() || String::from_utf8(observed.stdout)?.trim() != id {
        return Err("recorded terminal is absent or belongs to another launch; attach did not launch an agent".into());
    }
    let dead = tokio::process::Command::new("tmux")
        .args([
            "-S",
            socket,
            "display-message",
            "-p",
            "-t",
            pane,
            "#{pane_dead}",
        ])
        .output()
        .await?;
    if !dead.status.success() || String::from_utf8(dead.stdout)?.trim() != "0" {
        return Err("recorded terminal has exited; attach did not launch an agent".into());
    }
    let current = std::env::var("TMUX").unwrap_or_default();
    let own_socket = current
        .rsplit_once(',')
        .and_then(|(value, _)| value.rsplit_once(','))
        .map(|(socket, _)| socket);
    let mut command = tokio::process::Command::new("tmux");
    command.args(["-S", socket]);
    if own_socket == Some(socket) {
        command.args(["switch-client", "-t", pane]);
    } else {
        command
            .env_remove("TMUX")
            .args(["attach-session", "-t", pane]);
    }
    Ok(command.status().await?.code().unwrap_or(1))
}

pub(crate) async fn persistent_shell(agent: &Agent, command: &str) -> Result<i32, Error> {
    if !crate::host_platform::guest_exec_available(&agent.name).await {
        return Err("sandbox exec control is unavailable; run agent diagnostics".into());
    }
    let root = crate::host_platform::config_dir();
    let session = format!(
        "sy-shell-{}-{}",
        std::fs::read_to_string(root.join("data/instance_id"))?.trim(),
        agent.id
    );
    {
        let path = root.join("data/tmux-launch.lock");
        let _lock =
            tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&path))
                .await??;
        let existing = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(root.join("data/tmux.sock"))
            .args(["has-session", "-t", &format!("={session}")])
            .output()
            .await?;
        if !existing.status.success() {
            let args = vec![
                "--config".to_owned(),
                crate::host_platform::config_path()
                    .to_string_lossy()
                    .into_owned(),
                "agent".to_owned(),
                "shell".to_owned(),
                "--".to_owned(),
                agent.name.clone(),
                "-c".to_owned(),
                command.to_owned(),
            ];
            let result = tmux_session_with_current_env(
                &session,
                "sandbox-shell",
                &root.join("bin/safeyolo"),
                &args,
            )
            .await?;
            if !result.status.success() {
                return Err(format!(
                    "could not open independent shell: {}",
                    String::from_utf8_lossy(&result.stderr)
                )
                .into());
            }
        }
    }
    Ok(tokio::process::Command::new("tmux")
        .arg("-S")
        .arg(root.join("data/tmux.sock"))
        .env_remove("TMUX")
        .args(["attach-session", "-t", &format!("={session}")])
        .status()
        .await?
        .code()
        .unwrap_or(1))
}

fn valid_tmux_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

async fn tmux_session_with_current_env(
    session: &str,
    name: &str,
    binary: &std::path::Path,
    arguments: &[String],
) -> Result<std::process::Output, Error> {
    // tmux only imports its configured update-environment names from a client
    // when creating a session. Transfer current names and mask values left
    // in a pre-existing server, without putting any values in command argv.
    let socket = crate::host_platform::config_dir().join("data/tmux.sock");
    let option = tokio::process::Command::new("tmux")
        .arg("-S")
        .arg(&socket)
        .args(["show-options", "-gqv", "update-environment"])
        .output()
        .await?;
    let previous = if option.status.success() {
        let global = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .args(["show-environment", "-g"])
            .output()
            .await?;
        if !global.status.success() {
            return Err("Could not inspect tmux server environment".into());
        }
        let mut names = BTreeSet::new();
        for (name, _) in std::env::vars_os() {
            if let Some(name) = name.to_str().filter(|name| valid_tmux_env_name(name)) {
                names.insert(name.to_owned());
            }
        }
        for line in global.stdout.split(|byte| *byte == b'\n') {
            let line = line.strip_prefix(b"-").unwrap_or(line);
            let name = line.split(|byte| *byte == b'=').next().unwrap_or_default();
            if let Ok(name) = std::str::from_utf8(name)
                && valid_tmux_env_name(name)
            {
                names.insert(name.to_owned());
            }
        }
        let previous = String::from_utf8(option.stdout)?.trim_end().to_owned();
        let names = names.into_iter().collect::<Vec<_>>().join(" ");
        let set = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .args(["set-option", "-g", "update-environment", &names])
            .status()
            .await?;
        if !set.success() {
            return Err("Could not set tmux environment update names".into());
        }
        Some(previous)
    } else {
        let sessions = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .arg("list-sessions")
            .output()
            .await?;
        if sessions.status.success() {
            return Err("Could not inspect existing tmux environment setting".into());
        }
        None
    };
    let created = tokio::process::Command::new("tmux")
        .arg("-S")
        .arg(&socket)
        .args([
            "new-session",
            "-d",
            "-P",
            "-F",
            "#{pane_id}",
            "-s",
            session,
            "-n",
            name,
        ])
        .arg(binary)
        .args(arguments)
        .output()
        .await;
    if let Some(previous) = previous {
        let restored = tokio::process::Command::new("tmux")
            .arg("-S")
            .arg(&socket)
            .args(["set-option", "-g", "update-environment", &previous])
            .status()
            .await;
        if !matches!(restored, Ok(status) if status.success()) {
            if created.as_ref().is_ok_and(|output| output.status.success()) {
                let _ = tokio::process::Command::new("tmux")
                    .arg("-S")
                    .arg(&socket)
                    .args(["kill-session", "-t", &format!("={session}")])
                    .status()
                    .await;
            }
            return Err("Could not restore tmux environment update names".into());
        }
    }
    Ok(created?)
}

/// Fixed target used by the shipped tmux launchers. Preserve the accepted
/// current-environment handoff without changing an unrelated terminal server.
pub(crate) async fn launcher_session(name: &str, launch_id: &str) -> Result<Value, Error> {
    // Cover environment transfer and arrangement together: two different
    // agents can create their windows concurrently in the same instance.
    let path = crate::host_platform::config_dir().join("data/tmux-launch.lock");
    let _lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&path)).await??;
    let agent = crate::host_agents::list()?
        .into_iter()
        .find(|agent| agent.name == name)
        .ok_or("agent is not configured")?;
    let record = read_json(&launch_path(name))?.ok_or("no prepared launch")?;
    if record["launch_id"] != launch_id
        || record["agent_id"] != agent.id
        || record["state"] != "starting"
    {
        return Err("no matching prepared tmux launch".into());
    }
    let kind = record
        .pointer("/launcher/kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    let pane = match kind {
        "tmux-window" => false,
        "tmux-pane" => true,
        // Custom launchers retain their script identity for hooks and attach.
        // The shipped preset they delegate to supplies its own layout.
        "script" | "manager" => match std::env::var("SAFEYOLO_TMUX_LAYOUT").as_deref() {
            Ok("window") => false,
            Ok("pane") => true,
            _ => return Err("custom launcher did not select a shipped tmux layout".into()),
        },
        _ => return Err("prepared launch does not select a tmux preset".into()),
    };
    let session = record["tmux_session"]
        .as_str()
        .ok_or("tmux session missing")?;
    let socket = crate::host_platform::config_dir().join("data/tmux.sock");
    let temporary = format!("sy-launch-{}", launch_id);
    let arguments = vec![
        "--config".to_owned(),
        crate::host_platform::config_path()
            .to_string_lossy()
            .into_owned(),
        "agent".to_owned(),
        "entrypoint".to_owned(),
        name.to_owned(),
        launch_id.to_owned(),
    ];
    let output = tmux_session_with_current_env(
        &temporary,
        name,
        &crate::host_platform::config_dir().join("bin/safeyolo"),
        &arguments,
    )
    .await?;
    if !output.status.success() {
        return Err(format!(
            "could not create agent terminal: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    // Each launch gets the caller's environment in its temporary session.
    // Moving its pane/window retains it without changing other live agents.
    let existing = tokio::process::Command::new("tmux")
        .arg("-S")
        .arg(&socket)
        .args(["has-session", "-t", &format!("={session}")])
        .output()
        .await?;
    let mut arrange = tokio::process::Command::new("tmux");
    arrange.arg("-S").arg(&socket);
    if !existing.status.success() {
        arrange.args(["rename-session", "-t", &format!("={temporary}"), session]);
    } else {
        arrange.args([
            if pane { "join-pane" } else { "move-window" },
            "-d",
            "-s",
            &format!("={temporary}:"),
            "-t",
            &format!("={session}:"),
        ]);
    }
    let moved = arrange.output().await?;
    if !moved.status.success() {
        // A short command may have completed before arrangement. Its actual
        // exit record remains authoritative; no replacement is launched.
        let current = read_json(&launch_path(name))?.ok_or("launch record disappeared")?;
        if current["launch_id"] != launch_id
            || !matches!(current["state"].as_str(), Some("exited" | "failed"))
        {
            return Err(format!(
                "could not arrange agent terminal: {}",
                String::from_utf8_lossy(&moved.stderr)
            )
            .into());
        }
    }
    // The socket was selected with -S. Only the pane needs discovery.
    let target = String::from_utf8(output.stdout)?;
    let pane = target.trim();
    if pane
        .strip_prefix('%')
        .is_none_or(|number| number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("tmux did not report a valid pane for this launch".into());
    }
    Ok(json!({"tmux_socket":socket,"pane_id":pane}))
}

fn read_json(path: &std::path::Path) -> Result<Option<Value>, Error> {
    crate::guest_commands::read_state(path)
}

fn selected_launcher(agent: &Agent) -> Result<Value, Error> {
    let configured = match &agent.launcher {
        Some(launcher) => Some(launcher.clone()),
        None => {
            crate::native_config::host_settings()?
                .agent_launcher
                .default
        }
    };
    let (value, source) = match configured {
        Some(value) if agent.launcher.is_some() => (value, "agent"),
        Some(value) => (value, "host default"),
        None => ("tmux-window".to_owned(), "built-in"),
    };
    let kind = if value.starts_with("manager:") {
        "manager"
    } else if value.starts_with('/') {
        "script"
    } else {
        value.as_str()
    };
    let script = match kind {
        "tmux-window" | "tmux-pane" => Some(
            crate::host_platform::config_dir()
                .join("assets/launchers")
                .join(format!("{kind}.sh"))
                .to_string_lossy()
                .into_owned(),
        ),
        "manager" => Some(value.trim_start_matches("manager:").to_owned()),
        "script" => Some(value.clone()),
        _ => None,
    };
    let mut result = json!({"kind":kind,"source":source});
    if let Some(script) = script {
        result["script"] = script.into();
    }
    Ok(result)
}

fn harness(agent: &Agent) -> Option<&'static str> {
    match agent.host_script.as_deref()?.rsplit('/').next()? {
        "codex-host-setup.sh" | "codex-coord-host-setup.sh" => Some("codex"),
        "pi-host-setup.sh" | "pi-coord-host-setup.sh" => Some("pi"),
        "claude-host-setup.sh" => Some("claude"),
        "mise-shell-host-setup.sh" => Some("shell"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn process_token(pid: i64) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    if fields.first() == Some(&"Z") {
        return None;
    }
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(format!("linux:{}:{pid}:{}", boot.trim(), fields.get(19)?))
}

#[cfg(target_os = "macos")]
pub(crate) fn process_token(pid: i64) -> Option<String> {
    crate::host_platform::macos_process_token(pid)
}

fn process_matches(record: &Value, pid_key: &str, token_key: &str) -> bool {
    let Some(pid) = record.get(pid_key).and_then(Value::as_i64) else {
        return false;
    };
    let Some(token) = record.get(token_key).and_then(Value::as_str) else {
        return false;
    };
    process_token(pid).as_deref() == Some(token)
}

fn supervisor_state(name: &str) -> Result<Option<Value>, Error> {
    let Some(state) = read_json(&supervisor_path(name))? else {
        return Ok(None);
    };
    if state.get("schema_version").and_then(Value::as_i64) != Some(1)
        || state.get("name").and_then(Value::as_str) != Some(name)
        || !state.get("command").is_some_and(Value::is_string)
    {
        return Err("invalid command supervisor state".into());
    }
    Ok(Some(state))
}

async fn runtime(agent: &Agent) -> Result<Value, Error> {
    let sandbox = crate::host_runs::observe(&agent.name).await;
    let proxy_attachment = match crate::native_config::read(&crate::host_platform::config_path()) {
        Ok(config) => match config
            .listeners
            .iter()
            .find(|entry| entry.agent_id == agent.name)
        {
            Some(listener) => {
                let reachable = crate::host_commands::proxy_live()
                    && tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        tokio::net::UnixStream::connect(&listener.socket_path),
                    )
                    .await
                    .is_ok_and(|connected| connected.is_ok());
                json!({"state":if reachable {"ready"} else {"unavailable"}, "socket":listener.socket_path})
            }
            None => {
                json!({"state":"absent","next_action":"start the configured agent to prepare its proxy listener"})
            }
        },
        Err(error) => json!({"state":"unknown","error":error.to_string()}),
    };
    let effective_configuration = if sandbox["runtime_state"] == "stopped" {
        Value::Null
    } else {
        crate::guest_commands::read_state(
            &agent_dir(&agent.name).join("config-share/host-launch-context.json"),
        )
        .ok()
        .flatten()
        .filter(|context| context["generation"] == sandbox["run_id"])
        .map_or(Value::Null, |context| {
            json!({
                "workspace":context["workspace"], "memory_mb":context["memory_mb"],
                "extra_shares":context["extra_shares"]
            })
        })
    };
    let ready = sandbox["exec"] == true;
    let (record, record_error) = match read_json(&launch_path(&agent.name)) {
        Ok(Some(record)) if record["agent_id"] == agent.id && record["name"] == agent.name => {
            (Some(record), None)
        }
        Ok(Some(_)) => (
            None,
            Some("stored launcher identity does not match this agent".to_owned()),
        ),
        Ok(None) => (None, None),
        Err(error) => (
            None,
            Some(format!("coding-agent record is unreadable: {error}")),
        ),
    };
    let mut launcher = record
        .as_ref()
        .and_then(|value| value.get("launcher"))
        .cloned()
        .unwrap_or_else(|| {
            selected_launcher(agent)
                .unwrap_or_else(|error| json!({"kind":"unknown","error":error.to_string()}))
        });
    let mut state = "stopped".to_owned();
    let mut attachable = false;
    let mut launch_id = Value::Null;
    let mut exit_code = Value::Null;
    let mut error = record_error
        .as_ref()
        .map_or(Value::Null, |error| error.clone().into());
    if record_error.is_some() {
        state = "unknown".into();
    }
    let mut hook_errors = json!([]);
    if let Some(record) = record.as_ref() {
        if let Some(value) = record.get("launcher") {
            launcher = value.clone();
        }
        launch_id = record.get("launch_id").cloned().unwrap_or(Value::Null);
        exit_code = record.get("exit_code").cloned().unwrap_or(Value::Null);
        error = record.get("error").cloned().unwrap_or(Value::Null);
        hook_errors = record
            .get("hook_errors")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let recorded = record
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if !ready {
            if matches!(recorded, "launching" | "running" | "stopping" | "finishing")
                && process_matches(record, "runner_pid", "runner_token")
            {
                state = "finishing".to_owned();
            }
        } else if launcher.get("kind").and_then(Value::as_str) == Some("supervisor") {
            if recorded == "starting" {
                state = "starting".to_owned();
            } else if let Some(supervisor) =
                supervisor_state(&agent.name).unwrap_or_else(|supervisor_error| {
                    error = supervisor_error.to_string().into();
                    Some(json!({"state":"unknown"}))
                })
            {
                let current = supervisor
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                state = if matches!(
                    current,
                    "starting" | "restarting" | "failed" | "stopped" | "exited"
                ) {
                    current.to_owned()
                } else {
                    let heartbeat = supervisor
                        .get("heartbeat_at")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
                    if current == "running" && (0.0..=5.0).contains(&(now - heartbeat)) {
                        "running"
                    } else {
                        "unknown"
                    }
                    .to_owned()
                };
                error = supervisor
                    .get("last_stderr")
                    .cloned()
                    .unwrap_or(Value::Null);
            }
        } else {
            state = recorded.to_owned();
            if matches!(recorded, "launching" | "running" | "stopping" | "finishing")
                && record.get("runner_pid").is_some()
                && !process_matches(record, "runner_pid", "runner_token")
            {
                state = "exited".to_owned();
                if error.is_null() {
                    error = "Launch process exited without recording its result".into();
                }
            } else if recorded == "running" {
                state = if process_matches(record, "pid", "process_token") {
                    "running"
                } else if record.get("runner_pid").is_some() {
                    "finishing"
                } else {
                    "exited"
                }
                .to_owned();
            }
            attachable = state == "running"
                && launcher.get("kind").and_then(Value::as_str) != Some("interactive");
        }
    }
    if ready {
        match crate::host_platform::coding_agent_observation(&agent.name).await {
            Ok(observed) if observed == "running" => {
                if launch_id.is_null() || matches!(state.as_str(), "stopped" | "exited" | "failed")
                {
                    state = "manual".into();
                    attachable = false;
                    launcher = json!({"kind":"manual","source":"observed guest command"});
                } else if state == "unknown" {
                    state = "observed".into();
                }
            }
            Ok(_) if state == "running" => {
                state = "unknown".into();
                error = "host transport is live but no configured coding agent was detected".into();
            }
            Err(observation_error) => {
                state = "unknown".into();
                error = observation_error.to_string().into();
            }
            _ => {}
        }
    } else if sandbox["runtime_state"] != "stopped" {
        state = "unknown".into();
    } else if state != "finishing" {
        state = "stopped".into();
    }
    if let Some(record) = record.as_ref()
        && matches!(
            record.pointer("/launcher/kind").and_then(Value::as_str),
            Some("tmux-window" | "tmux-pane")
        )
    {
        attachable = terminal_live(record).await;
    }
    Ok(json!({
        "agent_id":agent.id,"name":agent.name,"configured":true,
        "sandbox_state":sandbox["runtime_state"],"runtime_state":sandbox["runtime_state"],
        "control_state":sandbox["control_state"],"run_id":sandbox["run_id"],
        "runtime_error":sandbox["error"],"next_action":sandbox["next_action"],
        "exec":sandbox["exec"],"port_forward":sandbox["port_forward"],
        "proxy_attachment":proxy_attachment,"traffic":{"state":"unknown","source":"proxy traffic telemetry"},
        "effective_configuration":effective_configuration,
        "next_start_configuration":{"workspace":agent.folder,"memory_mb":agent.memory_mb.unwrap_or(4096),"mounts":agent.mounts},
        "terminal_state":if attachable {"running"} else {"absent"},
        "agent_state":state,"launcher":launcher,"attachable":attachable,
        "launch_id":launch_id,"exit_code":exit_code,"error":error,
        "hook_errors":hook_errors,"harness":harness(agent)
    }))
}

pub(crate) async fn operate(operation: &str, agent_id: Option<&str>) -> Result<Value, Error> {
    let agents = crate::host_agents::list()?;
    if operation == "list" && agent_id.is_none() {
        let mut observed = Vec::with_capacity(agents.len());
        for agent in &agents {
            observed.push(match runtime(agent).await {
                Ok(value) => value,
                Err(error) => json!({"agent_id":agent.id,"name":agent.name,"sandbox_state":"unknown","runtime_state":"unknown","control_state":"unknown","agent_state":"unknown","terminal_state":"unknown","attachable":false,"exec":false,"error":error.to_string(),"next_action":"inspect agent diagnostics; existing runtime evidence is preserved"}),
            });
        }
        return Ok(json!({"agents":observed}));
    }
    let Some(agent) = agents
        .into_iter()
        .find(|agent| Some(agent.id.as_str()) == agent_id)
    else {
        return Ok(json!({"error":"Agent not found","status_code":404}));
    };
    let result = match operation {
        "start" | "start-interactive" | "start-foreground" | "sandbox-start" => {
            start(&agent, operation).await
        }
        "status" => runtime(&agent).await,
        "stop" => stop(&agent).await,
        "cleanup" => cleanup(&agent).await,
        _ => Ok(json!({"error":"invalid host operation","status_code":400})),
    };
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            Ok(json!({"error":format!("Agent operation failed: {error}"),"status_code":500}))
        }
    }
}

async fn start(agent: &Agent, operation: &str) -> Result<Value, Error> {
    let interactive = operation == "start-interactive";
    let foreground = operation == "start-foreground";
    let lock_root = agent_dir(&agent.name);
    let _lock =
        tokio::task::spawn_blocking(move || SetupLock::acquire_in(&lock_root, None)).await??;
    let current = crate::host_agents::list()?
        .into_iter()
        .find(|current| current.id == agent.id)
        .ok_or("agent configuration was removed while start was waiting")?;
    let agent = &current;
    let observed = runtime(agent).await?;
    let state = observed
        .get("agent_state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if matches!(state, "starting" | "launching" | "running" | "managed") {
        return Ok(observed);
    }
    if !matches!(state, "stopped" | "exited" | "failed") {
        return Ok(json!({"error":format!("Agent cannot start while {state}"),"status_code":409}));
    }
    if !matches!(
        observed["runtime_state"].as_str(),
        Some("running" | "stopped")
    ) {
        return Err(
            "sandbox runtime is degraded or unknown; inspect agent diagnostics before starting"
                .into(),
        );
    }
    crate::host_boot::validate(agent)?;
    let workspace = crate::host_boot::workspace(
        std::path::Path::new(agent.folder.as_deref().ok_or("missing workspace")?),
        agent.dangerously_allow_unowned,
    )?;
    if observed["runtime_state"] == "stopped" {
        if observed["backend"].is_object() {
            crate::host_platform::stop_sandbox(&agent.name).await?;
        }
        clear_stale_guest_command(&agent.name)?;
        let slot = crate::host_agents::reserve_network_slot(&agent.name)?;
        let address = u32::from(slot) + 1;
        let ip = format!("10.200.{}.{}", address / 256, address % 256);
        let run_id = uuid::Uuid::new_v4().simple().to_string();
        crate::host_boot::stage(agent, &ip, &run_id).await?;
        crate::host_runs::save(
            &agent.name,
            &json!({"name":agent.name,"agent_id":agent.id,"run_id":run_id,"ip":ip,"state":"starting"}),
        )?;
        crate::host_platform::update_agent_map(&agent.name, Some(&ip))?;
        if let Err(error) = sync_agent_listeners().await {
            let _ = crate::host_platform::update_agent_map(&agent.name, None);
            let _ = sync_agent_listeners().await;
            return Err(error);
        }
        let memory_mb = agent.memory_mb.unwrap_or(4096);
        if memory_mb <= 0 {
            return Err("agent memory_mb must be positive".into());
        }
        let boot = crate::host_platform::start_sandbox(
            &agent.name,
            &ip,
            memory_mb as u64,
            agent.rootfs_overlay.as_deref() == Some("memory"),
        )
        .await;
        if let Err(error) = boot {
            let _ = crate::host_platform::update_agent_map(&agent.name, None);
            let _ = sync_agent_listeners().await;
            return Err(error.into());
        }
    }
    if operation == "sandbox-start" {
        return runtime(agent).await;
    }
    stop_supervisor(&agent.name).await?;
    let mut launcher = selected_launcher(agent)?;
    if foreground {
        launcher = json!({"kind":"foreground","source":"caller terminal"});
    }
    if interactive {
        launcher = json!({"kind":"tmux-window","source":"requested"});
        launcher["script"] = crate::host_platform::config_dir()
            .join("assets/launchers/tmux-window.sh")
            .to_string_lossy()
            .into_owned()
            .into();
    }
    let debug_command = interactive && agent.launcher.as_deref() == Some("supervisor");
    let command = configured_guest_command(agent, debug_command)?;
    let launch_id = format!("launch-{}", uuid::Uuid::new_v4().simple());
    let timestamp =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let session = tmux_session()?;
    let record = json!({
        "name":agent.name,"agent_id":agent.id,"launch_id":launch_id,
        "launcher":launcher,"workspace":workspace,"mode":if foreground {"foreground"} else {"background"},
        "command":command,"state":"starting","tmux_session":session,
        "started_at":timestamp,"requester_pid":std::process::id(),
        "requester_token":process_token(std::process::id() as i64)
    });
    {
        let _launch_lock = LaunchLock::acquire(&agent.name)?;
        write_json(&launch_path(&agent.name), &record)?;
    }
    if foreground {
        return Ok(record);
    }
    let result = invoke_launcher(agent, &record).await;
    if let Err(error) = result {
        update_launch(
            &agent.name,
            &launch_id,
            &serde_json::Map::from_iter([
                ("state".to_owned(), "failed".into()),
                ("error".to_owned(), error.to_string().into()),
            ]),
        )?;
        return Err(error);
    }
    crate::host_events::write(
        &agent.name,
        "agent.started",
        "agent",
        format!("Agent {} started", agent.name),
        None,
        json!({}),
    );
    runtime(agent).await
}

fn configured_guest_command(agent: &Agent, interactive: bool) -> Result<String, Error> {
    let entry = if interactive {
        ".safeyolo-interactive-command"
    } else {
        ".safeyolo-command"
    };
    let path = agent_dir(&agent.name).join("home").join(entry);
    let args = agent
        .user_default_args
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>();
    if path.is_file() && path.metadata()?.permissions().mode() & 0o111 != 0 {
        return Ok(format!(
            "/home/agent/{entry}{}",
            if args.is_empty() {
                String::new()
            } else {
                format!(" {}", args.join(" "))
            }
        ));
    }
    if interactive {
        return Err("The managed agent has no separate interactive entrypoint".into());
    }
    if args.is_empty() {
        Ok("exec /safeyolo/safeyolo-guest observe exec -- /bin/bash -l".to_owned())
    } else {
        Ok(format!(
            "exec /safeyolo/safeyolo-guest observe exec -- {}",
            args.join(" ")
        ))
    }
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn tmux_session() -> Result<String, Error> {
    let session = crate::native_config::host_settings()?
        .agent_launcher
        .tmux_session;
    let instance =
        std::fs::read_to_string(crate::host_platform::config_dir().join("data/instance_id"))?;
    Ok(format!("{session}-{}", instance.trim()))
}

pub(crate) async fn sync_agent_listeners() -> Result<(), Error> {
    let path = crate::host_platform::config_path();
    if !path.is_file() {
        return Ok(());
    }
    if !path.is_absolute() {
        return Err("native proxy config path must be absolute".into());
    }
    let _same_process_lock = LISTENER_LOCK.lock().await;
    let lock_path = crate::host_platform::config_dir().join("data/native-listeners.lock");
    let _lock =
        tokio::task::spawn_blocking(move || crate::host_platform::lock_host_state(&lock_path))
            .await??;
    let cwd = crate::host_platform::config_dir();
    let sockets = crate::host_platform::config_dir().join("data/sockets");
    let source = std::fs::read(&path)?;
    let native = path
        .extension()
        .is_some_and(|extension| extension == "toml");
    let mut config: Value = if native {
        serde_json::to_value(crate::native_config::read(&path)?)?
    } else {
        serde_json::from_slice(&source)?
    };
    let entries = config
        .get("listeners")
        .and_then(Value::as_array)
        .ok_or("native listeners must be an array")?;
    let mut retained = Vec::new();
    for entry in entries {
        let socket = entry
            .get("socket_path")
            .and_then(Value::as_str)
            .ok_or("native listeners need socket_path strings")?;
        let path = PathBuf::from(socket);
        let path = if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        };
        let managed = path.file_name().is_some_and(|name| name == "proxy.sock")
            && path.parent().and_then(std::path::Path::parent) == Some(sockets.as_path())
            && path
                .parent()
                .and_then(std::path::Path::file_name)
                .and_then(|name| name.to_str())
                .and_then(|name| name.split_once('_'))
                .is_some_and(|(ip, name)| {
                    ip.parse::<std::net::Ipv4Addr>().is_ok()
                        && crate::host_platform::valid_agent_name(name)
                });
        if !managed {
            retained.push(entry.clone());
        }
    }
    let map_path = crate::host_platform::agent_map_path()?;
    let map: serde_json::Map<String, Value> = match std::fs::read(map_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .or_else(|_| crate::host_platform::agent_map_from_runs())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::host_platform::agent_map_from_runs()?
        }
        Err(error) => return Err(error.into()),
    };
    for (name, entry) in map {
        let Some(ip) = entry.get("ip").and_then(Value::as_str) else {
            continue;
        };
        if !crate::host_platform::valid_agent_name(&name)
            || ip.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Err("invalid agent listener identity".into());
        }
        let path = sockets.join(format!("{ip}_{name}")).join("proxy.sock");
        if path.as_os_str().as_bytes().len() > if cfg!(target_os = "macos") { 104 } else { 108 } {
            return Err("agent socket path exceeds platform limit".into());
        }
        retained.push(json!({"agent_id":name,"socket_path":path,"source_id":ip}));
    }
    let requested = uuid::Uuid::new_v4().simple().to_string();
    config["listeners"] = Value::Array(retained);
    config["reload_id"] = requested.clone().into();
    let mode = std::fs::metadata(&path)?.permissions().mode();
    let parent = path.parent().ok_or("native config has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    if native {
        let mut document: toml_edit::DocumentMut = std::str::from_utf8(&source)?.parse()?;
        let mut listeners = toml_edit::ArrayOfTables::new();
        for entry in config["listeners"]
            .as_array()
            .ok_or("listeners must be an array")?
        {
            let mut table = toml_edit::Table::new();
            for (name, value) in entry.as_object().ok_or("listener must be a table")? {
                table.insert(
                    name,
                    toml_edit::value(value.as_str().ok_or("listener fields must be strings")?),
                );
            }
            listeners.push(table);
        }
        document["listeners"] = toml_edit::Item::ArrayOfTables(listeners);
        document["reload_id"] = toml_edit::value(requested.as_str());
        temporary.write_all(document.to_string().as_bytes())?;
    } else {
        serde_json::to_writer_pretty(&mut temporary, &config)?;
        temporary.write_all(b"\n")?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.persist(&path)?;
    File::open(parent)?.sync_all()?;
    // Stop and independent recovery can update the projection while the
    // proxy is unavailable. Startup reconstructs listeners from current runs.
    if !crate::host_commands::proxy_live() {
        return Ok(());
    }
    let proxy = read_json(&cwd.join("data/proxy-process.json"))?
        .ok_or("proxy process identity is missing; run safeyolo start")?;
    if !process_matches(&proxy, "pid", "token") {
        return Err("proxy process identity is stale; run safeyolo start".into());
    }
    let pid = i32::try_from(proxy["pid"].as_i64().ok_or("proxy PID is missing")?)?;
    if unsafe { libc::kill(pid, libc::SIGHUP) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let readiness = config
        .get("readiness_file")
        .and_then(Value::as_str)
        .ok_or("native readiness file is missing")?;
    let readiness = PathBuf::from(readiness);
    let readiness = if readiness.is_absolute() {
        readiness
    } else {
        cwd.join(readiness)
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(&readiness)
            && let Ok(marker) = serde_json::from_slice::<Value>(&bytes)
            && marker.get("reload_id").and_then(Value::as_str) == Some(&requested)
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("native listener update was not acknowledged".into())
}

async fn invoke_launcher(agent: &Agent, record: &Value) -> Result<(), Error> {
    let kind = record
        .pointer("/launcher/kind")
        .and_then(Value::as_str)
        .ok_or("launcher kind is missing")?;
    let launch_id = record
        .get("launch_id")
        .and_then(Value::as_str)
        .ok_or("launch ID is missing")?;
    match kind {
        "supervisor" => {
            let directory = agent_dir(&agent.name);
            let share = directory.join("config-share");
            let context =
                crate::guest_commands::read_state(&share.join("host-launch-context.json"))?.ok_or(
                    "host launch context is missing; stage this agent before starting its command",
                )?;
            let generation = context["generation"]
                .as_str()
                .ok_or("current-run generation is missing")?;
            crate::guest_commands::publish(
                &directory.join("home"),
                &share,
                &agent.name,
                record["command"]
                    .as_str()
                    .ok_or("guest command is missing")?,
                launch_id,
                generation,
            )?;
            update_launch(
                &agent.name,
                launch_id,
                &serde_json::Map::from_iter([("state".to_owned(), "managed".into())]),
            )?;
            Ok(())
        }
        "tmux-window" | "tmux-pane" | "script" | "manager" => launch_script(agent, record).await,
        _ => Err(format!("unsupported agent launcher: {kind}").into()),
    }
}

pub(crate) fn validate_host_script(path: &std::path::Path) -> Result<(), Error> {
    if !path.is_file() || path.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err("Host launcher is missing or not executable".into());
    }
    for agent in crate::host_agents::list()? {
        let directory = agent_dir(&agent.name);
        let mut writable = vec![
            directory.join("home"),
            directory.join("status"),
            directory.join("cache"),
        ];
        if let Some(folder) = &agent.folder {
            writable.push(PathBuf::from(folder));
        }
        for mount in &agent.mounts {
            let parts = mount.split(':').collect::<Vec<_>>();
            if !(parts.len() == 2 || parts.len() == 3 && parts[2] == "ro") {
                return Err("invalid agent mount metadata".into());
            }
            if parts.len() == 2 {
                writable.push(PathBuf::from(parts[0]));
            }
        }
        let context = directory.join("config-share/host-launch-context.json");
        if let Some(context) = read_json(&context)? {
            if let Some(workspace) = context.get("workspace").and_then(Value::as_str) {
                writable.push(PathBuf::from(workspace));
            }
            if let Some(mounts) = context.get("writable_mounts") {
                let mounts = mounts.as_array().ok_or("invalid staged writable mounts")?;
                for mount in mounts {
                    writable.push(PathBuf::from(
                        mount.as_str().ok_or("invalid staged writable mount")?,
                    ));
                }
            }
        }
        for root in writable {
            match root.canonicalize() {
                Ok(root) if path.starts_with(&root) => {
                    return Err("Host launcher is inside an agent-writable mount".into());
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn script_command(path: &std::path::Path, action: &str, record: &Value) -> tokio::process::Command {
    let field = |name| record.get(name).and_then(Value::as_str).unwrap_or("");
    let logs_dir = std::env::var_os("SAFEYOLO_LOGS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
                })
                .join("safeyolo")
        });
    let mut command = tokio::process::Command::new(path);
    command
        .arg(action)
        .env("SAFEYOLO_CONFIG_DIR", crate::host_platform::config_dir())
        .env(
            "SAFEYOLO_NATIVE_CONFIG_PATH",
            crate::host_platform::config_path(),
        )
        .env("SAFEYOLO_LOGS_DIR", logs_dir)
        .env("SAFEYOLO_AGENT_NAME", field("name"))
        .env("SAFEYOLO_AGENT_ID", field("agent_id"))
        .env("SAFEYOLO_LAUNCH_ID", field("launch_id"))
        .env("SAFEYOLO_WORKSPACE", field("workspace"))
        .env("SAFEYOLO_LAUNCH_MODE", field("mode"))
        .env("SAFEYOLO_TMUX_SESSION", field("tmux_session"))
        .env(
            "SAFEYOLO_TMUX_SOCKET",
            if field("tmux_socket").is_empty() {
                crate::host_platform::config_dir()
                    .join("data/tmux.sock")
                    .to_string_lossy()
                    .into_owned()
            } else {
                field("tmux_socket").to_owned()
            },
        )
        .env("SAFEYOLO_LAUNCH_PANE", field("pane_id"))
        .env(
            "SAFEYOLO_AGENT_EXIT_CODE",
            record
                .get("exit_code")
                .filter(|value| !value.is_null())
                .map(Value::to_string)
                .unwrap_or_default(),
        )
        .env("SAFEYOLO_AGENT_EXIT_REASON", field("exit_reason"));
    command.env(
        "SAFEYOLO_EXECUTABLE",
        crate::host_platform::config_dir().join("bin/safeyolo"),
    );
    command.env(
        "SAFEYOLO_LAUNCHER_PRESETS",
        crate::host_platform::config_dir().join("assets/launchers"),
    );
    command
}

async fn launch_script(agent: &Agent, record: &Value) -> Result<(), Error> {
    let script = record
        .pointer("/launcher/script")
        .and_then(Value::as_str)
        .ok_or("launcher script missing")?;
    let path = std::path::Path::new(script).canonicalize()?;
    validate_host_script(&path)?;
    let output = script_command(&path, "launch", record)
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "Host launcher failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let launch_id = record["launch_id"].as_str().ok_or("launch ID missing")?;
    let result: Value = if output.stdout.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&output.stdout)?
    };
    if !result.is_object() {
        return Err("Host launch result must be a JSON object or empty".into());
    }
    let _lock = LaunchLock::acquire(&agent.name)?;
    let mut current = read_json(&launch_path(&agent.name))?.ok_or("current launch is missing")?;
    if current["launch_id"] != launch_id {
        return Err("launch changed during host launcher invocation".into());
    }
    for key in ["pane_id", "tmux_socket"] {
        if let Some(value) = result.get(key) {
            current[key] = value.clone();
        }
    }
    if current["state"] == "starting"
        && matches!(
            current.pointer("/launcher/kind").and_then(Value::as_str),
            Some("script" | "manager")
        )
    {
        current["state"] = "unknown".into();
    }
    write_json(&launch_path(&agent.name), &current)
}

async fn stop(agent: &Agent) -> Result<Value, Error> {
    let directory = agent_dir(&agent.name);
    let _lock =
        tokio::task::spawn_blocking(move || SetupLock::acquire_in(&directory, None)).await??;
    let command_warning = stop_supervisor(&agent.name)
        .await
        .err()
        .map(|error| error.to_string());
    stop_launcher(agent).await?;
    let observed = crate::host_runs::observe(&agent.name).await;
    if observed["runtime_state"] != "stopped" || observed["backend"].is_object() {
        crate::host_platform::stop_sandbox(&agent.name).await?;
    }
    crate::host_platform::update_agent_map(&agent.name, None)?;
    if let Some(mut run) = crate::host_runs::read(&agent.name)? {
        run["state"] = "stopped".into();
        crate::host_runs::save(&agent.name, &run)?;
    }
    sync_agent_listeners().await?;
    crate::host_events::write(
        &agent.name,
        "agent.stopped",
        "agent",
        format!("Agent {} stopped by user", agent.name),
        None,
        json!({"reason":"user_request"}),
    );
    let mut result = runtime(agent).await?;
    if let Some(warning) = command_warning {
        result["command_stop_warning"] = warning.into();
    }
    Ok(result)
}

fn clear_stale_guest_command(name: &str) -> Result<(), Error> {
    for relative in [
        "home/.safeyolo-command-supervisor.json",
        "home/.safeyolo-command-supervisor.stop",
        "config-share/command-supervisor-enabled",
    ] {
        match std::fs::remove_file(agent_dir(name).join(relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn cleanup(agent: &Agent) -> Result<Value, Error> {
    stop(agent).await?;
    let directory = agent_dir(&agent.name);
    let lock_directory = directory.clone();
    let _lock =
        tokio::task::spawn_blocking(move || SetupLock::acquire_in(&lock_directory, None)).await??;
    if crate::host_runs::observe(&agent.name).await["runtime_state"] != "stopped" {
        return Err("backend is not proven stopped; its state was preserved".into());
    }
    #[cfg(target_os = "macos")]
    crate::host_platform::remove_stopped_vz_sockets(&agent.name)?;
    if let Some(record) = read_json(&launch_path(&agent.name))?
        && process_matches(&record, "runner_pid", "runner_token")
    {
        return Err(
            "coding-agent exit hooks are still finishing; retry agent cleanup after they finish"
                .into(),
        );
    }
    clear_stale_guest_command(&agent.name)?;
    for file in [
        "runtime.json",
        "current-launch.json",
        "userns.pid",
        "container.pid",
        "vm.pid",
        "vm.token",
    ] {
        match std::fs::remove_file(directory.join(file)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    runtime(agent).await
}

async fn stop_supervisor(name: &str) -> Result<(), Error> {
    let marker = agent_dir(name).join("config-share/command-supervisor-enabled");
    match std::fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let Some(state) = supervisor_state(name)? else {
        return Ok(());
    };
    let id = state["supervision_id"]
        .as_str()
        .ok_or("command supervisor ownership is unverified")?;
    crate::guest_commands::request_stop(
        &agent_dir(name).join("home"),
        &agent_dir(name).join("config-share"),
        id,
    )?;
    // Give the native supervisor its existing ten-second command termination
    // interval before the host stops PID 1. A fence alone does not prove exit.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let current = supervisor_state(name)?
            .ok_or("command supervisor state disappeared; completion is unverified")?;
        if current["supervision_id"] != id {
            return Err(
                "command supervisor ownership changed; replacement work was left intact".into(),
            );
        }
        if matches!(
            current["state"].as_str(),
            Some("stopped" | "failed" | "exited")
        ) && current["command_pid"].is_null()
            && current["command_start_token"].is_null()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "command supervisor stop deadline expired; completion is unverified".into(),
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn stop_launcher(agent: &Agent) -> Result<(), Error> {
    let Some(mut record) = read_json(&launch_path(&agent.name))? else {
        return Ok(());
    };
    if record.get("agent_id").and_then(Value::as_str) != Some(&agent.id) {
        return Err("Stored launcher identity does not match agent".into());
    }
    let state = record
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !matches!(state, "exited" | "failed" | "stopped") {
        let launch_id = record
            .get("launch_id")
            .and_then(Value::as_str)
            .ok_or("stored launch ID is missing")?;
        update_launch(
            &agent.name,
            launch_id,
            &serde_json::Map::from_iter([("state".to_owned(), "stopping".into())]),
        )?;
        record["state"] = "stopping".into();
    }
    let kind = record
        .pointer("/launcher/kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    if matches!(kind, "script" | "manager") {
        let path = record
            .pointer("/launcher/script")
            .and_then(Value::as_str)
            .ok_or("host launcher path missing")?;
        let path = std::path::Path::new(path).canonicalize()?;
        validate_host_script(&path)?;
        let status = script_command(&path, "stop", &record).status().await?;
        if !status.success() {
            return Err("Host launcher stop failed".into());
        }
    } else if process_matches(&record, "pid", "process_token")
        && let Some(pid) = record.get("pid").and_then(Value::as_i64)
        && let Ok(pid) = i32::try_from(pid)
    {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_home_changes_cannot_replace_the_active_host_setup_lock() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("agent");
        let first = SetupLock::acquire_in(&directory, None).unwrap();
        let guest = directory.join("home/.safeyolo");
        std::fs::create_dir_all(&guest).unwrap();
        let replaced = guest.join("host-setup.lock");
        std::fs::write(&replaced, b"guest replacement").unwrap();
        std::fs::remove_file(&replaced).unwrap();
        let second = SetupLock::acquire_in(
            &directory,
            Some(std::time::Instant::now() + std::time::Duration::from_millis(10)),
        );
        assert!(second.is_err(), "guest home bypassed the active host lock");
        drop(first);
        assert!(SetupLock::acquire_in(&directory, None).is_ok());
    }
}
