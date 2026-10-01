//! Installed Command Centre agent state and fixed lifecycle operations.

use std::{
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

struct SetupLock(File);

impl SetupLock {
    fn acquire(name: &str) -> Result<Self, Error> {
        let home = agent_dir(name).join("home");
        std::fs::create_dir_all(&home)?;
        let directory = home.join(".safeyolo");
        if !directory.exists() {
            std::fs::create_dir(&directory)?;
        }
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)?;
        let metadata = opened.metadata()?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(format!("unsafe host setup directory for agent {name}").into());
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
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
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
        let path = launch_path(name).with_extension("lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .truncate(false)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(file))
    }
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
        .is_some_and(|state| !matches!(state, "exited" | "stopped"))
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

/// Hidden native proxy entrypoint used by its own host tmux launch. The stable
/// launch ID and host-owned record fence the guest command to one run.
pub(crate) async fn run_entrypoint(name: &str, launch_id: &str) -> Result<i32, Error> {
    if !crate::host_platform::valid_agent_name(name) || !launch_id.starts_with("launch-") {
        return Err("invalid host agent entrypoint".into());
    }
    let result = run_entrypoint_inner(name, launch_id).await;
    if let Err(error) = &result {
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
    let record = read_json(&launch_path(name))?.ok_or("No matching coding-agent launch")?;
    if record.get("launch_id").and_then(Value::as_str) != Some(launch_id)
        || !matches!(
            record.get("state").and_then(Value::as_str),
            Some("starting" | "unknown")
        )
    {
        return Err("No matching stopped coding-agent launch is ready".into());
    }
    let command = record
        .get("command")
        .and_then(Value::as_str)
        .ok_or("agent launch command is missing")?
        .to_owned();
    let pid = std::process::id() as i64;
    let mut changes = serde_json::Map::new();
    changes.insert("state".into(), "launching".into());
    changes.insert("runner_pid".into(), pid.into());
    changes.insert("runner_token".into(), process_token(pid).into());
    if let Ok(pane) = std::env::var("TMUX_PANE") {
        let output = tokio::process::Command::new("tmux")
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
    if !crate::host_platform::is_sandbox_running(name).await {
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
    let mut child = crate::host_platform::spawn_guest_command(name, &command).await?;
    let child_pid = i64::from(child.id().ok_or("guest transport has no PID")?);
    if let Err(error) = update_launch(
        name,
        launch_id,
        &serde_json::Map::from_iter([
            ("state".to_owned(), "running".into()),
            ("pid".to_owned(), child_pid.into()),
            ("process_token".to_owned(), process_token(child_pid).into()),
        ]),
    ) {
        let _ = child.kill().await;
        return Err(error);
    }
    let status = match child.wait().await {
        Ok(status) => status,
        Err(error) => {
            let _ = child.kill().await;
            return Err(error.into());
        }
    };
    let code = status.code().unwrap_or(1);
    update_launch(
        name,
        launch_id,
        &serde_json::Map::from_iter([
            ("state".to_owned(), "exited".into()),
            ("exit_code".to_owned(), code.into()),
            ("exit_reason".to_owned(), "command exited".into()),
        ]),
    )?;
    Ok(code)
}

fn read_json(path: &std::path::Path) -> Result<Option<Value>, Error> {
    match std::fs::read(path) {
        Ok(source) => Ok(Some(serde_json::from_slice(&source)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn selected_launcher(agent: &Agent) -> Value {
    let configured = agent.launcher.clone().or_else(|| {
        let path = crate::host_platform::config_dir().join("config.yaml");
        let source = std::fs::read_to_string(path).ok()?;
        let config = yaml_rust2::YamlLoader::load_from_str(&source).ok()?;
        config.first()?["agent_launcher"]["default"]
            .as_str()
            .map(str::to_owned)
    });
    let (mut value, source) = match configured {
        Some(value) if agent.launcher.is_some() => (value, "agent"),
        Some(value) => (value, "host default"),
        None => ("interactive".to_owned(), "built-in"),
    };
    if value == "interactive" {
        value = "tmux-window".to_owned();
    }
    let kind = if value.starts_with("manager:") {
        "manager"
    } else if value.starts_with('/') {
        "script"
    } else {
        value.as_str()
    };
    let script = match kind {
        "tmux-window" | "tmux-pane" => std::env::var_os("SAFEYOLO_CLI_ASSETS_DIR")
            .map(PathBuf::from)
            .map(|directory| directory.join("launchers").join(format!("{kind}.sh")))
            .map(|path| path.to_string_lossy().into_owned()),
        "manager" => Some(value.trim_start_matches("manager:").to_owned()),
        "script" => Some(value.clone()),
        _ => None,
    };
    let mut result = json!({"kind":kind,"source":source});
    if let Some(script) = script {
        result["script"] = script.into();
    }
    result
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
fn process_token(pid: i64) -> Option<String> {
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
fn process_token(pid: i64) -> Option<String> {
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
    let ready = crate::host_platform::is_sandbox_running(&agent.name).await;
    let mut launcher = selected_launcher(agent);
    let mut state = "stopped".to_owned();
    let mut attachable = false;
    let mut launch_id = Value::Null;
    let mut exit_code = Value::Null;
    let mut error = Value::Null;
    let mut hook_errors = json!([]);
    if let Some(record) = read_json(&launch_path(&agent.name))? {
        if record.get("agent_id").and_then(Value::as_str) != Some(&agent.id)
            || record.get("name").and_then(Value::as_str) != Some(&agent.name)
        {
            return Err(format!(
                "Stored launcher identity does not match agent {}",
                agent.name
            )
            .into());
        }
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
                && process_matches(&record, "runner_pid", "runner_token")
            {
                state = "finishing".to_owned();
            }
        } else if launcher.get("kind").and_then(Value::as_str) == Some("supervisor") {
            if recorded == "starting" {
                state = "starting".to_owned();
            } else if let Some(supervisor) = supervisor_state(&agent.name)? {
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
                && !process_matches(&record, "runner_pid", "runner_token")
            {
                state = "exited".to_owned();
                if error.is_null() {
                    error = "Launch process exited without recording its result".into();
                }
            } else if recorded == "running" {
                state = if process_matches(&record, "pid", "process_token") {
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
    Ok(json!({
        "agent_id":agent.id,"name":agent.name,
        "sandbox_state":if ready { "ready" } else { "stopped" },
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
            observed.push(runtime(agent).await?);
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
        "start" | "start-interactive" => start(&agent, operation == "start-interactive").await,
        "stop" => stop(&agent).await,
        _ => Ok(json!({"error":"invalid host operation","status_code":400})),
    };
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            Ok(json!({"error":format!("Agent operation failed: {error}"),"status_code":500}))
        }
    }
}

async fn start(agent: &Agent, interactive: bool) -> Result<Value, Error> {
    let _lock = SetupLock::acquire(&agent.name)?;
    let observed = runtime(agent).await?;
    let state = observed
        .get("agent_state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !matches!(state, "stopped" | "exited" | "failed") {
        return Ok(json!({"error":format!("Agent cannot start while {state}"),"status_code":409}));
    }
    let folder = agent
        .folder
        .as_deref()
        .ok_or("agent workspace is not configured")?;
    let workspace = std::path::Path::new(folder).canonicalize()?;
    let metadata = workspace.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("agent workspace is missing or is not owned by the operator".into());
    }
    stop_supervisor(&agent.name).await?;
    if !crate::host_platform::is_sandbox_running(&agent.name).await {
        let slot = crate::host_agents::reserve_network_slot(&agent.name)?;
        let address = u32::from(slot) + 1;
        let ip = format!("10.200.{}.{}", address / 256, address % 256);
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
    let mut launcher = selected_launcher(agent);
    if interactive {
        launcher = json!({"kind":"tmux-window","source":"requested"});
        if let Some(path) = std::env::var_os("SAFEYOLO_CLI_ASSETS_DIR") {
            launcher["script"] = PathBuf::from(path)
                .join("launchers/tmux-window.sh")
                .to_string_lossy()
                .into_owned()
                .into();
        }
    }
    let debug_command = interactive && agent.launcher.as_deref() == Some("supervisor");
    let command = configured_guest_command(agent, debug_command)?;
    let launch_id = format!("launch-{}", uuid::Uuid::new_v4().simple());
    let timestamp =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let session = tmux_session();
    let record = json!({
        "name":agent.name,"agent_id":agent.id,"launch_id":launch_id,
        "launcher":launcher,"workspace":workspace,"mode":"background",
        "command":command,"state":"starting","tmux_session":session,
        "started_at":timestamp,"requester_pid":std::process::id(),
        "requester_token":process_token(std::process::id() as i64)
    });
    {
        let _launch_lock = LaunchLock::acquire(&agent.name)?;
        write_json(&launch_path(&agent.name), &record)?;
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
        Ok("exec /bin/bash -l".to_owned())
    } else {
        Ok(args.join(" "))
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

fn tmux_session() -> String {
    let path = crate::host_platform::config_dir().join("config.yaml");
    let Some(config) = std::fs::read_to_string(path)
        .ok()
        .and_then(|source| yaml_rust2::YamlLoader::load_from_str(&source).ok())
    else {
        return "safeyolo".to_owned();
    };
    config
        .first()
        .and_then(|value| value["agent_launcher"]["tmux_session"].as_str())
        .unwrap_or("safeyolo")
        .to_owned()
}

async fn sync_agent_listeners() -> Result<(), Error> {
    let Some(path) = std::env::var_os("SAFEYOLO_NATIVE_CONFIG_PATH").map(PathBuf::from) else {
        // Direct embedded Proxy callers own their own configuration reload.
        return Ok(());
    };
    if !path.is_absolute() {
        return Err("native proxy config path must be absolute".into());
    }
    let _same_process_lock = LISTENER_LOCK.lock().await;
    let _lock = crate::host_platform::lock_host_state(
        &crate::host_platform::config_dir().join("data/native-listeners.lock"),
    )?;
    let cwd = std::env::var_os("SAFEYOLO_NATIVE_WORKING_DIRECTORY")
        .map(PathBuf::from)
        .ok_or("native proxy working directory is missing")?;
    let sockets = crate::host_platform::config_dir().join("data/sockets");
    let source = std::fs::read(&path)?;
    let mut config: Value = serde_json::from_slice(&source)?;
    let entries = config
        .get("listeners")
        .and_then(Value::as_array)
        .ok_or("native listeners must be a JSON array")?;
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
    let map_path = crate::host_platform::config_dir().join("data/agent_map.json");
    let map: serde_json::Map<String, Value> = serde_json::from_slice(&std::fs::read(map_path)?)?;
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
    serde_json::to_writer_pretty(&mut temporary, &config)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.persist(path)?;
    if unsafe { libc::kill(libc::getpid(), libc::SIGHUP) } != 0 {
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
            let path = supervisor_path(&agent.name);
            let stop = path.with_file_name(".safeyolo-command-supervisor.stop");
            if let Err(error) = std::fs::remove_file(stop)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error.into());
            }
            write_json(
                &path,
                &json!({
                    "schema_version":1,"name":agent.name,"command":record["command"],
                    "state":"starting","runtime_owner":"guest-pid1","started_at":time::OffsetDateTime::now_utc().unix_timestamp(),
                    "restart_count":0,"consecutive_failures":0,"heartbeat_at":null,
                    "last_stderr":"","last_exit_code":null,"next_restart_at":null
                }),
            )?;
            std::fs::write(
                agent_dir(&agent.name).join("config-share/command-supervisor-enabled"),
                b"",
            )?;
            update_launch(
                &agent.name,
                launch_id,
                &serde_json::Map::from_iter([("state".to_owned(), "managed".into())]),
            )?;
            Ok(())
        }
        "tmux-window" | "tmux-pane" => launch_tmux(agent, record, kind).await,
        "script" | "manager" => launch_script(agent, record).await,
        _ => Err(format!("unsupported agent launcher: {kind}").into()),
    }
}

async fn launch_tmux(agent: &Agent, record: &Value, kind: &str) -> Result<(), Error> {
    let session = record
        .get("tmux_session")
        .and_then(Value::as_str)
        .ok_or("tmux session missing")?;
    let launch_id = record
        .get("launch_id")
        .and_then(Value::as_str)
        .ok_or("launch ID missing")?;
    let binary = std::env::var_os("SAFEYOLO_NATIVE_PROXY_BINARY")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?);
    let mut arguments = vec![
        "--host-agent-entrypoint".to_owned(),
        agent.name.clone(),
        launch_id.to_owned(),
    ];
    let mut output = tokio::process::Command::new("tmux")
        .args(["has-session", "-t", &format!("={session}")])
        .output()
        .await?;
    let format = "#{socket_path}\n#{pane_id}";
    if !output.status.success() {
        output = tokio::process::Command::new("tmux")
            .args([
                "new-session",
                "-d",
                "-P",
                "-F",
                format,
                "-s",
                session,
                "-n",
                &agent.name,
            ])
            .arg(&binary)
            .args(&arguments)
            .output()
            .await?;
    } else {
        output.stdout.clear();
    }
    if !output.status.success() || output.stdout.is_empty() {
        let mut command = tokio::process::Command::new("tmux");
        if kind == "tmux-pane" {
            command.args([
                "split-window",
                "-d",
                "-P",
                "-F",
                format,
                "-t",
                &format!("={session}:"),
            ]);
        } else {
            command.args([
                "new-window",
                "-d",
                "-P",
                "-F",
                format,
                "-t",
                &format!("={session}:"),
                "-n",
                &agent.name,
            ]);
        }
        output = command.arg(&binary).args(&arguments).output().await?;
    }
    if !output.status.success() {
        return Err(format!(
            "tmux launcher failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let value = String::from_utf8(output.stdout)?;
    let (socket, pane) = value
        .trim_end()
        .rsplit_once('\n')
        .ok_or("tmux did not report a pane")?;
    update_launch(
        &agent.name,
        launch_id,
        &serde_json::Map::from_iter([
            ("tmux_socket".to_owned(), socket.into()),
            ("pane_id".to_owned(), pane.into()),
        ]),
    )?;
    arguments.clear();
    Ok(())
}

fn validate_host_script(path: &std::path::Path) -> Result<(), Error> {
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
        .env("SAFEYOLO_LOGS_DIR", logs_dir)
        .env("SAFEYOLO_AGENT_NAME", field("name"))
        .env("SAFEYOLO_AGENT_ID", field("agent_id"))
        .env("SAFEYOLO_LAUNCH_ID", field("launch_id"))
        .env("SAFEYOLO_WORKSPACE", field("workspace"))
        .env("SAFEYOLO_LAUNCH_MODE", field("mode"))
        .env("SAFEYOLO_TMUX_SESSION", field("tmux_session"))
        .env("SAFEYOLO_TMUX_SOCKET", field("tmux_socket"))
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
    if let Some(python) = std::env::var_os("SAFEYOLO_CLI_PYTHON") {
        command.env("SAFEYOLO_PYTHON", python);
    }
    if let Some(assets) = std::env::var_os("SAFEYOLO_CLI_ASSETS_DIR") {
        command.env(
            "SAFEYOLO_LAUNCHER_PRESETS",
            PathBuf::from(assets).join("launchers"),
        );
    }
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
    let mut changes = serde_json::Map::new();
    for key in ["pane_id", "tmux_socket"] {
        if let Some(value) = result.get(key) {
            changes.insert(key.to_owned(), value.clone());
        }
    }
    changes.insert("state".into(), "unknown".into());
    update_launch(&agent.name, launch_id, &changes)
}

async fn stop(agent: &Agent) -> Result<Value, Error> {
    let _lock = SetupLock::acquire(&agent.name)?;
    stop_supervisor(&agent.name).await?;
    stop_launcher(agent).await?;
    if !crate::host_platform::is_sandbox_running(&agent.name).await {
        return runtime(agent).await;
    }
    crate::host_platform::stop_sandbox(&agent.name).await?;
    crate::host_platform::update_agent_map(&agent.name, None)?;
    sync_agent_listeners().await?;
    crate::host_events::write(
        &agent.name,
        "agent.stopped",
        "agent",
        format!("Agent {} stopped by user", agent.name),
        None,
        json!({"reason":"user_request"}),
    );
    runtime(agent).await
}

async fn stop_supervisor(name: &str) -> Result<(), Error> {
    let marker = agent_dir(name).join("config-share/command-supervisor-enabled");
    match std::fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let Some(mut state) = supervisor_state(name)? else {
        return Ok(());
    };
    let path = supervisor_path(name);
    write_json(
        &path.with_file_name(".safeyolo-command-supervisor.stop"),
        &json!({"requested_at":time::OffsetDateTime::now_utc().unix_timestamp(),"name":name}),
    )?;
    let current = state
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if matches!(current, "stopped" | "failed" | "exited") {
        state["state"] = "stopped".into();
        state["next_restart_at"] = Value::Null;
        write_json(&path, &state)?;
    } else if state.get("runtime_owner").and_then(Value::as_str) != Some("guest-pid1") {
        // This state lives in the agent-writable home. A PID plus process
        // start token from that file cannot authorize a host signal. Let the
        // supervisor consume its stop fence, then require its acknowledgement.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if supervisor_state(name)?
                .as_ref()
                .is_none_or(|value| value.get("state").and_then(Value::as_str) == Some("stopped"))
            {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        return Err("Could not stop the command supervisor; the sandbox was left intact to prevent an automatic restart".into());
    }
    Ok(())
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
