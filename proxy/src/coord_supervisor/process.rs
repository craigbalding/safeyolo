//! Linux invocation ownership, deadlines and native harness event consumption.

use super::*;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::{
    fs::OpenOptions,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

pub(super) fn lock(path: &Path) -> Result<fs::File, Error> {
    let mut name = path
        .file_name()
        .ok_or("state has no filename")?
        .to_os_string();
    name.push(".lock");
    let lock = path.with_file_name(name);
    fs::create_dir_all(lock.parent().ok_or("state has no parent")?)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(lock)?;
    if !file.metadata()?.is_file() {
        return Err("supervisor lock must be a regular file".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another supervisor owns this checkpoint".into());
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn token(pid: i32) -> Option<String> {
    crate::host_lifecycle::process_token(i64::from(pid))
}
#[cfg(not(target_os = "linux"))]
fn token(_pid: i32) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn pid_handle(pid: i32, expected: &str) -> Option<OwnedFd> {
    if pid <= 0 || token(pid).as_deref() != Some(expected) {
        return None;
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    (token(pid).as_deref() == Some(expected)).then_some(fd)
}
#[cfg(not(target_os = "linux"))]
fn pid_handle(_pid: i32, _expected: &str) -> Option<OwnedFd> {
    None
}

#[cfg(target_os = "linux")]
fn signal(fd: &OwnedFd, number: i32) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            number,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}
#[cfg(not(target_os = "linux"))]
fn signal(_fd: &OwnedFd, _number: i32) {}

fn snapshot(leader: i32, include_group: bool) -> Result<BTreeMap<i32, String>, Error> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((_, tail)) = stat.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<_> = tail.split_whitespace().collect();
        let Some(parent) = fields.get(1).and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Some(group) = fields.get(2).and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if let Some(token) = token(pid) {
            processes.push((pid, parent, group, token));
        }
    }
    let mut descendants = BTreeSet::from([leader]);
    loop {
        let before = descendants.len();
        for (pid, parent, group, _) in &processes {
            if descendants.contains(parent) || (include_group && *group == leader) {
                descendants.insert(*pid);
            }
        }
        if before == descendants.len() {
            break;
        }
    }
    let found: BTreeMap<_, _> = processes
        .into_iter()
        .filter(|(pid, _, _, _)| *pid != leader && descendants.contains(pid))
        .map(|(pid, _, _, token)| (pid, token))
        .collect();
    if found.len() > 64 {
        return Err("owned invocation exceeds the existing 64-descendant checkpoint bound".into());
    }
    Ok(found)
}

fn capture_descendants(owned: &mut Owned) -> Result<(), Error> {
    // Only live birth identities need cleanup. Retaining every completed tool
    // child makes a serial invocation exceed the concurrent ownership bound.
    let mut living = BTreeMap::new();
    for (pid, expected) in &owned.descendants {
        if alive(*pid, expected)? {
            living.insert(*pid, expected.clone());
        }
    }
    owned.descendants = living;
    if token(owned.pid).as_deref() == Some(&owned.token) {
        owned.descendants.extend(snapshot(owned.pid, true)?);
    }
    // A setsid child becomes our child when its leader exits: this process
    // is the invocation's subreaper. Use kernel parentage, without including
    // other processes that merely share the supervisor's process group.
    let mut adopted = snapshot(std::process::id() as i32, false)?;
    adopted.remove(&owned.pid);
    owned.descendants.extend(adopted);
    if owned.descendants.len() > 64 {
        return Err("owned descendants exceed checkpoint capacity".into());
    }
    Ok(())
}

fn alive(pid: i32, expected: &str) -> Result<bool, Error> {
    if let Some(current) = token(pid) {
        return Ok(current == expected);
    }
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Ok(stat)
            if stat
                .rsplit_once(')')
                .is_some_and(|(_, tail)| tail.split_whitespace().next() == Some("Z")) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
        _ => Err("owned process identity is unavailable; checkpoint retained".into()),
    }
}

async fn cleanup(owned: &mut Owned, grace: u64) -> Result<(), Error> {
    capture_descendants(owned)?;
    if alive(owned.pid, &owned.token)? && pid_handle(owned.pid, &owned.token).is_none() {
        return Err("cannot open the owned invocation PID handle; checkpoint retained".into());
    }
    if let Some(leader) = pid_handle(owned.pid, &owned.token)
        && unsafe { libc::getpgid(owned.pid) } == owned.pid
    {
        // The live leader's PID handle and fingerprint bind the group. Once
        // that leader exits, only individual verified PID handles are used.
        if token(owned.pid).as_deref() == Some(&owned.token) {
            unsafe {
                libc::kill(-owned.pid, libc::SIGTERM);
            }
        }
        signal(&leader, libc::SIGTERM);
    }
    for (pid, expected) in &owned.descendants {
        if alive(*pid, expected)? && pid_handle(*pid, expected).is_none() {
            return Err("cannot open owned descendant PID handle; checkpoint retained".into());
        }
        if let Some(fd) = pid_handle(*pid, expected) {
            signal(&fd, libc::SIGTERM);
        }
    }
    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(grace);
    let mut killed = false;
    loop {
        let before = owned.descendants.clone();
        capture_descendants(owned)?;
        for (pid, expected) in &owned.descendants {
            if before.get(pid) != Some(expected) && alive(*pid, expected)? {
                let fd = pid_handle(*pid, expected)
                    .ok_or("cannot open owned descendant PID handle; checkpoint retained")?;
                signal(&fd, if killed { libc::SIGKILL } else { libc::SIGTERM });
            }
        }
        let identities = std::iter::once((owned.pid, &owned.token))
            .chain(owned.descendants.iter().map(|(pid, t)| (*pid, t)));
        let living = identities
            .map(|(pid, t)| alive(pid, t))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .any(|v| v);
        if !living {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            if killed {
                return Err("owned invocation did not stop; checkpoint retained".into());
            }
            if let Some(fd) = pid_handle(owned.pid, &owned.token) {
                signal(&fd, libc::SIGKILL);
            }
            for (pid, expected) in &owned.descendants {
                if let Some(fd) = pid_handle(*pid, expected) {
                    signal(&fd, libc::SIGKILL);
                }
            }
            killed = true;
            deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(target_os = "linux")]
fn require_pid_handles() -> Result<(), Error> {
    let pid = std::process::id() as i32;
    let expected = token(pid).ok_or("supervisor cannot identify itself")?;
    if pid_handle(pid, &expected).is_none() {
        return Err("supervisor requires Linux PID handles".into());
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn require_pid_handles() -> Result<(), Error> {
    Err("model-turn supervision runs inside a Linux guest, including guests on VZ".into())
}

pub(super) async fn recover(state: &mut State, path: &Path, grace: u64) -> Result<(), Error> {
    require_pid_handles()?;
    if let Some(owned) = &mut state.owned_process {
        let result = cleanup(owned, grace).await;
        state.save(path)?;
        result?;
        state.owned_process = None;
        state.phase = "uncertain".into();
        // Claude persists its selected session before dispatch. Resume that
        // session with the uncertain checkpoint after owned cleanup succeeds.
        if state.harness != "claude" {
            state.thread_id = None;
        }
        state.save(path)?;
    } else if state.phase == "running" {
        state.phase = "uncertain".into();
        if state.harness != "claude" {
            state.thread_id = None;
        }
        state.save(path)?;
    }
    Ok(())
}

#[derive(Default)]
struct Events {
    started: bool,
    completed: bool,
    failed: bool,
    harness_failed: bool,
    canonical: bool,
    consumed_information: bool,
    unresolved_send: bool,
    pi_args: BTreeMap<String, Value>,
    claude_calls: BTreeMap<String, Value>,
}

fn structured(item: &Value) -> Option<&Value> {
    item["result"]
        .get("structured_content")
        .or_else(|| item["result"].get("structuredContent"))
}
fn normalized(item: &Value) -> Option<(Value, Value)> {
    if item["status"] != "completed" || !item["error"].is_null() {
        return None;
    }
    let tool = item["tool"].as_str()?;
    if !["send", "send_task"].contains(&tool) {
        return None;
    }
    let mut args = item["arguments"].clone();
    let result = structured(item)?.clone();
    if tool == "send_task" {
        args["body"] = json!(format!(
            "TASK target={} assignee={}\n\n{}",
            text(&args, "target").ok()?,
            text(&args, "assignee").ok()?,
            text(&args, "body").ok()?
        ));
        args["notify"] = json!([text(&args, "assignee").ok()?]);
    }
    if !result["envelope"].is_object() || result["sequence"].as_u64().is_none_or(|n| n == 0) {
        return None;
    }
    Some((result, args))
}
impl Events {
    fn complete_information(
        &mut self,
        supervisor: &mut Supervisor,
        invoked: &BTreeSet<String>,
    ) -> Result<(), Error> {
        let completed: Vec<_> = supervisor
            .state
            .in_flight
            .iter()
            .filter(|p| !p.requires_terminal && invoked.contains(&p.attention_id))
            .map(|p| p.attention_id.clone())
            .collect();
        self.consumed_information |= !completed.is_empty();
        for id in completed {
            supervisor.state.complete(&id);
        }
        let completed: Vec<_> = supervisor
            .state
            .approval_notifications
            .iter()
            .map(approval_notification_id)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|id| invoked.contains(*id))
            .map(str::to_owned)
            .collect();
        self.consumed_information |= !completed.is_empty();
        supervisor
            .state
            .approval_notifications
            .retain(|p| !completed.iter().any(|id| p["edge"]["attention_id"] == *id));
        for id in completed {
            supervisor.state.remember(&id);
        }
        let before = supervisor.state.native_in_flight.len();
        supervisor
            .state
            .native_in_flight
            .retain(|d| d.action.requires_action || !invoked.contains(&d.action.key));
        self.consumed_information |= before != supervisor.state.native_in_flight.len();
        supervisor.state.save(&supervisor.state_path)?;
        Ok(())
    }

    fn consume(
        &mut self,
        supervisor: &mut Supervisor,
        event: &Value,
        invoked: &BTreeSet<String>,
    ) -> Result<(), Error> {
        if !event.is_object() {
            self.failed = true;
            return Ok(());
        }
        let kind = event["type"].as_str().unwrap_or("");
        let pi = supervisor.config.harness == "pi";
        let claude = supervisor.config.harness == "claude";
        let codex = !pi && !claude;
        // Match the native Claude session and main turn, as the existing
        // streaming attention adapter does. Nested tool sessions cannot finish it.
        if claude {
            if !event["parent_tool_use_id"].is_null() {
                return Ok(());
            }
            if kind == "system"
                && event["subtype"] == "init"
                && event["mcp_servers"].as_array().is_none_or(|servers| {
                    !servers.iter().any(|server| {
                        server["name"] == "safeyolo-coord" && server["status"] == "connected"
                    })
                })
            {
                self.failed = true;
                eprintln!("Claude safeyolo-coord MCP connection is unavailable");
            }
            if matches!(kind, "system" | "assistant" | "user" | "result")
                && event["session_id"].as_str() != supervisor.state.thread_id.as_deref()
            {
                self.failed = true;
                return Ok(());
            }
            if let Some(blocks) = event["message"]["content"].as_array() {
                for block in blocks {
                    if kind == "assistant"
                        && block["type"] == "tool_use"
                        && let (Some(id), Some(tool)) =
                            (block["id"].as_str(), block["name"].as_str())
                        && let Some(tool) = tool.strip_prefix("mcp__safeyolo-coord__")
                    {
                        if tool == "wait_for_coord" {
                            self.failed = true;
                        }
                        if matches!(tool, "send" | "send_task") {
                            self.claude_calls
                                .insert(id.into(), json!({"tool":tool,"arguments":block["input"]}));
                        }
                    } else if kind == "user"
                        && block["type"] == "tool_result"
                        && let Some(id) = block["tool_use_id"].as_str()
                        && let Some(mut item) = self.claude_calls.remove(id)
                    {
                        // Claude exposes the MCP structured result on the user
                        // tool-result event, separately from assistant narration.
                        item["status"] = json!("completed");
                        item["result"] = event["tool_use_result"].clone();
                        if block["is_error"] != true
                            && let Some((result, args)) = normalized(&item)
                        {
                            self.canonical |= supervisor.outbound(&result, &args, false)?;
                        } else {
                            self.unresolved_send = true;
                        }
                    }
                }
            }
        }
        if (codex && kind == "thread.started") || (pi && kind == "session") {
            let id = text(event, if pi { "id" } else { "thread_id" })?;
            if id.is_empty() {
                return Err("harness returned an empty session ID".into());
            }
            supervisor.state.thread_id = Some(id.into());
            supervisor.state.save(&supervisor.state_path)?;
        } else if (codex && kind == "turn.started")
            || (pi && kind == "agent_start")
            || (claude && kind == "system" && event["subtype"] == "init")
        {
            self.started = true;
            supervisor.state.phase = "running".into();
            supervisor.state.save(&supervisor.state_path)?;
        } else if (codex && kind == "turn.completed")
            || (claude
                && kind == "result"
                && event["subtype"] == "success"
                && event["is_error"] == false
                && self.started
                && !self.failed)
            || (pi
                && kind == "agent_end"
                && event["willRetry"] != true
                && !self.failed
                && !self.harness_failed)
        {
            self.completed = true;
            if !claude {
                self.complete_information(supervisor, invoked)?;
            }
        } else if (codex && kind == "turn.failed") || (claude && kind == "result") {
            self.failed = true;
        } else if pi && kind == "message_end" && event["message"]["role"] == "assistant" {
            self.harness_failed = matches!(
                event["message"]["stopReason"].as_str(),
                Some("error" | "aborted")
            );
        } else if pi && kind == "tool_execution_start" {
            if let Some(id) = event["toolCallId"].as_str() {
                self.pi_args.insert(id.into(), event["args"].clone());
            }
        } else if pi && kind == "tool_execution_end" {
            if let Some(id) = event["toolCallId"].as_str()
                && let Some(args) = self.pi_args.remove(id)
                && event["toolName"] == "send"
                && event["isError"] != true
                && event["result"]["details"]["envelope"].is_object()
                && event["result"]["details"]["sequence"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
            {
                self.canonical |= supervisor.outbound(&event["result"]["details"], &args, false)?;
            } else if event["toolName"] == "send" {
                self.unresolved_send = true;
            }
        } else if codex
            && kind == "item.completed"
            && event["item"]["type"] == "mcp_tool_call"
            && event["item"]["server"] == "safeyolo-coord"
        {
            if event["item"]["tool"] == "wait_for_coord" {
                self.failed = true;
            } else if matches!(event["item"]["tool"].as_str(), Some("send" | "send_task")) {
                if let Some((result, args)) = normalized(&event["item"]) {
                    self.canonical |= supervisor.outbound(&result, &args, false)?;
                } else {
                    self.unresolved_send = true;
                }
            }
        }
        Ok(())
    }
}

fn telemetry_body(harness: &str, event: &Value) -> String {
    let mut event = event.clone();
    // Pi agent_end includes the full session messages. Keep its completion
    // signal; the established per-event telemetry owns the individual items.
    if harness == "pi" && event["type"] == "agent_end" {
        let count = event["messages"].as_array().map_or(0, Vec::len);
        let mut usage = BTreeMap::<String, u64>::new();
        if let Some(messages) = event["messages"].as_array() {
            for message in messages.iter().filter(|m| m["role"] == "assistant") {
                for key in [
                    "input",
                    "output",
                    "cacheRead",
                    "cacheWrite",
                    "reasoning",
                    "totalTokens",
                ] {
                    if let Some(value) = message["usage"][key].as_u64() {
                        let total = usage.entry(key.into()).or_default();
                        *total = total.saturating_add(value);
                    }
                }
            }
        }
        if !usage.is_empty() {
            event["usage"] = json!(usage);
        }
        if let Some(object) = event.as_object_mut() {
            object.remove("messages");
        }
        event["message_count"] = json!(count);
    }
    let raw = event.to_string();
    if raw.len() <= 256 * 1024 {
        raw
    } else {
        let digest = ring::digest::digest(&ring::digest::SHA256, raw.as_bytes());
        let hash: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let head: String = raw.chars().take(10000).collect();
        let tail: String = raw
            .chars()
            .rev()
            .take(10000)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        json!({"type":format!("safeyolo.{harness}.stdout"),"event":"oversize","original_bytes":raw.len(),"sha256":hash,"head":head,"tail":tail,"middle_omitted":true}).to_string()
    }
}

async fn publish_telemetry(client: &Client, room: &str, body: String) {
    match tokio::time::timeout(Duration::from_secs(5),client.call("send",&json!({"room_name":room,"body":body,"declared_content_type":"text/plain","notify":"none"}))).await {
        Ok(Ok(_))=>{},Ok(Err(error))=>eprintln!("Coord telemetry unavailable: {error}"),Err(_)=>eprintln!("Coord telemetry deadline expired; publication outcome unknown"),
    }
}

// One invocation owns one ordered sender. Each queued body is at most 256 KiB;
// a full buffer drops new telemetry without delaying canonical event handling.
#[derive(Default)]
struct Telemetry {
    pending: Option<tokio::sync::mpsc::Sender<String>>,
    sender: tokio::task::JoinSet<()>,
    dropped: u64,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if !self.sender.is_empty() {
            // JoinSet aborts its tasks on drop, including cancellation of invoke.
            eprintln!(
                "Coord telemetry sender stopped; pending events omitted and publication outcome unknown"
            );
        }
    }
}

impl Telemetry {
    fn start(supervisor: &Supervisor) -> Self {
        let mut telemetry = Self::default();
        if let Some(room) = &supervisor.config.agent_room {
            let room = room.clone();
            let client = supervisor.client.clone();
            let (pending, mut receiver) = tokio::sync::mpsc::channel::<String>(64);
            telemetry.pending = Some(pending);
            telemetry.sender.spawn(async move {
                while let Some(body) = receiver.recv().await {
                    publish_telemetry(&client, &room, body).await;
                }
            });
        }
        telemetry
    }

    fn push(&mut self, supervisor: &Supervisor, event: &Value) {
        if let Some(pending) = &self.pending
            && pending
                .try_send(telemetry_body(&supervisor.config.harness, event))
                .is_err()
        {
            self.dropped = self.dropped.saturating_add(1);
            if self.dropped == 1 {
                eprintln!("Coord telemetry buffer full or sender unavailable; new events omitted");
            }
        }
    }

    async fn finish(&mut self) {
        drop(self.pending.take());
        match tokio::time::timeout(Duration::from_secs(1), self.sender.join_next()).await {
            Ok(Some(Err(error))) => {
                eprintln!("Coord telemetry sender failed: {error}; publication outcome unknown")
            }
            Err(_) => {
                eprintln!(
                    "Coord telemetry shutdown deadline expired; pending events omitted and in-flight publication outcome unknown"
                );
                self.sender.shutdown().await;
            }
            _ => {}
        }
        if self.dropped > 0 {
            eprintln!(
                "Coord telemetry omitted {} new events during invocation",
                self.dropped
            );
        }
    }
}

pub(super) async fn notice(supervisor: &Supervisor, event: &str, detail: &str) {
    if let Some(room) = &supervisor.config.agent_room {
        publish_telemetry(
            &supervisor.client,
            room,
            telemetry_body(
                &supervisor.config.harness,
                &json!({"type":"safeyolo.supervisor", "event":event, "detail":detail}),
            ),
        )
        .await;
    }
}

fn arguments(supervisor: &Supervisor) -> Vec<OsString> {
    let mut args = supervisor.harness_args.clone();
    if supervisor.state.repair_selection.is_some()
        && let Some(repair) = supervisor.config.repair_policy()
    {
        for pair in repair.args.chunks(2) {
            if pair.len() == 2 && pair[0].starts_with('-') {
                let mut position = 0;
                while position < args.len() {
                    if args[position] == std::ffi::OsStr::new(&pair[0]) {
                        args.remove(position);
                        if position < args.len() {
                            args.remove(position);
                        }
                    } else {
                        position += 1;
                    }
                }
            }
        }
        args.extend(repair.args.iter().map(OsString::from));
    }
    args
}

pub(super) async fn invoke(
    supervisor: &mut Supervisor,
    rooms: &BTreeMap<String, String>,
) -> Result<bool, Error> {
    let pi = supervisor.config.harness == "pi";
    let claude = supervisor.config.harness == "claude";
    let program = std::env::var_os(match supervisor.config.harness.as_str() {
        "pi" => "SAFEYOLO_PI_BIN",
        "claude" => "SAFEYOLO_CLAUDE_BIN",
        _ => "SAFEYOLO_CODEX_BIN",
    })
    .unwrap_or_else(|| supervisor.config.harness.clone().into());
    let resuming = supervisor.state.thread_id.is_some();
    let recovering_uncertainty = supervisor.state.phase == "uncertain";
    let mut command = tokio::process::Command::new(program);
    let args = arguments(supervisor);
    if claude {
        preflight::claude_arguments(&args)?;
        // Select the session before dispatch so even an interrupted first turn
        // has a known native recovery operand. Startup failure clears it below.
        let id = supervisor
            .state
            .thread_id
            .get_or_insert_with(|| uuid::Uuid::new_v4().to_string());
        command
            .args(&args)
            .args(["--print", "--output-format", "stream-json", "--verbose"])
            .arg(if resuming { "--resume" } else { "--session-id" })
            .arg(id);
    } else if pi {
        command.args(["--mode", "json", "--print"]);
        if let Some(id) = &supervisor.state.thread_id {
            command.args(["--session", id]);
        }
        command.args(&args);
    } else {
        command.args(&args).arg("exec");
        if let Some(id) = &supervisor.state.thread_id {
            command.args(["resume", "--json", "--skip-git-repo-check", id, "-"]);
        } else {
            command
                .args(["--json", "--cd"])
                .arg(&supervisor.config.workspace)
                .args(["--skip-git-repo-check", "-"]);
        }
    }
    command
        .current_dir(&supervisor.config.workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !pi {
        crate::coding_client::authenticate(command.as_std_mut(), &supervisor.config.harness)
            .await?;
    }
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let prompt = supervisor.prompt(rooms)?;
    let invoked: BTreeSet<_> = supervisor
        .state
        .objects()
        .iter()
        .map(|p| p.attention_id.clone())
        .chain(
            supervisor
                .state
                .approval_notifications
                .iter()
                .map(|p| p["edge"]["attention_id"].as_str().unwrap().to_owned()),
        )
        .chain(
            supervisor
                .state
                .native_in_flight
                .iter()
                .map(|d| d.action.key.clone()),
        )
        .collect();
    let began = tokio::time::Instant::now();
    let mut deadline = began + Duration::from_secs(supervisor.config.startup_timeout_seconds);
    let hard = deadline + Duration::from_secs(supervisor.config.work_timeout_seconds);
    let mut child = command.spawn()?;
    let pid = child.id().ok_or("harness has no PID")? as i32;
    let Some(expected) = token(pid) else {
        child.kill().await?;
        return Err("harness identity unavailable; child stopped before dispatch".into());
    };
    supervisor.state.owned_process = Some(Owned {
        pid,
        token: expected.clone(),
        descendants: BTreeMap::new(),
    });
    if let Err(error) = supervisor.state.save(&supervisor.state_path) {
        child.kill().await?;
        return Err(error);
    }
    let mut telemetry = Telemetry::start(supervisor);
    telemetry.push(
        supervisor,
        &json!({"type":"safeyolo.supervisor", "event":"start", "detail":"bounded harness invocation started; canonical work checkpointed"}),
    );
    let result=async {
        let mut stdin=child.stdin.take().ok_or("harness stdin is missing")?;
        tokio::time::timeout_at(deadline,async{stdin.write_all(prompt.as_bytes()).await?;stdin.shutdown().await}).await??;
        drop(stdin);
        let mut stdout=tokio::io::BufReader::new(child.stdout.take().ok_or("harness stdout is missing")?);
        let mut stderr=child.stderr.take().ok_or("harness stderr is missing")?;
        let mut line=Vec::new();let mut errbuf=vec![0u8;64*1024];let mut out_open=true;let mut err_open=true;
        let mut events=Events::default();let mut work_deadline=false;
        let mut tick=tokio::time::interval(Duration::from_millis(250));
        while out_open||err_open||child.try_wait()?.is_none() {
            tokio::select! {
                _=tokio::time::sleep_until(deadline)=>{events.failed=true;break;}
                _=tick.tick()=>{
                    let owned=supervisor.state.owned_process.as_mut().ok_or("lost invocation identity")?;
                    capture_descendants(owned)?;
                    supervisor.state.save(&supervisor.state_path)?;
                }
                count=stdout.read_until(b'\n',&mut line),if out_open=>{
                    let count=count?;if count==0{out_open=false;continue;}
                    if line.iter().all(u8::is_ascii_whitespace){line.clear();continue;}
                    match serde_json::from_slice::<Value>(&line) {
                        Ok(event)=>{
                            events.consume(supervisor,&event,&invoked)?;
                            if !pi||!matches!(event["type"].as_str(),Some("message_update"|"message_start")){telemetry.push(supervisor,&event);}
                        }
                        Err(_)=>{events.failed=true;eprintln!("harness emitted malformed JSON");}
                    }
                    line.clear();
                    if events.started&&!work_deadline {work_deadline=true;deadline=hard.min(tokio::time::Instant::now()+Duration::from_secs(supervisor.config.work_timeout_seconds));}
                    if events.completed {deadline=deadline.min(tokio::time::Instant::now()+Duration::from_secs(supervisor.config.completion_grace_seconds));}
                }
                count=stderr.read(&mut errbuf),if err_open=>{
                    let count=count?;if count==0{err_open=false;continue;}
                    let text=String::from_utf8_lossy(&errbuf[..count]);eprint!("{text}");
                    telemetry.push(supervisor,&json!({"type":format!("safeyolo.{}.stderr",supervisor.config.harness),"text":text}));
                }
            }
        }
        Ok::<_,Error>(events)
    }.await;
    let mut owned = supervisor
        .state
        .owned_process
        .clone()
        .ok_or("lost owned process checkpoint")?;
    capture_descendants(&mut owned)?;
    supervisor.state.owned_process = Some(owned.clone());
    supervisor.state.save(&supervisor.state_path)?;
    let cleanup_result = cleanup(&mut owned, supervisor.config.terminate_grace_seconds).await;
    supervisor.state.owned_process = Some(owned);
    supervisor.state.save(&supervisor.state_path)?;
    cleanup_result?;
    let exit_success = child.wait().await?.success();
    telemetry.push(
        supervisor,
        &json!({"type":"safeyolo.supervisor", "event":"exit", "detail":"owned harness invocation stopped and cleanup verified"}),
    );
    telemetry.finish().await;
    #[cfg(target_os = "linux")]
    loop {
        let mut status = 0;
        if unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } <= 0 {
            break;
        }
    }
    supervisor.state.owned_process = None;
    let mut events = match result {
        Ok(events) => events,
        Err(error) => {
            supervisor.state.phase = "uncertain".into();
            supervisor.state.thread_id = None;
            supervisor.state.save(&supervisor.state_path)?;
            return Err(error);
        }
    };
    if claude && events.completed && !events.failed && !events.harness_failed && exit_success {
        events.complete_information(supervisor, &invoked)?;
    }
    let terminals_before = supervisor
        .state
        .in_flight
        .iter()
        .filter(|p| p.requires_terminal)
        .count();
    let native_before: BTreeSet<_> = supervisor
        .state
        .native_in_flight
        .iter()
        .map(|d| d.action.key.clone())
        .collect();
    supervisor.reconcile().await?;
    let recovered_terminal = supervisor
        .state
        .in_flight
        .iter()
        .filter(|p| p.requires_terminal)
        .count()
        < terminals_before;
    let native_settled = supervisor
        .state
        .native_in_flight
        .iter()
        .filter(|d| native_before.contains(&d.action.key))
        .count()
        < native_before.len();
    let success = recovered_terminal
        || native_settled
        || ((!events.unresolved_send || supervisor.state.pending_count() == 0)
            && (events.canonical
                || ((supervisor.state.pending_count() == 0
                    || (events.consumed_information
                        && !recovering_uncertainty
                        && !supervisor.state.has_ready_work()))
                    && events.completed
                    && !events.failed
                    && !events.harness_failed
                    && exit_success)));
    if supervisor.state.pending_count() == 0 {
        supervisor.state.phase = "idle".into();
    } else if success {
        supervisor.state.phase = "accepted".into();
    } else {
        supervisor.state.phase = "uncertain".into();
        if resuming || !events.started {
            supervisor.state.thread_id = None;
        }
    }
    supervisor.state.consecutive_failures = if success {
        0
    } else {
        (supervisor.state.consecutive_failures + 1).min(31)
    };
    supervisor.state.save(&supervisor.state_path)?;
    Ok(success)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn waiting_child() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .args(["-c", "read -r line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn finish(child: &mut std::process::Child) {
        drop(child.stdin.take());
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn interrupted_recovery_keeps_claude_session_after_owned_cleanup() {
        let mut child = waiting_child();
        let owned = Owned {
            pid: child.id() as i32,
            token: token(child.id() as i32).unwrap(),
            descendants: BTreeMap::new(),
        };
        finish(&mut child);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("checkpoint.json");
        let session = "db6b6137-37d1-40d3-b1e8-caaf898afdc0";
        for harness in ["claude", "codex", "pi"] {
            for process in [None, Some(owned.clone())] {
                let mut state = State {
                    harness: harness.into(),
                    thread_id: Some(session.into()),
                    owned_process: process,
                    phase: "running".into(),
                    safe_cursor: 11,
                    ..State::default()
                };
                recover(&mut state, &path, 1).await.unwrap();
                assert_eq!(state.phase, "uncertain");
                assert!(state.owned_process.is_none());
                assert_eq!(state.safe_cursor, 11);
                assert_eq!(
                    state.thread_id.as_deref(),
                    (harness == "claude").then_some(session)
                );
                assert_eq!(State::load(&path).unwrap().thread_id, state.thread_id);
            }
        }
    }

    #[test]
    fn capture_retains_live_identities_without_accumulating_exited_children() {
        // The supervisor owns a process tree, so isolate this witness from
        // child processes created by other concurrently running Rust tests.
        if std::env::var_os("SAFEYOLO_TEST_CAPTURE_INNER").is_none() {
            let observed = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "coord_supervisor::process::tests::capture_retains_live_identities_without_accumulating_exited_children",
                    "--nocapture",
                ])
                .env("SAFEYOLO_TEST_CAPTURE_INNER", "1")
                .output()
                .unwrap();
            assert!(
                observed.status.success(),
                "{}{}",
                String::from_utf8_lossy(&observed.stdout),
                String::from_utf8_lossy(&observed.stderr)
            );
            return;
        }
        let pid = std::process::id() as i32;
        let mut owned = Owned {
            pid,
            token: token(pid).unwrap(),
            descendants: BTreeMap::new(),
        };
        let mut keeper = waiting_child();
        let keeper_pid = keeper.id() as i32;
        let keeper_token = token(keeper_pid).unwrap();
        for _ in 0..67 {
            let mut child = waiting_child();
            let observed = capture_descendants(&mut owned);
            finish(&mut child);
            observed.unwrap();
            assert_eq!(owned.descendants.get(&keeper_pid), Some(&keeper_token));
        }
        capture_descendants(&mut owned).unwrap();
        assert_eq!(owned.descendants.len(), 1);
        finish(&mut keeper);

        // The existing bound still rejects more than 64 concurrent children.
        let mut children: Vec<_> = (0..65).map(|_| waiting_child()).collect();
        let observed = capture_descendants(&mut owned);
        for child in &mut children {
            finish(child);
        }
        assert!(observed.unwrap_err().to_string().contains("64-descendant"));
    }
}
