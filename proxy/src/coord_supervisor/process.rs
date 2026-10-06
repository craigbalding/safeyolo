//! Linux invocation ownership, deadlines and Codex/Pi event consumption.

use super::*;
use std::{
    fs::OpenOptions,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

pub(super) fn lock(path: &Path) -> Result<fs::File, Error> {
    let lock = path.with_file_name(format!(
        "{}.lock",
        path.file_name()
            .ok_or("state has no filename")?
            .to_string_lossy()
    ));
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

fn snapshot(leader: i32) -> Result<BTreeMap<i32, String>, Error> {
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
            if descendants.contains(parent) || *group == leader {
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

async fn cleanup(owned: &Owned, grace: u64) -> Result<(), Error> {
    let mut descendants = owned.descendants.clone();
    if alive(owned.pid, &owned.token)? && pid_handle(owned.pid, &owned.token).is_none() {
        return Err("cannot open the owned invocation PID handle; checkpoint retained".into());
    }
    if let Some(leader) = pid_handle(owned.pid, &owned.token)
        && unsafe { libc::getpgid(owned.pid) } == owned.pid
    {
        descendants.extend(snapshot(owned.pid)?);
        // The live leader's PID handle and fingerprint bind the group. Once
        // that leader exits, only individual verified PID handles are used.
        if token(owned.pid).as_deref() == Some(&owned.token) {
            unsafe {
                libc::kill(-owned.pid, libc::SIGTERM);
            }
        }
        signal(&leader, libc::SIGTERM);
    }
    for (pid, expected) in &descendants {
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
        let identities = std::iter::once((owned.pid, &owned.token))
            .chain(descendants.iter().map(|(pid, t)| (*pid, t)));
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
            for (pid, expected) in &descendants {
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
    let expected = token(pid).ok_or("native supervisor cannot identify itself")?;
    if pid_handle(pid, &expected).is_none() {
        return Err("native supervisor requires Linux PID handles".into());
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
    if let Some(owned) = &state.owned_process {
        cleanup(owned, grace).await?;
        state.owned_process = None;
        state.phase = "uncertain".into();
        state.thread_id = None;
        state.save(path)?;
    } else if state.phase == "running" {
        state.phase = "uncertain".into();
        state.thread_id = None;
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
    pi_args: BTreeMap<String, Value>,
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
        if (!pi && kind == "thread.started") || (pi && kind == "session") {
            let id = text(event, if pi { "id" } else { "thread_id" })?;
            if id.is_empty() {
                return Err("harness returned an empty session ID".into());
            }
            supervisor.state.thread_id = Some(id.into());
            supervisor.state.save(&supervisor.state_path)?;
        } else if (!pi && kind == "turn.started") || (pi && kind == "agent_start") {
            self.started = true;
            supervisor.state.phase = "running".into();
            supervisor.state.save(&supervisor.state_path)?;
        } else if (!pi && kind == "turn.completed")
            || (pi
                && kind == "agent_end"
                && event["willRetry"] != true
                && !self.failed
                && !self.harness_failed)
        {
            self.completed = true;
            let completed: Vec<_> = supervisor
                .state
                .in_flight
                .iter()
                .filter(|p| !p.requires_terminal && invoked.contains(&p.attention_id))
                .map(|p| p.attention_id.clone())
                .collect();
            for id in completed {
                supervisor.state.complete(&id);
            }
            supervisor.state.save(&supervisor.state_path)?;
        } else if !pi && kind == "turn.failed" {
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
            {
                self.canonical |= supervisor.outbound(&event["result"]["details"], &args, false)?;
            }
        } else if !pi
            && kind == "item.completed"
            && event["item"]["type"] == "mcp_tool_call"
            && event["item"]["server"] == "safeyolo-coord"
        {
            if event["item"]["tool"] == "wait_for_coord" {
                self.failed = true;
            } else if let Some((result, args)) = normalized(&event["item"]) {
                self.canonical |= supervisor.outbound(&result, &args, false)?;
            }
        }
        Ok(())
    }
}

async fn telemetry(supervisor: &Supervisor, event: &Value) {
    let Some(room) = &supervisor.config.agent_room else {
        return;
    };
    let mut event = event.clone();
    // Pi agent_end includes the full session messages. Keep its completion
    // signal; the established per-event telemetry owns the individual items.
    if supervisor.config.harness == "pi" && event["type"] == "agent_end" {
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
    let body = if raw.len() <= 256 * 1024 {
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
        json!({"type":format!("safeyolo.{}.stdout",supervisor.config.harness),"event":"oversize","original_bytes":raw.len(),"sha256":hash,"head":head,"tail":tail,"middle_omitted":true}).to_string()
    };
    match tokio::time::timeout(Duration::from_secs(5),supervisor.client.call("send",&json!({"room_name":room,"body":body,"declared_content_type":"application/json","notify":"none"}))).await {
        Ok(Ok(_))=>{},Ok(Err(error))=>eprintln!("Coord telemetry unavailable: {error}"),Err(_)=>eprintln!("Coord telemetry deadline expired; publication outcome unknown"),
    }
}

pub(super) async fn notice(supervisor: &Supervisor, event: &str, detail: &str) {
    telemetry(
        supervisor,
        &json!({"type":"safeyolo.supervisor", "event":event, "detail":detail}),
    )
    .await;
}

fn arguments(supervisor: &Supervisor) -> Vec<String> {
    let mut args = supervisor.harness_args.clone();
    if supervisor.state.repair_selection.is_some()
        && let Some(repair) = supervisor.config.repair_policy()
    {
        for pair in repair.args.chunks(2) {
            if pair.len() == 2 && pair[0].starts_with('-') {
                let mut position = 0;
                while position < args.len() {
                    if args[position] == pair[0] {
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
        args.extend(repair.args.iter().cloned());
    }
    args
}

pub(super) async fn invoke(
    supervisor: &mut Supervisor,
    rooms: &BTreeMap<String, String>,
) -> Result<bool, Error> {
    let pi = supervisor.config.harness == "pi";
    let program = std::env::var_os(if pi {
        "SAFEYOLO_PI_BIN"
    } else {
        "SAFEYOLO_CODEX_BIN"
    })
    .unwrap_or_else(|| supervisor.config.harness.clone().into());
    let resuming = supervisor.state.thread_id.is_some();
    let mut command = tokio::process::Command::new(program);
    let args = arguments(supervisor);
    if pi {
        command.args(["--mode", "json", "--print"]);
        if let Some(id) = &supervisor.state.thread_id {
            command.args(["--session", id]);
        }
        command.args(&args);
    } else {
        command.args(&args).arg("exec");
        if let Some(id) = &supervisor.state.thread_id {
            command.args(["resume", "--json", id, "-"]);
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
    notice(
        supervisor,
        "start",
        "bounded harness invocation started; canonical work checkpointed",
    )
    .await;
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
                    if token(pid).as_deref()==Some(&expected) {
                        let descendants=snapshot(pid)?;
                        let owned=supervisor.state.owned_process.as_mut().ok_or("lost invocation identity")?;
                        owned.descendants.extend(descendants);
                        if owned.descendants.len()>64{return Err("owned descendants exceed checkpoint capacity".into());}
                        supervisor.state.save(&supervisor.state_path)?;
                    }
                }
                count=stdout.read_until(b'\n',&mut line),if out_open=>{
                    let count=count?;if count==0{out_open=false;continue;}
                    if line.iter().all(u8::is_ascii_whitespace){line.clear();continue;}
                    match serde_json::from_slice::<Value>(&line) {
                        Ok(event)=>{
                            events.consume(supervisor,&event,&invoked)?;
                            if !pi||!matches!(event["type"].as_str(),Some("message_update"|"message_start")){telemetry(supervisor,&event).await;}
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
                    telemetry(supervisor,&json!({"type":format!("safeyolo.{}.stderr",supervisor.config.harness),"text":text})).await;
                }
            }
        }
        Ok::<_,Error>(events)
    }.await;
    let owned = supervisor
        .state
        .owned_process
        .clone()
        .ok_or("lost owned process checkpoint")?;
    cleanup(&owned, supervisor.config.terminate_grace_seconds).await?;
    let exit_success = child.wait().await?.success();
    notice(
        supervisor,
        "exit",
        "owned harness invocation stopped and cleanup verified",
    )
    .await;
    #[cfg(target_os = "linux")]
    loop {
        let mut status = 0;
        if unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } <= 0 {
            break;
        }
    }
    supervisor.state.owned_process = None;
    let events = match result {
        Ok(events) => events,
        Err(error) => {
            supervisor.state.phase = "uncertain".into();
            supervisor.state.thread_id = None;
            supervisor.state.save(&supervisor.state_path)?;
            return Err(error);
        }
    };
    let terminals_before = supervisor
        .state
        .in_flight
        .iter()
        .filter(|p| p.requires_terminal)
        .count();
    supervisor.reconcile().await?;
    let recovered_terminal = supervisor
        .state
        .in_flight
        .iter()
        .filter(|p| p.requires_terminal)
        .count()
        < terminals_before;
    let success = events.canonical
        || recovered_terminal
        || (supervisor.state.in_flight.is_empty()
            && events.completed
            && !events.failed
            && !events.harness_failed
            && exit_success);
    if supervisor.state.in_flight.is_empty() {
        supervisor.state.phase = "idle".into();
    } else if events.canonical {
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
