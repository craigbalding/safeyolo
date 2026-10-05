//! Installed native operator commands, using the same host operations as Admin.

use crate::{Error, host_agents, host_lifecycle, host_platform, host_runs};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(any(target_os = "macos", test))]
use tokio::io::AsyncReadExt;

pub fn handles(args: &[String]) -> bool {
    args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "agent" | "start" | "stop" | "status" | "doctor"
        )
    })
}

pub async fn run(config: PathBuf, args: &[String]) -> Result<i32, Error> {
    let parent = config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let config = parent.join(config.file_name().ok_or("configuration has no filename")?);
    host_platform::in_config(config, run_inner(args)).await
}

/// Rebuild derived listeners from current runs before native proxy startup.
/// Guest traffic is not a recovery trigger.
pub async fn prepare_proxy(config: &mut crate::Config) -> Result<(), Error> {
    if let Some(path) = config.native_config_path.clone() {
        host_platform::in_config(path.clone(), async {
            restore_attachments(config).await?;
            host_lifecycle::sync_agent_listeners().await?;
            *config = crate::native_config::read(&path)?;
            Ok::<_, Error>(())
        })
        .await?;
    }
    Ok(())
}

pub fn record_proxy(root: &Path) -> Result<(), Error> {
    let pid = std::process::id();
    let token = host_lifecycle::process_token(i64::from(pid))
        .ok_or("proxy process identity unavailable")?;
    crate::guest_commands::write_json(
        &root.join("data/proxy-process.json"),
        &json!({"pid":pid,"token":token}),
    )
}

fn print(value: &Value) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn agent(name: &str) -> Result<host_agents::Agent, Error> {
    host_agents::list()?
        .into_iter()
        .find(|agent| agent.name == name)
        .ok_or_else(|| format!("agent not found: {name}").into())
}
fn process_path() -> PathBuf {
    host_platform::config_dir().join("data/proxy-process.json")
}
pub(crate) fn proxy_live() -> bool {
    crate::guest_commands::read_state(&process_path())
        .ok()
        .flatten()
        .is_some_and(|record| {
            record["pid"]
                .as_i64()
                .zip(record["token"].as_str())
                .is_some_and(|(pid, token)| {
                    host_lifecycle::process_token(pid).as_deref() == Some(token)
                        && host_platform::process_has_path_argument(
                            pid,
                            &host_platform::config_dir().join("bin/safeyolo-proxy"),
                            b"--config",
                            &host_platform::config_path(),
                        )
                })
        })
}

async fn start_proxy() -> Result<(), Error> {
    let root = host_platform::config_dir();
    let lock_path = root.join("data/proxy-start.lock");
    let _lock =
        tokio::task::spawn_blocking(move || host_platform::lock_host_state(&lock_path)).await??;
    if proxy_live() {
        return Ok(());
    }
    let config_path = host_platform::config_path();
    let config = crate::native_config::read(&config_path)?;
    let readiness = &config.readiness_file;
    match fs::remove_file(readiness) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(root.join("logs/proxy.log"))?;
    let mut command = tokio::process::Command::new(root.join("bin/safeyolo-proxy"));
    command
        .args(["--config"])
        .arg(config_path)
        .env("SAFEYOLO_CONFIG_DIR", &root)
        .env_remove("SAFEYOLO_HOST_SETUP_LOCK_FD")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        command.as_std_mut().pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Err("proxy exited during startup; inspect logs/proxy.log".into());
        }
        if Path::new(readiness).is_file() && proxy_live() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    child.kill().await?;
    Err("proxy did not publish readiness within five seconds; inspect logs/proxy.log".into())
}

async fn stop_proxy() -> Result<(), Error> {
    if !proxy_live() {
        return Ok(());
    }
    let record = crate::guest_commands::read_state(&process_path())?
        .ok_or("proxy process record is missing")?;
    let pid = i32::try_from(record["pid"].as_i64().ok_or("proxy PID is missing")?)?;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while proxy_live() {
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "proxy did not stop within five seconds; agent runtimes remain intact".into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

pub(crate) async fn restore_attachments(config: &mut crate::Config) -> Result<(), Error> {
    let root = host_platform::config_dir();
    let sockets = root.join("data/sockets");
    // Reconstruct only the owned per-agent projection. Explicit operator
    // listeners retain their existing owner and configuration.
    for agent in host_agents::list()? {
        let observed = host_runs::observe(&agent.name).await;
        if observed["runtime_state"] == "stopped" {
            host_platform::update_agent_map(&agent.name, None)?;
            config.listeners.retain(|entry| {
                entry.agent_id != agent.name || !entry.socket_path.starts_with(&sockets)
            });
            continue;
        }
        // Damaged evidence for one agent cannot discard another agent's
        // projection or make the whole proxy unavailable. Preserve unknown
        // bindings until they can be reconciled; only a proven stale backend
        // authorizes their removal.
        let run = host_runs::read(&agent.name).ok().flatten();
        let context = crate::guest_commands::read_state(
            &root
                .join("agents")
                .join(&agent.name)
                .join("config-share/host-launch-context.json"),
        )
        .ok()
        .flatten();
        let Some(ip) = current_attachment_ip(&agent, &observed, run.as_ref(), context.as_ref())
        else {
            continue;
        };
        host_platform::update_agent_map(&agent.name, Some(ip))?;
        config.listeners.retain(|entry| {
            entry.agent_id != agent.name || !entry.socket_path.starts_with(&sockets)
        });
        config.listeners.push(crate::AgentListener {
            agent_id: agent.name.clone(),
            source_id: Some(ip.into()),
            socket_path: sockets
                .join(format!("{ip}_{}", agent.name))
                .join("proxy.sock"),
        });
    }
    Ok(())
}

fn current_attachment_ip<'a>(
    agent: &host_agents::Agent,
    observed: &Value,
    run: Option<&'a Value>,
    context: Option<&'a Value>,
) -> Option<&'a str> {
    if !matches!(
        observed["runtime_state"].as_str(),
        Some("running" | "starting" | "degraded")
    ) {
        return None;
    }
    let run_id = observed["run_id"].as_str()?;
    // The backend observation must identify this incarnation before either
    // host-owned record can supply its listener address. The read-only boot
    // share remains available when the saved process handle is lost.
    for (record, generation_key) in [(run, "run_id"), (context, "generation")] {
        let Some(record) = record else { continue };
        if record["agent_id"] == agent.id
            && record[generation_key] == run_id
            && let Some(ip) = record["ip"].as_str()
            && ip.parse::<std::net::Ipv4Addr>().is_ok()
        {
            return Some(ip);
        }
    }
    None
}

#[cfg(any(target_os = "macos", test))]
pub(crate) async fn shell_banner(path: &Path) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        let mut response = Vec::new();
        loop {
            let mut buffer = [0; 256];
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err("guest shell closed before an SSH banner".into());
            }
            response.extend_from_slice(&buffer[..count]);
            if response.len() > 1024 {
                return Err("guest shell returned an invalid SSH banner".into());
            }
            if response.contains(&b'\n') {
                if response.starts_with(b"SSH-2.0-") {
                    return Ok(());
                }
                return Err("guest shell returned an invalid SSH banner".into());
            }
        }
    })
    .await
    .map_err(|_| {
        "guest shell accepted the connection but supplied no SSH banner within three seconds"
            .to_owned()
    })?
}

async fn diagnostics(agent: &host_agents::Agent) -> Result<Value, Error> {
    let mut observed = host_lifecycle::operate("status", Some(&agent.id)).await?;
    observed["proxy_state"] = if proxy_live() {
        "running"
    } else {
        "unavailable"
    }
    .into();
    #[cfg(target_os = "macos")]
    {
        let control = host_runs::control(&agent.name, json!({"operation":"status"})).await;
        observed["private_control"] = match control {
            Ok(value) => value,
            Err(error) => json!({"error":error.to_string()}),
        };
        observed["shell"] = match shell_banner(
            &host_platform::config_dir()
                .join("data/shell-sockets")
                .join(format!("{}.sock", agent.name)),
        )
        .await
        {
            Ok(()) => json!({"state":"ready"}),
            Err(error) => {
                json!({"state":"unavailable","error":error.to_string(),"next_action":"inspect the helper and guest shell bridge; agent recover does not require SSH"})
            }
        };
    }
    #[cfg(target_os = "linux")]
    {
        observed["shell"] = json!({"state":if observed["exec"]==true {"ready"} else {"unavailable"},"transport":"runsc exec in the recorded namespaces"});
    }
    Ok(observed)
}

fn start_arguments(extra: &[String]) -> Result<(&str, Option<&[String]>, bool), Error> {
    let mut operation = "start";
    let mut allow_unowned = false;
    let mut arguments = None;
    for (index, option) in extra.iter().enumerate() {
        match option.as_str() {
            "--" => {
                arguments = Some(&extra[index + 1..]);
                break;
            }
            "--foreground" | "--sandbox-only" if operation == "start" => {
                operation = if option == "--foreground" {
                    "start-foreground"
                } else {
                    "sandbox-start"
                };
            }
            "--dangerously-allow-unowned" => allow_unowned = true,
            _ => return Err(format!("unexpected start argument: {option}").into()),
        }
    }
    if operation == "sandbox-start" && arguments.is_some() {
        return Err("--sandbox-only does not launch coding-agent arguments".into());
    }
    Ok((operation, arguments, allow_unowned))
}

fn inherited_setup_lock(
    agent: &host_agents::Agent,
) -> Result<Option<host_lifecycle::SetupLock>, Error> {
    match std::env::var("SAFEYOLO_HOST_SETUP_LOCK_FD") {
        Ok(descriptor) => Ok(Some(host_lifecycle::SetupLock::inherit_in(
            &host_platform::config_dir().join("agents").join(&agent.name),
            descriptor.parse()?,
        )?)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn run_inner(args: &[String]) -> Result<i32, Error> {
    let root = host_platform::config_dir();
    match args {
        [kind, operation, name, id] if kind == "agent" && operation == "launcher-session" => {
            print(&host_lifecycle::launcher_session(name, id).await?)?;
        }
        [kind, operation, name, id] if kind == "agent" && operation == "entrypoint" => {
            return host_lifecycle::run_entrypoint(name, id).await;
        }
        [command] if command == "start" => {
            start_proxy().await?;
            print(&json!({"proxy_state":"running","root":root}))?;
        }
        [command] if command == "stop" => {
            stop_proxy().await?;
            print(&json!({"proxy_state":"stopped","agents":"unchanged"}))?;
        }
        [command] if command == "status" || command == "doctor" => {
            let agents = host_lifecycle::operate("list", None).await?;
            print(
                &json!({"proxy_state":if proxy_live(){"running"}else{"unavailable"},"agents":agents["agents"],"root":root}),
            )?;
        }
        [agent, help] if agent == "agent" && help == "--help" => println!(
            "safeyolo [--root ROOT] agent create|configure NAME --workspace PATH [--memory MB] [--mount HOST:GUEST[:ro]] [--launcher tmux-window|tmux-pane|supervisor|SCRIPT] [--host-script SCRIPT] [--command COMMAND] [--dangerously-allow-unowned]\nsafeyolo [--root ROOT] agent start NAME [--foreground|--sandbox-only] [--dangerously-allow-unowned] [-- ARGUMENTS...]\nsafeyolo [--root ROOT] agent status|stop|cleanup|attach|diagnostics|recover NAME\nsafeyolo [--root ROOT] agent shell [--persistent] [--] NAME [-c COMMAND]\nsafeyolo [--root ROOT] agent diagnostics NAME relays|dump|cancel INSTANCE ID\nConfiguration changes apply at the next sandbox start. Start arguments affect only that launch. Attach never launches an absent coding agent. Shell is independent."
        ),
        [kind, operation, name, rest @ ..]
            if kind == "agent" && matches!(operation.as_str(), "create" | "configure") =>
        {
            let mut options = Vec::new();
            let mut values = rest.iter();
            while let Some(option) = values.next() {
                if option == "--dangerously-allow-unowned" {
                    options.push(("dangerously_allow_unowned".into(), "true".into()));
                    continue;
                }
                let key = match option.as_str() {
                    "--workspace" => "folder",
                    "--memory" => "memory_mb",
                    "--mount" => "mounts",
                    "--launcher" => "launcher",
                    "--host-script" => "host_script",
                    "--command" => "user_default_args",
                    _ => return Err(format!("unknown agent setting: {option}").into()),
                };
                let value = values
                    .next()
                    .ok_or_else(|| format!("{option} needs a value"))?;
                options.push((
                    key.into(),
                    if key == "user_default_args" {
                        serde_json::to_string(&vec!["/bin/bash", "-lc", value])?
                    } else {
                        value.clone()
                    },
                ));
            }
            let agent = host_agents::configure(name, &options, operation == "create").await?;
            print(
                &json!({"configuration":agent,"scope":"next sandbox start; current run is unchanged"}),
            )?;
        }
        [kind, operation, rest @ ..] if kind == "agent" => {
            let rest = if rest.first().is_some_and(|arg| arg == "--") {
                &rest[1..]
            } else {
                rest
            };
            let persistent =
                operation == "shell" && rest.first().is_some_and(|arg| arg == "--persistent");
            let rest = if persistent { &rest[1..] } else { rest };
            let rest = if rest.first().is_some_and(|arg| arg == "--") {
                &rest[1..]
            } else {
                rest
            };
            let name = rest.first().ok_or("agent name is required")?;
            let agent = agent(name)?;
            let extra = &rest[1..];
            match operation.as_str() {
                "start"|"stop"|"status"|"cleanup"=>{
                    let (operation, arguments, allow_unowned) = if operation=="start" {
                        start_arguments(extra)?
                    }else{if !extra.is_empty(){return Err("unexpected agent argument".into());} (operation.as_str(), None, false)};
                    let setup_lock = if matches!(operation, "start"|"start-foreground"|"sandbox-start"|"stop") {
                        inherited_setup_lock(&agent)?
                    } else { None };
                    if operation.starts_with("start") || operation=="sandbox-start" {start_proxy().await?;}
                    // Ordinary named runtime operations use the same authenticated
                    // Admin path as Commander. Foreground terminals stay local;
                    // independent stop remains available when the proxy is down.
                    let observed = if matches!(operation, "start"|"start-foreground"|"sandbox-start")
                        && (setup_lock.is_some() || arguments.is_some() || allow_unowned) {
                        host_lifecycle::start(&agent,operation,setup_lock,arguments,allow_unowned).await?
                    } else if operation=="stop" && setup_lock.is_some() {
                        host_lifecycle::stop(&agent,setup_lock).await?
                    } else if matches!(operation, "start" | "stop") && proxy_live() {
                        crate::native_client::admin(
                            &host_platform::config_path(),
                            &format!("/admin/agents/{}/{operation}", agent.id),
                            hyper::Method::POST,
                            Value::Null,
                            Duration::from_secs(130),
                        ).await?
                    } else {
                        host_lifecycle::operate(operation,Some(&agent.id)).await?
                    };
                    if let Some(error)=observed["error"].as_str().filter(|_|observed["status_code"].is_number()){return Err(error.into());}
                    if operation=="start-foreground" && observed["state"]=="starting" {
                        let id=observed["launch_id"].as_str().ok_or("no foreground launch was prepared")?;
                        return host_lifecycle::run_entrypoint(name,id).await;
                    }
                    print(&observed)?;
                },
                "attach"=>{if !extra.is_empty(){return Err("unexpected attach argument".into());}return host_lifecycle::attach(&agent).await;},
                "shell"=>{
                    let command=match extra {[]=>"exec /bin/bash -l",[flag,command]if flag=="-c"=>command,_=>return Err("shell accepts -c COMMAND".into())};
                    if persistent {return host_lifecycle::persistent_shell(&agent,command).await;}
                    let mut child=host_platform::spawn_guest_command(name,command).await?;
                    return Ok(child.wait().await?.code().unwrap_or(1));
                },
                "present"=>{ if !extra.is_empty(){return Err("unexpected desktop argument".into());}
                    let result = crate::desktop_present::present(agent.id.clone(), false).await
                        .map_err(|error| format!("desktop presentation failed: {error:?}; run agent diagnostics {name}"))?;
                    print(&result)?;
                },
                "diagnostics"=>{
                    match extra {
                        []=>print(&diagnostics(&agent).await?)?,
                        [op] if op=="relays"||op=="dump"=>print(&host_runs::control(name,json!({"operation":op})).await?)?,
                        [op,instance,id] if op=="cancel"=>print(&host_runs::control(name,json!({"operation":"cancel","instance":instance,"ids":[id.parse::<u64>()?],"reason":"operator requested cancellation"})).await?)?,
                        _=>return Err("diagnostics accepts relays, dump, or cancel INSTANCE ID".into()),
                    }
                },
                "recover"=>{
                    let timeout=match extra {[]=>Duration::from_secs(15),[flag,value]if flag=="--timeout"=>Duration::try_from_secs_f64(value.parse()?)?,_=>return Err("recover accepts --timeout SECONDS".into())};
                    if timeout.is_zero(){return Err("recovery timeout must be positive".into());}
                    let result=crate::recover_guest_probe(&root,name,timeout)?;
                    print(&json!({"guest_probe":result,"lifecycle":diagnostics(&agent).await?}))?;
                },
                _=>return Err("unknown agent operation; use agent --help".into()),
            }
        }
        _ => return Err("usage: safeyolo --help".into()),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_start_arguments_keep_defaults_distinct_from_an_empty_override() {
        let empty = Vec::new();
        assert_eq!(start_arguments(&empty).unwrap(), ("start", None, false));
        let override_args = vec!["--".into()];
        assert_eq!(
            start_arguments(&override_args).unwrap(),
            ("start", Some(&[][..]), false)
        );
        let literal = vec![
            "--foreground".into(),
            "--".into(),
            "--model".into(),
            "fixture model $(literal)".into(),
        ];
        let selected = start_arguments(&literal).unwrap();
        assert_eq!(selected.0, "start-foreground");
        assert_eq!(selected.1, Some(&literal[2..]));
    }

    #[test]
    fn lost_host_handle_can_restore_only_the_observed_agents_current_listener() {
        let agent = host_agents::Agent {
            id: "ag-current".into(),
            name: "probe".into(),
            folder: None,
            launcher: None,
            host_script: None,
            memory_mb: None,
            rootfs_overlay: None,
            user_default_args: Vec::new(),
            mounts: Vec::new(),
            dangerously_allow_unowned: false,
        };
        let observed = json!({"runtime_state":"degraded", "run_id":"current"});
        let context = json!({"generation":"current", "agent_id":"ag-current", "ip":"10.80.0.10"});
        assert_eq!(
            current_attachment_ip(&agent, &observed, None, Some(&context)),
            Some("10.80.0.10")
        );
        let invalid_handle = json!({"run_id":"current", "agent_id":"ag-current", "ip":false});
        assert_eq!(
            current_attachment_ip(&agent, &observed, Some(&invalid_handle), Some(&context)),
            Some("10.80.0.10")
        );
        for (field, value) in [
            ("generation", json!("prior")),
            ("agent_id", json!("ag-other")),
            ("ip", json!("invalid address")),
        ] {
            let mut conflicting = context.clone();
            conflicting[field] = value;
            assert_eq!(
                current_attachment_ip(&agent, &observed, None, Some(&conflicting)),
                None,
                "conflicting {field} was accepted"
            );
        }
        for state in ["stopped", "unknown"] {
            let mut unavailable = observed.clone();
            unavailable["runtime_state"] = state.into();
            assert_eq!(
                current_attachment_ip(&agent, &unavailable, None, Some(&context)),
                None,
                "boot metadata alone was accepted as runtime evidence"
            );
        }
    }

    #[tokio::test]
    async fn accepting_shell_without_banner_reports_the_bounded_hop_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shell.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let hold = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(stream);
        });
        let started = std::time::Instant::now();
        let error = shell_banner(&path).await.unwrap_err();
        assert!(error.to_string().contains("no SSH banner"));
        assert!(started.elapsed() < Duration::from_secs(5));
        hold.abort();
        let _ = hold.await;
    }
}
