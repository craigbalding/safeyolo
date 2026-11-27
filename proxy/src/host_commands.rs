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

pub const AGENT_HELP: &str = "safeyolo [--instance-dir PATH] agent launch [WORKSPACE] [--name NAME] [--harness claude|codex] [--launcher LAUNCHER] [--authentication client|host-vault]\nsafeyolo [--instance-dir PATH] agent auth NAME [--json]\nsafeyolo [--instance-dir PATH] agent create|configure NAME --workspace PATH [--memory MB] [--nested-docker true|false] [--mount HOST:GUEST[:ro]] [--launcher tmux-window|tmux-pane|supervisor|SCRIPT] [--host-script SCRIPT] [--command COMMAND] [--dangerously-allow-unowned]\nsafeyolo [--instance-dir PATH] agent start NAME [--foreground|--sandbox-only] [--dangerously-allow-unowned] [-- ARGUMENTS...]\nsafeyolo [--instance-dir PATH] agent status|stop|cleanup|attach|present|diagnostics NAME\nsafeyolo [--instance-dir PATH] agent recover NAME [--timeout SECONDS]\nsafeyolo [--instance-dir PATH] agent watch NAME [--history COUNT] [--once] [--plain]\nsafeyolo [--instance-dir PATH] agent shell [--persistent] [--] NAME [-c COMMAND]\nsafeyolo [--instance-dir PATH] agent mount NAME HOST:GUEST[:ro]\nsafeyolo [--instance-dir PATH] agent unmount NAME GUEST\nsafeyolo [--instance-dir PATH] agent mounts add|update NAME HOST:GUEST[:ro]\nsafeyolo [--instance-dir PATH] agent mounts remove NAME GUEST\nsafeyolo [--instance-dir PATH] agent retire NAME [--yes]\nsafeyolo [--instance-dir PATH] agent diagnostics NAME relays|dump|cancel INSTANCE ID\nSaved mount add/update replaces that guest destination; remove selects the guest path. Saved edits affect the next explicit start; live mount/unmount affects only the current run. A live-removed saved mount returns on restart. retire without --yes previews effects and retained paths/references. --yes stops/cleans the selected agent and removes its saved definition while retaining its home and external data. Home deletion is separate.\nLaunch defaults to the current directory, reuses an unambiguous saved workspace/name harness, and defaults new agents to Claude. Setup and optional Claude host-state copying require host consent. Codex uses agent-local authentication and settings. Detach from the agent terminal to review requests here. Configure changes apply at the next sandbox start. Linux nested-docker enables guest mount and namespace administration for an inner Docker daemon; it adds no host mounts or network interface. Mount and unmount change only the current sandbox; saved mounts are unchanged and apply again on restart. Busy removal is refused. Copied or already resident data is not erased. Start arguments affect only that launch. Attach never launches an absent coding agent. Shell is independent. For runtime, coding-agent, terminal or shell failures, use agent diagnostics NAME; it probes the selected runtime/control and reports a targeted next_action. Use doctor for host/pipeline probes, or diagnose for saved/current policy and audit availability without test traffic.";

pub fn handles(args: &[String]) -> bool {
    args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "agent" | "mount" | "start" | "stop" | "status" | "doctor"
        )
    })
}

pub const AGENT_LAUNCH_HELP: &str = crate::host_launch::HELP;
pub const AGENT_AUTH_HELP: &str = crate::host_client_auth::HELP;

pub async fn run(config: PathBuf, args: &[String]) -> Result<i32, Error> {
    let arguments = crate::operator_output::without_json(args);
    let args = arguments.as_slice();
    let parent = config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned();
    let parent = if parent.is_absolute() {
        parent
    } else {
        std::env::current_dir()?.join(parent)
    };
    let config = parent.join(config.file_name().ok_or("configuration has no filename")?);
    host_platform::in_config(config, run_inner(args)).await
}

/// Rebuild derived listeners from current runs before native proxy startup.
/// Guest traffic is not a recovery trigger.
pub async fn prepare_proxy(config: &mut crate::Config) -> Result<(), Error> {
    if let Some(path) = config.native_config_path.clone() {
        host_platform::in_config(path.clone(), async {
            let mut timing = crate::startup_timings::StartupTimings::new("listener_preparation");
            *config = host_lifecycle::sync_agent_listener_config(None)
                .await?
                .ok_or("proxy configuration disappeared during listener reconciliation")?;
            timing.record("projection");
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

pub const WEB_HELP: &str = "safeyolo agent publish NAME --port PORT --audience local|tailnet [--tailnet-port PORT] [--ttl SECONDS] [--json]\nsafeyolo agent publications NAME [--json]\nsafeyolo agent unpublish NAME --port PORT --audience local|tailnet [--tailnet-port PORT] [--json]\n\nPublish this running agent's HTTP app without starting a desktop. Local URLs are\nreachable on the SafeYolo host; tailnet URLs use that host's existing Tailscale\nServe authority. Open the URL on your device and enter the separate unlock code.\nApp login and cookies remain the app's responsibility. Publication grants no\nnetwork, credential or peer-support access. Default lifetime: 900 seconds.\nStop and expiry disconnect only this publication and remove its foreground Serve\nmapping. Unrelated mappings remain. The same agent, guest port, audience and\noptional tailnet port select unpublish.\nExample: safeyolo agent publish builder --port 3000 --audience tailnet";

pub const AGENT_LIFECYCLE_HELP: &str = host_lifecycle::scheduled::HELP;

pub(crate) fn print(value: &Value) -> Result<(), Error> {
    use crate::operator_output::{field, json, json_requested, rows, text};
    if json_requested() {
        return json(value);
    }
    if let Some(probe) = value.get("guest_probe") {
        field("Instance", &json!(host_platform::config_dir()));
        println!(
            "Guest probe completed for agent {}.",
            text(&value["lifecycle"]["name"])
        );
        field("Guest UID", &probe["result"]["uid"]);
        field(
            "SSH banner observed",
            &probe["result"]["sshd_loopback"]["received"],
        );
        field(
            "SSH observation",
            &probe["result"]["sshd_loopback"]["error"],
        );
        print(&value["lifecycle"])?;
        println!("The probe does not start or resume the coding agent.");
        if probe["result"]["sshd_loopback"]["received"] != true {
            println!(
                "Inspect: {} agent diagnostics {}",
                host_lifecycle::current_instance_command()?,
                host_lifecycle::shell_quote(
                    value["lifecycle"]["name"].as_str().unwrap_or_default()
                )
            );
        }
        println!("Use --json for the full probe and lifecycle observations.");
    } else if value["saved_configuration_changed"].is_boolean() {
        field("Instance", &value["root"]);
        field("Agent", &value["agent"]);
        field("Mount operation", &value["operation"]);
        field("Completed", &value["ok"]);
        field(
            "Guest path",
            value
                .get("destination")
                .unwrap_or(&value["share"]["guest_path"]),
        );
        field(
            "Saved configuration changed",
            &value["saved_configuration_changed"],
        );
        field("Activation", &value["scope"]);
        field("Error", &value["error"]);
        if value["ok"] != true {
            println!(
                "Inspect: {} agent status {}",
                host_lifecycle::current_instance_command()?,
                host_lifecycle::shell_quote(value["agent"].as_str().unwrap_or_default())
            );
        }
        println!("Use --json for the saved, live and next-start mount details.");
    } else if value.get("saved_configuration").is_some() {
        field("Instance", &json!(host_platform::config_dir()));
        field("Agent", &value["name"]);
        field("Lifecycle", &value["state"]);
        field("Mode", &value["saved_configuration"]["mode"]);
        field("Paused", &value["saved_configuration"]["paused"]);
        field("Activation", &value["activation"]);
        field("Next occurrence", &value["next_occurrence"]["state"]);
        field("Next occurrence at", &value["next_occurrence"]["at"]);
        field("Observation", &value["next_occurrence"]["reason"]);
        field("Error", &value["error"]);
        if value["saved_configuration"].is_null() {
            println!("No lifecycle configuration.");
        }
        println!("Use --json for the full lifecycle configuration and receipt.");
    } else if let Some(agents) = value["agents"].as_array() {
        field("Instance", &value["root"]);
        field("Proxy", &value["proxy_state"]);
        if agents.is_empty() {
            println!(
                "No agents configured. Start with: {} agent launch [WORKSPACE]",
                host_lifecycle::current_instance_command()?
            );
        } else {
            rows(
                agents,
                &[
                    ("AGENT", "name"),
                    ("RUNTIME", "runtime_state"),
                    ("CODING AGENT", "agent_state"),
                    ("WORKSPACE", "/next_start_configuration/workspace"),
                ],
            );
            let mut failures = std::collections::BTreeMap::<String, Vec<String>>::new();
            for agent in agents {
                for key in ["error", "runtime_error"] {
                    if let Some(error) = agent[key].as_str() {
                        let names = failures.entry(error.to_owned()).or_default();
                        let name = text(&agent["name"]);
                        if !names.contains(&name) {
                            names.push(name);
                        }
                    }
                }
            }
            for (error, names) in failures {
                println!(
                    "Unavailable for {}: {}",
                    names.join(", "),
                    text(&json!(error))
                );
            }
            let command = host_lifecycle::current_instance_command()?;
            println!(
                "Inspect an agent: {command} agent status NAME\nDiagnose uncertain state: {command} agent diagnostics NAME"
            );
        }
        if value["proxy_state"] == "unavailable" {
            println!(
                "Proxy is not verified running. Use doctor to inspect prerequisites, then start when ready."
            );
        }
    } else if value.get("runtime_state").is_some() {
        println!(
            "Agent {}: runtime {}; coding agent {}; terminal {}.",
            text(&value["name"]),
            text(&value["runtime_state"]),
            text(&value["agent_state"]),
            text(&value["terminal_state"])
        );
        field("Guest control", &value["control_state"]);
        field("Runtime observation", &value["runtime_error"]);
        field("Coding-agent observation", &value["error"]);
        if value["runtime_state"] == "stopped" && value["error"].is_null() {
            if let Some(code) = value["exit_code"].as_i64() {
                println!(
                    "Previous coding process exited with code {code}; the runtime is now stopped."
                );
            }
            println!(
                "Home and workspace retained. Resume: {} agent launch --name {}",
                host_lifecycle::current_instance_command()?,
                host_lifecycle::shell_quote(value["name"].as_str().unwrap_or_default())
            );
        } else {
            field("Next action", &value["next_action"]);
        }
    } else if value["retirement_state"].is_string() {
        field("Instance", &value["root"]);
        field("Agent", &value["agent"]);
        field("Retirement", &value["retirement_state"]);
        field("Effects", &value["effects"]);
        field("Home retained", &value["home"]);
        field("Workspace retained", &value["workspace_retained"]);
        field("Failed step", &value["failed_stage"]);
        field("Error", &value["error"]);
        if value["retirement_state"] == "preview"
            && let Some(command) = value["apply_command"].as_array()
        {
            println!(
                "Apply: {}",
                command
                    .iter()
                    .filter_map(Value::as_str)
                    .map(host_lifecycle::shell_quote)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        println!("Use --json to inspect retained grant, credential and Coord references.");
    } else if let Some(publications) = value["publications"].as_array() {
        if publications.is_empty() {
            println!("No web publications for this agent.");
        }
        rows(
            publications,
            &[
                ("AGENT", "agent"),
                ("GUEST PORT", "guest_port"),
                ("ACTIVE", "active"),
                ("URL", "url"),
            ],
        );
    } else if value["url"].is_string() {
        field("Agent", &value["agent"]);
        field("Guest port", &value["guest_port"]);
        field("Audience", &value["audience"]);
        field("URL", &value["url"]);
        field("Unlock code", &value["unlock_code"]);
        field("Lifetime (seconds)", &value["ttl_seconds"]);
        println!("Open this URL on the selected audience's device. Keep the unlock code private.");
    } else if value["publication_id"].is_string() && value["stopped"].is_boolean() {
        println!(
            "Web publication {} for guest port {}. Other publications and Tailscale mappings remain.",
            if value["stopped"] == true {
                "stopped"
            } else {
                "was already absent"
            },
            text(&value["guest_port"])
        );
    } else if let Some(paths) = value["protected_host_directories"].as_array() {
        if paths.is_empty() {
            println!("No extra-mount directory protections configured.");
        }
        for path in paths {
            println!("Protected: {}", text(path));
        }
        field("Applies to", &value["scope"]);
    } else if value.get("configuration").is_some() {
        println!(
            "Saved configuration for {}.",
            text(&value["configuration"]["name"])
        );
        field("Activation", &value["scope"]);
    } else if value.get("proxy_state").is_some() {
        field("Instance", &value["root"]);
        field("Proxy", &value["proxy_state"]);
        if value["agents"] == "unchanged" {
            println!("Agent runtimes remain intact.");
        }
    } else {
        for (label, key) in [
            ("Outcome", "status"),
            ("Completed", "ok"),
            ("Agent", "name"),
            ("Effect", "effect"),
            ("Activation", "scope"),
            ("Next action", "next_action"),
            ("Error", "error"),
            ("Terminal", "terminal_state"),
        ] {
            field(label, &value[key]);
        }
        if let Some(paths) = value["retained_paths"].as_array() {
            for path in paths {
                println!("Retained: {}", text(path));
            }
        }
        println!("Use --json for complete operation details.");
    }
    Ok(())
}
fn agent(name: &str) -> Result<host_agents::Agent, Error> {
    let agents = host_agents::list()?;
    let selected = agents
        .iter()
        .find(|agent| agent.name == name)
        .ok_or_else(|| format!("agent not found: {name}"))?;
    host_agents::by_id(&agents, &selected.id)?;
    Ok(selected.clone())
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
                        && crate::guest_acquisition::retained_host_binaries(
                            &host_platform::config_dir(),
                            "safeyolo-proxy",
                        )
                        .is_ok_and(|binaries| {
                            binaries.iter().any(|binary| {
                                host_platform::process_has_config_path(
                                    pid,
                                    binary,
                                    &host_platform::config_path(),
                                )
                            })
                        })
                })
        })
}

pub(crate) async fn start_proxy() -> Result<Option<Value>, Error> {
    crate::host_root::refuse_root("start the proxy")?;
    let mut timing = crate::startup_timings::StartupTimings::new("launcher");
    let root = host_platform::config_dir();
    let lock_path = root.join("data/proxy-start.lock");
    let _lock =
        tokio::task::spawn_blocking(move || host_platform::lock_host_state(&lock_path)).await??;
    if proxy_live() {
        // Status describes reuse; start performs the ownership/readiness checks.
        let previous = crate::coord_rooms::status(&root).await.ok();
        match crate::coord_rooms::start(&root, None, None, None).await {
            Ok(current) => {
                if previous.is_some_and(|status| status["process"] == current) {
                    eprintln!("Coord ready: existing managed NATS is healthy.");
                } else {
                    eprintln!("Coord restored: managed NATS is ready.");
                }
            }
            Err(error) => eprintln!(
                "Coord unavailable: {error}. The running proxy is unchanged; run coord status and repair its prerequisite before retrying start."
            ),
        }
        return Ok(None);
    }
    let config_path = host_platform::config_path();
    timing.record("ownership_start_lock");
    let config = crate::native_config::read(&config_path)?;
    timing.record("configuration");
    // Coord is optional for proxy readiness. Keep both starts owned by this
    // command, and await both results before returning or releasing the lock.
    let coord = async {
        let mut timing = crate::startup_timings::StartupTimings::new("managed_nats");
        if let Err(error) = crate::coord_rooms::start(&root, None, None, None).await {
            eprintln!(
                "Coord unavailable: {error}. Proxy startup continues; run coord status after repairing its prerequisite."
            );
        }
        timing.record("start_complete");
    };
    let (_, proxy) = tokio::join!(
        coord,
        start_proxy_process(&root, &config_path, &config.readiness_file),
    );
    let (mut child, ready) = proxy?;
    // A proxy that became ready first can exit while NATS is still starting.
    // Retain its child handle and recheck readiness at command completion.
    let result = (|| {
        if child.try_wait()?.is_some() {
            return Err("proxy exited during startup; inspect logs/proxy.log".into());
        }
        if !config.readiness_file.is_file() || !proxy_live() {
            return Err(
                "proxy lost verified readiness during startup; inspect logs/proxy.log".into(),
            );
        }
        Ok(ready)
    })();
    if result.is_err() {
        child.kill().await?;
    }
    result
}

async fn start_proxy_process(
    root: &Path,
    config_path: &Path,
    readiness: &Path,
) -> Result<(tokio::process::Child, Option<Value>), Error> {
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
        .args(crate::host_root::allowed().then_some(crate::host_root::FLAG))
        .env("SAFEYOLO_CONFIG_DIR", root)
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
    // Healthy initialization can exceed five seconds on emulated hosts.
    // Keep polling readiness so faster starts return without an added delay.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let result = async {
        while tokio::time::Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Err("proxy exited during startup; inspect logs/proxy.log".into());
            }
            if readiness.is_file() && proxy_live() {
                // The startup lock binds this newly created incarnation. Demo can
                // release it only while this record and all runtimes still agree.
                return crate::guest_commands::read_state(&process_path());
            }
            tokio::select! {
                status = child.wait() => {
                    status?;
                    return Err("proxy exited during startup; inspect logs/proxy.log".into());
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        Err("proxy did not publish readiness within fifteen seconds; inspect logs/proxy.log".into())
    }
    .await;
    if result.is_err() {
        child.kill().await?;
    }
    result.map(|ready| (child, ready))
}

pub(crate) async fn stop_proxy() -> Result<(), Error> {
    // NATS has its own verified process ownership. A stop error preserves its
    // record and is reported independently of the proxy's lifecycle.
    if let Err(error) = crate::coord_rooms::stop(&host_platform::config_dir()).await {
        eprintln!("Coord stop failed: {error}");
    }
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
    // Reconstruct only the owned per-agent projection. Explicit operator
    // listeners retain their existing owner and configuration.
    let agents = host_agents::list()?;
    config.listeners.retain(|listener| {
        !host_platform::is_managed_agent_listener(listener)
            || agents.iter().any(|agent| agent.name == listener.agent_id)
    });
    for agent in agents {
        let observed = host_runs::observe(&agent.name).await;
        if observed["runtime_state"] == "stopped" {
            config.listeners.retain(|entry| {
                entry.agent_id != agent.name || !host_platform::is_managed_agent_listener(entry)
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
        // A running guest can still hold the old dedicated directory mount.
        // Preserve that accepted path when its host-owned source is unchanged.
        let listener = config
            .listeners
            .iter()
            .find(|entry| {
                entry.agent_id == agent.name
                    && entry.source_id().as_deref() == Some(ip)
                    && host_platform::is_managed_agent_listener(entry)
            })
            .cloned()
            .unwrap_or_else(|| host_platform::agent_proxy_listener(&agent.name, ip));
        config.listeners.retain(|entry| {
            entry.agent_id != agent.name || !host_platform::is_managed_agent_listener(entry)
        });
        config.listeners.push(listener);
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

pub(crate) fn diagnostic_commands(agent: Option<&str>) -> Value {
    let Ok(prefix) = host_lifecycle::current_instance_command() else {
        return json!({"available":false,"reason":"The current installed executable could not be identified; diagnostic commands cannot be qualified.","next_action":"Use the known installed CLI and configuration for this instance to inspect agent diagnostics, doctor or diagnose."});
    };
    let mut guidance = json!({
        "doctor":{"command":format!("{prefix} doctor"),"establishes":"Host prerequisites and a controlled request through the active policy pipeline; does not establish coding-agent readiness.","probes":true,"next_action":"Repair the reported failed prerequisite or control, then repeat this diagnostic."},
        "diagnose":{"command":format!("{prefix} diagnose"),"establishes":"Saved policy validity, current Admin policy availability, saved/active agreement and audit location; no test traffic.","probes":false,"next_action":"Follow the reported saved/active mismatch or Admin connection guidance; local logs remain available."}
    });
    if let Some(agent) = agent {
        guidance["agent"] = json!({"command":format!("{prefix} agent diagnostics {}",host_lifecycle::shell_quote(agent)),"establishes":"Independent runtime/control observations, recorded coding-agent launch, terminal and proxy attachment. A recorded launch is not current runtime evidence.","probes":true,"next_action":"Follow this agent's next_action; do not start another sandbox solely because its proxy attachment is unavailable."});
        guidance["diagnose"]["command"] = json!(format!(
            "{prefix} diagnose --agent {}",
            host_lifecycle::shell_quote(agent)
        ));
    }
    guidance
}

pub(crate) async fn diagnostics(agent: &host_agents::Agent) -> Result<Value, Error> {
    let mut observed = Box::pin(host_lifecycle::operate("status", Some(&agent.id))).await?;
    observed["diagnostic_commands"] = diagnostic_commands(Some(&agent.name));
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
        [kind, help] if kind == "mount" && help == "--help" => println!(
            "safeyolo [--instance-dir PATH | --config FILE] mount protect PATH\nsafeyolo [--instance-dir PATH | --config FILE] mount unprotect PATH\nsafeyolo [--instance-dir PATH | --config FILE] mount list\nProtection is saved in config.toml for extra mounts of the resolved path and its descendants. PATH may not exist yet. Protected sources require explicit :ro for configuration, live additions and startup. Workspace sharing and existing shares are unchanged."
        ),
        [kind, operation] if kind == "mount" && operation == "list" => {
            let directories = serde_json::to_value(
                crate::native_config::host_settings()?.protected_host_directories,
            )?;
            print(&json!({"protected_host_directories":directories}))?;
        }
        [kind, operation, path]
            if kind == "mount" && matches!(operation.as_str(), "protect" | "unprotect") =>
        {
            let directories =
                crate::native_config::protect_directory(Path::new(path), operation == "protect")
                    .await?;
            print(
                &json!({"protected_host_directories":directories,"scope":"extra mount configuration, future live additions and next sandbox start; existing shares are unchanged"}),
            )?;
        }
        [kind, ..] if kind == "mount" => {
            return Err("use mount protect PATH, mount unprotect PATH, or mount list".into());
        }
        [kind, operation, name, id] if kind == "agent" && operation == "launcher-session" => {
            print(&host_lifecycle::launcher_session(name, id).await?)?;
        }
        [kind, group, name, operation, file]
            if kind == "agent" && group == "lifecycle" && operation == "configure" =>
        {
            print(&host_lifecycle::scheduled::command(name, operation, Some(file)).await?)?;
        }
        [kind, group, name, operation] if kind == "agent" && group == "lifecycle" => {
            let mut result = host_lifecycle::scheduled::command(name, operation, None).await?;
            if result.is_null() {
                result = json!({"saved_configuration":null});
            }
            result["name"] = json!(name);
            print(&result)?;
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
            print(&json!({"proxy_state":"stopped","agents":"unchanged","root":root}))?;
        }
        [command] if command == "doctor" => {
            let report = crate::host_doctor::report(&host_platform::config_path()).await;
            let failed = report["exit_code"].as_i64().unwrap_or(1) as i32;
            if crate::operator_output::json_requested() {
                crate::operator_output::json(&report)?;
            } else {
                crate::host_doctor::show(&report);
            }
            return Ok(failed);
        }
        [command] if command == "status" => {
            let agents = host_lifecycle::operate("list", None).await.map_err(|error|
                format!("Cannot read agent inventory for instance {} (configuration {}): {error}. Inspect this path or select the installed instance with --instance-dir PATH; no service was changed", root.display(), host_platform::config_path().display()))?;
            let report = json!({"proxy_state":if proxy_live(){"running"}else{"unavailable"},"agents":agents["agents"],"root":root,"diagnostic_commands":diagnostic_commands(None)});
            print(&report)?;
        }
        [kind, operation] if kind == "agent" && operation == "list" => {
            let mut report = host_lifecycle::operate("list", None).await.map_err(|error|
                format!("Cannot read agent inventory for instance {} (configuration {}): {error}. Select the installed instance or repair its configuration; no service was changed", root.display(), host_platform::config_path().display()))?;
            report["root"] = json!(root);
            print(&report)?;
        }
        [agent, help] if agent == "agent" && help == "--help" => {
            println!("{AGENT_HELP}");
            println!("{}", host_lifecycle::scheduled::HELP);
        }
        [kind, group, help] if kind == "agent" && group == "lifecycle" && help == "--help" => {
            println!("{}", host_lifecycle::scheduled::HELP);
        }
        [kind, operation, rest @ ..] if kind == "agent" && operation == "launch" => {
            return crate::host_launch::run(rest).await;
        }
        [kind, operation, rest @ ..] if kind == "agent" && operation == "auth" => {
            return crate::host_client_auth::run(rest).await;
        }
        [kind, operation, rest @ ..] if kind == "agent" && operation == "watch" => {
            if rest.is_empty() || rest == ["--help"] {
                println!("{}", crate::agent_watch::HELP);
            } else {
                crate::coord_operator::watch_agent(
                    &host_platform::config_path(),
                    agent(&rest[0])?,
                    &rest[1..],
                )
                .await?;
            }
        }
        [kind, operation, name, operand]
            if kind == "agent" && matches!(operation.as_str(), "mount" | "unmount") =>
        {
            let selected = agent(name)?;
            let report = crate::host_mounts::operate(operation, &selected, operand).await?;
            print(&report)?;
            if report["ok"] != true {
                return Ok(1);
            }
        }
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
                    "--nested-docker" => "nested_docker",
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
            let agent = host_agents::configure(name, &options, operation == "create", None).await?;
            print(
                &json!({"configuration":agent,"scope":"next sandbox start; current run is unchanged"}),
            )?;
        }
        [kind, operation, action, name, operand] if kind == "agent" && operation == "mounts" => {
            let selected = agent(name)?;
            print(&host_agents::saved_mount(&selected, action, operand).await?)?;
        }
        [kind, operation, name, rest @ ..] if kind == "agent" && operation == "retire" => {
            let apply = match rest {
                [] => false,
                [flag] if flag == "--yes" => true,
                _ => return Err("use agent retire NAME to preview, or agent retire NAME --yes to stop/cleanup and remove its saved definition while retaining its home".into()),
            };
            let result = host_lifecycle::retire(&agent(name)?, apply).await?;
            let failed = result["ok"] == false;
            print(&result)?;
            return Ok(i32::from(failed));
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
                "publish"|"unpublish"|"publications" => {
                    let mut parameters = json!({"ttl_seconds":900});
                    if operation == "publications" {
                        if !extra.is_empty() { return Err("publications takes only the agent name and optional --json".into()); }
                    } else {
                        let mut index = 0;
                        while index < extra.len() {
                            let flag = extra[index].as_str();
                            let input = extra.get(index + 1).ok_or("publication option requires a value; use agent publish --help")?;
                            let key = match flag {"--port"=>"guest_port", "--audience"=>"audience", "--tailnet-port"=>"tailnet_port", "--ttl"=>"ttl_seconds", _=>return Err("unknown publication option; use agent publish --help".into())};
                            if key == "audience" { parameters[key] = json!(input); } else { parameters[key] = json!(input.parse::<u32>()?); }
                            index += 2;
                        }
                        let selected: crate::desktop_present::web::Parameters = serde_json::from_value(parameters.clone())
                            .map_err(|_| "publish and unpublish require --port PORT --audience local|tailnet")?;
                        selected.validate()?;
                    }
                    let config = host_platform::config_path();
                    let prefix = host_lifecycle::current_instance_command()?;
                    let result = crate::native_client::admin(&config,
                        &format!("/admin/agents/{}/web", agent.id),
                        match operation.as_str() {"publications"=>hyper::Method::GET, "unpublish"=>hyper::Method::DELETE, _=>hyper::Method::POST},
                        if operation == "publications" {Value::Null} else {parameters}, Duration::from_secs(40)).await
                        .map_err(|error| format!("Web {operation} result is unavailable for agent {} using configuration {}: {error}\nInspect this instance: {prefix} status\nWhen the proxy is available, inspect current publications before repeating a change: {prefix} agent publications {}",
                            host_lifecycle::shell_quote(name), host_lifecycle::shell_quote(&config.to_string_lossy()), host_lifecycle::shell_quote(name)))?;
                    print(&result)?;
                },
                "start"|"stop"|"status"|"cleanup"=>{
                    let (operation, arguments, allow_unowned) = if operation=="start" {
                        start_arguments(extra)?
                    }else{if !extra.is_empty(){return Err("unexpected agent argument".into());} (operation.as_str(), None, false)};
                    if matches!(operation, "start"|"start-foreground"|"sandbox-start") {
                        crate::host_root::refuse_root("start an agent")?;
                    }
                    let setup_lock = if matches!(operation, "start"|"start-foreground"|"sandbox-start"|"stop") {
                        inherited_setup_lock(&agent)?
                    } else { None };
                    if operation.starts_with("start") || operation=="sandbox-start" {
                        let mut proposed = agent.clone();
                        proposed.dangerously_allow_unowned |= allow_unowned;
                        let observed = host_lifecycle::runtime(&agent).await?;
                        if !host_lifecycle::reuses_current_launch(&observed) {
                            host_lifecycle::validate_start_launcher(&proposed,operation)?;
                            #[cfg(target_os = "macos")]
                            crate::host_boot::warn_broad_shares(&proposed);
                        }
                        start_proxy().await?;
                    }
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
                    if persistent {return host_lifecycle::persistent_shell(&agent,command,"sy-shell").await;}
                    let mut child=host_platform::spawn_guest_command(name,command,true).await?;
                    return Ok(child.wait().await?.code().unwrap_or(1));
                },
                "present"=>{ if !extra.is_empty(){return Err("unexpected desktop argument".into());}
                    // The running proxy owns the preview lifetime. A preview
                    // started in this short-lived CLI exits with the command.
                    let result = crate::native_client::admin(
                        &host_platform::config_path(),
                        &format!("/admin/agents/{}/desktop/present", agent.id),
                        hyper::Method::POST,
                        Value::Null,
                        Duration::from_secs(70),
                    ).await?;
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
    fn upgrade_proxy_identity_child() {
        let Some(directory) = std::env::var_os("SAFEYOLO_TEST_UPGRADE_PROXY") else {
            return;
        };
        let directory = PathBuf::from(directory);
        fs::write(directory.join("ready"), "ready").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !directory.join("finish").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[tokio::test]
    async fn host_upgrade_preserves_proxy_identity_and_config_ownership() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("data")).unwrap();
        fs::write(root.join("config.toml"), "").unwrap();
        std::os::unix::fs::symlink(
            std::env::current_exe().unwrap(),
            root.join("bin/safeyolo-proxy"),
        )
        .unwrap();
        let mut child = tokio::process::Command::new(root.join("bin/safeyolo-proxy"))
            .args([
                "--exact",
                "host_commands::tests::upgrade_proxy_identity_child",
                "--nocapture",
                "--",
                "--config",
            ])
            .arg(root.join("config.toml"))
            .env("SAFEYOLO_TEST_UPGRADE_PROXY", root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !root.join("ready").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "identity child exited before readiness"
            );
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid = i64::from(child.id().unwrap());
        let token = host_lifecycle::process_token(pid).unwrap();
        crate::guest_commands::write_json(
            &root.join("data/proxy-process.json"),
            &json!({"pid":pid,"token":token}),
        )
        .unwrap();
        assert!(host_platform::with_config(
            root.join("config.toml"),
            proxy_live
        ));
        fs::create_dir_all(root.join("versions/initial/host")).unwrap();
        fs::rename(root.join("bin"), root.join("versions/initial/host/bin")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::copy("/bin/sleep", root.join("bin/safeyolo-proxy")).unwrap();
        assert!(host_platform::with_config(
            root.join("config.toml"),
            proxy_live
        ));
        assert!(!host_platform::with_config(
            root.join("another.toml"),
            proxy_live
        ));
        crate::guest_commands::write_json(
            &root.join("data/proxy-process.json"),
            &json!({"pid":pid,"token":"wrong birth"}),
        )
        .unwrap();
        assert!(!host_platform::with_config(
            root.join("config.toml"),
            proxy_live
        ));
        fs::write(root.join("finish"), "finish").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }

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
            crate::host_root::FLAG.into(),
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
            nested_docker: false,
            user_default_args: Vec::new(),
            mounts: Vec::new(),
            dangerously_allow_unowned: false,
            lifecycle: None,
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
