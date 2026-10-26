//! First use composes the installed host, agent and operator operations.

use std::{
    io::{IsTerminal, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use hyper::Method;
use serde_json::Value;

use crate::{Error, host_agents, host_boot, host_commands, host_lifecycle, host_platform};

pub(crate) const HELP: &str = "safeyolo [--root ROOT] agent launch [WORKSPACE] [--name NAME] [--harness claude|codex] [--launcher LAUNCHER] [--dangerously-allow-unowned]
WORKSPACE defaults to the current directory. The harness defaults to Claude.
Launch asks before host setup, workspace sharing and optional authentication copying,
then starts the installed services and opens the agent terminal. For a stopped Codex
agent, select a trusted subscription login to authorize before startup, or keep normal
login/approvals. The first import asks for credential storage. Passphrase storage
requires explicit unlock; installation asks no storage question. If the agent has no login, launch also copies the selected host file.
In tmux, press Ctrl-b then d to return here for approvals.
Numbered requests use the existing inspect/approve/reject operations. Network approval is
agent-specific and reusable; credential approval changes persistent instance-shared policy.
Repeat launch keeps the same agent, home and workspace. Quit preserves the current sandbox state.
Use agent stop NAME when you want to stop that agent.";

#[derive(Default)]
struct Options {
    workspace: Option<PathBuf>,
    name: Option<String>,
    harness: Option<String>,
    launcher: Option<String>,
    allow_unowned: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, Error> {
        let mut options = Self::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--name" | "--harness" | "--launcher" => {
                    let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
                    let field = match arg.as_str() {
                        "--name" => &mut options.name,
                        "--harness" => &mut options.harness,
                        _ => &mut options.launcher,
                    };
                    if field.replace(value.clone()).is_some() {
                        return Err(format!("{arg} was supplied twice").into());
                    }
                }
                "--dangerously-allow-unowned" => options.allow_unowned = true,
                value if value.starts_with('-') => {
                    return Err(
                        format!("unknown launch option: {value}; use agent launch --help").into(),
                    );
                }
                _ => {
                    if options.workspace.replace(arg.into()).is_some() {
                        return Err("launch accepts one workspace".into());
                    }
                }
            }
        }
        if options
            .name
            .as_ref()
            .is_some_and(|name| !host_platform::valid_agent_name(name))
        {
            return Err("invalid agent name".into());
        }
        Ok(options)
    }
}

fn default_name(workspace: &Path) -> String {
    let stem: String = workspace
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(32)
        .collect();
    let digest = ring::digest::digest(&ring::digest::SHA256, workspace.as_os_str().as_bytes());
    let suffix: String = digest.as_ref()[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{}-{suffix}",
        if stem.trim_matches('-').is_empty() {
            "workspace"
        } else {
            stem.trim_matches('-')
        }
    )
}

fn matches(agent: &host_agents::Agent, workspace: &Path, script: &Path) -> bool {
    agent
        .folder
        .as_ref()
        .is_some_and(|folder| Path::new(folder) == workspace)
        && agent.host_script.as_ref().is_some_and(|path| {
            Path::new(path)
                .canonicalize()
                .is_ok_and(|path| path == script)
        })
}

fn select(
    options: &Options,
    workspace: &Path,
    script: &Path,
) -> Result<(String, Option<host_agents::Agent>), Error> {
    let agents = host_agents::list()?;
    let name = if let Some(name) = &options.name {
        name.clone()
    } else {
        let matching: Vec<_> = agents
            .iter()
            .filter(|agent| matches(agent, workspace, script))
            .collect();
        match matching.as_slice() {
            [agent] => agent.name.clone(),
            [] => default_name(workspace),
            _ => return Err("more than one matching agent; choose one with --name NAME".into()),
        }
    };
    let current = agents.iter().find(|agent| agent.name == name);
    if let Some(agent) = current {
        host_agents::by_id(&agents, &agent.id)?;
        // Compare the effective existing launcher. An omitted agent setting
        // can already resolve to the explicitly requested built-in or host
        // default; that case needs no configuration change.
        let launcher_matches = if let Some(requested) = options.launcher.as_deref() {
            let selected = host_lifecycle::selected_launcher(agent)?;
            match selected["kind"].as_str() {
                Some("script") => selected["script"].as_str() == Some(requested),
                Some("manager") => requested
                    .strip_prefix("manager:")
                    .is_some_and(|path| selected["script"].as_str() == Some(path)),
                kind => kind == Some(requested),
            }
        } else {
            true
        };
        if !matches(agent, workspace, script) || !launcher_matches {
            return Err(format!("agent {name} has a different workspace, harness or launcher; its configuration is unchanged. Choose another --name or use its configured workspace").into());
        }
    }
    Ok((name, current.cloned()))
}

pub(crate) fn input(prompt: &str) -> Result<Option<String>, Error> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    Ok((std::io::stdin().read_line(&mut answer)? != 0).then(|| answer.trim().to_owned()))
}

fn consent(prompt: &str) -> Result<bool, Error> {
    Ok(input(prompt)?
        .is_some_and(|answer| matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes")))
}

fn phase(name: &str, error: impl std::fmt::Display) -> Error {
    let error = crate::network_guard::sanitize_with_limit(&error.to_string(), usize::MAX);
    format!("First-agent {name} failed: {error}. Saved agent state is retained. Repair this phase, then repeat agent launch with the same workspace/name; use agent diagnostics for runtime failures").into()
}

fn current_selection(agent: &host_agents::Agent) -> Result<host_agents::Agent, Error> {
    let current = host_agents::refresh(agent)?;
    if current.folder != agent.folder
        || current.host_script != agent.host_script
        || current.launcher != agent.launcher
    {
        return Err("the selected agent's workspace, harness or launcher changed; its saved configuration and current run are unchanged. Repeat launch with the intended selection".into());
    }
    Ok(current)
}

async fn start(agent: &host_agents::Agent) -> Result<(), Error> {
    let directory = host_platform::config_dir().join("agents").join(&agent.name);
    let lock = tokio::task::spawn_blocking(move || {
        host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    let current = current_selection(agent)?;
    // An interactive launch never replays saved task arguments. The existing
    // lifecycle still reuses a live command, regardless of this empty override.
    let mut observed =
        host_lifecycle::start(&current, "start", Some(lock), Some(&[]), false).await?;
    if let Some(error) = observed["error"].as_str() {
        return Err(error.into());
    }
    // Lifecycle already checked this launch. Reuse its observation only for
    // this wait; attachment reads and checks the current terminal separately.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while observed["attachable"] != true
        && host_lifecycle::reuses_current_launch(&observed)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
        observed = host_lifecycle::runtime(&current).await?;
    }
    Ok(())
}

enum CodexLogin {
    Cancelled,
    NormalApprovals,
    Imported,
}

async fn codex_login(agent: &host_agents::Agent) -> Result<CodexLogin, Error> {
    let root = host_platform::config_dir();
    let directory = root.join("agents").join(&agent.name);
    let _lock = tokio::task::spawn_blocking(move || {
        host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    current_selection(agent)?;
    if host_lifecycle::runtime(agent).await?["runtime_state"] != "stopped" {
        return Ok(CodexLogin::NormalApprovals);
    }
    let home = root.join("agents").join(&agent.name).join("home");
    let auth = home.join(".codex/auth.json");
    let host_auth = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".codex")
        })
        .join("auth.json");
    println!(
        "Authorize a trusted Codex subscription login for {} ({}). Agent files can be changed by the guest. Authorization lasts until removed or replaced. Existing credential and network rules still apply. If the agent has no login, the selected host file is copied; guests can read the copy. Host originals stay unchanged. If authorization fails, the copy remains.",
        agent.name, agent.id
    );
    for (label, path) in [("a: agent login", &auth), ("h: host login", &host_auth)] {
        println!(
            "{label}: {}",
            crate::network_guard::sanitize_with_limit(&path.to_string_lossy(), usize::MAX)
        );
    }
    loop {
        let Some(choice) = input(
            "Codex login [a/h/file path, Enter: guest login/normal approvals, q: cancel launch]: ",
        )?
        else {
            return Ok(CodexLogin::Cancelled);
        };
        let source = match choice.as_str() {
            "" => return Ok(CodexLogin::NormalApprovals),
            "q" => return Ok(CodexLogin::Cancelled),
            "a" => auth.clone(),
            "h" => host_auth.clone(),
            _ => PathBuf::from(choice),
        };
        current_selection(agent)?;
        let result = async {
            let source = source.canonicalize().map_err(|_| "cannot resolve selected Codex login input")?;
            if auth.canonicalize().ok().as_ref() != Some(&source) {
                crate::coord_setup::copy_codex_login(&home, &source)?;
            } else {
                crate::coord_setup::codex_state(&home, None, false, Some("adopt"))?;
            }
            // Use the existing trusted import operation. Neither copying nor
            // an adoption marker is evidence for an automatic credential grant.
            let status = tokio::process::Command::new(root.join("bin/safeyolo"))
                .arg("--config").arg(host_platform::config_path())
                .args(["credentials", "import-codex", &format!("codex-{}", agent.id), "--agent", &agent.name, "--auth-file"])
                .arg(&auth)
                .kill_on_drop(true)
                .status().await?;
            if !status.success() {
                return Err("selected login was not authorized; repair the agent login or keep normal approvals".into());
            }
            Ok::<(), Error>(())
        }.await;
        match result {
            Ok(()) => return Ok(CodexLogin::Imported),
            Err(error) => eprintln!("{}", phase("Codex authorization", error)),
        }
    }
}

pub(crate) async fn run(args: &[String]) -> Result<i32, Error> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(0);
    }
    let options = Options::parse(args)?;
    let harness = options.harness.as_deref().unwrap_or("claude");
    let (script_name, client) = match harness {
        "claude" => ("claude-host-setup.sh", "Claude"),
        "codex" => ("codex-host-setup.sh", "Codex"),
        _ => {
            return Err(format!(
                "no shipped first-launch setup for harness {harness}; available: claude, codex"
            )
            .into());
        }
    };
    let root = host_platform::config_dir();
    let script = root
        .join("assets/contrib")
        .join(script_name)
        .canonicalize()
        .map_err(|error| phase("shipped harness setup", error))?;
    let workspace = host_boot::workspace(
        options.workspace.as_deref().unwrap_or(Path::new(".")),
        options.allow_unowned,
    )?;
    let (name, existing) = select(&options, &workspace, &script)?;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("agent launch needs an interactive host terminal for consent, login and approvals; use explicit agent create/start commands for automation".into());
    }
    let displayed_workspace =
        crate::network_guard::sanitize_with_limit(&workspace.to_string_lossy(), usize::MAX);
    println!("SafeYolo host — agent {name}, workspace {displayed_workspace}");
    let create = existing.is_none();
    let command = root
        .join("agents")
        .join(&name)
        .join("home/.safeyolo-command");
    let command_exists = command
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0);
    let repair = if let Some(agent) = &existing
        && !command_exists
    {
        !host_lifecycle::reuses_current_launch(&host_lifecycle::runtime(agent).await?)
    } else {
        false
    };
    let agent = if let Some(agent) = existing.filter(|_| !repair) {
        println!(
            "Reusing agent {} ({}) and its persistent home.",
            agent.name, agent.id
        );
        agent
    } else {
        if repair {
            println!(
                "The stopped agent's harness command is missing or not executable. Setup will repair it and retain the agent identity and home."
            );
        }
        println!(
            "Setup runs the shipped {harness} host script as your host account. The script writes this agent's persistent home, SafeYolo context and MCP settings. The guest can read and write {displayed_workspace} at /workspace. {client} may run tools without per-tool prompts inside this sandbox; SafeYolo network and credential policy still applies.",
        );
        if !consent("Run this setup and share this workspace? [y/N] ")? {
            println!("Setup declined; saved agents and services are unchanged.");
            return Ok(0);
        }
        let copy = if harness == "claude" {
            println!(
                "Optional host state: copy selected identity fields from ~/.claude.json, ~/.claude/.credentials.json, settings.json, plugins, commands, agents and skills (except SafeYolo's reserved skill) into this agent home. Claude and guest commands can read the copied authentication. Sessions and history are excluded. Declining leaves host authentication untouched; use Claude's login in the guest."
            );
            Some(consent(
                "Copy this selected host authentication and settings? [y/N] ",
            )?)
        } else {
            println!(
                "Codex uses authentication and settings in this agent's ~/.codex. Setup preserves that state; a host login choice follows."
            );
            None
        };
        let mut settings = vec![
            ("folder".into(), workspace.to_string_lossy().into_owned()),
            ("host_script".into(), script.to_string_lossy().into_owned()),
        ];
        if let Some(launcher) = &options.launcher {
            settings.push(("launcher".into(), launcher.clone()));
        }
        if options.allow_unowned {
            settings.push(("dangerously_allow_unowned".into(), "true".into()));
        }
        println!("Preparing the shipped harness setup…");
        host_agents::configure_with_host_state(&name, &settings, create, None, copy)
            .await
            .map_err(|error| phase("host setup", error))?
    };
    let login = if harness == "codex" {
        codex_login(&agent)
            .await
            .map_err(|error| phase("Codex login selection", error))?
    } else {
        CodexLogin::NormalApprovals
    };
    if matches!(login, CodexLogin::Cancelled) {
        println!(
            "Launch cancelled; saved agent state is retained. Services and the coding client were not started by this launch."
        );
        return Ok(0);
    }
    println!("Starting or reusing the installed services…");
    let started = host_commands::start_proxy()
        .await
        .map_err(|error| phase("services", error))?;
    crate::native_client::admin(
        &host_platform::config_path(),
        "/admin/instance",
        Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await
    .map_err(|error| phase("proxy readiness", error))?;
    if crate::coord_rooms::status(&root)
        .await
        .map_err(|error| phase("Coord readiness", error))?["state"]
        != "running"
    {
        return Err(phase(
            "Coord readiness",
            "managed NATS is not healthy; inspect coord status and the owned NATS log",
        ));
    }
    // An offline import cannot unlock a future process. After readiness, ask
    // explicitly for that process's unlock before starting the selected client.
    // Imports into a reused proxy already unlock through the credential command.
    if matches!(login, CodexLogin::Imported)
        && started.is_some()
        && crate::credentials::storage(
            &crate::native_config::read(&host_platform::config_path())?.data_dir(),
        )? == Some(crate::credentials::Storage::Passphrase)
    {
        println!("Unlock credential storage for the imported Codex login before client startup.");
        let status = tokio::process::Command::new(root.join("bin/safeyolo"))
            .arg("--config")
            .arg(host_platform::config_path())
            .args(["credentials", "unlock"])
            .kill_on_drop(true)
            .status()
            .await?;
        if !status.success() {
            return Err(phase(
                "credential unlock",
                "proxy remains ready; run credentials unlock before retrying launch",
            ));
        }
    }
    println!(
        "Starting or resuming {harness}. First use may download tools; sign in if {client} asks. In tmux, Ctrl-b then d returns to trusted SafeYolo approvals in this terminal."
    );
    start(&agent)
        .await
        .map_err(|error| phase("sandbox/harness startup", error))?;
    let mut attach = true;
    loop {
        current_selection(&agent)?;
        if attach {
            let result = host_lifecycle::attach(&agent).await;
            // Guest output stays inside the attached terminal. Host prompts
            // resume only after the operator returns through the host launcher.
            print!("\x1b[0m\x1b[2J\x1b[H");
            match result {
                Err(error) => eprintln!("{}", phase("terminal attachment", error)),
                Ok(code) if code != 0 => eprintln!(
                    "{}",
                    phase(
                        "terminal attachment",
                        format!("launcher returned exit status {code}")
                    )
                ),
                _ => {}
            }
            let observed = host_lifecycle::runtime(&agent).await?;
            if matches!(
                observed["agent_state"].as_str(),
                Some("failed" | "exited" | "stopped")
            ) {
                println!(
                    "Harness session: {}. Sandbox: {}. Exit status: {}.",
                    observed["agent_state"], observed["runtime_state"], observed["exit_code"]
                );
                if let Some(error) = observed["error"].as_str() {
                    eprintln!("{}", phase("harness session", error));
                }
                println!(
                    "If installation or login failed, inspect pending requests before retrying. The retry opens an interactive session; check any previous task's effects before giving it again."
                );
            }
        }
        println!(
            "SafeYolo host controls — {} ({})\nEnter: return to agent | a: inspect pending requests | r: retry a stopped harness | q: keep current state and exit",
            agent.name, agent.id
        );
        match input("SafeYolo host> ")?.as_deref() {
            None | Some("q" | "quit") => return Ok(0),
            Some("") => attach = true,
            Some("a") => {
                if let Err(error) =
                    crate::operator_commands::review_pending(&root, &agent.name).await
                {
                    eprintln!("{}", phase("approvals", error));
                }
                attach = false;
            }
            Some("r") => {
                println!(
                    "This opens an interactive session only. Check any previous task's effects before giving it again."
                );
                match start(&agent).await {
                    Ok(()) => attach = true,
                    Err(error) => {
                        eprintln!("{}", phase("sandbox/harness retry", error));
                        attach = false;
                    }
                }
            }
            _ => {
                println!("Choose Enter, a, r or q.");
                attach = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn launch_wait_reuses_start_observation_and_refreshes_pending_commands() {
        use serde_json::json;
        use std::{fs, process::Command};

        const TEST: &str = "host_launch::tests::launch_wait_reuses_start_observation_and_refreshes_pending_commands";
        let Some(root) = std::env::var_os("SAFEYOLO_TEST_LAUNCH_OBSERVATION_ROOT") else {
            for mode in ["ready", "delayed", "error"] {
                let temp = tempfile::tempdir().unwrap();
                let output = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env("SAFEYOLO_TEST_LAUNCH_OBSERVATION_ROOT", temp.path())
                    .env("SAFEYOLO_TEST_LAUNCH_OBSERVATION_MODE", mode)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{mode}: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        let root = PathBuf::from(root);
        let mode = std::env::var("SAFEYOLO_TEST_LAUNCH_OBSERVATION_MODE").unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        let mut backend = host_platform::guest_command_test_run::OwnedRun::start(&root);
        // Environment changes are confined to this fixture subprocess. The
        // shared helper retains the real namespace and process-birth checks.
        unsafe {
            std::env::set_var(
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("bin").display()),
            );
        }
        host_platform::in_instance(root.clone(), async {
            let workspace = root.join("workspace");
            fs::create_dir(&workspace).unwrap();
            let launcher = root.join("launcher.sh");
            let pid = std::process::id();
            let token = host_lifecycle::process_token(i64::from(pid)).unwrap();
            fs::write(&launcher, format!(r#"#!/bin/sh
case "$1" in
  launch)
    record="$SAFEYOLO_CONFIG_DIR/agents/alice/current-launch.json"
    sed 's/"state":"starting"/"state":"launching", "pid": {pid}, "process_token": "{token}", "runner_pid": {pid}, "runner_token": "{token}"/' "$record" > "$record.tmp" || exit
    mv "$record.tmp" "$record" || exit
    printf launch >> "$SAFEYOLO_CONFIG_DIR/launches";;
  *) exit 0;;
esac
"#)).unwrap();
            fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(root.join("bin/runsc"), format!(r#"#!/bin/bash
printf '%s\n' "$3" >> '{root}/calls'
case "$3" in
  state) printf '{{"id":"%s","status":"running"}}\n' "$4";;
  exec)
    case "${{@: -1}}" in
      *'observe check')
        if [ ! -e '{root}/launches' ]; then printf stopped
        elif [ '{mode}' = error ]; then exit 2
        elif [ '{mode}' = delayed ] && [ ! -e '{root}/checked' ]; then
          touch '{root}/checked'; printf stopped
        else printf running
        fi;;
      *) exit 2;;
    esac;;
  *) exit 2;;
esac
"#, root = root.display())).unwrap();
            let runsc = root.join("bin/runsc");
            fs::set_permissions(runsc, fs::Permissions::from_mode(0o700)).unwrap();
            let agent = host_agents::configure("alice", &[
                ("folder".into(), workspace.to_string_lossy().into()),
                ("user_default_args".into(), r#"["saved-task-argument"]"#.into()),
                ("launcher".into(), launcher.to_string_lossy().into()),
            ], true, None).await.unwrap();
            fs::create_dir_all(root.join("data")).unwrap();
            fs::write(root.join("data/instance_id"), "fixture").unwrap();
            let runtime = fs::read(root.join("agents/alice/runtime.json")).unwrap();
            let result = start(&agent).await;
            if mode == "error" {
                assert!(result.unwrap_err().to_string().contains("coding-agent observation failed"));
            } else {
                result.unwrap();
            }
            let calls = fs::read_to_string(root.join("calls")).unwrap();
            let observations = if mode == "delayed" { 3 } else { 2 };
            let record_path = root.join("agents/alice/current-launch.json");
            let mut record: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
            assert_eq!(calls.lines().filter(|call| *call == "state").count(), observations * 2, "{record}");
            assert_eq!(calls.lines().filter(|call| *call == "exec").count(), observations, "{record}");
            assert_eq!(record["agent_id"], agent.id);
            assert!(!record["command"].as_str().unwrap().contains("saved-task-argument"));
            assert_eq!(record["state"], if mode == "error" { "launching" } else { "running" });
            if mode != "error" {
                // Warm reentry reuses this launch and its single observation.
                fs::write(root.join("calls"), "").unwrap();
                start(&agent).await.unwrap();
                assert_eq!(fs::read_to_string(root.join("calls")).unwrap(), "state\nstate\nexec\n");
                assert_eq!(serde_json::from_slice::<Value>(&fs::read(&record_path).unwrap()).unwrap(), record);
                assert_eq!(fs::read_to_string(root.join("launches")).unwrap(), "launch");
                assert_eq!(fs::read(root.join("agents/alice/runtime.json")).unwrap(), runtime);
                // A prior ready observation grants no authority to attachment.
                record["agent_id"] = json!("ag-replacement");
                fs::write(&record_path, record.to_string()).unwrap();
                assert!(host_lifecycle::attach(&agent).await.unwrap_err().to_string().contains("another agent"));
            }
        }).await;
        backend.child.kill().unwrap();
        backend.assert_exited();
    }

    #[test]
    fn name_is_stable_and_distinguishes_equal_basenames() {
        let a = default_name(Path::new("/a/a project"));
        assert_eq!(a, default_name(Path::new("/a/a project")));
        assert!(host_platform::valid_agent_name(&a));
        assert_ne!(a, default_name(Path::new("/b/a project")));
        assert!(host_platform::valid_agent_name(&default_name(Path::new(
            "/"
        ))));
        for folder in ["/a/My_Project", "/a/.project", "/a/---", "/a/项目"] {
            assert!(host_platform::valid_agent_name(&default_name(Path::new(
                folder
            ))));
        }
    }

    #[tokio::test]
    async fn selection_preserves_named_agents_and_refuses_ambiguous_or_conflicting_reuse() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        host_platform::in_instance(temp.path().to_owned(), async {
            let script = temp.path().join("claude-host-setup.sh");
            std::fs::write(&script, "#!/bin/sh\nexit 99\n").unwrap();
            let folder = temp.path().join("workspace");
            std::fs::create_dir(&folder).unwrap();
            let original = host_agents::configure(
                "chosen",
                &[("folder".into(), folder.to_string_lossy().into())],
                true,
                None,
            )
            .await
            .unwrap();
            let policy = temp.path().join("policy.toml");
            let mut document = std::fs::read_to_string(&policy)
                .unwrap()
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            document["agents"]["chosen"]["host_script"] =
                toml_edit::value(script.to_string_lossy().as_ref());
            std::fs::write(&policy, document.to_string()).unwrap();
            let saved = std::fs::read(&policy).unwrap();
            let (_, selected) = select(&Options::default(), &folder, &script).unwrap();
            let selected = selected.unwrap();
            assert_eq!(selected.id, original.id);
            let explicit = Options {
                name: Some("chosen".into()),
                ..Default::default()
            };
            let effective_default = Options {
                name: Some("chosen".into()),
                launcher: Some("tmux-window".into()),
                ..Default::default()
            };
            assert_eq!(
                select(&effective_default, &folder, &script)
                    .unwrap()
                    .1
                    .unwrap()
                    .id,
                original.id
            );
            let different = Options {
                launcher: Some("tmux-pane".into()),
                ..effective_default
            };
            assert!(select(&different, &folder, &script).is_err());
            assert!(select(&explicit, temp.path(), &script).is_err());
            assert_eq!(std::fs::read(&policy).unwrap(), saved);
            document["agents"]["chosen"]["folder"] =
                toml_edit::value(temp.path().to_string_lossy().as_ref());
            std::fs::write(&policy, document.to_string()).unwrap();
            let reconfigured = std::fs::read(&policy).unwrap();
            assert!(current_selection(&selected).is_err());
            assert_eq!(std::fs::read(&policy).unwrap(), reconfigured);
            document["agents"]["chosen"]["folder"] =
                toml_edit::value(folder.to_string_lossy().as_ref());
            document["agents"]["other"] = document["agents"]["chosen"].clone();
            document["agents"]["other"]["agent_id"] = toml_edit::value("ag-other");
            std::fs::write(&policy, document.to_string()).unwrap();
            assert!(select(&Options::default(), &folder, &script).is_err());
            assert_eq!(
                select(&explicit, &folder, &script).unwrap().1.unwrap().id,
                original.id
            );
        })
        .await;
    }

    #[test]
    fn launcher_options_do_not_accept_workspace_setup_or_task_arguments() {
        for args in [
            vec!["--host-script", "./setup.sh"],
            vec!["a", "b"],
            vec!["--", "task"],
            vec!["--name", "a", "--name", "b"],
        ] {
            assert!(
                Options::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
            );
        }
    }
}
