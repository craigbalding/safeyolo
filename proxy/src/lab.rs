//! Objective-first Lab entry, using the existing native guest and terminal owners.

use crate::{Error, guest_commands, host_agents, host_commands, host_lifecycle, host_platform};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub const HELP: &str = "safeyolo [--root ROOT | --config FILE] lab [--objective TEXT] [--workspace PATH] [--agent NAME] [--nested-assets PATH] [--dangerously-allow-unowned] [--yes]\nsafeyolo [--root ROOT | --config FILE] lab [--agent NAME] --status [--json]\nsafeyolo [--root ROOT | --config FILE] lab [--agent NAME] --recover|--relaunch|--teardown [--keep-agent]\n\nStart from an experiment objective, or reattach to the same owned Lab. The installed instance needs its prepared guest runtime and Lab assets. Codex tools are prepared in the Lab's own guest home; normal authentication remains an operator choice.\nExiting the viewer retains the controller, workspace and evidence. --recover restarts an owned dead controller. --relaunch explicitly replaces it. --teardown captures redacted evidence and removes the owned session, then stops its guest unless --keep-agent is selected. Workspace, authentication and evidence files remain for inspection.\nOn Linux, Lab reuses this instance's installed CLI and proxy as inner inputs when available. --nested-assets selects another prepared native Linux installation. Only its CLI and proxy are copied into the guest read-only share at /safeyolo/lab-native; instance credentials and policy are not copied. The controller proposes the experiment before changing its inner instance. Outer policy is unchanged. Use --agent to choose among multiple Labs. Other agents and sessions are not adopted.";

#[derive(Default)]
struct Options {
    agent: Option<String>,
    workspace: Option<PathBuf>,
    objective: Option<String>,
    nested: Option<PathBuf>,
    action: Option<String>,
    json: bool,
    keep: bool,
    yes: bool,
    allow_unowned: bool,
}
impl Options {
    fn parse(args: &[String]) -> Result<Self, Error> {
        let mut options = Self::default();
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--agent" | "-a" => {
                    options.agent = Some(args.next().ok_or("--agent needs a name")?.clone())
                }
                "--workspace" | "--folder" | "-f" => {
                    options.workspace = Some(args.next().ok_or("--workspace needs a path")?.into())
                }
                "--objective" => {
                    options.objective = Some(args.next().ok_or("--objective needs text")?.clone())
                }
                "--nested-assets" => {
                    options.nested = Some(args.next().ok_or("--nested-assets needs a path")?.into())
                }
                "--backend" if args.next().map(String::as_str) == Some("codex") => {}
                "--status" | "--recover" | "--relaunch" | "--teardown" => {
                    if options.action.replace(flag.clone()).is_some() {
                        return Err("choose one Lab lifecycle action".into());
                    }
                }
                "--json" => options.json = true,
                "--keep-agent" => options.keep = true,
                "--yes" | "-y" => options.yes = true,
                "--dangerously-allow-unowned" => options.allow_unowned = true,
                _ => return Err(format!("unknown Lab option: {flag}; use lab --help").into()),
            }
        }
        if options.json && options.action.as_deref() != Some("--status") {
            return Err("--json requires --status".into());
        }
        if options.keep && options.action.as_deref() != Some("--teardown") {
            return Err("--keep-agent requires --teardown".into());
        }
        if options.action.is_some()
            && (options.objective.is_some()
                || options.workspace.is_some()
                || options.nested.is_some()
                || options.allow_unowned)
        {
            return Err(
                "objective, workspace and privilege choices apply when creating a Lab".into(),
            );
        }
        Ok(options)
    }
}

#[derive(Serialize, Deserialize)]
struct Lab {
    schema: u32,
    agent: String,
    agent_id: String,
    workspace: PathBuf,
    objective: String,
    #[serde(default)]
    nested_assets: Option<PathBuf>,
}
fn state_path(name: &str) -> Result<PathBuf, Error> {
    if !host_platform::valid_agent_name(name) {
        return Err("invalid Lab agent name".into());
    }
    Ok(host_platform::config_dir()
        .join("labs")
        .join(name)
        .join("lab-state.json"))
}
fn record(name: &str) -> Result<Option<Lab>, Error> {
    guest_commands::read_state(&state_path(name)?)?
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}
fn save(lab: &Lab) -> Result<(), Error> {
    let path = state_path(&lab.agent)?;
    fs::create_dir_all(path.parent().ok_or("Lab state has no parent")?)?;
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700))?;
    guest_commands::write_json(&path, &serde_json::to_value(lab)?)
}
fn compatible(lab: &Lab, agent: &host_agents::Agent) -> bool {
    lab.schema == 1
        && lab.agent == agent.name
        && lab.agent_id == agent.id
        && agent.folder.as_deref() == lab.workspace.to_str()
        && !lab.objective.trim().is_empty()
}
fn prompt(text: &str) -> Result<String, Error> {
    print!("{text}");
    io::stdout().flush()?;
    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Err("Lab input ended; retained state is unchanged".into());
    }
    Ok(value.trim().to_owned())
}
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}
fn safe(text: &str) -> String {
    crate::network_guard::sanitize(text)
}

fn private_directory(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(m)
            if !m.is_dir()
                || m.file_type().is_symlink()
                || m.uid() != unsafe { libc::getuid() }
                || m.mode() & 0o022 != 0 =>
        {
            return Err(format!("unsafe Lab staging directory: {}", path.display()).into());
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn stage_file(path: &Path, source: &[u8], mode: u32) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1 =>
        {
            return Err("refusing unsafe Lab staging file".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    crate::coord_supervisor::atomic_write(path, source, mode)
}
fn copy_tree(source: &Path, target: &Path) -> Result<(), Error> {
    private_directory(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = target.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &path)?;
        } else if kind.is_file() {
            stage_file(
                &path,
                &fs::read(entry.path())?,
                entry.metadata()?.mode() & 0o777,
            )?;
        } else {
            return Err("installed Lab assets contain an unsupported file type".into());
        }
    }
    Ok(())
}

fn stage_nested_inputs(inputs: &Path, share: &Path) -> Result<(), Error> {
    let destination = share.join("lab-native");
    private_directory(&destination)?;
    let bin = destination.join("bin");
    private_directory(&bin)?;
    for name in ["safeyolo", "safeyolo-proxy"] {
        // Select installation inputs, not a mount containing instance tokens.
        // Copy only matching Linux executable files through the checked handle.
        let source = inputs.join("bin").join(name);
        let mut input = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&source)?;
        if !input.metadata()?.is_file() {
            return Err("nested input must be a regular native executable".into());
        }
        let mut header = [0; 20];
        input.read_exact(&mut header)?;
        let machine = match std::env::consts::ARCH {
            "aarch64" => 183,
            "x86_64" => 62,
            _ => return Err("unsupported nested Linux architecture".into()),
        };
        if &header[..6] != b"\x7fELF\x02\x01"
            || u16::from_le_bytes([header[18], header[19]]) != machine
        {
            return Err("nested inputs must be matching native Linux artifacts".into());
        }
        let mut file = tempfile::NamedTempFile::new_in(&bin)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
        file.write_all(&header)?;
        io::copy(&mut input, &mut file)?;
        file.as_file().sync_all()?;
        file.persist(bin.join(name))?;
    }
    Ok(())
}

fn stage(agent: &host_agents::Agent, lab: &Lab) -> Result<(), Error> {
    let root = host_platform::config_dir();
    let directory = root.join("agents").join(&agent.name);
    private_directory(&directory)?;
    let home = directory.join("home");
    private_directory(&home)?;
    let managed = home.join(".safeyolo");
    private_directory(&managed)?;
    stage_file(
        &managed.join("AGENTS.md"),
        include_bytes!("../../docs/AGENTS.md"),
        0o600,
    )?;
    let command = home.join(".safeyolo-command");
    // The guest staging owner wraps this command at boot. Keep its recognized
    // payload on later boots instead of overwriting a guest's active command.
    if !command.try_exists()? {
        stage_file(
            &command,
            include_bytes!("../../contrib/codex-command.sh"),
            0o755,
        )?;
        stage_file(
            &home.join(".safeyolo-interactive-command"),
            include_bytes!("../../contrib/codex-command.sh"),
            0o755,
        )?;
    }
    crate::coord_setup::stage_runtime(&home, &root.join("assets/guest/safeyolo-coord"))?;
    stage_file(
        &managed.join("safeyolo-coord-mcp-launcher"),
        include_bytes!("../../contrib/safeyolo-coord-mcp-launcher.sh"),
        0o755,
    )?;
    crate::coord_setup::stage_mcp(&home, "codex", false)?;
    let share = directory.join("config-share");
    private_directory(&share)?;
    if let Some(inputs) = &lab.nested_assets {
        stage_nested_inputs(inputs, &share)?;
    }
    let skills = share.join("skills");
    private_directory(&skills)?;
    for name in ["safeyolo", "safeyolo-lab-controller"] {
        copy_tree(&root.join("assets/skills").join(name), &skills.join(name))?;
    }
    let agents = home.join(".agents");
    private_directory(&agents)?;
    let links = agents.join("skills");
    private_directory(&links)?;
    for name in ["safeyolo", "safeyolo-lab-controller"] {
        let link = links.join(name);
        let target = PathBuf::from(format!("/safeyolo/skills/{name}"));
        if let Ok(existing) = fs::read_link(&link) {
            if existing != target {
                return Err("refusing to replace an unrelated Lab skill link".into());
            }
        } else if link.try_exists()? {
            return Err("refusing to replace an unrelated Lab skill".into());
        } else {
            std::os::unix::fs::symlink(target, link)?;
        }
    }
    Ok(())
}

async fn output(agent: &str, command: &str) -> Result<std::process::Output, Error> {
    Ok(host_platform::guest_command_output(agent, command, Duration::from_secs(60)).await?)
}
const GUEST_LAB: &str = "/safeyolo/skills/safeyolo-lab-controller/scripts/safeyolo-lab";
fn validate_status(value: &Value, name: &str) -> Result<(), Error> {
    let flags: Option<Vec<_>> = ["session_exists", "owned", "controller_alive"]
        .iter()
        .map(|key| value[*key].as_bool())
        .collect();
    if value["agent"] != name
        || value["session"] != "lab"
        || !matches!(
            flags.as_deref(),
            Some(
                [false, false, false]
                    | [true, false, false]
                    | [true, true, false]
                    | [true, true, true]
            )
        )
    {
        return Err(
            "guest Lab status has an invalid identity or state; no session was changed".into(),
        );
    }
    Ok(())
}
async fn guest_status(name: &str) -> Result<Value, Error> {
    let result = output(name, &format!("{GUEST_LAB} --status --json")).await?;
    let value = serde_json::from_slice(&result.stdout)
        .map_err(|_| "guest Lab status is unverified; inspect agent diagnostics")?;
    validate_status(&value, name)?;
    if !matches!(result.status.code(), Some(0 | 3 | 4)) {
        return Err("guest Lab status command failed".into());
    }
    Ok(value)
}

async fn run_inner(options: Options) -> Result<i32, Error> {
    let root = host_platform::config_dir();
    let selected = {
        let lock_path = root.join("data/lab-selection.lock");
        let _lock = tokio::task::spawn_blocking(move || host_platform::lock_host_state(&lock_path))
            .await??;
        let agents = host_agents::list()?;
        let mut candidates = Vec::new();
        for agent in &agents {
            if let Some(lab) = record(&agent.name)? {
                if compatible(&lab, agent) {
                    candidates.push(agent.clone());
                } else if options.agent.as_deref() == Some(&agent.name) {
                    return Err("selected Lab record no longer matches its agent; inspect its configuration".into());
                }
            }
        }
        let selected = if let Some(name) = &options.agent {
            if let Some(agent) = agents.iter().find(|agent| &agent.name == name) {
                if !candidates.iter().any(|candidate| candidate.id == agent.id) {
                    return Err("selected agent is not owned by this Lab workflow; existing work is unchanged".into());
                }
                Some(agent.clone())
            } else {
                None
            }
        } else if candidates.len() == 1 {
            candidates.pop()
        } else if candidates.is_empty() {
            None
        } else {
            println!("Choose a Lab with --agent. Available Labs:");
            for agent in candidates {
                println!("  {}", safe(&agent.name));
            }
            return Err("multiple Labs are configured".into());
        };
        if selected.is_none() && options.action.is_some() {
            if options.action.as_deref() == Some("--status") {
                println!("{}", json!({"managed":false,"agents":[]}));
                return Ok(0);
            }
            return Err("no owned Lab is available; start safeyolo lab first".into());
        }
        if let Some(agent) = selected {
            if options.workspace.is_some()
                || options.nested.is_some()
                || options.objective.is_some()
                || options.allow_unowned
            {
                return Err("existing Lab retains its objective and workspace; choose a new --agent for another experiment".into());
            }
            agent
        } else {
            let objective =
                options.objective.clone().map(Ok).unwrap_or_else(|| {
                    prompt("What do you want to build, test, or understand? ")
                })?;
            let objective = objective.trim();
            if objective.chars().count() > 4096 {
                return Err(
                    "Lab objective exceeds the guest controller's 4096 character limit".into(),
                );
            }
            if objective.is_empty() {
                return Err("the Lab objective cannot be empty".into());
            }
            let workspace = crate::host_boot::workspace(
                &options
                    .workspace
                    .clone()
                    .unwrap_or(std::env::current_dir()?),
                options.allow_unowned,
            )?;
            let name = if let Some(name) = &options.agent {
                name.clone()
            } else {
                let mut name = "safeyolo-lab".to_owned();
                let mut suffix = 2;
                while agents.iter().any(|agent| agent.name == name)
                    || root.join("agents").join(&name).try_exists()?
                    || state_path(&name)?.try_exists()?
                {
                    name = format!("safeyolo-lab-{suffix}");
                    suffix += 1;
                }
                name
            };
            state_path(&name)?;
            if root.join("agents").join(&name).try_exists()? || state_path(&name)?.try_exists()? {
                return Err("Lab name has retained files; choose another --agent".into());
            }
            println!(
                "Lab objective: {}\nAgent: {name}\nWorkspace: {}\nExiting retains the Lab and its evidence. Teardown stops only its owned session and guest.",
                safe(objective),
                safe(&workspace.to_string_lossy())
            );
            if !options.yes
                && !matches!(
                    prompt("Create this Lab? [y/N] ")?.as_str(),
                    "y" | "Y" | "yes"
                )
            {
                println!("Lab creation cancelled; no agent was changed.");
                return Ok(0);
            }
            let mut settings = vec![("folder".into(), workspace.to_string_lossy().into_owned())];
            if options.allow_unowned {
                settings.push(("dangerously_allow_unowned".into(), "true".into()));
            }
            let nested_assets = options
                .nested
                .as_ref()
                .map(|path| path.canonicalize())
                .transpose()?
                .or_else(|| {
                    (cfg!(target_os = "linux")
                        && root.join("bin/safeyolo").is_file()
                        && root.join("bin/safeyolo-proxy").is_file())
                    .then(|| root.clone())
                });
            let agent = host_agents::configure(&name, &settings, true, None).await?;
            save(&Lab {
                schema: 1,
                agent: name,
                agent_id: agent.id.clone(),
                workspace,
                objective: objective.to_owned(),
                nested_assets,
            })?;
            agent
        }
    };
    let selected = host_agents::refresh(&selected)?;
    let name = &selected.name;
    let lab = record(name)?.ok_or("Lab record is missing")?;
    let runtime = host_lifecycle::runtime(&selected).await?;
    if options.action.as_deref() == Some("--status") {
        let guest = if runtime["exec"] == true {
            guest_status(name).await?
        } else {
            Value::Null
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"lab":lab,"runtime":runtime,"guest":guest}))?
        );
        return Ok(0);
    }
    if options.action.as_deref() == Some("--teardown") && runtime["runtime_state"] == "stopped" {
        println!(
            "Lab guest is stopped. No live session was inspected or removed. Workspace and evidence remain at {}.",
            root.join("agents")
                .join(name)
                .join("home/.safeyolo/lab-evidence")
                .display()
        );
        return Ok(0);
    }
    if runtime["runtime_state"] == "stopped" {
        let directory = root.join("agents").join(name);
        let lock = tokio::task::spawn_blocking(move || {
            host_lifecycle::SetupLock::acquire_in(&directory, None)
        })
        .await??;
        if host_lifecycle::runtime(&selected).await?["runtime_state"] != "stopped" {
            return Err(
                "Lab guest changed during preparation; retry after inspecting its status".into(),
            );
        }
        stage(&selected, &lab)?;
        host_commands::run(host_platform::config_path(), &["start".into()]).await?;
        let observed =
            host_lifecycle::start(&selected, "sandbox-start", Some(lock), None, false).await?;
        if observed["runtime_state"] != "running" || observed["exec"] != true {
            return Err("Lab guest did not become ready; retained state is available through lab --status and agent diagnostics".into());
        }
    } else if runtime["runtime_state"] != "running" || runtime["exec"] != true {
        return Err(
            "Lab runtime is degraded or unknown; inspect agent diagnostics before continuing"
                .into(),
        );
    }
    let guest = guest_status(name).await?;
    if guest["session_exists"] == true && guest["owned"] != true {
        return Err(
            "an unrelated guest session named lab exists; no session was adopted or changed".into(),
        );
    }
    if options.action.as_deref() == Some("--teardown") {
        if guest["session_exists"] == true {
            let result = output(name, &format!("{GUEST_LAB} --teardown")).await?;
            if !result.status.success() {
                return Err("Lab evidence capture or teardown failed; guest and files remain for inspection".into());
            }
            let evidence = String::from_utf8(result.stdout)?;
            let path = evidence
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Lab session removed after redacted evidence capture: ")
                })
                .ok_or("Lab teardown supplied no capture result; inspect retained guest")?;
            let relative = Path::new(path).strip_prefix("/home/agent/.safeyolo/lab-evidence")?;
            if relative.components().count() != 1
                || !relative
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                return Err("Lab teardown evidence path is invalid".into());
            }
            let capture = root
                .join("agents")
                .join(name)
                .join("home/.safeyolo/lab-evidence")
                .join(relative);
            let home = root.join("agents").join(name).join("home");
            for directory in [
                home.join(".safeyolo"),
                home.join(".safeyolo/lab-evidence"),
                capture.clone(),
            ] {
                let metadata = fs::symlink_metadata(directory)?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err("Lab teardown evidence directory is unverified".into());
                }
            }
            for file in ["capture-status.txt", "manifest.jsonl", "SHA256SUMS"] {
                let metadata = fs::symlink_metadata(capture.join(file))?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err("Lab teardown evidence capture is unverified".into());
                }
            }
            let mut status = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(capture.join("capture-status.txt"))?;
            if !status.metadata()?.is_file() || status.metadata()?.len() > 4096 {
                return Err("Lab teardown evidence capture is unverified".into());
            }
            let mut text = String::new();
            status.read_to_string(&mut text)?;
            if !text.lines().any(|line| line == "status=complete") {
                return Err("Lab teardown evidence capture is unverified".into());
            }
            println!("{}", safe(&evidence));
        } else {
            println!("No live Lab session was present; no session was removed.");
        }
        if !options.keep {
            host_lifecycle::stop(&selected, None).await?;
        }
        println!("Workspace, authentication and experiment evidence were retained.");
        return Ok(0);
    }
    if guest["session_exists"] == true {
        if let Some(action) = &options.action {
            let result = output(name, &format!("{GUEST_LAB} {action}")).await?;
            if !result.status.success() {
                return Err("owned Lab controller did not recover; inspect lab --status".into());
            }
        } else if guest["controller_alive"] != true {
            return Err(
                "owned Lab controller is not alive; run lab --recover to restart it".into(),
            );
        }
    } else {
        // --version uses the maintained Codex command's ordinary install path,
        // without starting a model or importing another identity's credentials.
        if host_platform::exec_guest_command(name, "/home/agent/.safeyolo-command --version")
            .await?
            != 0
        {
            return Err("Lab Codex setup failed; guest state is retained for repair".into());
        }
        let auth = "export PATH=/home/agent/.local/bin:/home/agent/.mise/shims:$PATH; codex login status >/dev/null 2>&1";
        if host_platform::exec_guest_command(name, auth).await? != 0 {
            println!(
                "This Lab needs its own normal Codex authentication. Login runs outside the experiment panes."
            );
            if !matches!(
                prompt("Sign in to this Lab now? [y/N] ")?.as_str(),
                "y" | "Y" | "yes"
            ) {
                return Err("Lab authentication is missing; rerun safeyolo lab after signing in to this guest".into());
            }
            let mut child = host_platform::spawn_guest_command(name, "export PATH=/home/agent/.local/bin:/home/agent/.mise/shims:$PATH; exec codex login --device-auth").await?;
            if !child.wait().await?.success()
                || host_platform::exec_guest_command(name, auth).await? != 0
            {
                return Err("Lab Codex login was not confirmed; no controller was started".into());
            }
        }
    }
    println!(
        "Lab: {name}\nObjective: {}\nEvidence: /home/agent/.safeyolo/lab-evidence\nExit the viewer with Ctrl-a d. Reattach with safeyolo lab --agent {name}.",
        safe(&lab.objective)
    );
    let command = if guest["session_exists"] == true {
        GUEST_LAB.to_owned()
    } else {
        format!("{GUEST_LAB} --objective {}", quote(&lab.objective))
    };
    host_lifecycle::persistent_shell(&selected, &command, "sy-lab").await
}

pub async fn run(config: PathBuf, args: &[String]) -> Result<i32, Error> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(0);
    }
    let options = Options::parse(args)?;
    let parent = config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let config = parent.join(config.file_name().ok_or("configuration has no filename")?);
    host_platform::in_config(config, run_inner(options)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_guest_status_does_not_authorize_a_lifecycle_change() {
        for value in [
            json!({}),
            json!({"agent":"other","session":"lab","session_exists":true,"owned":true,"controller_alive":true}),
            json!({"agent":"lab","session":"lab","session_exists":false,"owned":true,"controller_alive":true}),
            json!({"agent":"lab","session":"lab","session_exists":"true","owned":true,"controller_alive":true}),
        ] {
            assert!(validate_status(&value, "lab").is_err());
        }
        assert!(validate_status(&json!({"agent":"lab","session":"lab","session_exists":true,"owned":true,"controller_alive":false}),"lab").is_ok());
    }
    #[test]
    fn actions_preserve_the_recorded_objective_and_workspace() {
        for args in [
            vec!["--status", "--objective", "change"],
            vec!["--keep-agent"],
            vec!["--recover", "--teardown"],
            vec!["--json"],
        ] {
            assert!(
                Options::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
            );
        }
        assert_eq!(quote("$(marker)'value"), "'$(marker)'\\''value'");
    }
    #[test]
    fn nested_staging_copies_only_native_inputs_and_refuses_special_files() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("instance");
        let share = root.path().join("share");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir(&share).unwrap();
        fs::write(source.join("admin_token"), "private fixture value").unwrap();
        let mut header = [0; 20];
        header[..6].copy_from_slice(b"\x7fELF\x02\x01");
        let machine: u16 = if std::env::consts::ARCH == "aarch64" {
            183
        } else {
            62
        };
        header[18..].copy_from_slice(&machine.to_le_bytes());
        for name in ["safeyolo", "safeyolo-proxy"] {
            fs::write(source.join("bin").join(name), header).unwrap();
        }
        stage_nested_inputs(&source, &share).unwrap();
        let bin = share.join("lab-native/bin");
        assert_eq!(fs::read_dir(&bin).unwrap().count(), 2);
        assert!(!share.join("lab-native/admin_token").exists());
        fs::remove_file(source.join("bin/safeyolo")).unwrap();
        std::os::unix::fs::symlink(source.join("admin_token"), source.join("bin/safeyolo"))
            .unwrap();
        assert!(stage_nested_inputs(&source, &share).is_err());
        assert_eq!(fs::read(bin.join("safeyolo")).unwrap(), header);
        fs::remove_file(source.join("bin/safeyolo")).unwrap();
        fs::create_dir(source.join("bin/safeyolo")).unwrap();
        assert!(stage_nested_inputs(&source, &share).is_err());
    }
}
