//! Guided composition of the existing Factory and agent lifecycle operations.
use super::*;
use std::io::IsTerminal;

pub(super) fn prepared(
    root: &Path,
    snapshot: &Snapshot,
    name: &str,
    role: &Role,
    agent: &host_agents::Agent,
    choices: &Preparation,
) -> Result<bool, Error> {
    let folder = agent.folder.as_ref().map(PathBuf::from);
    let workspace_matches = choices
        .workspaces
        .get(name)
        .is_none_or(|selected| folder.as_ref() == Some(selected));
    if !workspace_matches {
        return Ok(false);
    }
    if let Some(folder) = &folder {
        host_boot::workspace(
            folder,
            choices.allow_unowned || agent.dangerously_allow_unowned,
        )?;
    }
    Ok(folder.is_some()
        && (!choices.allow_unowned || agent.dangerously_allow_unowned)
        && agent.launcher.as_deref() == Some("supervisor")
        && agent.host_script.as_deref() == setup_script(root, &role.harness)?.to_str()
        && role
            .args
            .as_ref()
            .is_none_or(|args| args == &agent.user_default_args)
        && staged(root, snapshot, name, role).is_ok())
}

fn command(root: &Path, args: &[&str]) -> String {
    std::iter::once(root.join("bin/safeyolo").to_string_lossy().into_owned())
        .chain(["--root".into(), root.display().to_string()])
        .chain(args.iter().map(|s| (*s).to_owned()))
        .map(|s| shell_quote(&s))
        .collect::<Vec<_>>()
        .join(" ")
}

fn resume(root: &Path, file: &Path, choices: &Preparation, extra: &[&str]) -> String {
    let mut args = vec![
        "factory".to_owned(),
        "setup".to_owned(),
        file.display().to_string(),
    ];
    for (role, workspace) in &choices.workspaces {
        args.extend([
            "--workspace".to_owned(),
            format!("{role}={}", workspace.display()),
        ]);
    }
    if choices.allow_unowned {
        args.push("--dangerously-allow-unowned".to_owned());
    }
    args.extend(extra.iter().map(|arg| (*arg).to_owned()));
    command(root, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

fn report(value: &Value) -> Result<(), Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn pending(value: &mut Value, state: &str, next: String, error: &str) -> Result<(), Error> {
    value["status"] = json!(state);
    value["next"] = json!(next);
    value["error"] = json!(error);
    report(value)?;
    Err(format!("Factory setup incomplete: {error}; next: {}", value["next"]).into())
}

/// Starts only an authentication sandbox, checks the actual installed harness,
/// then stops it. No supervisor, checkpoint initialization or model turn runs.
async fn authentication(root: &Path, role: &Role) -> Result<(), Error> {
    let agents = host_agents::list()?;
    let agent = agents
        .iter()
        .find(|a| a.name == role.agent)
        .ok_or("role is not prepared")?;
    let runtime = host_lifecycle::runtime(agent).await?;
    if runtime["runtime_state"] != "stopped" {
        if runtime["runtime_state"] != "running" || runtime["agent_state"] != "running" {
            return Err(format!("agent {} has an unfinished or unknown runtime; inspect agent diagnostics and stop this role before repeating authentication",role.agent).into());
        }
        return guest_preflight(
            role,
            role.args.as_deref().unwrap_or(&agent.user_default_args),
        )
        .await;
    }
    if role.harness == "codex" {
        coord_setup::codex_state(&home(root, role), None, true, None)?;
    }
    let started = host_lifecycle::start(agent, "sandbox-start", None, None, false).await?;
    if let Some(error) = role_start_error(&started) {
        return Err(format!("authentication sandbox failed: {error}").into());
    }
    let result = async {
        let child = host_platform::spawn_guest_command_with_output(
            &role.agent,
            "/home/agent/.safeyolo-interactive-command --version",
            true,
            false,
        )
        .await?;
        let output = tokio::time::timeout(Duration::from_secs(120), child.wait_with_output())
            .await
            .map_err(|_| "harness preparation timed out; inspect agent diagnostics")??;
        if !output.status.success() {
            return Err(format!(
                "harness preparation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        guest_preflight(
            role,
            role.args.as_deref().unwrap_or(&agent.user_default_args),
        )
        .await
    }
    .await;
    let stopped = host_lifecycle::stop(agent, None).await?;
    if let Some(error) = role_lifecycle_error(&stopped) {
        return Err(format!("authentication sandbox stop failed: {error}; inspect agent diagnostics {} before retry", role.agent).into());
    }
    result
}

async fn refresh(
    root: &Path,
    snapshot: &Snapshot,
    choices: &Preparation,
    value: &mut Value,
) -> Result<(), Error> {
    let configured = host_agents::list()?;
    for observed in value["roles"].as_array_mut().unwrap() {
        let name = observed["role"].as_str().unwrap().to_owned();
        let role = &snapshot.roles[&name];
        if let Some(agent) = configured.iter().find(|a| a.name == role.agent) {
            observed["agent_id"] = json!(agent.id);
            observed["runtime"] = host_lifecycle::runtime(agent).await.unwrap_or_else(
                |error| json!({"runtime_state":"unknown","error":error.to_string()}),
            );
            match prepared(root, snapshot, &name, role, agent, choices) {
                Ok(matches) => observed["prepared"] = json!(matches),
                Err(error) => {
                    observed["prepared"] = Value::Null;
                    observed["preparation_error"] = json!(error.to_string());
                }
            }
            observed["staging_error"] = json!(
                staged(root, snapshot, &name, role)
                    .err()
                    .map(|e| e.to_string())
            );
        }
    }
    Ok(())
}

pub(super) async fn run(root: &Path, file: &Path, options: &[String]) -> Result<(), Error> {
    let file = file.canonicalize()?;
    let snapshot = load_file(&file)?;
    let mut preview = false;
    let mut yes = false;
    let mut fresh = false;
    let mut logins = BTreeSet::new();
    let mut preparation_options = Vec::new();
    let mut options = options.iter();
    while let Some(option) = options.next() {
        match option.as_str() {
            "--preview" => preview = true,
            "--yes" => yes = true,
            "--confirm-fresh-identity" => fresh = true,
            "--login" => {
                let name = options.next().ok_or("--login requires a declared role")?;
                if !snapshot.roles.contains_key(name) || !logins.insert(name.clone()) {
                    return Err("--login requires a distinct declared role".into());
                }
            }
            "--workspace" => {
                preparation_options.push(option.clone());
                preparation_options.push(
                    options
                        .next()
                        .ok_or("--workspace requires ROLE=PATH")?
                        .clone(),
                );
            }
            "--dangerously-allow-unowned" => preparation_options.push(option.clone()),
            _ => return Err(format!("unknown Factory setup option: {option}").into()),
        }
    }
    let interactive = std::io::stdin().is_terminal() && !yes && !preview;
    let mut choices = preparation(&snapshot, &preparation_options)?;
    let configured = host_agents::list()?;
    let previous = if root
        .join("factories")
        .join(&snapshot.name)
        .join("approved")
        .try_exists()?
    {
        Some(approved(root, &snapshot.name)?.0)
    } else {
        None
    };
    let id = snapshot.id()?;
    let same = previous
        .as_ref()
        .is_some_and(|old| old.id().ok().as_ref() == Some(&id));
    let mut roles = Vec::new();
    for (name, role) in &snapshot.roles {
        let agent = configured.iter().find(|a| a.name == role.agent);
        if !choices.workspaces.contains_key(name) {
            if let Some(folder) = agent.and_then(|a| a.folder.as_ref()) {
                choices.workspaces.insert(
                    name.clone(),
                    host_boot::workspace(
                        Path::new(folder),
                        choices.allow_unowned || agent.unwrap().dangerously_allow_unowned,
                    )?,
                );
            } else if interactive {
                print!("Workspace for role {name} (agent {}): ", role.agent);
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                choices.workspaces.insert(
                    name.clone(),
                    host_boot::workspace(Path::new(input.trim()), choices.allow_unowned)?,
                );
            }
        }
        let runtime = if let Some(agent) = agent {
            host_lifecycle::runtime(agent).await?
        } else {
            json!({"runtime_state":"missing"})
        };
        let staging_error = staged(root, &snapshot, name, role)
            .err()
            .map(|e| e.to_string());
        roles.push(json!({"role":name,"agent":role.agent,"agent_id":agent.map(|a| &a.id),
            "workspace":choices.workspaces.get(name),"previous_workspace":agent.and_then(|a| a.folder.as_ref()),"runtime":runtime,
            "prepared":agent.map(|a| prepared(root,&snapshot,name,role,a,&choices)).transpose()?.unwrap_or(false),
            "staging_error":staging_error,"authentication":"unverified"}));
    }
    let mut value = json!({"root":root,"source":file,"factory":snapshot.name,"snapshot":id,
        "approved":same,"status":"preview","roles":roles,"resume":resume(root,&file,&choices,&[]),
        "login_roles":logins,"confirm_fresh_identity":fresh,"dangerously_allow_unowned":choices.allow_unowned,
        "previous_contract":if same {None} else {previous.as_ref()},
        "selected_contract":if !same || preview {Some(&snapshot)} else {None},
        "effects":"Approve the exact snapshot when needed; prepare declared roles and their room grants; check each role's own authentication in a sandbox; start supervised roles. Existing identities, homes, checkpoints and room history are retained. No host or peer credentials are copied."});
    if preview {
        return report(&value);
    }

    // Preview exact old/new contract bytes and the workspace choices before
    // the existing approval decision. Approval selects future instructions;
    // prepare_roles retains the existing refusal to replace live staging.
    report(&value)?;
    if !same {
        if !yes {
            if !interactive {
                return pending(
                    &mut value,
                    "approval-required",
                    command(
                        root,
                        &[
                            "factory",
                            "approve",
                            file.to_str().ok_or("Factory path must be UTF-8")?,
                        ],
                    ),
                    "the selected exact snapshot has not been approved",
                );
            }
            confirm("Approve this exact Factory contract? [y/N] ")?;
        }
        approve(root, &snapshot)?;
        value["approved"] = json!(true);
    }
    value["status"] = json!("approved");
    value.as_object_mut().unwrap().remove("previous_contract");
    value.as_object_mut().unwrap().remove("selected_contract");
    if !crate::host_commands::proxy_live() {
        return pending(
            &mut value,
            "approved",
            command(root, &["start"]),
            "start the selected instance proxy, then repeat this setup command",
        );
    }
    for name in snapshot.roles.keys() {
        if !choices.workspaces.contains_key(name) {
            return pending(
                &mut value,
                "workspace-required",
                resume(
                    root,
                    &file,
                    &choices,
                    &["--workspace", &format!("{name}=PATH")],
                ),
                &format!("role {name} needs an owned workspace"),
            );
        }
    }
    let (selected, path) = approved(root, &snapshot.name)?;
    if selected.id()? != id {
        return Err(
            "approved snapshot changed during setup; repeat setup to inspect the current selection"
                .into(),
        );
    }
    if let Err(error) = prepare_roles(root, &snapshot, &path, &choices, false, true).await {
        refresh(root, &snapshot, &choices, &mut value).await?;
        return pending(
            &mut value,
            "preparation-incomplete",
            resume(root, &file, &choices, &[]),
            &error.to_string(),
        );
    }
    refresh(root, &snapshot, &choices, &mut value).await?;
    value["status"] = json!("prepared");
    report(&value)?;
    for (name, role) in &snapshot.roles {
        if logins.contains(name) {
            if let Err(error) = login(&snapshot, name).await {
                return pending(
                    &mut value,
                    "authentication-required",
                    command(root, &["factory", "login", &snapshot.name, name]),
                    &error.to_string(),
                );
            }
        }
        // The retained start guard owns checkpoint validity and freshness.
        let state = home(root, role).join(".safeyolo/coord-supervisor-state.json");
        if let Err(error) = coord_supervisor::State::load_for_start(&state, fresh) {
            if interactive && !state.try_exists()? {
                println!(
                    "Missing checkpoint for role {name}. Confirm only if every role without a checkpoint has never received targeted attention in any configured room. Clearing history does not reset attention."
                );
                confirm("Confirm these fresh identities for this launch? [y/N] ")?;
                fresh = true;
            } else {
                let next = if state.try_exists()? {
                    command(root, &["agent", "diagnostics", &role.agent])
                } else {
                    resume(root, &file, &choices, &["--confirm-fresh-identity"])
                };
                return pending(
                    &mut value,
                    "checkpoint-required",
                    next,
                    &format!("role {name}: {error}"),
                );
            }
        }
    }
    for (name, role) in &snapshot.roles {
        let mut checked = authentication(root, role).await;
        if checked.is_err() && interactive {
            eprintln!("role {name}: {}", checked.as_ref().unwrap_err());
            println!(
                "Use role {name}'s own login, or return and configure its supported external provider. Host and peer logins are not copied."
            );
            print!("Enter login to authenticate this role, or press Enter to return: ");
            std::io::stdout().flush()?;
            let mut choice = String::new();
            std::io::stdin().read_line(&mut choice)?;
            if choice.trim() == "login" {
                checked = match login(&snapshot, name).await {
                    Ok(()) => authentication(root, role).await,
                    Err(error) => Err(error),
                };
            }
        }
        if let Err(error) = checked {
            refresh(root, &snapshot, &choices, &mut value).await?;
            let current = value["roles"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["role"] == *name)
                .unwrap();
            let next = if current["runtime"]["runtime_state"] == "stopped" {
                command(root, &["factory", "login", &snapshot.name, name])
            } else {
                command(root, &["agent", "diagnostics", &role.agent])
            };
            return pending(
                &mut value,
                "authentication-required",
                next,
                &format!(
                    "role {name} authentication or harness/Coord preflight is unverified: {error}; correct the named prerequisite, then repeat setup"
                ),
            );
        }
        let observed = value["roles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["role"] == *name)
            .unwrap();
        observed["authentication"] = json!("checked");
    }
    if approved(root, &snapshot.name)?.0.id()? != id {
        return Err(
            "approved snapshot changed during setup; repeat setup before starting roles".into(),
        );
    }
    match start_roles(root, &snapshot, fresh).await {
        Ok(observed) => {
            refresh(root, &snapshot, &choices, &mut value).await?;
            value["status"] = json!("running");
            value["readiness"] = observed;
            report(&value)
        }
        Err(error) => {
            refresh(root, &snapshot, &choices, &mut value).await?;
            value["readiness"] = doctor(root, &snapshot).await?;
            pending(
                &mut value,
                "start-incomplete",
                command(root, &["factory", "doctor", &snapshot.name]),
                &error.to_string(),
            )
        }
    }
}
