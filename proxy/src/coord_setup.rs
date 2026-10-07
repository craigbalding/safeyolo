//! Native Codex state and factory-role staging. Credential bytes stay agent-local.

use crate::{
    Error,
    coord_supervisor::{Config, Factory, atomic_write, simple_name},
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use toml_edit::{DocumentMut, Item, Table, value};

const PROVENANCE: &str = "safeyolo.codex-provenance/v1";

fn safe(path: &Path, directory: bool, mode: Option<u32>) -> Result<bool, Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || metadata.uid() != unsafe { libc::getuid() }
        || mode.is_some_and(|mode| metadata.permissions().mode() & 0o7777 != mode)
        || (mode.is_none() && metadata.permissions().mode() & 0o022 != 0)
    {
        return Err(format!("unsafe agent-local path: {}", path.display()).into());
    }
    Ok(true)
}
fn directory(path: &Path) -> Result<(), Error> {
    if !safe(path, true, None)? {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn read_text(path: &Path) -> Result<String, Error> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("staged input is not a regular file".into());
    }
    let mut text = String::new();
    std::io::Read::by_ref(&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut text)?;
    if text.len() > 4 * 1024 * 1024 {
        return Err("staged configuration exceeds the existing checkpoint bound".into());
    }
    Ok(text)
}

/// Staging may run on macOS, so inspect the Linux artifact and its build
/// receipts without executing it on the operator host.
pub fn stage_runtime(home: &Path, source: &Path) -> Result<(), Error> {
    safe(home, true, None)?
        .then_some(())
        .ok_or("agent home is missing")?;
    let directory_path = home.join(".safeyolo");
    directory(&directory_path)?;
    let destination = directory_path.join("safeyolo-coord");
    safe(&destination, false, None)?;
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    if !input.metadata()?.is_file() {
        return Err("native Coord artifact must be a regular file".into());
    }
    let mut header = [0u8; 20];
    input.read_exact(&mut header)?;
    let expected_machine = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => return Err("unsupported guest architecture".into()),
    };
    if &header[..6] != b"\x7fELF\x02\x01"
        || u16::from_le_bytes([header[18], header[19]]) != expected_machine
    {
        return Err("Coord guest artifact must be the matching 64-bit Linux executable; select assets/guest/safeyolo-coord".into());
    }
    let identity = read_text(&source.with_extension("version"))?;
    let expected_identity = format!(
        "safeyolo-coord {} commit={} profile={}\n",
        env!("CARGO_PKG_VERSION"),
        env!("SAFEYOLO_BUILD_REVISION"),
        env!("SAFEYOLO_BUILD_PROFILE")
    );
    if identity != expected_identity {
        return Err("Coord host and guest source/profile identities differ".into());
    }
    let checksum = read_text(&source.with_extension("sha256"))?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(&header);
    let mut temporary = tempfile::NamedTempFile::new_in(&directory_path)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary.write_all(&header)?;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        temporary.write_all(&buffer[..count])?;
    }
    let observed: String = digest
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if checksum.trim() != observed {
        return Err("Coord guest bytes differ from their build receipt".into());
    }
    temporary.as_file().sync_all()?;
    temporary.persist(&destination)?;
    fs::File::open(directory_path)?.sync_all()?;
    Ok(())
}
fn marker(path: &Path) -> Result<Option<String>, Error> {
    if !safe(path, false, Some(0o600))? {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(&read_text(path)?)?;
    if parsed.as_object().is_none_or(|o| o.len() != 2)
        || parsed["schema"] != PROVENANCE
        || ![
            "fresh",
            "agent-local",
            "external-provider",
            "legacy-unknown",
            "reset",
        ]
        .contains(&parsed["state"].as_str().unwrap_or(""))
    {
        return Err("invalid Codex provenance marker".into());
    }
    Ok(parsed["state"].as_str().map(str::to_owned))
}
fn write_marker(path: &Path, state: &str) -> Result<(), Error> {
    atomic_write(
        path,
        &serde_json::to_vec(&json!({"schema":PROVENANCE,"state":state}))?,
        0o600,
    )
}

/// This function inspects authentication metadata only. It never opens, copies,
/// hashes or changes the mode of an auth file during setup or adoption.
pub fn codex_state(
    home: &Path,
    launcher: Option<&str>,
    require_local: bool,
    recovery: Option<&str>,
) -> Result<(), Error> {
    safe(home, true, None)?
        .then_some(())
        .ok_or("agent home is missing")?;
    let codex = home.join(".codex");
    directory(&codex)?;
    let auth = codex.join("auth.json");
    let provenance = codex.join(".safeyolo-provenance.json");
    if let Some(action) = recovery {
        marker(&provenance)?;
        if action == "adopt" {
            if !safe(&auth, false, Some(0o600))? {
                return Err("cannot adopt missing auth.json; run codex login --device-auth inside this agent first".into());
            }
            return write_marker(&provenance, "agent-local");
        }
        if action != "reset" {
            return Err("Codex recovery requires adopt or reset".into());
        }
        match fs::symlink_metadata(&auth) {
            Ok(m) => {
                if m.is_dir() {
                    return Err("auth.json is a directory; inspect it inside this agent and use rmdir /home/agent/.codex/auth.json if it is empty, then repeat reset".into());
                }
                fs::remove_file(&auth)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        return write_marker(&provenance, "reset");
    }
    let auth_present = safe(&auth, false, Some(0o600))?;
    let config_path = codex.join("config.toml");
    let exists = safe(&config_path, false, None)?;
    let existing = if exists {
        read_text(&config_path)?
    } else {
        String::new()
    };
    let mut config = existing
        .parse::<DocumentMut>()
        .map_err(|_| "invalid Codex config; repair config.toml inside the agent and rerun setup")?;
    let external = config.get("forced_chatgpt_auth").and_then(Item::as_bool) == Some(false);
    let previous = marker(&provenance)?;
    if external && auth_present {
        return Err("external-provider configuration also has auth.json; reset or re-enable ChatGPT authentication".into());
    }
    let state = if external {
        if previous.as_deref() == Some("legacy-unknown") {
            return Err(
                "Codex credentials have unknown provenance; adopt or reset inside this agent"
                    .into(),
            );
        }
        if previous.as_deref() != Some("external-provider") {
            write_marker(&provenance, "external-provider")?;
        }
        "external-provider".to_owned()
    } else {
        let state = previous.unwrap_or_else(|| {
            if auth_present {
                "legacy-unknown".into()
            } else {
                "fresh".into()
            }
        });
        if !provenance.exists() {
            write_marker(&provenance, &state)?;
        }
        if state == "legacy-unknown"
            || (matches!(state.as_str(), "fresh" | "reset") && auth_present)
            || (state == "agent-local" && !auth_present)
        {
            return Err("Codex authentication needs explicit agent-local adopt or reset; credential contents were not changed. Inside this agent, run /home/agent/.safeyolo/safeyolo-coord codex-state adopt after codex login --device-auth, or use codex-state reset to remove the local login".into());
        }
        state
    };
    if require_local
        && !((state == "agent-local" && auth_present)
            || (state == "external-provider" && !auth_present))
    {
        return Err("coordinated Codex requires an adopted agent-local auth.json or forced_chatgpt_auth=false external-provider configuration. Inside this agent, run codex login --device-auth, then /home/agent/.safeyolo/safeyolo-coord codex-state adopt, then rerun host setup".into());
    }
    config["forced_chatgpt_auth"] = value(!external);
    config["cli_auth_credentials_store"] = value("file");
    if let Some(launcher) = launcher {
        if config.get("mcp_servers").is_none() {
            config["mcp_servers"] = Item::Table(Table::new());
        }
        let inline_table = config["mcp_servers"].as_inline_table().is_some();
        let servers = config["mcp_servers"]
            .as_table_like_mut()
            .ok_or("Codex mcp_servers must be a table")?;
        let mut registration = Table::new();
        registration["command"] = value(launcher);
        registration["args"] = value(toml_edit::Array::new());
        registration["tool_timeout_sec"] = value(330);
        if inline_table {
            let mut inline = toml_edit::InlineTable::new();
            inline.insert("command", launcher.into());
            inline.insert("args", toml_edit::Array::new().into());
            inline.insert("tool_timeout_sec", 330.into());
            servers.insert("safeyolo-coord", value(inline));
        } else {
            servers.insert("safeyolo-coord", Item::Table(registration));
        }
    }
    if config.to_string() != existing {
        let mode = if exists {
            fs::symlink_metadata(&config_path)?.permissions().mode() & 0o7777
        } else {
            0o600
        };
        atomic_write(&config_path, config.to_string().as_bytes(), mode)?;
    }
    let rules = codex.join("rules");
    directory(&rules)?;
    let path = rules.join("safeyolo-guest.rules");
    safe(&path, false, None)?;
    let mut text =
        String::from("# SafeYolo owns guest isolation; writable mounts still contain real data.\n");
    for command in ["bash", "sh", "dash", "zsh", "rm", "sudo", "env"] {
        for prefix in ["", "/bin/", "/usr/bin/"] {
            text.push_str(&format!(
                "prefix_rule(pattern=[{}], decision=\"allow\")\n",
                serde_json::to_string(&format!("{prefix}{command}"))?
            ));
        }
    }
    for command in ["/usr/local/bin/sudo", "trap"] {
        text.push_str(&format!(
            "prefix_rule(pattern=[{}], decision=\"allow\")\n",
            serde_json::to_string(command)?
        ));
    }
    atomic_write(&path, text.as_bytes(), 0o600)
}

pub fn stage_mcp(home: &Path, harness: &str, require_local: bool) -> Result<(), Error> {
    let launcher = "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher";
    match harness {
        "codex" => codex_state(home, Some(launcher), require_local, None),
        "claude" => {
            let path = home.join(".claude.json");
            safe(&path, false, None)?;
            let mut config = if path.exists() {
                serde_json::from_str::<Value>(&read_text(&path)?)?
            } else {
                json!({})
            };
            if !config.is_object() {
                return Err("Claude config must be an object".into());
            }
            if config.get("mcpServers").is_none() {
                config["mcpServers"] = json!({});
            }
            if !config["mcpServers"].is_object() {
                return Err("Claude mcpServers must be an object".into());
            }
            config["mcpServers"]["safeyolo-coord"] =
                json!({"type":"stdio","command":launcher,"args":[]});
            atomic_write(&path, &serde_json::to_vec_pretty(&config)?, 0o600)
        }
        _ => Err("MCP staging requires codex or claude".into()),
    }
}

fn sorted_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map
                .iter()
                .map(|(k, v)| (k.clone(), sorted_json(v)))
                .collect();
            serde_json::to_value(sorted).unwrap()
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted_json).collect()),
        _ => value.clone(),
    }
}
pub(crate) fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn factory_stage(
    config_path: &Path,
    instructions: &Path,
    agent: &str,
    snapshot_path: &Path,
    role: &str,
    harness: &str,
) -> Result<(), Error> {
    let snapshot: Value = serde_json::from_str(&read_text(snapshot_path)?)?;
    let shape = snapshot
        .as_object()
        .ok_or("factory snapshot must be an object")?;
    let required = [
        "schema",
        "name",
        "room",
        "roles",
        "handoffs",
        "operator_input",
    ];
    if shape
        .keys()
        .any(|k| !required.contains(&k.as_str()) && k != "updates")
        || required.iter().any(|k| !shape.contains_key(*k))
    {
        return Err("invalid factory snapshot shape".into());
    }
    let roles = snapshot["roles"]
        .as_object()
        .ok_or("invalid factory roles")?;
    let selected = roles.get(role).ok_or("factory role not found")?;
    let contract = selected["contract_text"]
        .as_str()
        .ok_or("factory role contract is missing")?;
    let selected_harness = selected["harness"].as_str().unwrap_or("codex");
    if !simple_name(agent)
        || !simple_name(role)
        || selected["agent"] != agent
        || selected_harness != harness
        || selected["contract_bytes"].as_u64() != Some(contract.len() as u64)
        || selected["contract_sha256"] != sha256(contract.as_bytes())
    {
        return Err("factory role, harness or contract identity does not match".into());
    }
    if selected.get("args").is_some_and(|a| {
        a.as_array().is_none_or(|args| {
            args.iter()
                .any(|a| a.as_str().is_none_or(|a| a.contains('\0')))
        })
    }) {
        return Err("invalid factory harness arguments".into());
    }
    let mut role_agents = json!({});
    let mut repairs = json!({});
    for (name, entry) in roles {
        role_agents[name] = entry
            .get("agent")
            .ok_or("factory agent binding is missing")?
            .clone();
        if let Some(repair) = entry.get("repair") {
            repairs[name] = repair.clone();
        }
    }
    let mut canonical = serde_json::to_vec(&sorted_json(&snapshot))?;
    canonical.push(b'\n');
    let mut factory = serde_json::from_value::<Factory>(
        json!({"schema":snapshot["schema"],"name":snapshot["name"],"role":role,"roles":role_agents,"handoffs":snapshot["handoffs"],"operator_input":snapshot["operator_input"],"contract_sha256":sha256(contract.as_bytes()),"snapshot_id":sha256(&canonical),"updates":snapshot.get("updates").cloned().unwrap_or(json!([])),"repairs":repairs}),
    )?;
    for handoff in &mut factory.handoffs {
        if handoff.response_to.is_empty() {
            handoff.response_to.push(handoff.source.clone());
        }
    }
    let mut coordinators = Vec::new();
    for handoff in factory.handoffs.iter().filter(|h| h.request == "TASK") {
        let agent = &factory.roles[&handoff.source];
        if !coordinators.contains(agent) {
            coordinators.push(agent.clone());
        }
    }
    let config = Config {
        agent_name: agent.into(),
        agent_room: Some(format!("{agent}-agent")),
        rooms: vec![
            snapshot["room"]
                .as_str()
                .ok_or("factory room is missing")?
                .into(),
        ],
        coordinators,
        harness: harness.into(),
        factory: Some(factory),
        ..Config::default()
    };
    config.validate()?;
    let baseline = read_text(instructions)?;
    atomic_write(config_path, &serde_json::to_vec(&config)?, 0o600)?;
    atomic_write(
        instructions,
        format!(
            "{}\n\n---\n\n{}",
            baseline.trim_end(),
            contract.trim_start()
        )
        .as_bytes(),
        0o600,
    )
}

pub fn ordinary_stage(
    path: &Path,
    agent: &str,
    rooms: &str,
    coordinators: &str,
) -> Result<(), Error> {
    let names =
        |text: &str| -> Vec<String> { text.split(',').map(str::trim).map(str::to_owned).collect() };
    let config = Config {
        agent_name: agent.into(),
        rooms: names(rooms),
        coordinators: names(coordinators),
        ..Config::default()
    };
    config.validate()?;
    atomic_write(path, &serde_json::to_vec(&config)?, 0o600)
}

pub fn supervised_launcher(path: &Path, harness: &str) -> Result<(), Error> {
    let source = read_text(path)?;
    let (anchor, replacement) = match harness {
        "codex" => (
            "exec codex \"${args[@]}\" \"$@\"\n",
            "exec \"$HOME/.safeyolo/safeyolo-coord\" supervise -- \"${supervised_args[@]}\" \"$@\"\n",
        ),
        "pi" => (
            "exec \"$pi_bin\" \"${args[@]}\" \"$@\"\n",
            "export SAFEYOLO_PI_BIN=\"$pi_bin\"\nexec \"$HOME/.safeyolo/safeyolo-coord\" supervise -- \"${args[@]}\" \"$@\"\n",
        ),
        _ => return Err("unknown supervised harness".into()),
    };
    if source.matches(anchor).count() != 1 {
        return Err("cannot locate the harness foreground command".into());
    }
    atomic_write(
        path,
        source.replace(anchor, replacement).as_bytes(),
        fs::metadata(path)?.permissions().mode() & 0o7777,
    )
}

fn argument_text(argument: &std::ffi::OsStr) -> Result<&str, Error> {
    argument
        .to_str()
        .ok_or_else(|| "command names and text options must be UTF-8".into())
}

pub fn run(arguments: &[OsString]) -> Result<(), Error> {
    match arguments {
        [kind, rest @ ..] if kind == "codex-state" => {
            let mut home = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .ok_or("HOME is missing")?;
            let mut launcher = None;
            let mut local = false;
            let mut recovery = None;
            let mut args = rest.iter();
            while let Some(arg) = args.next() {
                match argument_text(arg)? {
                    "--home" => home = args.next().ok_or("--home requires a path")?.into(),
                    "--mcp-launcher" => {
                        launcher = Some(argument_text(args.next().ok_or("--mcp-launcher requires a path")?)?);
                    }
                    "--require-agent-local" => local = true,
                    "adopt" | "reset" => {
                        if recovery.replace(argument_text(arg)?).is_some() {
                            return Err("choose one Codex authentication action: adopt or reset".into());
                        }
                    }
                    _ => return Err("unknown codex-state argument".into()),
                }
            }
            codex_state(&home, launcher, local, recovery)
        }
        [kind,home,source] if kind=="stage-runtime"=>stage_runtime(Path::new(home),Path::new(source)),
        [kind,home,harness,rest @ ..] if kind=="stage-mcp"=>{
            if !rest.is_empty() && rest!=["--require-agent-local"] { return Err("unknown stage-mcp argument".into()); }
            stage_mcp(Path::new(home),argument_text(harness)?,!rest.is_empty())
        },
        [kind,config,instructions,agent,snapshot,role,harness] if kind=="factory-stage"=>factory_stage(Path::new(config),Path::new(instructions),argument_text(agent)?,Path::new(snapshot),argument_text(role)?,argument_text(harness)?),
        [kind,path,agent,rooms,coordinators] if kind=="ordinary-stage"=>ordinary_stage(Path::new(path),argument_text(agent)?,argument_text(rooms)?,argument_text(coordinators)?),
        [kind,path,harness] if kind=="supervised-launcher"=>supervised_launcher(Path::new(path),argument_text(harness)?),
        _=>Err("usage: safeyolo-coord codex-state|stage-mcp|factory-stage|ordinary-stage|supervised-launcher --help".into()),
    }
}
