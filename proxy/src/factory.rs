//! Operator-owned Factory entry. Coord and role checkpoints own work state.

use crate::{
    Error, agent_api::coord::OperatorCoord, coord_setup, coord_supervisor, host_agents, host_boot,
    host_lifecycle, host_platform,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub const HELP: &str = "safeyolo [--root ROOT] factory check FILE\nsafeyolo [--root ROOT] factory approve FILE [--yes]\nsafeyolo [--root ROOT] factory prepare NAME --workspace ROLE=PATH [--workspace ROLE=PATH ...] [--dangerously-allow-unowned]\nsafeyolo [--root ROOT] factory login NAME ROLE\nsafeyolo [--root ROOT] factory run NAME [--workspace ROLE=PATH ...]\nsafeyolo [--root ROOT] factory doctor|stop NAME\nsafeyolo [--root ROOT] factory send NAME TEXT\nsafeyolo [--root ROOT] factory history NAME [--since SEQUENCE]\nsafeyolo [--root ROOT] factory release NAME --target URL [--target URL ...] [--room ROOM] [--yes]\n\ncheck validates the contract. approve selects its immutable content; it does not start roles.\nprepare provisions declared agents, rooms and staging without starting a model. Each harness needs its own agent-local login.\nrun starts the approved roles and verifies their actual readiness. stop preserves identities, checkpoints and messages; run restarts that same state.\ndoctor is read-only and names the failed role or room. send targets the approved operator-input role. Direct agent diagnosis and recovery remain available.";

fn codex() -> String {
    "codex".into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    agent: String,
    #[serde(default = "codex")]
    harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repair: Option<coord_supervisor::Repair>,
    contract: String,
    contract_bytes: usize,
    contract_sha256: String,
    contract_text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    schema: String,
    pub(crate) name: String,
    pub(crate) room: String,
    roles: BTreeMap<String, Role>,
    handoffs: Vec<coord_supervisor::Handoff>,
    operator_input: coord_supervisor::OperatorInput,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    updates: Vec<coord_supervisor::Update>,
}

fn named(name: &str) -> Result<(), Error> {
    if !coord_supervisor::simple_name(name) || [".", ".."].contains(&name) {
        return Err("Factory and role names must be simple names".into());
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>, Error> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(format!("Factory input must be a regular file: {}", path.display()).into());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("Factory input exceeds the existing two MiB staging bound".into());
    }
    Ok(bytes)
}
impl Snapshot {
    fn validate(&self) -> Result<(), Error> {
        named(&self.name)?;
        named(&self.room)?;
        if self.roles.is_empty() {
            return Err("Factory roles are empty".into());
        }
        let mut agents = BTreeSet::new();
        let value = serde_json::to_value(self)?;
        for (name, role) in &self.roles {
            named(name)?;
            if !host_platform::valid_agent_name(&role.agent) {
                return Err(format!(
                    "role {name}: agent name does not match the native host naming rules"
                )
                .into());
            }
            if !agents.insert(&role.agent) {
                return Err("one agent is bound to more than one Factory role".into());
            }
            if self.room == format!("{}-agent", role.agent) {
                return Err(
                    "shared Factory room cannot replace a role's private agent room".into(),
                );
            }
            if role.contract.is_empty()
                || Path::new(&role.contract).is_absolute()
                || role.contract_bytes != role.contract_text.len()
                || role.contract_sha256 != coord_setup::sha256(role.contract_text.as_bytes())
            {
                return Err(
                    format!("role {name}: contract content identity does not match").into(),
                );
            }
            // Reuse the supervised guest's authoritative graph, argument and
            // role-binding validation instead of a second contract evaluator.
            coord_setup::factory_config(&value, &role.agent, name, &role.harness)?;
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes =
            serde_json::to_vec(&coord_setup::sorted_json(&serde_json::to_value(self)?))?;
        bytes.push(b'\n');
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("Factory snapshot exceeds the existing staging bound".into());
        }
        Ok(bytes)
    }
    fn id(&self) -> Result<String, Error> {
        Ok(coord_setup::sha256(&self.bytes()?))
    }
    pub(crate) fn agents(&self) -> Vec<String> {
        self.roles.values().map(|role| role.agent.clone()).collect()
    }
    fn operator_agent(&self) -> &str {
        &self.roles[&self.operator_input.to].agent
    }
}
fn load_file(path: &Path) -> Result<Snapshot, Error> {
    let path = path.canonicalize()?;
    let mut raw = crate::policy::parse_toml_document(std::str::from_utf8(&read(&path)?)?)?;
    let roles = raw["roles"]
        .as_object_mut()
        .ok_or("Factory roles must be a table")?;
    for (name, entry) in roles {
        let fields = entry
            .as_object_mut()
            .ok_or("Factory role must be a table")?;
        if fields
            .keys()
            .any(|key| !["agent", "harness", "args", "repair", "contract"].contains(&key.as_str()))
        {
            return Err(format!("role {name}: unknown contract field").into());
        }
        let source = fields
            .get("contract")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty() && !Path::new(p).is_absolute())
            .ok_or("role contract must be an explicit relative path")?;
        let text = String::from_utf8(read(
            &path
                .parent()
                .ok_or("Factory file has no parent")?
                .join(source)
                .canonicalize()?,
        )?)?;
        fields.insert("contract_bytes".into(), json!(text.len()));
        fields.insert(
            "contract_sha256".into(),
            json!(coord_setup::sha256(text.as_bytes())),
        );
        fields.insert("contract_text".into(), json!(text));
    }
    let mut snapshot: Snapshot = serde_json::from_value(raw)?;
    for handoff in &mut snapshot.handoffs {
        if handoff.response_to.is_empty() {
            handoff.response_to.push(handoff.source.clone());
        }
    }
    snapshot.validate()?;
    Ok(snapshot)
}
fn directory(root: &Path, name: &str) -> Result<PathBuf, Error> {
    named(name)?;
    for path in [
        root.join("factories"),
        root.join("factories").join(name),
        root.join("factories").join(name).join("snapshots"),
    ] {
        coord_setup::safe(&path, true, None)?;
    }
    Ok(root.join("factories").join(name))
}
fn approve(root: &Path, snapshot: &Snapshot) -> Result<PathBuf, Error> {
    let id = snapshot.id()?;
    let directory = directory(root, &snapshot.name)?;
    let snapshots = directory.join("snapshots");
    fs::create_dir_all(&snapshots)?;
    let path = snapshots.join(format!("{id}.json"));
    let bytes = snapshot.bytes()?;
    match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::File::open(&snapshots)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read(&path)? != bytes {
                return Err("immutable Factory snapshot collision".into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    coord_supervisor::atomic_write(
        &directory.join("approved"),
        format!("{id}\n").as_bytes(),
        0o600,
    )?;
    Ok(path)
}
pub(crate) fn approved(root: &Path, name: &str) -> Result<(Snapshot, PathBuf), Error> {
    let directory = directory(root, name)?;
    let pointer = String::from_utf8(read(&directory.join("approved"))?)?;
    load_snapshot(root, name, pointer.trim())
}
fn load_snapshot(root: &Path, name: &str, id: &str) -> Result<(Snapshot, PathBuf), Error> {
    let directory = directory(root, name)?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid approved Factory snapshot ID".into());
    }
    let path = directory.join("snapshots").join(format!("{id}.json"));
    let snapshot: Snapshot = serde_json::from_slice(&read(&path)?)?;
    snapshot.validate()?;
    if snapshot.name != name || snapshot.id()? != id {
        return Err("approved Factory snapshot content identity does not match".into());
    }
    Ok((snapshot, path))
}
fn describe(snapshot: &Snapshot) -> Result<(), Error> {
    println!(
        "factory={} room={} snapshot={}",
        snapshot.name,
        snapshot.room,
        snapshot.id()?
    );
    for (name, role) in &snapshot.roles {
        println!(
            "role={name} agent={} harness={} args={} contract={} bytes={} sha256={}",
            role.agent,
            role.harness,
            serde_json::to_string(&role.args)?,
            role.contract,
            role.contract_bytes,
            role.contract_sha256
        );
    }
    println!(
        "operator_input=operator to={} types={}",
        snapshot.operator_input.to,
        snapshot.operator_input.types.join(",")
    );
    Ok(())
}

#[derive(Default)]
struct Preparation {
    workspaces: BTreeMap<String, PathBuf>,
    allow_unowned: bool,
}
fn preparation(snapshot: &Snapshot, options: &[String]) -> Result<Preparation, Error> {
    let mut result = Preparation::default();
    let mut options = options.iter();
    while let Some(option) = options.next() {
        match option.as_str() {
            "--dangerously-allow-unowned" => result.allow_unowned = true,
            "--workspace" => {
                let value = options.next().ok_or("--workspace requires ROLE=PATH")?;
                let (role, path) = value
                    .split_once('=')
                    .ok_or("--workspace requires ROLE=PATH")?;
                if !snapshot.roles.contains_key(role) || result.workspaces.contains_key(role) {
                    return Err(format!("unknown or repeated workspace role: {role}").into());
                }
                result.workspaces.insert(role.into(), PathBuf::from(path));
            }
            _ => return Err(format!("unknown Factory preparation option: {option}").into()),
        }
    }
    for path in result.workspaces.values_mut() {
        *path = host_boot::workspace(path, result.allow_unowned)?;
    }
    Ok(result)
}
fn home(root: &Path, role: &Role) -> PathBuf {
    root.join("agents").join(&role.agent).join("home")
}
fn setup_script(root: &Path, harness: &str) -> Result<PathBuf, Error> {
    let path = root
        .join("assets/contrib")
        .join(format!("{harness}-coord-host-setup.sh"));
    if !path.is_file() || path.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "required role setup executable is missing: {}; reinstall native assets",
            path.display()
        )
        .into());
    }
    Ok(path)
}
async fn prepare_roles(
    root: &Path,
    snapshot: &Snapshot,
    path: &Path,
    options: &Preparation,
    require_login: bool,
) -> Result<(), Error> {
    let configured = host_agents::list()?;
    // Check all inputs before setup mutates the first role. Unknown live
    // ownership is preserved and never treated as a stopped role.
    for (name, role) in &snapshot.roles {
        setup_script(root, &role.harness)?;
        if let Some(agent) = configured.iter().find(|agent| agent.name == role.agent) {
            host_agents::by_id(&configured, &agent.id)?;
            let observed = host_lifecycle::runtime(agent).await?;
            if observed["runtime_state"] != "stopped" {
                return Err(format!(
                    "role {name} agent {} runtime={}; stop this role before staging",
                    role.agent, observed["runtime_state"]
                )
                .into());
            }
            let folder = options
                .workspaces
                .get(name)
                .cloned()
                .or_else(|| agent.folder.as_ref().map(PathBuf::from))
                .ok_or_else(|| format!("role {name}: supply --workspace {name}=PATH"))?;
            host_boot::workspace(
                &folder,
                options.allow_unowned || agent.dangerously_allow_unowned,
            )?;
        } else if !options.workspaces.contains_key(name) {
            return Err(format!(
                "role {name}: supply --workspace {name}=PATH to provision agent {}",
                role.agent
            )
            .into());
        }
    }
    for (name, role) in &snapshot.roles {
        let existing = configured.iter().find(|agent| agent.name == role.agent);
        let mut fields = vec![
            ("launcher".into(), "supervisor".into()),
            (
                "host_script".into(),
                setup_script(root, &role.harness)?
                    .to_str()
                    .ok_or("setup path must be UTF-8")?
                    .into(),
            ),
        ];
        if let Some(folder) = options.workspaces.get(name) {
            fields.push((
                "folder".into(),
                folder
                    .to_str()
                    .ok_or("workspace path must be UTF-8")?
                    .into(),
            ));
        }
        if options.allow_unowned {
            fields.push(("dangerously_allow_unowned".into(), "true".into()));
        }
        if let Some(args) = &role.args {
            fields.push(("user_default_args".into(), serde_json::to_string(args)?));
        }
        host_agents::configure(&role.agent, &fields, existing.is_none(), Some((path, name.as_str(), !require_login))).await.map_err(|error| format!("role {name} agent {} setup failed: {error}; use factory prepare and factory login for agent-local authentication", role.agent))?;
    }
    crate::coord_rooms::start(root, None, None, None).await?;
    crate::coord_rooms::ensure_factory_rooms(
        &host_platform::config_path(),
        &snapshot.room,
        &snapshot.agents(),
    )
    .await?;
    Ok(())
}
fn staged(root: &Path, snapshot: &Snapshot, role_name: &str, role: &Role) -> Result<(), Error> {
    let home = home(root, role);
    for directory in [&home, &home.join(".safeyolo")] {
        if !coord_setup::safe(directory, true, None)? {
            return Err("required Factory staging directory is missing".into());
        }
    }
    let config = coord_supervisor::Config::load(&home.join(".safeyolo/coord-supervisor.json")).map_err(|_| "staged role configuration is invalid; inspect its coord-supervisor.json inside the agent")?;
    let expected = coord_setup::factory_config(
        &serde_json::to_value(snapshot)?,
        &role.agent,
        role_name,
        &role.harness,
    )?;
    if serde_json::to_value(&config)? != serde_json::to_value(&expected)? {
        return Err("staged role configuration differs from the approved contract".into());
    }
    let baseline = read(&root.join("assets/docs/AGENTS.md"))?;
    let expected_instructions = format!(
        "{}\n\n---\n\n{}",
        std::str::from_utf8(&baseline)?.trim_end(),
        role.contract_text.trim_start()
    );
    if read(&home.join(".safeyolo/AGENTS.md"))? != expected_instructions.as_bytes() {
        return Err("staged role instructions differ from the approved contract".into());
    }
    let executable = home.join(".safeyolo/safeyolo-coord");
    if !coord_setup::safe(&executable, false, None)? {
        return Err(format!(
            "required role executable is missing: {}",
            executable.display()
        )
        .into());
    }
    let expected_size = root.join("assets/guest/safeyolo-coord").metadata()?.len();
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&executable)?;
    let metadata = file.metadata()?;
    let mut input = file.take(expected_size + 1);
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let observed: String = digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if metadata.len() != expected_size
        || metadata.permissions().mode() & 0o111 == 0
        || observed
            != String::from_utf8(read(&root.join("assets/guest/safeyolo-coord.sha256"))?)?.trim()
    {
        return Err("staged native role executable differs from the installed artifact".into());
    }
    if role.harness == "pi" {
        for directory in [
            home.join(".pi"),
            home.join(".pi/agent"),
            home.join(".pi/agent/extensions"),
        ] {
            if !coord_setup::safe(&directory, true, None)? {
                return Err("staged Pi Coord extension directory is missing".into());
            }
        }
    }
    if role.harness == "pi"
        && read(&home.join(".pi/agent/extensions/safeyolo-coord.ts"))?
            != read(&root.join("assets/contrib/pi-coord-extension.ts"))?
    {
        return Err("staged Pi Coord extension differs from the installed adapter".into());
    }
    staged_command(root, &home, &role.harness)
        .map_err(|error| format!("staged role command is invalid: {error}"))?;
    Ok(())
}

fn staged_command(root: &Path, home: &Path, harness: &str) -> Result<(), Error> {
    // Compare the complete launcher emitted by the installed setup script,
    // using the same transformation as setup, rather than shell substrings.
    let source = if harness == "codex" {
        String::from_utf8(read(&root.join("assets/contrib/codex-command.sh"))?)?
    } else {
        let template = String::from_utf8(read(
            &root.join(format!("assets/contrib/{harness}-host-setup.sh")),
        )?)?;
        template
            .split_once("<<'EOF'\n")
            .and_then(|(_, body)| body.split_once("\nEOF\n"))
            .map(|(body, _)| format!("{body}\n"))
            .ok_or("installed harness launcher template is missing")?
    };
    let expected = coord_setup::supervised_launcher_source(&source, harness)?;
    let entry = home.join(".safeyolo-command");
    let executable = |path: &Path| -> Result<Vec<u8>, Error> {
        if !coord_setup::safe(path, false, None)?
            || fs::metadata(path)?.permissions().mode() & 0o111 == 0
        {
            return Err(format!("missing or non-executable {}", path.display()).into());
        }
        read(path)
    };
    let command = executable(&entry)?;
    if command == crate::guest_commands::WRAPPER {
        let payload = home.join(".safeyolo-command.payload");
        if executable(&payload)? != expected.as_bytes() {
            return Err("wrapped payload differs from the installed supervised launcher".into());
        }
        let share = home
            .parent()
            .ok_or("agent directory is missing")?
            .join("config-share");
        if !coord_setup::safe(&share, true, None)? {
            return Err("wrapped command launch context is missing".into());
        }
        let context: Value =
            serde_json::from_slice(&read(&share.join("host-launch-context.json"))?)?;
        if context["command_payloads"][".safeyolo-command"]
            != crate::guest_commands::payload_identity(&payload)?
        {
            return Err("wrapped command payload identity differs from its launch context".into());
        }
    } else if command != expected.as_bytes() {
        return Err(
            "entry differs from the installed supervised launcher or native wrapper".into(),
        );
    }
    Ok(())
}
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}
fn staged_binding(root: &Path, agent: &Role) -> Result<Value, Error> {
    let home = home(root, agent);
    for directory in [&home, &home.join(".safeyolo")] {
        coord_setup::safe(directory, true, None)?;
    }
    let config = coord_supervisor::Config::load(&home.join(".safeyolo/coord-supervisor.json")).map_err(|_| "staged role configuration is invalid; inspect its coord-supervisor.json inside the agent")?;
    let binding = config.factory.ok_or("staged role has no Factory binding")?;
    let (snapshot, _) = load_snapshot(root, &binding.name, &binding.snapshot_id)?;
    let role = snapshot
        .roles
        .get(&binding.role)
        .ok_or("staged role is absent from its snapshot")?;
    if role.agent != agent.agent {
        return Err("staged Factory agent identity differs".into());
    }
    staged(root, &snapshot, &binding.role, role)?;
    Ok(
        json!({"factory":snapshot.name,"room":snapshot.room,"role":binding.role,"agent":role.agent,"harness":role.harness,"snapshot":snapshot.id()?}),
    )
}
async fn guest_preflight(role: &Role, args: &[String]) -> Result<(), Error> {
    let command = format!(
        "export CODEX_HOME=/home/agent/.codex; /home/agent/.safeyolo/safeyolo-coord preflight -- {}",
        args.iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let child =
        host_platform::spawn_guest_command_with_output(&role.agent, &command, true, false).await?;
    let result = tokio::time::timeout(Duration::from_secs(40), child.wait_with_output())
        .await
        .map_err(|_| "role preflight did not finish; inspect agent diagnostics")??;
    if !result.status.success() {
        return Err(format!(
            "guest harness executable, login or Coord preflight failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(())
}

async fn doctor(root: &Path, snapshot: &Snapshot) -> Result<Value, Error> {
    let mut checks = Vec::new();
    checks.push(json!({"component":"snapshot","status":"PASS","snapshot":snapshot.id()?}));
    checks.push(json!({"component":"proxy","status":if crate::host_commands::proxy_live() {"PASS"} else {"FAIL"},"recovery":"safeyolo start"}));
    let nats = crate::coord_rooms::status(root).await;
    checks.push(match nats { Ok(value) => json!({"component":"coord-nats","status":if value["state"]=="running" {"PASS"} else {"FAIL"},"observation":value}), Err(error) => json!({"component":"coord-nats","status":"FAIL","error":error.to_string()}) });
    let configured = host_agents::list()?;
    let approvals = crate::native_client::admin(
        &host_platform::config_path(),
        "/admin/approvals",
        hyper::Method::GET,
        Value::Null,
        Duration::from_secs(5),
    )
    .await;
    checks.push(match approvals {
        Ok(value) if value["approvals"].is_array() => {
            let count = value["approvals"].as_array().unwrap().iter().filter(|approval| snapshot.roles.values().any(|role| approval["agent"] == role.agent)).count();
            json!({"component":"operator-approvals","status":if count == 0 {"PASS"} else {"WARN"},"pending_count":count,"recovery":"Inspect approvals pending for the named Factory agents. A pending decision is not an instruction to approve and does not block Factory readiness."})
        },
        Ok(_) => json!({"component":"operator-approvals","status":"WARN","error":"pending approvals response is malformed; current decisions are unverified"}),
        Err(error) => json!({"component":"operator-approvals","status":"WARN","error":error.to_string(),"recovery":"Pending decisions are unverified; use the native approval commands when the Admin route is available."}),
    });
    for (name, role) in &snapshot.roles {
        let binding = staged_binding(root, role);
        let runtime = match configured.iter().find(|agent| agent.name == role.agent) {
            Some(agent) => host_lifecycle::runtime(agent).await.unwrap_or_else(
                |error| json!({"runtime_state":"unknown","error":error.to_string()}),
            ),
            None => json!({"runtime_state":"missing"}),
        };
        let observation = async {
            let agent = configured.iter().find(|agent| agent.name==role.agent).ok_or("required role agent is missing")?;
            host_agents::by_id(&configured, &agent.id)?;
            let staged = binding.as_ref().map_err(|error| error.to_string())?;
            if staged["snapshot"] != snapshot.id()? || staged["role"] != *name || staged["agent"] != role.agent || staged["harness"] != role.harness {
                return Err("staged role configuration differs from the approved contract; stop the roles before staging that selection".into());
            }
            crate::coord_rooms::factory_access(root, &snapshot.room, &agent.id)?;
            crate::coord_rooms::factory_access(root, &format!("{}-agent", role.agent), &agent.id)?;
            if runtime["runtime_state"] != "running" || runtime["agent_state"] != "running" || runtime["proxy_attachment"]["state"] != "ready" { return Err(format!("role runtime is not ready: {runtime}").into()); }
            let state = home(root, role).join(".safeyolo/coord-supervisor-state.json");
            coord_supervisor::inspect(&state)?;
            guest_preflight(role, role.args.as_deref().unwrap_or(&agent.user_default_args)).await?;
            Ok::<_, Error>(json!({"agent_id":agent.id,"runtime":runtime,"checkpoint":coord_supervisor::inspect(&state)?}))
        }.await;
        checks.push(match observation { Ok(value) => json!({"component":"role","role":name,"agent":role.agent,"status":"PASS","staged_binding":binding.as_ref().ok(),"observation":value}), Err(error) => json!({"component":"role","role":name,"agent":role.agent,"runtime":runtime,"staged_binding":binding.as_ref().ok(),"status":"FAIL","error":error.to_string(),"recovery":format!("inspect agent diagnostics {}; correct the named input, then factory run {}",role.agent,snapshot.name)}) });
    }
    let ready = checks.iter().all(|check| check["status"] != "FAIL");
    Ok(
        json!({"factory":snapshot.name,"status":if ready {"ready"} else {"not-ready"},"checks":checks}),
    )
}
fn role_lifecycle_error(observation: &Value) -> Option<&Value> {
    // A healthy supervisor reports an empty last_stderr through this field.
    observation
        .get("error")
        .filter(|error| !error.is_null() && error.as_str() != Some(""))
}

async fn start_roles(root: &Path, snapshot: &Snapshot) -> Result<Value, Error> {
    let agents = host_agents::list()?;
    for (name, role) in &snapshot.roles {
        let agent = agents
            .iter()
            .find(|a| a.name == role.agent)
            .ok_or("required role is missing")?;
        staged(root, snapshot, name, role)?;
        crate::coord_rooms::factory_access(root, &snapshot.room, &agent.id)?;
        crate::coord_rooms::factory_access(root, &format!("{}-agent", role.agent), &agent.id)?;
    }
    for (name, role) in &snapshot.roles {
        let agent = agents
            .iter()
            .find(|a| a.name == role.agent)
            .ok_or("required role is missing")?;
        let observation =
            host_lifecycle::start(agent, "start", None, role.args.as_deref(), false).await?;
        if let Some(error) = role_lifecycle_error(&observation) {
            return Err(
                format!("role {name} start failed: {error}; existing role state retained").into(),
            );
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let report = doctor(root, snapshot).await?;
        if report["status"] == "ready" {
            return Ok(report);
        }
        if tokio::time::Instant::now() >= deadline {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Err("Factory did not become ready; inspect factory doctor. Started roles and checkpoints are preserved".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
async fn stop_roles(snapshot: &Snapshot) -> Result<(), Error> {
    let agents = host_agents::list()?;
    let mut errors = Vec::new();
    for (name, role) in &snapshot.roles {
        if let Some(agent) = agents.iter().find(|a| a.name == role.agent) {
            match host_lifecycle::stop(agent, None).await {
                Ok(value) if role_lifecycle_error(&value).is_none() => {}
                Ok(value) => errors.push(format!("role {name}: {value}")),
                Err(error) => errors.push(format!("role {name}: {error}")),
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; ").into());
    }
    println!(
        "Stopped Factory {} roles; approved contract, identities, checkpoints and room history retained",
        snapshot.name
    );
    Ok(())
}
async fn login(snapshot: &Snapshot, name: &str) -> Result<(), Error> {
    let role = snapshot.roles.get(name).ok_or("unknown Factory role")?;
    let agents = host_agents::list()?;
    let agent = agents
        .iter()
        .find(|agent| agent.name == role.agent)
        .ok_or("role is not prepared; run factory prepare first")?;
    if host_lifecycle::runtime(agent).await?["runtime_state"] != "stopped" {
        return Err("stop this role before Factory login; its current work is preserved".into());
    }
    let started = host_lifecycle::start(agent, "sandbox-start", None, None, false).await?;
    if started.get("error").is_some_and(|value| !value.is_null()) {
        return Err(format!("login sandbox failed: {started}").into());
    }
    let result = async {
        let command = if role.harness == "codex" {
            "/home/agent/.safeyolo-interactive-command login --device-auth && /home/agent/.safeyolo/safeyolo-coord codex-state adopt".into()
        } else {
            println!("Use Pi /login for the selected provider, then exit. Only this role's home is used.");
            format!("/home/agent/.safeyolo-interactive-command {}", role.args.as_deref().unwrap_or(&agent.user_default_args).iter().map(|arg| shell_quote(arg)).collect::<Vec<_>>().join(" "))
        };
        let mut child = host_platform::spawn_guest_command(&role.agent, &command, true).await?;
        if !child.wait().await?.success() { return Err("role login or adoption failed; agent-local files retained".into()); }
        Ok::<_,Error>(())
    }.await;
    host_lifecycle::stop(agent, None).await?;
    result
}
async fn release(
    root: &Path,
    snapshot: &Snapshot,
    room: &str,
    targets: &[String],
    yes: bool,
) -> Result<(), Error> {
    // Validate the selection even when every checkpoint is empty.
    coord_supervisor::release_preview(
        serde_json::to_value(coord_supervisor::State::default())?,
        room,
        targets,
    )?;
    let mut plans = Vec::new();
    let mut locks = Vec::new();
    let agents = host_agents::list()?;
    for role in snapshot.roles.values() {
        let agent = agents
            .iter()
            .find(|agent| agent.name == role.agent)
            .ok_or("required Factory agent is not registered")?;
        let path = home(root, role).join(".safeyolo/coord-supervisor-state.json");
        for directory in [home(root, role), home(root, role).join(".safeyolo")] {
            coord_setup::safe(&directory, true, None)?;
        }
        if !coord_setup::safe(&path, false, None)? {
            continue;
        }
        coord_setup::safe(
            &path.with_file_name("coord-supervisor-state.json.lock"),
            false,
            None,
        )?;
        locks.push(coord_supervisor::lock_state(&path)?);
        let state = coord_supervisor::State::load(&path)?;
        let before = serde_json::to_value(&state)?;
        let next = coord_supervisor::release_preview(before.clone(), room, targets)?;
        if serde_json::to_value(&next)? == before {
            continue;
        }
        if host_lifecycle::runtime(agent).await?["runtime_state"] != "stopped" {
            return Err(format!(
                "agent {} has selected work and is running; stop it before release",
                role.agent
            )
            .into());
        }
        println!(
            "agent={} in_flight={} awaiting_handoffs={}",
            role.agent,
            state.in_flight.len() - next.in_flight.len(),
            state.awaiting_handoffs.len() - next.awaiting_handoffs.len()
        );
        plans.push((role.agent.clone(), path.clone(), read(&path)?, next));
    }
    if plans.is_empty() {
        println!("No matching checkpointed work; nothing changed");
        return Ok(());
    }
    for target in targets {
        println!("target={target}");
    }
    if !yes {
        confirm("Release only these stopped-work records? [y/N] ")?;
    }
    let operation = uuid::Uuid::new_v4().simple().to_string();
    let mut backups = Vec::new();
    for (_, path, original, _) in &plans {
        let backup = path.with_file_name(format!(
            "coord-supervisor-state.before-release-{operation}.json"
        ));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&backup)?;
        file.write_all(original)?;
        file.sync_all()?;
        backups.push(backup);
    }
    let mut changed = Vec::new();
    let operator = OperatorCoord::open(&host_platform::config_path())?;
    let result = async {
        operator.send(
            room,
            &format!(
                "Factory work release requested. operation_id={operation}\nfactory={} targets={}",
                snapshot.name,
                targets.join(",")
            ),
            "text/plain",
            json!([]),
        )
        .await?;
        for (agent, path, original, next) in &plans {
            if read(path)? != *original {
                return Err(format!("checkpoint changed for {agent}; inspect and retry").into());
            }
            next.save(path)?;
            changed.push(agent.clone());
        }
        operator.send(
            room,
            &format!(
                "Factory work release completed. operation_id={operation}\nfactory={} targets={}",
                snapshot.name,
                targets.join(",")
            ),
            "text/plain",
            json!([]),
        )
        .await?;
        Ok::<_, Error>(())
    }
    .await;
    operator.shutdown().await;
    if let Err(error) = result {
        return Err(format!("release {operation} did not finish: {error}; changed agents={}; keep affected agents stopped and inspect checkpoints. Backups: {}", changed.join(","), backups.iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")).into());
    }
    println!(
        "Released checkpointed work for {}; files, duplicate detection and Coord history retained. operation_id={operation}",
        changed.join(",")
    );
    for backup in backups {
        println!("backup={}", backup.display());
    }
    Ok(())
}
fn confirm(prompt: &str) -> Result<(), Error> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !["y", "yes"].contains(&input.trim().to_ascii_lowercase().as_str()) {
        return Err("Factory operation cancelled".into());
    }
    Ok(())
}
pub async fn run(config: &Path, args: &[String]) -> Result<(), Error> {
    if args.is_empty() || args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let parent = config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()?;
    let config = parent.join(config.file_name().ok_or("configuration has no filename")?);
    host_platform::in_config(config, async {
        let root = host_platform::config_dir();
        match args {
            [kind,file,rest @ ..] if kind=="check" || kind=="approve" => {
                if kind=="check" && !rest.is_empty() || kind=="approve" && !rest.is_empty() && rest!=["--yes"] { return Err("usage: factory check FILE | approve FILE [--yes]".into()); }
                let snapshot = load_file(Path::new(file))?;
                describe(&snapshot)?;
                if kind=="approve" { if rest.is_empty() { confirm("Approve this exact Factory contract? [y/N] ")?; } let path=approve(&root,&snapshot)?; println!("Approved snapshot={}.json at {}; roles have not been started",snapshot.id()?,path.display()); }
                Ok(())
            }
            [kind,name,options @ ..] if kind=="prepare" || kind=="run" => {
                let (snapshot,path) = approved(&root,name)?;
                let choices = preparation(&snapshot,options)?;
                if kind=="prepare" {
                    prepare_roles(&root,&snapshot,&path,&choices,false).await?;
                    println!("Prepared Factory {}; no models started. Establish each role's own authentication: factory login {} ROLE. Then factory run {}",name,name,name);
                } else {
                    let configured=host_agents::list()?;
                    let any_live = futures_util::future::join_all(configured.iter().filter(|agent| snapshot.roles.values().any(|role| role.agent==agent.name)).map(host_lifecycle::runtime)).await.into_iter().any(|r| r.is_ok_and(|v| v["runtime_state"]!="stopped"));
                    if any_live {
                        if !options.is_empty() { return Err("stop the Factory roles before changing preparation choices".into()); }
                        for (role_name,role) in &snapshot.roles { staged(&root,&snapshot,role_name,role)?; }
                    } else { prepare_roles(&root,&snapshot,&path,&choices,true).await?; }
                    let report=start_roles(&root,&snapshot).await?;
                    println!("{}",serde_json::to_string_pretty(&report)?);
                    println!("Started Factory {name}; observed all approved roles ready");
                }
                Ok(())
            }
            [kind,name] if kind=="doctor" || kind=="stop" => {
                let (snapshot,_) = approved(&root,name)?;
                if kind=="stop" { return stop_roles(&snapshot).await; }
                let report=doctor(&root,&snapshot).await?;
                println!("{}",serde_json::to_string_pretty(&report)?);
                if report["status"]!="ready" { return Err("Factory is not ready; correct the named component".into()); }
                Ok(())
            }
            [kind,name,role] if kind=="login" => { let(snapshot,_)=approved(&root,name)?; login(&snapshot,role).await }
            [kind,name,text] if kind=="send" => {
                let(snapshot,_)=approved(&root,name)?;
                let operator = OperatorCoord::open(&host_platform::config_path())?;
                let result = operator.send(&snapshot.room, text, "text/plain", json!([snapshot.operator_agent()])).await;
                operator.shutdown().await;
                println!("{}",serde_json::to_string_pretty(&result?)?); Ok(())
            }
            [kind,name,options @ ..] if kind=="history" => {
                let(snapshot,_)=approved(&root,name)?;
                let since=match options { []=>0, [flag,sequence] if flag=="--since"=>sequence.parse()?, _=>return Err("usage: factory history NAME [--since SEQUENCE]".into()) };
                let operator = OperatorCoord::open(&host_platform::config_path())?;
                let (_cancel, cancellation) = tokio::sync::watch::channel(false);
                let result = operator.read(&snapshot.room, since, 200, false, cancellation).await;
                operator.shutdown().await;
                println!("{}",serde_json::to_string_pretty(&result?)?); Ok(())
            }
            [kind,name,options @ ..] if kind=="release" => {
                let(snapshot,_)=approved(&root,name)?;
                let mut targets=Vec::new(); let mut yes=false; let mut room=snapshot.room.clone(); let mut options=options.iter();
                while let Some(option)=options.next() { match option.as_str() { "--yes"=>yes=true,"--room"=>room=options.next().ok_or("--room requires a name")?.clone(),"--target"=>targets.push(options.next().ok_or("--target requires a URL")?.clone()),_=>return Err("usage: factory release NAME --target URL [--room ROOM] [--yes]".into()) } }
                named(&room)?;
                let agents=host_agents::list()?;
                // Hold every role's existing setup lock in sorted name order,
                // then prove stopped before editing any checkpoint.
                let mut selected:Vec<_>=agents.iter().filter(|a|snapshot.roles.values().any(|r|r.agent==a.name)).collect(); selected.sort_by(|a,b|a.name.cmp(&b.name));
                if selected.len()!=snapshot.roles.len() { return Err("required Factory agent is not registered".into()); }
                let mut locks=Vec::new();
                for agent in &selected { let directory=root.join("agents").join(&agent.name); locks.push(tokio::task::spawn_blocking(move||host_lifecycle::SetupLock::acquire_in(&directory,None)).await??); }
                release(&root,&snapshot,&room,&targets,yes).await
            }
            _=>Err("usage: safeyolo factory --help".into()),
        }
    }).await
}

#[cfg(test)]
mod tests;
