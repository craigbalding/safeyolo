//! Configured agents in the host-owned policy.toml.

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde_json::{Value, json};
use toml_edit::{DocumentMut, Item, value};

use crate::Error;

#[derive(Clone, serde::Serialize)]
pub(crate) struct Agent {
    pub(crate) name: String,
    pub(crate) id: String,
    pub(crate) folder: Option<String>,
    pub(crate) launcher: Option<String>,
    pub(crate) host_script: Option<String>,
    pub(crate) memory_mb: Option<i64>,
    pub(crate) rootfs_overlay: Option<String>,
    pub(crate) nested_docker: bool,
    pub(crate) user_default_args: Vec<String>,
    pub(crate) mounts: Vec<String>,
    pub(crate) dangerously_allow_unowned: bool,
}

impl Agent {
    fn from_item(name: String, item: &Item) -> Result<Self, Error> {
        let table = item
            .as_table_like()
            .ok_or("agent metadata must be a TOML table")?;
        for key in [
            "agent_id",
            "folder",
            "launcher",
            "host_script",
            "rootfs_overlay",
        ] {
            if table.get(key).is_some_and(|item| item.as_str().is_none()) {
                return Err(format!("agent {key} must be a string").into());
            }
        }
        if table
            .get("memory_mb")
            .is_some_and(|item| item.as_integer().is_none_or(|value| value <= 0))
        {
            return Err("agent memory_mb must be a positive integer".into());
        }
        for key in ["dangerously_allow_unowned", "nested_docker"] {
            if table.get(key).is_some_and(|item| item.as_bool().is_none()) {
                return Err(format!("{key} must be a Boolean").into());
            }
        }
        let string = |key| table.get(key).and_then(Item::as_str).map(str::to_owned);
        let integer = |key| table.get(key).and_then(Item::as_integer);
        let strings = |key| -> Result<Vec<String>, Error> {
            let Some(item) = table.get(key) else {
                return Ok(Vec::new());
            };
            let array = item
                .as_array()
                .ok_or("agent list metadata must be an array")?;
            array
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "agent list metadata must contain strings".into())
                })
                .collect()
        };
        Ok(Self {
            name,
            id: string("agent_id").ok_or("agent identity is missing")?,
            folder: string("folder"),
            launcher: string("launcher"),
            host_script: string("host_script"),
            memory_mb: integer("memory_mb"),
            rootfs_overlay: string("rootfs_overlay"),
            nested_docker: table
                .get("nested_docker")
                .and_then(Item::as_bool)
                .unwrap_or(false),
            user_default_args: strings("user_default_args")?,
            mounts: strings("mounts")?,
            dangerously_allow_unowned: table
                .get("dangerously_allow_unowned")
                .and_then(Item::as_bool)
                .unwrap_or(false),
        })
    }
}

pub(crate) fn policy_path() -> Result<PathBuf, Error> {
    let path = crate::host_platform::config_path();
    if path.is_file() {
        return crate::native_config::read(&path)?
            .policy_file
            .ok_or_else(|| "policy_file is missing".into());
    }
    Ok(crate::host_platform::config_dir().join("policy.toml"))
}

fn read_document(path: &Path) -> Result<DocumentMut, Error> {
    let source = match std::fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(DocumentMut::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(DocumentMut::from_str(&source)?)
}

fn save_document(path: &Path, document: &DocumentMut) -> Result<(), Error> {
    let parent = path.parent().ok_or("policy file has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(document.to_string().as_bytes())?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_document(path: &Path, document: &DocumentMut) -> Result<crate::policy::Policy, Error> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().ok_or("policy has no parent")?)?;
    temporary.write_all(document.to_string().as_bytes())?;
    Ok(crate::policy::Policy::from_native_path(temporary.path())?)
}

/// Add and update both express desired saved intent at one guest destination.
fn edit_mounts(item: &mut Item, destination: &str, desired: Option<&str>) -> Result<(), Error> {
    let mut mounts = match item.get("mounts") {
        Some(value) => value
            .as_array()
            .ok_or("agent mounts must be an array")?
            .clone(),
        None => toml_edit::Array::new(),
    };
    let mut selected = Vec::new();
    for (index, entry) in mounts.iter().enumerate() {
        if crate::host_boot::mount_destination(
            entry.as_str().ok_or("agent mounts must contain strings")?,
        )? == destination
        {
            selected.push(index);
        }
    }
    if let Some(desired) = desired {
        if let Some(first) = selected.first().copied() {
            mounts.replace(first, desired);
            for index in selected.into_iter().skip(1).rev() {
                mounts.remove(index);
            }
        } else {
            mounts.push(desired);
        }
    } else {
        for index in selected.into_iter().rev() {
            mounts.remove(index);
        }
    }
    item["mounts"] = value(mounts);
    Ok(())
}

pub(crate) async fn saved_mount(
    selected: &Agent,
    operation: &str,
    operand: &str,
) -> Result<Value, Error> {
    let directory = crate::host_platform::config_dir()
        .join("agents")
        .join(&selected.name);
    let _setup = tokio::task::spawn_blocking(move || {
        crate::host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    let path = policy_path()?;
    let lock_path = path.clone();
    let _policy =
        tokio::task::spawn_blocking(move || crate::approvals::lock_policy(&lock_path)).await??;
    let agent = refresh(selected)?;
    let (destination, desired) = match operation {
        "add" | "update" => {
            let (_, destination, _) = crate::host_boot::mount(operand)?;
            (destination, Some(operand))
        }
        "remove" => (crate::host_boot::guest_mount_destination(operand)?, None),
        _ => return Err(
            "use agent mounts add|update NAME HOST:GUEST[:ro], or agent mounts remove NAME GUEST"
                .into(),
        ),
    };
    let mut document = read_document(&path)?;
    let before = document.to_string();
    edit_mounts(&mut document["agents"][&agent.name], &destination, desired)?;
    let saved = Agent::from_item(agent.name.clone(), &document["agents"][&agent.name])?;
    crate::host_boot::validate(&saved)?;
    validate_document(&path, &document)?;
    let changed = before != document.to_string();
    if changed {
        save_document(&path, &document)?;
    }
    let observed = crate::host_lifecycle::runtime(&saved).await?;
    Ok(
        json!({"ok":true,"operation":operation,"root":crate::host_platform::config_dir(),
        "agent":saved.name,"agent_id":saved.id,"destination":destination,
        "saved_configuration_changed":changed,"saved_mounts":saved.mounts,
        "live_mounts":observed["live_mounts"],"runtime_state":observed["runtime_state"],
        "effective_configuration":observed["effective_configuration"],
        "next_start_configuration":observed["next_start_configuration"],
        "scope":"saved configuration only; the current sandbox is unchanged. The next explicit start uses saved mounts."}),
    )
}

/// Caller holds the selected agent's setup lock through final publication.
pub(crate) async fn remove_definition(selected: &Agent, apply: bool) -> Result<(), Error> {
    let path = policy_path()?;
    let lock_path = path.clone();
    let _policy =
        tokio::task::spawn_blocking(move || crate::approvals::lock_policy(&lock_path)).await??;
    refresh(selected)?;
    let mut document = read_document(&path)?;
    document["agents"]
        .as_table_like_mut()
        .ok_or("agents table is missing")?
        .remove(&selected.name);
    validate_document(&path, &document).map_err(|error| format!("cannot remove agent {}: {error}. Resolve named approval dependencies with configure approvals before retrying retirement", selected.name))?;
    if apply {
        save_document(&path, &document)?;
    }
    Ok(())
}

/// Inventory only the local owners already available to this host command.
pub(crate) fn retained_references(agent: &Agent) -> Value {
    let policy = (|| -> Result<Value, Error> {
        let policy = crate::policy::Policy::from_native_path(&policy_path()?)?;
        let support = policy
            .support_grants()
            .into_iter()
            .filter_map(|(name, grant)| {
                (grant.support.agent_id == agent.id
                    || grant
                        .targets
                        .iter()
                        .any(|target| target.agent_id == agent.id))
                .then_some(name)
            })
            .collect::<Vec<_>>();
        let delegations = policy
            .delegations()
            .iter()
            .filter_map(|(name, delegation)| {
                (delegation
                    .reviewers
                    .iter()
                    .filter_map(|reviewer| reviewer.local_agent())
                    .chain(delegation.beneficiaries.iter().cloned())
                    .any(|entry| entry.agent_id == agent.id))
                .then_some(name)
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"state":"observed","support_grants":support,"approval_delegations":delegations,
            "note":"Support grants remain saved and may become inactive when this identity is removed. Approval dependencies must be changed explicitly before retirement."}),
        )
    })();
    let root = crate::host_platform::config_dir();
    json!({"policy":reference_result(policy),
        "factories":reference_result(crate::factory::agent_references(&root, &agent.name)),
        "coord":reference_result(crate::coord_rooms::agent_references(&root, &agent.id)),
        "credentials":{"state":"unknown","reason":"Credential metadata is not open in this local command. Retirement does not create or unlock storage. Inspect credential bindings through the existing credentials owner."},
        "scope":"Local owner observations at preview time; remote references are unknown. These records are retained, not revoked or reassigned by retirement."})
}

fn reference_result(result: Result<Value, Error>) -> Value {
    result.unwrap_or_else(|error| json!({"state":"unknown","error":error.to_string()}))
}

/// Local operator configuration only. Executables and arguments are never
/// accepted by the remote lifecycle API.
pub(crate) async fn configure(
    name: &str,
    options: &[(String, String)],
    create: bool,
    factory: Option<(&Path, &str, bool)>,
) -> Result<Agent, Error> {
    configure_with_host_state(name, options, create, factory, None).await
}

/// The first-launch host prompt supplies a scoped choice. Existing explicit
/// host-script callers keep their current staging behavior.
pub(crate) async fn configure_with_host_state(
    name: &str,
    options: &[(String, String)],
    create: bool,
    factory: Option<(&Path, &str, bool)>,
    copy_host_state: Option<bool>,
) -> Result<Agent, Error> {
    if !crate::host_platform::valid_agent_name(name) {
        return Err("invalid agent name".into());
    }
    let directory = crate::host_platform::config_dir().join("agents").join(name);
    let _setup = tokio::task::spawn_blocking(move || {
        crate::host_lifecycle::SetupLock::acquire_in(&directory, None)
    })
    .await??;
    let path = policy_path()?;
    let lock_path = path.clone();
    let _lock =
        tokio::task::spawn_blocking(move || crate::approvals::lock_policy(&lock_path)).await??;
    let mut document = read_document(&path)?;
    let exists = document
        .get("agents")
        .and_then(Item::as_table_like)
        .is_some_and(|agents| agents.contains_key(name));
    if create == exists {
        return Err(if create {
            "agent already exists"
        } else {
            "agent not found"
        }
        .into());
    }
    if !exists {
        document["agents"][name]["agent_id"] =
            value(format!("ag-{}", uuid::Uuid::new_v4().simple()));
    }
    for (key, text) in options {
        document["agents"][name][key.as_str()] = match key.as_str() {
            "folder" => value(
                crate::host_boot::workspace(
                    Path::new(text),
                    options
                        .iter()
                        .any(|(key, value)| key == "dangerously_allow_unowned" && value == "true")
                        || document["agents"][name]
                            .get("dangerously_allow_unowned")
                            .and_then(Item::as_bool)
                            == Some(true),
                )?
                .to_string_lossy()
                .as_ref(),
            ),
            "memory_mb" => {
                let memory: i64 = text.parse()?;
                if memory <= 0 {
                    return Err("agent memory_mb must be positive".into());
                }
                value(memory)
            }
            "dangerously_allow_unowned" | "nested_docker" => value(text.parse::<bool>()?),
            "mounts" => {
                let (_, destination, _) = crate::host_boot::mount(text)?;
                edit_mounts(&mut document["agents"][name], &destination, Some(text))?;
                continue;
            }
            "user_default_args" => {
                let args: Vec<String> = serde_json::from_str(text)?;
                let mut array = toml_edit::Array::new();
                for arg in args {
                    array.push(arg);
                }
                value(array)
            }
            "launcher" | "host_script" | "rootfs_overlay" => value(text.as_str()),
            _ => return Err(format!("unsupported agent setting: {key}").into()),
        };
    }
    let agent = Agent::from_item(name.into(), &document["agents"][name])?;
    crate::host_boot::validate(&agent)?;
    // Validate the complete policy before atomic publication, so rejected
    // configuration leaves the saved document and running policy intact.
    validate_document(&path, &document)?;
    if options.iter().any(|(key, _)| key == "host_script") {
        if crate::host_runs::observe(name).await["runtime_state"] != "stopped" {
            return Err("stop the agent before applying a host setup script; saved configuration is unchanged".into());
        }
        crate::host_boot::setup(&agent, factory, copy_host_state).await?;
    }
    save_document(&path, &document)?;
    Ok(agent)
}

/// Read configured host agents from the atomic native policy snapshot.
/// Policy-only overrides do not create host agents. Fresh creation owns ID
/// assignment; status does not migrate or rewrite configuration.
pub(crate) fn list() -> Result<Vec<Agent>, Error> {
    let document = read_document(&policy_path()?)?;
    let mut agents = Vec::new();
    if let Some(table) = document.get("agents").and_then(Item::as_table_like) {
        for (name, item) in table.iter() {
            let fields = item
                .as_table_like()
                .ok_or_else(|| format!("agent {name}: metadata must be a TOML table"))?;
            let host_settings = [
                "agent_id",
                "folder",
                "launcher",
                "host_script",
                "memory_mb",
                "rootfs_overlay",
                "nested_docker",
                "user_default_args",
                "mounts",
                "dangerously_allow_unowned",
                "network_slot",
                "tailnet_port",
            ]
            .iter()
            .any(|key| fields.contains_key(key));
            // Retained incarnation evidence also identifies a host record if
            // its configuration was damaged. Do not hide it as a policy entry.
            if !host_settings
                && !crate::host_runs::path(name).try_exists()?
                && !crate::host_platform::config_dir()
                    .join("agents")
                    .join(name)
                    .join("config-share/host-launch-context.json")
                    .try_exists()?
            {
                continue;
            }
            agents.push(
                Agent::from_item(name.into(), item)
                    .map_err(|error| format!("agent {name}: {error}"))?,
            );
        }
    }
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(agents)
}

/// An operation must not choose between names sharing a durable identity.
pub(crate) fn by_id<'a>(agents: &'a [Agent], id: &str) -> Result<Option<&'a Agent>, Error> {
    let mut matching = agents.iter().filter(|agent| agent.id == id);
    let selected = matching.next();
    if let (Some(selected), Some(other)) = (selected, matching.next()) {
        return Err(format!(
            "agent {}: durable identity {id} is also configured for agent {}",
            selected.name, other.name
        )
        .into());
    }
    Ok(selected)
}

/// Reread configuration without replacing a previously selected name or ID.
pub(crate) fn refresh(selected: &Agent) -> Result<Agent, Error> {
    let agents = list()?;
    by_id(&agents, &selected.id)?
        .filter(|current| current.name == selected.name)
        .cloned()
        .ok_or_else(|| {
            format!(
                "agent {}: configuration identity changed or was removed",
                selected.name
            )
            .into()
        })
}

/// Preserve the assigned 10.200/16 identity and avoid addresses already in
/// the derived live attachment projection.
pub(crate) fn reserve_network_slot(name: &str) -> Result<u16, Error> {
    let path = policy_path()?;
    let _lock = crate::approvals::lock_policy(&path)?;
    let mut document = read_document(&path)?;
    let agents = document
        .get("agents")
        .and_then(Item::as_table_like)
        .ok_or("Agent not found")?;
    if !agents.contains_key(name) {
        return Err("Agent not found".into());
    }
    let mut used = std::collections::HashMap::<u16, String>::new();
    let mut current = None;
    for (other, item) in agents.iter() {
        let Some(slot) = item.get("network_slot") else {
            continue;
        };
        let slot = slot
            .as_integer()
            .ok_or("agent network slot must be an integer")?;
        let slot = u16::try_from(slot).map_err(|_| "agent network slot is outside 0-65534")?;
        if slot == u16::MAX {
            return Err("agent network slot is outside 0-65534".into());
        }
        if let Some(previous) = used.insert(slot, other.to_owned()) {
            return Err(format!(
                "network slot {slot} is already assigned to both {previous} and {other}"
            )
            .into());
        }
        if other == name {
            current = Some(slot);
        }
    }
    let mut active = std::collections::HashMap::new();
    let configured = crate::native_config::read(&crate::host_platform::config_path())?;
    for other in list()? {
        // A damaged run cannot replace the retained host listener source.
        // Persistent policy slots still reserve addresses for these agents.
        let run = crate::host_runs::read(&other.name).ok().flatten();
        if run.as_ref().is_some_and(|run| run["state"] == "stopped") {
            continue;
        }
        let saved_ip = run
            .as_ref()
            .filter(|run| {
                run["agent_id"] == other.id
                    && crate::host_runs::id(&other.name).ok().as_deref()
                        == run["run_id"]
                            .as_str()
                            .map(|id| format!("safeyolo-{id}"))
                            .as_deref()
            })
            .and_then(|run| run["ip"].as_str());
        let listener_ip = configured
            .listeners
            .iter()
            .find(|listener| {
                listener.agent_id == other.name
                    && crate::host_platform::is_managed_agent_listener(listener)
            })
            .and_then(|listener| listener.source_id());
        let Some(ip) = saved_ip.or(listener_ip.as_deref()) else {
            continue;
        };
        let Ok([10, 200, third, fourth]) = ip.parse::<std::net::Ipv4Addr>().map(|ip| ip.octets())
        else {
            continue;
        };
        let address = u16::from(third) * 256 + u16::from(fourth);
        if address > 0 {
            active.insert(other.name, address - 1);
        }
    }
    for (other, slot) in active.iter() {
        if other != name {
            if let Some(owner) = used.get(slot) {
                if owner != other {
                    return Err(format!(
                        "network slot {slot} is assigned to {owner} and used by live agent {other}"
                    )
                    .into());
                }
            } else {
                used.insert(*slot, other.clone());
            }
        }
    }
    if let Some(slot) = current {
        if used.get(&slot).is_some_and(|owner| owner != name) {
            return Err("agent network slot conflicts with a live agent".into());
        }
        return Ok(slot);
    }
    let own_active = active.get(name).copied();
    let slot = own_active
        .filter(|slot| !used.contains_key(slot))
        .or_else(|| (0..u16::MAX).find(|slot| !used.contains_key(slot)))
        .ok_or("no free SafeYolo agent network slots")?;
    document["agents"][name]["network_slot"] = value(i64::from(slot));
    save_document(&path, &document)?;
    Ok(slot)
}

/// Reserve a unique Tailnet HTTPS port, returning its previous value so a
/// failed presentation can restore the host-owned policy.
pub(crate) fn reserve_tailnet_port(name: &str) -> Result<(u16, Option<u16>), Error> {
    let path = policy_path()?;
    let _lock = crate::approvals::lock_policy(&path)?;
    let mut document = read_document(&path)?;
    let agents = document
        .get("agents")
        .and_then(Item::as_table_like)
        .ok_or("Agent not found")?;
    let mut used = std::collections::HashSet::new();
    let mut previous = None;
    let mut found = false;
    for (other, item) in agents.iter() {
        if other == name {
            found = true;
            previous = item.get("tailnet_port").and_then(Item::as_integer);
        } else if let Some(port) = item.get("tailnet_port").and_then(Item::as_integer) {
            used.insert(port);
        }
    }
    if !found {
        return Err("Agent not found".into());
    }
    let prior = previous.map(u16::try_from).transpose()?;
    let port = if let Some(port) = prior {
        if port == 0 || used.contains(&i64::from(port)) {
            return Err(
                format!("tailnet HTTPS port {port} is already assigned to another agent").into(),
            );
        }
        port
    } else {
        let port = (8443..=8999)
            .find(|port| !used.contains(&i64::from(*port)))
            .ok_or("no free automatic tailnet ports in 8443-8999")?;
        document["agents"][name]["tailnet_port"] = value(i64::from(port));
        save_document(&path, &document)?;
        port
    };
    Ok((port, prior))
}

pub(crate) fn restore_tailnet_port(
    name: &str,
    expected: u16,
    previous: Option<u16>,
) -> Result<bool, Error> {
    let path = policy_path()?;
    let _lock = crate::approvals::lock_policy(&path)?;
    let mut document = read_document(&path)?;
    let Some(agents) = document.get("agents").and_then(Item::as_table_like) else {
        return Ok(false);
    };
    let Some(item) = agents.get(name) else {
        return Ok(false);
    };
    if item.get("tailnet_port").and_then(Item::as_integer) != Some(i64::from(expected)) {
        return Ok(false);
    }
    match previous {
        Some(port) => document["agents"][name]["tailnet_port"] = value(i64::from(port)),
        None => {
            document["agents"][name]
                .as_table_like_mut()
                .ok_or("agent metadata must be a table")?
                .remove("tailnet_port");
        }
    }
    save_document(&path, &document)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn saved_edits_reject_a_selected_identity_replaced_while_waiting() {
        let root = tempfile::tempdir().unwrap();
        crate::host_platform::in_instance(root.path().to_owned(), async {
            let agent = configure(
                "alice",
                &[("folder".into(), root.path().to_string_lossy().into_owned())],
                true,
                None,
            )
            .await
            .unwrap();
            let directory = root.path().join("agents/alice");
            let lock = crate::host_lifecycle::SetupLock::acquire_in(&directory, None).unwrap();
            let edit = saved_mount(&agent, "remove", "/mnt/old");
            let change = async {
                let path = policy_path().unwrap();
                let _policy = crate::approvals::lock_policy(&path).unwrap();
                let mut document = read_document(&path).unwrap();
                document["agents"]["alice"]["agent_id"] =
                    value(format!("ag-{}", uuid::Uuid::new_v4().simple()));
                save_document(&path, &document).unwrap();
                let replaced = std::fs::read(&path).unwrap();
                drop(lock);
                replaced
            };
            let (rejected, replaced) = tokio::join!(edit, change);
            assert!(
                rejected
                    .unwrap_err()
                    .to_string()
                    .contains("identity changed")
            );
            assert_eq!(std::fs::read(policy_path().unwrap()).unwrap(), replaced);
        })
        .await;
    }

    #[tokio::test]
    async fn retirement_preflight_names_existing_approval_dependencies_before_stopping() {
        let root = tempfile::tempdir().unwrap();
        crate::host_platform::in_instance(root.path().to_owned(), async {
            let options = [("folder".into(), root.path().to_string_lossy().into_owned())];
            let alice = configure("alice", &options, true, None).await.unwrap();
            let bob = configure("bob", &options, true, None).await.unwrap();
            let mut delegation: crate::policy::delegation::Delegation = serde_json::from_value(json!({
                "reviewers":[{"name":bob.name,"agent_id":bob.id}],
                "beneficiaries":[{"name":alice.name,"agent_id":alice.id}],
                "scopes":[{"type":"network_egress","host":"example.com","ports":[443],"all_ports":false,"actions":["request"]}],
                "expires_at":null,"grant_seconds":null,"gateway_once":true,"acknowledgment":null
            })).unwrap();
            delegation.acknowledgment = Some(delegation.revision());
            let path = policy_path().unwrap();
            let mut document = read_document(&path).unwrap();
            document["approval_delegations"]["local"] = value(serde_json::to_string(&delegation).unwrap());
            validate_document(&path, &document).unwrap();
            save_document(&path, &document).unwrap();
            let original = std::fs::read(&path).unwrap();
            let run = root.path().join("agents/alice/runtime.json");
            std::fs::write(&run, b"unverified runtime must be preserved").unwrap();
            let result = crate::host_lifecycle::retire(&alice, true).await.unwrap();
            assert_eq!(result["ok"], false);
            assert_eq!(result["failed_stage"], "preflight");
            assert!(result["error"].as_str().unwrap().contains("delegation local"));
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(std::fs::read(&run).unwrap(), b"unverified runtime must be preserved");
        }).await;
    }

    #[test]
    fn nested_docker_is_an_explicit_boolean_operator_setting() {
        for (setting, enabled) in [
            ("", false),
            ("nested_docker = false", false),
            ("nested_docker = true", true),
        ] {
            let document = DocumentMut::from_str(&format!(
                "[agents.alice]\nagent_id = 'ag-alice'\n{setting}\n"
            ))
            .unwrap();
            let agent = Agent::from_item("alice".into(), &document["agents"]["alice"]).unwrap();
            assert_eq!(agent.nested_docker, enabled);
        }
        for setting in ["'true'", "1", "[]"] {
            let document = DocumentMut::from_str(&format!(
                "[agents.alice]\nagent_id = 'ag-alice'\nnested_docker = {setting}\n"
            ))
            .unwrap();
            let error = Agent::from_item("alice".into(), &document["agents"]["alice"])
                .err()
                .unwrap();
            assert_eq!(error.to_string(), "nested_docker must be a Boolean");
        }
    }

    #[test]
    fn policy_overrides_are_read_only_and_separate_from_host_agents() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.toml");
        let source = "[agents]\nbob={egress='deny'}\n[agents.alice.hosts]\n'*'={egress='allow'}\n[agents.configured]\nagent_id='ag-original'\nmemory_mb=512\n";
        std::fs::write(&policy, source).unwrap();
        crate::host_platform::with_config(root.path().join("config.toml"), || {
            let agents = list().unwrap();
            assert_eq!(agents.len(), 1);
            assert_eq!(agents[0].name, "configured");
            assert_eq!(agents[0].id, "ag-original");
            assert_eq!(agents[0].memory_mb, Some(512));
        });
        assert_eq!(std::fs::read_to_string(policy).unwrap(), source);
    }

    #[test]
    fn damaged_host_identity_is_not_hidden_by_policy_only_fields() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.toml");
        crate::host_platform::with_config(root.path().join("config.toml"), || {
            for source in [
                "[agents.alice]\negress='allow'\nmemory_mb=512\n",
                "[agents.alice]\negress='allow'\nagent_id=7\n",
            ] {
                std::fs::write(&policy, source).unwrap();
                let error = list().err().unwrap().to_string();
                assert!(error.contains("agent alice:"), "{error}");
                assert!(
                    error.contains("identity") || error.contains("agent_id"),
                    "{error}"
                );
                assert_eq!(std::fs::read_to_string(&policy).unwrap(), source);
            }
            let source = "[agents.alice]\negress='allow'\n";
            std::fs::write(&policy, source).unwrap();
            for record in [
                crate::host_runs::path("alice"),
                root.path()
                    .join("agents/alice/config-share/host-launch-context.json"),
            ] {
                std::fs::create_dir_all(record.parent().unwrap()).unwrap();
                std::fs::write(&record, "corrupt").unwrap();
                let error = list().err().unwrap().to_string();
                assert!(
                    error.contains("agent alice: agent identity is missing"),
                    "{error}"
                );
                assert_eq!(std::fs::read_to_string(&policy).unwrap(), source);
                assert_eq!(std::fs::read_to_string(&record).unwrap(), "corrupt");
                std::fs::remove_file(record).unwrap();
            }
            assert!(list().unwrap().is_empty());
        });
    }
}
