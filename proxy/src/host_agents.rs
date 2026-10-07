//! Configured agents in the host-owned policy.toml.

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

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
        if table
            .get("dangerously_allow_unowned")
            .is_some_and(|item| item.as_bool().is_none())
        {
            return Err("dangerously_allow_unowned must be a Boolean".into());
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
            user_default_args: strings("user_default_args")?,
            mounts: strings("mounts")?,
            dangerously_allow_unowned: table
                .get("dangerously_allow_unowned")
                .and_then(Item::as_bool)
                .unwrap_or(false),
        })
    }
}

fn policy_path() -> Result<PathBuf, Error> {
    let path = crate::host_platform::config_path();
    if path.is_file() {
        return crate::native_config::read(&path)?
            .policy_file
            .ok_or_else(|| "native policy_file is missing".into());
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

/// Local operator configuration only. Executables and arguments are never
/// accepted by the remote lifecycle API.
pub(crate) async fn configure(
    name: &str,
    options: &[(String, String)],
    create: bool,
    factory: Option<(&Path, &str, bool)>,
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
            "dangerously_allow_unowned" => value(text.parse::<bool>()?),
            "mounts" => {
                crate::host_boot::mount(text)?;
                let mut array = document["agents"][name]
                    .get("mounts")
                    .and_then(Item::as_array)
                    .cloned()
                    .unwrap_or_default();
                array.push(text.as_str());
                value(array)
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
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().ok_or("policy has no parent")?)?;
    temporary.write_all(document.to_string().as_bytes())?;
    crate::policy::Policy::from_native_path(temporary.path())?;
    if options.iter().any(|(key, _)| key == "host_script") {
        if crate::host_runs::observe(name).await["runtime_state"] != "stopped" {
            return Err("stop the agent before applying a host setup script; saved configuration is unchanged".into());
        }
        crate::host_boot::setup(&agent, factory).await?;
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
    let map_path = crate::host_platform::agent_map_path()?;
    if let Ok(source) = std::fs::read(&map_path)
        && let Ok(map) =
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&source)
    {
        for (other, entry) in map {
            let Some(ip) = entry.get("ip").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Ok([10, 200, third, fourth]) = ip
                .parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.octets())
                .map_err(|_| ())
            else {
                continue;
            };
            let address = u16::from(third) * 256 + u16::from(fourth);
            if address > 0 {
                active.insert(other, address - 1);
            }
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
