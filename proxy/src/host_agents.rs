//! Configured agents in the host-owned policy.toml.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
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

fn policy_path() -> PathBuf {
    crate::host_platform::config_dir().join("policy.toml")
}

struct PolicyLock(File);

impl PolicyLock {
    fn exclusive() -> Result<Self, Error> {
        let path = crate::host_platform::config_dir().join(".policy.toml.lock");
        std::fs::create_dir_all(path.parent().ok_or("policy lock has no parent")?)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(file))
    }
}

impl Drop for PolicyLock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
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
pub(crate) fn configure(
    name: &str,
    options: &[(String, String)],
    create: bool,
) -> Result<Agent, Error> {
    if !crate::host_platform::valid_agent_name(name) {
        return Err("invalid agent name".into());
    }
    let _lock = PolicyLock::exclusive()?;
    let path = policy_path();
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
    save_document(&path, &document)?;
    Ok(agent)
}

/// Read the atomic native policy snapshot. Fresh agent creation owns ID
/// assignment; status does not migrate or rewrite configuration.
pub(crate) fn list() -> Result<Vec<Agent>, Error> {
    let document = read_document(&policy_path())?;
    let mut agents = document
        .get("agents")
        .and_then(Item::as_table_like)
        .map(|table| {
            table
                .iter()
                .map(|(name, item)| Agent::from_item(name.into(), item))
                .collect::<Result<Vec<_>, Error>>()
        })
        .transpose()?
        .unwrap_or_default();
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(agents)
}

/// Preserve the assigned 10.200/16 identity and avoid addresses already in
/// the live agent map, including legacy agents with no saved slot.
pub(crate) fn reserve_network_slot(name: &str) -> Result<u16, Error> {
    let _lock = PolicyLock::exclusive()?;
    let path = policy_path();
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
    let map_path = crate::host_platform::config_dir().join("data/agent_map.json");
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
    let _lock = PolicyLock::exclusive()?;
    let path = policy_path();
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
    let _lock = PolicyLock::exclusive()?;
    let path = policy_path();
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
