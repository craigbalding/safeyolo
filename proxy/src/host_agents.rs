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

#[derive(Clone)]
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
}

impl Agent {
    fn from_item(name: String, item: &Item) -> Result<Self, Error> {
        let table = item
            .as_table_like()
            .ok_or("agent metadata must be a TOML table")?;
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

/// Mint missing IDs with the same policy lock as the Python CLI, then return
/// the configured agents in stable name order.
pub(crate) fn list() -> Result<Vec<Agent>, Error> {
    let _lock = PolicyLock::exclusive()?;
    let path = policy_path();
    let mut document = read_document(&path)?;
    let names: Vec<String> = document
        .get("agents")
        .and_then(Item::as_table_like)
        .map(|agents| agents.iter().map(|(name, _)| name.to_owned()).collect())
        .unwrap_or_default();
    let mut changed = false;
    for name in &names {
        let item = &mut document["agents"][name.as_str()];
        if item.as_table_like().is_none() {
            return Err(format!("agent {name} metadata must be a TOML table").into());
        }
        if item
            .get("agent_id")
            .and_then(Item::as_str)
            .is_none_or(str::is_empty)
        {
            item["agent_id"] = value(format!("ag-{}", uuid::Uuid::new_v4().simple()));
            changed = true;
        }
    }
    if changed {
        save_document(&path, &document)?;
    }
    let mut agents = names
        .into_iter()
        .map(|name| Agent::from_item(name.clone(), &document["agents"][name.as_str()]))
        .collect::<Result<Vec<_>, _>>()?;
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
