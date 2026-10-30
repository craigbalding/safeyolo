//! Room-visible projection of current host grants and provider-owned observations.
use super::{
    CoordClient, CoordError, Path, RoomAccess, now_ms, open_db, public_name_part, valid_agent_id,
    valid_capability,
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

pub(crate) const MAX_CAPABILITIES: usize = 512;
pub(crate) const MAX_RESOURCES: usize = 128;
pub(crate) const MAX_PROVIDERS: usize = 16;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024;
const MAX_OBSERVATIONS: usize = 1024;
const MAX_TTL_MS: i64 = 5 * 60 * 1000;
const MAX_STATE_BYTES: usize = 512 * 1024;
const MAX_INFLIGHT: usize = 32;
const MAX_PROVIDER_INFLIGHT: usize = 2;
const READ_TIMEOUT: Duration = Duration::from_secs(1);
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
type BeforeProviderRead = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
pub(super) struct SnapshotReads {
    providers: Mutex<HashMap<String, usize>>,
    // Pause the real state-read path at provider I/O in deterministic tests.
    #[cfg(test)]
    before_read: Mutex<Option<BeforeProviderRead>>,
}

struct ReadPermit {
    reads: Arc<SnapshotReads>,
    provider: String,
}
impl Drop for ReadPermit {
    fn drop(&mut self) {
        let mut providers = self
            .reads
            .providers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(count) = providers.get_mut(&self.provider) {
            *count -= 1;
            if *count == 0 {
                providers.remove(&self.provider);
            }
        }
        INFLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SnapshotReads {
    // A timed-out OS read may still block. Its permit lives on that dedicated
    // thread until it exits, rather than being returned by the waiting future.
    fn start(
        self: &Arc<Self>,
        provider: &str,
        read: impl FnOnce() -> Option<Observations> + Send + 'static,
    ) -> Option<tokio::sync::oneshot::Receiver<Option<Observations>>> {
        let mut providers = self.providers.lock().ok()?;
        if providers.get(provider).copied().unwrap_or(0) >= MAX_PROVIDER_INFLIGHT {
            return None;
        }
        INFLIGHT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_INFLIGHT).then_some(n + 1)
            })
            .ok()?;
        *providers.entry(provider.into()).or_default() += 1;
        drop(providers);
        let permit = ReadPermit {
            reads: self.clone(),
            provider: provider.into(),
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("coord-observation".into())
            .spawn(move || {
                let _permit = permit;
                let _ = sender.send(read());
            })
            .ok()?;
        Some(receiver)
    }

    async fn observe(
        self: &Arc<Self>,
        directory: Option<&Path>,
        providers: BTreeSet<String>,
    ) -> BTreeMap<String, Observations> {
        let Some(directory) = directory else {
            return BTreeMap::new();
        };
        let mut pending = FuturesUnordered::new();
        for provider in providers {
            let directory = directory.to_owned();
            let name = provider.clone();
            #[cfg(test)]
            let before_read = self.before_read.lock().unwrap().clone();
            let Some(receiver) = self.start(&provider, move || {
                #[cfg(test)]
                if let Some(before_read) = before_read {
                    before_read(&name);
                }
                read_snapshot(&directory, &name)
            }) else {
                continue;
            };
            pending.push(async move {
                (
                    provider,
                    tokio::time::timeout(READ_TIMEOUT, receiver)
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .flatten(),
                )
            });
        }
        let mut observations = BTreeMap::new();
        while let Some((provider, result)) = pending.next().await {
            if let Some(result) = result {
                observations.insert(provider, result);
            }
        }
        observations
    }
}

#[derive(Deserialize)]
struct Observations {
    #[serde(default)]
    capabilities: Vec<CapabilityObservation>,
    #[serde(default)]
    leases: Vec<LeaseObservation>,
}
#[derive(Deserialize)]
struct CapabilityObservation {
    agent_id: String,
    capability: String,
    availability: Availability,
    observed_at: i64,
    valid_until: i64,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Available,
    Unavailable,
}
#[derive(Deserialize)]
struct LeaseObservation {
    resource: String,
    state: LeaseState,
    holder_agent_id: Option<String>,
    observed_at: i64,
    valid_until: i64,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LeaseState {
    Held,
    Unleased,
}

fn read_snapshot(directory: &Path, provider: &str) -> Option<Observations> {
    // Open the directory itself without following a symlink, then openat its
    // retained descriptor. Directory replacement cannot redirect this read.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory)
        .ok()?;
    let name = std::ffi::CString::new(format!("{provider}.json")).ok()?;
    // SAFETY: the directory owns a live descriptor and name is NUL-terminated.
    // openat borrows both and returns an independently owned file descriptor.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: openat returned a new descriptor; File owns its only Rust handle.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let observations: Observations = serde_json::from_slice(&bytes).ok()?;
    if observations.capabilities.len() + observations.leases.len() > MAX_OBSERVATIONS {
        return None;
    }
    let mut capabilities = HashSet::new();
    for row in &observations.capabilities {
        if !valid_agent_id(&row.agent_id)
            || !valid_capability(&row.capability)
            || row.capability.split_once(':')?.0 != provider
            || !capabilities.insert((&row.agent_id, &row.capability))
            || row.observed_at < 0
            || row.valid_until < 0
        {
            return None;
        }
    }
    let mut resources = HashSet::new();
    for row in &observations.leases {
        if !public_name_part(&row.resource)
            || !resources.insert(&row.resource)
            || row.observed_at < 0
            || row.valid_until < 0
            || match row.state {
                LeaseState::Held => row
                    .holder_agent_id
                    .as_deref()
                    .is_none_or(|id| !valid_agent_id(id)),
                LeaseState::Unleased => row.holder_agent_id.is_some(),
            }
        {
            return None;
        }
    }
    Some(observations)
}

fn freshness(observed: i64, until: i64, now: i64) -> &'static str {
    if observed > now || until <= observed || until - observed > MAX_TTL_MS {
        "unknown"
    } else if now >= until {
        "stale"
    } else {
        "fresh"
    }
}

pub(crate) struct ConfiguredAgent {
    pub(crate) name: String,
    grants: BTreeSet<String>,
}

pub(crate) fn configured_agents(
    policy: Option<&Path>,
    ids: &[String],
) -> HashMap<String, ConfiguredAgent> {
    let Some(policy) = policy else {
        return HashMap::new();
    };
    let Ok(source) = std::fs::read_to_string(policy).map(zeroize::Zeroizing::new) else {
        return HashMap::new();
    };
    let Ok(document) = source.parse::<toml_edit::DocumentMut>() else {
        return HashMap::new();
    };
    let Some(agents) = document
        .get("agents")
        .and_then(toml_edit::Item::as_table_like)
    else {
        return HashMap::new();
    };
    let mut configured = HashMap::new();
    let mut duplicates = HashSet::new();
    for (name, item) in agents.iter() {
        let Some(id) = item
            .get("agent_id")
            .and_then(toml_edit::Item::as_str)
            .filter(|id| valid_agent_id(id))
        else {
            continue;
        };
        if !ids.iter().any(|requested| requested == id) {
            continue;
        }
        let mut grants = BTreeSet::new();
        if let Some(services) = item
            .get("services")
            .and_then(toml_edit::Item::as_table_like)
        {
            for (provider, grant) in services.iter() {
                let capability = grant.as_str().or_else(|| {
                    grant
                        .get("capability")
                        .or_else(|| grant.get("role"))
                        .and_then(toml_edit::Item::as_str)
                });
                if let Some(capability) = capability {
                    let label = format!("{provider}:{capability}");
                    if valid_capability(&label) {
                        grants.insert(label);
                    }
                }
            }
        }
        if configured
            .insert(
                id.to_owned(),
                ConfiguredAgent {
                    name: name.into(),
                    grants,
                },
            )
            .is_some()
        {
            duplicates.insert(id.to_owned());
        }
    }
    for id in duplicates {
        configured.remove(&id);
    }
    configured
}

struct Inventory {
    access: RoomAccess,
    configured: HashMap<String, ConfiguredAgent>,
    capabilities: BTreeSet<(String, String)>,
    resources: BTreeSet<(String, String)>,
    declarations: Vec<(String, String, i64, i64)>,
}

fn read_inventory(
    db: &Path,
    policy: Option<&Path>,
    room: &str,
    kind: &str,
    principal: &str,
) -> Result<Inventory, CoordError> {
    let conn = open_db(db, false)?;
    conn.execute_batch("BEGIN")
        .map_err(|_| CoordError::Unavailable)?;
    let access = super::read_access_from(&conn, room, kind, principal)?;
    if !access
        .permissions
        .iter()
        .any(|permission| permission == "receive")
    {
        return Err(CoordError::Forbidden);
    }
    let ids = access
        .members
        .iter()
        .filter(|m| m.principal_kind == "agent")
        .map(|m| m.principal_id.clone())
        .collect::<Vec<_>>();
    let configured = configured_agents(policy, &ids);
    // Ingress resolved the listener name before provider I/O. A removed or
    // replaced identity must not finish that read using its former room grant.
    if kind == "agent" && !configured.contains_key(principal) {
        return Err(CoordError::NotFound);
    }
    let capabilities = conn.prepare("SELECT agent_id,capability FROM coord_capability_advertisements WHERE room_id=?1 ORDER BY agent_id,capability LIMIT ?2")
        .map_err(|_| CoordError::Data)?.query_map(params![access.room_id, MAX_CAPABILITIES as i64 + 1], |r| Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?)))
        .map_err(|_| CoordError::Data)?.collect::<Result<BTreeSet<_>,_>>().map_err(|_| CoordError::Data)?;
    let resources = conn.prepare("SELECT provider,resource FROM coord_resource_advertisements WHERE room_id=?1 ORDER BY provider,resource LIMIT ?2")
        .map_err(|_| CoordError::Data)?.query_map(params![access.room_id, MAX_RESOURCES as i64 + 1], |r| Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?)))
        .map_err(|_| CoordError::Data)?.collect::<Result<BTreeSet<_>,_>>().map_err(|_| CoordError::Data)?;
    if capabilities.len() > MAX_CAPABILITIES || resources.len() > MAX_RESOURCES {
        return Err(CoordError::Data);
    }
    let capabilities = capabilities
        .into_iter()
        .filter(|(id, label)| {
            configured
                .get(id)
                .is_some_and(|agent| agent.grants.contains(label))
        })
        .collect();
    let declarations = conn.prepare("SELECT agent_id,capability,asserted_at,valid_until FROM coord_capability_declarations WHERE room_id=?1 AND valid_until>?2 ORDER BY agent_id,capability")
        .map_err(|_| CoordError::Data)?.query_map(params![access.room_id, now_ms()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))
        .map_err(|_| CoordError::Data)?.collect::<Result<Vec<_>,_>>().map_err(|_| CoordError::Data)?;
    conn.execute_batch("COMMIT")
        .map_err(|_| CoordError::Unavailable)?;
    Ok(Inventory {
        access,
        configured,
        capabilities,
        resources,
        declarations,
    })
}

async fn read_current(
    client: &CoordClient,
    room: &str,
    kind: &str,
    principal: &str,
) -> Result<Inventory, CoordError> {
    let (db, policy, room, kind, principal) = (
        client.owner.data_dir.join("v0.db"),
        client.policy_file.clone(),
        room.to_owned(),
        kind.to_owned(),
        principal.to_owned(),
    );
    tokio::task::spawn_blocking(move || {
        read_inventory(&db, policy.as_deref(), &room, &kind, &principal)
    })
    .await
    .map_err(|_| CoordError::Unavailable)?
}

pub(super) async fn room_state(
    client: &CoordClient,
    room: &str,
    kind: &str,
    principal: &str,
    runtime: Option<&crate::RuntimeState>,
) -> Result<Value, CoordError> {
    let mut initial = read_current(client, room, kind, principal).await?;
    retain_active_grants(&mut initial, runtime)?;
    let providers = initial
        .capabilities
        .iter()
        .filter_map(|(_, label)| label.split_once(':').map(|(p, _)| p.to_owned()))
        .chain(initial.resources.iter().map(|(p, _)| p.clone()))
        .collect::<BTreeSet<_>>();
    if providers.len() > MAX_PROVIDERS {
        return Err(CoordError::Data);
    }
    let observations = client
        .owner
        .snapshot_reads
        .observe(client.provider_directory.as_deref(), providers)
        .await;
    // Provider I/O is outside the authoritative snapshot. Re-read membership,
    // advertisements, current service grants and declarations together before
    // projecting; never carry a revoked grant or removed holder across I/O.
    let mut current = read_current(client, room, kind, principal).await?;
    retain_active_grants(&mut current, runtime)?;
    project(current, &initial, &observations, now_ms())
}

fn retain_active_grants(
    inventory: &mut Inventory,
    runtime: Option<&crate::RuntimeState>,
) -> Result<(), CoordError> {
    let Some(state) = runtime else {
        return Ok(());
    };
    let current = state.read().map_err(|_| CoordError::Unavailable)?;
    let gateway = current
        .policy
        .as_ref()
        .and_then(crate::policy::Policy::gateway);
    inventory.capabilities.retain(|(id, label)| {
        let Some(agent) = inventory.configured.get(id) else {
            return false;
        };
        let Some((provider, capability)) = label.split_once(':') else {
            return false;
        };
        gateway.is_some_and(|gateway| {
            gateway.room_capability_authorized(&agent.name, id, provider, capability)
        })
    });
    Ok(())
}

fn project(
    current: Inventory,
    initial: &Inventory,
    observations: &BTreeMap<String, Observations>,
    now: i64,
) -> Result<Value, CoordError> {
    let mut members = Vec::new();
    let ids = current
        .access
        .members
        .iter()
        .filter(|m| m.principal_kind == "agent")
        .map(|m| m.principal_id.as_str())
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    for member in current
        .access
        .members
        .iter()
        .filter(|m| m.principal_kind == "agent")
    {
        if !seen.insert(&member.principal_id) {
            continue;
        }
        let configured = current.configured.get(&member.principal_id);
        let mut verified = Vec::new();
        for (id, label) in &current.capabilities {
            if id != &member.principal_id {
                continue;
            }
            let Some((provider, _)) = label.split_once(':') else {
                continue;
            };
            let observation = initial
                .capabilities
                .contains(&(id.clone(), label.clone()))
                .then(|| observations.get(provider))
                .flatten()
                .and_then(|o| {
                    o.capabilities
                        .iter()
                        .find(|r| r.agent_id == *id && r.capability == *label)
                });
            let fresh =
                observation.map_or("unknown", |r| freshness(r.observed_at, r.valid_until, now));
            verified.push(json!({"capability":label,"authorized":true,"availability":match observation.filter(|_| fresh == "fresh").map(|r| &r.availability) { Some(Availability::Available)=>"available",Some(Availability::Unavailable)=>"unavailable",None=>"unknown" },
                "provider":provider,"observed_at":observation.map(|r| r.observed_at),"valid_until":observation.map(|r| r.valid_until),"freshness":fresh,
                "provenance":{"authorization":"safeyolo_current_grant","visibility":"operator_room_advertisement","availability":"provider_observation"}}));
        }
        let declared = current.declarations.iter().filter(|(id,_,_,until)| id == &member.principal_id && now < *until).map(|(id,label,at,until)| json!({"capability":label,"asserted_by_agent_id":id,"asserted_at":at,"valid_until":until,"freshness":"fresh","provenance":"agent_declared"})).collect::<Vec<_>>();
        members.push(json!({"agent_id":member.principal_id,"display_name":configured.map(|a| &a.name),"configured":configured.is_some(),"origin_instance_id":current.access.instance_id,"room_permissions":member.permissions,"verified":verified,"declared":declared}));
    }
    let leases = current.resources.iter().map(|(provider, resource)| {
        let observation = initial.resources.contains(&(provider.clone(),resource.clone())).then(|| observations.get(provider)).flatten().and_then(|o| o.leases.iter().find(|r| r.resource == *resource));
        let mut fresh = observation.map_or("unknown",|r| freshness(r.observed_at,r.valid_until,now));
        if observation.is_some_and(|r| matches!(r.state,LeaseState::Held) && r.holder_agent_id.as_deref().is_none_or(|id| !ids.contains(id))) { fresh = "unknown"; }
        let observation_current = observation.filter(|_| fresh == "fresh");
        let holder = observation_current.and_then(|r| r.holder_agent_id.as_deref());
        json!({"provider":provider,"resource":resource,"state":match observation_current.map(|r| &r.state) { Some(LeaseState::Held)=>"held",Some(LeaseState::Unleased)=>"unleased",None=>"unknown" },"holder_agent_id":holder,"holder_display_name":holder.and_then(|id| current.configured.get(id)).map(|a| &a.name),"observed_at":observation.map(|r| r.observed_at),"valid_until":observation.map(|r| r.valid_until),"freshness":fresh,"provenance":"provider_owned_lease"})
    }).collect::<Vec<_>>();
    let state = json!({"room_id":current.access.room_id,"room_name":current.access.room_name,"origin_instance_id":current.access.instance_id,"generated_at":now,"brief":current.access.brief,"members":members,"resource_leases":leases});
    if state.to_string().len() > MAX_STATE_BYTES {
        return Err(CoordError::Data);
    }
    Ok(state)
}

#[cfg(test)]
mod tests;
