//! Operator TCP bindings reuse the configured UDS listener's evidence owner.
//! Client bytes never select identity, a sandbox run, or a source slot.

use crate::{AgentListener, Config, Error, Proxy, RuntimeState};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    net::{TcpListener, TcpStream, UnixSocket, UnixStream},
    sync::{oneshot, watch},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub name: String,
    pub listen: SocketAddr,
    pub agent: String,
}

fn target<'a>(config: &'a Config, binding: &Binding) -> Option<&'a AgentListener> {
    config
        .listeners
        .iter()
        .find(|entry| entry.agent_id == binding.agent)
}

pub(crate) fn validate(config: &Config) -> Result<(), Error> {
    let mut names = HashSet::new();
    let mut addresses = HashSet::new();
    for binding in &config.ingress_bindings {
        if binding.name.trim().is_empty() || !names.insert(&binding.name) {
            return Err("ingress bindings need a nonempty unique name".into());
        }
        if binding.agent.trim().is_empty() {
            return Err("ingress binding needs a target agent".into());
        }
        if binding.listen.port() != 0 && !addresses.insert(binding.listen) {
            return Err("ingress bindings need distinct listen addresses".into());
        }
        if config
            .listeners
            .iter()
            .filter(|entry| entry.agent_id == binding.agent)
            .count()
            > 1
        {
            return Err(format!(
                "ingress binding {:?}: target agent has multiple UDS listeners",
                binding.name
            )
            .into());
        }
    }
    Ok(())
}

/// Pending provenance for host-created, bound UDS peers. The accepting UDS
/// listener remains the sole evidence-owner authority. These notes cannot be
/// created by HTTP bytes and never supply a sandbox run.
#[derive(Default)]
pub(crate) struct Peers(Mutex<HashMap<PathBuf, Pending>>);

pub(crate) struct Pending {
    target: AgentListener,
    pub(crate) binding: String,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) remote: Option<SocketAddr>,
    pub(crate) accepted: oneshot::Sender<Option<crate::connection_events::Connection>>,
}

fn same_process(socket: &UnixStream) -> bool {
    socket.peer_cred().is_ok_and(|peer| {
        peer.pid() == Some(std::process::id() as libc::pid_t)
            && peer.uid() == unsafe { libc::geteuid() }
    })
}

impl Peers {
    pub(crate) fn claim(
        &self,
        socket: &UnixStream,
        target: &AgentListener,
    ) -> Result<Option<Pending>, Error> {
        let peer = socket.peer_addr()?;
        let Some(path) = peer.as_pathname() else {
            return Ok(None);
        };
        let pending = self
            .0
            .lock()
            .map_err(|_| "ingress peer lock poisoned")?
            .remove(path);
        // Cancellation can remove a note while its accepted UDS peer is still
        // queued. Such a host-created peer must never acquire sandbox authority.
        if pending.is_none() && same_process(socket) {
            return Err("unregistered host UDS ingress peer".into());
        }
        if let Some(pending) = &pending
            && (!same_process(socket) || &pending.target != target)
        {
            return Err("ingress peer did not reach its selected UDS listener".into());
        }
        Ok(pending)
    }
}

struct PeerRegistration {
    peers: Arc<Peers>,
    path: PathBuf,
    directory: Option<tempfile::TempDir>,
}
impl Drop for PeerRegistration {
    fn drop(&mut self) {
        self.peers
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.path);
        if let Some(directory) = self.directory.take()
            && let Err(error) = directory.close()
        {
            eprintln!("ingress peer socket cleanup failed: {error}");
        }
    }
}

async fn bridge(
    mut client: TcpStream,
    binding: String,
    target: AgentListener,
    peers: Arc<Peers>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Error> {
    // tempfile creates a private host directory. The sandbox receives only its
    // server socket directory, never this client endpoint or the pending map.
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("p");
    let _registration = PeerRegistration {
        peers: peers.clone(),
        path: path.clone(),
        directory: Some(directory),
    };
    let socket = UnixSocket::new_stream()?;
    socket.bind(&path)?;
    let (accepted, acknowledgement) = oneshot::channel();
    let pending = Pending {
        target: target.clone(),
        binding,
        local: client.local_addr().ok(),
        remote: client.peer_addr().ok(),
        accepted,
    };
    peers
        .0
        .lock()
        .map_err(|_| "ingress peer lock poisoned")?
        .insert(path, pending);
    let mut upstream = socket.connect(&target.socket_path).await?;
    if !same_process(&upstream) {
        return Err("ingress target UDS is not owned by this native proxy process".into());
    }
    // The selected listener must claim this exact peer before any external
    // bytes can be forwarded. Wrong/replaced listeners cannot acknowledge it.
    let _connection = acknowledgement
        .await
        .map_err(|_| "selected UDS rejected ingress provenance")?;
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut upstream) => { result?; },
        _ = stop.changed() => {},
    }
    Ok(())
}

pub(crate) struct Running {
    binding: Binding,
    target: AgentListener,
    listener: Arc<TcpListener>,
    stop: watch::Sender<bool>,
    released: oneshot::Receiver<()>,
    task: JoinHandle<()>,
}

pub(crate) type Prepared = HashMap<String, Arc<TcpListener>>;

pub(crate) fn prepare(
    current: &HashMap<String, Running>,
    config: &Config,
) -> Result<Prepared, Error> {
    let mut prepared = HashMap::new();
    for binding in &config.ingress_bindings {
        if target(config, binding).is_none() {
            continue;
        }
        if let Some(old) = current.get(&binding.name)
            && old.binding.listen == binding.listen
            && !old.task.is_finished()
        {
            prepared.insert(binding.name.clone(), old.listener.clone());
        } else {
            let socket = std::net::TcpListener::bind(binding.listen).map_err(|error| {
                format!(
                    "ingress binding {:?} at {}: {error}",
                    binding.name, binding.listen
                )
            })?;
            socket.set_nonblocking(true)?;
            prepared.insert(
                binding.name.clone(),
                Arc::new(TcpListener::from_std(socket)?),
            );
        }
    }
    Ok(prepared)
}

pub(crate) fn endpoints(
    prepared: &Prepared,
) -> Result<Vec<crate::admin_shield::BoundTcpEndpoint>, Error> {
    prepared
        .values()
        .map(|socket| crate::admin_shield::BoundTcpEndpoint::new(socket).map_err(Into::into))
        .collect()
}

impl Running {
    fn start(
        binding: Binding,
        target: AgentListener,
        listener: Arc<TcpListener>,
        runtime: RuntimeState,
        peers: Arc<Peers>,
    ) -> Self {
        let (stop, mut stopping) = watch::channel(false);
        let stop_signal = stop.clone();
        let (released_tx, released) = oneshot::channel();
        let socket = listener.clone();
        let name = binding.name.clone();
        let selected = target.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = stopping.changed() => break,
                    accepted = socket.accept() => match accepted {
                        Ok((client, _)) => {
                            let target = selected.clone();
                            let name = name.clone();
                            let peers = peers.clone();
                            let stop = stopping.clone();
                            connections.spawn(async move {
                                let tasks = crate::connection_tasks::ConnectionTasks::new(stop.clone());
                                let monitor = crate::monitor_agent_disconnect(&client, &tasks);
                                tasks.run(async move {
                                    let result = bridge(client, name.clone(), target, peers, stop).await;
                                    if let Err(error) = &result { eprintln!("ingress binding {name:?} target/relay failed: {error}"); }
                                    result
                                }).await;
                                if let Some(monitor) = monitor { monitor.abort(); let _ = monitor.await; }
                            });
                        }
                        Err(error) => {
                            eprintln!("ingress binding {name:?} accept failed: {error}");
                            if let Ok(snapshot) = runtime.read() {
                                crate::clear_readiness(&snapshot.config.readiness_file, &snapshot.instance_id);
                            }
                            break;
                        }
                    },
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        if let Err(error) = result { eprintln!("external connection task failed: {error}"); }
                    }
                }
            }
            drop(socket);
            stop_signal.send_replace(true);
            let _ = released_tx.send(());
            // Stop notification reaches the same connection/upgrade owners as UDS traffic.
            while connections.join_next().await.is_some() {}
        });
        Self {
            binding,
            target,
            listener,
            stop,
            released,
            task,
        }
    }

    pub(crate) fn stop(self) -> (JoinHandle<()>, oneshot::Receiver<()>) {
        self.stop.send_replace(true);
        (self.task, self.released)
    }
}

pub(crate) fn status(current: &HashMap<String, Running>, config: &Config) -> Value {
    json!(
        config
            .ingress_bindings
            .iter()
            .map(|binding| {
                let running = current
                    .get(&binding.name)
                    .filter(|entry| !entry.task.is_finished());
                json!({"name":binding.name, "listen":binding.listen, "agent":binding.agent,
            "target_socket":target(config, binding).map(|entry| &entry.socket_path),
            "address":running.and_then(|entry| entry.listener.local_addr().ok()),
            "state":if running.is_some() { "listening" } else if target(config, binding).is_none() {
                "target_unavailable"
            } else { "failed" }})
            })
            .collect::<Vec<_>>()
    )
}

impl Proxy {
    pub(crate) fn commit_ingress(
        &mut self,
        config: &Config,
        mut prepared: Prepared,
    ) -> Vec<oneshot::Receiver<()>> {
        let mut released = Vec::new();
        let removed: Vec<_> = self
            .ingress_bindings
            .iter()
            .filter(|(_, running)| {
                running.task.is_finished()
                    || !config.ingress_bindings.iter().any(|binding| {
                        binding == &running.binding
                            && target(config, binding) == Some(&running.target)
                    })
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in removed {
            let (task, stopped) = self.ingress_bindings.remove(&name).unwrap().stop();
            self.draining.push(task);
            released.push(stopped);
        }
        for binding in &config.ingress_bindings {
            if !self.ingress_bindings.contains_key(&binding.name)
                && let Some(target) = target(config, binding)
                && let Some(listener) = prepared.remove(&binding.name)
            {
                self.ingress_bindings.insert(
                    binding.name.clone(),
                    Running::start(
                        binding.clone(),
                        target.clone(),
                        listener,
                        self.runtime.clone(),
                        self.ingress_peers.clone(),
                    ),
                );
            }
        }
        released
    }
}

#[cfg(test)]
mod tests;
