//! First migration slice: trusted UDS ingress and HTTP/1 through existing policy.
//! The temporary Python network decision bridge is required; this is not production parity.

mod config;
mod http;

pub use config::{AgentListener, Config};

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub(crate) struct ConnectionIdentity {
    agent_id: String,
    connection_id: String,
}

pub(crate) struct Runtime {
    config: Config,
    parent: Option<config::ParentProxy>,
    tls: Option<Arc<rustls::ClientConfig>>,
    via_token: String,
    events: Mutex<File>,
    instance_id: String,
}

impl Runtime {
    fn new(config: Config, default_via: &str) -> Result<Self, Error> {
        config.validate()?;
        let parent = config.parent()?;
        let tls = if parent.as_ref().is_some_and(|parent| parent.tls) {
            Some(http::parent_tls(&config)?)
        } else {
            None
        };
        Ok(Self {
            parent,
            tls,
            via_token: config
                .via_token
                .clone()
                .unwrap_or_else(|| default_via.to_owned()),
            events: Mutex::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&config.event_log)?,
            ),
            config,
            instance_id: default_via.to_owned(),
        })
    }

    fn record(&self, event: Value) -> Result<(), Error> {
        let mut bytes = serde_json::to_vec(&event)?;
        bytes.push(b'\n');
        let mut events = self.events.lock().map_err(|_| "event log lock poisoned")?;
        events.write_all(&bytes)?;
        Ok(())
    }
}

pub(crate) fn is_reserved(host: &str) -> bool {
    host.eq_ignore_ascii_case("_safeyolo.proxy.internal")
        || host.eq_ignore_ascii_case("_safeyolo.probe.internal")
}

fn clear_readiness(path: &Path, instance_id: &str) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let Ok(marker) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    if marker["instance_id"] == instance_id {
        let _ = std::fs::remove_file(path);
    }
}

/// Removes only this process's socket inode, including during partial startup failure.
struct SocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketPath {
    fn bind(path: &Path) -> Result<(UnixListener, Self), Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                match std::os::unix::net::UnixStream::connect(path) {
                    Ok(_) => {
                        return Err(format!("listener already active: {}", path.display()).into());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        let current = std::fs::symlink_metadata(path)?;
                        if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
                            return Err("socket changed during stale listener cleanup".into());
                        }
                        std::fs::remove_file(path)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(_) => return Err(format!("socket path is not a socket: {}", path.display()).into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let owned = Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        Ok((listener, owned))
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

struct RunningListener {
    agent_id: String,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
    socket: SocketPath,
}

impl RunningListener {
    fn start(
        listener: UnixListener,
        socket: SocketPath,
        agent_id: String,
        runtime: Arc<RwLock<Arc<Runtime>>>,
    ) -> Self {
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(accept_agents(listener, agent_id.clone(), runtime, receiver));
        Self {
            agent_id,
            stop,
            task,
            socket,
        }
    }

    fn stop(self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        drop(self.socket);
        self.task
    }
}

async fn accept_agents(
    listener: UnixListener,
    agent_id: String,
    runtime: Arc<RwLock<Arc<Runtime>>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((socket, _)) => {
                    let identity = ConnectionIdentity { agent_id: agent_id.clone(), connection_id: format!("conn-{}", uuid::Uuid::new_v4().simple()) };
                    connections.spawn(serve_connection(socket, identity, runtime.clone(), stop.clone()));
                }
                Err(error) => {
                    eprintln!("listener accept failed: {error}");
                    // A failed listener cannot leave a healthy readiness marker behind.
                    if let Ok(snapshot) = runtime.read() {
                        clear_readiness(&snapshot.config.readiness_file, &snapshot.instance_id);
                    }
                    break;
                }
            },
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { eprintln!("agent connection task failed: {error}"); }
            }
        }
    }
    drop(listener);
    // Stop keep-alive admission but allow in-flight requests/streams to complete.
    if tokio::time::timeout(Duration::from_secs(10), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

async fn serve_connection(
    socket: UnixStream,
    identity: ConnectionIdentity,
    runtime: Arc<RwLock<Arc<Runtime>>>,
    mut stop: watch::Receiver<bool>,
) {
    let service = service_fn(move |request| {
        let snapshot = runtime.read().expect("runtime read lock").clone();
        http::serve_request(snapshot, identity.clone(), request)
    });
    let connection =
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => if let Err(error) = result { eprintln!("agent HTTP connection: {error}"); },
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            if let Err(error) = connection.await { eprintln!("agent HTTP shutdown: {error}"); }
        }
    }
}

/// Owns listening sockets. Identity is fixed at accept, never taken from client bytes.
pub struct Proxy {
    runtime: Arc<RwLock<Arc<Runtime>>>,
    listeners: HashMap<PathBuf, RunningListener>,
    draining: Vec<JoinHandle<()>>,
    default_via: String,
    readiness_file: PathBuf,
}

impl Proxy {
    pub async fn start(config: Config) -> Result<Self, Error> {
        let default_via = uuid::Uuid::new_v4().simple().to_string();
        let runtime = Arc::new(Runtime::new(config.clone(), &default_via)?);
        let mut proxy = Self {
            runtime: Arc::new(RwLock::new(runtime)),
            listeners: HashMap::new(),
            draining: Vec::new(),
            default_via,
            readiness_file: config.readiness_file.clone(),
        };
        // A readiness marker is useful only after all configured sockets have bound.
        proxy.install_listeners(&config).await?;
        proxy.write_readiness()?;
        Ok(proxy)
    }

    fn write_readiness(&self) -> Result<(), Error> {
        let temporary = self
            .readiness_file
            .with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(
            &temporary,
            serde_json::to_vec(&json!({
            "ready": true, "pid": std::process::id(), "backend": "rust-m2",
            "instance_id": self.default_via,
                "listeners": self.listeners.len(),
            }))?,
        )?;
        std::fs::rename(temporary, &self.readiness_file)?;
        Ok(())
    }

    async fn install_listeners(&mut self, config: &Config) -> Result<(), Error> {
        // Bind additions before changing live state. Failure leaves existing listeners active.
        let mut additions = Vec::new();
        for entry in &config.listeners {
            if !self.listeners.contains_key(&entry.socket_path) {
                let (listener, socket) = SocketPath::bind(&entry.socket_path)?;
                additions.push((listener, socket, entry.agent_id.clone()));
            }
        }
        let removed: Vec<PathBuf> = self
            .listeners
            .iter()
            .filter(|(path, listener)| {
                listener.task.is_finished()
                    || !config.listeners.iter().any(|entry| {
                        &entry.socket_path == *path && entry.agent_id == listener.agent_id
                    })
            })
            .map(|(path, _)| path.clone())
            .collect();
        for path in removed {
            self.draining
                .push(self.listeners.remove(&path).unwrap().stop());
            if let Some(entry) = config
                .listeners
                .iter()
                .find(|entry| entry.socket_path == path)
            {
                let (listener, socket) = SocketPath::bind(&entry.socket_path)?;
                additions.push((listener, socket, entry.agent_id.clone()));
            }
        }
        for (listener, socket, agent) in additions {
            self.listeners.insert(
                socket.path.clone(),
                RunningListener::start(listener, socket, agent, self.runtime.clone()),
            );
        }
        let mut index = 0;
        while index < self.draining.len() {
            if self.draining[index].is_finished() {
                if let Err(error) = self.draining.swap_remove(index).await {
                    eprintln!("draining listener failed: {error}");
                }
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    pub async fn reload(&mut self, config: Config) -> Result<(), Error> {
        let runtime = Arc::new(Runtime::new(config.clone(), &self.default_via)?);
        // Once topology changes begin, readiness is re-published only after commit.
        clear_readiness(&self.readiness_file, &self.default_via);
        self.install_listeners(&config).await?;
        *self
            .runtime
            .write()
            .map_err(|_| "runtime write lock poisoned")? = runtime;
        if self.readiness_file != config.readiness_file {
            clear_readiness(&self.readiness_file, &self.default_via);
            self.readiness_file = config.readiness_file;
        }
        self.write_readiness()
    }

    pub async fn shutdown(mut self) {
        clear_readiness(&self.readiness_file, &self.default_via);
        for (_, listener) in self.listeners.drain() {
            self.draining.push(listener.stop());
        }
        for task in self.draining.drain(..) {
            if let Err(error) = task.await {
                eprintln!("listener shutdown failed: {error}");
            }
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        clear_readiness(&self.readiness_file, &self.default_via);
        for (_, listener) in self.listeners.drain() {
            drop(listener.stop());
        }
    }
}
