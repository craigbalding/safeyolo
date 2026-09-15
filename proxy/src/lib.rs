//! Development proxy: trusted UDS ingress, HTTP/TLS and admitted CONNECT streams.
//! Network policy runs natively or through an explicitly configured temporary
//! Python bridge. The development pipeline does not yet have production parity.

pub mod admin_api;
mod admin_listener;
pub mod admin_shield;
pub mod agent_api;
pub mod approvals;
pub mod circuits;
mod config;
pub mod contracts;
pub mod credential_guard;
pub mod credential_injection;
pub mod credentials;
pub mod grants;
pub mod host_names;
mod http;
pub mod inspection;
pub mod network_guard;
pub mod oauth;
pub mod policy;
mod python_json;
mod python_text;
mod request_headers;
pub mod services;
pub mod tasks;
pub mod test_context;
pub mod tls;
mod tunnels;
pub mod websocket;
mod websocket_relay;

pub use config::{AgentListener, Config, Inspection};

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
pub(crate) type RuntimeState = Arc<RwLock<Arc<Runtime>>>;
pub(crate) type UpgradeTasks = Arc<UpgradeState>;

pub(crate) struct UpgradeState {
    tasks: tokio::sync::Mutex<JoinSet<()>>,
    stop: watch::Receiver<bool>,
}

#[derive(Clone)]
pub(crate) struct ConnectionIdentity {
    agent_id: String,
    connection_id: String,
}

pub(crate) struct Runtime {
    config: Config,
    parent: Option<config::ParentProxy>,
    tls: Option<Arc<rustls::ClientConfig>>,
    certificate_authority: Option<Arc<tls::CertificateAuthority>>,
    passthrough: tunnels::Passthrough,
    scanner: inspection::Scanner,
    policy: Option<policy::Policy>,
    tasks: tasks::Registry,
    admin_address: Option<std::net::SocketAddr>,
    admin_shield: admin_shield::AdminShield,
    network_guard: network_guard::NetworkGuard,
    via_token: String,
    events: Mutex<File>,
    temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
    instance_id: String,
}

impl Runtime {
    fn new(
        config: Config,
        default_via: &str,
        temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
        previous: Option<&Runtime>,
        admin_address: Option<std::net::SocketAddr>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let admin_shield = admin_shield::AdminShield::new(
            config.admin_port.unwrap_or(9090),
            &config.admin_shield_extra_ports,
        )?;
        let tasks = previous
            .map(|runtime| runtime.tasks.clone())
            .unwrap_or_default();
        let policy = config
            .policy_file
            .as_ref()
            .map(
                |path| match previous.and_then(|runtime| runtime.policy.as_ref()) {
                    Some(policy) => policy.reload_from_path_at(path, policy::current_time_ms()),
                    None => policy::Policy::from_path(path),
                },
            )
            .transpose()?;
        let network_guard = previous
            .map(|runtime| runtime.network_guard.clone())
            .unwrap_or_default();
        let scanner = inspection::Scanner::default();
        if let Some(inspection) = &config.inspection {
            let source = std::fs::read_to_string(&inspection.policy_file)?;
            let format = match inspection
                .policy_file
                .extension()
                .and_then(|value| value.to_str())
            {
                Some("toml") => policy::Format::Toml,
                Some("yaml" | "yml") => policy::Format::Yaml,
                _ => policy::Format::Json,
            };
            let document = policy::parse_document(&source, format)?;
            scanner.load_policy_config(&Value::Object(document))?;
        }
        let passthrough = tunnels::Passthrough::new(
            &config.ignore_hosts,
            &std::env::var("SAFEYOLO_IGNORE_CIDRS").unwrap_or_default(),
        )?;
        let parent = config.parent()?;
        let certificate_authority = config
            .tls_ca_file
            .as_deref()
            .map(tls::CertificateAuthority::load)
            .transpose()?
            .map(Arc::new);
        let tls = if parent.as_ref().is_some_and(|parent| parent.tls)
            || certificate_authority.is_some()
        {
            Some(http::parent_tls(&config)?)
        } else {
            None
        };
        Ok(Self {
            temporary_policy_lock,
            parent,
            tls,
            certificate_authority,
            passthrough,
            scanner,
            policy,
            tasks,
            admin_address,
            admin_shield,
            network_guard,
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
    // A DNS root dot denotes the same endpoint. Classify that spelling locally
    // too, so a parent proxy never receives a reserved API request or token.
    let host = host.strip_suffix('.').unwrap_or(host);
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
    let upgrades: UpgradeTasks = Arc::new(UpgradeState {
        tasks: tokio::sync::Mutex::new(JoinSet::new()),
        stop: stop.clone(),
    });
    let request_upgrades = upgrades.clone();
    let service = service_fn(move |request| {
        http::serve_request(
            runtime.clone(),
            identity.clone(),
            request,
            None,
            Some(request_upgrades.clone()),
        )
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(socket), service)
        .with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => if let Err(error) = result { eprintln!("agent HTTP connection: {error}"); },
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            if let Err(error) = connection.await { eprintln!("agent HTTP shutdown: {error}"); }
        }
    }
    // Upgrades receive the same shutdown signal as plain HTTP. Their own
    // protocol driver drains active responses; the listener's existing timeout
    // still bounds the lifetime of this connection and its owned tasks.
    let mut upgrades = upgrades.tasks.lock().await;
    while upgrades.join_next().await.is_some() {}
}

/// Owns listening sockets. Identity is fixed at accept, never taken from client bytes.
pub struct Proxy {
    runtime: Arc<RwLock<Arc<Runtime>>>,
    listeners: HashMap<PathBuf, RunningListener>,
    admin: Option<admin_listener::Running>,
    draining: Vec<JoinHandle<()>>,
    default_via: String,
    readiness_file: PathBuf,
    temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Proxy {
    pub async fn start(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let prepared_admin = admin_listener::Prepared::bind(&config).await?;
        let admin_address = prepared_admin
            .as_ref()
            .map(admin_listener::Prepared::address);
        let default_via = uuid::Uuid::new_v4().simple().to_string();
        let temporary_policy_lock = Arc::new(tokio::sync::Mutex::new(()));
        let runtime = Arc::new(Runtime::new(
            config.clone(),
            &default_via,
            temporary_policy_lock.clone(),
            None,
            admin_address,
        )?);
        let mut proxy = Self {
            runtime: Arc::new(RwLock::new(runtime)),
            listeners: HashMap::new(),
            admin: None,
            draining: Vec::new(),
            default_via,
            readiness_file: config.readiness_file.clone(),
            temporary_policy_lock,
        };
        // A readiness marker is useful only after all configured sockets have bound.
        // Keep the prepared operator socket locally owned until agent binds succeed.
        proxy.install_listeners(&config).await?;
        proxy.admin = prepared_admin.map(|listener| listener.start(proxy.runtime.clone()));
        proxy.write_readiness()?;
        Ok(proxy)
    }

    fn write_readiness(&self) -> Result<(), Error> {
        let temporary = self
            .readiness_file
            .with_extension(format!("{}.tmp", std::process::id()));
        let mut marker = json!({
            "ready": true, "pid": std::process::id(), "backend": "rust-m2",
            "instance_id": self.default_via, "listeners": self.listeners.len(),
        });
        if let Some(listener) = &self.admin {
            marker["admin_port"] = Value::from(listener.address().port());
        }
        std::fs::write(&temporary, serde_json::to_vec(&marker)?)?;
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
        let previous = self
            .runtime
            .read()
            .map_err(|_| "runtime read lock poisoned")?
            .clone();
        let runtime = Arc::new(Runtime::new(
            config.clone(),
            &self.default_via,
            self.temporary_policy_lock.clone(),
            Some(&previous),
            self.admin.as_ref().map(admin_listener::Running::address),
        )?);
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
        if let Some(listener) = self.admin.take() {
            self.draining.push(listener.stop());
        }
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
