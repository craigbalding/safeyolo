//! Development proxy: trusted UDS ingress, HTTP/TLS and admitted CONNECT streams.
//! Network policy runs natively or through an explicitly configured temporary
//! Python bridge. The development pipeline does not yet have production parity.

pub mod admin_api;
mod admin_listener;
pub mod admin_shield;
pub mod agent_api;
pub mod agent_discovery;
pub mod approvals;
pub mod audit;
mod circuit_runtime;
pub mod circuits;
mod config;
mod connection_tasks;
pub mod contracts;
pub mod credential_guard;
mod credential_hmac;
pub mod credential_injection;
mod credential_text;
pub mod credentials;
mod flow_recorder;
#[cfg(test)]
mod flow_runtime_tests;
pub mod flow_store;
mod flow_writer;
pub mod grants;
pub mod host_names;
mod http;
pub mod http_content;
pub mod ignored_host_logger;
pub mod inspection;
pub mod memory_monitor;
mod memory_runtime;
pub mod metrics;
pub mod network_guard;
pub mod oauth;
mod operator_stats;
pub mod policy;
mod policy_runtime;
mod python_json;
mod python_text;
mod request_headers;
mod request_logger;
mod request_trace;
#[cfg(test)]
mod service_catalog_tests;
pub mod services;
pub mod tasks;
pub mod test_context;
pub mod tls;
pub mod trace;
pub(crate) mod traffic_view;
#[cfg(test)]
mod traffic_view_runtime_tests;
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
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use ring::digest::{SHA256, digest};
use serde_json::{Value, json};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type RuntimeState = Arc<RwLock<Arc<Runtime>>>;
pub(crate) type UpgradeTasks = Arc<connection_tasks::ConnectionTasks>;

/// Owns the process boundary at which a newly persisted vault snapshot becomes
/// active. Refresh publication is rejected after shutdown begins, while the
/// vault rollback callback remains allowed to restore the prior active view.
#[derive(Clone, Default)]
struct CredentialActivation {
    closing: Arc<AtomicBool>,
    rejected: Arc<AtomicBool>,
    active: Arc<Mutex<Vec<credentials::CredentialMetadata>>>,
}
impl CredentialActivation {
    fn activate(
        &self,
        metadata: &[credentials::CredentialMetadata],
    ) -> std::result::Result<(), ()> {
        if self.closing.load(Ordering::Acquire) {
            // Reject the candidate exactly once. Vault rollback invokes the
            // same callback with the old metadata and must still succeed.
            if !self.rejected.swap(true, Ordering::AcqRel) {
                return Err(());
            }
            return Ok(());
        }
        let Ok(mut active) = self.active.lock() else {
            return Err(());
        };
        *active = metadata.to_vec();
        Ok(())
    }
    fn close(&self) {
        self.closing.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionIdentity {
    agent_id: String,
    connection_id: String,
    source_id: Option<String>,
}

impl ConnectionIdentity {
    fn audit_attribution(&self) -> audit::Attribution {
        audit::Attribution {
            evidence_owner: Some(self.agent_id.clone()),
            trusted_transport_identity: Some(self.agent_id.clone()),
            initiator: Some(audit::Initiator::Unknown),
            status: Some(audit::AttributionStatus::Resolved),
            provenance: Some(
                serde_json::json!({
                    "transport_source": "uds",
                    "uds_agent": self.agent_id.chars().take(128).collect::<String>(),
                })
                .into(),
            ),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Runtime {
    config: Config,
    parent: Option<config::ParentProxy>,
    tls: Option<Arc<rustls::ClientConfig>>,
    certificate_authority: Option<Arc<tls::CertificateAuthority>>,
    passthrough: tunnels::Passthrough,
    scanner: inspection::Scanner,
    policy: Option<policy::Policy>,
    /// The encrypted credential snapshot is retained across policy reloads;
    /// gateway selection consumes only the authorized vault reference.
    vault: Option<credentials::Vault>,
    /// One process-owned refresh coordinator shares flights across requests.
    /// Its vault clone is the same state used for credential injection.
    oauth: Option<oauth::OAuthRefresh>,
    credential_activation: CredentialActivation,
    /// Durable identity of the loaded vault. The key fingerprint is only used
    /// to decide whether a reload may retain the existing Vault/coordinator;
    /// it is never included in Runtime diagnostics.
    vault_identity: Option<VaultIdentity>,
    /// One process-owned store for contract bindings and risky grants. Clones
    /// share reservations; reloads reconcile its durable view before publish.
    gateway_grants: Option<grants::Store>,
    credential_guard: Option<credential_guard::CredentialGuard>,
    credential_key_empty: bool,
    tasks: tasks::Registry,
    service_mutations: admin_api::ServiceMutationOwner,
    admin_address: Option<std::net::SocketAddr>,
    admin_shield: admin_shield::AdminShield,
    network_guard: network_guard::NetworkGuard,
    circuits: circuits::CircuitBreaker,
    test_context: test_context::TestContext,
    flow_recorder: Arc<flow_recorder::FlowRecorder>,
    traffic_view: Arc<traffic_view::TrafficView>,
    audit: Arc<audit::Writer>,
    request_logger: Arc<request_logger::RequestLogger>,
    agent_discovery: Arc<agent_discovery::AgentDiscovery>,
    metrics: Arc<metrics::Metrics>,
    traces: Arc<trace::TraceStore>,
    memory_monitor: Arc<memory_monitor::MemoryMonitor>,
    via_token: String,
    events: Arc<Mutex<File>>,
    temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
    instance_id: String,
}

impl Runtime {
    #[cfg(test)]
    fn new(
        config: Config,
        default_via: &str,
        temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
        previous: Option<&Runtime>,
        admin_address: Option<std::net::SocketAddr>,
    ) -> Result<Self, Error> {
        Self::load(
            config,
            default_via,
            temporary_policy_lock,
            previous,
            admin_address,
            &mut None,
        )
    }

    fn load(
        config: Config,
        default_via: &str,
        temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
        previous: Option<&Runtime>,
        admin_address: Option<std::net::SocketAddr>,
        service_files: &mut Option<services::CatalogMetadata>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let admin_shield = admin_shield::AdminShield::new(
            config.admin_port.unwrap_or(9090),
            &config.admin_shield_extra_ports,
        )?;
        let tasks = previous
            .map(|runtime| runtime.tasks.clone())
            .unwrap_or_default();
        let service_mutations = previous
            .map(|runtime| runtime.service_mutations.clone())
            .unwrap_or_default();
        let audit = match previous {
            Some(runtime) => runtime.audit.clone(),
            None => Arc::new(audit::Writer::new(
                config.audit_log_path.clone().unwrap_or_else(|| {
                    std::env::var_os("SAFEYOLO_LOG_PATH")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("/app/logs/safeyolo.jsonl"))
                }),
                audit::Settings::from_env()?,
            )),
        };
        let result = (|| {
            let registry = load_service_catalog(&config, &audit, service_files)?;
            let mut policy = config
                .policy_file
                .as_ref()
                .map(|path| {
                    policy_runtime::load(
                        path,
                        registry,
                        previous.and_then(|runtime| runtime.policy.as_ref()),
                        &audit,
                    )
                })
                .transpose()?;
            // A reload with the same vault path and key material must retain
            // the old state object: its OAuth flight table is part of the
            // process-owned attempt domain. A changed key/path starts a fresh
            // domain; an invalid replacement is therefore unavailable rather
            // than silently sharing the old coordinator.
            let vault_material = gateway_vault_material(&config);
            let retained = previous.and_then(|runtime| {
                vault_material
                    .as_ref()
                    .filter(|material| runtime.vault_identity.as_ref() == Some(&material.identity))
                    .map(|_| runtime)
            });
            let loaded = if retained.is_some() {
                None
            } else {
                load_gateway_vault(vault_material.as_ref())?
            };
            let (vault, oauth, vault_identity) = if let Some(runtime) = retained {
                (
                    runtime.vault.clone(),
                    runtime.oauth.clone(),
                    runtime.vault_identity.clone(),
                )
            } else if let Some(loaded) = loaded {
                let oauth = Some(oauth::OAuthRefresh::new(loaded.vault.clone()));
                (Some(loaded.vault), oauth, Some(loaded.identity))
            } else {
                (None, None, None)
            };
            let credential_activation = previous
                .map(|runtime| runtime.credential_activation.clone())
                .unwrap_or_default();
            if let Some(vault) = vault.as_ref() {
                let metadata = vault.metadata()?;
                credential_activation
                    .activate(&metadata)
                    .map_err(|_| "vault credential activation unavailable")?;
            }
            let gateway_grants = if let Some(previous_store) = previous
                .filter(|runtime| runtime.config.policy_file == config.policy_file)
                .and_then(|runtime| runtime.gateway_grants.as_ref())
            {
                let store = previous_store.clone();
                store.reload(time::OffsetDateTime::now_utc(), |_| Ok(()))?;
                Some(store)
            } else if let Some(path) = config
                .policy_file
                .as_ref()
                .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
                && config.gateway_builtin_services_dir.is_some()
            {
                Some(grants::Store::open(path, time::OffsetDateTime::now_utc())?)
            } else {
                None
            };
            // Store::open/reload may normalize legacy grant metadata in place.
            // Re-observe after that durable normalization so the accepted
            // Runtime watermark describes the bytes whose token was exposed;
            // otherwise the policy watcher performs a synthetic second
            // publication immediately after startup/reload.
            if let Some(policy) = policy.as_mut()
                && gateway_grants.is_some()
            {
                policy
                    .observe_baseline_files(previous.and_then(|runtime| runtime.policy.as_ref()))?;
            }
            // CredentialGuard is a native generation owned by the same Runtime
            // publication as the accepted Policy. Reuse the key on ordinary
            // reloads; an empty environment key deliberately retries loading
            // the configured source, matching the source lifecycle contract.
            let (credential_guard, credential_key_empty) = if let Some(policy) = policy.as_ref() {
                let previous_guard = previous.and_then(|runtime| runtime.credential_guard.as_ref());
                let key = if previous_guard.is_none()
                    || previous.is_some_and(|runtime| runtime.credential_key_empty)
                {
                    let environment = std::env::var_os("CREDGUARD_HMAC_SECRET").map(|value| {
                        zeroize::Zeroizing::new(std::os::unix::ffi::OsStringExt::into_vec(value))
                    });
                    Some(credential_hmac::load(
                        &config.data_dir().join("hmac_secret"),
                        environment
                            .as_ref()
                            .map(|value| std::os::unix::ffi::OsStrExt::from_bytes(value)),
                    )?)
                } else {
                    None
                };
                let seed = previous_guard
                    .cloned()
                    .unwrap_or_else(|| credential_guard::CredentialGuard::new(&[]));
                let (guard, _) = seed.prepare_policy_with_key(
                    policy,
                    key.as_ref().map(credential_hmac::HmacSecret::as_bytes),
                )?;
                (
                    Some(guard),
                    key.as_ref()
                        .is_some_and(credential_hmac::HmacSecret::is_empty),
                )
            } else {
                (
                    previous.and_then(|runtime| runtime.credential_guard.clone()),
                    previous.is_none_or(|runtime| runtime.credential_key_empty),
                )
            };
            let network_guard = previous
                .map(|runtime| runtime.network_guard.clone())
                .unwrap_or_default();
            let circuits = previous
                .map(|runtime| runtime.circuits.clone())
                .unwrap_or_default();
            let test_context = previous
                .map(|runtime| runtime.test_context.clone())
                .unwrap_or_default();
            let request_logger = previous
                .map(|runtime| runtime.request_logger.clone())
                .unwrap_or_default();
            let agent_discovery = previous
                .map(|runtime| runtime.agent_discovery.clone())
                .unwrap_or_else(|| Arc::new(agent_discovery::AgentDiscovery::new()));
            let metrics = previous
                .map(|runtime| runtime.metrics.clone())
                .unwrap_or_else(|| Arc::new(metrics::Metrics::new(circuit_runtime::now)));
            let traces = previous
                .map(|runtime| runtime.traces.clone())
                .unwrap_or_else(|| Arc::new(trace::TraceStore::new(trace::Settings::from_env())));
            let memory_monitor = previous
                .map(|runtime| runtime.memory_monitor.clone())
                .unwrap_or_else(|| Arc::new(memory_monitor::MemoryMonitor::new()));
            let flow_recorder = match previous {
                Some(runtime) => runtime.flow_recorder.clone(),
                None => Arc::new(flow_recorder::FlowRecorder::start(
                    config.flow_store_enabled,
                    &config.flow_store_db_path,
                    policy.as_ref(),
                )),
            };
            let traffic_view = previous
                .map(|runtime| runtime.traffic_view.clone())
                .unwrap_or_else(|| {
                    Arc::new(traffic_view::TrafficView::new(
                        config.flow_pruner_max,
                        config.flow_pruner_max_body_bytes,
                    ))
                });
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
                || config.upstream_ca_file.is_some()
            {
                Some(http::parent_tls(&config)?)
            } else {
                None
            };
            let mut startup_transitions = Vec::new();
            if previous.is_none()
                && let Some(path) = circuit_runtime::state_path(&config)
            {
                match circuits.load_file(path, circuit_runtime::now(), &mut rand::random::<f64>) {
                    Ok(outcome) => startup_transitions = outcome.events,
                    Err(_) => eprintln!("Circuit state load failed"),
                }
            }
            let runtime = Self {
                temporary_policy_lock,
                parent,
                tls,
                certificate_authority,
                passthrough,
                scanner,
                policy,
                vault,
                oauth,
                credential_activation,
                vault_identity,
                gateway_grants,
                credential_guard,
                credential_key_empty,
                tasks,
                service_mutations,
                admin_address,
                admin_shield,
                network_guard,
                circuits,
                test_context,
                flow_recorder,
                traffic_view,
                audit: audit.clone(),
                request_logger,
                agent_discovery,
                metrics,
                traces,
                memory_monitor,
                via_token: config
                    .via_token
                    .clone()
                    .unwrap_or_else(|| default_via.to_owned()),
                events: Arc::new(Mutex::new(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&config.event_log)?,
                )),
                config,
                instance_id: default_via.to_owned(),
            };
            if circuit_runtime::record_transitions(&runtime, &startup_transitions, None) {
                eprintln!("Circuit startup evidence write failed");
            }
            if previous.is_none() {
                runtime.configure_declarations()?;
            }
            if !runtime
                .agent_discovery
                .matches_path(&runtime.config.agent_map_file)?
                && let Err(error) = runtime
                    .agent_discovery
                    .configure(&runtime.config.agent_map_file, &runtime.audit)
            {
                // The source addon dispatcher logs configuration exceptions and
                // keeps running. Reporting metadata is not a startup requirement.
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "Agent discovery configuration failed: {error}"
                );
            }
            Ok(runtime)
        })();
        // Catalog errors can start the writer before a Runtime exists. Drain
        // that startup owner's diagnostics; a rejected reload keeps its writer.
        if previous.is_none()
            && result.is_err()
            && !matches!(audit.shutdown(Duration::from_secs(5)), Ok(true))
        {
            let _ = writeln!(
                std::io::stderr().lock(),
                "Startup audit writer shutdown did not complete"
            );
        }
        result
    }

    fn configure_declarations(&self) -> Result<(), Error> {
        let options = test_context::Options {
            block: self.config.test_context_block,
            inject_declared: self.config.test_context_inject_declared,
            declared_ttl: self.config.test_context_declared_ttl.clone(),
        };
        match &self.policy {
            Some(policy) => {
                policy.configure_test_context_declarations(&self.test_context, options)?
            }
            None => self.test_context.configure_declarations(None, options)?,
        }
        Ok(())
    }

    fn observe_agent(&self, agent: &str, source: Option<&str>) {
        // Source identity resolution catches lookup/reload failures before
        // recording the already trusted UDS owner. Discovery metadata never
        // supplies or replaces the native listener identity.
        if source.is_some()
            && let Err(error) = self.agent_discovery.reload(&self.audit)
        {
            let _ = writeln!(
                std::io::stderr().lock(),
                "Agent discovery refresh failed: {error}"
            );
        }
        if let Err(error) = self
            .agent_discovery
            .observe_trusted(agent, circuit_runtime::now)
        {
            let _ = writeln!(
                std::io::stderr().lock(),
                "Agent discovery observation failed: {error}"
            );
        }
    }

    fn record(&self, event: Value) -> Result<(), Error> {
        self.record_bytes(serde_json::to_vec(&event)?)
    }

    fn record_bytes(&self, mut bytes: Vec<u8>) -> Result<(), Error> {
        bytes.push(b'\n');
        let mut events = self.events.lock().map_err(|_| "event log lock poisoned")?;
        events.write_all(&bytes)?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct VaultIdentity {
    vault_path: PathBuf,
    key_path: PathBuf,
    key_fingerprint: [u8; 32],
}

struct VaultMaterial {
    identity: VaultIdentity,
    passphrase: credentials::Secret,
}

fn gateway_vault_material(config: &Config) -> Option<VaultMaterial> {
    let data_dir = config.data_dir();
    let vault_path = data_dir.join("vault.yaml.enc");
    let key_path = data_dir.join("vault.key");
    let passphrase = std::fs::read_to_string(&key_path).ok()?.trim().to_owned();
    if passphrase.is_empty() {
        return None;
    }
    let fingerprint = digest(&SHA256, passphrase.as_bytes());
    let mut key_fingerprint = [0; 32];
    key_fingerprint.copy_from_slice(fingerprint.as_ref());
    Some(VaultMaterial {
        identity: VaultIdentity {
            vault_path,
            key_path,
            key_fingerprint,
        },
        passphrase: credentials::Secret::new(passphrase),
    })
}

struct LoadedGatewayVault {
    vault: credentials::Vault,
    identity: VaultIdentity,
}

/// Load the existing Python-compatible vault material when both files are
/// present. The passphrase is process-local configuration and is never copied
/// into Runtime diagnostics. A missing or unusable vault leaves the gateway
/// unavailable so a selected request fails closed at the injection boundary.
fn load_gateway_vault(
    material: Option<&VaultMaterial>,
) -> Result<Option<LoadedGatewayVault>, Error> {
    let Some(material) = material else {
        return Ok(None);
    };
    if !material.identity.vault_path.exists() {
        return Ok(None);
    }
    match credentials::Vault::unlock(&material.identity.vault_path, &material.passphrase) {
        Ok(vault) => Ok(Some(LoadedGatewayVault {
            vault,
            identity: material.identity.clone(),
        })),
        Err(error) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "Gateway vault unavailable: {error}"
            );
            Ok(None)
        }
    }
}

fn load_service_catalog(
    config: &Config,
    writer: &audit::Writer,
    service_files: &mut Option<services::CatalogMetadata>,
) -> Result<Option<Arc<services::Registry>>, Error> {
    match (
        &config.gateway_builtin_services_dir,
        &config.gateway_services_dir,
    ) {
        (Some(builtin), Some(user)) => {
            let load = services::Registry::load_directories(builtin, user, &mut |problem| {
                record_service_problem(writer, problem);
            })?;
            *service_files = Some(load.metadata);
            Ok(Some(Arc::new(load.result?)))
        }
        _ => {
            *service_files = None;
            Ok(None)
        }
    }
}

fn record_service_problem(writer: &audit::Writer, problem: &services::ServiceLoadProblem) {
    let filename = problem
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let mut event = audit::Event::new(
        "ops.config_error",
        audit::Kind::Ops,
        audit::Severity::Medium,
        format!("Service definition {filename} failed to load"),
    );
    event.addon = Some("service-loader".into());
    event.details = json!({
        "file": filename,
        "error_type": problem.kind.error_type(),
        "error": network_guard::sanitize(&problem.message),
    })
    .into();
    if writer.emit(event).is_err() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "Service config-error audit submission failed"
        );
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
    fn is_current(&self) -> std::io::Result<bool> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => Ok(metadata.dev() == self.device && metadata.ino() == self.inode),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

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
    listener: Arc<UnixListener>,
    agent_id: String,
    source_id: Option<String>,
    stop: Arc<watch::Sender<bool>>,
    task: JoinHandle<()>,
    socket: SocketPath,
}

impl RunningListener {
    fn start(
        listener: impl Into<Arc<UnixListener>>,
        socket: SocketPath,
        agent_id: String,
        source_id: Option<String>,
        runtime: Arc<RwLock<Arc<Runtime>>>,
    ) -> Self {
        let listener = listener.into();
        let (stop, receiver) = watch::channel(false);
        let stop = Arc::new(stop);
        let task = tokio::spawn(accept_agents(
            listener.clone(),
            agent_id.clone(),
            source_id.clone(),
            runtime,
            Arc::downgrade(&stop),
            receiver,
        ));
        Self {
            listener,
            agent_id,
            source_id,
            stop,
            task,
            socket,
        }
    }

    fn retire(self) -> (Arc<UnixListener>, SocketPath, JoinHandle<()>) {
        let _ = self.stop.send(true);
        (self.listener, self.socket, self.task)
    }

    fn stop(self) -> JoinHandle<()> {
        let (listener, socket, task) = self.retire();
        drop(listener);
        drop(socket);
        task
    }
}

async fn accept_agents(
    listener: Arc<UnixListener>,
    agent_id: String,
    source_id: Option<String>,
    runtime: Arc<RwLock<Arc<Runtime>>>,
    stop_signal: std::sync::Weak<watch::Sender<bool>>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((socket, _)) => {
                    let identity = ConnectionIdentity {
                        agent_id: agent_id.clone(),
                        connection_id: format!("conn-{}", uuid::Uuid::new_v4().simple()),
                        source_id: source_id.clone(),
                    };
                    // Register before spawning so even an unpolled canceled
                    // task owns cleanup. One guard spans all inner upgrades.
                    let memory = match runtime.read() {
                        Ok(runtime) => Some(memory_runtime::Client::new(&runtime, &identity.connection_id)),
                        Err(_) => {
                            let _ = writeln!(std::io::stderr().lock(), "Memory monitor runtime unavailable");
                            None
                        }
                    };
                    let connection_runtime = runtime.clone();
                    let connection_stop = stop.clone();
                    connections.spawn(async move {
                        let _memory = memory;
                        let tasks = connection_tasks::ConnectionTasks::new(connection_stop.clone());
                        let driver_tasks = tasks.clone();
                        tasks.run(serve_connection(socket, identity, connection_runtime, connection_stop, driver_tasks)).await;
                    });
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
    // Cleanup supervisors are never aborted: they cancel transport tasks after
    // the existing grace and join tracked transport tasks before dropping the client.
    if let Some(stop_signal) = stop_signal.upgrade() {
        stop_signal.send_replace(true);
    }
    while connections.join_next().await.is_some() {}
}

async fn serve_connection(
    socket: UnixStream,
    identity: ConnectionIdentity,
    runtime: Arc<RwLock<Arc<Runtime>>>,
    mut stop: watch::Receiver<bool>,
    upgrades: UpgradeTasks,
) -> Result<(), Error> {
    let request_upgrades = upgrades.clone();
    let service = service_fn(move |request| {
        http::serve_request(
            runtime.clone(),
            identity.clone(),
            request,
            None,
            request_upgrades.clone(),
            true,
        )
    });
    let connection = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(socket), service)
        .with_upgrades();
    tokio::pin!(connection);
    if *stop.borrow() {
        connection.as_mut().graceful_shutdown();
    }
    let result = tokio::select! {
        result = &mut connection => result,
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = &result {
        eprintln!("agent HTTP connection: {error}");
    }
    result.map_err(Into::into)
}

type PreparedListeners = HashMap<PathBuf, (Arc<UnixListener>, SocketPath)>;

/// Owns listening sockets. Identity is fixed at accept, never taken from client bytes.
pub struct Proxy {
    runtime: Arc<RwLock<Arc<Runtime>>>,
    listeners: HashMap<PathBuf, RunningListener>,
    admin: Option<admin_listener::Running>,
    draining: Vec<JoinHandle<()>>,
    default_via: String,
    readiness_file: PathBuf,
    temporary_policy_lock: Arc<tokio::sync::Mutex<()>>,
    circuit_snapshots: Option<circuit_runtime::Snapshots>,
    service_files: Option<services::CatalogMetadata>,
    service_check_at: Option<tokio::time::Instant>,
    policy_check_at: Option<tokio::time::Instant>,
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
        let (runtime, service_files) = {
            let config = config.clone();
            let default_via = default_via.clone();
            let temporary_policy_lock = temporary_policy_lock.clone();
            tokio::task::spawn_blocking(move || {
                let mut service_files = None;
                let runtime = Runtime::load(
                    config,
                    &default_via,
                    temporary_policy_lock,
                    None,
                    admin_address,
                    &mut service_files,
                )?;
                policy_runtime::accepted(runtime.policy.as_ref(), &runtime.audit);
                memory_runtime::running(&runtime);
                Ok::<_, Error>((Arc::new(runtime), service_files))
            })
            .await??
        };
        let mut proxy = Self {
            runtime: Arc::new(RwLock::new(runtime)),
            listeners: HashMap::new(),
            admin: None,
            draining: Vec::new(),
            default_via,
            readiness_file: config.readiness_file.clone(),
            temporary_policy_lock,
            circuit_snapshots: None,
            service_check_at: service_files.as_ref().map(|_| tokio::time::Instant::now()),
            service_files,
            policy_check_at: config
                .policy_file
                .as_ref()
                .map(|_| tokio::time::Instant::now()),
        };
        // A readiness marker is useful only after all configured sockets have bound.
        // Keep the prepared operator socket locally owned until agent binds succeed.
        let additions = proxy.prepare_listeners(&config)?;
        proxy.commit_listeners(&config, additions);
        proxy.admin = prepared_admin.map(|listener| listener.start(proxy.runtime.clone()));
        proxy.write_readiness()?;
        if circuit_runtime::state_path(&config).is_some() {
            proxy.circuit_snapshots =
                Some(circuit_runtime::Snapshots::start(proxy.runtime.clone())?);
        }
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
        if let Some(reload_id) = &self
            .runtime
            .read()
            .map_err(|_| "runtime read lock poisoned")?
            .config
            .reload_id
        {
            marker["reload_id"] = Value::from(reload_id.clone());
        }
        if let Some(listener) = &self.admin {
            marker["admin_port"] = Value::from(listener.address().port());
        }
        std::fs::write(&temporary, serde_json::to_vec(&marker)?)?;
        std::fs::rename(temporary, &self.readiness_file)?;
        Ok(())
    }

    fn prepare_listeners(&self, config: &Config) -> Result<PreparedListeners, Error> {
        // Bind every new path before changing active identities or readiness.
        let mut additions = HashMap::new();
        for entry in &config.listeners {
            let reusable = self
                .listeners
                .get(&entry.socket_path)
                .map(|listener| listener.socket.is_current())
                .transpose()?
                .unwrap_or(false);
            if !reusable {
                let (listener, socket) = SocketPath::bind(&entry.socket_path)?;
                additions.insert(entry.socket_path.clone(), (Arc::new(listener), socket));
            }
        }
        Ok(additions)
    }

    fn commit_listeners(&mut self, config: &Config, mut additions: PreparedListeners) {
        let removed: Vec<PathBuf> = self
            .listeners
            .iter()
            .filter(|(path, listener)| {
                additions.contains_key(*path)
                    || listener.task.is_finished()
                    || !config.listeners.iter().any(|entry| {
                        &entry.socket_path == *path
                            && entry.agent_id == listener.agent_id
                            && entry.source_id() == listener.source_id
                    })
            })
            .map(|(path, _)| path.clone())
            .collect();
        for path in removed {
            let previous = self.listeners.remove(&path).unwrap();
            if config
                .listeners
                .iter()
                .any(|entry| entry.socket_path == path)
                && !additions.contains_key(&path)
            {
                // Transfer the existing socket and its inode owner. Existing
                // clients drain with their accepted identity; only future
                // accepts use the replacement identity/source configuration.
                let (listener, socket, task) = previous.retire();
                self.draining.push(task);
                additions.insert(path, (listener, socket));
            } else {
                self.draining.push(previous.stop());
            }
        }
        for entry in &config.listeners {
            if let Some((listener, socket)) = additions.remove(&entry.socket_path) {
                self.listeners.insert(
                    entry.socket_path.clone(),
                    RunningListener::start(
                        listener,
                        socket,
                        entry.agent_id.clone(),
                        entry.source_id(),
                        self.runtime.clone(),
                    ),
                );
            }
        }
    }

    async fn reap_listeners(&mut self) {
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
    }

    /// Wait for the next process-owned catalog check. With no configured
    /// catalog this stays pending. The caller can cancel this wait on shutdown
    /// or explicit reload, then arm it again with the accepted configuration.
    pub async fn wait_for_service_catalog_check(&self) {
        match self.service_check_at {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    }

    /// Check configured service files and publish one complete candidate when
    /// their metadata changed. Embedded callers must drive this check; the
    /// native executable does so in its sole configuration control loop.
    pub async fn reload_services_if_changed(&mut self) -> Result<bool, Error> {
        let result = (|| {
            let previous = self
                .runtime
                .read()
                .map_err(|_| "runtime read lock poisoned")?
                .clone();
            self.reload_service_policy(&previous)
        })();
        // Source waits after every attempt, including rejection. Missed checks
        // never produce a burst of catch-up loads.
        self.service_check_at = self
            .service_files
            .as_ref()
            .map(|_| tokio::time::Instant::now() + Duration::from_secs(2));
        result
    }

    fn reload_service_policy(&mut self, previous: &Runtime) -> Result<bool, Error> {
        let config = &previous.config;
        match (
            &config.gateway_builtin_services_dir,
            &config.gateway_services_dir,
        ) {
            (Some(builtin), Some(user)) => {
                let files = services::scan_service_files(builtin, user)?;
                if self.service_files.as_ref() == Some(&files) {
                    Ok(false)
                } else {
                    // A reached load consumes its pre-read metadata, including
                    // when a later policy compile rejects the candidate.
                    let registry =
                        load_service_catalog(config, &previous.audit, &mut self.service_files)?;
                    let policy = policy_runtime::load(
                        config
                            .policy_file
                            .as_ref()
                            .ok_or("service catalog requires policy_file")?,
                        registry,
                        Some(
                            previous
                                .policy
                                .as_ref()
                                .ok_or("service catalog requires native policy")?,
                        ),
                        &previous.audit,
                    )?;
                    self.publish_policy(previous, policy)?;
                    Ok(true)
                }
            }
            _ => Ok(false),
        }
    }

    /// Wait for the next baseline/addons/list check. Without a configured native
    /// policy this remains pending; the control loop can cancel it on shutdown.
    pub async fn wait_for_policy_check(&self) {
        match self.policy_check_at {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    }

    /// Reload a changed baseline against the accepted service registry. Keep
    /// file observation and publication separate from catalog change detection.
    pub async fn reload_policy_if_changed(&mut self) -> Result<bool, Error> {
        let result = (|| {
            let previous = self
                .runtime
                .read()
                .map_err(|_| "runtime read lock poisoned")?
                .clone();
            let Some(policy) = previous.policy.as_ref() else {
                return Ok(false);
            };
            if !policy.baseline_files_changed()? {
                return Ok(false);
            }
            let candidate = policy_runtime::load(
                previous
                    .config
                    .policy_file
                    .as_ref()
                    .ok_or("native policy requires policy_file")?,
                policy.gateway().and_then(|gateway| gateway.registry()),
                Some(policy),
                &previous.audit,
            )?;
            self.publish_policy(&previous, candidate)?;
            Ok(true)
        })();
        // Every reached attempt owns its next deadline, including a poisoned
        // Runtime lock or rejected candidate. Catalog checks have their own wait.
        self.policy_check_at = self
            .policy_check_at
            .map(|_| tokio::time::Instant::now() + Duration::from_secs(2));
        result
    }

    fn publish_policy(&self, previous: &Runtime, mut policy: policy::Policy) -> Result<(), Error> {
        let previous_guard = previous
            .credential_guard
            .as_ref()
            .ok_or("native credential guard is unavailable")?;
        let (credential_guard, _) = previous_guard.prepare_policy(&policy)?;
        let gateway_grants = if let Some(store) = previous.gateway_grants.as_ref() {
            let store = store.clone();
            store.reload(time::OffsetDateTime::now_utc(), |_| Ok(()))?;
            Some(store)
        } else {
            None
        };
        if gateway_grants.is_some() {
            policy.observe_baseline_files(Some(
                previous
                    .policy
                    .as_ref()
                    .ok_or("native policy is unavailable")?,
            ))?;
        }
        let runtime = Arc::new(Runtime {
            policy: Some(policy),
            credential_guard: Some(credential_guard),
            gateway_grants,
            credential_key_empty: previous.credential_key_empty,
            ..previous.clone()
        });
        {
            let mut current = self
                .runtime
                .write()
                .map_err(|_| "runtime write lock poisoned")?;
            runtime.configure_declarations()?;
            *current = runtime.clone();
        }
        policy_runtime::accepted(runtime.policy.as_ref(), &runtime.audit);
        Ok(())
    }

    pub async fn reload(&mut self, config: Config) -> Result<(), Error> {
        let previous = self
            .runtime
            .read()
            .map_err(|_| "runtime read lock poisoned")?
            .clone();
        let mut service_files = None;
        let runtime = Arc::new(Runtime::load(
            config.clone(),
            &self.default_via,
            self.temporary_policy_lock.clone(),
            Some(&previous),
            self.admin.as_ref().map(admin_listener::Running::address),
            &mut service_files,
        )?);
        let additions = self.prepare_listeners(&config)?;
        if self.circuit_snapshots.is_none() && circuit_runtime::state_path(&config).is_some() {
            self.circuit_snapshots = Some(circuit_runtime::Snapshots::start(self.runtime.clone())?);
        }
        {
            // Completion, admission and snapshots all retain this same lock
            // through their state operation. Publish the selected file's state
            // and configuration together, preserving counters and settings.
            let state = self.runtime.clone();
            let mut current = state.write().map_err(|_| "runtime write lock poisoned")?;
            let old_path = circuit_runtime::state_path(&current.config);
            let new_path = circuit_runtime::state_path(&runtime.config);
            if old_path != new_path {
                let changed = runtime.circuits.replace_state_file(
                    old_path,
                    new_path,
                    circuit_runtime::now(),
                    &mut rand::random::<f64>,
                )?;
                if changed.previous_save_failed {
                    eprintln!("Circuit previous state snapshot failed");
                }
                if changed.load_failed {
                    eprintln!("Circuit state load failed");
                }
            }
            // Publish current declaration defaults on the process owner. A
            // POST whose body spans this reload uses these latest settings;
            // existing declarations retain their original expiry and context.
            runtime.configure_declarations()?;
            runtime.flow_recorder.set_enabled(config.flow_store_enabled);
            runtime
                .traffic_view
                .configure(config.flow_pruner_max, config.flow_pruner_max_body_bytes);
            // No fallible preparation remains before topology/runtime publication.
            clear_readiness(&self.readiness_file, &self.default_via);
            self.commit_listeners(&config, additions);
            *current = runtime.clone();
        }
        policy_runtime::accepted(runtime.policy.as_ref(), &runtime.audit);
        self.service_check_at = service_files.as_ref().map(|_| tokio::time::Instant::now());
        self.service_files = service_files;
        if previous.config.policy_file != config.policy_file {
            self.policy_check_at = config
                .policy_file
                .as_ref()
                .map(|_| tokio::time::Instant::now());
        }
        if self.readiness_file != config.readiness_file {
            clear_readiness(&self.readiness_file, &self.default_via);
            self.readiness_file = config.readiness_file;
        }
        let result = self.write_readiness();
        self.reap_listeners().await;
        result
    }

    pub async fn shutdown(mut self) {
        clear_readiness(&self.readiness_file, &self.default_via);
        let credential_activation = self
            .runtime
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .credential_activation
            .clone();
        credential_activation.close();
        let service_mutations = self
            .runtime
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .service_mutations
            .clone();
        service_mutations.stop_admission().await;
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
        service_mutations.drain().await;
        let recorder = self
            .runtime
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .flow_recorder
            .clone();
        if !tokio::task::spawn_blocking(move || recorder.shutdown())
            .await
            .unwrap_or(false)
        {
            eprintln!("Flow writer shutdown did not complete");
        }
        if let Some(snapshots) = self.circuit_snapshots.take()
            && tokio::task::spawn_blocking(move || snapshots.stop())
                .await
                .is_err()
        {
            eprintln!("Circuit snapshot shutdown failed");
        }
        let audit = self
            .runtime
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .audit
            .clone();
        if !matches!(
            tokio::task::spawn_blocking(move || audit.shutdown(Duration::from_secs(5))).await,
            Ok(Ok(true))
        ) {
            eprintln!("Audit writer shutdown did not complete");
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

#[cfg(test)]
mod audit_runtime_tests;

#[cfg(test)]
mod listener_reload_tests;
