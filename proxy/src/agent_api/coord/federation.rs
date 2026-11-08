//! Scoped Core NATS requests. Canonical owners retain identity and effects.
use super::*;
use crate::{Error, coord_rooms::federation as trust};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};

// DOC: docs/peer-support.md
const MAX_WIRE_REQUEST: usize = crate::coord_rooms::COLLABORATION_MAX_ENVELOPE_BYTES;

// These are resource budgets, not grants. Waits cannot occupy command slots.
const MAX_CONNECTIONS: usize = 32;
const MAX_REQUESTS: usize = 32;
const MAX_WAITS: usize = 32;
const MAX_INCOMING: usize = 64;
const MAX_PEER_REQUESTS: usize = 16;
const MAX_PEER_WAITS: usize = 8;

struct Cached {
    destination: String,
    used: tokio::time::Instant,
    connection: Arc<OnceCell<async_nats::Client>>,
}

pub(super) struct Connections {
    cache: tokio::sync::Mutex<HashMap<String, Cached>>,
    requests: Arc<Semaphore>,
    waits: Arc<Semaphore>,
    incoming: Arc<Semaphore>,
    incoming_waits: Arc<Semaphore>,
    incoming_cleanup: Arc<Semaphore>,
    cleanup: Arc<Semaphore>,
    read_waits: StdMutex<HashMap<ReadWaitId, futures_util::future::AbortHandle>>,
    rejected: AtomicU64,
    delivery_failures: Arc<AtomicU64>,
    events: Arc<StdMutex<HashMap<String, (String, u64)>>>,
}

impl Default for Connections {
    fn default() -> Self {
        Self {
            cache: Default::default(),
            requests: Arc::new(Semaphore::new(MAX_REQUESTS)),
            waits: Arc::new(Semaphore::new(MAX_WAITS)),
            incoming: Arc::new(Semaphore::new(MAX_INCOMING)),
            incoming_waits: Arc::new(Semaphore::new(16)),
            incoming_cleanup: Arc::new(Semaphore::new(8)),
            cleanup: Arc::new(Semaphore::new(4)),
            read_waits: Default::default(),
            rejected: AtomicU64::new(0),
            delivery_failures: Arc::new(AtomicU64::new(0)),
            events: Default::default(),
        }
    }
}

fn security(home: &trust::Home, source: &str) -> Result<String, Error> {
    let credential = trust::token(&home.token_file)?;
    let ca = std::fs::read(&home.ca_file)?;
    Ok(crate::approvals::pending::digest(&json!([
        source,
        home.instance_id,
        home.url,
        home.revision,
        trust::nats::subject_token(credential.trim()),
        hash_hex(&ca)
    ])))
}

fn hash_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Connections {
    fn options(&self, destination: String) -> async_nats::ConnectOptions {
        let events = self.events.clone();
        async_nats::ConnectOptions::new().event_callback(move |event| {
            let (events, destination) = (events.clone(), destination.clone());
            async move {
                // Error text may contain authored subjects or credentials.
                let class = match event {
                    async_nats::Event::Connected => "connected",
                    async_nats::Event::Disconnected => "disconnected",
                    async_nats::Event::Closed => "closed",
                    async_nats::Event::SlowConsumer(_) => "slow_consumer",
                    async_nats::Event::ServerError(_) => "server_error",
                    async_nats::Event::ClientError(_) => "client_error",
                    async_nats::Event::LameDuckMode => "lame_duck",
                    async_nats::Event::Draining => "draining",
                };
                if let Ok(mut events) = events.lock() {
                    if !events.contains_key(&destination) && events.len() > MAX_CONNECTIONS {
                        events.clear();
                    }
                    let entry = events.entry(destination).or_default();
                    entry.0 = class.into();
                    entry.1 += 1;
                }
            }
        })
    }

    async fn connect(&self, home: &trust::Home, source: &str) -> Result<async_nats::Client, Error> {
        let key = security(home, source)?;
        let cell = {
            let mut cache = self.cache.lock().await;
            // A changed credential, CA, route or configuration revision cannot
            // reuse the previous connection. In-flight callers recheck below.
            cache.retain(|security, entry| {
                entry.destination != home.instance_id || security == &key
            });
            if !cache.contains_key(&key) && cache.len() >= MAX_CONNECTIONS {
                if let Some(oldest) = cache
                    .iter()
                    .filter(|(_, entry)| Arc::strong_count(&entry.connection) == 1)
                    .min_by_key(|(_, entry)| entry.used)
                    .map(|(key, _)| key.clone())
                {
                    cache.remove(&oldest);
                } else {
                    self.rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(AdmissionFull.into());
                }
            }
            cache
                .entry(key.clone())
                .or_insert_with(|| Cached {
                    destination: home.instance_id.clone(),
                    used: tokio::time::Instant::now(),
                    connection: Arc::new(OnceCell::new()),
                })
                .used = tokio::time::Instant::now();
            cache
                .get(&key)
                .expect("inserted connection")
                .connection
                .clone()
        };
        let connection = cell
            .get_or_try_init(|| async {
                let result = trust::nats::connect_with_options(
                    home,
                    source,
                    self.options(home.instance_id.clone()),
                )
                .await;
                if result.is_err() {
                    self.delivery_failures.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut events) = self.events.lock() {
                        let class = if result
                            .as_ref()
                            .err()
                            .and_then(|error| error.downcast_ref::<async_nats::ConnectError>())
                            .is_some_and(|error| {
                                matches!(
                                    error.kind(),
                                    async_nats::ConnectErrorKind::Authentication
                                        | async_nats::ConnectErrorKind::AuthorizationViolation
                                )
                            }) {
                            "authentication_denied"
                        } else {
                            "connect_failed"
                        };
                        if events.len() > MAX_CONNECTIONS {
                            events.clear();
                        }
                        events.insert(home.instance_id.clone(), (class.into(), 1));
                    }
                }
                result
            })
            .await?;
        if connection.connection_state() != async_nats::connection::State::Connected {
            return Err("peer reconnecting; no request submitted".into());
        }
        Ok(connection.clone())
    }

    fn register_wait(
        &self,
        key: ReadWaitId,
    ) -> Result<futures_util::future::AbortRegistration, Error> {
        let mut waits = self
            .read_waits
            .lock()
            .map_err(|_| "read wait state unavailable")?;
        if waits.contains_key(&key) {
            return Err(AdmissionFull.into());
        }
        let (abort, registration) = futures_util::future::AbortHandle::new_pair();
        waits.insert(key, abort);
        Ok(registration)
    }

    pub(super) async fn diagnostics(&self) -> Value {
        let cache = self.cache.lock().await;
        let connections: Vec<_> = cache.values().map(|entry| json!({"instance_id":entry.destination,
            "state":entry.connection.get().map(|client|format!("{:?}", client.connection_state())).unwrap_or_else(||"connecting".into())})).collect();
        json!({"connections":connections,"connection_count":cache.len(),
            "active_read_waits":self.read_waits.lock().map(|waits|waits.len()).unwrap_or(0),
            "active_requests":MAX_REQUESTS-self.requests.available_permits(),
            "active_waits":MAX_WAITS-self.waits.available_permits(),
            "active_incoming":MAX_INCOMING-self.incoming.available_permits(),"active_cleanup":8-self.incoming_cleanup.available_permits(),
            "rejected_admission":self.rejected.load(Ordering::Relaxed),
            "delivery_failures":self.delivery_failures.load(Ordering::Relaxed),
            "connection_events":self.events.lock().map(|events|json!(*events)).unwrap_or(Value::Null),
            "budget":{"connections":MAX_CONNECTIONS,"requests":MAX_REQUESTS,"waits":MAX_WAITS,"incoming":MAX_INCOMING,"per_peer_requests":MAX_PEER_REQUESTS,"per_peer_waits":MAX_PEER_WAITS}})
    }
}

#[derive(Debug)]
struct AdmissionFull;
impl std::fmt::Display for AdmissionFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Coord connection admission full; no request submitted")
    }
}
impl std::error::Error for AdmissionFull {}

fn admission_full() -> Outcome<'static> {
    response(
        429,
        json!({"error":"Coord request admission full; no operation attempted","mutation_outcome":"not_attempted","availability":"busy"}),
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRequest {
    destination_instance_id: String,
    source_run: Option<crate::host_runs::AgentRun>,
    method: String,
    path: String,
    body: Option<Value>,
}

impl CoordClient {
    pub(super) async fn check_remote(&self) -> Result<(), CoordError> {
        let Some(remote) = self.remote.clone() else {
            return Ok(());
        };
        let db = self.owner.data_dir.join("v0.db");
        tokio::task::spawn_blocking(move || {
            trust::authorize(&open_db(&db, false)?, &remote).map_err(|_| CoordError::Forbidden)
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }
}

fn without_home(path: &str) -> Result<String, CoordError> {
    let Some((path, query)) = path.split_once('?') else {
        return Err(CoordError::Invalid);
    };
    let mut homes = 0;
    let mut retained = Vec::new();
    for part in query.split('&') {
        let key =
            percent_encoding::percent_decode_str(part.split_once('=').map_or(part, |(key, _)| key))
                .decode_utf8()
                .map_err(|_| CoordError::Invalid)?;
        if key == "home" {
            homes += 1;
        } else {
            retained.push(part);
        }
    }
    if homes != 1 {
        return Err(CoordError::Invalid);
    }
    Ok(if retained.is_empty() {
        path.into()
    } else {
        format!("{path}?{}", retained.join("&"))
    })
}

fn support_route(request: Request<'_>) -> bool {
    let path = super::super::route(request);
    (request.method == "GET" && path == "/support/grants")
        || (request.method == "POST"
            && matches!(
                path,
                "/support/operations" | crate::peer_support::authority::METADATA_PATH
            ))
        || (request.method == "GET"
            && path
                .strip_prefix("/support/operations/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/')))
}

fn approval_route(request: Request<'_>) -> bool {
    let path = super::super::route(request);
    (request.method == "GET" && path == "/approvals")
        || path.strip_prefix("/approvals/").is_some_and(|suffix| {
            let (id, resolve) = suffix
                .strip_suffix("/resolve")
                .map_or((suffix, false), |id| (id, true));
            crate::approvals::pending::valid_id(id)
                && !id.contains('/')
                && ((request.method == "GET" && !resolve) || (request.method == "POST" && resolve))
        })
}

fn allowed(request: Request<'_>) -> bool {
    request.path_and_query.len() <= 16384
        && query_parameter(request.path_and_query, "home").is_ok_and(|home| home.is_none())
        && (route_parts(request).is_some()
            || attention_wait_route(request)
            || attention_object_route(request).is_some()
            || support_route(request)
            || approval_route(request)
            || (request.method == "POST"
                && matches!(
                    super::super::route(request),
                    "/api/coord/attention/subscribe" | "/api/coord/attention/unsubscribe"
                )))
}

fn unavailable(request: Request<'_>) -> Outcome<'static> {
    response(
        503,
        json!({"error":"owning instance unreachable; inspect the original operation_id or canonical history before retrying. A lost reply does not prove cancellation or target death.",
        "mutation_outcome":if request.method == "POST" {"unknown"} else {"not_requested"},
        "availability":"unreachable"}),
    )
}

fn long_wait(peer: &PeerRequest) -> bool {
    let request = Request {
        method: &peer.method,
        path_and_query: &peer.path,
        authorization: None,
        identity: crate::network_guard::Identity::Unavailable,
        client_ip: None,
        request_id: "wait-admission",
    };
    peer.method == "GET"
        && (attention_wait_route(request)
            || route_parts(request).is_some_and(|(_, operation)| operation == "wait"))
        && query_parameter(&peer.path, "timeout")
            .ok()
            .flatten()
            .and_then(|seconds| seconds.parse::<f64>().ok())
            .unwrap_or(60.0)
            > 1.0
}

fn valid_wait_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ReadWaitId {
    source: String,
    agent: String,
    id: String,
}

struct ActiveReadWait {
    owner: Arc<CoordOwner>,
    key: ReadWaitId,
}
impl Drop for ActiveReadWait {
    fn drop(&mut self) {
        if let Ok(mut waits) = self.owner.federation.read_waits.lock() {
            waits.remove(&self.key);
        }
    }
}

fn local_run_current(context: &CoordContext<'_>, run: &crate::host_runs::AgentRun) -> bool {
    context
        .runtime
        .and_then(|runtime| crate::peer_support::current_policy(runtime).ok())
        .is_some_and(|policy| run.current(&policy))
}

pub(super) async fn forward(
    request: Request<'_>,
    context: &CoordContext<'_>,
    payload: Option<&[u8]>,
    _agent_name: &str,
    principal: &str,
    home_name: &str,
) -> Outcome<'static> {
    if !public_name_part(home_name) {
        return error_response(CoordError::Invalid);
    }
    let Some(run) = request.identity.run() else {
        return response(
            403,
            json!({"error":"trusted current source-agent run required"}),
        );
    };
    if run.agent_id != principal || !local_run_current(context, run) {
        return error_response(CoordError::Forbidden);
    }
    let path = match without_home(request.path_and_query) {
        Ok(path) => path,
        Err(error) => return error_response(error),
    };
    if !allowed(Request {
        path_and_query: &path,
        ..request
    }) {
        return error_response(CoordError::NotFound);
    }
    let source = match std::fs::read_to_string(context.client.owner.data_dir.join("instance_id")) {
        Ok(id) => id.trim().to_owned(),
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let db = context.client.owner.data_dir.join("v0.db");
    let home = match open_db(&db, false)
        .and_then(|conn| trust::home(&conn, home_name).map_err(|_| CoordError::Forbidden))
    {
        Ok(home) => home,
        Err(error) => return error_response(error),
    };
    if query_parameter(request.path_and_query, "instance_id")
        .ok()
        .flatten()
        .is_some_and(|selected| selected != home.instance_id)
    {
        return response(
            409,
            json!({"error":"source cursor belongs to another instance; inspect the current route","instance_id":home.instance_id}),
        );
    }
    let body = match payload
        .filter(|_| request.method == "POST")
        .map(serde_json::from_slice::<Value>)
        .transpose()
    {
        Ok(body) => body,
        Err(_) => return response(400, json!({"error":"invalid JSON body"})),
    };
    let mut peer = PeerRequest {
        destination_instance_id: home.instance_id.clone(),
        source_run: Some(run.clone()),
        method: request.method.into(),
        path,
        body,
    };
    let waiting = long_wait(&peer);
    if waiting
        && !attention_wait_route(Request {
            path_and_query: &peer.path,
            ..request
        })
    {
        peer.body = Some(json!({"wait_id":uuid::Uuid::new_v4().simple().to_string()}));
    }
    if serde_json::to_vec(&peer).is_ok_and(|wire| wire.len() > MAX_WIRE_REQUEST) {
        return response(
            413,
            json!({"error":"request exceeds the managed NATS payload limit; no remote operation attempted"}),
        );
    }
    let budget = if waiting {
        &context.client.owner.federation.waits
    } else {
        &context.client.owner.federation.requests
    };
    let Ok(permit) = budget.clone().try_acquire_owned() else {
        context
            .client
            .owner
            .federation
            .rejected
            .fetch_add(1, Ordering::Relaxed);
        return admission_full();
    };
    let before_security = security(&home, &source).ok();
    let result = async {
        let connection = context
            .client
            .owner
            .federation
            .connect(&home, &source)
            .await?;
        if attention_wait_route(Request {
            path_and_query: &peer.path,
            ..request
        }) {
            wait_remote(
                &connection,
                &home,
                &source,
                &peer,
                context.client.owner.cleanup.clone(),
                &context.client.owner.federation,
                permit,
            )
            .await
        } else if let Some(id) = peer
            .body
            .as_ref()
            .and_then(|body| body["wait_id"].as_str())
            .filter(|_| waiting)
        {
            let cleanup = WaitCleanup {
                connection: connection.clone(),
                home: home.clone(),
                source: source.clone(),
                request: PeerRequest {
                    method: "POST".into(),
                    path: "/api/coord/attention/unsubscribe".into(),
                    body: Some(json!({"wait_id":id})),
                    ..peer.clone()
                },
                owner: context.client.owner.cleanup.clone(),
                cleanup: context.client.owner.federation.cleanup.clone(),
                failures: context.client.owner.federation.delivery_failures.clone(),
                permit: Some(permit),
            };
            let result = exchange(&connection, &home, &source, &peer).await;
            cleanup.finish().await;
            result
        } else {
            let _permit = permit;
            exchange(&connection, &home, &source, &peer).await
        }
    };
    let mut cancellation = context.cancellation.clone();
    let result = tokio::select! {
        value=result=>value,
        _=wait_cancelled(&mut cancellation)=>return unavailable(request),
    };
    if !local_run_current(context, run)
        || before_security.is_none()
        || security(&home, &source).ok() != before_security
        || open_db(&db, false)
            .ok()
            .and_then(|conn| trust::home(&conn, home_name).ok())
            .as_ref()
            != Some(&home)
    {
        return error_response(CoordError::Forbidden);
    }
    match result {
        Ok(reply) if reply["home_instance_id"] == home.instance_id => {
            let Some(status) = reply["status"]
                .as_u64()
                .and_then(|s| u16::try_from(s).ok())
                .filter(|s| (200..600).contains(s))
            else {
                return error_response(CoordError::Data);
            };
            match reply.get("body") {
                Some(body) => response(status, body.clone()),
                None => error_response(CoordError::Data),
            }
        }
        Ok(_) => response(
            503,
            json!({"error":"response identity differs from selected owning instance","availability":"unknown"}),
        ),
        Err(error) if error.downcast_ref::<AdmissionFull>().is_some() => admission_full(),
        Err(error)
            if error
                .downcast_ref::<async_nats::ConnectError>()
                .is_some_and(|error| {
                    matches!(
                        error.kind(),
                        async_nats::ConnectErrorKind::AuthorizationViolation
                            | async_nats::ConnectErrorKind::Authentication
                    )
                }) =>
        {
            response(
                403,
                json!({"error":"peer broker authentication denied; reconcile any prior in-flight operation before retrying"}),
            )
        }
        Err(_) => unavailable(request),
    }
}

async fn exchange(
    connection: &async_nats::Client,
    home: &trust::Home,
    source: &str,
    peer: &PeerRequest,
) -> Result<Value, Error> {
    let timeout = if peer.path.starts_with("/api/coord/attention/") {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(330)
    };
    let request = connection.send_request(
        trust::nats::request_subject(&home.instance_id, source),
        async_nats::Request::new()
            .payload(serde_json::to_vec(peer)?.into())
            .timeout(Some(timeout)),
    );
    // Inspect only the library's local connection state. A disconnect closes
    // this uncertain request promptly; it never submits a replacement RPC.
    let disconnected = async {
        loop {
            if connection.connection_state() != async_nats::connection::State::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let message = tokio::select! {
        value=request=>value?,
        _=disconnected=>return Err("peer disconnected; inspect the original operation before retrying".into()),
    };
    if message.payload.len() > 8 * 1024 * 1024 {
        return Err("federation response exceeds limit".into());
    }
    Ok(serde_json::from_slice(&message.payload)?)
}

/// Admin-authenticated inventory collection uses the existing authenticated
/// Core NATS connection and request budgets, without selecting an agent run.
pub(crate) async fn authority_metadata(
    runtime: &crate::RuntimeState,
    selected: &crate::peer_support::authority::Owner,
    query: Value,
) -> Result<Value, Error> {
    let client = runtime
        .read()
        .map_err(|_| "runtime unavailable")?
        .coord
        .clone();
    let home_name = selected
        .home
        .as_deref()
        .ok_or("remote owner needs a configured home")?;
    let conn = open_db(&client.owner.data_dir.join("v0.db"), false)
        .map_err(|_| "metadata route store unavailable")?;
    let home = trust::home(&conn, home_name)?;
    if home.instance_id != selected.instance_id {
        return Err(crate::peer_support::refuse(
            403,
            "metadata route identity differs from selected owner",
        ));
    }
    let source = std::fs::read_to_string(client.owner.data_dir.join("instance_id"))?
        .trim()
        .to_owned();
    let before_security = security(&home, &source)?;
    let _permit = client
        .owner
        .federation
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| AdmissionFull)?;
    let connection = client.owner.federation.connect(&home, &source).await?;
    let peer = PeerRequest {
        destination_instance_id: selected.instance_id.clone(),
        source_run: None,
        method: "POST".into(),
        path: crate::peer_support::authority::METADATA_PATH.into(),
        body: Some(query),
    };
    let result = exchange(&connection, &home, &source, &peer).await?;
    if security(&home, &source)? != before_security
        || trust::home(&conn, home_name)? != home
        || result["home_instance_id"] != selected.instance_id
    {
        return Err(crate::peer_support::refuse(
            403,
            "metadata source route or destination identity changed",
        ));
    }
    if result["status"] != 200 {
        let status = result["status"]
            .as_u64()
            .and_then(|s| u16::try_from(s).ok())
            .unwrap_or(503);
        return Err(crate::peer_support::refuse(
            status,
            "owner authority metadata unavailable",
        ));
    }
    Ok(result["body"].clone())
}

/// Subscribe before reading B's retained position. There is no network poll
/// and no global cross-instance position.
async fn wait_remote(
    connection: &async_nats::Client,
    home: &trust::Home,
    source: &str,
    peer: &PeerRequest,
    owner: Arc<CoordCleanup>,
    connections: &Connections,
    permit: OwnedSemaphorePermit,
) -> Result<Value, Error> {
    let seconds = query_parameter(&peer.path, "timeout")
        .map_err(|_| "invalid wait timeout")?
        .map_or(Ok(60.0), |value| value.parse::<f64>())
        .map_err(|_| "invalid wait timeout")?;
    if !seconds.is_finite() || !(0.0..=300.0).contains(&seconds) {
        return Err("invalid wait timeout".into());
    }
    if seconds == 0.0 {
        return exchange(connection, home, source, peer).await;
    }
    let wait_id = uuid::Uuid::new_v4().simple().to_string();
    let cleanup = WaitCleanup {
        connection: connection.clone(),
        home: home.clone(),
        source: source.into(),
        request: PeerRequest {
            method: "POST".into(),
            path: "/api/coord/attention/unsubscribe".into(),
            body: Some(json!({"wait_id":wait_id})),
            ..peer.clone()
        },
        owner,
        cleanup: connections.cleanup.clone(),
        failures: connections.delivery_failures.clone(),
        permit: Some(permit),
    };
    let subscription = exchange(
        connection,
        home,
        source,
        &PeerRequest {
            method: "POST".into(),
            path: "/api/coord/attention/subscribe".into(),
            body: Some(json!({"wait_id":wait_id})),
            ..peer.clone()
        },
    )
    .await?;
    if subscription["status"] != 200 {
        return Ok(subscription);
    }
    let result = wait_subscribed(connection, home, source, peer, seconds, subscription).await;
    cleanup.finish().await;
    result
}

struct WaitCleanup {
    connection: async_nats::Client,
    home: trust::Home,
    source: String,
    request: PeerRequest,
    owner: Arc<CoordCleanup>,
    cleanup: Arc<Semaphore>,
    failures: Arc<AtomicU64>,
    permit: Option<OwnedSemaphorePermit>,
}
impl WaitCleanup {
    async fn finish(mut self) {
        cleanup_wait(
            &self.cleanup,
            &self.failures,
            &self.connection,
            &self.home,
            &self.source,
            &self.request,
        )
        .await;
        self.permit = None;
    }
}
async fn cleanup_wait(
    budget: &Semaphore,
    failures: &AtomicU64,
    connection: &async_nats::Client,
    home: &trust::Home,
    source: &str,
    request: &PeerRequest,
) {
    let Ok(_permit) = budget.acquire().await else {
        return;
    };
    if !matches!(tokio::time::timeout(Duration::from_secs(2),exchange(connection,home,source,request)).await,Ok(Ok(value)) if value["status"]==200)
    {
        failures.fetch_add(1, Ordering::Relaxed);
    }
}
impl Drop for WaitCleanup {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let (connection, home, source, request, budget, failures) = (
            self.connection.clone(),
            self.home.clone(),
            self.source.clone(),
            self.request.clone(),
            self.cleanup.clone(),
            self.failures.clone(),
        );
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            self.owner.track(handle.spawn(async move {
                let _permit = permit;
                cleanup_wait(&budget, &failures, &connection, &home, &source, &request).await;
            }));
        }
    }
}

async fn wait_subscribed(
    connection: &async_nats::Client,
    home: &trust::Home,
    source: &str,
    peer: &PeerRequest,
    seconds: f64,
    subscription: Value,
) -> Result<Value, Error> {
    let stream = async_nats::jetstream::new(connection.clone())
        .get_stream(trust::nats::notice_stream(source))
        .await?;
    let consumer = stream
        .get_consumer::<pull::Config>(
            subscription["body"]["consumer"]
                .as_str()
                .ok_or("invalid notification consumer")?,
        )
        .await?;
    let mut hints = consumer.messages().await?;
    let path = peer
        .path
        .split_once('?')
        .map_or(peer.path.as_str(), |(path, _)| path);
    let since = query_parameter(&peer.path, "since")
        .map_err(|_| "invalid cursor")?
        .unwrap_or_else(|| "0".into());
    let limit = query_parameter(&peer.path, "limit")
        .map_err(|_| "invalid limit")?
        .unwrap_or_else(|| "1".into());
    let read = PeerRequest {
        path: format!("{path}?since={since}&limit={limit}&timeout=0"),
        ..peer.clone()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(seconds);
    loop {
        let reply = exchange(connection, home, source, &read).await?;
        if reply["status"] != 200
            || reply["body"]["edges"]
                .as_array()
                .is_none_or(|edges| !edges.is_empty())
            || reply["body"]["next_cursor"]
                .as_u64()
                .is_some_and(|next| Some(next) != since.parse::<u64>().ok())
            || tokio::time::Instant::now() >= deadline
        {
            return Ok(reply);
        }
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>return exchange(connection,home,source,&read).await,
            hint=hints.next()=>match hint { Some(Ok(_))=>{}, _=>return Err("remote notification subscription unavailable".into()) },
        }
    }
}

pub(crate) async fn forward_support(
    request: Request<'_>,
    state: &crate::RuntimeState,
    payload: Option<&[u8]>,
    home: &str,
) -> Outcome<'static> {
    let Some(run) = request.identity.run() else {
        return error_response(CoordError::Forbidden);
    };
    let client = match state.read() {
        Ok(runtime) => runtime.coord.clone(),
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let (_cancel, cancellation) = tokio::sync::watch::channel(false);
    forward(
        request,
        &CoordContext {
            client: &client,
            cancellation,
            runtime: Some(state),
        },
        payload,
        &run.agent,
        &run.agent_id,
        home,
    )
    .await
}

fn reply(instance: &str, status: u16, body: Value) -> Value {
    json!({"home_instance_id":instance,"status":status,"body":body})
}

async fn refuse_peer(
    runtime: &crate::RuntimeState,
    owner_source: (&str, &str),
    peer: &PeerRequest,
    remote: Option<&trust::RemoteAgent>,
    correlation: &str,
    decision: (u16, &str, &str, &str),
) -> Value {
    let (instance, source) = owner_source;
    let (status, phase, reason, message) = decision;
    let request = Request {
        method: &peer.method,
        path_and_query: &peer.path,
        authorization: None,
        identity: crate::network_guard::Identity::Unavailable,
        client_ip: None,
        request_id: correlation,
    };
    // Classify routes without copying authored paths, queries or bodies.
    let operation = if support_route(request) {
        "support"
    } else if approval_route(request) {
        "approval"
    } else if let Some((_, operation)) = route_parts(request) {
        operation
    } else if attention_wait_route(request) || attention_object_route(request).is_some() {
        "attention"
    } else {
        "unavailable"
    };
    let operation_id = peer
        .body
        .as_ref()
        .and_then(|body| body["operation_id"].as_str())
        .filter(|id| crate::peer_support::operations::valid_operation_id(id));
    let mut event = crate::audit::Event::new(
        "coord.federation_refused",
        crate::audit::Kind::Coord,
        crate::audit::Severity::High,
        "Owning instance refused a federated request",
    );
    event.request_id = Some(correlation.into());
    event.agent = remote.map(|remote| remote.display_name.clone());
    event.details = json!({"instance_id":instance,"source_instance_id":source,
        "identity_basis":"authenticated_nats_peer","qualified_principal":remote,
        "phase":phase,"reason":reason,"state":"refused","operation":operation,
        "mutation_outcome":if phase == "post_dispatch" {"response_withheld"} else {"not_attempted"},
        "untrusted_claims":{"destination_instance_id":Some(&peer.destination_instance_id).filter(|id|id.strip_prefix("sy-").is_some_and(valid_wait_id)),
            "agent_id":peer.source_run.as_ref().map(|run| &run.agent_id).filter(|id| valid_agent_id(id)),
            "agent_name":peer.source_run.as_ref().map(|run| &run.agent).filter(|name| public_name_part(name)),
            "run_id":peer.source_run.as_ref().map(|run| &run.run_id).filter(|id| valid_wait_id(id)),"operation_id":operation_id}}).into();
    // Refusals use the existing bounded writer admission and never allocate a
    // persistent obligation per input. Sink failure remains explicit to callers.
    let writer = runtime.read().ok().map(|runtime| runtime.audit.clone());
    let recorded = if let Some(writer) = writer {
        writer.emit_confirmed(event).await.is_ok()
    } else {
        false
    };
    let mut body = json!({"error":message,"request_id":correlation});
    if !recorded {
        body["audit_status"] = json!(
            "unavailable; the owner refused the request but could not confirm its canonical decision record"
        );
    }
    reply(instance, status, body)
}

async fn receive(
    client: &CoordClient,
    runtime: &crate::RuntimeState,
    instance: &str,
    source: &str,
    credential_hash: &str,
    bytes: &[u8],
) -> Value {
    if bytes.len() > MAX_WIRE_REQUEST {
        return reply(instance, 413, json!({"error":"request body too large"}));
    }
    let Ok(peer) = serde_json::from_slice::<PeerRequest>(bytes) else {
        return reply(instance, 400, json!({"error":"invalid federation request"}));
    };
    let correlation = format!("req-{}", uuid::Uuid::new_v4().simple());
    if peer.path == crate::peer_support::authority::METADATA_PATH && peer.method == "POST" {
        if peer.destination_instance_id != instance {
            return refuse_peer(
                runtime,
                (instance, source),
                &peer,
                None,
                &correlation,
                (
                    403,
                    "pre_dispatch",
                    "destination_mismatch",
                    "destination instance mismatch; no operation attempted",
                ),
            )
            .await;
        }
        let result = crate::peer_support::authority::remote_metadata(
            runtime,
            source,
            credential_hash,
            peer.source_run.as_ref(),
            peer.body.clone().unwrap_or(Value::Null),
        );
        return match result {
            Ok(value) => reply(instance, 200, value),
            Err(error) => {
                let status = error
                    .downcast_ref::<crate::peer_support::Refusal>()
                    .map_or(503, |r| r.status);
                refuse_peer(
                    runtime,
                    (instance, source),
                    &peer,
                    None,
                    &correlation,
                    (
                        status,
                        "pre_dispatch",
                        "authority_metadata_unavailable",
                        "authority metadata unavailable or not disclosed to this reader",
                    ),
                )
                .await
            }
        };
    }
    let Some(run) = peer.source_run.as_ref() else {
        return refuse_peer(
            runtime,
            (instance, source),
            &peer,
            None,
            &correlation,
            (
                403,
                "pre_dispatch",
                "agent_required",
                "operator metadata identity cannot execute agent operations",
            ),
        )
        .await;
    };
    let authentication = open_db(&client.owner.data_dir.join("v0.db"), false)
        .map_err(|_| "identity_store_unavailable")
        .and_then(|conn| {
            let trusted: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM coord_federation_peers WHERE instance_id=?1 AND token_hash=?2 AND enabled=1)",
                rusqlite::params![source,credential_hash], |row| row.get(0)).map_err(|_| "identity_store_unavailable")?;
            if !trusted { return Err("peer_trust_unavailable"); }
            trust::authenticate_transport(&conn, source, credential_hash, &run.agent_id)
                .map_err(|_| "qualified_principal_unavailable")
        });
    // DOC: docs/coord-reference.md, docs/coord-trust-boundary.md
    if peer.destination_instance_id != instance {
        return refuse_peer(
            runtime,
            (instance, source),
            &peer,
            authentication.as_ref().ok(),
            &correlation,
            (
                403,
                "pre_dispatch",
                "destination_mismatch",
                "destination instance mismatch; no operation attempted",
            ),
        )
        .await;
    }
    let remote = match authentication {
        Ok(remote) => remote,
        Err(reason) => {
            return refuse_peer(
                runtime,
                (instance, source),
                &peer,
                None,
                &correlation,
                (
                    403,
                    "pre_dispatch",
                    reason,
                    "peer or qualified agent is not authorized",
                ),
            )
            .await;
        }
    };
    let request = Request {
        method: &peer.method,
        path_and_query: &peer.path,
        authorization: None,
        identity: crate::network_guard::Identity::Resolved(&remote.display_name),
        client_ip: None,
        request_id: &correlation,
    };
    if !allowed(request) {
        return refuse_peer(
            runtime,
            (instance, source),
            &peer,
            Some(&remote),
            &correlation,
            (
                404,
                "pre_dispatch",
                "operation_unavailable",
                "remote operation is not available",
            ),
        )
        .await;
    }
    let mut scoped = client.clone();
    scoped.remote = Some(remote.clone());
    scoped.request_run = Some(Arc::new(SourceRun::Remote { run: run.clone() }));
    if scoped.bound_current().is_err() {
        return refuse_peer(
            runtime,
            (instance, source),
            &peer,
            Some(&remote),
            &correlation,
            (
                403,
                "pre_dispatch",
                "source_binding_or_trust_changed",
                "source binding or peer trust changed",
            ),
        )
        .await;
    }
    let payload = peer
        .body
        .as_ref()
        .map(|body| serde_json::to_vec(body).expect("JSON value serialization"));
    let max = if support_route(request) {
        MAX_WIRE_REQUEST
    } else {
        match route_parts(request).map(|(_, op)| op) {
            Some("send") => MAX_COORD_REQUEST_BYTES,
            Some("work") => crate::coord_rooms::work::MAX_REQUEST_BYTES,
            Some("signals") => crate::coord_rooms::signals::MAX_REQUEST_BYTES,
            _ => MAX_DECLARATION_REQUEST_BYTES,
        }
    };
    if payload.as_ref().is_some_and(|payload| payload.len() > max) {
        return reply(instance, 413, json!({"error":"request body too large"}));
    }
    let outcome = if peer.method == "POST"
        && matches!(
            peer.path.as_str(),
            "/api/coord/attention/subscribe" | "/api/coord/attention/unsubscribe"
        ) {
        if !payload
            .as_deref()
            .and_then(|payload| serde_json::from_slice::<Value>(payload).ok())
            .is_some_and(|payload| payload["wait_id"].as_str().is_some_and(valid_wait_id))
        {
            return reply(instance, 400, json!({"error":"invalid wait identity"}));
        }
        match subscribe(
            client,
            instance,
            &remote,
            payload.as_deref(),
            peer.path.ends_with("/unsubscribe"),
        )
        .await
        {
            Ok(value) => response(200, value),
            Err(error) if error.downcast_ref::<AdmissionFull>().is_some() => {
                client
                    .owner
                    .federation
                    .rejected
                    .fetch_add(1, Ordering::Relaxed);
                admission_full()
            }
            Err(_) => response(503, json!({"error":"retained notifications unavailable"})),
        }
    } else if approval_route(request) {
        crate::agent_api::approvals::remote(
            request,
            runtime,
            crate::peer_support::Caller {
                run: run.clone(),
                remote: Some(remote.clone()),
            },
            payload.as_deref(),
        )
        .await
    } else if support_route(request) {
        crate::agent_api::support::remote(
            request,
            runtime,
            remote.clone(),
            run.clone(),
            payload.as_deref(),
        )
        .await
    } else {
        let (_cancel, cancellation) = tokio::sync::watch::channel(false);
        Box::pin(respond_as(
            request,
            CoordContext {
                client: &scoped,
                cancellation,
                runtime: Some(runtime),
            },
            payload.as_deref(),
            &remote.principal_id,
            &remote.display_name,
        ))
        .await
    };
    if scoped.check_remote().await.is_err() {
        return refuse_peer(
            runtime,
            (instance, source),
            &peer,
            Some(&remote),
            &correlation,
            (
                403,
                "post_dispatch",
                "peer_trust_changed",
                "federation access changed",
            ),
        )
        .await;
    }
    let super::super::ResponseBody::Json(body) = &outcome.response.body else {
        return reply(instance, 503, json!({"error":"response unavailable"}));
    };
    reply(instance, outcome.response.status, body.clone())
}

async fn subscribe(
    client: &CoordClient,
    instance: &str,
    remote: &trust::RemoteAgent,
    payload: Option<&[u8]>,
    remove: bool,
) -> Result<Value, Error> {
    let connection = client
        .owner
        .federation_nats
        .lock()
        .await
        .clone()
        .ok_or("federation notifications unavailable")?;
    let payload: Value = serde_json::from_slice(payload.ok_or("missing wait identity")?)?;
    let id = payload["wait_id"]
        .as_str()
        .filter(|id| valid_wait_id(id))
        .ok_or("invalid wait identity")?;
    let name = format!(
        "sfw-{}",
        crate::approvals::pending::digest(&json!([remote.instance_id, remote.principal_id, id]))
    );
    if remove {
        if let Some(wait) = client
            .owner
            .federation
            .read_waits
            .lock()
            .map_err(|_| "read wait state unavailable")?
            .get(&ReadWaitId {
                source: remote.instance_id.clone(),
                agent: remote.agent_id.clone(),
                id: id.to_owned(),
            })
        {
            wait.abort();
        }
        let stream = async_nats::jetstream::new(connection)
            .get_stream(trust::nats::notice_stream(&remote.instance_id))
            .await;
        match stream {
            Ok(stream) => match stream.delete_consumer(&name).await {
                Ok(_) => {}
                Err(error) if consumer_delete_not_found(&error) => {}
                Err(error) => return Err(error.into()),
            },
            Err(error) if matches!(error.kind(),async_nats::jetstream::context::GetStreamErrorKind::JetStream(error) if error.code()==404) =>
                {}
            Err(error) => return Err(error.into()),
        }
        return Ok(json!({"removed":true,"instance_id":instance}));
    }
    let mut stream =
        trust::nats::retained_notices(&connection, instance, &remote.instance_id).await?;
    let info = stream.info().await?;
    if info.state.consumer_count >= trust::nats::MAX_WAIT_CONSUMERS as usize {
        return Err(AdmissionFull.into());
    }
    if info.config.max_consumers != trust::nats::MAX_WAIT_CONSUMERS {
        // Bound retained streams as well as newly created ones. Existing waits
        // are never deleted to make room; normal cleanup/inactivity retires them.
        let mut config = info.config.clone();
        config.max_consumers = trust::nats::MAX_WAIT_CONSUMERS;
        async_nats::jetstream::new(connection.clone())
            .update_stream(config)
            .await?;
    }
    stream
        .get_or_create_consumer(
            &name,
            pull::Config {
                name: Some(name.clone()),
                ack_policy: AckPolicy::None,
                deliver_policy: DeliverPolicy::LastPerSubject,
                filter_subject: trust::nats::notice_subject(
                    instance,
                    &remote.instance_id,
                    &remote.principal_id,
                ),
                inactive_threshold: Duration::from_secs(330),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| -> Error {
            if matches!(error.kind(), async_nats::jetstream::stream::ConsumerErrorKind::JetStream(error)
                if error.error_code() == async_nats::jetstream::ErrorCode::MAXIMUM_CONSUMERS_LIMIT)
            {
                AdmissionFull.into()
            } else {
                error.into()
            }
        })?;
    Ok(json!({"consumer":name,"instance_id":instance}))
}

pub(crate) struct Running {
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Running {
    pub(crate) fn start(runtime: crate::RuntimeState) -> Option<Self> {
        let root = runtime.read().ok()?.config.native_config_dir.clone()?;
        if !root.join("coord-federation.json").is_file() {
            return None;
        }
        Some(Self {
            task: tokio::spawn(async move {
                loop {
                    if serve(&root, &runtime).await.is_err() {
                        eprintln!(
                            "NATS federation unavailable; inspect Coord diagnostics and the owned broker log."
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }),
        })
    }
}

async fn serve(root: &Path, runtime: &crate::RuntimeState) -> Result<(), Error> {
    let client = runtime
        .read()
        .map_err(|_| "runtime unavailable")?
        .coord
        .clone();
    let broker: Value = serde_json::from_slice(&std::fs::read(
        client.owner.data_dir.join("nats/process.json"),
    )?)?;
    let peers: Vec<trust::nats::TransportPeer> =
        serde_json::from_value(broker["federation_peers"].clone())?;
    let instance = std::fs::read_to_string(root.join("data/instance_id"))?
        .trim()
        .to_owned();
    let password = trust::token(&client.owner.data_dir.join("nats/federation-creds"))?;
    let (url, options) = trust::nats::local_options(
        &client.owner.data_dir,
        client.nats_url(),
        client.owner.federation.options("owner".into()),
    )?;
    let connection = options
        .user_and_password("safeyolo-federation".into(), password.trim().into())
        .connection_timeout(Duration::from_secs(2))
        .connect(url)
        .await?;
    let mut requests = connection
        .subscribe(format!(
            "SY_FED.request.{}.*",
            trust::nats::subject_token(&instance)
        ))
        .await?;
    connection.flush().await?;
    *client.owner.federation_nats.lock().await = Some(connection.clone());
    let mut tasks = tokio::task::JoinSet::new();
    let budgets: HashMap<_, _> = peers
        .iter()
        .map(|peer| {
            (
                peer.instance_id.clone(),
                (
                    Arc::new(Semaphore::new(MAX_PEER_REQUESTS)),
                    Arc::new(Semaphore::new(MAX_PEER_WAITS)),
                    Arc::new(Semaphore::new(4)),
                ),
            )
        })
        .collect();
    loop {
        tokio::select! {
            message=requests.next()=>{
                let message=message.ok_or("federation subscription closed")?;
                let Some(source_token)=message.subject.rsplit('.').next() else{continue;};
                let Some(source)=peers.iter().find(|peer|trust::nats::subject_token(&peer.instance_id)==source_token) else{continue;};
                let Some(reply_to)=message.reply else{continue;};
                if !reply_to.starts_with(&format!("{}.",trust::nats::reply_prefix(&source.instance_id))) {continue;}
                let parsed=serde_json::from_slice::<PeerRequest>(&message.payload).ok();
                let waiting=parsed.as_ref().is_some_and(long_wait);
                let removing=parsed.as_ref().is_some_and(|peer|peer.method=="POST" && peer.path=="/api/coord/attention/unsubscribe");
                let budgets=budgets.get(&source.instance_id).expect("configured peer budget");
                let peer_permit=if removing {&budgets.2} else if waiting { &budgets.1 } else { &budgets.0 }.clone().try_acquire_owned();
                let wait_permit=if waiting {Some(client.owner.federation.incoming_waits.clone().try_acquire_owned())} else {None};
                let total_permit=if removing {&client.owner.federation.incoming_cleanup} else {&client.owner.federation.incoming}.clone().try_acquire_owned();
                let wait_permit=wait_permit.transpose();
                let (Ok(peer_permit),Ok(total_permit),Ok(wait_permit))=(peer_permit,total_permit,wait_permit) else {
                    client.owner.federation.rejected.fetch_add(1,Ordering::Relaxed);
                    let value=reply(&instance,429,json!({"error":"Coord request admission full; no operation attempted","mutation_outcome":"not_attempted","availability":"busy"}));
                    if !matches!(tokio::time::timeout(Duration::from_secs(2),async {connection.publish(reply_to,value.to_string().into()).await.map_err(|_|())?;connection.flush().await.map_err(|_|())}).await,Ok(Ok(()))) {client.owner.federation.delivery_failures.fetch_add(1,Ordering::Relaxed);}
                    continue;
                };
                let cancellation=if waiting {
                    if let Some((agent,id))=parsed.as_ref().and_then(|peer|Some((peer.source_run.as_ref()?.agent_id.clone(),peer.body.as_ref()?["wait_id"].as_str()?.to_owned()))).filter(|(_,id)|valid_wait_id(id)) {
                        let key=ReadWaitId {source:source.instance_id.clone(),agent,id};
                        match client.owner.federation.register_wait(key.clone()) {
                            Ok(registration)=>Some((ActiveReadWait {owner:client.owner.clone(),key},registration)),
                            Err(_)=>{client.owner.federation.rejected.fetch_add(1,Ordering::Relaxed); let value=reply(&instance,429,json!({"error":"read wait already active; no operation attempted","mutation_outcome":"not_attempted"})); if connection.publish(reply_to,value.to_string().into()).await.is_err(){client.owner.federation.delivery_failures.fetch_add(1,Ordering::Relaxed);} continue;},
                        }
                    } else {None}
                } else {None};
                let credential_hash=source.credential_hash.clone();
                let (client,runtime,connection,instance,source)=(client.clone(),runtime.clone(),connection.clone(),instance.clone(),source.instance_id.clone());
                let config=root.join("config.toml");
                tasks.spawn(async move {crate::host_platform::in_config(config,async {
                    let (_peer_permit,_total_permit,_wait_permit)=(peer_permit,total_permit,wait_permit);
                    let request=receive(&client,&runtime,&instance,&source,&credential_hash,&message.payload);
                    let value=if let Some((active,registration))=cancellation {
                        let _active=active;
                        match futures_util::future::Abortable::new(request,registration).await {
                            Ok(value)=>value,
                            Err(_)=>reply(&instance,503,json!({"error":"read wait cancelled","mutation_outcome":"not_requested"})),
                        }
                    } else {request.await};
                    if !matches!(tokio::time::timeout(Duration::from_secs(2),async {connection.publish(reply_to,value.to_string().into()).await.map_err(|_|())?;connection.flush().await.map_err(|_|())}).await,Ok(Ok(()))) {client.owner.federation.delivery_failures.fetch_add(1,Ordering::Relaxed);}
                }).await;});
            },
            result=tasks.join_next(),if !tasks.is_empty()=>{ if matches!(result,Some(Err(_))) {client.owner.federation.delivery_failures.fetch_add(1,Ordering::Relaxed);} },
        }
    }
}

#[cfg(test)]
mod tests;
