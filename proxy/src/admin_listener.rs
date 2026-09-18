//! Startup-owned operator listener, separate from trusted per-agent ingress.

#[cfg(test)]
mod stats_tests;

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, watch},
    task::{JoinHandle, JoinSet},
};
use zeroize::Zeroizing;

use crate::websocket::{Event as WebSocketEvent, Handshake, Reader, Writer};
use crate::{Config, Error, RuntimeState, admin_api, policy::python_whitespace};
use tungstenite::protocol::frame::coding::Control;

pub(crate) struct Prepared {
    listener: TcpListener,
    token: Arc<Zeroizing<String>>,
    address: SocketAddr,
}

type EventTasks = Arc<AsyncMutex<JoinSet<()>>>;

impl Prepared {
    pub(crate) async fn bind(config: &Config) -> Result<Option<Self>, Error> {
        let Some(port) = config.admin_port else {
            return Ok(None);
        };
        let token = Arc::new(read_token(config.admin_api_token_file.as_deref())?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        Ok(Some(Self {
            listener,
            token,
            address,
        }))
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn start(self, state: RuntimeState) -> Running {
        let (stop, receiver) = watch::channel(false);
        let event_tasks = Arc::new(AsyncMutex::new(JoinSet::new()));
        Running {
            address: self.address,
            stop,
            _event_tasks: event_tasks.clone(),
            task: Some(tokio::spawn(accept(self, state, receiver, event_tasks))),
        }
    }
}

pub(crate) struct Running {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    _event_tasks: EventTasks,
    task: Option<JoinHandle<()>>,
}

impl Running {
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn stop(mut self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task.take().expect("operator listener task is owned")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

fn read_token(path: Option<&Path>) -> Result<Zeroizing<String>, Error> {
    let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(Zeroizing::new(String::new()));
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(Zeroizing::new(String::new()));
        }
        Err(error) => return Err(error.into()),
    };
    let source = std::str::from_utf8(&bytes)?;
    let mut token = Zeroizing::new(String::with_capacity(source.len()));
    let mut chars = source.chars().peekable();
    // Python's startup text-file read translates universal newlines before strip.
    while let Some(character) = chars.next() {
        if character == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            token.push('\n');
        } else {
            token.push(character);
        }
    }
    Ok(token)
}

async fn accept(
    prepared: Prepared,
    state: RuntimeState,
    mut stop: watch::Receiver<bool>,
    event_tasks: EventTasks,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = prepared.listener.accept() => match accepted {
                Ok((socket, peer)) => {
                    connections.spawn(serve_connection(
                        socket,
                        peer,
                        state.clone(),
                        prepared.token.clone(),
                        stop.clone(),
                        event_tasks.clone(),
                    ));
                }
                Err(_) => {
                    eprintln!("Operator API listener failed");
                    if let Ok(runtime) = state.read() {
                        crate::clear_readiness(&runtime.config.readiness_file, &runtime.instance_id);
                    }
                    break;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
        }
    }
    drop(prepared.listener);
    if tokio::time::timeout(Duration::from_secs(10), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    let event_tasks_for_join = event_tasks.clone();
    if tokio::time::timeout(
        Duration::from_secs(2),
        drain_event_tasks(event_tasks_for_join.clone()),
    )
    .await
    .is_err()
    {
        let mut tasks = event_tasks_for_join.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

async fn drain_event_tasks(event_tasks: EventTasks) {
    let mut tasks = event_tasks.lock().await;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            eprintln!("operator event stream failed: {error}");
        }
    }
}

async fn spawn_event_task<F>(event_tasks: &EventTasks, task: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut tasks = event_tasks.lock().await;
    while let Some(result) = tasks.try_join_next() {
        if let Err(error) = result {
            eprintln!("operator event stream failed: {error}");
        }
    }
    tasks.spawn(task);
}

async fn serve_connection(
    socket: TcpStream,
    peer: SocketAddr,
    state: RuntimeState,
    token: Arc<Zeroizing<String>>,
    mut stop: watch::Receiver<bool>,
    event_tasks: EventTasks,
) {
    let event_stop = stop.clone();
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let token = token.clone();
        let event_stop = event_stop.clone();
        let event_tasks = event_tasks.clone();
        async move {
            let runtime = state
                .read()
                .map_err(|_| admin_api::Error::RegistryUnavailable)?
                .clone();
            let target = request.uri().to_string();
            // BaseHTTPRequestHandler collapses a leading // before dispatch.
            // Keep query and absolute-form presentation independently of routes.
            let path = if target.starts_with("//") {
                format!("/{}", target.trim_start_matches('/'))
            } else {
                target
            };
            let client_ip = request
                .headers()
                .get("x-forwarded-for")
                .filter(|value| !value.as_bytes().is_empty())
                .map(|value| {
                    // The source HTTP header parser decodes Latin-1. This is
                    // client-provided audit text, never trusted agent identity.
                    let value: String = value
                        .as_bytes()
                        .iter()
                        .map(|byte| char::from(*byte))
                        .collect();
                    value
                        .split(',')
                        .next()
                        .unwrap()
                        .trim_matches(python_whitespace)
                        .to_owned()
                })
                .unwrap_or_else(|| peer.ip().to_string());
            if request.method() == hyper::Method::GET && request.uri().path() == "/admin/events" {
                return serve_events(
                    request,
                    runtime,
                    token.trim_matches(python_whitespace),
                    event_stop,
                    client_ip,
                    path,
                    event_tasks,
                )
                .await;
            }
            let stats = || {
                let runtime = runtime.clone();
                tokio::task::spawn_blocking(move || crate::operator_stats::document(&runtime))
            };
            let outcome = admin_api::respond_with_context(
                request,
                token.trim_matches(python_whitespace),
                admin_api::OperatorContext {
                    tasks: &runtime.tasks,
                    policy: runtime.policy.as_ref(),
                    circuits: runtime.policy.as_ref().map(|_| &runtime.circuits),
                    stats: Some(&stats),
                    view: Some(&runtime.traffic_view),
                    policy_path: runtime.config.policy_file.as_deref(),
                    instance_id: Some(&runtime.instance_id),
                    admin_address: runtime.admin_address,
                    operator_modes: Some(&runtime.operator_modes),
                    agent_discovery: Some(&runtime.agent_discovery),
                    listeners: &runtime.config.listeners,
                    audit: Some(&runtime.audit),
                    client_ip: Some(&client_ip),
                    service_audit: Some(admin_api::ServiceAudit {
                        writer: &runtime.audit,
                        client_ip: &client_ip,
                        target: &path,
                        mutation_owner: &runtime.service_mutations,
                        gateway_store: runtime.gateway_grants.as_ref(),
                    }),
                    plumb: Some(runtime.plumb.as_ref()),
                },
            )
            .await?
            .submit_audit(&runtime.audit, &client_ip, &path)?;
            let audits = outcome.audit().map(|intent| match intent {
                admin_api::Audit::AuthenticationFailed => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.auth_failure",
                    "client_ip":client_ip, "path":path,
                    "reason":"invalid_or_missing_token",
                })],
                admin_api::Audit::TaskUpdated {
                    task_id,
                    permission_count,
                } => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.task_policy_update",
                    "client_ip":client_ip, "task_id":task_id,
                    "permission_count":permission_count,
                })],
                admin_api::Audit::CircuitReset(reset) => reset.events(&client_ip).into(),
                admin_api::Audit::ServiceAuthorized(_) => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.agent_service_authorized",
                    "client_ip":client_ip,
                })],
                admin_api::Audit::ServiceRevoked(_) => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.agent_service_revoked",
                    "client_ip":client_ip,
                })],
                admin_api::Audit::TrafficScopeUpdated(_) => vec![json!({
                    "event":"proxy.admin_api", "audit_intent":"admin.traffic_scope_update",
                    "client_ip":client_ip,
                })],
                admin_api::Audit::BudgetsReset(reset) => {
                    let safe_resource = reset.safe_resource();
                    let engine_resource = if reset.resets_all() {
                        serde_json::Value::String("all".into())
                    } else {
                        reset.resource().clone()
                    };
                    vec![
                        json!({"event":"proxy.admin_api", "audit_intent":"admin.budget_reset",
                            "kind":"admin", "severity":"medium", "addon":"policy-engine",
                            "summary":if reset.resets_all() { "All budgets reset".into() }
                                else { format!("Budget reset for {safe_resource}") },
                            "resource":engine_resource}),
                        json!({"event":"proxy.admin_api", "audit_intent":"admin.budgets_reset",
                            "kind":"admin", "severity":"medium", "addon":"admin-api",
                            "summary":format!("Budget counters reset: {safe_resource}"),
                            "client_ip":client_ip, "resource":reset.resource()}),
                    ]
                }
                admin_api::Audit::PolicyMutation(_) | admin_api::Audit::ModeChanged { .. } => {
                    vec![]
                }
                admin_api::Audit::PlumbMutation(_) => vec![],
            });
            // Diagnostic sink failures remain separate from canonical producer
            // exceptions. Attempt each diagnostic without claiming rollback.
            let mut failed = false;
            for event in audits.into_iter().flatten() {
                failed |= runtime.record(event).is_err();
            }
            let mut response = outcome.into_response();
            if failed {
                eprintln!("Operator API evidence write failed");
                response
                    .headers_mut()
                    .insert("x-safeyolo-evidence-error", "true".parse().unwrap());
            }
            Ok::<_, admin_api::Error>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    // The shipped BaseHTTPRequestHandler closes after its HTTP/1.0 response.
    builder.keep_alive(false);
    let connection = builder
        .serve_connection(TokioIo::new(socket), service)
        .with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

async fn serve_events(
    mut request: hyper::Request<hyper::body::Incoming>,
    runtime: std::sync::Arc<crate::Runtime>,
    token: &str,
    stop: watch::Receiver<bool>,
    client_ip: String,
    target: String,
    event_tasks: EventTasks,
) -> Result<hyper::Response<crate::admin_api::AdminBody>, admin_api::Error> {
    if !admin_api::authenticate(request.headers(), token)
        .map_err(|_| admin_api::Error::AuthenticationEncoding)?
    {
        return Ok(admin_api::unauthorized()
            .submit_audit(&runtime.audit, &client_ip, &target)?
            .into_response());
    }
    let path = runtime.audit.path().to_owned();
    // Capture the source position after authentication, but before the 101 is
    // returned. Events appended while the handshake is in flight are then
    // delivered, while no event already present in the log is replayed.
    let offset = audit_offset(&path);
    let handshake = Handshake::request(&mut request).map_err(|_| admin_api::Error::BodyFraming)?;
    let upgrade = hyper::upgrade::on(request);
    let body = Full::new(Bytes::new())
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed();
    let response = handshake
        .server_response(body)
        .map_err(|_| admin_api::Error::BodyFraming)?;
    spawn_event_task(&event_tasks, async move {
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        stream_events(upgraded, path, offset, stop).await;
    })
    .await;
    Ok(response)
}

fn audit_offset(path: &Path) -> u64 {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

async fn stream_events(
    upgraded: hyper::upgrade::Upgraded,
    path: std::path::PathBuf,
    mut offset: u64,
    mut stop: watch::Receiver<bool>,
) {
    let (read, write) = tokio::io::split(TokioIo::new(upgraded));
    let mut reader = Reader::new(read, true, None);
    let mut writer = Writer::new(write, false, None);
    let mut pending = Vec::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => {
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    writer.control(Control::Close, &[0x03, 0xe9]),
                ).await;
                let _ = tokio::time::timeout(Duration::from_secs(1), writer.shutdown()).await;
                return;
            }
            event = reader.read() => {
                match event {
                    Ok(WebSocketEvent::Ping(payload)) => {
                        if !matches!(
                            tokio::time::timeout(
                                Duration::from_secs(1),
                                writer.control(Control::Pong, &payload),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            return;
                        }
                    }
                    Ok(WebSocketEvent::Close(payload)) => {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(1),
                            writer.control(Control::Close, &payload),
                        ).await;
                        let _ = tokio::time::timeout(Duration::from_secs(1), writer.shutdown()).await;
                        return;
                    }
                    Ok(WebSocketEvent::Pong(_)) | Ok(WebSocketEvent::Message(_)) => {}
                    Err(_) => return,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                let lines = read_event_lines(&path, &mut offset, &mut pending).await;
                for line in lines {
                    let Ok(line) = String::from_utf8(line) else {
                        continue;
                    };
                    if !matches!(
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            writer.message(crate::websocket::Message::text_for_send(line)),
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        return;
                    }
                }
            }
        }
    }
}

async fn read_event_lines(path: &Path, offset: &mut u64, pending: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let Ok(metadata) = tokio::fs::metadata(path).await else {
        return Vec::new();
    };
    if metadata.len() < *offset {
        *offset = 0;
        pending.clear();
    }
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return Vec::new();
    };
    if file.seek(std::io::SeekFrom::Start(*offset)).await.is_err() {
        return Vec::new();
    }
    let mut chunk = vec![0u8; 16 * 1024];
    let Ok(read) = file.read(&mut chunk).await else {
        return Vec::new();
    };
    if read == 0 {
        return Vec::new();
    }
    *offset += read as u64;
    pending.extend_from_slice(&chunk[..read]);
    // A malformed producer line cannot grow the stream owner without limit.
    if pending.len() > 1024 * 1024 {
        if let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            pending.drain(..=newline);
        } else {
            pending.clear();
        }
    }
    let mut lines = Vec::new();
    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
        let mut line = pending.drain(..=newline).collect::<Vec<_>>();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if let Ok(event) = serde_json::from_slice::<serde_json::Value>(&line)
            && is_operator_event(&event)
            && let Ok(encoded) = serde_json::to_vec(&event)
        {
            lines.push(encoded);
        }
    }
    lines
}

fn is_operator_event(event: &serde_json::Value) -> bool {
    let approval = event.get("approval").and_then(serde_json::Value::as_object);
    if approval
        .and_then(|approval| approval.get("required"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    let event_name = event
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if event_name.starts_with("agent.")
        || event_name == "ops.circuit_breaker.open"
        || matches!(
            event_name,
            "admin.approval_added"
                | "admin.denial"
                | "admin.host_allowed"
                | "admin.host_denied"
                | "admin.host_rate_updated"
                | "admin.host_bypass_added"
                | "admin.mode_change"
                | "admin.baseline_update"
                | "admin.task_policy_update"
                | "admin.agent_service_authorized"
                | "admin.agent_service_revoked"
                | "admin.gateway_grant"
                | "admin.gateway_grant_revoked"
                | "admin.contract_binding_approved"
                | "admin.desktop_presented"
                | "plumb.approved"
                | "plumb.denied"
                | "plumb.conversation_created"
                | "plumb.message_blocked"
                | "plumb.message_flagged"
                | "plumb.message_allowed"
                | "plumb.conversation_closed"
        )
        || matches!(
            event_name,
            "ops.command_centre_tailnet_exited"
                | "ops.command_centre_tailnet_failed"
                | "ops.command_centre_tailnet_started"
                | "ops.command_centre_tailnet_stopped"
                | "ops.proxy_start"
                | "ops.proxy_stop"
                | "ops.proxy_start_failed"
        )
    {
        return true;
    }
    event
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| matches!(kind, "security" | "gateway"))
        && event
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|severity| matches!(severity, "high" | "critical"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn captured_audit_offset_excludes_old_lines_and_includes_following_lines() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        std::fs::write(&path, b"{\"event\":\"admin.denial\",\"details\":{}}\n").unwrap();
        let mut offset = audit_offset(&path);
        let mut pending = Vec::new();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"event\":\"admin.host_allowed\",\"details\":{}}\n")
            .unwrap();

        let lines = read_event_lines(&path, &mut offset, &mut pending).await;
        assert_eq!(lines.len(), 1);
        let event: serde_json::Value = serde_json::from_slice(&lines[0]).unwrap();
        assert_eq!(event["event"], "admin.host_allowed");
    }

    #[tokio::test]
    async fn completed_event_subscription_is_reaped_before_reconnect() {
        let event_tasks = Arc::new(AsyncMutex::new(JoinSet::new()));
        let (finished, wait_for_finish) = tokio::sync::oneshot::channel();
        spawn_event_task(&event_tasks, async move {
            let _ = finished.send(());
        })
        .await;
        wait_for_finish.await.unwrap();
        // Let the completed subscription reach the JoinSet before the
        // replacement subscription models a reconnect.
        tokio::time::sleep(Duration::from_millis(1)).await;

        let (_release, release_receiver) = tokio::sync::oneshot::channel::<()>();
        spawn_event_task(&event_tasks, async move {
            let _ = release_receiver.await;
        })
        .await;

        let mut tasks = event_tasks.lock().await;
        assert_eq!(tasks.len(), 1, "the completed subscription was reaped");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
