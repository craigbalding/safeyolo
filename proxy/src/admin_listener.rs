//! Startup-owned operator listener, separate from trusted per-agent ingress.

#[cfg(test)]
mod stats_tests;

#[cfg(test)]
mod mutation_tests;

use std::{
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use zeroize::Zeroizing;

use crate::websocket::{Event as WebSocketEvent, Handshake, Reader, Writer};
use crate::{Config, Error, RuntimeState, admin_api, command_centre, policy::python_whitespace};
use tungstenite::protocol::frame::coding::Control;

pub(crate) struct Prepared {
    listener: TcpListener,
    events_listener: Option<TcpListener>,
    token: Arc<Zeroizing<String>>,
    address: SocketAddr,
    events_address: Option<SocketAddr>,
    command_centre: Option<command_centre::Host>,
}

pub(crate) type EventTasks = Arc<AsyncMutex<JoinSet<()>>>;

#[derive(Clone)]
struct ConnectionAccess {
    events: Arc<crate::operator_events::Feed>,
    events_only: bool,
    token: Arc<Zeroizing<String>>,
    command_centre: Option<command_centre::Host>,
}

/// Keep blocking statistics work owned by the operator listener. The request
/// only owns the result receiver; the listener joins the worker before proxy
/// shutdown stops the shared audit writer.
struct StatsTasks {
    tasks: Mutex<JoinSet<()>>,
    closing: AtomicBool,
}

impl StatsTasks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tasks: Mutex::new(JoinSet::new()),
            closing: AtomicBool::new(false),
        })
    }

    fn spawn<R: Send + 'static>(&self, work: impl FnOnce() -> R + Send + 'static) -> JoinHandle<R> {
        let (sender, receiver) = oneshot::channel();
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        if self.closing.load(Ordering::Acquire) {
            drop(tasks);
            return tokio::spawn(async {
                panic!("closed statistics owner cannot return a result")
            });
        }
        tasks.spawn_blocking(move || {
            let _ = sender.send(work());
        });
        drop(tasks);
        tokio::spawn(async move {
            receiver
                .await
                .expect("statistics worker must return a result")
        })
    }

    async fn drain(&self) {
        // Publish the closing fence before waiting for the registration lock.
        // A spawn that already holds the lock either registers before this
        // drain acquires it or observes the fence and does not start work.
        self.closing.store(true, Ordering::Release);
        loop {
            let result = poll_fn(|context| {
                self.tasks
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .poll_join_next(context)
            })
            .await;
            let Some(result) = result else {
                return;
            };
            if let Err(error) = result {
                eprintln!("operator statistics worker failed: {error}");
            }
        }
    }
}

impl Prepared {
    pub(crate) async fn bind(config: &Config) -> Result<Option<Self>, Error> {
        let command_centre = command_centre::Host::from_config(config)?;
        let Some(port) = config.admin_port else {
            if command_centre
                .as_ref()
                .is_some_and(|host| host.events_port().is_some())
            {
                return Err("Command Centre events require an Admin listener".into());
            }
            return Ok(None);
        };
        let token = Arc::new(read_token(config.admin_api_token_file.as_deref())?);
        if command_centre
            .as_ref()
            .is_some_and(|host| host.events_port().is_some())
            && token.trim_matches(python_whitespace).is_empty()
        {
            return Err("Command Centre events require an Admin API token".into());
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        let events_listener = if let Some(events_port) = command_centre
            .as_ref()
            .and_then(command_centre::Host::events_port)
        {
            if events_port == address.port() {
                return Err("Command Centre event port must differ from the Admin port".into());
            }
            Some(TcpListener::bind((Ipv4Addr::LOCALHOST, events_port)).await?)
        } else {
            None
        };
        let events_address = events_listener
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()?;
        Ok(Some(Self {
            listener,
            events_listener,
            token,
            address,
            events_address,
            command_centre,
        }))
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn event_address(&self) -> Option<SocketAddr> {
        self.events_address
    }

    pub(crate) fn command_centre(&self) -> Option<command_centre::Host> {
        self.command_centre.clone()
    }

    pub(crate) fn start(self, state: RuntimeState) -> Running {
        let (stop, receiver) = watch::channel(false);
        let event_tasks = Arc::new(AsyncMutex::new(JoinSet::new()));
        let stats_tasks = StatsTasks::new();
        Running {
            address: self.address,
            events_address: self.events_address,
            stop,
            _event_tasks: event_tasks.clone(),
            _stats_tasks: stats_tasks.clone(),
            task: Some(tokio::spawn(accept(
                self,
                state,
                receiver,
                event_tasks,
                stats_tasks,
            ))),
        }
    }
}

pub(crate) struct Running {
    address: SocketAddr,
    events_address: Option<SocketAddr>,
    stop: watch::Sender<bool>,
    _event_tasks: EventTasks,
    _stats_tasks: Arc<StatsTasks>,
    task: Option<JoinHandle<()>>,
}

impl Running {
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn event_address(&self) -> Option<SocketAddr> {
        self.events_address
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

pub(crate) fn read_token(path: Option<&Path>) -> Result<Zeroizing<String>, Error> {
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
    stats_tasks: Arc<StatsTasks>,
) {
    let events =
        crate::operator_events::Feed::start(state.clone(), stop.clone(), &event_tasks).await;
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
                        ConnectionAccess {
                            events: events.clone(),
                            events_only: false,
                            token: prepared.token.clone(),
                            command_centre: prepared.command_centre.clone(),
                        },
                        state.clone(),
                        stop.clone(),
                        event_tasks.clone(),
                        stats_tasks.clone(),
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
            accepted = async {
                match &prepared.events_listener {
                    Some(listener) => listener.accept().await,
                    None => std::future::pending().await,
                }
            } => match accepted {
                Ok((socket, peer)) => {
                    connections.spawn(serve_connection(
                        socket,
                        peer,
                        ConnectionAccess {
                            events: events.clone(),
                            events_only: true,
                            token: prepared.token.clone(),
                            command_centre: prepared.command_centre.clone(),
                        },
                        state.clone(),
                        stop.clone(),
                        event_tasks.clone(),
                        stats_tasks.clone(),
                    ));
                }
                Err(_) => {
                    eprintln!("Command Centre event listener failed");
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
    drop(prepared.events_listener);
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
    stats_tasks.drain().await;
}

async fn drain_event_tasks(event_tasks: EventTasks) {
    let mut tasks = event_tasks.lock().await;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            eprintln!("operator event stream failed: {error}");
        }
    }
}

pub(crate) async fn spawn_event_task<F>(event_tasks: &EventTasks, task: F)
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
    access: ConnectionAccess,
    state: RuntimeState,
    mut stop: watch::Receiver<bool>,
    event_tasks: EventTasks,
    stats_tasks: Arc<StatsTasks>,
) {
    let event_stop = stop.clone();
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let access = access.clone();
        let event_stop = event_stop.clone();
        let event_tasks = event_tasks.clone();
        let stats_tasks = stats_tasks.clone();
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
            if request.method() == hyper::Method::GET && request.uri().path() == "/admin/capture" {
                return serve_capture(
                    request,
                    runtime,
                    access.token.trim_matches(python_whitespace),
                    event_stop,
                    client_ip,
                    path,
                    event_tasks,
                )
                .await
                .map(close_http_response_unless_upgrade);
            }
            if request.method() == hyper::Method::GET && request.uri().path() == "/admin/events" {
                return serve_events(
                    request,
                    runtime,
                    &access,
                    event_stop,
                    client_ip,
                    path,
                    event_tasks,
                )
                .await
                .map(|response| {
                    if response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
                        response
                    } else {
                        close_http_response(response)
                    }
                });
            }
            if access.events_only {
                return Ok::<_, admin_api::Error>(close_http_response(
                    admin_api::event_not_found().into_response(),
                ));
            }
            if crate::jobs::network::route(request.uri().path()) {
                return crate::jobs::network::serve(
                    request,
                    state,
                    access.token.trim_matches(python_whitespace),
                    event_stop,
                    &event_tasks,
                )
                .await
                .map(close_http_response_unless_upgrade);
            }
            let stats = |allocator| {
                let runtime = runtime.clone();
                stats_tasks.spawn(move || crate::operator_stats::document(&runtime, allocator))
            };
            let outcome = admin_api::respond_with_context(
                request,
                access.token.trim_matches(python_whitespace),
                admin_api::OperatorContext {
                    tasks: &runtime.tasks,
                    policy: runtime.policy.as_ref(),
                    circuits: runtime.policy.as_ref().map(|_| &runtime.circuits),
                    stats: Some(&stats),
                    view: Some(&runtime.traffic_view),
                    policy_path: runtime.config.policy_file.as_deref(),
                    instance_id: Some(&runtime.instance_id),
                    command_centre: access.command_centre.as_ref(),
                    operator_modes: Some(&runtime.operator_modes),
                    agent_activity: Some(&runtime.agent_activity),
                    listeners: &runtime.config.listeners,
                    audit: Some(&runtime.audit),
                    client_ip: Some(&client_ip),
                    passthrough: Some(&runtime.passthrough),
                    service_audit: Some(admin_api::ServiceAudit {
                        writer: &runtime.audit,
                        client_ip: &client_ip,
                        target: &path,
                        mutation_owner: &runtime.service_mutations,
                        gateway_store: runtime.gateway_grants.as_ref(),
                    }),
                    task_state: Some(&state),
                },
            )
            .await?
            .submit_audit_with_desktop_confirmation(&runtime.audit, &client_ip, &path)
            .await?;
            let response = outcome.into_response();
            Ok::<_, admin_api::Error>(close_http_response(response))
        }
    });
    // Hyper replaces Connection: Upgrade with Connection: close on a 101 when
    // keep_alive(false) is set. Close ordinary responses explicitly instead.
    let builder = hyper::server::conn::http1::Builder::new();
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

fn close_http_response_unless_upgrade<B>(response: hyper::Response<B>) -> hyper::Response<B> {
    if response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
        response
    } else {
        close_http_response(response)
    }
}

fn close_http_response<B>(mut response: hyper::Response<B>) -> hyper::Response<B> {
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}

async fn serve_events(
    mut request: hyper::Request<hyper::body::Incoming>,
    runtime: std::sync::Arc<crate::Runtime>,
    access: &ConnectionAccess,
    stop: watch::Receiver<bool>,
    client_ip: String,
    target: String,
    event_tasks: EventTasks,
) -> Result<hyper::Response<crate::admin_api::AdminBody>, admin_api::Error> {
    if !admin_api::authenticate(
        request.headers(),
        access.token.trim_matches(python_whitespace),
    )
    .map_err(|_| admin_api::Error::AuthenticationEncoding)?
    {
        let mut response = admin_api::unauthorized()
            .submit_audit(&runtime.audit, &client_ip, &target)?
            .into_response();
        response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
        return Ok(response);
    }
    let handshake = Handshake::request(&mut request).map_err(|_| admin_api::Error::BodyFraming)?;
    // Register before 101 and before the client's canonical snapshot. The
    // shared state receiver retains changes even when invalidations coalesce.
    let subscription = access.events.subscribe();
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
        stream_events(upgraded, subscription, stop).await;
    })
    .await;
    Ok(response)
}

async fn stream_events(
    upgraded: hyper::upgrade::Upgraded,
    mut subscription: crate::operator_events::Subscription,
    mut stop: watch::Receiver<bool>,
) {
    let (read, write) = tokio::io::split(TokioIo::new(upgraded));
    // Keep the frame read future inside the stream while state/event sends
    // win the select. Canceling a partial WebSocket read would corrupt the
    // next ping or close frame.
    let incoming =
        futures_util::stream::unfold(Reader::new(read, true, None), |mut reader| async move {
            let event = reader.read().await;
            Some((event, reader))
        });
    futures_util::pin_mut!(incoming);
    let mut writer = Writer::new(write, false, None);
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
            event = incoming.next() => {
                match event.expect("frame stream always yields a result") {
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
            event = subscription.next() => {
                let Ok(line) = event else {
                    let _ = tokio::time::timeout(Duration::from_secs(1), writer.control(Control::Close, &[0x03, 0xf5])).await;
                    return;
                };
                let Ok(mut event) = serde_json::from_slice::<serde_json::Value>(&line) else { return };
                let eligible = crate::operator_events::is_operator_event(&event) || event["type"] == "operator_state";
                crate::credentials::wipe_json(&mut event);
                if eligible {
                    let Ok(line) = String::from_utf8(line.to_vec()) else { return };
                    if !matches!(tokio::time::timeout(Duration::from_secs(1), writer.message(crate::websocket::Message::text_for_send(line))).await, Ok(Ok(()))) {
                        return;
                    }
                }
            }
        }
    }
}

async fn serve_capture(
    mut request: hyper::Request<hyper::body::Incoming>,
    runtime: Arc<crate::Runtime>,
    token: &str,
    stop: watch::Receiver<bool>,
    client_ip: String,
    target: String,
    tasks: EventTasks,
) -> Result<hyper::Response<crate::admin_api::AdminBody>, admin_api::Error> {
    // DOC: docs/native-observations.md
    let read = admin_api::authenticate(request.headers(), token)?;
    let capture = runtime
        .connection_events
        .as_ref()
        .and_then(|events| events.observations.capture.get())
        .filter(|capture| capture.settings.wss);
    let secrets = match capture {
        Some(capture) => capture.authorize_secrets(request.headers())?,
        None => false,
    };
    if !read && !secrets {
        return Ok(admin_api::unauthorized()
            .submit_audit(&runtime.audit, &client_ip, &target)?
            .into_response());
    }
    let Some(capture) = capture else {
        return Ok(admin_api::event_not_found().into_response());
    };
    let handshake = Handshake::request(&mut request).map_err(|_| admin_api::Error::BodyFraming)?;
    let Ok(receiver) = capture.subscribe_authorized(crate::packet_capture::Sink::Wss, secrets)
    else {
        return Ok(hyper::Response::builder()
            .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
            .body(
                Full::new(Bytes::new())
                    .map_err(|never: std::convert::Infallible| match never {})
                    .boxed(),
            )
            .unwrap());
    };
    let upgrade = hyper::upgrade::on(request);
    let body = Full::new(Bytes::new())
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed();
    let response = handshake
        .server_response(body)
        .map_err(|_| admin_api::Error::BodyFraming)?;
    spawn_event_task(&tasks, async move {
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        stream_capture(upgraded, receiver, stop).await;
    })
    .await;
    Ok(response)
}
async fn stream_capture(
    upgraded: hyper::upgrade::Upgraded,
    mut receiver: crate::packet_capture::Receiver,
    mut stop: watch::Receiver<bool>,
) {
    let (read, write) = tokio::io::split(TokioIo::new(upgraded));
    let mut reader = Reader::new(read, true, None);
    let mut writer = Writer::new(write, false, None);
    loop {
        // Keep a partially received client frame alive across capture deliveries.
        // Reader::read may only be cancelled when discarding this connection.
        let incoming = reader.read();
        tokio::pin!(incoming);
        loop {
            tokio::select! {
                biased;
                _=stop.changed()=>return,
                event=&mut incoming=>match event {
                    Ok(WebSocketEvent::Ping(bytes))=>{
                        if !matches!(tokio::time::timeout(Duration::from_secs(1),writer.control(Control::Pong,&bytes)).await,Ok(Ok(()))) {receiver.error("wss_control_failed");return;}
                        break;
                    },
                    Ok(WebSocketEvent::Pong(_))=>break,
                    Ok(WebSocketEvent::Close(bytes))=>{let _=tokio::time::timeout(Duration::from_secs(1),writer.control(Control::Close,&bytes)).await;return;},
                    Ok(WebSocketEvent::Message(_))=>break,
                    Err(_)=>return,
                },
                delivery=receiver.recv()=>{
                    let Some(delivery)=delivery else {return;};
                    if !matches!(tokio::time::timeout(Duration::from_secs(1),writer.binary(&delivery.bytes)).await,Ok(Ok(()))) {receiver.error("wss_write_failed_or_timed_out");return;}
                    receiver.written(delivery.bytes.len());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_statistics_result_remains_owned_until_listener_drain() {
        let owner = StatsTasks::new();
        let (started, started_receiver) = tokio::sync::oneshot::channel();
        let (release, release_receiver) = std::sync::mpsc::channel();
        let result = owner.spawn(move || {
            started.send(()).expect("worker start signal receiver");
            release_receiver.recv().expect("statistics worker release");
            7_u8
        });
        started_receiver
            .await
            .expect("statistics worker must start");
        result.abort();

        let mut drain = tokio::spawn({
            let owner = owner.clone();
            async move { owner.drain().await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut drain)
                .await
                .is_err(),
            "listener drain must retain a canceled statistics worker"
        );
        release
            .send(())
            .expect("statistics worker must remain owned");
        drain.await.expect("statistics owner drain must join");
        assert!(owner.tasks.lock().unwrap().is_empty());
    }
}
