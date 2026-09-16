//! Development WS message relay. Each writer owns its compression dictionary.
//! Queues retain at most one complete spooled message in each direction. A
//! close stops admission; writers finish an active frame before sending close.

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
};
use tungstenite::protocol::frame::coding::Control;

use crate::{
    ConnectionIdentity, Error, RuntimeState, UpgradeTasks,
    connection_tasks::Task,
    inspection,
    memory_monitor::MemoryMonitor,
    memory_runtime,
    traffic_view::Exchange,
    tunnels::BoxStream,
    websocket::{Event, MessageType, Negotiated, Reader, ReceiveError, Writer},
};

pub(crate) struct Session {
    pub state: RuntimeState,
    pub identity: ConnectionIdentity,
    pub request_id: String,
    pub host: String,
    pub port: u16,
    pub live: Option<Arc<Exchange>>,
}

/// Held by the upgrade future separately from the readers and blocking workers.
/// Even an unpolled or canceled upgrade ends its view session on release.
pub(crate) struct LiveSession(Option<Arc<Exchange>>);

impl Session {
    pub(crate) fn start_live(&self) -> LiveSession {
        if let Some(live) = &self.live {
            live.websocket_start(crate::circuit_runtime::now());
        }
        LiveSession(self.live.clone())
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        if let Some(live) = &self.0 {
            live.websocket_cancel(crate::circuit_runtime::now());
        }
    }
}

struct InspectionLifetime {
    cancelled: AtomicBool,
    publication: Mutex<()>,
}

struct CancelInspectionOnDrop(Arc<InspectionLifetime>);

impl Drop for CancelInspectionOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
struct Closing {
    payload: Vec<u8>,
    code: u16,
    from_client: Option<bool>,
    outcome: &'static str,
}
impl Closing {
    fn failure(code: u16, from_client: Option<bool>, outcome: &'static str) -> Self {
        Self {
            // wsproto uses normal closure on the wire for local-only 1006.
            payload: if code == 1006 { 1000u16 } else { code }
                .to_be_bytes()
                .to_vec(),
            code,
            from_client,
            outcome,
        }
    }
}

enum Finished {
    Reader(Closing),
    Writer(Result<(), Error>),
    Stopped,
}

#[allow(clippy::too_many_arguments)]
async fn read_messages<R: AsyncRead + Unpin>(
    mut reader: Reader<R>,
    from_client: bool,
    destination: mpsc::Sender<Event>,
    mut closing: watch::Receiver<Option<Closing>>,
    session: Arc<Session>,
    inspection_lifetime: Arc<InspectionLifetime>,
    memory: Arc<MemoryMonitor>,
    tasks: UpgradeTasks,
) -> Finished {
    loop {
        let event = tokio::select! {
            biased;
            _ = closing.changed() => return Finished::Stopped,
            result = reader.read() => match result {
                Ok(event) => event,
                Err(error) => return Finished::Reader(Closing::failure(
                    error.close_code().unwrap_or(1006), Some(from_client), match error {
                        ReceiveError::Protocol => "protocol_error",
                        ReceiveError::InvalidPayload => "invalid_payload",
                        ReceiveError::Transport(_) => "transport_error",
                        ReceiveError::Storage => "storage_error",
                    },
                )),
            }
        };
        let event = match event {
            Event::Close(payload) => {
                return Finished::Reader(Closing {
                    code: payload
                        .get(..2)
                        .map_or(1005, |bytes| u16::from_be_bytes([bytes[0], bytes[1]])),
                    payload,
                    from_client: Some(from_client),
                    outcome: "peer_close",
                });
            }
            Event::Message(message) => {
                // Source appends complete unmasked/decompressed content before
                // invoking hooks. Observe before either direction awaits its
                // scanner, so diagnostic failure cannot erase received bytes.
                let observed = session.live.as_ref().and_then(|live| {
                    live.websocket_message(
                        message.kind,
                        from_client,
                        crate::circuit_runtime::now(),
                        message.content(),
                    )
                });
                // The source counts every complete data message before later
                // scanner decisions, including messages the scanner drops.
                // Observation failure must not skip that security decision.
                memory_runtime::observe(memory.websocket_message(&session.identity.connection_id));
                let state = session.clone();
                let lifetime = inspection_lifetime.clone();
                // Complete-message decoding, matching and synchronous evidence
                // writes run outside the asynchronous connection executor.
                let mut inspecting = tasks.spawn_blocking(move || -> Result<_, Error> {
                    if lifetime.cancelled.load(Ordering::Acquire) {
                        return Ok((message, true));
                    }
                    let runtime = state
                        .state
                        .read()
                        .map_err(|_| "runtime state unavailable")?
                        .clone();
                    let options = runtime.config.inspection.as_ref().map_or_else(
                        inspection::Options::default,
                        |config| inspection::Options {
                            block_websocket_request: Some(config.block_websocket_request),
                            block_websocket_response: Some(config.block_websocket_response),
                            ..Default::default()
                        },
                    );
                    let direction = if from_client {
                        inspection::Direction::Request
                    } else {
                        inspection::Direction::Response
                    };
                    let kind = match message.kind {
                        MessageType::Text => inspection::MessageType::Text,
                        MessageType::Binary => inspection::MessageType::Binary,
                    };
                    let decision = message.with_text(|text| {
                        runtime.scanner.scan_websocket_text_cancellable(
                            direction,
                            kind,
                            text,
                            options,
                            &lifetime.cancelled,
                        )
                    });
                    let (drop_message, decision, failure) = match decision {
                        Ok(Ok(decision)) => (decision.drop_message, Some(decision), None),
                        Ok(Err(_)) => (true, None, Some("inspection_state")),
                        Err(_) => (true, None, Some("inspection_storage")),
                    };
                    // A reached scanner drop precedes evidence publication.
                    // The observation is retained even if that write fails.
                    if let (Some(live), Some(id)) = (&state.live, observed) {
                        live.websocket_message_dropped(id, drop_message);
                    }
                    let _publication = lifetime
                        .publication
                        .lock()
                        .map_err(|_| "WebSocket inspection publication unavailable")?;
                    if lifetime.cancelled.load(Ordering::Acquire) {
                        return Ok((message, true));
                    }
                    runtime.record(json!({
                        "event": "proxy.websocket.message", "agent": state.identity.agent_id,
                        "connection_id": state.identity.connection_id, "request_id": state.request_id,
                        "host": state.host, "port": state.port, "from_client": from_client,
                        "message_type": kind, "message_bytes": message.len(),
                        "fragments": message.fragment_count(), "spilled": message.spilled(),
                        "dropped": drop_message, "inspection": decision, "failure": failure,
                    }))?;
                    Ok((message, drop_message))
                });
                let result = tokio::select! {
                    biased;
                    _ = closing.changed() => {
                        // Abort a queued worker; an already-running worker must
                        // observe the cancellation flag and return. Awaiting it
                        // makes the session's drain result include inspection.
                        inspecting.abort();
                        let _ = inspecting.await;
                        return Finished::Stopped;
                    },
                    result = &mut inspecting => result,
                };
                match result {
                    Ok(Ok((_, true))) => continue,
                    Ok(Ok((message, false))) => Event::Message(message),
                    _ => {
                        return Finished::Reader(Closing::failure(
                            1011,
                            Some(from_client),
                            "inspection_error",
                        ));
                    }
                }
            }
            control => control,
        };
        tokio::select! {
            biased;
            _ = closing.changed() => return Finished::Stopped,
            result = destination.send(event) => if result.is_err() { return Finished::Stopped; },
        }
    }
}

async fn write_messages<W: AsyncWrite + Unpin>(
    mut writer: Writer<W>,
    mut messages: mpsc::Receiver<Event>,
    mut closing: watch::Receiver<Option<Closing>>,
) -> Result<(), Error> {
    loop {
        let close = closing.borrow().clone();
        if let Some(close) = close {
            // Messages admitted before the close remain ordered before it.
            // In particular, DATA+CLOSE in one read must deliver the data.
            while let Ok(event) = messages.try_recv() {
                write_event(&mut writer, event).await?;
            }
            writer.control(Control::Close, &close.payload).await?;
            return writer.shutdown().await;
        }
        let event = tokio::select! {
            biased;
            _ = closing.changed() => continue,
            event = messages.recv() => event,
        };
        match event {
            Some(event) => write_event(&mut writer, event).await?,
            None => {
                closing.changed().await?;
            }
        }
    }
}

async fn write_event<W: AsyncWrite + Unpin>(
    writer: &mut Writer<W>,
    event: Event,
) -> Result<(), Error> {
    match event {
        Event::Message(message) => writer.message(message).await,
        Event::Ping(payload) => writer.control(Control::Ping, &payload).await,
        Event::Pong(payload) => writer.control(Control::Pong, &payload).await,
        Event::Close(_) => unreachable!("close belongs to the session owner"),
    }
}

// Receivers preserve relay-specific completion/error handling. Their actual
// async tasks and blocking scanners are joined by the accepted connection.
struct RelayTasks {
    owner: UpgradeTasks,
    pending: Vec<Task<Finished>>,
}
impl RelayTasks {
    fn spawn(&mut self, future: impl Future<Output = Finished> + Send + 'static) {
        self.pending.push(self.owner.spawn_result(future));
    }
    async fn join_next(
        &mut self,
    ) -> Option<Result<Finished, tokio::sync::oneshot::error::RecvError>> {
        poll_fn(|cx| {
            for index in 0..self.pending.len() {
                if let Poll::Ready(result) = Pin::new(&mut self.pending[index]).poll(cx) {
                    drop(self.pending.swap_remove(index));
                    return Poll::Ready(Some(result));
                }
            }
            if self.pending.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        })
        .await
    }
    fn abort_all(&self) {
        for task in &self.pending {
            task.abort();
        }
    }
}

pub(crate) async fn relay(
    client: BoxStream,
    server: BoxStream,
    negotiated: Negotiated,
    session: Session,
    mut stop: watch::Receiver<bool>,
    memory: memory_runtime::WebSocket,
    owner: UpgradeTasks,
) -> Result<(), Error> {
    let monitor = memory.monitor();
    let _memory = memory;
    let session = Arc::new(session);
    let inspection_lifetime = Arc::new(InspectionLifetime {
        cancelled: AtomicBool::new(false),
        publication: Mutex::new(()),
    });
    // Relay cancellation also signals its inspection worker. Aborting the
    // reader cannot stop spawn_blocking work that already started.
    let _cancel_inspection = CancelInspectionOnDrop(inspection_lifetime.clone());
    let started = std::time::Instant::now();
    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let (to_server, server_messages) = mpsc::channel(1);
    let (to_client, client_messages) = mpsc::channel(1);
    let (closing, close) = watch::channel(None);
    let mut tasks = RelayTasks {
        owner: owner.clone(),
        pending: Vec::new(),
    };
    tasks.spawn(read_messages(
        Reader::new(client_read, true, negotiated.client),
        true,
        to_server,
        close.clone(),
        session.clone(),
        inspection_lifetime.clone(),
        monitor.clone(),
        owner.clone(),
    ));
    tasks.spawn(read_messages(
        Reader::new(server_read, false, negotiated.server),
        false,
        to_client,
        close.clone(),
        session.clone(),
        inspection_lifetime.clone(),
        monitor,
        owner,
    ));
    let client_close = close.clone();
    tasks.spawn(async move {
        Finished::Writer(
            write_messages(
                Writer::new(client_write, false, negotiated.server),
                client_messages,
                client_close,
            )
            .await,
        )
    });
    tasks.spawn(async move {
        Finished::Writer(
            write_messages(
                Writer::new(server_write, true, negotiated.client),
                server_messages,
                close,
            )
            .await,
        )
    });
    let end = if *stop.borrow() {
        Closing::failure(1001, None, "shutdown")
    } else {
        loop {
            tokio::select! {
                biased;
                _ = stop.changed() => break Closing::failure(1001, None, "shutdown"),
                result = tasks.join_next() => match result {
                    Some(Ok(Finished::Reader(end))) => break end,
                    Some(Ok(Finished::Writer(Err(_)))) => break Closing::failure(1006, None, "write_error"),
                    Some(Ok(Finished::Stopped | Finished::Writer(Ok(())))) => (),
                    Some(Err(_)) | None => break Closing::failure(1011, None, "task_error"),
                }
            }
        }
    };
    if let Some(live) = &session.live {
        let reason = (end.outcome == "peer_close")
            .then(|| std::str::from_utf8(end.payload.get(2..).unwrap_or_default()).ok())
            .flatten();
        live.websocket_end(
            crate::circuit_runtime::now(),
            end.from_client,
            Some(end.code),
            reason,
            (!matches!(end.outcome, "peer_close" | "shutdown")).then_some(end.outcome),
        );
    }
    {
        let _publication = inspection_lifetime
            .publication
            .lock()
            .map_err(|_| "WebSocket inspection publication unavailable")?;
        inspection_lifetime.cancelled.store(true, Ordering::Release);
    }
    closing.send_replace(Some(end.clone()));
    // This is the listener's existing shutdown grace, applied after closure;
    // open messages have no new size, idle, or total-duration limit.
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !drained {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    let runtime = session
        .state
        .read()
        .map_err(|_| "runtime state unavailable")?
        .clone();
    runtime.record(json!({
        "event": "proxy.websocket.end", "agent": session.identity.agent_id,
        "connection_id": session.identity.connection_id, "request_id": session.request_id,
        "host": session.host, "port": session.port, "close_code": end.code,
        "closed_by_client": end.from_client, "outcome": end.outcome,
        "drained": drained, "duration_ms": started.elapsed().as_millis(),
    }))
}

#[cfg(test)]
mod tests;
