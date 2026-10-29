//! Sparse audit records follow transport ownership through TLS and upgrades.
//! Dropping the final owner closes a lifecycle; EOF and half-close do not.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{ConnectionIdentity, Runtime, audit, tunnels::BoxStream};

pub(crate) mod novelty;

pub(crate) struct ConnectionEvents {
    writer: Arc<audit::Writer>,
    instance_id: String,
    runtime_id: String,
    novelty: Mutex<novelty::History>,
    pub(crate) observations: Arc<crate::observations::ObservationBus>,
}

impl ConnectionEvents {
    pub(crate) fn new(
        config: &crate::Config,
        runtime_id: &str,
        writer: Arc<audit::Writer>,
        metrics: &crate::metrics::Metrics,
    ) -> Option<Arc<Self>> {
        let instance_id = match crate::command_centre::Host::from_config(config) {
            Ok(Some(host)) => match host.instance_id() {
                Ok(id) => id,
                Err(_) => {
                    eprintln!("Connection audit durable instance identity unavailable");
                    return None;
                }
            },
            // A standalone proxy has no installed instance identity. Its
            // namespace is process-local, including across policy reloads.
            Ok(None) => runtime_id.to_owned(),
            Err(_) => {
                eprintln!("Connection audit instance configuration unavailable");
                return None;
            }
        };
        let counters = metrics
            .observations
            .get_or_init(|| Arc::new(crate::observations::Counters::default()))
            .clone();
        let observations = crate::observations::ObservationBus::with_payload(
            instance_id.clone(),
            runtime_id.to_owned(),
            config
                .native_settings
                .as_ref()
                .map_or_else(Default::default, |settings| settings.observations),
            counters,
            config
                .native_settings
                .as_ref()
                .map_or_else(Vec::new, |settings| {
                    settings.packet_capture.payload_layers()
                }),
        );
        Some(Arc::new(Self {
            observations,
            writer,
            instance_id,
            runtime_id: runtime_id.to_owned(),
            novelty: Mutex::new(novelty::History::default()),
        }))
    }

    /// Add scope without submitting: the caller retains its ordinary or
    /// confirmed audit write and pending-approval binding.
    pub(crate) fn bind_request(&self, identity: &ConnectionIdentity, event: &mut audit::Event) {
        event.bind_request_scope(
            &self.instance_id,
            &self.runtime_id,
            &identity.connection_id,
            identity.run.as_ref(),
        );
        event.agent = identity.request_agent().map(str::to_owned);
        event.attribution = Some(identity.audit_attribution());
    }

    pub(crate) fn emit(
        &self,
        identity: &ConnectionIdentity,
        mut event: audit::Event,
        mut details: Value,
    ) {
        details["instance_id"] = json!(self.instance_id);
        details["runtime_id"] = json!(self.runtime_id);
        // Historical provenance is the accepted ingress snapshot. A late close
        // still belongs to it, even after current-run authority has expired.
        details
            .as_object_mut()
            .expect("NSM details")
            .remove("sandbox_run");
        if let Some(run) = &identity.run {
            details["sandbox_run"] = json!(run);
        }
        event.agent = identity.request_agent().map(str::to_owned);
        event.attribution = Some(identity.audit_attribution());
        event.details = details.into();
        if let Err(error) = self.writer.emit(event) {
            eprintln!("NSM audit submission failed: {error}");
        }
    }

    pub(crate) fn ingress(
        self: &Arc<Self>,
        identity: &ConnectionIdentity,
        socket: &tokio::net::UnixStream,
    ) -> Connection {
        let connection = self.connection(
            identity,
            &identity.connection_id,
            "client_to_proxy",
            "unix",
            None,
            None,
            None,
            None,
        );
        connection.connected(
            socket
                .local_addr()
                .ok()
                .map(|address| unix_endpoint(address.as_pathname())),
            socket
                .peer_addr()
                .ok()
                .map(|address| unix_endpoint(address.as_pathname())),
            None,
        );
        connection
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn upstream(
        self: &Arc<Self>,
        identity: &ConnectionIdentity,
        id: &str,
        target: &str,
        destination_host_and_port: (&str, u16),
        route: &'static str,
        transport: &'static str,
        client: Option<&Connection>,
    ) -> Connection {
        self.connection(
            identity,
            id,
            "proxy_to_upstream",
            transport,
            Some(target),
            Some(route),
            Some(novelty::Destination::new(
                destination_host_and_port.0,
                destination_host_and_port.1,
                route,
            )),
            client.cloned(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn connection(
        self: &Arc<Self>,
        identity: &ConnectionIdentity,
        id: &str,
        leg: &'static str,
        transport: &'static str,
        target: Option<&str>,
        route: Option<&str>,
        destination: Option<novelty::Destination>,
        client: Option<Connection>,
    ) -> Connection {
        let started = OffsetDateTime::now_utc();
        let mut details = json!({
            "connection_id":id, "leg":leg, "transport":transport,
            "started_at":timestamp(started), "ended_at":null, "state":"open",
            "local_endpoint":null, "remote_endpoint":null,
            "requested_target":target, "resolved_peer":null,
            "resolved_origin_peer":null, "route":route, "ingress":"agent-uds",
        });
        if leg == "proxy_to_upstream" {
            details["client_connection_id"] = json!(identity.connection_id);
        }
        let source = crate::observations::Source::new(
            self.observations.clone(),
            identity,
            id,
            if leg == "client_to_proxy" {
                crate::observations::Point::AgentUds
            } else {
                crate::observations::Point::Upstream
            },
            crate::observations::Layer::TransportStream,
            match transport {
                "unix" => crate::observations::Transport::Unix,
                "tcp" => crate::observations::Transport::Tcp,
                _ => crate::observations::Transport::Provider,
            },
            None,
        );
        Connection(Arc::new(ConnectionEnd {
            wire: Mutex::new(None),
            events: self.clone(),
            identity: identity.clone(),
            destination,
            client,
            client_destination_observed: AtomicBool::new(false),
            source: Mutex::new(source),
            facts: Mutex::new(Facts {
                details,
                started,
                connected: false,
                error: None,
                client_hello_observation: None,
                connected_observation: None,
            }),
        }))
    }
}

fn timestamp(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).expect("format UTC timestamp")
}

fn unix_endpoint(path: Option<&std::path::Path>) -> Value {
    json!({"type":"unix", "path":path.and_then(std::path::Path::to_str)})
}

pub(crate) fn ip_endpoint(address: SocketAddr) -> Value {
    json!({"type":"ip", "address":address})
}

struct Facts {
    details: Value,
    started: OffsetDateTime,
    connected: bool,
    error: Option<&'static str>,
    client_hello_observation: Option<novelty::Observation>,
    connected_observation: Option<novelty::Observation>,
}

struct ConnectionEnd {
    events: Arc<ConnectionEvents>,
    identity: ConnectionIdentity,
    destination: Option<novelty::Destination>,
    client: Option<Connection>,
    client_destination_observed: AtomicBool,
    facts: Mutex<Facts>,
    source: Mutex<Arc<crate::observations::Source>>,
    wire: Mutex<Option<crate::packet_capture::wire::Ownership>>,
}

impl ConnectionEnd {
    fn emit(&self, details: Value) -> novelty::Observation {
        let event_id = uuid::Uuid::new_v4().to_string();
        let observation = novelty::Observation::new(
            details["connection_id"]
                .as_str()
                .expect("transport-owned connection ID"),
            event_id.clone(),
        );
        let mut event = audit::Event::new(
            "network.connection",
            audit::Kind::Network,
            audit::Severity::Low,
            "Connection lifecycle",
        );
        event.event_id = Some(event_id);
        self.events.emit(&self.identity, event, details);
        observation
    }

    fn emit_observation(
        &self,
        details: Value,
        tls: Option<(&str, &crate::tls_identity::TlsSession)>,
        observe_destination: bool,
    ) -> novelty::Observation {
        if self.destination.is_none() || self.identity.request_agent().is_none() {
            return self.emit(details);
        }
        // Read the ingress before taking history: ClientHello takes its own
        // facts lock before history, so the inverse order would deadlock.
        let client = self.client_hello_observation();
        if !observe_destination && client.is_none() {
            return self.emit(details);
        }
        // Serialize the supporting record, comparison and indication together.
        // Concurrent handshakes must not reverse the baseline's audit order.
        let mut history = self
            .events
            .novelty
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Only the direct socket owner currently supplies this origin peer.
        // The immediate parent/provider peer does not measure an origin IP.
        let origin_ip = details["resolved_origin_peer"]
            .as_str()
            .and_then(|peer| peer.parse::<SocketAddr>().ok())
            .map(|peer| peer.ip());
        let observation = self.emit(details);
        if observe_destination {
            self.events.observe_destination(
                &mut history,
                &self.identity,
                self.destination.as_ref(),
                observation.clone(),
                tls,
                origin_ip,
            );
        }
        if let Some(client) = client {
            self.compare_client_destination(&mut history, client, observation.clone());
        }
        observation
    }

    fn compare_client_destination(
        &self,
        history: &mut novelty::History,
        client: novelty::Observation,
        observation: novelty::Observation,
    ) {
        if !self
            .client_destination_observed
            .swap(true, Ordering::Relaxed)
        {
            self.events.observe_client_destination(
                history,
                &self.identity,
                self.destination.as_ref().expect("upstream destination"),
                client,
                observation,
            );
        }
    }

    fn client_hello_observation(&self) -> Option<novelty::Observation> {
        if self.client_destination_observed.load(Ordering::Relaxed) {
            return None;
        }
        self.client
            .as_ref()?
            .0
            .facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .client_hello_observation
            .clone()
    }
}

impl Drop for ConnectionEnd {
    fn drop(&mut self) {
        let mut facts = self.facts.lock().unwrap_or_else(|error| error.into_inner());
        let error = facts
            .error
            .or((!facts.connected).then_some("connect_cancelled"));
        facts.details["state"] = json!(if error.is_some() { "failed" } else { "closed" });
        // A wall-clock adjustment cannot make the serialized end precede start.
        facts.details["ended_at"] = json!(timestamp(OffsetDateTime::now_utc().max(facts.started)));
        facts.details["error"] = json!(error);
        self.source
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .connection_state(if error.is_some() {
                crate::observations::State::Failed
            } else {
                crate::observations::State::Closed
            });
        self.emit_observation(facts.details.clone(), None, !facts.connected);
    }
}

#[derive(Clone)]
pub(crate) struct Connection(Arc<ConnectionEnd>);

impl Connection {
    pub(crate) fn wire_connected(&self, local: SocketAddr, remote: SocketAddr) {
        let source = self.source();
        if let Some(wire) = source.wire() {
            *self.0.wire.lock().unwrap_or_else(|e| e.into_inner()) =
                wire.register(local, remote, source.clone());
        }
    }
    pub(crate) fn connected(
        &self,
        local: Option<Value>,
        remote: Option<Value>,
        origin: Option<SocketAddr>,
    ) {
        let mut facts = self
            .0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if facts.connected {
            return;
        }
        facts.connected = true;
        self.source()
            .connection_state(crate::observations::State::Connected);
        facts.details["local_endpoint"] = json!(local);
        facts.details["remote_endpoint"] = json!(remote);
        facts.details["resolved_peer"] = facts.details["remote_endpoint"]
            .get("address")
            .cloned()
            .unwrap_or(Value::Null);
        facts.details["resolved_origin_peer"] = json!(origin);
        facts.connected_observation =
            Some(self.0.emit_observation(facts.details.clone(), None, true));
    }

    pub(crate) fn source(&self) -> Arc<crate::observations::Source> {
        self.0
            .source
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(crate) fn observe_tls(
        &self,
        stream: BoxStream,
        point: crate::observations::Point,
    ) -> BoxStream {
        let mut source = self.0.source.lock().unwrap_or_else(|e| e.into_inner());
        *source = source.tls(point);
        crate::observations::observe(stream, source.clone())
    }

    pub(crate) fn failed(&self, category: &'static str) {
        self.0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .error
            .get_or_insert(category);
    }

    pub(crate) fn http_error(&self, error: &(dyn std::error::Error + 'static)) {
        let mut cause = Some(error);
        while let Some(error) = cause {
            if let Some(error) = error.downcast_ref::<hyper::Error>()
                && self.source().parser_error(error)
            {
                break;
            }
            cause = error.source();
        }
        self.failed("http_error");
    }

    pub(crate) fn tls(&self, name: &str) {
        // Rustls omits SNI for an IP verification name.
        if name.parse::<std::net::IpAddr>().is_ok() {
            return;
        }
        let mut facts = self
            .0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        facts.details["tls_server_name"] = json!(name);
    }

    pub(crate) fn client_hello(&self, hello: crate::tls_identity::ClientHello) {
        let mut facts = self
            .0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        facts.details["tls_client_hello"] = json!(hello);
        let mut snapshot = facts.details.clone();
        snapshot["state"] = json!("updated");
        if snapshot["leg"] != "client_to_proxy" || self.0.identity.request_agent().is_none() {
            self.0.emit(snapshot);
            return;
        }
        // The observed client bytes and their comparison share the audit order.
        let mut history = self
            .0
            .events
            .novelty
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let observation = self.0.emit(snapshot);
        facts.client_hello_observation = observation.clone().with_client_fingerprint(&hello);
        self.0.events.observe_client_fingerprint(
            &mut history,
            &self.0.identity,
            &hello,
            observation,
        );
    }

    /// The CONNECT attempt can connect before its client sends TLS bytes.
    /// The byte observer calls this when that attempt acquires a ClientHello.
    pub(crate) fn observe_client_destination(&self) {
        let facts = self.0.facts.lock().unwrap_or_else(|e| e.into_inner());
        let (Some(client), Some(observation)) = (
            self.0.client_hello_observation(),
            &facts.connected_observation,
        ) else {
            return;
        };
        let mut history = self
            .0
            .events
            .novelty
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.0
            .compare_client_destination(&mut history, client, observation.clone());
    }

    pub(crate) fn tls_session(&self, peer: &str, name: &str, session: &rustls::ClientConnection) {
        let session = crate::tls_identity::TlsSession::observed(peer, name, session);
        if let Some(name) = session.sni.as_deref() {
            self.tls(name);
        }
        self.update_tls(Some((name, &session)), |details| {
            if !details["tls_sessions"].is_array() {
                details["tls_sessions"] = json!([]);
            }
            details["tls_sessions"]
                .as_array_mut()
                .unwrap()
                .push(json!(session));
        });
    }

    pub(crate) fn server_hello(&self, hello: crate::tls_identity::ServerHelloObservation) {
        self.update_tls(None, |details| details["tls_server_hello"] = json!(hello));
    }

    fn update_tls(
        &self,
        tls: Option<(&str, &crate::tls_identity::TlsSession)>,
        update: impl FnOnce(&mut Value),
    ) {
        let mut facts = self
            .0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        update(&mut facts.details);
        let mut snapshot = facts.details.clone();
        snapshot["state"] = json!("updated");
        if tls.is_some() {
            self.0.emit_observation(snapshot, tls, true);
        } else {
            self.0.emit(snapshot);
        }
    }
}

struct ObservedStream {
    stream: Option<BoxStream>,
    connection: Connection,
}

pub(crate) fn observe(stream: BoxStream, connection: Option<Connection>) -> BoxStream {
    match connection {
        Some(connection) => Box::new(ObservedStream {
            stream: Some(crate::observations::observe(stream, connection.source())),
            connection,
        }),
        None => stream,
    }
}

impl Drop for ObservedStream {
    fn drop(&mut self) {
        drop(self.stream.take());
    }
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(self.stream.as_mut().unwrap()).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Err(_))) {
            self.connection.failed("read_error");
        }
        result
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(self.stream.as_mut().unwrap()).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Err(_))) {
            self.connection.failed("write_error");
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(self.stream.as_mut().unwrap()).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.connection.failed("write_error");
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(self.stream.as_mut().unwrap()).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.connection.failed("write_error");
        }
        result
    }
}

/// One correlation record per exchange, including local replies and failures.
/// This owner contains no bodies, and never enables FlowStore capture.
pub(crate) struct Flow {
    events: Arc<ConnectionEvents>,
    identity: ConnectionIdentity,
    request_id: String,
    pub(crate) server_connection_id: Option<String>,
}

impl Flow {
    pub(crate) fn new(
        runtime: &Runtime,
        identity: &ConnectionIdentity,
        request_id: &str,
    ) -> Option<Self> {
        Some(Self {
            events: runtime.connection_events.clone()?,
            identity: identity.clone(),
            request_id: request_id.to_owned(),
            server_connection_id: None,
        })
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        let mut event = audit::Event::new(
            "traffic.flow",
            audit::Kind::Traffic,
            audit::Severity::Low,
            "Flow connection correlation",
        );
        event.request_id = Some(self.request_id.clone());
        self.events.emit(
            &self.identity,
            event,
            json!({
                "client_connection_id":self.identity.connection_id,
                "server_connection_id":self.server_connection_id,
            }),
        );
    }
}

#[cfg(test)]
pub(crate) mod tests;
