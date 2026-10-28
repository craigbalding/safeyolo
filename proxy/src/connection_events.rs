//! Sparse audit records follow transport ownership through TLS and upgrades.
//! Dropping the final owner closes a lifecycle; EOF and half-close do not.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{ConnectionIdentity, Runtime, audit, tunnels::BoxStream};

pub(crate) struct ConnectionEvents {
    writer: Arc<audit::Writer>,
    instance_id: String,
    runtime_id: String,
}

impl ConnectionEvents {
    pub(crate) fn new(
        config: &crate::Config,
        runtime_id: &str,
        writer: Arc<audit::Writer>,
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
        Some(Arc::new(Self {
            writer,
            instance_id,
            runtime_id: runtime_id.to_owned(),
        }))
    }

    pub(crate) fn emit(
        &self,
        identity: &ConnectionIdentity,
        mut event: audit::Event,
        mut details: Value,
    ) {
        details["instance_id"] = json!(self.instance_id);
        details["runtime_id"] = json!(self.runtime_id);
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

    pub(crate) fn upstream(
        self: &Arc<Self>,
        identity: &ConnectionIdentity,
        id: &str,
        target: &str,
        route: &'static str,
        transport: &'static str,
    ) -> Connection {
        self.connection(
            identity,
            id,
            "proxy_to_upstream",
            transport,
            Some(target),
            Some(route),
        )
    }

    fn connection(
        self: &Arc<Self>,
        identity: &ConnectionIdentity,
        id: &str,
        leg: &'static str,
        transport: &'static str,
        target: Option<&str>,
        route: Option<&str>,
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
        Connection(Arc::new(ConnectionEnd {
            events: self.clone(),
            identity: identity.clone(),
            facts: Mutex::new(Facts {
                details,
                started,
                connected: false,
                error: None,
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
}

struct ConnectionEnd {
    events: Arc<ConnectionEvents>,
    identity: ConnectionIdentity,
    facts: Mutex<Facts>,
}

impl ConnectionEnd {
    fn emit(&self, details: Value) {
        self.events.emit(
            &self.identity,
            audit::Event::new(
                "network.connection",
                audit::Kind::Network,
                audit::Severity::Low,
                "Connection lifecycle",
            ),
            details,
        );
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
        self.emit(facts.details.clone());
    }
}

#[derive(Clone)]
pub(crate) struct Connection(Arc<ConnectionEnd>);

impl Connection {
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
        facts.details["local_endpoint"] = json!(local);
        facts.details["remote_endpoint"] = json!(remote);
        facts.details["resolved_peer"] = facts.details["remote_endpoint"]
            .get("address")
            .cloned()
            .unwrap_or(Value::Null);
        facts.details["resolved_origin_peer"] = json!(origin);
        self.0.emit(facts.details.clone());
    }

    pub(crate) fn failed(&self, category: &'static str) {
        self.0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .error
            .get_or_insert(category);
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
        self.update_tls(|details| {
            details["tls_client_hello"] = json!(hello);
        });
    }

    pub(crate) fn tls_session(&self, peer: &str, name: &str, session: &rustls::ClientConnection) {
        let session = crate::tls_identity::TlsSession::observed(peer, name, session);
        if let Some(name) = session.sni.as_deref() {
            self.tls(name);
        }
        self.update_tls(|details| {
            if !details["tls_sessions"].is_array() {
                details["tls_sessions"] = json!([]);
            }
            details["tls_sessions"]
                .as_array_mut()
                .unwrap()
                .push(json!(session));
        });
    }

    fn update_tls(&self, update: impl FnOnce(&mut Value)) {
        let mut facts = self
            .0
            .facts
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        update(&mut facts.details);
        let mut snapshot = facts.details.clone();
        snapshot["state"] = json!("updated");
        self.0.emit(snapshot);
    }
}

struct ObservedStream {
    stream: Option<BoxStream>,
    connection: Connection,
}

pub(crate) fn observe(stream: BoxStream, connection: Option<Connection>) -> BoxStream {
    match connection {
        Some(connection) => Box::new(ObservedStream {
            stream: Some(stream),
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
