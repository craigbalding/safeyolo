//! Canonical ignored-host evidence follows the owned physical TCP lifetime.
//! Polling, EOF and one half-close do not finalize the connection.

use std::{
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use zeroize::Zeroizing;

use crate::{
    ConnectionIdentity,
    audit::Writer,
    ignored_host_logger::{Facts, IgnoredHostConnection, SelectedDestination},
    tunnels::BoxStream,
};

enum Phase {
    Connecting,
    Connected,
    Finished,
}

pub(super) struct ConnectionAudit {
    connection: IgnoredHostConnection,
    writer: Arc<Writer>,
    agent: Option<Zeroizing<String>>,
    client: Option<Zeroizing<String>>,
    phase: Phase,
}

impl ConnectionAudit {
    pub(super) fn new(
        writer: Arc<Writer>,
        identity: &ConnectionIdentity,
        selected: SelectedDestination<'_>,
    ) -> Self {
        let mut connection = IgnoredHostConnection::new();
        connection.connect(Some(selected), monotonic_time);
        Self {
            connection,
            writer,
            agent: identity
                .request_agent()
                .map(|agent| Zeroizing::new(agent.to_owned())),
            client: identity.source_id.clone().map(Zeroizing::new),
            phase: Phase::Connecting,
        }
    }

    pub(super) fn connected(&mut self) {
        self.phase = Phase::Connected;
        report(self.connection.connected(
            facts(
                self.agent.as_deref().map(String::as_str),
                self.client.as_deref().map(String::as_str),
            ),
            &self.writer,
        ));
    }

    pub(super) fn failed(&mut self, error: &str) {
        self.phase = Phase::Finished;
        report(self.connection.connect_error(
            facts(
                self.agent.as_deref().map(String::as_str),
                self.client.as_deref().map(String::as_str),
            ),
            Some(error),
            &self.writer,
        ));
    }
}

impl Drop for ConnectionAudit {
    fn drop(&mut self) {
        match self.phase {
            Phase::Connecting => self.failed("connection cancelled"),
            Phase::Connected => {
                self.phase = Phase::Finished;
                report(self.connection.disconnected(
                    facts(
                        self.agent.as_deref().map(String::as_str),
                        self.client.as_deref().map(String::as_str),
                    ),
                    monotonic_time,
                    &self.writer,
                ));
            }
            Phase::Finished => {}
        }
    }
}

fn facts<'a>(agent: Option<&'a str>, client: Option<&'a str>) -> Facts<'a> {
    Facts {
        agent,
        client,
        transport: "tcp",
    }
}

fn monotonic_time() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

fn report(result: crate::ignored_host_logger::Result<()>) {
    if let Err(error) = result {
        use std::io::Write as _;
        // Source dispatcher catches these failures and continues transport.
        let _ = writeln!(
            std::io::stderr().lock(),
            "Ignored-host audit failed: {error}"
        );
    }
}

struct ObservedSocket {
    socket: Option<TcpStream>,
    _audit: ConnectionAudit,
}

pub(super) fn observe(socket: TcpStream, audit: ConnectionAudit) -> BoxStream {
    Box::new(ObservedSocket {
        socket: Some(socket),
        _audit: audit,
    })
}

impl Drop for ObservedSocket {
    fn drop(&mut self) {
        // Close the physical socket before the audit field emits its terminal
        // record. Automatic field drop alone would occur after this Drop body.
        drop(self.socket.take());
    }
}

impl AsyncRead for ObservedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.socket.as_mut().expect("live observed socket")).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ObservedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.socket.as_mut().expect("live observed socket")).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.socket.as_mut().expect("live observed socket")).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.socket.as_mut().expect("live observed socket")).poll_shutdown(cx)
    }
}
