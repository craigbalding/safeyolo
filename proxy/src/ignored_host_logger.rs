//! Canonical ignored-host connection events. The caller supplies the selected
//! destination and owns the physical connection lifetime; this component does
//! not match hosts, schedule work, or emit events when dropped.

#[cfg(test)]
mod tests;

use std::fmt;

use indexmap::IndexMap;
use num_bigint::{BigInt, ToBigInt};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    audit::{self, Event, Kind, Severity, Writer},
    circuits::CircuitValue,
    network_guard::sanitize,
};

/// The source pre-connect matcher has already selected this destination.
pub struct SelectedDestination<'a> {
    pub host: &'a str,
    pub port: u16,
}

/// Current callback facts, not a snapshot retained by the connection session.
pub struct Facts<'a> {
    pub agent: Option<&'a str>,
    pub client: Option<&'a str>,
    pub transport: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Audit(audit::ErrorKind),
    Value,
    Overflow,
}

/// A categorical error never contains a destination, identity or socket error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(ErrorKind);

impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ignored-host lifecycle operation failed")
    }
}
impl std::error::Error for Error {}
impl From<audit::Error> for Error {
    fn from(error: audit::Error) -> Self {
        Self(ErrorKind::Audit(error.kind()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

struct Session {
    host: Zeroizing<String>,
    port: u16,
    started_at: f64,
    connected: bool,
}

impl Session {
    fn event(&self, name: &str, severity: Severity, verb: &str, facts: Facts<'_>) -> Event {
        let mut event = Event::new(
            name,
            Kind::Traffic,
            severity,
            format!(
                "TLS passthrough {verb} {}:{}",
                sanitize(&self.host),
                self.port
            ),
        );
        event.host = Some(self.host.to_string());
        event.agent = facts.agent.map(str::to_owned);
        event.addon = Some("ignored-host-logger".into());
        event.details = CircuitValue::Object(IndexMap::from([
            ("port".into(), i32::from(self.port).into()),
            ("transport".into(), text(facts.transport)),
            (
                "client".into(),
                facts.client.map_or_else(|| Value::Null.into(), text),
            ),
        ]));
        event
    }
}

/// One handle per physical server connection. Operations preserve reached
/// mutations when clocks or audit submission fail; terminal operations consume
/// the session. The caller remains responsible for explicit terminal cleanup.
#[derive(Default)]
pub struct IgnoredHostConnection {
    session: Option<Session>,
}

impl IgnoredHostConnection {
    pub fn new() -> Self {
        Self::default()
    }

    /// A missing match is inert, including when this handle already has a
    /// session. A matched reconnect replaces it only after sampling the clock.
    pub fn connect(
        &mut self,
        selected: Option<SelectedDestination<'_>>,
        clock: impl FnOnce() -> f64,
    ) {
        let Some(selected) = selected else { return };
        let started_at = clock();
        self.session = Some(Session {
            host: Zeroizing::new(selected.host.to_owned()),
            port: selected.port,
            started_at,
            connected: false,
        });
    }

    /// The connected flag is published before the start event is submitted.
    /// Repeated callbacks produce repeated start events, as the source does.
    pub fn connected(&mut self, facts: Facts<'_>, writer: &Writer) -> Result<()> {
        let Some(session) = &mut self.session else {
            return Ok(());
        };
        session.connected = true;
        writer.emit(session.event(
            "traffic.passthrough_start",
            Severity::Medium,
            "connected to",
            facts,
        ))?;
        Ok(())
    }

    /// Consume the session before event construction/submission. Socket errors
    /// are supplied by the caller; an absent source error sanitizes to empty.
    pub fn connect_error(
        &mut self,
        facts: Facts<'_>,
        error: Option<&str>,
        writer: &Writer,
    ) -> Result<()> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        let mut event = session.event(
            "traffic.passthrough_error",
            Severity::Medium,
            "failed for",
            facts,
        );
        let CircuitValue::Object(details) = &mut event.details else {
            unreachable!("session events have object details")
        };
        details.insert("error".into(), text(&sanitize(error.unwrap_or_default())));
        writer.emit(event)?;
        Ok(())
    }

    /// Pop before checking connected or calling the clock. Duration matches
    /// Python round(float) with ties to even and an unbounded integer result.
    pub fn disconnected(
        &mut self,
        facts: Facts<'_>,
        clock: impl FnOnce() -> f64,
        writer: &Writer,
    ) -> Result<()> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        if !session.connected {
            return Ok(());
        }
        let elapsed = (clock() - session.started_at) * 1000.0;
        let duration = elapsed
            .round_ties_even()
            .to_bigint()
            .ok_or(Error(if elapsed.is_nan() {
                ErrorKind::Value
            } else {
                ErrorKind::Overflow
            }))?
            .max(BigInt::from(0));
        let mut event = session.event(
            "traffic.passthrough_end",
            Severity::Low,
            "disconnected from",
            facts,
        );
        let CircuitValue::Object(details) = &mut event.details else {
            unreachable!("session events have object details")
        };
        details.insert("duration_ms".into(), duration.into());
        writer.emit(event)?;
        Ok(())
    }
}

fn text(value: &str) -> CircuitValue {
    Value::String(value.to_owned()).into()
}
