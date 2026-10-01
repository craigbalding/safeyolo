//! Source memory/connection monitor component. Callers own reached lifecycle
//! hooks, decoded content, wall clocks and process sampling. No timer, policy
//! decision, transport activation or body/message retention lives here.

pub mod process;

#[cfg(test)]
mod tests;

use std::{
    fmt,
    sync::{Mutex, MutexGuard},
};

use indexmap::IndexMap;
use num_bigint::{BigInt, ToBigInt};
use serde_json::Value;
use zeroize::Zeroize;

use crate::{
    audit::{self, Event, Kind, Severity, Writer},
    circuits::{CircuitValue as C, ErrorKind as NumericError},
    http_content::ContentError,
    network_guard::sanitize,
};

/// The process sampler's completed result, including its source peak fallback.
#[derive(Clone)]
pub struct MemorySample {
    pub rss_kb: BigInt,
    pub peak_kb: BigInt,
}

/// The source sampler catches OSError/ValueError but not a missing value token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleError {
    Index,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Poisoned,
    Sample(SampleError),
    Content(ContentError),
    Numeric(NumericError),
    Audit(audit::ErrorKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(ErrorKind);
impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("memory monitor operation failed")
    }
}
impl std::error::Error for Error {}
impl From<SampleError> for Error {
    fn from(error: SampleError) -> Self {
        Self(ErrorKind::Sample(error))
    }
}
impl From<ContentError> for Error {
    fn from(error: ContentError) -> Self {
        Self(ErrorKind::Content(error))
    }
}
impl From<crate::circuits::Error> for Error {
    fn from(error: crate::circuits::Error) -> Self {
        Self(ErrorKind::Numeric(error.kind()))
    }
}
pub type Result<T> = std::result::Result<T, Error>;

struct Connection {
    domain: Option<String>,
    started: f64,
    flows: BigInt,
    sent: BigInt,
    received: BigInt,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.domain.zeroize();
    }
}
struct WebSocket {
    domain: String,
    started: f64,
    messages: BigInt,
}
impl Drop for WebSocket {
    fn drop(&mut self) {
        self.domain.zeroize();
    }
}
#[derive(Default)]
struct State {
    connections: IndexMap<String, Connection>,
    websockets: IndexMap<String, WebSocket>,
    rss_start_kb: BigInt,
    started: f64,
    last_event_time: f64,
    total_flows: BigInt,
}
impl Drop for State {
    fn drop(&mut self) {
        for (mut key, _) in self.connections.drain(..) {
            key.zeroize();
        }
        for (mut key, _) in self.websockets.drain(..) {
            key.zeroize();
        }
    }
}

/// One owner per process, retained across ordinary runtime reloads. The short
/// synchronous hook callbacks must not re-enter this owner while its state is
/// locked. No state is rolled back when decoding, sampling or submission fails.
#[derive(Default)]
pub struct MemoryMonitor {
    state: Mutex<State>,
}

impl MemoryMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))
    }

    /// Sample baseline, then read the wall clock twice. Repeated running calls
    /// replace the baseline/times without clearing connections, WS or totals.
    pub fn running(
        &self,
        writer: &Writer,
        sample: impl FnOnce() -> std::result::Result<MemorySample, SampleError>,
        mut clock: impl FnMut() -> f64,
    ) -> Result<()> {
        let mut state = self.lock()?;
        state.rss_start_kb = sample()?.rss_kb;
        state.started = clock();
        state.last_event_time = clock();
        // Arithmetic shift is floor division by 1024, including negative input.
        let whole_mb = &state.rss_start_kb >> 10_usize;
        let mut event = event(
            "ops.startup",
            format!("Memory monitor started (baseline RSS: {whole_mb} MB)"),
        );
        event.details = object([("rss_start_mb", C::Float(megabytes(&state.rss_start_kb)?))]);
        submit(writer, event)
    }

    pub fn client_connected(&self, id: &str, clock: impl FnOnce() -> f64) -> Result<()> {
        let mut state = self.lock()?;
        let started = clock();
        state.connections.insert(
            id.into(),
            Connection {
                domain: None,
                started,
                flows: 0.into(),
                sent: 0.into(),
                received: 0.into(),
            },
        );
        Ok(())
    }

    pub fn client_disconnected(
        &self,
        id: &str,
        writer: &Writer,
        clock: impl FnOnce() -> f64,
    ) -> Result<()> {
        let mut state = self.lock()?;
        let Some((mut key, info)) = state.connections.shift_remove_entry(id) else {
            return Ok(());
        };
        key.zeroize();
        if info.flows <= BigInt::from(0) {
            return Ok(());
        }
        let lifetime = age(clock(), info.started)?;
        let domain = display_domain(info.domain.as_deref());
        let mut event = event(
            "ops.memory.conn_closed",
            format!(
                "Connection closed: {} ({} flows, {lifetime}s)",
                sanitize(domain),
                info.flows,
            ),
        );
        event.host = info
            .domain
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned();
        event.details = object([
            ("flow_count", info.flows.clone().into()),
            ("lifetime_s", lifetime.into()),
            ("bytes_sent", info.sent.clone().into()),
            ("bytes_received", info.received.clone().into()),
        ]);
        submit(writer, event)
    }

    /// Only a known connection reaches decoded-size evaluation. Total/count/
    /// first-domain assignment precede it; periodic time is sampled afterward.
    pub fn request(
        &self,
        id: &str,
        host: &str,
        writer: &Writer,
        decoded_size: impl FnOnce() -> std::result::Result<u64, ContentError>,
        clock: impl FnOnce() -> f64,
        sample: impl FnOnce() -> std::result::Result<MemorySample, SampleError>,
    ) -> Result<()> {
        let mut state = self.lock()?;
        state.total_flows += 1;
        if let Some(info) = state.connections.get_mut(id) {
            info.flows += 1;
            if info.domain.is_none() {
                info.domain = Some(host.into());
            }
            info.sent += decoded_size()?;
        }
        let now = clock();
        if now - state.last_event_time >= 60. {
            state.last_event_time = now;
            periodic(&state, now, sample()?, writer)?;
        }
        Ok(())
    }

    /// A missing/streamed response and an unknown connection never decode.
    pub fn response(
        &self,
        id: &str,
        present: bool,
        streamed: bool,
        decoded_size: impl FnOnce() -> std::result::Result<u64, ContentError>,
    ) -> Result<()> {
        if !present || streamed {
            return Ok(());
        }
        if let Some(info) = self.lock()?.connections.get_mut(id) {
            info.received += decoded_size()?;
        }
        Ok(())
    }

    pub fn websocket_start(&self, id: &str, host: &str, clock: impl FnOnce() -> f64) -> Result<()> {
        let mut state = self.lock()?;
        let started = clock();
        state.websockets.insert(
            id.into(),
            WebSocket {
                domain: host.into(),
                started,
                messages: 0.into(),
            },
        );
        Ok(())
    }

    /// One complete data-message hook; there is no payload or byte counter.
    pub fn websocket_message(&self, id: &str) -> Result<()> {
        if let Some(info) = self.lock()?.websockets.get_mut(id) {
            info.messages += 1;
        }
        Ok(())
    }

    pub fn websocket_end(
        &self,
        id: &str,
        writer: &Writer,
        clock: impl FnOnce() -> f64,
    ) -> Result<()> {
        let mut state = self.lock()?;
        let Some((mut key, info)) = state.websockets.shift_remove_entry(id) else {
            return Ok(());
        };
        key.zeroize();
        let lifetime = age(clock(), info.started)?;
        let mut event = event(
            "ops.memory.ws_closed",
            format!(
                "WebSocket closed: {} ({} msgs, {lifetime}s)",
                sanitize(&info.domain),
                info.messages,
            ),
        );
        event.host = Some(info.domain.clone());
        event.details = object([
            ("message_count", info.messages.clone().into()),
            ("lifetime_s", lifetime.into()),
        ]);
        submit(writer, event)
    }

    /// Sample memory then wall time. Source computes every sorted connection's
    /// age before slicing the result to ten; WS reports have no presentation cap.
    pub fn get_stats(
        &self,
        sample: impl FnOnce() -> std::result::Result<MemorySample, SampleError>,
        clock: impl FnOnce() -> f64,
    ) -> Result<C> {
        let state = self.lock()?;
        let memory = sample()?;
        let now = clock();
        let mut connections = Vec::with_capacity(state.connections.len());
        for info in sorted_connections(&state) {
            connections.push(object([
                ("domain", text(display_domain(info.domain.as_deref()))),
                ("flows", info.flows.clone().into()),
                ("age_s", age(now, info.started)?.into()),
                ("bytes_sent", info.sent.clone().into()),
                ("bytes_received", info.received.clone().into()),
            ]));
        }
        let mut websockets = Vec::with_capacity(state.websockets.len());
        for info in state.websockets.values() {
            websockets.push(object([
                ("domain", text(&info.domain)),
                ("messages", info.messages.clone().into()),
                ("age_s", age(now, info.started)?.into()),
            ]));
        }
        let rss = megabytes(&memory.rss_kb)?;
        let peak = megabytes(&memory.peak_kb)?;
        let baseline = megabytes(&state.rss_start_kb)?;
        let uptime = if state.started != 0. {
            age(now, state.started)?
        } else {
            0.into()
        };
        connections.truncate(10);
        Ok(object([
            ("rss_mb", C::Float(rss)),
            ("rss_hwm_mb", C::Float(peak)),
            ("rss_start_mb", C::Float(baseline)),
            ("uptime_s", uptime.into()),
            ("total_flows", state.total_flows.clone().into()),
            (
                "active_connections",
                BigInt::from(state.connections.len()).into(),
            ),
            ("connections", C::Array(connections)),
            (
                "active_websockets",
                BigInt::from(state.websockets.len()).into(),
            ),
            ("websockets", C::Array(websockets)),
        ]))
    }
}

fn sorted_connections(state: &State) -> Vec<&Connection> {
    let mut connections: Vec<_> = state.connections.values().collect();
    connections.sort_by(|a, b| b.flows.cmp(&a.flows));
    connections
}

fn periodic(state: &State, now: f64, memory: MemorySample, writer: &Writer) -> Result<()> {
    let top = sorted_connections(state);
    let rss = megabytes(&memory.rss_kb)?;
    let rss_text = C::Float(rss).render_json(false)?;
    let mut event = event(
        "ops.memory",
        format!(
            "RSS {rss_text}MB, {} conns, {} flows",
            state.connections.len(),
            state.total_flows,
        ),
    );
    let peak = megabytes(&memory.peak_kb)?;
    let baseline = megabytes(&state.rss_start_kb)?;
    let top = top
        .into_iter()
        .take(10)
        .map(|info| {
            Ok(object([
                ("domain", text(display_domain(info.domain.as_deref()))),
                ("flows", info.flows.clone().into()),
                ("age_s", age(now, info.started)?.into()),
            ]))
        })
        .collect::<Result<Vec<_>>>()?;
    event.details = object([
        ("rss_mb", C::Float(rss)),
        ("rss_hwm_mb", C::Float(peak)),
        ("rss_start_mb", C::Float(baseline)),
        (
            "active_connections",
            BigInt::from(state.connections.len()).into(),
        ),
        (
            "active_websockets",
            BigInt::from(state.websockets.len()).into(),
        ),
        ("total_flows", state.total_flows.clone().into()),
        ("top_connections", C::Array(top)),
    ]);
    submit(writer, event)
}

fn megabytes(kb: &BigInt) -> Result<f64> {
    let C::Float(value) = C::Integer(kb.clone()).divide(&1024.into())? else {
        unreachable!("integer true division returns float");
    };
    // Same exact-binary one-decimal conversion already used by request_logger.
    Ok(if value.is_finite() {
        format!("{value:.1}").parse().expect("formatted float")
    } else {
        value
    })
}
fn age(now: f64, started: f64) -> Result<BigInt> {
    let elapsed = now - started;
    elapsed.to_bigint().ok_or_else(|| {
        Error(ErrorKind::Numeric(if elapsed.is_nan() {
            NumericError::Value
        } else {
            NumericError::Overflow
        }))
    })
}
fn display_domain(domain: Option<&str>) -> &str {
    domain
        .filter(|value| !value.is_empty())
        .unwrap_or("(unknown)")
}
fn text(value: &str) -> C {
    C::Other(Value::String(value.into()))
}
fn object<const N: usize>(fields: [(&str, C); N]) -> C {
    C::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
fn event(name: &str, summary: String) -> Event {
    let mut event = Event::new(name, Kind::Ops, Severity::Low, summary);
    event.addon = Some("memory-monitor".into());
    event
}
fn submit(writer: &Writer, event: Event) -> Result<()> {
    writer
        .emit(event)
        .map(|_| ())
        .map_err(|error| Error(ErrorKind::Audit(error.kind())))
}
