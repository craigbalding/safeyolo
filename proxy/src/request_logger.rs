//! Concrete source request/response logger. The caller invokes only reached
//! hooks, supplies trusted attribution and source-parsed pretty URL fields,
//! and owns body decoding and HTTP completion. There is no error hook.

mod quiet;
#[cfg(test)]
mod tests;

use std::{fmt, sync::Mutex};

use indexmap::IndexMap;
use num_bigint::BigInt;
use serde_json::Value;
use zeroize::Zeroize;

use crate::{
    audit::{Attribution, Event, Kind, Severity, Writer},
    circuits::CircuitValue as C,
    network_guard::sanitize,
    policy::Policy,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    Type,
    Value,
    Attribute,
    Decode,
    Audit,
    Poisoned,
    Compatibility,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Error(pub(crate) ErrorKind);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request logger hook failed")
    }
}
impl std::error::Error for Error {}

/// Counters belong to the reached hooks, not successful decoding or disk writes.
#[derive(Clone, Default)]
pub(crate) struct Stats {
    pub(crate) requests_total: BigInt,
    pub(crate) requests_quieted: BigInt,
    pub(crate) responses_total: BigInt,
    pub(crate) blocks_total: BigInt,
}
impl Stats {
    pub(crate) fn document(&self) -> C {
        object([
            ("requests_total", self.requests_total.clone().into()),
            ("requests_quieted", self.requests_quieted.clone().into()),
            ("responses_total", self.responses_total.clone().into()),
            ("blocks_total", self.blocks_total.clone().into()),
        ])
    }
}
#[derive(Default)]
struct State {
    stats: Stats,
    hash: String,
    quiet: quiet::Quiet,
}
#[derive(Default)]
pub(crate) struct RequestLogger {
    state: Mutex<State>,
}

/// Stable per-exchange trust snapshot, never constructed from request headers.
/// Ingress may create it before the request hook for an early response.
pub(crate) struct Exchange {
    attribution: Attribution,
    agent: Option<String>,
    quieted: bool,
}
impl Exchange {
    pub(crate) fn new(attribution: Attribution, agent: Option<String>) -> Self {
        Self {
            attribution,
            agent,
            quieted: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn quieted(&self) -> bool {
        self.quieted
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        self.agent.zeroize();
    }
}

/// Fresh facts from the current request object. `path` is urlparse(...).path,
/// excluding query, fragment and the final segment's semicolon parameters.
/// `host` is the pretty URL hostname, not necessarily the dial destination.
#[derive(Clone, Copy)]
pub(crate) struct PrettyUrl<'a> {
    pub(crate) host: &'a str,
    pub(crate) path: &'a str,
}
pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    pub(crate) parsed: Result<PrettyUrl<'a>, Error>,
    pub(crate) request_id: Option<&'a str>,
    pub(crate) client: Option<&'a str>,
}
pub(crate) struct Response<'a> {
    pub(crate) status: Option<u16>,
    pub(crate) start_time: Option<f64>,
    pub(crate) now: f64,
    /// Trusted addon metadata; an upstream X-Blocked-By header is not authority.
    pub(crate) blocked_by: Option<&'a C>,
    pub(crate) block_reason: Option<&'a C>,
    pub(crate) credential_fingerprint: Option<&'a C>,
    /// The existing trusted identity owner has detected a late change. This
    /// logger retains its original snapshot; it does not implement IP-map lookup.
    pub(crate) attribution_quarantined: bool,
}

impl RequestLogger {
    pub(crate) fn stats(&self) -> Result<Stats, Error> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?
            .stats
            .clone())
    }
    fn refresh(&self, policy: Option<&Policy>, writer: &Writer) -> Result<(), Error> {
        let Some(policy) = policy else {
            return Ok(());
        };
        let view = policy.request_logger_settings();
        {
            let mut state = self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
            if state.hash == view.hash() {
                return Ok(());
            }
            state.hash = view.hash().to_owned();
        }
        // Source latches the hash before validation, builds outside the lock,
        // and commits only complete good rules. A failed hash is not retried.
        match quiet::Quiet::load(policy) {
            Ok(quiet) => {
                self.state
                    .lock()
                    .map_err(|_| Error(ErrorKind::Poisoned))?
                    .quiet = quiet
            }
            Err(quiet::LoadError::Reached(error)) => return Err(error),
            Err(quiet::LoadError::Malformed(message)) => {
                let mut event = Event::new(
                    "ops.config_error",
                    Kind::Ops,
                    Severity::Medium,
                    "request-logger quiet_hosts config malformed",
                );
                event.addon = Some("request-logger".into());
                event.details = object([("error", text(&sanitize(&message)))]);
                emit(writer, event)?;
            }
        }
        Ok(())
    }
    pub(crate) fn request(
        &self,
        policy: Option<&Policy>,
        exchange: &mut Exchange,
        request: &Request<'_>,
        decoded_size: impl FnOnce() -> Result<u64, Error>,
        writer: &Writer,
    ) -> Result<(), Error> {
        self.state
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?
            .stats
            .requests_total += 1;
        self.refresh(policy, writer)?;
        let parsed = request.parsed?;
        {
            let mut state = self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
            if state.quiet.matches(parsed.host, parsed.path)? {
                state.stats.requests_quieted += 1;
                exchange.quieted = true;
                return Ok(());
            }
        }
        let size = decoded_size()?;
        let mut event = event(
            exchange,
            request,
            parsed,
            "traffic.request",
            Kind::Traffic,
            Severity::Low,
            format!(
                "{} {}{}",
                request.method,
                sanitize(parsed.host),
                sanitize(parsed.path)
            ),
        );
        event.details = object([
            ("method", text(request.method)),
            ("path", text(parsed.path)),
            ("size", size.into()),
            ("client", request.client.map_or(C::Other(Value::Null), text)),
        ]);
        emit(writer, event)
    }
    pub(crate) fn response(
        &self,
        exchange: &Exchange,
        request: &Request<'_>,
        response: &Response<'_>,
        decoded_size: impl FnOnce() -> Result<u64, Error>,
        writer: &Writer,
    ) -> Result<(), Error> {
        let blocked = response.blocked_by.filter(|value| value.truthy());
        if exchange.quieted && blocked.is_none() {
            return Ok(());
        }
        let Some(status) = response.status else {
            let parsed = request.parsed?;
            let mut event = event(
                exchange,
                request,
                parsed,
                "ops.response_missing",
                Kind::Ops,
                Severity::Medium,
                format!(
                    "no response for {} {}{}",
                    request.method,
                    sanitize(parsed.host),
                    sanitize(parsed.path)
                ),
            );
            event.details = object([
                ("method", text(request.method)),
                ("path", text(parsed.path)),
            ]);
            quarantine(&mut event.details, response.attribution_quarantined);
            return emit(writer, event);
        };
        {
            let mut state = self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
            if blocked.is_some() {
                state.stats.blocks_total += 1;
            } else {
                state.stats.responses_total += 1;
            }
        }
        let duration = duration(response.start_time, response.now);
        let parsed = request.parsed?;
        let size = decoded_size()?;
        let mut details = object([
            ("path", text(parsed.path)),
            ("status", u64::from(status).into()),
            ("size", size.into()),
            ("ms", duration.map_or(C::Other(Value::Null), C::Float)),
        ]);
        quarantine(&mut details, response.attribution_quarantined);
        let suffix = if let Some(blocked) = blocked {
            let C::Object(fields) = &mut details else {
                unreachable!()
            };
            fields.insert("blocked_by".into(), blocked.clone());
            for (name, value) in [
                ("block_reason", response.block_reason),
                ("credential_fingerprint", response.credential_fingerprint),
            ] {
                if let Some(value) = value.filter(|value| value.truthy()) {
                    fields.insert(name.into(), value.clone());
                }
            }
            format!(
                " [blocked by {}]",
                crate::circuit_runtime::count_text(blocked)
                    .map_err(|_| Error(ErrorKind::Compatibility))?
            )
        } else {
            String::new()
        };
        let mut event = event(
            exchange,
            request,
            parsed,
            "traffic.response",
            Kind::Traffic,
            if blocked.is_some() {
                Severity::High
            } else {
                Severity::Low
            },
            format!(
                "{status} {}{}{suffix}",
                sanitize(parsed.host),
                sanitize(parsed.path)
            ),
        );
        event.details = details;
        emit(writer, event)
    }
}
fn emit(writer: &Writer, event: Event) -> Result<(), Error> {
    writer
        .emit(event)
        .map(|_| ())
        .map_err(|_| Error(ErrorKind::Audit))
}
fn event(
    exchange: &Exchange,
    request: &Request<'_>,
    parsed: PrettyUrl<'_>,
    name: &str,
    kind: Kind,
    severity: Severity,
    summary: String,
) -> Event {
    let mut event = Event::new(name, kind, severity, summary);
    event.request_id = request.request_id.map(str::to_owned);
    event.agent = exchange.agent.clone();
    event.addon = Some("request-logger".into());
    event.host = Some(parsed.host.to_owned());
    event.attribution = Some(exchange.attribution.clone());
    event
}
fn text(value: &str) -> C {
    C::Other(Value::String(value.to_owned()))
}
fn object<const N: usize>(fields: [(&str, C); N]) -> C {
    C::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect::<IndexMap<_, _>>(),
    )
}
fn quarantine(details: &mut C, quarantined: bool) {
    if quarantined {
        let C::Object(fields) = details else {
            unreachable!()
        };
        fields.insert("attribution_quarantined".into(), C::Bool(true));
    }
}
fn duration(start: Option<f64>, now: f64) -> Option<f64> {
    let start = start.filter(|value| *value != 0.)?;
    let ms = (now - start) * 1000.;
    // Python round(x, 1) rounds the exact binary float to one decimal place,
    // with ties to even. Multiplying by ten first would introduce a second
    // binary rounding. Decimal formatting preserves signed zero and uses the
    // existing standard-library correctly rounded conversion.
    Some(if ms.is_finite() {
        format!("{ms:.1}").parse().expect("formatted float")
    } else {
        ms
    })
}
