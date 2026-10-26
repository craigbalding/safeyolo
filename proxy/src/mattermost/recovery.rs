//! Mattermost failure categories and the foreground retry/health state.
use super::state::now;
use crate::{Error, agent_api::coord::OperatorCoordError, native_client::RestStatusError};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Transient,
    Permanent,
    Reconcile,
}

#[derive(Clone, Debug)]
pub(super) struct Failure {
    pub kind: Kind,
    pub category: &'static str,
    pub retry_after: Option<Duration>,
    detail: &'static str,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.category)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    pub fn new(kind: Kind, category: &'static str, detail: &'static str) -> Self {
        Self {
            kind,
            category,
            detail,
            retry_after: None,
        }
    }
    pub fn classify(error: &Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return failure.clone();
        }
        if let Some(coord) = error.downcast_ref::<OperatorCoordError>() {
            return Self::new(
                if coord.unknown {
                    Kind::Reconcile
                } else if coord.unavailable {
                    Kind::Transient
                } else {
                    Kind::Permanent
                },
                if coord.unknown {
                    "coord_append_unknown"
                } else if coord.unavailable {
                    "coord_unavailable"
                } else {
                    "coord_authorization_or_protocol"
                },
                "Coord operation failed; pending appends require reconciliation",
            );
        }
        Self::new(
            Kind::Permanent,
            "configuration_or_protocol",
            "Mattermost configuration, state or protocol is invalid",
        )
    }
    pub fn http(error: &Error, write: bool) -> Self {
        let mut failure = if let Some(status) = error.downcast_ref::<RestStatusError>() {
            let transient = matches!(status.status, 408 | 429 | 500..=599);
            let mut result = Self::new(
                if transient {
                    Kind::Transient
                } else {
                    Kind::Permanent
                },
                match status.status {
                    408 => "http_408",
                    429 => "http_429",
                    500..=599 => "http_5xx",
                    401 | 403 | 407 => "http_authorization",
                    _ => "http_configuration",
                },
                "Mattermost HTTP request failed",
            );
            result.retry_after = status.retry_after;
            result
        } else if error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
        {
            Self::new(Kind::Transient, "timeout", "Mattermost request timed out")
        } else if error.downcast_ref::<hyper::Error>().is_some() {
            Self::new(
                Kind::Transient,
                "disconnect",
                "Mattermost connection failed",
            )
        } else if let Some(io) = error.downcast_ref::<std::io::Error>() {
            // Certificate and TLS protocol failures require configuration repair.
            let tls = io.get_ref().is_some_and(|e| e.is::<rustls::Error>());
            Self::new(
                if tls {
                    Kind::Permanent
                } else {
                    Kind::Transient
                },
                if tls { "tls" } else { "connection" },
                "Mattermost connection failed",
            )
        } else {
            Self::new(
                Kind::Permanent,
                "configuration_or_protocol",
                "Mattermost transport configuration or response is invalid",
            )
        };
        // Even an HTTP error may follow an accepted POST. Only correlation
        // reconciliation may resolve it; retrying the write is never safe.
        if write {
            failure.kind = Kind::Reconcile;
            failure.detail = "Mattermost write outcome is unknown; reconcile before another write";
        }
        failure
    }
}

pub(super) fn blocked(category: &'static str, detail: &'static str) -> Error {
    Failure::new(Kind::Reconcile, category, detail).into()
}

pub(super) fn retry_delay(failures: u32, retry_after: Option<Duration>, unit: f64) -> Duration {
    // Same capped exponential pattern as Coord watch, with bounded jitter.
    // Circuit Settings carries policy numeric semantics that this adapter does not need.
    let base = (1u64 << failures.saturating_sub(1).min(5)).min(30) as f64;
    let delay = Duration::from_secs_f64((base * (0.8 + 0.4 * unit)).clamp(0.8, 30.0));
    delay.max(retry_after.unwrap_or_default())
}

pub(super) struct SyncStatus {
    pub status: &'static str,
    pub last_success: Option<i64>,
    pub last_error: Option<&'static str>,
    since: i64,
    failures: u32,
    pub next_attempt: Option<Instant>,
}
impl SyncStatus {
    pub fn new() -> Self {
        Self {
            status: "retrying",
            last_success: None,
            last_error: None,
            since: now(),
            failures: 0,
            next_attempt: Some(Instant::now()),
        }
    }
    pub fn due(&self) -> bool {
        self.next_attempt.is_some_and(|at| at <= Instant::now())
    }
    pub fn update(&mut self, scope: &str, result: &Result<(), Error>, interval: Duration) {
        let previous = (self.status, self.last_error);
        match result {
            Ok(()) => {
                self.status = "connected";
                self.last_success = Some(now());
                self.since = now();
                self.failures = 0;
                self.next_attempt = Some(Instant::now() + interval);
            }
            Err(error) => {
                let failure = Failure::classify(error);
                self.last_error = Some(failure.category);
                self.status = if failure.kind == Kind::Transient {
                    "retrying"
                } else {
                    "blocked"
                };
                self.failures = self.failures.saturating_add(1);
                self.next_attempt = if failure.kind == Kind::Permanent {
                    None
                } else {
                    let delay = retry_delay(self.failures, failure.retry_after, rand::random());
                    Instant::now().checked_add(delay)
                };
            }
        }
        if previous != (self.status, self.last_error) {
            eprintln!(
                "Mattermost sync scope={scope} status={} category={}",
                self.status,
                self.last_error.unwrap_or("none")
            );
        }
    }
    pub fn json(&self) -> Value {
        let retry_in = (self.status != "connected")
            .then(|| {
                self.next_attempt.map(|at| {
                    at.saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(i64::MAX as u128) as i64
                })
            })
            .flatten();
        json!({"status":self.status,"last_success_at":self.last_success,"last_error_category":self.last_error,
            "retry_in_ms":retry_in,"retry_at":retry_in.map(|ms|now().saturating_add(ms)),
            "backlog_age_seconds":if self.status=="connected"{0}else{now().saturating_sub(self.since)/1000}})
    }
}
