//! Shared circuit-breaker state for native HTTP and operator controls.
//!
//! All transitions share one locked state. Clock and jitter inputs are explicit;
//! the caller owns addon enable/bypass decisions, event emission and scheduling
//! snapshots on a blocking worker. Transport errors have no shipped error hook.
//! Numeric operations preserve Python scalar kinds and committed transitions on
//! failure. Typed documents preserve Python nonfinite JSON through persistence
//! and caller-owned output; the legacy serde_json views remain fallible.
//! Malformed structural cache and sequence arithmetic compatibility remain open.

use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use indexmap::IndexMap;
use num_bigint::BigInt;
use serde::Serialize;

mod config;
#[cfg(test)]
mod file_switch_tests;
mod json;
mod numeric;
pub use numeric::{CircuitValue, TemporalOperand};

type Record = IndexMap<String, CircuitValue>;
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Invalid,
    Type,
    Value,
    Overflow,
    ZeroDivision,
    Compatibility,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    events: Vec<Transition>,
}
impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    /// Transitions already emitted by the source operation before it failed.
    pub fn events(&self) -> &[Transition] {
        &self.events
    }
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        failure_kind(ErrorKind::Invalid, &error.to_string())
    }
}
fn failure_kind(kind: ErrorKind, message: &str) -> Error {
    Error {
        kind,
        message: message.into(),
        events: Vec::new(),
    }
}
fn invalid(message: &str) -> Error {
    failure_kind(ErrorKind::Invalid, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Status {
    pub state: State,
    pub failure_count: CircuitValue,
    pub success_count: CircuitValue,
    pub last_failure_time: Option<CircuitValue>,
    pub last_success_time: Option<CircuitValue>,
    pub opened_at: Option<CircuitValue>,
    pub failure_streak: CircuitValue,
    pub current_timeout: CircuitValue,
}
impl Status {
    /// A typed caller view that also preserves nonfinite status fields.
    pub fn document(&self) -> CircuitValue {
        CircuitValue::Object(
            [
                (
                    "state".into(),
                    serde_json::to_value(self.state).unwrap().into(),
                ),
                ("failure_count".into(), self.failure_count.clone()),
                ("success_count".into(), self.success_count.clone()),
                (
                    "last_failure_time".into(),
                    self.last_failure_time
                        .clone()
                        .unwrap_or_else(|| Value::Null.into()),
                ),
                (
                    "last_success_time".into(),
                    self.last_success_time
                        .clone()
                        .unwrap_or_else(|| Value::Null.into()),
                ),
                (
                    "opened_at".into(),
                    self.opened_at.clone().unwrap_or_else(|| Value::Null.into()),
                ),
                ("failure_streak".into(), self.failure_streak.clone()),
                ("current_timeout".into(), self.current_timeout.clone()),
            ]
            .into(),
        )
    }
    pub fn time_until_half_open(&self, now: f64) -> Result<Option<CircuitValue>> {
        if self.state != State::Open {
            return Ok(None);
        }
        self.opened_at
            .as_ref()
            .map(|opened| {
                CircuitValue::from(0).max_first(
                    self.current_timeout
                        .subtract(&CircuitValue::Float(now).subtract(opened)?)?,
                )
            })
            .transpose()
    }
}

/// Return transitions to the caller; do not maintain a detached audit queue.
/// Only open/reopen/close carry the observing response's request correlation in
/// Python. Status/admin-generated half_open/reset/force_open have no flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    Open,
    Reopen,
    HalfOpen,
    Close,
    Reset,
    ForceOpen,
}
impl TransitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reopen => "reopen",
            Self::HalfOpen => "half_open",
            Self::Close => "close",
            Self::Reset => "reset",
            Self::ForceOpen => "force_open",
        }
    }
    pub fn response_scoped(self) -> bool {
        matches!(self, Self::Open | Self::Reopen | Self::Close)
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Transition {
    pub event: TransitionKind,
    pub domain: String,
    #[serde(serialize_with = "serialize_details")]
    pub details: Option<IndexMap<String, CircuitValue>>,
}
impl Transition {
    /// Caller-owned event serialization, without a serde_json nonfinite boundary.
    pub fn document(&self) -> CircuitValue {
        CircuitValue::Object(
            [
                ("event".into(), json!(self.event.as_str()).into()),
                ("domain".into(), Value::String(self.domain.clone()).into()),
                (
                    "details".into(),
                    self.details
                        .as_ref()
                        .map(|values| CircuitValue::Object(values.clone()))
                        .unwrap_or_else(|| Value::Null.into()),
                ),
            ]
            .into(),
        )
    }
}
fn serialize_details<S: serde::Serializer>(
    details: &Option<IndexMap<String, CircuitValue>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let Some(details) = details else {
        return serializer.serialize_none();
    };
    let mut map = serializer.serialize_map(Some(details.len()))?;
    for (key, value) in details {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Outcome<T> {
    pub value: T,
    pub events: Vec<Transition>,
}
fn outcome<T>(value: T, events: Vec<Transition>) -> Outcome<T> {
    Outcome { value, events }
}
fn event(
    events: &mut Vec<Transition>,
    name: TransitionKind,
    domain: &str,
    details: Option<IndexMap<String, CircuitValue>>,
) {
    events.push(Transition {
        event: name,
        domain: domain.into(),
        details,
    });
}

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub failure_threshold: CircuitValue,
    pub success_threshold: CircuitValue,
    pub timeout_seconds: CircuitValue,
    pub half_open_max_requests: CircuitValue,
    pub use_exponential_backoff: bool,
    pub max_timeout_seconds: CircuitValue,
    pub backoff_multiplier: CircuitValue,
    pub jitter_factor: CircuitValue,
    pub streak_decay_seconds: CircuitValue,
    pub excluded_domains: BTreeSet<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            failure_threshold: 5.into(),
            success_threshold: 2.into(),
            timeout_seconds: 60.into(),
            half_open_max_requests: 3.into(),
            use_exponential_backoff: true,
            max_timeout_seconds: 3600.into(),
            backoff_multiplier: 2.0.into(),
            jitter_factor: 0.3.into(),
            streak_decay_seconds: 3600.into(),
            excluded_domains: ["localhost", "127.0.0.1", "_safeyolo.probe.internal"]
                .map(str::to_owned)
                .into(),
        }
    }
}
impl Settings {
    pub fn calculate_timeout(
        &self,
        streak: impl Into<CircuitValue>,
        random: &mut impl FnMut() -> f64,
    ) -> Result<CircuitValue> {
        let mut streak = streak.into();
        if !self.use_exponential_backoff || streak.equal(&0.into()) {
            return Ok(self.timeout_seconds.clone());
        }
        if self.backoff_multiplier.greater(&1.into())? {
            let ratio = self.max_timeout_seconds.divide(&self.timeout_seconds)?;
            let maximum = CircuitValue::Float(ratio.logarithm()?)
                .divide(&CircuitValue::Float(self.backoff_multiplier.logarithm()?))?;
            streak = streak.min_first(maximum.ceil()?)?;
        }
        let timeout = self
            .timeout_seconds
            .multiply(&self.backoff_multiplier.power(&streak)?)?
            .min_first(self.max_timeout_seconds.clone())?;
        let range = timeout.multiply(&self.jitter_factor)?;
        let negative_range = range.negative()?;
        let unit = random();
        if !unit.is_finite() || !(0. ..=1.).contains(&unit) {
            return Err(invalid("circuit jitter input must be from zero to one"));
        }
        // random.uniform(a,b) evaluates its arithmetic after the random draw.
        let jitter =
            negative_range.add(&range.subtract(&negative_range)?.multiply(&unit.into())?)?;
        self.timeout_seconds
            .clone()
            .max_first(timeout.add(&jitter)?)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RequestGate {
    pub enabled: bool,
    pub prior_response: bool,
    pub policy_bypassed: bool,
}
impl Default for RequestGate {
    fn default() -> Self {
        Self {
            enabled: true,
            prior_response: false,
            policy_bypassed: false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RequestDecision {
    AddonDisabled,
    PriorResponse,
    PolicyDisabled,
    ExcludedDomain,
    Allowed {
        status: Status,
    },
    Blocked {
        status: Status,
        retry_after_seconds: serde_json::Number,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDecision {
    AddonDisabled,
    PriorBlock,
    NoResponse,
    ExcludedDomain,
    SuccessRecorded,
    FailureRecorded,
    StatusNoAction,
}
#[derive(Clone, Copy, Debug)]
pub struct ResponseInput {
    pub enabled: bool,
    pub prior_block: bool,
    pub status: Option<u16>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadDisposition {
    Loaded,
    Missing,
    DiscardedUnreadable,
    DiscardedInvalidJson,
}

#[derive(Default)]
struct Counters {
    checks: BigInt,
    opens: BigInt,
    half_opens: BigInt,
    recoveries: BigInt,
}
#[derive(Default)]
struct Inner {
    settings: Settings,
    // Retain field presence and unrelated persisted metadata, matching the
    // existing {states:{domain:record},saved_at:seconds} document.
    states: IndexMap<String, Record>,
    counters: Counters,
    policy_hash: String,
}
#[derive(Clone, Default)]
pub struct CircuitBreaker {
    inner: Arc<Mutex<Inner>>,
    // Serialize explicit file operations so an older save cannot overwrite a
    // newer clone's snapshot. File replacement also holds the state lock so
    // reset/stats cannot mutate the discarded state between save and load.
    persistence: Arc<Mutex<()>>,
}
impl CircuitBreaker {
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| invalid("circuit state lock poisoned"))
    }
    pub fn settings(&self) -> Result<Settings> {
        Ok(self.lock()?.settings.clone())
    }

    /// Refresh on a changed policy hash. Assignments and exclusion additions
    /// retain source order; an error preserves earlier effects and leaves the
    /// previous hash so a later refresh retries the configuration.
    pub fn apply_sensor_config(&self, sensor: &Value) -> Result<bool> {
        config::apply_sensor_config(self, sensor)
    }
    pub fn status(
        &self,
        domain: &str,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Status>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let result = status(&mut *self.lock()?, domain, now, random, &mut events);
        completed(result, events)
    }
    pub fn admit(
        &self,
        domain: &str,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<(bool, Status)>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let result = admit(&mut *self.lock()?, domain, now, random, &mut events);
        completed(result, events)
    }
    pub fn record_failure(
        &self,
        domain: &str,
        error: Option<&str>,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Status>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let result = failure(&mut *self.lock()?, domain, error, now, random, &mut events);
        completed(result, events)
    }
    pub fn record_success(
        &self,
        domain: &str,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Status>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let result = success(&mut *self.lock()?, domain, now, random, &mut events);
        completed(result, events)
    }
    pub fn reset(&self, domain: &str) -> Result<Outcome<()>> {
        self.lock()?.states.shift_remove(domain);
        let mut events = Vec::new();
        event(&mut events, TransitionKind::Reset, domain, None);
        Ok(outcome((), events))
    }

    /// Operator JSON keys retain Python's hashability rules. Only strings can
    /// match the host keys in this state owner. The caller owns the reset audit,
    /// including the source event writer's treatment of a non-string host.
    pub fn reset_json_key(&self, domain: &Value) -> Result<()> {
        if domain.is_array() || domain.is_object() {
            return Err(failure_kind(
                ErrorKind::Type,
                "unhashable circuit reset key",
            ));
        }
        let mut inner = self.lock()?;
        if let Some(domain) = domain.as_str() {
            inner.states.shift_remove(domain);
        }
        Ok(())
    }
    pub fn force_open(&self, domain: &str, now: f64) -> Result<Outcome<()>> {
        finite_time(now)?;
        let mut inner = self.lock()?;
        let threshold = inner.settings.failure_threshold.clone();
        // Python writes the configured threshold itself, including fractional
        // values. Preserve it; count arithmetic accepts the same numeric type.
        inner.states.insert(
            domain.into(),
            [
                ("state".into(), json!("open").into()),
                ("opened_at".into(), now.into()),
                ("failure_count".into(), threshold),
                ("success_count".into(), 0.into()),
                ("failure_streak".into(), 0.into()),
                ("manual_open".into(), json!(true).into()),
            ]
            .into(),
        );
        let mut events = Vec::new();
        event(&mut events, TransitionKind::ForceOpen, domain, None);
        Ok(outcome((), events))
    }
    pub fn request(
        &self,
        domain: &str,
        gate: RequestGate,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<RequestDecision>> {
        self.request_with_config(domain, gate, now, random, None)
    }

    /// Refresh and admission share one state lock. The caller retains its
    /// current runtime read lock until this operation finishes.
    pub(crate) fn request_current(
        &self,
        policy: &crate::policy::Policy,
        domain: &str,
        gate: RequestGate,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<RequestDecision>> {
        self.request_with_config(domain, gate, now, random, Some(policy))
    }

    fn request_with_config(
        &self,
        domain: &str,
        gate: RequestGate,
        now: f64,
        random: &mut impl FnMut() -> f64,
        policy: Option<&crate::policy::Policy>,
    ) -> Result<Outcome<RequestDecision>> {
        if !gate.enabled {
            return Ok(outcome(RequestDecision::AddonDisabled, vec![]));
        }
        if gate.prior_response {
            return Ok(outcome(RequestDecision::PriorResponse, vec![]));
        }
        if gate.policy_bypassed {
            return Ok(outcome(RequestDecision::PolicyDisabled, vec![]));
        }
        finite_time(now)?;
        let mut inner = self.lock()?;
        if let Some(policy) = policy {
            config::apply(&mut inner, &policy.circuit_settings())?;
        }
        if inner.settings.excluded_domains.contains(domain) {
            return Ok(outcome(RequestDecision::ExcludedDomain, vec![]));
        }
        let mut events = Vec::new();
        let result = (|| {
            let (allowed, status) = admit(&mut inner, domain, now, random, &mut events)?;
            Ok(if allowed {
                RequestDecision::Allowed { status }
            } else {
                let remaining = status
                    .time_until_half_open(now)?
                    .filter(CircuitValue::truthy)
                    .unwrap_or_else(|| inner.settings.timeout_seconds.clone());
                RequestDecision::Blocked {
                    status,
                    retry_after_seconds: remaining
                        .truncate()?
                        .to_string()
                        .parse()
                        .expect("integer retry interval"),
                }
            })
        })();
        completed(result, events)
    }

    /// Response processing intentionally has no domain/client policy bypass
    /// parameter: the shipped response hook checks only its global enable flag.
    /// No response (including a transport error without a response) is a no-op.
    pub fn response(
        &self,
        domain: &str,
        input: ResponseInput,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<ResponseDecision>> {
        self.response_with_config(domain, input, now, random, None)
    }

    /// Source response refresh runs before a prior local block is skipped.
    pub(crate) fn response_current(
        &self,
        policy: &crate::policy::Policy,
        domain: &str,
        input: ResponseInput,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<ResponseDecision>> {
        self.response_with_config(domain, input, now, random, Some(policy))
    }

    fn response_with_config(
        &self,
        domain: &str,
        input: ResponseInput,
        now: f64,
        random: &mut impl FnMut() -> f64,
        policy: Option<&crate::policy::Policy>,
    ) -> Result<Outcome<ResponseDecision>> {
        if !input.enabled {
            return Ok(outcome(ResponseDecision::AddonDisabled, vec![]));
        }
        if policy.is_none() && input.prior_block {
            return Ok(outcome(ResponseDecision::PriorBlock, vec![]));
        }
        if policy.is_none() && input.status.is_none() {
            return Ok(outcome(ResponseDecision::NoResponse, vec![]));
        }
        let mut inner = self.lock()?;
        if let Some(policy) = policy {
            config::apply(&mut inner, &policy.circuit_settings())?;
        }
        if input.prior_block {
            return Ok(outcome(ResponseDecision::PriorBlock, vec![]));
        }
        let Some(code) = input.status else {
            return Ok(outcome(ResponseDecision::NoResponse, vec![]));
        };
        if inner.settings.excluded_domains.contains(domain) {
            return Ok(outcome(ResponseDecision::ExcludedDomain, vec![]));
        }
        let mut events = Vec::new();
        let result = (|| {
            Ok(if code >= 500 || code == 429 {
                finite_time(now)?;
                failure(
                    &mut inner,
                    domain,
                    Some(&format!("HTTP {code}")),
                    now,
                    random,
                    &mut events,
                )?;
                ResponseDecision::FailureRecorded
            } else if code < 400 {
                finite_time(now)?;
                success(&mut inner, domain, now, random, &mut events)?;
                ResponseDecision::SuccessRecorded
            } else {
                ResponseDecision::StatusNoAction
            })
        })();
        completed(result, events)
    }

    /// Admin stats can decay streaks and transition stale circuits, as Python's
    /// get_stats calls get_status for every domain in insertion order.
    pub fn stats_document(
        &self,
        enabled: bool,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<CircuitValue>> {
        finite_time(now)?;
        let mut inner = self.lock()?;
        let domains: Vec<_> = inner.states.keys().cloned().collect();
        let mut values: IndexMap<String, Record> = IndexMap::new();
        let mut events = Vec::new();
        let result = (|| {
            for domain in domains {
                let status = status(&mut inner, &domain, now, random, &mut events)?;
                let remaining = status
                    .time_until_half_open(now)?
                    .unwrap_or_else(|| Value::Null.into());
                values.insert(
                    domain,
                    [
                        (
                            "state".into(),
                            serde_json::to_value(status.state).unwrap().into(),
                        ),
                        ("failure_count".into(), status.failure_count),
                        ("failure_streak".into(), status.failure_streak),
                        ("time_until_half_open".into(), remaining),
                    ]
                    .into(),
                );
            }
            Ok(CircuitValue::Object(
                [
                    ("enabled".into(), CircuitValue::Bool(enabled)),
                    (
                        "failure_threshold".into(),
                        inner.settings.failure_threshold.clone(),
                    ),
                    (
                        "timeout_seconds".into(),
                        inner.settings.timeout_seconds.clone(),
                    ),
                    (
                        "checks_total".into(),
                        CircuitValue::Integer(inner.counters.checks.clone()),
                    ),
                    (
                        "opens_total".into(),
                        CircuitValue::Integer(inner.counters.opens.clone()),
                    ),
                    (
                        "half_opens_total".into(),
                        CircuitValue::Integer(inner.counters.half_opens.clone()),
                    ),
                    (
                        "recoveries_total".into(),
                        CircuitValue::Integer(inner.counters.recoveries.clone()),
                    ),
                    ("domains".into(), states_document(values)),
                ]
                .into(),
            ))
        })();
        completed(result, events)
    }

    /// Legacy JSON view. All source state observations complete before the
    /// conversion; callers needing NaN use stats_document and write_json.
    pub fn stats(
        &self,
        enabled: bool,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Value>> {
        let result = self.stats_document(enabled, now, random)?;
        completed(result.value.json(), result.events)
    }

    pub fn snapshot_document(&self, now: f64) -> Result<CircuitValue> {
        finite_time(now)?;
        let inner = self.lock()?;
        Ok(snapshot_inner(&inner, now))
    }

    pub fn snapshot(&self, now: f64) -> Result<Value> {
        self.snapshot_document(now)?.json()
    }
    /// Explicit synchronous persistence. Run this method on the caller's
    /// blocking worker; it neither creates timers nor starts background tasks.
    pub fn save_file(&self, path: &Path, now: f64) -> Result<()> {
        let _writer = self
            .persistence
            .lock()
            .map_err(|_| invalid("circuit persistence lock poisoned"))?;
        write_snapshot(path, &self.snapshot_document(now)?)
    }
    /// Missing/unreadable/invalid-JSON caches start empty, matching the Python
    /// loader. Valid JSON with malformed state records returns an explicit error
    /// and retains the last good state instead of crashing later on a request.
    pub fn load_file(
        &self,
        path: &Path,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<LoadDisposition>> {
        let _reader = self
            .persistence
            .lock()
            .map_err(|_| invalid("circuit persistence lock poisoned"))?;
        let (value, disposition) = read_snapshot(path);
        let events = self.restore_document(&value, now, random)?.events;
        Ok(outcome(disposition, events))
    }
    pub fn restore(
        &self,
        snapshot: &Value,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<()>> {
        self.restore_document(&CircuitValue::from_json_value(snapshot), now, random)
    }

    pub fn restore_document(
        &self,
        snapshot: &CircuitValue,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<()>> {
        let mut inner = self.lock()?;
        restore_inner(&mut inner, snapshot, now, random)
    }

    /// Select the next file atomically with resets and stats, including callers
    /// retaining an older Runtime. Reuse the existing persistence→state order.
    pub(crate) fn replace_state_file(
        &self,
        previous: Option<&Path>,
        next: Option<&Path>,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<FileChange> {
        finite_time(now)?;
        let _writer = self
            .persistence
            .lock()
            .map_err(|_| invalid("circuit persistence lock poisoned"))?;
        let mut inner = self.lock()?;
        let previous_save_failed = previous
            .is_some_and(|path| write_snapshot(path, &snapshot_inner(&inner, now)).is_err());
        // A new missing or malformed cache never inherits the old file's keys.
        // Clearing persistence selects the source's fresh empty domain state.
        inner.states.clear();
        let load_failed = next.is_some_and(|path| {
            let (snapshot, _) = read_snapshot(path);
            restore_inner(&mut inner, &snapshot, now, random).is_err()
        });
        Ok(FileChange {
            previous_save_failed,
            load_failed,
        })
    }
}

pub(crate) struct FileChange {
    pub(crate) previous_save_failed: bool,
    pub(crate) load_failed: bool,
}

fn snapshot_inner(inner: &Inner, now: f64) -> CircuitValue {
    CircuitValue::Object(
        [
            ("states".into(), states_document(inner.states.clone())),
            ("saved_at".into(), CircuitValue::Float(now)),
        ]
        .into(),
    )
}

fn write_snapshot(path: &Path, snapshot: &CircuitValue) -> Result<()> {
    let bytes = snapshot.render_json(true)?.into_bytes();
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".circuit-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let written = file.write_all(&bytes).and_then(|()| file.sync_all());
        // The source closes before rename, including after a write error.
        // A close failure takes precedence and must prevent publication.
        close_snapshot(file)?;
        written?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn read_snapshot(path: &Path) -> (CircuitValue, LoadDisposition) {
    match fs::read_to_string(path) {
        Ok(source) => match CircuitValue::parse_json(&source) {
            Ok(value) if value.as_object().is_some() => (value, LoadDisposition::Loaded),
            _ => (json!({}).into(), LoadDisposition::DiscardedInvalidJson),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (json!({}).into(), LoadDisposition::Missing)
        }
        Err(_) => (json!({}).into(), LoadDisposition::DiscardedUnreadable),
    }
}

fn restore_inner(
    inner: &mut Inner,
    snapshot: &CircuitValue,
    now: f64,
    random: &mut impl FnMut() -> f64,
) -> Result<Outcome<()>> {
    finite_time(now)?;
    let root = snapshot
        .as_object()
        .ok_or_else(|| invalid("circuit snapshot must be an object"))?;
    let states = root
        .get("states")
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| invalid("circuit states must be an object"))
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();
    let mut states: IndexMap<String, Record> = states
        .iter()
        .map(|(domain, value)| {
            let fields = value
                .as_object()
                .ok_or_else(|| invalid("circuit record must be an object"))?;
            let record = fields.clone();
            state(&record)?;
            Ok((domain.clone(), record))
        })
        .collect::<Result<_>>()?;
    let mut reconciled = BigInt::from(0);
    // Structural cache publication remains transactional; numeric fields are
    // consumed only where source reconciliation actually reads them.
    for record in states.values_mut() {
        if record.is_empty() {
            continue;
        }
        if field(record, "failure_streak").greater(&1.into())? {
            record.insert("failure_streak".into(), 1.into());
        }
        if state(record)? == State::Open {
            let timeout = inner
                .settings
                .calculate_timeout(field(record, "failure_streak"), random)?;
            if CircuitValue::Float(now)
                .subtract(&field(record, "opened_at"))?
                .at_least(&timeout)?
            {
                record.insert("state".into(), json!("half_open").into());
                record.insert("success_count".into(), 0.into());
                record.insert("half_open_requests".into(), 0.into());
                reconciled += 1;
            }
        }
    }
    inner.counters.half_opens += reconciled;
    inner.states = states;
    // Reconciliation logs informational messages but no ops events in the
    // shipped implementation; keep that distinction at the caller seam.
    Ok(outcome((), Vec::new()))
}

fn close_snapshot(file: fs::File) -> std::io::Result<()> {
    use std::os::fd::IntoRawFd;
    let descriptor = file.into_raw_fd();
    // SAFETY: File transferred its sole descriptor owner. Close exactly once;
    // never retry EINTR, because the descriptor may already have been released.
    if unsafe { libc::close(descriptor) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn state(record: &Record) -> Result<State> {
    match record
        .get("state")
        .map(|value| match value {
            CircuitValue::Other(Value::String(value)) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or(Some("closed"))
    {
        Some("closed") => Ok(State::Closed),
        Some("open") => Ok(State::Open),
        Some("half_open") => Ok(State::HalfOpen),
        _ => Err(failure_kind(
            ErrorKind::Value,
            "invalid persisted circuit state",
        )),
    }
}
fn field(record: &Record, key: &str) -> CircuitValue {
    record.get(key).cloned().unwrap_or_else(|| 0.into())
}
fn optional_time(record: &Record, key: &str) -> Option<CircuitValue> {
    record
        .get(key)
        .filter(|value| !matches!(value, CircuitValue::Other(Value::Null)))
        .cloned()
}
fn finite_time(now: f64) -> Result<()> {
    if now.is_finite() {
        Ok(())
    } else {
        Err(invalid("circuit clock must be finite"))
    }
}
fn record(inner: &Inner, domain: &str) -> Record {
    inner.states.get(domain).cloned().unwrap_or_default()
}
fn states_document(states: IndexMap<String, Record>) -> CircuitValue {
    CircuitValue::Object(
        states
            .into_iter()
            .map(|(domain, fields)| (domain, CircuitValue::Object(fields)))
            .collect(),
    )
}
fn completed<T>(result: Result<T>, events: Vec<Transition>) -> Result<Outcome<T>> {
    match result {
        Ok(value) => Ok(outcome(value, events)),
        Err(mut error) => {
            error.events = events;
            Err(error)
        }
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
fn status(
    inner: &mut Inner,
    domain: &str,
    now: f64,
    random: &mut impl FnMut() -> f64,
    events: &mut Vec<Transition>,
) -> Result<Status> {
    let mut data = record(inner, domain);
    if data.is_empty() {
        return Ok(Status {
            state: State::Closed,
            failure_count: 0.into(),
            success_count: 0.into(),
            last_failure_time: None,
            last_success_time: None,
            opened_at: None,
            failure_streak: 0.into(),
            current_timeout: inner.settings.timeout_seconds.clone(),
        });
    }
    let mut state = state(&data)?;
    let mut streak = field(&data, "failure_streak");
    let failure_time = optional_time(&data, "last_failure_time");
    if streak.greater(&0.into())?
        && let Some(time) = failure_time.as_ref().filter(|time| time.truthy())
        && CircuitValue::Float(now)
            .subtract(time)?
            .greater(&inner.settings.streak_decay_seconds)?
    {
        streak = 0.into();
        data.insert("failure_streak".into(), streak.clone());
        // Source publishes decay before later timeout arithmetic can fail.
        inner.states.insert(domain.into(), data.clone());
    }
    let timeout = inner.settings.calculate_timeout(streak.clone(), random)?;
    if state == State::Open
        && CircuitValue::Float(now)
            .subtract(&field(&data, "opened_at"))?
            .at_least(&timeout)?
    {
        state = State::HalfOpen;
        data.insert("state".into(), json!("half_open").into());
        data.insert("success_count".into(), 0.into());
        data.insert("half_open_requests".into(), 0.into());
        inner.states.insert(domain.into(), data.clone());
        inner.counters.half_opens += 1;
        event(events, TransitionKind::HalfOpen, domain, None);
    }
    Ok(Status {
        state,
        failure_count: field(&data, "failure_count"),
        success_count: field(&data, "success_count"),
        last_failure_time: failure_time,
        last_success_time: optional_time(&data, "last_success_time"),
        opened_at: optional_time(&data, "opened_at"),
        failure_streak: streak,
        current_timeout: timeout,
    })
}
fn admit(
    inner: &mut Inner,
    domain: &str,
    now: f64,
    random: &mut impl FnMut() -> f64,
    events: &mut Vec<Transition>,
) -> Result<(bool, Status)> {
    inner.counters.checks += 1;
    let status = status(inner, domain, now, random, events)?;
    let allowed = match status.state {
        State::Closed => true,
        State::Open => false,
        State::HalfOpen => {
            let mut data = record(inner, domain);
            let used = field(&data, "half_open_requests");
            if used.at_least(&inner.settings.half_open_max_requests)? {
                false
            } else {
                data.insert("half_open_requests".into(), used.add(&1.into())?);
                inner.states.insert(domain.into(), data);
                true
            }
        }
    };
    Ok((allowed, status))
}
fn failure(
    inner: &mut Inner,
    domain: &str,
    error: Option<&str>,
    now: f64,
    random: &mut impl FnMut() -> f64,
    events: &mut Vec<Transition>,
) -> Result<Status> {
    let mut data = record(inner, domain);
    let current = state(&data)?;
    let failures = field(&data, "failure_count").add(&1.into())?;
    let streak = field(&data, "failure_streak");
    data.insert("failure_count".into(), failures.clone());
    data.insert("last_failure_time".into(), now.into());
    data.insert("last_error".into(), json!(error.unwrap_or("")).into());
    match current {
        State::Closed => {
            if failures.at_least(&inner.settings.failure_threshold)? {
                data.insert("state".into(), json!("open").into());
                data.insert("opened_at".into(), now.into());
                data.insert("success_count".into(), 0.into());
                inner.counters.opens += 1;
                event(
                    events,
                    TransitionKind::Open,
                    domain,
                    Some(
                        [
                            ("failure_count".into(), failures),
                            ("error".into(), json!(error).into()),
                        ]
                        .into(),
                    ),
                );
            } else {
                data.insert("state".into(), json!("closed").into());
            }
        }
        State::HalfOpen => {
            let streak = streak.add(&1.into())?;
            data.insert("state".into(), json!("open").into());
            data.insert("opened_at".into(), now.into());
            data.insert("failure_streak".into(), streak.clone());
            data.insert("success_count".into(), 0.into());
            inner.counters.opens += 1;
            event(
                events,
                TransitionKind::Reopen,
                domain,
                Some(
                    [
                        ("streak".into(), streak),
                        ("error".into(), json!(error).into()),
                    ]
                    .into(),
                ),
            );
        }
        State::Open => {}
    }
    inner.states.insert(domain.into(), data);
    status(inner, domain, now, random, events)
}
fn success(
    inner: &mut Inner,
    domain: &str,
    now: f64,
    random: &mut impl FnMut() -> f64,
    events: &mut Vec<Transition>,
) -> Result<Status> {
    let current = status(inner, domain, now, random, events)?;
    let mut data = record(inner, domain);
    if data.is_empty() {
        return Ok(current);
    }
    let successes = field(&data, "success_count").add(&1.into())?;
    data.insert("success_count".into(), successes.clone());
    data.insert("last_success_time".into(), now.into());
    match current.state {
        State::HalfOpen => {
            if successes.at_least(&inner.settings.success_threshold)? {
                data.insert("state".into(), json!("closed").into());
                data.insert("failure_count".into(), 0.into());
                data.insert("failure_streak".into(), 0.into());
                inner.counters.recoveries += 1;
                event(
                    events,
                    TransitionKind::Close,
                    domain,
                    Some([("success_count".into(), successes)].into()),
                );
            } else {
                data.insert("state".into(), json!("half_open").into());
            }
        }
        State::Closed => {
            let failures = field(&data, "failure_count");
            if failures.greater(&0.into())? {
                data.insert("failure_count".into(), failures.subtract(&1.into())?);
            }
        }
        State::Open => {}
    }
    inner.states.insert(domain.into(), data);
    status(inner, domain, now, random, events)
}

#[cfg(test)]
mod numeric_state_tests {
    use super::*;

    #[test]
    fn nonfinite_state_and_transition_survive_until_json_conversion() {
        let cb = CircuitBreaker::new();
        let mut record: Record = [
            ("state".into(), json!("half_open").into()),
            ("failure_count".into(), CircuitValue::Float(f64::NAN)),
            ("failure_streak".into(), CircuitValue::Float(f64::NAN)),
        ]
        .into();
        record.insert("success_count".into(), CircuitValue::Float(f64::INFINITY));
        cb.lock().unwrap().states.insert("api".into(), record);
        let result = cb.record_failure("api", None, 100., &mut || 0.5).unwrap();
        assert_eq!(result.value.state, State::Open);
        assert!(matches!(result.value.failure_count, CircuitValue::Float(value) if value.is_nan()));
        assert!(
            matches!(result.value.failure_streak, CircuitValue::Float(value) if value.is_nan())
        );
        assert!(
            matches!(result.events[0].details.as_ref().unwrap()["streak"], CircuitValue::Float(value) if value.is_nan())
        );
        assert_eq!(
            cb.snapshot(100.).unwrap_err().kind(),
            ErrorKind::Compatibility
        );
        assert_eq!(cb.lock().unwrap().counters.opens, BigInt::from(1));
        assert!(
            matches!(cb.lock().unwrap().states["api"]["failure_count"], CircuitValue::Float(value) if value.is_nan())
        );
    }

    #[test]
    fn json_view_failure_follows_all_source_status_observations() {
        let source: Value =
            serde_json::from_str(include_str!("../tests/circuit_nonfinite_source.json")).unwrap();
        assert_eq!(source["stats_visits_later_domain"], true);
        let cb = CircuitBreaker::new();
        cb.lock().unwrap().states.insert(
            "nan".into(),
            [
                ("state".into(), json!("closed").into()),
                ("failure_count".into(), CircuitValue::Float(f64::NAN)),
            ]
            .into(),
        );
        cb.force_open("later", 0.).unwrap();
        let error = cb.stats(true, 100., &mut || 0.5).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Compatibility);
        assert_eq!(error.events()[0].event, TransitionKind::HalfOpen);
        assert_eq!(
            state(&cb.lock().unwrap().states["later"]).unwrap(),
            State::HalfOpen
        );
        assert_eq!(cb.lock().unwrap().counters.half_opens, BigInt::from(1));
    }

    #[test]
    fn lifetime_count_has_no_machine_integer_ceiling() {
        let cb = CircuitBreaker::new();
        cb.lock().unwrap().counters.checks = BigInt::from(u64::MAX);
        cb.admit("api", 100., &mut || 0.5).unwrap();
        assert_eq!(
            cb.stats(true, 100., &mut || 0.5).unwrap().value["checks_total"].to_string(),
            "18446744073709551616"
        );
    }
}
