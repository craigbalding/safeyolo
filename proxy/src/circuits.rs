//! Native circuit-breaker state, pending runtime integration.
//!
//! All transitions share one locked state. Clock and jitter inputs are explicit;
//! the caller owns addon enable/bypass decisions, event emission and scheduling
//! snapshots on a blocking worker. Transport errors have no shipped error hook.

use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use serde::Serialize;
use serde_json::{Map, Value, json};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}
fn invalid(message: &str) -> Error {
    Error(message.into())
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
    pub failure_count: f64,
    pub success_count: i64,
    pub last_failure_time: Option<f64>,
    pub last_success_time: Option<f64>,
    pub opened_at: Option<f64>,
    pub failure_streak: i64,
    pub current_timeout: f64,
}
impl Status {
    pub fn time_until_half_open(&self, now: f64) -> Option<f64> {
        (self.state == State::Open)
            .then_some(self.opened_at)
            .flatten()
            .map(|opened| (self.current_timeout - (now - opened)).max(0.))
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
    pub details: Value,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Outcome<T> {
    pub value: T,
    pub events: Vec<Transition>,
}
fn outcome<T>(value: T, events: Vec<Transition>) -> Outcome<T> {
    Outcome { value, events }
}
fn event(events: &mut Vec<Transition>, name: TransitionKind, domain: &str, details: Value) {
    events.push(Transition {
        event: name,
        domain: domain.into(),
        details,
    });
}

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub failure_threshold: f64,
    // force_open persists the configured value itself, including integer vs
    // float spelling; retain that provenance when using the numeric API.
    failure_threshold_source: Value,
    pub success_threshold: f64,
    pub timeout_seconds: f64,
    pub half_open_max_requests: f64,
    pub use_exponential_backoff: bool,
    pub max_timeout_seconds: f64,
    pub backoff_multiplier: f64,
    pub jitter_factor: f64,
    pub streak_decay_seconds: f64,
    pub excluded_domains: BTreeSet<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            failure_threshold: 5.,
            failure_threshold_source: json!(5),
            success_threshold: 2.,
            timeout_seconds: 60.,
            half_open_max_requests: 3.,
            use_exponential_backoff: true,
            max_timeout_seconds: 3600.,
            backoff_multiplier: 2.,
            jitter_factor: 0.3,
            streak_decay_seconds: 3600.,
            excluded_domains: ["localhost", "127.0.0.1", "_safeyolo.probe.internal"]
                .map(str::to_owned)
                .into(),
        }
    }
}
impl Settings {
    fn apply(&mut self, values: &Map<String, Value>) -> Result<()> {
        for (name, field) in [
            ("failure_threshold", &mut self.failure_threshold),
            ("success_threshold", &mut self.success_threshold),
            ("timeout_seconds", &mut self.timeout_seconds),
            ("half_open_max_requests", &mut self.half_open_max_requests),
            ("max_timeout_seconds", &mut self.max_timeout_seconds),
            ("backoff_multiplier", &mut self.backoff_multiplier),
            ("jitter_factor", &mut self.jitter_factor),
            ("streak_decay_seconds", &mut self.streak_decay_seconds),
        ] {
            if let Some(value) = values.get(name) {
                *field = finite_number(value)?;
            }
        }
        if let Some(value) = values.get("failure_threshold") {
            self.failure_threshold_source = value.clone();
        }
        if let Some(value) = values.get("use_exponential_backoff") {
            self.use_exponential_backoff = truthy(value);
        }
        if let Some(value) = values.get("excluded_domains").filter(|value| truthy(value)) {
            match value {
                Value::String(value) => self
                    .excluded_domains
                    .extend(value.chars().map(|character| character.to_string())),
                Value::Object(value) => self.excluded_domains.extend(value.keys().cloned()),
                Value::Array(values) => {
                    for value in values {
                        match value {
                            Value::String(value) => {
                                self.excluded_domains.insert(value.clone());
                            }
                            Value::Array(_) | Value::Object(_) => {
                                return Err(invalid("excluded domain entries must be hashable"));
                            }
                            // Hashable non-strings can enter the Python set but can
                            // never match the string domain supplied by HTTP.
                            _ => {}
                        }
                    }
                }
                _ => return Err(invalid("excluded domains must be iterable")),
            }
        }
        Ok(())
    }
    pub fn calculate_timeout(
        &self,
        mut streak: i64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<f64> {
        if !self.use_exponential_backoff || streak == 0 {
            return Ok(self.timeout_seconds);
        }
        if self.backoff_multiplier > 1. {
            let ratio = self.max_timeout_seconds / self.timeout_seconds;
            if self.timeout_seconds == 0. || ratio <= 0. || !ratio.is_finite() {
                return Err(invalid("invalid circuit backoff logarithm"));
            }
            let maximum = ratio.log(self.backoff_multiplier).ceil();
            if !maximum.is_finite() || maximum < i64::MIN as f64 || maximum >= i64::MAX as f64 {
                return Err(invalid("circuit backoff exponent is out of range"));
            }
            streak = streak.min(maximum as i64);
        }
        let base = self.timeout_seconds * self.backoff_multiplier.powf(streak as f64);
        if !base.is_finite() {
            return Err(invalid("circuit backoff overflow"));
        }
        let timeout = base.min(self.max_timeout_seconds);
        let range = timeout * self.jitter_factor;
        let unit = random();
        if !unit.is_finite() || !(0. ..=1.).contains(&unit) {
            return Err(invalid("circuit jitter input must be from zero to one"));
        }
        // random.uniform(a,b) uses a + (b-a)*random(), including rounding order.
        let jittered = timeout + (-range + (range - -range) * unit);
        if !jittered.is_finite() {
            return Err(invalid("circuit jitter overflow"));
        }
        Ok(jittered.max(self.timeout_seconds))
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
    checks: u64,
    opens: u64,
    half_opens: u64,
    recoveries: u64,
}
#[derive(Default)]
struct Inner {
    settings: Settings,
    // Retain field presence and unrelated persisted metadata, matching the
    // existing {states:{domain:record},saved_at:seconds} document.
    states: Map<String, Value>,
    counters: Counters,
    policy_hash: String,
}
#[derive(Clone, Default)]
pub struct CircuitBreaker {
    inner: Arc<Mutex<Inner>>,
    // Serialize explicit file operations so an older save cannot overwrite a
    // newer clone's snapshot. Filesystem I/O never holds the request-state lock.
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

    /// Apply the already resolved sensor config only when its policy hash
    /// changes. Omitted fields retain their last values; exclusions accumulate.
    /// Malformed candidates return an error and preserve the previous settings.
    pub fn apply_sensor_config(&self, sensor: &Value) -> Result<bool> {
        let sensor = sensor
            .as_object()
            .ok_or_else(|| invalid("sensor config must be an object"))?;
        let hash = sensor
            .get("policy_hash")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| invalid("policy hash must be a string"))
            })
            .transpose()?
            .unwrap_or("");
        let mut inner = self.lock()?;
        if hash == inner.policy_hash {
            return Ok(false);
        }
        let empty = Map::new();
        let addons = sensor
            .get("addons")
            .map(|value| {
                value
                    .as_object()
                    .ok_or_else(|| invalid("addons must be an object"))
            })
            .transpose()?
            .unwrap_or(&empty);
        let values = addons
            .get("circuit_breaker")
            .map(|value| {
                value
                    .as_object()
                    .ok_or_else(|| invalid("circuit settings must be an object"))
            })
            .transpose()?
            .unwrap_or(&empty);
        let mut settings = inner.settings.clone();
        settings.apply(values)?;
        inner.settings = settings;
        inner.policy_hash = hash.into();
        Ok(true)
    }
    pub fn status(
        &self,
        domain: &str,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Status>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let status = status(&mut *self.lock()?, domain, now, random, &mut events)?;
        Ok(outcome(status, events))
    }
    pub fn admit(
        &self,
        domain: &str,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<(bool, Status)>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let value = admit(&mut *self.lock()?, domain, now, random, &mut events)?;
        Ok(outcome(value, events))
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
        let value = failure(&mut *self.lock()?, domain, error, now, random, &mut events)?;
        Ok(outcome(value, events))
    }
    pub fn record_success(
        &self,
        domain: &str,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Status>> {
        finite_time(now)?;
        let mut events = Vec::new();
        let value = success(&mut *self.lock()?, domain, now, random, &mut events)?;
        Ok(outcome(value, events))
    }
    pub fn reset(&self, domain: &str) -> Result<Outcome<()>> {
        self.lock()?.states.shift_remove(domain);
        let mut events = Vec::new();
        event(&mut events, TransitionKind::Reset, domain, Value::Null);
        Ok(outcome((), events))
    }
    pub fn force_open(&self, domain: &str, now: f64) -> Result<Outcome<()>> {
        finite_time(now)?;
        let mut inner = self.lock()?;
        let threshold = inner.settings.failure_threshold_source.clone();
        // Python writes the configured threshold itself, including fractional
        // values. Preserve it; count arithmetic accepts the same numeric type.
        inner.states.insert(domain.into(), json!({"state":"open", "opened_at":now, "failure_count":threshold, "success_count":0, "failure_streak":0, "manual_open":true}));
        let mut events = Vec::new();
        event(&mut events, TransitionKind::ForceOpen, domain, Value::Null);
        Ok(outcome((), events))
    }
    pub fn request(
        &self,
        domain: &str,
        gate: RequestGate,
        now: f64,
        random: &mut impl FnMut() -> f64,
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
        if inner.settings.excluded_domains.contains(domain) {
            return Ok(outcome(RequestDecision::ExcludedDomain, vec![]));
        }
        let mut events = Vec::new();
        let (allowed, status) = admit(&mut inner, domain, now, random, &mut events)?;
        let decision = if allowed {
            RequestDecision::Allowed { status }
        } else {
            let remaining = status
                .time_until_half_open(now)
                .filter(|value| *value != 0.)
                .unwrap_or(inner.settings.timeout_seconds);
            RequestDecision::Blocked {
                status,
                retry_after_seconds: if remaining == 0. {
                    0.into()
                } else {
                    format!("{:.0}", remaining.trunc())
                        .parse()
                        .map_err(|_| invalid("invalid circuit retry interval"))?
                },
            }
        };
        Ok(outcome(decision, events))
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
        if !input.enabled {
            return Ok(outcome(ResponseDecision::AddonDisabled, vec![]));
        }
        if input.prior_block {
            return Ok(outcome(ResponseDecision::PriorBlock, vec![]));
        }
        let Some(code) = input.status else {
            return Ok(outcome(ResponseDecision::NoResponse, vec![]));
        };
        let mut inner = self.lock()?;
        if inner.settings.excluded_domains.contains(domain) {
            return Ok(outcome(ResponseDecision::ExcludedDomain, vec![]));
        }
        let mut events = Vec::new();
        let value = if code >= 500 || code == 429 {
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
        };
        Ok(outcome(value, events))
    }
    /// Admin stats can decay streaks and transition stale circuits, as Python's
    /// get_stats calls get_status for every domain in insertion order.
    pub fn stats(
        &self,
        enabled: bool,
        now: f64,
        random: &mut impl FnMut() -> f64,
    ) -> Result<Outcome<Value>> {
        finite_time(now)?;
        let mut inner = self.lock()?;
        let domains: Vec<_> = inner.states.keys().cloned().collect();
        let mut values = Map::new();
        let mut events = Vec::new();
        for domain in domains {
            let status = status(&mut inner, &domain, now, random, &mut events)?;
            values.insert(domain, json!({"state":status.state,"failure_count":status.failure_count,"failure_streak":status.failure_streak,"time_until_half_open":status.time_until_half_open(now)}));
        }
        Ok(outcome(
            json!({"enabled":enabled,"failure_threshold":inner.settings.failure_threshold_source,"timeout_seconds":inner.settings.timeout_seconds,"checks_total":inner.counters.checks,"opens_total":inner.counters.opens,"half_opens_total":inner.counters.half_opens,"recoveries_total":inner.counters.recoveries,"domains":values}),
            events,
        ))
    }
    pub fn snapshot(&self, now: f64) -> Result<Value> {
        finite_time(now)?;
        Ok(json!({"states":self.lock()?.states.clone(),"saved_at":now}))
    }
    /// Explicit synchronous persistence. Run this method on the caller's
    /// blocking worker; it neither creates timers nor starts background tasks.
    pub fn save_file(&self, path: &Path, now: f64) -> Result<()> {
        let _writer = self
            .persistence
            .lock()
            .map_err(|_| invalid("circuit persistence lock poisoned"))?;
        let bytes = serde_json::to_vec_pretty(&self.snapshot(now)?)
            .map_err(|_| invalid("cannot serialize circuit state"))?;
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
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
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
        let (value, disposition) = match fs::read_to_string(path) {
            Ok(source) => match crate::policy::parse_json(&source, false) {
                Ok(value) if value.is_object() => (value, LoadDisposition::Loaded),
                _ => (json!({}), LoadDisposition::DiscardedInvalidJson),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (json!({}), LoadDisposition::Missing)
            }
            Err(_) => (json!({}), LoadDisposition::DiscardedUnreadable),
        };
        let events = self.restore(&value, now, random)?.events;
        Ok(outcome(disposition, events))
    }
    pub fn restore(
        &self,
        snapshot: &Value,
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
        for value in states.values() {
            validate_record(value)?;
        }
        let mut inner = self.lock()?;
        let mut reconciled = 0;
        let mut states = states;
        // Reconciliation does not call get_status: it caps streaks first and
        // does not decay them from last_failure_time until a later status query.
        for value in states.values_mut() {
            let record = value.as_object_mut().expect("validated record");
            if record.is_empty() {
                continue;
            }
            let streak = count(record, "failure_streak")?;
            if streak > 1 {
                record.insert("failure_streak".into(), json!(1));
            }
            if state(record)? == State::Open {
                let timeout = inner
                    .settings
                    .calculate_timeout(count(record, "failure_streak")?, random)?;
                let opened = number_or(record, "opened_at", 0.)?;
                if now - opened >= timeout {
                    record.insert("state".into(), json!("half_open"));
                    record.insert("success_count".into(), json!(0));
                    record.insert("half_open_requests".into(), json!(0));
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
}

fn state(record: &Map<String, Value>) -> Result<State> {
    match record
        .get("state")
        .map(Value::as_str)
        .unwrap_or(Some("closed"))
    {
        Some("closed") => Ok(State::Closed),
        Some("open") => Ok(State::Open),
        Some("half_open") => Ok(State::HalfOpen),
        _ => Err(invalid("invalid persisted circuit state")),
    }
}
fn count(record: &Map<String, Value>, key: &str) -> Result<i64> {
    match record.get(key) {
        None => Ok(0),
        Some(Value::Bool(value)) => Ok(i64::from(*value)),
        Some(value) => value
            .as_i64()
            .or_else(|| {
                value
                    .as_f64()
                    .filter(|value| {
                        value.fract() == 0. && *value >= i64::MIN as f64 && *value < i64::MAX as f64
                    })
                    .map(|value| value as i64)
            })
            .ok_or_else(|| invalid("circuit count must be an integer")),
    }
}
fn finite_time(now: f64) -> Result<()> {
    if now.is_finite() {
        Ok(())
    } else {
        Err(invalid("circuit clock must be finite"))
    }
}
fn finite_number(value: &Value) -> Result<f64> {
    let converted = match value {
        Value::Bool(value) => f64::from(*value),
        value => value
            .as_f64()
            .ok_or_else(|| invalid("circuit setting must be numeric"))?,
    };
    finite_time(converted)?;
    if let Value::Number(number) = value
        && integer_spelling(number)
    {
        let authored: num_bigint::BigInt = number
            .to_string()
            .parse()
            .map_err(|_| invalid("invalid circuit integer"))?;
        let represented: num_bigint::BigInt = format!("{converted:.0}")
            .parse()
            .map_err(|_| invalid("invalid circuit number"))?;
        if authored != represented {
            return Err(invalid(
                "circuit integer cannot be represented exactly by the native numeric API",
            ));
        }
    }
    Ok(converted)
}
fn integer_spelling(number: &serde_json::Number) -> bool {
    !number.to_string().contains(['.', 'e', 'E'])
}
// Preserve integer counters on disk. Refuse an increment/decrement that the
// current f64 status API cannot represent, instead of silently losing a failure.
fn change_failure_count(record: &Map<String, Value>, delta: i32) -> Result<Value> {
    let previous = record.get("failure_count");
    let integer = match previous {
        None => Some(num_bigint::BigInt::from(0)),
        Some(Value::Bool(value)) => Some(num_bigint::BigInt::from(i32::from(*value))),
        Some(Value::Number(number)) if integer_spelling(number) => Some(
            number
                .to_string()
                .parse::<num_bigint::BigInt>()
                .map_err(|_| invalid("invalid circuit integer"))?,
        ),
        _ => None,
    };
    let value = if let Some(integer) = integer {
        Value::Number(
            (integer + delta)
                .to_string()
                .parse()
                .map_err(|_| invalid("invalid circuit counter"))?,
        )
    } else {
        let number = number_or(record, "failure_count", 0.)? + f64::from(delta);
        Value::Number(
            serde_json::Number::from_f64(number)
                .ok_or_else(|| invalid("circuit counter overflow"))?,
        )
    };
    finite_number(&value)?;
    Ok(value)
}

fn number_or(record: &Map<String, Value>, key: &str, default: f64) -> Result<f64> {
    record
        .get(key)
        .map(finite_number)
        .transpose()
        .map(|value| value.unwrap_or(default))
}
fn optional_time(record: &Map<String, Value>, key: &str) -> Result<Option<f64>> {
    record
        .get(key)
        .filter(|value| !value.is_null())
        .map(finite_number)
        .transpose()
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
fn validate_record(value: &Value) -> Result<()> {
    let record = value
        .as_object()
        .ok_or_else(|| invalid("circuit record must be an object"))?;
    state(record)?;
    number_or(record, "failure_count", 0.)?;
    for key in ["success_count", "half_open_requests", "failure_streak"] {
        count(record, key)?;
    }
    for key in ["last_failure_time", "last_success_time", "opened_at"] {
        optional_time(record, key)?;
    }
    Ok(())
}
fn record(inner: &Inner, domain: &str) -> Map<String, Value> {
    inner
        .states
        .get(domain)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
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
            failure_count: 0.,
            success_count: 0,
            last_failure_time: None,
            last_success_time: None,
            opened_at: None,
            failure_streak: 0,
            current_timeout: inner.settings.timeout_seconds,
        });
    }
    let mut state = state(&data)?;
    let mut streak = count(&data, "failure_streak")?;
    let failure_time = optional_time(&data, "last_failure_time")?;
    if streak > 0
        && failure_time
            .is_some_and(|time| time != 0. && now - time > inner.settings.streak_decay_seconds)
    {
        streak = 0;
        data.insert("failure_streak".into(), json!(0));
    }
    let timeout = inner.settings.calculate_timeout(streak, random)?;
    if state == State::Open && now - number_or(&data, "opened_at", 0.)? >= timeout {
        state = State::HalfOpen;
        data.insert("state".into(), json!("half_open"));
        data.insert("success_count".into(), json!(0));
        data.insert("half_open_requests".into(), json!(0));
        inner.counters.half_opens += 1;
        event(events, TransitionKind::HalfOpen, domain, Value::Null);
    }
    let status = Status {
        state,
        failure_count: number_or(&data, "failure_count", 0.)?,
        success_count: count(&data, "success_count")?,
        last_failure_time: failure_time,
        last_success_time: optional_time(&data, "last_success_time")?,
        opened_at: optional_time(&data, "opened_at")?,
        failure_streak: streak,
        current_timeout: timeout,
    };
    inner.states.insert(domain.into(), Value::Object(data));
    Ok(status)
}
// Compare without rounding a large integer counter to floating point.
fn reaches_threshold(count: i64, threshold: f64) -> bool {
    if threshold <= i64::MIN as f64 {
        return true;
    }
    if threshold >= -(i64::MIN as f64) {
        return false;
    }
    count >= threshold.ceil() as i64
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
            let used = count(&data, "half_open_requests")?;
            if reaches_threshold(used, inner.settings.half_open_max_requests) {
                false
            } else {
                data.insert(
                    "half_open_requests".into(),
                    json!(
                        used.checked_add(1)
                            .ok_or_else(|| invalid("circuit counter overflow"))?
                    ),
                );
                inner.states.insert(domain.into(), Value::Object(data));
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
    let counter = change_failure_count(&data, 1)?;
    let failures = finite_number(&counter)?;
    let streak = count(&data, "failure_streak")?;
    data.insert("failure_count".into(), counter);
    data.insert("last_failure_time".into(), json!(now));
    data.insert("last_error".into(), json!(error.unwrap_or("")));
    match current {
        State::Closed => {
            if failures >= inner.settings.failure_threshold {
                data.insert("state".into(), json!("open"));
                data.insert("opened_at".into(), json!(now));
                data.insert("success_count".into(), json!(0));
                inner.counters.opens += 1;
                event(
                    events,
                    TransitionKind::Open,
                    domain,
                    json!({"failure_count":failures,"error":error}),
                );
            } else {
                data.insert("state".into(), json!("closed"));
            }
        }
        State::HalfOpen => {
            let streak = streak
                .checked_add(1)
                .ok_or_else(|| invalid("circuit streak overflow"))?;
            data.insert("state".into(), json!("open"));
            data.insert("opened_at".into(), json!(now));
            data.insert("failure_streak".into(), json!(streak));
            data.insert("success_count".into(), json!(0));
            inner.counters.opens += 1;
            event(
                events,
                TransitionKind::Reopen,
                domain,
                json!({"streak":streak,"error":error}),
            );
        }
        State::Open => {}
    }
    inner.states.insert(domain.into(), Value::Object(data));
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
    let successes = count(&data, "success_count")?
        .checked_add(1)
        .ok_or_else(|| invalid("circuit counter overflow"))?;
    data.insert("success_count".into(), json!(successes));
    data.insert("last_success_time".into(), json!(now));
    match current.state {
        State::HalfOpen => {
            if reaches_threshold(successes, inner.settings.success_threshold) {
                data.insert("state".into(), json!("closed"));
                data.insert("failure_count".into(), json!(0));
                data.insert("failure_streak".into(), json!(0));
                inner.counters.recoveries += 1;
                event(
                    events,
                    TransitionKind::Close,
                    domain,
                    json!({"success_count":successes}),
                );
            } else {
                data.insert("state".into(), json!("half_open"));
            }
        }
        State::Closed => {
            let failures = number_or(&data, "failure_count", 0.)?;
            if failures > 0. {
                data.insert("failure_count".into(), change_failure_count(&data, -1)?);
            }
        }
        State::Open => {}
    }
    inner.states.insert(domain.into(), Value::Object(data));
    status(inner, domain, now, random, events)
}
