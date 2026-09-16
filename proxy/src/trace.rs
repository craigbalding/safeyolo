//! In-memory source trace records. The caller owns opt-in, trusted identity,
//! clock sampling and runtime hook reachability; this store schedules no work.

use std::{fmt, sync::Mutex};

use indexmap::IndexMap;
use num_bigint::BigInt;
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::circuits::{CircuitValue as C, ErrorKind as NumericError};

const EXPECTED_ADDONS: [&str; 6] = [
    "service-gateway",
    "network-guard",
    "circuit-breaker",
    "credential-guard",
    "pattern-scanner",
    "test-context",
];

#[derive(Clone)]
pub struct Settings {
    pub ttl_s: C,
    pub global_max: BigInt,
    pub per_agent_max: BigInt,
    pub steps_max: BigInt,
    pub details_max_bytes: BigInt,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ttl_s: 300.into(),
            global_max: 1000.into(),
            per_agent_max: 200.into(),
            steps_max: 128.into(),
            details_max_bytes: 4096.into(),
        }
    }
}

impl Settings {
    /// The runtime samples these once when it creates the shared store.
    /// Invalid integers, including non-Unicode environment bytes, use defaults.
    pub fn from_env() -> Self {
        let read = |name| std::env::var(name).ok();
        let ttl = read("SAFEYOLO_TRACE_TTL_S");
        let global = read("SAFEYOLO_TRACE_GLOBAL_MAX");
        let agent = read("SAFEYOLO_TRACE_PER_AGENT_MAX");
        let steps = read("SAFEYOLO_TRACE_STEPS_MAX");
        let details = read("SAFEYOLO_TRACE_DETAILS_MAX_BYTES");
        Self::from_environment_values(
            ttl.as_deref(),
            global.as_deref(),
            agent.as_deref(),
            steps.as_deref(),
            details.as_deref(),
        )
    }

    pub fn from_environment_values(
        ttl_s: Option<&str>,
        global_max: Option<&str>,
        per_agent_max: Option<&str>,
        steps_max: Option<&str>,
        details_max_bytes: Option<&str>,
    ) -> Self {
        let integer = |value: Option<&str>, default: i32| {
            value
                .and_then(|value| {
                    crate::flow_store::integer(&C::Other(Value::String(value.into())))
                })
                .unwrap_or_else(|| default.into())
        };
        Self {
            ttl_s: integer(ttl_s, 300).into(),
            global_max: integer(global_max, 1000),
            per_agent_max: integer(per_agent_max, 200),
            steps_max: integer(steps_max, 128),
            details_max_bytes: integer(details_max_bytes, 4096),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Poisoned,
    Type,
    Attribute,
    Overflow,
    Compatibility,
    Index,
    StopIteration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(ErrorKind);
impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("trace store operation failed")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Concrete source Step fields. Details accept ordered JSON-shaped values;
/// strings/integers/bools/null survive, while floats and containers are named.
pub struct Step {
    pub addon: String,
    pub hook: String,
    pub state: String,
    pub outcome: Option<String>,
    pub reason: Option<String>,
    pub duration_us: Option<BigInt>,
    pub details: Option<C>,
    pub ts: f64,
    pub connection_id: Option<String>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub port: Option<BigInt>,
}

impl Step {
    pub fn new(
        addon: impl Into<String>,
        hook: impl Into<String>,
        state: impl Into<String>,
        ts: f64,
    ) -> Self {
        Self {
            addon: addon.into(),
            hook: hook.into(),
            state: state.into(),
            outcome: None,
            reason: None,
            duration_us: None,
            details: None,
            ts,
            connection_id: None,
            method: None,
            host: None,
            port: None,
        }
    }

    fn document(&self, limit: &BigInt) -> Result<Value> {
        let mut fields = serde_json::Map::new();
        fields.insert("addon".into(), json!(self.addon));
        fields.insert("hook".into(), json!(self.hook));
        fields.insert("state".into(), json!(self.state));
        optional(&mut fields, "outcome", self.outcome.as_deref());
        optional(&mut fields, "reason", self.reason.as_deref());
        if let Some(value) = &self.duration_us {
            fields.insert("duration_us".into(), integer_json(value));
        }
        if let Some(value) = &self.details
            && !matches!(value, C::Other(Value::Null))
        {
            fields.insert("details".into(), cap_details(value, limit)?);
        }
        optional(&mut fields, "connection_id", self.connection_id.as_deref());
        optional(&mut fields, "method", self.method.as_deref());
        optional(&mut fields, "host", self.host.as_deref());
        if let Some(value) = &self.port {
            fields.insert("port".into(), integer_json(value));
        }
        Ok(Value::Object(fields))
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        self.addon.zeroize();
        self.hook.zeroize();
        self.state.zeroize();
        for value in [
            &mut self.outcome,
            &mut self.reason,
            &mut self.connection_id,
            &mut self.method,
            &mut self.host,
        ]
        .into_iter()
        .flatten()
        {
            value.zeroize();
        }
    }
}

struct Record {
    agent_id: Option<String>,
    created_at: f64,
    steps: Vec<Step>,
    truncated: bool,
}
impl Drop for Record {
    fn drop(&mut self) {
        if let Some(agent) = &mut self.agent_id {
            agent.zeroize();
        }
    }
}

#[derive(Default)]
struct State {
    records: IndexMap<String, Record>,
    by_agent: IndexMap<String, Vec<String>>,
}

impl State {
    fn drop_record(&mut self, request_id: &str) {
        let Some((mut id, record)) = self.records.shift_remove_entry(request_id) else {
            return;
        };
        id.zeroize();
        if let Some(agent) = record.agent_id.as_deref().filter(|agent| !agent.is_empty()) {
            let empty = if let Some(ids) = self.by_agent.get_mut(agent) {
                if let Some(index) = ids.iter().position(|id| id == request_id) {
                    ids.remove(index).zeroize();
                }
                ids.is_empty()
            } else {
                false
            };
            if empty && let Some((mut name, _)) = self.by_agent.shift_remove_entry(agent) {
                name.zeroize();
            }
        }
    }

    fn expire(&mut self, settings: &Settings, now: f64) -> Result<()> {
        // Division by float one reuses the existing Python numeric conversion,
        // including Overflow for an integer too large to convert to float.
        let C::Float(ttl) = settings
            .ttl_s
            .divide(&C::Float(1.0))
            .map_err(numeric_error)?
        else {
            unreachable!("floating divisor")
        };
        let cutoff = now - ttl;
        let count = self
            .records
            .values()
            .take_while(|record| {
                record
                    .steps
                    .last()
                    .map_or(record.created_at, |step| step.ts)
                    < cutoff
            })
            .count();
        // Source deliberately stops at the first live record. Append order and
        // retained step timestamps can disagree; do not scan beyond that point.
        for _ in 0..count {
            let id = self.records.first().expect("counted record").0.clone();
            self.drop_record(&id);
        }
        Ok(())
    }

    fn enforce_caps(&mut self, settings: &Settings, agent: Option<&str>) -> Result<()> {
        if let Some(agent) = agent.filter(|agent| !agent.is_empty()) {
            loop {
                let ids = self.by_agent.get(agent);
                if BigInt::from(ids.map_or(0, Vec::len)) <= settings.per_agent_max {
                    break;
                }
                let oldest = ids
                    .and_then(|ids| ids.first())
                    .ok_or(Error(ErrorKind::Index))?
                    .clone();
                self.drop_record(&oldest);
            }
        }
        while BigInt::from(self.records.len()) > settings.global_max {
            let oldest = self
                .records
                .first()
                .ok_or(Error(ErrorKind::StopIteration))?
                .0
                .clone();
            self.drop_record(&oldest);
        }
        Ok(())
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for (mut id, _) in self.records.drain(..) {
            id.zeroize();
        }
        for (mut agent, mut ids) in self.by_agent.drain(..) {
            agent.zeroize();
            for id in &mut ids {
                id.zeroize();
            }
        }
    }
}

pub struct TraceStore {
    settings: Settings,
    state: Mutex<State>,
}

impl TraceStore {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            state: Mutex::new(State::default()),
        }
    }

    pub fn append(
        &self,
        request_id: &str,
        agent: Option<&str>,
        step: Step,
        now: f64,
    ) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
        state.expire(&self.settings, now)?;
        if let Some((id, mut record)) = state.records.shift_remove_entry(request_id) {
            // Only None can be filled; an empty first owner is not None.
            if record.agent_id.is_none()
                && let Some(agent) = agent.filter(|agent| !agent.is_empty())
            {
                record.agent_id = Some(agent.into());
                state
                    .by_agent
                    .entry(agent.into())
                    .or_default()
                    .push(request_id.into());
            }
            // Existing records move even when the new step will be capped.
            // Late owner fill does not enforce caps in the source.
            state.records.insert(id, record);
        } else {
            state.records.insert(
                request_id.into(),
                Record {
                    agent_id: agent.map(str::to_owned),
                    created_at: now,
                    steps: Vec::new(),
                    truncated: false,
                },
            );
            if let Some(agent) = agent.filter(|agent| !agent.is_empty()) {
                state
                    .by_agent
                    .entry(agent.into())
                    .or_default()
                    .push(request_id.into());
            }
            state.enforce_caps(&self.settings, agent)?;
        }
        // A zero cap may already have removed the just-created source record.
        // Its subsequent orphan append has no observable store effect.
        if let Some(record) = state.records.get_mut(request_id) {
            if BigInt::from(record.steps.len()) >= self.settings.steps_max {
                record.truncated = true;
            } else {
                record.steps.push(step);
            }
        }
        Ok(())
    }

    /// Missing, unresolved and foreign-owner reads all return None after expiry.
    /// The returned report is an owned snapshot; reads do not refresh LRU order.
    pub fn get(&self, request_id: &str, agent: Option<&str>, now: f64) -> Result<Option<Value>> {
        let mut state = self.state.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
        state.expire(&self.settings, now)?;
        let Some(record) = state.records.get(request_id) else {
            return Ok(None);
        };
        if agent.is_none_or(str::is_empty) || record.agent_id.as_deref() != agent {
            return Ok(None);
        }
        let created_at = serde_json::Number::from_f64(record.created_at)
            .ok_or(Error(ErrorKind::Compatibility))?;
        let expected: &[&str] = if record.steps.iter().any(|step| step.hook == "http_connect") {
            &["network-guard"]
        } else {
            &EXPECTED_ADDONS
        };
        let not_loaded: Vec<_> = expected
            .iter()
            .filter(|name| !record.steps.iter().any(|step| &step.addon == *name))
            .map(|name| json!({"addon":name,"state":"not_loaded"}))
            .collect();
        let steps = record
            .steps
            .iter()
            .map(|step| step.document(&self.settings.details_max_bytes))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(
            json!({"request_id":request_id,"agent_id":record.agent_id,
            "created_at":created_at,"truncated":record.truncated,"steps":steps,"not_loaded":not_loaded}),
        ))
    }
}

fn numeric_error(error: crate::circuits::Error) -> Error {
    Error(match error.kind() {
        NumericError::Type => ErrorKind::Type,
        NumericError::Overflow => ErrorKind::Overflow,
        _ => ErrorKind::Compatibility,
    })
}
fn optional(fields: &mut serde_json::Map<String, Value>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        fields.insert(name.into(), json!(value));
    }
}
fn integer_json(value: &BigInt) -> Value {
    Value::Number(value.to_string().parse().expect("BigInt JSON integer"))
}

fn cap_details(details: &C, limit: &BigInt) -> Result<Value> {
    if let C::Other(Value::Object(_)) = details {
        return cap_details(&C::from(details.json().map_err(numeric_error)?), limit);
    }
    let fields = details.as_object().ok_or(Error(ErrorKind::Attribute))?;
    let mut cleaned = serde_json::Map::new();
    for (key, value) in fields {
        let value = match value {
            C::Integer(value) => {
                if value.to_string().trim_start_matches('-').len() > 4300 {
                    return Ok(json!({"_truncated":true}));
                }
                integer_json(value)
            }
            C::Bool(value) => json!(value),
            C::Float(_) => json!("<float>"),
            C::Array(_) => json!("<list>"),
            C::Object(_) => json!("<dict>"),
            C::Other(Value::String(value)) => json!(value),
            C::Other(Value::Null) => Value::Null,
            C::Other(Value::Bool(value)) => json!(value),
            C::Other(Value::Array(_)) => json!("<list>"),
            C::Other(Value::Object(_)) => json!("<dict>"),
            C::Other(Value::Number(value)) => {
                let text = value.to_string();
                if text.contains(['.', 'e', 'E']) {
                    json!("<float>")
                } else if text.trim_start_matches('-').len() > 4300 {
                    return Ok(json!({"_truncated":true}));
                } else {
                    Value::Number(value.clone())
                }
            }
            C::Temporal(_) => return Err(Error(ErrorKind::Compatibility)),
        };
        cleaned.insert(key.clone(), value);
    }
    let cleaned = Value::Object(cleaned);
    // Source names this a byte cap, but counts default json.dumps characters.
    // The shared formatter emits ASCII escapes, so its byte length is exact.
    if BigInt::from(crate::python_json::encoded_len(&cleaned)) > *limit {
        Ok(json!({"_truncated":true}))
    } else {
        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests;
