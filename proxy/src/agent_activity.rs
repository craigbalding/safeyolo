//! Request activity for the configured agent listeners. This report is never
//! consulted to select a request's identity.

use std::sync::Mutex;

use indexmap::IndexMap;
use serde_json::Value;
use zeroize::Zeroize;

use crate::{AgentListener, circuits::CircuitValue};

#[derive(Debug)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("agent activity unavailable")
    }
}

impl std::error::Error for Error {}

/// Retained across runtime reloads so listener reports keep prior observations.
#[derive(Default)]
pub struct AgentActivity {
    last_seen: Mutex<IndexMap<String, f64>>,
}

impl AgentActivity {
    pub fn observe(&self, agent: &str, now: f64) -> Result<(), Error> {
        self.last_seen
            .lock()
            .map_err(|_| Error)?
            .insert(agent.into(), now);
        Ok(())
    }

    /// Report only configured listeners. Removed agents do not reappear merely
    /// because this process observed them in an earlier listener generation.
    pub fn report(&self, listeners: &[AgentListener], now: f64) -> Result<CircuitValue, Error> {
        let seen = self.last_seen.lock().map_err(|_| Error)?;
        let mut agents = IndexMap::new();
        for listener in listeners {
            let mut info = IndexMap::new();
            info.insert(
                "ip".into(),
                listener
                    .source_id()
                    // Source slots can be opaque declaration keys. Only IP
                    // addresses belong in the global Agent API report.
                    .filter(|source| source.parse::<std::net::IpAddr>().is_ok())
                    .map_or(Value::Null, Value::String)
                    .into(),
            );
            if let Some(last_seen) = seen.get(&listener.agent_id) {
                info.insert("last_seen".into(), CircuitValue::Float(*last_seen));
                let elapsed = now - last_seen;
                let idle = if elapsed.is_finite() {
                    format!("{elapsed:.1}").parse().expect("formatted float")
                } else {
                    elapsed
                };
                info.insert("idle_seconds".into(), CircuitValue::Float(idle));
            }
            agents.insert(listener.agent_id.clone(), CircuitValue::Object(info));
        }
        Ok(CircuitValue::Object(IndexMap::from([
            ("count".into(), Value::from(agents.len()).into()),
            ("agents".into(), CircuitValue::Object(agents)),
        ])))
    }
}

impl Drop for AgentActivity {
    fn drop(&mut self) {
        let seen = self
            .last_seen
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for (mut name, _) in seen.drain(..) {
            name.zeroize();
        }
    }
}
