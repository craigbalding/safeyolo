//! Shared host-execution contract. Transport, issuer policy and native process
//! containment remain with their owners; validation alone never executes code.

mod authority;
pub mod effects;
mod ledger;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
mod native;
mod package;
mod protocol;
mod semantics;
pub mod server;
#[cfg(unix)]
mod unix_services;
#[cfg(windows)]
pub mod windows;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(
    schemars::JsonSchema, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct AgentRun {
    pub agent: String,
    pub agent_id: String,
    pub run_id: String,
}

#[derive(schemars::JsonSchema, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub location: String,
    pub version: String,
}

#[derive(schemars::JsonSchema, Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedEffect {
    pub description: String,
    pub persists_after_access: bool,
    pub evidence: Vec<String>,
}

pub fn valid_agent_id(value: &str) -> bool {
    value.strip_prefix("ag-").is_some_and(|s| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}
pub use authority::*;
pub use ledger::*;
pub use native::{NativeRuntime, now};
pub use package::*;
pub use protocol::*;
pub use semantics::*;

use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroize;

pub const VERSION: &str = "safeyolo.host-execution/v1";
pub const FEATURES: &[&str] = &["signed-request-v1", "revision-binding-v1", "job-receipt-v1"];

pub fn schemas() -> Value {
    serde_json::json!({
        "version": VERSION,
        "package": schemars::schema_for!(Package),
        "request": schemars::schema_for!(SignedRequest),
        "response": schemars::schema_for!(Response),
    })
}

/// Use the same recursively ordered JSON digest as policy approvals and reports.
pub fn revision(value: &impl Serialize) -> String {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(fields) => {
                let sorted: std::collections::BTreeMap<_, _> = fields.iter().collect();
                Value::Object(
                    sorted
                        .into_iter()
                        .map(|(key, value)| (key.clone(), canonical(value)))
                        .collect(),
                )
            }
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            _ => value.clone(),
        }
    }
    fn wipe(value: &mut Value) {
        match value {
            Value::String(value) => value.zeroize(),
            Value::Array(values) => values.iter_mut().for_each(wipe),
            Value::Object(values) => {
                for (mut key, mut value) in std::mem::take(values) {
                    key.zeroize();
                    wipe(&mut value);
                }
            }
            _ => {}
        }
    }
    let mut ordered = canonical(&serde_json::to_value(value).expect("contract serialization"));
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&ordered).expect("JSON value"));
    wipe(&mut ordered);
    ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn selector(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn require(condition: bool, code: RefusalCode, message: &str) -> Result<(), Refusal> {
    if condition {
        Ok(())
    } else {
        Err(Refusal {
            code,
            message: message.into(),
        })
    }
}

/// The embedding host supplies current-run observations from its existing owner.
pub trait AgentRunPolicy {
    fn run_is_current(&self, run: &AgentRun) -> bool;
}
impl<T: AgentRunPolicy> AgentRunPolicy for std::sync::Arc<T> {
    fn run_is_current(&self, run: &AgentRun) -> bool {
        self.as_ref().run_is_current(run)
    }
}
impl AgentRun {
    pub fn current(&self, policy: &impl AgentRunPolicy) -> bool {
        policy.run_is_current(self)
    }
}
