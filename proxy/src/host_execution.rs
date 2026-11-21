//! Shared host-execution contract. Transport, issuer policy and native process
//! containment remain with their owners; validation alone never executes code.

mod authority;
mod ledger;
mod package;
mod protocol;

pub use crate::host_runs::AgentRun;
pub use authority::*;
pub use ledger::*;
pub use package::*;
pub use protocol::*;

use serde::Serialize;
use serde_json::Value;

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
    crate::approvals::pending::digest(&serde_json::to_value(value).expect("contract serialization"))
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
