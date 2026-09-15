//! Borrow only canonical TestContext targets; unrelated Any values stay with
//! their existing baseline owner and never enter the sensor JSON serializer.

use super::{Policy, TimestampPaths, Value};

const PATH: [&str; 3] = ["addons", "test_context", "target_hosts"];

pub(crate) struct TestContextTargets<'a> {
    hash: String,
    value: Option<&'a Value>,
    timestamps: Option<&'a TimestampPaths>,
}

impl Policy {
    /// The existing hash includes the task; addon settings come from baseline.
    pub(crate) fn test_context_targets(&self) -> TestContextTargets<'_> {
        let baseline = self.baseline.as_deref();
        TestContextTargets {
            hash: self.policy_hash(),
            value: baseline
                .and_then(|owner| owner.value.pointer("/addons/test_context/target_hosts")),
            timestamps: baseline.map(|owner| &owner.timestamps),
        }
    }
}

impl<'a> TestContextTargets<'a> {
    pub(crate) fn hash(&self) -> &str {
        &self.hash
    }
    pub(crate) fn value(&self) -> Option<&'a Value> {
        self.value
    }
    /// Called only when the hash changed. Preserve root values and nested keys
    /// without interpreting the parser's private storage as an authored value.
    pub(crate) fn projected_timestamps(&self) -> TimestampPaths {
        self.timestamps
            .map(|timestamps| timestamps.projected(&PATH))
            .unwrap_or_default()
    }
}
