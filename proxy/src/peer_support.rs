//! Local delegated support. Policy owns authority; existing host owners execute.

pub(crate) mod grants;
mod operations;
pub(crate) use operations::{Request, discover, read, submit};

use crate::{Error, RuntimeState, policy::Policy};

/// Only explicit support diagnostics cross the API. Backend errors can contain
/// host paths or launcher output and remain with their existing host owners.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub status: u16,
    pub message: &'static str,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}
impl std::error::Error for Refusal {}

fn refuse(status: u16, message: &'static str) -> Error {
    Box::new(Refusal { status, message })
}

/// Read the host's current policy source, including edits not yet observed by
/// the watcher. Call again after a lifecycle-lock wait, before execution.
pub(crate) fn current_policy(state: &RuntimeState) -> Result<Policy, Error> {
    let runtime = state.read().map_err(|_| "runtime unavailable")?;
    let policy = runtime.policy.as_ref().ok_or("policy unavailable")?;
    let path = runtime
        .config
        .policy_file
        .as_ref()
        .ok_or("policy path unavailable")?;
    Ok(policy.reload_native_source(&std::fs::read_to_string(path)?, path)?)
}

pub(crate) fn instance_id() -> Result<String, Error> {
    crate::desktop_present::instance_id().map_err(|_| "owning instance identity unavailable".into())
}

pub(crate) fn grant_view(
    policy: &Policy,
    name: &str,
    grant: &crate::policy::support::Grant,
    instance: &str,
) -> serde_json::Value {
    use serde_json::json;
    let support_current =
        policy.evidence_agent_id(&grant.support.name) == Some(grant.support.agent_id.as_str());
    let current = grant.active() && grant.instance_id == instance && support_current;
    let targets: Vec<_> = grant.targets.iter().map(|target| json!({"name":target.name,"agent_id":target.agent_id,
        "active":current && policy.evidence_agent_id(&target.name) == Some(target.agent_id.as_str())})).collect();
    json!({"name":name,"revision":grant.revision(),"active":targets.iter().any(|target| target["active"] == true),
        "target_status":targets,"grant":grant})
}
