//! Delegated support. The target's policy and host owners retain authority.

pub(crate) mod events;
pub(crate) mod grants;
mod operations;
pub(crate) use operations::Request;

use crate::{Error, RuntimeState, policy::Policy};

#[derive(Clone, serde::Serialize)]
pub(crate) struct Caller {
    #[serde(flatten)]
    pub run: crate::host_runs::AgentRun,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<crate::coord_rooms::federation::RemoteAgent>,
}

impl Caller {
    pub fn local(run: &crate::host_runs::AgentRun) -> Self {
        Self {
            run: run.clone(),
            remote: None,
        }
    }
    fn principal(&self) -> &str {
        self.remote
            .as_ref()
            .map_or(&self.run.agent_id, |remote| &remote.principal_id)
    }
    fn current(&self, policy: &Policy) -> bool {
        if let Some(remote) = &self.remote {
            remote.agent_id == self.run.agent_id
                && policy.identity_root().is_some_and(|root| {
                    crate::coord_rooms::open(root).is_ok_and(|conn| {
                        crate::coord_rooms::federation::authorize(&conn, remote).is_ok()
                    })
                })
        } else {
            self.run.current(policy)
        }
    }
    fn matches(&self, policy: &Policy, grant: &crate::policy::support::Grant) -> bool {
        self.current(policy)
            && grant.support.agent_id == self.run.agent_id
            && support_principal(policy, grant).as_deref() == Some(self.principal())
            && match &self.remote {
                Some(remote) => grant.support_instance_id.as_deref() == Some(&remote.instance_id),
                None => grant.support_instance_id.is_none() && grant.support.name == self.run.agent,
            }
    }
}

pub(crate) fn support_principal(
    policy: &Policy,
    grant: &crate::policy::support::Grant,
) -> Option<String> {
    checked_support_principal(policy, grant).ok().flatten()
}

pub(crate) fn checked_support_principal(
    policy: &Policy,
    grant: &crate::policy::support::Grant,
) -> Result<Option<String>, Error> {
    if let Some(instance) = &grant.support_instance_id {
        let conn = crate::coord_rooms::open(
            policy
                .identity_root()
                .ok_or("owning identity root unavailable")?,
        )?;
        let Some(epoch) = grant.support_peer_epoch else {
            return Ok(None);
        };
        let id = crate::coord_rooms::federation::principal(instance, &grant.support.agent_id);
        let current:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM coord_federation_peers p JOIN coord_federation_agents a USING(instance_id) WHERE p.instance_id=?1 AND p.enabled=1 AND p.epoch=?2 AND a.principal_id=?3 AND a.agent_id=?4)",rusqlite::params![instance,epoch,id,grant.support.agent_id],|row|row.get(0))?;
        Ok(current.then_some(id))
    } else {
        Ok(
            (policy.evidence_agent_id(&grant.support.name)
                == Some(grant.support.agent_id.as_str()))
            .then(|| grant.support.agent_id.clone()),
        )
    }
}

pub(crate) fn discover(
    state: &RuntimeState,
    run: &crate::host_runs::AgentRun,
) -> Result<serde_json::Value, Error> {
    operations::discover(state, &Caller::local(run))
}
pub(crate) fn read(
    state: &RuntimeState,
    run: &crate::host_runs::AgentRun,
    id: &str,
) -> Result<serde_json::Value, Error> {
    operations::read(state, &Caller::local(run), id)
}
pub(crate) async fn submit(
    state: &RuntimeState,
    writer: &std::sync::Arc<crate::audit::Writer>,
    run: &crate::host_runs::AgentRun,
    input: Request,
) -> Result<serde_json::Value, Error> {
    operations::submit(state, writer, &Caller::local(run), input).await
}

pub(crate) async fn remote(
    state: &RuntimeState,
    writer: &std::sync::Arc<crate::audit::Writer>,
    caller: &Caller,
    method: &str,
    path: &str,
    payload: Option<&[u8]>,
) -> Result<serde_json::Value, Error> {
    if method == "GET" && path == "/support/grants" {
        operations::discover(state, caller)
    } else if method == "GET"
        && let Some(id) = path.strip_prefix("/support/operations/")
    {
        let id = percent_encoding::percent_decode_str(id)
            .decode_utf8()
            .map_err(|_| refuse(400, "operation ID must be UTF-8"))?;
        operations::read(state, caller, &id)
    } else if method == "POST" && path == "/support/operations" {
        let input: Request = serde_json::from_slice(payload.unwrap_or_default())
            .map_err(|_| refuse(400, "invalid typed support operation"))?;
        let id = input.operation_id.clone();
        operations::submit(state, writer, caller, input).await?;
        operations::read(state, caller, &id)
    } else {
        Err(refuse(404, "support operation unavailable"))
    }
}

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
    let support_current = support_principal(policy, grant).is_some();
    let current = grant.active() && grant.instance_id == instance && support_current;
    let targets: Vec<_> = grant.targets.iter().map(|target| json!({"name":target.name,"agent_id":target.agent_id,
        "active":current && policy.evidence_agent_id(&target.name) == Some(target.agent_id.as_str())})).collect();
    json!({"name":name,"revision":grant.revision(),"active":targets.iter().any(|target| target["active"] == true),
        "target_status":targets,"grant":grant})
}
