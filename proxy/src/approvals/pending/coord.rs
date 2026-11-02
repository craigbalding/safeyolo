//! Trusted-ingress requests for access to an existing local room.
use super::{Authority, Record, Result, digest, invalid, revision};
use crate::{
    Runtime,
    coord_rooms::membership::{self, Participant},
    host_runs::AgentRun,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    room_name: String,
    permissions: Vec<String>,
    operation_id: String,
}

pub(crate) fn submit(runtime: &Runtime, run: &AgentRun, request: Request) -> Result<Record> {
    let policy = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    if !run.current(policy) {
        return Err(invalid("current trusted worker run required"));
    }
    if request.operation_id.trim().is_empty()
        || request.operation_id.len() > 1024
        || !membership::valid_permissions(&request.permissions)
    {
        return Err(invalid(
            "operation_id and explicit send/receive/page_operator permissions required",
        ));
    }
    let root = membership::root(policy).map_err(|e| invalid(e.to_string()))?;
    let conn = crate::coord_rooms::open(&root).map_err(|e| invalid(e.to_string()))?;
    let room: String = conn
        .query_row(
            "SELECT room_id FROM rooms WHERE name=?1",
            [&request.room_name],
            |r| r.get(0),
        )
        .map_err(|_| {
            invalid("existing local room unavailable; room creation remains operator-only")
        })?;
    let mut permissions = request.permissions;
    permissions.sort();
    permissions.dedup();
    let existing = membership::effective(&conn, &room).map_err(|e| invalid(e.to_string()))?;
    let mut participants = existing
        .iter()
        .map(|m| m.participant.clone())
        .collect::<Vec<_>>();
    let before = participants
        .iter()
        .find(|p| p.principal_kind == "agent" && p.principal_id == run.agent_id)
        .map(|p| p.permissions.clone())
        .unwrap_or_default();
    if let Some(worker) = participants
        .iter_mut()
        .find(|p| p.principal_kind == "agent" && p.principal_id == run.agent_id)
    {
        worker.permissions.extend(permissions.clone());
        worker.permissions.sort();
        worker.permissions.dedup();
    } else {
        participants.push(Participant {
            principal_kind: "agent".into(),
            principal_id: run.agent_id.clone(),
            permissions: permissions.clone(),
        });
    }
    participants.sort_by(|a, b| {
        (&a.principal_kind, &a.principal_id).cmp(&(&b.principal_kind, &b.principal_id))
    });
    let action = json!({"kind":"coord_access","agent":run.agent,"agent_id":run.agent_id,"run":run,"room_id":room,"room_name":request.room_name,"permissions":permissions,"participants":participants});
    let effect = format!(
        "Issue {} the explicit Coord rights {} in existing room {} for its current worker run, bounded by the selected delegation's lifetime. Existing worker rights: {}. Receive exposes retained history and native work, signals, state and brief. Send plus receive permits existing work/signal mutations; page_operator permits paging. The canonical participants bound this decision's audience. Independent grants remain; disclosed content cannot be retracted.",
        run.agent,
        permissions.join(","),
        request.room_name,
        if before.is_empty() {
            "none".into()
        } else {
            before.join(",")
        }
    );
    let request_id = format!(
        "req-{}",
        &digest(&json!({"run":run,"operation_id":request.operation_id}))[..32]
    );
    let authority = Authority {
        revision: revision(policy, &action).ok_or_else(|| invalid("room authority unavailable"))?,
        action,
        method: "POST".into(),
        scheme: "agent-api".into(),
        port: None,
        resource_digest: digest(&json!({"operation_id":request.operation_id})),
        options: vec![super::run_option(&effect)],
        expires_at: None,
        credential_bindings: Default::default(),
    };
    runtime
        .audit
        .approvals()
        .submit(authority, &request_id, policy)
}

pub(crate) async fn request(
    state: &crate::RuntimeState,
    run: &AgentRun,
    payload: &[u8],
) -> Result<Value> {
    let request: Request = serde_json::from_slice(payload)
        .map_err(|e| invalid(format!("invalid Coord access request: {e}")))?;
    let runtime = state
        .read()
        .map_err(|_| invalid("runtime unavailable"))?
        .clone();
    let owner = runtime.clone();
    let worker = run.clone();
    let pending = tokio::task::spawn_blocking(move || submit(&owner, &worker, request))
        .await
        .map_err(|_| invalid("Coord request state unavailable"))??;
    super::delegation::notify(&runtime, &pending).await;
    let mut view = pending.view(
        runtime
            .policy
            .as_deref()
            .ok_or_else(|| invalid("policy unavailable"))?,
    )?;
    view["retry"] = json!(
        "Inspect this canonical approval before repeating a decision. After approval retry ordinary Coord join, history or message access."
    );
    Ok(view)
}
