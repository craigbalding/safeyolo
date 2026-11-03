//! Trusted-ingress requests for existing room access or a new collaboration.
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollaborationRequest {
    participants: Vec<String>,
    topic: Option<String>,
    ttl_seconds: Option<i64>,
    operation_id: String,
}

fn submit_collaboration(
    runtime: &Runtime,
    run: &AgentRun,
    request: CollaborationRequest,
) -> Result<Record> {
    let policy = runtime
        .policy
        .as_deref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    if !run.current(policy)
        || request.operation_id.trim().is_empty()
        || request.operation_id.len() > 1024
    {
        return Err(invalid(
            "current trusted worker run and operation_id required",
        ));
    }
    let mut names = request.participants;
    names.push(run.agent.clone());
    names.sort();
    names.dedup();
    let limit = if runtime.config.collaboration.max_participants == 0 {
        8
    } else {
        runtime.config.collaboration.max_participants.max(2)
    };
    if names.len() < 2 || names.len() > limit {
        return Err(invalid(format!(
            "collaboration requires 2..{limit} explicit participants including the requester"
        )));
    }
    let participants = names
        .iter()
        .map(|name| {
            policy
                .evidence_agent_id(name)
                .map(|id| json!({"name":name,"agent_id":id}))
                .ok_or_else(|| {
                    invalid("every participant must have a current durable agent identity")
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let default_ttl = runtime.config.collaboration.default_ttl_seconds;
    let ttl = request
        .ttl_seconds
        .filter(|ttl| *ttl > 0)
        .unwrap_or(if default_ttl > 0 { default_ttl } else { 3600 });
    let key = digest(&json!({"run":run,"operation_id":request.operation_id}));
    let request_id = format!("req-{}", &key[..32]);
    let action = json!({"kind":"coord_collaboration","agent":run.agent,"agent_id":run.agent_id,"run":run,
        "room_id":format!("rm-{}",&key[..32]),"room_name":format!("collaboration-{}",&key[..32]),
        "participants":participants,"topic":request.topic,"ttl_seconds":ttl});
    // The canonical submit transaction retains the first deadline on retry.
    let expires_at = Some(
        time::OffsetDateTime::now_utc()
            .checked_add(time::Duration::seconds(ttl))
            .ok_or_else(|| invalid("collaboration lifetime is out of range"))?
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| invalid("collaboration lifetime is out of range"))?,
    );
    let effect = format!(
        "Create room {} for the named durable identities with send and receive rights until {}. The host operator also has ordinary room access. Lifetime starts at this request, not at approval. Receive exposes retained room history; revoke/regrant preserves ordinary room history. This does not grant page_operator, room creation authority, service access or direct broker access.",
        action["room_name"].as_str().unwrap_or(""),
        expires_at.as_deref().unwrap_or("")
    );
    let authority = Authority {
        revision: revision(policy, &action)
            .ok_or_else(|| invalid("collaboration identities unavailable"))?,
        action,
        method: "POST".into(),
        scheme: "agent-api".into(),
        port: None,
        resource_digest: digest(&json!({"operation_id":request.operation_id})),
        options: vec![super::OptionScope {
            id: "collaboration".into(),
            effect,
            session_id: None,
            parameters: Value::Null,
        }],
        expires_at,
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
    collaboration: bool,
) -> Result<Value> {
    let runtime = state
        .read()
        .map_err(|_| invalid("runtime unavailable"))?
        .clone();
    let owner = runtime.clone();
    let worker = run.clone();
    let payload = payload.to_vec();
    let pending = tokio::task::spawn_blocking(move || {
        if collaboration {
            let request = serde_json::from_slice(&payload)
                .map_err(|e| invalid(format!("invalid collaboration request: {e}")))?;
            submit_collaboration(&owner, &worker, request)
        } else {
            let request = serde_json::from_slice(&payload)
                .map_err(|e| invalid(format!("invalid Coord access request: {e}")))?;
            submit(&owner, &worker, request)
        }
    })
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
        "Inspect this canonical approval before repeating a decision. After approval use ordinary Coord join, history or send with room_name."
    );
    Ok(view)
}
