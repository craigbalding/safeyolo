//! The finite operator-action vocabulary. Pending approvals own decisions;
//! the desktop presenter owns preview execution and cleanup.

use std::{path::PathBuf, sync::Arc};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    RuntimeState,
    approvals::{Result, invalid, network_action::Decision, pending},
    audit::{Event, Kind, Severity, Writer},
    desktop_present::{self, Parameters, Route},
    host_agents, host_platform,
    policy::Policy,
};

pub(crate) const DESKTOP_PRESENT: &str = "desktop.present";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) action_id: String,
    #[serde(default)]
    pub(crate) parameters: Parameters,
    pub(crate) reason: Option<String>,
}

fn config_path(state: &RuntimeState) -> Result<PathBuf> {
    let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
    Ok(runtime
        .config
        .native_config_path
        .clone()
        .or_else(|| {
            runtime
                .config
                .native_config_dir
                .as_ref()
                .map(|root| root.join("config.toml"))
        })
        .unwrap_or_else(host_platform::config_path))
}

fn requester(policy: &Policy, caller: &str) -> Result<host_agents::Agent> {
    let agents = host_agents::list().map_err(|_| invalid("host agent registry unavailable"))?;
    let id = policy
        .evidence_agent_id(caller)
        .ok_or_else(|| invalid("requesting agent identity unavailable"))?;
    let agent = host_agents::by_id(&agents, id)
        .map_err(|_| invalid("host agent identity is ambiguous"))?
        .filter(|agent| agent.name == caller)
        .ok_or_else(|| invalid("requesting agent was removed or replaced"))?;
    Ok(agent.clone())
}

pub(crate) async fn discover(state: &RuntimeState, policy: &Policy, caller: &str) -> Result<Value> {
    host_platform::in_config(config_path(state)?, async {
        let agent = requester(policy, caller)?;
        let prerequisite = desktop_present::action_prerequisites(&agent.name).await;
        Ok(json!({"actions":[{"action_id":DESKTOP_PRESENT,"name":"Present agent desktop",
            "description":"Start or reuse this agent's gated desktop preview for the operator. Optionally launch its guest browser.",
            "target":"requesting_agent","approval_required":true,"approval_option":"once",
            "parameters":{"type":"object","additionalProperties":false,"properties":{
                "browser_url":{"type":"string","description":"HTTP or HTTPS URL without credentials, or about:blank","maxLength":8192},
                "ttl_seconds":{"type":"integer","minimum":1,"maximum":86400,"default":900}}},
            "available":prerequisite.is_ok(),
            "presentation":prerequisite.as_ref().ok(),
            "diagnostic":prerequisite.err().map(|error| error.json()),
            "side_effects":["Start or reuse the managed guest desktop and gated preview.",
                "Use the host's local browser or configured Tailscale Serve route.",
                "Close preview access when its approved lifetime expires."],
            "non_grants":["No change to network policy, service grants or credentials.","No public or Funnel exposure."]}]}))
    }).await
}

pub(crate) fn agent_view(record: &pending::Record) -> Value {
    // Whitelist the result. Never return a general approval view: operator
    // results may contain a URL/unlock code and browser parameters are data.
    let mut result = json!({"action_id":DESKTOP_PRESENT,"action_request_id":record.approval_id,
        "approval_id":record.approval_id,"request_id":record.request_id,
        "status":if record.status == "pending" {"pending_operator_approval"} else {record.status.as_str()},
        "result":{"status":record.result["status"],"presentation":record.result["presentation"],
            "reused":record.result["reused"],"expires_at":record.result["expires_at"],
            "diagnostic":record.result["diagnostic"]}});
    if record.result["status"] == "started"
        && record.result["expires_at"]
            .as_str()
            .and_then(crate::policy::parse_expiry)
            .is_some_and(|expiry| time::OffsetDateTime::now_utc() >= expiry)
    {
        result["result"]["status"] = json!("expired");
    }
    result
}

pub(crate) async fn request(
    state: &RuntimeState,
    writer: &Arc<Writer>,
    policy: &Policy,
    caller: &str,
    request_id: &str,
    input: Request,
) -> Result<Value> {
    if input.action_id != DESKTOP_PRESENT {
        return Err(invalid("unknown operator action"));
    }
    input.parameters.validate().map_err(invalid)?;
    if input
        .reason
        .as_ref()
        .is_some_and(|reason| reason.len() > pending::context::MAX_FIELD_BYTES)
    {
        return Err(invalid("reason is limited to 2048 UTF-8 bytes"));
    }
    host_platform::in_config(config_path(state)?, async {
        let agent = requester(policy, caller)?;
        let route = match desktop_present::action_prerequisites(&agent.name).await {
            Ok(route) => route,
            Err(error) => return Ok(json!({"action_id":DESKTOP_PRESENT,"status":"unavailable","diagnostic":error.json()})),
        };
        let action = json!({"kind":"operator_action","action_id":DESKTOP_PRESENT,"agent":agent.name,
            "agent_id":agent.id,"parameters":input.parameters,"presentation":route});
        let effect = format!("Present this agent's managed desktop through the {} path once. {}Preview access expires after {} seconds. Reusing an active preview resets its expiry to this lifetime. Network and service permissions stay unchanged.",
            if route == Route::Local {"local browser"} else {"configured gated tailnet"},
            if input.parameters.browser_url.is_some() {"Open the validated URL in its guest browser. "} else {""},
            input.parameters.ttl_seconds);
        let authority = pending::Authority {
            revision:pending::revision(policy, &action).ok_or_else(|| invalid("action authority unavailable"))?,
            resource_digest:pending::digest(&action), action,
            method:"POST".into(),scheme:"http".into(),port:None,
            options:vec![pending::OptionScope {id:"once".into(),effect,session_id:None,parameters:Value::Null}],
            expires_at:None,credential_bindings:Default::default(),
        };
        let (work_writer, work_policy, work_id) = (writer.clone(), policy.clone(), request_id.to_owned());
        let record = tokio::task::spawn_blocking(move || {
            let record = work_writer.approvals().submit(authority, &work_id, &work_policy)?;
            work_writer.approvals().decide(&record.approval_id, |record| {
                if record.status == "pending" && record.untrusted_reason_text.is_none() {
                    record.untrusted_reason_text = input.reason;
                }
                Ok(())
            })?.ok_or_else(|| invalid("approval unavailable"))
        }).await.map_err(|_| invalid("pending action unavailable"))??;
        let mut event = event(&record, "agent.operator_action_requested", "Operator preview requested");
        event.approval = Some(crate::audit::Approval {
            required: record.status == "pending",
            approval_type: crate::audit::ApprovalType::DesktopPresent,
            key: record.approval_id.clone(), target: format!("desktop:{}", agent.id),
            scope_hint: json!({"agent_id":agent.id}).into(),
        });
        event.details = json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
            "action_id":DESKTOP_PRESENT,"validated_action":record.authority.action,
            "untrusted_reason_text":record.untrusted_reason_text}).into();
        let mut view = agent_view(&record);
        if writer.emit_confirmed(event).await.is_err() {
            view["audit_status"] = json!("unavailable; the canonical pending request is saved");
        }
        Ok(view)
    }).await
}

fn event(record: &pending::Record, name: &'static str, summary: &str) -> Event {
    let from_agent = name == "agent.operator_action_requested";
    let mut event = Event::new(
        name,
        if from_agent { Kind::Agent } else { Kind::Admin },
        Severity::High,
        summary,
    );
    event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
    event.request_id = Some(record.request_id.clone());
    event.attribution = Some(crate::audit::Attribution {
        evidence_owner: event.agent.clone(),
        trusted_transport_identity: from_agent.then(|| event.agent.clone()).flatten(),
        initiator: Some(if from_agent {
            crate::audit::Initiator::Agent
        } else {
            crate::audit::Initiator::Operator
        }),
        status: Some(crate::audit::AttributionStatus::Resolved),
        provenance: None,
    });
    event.details =
        json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
        "action_id":DESKTOP_PRESENT,"status":record.status,"result":record.result})
        .into();
    event
}

/// Called by the existing process-owned approval mutation path. Commit the
/// decision before the side effect. A retry reads the saved outcome and never
/// replays an effect whose completion was interrupted.
pub(crate) fn resolve(
    state: &RuntimeState,
    writer: &Writer,
    id: &str,
    decision: Decision,
    option: Option<&str>,
) -> Result<(u16, Value)> {
    let path = config_path(state)?;
    let mut execute = false;
    let mut decided = false;
    let record = writer
        .approvals()
        .decide(id, |record| {
            if record.status != "pending" {
                return Ok(());
            }
            let policy = state
                .read()
                .map_err(|_| invalid("runtime unavailable"))?
                .policy
                .clone()
                .ok_or_else(|| invalid("policy unavailable"))?;
            let current = pending::current_view(writer, &policy, record, Some(state))?;
            if current["status"] != "pending" {
                record.status = current["status"].as_str().unwrap_or("superseded").into();
                return Ok(());
            }
            if matches!(decision, Decision::Reject) {
                record.status = "rejected".into();
                record.result = json!({"status":"denied","permission_changed":false});
            } else {
                let selected = record
                    .authority
                    .selected_option(option)
                    .ok_or_else(|| invalid("select this action's once option"))?;
                record.option = Some(selected.id.clone());
                record.status = "approved".into();
                record.result = json!({"status":"starting","execution_session_id":writer.approvals().session_id,"permission_changed":false});
                execute = true;
            }
            decided = true;
            Ok(())
        })?
        .ok_or_else(|| invalid("approval unavailable"))?;
    let handle = tokio::runtime::Handle::current();
    let mut operator_preview = None;
    let mut audit_unavailable = false;
    if decided {
        audit_unavailable = handle
            .block_on(writer.emit_confirmed(event(
                &record,
                "admin.approval_decided",
                "Operator preview decision saved",
            )))
            .is_err();
    }
    if execute {
        let parameters: Parameters =
            serde_json::from_value(record.authority.action["parameters"].clone())
                .map_err(|_| invalid("saved preview parameters unavailable"))?;
        let route: Route = serde_json::from_value(record.authority.action["presentation"].clone())
            .map_err(|_| invalid("saved presentation unavailable"))?;
        let agent_id = record.authority.action["agent_id"]
            .as_str()
            .ok_or_else(|| invalid("saved target unavailable"))?;
        let result = handle.block_on(host_platform::in_config(
            path,
            desktop_present::present_action(agent_id, &parameters, route, &record.approval_id),
        ));
        let result = match result {
            Ok(value) => {
                let result = json!({"status":"started","presentation":route,"reused":value["reused"],"expires_at":value["expires_at"],"permission_changed":false});
                operator_preview = Some(value);
                result
            }
            Err(error) => {
                json!({"status":"failed","diagnostic":error.json(),"permission_changed":false})
            }
        };
        let record = writer
            .approvals()
            .decide(id, |record| {
                record.result = result;
                Ok(())
            })?
            .ok_or_else(|| {
                invalid("action result unavailable; inspect the preview before requesting again")
            })?;
        audit_unavailable |= handle
            .block_on(writer.emit_confirmed(event(
                &record,
                "admin.operator_action_result",
                "Operator preview action completed",
            )))
            .is_err();
    }
    let record = writer
        .approvals()
        .get(id)?
        .ok_or_else(|| invalid("action unavailable"))?;
    let policy = state
        .read()
        .map_err(|_| invalid("runtime unavailable"))?
        .policy
        .clone()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let mut view = pending::current_view(writer, &policy, &record, Some(state))?;
    if let Some(presentation) = operator_preview {
        view["operator_preview"] = presentation;
    }
    if audit_unavailable {
        view["audit_status"] = json!("unavailable; the canonical decision and result are saved");
    }
    Ok((
        if matches!(record.status.as_str(), "expired" | "superseded") {
            409
        } else {
            200
        },
        view,
    ))
}
