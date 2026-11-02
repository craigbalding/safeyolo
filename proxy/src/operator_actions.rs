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

pub(crate) fn config_path(state: &RuntimeState) -> Result<PathBuf> {
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

pub(crate) fn configuration_current(state: &RuntimeState, action: &Value) -> bool {
    config_path(state).ok().is_some_and(|path| {
        host_platform::with_config(path, || {
            desktop_present::configuration_revision()
                .is_ok_and(|revision| action["configuration_revision"] == revision)
        })
    })
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
                "Remove only this approval source when its finite lifetime expires; independent sources can preserve access."],
            "non_grants":["No change to network policy, service grants or credentials.","No public or Funnel exposure."]}]}))
    }).await
}

pub(crate) fn agent_view(record: &pending::Record) -> Value {
    json!({"action_id":DESKTOP_PRESENT,"action_request_id":record.approval_id,
        "approval_id":record.approval_id,"request_id":record.request_id,
        "status":if record.status == "pending" {"pending_approval"} else {record.status.as_str()},
        "result":agent_result(&record.result)})
}

/// Project only nonsecret execution facts from the reconciled canonical result.
pub(crate) fn agent_result(result: &Value) -> Value {
    let expires_at = result
        .get("expires_at")
        .unwrap_or(&result["issued_access"]["expires_at"]);
    let mut view = json!({"status":result["status"],"presentation":result["presentation"],
        "preview_active":result["preview_active"],"reused":result["reused"],
        "expires_at":expires_at,"diagnostic":result["diagnostic"]});
    if result["status"] == "started"
        && expires_at
            .as_str()
            .and_then(crate::policy::parse_expiry)
            .is_some_and(|expiry| time::OffsetDateTime::now_utc() >= expiry)
    {
        view["status"] = json!("expired");
    }
    view
}

pub(crate) async fn request(
    state: &RuntimeState,
    writer: &Arc<Writer>,
    policy: &Policy,
    caller: &str,
    run: &crate::host_runs::AgentRun,
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
        if !run.current(policy) || run.agent != caller || run.agent_id != agent.id {
            return Err(invalid("trusted current-run requester identity required"));
        }
        let route = match desktop_present::action_prerequisites(&agent.name).await {
            Ok(route) => route,
            Err(error) => return Ok(json!({"action_id":DESKTOP_PRESENT,"status":"unavailable","diagnostic":error.json()})),
        };
        let action = json!({"kind":"operator_action","action_id":DESKTOP_PRESENT,"agent":agent.name,
            "instance_id":desktop_present::instance_id().map_err(|_| invalid("desktop instance unavailable"))?,
            "agent_id":agent.id,"run":run,"parameters":input.parameters,"presentation":route,
            "configuration_revision":desktop_present::configuration_revision().map_err(|_| invalid("host desktop configuration unavailable"))?});
        let effect = format!("Present this exact worker run's managed desktop through the {} path once. {}Add a separate preview authority source for at most {} seconds. Independent preview sources remain. If no valid source remains, refuse future access and disconnect viewers on the next authority check. Browser opening and disclosed content cannot be undone. Network and service permissions stay unchanged.",
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
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?.clone();
        pending::delegation::notify(&runtime, &record).await;
        Ok(view)
    }).await
}

fn event(record: &pending::Record, name: &'static str, summary: &str) -> Event {
    let from_agent = name == "agent.operator_action_requested";
    let reviewer = record.result["issued_access"]["reviewer"]["name"]
        .as_str()
        .or_else(|| record.result["decided_by"]["name"].as_str())
        .filter(|name| *name != "operator");
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
        trusted_transport_identity: reviewer
            .map(str::to_owned)
            .or_else(|| from_agent.then(|| event.agent.clone()).flatten()),
        initiator: Some(if from_agent || reviewer.is_some() {
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
    reviewer: Option<(&crate::host_runs::AgentRun, &str)>,
) -> Result<(u16, Value)> {
    let path = config_path(state)?;
    let mut execute = false;
    let mut decided = false;
    let record = writer
        .approvals()
        .decide(id, |record| {
            let policy = state
                .read()
                .map_err(|_| invalid("runtime unavailable"))?
                .policy
                .clone()
                .ok_or_else(|| invalid("policy unavailable"))?;
            let delegated = reviewer.map(|(run, name)| pending::delegation::authorize(&policy, record, run, name, option.unwrap_or("once"))).transpose()?;
            if record.status != "pending" { return Ok(()); }
            let current = pending::current_view(writer, &policy, record, Some(state))?;
            if current["status"] != "pending" {
                record.status = current["status"].as_str().unwrap_or("superseded").into();
                if record.status == "approved" {
                    // A committed policy receipt with a missing canonical save
                    // is recovery evidence, never permission to replay an effect.
                    record.option = current["option"].as_str().map(str::to_owned);
                    record.result = current["result"].clone();
                    record.result["status"] = json!("outcome_unknown");
                    record.result["diagnostic"] = json!({"code":"preview_execution_interrupted","message":"Inspect the preview and guest before a new request. SafeYolo did not replay the recovered decision.","graph":"triage-desktop-preview"});
                }
                return Ok(());
            }
            let issued = if let Some(issued) = delegated { issued } else {
                pending::delegation::issue(&policy, record, "", None, option.unwrap_or("once"))?
            };

            if matches!(decision, Decision::Reject) {
                record.status = "rejected".into();
                record.result = json!({"status":"denied","decided_by":issued.reviewer,"delegation":issued.delegation,"delegation_revision":issued.delegation_revision});
            } else {
                let selected = record
                    .authority
                    .selected_option(option)
                    .ok_or_else(|| invalid("select this action's once option"))?;
                record.option = Some(selected.id.clone());
                record.status = "approved".into();
                record.result = json!({"status":"starting","execution_session_id":writer.approvals().session_id,"issued_access":issued});
                let policy_path=state.read().map_err(|_| invalid("runtime unavailable"))?.config.policy_file.clone().ok_or_else(|| invalid("policy path unavailable"))?;
                crate::edit_native_policy(state,true, |source| {
                    let saved=policy.reload_native_source(source,&policy_path).map_err(|e| invalid(e.to_string()))?;
                    if !issued.active_snapshot(&saved) || !configuration_current(state,&issued.action) {
                        return Err(invalid("preview authority changed before activation"));
                    }
                    let (mut document,context)=crate::policy::parse_toml_for_edit(source).map_err(|e| invalid(e.to_string()))?;
                    document["agents"][&issued.beneficiary.agent]["desktop_grants"][&record.approval_id]=toml_edit::value(serde_json::to_string(&issued).map_err(|_| invalid("preview source encoding unavailable"))?);
                    pending::save_receipt(&mut document,record)?;
                    Ok(((),crate::policy::restore_large_toml_integers(&document.to_string(),&context)))
                }).map_err(|e| invalid(e.to_string()))?;
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
        let issued: crate::policy::delegation::IssuedAccess =
            serde_json::from_value(record.result["issued_access"].clone())
                .map_err(|_| invalid("saved preview authority unavailable"))?;
        let authority = crate::desktop_preview::PreviewAuthority::Action {
            issued: Box::new(issued.clone()),
            state: state.clone(),
            store: writer.approvals().clone(),
        };
        let result = handle.block_on(host_platform::in_config(
            path,
            desktop_present::present_action(
                agent_id,
                &parameters,
                route,
                &record.approval_id,
                authority,
            ),
        ));
        let result = match result {
            Ok(value) => {
                let result = json!({"status":"started","presentation":route,"reused":value["reused"],"expires_at":issued.expires_at,"issued_access":issued});
                if reviewer.is_none() {
                    operator_preview = Some(value);
                }
                result
            }
            Err(error) => {
                json!({"status":"failed","diagnostic":error.json(),"issued_access":issued})
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
    if reviewer.is_none() && view["result"]["status"] == "started" {
        operator_preview = preview(state, &record, true);
    }
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

pub(crate) fn preview(
    state: &RuntimeState,
    record: &pending::Record,
    require_source: bool,
) -> Option<Value> {
    let path = config_path(state).ok()?;
    let agent_id = record.authority.action["agent_id"].as_str()?;
    tokio::runtime::Handle::current().block_on(host_platform::in_config(
        path,
        desktop_present::inspect(
            agent_id,
            require_source.then_some(record.approval_id.as_str()),
        ),
    ))
}
