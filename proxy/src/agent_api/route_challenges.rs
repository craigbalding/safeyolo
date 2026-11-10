//! Explicit escalation references host authority; caller prose cannot replace it.

use super::{Outcome, Request, RequestBody, response};
use crate::{
    approvals::pending::{self, route_challenge},
    audit::{Approval, ApprovalType, Decision, Event, Kind, Severity},
    policy::Policy,
};
use bytes::Bytes;
use hyper::body::Body;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Escalation {
    context: pending::context::Fields,
    source: String,
}

pub(super) async fn respond<B>(
    request: Request<'_>,
    policy: &Policy,
    state: Option<&crate::RuntimeState>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Some(run) = request.identity.run().filter(|run| run.current(policy)) else {
        return Ok(response(
            403,
            json!({"error":"trusted current-run identity required"}),
        ));
    };
    let Some(state) = state else {
        return Ok(response(503, json!({"error":"gateway unavailable"})));
    };
    let suffix = super::route(request)
        .strip_prefix("/gateway/challenges/")
        .unwrap_or("");
    let (id, escalate) = suffix
        .strip_suffix("/escalate")
        .map_or((suffix, false), |id| (id, true));
    if id.contains('/') || !pending::valid_id(id) {
        return Ok(response(404, json!({"error":"challenge unavailable"})));
    }
    if (escalate && request.method != "POST") || (!escalate && request.method != "GET") {
        return Ok(response(405, json!({"error":"Method Not Allowed"})));
    }
    let input = if escalate {
        let content = match super::declarations::read_content(body).await? {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        let input = match serde_json::from_slice::<Escalation>(&content) {
            Ok(input)
                if input.context.validate().is_ok()
                    && !input.source.trim().is_empty()
                    && input.source.len() <= pending::context::MAX_FIELD_BYTES
                    && !input.context.task.trim().is_empty()
                    && !input.context.fallback.trim().is_empty() =>
            {
                input
            }
            _ => {
                return Ok(response(
                    400,
                    json!({"error":"supply context with task, reason and fallback (why alternatives are insufficient), and source context distinguishing direct request, inference or untrusted content; each field is limited to 2048 UTF-8 bytes; scope overrides are not accepted"}),
                ));
            }
        };
        Some(input)
    } else {
        None
    };
    let runtime = match state.read() {
        Ok(runtime) => runtime.clone(),
        Err(_) => return Ok(response(503, json!({"error":"gateway unavailable"}))),
    };
    let (state, run, id) = (state.clone(), run.clone(), id.to_owned());
    let runtime_owned = runtime.clone();
    let result = tokio::task::spawn_blocking(
        move || -> crate::approvals::Result<Option<(pending::Record, serde_json::Value, bool)>> {
            let runtime = runtime_owned;
            let policy = runtime
                .policy
                .as_ref()
                .ok_or_else(|| crate::approvals::invalid("policy unavailable"))?;
            let Some(record) = pending::lookup(&runtime.audit, &id)?.filter(|record| {
                route_challenge::is_exception(record)
                    && record.authority.action["run"] == json!(run)
            }) else {
                return Ok(None);
            };
            let mut transitioned = false;
            if let Some(input) = input {
                runtime.audit.approvals().decide(&id, |current| {
                    if current.current_status(policy)? != "challenged" {
                        return Ok(());
                    }
                    if !pending::check_saved(
                        &state,
                        &std::fs::read_to_string(
                            runtime
                                .config
                                .policy_file
                                .as_ref()
                                .ok_or_else(|| crate::approvals::invalid("policy unavailable"))?,
                        )
                        .map_err(|_| crate::approvals::invalid("saved policy unavailable"))?,
                        current,
                    )? {
                        current.status = "superseded".into();
                        return Ok(());
                    }
                    current.untrusted_reason_text =
                        Some(json!({"source":input.source,"context":input.context}).to_string());
                    current.status = "pending".into();
                    transitioned = true;
                    Ok(())
                })?;
            }
            let record = runtime
                .audit
                .approvals()
                .get(&record.approval_id)?
                .ok_or_else(|| crate::approvals::invalid("challenge unavailable"))?;
            let view = pending::current_view(&runtime.audit, policy, &record, Some(&state))?;
            Ok(Some((record, view, transitioned)))
        },
    )
    .await;
    match result {
        Ok(Ok(Some((record, view, transitioned)))) => {
            if escalate && record.status == "pending" {
                let mut event = Event::new(
                    "gateway.route_escalated",
                    Kind::Gateway,
                    Severity::High,
                    "Agent explicitly escalated a service route challenge",
                );
                event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
                event.host = record.authority.action["host"].as_str().map(str::to_owned);
                event.request_id = Some(request.request_id.into());
                event.decision = Some(Decision::RequireApproval);
                event.approval = Some(Approval {required:true,approval_type:ApprovalType::GatewayRoute,key:record.approval_id.clone(),target:record.authority.action["service"].as_str().unwrap_or("").into(),scope_hint:json!({"method":record.authority.method,"path":record.authority.action["path"]}).into()});
                event.details = json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,"transitioned":transitioned}).into();
                if runtime.audit.emit_confirmed(event).await.is_err() {
                    return Ok(response(
                        503,
                        json!({"error":"escalation audit unavailable; inspect the canonical challenge before retrying"}),
                    ));
                }
                pending::delegation::notify(&runtime, &record).await;
            }
            Ok(response(
                if escalate && view["status"] == "pending" {
                    202
                } else {
                    200
                },
                view,
            ))
        }
        Ok(Ok(None)) => Ok(response(
            404,
            json!({"error":"challenge unavailable for this run"}),
        )),
        _ => Ok(response(
            503,
            json!({"error":"challenge state unavailable; inspect before retrying"}),
        )),
    }
}
