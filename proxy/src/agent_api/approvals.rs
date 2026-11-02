//! Helper preparation has selected read authority and no operator credential.

use bytes::Bytes;
use hyper::body::Body;
use serde_json::json;
use std::sync::Arc;

use super::{Outcome, Request, RequestBody, agent, response};
use crate::{
    approvals::network_action,
    audit::Writer,
    policy::{Policy, evidence::Read},
};

pub(super) fn request_id(path: &str) -> Option<(&str, bool)> {
    let suffix = path.strip_prefix("/approvals/")?;
    let (id, prepare) = suffix
        .strip_suffix("/prepare")
        .map_or((suffix, false), |id| (id, true));
    (!id.contains('/') && crate::approvals::pending::valid_id(id)).then_some((id, prepare))
}

pub(super) async fn read(
    request: Request<'_>,
    writer: Option<&Arc<Writer>>,
    policy: &Arc<Policy>,
    state: Option<&crate::RuntimeState>,
    id: &str,
    read: Read,
) -> Outcome<'static> {
    let Some(caller) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let Some(writer) = writer else {
        return response(
            503,
            json!({"error":"evidence unavailable; direct operator controls remain available"}),
        );
    };
    let (writer, policy, state, caller, id) = (
        writer.clone(),
        Arc::clone(policy),
        state.cloned(),
        caller.to_owned(),
        id.to_owned(),
    );
    match tokio::task::spawn_blocking(move || {
        match crate::approvals::pending::lookup(&writer, &id) {
            Ok(Some(record)) => {
                let action = &record.authority.action;
                let owner = action["agent"].as_str().unwrap_or("");
                if policy.evidence_agent_id(owner) != action["agent_id"].as_str()
                    || (caller != owner && policy.evidence_reader(&caller, &id, read).as_deref() != Some(owner)) {
                    return response(404, json!({"error":"selected evidence unavailable or not granted"}));
                }
                return match crate::approvals::pending::current_view(&writer, &policy, &record, state.as_ref()) {
                    Ok(mut view) => {
                        if let Some(fields) = view.as_object_mut() { fields.shift_remove("untrusted_reason_text"); fields.shift_remove("details"); }
                        if read == Read::Diagnostic { view["diagnostic"] = json!({"decision":"require_approval","agent":action["agent"],"host":action["host"],"port":action["port"]}); }
                        response(200, view)
                    }
                    Err(_) => response(503, json!({"error":"approval state unavailable"})),
                };
            }
            Ok(None) => {},
            Err(_) => return response(503, json!({"error":"approval state unavailable"})),
        }
        match network_action::record(&writer, &policy, &id) {
            Ok(Some(record)) if record.readable(&policy, &caller, &id, read) => {
                let mut value = record.view(&id, false);
                if read == Read::Diagnostic { value["diagnostic"] = json!({"decision":"require_approval","agent":record.action.agent,"host":record.action.host,"port":record.action.port}); }
                response(200, value)
            }
            Ok(_) => response(404, json!({"error":"selected evidence unavailable or not granted"})),
            Err(_) => response(503, json!({"error":"evidence unavailable; direct operator controls remain available"})),
        }
    }).await {
        Ok(outcome) => outcome,
        Err(_) => response(503, json!({"error":"evidence unavailable"})),
    }
}

pub(super) async fn respond<B>(
    request: Request<'_>,
    writer: Option<&Arc<Writer>>,
    policy: &Arc<Policy>,
    state: Option<&crate::RuntimeState>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let path = super::route(request);
    let reviewing = request.identity.run().is_some_and(|run| {
        policy.delegations().values().any(|d| {
            d.reviewers
                .iter()
                .any(|reviewer| reviewer.name == run.agent && reviewer.agent_id == run.agent_id)
        })
    });
    if path == "/approvals"
        || path.ends_with("/resolve")
        || (reviewing && request.method == "GET" && !path.ends_with("/context"))
    {
        let (Some(writer), Some(state)) = (writer, state) else {
            return Ok(response(
                503,
                json!({"error":"approval state unavailable; operator controls remain available"}),
            ));
        };
        return delegated(request, writer, state, policy, body).await;
    }
    if let Some(id) = super::route(request)
        .strip_prefix("/approvals/")
        .and_then(|path| path.strip_suffix("/context"))
        .filter(|id| !id.contains('/') && crate::approvals::pending::valid_id(id))
    {
        return context(request, writer, policy, state, body, id).await;
    }
    let Some((id, prepare)) = request_id(super::route(request)) else {
        return Ok(response(404, json!({"error":"approval unavailable"})));
    };
    if !prepare && request.method == "GET" {
        return Ok(read(request, writer, policy, state, id, Read::Approval).await);
    }
    if !prepare || request.method != "POST" {
        return Ok(response(405, json!({"error":"Method Not Allowed"})));
    }
    let Some(caller) = agent(request.identity) else {
        return Ok(response(403, json!({"error":"Could not identify agent"})));
    };
    if policy.evidence_reader(caller, id, Read::Approval).is_none() {
        return Ok(response(
            403,
            json!({"error":"selected approval read is not granted"}),
        ));
    }
    let Some(writer) = writer else {
        return Ok(response(503, json!({"error":"evidence unavailable"})));
    };
    let content = match super::declarations::read_content(body).await? {
        Ok(content) => content,
        Err(error) => return Ok(super::declarations::content_error(error)),
    };
    let Ok(input) = serde_json::from_slice::<network_action::Preparation>(&content) else {
        return Ok(response(
            400,
            json!({"error":"expected the exact typed network action and an untrusted reason; executable/argv and identity overrides are not supported"}),
        ));
    };
    let (work_writer, policy, caller, work_id) = (
        writer.clone(),
        Arc::clone(policy),
        caller.to_owned(),
        id.to_owned(),
    );
    let prepared = tokio::task::spawn_blocking(move || {
        network_action::prepare(&work_writer, &policy, &caller, &work_id, input)
    })
    .await;
    let event = match prepared {
        Ok(Ok(event)) => event,
        _ => {
            return Ok(response(
                409,
                json!({"error":"action changed, resolved, stale or unavailable; read canonical state"}),
            ));
        }
    };
    if writer.emit_confirmed(event).await.is_err() {
        return Ok(response(
            503,
            json!({"error":"preparation evidence unavailable; no permission was granted"}),
        ));
    }
    Ok(response(
        202,
        json!({"request_id":id,"status":"pending","message":"Prepared for the human operator; no permission was granted."}),
    ))
}

async fn context<B>(
    request: Request<'_>,
    writer: Option<&Arc<Writer>>,
    policy: &Arc<Policy>,
    state: Option<&crate::RuntimeState>,
    body: RequestBody<'_, B>,
    id: &str,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    use crate::approvals::pending::{self, context};
    let Some(caller) = agent(request.identity) else {
        return Ok(response(403, json!({"error":"Could not identify agent"})));
    };
    let Some(writer) = writer else {
        return Ok(response(
            503,
            json!({"error":"context unavailable; ordinary decisions remain available"}),
        ));
    };
    if !matches!(request.method, "GET" | "POST") {
        return Ok(response(405, json!({"error":"Method Not Allowed"})));
    }
    let (writer, policy, state, caller, id) = (
        writer.clone(),
        Arc::clone(policy),
        state.cloned(),
        caller.to_owned(),
        id.to_owned(),
    );
    let (work_writer, work_policy, work_caller, work_id) =
        (writer.clone(), policy.clone(), caller.clone(), id.clone());
    let authorized = tokio::task::spawn_blocking(move || {
        pending::lookup(&work_writer, &work_id).map(|record| {
            record.filter(|record| context::owner(&work_policy, record, &work_caller))
        })
    })
    .await;
    let record = match authorized {
        Ok(Ok(Some(record))) => record,
        Ok(Ok(None)) => return Ok(response(404, json!({"error":"context unavailable"}))),
        _ => return Ok(response(503, json!({"error":"context unavailable"}))),
    };
    if request.method == "POST" {
        let content = match read_context(body).await? {
            Ok(content) => content,
            Err(outcome) => return Ok(outcome),
        };
        let Ok(input) = serde_json::from_slice::<context::Answer>(&content) else {
            return Ok(response(
                400,
                json!({"error":"supply context_id and context fields task, reason, next_step, fallback only; authority and sender come from SafeYolo"}),
            ));
        };
        if input.context.validate().is_err() {
            return Ok(response(
                400,
                json!({"error":"reason must be nonempty; each context field is limited to 2048 UTF-8 bytes"}),
            ));
        }
        let (work_writer, work_policy, work_state, work_id) =
            (writer.clone(), policy.clone(), state.clone(), id.clone());
        match tokio::task::spawn_blocking(move || {
            context::answer(
                &work_writer,
                &work_policy,
                work_state.as_ref(),
                &work_id,
                &caller,
                input,
            )
        })
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Ok(response(
                    if error.kind == crate::approvals::ErrorKind::Io {
                        503
                    } else {
                        409
                    },
                    json!({"error":error.to_string()}),
                ));
            }
            _ => {
                return Ok(response(
                    503,
                    json!({"error":"context write unavailable; read context before retrying"}),
                ));
            }
        }
    }
    let work_writer = writer.clone();
    let work_record = record.clone();
    let value = match tokio::task::spawn_blocking(move || {
        context::view(&work_writer, &policy, &work_record, state.as_ref())
    })
    .await
    {
        Ok(Ok(value)) => value,
        _ => return Ok(response(503, json!({"error":"context unavailable"}))),
    };
    if request.method == "POST"
        && writer
            .emit_confirmed(context::event(&record, &value, true))
            .await
            .is_err()
    {
        return Ok(response(
            503,
            json!({"error":"context audit unavailable; read context before retrying; approval is unchanged"}),
        ));
    }
    Ok(response(200, value))
}

async fn read_context<B>(
    mut body: RequestBody<'_, B>,
) -> Result<Result<zeroize::Zeroizing<Vec<u8>>, Outcome<'static>>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    use http_body_util::BodyExt;
    // Four 2048-byte fields can expand sixfold under JSON escaping.
    const LIMIT: usize = 52 * 1024;
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    let mut encoded_size = 0u64;
    while let Some(frame) = body.body.frame().await {
        if let Ok(data) = frame?.into_data() {
            encoded_size = encoded_size.saturating_add(data.len() as u64);
            if encoded_size <= LIMIT as u64 {
                encoded.extend_from_slice(&data);
            }
        }
    }
    if encoded_size > LIMIT as u64 {
        return Ok(Err(response(
            413,
            json!({"error":"context response is too large"}),
        )));
    }
    let decoded = match crate::http_content::decode_prefix_with_size(
        &encoded,
        body.content_encoding,
        LIMIT,
    ) {
        Ok(decoded) => decoded,
        Err(error) => return Ok(Err(super::declarations::content_error(error))),
    };
    if let Some(observation) = body.observation.as_deref_mut() {
        observation.encoded_size = Some(encoded_size);
        observation.decoded_size = Some(Ok(decoded.total_bytes as u64));
    }
    if decoded.total_bytes > LIMIT {
        return Ok(Err(response(
            413,
            json!({"error":"context response is too large"}),
        )));
    }
    Ok(Ok(decoded.content))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewDecision {
    decision: String,
    delegation: String,
    option: String,
}

async fn delegated<B: Body<Data = Bytes> + Unpin>(
    request: Request<'_>,
    writer: &Arc<Writer>,
    state: &crate::RuntimeState,
    policy: &Arc<Policy>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error> {
    use crate::approvals::pending::{self, delegation};
    let Some(reviewer) = request.identity.run().filter(|run| run.current(policy)) else {
        return Ok(response(
            403,
            json!({"error":"trusted current-run reviewer identity required"}),
        ));
    };
    let path = super::route(request);
    if path == "/approvals" && request.method == "GET" {
        let (writer, policy, state, reviewer) = (
            writer.clone(),
            Arc::clone(policy),
            state.clone(),
            reviewer.clone(),
        );
        return Ok(
            match tokio::task::spawn_blocking(move || -> crate::approvals::Result<_> {
                let mut views = vec![];
                for record in writer.approvals().list()? {
                    if !delegation::eligible(&policy, &record, &reviewer).is_empty()
                        && pending::current_view(&writer, &policy, &record, Some(&state))?["status"]
                            == "pending"
                    {
                        views.push(delegation::view(
                            &writer, &policy, &record, &state, &reviewer,
                        )?);
                    }
                }
                Ok(json!({"approvals":views}))
            })
            .await
            {
                Ok(Ok(value)) => response(200, value),
                _ => response(
                    503,
                    json!({"error":"approval state unavailable; operator controls remain available"}),
                ),
            },
        );
    }
    let suffix = path.strip_prefix("/approvals/").unwrap_or("");
    let (id, resolve) = suffix
        .strip_suffix("/resolve")
        .map_or((suffix, false), |id| (id, true));
    if id.contains('/') || !pending::valid_id(id) {
        return Ok(response(404, json!({"error":"approval unavailable"})));
    }
    if !resolve && request.method == "GET" {
        let (writer, policy, state, reviewer, id) = (
            writer.clone(),
            Arc::clone(policy),
            state.clone(),
            reviewer.clone(),
            id.to_owned(),
        );
        return Ok(
            match tokio::task::spawn_blocking(move || -> crate::approvals::Result<_> {
                let record = pending::lookup(&writer, &id)?
                    .ok_or_else(|| crate::approvals::invalid("approval unavailable"))?;
                delegation::view(&writer, &policy, &record, &state, &reviewer)
            })
            .await
            {
                Ok(Ok(value)) => response(200, value),
                Ok(Err(e)) if e.kind == crate::approvals::ErrorKind::Invalid => {
                    response(404, json!({"error":"approval unavailable"}))
                }
                _ => response(503, json!({"error":"approval state unavailable"})),
            },
        );
    }
    if !resolve || request.method != "POST" {
        return Ok(response(405, json!({"error":"Method Not Allowed"})));
    }
    let content = match super::declarations::read_content(body).await? {
        Ok(value) => value,
        Err(error) => return Ok(super::declarations::content_error(error)),
    };
    let Ok(input) = serde_json::from_slice::<ReviewDecision>(&content) else {
        return Ok(response(
            400,
            json!({"error":"supply only decision, delegation and a host-generated option"}),
        ));
    };
    if !matches!(input.decision.as_str(), "approve" | "reject" | "defer") {
        return Ok(response(
            400,
            json!({"error":"decision must be approve, reject or defer"}),
        ));
    }
    let owner = match state.read() {
        Ok(runtime) => runtime.service_mutations.clone(),
        _ => return Ok(response(503, json!({"error":"mutation owner unavailable"}))),
    };
    let (writer, state, reviewer, id) = (
        writer.clone(),
        state.clone(),
        reviewer.clone(),
        id.to_owned(),
    );
    let result=owner.spawn_blocking(move || {
        let execute=|| -> crate::approvals::Result<(u16,serde_json::Value)> {
            if input.decision=="defer" {
                let policy=state.read().map_err(|_| crate::approvals::invalid("runtime unavailable"))?.policy.clone().ok_or_else(||crate::approvals::invalid("policy unavailable"))?;
                let record=pending::lookup(&writer,&id)?.ok_or_else(||crate::approvals::invalid("approval unavailable"))?;
                delegation::authorize(&policy,&record,&reviewer,&input.delegation,&input.option)?;
                return Ok((200,json!({"approval_id":record.approval_id,"status":record.current_status(&policy)?,"permission_changed":false})));
            }
            let decision=if input.decision=="approve" {crate::approvals::network_action::Decision::Approve} else {crate::approvals::network_action::Decision::Reject};
            let (status,value)=pending::resolve_as(&state,&writer,&id,decision,Some(&input.option),Some((&reviewer,&input.delegation)))?.ok_or_else(||crate::approvals::invalid("approval unavailable"))?;
            // Never return the operator projection, which can contain secret
            // URL path values. Read the authorized trusted projection anew.
            Ok((status,json!({"approval_id":value["approval_id"],"status":value["status"],"option":value["option"],"authority_digest":value["authority_digest"],"audit_status":value["audit_status"],"activation_status":value["activation_status"],"grant_active":value["grant_active"]})))
        };
        Ok(match execute() { Ok(value)=>value,Err(_)=>(409,json!({"error":"decision unavailable or authority changed; read the canonical approval before retrying"})) })
    }).await;
    Ok(match result {
        Ok(receiver) => match receiver.await {
            Ok(Ok((status, value))) => response(status, value),
            _ => response(
                503,
                json!({"error":"decision outcome unknown; inspect canonical state before retrying"}),
            ),
        },
        Err(_) => response(
            503,
            json!({"error":"decision owner unavailable; operator controls remain available"}),
        ),
    })
}
