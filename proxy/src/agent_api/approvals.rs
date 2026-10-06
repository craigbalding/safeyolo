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
    (!id.contains('/') && super::valid_request_id(id)).then_some((id, prepare))
}

pub(super) async fn read(
    request: Request<'_>,
    writer: Option<&Arc<Writer>>,
    policy: &Policy,
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
    let (writer, policy, caller, id) = (
        writer.clone(),
        policy.clone(),
        caller.to_owned(),
        id.to_owned(),
    );
    match tokio::task::spawn_blocking(move || {
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
    policy: &Policy,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Some((id, prepare)) = request_id(super::route(request)) else {
        return Ok(response(404, json!({"error":"approval unavailable"})));
    };
    if !prepare && request.method == "GET" {
        return Ok(read(request, writer, policy, id, Read::Approval).await);
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
        policy.clone(),
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
