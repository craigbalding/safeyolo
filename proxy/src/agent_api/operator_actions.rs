//! Typed action requests share Agent API authentication and listener identity.

use bytes::Bytes;
use hyper::body::Body;
use serde_json::json;
use std::sync::Arc;

use super::{Outcome, Request, RequestBody, agent, response};
use crate::{audit::Writer, operator_actions, policy::Policy};

pub(super) async fn respond<B>(
    request: Request<'_>,
    policy: &Policy,
    state: Option<&crate::RuntimeState>,
    writer: Option<&Arc<Writer>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Some(caller) = agent(request.identity) else {
        return Ok(response(403, json!({"error":"Could not identify agent"})));
    };
    let (Some(state), Some(writer)) = (state, writer.filter(|writer| writer.approvals_enabled()))
    else {
        return Ok(response(
            503,
            json!({"error":"operator actions unavailable"}),
        ));
    };
    let path = super::route(request);
    if path == "/operator-actions" && request.method == "GET" {
        return Ok(
            match operator_actions::discover(state, policy, caller).await {
                Ok(value) => response(200, value),
                Err(_) => response(
                    503,
                    json!({"error":"operator action discovery unavailable for this requester"}),
                ),
            },
        );
    }
    if let Some(id) = path.strip_prefix("/operator-actions/") {
        if request.method != "GET" {
            return Ok(response(405, json!({"error":"Method Not Allowed"})));
        }
        if !crate::approvals::pending::valid_id(id) || id.contains('/') {
            return Ok(response(404, json!({"error":"action unavailable"})));
        }
        let (writer, policy, caller, id, state) = (
            writer.clone(),
            policy.clone(),
            caller.to_owned(),
            id.to_owned(),
            state.clone(),
        );
        return Ok(
            match tokio::task::spawn_blocking(move || {
                let record = match crate::approvals::pending::lookup(&writer, &id) {
                    Ok(record) => record,
                    Err(_) => return response(503, json!({"error":"action state unavailable"})),
                }
                .filter(|record| {
                    record.authority.action["kind"] == "operator_action"
                        && crate::approvals::pending::context::owner(&policy, record, &caller)
                });
                match record {
                    Some(mut record) => {
                        let view = crate::approvals::pending::current_view(
                            &writer,
                            &policy,
                            &record,
                            Some(&state),
                        );
                        match view {
                            Ok(view) => {
                                record.status =
                                    view["status"].as_str().unwrap_or("unavailable").into();
                                record.result = view["result"].clone();
                                response(200, operator_actions::agent_view(&record))
                            }
                            Err(_) => response(503, json!({"error":"action state unavailable"})),
                        }
                    }
                    None => response(404, json!({"error":"action unavailable"})),
                }
            })
            .await
            {
                Ok(value) => value,
                Err(_) => response(503, json!({"error":"action state unavailable"})),
            },
        );
    }
    if path != "/operator-actions" {
        return Ok(response(404, json!({"error":"action unavailable"})));
    }
    if request.method != "POST" {
        return Ok(response(405, json!({"error":"Method Not Allowed"})));
    }
    let content = match super::declarations::read_content(body).await? {
        Ok(content) => content,
        Err(error) => return Ok(super::declarations::content_error(error)),
    };
    let input = match serde_json::from_slice::<operator_actions::Request>(&content) {
        Ok(input) => input,
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"supply action_id, typed parameters and optional untrusted reason only"}),
            ));
        }
    };
    Ok(
        match operator_actions::request(state, writer, policy, caller, request.request_id, input)
            .await
        {
            Ok(value) => response(
                if value["status"] == "unavailable" {
                    409
                } else {
                    202
                },
                value,
            ),
            Err(error) => response(
                if error.kind == crate::approvals::ErrorKind::Io {
                    503
                } else {
                    400
                },
                json!({"error":error.to_string()}),
            ),
        },
    )
}
