//! Local, current-run authenticated policy disclosure. No host path is input.

use bytes::Bytes;
use hyper::body::Body;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use super::{Outcome, Request, RequestBody, response};
use crate::{approvals::pending::policy_snapshot, audit::Writer};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    operation_id: String,
}

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&crate::RuntimeState>,
    writer: Option<&Arc<Writer>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    // DOC: docs/policy-snapshots.md
    if request.path_and_query.contains('?') {
        return Ok(response(
            400,
            json!({"error":"policy snapshots select only the authenticated local instance; query selectors are not accepted"}),
        ));
    }
    let Some(run) = request.identity.run().cloned() else {
        return Ok(response(
            403,
            json!({"error":"trusted current-run requester identity required"}),
        ));
    };
    let (Some(state), Some(writer)) = (state, writer.filter(|writer| writer.approvals_enabled()))
    else {
        return Ok(response(
            503,
            json!({"error":"policy snapshot approval state unavailable"}),
        ));
    };
    let path = super::route(request);
    let (state, writer) = (state.clone(), writer.clone());
    if let Some(encoded_id) = path.strip_prefix("/policy/snapshots/") {
        if request.method != "GET" {
            return Ok(response(405, json!({"error":"Method Not Allowed"})));
        }
        let Ok(id) = percent_encoding::percent_decode_str(encoded_id).decode_utf8() else {
            return Ok(response(
                404,
                json!({"error":"snapshot request unavailable"}),
            ));
        };
        if !crate::approvals::pending::valid_id(&id) || id.contains('/') {
            return Ok(response(
                404,
                json!({"error":"snapshot request unavailable"}),
            ));
        }
        let id = id.into_owned();
        return Ok(
            match tokio::task::spawn_blocking(move || {
                policy_snapshot::read_snapshot(&state, &writer, &run, &id)
            })
            .await
            {
                Ok(Ok(Some(value))) => response(200, value),
                Ok(Ok(None)) => response(404, json!({"error":"snapshot request unavailable"})),
                _ => response(
                    503,
                    json!({"error":"snapshot unavailable; reconcile the original request before retrying"}),
                ),
            },
        );
    }
    if request.method != "POST" {
        return Ok(response(405, json!({"error":"Method Not Allowed"})));
    }
    let content = match super::declarations::read_content(body).await? {
        Ok(content) => content,
        Err(error) => return Ok(super::declarations::content_error(error)),
    };
    let Ok(input) = serde_json::from_slice::<Submission>(&content) else {
        return Ok(response(
            400,
            json!({"error":"supply only operation_id; requester, instance and policy source come from SafeYolo"}),
        ));
    };
    let work_writer = writer.clone();
    let work_state = state.clone();
    let submitted = tokio::task::spawn_blocking(move || {
        let record =
            policy_snapshot::request(&work_state, &work_writer, &run, &input.operation_id)?;
        let policy = work_state
            .read()
            .map_err(|_| crate::approvals::invalid("runtime unavailable"))?
            .policy
            .clone()
            .ok_or_else(|| crate::approvals::invalid("policy unavailable"))?;
        let view =
            policy_snapshot::approval_view(&work_writer, &policy, &record, Some(&work_state))?;
        Ok::<_, crate::approvals::ApprovalError>((record, view))
    })
    .await;
    Ok(match submitted {
        Ok(Ok((record, mut view))) => {
            if writer
                .emit_confirmed(policy_snapshot::event(
                    &record,
                    "agent.policy_snapshot_requested",
                ))
                .await
                .is_err()
            {
                view["audit_status"] = json!(
                    "unavailable; canonical request is retained; read the original operation_id"
                );
            }
            // Existing operator attention discovers the canonical approval from
            // this event. This action cannot fit an agent deciding delegation.
            response(202, view)
        }
        Ok(Err(error)) => response(
            if error.kind == crate::approvals::ErrorKind::Io {
                503
            } else {
                409
            },
            json!({"error":error.to_string(),"next_action":"read the original operation_id before another submission"}),
        ),
        Err(_) => response(
            503,
            json!({"error":"snapshot request outcome unavailable; read the original operation_id before retrying"}),
        ),
    })
}
