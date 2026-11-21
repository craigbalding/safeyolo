//! Agent submission and scoped result readback. Decisions stay on the host.
use super::{Outcome, Request, RequestBody, response};
use crate::{approvals::pending::policy_change, audit::Writer};
use bytes::Bytes;
use hyper::body::Body;
use serde_json::json;
use std::sync::Arc;

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&crate::RuntimeState>,
    writer: Option<&Arc<Writer>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    if request.path_and_query.contains('?') {
        return Ok(response(
            400,
            json!({"error":"policy changes select only the authenticated local instance"}),
        ));
    }
    let (Some(state), Some(writer), Some(run)) = (
        state,
        writer.filter(|writer| writer.approvals_enabled()),
        request.identity.run().cloned(),
    ) else {
        return Ok(response(
            403,
            json!({"error":"trusted current-run requester and approval owner required"}),
        ));
    };
    let (state, writer) = (state.clone(), writer.clone());
    if let Some(id) = super::route(request).strip_prefix("/policy/changes/") {
        if request.method != "GET" {
            return Ok(response(405, json!({"error":"Method Not Allowed"})));
        }
        let Ok(id) = percent_encoding::percent_decode_str(id).decode_utf8() else {
            return Ok(response(404, json!({"error":"policy change unavailable"})));
        };
        if !crate::approvals::pending::valid_id(&id) {
            return Ok(response(404, json!({"error":"policy change unavailable"})));
        }
        let id = id.into_owned();
        return Ok(
            match tokio::task::spawn_blocking(move || {
                policy_change::read_agent(&state, &writer, &run, &id)
            })
            .await
            {
                Ok(Ok(Some(value))) => response(200, value),
                Ok(Ok(None)) => response(404, json!({"error":"policy change unavailable"})),
                _ => response(
                    503,
                    json!({"error":"readback unavailable; retain the original operation_id; do not replay a decision"}),
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
    let input: policy_change::Submission = match serde_json::from_slice(&content) {
        Ok(input) => input,
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"supply operation_id and candidate {snapshot_request_id, source, definition_version}; no approval authority is accepted"}),
            ));
        }
    };
    let emit = writer.clone();
    let result = tokio::task::spawn_blocking(move || {
        let record = policy_change::submit(&state, &writer, &run, &input)?;
        let policy = state
            .read()
            .map_err(|_| crate::approvals::invalid("runtime unavailable"))?
            .policy
            .clone()
            .ok_or_else(|| crate::approvals::invalid("policy unavailable"))?;
        let view = policy_change::view(&writer, &policy, &record)?;
        Ok::<_, crate::approvals::ApprovalError>((record, view))
    })
    .await;
    Ok(match result {
        Ok(Ok((record, mut view))) => {
            if emit
                .emit_confirmed(policy_change::event(
                    &record,
                    "agent.policy_change_submitted",
                ))
                .await
                .is_err()
            {
                view["audit_status"] = json!(
                    "unavailable; canonical submission is retained; read the original operation_id"
                );
            }
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
            json!({"error":"submission outcome unknown; read the original operation_id before retrying"}),
        ),
    })
}
