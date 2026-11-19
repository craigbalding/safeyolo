//! Authenticated local preparation over an approved policy snapshot.
use super::{Outcome, Request, RequestBody, response};
use bytes::Bytes;
use hyper::body::Body;
use serde_json::json;
use std::sync::Arc;

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&crate::RuntimeState>,
    writer: Option<&Arc<crate::audit::Writer>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    if request.method != "POST" || request.path_and_query.contains('?') {
        return Ok(response(
            400,
            json!({"error":"assessment requires a local POST with no query selectors"}),
        ));
    }
    let (Some(state), Some(writer), Some(run)) = (state, writer, request.identity.run().cloned())
    else {
        return Ok(response(
            403,
            json!({"error":"approved snapshot unavailable"}),
        ));
    };
    let content = match super::declarations::read_content(body).await? {
        Ok(content) => content,
        Err(error) => return Ok(super::declarations::content_error(error)),
    };
    let input: crate::services::effects::policy::Candidate = match serde_json::from_slice(&content)
    {
        Ok(input) => input,
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"supply snapshot_request_id, complete TOML source and installed definition_version only"}),
            ));
        }
    };
    let (state, writer) = (state.clone(), writer.clone());
    Ok(
        match tokio::task::spawn_blocking(move || {
            crate::approvals::pending::policy_assessment::private(&state, &writer, &run, &input)
        })
        .await
        {
            Ok(Ok(value)) => response(200, value),
            Ok(Err(error)) => response(
                400,
                json!({"error":error.to_string(),"activated":false,"operator_notified":false}),
            ),
            Err(_) => response(
                503,
                json!({"error":"assessment unavailable; no candidate was applied or submitted"}),
            ),
        },
    )
}
