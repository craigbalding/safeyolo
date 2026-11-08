//! Authenticated local support without a Coord or NATS dependency.

use bytes::Bytes;
use hyper::body::Body;
use serde_json::json;

use super::{Outcome, Request, RequestBody, response};

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&crate::RuntimeState>,
    writer: Option<&std::sync::Arc<crate::audit::Writer>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let (Some(state), Some(writer)) = (state, writer) else {
        return Ok(response(503, json!({"error":"local support unavailable"})));
    };
    let Some(run) = request.identity.run().cloned() else {
        return Ok(response(
            403,
            json!({"error":"trusted current support-agent run required"}),
        ));
    };
    let config = match crate::operator_actions::config_path(state) {
        Ok(path) => path,
        Err(_) => {
            return Ok(response(
                503,
                json!({"error":"support configuration unavailable"}),
            ));
        }
    };
    let path = super::route(request);
    let result = if request.method == "GET" && path == "/support/grants" {
        crate::host_platform::in_config(config, async {
            crate::peer_support::discover(state, &run)
        })
        .await
    } else if request.method == "GET"
        && let Some(id) = path.strip_prefix("/support/operations/")
    {
        let id = match percent_encoding::percent_decode_str(id).decode_utf8() {
            Ok(id) => id,
            Err(_) => return Ok(response(400, json!({"error":"operation_id must be UTF-8"}))),
        };
        crate::host_platform::in_config(config, async {
            crate::peer_support::read(state, &run, &id)
        })
        .await
    } else if request.method == "POST" && path == "/support/operations" {
        let content = match super::declarations::read_content(body).await? {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        let input = match serde_json::from_slice::<crate::peer_support::Request>(&content) {
            Ok(input) => input,
            Err(_) => {
                return Ok(response(
                    400,
                    json!({"error":"supply operation_id, grant, target_id, optional instance_id, expected_run and a typed operation only; caller identity is transport-bound"}),
                ));
            }
        };
        crate::peer_support::submit(state, writer, &run, input).await
    } else {
        return Ok(response(
            405,
            json!({"error":"use GET /support/grants, POST /support/operations or GET /support/operations/ID"}),
        ));
    };
    Ok(match result {
        Ok(value) => response(200, value),
        // Authority failures do not disclose host record paths or backend
        // errors. The operator can inspect private state through host tools.
        Err(error) => {
            let refusal = error.downcast_ref::<crate::peer_support::Refusal>();
            response(
                refusal.map_or(503, |refusal| refusal.status),
                json!({"error":refusal.map_or("support state or runtime control unavailable", |refusal| refusal.message),"next_action":"inspect your current support grants; ask the operator to preview missing target/action authority. After a lost reply, read the original operation_id before requesting another operation."}),
            )
        }
    })
}
