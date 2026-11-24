//! Self-stop has an inferred current worker/run and no caller-selected host action.
use super::{Outcome, Request, RequestBody, response};
use crate::{RuntimeState, host_lifecycle::scheduled, host_platform};
use bytes::Bytes;
use hyper::body::Body;
use serde_json::json;

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&RuntimeState>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Some(state) = state else {
        return Ok(response(503, json!({"error":"lifecycle unavailable"})));
    };
    let Some(run) = request.identity.run() else {
        return Ok(response(
            403,
            json!({"error":"trusted current-run worker required"}),
        ));
    };
    let config = match crate::operator_actions::config_path(state) {
        Ok(config) => config,
        Err(_) => {
            return Ok(response(
                503,
                json!({"error":"lifecycle configuration unavailable"}),
            ));
        }
    };
    let path = super::route(request);
    let result = host_platform::in_config(config, async {
        let policy = crate::peer_support::current_policy(state)?;
        if !run.current(&policy) {
            return Err(crate::peer_support::refuse(
                403,
                "worker run is no longer current",
            ));
        }
        if request.method == "GET" {
            if path == "/lifecycle" {
                let agent = crate::host_agents::list()?
                    .into_iter()
                    .find(|a| a.id == run.agent_id && a.name == run.agent)
                    .ok_or("worker identity unavailable")?;
                return scheduled::status(&agent).await;
            }
            if let Some(id) = path.strip_prefix("/lifecycle/requests/") {
                let id = percent_encoding::percent_decode_str(id)
                    .decode_utf8()
                    .map_err(|_| {
                        crate::peer_support::refuse(400, "invalid operation_id encoding")
                    })?;
                return scheduled::read_request(&host_platform::config_dir(), &run.agent_id, &id);
            }
            return Err(crate::peer_support::refuse(
                404,
                "lifecycle route not found",
            ));
        }
        if request.method != "POST" || path != "/lifecycle/stop" {
            return Err(crate::peer_support::refuse(405, "method not allowed"));
        }
        Ok(serde_json::Value::Null)
    })
    .await;
    if request.method == "POST" && path == "/lifecycle/stop" && result.is_ok() {
        let content = match super::declarations::read_content(body).await? {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        let input = match serde_json::from_slice(&content) {
            Ok(input) => input,
            Err(_) => {
                return Ok(response(
                    400,
                    json!({"error":"supply operation_id and shutdown_work_id only"}),
                ));
            }
        };
        let config = match crate::operator_actions::config_path(state) {
            Ok(config) => config,
            Err(_) => {
                return Ok(response(
                    503,
                    json!({"error":"lifecycle configuration unavailable"}),
                ));
            }
        };
        return Ok(render(
            host_platform::in_config(config, scheduled::request(state, run, input)).await,
            202,
        ));
    }
    Ok(render(result, 200))
}

fn render(result: Result<serde_json::Value, crate::Error>, success: u16) -> Outcome<'static> {
    match result {
        Ok(value) => response(success, value),
        Err(error) => {
            let code = error
                .downcast_ref::<crate::peer_support::Refusal>()
                .map_or(409, |e| e.status);
            response(code, json!({"error":error.to_string()}))
        }
    }
}
