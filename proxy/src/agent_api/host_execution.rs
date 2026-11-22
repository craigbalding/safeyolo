//! Agent-local host execution uses the ordinary bearer and listener identity.
use super::{Outcome, Request, RequestBody, response};
use crate::host_execution::gateway;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;
use serde_json::json;

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&crate::RuntimeState>,
    mut body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Some(state) = state else {
        return Ok(response(503, json!({"error":"host gateway unavailable"})));
    };
    let runtime = match state.read() {
        Ok(runtime) => runtime.clone(),
        Err(_) => return Ok(response(503, json!({"error":"host gateway unavailable"}))),
    };
    let Some(policy) = runtime.policy.as_ref() else {
        return Ok(response(503, json!({"error":"host policy unavailable"})));
    };
    let Some(run) = request.identity.run().filter(|run| run.current(policy)) else {
        return Ok(response(
            403,
            json!({"error":"trusted current-run identity required"}),
        ));
    };
    if request.path_and_query.contains('?') {
        return Ok(response(
            400,
            json!({"error":"host gateway accepts no query selectors"}),
        ));
    }
    let path = super::route(request);
    if path == "/gateway/host" {
        if request.method != "GET" {
            return Ok(response(
                405,
                json!({"error":"use GET for bound host capabilities"}),
            ));
        }
        return Ok(match policy.host_bindings() {
            Ok(bindings) => response(
                200,
                json!({"host_bindings":bindings.into_iter().filter_map(|(name,binding)| {
                let principal=binding.principal(&runtime,run).ok()?;
                Some(json!({"binding":name,"target_id":binding.target.target_id,"principal":principal,"service":binding.service,
                    "endpoint":format!("/gateway/host/{name}"),"authority":"operator-adopted; discover current target revisions before proposing an invocation"}))
            }).collect::<Vec<_>>()}),
            ),
            Err(_) => response(503, json!({"error":"host bindings unavailable"})),
        });
    }
    let name = path.strip_prefix("/gateway/host/").unwrap_or("");
    if name.is_empty() || name.contains('/') {
        return Ok(response(404, json!({"error":"host binding unavailable"})));
    }
    if request.method != "POST" {
        return Ok(response(
            405,
            json!({"error":"use POST with a host action"}),
        ));
    }
    let binding = match gateway::binding(policy, name) {
        Ok(binding) if binding.principal(&runtime, run).is_ok() => binding,
        _ => {
            return Ok(response(
                403,
                json!({"error":"host binding unavailable for this run and task"}),
            ));
        }
    };
    if !body.content_encoding.is_empty() && body.content_encoding != b"identity" {
        return Ok(response(
            415,
            json!({"error":"host gateway requires uncompressed JSON"}),
        ));
    }
    let maximum = binding.request_bytes;
    if body.content_length.is_some_and(|len| len > maximum as u64) {
        return Ok(response(
            413,
            json!({"error":"host request limit exceeded"}),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(frame) = body.body.frame().await {
        if let Ok(data) = frame?.into_data() {
            if data.len() > maximum.saturating_sub(bytes.len()) {
                return Ok(response(
                    413,
                    json!({"error":"host request limit exceeded"}),
                ));
            }
            bytes.extend_from_slice(&data);
        }
    }
    if let Some(observation) = body.observation.as_deref_mut() {
        observation.encoded_size = Some(bytes.len() as u64);
        observation.decoded_size = Some(Ok(bytes.len() as u64));
    }
    let input = match serde_json::from_slice::<gateway::Input>(&bytes) {
        Ok(input) => input,
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"supply request_id, expected revisions and action; caller-selected authority and definition management are not supported"}),
            ));
        }
    };
    Ok(match gateway::execute(state, run, name, input).await {
        Ok(reply) => response(reply.status, reply.value),
        Err(error) => match error.downcast_ref::<crate::host_execution::Refusal>() {
            Some(refusal) => response(
                gateway::status(refusal.code),
                json!({"kind":"refused","refusal":refusal}),
            ),
            None => response(
                503,
                json!({"error":"host gateway unavailable; inspect the original operation before retrying"}),
            ),
        },
    })
}
