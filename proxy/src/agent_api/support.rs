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
    if super::route(request).starts_with("/support/diagnostics") {
        return diagnostic_response(request, state, writer, body).await;
    }
    match super::coord::query_parameter(request.path_and_query, "home") {
        Ok(Some(home)) => {
            let payload = if request.method == "POST" {
                match super::declarations::read_content(body).await? {
                    Ok(content) => Some(content),
                    Err(error) => return Ok(super::declarations::content_error(error)),
                }
            } else {
                None
            };
            return Ok(super::coord::federation::forward_support(
                request,
                state,
                payload.as_ref().map(|content| content.as_slice()),
                &home,
            )
            .await);
        }
        Ok(None) => {}
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"select one configured owning instance"}),
            ));
        }
    }
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
    let result = if request.method == "POST"
        && path == crate::peer_support::authority::METADATA_PATH
    {
        let content = match super::declarations::read_content(body).await? {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        crate::host_platform::in_config(config, async {
            let policy = crate::peer_support::authority::read_policy(state)?;
            if !run.current(&policy) {
                return Err(crate::peer_support::refuse(
                    403,
                    "current metadata reader run required",
                ));
            }
            let instance = crate::peer_support::instance_id()?;
            let disclosure = policy
                .authority_disclosure(&instance, Some(&run.agent_id), None)
                .map_err(|_| {
                    crate::peer_support::refuse(
                        403,
                        "authority metadata is not disclosed to this reader",
                    )
                })?;
            let result = crate::peer_support::authority::metadata(
                state,
                &policy,
                Some(&disclosure),
                serde_json::from_slice(&content)?,
            )?;
            let current = crate::peer_support::authority::read_policy(state)?;
            let reader = current
                .authority_disclosure(&instance, Some(&run.agent_id), None)
                .map_err(|_| {
                    crate::peer_support::refuse(403, "authority metadata disclosure was revoked")
                })?;
            if !run.current(&current) || json!(reader) != json!(disclosure) {
                return Err(crate::peer_support::refuse(
                    403,
                    "authority metadata reader changed",
                ));
            }
            if crate::peer_support::authority::snapshot(state, &current, Some(&reader))?.revision
                != result["snapshot"]["revision"]
            {
                return Err(crate::peer_support::refuse(
                    409,
                    "owner authority changed during collection",
                ));
            }
            Ok(result)
        })
        .await
    } else if request.method == "GET" && path == "/support/grants" {
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

async fn diagnostic_response<B>(
    request: Request<'_>,
    state: &crate::RuntimeState,
    writer: &std::sync::Arc<crate::audit::Writer>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    use crate::peer_support::{diagnostics, refuse};
    let Some(run) = request.identity.run().cloned() else {
        return Ok(response(
            403,
            json!({"error":"current authenticated agent run required"}),
        ));
    };
    if request.path_and_query.contains('?') {
        return Ok(response(
            400,
            json!({"error":"diagnostic disclosure is local; select filters only through the typed request body"}),
        ));
    }
    let config = match crate::operator_actions::config_path(state) {
        Ok(config) => config,
        Err(_) => {
            return Ok(response(
                503,
                json!({"error":"diagnostic owner unavailable"}),
            ));
        }
    };
    let result = if request.method == "GET" && super::route(request) == "/support/diagnostics" {
        crate::host_platform::in_config(config, async { diagnostics::discover(state, &run) }).await
    } else if request.method == "POST" {
        let content = match super::declarations::read_content(body).await? {
            Ok(c) => c,
            Err(e) => return Ok(super::declarations::content_error(e)),
        };
        match super::route(request) {
            "/support/diagnostics/requests" => match serde_json::from_slice(&content) {
                Ok(input) => diagnostics::request(state, writer, &run, input).await,
                Err(_) => Err(refuse(
                    400,
                    "invalid typed diagnostic disclosure request; requester identity is transport-bound",
                )),
            },
            "/support/diagnostics/query" => match serde_json::from_slice(&content) {
                Ok(input) => {
                    crate::host_platform::in_config(config, async {
                        diagnostics::query(state, writer, &run, input).await
                    })
                    .await
                }
                Err(_) => Err(refuse(
                    400,
                    "invalid typed diagnostic query; unsupported fields and filters are refused",
                )),
            },
            _ => Err(refuse(404, "diagnostic endpoint unavailable")),
        }
    } else {
        Err(refuse(
            405,
            "use GET /support/diagnostics or POST /support/diagnostics/requests or /support/diagnostics/query",
        ))
    };
    Ok(match result {
        Ok(value) => response(200, value),
        Err(error) => {
            let refusal = error.downcast_ref::<crate::peer_support::Refusal>();
            let invalid = error
                .downcast_ref::<crate::approvals::ApprovalError>()
                .is_some_and(|e| {
                    matches!(
                        e.kind,
                        crate::approvals::ErrorKind::Invalid
                            | crate::approvals::ErrorKind::Unsupported
                    )
                });
            response(
                refusal.map_or(if invalid { 400 } else { 503 }, |e| e.status),
                json!({"error":refusal.map_or(if invalid {"invalid diagnostic selection or request; discover supported scope and read the canonical approval"} else {"diagnostic source or authority unavailable"},|e|e.message),"next_action":"Read current diagnostic disclosure and the canonical approval. A failed or incomplete read does not establish empty evidence. Retry an authorized collection with its original operation_id and page token."}),
            )
        }
    })
}

pub(crate) async fn remote(
    request: Request<'_>,
    state: &crate::RuntimeState,
    remote: crate::coord_rooms::federation::RemoteAgent,
    run: crate::host_runs::AgentRun,
    payload: Option<&[u8]>,
) -> Outcome<'static> {
    let writer = match state.read() {
        Ok(runtime) => runtime.audit.clone(),
        Err(_) => return response(503, json!({"error":"runtime unavailable"})),
    };
    let caller = crate::peer_support::Caller {
        run,
        remote: Some(remote),
    };
    let result = crate::peer_support::remote(
        state,
        &writer,
        &caller,
        request.method,
        super::route(request),
        payload,
    )
    .await;
    match result {
        Ok(value) => response(200, value),
        Err(error) => {
            let refusal = error.downcast_ref::<crate::peer_support::Refusal>();
            response(
                refusal.map_or(503, |refusal| refusal.status),
                json!({"error":refusal.map_or("support state or runtime control unavailable",|refusal|refusal.message),"next_action":"inspect current B-side grants and the original operation_id before another operation"}),
            )
        }
    }
}
