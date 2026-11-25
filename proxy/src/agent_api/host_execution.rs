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
    if let Some(operation) = path.strip_prefix("/gateway/host-setup/") {
        if request.method != "GET" {
            return Ok(response(
                405,
                json!({"error":"use GET to inspect the original host preparation"}),
            ));
        }
        return Ok(
            match crate::host_execution::setup::read_preparation(state, run, operation).await {
                Ok(value) => response(200, value),
                Err(error) => response(
                    404,
                    json!({"error":error.to_string(),"new_key_created":false}),
                ),
            },
        );
    }
    if path == "/gateway/host-setup" {
        if request.method == "GET" {
            return Ok(response(
                200,
                json!({
                    "plan_schema":schemars::schema_for!(safeyolo_host_executor::enrolment::TaskPlan),
                    "enrolment_schema":schemars::schema_for!(safeyolo_host_executor::enrolment::Enrolment),
                    "sequence":["prepare","trusted target bootstrap","submit","existing human policy review","resume","discover"],
                    "bootstrap_platforms":["linux","macos"],"permission_granted":false,
                    "limitations":"Preparation creates a vault-held signing key. Target bootstrap requires its existing authorized install/transfer owner. Actual native qualification may refuse unsupported bounds. No task program runs during setup."
                }),
            ));
        }
        if request.method != "POST" {
            return Ok(response(
                405,
                json!({"error":"use POST to prepare or submit a host setup"}),
            ));
        }
        #[derive(serde::Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Setup {
            Prepare {
                operation_id: String,
                plan: Box<safeyolo_host_executor::enrolment::TaskPlan>,
            },
            Submit {
                operation_id: String,
                enrolment: Box<safeyolo_host_executor::enrolment::Enrolment>,
            },
        }
        let content = match super::declarations::read_content(body).await? {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        let input: Setup = match serde_json::from_slice(&content) {
            Ok(input) => input,
            Err(_) => {
                return Ok(response(
                    400,
                    json!({"error":"supply a prepare plan or submit the original target enrolment; signing keys and live authority are not accepted"}),
                ));
            }
        };
        let result = match input {
            Setup::Prepare { operation_id, plan } => {
                crate::host_execution::setup::prepare(state, run, &operation_id, *plan).await
            }
            Setup::Submit {
                operation_id,
                enrolment,
            } => crate::host_execution::setup::submit(state, run, &operation_id, *enrolment).await,
        };
        return Ok(match result {
            Ok(value) => response(200, value),
            Err(error) => response(
                409,
                json!({"error":error.to_string(),"next_action":"Inspect the original setup, target enrolment and policy-change request before another effect. No task program was invoked."}),
            ),
        });
    }
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
                let active = binding.principal(&runtime,run).is_ok();
                let principal=if active || binding.resume_task {binding.eligible_run(&runtime,run).ok()?} else {return None};
                Some(json!({"binding":name,"target_id":binding.target.target_id,"issuer_id":binding.issuer_id,"principal":principal,"service":binding.service,
                    "task_active":active,"resume_available":binding.resume_task,
                    "agent_code_classes":binding.target.issuers[&binding.issuer_id].authority.grants[&binding.grant_id].families.iter().filter(|family|family.rule.allow_agent_code).collect::<Vec<_>>(),
                    "target_code_classes":binding.target.families.iter().filter(|family|family.rule.allow_agent_code).collect::<Vec<_>>(),
                    "endpoint":format!("/gateway/host/{name}"),"authority":"operator-adopted; discover current target revisions before proposing an invocation"}))
            }).collect::<Vec<_>>()}),
            ),
            Err(_) => response(503, json!({"error":"host bindings unavailable"})),
        });
    }
    if let Some(name) = path
        .strip_prefix("/gateway/host/")
        .and_then(|name| name.strip_suffix("/resume"))
    {
        if name.is_empty() || name.contains('/') || request.method != "POST" {
            return Ok(response(
                400,
                json!({"error":"use POST with the selected binding's resume endpoint"}),
            ));
        }
        let content = match super::declarations::read_content(body).await? {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Resume {
            request_id: String,
        }
        let input: Resume = match serde_json::from_slice(&content) {
            Ok(input) => input,
            Err(_) => {
                return Ok(response(
                    400,
                    json!({"error":"supply request_id only; task and authority come from the adopted binding"}),
                ));
            }
        };
        if !super::valid_request_id(&input.request_id) {
            return Ok(response(400, json!({"error":"use a req- request_id"})));
        }
        return Ok(match gateway::resume(state, run, name).await {
            Ok(mut value) => {
                value["request_id"] = json!(input.request_id);
                response(200, value)
            }
            Err(error) => {
                let status = if error
                    .downcast_ref::<safeyolo_host_executor::Refusal>()
                    .is_some_and(|r| {
                        matches!(
                            r.code,
                            safeyolo_host_executor::RefusalCode::Principal
                                | safeyolo_host_executor::RefusalCode::Issuer
                                | safeyolo_host_executor::RefusalCode::Authority
                                | safeyolo_host_executor::RefusalCode::Expired
                        )
                    }) {
                    403
                } else {
                    409
                };
                response(
                    status,
                    json!({"error":error.to_string(),"request_id":input.request_id,"next_action":"Read the binding and active task; no target operation was sent."}),
                )
            }
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
                json!({"error":"supply request_id, expected revisions and an action; code adoption needs an explicit standing code class, and caller-selected authority is not accepted"}),
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
