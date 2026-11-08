//! Operator-only support authority. The ordinary Admin bearer boundary applies.

use super::*;

pub(super) async fn respond<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    state: Option<&crate::RuntimeState>,
    owner: Option<ServiceAudit<'_>>,
) -> Result<Outcome, Error> {
    let (Some(state), Some(owner)) = (state, owner) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"support policy owner unavailable"}),
        ));
    };
    let config = match crate::operator_actions::config_path(state) {
        Ok(config) => config,
        Err(_) => {
            return Ok(response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"support configuration unavailable"}),
            ));
        }
    };
    if request.method() == Method::GET && path == "/admin/support-grants" {
        return Ok(crate::host_platform::in_config(config, async {
            match crate::peer_support::current_policy(state).and_then(|policy| {
                let instance = crate::peer_support::instance_id()?;
                Ok(json!({"instance_id":instance,"grants":policy.support_grants().into_iter().map(|(name,grant)| crate::peer_support::grant_view(&policy, &name, &grant, &instance)).collect::<Vec<_>>()}))
            }) {
                Ok(value) => response(StatusCode::OK, value),
                Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"support policy unavailable"})),
            }
        }).await);
    }
    let Some((name, operation)) = path
        .strip_prefix("/admin/support-grants/")
        .and_then(|path| path.split_once('/'))
    else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"support grant unavailable"}),
        ));
    };
    if request.method() != Method::POST
        || !crate::host_platform::valid_agent_name(name)
        || !matches!(operation, "preview" | "apply" | "revoke")
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"select a named support grant and preview, apply or revoke"}),
        ));
    }
    let value = match read_json(request).await? {
        ParsedBody::Value(value) => value.0.clone(),
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"support grant proposal required"}),
            ));
        }
    };
    let (name, operation, state, writer) = (
        name.to_owned(),
        operation.to_owned(),
        state.clone(),
        owner.writer.clone(),
    );
    owner.mutation_owner.spawn_blocking(move || Ok(tokio::runtime::Handle::current().block_on(
        crate::host_platform::in_config(config, async {
            let result = if operation == "revoke" {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Revoke { expected_revision: String }
                match serde_json::from_value::<Revoke>(value) {
                    Ok(input) => crate::peer_support::grants::revoke(&state, &name, &input.expected_revision),
                    Err(_) => Err(crate::approvals::invalid("supply expected_revision only")),
                }
            } else {
                match serde_json::from_value::<crate::peer_support::grants::Proposal>(value) {
                    Ok(proposal) if operation == "apply" => crate::peer_support::grants::apply(&state, &name, proposal),
                    Ok(proposal) => crate::peer_support::current_policy(&state)
                        .map_err(|_| crate::approvals::invalid("support policy unavailable"))
                        .and_then(|policy| crate::peer_support::grants::preview(&policy, &name, &proposal)),
                    Err(_) => Err(crate::approvals::invalid("invalid support grant proposal; supply expected_revision and grant")),
                }
            };
            match result {
                Ok(mut value) => {
                    if operation != "preview"
                        && let Some(id) = value["audit_event_id"].as_str()
                        && crate::peer_support::audit_delivery::deliver_grant(&writer, id).await.is_err() {
                        value["audit_status"] = json!(crate::peer_support::audit_delivery::PENDING);
                    }
                    response(StatusCode::OK, value)
                }
                Err(error) => response(StatusCode::CONFLICT, json!({"error":error.to_string()})),
            }
        })
    ))).await?.await.map_err(|_| Error::ServiceMutation)?
}
