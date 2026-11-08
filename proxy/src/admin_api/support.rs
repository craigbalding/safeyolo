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
        || !matches!(operation, "preview" | "apply" | "revoke" | "report")
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
            let result: crate::approvals::Result<serde_json::Value> = async { if operation == "revoke" {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Revoke { expected_revision: String }
                match serde_json::from_value::<Revoke>(value) {
                    Ok(input) => crate::peer_support::grants::revoke(&state, &name, &input.expected_revision),
                    Err(_) => Err(crate::approvals::invalid("supply expected_revision only")),
                }
            } else if operation == "report" {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Inspect { #[serde(default)] owners: Vec<crate::peer_support::authority::Owner>, #[serde(default)] remove: bool }
                match serde_json::from_value::<Inspect>(value) {
                    Ok(input) => {
                        let policy = crate::peer_support::current_policy(&state).map_err(|_| crate::approvals::invalid("support policy unavailable"))?;
                        let grant = policy.support_grants().remove(&name).ok_or_else(|| crate::approvals::invalid("support grant unavailable"))?;
                        let instance = crate::peer_support::instance_id().map_err(|_| crate::approvals::invalid("owner identity unavailable"))?;
                        let subject = crate::peer_support::authority::Principal::new(grant.support_instance_id.as_deref().unwrap_or(&instance), &grant.support.agent_id);
                        let selection = crate::peer_support::authority::Selection { owners: input.owners, considered: None };
                        let report = crate::peer_support::authority::report(&state, &selection, input.remove.then_some(name.as_str()), None, Some(subject)).await
                            .map_err(|error| crate::approvals::invalid(error.to_string()))?;
                        let mut view = json!({"name":name,"revision":grant.revision(),"remove":input.remove});
                        crate::peer_support::authority::attach(&mut view, &selection, report);
                        Ok(view)
                    }
                    Err(_) => Err(crate::approvals::invalid("report requires selected owners and optional remove")),
                }
            } else {
                match serde_json::from_value::<crate::peer_support::grants::Proposal>(value) {
                    Ok(proposal) => {
                        let policy = crate::peer_support::current_policy(&state)
                            .map_err(|_| crate::approvals::invalid("support policy unavailable"))?;
                        let mut view = crate::peer_support::grants::preview(&policy, &name, &proposal)?;
                        let prepared: crate::policy::support::Grant = serde_json::from_value(view["after"].clone())
                            .map_err(|_| crate::approvals::invalid("prepared support grant unavailable"))?;
                        let subject = crate::peer_support::authority::Principal::new(
                            prepared.support_instance_id.as_deref().unwrap_or(&prepared.instance_id), &prepared.support.agent_id);
                        let report = crate::peer_support::authority::report(&state, &proposal.authority, Some(&name), Some(&prepared), Some(subject)).await
                            .map_err(|error| crate::approvals::invalid(error.to_string()))?;
                        if operation == "apply" {
                            if !crate::peer_support::authority::acknowledged(&proposal.authority, &report) {
                                crate::peer_support::authority::attach(&mut view, &proposal.authority, report);
                                view["error"] = json!("authority evidence changed or was not acknowledged; inspect this refreshed preview and acknowledge its report before apply");
                                return Ok(view);
                            }
                            crate::peer_support::grants::apply(&state, &name, proposal, &report)
                        } else {
                            crate::peer_support::authority::attach(&mut view, &proposal.authority, report);
                            Ok(view)
                        }
                    },
                    Err(_) => Err(crate::approvals::invalid("invalid support grant proposal; supply expected_revision and grant")),
                }
            } }.await;
            match result {
                Ok(mut value) => {
                    if matches!(operation.as_str(), "apply" | "revoke")
                        && let Some(id) = value["audit_event_id"].as_str()
                        && crate::peer_support::audit_delivery::deliver_grant(&writer, id).await.is_err() {
                        value["audit_status"] = json!(crate::peer_support::audit_delivery::PENDING);
                    }
                    if matches!(operation.as_str(), "preview" | "report") {
                        let mut event = crate::audit::Event::new("admin.support_authority_preview", crate::audit::Kind::Admin, crate::audit::Severity::Low, "Support authority preview generated");
                        event.details = json!({"grant":name,"operation":operation,"proposal":value["after"],"report":value["authority"]["considered"]}).into();
                        if writer.emit_confirmed(event).await.is_err() { value["audit_status"] = json!("authority preview audit unavailable"); }
                    }
                    response(if value.get("error").is_some() { StatusCode::CONFLICT } else { StatusCode::OK }, value)
                }
                Err(error) => response(StatusCode::CONFLICT, json!({"error":error.to_string()})),
            }
        })
    ))).await?.await.map_err(|_| Error::ServiceMutation)?
}
