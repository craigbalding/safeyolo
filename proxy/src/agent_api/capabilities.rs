//! Definition reads do not execute a request or consume an approval.
use super::{Outcome, PolicyState, Request, RequestBody, agent, response};
use crate::{RuntimeState, peer_support, policy::capabilities};
use bytes::Bytes;
use hyper::body::Body;
use serde::Deserialize;
use serde_json::{Value, json};

fn unknown() -> Value {
    json!({"observation":"unknown","granted":null,"requestable":null,"prohibited":null,"unavailable":null})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Support {
    definition_version: String,
    request: peer_support::operations::Request,
}

pub(super) async fn respond<B>(
    request: Request<'_>,
    policy: PolicyState<'_>,
    state: Option<&RuntimeState>,
    gateway: Option<super::GatewayContext<'_>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let path = super::route(request);
    if path == "/policy/capabilities" && request.method == "GET" {
        // There is no target, identity, source, snapshot or remote-home override.
        if !matches!(
            request
                .path_and_query
                .split_once('?')
                .map(|(_, query)| query),
            None | Some("observe=true") | Some("observe=false")
        ) {
            return Ok(response(
                400,
                json!({"error":"only observe=true or observe=false is accepted"}),
            ));
        }
        let mut view = capabilities::discover();
        if request.path_and_query.ends_with("?observe=true") {
            let mut observations = json!({"observation":"unknown","support":unknown(),"services":unknown(),"desktop":unknown()});
            if let (Some(caller), PolicyState::Ready(policy), Some(state)) =
                (agent(request.identity), policy, state)
            {
                observations["policy_revision"] = json!(policy.policy_hash());
                observations["observed_at_ms"] = json!(crate::policy::current_time_ms());
                observations["observation"] = json!("current_read_attempt");
                if let Some(run) = request.identity.run().filter(|run| run.current(policy))
                    && let Ok(value) = peer_support::discover(state, run)
                {
                    observations["support"] =
                        json!({"observation":"current","owner":"support_grants","value":value});
                }
                if let Some(context) = gateway {
                    observations["services"] = match context.snapshot {
                        Some(snapshot) => snapshot
                            .policy_capabilities(caller)
                            .unwrap_or_else(|_| unknown()),
                        None => json!({"observation":"current","authorized":[],"available":[]}),
                    };
                }
                if let Ok(value) = crate::operator_actions::discover(state, policy, caller).await {
                    // Keep prerequisite diagnostics on their existing owner path.
                    let actions: Vec<_> = value["actions"].as_array().into_iter().flatten()
                        .map(|action| json!({"action_id":action["action_id"],"supported":true,
                            "requestable":true,"unavailable":action["available"].as_bool().map(|available|!available),
                            "granted":null,"prohibited":null})).collect();
                    observations["desktop"] = json!({"observation":"current","actions":actions,"owner":"GET /operator-actions"});
                }
            }
            view["observations"] = observations;
        }
        return Ok(response(200, view));
    }
    if request.method != "POST"
        || !matches!(
            path,
            "/policy/capabilities/validate" | "/policy/capabilities/support"
        )
    {
        return Ok(response(
            405,
            json!({"error":"unsupported capability route or method"}),
        ));
    }
    let content = match super::declarations::read_content(body).await? {
        Ok(value) => value,
        Err(error) => return Ok(super::declarations::content_error(error)),
    };
    if path == "/policy/capabilities/validate" {
        return Ok(
            match serde_json::from_slice(&content)
                .map_err(crate::Error::from)
                .and_then(capabilities::validate)
            {
                Ok(value) => response(200, value),
                Err(error) => response(
                    400,
                    json!({"error":error.to_string(),"authorized":false,"activated":false}),
                ),
            },
        );
    }
    let (Some(state), Some(run)) = (state, request.identity.run()) else {
        return Ok(response(200, unknown()));
    };
    let input = match serde_json::from_slice::<Support>(&content) {
        Ok(input) => input,
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"supply definition_version and typed support request only"}),
            ));
        }
    };
    if input.definition_version != env!("SAFEYOLO_DEFINITION_VERSION") {
        return Ok(response(
            400,
            json!({"error":"definition version changed; discover again"}),
        ));
    }
    Ok(response(
        200,
        peer_support::operations::capability_observation(
            state,
            &peer_support::Caller::local(run),
            input.request,
        )
        .await,
    ))
}
