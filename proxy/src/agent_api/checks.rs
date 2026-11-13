//! Invoke an operator-adopted check without accepting a caller-owned JobSpec.
use super::{Outcome, Request, RequestBody, agent, response};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    check: String,
    subject: crate::policy::checks::Subject,
}

pub(super) async fn respond<B>(
    request: Request<'_>,
    state: Option<&crate::RuntimeState>,
    mut body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    if request.method != "POST" {
        return Ok(response(
            405,
            json!({"error":"use POST to invoke an adopted check"}),
        ));
    }
    let Some(caller) = agent(request.identity) else {
        return Ok(response(
            403,
            json!({"error":"trusted caller identity required"}),
        ));
    };
    let Some(state) = state else {
        return Ok(response(
            503,
            json!({"error":"check execution unavailable"}),
        ));
    };
    if !body.content_encoding.is_empty() && body.content_encoding != b"identity" {
        return Ok(response(
            415,
            json!({"error":"check invocation requires uncompressed JSON"}),
        ));
    }
    const MAXIMUM: usize = 48 * 1024;
    if body
        .content_length
        .is_some_and(|size| size > MAXIMUM as u64)
    {
        return Ok(response(
            413,
            json!({"error":"check invocation input limit exceeded"}),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(frame) = body.body.frame().await {
        if let Ok(data) = frame?.into_data() {
            if data.len() > MAXIMUM.saturating_sub(bytes.len()) {
                return Ok(response(
                    413,
                    json!({"error":"check invocation input limit exceeded"}),
                ));
            }
            bytes.extend_from_slice(&data);
        }
    }
    if let Some(observation) = body.observation.as_deref_mut() {
        observation.encoded_size = Some(bytes.len() as u64);
        observation.decoded_size = Some(Ok(bytes.len() as u64));
    }
    let invocation: Invocation = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return Ok(response(
                400,
                json!({"error":"supply only an adopted check name and typed subject"}),
            ));
        }
    };
    let runtime = match state.read() {
        Ok(current) => current.clone(),
        Err(_) => {
            return Ok(response(
                503,
                json!({"error":"current check policy unavailable"}),
            ));
        }
    };
    let Some(policy) = runtime.policy.as_ref() else {
        return Ok(response(503, json!({"error":"check policy unavailable"})));
    };
    if request
        .identity
        .run()
        .is_some_and(|run| !run.current(policy))
    {
        return Ok(response(
            403,
            json!({"error":"current caller run required"}),
        ));
    }
    let Some(check) = policy.named_checks().checks.get(&invocation.check) else {
        return Ok(response(404, json!({"error":"unknown adopted check"})));
    };
    if !check
        .invokers
        .iter()
        .any(|allowed| allowed == caller || allowed == "*")
    {
        return Ok(response(
            403,
            json!({"error":"caller is not an adopted check invoker"}),
        ));
    }
    let result = policy
        .named_checks()
        .invoke_named(
            &invocation.check,
            caller,
            invocation.subject,
            &runtime,
            state,
        )
        .await;
    let current = state.read().ok().is_some_and(|current| {
        current.policy.as_ref().is_some_and(|active| {
            std::sync::Arc::ptr_eq(active, policy)
                && request.identity.run().is_none_or(|run| run.current(active))
        })
    });
    if !current {
        return Ok(response(
            409,
            json!({"error":"check authority changed while pending; late result discarded"}),
        ));
    }
    let mut event = crate::audit::Event::new(
        "ops.check_invoked",
        crate::audit::Kind::Ops,
        crate::audit::Severity::Low,
        "Adopted check requested by agent",
    );
    event.agent = Some(caller.into());
    event.request_id = Some(request.request_id.into());
    event.details = json!({"check":invocation.check,"policy_hash":policy.policy_hash(),"execution_error":result.as_ref().err().map(ToString::to_string)}).into();
    if runtime.audit.emit(event).is_err() {
        return Ok(response(
            503,
            json!({"error":"check invocation audit unavailable"}),
        ));
    }
    Ok(match result {
        Ok(evidence) => response(200, json!({"check":invocation.check,"evidence":evidence})),
        Err(error) => response(422, json!({"error":error.to_string()})),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invocation_cannot_replace_adopted_expectations_or_host_paths() {
        let request = json!({"check":"author","subject":{"kind":"value","value":"123"}});
        assert!(serde_json::from_value::<Invocation>(request.clone()).is_ok());
        for field in [
            "spec",
            "path",
            "inputs",
            "expected_author",
            "argv",
            "result",
            "engine",
        ] {
            let mut changed = request.clone();
            changed[field] = json!("untrusted");
            assert!(
                serde_json::from_value::<Invocation>(changed).is_err(),
                "{field}"
            );
        }
    }
}
