//! Native operator gateway binding and risky-grant consumers.
//!
//! These routes deliberately call the process-owned `grants::Store`; they do
//! not maintain a second grant map or publish a hand-built gateway snapshot.

use bytes::Bytes;
use hyper::{Method, Request, StatusCode, body::Body};
use serde_json::{Value, json};

use super::{Error, Json, Outcome, ParsedBody, ServiceAudit, read_json, response};

pub(super) async fn respond<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    audit: Option<&ServiceAudit<'_>>,
) -> Result<Outcome, Error> {
    let Some(audit) = audit else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"Gateway grant store unavailable"}),
        ));
    };
    let Some(store) = audit.gateway_store else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"Service gateway not available"}),
        ));
    };
    let method = request.method().clone();
    if method == Method::GET && path == "/admin/gateway/grants" {
        let grants = store
            .list_grants(time::OffsetDateTime::now_utc())
            .map_err(|_| Error::ServiceMutation)?;
        return Ok(response(StatusCode::OK, json!({"grants":grants})));
    }
    if method == Method::DELETE {
        let Some(grant_id) = path.strip_prefix("/admin/gateway/grants/") else {
            return Ok(response(
                StatusCode::NOT_FOUND,
                json!({"error":"not found"}),
            ));
        };
        if grant_id.is_empty() {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"missing grant_id"}),
            ));
        }
        let revoked = store
            .revoke_grant_by_id(grant_id, time::OffsetDateTime::now_utc(), |_| Ok(()))
            .map_err(|_| Error::ServiceMutation)?;
        if !revoked {
            return Ok(response(
                StatusCode::NOT_FOUND,
                json!({"error":format!("grant '{grant_id}' not found")}),
            ));
        }
        emit(
            audit,
            "admin.gateway_grant_revoked",
            "Gateway grant revoked",
            None,
            json!({"grant_id":grant_id}),
            crate::audit::Decision::Allow,
        )?;
        return Ok(response(
            StatusCode::OK,
            json!({"status":"revoked","grant_id":grant_id}),
        ));
    }
    if method != Method::POST {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"not found"}),
        ));
    }
    let data = match read_json(request).await? {
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => Json(Value::Null),
        ParsedBody::Value(value) => value,
    };
    let Some(fields) = data.0.as_object() else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"missing request body"}),
        ));
    };
    if path == "/admin/gateway/grant" {
        let Some(agent) = text(fields, "agent") else {
            return missing("agent, service, method, path");
        };
        let Some(service) = text(fields, "service") else {
            return missing("agent, service, method, path");
        };
        let Some(method) = text(fields, "method") else {
            return missing("agent, service, method, path");
        };
        let Some(scope_path) = text(fields, "path") else {
            return missing("agent, service, method, path");
        };
        let default_lifetime = Value::String("once".into());
        let lifetime = fields.get("lifetime").unwrap_or(&default_lifetime);
        let scope = match crate::grants::GrantScope::from_admin_lifetime(lifetime) {
            Ok(scope) => scope,
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"lifetime must be once, session, or remembered"}),
                ));
            }
        };
        let addition = store
            .add_grant(
                crate::grants::GrantRequest {
                    agent: agent.to_owned(),
                    service: service.to_owned(),
                    method: method.to_owned(),
                    path: scope_path.to_owned(),
                    scope,
                },
                time::OffsetDateTime::now_utc(),
                |_| Ok(()),
            )
            .map_err(|_| Error::ServiceMutation)?;
        let grant_id = addition.grant.grant_id.clone();
        emit(
            audit,
            "admin.gateway_grant",
            "Gateway grant added",
            Some(agent),
            json!({
                "grant_id":grant_id,
                "service":service,
                "method":method,
                "path":scope_path,
                "scope":addition.grant.scope,
            }),
            crate::audit::Decision::Allow,
        )?;
        return Ok(response(
            StatusCode::OK,
            json!({"grant_id":addition.grant.grant_id,"status":"granted"}),
        ));
    }
    if path == "/admin/gateway/contract-binding" {
        let Some(agent) = text(fields, "agent") else {
            return missing("agent, service, capability");
        };
        let Some(service) = text(fields, "service") else {
            return missing("agent, service, capability");
        };
        let Some(capability) = text(fields, "capability") else {
            return missing("agent, service, capability");
        };
        let Some(bindings) = fields
            .get("bindings")
            .and_then(Value::as_object)
            .filter(|v| !v.is_empty())
        else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"bindings must be a non-empty object"}),
            ));
        };
        let operations = fields
            .get("grantable_operations")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let binding = crate::contracts::ContractBinding {
            binding_id: String::new(),
            agent: agent.to_owned(),
            service: service.to_owned(),
            capability: capability.to_owned(),
            template: text(fields, "template").unwrap_or_default().to_owned(),
            bound_values: bindings.clone(),
            grantable_operations: operations,
        };
        let addition = store
            .approve_binding(binding, time::OffsetDateTime::now_utc(), |_| Ok(()))
            .map_err(|_| Error::ServiceMutation)?;
        let binding_id = addition.binding.binding.binding_id.clone();
        emit(
            audit,
            "admin.contract_binding_approved",
            "Contract binding approved",
            Some(agent),
            json!({
                "binding_id":binding_id,
                "service":service,
                "capability":capability,
                "template":addition.binding.binding.template,
                "binding_fields":bindings.keys().collect::<Vec<_>>(),
            }),
            crate::audit::Decision::Allow,
        )?;
        return Ok(response(
            StatusCode::OK,
            json!({"binding_id":addition.binding.binding.binding_id,"status":"bound"}),
        ));
    }
    Ok(response(
        StatusCode::NOT_FOUND,
        json!({"error":"not found"}),
    ))
}

fn missing(field: &str) -> Result<Outcome, Error> {
    Ok(response(
        StatusCode::BAD_REQUEST,
        json!({"error":format!("missing required fields: {field}")}),
    ))
}

fn text<'a>(fields: &'a serde_json::Map<String, Value>, field: &str) -> Option<&'a str> {
    fields
        .get(field)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

fn emit(
    audit: &ServiceAudit<'_>,
    name: &str,
    summary: &str,
    agent: Option<&str>,
    details: Value,
    decision: crate::audit::Decision,
) -> Result<(), Error> {
    let mut event = crate::audit::Event::new(
        name,
        crate::audit::Kind::Admin,
        crate::audit::Severity::Medium,
        summary,
    );
    event.addon = Some("admin-api".into());
    event.decision = Some(decision);
    event.agent = agent.map(str::to_owned);
    event.details = crate::circuits::CircuitValue::from(details);
    audit
        .writer
        .emit(event)
        .map(|_| ())
        .map_err(|error| Error::Audit(error.kind()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use std::sync::Arc;

    async fn call(
        store: &crate::grants::Store,
        writer: &Arc<crate::audit::Writer>,
        owner: &crate::admin_api::ServiceMutationOwner,
        path: &str,
        method: Method,
        body: &str,
    ) -> (StatusCode, Value) {
        let audit = ServiceAudit {
            writer,
            client_ip: "127.0.0.1",
            target: path,
            mutation_owner: owner,
            gateway_store: Some(store),
        };
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Content-Length", body.len())
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap();
        let outcome = respond(request, path, Some(&audit)).await.unwrap();
        let status = outcome.status();
        let body = outcome
            .into_response()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn operator_routes_persist_and_revoke_shared_grants_and_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        std::fs::write(&policy, "[agents.alice]\n").unwrap();
        let store = crate::grants::Store::open(&policy, time::OffsetDateTime::now_utc()).unwrap();
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        let owner = crate::admin_api::ServiceMutationOwner::default();

        let (status, added) = call(
            &store,
            &writer,
            &owner,
            "/admin/gateway/grant",
            Method::POST,
            r#"{"agent":"alice","service":"mail","method":"POST","path":"/v1/send","lifetime":"once"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let grant_id = added["grant_id"].as_str().unwrap();
        let (status, listed) = call(
            &store,
            &writer,
            &owner,
            "/admin/gateway/grants",
            Method::GET,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["grants"][0]["grant_id"], grant_id);

        let (status, bound) = call(
            &store,
            &writer,
            &owner,
            "/admin/gateway/contract-binding",
            Method::POST,
            r#"{"agent":"alice","service":"mail","capability":"send","template":"mail.v1","bindings":{"tenant":"tenant-alpha"},"grantable_operations":["send"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(bound["binding_id"].as_str().is_some());
        assert!(
            store
                .binding_for_agent("alice", "mail", "send")
                .unwrap()
                .is_some()
        );

        let (status, revoked) = call(
            &store,
            &writer,
            &owner,
            &format!("/admin/gateway/grants/{grant_id}"),
            Method::DELETE,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(revoked["status"], "revoked");
        assert!(
            store
                .list_grants(time::OffsetDateTime::now_utc())
                .unwrap()
                .is_empty()
        );
        assert!(
            writer
                .wait_for_drain(std::time::Duration::from_secs(3))
                .unwrap()
        );
        let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
        assert!(audit.contains("admin.gateway_grant"));
        assert!(audit.contains("admin.contract_binding_approved"));
        assert!(audit.contains("admin.gateway_grant_revoked"));
        assert!(!audit.contains("tenant-alpha"));
    }
}
