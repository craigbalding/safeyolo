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
        let grant_id = grant_id.to_owned();
        let store = store.clone();
        let writer = audit.writer.clone();
        let client_ip = audit.client_ip.to_owned();
        let owner = audit.mutation_owner.clone();
        return run_mutation(owner, move || {
            let revoked = store
                .revoke_grant_by_id(&grant_id, time::OffsetDateTime::now_utc(), |_| Ok(()))
                .map_err(|_| Error::ServiceMutation)?;
            if !revoked {
                return Ok(response(
                    StatusCode::NOT_FOUND,
                    json!({"error":format!("grant '{grant_id}' not found")}),
                ));
            }
            emit_writer(
                &writer,
                "admin.gateway_grant_revoked",
                "Gateway grant revoked",
                None,
                json!({"client_ip":client_ip,"grant_id":grant_id}),
                crate::audit::Decision::Allow,
            )?;
            Ok(response(
                StatusCode::OK,
                json!({"status":"revoked","grant_id":grant_id}),
            ))
        })
        .await;
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
        let agent = agent.to_owned();
        let service = service.to_owned();
        let request_method = method.to_owned();
        let scope_path = scope_path.to_owned();
        let writer = audit.writer.clone();
        let client_ip = audit.client_ip.to_owned();
        let owner = audit.mutation_owner.clone();
        let store = store.clone();
        return run_mutation(owner, move || {
            let addition = store
                .add_grant(
                    crate::grants::GrantRequest {
                        agent: agent.clone(),
                        service: service.clone(),
                        method: request_method.clone(),
                        path: scope_path.clone(),
                        scope,
                    },
                    time::OffsetDateTime::now_utc(),
                    |_| Ok(()),
                )
                .map_err(|_| Error::ServiceMutation)?;
            let grant_id = addition.grant.grant_id.clone();
            emit_writer(
                &writer,
                "admin.gateway_grant",
                "Gateway grant added",
                Some(&agent),
                json!({
                    "client_ip":client_ip,
                    "grant_id":grant_id,
                    "agent":agent,
                    "service":service,
                    "method":request_method,
                    "path":scope_path,
                    "scope":addition.grant.scope,
                }),
                crate::audit::Decision::Allow,
            )?;
            Ok(response(
                StatusCode::OK,
                json!({"grant_id":addition.grant.grant_id,"status":"granted"}),
            ))
        })
        .await;
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
        let operations = match fields.get("grantable_operations") {
            None => Vec::new(),
            Some(Value::Array(values)) => {
                let mut operations = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value) = value.as_str() else {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            json!({"error":"grantable_operations must be a string list"}),
                        ));
                    };
                    operations.push(value.to_owned());
                }
                operations
            }
            Some(_) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"grantable_operations must be a string list"}),
                ));
            }
        };
        let binding = crate::contracts::ContractBinding {
            binding_id: String::new(),
            agent: agent.to_owned(),
            service: service.to_owned(),
            capability: capability.to_owned(),
            template: text(fields, "template").unwrap_or_default().to_owned(),
            bound_values: bindings.clone(),
            grantable_operations: operations,
        };
        let agent = agent.to_owned();
        let service = service.to_owned();
        let capability = capability.to_owned();
        let binding_fields = bindings.keys().cloned().collect::<Vec<_>>();
        let writer = audit.writer.clone();
        let client_ip = audit.client_ip.to_owned();
        let owner = audit.mutation_owner.clone();
        let store = store.clone();
        return run_mutation(owner, move || {
            let addition = store
                .approve_binding(binding, time::OffsetDateTime::now_utc(), |_| Ok(()))
                .map_err(|_| Error::ServiceMutation)?;
            let binding_id = addition.binding.binding.binding_id.clone();
            emit_writer(
                &writer,
                "admin.contract_binding_approved",
                "Contract binding approved",
                Some(&agent),
                json!({
                    "client_ip":client_ip,
                    "binding_id":binding_id,
                    "agent":agent,
                    "service":service,
                    "capability":capability,
                    "template":addition.binding.binding.template,
                    "binding_fields":binding_fields,
                }),
                crate::audit::Decision::Allow,
            )?;
            Ok(response(
                StatusCode::OK,
                json!({"binding_id":addition.binding.binding.binding_id,"status":"bound"}),
            ))
        })
        .await;
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

async fn run_mutation(
    owner: super::ServiceMutationOwner,
    work: impl FnOnce() -> Result<Outcome, Error> + Send + 'static,
) -> Result<Outcome, Error> {
    owner
        .spawn_blocking(work)
        .await?
        .await
        .map_err(|_| Error::ServiceMutation)?
}

fn emit_writer(
    writer: &crate::audit::Writer,
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
    writer
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
            r#"{"agent":"alice","service":"mail","capability":"send","template":"mail.v1","bindings":{"tenant":"tenant-alpha","integer":9223372036854775807,"array":[1,2.5,true,{"nested":3}]},"grantable_operations":["send"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(bound["binding_id"].as_str().is_some());
        let expected_values = json!({
            "tenant": "tenant-alpha",
            "integer": i64::MAX,
            "array": [1, 2.5, true, {"nested": 3}],
        })
        .as_object()
        .unwrap()
        .clone();
        assert_eq!(
            store
                .binding_for_agent("alice", "mail", "send")
                .unwrap()
                .unwrap()
                .binding
                .bound_values,
            expected_values
        );
        // Exercise the retained operator consumer's durable save and reload
        // path, preserving typed scalar and structured binding values exactly.
        store
            .reload(time::OffsetDateTime::now_utc(), |_| Ok(()))
            .unwrap();
        assert!(
            store
                .binding_for_agent("alice", "mail", "send")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .binding_for_agent("alice", "mail", "send")
                .unwrap()
                .unwrap()
                .binding
                .bound_values,
            expected_values
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

    #[tokio::test]
    async fn non_string_operation_names_are_rejected_without_filtering() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        std::fs::write(&policy, "[agents.alice]\n").unwrap();
        let store = crate::grants::Store::open(&policy, time::OffsetDateTime::now_utc()).unwrap();
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        let owner = crate::admin_api::ServiceMutationOwner::default();
        let (status, body) = call(
            &store,
            &writer,
            &owner,
            "/admin/gateway/contract-binding",
            Method::POST,
            r#"{"agent":"alice","service":"mail","capability":"send","bindings":{"tenant":"alpha"},"grantable_operations":["send",3]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "grantable_operations must be a string list");
        assert!(
            store
                .binding_for_agent("alice", "mail", "send")
                .unwrap()
                .is_none()
        );
        assert!(!directory.path().join("audit.jsonl").exists());
    }

    #[tokio::test]
    async fn retained_binding_api_rejects_unsupported_large_integer_explicitly() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        std::fs::write(&policy, "[agents.alice]\n").unwrap();
        let store = crate::grants::Store::open(&policy, time::OffsetDateTime::now_utc()).unwrap();
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        let owner = crate::admin_api::ServiceMutationOwner::default();
        let source = r#"{"agent":"alice","service":"mail","capability":"send","template":"mail.v1","bindings":{"limit":18446744073709551616},"grantable_operations":["send"]}"#;
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/gateway/contract-binding")
            .header("Content-Length", source.len())
            .body(Full::new(Bytes::copy_from_slice(source.as_bytes())))
            .unwrap();
        let outcome = {
            let audit = ServiceAudit {
                writer: &writer,
                client_ip: "127.0.0.1",
                target: "/admin/gateway/contract-binding",
                mutation_owner: &owner,
                gateway_store: Some(&store),
            };
            respond(request, "/admin/gateway/contract-binding", Some(&audit)).await
        };
        // Native durable bindings retain the source integer through parsing,
        // then reject values outside TOML's signed 64-bit range before any
        // state or audit publication. This is the explicit D22 contract.
        assert!(matches!(outcome, Err(Error::ServiceMutation)));
        assert!(
            store
                .binding_for_agent("alice", "mail", "send")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::read_to_string(&policy).unwrap(),
            "[agents.alice]\n"
        );
        assert!(!directory.path().join("audit.jsonl").exists());
    }

    #[tokio::test]
    async fn canceled_mutation_is_drained_and_audited_after_lock_release() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        std::fs::write(&policy, "[agents.alice]\n").unwrap();
        let store =
            Arc::new(crate::grants::Store::open(&policy, time::OffsetDateTime::now_utc()).unwrap());
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        let owner = crate::admin_api::ServiceMutationOwner::default();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.path().join(".policy.toml.lock"))
            .unwrap();
        lock.lock().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/gateway/grant")
            .header("Content-Length", 85)
            .body(Full::new(Bytes::from_static(
                br#"{"agent":"alice","service":"mail","method":"POST","path":"/v1/send"}"#,
            )))
            .unwrap();
        let request_store = store.clone();
        let request_writer = writer.clone();
        let request_owner = owner.clone();
        let task = tokio::spawn(async move {
            let audit = ServiceAudit {
                writer: &request_writer,
                client_ip: "127.0.0.1",
                target: "/admin/gateway/grant",
                mutation_owner: &request_owner,
                gateway_store: Some(request_store.as_ref()),
            };
            respond(request, "/admin/gateway/grant", Some(&audit)).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while Arc::strong_count(&writer) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        owner.stop_admission().await;
        lock.unlock().unwrap();
        owner.drain().await;
        let grants = store.list_grants(time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(grants.len(), 1);
        assert!(
            writer
                .wait_for_drain(std::time::Duration::from_secs(3))
                .unwrap()
        );
        let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
        assert_eq!(audit.matches("admin.gateway_grant").count(), 1);
    }

    #[tokio::test]
    async fn mutation_storage_and_audit_failures_do_not_claim_success() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.toml");
        std::fs::write(&policy, "[agents.alice]\n").unwrap();
        let store = crate::grants::Store::open(&policy, time::OffsetDateTime::now_utc()).unwrap();
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        let owner = crate::admin_api::ServiceMutationOwner::default();
        let body = r#"{"agent":"alice","service":"mail","method":"POST","path":"/v1/send"}"#;
        let lock_path = directory.path().join(".policy.toml.lock");
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::create_dir(&lock_path).unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/gateway/grant")
            .header("Content-Length", body.len())
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap();
        let outcome = {
            let audit = ServiceAudit {
                writer: &writer,
                client_ip: "127.0.0.1",
                target: "/admin/gateway/grant",
                mutation_owner: &owner,
                gateway_store: Some(&store),
            };
            respond(request, "/admin/gateway/grant", Some(&audit)).await
        };
        assert!(matches!(outcome, Err(Error::ServiceMutation)));
        assert!(
            store
                .list_grants(time::OffsetDateTime::now_utc())
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir(&lock_path).unwrap();
        writer.poison_for_test();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/gateway/grant")
            .header("Content-Length", body.len())
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap();
        let outcome = {
            let audit = ServiceAudit {
                writer: &writer,
                client_ip: "127.0.0.1",
                target: "/admin/gateway/grant",
                mutation_owner: &owner,
                gateway_store: Some(&store),
            };
            respond(request, "/admin/gateway/grant", Some(&audit)).await
        };
        assert!(matches!(outcome, Err(Error::Audit(_))));
        assert_eq!(
            store
                .list_grants(time::OffsetDateTime::now_utc())
                .unwrap()
                .len(),
            1
        );
    }
}
