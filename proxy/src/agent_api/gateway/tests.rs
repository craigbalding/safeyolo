//! Replay actual source catalog responses through native auth and body dispatch.

use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Frame};
use serde_json::{Map, Value, json};

use super::*;
use crate::{
    agent_api::{self, BodyObservation, Controls, PolicyState, RequestBody},
    network_guard::Identity,
    policy::{Format, Policy},
    services::Registry,
};

const TOKEN: &str = "owned-service-catalog-api-token";

struct UnreadBody;
impl Body for UnreadBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        panic!("catalog handler must not read request content");
    }
}

fn registry(defaults: &Value, kind: &str) -> Option<Arc<Registry>> {
    if kind == "absent" {
        return None;
    }
    let mut builtin = Vec::new();
    let mut user = Vec::new();
    for (path, definition) in defaults["registries"][kind]["files"].as_object().unwrap() {
        let (source, filename) = path.split_once('/').unwrap();
        let document = definition
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| definition.to_string());
        if source == "builtin" {
            builtin.push((filename.to_owned(), document));
        } else {
            assert_eq!(source, "user");
            user.push((filename.to_owned(), document));
        }
    }
    Some(Arc::new(Registry::from_sources(&builtin, &user).unwrap()))
}

fn policy(defaults: &Value, spec: &Value) -> Policy {
    let mut bindings = spec["bindings"].as_array().unwrap().clone();
    if let Some(extra) = spec.get("extra_binding") {
        bindings.push(extra.clone());
    }
    let mut tokens = Map::new();
    let mut timestamps = Vec::new();
    for binding in bindings {
        let mut account = binding.get("account").cloned().unwrap_or(json!("agent"));
        let mut capability = binding["capability"].clone();
        for (field, target) in [("account", &mut account), ("capability", &mut capability)] {
            if let Some(value) = binding.get(format!("{field}_datetime")) {
                let marker = format!("__owned_source_datetime_{}__", timestamps.len());
                timestamps.push((marker.clone(), value.as_str().unwrap().to_owned()));
                *target = Value::from(marker);
            }
        }
        tokens.insert(
            binding["token"].as_str().unwrap().to_owned(),
            json!({
                "agent":binding["agent"], "service":binding["service"],
                    "capability":capability, "token":"owned-vault-reference", "account":account,
            }),
        );
    }
    let mut document = json!({"gateway":{"host_map":spec["hosts"],"token_map":tokens}}).to_string();
    let format = if timestamps.is_empty() {
        Format::Json
    } else {
        // JSON flow mappings are YAML too. Unquoted scalars keep the source
        // fixture's actual datetime types through native parsing.
        for (marker, value) in timestamps {
            document = document.replace(&serde_json::to_string(&marker).unwrap(), &value);
        }
        Format::Yaml
    };
    Policy::parse_with_registry_at(
        &document,
        format,
        registry(defaults, spec["registry"].as_str().unwrap()),
        0.,
    )
    .unwrap()
}

fn access_policy(service: &str) -> Policy {
    let registry =
        Arc::new(Registry::from_sources(&[("demo.yaml".into(), service.into())], &[]).unwrap());
    Policy::parse_with_registry_at(r#"{"gateway":{}}"#, Format::Json, Some(registry), 0.).unwrap()
}

async fn access<'a>(
    policy: &'a Policy,
    body: &str,
    identity: Identity<'_>,
) -> agent_api::Outcome<'a> {
    gateway_call(policy, "/gateway/request-access", body, identity).await
}

async fn gateway_call<'a>(
    policy: &'a Policy,
    path: &str,
    body: &str,
    identity: Identity<'_>,
) -> agent_api::Outcome<'a> {
    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("agent_token");
    std::fs::write(&token_path, TOKEN).unwrap();
    let mut body = Full::new(Bytes::copy_from_slice(body.as_bytes()));
    let tasks = crate::tasks::Registry::default();
    let authorization = format!("Bearer {TOKEN}");
    agent_api::respond_with_body(
        Request {
            method: "POST",
            path_and_query: path,
            authorization: Some(authorization.as_bytes()),
            identity,
            client_ip: Some("192.0.2.10"),
            request_id: "owned-access-request",
        },
        &token_path,
        PolicyState::Ready(policy),
        &tasks,
        0.,
        Controls {
            gateway: Some(GatewayContext {
                snapshot: policy.gateway(),
            }),
            memory: None,
            traces: None,
            discovery: None,
            audit: None,
            flows: None,
            circuits: None,
            declarations: None,
            coord: None,
        },
        RequestBody {
            body: &mut body,
            content_encoding: b"",
            content_length: None,
            observation: None,
        },
    )
    .await
    .unwrap()
}

const NO_CONTRACT_SERVICE: &str = r#"
schema_version: 1
name: demo
default_host: api.demo.invalid
description: Demo service
capabilities:
  read:
    description: Read demo data
    routes: []
"#;

const CONTRACT_SERVICE: &str = r#"
schema_version: 1
name: demo
default_host: api.demo.invalid
capabilities:
  read:
    routes:
      - methods: [GET]
        path: /v1/items/{id}
    contract:
      template: demo.read.v1
      bindings:
        approved:
          source: operator
          type: enum
          options: [alpha, beta]
          visible_to_operator: true
      operations:
        - name: read_item
          request:
            method: GET
            path: /v1/items/{id}
            path_params:
              id:
                equals_var: approved
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
        response_validators: declared
"#;

#[tokio::test]
async fn contract_access_returns_challenge_and_submit_emits_binding_approval() {
    let policy = access_policy(CONTRACT_SERVICE);
    let challenge = access(
        &policy,
        r#"{"service":"demo","capability":"read"}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(challenge.response.status, 200);
    let challenge_body: Value = serde_json::from_slice(&challenge.response.body_bytes()).unwrap();
    assert_eq!(challenge_body["decision"], "needs_contract_binding");
    assert_eq!(challenge_body["template"], "demo.read.v1");
    assert_eq!(challenge_body["bindings"]["approved"]["type"], "enum");
    assert_eq!(
        challenge_body["grantable_operations"][0]["name"],
        "read_item"
    );

    let submitted = gateway_call(
        &policy,
        "/gateway/submit-binding",
        r#"{"service":"demo","capability":"read","bindings":{"approved":"beta"},"purpose_code":"review"}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(submitted.response.status, 202);
    let body: Value = serde_json::from_slice(&submitted.response.body_bytes()).unwrap();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["bindings"]["approved"], "beta");
    let audit = submitted.audit.as_ref().expect("binding approval intent");
    assert_eq!(audit.kind, agent_api::AuditKind::GatewayBindingSubmitted);
    let event = audit.to_event();
    assert_eq!(event.event, "gateway.submit_binding");
    assert_eq!(
        event.approval.as_ref().unwrap().approval_type,
        crate::audit::ApprovalType::ContractBinding
    );
    assert_eq!(event.approval.as_ref().unwrap().key, "alice:demo:read");
}

#[tokio::test]
async fn contract_submit_rejects_unknown_or_invalid_values_without_approval() {
    let policy = access_policy(CONTRACT_SERVICE);
    let invalid = gateway_call(
        &policy,
        "/gateway/submit-binding",
        r#"{"service":"demo","capability":"read","bindings":{"approved":"other"}}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(invalid.response.status, 200);
    let body: Value = serde_json::from_slice(&invalid.response.body_bytes()).unwrap();
    assert_eq!(body["decision"], "denied_out_of_scope");
    assert!(invalid.audit.is_none());
}

#[tokio::test]
async fn twenty_actual_source_catalog_responses_match_without_reading_a_body() {
    let source: Value =
        serde_json::from_str(include_str!("../../../tests/service_catalog_source.json")).unwrap();
    let defaults = &source["api_defaults"];
    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("agent_token");
    std::fs::write(&token_path, TOKEN).unwrap();
    let rows = source["api_rows"].as_array().unwrap();
    assert_eq!(rows.len(), 20);
    for row in rows {
        let mut spec = defaults.clone();
        for (key, value) in row["input"].as_object().unwrap() {
            spec[key] = value.clone();
        }
        let policy = policy(defaults, &spec);
        let before = policy.engine_stats().unwrap();
        let gateway = spec["gateway"]
            .as_bool()
            .unwrap()
            .then_some(GatewayContext {
                snapshot: policy.gateway(),
            });
        let mut path = spec["path"].as_str().unwrap().to_owned();
        if !spec["query"].as_str().unwrap().is_empty() {
            path.push('?');
            path.push_str(spec["query"].as_str().unwrap());
        }
        let identity = if spec.get("metadata_agent").is_some() {
            Identity::Conflict
        } else {
            spec["agent"]
                .as_str()
                .map_or(Identity::Unavailable, Identity::Resolved)
        };
        let supplied = format!("Bearer {TOKEN}");
        let authorization = match spec["auth"].as_str().unwrap() {
            "missing" => None,
            "valid" => Some(supplied.as_bytes()),
            "wrong" => Some(&b"Bearer owned-wrong"[..]),
            other => panic!("unknown auth recipe {other}"),
        };
        let mut body = UnreadBody;
        let mut observed = BodyObservation::default();
        let tasks = crate::tasks::Registry::default();
        let outcome = agent_api::respond_with_body(
            Request {
                method: spec["method"].as_str().unwrap(),
                path_and_query: &path,
                authorization,
                identity,
                client_ip: Some("192.0.2.10"),
                request_id: "owned-catalog-request",
            },
            &token_path,
            PolicyState::Ready(&policy),
            &tasks,
            0.,
            Controls {
                gateway,
                memory: None,
                traces: None,
                discovery: None,
                audit: None,
                flows: None,
                circuits: None,
                declarations: None,
                coord: None,
            },
            RequestBody {
                body: &mut body,
                content_encoding: b"gzip",
                content_length: Some(100),
                observation: Some(&mut observed),
            },
        )
        .await
        .unwrap();
        let name = spec["name"].as_str().unwrap();
        assert_eq!(
            outcome.response.status,
            row["result"]["status"].as_u64().unwrap() as u16,
            "{name}"
        );
        assert_eq!(
            std::str::from_utf8(&outcome.response.body_bytes()).unwrap(),
            row["result"]["body_text"].as_str().unwrap(),
            "{name}"
        );
        assert!(outcome.handler_owned, "{name}");
        assert_eq!(outcome.blocked_by, row["result"]["blocked_by"], "{name}");
        for (header, value) in &outcome.response.headers {
            assert!(
                row["result"]["headers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!([header, value])),
                "{name}: {header}"
            );
        }
        assert!(
            observed.encoded_size.is_none() && observed.decoded_size.is_none(),
            "{name}"
        );
        assert_eq!(policy.engine_stats().unwrap(), before, "{name}");
        if outcome.response.status == 500 {
            assert_eq!(
                outcome.failure,
                Some(Failure::GatewayReporting(ServiceViewError::Type)),
                "{name}"
            );
        }
    }
}

#[test]
fn encoded_binding_projection_retains_python_infinity_without_reparsing() {
    let policy = Policy::parse_with_registry_at(r#"{"gateway":{"token_map":{"owned-token":{"agent":"alice","service":"demo","capability":1e999,"token":"owned-vault-reference"}}}}"#, Format::Json, None, 0.).unwrap();
    let request = Request {
        method: "GET",
        path_and_query: "/gateway/services",
        authorization: None,
        identity: Identity::Resolved("alice"),
        client_ip: None,
        request_id: "owned-catalog-request",
    };
    let result = respond(
        request,
        Some(GatewayContext {
            snapshot: policy.gateway(),
        }),
    );
    assert_eq!(result.response.status, 200);
    assert_eq!(
        std::str::from_utf8(&result.response.body_bytes()).unwrap(),
        r#"{"agent": "alice", "authorized": {"demo": {"host": "", "token": "owned-token", "capability": Infinity, "account": "agent"}}, "available": []}"#
    );
}

#[tokio::test]
async fn request_access_without_contract_returns_pending_and_existing_approval_event() {
    let policy = access_policy(NO_CONTRACT_SERVICE);
    let outcome = access(
        &policy,
        r#"{"service":"demo","capability":"read","reason":"inbox review"}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(outcome.response.status, 202);
    assert_eq!(
        serde_json::from_slice::<Value>(&outcome.response.body_bytes()).unwrap(),
        json!({
            "status":"pending",
            "agent":"alice",
            "service":"demo",
            "capability":"read",
            "reason":"inbox review",
            "message":"Access request submitted. Operator will review in watch.",
        })
    );
    let audit = outcome.audit.as_ref().expect("approval intent");
    assert_eq!(audit.kind, agent_api::AuditKind::GatewayAccessRequested);
    let event = audit.to_event();
    assert_eq!(event.kind, crate::audit::Kind::Gateway);
    assert_eq!(event.severity, crate::audit::Severity::Critical);
    assert_eq!(
        event.decision,
        Some(crate::audit::Decision::RequireApproval)
    );
    assert_eq!(event.request_id, None);
    assert_eq!(event.host.as_deref(), Some("api.demo.invalid"));
    let approval = event.approval.as_ref().expect("service approval");
    assert_eq!(approval.approval_type, crate::audit::ApprovalType::Service);
    assert_eq!(approval.key, "alice:demo");
    assert_eq!(approval.target, "demo");
    assert_eq!(
        approval.scope_hint.as_object().unwrap().get("capability"),
        Some(&crate::circuits::CircuitValue::Other(Value::String(
            "read".into(),
        )))
    );
    let directory = tempfile::tempdir().unwrap();
    let audit_path = directory.path().join("audit.jsonl");
    let writer = crate::audit::Writer::new(audit_path.clone(), crate::audit::Settings::default());
    assert_eq!(
        writer.emit(event).unwrap(),
        crate::audit::Submission::Queued
    );
    assert!(
        writer
            .wait_for_drain(std::time::Duration::from_secs(1))
            .unwrap()
    );
    let written: Value = serde_json::from_str(
        std::fs::read_to_string(audit_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(written["event"], "gateway.request_access");
    assert_eq!(written["kind"], "gateway");
    assert_eq!(written["decision"], "require_approval");
    assert_eq!(written["approval"]["approval_type"], "service");
    assert_eq!(written["approval"]["scope_hint"]["service"], "demo");
}

#[tokio::test]
async fn request_access_checks_catalog_and_identity_after_body_validation() {
    let policy = access_policy(NO_CONTRACT_SERVICE);
    let malformed = access(&policy, "{not-json", Identity::Resolved("alice")).await;
    assert_eq!(malformed.response.status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&malformed.response.body_bytes()).unwrap(),
        json!({"error":"Invalid JSON body"})
    );
    let missing_fields = access(&policy, "", Identity::Resolved("alice")).await;
    assert_eq!(missing_fields.response.status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&missing_fields.response.body_bytes()).unwrap(),
        json!({"error":"service and capability are required"})
    );
    let missing = access(
        &policy,
        r#"{"service":"absent","capability":"read"}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(missing.response.status, 404);
    assert_eq!(
        serde_json::from_slice::<Value>(&missing.response.body_bytes()).unwrap(),
        json!({"error":"Service 'absent' not found"})
    );
    let identity = access(
        &policy,
        r#"{"service":"demo","capability":"missing"}"#,
        Identity::Unavailable,
    )
    .await;
    assert_eq!(identity.response.status, 403);
    assert_eq!(
        serde_json::from_slice::<Value>(&identity.response.body_bytes()).unwrap(),
        json!({"error":"Could not identify agent"})
    );
    let empty_catalog =
        Policy::parse_with_registry_at(r#"{"gateway":{}}"#, Format::Json, None, 0.).unwrap();
    let unavailable = access(
        &empty_catalog,
        r#"{"service":"demo","capability":"read"}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(unavailable.response.status, 503);
    assert_eq!(
        serde_json::from_slice::<Value>(&unavailable.response.body_bytes()).unwrap(),
        json!({"error":"Service registry not available"})
    );
}

#[tokio::test]
async fn request_access_audit_submission_failure_is_a_500_after_event_construction() {
    let policy = access_policy(NO_CONTRACT_SERVICE);
    let outcome = access(
        &policy,
        r#"{"service":"demo","capability":"read"}"#,
        Identity::Resolved("alice"),
    )
    .await;
    assert_eq!(outcome.response.status, 202);
    assert!(outcome.audit.is_some());
    let failed = outcome.audit_submission_failed(
        Request {
            method: "POST",
            path_and_query: "/gateway/request-access",
            authorization: None,
            identity: Identity::Resolved("alice"),
            client_ip: Some("192.0.2.10"),
            request_id: "owned-access-request",
        },
        crate::audit::ErrorKind::Io,
    );
    assert_eq!(failed.response.status, 500);
    assert_eq!(failed.failure, Some(agent_api::Failure::AuditWrite));
    assert_eq!(
        serde_json::from_slice::<Value>(&failed.response.body_bytes()).unwrap(),
        json!({"error":"Internal error: RuntimeError"})
    );
}

#[tokio::test]
async fn request_access_authenticates_before_polling_body() {
    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("agent_token");
    std::fs::write(&token_path, TOKEN).unwrap();
    let mut body = UnreadBody;
    let tasks = crate::tasks::Registry::default();
    let outcome = agent_api::respond_with_body(
        Request {
            method: "POST",
            path_and_query: "/gateway/request-access",
            authorization: None,
            identity: Identity::Resolved("alice"),
            client_ip: Some("192.0.2.10"),
            request_id: "owned-access-auth-first",
        },
        &token_path,
        PolicyState::Unavailable,
        &tasks,
        0.,
        Controls {
            gateway: None,
            memory: None,
            traces: None,
            discovery: None,
            audit: None,
            flows: None,
            circuits: None,
            declarations: None,
            coord: None,
        },
        RequestBody {
            body: &mut body,
            content_encoding: b"",
            content_length: None,
            observation: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome.response.status, 401);
}
