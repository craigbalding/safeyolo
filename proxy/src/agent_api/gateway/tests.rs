//! Replay actual source catalog responses through native auth and body dispatch.

use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
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
