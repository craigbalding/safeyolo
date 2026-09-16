//! Discovery reads retain global reporting and leave request bodies untouched.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{self, BodyObservation, Controls, PolicyState, Request, RequestBody},
    agent_discovery::AgentDiscovery,
    audit::{Settings, Writer},
    network_guard::Identity,
    tasks::Registry,
};
use serde_json::{Value, json};

struct Unread;
impl Body for Unread {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        panic!("discovery read must not poll the request body");
    }
}

#[tokio::test]
async fn discovery_auth_precedes_global_reporting_without_body_reads() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, b"synthetic-discovery-api").unwrap();
    let writer = Arc::new(Writer::new(
        directory.path().join("audit.jsonl"),
        Settings::default(),
    ));
    let discovery = Arc::new(AgentDiscovery::new());
    let map = directory.path().join("map.json");
    std::fs::write(
        &map,
        br#"{"alice":{"ip":"192.0.2.10"},"bob":{"ip":"192.0.2.11"}}"#,
    )
    .unwrap();
    discovery.configure(map.to_str().unwrap(), &writer).unwrap();
    for (method, authorization, identity, installed, status, error) in [
        (
            "POST",
            None,
            Identity::Unavailable,
            true,
            405,
            Some("Method Not Allowed"),
        ),
        (
            "GET",
            None,
            Identity::Unavailable,
            true,
            401,
            Some("Authorization required"),
        ),
        (
            "GET",
            Some(b"Bearer wrong".as_slice()),
            Identity::Resolved("alice"),
            true,
            401,
            Some("Invalid agent token"),
        ),
        (
            "GET",
            Some(b"Bearer synthetic-discovery-api".as_slice()),
            Identity::Resolved("alice"),
            false,
            503,
            Some("service-discovery addon not loaded"),
        ),
        (
            "GET",
            Some(b"Bearer synthetic-discovery-api".as_slice()),
            Identity::Unavailable,
            true,
            200,
            None,
        ),
        (
            "GET",
            Some(b"Bearer synthetic-discovery-api".as_slice()),
            Identity::Conflict,
            true,
            200,
            None,
        ),
        (
            "GET",
            Some(b"Bearer synthetic-discovery-api".as_slice()),
            Identity::Resolved("bob"),
            true,
            200,
            None,
        ),
    ] {
        let mut body = Unread;
        let mut observation = BodyObservation::default();
        let result = agent_api::respond_with_body(
            Request {
                method,
                path_and_query: "/agents?agent=forged",
                authorization,
                identity,
                client_ip: None,
                request_id: "native-id",
            },
            &token,
            PolicyState::Unavailable,
            &Registry::default(),
            0.,
            Controls {
                discovery: installed.then_some(&discovery),
                audit: Some(&writer),
                flows: None,
                circuits: None,
                declarations: None,
            },
            RequestBody {
                body: &mut body,
                content_encoding: b"invalid-coding",
                content_length: Some(100),
                observation: Some(&mut observation),
            },
        )
        .await
        .unwrap();
        assert_eq!(result.response.status, status);
        assert_eq!(result.policy_evaluations, 0);
        assert!(observation.decoded_size.is_none() && observation.encoded_size.is_none());
        let value: Value = serde_json::from_slice(&result.response.body_bytes()).unwrap();
        if let Some(error) = error {
            assert_eq!(value["error"], error);
        } else {
            assert_eq!(
                value,
                json!({"agents":{"alice":{"ip":"192.0.2.10"},"bob":{"ip":"192.0.2.11"}},"count":2})
            );
        }
    }
}
