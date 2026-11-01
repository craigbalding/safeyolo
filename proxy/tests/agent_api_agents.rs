//! Listener reads retain global reporting and leave request bodies untouched.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_activity::AgentActivity,
    agent_api::{
        self, AgentReportContext, BodyObservation, Controls, PolicyState, Request, RequestBody,
    },
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
async fn listener_auth_precedes_global_reporting_without_body_reads() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, b"synthetic-discovery-api").unwrap();
    let writer = Arc::new(Writer::new(
        directory.path().join("audit.jsonl"),
        Settings::default(),
    ));
    let activity = AgentActivity::default();
    let listeners = ["alice", "bob", "opaque"]
        .into_iter()
        .zip(["192.0.2.10", "192.0.2.11", "/private/declaration-slot"])
        .map(|(agent, ip)| safeyolo_proxy::AgentListener {
            agent_id: agent.into(),
            socket_path: directory.path().join(format!("{agent}.sock")),
            source_id: Some(ip.into()),
        })
        .collect::<Vec<_>>();
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
            Some("agent listener report unavailable"),
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
                gateway: None,
                memory: None,
                traces: None,
                agents: installed.then_some(AgentReportContext {
                    activity: &activity,
                    listeners: &listeners,
                }),
                audit: Some(&writer),
                flows: None,
                circuits: None,
                declarations: None,
                coord: None,
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
        let encoded = result.response.body_bytes();
        assert!(!String::from_utf8_lossy(&encoded).contains("/private/declaration-slot"));
        let value: Value = serde_json::from_slice(&encoded).unwrap();
        if let Some(error) = error {
            assert_eq!(value["error"], error);
        } else {
            assert_eq!(
                value,
                json!({"agents":{"alice":{"ip":"192.0.2.10"},"bob":{"ip":"192.0.2.11"},"opaque":{"ip":null}},"count":3})
            );
        }
    }
}
