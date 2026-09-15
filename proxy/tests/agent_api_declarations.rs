//! Body ownership and failure boundaries not representable as complete wire requests.

use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{self, Controls, DeclarationContext, PolicyState, Request, RequestBody},
    network_guard::Identity,
    tasks::Registry,
    test_context::{self, TestContext, TrustedIdentity},
};
use serde_json::{Value, json};

const AUTH: &[u8] = b"Bearer synthetic-declaration-test";

fn request() -> Request<'static> {
    Request {
        method: "POST",
        path_and_query: "/api/test-context/current",
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: Some("10.0.0.2"),
        request_id: "declaration-body-fixture",
    }
}

struct Frames {
    frames: VecDeque<Result<Frame<Bytes>, &'static str>>,
    polls: usize,
    forbid_poll: bool,
}
impl Body for Frames {
    type Data = Bytes;
    type Error = &'static str;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        assert!(
            !self.forbid_poll,
            "body polled before API prerequisite checks"
        );
        self.polls += 1;
        Poll::Ready(self.frames.pop_front())
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, b"synthetic-declaration-test").unwrap();
    (directory, token)
}

#[tokio::test]
async fn method_auth_identity_owner_and_read_routes_never_poll_declaration_body() {
    let (_directory, token) = fixture();
    let owner = TestContext::default();
    for (request, available, status) in [
        (
            Request {
                method: "PUT",
                authorization: None,
                ..request()
            },
            true,
            405,
        ),
        (
            Request {
                path_and_query: "/health",
                authorization: None,
                ..request()
            },
            true,
            405,
        ),
        (
            Request {
                authorization: None,
                ..request()
            },
            true,
            401,
        ),
        (
            Request {
                authorization: Some(b"Bearer wrong-fixture"),
                ..request()
            },
            true,
            401,
        ),
        (
            Request {
                identity: Identity::Conflict,
                client_ip: None,
                ..request()
            },
            false,
            403,
        ),
        (
            Request {
                client_ip: None,
                ..request()
            },
            false,
            403,
        ),
        (request(), false, 503),
        (
            Request {
                method: "GET",
                ..request()
            },
            true,
            200,
        ),
        (
            Request {
                method: "DELETE",
                ..request()
            },
            true,
            200,
        ),
        (
            Request {
                method: "GET",
                path_and_query: "/health",
                ..request()
            },
            true,
            200,
        ),
    ] {
        let mut body = Frames {
            frames: VecDeque::new(),
            polls: 0,
            forbid_poll: true,
        };
        let outcome = agent_api::respond_with_body(
            request,
            &token,
            PolicyState::Unavailable,
            &Registry::default(),
            0.,
            Controls {
                flows: None,
                circuits: None,
                declarations: available.then_some(DeclarationContext {
                    owner: &owner,
                    now: || 10.,
                }),
            },
            RequestBody {
                body: &mut body,
                content_encoding: b"broken-encoding",
                content_length: Some(1),
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.response.status, status);
        assert_eq!(body.polls, 0);
        assert_eq!(outcome.policy_evaluations, 0);
    }
}

#[tokio::test]
async fn truncated_post_preserves_declaration_and_returns_original_transport_failure() {
    let (_directory, token) = fixture();
    let owner = TestContext::default();
    let identity = TrustedIdentity::new("10.0.0.2", "alice").unwrap();
    owner
        .set_declaration(
            &identity,
            test_context::Context::parse("run=old;agent=alice;test=retained").unwrap(),
            None,
            0.,
        )
        .unwrap();
    for (length, cross_threshold) in [(None, false), (Some(20 * 1024 * 1024), false), (None, true)]
    {
        let mut frames = VecDeque::from([Ok(Frame::data(Bytes::from_static(
            br#"{"context":"run=new;agent=alice;test=replacement"}"#,
        )))]);
        if cross_threshold {
            frames.push_back(Ok(Frame::data(Bytes::from(vec![b' '; 10 * 1024 * 1024]))));
        }
        frames.push_back(Err("fixture truncated body"));
        let mut body = Frames {
            frames,
            polls: 0,
            forbid_poll: false,
        };
        let result = agent_api::respond_with_body(
            request(),
            &token,
            PolicyState::Unavailable,
            &Registry::default(),
            0.,
            Controls {
                flows: None,
                circuits: None,
                declarations: Some(DeclarationContext {
                    owner: &owner,
                    now: || 10.,
                }),
            },
            RequestBody {
                body: &mut body,
                content_encoding: b"identity",
                content_length: length,
            },
        )
        .await;
        assert!(matches!(result, Err("fixture truncated body")));
        assert_eq!(body.polls, if cross_threshold { 3 } else { 2 });
        assert_eq!(
            owner
                .get_declaration(&identity, 10.)
                .unwrap()
                .unwrap()
                .context
                .get("run"),
            Some("old")
        );
    }
}

#[tokio::test]
async fn buffered_json_is_parsed_after_eom_and_missing_streamed_content_is_empty_object() {
    let (_directory, token) = fixture();
    let owner = TestContext::default();
    let document = br#"{"context":"run=fixture;agent=claim;test=body","unused":NaN,"ttl":7}"#;
    for (size, known_length, status) in [
        (document.len(), false, 200),
        (10 * 1024 * 1024, true, 200),
        (10 * 1024 * 1024 + 1, true, 400),
        (10 * 1024 * 1024 + 1, false, 400),
    ] {
        let mut encoded = Vec::from(document.as_slice());
        encoded.resize(size, b' ');
        let length = known_length.then_some(size as u64);
        let encoded = Bytes::from(encoded);
        let mut body = Frames {
            frames: VecDeque::from([
                Ok(Frame::data(encoded.slice(..8))),
                Ok(Frame::data(Bytes::new())),
                Ok(Frame::data(encoded.slice(8..))),
                Ok(Frame::trailers(hyper::HeaderMap::new())),
            ]),
            polls: 0,
            forbid_poll: false,
        };
        let outcome = agent_api::respond_with_body(
            request(),
            &token,
            PolicyState::Unavailable,
            &Registry::default(),
            0.,
            Controls {
                flows: None,
                circuits: None,
                declarations: Some(DeclarationContext {
                    owner: &owner,
                    now: || 10.,
                }),
            },
            RequestBody {
                body: &mut body,
                content_encoding: b"identity",
                content_length: length,
            },
        )
        .await
        .unwrap();
        assert_eq!(body.polls, 5);
        assert_eq!(outcome.response.status, status);
        let response: Value = serde_json::from_slice(&outcome.response.body_bytes()).unwrap();
        if status == 200 {
            assert_eq!(response["expires_in"], json!(7));
            let audit = outcome.audit.unwrap();
            assert_eq!(audit.kind, agent_api::AuditKind::TestContextDeclared);
            assert_eq!(audit.agent.as_deref(), Some("alice"));
            assert_eq!(audit.details["source_id"], "10.0.0.2");
            assert_eq!(audit.details["test_agent_match"], false);
        } else {
            assert_eq!(response["error"], "context must be a string");
            assert!(outcome.audit.is_none());
        }
    }
}
