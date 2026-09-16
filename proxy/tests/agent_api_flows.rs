//! Actual facade/store composition; only synthetic owned records and token files.
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{self, Controls, PolicyState, Request, RequestBody},
    flow_store::{BodyInput, FlowRecord, FlowStore, Settings},
    network_guard::Identity,
    tasks::Registry,
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

const AUTH: &[u8] = b"Bearer synthetic-owned-flow-api";
struct Fixture {
    directory: tempfile::TempDir,
    token: PathBuf,
    store: Arc<FlowStore>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("agent_token");
        std::fs::write(&token, b"synthetic-owned-flow-api").unwrap();
        let store = Arc::new(
            FlowStore::open(&directory.path().join("flows.sqlite"), Settings::default()).unwrap(),
        );
        let source: Value =
            serde_json::from_str(include_str!("agent_api_flows_source.json")).unwrap();
        for record in source["records"].as_array().unwrap() {
            store
                .record(
                    FlowRecord {
                        metadata: record["metadata"].as_object().unwrap(),
                        request_body: Some(BodyInput::complete(&unhex(
                            record["request_hex"].as_str().unwrap(),
                        ))),
                        response_body: Some(BodyInput::complete(&unhex(
                            record["response_hex"].as_str().unwrap(),
                        ))),
                    },
                    1000,
                )
                .unwrap();
        }
        rusqlite::Connection::open(directory.path().join("flows.sqlite"))
            .unwrap()
            .execute(
                "UPDATE flows SET evidence_owner=NULL,attribution_status='conflict' WHERE id=3",
                [],
            )
            .unwrap();
        Self {
            directory,
            token,
            store,
        }
    }
    async fn call<B: Body<Data = Bytes> + Unpin>(
        &self,
        request: Request<'_>,
        available: bool,
        body: &mut B,
        encoding: &[u8],
        length: Option<u64>,
    ) -> Result<agent_api::Outcome<'static>, B::Error> {
        agent_api::respond_with_body(
            request,
            &self.token,
            PolicyState::Unavailable,
            &Registry::default(),
            1000.,
            Controls {
                gateway: None,
                memory: None,
                traces: None,
                discovery: None,
                audit: None,
                flows: available.then_some(&self.store),
                circuits: None,
                declarations: None,
            },
            RequestBody {
                body,
                content_encoding: encoding,
                content_length: length,
                observation: None,
            },
        )
        .await
    }
}
fn request(path: &str) -> Request<'_> {
    Request {
        method: "POST",
        path_and_query: path,
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: Some("127.0.0.1"),
        request_id: "synthetic-flow-read",
    }
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect()
}
fn body(outcome: &agent_api::Outcome<'_>) -> Value {
    serde_json::from_slice(&outcome.response.body_bytes()).unwrap()
}

#[tokio::test]
async fn actual_source_dispatch_and_body_projection() {
    let fixture = Fixture::new();
    let source: Value = serde_json::from_str(include_str!("agent_api_flows_source.json")).unwrap();
    for row in source["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let path = row["path"].as_str().unwrap();
        let mut content = Full::new(Bytes::from(unhex(row["input_hex"].as_str().unwrap())));
        let outcome = fixture
            .call(
                Request {
                    method: row["method"].as_str().unwrap(),
                    identity: row["identity"]
                        .as_str()
                        .map_or(Identity::Unavailable, Identity::Resolved),
                    authorization: (row["auth"] == "valid").then_some(AUTH),
                    ..request(path)
                },
                row["available"].as_bool().unwrap(),
                &mut content,
                row["content_encoding"].as_str().unwrap().as_bytes(),
                None,
            )
            .await
            .unwrap();
        match name {
            "ownerless_source_defect" | "ownerless_body_source_defect" => {
                assert_eq!(row["status"], 200);
                assert_eq!(outcome.response.status, 404);
                assert_eq!(body(&outcome), json!({"error":"Flow not found"}));
            }
            "search_surrogate_query" => {
                assert_eq!(row["status"], 400);
                assert_eq!(outcome.response.status, 503);
                assert_eq!(
                    outcome.failure,
                    Some(agent_api::Failure::FlowReporting(
                        agent_api::FlowFailure::QueryCompatibility
                    ))
                );
            }
            "search_surrogate" => {
                assert_eq!(row["status"], 400);
                assert_eq!(outcome.response.status, 503);
                assert_eq!(
                    outcome.failure,
                    Some(agent_api::Failure::FlowReporting(
                        agent_api::FlowFailure::JsonCompatibility
                    ))
                );
            }
            "detail_oversized_digits" => {
                assert_eq!(row["exception"], "ValueError");
                assert_eq!(outcome.response.status, 503);
                assert_eq!(
                    outcome.failure,
                    Some(agent_api::Failure::FlowReporting(
                        agent_api::FlowFailure::DispatchInteger
                    ))
                );
            }
            _ => {
                assert_eq!(
                    u64::from(outcome.response.status),
                    row["status"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    outcome.response.body_bytes().as_ref(),
                    row["text"].as_str().unwrap().as_bytes(),
                    "{name}"
                );
            }
        }
        assert_eq!(outcome.policy_evaluations, 0, "{name}");
        if outcome.handler_owned {
            assert!(outcome.audit.is_none(), "{name}");
        }
    }
}

struct Frames {
    frames: VecDeque<Result<Frame<Bytes>, &'static str>>,
    polls: usize,
    forbidden: bool,
}
impl Body for Frames {
    type Data = Bytes;
    type Error = &'static str;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        assert!(
            !self.forbidden,
            "flow API polled before prerequisite or on a read-only route"
        );
        self.polls += 1;
        Poll::Ready(self.frames.pop_front())
    }
}
#[tokio::test]
async fn method_auth_store_and_direct_routes_do_not_poll_body() {
    let fixture = Fixture::new();
    for (method, path, auth, available, status) in [
        ("PUT", "/api/flows/search", None, true, 405),
        ("POST", "/api/flows/search", None, true, 401),
        ("POST", "/api/flows/search", Some(AUTH), false, 503),
        ("GET", "/api/flows/search", Some(AUTH), true, 200),
        ("POST", "/api/flows/1", Some(AUTH), true, 200),
        (
            "DELETE",
            "/api/flows/1/response-body",
            Some(AUTH),
            true,
            200,
        ),
        ("GET", "/api/flows/endpoints", Some(AUTH), true, 404),
    ] {
        let mut frames = Frames {
            frames: VecDeque::new(),
            polls: 0,
            forbidden: true,
        };
        let outcome = fixture
            .call(
                Request {
                    method,
                    authorization: auth,
                    ..request(path)
                },
                available,
                &mut frames,
                b"broken",
                Some(100),
            )
            .await
            .unwrap();
        assert_eq!(outcome.response.status, status, "{path}");
        assert_eq!(frames.polls, 0);
    }
}
#[tokio::test]
async fn body_transport_failure_is_not_a_query_or_local_json_reply() {
    let fixture = Fixture::new();
    for streamed in [false, true] {
        let mut frames = Frames {
            frames: VecDeque::from([
                Ok(Frame::data(Bytes::from_static(b"{}"))),
                Err("owned-body-failure"),
            ]),
            polls: 0,
            forbidden: false,
        };
        let result = fixture
            .call(
                request("/api/flows/search"),
                true,
                &mut frames,
                b"broken",
                streamed.then_some(20 * 1024 * 1024),
            )
            .await;
        assert!(matches!(result, Err("owned-body-failure")));
        assert_eq!(frames.polls, 2);
    }
}
#[tokio::test]
async fn exact_owner_precedes_body_decompression_and_malformed_storage_errors_are_categorical() {
    let fixture = Fixture::new();
    let connection =
        rusqlite::Connection::open(fixture.directory.path().join("flows.sqlite")).unwrap();
    connection.execute("UPDATE flows SET response_body_blob=x'0000',response_body_encoding='gzip' WHERE id IN(1,2,3)",[]).unwrap();
    for (id, identity, status, message) in [
        (
            1,
            Identity::Resolved("alice"),
            500,
            "Internal error: BadGzipFile",
        ),
        (1, Identity::Resolved("bob"), 404, "Flow not found"),
        (1, Identity::Unavailable, 404, "Flow not found"),
        (2, Identity::Resolved("alice"), 404, "Flow not found"),
        (3, Identity::Resolved("alice"), 404, "Flow not found"),
    ] {
        let mut content = Full::new(Bytes::new());
        let path = format!("/api/flows/{id}/response-body");
        let outcome = fixture
            .call(
                Request {
                    identity,
                    ..request(&path)
                },
                true,
                &mut content,
                b"",
                None,
            )
            .await
            .unwrap();
        assert_eq!(outcome.response.status, status);
        assert_eq!(body(&outcome), json!({"error":message}));
    }
    for (blob, class) in [
        (vec![0x1f, 0x8b], "EOFError"),
        (vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 7], "error"),
    ] {
        connection
            .execute("UPDATE flows SET response_body_blob=? WHERE id=1", [blob])
            .unwrap();
        let mut content = Full::new(Bytes::new());
        let outcome = fixture
            .call(
                request("/api/flows/1/response-body"),
                true,
                &mut content,
                b"",
                None,
            )
            .await
            .unwrap();
        assert_eq!(outcome.response.status, 500);
        assert_eq!(
            body(&outcome),
            json!({"error":format!("Internal error: {class}")})
        );
        assert!(!format!("{:?}", outcome.failure).contains("owned"));
    }
}

#[test]
#[ignore = "requires pinned actual source Python environment"]
fn live_source_flow_facade_oracle() {
    let root = std::env::var_os("SAFEYOLO_SOURCE_ROOT")
        .unwrap_or_else(|| "/home/agent/safeyolo-rust-620".into());
    let python = std::env::var_os("SAFEYOLO_PYTHON").unwrap_or_else(|| "python".into());
    let status = std::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/agent_api_flows_oracle.py"
        ))
        .arg("--check")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/agent_api_flows_source.json"
        ))
        .env("SAFEYOLO_SOURCE_ROOT", root)
        .status()
        .unwrap();
    assert!(status.success());
}
