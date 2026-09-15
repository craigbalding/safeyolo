//! Actual diff/tag facade + store composition, with source-controlled requests.
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{self, Controls, PolicyState, Request, RequestBody},
    circuits::CircuitValue,
    flow_store::{BodyInput, FlowRecord, FlowStore, Settings},
    network_guard::Identity,
    tasks::Registry,
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

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
        for row in source["records"].as_array().unwrap() {
            store
                .record(
                    FlowRecord {
                        metadata: row["metadata"].as_object().unwrap(),
                        request_body: Some(BodyInput::complete(&unhex(
                            row["request_hex"].as_str().unwrap(),
                        ))),
                        response_body: Some(BodyInput::complete(&unhex(
                            row["response_hex"].as_str().unwrap(),
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
    async fn call(&self, row: &Value) -> agent_api::Outcome<'static> {
        let mut body = Full::new(Bytes::copy_from_slice(
            row["body"].as_str().unwrap().as_bytes(),
        ));
        self.call_body(row, &mut body).await.unwrap()
    }
    async fn call_body<B: Body<Data = Bytes> + Unpin>(
        &self,
        row: &Value,
        body: &mut B,
    ) -> Result<agent_api::Outcome<'static>, B::Error> {
        agent_api::respond_with_body(
            Request {
                method: row["method"].as_str().unwrap(),
                path_and_query: row["path"].as_str().unwrap(),
                authorization: row["auth"]
                    .as_bool()
                    .unwrap()
                    .then_some(b"Bearer synthetic-owned-flow-api"),
                identity: row["identity"]
                    .as_str()
                    .map_or(Identity::Unavailable, Identity::Resolved),
                client_ip: Some("127.0.0.1"),
                request_id: "owned-details-read",
            },
            &self.token,
            PolicyState::Unavailable,
            &Registry::default(),
            1000.,
            Controls {
                flows: row["available"].as_bool().unwrap().then_some(&self.store),
                circuits: None,
                declarations: None,
            },
            RequestBody {
                body,
                content_encoding: b"",
                content_length: None,
            },
        )
        .await
    }
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
fn normalize_times(value: &mut CircuitValue, before: u128, after: u128) {
    match value {
        CircuitValue::Object(fields) => {
            for (key, value) in fields {
                if key == "created_at" {
                    let CircuitValue::Integer(integer) = value else {
                        panic!("timestamp kind")
                    };
                    let millis = u128::try_from(integer.clone()).unwrap();
                    assert!((before..=after).contains(&millis));
                    *value = 1234_i64.into();
                } else {
                    normalize_times(value, before, after)
                }
            }
        }
        CircuitValue::Array(values) => {
            for value in values {
                normalize_times(value, before, after)
            }
        }
        _ => {}
    }
}
fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
#[tokio::test]
async fn actual_source_diff_tag_status_types_state_and_order() {
    let before = now();
    let fixture = Fixture::new();
    let source: Value =
        serde_json::from_str(include_str!("agent_api_flow_details_source.json")).unwrap();
    for row in source["rows"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let outcome = fixture.call(row).await;
        let raw = outcome.response.body_bytes();
        let mut actual = CircuitValue::parse_json(std::str::from_utf8(&raw).unwrap()).unwrap();
        normalize_times(&mut actual, before, now());
        match name {
            "diff_ownerless_defect" | "tag_ownerless_defect" => {
                assert_eq!(row["status"], 200);
                assert_eq!(outcome.response.status, 404);
            }
            "tag_oversized_id_wrong_method" => {
                assert_eq!(row["exception"], "ValueError");
                assert_eq!(outcome.response.status, 503);
            }
            _ => {
                assert_eq!(
                    u64::from(outcome.response.status),
                    row["status"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    actual.render_json(false).unwrap(),
                    row["text"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
        let mut tags = CircuitValue::from(fixture.store.get_flow_tags(1).unwrap());
        normalize_times(&mut tags, before, now());
        assert_eq!(
            tags.render_json(false).unwrap(),
            row["tags"].as_str().unwrap(),
            "tag state after {name}"
        );
        assert_eq!(outcome.policy_evaluations, 0);
        if outcome.handler_owned {
            assert!(outcome.audit.is_none());
        }
    }
}
#[tokio::test]
async fn both_owners_are_checked_before_any_diff_body_is_decompressed() {
    let fixture = Fixture::new();
    let db = rusqlite::Connection::open(fixture.directory.path().join("flows.sqlite")).unwrap();
    db.execute(
        "UPDATE flows SET response_body_blob=x'0000',response_body_encoding='gzip' WHERE id=1",
        [],
    )
    .unwrap();
    for (right, status, message) in [
        (2, 404, "One or both flows not found"),
        (3, 404, "One or both flows not found"),
        (4, 500, "Internal error: BadGzipFile"),
    ] {
        let outcome=fixture.call(&json!({"method":"POST","path":"/api/flows/diff","body":format!("{{\"flow_id_a\":1,\"flow_id_b\":{right}}}"),"identity":"alice","auth":true,"available":true})).await;
        assert_eq!(outcome.response.status, status);
        let body: Value = serde_json::from_slice(&outcome.response.body_bytes()).unwrap();
        assert_eq!(body, json!({"error":message}));
    }
}
#[test]
#[ignore = "requires pinned actual source Python environment"]
fn live_source_diff_tag_facade_controls() {
    let python = std::env::var_os("SAFEYOLO_PYTHON").expect("set SAFEYOLO_PYTHON");
    let source = std::env::var_os("SAFEYOLO_SOURCE_ROOT")
        .unwrap_or_else(|| "/home/agent/safeyolo-rust-620".into());
    let status = std::process::Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/agent_api_flow_details_oracle.py"
        ))
        .arg("--check")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/agent_api_flow_details_source.json"
        ))
        .env("SAFEYOLO_SOURCE_ROOT", source)
        .status()
        .unwrap();
    assert!(status.success());
}

struct Frames {
    frames: VecDeque<Result<Frame<Bytes>, &'static str>>,
    forbidden: bool,
    polls: usize,
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
            "tag route polled body before preflight or on DELETE"
        );
        self.polls += 1;
        Poll::Ready(self.frames.pop_front())
    }
}
#[tokio::test]
async fn tag_preflight_delete_and_failed_body_keep_mutation_boundary() {
    let fixture = Fixture::new();
    for (method, path, available, status) in [
        ("POST", "/api/flows/1/tag", false, 503),
        ("GET", "/api/flows/1/tag", true, 404),
        ("POST", "/api/flows/1/tag/name", true, 404),
        ("DELETE", "/api/flows/1/tag/missing", true, 404),
    ] {
        let mut frames = Frames {
            frames: VecDeque::new(),
            forbidden: true,
            polls: 0,
        };
        let row = json!({"method":method,"path":path,"available":available,"auth":true,"identity":"alice"});
        let outcome = fixture.call_body(&row, &mut frames).await.unwrap();
        assert_eq!(outcome.response.status, status);
        assert_eq!(frames.polls, 0);
    }
    let row = json!({"method":"POST","path":"/api/flows/1/tag","available":true,"auth":true,"identity":"alice"});
    let mut frames = Frames {
        frames: VecDeque::from([
            Ok(Frame::data(Bytes::from_static(
                br#"{"tag":"never-committed"}"#,
            ))),
            Err("owned incomplete body"),
        ]),
        forbidden: false,
        polls: 0,
    };
    assert!(matches!(
        fixture.call_body(&row, &mut frames).await,
        Err("owned incomplete body")
    ));
    assert_eq!(fixture.store.get_flow_tags(1).unwrap(), json!([]));
}
