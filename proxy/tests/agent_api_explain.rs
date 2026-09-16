//! Actual private writer reads through the body-aware API, without an HTTP peer.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{
        self, BodyObservation, Controls, ExplainFailure, Failure, Outcome, PolicyState, Request,
        RequestBody,
    },
    audit::{ExplainErrorKind, Settings, Writer},
    network_guard::Identity,
    tasks::Registry,
};
use serde_json::{Value, json};

const AUTH: &[u8] = b"Bearer synthetic-explain-api";
const RID: &str = "req-0123456789abcdef0123456789abcdef";

struct Unread;
impl Body for Unread {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        panic!("explain must not poll the GET body");
    }
}

fn request(path: &str) -> Request<'_> {
    Request {
        method: "GET",
        path_and_query: path,
        authorization: Some(AUTH),
        identity: Identity::Resolved("alice"),
        client_ip: None,
        request_id: "native-contained-id",
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Arc<Writer>) {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("agent_token");
    std::fs::write(&token, b"synthetic-explain-api").unwrap();
    let writer = Arc::new(Writer::new(
        directory.path().join("audit.jsonl"),
        Settings::default(),
    ));
    (directory, token, writer)
}

async fn call(
    request: Request<'_>,
    token: &std::path::Path,
    writer: Option<&Arc<Writer>>,
) -> Outcome<'static> {
    let mut body = Unread;
    let mut observation = BodyObservation::default();
    let result = agent_api::respond_with_body(
        request,
        token,
        PolicyState::Unavailable,
        &Registry::default(),
        0.,
        Controls {
            traces: None,
            discovery: None,
            audit: writer,
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
    assert!(observation.decoded_size.is_none() && observation.encoded_size.is_none());
    assert_eq!(result.policy_evaluations, 0);
    result
}

fn json_body(outcome: &Outcome<'_>) -> Value {
    serde_json::from_slice(&outcome.response.body_bytes()).unwrap()
}

#[tokio::test]
async fn method_auth_id_identity_and_control_order_leave_body_unread() {
    let (directory, token, writer) = fixture();
    let valid = format!("/explain?request_id={RID}");
    for (input, available, status, error) in [
        (
            Request {
                method: "PUT",
                authorization: None,
                ..request(&valid)
            },
            true,
            405,
            "Method Not Allowed",
        ),
        (
            Request {
                method: "POST",
                authorization: None,
                ..request(&valid)
            },
            true,
            405,
            "Method Not Allowed",
        ),
        (
            Request {
                method: "DELETE",
                authorization: None,
                ..request(&valid)
            },
            true,
            405,
            "Method Not Allowed",
        ),
        (
            Request {
                authorization: None,
                ..request("/explain")
            },
            true,
            401,
            "Authorization required",
        ),
        (
            Request {
                authorization: Some(b"Bearer wrong-synthetic-token"),
                ..request("/explain")
            },
            true,
            401,
            "Invalid agent token",
        ),
        (
            Request {
                identity: Identity::Unavailable,
                ..request("/explain")
            },
            false,
            400,
            "Invalid or missing request_id",
        ),
        (
            Request {
                identity: Identity::Unavailable,
                ..request(&valid)
            },
            false,
            403,
            "Could not identify agent",
        ),
        (
            Request {
                identity: Identity::Conflict,
                ..request(&valid)
            },
            true,
            403,
            "Could not identify agent",
        ),
        (
            request(&valid),
            false,
            503,
            "Agent API endpoint unavailable in native development mode",
        ),
    ] {
        let outcome = call(input, &token, available.then_some(&writer)).await;
        assert_eq!(outcome.response.status, status);
        assert_eq!(json_body(&outcome)["error"], error);
        if status == 503 {
            assert_eq!(json_body(&outcome), json!({"error":error}));
            assert!(outcome.handler_owned && outcome.audit.is_none());
            assert_eq!(outcome.failure, Some(Failure::DevelopmentEndpoint));
        }
    }
    assert!(!directory.path().join("audit.jsonl").exists());
}

#[tokio::test]
async fn existing_query_projection_keeps_first_id_and_exact_terminal_lf() {
    let source: Value =
        serde_json::from_str(include_str!("agent_api_explain_source.json")).unwrap();
    let names = [
        "missing_query",
        "invalid_id",
        "terminal_lf",
        "duplicate_first_valid",
        "duplicate_first_empty",
        "unresolved_identity",
    ];
    let mut compared = 0;
    for row in source["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| names.contains(&row["input"]["name"].as_str().unwrap()))
    {
        let (directory, token, writer) = fixture();
        for file in row["input"]["files"].as_array().unwrap() {
            let mut text = String::new();
            for part in file["parts"].as_array().unwrap() {
                text.push_str(
                    &part["text"]
                        .as_str()
                        .unwrap()
                        .repeat(part["repeat"].as_u64().unwrap() as usize),
                );
            }
            std::fs::write(directory.path().join(file["name"].as_str().unwrap()), text).unwrap();
        }
        let path = format!("/explain?{}", row["input"]["query"].as_str().unwrap());
        let input = Request {
            identity: if row["input"]["resolved_identity"].as_bool().unwrap() {
                Identity::Resolved("alice")
            } else {
                Identity::Unavailable
            },
            ..request(&path)
        };
        let outcome = call(input, &token, Some(&writer)).await;
        assert_eq!(
            outcome.response.status,
            row["result"]["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            std::str::from_utf8(&outcome.response.body_bytes()).unwrap(),
            row["result"]["body_text"].as_str().unwrap()
        );
        assert_eq!(
            outcome.response.headers[0],
            ("Content-Type".into(), "application/json".into())
        );
        assert_eq!(
            outcome.response.headers[1],
            ("X-SafeYolo-Agent-API".into(), "true".into())
        );
        compared += 1;
    }
    assert_eq!(compared, names.len());
    let (_directory, token, writer) = fixture();
    for (query, expected_id) in [
        (format!("request_id={RID}"), Some(RID.to_owned())),
        (
            format!("request%5Fid={RID}&agent=bob&request_id=bad"),
            Some(RID.to_owned()),
        ),
        (format!("request_id=bad&request_id={RID}"), None),
        (format!("request_id=&request_id={RID}"), None),
        (format!("request_id={RID}%0A"), Some(format!("{RID}\n"))),
        (format!("request_id={RID}%0A%0A"), None),
        (format!("request_id={RID}%0D%0A"), None),
        (format!("request_id={}", RID.to_uppercase()), None),
        ("request_id=%FF".to_owned(), None),
        (
            format!("request_id={RID}#request_id=bad"),
            Some(RID.to_owned()),
        ),
    ] {
        let path = format!("/explain///?{query}");
        let outcome = call(request(&path), &token, Some(&writer)).await;
        let expected = match expected_id {
            Some(id) => {
                assert_eq!(outcome.response.status, 200);
                json!({"request_id":id,"status":"complete","events":[]})
            }
            None => {
                assert_eq!(outcome.response.status, 400);
                json!({"error":"Invalid or missing request_id","usage":"/explain?request_id=req-<32hex>"})
            }
        };
        assert_eq!(json_body(&outcome), expected);
        assert!(outcome.audit.is_none());
    }
}

#[tokio::test]
async fn actual_writer_read_uses_trusted_agent_and_preserves_typed_extensions() {
    let (directory, token, writer) = fixture();
    let alice = format!(
        r#"{{"request_id":"{RID}","agent":"alice","details":{{"n":NaN,"big":1208925819614629174706176}}}}"#
    );
    let bob = format!(r#"{{"request_id":"{RID}","agent":"bob","details":{{"value":"bob-only"}}}}"#);
    let unowned = format!(r#"{{"request_id":"{RID}","details":{{"agent":"alice"}}}}"#);
    std::fs::write(
        directory.path().join("audit.jsonl"),
        format!("{alice}\n{bob}\n{unowned}\n"),
    )
    .unwrap();
    let path = format!("/explain?request_id={RID}&agent=bob&owner=bob");
    let outcome = call(request(&path), &token, Some(&writer)).await;
    assert_eq!(outcome.response.status, 200);
    assert_eq!(
        std::str::from_utf8(&outcome.response.body_bytes()).unwrap(),
        format!(
            r#"{{"request_id": "{RID}", "status": "complete", "events": [{{"request_id": "{RID}", "agent": "alice", "details": {{"n": NaN, "big": 1208925819614629174706176}}}}]}}"#
        )
    );
    assert!(outcome.failure.is_none() && outcome.audit.is_none());
    let bob_result = call(
        Request {
            identity: Identity::Resolved("bob"),
            ..request(&path)
        },
        &token,
        Some(&writer),
    )
    .await;
    assert_eq!(
        json_body(&bob_result)["events"],
        json!([serde_json::from_str::<Value>(&bob).unwrap()])
    );
    let empty = call(
        Request {
            identity: Identity::Resolved("charlie"),
            ..request(&path)
        },
        &token,
        Some(&writer),
    )
    .await;
    assert_eq!(
        json_body(&empty),
        json!({"request_id":RID,"status":"complete","events":[]})
    );
}

#[tokio::test]
async fn reader_exceptions_keep_source_outer_handler_classes() {
    for (data, kind, class) in [
        (
            b"[]\n".to_vec(),
            ExplainErrorKind::Attribute,
            "AttributeError",
        ),
        (
            b"\xff\n".to_vec(),
            ExplainErrorKind::UnicodeDecode,
            "UnicodeDecodeError",
        ),
        (
            format!("{}\n", "1".repeat(4301)).into_bytes(),
            ExplainErrorKind::Value,
            "ValueError",
        ),
    ] {
        let (directory, token, writer) = fixture();
        std::fs::write(directory.path().join("audit.jsonl"), data).unwrap();
        let path = format!("/explain?request_id={RID}");
        let outcome = call(request(&path), &token, Some(&writer)).await;
        assert_eq!(outcome.response.status, 500);
        assert!(outcome.handler_owned && outcome.audit.is_none());
        assert_eq!(
            outcome.failure,
            Some(Failure::ExplainReporting(ExplainFailure::Reader(kind)))
        );
        assert_eq!(
            json_body(&outcome),
            json!({"error":format!("Internal error: {class}")})
        );
    }
}
