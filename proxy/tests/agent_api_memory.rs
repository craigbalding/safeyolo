//! Report-only controls; earlier source lifecycle hooks are outside this facade.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::{Body, Frame};
use safeyolo_proxy::{
    agent_api::{
        self, BodyObservation, Controls, MemoryContext, PolicyState, Request, RequestBody,
    },
    audit::{Settings, Writer},
    memory_monitor::{MemoryMonitor, MemorySample, SampleError},
    network_guard::Identity,
    tasks::Registry,
};
use serde_json::{Value, json};

const AUTH: &[u8] = b"Bearer synthetic-memory-report";
const SAMPLE: fn() -> Result<MemorySample, SampleError> = || {
    Ok(MemorySample {
        rss_kb: 1280.into(),
        peak_kb: 2560.into(),
    })
};

struct Unread;
impl Body for Unread {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        panic!("memory reporting must not poll the request body");
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    owner: Arc<MemoryMonitor>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("token"), &AUTH[7..]).unwrap();
        Self {
            directory,
            owner: Arc::new(MemoryMonitor::new()),
        }
    }

    fn context(&self) -> MemoryContext<'_> {
        MemoryContext {
            owner: &self.owner,
            sample: SAMPLE,
            now: || 15.9,
        }
    }

    async fn call(
        &self,
        method: &str,
        authorization: Option<&[u8]>,
        identity: Identity<'_>,
        memory: Option<MemoryContext<'_>>,
    ) -> agent_api::Outcome<'static> {
        let mut body = Unread;
        let mut observed = BodyObservation::default();
        let outcome = agent_api::respond_with_body(
            Request {
                method,
                path_and_query: "/memory?agent=forged&host=hidden.invalid",
                authorization,
                identity,
                client_ip: None,
                request_id: "native-owned-id",
            },
            &self.directory.path().join("token"),
            PolicyState::Unavailable,
            &Registry::default(),
            0.,
            Controls {
                gateway: None,
                memory,
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
                content_encoding: b"invalid-coding",
                content_length: Some(100),
                observation: Some(&mut observed),
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.policy_evaluations, 0);
        assert!(observed.encoded_size.is_none() && observed.decoded_size.is_none());
        outcome
    }
}

fn source_report(name: &str) -> String {
    let source: Value = serde_json::from_str(include_str!("memory_monitor_source.json")).unwrap();
    source["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["input"]["name"] == name)
        .unwrap()["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|step| step["stats_json"].as_str())
        .unwrap()
        .into()
}

#[tokio::test]
async fn method_and_auth_precede_reporting_without_body_reads() {
    let fixture = Fixture::new();
    for (method, auth, status, error) in [
        ("HEAD", None, 405, "Method Not Allowed"),
        ("POST", None, 405, "Method Not Allowed"),
        ("GET", None, 401, "Authorization required"),
        (
            "GET",
            Some(b"Bearer wrong".as_slice()),
            401,
            "Invalid agent token",
        ),
    ] {
        let context = MemoryContext {
            sample: || panic!("unauthorized report sampler reached"),
            now: || panic!("unauthorized report clock reached"),
            ..fixture.context()
        };
        let outcome = fixture
            .call(method, auth, Identity::Unavailable, Some(context))
            .await;
        assert_eq!(outcome.response.status, status);
        let body: Value = serde_json::from_slice(&outcome.response.body_bytes()).unwrap();
        assert_eq!(body["error"], error);
        assert_eq!(outcome.audit.is_some(), auth.is_some());
    }
    let missing = fixture
        .call("GET", Some(AUTH), Identity::Conflict, None)
        .await;
    assert_eq!(missing.response.status, 503);
    assert_eq!(
        missing.response.body_bytes(),
        br#"{"error": "memory-monitor addon not loaded"}"#.as_slice()
    );
    assert!(missing.audit.is_none() && missing.failure.is_none());
}

#[tokio::test]
async fn shared_global_report_preserves_source_bytes_and_ignores_identity_hints() {
    let fixture = Fixture::new();
    let initial = fixture
        .call(
            "GET",
            Some(AUTH),
            Identity::Unavailable,
            Some(MemoryContext {
                sample: || tokio::runtime::Handle::current().block_on(async { SAMPLE() }),
                ..fixture.context()
            }),
        )
        .await;
    assert_eq!(initial.response.status, 200);
    assert_eq!(
        initial.response.body_bytes(),
        source_report("pristine_stats").as_bytes()
    );

    // Reuse the frozen source workflow's already-decoded scalar facts; this is
    // report integration, not another HTTP content-decoder proof.
    let audit_path = fixture.directory.path().join("audit.jsonl");
    let writer = Writer::new(audit_path.clone(), Settings::default());
    fixture.owner.client_connected("conn", || 10.).unwrap();
    fixture
        .owner
        .request("conn", "first.invalid", &writer, || Ok(3), || 11., SAMPLE)
        .unwrap();
    fixture
        .owner
        .response("conn", true, false, || Ok(5))
        .unwrap();
    fixture
        .owner
        .request("conn", "second.invalid", &writer, || Ok(1), || 13., SAMPLE)
        .unwrap();
    let expected = source_report("decoded_http_bytes_and_first_domain");
    for identity in [
        Identity::Resolved("alice"),
        Identity::Resolved("bob"),
        Identity::Unavailable,
        Identity::Conflict,
    ] {
        let outcome = fixture
            .call("GET", Some(AUTH), identity, Some(fixture.context()))
            .await;
        assert_eq!(outcome.response.status, 200);
        assert_eq!(outcome.response.body_bytes(), expected.as_bytes());
        assert!(outcome.audit.is_none() && outcome.failure.is_none());
    }
    assert!(
        !audit_path.exists(),
        "reporting does not submit audit events"
    );
}

#[tokio::test]
async fn reached_sample_and_numeric_errors_use_source_classes() {
    let fixture = Fixture::new();
    let context = MemoryContext {
        sample: || Err(SampleError::Index),
        now: || panic!("clock after failed sample"),
        ..fixture.context()
    };
    let outcome = fixture
        .call("GET", Some(AUTH), Identity::Unavailable, Some(context))
        .await;
    assert_eq!(outcome.response.status, 500);
    assert_eq!(
        outcome.response.body_bytes(),
        br#"{"error": "Internal error: IndexError"}"#.as_slice()
    );
    assert!(outcome.audit.is_none() && outcome.failure.is_some());

    fixture.owner.client_connected("conn", || 10.).unwrap();
    for (clock, class) in [(f64::NAN, "ValueError"), (f64::INFINITY, "OverflowError")] {
        let now: fn() -> f64 = if clock.is_nan() {
            || f64::NAN
        } else {
            || f64::INFINITY
        };
        let context = MemoryContext {
            now,
            ..fixture.context()
        };
        let outcome = fixture
            .call("GET", Some(AUTH), Identity::Unavailable, Some(context))
            .await;
        assert_eq!(outcome.response.status, 500);
        let body: Value = serde_json::from_slice(&outcome.response.body_bytes()).unwrap();
        assert_eq!(body, json!({"error":format!("Internal error: {class}")}));
        assert!(outcome.audit.is_none());
    }
    let report = fixture.owner.get_stats(SAMPLE, || 15.9).unwrap();
    assert_eq!(
        report.as_object().unwrap()["active_connections"]
            .render_json(false)
            .unwrap(),
        "1"
    );
}

#[tokio::test]
async fn native_poison_retains_its_category_and_containment() {
    let fixture = Fixture::new();
    let owner = fixture.owner.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = owner.client_connected("poison", || panic!("owned clock failure"));
        }))
        .is_err()
    );
    let outcome = fixture
        .call(
            "GET",
            Some(AUTH),
            Identity::Unavailable,
            Some(fixture.context()),
        )
        .await;
    assert_eq!(outcome.response.status, 503);
    assert!(matches!(
        outcome.failure,
        Some(agent_api::Failure::MemoryReporting(
            safeyolo_proxy::memory_monitor::ErrorKind::Poisoned
        ))
    ));
    let value: Value = serde_json::from_slice(&outcome.response.body_bytes()).unwrap();
    assert_eq!(value["reason_code"], "agent_api_unavailable");
    assert!(outcome.audit.is_some());
}
