use super::*;
use crate::admin_api::{OperatorContext, respond_with_context};
use http_body_util::{BodyExt, Full};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context as PollContext, Poll},
};

const TOKEN: &str = "owned-service-operator";
const BODY: &str = r#"{"service":"mail","capability":"read","credential":"vault-entry"}"#;
const INITIAL: &str = "version = '2.0'\n# retained comment\n[hosts]\n'*' = {rate=600}\n[agents.alice]\nimage = 'owned-image'\n[agents.alice.services.other]\ncapability = 'other'\ntoken = 'old-name'\n";

struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    registry: Arc<crate::services::Registry>,
    policy: Policy,
    writer: Arc<crate::audit::Writer>,
    mutation_owner: crate::admin_api::ServiceMutationOwner,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.toml");
        std::fs::write(&path, INITIAL).unwrap();
        let services = directory.path().join("services");
        std::fs::create_dir(&services).unwrap();
        std::fs::write(services.join("mail.yaml"), "schema_version: 1\nname: mail\nauth: {type: bearer}\ncapabilities:\n  read:\n    routes: []\n").unwrap();
        std::fs::create_dir(directory.path().join("no-builtins")).unwrap();
        let registry = Arc::new(
            crate::services::Registry::from_directories(
                &directory.path().join("no-builtins"),
                &services,
            )
            .unwrap(),
        );
        let policy =
            Policy::from_path_with_registry_at(&path, Some(registry.clone()), 1000.).unwrap();
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        Self {
            writer,
            directory,
            path,
            registry,
            policy,
            mutation_owner: crate::admin_api::ServiceMutationOwner::default(),
        }
    }
    async fn call(&self, agent: &str, body: &str) -> Result<Outcome, Error> {
        let tasks = crate::tasks::Registry::default();
        let request = Request::builder()
            .method("POST")
            .uri(format!("/admin/agents/{agent}/services"))
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Content-Length", body.len())
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap();
        respond_with_context(
            request,
            TOKEN,
            OperatorContext {
                tasks: &tasks,
                policy: Some(&self.policy),
                circuits: None,
                stats: None,
                view: None,
                policy_path: Some(&self.path),
                service_audit: Some(crate::admin_api::ServiceAudit {
                    writer: &self.writer,
                    client_ip: "127.0.0.1",
                    target: "/admin/agents/alice/services",
                    mutation_owner: &self.mutation_owner,
                }),
            },
        )
        .await
    }
    fn events(&self) -> Vec<Value> {
        assert!(
            self.writer
                .wait_for_drain(std::time::Duration::from_secs(3))
                .unwrap()
        );
        std::fs::read_to_string(self.directory.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn persisted(&self) -> Value {
        crate::policy::parse_toml_document(&std::fs::read_to_string(&self.path).unwrap()).unwrap()
    }
}
async fn body(outcome: Outcome) -> Value {
    serde_json::from_slice(
        &outcome
            .into_response()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap()
}

#[tokio::test]
async fn service_authorization_persists_preserves_and_requires_later_reload() {
    let fixture = Fixture::new();
    let before = fixture.policy.baseline().unwrap().unwrap().clone();
    let outcome = fixture.call("alice", BODY).await.unwrap();
    assert_eq!(outcome.status(), StatusCode::OK);
    assert!(outcome.audit().is_none());
    let outcome = outcome
        .submit_audit(&fixture.writer, "127.0.0.1", "/unused")
        .unwrap();
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "admin.agent_service_authorized");
    assert_eq!(
        events[0]["summary"],
        "Agent service authorized: alice -> mail"
    );
    assert_eq!(events[0]["addon"], "admin-api");
    assert_eq!(
        events[0]["details"],
        json!({"client_ip":"127.0.0.1","agent":"alice","service":"mail","capability":"read","credential":"vault-entry"})
    );

    assert_eq!(
        fixture.persisted()["agents"]["alice"]["services"]["mail"],
        json!({"capability":"read","token":"vault-entry"})
    );
    assert_eq!(
        fixture.persisted()["agents"]["alice"]["services"]["other"]["token"],
        "old-name"
    );
    assert_eq!(
        fixture.persisted()["agents"]["alice"]["image"],
        "owned-image"
    );
    assert!(
        std::fs::read_to_string(&fixture.path)
            .unwrap()
            .contains("# retained comment")
    );
    assert!(fixture.policy.baseline().unwrap().unwrap() == &before);
    let reloaded =
        Policy::from_path_with_registry_at(&fixture.path, Some(fixture.registry.clone()), 1001.)
            .unwrap();
    assert!(
        reloaded.gateway().unwrap().canonical_gateway()["token_map"]
            .as_object()
            .unwrap()
            .values()
            .any(|binding| {
                binding["agent"] == "alice"
                    && binding["service"] == "mail"
                    && binding["capability"] == "read"
                    && binding["token"] == "vault-entry"
            })
    );
    assert_eq!(
        body(outcome).await,
        json!({"status":"authorized","agent":"alice","service":"mail","capability":"read"})
    );
    fixture
        .call("alice", &BODY.replace("vault-entry", "replacement-name"))
        .await
        .unwrap();
    assert_eq!(
        fixture.persisted()["agents"]["alice"]["services"]["mail"]["token"],
        "replacement-name"
    );
}

#[tokio::test]
async fn service_validation_precedes_agent_lookup_and_preserves_disk() {
    let fixture = Fixture::new();
    for (agent, payload, expected, message) in [
        ("alice", "", 400, "missing request body"),
        ("alice", "{}", 400, "missing request body"),
        (
            "alice",
            r#"{"service":"mail"}"#,
            400,
            "missing required fields: service, capability, credential",
        ),
        (
            "missing",
            r#"{"service":"unknown","capability":"read","credential":"name"}"#,
            404,
            "service 'unknown' is not loaded by the running gateway",
        ),
        (
            "missing",
            r#"{"service":"mail","capability":"unknown","credential":"name"}"#,
            404,
            "capability 'unknown' is not loaded for service 'mail'",
        ),
        ("missing", BODY, 404, "agent 'missing' not found"),
    ] {
        let outcome = fixture.call(agent, payload).await.unwrap();
        assert_eq!(outcome.status().as_u16(), expected);
        assert!(outcome.audit().is_none());
        assert_eq!(body(outcome).await["error"], message);
        assert_eq!(std::fs::read_to_string(&fixture.path).unwrap(), INITIAL);
    }
}

struct NeverPoll;
impl Body for NeverPoll {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut PollContext<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        panic!("unauthenticated service request read its body")
    }
}
#[tokio::test]
async fn service_authentication_precedes_body_and_policy_access() {
    let tasks = crate::tasks::Registry::default();
    let request = Request::builder()
        .method("POST")
        .uri("/admin/agents/alice/services")
        .header("Content-Length", 100)
        .body(NeverPoll)
        .unwrap();
    let outcome = respond_with_context(
        request,
        TOKEN,
        OperatorContext {
            tasks: &tasks,
            policy: None,
            circuits: None,
            stats: None,
            view: None,
            policy_path: Some(Path::new("/missing-owned-test/policy.toml")),
            service_audit: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome.status(), StatusCode::UNAUTHORIZED);
    assert!(matches!(outcome.audit(), Some(Audit::AuthenticationFailed)));
}

#[tokio::test]
async fn service_persistence_failure_emits_no_authorization_and_audit_failure_keeps_write() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.directory.path().join(".policy.toml.lock")).unwrap();
    assert!(matches!(
        fixture.call("alice", BODY).await,
        Err(Error::ServiceMutation)
    ));
    assert_eq!(std::fs::read_to_string(&fixture.path).unwrap(), INITIAL);
    assert!(!fixture.directory.path().join("audit.jsonl").exists());
    std::fs::remove_dir(fixture.directory.path().join(".policy.toml.lock")).unwrap();
    fixture.writer.poison_for_test();
    assert!(matches!(
        fixture.call("alice", BODY).await,
        Err(Error::Audit(_))
    ));
    assert_eq!(
        fixture.persisted()["agents"]["alice"]["services"]["mail"]["token"],
        "vault-entry"
    );
}

#[tokio::test]
async fn service_missing_registry_or_policy_path_never_mutates() {
    let fixture = Fixture::new();
    let tasks = crate::tasks::Registry::default();
    for (policy, path, message) in [
        (
            None,
            Some(fixture.path.as_path()),
            "service registry is not available",
        ),
        (Some(&fixture.policy), None, "Policy path not available"),
        (
            Some(&fixture.policy),
            Some(fixture.path.as_path()),
            "Operator audit unavailable",
        ),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/admin/agents/alice/services")
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Content-Length", BODY.len())
            .body(Full::new(Bytes::from_static(BODY.as_bytes())))
            .unwrap();
        let outcome = respond_with_context(
            request,
            TOKEN,
            OperatorContext {
                tasks: &tasks,
                policy,
                circuits: None,
                stats: None,
                view: None,
                policy_path: path,
                service_audit: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(outcome.audit().is_none());
        assert_eq!(body(outcome).await["error"], message);
        assert_eq!(std::fs::read_to_string(&fixture.path).unwrap(), INITIAL);
    }
}

#[tokio::test]
async fn service_update_uses_latest_locked_document_and_accepts_inline_agents() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.path, "version = '2.0'\nagents = { alice = { image = 'changed-after-snapshot' } }\n[hosts]\n'new.owned.invalid' = {rate=123}\n").unwrap();
    let outcome = fixture.call("alice", BODY).await.unwrap();
    assert_eq!(outcome.status(), StatusCode::OK);
    let saved = fixture.persisted();
    assert_eq!(saved["agents"]["alice"]["image"], "changed-after-snapshot");
    assert_eq!(saved["hosts"]["new.owned.invalid"]["rate"], 123);
    assert_eq!(
        saved["agents"]["alice"]["services"]["mail"]["token"],
        "vault-entry"
    );
}

#[tokio::test]
async fn canceled_service_request_still_audits_its_committed_write_once() {
    let fixture = Arc::new(Fixture::new());
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(fixture.directory.path().join(".policy.toml.lock"))
        .unwrap();
    lock.lock().unwrap();
    let request_fixture = fixture.clone();
    let request = tokio::spawn(async move { request_fixture.call("alice", BODY).await });
    // Only the continuing worker clones this writer. The held OS file lock
    // prevents it from committing before the actual request future is dropped.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while Arc::strong_count(&fixture.writer) == 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read_to_string(&fixture.path).unwrap(), INITIAL);
    request.abort();
    assert!(matches!(request.await, Err(error) if error.is_cancelled()));
    lock.unlock().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while Arc::strong_count(&fixture.writer) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture.persisted()["agents"]["alice"]["services"]["mail"]["token"],
        "vault-entry"
    );
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "admin.agent_service_authorized");
}

#[tokio::test]
async fn shutdown_owner_drains_canceled_mutation_before_audit_shutdown() {
    let fixture = Arc::new(Fixture::new());
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(fixture.directory.path().join(".policy.toml.lock"))
        .unwrap();
    lock.lock().unwrap();
    let request_fixture = fixture.clone();
    let request = tokio::spawn(async move { request_fixture.call("alice", BODY).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while Arc::strong_count(&fixture.writer) == 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    assert!(matches!(request.await, Err(error) if error.is_cancelled()));

    // This is the process shutdown ordering: close admission, release the
    // held mutation, join its canonical audit attempt, then stop the writer.
    fixture.mutation_owner.stop_admission().await;
    lock.unlock().unwrap();
    fixture.mutation_owner.drain().await;
    assert_eq!(
        fixture.persisted()["agents"]["alice"]["services"]["mail"]["token"],
        "vault-entry"
    );
    let events = fixture.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "admin.agent_service_authorized");
    fixture
        .writer
        .shutdown(std::time::Duration::from_secs(3))
        .unwrap();

    // Work admitted after shutdown is rejected before a blocking worker starts.
    assert!(matches!(
        fixture.call("alice", BODY).await,
        Err(Error::ServiceMutation)
    ));
}
