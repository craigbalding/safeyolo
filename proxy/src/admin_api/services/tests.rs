use super::*;
use crate::admin_api::{OperatorContext, respond_with_context};
#[cfg(target_os = "linux")]
use crate::audit::{Event, Kind, Settings as AuditSettings, Severity, Submission};
use http_body_util::{BodyExt, Full};
#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    time::{Duration, Instant},
};
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
                instance_id: None,
                admin_address: None,
                operator_modes: None,
                agent_discovery: None,
                listeners: &[],
                audit: None,
                client_ip: None,
                passthrough: None,
                service_audit: Some(crate::admin_api::ServiceAudit {
                    writer: &self.writer,
                    client_ip: "127.0.0.1",
                    target: "/admin/agents/alice/services",
                    mutation_owner: &self.mutation_owner,
                    gateway_store: None,
                }),
                plumb: None,
                task_state: None,
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

async fn revoke(fixture: &Fixture, agent: &str, service: &str) -> Result<Outcome, Error> {
    let tasks = crate::tasks::Registry::default();
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/admin/agents/{agent}/services/{service}"))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    respond_with_context(
        request,
        TOKEN,
        OperatorContext {
            tasks: &tasks,
            policy: Some(&fixture.policy),
            circuits: None,
            stats: None,
            view: None,
            policy_path: Some(&fixture.path),
            instance_id: None,
            admin_address: None,
            operator_modes: None,
            agent_discovery: None,
            listeners: &[],
            audit: None,
            client_ip: None,
            passthrough: None,
            service_audit: Some(crate::admin_api::ServiceAudit {
                writer: &fixture.writer,
                client_ip: "127.0.0.1",
                target: "/admin/agents/alice/services/mail",
                mutation_owner: &fixture.mutation_owner,
                gateway_store: None,
            }),
            plumb: None,
            task_state: None,
        },
    )
    .await
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
            instance_id: None,
            admin_address: None,
            operator_modes: None,
            agent_discovery: None,
            listeners: &[],
            audit: None,
            client_ip: None,
            passthrough: None,
            service_audit: None,
            plumb: None,
            task_state: None,
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
                instance_id: None,
                admin_address: None,
                operator_modes: None,
                agent_discovery: None,
                listeners: &[],
                audit: None,
                client_ip: None,
                passthrough: None,
                service_audit: None,
                plumb: None,
                task_state: None,
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
async fn service_removal_deletes_last_binding_and_keeps_other_service_control() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.call("alice", BODY).await.unwrap().status(),
        StatusCode::OK
    );

    let outcome = revoke(&fixture, "alice", "mail").await.unwrap();
    assert_eq!(outcome.status(), StatusCode::OK);
    assert!(outcome.audit().is_none());
    assert_eq!(
        body(outcome).await,
        json!({
            "status":"revoked",
            "agent":"alice",
            "service":"mail",
            "credential":"vault-entry"
        })
    );
    let saved = fixture.persisted();
    assert!(saved["agents"]["alice"]["services"].get("mail").is_none());
    assert_eq!(
        saved["agents"]["alice"]["services"]["other"]["token"],
        "old-name"
    );

    // The observer reads the saved document through the same gateway snapshot
    // constructor used by the running proxy; no test-only cache is refreshed.
    let observed =
        Policy::from_path_with_registry_at(&fixture.path, Some(fixture.registry.clone()), 1001.)
            .unwrap();
    let services: Value = serde_json::from_str(
        observed
            .gateway()
            .unwrap()
            .agent_services_json("alice")
            .unwrap()
            .expose_secret(),
    )
    .unwrap();
    assert!(services.get("mail").is_none());
    assert!(
        services["other"]["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    // Removing the remaining binding removes the empty services table. This
    // prevents a stale last binding from surviving a later reload.
    let last = revoke(&fixture, "alice", "other").await.unwrap();
    assert_eq!(last.status(), StatusCode::OK);
    assert_eq!(body(last).await["credential"], "old-name");
    assert!(
        fixture.persisted()["agents"]["alice"]
            .get("services")
            .is_none()
    );

    let events = fixture.events();
    assert!(events.iter().any(|event| {
        event["event"] == "admin.agent_service_revoked"
            && event["details"]["agent"] == "alice"
            && event["details"]["service"] == "mail"
            && event["details"]["credential"] == "vault-entry"
    }));
}

#[tokio::test]
async fn service_removal_rejects_unknown_agent_or_service_without_mutation() {
    let fixture = Fixture::new();
    for (agent, service) in [("missing", "mail"), ("alice", "missing")] {
        let outcome = revoke(&fixture, agent, service).await.unwrap();
        assert_eq!(outcome.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body(outcome).await["error"],
            format!("agent '{agent}' or service '{service}' not found")
        );
        assert_eq!(std::fs::read_to_string(&fixture.path).unwrap(), INITIAL);
    }
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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn admitted_service_mutation_distinguishes_queue_full_submission_failure() {
    let mut fixture = Fixture::new();
    let sink = fixture.directory.path().join("held-audit-fifo");
    let name = CString::new(sink.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    fixture.writer = Arc::new(crate::audit::Writer::new(
        sink.clone(),
        AuditSettings {
            max_queue: 1.into(),
            ..AuditSettings::default()
        },
    ));

    let mut seed = Event::new(
        "ops.service-queue-fixture",
        Kind::Ops,
        Severity::Low,
        "Held audit queue fixture",
    );
    seed.details = json!({"canary":"queue-held"}).into();
    assert_eq!(fixture.writer.emit(seed).unwrap(), Submission::Queued);

    // There is no FIFO reader. The real writer thread therefore remains
    // blocked opening the first batch while the one-entry queue fills behind
    // it. The loop tolerates either scheduling order (the worker may dequeue
    // the first entry before the second producer runs).
    let mut queue_full = false;
    for index in 0..32 {
        let mut event = Event::new(
            "ops.service-queue-fixture",
            Kind::Ops,
            Severity::Low,
            "Held audit queue fixture",
        );
        event.details = json!({"canary":"queue-fill","index":index}).into();
        if fixture.writer.emit(event).unwrap() == Submission::QueueFull {
            queue_full = true;
            break;
        }
    }
    assert!(
        queue_full,
        "the one-entry queue must reject a later submission"
    );
    let held_reservations = fixture.writer.pending_count().unwrap();
    assert!(held_reservations >= 1);
    let dropped_before_failure = fixture.writer.dropped_count().unwrap();
    assert!(dropped_before_failure >= 1.into());

    // This is the same synchronous submission-failure injection used by the
    // native operator tests. It runs in this process while the same writer is
    // still held/full. The service mutation must remain committed, while its
    // canonical event must not be presented as durable evidence.
    fixture.writer.poison_for_test();
    let outcome = fixture.call("alice", BODY).await;
    assert!(matches!(outcome, Err(Error::Audit(_))));
    let persisted = fixture.persisted();
    assert_eq!(
        persisted["agents"]["alice"]["services"]["mail"],
        json!({"capability":"read","token":"vault-entry"})
    );

    // Release the held writer and independently inspect the FIFO bytes. The
    // service event is absent because submission failed before admission;
    // the only rows observed are the pre-existing synthetic canaries.
    let mut reader = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&sink)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while fixture.writer.pending_count().unwrap() != 0 {
        assert!(
            Instant::now() < deadline,
            "held audit reservations did not drain"
        );
        tokio::task::yield_now().await;
    }
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("held FIFO read failed: {error}"),
        }
    }
    let rows: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!rows.is_empty(), "admitted canaries must reach the FIFO");
    assert!(rows.iter().all(|row| {
        row["event"] != "admin.agent_service_authorized" && row["details"]["service"] != "mail"
    }));
    assert_eq!(fixture.writer.pending_count().unwrap(), 0);
    assert!(fixture.writer.wait_for_drain(Duration::ZERO).unwrap());

    let evidence = json!({
        "mutation": "alice -> mail/read",
        "policy_persisted": true,
        "submission_result": "synchronous audit submission failure",
        "queue_capacity": 1,
        "queue_full_observed": queue_full,
        "held_reservations_before_failure": held_reservations,
        "dropped_before_failure": dropped_before_failure.to_string(),
        "reservations_after_release": fixture.writer.pending_count().unwrap(),
        "durable_fifo_rows": rows.len(),
        "canonical_service_event_durable": false,
        "limits": [
            "Linux FIFO and a poisoned writer are deterministic in-process controls; this does not claim arbitrary filesystem-crash durability.",
            "The synthetic canaries exercise the existing audit writer; the service route is the production mutation owner path.",
        ],
    });
    println!("service-634 queue/submission observation: {evidence}");
    if let Some(path) = std::env::var_os("SAFEYOLO_SERVICE_QUEUE_FAILURE_EVIDENCE") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}
