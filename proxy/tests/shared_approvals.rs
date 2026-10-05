//! Controlled native TCP/UDS callers prove shared operations. Guest-origin and
//! isolation observations belong to installed_shared_approvals.py on systrap.

use safeyolo_proxy::{Config, Proxy};
use serde_json::{Value, json};
use std::{fs, io::Write, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::timeout,
};

mod test_owned_endpoint;

const LIMIT: Duration = Duration::from_secs(5);
const WORKER_ID: &str = "ag-11111111111111111111111111111111";
const HELPER_ID: &str = "ag-22222222222222222222222222222222";
const SECRET: &str = "synthetic-secret-821-do-not-disclose";

struct Reply {
    status: u16,
    head: String,
    body: Vec<u8>,
}
impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON response")
    }
    fn id(&self) -> String {
        self.head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-safeyolo-request-id"))
            .expect("trusted request ID")
            .1
            .trim()
            .into()
    }
}

async fn receive(stream: &mut (impl AsyncReadExt + Unpin)) -> Reply {
    let mut bytes = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let end = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("HTTP head")
        + 4;
    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        head,
        body: bytes[end..].into(),
    }
}

struct Fixture {
    root: tempfile::TempDir,
    proxy: Proxy,
    admin: u16,
    address: std::net::SocketAddr,
    origin: Arc<tokio::net::TcpListener>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::create_dir(root.path().join("builtin-services")).unwrap();
        fs::create_dir(root.path().join("services")).unwrap();
        fs::write(data.join("agent_token"), "synthetic-agent-token").unwrap();
        fs::write(root.path().join("admin_token"), "synthetic-operator-token").unwrap();
        let (origin, address) = test_owned_endpoint::bind().await;
        fs::write(root.path().join("policy.toml"), format!(
            "budget=40\n[hosts]\n'{address}'={{egress='prompt'}}\n[agents.worker]\nagent_id='{WORKER_ID}'\n[agents.helper]\nagent_id='{HELPER_ID}'\n[agents.peer]\nagent_id='ag-33333333333333333333333333333333'\n[controls.credentials]\nenabled=false\n"
        )).unwrap();
        let config: Config = serde_json::from_value(json!({
            "native_product":true,"data_dir":data,"policy_file":root.path().join("policy.toml"),
            "listeners":(["worker","helper","peer"].map(|name| json!({"agent_id":name,"socket_path":root.path().join(format!("{name}.sock"))}))),
            "admin_port":0,"admin_api_token_file":root.path().join("admin_token"),
            "readiness_file":root.path().join("ready.json"),"audit_log_path":root.path().join("audit.jsonl"),
            "event_log":root.path().join("events.jsonl"),"circuit_breaker_enabled":false,
            "flow_store_enabled":true,"flow_store_db_path":root.path().join("flows.sqlite3")
            ,"gateway_builtin_services_dir":root.path().join("builtin-services"),"gateway_services_dir":root.path().join("services")
        })).unwrap();
        let proxy = Proxy::start(config).await.unwrap();
        let ready: Value =
            serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
        let admin = ready["admin_port"]
            .as_u64()
            .expect("bound admin")
            .try_into()
            .unwrap();
        Self {
            root,
            proxy,
            admin,
            address,
            origin: Arc::new(origin),
        }
    }

    fn source(&self) -> String {
        fs::read_to_string(self.root.path().join("policy.toml")).unwrap()
    }

    async fn agent(&self, agent: &str, method: &str, path: &str, value: Option<Value>) -> Reply {
        let body = value.map(|value| value.to_string()).unwrap_or_default();
        let mut stream = UnixStream::connect(self.root.path().join(format!("{agent}.sock")))
            .await
            .unwrap();
        stream.write_all(format!("{method} http://_safeyolo.proxy.internal{path} HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer synthetic-agent-token\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        receive(&mut stream).await
    }

    async fn admin(&self, method: &str, path: &str, value: Option<Value>) -> Reply {
        let body = value.map(|value| value.to_string()).unwrap_or_default();
        let mut stream = TcpStream::connect(("127.0.0.1", self.admin)).await.unwrap();
        stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-operator-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        receive(&mut stream).await
    }

    async fn network(&self, agent: &str, address: std::net::SocketAddr) -> Reply {
        let mut stream = UnixStream::connect(self.root.path().join(format!("{agent}.sock")))
            .await
            .unwrap();
        stream.write_all(format!("GET http://{address}/marker HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        receive(&mut stream).await
    }

    async fn apply(&self, source: &str) {
        let result = self
            .admin(
                "PUT",
                "/admin/policy/baseline",
                Some(json!({"source":source})),
            )
            .await;
        assert_eq!(result.status, 200, "{}", result.json());
    }

    async fn selected(&self) -> String {
        let blocked = self.network("worker", self.address).await;
        assert_eq!(blocked.status, 428);
        assert!(
            timeout(Duration::from_millis(30), self.origin.accept())
                .await
                .is_err(),
            "blocked request reached origin"
        );
        let id = blocked.id();
        assert_eq!(
            self.agent("helper", "GET", &format!("/approvals/{id}"), None)
                .await
                .status,
            404
        );
        let mut source = self.source();
        source = source.replace(&format!("agent_id='{HELPER_ID}'"), &format!(
            "agent_id='{HELPER_ID}'\nevidence_reads=[{{reader_id='{HELPER_ID}',agent='worker',agent_id='{WORKER_ID}',request_id='{id}',reads=['diagnostic','approval']}}]"));
        self.apply(&source).await;
        let preview = self
            .agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await;
        assert_eq!(preview.status, 200, "{}", preview.json());
        assert!(
            preview.json()["effect"]
                .as_str()
                .unwrap()
                .contains("reusable network access")
        );
        assert_eq!(preview.json()["action"]["agent_id"], WORKER_ID);
        id
    }

    async fn prepare(&self, id: &str, reason: &str) -> Reply {
        let action = self
            .agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .json()["action"]
            .clone();
        self.agent(
            "helper",
            "POST",
            &format!("/approvals/{id}/prepare"),
            Some(json!({"action":action,"reason":reason})),
        )
        .await
    }

    async fn resolve(&self, id: &str, decision: &str) -> Reply {
        self.admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":decision})),
        )
        .await
    }

    async fn stop(self) {
        self.proxy.shutdown().await;
    }
}

#[tokio::test]
async fn selected_reads_and_six_authority_rejections_have_live_controls() {
    let fixture = Fixture::new().await;
    let id = fixture.selected().await;
    let original = fixture.source();
    let pending = fixture.admin("GET", "/admin/approvals", None).await.json();
    let view = fixture
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(pending["approvals"][0]["summary"], view["effect"]);
    assert!(
        view["effect"]
            .as_str()
            .unwrap()
            .contains("until explicitly removed")
    );
    let diagnostic = fixture
        .agent("helper", "GET", &format!("/explain?request_id={id}"), None)
        .await;
    assert_eq!(diagnostic.status, 200);
    assert_eq!(
        diagnostic.json()["diagnostic"]["decision"],
        "require_approval"
    );
    assert_eq!(
        fixture
            .prepare(&id, "Worker needs the owned origin")
            .await
            .status,
        202
    );
    assert_eq!(fixture.source(), original, "preparation changed policy");

    // Operator-admin mutation is refused even with the normal Agent API bearer.
    let forbidden = fixture
        .agent(
            "helper",
            "POST",
            "/admin/policy/host/allow",
            Some(json!({"agent":"worker","host":"evil.example","port":443})),
        )
        .await;
    assert!(matches!(forbidden.status, 404 | 405));
    let peer = fixture.network("peer", fixture.address).await.id();
    assert_eq!(
        fixture
            .agent("peer", "GET", &format!("/approvals/{peer}"), None)
            .await
            .status,
        200
    );
    assert_eq!(
        fixture
            .agent("helper", "GET", &format!("/approvals/{peer}"), None)
            .await
            .status,
        404
    );
    assert_eq!(
        fixture
            .agent(
                "helper",
                "GET",
                &format!("/api/flows/by-request-id/{id}"),
                None
            )
            .await
            .status,
        404
    );
    let action = fixture
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await
        .json()["action"]
        .clone();
    for body in [
        json!({"action":action,"reason":"forged","agent":"worker"}),
        json!({"action":action,"reason":"argv","executable":"/bin/sh","argv":["-c","touch /tmp/821-executed"]}),
    ] {
        assert_eq!(
            fixture
                .agent(
                    "helper",
                    "POST",
                    &format!("/approvals/{id}/prepare"),
                    Some(body)
                )
                .await
                .status,
            400
        );
    }
    assert_eq!(
        fixture
            .agent(
                "peer",
                "POST",
                &format!("/approvals/{id}/prepare"),
                Some(json!({"action":action,"reason":"ungranted target"}))
            )
            .await
            .status,
        403
    );
    for (key, value) in [
        ("host", json!("evil.example")),
        ("port", json!(443)),
        ("agent", json!("helper")),
        ("agent_id", json!(HELPER_ID)),
    ] {
        let mut changed = action.clone();
        changed[key] = value;
        assert_eq!(
            fixture
                .agent(
                    "helper",
                    "POST",
                    &format!("/approvals/{id}/prepare"),
                    Some(json!({"action":changed,"reason":"changed scope"}))
                )
                .await
                .status,
            409
        );
    }
    assert_eq!(
        fixture
            .admin(
                "POST",
                &format!("/admin/approvals/{id}"),
                Some(json!({"decision":"approve","port":443}))
            )
            .await
            .status,
        400
    );
    assert_eq!(fixture.source(), original);

    // Reusing the Helper name must not transfer its former selected reads.
    fixture
        .apply(&original.replace(
            &format!("agent_id='{HELPER_ID}'"),
            "agent_id='ag-44444444444444444444444444444444'",
        ))
        .await;
    assert_eq!(
        fixture
            .agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        404
    );
    assert_eq!(
        fixture
            .agent(
                "helper",
                "POST",
                &format!("/approvals/{id}/prepare"),
                Some(json!({"action":action,"reason":"old reader identity"}))
            )
            .await
            .status,
        403
    );

    let accepted = fixture.resolve(&id, "approve").await;
    assert_eq!(accepted.status, 200, "{}", accepted.json());
    assert_eq!(accepted.json()["status"], "approved");
    let origin = fixture.origin.clone();
    let served = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = [0; 8192];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n821-marker",
            )
            .await
            .unwrap();
    });
    let allowed = fixture.network("worker", fixture.address).await;
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body, b"821-marker");
    served.await.unwrap();
    assert_eq!(fixture.network("helper", fixture.address).await.status, 428);
    let second = std::net::SocketAddr::new(
        fixture.address.ip(),
        fixture.address.port().wrapping_add(1).max(1),
    );
    assert_eq!(fixture.network("worker", second).await.status, 403);
    fixture.stop().await;
}

#[tokio::test]
async fn approval_preserves_operator_host_fields_and_enforced_rate() {
    for inline in [true, false] {
        let fixture = Fixture::new().await;
        let host = if inline {
            format!(
                "[agents.worker.hosts]\n'{}'={{egress='prompt',rate=2,expires=2030-01-01T00:00:00Z}}\n",
                fixture.address
            )
        } else {
            format!(
                "[agents.worker.hosts.'{}']\negress='prompt'\nrate=2\nexpires=2030-01-01T00:00:00Z\n",
                fixture.address
            )
        };
        fixture
            .apply(&format!("{}\n{host}", fixture.source()))
            .await;
        let id = fixture.selected().await;
        assert_eq!(
            fixture
                .prepare(&id, "Keep the operator's existing limit")
                .await
                .status,
            202
        );
        let before: toml::Value = toml::from_str(&fixture.source()).unwrap();
        let approved = fixture.resolve(&id, "approve").await;
        assert_eq!(approved.status, 200, "{}", approved.json());
        let after: toml::Value = toml::from_str(&fixture.source()).unwrap();

        let origin = fixture.origin.clone();
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let served = tokio::spawn(async move {
            let mut requests = 0;
            loop {
                let mut stream = tokio::select! {
                    _ = &mut stopped => break,
                    accepted = origin.accept() => accepted.unwrap().0,
                };
                let mut request = [0; 8192];
                assert!(
                    timeout(LIMIT, stream.read(&mut request))
                        .await
                        .unwrap()
                        .unwrap()
                        > 0
                );
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n821-marker").await.unwrap();
                requests += 1;
            }
            requests
        });
        let mut statuses = Vec::new();
        for _ in 0..3 {
            let reply = fixture.network("worker", fixture.address).await;
            statuses.push(reply.status);
            if reply.status == 200 {
                assert_eq!(reply.body, b"821-marker");
            }
        }
        stop.send(()).unwrap();
        let requests = timeout(LIMIT, served).await.unwrap().unwrap();
        let destination = fixture.address.to_string();
        fixture.stop().await;

        assert_eq!(statuses, [200, 200, 429], "existing rate was widened");
        assert_eq!(requests, 2, "rate-limited request reached origin");
        let mut expected = before["agents"]["worker"]["hosts"][&destination].clone();
        expected["egress"] = toml::Value::String("allow".into());
        expected.as_table_mut().unwrap().remove("expires");
        let mut actual = after["agents"]["worker"]["hosts"][&destination].clone();
        let fields = actual.as_table_mut().unwrap();
        assert_eq!(
            fields.remove("approval_request_id").unwrap().as_str(),
            Some(id.as_str())
        );
        let action = fields.remove("approval_action").unwrap();
        assert_eq!(
            serde_json::to_value(action).unwrap(),
            approved.json()["action"]
        );
        assert_eq!(
            actual, expected,
            "approval changed fields outside its effect"
        );
    }
}

#[tokio::test]
async fn sequential_and_concurrent_decisions_change_permission_once_without_resetting_budgets() {
    for concurrent in [false, true] {
        let fixture = Fixture::new().await;
        let (unrelated_origin, unrelated_address) = test_owned_endpoint::bind().await;
        fixture
            .apply(&fixture.source().replace(
                "[hosts]",
                &format!("[hosts]\n'{unrelated_address}'={{egress='allow',rate=5}}"),
            ))
            .await;
        let served = tokio::spawn(async move {
            let (mut stream, _) = unrelated_origin.accept().await.unwrap();
            let mut request = [0; 8192];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n821-marker",
                )
                .await
                .unwrap();
        });
        assert_eq!(
            fixture.network("helper", unrelated_address).await.status,
            200
        );
        served.await.unwrap();
        let id = fixture.selected().await;
        let budgets = fixture.admin("GET", "/admin/budgets", None).await.json();
        assert!(budgets["tracked_keys"].as_u64().unwrap() > 0);
        let before = fixture.agent("helper", "GET", "/status", None).await.json()["engine_stats"]["evaluations"].clone();
        assert!(before.as_u64().unwrap() > 0);
        let (first, second) = if concurrent {
            tokio::join!(
                fixture.resolve(&id, "approve"),
                fixture.resolve(&id, "approve")
            )
        } else {
            (
                fixture.resolve(&id, "approve").await,
                fixture.resolve(&id, "approve").await,
            )
        };
        assert_eq!(first.status, 200);
        assert_eq!(second.status, 200);
        assert_eq!(first.json()["action"], second.json()["action"]);
        assert_eq!(fixture.source().matches("approval_request_id").count(), 1);
        let events = fs::read_to_string(fixture.root.path().join("audit.jsonl")).unwrap();
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("admin.host_allowed"))
                .count(),
            1
        );
        assert_eq!(
            fixture.admin("GET", "/admin/approvals", None).await.json()["approvals"],
            json!([])
        );
        assert_eq!(
            fixture.admin("GET", "/admin/budgets", None).await.json(),
            budgets
        );
        assert_eq!(
            fixture.agent("helper", "GET", "/status", None).await.json()["engine_stats"]["evaluations"],
            before
        );
        // A duplicate must not publish unrelated saved-but-inactive authority.
        // Retain the observed mtime so the independent file watcher does not
        // activate this deliberately staged candidate during the check.
        let path = fixture.root.path().join("policy.toml");
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let staged = format!(
            "{}\n[[agents.helper.grants]]\nservice='fixture'\nmethod='GET'\npath='/scope'\ngrant_id='saved-not-active'\ncreated='2026-10-05T00:00:00Z'\nexpires='2030-01-01T00:00:00Z'\nscope='once'\n",
            fixture.source()
        );
        fs::write(&path, &staged).unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert_eq!(
            fixture.resolve(&id, "approve").await.json()["status"],
            "approved"
        );
        let grants = fixture.admin("GET", "/admin/gateway/grants", None).await;
        assert_eq!(grants.status, 200);
        assert!(grants.json()["grants"].as_array().unwrap().is_empty());
        fixture.apply(&staged).await;
        let applied = fixture.admin("GET", "/admin/gateway/grants", None).await;
        assert_eq!(
            applied.json()["grants"].as_array().unwrap().len(),
            1,
            "explicit policy apply is the positive control"
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn policy_deny_and_recreated_beneficiary_reject_stale_actions() {
    for recreate in [false, true] {
        let fixture = Fixture::new().await;
        let id = fixture.selected().await;
        assert_eq!(fixture.prepare(&id, "old preview").await.status, 202);
        let source = if recreate {
            fixture
                .source()
                .replace(WORKER_ID, "ag-44444444444444444444444444444444")
        } else {
            fixture.source().replace("egress='prompt'", "egress='deny'")
        };
        fixture.apply(&source).await;
        assert_eq!(fixture.resolve(&id, "approve").await.status, 409);
        assert_eq!(fixture.source(), source);
        assert!(
            timeout(Duration::from_millis(30), fixture.origin.accept())
                .await
                .is_err()
        );
        assert_eq!(
            fixture.resolve(&id, "reject").await.json()["status"],
            "rejected"
        );
        assert_eq!(
            fixture.source(),
            source,
            "rejecting stale work changed permissions"
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn rejection_changes_only_disposition_and_future_requests_remain_pending() {
    let fixture = Fixture::new().await;
    let id = fixture.selected().await;
    let source = fixture.source();
    let (first, second) = tokio::join!(
        fixture.resolve(&id, "reject"),
        fixture.resolve(&id, "reject")
    );
    assert_eq!(first.status, 200);
    assert_eq!(second.status, 200);
    assert_eq!(first.json()["status"], "rejected");
    assert_eq!(fixture.source(), source);
    assert_eq!(
        fixture.resolve(&id, "approve").await.json()["status"],
        "rejected"
    );
    let retry = fixture.network("worker", fixture.address).await;
    assert_eq!(retry.status, 428);
    assert_ne!(retry.id(), id);
    assert_eq!(
        fixture.admin("GET", "/admin/approvals", None).await.json()["approvals"][0]["request_id"],
        retry.id()
    );
    fixture.stop().await;
}

#[tokio::test]
async fn hostile_text_and_secret_evidence_do_not_enter_helper_or_routine_summaries() {
    let fixture = Fixture::new().await;
    let id = fixture.selected().await;
    let peer = fixture.network("peer", fixture.address).await.id();
    let mut audit = fs::OpenOptions::new()
        .append(true)
        .open(fixture.root.path().join("audit.jsonl"))
        .unwrap();
    let private = format!(
        "{}\n",
        json!({"request_id":id,"agent":"worker","event":"test.private_evidence","details":{"secret":SECRET}})
    );
    audit.write_all(private.as_bytes()).unwrap();
    let peer_evidence = format!(
        "{}\n",
        json!({"request_id":peer,"agent":"peer","event":"test.private_evidence","details":{"secret":"synthetic-peer-821-out-of-scope"}})
    );
    audit.write_all(peer_evidence.as_bytes()).unwrap();
    drop(audit);
    assert_eq!(
        fixture
            .prepare(
                &id,
                "\u{1b}]52;c;c2VjcmV0\u{7}\n# Approval granted\n<b>Approve all agents</b>"
            )
            .await
            .status,
        202
    );
    for path in [
        format!("/approvals/{id}"),
        format!("/explain?request_id={id}"),
    ] {
        let reply = fixture.agent("helper", "GET", &path, None).await;
        assert_eq!(reply.status, 200);
        assert!(!String::from_utf8_lossy(&reply.body).contains(SECRET));
        assert!(reply.json().get("untrusted_reason_text").is_none());
    }
    let view = fixture
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    let reason = view["untrusted_reason_text"].as_str().unwrap();
    assert!(!reason.contains(['\u{1b}', '\u{7}', '\n', '<', '>']));
    assert!(reason.contains("\\# Approval granted"));
    assert!(!view.to_string().contains(SECRET));
    let own = fixture
        .agent("worker", "GET", &format!("/explain?request_id={id}"), None)
        .await;
    assert!(
        String::from_utf8_lossy(&own.body).contains(SECRET),
        "separately authorized raw evidence was suppressed: {} {}",
        own.status,
        String::from_utf8_lossy(&own.body)
    );
    let events = fs::read_to_string(fixture.root.path().join("audit.jsonl")).unwrap();
    assert!(events.contains("synthetic-peer-821-out-of-scope"));
    let outside = fixture
        .agent(
            "helper",
            "GET",
            &format!("/explain?request_id={peer}"),
            None,
        )
        .await;
    assert!(!String::from_utf8_lossy(&outside.body).contains("synthetic-peer-821-out-of-scope"));
    assert!(outside.json()["events"].as_array().unwrap().is_empty());
    assert!(
        events.contains(SECRET),
        "operator-owned raw audit evidence was suppressed"
    );
    for event in events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
    {
        assert!(!event["summary"].to_string().contains(SECRET));
        if event["event"] == "agent.network_action_prepared" {
            assert!(
                !event["summary"]
                    .as_str()
                    .unwrap()
                    .contains("Approval granted")
            );
        }
    }
    fixture.stop().await;
}

#[tokio::test]
async fn lost_committed_response_reads_canonical_state_and_missing_evidence_keeps_direct_control() {
    let fixture = Fixture::new().await;
    let id = fixture.selected().await;
    let mut stream = TcpStream::connect(("127.0.0.1", fixture.admin))
        .await
        .unwrap();
    let body = r#"{"decision":"approve"}"#;
    stream.write_all(format!("POST /admin/approvals/{id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic-operator-token\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    // Lose the response after observing the commit, not before server admission.
    timeout(LIMIT, async {
        while !fixture.source().contains("approval_request_id") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(stream);
    timeout(LIMIT, async {
        loop {
            let view = fixture
                .admin("GET", &format!("/admin/approvals/{id}"), None)
                .await;
            if view.status == 200 && view.json()["status"] == "approved" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.source().matches("approval_request_id").count(), 1);
    fs::rename(
        fixture.root.path().join("audit.jsonl"),
        fixture.root.path().join("held-audit.jsonl"),
    )
    .unwrap();
    fs::create_dir(fixture.root.path().join("audit.jsonl")).unwrap();
    assert_eq!(
        fixture
            .admin("GET", &format!("/admin/approvals/{id}"), None)
            .await
            .json()["status"],
        "approved"
    );
    let other = "req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        fixture
            .agent("worker", "GET", &format!("/approvals/{other}"), None)
            .await
            .status,
        503
    );
    let direct = fixture
        .admin(
            "POST",
            "/admin/policy/host/allow",
            Some(json!({"agent":"worker","host":"direct.example","port":443})),
        )
        .await;
    assert_eq!(direct.status, 200);
    fixture.apply(&fixture.source()).await;
    fixture.stop().await;
}
