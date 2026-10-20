//! Real native UDS/Admin/origin boundaries. These controlled run records are not
//! proof of guest isolation or model-visible reviewer attention.
#![cfg(target_os = "linux")]
use serde_json::{Value, json};
use std::{fs, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
#[allow(dead_code)]
#[path = "support/shared_approvals.rs"]
mod shared_approval_fixture;
mod test_owned_endpoint;
use shared_approval_fixture::*;
const PEER_ID: &str = "ag-33333333333333333333333333333333";

struct Backend(std::process::Child);
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn runs(fixture: &Fixture) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("python3");
    command
        .arg0("runsc-sandbox")
        .args([
            "-c",
            "import time; time.sleep(300)",
            "boot",
            "safeyolo-0123456789abcdef0123456789abcdef",
            "--root",
        ])
        .arg(fixture.root.path().join("run"));
    let backend = command.spawn().unwrap();
    let pid = backend.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let birth = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let token = format!(
        "linux:{}:{pid}:{birth}",
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
    );
    for (name, id) in [
        ("worker", WORKER_ID),
        ("helper", HELPER_ID),
        ("peer", PEER_ID),
    ] {
        let directory = fixture.root.path().join("agents").join(name);
        fs::create_dir_all(directory.join("config-share")).unwrap();
        fs::write(directory.join("runtime.json"),json!({"name":name,"agent_id":id,"run_id":"0123456789abcdef0123456789abcdef","state":"running","backend_pid":pid,"backend_token":token}).to_string()).unwrap();
        fs::write(
            directory.join("config-share/host-launch-context.json"),
            json!({"agent_id":id,"generation":"0123456789abcdef0123456789abcdef"}).to_string(),
        )
        .unwrap();
    }
    backend
}
fn proposal(fixture: &Fixture) -> Value {
    json!({"expected_revision":null,"delegation":{
        "reviewers":[{"name":"helper","agent_id":HELPER_ID},{"name":"peer","agent_id":PEER_ID}],
        "beneficiaries":[{"name":"worker","agent_id":WORKER_ID}],
        "scopes":[{"type":"network_egress","host":fixture.address.ip().to_string(),"ports":[fixture.address.port()],"all_ports":false,"actions":["request"]}],
        "expires_at":null,"grant_seconds":null,"gateway_once":true,"acknowledgment":null}})
}
async fn delegate(fixture: &Fixture, mut input: Value) -> (Value, String) {
    let preview = fixture
        .admin(
            "POST",
            "/admin/approval-delegations/local/preview",
            Some(input.clone()),
        )
        .await;
    assert_eq!(preview.status, 200, "{}", preview.json());
    let revision = preview.json()["revision"].as_str().unwrap().to_owned();
    input["delegation"] = preview.json()["after"].clone();
    input["delegation"]["acknowledgment"] = json!(revision);
    let applied = fixture
        .admin(
            "POST",
            "/admin/approval-delegations/local/apply",
            Some(input.clone()),
        )
        .await;
    assert_eq!(applied.status, 200, "{}", applied.json());
    (input, revision)
}
async fn decide(f: &Fixture, reviewer: &str, id: &str, decision: &str, option: &str) -> Reply {
    f.agent(
        reviewer,
        "POST",
        &format!("/approvals/{id}/resolve"),
        Some(json!({"delegation":"local","decision":decision,"option":option})),
    )
    .await
}
async fn origin(listener: Arc<tokio::net::TcpListener>) -> Vec<u8> {
    let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = vec![];
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buffer = [0; 2048];
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buffer[..n]);
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin")
        .await
        .unwrap();
    bytes
}
async fn no_origin(f: &Fixture) {
    assert!(
        timeout(Duration::from_millis(30), f.origin.accept())
            .await
            .is_err(),
        "forbidden origin effect"
    );
}

#[tokio::test]
async fn delegated_network_race_retry_revocation_and_same_name_controls() {
    let f = Fixture::new().await;
    let backend = runs(&f);
    let _backend = Backend(backend);
    let blocked = f.network("worker", f.address).await;
    assert_eq!(blocked.status, 428);
    let id = blocked.id();
    no_origin(&f).await;
    let before = f.source();
    let invalid = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/apply",
            Some(proposal(&f)),
        )
        .await;
    assert_eq!(invalid.status, 409);
    assert_eq!(f.source(), before);
    let (input, revision) = delegate(&f, proposal(&f)).await;
    let view = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(view.status, 200, "{}", view.json());
    assert_eq!(view.json()["choices"][0]["option"], "run");
    assert_eq!(view.json()["observed"]["agent_id"], WORKER_ID);
    let foreign = f.network("helper", f.address).await.id();
    assert_eq!(
        f.agent("peer", "GET", &format!("/approvals/{foreign}"), None)
            .await
            .status,
        404
    );
    let widened=f.agent("helper","POST",&format!("/approvals/{id}/resolve"),Some(json!({"decision":"approve","delegation":"local","option":"run","host":"other.invalid"}))).await;
    assert_eq!(widened.status, 400);
    let (one, two) = tokio::join!(
        decide(&f, "helper", &id, "approve", "run"),
        decide(&f, "peer", &id, "approve", "run")
    );
    assert_eq!(one.status, 200, "{}", one.json());
    assert_eq!(two.status, 200, "{}", two.json());
    let grants = f
        .admin("GET", "/admin/approval-delegations", None)
        .await
        .json();
    assert_eq!(
        grants["issued_access"].as_array().unwrap().len(),
        1,
        "{grants}"
    );
    assert_eq!(grants["issued_access"][0]["active"], true);
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(f.network("worker", f.address).await.status, 200);
    assert!(
        String::from_utf8(observer.await.unwrap())
            .unwrap()
            .starts_with("GET /marker ")
    );
    assert_eq!(f.network("helper", f.address).await.status, 428);
    assert_eq!(
        f.request("worker", f.address, "CONNECT", "/", "")
            .await
            .status,
        428
    );
    no_origin(&f).await;
    let revoked = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
    assert_eq!(f.network("worker", f.address).await.status, 428);
    no_origin(&f).await;
    // Recreating an identical named delegation must not restore its old grant.
    delegate(&f, input).await;
    assert_eq!(f.network("worker", f.address).await.status, 428);
    no_origin(&f).await;
    let pending = f.network("worker", f.address).await.id();
    let changed = f
        .root
        .path()
        .join("agents/worker/config-share/host-launch-context.json");
    fs::write(
        changed,
        json!({"agent_id":WORKER_ID,"generation":"fedcba9876543210fedcba9876543210"}).to_string(),
    )
    .unwrap();
    assert_eq!(
        decide(&f, "helper", &pending, "approve", "run")
            .await
            .status,
        409
    );
    f.stop().await;
}

#[tokio::test]
async fn invalid_bounds_self_benefit_and_deferral_preserve_operator_fallback() {
    let f = Fixture::new().await;
    let backend = runs(&f);
    let _backend = Backend(backend);
    let pristine = f.source();
    for mutation in [
        "missing_ports",
        "self",
        "credential_method",
        "unknown",
        "stale_identity",
    ] {
        let mut input = proposal(&f);
        match mutation {
            "missing_ports" => {
                input["delegation"]["scopes"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("ports");
            }
            "self" => {
                input["delegation"]["reviewers"][0] = json!({"name":"worker","agent_id":WORKER_ID})
            }
            "credential_method" => {
                input["delegation"]["scopes"] = json!([{"type":"credential","host":"owned.invalid","fingerprints":["hmac:test"],"method":"GET"}])
            }
            "unknown" => input["delegation"]["lifetime"] = json!("once"),
            _ => input["delegation"]["beneficiaries"][0]["agent_id"] = json!("ag-recreated"),
        }
        assert_eq!(
            f.admin(
                "POST",
                "/admin/approval-delegations/local/preview",
                Some(input)
            )
            .await
            .status,
            409,
            "{mutation}"
        );
        assert_eq!(f.source(), pristine);
    }
    delegate(&f, proposal(&f)).await;
    let id = f.network("worker", f.address).await.id();
    assert_eq!(decide(&f, "helper", &id, "defer", "run").await.status, 200);
    assert_eq!(
        f.admin("GET", "/admin/approvals", None).await.json()["approvals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(decide(&f, "helper", &id, "reject", "run").await.status, 200);
    assert!(
        f.admin("GET", "/admin/approvals", None).await.json()["approvals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!f.source().contains("expires ="));
    assert_eq!(f.resolve(&id, "approve").await.json()["status"], "rejected");
    assert_eq!(f.network("worker", f.address).await.status, 428);
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn delegated_credentials_are_run_scoped_and_never_change_the_shared_baseline() {
    let f = Fixture::new().await;
    let backend = runs(&f);
    let _backend = Backend(backend);
    let mut source = f
        .source()
        .replace("egress='prompt'", "egress='deny'")
        .replace("enabled=false", "enabled=true");
    for agent in ["worker", "helper", "peer"] {
        source.push_str(&format!(
            "\n[agents.{agent}.hosts.'{}']\negress='allow'\n",
            f.address
        ));
    }
    f.apply(&source).await;
    let header = format!("Authorization: Bearer {SECRET}\r\n");
    let blocked = f
        .request("worker", f.address, "GET", "/credential", &header)
        .await;
    assert_eq!(
        blocked.status,
        428,
        "{}",
        String::from_utf8_lossy(&blocked.body)
    );
    let id = blocked.id();
    no_origin(&f).await;
    let canonical = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(canonical["action"]["kind"], "credential_allow");
    let mut input = proposal(&f);
    input["delegation"]["scopes"] = json!([{"type":"credential","host":f.address.ip().to_string(),"fingerprints":canonical["action"]["credentials"]}]);
    delegate(&f, input).await;
    let view = f
        .agent("helper", "GET", &format!("/approvals/{id}"), None)
        .await;
    assert_eq!(view.status, 200, "{}", view.json());
    assert!(!String::from_utf8_lossy(&view.body).contains(SECRET));
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(
        f.request("worker", f.address, "POST", "/different-operation", &header)
            .await
            .status,
        200
    );
    assert!(
        String::from_utf8(observer.await.unwrap())
            .unwrap()
            .contains(SECRET)
    );
    // The supported credential grant covers all methods and paths at this host.
    // Possession by a reviewer or another worker is not deciding authority.
    assert_eq!(
        f.request("helper", f.address, "GET", "/credential", &header)
            .await
            .status,
        428
    );
    assert_eq!(
        f.request("peer", f.address, "GET", "/credential", &header)
            .await
            .status,
        428
    );
    no_origin(&f).await;
    let policy: toml::Value = toml::from_str(&f.source()).unwrap();
    assert!(
        policy["hosts"][f.address.to_string()]
            .get("allow")
            .is_none()
    );
    let f = f.restart().await;
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(
        f.request("worker", f.address, "GET", "/credential", &header)
            .await
            .status,
        200
    );
    observer.await.unwrap();
    let state = f.root.path().join("agents/worker/runtime.json");
    let mut run: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    run["state"] = json!("stopped");
    fs::write(&state, run.to_string()).unwrap();
    assert_eq!(
        f.request("worker", f.address, "GET", "/credential", &header)
            .await
            .status,
        428
    );
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn delegated_gateway_once_reserves_consumes_and_keeps_service_authorization_separate() {
    let f = Fixture::new().await;
    let backend = runs(&f);
    let _backend = Backend(backend);
    fs::write(f.root.path().join("services/fixture.yaml"),format!("schema_version: 1\nname: fixture\ndefault_host: {}\ncapabilities:\n  writer:\n    routes:\n      - methods: [POST, GET]\n        path: /write\nrisky_routes:\n  - path: /write\n    methods: [POST]\n    tactics: [impact]\n",f.address.ip())).unwrap();
    let mut source = f.source().replace("egress='prompt'", "egress='allow'");
    source.push_str(&format!("\n[hosts.'{}']\nservice='fixture'\n[agents.worker.services.fixture]\ncapability='writer'\naccount='agent'\n[[risk]]\naccount='agent'\ntactics=['impact']\ndecision='require_approval'\n",f.address.ip()));
    fs::write(f.root.path().join("policy.toml"), source).unwrap();
    let f = f.restart().await;
    let services = f
        .agent("worker", "GET", "/gateway/services", None)
        .await
        .json();
    let token = services["authorized"]["fixture"]["token"]
        .as_str()
        .expect("worker service token");
    let header = format!("Authorization: Bearer {token}\r\n");
    let blocked = f
        .request("worker", f.address, "POST", "/write", &header)
        .await;
    assert_eq!(
        blocked.status,
        428,
        "{}",
        String::from_utf8_lossy(&blocked.body)
    );
    let id = blocked.id();
    no_origin(&f).await;
    let mut input = proposal(&f);
    input["delegation"]["scopes"] = json!([{"type":"gateway_route","service":"fixture","capability":"writer","binding_id":null,"method":"POST","path":"/write"}]);
    let (_, revision) = delegate(&f, input).await;
    // An unrelated peer's network edit cannot require a fresh operator
    // acknowledgment of this service envelope.
    f.apply(&format!(
        "{}\n[agents.peer.hosts.'other.invalid']\negress='allow'\n",
        f.source().replace(
            "[agents.helper]",
            "[agents.helper]\nmounts=['/tmp:/unrelated:ro']"
        )
    ))
    .await;
    let inventory = f
        .admin("GET", "/admin/approval-delegations", None)
        .await
        .json();
    assert_eq!(inventory["delegations"][0]["revision"], revision);
    assert_eq!(inventory["delegations"][0]["active"], true);
    assert_eq!(
        f.agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        200
    );
    assert_eq!(
        decide(&f, "helper", &id, "approve", "delegated_once")
            .await
            .status,
        200
    );
    // Native policy publication rotates gateway bearer tokens. Refresh through
    // the existing gateway client path before retrying the approved route.
    let current = f
        .agent("worker", "GET", "/gateway/services", None)
        .await
        .json();
    let token = current["authorized"]["fixture"]["token"].as_str().unwrap();
    let header = format!("Authorization: Bearer {token}\r\n");
    let (accepted, release) = tokio::sync::oneshot::channel();
    let listener = f.origin.clone();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let observer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        let n = stream.read(&mut bytes).await.unwrap();
        accepted.send(bytes[..n].to_vec()).unwrap();
        finished.await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let first = f.request("worker", f.address, "POST", "/write", &header);
    let concurrency = async {
        let bytes = timeout(Duration::from_secs(5), release)
            .await
            .expect("first request did not reach the origin")
            .unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with("POST /write "));
        assert!(!String::from_utf8_lossy(&bytes).contains(token));
        assert_eq!(
            f.request("worker", f.address, "POST", "/write", &header)
                .await
                .status,
            428
        );
        finish.send(()).unwrap();
    };
    let (first, ()) = tokio::join!(first, concurrency);
    assert_eq!(first.status, 200);
    observer.await.unwrap();
    let refreshed = f
        .agent("worker", "GET", "/gateway/services", None)
        .await
        .json();
    let header = format!(
        "Authorization: Bearer {}\r\n",
        refreshed["authorized"]["fixture"]["token"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        f.request("worker", f.address, "POST", "/write", &header)
            .await
            .status,
        428
    );
    assert!(
        f.agent("helper", "GET", "/gateway/services", None)
            .await
            .json()["authorized"]["fixture"]
            .is_null()
    );
    assert_eq!(
        f.request("helper", f.address, "POST", "/write", &header)
            .await
            .status,
        403
    );
    no_origin(&f).await;
    // Loading a changed service definition invalidates the acknowledged
    // envelope, including across proxy restart with the same names and run.
    let definition = f.root.path().join("services/fixture.yaml");
    let changed = fs::read_to_string(&definition)
        .unwrap()
        .replace("[POST, GET]", "[POST, GET, DELETE]");
    fs::write(definition, changed).unwrap();
    let f = f.restart().await;
    assert_eq!(
        f.admin("GET", "/admin/approval-delegations", None)
            .await
            .json()["delegations"][0]["active"],
        false
    );
    f.stop().await;
}

#[tokio::test]
async fn preview_warns_when_worker_can_write_reviewer_codex_configuration() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    let target = f.root.path().join("agents/helper/home/.codex");
    fs::create_dir_all(&target).unwrap();
    let source = f.source().replace(
        "[agents.worker]",
        &format!(
            "[agents.worker]\nmounts=[{}]\n",
            json!(format!("{}:/reviewer-config", target.display()))
        ),
    );
    f.apply(&source).await;
    let view = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/preview",
            Some(proposal(&f)),
        )
        .await
        .json();
    assert!(
        view["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains(".codex")),
        "{view}"
    );
    f.stop().await;
}

#[tokio::test]
async fn same_connection_rechecks_revocation_and_the_current_run() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, client::conn::http1};
    use hyper_util::rt::TokioIo;
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    let (_, revision) = delegate(&f, proposal(&f)).await;
    let id = f.network("worker", f.address).await.id();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let stream = tokio::net::UnixStream::connect(f.root.path().join("worker.sock"))
        .await
        .unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    let connection = tokio::spawn(connection);
    let listener = f.origin.clone();
    let observer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        assert!(stream.read(&mut bytes).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let request = || {
        Request::builder()
            .uri(format!("http://{}/marker", f.address))
            .header("Host", f.address.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap()
    };
    let reply = sender.send_request(request()).await.unwrap();
    assert_eq!(reply.status(), 200);
    reply.into_body().collect().await.unwrap();
    observer.await.unwrap();
    assert_eq!(
        f.admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision}))
        )
        .await
        .status,
        200
    );
    let reply = sender.send_request(request()).await.unwrap();
    assert_eq!(reply.status(), 428);
    reply.into_body().collect().await.unwrap();
    let path = f.root.path().join("agents/worker/runtime.json");
    let mut run: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    run["state"] = json!("stopping");
    fs::write(path, run.to_string()).unwrap();
    let reply = sender.send_request(request()).await.unwrap();
    assert_eq!(reply.status(), 403);
    reply.into_body().collect().await.unwrap();
    drop(sender);
    connection.await.unwrap().unwrap();
    no_origin(&f).await;
    f.stop().await;
}

#[tokio::test]
async fn expiry_explicit_denial_and_independent_permission_have_distinct_effects() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    let mut input = proposal(&f);
    input["delegation"]["grant_seconds"] = json!(1);
    let (mut input, revision) = delegate(&f, input).await;
    let id = f.network("worker", f.address).await.id();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(f.network("worker", f.address).await.status, 200);
    observer.await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let view = f
            .admin("GET", "/admin/approval-delegations", None)
            .await
            .json();
        if view["issued_access"][0]["active"] == false {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "grant did not expire at authorization boundary"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(f.network("worker", f.address).await.status, 428);
    no_origin(&f).await;
    input["expected_revision"] = json!(revision);
    input["delegation"]["grant_seconds"] = Value::Null;
    input["delegation"]["definition_revisions"] = json!({});
    let (_, revision) = delegate(&f, input).await;
    let id = f.network("worker", f.address).await.id();
    f.apply(&f.source().replace("egress='prompt'", "egress='deny'"))
        .await;
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    assert_eq!(f.network("worker", f.address).await.status, 403);
    no_origin(&f).await;
    // A separately issued operator permission survives delegation revocation.
    f.apply(&f.source().replace("egress='deny'", "egress='allow'"))
        .await;
    assert_eq!(
        f.admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision}))
        )
        .await
        .status,
        200
    );
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(f.network("worker", f.address).await.status, 200);
    observer.await.unwrap();
    f.stop().await;
}

#[tokio::test]
async fn network_decision_cannot_union_two_partial_delegations() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    let id = f.network("worker", f.address).await.id();
    let mut one = proposal(&f);
    one["delegation"]["scopes"][0]["actions"] = json!(["connect"]);
    let (mut one, revision) = delegate(&f, one).await;
    let mut two = one.clone();
    two["delegation"]["scopes"][0]["actions"] = json!(["request"]);
    two["delegation"]["scopes"][0]["ports"] = json!([if f.address.port() == 65535 {
        65534
    } else {
        f.address.port() + 1
    }]);
    two["expected_revision"] = Value::Null;
    two["delegation"]["acknowledgment"] = Value::Null;
    let preview = f
        .admin(
            "POST",
            "/admin/approval-delegations/other/preview",
            Some(two.clone()),
        )
        .await
        .json();
    two["delegation"] = preview["after"].clone();
    two["delegation"]["acknowledgment"] = preview["revision"].clone();
    assert_eq!(
        f.admin("POST", "/admin/approval-delegations/other/apply", Some(two))
            .await
            .status,
        200
    );
    assert_eq!(
        f.agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        404
    );
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    no_origin(&f).await;
    one["expected_revision"] = json!(revision);
    one["delegation"]["scopes"][0]["actions"] = json!(["request"]);
    delegate(&f, one).await;
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(f.network("worker", f.address).await.status, 200);
    observer.await.unwrap();
    f.stop().await;
}

async fn native(f: &Fixture, args: &[&str]) -> std::process::Output {
    timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(f.root.path())
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn native_operator_and_reviewer_clients_use_the_canonical_resolver() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    fs::write(f.root.path().join("config.toml"),format!("admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n",f.admin)).unwrap();
    let proposal_file = f.root.path().join("proposal.json");
    let mut input = proposal(&f);
    input["delegation"]["scopes"][0]["host"] = json!("*");
    input["delegation"]["scopes"][0]["ports"] = json!([]);
    input["delegation"]["scopes"][0]["all_ports"] = json!(true);
    fs::write(&proposal_file, input.to_string()).unwrap();
    let checked = native(
        &f,
        &[
            "approvals",
            "delegation",
            "check",
            "local",
            "--file",
            proposal_file.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let preview: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert!(
        preview["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("every destination port"))
    );
    input["delegation"] = preview["after"].clone();
    input["delegation"]["acknowledgment"] = preview["revision"].clone();
    fs::write(&proposal_file, input.to_string()).unwrap();
    assert!(
        native(
            &f,
            &[
                "approvals",
                "delegation",
                "apply",
                "local",
                "--file",
                proposal_file.to_str().unwrap()
            ]
        )
        .await
        .status
        .success()
    );
    let id = f.network("worker", f.address).await.id();
    let socket = f.root.path().join("helper.sock");
    let token = f.root.path().join("data/agent_token");
    let read = native(
        &f,
        &[
            "helper",
            "show",
            &id,
            "--socket",
            socket.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    let value: Value = serde_json::from_slice(&read.stdout).unwrap();
    assert!(!value["choices"].as_array().unwrap().is_empty());
    let approved = native(
        &f,
        &[
            "helper",
            "approve",
            &id,
            "--delegation",
            "local",
            "--option",
            "run",
            "--socket",
            socket.to_str().unwrap(),
            "--token-file",
            token.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&approved.stdout).unwrap()["status"],
        "approved"
    );
    let observer = tokio::spawn(origin(f.origin.clone()));
    assert_eq!(
        f.request("worker", f.address, "POST", "/network-is-reusable", "")
            .await
            .status,
        200
    );
    observer.await.unwrap();
    let pending = native(&f, &["approvals", "list", "--json"]).await;
    assert!(pending.status.success());
    f.stop().await;
}

#[tokio::test]
async fn operator_reviewer_race_and_lost_canonical_write_do_not_duplicate_grants() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    delegate(&f, proposal(&f)).await;
    let id = f.network("worker", f.address).await.id();
    let (reviewer, operator) = tokio::join!(
        decide(&f, "helper", &id, "approve", "run"),
        f.resolve(&id, "approve")
    );
    assert_eq!(reviewer.status, 200);
    assert_eq!(operator.status, 200);
    assert_eq!(reviewer.json()["status"], operator.json()["status"]);
    let policy: toml::Value = toml::from_str(&f.source()).unwrap();
    let derived = policy["agents"]["worker"]
        .get("network_grants")
        .and_then(toml::Value::as_table)
        .map_or(0, |v| v.len());
    let direct = policy["agents"]["worker"]
        .get("hosts")
        .and_then(toml::Value::as_table)
        .map_or(0, |v| v.len());
    assert_eq!(derived + direct, 1);
    f.stop().await;

    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    delegate(&f, proposal(&f)).await;
    let id = f.network("worker", f.address).await.id();
    let db = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_canonical_result BEFORE UPDATE ON approvals WHEN json_extract(NEW.record,'$.status')='approved' BEGIN SELECT RAISE(FAIL,'controlled canonical write failure'); END;").unwrap();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        409
    );
    // The policy receipt owns the committed permission when the final database
    // status write is lost. Readback is truthful and retry cannot issue again.
    let view = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(view["status"], "approved");
    let snapshot = f.source();
    db.execute_batch("DROP TRIGGER fail_canonical_result")
        .unwrap();
    assert_eq!(
        decide(&f, "helper", &id, "approve", "run").await.status,
        200
    );
    assert_eq!(f.source(), snapshot);
    assert_eq!(
        f.admin("GET", "/admin/approval-delegations", None)
            .await
            .json()["issued_access"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires the pinned NATS binary; run the focused native attention witness"]
async fn reviewer_attention_is_a_reference_and_reconnect_rechecks_canonical_authority() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    fs::write(f.root.path().join("config.toml"),format!("admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n",f.admin)).unwrap();
    fs::write(
        f.root.path().join("data/instance_id"),
        "sy-44444444444444444444444444444444\n",
    )
    .unwrap();
    struct CoordStop(Option<std::path::PathBuf>);
    impl Drop for CoordStop {
        fn drop(&mut self) {
            let Some(root) = self.0.as_ref() else {
                return;
            };
            let _ = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
                .arg("--root")
                .arg(root)
                .args(["coord", "stop"])
                .stdout(std::process::Stdio::null())
                .status();
        }
    }
    let mut coord = CoordStop(Some(f.root.path().to_owned()));
    let binary = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set the pinned NATS binary");
    let started = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
        .arg("--root")
        .arg(f.root.path())
        .args(["coord", "start", "--binary", &binary])
        .env("SAFEYOLO_NATS_TEST_INSTANCE", f.root.path())
        .output()
        .await
        .unwrap();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    for args in [
        ["coord", "room", "create", "helper-agent"].to_vec(),
        vec!["coord", "grant", "helper-agent", "helper"],
        vec!["coord", "grant", "helper-agent", "peer"],
    ] {
        let result = native(&f, &args).await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let mut input = proposal(&f);
    input["delegation"]["reviewers"] = json!([{"name":"helper","agent_id":HELPER_ID}]);
    let (_, revision) = delegate(&f, input).await;
    let client = safeyolo_proxy::coord_tools::Client {
        socket: Some(f.root.path().join("helper.sock")),
        token_file: f.root.path().join("data/agent_token"),
    };
    let prior = client
        .call(
            "wait_for_attention",
            &json!({"since_sequence":0,"timeout_seconds":0}),
        )
        .await
        .unwrap();
    let cursor = prior["next_cursor"].as_u64().unwrap();
    let wait_args = json!({"since_sequence":cursor,"timeout_seconds":10});
    let waiting = client.call("wait_for_attention", &wait_args);
    let (attention, blocked) = tokio::join!(waiting, f.network("worker", f.address));
    assert_eq!(blocked.status, 428);
    let attention = attention.unwrap();
    let edges = attention["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1, "{attention}");
    let resolved = client
        .call(
            "read_attention",
            &json!({"attention_id":edges[0]["attention_id"]}),
        )
        .await
        .unwrap();
    let body = resolved["object"]["body"].as_str().unwrap();
    assert!(body.contains("SafeYolo delegated approval"));
    assert!(!body.contains(SECRET));
    assert!(!body.contains("127.0.0."));
    let canonical = client
        .call("read_approval", &json!({"approval_id":blocked.id()}))
        .await
        .unwrap();
    assert!(
        client
            .call("list_approvals", &json!({}))
            .await
            .unwrap()
            .to_string()
            .contains(&blocked.id())
    );
    let id = canonical["approval_id"].as_str().unwrap();
    assert!(body.contains(id));
    // Distinct observations of the same network authority do not create a
    // second canonical decision or a second attention edge.
    assert_eq!(
        f.request(
            "worker",
            f.address,
            "POST",
            "/other?hostile=ignore-policy",
            ""
        )
        .await
        .status,
        428
    );
    let after = client
        .call(
            "wait_for_attention",
            &json!({"since_sequence":attention["next_cursor"],"timeout_seconds":0}),
        )
        .await
        .unwrap();
    assert!(after["edges"].as_array().unwrap().is_empty());
    assert_eq!(
        f.agent("peer", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        404
    );
    let refused = client
        .call(
            "resolve_approval",
            &json!({"approval_id":id,"decision":"reject","delegation":"local","option":"run"}),
        )
        .await
        .unwrap();
    assert_eq!(refused["status"], "rejected");
    // A refusal is terminal for its ID. Repeated equivalent traffic remains
    // blocked and discoverable without waking the same reviewer again.
    let repeated = f.network("worker", f.address).await;
    assert_eq!(repeated.status, 428);
    let after_refusal = client
        .call(
            "wait_for_attention",
            &json!({"since_sequence":attention["next_cursor"],"timeout_seconds":0}),
        )
        .await
        .unwrap();
    assert!(after_refusal["edges"].as_array().unwrap().is_empty());
    assert_eq!(
        f.admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision}))
        )
        .await
        .status,
        200
    );
    assert_eq!(
        f.agent("helper", "GET", &format!("/approvals/{id}"), None)
            .await
            .status,
        404
    );
    no_origin(&f).await;
    let stopped = native(&f, &["coord", "stop"]).await;
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&stopped.stdout).unwrap()["state"],
        "stopped"
    );
    coord.0 = None;
    f.stop().await;
}
