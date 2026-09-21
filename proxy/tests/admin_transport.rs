//! Owned-loopback integration witnesses for operator tasks and budget resets.
//!
//! Source contract: operator-api-task-wire-source/results.json, SHA256
//! 6d86bb348eaf0657690a3221f59c149f47c3fba0c9bf1bc934d8f7279919be35.
//! Registry writes do not activate tasks. Numeric alias containment and rejecting
//! malformed shield reloads intentionally repair the separately witnessed source
//! gaps. These tests use no operational token, external resolver, or host listener.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use safeyolo_proxy::{Config, Proxy, admin_shield::REJECTION};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    task::JoinHandle,
};

const ALLOW: &str =
    "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"allow\"\n";
const DENY: &str =
    "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"deny\"\n";
const TASK_PATH: &str = "/admin/policy/task/alpha";
// This synthetic bearer has 64 distinct printable characters. It always meets
// the default credential detector thresholds, unlike a random UUID whose
// character distribution can accidentally avoid detection.
const DETECTABLE_BEARER_TOKEN: &str =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

#[test]
#[ignore = "actual Python parser/auth hook; set SAFEYOLO_POLICY_PYTHON"]
fn operator_audit_auth_parser_matches_actual_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (fixture, failures) in [
        ("admin_audit_source.json", false),
        ("admin_audit_failures_source.json", true),
    ] {
        let mut command = std::process::Command::new(
            std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("source Python"),
        );
        command
            .arg("-B")
            .arg(root.join("tests/admin_audit_source.py"));
        if failures {
            command.arg("--failures");
        }
        let result = command
            .arg("--check")
            .arg(root.join("tests").join(fixture))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[tokio::test]
async fn operator_auth_target_and_client_text_match_source_canonical_events() {
    let directory = TempDir::new().unwrap();
    let token = synthetic();
    let config = config(directory.path(), &token);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let cases: Value = serde_json::from_str(include_str!("admin_audit_source.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let mut bytes = format!(
            "GET {} HTTP/1.1\r\nHost: owned.invalid\r\nConnection: close\r\n",
            case["target"].as_str().unwrap()
        )
        .into_bytes();
        let hex = case["headers_hex"].as_str().unwrap();
        bytes.extend(
            (0..hex.len())
                .step_by(2)
                .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap()),
        );
        bytes.extend_from_slice(b"\r\n");
        let reply = exchange(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap(),
            &bytes,
        )
        .await;
        assert_eq!(reply.status, 401);
    }
    let reply = admin(
        port,
        &token,
        "PUT",
        TASK_PATH,
        br#"{"policy":{"permissions":[]}}"#,
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_shutdown(proxy, &config, port).await;
    let rows: Vec<Value> = std::fs::read_to_string(config.audit_log_path.as_ref().unwrap())
        .unwrap()
        .lines()
        .map(|line| {
            let mut row: Value = serde_json::from_str(line).unwrap();
            assert!(row.as_object_mut().unwrap().remove("ts").is_some());
            row
        })
        .collect();
    assert_eq!(rows.len(), cases.as_array().unwrap().len() + 1);
    for (row, case) in rows.iter().zip(cases.as_array().unwrap()) {
        assert_eq!(row, &case["event"]);
    }
    assert_eq!(
        rows.last().unwrap(),
        &json!({
            "schema_version":1,"event":"admin.task_policy_update","kind":"admin","severity":"medium",
            "summary":"Task policy 'alpha' updated: 0 permissions","addon":"admin-api",
            "details":{"client_ip":"127.0.0.1","task_id":"alpha","permission_count":0}
        })
    );
    assert!(
        !std::fs::read_to_string(config.audit_log_path.as_ref().unwrap())
            .unwrap()
            .contains(&token)
    );
}

fn config(directory: &Path, token: &str) -> Config {
    std::fs::write(directory.join("policy.toml"), ALLOW).unwrap();
    std::fs::write(directory.join("operator-token"), token).unwrap();
    serde_json::from_value(json!({
        "listeners":[
            {"agent_id":"alice","socket_path":directory.join("alice.sock")},
            {"agent_id":"bob","socket_path":directory.join("bob.sock")}
        ],
        "policy_file":directory.join("policy.toml"),"data_dir":directory.join("data"),
        "agent_api_enabled":false,
        "admin_port":0,
        "admin_api_token_file":directory.join("operator-token"),
        "readiness_file":directory.join("ready.json"),
        "flow_store_enabled": false,
        "audit_log_path": directory.join("audit.jsonl"),
        "event_log":directory.join("events.jsonl")
    }))
    .unwrap()
}

fn admin_port(config: &Config) -> u16 {
    let ready: Value =
        serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap();
    assert_eq!(ready["ready"], true);
    assert_eq!(ready["listeners"], 2);
    ready["admin_port"].as_u64().unwrap().try_into().unwrap()
}

fn synthetic() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

// Deliberately has no Debug implementation: assertion failures must not print
// authorized raw task bodies or the bearer included in the request.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response JSON must parse")
    }
}

fn request(method: &str, target: &str, host: &str, token: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &[u8]) -> Reply {
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(request).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP response head");
        let head = std::str::from_utf8(&bytes[..split]).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_owned(), value.trim().to_owned())
            })
            .collect();
        Reply {
            status,
            headers,
            body: bytes[split + 4..].to_vec(),
        }
    })
    .await
    .expect("owned HTTP exchange must finish and close")
}

async fn admin(port: u16, token: &str, method: &str, path: &str, body: &[u8]) -> Reply {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    exchange(
        stream,
        &request(method, path, "localhost", Some(token), body),
    )
    .await
}

async fn agent(
    config: &Config,
    id: &str,
    method: &str,
    target: &str,
    host: &str,
    token: Option<&str>,
    body: &[u8],
) -> Reply {
    let listener = config
        .listeners
        .iter()
        .find(|entry| entry.agent_id == id)
        .unwrap();
    let stream = UnixStream::connect(&listener.socket_path).await.unwrap();
    exchange(stream, &request(method, target, host, token, body)).await
}

fn assert_blocked(reply: &Reply) {
    assert_eq!(reply.status, REJECTION.status);
    assert_eq!(reply.header("x-blocked-by"), Some("admin-shield"));
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert!(reply.body == REJECTION.body, "source shield body is exact");
}

#[tokio::test]
async fn ephemeral_operator_port_is_shielded_before_agent_egress() {
    let directory = TempDir::new().unwrap();
    let token = synthetic();
    let config = config(directory.path(), &token);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let before = events(&config)
        .into_iter()
        .filter(|row| row["event"] == "proxy.egress")
        .count();

    let target = format!("http://127.0.0.1:{port}{TASK_PATH}");
    let host = format!("127.0.0.1:{port}");
    assert_blocked(&agent(&config, "alice", "GET", &target, &host, Some(&token), b"").await);
    assert_blocked(&agent(&config, "bob", "CONNECT", &host, &host, Some(&token), b"").await);

    let after = events(&config)
        .into_iter()
        .filter(|row| row["event"] == "proxy.egress")
        .count();
    assert_eq!(after, before, "shielded operator requests do not dial");
    assert_shutdown(proxy, &config, port).await;
}

fn events(config: &Config) -> Vec<Value> {
    std::fs::read_to_string(&config.event_log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn assert_private(config: &Config, secrets: &[&str]) {
    let log = std::fs::read_to_string(&config.event_log).unwrap();
    for secret in secrets {
        assert!(
            !log.contains(secret),
            "operator secret must stay out of events"
        );
        let hex: String = secret
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(
            !log.contains(&hex),
            "hex operator secret must stay out of events"
        );
    }
}

async fn assert_shutdown(proxy: Proxy, config: &Config, port: u16) {
    tokio::time::timeout(Duration::from_secs(5), proxy.shutdown())
        .await
        .expect("proxy drains owned listeners");
    assert!(!config.readiness_file.exists());
    for listener in &config.listeners {
        assert!(!listener.socket_path.exists());
    }
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err()
    );
    let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("operator port released");
    drop(rebound);
}

struct Peer {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Peer {
    async fn bind(address: (Ipv4Addr, u16), response_headers: &str) -> Self {
        let listener = TcpListener::bind(address).await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = accepts.clone();
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n{response_headers}\r\nowned").into_bytes();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let mut head = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    head.push(byte);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(head.len() < 16_384);
                }
                stream.write_all(&response).await.unwrap();
            }
        });
        Self {
            address,
            accepts,
            task,
        }
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
        assert!(TcpStream::connect(self.address).await.is_err());
    }
}

#[tokio::test]
async fn raw_registry_reload_startup_ownership_restart_and_no_activation() {
    let directory = TempDir::new().unwrap();
    let token = synthetic();
    let replacement_token = synthetic();
    let secret = synthetic();
    let mut config = config(directory.path(), &token);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let peer = Peer::bind((Ipv4Addr::LOCALHOST, 0), "").await;
    let host = peer.address.to_string();
    let target = format!("http://{host}/owned?unchanged=yes");
    let raw = json!({
        "metadata":{"task_id":"authored-id"},
        "unknown":{"synthetic_secret":secret,"sequence":[3,1]},
        "permissions":[{"action":"network:request","resource":"*","effect":"deny"}]
    });
    let put_body = serde_json::to_vec(&json!({"policy":raw})).unwrap();
    for id in ["alpha", "beta"] {
        let reply = admin(
            port,
            &token,
            "PUT",
            &format!("/admin/policy/task/{id}"),
            &put_body,
        )
        .await;
        assert_eq!(reply.status, 200);
        let expected = format!(
            "{{\n  \"status\": \"updated\",\n  \"task_id\": \"{id}\",\n  \"permission_count\": 1,\n  \"message\": \"Task policy updated\"\n}}"
        );
        assert!(
            reply.body == expected.as_bytes(),
            "source PUT bytes and field order"
        );
        assert_eq!(reply.header("content-type"), Some("application/json"));
        assert_eq!(
            reply.header("content-length"),
            Some(expected.len().to_string().as_str())
        );
        let reply = admin(
            port,
            &token,
            "GET",
            &format!("/admin/policy/task/{id}"),
            b"",
        )
        .await;
        assert_eq!(reply.status, 200);
        let expected = serde_json::to_string_pretty(&json!({"task_id":id,"policy":raw})).unwrap();
        assert!(
            reply.body == expected.as_bytes(),
            "authorized raw document is preserved exactly"
        );
    }
    for id in ["alice", "bob"] {
        assert_eq!(
            agent(&config, id, "GET", &target, &host, None, b"")
                .await
                .status,
            200
        );
    }
    assert_eq!(
        peer.accepts.load(Ordering::SeqCst),
        2,
        "registered deny tasks are not active"
    );

    let replacement = json!({"unknown":{"synthetic_secret":secret},"permissions":[]});
    let body = serde_json::to_vec(&json!({"policy":replacement})).unwrap();
    assert_eq!(
        admin(port, &token, "PUT", TASK_PATH, &body).await.status,
        200
    );
    let bad = br#"{"policy":{"permissions":[{"action":"network:request","resource":"*","effect":"invalid"}]}}"#;
    assert_eq!(admin(port, &token, "PUT", TASK_PATH, bad).await.status, 400);
    assert!(admin(port, &token, "GET", TASK_PATH, b"").await.json()["policy"] == replacement);
    assert!(
        admin(port, &token, "GET", "/admin/policy/task/beta", b"")
            .await
            .json()["policy"]
            == raw
    );

    // Changing both the old file contents and configured filename cannot rotate
    // a startup-owned token, and a new requested port cannot move its listener.
    std::fs::write(
        config.admin_api_token_file.as_ref().unwrap(),
        &replacement_token,
    )
    .unwrap();
    let other_token = directory.path().join("replacement-token");
    std::fs::write(&other_token, &replacement_token).unwrap();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    config.admin_port = Some(occupied.local_addr().unwrap().port());
    config.admin_api_token_file = Some(other_token);
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(admin_port(&config), port);
    // The current configured port B and actual startup endpoint A are separate
    // protections. Check both while network policy still allows the requests.
    for protected in [port, config.admin_port.unwrap()] {
        let host = format!("2130706433:{protected}");
        assert_blocked(
            &agent(
                &config,
                "alice",
                "GET",
                &format!("http://{host}/health"),
                &host,
                Some(&token),
                b"",
            )
            .await,
        );
    }
    std::fs::write(config.policy_file.as_ref().unwrap(), DENY).unwrap();
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(admin_port(&config), port);
    assert_eq!(
        admin(port, &replacement_token, "GET", TASK_PATH, b"")
            .await
            .status,
        401
    );
    assert!(admin(port, &token, "GET", TASK_PATH, b"").await.json()["policy"] == replacement);
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        403
    );
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 2);

    let recorded = events(&config);
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["audit_intent"] == "admin.task_policy_update")
            .count(),
        3
    );
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["audit_intent"] == "admin.auth_failure")
            .count(),
        1
    );
    assert_private(&config, &[&token, &replacement_token, &secret]);
    assert_shutdown(proxy, &config, port).await;
    drop(occupied);
    config.admin_port = Some(0);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    assert_eq!(
        admin(port, &replacement_token, "GET", TASK_PATH, b"")
            .await
            .status,
        404
    );
    assert_eq!(
        admin(
            port,
            &replacement_token,
            "GET",
            "/admin/policy/task/beta",
            b""
        )
        .await
        .status,
        404
    );
    assert_shutdown(proxy, &config, port).await;
    peer.stop().await;
}

#[tokio::test]
async fn task_activation_boundary_publishes_enforcement_config_hash_and_clear() {
    let directory = TempDir::new().unwrap();
    let token = synthetic();
    let agent_token = synthetic();
    let mut config = config(directory.path(), &token);
    config.agent_api_enabled = true;
    let data_dir = directory.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("agent_token"), &agent_token).unwrap();
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let peer = Peer::bind((Ipv4Addr::LOCALHOST, 0), "").await;
    let host = peer.address.to_string();
    let target = format!("http://{host}/task");
    let deny_first = json!({"permissions":[
        {"action":"network:request","resource":"*","effect":"deny"}
    ]});
    let deny_second = json!({"permissions":[
        {"action":"network:request","resource":"other.invalid/*","effect":"deny"}
    ]});
    let put = |policy: &Value| serde_json::to_vec(&json!({"policy":policy})).unwrap();

    assert_eq!(
        admin(
            port,
            &token,
            "PUT",
            "/admin/policy/task/alpha",
            &put(&deny_first),
        )
        .await
        .status,
        200
    );
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        200,
        "registration does not activate enforcement"
    );
    let baseline_config = agent(
        &config,
        "alice",
        "GET",
        "http://_safeyolo.proxy.internal/config",
        "_safeyolo.proxy.internal",
        Some(&agent_token),
        b"",
    )
    .await
    .json();

    let activated = admin(
        port,
        &token,
        "POST",
        "/admin/policy/task/alpha/activate",
        b"",
    )
    .await;
    assert_eq!(activated.status, 200);
    assert_eq!(activated.json()["status"], "activated");
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        403,
        "the published task overlay reaches the request evaluator"
    );
    let active_config = agent(
        &config,
        "alice",
        "GET",
        "http://_safeyolo.proxy.internal/config",
        "_safeyolo.proxy.internal",
        Some(&agent_token),
        b"",
    )
    .await
    .json();
    assert_ne!(active_config["policy_hash"], baseline_config["policy_hash"]);
    assert_eq!(active_config["policy_hash"].as_str().unwrap().len(), 23);
    assert_eq!(
        admin(port, &token, "GET", "/admin/policy/task/alpha", b"")
            .await
            .json()["policy"],
        deny_first
    );

    // Replacement is retained as a candidate and does not silently change the
    // selected generation until the explicit activation boundary is crossed.
    assert_eq!(
        admin(
            port,
            &token,
            "PUT",
            "/admin/policy/task/alpha",
            &put(&deny_second),
        )
        .await
        .status,
        200
    );
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        403
    );
    let native_invalid = json!({"permissions":[
        {"action":"network:request","resource":"*","effect":"budget","budget":-1}
    ]});
    assert_eq!(
        admin(
            port,
            &token,
            "PUT",
            "/admin/policy/task/alpha",
            &put(&native_invalid),
        )
        .await
        .status,
        200,
        "schema admission retains the raw candidate"
    );
    assert_eq!(
        admin(
            port,
            &token,
            "POST",
            "/admin/policy/task/alpha/activate",
            b"",
        )
        .await
        .status,
        400,
        "native activation rejects a matcher-invalid candidate"
    );
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        403,
        "failed activation retains the previous enforcement generation"
    );
    assert_eq!(
        admin(
            port,
            &token,
            "PUT",
            "/admin/policy/task/alpha",
            &put(&deny_second),
        )
        .await
        .status,
        200
    );
    assert_eq!(
        admin(
            port,
            &token,
            "POST",
            "/admin/policy/task/alpha/activate",
            b"",
        )
        .await
        .status,
        200
    );
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        200,
        "replacement takes effect only after activation"
    );
    let replaced_config = agent(
        &config,
        "alice",
        "GET",
        "http://_safeyolo.proxy.internal/config",
        "_safeyolo.proxy.internal",
        Some(&agent_token),
        b"",
    )
    .await
    .json();
    assert_ne!(replaced_config["policy_hash"], active_config["policy_hash"]);

    let cleared = admin(port, &token, "DELETE", "/admin/policy/task/alpha", b"").await;
    assert_eq!(cleared.status, 200);
    assert_eq!(cleared.json()["status"], "cleared");
    assert_eq!(
        agent(&config, "alice", "GET", &target, &host, None, b"")
            .await
            .status,
        200
    );
    let cleared_config = agent(
        &config,
        "alice",
        "GET",
        "http://_safeyolo.proxy.internal/config",
        "_safeyolo.proxy.internal",
        Some(&agent_token),
        b"",
    )
    .await
    .json();
    assert_eq!(
        cleared_config["policy_hash"],
        baseline_config["policy_hash"]
    );
    assert_eq!(
        admin(port, &token, "GET", "/admin/policy/task/alpha", b"")
            .await
            .status,
        404
    );
    assert_shutdown(proxy, &config, port).await;
    peer.stop().await;
}

#[tokio::test]
async fn occupied_operator_bind_never_publishes_agent_sockets_or_readiness() {
    let directory = TempDir::new().unwrap();
    let token = synthetic();
    let mut config = config(directory.path(), &token);
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = occupied.local_addr().unwrap();
    config.admin_port = Some(address.port());
    assert!(Proxy::start(config.clone()).await.is_err());
    assert!(!config.readiness_file.exists());
    assert!(
        !config.event_log.exists(),
        "failed bind precedes runtime publication"
    );
    for listener in &config.listeners {
        assert!(!listener.socket_path.exists());
    }
    assert_eq!(occupied.local_addr().unwrap(), address);
    drop(occupied);
    config.admin_api_token_file = Some("".into());
    let proxy = Proxy::start(config.clone()).await.unwrap();
    assert_eq!(admin_port(&config), address.port());
    assert_eq!(
        admin(address.port(), &token, "GET", "/health", b"")
            .await
            .status,
        200
    );
    assert_eq!(
        admin(address.port(), &token, "GET", TASK_PATH, b"")
            .await
            .status,
        401
    );
    assert_private(&config, &[&token]);
    assert_shutdown(proxy, &config, address.port()).await;
}

#[tokio::test]
async fn both_agents_cannot_reach_operator_aliases_but_same_port_peer_remains_usable() {
    let directory = TempDir::new().unwrap();
    let token = DETECTABLE_BEARER_TOKEN.to_owned();
    let secret = synthetic();
    let mut config = config(directory.path(), &token);
    // PUT is rejected before token-file lookup by the agent facade, so this
    // enabled-route witness reads no sandbox Agent API credential.
    config.agent_api_enabled = true;
    let extra_peer = Peer::bind((Ipv4Addr::LOCALHOST, 0), "").await;
    config.admin_shield_extra_ports = extra_peer.address.port().to_string();
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    // Source textual local-host protection applies to the configured port.
    // Align that port with A for this source-rule matrix; other tests preserve
    // port 0 and change the configured port to prove independent A protection.
    config.admin_port = Some(port);
    proxy.reload(config.clone()).await.unwrap();
    let peer = Peer::bind(
        (Ipv4Addr::new(127, 0, 0, 2), port),
        "X-Blocked-By: admin-shield\r\n",
    )
    .await;
    let different_port_peer = Peer::bind((Ipv4Addr::LOCALHOST, 0), "").await;
    let body =
        serde_json::to_vec(&json!({"policy":{"unknown":{"synthetic_secret":secret}}})).unwrap();
    let aliases = [
        "127.0.0.1",
        "localhost",
        "LOCALHOST",
        "owned.localhost",
        "0.0.0.0",
        "[::1]",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "[::ffff:127.0.0.1]",
    ];
    for id in ["alice", "bob"] {
        for alias in aliases {
            let host = format!("{alias}:{port}");
            let target = format!("http://{host}{TASK_PATH}");
            let reply = agent(&config, id, "PUT", &target, &host, Some(&token), &body).await;
            assert_eq!(reply.status, REJECTION.status, "{id} PUT {alias}");
            assert_blocked(&reply);
            let reply = agent(&config, id, "CONNECT", &host, &host, Some(&token), b"").await;
            assert_eq!(reply.status, REJECTION.status, "{id} CONNECT {alias}");
            assert_blocked(&reply);
        }
        let extra_host = format!("2130706433:{}", extra_peer.address.port());
        assert_blocked(
            &agent(
                &config,
                id,
                "GET",
                &format!("http://{extra_host}/owned"),
                &extra_host,
                Some(&token),
                b"",
            )
            .await,
        );
        assert_blocked(
            &agent(
                &config,
                id,
                "CONNECT",
                &extra_host,
                &extra_host,
                Some(&token),
                b"",
            )
            .await,
        );
        let reply = agent(
            &config,
            id,
            "PUT",
            &format!("http://_safeyolo.proxy.internal{TASK_PATH}"),
            "_safeyolo.proxy.internal",
            Some(&token),
            &body,
        )
        .await;
        assert_eq!(reply.status, 405);
        let host = peer.address.to_string();
        let reply = agent(
            &config,
            id,
            "GET",
            &format!("http://{host}/owned"),
            &host,
            None,
            b"",
        )
        .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("x-blocked-by"), Some("admin-shield"));
        assert!(reply.body == b"owned");
        let different_port_host = different_port_peer.address.to_string();
        let reply = agent(
            &config,
            id,
            "GET",
            &format!("http://{different_port_host}/owned"),
            &different_port_host,
            None,
            b"",
        )
        .await;
        assert_eq!(reply.status, 200);
        assert!(reply.header("x-blocked-by").is_none());
        assert!(reply.body == b"owned");
    }
    assert_eq!(admin(port, &token, "GET", TASK_PATH, b"").await.status, 404);
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 2);
    assert_eq!(different_port_peer.accepts.load(Ordering::SeqCst), 2);
    let recorded = events(&config);
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["event"] == "proxy.egress")
            .count(),
        4
    );
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["event"] == "proxy.admin_api")
            .count(),
        0
    );
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["blocked_by"] == "admin-shield")
            .count(),
        aliases.len() * 4 + 4
    );
    // An upstream header remains wire data; it cannot forge local enforcement
    // evidence. Check the two allowed requests separately from genuine blocks.
    for (host, control_port) in [
        (peer.address.ip().to_string(), port),
        (
            different_port_peer.address.ip().to_string(),
            different_port_peer.address.port(),
        ),
    ] {
        let controls: Vec<&Value> = recorded
            .iter()
            .filter(|row| {
                row["event"] == "proxy.request"
                    && row["host"] == host
                    && row["port"] == control_port
            })
            .collect();
        assert_eq!(controls.len(), 2);
        for row in controls {
            assert_eq!(
                row["coverage"],
                "native_network_guard_circuits_and_test_context"
            );
            assert_eq!(row["decision"], "allow");
            assert!(row.get("blocked_by").is_none());
            assert!(row.get("block_reason").is_none());
        }
    }
    let credential_events: Vec<&Value> = recorded
        .iter()
        .filter(|row| row["event"] == "proxy.credential_guard")
        .collect();
    assert_eq!(credential_events.len(), 4);
    for row in credential_events {
        assert_eq!(row["outcome"], "no_detection");
        assert!(row["host"] == "127.0.0.2" || row["host"] == "127.0.0.1");
    }
    assert_eq!(extra_peer.accepts.load(Ordering::SeqCst), 0);
    assert_private(&config, &[&token, &secret]);
    assert_shutdown(proxy, &config, port).await;
    peer.stop().await;
    different_port_peer.stop().await;
    extra_peer.stop().await;
}

#[tokio::test]
async fn immediate_parent_alias_and_invalid_shield_reload_preserve_live_containment() {
    let directory = TempDir::new().unwrap();
    let token = DETECTABLE_BEARER_TOKEN.to_owned();
    let mut config = config(directory.path(), &token);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    // The immediate numeric parent must be checked even though the requested
    // origin is a different owned endpoint. A regression can only reach that
    // owned control, so this witness cannot cause external DNS or egress.
    let peer = Peer::bind((Ipv4Addr::new(127, 0, 0, 2), 0), "").await;
    let target_host = peer.address.to_string();
    let target = format!("http://{target_host}/health");
    config.parent_proxy = Some(format!("http://2130706433:{port}"));
    proxy.reload(config.clone()).await.unwrap();
    for malformed in ["²".to_owned(), "0".repeat(4301)] {
        let mut rejected = config.clone();
        rejected.admin_shield_extra_ports = malformed;
        rejected.parent_proxy = None;
        assert!(proxy.reload(rejected).await.is_err());
        assert_eq!(admin_port(&config), port);
        assert_eq!(admin(port, &token, "GET", "/health", b"").await.status, 200);
        for id in ["alice", "bob"] {
            let reply = agent(&config, id, "GET", &target, &target_host, Some(&token), b"").await;
            assert_blocked(&reply);
            let reply = agent(
                &config,
                id,
                "CONNECT",
                &target_host,
                &target_host,
                Some(&token),
                b"",
            )
            .await;
            assert_blocked(&reply);
            let host = format!("127.0.0.1:{port}");
            assert_blocked(
                &agent(
                    &config,
                    id,
                    "GET",
                    &format!("http://{host}/health"),
                    &host,
                    Some(&token),
                    b"",
                )
                .await,
            );
        }
    }
    let recorded = events(&config);
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["event"] == "proxy.egress")
            .count(),
        0
    );
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["event"] == "proxy.admin_api")
            .count(),
        0
    );
    assert_eq!(
        recorded
            .iter()
            .filter(|row| row["blocked_by"] == "admin-shield")
            .count(),
        12
    );
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 0);
    assert_private(&config, &[&token]);
    assert_shutdown(proxy, &config, port).await;
    peer.stop().await;
}

// /dev/full is an actual failing output sink. The policy state and both HTTP
// listeners remain real; no mocked audit callback supplies the result.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn reset_commits_when_evidence_fails_and_survives_sink_recovery() {
    let directory = TempDir::new().unwrap();
    let token = synthetic();
    let config = config(directory.path(), &token);
    std::fs::write(
        config.policy_file.as_ref().unwrap(),
        "[[permissions]]\naction = \"network:request\"\nresource = \"*\"\neffect = \"budget\"\nbudget = 1\n",
    )
    .unwrap();
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let port = admin_port(&config);
    let peer = Peer::bind((Ipv4Addr::LOCALHOST, 0), "").await;
    let host = peer.address.to_string();
    let target = format!("http://{host}/budget-evidence");
    // The source GCRA burst of one permits two immediate initial requests.
    for expected in [200, 200, 429] {
        assert_eq!(
            agent(&config, "alice", "GET", &target, &host, None, b"")
                .await
                .status,
            expected
        );
    }
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 2);
    let before = admin(port, &token, "GET", "/admin/budgets", b"").await;
    assert_eq!(before.status, 200);
    assert_eq!(before.json()["tracked_keys"], 1);
    let saved_events = std::fs::read(&config.event_log).unwrap();

    let mut broken_sink = config.clone();
    broken_sink.event_log = "/dev/full".into();
    proxy.reload(broken_sink.clone()).await.unwrap();
    assert_eq!(admin_port(&broken_sink), port);
    // A rejected body must not commit an all-key reset or emit success evidence.
    let rejected = admin(port, &token, "POST", "/admin/budgets/reset", b"{").await;
    assert_eq!(rejected.status, 400);
    assert_eq!(rejected.header("x-safeyolo-evidence-error"), None);
    assert_eq!(
        admin(port, &token, "GET", "/admin/budgets", b"")
            .await
            .json(),
        before.json()
    );
    let reset = admin(port, &token, "POST", "/admin/budgets/reset", b"").await;
    assert_eq!(reset.status, 200);
    assert_eq!(reset.header("x-safeyolo-evidence-error"), Some("true"));
    assert_eq!(
        reset.json(),
        json!({"status":"ok", "resource":"all", "reset_count":0})
    );
    let after = admin(port, &token, "GET", "/admin/budgets", b"").await;
    assert_eq!(after.status, 200);
    assert_eq!(after.header("x-safeyolo-evidence-error"), None);
    assert_eq!(after.json()["tracked_keys"], 0);
    assert!(std::fs::read(&config.event_log).unwrap() == saved_events);
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 2);

    // A real reload restores the sink while retaining the committed empty map.
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(admin_port(&config), port);
    assert_eq!(
        admin(port, &token, "GET", "/admin/budgets", b"")
            .await
            .json()["tracked_keys"],
        0
    );
    assert_eq!(
        agent(&config, "bob", "GET", &target, &host, None, b"")
            .await
            .status,
        200
    );
    assert_eq!(peer.accepts.load(Ordering::SeqCst), 3);
    let reset = admin(port, &token, "POST", "/admin/budgets/reset", b"{}").await;
    assert_eq!(reset.status, 200);
    assert_eq!(reset.header("x-safeyolo-evidence-error"), None);
    let audit_names: Vec<_> = events(&config)
        .into_iter()
        .filter_map(|row| row["audit_intent"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(audit_names, ["admin.budget_reset", "admin.budgets_reset"]);
    assert_private(&config, &[&token]);
    assert_shutdown(proxy, &config, port).await;
    peer.stop().await;
}
