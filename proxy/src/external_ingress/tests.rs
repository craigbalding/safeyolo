use super::*;
use crate::tls::CertificateAuthority;
use std::{path::Path, sync::Mutex, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(8);
const TOKEN: &str = "owned-ingress-api-token";
const HOST: &str = "ingress-origin.invalid";
const BUDGET_HOST: &str = "budget-origin.invalid";
const CONTEXT: &str = "X-SafeYolo-Test-Context: run=external-proof;agent=bob;test=ingress";

fn config(root: &Path, body_limit: usize) -> Config {
    for path in ["data", "logs", "builtin-services", "services"] {
        std::fs::create_dir_all(root.join(path)).unwrap();
    }
    std::fs::write(root.join("data/admin_token"), "owned-ingress-admin-token").unwrap();
    std::fs::write(root.join("data/agent_token"), TOKEN).unwrap();
    std::fs::write(
        root.join("data/instance_id"),
        "sy-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    std::fs::write(root.join("policy.toml"), policy("deny")).unwrap();
    std::fs::write(
        root.join("config.toml"),
        format!(
            r#"
admin_port=0
circuit_state_file=''
[capture]
max_request_body_bytes={body_limit}
max_response_body_bytes={body_limit}
[[listeners]]
agent_id='alice'
socket_path='alice.sock'
source_id='192.0.2.1'
[[listeners]]
agent_id='bob'
socket_path='bob.sock'
source_id='192.0.2.2'
[[ingress_bindings]]
name='mobile-test'
listen='127.0.0.1:0'
agent='alice'
"#
        ),
    )
    .unwrap();
    crate::native_config::read(&root.join("config.toml")).unwrap()
}

fn policy(credential_effect: &str) -> String {
    format!(
        r#"
[hosts.'*']
egress='deny'
[hosts.'{HOST}']
[[hosts.'{HOST}'.rules]]
action='credential:use'
resource='{HOST}/*'
effect='{credential_effect}'
condition={{credential='ingress-fixture:*'}}
[agents.alice]
agent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
[agents.alice.hosts.'{HOST}']
egress='allow'
[agents.alice.hosts.'{BUDGET_HOST}']
egress='allow'
rate=1
[agents.bob]
agent_id='ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
[agents.bob.hosts.'{BUDGET_HOST}']
egress='allow'
[credential.ingress-fixture]
match=['ownedsecret-[a-z]+']
headers=['x-api-key']
allowed_hosts=['{HOST}']
[controls.test_context]
target_hosts=['{HOST}', '{BUDGET_HOST}']
"#
    )
}

fn marker(config: &Config) -> Value {
    serde_json::from_slice(&std::fs::read(&config.readiness_file).unwrap()).unwrap()
}
fn address(config: &Config) -> SocketAddr {
    marker(config)["ingress_bindings"][0]["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}
async fn exchange(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    url: &str,
    headers: &[&str],
) -> (u16, String) {
    let mut request =
        format!("GET {url} HTTP/1.1\r\nHost: forged.invalid\r\nConnection: close\r\n");
    for header in headers {
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body.into(),
    )
}
async fn uds(config: &Config, agent: &str, url: &str, headers: &[&str]) -> (u16, String) {
    let path = &config
        .listeners
        .iter()
        .find(|entry| entry.agent_id == agent)
        .unwrap()
        .socket_path;
    exchange(UnixStream::connect(path).await.unwrap(), url, headers).await
}
async fn curl(config: &Config, url: &str, extra: &[&str]) -> (u16, String) {
    let output = timeout(
        LIMIT,
        tokio::process::Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "6",
                "--http1.1",
                "--proxy",
            ])
            .arg(format!("http://{}", address(config)))
            .args([
                "--header",
                CONTEXT,
                "--header",
                "X-SafeYolo-Agent: bob",
                "--header",
                "X-SafeYolo-Ingress: agent-uds",
                "--write-out",
                "\n%{http_code}",
            ])
            .args(extra)
            .arg(url)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "curl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let (body, status) = text.rsplit_once('\n').unwrap();
    (status.parse().unwrap(), body.into())
}

struct Origin {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn origin(root: &Path, tls: bool) -> Origin {
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let acceptor = if tls {
        let (pem, cert) = CertificateAuthority::create().unwrap();
        std::fs::write(root.join("ca.pem"), pem.as_bytes()).unwrap();
        std::fs::write(root.join("ca.crt"), cert).unwrap();
        let ca = CertificateAuthority::from_pem(pem.as_bytes()).unwrap();
        let leaf = ca.issue(HOST, time::OffsetDateTime::now_utc()).unwrap();
        let mut resolver = tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new();
        resolver.add(HOST, (*leaf).clone()).unwrap();
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(
            tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver)),
        )))
    } else {
        None
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let requests = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let mut stream: crate::tunnels::BoxStream = if let Some(acceptor) = &acceptor {
                Box::new(acceptor.accept(stream).await.unwrap())
            } else {
                Box::new(stream)
            };
            let head = crate::connection_events::tests::head(&mut stream).await;
            requests
                .lock()
                .unwrap()
                .push(String::from_utf8(head).unwrap());
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nowned-body").await.unwrap();
        }
    });
    Origin {
        address,
        seen,
        task,
    }
}
fn route(config: &mut Config, origin: &Origin, host: &str) {
    allow_origin(config, origin.address);
    config
        .target_ip_mappings
        .push(crate::config::TargetIpMapping {
            host: host.into(),
            ip: origin.address.ip(),
            port: Some(origin.address.port()),
            agents: vec![],
        });
}

fn allow_origin(config: &Config, address: SocketAddr) {
    let path = config.policy_file.as_ref().unwrap();
    let mut source = std::fs::read_to_string(path).unwrap();
    let table = format!("[hosts.'{address}']");
    if !source.contains(&table) {
        source.push_str(&format!("\n{table}\negress='allow'\n"));
        std::fs::write(path, source).unwrap();
    }
}

#[tokio::test]
async fn curl_http_connect_reuses_policy_credentials_budgets_and_scoped_store() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let mut config = config(root, 64);
    let http = origin(root, false).await;
    let https = origin(root, true).await;
    route(&mut config, &http, HOST);
    route(&mut config, &https, HOST);
    route(&mut config, &http, BUDGET_HOST);
    config.tls_ca_file = Some(root.join("ca.pem"));
    config.upstream_ca_file = Some(root.join("ca.crt"));
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let url = format!("http://{HOST}:{}/external", http.address.port());
    let (external, ordinary) = tokio::join!(
        curl(&config, &url, &[]),
        uds(&config, "alice", &url, &[CONTEXT])
    );
    assert_eq!(external, (200, "owned-body".into()));
    assert_eq!(ordinary, (200, "owned-body".into()));
    assert_eq!(
        uds(&config, "bob", &url, &[CONTEXT, "X-SafeYolo-Agent: alice"])
            .await
            .0,
        403
    );
    let secure = format!("https://{HOST}:{}/connect", https.address.port());
    let ca = root.join("ca.crt");
    assert_eq!(
        curl(&config, &secure, &["--cacert", ca.to_str().unwrap()]).await,
        (200, "owned-body".into())
    );
    assert_eq!(
        curl(
            &config,
            &url,
            &["--header", "X-Api-Key: ownedsecret-ephemeral"]
        )
        .await
        .0,
        403
    );
    assert_eq!(
        http.seen.lock().unwrap().len(),
        2,
        "denied requests did not reach origin"
    );
    std::fs::write(config.policy_file.as_ref().unwrap(), policy("allow")).unwrap();
    allow_origin(&config, http.address);
    allow_origin(&config, https.address);
    proxy.reload(config.clone()).await.unwrap();
    assert!(Arc::ptr_eq(
        &runtime.flow_recorder,
        &proxy.runtime.read().unwrap().flow_recorder
    ));
    assert_eq!(
        curl(
            &config,
            &url,
            &["--header", "X-Api-Key: ownedsecret-ephemeral"]
        )
        .await
        .0,
        200
    );
    let budget = format!("http://{BUDGET_HOST}:{}/budget", http.address.port());
    assert_eq!(curl(&config, &budget, &[]).await.0, 200);
    assert_eq!(uds(&config, "alice", &budget, &[CONTEXT]).await.0, 200,);
    assert_eq!(
        curl(&config, &budget, &[]).await.0,
        429,
        "ordinary and external share the existing two-request burst"
    );
    assert_eq!(
        uds(&config, "bob", &budget, &[CONTEXT]).await.0,
        200,
        "bob retains its ordinary allow rule without a rate limit"
    );
    let store = runtime.flow_recorder.store().unwrap();
    timeout(LIMIT, async {
        while store
            .search_flows(&json!({}).into())
            .unwrap()
            .as_array()
            .unwrap()
            .len()
            < 6
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let authorization = format!("Authorization: Bearer {TOKEN}");
    let api = "http://_safeyolo.proxy.internal/api/flows/search?evidence_owner=bob";
    let (status, text) = exchange(
        TcpStream::connect(address(&config)).await.unwrap(),
        api,
        &[&authorization],
    )
    .await;
    assert_eq!(status, 200);
    let found: Value = serde_json::from_str(&text).unwrap();
    assert!(found["count"].as_i64().unwrap() >= 4);
    let flows = found["flows"].as_array().unwrap();
    assert!(flows.iter().all(|flow| flow["evidence_owner"] == "alice"));
    let external = flows
        .iter()
        .find(|flow| flow["initiator"] == "external" && flow["status_code"] == 200)
        .unwrap();
    let id = external["id"].as_i64().unwrap();
    let detail = format!("http://_safeyolo.proxy.internal/api/flows/{id}");
    assert_eq!(uds(&config, "bob", &detail, &[&authorization]).await.0, 404);
    let body_url = format!("{detail}/response-body");
    let (status, body) = exchange(
        TcpStream::connect(address(&config)).await.unwrap(),
        &body_url,
        &[&authorization],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["body_text"],
        "owned-body"
    );
    assert_eq!(
        uds(&config, "bob", &body_url, &[&authorization]).await.0,
        404
    );
    assert_eq!(
        exchange(
            TcpStream::connect(address(&config)).await.unwrap(),
            &detail,
            &[]
        )
        .await
        .0,
        401
    );
    let flow = store.get_flow(id).unwrap().unwrap();
    assert_eq!(flow["trusted_transport_identity"], "alice");
    assert_eq!(flow["source_type"], "external");
    assert_eq!(flow["source_id"], "mobile-test");
    let provenance: Value =
        serde_json::from_str(flow["attribution_provenance_json"].as_str().unwrap()).unwrap();
    assert_eq!(provenance["ingress"], "switchboard/mobile-test");
    assert_eq!(provenance["selected_agent"], "alice");
    proxy.shutdown().await;
    assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
    let rows: Vec<Value> = std::fs::read_to_string(root.join("logs/audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| crate::audit::parse_record(line).unwrap())
        .collect();
    let external: Vec<_> = rows
        .iter()
        .filter(|row| row["details"]["attribution"]["initiator"] == "external")
        .collect();
    assert!(external.iter().any(|row| row["event"]=="network.connection" && row["details"]["transport"]=="tcp"));
    assert!(external.iter().any(|row| row["event"] == "traffic.flow"));
    assert!(
        external
            .iter()
            .any(|row| row["event"] == "security.indicator")
    );
    assert!(
        external
            .iter()
            .any(|row| row["event"] == "security.credential_guard"
                && row["details"]["client_connection_id"].is_string())
    );
    assert!(rows.iter().any(
        |row| row["event"] == "network.connection" && row["details"]["ingress"] == "agent-uds"
    ));
    for row in external {
        assert_eq!(row["schema_version"], 2);
        assert_eq!(row["agent"], "alice");
        assert!(row["details"].get("sandbox_run").is_none());
        assert_eq!(
            row["details"]["attribution"]["attribution_provenance"]["binding"],
            "mobile-test"
        );
    }
    assert!(
        !std::fs::read_to_string(root.join("logs/audit.jsonl"))
            .unwrap()
            .contains("ownedsecret-ephemeral")
    );
}

#[tokio::test]
async fn occupied_bind_missing_replaced_target_remove_and_restart_preserve_owners() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = occupied.local_addr().unwrap();
    config.ingress_bindings[0].listen = listen;
    assert!(
        Proxy::start(config.clone())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("mobile-test")
    );
    assert!(!config.listeners[0].socket_path.exists());
    drop(occupied);
    let mut proxy = Proxy::start(config.clone()).await.unwrap();
    let before = std::fs::read(&config.readiness_file).unwrap();
    let previous_shield = proxy.runtime.read().unwrap().admin_shield.clone();
    let health = "http://_safeyolo.proxy.internal/health";
    let authorization = format!("Authorization: Bearer {TOKEN}");
    assert_eq!(
        exchange(
            TcpStream::connect(listen).await.unwrap(),
            health,
            &[&authorization]
        )
        .await
        .0,
        200
    );
    let unrelated = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut rejected = config.clone();
    rejected.ingress_bindings.push(Binding {
        name: "occupied".into(),
        listen: unrelated.local_addr().unwrap(),
        agent: "bob".into(),
    });
    assert!(proxy.reload(rejected).await.is_err());
    assert!(!previous_shield.blocks_address(unrelated.local_addr().unwrap()));
    assert_eq!(std::fs::read(&config.readiness_file).unwrap(), before);
    assert_eq!(
        uds(&config, "alice", health, &[&authorization]).await.0,
        200
    );
    let mut suspended = config.clone();
    // Replace the selected path with another owner. The binding never follows it.
    suspended.listeners = vec![AgentListener {
        agent_id: "bob".into(),
        socket_path: config.listeners[0].socket_path.clone(),
        source_id: None,
    }];
    proxy.reload(suspended.clone()).await.unwrap();
    assert_eq!(
        marker(&config)["ingress_bindings"][0]["state"],
        "target_unavailable"
    );
    assert!(TcpStream::connect(listen).await.is_err());
    assert_eq!(
        uds(&suspended, "bob", health, &[&authorization]).await.0,
        200
    );
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(address(&config), listen);
    assert!(
        previous_shield.blocks_address(listen),
        "older admitted runtime snapshots observe new bindings"
    );
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"GET ").await.unwrap();
    let mut removed = config.clone();
    removed.ingress_bindings.clear();
    proxy.reload(removed).await.unwrap();
    assert!(
        marker(&config)["ingress_bindings"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Check bounded cleanup rather than one TCP handshake racing parallel
    // client subprocesses and descriptor closure.
    timeout(LIMIT, async {
        while TcpStream::connect(listen).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("removed ingress still accepts connections");
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(15), client.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0))
            || closed.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    proxy.reload(config.clone()).await.unwrap();
    assert_eq!(address(&config), listen);
    proxy.shutdown().await;
    assert!(!config.readiness_file.exists());
    let owned_after = TcpListener::bind(listen).await.unwrap();
    let socket = TcpStream::connect(unrelated.local_addr().unwrap())
        .await
        .unwrap();
    let (_accepted, _) = timeout(LIMIT, unrelated.accept()).await.unwrap().unwrap();
    drop(socket);
    assert_eq!(owned_after.local_addr().unwrap(), listen);
}

#[tokio::test]
async fn zero_body_retention_stays_metadata_only_for_external_flows() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    let origin = origin(directory.path(), false).await;
    route(&mut config, &origin, HOST);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let url = format!("http://{HOST}:{}/sparse", origin.address.port());
    assert_eq!(curl(&config, &url, &[]).await, (200, "owned-body".into()));
    proxy.shutdown().await;
    let store = runtime.flow_recorder.store().unwrap();
    let flows = store.search_flows(&json!({}).into()).unwrap();
    assert_eq!(flows.as_array().unwrap().len(), 1);
    let id = flows[0]["id"].as_i64().unwrap();
    assert!(
        store
            .body(id, crate::flow_store::Side::Response)
            .unwrap()
            .is_none_or(|body| body.body.is_empty())
    );
    let flow = store.get_flow(id).unwrap().unwrap();
    assert_eq!(flow["initiator"], "external");
    assert_ne!(flow["response_body_text_preview"], "owned-body");
}

#[tokio::test]
async fn ingress_endpoint_shield_stops_partition_hops_without_blocking_remote_ports() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    std::fs::write(
        config.policy_file.as_ref().unwrap(),
        "[hosts.'*']\negress='allow'\n",
    )
    .unwrap();
    for bind in ["127.0.0.1:0", "0.0.0.0:0", "[::]:0", "[::1]:0"] {
        config.ingress_bindings[0].listen = bind.parse().unwrap();
        let mut proxy = Proxy::start(config.clone()).await.unwrap();
        let endpoint = address(&config);
        let url = format!("http://127.0.0.1:{}/partition-hop", endpoint.port());
        if endpoint.is_ipv4()
            || endpoint.ip().is_unspecified()
                && !crate::admin_shield::BoundTcpEndpoint::new(
                    &proxy.ingress_bindings["mobile-test"].listener,
                )
                .unwrap()
                .ipv6_only
        {
            let (status, body) = uds(&config, "bob", &url, &[]).await;
            assert_eq!(status, 403);
            assert!(body.contains("Admin API not accessible through proxy"));
        }
        let hosts = if endpoint.is_ipv6() {
            ["[::1]", "[::]"]
        } else {
            ["127.1", "0.0.0.0"]
        };
        let urls = hosts.map(|host| format!("http://{host}:{}/partition-hop", endpoint.port()));
        for url in &urls {
            let (status, body) = uds(&config, "bob", url, &[]).await;
            assert_eq!(status, 403, "binding {bind}, destination {url}");
            assert!(body.contains("Admin API not accessible through proxy"));
        }
        let runtime = proxy.runtime.read().unwrap().clone();
        let shield = &runtime.admin_shield;
        for remote in ["192.0.2.10", "2001:db8::10"] {
            assert!(
                !shield.blocks_address(SocketAddr::new(remote.parse().unwrap(), endpoint.port()))
            );
        }
        if bind == "0.0.0.0:0" {
            assert!(shield.blocks_address(SocketAddr::from(([127, 0, 0, 2], endpoint.port()))));
        }
        proxy.reload(config.clone()).await.unwrap();
        for url in &urls {
            assert_eq!(uds(&config, "bob", url, &[]).await.0, 403);
        }
        proxy.shutdown().await;
        assert!(runtime.audit.wait_for_drain(LIMIT).unwrap());
        let rows: Vec<Value> = std::fs::read_to_string(directory.path().join("logs/audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| crate::audit::parse_record(line).unwrap())
            .collect();
        assert!(rows.iter().any(|row| row["agent"] == "bob"
            && row["event"] == "network.connection"
            && row["details"]["ingress"] == "agent-uds"));
        assert!(
            rows.iter()
                .all(|row| row["details"]["ingress"] != "switchboard/mobile-test")
        );
    }
}

#[test]
fn bindings_reject_ambiguous_owners_and_duplicate_names_before_publication() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config
        .ingress_bindings
        .push(config.ingress_bindings[0].clone());
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unique name")
    );
    config.ingress_bindings.pop();
    let mut duplicate = config.listeners[0].clone();
    duplicate.socket_path = directory.path().join("second-alice.sock");
    config.listeners.push(duplicate);
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("multiple UDS listeners")
    );
}

#[tokio::test]
async fn existing_uds_acceptor_is_required_and_replacement_cannot_claim_the_binding() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), 0);
    let proxy = Proxy::start(config.clone()).await.unwrap();
    let alice = &config.listeners[0].socket_path;
    let bob = &config.listeners[1].socket_path;
    let saved = directory.path().join("saved.sock");
    std::fs::rename(alice, &saved).unwrap();
    for replaced in [false, true] {
        if replaced {
            std::fs::rename(bob, alice).unwrap();
        }
        let mut client = TcpStream::connect(address(&config)).await.unwrap();
        let _ = client.write_all(b"GET http://_safeyolo.proxy.internal/health HTTP/1.1\r\nHost: forged.invalid\r\nX-SafeYolo-Agent: bob\r\n\r\n").await;
        let mut byte = [0];
        let result = timeout(LIMIT, client.read(&mut byte)).await.unwrap();
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
        );
        if replaced {
            std::fs::rename(alice, bob).unwrap();
        }
    }
    std::fs::rename(&saved, alice).unwrap();
    let authorization = format!("Authorization: Bearer {TOKEN}");
    assert_eq!(
        exchange(
            TcpStream::connect(address(&config)).await.unwrap(),
            "http://_safeyolo.proxy.internal/health",
            &[&authorization]
        )
        .await
        .0,
        200
    );
    // A canceled provenance note must not turn its queued host-bound peer into
    // an ordinary sandbox connection. Unnamed ordinary UDS clients still work.
    let orphan = UnixSocket::new_stream().unwrap();
    orphan.bind(directory.path().join("orphan.sock")).unwrap();
    let mut orphan = orphan.connect(alice).await.unwrap();
    let request = format!(
        "GET http://_safeyolo.proxy.internal/health HTTP/1.1\r\nHost: ignored.invalid\r\n{authorization}\r\n\r\n"
    );
    let _ = orphan.write_all(request.as_bytes()).await;
    let mut byte = [0];
    let rejected = timeout(LIMIT, orphan.read(&mut byte)).await.unwrap();
    assert!(
        matches!(rejected, Ok(0))
            || rejected.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    assert_eq!(
        uds(
            &config,
            "alice",
            "http://_safeyolo.proxy.internal/health",
            &[&authorization]
        )
        .await
        .0,
        200
    );
    let peers = proxy.ingress_peers.clone();
    proxy.shutdown().await;
    assert!(
        peers.0.lock().unwrap().is_empty(),
        "pending provenance is removed on every terminal path"
    );
}
