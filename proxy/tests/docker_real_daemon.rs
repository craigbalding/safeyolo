//! Finite real Engine/Compose witness for #1437 and #1438. The operator supplies
//! an owned disposable daemon, authenticated HTTPS endpoint and private inputs.
//! This test does not provision a daemon or establish nested sandbox isolation.

use safeyolo_proxy::{
    Config, Proxy,
    credentials::{Credential, Secret},
    grants::{Grant, GrantScope},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    process::Command,
    time::timeout,
};

const AGENT_API_TOKEN: &str = "synthetic-docker-witness-agent-api";
const LIMIT: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct Inputs {
    endpoint: String,
    ca: PathBuf,
    credential: String,
    image: String,
}
impl Inputs {
    fn read() -> Self {
        let endpoint = std::env::var("SAFEYOLO_DOCKER_ENDPOINT")
            .expect("owned HTTPS Docker endpoint required");
        assert!(
            endpoint.starts_with("https://"),
            "real proof requires authenticated HTTPS"
        );
        let ca = PathBuf::from(
            std::env::var_os("SAFEYOLO_DOCKER_CA_FILE").expect("endpoint CA file required"),
        );
        let credential = std::fs::read_to_string(
            std::env::var_os("SAFEYOLO_DOCKER_CREDENTIAL_FILE")
                .expect("private bearer file required"),
        )
        .unwrap()
        .trim()
        .to_owned();
        assert!(!credential.is_empty() && !credential.contains(['\r', '\n']));
        Self {
            endpoint,
            ca,
            credential,
            image: std::env::var("SAFEYOLO_DOCKER_IMAGE").unwrap_or_else(|_| "busybox:1.36".into()),
        }
    }
}

async fn start(root: &Path, inputs: &Inputs) -> Proxy {
    start_with_access(root, inputs, None, None).await
}
async fn start_with_access(
    root: &Path,
    inputs: &Inputs,
    access: Option<Value>,
    rename_grant: Option<&Grant>,
) -> Proxy {
    std::fs::create_dir_all(root.join("builtin")).unwrap();
    std::fs::create_dir_all(root.join("services")).unwrap();
    std::fs::create_dir_all(root.join("client")).unwrap();
    let mut definition = safeyolo_proxy::services::ServiceDefinition::from_yaml(include_str!(
        "../../contrib/docker/service.yaml"
    ))
    .unwrap()
    .raw;
    if let Some(access) = access {
        definition["capabilities"]["workloads"]["docker_access"] = access;
    }
    // Require the existing native grant mechanism for this witness's rename.
    // Static workload authorization still selects the bounded capability.
    if let Some(grant) = rename_grant {
        definition["risky_routes"] = json!([{"path":grant.path,"methods":[grant.method]}]);
    }
    definition["name"] = json!("docker-proof");
    definition["docker"]["endpoint"] = json!(inputs.endpoint);
    let endpoint: hyper::Uri = inputs.endpoint.parse().unwrap();
    definition["default_host"] = json!(endpoint.host().unwrap());
    std::fs::write(root.join("services/docker.yaml"), definition.to_string()).unwrap();
    // TOML service authorizations mint the scoped token and let runtime open
    // the native grant store used by the adopted effect-model admission.
    let mut policy = json!({
        "hosts": {
            endpoint.host().unwrap(): {"service":"docker-proof", "credentials":["unknown:*"]},
            format!("{}:{}", endpoint.host().unwrap(), endpoint.port_u16().unwrap_or(443)): {"egress":"allow"}
        },
        "agents": {"witness": {"services": {"docker-proof": {
            "capability":"workloads", "token":"docker-origin", "account":"proof"
        }}}}
    });
    if let Some(grant) = rename_grant {
        policy["agents"]["witness"]["grants"] = json!([grant]);
    }
    std::fs::write(root.join("policy.toml"), toml::to_string(&policy).unwrap()).unwrap();
    let vault = safeyolo_proxy::credentials::open(&root.join("data")).unwrap();
    let credential = Credential::new(
        "docker-origin",
        "bearer",
        Secret::new(inputs.credential.clone()),
    );
    vault.store(credential).unwrap();
    std::fs::write(root.join("data/agent_token"), AGENT_API_TOKEN).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&key).unwrap();
    std::fs::write(
        root.join("interception.pem"),
        format!("{}{}", key.serialize_pem(), ca.pem()),
    )
    .unwrap();
    start_saved_proxy(root, &inputs.ca).await
}

async fn start_saved_proxy(root: &Path, upstream_ca: &Path) -> Proxy {
    let config:Config=serde_json::from_value(json!({"listeners":[{"agent_id":"witness","socket_path":root.join("docker.sock")}],"policy_file":root.join("policy.toml"),
        "gateway_builtin_services_dir":root.join("builtin"),"gateway_services_dir":root.join("services"),"data_dir":root.join("data"),"readiness_file":root.join("ready"),
        "audit_log_path":root.join("audit.jsonl"),"flow_store_enabled":false,"flow_store_db_path":root.join("flows.sqlite3"),"circuit_breaker_enabled":false,"circuit_state_file":"",
        "tls_ca_file":root.join("interception.pem"),"upstream_ca_file":upstream_ca})).unwrap();
    let proxy = Proxy::start(config).await.unwrap();
    let (status, response) = wire(root, format!("GET http://_safeyolo.proxy.internal/gateway/services HTTP/1.1\r\nHost: _safeyolo.proxy.internal\r\nAuthorization: Bearer {AGENT_API_TOKEN}\r\nConnection: close\r\n\r\n").as_bytes()).await;
    assert_eq!(status, 200, "witness service discovery failed");
    let view: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(view["agent"], "witness");
    let service = &view["authorized"]["docker-proof"];
    assert_eq!(service["capability"], "workloads");
    let token = service["token"].as_str().expect("native workload token");
    std::fs::write(root.join("client/config.json"),json!({"HttpHeaders":{"X-SafeYolo-Docker-Service":"docker-proof","Authorization":format!("Bearer {token}")}}).to_string()).unwrap();
    proxy
}

fn docker(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command
        .args(args)
        .kill_on_drop(true)
        .env(
            "DOCKER_HOST",
            format!("unix://{}", root.join("docker.sock").display()),
        )
        .env("DOCKER_CONFIG", root.join("client"))
        .env("DOCKER_API_VERSION", "1.45")
        .env("DOCKER_BUILDKIT", "0")
        .env("COMPOSE_DOCKER_CLI_BUILD", "0")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH");
    command
}
async fn run(root: &Path, args: &[&str]) -> String {
    String::from_utf8(run_output(root, args).await.stdout).unwrap()
}
async fn run_output(root: &Path, args: &[&str]) -> std::process::Output {
    let out = timeout(LIMIT, docker(root, args).output())
        .await
        .expect("Docker client deadline")
        .unwrap();
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
async fn api(root: &Path, method: &str, path: &str, body: &Value) -> (u16, String) {
    let body = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).unwrap()
    };
    let client: Value =
        serde_json::from_slice(&std::fs::read(root.join("client/config.json")).unwrap()).unwrap();
    let authorization = client["HttpHeaders"]["Authorization"].as_str().unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: gateway.invalid\r\nX-SafeYolo-Docker-Service: docker-proof\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    request.extend_from_slice(&body);
    wire(root, &request).await
}

async fn wire(root: &Path, request: &[u8]) -> (u16, String) {
    let mut stream = UnixStream::connect(root.join("docker.sock")).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, response)
}

/// Fixture-only operator path. The bearer travels on stdin, and curl verifies
/// the configured CA/name. It never follows redirects or repeats a mutation.
async fn operator(
    inputs: &Inputs,
    root: &Path,
    method: &str,
    path: &str,
    body: &Value,
) -> (u16, Value) {
    let reply = operator_reply(inputs, root, method, path, body).await;
    (
        reply.status,
        serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
    )
}

struct EngineReply {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

async fn operator_reply(
    inputs: &Inputs,
    root: &Path,
    method: &str,
    path: &str,
    body: &Value,
) -> EngineReply {
    let payload = root.join("operator-body.json");
    let response_body = root.join("operator-response-body");
    let response_headers = root.join("operator-response-headers");
    std::fs::write(&payload, serde_json::to_vec(body).unwrap()).unwrap();
    let mut command = Command::new("curl");
    command
        .kill_on_drop(true)
        .args(["--silent", "--show-error", "--cacert"])
        .arg(&inputs.ca)
        .arg("--output")
        .arg(&response_body)
        .arg("--dump-header")
        .arg(&response_headers)
        .args([
            "--header",
            "@-",
            "--request",
            method,
            "--write-out",
            "%{http_code}",
            "--header",
            "Content-Type: application/json",
        ]);
    // --request HEAD alone makes curl expect the advertised GET body length.
    // --head uses HEAD semantics; its header output is not an entity body.
    if method == "HEAD" {
        command.arg("--head");
    }
    if !body.is_null() {
        command
            .arg("--data-binary")
            .arg(format!("@{}", payload.display()));
    }
    command
        .arg(format!("{}{path}", inputs.endpoint.trim_end_matches('/')))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("Authorization: Bearer {}\n", inputs.credential).as_bytes())
        .await
        .unwrap();
    let output = timeout(LIMIT, child.wait_with_output())
        .await
        .expect("operator observation deadline")
        .unwrap();
    assert!(
        output.status.success(),
        "operator endpoint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    EngineReply {
        status: String::from_utf8(output.stdout).unwrap().parse().unwrap(),
        headers: std::fs::read_to_string(response_headers).unwrap(),
        body: if method == "HEAD" {
            Vec::new()
        } else {
            std::fs::read(response_body).unwrap()
        },
    }
}

fn engine_reply_bytes(method: &str, reply: &EngineReply) -> Vec<u8> {
    let bodyless = method == "HEAD" || matches!(reply.status, 204 | 304);
    let mut head = format!("HTTP/1.1 {} Engine\r\nConnection: close\r\n", reply.status);
    // curl can include a CONNECT or informational header block. Use only the
    // final Engine headers, retaining Docker's ordinary negotiation metadata.
    let headers = reply.headers.trim_end().rsplit("\r\n\r\n").next().unwrap();
    for (name, value) in headers.lines().filter_map(|line| line.split_once(':')) {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "api-version"
                | "docker-experimental"
                | "ostype"
                | "server"
                | "builder-version"
                | "content-type"
        ) || (name.eq_ignore_ascii_case("content-length")
            && (method == "HEAD" || reply.status == 304))
        {
            head.push_str(&format!("{name}: {}\r\n", value.trim()));
        }
    }
    // curl has decoded transfer framing. Recompute the length only for replies
    // that carry a body; a 204 must not have Content-Length, and HEAD sends none.
    if !bodyless {
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    head.push_str("\r\n");
    let mut response = head.into_bytes();
    if !bodyless {
        response.extend_from_slice(&reply.body);
    }
    response
}

/// Forward to the actual authenticated Engine, but truncate the single named
/// creation's successful reply. All prerequisite and reconciliation reads stay
/// real Engine reads. There is no synthetic Docker state or mutation retry.
async fn interrupted_creation_origin(
    root: &Path,
    inputs: &Inputs,
    create_path: String,
    creations: Arc<AtomicUsize>,
    origin: TcpListener,
) -> (Inputs, tokio::task::JoinHandle<()>) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let ca = root.join("interrupted-origin.pem");
    std::fs::write(&ca, cert.pem()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let local = Inputs {
        endpoint: format!("https://{}", origin.local_addr().unwrap()),
        ca,
        ..inputs.clone()
    };
    let inputs = inputs.clone();
    let root = root.to_owned();
    let backend = tokio::spawn(async move {
        loop {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = tls.accept(stream).await.unwrap();
            timeout(LIMIT, async {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                    assert!(head.len() < 64 * 1024);
                }
                let head = String::from_utf8(head).unwrap();
                let mut words = head.lines().next().unwrap().split_whitespace();
                let method = words.next().unwrap();
                let path = words.next().unwrap();
                let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':')).collect();
                let authorization = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).unwrap().1.trim();
                assert!(authorization == format!("Bearer {}", inputs.credential), "endpoint credential missing");
                let length: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse().unwrap()).unwrap_or(0);
                assert!(length <= 10 * 1024 * 1024);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let body = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
                let create = method == "POST";
                if create {
                    assert_eq!(path, create_path);
                    if creations.fetch_add(1, Ordering::SeqCst) != 0 {
                        // Count a replay attempt, but never repeat its Engine effect.
                        stream.write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        return;
                    }
                } else {
                    assert!(matches!(method, "HEAD" | "GET" | "DELETE"));
                }
                let reply = operator_reply(&inputs, &root, method, path, &body).await;
                if create {
                    // Save the actual effect before any assertion or response loss.
                    std::fs::write(root.join("interrupted-engine-reply.json"), &reply.body).unwrap();
                    println!("Actual Engine creation before reply interruption: status {}, {}", reply.status, String::from_utf8_lossy(&reply.body));
                    assert_eq!(reply.status, 201);
                    stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{\"Id\":\"").await.unwrap();
                } else {
                    stream.write_all(&engine_reply_bytes(method, &reply)).await.unwrap();
                }
                stream.shutdown().await.unwrap();
            }).await.expect("interrupted-creation origin deadline");
        }
    });
    (local, backend)
}

#[tokio::test]
async fn interrupted_origin_preserves_docker_http() {
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

    // Protocol control only: no daemon, project state or container effects.
    // The forwarding hop still uses its actual TLS, curl and bearer path.
    let root = tempfile::tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inputs = Inputs {
        endpoint: format!("http://{}", upstream.local_addr().unwrap()),
        ca: root.path().join("unused-for-http.pem"),
        credential: "synthetic-protocol-control".into(),
        image: String::new(),
    };
    let cases = [
        ("HEAD", "/_ping", 200, ""),
        ("GET", "/_ping", 200, "OK"),
        ("GET", "/v1.45/version", 200, "{\"Version\":\"29.1.3\"}"),
        (
            "GET",
            "/v1.45/containers/missing/json",
            404,
            "{\"message\":\"missing\"}",
        ),
        ("DELETE", "/v1.45/containers/owned", 204, ""),
    ];
    let control = tokio::spawn(async move {
        for (method, path, status, body) in cases {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
                assert!(head.len() < 64 * 1024);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
            assert!(head.lines().any(|line| {
                line.eq_ignore_ascii_case("Authorization: Bearer synthetic-protocol-control")
            }));
            let mut response = format!(
                "HTTP/1.1 {status} Control\r\nAPI-Version: 1.52\r\nOstype: linux\r\nConnection: close\r\n"
            );
            if method == "HEAD" {
                // Docker advertises the length of GET /_ping, with no HEAD body.
                response.push_str("Content-Length: 2\r\n\r\n");
            } else if status == 204 {
                response.push_str("\r\n");
            } else if path.ends_with("/version") {
                response.push_str(&format!("Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n", body.len()));
            } else {
                response.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
            }
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let creations = Arc::new(AtomicUsize::new(0));
    let (local, backend) = interrupted_creation_origin(
        root.path(),
        &inputs,
        "/v1.45/containers/create?name=unused".into(),
        creations.clone(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    )
    .await;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(&local.ca).unwrap())
        .unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ));
    let address = local.endpoint.strip_prefix("https://").unwrap();
    for (method, path, status, body) in cases {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut stream = tls
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
            .unwrap();
        stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", inputs.credential).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        let (head, received) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with(&format!("HTTP/1.1 {status} ")));
        assert_eq!(received, body);
        assert!(head.lines().any(|line| line == "API-Version: 1.52"));
        assert!(head.lines().any(|line| line == "Ostype: linux"));
        assert!(!head.to_ascii_lowercase().contains("transfer-encoding:"));
        if method == "HEAD" {
            assert!(head.contains("Content-Length: 2"));
        } else if status == 204 {
            assert!(!head.to_ascii_lowercase().contains("content-length:"));
        } else {
            assert!(head.contains(&format!("Content-Length: {}", body.len())));
        }
    }
    timeout(Duration::from_secs(10), control)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(creations.load(Ordering::SeqCst), 0);
    backend.abort();
    assert!(backend.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[ignore = "requires operator-owned disposable Engine, HTTPS CA/bearer files, Docker and Compose; see contrib/docker/proof.md"]
async fn real_docker_compose_enforcement_and_persistent_effects() {
    let inputs = Inputs::read();
    let parent = PathBuf::from(
        std::env::var_os("SAFEYOLO_DOCKER_PROOF_ROOT")
            .expect("disk-backed owned scratch parent required"),
    );
    let root = tempfile::Builder::new()
        .prefix("docker-proof-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    let client = root.as_path().join("client-instance");
    let prefix = format!(
        "syproof{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    println!(
        "Docker/Compose real-boundary proof: owned resource prefix {prefix}; private scratch {}",
        root.display()
    );
    let mut proxy = start(&client, &inputs).await;
    println!("{}", run(&client, &["version"]).await);
    println!("{}", run(&client, &["compose", "version"]).await);
    run(&client, &["pull", &inputs.image]).await;
    let build = root.as_path().join("context");
    std::fs::create_dir(&build).unwrap();
    std::fs::write(
        build.join("Dockerfile"),
        format!("FROM {}\nCOPY seed /seed\n", inputs.image),
    )
    .unwrap();
    std::fs::write(build.join("seed"), "built-through-gateway\n").unwrap();
    let image = format!("{prefix}:proof");
    run(&client, &["build", "-t", &image, build.to_str().unwrap()]).await;
    let compose = root.as_path().join("compose.yaml");
    std::fs::write(&compose,format!("services:\n  web:\n    image: {image}\n    command: [sh, -c, 'mkdir -p /www; cp /seed /www/index.html; httpd -f -p 8080 -h /www']\n    healthcheck:\n      test: [CMD, wget, -qO-, 'http://127.0.0.1:8080']\n      interval: 1s\n      retries: 30\n  worker:\n    image: {image}\n    command: [sh, -c, 'echo worker-ready; sleep 3600']\n    volumes: [data:/data]\nvolumes:\n  data: {{}}\n")).unwrap();
    let cf = compose.to_str().unwrap();
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "45",
        ],
    )
    .await;
    let worker = run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "ps", "-q", "worker"],
    )
    .await
    .trim()
    .to_owned();
    let web = run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "ps", "-q", "web"],
    )
    .await
    .trim()
    .to_owned();
    let exec_output = run_output(
        &client,
        &[
            "exec",
            &worker,
            "sh",
            "-c",
            "wget -qO- http://web:8080; echo retained > /data/value",
        ],
    )
    .await;
    assert!(
        String::from_utf8_lossy(&exec_output.stdout).contains("built-through-gateway"),
        "exec stdout marker missing; stdout={:?}; stderr={:?}",
        String::from_utf8_lossy(&exec_output.stdout),
        String::from_utf8_lossy(&exec_output.stderr),
    );
    run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "logs", "--no-color"],
    )
    .await;
    run(&client, &["top", &worker]).await;
    let copied = root.as_path().join("copied");
    std::fs::write(&copied, "copy-round-trip").unwrap();
    run(
        &client,
        &["cp", copied.to_str().unwrap(), &format!("{worker}:/copied")],
    )
    .await;
    let returned = root.as_path().join("returned");
    run(
        &client,
        &[
            "cp",
            &format!("{worker}:/copied"),
            returned.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(std::fs::read(returned).unwrap(), b"copy-round-trip");
    let mut child = docker(&client, &["exec", "-i", &worker, "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"interactive-half-close\n")
        .await
        .unwrap();
    let output = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "interactive exec failed");
    assert_eq!(output.stdout, b"interactive-half-close\n");
    let attached = format!("{prefix}-attach");
    run(
        &client,
        &[
            "create",
            "-i",
            "--name",
            &attached,
            &inputs.image,
            "sh",
            "-c",
            "read line; echo received:$line",
        ],
    )
    .await;
    run(&client, &["start", &attached]).await;
    let mut child = docker(&client, &["attach", "--sig-proxy=false", &attached])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"attach-half-close\n")
        .await
        .unwrap();
    let output = timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "interactive attach failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("received:attach-half-close"));
    assert!(
        run(&client, &["logs", "--follow", &attached])
            .await
            .contains("received:attach-half-close")
    );
    run(&client, &["rm", &attached]).await;
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "up",
            "-d",
            "--force-recreate",
            "--wait",
            "--wait-timeout",
            "45",
        ],
    )
    .await;
    let worker = run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "ps", "-q", "worker"],
    )
    .await
    .trim()
    .to_owned();
    assert!(
        run(&client, &["exec", &worker, "cat", "/data/value"])
            .await
            .contains("retained")
    );

    for (index,host) in [json!({"Privileged":true}),json!({"NetworkMode":"host"}),json!({"PidMode":"host"}),json!({"IpcMode":"host"}),json!({"Devices":[{"PathOnHost":"/dev/null","PathInContainer":"/dev/null","CgroupPermissions":"rwm"}]}),json!({"CapAdd":["SYS_ADMIN"]}),json!({"SecurityOpt":["seccomp=unconfined"]}),json!({"Binds":["/var/run/docker.sock:/socket"]}),json!({"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}),json!({"Mounts":[{"Type":"volume","Target":"/host","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]})].into_iter().enumerate() {
        let name=format!("{prefix}-forbidden-{index}");
        let (status,response)=api(&client,"POST",&format!("/v1.45/containers/create?name={name}"),&json!({"Image":inputs.image,"HostConfig":host})).await;
        assert_eq!(status,403,"{response}");assert!(response.contains("GATEWAY_DOCKER_CONSTRAINT"));
        assert_eq!(operator(&inputs,root.as_path(),"GET",&format!("/v1.45/containers/{name}/json"),&Value::Null).await.0,404,"forbidden container reached the daemon");
    }
    let unsafe_name = format!("{prefix}-unsafe-existing");
    let (status, unsafe_container) = operator(
        &inputs,
        root.as_path(),
        "POST",
        &format!("/v1.45/containers/create?name={unsafe_name}"),
        &json!({"Image":inputs.image,"Cmd":["sleep","3600"],"HostConfig":{"Privileged":true}}),
    )
    .await;
    assert_eq!(status, 201);
    for path in [
        format!("/v1.45/containers/{unsafe_name}/start"),
        format!("/v1.45/containers/{unsafe_name}/exec"),
        format!("/v1.45/containers/{unsafe_name}/rename?name={unsafe_name}-renamed"),
    ] {
        let (status, response) = api(
            &client,
            "POST",
            &path,
            &if path.ends_with("exec") {
                json!({"Cmd":["id"]})
            } else {
                Value::Null
            },
        )
        .await;
        assert_eq!(status, 403, "{response}");
        assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    }
    let (_, state) = operator(
        &inputs,
        root.as_path(),
        "GET",
        &format!("/v1.45/containers/{unsafe_name}/json"),
        &Value::Null,
    )
    .await;
    assert_eq!(
        state["State"]["Running"], false,
        "unsafe existing workload was started"
    );
    assert_eq!(
        state["Name"],
        format!("/{unsafe_name}"),
        "unsafe existing workload was renamed"
    );
    let unsafe_id = unsafe_container["Id"].as_str().unwrap();
    for host in [
        json!({"VolumesFrom":[format!("{unsafe_name}:ro")]}),
        json!({"NetworkMode":format!("container:{unsafe_name}")}),
    ] {
        let (status, response) = api(
            &client,
            "POST",
            "/v1.45/containers/create",
            &json!({"Image":inputs.image,"HostConfig":host}),
        )
        .await;
        assert_eq!(status, 403, "{response}");
        assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    }
    let volume = format!("{prefix}-unsafe-volume");
    assert_eq!(operator(&inputs,root.as_path(),"POST","/v1.45/volumes/create",&json!({"Name":volume,"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}})).await.0,201);
    let (status,response)=api(&client,"POST","/v1.45/containers/create",&json!({"Image":inputs.image,"HostConfig":{"Mounts":[{"Type":"volume","Source":volume,"Target":"/host"}]}})).await;
    assert_eq!(status, 403, "{response}");
    assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    assert_eq!(
        operator(
            &inputs,
            root.as_path(),
            "DELETE",
            &format!("/v1.45/volumes/{volume}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    let (status, privileged_exec) = operator(
        &inputs,
        root.as_path(),
        "POST",
        &format!("/v1.45/containers/{worker}/exec"),
        &json!({"Cmd":["touch","/data/privileged-exec"],"Privileged":true}),
    )
    .await;
    assert_eq!(status, 201);
    let exec_id = privileged_exec["Id"].as_str().unwrap();
    let (status, response) = api(
        &client,
        "POST",
        &format!("/v1.45/exec/{exec_id}/start"),
        &json!({"Detach":true,"Tty":false}),
    )
    .await;
    assert_eq!(status, 403, "{response}");
    assert!(response.contains("GATEWAY_DOCKER_RESOURCE_CONSTRAINT"));
    let (_, exec) = operator(
        &inputs,
        root.as_path(),
        "GET",
        &format!("/v1.45/exec/{exec_id}/json"),
        &Value::Null,
    )
    .await;
    assert_eq!(exec["Running"], false);
    assert_eq!(
        api(
            &client,
            "POST",
            "/v1.45/build?version=2&entitlements=security.insecure",
            &Value::Null
        )
        .await
        .0,
        403
    );
    assert_eq!(
        operator(
            &inputs,
            root.as_path(),
            "DELETE",
            &format!("/v1.45/containers/{unsafe_id}"),
            &Value::Null
        )
        .await
        .0,
        204
    );

    let temporary_root = root.join("temporary-instance");
    let rename_path = format!("/v1.45/containers/{worker}/rename");
    let now = time::OffsetDateTime::now_utc();
    let expires = now + time::Duration::seconds(15);
    let grant = Grant {
        grant_id: "real-docker-rename".into(),
        agent: "witness".into(),
        service: "docker-proof".into(),
        method: "POST".into(),
        path: rename_path.clone(),
        literal_path: true,
        scope: GrantScope::Remembered,
        created: now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        expires: expires
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        delegated: None,
    };
    let temporary = start_with_access(&temporary_root, &inputs, None, Some(&grant)).await;
    let granted_name = format!("{prefix}-granted-worker");
    let (status, response) = api(
        &temporary_root,
        "POST",
        &format!("{rename_path}?name={granted_name}"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 204, "active native grant: {response}");
    // Observe the same live authority expire, without changing the bearer or
    // static service authorization, then attempt a directly visible mutation.
    let remaining = expires - time::OffsetDateTime::now_utc();
    if remaining.is_positive() {
        tokio::time::sleep(remaining.unsigned_abs()).await;
    }
    let (status, response) = api(
        &temporary_root,
        "POST",
        &format!("{rename_path}?name={prefix}-after-expiry"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 428, "expired native grant: {response}");
    assert!(response.contains("GATEWAY_RISKY_ROUTE"));
    let (status, container) = operator(
        &inputs,
        &root,
        "GET",
        &format!("/v1.45/containers/{worker}/json"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(container["Name"], format!("/{granted_name}"));
    temporary.shutdown().await;
    assert!(
        run(&client, &["exec", &worker, "cat", "/data/value"])
            .await
            .contains("retained")
    );
    println!(
        "Active native rename grant, expiry refusal, unchanged name and retained volume value passed."
    );
    let path = client.join("policy.toml");
    let mut policy: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    policy["agents"]["witness"]["services"]
        .as_table_mut()
        .unwrap()
        .remove("docker-proof");
    std::fs::write(&path, toml::to_string(&policy).unwrap()).unwrap();
    assert!(proxy.reload_policy_if_changed().await.unwrap());
    let (status, response) = api(
        &client,
        "POST",
        &format!("{rename_path}?name={prefix}-after-revocation"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 403, "revoked service authorization: {response}");
    let observer_root = root.as_path().join("observer-instance");
    let observer = start(&observer_root, &inputs).await;
    let container: Value =
        serde_json::from_str(&run(&observer_root, &["inspect", &worker]).await).unwrap();
    assert_eq!(container[0]["Name"], format!("/{granted_name}"));
    assert!(
        run(&observer_root, &["exec", &worker, "cat", "/data/value"])
            .await
            .contains("retained")
    );
    run(
        &observer_root,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "down",
            "--volumes",
            "--remove-orphans",
        ],
    )
    .await;
    run(&observer_root, &["image", "rm", &image]).await;
    assert_eq!(
        operator(
            &inputs,
            root.as_path(),
            "GET",
            &format!("/v1.45/containers/{web}/json"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    observer.shutdown().await;
    proxy.shutdown().await;
    std::fs::remove_dir_all(&root).unwrap();
    println!(
        "Allowed lifecycle, pre-effect refusals, expiry/revocation and retained persistent data passed for {prefix}."
    );
}

/// Reuses the protected daemon, clients and TLS inputs from the transport and
/// workload witness. Run only this test for the project candidate.
#[tokio::test]
#[ignore = "requires the existing operator-owned Docker/Compose acceptance venue"]
async fn real_docker_project_lifecycle_and_identity() {
    let inputs = Inputs::read();
    let parent = PathBuf::from(
        std::env::var_os("SAFEYOLO_DOCKER_PROOF_ROOT")
            .expect("disk-backed owned scratch parent required"),
    );
    let root = tempfile::Builder::new()
        .prefix("docker-project-proof-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    let client = root.join("project-client");
    let prefix = format!(
        "syproject{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    println!(
        "Project proof owned prefix {prefix}; private scratch {}",
        root.display()
    );
    let (_, image) = operator(
        &inputs,
        &root,
        "GET",
        &format!("/v1.45/images/{}/json", inputs.image),
        &Value::Null,
    )
    .await;
    let image_id = image["Id"]
        .as_str()
        .expect("reuse the already prepared qualified Linux image")
        .to_owned();
    let volume_name = format!("{prefix}-ordinary-data");
    let (status, volume) = operator(
        &inputs,
        &root,
        "POST",
        "/v1.45/volumes/create",
        &json!({"Name":volume_name}),
    )
    .await;
    assert_eq!(status, 201);
    let mut networks = Vec::new();
    for suffix in ["ordinary-net", "shared-net", "beta-net"] {
        let (status, value) = operator(
            &inputs,
            &root,
            "POST",
            "/v1.45/networks/create",
            &json!({"Name":format!("{prefix}-{suffix}"),"Driver":"bridge"}),
        )
        .await;
        assert_eq!(status, 201);
        networks.push(value["Id"].as_str().unwrap().to_owned());
    }
    let ordinary = format!("{prefix}-ordinary");
    let beta = format!("{prefix}-unrelated");
    let mut containers = Vec::new();
    for (name, network) in [(&ordinary, &networks[0]), (&beta, &networks[2])] {
        let mut config = json!({"Image":image_id,"Cmd":["sh","-c","while :; do sleep 1; done"],"HostConfig":{"CgroupnsMode":"private","NetworkMode":network}});
        if name == &ordinary {
            config["HostConfig"]["Binds"] = json!([format!("{volume_name}:/data")]);
        }
        let (status, value) = operator(
            &inputs,
            &root,
            "POST",
            &format!("/v1.45/containers/create?name={name}"),
            &config,
        )
        .await;
        assert_eq!(status, 201);
        containers.push(value["Id"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        operator(
            &inputs,
            &root,
            "POST",
            &format!("/v1.45/networks/{}/connect", networks[1]),
            &json!({"Container":containers[1]})
        )
        .await
        .0,
        200
    );
    let access = json!({"mode":"project","name":prefix,"adoption":"operator-selection-1","selected":{"containers":[containers[0]],"networks":[networks[0]],"volumes":{volume_name.clone():volume["CreatedAt"]}},"shared":{"images":[image_id],"networks":[networks[1]]}});
    let mut proxy = start_with_access(&client, &inputs, Some(access.clone()), None).await;
    println!("{}", run(&client, &["version"]).await);
    println!("{}", run(&client, &["compose", "version"]).await);
    run(&client, &["start", &ordinary]).await;
    run(
        &client,
        &[
            "exec",
            &ordinary,
            "sh",
            "-c",
            "echo project-data >/data/proof",
        ],
    )
    .await;
    for path in [
        "/v1.45/containers/json?all=true",
        "/v1.45/networks",
        "/v1.45/volumes",
        "/v1.45/images/json",
        "/v1.45/info",
    ] {
        let (status, body) = api(&client, "GET", path, &Value::Null).await;
        assert_eq!(status, 200, "{path}");
        assert!(
            !body.contains(&beta) && !body.contains(&containers[1]) && !body.contains(&networks[2]),
            "foreign metadata at {path}"
        );
    }
    let (_, body) = api(
        &client,
        "GET",
        &format!("/v1.45/networks/{}", networks[1]),
        &Value::Null,
    )
    .await;
    assert!(!body.contains(&beta) && !body.contains(&containers[1]));
    for id in [&containers[1], &beta, &"f".repeat(64)] {
        assert_eq!(
            api(
                &client,
                "GET",
                &format!("/v1.45/containers/{id}/json"),
                &Value::Null
            )
            .await
            .0,
            404
        );
        assert_eq!(
            api(
                &client,
                "POST",
                &format!("/v1.45/containers/{id}/start"),
                &Value::Null
            )
            .await
            .0,
            404
        );
    }
    let until = time::OffsetDateTime::now_utc().unix_timestamp() + 1;
    let (status, body) = api(
        &client,
        "GET",
        &format!("/v1.45/events?since=0&until={until}"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        !body.contains(&beta) && !body.contains(&containers[1]) && !body.contains(&networks[2])
    );
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/containers/{}/stats?stream=false", containers[1]),
            &Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            &client,
            "POST",
            &format!("/v1.45/networks/{}/connect", networks[1]),
            &json!({"Container":containers[1]})
        )
        .await
        .0,
        404
    );
    for host in [
        json!({"NetworkMode":format!("container:{}",containers[1])}),
        json!({"VolumesFrom":[containers[1]]}),
        json!({"NetworkMode":networks[2]}),
    ] {
        let (status, _) = api(
            &client,
            "POST",
            "/v1.45/containers/create",
            &json!({"Image":image_id,"HostConfig":host}),
        )
        .await;
        assert_eq!(status, 404, "indirect project escape");
    }
    assert_eq!(
        api(
            &client,
            "DELETE",
            &format!("/v1.45/networks/{}", networks[1]),
            &Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            &client,
            "DELETE",
            &format!("/v1.45/images/{image_id}"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    let compose = root.join("project-compose.yaml");
    std::fs::write(&compose,format!("services:\n  app:\n    image: {image_id}\n    command: ['sh', '-c', 'echo project-started; while :; do sleep 1; done']\n    volumes: ['state:/data']\nvolumes:\n  state: {{}}\n")).unwrap();
    let cf = compose.to_str().unwrap();
    run(&client, &["compose", "-p", &prefix, "-f", cf, "up", "-d"]).await;
    assert!(
        run(&client, &["compose", "-p", &prefix, "-f", cf, "logs"])
            .await
            .contains("project-started")
    );
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "exec",
            "-T",
            "app",
            "sh",
            "-c",
            "echo persistent >/data/value",
        ],
    )
    .await;
    run(
        &client,
        &[
            "compose",
            "-p",
            &prefix,
            "-f",
            cf,
            "up",
            "-d",
            "--force-recreate",
        ],
    )
    .await;
    assert!(
        run(
            &client,
            &[
                "compose",
                "-p",
                &prefix,
                "-f",
                cf,
                "exec",
                "-T",
                "app",
                "cat",
                "/data/value"
            ]
        )
        .await
        .contains("persistent")
    );
    let renamed = format!("{prefix}-renamed");
    assert_eq!(
        operator(
            &inputs,
            &root,
            "POST",
            &format!("/v1.45/containers/{}/rename?name={renamed}", containers[0]),
            &Value::Null
        )
        .await
        .0,
        204
    );
    let (status,replacement)=operator(&inputs,&root,"POST",&format!("/v1.45/containers/create?name={ordinary}"),&json!({"Image":image_id,"Labels":{"com.docker.compose.project":prefix},"HostConfig":{"CgroupnsMode":"private","NetworkMode":networks[2]}})).await;
    assert_eq!(status, 201);
    containers.push(replacement["Id"].as_str().unwrap().into());
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/containers/{ordinary}/json"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/containers/{renamed}/json"),
            &Value::Null
        )
        .await
        .0,
        200
    );
    run(&client, &["update", "--cpus", "0.5", &renamed]).await;
    proxy.shutdown().await;
    proxy = start_with_access(&client, &inputs, Some(access.clone()), None).await;
    assert!(
        run(&client, &["exec", &renamed, "cat", "/data/proof"])
            .await
            .contains("project-data")
    );
    run(&client, &["compose", "-p", &prefix, "-f", cf, "stop"]).await;
    run(&client, &["compose", "-p", &prefix, "-f", cf, "start"]).await;
    run(
        &client,
        &["compose", "-p", &prefix, "-f", cf, "down", "--volumes"],
    )
    .await;
    // Removing the selected container permits the second administrator to
    // replace its ordinary volume name, even with the same client labels.
    run(&client, &["rm", "-f", &renamed]).await;
    assert_eq!(
        operator(
            &inputs,
            &root,
            "DELETE",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    let (status, new_volume) = operator(
        &inputs,
        &root,
        "POST",
        "/v1.45/volumes/create",
        &json!({"Name":volume_name,"Labels":{"com.docker.compose.project":prefix}}),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        404
    );
    proxy.shutdown().await;
    let mut readopt = access;
    readopt["adoption"] = json!("explicit-operator-readoption-2");
    readopt["selected"]["volumes"][&volume_name] = new_volume["CreatedAt"].clone();
    proxy = start_with_access(&client, &inputs, Some(readopt), None).await;
    assert_eq!(
        api(
            &client,
            "GET",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        200
    );
    // Cleanup uses only this run's exact returned IDs and the verified volume.
    proxy.shutdown().await;
    for id in &containers[1..] {
        assert_eq!(
            operator(
                &inputs,
                &root,
                "DELETE",
                &format!("/v1.45/containers/{id}?force=true"),
                &Value::Null
            )
            .await
            .0,
            204
        );
    }
    for id in &networks {
        assert_eq!(
            operator(
                &inputs,
                &root,
                "DELETE",
                &format!("/v1.45/networks/{id}"),
                &Value::Null
            )
            .await
            .0,
            204
        );
    }
    assert_eq!(
        operator(
            &inputs,
            &root,
            "DELETE",
            &format!("/v1.45/volumes/{volume_name}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    std::fs::remove_dir_all(&root).unwrap();
    println!(
        "Project lifecycle, visibility, indirect references, co-administrator changes, restart and readoption passed for {prefix}. Run real_docker_project_interrupted_creation separately for the real Engine interruption case."
    );
}

#[tokio::test]
#[ignore = "requires the existing operator-owned Docker/Compose acceptance venue"]
async fn real_docker_project_interrupted_creation() {
    let inputs = Inputs::read();
    let parent = PathBuf::from(
        std::env::var_os("SAFEYOLO_DOCKER_PROOF_ROOT")
            .expect("disk-backed owned scratch parent required"),
    );
    let root = tempfile::Builder::new()
        .prefix("docker-project-interrupted-")
        .tempdir_in(parent)
        .unwrap()
        .keep();
    let client = root.join("project-client");
    let prefix = format!(
        "syinterrupted{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    println!(
        "Interrupted project creation owned prefix {prefix}; private scratch {}",
        root.display()
    );
    let (status, image) = operator(
        &inputs,
        &root,
        "GET",
        &format!("/v1.45/images/{}/json", inputs.image),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200, "reuse the already qualified image");
    let image_id = image["Id"].as_str().unwrap();
    let (status, network) = operator(
        &inputs,
        &root,
        "GET",
        "/v1.45/networks/bridge",
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    let network_id = network["Id"].as_str().unwrap();

    let name = format!("{prefix}-created");
    let create_path = format!("/v1.45/containers/create?name={name}");
    let creations = Arc::new(AtomicUsize::new(0));
    let (local, backend) = interrupted_creation_origin(
        &root,
        &inputs,
        create_path.clone(),
        creations.clone(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    )
    .await;
    // Exercise the actual ordinary client through this forwarding path before
    // the first fixture creation. A prerequisite failure leaves no new resources.
    let protocol_client = root.join("protocol-client");
    let preflight = start(&protocol_client, &local).await;
    println!("{}", run(&protocol_client, &["version"]).await);
    println!("{}", run(&protocol_client, &["compose", "version"]).await);
    assert_eq!(creations.load(Ordering::SeqCst), 0);
    preflight.shutdown().await;

    // The operator selects an existing container but grants only use of its
    // anonymous volume. Removing that container must not destroy the dependency.
    let shared_name = format!("{prefix}-shared");
    let config = json!({"Image":image_id,"Volumes":{"/data":{}},"HostConfig":{"CgroupnsMode":"private","NetworkMode":network_id}});
    let (status, shared) = operator(
        &inputs,
        &root,
        "POST",
        &format!("/v1.45/containers/create?name={shared_name}"),
        &config,
    )
    .await;
    std::fs::write(root.join("shared-engine-reply.json"), shared.to_string()).unwrap();
    println!("Shared fixture creation: status {status}, {shared}");
    assert_eq!(status, 201);
    let shared_id = shared["Id"].as_str().unwrap();
    let (status, shared_container) = operator(
        &inputs,
        &root,
        "GET",
        &format!("/v1.45/containers/{shared_id}/json"),
        &Value::Null,
    )
    .await;
    std::fs::write(
        root.join("shared-container.json"),
        shared_container.to_string(),
    )
    .unwrap();
    assert_eq!(status, 200);
    let shared_volume = shared_container["Mounts"][0]["Name"].as_str().unwrap();
    let (status, volume) = operator(
        &inputs,
        &root,
        "GET",
        &format!("/v1.45/volumes/{shared_volume}"),
        &Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    let access = json!({"mode":"project","name":prefix,"adoption":"operator-selection-1","selected":{"containers":[shared_id]},"shared":{"images":[image_id],"networks":[network_id],"volumes":{shared_volume:volume["CreatedAt"]}}});
    let proxy = start_with_access(&client, &local, Some(access), None).await;
    let (create_status, response) = api(&client, "POST", &create_path, &config).await;
    std::fs::write(root.join("interrupted-client-response.txt"), &response).unwrap();

    // Observe and retain the real effect before a dependent request or cleanup.
    // Do not replay the creation, including if an assertion below fails.
    let inspect_path = format!("/v1.45/containers/{name}/json");
    let (status, created) = operator(&inputs, &root, "GET", &inspect_path, &Value::Null).await;
    std::fs::write(root.join("created-container.json"), created.to_string()).unwrap();
    println!(
        "Interrupted client status {create_status}; actual Engine inspect status {status}; container {}; mounts {}",
        created["Id"], created["Mounts"]
    );
    assert_eq!(status, 200);
    let id = created["Id"].as_str().unwrap();
    let owned_volume = created["Mounts"][0]["Name"].as_str().unwrap();
    let engine_reply: Value =
        serde_json::from_slice(&std::fs::read(root.join("interrupted-engine-reply.json")).unwrap())
            .unwrap();
    assert_eq!(engine_reply["Id"], id);
    let state_path = std::fs::read_dir(client.join("data/docker-projects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    std::fs::write(
        root.join("state-before-reconciliation.json"),
        before.to_string(),
    )
    .unwrap();
    assert_eq!(
        create_status, 503,
        "interruption must report uncertainty: {response}"
    );
    assert_eq!(before["pending"]["kind"], "container");
    assert!(
        before["pending"]["marker"]
            .as_str()
            .is_some_and(|marker| !marker.is_empty())
    );
    assert_eq!(
        before["pending"]["marker"],
        created["Config"]["Labels"]["io.safeyolo.creation"]
    );
    assert!(
        !before["containers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == id)
    );
    let (status, body) = api(&client, "GET", &inspect_path, &Value::Null).await;
    assert_eq!(
        status, 200,
        "dependent inspect after reconciliation: {body}"
    );
    assert!(body.contains(id) && !body.contains("io.safeyolo.creation"));
    let after: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    std::fs::write(
        root.join("state-after-reconciliation.json"),
        after.to_string(),
    )
    .unwrap();
    assert!(after["pending"].is_null());
    assert!(
        after["containers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == id)
    );
    assert!(after["volumes"].get(owned_volume).is_some());
    let audit: Vec<Value> = std::fs::read_to_string(client.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_interrupted_audit(&audit, &create_path);
    assert_eq!(creations.load(Ordering::SeqCst), 1, "creation was replayed");
    println!(
        "Real Engine creation {id} and anonymous volume {owned_volume} reconciled after response loss; exactly one creation request."
    );

    project_volume_removal(&inputs, &root, &shared_container, &created, &volume, &after).await;
    assert_eq!(creations.load(Ordering::SeqCst), 1, "creation was replayed");
    proxy.shutdown().await;
    backend.abort();
    assert!(backend.await.unwrap_err().is_cancelled());
    // Only the operator removes the retained shared dependency, after readback.
    assert_eq!(
        operator(
            &inputs,
            &root,
            "DELETE",
            &format!("/v1.45/volumes/{shared_volume}"),
            &Value::Null
        )
        .await
        .0,
        204
    );
    std::fs::remove_dir_all(&root).unwrap();
    println!(
        "Real Engine interrupted creation, reconciliation, no replay and shared/owned anonymous-volume deletion passed for {prefix}."
    );
}

fn assert_interrupted_audit(audit: &[Value], create_path: &str) {
    let interrupted = audit
        .iter()
        .position(|e| {
            e["event"] == "gateway.docker_request"
                && e["details"]["method"] == "POST"
                && e["details"]["path"] == "/v1.45/containers/create"
                && e["details"]["mutation_outcome"] == "unknown"
                && e["details"]["replayed"] == false
        })
        .expect("reported interrupted mutation");
    let reconciled = audit
        .iter()
        .position(|e| {
            e["event"] == "gateway.docker_reconciled"
                && e["details"]["prior_path"] == create_path
                && e["details"]["replayed"] == false
        })
        .expect("dependent read reconciled the creation");
    assert!(interrupted < reconciled);
}

#[test]
fn interrupted_audit_keeps_request_and_reconciliation_paths_distinct() {
    let path = "/v1.45/containers/create?name=ordinary-name";
    let events = vec![
        json!({"event":"gateway.docker_request","details":{"method":"POST","path":"/v1.45/containers/create","mutation_outcome":"unknown","replayed":false}}),
        json!({"event":"gateway.docker_reconciled","details":{"prior_path":path,"replayed":false}}),
    ];
    assert_interrupted_audit(&events, path);
    for (index, field, value) in [
        (0, "path", json!(path)),
        (0, "method", json!("GET")),
        (0, "mutation_outcome", json!("complete")),
        (0, "replayed", json!(true)),
        (1, "prior_path", json!("/v1.45/containers/create")),
        (1, "replayed", json!(true)),
    ] {
        let mut invalid = events.clone();
        invalid[index]["details"][field] = value;
        assert!(std::panic::catch_unwind(|| assert_interrupted_audit(&invalid, path)).is_err());
    }
}

#[tokio::test]
#[ignore = "requires the preserved real Engine interruption root and its existing private Engine inputs"]
async fn real_docker_project_volume_continuation() {
    let inputs = Inputs::read();
    let root = PathBuf::from(
        std::env::var_os("SAFEYOLO_DOCKER_CONTINUATION_ROOT")
            .expect("existing interrupted-creation root required; never rerun creation"),
    );
    let client = root.join("project-client");
    let shared: Value =
        serde_json::from_slice(&std::fs::read(root.join("shared-container.json")).unwrap())
            .unwrap();
    let created: Value =
        serde_json::from_slice(&std::fs::read(root.join("created-container.json")).unwrap())
            .unwrap();
    let definition: Value =
        serde_json::from_slice(&std::fs::read(client.join("services/docker.yaml")).unwrap())
            .unwrap();
    let access = &definition["capabilities"]["workloads"]["docker_access"];
    assert_eq!(access["mode"], "project");
    let prefix = access["name"].as_str().unwrap();
    assert_eq!(shared["Name"], format!("/{prefix}-shared"));
    assert_eq!(created["Name"], format!("/{prefix}-created"));
    assert!(
        access["selected"]["containers"]
            .as_array()
            .unwrap()
            .contains(&shared["Id"])
    );
    let shared_volume = shared["Mounts"][0]["Name"].as_str().unwrap();
    let volume = json!({"CreatedAt":access["shared"]["volumes"][shared_volume]});
    assert!(volume["CreatedAt"].is_string());
    let states: Vec<_> = std::fs::read_dir(client.join("data/docker-projects"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(states.len(), 1, "reuse the actual single project state");
    let state: Value = serde_json::from_slice(&std::fs::read(&states[0]).unwrap()).unwrap();
    assert_eq!(state["adoption"], access["adoption"]);
    let audit_before = std::fs::read_to_string(client.join("audit.jsonl")).unwrap();
    let events: Vec<Value> = audit_before
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_interrupted_audit(
        &events,
        &format!("/v1.45/containers/create?name={prefix}-created"),
    );

    // Project association is endpoint-bound. Keep the saved endpoint, policy,
    // identity and state; only renew the stopped test listener's TLS certificate.
    let endpoint = definition["docker"]["endpoint"].as_str().unwrap();
    let address: hyper::Uri = endpoint.parse().unwrap();
    assert_eq!(address.scheme_str(), Some("https"));
    assert_eq!(address.host(), Some("127.0.0.1"));
    let port = address.port_u16().unwrap();
    assert_ne!(port, 0);
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let creations = Arc::new(AtomicUsize::new(0));
    // An empty allowed creation path rejects every POST before Engine dispatch.
    let (local, backend) =
        interrupted_creation_origin(&root, &inputs, String::new(), creations.clone(), listener)
            .await;
    assert_eq!(local.endpoint, endpoint);
    let proxy = start_saved_proxy(&client, &local.ca).await;
    project_volume_removal(&inputs, &root, &shared, &created, &volume, &state).await;
    proxy.shutdown().await;
    backend.abort();
    assert!(backend.await.unwrap_err().is_cancelled());
    assert_eq!(creations.load(Ordering::SeqCst), 0);
    let audit_after = std::fs::read_to_string(client.join("audit.jsonl")).unwrap();
    assert!(audit_after.starts_with(&audit_before));
    for line in audit_after[audit_before.len()..].lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(
            !(event["event"] == "gateway.docker_request" && event["details"]["method"] == "POST")
        );
    }
    println!(
        "Remaining shared/owned volume checks passed without creation; retain {} and the shared volume {shared_volume} for verified operator cleanup. The original run's in-memory creation-counter assertion was not reached.",
        root.display()
    );
}

async fn project_volume_removal(
    inputs: &Inputs,
    root: &Path,
    shared: &Value,
    created: &Value,
    volume: &Value,
    state: &Value,
) {
    let client = root.join("project-client");
    let shared_id = shared["Id"].as_str().unwrap();
    let shared_volume = shared["Mounts"][0]["Name"].as_str().unwrap();
    let id = created["Id"].as_str().unwrap();
    let owned_volume = created["Mounts"][0]["Name"].as_str().unwrap();

    let shared_now = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/containers/{shared_id}/json"),
        &Value::Null,
    )
    .await;
    let created_now = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/containers/{id}/json"),
        &Value::Null,
    )
    .await;
    let shared_volume_now = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/volumes/{shared_volume}"),
        &Value::Null,
    )
    .await;
    let owned_volume_now = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/volumes/{owned_volume}"),
        &Value::Null,
    )
    .await;
    std::fs::write(
        root.join("volume-continuation-before.json"),
        json!({
            "shared_container":shared_now,"created_container":created_now,
            "shared_volume":shared_volume_now,"owned_volume":owned_volume_now,"project_state":state
        })
        .to_string(),
    )
    .unwrap();
    for (saved, current) in [(shared, &shared_now), (created, &created_now)] {
        assert_eq!(current.0, 200);
        assert_eq!(current.1["Id"], saved["Id"]);
        assert_eq!(current.1["Name"], saved["Name"]);
        assert_eq!(current.1["Created"], saved["Created"]);
        assert_eq!(current.1["Mounts"], saved["Mounts"]);
        assert_eq!(current.1["State"]["Running"], false);
    }
    assert_eq!(shared_volume_now.0, 200);
    assert_eq!(shared_volume_now.1["Name"], shared_volume);
    assert_eq!(shared_volume_now.1["CreatedAt"], volume["CreatedAt"]);
    assert_eq!(owned_volume_now.0, 200);
    assert_eq!(owned_volume_now.1["Name"], owned_volume);
    assert_eq!(
        owned_volume_now.1["CreatedAt"],
        state["volumes"][owned_volume]["created"]
    );
    assert_eq!(
        created_now.1["Config"]["Labels"]["io.safeyolo.creation"],
        state["volumes"][owned_volume]["marker"]
    );
    assert!(state["pending"].is_null());
    assert!(
        state["containers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == id)
    );
    assert!(state["volumes"].get(shared_volume).is_none());

    // Criteria 4/5: shared use cannot authorize anonymous-volume deletion.
    let (status, body) = api(
        &client,
        "DELETE",
        &format!("/v1.45/containers/{shared_id}?v=true"),
        &Value::Null,
    )
    .await;
    let shared_after = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/containers/{shared_id}/json"),
        &Value::Null,
    )
    .await;
    let volume_after = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/volumes/{shared_volume}"),
        &Value::Null,
    )
    .await;
    println!(
        "Shared anonymous-volume removal: gateway {status}; actual container {}, volume {}",
        shared_after.0, volume_after.0
    );
    std::fs::write(root.join("volume-shared-rm-v.json"), json!({"gateway_status":status,"gateway_response":body,"container":shared_after,"volume":volume_after}).to_string()).unwrap();
    assert_eq!(status, 404, "shared volume deletion: {body}");
    assert_eq!(shared_after.0, 200);
    assert_eq!(volume_after.0, 200);
    assert_eq!(shared_after.1["Id"], shared_id);
    assert_eq!(volume_after.1["CreatedAt"], volume["CreatedAt"]);
    let shared_delete = api(
        &client,
        "DELETE",
        &format!("/v1.45/volumes/{shared_volume}"),
        &Value::Null,
    )
    .await;
    let shared_after_delete = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/volumes/{shared_volume}"),
        &Value::Null,
    )
    .await;
    std::fs::write(root.join("volume-shared-delete.json"), json!({"gateway_status":shared_delete.0,"gateway_response":shared_delete.1,"volume":shared_after_delete}).to_string()).unwrap();
    assert_eq!(shared_delete.0, 404);
    assert_eq!(shared_after_delete.0, 200);
    assert_eq!(shared_after_delete.1["CreatedAt"], volume["CreatedAt"]);
    // Ordinary container removal remains permitted and preserves the shared volume.
    let shared_remove = api(
        &client,
        "DELETE",
        &format!("/v1.45/containers/{shared_id}"),
        &Value::Null,
    )
    .await;
    let shared_removed = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/containers/{shared_id}/json"),
        &Value::Null,
    )
    .await;
    let retained_volume = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/volumes/{shared_volume}"),
        &Value::Null,
    )
    .await;
    std::fs::write(root.join("volume-shared-container-removed.json"), json!({"gateway_status":shared_remove.0,"gateway_response":shared_remove.1,"container":shared_removed,"volume":retained_volume}).to_string()).unwrap();
    assert_eq!(shared_remove.0, 204);
    assert_eq!(shared_removed.0, 404);
    assert_eq!(retained_volume.0, 200);
    assert_eq!(retained_volume.1["CreatedAt"], volume["CreatedAt"]);
    // The interrupted creation's recorded volume is owned, so rm -v must work.
    let (status, body) = api(
        &client,
        "DELETE",
        &format!("/v1.45/containers/{id}?v=true"),
        &Value::Null,
    )
    .await;
    let container_after = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/containers/{id}/json"),
        &Value::Null,
    )
    .await;
    let owned_after = operator(
        inputs,
        root,
        "GET",
        &format!("/v1.45/volumes/{owned_volume}"),
        &Value::Null,
    )
    .await;
    println!(
        "Owned anonymous-volume removal: gateway {status}; actual container {}, volume {}",
        container_after.0, owned_after.0
    );
    std::fs::write(root.join("volume-owned-rm-v.json"), json!({"gateway_status":status,"gateway_response":body,"container":container_after,"volume":owned_after}).to_string()).unwrap();
    assert_eq!(status, 204, "owned volume deletion: {body}");
    assert_eq!(container_after.0, 404);
    assert_eq!(owned_after.0, 404);
}
