//! Imported operator credentials cross the real UDS, CONNECT and verified TLS.
use super::*;
use safeyolo_proxy::credentials;

const CLIENT: &str = safeyolo_proxy::credential_guard::codex::CLIENT_ID;
const ACCOUNT: &str = "/backend-api/wham/accounts/check?workspace_id=owned";
const NATIVE_GET_PATHS: [&str; 5] = [
    "/backend-api/plugins/featured",
    "/backend-api/ps/plugins/installed",
    "/backend-api/ps/plugins/suggested/codex",
    "/backend-api/ps/plugins/list",
    "/backend-api/wham/rate-limit-reset-credits",
];
const ACCESS: [&str; 3] = [
    "codex-owned-access-0",
    "codex-owned-access-1",
    "codex-owned-access-2",
];
const REFRESH: [&str; 3] = [
    "codex-owned-refresh-0: opaque+ /",
    "codex-owned-refresh-1: opaque+ /",
    "codex-owned-refresh-2: opaque+ /",
];
const POLICY: &str = "budget=12000\n[credential.companion]\nmatch=[\"companion-protected-1123\"]\nheaders=[\"x-api-key\"]\n[hosts]\n\"*\"={egress=\"allow\",unknown_creds=\"prompt\"}\n[agents.alice]\nagent_id=\"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n[agents.bob]\nagent_id=\"ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n";

struct Fixture {
    directory: TempDir,
    config: Config,
    ca: rustls::pki_types::CertificateDer<'static>,
    parent: tokio::task::JoinHandle<()>,
    response: Arc<Mutex<(u16, String)>>,
    seen: Arc<AtomicUsize>,
    release: Arc<Notify>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.parent.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let initialized = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .args(["--root", directory.path().to_str().unwrap(), "init"])
            .output()
            .unwrap();
        assert!(initialized.status.success(), "native initialization failed");
        let path = directory.path().join("policy.toml");
        std::fs::write(&path, POLICY).unwrap();
        let mut config = super::config(
            &directory,
            &path,
            &directory.path().join("agent.sock"),
            true,
        );
        config.native_product = true;
        config.native_config_dir = Some(directory.path().into());
        let tls = configure_h2_test_tls(&directory, &mut config, "auth.openai.com");
        let origin = rcgen::generate_simple_self_signed(vec![
            "auth.openai.com".into(),
            "chatgpt.com".into(),
            "other.test".into(),
        ])
        .unwrap();
        std::fs::write(config.upstream_ca_file.as_ref().unwrap(), origin.cert.pem()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![origin.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(origin.signing_key.serialize_der()).into(),
        )
        .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let (listener, address) = test_owned_endpoint::bind().await;
        config.parent_proxy = Some(format!("http://{address}"));
        let response = Arc::new(Mutex::new((200, "{}".to_owned())));
        let seen = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let parent = tokio::spawn({
            let response = response.clone();
            let seen = seen.clone();
            let release = release.clone();
            async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        peer=listener.accept() => {
                            let (mut peer,_) = peer.unwrap();
                            let acceptor=acceptor.clone(); let response=response.clone(); let seen=seen.clone(); let release=release.clone();
                            children.spawn(async move {
                                let mut head=Vec::new();
                                while !head.ends_with(b"\r\n\r\n") {head.push(peer.read_u8().await.unwrap());}
                                peer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                                let Ok(tls)=acceptor.accept(peer).await else { return };
                                let h2=tls.get_ref().1.alpn_protocol()==Some(b"h2".as_slice());
                                let service=service_fn(move |mut request: Request<Incoming>| {
                                    let response=response.clone(); let seen=seen.clone(); let release=release.clone();
                                    async move {
                                        if request.headers().get("upgrade").is_some_and(|value| value=="websocket") {
                                            let accept=tungstenite::handshake::derive_accept_key(request.headers()["sec-websocket-key"].as_bytes());
                                            let upgrade=hyper::upgrade::on(&mut request);
                                            seen.fetch_add(1,Ordering::SeqCst);
                                            tokio::spawn(async move {
                                                let mut stream=TokioIo::new(upgrade.await.unwrap());
                                                assert_eq!(stream.read_u8().await.unwrap(),0x81);
                                                assert_eq!(stream.read_u8().await.unwrap(),0x84);
                                                let mut key=[0u8;4];stream.read_exact(&mut key).await.unwrap();
                                                let mut data=[0u8;4];stream.read_exact(&mut data).await.unwrap();
                                                for (value,mask) in data.iter_mut().zip(key) { *value^=mask; }
                                                assert_eq!(&data,b"ping");
                                                stream.write_all(b"\x81\x04pong").await.unwrap();
                                            });
                                            return Ok::<_,Infallible>(hyper::Response::builder().status(101)
                                                .header("connection","Upgrade").header("upgrade","websocket")
                                                .header("sec-websocket-accept",accept).body(Full::new(Bytes::new()).map_err(|never| -> safeyolo_proxy::Error { match never {} }).boxed()).unwrap());
                                        }
                                        let token=request.uri().path()=="/oauth/token";
                                        let _body=request.into_body().collect().await.unwrap();
                                        let sequence=seen.fetch_add(1,Ordering::SeqCst);
                                        let (status,mut body)=if token {response.lock().unwrap().clone()} else {(200,"owned-account-response".into())};
                                        if token && body=="concurrent" {
                                            let index=1+sequence%2;
                                            body=json!({"access_token":ACCESS[index],"refresh_token":REFRESH[index]}).to_string();
                                        }
                                        if token && body=="paused" {
                                            release.notified().await;
                                            body=json!({"access_token":ACCESS[1],"refresh_token":REFRESH[1]}).to_string();
                                        }
                                        let mut reply=hyper::Response::builder().status(status).header("content-type","application/json");
                                        if status==307 {reply=reply.header("location","https://other.test/oauth/token");}
                                        let body = if token && body == "incomplete" {
                                            let bytes = json!({"access_token":ACCESS[1],"refresh_token":REFRESH[1]}).to_string();
                                            let frames = [Ok(hyper::body::Frame::data(Bytes::from(bytes))), Err(std::io::Error::other("owned incomplete issuance"))];
                                            http_body_util::StreamBody::new(futures_util::stream::iter(frames)).map_err(|error| -> safeyolo_proxy::Error { Box::new(error) }).boxed()
                                        } else {
                                            Full::new(Bytes::from(body)).map_err(|never| -> safeyolo_proxy::Error { match never {} }).boxed()
                                        };
                                        Ok::<_,Infallible>(reply.body(body).unwrap())
                                    }
                                });
                                if h2 { let _=hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls),service).await; }
                                else { let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls),service).with_upgrades().await; }
                            });
                        }
                        _=children.join_next(), if !children.is_empty() => {}
                    }
                }
            }
        });
        Self {
            directory,
            config,
            ca: tls.proxy_ca,
            parent,
            response,
            seen,
            release,
        }
    }
    fn import(&self) {
        self.import_scope("persistent");
    }
    fn import_scope(&self, scope: &str) {
        let result = self.import_document(&json!({"auth_mode":"chatgpt","tokens":{"access_token":ACCESS[0],"refresh_token":REFRESH[0],"id_token":"not-a-trust-root"}}).to_string(), scope);
        assert!(
            result.status.success(),
            "host import failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        for value in ACCESS.into_iter().chain(REFRESH) {
            assert!(!String::from_utf8_lossy(&result.stdout).contains(value));
        }
    }
    fn import_document(&self, document: &str, scope: &str) -> std::process::Output {
        let source = self.directory.path().join("selected-host-login.json");
        std::fs::write(&source, document).unwrap();
        std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .args([
                "--root",
                self.directory.path().to_str().unwrap(),
                "credentials",
                "import-codex",
                "owned-codex",
                "--storage",
                "local",
                "--agent",
                "alice",
                "--auth-file",
                source.to_str().unwrap(),
                "--scope",
                scope,
            ])
            .output()
            .unwrap()
    }
    async fn send(&self, agent: usize, request: Request<Full<Bytes>>, h2: bool) -> u16 {
        super::ghcr::fetch_request(
            &self.config.listeners[agent].socket_path,
            self.ca.clone(),
            request,
            h2,
        )
        .await
        .status()
        .as_u16()
    }

    async fn access(&self, token: &str, method: &str, path: &str, h2: bool) -> u16 {
        self.send(
            0,
            request(
                "chatgpt.com",
                method,
                path,
                &[("authorization", &format!("Bearer {token}"))],
                vec![],
            ),
            h2,
        )
        .await
    }
    async fn refresh(&self, token: &str, client: &str, h2: bool) -> u16 {
        self.send(
            0,
            request(
                "auth.openai.com",
                "POST",
                "/oauth/token",
                &[("content-type", "application/json")],
                json!({"grant_type":"refresh_token","client_id":client,"refresh_token":token})
                    .to_string()
                    .into_bytes(),
            ),
            h2,
        )
        .await
    }

    async fn websocket(&self, token: &str) -> u16 {
        tokio::time::timeout(Duration::from_secs(10),async {
            let mut stream=super::ghcr::connect_tls(&self.config.listeners[0].socket_path,self.ca.clone(),"chatgpt.com",false).await;
            stream.write_all(format!("GET /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer {token}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
            let head=super::response_head(&mut stream).await;
            let status=std::str::from_utf8(&head).unwrap().split_whitespace().nth(1).unwrap().parse::<u16>().unwrap();
            if status==101 {
                stream.write_all(b"\x81\x84\x01\x02\x03\x04qkmc").await.unwrap();
                let mut response=[0u8;6];stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response,b"\x81\x04pong");
            }
            status
        }).await.expect("Codex WebSocket deadline")
    }
}

fn request(
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Request<Full<Bytes>> {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"))
        .header("host", host);
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    request.body(Full::new(Bytes::from(body))).unwrap()
}

#[tokio::test]
async fn imported_login_two_rotations_reload_restart_and_redaction() {
    for h2 in [false, true] {
        let fixture = Fixture::new().await;
        fixture.import();
        let mut proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        assert_eq!(fixture.access(ACCESS[0], "GET", ACCOUNT, h2).await, 200);
        for path in NATIVE_GET_PATHS {
            assert_eq!(fixture.access(ACCESS[0], "GET", path, h2).await, 200);
        }
        for index in 1..=2 {
            *fixture.response.lock().unwrap() = (
                200,
                json!({"access_token":ACCESS[index],"refresh_token":REFRESH[index]}).to_string(),
            );
            assert_eq!(fixture.refresh(REFRESH[index - 1], CLIENT, h2).await, 200);
            for path in NATIVE_GET_PATHS {
                assert_eq!(
                    fixture
                        .access(ACCESS[index], "GET", &format!("{path}?limit=20"), h2)
                        .await,
                    200
                );
            }
            assert_eq!(
                fixture
                    .access(ACCESS[index], "POST", "/backend-api/codex/responses", h2)
                    .await,
                200
            );
            assert_eq!(
                fixture
                    .access(ACCESS[index], "GET", "/backend-api/codex/responses", h2)
                    .await,
                200
            );
            proxy.reload(fixture.config.clone()).await.unwrap();
            assert_eq!(fixture.access(ACCESS[index], "GET", ACCOUNT, h2).await, 200);
        }
        // An omitted refresh field retains the exact previously trusted value.
        assert_eq!(fixture.websocket(ACCESS[2]).await, 101);
        assert_eq!(fixture.websocket("unobserved-websocket-token").await, 428);
        *fixture.response.lock().unwrap() = (200, json!({"access_token":ACCESS[2]}).to_string());
        assert_eq!(fixture.refresh(REFRESH[2], CLIENT, h2).await, 200);
        *fixture.response.lock().unwrap() =
            (200, json!({"id_token":"opaque-id-replacement"}).to_string());
        assert_eq!(fixture.refresh(REFRESH[2], CLIENT, h2).await, 200);
        proxy.shutdown().await;
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        assert_eq!(fixture.access(ACCESS[2], "GET", ACCOUNT, h2).await, 200);
        let vault = credentials::open(fixture.config.data_dir.as_ref().unwrap()).unwrap();
        vault.remove("owned-codex").unwrap();
        assert_eq!(
            fixture
                .access(ACCESS[2], "POST", "/backend-api/codex/responses", h2)
                .await,
            428
        );
        proxy.shutdown().await;
        let audit =
            std::fs::read_to_string(fixture.config.audit_log_path.as_ref().unwrap()).unwrap();
        let refreshed: Vec<Value> = audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|row| row["event"] == "security.credential_guard.codex_refreshed")
            .collect();
        assert_eq!(refreshed.len(), 4);
        assert!(
            refreshed.iter().all(|row| row["agent"] == "alice"
                && row["host"] == "auth.openai.com"
                && row["decision"] == "allow"
                && row["request_id"].is_string()),
            "refresh audit lost its validated envelope"
        );
        assert!(
            audit
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .any(|row| row["event"] == "security.credential_guard"
                    && row["details"]["location"] == "body:refresh_token"
                    && row["details"]["codex_authorized"] == true)
        );
        assert!(
            audit
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .any(|row| row["event"] == "security.credential_guard.evaluated"
                    && row["details"]["body_scope"] == "codex_refresh_token")
        );
        for token in ACCESS
            .into_iter()
            .chain(REFRESH)
            .chain(["opaque-id-replacement"])
        {
            assert!(!audit.contains(token), "raw credential in audit");
            assert!(
                !std::fs::read(fixture.directory.path().join("data/credentials.enc"))
                    .unwrap()
                    .windows(token.len())
                    .any(|w| w == token.as_bytes())
            );
        }
    }
}

#[tokio::test]
async fn credentials_do_not_inherit_other_origins_routes_clients_or_beneficiaries() {
    let fixture = Fixture::new().await;
    fixture.import();
    let mut proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    for (method, path) in [
        ("DELETE", "/backend-api/codex/responses"),
        ("POST", ACCOUNT),
        ("GET", "/unrelated"),
        ("GET", "/backend-api/codex/responses/../unrelated"),
        ("POST", NATIVE_GET_PATHS[0]),
        ("POST", NATIVE_GET_PATHS[1]),
        ("POST", NATIVE_GET_PATHS[2]),
        ("POST", NATIVE_GET_PATHS[3]),
        ("POST", NATIVE_GET_PATHS[4]),
        ("GET", "/backend-api/plugins/featured/extra"),
        ("GET", "/backend-api/ps/plugins/suggested/other"),
    ] {
        assert_ne!(fixture.access(ACCESS[0], method, path, true).await, 200);
    }
    for path in NATIVE_GET_PATHS {
        assert_eq!(fixture.access(ACCESS[1], "GET", path, true).await, 428);
        for (agent, host) in [(1, "chatgpt.com"), (0, "other.test")] {
            assert_eq!(
                fixture
                    .send(
                        agent,
                        request(
                            host,
                            "GET",
                            path,
                            &[("authorization", &format!("Bearer {}", ACCESS[0]))],
                            vec![]
                        ),
                        true
                    )
                    .await,
                428
            );
        }
    }
    assert_eq!(
        fixture
            .access(
                "forged-arbitrary-opaque-token",
                "POST",
                "/backend-api/codex/responses",
                true
            )
            .await,
        428
    );
    assert_eq!(
        fixture
            .access(REFRESH[0], "POST", "/backend-api/codex/responses", true)
            .await,
        428
    );
    assert_eq!(
        fixture
            .send(
                1,
                request(
                    "chatgpt.com",
                    "POST",
                    "/backend-api/codex/responses",
                    &[("authorization", &format!("Bearer {}", ACCESS[0]))],
                    vec![]
                ),
                false
            )
            .await,
        428
    );
    assert_eq!(
        fixture
            .send(
                0,
                request(
                    "other.test",
                    "POST",
                    "/backend-api/codex/responses",
                    &[("authorization", &format!("Bearer {}", ACCESS[0]))],
                    vec![]
                ),
                false
            )
            .await,
        428
    );
    assert_eq!(
        fixture.refresh("unobserved-refresh", CLIENT, true).await,
        428
    );
    assert_eq!(fixture.refresh(REFRESH[0], "other-client", true).await, 428);
    let plaintext = format!(
        "POST http://chatgpt.com/backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ACCESS[0]
    );
    let reply = super::raw_round_trip(
        &fixture.config.listeners[0].socket_path,
        plaintext.as_bytes(),
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 428"));
    assert_eq!(
        fixture
            .send(
                0,
                request(
                    "chatgpt.com",
                    "POST",
                    "/backend-api/codex/responses",
                    &[
                        ("authorization", &format!("Bearer {}", ACCESS[0])),
                        ("x-api-key", "companion-protected-1123")
                    ],
                    vec![]
                ),
                false
            )
            .await,
        428
    );
    assert_eq!(
        fixture.seen.load(Ordering::SeqCst),
        0,
        "blocked request reached origin"
    );
    for (effect, status) in [("deny", 403), ("prompt", 428)] {
        let explicit = format!(
            "budget=12000\n[agents.alice]\nagent_id=\"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n[agents.bob]\nagent_id=\"ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n[[permissions]]\naction=\"network:request\"\nresource=\"*\"\neffect=\"allow\"\n[[permissions]]\naction=\"credential:use\"\nresource=\"*\"\neffect=\"{effect}\"\n"
        );
        std::fs::write(fixture.config.policy_file.as_ref().unwrap(), explicit).unwrap();
        proxy.reload(fixture.config.clone()).await.unwrap();
        for path in NATIVE_GET_PATHS {
            assert_eq!(fixture.access(ACCESS[0], "GET", path, true).await, status);
        }
        assert_eq!(
            fixture
                .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
                .await,
            status
        );
        assert_eq!(fixture.refresh(REFRESH[0], CLIENT, true).await, status);
    }
    std::fs::write(
        fixture.config.policy_file.as_ref().unwrap(),
        POLICY.replace("egress=\"allow\"", "egress=\"deny\""),
    )
    .unwrap();
    proxy.reload(fixture.config.clone()).await.unwrap();
    let blocked = super::raw_round_trip(
        &fixture.config.listeners[0].socket_path,
        b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n",
    )
    .await;
    assert!(blocked.starts_with(b"HTTP/1.1 403"));
    proxy.shutdown().await;
}

#[tokio::test]
async fn host_import_requires_a_subscription_pair_and_unique_beneficiary() {
    let fixture = Fixture::new().await;
    let pair = json!({"tokens":{"access_token":ACCESS[0],"refresh_token":REFRESH[0]}}).to_string();
    let duplicate = format!(
        "{{\"tokens\":{{\"access_token\":\"{}\",\"access_token\":\"{}\",\"refresh_token\":\"{}\"}}}}",
        ACCESS[0], ACCESS[1], REFRESH[0]
    );
    for (document, scope) in [
        ("{malformed".to_owned(), "persistent"),
        (json!({"OPENAI_API_KEY":ACCESS[0]}).to_string(), "persistent"),
        (json!({"tokens":{"access_token":ACCESS[0]}}).to_string(), "persistent"),
        (json!({"auth_mode":"apikey","tokens":{"access_token":ACCESS[0],"refresh_token":REFRESH[0]}}).to_string(), "persistent"),
        (duplicate, "persistent"),
        (pair.clone(), "run"),
        (pair.clone(), "invalid"),
    ] {
        let output = fixture.import_document(&document, scope);
        assert!(!output.status.success());
        for token in ACCESS.into_iter().chain(REFRESH) {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
        }
    }
    std::fs::write(
        fixture.config.policy_file.as_ref().unwrap(),
        POLICY.replace(
            "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    )
    .unwrap();
    assert!(
        !fixture
            .import_document(&pair, "persistent")
            .status
            .success()
    );
    let vault = credentials::open(fixture.config.data_dir.as_ref().unwrap()).unwrap();
    assert!(vault.list_names().unwrap().is_empty());
}

#[tokio::test]
async fn refresh_observation_uses_the_final_route_json_and_only_imported_authentication() {
    let fixture = Fixture::new().await;
    fixture.import();
    *fixture.response.lock().unwrap() = (
        200,
        json!({"access_token":ACCESS[1],"refresh_token":REFRESH[1]}).to_string(),
    );
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    let body = json!({"grant_type":"refresh_token","client_id":CLIENT,"refresh_token":REFRESH[0]})
        .to_string()
        .into_bytes();
    let json_headers = [("content-type", "application/json")];
    let duplicate = format!("{{\"grant_type\":\"refresh_token\",\"client_id\":\"{CLIENT}\",\"refresh_token\":\"untrusted\",\"refresh_token\":\"{}\"}}",REFRESH[0]).into_bytes();
    for (request, status) in [
        (
            request(
                "other.test",
                "POST",
                "/oauth/token",
                &json_headers,
                body.clone(),
            ),
            200,
        ),
        (
            request(
                "auth.openai.com",
                "POST",
                "/unrelated",
                &json_headers,
                body.clone(),
            ),
            200,
        ),
        (
            request(
                "auth.openai.com",
                "GET",
                "/oauth/token",
                &json_headers,
                body.clone(),
            ),
            428,
        ),
        (
            request(
                "auth.openai.com",
                "POST",
                "/oauth/token",
                &json_headers,
                duplicate,
            ),
            200,
        ),
        (
            request(
                "auth.openai.com",
                "POST",
                "/oauth/token",
                &[("content-type", "application/json"), ("x-api-key", "short")],
                body.clone(),
            ),
            200,
        ),
        (
            request(
                "auth.openai.com",
                "POST",
                "/oauth/token",
                &[
                    ("content-type", "application/json"),
                    ("cookie2", "different-account"),
                ],
                body.clone(),
            ),
            200,
        ),
        (
            request(
                "auth.openai.com",
                "POST",
                "/oauth/token",
                &[
                    ("content-type", "application/json"),
                    ("connection", "content-type"),
                ],
                body,
            ),
            200,
        ),
    ] {
        assert_eq!(fixture.send(0, request, false).await, status);
        assert_eq!(
            fixture
                .access(ACCESS[1], "POST", "/backend-api/codex/responses", false)
                .await,
            428
        );
        assert_eq!(fixture.refresh(REFRESH[1], CLIENT, false).await, 428);
    }
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 6);
    proxy.shutdown().await;
}

#[tokio::test]
async fn refresh_trailers_cannot_supply_unobserved_authentication() {
    let fixture = Fixture::new().await;
    fixture.import();
    *fixture.response.lock().unwrap() = (200, json!({"access_token":ACCESS[1]}).to_string());
    let mut proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    for denied in [false, true] {
        if denied {
            let policy = "budget=12000\n[agents.alice]\nagent_id=\"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n[agents.bob]\nagent_id=\"ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n[[permissions]]\naction=\"network:request\"\nresource=\"*\"\neffect=\"allow\"\n[[permissions]]\naction=\"credential:use\"\nresource=\"auth.openai.com/*\"\neffect=\"deny\"\n";
            std::fs::write(fixture.config.policy_file.as_ref().unwrap(), policy).unwrap();
            proxy.reload(fixture.config.clone()).await.unwrap();
            assert_eq!(fixture.refresh(REFRESH[0], CLIENT, true).await, 403);
        }
        let tls = super::ghcr::connect_tls(
            &fixture.config.listeners[0].socket_path,
            fixture.ca.clone(),
            "auth.openai.com",
            true,
        )
        .await;
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        let connection = tokio::spawn(connection);
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            "authorization",
            "Bearer unobserved-account".parse().unwrap(),
        );
        let body =
            json!({"grant_type":"refresh_token","client_id":CLIENT,"refresh_token":REFRESH[0]})
                .to_string();
        let frames = [
            Ok::<_, Infallible>(hyper::body::Frame::data(Bytes::from(body))),
            Ok(hyper::body::Frame::trailers(trailers)),
        ];
        let response = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://auth.openai.com/oauth/token")
                    .header("content-type", "application/json")
                    .body(http_body_util::StreamBody::new(futures_util::stream::iter(
                        frames,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), if denied { 403 } else { 200 });
        let _ = response.collect().await.unwrap();
        assert_eq!(fixture.seen.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture
                .access(ACCESS[1], "POST", "/backend-api/codex/responses", true)
                .await,
            428
        );
        connection.abort();
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn concurrent_issuance_retains_each_token_under_one_import() {
    let fixture = Fixture::new().await;
    fixture.import();
    *fixture.response.lock().unwrap() = (200, "concurrent".into());
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    let (first, second) = tokio::join!(
        fixture.refresh(REFRESH[0], CLIENT, true),
        fixture.refresh(REFRESH[0], CLIENT, true)
    );
    assert_eq!((first, second), (200, 200));
    for token in ACCESS {
        assert_eq!(
            fixture
                .access(token, "POST", "/backend-api/codex/responses", true)
                .await,
            200
        );
    }
    proxy.shutdown().await;
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    for token in ACCESS {
        assert_eq!(
            fixture
                .access(token, "POST", "/backend-api/codex/responses", true)
                .await,
            200
        );
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn revocation_or_reimport_during_exchange_cannot_restore_old_authority() {
    for reimport in [false, true] {
        let fixture = Fixture::new().await;
        fixture.import();
        *fixture.response.lock().unwrap() = (200, "paused".into());
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let vault = credentials::open(fixture.config.data_dir.as_ref().unwrap()).unwrap();
        let (result, ()) = tokio::join!(fixture.refresh(REFRESH[0], CLIENT, true), async {
            tokio::time::timeout(Duration::from_secs(5), async {
                while fixture.seen.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if reimport {
                fixture.import();
            } else {
                vault.remove("owned-codex").unwrap();
            }
            fixture.release.notify_one();
        });
        assert!(result >= 500);
        assert_eq!(
            fixture
                .access(ACCESS[1], "POST", "/backend-api/codex/responses", true)
                .await,
            428
        );
        proxy.shutdown().await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn run_scoped_import_follows_the_verified_backend_lifetime() {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    struct Backend(std::process::Child);
    impl Drop for Backend {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fixture = Fixture::new().await;
    let generation = "0123456789abcdef0123456789abcdef";
    let root = std::env::var_os("SAFEYOLO_RUNSC_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| fixture.directory.path().join("run"));
    let mut backend = Backend(
        Command::new("/bin/sh")
            .arg0("runsc-sandbox")
            .args(["-c", "read line"])
            .arg(format!("--root={}", root.display()))
            .arg("boot")
            .arg(format!("safeyolo-{generation}"))
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pid = backend.0.id();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let birth = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let agent = fixture.directory.path().join("agents/alice");
    std::fs::create_dir_all(agent.join("config-share")).unwrap();
    std::fs::write(agent.join("runtime.json"),json!({"name":"alice","agent_id":"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "run_id":generation,"state":"running","backend_pid":pid,"backend_token":format!("linux:{}:{pid}:{birth}",boot.trim())}).to_string()).unwrap();
    std::fs::write(
        agent.join("config-share/host-launch-context.json"),
        json!({"agent_id":"ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":generation})
            .to_string(),
    )
    .unwrap();
    fixture.import_scope("run");
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    assert_eq!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await,
        200
    );
    *fixture.response.lock().unwrap() = (
        200,
        json!({"access_token":ACCESS[1],"refresh_token":REFRESH[1]}).to_string(),
    );
    assert_eq!(fixture.refresh(REFRESH[0], CLIENT, true).await, 200);
    assert_eq!(
        fixture
            .access(ACCESS[1], "POST", "/backend-api/codex/responses", true)
            .await,
        200
    );
    backend.0.kill().unwrap();
    backend.0.wait().unwrap();
    assert_ne!(
        fixture
            .access(ACCESS[1], "POST", "/backend-api/codex/responses", true)
            .await,
        200
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn guest_markers_expiry_identity_and_stopped_run_do_not_create_authority() {
    let fixture = Fixture::new().await;
    let home = fixture.directory.path().join("agents/alice/home/.codex");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("auth.json"),
        json!({"tokens":{"access_token":ACCESS[0],"refresh_token":REFRESH[0]}}).to_string(),
    )
    .unwrap();
    std::fs::write(
        home.join(".safeyolo-provenance.json"),
        r#"{"schema":"safeyolo.codex-provenance/v1","state":"agent-local"}"#,
    )
    .unwrap();
    let mut proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    assert_eq!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await,
        428
    );
    assert_eq!(fixture.refresh(REFRESH[0], CLIENT, true).await, 428);
    assert_eq!(
        fixture
            .access(
                "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2F1dGgub3BlbmFpLmNvbSJ9.forged",
                "POST",
                "/backend-api/codex/responses",
                true
            )
            .await,
        428
    );
    fixture.import();
    assert_eq!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await,
        200
    );
    let vault = credentials::open(fixture.config.data_dir.as_ref().unwrap()).unwrap();
    let original = vault.get("owned-codex").unwrap().unwrap();
    let mut expired = original.clone();
    expired.expires_at = Some("2000-01-01T00:00:00Z".into());
    vault.store(expired).unwrap();
    assert_eq!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await,
        428
    );
    let mut stopped = original.clone();
    stopped.codex.as_mut().unwrap().run_id = Some("0123456789abcdef0123456789abcdef".into());
    vault.store(stopped).unwrap();
    assert_eq!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await,
        428
    );
    vault.store(original).unwrap();
    std::fs::write(
        fixture.config.policy_file.as_ref().unwrap(),
        POLICY.replace(
            "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ag-cccccccccccccccccccccccccccccccc",
        ),
    )
    .unwrap();
    proxy.reload(fixture.config.clone()).await.unwrap();
    assert_eq!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await,
        428
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn imported_credentials_do_not_bypass_upstream_tls_verification() {
    let fixture = Fixture::new().await;
    fixture.import();
    let unrelated =
        rcgen::generate_simple_self_signed(vec!["unrelated-trust.test".into()]).unwrap();
    std::fs::write(
        fixture.config.upstream_ca_file.as_ref().unwrap(),
        unrelated.cert.pem(),
    )
    .unwrap();
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    assert!(
        fixture
            .access(ACCESS[0], "POST", "/backend-api/codex/responses", true)
            .await
            >= 500
    );
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 0);
    proxy.shutdown().await;
}

#[tokio::test]
async fn malformed_duplicate_and_redirected_issuance_cannot_authorize_replacements() {
    for (status, body) in [
        (
            200,
            format!(
                "{{\"access_token\":\"{}\",\"access_token\":\"{}\"}}",
                ACCESS[1], ACCESS[2]
            ),
        ),
        (200, "{malformed".into()),
        (200, "incomplete".into()),
        (
            200,
            json!({"access_token":ACCESS[1],"padding":"x".repeat(65536)}).to_string(),
        ),
        (307, json!({"access_token":ACCESS[1]}).to_string()),
    ] {
        let fixture = Fixture::new().await;
        fixture.import();
        *fixture.response.lock().unwrap() = (status, body);
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let result = fixture.refresh(REFRESH[0], CLIENT, false).await;
        assert!(result >= 300, "invalid issuance was released as success");
        assert_eq!(
            fixture
                .access(ACCESS[1], "POST", "/backend-api/codex/responses", false)
                .await,
            428
        );
        assert_eq!(fixture.access(ACCESS[0], "GET", ACCOUNT, false).await, 200);
        proxy.shutdown().await;
    }
}
