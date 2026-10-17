//! GHCR exchanges cross the real UDS, CONNECT, verified TLS and HTTP pipeline.
use super::*;
use safeyolo_proxy::credentials::Secret;

const QUERY: &str = "/token?service=ghcr.io&scope=repository:owner/image:pull";
const READ: &str = "/v2/owner/image/manifests/latest";
const FIRST: &str = "v1.abcdefgh0123456789ZYXWVUTSRQPOnmlkjihg";
const SECOND: &str = "v1.replacementZYXW9876543210abcdefghJKLMN";

struct OriginRequest {
    host: String,
    path: String,
    authenticated: bool,
    headers: hyper::HeaderMap,
}

struct Fixture {
    directory: TempDir,
    config: Config,
    ca: rustls::pki_types::CertificateDer<'static>,
    parent: tokio::task::JoinHandle<()>,
    seen: Arc<Mutex<Vec<OriginRequest>>>,
    response_mode: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(policy: Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("agent.sock");
        let policy_path = directory.path().join("policy.json");
        std::fs::write(&policy_path, policy.to_string()).unwrap();
        let mut config = super::config(&directory, &policy_path, &socket, true);
        let tls = configure_h2_test_tls(&directory, &mut config, "ghcr.io");
        let origin =
            rcgen::generate_simple_self_signed(vec!["ghcr.io".into(), "other.test".into()])
                .unwrap();
        std::fs::write(config.upstream_ca_file.as_ref().unwrap(), origin.cert.pem()).unwrap();
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
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
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let (listener, address) = test_owned_endpoint::bind().await;
        config.parent_proxy = Some(format!("http://{address}"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::new(AtomicUsize::new(0));
        let response_mode = Arc::new(AtomicUsize::new(0));
        let parent = tokio::spawn({
            let seen = seen.clone();
            let response_mode = response_mode.clone();
            async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        peer=listener.accept() => {
                            let (mut peer,_)=peer.unwrap();
                            let acceptor=acceptor.clone(); let seen=seen.clone(); let counter=counter.clone(); let response_mode=response_mode.clone();
                            children.spawn(async move {
                                let mut head=Vec::new();
                                while !head.ends_with(b"\r\n\r\n") {head.push(peer.read_u8().await.unwrap());}
                                let host=std::str::from_utf8(&head).unwrap().lines().next().unwrap().split_whitespace().nth(1).unwrap().to_owned();
                                assert!(matches!(host.as_str(),"ghcr.io:443"|"other.test:443"));
                                peer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                                // A TLS failure is an expected negative control.
                                let Ok(tls)=acceptor.accept(peer).await else { return; };
                                let h2=tls.get_ref().1.alpn_protocol()==Some(b"h2".as_slice());
                                let service=service_fn(move |request:Request<Incoming>| {
                                    let seen=seen.clone(); let counter=counter.clone(); let host=host.clone(); let response_mode=response_mode.clone();
                                    async move {
                                        let (request,body)=request.into_parts();
                                        let body=body.collect().await.unwrap();
                                        let path=request.uri.path_and_query().unwrap().as_str().to_owned();
                                        let authenticated=request.headers.contains_key("authorization") || request.headers.contains_key("x-final-auth")
                                            || body.trailers().is_some_and(|trailers|trailers.contains_key("authorization"));
                                        seen.lock().unwrap().push(OriginRequest {host:host.clone(),path:path.clone(),authenticated,headers:request.headers.clone()});
                                        let (status,body,location) = if path.starts_with("/token") {
                                            let token=if counter.fetch_add(1,Ordering::SeqCst).is_multiple_of(2) {FIRST} else {SECOND};
                                            match response_mode.load(Ordering::SeqCst) {
                                                1 => (401,json!({"token":token}).to_string(),None),
                                                2 => (200,format!("{{\"token\":\"{token}\",\"expires_in\":\"bad\"}}"),None),
                                                3 => (302,json!({"token":token}).to_string(),Some("https://other.test/token")),
                                                4 => (200,format!("{{\"token\":\"{token}\",\"unused\":\"{}\"}}","x".repeat(65536)),None),
                                                5 => (200,json!({"token":"opaque"}).to_string(),None),
                                                _ => (200,json!({"token":token}).to_string(),None),
                                            }
                                        } else if path.contains("redirect") {
                                            (307,String::new(),Some("https://other.test/v2/owner/image/manifests/latest"))
                                        } else {(200,"small-public-blob".to_owned(),None)};
                                        let mut reply=hyper::Response::builder().status(status).header("content-type","application/json");
                                        if let Some(location)=location {reply=reply.header("location",location);}
                                        let body=if request.method==hyper::Method::HEAD {String::new()} else {body};
                                        Ok::<_,Infallible>(reply.body(Full::new(Bytes::from(body))).unwrap())
                                    }
                                });
                                if h2 {
                                    let _=hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls),service).await;
                                } else {
                                    let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls),service).await;
                                }
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
            seen,
            response_mode,
        }
    }
    async fn fetch(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        h2: bool,
    ) -> (u16, Vec<u8>) {
        tokio::time::timeout(
            Duration::from_secs(10),
            fetch(
                &self.config.listeners[0].socket_path,
                self.ca.clone(),
                host,
                method,
                path,
                headers,
                h2,
            ),
        )
        .await
        .expect("GHCR request deadline")
    }
    async fn token(&self, h2: bool) -> String {
        let (status, bytes) = self.fetch("ghcr.io", "GET", QUERY, &[], h2).await;
        assert_eq!(status, 200);
        serde_json::from_slice::<Value>(&bytes).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.parent.abort();
    }
}

fn default_policy() -> Value {
    json!({"hosts":{"*":{"egress":"allow","unknown_credentials":"prompt"}}})
}

async fn assert_no_pending(directory: &TempDir) {
    let reply = super::raw_admin_exchange(directory,b"GET /admin/approvals HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer credential-http-admin\r\nConnection: close\r\n\r\n").await;
    let split = reply
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    let body: Value = serde_json::from_slice(&reply[split + 4..]).unwrap();
    assert!(body["approvals"].as_array().unwrap().is_empty());
}

async fn fetch(
    socket: &std::path::Path,
    ca: rustls::pki_types::CertificateDer<'static>,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    h2: bool,
) -> (u16, Vec<u8>) {
    let reply = fetch_response(socket, ca, host, method, path, headers, h2).await;
    (reply.status().as_u16(), reply.into_body())
}

async fn fetch_response(
    socket: &std::path::Path,
    ca: rustls::pki_types::CertificateDer<'static>,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    h2: bool,
) -> hyper::Response<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let head = super::response_head(&mut stream).await;
        assert!(head.starts_with(b"HTTP/1.1 200"), "CONNECT failed");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(
                rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap(),
                stream,
            )
            .await
            .unwrap();
        let mut request = Request::builder()
            .method(method)
            .uri(format!("https://{host}{path}"))
            .header("host", host);
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let request = request.body(Empty::<Bytes>::new()).unwrap();
        let (reply, connection) = if h2 {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                    .await
                    .unwrap();
            let connection = tokio::spawn(connection);
            (sender.send_request(request).await.unwrap(), connection)
        } else {
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .unwrap();
            let connection = tokio::spawn(connection);
            (sender.send_request(request).await.unwrap(), connection)
        };
        let (parts, body) = reply.into_parts();
        let bytes = http_body_util::Limited::new(body, 256 * 1024)
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        connection.abort();
        hyper::Response::from_parts(parts, bytes)
    })
    .await
    .expect("GHCR response deadline")
}

#[tokio::test]
async fn repeated_public_pull_reuse_concurrency_replacement_and_restart() {
    for h2 in [false, true] {
        let fixture = Fixture::new(default_policy()).await;
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let policy_before = std::fs::read(fixture.config.policy_file.as_ref().unwrap()).unwrap();
        let first = fixture.token(h2).await;
        let second = fixture.token(h2).await;
        assert!(first != second, "fixture must rotate tokens");
        for token in [&first, &second] {
            let authorization = format!("Bearer {token}");
            let reads = ["/v2/", READ, "/v2/owner/image/blobs/sha256:abc"];
            let results = futures_util::future::join_all(reads.iter().map(|path| async {
                fixture
                    .fetch(
                        "ghcr.io",
                        "GET",
                        path,
                        &[("authorization", authorization.as_str())],
                        h2,
                    )
                    .await
            }))
            .await;
            assert!(results.iter().all(|(status, _)| *status == 200));
            assert_eq!(
                fixture
                    .fetch(
                        "ghcr.io",
                        "HEAD",
                        READ,
                        &[("authorization", &authorization)],
                        h2
                    )
                    .await
                    .0,
                200
            );
        }
        assert_no_pending(&fixture.directory).await;
        assert_eq!(
            std::fs::read(fixture.config.policy_file.as_ref().unwrap()).unwrap(),
            policy_before
        );
        proxy.shutdown().await;
        let events = std::fs::read_to_string(&fixture.config.event_log).unwrap();
        let audit =
            std::fs::read_to_string(fixture.config.audit_log_path.as_ref().unwrap()).unwrap();
        assert!(
            !events.contains(&first)
                && !events.contains(&second)
                && !audit.contains(&first)
                && !audit.contains(&second)
        );
        assert!(
            !audit
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .any(|row| row["approval"]["required"] == true)
        );
        let allowed: Vec<_> = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|row| row["event"] == "proxy.credential_guard" && row["outcome"] == "allowed")
            .collect();
        assert_eq!(allowed.len(), 8);
        assert!(
            allowed
                .iter()
                .all(|row| row["audit"][0]["details"]["observed_anonymous_ghcr_pull"] == true)
        );
        // Restart over the same data/policy retains no token approval or cache.
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let auth = format!("Bearer {second}");
        assert_eq!(
            fixture
                .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], h2)
                .await
                .0,
            428
        );
        let fresh = fixture.token(h2).await;
        let auth = format!("Bearer {fresh}");
        assert_eq!(
            fixture
                .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], h2)
                .await
                .0,
            200
        );
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn learned_tokens_keep_repeated_field_inspection_approvals_and_budgets() {
    use super::boundary::{KEY, basic, fingerprint};

    for h2 in [false, true] {
        let fixture = Fixture::new(default_policy()).await;
        let data = fixture.config.data_dir.as_ref().unwrap();
        std::fs::create_dir_all(data).unwrap();
        std::fs::write(data.join("hmac_secret"), KEY).unwrap();
        let mut proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let first = fixture.token(h2).await;
        let second = fixture.token(h2).await;
        fixture.response_mode.store(5, Ordering::SeqCst);
        let opaque = fixture.token(h2).await;
        let bearer = format!("Bearer {first}");
        let other = format!("Bearer {second}");
        let opaque_bearer = format!("Bearer {opaque}");
        let encoded = basic(&first);
        let encoded_other = basic(&second);
        let combined_equal = format!("{bearer}, {bearer}");
        let combined_distinct = format!("{bearer}, {other}");
        let combined_basic = format!("{encoded}, {encoded_other}");
        let combined_mixed = format!("{bearer}, {encoded}");
        let cases = [
            vec![
                ("Authorization", bearer.as_str()),
                ("authorization", &bearer),
            ],
            vec![("Authorization", &bearer), ("authorization", &other)],
            vec![("Authorization", &encoded), ("authorization", &encoded)],
            vec![("Authorization", &bearer), ("authorization", &encoded)],
            vec![("Authorization", &combined_equal)],
            vec![("Authorization", &combined_distinct)],
            vec![("Authorization", &combined_basic)],
            vec![("Authorization", &combined_mixed)],
            vec![
                ("Authorization", &opaque_bearer),
                ("authorization", &opaque_bearer),
            ],
        ];
        // Recognition also detects opaque values below entropy thresholds.
        assert_eq!(
            fixture
                .fetch(
                    "ghcr.io",
                    "GET",
                    READ,
                    &[("authorization", &opaque_bearer)],
                    h2
                )
                .await
                .0,
            200
        );
        assert_no_pending(&fixture.directory).await;
        let before = fixture.seen.lock().unwrap().len();
        // Neither repeated fields nor combined entries gain the singleton
        // anonymous allowance. Each value still needs its ordinary approval.
        for (index, fields) in cases.iter().enumerate() {
            for method in ["GET", "HEAD"] {
                let reply = fetch_response(
                    &fixture.config.listeners[0].socket_path,
                    fixture.ca.clone(),
                    "ghcr.io",
                    method,
                    READ,
                    fields,
                    h2,
                )
                .await;
                assert_eq!(reply.status(), 428, "case {index}, {method}, h2={h2}");
                assert_eq!(reply.headers()["x-blocked-by"], "credential-guard");
                assert!(reply.headers().contains_key("x-safeyolo-request-id"));
                if method == "HEAD" {
                    assert!(reply.body().is_empty());
                } else {
                    assert_eq!(
                        serde_json::from_slice::<Value>(reply.body()).unwrap()["error"],
                        "Require Approval"
                    );
                }
                assert_eq!(fixture.seen.lock().unwrap().len(), before);
            }
        }
        let mut policy = default_policy();
        let approval = json!({
            "action":"credential:use", "resource":"ghcr.io/*", "effect":"allow",
            "condition":{"credential":[fingerprint(&first)]}
        });
        policy["hosts"]["ghcr.io"] = json!({"rules":[approval]});
        let policy_path = fixture.config.policy_file.as_ref().unwrap();
        std::fs::write(policy_path, policy.to_string()).unwrap();
        proxy.reload(fixture.config.clone()).await.unwrap();
        for fields in [&cases[1], &cases[5], &cases[6]] {
            assert_eq!(
                fixture.fetch("ghcr.io", "GET", READ, fields, h2).await.0,
                428
            );
            assert_eq!(fixture.seen.lock().unwrap().len(), before);
        }
        policy["hosts"]["ghcr.io"]["rules"][0]["condition"]["credential"] = json!([
            fingerprint(&first),
            fingerprint(&second),
            fingerprint(&opaque)
        ]);
        std::fs::write(policy_path, policy.to_string()).unwrap();
        proxy.reload(fixture.config.clone()).await.unwrap();
        for (index, fields) in cases.iter().enumerate() {
            assert_eq!(
                fixture.fetch("ghcr.io", "GET", READ, fields, h2).await.0,
                200,
                "approved case {index}, h2={h2}"
            );
            let requests = fixture.seen.lock().unwrap();
            assert_eq!(requests.len(), before + index + 1);
            let forwarded = requests
                .last()
                .unwrap()
                .headers
                .get_all("authorization")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>();
            assert!(
                forwarded == fields.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
                "approved fields changed at origin, case {index}, h2={h2}"
            );
        }
        let before = fixture.seen.lock().unwrap().len();
        let extra_secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
        for (host, fields) in [
            ("other.test", cases[0].clone()),
            (
                "ghcr.io",
                vec![
                    ("authorization", bearer.as_str()),
                    ("x-api-key", extra_secret),
                ],
            ),
            (
                "ghcr.io",
                vec![
                    ("authorization", bearer.as_str()),
                    ("authorization", bearer.as_str()),
                    ("x-api-key", extra_secret),
                ],
            ),
        ] {
            assert_eq!(fixture.fetch(host, "GET", READ, &fields, h2).await.0, 428);
            assert_eq!(fixture.seen.lock().unwrap().len(), before);
        }
        policy["hosts"]["ghcr.io"]["rules"][0]["effect"] = json!("deny");
        std::fs::write(policy_path, policy.to_string()).unwrap();
        proxy.reload(fixture.config.clone()).await.unwrap();
        let reply = fetch_response(
            &fixture.config.listeners[0].socket_path,
            fixture.ca.clone(),
            "ghcr.io",
            "HEAD",
            READ,
            &cases[0],
            h2,
        )
        .await;
        assert_eq!(reply.status(), 403);
        assert_eq!(reply.headers()["x-blocked-by"], "credential-guard");
        assert!(reply.body().is_empty());
        assert_eq!(fixture.seen.lock().unwrap().len(), before);
        // One charge per equal credential leaves the second burst use intact.
        policy["hosts"]["ghcr.io"]["rules"][0]["effect"] = json!("budget");
        policy["hosts"]["ghcr.io"]["rules"][0]["budget"] = json!(1);
        policy["hosts"]["ghcr.io"]["rules"][0]["condition"]["credential"] =
            json!([fingerprint(&first)]);
        std::fs::write(policy_path, policy.to_string()).unwrap();
        proxy.reload(fixture.config.clone()).await.unwrap();
        for (fields, status) in [(&cases[0], 200), (&cases[4], 200), (&cases[0], 429)] {
            assert_eq!(
                fixture.fetch("ghcr.io", "GET", READ, fields, h2).await.0,
                status
            );
        }
        assert_eq!(fixture.seen.lock().unwrap().len(), before + 2);
        proxy.shutdown().await;
        for path in [
            &fixture.config.event_log,
            fixture.config.audit_log_path.as_ref().unwrap(),
        ] {
            let text = std::fs::read_to_string(path).unwrap();
            for value in [
                first.as_str(),
                second.as_str(),
                opaque.as_str(),
                encoded.as_str(),
                encoded_other.as_str(),
                extra_secret,
            ] {
                assert!(!text.contains(value), "raw credential in events or audit");
            }
        }
    }
}

#[tokio::test]
async fn acquisition_origin_scope_authentication_and_redirects_do_not_register() {
    for h2 in [false, true] {
        // Permit test authentication to reach the token endpoint, so refusal
        // to learn is tested after an actual successful authenticated response.
        let mut policy = default_policy();
        policy["hosts"]["ghcr.io"] = json!({"rules":[{"action":"credential:use","resource":"ghcr.io/*","effect":"allow","condition":{"path_prefix":"/token"}}]});
        let fixture = Fixture::new(policy).await;
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let cases = [
            (
                "ghcr.io",
                format!("{QUERY}&scope=repository:owner/image:pull,push"),
                vec![],
            ),
            ("ghcr.io", format!("{QUERY}&refresh_token=example"), vec![]),
            (
                "ghcr.io",
                QUERY.to_owned(),
                vec![("authorization", "Basic dXNlcjpwYXNzd29yZA==")],
            ),
            (
                "ghcr.io",
                QUERY.to_owned(),
                vec![(
                    "authorization",
                    "Bearer ghp_012345678901234567890123456789012345",
                )],
            ),
            (
                "ghcr.io",
                QUERY.to_owned(),
                vec![("cookie", "session=private")],
            ),
            ("other.test", QUERY.to_owned(), vec![]),
        ];
        for (host, path, headers) in cases {
            assert_eq!(
                fixture.fetch(host, "GET", &path, &headers, h2).await.0,
                200,
                "negative acquisition must reach its upstream response"
            );
            for token in [FIRST, SECOND] {
                let auth = format!("Bearer {token}");
                assert_eq!(
                    fixture
                        .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], h2)
                        .await
                        .0,
                    428
                );
            }
        }
        // The request still qualifies in these cases: only response status,
        // payload, redirect or capture size prevents recognition.
        for mode in 1..=4 {
            fixture.response_mode.store(mode, Ordering::SeqCst);
            let _ = fixture.fetch("ghcr.io", "GET", QUERY, &[], h2).await;
            for token in [FIRST, SECOND] {
                let auth = format!("Bearer {token}");
                assert_eq!(
                    fixture
                        .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], h2)
                        .await
                        .0,
                    428
                );
            }
        }
        fixture.response_mode.store(0, Ordering::SeqCst);
        let token = fixture.token(h2).await;
        let auth = format!("Bearer {token}");
        assert_eq!(
            fixture
                .fetch(
                    "ghcr.io",
                    "GET",
                    "/v2/owner/image/manifests/redirect",
                    &[("authorization", &auth)],
                    h2
                )
                .await
                .0,
            307
        );
        for (host, method, path) in [
            ("other.test", "GET", READ),
            ("ghcr.io", "GET", "/v2/other/image/manifests/latest"),
            ("ghcr.io", "POST", READ),
        ] {
            assert_eq!(
                fixture
                    .fetch(host, method, path, &[("authorization", &auth)], h2)
                    .await
                    .0,
                428
            );
        }
        assert_eq!(
            fixture
                .fetch(
                    "ghcr.io",
                    "GET",
                    READ,
                    &[
                        ("authorization", &auth),
                        ("x-api-key", "sk-abcdefghijklmnopqrstuvwxyz0123456789")
                    ],
                    h2
                )
                .await
                .0,
            428
        );
        assert!(
            fixture
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.path == QUERY && request.authenticated),
            "authenticated token exchange did not reach origin"
        );
        assert!(
            !fixture
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.host == "other.test:443" && request.path == READ),
            "redirect leaked bearer across origin"
        );
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn learned_token_still_obeys_credential_and_network_denials_after_reload() {
    let fixture = Fixture::new(default_policy()).await;
    let mut proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    fixture.response_mode.store(5, Ordering::SeqCst);
    let token = fixture.token(false).await;
    let auth = format!("Bearer {token}");
    assert_eq!(
        fixture
            .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], false)
            .await
            .0,
        200
    );
    assert_eq!(
        fixture
            .fetch(
                "ghcr.io",
                "GET",
                "/v2/owner/private/manifests/latest",
                &[("authorization", &auth)],
                false
            )
            .await
            .0,
        428
    );
    for permission in [
        json!({"action":"credential:use","resource":"ghcr.io/*","effect":"deny"}),
        json!({"action":"credential:use","resource":"*","effect":"deny","condition":{"credential":["unknown:*"]}}),
        json!({"action":"network:request","resource":"ghcr.io/*","effect":"deny","condition":{"method":["GET","HEAD"]}}),
    ] {
        let mut policy = default_policy();
        policy["hosts"]["ghcr.io"] = json!({"rules":[permission.clone()]});
        std::fs::write(
            fixture.config.policy_file.as_ref().unwrap(),
            policy.to_string(),
        )
        .unwrap();
        proxy.reload(fixture.config.clone()).await.unwrap();
        let before = fixture.seen.lock().unwrap().len();
        assert_eq!(
            fixture
                .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], false)
                .await
                .0,
            403,
            "permission {permission}"
        );
        assert_eq!(before, fixture.seen.lock().unwrap().len());
    }
    std::fs::write(
        fixture.config.policy_file.as_ref().unwrap(),
        default_policy().to_string(),
    )
    .unwrap();
    proxy.reload(fixture.config.clone()).await.unwrap();
    assert_eq!(
        fixture
            .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], false)
            .await
            .0,
        200
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn final_gateway_injection_cannot_turn_authenticated_response_into_anonymous_issuance() {
    use safeyolo_proxy::credentials::{Credential, Vault};
    let policy = json!({"permissions":[
        {"action":"network:request","resource":"*","effect":"allow"},
        {"action":"gateway:request","resource":"*","effect":"allow"}
    ],"gateway":{"host_map":{"ghcr.io":"ghcr-auth"},"token_map":{
        "sgw_final_auth":{"agent":"alice","service":"ghcr-auth","capability":"reader","token":"private-account"}
    }}});
    let mut fixture = Fixture::new(policy).await;
    let services = fixture.directory.path().join("services");
    std::fs::create_dir(&services).unwrap();
    std::fs::write(
        services.join("ghcr-auth.yaml"),
        r#"
schema_version: 1
name: ghcr-auth
default_host: ghcr.io
auth:
  type: api_key
  header: X-Final-Auth
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /token
"#,
    )
    .unwrap();
    fixture.config.gateway_services_dir = Some(services);
    let builtin = fixture.directory.path().join("builtin");
    std::fs::create_dir(&builtin).unwrap();
    fixture.config.gateway_builtin_services_dir = Some(builtin);
    let data = fixture.config.data_dir.as_ref().unwrap();
    std::fs::create_dir_all(data).unwrap();
    std::fs::write(data.join("credentials.key"), "test-ghcr-vault-password").unwrap();
    let vault = Vault::unlock(
        data.join("credentials.enc"),
        &Secret::new("test-ghcr-vault-password"),
    )
    .unwrap();
    vault
        .store(Credential::new(
            "private-account",
            "api_key",
            Secret::new("private-upstream-account"),
        ))
        .unwrap();
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    let (status, _) = fixture
        .fetch(
            "ghcr.io",
            "GET",
            QUERY,
            &[("x-final-auth", "sgw_final_auth")],
            false,
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        fixture
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.path == QUERY && request.authenticated)
    );
    for token in [FIRST, SECOND] {
        let auth = format!("Bearer {token}");
        assert_eq!(
            fixture
                .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], false)
                .await
                .0,
            428
        );
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn unverified_upstream_tls_cannot_register_a_token() {
    let fixture = Fixture::new(default_policy()).await;
    let unrelated = rcgen::generate_simple_self_signed(vec!["unrelated.test".into()]).unwrap();
    std::fs::write(
        fixture.config.upstream_ca_file.as_ref().unwrap(),
        unrelated.cert.pem(),
    )
    .unwrap();
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    assert!(fixture.fetch("ghcr.io", "GET", QUERY, &[], false).await.0 >= 500);
    let auth = format!("Bearer {FIRST}");
    assert_eq!(
        fixture
            .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], false)
            .await
            .0,
        428
    );
    assert!(fixture.seen.lock().unwrap().is_empty());
    proxy.shutdown().await;
}

#[tokio::test]
async fn discovery_token_without_repository_scope_cannot_read_a_repository() {
    let fixture = Fixture::new(default_policy()).await;
    let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
    assert_eq!(
        fixture
            .fetch(
                "ghcr.io",
                "GET",
                "/token?service=ghcr.io&client_id=&offline_token=false&account=",
                &[],
                false
            )
            .await
            .0,
        200
    );
    let auth = format!("Bearer {FIRST}");
    assert_eq!(
        fixture
            .fetch("ghcr.io", "GET", "/v2/", &[("authorization", &auth)], false)
            .await
            .0,
        200
    );
    assert_no_pending(&fixture.directory).await;
    assert_eq!(
        fixture
            .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], false)
            .await
            .0,
        428
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn h2_empty_data_is_anonymous_but_authentication_trailers_are_not() {
    use hyper::{HeaderMap, body::Frame};
    for authenticated in [false, true] {
        let fixture = Fixture::new(default_policy()).await;
        let proxy = Proxy::start(fixture.config.clone()).await.unwrap();
        let tls = connect_h2_through_proxy(
            &fixture.config.listeners[0].socket_path,
            "ghcr.io:443",
            "ghcr.io",
            fixture.ca.clone(),
        )
        .await;
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        let connection = tokio::spawn(connection);
        let mut frames = vec![Ok::<_, Infallible>(Frame::data(Bytes::new()))];
        if authenticated {
            let mut trailers = HeaderMap::new();
            trailers.insert(
                "authorization",
                "Bearer private-trailing-auth".parse().unwrap(),
            );
            frames.push(Ok(Frame::trailers(trailers)));
        }
        let response = sender
            .send_request(
                Request::builder()
                    .uri(format!("https://ghcr.io{QUERY}"))
                    .header("content-length", "0")
                    .body(http_body_util::StreamBody::new(futures_util::stream::iter(
                        frames,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let _ = response.collect().await.unwrap();
        let auth = format!("Bearer {FIRST}");
        assert_eq!(
            fixture
                .fetch("ghcr.io", "GET", READ, &[("authorization", &auth)], true)
                .await
                .0,
            if authenticated { 428 } else { 200 }
        );
        assert!(
            fixture
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.path == QUERY && request.authenticated == authenticated)
        );
        connection.abort();
        proxy.shutdown().await;
    }
}

/// Manual online witness. The candidate runs in this process and uses the
/// configured parent proxy; it never opens a direct route around that parent.
#[tokio::test]
#[ignore = "live GHCR access; run explicitly at the clean candidate revision"]
async fn live_public_manifest_and_small_blob() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy = directory.path().join("policy.json");
    std::fs::write(&policy, default_policy().to_string()).unwrap();
    let before = std::fs::read(&policy).unwrap();
    let mut config = super::config(&directory, &policy, &socket, true);
    let tls = configure_h2_test_tls(&directory, &mut config, "ghcr.io");
    config.upstream_ca_file = std::env::var_os("SSL_CERT_FILE").map(std::path::PathBuf::from);
    config.parent_proxy = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .ok()
        .filter(|value| !value.is_empty());
    let event_log = config.event_log.clone();
    let audit_path = config.audit_log_path.clone().unwrap();
    let proxy = Proxy::start(config).await.unwrap();
    let repository = "craigbalding/safeyolo-guest";
    let token_path = format!("/token?service=ghcr.io&scope=repository:{repository}:pull");
    let mut previous = None::<Secret>;
    let mut manifest_reads = 0usize;
    let mut blob_bytes = 0usize;
    for _ in 0..2 {
        let (status, bytes) = fetch(
            &socket,
            tls.proxy_ca.clone(),
            "ghcr.io",
            "GET",
            &token_path,
            &[],
            false,
        )
        .await;
        assert_eq!(status, 200, "live token exchange failed");
        let document: Value = serde_json::from_slice(&bytes).unwrap();
        let token = Secret::new(
            document["token"]
                .as_str()
                .or_else(|| document["access_token"].as_str())
                .expect("missing live bearer"),
        );
        if let Some(previous) = &previous {
            assert!(
                previous.expose_secret() != token.expose_secret(),
                "GHCR did not rotate tokens"
            );
        }
        let auth = Secret::new(format!("Bearer {}", token.expose_secret()));
        let headers = [
            ("authorization", auth.expose_secret()),
            (
                "accept",
                "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json",
            ),
        ];
        let mut path = format!("/v2/{repository}/manifests/compat-v1");
        let (status, bytes) = fetch(
            &socket,
            tls.proxy_ca.clone(),
            "ghcr.io",
            "GET",
            &path,
            &headers,
            false,
        )
        .await;
        assert_eq!(status, 200, "live manifest retrieval failed");
        manifest_reads += 1;
        let mut manifest: Value = serde_json::from_slice(&bytes).unwrap();
        if let Some(entries) = manifest["manifests"].as_array() {
            let child = entries
                .iter()
                .find(|entry| {
                    entry["platform"]["os"] == "linux"
                        && entry["platform"]["architecture"] == "amd64"
                })
                .or_else(|| entries.first())
                .unwrap();
            path = format!(
                "/v2/{repository}/manifests/{}",
                child["digest"].as_str().unwrap()
            );
            let (status, bytes) = fetch(
                &socket,
                tls.proxy_ca.clone(),
                "ghcr.io",
                "GET",
                &path,
                &headers,
                false,
            )
            .await;
            assert_eq!(status, 200, "live child manifest retrieval failed");
            manifest_reads += 1;
            manifest = serde_json::from_slice(&bytes).unwrap();
        }
        let descriptor = &manifest["config"];
        assert!(
            descriptor["size"]
                .as_u64()
                .is_some_and(|size| size > 0 && size <= 256 * 1024),
            "select only a small config blob"
        );
        let path = format!(
            "/v2/{repository}/blobs/{}",
            descriptor["digest"].as_str().unwrap()
        );
        let mut reply = fetch_response(
            &socket,
            tls.proxy_ca.clone(),
            "ghcr.io",
            "GET",
            &path,
            &headers,
            false,
        )
        .await;
        for _ in 0..5 {
            if !reply.status().is_redirection() {
                break;
            }
            let location: Uri = reply.headers()["location"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(location.scheme_str(), Some("https"));
            let host = location.host().unwrap();
            assert!(location.port_u16().is_none_or(|port| port == 443));
            let redirected_headers = if host == "ghcr.io" {
                headers.as_slice()
            } else {
                &[]
            };
            reply = fetch_response(
                &socket,
                tls.proxy_ca.clone(),
                host,
                "GET",
                location.path_and_query().unwrap().as_str(),
                redirected_headers,
                false,
            )
            .await;
        }
        assert_eq!(reply.status(), 200, "live small-blob retrieval failed");
        let bytes = reply.into_body();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len() as u64, descriptor["size"].as_u64().unwrap());
        let expected = descriptor["digest"].as_str().unwrap();
        let actual = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            expected,
            format!("sha256:{actual}"),
            "small blob must match the manifest"
        );
        blob_bytes += bytes.len();
        previous = Some(token);
    }
    assert_no_pending(&directory).await;
    assert_eq!(std::fs::read(&policy).unwrap(), before);
    proxy.shutdown().await;
    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(
        !audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .any(|row| row["approval"]["required"] == true)
    );
    let events = std::fs::read_to_string(event_log).unwrap();
    let rows: Vec<Value> = events
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let observed = rows
        .iter()
        .filter(|row| {
            row["event"] == "proxy.credential_guard"
                && row["audit"][0]["details"]["observed_anonymous_ghcr_pull"] == true
        })
        .count();
    assert!(
        observed >= manifest_reads + 2,
        "missing candidate credential decisions"
    );
    assert!(
        rows.iter()
            .any(|row| row["event"] == "proxy.egress" && row["host"] == "ghcr.io")
    );
    println!(
        "live GHCR candidate: two distinct tokens, {manifest_reads} manifests, two blobs ({blob_bytes} bytes), {observed} observed-token decisions, zero approval events, zero pending approvals; source {}",
        option_env!("SAFEYOLO_BUILD_REVISION").unwrap_or("unknown")
    );
}
