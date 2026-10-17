use super::*;
use base64::Engine;
use hyper::body::Body as _;

const TOKEN: &str = "v1.abcdefgh0123456789ZYXWVUTSRQPOnmlkjihg";
const OTHER: &str = "v1.ZYXWVUTSRQPOnmlkjihg9876543210abcdefgh";
const KEY: &[u8] = b"credential-http-boundary-key";

fn fingerprint(value: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, KEY);
    let digest = ring::hmac::sign(&key, value.as_bytes());
    format!("hmac:{}", hex_encode(&digest.as_ref()[..8]))
}

fn policy(permissions: Vec<Value>) -> Value {
    json!({
        "permissions": permissions,
        "credential_rules": [{
            "name":"catalogue-control",
            "patterns":["catalogue-[a-z]+"],
            "allowed_hosts":["127.0.0.1", "localhost"],
            "header_names":["authorization", "x-api-key"]
        }]
    })
}

fn permissions(host: &str, approved: &[&str]) -> Vec<Value> {
    vec![
        json!({"action":"network:request", "resource":"*", "effect":"allow"}),
        json!({"action":"credential:use", "resource":format!("{host}/*"), "effect":"allow",
            "condition":{"credential":approved.iter().map(|token| fingerprint(token)).collect::<Vec<_>>()}}),
        json!({"action":"credential:use", "resource":"*", "effect":"prompt"}),
    ]
}

fn basic(password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("user:{password}"))
    )
}

fn check_redaction(directory: &TempDir) {
    for path in ["events.jsonl", "audit.jsonl"] {
        let text = std::fs::read_to_string(directory.path().join(path)).unwrap();
        for secret in [
            TOKEN.to_owned(),
            OTHER.to_owned(),
            basic(TOKEN),
            basic(OTHER),
        ] {
            assert!(!text.contains(&secret), "raw credential in {path}");
        }
    }
}

#[tokio::test]
async fn repeated_h1_fields_keep_credential_decisions_and_forwarding() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::create_dir_all(directory.path().join("data")).unwrap();
    std::fs::write(directory.path().join("data/hmac_secret"), KEY).unwrap();
    std::fs::write(
        &policy_path,
        policy(permissions("127.0.0.1", &[])).to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn(origin(listener, seen.clone(), Arc::new(Notify::new())));
    let mut proxy = Proxy::start(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let bearer = format!("Bearer {TOKEN}");
    let other = format!("Bearer {OTHER}");
    let encoded = basic(TOKEN);
    let encoded_other = basic(OTHER);
    let combined = format!("{bearer}, {bearer}");
    let combined_basic = format!("{encoded}, {encoded_other}");
    let mixed = format!("{bearer}, {encoded}");
    let unsupported = format!("Other ordinary, {bearer}, {bearer}");
    let comma_key = format!("{TOKEN}, tail");
    let digest = format!("Digest opaque=\"{TOKEN}\", qop=auth");
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("Authorization", &bearer)],
        vec![("Authorization", &bearer), ("authorization", &bearer)],
        vec![("Authorization", &bearer), ("authorization", &other)],
        vec![
            ("Authorization", "Bearer ordinary"),
            ("authorization", &bearer),
        ],
        vec![("Authorization", ""), ("authorization", &bearer)],
        vec![("Authorization", &encoded), ("authorization", &encoded)],
        vec![
            ("Authorization", &encoded),
            ("authorization", &encoded_other),
        ],
        vec![("Authorization", &bearer), ("authorization", &encoded)],
        vec![("Authorization", &combined)],
        vec![("Authorization", &combined_basic)],
        vec![("Authorization", &mixed)],
        vec![("X-Api-Key", TOKEN), ("x-api-key", TOKEN)],
        vec![("X-Api-Key", TOKEN), ("x-api-key", OTHER)],
        vec![("X-Api-Key", "ordinary"), ("x-api-key", TOKEN)],
        vec![("X-Api-Key", &comma_key)],
        vec![("Authorization", &digest)],
    ];
    let request = |host: &str, method: &str, fields: &[(&str, &str)]| {
        let mut wire = format!(
            "{method} http://{host}:{port}/v2/owner/image/manifests/latest HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: 0\r\n"
        );
        for (name, value) in fields {
            wire.push_str(&format!("{name}: {value}\r\n"));
        }
        wire.push_str("\r\n");
        wire.into_bytes()
    };
    let catalogue_case = vec![
        ("Authorization", "Bearer catalogue-control"),
        ("authorization", bearer.as_str()),
    ];
    let unsupported_case = vec![("Authorization", unsupported.as_str())];
    for (index, fields) in cases
        .iter()
        .chain([&catalogue_case, &unsupported_case])
        .enumerate()
    {
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            raw_exchange(&socket, &request("127.0.0.1", "GET", fields)),
        )
        .await
        .unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 428"), "case {index}: status");
        assert_eq!(response_header(&reply, "x-blocked-by"), "credential-guard");
        assert!(
            seen.lock().unwrap().is_empty(),
            "case {index}: credential reached origin"
        );
    }
    let head = raw_exchange(&socket, &request("127.0.0.1", "HEAD", &cases[1])).await;
    assert!(head.starts_with(b"HTTP/1.1 428"));
    assert!(head.ends_with(b"\r\n\r\n"));
    let post = raw_exchange(&socket, &request("127.0.0.1", "POST", &cases[1])).await;
    assert!(post.starts_with(b"HTTP/1.1 428"));
    assert!(seen.lock().unwrap().is_empty());
    // Short values remain ordinary fields even when repeated.
    let ordinary = [
        ("Authorization", "Bearer ordinary"),
        ("authorization", "Bearer ordinary"),
    ];
    let reply = raw_exchange(&socket, &request("127.0.0.1", "GET", &ordinary)).await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    assert_eq!(seen.lock().unwrap().len(), 1);

    // An approval for one exact value permits all its supported field forms.
    // It does not approve another value, destination, or secret header.
    let comma_password = format!("{TOKEN},:tail");
    let comma_basic = basic(&comma_password);
    std::fs::write(
        &policy_path,
        policy(permissions(
            "127.0.0.1",
            &[TOKEN, OTHER, &comma_password, &comma_key, &digest],
        ))
        .to_string(),
    )
    .unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let mut allowed = cases.clone();
    allowed.push(vec![
        ("Authorization", &comma_basic),
        ("authorization", &comma_basic),
    ]);
    for (index, fields) in allowed.iter().enumerate() {
        let reply = raw_exchange(&socket, &request("127.0.0.1", "GET", fields)).await;
        assert!(
            reply.starts_with(b"HTTP/1.1 200"),
            "approved case {index}: status"
        );
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), index + 2);
        let lines = std::str::from_utf8(requests.last().unwrap())
            .unwrap()
            .split("\r\n");
        let forwarded = lines
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case(fields[0].0))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>();
        assert!(
            forwarded == fields.iter().map(|(_, value)| *value).collect::<Vec<_>>(),
            "approved case {index}: forwarded values"
        );
    }
    let before = seen.lock().unwrap().len();
    std::fs::write(
        &policy_path,
        policy(permissions("127.0.0.1", &[TOKEN, "catalogue-control"])).to_string(),
    )
    .unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    for (host, fields) in [
        ("127.0.0.1", cases[2].clone()),
        (
            "127.0.0.1",
            vec![("Authorization", bearer.as_str()), ("X-Api-Key", OTHER)],
        ),
        ("localhost", cases[1].clone()),
        (
            "127.0.0.1",
            vec![
                ("Authorization", "Bearer catalogue-control"),
                ("authorization", other.as_str()),
            ],
        ),
    ] {
        let reply = raw_exchange(&socket, &request(host, "GET", &fields)).await;
        assert!(reply.starts_with(b"HTTP/1.1 428"));
        assert_eq!(seen.lock().unwrap().len(), before);
    }
    let mut denied = permissions("127.0.0.1", &[TOKEN]);
    denied.insert(0, json!({"action":"credential:use", "resource":"127.0.0.1/*", "effect":"deny", "condition":{"credential":[fingerprint(TOKEN)]}}));
    std::fs::write(&policy_path, policy(denied).to_string()).unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let reply = raw_exchange(&socket, &request("127.0.0.1", "GET", &cases[1])).await;
    assert!(reply.starts_with(b"HTTP/1.1 403"));
    assert_eq!(seen.lock().unwrap().len(), before);
    // The rate-1 budget permits two immediate uses. Equal copies retain one
    // charge, leaving one more use before the existing budget refuses traffic.
    let mut budgeted = permissions("127.0.0.1", &[TOKEN]);
    budgeted[1]["effect"] = json!("budget");
    budgeted[1]["budget"] = json!(1);
    std::fs::write(&policy_path, policy(budgeted).to_string()).unwrap();
    proxy
        .reload(config(&directory, &policy_path, &socket, true))
        .await
        .unwrap();
    let reply = raw_exchange(&socket, &request("127.0.0.1", "GET", &cases[1])).await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    let reply = raw_exchange(&socket, &request("127.0.0.1", "GET", &cases[0])).await;
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    let reply = raw_exchange(&socket, &request("127.0.0.1", "GET", &cases[0])).await;
    assert!(reply.starts_with(b"HTTP/1.1 429"));
    assert_eq!(seen.lock().unwrap().len(), before + 2);
    proxy.shutdown().await;
    origin_task.abort();
    check_redaction(&directory);
}

#[tokio::test]
async fn repeated_h2_fields_and_head_refusals_stay_at_proxy() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let policy_path = directory.path().join("policy.json");
    std::fs::create_dir_all(directory.path().join("data")).unwrap();
    std::fs::write(directory.path().join("data/hmac_secret"), KEY).unwrap();
    std::fs::write(
        &policy_path,
        policy(permissions("localhost", &[])).to_string(),
    )
    .unwrap();
    let mut proxy_config = config(&directory, &policy_path, &socket, true);
    let tls = configure_h2_test_tls(&directory, &mut proxy_config, "localhost");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = format!("localhost:{}", listener.local_addr().unwrap().port());
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(h2_origin_tls(&tls)));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin_task = tokio::spawn({
        let seen = seen.clone();
        async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let stream = acceptor.accept(stream).await.unwrap();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let head = request.method() == "HEAD";
                            seen.lock().unwrap().push(request.headers().clone());
                            let body = if head {
                                Bytes::new()
                            } else {
                                Bytes::from_static(b"origin-ok")
                            };
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .header("content-length", "9")
                                    .body(Full::new(body))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });
    let mut proxy = Proxy::start(proxy_config.clone()).await.unwrap();
    let stream = connect_h2_through_proxy(&socket, &authority, "localhost", tls.proxy_ca).await;
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    let connection_task = tokio::spawn(connection);
    let bearer = format!("Bearer {TOKEN}");
    let encoded = basic(TOKEN);
    let combined = format!("{bearer}, {bearer}");
    let cases = [
        (
            "GET",
            "authorization",
            vec![bearer.as_str(), bearer.as_str()],
        ),
        (
            "GET",
            "authorization",
            vec![encoded.as_str(), encoded.as_str()],
        ),
        ("GET", "authorization", vec![combined.as_str()]),
        ("GET", "x-api-key", vec![TOKEN, TOKEN]),
        ("HEAD", "authorization", vec![bearer.as_str()]),
    ];
    for (method, name, values) in &cases {
        let mut request = Request::builder()
            .method(*method)
            .uri(format!("https://{authority}/v2/a/a-other/manifests/0"));
        for value in values {
            request = request.header(*name, *value);
        }
        let reply = sender
            .send_request(request.body(Empty::<Bytes>::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(reply.status(), 428);
        assert_eq!(reply.headers()["x-blocked-by"], "credential-guard");
        assert_eq!(reply.headers()["content-type"], "application/json");
        assert!(reply.headers().contains_key("x-safeyolo-request-id"));
        if *method == "HEAD" {
            assert!(
                reply.body().is_end_stream(),
                "HEAD refusal has a body stream"
            );
        }
        let body = reply.collect().await.unwrap().to_bytes();
        if *method == "HEAD" {
            assert!(body.is_empty());
        } else {
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["error"],
                "Require Approval"
            );
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "refused credential reached origin"
        );
    }
    std::fs::write(
        &policy_path,
        policy(permissions("localhost", &[TOKEN])).to_string(),
    )
    .unwrap();
    proxy.reload(proxy_config.clone()).await.unwrap();
    for method in ["HEAD", "GET"] {
        let request = Request::builder()
            .method(method)
            .uri(format!("https://{authority}/allowed"))
            .header("authorization", &bearer)
            .header("authorization", &bearer)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let reply = sender.send_request(request).await.unwrap();
        assert_eq!(reply.status(), 200);
        assert_eq!(reply.headers()["content-length"], "9");
        let body = reply.collect().await.unwrap().to_bytes();
        assert_eq!(
            body.as_ref(),
            if method == "HEAD" {
                b"".as_slice()
            } else {
                b"origin-ok".as_slice()
            }
        );
    }
    assert_eq!(seen.lock().unwrap().len(), 2);
    for fields in seen.lock().unwrap().iter() {
        assert_eq!(
            fields
                .get_all("authorization")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            [&bearer, &bearer]
        );
    }
    let mut denied = permissions("localhost", &[TOKEN]);
    denied.insert(0, json!({"action":"credential:use", "resource":"localhost/*", "effect":"deny", "condition":{"credential":[fingerprint(TOKEN)]}}));
    std::fs::write(&policy_path, policy(denied).to_string()).unwrap();
    proxy.reload(proxy_config).await.unwrap();
    let request = Request::builder()
        .method("HEAD")
        .uri(format!("https://{authority}/denied"))
        .header("authorization", &bearer)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let reply = sender.send_request(request).await.unwrap();
    assert_eq!(reply.status(), 403);
    assert_eq!(reply.headers()["x-blocked-by"], "credential-guard");
    assert!(reply.body().is_end_stream());
    assert!(reply.collect().await.unwrap().to_bytes().is_empty());
    assert_eq!(seen.lock().unwrap().len(), 2);
    drop(sender);
    connection_task.abort();
    proxy.shutdown().await;
    origin_task.abort();
    check_redaction(&directory);
    let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
    let decisions = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| {
            event["event"] == "security.credential_guard" && event["details"]["method"] == "HEAD"
        })
        .map(|event| event["decision"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        decisions,
        json!(["require_approval", "allow", "deny"])
            .as_array()
            .unwrap()
            .to_vec()
    );
}
