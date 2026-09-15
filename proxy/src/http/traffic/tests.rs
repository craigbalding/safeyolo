//! Owned UDS/origin traffic checks. No TestContext claim or configured targets
//! participate, so these exercise the ordinary RequestLogger hook lifetime.
use crate::{Config, Proxy, Runtime};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::{convert::Infallible, io::Write, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);
const STREAMED_SIZE: usize = 10 * 1024 * 1024 + 1;

fn config(directory: &Path, quiet: bool) -> Config {
    let policy = directory.join("policy.json");
    std::fs::write(
        &policy,
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
            "addons":{"request_logger":{"quiet_hosts":{"hosts":if quiet {vec!["logical.invalid"]} else {vec![]}}}}
        }).to_string(),
    ).unwrap();
    serde_json::from_value(json!({
        "listeners":[{"agent_id":"alice","socket_path":directory.join("alice.sock")},
                     {"agent_id":"bob","socket_path":directory.join("bob.sock")}],
        "policy_file":policy,"readiness_file":directory.join("ready"),
        "audit_log_path":directory.join("audit.jsonl"),"event_log":directory.join("events"),
        "flow_store_enabled":false,"flow_store_db_path":directory.join("flows.sqlite3"),
        "circuit_breaker_enabled":false,"circuit_state_file":""
    }))
    .unwrap()
}
fn stats(runtime: &Runtime) -> Value {
    runtime
        .request_logger
        .stats()
        .unwrap()
        .document()
        .json()
        .unwrap()
}
fn expected_stats(requests: u64, quieted: u64, responses: u64) -> Value {
    json!({"requests_total":requests,"requests_quieted":quieted,"responses_total":responses,"blocks_total":0})
}
fn records(directory: &Path) -> Vec<Value> {
    std::fs::read_to_string(directory.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn cleanup(directory: &Path) {
    for name in ["alice.sock", "bob.sock", "ready"] {
        assert!(!directory.join(name).exists(), "left behind {name}");
    }
}
fn owned_egress(directory: &Path, port: u16, expected: usize) {
    let events: Vec<Value> = std::fs::read_to_string(directory.join("events"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let egress: Vec<_> = events
        .iter()
        .filter(|row| row["event"] == "proxy.egress")
        .collect();
    assert_eq!(egress.len(), expected);
    assert!(
        egress
            .iter()
            .all(|row| row["host"] == "127.0.0.2" && row["port"] == port)
    );
    assert!(
        !events
            .iter()
            .any(|row| row["event"] == "ops.test_context.request_applied")
    );
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
async fn listener() -> TcpListener {
    TcpListener::bind((std::net::Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap()
}
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    timeout(LIMIT, async {
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    head
}
async fn origin_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let head = read_head(stream).await;
    let length = std::str::from_utf8(&head)
        .unwrap()
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    timeout(LIMIT, stream.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    body
}
async fn start_request(
    socket: &Path,
    port: u16,
    route: &str,
    length: usize,
    encoding: &str,
) -> UnixStream {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(format!(
        "POST http://127.0.0.2:{port}{route} HTTP/1.1\r\nHost: logical.invalid:{port}\r\nConnection: close\r\nContent-Encoding: {encoding}\r\nContent-Length: {length}\r\n\r\n"
    ).as_bytes()).await.unwrap();
    stream
}
async fn send(socket: &Path, port: u16, route: &str, body: &[u8], encoding: &str) -> Vec<u8> {
    let mut stream = start_request(socket, port, route, body.len(), encoding).await;
    stream.write_all(body).await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    reply
}
fn attribution(agent: &str) -> Value {
    json!({"evidence_owner":agent,"trusted_transport_identity":agent,"initiator":"unknown",
        "attribution_status":"resolved","attribution_provenance":{"transport_source":"uds","uds_agent":agent}})
}
// Compare complete source-shaped values and insertion order. Only live clock,
// elapsed duration and generated request ID are taken from the observed event.
fn check_event(
    row: &Value,
    agent: &str,
    host: &str,
    path: &str,
    response: bool,
    size: usize,
    started: bool,
) {
    let timestamp = row["ts"].as_str().unwrap();
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).unwrap();
    let mut expected = json!({"schema_version":1,"ts":timestamp,
        "event":if response {"traffic.response"} else {"traffic.request"},
        "kind":"traffic","severity":"low",
        "summary":format!("{} {host}{path}",if response {"200"} else {"POST"})});
    if started {
        let id = row["request_id"].as_str().unwrap();
        assert!(id.starts_with("req-") && id.len() == 36);
        expected["request_id"] = json!(id);
    } else {
        assert!(row.get("request_id").is_none());
    }
    expected["agent"] = json!(agent);
    expected["addon"] = json!("request-logger");
    expected["host"] = json!(host);
    expected["details"] = if response {
        let ms = if started {
            assert!(row["details"]["ms"].as_f64().unwrap().is_finite());
            row["details"]["ms"].clone()
        } else {
            Value::Null
        };
        json!({"path":path,"status":200,"size":size,"ms":ms,"attribution":attribution(agent)})
    } else {
        json!({"method":"POST","path":path,"size":size,"client":null,"attribution":attribution(agent)})
    };
    assert_eq!(row, &expected);
    assert_eq!(
        serde_json::to_string(row).unwrap(),
        serde_json::to_string(&expected).unwrap()
    );
}

#[tokio::test]
async fn ordinary_h1_without_test_context_logs_plain_and_decoded_gzip() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path(), false)).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    assert!(runtime.policy.is_some() && runtime.config.temporary_policy_socket.is_none());
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        for compressed in [false, true] {
            let (mut stream, _) = timeout(LIMIT, origin.accept()).await.unwrap().unwrap();
            let body = origin_request(&mut stream).await;
            assert_eq!(
                body,
                if compressed {
                    gzip(b"request body")
                } else {
                    b"request body".to_vec()
                }
            );
            let body = if compressed {
                gzip(b"response body")
            } else {
                b"response body".to_vec()
            };
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: {}\r\nConnection: close\r\n\r\n",body.len(),if compressed {"gzip"} else {"identity"}).as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    for (agent, compressed) in [("alice", false), ("bob", true)] {
        let body = if compressed {
            gzip(b"request body")
        } else {
            b"request body".to_vec()
        };
        let reply = send(
            &directory.path().join(format!("{agent}.sock")),
            port,
            "/plain;parameter?query=private",
            &body,
            if compressed { "gzip" } else { "identity" },
        )
        .await;
        assert!(reply.starts_with(b"HTTP/1.1 200"));
    }
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(stats(&runtime), expected_stats(2, 0, 2));
    let rows = records(directory.path());
    assert_eq!(rows.len(), 4);
    for (i, agent) in ["alice", "bob"].iter().enumerate() {
        check_event(
            &rows[i * 2],
            agent,
            "logical.invalid",
            "/plain",
            false,
            12,
            true,
        );
        check_event(
            &rows[i * 2 + 1],
            agent,
            "logical.invalid",
            "/plain",
            true,
            13,
            true,
        );
        assert_eq!(rows[i * 2]["request_id"], rows[i * 2 + 1]["request_id"]);
    }
    owned_egress(directory.path(), port, 2);
}

#[tokio::test]
async fn quiet_invalid_coding_is_never_decoded_on_either_leg() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path(), true)).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        assert_eq!(origin_request(&mut stream).await, b"invalid gzip");
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\ninvalid gzip").await.unwrap();
    });
    let reply = send(
        &directory.path().join("alice.sock"),
        port,
        "/quiet",
        b"invalid gzip",
        "gzip",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200") && reply.ends_with(b"invalid gzip"));
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(stats(&runtime), expected_stats(1, 1, 0));
    assert!(records(directory.path()).is_empty());
    owned_egress(directory.path(), port, 1);
}

#[tokio::test]
async fn streamed_upload_and_sse_response_use_absent_content_size_zero() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path(), false)).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let body = origin_request(&mut stream).await;
        assert_eq!(body.len(), STREAMED_SIZE);
        assert!(body.iter().all(|byte| *byte == b'x'));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nContent-Length: 12\r\nConnection: close\r\n\r\ninvalid gzip").await.unwrap();
    });
    let body = vec![b'x'; STREAMED_SIZE];
    let reply = send(
        &directory.path().join("alice.sock"),
        port,
        "/streamed",
        &body,
        "gzip",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 200") && reply.ends_with(b"invalid gzip"));
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(stats(&runtime), expected_stats(1, 0, 1));
    let rows = records(directory.path());
    assert_eq!(rows.len(), 2);
    check_event(
        &rows[0],
        "alice",
        "logical.invalid",
        "/streamed",
        false,
        0,
        true,
    );
    check_event(
        &rows[1],
        "alice",
        "logical.invalid",
        "/streamed",
        true,
        0,
        true,
    );
    owned_egress(directory.path(), port, 1);
}

#[tokio::test]
async fn early_response_before_upload_eom_has_no_request_id_or_start_time() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path(), false)).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let _ = read_head(&mut stream).await;
        let mut first = [0; 5];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"first");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nearly")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut client = start_request(
        &directory.path().join("alice.sock"),
        port,
        "/early",
        STREAMED_SIZE,
        "identity",
    )
    .await;
    client.write_all(b"first").await.unwrap();
    let head = read_head(&mut client).await;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 5];
    timeout(LIMIT, client.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&body, b"early");
    drop(client);
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(stats(&runtime), expected_stats(0, 0, 1));
    let rows = records(directory.path());
    assert_eq!(rows.len(), 1);
    check_event(
        &rows[0],
        "alice",
        "logical.invalid",
        "/early",
        true,
        5,
        false,
    );
    owned_egress(directory.path(), port, 1);
}

#[tokio::test]
async fn canceled_response_and_real_dial_error_never_fabricate_response_events() {
    let directory = tempfile::tempdir().unwrap();
    let proxy = Proxy::start(config(directory.path(), false)).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        assert_eq!(origin_request(&mut stream).await, b"request body");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nfirst")
            .await
            .unwrap();
        let mut rest = Vec::new();
        timeout(LIMIT, stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.is_empty());
    });
    let mut client = start_request(
        &directory.path().join("alice.sock"),
        port,
        "/cancel",
        12,
        "identity",
    )
    .await;
    client.write_all(b"request body").await.unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let mut first = [0; 5];
    client.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"first");
    drop(client);
    timeout(LIMIT, peer).await.unwrap().unwrap();
    let reply = send(
        &directory.path().join("bob.sock"),
        port,
        "/refused",
        b"request body",
        "identity",
    )
    .await;
    assert!(reply.starts_with(b"HTTP/1.1 502"));
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(stats(&runtime), expected_stats(2, 0, 0));
    let rows = records(directory.path());
    assert_eq!(rows.len(), 2);
    check_event(
        &rows[0],
        "alice",
        "logical.invalid",
        "/cancel",
        false,
        12,
        true,
    );
    check_event(
        &rows[1],
        "bob",
        "logical.invalid",
        "/refused",
        false,
        12,
        true,
    );
    // The development egress event includes the refused owned dial attempt.
    owned_egress(directory.path(), port, 2);
}

#[tokio::test]
async fn ordinary_h2_inside_owned_tls_logs_inner_exchange_only() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(directory.path(), false);
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&key).unwrap();
    let ca_path = directory.path().join("interception-ca.pem");
    std::fs::write(&ca_path, format!("{}{}", key.serialize_pem(), ca.pem())).unwrap();
    configuration.tls_ca_file = Some(ca_path);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.2".into()]).unwrap();
    let upstream_path = directory.path().join("upstream-ca.pem");
    std::fs::write(&upstream_path, cert.pem()).unwrap();
    configuration.upstream_ca_file = Some(upstream_path);
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let origin = listener().await;
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(request.version(), hyper::Version::HTTP_2);
                    assert_eq!(
                        request.into_body().collect().await.unwrap().to_bytes(),
                        Bytes::from_static(b"request body")
                    );
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"response body",
                    ))))
                }),
            )
            .await
            .unwrap();
    });
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client
        .write_all(
            format!("CONNECT 127.0.0.2:{port} HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let client = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(
            rustls::pki_types::ServerName::try_from("127.0.0.2").unwrap(),
            client,
        )
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://127.0.0.2:{port}/h2?private=query"))
        .body(Full::new(Bytes::from_static(b"request body")))
        .unwrap();
    let reply = timeout(LIMIT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(
        reply.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"response body")
    );
    drop(sender);
    timeout(LIMIT, driver).await.unwrap().unwrap().unwrap();
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    cleanup(directory.path());
    assert_eq!(stats(&runtime), expected_stats(1, 0, 1));
    let rows = records(directory.path());
    assert_eq!(rows.len(), 2);
    check_event(&rows[0], "alice", "127.0.0.2", "/h2", false, 12, true);
    check_event(&rows[1], "alice", "127.0.0.2", "/h2", true, 13, true);
    assert_eq!(rows[0]["request_id"], rows[1]["request_id"]);
    owned_egress(directory.path(), port, 1);
}
