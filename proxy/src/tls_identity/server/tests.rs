use super::*;
use crate::{
    Proxy,
    connection_events::tests::{assert_pairs, config, connections, head, records},
};
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

fn body(cipher: u16, kinds: &[u16], retry: bool) -> Vec<u8> {
    let mut bytes = vec![3, 3];
    bytes.extend(if retry { RETRY_RANDOM } else { [0x58; 32] });
    bytes.push(0);
    bytes.extend(cipher.to_be_bytes());
    bytes.push(0);
    if !kinds.is_empty() {
        bytes.extend(((kinds.len() * 4) as u16).to_be_bytes());
        for kind in kinds {
            bytes.extend(kind.to_be_bytes());
            bytes.extend([0, 0]);
        }
    }
    bytes
}

fn wire(body: &[u8], fragment: usize) -> Vec<u8> {
    let mut message = (body.len() as u32).to_be_bytes().to_vec();
    message[0] = 2;
    message.extend(body);
    let mut bytes = Vec::new();
    for chunk in message.chunks(fragment) {
        bytes.extend([22, 3, 3]);
        bytes.extend((chunk.len() as u16).to_be_bytes());
        bytes.extend(chunk);
    }
    bytes
}

#[test]
fn ordered_wire_vectors_fragmentation_and_summary_limits() {
    // Independently computed with Python hashlib.md5 over these decimal tuples.
    for (cipher, kinds, expected) in [
        (4865, vec![43, 51], "f4febc55ea12b31ae17cfb7e614afda8"),
        (4865, vec![51, 43], "eb1d94daa7e0344597e756a1fb6e7054"),
        (47, vec![], "5397c414a9ebeaff1bf18b70ca22eaa0"),
        (4865, vec![2570, 43, 51], "cb9736be102c470e595c61b5f74d967a"),
    ] {
        for record_split in [1, 2, 3, 4, 5, 17, 16384] {
            let bytes = wire(&body(cipher, &kinds, false), record_split);
            for read_split in [1, 2, 4, 5, 19, usize::MAX] {
                let mut capture = Capture::default();
                for read in bytes.chunks(read_split) {
                    capture.feed(read);
                }
                assert_eq!(capture.observation.status, Status::Complete);
                let hello = capture.observation.hello.unwrap();
                assert_eq!(hello.legacy_version, 771);
                assert_eq!(hello.cipher_suite, cipher);
                assert_eq!(hello.extension_types, kinds);
                assert_eq!(hello.ja3s, expected);
                assert!(hello.valid());
            }
        }
    }
    let kinds = (0..100).collect::<Vec<_>>();
    let (hello, _) = parse(&body(4865, &kinds, false)).unwrap();
    assert_eq!(hello.extension_types.len(), 64);
    assert_eq!(hello.extension_count, 100);
    assert!(hello.truncated && hello.valid());
    assert_eq!(
        hello.ja3s,
        independent_md5(&format!(
            "771,4865,{}",
            (0..100)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join("-")
        ))
    );
}

#[test]
fn retry_then_final_and_coalesced_messages() {
    let retry = body(4865, &[43, 51], true);
    let final_hello = body(4865, &[51, 43], false);
    for ccs in [false, true] {
        let mut bytes = wire(&retry, 7);
        if ccs {
            bytes.extend([20, 3, 3, 0, 1, 1]);
        }
        bytes.extend(wire(&final_hello, 13));
        // Later encrypted/application bytes must not replace the final hello.
        bytes.extend([23, 3, 3, 0, 2, 0, 0]);
        for size in [1, 5, 21, usize::MAX] {
            let mut capture = Capture::default();
            for read in bytes.chunks(size) {
                capture.feed(read);
            }
            assert_eq!(capture.observation.status, Status::Complete);
            assert_eq!(
                capture.observation.hello_retry_request.unwrap().ja3s,
                "f4febc55ea12b31ae17cfb7e614afda8"
            );
            assert_eq!(
                capture.observation.hello.unwrap().ja3s,
                "eb1d94daa7e0344597e756a1fb6e7054"
            );
        }
    }
    // Both handshake messages may share one record and one read.
    let mut messages = vec![2, 0, 0, retry.len() as u8];
    messages.extend(&retry);
    messages.extend([2, 0, 0, final_hello.len() as u8]);
    messages.extend(&final_hello);
    let mut bytes = vec![22, 3, 3];
    bytes.extend((messages.len() as u16).to_be_bytes());
    bytes.extend(messages);
    let mut capture = Capture::default();
    capture.feed(&bytes);
    assert_eq!(capture.observation.status, Status::Complete);
    assert!(capture.observation.valid());
}

#[test]
fn incomplete_invalid_opaque_and_hostile_inputs_do_not_fabricate_a_hello() {
    let bytes = wire(&body(4865, &[43, 51], false), 9);
    for end in 0..bytes.len() {
        let mut capture = Capture::default();
        capture.feed(&bytes[..end]);
        assert_eq!(capture.observation.status, Status::Incomplete);
        assert!(capture.observation.hello.is_none() && capture.observation.valid());
    }
    for (bytes, status) in [
        (wire(&body(4865, &[43, 43], false), 16384), Status::Invalid),
        (
            vec![22, 3, 3, 0, 4, 2, 255, 255, 255],
            Status::LimitExceeded,
        ),
        (vec![22, 3, 3, 0, 4, 1, 0, 0, 1], Status::Invalid),
        (vec![22, 3, 3, 0, 4, 2, 0, 0, 0], Status::Invalid),
        (vec![23, 3, 3, 0, 2, 0, 0], Status::Unavailable),
        (b"HTTP/1.1".to_vec(), Status::Unavailable),
        (vec![22, 3, 3, 255, 255], Status::Invalid),
    ] {
        let mut capture = Capture::default();
        capture.feed(&bytes);
        capture.feed(&vec![0; 1024 * 1024]);
        assert_eq!(capture.observation.status, status);
        assert!(capture.observation.hello.is_none() && capture.observation.valid());
        assert!(capture.hello.len() <= HELLO_LIMIT && capture.header.len() <= 5);
    }
    let retry = wire(&body(4865, &[43], true), 7);
    let mut capture = Capture::default();
    capture.feed(&retry);
    assert_eq!(capture.observation.status, Status::Incomplete);
    assert!(capture.observation.hello_retry_request.is_some());
    capture.feed(&retry);
    assert_eq!(capture.observation.status, Status::Invalid);
    let mut malformed = body(4865, &[43], false);
    malformed.push(0);
    assert!(parse(&malformed).is_none());
    malformed = body(4865, &[43], false);
    malformed.pop();
    assert!(parse(&malformed).is_none());
}

type Wire = Arc<Mutex<Vec<u8>>>;
pub(in crate::tls_identity) struct Tap<S> {
    stream: S,
    bytes: Wire,
}
pub(in crate::tls_identity) fn tap<S>(stream: S) -> (Tap<S>, Wire) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    (
        Tap {
            stream,
            bytes: bytes.clone(),
        },
        bytes,
    )
}
impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            self.bytes.lock().unwrap().extend_from_slice(&bytes[..n]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn independent_md5(text: &str) -> String {
    let mut child = std::process::Command::new("openssl")
        .args(["dgst", "-md5"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_owned()
}

/// Independent byte oracle: concatenate plaintext handshake records, walk their
/// declared lengths and read the ServerHello fields by offsets. OpenSSL supplies
/// MD5. It never calls the production parser, framing code or MD5 implementation.
pub(in crate::tls_identity) fn assert_wire(observation: &serde_json::Value, wire: &Wire) {
    let bytes = wire.lock().unwrap();
    let mut handshake = Vec::new();
    let mut offset = 0;
    while offset + 5 <= bytes.len() {
        let n = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
        let data = &bytes[offset + 5..offset + 5 + n];
        if bytes[offset] == 22 {
            handshake.extend_from_slice(data);
        }
        offset += 5 + n;
    }
    let mut offset = 0;
    let mut found = 0;
    while offset + 4 <= handshake.len() {
        let n = u32::from_be_bytes([
            0,
            handshake[offset + 1],
            handshake[offset + 2],
            handshake[offset + 3],
        ]) as usize;
        let data = &handshake[offset + 4..offset + 4 + n];
        if handshake[offset] == 2 {
            let version = u16::from_be_bytes([data[0], data[1]]);
            let cipher_pos = 35 + data[34] as usize;
            let cipher = u16::from_be_bytes([data[cipher_pos], data[cipher_pos + 1]]);
            let mut kinds = Vec::new();
            let mut ext = cipher_pos + 5;
            while ext < data.len() {
                kinds.push(u16::from_be_bytes([data[ext], data[ext + 1]]));
                ext += 4 + u16::from_be_bytes([data[ext + 2], data[ext + 3]]) as usize;
            }
            assert_eq!(ext, data.len());
            let is_retry = &data[2..34]
                == ring::digest::digest(&ring::digest::SHA256, b"HelloRetryRequest").as_ref();
            let hello = &observation[if is_retry {
                "hello_retry_request"
            } else {
                "hello"
            }];
            assert_eq!(hello["legacy_version"], version);
            assert_eq!(hello["cipher_suite"], cipher);
            assert_eq!(hello["extension_types"], serde_json::json!(kinds));
            let text = format!(
                "{version},{cipher},{}",
                kinds
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join("-")
            );
            assert_eq!(hello["ja3s"], independent_md5(&text));
            found += 1;
            // TLS 1.2's later Finished record is encrypted even though its
            // content type remains handshake. Only the plaintext hellos are
            // the oracle's evidence.
            if !is_retry {
                break;
            }
        }
        offset += 4 + n;
    }
    assert_eq!(
        found,
        if observation["hello_retry_request"].is_object() {
            2
        } else {
            1
        }
    );
    assert_eq!(observation["status"], "complete");
}

#[tokio::test]
async fn production_origin_tls12_tls13_full_resumed_and_retry_match_wire() {
    for (version, retry) in [
        (&rustls::version::TLS12, false),
        (&rustls::version::TLS13, false),
        (&rustls::version::TLS13, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let (origin, address) = crate::test_owned_endpoint::bind().await;
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![address.ip().to_string()]).unwrap();
        let mut provider = rustls::crypto::ring::default_provider();
        if retry {
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        }
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = Arc::new(tls);
        let trust = directory.path().join("trust.pem");
        std::fs::write(&trust, cert.pem()).unwrap();
        let mut configuration = config(directory.path());
        configuration.upstream_ca_file = Some(trust);
        let (pem, _) = crate::tls::CertificateAuthority::create().unwrap();
        let ca = directory.path().join("interception.pem");
        std::fs::write(&ca, pem).unwrap();
        configuration.tls_ca_file = Some(ca);
        let peer = tokio::spawn(async move {
            let mut wires = Vec::new();
            for _ in 0..2 {
                let (socket, _) = origin.accept().await.unwrap();
                let (socket, wire) = tap(socket);
                let mut stream = tokio_rustls::TlsAcceptor::from(tls.clone())
                    .accept(socket)
                    .await
                    .unwrap();
                assert!(head(&mut stream).await.starts_with(b"GET /path HTTP/1.1"));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
                wires.push(wire);
            }
            wires
        });
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        for _ in 0..2 {
            let mut client = UnixStream::connect(directory.path().join("alice.sock"))
                .await
                .unwrap();
            client.write_all(format!("GET https://{address}/path HTTP/1.1\r\nHost: forged.invalid\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(
                reply.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&reply)
            );
        }
        let wires = timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap();
        proxy.shutdown().await;
        let rows = records(&runtime, directory.path());
        assert_pairs(&rows);
        let servers = connections(&rows, "proxy_to_upstream", "terminal");
        assert_eq!(servers.len(), 2);
        for (i, server) in servers.iter().enumerate() {
            assert_wire(&server["tls_server_hello"], &wires[i]);
            assert_eq!(server["tls_server_hello"]["hello"]["legacy_version"], 771);
            if i == 0 {
                assert_eq!(
                    server["tls_server_hello"]["hello_retry_request"].is_object(),
                    retry
                );
            }
            let session = &server["tls_sessions"][0];
            assert_eq!(
                session["version"],
                if version == &rustls::version::TLS12 {
                    "TLSv1_2"
                } else {
                    "TLSv1_3"
                }
            );
            assert_eq!(
                session["handshake_kind"],
                if i == 1 {
                    "Resumed"
                } else if retry {
                    "FullWithHelloRetryRequest"
                } else {
                    "Full"
                }
            );
            assert!(session["leaf_certificate"].is_object());
            assert_eq!(server["route"], "direct");
            assert_eq!(server["resolved_origin_peer"], address.to_string());
            assert!(rows.iter().any(|row| row["event"] == "traffic.flow"
                && row["details"]["server_connection_id"] == server["connection_id"]));
            let flow = rows
                .iter()
                .find(|row| {
                    row["event"] == "traffic.flow"
                        && row["details"]["server_connection_id"] == server["connection_id"]
                })
                .unwrap();
            // Exercise the same retained reader used by logs connection/request.
            for (kind, id) in [
                ("connection", server["connection_id"].as_str().unwrap()),
                ("request", flow["request_id"].as_str().unwrap()),
            ] {
                let query = crate::audit::pivot::Query {
                    instance: flow["details"]["instance_id"].as_str().unwrap(),
                    runtime: flow["details"]["runtime_id"].as_str().unwrap(),
                    kind,
                    id,
                    agent: Some("alice"),
                    sandbox_run: None,
                    lines: 1000,
                };
                let path = directory.path().join("audit.jsonl");
                let tail = crate::audit::local_tail(&path, query.agent, query.lines).unwrap();
                let view = crate::audit::pivot::read(&[path], vec![tail], false, &query).unwrap();
                assert!(view["records"].as_array().unwrap().iter().any(|entry| {
                    let row = &entry["record"];
                    row["event_id"].is_string()
                        && row["details"]["connection_id"] == server["connection_id"]
                        && row["details"]["tls_server_hello"] == server["tls_server_hello"]
                }));
            }
        }
        assert!(!directory.path().join("unused.sqlite3").exists());
    }
}

#[tokio::test]
async fn production_failed_and_incomplete_handshakes_preserve_only_observed_metadata() {
    let final_hello = wire(&body(49195, &[], false), 11);
    let retry = wire(&body(4865, &[43], true), 11);
    for (bytes, expected, saw_retry) in [
        (final_hello, "complete", false),
        (vec![22, 3, 3, 0, 10, 2, 0, 0, 40, 3], "incomplete", false),
        (b"HTTP/1.1 500\r\n\r\n".to_vec(), "unavailable", false),
        (wire(&body(4865, &[43, 43], false), 13), "invalid", false),
        (retry, "incomplete", true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let (origin, address) = crate::test_owned_endpoint::bind().await;
        let peer = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            for chunk in bytes.chunks(3) {
                socket.write_all(chunk).await.unwrap();
            }
            socket.shutdown().await.unwrap();
        });
        let mut configuration = config(directory.path());
        let (pem, _) = crate::tls::CertificateAuthority::create().unwrap();
        let ca = directory.path().join("interception.pem");
        std::fs::write(&ca, pem).unwrap();
        configuration.tls_ca_file = Some(ca);
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        client.write_all(format!("GET https://{address}/path HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 502"));
        drop(client);
        timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap();
        proxy.shutdown().await;
        let rows = records(&runtime, directory.path());
        assert_pairs(&rows);
        let servers = connections(&rows, "proxy_to_upstream", "terminal");
        assert_eq!(servers.len(), 1);
        let server = &servers[0];
        assert_eq!(server["state"], "failed");
        assert_eq!(server["error"], "origin_tls_failed");
        assert!(server["tls_sessions"].is_null());
        let hello = &server["tls_server_hello"];
        assert_eq!(hello["status"], expected);
        assert_eq!(hello["hello_retry_request"].is_object(), saw_retry);
        assert_eq!(hello["hello"].is_object(), expected == "complete");
        assert!(
            rows.iter()
                .filter(|row| row["event"] == "network.connection")
                .all(|row| !row.to_string().contains("raw_bytes"))
        );
    }
}
