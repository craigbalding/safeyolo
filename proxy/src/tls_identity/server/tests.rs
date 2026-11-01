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
    let extensions = kinds
        .iter()
        .map(|kind| {
            (
                *kind,
                match kind {
                    43 => &[3, 4][..],
                    16 => &[0, 3, 2, b'h', b'2'][..],
                    _ => &[][..],
                },
            )
        })
        .collect::<Vec<_>>();
    body_with_extensions(cipher, &extensions, retry)
}

fn body_with_extensions(cipher: u16, extensions: &[(u16, &[u8])], retry: bool) -> Vec<u8> {
    let mut bytes = vec![3, 3];
    bytes.extend(if retry { RETRY_RANDOM } else { [0x58; 32] });
    bytes.push(0);
    bytes.extend(cipher.to_be_bytes());
    bytes.push(0);
    if !extensions.is_empty() {
        let mut vector = Vec::new();
        for (kind, value) in extensions {
            vector.extend(kind.to_be_bytes());
            vector.extend((value.len() as u16).to_be_bytes());
            vector.extend_from_slice(value);
        }
        bytes.extend((vector.len() as u16).to_be_bytes());
        bytes.extend(vector);
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
        let extension_text = kinds
            .iter()
            .map(|v| format!("{v:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let hash = if kinds.is_empty() {
            "000000000000".into()
        } else {
            independent_digest(&extension_text, "-sha256")[..12].to_owned()
        };
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
                assert_eq!(
                    hello.ja4s,
                    format!(
                        "t{}{:02}00_{cipher:04x}_{hash}",
                        if kinds.contains(&43) { "13" } else { "12" },
                        kinds.len()
                    )
                );
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
        independent_digest(
            &format!(
                "771,4865,{}",
                (0..100)
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("-")
            ),
            "-md5"
        )
    );
    assert_eq!(
        hello.ja4s,
        format!(
            "t1399h2_1301_{}",
            &independent_digest(
                &(0..100)
                    .map(|v| format!("{v:04x}"))
                    .collect::<Vec<_>>()
                    .join(","),
                "-sha256"
            )[..12]
        )
    );
}

#[test]
fn ja4s_published_vector_and_selected_version_alpn() {
    // FoxIO rust/ja4/src/tls.rs::test_server_stats_into_out at c6469a7b.
    // The same vector is displayed in technical_details/JA4S.png.
    let (hello, _) = parse(&body(0xc030, &[5, 23, 0xff01, 0], false)).unwrap();
    assert_eq!(hello.ja4s, "t120400_c030_4e8089b08790");
    assert_eq!(hello.supported_version, None);
    assert_eq!(hello.alpn, None);
    assert!(hello.valid());
    for (version, code) in [
        (0x0304_u16, "13"),
        (0x0303, "12"),
        (0x0302, "11"),
        (0x0301, "10"),
        (0x0300, "s3"),
        (2, "s2"),
        (0x7f1c, "00"),
    ] {
        for (protocol, expected) in [
            (b"h2".as_slice(), "h2"),
            (b"http/1.1", "h1"),
            (b"x", "xx"),
            (&[0xff, b'x'], "9x"),
            (&[b'x', 0xff], "x9"),
            (b"/", "//"),
            (&[0], "\0\0"),
        ] {
            let mut alpn = ((protocol.len() + 1) as u16).to_be_bytes().to_vec();
            alpn.push(protocol.len() as u8);
            alpn.extend_from_slice(protocol);
            let (hello, _) = parse(&body_with_extensions(
                4865,
                &[(43, &version.to_be_bytes()), (16, &alpn)],
                false,
            ))
            .unwrap();
            assert_eq!(hello.supported_version, Some(version));
            assert_eq!(hello.alpn, Some(alpn_display(protocol)));
            assert_eq!(
                hello.ja4s,
                format!(
                    "t{code}02{expected}_1301_{}",
                    &independent_digest("002b,0010", "-sha256")[..12]
                )
            );
            assert!(hello.valid());
        }
    }
    let mut alpn = vec![1, 0, 255];
    alpn.extend([255; 255]);
    let (hello, _) = parse(&body_with_extensions(4865, &[(16, &alpn)], false)).unwrap();
    assert_eq!(hello.alpn.as_ref().unwrap().len(), 1020);
    assert!(hello.ja4s.starts_with("t120199_") && hello.valid());
}

#[test]
fn malformed_ja4s_inputs_cannot_emit_a_fingerprint() {
    for (kind, value) in [
        (43, vec![]),
        (43, vec![3]),
        (43, vec![3, 4, 0]),
        (16, vec![]),
        (16, vec![0, 0]),
        (16, vec![0, 1, 0]),
        (16, vec![0, 3, 2, b'h']),
        (16, vec![0, 2, 1, b'h', 0]),
        (16, vec![0, 4, 1, b'h', 1, b'2']),
    ] {
        let mut capture = Capture::default();
        for bytes in wire(&body_with_extensions(4865, &[(kind, &value)], false), 3).chunks(2) {
            capture.feed(bytes);
        }
        assert_eq!(
            capture.observation.status,
            Status::Invalid,
            "{kind}: {value:?}"
        );
        assert!(capture.observation.hello.is_none() && capture.observation.valid());
    }
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

fn independent_digest(text: &str, algorithm: &str) -> String {
    let mut child = std::process::Command::new("openssl")
        .args(["dgst", algorithm])
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
/// MD5 and SHA-256. It never calls the production parser, framing or hash helpers.
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
            let mut selected_version = None;
            let mut selected_alpn = None;
            let mut ext = cipher_pos + 5;
            while ext < data.len() {
                let kind = u16::from_be_bytes([data[ext], data[ext + 1]]);
                let len = u16::from_be_bytes([data[ext + 2], data[ext + 3]]) as usize;
                kinds.push(kind);
                if kind == 43 {
                    assert_eq!(len, 2);
                    selected_version = Some(u16::from_be_bytes([data[ext + 4], data[ext + 5]]));
                } else if kind == 16 {
                    selected_alpn = Some(&data[ext + 7..ext + 4 + len]);
                }
                ext += 4 + len;
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
            assert_eq!(hello["ja3s"], independent_digest(&text, "-md5"));
            assert_eq!(
                hello["supported_version"],
                serde_json::json!(selected_version)
            );
            assert_eq!(
                hello["alpn"],
                serde_json::json!(selected_alpn.map(|b| String::from_utf8(b.to_vec()).unwrap()))
            );
            let version = match selected_version.unwrap_or(version) {
                0x0304 => "13",
                0x0303 => "12",
                other => panic!("unexpected endpoint version {other}"),
            };
            let alpn = selected_alpn.map_or_else(
                || "00".into(),
                |p| format!("{}{}", p[0] as char, p[p.len() - 1] as char),
            );
            let extensions = kinds
                .iter()
                .map(|kind| format!("{kind:04x}"))
                .collect::<Vec<_>>()
                .join(",");
            let hash = if kinds.is_empty() {
                "000000000000".into()
            } else {
                independent_digest(&extensions, "-sha256")[..12].to_owned()
            };
            assert_eq!(
                hello["ja4s"],
                format!(
                    "t{version}{:02}{alpn}_{cipher:04x}_{hash}",
                    kinds.len().min(99)
                )
            );
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
        (
            wire(&body_with_extensions(4865, &[(43, &[])], false), 3),
            "invalid",
            false,
        ),
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
        if expected == "complete" {
            assert_eq!(hello["hello"]["ja4s"], "t120000_c02b_000000000000");
        }
        if saw_retry {
            assert!(
                hello["hello_retry_request"]["ja4s"]
                    .as_str()
                    .unwrap()
                    .starts_with("t130100_1301_")
            );
        }
        assert!(
            rows.iter()
                .filter(|row| row["event"] == "network.connection")
                .all(|row| !row.to_string().contains("raw_bytes"))
        );
    }
}
