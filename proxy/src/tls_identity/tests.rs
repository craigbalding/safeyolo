use super::*;
use rustls::pki_types::{CertificateDer, pem::PemObject};

fn vector16(bytes: &[u8]) -> Vec<u8> {
    let mut output = (bytes.len() as u16).to_be_bytes().to_vec();
    output.extend_from_slice(bytes);
    output
}
fn u16_bytes(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}
fn body(version: u16, ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x58; 32]);
    body.push(0);
    body.extend(vector16(&u16_bytes(ciphers)));
    body.extend([1, 0]);
    if !extensions.is_empty() {
        let mut bytes = Vec::new();
        for (kind, value) in extensions {
            bytes.extend(kind.to_be_bytes());
            bytes.extend(vector16(value));
        }
        body.extend(vector16(&bytes));
    }
    body
}
fn sni(name: &str) -> Vec<u8> {
    let mut name_bytes = vec![0];
    name_bytes.extend(vector16(name.as_bytes()));
    vector16(&name_bytes)
}
fn alpn(values: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(value);
    }
    vector16(&bytes)
}
fn records(body: &[u8], fragment: usize) -> Vec<u8> {
    let mut handshake = (body.len() as u32).to_be_bytes().to_vec();
    handshake[0] = 1;
    handshake.extend_from_slice(body);
    let mut wire = Vec::new();
    for chunk in handshake.chunks(fragment) {
        wire.extend([22, 3, 1]);
        wire.extend(vector16(chunk));
    }
    wire
}

/// The ordered cipher/extension/signature lists and expected JA4 come from
/// FoxIO's technical_details/JA4.md example. Other extension payloads are
/// synthetic, not a claim to be a captured browser handshake.
fn foxio_body(with_grease: bool) -> Vec<u8> {
    let mut ciphers = vec![
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let kinds = [
        0x1b, 0, 0x33, 0x10, 0x4469, 0x17, 0x2d, 0xd, 5, 0x23, 0x12, 0x2b, 0xff01, 0xb, 0xa, 0x15,
    ];
    let mut extensions: Vec<_> = kinds
        .into_iter()
        .map(|kind| {
            (
                kind,
                match kind {
                    0 => sni("tls-fixture.invalid"),
                    10 => vector16(&u16_bytes(&[29, 23, 24])),
                    11 => vec![1, 0],
                    13 => vector16(&u16_bytes(&[
                        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                    ])),
                    16 => alpn(&[b"h2", b"http/1.1"]),
                    43 => vec![4, 3, 4, 3, 3],
                    _ => Vec::new(),
                },
            )
        })
        .collect();
    if with_grease {
        ciphers.insert(0, 0x0a0a);
        extensions.insert(0, (0x1a1a, vec![0xff]));
        extensions.iter_mut().find(|e| e.0 == 10).unwrap().1 =
            vector16(&u16_bytes(&[0x2a2a, 29, 23, 24]));
        extensions.iter_mut().find(|e| e.0 == 43).unwrap().1 = vec![6, 0x3a, 0x3a, 3, 4, 3, 3];
        extensions.iter_mut().find(|e| e.0 == 13).unwrap().1 = vector16(&u16_bytes(&[
            0x4a4a, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]));
    }
    body(771, &ciphers, &extensions)
}

#[test]
fn published_ja3_vectors_and_absent_extensions() {
    // Salesforce README's two example preimages and hashes, encoded as real
    // ClientHello bodies. The SNI value does not enter either JA3 preimage.
    let first = body(
        769,
        &[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
        &[
            (0, sni("tls-fixture.invalid")),
            (10, vector16(&u16_bytes(&[23, 24, 25]))),
            (11, vec![1, 0]),
        ],
    );
    assert_eq!(
        client_hello(&first).unwrap().ja3,
        "ada70206e40642a3e4461f35503241d5"
    );
    let second = body(769, &[4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99], &[]);
    let hello = client_hello(&second).unwrap();
    assert_eq!(hello.ja3, "de350869b8c85de67a350c8d186f11e6");
    assert!(hello.ja4.starts_with("t10i110000_"));
    assert!(hello.ja4.ends_with("_000000000000"));
    assert!(hello.sni.is_none());
    assert!(hello.alpn_offers.is_empty());
}

#[test]
fn published_ja4_vector_grease_and_fragmented_records() {
    for grease in [false, true] {
        let body = foxio_body(grease);
        for fragment in [1, 3, 31, body.len() + 4] {
            let wire = records(&body, fragment);
            for read_size in [1, 2, 17, wire.len()] {
                let mut capture = Capture::default();
                for read in wire.chunks(read_size) {
                    capture.feed(read);
                }
                let hello = capture.parsed().unwrap();
                assert_eq!(hello.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
                assert_eq!(hello.ja3, "c000e2caf3a25423f9de6c8a4b12a975");
                assert_eq!(hello.sni.as_deref(), Some("tls-fixture.invalid"));
                assert_eq!(hello.alpn_offers, ["h2", "http/1.1"]);
                assert_eq!(hello.cipher_suite_count, if grease { 16 } else { 15 });
                assert!(hello.valid());
            }
        }
    }
}

#[test]
fn ja4_alpn_unknown_versions_counts_and_empty_hash_rules() {
    for (value, expected) in [
        (b"h2".as_slice(), "h2"),
        (b"http/1.1", "h1"),
        (b"a", "aa"),
        (&[0xab], "ab"),
        (&[0x30, 0xab, 0xcd, 0x31], "01"),
        (b"", "00"),
    ] {
        assert_eq!(alpn_code(value), expected);
    }
    let ciphers: Vec<_> = (0x0100..0x0164).collect();
    let extensions = [
        (0, sni("tls-fixture.invalid")),
        (16, alpn(&[b"h2"])),
        (43, vec![2, 0x7f, 0x1c]),
    ];
    let hello = client_hello(&body(771, &ciphers, &extensions)).unwrap();
    assert!(hello.ja4.starts_with("t00d9903h2_"));
    assert_eq!(hello.cipher_suites.len(), LIST_LIMIT);
    assert!(hello.truncated);
    let hello = client_hello(&body(771, &[], &[(0, sni("x")), (16, alpn(&[b"h2"]))])).unwrap();
    assert_eq!(hello.ja4, "t12d0002h2_000000000000_000000000000");
    // No signature list means no trailing underscore before the extension hash.
    let ext = [
        5, 10, 11, 13, 18, 21, 23, 27, 35, 43, 45, 51, 0x4469, 0xff01,
    ];
    assert_eq!(short_hash(&ext, &[]), "6d807ffa2a79");
}

#[test]
fn incomplete_malformed_and_oversized_hello_produces_no_identity() {
    let wire = records(&foxio_body(false), 17);
    for end in 0..wire.len() {
        let mut capture = Capture::default();
        capture.feed(&wire[..end]);
        assert!(capture.parsed().is_none());
    }
    for wire in [
        b"GET / HTTP/1.1\r\n".to_vec(),
        vec![22, 3, 1, 0, 4, 1, 0, 0, 0],
        vec![22, 3, 1, 0, 4, 1, 255, 255, 255],
    ] {
        let mut capture = Capture::default();
        capture.feed(&wire);
        capture.feed(&[0; 32]);
        assert!(capture.parsed().is_none());
    }
    let duplicate = body(
        771,
        &[0x1301],
        &[(16, alpn(&[b"h2"])), (16, alpn(&[b"h2"]))],
    );
    assert!(client_hello(&duplicate).is_none());
}

#[test]
fn certificate_der_and_spki_known_hashes_renewal_and_absence() {
    let leaf = CertificateDer::from_pem_slice(include_bytes!(
        "../../tests/fixtures/tls-identity-leaf.pem"
    ))
    .unwrap();
    let renewed = CertificateDer::from_pem_slice(include_bytes!(
        "../../tests/fixtures/tls-identity-renewed.pem"
    ))
    .unwrap();
    let first = certificate(&[leaf]).unwrap();
    let second = certificate(&[renewed]).unwrap();
    // OpenSSL x509 -outform DER and pkey -pubin -outform DER, SHA-256.
    assert_eq!(
        first.cert_sha256,
        "1ede353569eb15756dd2da8ba43a931c5ca15f2a0835741331680a22b9cc074e"
    );
    assert_eq!(
        second.cert_sha256,
        "82bb9ed605a5232daf4724048c3b1fa0a415c87fa3d3e4f4952eb2725221943a"
    );
    assert_eq!(
        first.spki_sha256.as_deref(),
        Some("cc675bb5fe4d2c1d16ff40833ef2db919cb041e29348fb8cc2c00d1784dec31f")
    );
    assert_ne!(first.cert_sha256, second.cert_sha256);
    assert_eq!(first.spki_sha256, second.spki_sha256);
    assert_eq!(first.san, ["tls-fixture.invalid", "192.0.2.1"]);
    assert_eq!(first.key_bits, Some(256));
    assert_eq!(first.key_algorithm.as_deref(), Some("1.2.840.10045.2.1"));
    assert!(
        first
            .subject
            .as_deref()
            .unwrap()
            .contains("tls-fixture.invalid")
    );
    assert!(first.valid());
    assert!(second.valid());
    let changed_key =
        rcgen::generate_simple_self_signed(vec!["tls-fixture.invalid".into()]).unwrap();
    let changed_key = certificate(&[changed_key.cert.der().clone()]).unwrap();
    assert_ne!(first.spki_sha256, changed_key.spki_sha256);
    assert!(certificate(&[]).is_none());
    let malformed = certificate(&[CertificateDer::from(vec![1, 2, 3])]).unwrap();
    assert!(malformed.spki_sha256.is_none());
    assert!(malformed.subject.is_none());
    assert!(malformed.key_bits.is_none());
    assert!(malformed.san.is_empty());
}

#[test]
fn offered_metadata_and_certificate_summaries_are_bounded() {
    let name = "a".repeat(NAME_LIMIT + 20);
    let offer = [0xff; 100];
    let offers = vec![offer.as_slice(); ALPN_LIMIT + 3];
    let hello = client_hello(&body(
        771,
        &[0x1301],
        &[(0, sni(&name)), (16, alpn(&offers))],
    ))
    .unwrap();
    assert_eq!(hello.sni.as_ref().unwrap().len(), NAME_LIMIT);
    assert_eq!(hello.alpn_offers.len(), ALPN_LIMIT);
    assert!(hello.alpn_offers.iter().all(|s| s.len() == 256));
    assert!(hello.truncated && hello.valid());

    let names = (0..20)
        .map(|n| format!("san{n}.invalid"))
        .collect::<Vec<_>>();
    let mut parameters = rcgen::CertificateParams::new(names).unwrap();
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "b".repeat(600));
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = parameters.self_signed(&key).unwrap();
    let identity = certificate(&[cert.der().clone()]).unwrap();
    assert_eq!(identity.subject.as_ref().unwrap().len(), 512);
    assert_eq!(identity.san.len(), 16);
    assert_eq!(identity.san_count, 20);
    assert!(identity.truncated && identity.valid());
}

#[tokio::test]
async fn real_ingress_retains_fingerprint_when_handshake_fails_after_fragmented_hello() {
    use crate::{
        Proxy,
        connection_events::tests::{
            assert_pairs, config, connections, head, records as audit_records,
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        time::{Duration, timeout},
    };
    let directory = tempfile::tempdir().unwrap();
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    // Keep the actual upstream socket alive until the proxy has classified the
    // complete ClientHello. The synthetic fixture deliberately has no valid
    // key share; rustls rejects its extensions after the observation boundary.
    let peer = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut bytes = Vec::new();
        let _ = socket.read_to_end(&mut bytes).await;
    });
    let mut configuration = config(directory.path());
    let (pem, _) = crate::tls::CertificateAuthority::create().unwrap();
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, pem.as_bytes()).unwrap();
    configuration.tls_ca_file = Some(ca);
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client
        .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let wire = records(&foxio_body(true), 7);
    for read in wire.chunks(11) {
        client.write_all(read).await.unwrap();
    }
    let mut reply = Vec::new();
    let _ = timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
        .await
        .unwrap();
    drop(client);
    timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
    proxy.shutdown().await;
    let rows = audit_records(&runtime, directory.path());
    assert_pairs(&rows);
    let clients = connections(&rows, "client_to_proxy", "terminal");
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0]["state"], "failed");
    assert_eq!(
        clients[0]["tls_client_hello"]["ja4"],
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
    assert_eq!(
        clients[0]["tls_client_hello"]["ja3"],
        "c000e2caf3a25423f9de6c8a4b12a975"
    );
    let updates = connections(&rows, "client_to_proxy", "updated");
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["connection_id"], clients[0]["connection_id"]);
    assert!(clients[0]["tls_sessions"].is_null());
    for server in connections(&rows, "proxy_to_upstream", "terminal") {
        assert!(server["tls_sessions"].is_null());
    }
    for row in rows.iter().filter(|r| r["event"] == "network.connection") {
        let text = row.to_string();
        for forbidden in [
            "BEGIN CERTIFICATE",
            "ClientHello bytes",
            "request body",
            "raw_extensions",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}

#[tokio::test]
async fn nested_parent_tls_keeps_both_sessions_and_preserves_parent_on_origin_failure() {
    use crate::{
        Proxy,
        connection_events::tests::{
            assert_pairs, config, connections, head, records as audit_records,
        },
    };
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        time::timeout,
    };
    for origin_valid in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let (parent, address) = crate::test_owned_endpoint::bind().await;
        let endpoint = |name: String| {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec![name]).unwrap();
            let pem = cert.pem();
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
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            (pem, Arc::new(tls), sha256(cert.der()))
        };
        let (parent_pem, parent_tls, parent_hash) = endpoint(address.ip().to_string());
        let (origin_pem, origin_tls, origin_hash) = endpoint(
            if origin_valid {
                "origin.invalid"
            } else {
                "wrong.invalid"
            }
            .into(),
        );
        let trust = directory.path().join("trust.pem");
        std::fs::write(&trust, format!("{parent_pem}{origin_pem}")).unwrap();
        let mut configuration = config(directory.path());
        configuration.parent_proxy = Some(format!("https://{address}"));
        configuration.upstream_ca_file = Some(trust);
        // Absolute HTTPS requests use the existing interception-enabled path.
        let (pem, _) = crate::tls::CertificateAuthority::create().unwrap();
        let ca = directory.path().join("interception.pem");
        std::fs::write(&ca, pem.as_bytes()).unwrap();
        configuration.tls_ca_file = Some(ca);
        let peer = tokio::spawn(async move {
            let (socket, _) = parent.accept().await.unwrap();
            let mut outer = tokio_rustls::TlsAcceptor::from(parent_tls)
                .accept(socket)
                .await
                .unwrap();
            assert!(
                head(&mut outer)
                    .await
                    .starts_with(b"CONNECT origin.invalid.:443 HTTP/1.1")
            );
            outer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let inner = tokio_rustls::TlsAcceptor::from(origin_tls)
                .accept(outer)
                .await;
            if !origin_valid {
                assert!(inner.is_err());
                return;
            }
            let mut inner = inner.unwrap();
            assert_eq!(inner.get_ref().1.server_name(), Some("origin.invalid"));
            assert!(head(&mut inner).await.starts_with(b"GET /path HTTP/1.1"));
            inner
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            inner.shutdown().await.unwrap();
        });
        let proxy = Proxy::start(configuration).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        client.write_all(b"GET https://origin.invalid./path HTTP/1.1\r\nHost: origin.invalid.\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut reply = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(
            reply.starts_with(if origin_valid {
                b"HTTP/1.1 200"
            } else {
                b"HTTP/1.1 502"
            }),
            "origin_valid={origin_valid}, reply={}",
            String::from_utf8_lossy(&reply)
        );
        drop(client);
        timeout(Duration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap();
        proxy.shutdown().await;
        let rows = audit_records(&runtime, directory.path());
        assert_pairs(&rows);
        let servers = connections(&rows, "proxy_to_upstream", "terminal");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["route"], "parent");
        assert_eq!(servers[0]["resolved_peer"], address.to_string());
        assert!(servers[0]["resolved_origin_peer"].is_null());
        let sessions = servers[0]["tls_sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), if origin_valid { 2 } else { 1 });
        assert_eq!(sessions[0]["peer"], "parent");
        assert_eq!(sessions[0]["leaf_certificate"]["cert_sha256"], parent_hash);
        assert!(sessions[0]["sni"].is_null());
        if origin_valid {
            assert_eq!(sessions[1]["peer"], "origin");
            assert_eq!(sessions[1]["sni"], "origin.invalid");
            assert_eq!(sessions[1]["alpn"], "http/1.1");
            assert_eq!(sessions[1]["leaf_certificate"]["cert_sha256"], origin_hash);
        } else {
            assert_eq!(servers[0]["error"], "origin_tls_failed");
        }
        assert_eq!(
            connections(&rows, "proxy_to_upstream", "updated").len(),
            sessions.len()
        );
        assert!(connections(&rows, "client_to_proxy", "terminal")[0]["tls_client_hello"].is_null());
    }
}
