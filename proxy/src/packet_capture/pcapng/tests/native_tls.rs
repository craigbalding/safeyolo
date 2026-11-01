//! Real intercepted TLS and the existing WSS route. Native mode additionally
//! acquires genuine packets; its isolated test PEN cannot establish release acceptance.
use super::{Format, TEST_ENTERPRISE, blocks, custom, word};
use crate::{
    observations::{ConsumerKind, Layer, Limits, Record},
    packet_capture::{Profile, SecretOutput, Settings},
};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::watch,
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(8);
const BODY: &[u8] = b"controlled TLS plaintext 858";

fn tls(
    root: &Path,
    config: &mut crate::Config,
) -> (rustls::ServerConfig, tokio_rustls::TlsConnector) {
    let (key, ca) = crate::tls::CertificateAuthority::create().unwrap();
    let ca_path = root.join("interception-ca.pem");
    std::fs::write(&ca_path, key.as_bytes()).unwrap();
    config.tls_ca_file = Some(ca_path);
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let upstream_path = root.join("origin-ca.pem");
    std::fs::write(&upstream_path, cert.pem()).unwrap();
    config.upstream_ca_file = Some(upstream_path);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap())
        .unwrap();
    roots.add(cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    (server, tokio_rustls::TlsConnector::from(Arc::new(client)))
}
async fn wss_clients(
    admin: std::net::SocketAddr,
    tls: rustls::ServerConfig,
    connector: tokio_rustls::TlsConnector,
) -> (
    tokio::task::JoinHandle<Vec<u8>>,
    tokio::task::JoinHandle<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let bridge = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = tls.clone();
            clients.spawn(async move {
                let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                    .accept(socket)
                    .await
                    .unwrap();
                let mut backend = TcpStream::connect(admin).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut backend).await;
            });
        }
        while clients.join_next().await.is_some() {}
    });
    let mut readers = Vec::new();
    for token in ["capture-read-858", "capture-secret-858"] {
        let mut stream = connector
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        stream.write_all(format!("GET /admin/capture HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
        assert!(
            crate::connection_events::tests::head(&mut stream)
                .await
                .starts_with(b"HTTP/1.1 101")
        );
        readers.push(tokio::spawn(async move {
            let mut reader = crate::websocket::Reader::new(stream, false, None);
            let mut bytes = Vec::new();
            while let Ok(event) = reader.read().await {
                match event {
                    crate::websocket::Event::Message(message) => message
                        .content()
                        .with_bytes(|part| bytes.extend_from_slice(part))
                        .unwrap(),
                    crate::websocket::Event::Close(_) => break,
                    _ => {}
                }
            }
            bytes
        }));
    }
    let mut stream = connector
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    stream.write_all(b"GET /admin/stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer capture-secret-858\r\nConnection: close\r\n\r\n").await.unwrap();
    assert!(
        crate::connection_events::tests::head(&mut stream)
            .await
            .starts_with(b"HTTP/1.1 401")
    );
    drop(stream);
    let secret = readers.pop().unwrap();
    let read = readers.pop().unwrap();
    (read, secret, bridge)
}
async fn capture_tls(root: &Path, native: bool, enabled: bool, exhausted: bool) {
    let mut config = crate::packet_capture::tests::config(root);
    config.admin_port = Some(0);
    let read = root.join("read-token");
    std::fs::write(&read, "capture-read-858").unwrap();
    config.admin_api_token_file = Some(read);
    let secret = root.join("secret-token");
    std::fs::write(&secret, "capture-secret-858").unwrap();
    config.native_settings.as_mut().unwrap().packet_capture = Settings {
        profile: Profile::Pcapng,
        test_enterprise: Some(TEST_ENTERPRISE),
        file: Some(root.join("capture.pcapng")),
        payload_layers: vec![
            Layer::TransportStream,
            Layer::TlsCleartext,
            Layer::WirePacket,
        ],
        wire_interface: native
            .then(|| std::env::var("SAFEYOLO_WIRE_INTERFACE").expect("native interface")),
        compatibility_packets: true,
        tls_secrets: enabled,
        secret_outputs: vec![SecretOutput::File],
        secrets_token_file: Some(secret),
        wss: true,
        queue: Limits {
            items: 64,
            bytes: 256 * 1024,
        },
        ..Default::default()
    };
    let (server_tls, connector) = tls(root, &mut config);
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    std::fs::write(root.join("origin-port"), address.port().to_string()).unwrap();
    let origin_tls = server_tls.clone();
    let (origin_ready_send, origin_ready) = tokio::sync::oneshot::channel();
    let (response_send, response_ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = origin.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(origin_tls))
            .accept(socket)
            .await
            .unwrap();
        let request = crate::connection_events::tests::head(&mut tls).await;
        assert!(
            request
                .windows(b"/pcapng-owned-858".len())
                .any(|b| b == b"/pcapng-owned-858")
        );
        origin_ready_send.send(()).unwrap();
        response_ready.await.unwrap();
        tls.write_all(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len()).as_bytes(),
        )
        .await
        .unwrap();
        tls.write_all(BODY).await.unwrap();
        tls
    });
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = &runtime.connection_events.as_ref().unwrap().observations;
    let capture = bus.capture.get().unwrap().clone();
    if native {
        assert!(
            capture.wire_format().is_some(),
            "native acquisition must be available"
        );
    }
    assert_eq!(capture.secrets.is_some(), enabled);
    let mut reservations = Vec::new();
    if exhausted {
        while let Some(entry) =
            capture.register_secrets(&format!("budget-slot-{}", reservations.len()))
        {
            reservations.push(entry);
        }
        assert!(!reservations.is_empty());
    }
    let wss = if enabled && !exhausted {
        Some(
            wss_clients(
                runtime.admin_address.unwrap(),
                server_tls,
                connector.clone(),
            )
            .await,
        )
    } else {
        None
    };
    let mut source = bus.subscribe(ConsumerKind::Capture, Limits::default());
    let records = Arc::new(Mutex::new(Vec::new()));
    let observed = records.clone();
    let through = Arc::new(AtomicU64::new(0));
    let seen = through.clone();
    let (stop, mut stopped) = watch::channel(false);
    let observer = tokio::spawn(async move {
        loop {
            tokio::select! {biased; _=stopped.changed()=>break,record=source.recv()=>{
                let Some(record)=record else {break};let last=match record.as_ref(){Record::Observation(o)=>o.id.sequence,Record::Gap(g)=>g.last_sequence};
                observed.lock().unwrap().push(record);seen.store(last,Ordering::Release);
            }}
        }
    });
    let mut agent = UnixStream::connect(root.join("alice.sock")).await.unwrap();
    agent
        .write_all(
            format!(
                "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                address.port(),
                address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(
        crate::connection_events::tests::head(&mut agent)
            .await
            .starts_with(b"HTTP/1.1 200")
    );
    let mut agent = connector
        .connect(ServerName::try_from("localhost").unwrap(), agent)
        .await
        .unwrap();
    agent
        .write_all(
            format!(
                "GET /pcapng-owned-858 HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    timeout(WAIT, origin_ready).await.unwrap().unwrap();
    capture.flush().await;
    let end = capture.encoded_through.load(Ordering::Acquire);
    timeout(WAIT, async {
        while through.load(Ordering::Acquire) < end {
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    let groups = records
        .lock()
        .unwrap()
        .iter()
        .filter_map(|record| match record.as_ref() {
            Record::Observation(o) if o.point == crate::observations::Point::OriginTls => {
                Some(o.connection_id.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if enabled && !exhausted {
        assert!(!groups.is_empty());
        let (lines, reason) = capture.secrets.as_ref().unwrap().snapshot(&groups[0]).await;
        assert!(!lines.is_empty(), "secret snapshot reason={reason:?}");
        assert!(reason.is_none());
        let audit = std::fs::read(root.join("audit.jsonl")).unwrap();
        for line in lines.lines() {
            let key = line.split_whitespace().last().unwrap();
            assert!(!audit.windows(key.len()).any(|b| b == key.as_bytes()));
        }
    }
    response_send.send(()).unwrap();
    assert!(
        crate::connection_events::tests::head(&mut agent)
            .await
            .starts_with(b"HTTP/1.1 200")
    );
    let mut response = vec![0; BODY.len()];
    timeout(WAIT, agent.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, BODY);
    let origin_stream = server.await.unwrap();
    if native {
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        let precision = capture.wire_format().unwrap().precision_ns;
        // Observe an actual post-response source sample, including file delivery.
        // A previously sampled receive count alone does not establish this boundary.
        timeout(WAIT, async {
            loop {
                let bytes = tokio::fs::read(root.join("capture.pcapng")).await.unwrap();
                let mut at = 0;
                let mut complete = false;
                while at + 8 <= bytes.len() {
                    let length = word(&bytes, at + 4) as usize;
                    if length < 12 || at + length > bytes.len() {
                        break;
                    }
                    if word(&bytes, at) == 5 && length >= 24 {
                        let ticks =
                            ((word(&bytes, at + 12) as u64) << 32) | word(&bytes, at + 16) as u64;
                        complete |= ticks as i128 * precision as i128 >= after;
                    }
                    at += length;
                }
                if complete {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    capture.flush().await;
    drop(agent);
    drop(origin_stream);
    proxy.shutdown().await;
    let last = capture.encoded_through.load(Ordering::Acquire);
    timeout(WAIT, async {
        while through.load(Ordering::Acquire) < last {
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    observer.await.unwrap();
    let file = std::fs::read(root.join("capture.pcapng")).unwrap();
    let rows = blocks(&file);
    assert_eq!(
        rows.iter().filter(|b| b.0 == 10).count() > 0,
        native && enabled && !exhausted
    );
    if let Some((read, secret, bridge)) = wss {
        let read = timeout(WAIT, read).await.unwrap().unwrap();
        let secret = timeout(WAIT, secret).await.unwrap().unwrap();
        timeout(WAIT, bridge).await.unwrap().unwrap();
        assert!(!blocks(&read).iter().any(|b| b.0 == 10));
        assert_eq!(blocks(&secret).iter().any(|b| b.0 == 10), native);
        std::fs::write(root.join("read-only.pcapng"), read).unwrap();
        std::fs::write(root.join("secrets-authorized.pcapng"), secret).unwrap();
    }
    if native {
        let wire = capture.wire_format().unwrap();
        let mut classic = wire.header();
        let packet_format = Format {
            enterprise: TEST_ENTERPRISE,
            wire: Some(wire),
            compatibility: false,
            wire_unavailable: None,
        };
        let mut packet_file = packet_format
            .session(&capture.session, "file", 65536)
            .unwrap();
        let mut expected = Vec::new();
        for record in records.lock().unwrap().iter() {
            if let Record::Observation(o) = record.as_ref()
                && o.packet.is_some()
                && o.id.sequence <= last
            {
                assert_eq!(o.agent.as_deref(), Some("alice"));
                let bytes = o.payload.as_ref().unwrap();
                let tuple =
                    crate::packet_capture::wire::tcp_tuple_for_test(wire.link_type, bytes).unwrap();
                assert!(tuple.0 == address || tuple.1 == address);
                expected.push((o.timestamp.wall_unix_ns, bytes.to_vec()));
                classic.extend(wire.encode(record, 65536).unwrap());
                packet_file.extend(packet_format.encode(record, 65536).unwrap());
            }
        }
        let actual: Vec<_> = rows
            .iter()
            .filter(|b| b.0 == 6 && word(b.1, 0) == 0)
            .map(|b| {
                let ticks = ((word(b.1, 4) as u64) << 32) | word(b.1, 8) as u64;
                (
                    ticks as i128 * wire.precision_ns as i128,
                    b.1[20..20 + word(b.1, 12) as usize].to_vec(),
                )
            })
            .collect();
        assert!(!actual.is_empty());
        assert_eq!(actual, expected);
        assert!(rows.iter().any(|b| b.0 == 5));
        if exhausted {
            assert!(
                rows.iter()
                    .filter(|b| b.0 == super::super::COPYABLE)
                    .any(|b| custom(b.1).0["type"] == "decryption_limitation")
            );
        }
        if enabled && !exhausted {
            let first_dsb = rows.iter().position(|b| b.0 == 10).unwrap();
            let dependent = rows
                .iter()
                .position(|b| {
                    if b.0 != 6 || word(b.1, 0) != 0 {
                        return false;
                    }
                    let bytes = &b.1[20..20 + word(b.1, 12) as usize];
                    let ip = match wire.link_type {
                        0 | 108 => 4,
                        1 => 14,
                        _ => return false,
                    };
                    if bytes.get(ip).is_none_or(|b| b >> 4 != 4) {
                        return false;
                    }
                    let tcp = ip + (bytes[ip] & 15) as usize * 4;
                    let data = tcp + (bytes.get(tcp + 12).copied().unwrap_or(0) >> 4) as usize * 4;
                    bytes.get(data) == Some(&23)
                })
                .expect("encrypted TLS application record");
            assert!(first_dsb < dependent);
        }
        std::fs::write(root.join("wire.pcap"), classic).unwrap();
        std::fs::write(root.join("packet-subset.pcapng"), packet_file).unwrap();
    }
    eprintln!(
        "PCAPNG TLS proof native={native} enabled={enabled} budget_exhausted={exhausted} output={}",
        root.display()
    );
}
#[tokio::test]
async fn intercepted_tls_secret_callbacks_and_scoped_wss_authorization() {
    for (enabled, exhausted) in [(true, false), (false, false), (true, true)] {
        let root = tempfile::tempdir().unwrap();
        capture_tls(root.path(), false, enabled, exhausted).await;
    }
}
#[tokio::test]
#[ignore = "requires native libpcap access and SAFEYOLO_WIRE_INTERFACE/SAFEYOLO_PCAPNG_PROOF_DIR"]
async fn native_intercepted_tls_packets_secrets_order_authorization_and_wire_subset() {
    let parent = std::path::PathBuf::from(
        std::env::var_os("SAFEYOLO_PCAPNG_PROOF_DIR").expect("proof directory"),
    );
    for (enabled, exhausted, name) in [
        (true, false, "enabled"),
        (false, false, "disabled"),
        (true, true, "bounded-failure"),
    ] {
        let root = parent.join(name);
        std::fs::create_dir(&root).unwrap();
        capture_tls(&root, true, enabled, exhausted).await;
    }
}
