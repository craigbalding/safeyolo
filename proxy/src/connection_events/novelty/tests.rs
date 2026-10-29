use super::*;
use crate::{
    Proxy,
    connection_events::tests::{config, head, records},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(5);

fn key(agent: &str, destination: &str) -> Key {
    Key {
        agent: agent.into(),
        destination: destination.into(),
        route: "direct",
    }
}

fn observation(id: &str) -> Observation {
    Observation::new(id, format!("event-{id}"))
}

fn session(cert: char, spki: Option<char>) -> TlsSession {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::from_pem_slice(include_bytes!(
        "../../../tests/fixtures/tls-identity-leaf.pem"
    ))
    .unwrap();
    let mut leaf = crate::tls_identity::certificate(&[der]).unwrap();
    leaf.cert_sha256 = cert.to_string().repeat(64);
    leaf.spki_sha256 = spki.map(|c| c.to_string().repeat(64));
    TlsSession {
        peer: "origin".into(),
        sni: Some("origin.invalid".into()),
        version: Some("TLSv1_3".into()),
        cipher: None,
        alpn: None,
        handshake_kind: Some("Full".into()),
        leaf_certificate: Some(leaf),
    }
}

#[test]
fn fifo_repeats_eviction_and_tls_after_eviction_are_bounded() {
    let mut history = History {
        capacity: 2,
        ..History::default()
    };
    let a = key("alice", "a.invalid:443");
    let b = key("alice", "b.invalid:443");
    let c = key("bob", "a.invalid:443");
    assert!(
        history
            .destination(&a, observation("a1"))
            .unwrap()
            .valid(Some("a1"))
    );
    let first = session('a', Some('b'));
    assert!(
        history
            .certificate(&a, "a.invalid", &first, observation("cert-a1"))
            .is_none()
    );
    assert!(
        history
            .negotiation(&a, "a.invalid", &first, observation("negotiation-a1"))
            .is_none()
    );
    assert!(history.destination(&b, observation("b1")).is_some());
    assert!(history.destination(&a, observation("a2")).is_none());
    assert!(history.destination(&c, observation("c1")).is_some());
    assert!(
        !history.entries.contains_key(&a),
        "repetition does not refresh FIFO age"
    );
    assert!(
        history
            .certificate(
                &a,
                "a.invalid",
                &session('a', Some('b')),
                observation("late")
            )
            .is_none()
    );
    assert!(history.destination(&a, observation("a3")).is_some());
    let mut changed = first;
    changed.version = Some("TLSv1_2".into());
    assert!(
        history
            .negotiation(&a, "a.invalid", &changed, observation("new-baseline"))
            .is_none()
    );
    assert_eq!(history.entries.len(), 2);
    assert_eq!(history.oldest.len(), 2);
    assert!(!history.entries.contains_key(&b));
    assert_eq!(
        Destination::new("ORIGIN.INVALID.", 443, "direct").authority,
        "origin.invalid:443"
    );
    assert_eq!(
        Destination::new("2001:0db8::1", 443, "direct").authority,
        "[2001:db8::1]:443"
    );
}

#[test]
fn only_comparable_full_origin_certificates_advance_the_baseline() {
    let mut history = History::default();
    let key = key("alice", "origin.invalid:443");
    history.destination(&key, observation("open"));
    let first = session('a', Some('b'));
    assert!(
        history
            .certificate(&key, "ORIGIN.INVALID.", &first, observation("first"))
            .is_none()
    );
    assert!(
        history
            .certificate(&key, "origin.invalid", &first, observation("repeat"))
            .is_none()
    );
    {
        let mut unknown = session('c', Some('d'));
        unknown.peer = "parent".into();
        assert!(
            history
                .certificate(&key, "origin.invalid", &unknown, observation("parent"))
                .is_none()
        );
        unknown.peer = "origin".into();
        unknown.handshake_kind = Some("Resumed".into());
        assert!(
            history
                .certificate(&key, "origin.invalid", &unknown, observation("resumed"))
                .is_none()
        );
        unknown.handshake_kind = Some("Full".into());
        unknown.leaf_certificate = None;
        assert!(
            history
                .certificate(&key, "origin.invalid", &unknown, observation("missing"))
                .is_none()
        );
    }
    let renewal = history
        .certificate(
            &key,
            "origin.invalid",
            &session('c', Some('b')),
            observation("renewal"),
        )
        .unwrap();
    assert_eq!(renewal.previous.as_ref().unwrap().connection_id, "repeat");
    assert_eq!(
        renewal.previous.as_ref().unwrap().spki_sha256,
        renewal.current.spki_sha256
    );
    let missing_spki = history
        .certificate(
            &key,
            "origin.invalid",
            &session('d', None),
            observation("unparsed"),
        )
        .unwrap();
    assert!(missing_spki.current.spki_sha256.is_none());
    // Learning a previously absent SPKI is not a measured change.
    assert!(
        history
            .certificate(
                &key,
                "origin.invalid",
                &session('d', Some('e')),
                observation("parsed")
            )
            .is_none()
    );
    let changed = history
        .certificate(
            &key,
            "origin.invalid",
            &session('f', Some('a')),
            observation("changed"),
        )
        .unwrap();
    assert!(changed.valid(Some("changed")));
    assert_ne!(
        changed.previous.as_ref().unwrap().spki_sha256,
        changed.current.spki_sha256
    );
    // A selected numeric endpoint can later verify another SNI name. Reset
    // that single baseline instead of comparing certificates for two names.
    assert!(
        history
            .certificate(&key, "other.invalid", &first, observation("other-name"))
            .is_none()
    );
}

#[test]
fn negotiation_availability_resumption_verification_and_route_are_distinct() {
    let mut history = History::default();
    let key = key("alice", "origin.invalid:443");
    history.destination(&key, observation("open"));
    let mut measured = session('a', Some('b'));
    assert!(
        history
            .negotiation(&key, "ORIGIN.INVALID.", &measured, observation("first"))
            .is_none()
    );
    assert!(
        history
            .negotiation(&key, "origin.invalid", &measured, observation("repeat"))
            .is_none()
    );
    for peer in ["parent", "provider"] {
        let mut unavailable = measured.clone();
        unavailable.peer = peer.into();
        unavailable.alpn = Some("h2".into());
        assert!(
            history
                .negotiation(&key, "origin.invalid", &unavailable, observation(peer))
                .is_none()
        );
    }
    for field in ["version", "handshake_kind"] {
        let mut unavailable = measured.clone();
        if field == "version" {
            unavailable.version = None;
        } else {
            unavailable.handshake_kind = None;
        }
        unavailable.alpn = Some("h2".into());
        assert!(
            history
                .negotiation(&key, "origin.invalid", &unavailable, observation(field))
                .is_none()
        );
    }
    // The negotiated values are current even when a resumed certificate chain
    // could be cached, or a certificate summary is unavailable.
    measured.handshake_kind = Some("Resumed".into());
    measured.leaf_certificate = None;
    measured.alpn = Some("h2".into());
    let changed = history
        .negotiation(&key, "origin.invalid", &measured, observation("resumed"))
        .unwrap();
    assert_eq!(changed.previous.as_ref().unwrap().connection_id, "repeat");
    assert!(
        changed
            .previous
            .as_ref()
            .unwrap()
            .negotiation
            .as_ref()
            .unwrap()
            .alpn
            .is_none()
    );
    assert!(changed.valid(Some("resumed")));
    measured.version = Some("TLSv1_2".into());
    let changed = history
        .negotiation(
            &key,
            "origin.invalid",
            &measured,
            observation("version-change"),
        )
        .unwrap();
    assert_eq!(changed.previous.as_ref().unwrap().connection_id, "resumed");
    assert!(
        history
            .negotiation(&key, "other.invalid", &measured, observation("other-name"))
            .is_none()
    );
    measured.alpn = None;
    let changed = history
        .negotiation(&key, "other.invalid", &measured, observation("no-alpn"))
        .unwrap();
    assert_eq!(
        changed.previous.as_ref().unwrap().connection_id,
        "other-name"
    );
    let mut other_route = key.clone();
    other_route.route = "provider";
    history.destination(&other_route, observation("provider-open"));
    assert!(
        history
            .negotiation(
                &other_route,
                "other.invalid",
                &measured,
                observation("provider-origin")
            )
            .is_none()
    );
}

fn tls_origin(
    name: &str,
    key: &rcgen::KeyPair,
    serial: u64,
) -> (
    String,
    Arc<rustls::ServerConfig>,
    crate::tls_identity::Certificate,
) {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.serial_number = Some(serial.into());
    let cert = params.self_signed(key).unwrap();
    let identity = crate::tls_identity::certificate(&[cert.der().clone()]).unwrap();
    let tls = tls_config(
        cert.der().clone(),
        key,
        rustls::DEFAULT_VERSIONS,
        Some(b"http/1.1"),
    );
    (cert.pem(), tls, identity)
}

fn tls_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: &rcgen::KeyPair,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: Option<&[u8]>,
) -> Arc<rustls::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = alpn.into_iter().map(<[u8]>::to_vec).collect();
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Arc::new(tls)
}

async fn serve_tls(listener: TcpListener, configs: Vec<Arc<rustls::ServerConfig>>) {
    for config in configs {
        let (socket, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(config)
            .accept(socket)
            .await
            .unwrap();
        assert!(head(&mut tls).await.starts_with(b"GET /path HTTP/1.1"));
        tls.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nunchanged",
        )
        .await
        .unwrap();
        tls.shutdown().await.unwrap();
    }
}

async fn request(directory: &Path, agent: &str, url: &str) -> Vec<u8> {
    let reply = response(directory, agent, url).await;
    assert!(
        reply.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    assert!(reply.ends_with(b"unchanged"));
    reply
}

async fn response(directory: &Path, agent: &str, url: &str) -> Vec<u8> {
    let mut socket = UnixStream::connect(directory.join(format!("{agent}.sock")))
        .await
        .unwrap();
    socket.write_all(format!("GET {url}/path HTTP/1.1\r\nHost: ignored.invalid\r\nX-SafeYolo-Agent: forged\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, socket.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    reply
}

fn tls_proxy_config(directory: &Path, trust_pem: &str) -> crate::Config {
    let mut configuration = config(directory);
    let trust = directory.join("trust.pem");
    std::fs::write(&trust, trust_pem).unwrap();
    configuration.upstream_ca_file = Some(trust);
    let (pem, _) = crate::tls::CertificateAuthority::create().unwrap();
    let ca = directory.join("interception.pem");
    std::fs::write(&ca, pem).unwrap();
    configuration.tls_ca_file = Some(ca);
    configuration
}

fn indicators(rows: &[Value]) -> Vec<&Value> {
    rows.iter()
        .filter(|row| {
            row["event"] == "security.indicator"
                && row["details"]["sensor"] == "connection-history.v1"
        })
        .collect()
}

fn assert_observation(rows: &[Value], indicator: &Value, observation: &Value, certificate: bool) {
    let source = rows
        .iter()
        .find(|row| row["event_id"] == observation["event_id"])
        .unwrap();
    assert_eq!(source["event"], "network.connection");
    assert_eq!(source["agent"], indicator["agent"]);
    for field in ["instance_id", "runtime_id"] {
        assert_eq!(source["details"][field], indicator["details"][field]);
    }
    assert_eq!(
        source["details"]["connection_id"],
        observation["connection_id"]
    );
    if certificate {
        assert_eq!(source["details"]["state"], "updated");
        let tls = source["details"]["tls_sessions"]
            .as_array()
            .unwrap()
            .last()
            .unwrap();
        assert_eq!(tls["peer"], "origin");
        for field in ["cert_sha256", "spki_sha256"] {
            assert_eq!(tls["leaf_certificate"][field], observation[field]);
        }
    }
    if observation["negotiation"].is_object() {
        let tls = source["details"]["tls_sessions"]
            .as_array()
            .unwrap()
            .last()
            .unwrap();
        assert_eq!(tls["peer"], "origin");
        for field in ["version", "alpn"] {
            assert_eq!(tls[field], observation["negotiation"][field]);
        }
    }
}

#[tokio::test]
async fn native_tls_renewal_key_change_isolation_reload_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let (other, other_address) = crate::test_owned_endpoint::bind().await;
    let key = rcgen::KeyPair::generate().unwrap();
    let (pem_a, a, cert_a) = tls_origin(&address.ip().to_string(), &key, 1);
    let (pem_b, b, cert_b) = tls_origin(&address.ip().to_string(), &key, 2);
    let (pem_c, c, cert_c) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        3,
    );
    assert_eq!(cert_a.spki_sha256, cert_b.spki_sha256);
    assert_ne!(cert_a.cert_sha256, cert_b.cert_sha256);
    assert_ne!(cert_b.spki_sha256, cert_c.spki_sha256);
    let peer = tokio::spawn(serve_tls(
        listener,
        vec![
            a.clone(),
            a.clone(),
            b.clone(),
            b,
            c.clone(),
            c.clone(),
            c.clone(),
            c,
        ],
    ));
    let other_peer = tokio::spawn(serve_tls(other, vec![a]));
    let mut configuration = tls_proxy_config(directory.path(), &format!("{pem_a}{pem_b}{pem_c}"));
    for (agent, source_id) in [("bob", "192.0.2.21"), ("unknown", "192.0.2.22")] {
        configuration.listeners.push(crate::config::AgentListener {
            agent_id: agent.into(),
            source_id: Some(source_id.into()),
            socket_path: directory.path().join(format!("{agent}.sock")),
        });
    }
    std::fs::write(
        configuration.policy_file.as_ref().unwrap(),
        json!({
            "permissions":[{"action":"network:request","resource":"*","effect":"allow"}],
        "addons":{"request_logger":{"quiet_hosts":{"hosts":["ignored.invalid"]}}}
        })
        .to_string(),
    )
    .unwrap();
    let url = format!("https://{address}");
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    for _ in 0..2 {
        request(directory.path(), "alice", &url).await;
    }
    assert_eq!(indicators(&records(&runtime, directory.path())).len(), 1);
    proxy.reload(configuration.clone()).await.unwrap();
    request(directory.path(), "alice", &url).await;
    request(directory.path(), "alice", &url).await;
    request(directory.path(), "bob", &url).await;
    request(directory.path(), "alice", &url).await;
    request(directory.path(), "unknown", &url).await;
    request(
        directory.path(),
        "alice",
        &format!("https://{other_address}"),
    )
    .await;
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let clues = indicators(&rows);
    assert_eq!(
        clues.len(),
        5,
        "{}",
        serde_json::to_string_pretty(&clues).unwrap()
    );
    assert_eq!(
        clues
            .iter()
            .filter(|r| r["details"]["rule"] == "destination.first_observation.v1")
            .count(),
        3
    );
    let changes: Vec<_> = clues
        .iter()
        .filter(|r| r["details"]["rule"] == "tls.origin_identity_changed.v1")
        .collect();
    assert_eq!(changes.len(), 2);
    for (change, previous, current) in [
        (changes[0], &cert_a, &cert_b),
        (changes[1], &cert_b, &cert_c),
    ] {
        let evidence = &change["details"]["novelty"];
        assert_eq!(evidence["previous"]["cert_sha256"], previous.cert_sha256);
        assert_eq!(evidence["current"]["cert_sha256"], current.cert_sha256);
        assert_eq!(
            evidence["previous"]["spki_sha256"],
            json!(previous.spki_sha256)
        );
        assert_eq!(
            evidence["current"]["spki_sha256"],
            json!(current.spki_sha256)
        );
        assert_eq!(evidence["destination"], address.to_string());
        assert_observation(&rows, change, &evidence["previous"], true);
    }
    for clue in clues {
        let evidence = &clue["details"]["novelty"];
        assert_eq!(evidence["history_scope"], "runtime_fifo");
        assert_eq!(evidence["history_capacity"], CAPACITY);
        assert_eq!(
            clue["details"]["attribution"]["trusted_transport_identity"],
            clue["agent"]
        );
        assert_eq!(clue["details"]["attribution"]["initiator"], "unknown");
        assert_observation(
            &rows,
            clue,
            &evidence["current"],
            evidence["previous"].is_object(),
        );
        assert!(clue.get("request_id").is_none());
        assert!(clue.get("decision").is_none());
        let text = clue.to_string();
        assert!(
            !text.contains("unchanged")
                && !text.contains("BEGIN CERTIFICATE")
                && !text.contains("forged")
        );
    }
    assert!(rows.iter().any(|r| r["event"] == "network.connection"
        && r["details"]["attribution"]["attribution_status"] == "unavailable"));
    assert!(
        !rows.iter().any(|r| r["event"] == "traffic.request"),
        "{rows:?}"
    );
    assert!(!directory.path().join("unused.sqlite3").exists());
    let proxy = Proxy::start(configuration).await.unwrap();
    let restarted = proxy.runtime.read().unwrap().clone();
    assert_ne!(runtime.instance_id, restarted.instance_id);
    request(directory.path(), "alice", &url).await;
    proxy.shutdown().await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    timeout(LIMIT, other_peer).await.unwrap().unwrap();
    let rows = records(&restarted, directory.path());
    let clues: Vec<_> = indicators(&rows)
        .into_iter()
        .filter(|r| r["details"]["runtime_id"] == restarted.instance_id)
        .collect();
    assert_eq!(
        clues.len(),
        1,
        "retained JSONL does not restore comparison state"
    );
    assert_eq!(
        clues[0]["details"]["rule"],
        "destination.first_observation.v1"
    );
}

#[tokio::test]
async fn native_same_certificate_version_and_alpn_changes_keep_exact_links() {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let (other, other_address) = crate::test_owned_endpoint::bind().await;
    let key = rcgen::KeyPair::generate().unwrap();
    let (pem, a, cert) = tls_origin(&address.ip().to_string(), &key, 1);
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    let b = tls_config(
        der.clone(),
        &key,
        &[&rustls::version::TLS12],
        Some(b"http/1.1"),
    );
    let c = tls_config(der, &key, &[&rustls::version::TLS12], None);
    let peer = tokio::spawn(serve_tls(
        listener,
        vec![
            a.clone(),
            a.clone(),
            b.clone(),
            b.clone(),
            c.clone(),
            c.clone(),
            a.clone(),
            c.clone(),
            a,
            b,
        ],
    ));
    let other_peer = tokio::spawn(serve_tls(other, vec![c]));
    let mut configuration = tls_proxy_config(directory.path(), &pem);
    for (agent, source_id) in [("bob", "192.0.2.21"), ("unknown", "192.0.2.22")] {
        configuration.listeners.push(crate::config::AgentListener {
            agent_id: agent.into(),
            source_id: Some(source_id.into()),
            socket_path: directory.path().join(format!("{agent}.sock")),
        });
    }
    let url = format!("https://{address}");
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    for _ in 0..2 {
        request(directory.path(), "alice", &url).await;
    }
    assert_eq!(indicators(&records(&runtime, directory.path())).len(), 1);
    proxy.reload(configuration.clone()).await.unwrap();
    for _ in 0..4 {
        request(directory.path(), "alice", &url).await;
    }
    request(directory.path(), "bob", &url).await;
    request(directory.path(), "unknown", &url).await;
    request(directory.path(), "alice", &url).await;
    request(
        directory.path(),
        "alice",
        &format!("https://{other_address}"),
    )
    .await;
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let clues = indicators(&rows);
    assert_eq!(clues.len(), 6, "{clues:?}");
    assert_eq!(
        clues
            .iter()
            .filter(|r| r["details"]["rule"] == "destination.first_observation.v1")
            .count(),
        3
    );
    let samples: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["event"] == "network.connection"
                && row["agent"] == "alice"
                && row["details"]["state"] == "updated"
                && row["details"]["leg"] == "proxy_to_upstream"
                && row["details"]["requested_target"] == address.to_string()
        })
        .collect();
    assert_eq!(samples.len(), 7, "{rows:?}");
    for sample in &samples {
        assert_eq!(
            sample["details"]["tls_sessions"][0]["leaf_certificate"]["cert_sha256"],
            cert.cert_sha256
        );
    }
    let changes: Vec<_> = clues
        .iter()
        .filter(|r| r["details"]["rule"] == "tls.origin_negotiation_changed.v1")
        .collect();
    assert_eq!(changes.len(), 3);
    for (change, previous_index, current_index, version, alpn) in [
        (changes[0], 1, 2, "TLSv1_2", Some("http/1.1")),
        (changes[1], 3, 4, "TLSv1_2", None),
        (changes[2], 5, 6, "TLSv1_3", Some("http/1.1")),
    ] {
        let evidence = &change["details"]["novelty"];
        assert_eq!(
            change["details"]["indicator_type"],
            "tls_negotiation_change"
        );
        assert_eq!(
            evidence["previous"]["event_id"],
            samples[previous_index]["event_id"]
        );
        assert_eq!(
            evidence["current"]["event_id"],
            samples[current_index]["event_id"]
        );
        assert_eq!(evidence["current"]["negotiation"]["version"], version);
        assert_eq!(evidence["current"]["negotiation"]["alpn"], json!(alpn));
        assert_eq!(evidence["destination"], address.to_string());
        for field in ["current", "previous"] {
            assert_observation(&rows, change, &evidence[field], false);
            assert!(evidence[field]["cert_sha256"].is_null());
        }
    }
    let proxy = Proxy::start(configuration).await.unwrap();
    let restarted = proxy.runtime.read().unwrap().clone();
    request(directory.path(), "alice", &url).await;
    proxy.shutdown().await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    timeout(LIMIT, other_peer).await.unwrap().unwrap();
    let rows = records(&restarted, directory.path());
    let clues: Vec<_> = indicators(&rows)
        .into_iter()
        .filter(|r| r["details"]["runtime_id"] == restarted.instance_id)
        .collect();
    assert_eq!(
        clues.len(),
        1,
        "restart does not restore negotiation history"
    );
    assert_eq!(
        clues[0]["details"]["rule"],
        "destination.first_observation.v1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_concurrent_tls_comparisons_follow_supporting_event_order() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let key = rcgen::KeyPair::generate().unwrap();
    let (pem_a, a, _) = tls_origin(&address.ip().to_string(), &key, 1);
    let (pem_b, mut b, _) = tls_origin(&address.ip().to_string(), &key, 2);
    Arc::make_mut(&mut b).alpn_protocols.clear();
    let peer = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..12 {
            let (socket, _) = listener.accept().await.unwrap();
            let config = if index % 2 == 0 { a.clone() } else { b.clone() };
            tasks.spawn(async move {
                let mut tls = tokio_rustls::TlsAcceptor::from(config)
                    .accept(socket)
                    .await
                    .unwrap();
                head(&mut tls).await;
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nunchanged",
                )
                .await
                .unwrap();
                tls.shutdown().await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let proxy = Proxy::start(tls_proxy_config(
        directory.path(),
        &format!("{pem_a}{pem_b}"),
    ))
    .await
    .unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let path = directory.path().to_owned();
        clients.spawn(async move {
            request(&path, "alice", &format!("https://{address}")).await;
        });
    }
    while let Some(result) = timeout(LIMIT, clients.join_next()).await.unwrap() {
        result.unwrap();
    }
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let samples: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["event"] == "network.connection"
                && row["details"]["state"] == "updated"
                && row["details"]["leg"] == "proxy_to_upstream"
        })
        .collect();
    assert_eq!(samples.len(), 12);
    let expected: Vec<_> = samples
        .windows(2)
        .filter(|pair| {
            pair[0]["details"]["tls_sessions"][0]["leaf_certificate"]["cert_sha256"]
                != pair[1]["details"]["tls_sessions"][0]["leaf_certificate"]["cert_sha256"]
        })
        .collect();
    let clues = indicators(&rows);
    assert_eq!(
        clues
            .iter()
            .filter(|r| r["details"]["rule"] == "destination.first_observation.v1")
            .count(),
        1
    );
    let changes: Vec<_> = clues
        .iter()
        .filter(|r| r["details"]["rule"] == "tls.origin_identity_changed.v1")
        .collect();
    assert_eq!(changes.len(), expected.len());
    assert!(!changes.is_empty());
    for (change, pair) in changes.into_iter().zip(&expected) {
        let evidence = &change["details"]["novelty"];
        assert_eq!(evidence["previous"]["event_id"], pair[0]["event_id"]);
        assert_eq!(evidence["current"]["event_id"], pair[1]["event_id"]);
        assert_observation(&rows, change, &evidence["previous"], true);
        assert_observation(&rows, change, &evidence["current"], true);
    }
    let negotiation_changes: Vec<_> = clues
        .iter()
        .filter(|r| r["details"]["rule"] == "tls.origin_negotiation_changed.v1")
        .collect();
    assert_eq!(negotiation_changes.len(), expected.len());
    for (change, pair) in negotiation_changes.into_iter().zip(expected) {
        let evidence = &change["details"]["novelty"];
        assert_eq!(evidence["previous"]["event_id"], pair[0]["event_id"]);
        assert_eq!(evidence["current"]["event_id"], pair[1]["event_id"]);
        assert_observation(&rows, change, &evidence["previous"], false);
        assert_observation(&rows, change, &evidence["current"], false);
    }
}

#[tokio::test]
async fn native_parent_certificate_changes_and_failed_origin_tls_keep_origin_baseline() {
    let directory = tempfile::tempdir().unwrap();
    let (parent, address) = crate::test_owned_endpoint::bind().await;
    let (pem_pa, pa, _) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        1,
    );
    let (pem_pb, mut pb, _) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        2,
    );
    Arc::make_mut(&mut pb).alpn_protocols.clear();
    let (pem_a, a, cert_a) = tls_origin("origin.invalid", &rcgen::KeyPair::generate().unwrap(), 3);
    let (pem_b, mut b, cert_b) =
        tls_origin("origin.invalid", &rcgen::KeyPair::generate().unwrap(), 4);
    Arc::make_mut(&mut b).alpn_protocols.clear();
    let (pem_wrong, wrong, _) =
        tls_origin("wrong.invalid", &rcgen::KeyPair::generate().unwrap(), 5);
    let peer = tokio::spawn(async move {
        for (outer, inner, valid) in [
            (pa.clone(), a.clone(), true),
            (pb.clone(), a, true),
            (pb, wrong, false),
            (pa, b, true),
        ] {
            let (socket, _) = parent.accept().await.unwrap();
            let mut outer = tokio_rustls::TlsAcceptor::from(outer)
                .accept(socket)
                .await
                .unwrap();
            assert!(
                head(&mut outer)
                    .await
                    .starts_with(b"CONNECT origin.invalid")
            );
            outer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let inner = tokio_rustls::TlsAcceptor::from(inner).accept(outer).await;
            if !valid {
                assert!(inner.is_err());
                continue;
            }
            let mut inner = inner.unwrap();
            head(&mut inner).await;
            inner
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nunchanged",
                )
                .await
                .unwrap();
            inner.shutdown().await.unwrap();
        }
    });
    let mut configuration = tls_proxy_config(
        directory.path(),
        &format!("{pem_pa}{pem_pb}{pem_a}{pem_b}{pem_wrong}"),
    );
    configuration.parent_proxy = Some(format!("https://{address}"));
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    request(directory.path(), "alice", "https://ORIGIN.INVALID.").await;
    request(directory.path(), "alice", "https://origin.invalid").await;
    let failed = response(directory.path(), "alice", "https://origin.invalid").await;
    assert!(
        failed.starts_with(b"HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&failed)
    );
    request(directory.path(), "alice", "https://origin.invalid").await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let clues = indicators(&rows);
    assert_eq!(clues.len(), 3, "{clues:?}");
    let evidence = &clues[1]["details"]["novelty"];
    assert_eq!(evidence["destination"], "origin.invalid:443");
    assert_eq!(evidence["route"], "parent");
    assert_eq!(evidence["verification_name"], "origin.invalid");
    assert_eq!(evidence["previous"]["cert_sha256"], cert_a.cert_sha256);
    assert_eq!(evidence["current"]["cert_sha256"], cert_b.cert_sha256);
    assert_observation(&rows, clues[1], &evidence["previous"], true);
    assert_observation(&rows, clues[1], &evidence["current"], true);
    assert_eq!(
        clues[2]["details"]["rule"],
        "tls.origin_negotiation_changed.v1"
    );
    let negotiation = &clues[2]["details"]["novelty"];
    assert_eq!(negotiation["route"], "parent");
    assert_eq!(
        negotiation["previous"]["event_id"],
        evidence["previous"]["event_id"]
    );
    assert_eq!(
        negotiation["current"]["event_id"],
        evidence["current"]["event_id"]
    );
    assert_eq!(negotiation["previous"]["negotiation"]["alpn"], "http/1.1");
    assert!(negotiation["current"]["negotiation"]["alpn"].is_null());
    assert_observation(&rows, clues[2], &negotiation["previous"], false);
    assert_observation(&rows, clues[2], &negotiation["current"], false);
    let failed = rows
        .iter()
        .find(|r| {
            r["event"] == "network.connection" && r["details"]["error"] == "origin_tls_failed"
        })
        .unwrap();
    assert!(failed["details"]["resolved_origin_peer"].is_null());
    let sessions = failed["details"]["tls_sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["peer"], "parent");
}
