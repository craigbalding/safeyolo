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
    Key::Destination {
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
    if let Key::Destination { route, .. } = &mut other_route {
        *route = "provider";
    }
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
    if let Some(ip) = observation["origin_ip"].as_str() {
        let peer: std::net::SocketAddr = source["details"]["resolved_origin_peer"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(peer.ip().to_canonical().to_string(), ip);
    }
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

fn client_hello(ja3: char) -> ClientHello {
    serde_json::from_value(json!({
        "ja3":ja3.to_string().repeat(32),
        "ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1",
        "sni":"origin.invalid", "alpn_offers":["h2"], "legacy_version":771,
        "supported_versions":[772,771], "cipher_suites":[4865], "cipher_suite_count":1,
        "extension_types":[0,16], "extension_count":2, "truncated":false,
    }))
    .unwrap()
}

#[test]
fn client_fingerprint_history_shares_fifo_and_skips_invalid_metadata() {
    let mut history = History {
        capacity: 2,
        ..History::default()
    };
    let a = client_hello('a');
    let b = client_hello('b');
    assert!(
        history
            .client_fingerprint("alice", &a, observation("first"))
            .unwrap()
            .previous
            .is_none()
    );
    assert!(
        history
            .client_fingerprint("alice", &a, observation("repeat"))
            .is_none()
    );
    for field in ["ja3", "ja4", "sni"] {
        let mut invalid = b.clone();
        match field {
            "ja3" => invalid.ja3 = "unavailable".into(),
            "ja4" => invalid.ja4.clear(),
            _ => invalid.sni = Some("x".repeat(254)),
        }
        assert!(
            history
                .client_fingerprint("alice", &invalid, observation(field))
                .is_none()
        );
    }
    let changed = history
        .client_fingerprint("alice", &b, observation("changed"))
        .unwrap();
    assert_eq!(changed.previous.unwrap().connection_id, "repeat");
    let mut ja4_change = b.clone();
    ja4_change.ja4.replace_range(0..1, "q");
    assert!(
        history
            .client_fingerprint("alice", &ja4_change, observation("ja4-only"))
            .is_some()
    );
    history.destination(&key("alice", "a.invalid:443"), observation("destination"));
    assert!(
        history
            .client_fingerprint("alice", &ja4_change, observation("stable"))
            .is_none()
    );
    assert!(
        history
            .client_fingerprint("bob", &a, observation("bob"))
            .unwrap()
            .previous
            .is_none()
    );
    assert!(
        !history.entries.contains_key(&Key::Client("alice".into())),
        "repetition does not refresh FIFO age"
    );
    assert!(
        history
            .client_fingerprint("alice", &a, observation("after-eviction"))
            .unwrap()
            .previous
            .is_none()
    );
    assert_eq!(history.entries.len(), 2);
    assert_eq!(history.oldest.len(), 2);
}

// Rustls randomizes extension order, which intentionally changes JA3. Fix only
// its two-byte ordering seed in these isolated clients to exercise stable repeats.
#[derive(Debug)]
struct StableExtensionOrder;
impl rustls::crypto::SecureRandom for StableExtensionOrder {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(bytes)?;
        if bytes.len() == 2 {
            bytes.fill(0);
        }
        Ok(())
    }
}

fn fingerprint_client(directory: &Path, changed: bool) -> Arc<rustls::ClientConfig> {
    let ca = crate::tls::CertificateAuthority::load(&directory.join("interception.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.certificate().clone()).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.secure_random = &StableExtensionOrder;
    let versions = if changed {
        &[&rustls::version::TLS12][..]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !changed {
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    tls.resumption = rustls::client::Resumption::disabled();
    Arc::new(tls)
}

async fn fingerprint_request(
    directory: &Path,
    agent: &str,
    address: std::net::SocketAddr,
    tls: Arc<rustls::ClientConfig>,
) {
    let mut socket = fingerprint_socket(directory, agent, address, tls).await;
    socket
        .write_all(format!("GET /path HTTP/1.1\r\nHost: {address}\r\nX-SafeYolo-Agent: forged\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, socket.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(
        reply.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    assert!(reply.ends_with(b"unchanged"));
}

async fn fingerprint_socket(
    directory: &Path,
    agent: &str,
    address: std::net::SocketAddr,
    tls: Arc<rustls::ClientConfig>,
) -> tokio_rustls::client::TlsStream<UnixStream> {
    let mut socket = UnixStream::connect(directory.join(format!("{agent}.sock")))
        .await
        .unwrap();
    socket.write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: ignored.invalid\r\nX-SafeYolo-Agent: forged\r\n\r\n").as_bytes()).await.unwrap();
    assert!(head(&mut socket).await.starts_with(b"HTTP/1.1 200"));
    let name = rustls::pki_types::ServerName::IpAddress(address.ip().into());
    timeout(
        LIMIT,
        tokio_rustls::TlsConnector::from(tls).connect(name, socket),
    )
    .await
    .unwrap()
    .unwrap()
}

fn client_indicators(rows: &[Value]) -> Vec<&Value> {
    indicators(rows)
        .into_iter()
        .filter(|row| row["details"]["novelty"]["current"]["client_fingerprint"].is_object())
        .collect()
}

fn assert_client_links(rows: &[Value]) {
    for clue in client_indicators(rows) {
        let evidence = &clue["details"]["novelty"];
        assert!(evidence["destination"].is_null());
        assert!(evidence["route"].is_null());
        for observation in [&evidence["previous"], &evidence["current"]]
            .into_iter()
            .filter(|o| o.is_object())
        {
            assert_observation(rows, clue, observation, false);
            let source_index = rows
                .iter()
                .position(|r| r["event_id"] == observation["event_id"])
                .unwrap();
            let clue_index = rows.iter().position(|r| r == clue).unwrap();
            assert!(source_index < clue_index);
            let source = &rows[source_index]["details"];
            assert_eq!(source["leg"], "client_to_proxy");
            assert_eq!(source["state"], "updated");
            for field in ["ja3", "ja4"] {
                assert_eq!(
                    source["tls_client_hello"][field],
                    observation["client_fingerprint"][field]
                );
            }
        }
    }
}

#[tokio::test]
async fn native_client_fingerprints_repeat_change_isolate_reload_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let (pem, origin, _) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        1,
    );
    let peer = tokio::spawn(serve_tls(listener, vec![origin; 9]));
    let mut configuration = tls_proxy_config(directory.path(), &pem);
    for (agent, source_id) in [("bob", "192.0.2.21"), ("unknown", "192.0.2.22")] {
        configuration.listeners.push(crate::config::AgentListener {
            agent_id: agent.into(),
            source_id: Some(source_id.into()),
            socket_path: directory.path().join(format!("{agent}.sock")),
        });
    }
    let a = fingerprint_client(directory.path(), false);
    let b = fingerprint_client(directory.path(), true);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    fingerprint_request(directory.path(), "alice", address, a.clone()).await;
    fingerprint_request(directory.path(), "alice", address, a.clone()).await;
    assert_eq!(
        client_indicators(&records(&runtime, directory.path())).len(),
        1
    );
    proxy.reload(configuration.clone()).await.unwrap();
    fingerprint_request(directory.path(), "alice", address, b.clone()).await;
    fingerprint_request(directory.path(), "alice", address, b.clone()).await;
    fingerprint_request(directory.path(), "bob", address, a.clone()).await;
    fingerprint_request(directory.path(), "unknown", address, b).await;
    // An absolute HTTPS request measures proxy-to-origin TLS, not client TLS.
    request(directory.path(), "alice", &format!("https://{address}")).await;
    fingerprint_request(directory.path(), "alice", address, a.clone()).await;
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_client_links(&rows);
    let clues = client_indicators(&rows);
    assert_eq!(clues.len(), 4, "{clues:?}");
    assert_eq!(clues.iter().filter(|r| r["agent"] == "alice").count(), 3);
    assert_eq!(clues[2]["agent"], "bob");
    assert!(clues[2]["details"]["novelty"]["previous"].is_null());
    let samples: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["event"] == "network.connection"
                && r["agent"] == "alice"
                && r["details"]["state"] == "updated"
                && r["details"]["tls_client_hello"].is_object()
        })
        .collect();
    assert_eq!(samples.len(), 5);
    for (clue, previous, current) in [(clues[1], 1, 2), (clues[3], 3, 4)] {
        let evidence = &clue["details"]["novelty"];
        assert_eq!(clue["details"]["rule"], "tls.client_fingerprint_changed.v1");
        assert_eq!(
            evidence["previous"]["event_id"],
            samples[previous]["event_id"]
        );
        assert_eq!(
            evidence["current"]["event_id"],
            samples[current]["event_id"]
        );
        for field in ["ja3", "ja4"] {
            assert_ne!(
                evidence["previous"]["client_fingerprint"][field],
                evidence["current"]["client_fingerprint"][field]
            );
        }
    }
    let previous_runtime = clues[0]["details"]["runtime_id"].clone();
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    fingerprint_request(directory.path(), "alice", address, a).await;
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let clues: Vec<_> = client_indicators(&rows)
        .into_iter()
        .filter(|row| row["details"]["runtime_id"] != previous_runtime)
        .collect();
    assert_eq!(clues.len(), 1);
    assert!(clues[0]["details"]["novelty"]["previous"].is_null());
    assert_ne!(clues[0]["details"]["runtime_id"], previous_runtime);
    timeout(LIMIT, peer).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_concurrent_client_fingerprints_follow_supporting_event_order() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let (pem, origin, _) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        1,
    );
    let peer = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let (socket, _) = listener.accept().await.unwrap();
            let origin = origin.clone();
            tasks.spawn(async move {
                let mut tls = tokio_rustls::TlsAcceptor::from(origin)
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
    let configuration = tls_proxy_config(directory.path(), &pem);
    let a = fingerprint_client(directory.path(), false);
    let b = fingerprint_client(directory.path(), true);
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut clients = tokio::task::JoinSet::new();
    for index in 0..12 {
        let path = directory.path().to_owned();
        let tls = if index % 2 == 0 { a.clone() } else { b.clone() };
        clients.spawn(async move {
            fingerprint_request(&path, "alice", address, tls).await;
        });
    }
    while let Some(result) = timeout(LIMIT, clients.join_next()).await.unwrap() {
        result.unwrap();
    }
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_client_links(&rows);
    assert_client_destination_links(&rows);
    assert_eq!(client_destination_indicators(&rows).len(), 2);
    let samples: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["event"] == "network.connection"
                && r["details"]["state"] == "updated"
                && r["details"]["tls_client_hello"].is_object()
        })
        .collect();
    assert_eq!(samples.len(), 12);
    let changes: Vec<_> = samples
        .windows(2)
        .filter(|pair| {
            ["ja3", "ja4"].iter().any(|field| {
                pair[0]["details"]["tls_client_hello"][field]
                    != pair[1]["details"]["tls_client_hello"][field]
            })
        })
        .collect();
    assert!(!changes.is_empty());
    let clues = client_indicators(&rows);
    assert_eq!(clues.len(), changes.len() + 1);
    assert!(clues[0]["details"]["novelty"]["previous"].is_null());
    for (clue, pair) in clues.into_iter().skip(1).zip(changes) {
        assert_eq!(
            clue["details"]["novelty"]["previous"]["event_id"],
            pair[0]["event_id"]
        );
        assert_eq!(
            clue["details"]["novelty"]["current"]["event_id"],
            pair[1]["event_id"]
        );
    }
}

#[tokio::test]
async fn native_incomplete_and_unsupported_client_hellos_do_not_establish_history() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            // TLS classification can close the upstream before any TLS bytes.
            socket.read_to_end(&mut bytes).await.unwrap();
        }
    });
    let configuration = tls_proxy_config(directory.path(), "");
    let tls = fingerprint_client(directory.path(), false);
    let name = rustls::pki_types::ServerName::IpAddress(address.ip().into());
    let mut client = rustls::ClientConnection::new(tls, name).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut unsupported = hello.clone();
    unsupported[5] = 2; // ServerHello is not client fingerprint evidence.
    hello.pop(); // Incomplete handshake framing must remain unavailable.
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    for wire in [hello, unsupported] {
        let mut socket = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        socket
            .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        assert!(head(&mut socket).await.starts_with(b"HTTP/1.1 200"));
        socket.write_all(&wire).await.unwrap();
        socket.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(LIMIT, socket.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
    }
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert!(client_indicators(&rows).is_empty());
    assert!(client_destination_indicators(&rows).is_empty());
    assert!(
        rows.iter()
            .filter(|r| r["event"] == "network.connection")
            .all(|r| r["details"]["tls_client_hello"].is_null())
    );
    let history = runtime
        .connection_events
        .as_ref()
        .unwrap()
        .novelty
        .lock()
        .unwrap();
    assert!(!history.entries.contains_key(&Key::Client("alice".into())));
}

#[test]
fn origin_spki_history_requires_measured_pairs_and_shares_finite_fifo() {
    let mut history = History {
        capacity: 3,
        ..History::default()
    };
    let destination = Destination::new("ORIGIN.INVALID.", 443, "direct");
    let a = "192.0.2.1".parse().unwrap();
    let b = "2001:db8::2".parse().unwrap();
    let measured = session('a', Some('b'));
    assert!(
        history
            .origin_spki(
                "alice",
                &destination,
                ("origin.invalid", &measured),
                Some(a),
                observation("first")
            )
            .is_none()
    );
    assert!(
        history
            .origin_spki(
                "alice",
                &destination,
                ("origin.invalid", &measured),
                Some(a),
                observation("repeat")
            )
            .is_none()
    );
    for field in [
        "parent",
        "provider",
        "resumed",
        "unknown-handshake",
        "missing-cert",
        "missing-spki",
        "invalid-spki",
        "missing-ip",
    ] {
        let mut unavailable = measured.clone();
        match field {
            "parent" | "provider" => unavailable.peer = field.into(),
            "resumed" => unavailable.handshake_kind = Some("Resumed".into()),
            "unknown-handshake" => unavailable.handshake_kind = None,
            "missing-cert" => unavailable.leaf_certificate = None,
            "missing-spki" => unavailable.leaf_certificate.as_mut().unwrap().spki_sha256 = None,
            "invalid-spki" => {
                unavailable.leaf_certificate.as_mut().unwrap().spki_sha256 =
                    Some("unmeasured".into())
            }
            _ => (),
        }
        assert!(
            history
                .origin_spki(
                    "alice",
                    &destination,
                    ("origin.invalid", &unavailable),
                    (field != "missing-ip").then_some(b),
                    observation(field)
                )
                .is_none()
        );
        assert_eq!(
            history.entries.len(),
            1,
            "{field} cannot establish an association"
        );
    }
    let mapped = "::ffff:192.0.2.1".parse().unwrap();
    assert!(
        history
            .origin_spki(
                "alice",
                &destination,
                ("other.invalid", &measured),
                Some(mapped),
                observation("mapped-repeat")
            )
            .is_none()
    );
    assert_eq!(history.entries.len(), 1);
    let changed = history
        .origin_spki(
            "alice",
            &destination,
            ("origin.invalid", &measured),
            Some(b),
            observation("new-ip"),
        )
        .unwrap();
    assert!(changed.valid(Some("new-ip")));
    assert_eq!(
        changed.previous.as_ref().unwrap().connection_id,
        "mapped-repeat"
    );
    assert_eq!(changed.current.origin_ip, Some(b));
    assert!(
        history
            .origin_spki(
                "alice",
                &destination,
                ("origin.invalid", &measured),
                Some(a),
                observation("return")
            )
            .is_none(),
        "returning to a retained IP is stable"
    );
    let c = "192.0.2.3".parse().unwrap();
    let changed = history
        .origin_spki(
            "alice",
            &destination,
            ("origin.invalid", &measured),
            Some(c),
            observation("third-ip"),
        )
        .unwrap();
    assert_eq!(
        changed.previous.unwrap().connection_id,
        "new-ip",
        "choose the most recently inserted retained IP"
    );
    history.client_fingerprint("bob", &client_hello('a'), observation("bob-client"));
    assert_eq!(history.entries.len(), 3);
    assert!(!history.entries.contains_key(&Key::OriginSpki {
        agent: "alice".into(),
        spki_sha256: "b".repeat(64),
        ip: a
    }));
    let changed = history
        .origin_spki(
            "alice",
            &destination,
            ("origin.invalid", &measured),
            Some(a),
            observation("after-eviction"),
        )
        .unwrap();
    assert_eq!(changed.previous.unwrap().connection_id, "third-ip");
    history.destination(&key("bob", "one.invalid:443"), observation("one"));
    history.destination(&key("bob", "two.invalid:443"), observation("two"));
    history.destination(&key("bob", "three.invalid:443"), observation("three"));
    assert!(
        history
            .origin_spki(
                "alice",
                &destination,
                ("origin.invalid", &measured),
                Some(b),
                observation("all-lost")
            )
            .is_none(),
        "no retained key is a fresh baseline"
    );
    assert_eq!(history.entries.len(), history.oldest.len());
}

fn spki_ip_indicators(rows: &[Value]) -> Vec<&Value> {
    indicators(rows)
        .into_iter()
        .filter(|row| row["details"]["rule"] == "tls.origin_spki_new_ip.v1")
        .collect()
}

async fn two_origin_ips() -> (
    TcpListener,
    std::net::SocketAddr,
    TcpListener,
    std::net::SocketAddr,
) {
    let (first, a) = crate::test_owned_endpoint::bind().await;
    // The second owned loopback works on hosts where only ::1 is available
    // to bind() as well. These fixtures disable the private-address guard.
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b = second.local_addr().unwrap();
    assert_ne!(a.ip(), b.ip());
    (first, a, second, b)
}

#[tokio::test]
async fn native_origin_spki_new_ip_repeats_ports_agents_failure_reload_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (first, a, second, b) = two_origin_ips().await;
    let (other_port, a2) = crate::test_owned_endpoint::bind_on(a.ip()).await;
    let failed_listener = TcpListener::bind((b.ip(), 0)).await.unwrap();
    let failed_address = failed_listener.local_addr().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let (pem_a, tls_a, cert_a) = tls_origin(&a.ip().to_string(), &key, 1);
    let (pem_b, tls_b, cert_b) = tls_origin(&b.ip().to_string(), &key, 2);
    let (pem_different, different, cert_different) =
        tls_origin(&b.ip().to_string(), &rcgen::KeyPair::generate().unwrap(), 3);
    let (pem_wrong, wrong, _) = tls_origin("wrong.invalid", &key, 4);
    assert_eq!(cert_a.spki_sha256, cert_b.spki_sha256);
    assert_ne!(cert_a.spki_sha256, cert_different.spki_sha256);
    let first_peer = tokio::spawn(serve_tls(first, vec![tls_a.clone(); 4]));
    let port_peer = tokio::spawn(serve_tls(other_port, vec![tls_a]));
    let second_peer = tokio::spawn(serve_tls(
        second,
        vec![
            tls_b.clone(),
            tls_b.clone(),
            different,
            tls_b.clone(),
            tls_b.clone(),
            tls_b.clone(),
            tls_b,
        ],
    ));
    let failed_peer = tokio::spawn(async move {
        let (socket, _) = failed_listener.accept().await.unwrap();
        assert!(
            tokio_rustls::TlsAcceptor::from(wrong)
                .accept(socket)
                .await
                .is_err()
        );
    });
    let mut configuration = tls_proxy_config(
        directory.path(),
        &format!("{pem_a}{pem_b}{pem_different}{pem_wrong}"),
    );
    configuration.network_guard_enabled = false;
    for (agent, source_id) in [("bob", "192.0.2.21"), ("unknown", "192.0.2.22")] {
        configuration.listeners.push(crate::config::AgentListener {
            agent_id: agent.into(),
            source_id: Some(source_id.into()),
            socket_path: directory.path().join(format!("{agent}.sock")),
        });
    }
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    for address in [a, a, a2] {
        request(directory.path(), "alice", &format!("https://{address}")).await;
    }
    for agent in ["bob", "unknown"] {
        request(directory.path(), agent, &format!("https://{b}")).await;
    }
    let failed = response(
        directory.path(),
        "alice",
        &format!("https://{failed_address}"),
    )
    .await;
    assert!(failed.starts_with(b"HTTP/1.1 502"));
    request(directory.path(), "alice", &format!("https://{b}")).await; // Different key.
    assert!(spki_ip_indicators(&records(&runtime, directory.path())).is_empty());
    for _ in 0..2 {
        request(directory.path(), "alice", &format!("https://{b}")).await;
    }
    proxy.reload(configuration.clone()).await.unwrap();
    for address in [a, b] {
        request(directory.path(), "alice", &format!("https://{address}")).await;
    }
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let clues = spki_ip_indicators(&rows);
    assert_eq!(clues.len(), 1, "{clues:?}");
    let clue = clues[0];
    assert_eq!(clue["agent"], "alice");
    assert_eq!(clue["details"]["indicator_type"], "tls_spki_new_origin_ip");
    let evidence = &clue["details"]["novelty"];
    assert_eq!(evidence["destination"], b.to_string());
    assert_eq!(evidence["verification_name"], b.ip().to_string());
    assert_eq!(evidence["route"], "direct");
    for (field, address, cert) in [("previous", a, &cert_a), ("current", b, &cert_b)] {
        assert_eq!(evidence[field]["origin_ip"], address.ip().to_string());
        assert_eq!(evidence[field]["cert_sha256"], cert.cert_sha256);
        assert_eq!(evidence[field]["spki_sha256"], json!(cert.spki_sha256));
        assert_observation(&rows, clue, &evidence[field], true);
    }
    let prior = rows
        .iter()
        .find(|row| row["event_id"] == evidence["previous"]["event_id"])
        .unwrap();
    assert_eq!(
        prior["details"]["resolved_origin_peer"],
        a2.to_string(),
        "a new port refreshes the same IP's supporting link"
    );
    assert!(rows.iter().any(|r| r["event"] == "network.connection"
        && r["details"]["error"] == "origin_tls_failed"
        && r["details"]["resolved_origin_peer"] == failed_address.to_string()
        && r["details"]["tls_sessions"].is_null()));
    assert!(rows.iter().any(|r| r["event"] == "network.connection"
        && r["details"]["attribution"]["attribution_status"] == "unavailable"));
    let proxy = Proxy::start(configuration).await.unwrap();
    let restarted = proxy.runtime.read().unwrap().clone();
    request(directory.path(), "alice", &format!("https://{b}")).await;
    assert!(
        spki_ip_indicators(&records(&restarted, directory.path()))
            .iter()
            .all(|r| r["details"]["runtime_id"] != restarted.instance_id)
    );
    request(directory.path(), "alice", &format!("https://{a}")).await;
    proxy.shutdown().await;
    let rows = records(&restarted, directory.path());
    let clues: Vec<_> = spki_ip_indicators(&rows)
        .into_iter()
        .filter(|r| r["details"]["runtime_id"] == restarted.instance_id)
        .collect();
    assert_eq!(
        clues.len(),
        1,
        "retained audit rows do not restore associations"
    );
    for peer in [first_peer, port_peer, second_peer, failed_peer] {
        timeout(LIMIT, peer).await.unwrap().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_origin_spki_concurrency_uses_supporting_audit_order() {
    let directory = tempfile::tempdir().unwrap();
    let (first, a, second, b) = two_origin_ips().await;
    let key = rcgen::KeyPair::generate().unwrap();
    let (pem_a, tls_a, _) = tls_origin(&a.ip().to_string(), &key, 1);
    let (pem_b, tls_b, _) = tls_origin(&b.ip().to_string(), &key, 2);
    let peers = [
        tokio::spawn(serve_tls(first, vec![tls_a; 6])),
        tokio::spawn(serve_tls(second, vec![tls_b; 6])),
    ];
    let mut configuration = tls_proxy_config(directory.path(), &format!("{pem_a}{pem_b}"));
    configuration.network_guard_enabled = false;
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut clients = tokio::task::JoinSet::new();
    for address in [a, b].into_iter().cycle().take(12) {
        let path = directory.path().to_owned();
        clients.spawn(async move {
            request(&path, "alice", &format!("https://{address}")).await;
        });
    }
    while let Some(result) = clients.join_next().await {
        result.unwrap();
    }
    for peer in peers {
        timeout(LIMIT, peer).await.unwrap().unwrap();
    }
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    let samples: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["event"] == "network.connection"
                && row["details"]["state"] == "updated"
                && row["details"]["tls_sessions"][0]["peer"] == "origin"
        })
        .collect();
    assert_eq!(samples.len(), 12);
    let first_ip: std::net::SocketAddr = samples[0]["details"]["resolved_origin_peer"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let other_index = samples
        .iter()
        .position(|row| {
            row["details"]["resolved_origin_peer"]
                .as_str()
                .unwrap()
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip()
                != first_ip.ip()
        })
        .unwrap();
    let clues = spki_ip_indicators(&rows);
    assert_eq!(clues.len(), 1, "{clues:?}");
    let evidence = &clues[0]["details"]["novelty"];
    assert_eq!(
        evidence["previous"]["event_id"],
        samples[other_index - 1]["event_id"]
    );
    assert_eq!(
        evidence["current"]["event_id"],
        samples[other_index]["event_id"]
    );
    for field in ["previous", "current"] {
        assert_observation(&rows, clues[0], &evidence[field], true);
    }
}

#[tokio::test]
async fn native_origin_spki_does_not_treat_a_parent_peer_as_a_new_origin_ip() {
    let directory = tempfile::tempdir().unwrap();
    let (origin, a, parent, b) = two_origin_ips().await;
    let key = rcgen::KeyPair::generate().unwrap();
    let (pem_a, tls_a, _) = tls_origin(&a.ip().to_string(), &key, 1);
    let (pem_b, tls_b, _) = tls_origin(&b.ip().to_string(), &key, 2);
    let first_peer = tokio::spawn(serve_tls(origin, vec![tls_a.clone()]));
    let parent_peer = tokio::spawn(async move {
        let (socket, _) = parent.accept().await.unwrap();
        let mut outer = tokio_rustls::TlsAcceptor::from(tls_b)
            .accept(socket)
            .await
            .unwrap();
        assert!(head(&mut outer).await.starts_with(b"CONNECT "));
        outer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let mut inner = tokio_rustls::TlsAcceptor::from(tls_a)
            .accept(outer)
            .await
            .unwrap();
        head(&mut inner).await;
        inner
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nunchanged",
            )
            .await
            .unwrap();
        inner.shutdown().await.unwrap();
    });
    let mut configuration = tls_proxy_config(directory.path(), &format!("{pem_a}{pem_b}"));
    configuration.network_guard_enabled = false;
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    request(directory.path(), "alice", &format!("https://{a}")).await;
    configuration.parent_proxy = Some(format!("https://{b}"));
    proxy.reload(configuration).await.unwrap();
    request(directory.path(), "alice", &format!("https://{a}")).await;
    for peer in [first_peer, parent_peer] {
        timeout(LIMIT, peer).await.unwrap().unwrap();
    }
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert!(spki_ip_indicators(&rows).is_empty());
    let parent_record = rows
        .iter()
        .find(|r| {
            r["event"] == "network.connection"
                && r["details"]["state"] == "updated"
                && r["details"]["tls_sessions"]
                    .as_array()
                    .is_some_and(|s| s.len() == 2)
        })
        .unwrap();
    assert_eq!(parent_record["details"]["route"], "parent");
    assert_eq!(parent_record["details"]["resolved_peer"], b.to_string());
    assert!(parent_record["details"]["resolved_origin_peer"].is_null());
    let sessions = parent_record["details"]["tls_sessions"].as_array().unwrap();
    assert_eq!(sessions[0]["peer"], "parent");
    assert_eq!(sessions[1]["peer"], "origin");
    assert_eq!(
        sessions[0]["leaf_certificate"]["spki_sha256"],
        sessions[1]["leaf_certificate"]["spki_sha256"],
        "even the same key on a parent does not measure an origin association"
    );
}

fn client_destination_indicators(rows: &[Value]) -> Vec<&Value> {
    indicators(rows)
        .into_iter()
        .filter(|row| row["details"]["rule"] == "tls.client_destination_first_observation.v1")
        .collect()
}

fn assert_client_destination_links(rows: &[Value]) {
    for clue in client_destination_indicators(rows) {
        let evidence = &clue["details"]["novelty"];
        assert_eq!(
            clue["details"]["indicator_type"],
            "tls_client_destination_novelty"
        );
        assert!(evidence["previous"].is_null());
        assert!(evidence["verification_name"].is_null());
        assert_eq!(
            clue["details"]["connection_id"],
            evidence["current"]["connection_id"]
        );
        for observation in [&evidence["current"], &evidence["client"]] {
            assert_observation(rows, clue, observation, false);
            let source = rows
                .iter()
                .position(|row| row["event_id"] == observation["event_id"])
                .unwrap();
            let indication = rows.iter().position(|row| row == clue).unwrap();
            assert!(source < indication);
        }
        let current = rows
            .iter()
            .find(|row| row["event_id"] == evidence["current"]["event_id"])
            .unwrap();
        assert_eq!(current["details"]["leg"], "proxy_to_upstream");
        assert_eq!(
            current["details"]["client_connection_id"],
            evidence["client"]["connection_id"]
        );
        assert_eq!(current["details"]["route"], evidence["route"]);
        let client = rows
            .iter()
            .find(|row| row["event_id"] == evidence["client"]["event_id"])
            .unwrap();
        assert_eq!(client["details"]["leg"], "client_to_proxy");
        for field in ["ja3", "ja4"] {
            assert_eq!(
                client["details"]["tls_client_hello"][field],
                evidence["client"]["client_fingerprint"][field]
            );
        }
    }
}

#[test]
fn client_destination_history_normalizes_and_keeps_interleaved_pairs_until_shared_eviction() {
    let mut history = History {
        capacity: 6,
        ..History::default()
    };
    let a = observation("client-a")
        .with_client_fingerprint(&client_hello('a'))
        .unwrap();
    let mut hello_b = client_hello('a');
    hello_b.ja4.replace_range(0..1, "q");
    let b = observation("client-b")
        .with_client_fingerprint(&hello_b)
        .unwrap();
    for (agent, host, route, client, expected) in [
        ("alice", "ORIGIN.INVALID.", "direct", &a, true),
        ("alice", "origin.invalid", "direct", &a, false),
        ("alice", "origin.invalid", "direct", &b, true),
        ("alice", "other.invalid", "direct", &a, true),
        ("alice", "origin.invalid", "direct", &a, false),
        ("alice", "origin.invalid", "direct", &b, false),
        ("alice", "origin.invalid", "parent", &a, true),
        ("alice", "origin.invalid", "provider", &a, true),
        ("bob", "origin.invalid", "direct", &a, true),
    ] {
        let destination = Destination::new(host, 443, route);
        let result = history.client_destination(
            agent,
            &destination,
            client.clone(),
            observation("upstream"),
        );
        assert_eq!(result.is_some(), expected, "{agent}/{host}/{route}");
        if let Some(evidence) = result {
            assert!(evidence.valid(Some("upstream")));
        }
    }
    assert_eq!(history.entries.len(), 6);
    assert!(
        history
            .client_destination(
                "alice",
                &Destination::new("origin.invalid", 443, "direct"),
                observation("no-hello"),
                observation("upstream")
            )
            .is_none()
    );
    assert_eq!(
        history.entries.len(),
        6,
        "missing fingerprints consume no history"
    );
    // Destination, fingerprint and pair entries all use the same FIFO.
    history.destination(&key("alice", "unrelated:80"), observation("plain"));
    assert!(
        history
            .client_destination(
                "alice",
                &Destination::new("origin.invalid", 443, "direct"),
                a.clone(),
                observation("after-eviction")
            )
            .is_some()
    );
    assert!(
        history
            .client_destination(
                "alice",
                &Destination::new("origin.invalid", 8443, "direct"),
                a.clone(),
                observation("port-change")
            )
            .is_some()
    );
    assert!(
        history
            .client_destination(
                "alice",
                &Destination::new("2001:0DB8:0:0:0:0:0:1", 443, "direct"),
                a.clone(),
                observation("ipv6")
            )
            .is_some()
    );
    assert!(
        history
            .client_destination(
                "alice",
                &Destination::new("2001:db8::1", 443, "direct"),
                a,
                observation("ipv6-repeat")
            )
            .is_none()
    );
    assert_eq!(history.entries.len(), 6);
}

#[tokio::test]
async fn native_client_destination_pairs_distinguish_new_fingerprints_destinations_and_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let (one, address_one) = crate::test_owned_endpoint::bind().await;
    let (two, address_two) = crate::test_owned_endpoint::bind().await;
    let (plain, address_plain) = crate::test_owned_endpoint::bind().await;
    let (pem, origin, _) = tls_origin(
        &address_one.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        1,
    );
    let peer_one = tokio::spawn(serve_tls(one, vec![origin.clone(); 9]));
    let peer_two = tokio::spawn(serve_tls(two, vec![origin.clone(); 2]));
    let peer_plain = tokio::spawn(serve_tls(plain, vec![origin; 1]));
    let mut configuration = tls_proxy_config(directory.path(), &pem);
    for (agent, source) in [("bob", "192.0.2.21"), ("unknown", "192.0.2.22")] {
        configuration.listeners.push(crate::config::AgentListener {
            agent_id: agent.into(),
            source_id: Some(source.into()),
            socket_path: directory.path().join(format!("{agent}.sock")),
        });
    }
    let a = fingerprint_client(directory.path(), false);
    let b = fingerprint_client(directory.path(), true);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    for (agent, destination, tls) in [
        ("alice", address_one, a.clone()),
        ("alice", address_one, a.clone()),
        ("alice", address_one, b.clone()),
        ("alice", address_two, a.clone()),
        ("alice", address_one, a.clone()),
        ("alice", address_one, b.clone()),
        ("alice", address_two, b.clone()),
        ("bob", address_one, a.clone()),
        ("unknown", address_one, b),
    ] {
        fingerprint_request(directory.path(), agent, destination, tls).await;
    }
    request(
        directory.path(),
        "alice",
        &format!("https://{address_plain}"),
    )
    .await;
    let rows = records(&runtime, directory.path());
    let pairs = client_destination_indicators(&rows);
    assert_eq!(pairs.len(), 5);
    assert_eq!(
        pairs.iter().filter(|row| row["agent"] == "alice").count(),
        4
    );
    assert_eq!(
        pairs[0]["details"]["novelty"]["destination"],
        address_one.to_string()
    );
    assert_eq!(
        pairs[1]["details"]["novelty"]["destination"],
        address_one.to_string()
    );
    assert_eq!(
        pairs[2]["details"]["novelty"]["destination"],
        address_two.to_string()
    );
    let fp =
        |index: usize| pairs[index]["details"]["novelty"]["client"]["client_fingerprint"].clone();
    assert_ne!(
        fp(0),
        fp(1),
        "a fingerprint change is visible at the same destination"
    );
    assert_eq!(
        fp(0),
        fp(2),
        "a destination change preserves the fingerprint"
    );
    proxy.reload(configuration.clone()).await.unwrap();
    fingerprint_request(directory.path(), "alice", address_one, a.clone()).await;
    assert_eq!(
        client_destination_indicators(&records(&runtime, directory.path())).len(),
        5
    );
    proxy.shutdown().await;
    let old_runtime = runtime.instance_id.clone();
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    fingerprint_request(directory.path(), "alice", address_one, a).await;
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_client_destination_links(&rows);
    assert_eq!(
        client_destination_indicators(&rows)
            .iter()
            .filter(|row| row["details"]["runtime_id"] != old_runtime)
            .count(),
        1
    );
    for peer in [peer_one, peer_two, peer_plain] {
        timeout(LIMIT, peer).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn native_client_destination_reused_tls_keeps_its_fingerprint_across_parent_reload() {
    let directory = tempfile::tempdir().unwrap();
    let (direct, address) = crate::test_owned_endpoint::bind().await;
    let (parent, parent_address) = crate::test_owned_endpoint::bind().await;
    let (pem, origin, _) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        1,
    );
    let direct_origin = origin.clone();
    let direct_peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (socket, _) = direct.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(direct_origin.clone())
                .accept(socket)
                .await
                .unwrap();
            keepalive_origin(tls).await;
        }
    });
    let parent_peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = parent.accept().await.unwrap();
            assert!(
                head(&mut socket)
                    .await
                    .starts_with(format!("CONNECT {address} HTTP/1.1").as_bytes())
            );
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(origin.clone())
                .accept(socket)
                .await
                .unwrap();
            keepalive_origin(tls).await;
        }
    });
    let mut configuration = tls_proxy_config(directory.path(), &pem);
    let a = fingerprint_client(directory.path(), false);
    let b = fingerprint_client(directory.path(), true);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut old_client = fingerprint_socket(directory.path(), "alice", address, a).await;
    keepalive_request(&mut old_client, address).await;
    // The agent's newest hello now belongs to a different accepted connection.
    fingerprint_request(directory.path(), "alice", address, b).await;
    configuration.parent_proxy = Some(format!("http://{parent_address}"));
    proxy.reload(configuration).await.unwrap();
    keepalive_request(&mut old_client, address).await;
    keepalive_request(&mut old_client, address).await;
    {
        let mut history = runtime
            .connection_events
            .as_ref()
            .unwrap()
            .novelty
            .lock()
            .unwrap();
        history.capacity = 1;
        history.destination(&key("alice", "evict.invalid:80"), observation("eviction"));
    }
    // Closing these already compared attempts must not recreate evicted pairs.
    drop(old_client);
    for peer in [direct_peer, parent_peer] {
        timeout(LIMIT, peer).await.unwrap().unwrap();
    }
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_client_destination_links(&rows);
    let pairs = client_destination_indicators(&rows);
    assert_eq!(pairs.len(), 3);
    let first = &pairs[0]["details"]["novelty"];
    let parent = &pairs[2]["details"]["novelty"];
    assert_eq!(first["route"], "direct");
    assert_eq!(parent["route"], "parent");
    assert_eq!(first["destination"], parent["destination"]);
    assert_eq!(
        first["client"], parent["client"],
        "reuse links the original client hello, not the agent's latest"
    );
    assert_ne!(pairs[1]["details"]["novelty"]["client"], first["client"]);
    let client_id = &first["client"]["connection_id"];
    assert_eq!(
        rows.iter()
            .filter(|row| row["event"] == "traffic.flow"
                && row["details"]["client_connection_id"] == *client_id
                && row["details"]["server_connection_id"].is_string())
            .count(),
        4,
        "CONNECT plus three transactions belong to this client"
    );
}

async fn keepalive_origin(mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) {
    assert!(head(&mut tls).await.starts_with(b"GET /path HTTP/1.1"));
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nunchanged")
        .await
        .unwrap();
    tls.shutdown().await.unwrap();
}

async fn keepalive_request(
    tls: &mut tokio_rustls::client::TlsStream<UnixStream>,
    address: std::net::SocketAddr,
) {
    tls.write_all(format!("GET /path HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(head(tls).await.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 9];
    timeout(LIMIT, tls.read_exact(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&body, b"unchanged");
}

#[tokio::test]
async fn native_client_destination_complete_hello_and_aborted_handshake_establish_attempt_only() {
    let directory = tempfile::tempdir().unwrap();
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "the aborted client did not initiate origin TLS or HTTP"
        );
    });
    let configuration = tls_proxy_config(directory.path(), "");
    let tls = fingerprint_client(directory.path(), false);
    let mut client = rustls::ClientConnection::new(
        tls,
        rustls::pki_types::ServerName::IpAddress(address.ip().into()),
    )
    .unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let proxy = Proxy::start(configuration).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut socket = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    socket
        .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(head(&mut socket).await.starts_with(b"HTTP/1.1 200"));
    socket.write_all(&wire).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, socket.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_client_destination_links(&rows);
    assert_eq!(client_destination_indicators(&rows).len(), 1);
    assert!(
        rows.iter()
            .filter(|row| row["event"] == "network.connection")
            .all(|row| row["details"]["tls_sessions"].is_null())
    );
    assert!(
        rows.iter()
            .any(|row| row["event"] == "network.connection" && row["details"]["state"] == "failed")
    );
}

#[tokio::test]
async fn native_client_destination_failed_later_attempt_uses_the_original_hello() {
    let directory = tempfile::tempdir().unwrap();
    let (direct, address) = crate::test_owned_endpoint::bind().await;
    let (parent, parent_address) = crate::test_owned_endpoint::bind().await;
    drop(parent);
    let (pem, origin, _) = tls_origin(
        &address.ip().to_string(),
        &rcgen::KeyPair::generate().unwrap(),
        1,
    );
    let peer = tokio::spawn(async move {
        let (socket, _) = direct.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(origin)
            .accept(socket)
            .await
            .unwrap();
        keepalive_origin(tls).await;
    });
    let mut configuration = tls_proxy_config(directory.path(), &pem);
    let tls = fingerprint_client(directory.path(), false);
    let mut proxy = Proxy::start(configuration.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let mut client = fingerprint_socket(directory.path(), "alice", address, tls).await;
    keepalive_request(&mut client, address).await;
    configuration.parent_proxy = Some(format!("http://{parent_address}"));
    proxy.reload(configuration).await.unwrap();
    client
        .write_all(
            format!("GET /path HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut reply = Vec::new();
    timeout(LIMIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 502"));
    timeout(LIMIT, peer).await.unwrap().unwrap();
    proxy.shutdown().await;
    let rows = records(&runtime, directory.path());
    assert_client_destination_links(&rows);
    let pairs = client_destination_indicators(&rows);
    assert_eq!(pairs.len(), 2);
    let evidence = &pairs[1]["details"]["novelty"];
    assert_eq!(evidence["route"], "parent");
    assert_eq!(evidence["destination"], address.to_string());
    assert_eq!(evidence["client"], pairs[0]["details"]["novelty"]["client"]);
    let attempt = rows
        .iter()
        .find(|row| row["event_id"] == evidence["current"]["event_id"])
        .unwrap();
    assert_eq!(attempt["details"]["state"], "failed");
    assert_eq!(attempt["details"]["error"], "connect_failed");
    assert!(attempt["details"]["remote_endpoint"].is_null());
    assert!(attempt["details"]["tls_sessions"].is_null());
}
