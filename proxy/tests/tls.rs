use std::{path::Path, process::Command, sync::Arc};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{ServerName, UnixTime},
};
use safeyolo_proxy::tls::CertificateAuthority;
use time::{Duration, OffsetDateTime};

fn ca_pem(not_before: OffsetDateTime, not_after: OffsetDateTime, is_ca: bool) -> (String, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    }
    let certificate = params.self_signed(&key).unwrap();
    (format!("{}{}", key.serialize_pem(), certificate.pem()), key)
}

fn verifier(ca: &CertificateAuthority) -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate().clone()).unwrap();
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap()
}

fn check_leaf(ca: &CertificateAuthority, host: &str) {
    let now = OffsetDateTime::now_utc();
    let leaf = ca.issue(host, now).unwrap();
    leaf.keys_match().unwrap();
    assert_eq!(&leaf.cert[1], ca.certificate());
    let verifier = verifier(ca);
    let now =
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(now.unix_timestamp() as u64));
    verifier
        .verify_server_cert(
            &leaf.cert[0],
            &[],
            &ServerName::try_from(host).unwrap(),
            &[],
            now,
        )
        .unwrap();
    assert!(
        verifier
            .verify_server_cert(
                &leaf.cert[0],
                &[],
                &ServerName::try_from("other.invalid").unwrap(),
                &[],
                now
            )
            .is_err()
    );
}

#[test]
fn imported_ca_issues_only_the_requested_dns_or_ip_name() {
    let now = OffsetDateTime::now_utc();
    let (pem, _) = ca_pem(now - Duration::days(1), now + Duration::days(365), true);
    let ca = CertificateAuthority::from_pem(pem.as_bytes()).unwrap();
    for host in ["example.invalid", "127.0.0.1", "::1"] {
        check_leaf(&ca, host);
    }
    for invalid in ["", "example.invalid:443", "host/path", "*.example.invalid"] {
        assert!(ca.issue(invalid, now).is_err(), "{invalid}");
    }
}

#[test]
fn missing_mismatched_or_invalid_ca_never_creates_a_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mitmproxy-ca.pem");
    assert!(CertificateAuthority::load(&path).is_err());
    assert!(!path.exists());
    let now = OffsetDateTime::now_utc();
    let (pem, _) = ca_pem(now - Duration::days(1), now + Duration::days(1), true);
    let (_, different_key) = ca_pem(now - Duration::days(1), now + Duration::days(1), true);
    let (_, certificate) = pem.split_once("-----BEGIN CERTIFICATE-----").unwrap();
    let mismatched = format!(
        "{}-----BEGIN CERTIFICATE-----{}",
        different_key.serialize_pem(),
        certificate
    );
    for invalid in [
        mismatched,
        ca_pem(now - Duration::days(1), now + Duration::days(1), false).0,
        "not a PEM file".to_owned(),
    ] {
        std::fs::write(&path, &invalid).unwrap();
        assert!(CertificateAuthority::load(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
    }
}

#[test]
fn ca_validity_and_leaf_validity_remain_explicit() {
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    for (before, after) in [
        (now - Duration::days(2), now - Duration::days(1)),
        (now + Duration::days(1), now + Duration::days(2)),
    ] {
        let (pem, _) = ca_pem(before, after, true);
        let ca = CertificateAuthority::from_pem(pem.as_bytes()).unwrap();
        assert!(ca.issue("example.invalid", now).is_err());
    }
    let (pem, _) = ca_pem(now - Duration::days(1), now + Duration::days(1), true);
    let ca = CertificateAuthority::from_pem(pem.as_bytes()).unwrap();
    let leaf = ca.issue("example.invalid", now).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf.cert[0]).unwrap();
    assert_eq!(
        parsed.validity().not_after.to_datetime(),
        now + Duration::days(1)
    );
    let name = ServerName::try_from("example.invalid").unwrap();
    for time in [now - Duration::days(3), now + Duration::days(2)] {
        assert!(
            verifier(&ca)
                .verify_server_cert(
                    &leaf.cert[0],
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        time.unix_timestamp() as u64
                    )),
                )
                .is_err()
        );
    }
}

fn assert_load_preserves_file(path: &Path) {
    let original = std::fs::read(path).unwrap();
    let ca = CertificateAuthority::load(path).unwrap();
    check_leaf(&ca, "example.invalid");
    let reloaded = CertificateAuthority::load(path).unwrap();
    assert_eq!(ca.certificate(), reloaded.certificate());
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn existing_rsa_ca_formats_survive_native_import_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    for arguments in [
        vec![
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=Native import fixture",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            "key.pem",
            "-out",
            "certificate.pem",
        ],
        vec!["rsa", "-in", "key.pem", "-traditional", "-out", "pkcs1.key"],
        vec![
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "key.pem",
            "-out",
            "pkcs8.key",
        ],
    ] {
        let result = Command::new("openssl")
            .args(arguments)
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let certificate = std::fs::read(directory.path().join("certificate.pem")).unwrap();
    for (key_file, label) in [
        ("pkcs1.key", "RSA PRIVATE KEY"),
        ("pkcs8.key", "PRIVATE KEY"),
    ] {
        let prefix = format!("-----BEGIN {label}-----");
        let mut combined = std::fs::read(directory.path().join(key_file)).unwrap();
        assert!(combined.starts_with(prefix.as_bytes()));
        combined.extend_from_slice(&certificate);
        let path = directory.path().join(format!("{key_file}.pem"));
        std::fs::write(&path, combined).unwrap();
        assert_load_preserves_file(&path);
    }
    let absent = directory.path().join("missing-ca.pem");
    assert!(CertificateAuthority::load(&absent).is_err());
    assert!(
        !absent.exists(),
        "native import must not generate a replacement CA"
    );
}
