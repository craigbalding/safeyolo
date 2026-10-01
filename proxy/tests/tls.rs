use ring::digest::{SHA256, digest};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{ServerName, UnixTime},
};
use safeyolo_proxy::tls::CertificateAuthority;
use time::{Duration, OffsetDateTime};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
#[ignore = "historical mitmproxy CA oracle; set SAFEYOLO_POLICY_PYTHON to the baseline Python environment"]
fn existing_mitmproxy_rsa_ca_survives_import_restart_and_old_proxy_reload() {
    use std::process::Command;
    let python = std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("baseline Python environment");
    let directory = tempfile::tempdir().unwrap();
    let create = r#"
import pathlib, sys
from mitmproxy.certs import CertStore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
root = pathlib.Path(sys.argv[1])
store = CertStore.from_store(root, 'mitmproxy', 2048)
raw = (root/'mitmproxy-ca.pem').read_bytes()
key = serialization.load_pem_private_key(raw, None)
assert isinstance(key, rsa.RSAPrivateKey)
assert raw.startswith(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
public = (root/'mitmproxy-ca-cert.pem').read_bytes()
(root/'pkcs8.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + public)
"#;
    let result = Command::new(&python)
        .arg("-c")
        .arg(create)
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for file in ["mitmproxy-ca.pem", "pkcs8.pem"] {
        assert_load_preserves_file(&directory.path().join(file));
    }
    let rollback = r#"
import pathlib, sys
from mitmproxy.certs import CertStore
root = pathlib.Path(sys.argv[1])
before = (root/'mitmproxy-ca.pem').read_bytes()
store = CertStore.from_store(root, 'mitmproxy', 2048)
leaf = store.get_cert('example.invalid', ['example.invalid'])
assert leaf.cert.cn == 'example.invalid'
assert (root/'mitmproxy-ca.pem').read_bytes() == before
"#;
    let result = Command::new(python)
        .arg("-c")
        .arg(rollback)
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

const COMPARATOR_COMMIT: &str = "7e934a5470f1aa9b74052fea08c6bae9b5f32e8a";
const CA_FILES: [&str; 6] = [
    "mitmproxy-ca.pem",
    "mitmproxy-ca-cert.pem",
    "mitmproxy-ca-cert.cer",
    "mitmproxy-ca.p12",
    "mitmproxy-ca-cert.p12",
    "mitmproxy-dhparam.pem",
];

fn sha256(path: &Path) -> String {
    sha256_bytes(&std::fs::read(path).unwrap())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn mode(path: &Path) -> String {
    format!(
        "{:04o}",
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    )
}

fn git_output(repository: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn python_ca_stage(root: &Path, operation: &str) -> Value {
    let source = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE")
            .expect("SAFEYOLO_STATE_PYTHON_SOURCE must name the comparator checkout"),
    );
    let executable = PathBuf::from(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON")
            .expect("SAFEYOLO_POLICY_PYTHON must name the comparator interpreter"),
    );
    assert_eq!(
        git_output(&source, &["rev-parse", "HEAD"]),
        COMPARATOR_COMMIT,
        "the selected old-Python comparator must be the recorded checkout"
    );
    assert!(
        git_output(&source, &["status", "--porcelain"]).is_empty(),
        "the selected old-Python comparator must be clean"
    );
    assert!(executable.is_file(), "comparator interpreter is missing");
    let script = r#"
import hashlib
import importlib.metadata
import json
import pathlib
import stat
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from mitmproxy.certs import CertStore
import safeyolo

root = pathlib.Path(sys.argv[1])
operation = sys.argv[2]
expected_executable = pathlib.Path(sys.argv[3])
source = pathlib.Path(sys.argv[4])
assert pathlib.Path(sys.executable).resolve() == expected_executable.resolve()
names = [
    'mitmproxy-ca.pem',
    'mitmproxy-ca-cert.pem',
    'mitmproxy-ca-cert.cer',
    'mitmproxy-ca.p12',
    'mitmproxy-ca-cert.p12',
    'mitmproxy-dhparam.pem',
]

def snapshot():
    result = []
    for name in names:
        path = root / name
        raw = path.read_bytes()
        result.append({
            'name': name,
            'sha256': hashlib.sha256(raw).hexdigest(),
            'mode': format(stat.S_IMODE(path.stat().st_mode), '04o'),
        })
    return result

before = snapshot() if operation == 'reload' else None
store = CertStore.from_store(root, 'mitmproxy', 2048)
after = snapshot()
if before is not None:
    assert before == after, 'old Python consumer rewrote existing CA material'

combined = (root / 'mitmproxy-ca.pem').read_bytes()
certificate = x509.load_pem_x509_certificate((root / 'mitmproxy-ca-cert.pem').read_bytes())
key = serialization.load_pem_private_key(combined, None)
assert key.public_key().public_numbers() == certificate.public_key().public_numbers()
leaf = store.get_cert('example.invalid', ['example.invalid'])
assert leaf.cert.cn == 'example.invalid'
print(json.dumps({
    'backend': 'python-comparator',
    'operation': operation,
    'runtime': {
        'source': str(source),
        'commit': '7e934a5470f1aa9b74052fea08c6bae9b5f32e8a',
        'launcher': str(expected_executable),
        'program': sys.executable,
        'python_version': '.'.join(map(str, sys.version_info[:3])),
        'safeyolo': importlib.metadata.version('safeyolo'),
        'safeyolo_file': str(pathlib.Path(safeyolo.__file__).resolve()),
        'mitmproxy': importlib.metadata.version('mitmproxy'),
        'cryptography': importlib.metadata.version('cryptography'),
        'mitmproxy_file': str(pathlib.Path(__import__('mitmproxy').__file__).resolve()),
    },
    'files': after,
    'effective': {
        'root_certificate_sha256': certificate.fingerprint(hashes.SHA256()).hex(),
        'leaf_dns_name': leaf.cert.cn,
        'existing_material_unchanged': before == after if before is not None else True,
    },
}))
"#;
    let output = Command::new(&executable)
        .arg("-c")
        .arg(script)
        .arg(root)
        .arg(operation)
        .arg(&executable)
        .arg(&source)
        .env(
            "PYTHONPATH",
            format!("{}:{}", source.join("cli/src").display(), source.display()),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "old Python CA stage {operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "old Python CA stage {operation} returned invalid JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

async fn native_ca_handshake(ca: &CertificateAuthority) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_config = ca
        .server_config("example.invalid", OffsetDateTime::now_utc())
        .unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = TlsAcceptor::from(server_config)
            .accept(socket)
            .await
            .unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let socket = TcpStream::connect(address).await.unwrap();
    let mut stream = TlsConnector::from(Arc::new(client_config))
        .connect(
            rustls::pki_types::ServerName::try_from("example.invalid".to_owned()).unwrap(),
            socket,
        )
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

fn native_ca_files(root: &Path) -> Vec<Value> {
    CA_FILES
        .iter()
        .map(|name| {
            let path = root.join(name);
            json!({"name": name, "sha256": sha256(&path), "mode": mode(&path)})
        })
        .collect()
}

async fn native_ca_stage(root: &Path, operation: &str) -> Value {
    let ca_path = root.join("mitmproxy-ca.pem");
    let ca = CertificateAuthority::load(&ca_path).unwrap();
    native_ca_handshake(&ca).await;
    json!({
        "backend": "rust-native",
        "operation": operation,
        "files": native_ca_files(root),
        "effective": {
            "root_certificate_sha256": sha256_bytes(ca.certificate().as_ref()),
            "native_tls_handshake": "success",
        },
    })
}

#[tokio::test]
#[ignore = "selected Python→Rust→Python→Rust CA/key trust transition"]
async fn selected_python_native_python_native_ca_trust_transition() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path();
    let initial = python_ca_stage(root_path, "write");
    let first_native = native_ca_stage(root_path, "read-and-handshake").await;
    assert_eq!(initial["files"], first_native["files"]);
    assert_eq!(
        initial["effective"]["root_certificate_sha256"],
        first_native["effective"]["root_certificate_sha256"]
    );

    let missing = root_path.join("unexpected-new-root.pem");
    assert!(CertificateAuthority::load(&missing).is_err());
    assert!(
        !missing.exists(),
        "native load must not generate a new root"
    );
    let negative = json!({
        "backend": "rust-native",
        "operation": "missing-root-rejected-without-generation",
        "effective": {"path_created": false},
    });

    let python_reload = python_ca_stage(root_path, "reload");
    assert_eq!(initial["files"], python_reload["files"]);
    assert_eq!(initial["effective"], python_reload["effective"]);
    let final_native = native_ca_stage(root_path, "restart-read-and-handshake").await;
    assert_eq!(initial["files"], final_native["files"]);
    assert_eq!(
        initial["effective"]["root_certificate_sha256"],
        final_native["effective"]["root_certificate_sha256"]
    );

    let source = PathBuf::from(std::env::var_os("SAFEYOLO_STATE_PYTHON_SOURCE").unwrap());
    let executable = PathBuf::from(std::env::var_os("SAFEYOLO_POLICY_PYTHON").unwrap());
    let native_source = git_output(
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap(),
        &["rev-parse", "HEAD"],
    );
    let manifest = json!({
        "schema": 1,
        "family": "interception-ca-and-key",
        "comparator": initial["runtime"],
        "native": {
            "source": native_source,
            "package": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "test": "selected_python_native_python_native_ca_trust_transition",
        },
        "commands": {
            "python": format!("{} -c <embedded-ca-fixture> ROOT OP", executable.display()),
            "native": "cargo test --test tls selected_python_native_python_native_ca_trust_transition -- --ignored --exact --nocapture",
        },
        "files": initial["files"],
        "trust_identity_sha256": initial["effective"]["root_certificate_sha256"],
        "stages": [initial, first_native, negative, python_reload, final_native],
        "secret_free": true,
        "comparator_source": source,
    });
    let evidence_dir = PathBuf::from(
        std::env::var_os("SAFEYOLO_STATE_EVIDENCE_DIR")
            .expect("SAFEYOLO_STATE_EVIDENCE_DIR must retain the evidence manifest"),
    );
    std::fs::create_dir_all(&evidence_dir).unwrap();
    let evidence_path = evidence_dir.join("ca-python-rust-python-rust.json");
    std::fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!(
        "CA trust transition manifest: {}",
        serde_json::to_string_pretty(&manifest).unwrap()
    );
}
