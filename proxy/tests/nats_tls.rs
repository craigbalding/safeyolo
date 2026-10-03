//! Exercise the updated NATS client's PEM readers and certificate verification.
//! Set SAFEYOLO_NATS_TLS_TEST_BINARY to the pinned nats-server binary and run
//! this target with --include-ignored. The test owns its server and dynamic port.

use std::{path::Path, process::Command, time::Duration};

use futures_util::StreamExt;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use tokio::time::{sleep, timeout};

struct TestServer(std::process::Child);

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn options(root: &Path, ca: &str, client_key: Option<&str>) -> async_nats::ConnectOptions {
    let options = async_nats::ConnectOptions::new()
        .require_tls(true)
        .connection_timeout(Duration::from_secs(2))
        .add_root_certificates(root.join(ca));
    match client_key {
        Some(key) => options.add_client_certificate(root.join("client.pem"), root.join(key)),
        None => options,
    }
}

#[tokio::test]
#[ignore = "requires SAFEYOLO_NATS_TLS_TEST_BINARY from the pinned Coord fixture"]
async fn real_nats_tls_preserves_pem_and_trusted_untrusted_controls() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let binary = std::env::var_os("SAFEYOLO_NATS_TLS_TEST_BINARY")
        .expect("set SAFEYOLO_NATS_TLS_TEST_BINARY to the pinned nats-server");
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();
    for (name, purpose) in [
        ("server", ExtendedKeyUsagePurpose::ServerAuth),
        ("client", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![purpose];
        let certificate = params.signed_by(&key, &issuer).unwrap();
        std::fs::write(root.join(format!("{name}.pem")), certificate.pem()).unwrap();
        std::fs::write(root.join(format!("{name}.key")), key.serialize_pem()).unwrap();
    }
    let unrelated_ca = ca_params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap();
    std::fs::write(root.join("unrelated-ca.pem"), unrelated_ca.pem()).unwrap();
    let malformed = "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n";
    std::fs::write(
        root.join("malformed-ca.pem"),
        format!("{}{malformed}", ca.pem()),
    )
    .unwrap();
    std::fs::write(
        root.join("malformed.key"),
        "-----BEGIN PRIVATE KEY-----\n!\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let result = Command::new("openssl")
        .args(["ec", "-in", "client.key", "-out", "client-sec1.key"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result.stderr);
    assert!(
        std::fs::read(root.join("client-sec1.key"))
            .unwrap()
            .starts_with(b"-----BEGIN EC PRIVATE KEY-----")
    );
    std::fs::write(
        root.join("nats.conf"),
        format!(
            "listen: 127.0.0.1:-1\nports_file_dir: {root:?}\ntls {{\ncert_file: {cert:?}\nkey_file: {key:?}\nca_file: {ca:?}\nverify: true\n}}\n",
            root = root,
            cert = root.join("server.pem"),
            key = root.join("server.key"),
            ca = root.join("ca.pem"),
        ),
    )
    .unwrap();
    let log_path = root.join("nats.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut server = TestServer(
        Command::new(binary)
            .args(["-c", "nats.conf"])
            .current_dir(root)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let ports_path = root.join(format!("nats-server_{}.ports", server.0.id()));
    timeout(Duration::from_secs(5), async {
        while !ports_path.exists() {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(&log_path).unwrap()
            );
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("NATS writes its selected port");
    let ports: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ports_path).unwrap()).unwrap();
    let ip_url = ports["nats"][0].as_str().unwrap();
    let trusted_url = ip_url.replace("127.0.0.1", "localhost");
    for key in ["client.key", "client-sec1.key"] {
        let client = options(root, "ca.pem", Some(key))
            .connect(&trusted_url)
            .await
            .unwrap();
        let mut subscription = client.subscribe("dependency.repair").await.unwrap();
        client.flush().await.unwrap();
        client
            .publish("dependency.repair", "verified TLS".into())
            .await
            .unwrap();
        let message = timeout(Duration::from_secs(2), subscription.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message.payload.as_ref(), b"verified TLS");
        client.drain().await.unwrap();
    }
    for (ca, key, url) in [
        ("unrelated-ca.pem", Some("client.key"), trusted_url.as_str()),
        ("ca.pem", Some("client.key"), ip_url),
        ("ca.pem", None, trusted_url.as_str()),
        ("malformed-ca.pem", Some("client.key"), trusted_url.as_str()),
        ("ca.pem", Some("malformed.key"), trusted_url.as_str()),
    ] {
        assert!(
            options(root, ca, key).connect(url).await.is_err(),
            "unexpected connection with CA {ca}, key {key:?}, URL {url}"
        );
    }
}
