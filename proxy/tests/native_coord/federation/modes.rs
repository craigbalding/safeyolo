//! Certificate renewal and credential/trust rotation through the CLI.
use super::*;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};

fn leaf(root: &Path, ca: &CertificateParams, ca_key: &KeyPair, expired: bool) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if expired {
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    }
    let cert = params
        .signed_by(&key, &Issuer::from_params(ca, ca_key))
        .unwrap();
    fs::write(root.join("peer.pem"), cert.pem()).unwrap();
    fs::write(root.join("peer.key"), key.serialize_pem()).unwrap();
}

async fn apply_broker(root: &Path, rotate: bool, success: bool) -> Value {
    let input = root.join("broker-input.json");
    let mut args = vec![
        "coord",
        "federation",
        "broker",
        "apply",
        input.to_str().unwrap(),
    ];
    if rotate {
        args.push("--rotate-trust");
    }
    let output = host_cli(root, &args).await;
    assert_eq!(
        output.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if success {
        serde_json::from_slice(&output.stdout).unwrap()
    } else {
        Value::Null
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; actual native certificate lifecycle"]
async fn renewal_and_explicit_rotation_preserve_retained_state_and_report_activation() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let (home, peer) = (temp.path().join("home"), temp.path().join("peer"));
    initialize(&home, &nats).await;
    let _home_cleanup = NatsCleanup(home.clone());
    initialize(&peer, &nats).await;
    let _peer_cleanup = NatsCleanup(peer.clone());
    coord_json(&home, &["room", "create", "retained"]).await;
    coord_json(&home, &["grant", "retained", "alice"]).await;
    coord_json(
        &peer,
        &[
            "federation",
            "credential",
            peer.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    let peer_id = fs::read_to_string(peer.join("data/instance_id"))
        .unwrap()
        .trim()
        .to_owned();
    let home_id = fs::read_to_string(home.join("data/instance_id"))
        .unwrap()
        .trim()
        .to_owned();
    coord_json(
        &home,
        &[
            "federation",
            "trust",
            &peer_id,
            peer.join("federation-secret").to_str().unwrap(),
        ],
    )
    .await;
    let local_credential =
        zeroize::Zeroizing::new(fs::read(home.join("data/coord/nats/creds")).unwrap());
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_key = KeyPair::generate().unwrap();
    fs::write(home.join("ca.pem"), ca.self_signed(&ca_key).unwrap().pem()).unwrap();
    leaf(&home, &ca, &ca_key, false);
    let setup = json!({"listen":"127.0.0.1","cert_file":home.join("peer.pem"),"key_file":home.join("peer.key"),"ca_file":home.join("ca.pem"),"local_server_name":"127.0.0.1","peers":[{"instance_id":peer_id,"credential_file":peer.join("federation-secret")}]});
    fs::write(home.join("broker-input.json"), setup.to_string()).unwrap();
    let applied = apply_broker(&home, false, true).await;
    assert_eq!(applied["active"], false);
    assert_eq!(applied["restart_required"], true);
    coord_json(&home, &["stop"]).await;
    let ready = coord_json(&home, &["start", "--binary", &nats]).await;
    let port = ready["client_port"].as_u64().unwrap().to_string();
    let origin = format!("tls://127.0.0.1:{port}");
    let ca_path = home.join("ca.pem");
    let credential_path = peer.join("federation-secret");
    let home_args = [
        "federation",
        "home",
        "primary",
        &home_id,
        "tls",
        &origin,
        ca_path.to_str().unwrap(),
        credential_path.to_str().unwrap(),
    ];
    coord_json(&peer, &home_args).await;
    coord_json(&home, &["room", "create", "initial-tls"]).await;
    let ca_pem = fs::read_to_string(home.join("ca.pem")).unwrap();
    fs::write(home.join("ca.pem"), format!("\n{ca_pem}\n")).unwrap();
    let reformatted = apply_broker(&home, false, true).await;
    assert_eq!(reformatted["trust_changed"], false);
    assert_eq!(reformatted["active"], true);
    assert_eq!(
        coord_json(&peer, &["federation", "check", "primary"]).await["broker_authentication"],
        "authenticated"
    );

    // Invalid material never replaces the saved configuration.
    let saved = fs::read(home.join("coord-federation.json")).unwrap();
    let mut wrong_name = setup.clone();
    wrong_name["server_names"] = json!(["uncovered.example.test"]);
    fs::write(home.join("broker-input.json"), wrong_name.to_string()).unwrap();
    apply_broker(&home, false, false).await;
    fs::write(home.join("broker-input.json"), setup.to_string()).unwrap();
    let config = fs::read_to_string(home.join("config.toml")).unwrap();
    fs::write(
        home.join("config.toml"),
        format!("tls_ca_file='{}'\n{config}", home.join("ca.pem").display()),
    )
    .unwrap();
    let refused = host_cli(
        &home,
        &[
            "coord",
            "federation",
            "broker",
            "check",
            home.join("broker-input.json").to_str().unwrap(),
        ],
    )
    .await;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("dedicated broker TLS material"));
    let broker_key =
        KeyPair::from_pem(&fs::read_to_string(home.join("peer.key")).unwrap()).unwrap();
    fs::write(
        home.join("interception.pem"),
        ca.self_signed(&broker_key).unwrap().pem(),
    )
    .unwrap();
    fs::write(
        home.join("config.toml"),
        format!(
            "tls_ca_file='{}'\n{config}",
            home.join("interception.pem").display()
        ),
    )
    .unwrap();
    let refused = host_cli(
        &home,
        &[
            "coord",
            "federation",
            "broker",
            "check",
            home.join("broker-input.json").to_str().unwrap(),
        ],
    )
    .await;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("dedicated broker TLS material"));
    fs::write(home.join("config.toml"), config).unwrap();
    let previous_ca = fs::read(home.join("ca.pem")).unwrap();
    let unrelated_ca = KeyPair::generate().unwrap();
    fs::write(
        home.join("ca.pem"),
        ca.self_signed(&unrelated_ca).unwrap().pem(),
    )
    .unwrap();
    apply_broker(&home, false, false).await;
    fs::write(home.join("ca.pem"), previous_ca).unwrap();
    let old_key = zeroize::Zeroizing::new(fs::read(home.join("peer.key")).unwrap());
    fs::write(
        home.join("peer.key"),
        KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    apply_broker(&home, false, false).await;
    fs::write(home.join("peer.key"), old_key.as_slice()).unwrap();
    let old_cert = fs::read(home.join("peer.pem")).unwrap();
    leaf(&home, &ca, &ca_key, true);
    apply_broker(&home, false, false).await;
    assert_eq!(fs::read(home.join("coord-federation.json")).unwrap(), saved);
    leaf(&home, &ca, &ca_key, false);
    assert_ne!(fs::read(home.join("peer.pem")).unwrap(), old_cert);
    let renewal = apply_broker(&home, false, true).await;
    assert_eq!(renewal["trust_changed"], false);
    assert_eq!(renewal["active"], false);
    assert_eq!(
        coord_json(&home, &["federation", "check"]).await["configuration_active"],
        false
    );
    coord_json(&home, &["stop"]).await;
    coord_json(&home, &["start", "--binary", &nats, "--client-port", &port]).await;
    coord_json(&home, &["room", "create", "renewed-tls"]).await;
    assert_eq!(
        coord_json(&home, &["federation", "check"]).await["configuration_active"],
        true
    );
    let check = coord_json(&peer, &["federation", "check", "primary"]).await;
    assert_eq!(check["broker_authentication"], "authenticated");
    assert_eq!(
        count(
            &home,
            "SELECT count(*) FROM memberships WHERE principal_kind='agent' AND revoked_at IS NULL"
        ),
        1
    );
    assert_eq!(count(&home, "SELECT epoch FROM coord_federation_peers"), 1);
    assert_eq!(
        fs::read(home.join("data/coord/nats/creds")).unwrap(),
        local_credential.as_slice()
    );
    assert_eq!(
        count(&home, "SELECT count(*) FROM rooms WHERE name='retained'"),
        1
    );

    ca_key = KeyPair::generate().unwrap();
    fs::write(home.join("ca.pem"), ca.self_signed(&ca_key).unwrap().pem()).unwrap();
    leaf(&home, &ca, &ca_key, false);
    apply_broker(&home, false, false).await;
    let rotated = apply_broker(&home, true, true).await;
    assert_eq!(rotated["trust_changed"], true);
    assert_eq!(rotated["active"], false);
    coord_json(&home, &["stop"]).await;
    coord_json(&home, &["start", "--binary", &nats, "--client-port", &port]).await;
    let refused = coord_json(&peer, &["federation", "check", "primary"]).await;
    assert_eq!(refused["protection"]["verified"], false);
    assert_eq!(refused["broker_authentication"], "not_checked");
    let mut no_rotation = vec!["coord"];
    no_rotation.extend_from_slice(&home_args);
    assert!(!host_cli(&peer, &no_rotation).await.status.success());
    let mut rotated_args = home_args.to_vec();
    rotated_args.push("--rotate-trust");
    coord_json(&peer, &rotated_args).await;
    assert_eq!(
        coord_json(&peer, &["federation", "check", "primary"]).await["broker_authentication"],
        "authenticated"
    );
    assert_eq!(count(&home, "SELECT epoch FROM coord_federation_peers"), 1);
    assert_eq!(
        count(
            &home,
            "SELECT count(*) FROM memberships WHERE principal_kind='agent' AND revoked_at IS NULL"
        ),
        1
    );
    println!(
        "leaf renewal and explicit CA rotation retain local credentials, streams, membership and peer generation; activation requires owned restart"
    );
}

async fn assert_peer_authentication(
    origin: &str,
    username: &str,
    credential: &str,
    expected: bool,
) {
    match async_nats::ConnectOptions::new()
        .user_and_password(username.to_owned(), credential.trim().to_owned())
        .connection_timeout(Duration::from_secs(2))
        .connect(origin)
        .await
    {
        Ok(connection) => {
            assert!(expected, "broker accepted an inactive peer credential");
            connection.flush().await.unwrap();
        }
        Err(error) => {
            assert!(!expected, "broker rejected its active peer credential");
            assert!(matches!(
                error.kind(),
                async_nats::ConnectErrorKind::Authentication
                    | async_nats::ConnectErrorKind::AuthorizationViolation
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; actual same-path credential rotation and activation"]
async fn same_path_peer_rotation_reports_restart_until_broker_loads_new_credentials() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    initialize(&home, &nats).await;
    let _cleanup = NatsCleanup(home.clone());
    let peer_id = "sy-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let username = support::hash(peer_id);
    let credential_path = home.join("peer-secret");
    let path = credential_path.to_str().unwrap();
    coord_json(&home, &["federation", "credential", path]).await;
    coord_json(&home, &["federation", "trust", peer_id, path]).await;
    let original = zeroize::Zeroizing::new(fs::read_to_string(&credential_path).unwrap());
    let setup = json!({"mode":"loopback","listen":"127.0.0.1",
        "peers":[{"instance_id":peer_id,"credential_file":credential_path}]});
    let input = home.join("broker-input.json");
    fs::write(&input, setup.to_string()).unwrap();
    apply_broker(&home, false, true).await;
    coord_json(&home, &["stop"]).await;
    let ready = coord_json(&home, &["start", "--binary", &nats]).await;
    let port = ready["client_port"].as_u64().unwrap().to_string();
    let origin = format!("nats://127.0.0.1:{port}");
    assert_eq!(apply_broker(&home, false, true).await["active"], true);
    assert_eq!(
        coord_json(&home, &["federation", "check"]).await["configuration_active"],
        true
    );
    assert_peer_authentication(&origin, &username, &original, true).await;

    // Change the bytes at the configured path without changing the broker JSON.
    let rotated_path = home.join("rotated-secret");
    coord_json(
        &home,
        &["federation", "credential", rotated_path.to_str().unwrap()],
    )
    .await;
    fs::copy(&rotated_path, &credential_path).unwrap();
    let rotated = zeroize::Zeroizing::new(fs::read_to_string(&credential_path).unwrap());
    assert!(original.as_str() != rotated.as_str());
    let trusted = coord_json(&home, &["federation", "trust", peer_id, path]).await;
    assert_eq!(trusted["epoch"], 2);

    let checked = coord_json(
        &home,
        &["federation", "broker", "check", input.to_str().unwrap()],
    )
    .await;
    assert_eq!(checked["active"], false);
    let applied = apply_broker(&home, false, true).await;
    assert_eq!(applied["active"], false);
    assert_eq!(applied["restart_required"], true);
    assert_eq!(
        coord_json(&home, &["federation", "check"]).await["configuration_active"],
        false
    );
    let reused = coord_json(&home, &["start", "--binary", &nats]).await;
    assert_eq!(reused["configuration_active"], false);
    assert_eq!(reused["restart_required"], true);
    assert_peer_authentication(&origin, &username, &original, true).await;
    assert_peer_authentication(&origin, &username, &rotated, false).await;

    coord_json(&home, &["stop"]).await;
    coord_json(&home, &["start", "--binary", &nats, "--client-port", &port]).await;
    let applied = apply_broker(&home, false, true).await;
    assert_eq!(applied["active"], true);
    assert_eq!(applied["restart_required"], false);
    assert_eq!(
        coord_json(&home, &["federation", "check"]).await["configuration_active"],
        true
    );
    assert_peer_authentication(&origin, &username, &original, false).await;
    assert_peer_authentication(&origin, &username, &rotated, true).await;
}
