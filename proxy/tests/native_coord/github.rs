//! Real Agent API, NATS and service injection against a controlled GitHub TLS fixture.
//! These responses are external fixtures, not observations of GitHub's service.
use super::*;
use hyper::Method;
use safeyolo_proxy::credentials::{self, Credential, Secret};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    net::TcpListener,
    sync::{Notify, mpsc},
};
use tokio_rustls::{TlsAcceptor, rustls};

const ALICE: &str = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const UPSTREAM_TOKEN: &str = "synthetic-host-only-github-token";

async fn observed_request(requests: &mut mpsc::Receiver<String>) -> String {
    tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("GitHub fixture did not observe a request within 10 seconds")
        .expect("GitHub fixture stopped before observing the request")
}

async fn headers(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16384);
        head.push(stream.read_u8().await.unwrap());
    }
    head
}

async fn adapter(root: &Path, agent: &str, name: &str, args: Value) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"));
    command
        .args(["call", name])
        .env("SAFEYOLO_COORD_SOCKET", root.join(format!("{agent}.sock")))
        .env("SAFEYOLO_COORD_TOKEN_PATH", root.join("data/agent_token"))
        .env("SSL_CERT_FILE", root.join("ca.pem"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(args.to_string().as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}

async fn external(root: &Path, agent: &str, work: &Value) -> Value {
    let output = adapter(
        root,
        agent,
        "read_github_work",
        json!({"room_name":"shared","work_id":work["work_id"]}),
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!result.to_string().contains(UPSTREAM_TOKEN));
    assert!(!result.to_string().contains("sgw_"));
    result
}

async fn service(root: &Path, revoke: bool) {
    let path = if revoke {
        "/admin/agents/alice/services/github"
    } else {
        "/admin/agents/alice/services"
    };
    safeyolo_proxy::native_client::admin(&root.join("config.toml"),path,
        if revoke {Method::DELETE} else {Method::POST},
        if revoke {Value::Null} else {json!({"service":"github","capability":"read_work","credential":"github-fixture","host":"api.github.com"})},
        Duration::from_secs(5)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned NATS; controlled external TLS fixture with real service controls"]
async fn native_github_read_uses_caller_service_and_preserves_local_work() {
    let nats = std::env::var("SAFEYOLO_COORD_NATS_BINARY").expect("set pinned NATS binary");
    let temp = tempfile::Builder::new()
        .prefix("coord-github-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let retained = temp.keep();
    let root = retained.as_path();
    println!("GitHub controlled fixture: {}", root.display());
    assert!(host_cli(root, &["init"]).await.status.success());
    fs::create_dir_all(root.join("builtin-services")).unwrap();
    fs::write(
        root.join("builtin-services/github.yaml"),
        include_str!("../../../cli/src/safeyolo/services/github.yaml"),
    )
    .unwrap();
    credentials::open(&root.join("data"))
        .unwrap()
        .store(Credential::new(
            "github-fixture",
            "bearer",
            Secret::new(UPSTREAM_TOKEN),
        ))
        .unwrap();

    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = params.self_signed(&ca_key).unwrap();
    fs::write(
        root.join("ca.pem"),
        format!("{}{}", ca_key.serialize_pem(), ca.pem()),
    )
    .unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["api.github.com".into()]).unwrap();
    fs::write(root.join("upstream.pem"), cert.pem()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let parent_port = parent.local_addr().unwrap().port();
    // 0=open, 1=closed/reassigned, 2=outage, 3=held response, 4=redirect, 5=oversize.
    let mode = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let (observed, mut requests) = mpsc::channel(32);
    let origin = tokio::spawn({
        let mode = mode.clone();
        let release = release.clone();
        let tls = Arc::new(tls);
        async move {
            loop {
                let (mut stream, _) = parent.accept().await.unwrap();
                let mode = mode.clone();
                let release = release.clone();
                let tls = tls.clone();
                let observed = observed.clone();
                tokio::spawn(async move {
                    let connect = headers(&mut stream).await;
                    assert!(connect.starts_with(b"CONNECT api.github.com:443 "));
                    stream
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut stream = TlsAcceptor::from(tls).accept(stream).await.unwrap();
                    let request = String::from_utf8(headers(&mut stream).await).unwrap();
                    assert!(request.starts_with("GET /repos/craigbalding/safeyolo/"));
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains(&format!("authorization: bearer {UPSTREAM_TOKEN}"))
                    );
                    assert!(!request.contains("sgw_"));
                    let selected = mode.load(Ordering::SeqCst);
                    observed
                        .send(request.lines().next().unwrap().to_owned())
                        .await
                        .unwrap();
                    if selected == 3 {
                        release.notified().await;
                    }
                    let state = if selected == 1 { "closed" } else { "open" };
                    let assignee = if selected == 1 {
                        "remote-mallory"
                    } else {
                        "remote-alice"
                    };
                    let head = if selected == 1 {
                        "changed-remote-head"
                    } else {
                        "original-remote-head"
                    };
                    let body = if selected == 5 {
                        json!({"title":"large","state":"open","body":"x".repeat(1024*1024)})
                            .to_string()
                    } else {
                        json!({"title":"External fixture π\u{001b}[2J\u{202e}","state":state,"body":"PRIVATE-DESCRIPTION","assignees":[assignee],"head":{"sha":head}}).to_string()
                    };
                    let status = if selected == 2 {
                        "503 Unavailable"
                    } else if selected == 4 {
                        "302 Found"
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nLocation: https://other.invalid/secret\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    // A bounded client may close an oversized response early.
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    });
    fs::write(root.join("config.toml"),format!("admin_port=0\nflow_store_enabled=false\ntls_ca_file='ca.pem'\nupstream_ca_file='upstream.pem'\nparent_proxy='http://127.0.0.1:{parent_port}'\nparent_proxy_hosts=['api.github.com']\n[[listeners]]\nagent_id='alice'\nsocket_path='alice.sock'\n[[listeners]]\nagent_id='bob'\nsocket_path='bob.sock'\n")).unwrap();
    fs::write(root.join("policy.toml"),format!("[hosts.'api.github.com']\negress='allow'\nservice='github'\n[hosts.'*']\negress='deny'\n[controls.credentials]\nenabled=true\ndetection_level='none'\nuse_default_credential_rules=false\nstandard_auth_headers=[]\n[agents.alice]\nagent_id='{ALICE}'\n[agents.bob]\nagent_id='{BOB}'\n")).unwrap();
    coord_json(root, &["start", "--binary", &nats]).await;
    let _cleanup = NatsCleanup(root.into());
    coord_json(root, &["room", "create", "shared"]).await;
    for actor in ["alice", "bob"] {
        coord_json(root, &["grant", "shared", actor]).await;
    }
    let mut proxy = stage0::start_proxy(root).await;
    let client = |actor: &str| Client {
        socket: Some(root.join(format!("{actor}.sock"))),
        token_file: root.join("data/agent_token"),
    };
    let alice = client("alice");
    let bob = client("bob");
    let input = json!({"room_name":"shared","url":"https://github.com/craigbalding/safeyolo/issues/1313","operation_id":"github-seed"});
    let seed = alice.call("import_github_work", &input).await.unwrap();
    assert_eq!(
        alice.call("import_github_work", &input).await.unwrap(),
        seed
    );
    assert_eq!(
        external(root, "bob", &seed["work"]).await["external"]["status"],
        "unavailable"
    );
    let mut work=alice.call("claim_work",&json!({"room_name":"shared","work_id":seed["work"]["work_id"],"expected_version":1,"expected_generation":0,"operation_id":"claim"})).await.unwrap()["work"].clone();
    work=alice.call("change_work_target",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_target_generation":0,"target_ref":"opaque:explicit-candidate","operation_id":"target"})).await.unwrap()["work"].clone();
    work=bob.call("attest_work",&json!({"room_name":"shared","work_id":work["work_id"],"target_generation":1,"kind":"review","verdict":"approve","summary":"Controlled fixture target, not independent issue acceptance","operation_id":"review"})).await.unwrap()["work"].clone();
    service(root, false).await;
    let open = external(root, "alice", &work).await;
    assert_eq!(open["external"]["state"], "open");
    assert_eq!(open["work"], work);
    assert!(!open.to_string().contains("PRIVATE-DESCRIPTION"));
    assert!(
        observed_request(&mut requests)
            .await
            .contains("/issues/1313 ")
    );
    let operator_seed = coord_json(
        root,
        &[
            "work",
            "import-github",
            "shared",
            "https://github.com/craigbalding/safeyolo/pull/1314",
            "--operation-id",
            "operator-pr",
        ],
    )
    .await;
    assert_eq!(operator_seed["work"]["created_by"]["kind"], "operator");
    assert_eq!(
        external(root, "alice", &operator_seed["work"]).await["external"]["state"],
        "open"
    );
    assert!(
        observed_request(&mut requests)
            .await
            .contains("/pulls/1314 ")
    );
    mode.store(1, Ordering::SeqCst);
    let closed = external(root, "alice", &work).await;
    assert_eq!(closed["external"]["state"], "closed");
    assert_eq!(closed["work"], work); // Closing/reassigning remotely has no local effect.
    observed_request(&mut requests).await;
    for selected in [2, 4, 5] {
        mode.store(selected, Ordering::SeqCst);
        let unavailable = external(root, "alice", &work).await;
        assert_eq!(unavailable["external"]["status"], "unavailable");
        assert_eq!(unavailable["work"], work);
        observed_request(&mut requests).await;
    }
    // A held external request does not hold the work transaction. Bob lacks
    // GitHub access but can receive a released claim under normal room policy.
    mode.store(3, Ordering::SeqCst);
    let pending = tokio::spawn({
        let root = root.to_owned();
        let work = work.clone();
        async move { external(&root, "alice", &work).await }
    });
    observed_request(&mut requests).await;
    let released=alice.call("release_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"operation_id":"release"})).await.unwrap();
    work=bob.call("claim_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":released["work"]["version"],"expected_generation":released["work"]["claim_generation"],"operation_id":"bob-claim"})).await.unwrap()["work"].clone();
    service(root, true).await;
    release.notify_one();
    let revoked = pending.await.unwrap();
    assert_eq!(revoked["external"]["status"], "unavailable");
    assert_eq!(revoked["work"], work);
    assert_eq!(work["claim_agent_id"], BOB);
    assert_eq!(work["target_generation"], 1);
    assert_eq!(work["target_ref"], "opaque:explicit-candidate");
    work=bob.call("complete_work",&json!({"room_name":"shared","work_id":work["work_id"],"expected_version":work["version"],"expected_generation":work["claim_generation"],"short_result":"Local completion without GitHub access","operation_id":"complete"})).await.unwrap()["work"].clone();
    assert_eq!(work["state"], "done");
    assert!(requests.try_recv().is_err());

    // Restart the real proxy and NATS, then replay the original seed.
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
    coord_json(root, &["stop"]).await;
    coord_json(root, &["start", "--binary", &nats]).await;
    proxy = stage0::start_proxy(root).await;
    assert_eq!(
        alice.call("import_github_work", &input).await.unwrap(),
        seed
    );
    assert_eq!(
        bob.call(
            "read_work",
            &json!({"room_name":"shared","work_id":work["work_id"]})
        )
        .await
        .unwrap(),
        work
    );
    let status = coord_cli(root, &["status", "shared"]).await;
    assert!(
        String::from_utf8(status.stdout)
            .unwrap()
            .contains("GitHub reference (external)")
    );
    // Revoke room receive after dispatch but before the external response.
    service(root, false).await;
    let pending = tokio::spawn({
        let root = root.to_owned();
        let work = work.clone();
        async move {
            adapter(
                &root,
                "alice",
                "read_github_work",
                json!({"room_name":"shared","work_id":work["work_id"]}),
            )
            .await
        }
    });
    observed_request(&mut requests).await;
    coord_json(root, &["revoke", "shared", "alice"]).await;
    release.notify_one();
    let denied = pending.await.unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
    origin.abort();
    println!(
        "GitHub fixture passed: GET-only vaulted injection, no-access participation, outage/redirect/size isolation, revocation races and restart replay; local work={work}"
    );
    fs::remove_dir_all(root).unwrap();
}
