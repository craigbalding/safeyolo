//! The real CLI, Admin/API authority, HTTP gate and arbitrary-port transport.
//! A controlled backend supplies streams; this is not operator-device proof.
use super::*;

#[test]
fn guest_web_publication_preserves_app_http_and_owns_only_its_run_port_and_lifetime() {
    let _environment = DESKTOP_TEST_ENV.lock().unwrap_or_else(|e| e.into_inner());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(check());
}

async fn check() {
    let root = TempDir::new().unwrap();
    fixture(root.path());
    unsafe {
        std::env::set_var("SAFEYOLO_TEST_GUEST_PORT", "3000");
    }
    fs::write(root.path().join("config.toml"), "admin_port=0\nadmin_api_token_file='token'\npolicy_file='policy.toml'\nreadiness_file='ready.json'\naudit_log_path='audit.jsonl'\n").unwrap();
    let mut run = OwnedRun::start(root.path());
    bind_action_run(root.path(), "alice", ID);
    let mut config = config(root.path());
    config.native_product = true;
    config.native_config_dir = Some(root.path().into());
    config.native_config_path = Some(root.path().join("config.toml"));
    config.policy_file = Some(root.path().join("policy.toml"));
    let guest = UnixListener::bind(root.path().join("guest.sock")).unwrap();
    let app = tokio::spawn(async move {
        for path in [
            "/login",
            "/callback?done=1",
            "/events",
            "/socket",
            "/submit",
        ] {
            let (mut stream, _) = guest.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
                assert!(header.len() < 8192);
            }
            let header = String::from_utf8(header).unwrap();
            let method = if path == "/submit" { "POST" } else { "GET" };
            assert!(
                header.starts_with(&format!("{method} {path} HTTP/1.1\r\n")),
                "{header}"
            );
            assert!(header.contains("Host: 127.0.0.1:"));
            assert!(
                !header.contains("safeyolo_preview_token_"),
                "preview credentials reached app"
            );
            assert!(!header.contains("forged.invalid"));
            assert!(!header.to_ascii_lowercase().contains("x-forwarded-"));
            match path {
                "/login" => stream.write_all(b"HTTP/1.1 303 See Other\r\nLocation: /callback?done=1\r\nSet-Cookie: app_session=known; Path=/; HttpOnly\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap(),
                "/callback?done=1" => {
                    assert!(header.contains("app_session=known"));
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone").await.unwrap();
                }
                "/events" => {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: first\n\n").await.unwrap();
                    // The client must receive the first event before this closes.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                "/socket" => {
                    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
                    let mut frame = [0; 8];
                    stream.read_exact(&mut frame).await.unwrap();
                    assert_eq!(&frame, b"\x81\x82\x01\x02\x03\x04ik");
                    stream.write_all(b"\x81\x02hi").await.unwrap();
                }
                _ => {
                    let mut body = [0; 3];
                    stream.read_exact(&mut body).await.unwrap();
                    assert_eq!(&body, b"one");
                    // The app committed this form, then lost its response.
                    // Keep the listener open to detect an unsafe second send.
                    drop(stream);
                    assert!(tokio::time::timeout(Duration::from_millis(1200), guest.accept()).await.is_err(),
                        "publication replayed a submitted form after losing the reply");
                }
            }
        }
    });
    let proxy = Proxy::start(config).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let admin = ready["admin_port"].as_u64().unwrap() as u16;
    let config_path = root.path().join("config.toml");
    let source = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        source.replace("admin_port=0", &format!("admin_port={admin}")),
    )
    .unwrap();
    let auth = [("Authorization", format!("Bearer {TOKEN}"))];
    for port in [8080, 9090] {
        let refused = request(
            admin,
            "POST",
            &format!("/admin/agents/{ID}/web"),
            &auth,
            format!("{{\"guest_port\":{port},\"audience\":\"local\"}}").as_bytes(),
        )
        .await;
        assert_eq!(status(&refused), 400);
        assert!(String::from_utf8_lossy(&refused).contains("reserved"));
    }
    let pending = action_request(root.path(), "POST", "/operator-actions", json!({
        "action_id":"web.publish","parameters":{"guest_port":3000,"audience":"local","ttl_seconds":3},
        "reason":"Show the app running in this guest"
    }), "alice").await;
    assert_eq!(
        status(&pending),
        202,
        "{}",
        String::from_utf8_lossy(&pending)
    );
    let pending = body(&pending);
    assert_eq!(pending["action_id"], "web.publish");
    assert_eq!(pending["status"], "pending_approval");
    assert!(pending["result"]["url"].is_null());
    let id = pending["approval_id"].as_str().unwrap();
    let selected_cli = std::env::var_os("SAFEYOLO_NATIVE_CLI")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_safeyolo").into());
    let preview = tokio::process::Command::new(&selected_cli)
        .arg("--instance-dir")
        .arg(root.path())
        .args(["approvals", "show", id])
        .output()
        .await
        .unwrap();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview = String::from_utf8(preview.stdout).unwrap();
    assert!(preview.contains("Publish agent web port"), "{preview}");
    assert!(
        preview.contains("Guest port: 3000") && preview.contains("Audience: local"),
        "{preview}"
    );
    assert!(
        preview.contains("Preview lifetime: 3 seconds") && preview.contains("No desktop starts"),
        "{preview}"
    );
    assert!(
        !preview.contains("Present agent desktop")
            && !preview.contains("Presentation: unavailable"),
        "{preview}"
    );
    let forged = action_request(root.path(), "POST", "/operator-actions", json!({
        "action_id":"web.publish","parameters":{"guest_port":3000,"audience":"local","agent_id":"other"}
    }), "alice").await;
    assert_eq!(status(&forged), 400);
    let decision = request(
        admin,
        "POST",
        &format!("/admin/approvals/{id}"),
        &auth,
        br#"{"decision":"approve","option":"once"}"#,
    )
    .await;
    assert_eq!(
        status(&decision),
        200,
        "{}",
        String::from_utf8_lossy(&decision)
    );
    assert_eq!(body(&decision)["result"]["status"], "started");
    let result = action_request(
        root.path(),
        "GET",
        &format!("/operator-actions/{id}"),
        Value::Null,
        "alice",
    )
    .await;
    assert!(body(&result)["result"]["unlock_code"].is_null());
    assert_eq!(
        status(
            &request(
                admin,
                "POST",
                &format!("/admin/agents/{ID}/web"),
                &[],
                br#"{"guest_port":3000,"audience":"local"}"#
            )
            .await
        ),
        401
    );
    let output = tokio::process::Command::new(selected_cli)
        .arg("--instance-dir")
        .arg(root.path())
        .args([
            "agent",
            "publish",
            "alice",
            "--port",
            "3000",
            "--audience",
            "local",
            "--ttl",
            "60",
            "--json",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let published: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(published["guest_port"], 3000);
    assert_eq!(published["agent_id"], ID);
    assert_eq!(published["reused"], true);
    let url: hyper::Uri = published["url"].as_str().unwrap().parse().unwrap();
    let port = url.port_u16().unwrap();
    let locked = request(port, "GET", "/callback?done=1", &[], b"").await;
    assert!(String::from_utf8_lossy(&locked).contains("return_to"));
    assert!(!String::from_utf8_lossy(&locked).contains("app_session"));
    let unlock = request(
        port,
        "POST",
        "/_safeyolo_preview/unlock",
        &[
            ("Content-Type", "application/x-www-form-urlencoded".into()),
            ("Origin", format!("http://127.0.0.1:{port}")),
        ],
        format!(
            "code={}&return_to=%2Flogin",
            published["unlock_code"].as_str().unwrap()
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status(&unlock), 303);
    let unlock = String::from_utf8(unlock).unwrap();
    assert!(unlock.contains("Location: /login\r\n"));
    let cookie = unlock
        .lines()
        .find_map(|line| line.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let login = request(
        port,
        "GET",
        "/login",
        &[
            ("Cookie", cookie.clone()),
            ("X-Forwarded-Host", "forged.invalid".into()),
        ],
        b"",
    )
    .await;
    assert_eq!(status(&login), 303);
    assert!(String::from_utf8_lossy(&login).contains("Set-Cookie: app_session=known"));
    let callback = request(
        port,
        "GET",
        "/callback?done=1",
        &[("Cookie", format!("{cookie}; app_session=known"))],
        b"",
    )
    .await;
    assert!(callback.ends_with(b"done"));
    let mut events = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    events
        .write_all(
            format!("GET /events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: {cookie}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut event = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !event.ends_with(b"data: first\n\n") {
            event.push(events.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    drop(events);
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    socket.write_all(format!("GET /socket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nCookie: {cookie}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    assert_eq!(status(&head), 101);
    socket
        .write_all(b"\x81\x82\x01\x02\x03\x04ik")
        .await
        .unwrap();
    let mut echo = [0; 4];
    socket.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"\x81\x02hi");
    drop(socket);
    let submitted = request(
        port,
        "POST",
        "/submit",
        &[("Cookie", cookie.clone())],
        b"one",
    )
    .await;
    assert_eq!(status(&submitted), 502);
    app.await.unwrap();
    assert!(!root.path().join("desktop-start-command").exists());
    assert!(!root.path().join("desktop-ready").exists());
    let other = request(
        admin,
        "POST",
        &format!("/admin/agents/{ID}/web"),
        &auth,
        br#"{"guest_port":3001,"audience":"local","ttl_seconds":1}"#,
    )
    .await;
    assert_eq!(status(&other), 200);
    let other_url: hyper::Uri = body(&other)["url"].as_str().unwrap().parse().unwrap();
    let stopped = request(
        admin,
        "DELETE",
        &format!("/admin/agents/{ID}/web"),
        &auth,
        br#"{"guest_port":3000,"audience":"local"}"#,
    )
    .await;
    assert_eq!(body(&stopped)["stopped"], true);
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err()
    );
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, other_url.port_u16().unwrap()))
            .await
            .is_ok()
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, other_url.port_u16().unwrap()))
            .await
            .is_err()
    );
    proxy.shutdown().await;
    run.child.kill().unwrap();
    run.child.wait().unwrap();
}
