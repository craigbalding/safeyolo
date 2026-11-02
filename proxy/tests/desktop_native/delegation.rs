//! Controlled commands exercise the real approval and preview transport. These
//! checks do not establish graphical presentation or model-visible attention.
use super::*;

const BOB: &str = "ag-22222222222222222222222222222222";

#[test]
fn delegated_desktop_preserves_independent_sources_and_disconnects_revoked_viewers() {
    let _environment = DESKTOP_TEST_ENV.lock().unwrap_or_else(|e| e.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(check());
}

async fn admin(port: u16, path: &str, input: Value) -> Value {
    let reply = request(
        port,
        if input.is_null() { "GET" } else { "POST" },
        path,
        &[("Authorization", format!("Bearer {TOKEN}"))],
        if input.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&input).unwrap()
        }
        .as_slice(),
    )
    .await;
    assert_eq!(status(&reply), 200, "{}", String::from_utf8_lossy(&reply));
    body(&reply)
}

async fn delegate(port: u16, name: &str, mut input: Value) -> (Value, String) {
    let preview = admin(
        port,
        &format!("/admin/approval-delegations/{name}/preview"),
        input.clone(),
    )
    .await;
    let revision = preview["revision"].as_str().unwrap().to_owned();
    input["delegation"] = preview["after"].clone();
    input["delegation"]["acknowledgment"] = json!(revision);
    admin(
        port,
        &format!("/admin/approval-delegations/{name}/apply"),
        input.clone(),
    )
    .await;
    (input, revision)
}

async fn ask(root: &Path, ttl: u32, url: Option<&str>) -> String {
    let reply = action_request(
        root,
        "POST",
        "/operator-actions",
        json!({"action_id":"desktop.present","parameters":{"ttl_seconds":ttl,"browser_url":url}}),
        "alice",
    )
    .await;
    assert_eq!(status(&reply), 202, "{}", String::from_utf8_lossy(&reply));
    body(&reply)["approval_id"].as_str().unwrap().into()
}

async fn decide(root: &Path, id: &str, decision: &str, delegation: &str) -> Vec<u8> {
    action_request(
        root,
        "POST",
        &format!("/approvals/{id}/resolve"),
        json!({"decision":decision,"delegation":delegation,"option":"once"}),
        "bob",
    )
    .await
}

async fn inspect(port: u16, id: &str) -> Value {
    admin(port, &format!("/admin/approvals/{id}"), Value::Null).await
}

async fn viewer(port: u16, id: &str) -> (Value, TcpStream, String) {
    let view = inspect(port, id).await;
    let preview = &view["operator_preview"];
    let url = preview["url"].as_str().unwrap();
    let uri = url.parse::<hyper::Uri>().unwrap();
    let port = uri.port_u16().unwrap();
    let unlocked = request_host(
        port,
        &format!("alice.localhost:{port}"),
        "POST",
        "/_safeyolo_preview/unlock",
        &[("Content-Type", "application/x-www-form-urlencoded".into())],
        format!("code={}", preview["unlock_code"].as_str().unwrap()).as_bytes(),
    )
    .await;
    assert_eq!(
        status(&unlocked),
        303,
        "{}",
        String::from_utf8_lossy(&unlocked)
    );
    let cookie = String::from_utf8_lossy(&unlocked)
        .lines()
        .find_map(|line| line.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let socket = preview_viewer(port, "alice", &cookie, "/websockify").await;
    (view, socket, cookie)
}

async fn check() {
    let root = TempDir::new().unwrap();
    fixture(root.path());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let preview_port = listener.local_addr().unwrap().port();
    drop(listener);
    fs::write(root.path().join("policy.toml"),format!("[agents.alice]\nagent_id='{ID}'\n[agents.bob]\nagent_id='{BOB}'\n[controls.credentials]\nenabled=false\n")).unwrap();
    fs::write(root.path().join("config.toml"),format!("admin_port=0\nadmin_api_token_file='token'\npolicy_file='policy.toml'\nreadiness_file='ready.json'\naudit_log_path='audit.jsonl'\n[desktop]\nsize='1280x800'\npresent_host_port={preview_port}\n")).unwrap();
    for (program, source) in [
        (
            "xdpyinfo",
            "#!/bin/sh\nprintf 'dimensions: 1920x1080 pixels\\n'\n",
        ),
        (
            "xdg-open",
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$SAFEYOLO_CONFIG_DIR/opened\"\n",
        ),
    ] {
        let path = root.path().join("bin").join(program);
        fs::write(&path, source).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let _alice = OwnedRun::start(root.path());
    let run = bind_action_run(root.path(), "alice", ID);
    let _bob = OwnedRun::start_agent(root.path(), "bob");
    bind_action_run(root.path(), "bob", BOB);
    unsafe {
        std::env::set_var(
            "FAKE_RUN_ID",
            format!("safeyolo-{}", run["run_id"].as_str().unwrap()),
        );
    }
    let guest = preview_guest(
        UnixListener::bind(root.path().join("guest.sock")).unwrap(),
        "alice",
    );
    let mut config = config(root.path());
    config.native_product = true;
    config.native_config_dir = Some(root.path().into());
    config.native_config_path = Some(root.path().join("config.toml"));
    config.policy_file = Some(root.path().join("policy.toml"));
    config.listeners.push(
        serde_json::from_value(
            json!({"agent_id":"bob","socket_path":root.path().join("bob.sock")}),
        )
        .unwrap(),
    );
    let proxy = Proxy::start(config).await.unwrap();
    let ready: Value =
        serde_json::from_slice(&fs::read(root.path().join("ready.json")).unwrap()).unwrap();
    let port = ready["admin_port"].as_u64().unwrap() as u16;
    let input = json!({"expected_revision":null,"delegation":{
        "reviewers":[{"name":"bob","agent_id":BOB}],"beneficiaries":[{"name":"alice","agent_id":ID}],
        "scopes":[{"type":"desktop_present","run":run,"presentation":"local","browser_urls":[null,"about:blank"],"any_browser_url":false,"max_ttl_seconds":60}],
        "expires_at":null,"grant_seconds":null,"gateway_once":false,"acknowledgment":null}});
    for bad in [
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["command"] = json!("arbitrary");
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["type"] = json!("*");
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["run"]["run_id"] = json!("0".repeat(32));
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["presentation"] = json!("tailnet");
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["scopes"][0]["max_ttl_seconds"] = json!(86401);
            v
        },
        {
            let mut v = input.clone();
            v["delegation"]["reviewers"] = v["delegation"]["beneficiaries"].clone();
            v
        },
    ] {
        let reply = request(
            port,
            "POST",
            "/admin/approval-delegations/desktop/preview",
            &[("Authorization", format!("Bearer {TOKEN}"))],
            &serde_json::to_vec(&bad).unwrap(),
        )
        .await;
        assert_eq!(status(&reply), 409, "{}", String::from_utf8_lossy(&reply));
    }
    let (_, revision) = delegate(port, "desktop", input.clone()).await;
    let id = ask(root.path(), 30, Some("about:blank")).await;
    let alias = action_request(
        root.path(),
        "POST",
        "/desktop/present",
        json!({"ttl_seconds":30,"browser_url":"about:blank"}),
        "alice",
    )
    .await;
    assert_eq!(
        body(&alias)["approval_id"],
        id,
        "both request surfaces must share one authority record"
    );
    let self_decision = action_request(
        root.path(),
        "POST",
        &format!("/approvals/{id}/resolve"),
        json!({"decision":"approve","delegation":"desktop","option":"once"}),
        "alice",
    )
    .await;
    assert!(matches!(status(&self_decision), 403 | 409));
    let mut partial = input.clone();
    partial["delegation"]["scopes"][0]["max_ttl_seconds"] = json!(2);
    let mut second = partial["delegation"]["scopes"][0].clone();
    second["max_ttl_seconds"] = json!(60);
    second["browser_urls"] = json!([null]);
    partial["delegation"]["scopes"][0]["browser_urls"] = json!(["about:blank"]);
    partial["delegation"]["scopes"]
        .as_array_mut()
        .unwrap()
        .push(second);
    delegate(port, "partial", partial).await;
    assert_eq!(
        status(&decide(root.path(), &id, "approve", "partial").await),
        409,
        "partial URL/lifetime envelopes cannot be combined"
    );
    let mut broad = input.clone();
    broad["delegation"]["scopes"][0]["browser_urls"] = json!([]);
    broad["delegation"]["scopes"][0]["any_browser_url"] = json!(true);
    broad["delegation"]["scopes"][0]["max_ttl_seconds"] = json!(86400);
    let (_, broad_revision) = delegate(port, "broad", broad).await;
    admin(
        port,
        "/admin/approval-delegations/broad/revoke",
        json!({"expected_revision":broad_revision}),
    )
    .await;
    let facts = action_request(
        root.path(),
        "GET",
        &format!("/approvals/{id}"),
        Value::Null,
        "bob",
    )
    .await;
    assert_eq!(status(&facts), 200, "{}", String::from_utf8_lossy(&facts));
    let facts = body(&facts);
    assert_eq!(facts["observed"]["worker_run"], run);
    assert_eq!(facts["choices"][0]["option"], "once");
    let outside = ask(root.path(), 30, Some("https://outside.invalid/")).await;
    assert_eq!(
        status(&decide(root.path(), &outside, "approve", "desktop").await),
        409
    );
    let denied = ask(root.path(), 29, None).await;
    assert_eq!(
        status(&decide(root.path(), &denied, "reject", "desktop").await),
        200
    );
    assert!(!root.path().join("opened").exists());
    let accepted = decide(root.path(), &id, "approve", "desktop").await;
    assert_eq!(
        status(&accepted),
        200,
        "{}",
        String::from_utf8_lossy(&accepted)
    );
    assert!(!String::from_utf8_lossy(&accepted).contains("unlock_code"));
    let (view, mut connected, cookie) = viewer(port, &id).await;
    assert_eq!(view["result"]["status"], "started");
    assert_eq!(
        view["result"]["issued_access"]["delegation_revision"],
        revision
    );
    let opened = fs::read(root.path().join("opened")).unwrap();
    for _ in 0..3 {
        assert_eq!(
            status(&decide(root.path(), &id, "approve", "desktop").await),
            200
        );
    }
    assert_eq!(
        fs::read(root.path().join("opened")).unwrap(),
        opened,
        "approval retry replayed opener"
    );
    let worker = action_request(
        root.path(),
        "GET",
        &format!("/operator-actions/{id}"),
        Value::Null,
        "alice",
    )
    .await;
    let worker = String::from_utf8_lossy(&worker);
    assert!(
        !worker.contains("unlock_code")
            && !worker.contains("sources")
            && !worker.contains("operator_preview")
    );
    admin(
        port,
        "/admin/approval-delegations/desktop/revoke",
        json!({"expected_revision":revision}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), closed_connection(&mut connected))
        .await
        .unwrap();
    let stale = request_host(
        preview_port,
        &format!("alice.localhost:{preview_port}"),
        "GET",
        "/_safeyolo_desktop/",
        &[("Cookie", cookie)],
        b"",
    )
    .await;
    assert!(stale.is_empty() || matches!(status(&stale), 403 | 404));
    assert_eq!(inspect(port, &id).await["result"]["status"], "revoked");
    assert_eq!(
        status(&decide(root.path(), &id, "approve", "desktop").await),
        409
    );

    // Narrowing one source preserves a separately valid delegated source.
    let (_, revision) = delegate(port, "desktop", input.clone()).await;
    let (_, other_revision) = delegate(port, "other", input.clone()).await;
    let first = ask(root.path(), 26, Some("about:blank")).await;
    assert_eq!(
        status(&decide(root.path(), &first, "approve", "desktop").await),
        200
    );
    let (_, mut shared, _) = viewer(port, &first).await;
    let second = ask(root.path(), 27, None).await;
    assert_eq!(
        status(&decide(root.path(), &second, "approve", "other").await),
        200
    );
    let mut narrower = input.clone();
    narrower["expected_revision"] = json!(revision);
    narrower["delegation"]["scopes"][0]["max_ttl_seconds"] = json!(1);
    let (_, narrow_revision) = delegate(port, "desktop", narrower).await;
    assert_eq!(inspect(port, &first).await["result"]["status"], "revoked");
    viewer_message(&mut shared, "alice").await;
    admin(
        port,
        "/admin/approval-delegations/other/revoke",
        json!({"expected_revision":other_revision}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), closed_connection(&mut shared))
        .await
        .unwrap();
    admin(
        port,
        "/admin/approval-delegations/desktop/revoke",
        json!({"expected_revision":narrow_revision}),
    )
    .await;

    // Ordinary operator recovery works without the reviewer and creates its
    // own source. A later delegated source cannot shorten or remove it.
    admin(
        port,
        &format!("/admin/agents/{ID}/desktop/present"),
        json!({}),
    )
    .await;
    let (_, revision) = delegate(port, "desktop", input.clone()).await;
    let next = ask(root.path(), 28, None).await;
    assert_eq!(
        status(&decide(root.path(), &next, "approve", "desktop").await),
        200
    );
    let (_, mut independent, _) = viewer(port, &next).await;
    admin(
        port,
        "/admin/approval-delegations/desktop/revoke",
        json!({"expected_revision":revision}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    viewer_message(&mut independent, "alice").await;
    assert_eq!(inspect(port, &next).await["result"]["status"], "revoked");
    // Denial and expiry also preserve the independently opened preview.
    delegate(port, "desktop", input).await;
    assert_eq!(
        inspect(port, &next).await["result"]["status"],
        "revoked",
        "recreating identical delegation content must not revive an old source"
    );
    let short = ask(root.path(), 1, None).await;
    assert_eq!(
        status(&decide(root.path(), &short, "approve", "desktop").await),
        200
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    viewer_message(&mut independent, "alice").await;
    assert_eq!(inspect(port, &short).await["result"]["status"], "expired");
    let raced = ask(root.path(), 24, None).await;
    let before = fs::read_to_string(root.path().join("opened"))
        .unwrap()
        .lines()
        .count();
    let path = format!("/admin/approvals/{raced}");
    let (reviewer, operator) = tokio::join!(
        decide(root.path(), &raced, "approve", "desktop"),
        admin(port, &path, json!({"decision":"reject"}))
    );
    assert_eq!(
        status(&reviewer),
        200,
        "{}",
        String::from_utf8_lossy(&reviewer)
    );
    assert_eq!(
        body(&reviewer)["status"],
        operator["status"],
        "one terminal decision must win"
    );
    let after = fs::read_to_string(root.path().join("opened"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(
        after - before,
        usize::from(operator["status"] == "approved")
    );
    // A real canonical write failure after policy publication leaves an
    // attributable receipt but cannot start or replay an external effect.
    let lost = ask(root.path(), 23, None).await;
    let database = rusqlite::Connection::open(root.path().join("data/approvals.sqlite3")).unwrap();
    database.execute_batch("CREATE TRIGGER fail_desktop_save BEFORE UPDATE OF record ON approvals WHEN json_extract(NEW.record,'$.result.status')='starting' BEGIN SELECT RAISE(FAIL,'controlled canonical write failure'); END;").unwrap();
    let before = fs::read(root.path().join("opened")).unwrap();
    let failed = decide(root.path(), &lost, "approve", "desktop").await;
    assert!(matches!(status(&failed), 409 | 503));
    assert_eq!(fs::read(root.path().join("opened")).unwrap(), before);
    database
        .execute_batch("DROP TRIGGER fail_desktop_save;")
        .unwrap();
    let recovered = decide(root.path(), &lost, "approve", "desktop").await;
    assert_eq!(
        status(&recovered),
        200,
        "{}",
        String::from_utf8_lossy(&recovered)
    );
    let recovered = inspect(port, &lost).await;
    assert_eq!(recovered["status"], "approved");
    assert_eq!(recovered["result"]["status"], "outcome_unknown");
    assert_eq!(recovered["result"]["issued_access"]["beneficiary"], run);
    assert_eq!(recovered["result"]["preview_active"], false);
    for _ in 0..3 {
        assert_eq!(
            status(&decide(root.path(), &lost, "approve", "desktop").await),
            200
        );
    }
    assert_eq!(
        fs::read(root.path().join("opened")).unwrap(),
        before,
        "recovery replayed an opener"
    );

    // Configuration replacement invalidates the whole delegated action; the
    // operator source remains a separate explicit choice.
    let fresh = ask(root.path(), 25, None).await;
    let source = fs::read_to_string(root.path().join("config.toml")).unwrap();
    fs::write(
        root.path().join("config.toml"),
        source.replace("1280x800", "1024x768"),
    )
    .unwrap();
    assert_eq!(
        status(&decide(root.path(), &fresh, "approve", "desktop").await),
        409
    );
    viewer_message(&mut independent, "alice").await;
    guest.abort();
    let _ = guest.await;
    proxy.shutdown().await;
}
