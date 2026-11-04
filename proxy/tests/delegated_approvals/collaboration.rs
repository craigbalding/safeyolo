//! Real Agent API, native approvals, current identities and pinned JetStream.
use super::*;
struct CollaborationNats(std::path::PathBuf);
impl CollaborationNats {
    async fn start(f: &Fixture) -> Self {
        let binary = std::env::var_os("SAFEYOLO_COORD_NATS_BINARY").expect("pinned NATS binary");
        safeyolo_proxy::coord_rooms::start(
            f.root.path(),
            Some(std::path::Path::new(&binary)),
            None,
            None,
        )
        .await
        .unwrap();
        Self(f.root.path().to_owned())
    }
}
impl Drop for CollaborationNats {
    fn drop(&mut self) {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"))
            .arg("--root")
            .arg(&self.0)
            .args(["coord", "stop"])
            .output();
        if let Ok(result) = result
            && !result.status.success()
        {
            eprintln!(
                "owned broker cleanup: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}

fn prepare(f: &Fixture) {
    approval_results::prepare(f);
    fs::write(f.root.path().join("config.toml"),format!("admin_port={}\nadmin_api_token_file='admin_token'\npolicy_file='policy.toml'\naudit_log_path='audit.jsonl'\n",f.admin)).unwrap();
}

async fn request(f: &Fixture, operation: &str, ttl: i64) -> Value {
    let reply = f.agent("worker","POST","/api/coord/request-collaboration",Some(json!({
        "participants":["helper"],"topic":"Inspect the proposed repair","ttl_seconds":ttl,"operation_id":operation,
    }))).await;
    assert_eq!(reply.status, 200, "{}", reply.json());
    reply.json()
}

async fn approve(f: &Fixture, id: &str) -> Value {
    let reply = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":"approve","option":"collaboration"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.json());
    assert_eq!(reply.json()["status"], "approved");
    reply.json()
}

async fn send(f: &Fixture, room: &str, agent: &str, body: &str) -> Reply {
    f.agent(
        agent,
        "POST",
        &format!("/api/coord/rooms/{room}/send"),
        Some(json!({"body":body,"notify":["helper"],"declared_content_type":"text/plain"})),
    )
    .await
}

async fn history(f: &Fixture, room: &str, agent: &str) -> Reply {
    f.agent(
        agent,
        "GET",
        &format!("/api/coord/rooms/{room}/messages?since_sequence=0"),
        None,
    )
    .await
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn collaboration_approval_inspection_offline_restart_and_revocation() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    prepare(&f);
    let nats = CollaborationNats::start(&f).await;
    let pending = request(&f, "ordinary-collaboration", 120).await;
    let id = pending["approval_id"].as_str().unwrap();
    let room = pending["room_name"].as_str().unwrap();
    assert_eq!(pending["status"], "pending");
    assert!(matches!(
        history(&f, room, "helper").await.status,
        403 | 404
    ));
    let shown = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(
        shown["action"]["participants"],
        json!([
            {"name":"helper","agent_id":HELPER_ID},{"name":"worker","agent_id":WORKER_ID}
        ])
    );
    assert!(
        shown["options"][0]["effect"]
            .as_str()
            .unwrap()
            .contains("until")
    );
    for args in [
        vec!["approvals", "show", id],
        vec!["approvals", "explain", id, "--option", "collaboration"],
    ] {
        let rendered = native(&f, &args).await;
        assert!(
            rendered.status.success(),
            "{}",
            String::from_utf8_lossy(&rendered.stderr)
        );
        let display = String::from_utf8(rendered.stdout).unwrap();
        for expected in [
            HELPER_ID,
            WORKER_ID,
            shown["authority"]["expires_at"].as_str().unwrap(),
        ] {
            assert!(display.contains(expected), "missing {expected}: {display}");
        }
    }
    let decision = approve(&f, id).await;
    assert_eq!(
        decision["result"]["expires_at"],
        shown["authority"]["expires_at"]
    );
    assert_eq!(approve(&f, id).await["result"], decision["result"]);
    assert_eq!(
        request(&f, "ordinary-collaboration", 120).await["approval_id"],
        id
    );
    let conn = rusqlite::Connection::open(f.root.path().join("data/coord/v0.db")).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM rooms", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM coord_collaboration_grants", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    let blocked = send(
        &f,
        room,
        "worker",
        "sk-admin-12345678 bearer abcdefghijklmnopqrst",
    )
    .await;
    assert_eq!(blocked.status, 403, "{}", blocked.json());
    assert!(
        history(&f, room, "helper").await.json()["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // The receiver has no connection during this send. Ordinary room history
    // and targeted attention survive both proxy and broker restart.
    let sent = send(&f, room, "worker", "offline recipient receives this repair").await;
    assert_eq!(sent.status, 200, "{}", sent.json());
    assert_eq!(sent.json()["envelope"]["sender_agent_id"], WORKER_ID);
    let attention = sent.json()["attention_recipients"][0]["attention_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(matches!(history(&f, room, "peer").await.status, 403 | 404));
    drop(conn);
    drop(nats);
    assert!(matches!(
        send(&f, room, "worker", "broker unavailable").await.status,
        503 | 504
    ));
    let f = f.restart().await;
    let _nats = CollaborationNats::start(&f).await;
    // The operator attaches through host-only credentials. Guests continue to
    // use the Agent API; inspection events contain metadata, not message text.
    let process: Value = serde_json::from_slice(
        &fs::read(f.root.path().join("data/coord/nats/process.json")).unwrap(),
    )
    .unwrap();
    let password = fs::read_to_string(f.root.path().join("data/coord/nats/creds")).unwrap();
    let operator = async_nats::ConnectOptions::new()
        .user_and_password("safeyolo".into(), password.trim().into())
        .connect(format!(
            "nats://127.0.0.1:{}",
            process["client_port"].as_u64().unwrap()
        ))
        .await
        .unwrap();
    let mut events = operator
        .subscribe("safeyolo.operator.events")
        .await
        .unwrap();
    operator.flush().await.unwrap();
    let retained = history(&f, room, "helper").await;
    assert_eq!(retained.status, 200, "{}", retained.json());
    assert_eq!(
        retained.json()["messages"][0]["body"],
        "offline recipient receives this repair"
    );
    assert_eq!(retained.json()["messages"].as_array().unwrap().len(), 1);
    let observed = f
        .agent(
            "helper",
            "GET",
            &format!("/api/coord/attention/{attention}/object"),
            None,
        )
        .await;
    assert_eq!(observed.status, 200, "{}", observed.json());
    let wait_path = format!(
        "/api/coord/rooms/{room}/wait?since={}&timeout=2",
        sent.json()["sequence"].as_u64().unwrap()
    );
    let (waiting, ()) = tokio::join!(f.agent("helper", "GET", &wait_path, None), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        safeyolo_proxy::coord_rooms::grant(
            &f.root.path().join("config.toml"),
            room,
            "helper",
            &[],
            true,
            Some("revoke-collaborator"),
        )
        .unwrap();
    });
    assert!(
        matches!(waiting.status, 403 | 404)
            || (waiting.status == 200
                && waiting.json()["messages"]
                    .as_array()
                    .is_some_and(Vec::is_empty)),
        "{} {}",
        waiting.status,
        waiting.json()
    );
    assert!(matches!(
        history(&f, room, "helper").await.status,
        403 | 404
    ));
    safeyolo_proxy::coord_rooms::grant(
        &f.root.path().join("config.toml"),
        room,
        "helper",
        &["receive".into()],
        false,
        Some("regrant-reader"),
    )
    .unwrap();
    assert_eq!(
        history(&f, room, "helper").await.json()["messages"][0]["body"],
        "offline recipient receives this repair"
    );
    let detected = send(&f, room, "worker", "bearer abcdefghijklmnopqrst").await;
    assert_eq!(detected.status, 200, "{}", detected.json());
    assert_eq!(
        detected.json()["envelope"]["inspection"]["detected_classes"],
        json!(["generic-bearer-in-body"])
    );
    use futures_util::StreamExt;
    let observed = timeout(Duration::from_secs(5), async {
        while let Some(message) = events.next().await {
            let event: Value = serde_json::from_slice(&message.payload).unwrap();
            if event["event"] == "coord.message_flagged" {
                return event;
            }
        }
        panic!("operator inspection stream ended");
    })
    .await
    .unwrap();
    assert_eq!(
        observed["details"]["inspection"]["detected_classes"],
        json!(["generic-bearer-in-body"])
    );
    assert!(!observed.to_string().contains("abcdefghijklmnopqrst"));
    drop(_nats);
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn collaboration_default_multibyte_escaped_and_configured_body_bounds() {
    let mut f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    prepare(&f);
    let _nats = CollaborationNats::start(&f).await;
    let pending = request(&f, "size-collaboration", 120).await;
    approve(&f, pending["approval_id"].as_str().unwrap()).await;
    let room = pending["room_name"].as_str().unwrap();
    for body in ["é".repeat(524288), "\u{1}".repeat(1048576)] {
        let reply = send(&f, room, "worker", &body).await;
        assert_eq!(reply.status, 200, "{}", reply.json());
        assert_eq!(
            reply.json()["envelope"]["inspection"]["size_bytes"],
            1048576
        );
    }
    assert_eq!(
        send(&f, room, "worker", &"a".repeat(1048577)).await.status,
        413
    );
    let received = history(&f, room, "helper").await;
    assert_eq!(received.status, 200, "{}", received.json());
    assert_eq!(received.json()["messages"].as_array().unwrap().len(), 2);
    f.config.collaboration.max_message_bytes = 0;
    let f = f.restart().await;
    assert_eq!(
        send(&f, room, "worker", &"a".repeat(1048577)).await.status,
        200
    );
    // A zero body bound still has the separately reported envelope ceiling.
    let oversized = send(&f, room, "worker", &"\u{1}".repeat(1400000)).await;
    assert_eq!(oversized.status, 413, "{}", oversized.json());
    assert_eq!(oversized.json()["max_bytes"], 8 * 1024 * 1024);
    let envelope = send(&f, room, "worker", &"a".repeat(8 * 1024 * 1024 - 256)).await;
    assert_eq!(envelope.status, 413, "{}", envelope.json());
    assert_eq!(envelope.json()["max_envelope_bytes"], 8 * 1024 * 1024);
    drop(_nats);
    f.stop().await;
}

#[tokio::test]
#[ignore = "requires pinned SAFEYOLO_COORD_NATS_BINARY"]
async fn collaboration_pending_denial_expiry_identity_and_interrupted_commit() {
    let f = Fixture::new().await;
    let _backend = Backend(runs(&f));
    coord_room::rooms(&f);
    let nats = CollaborationNats::start(&f).await;
    let (first, retry) = tokio::join!(
        request(&f, "concurrent-collaboration", 120),
        request(&f, "concurrent-collaboration", 120)
    );
    assert_eq!(first["approval_id"], retry["approval_id"]);
    let denied = request(&f, "denied-collaboration", 120).await;
    let id = denied["approval_id"].as_str().unwrap();
    let rejection = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":"reject","option":"collaboration"})),
        )
        .await;
    assert_eq!(rejection.status, 200, "{}", rejection.json());
    assert_eq!(
        request(&f, "denied-collaboration", 120).await["status"],
        "rejected"
    );
    assert!(matches!(
        history(&f, denied["room_name"].as_str().unwrap(), "helper")
            .await
            .status,
        403 | 404
    ));
    let expired = request(&f, "expired-collaboration", 1).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let expiry = f
        .admin(
            "POST",
            &format!(
                "/admin/approvals/{}",
                expired["approval_id"].as_str().unwrap()
            ),
            Some(json!({"decision":"approve","option":"collaboration"})),
        )
        .await;
    assert_eq!(expiry.status, 409, "{}", expiry.json());
    assert_eq!(expiry.json()["status"], "expired");
    let short = request(&f, "short-approved-collaboration", 1).await;
    let short_id = short["approval_id"].as_str().unwrap();
    approve(&f, short_id).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        history(&f, short["room_name"].as_str().unwrap(), "helper")
            .await
            .status,
        403 | 404
    ));
    assert_eq!(
        f.admin("GET", &format!("/admin/approvals/{short_id}"), None)
            .await
            .json()["grant_active"],
        false
    );
    let pending = request(&f, "interrupted-collaboration", 120).await;
    let id = pending["approval_id"].as_str().unwrap();
    // Existing-room delegation cannot create this room or grant its audience.
    let (_, revision) = delegate(&f, coord_room::envelope()).await;
    let delegated = decide(&f, "helper", id, "approve", "collaboration").await;
    assert!(
        matches!(delegated.status, 400 | 403 | 404 | 409),
        "{} {}",
        delegated.status,
        delegated.json()
    );
    let changed = f.agent("worker","POST","/api/coord/request-collaboration",Some(json!({"participants":["peer"],"operation_id":"interrupted-collaboration","ttl_seconds":120}))).await;
    assert_eq!(changed.status, 400);
    let inert = request(&f, "inert-collaboration", 120).await;
    let inert_id = inert["approval_id"].as_str().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let interrupted = f
        .admin(
            "POST",
            &format!("/admin/approvals/{inert_id}"),
            Some(json!({"decision":"approve","option":"collaboration"})),
        )
        .await;
    fs::set_permissions(f.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_ne!(interrupted.status, 200, "{}", interrupted.json());
    assert!(
        matches!(
            history(&f, inert["room_name"].as_str().unwrap(), "helper")
                .await
                .status,
            403 | 404
        ),
        "prepared membership without a policy receipt is inert"
    );
    let inert_room = inert["room_name"].as_str().unwrap();
    safeyolo_proxy::coord_rooms::grant(
        &f.root.path().join("config.toml"),
        inert_room,
        "peer",
        &["receive".into()],
        false,
        Some("changed-prepared-audience"),
    )
    .unwrap();
    let widened = f
        .admin(
            "POST",
            &format!("/admin/approvals/{inert_id}"),
            Some(json!({"decision":"approve","option":"collaboration"})),
        )
        .await;
    assert_eq!(widened.status, 503, "{}", widened.json());
    assert!(matches!(
        history(&f, inert_room, "helper").await.status,
        403 | 404
    ));
    safeyolo_proxy::coord_rooms::grant(
        &f.root.path().join("config.toml"),
        inert_room,
        "peer",
        &[],
        true,
        Some("restore-prepared-audience"),
    )
    .unwrap();
    approve(&f, inert_id).await;
    assert_eq!(
        send(
            &f,
            inert["room_name"].as_str().unwrap(),
            "worker",
            "activated once"
        )
        .await
        .status,
        200
    );
    let store = rusqlite::Connection::open(f.root.path().join("data/approvals.sqlite3")).unwrap();
    store.execute_batch("CREATE TRIGGER interrupt_collaboration_commit BEFORE UPDATE ON approvals WHEN json_extract(NEW.record,'$.status')='approved' BEGIN SELECT RAISE(FAIL,'controlled lost terminal save'); END;").unwrap();
    let committed = f
        .admin(
            "POST",
            &format!("/admin/approvals/{id}"),
            Some(json!({"decision":"approve","option":"collaboration"})),
        )
        .await;
    assert_eq!(committed.status, 503, "{}", committed.json());
    store
        .execute_batch("DROP TRIGGER interrupt_collaboration_commit")
        .unwrap();
    drop(store);
    let recovered = approve(&f, id).await;
    let room = pending["room_name"].as_str().unwrap();
    assert_eq!(recovered["grant_active"], true);
    assert_eq!(
        send(&f, room, "worker", "recovered native receipt")
            .await
            .status,
        200
    );
    let revoked = f
        .admin(
            "POST",
            "/admin/approval-delegations/local/revoke",
            Some(json!({"expected_revision":revision})),
        )
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.json());
    let original = f.source();
    f.apply(&original.replace(HELPER_ID, "ag-66666666666666666666666666666666"))
        .await;
    assert!(matches!(
        history(&f, room, "helper").await.status,
        403 | 404
    ));
    f.apply(&original).await;
    assert!(
        matches!(history(&f, room, "helper").await.status, 403 | 404),
        "restoring a removed identity cannot resurrect its collaboration source"
    );
    let native = f
        .admin("GET", &format!("/admin/approvals/{id}"), None)
        .await
        .json();
    assert_eq!(native["active_participant_ids"], json!([WORKER_ID]));
    drop(nats);
    f.stop().await;
}
