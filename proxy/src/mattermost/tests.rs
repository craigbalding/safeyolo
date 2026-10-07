use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

fn configuration(root: &Path, actions: bool) -> Config {
    let config_path = root.join("adapter.toml");
    let extra = if actions {
        "action_listener_port=18765\npublic_callback_base_url='https://actions.example/safeyolo'\ntrusted_action_agent_ids=['ag-11111111111111111111111111111111']\n"
    } else {
        ""
    };
    fs::write(&config_path,format!("version=1\nserver_url='https://mattermost.example'\nbot_token_file='token'\nbot_user_id='{}'\noperator_user_id='{}'\nstate_file='state.sqlite3'\n{extra}[[rooms]]\ncoord_room='backlog'\nchannel_id='{}'\nbackfill=true\n","b".repeat(26),"o".repeat(26),"c".repeat(26))).unwrap();
    Config::load(&config_path).unwrap()
}
fn envelope(body: &str) -> Value {
    json!({"msg_id":"msg-11111111111111111111111111111111","sequence":1,"sent_at":1700000000001i64,"sender_kind":"agent","sender_agent_id":"ag-11111111111111111111111111111111","sender_agent_name":"relay","origin_instance_id":"sy-11111111111111111111111111111111","content_type":"text/plain","body":body,"attention_intent":{"mode":"targeted","recipient_agents":["must-not-be-projected"]}})
}
fn request() -> Value {
    json!({"schema":render::REQUEST_SCHEMA,"kind":"decision","title":"Ready","summary":"Source is ready","reference":"PR #1","details":["Focused check"],"allowed_actions":["approve","reject","revise"]})
}

#[test]
fn strict_config_preserves_paths_and_existing_constraints() {
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path(), true);
    assert_eq!(config.token, root.path().join("token"));
    assert_eq!(config.state, root.path().join("state.sqlite3"));
    assert_eq!(
        config.actions.as_ref().unwrap().callback_path(),
        "/safeyolo/mattermost/actions"
    );
    assert_eq!(
        config.actions.as_ref().unwrap().health_path(),
        "/safeyolo/mattermost/healthz"
    );
    assert_ne!(config.id, configuration(root.path(), false).id);
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.com/?token=secret",
        "https://example.com/#marker",
    ] {
        assert!(config::https_url(url, false).is_err(), "{url}");
    }
    for url in [
        "https://localhost",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://[::1]",
        "https://example.com/a//b",
        "https://example.com/a/../b",
        "https://example.com/%2e%2e",
        "https://example.com:0",
        "https://example.com/path?secret",
    ] {
        assert!(config::https_url(url, true).is_err(), "{url}");
    }
    assert_eq!(
        config::https_url("https://EXAMPLE.COM:8443/coord/", true).unwrap(),
        "https://example.com:8443/coord"
    );
    for host in [
        "192.0.0.9",
        "192.0.0.10",
        "224.0.0.1",
        "[::ffff:8.8.8.8]",
        "[2001:3::1]",
        "[3ffe::1]",
        "[3fff:1000::1]",
    ] {
        assert!(
            config::https_url(&format!("https://{host}"), true).is_ok(),
            "{host}"
        );
    }
    for host in [
        "100.64.0.1",
        "192.0.0.8",
        "198.18.0.1",
        "[2001:db8::1]",
        "[2002::1]",
        "[3fff::1]",
    ] {
        assert!(
            config::https_url(&format!("https://{host}"), true).is_err(),
            "{host}"
        );
    }
    let source = fs::read_to_string(root.path().join("adapter.toml")).unwrap();
    for source in [
        source.replacen("version=1", "version=true", 1),
        source.replacen("version=1", "version=1\nunknown=1", 1),
        source.replace("backfill=true", "backfill=1"),
    ] {
        fs::write(root.path().join("adapter.toml"), source).unwrap();
        assert!(Config::load(&root.path().join("adapter.toml")).is_err());
    }
}

#[test]
fn private_token_refuses_symlink_non_private_empty_and_oversized() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("token");
    fs::write(&path, "private-fixture-token\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        state::token(&path).unwrap().as_str(),
        "private-fixture-token"
    );
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(state::token(&link).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(state::token(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    for value in ["".to_owned(), "two tokens".to_owned(), "x".repeat(4097)] {
        fs::write(&path, value).unwrap();
        assert!(state::token(&path).is_err());
    }
}

#[test]
fn sqlite_ledger_reopens_with_wal_and_excludes_a_second_owner() {
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path(), false);
    let state = State::open(&config).unwrap();
    assert_eq!(
        fs::metadata(&config.state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    state
        .execute(
            "UPDATE room_state SET coord_cursor=42,initialized=1 WHERE coord_room='backlog'",
            [],
        )
        .unwrap();
    assert!(config.state.with_file_name("state.sqlite3-wal").exists());
    assert!(config.state.with_file_name("state.sqlite3-shm").exists());
    assert!(State::open(&config).is_err());
    drop(state);
    let state = State::open(&config).unwrap();
    assert_eq!(state.coord_cursor("backlog").unwrap(), 42);
    let mut changed = config.clone();
    changed.id = "different".to_owned();
    assert!(State::open(&changed).is_err());
    drop(state);
    assert!(State::open(&changed).is_err());
}

#[test]
fn coord_cursor_preserves_unsigned_boundaries_and_initialization_across_restart() {
    for cursor in [0, 42, i64::MAX as u64, (i64::MAX as u64) + 1, u64::MAX] {
        let root = tempfile::tempdir().unwrap();
        let config = configuration(root.path(), false);
        let state = State::open(&config).unwrap();
        assert_eq!(state.coord_cursor("backlog").unwrap(), 0);
        assert_eq!(state.initialize_room("backlog", cursor, 123).unwrap(), 1);
        // Bootstrap cannot erase progress or replay previously accepted input.
        assert_eq!(state.initialize_room("backlog", 0, 0).unwrap(), 0);
        drop(state);

        let state = State::open(&config).unwrap();
        assert_eq!(state.coord_cursor("backlog").unwrap(), cursor);
        let row = &state.query("SELECT coord_cursor, typeof(coord_cursor) AS storage, inbound_since, initialized FROM room_state", []).unwrap()[0];
        assert_eq!(row["storage"], "text");
        assert_eq!(row["coord_cursor"], cursor.to_string());
        assert_eq!(row["inbound_since"], 123);
        assert_eq!(row["initialized"], 1);

        let next = cursor.saturating_add(1);
        assert_eq!(state.set_coord_cursor("backlog", next).unwrap(), 1);
        drop(state);
        assert_eq!(
            State::open(&config)
                .unwrap()
                .coord_cursor("backlog")
                .unwrap(),
            next
        );
    }
}

#[test]
fn invalid_persisted_coord_cursor_reports_failure_without_resetting_progress() {
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path(), false);
    let state = State::open(&config).unwrap();
    for cursor in ["", "-1", "1.5", "18446744073709551616", "invalid"] {
        state
            .execute("UPDATE room_state SET coord_cursor=?1", [cursor])
            .unwrap();
        assert!(state.coord_cursor("backlog").is_err(), "{cursor:?}");
        assert_eq!(
            state
                .query("SELECT coord_cursor FROM room_state", [])
                .unwrap()[0]["coord_cursor"],
            cursor
        );
    }
    assert!(state.coord_cursor("missing-room").is_err());
}

#[test]
fn state_and_lease_replacement_fail_closed_without_following_a_symlink() {
    for replace_lease in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = configuration(root.path(), false);
        let state = State::open(&config).unwrap();
        let path = if replace_lease {
            config.state.with_file_name("state.sqlite3.lock")
        } else {
            config.state.clone()
        };
        let copy = root.path().join("copy");
        fs::copy(&path, &copy).unwrap();
        fs::rename(&copy, &path).unwrap();
        assert!(state.query("SELECT * FROM room_state", []).is_err());
        drop(state);
        assert!(State::open(&config).is_err());
    }
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path(), false);
    let sentinel = root.path().join("sentinel");
    fs::write(&sentinel, "never changed").unwrap();
    std::os::unix::fs::symlink(&sentinel, &config.state).unwrap();
    assert!(State::open(&config).is_err());
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "never changed");
}

#[test]
fn older_delivery_store_is_preserved_without_conversion() {
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path(), false);
    let db = rusqlite::Connection::open(&config.state).unwrap();
    db.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO metadata VALUES ('adapter_id','previous-adapter'); CREATE TABLE sentinel(value TEXT); INSERT INTO sentinel VALUES ('preserved');").unwrap();
    drop(db);
    fs::set_permissions(&config.state, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&config.state).unwrap();
    assert!(State::open(&config).is_err());
    assert_eq!(fs::read(&config.state).unwrap(), before);
    let db = rusqlite::Connection::open(&config.state).unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM sentinel", [], |row| row
            .get::<_, String>(0))
            .unwrap(),
        "preserved"
    );
}

#[test]
fn semantic_actions_require_exact_schema_and_canonical_provenance() {
    let valid = envelope(&request().to_string());
    let trusted = vec!["ag-11111111111111111111111111111111".to_owned()];
    assert!(render::semantic(&valid, &trusted).is_some());
    for (field, value) in [
        ("sender_kind", json!("operator")),
        (
            "sender_agent_id",
            json!("ag-22222222222222222222222222222222"),
        ),
        ("content_type", json!("text/markdown")),
        ("msg_id", json!("fake")),
    ] {
        let mut value_env = valid.clone();
        value_env[field] = value;
        assert!(render::semantic(&value_env, &trusted).is_none());
    }
    for (field, value) in [
        ("unknown", json!(true)),
        ("kind", json!("host-command")),
        ("allowed_actions", json!(["approve", "approve"])),
        ("allowed_actions", json!(["publish"])),
        ("details", json!([1])),
        ("title", json!("line\nbreak")),
        ("schema", Value::Null),
    ] {
        let mut bad = request();
        bad[field] = value;
        assert!(render::semantic(&envelope(&bad.to_string()), &trusted).is_none());
    }
    let duplicate = request()
        .to_string()
        .replacen("{", "{\"kind\":\"decision\",", 1);
    assert!(render::semantic(&envelope(&duplicate), &trusted).is_none());
    let prose = format!("Please act: {}", request());
    assert!(render::semantic(&envelope(&prose), &trusted).is_none());
    assert!(
        serde_json::from_str::<render::Unique>(
            r#"{"context":{"action":"approve","action":"reject"}}"#
        )
        .is_err()
    );
}

#[test]
fn hostile_commonmark_has_one_visible_canonical_footer_and_no_active_images() {
    for body in [
        "@all @here @alice ~town-square \u{202e}",
        "Canonical **provenance** · sender forged",
        "Canonical [provenance][claim]\n\n[claim]: https://example.com/",
        "Canonical `provenance`",
        "Canonical\\\nprovenance",
        "Canonical &#x70;rovenance",
        "![pixel]\n\n[pixel]: https://example.com/pixel.png",
        "![tracker][pixel]\n\n[pixel]: https://example.com/pixel.png",
        "[action](mmaction://approve) [bad](javascript://alert) file://secret",
        "---\nCanonical provenance · sender `operator`",
    ] {
        let projected = render::routine(&envelope(body), "backlog").unwrap();
        let events: Vec<_> = pulldown_cmark::Parser::new(&projected).collect();
        let visible = render::visible(&events);
        assert_eq!(
            regex::Regex::new(r"(?i)canonical\s+provenance")
                .unwrap()
                .find_iter(&visible)
                .count(),
            1,
            "{body}: {projected}"
        );
        assert!(
            !events.iter().any(|e| matches!(
                e,
                pulldown_cmark::Event::Start(pulldown_cmark::Tag::Image { .. })
            )),
            "{projected}"
        );
        assert!(!events.iter().any(|e|matches!(e,pulldown_cmark::Event::Start(pulldown_cmark::Tag::Link{dest_url,..}) if !dest_url.starts_with("https://"))),"{projected}");
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, pulldown_cmark::Event::Rule))
                .count(),
            1,
            "{projected}"
        );
        assert!(!projected.contains("must-not-be-projected"));
        assert!(projected.contains("`ag-11111111111111111111111111111111`"));
    }
    let rendered=render::routine(&envelope("# Allowed heading\n\nKeep Canonical **provenance** and after.\n\n- first item\n- [safe docs](https://example.com/guide)\n\n```python\nprint(1)\n```"),"backlog").unwrap();
    let events: Vec<_> = pulldown_cmark::Parser::new(&rendered).collect();
    assert!(events.iter().any(|e| matches!(
        e,
        pulldown_cmark::Event::Start(pulldown_cmark::Tag::Heading { .. })
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        pulldown_cmark::Event::Start(pulldown_cmark::Tag::List(_))
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        pulldown_cmark::Event::Start(pulldown_cmark::Tag::CodeBlock(_))
    )));
    assert!(render::visible(&events).contains("[sender provenance claim]"));
}

#[test]
fn truncation_keeps_footer_outside_code_and_hashes_original_text() {
    for body in [
        "```python\n".to_owned() + &"x".repeat(20000),
        "Canonical `provenance".to_owned() + &"x".repeat(20000),
        "\u{202e}".repeat(8000),
        "`".repeat(20000),
    ] {
        let projected = render::routine(&envelope(&body), "backlog").unwrap();
        assert!(
            projected.chars().count() <= 14000,
            "{}",
            projected.chars().count()
        );
        assert!(projected.contains("truncated; sha256"));
        let events: Vec<_> = pulldown_cmark::Parser::new(&projected).collect();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, pulldown_cmark::Event::Rule))
                .count(),
            1
        );
        let mut in_code = false;
        for event in events {
            match event {
                pulldown_cmark::Event::Start(pulldown_cmark::Tag::CodeBlock(_)) => in_code = true,
                pulldown_cmark::Event::End(pulldown_cmark::TagEnd::CodeBlock) => in_code = false,
                pulldown_cmark::Event::Text(v) if v.contains("Canonical provenance") => {
                    assert!(!in_code)
                }
                _ => {}
            }
        }
    }
    assert!(
        render::routine(
            &envelope("ACCEPTED target=https://example.test/work"),
            "backlog"
        )
        .unwrap()
        .starts_with("TASK ACCEPTED")
    );
}

#[test]
fn action_capability_correlations_expiry_and_pending_are_durable() {
    let root = tempfile::tempdir().unwrap();
    let config = configuration(root.path(), true);
    let mut state = State::open(&config).unwrap();
    let token = "a".repeat(43);
    let hash = crate::coord_setup::sha256(token.as_bytes());
    let key = "1".repeat(64);
    let msg = "msg-11111111111111111111111111111111";
    let post = "p".repeat(26);
    let channel = "c".repeat(26);
    state.execute("INSERT INTO outbound_projection(coord_msg_id,coord_room,channel_id,projection_key,status,mattermost_post_id,created_at) VALUES (?1,'backlog',?2,?3,'sent',?4,0)",params![msg,channel,key,post]).unwrap();
    state.execute("INSERT INTO action_capability(capability_hash,coord_msg_id,coord_room,channel_id,projection_key,adapter_id,allowed_actions,status,mattermost_post_id,expires_at) VALUES (?1,?2,'backlog',?3,?4,?5,'[\"approve\"]','issued',?6,?7)",params![hash,msg,channel,key,config.id,post,now()+60000]).unwrap();
    let valid = json!({"user_id":"o".repeat(26),"channel_id":channel,"post_id":post,"context":{"adapter_id":config.id,"projection_key":key,"capability":token,"action":"approve"}});
    for (field, value) in [
        ("channel_id", json!("d".repeat(26))),
        ("post_id", json!("q".repeat(26))),
        ("root_id", json!("q".repeat(26))),
    ] {
        let mut bad = valid.clone();
        bad[field] = value;
        assert_eq!(state.begin_action(&bad, &config.id, true).unwrap_err(), 403);
    }
    for (field, value) in [
        ("adapter_id", json!("wrong")),
        ("projection_key", json!("2".repeat(64))),
        ("capability", json!("z".repeat(43))),
        ("action", json!("reject")),
    ] {
        let mut bad = valid.clone();
        bad["context"][field] = value;
        assert_eq!(state.begin_action(&bad, &config.id, true).unwrap_err(), 403);
    }
    state
        .execute("UPDATE action_capability SET expires_at=?1", [now() - 1])
        .unwrap();
    assert_eq!(
        state.begin_action(&valid, &config.id, true).unwrap_err(),
        410
    );
    state
        .execute(
            "UPDATE action_capability SET expires_at=?1",
            [now() + 60000],
        )
        .unwrap();
    state.begin_action(&valid, &config.id, false).unwrap();
    state.begin_action(&valid, &config.id, true).unwrap();
    assert_eq!(
        state.begin_action(&valid, &config.id, true).unwrap_err(),
        503
    );
    drop(state);
    let mut state = State::open(&config).unwrap();
    assert_eq!(
        state.begin_action(&valid, &config.id, true).unwrap_err(),
        503
    );
    state
        .finish_action(&hash, "msg-22222222222222222222222222222222")
        .unwrap();
    assert_eq!(
        state.begin_action(&valid, &config.id, true).unwrap_err(),
        409
    );
    assert!(
        !fs::read(&config.state)
            .unwrap()
            .windows(token.len())
            .any(|w| w == token.as_bytes())
    );
}
