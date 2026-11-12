use safeyolo_proxy::coding_client::{configure, conflicts, selected};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::symlink, net::UnixListener},
    path::Path,
    process::{Command, Output},
};

#[test]
fn codex_custody_change_requires_disposition_and_preserves_settings() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    fs::create_dir(home.join(".codex")).unwrap();
    fs::write(home.join(".codex/auth.json"), "retained-login").unwrap();
    let before = "# retained\nmodel = 'selected-model'\n[mcp_servers.other]\ncommand = 'other'\n[model_providers.other]\nname = 'other'\n";
    fs::write(home.join(".codex/config.toml"), before).unwrap();
    assert!(configure(home, "codex", "host-vault", false).is_err());
    assert_eq!(
        fs::read_to_string(home.join(".codex/auth.json")).unwrap(),
        "retained-login"
    );
    assert_eq!(
        fs::read_to_string(home.join(".codex/config.toml")).unwrap(),
        before
    );
    configure(home, "codex", "host-vault", true).unwrap();
    assert!(selected(home, "codex").unwrap());
    assert!(!home.join(".codex/auth.json").exists());
    let config = fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(
        config.contains("# retained")
            && config.contains("selected-model")
            && config.contains("[mcp_servers.other]")
    );
    let config: toml::Value = toml::from_str(&config).unwrap();
    assert_eq!(
        config["model_providers"]["safeyolo"]["requires_openai_auth"].as_bool(),
        Some(false)
    );
    assert_eq!(
        config["model_providers"]["safeyolo"]["supports_websockets"].as_bool(),
        Some(false)
    );
    safeyolo_proxy::coord_setup::codex_state(home, None, false, None).unwrap();
    configure(home, "codex", "client", false).unwrap();
    assert!(!selected(home, "codex").unwrap());
}

#[test]
fn claude_disposition_retains_denies_and_reapply_does_not_copy_host_login() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("agent");
    let host = temp.path().join("operator");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(host.join(".claude")).unwrap();
    fs::write(home.join(".claude/.credentials.json"), "guest-original").unwrap();
    fs::write(host.join(".claude/.credentials.json"), "host-original").unwrap();
    fs::write(home.join(".claude/settings.json"),r#"{"permissions":{"deny":["Bash(secret)"]},"env":{"OTHER":"retained","ANTHROPIC_AUTH_TOKEN":"old-auth"},"apiKeyHelper":"old-helper"}"#).unwrap();
    assert_eq!(conflicts(&home, "claude").unwrap().len(), 3);
    assert!(configure(&home, "claude", "host-vault", false).is_err());
    configure(&home, "claude", "host-vault", true).unwrap();
    safeyolo_proxy::coord_setup::claude_state(&home, &host).unwrap();
    assert!(!home.join(".claude/.credentials.json").exists());
    assert_eq!(
        fs::read_to_string(host.join(".claude/.credentials.json")).unwrap(),
        "host-original"
    );
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(home.join(".claude/settings.json")).unwrap()).unwrap();
    assert_eq!(config["permissions"]["deny"][0], "Bash(secret)");
    assert_eq!(config["env"]["OTHER"], "retained");
    assert!(config.get("apiKeyHelper").is_none());
    assert!(selected(&home, "claude").unwrap());
}

#[test]
fn host_configuration_does_not_follow_guest_authentication_links() {
    let temp = tempfile::tempdir().unwrap();
    let host = temp.path().join("host");
    fs::write(&host, "preserve-host-login").unwrap();
    for client in ["codex", "claude"] {
        let home = temp.path().join(client);
        let directory = home.join(if client == "codex" {
            ".codex"
        } else {
            ".claude"
        });
        fs::create_dir_all(&directory).unwrap();
        symlink(
            &host,
            directory.join(if client == "codex" {
                "auth.json"
            } else {
                ".credentials.json"
            }),
        )
        .unwrap();
        assert!(configure(&home, client, "host-vault", true).is_err());
        assert_eq!(fs::read_to_string(&host).unwrap(), "preserve-host-login");
    }
}

#[test]
fn codex_inline_provider_settings_are_retained_and_invalid_shape_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join(".codex")).unwrap();
    let path = temp.path().join(".codex/config.toml");
    fs::write(
        &path,
        "model_providers = { other = { name = 'retained' } }\n",
    )
    .unwrap();
    configure(temp.path(), "codex", "host-vault", false).unwrap();
    let config: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        config["model_providers"]["other"]["name"].as_str(),
        Some("retained")
    );
    fs::write(&path, "model_providers = false\n").unwrap();
    assert!(configure(temp.path(), "codex", "host-vault", false).is_err());
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "model_providers = false\n"
    );
}

#[test]
fn ordinary_client_authentication_launches_without_gateway_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"))
        .args([
            "client-exec",
            "claude",
            "--",
            "/bin/sh",
            "-c",
            "test \"$ANTHROPIC_API_KEY\" = ordinary-client-key && printf ORDINARY_CLIENT",
        ])
        .env("HOME", temp.path())
        .env("ANTHROPIC_API_KEY", "ordinary-client-key")
        .env("SAFEYOLO_COORD_SOCKET", temp.path().join("absent.sock"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ORDINARY_CLIENT");
    assert!(output.stderr.is_empty());
}

fn client_run(home: &Path, socket: &Path, token_file: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_safeyolo-coord"))
        .args(["client-exec","claude","--","/bin/sh","-c","test \"$CLAUDE_CODE_OAUTH_TOKEN\" = \"$EXPECTED_SYNTHETIC_TOKEN\" && test -z \"${ANTHROPIC_API_KEY+x}\" && printf CLIENT_STARTED"])
        .env("HOME",home).env("SAFEYOLO_COORD_SOCKET",socket).env("SAFEYOLO_COORD_TOKEN_PATH",token_file)
        .env("ANTHROPIC_API_KEY","synthetic-conflicting-key").env("EXPECTED_SYNTHETIC_TOKEN","sgw_second")
        .output().unwrap()
}

#[test]
fn each_launch_reads_current_scoped_token_and_refusal_never_starts_client() {
    let temp = tempfile::tempdir().unwrap();
    configure(temp.path(), "claude", "host-vault", false).unwrap();
    let socket = temp.path().join("api.sock");
    let token_file = temp.path().join("agent-token");
    fs::write(&token_file, "synthetic-agent-identity").unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        for token in ["sgw_first", "sgw_second", ""] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let read = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).contains("GET /gateway/services"));
            let authorized = if token.is_empty() {
                serde_json::json!({})
            } else {
                serde_json::json!({"claude":{"token":token,"capability":"inference"}})
            };
            let body = serde_json::json!({"authorized":authorized}).to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
    });
    let first = client_run(temp.path(), &socket, &token_file);
    assert!(!first.status.success());
    let second = client_run(temp.path(), &socket, &token_file);
    assert!(second.status.success());
    assert_eq!(second.stdout, b"CLIENT_STARTED");
    let refused = client_run(temp.path(), &socket, &token_file);
    assert!(!refused.status.success() && refused.stdout.is_empty());
    for output in [first, second, refused] {
        let visible = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !visible.contains("sgw_first")
                && !visible.contains("sgw_second")
                && !visible.contains("synthetic-agent-identity")
        );
    }
    server.join().unwrap();
}
