use safeyolo_proxy::subscription_login::{Client, import_login};
use serde_json::json;

#[test]
fn imports_native_subscription_pairs_and_host_refresh_parameters() {
    let codex = json!({"auth_mode":"chatgpt", "tokens":{
        "access_token":"header.eyJleHAiOjIwMDAwMDAwMDB9.signature",
        "refresh_token":"synthetic-codex-refresh", "account_id":"account", "id_token":"private-id"
    }});
    let record =
        import_login(Client::Codex, "codex-account", codex.to_string().as_bytes()).unwrap();
    assert_eq!(record.credential_type, "oauth2");
    assert_eq!(
        record.value.expose_secret(),
        codex["tokens"]["access_token"].as_str().unwrap()
    );
    assert_eq!(
        record.refresh_token.unwrap().expose_secret(),
        "synthetic-codex-refresh"
    );
    assert_eq!(record.expires_at.as_deref(), Some("2033-05-18T03:33:20Z"));
    assert_eq!(
        record.token_url.as_deref(),
        Some("https://auth.openai.com/oauth/token")
    );
    assert!(matches!(record.subscription_client, Some(Client::Codex)));
    assert!(record.codex.is_none());
    assert_eq!(record.chatgpt_account_id.as_deref(), Some("account"));
    let claude = json!({"claudeAiOauth":{
        "accessToken":"synthetic-claude-access", "refreshToken":"synthetic-claude-refresh",
        "expiresAt":2000000000000_i64, "scopes":["user:profile","user:inference"]
    }});
    let record = import_login(
        Client::Claude,
        "claude-account",
        claude.to_string().as_bytes(),
    )
    .unwrap();
    assert_eq!(record.value.expose_secret(), "synthetic-claude-access");
    assert_eq!(
        record.refresh_token.unwrap().expose_secret(),
        "synthetic-claude-refresh"
    );
    assert_eq!(
        record.token_url.as_deref(),
        Some("https://platform.claude.com/v1/oauth/token")
    );
    assert_eq!(
        record.client_id.as_deref(),
        Some("9d1c250a-e61b-44d9-88ed-5944d1962f5e")
    );
    assert_eq!(
        record.refresh_scope.as_deref(),
        Some("user:profile user:inference")
    );
    assert_eq!(record.expires_at.as_deref(), Some("2033-05-18T03:33:20Z"));
    assert!(matches!(record.subscription_client, Some(Client::Claude)));
    assert!(record.codex.is_none());
}

#[test]
fn invalid_logins_report_no_input_tokens_and_do_not_substitute_api_credentials() {
    for (client, value) in [
        (
            Client::Codex,
            json!({"auth_mode":"api_key", "OPENAI_API_KEY":"synthetic-private"}),
        ),
        (
            Client::Codex,
            json!({"tokens":{"access_token":"synthetic-private", "refresh_token":"refresh"}}),
        ),
        (
            Client::Codex,
            json!({"tokens":{"access_token":"header.eyJleHAiOiJzeW50aGV0aWMtcHJpdmF0ZSJ9.signature", "refresh_token":"refresh"}}),
        ),
        (
            Client::Claude,
            json!({"claudeAiOauth":{"accessToken":"synthetic-private", "expiresAt":2000000000000_i64}}),
        ),
        (
            Client::Claude,
            json!({"claudeAiOauth":{"accessToken":"synthetic-private", "refreshToken":"refresh", "expiresAt":2000000000000_i64, "scopes":["user:profile"]}}),
        ),
        (
            Client::Claude,
            json!({"claudeAiOauth":{"accessToken":"synthetic-private", "refreshToken":"refresh", "expiresAt":"synthetic-private", "scopes":["user:inference"]}}),
        ),
    ] {
        let error = import_login(client, "account", value.to_string().as_bytes())
            .err()
            .unwrap();
        assert!(!error.to_string().contains("synthetic-private"));
    }
    assert!(
        import_login(
            Client::Codex,
            "account",
            b"{\"private\": \"synthetic-private".as_slice()
        )
        .is_err()
    );
}
