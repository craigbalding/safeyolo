//! Explicit host imports for native clients using scoped gateway credentials.
//! These imports do not authorize a service or copy a login into an agent home.

use std::io::Read;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    Error,
    credentials::{Credential, Secret, wipe_json},
};

pub use crate::credentials::SubscriptionClient as Client;

/// Inspect only the explicitly selected local file. Never expose its tokens,
/// infer provider validity, or modify a source while building a login menu.
pub(crate) fn inspect(path: &std::path::Path, client: Client) -> Value {
    use std::{fs, io::Read, os::unix::fs::OpenOptionsExt};
    let result = (|| -> Result<Value, Error> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 {
            return Ok(
                serde_json::json!({"state":"unsupported","reason":"expected a bounded ordinary login file"}),
            );
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err("login file changed while reading".into());
        }
        let mut document: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return Ok(
                    serde_json::json!({"state":"unsupported","reason":"not supported login JSON"}),
                );
            }
        };
        let api_key = client == Client::Codex
            && document["OPENAI_API_KEY"]
                .as_str()
                .is_some_and(|key| !key.is_empty());
        wipe_json(&mut document);
        if api_key {
            return Ok(
                serde_json::json!({"state":"found","kind":"API key","provider_validity":"unknown"}),
            );
        }
        // Reuse the real subscription parser, then retain safe metadata only.
        match import_login(client, "inspection", bytes.as_slice()) {
            Ok(record) => Ok(
                serde_json::json!({"state":"found","kind":"subscription","account_id":record.chatgpt_account_id,
                "expires_at":record.expires_at,"provider_validity":"unknown"}),
            ),
            Err(_) => Ok(
                serde_json::json!({"state":"unsupported","reason":"no supported subscription login or client API key"}),
            ),
        }
    })();
    match result {
        Ok(value) => value,
        Err(_) => {
            serde_json::json!({"state":if matches!(fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound) {"missing"} else {"unreadable"},
            "provider_validity":"unknown"})
        }
    }
}

pub fn import_login(client: Client, name: &str, mut input: impl Read) -> Result<Credential, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    input.read_to_end(&mut bytes)?;
    let mut document: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid subscription login JSON")?;
    let result = match client {
        Client::Codex => codex(name, &document),
        Client::Claude => claude(name, &document),
    };
    wipe_json(&mut document);
    result
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "subscription login is missing a required token".into())
}

fn expiry(timestamp: i64) -> Result<String, Error> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| "subscription login expiry is outside the supported range")?
        .format(&Rfc3339)
        .map_err(|_| "subscription login expiry is invalid".into())
}

fn codex(name: &str, document: &Value) -> Result<Credential, Error> {
    if document
        .get("auth_mode")
        .filter(|mode| !mode.is_null())
        .is_some_and(|mode| mode.as_str() != Some("chatgpt"))
    {
        return Err("select a Codex ChatGPT subscription login".into());
    }
    let tokens = &document["tokens"];
    let access = required(tokens, "access_token")?;
    let refresh = required(tokens, "refresh_token")?;
    let mut record = Credential::new(name, "oauth2", Secret::new(access));
    record.refresh_token = Some(Secret::new(refresh));
    record.expires_at = Some(codex_access_expiry(access)?);
    record.client_id = Some(crate::credential_guard::codex::CLIENT_ID.into());
    record.token_url = Some(crate::credential_guard::codex::TOKEN_URL.into());
    record.subscription_client = Some(Client::Codex);
    record.chatgpt_account_id = tokens["account_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(record)
}

fn claude(name: &str, document: &Value) -> Result<Credential, Error> {
    let tokens = &document["claudeAiOauth"];
    let access = required(tokens, "accessToken")?;
    let refresh = required(tokens, "refreshToken")?;
    let expires = tokens["expiresAt"]
        .as_i64()
        .ok_or("Claude subscription login has no valid expiry")?;
    let scopes = tokens["scopes"]
        .as_array()
        .ok_or("Claude subscription login has no scope list")?
        .iter()
        .map(|value| value.as_str().ok_or("Claude subscription scope is invalid"))
        .collect::<Result<Vec<_>, _>>()?;
    if !scopes.contains(&"user:inference") {
        return Err("select a Claude subscription login with inference access".into());
    }
    let mut record = Credential::new(name, "oauth2", Secret::new(access));
    record.refresh_token = Some(Secret::new(refresh));
    record.expires_at = Some(expiry(expires.div_euclid(1000))?);
    record.client_id = Some("9d1c250a-e61b-44d9-88ed-5944d1962f5e".into());
    record.token_url = Some("https://platform.claude.com/v1/oauth/token".into());
    record.subscription_client = Some(Client::Claude);
    record.refresh_scope = Some(scopes.join(" "));
    Ok(record)
}

pub(crate) fn codex_access_expiry(access: &str) -> Result<String, Error> {
    // The host selected this login. Decode the issuer's expiry for scheduling;
    // decoding a claim is not credential or service authorization.
    let payload = access
        .split('.')
        .nth(1)
        .ok_or("Codex subscription access token has no expiry payload")?;
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .map_err(|_| "Codex subscription access token payload is invalid")?,
    );
    let mut claims: Value = serde_json::from_slice(&decoded)
        .map_err(|_| "Codex subscription access token payload is invalid")?;
    let expires = claims["exp"]
        .as_i64()
        .ok_or_else(|| Error::from("Codex subscription access token has no valid expiry"))
        .and_then(expiry);
    wipe_json(&mut claims);
    expires
}

#[cfg(test)]
mod inspection_tests {
    use super::*;

    #[test]
    fn inspection_distinguishes_sources_and_never_returns_authentication_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("auth.json");
        assert_eq!(inspect(&path, Client::Codex)["state"], "missing");
        std::fs::write(&path, "invalid JSON").unwrap();
        assert_eq!(inspect(&path, Client::Codex)["state"], "unsupported");
        std::fs::write(&path, r#"{"OPENAI_API_KEY":"synthetic-private-key"}"#).unwrap();
        let inspected = inspect(&path, Client::Codex);
        assert_eq!(inspected["state"], "found");
        assert_eq!(inspected["kind"], "API key");
        assert_eq!(inspected["provider_validity"], "unknown");
        assert!(!inspected.to_string().contains("synthetic-private-key"));
        std::fs::write(&path, r#"{"claudeAiOauth":{"accessToken":"synthetic-access","refreshToken":"synthetic-refresh","expiresAt":2000000000000,"scopes":["user:inference"]}}"#).unwrap();
        let inspected = inspect(&path, Client::Claude);
        assert_eq!(inspected["state"], "found");
        assert_eq!(inspected["kind"], "subscription");
        assert!(!inspected.to_string().contains("synthetic-access"));
        let linked = directory.path().join("linked");
        std::os::unix::fs::symlink(&path, &linked).unwrap();
        assert_eq!(inspect(&linked, Client::Claude)["state"], "unreadable");
        assert_eq!(
            inspect(directory.path(), Client::Claude)["state"],
            "unsupported"
        );
    }
}
