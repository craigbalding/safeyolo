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
