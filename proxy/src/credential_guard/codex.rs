//! Host-imported Codex logins and exact, client-managed refresh exchanges.
//! The encrypted vault owns both credentials and their authorization scope.

use std::io::Read;

use hyper::{HeaderMap, header};
use ring::hmac;
use serde::Deserialize;
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    credentials::{CodexAuthorization, Credential, CredentialSnapshot, Secret, Vault},
    network_guard::Identity,
    policy::Policy,
};

use super::{CredentialGuard, Error, Options, Outcome, Pdp, Request, Result};

pub const CREDENTIAL_TYPE: &str = "codex_subscription";
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;

// HTTP Bearer syntax alone grants no authority. The host import or verified
// issuer exchange must independently bind the exact credential.
fn valid_access_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .trim_end_matches('=')
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        && !token.starts_with('=')
}

/// Called only for an explicitly selected host input, never an adoption marker
/// or a scan of an agent's mutable authentication directory.
pub fn import_login(
    mut input: impl Read,
    name: &str,
    authorization: CodexAuthorization,
) -> std::result::Result<Credential, crate::Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    input.read_to_end(&mut bytes)?;
    let mut document: Login = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid Codex login input; access and refresh tokens are required")?;
    if document
        .auth_mode
        .as_deref()
        .is_some_and(|mode| mode != "chatgpt")
        || !valid_access_token(&document.tokens.access_token)
        || document.tokens.refresh_token.is_empty()
    {
        return Err("Codex subscription access and refresh tokens are required".into());
    }
    let mut record = Credential::new(
        name,
        CREDENTIAL_TYPE,
        Secret::new(std::mem::take(&mut document.tokens.access_token)),
    );
    record.refresh_token = Some(Secret::new(std::mem::take(
        &mut document.tokens.refresh_token,
    )));
    record.token_url = Some(TOKEN_URL.into());
    record.client_id = Some(CLIENT_ID.into());
    record.codex = Some(authorization);
    Ok(record)
}

#[derive(Deserialize)]
struct Login {
    auth_mode: Option<String>,
    tokens: LoginTokens,
}
#[derive(Deserialize)]
struct LoginTokens {
    access_token: String,
    refresh_token: String,
    id_token: Option<String>,
}
impl Drop for LoginTokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Refresh {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}
impl Refresh {
    pub(crate) fn parse(headers: &HeaderMap, body: &[u8]) -> Option<Self> {
        if body.len() > RESPONSE_LIMIT || !Self::json_headers(headers) {
            return None;
        }
        let request: Self = serde_json::from_slice(body).ok()?;
        (request.grant_type == "refresh_token" && !request.refresh_token.is_empty())
            .then_some(request)
    }

    fn json_headers(headers: &HeaderMap) -> bool {
        !headers.contains_key(header::CONTENT_ENCODING)
            && headers.get_all(header::CONTENT_TYPE).iter().count() == 1
            && headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    }
}
impl Drop for Refresh {
    fn drop(&mut self) {
        self.refresh_token.zeroize();
    }
}

pub(crate) fn refresh_endpoint(scheme: &str, host: &str, port: u16, path: &str) -> bool {
    scheme == "https" && host == "auth.openai.com" && port == 443 && path == "/oauth/token"
}

fn access_path(method: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or("");
    matches!(
        (method, path),
        (
            "GET",
            "/backend-api/wham/accounts/check"
                | "/backend-api/wham/usage"
                | "/backend-api/wham/rate-limit-reset-credits"
                | "/backend-api/plugins/featured"
                | "/backend-api/ps/plugins/installed"
                | "/backend-api/ps/plugins/suggested/codex"
                | "/backend-api/ps/plugins/list"
                | "/backend-api/codex/models"
                | "/backend-api/codex/rate_limits"
                | "/backend-api/codex/responses"
        ) | (
            "POST",
            "/backend-api/codex/responses" | "/backend-api/codex/responses/compact"
        )
    )
}

pub(crate) struct Exchange {
    snapshot: CredentialSnapshot,
    authorization: CodexAuthorization,
}

impl CredentialGuard {
    pub(crate) fn with_codex_vault(mut self, vault: Option<Vault>) -> Self {
        self.codex_vault = vault;
        self
    }

    fn codex_digest(&self, value: &str) -> [u8; 32] {
        let mut digest = hmac::Context::with_key(&self.key);
        digest.update(b"safeyolo.codex-credential.v1\0");
        digest.update(value.as_bytes());
        digest.sign().as_ref().try_into().expect("SHA256 length")
    }

    /// JSON credentials use their exact UTF-8 string, without the HTTP header
    /// source-text adaptation or Bearer whitespace normalization.
    pub(super) fn codex_refresh_fingerprint(&self, value: &str) -> String {
        self.codex_digest(value)[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn codex_root(
        &self,
        policy: &Policy,
        identity: Identity<'_>,
        value: &str,
        refresh: bool,
    ) -> Result<Option<CredentialSnapshot>> {
        let Some(vault) = &self.codex_vault else {
            return Ok(None);
        };
        vault.reload_if_changed().map_err(|_| Error::State)?;
        let digest = self.codex_digest(value);
        for name in vault.list_names().map_err(|_| Error::State)? {
            let Some(snapshot) = vault.snapshot(&name).map_err(|_| Error::State)? else {
                continue;
            };
            let credential = snapshot.credential();
            if !root_current(credential, policy, identity) {
                continue;
            }
            let stored = if refresh {
                credential.refresh_token.as_ref()
            } else {
                Some(&credential.value)
            };
            let observed = if refresh {
                &credential.codex_tokens.refresh
            } else {
                &credential.codex_tokens.access
            };
            if stored.is_some_and(|stored| self.codex_digest(stored.expose_secret()) == digest)
                || observed.contains(&digest)
            {
                return Ok(Some(snapshot));
            }
        }
        Ok(None)
    }

    pub(super) fn observed_codex_access(
        &self,
        pdp: &Pdp<'_>,
        request: &Request<'_>,
        header: &str,
        value: &str,
    ) -> Result<bool> {
        if request.scheme != "https"
            || request.host != "chatgpt.com"
            || request.port != 443
            || !header.eq_ignore_ascii_case("authorization")
            || !access_path(request.method, request.path)
        {
            return Ok(false);
        }
        let mut headers = request
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("authorization"));
        let Some(authorization) = headers.next() else {
            return Ok(false);
        };
        let authorization = authorization.value.expose_secret();
        if headers.next().is_some()
            || !authorization
                .get(..7)
                .is_some_and(|s| s.eq_ignore_ascii_case("Bearer "))
            || authorization[7..] != *value
            || !valid_access_token(value)
        {
            return Ok(false);
        }
        let Some(policy) = pdp.policy() else {
            return Ok(false);
        };
        Ok(self
            .codex_root(policy, request.identity, value, false)?
            .is_some())
    }

    pub(crate) fn enforce_codex_refresh(
        &self,
        pdp: Pdp<'_>,
        request: Request<'_>,
        refresh: &Refresh,
        options: Options,
        now_ms: f64,
    ) -> Result<Outcome> {
        let observed = refresh.client_id == CLIENT_ID
            && request.method == "POST"
            && refresh_endpoint(request.scheme, request.host, request.port, request.path)
            && match pdp.policy() {
                Some(policy) => self
                    .codex_root(policy, request.identity, &refresh.refresh_token, true)?
                    .is_some(),
                None => false,
            };
        let mut outcome = self.enforce_inner(
            pdp,
            request,
            options,
            now_ms,
            Some((refresh.refresh_token.as_str(), observed)),
        )?;
        for audit in &mut outcome.audit {
            audit.details["location"] = serde_json::json!("body:refresh_token");
        }
        Ok(outcome)
    }

    pub(crate) fn codex_exchange(
        &self,
        policy: &Policy,
        identity: Identity<'_>,
        refresh: &Refresh,
        headers: &HeaderMap,
    ) -> Result<Option<Exchange>> {
        if refresh.client_id != CLIENT_ID || !Refresh::json_headers(headers) {
            return Ok(None);
        }
        let snapshot = self.snapshot()?;
        // The selected refresh credential must be the only authentication
        // input. A permitted companion header can select a different account.
        if headers.keys().any(|name| {
            let name = name.as_str();
            matches!(
                name,
                "authorization" | "proxy-authorization" | "cookie" | "cookie2" | "trailer"
            ) || snapshot
                .auth_headers
                .iter()
                .any(|auth| auth.eq_ignore_ascii_case(name))
                || snapshot.rules.iter().any(|rule| {
                    rule.headers
                        .iter()
                        .any(|auth| auth.eq_ignore_ascii_case(name))
                })
        }) {
            return Ok(None);
        }
        Ok(self
            .codex_root(policy, identity, &refresh.refresh_token, true)?
            .map(|snapshot| Exchange {
                authorization: snapshot.credential().codex.clone().expect("Codex scope"),
                snapshot,
            }))
    }

    pub(crate) fn observe_codex_response(
        &self,
        exchange: Exchange,
        policy: &Policy,
        identity: Identity<'_>,
        body: &[u8],
    ) -> Result<bool> {
        if body.len() > RESPONSE_LIMIT {
            return Ok(false);
        }
        let Ok(response) = serde_json::from_slice::<Replacements>(body) else {
            return Ok(false);
        };
        if response
            .access_token
            .as_deref()
            .is_some_and(|t| !valid_access_token(t))
            || response
                .refresh_token
                .as_deref()
                .is_some_and(|t| t.is_empty())
        {
            return Ok(false);
        }
        let Some(vault) = &self.codex_vault else {
            return Ok(false);
        };
        let binding = self.approval_binding(exchange.snapshot.credential());
        vault
            .record_codex_tokens(
                &exchange.snapshot.credential().name,
                response
                    .access_token
                    .as_deref()
                    .map(|token| self.codex_digest(token)),
                response
                    .refresh_token
                    .as_deref()
                    .map(|token| self.codex_digest(token)),
                |credential| {
                    credential.codex.as_ref() == Some(&exchange.authorization)
                        && self.approval_binding(credential) == binding
                        && root_current(credential, policy, identity)
                },
            )
            .map_err(|_| Error::State)
    }
}

fn root_current(credential: &Credential, policy: &Policy, identity: Identity<'_>) -> bool {
    let Some(scope) = credential.codex.as_ref() else {
        return false;
    };
    let agent = match identity {
        Identity::Resolved(agent) => agent,
        Identity::Current(run) if run.current(policy) => &run.agent,
        _ => return false,
    };
    credential.credential_type == CREDENTIAL_TYPE
        && credential.reference.is_none()
        && credential.token_url.as_deref() == Some(TOKEN_URL)
        && credential.client_id.as_deref() == Some(CLIENT_ID)
        && credential
            .is_expired(OffsetDateTime::now_utc())
            .is_ok_and(|expired| !expired)
        && scope.agent == agent
        && policy.evidence_agent_id(agent) == Some(scope.agent_id.as_str())
        && scope.run_id.as_ref().is_none_or(|id| {
            identity.run().is_some_and(|run| {
                &run.run_id == id && policy.agent_run(agent).as_ref() == Some(run)
            })
        })
}

#[derive(Deserialize)]
struct Replacements {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
}
impl Drop for Replacements {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::access_path;

    #[test]
    fn native_discovery_paths_require_exact_get_routes() {
        for path in [
            "/backend-api/plugins/featured",
            "/backend-api/ps/plugins/installed",
            "/backend-api/ps/plugins/suggested/codex",
            "/backend-api/ps/plugins/list",
            "/backend-api/wham/rate-limit-reset-credits",
        ] {
            assert!(access_path("GET", path));
            assert!(access_path("GET", &format!("{path}?limit=20&cursor=next")));
            for method in ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "get"] {
                assert!(!access_path(method, path), "{method} {path}");
            }
            for suffix in ["/", "/extra", "-extra", "/../unrelated"] {
                assert!(!access_path("GET", &format!("{path}{suffix}")));
            }
        }
        for path in [
            "/backend-api/plugins",
            "/backend-api/ps/plugins",
            "/backend-api/ps/plugins/suggested/other",
            "/backend-api/wham/unrelated",
        ] {
            assert!(!access_path("GET", path));
        }
    }
}
