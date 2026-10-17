//! Temporary recognition of tokens observed at GHCR's anonymous token endpoint.
//! Only keyed digests and requested repository names survive the exchange.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use hyper::{HeaderMap, Method};
use percent_encoding::percent_decode_str;
use ring::hmac;
use serde::{Deserialize, Deserializer};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroize;

use super::{CredentialGuard, Error, Header, Request, Result};

pub(crate) const RESPONSE_LIMIT: usize = 64 * 1024;
const MAX_TOKENS: usize = 256;
const MAX_SCOPES: usize = 16;
// A local recognition window, not a claim about GHCR's opaque token lifetime.
const RETENTION: Duration = Duration::from_secs(15 * 60);

#[derive(Default)]
pub(super) struct Tokens(VecDeque<Token>);

struct Token {
    digest: [u8; 32],
    repositories: Vec<String>,
    retain_until: Instant,
    expires_at_ms: Option<f64>,
}

/// Created from the final outgoing request, never from a challenge or client
/// assertion. No redirect response can construct or extend this observation.
pub(crate) struct Exchange {
    repositories: Vec<String>,
}

impl CredentialGuard {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ghcr_exchange(
        &self,
        scheme: &str,
        host: &str,
        port: u16,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        empty_body: bool,
        credential_injected: bool,
    ) -> Result<Option<Exchange>> {
        if scheme != "https"
            || host != "ghcr.io"
            || port != 443
            || method != Method::GET
            || !empty_body
            || credential_injected
        {
            return Ok(None);
        }
        let snapshot = self.snapshot()?;
        // GHCR authentication headers and all configured credential headers
        // must be absent, even if their value is empty or detection is disabled.
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
        Ok(Exchange::from_path(path))
    }

    pub(crate) fn observe_ghcr_response(
        &self,
        exchange: Exchange,
        body: &[u8],
        now_ms: f64,
    ) -> Result<()> {
        self.observe_ghcr_at(exchange, body, now_ms, Instant::now())
    }

    fn observe_ghcr_at(
        &self,
        exchange: Exchange,
        body: &[u8],
        now_ms: f64,
        now: Instant,
    ) -> Result<()> {
        if body.len() > RESPONSE_LIMIT || !now_ms.is_finite() {
            return Ok(());
        }
        // Derived struct parsing rejects duplicate security-relevant fields.
        // Discard parser diagnostics: they may quote token response bytes.
        let Ok(document) = serde_json::from_slice::<TokenResponse>(body) else {
            return Ok(());
        };
        let token = match (&document.token, &document.access_token) {
            (Some(token), None) | (None, Some(token)) => token,
            (Some(token), Some(access)) if token == access => token,
            _ => return Ok(()),
        };
        if !valid_bearer(token) {
            return Ok(());
        }
        if document.expires_in == Some(0) {
            return Ok(());
        }
        let issued_at = match &document.issued_at {
            Some(value) => match OffsetDateTime::parse(value, &Rfc3339) {
                Ok(time) => Some(time.unix_timestamp_nanos() as f64 / 1_000_000.),
                Err(_) => return Ok(()),
            },
            None => None,
        };
        let expires_at_ms = document
            .expires_in
            .map(|seconds| issued_at.unwrap_or(now_ms) + seconds as f64 * 1000.);
        let retention = match expires_at_ms {
            Some(expiry) if !expiry.is_finite() || expiry <= now_ms => return Ok(()),
            Some(expiry) => {
                Duration::from_secs_f64(((expiry - now_ms) / 1000.).min(RETENTION.as_secs_f64()))
            }
            None => RETENTION,
        };
        let digest = self.ghcr_digest(token);
        let mut tokens = self.ghcr_tokens.lock().map_err(|_| Error::State)?;
        tokens.0.retain(|known| {
            known.retain_until > now
                && known.digest != digest
                && known.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
        });
        if tokens.0.len() == MAX_TOKENS {
            tokens.0.pop_front();
        }
        tokens.0.push_back(Token {
            digest,
            repositories: exchange.repositories,
            retain_until: now + retention,
            expires_at_ms,
        });
        Ok(())
    }

    fn ghcr_digest(&self, token: &str) -> [u8; 32] {
        let mut context = hmac::Context::with_key(&self.key);
        context.update(b"ghcr-anonymous-pull\0");
        context.update(token.as_bytes());
        context.sign().as_ref().try_into().expect("SHA256 length")
    }

    pub(super) fn known_ghcr_token(&self, value: &str, now_ms: f64) -> Result<bool> {
        if !valid_bearer(value) || !now_ms.is_finite() {
            return Ok(false);
        }
        let digest = self.ghcr_digest(value);
        let now = Instant::now();
        let mut tokens = self.ghcr_tokens.lock().map_err(|_| Error::State)?;
        tokens.0.retain(|token| {
            token.retain_until > now && token.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
        });
        Ok(tokens.0.iter().any(|token| token.digest == digest))
    }

    pub(super) fn observed_ghcr_pull(
        &self,
        request: &Request<'_>,
        header: &str,
        value: &str,
        now_ms: f64,
    ) -> Result<bool> {
        if request.scheme != "https"
            || !request.host.eq_ignore_ascii_case("ghcr.io")
            || request.port != 443
            || !matches!(request.method, "GET" | "HEAD")
            || !header.eq_ignore_ascii_case("authorization")
            || !now_ms.is_finite()
        {
            return Ok(false);
        }
        // A finding that matched only a substring, Basic auth, or a combined
        // duplicate Authorization field must not inherit the observation.
        let mut headers = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("authorization"));
        let Some(Header {
            value: authorization,
            ..
        }) = headers.next()
        else {
            return Ok(false);
        };
        let authorization = authorization.expose_secret();
        if headers.next().is_some()
            || !authorization
                .get(..7)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Bearer "))
            || authorization[7..].trim_ascii() != value
            || !valid_bearer(value)
        {
            return Ok(false);
        }
        let digest = self.ghcr_digest(value);
        let now = Instant::now();
        let mut tokens = self.ghcr_tokens.lock().map_err(|_| Error::State)?;
        tokens.0.retain(|token| {
            token.retain_until > now && token.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
        });
        Ok(tokens
            .0
            .iter()
            .any(|token| token.digest == digest && read_path(request.path, &token.repositories)))
    }
}

impl Exchange {
    fn from_path(path: &str) -> Option<Self> {
        let (endpoint, query) = path.split_once('?')?;
        if endpoint != "/token" || query.len() > 8192 {
            return None;
        }
        let mut service = None;
        let mut repositories = Vec::new();
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=')?;
            let key = percent_decode_str(key).decode_utf8().ok()?;
            let value = percent_decode_str(&value.replace('+', " "))
                .decode_utf8()
                .ok()?
                .into_owned();
            match key.as_ref() {
                "service" if service.is_none() && value == "ghcr.io" => service = Some(()),
                "scope" => {
                    for scope in value.split(' ') {
                        let repository =
                            scope.strip_prefix("repository:")?.strip_suffix(":pull")?;
                        if !valid_repository(repository) || repositories.len() == MAX_SCOPES {
                            return None;
                        }
                        repositories.push(repository.to_owned());
                    }
                }
                // These standard client options carry no authentication.
                // Unknown parameters, nonempty accounts and refresh tokens
                // cannot establish an anonymous exchange.
                "client_id" => {}
                "offline_token" if matches!(value.as_str(), "true" | "false") => {}
                "account" if value.is_empty() => {}
                _ => return None,
            }
        }
        service?;
        // Without a repository scope, read_path permits discovery only.
        Some(Self { repositories })
    }
}

fn valid_repository(repository: &str) -> bool {
    repository.len() <= 255
        && repository.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                })
        })
}

fn valid_bearer(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 16 * 1024
        && token
            .trim_end_matches('=')
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        && !token.starts_with('=')
}

fn read_path(path: &str, repositories: &[String]) -> bool {
    let path = path.split('?').next().unwrap_or("");
    if matches!(path, "/v2" | "/v2/") {
        return true;
    }
    repositories.iter().any(|repository| {
        let Some(endpoint) = path.strip_prefix(&format!("/v2/{repository}/")) else {
            return false;
        };
        if endpoint == "tags/list" {
            return true;
        }
        let (kind, reference) = match endpoint.split_once('/') {
            Some(pair) => pair,
            None => return false,
        };
        matches!(kind, "manifests" | "blobs")
            && !reference.is_empty()
            && reference != "."
            && reference != ".."
            && reference
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
            && (kind != "blobs" || reference.contains(':'))
    })
}

fn present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default, deserialize_with = "present")]
    token: Option<String>,
    #[serde(default, deserialize_with = "present")]
    access_token: Option<String>,
    #[serde(default, deserialize_with = "present")]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    issued_at: Option<String>,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.token.zeroize();
        self.access_token.zeroize();
    }
}

#[cfg(test)]
mod tests;
