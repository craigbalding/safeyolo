//! Inactive OAuth refresh lifecycle. The host transport executes requests.
//!
//! Construct one OAuthRefresh for an active Vault and clone it for all callers.
//! This owns no network client, DNS, policy matcher, timer or worker. begin and
//! complete may perform synchronous vault work and belong on a blocking worker;
//! followers wait asynchronously. The caller has already authorized service use.
//! Refresh uses the existing host credential-management route, not agent policy.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use num_bigint::BigInt;
use serde_json::Value;
use time::{OffsetDateTime, UtcOffset};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::credentials::{
    Credential, CredentialMetadata, CredentialSnapshot, Secret, Vault, VaultError, wipe_json,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportFailure {
    Connect,
    Tls,
    Timeout,
    Protocol,
    Body,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshError {
    Vault(VaultError),
    State,
    Transport(TransportFailure),
    HttpStatus(u16),
    JsonEncoding,
    Json,
    ResponseShape,
    MissingAccessToken,
    AccessTokenType,
    RefreshTokenType,
    ExpiryType,
    ExpiryRange,
}
impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Vault(_) => "OAuth refresh vault operation failed",
            Self::State => "OAuth refresh state unavailable",
            Self::Transport(_) => "OAuth refresh transport failed",
            Self::HttpStatus(_) => "OAuth token endpoint returned a non-success status",
            Self::JsonEncoding => "OAuth token response encoding is invalid",
            Self::Json => "OAuth token response is not valid JSON",
            Self::ResponseShape => "OAuth token response must be an object",
            Self::MissingAccessToken => "OAuth token response has no access token",
            Self::AccessTokenType => "OAuth access token must be a string",
            Self::RefreshTokenType => "OAuth refresh token must be a string or null",
            Self::ExpiryType => "OAuth expires_in must be a number",
            Self::ExpiryRange => "OAuth expiry is outside the supported datetime range",
        })
    }
}
impl std::error::Error for RefreshError {}
impl From<VaultError> for RefreshError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}
type Result<T> = std::result::Result<T, RefreshError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotNeeded {
    MissingCredential,
    NotOAuth2,
    MissingRefreshToken,
    MissingTokenUrl,
    NotExpired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    Refreshed,
    /// Existing HTTP/JSON failure path: refresh returned false and gateway kept
    /// the old credential for injection. No retry delay is introduced.
    Retained(RefreshError),
    /// Malformed token/publication failure. Do not turn this into a successful
    /// refresh or an implicit permission to inject an unvalidated replacement.
    Rejected(RefreshError),
    /// A store, removal or changed reload superseded the captured revision.
    Superseded,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    HostCredentialManagement,
}

/// Contains an endpoint and form body that may hold secrets. No Debug,
/// Display or Serialize implementation exists. URL parsing, userinfo auth,
/// proxy/CA selection and transport execution remain with the host caller.
///
/// ```compile_fail
/// use safeyolo_proxy::oauth::RefreshRequest;
/// fn expose(request: &RefreshRequest) { let _ = format!("{request:?}"); }
/// ```
/// ```compile_fail
/// use safeyolo_proxy::oauth::RefreshRequest;
/// fn expose(request: &RefreshRequest) { let _ = serde_json::to_string(request); }
/// ```
pub struct RefreshRequest {
    endpoint: Secret,
    form: Secret,
}
impl RefreshRequest {
    pub fn authority(&self) -> Authority {
        Authority::HostCredentialManagement
    }
    pub fn method(&self) -> &'static str {
        "POST"
    }
    pub fn content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }
    pub fn endpoint(&self) -> &Secret {
        &self.endpoint
    }
    pub fn form_body(&self) -> &Secret {
        &self.form
    }
    pub fn content_length(&self) -> usize {
        self.form.expose_secret().len()
    }
    /// HTTPX's timeout=10 configures each connect/read/write/pool phase. It is
    /// not a total refresh deadline. The transport owner enforces these phases.
    pub fn io_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    pub fn follow_redirects(&self) -> bool {
        false
    }
    fn from_credential(credential: &Credential) -> Self {
        let fields = [
            ("grant_type", "refresh_token"),
            (
                "refresh_token",
                credential.refresh_token.as_ref().unwrap().expose_secret(),
            ),
            ("client_id", credential.client_id.as_deref().unwrap_or("")),
            (
                "client_secret",
                credential
                    .client_secret
                    .as_ref()
                    .map_or("", Secret::expose_secret),
            ),
        ];
        let mut form = String::new();
        for (index, (name, value)) in fields.into_iter().enumerate() {
            if index > 0 {
                form.push('&');
            }
            form.push_str(name);
            form.push('=');
            quote_plus(value, &mut form);
        }
        Self {
            endpoint: Secret::new(credential.token_url.as_deref().unwrap()),
            form: Secret::new(form),
        }
    }
}

/// The caller supplies response entity bytes after HTTP content decoding.
/// Header values, URLs and error descriptions never enter diagnostic errors.
pub struct RefreshResponse {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}
impl RefreshResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body: Zeroizing::new(body),
        }
    }
}

struct Flight {
    result: watch::Sender<Option<RefreshOutcome>>,
}
type Flights = Arc<Mutex<HashMap<String, Arc<Flight>>>>;
#[derive(Clone)]
pub struct OAuthRefresh {
    vault: Vault,
    flights: Flights,
}
pub enum RefreshStart {
    NotNeeded(NotNeeded),
    Leader(RefreshAttempt),
    Follower(RefreshWaiter),
}

impl OAuthRefresh {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            flights: Arc::default(),
        }
    }
    pub fn begin(&self, name: &str, now: OffsetDateTime) -> Result<RefreshStart> {
        let mut flights = self.flights.lock().map_err(|_| RefreshError::State)?;
        if let Some(flight) = flights.get(name) {
            return Ok(RefreshStart::Follower(RefreshWaiter {
                result: flight.result.subscribe(),
            }));
        }
        // Serialize snapshot selection with completion's flight removal so a
        // delayed caller cannot start with a credential fetched before refresh.
        let Some(snapshot) = self.vault.snapshot(name)? else {
            return Ok(RefreshStart::NotNeeded(NotNeeded::MissingCredential));
        };
        let credential = snapshot.credential();
        let reason = if credential.credential_type != "oauth2" {
            Some(NotNeeded::NotOAuth2)
        } else if credential
            .refresh_token
            .as_ref()
            .is_none_or(|secret| secret.expose_secret().is_empty())
        {
            Some(NotNeeded::MissingRefreshToken)
        } else if credential.token_url.as_deref().is_none_or(str::is_empty) {
            Some(NotNeeded::MissingTokenUrl)
        } else if !credential.is_expired(now)? {
            Some(NotNeeded::NotExpired)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Ok(RefreshStart::NotNeeded(reason));
        }
        let request = RefreshRequest::from_credential(credential);
        let (result, _) = watch::channel(None);
        let flight = Arc::new(Flight { result });
        flights.insert(name.to_owned(), flight.clone());
        Ok(RefreshStart::Leader(RefreshAttempt {
            owner: self.clone(),
            snapshot: Box::new(snapshot),
            request,
            flight,
            finished: false,
        }))
    }
}

pub struct RefreshWaiter {
    result: watch::Receiver<Option<RefreshOutcome>>,
}
impl RefreshWaiter {
    pub async fn wait(&mut self) -> RefreshOutcome {
        loop {
            if let Some(result) = *self.result.borrow_and_update() {
                return result;
            }
            if self.result.changed().await.is_err() {
                return RefreshOutcome::Cancelled;
            }
        }
    }
}

pub struct RefreshAttempt {
    owner: OAuthRefresh,
    snapshot: Box<CredentialSnapshot>,
    request: RefreshRequest,
    flight: Arc<Flight>,
    finished: bool,
}
impl RefreshAttempt {
    pub fn request(&self) -> &RefreshRequest {
        &self.request
    }
    pub fn complete(
        self,
        response: std::result::Result<RefreshResponse, TransportFailure>,
        now: OffsetDateTime,
    ) -> RefreshOutcome {
        self.complete_with_activation(response, now, |_| Ok(()))
    }
    /// Runs the vault's atomic compare/replace and optional activation callback.
    /// The callback must not re-enter this Vault or OAuthRefresh coordinator.
    pub fn complete_with_activation(
        mut self,
        response: std::result::Result<RefreshResponse, TransportFailure>,
        now: OffsetDateTime,
        activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> RefreshOutcome {
        let outcome = match response {
            Err(TransportFailure::Cancelled) => RefreshOutcome::Cancelled,
            Err(error) => RefreshOutcome::Retained(RefreshError::Transport(error)),
            Ok(response) if !(200..300).contains(&response.status) => {
                RefreshOutcome::Retained(RefreshError::HttpStatus(response.status))
            }
            Ok(response) => match decode_response(&response.body, now) {
                Err(error @ (RefreshError::Json | RefreshError::JsonEncoding)) => {
                    RefreshOutcome::Retained(error)
                }
                Err(error) => RefreshOutcome::Rejected(error),
                Ok(update) => {
                    let mut credential = self.snapshot.credential().clone();
                    credential.value = update.access;
                    if let Some(refresh) = update.refresh {
                        credential.refresh_token = refresh;
                    }
                    if let Some(expiry) = update.expiry {
                        credential.expires_at = Some(expiry);
                    }
                    match self
                        .owner
                        .vault
                        .replace_if_current(&self.snapshot, credential, activate)
                    {
                        Ok(true) => RefreshOutcome::Refreshed,
                        Ok(false) => RefreshOutcome::Superseded,
                        Err(error) => RefreshOutcome::Rejected(RefreshError::Vault(error)),
                    }
                }
            },
        };
        self.finish(outcome);
        outcome
    }
    fn finish(&mut self, outcome: RefreshOutcome) {
        if let Ok(mut flights) = self.owner.flights.lock() {
            let name = &self.snapshot.credential().name;
            if flights
                .get(name)
                .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
            {
                flights.remove(name);
            }
            self.flight.result.send_replace(Some(outcome));
        } else {
            // Poison remains an explicit error for new begin calls; already
            // waiting callers must still be released even during unwinding.
            self.flight.result.send_replace(Some(outcome));
        }
        self.finished = true;
    }
}
impl Drop for RefreshAttempt {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(RefreshOutcome::Cancelled);
        }
    }
}

struct TokenUpdate {
    access: Secret,
    refresh: Option<Option<Secret>>,
    expiry: Option<String>,
}
fn decode_response(body: &[u8], now: OffsetDateTime) -> Result<TokenUpdate> {
    let text = decode_json_text(body)?;
    let mut value = crate::policy::parse_json(&text, false).map_err(|_| RefreshError::Json)?;
    let result = decode_tokens(&mut value, now);
    wipe_json(&mut value);
    result
}
fn decode_tokens(value: &mut Value, now: OffsetDateTime) -> Result<TokenUpdate> {
    let object = value.as_object_mut().ok_or(RefreshError::ResponseShape)?;
    // Validate every field before taking any secret or mutating the vault.
    let access = object
        .get("access_token")
        .ok_or(RefreshError::MissingAccessToken)?;
    if !access.is_string() {
        return Err(RefreshError::AccessTokenType);
    }
    if object
        .get("refresh_token")
        .is_some_and(|value| !value.is_string() && !value.is_null())
    {
        return Err(RefreshError::RefreshTokenType);
    }
    let expiry = object
        .get("expires_in")
        .map(|value| expires_at(value, now))
        .transpose()?;
    let Value::String(access) = object.get_mut("access_token").unwrap().take() else {
        unreachable!()
    };
    let refresh = object
        .get_mut("refresh_token")
        .map(|value| match value.take() {
            Value::Null => None,
            Value::String(value) => Some(Secret::new(value)),
            _ => unreachable!(),
        });
    Ok(TokenUpdate {
        access: Secret::new(access),
        refresh,
        expiry,
    })
}

fn expires_at(value: &Value, now: OffsetDateTime) -> Result<String> {
    let micros: BigInt = match value {
        Value::Bool(value) => BigInt::from(u8::from(*value)) * 1_000_000,
        Value::Number(value) => {
            let text = value.to_string();
            if !text.contains(['.', 'e', 'E']) {
                text.parse::<BigInt>()
                    .map_err(|_| RefreshError::ExpiryType)?
                    * 1_000_000
            } else {
                let seconds = value
                    .as_f64()
                    .filter(|seconds| seconds.is_finite())
                    .ok_or(RefreshError::ExpiryRange)?;
                // timedelta splits integer seconds before rounding the fractional
                // microseconds. Rounding seconds*1e6 loses large exact integers.
                let whole = format!("{:.0}", seconds.trunc())
                    .parse::<BigInt>()
                    .map_err(|_| RefreshError::ExpiryRange)?;
                whole * 1_000_000
                    + BigInt::from((seconds.fract() * 1_000_000.).round_ties_even() as i64)
            }
        }
        _ => return Err(RefreshError::ExpiryType),
    };
    let micros = i128::try_from(micros).map_err(|_| RefreshError::ExpiryRange)?;
    let timestamp = now
        .unix_timestamp_nanos()
        .div_euclid(1000)
        .checked_add(micros)
        .and_then(|value| value.checked_mul(1000))
        .ok_or(RefreshError::ExpiryRange)?;
    let expiry = OffsetDateTime::from_unix_timestamp_nanos(timestamp)
        .map_err(|_| RefreshError::ExpiryRange)?
        .to_offset(UtcOffset::UTC);
    if !(1..=9999).contains(&expiry.year()) {
        return Err(RefreshError::ExpiryRange);
    }
    let fraction = if expiry.microsecond() == 0 {
        String::new()
    } else {
        format!(".{:06}", expiry.microsecond())
    };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}+00:00",
        expiry.year(),
        expiry.month() as u8,
        expiry.day(),
        expiry.hour(),
        expiry.minute(),
        expiry.second()
    ))
}

fn quote_plus(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            b' ' => output.push('+'),
            _ => {
                output.push('%');
                output.push(HEX[(byte >> 4) as usize] as char);
                output.push(HEX[(byte & 15) as usize] as char);
            }
        }
    }
}

fn decode_json_text(body: &[u8]) -> Result<Zeroizing<String>> {
    crate::python_json::decode_json_text(body).map_err(|_| RefreshError::JsonEncoding)
}
