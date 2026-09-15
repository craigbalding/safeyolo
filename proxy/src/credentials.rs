//! Existing encrypted vault format, inactive in proxy transport.
//!
//! Files contain a 16-byte salt followed by a Fernet token. The key is derived
//! with PBKDF2-HMAC-SHA256, 480,000 iterations, from the UTF-8 passphrase. Fernet
//! authenticates the encrypted YAML; vault files have no Fernet token TTL.
//! Mozilla's `fernet` crate supplies the protocol and RustCrypto primitives.
//!
//! One Vault and its clones serialize local mutations. Python's vault has no
//! cross-process lock, so independent writers still require coordination. Polling
//! and gateway activation belong to the caller. Atomic reload and write rollback
//! retain the previous snapshot on failure, correcting Python's partial reload
//! and mutation-before-save behavior. Changed salt requires a fresh unlock.
//!
//! OAuth refresh inventory (core/vault.py and service_gateway.py): `oauth2`, a
//! nonempty refresh_token and token_url, and actual expiry are required. Despite
//! its name, auth.refresh_on_401 gates refresh before credential injection. Python
//! sends a form POST with grant_type=refresh_token, refresh_token, client_id and
//! client_secret (missing client values become empty), with a 10-second timeout.
//! Success requires an HTTP success status and JSON access_token; refresh_token
//! rotates only when present, expires_in replaces expiry relative to response
//! time, then the vault saves. HTTP/JSON failure returns false and the gateway
//! retains the old credential for injection; missing access_token or invalid
//! expires_in can instead propagate errors during publication. The old method
//! reselects by name after network completion without a version check or request
//! deduplication. HTTP execution, refresh response publication, concurrent-refresh
//! arbitration, key-file loading and secret injection are not implemented here.

use std::{
    fmt,
    fs::{self, File, Permissions},
    io::{Read, Write},
    num::NonZeroU32,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use base64::{
    Engine, alphabet,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE},
    },
};
use fernet::Fernet;
use ring::{
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::Serialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use crate::policy::{expiry_has_offset, parse_expiry, parse_yaml_for_vault};

const SALT_LENGTH: usize = 16;
const KDF_ITERATIONS: u32 = 480_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Io,
    Authentication,
    Format,
    KeyChanged,
    InvalidExpiry,
    Activation,
    Rollback,
    State,
}

/// Errors intentionally contain no source text, passphrase, token, or callback
/// error strings. YAML parser diagnostics can include decrypted credential text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultError {
    pub kind: ErrorKind,
    pub io_kind: Option<std::io::ErrorKind>,
}
impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ErrorKind::Io => "vault filesystem operation failed",
            ErrorKind::Authentication => "wrong passphrase or corrupted vault",
            ErrorKind::Format => "invalid decrypted vault document",
            ErrorKind::KeyChanged => "vault salt changed; unlock with its current passphrase",
            ErrorKind::InvalidExpiry => "credential expiry has no timezone",
            ErrorKind::Activation => "vault activation rejected",
            ErrorKind::Rollback => "vault rollback failed",
            ErrorKind::State => "vault state unavailable",
        })
    }
}
impl std::error::Error for VaultError {}
impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            io_kind: Some(error.kind()),
        }
    }
}
type Result<T> = std::result::Result<T, VaultError>;
fn error(kind: ErrorKind) -> VaultError {
    VaultError {
        kind,
        io_kind: None,
    }
}

/// Secret material has no Debug, Display, or Serialize implementation. Explicit
/// access is required at the later authorized injection or refresh boundary.
///
/// ```compile_fail
/// use safeyolo_proxy::credentials::Secret;
/// let secret = Secret::new("synthetic");
/// let _ = format!("{secret:?}");
/// ```
/// ```compile_fail
/// use safeyolo_proxy::credentials::Secret;
/// let _ = serde_json::to_string(&Secret::new("synthetic"));
/// ```
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Clone supports isolated read snapshots and atomic mutation candidates. Only
/// the private encrypted-storage encoder can serialize this complete record.
#[derive(Clone)]
pub struct Credential {
    pub name: String,
    pub credential_type: String,
    pub value: Secret,
    pub refresh_token: Option<Secret>,
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<Secret>,
    pub expires_at: Option<String>,
}
impl Credential {
    pub fn new(name: impl Into<String>, credential_type: impl Into<String>, value: Secret) -> Self {
        Self {
            name: name.into(),
            credential_type: credential_type.into(),
            value,
            refresh_token: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            expires_at: None,
        }
    }
    pub fn metadata(&self) -> CredentialMetadata {
        CredentialMetadata {
            name: self.name.clone(),
            credential_type: self.credential_type.clone(),
            expires_at: self.expires_at.clone(),
        }
    }
    /// Python treats malformed expiry as expired but raises for valid naive
    /// timestamps. Preserve that distinction instead of silently assuming UTC.
    pub fn is_expired(&self, now: OffsetDateTime) -> Result<bool> {
        let Some(value) = self.expires_at.as_deref().filter(|value| !value.is_empty()) else {
            return Ok(false);
        };
        let Some(expiry) = parse_expiry(value) else {
            return Ok(true);
        };
        if !expiry_has_offset(value) {
            return Err(error(ErrorKind::InvalidExpiry));
        }
        Ok(now >= expiry)
    }
    pub fn needs_oauth_refresh(&self, now: OffsetDateTime) -> Result<bool> {
        if self.credential_type != "oauth2"
            || self.refresh_token.as_ref().is_none_or(Secret::is_empty)
            || self.token_url.as_deref().is_none_or(str::is_empty)
        {
            return Ok(false);
        }
        self.is_expired(now)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialMetadata {
    pub name: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub expires_at: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    modified: SystemTime,
    length: u64,
    device: u64,
    inode: u64,
}
fn stamp(file: &File) -> Result<Stamp> {
    let metadata = file.metadata()?;
    Ok(Stamp {
        modified: metadata.modified()?,
        length: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
fn read_file(path: &Path) -> Result<(Vec<u8>, Stamp)> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok((bytes, stamp(&file)?))
}
struct State {
    cipher: Zeroizing<Fernet>,
    salt: [u8; SALT_LENGTH],
    credentials: Vec<Credential>,
    stamp: Stamp,
}

/// All clones share the same local snapshot. Operations perform synchronous KDF
/// and filesystem work and should run outside an async request executor.
#[derive(Clone)]
pub struct Vault {
    path: PathBuf,
    state: Arc<Mutex<State>>,
}
impl Vault {
    /// Match Python unlock: create an empty encrypted vault when the file is
    /// absent. Gateway startup must check its configured paths before calling.
    pub fn unlock(path: impl Into<PathBuf>, passphrase: &Secret) -> Result<Self> {
        let path = path.into();
        let loaded = match read_file(&path) {
            Ok(value) => Some(value),
            Err(value) if value.io_kind == Some(std::io::ErrorKind::NotFound) => None,
            Err(value) => return Err(value),
        };
        let mut salt = [0; SALT_LENGTH];
        if let Some((raw, _)) = &loaded {
            salt.copy_from_slice(
                raw.get(..SALT_LENGTH)
                    .ok_or_else(|| error(ErrorKind::Authentication))?,
            );
        } else {
            SystemRandom::new()
                .fill(&mut salt)
                .map_err(|_| error(ErrorKind::State))?;
        }
        let cipher = derive_cipher(passphrase, &salt)?;
        let (credentials, stamp) = if let Some((raw, stamp)) = loaded {
            (decrypt(&cipher, &raw)?, stamp)
        } else {
            let bytes = encrypt(&cipher, &salt, &[])?;
            (
                Vec::new(),
                save_atomic(&path, &bytes).map_err(|failure| failure.error)?,
            )
        };
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(State {
                cipher,
                salt,
                credentials,
                stamp,
            })),
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| error(ErrorKind::State))
    }
    pub fn get(&self, name: &str) -> Result<Option<Credential>> {
        Ok(self
            .lock()?
            .credentials
            .iter()
            .find(|credential| credential.name == name)
            .cloned())
    }
    pub fn list_names(&self) -> Result<Vec<String>> {
        Ok(self
            .lock()?
            .credentials
            .iter()
            .map(|credential| credential.name.clone())
            .collect())
    }
    pub fn metadata(&self) -> Result<Vec<CredentialMetadata>> {
        Ok(metadata(&self.lock()?.credentials))
    }
    pub fn store(&self, credential: Credential) -> Result<()> {
        self.store_with_activation(credential, |_| Ok(()))
    }
    pub fn store_with_activation(
        &self,
        credential: Credential,
        activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<()> {
        self.mutate(
            |credentials| {
                upsert(credentials, credential);
                true
            },
            activate,
        )
        .map(|_| ())
    }
    pub fn remove(&self, name: &str) -> Result<bool> {
        self.remove_with_activation(name, |_| Ok(()))
    }
    pub fn remove_with_activation(
        &self,
        name: &str,
        activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        self.mutate(
            |credentials| {
                let before = credentials.len();
                credentials.retain(|credential| credential.name != name);
                credentials.len() != before
            },
            activate,
        )
    }
    pub fn save(&self) -> Result<()> {
        self.mutate(|_| true, |_| Ok(())).map(|_| ())
    }
    /// Callbacks receive metadata only and must not re-enter this Vault. Rejected
    /// activation restores the exact preceding encrypted bytes and old metadata.
    fn mutate(
        &self,
        mutation: impl FnOnce(&mut Vec<Credential>) -> bool,
        mut activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        let mut state = self.lock()?;
        let mut candidate = state.credentials.clone();
        if !mutation(&mut candidate) {
            return Ok(false);
        }
        let original = fs::read(&self.path)?;
        let encrypted = encrypt(&state.cipher, &state.salt, &candidate)?;
        let stamp = match save_atomic(&self.path, &encrypted) {
            Ok(stamp) => stamp,
            Err(failure) => {
                if failure.committed {
                    restore(&self.path, &original, &mut state, &mut activate)?;
                }
                return Err(failure.error);
            }
        };
        if activate(&metadata(&candidate)).is_err() {
            restore(&self.path, &original, &mut state, &mut activate)?;
            return Err(error(ErrorKind::Activation));
        }
        state.credentials = candidate;
        state.stamp = stamp;
        Ok(true)
    }
    /// Missing files match Python's watcher: no reload is signaled. Explicit
    /// reload still reports the filesystem failure and retains the active state.
    pub fn has_changes(&self) -> Result<bool> {
        let state = self.lock()?;
        match File::open(&self.path) {
            Ok(file) => Ok(stamp(&file)? != state.stamp),
            Err(value) if value.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(value) => Err(value.into()),
        }
    }
    pub fn reload_if_changed(&self) -> Result<bool> {
        if !self.has_changes()? {
            return Ok(false);
        }
        self.reload()?;
        Ok(true)
    }
    pub fn reload(&self) -> Result<()> {
        self.reload_with_activation(|_| Ok(()))
    }
    pub fn reload_with_activation(
        &self,
        mut activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<()> {
        let mut state = self.lock()?;
        let (raw, stamp) = read_file(&self.path)?;
        if raw.get(..SALT_LENGTH) != Some(state.salt.as_slice()) {
            return Err(error(ErrorKind::KeyChanged));
        }
        let candidate = decrypt(&state.cipher, &raw)?;
        if activate(&metadata(&candidate)).is_err() {
            activate(&metadata(&state.credentials)).map_err(|_| error(ErrorKind::Rollback))?;
            return Err(error(ErrorKind::Activation));
        }
        state.credentials = candidate;
        state.stamp = stamp;
        Ok(())
    }
}

fn metadata(credentials: &[Credential]) -> Vec<CredentialMetadata> {
    credentials.iter().map(Credential::metadata).collect()
}
fn upsert(credentials: &mut Vec<Credential>, credential: Credential) {
    if let Some(existing) = credentials
        .iter_mut()
        .find(|existing| existing.name == credential.name)
    {
        *existing = credential;
    } else {
        credentials.push(credential);
    }
}
fn derive_cipher(passphrase: &Secret, salt: &[u8; SALT_LENGTH]) -> Result<Zeroizing<Fernet>> {
    let mut raw = Zeroizing::new([0u8; 32]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(KDF_ITERATIONS).unwrap(),
        salt,
        passphrase.expose_secret().as_bytes(),
        raw.as_mut(),
    );
    let encoded = Zeroizing::new(URL_SAFE.encode(raw.as_ref()));
    Fernet::new(&encoded)
        .map(Zeroizing::new)
        .ok_or_else(|| error(ErrorKind::State))
}
fn decrypt(cipher: &Fernet, raw: &[u8]) -> Result<Vec<Credential>> {
    let token = canonical_token(
        raw.get(SALT_LENGTH..)
            .ok_or_else(|| error(ErrorKind::Authentication))?,
    )?;
    // fernet 0.2.2 applies a future-clock check even with TTL=None, unlike
    // Python cryptography. Its explicit-time API disables that extra check when
    // now+MAX_CLOCK_SKEW is u64::MAX. No TTL is supplied; HMAC, version and PKCS7
    // verification still run in the library. Keep this adapter private to vaults.
    let plaintext = Zeroizing::new(
        cipher
            .decrypt_at_time(&token, None, u64::MAX - 60)
            .map_err(|_| error(ErrorKind::Authentication))?,
    );
    let plaintext = std::str::from_utf8(&plaintext).map_err(|_| error(ErrorKind::Format))?;
    let mut document = parse_yaml_for_vault(plaintext).map_err(|_| error(ErrorKind::Format))?;
    let result = decode_credentials(&mut document);
    wipe_json(&mut document);
    result
}

/// Python's urlsafe_b64decode uses binascii's non-strict mode: non-alphabet
/// bytes and premature padding are ignored, completed padding ends the token,
/// and final incomplete groups fail. Canonicalize those encodings through the
/// base64 library; no authenticated token bytes are modified or trusted here.
fn canonical_token(raw: &[u8]) -> Result<String> {
    let mut encoded = Vec::new();
    let mut padding = 0;
    for byte in raw {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_' => {
                encoded.push(match byte {
                    b'+' => b'-',
                    b'/' => b'_',
                    value => *value,
                });
                padding = 0;
            }
            b'=' if encoded.len() % 4 == 3 => {
                encoded.push(b'=');
                break;
            }
            b'=' if encoded.len() % 4 == 2 => {
                padding += 1;
                if padding == 2 {
                    encoded.extend_from_slice(b"==");
                    break;
                }
            }
            _ => {}
        }
    }
    if !encoded.len().is_multiple_of(4) {
        return Err(error(ErrorKind::Authentication));
    }
    let decoder = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(true),
    );
    let decoded = decoder
        .decode(encoded)
        .map_err(|_| error(ErrorKind::Authentication))?;
    Ok(URL_SAFE.encode(decoded))
}
fn decode_credentials(document: &mut Value) -> Result<Vec<Credential>> {
    if matches!(document, Value::Null | Value::Bool(false))
        || document.as_array().is_some_and(Vec::is_empty)
        || document.as_str() == Some("")
        || document.as_i64() == Some(0)
    {
        return Ok(Vec::new());
    }
    let document = document
        .as_object_mut()
        .ok_or_else(|| error(ErrorKind::Format))?;
    let Some(records) = document.get_mut("credentials") else {
        return Ok(Vec::new());
    };
    let records = records
        .as_array_mut()
        .ok_or_else(|| error(ErrorKind::Format))?;
    let mut credentials = Vec::new();
    for record in records {
        let record = record
            .as_object_mut()
            .ok_or_else(|| error(ErrorKind::Format))?;
        let mut credential = Credential::new(
            required(record, "name")?,
            required(record, "type")?,
            Secret::new(required(record, "value")?),
        );
        credential.refresh_token = optional(record, "refresh_token")?.map(Secret::new);
        credential.token_url = optional(record, "token_url")?;
        credential.client_id = optional(record, "client_id")?;
        credential.client_secret = optional(record, "client_secret")?.map(Secret::new);
        credential.expires_at = optional(record, "expires_at")?;
        upsert(&mut credentials, credential);
    }
    Ok(credentials)
}
fn required(record: &mut Map<String, Value>, key: &str) -> Result<String> {
    match record.get_mut(key).map(Value::take) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(error(ErrorKind::Format)),
    }
}
fn optional(record: &mut Map<String, Value>, key: &str) -> Result<Option<String>> {
    match record.get_mut(key).map(Value::take) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(error(ErrorKind::Format)),
    }
}
fn wipe_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_json),
        Value::Object(values) => values.values_mut().for_each(wipe_json),
        _ => {}
    }
}
fn encrypt(
    cipher: &Fernet,
    salt: &[u8; SALT_LENGTH],
    credentials: &[Credential],
) -> Result<Vec<u8>> {
    // JSON is valid YAML and avoids a public Serialize implementation for secret
    // records. Escaping uses serde_json only inside this encrypted-storage path.
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext.extend_from_slice(b"{\"credentials\":[");
    for (index, credential) in credentials.iter().enumerate() {
        if index > 0 {
            plaintext.push(b',');
        }
        plaintext.push(b'{');
        let fields = [
            ("name", Some(credential.name.as_str())),
            ("type", Some(credential.credential_type.as_str())),
            ("value", Some(credential.value.expose_secret())),
            (
                "refresh_token",
                credential
                    .refresh_token
                    .as_ref()
                    .map(Secret::expose_secret)
                    .filter(|value| !value.is_empty()),
            ),
            (
                "token_url",
                credential
                    .token_url
                    .as_deref()
                    .filter(|value| !value.is_empty()),
            ),
            (
                "client_id",
                credential
                    .client_id
                    .as_deref()
                    .filter(|value| !value.is_empty()),
            ),
            (
                "client_secret",
                credential
                    .client_secret
                    .as_ref()
                    .map(Secret::expose_secret)
                    .filter(|value| !value.is_empty()),
            ),
            (
                "expires_at",
                credential
                    .expires_at
                    .as_deref()
                    .filter(|value| !value.is_empty()),
            ),
        ];
        let mut comma = false;
        for (key, value) in fields {
            if let Some(value) = value {
                if comma {
                    plaintext.push(b',');
                }
                comma = true;
                serde_json::to_writer(&mut *plaintext, key)
                    .map_err(|_| error(ErrorKind::Format))?;
                plaintext.push(b':');
                serde_json::to_writer(&mut *plaintext, value)
                    .map_err(|_| error(ErrorKind::Format))?;
            }
        }
        plaintext.push(b'}');
    }
    plaintext.extend_from_slice(b"]}");
    let encrypted = cipher.encrypt(&plaintext);
    let mut bytes = salt.to_vec();
    bytes.extend_from_slice(encrypted.as_bytes());
    Ok(bytes)
}
struct SaveError {
    error: VaultError,
    committed: bool,
}
fn save_atomic(path: &Path, bytes: &[u8]) -> std::result::Result<Stamp, SaveError> {
    let mut committed = false;
    let operation = (|| -> Result<Stamp> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".vault-")
            .tempfile_in(parent)?;
        temporary
            .as_file()
            .set_permissions(Permissions::from_mode(0o600))?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        let file = temporary
            .persist(path)
            .map_err(|value| VaultError::from(value.error))?;
        committed = true;
        File::open(parent)?.sync_all()?;
        stamp(&file)
    })();
    operation.map_err(|error| SaveError { error, committed })
}
fn restore(
    path: &Path,
    original: &[u8],
    state: &mut State,
    activate: &mut impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
) -> Result<()> {
    state.stamp = save_atomic(path, original).map_err(|_| error(ErrorKind::Rollback))?;
    activate(&metadata(&state.credentials)).map_err(|_| error(ErrorKind::Rollback))
}
