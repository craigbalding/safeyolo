//! Native encrypted credentials and host-controlled external references.
//!
//! Files contain a 16-byte salt followed by an authenticated Fernet token.
//! PBKDF2-HMAC-SHA256 derives the key with 480,000 iterations. New native
//! credentials use encrypted JSON; old vault files and keys are not loaded.
//! Clones share snapshots and OAuth revisions. A file lock serializes native
//! command writes with refresh publication across processes.

use std::{
    collections::HashMap,
    fmt,
    fs::{self, File, Permissions},
    io::{Read, Write},
    num::NonZeroU32,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

use base64::{Engine, engine::general_purpose::URL_SAFE};
use fernet::Fernet;
use ring::{
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use crate::policy::{expiry_has_offset, parse_expiry};

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

/// Identifies the side of an atomic vault publication callback. Candidate
/// activation may be rejected independently for every in-flight operation;
/// rollback is the matching restoration of that operation's prior snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationPhase {
    Candidate,
    Rollback,
}

/// Errors intentionally contain no source text, passphrase, token, or callback
/// error strings. Parser diagnostics can include decrypted credential text.
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
    pub reference: Option<ExternalReference>,
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
            reference: None,
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
            reference: self.reference.clone(),
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
    pub reference: Option<ExternalReference>,
}

/// Provider selection is stored by the host. Guests select only minted gateway
/// credentials; neither a reference nor an executable comes from their request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", content = "reference", rename_all = "lowercase")]
pub enum ExternalReference {
    Onepassword(String),
}

impl ExternalReference {
    pub fn validate(&self) -> Result<()> {
        let Self::Onepassword(reference) = self;
        if !reference.starts_with("op://")
            || reference[5..].is_empty()
            || reference.chars().any(char::is_control)
        {
            return Err(error(ErrorKind::Format));
        }
        Ok(())
    }
}

fn lock_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.lock()?;
    Ok(file)
}

/// Fresh native state has its own names and JSON schema. Old vault keys/files
/// are never inspected. This is the same encrypted store used by OAuth refresh.
pub fn open(data_dir: &Path) -> Result<Vault> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::create_dir_all(data_dir)?;
    let key_path = data_dir.join("credentials.key");
    let key_lock = lock_file(&data_dir.join(".credentials.key.lock"))?;
    let key = match fs::read_to_string(&key_path) {
        Ok(key) => Zeroizing::new(key),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
            let mut raw = Zeroizing::new([0u8; 32]);
            SystemRandom::new()
                .fill(raw.as_mut())
                .map_err(|_| error(ErrorKind::State))?;
            let key = Zeroizing::new(URL_SAFE.encode(raw.as_ref()));
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&key_path)?;
            file.write_all(key.as_bytes())?;
            file.sync_all()?;
            key
        }
        Err(failure) => return Err(failure.into()),
    };
    drop(key_lock);
    if key.trim().is_empty() {
        return Err(error(ErrorKind::Authentication));
    }
    Vault::unlock(data_dir.join("credentials.enc"), &Secret::new(key.trim()))
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
    revisions: HashMap<String, Arc<()>>,
    stamp: Stamp,
}

/// An opaque record and revision bound to one Vault and its clones. A late
/// refresh can publish only while this revision remains current. Secret-bearing
/// snapshots intentionally have no Debug, Display or Serialize implementation.
pub struct CredentialSnapshot {
    credential: Credential,
    revision: Arc<()>,
    state: Arc<Mutex<State>>,
}
impl CredentialSnapshot {
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
}

/// All clones share the same local snapshot. Operations perform synchronous KDF
/// and filesystem work and should run outside an async request executor.
#[derive(Clone)]
pub struct Vault {
    path: PathBuf,
    state: Arc<Mutex<State>>,
}
impl Vault {
    /// Create an empty encrypted store when absent.
    pub fn unlock(path: impl Into<PathBuf>, passphrase: &Secret) -> Result<Self> {
        let path = path.into();
        let _file_lock = lock_file(&path.with_extension("lock"))?;
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
        let revisions = credentials
            .iter()
            .map(|credential| (credential.name.clone(), Arc::new(())))
            .collect();
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(State {
                cipher,
                salt,
                credentials,
                revisions,
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
    pub fn snapshot(&self, name: &str) -> Result<Option<CredentialSnapshot>> {
        let state = self.lock()?;
        let Some(credential) = state.credentials.iter().find(|record| record.name == name) else {
            return Ok(None);
        };
        let revision = state
            .revisions
            .get(name)
            .ok_or_else(|| error(ErrorKind::State))?;
        Ok(Some(CredentialSnapshot {
            credential: credential.clone(),
            revision: revision.clone(),
            state: self.state.clone(),
        }))
    }
    /// Observe whether a captured record is still current, including visible
    /// external replacement or removal of the encrypted file. This read-only
    /// check does not reserve the record for later transport work.
    pub fn is_current(&self, snapshot: &CredentialSnapshot) -> Result<bool> {
        let state = self.lock()?;
        if !self.same_revision(&state, snapshot) {
            return Ok(false);
        }
        match File::open(&self.path) {
            Ok(file) => Ok(stamp(&file)? == state.stamp),
            Err(value) if value.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(value) => Err(value.into()),
        }
    }
    fn same_revision(&self, state: &State, snapshot: &CredentialSnapshot) -> bool {
        Arc::ptr_eq(&self.state, &snapshot.state)
            && state
                .revisions
                .get(&snapshot.credential.name)
                .is_some_and(|revision| Arc::ptr_eq(revision, &snapshot.revision))
    }
    /// Returns false without writing or activating if a store, removal, changed
    /// reload, or visible external file replacement superseded the snapshot.
    /// Unrelated edits through this Vault preserve the revision. Visible external
    /// writes are also checked under the file lock before conditional publication.
    pub fn replace_if_current(
        &self,
        snapshot: &CredentialSnapshot,
        replacement: Credential,
        mut activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        self.replace_if_current_transactional(snapshot, replacement, |_, metadata| {
            activate(metadata)
        })
    }
    /// Conditional replacement with a callback that can distinguish a new
    /// candidate from the exact rollback performed after its rejection.
    pub fn replace_if_current_transactional(
        &self,
        snapshot: &CredentialSnapshot,
        replacement: Credential,
        activate: impl FnMut(ActivationPhase, &[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        if replacement.name != snapshot.credential.name {
            return Err(error(ErrorKind::Format));
        }
        self.mutate(
            Some(snapshot),
            Some(&snapshot.credential.name),
            |credentials| {
                upsert(credentials, replacement);
                true
            },
            activate,
        )
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
        mut activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<()> {
        self.store_with_transactional_activation(credential, |_, metadata| activate(metadata))
    }
    pub fn store_with_transactional_activation(
        &self,
        credential: Credential,
        activate: impl FnMut(ActivationPhase, &[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<()> {
        let name = credential.name.clone();
        self.mutate(
            None,
            Some(&name),
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
        mut activate: impl FnMut(&[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        self.remove_with_transactional_activation(name, |_, metadata| activate(metadata))
    }
    pub fn remove_with_transactional_activation(
        &self,
        name: &str,
        activate: impl FnMut(ActivationPhase, &[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        self.mutate(
            None,
            Some(name),
            |credentials| {
                let before = credentials.len();
                credentials.retain(|credential| credential.name != name);
                credentials.len() != before
            },
            activate,
        )
    }
    pub fn save(&self) -> Result<()> {
        self.mutate(None, None, |_| true, |_, _| Ok(())).map(|_| ())
    }
    /// Callbacks receive metadata only and must not re-enter this Vault. Rejected
    /// activation restores the exact preceding encrypted bytes and old metadata.
    fn mutate(
        &self,
        expected: Option<&CredentialSnapshot>,
        invalidate: Option<&str>,
        mutation: impl FnOnce(&mut Vec<Credential>) -> bool,
        mut activate: impl FnMut(ActivationPhase, &[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<bool> {
        let _file_lock = lock_file(&self.path.with_extension("lock"))?;
        let mut state = self.lock()?;
        if let Some(snapshot) = expected
            && !self.same_revision(&state, snapshot)
        {
            return Ok(false);
        }
        let (original, original_stamp) = read_file(&self.path)?;
        if original_stamp != state.stamp {
            if expected.is_some() {
                return Ok(false);
            }
            if original.get(..SALT_LENGTH) != Some(state.salt.as_slice()) {
                return Err(error(ErrorKind::KeyChanged));
            }
            let loaded = decrypt(&state.cipher, &original)?;
            state.revisions = revisions_for(&state, &loaded, None);
            state.credentials = loaded;
            state.stamp = original_stamp.clone();
        }
        let mut candidate = state.credentials.clone();
        if !mutation(&mut candidate) {
            return Ok(false);
        }
        if expected.is_some() && original_stamp != state.stamp {
            return Ok(false);
        }
        let encrypted = encrypt(&state.cipher, &state.salt, &candidate)?;
        let stamp = match save_atomic(&self.path, &encrypted) {
            Ok(stamp) => stamp,
            Err(failure) => {
                if failure.committed {
                    restore(
                        &self.path,
                        &original,
                        &original_stamp,
                        &mut state,
                        &mut activate,
                    )?;
                }
                return Err(failure.error);
            }
        };
        if activate(ActivationPhase::Candidate, &metadata(&candidate)).is_err() {
            restore(
                &self.path,
                &original,
                &original_stamp,
                &mut state,
                &mut activate,
            )?;
            return Err(error(ErrorKind::Activation));
        }
        state.revisions = revisions_for(&state, &candidate, invalidate);
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
        self.reload_with_transactional_activation(|_, metadata| activate(metadata))
    }
    pub fn reload_with_transactional_activation(
        &self,
        mut activate: impl FnMut(ActivationPhase, &[CredentialMetadata]) -> std::result::Result<(), ()>,
    ) -> Result<()> {
        let mut state = self.lock()?;
        let (raw, stamp) = read_file(&self.path)?;
        if raw.get(..SALT_LENGTH) != Some(state.salt.as_slice()) {
            return Err(error(ErrorKind::KeyChanged));
        }
        let candidate = decrypt(&state.cipher, &raw)?;
        if activate(ActivationPhase::Candidate, &metadata(&candidate)).is_err() {
            activate(ActivationPhase::Rollback, &metadata(&state.credentials))
                .map_err(|_| error(ErrorKind::Rollback))?;
            return Err(error(ErrorKind::Activation));
        }
        state.revisions = revisions_for(&state, &candidate, None);
        state.credentials = candidate;
        state.stamp = stamp;
        Ok(())
    }
}

fn revisions_for(
    state: &State,
    candidate: &[Credential],
    invalidate: Option<&str>,
) -> HashMap<String, Arc<()>> {
    let previous: HashMap<_, _> = state
        .credentials
        .iter()
        .map(|credential| (credential.name.as_str(), credential))
        .collect();
    candidate
        .iter()
        .map(|credential| {
            let revision = if invalidate != Some(credential.name.as_str())
                && previous
                    .get(credential.name.as_str())
                    .is_some_and(|old| same_credential(old, credential))
            {
                state.revisions.get(&credential.name).cloned()
            } else {
                None
            };
            (
                credential.name.clone(),
                revision.unwrap_or_else(|| Arc::new(())),
            )
        })
        .collect()
}

fn same_credential(left: &Credential, right: &Credential) -> bool {
    left.name == right.name
        && left.reference == right.reference
        && left.credential_type == right.credential_type
        && left.value.expose_secret() == right.value.expose_secret()
        && left.refresh_token.as_ref().map(Secret::expose_secret)
            == right.refresh_token.as_ref().map(Secret::expose_secret)
        && left.token_url == right.token_url
        && left.client_id == right.client_id
        && left.client_secret.as_ref().map(Secret::expose_secret)
            == right.client_secret.as_ref().map(Secret::expose_secret)
        && left.expires_at == right.expires_at
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
    let token = std::str::from_utf8(
        raw.get(SALT_LENGTH..)
            .ok_or_else(|| error(ErrorKind::Authentication))?,
    )
    .map_err(|_| error(ErrorKind::Authentication))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(token)
            .map_err(|_| error(ErrorKind::Authentication))?,
    );
    let mut document: Value =
        serde_json::from_slice(&plaintext).map_err(|_| error(ErrorKind::Format))?;
    let result = decode_credentials(&mut document);
    wipe_json(&mut document);
    result
}

fn decode_credentials(document: &mut Value) -> Result<Vec<Credential>> {
    let document = document
        .as_object_mut()
        .ok_or_else(|| error(ErrorKind::Format))?;
    let records = document
        .get_mut("credentials")
        .ok_or_else(|| error(ErrorKind::Format))?;
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
        credential.reference = record
            .get_mut("reference")
            .map(Value::take)
            .filter(|value| !value.is_null())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| error(ErrorKind::Format))?;
        if let Some(reference) = &credential.reference {
            reference.validate()?;
        }
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
pub(crate) fn wipe_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_json),
        Value::Object(values) => {
            // Gateway maps can use credentials as keys. Own each key before
            // wiping it so the map never retains a modified hash key.
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                wipe_json(&mut value);
            }
        }
        _ => {}
    }
}

fn encrypt(
    cipher: &Fernet,
    salt: &[u8; SALT_LENGTH],
    credentials: &[Credential],
) -> Result<Vec<u8>> {
    // Secret records have no public Serialize implementation. Escaping uses
    // serde_json only inside this encrypted-storage path.
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
        if let Some(reference) = &credential.reference {
            if comma {
                plaintext.push(b',');
            }
            plaintext.extend_from_slice(b"\"reference\":");
            serde_json::to_writer(&mut *plaintext, reference)
                .map_err(|_| error(ErrorKind::Format))?;
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
    original_stamp: &Stamp,
    state: &mut State,
    activate: &mut impl FnMut(ActivationPhase, &[CredentialMetadata]) -> std::result::Result<(), ()>,
) -> Result<()> {
    let restored_stamp = save_atomic(path, original).map_err(|_| error(ErrorKind::Rollback))?;
    // An external edit may already have made the active snapshot stale before
    // this local write. Restoring those external bytes must not mark the old
    // in-memory credential and its pending refresh revision as current.
    if original_stamp == &state.stamp {
        state.stamp = restored_stamp;
    }
    activate(ActivationPhase::Rollback, &metadata(&state.credentials))
        .map_err(|_| error(ErrorKind::Rollback))
}

#[cfg(test)]
mod wiping_tests {
    #[test]
    fn structural_wipe_removes_object_keys_and_clears_nested_values() {
        let mut value = serde_json::json!([
            "synthetic-array-value",
            {"synthetic-object-key": ["synthetic-nested-value", {"nested-key":"nested-value"}]},
            ["other-array-value"]
        ]);
        super::wipe_json(&mut value);
        assert_eq!(value, serde_json::json!(["", {}, [""]]));
    }
}
