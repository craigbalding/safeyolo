//! Network approvals are durable host-policy edits, not independent grants.
//! Prompt metadata retains the current audit schema. Gateway once/session grants
//! are a separate capability and are not represented here.

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::policy::{
    LargeIntegerContext, expired_host_entries, expiry_has_offset, parse_expiry,
    restore_large_toml_integers, split_destination,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Invalid,
    Unsupported,
    Io,
    Activation,
    Rollback,
}

#[derive(Debug)]
pub struct ApprovalError {
    pub kind: ErrorKind,
    pub message: String,
}
impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}
impl std::error::Error for ApprovalError {}
impl From<std::io::Error> for ApprovalError {
    fn from(error: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: error.to_string(),
        }
    }
}
type Result<T> = std::result::Result<T, ApprovalError>;
fn invalid(message: impl Into<String>) -> ApprovalError {
    ApprovalError {
        kind: ErrorKind::Invalid,
        message: message.into(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkScope {
    pub host: String,
    pub agent: Option<String>,
    pub port: Option<u16>,
}

impl NetworkScope {
    pub fn new(host: &str, agent: Option<&str>, port: Option<u16>) -> Result<Self> {
        let (host, embedded) =
            split_destination(host).map_err(|error| invalid(error.to_string()))?;
        if host.is_empty() || port == Some(0) {
            return Err(invalid(
                "host must be present and port must be from 1 to 65535",
            ));
        }
        if embedded.is_some() && port.is_some() && embedded != port {
            return Err(invalid("host endpoint and port disagree"));
        }
        Ok(Self {
            host,
            agent: agent.map(str::to_owned),
            port: port.or(embedded),
        })
    }

    /// New sensor events always have a port; legacy operator events may not.
    pub fn from_event(event: &Json) -> Result<Self> {
        if !event.is_object() {
            return Err(invalid("approval event must be an object"));
        }
        for path in ["/approval", "/approval/scope_hint", "/details"] {
            if event.pointer(path).is_some_and(|value| !value.is_object()) {
                return Err(invalid(format!("{path} must be an object")));
            }
        }
        for path in ["/host", "/approval/target", "/agent"] {
            if event
                .pointer(path)
                .is_some_and(|value| !value.is_string() && !value.is_null())
            {
                return Err(invalid(format!("{path} must be a string")));
            }
        }
        let port = event
            .pointer("/approval/scope_hint/port")
            .filter(|value| !value.is_null())
            .or_else(|| {
                event
                    .pointer("/details/port")
                    .filter(|value| !value.is_null())
            });
        let port = port
            .map(|value| {
                value
                    .as_u64()
                    .filter(|port| *port > 0)
                    .and_then(|port| u16::try_from(port).ok())
                    .ok_or_else(|| invalid("port must be an integer from 1 to 65535"))
            })
            .transpose()?;
        let host = event
            .get("host")
            .and_then(Json::as_str)
            .or_else(|| event.pointer("/approval/target").and_then(Json::as_str))
            .unwrap_or("");
        Self::new(
            host,
            event
                .get("agent")
                .and_then(Json::as_str)
                .filter(|agent| !agent.is_empty()),
            port,
        )
    }

    pub fn destination(&self) -> String {
        match self.port {
            None => self.host.clone(),
            Some(port) if self.host.contains(':') => format!("[{}]:{port}", self.host),
            Some(port) => format!("{}:{port}", self.host),
        }
    }

    pub fn approval_key(&self) -> Result<String> {
        validate_scope(self)?;
        let port = self
            .port
            .ok_or_else(|| invalid("new network prompts require a destination port"))?;
        // Python json.dumps defaults to ASCII escapes. Preserve the actual key,
        // including UTF-16 surrogate pairs for non-BMP agent names.
        let compact =
            serde_json::to_string(&(self.agent.as_deref().unwrap_or(""), &self.host, port))
                .map_err(|error| invalid(error.to_string()))?;
        let mut key = String::new();
        for character in compact.chars() {
            if character.is_ascii() && character != '\u{7f}' {
                key.push(character);
            } else {
                for unit in character.encode_utf16(&mut [0u16; 2]) {
                    key.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
        Ok(key)
    }

    pub fn resolved_key(&self) -> Result<String> {
        if self.port.is_none() {
            return Ok(format!("{}:{}", self.host, self.host));
        }
        Ok(format!("{}:{}", self.approval_key()?, self.destination()))
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkPrompt {
    required: bool,
    approval_type: &'static str,
    pub key: String,
    pub target: String,
    pub scope_hint: PortHint,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PortHint {
    pub port: u16,
}

impl NetworkPrompt {
    pub fn new(scope: &NetworkScope) -> Result<Self> {
        Ok(Self {
            required: true,
            approval_type: "network_egress",
            key: scope.approval_key()?,
            target: scope.destination(),
            scope_hint: PortHint {
                port: scope.port.unwrap(),
            },
        })
    }
}

#[derive(Debug, Serialize)]
pub struct AllowedHost {
    status: &'static str,
    pub host: String,
    pub rate: Option<u64>,
    pub agent: Option<String>,
    pub port: Option<u16>,
    pub global_budget: Option<u64>,
    rate_source: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DeniedHost {
    status: &'static str,
    pub host: String,
    pub expires: Option<String>,
    pub agent: Option<String>,
    pub port: Option<u16>,
}

/// Existing network approve operation. The caller supplies the current policy
/// activation operation; returning an error restores and reactivates old text.
pub fn allow_host(
    path: &Path,
    scope: &NetworkScope,
    rate: Option<u64>,
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<AllowedHost> {
    validate_scope(scope)?;
    let global = update_policy(
        path,
        false,
        |document, _| {
            let global = validate_rate(document, rate)?;
            let mut fields = InlineTable::new();
            fields.insert("egress", Value::from("allow"));
            if let Some(rate) = rate {
                fields.insert(
                    "rate",
                    Value::from(
                        i64::try_from(rate)
                            .map_err(|_| invalid("rate exceeds TOML integer range"))?,
                    ),
                );
            }
            replace_host(document, scope, fields)?;
            Ok(global)
        },
        activate,
    )?;
    Ok(AllowedHost {
        status: "added",
        host: scope.host.clone(),
        rate,
        agent: scope.agent.clone(),
        port: scope.port,
        global_budget: global,
        rate_source: if rate.is_some() { "host" } else { "global" },
    })
}

pub fn deny_host(
    path: &Path,
    scope: &NetworkScope,
    expires: Option<&str>,
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<DeniedHost> {
    validate_scope(scope)?;
    let expiry = expires
        .filter(|value| !value.is_empty())
        .map(|value| {
            let parsed = parse_expiry(value)
                .ok_or_else(|| invalid("expires must be an ISO datetime string"))?;
            let mut rendered = parsed
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| invalid(error.to_string()))?;
            if !expiry_has_offset(value) {
                rendered.truncate(rendered.len() - 1); // Preserve naive datetime storage.
            }
            rendered
                .parse::<toml_edit::Datetime>()
                .map(Value::from)
                .map_err(|error| invalid(error.to_string()))
        })
        .transpose()?;
    update_policy(
        path,
        false,
        |document, _| {
            let mut fields = InlineTable::new();
            fields.insert("egress", Value::from("deny"));
            if let Some(expiry) = expiry {
                fields.insert("expires", expiry);
            }
            replace_host(document, scope, fields)
        },
        activate,
    )?;
    Ok(DeniedHost {
        status: "denied",
        host: scope.host.clone(),
        expires: expires.map(str::to_owned),
        agent: scope.agent.clone(),
        port: scope.port,
    })
}

/// Add a credential identifier to one durable host entry while preserving its
/// existing egress, rate and bypass fields. Credential identifiers are policy
/// references; this operation never receives or stores secret material.
pub fn allow_credential(
    path: &Path,
    destination: &str,
    credential: &str,
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<usize> {
    allow_credentials(path, destination, &[credential.to_owned()], activate)
}

/// Add several credential identifiers to one durable host entry while
/// preserving existing egress, rate and bypass fields. The caller owns the
/// activation boundary and this function retains no secret material.
pub fn allow_credentials(
    path: &Path,
    destination: &str,
    credentials: &[String],
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<usize> {
    let scope = NetworkScope::new(destination, None, None)?;
    if credentials.is_empty() || credentials.iter().any(String::is_empty) {
        return Err(invalid("credential identifier must be non-empty"));
    }
    update_policy(
        path,
        false,
        |document, _| {
            let hosts = hosts_table(document, &scope)?;
            let item = hosts
                .entry(&scope.destination())
                .or_insert(Item::Value(Value::InlineTable(InlineTable::new())));
            let table = item
                .as_table_like_mut()
                .ok_or_else(|| invalid("host entry must be a table"))?;
            let allow = match table.get_mut("allow") {
                Some(item) => item
                    .as_value_mut()
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| invalid("host allow must be an array"))?,
                None => {
                    table.insert("allow", Item::Value(Value::Array(toml_edit::Array::new())));
                    table
                        .get_mut("allow")
                        .and_then(Item::as_value_mut)
                        .and_then(Value::as_array_mut)
                        .ok_or_else(|| invalid("host allow must be an array"))?
                }
            };
            for credential in credentials {
                if !allow.iter().any(|value| value.as_str() == Some(credential)) {
                    allow.push(credential);
                }
            }
            Ok(allow.len())
        },
        activate,
    )
}

/// Update only a host's rate field, retaining all other operator policy data.
pub fn update_host_rate(
    path: &Path,
    scope: &NetworkScope,
    rate: u64,
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<Option<u64>> {
    validate_scope(scope)?;
    if rate == 0 {
        return Err(invalid("rate must be a positive integer"));
    }
    update_policy(
        path,
        false,
        |document, _| {
            validate_rate(document, Some(rate))?;
            let hosts = hosts_table(document, scope)?;
            let item = hosts
                .entry(&scope.destination())
                .or_insert(Item::Value(Value::InlineTable(InlineTable::new())));
            let table = item
                .as_table_like_mut()
                .ok_or_else(|| invalid("host entry must be a table"))?;
            let old = table
                .get("rate")
                .and_then(Item::as_integer)
                .and_then(|value| u64::try_from(value).ok());
            table.insert(
                "rate",
                Item::Value(Value::from(
                    i64::try_from(rate).map_err(|_| invalid("rate exceeds TOML range"))?,
                )),
            );
            Ok(old)
        },
        activate,
    )
}

/// Add an addon bypass to one host while retaining its other fields.
pub fn add_host_bypass(
    path: &Path,
    scope: &NetworkScope,
    addon: &str,
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<Vec<String>> {
    validate_scope(scope)?;
    if addon.is_empty() {
        return Err(invalid("addon must be non-empty"));
    }
    update_policy(
        path,
        false,
        |document, _| {
            let hosts = hosts_table(document, scope)?;
            let item = hosts
                .entry(&scope.destination())
                .or_insert(Item::Value(Value::InlineTable(InlineTable::new())));
            let table = item
                .as_table_like_mut()
                .ok_or_else(|| invalid("host entry must be a table"))?;
            let bypass = match table.get_mut("bypass") {
                Some(item) => item
                    .as_value_mut()
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| invalid("host bypass must be an array"))?,
                None => {
                    table.insert("bypass", Item::Value(Value::Array(toml_edit::Array::new())));
                    table
                        .get_mut("bypass")
                        .and_then(Item::as_value_mut)
                        .and_then(Value::as_array_mut)
                        .ok_or_else(|| invalid("host bypass must be an array"))?
                }
            };
            if !bypass.iter().any(|value| value.as_str() == Some(addon)) {
                bypass.push(addon);
            }
            Ok(bypass
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect())
        },
        activate,
    )
}

/// Removes expired entries durably at an explicit load/reload boundary. The
/// native expiry fix covers agent hosts as well as top-level hosts.
pub fn prune_expired(
    path: &Path,
    now_ms: f64,
    activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<usize> {
    update_policy(
        path,
        true,
        |document, context| {
            let value =
                crate::policy::parse_toml_document_with_context(&document.to_string(), context)
                    .map_err(|error| invalid(error.to_string()))?;
            let expired =
                expired_host_entries(&value, now_ms).map_err(|error| invalid(error.to_string()))?;
            for (agent, host) in &expired {
                let scope = NetworkScope {
                    host: host.clone(),
                    agent: agent.clone(),
                    port: None,
                };
                hosts_table(document, &scope)?.remove(host);
            }
            Ok(expired.len())
        },
        activate,
    )
}

fn validate_scope(scope: &NetworkScope) -> Result<()> {
    let normalized = NetworkScope::new(&scope.host, scope.agent.as_deref(), scope.port)?;
    if normalized != *scope {
        return Err(invalid(
            "use NetworkScope::new to normalize the destination",
        ));
    }
    Ok(())
}

fn validate_rate(document: &DocumentMut, rate: Option<u64>) -> Result<Option<u64>> {
    if rate == Some(0) {
        return Err(invalid("rate must be a positive integer"));
    }
    let positive = |item: &Item| {
        item.as_integer()
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid("global network budget must be a positive integer"))
    };
    // Match both the engine's precheck and its latest-locked-document check.
    let current = document
        .get("budget")
        .or_else(|| document.get("global_budget"))
        .or_else(|| {
            document
                .get("budgets")
                .and_then(|item| item.get("network:request"))
        })
        .map(positive)
        .transpose()?;
    if let (Some(rate), Some(global)) = (rate, current)
        && rate > global
    {
        return Err(invalid(format!(
            "rate {rate} exceeds global budget {global}"
        )));
    }
    let locked_global = document.get("budget").map(positive).transpose()?;
    if rate.is_none() && locked_global.is_none() {
        return Err(invalid(
            "no global network budget is configured; pass rate or configure budget",
        ));
    }
    Ok(locked_global)
}

fn hosts_table<'a>(
    document: &'a mut DocumentMut,
    scope: &NetworkScope,
) -> Result<&'a mut dyn TableLike> {
    let mut table: &mut dyn TableLike = document.as_table_mut();
    if let Some(agent) = scope.agent.as_deref().filter(|agent| !agent.is_empty()) {
        for key in ["agents", agent] {
            if !table.contains_key(key) {
                table.insert(key, Item::Table(Table::new()));
            }
            table = table
                .get_mut(key)
                .and_then(Item::as_table_like_mut)
                .ok_or_else(|| invalid("agent policy must be a table"))?;
        }
    }
    if !table.contains_key("hosts") {
        table.insert("hosts", Item::Table(Table::new()));
    }
    table
        .get_mut("hosts")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| invalid("hosts must be a table"))
}

fn replace_host(
    document: &mut DocumentMut,
    scope: &NetworkScope,
    mut fields: InlineTable,
) -> Result<()> {
    fields.fmt();
    hosts_table(document, scope)?.insert(
        &scope.destination(),
        Item::Value(Value::InlineTable(fields)),
    );
    Ok(())
}

struct TemporaryPolicy(PathBuf);
impl Drop for TemporaryPolicy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(crate) struct SaveError {
    pub(crate) error: std::io::Error,
    committed: bool,
}

pub(crate) fn save_policy(path: &Path, source: &str) -> std::result::Result<(), SaveError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary =
        TemporaryPolicy(parent.join(format!(".policy-{}.toml", uuid::Uuid::new_v4().simple())));
    let mut committed = false;
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary.0)?;
        file.write_all(source.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary.0, path)?;
        committed = true;
        File::open(parent)?.sync_all()
    })();
    result.map_err(|error| SaveError { error, committed })
}

pub(crate) fn update_policy<T>(
    path: &Path,
    skip_unchanged: bool,
    mutate: impl FnOnce(&mut DocumentMut, &mut LargeIntegerContext) -> Result<T>,
    mut activate: impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<T> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
        return Err(ApprovalError {
            kind: ErrorKind::Unsupported,
            message: "native durable network approvals currently require policy.toml".into(),
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(parent.join(".policy.toml.lock"))?;
    lock.lock()?;
    let original = std::fs::read_to_string(path)?;
    let (mut document, mut context) = crate::policy::parse_toml_for_edit(&original)
        .map_err(|error| invalid(error.to_string()))?;
    let result = mutate(&mut document, &mut context)?;
    let changed = restore_large_toml_integers(&document.to_string(), &context);
    if skip_unchanged && changed == original {
        return Ok(result);
    }
    if let Err(error) = save_policy(path, &changed) {
        if error.committed {
            restore_policy(path, &original, &mut activate)?;
        }
        return Err(error.error.into());
    }
    if let Err(error) = activate(&changed) {
        restore_policy(path, &original, &mut activate)?;
        return Err(ApprovalError {
            kind: ErrorKind::Activation,
            message: format!("policy activation failed: {error}"),
        });
    }
    // Dropping this exact descriptor releases the process-compatible flock.
    drop(lock);
    Ok(result)
}

fn restore_policy(
    path: &Path,
    original: &str,
    activate: &mut impl FnMut(&str) -> std::result::Result<(), String>,
) -> Result<()> {
    save_policy(path, original).map_err(|error| ApprovalError {
        kind: ErrorKind::Rollback,
        message: format!("failed to restore original policy: {}", error.error),
    })?;
    activate(original).map_err(|error| ApprovalError {
        kind: ErrorKind::Rollback,
        message: format!("failed to reactivate restored policy: {error}"),
    })
}

/// Existing one-day operator denial convenience; callers can supply their own
/// explicit expiry through deny_host without a newly imposed lifetime limit.
pub fn operator_denial_expiry(now: time::OffsetDateTime) -> Result<String> {
    (now + time::Duration::days(1))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| invalid(error.to_string()))
}
