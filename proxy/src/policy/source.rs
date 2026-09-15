//! Parser-owned temporal provenance for one policy load.
//!
//! The JSON-shaped working document is not authoritative about timestamp types
//! or temporal mapping keys. These records preserve that information through
//! source transformations without encoding a forgeable object marker.

use std::hash::{Hash, Hasher};

use serde_json::{Map, Value};
use time::OffsetDateTime;
use zeroize::Zeroize;

use super::{Result, invalid, parse_expiry};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TemporalKind {
    Date,
    NaiveDateTime,
    AwareDateTime,
    Time,
}

#[derive(Clone)]
pub(crate) struct TemporalValue {
    kind: TemporalKind,
    value: OffsetDateTime,
}

impl TemporalValue {
    pub(super) fn from_toml(value: &toml_edit::Datetime) -> Result<Self> {
        let text = value.to_string();
        let (kind, parse_text) = if value.date.is_some() && value.time.is_none() {
            (TemporalKind::Date, text)
        } else if value.date.is_none() {
            (TemporalKind::Time, format!("2000-01-01T{text}"))
        } else if value.offset.is_some() {
            (TemporalKind::AwareDateTime, text)
        } else {
            (TemporalKind::NaiveDateTime, text)
        };
        Ok(Self {
            kind,
            value: parse_expiry(&parse_text)
                .ok_or_else(|| invalid("invalid TOML temporal scalar"))?,
        })
    }
    pub(super) fn from_yaml(value: &Value) -> Result<Self> {
        if let Some(date) = value.get("yaml_date").and_then(Value::as_str) {
            return Ok(Self {
                kind: TemporalKind::Date,
                value: parse_expiry(date).ok_or_else(|| invalid("invalid YAML date"))?,
            });
        }
        let text = value
            .as_str()
            .ok_or_else(|| invalid("invalid resolved YAML timestamp"))?;
        Ok(Self {
            kind: if super::expiry_has_offset(text) {
                TemporalKind::AwareDateTime
            } else {
                TemporalKind::NaiveDateTime
            },
            value: parse_expiry(text).ok_or_else(|| invalid("invalid YAML datetime"))?,
        })
    }

    pub(crate) fn python_display(&self) -> String {
        let value = self.value;
        let date = format!(
            "{:04}-{:02}-{:02}",
            value.year(),
            u8::from(value.month()),
            value.day()
        );
        if self.kind == TemporalKind::Date {
            return date;
        }
        let mut clock = format!(
            "{:02}:{:02}:{:02}",
            value.hour(),
            value.minute(),
            value.second()
        );
        if value.microsecond() != 0 {
            clock.push_str(&format!(".{:06}", value.microsecond()));
        }
        if self.kind == TemporalKind::AwareDateTime {
            let seconds = value.offset().whole_seconds();
            clock.push_str(&format!(
                "{}{:02}:{:02}",
                if seconds < 0 { '-' } else { '+' },
                seconds.abs() / 3600,
                seconds.abs() / 60 % 60
            ));
        }
        if self.kind == TemporalKind::Time {
            clock
        } else {
            format!("{date} {clock}")
        }
    }

    /// Pydantic model JSON differs from Python str(datetime): the separator is
    /// T and a zero UTC offset is Z. Emit only this scalar into the caller's
    /// sink; do not create another canonical value or alter ordinary API JSON.
    pub(super) fn write_model_json(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        let value = self.value;
        writer.write_all(b"\"")?;
        if self.kind != TemporalKind::Time {
            write!(
                writer,
                "{:04}-{:02}-{:02}",
                value.year(),
                u8::from(value.month()),
                value.day()
            )?;
        }
        if self.kind != TemporalKind::Date {
            if self.kind != TemporalKind::Time {
                writer.write_all(b"T")?;
            }
            write!(
                writer,
                "{:02}:{:02}:{:02}",
                value.hour(),
                value.minute(),
                value.second()
            )?;
            if value.microsecond() != 0 {
                write!(writer, ".{:06}", value.microsecond())?;
            }
        }
        if self.kind == TemporalKind::AwareDateTime {
            let seconds = value.offset().whole_seconds();
            if seconds == 0 {
                writer.write_all(b"Z")?;
            } else {
                write!(
                    writer,
                    "{}{:02}:{:02}",
                    if seconds < 0 { '-' } else { '+' },
                    seconds.abs() / 3600,
                    seconds.abs() / 60 % 60
                )?;
            }
        }
        writer.write_all(b"\"")
    }

    fn identity(&self) -> (TemporalKind, i128) {
        (self.kind, self.value.unix_timestamp_nanos())
    }
}

impl PartialEq for TemporalValue {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for TemporalValue {}

impl Hash for TemporalValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity().hash(state);
    }
}

#[derive(Clone)]
pub(super) struct TemporalEntry {
    pub(super) path: Vec<String>,
    pub(super) key: bool,
    pub(super) value: TemporalValue,
}

impl Drop for TemporalEntry {
    fn drop(&mut self) {
        for part in &mut self.path {
            part.zeroize();
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct TimestampPaths {
    pub(super) entries: Vec<TemporalEntry>,
}

impl TimestampPaths {
    pub(crate) fn value_at(&self, path: &[&str]) -> Option<&TemporalValue> {
        self.entries
            .iter()
            .find(|entry| !entry.key && path_eq(&entry.path, path))
            .map(|entry| &entry.value)
    }

    pub(crate) fn key_at(&self, path: &[&str]) -> Option<&TemporalValue> {
        self.entries
            .iter()
            .find(|entry| entry.key && path_eq(&entry.path, path))
            .map(|entry| &entry.value)
    }

    pub(crate) fn has_under(&self, path: &[&str]) -> bool {
        self.entries.iter().any(|entry| below_value(entry, path))
    }

    pub(crate) fn projected(&self, path: &[&str]) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|entry| below_value(entry, path))
                .map(|entry| TemporalEntry {
                    path: entry.path[path.len()..].to_vec(),
                    key: entry.key,
                    value: entry.value.clone(),
                })
                .collect(),
        }
    }

    pub(crate) fn copy_under(&self, source: &[&str], target: &[&str]) -> Self {
        let mut output = self.projected(source);
        output.prepend(target);
        output
    }

    pub(crate) fn copy_key_as_value(&self, source: &[&str], target: &[&str]) -> Self {
        let mut output = Self::default();
        if let Some(value) = self.key_at(source) {
            output.insert_value(target, value.clone());
        }
        output
    }

    pub(crate) fn insert_value(&mut self, path: &[&str], value: TemporalValue) {
        self.entries.push(TemporalEntry {
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            key: false,
            value,
        });
    }

    pub(crate) fn insert_key(&mut self, path: &[&str], value: TemporalValue) {
        self.entries.push(TemporalEntry {
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            key: true,
            value,
        });
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    pub(crate) fn remove_under(&mut self, path: &[&str]) {
        self.entries.retain(|entry| !starts_with(&entry.path, path));
    }

    pub(super) fn move_under(&mut self, source: &[&str], target: &[&str]) {
        let moved = self.copy_under(source, target);
        self.remove_under(target);
        self.remove_under(source);
        self.extend(moved);
    }

    pub(super) fn prepend(&mut self, prefix: &[&str]) {
        for entry in &mut self.entries {
            entry
                .path
                .splice(0..0, prefix.iter().map(|part| (*part).to_owned()));
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn retain_document(&mut self, document: &Map<String, Value>) {
        self.entries.retain(|entry| {
            let Some(first) = entry.path.first() else {
                return true;
            };
            let Some(mut value) = document.get(first) else {
                return false;
            };
            for part in &entry.path[1..] {
                value = match value {
                    Value::Object(object) => match object.get(part) {
                        Some(value) => value,
                        None => return false,
                    },
                    Value::Array(array) => {
                        match part.parse::<usize>().ok().and_then(|i| array.get(i)) {
                            Some(value) => value,
                            None => return false,
                        }
                    }
                    _ => return false,
                };
            }
            true
        });
    }
}

fn starts_with(path: &[String], prefix: &[&str]) -> bool {
    path.len() >= prefix.len() && path.iter().zip(prefix).all(|(a, b)| a == b)
}

fn path_eq(path: &[String], other: &[&str]) -> bool {
    path.len() == other.len() && starts_with(path, other)
}

fn below_value(entry: &TemporalEntry, prefix: &[&str]) -> bool {
    starts_with(&entry.path, prefix) && (!entry.key || entry.path.len() > prefix.len())
}

pub(super) struct ParsedPolicy {
    pub(super) document: Map<String, Value>,
    pub(super) timestamps: TimestampPaths,
}

impl ParsedPolicy {
    pub(super) fn into_parts(mut self) -> (Map<String, Value>, TimestampPaths) {
        (
            std::mem::take(&mut self.document),
            std::mem::take(&mut self.timestamps),
        )
    }
}

impl Drop for ParsedPolicy {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut Value::Object(std::mem::take(&mut self.document)));
    }
}

#[derive(Clone, Copy)]
enum Disposition {
    Drop,
    Retain,
    Reject,
}

const METADATA: &[&str] = &[
    "version",
    "task_id",
    "description",
    "created",
    "approved",
    "brief_hash",
    "policy_hash",
];
const CONDITIONS: &[&str] = &[
    "credential",
    "method",
    "port",
    "path_prefix",
    "content_type",
    "tactics",
    "enables",
    "irreversible",
    "account",
    "agent",
    "service",
    "capability",
];
const CREDENTIAL: &[&str] = &[
    "name",
    "patterns",
    "allowed_hosts",
    "header_names",
    "suggested_url",
];
const SCAN: &[&str] = &[
    "name",
    "pattern",
    "target",
    "scope",
    "action",
    "severity",
    "message",
    "case_sensitive",
];

fn model_field(path: &[String], key: bool, fields: &[&str]) -> Disposition {
    if path.is_empty() || (!key || path.len() > 1) && fields.contains(&path[0].as_str()) {
        Disposition::Reject
    } else {
        Disposition::Drop
    }
}

fn model_array(path: &[String], key: bool, fields: &[&str]) -> Disposition {
    if path.is_empty() {
        Disposition::Reject
    } else {
        model_field(&path[1..], key, fields)
    }
}

fn addon(path: &[String], key: bool) -> Disposition {
    if path.len() <= 1 || key && path.len() == 2 {
        return Disposition::Reject;
    }
    match path[1].as_str() {
        "enabled" => Disposition::Reject,
        "settings" if path.len() == 2 || key && path.len() == 3 => Disposition::Reject,
        _ => Disposition::Retain,
    }
}

fn overrides(path: &[String], key: bool) -> Disposition {
    if path.len() <= 1 {
        return Disposition::Reject;
    }
    if key && path.len() == 2 {
        return Disposition::Drop;
    }
    match path[1].as_str() {
        "bypass" => Disposition::Reject,
        "addons" => addon(&path[2..], key),
        _ => Disposition::Drop,
    }
}

/// Classify only fields preserved by the existing canonical schema builder.
/// Host-generated permissions and overrides pass through their existing emitter.
pub(super) fn baseline_timestamps(
    timestamps: &TimestampPaths,
    host_centric: bool,
    source: &Map<String, Value>,
) -> Result<TimestampPaths> {
    let mut retained = TimestampPaths::default();
    for entry in &timestamps.entries {
        if entry.path.is_empty() {
            return Err(invalid("policy document must be a mapping"));
        }
        if entry.key && entry.path.len() == 1 {
            continue; // Unknown top-level model keys are dropped by Pydantic.
        }
        let path = &entry.path[1..];
        let disposition = match entry.path[0].as_str() {
            "metadata" => model_field(path, entry.key, METADATA),
            "required" | "budgets" | "simple_permissions" => {
                if host_centric
                    && (entry.path[0] == "simple_permissions"
                        || entry.path[0] == "budgets" && source.contains_key("global_budget"))
                {
                    Disposition::Drop
                } else {
                    Disposition::Reject
                }
            }
            "global_budget" if host_centric => Disposition::Reject,
            "credential_rules" if host_centric && source.contains_key("credentials") => {
                Disposition::Drop
            }
            "credential_rules" => model_array(path, entry.key, CREDENTIAL),
            "scan_patterns" => model_array(path, entry.key, SCAN),
            "addons" => addon(path, entry.key),
            "domains" => Disposition::Retain,
            "clients" => overrides(path, entry.key),
            // The gateway compiler alone selects its retained source fields.
            "gateway" if !host_centric => {
                if path.is_empty() {
                    Disposition::Reject
                } else {
                    Disposition::Retain
                }
            }
            _ => Disposition::Drop,
        };
        match disposition {
            Disposition::Drop => {}
            Disposition::Retain => retained.entries.push(entry.clone()),
            Disposition::Reject => {
                return Err(invalid(
                    "typed timestamp is invalid in a declared policy field",
                ));
            }
        }
    }
    Ok(retained)
}

pub(super) fn finish_domain_timestamps(timestamps: &mut TimestampPaths) -> Result<()> {
    let mut rejected = false;
    timestamps.entries.retain(|entry| {
        if entry.path.first().is_none_or(|part| part != "domains") {
            return true;
        }
        match overrides(&entry.path[1..], entry.key) {
            Disposition::Retain => true,
            Disposition::Drop => false,
            Disposition::Reject => {
                rejected = true;
                false
            }
        }
    });
    if rejected {
        return Err(invalid(
            "typed timestamp is invalid in a declared domain field",
        ));
    }
    Ok(())
}

pub(super) fn validate_permission_timestamps(
    timestamps: &TimestampPaths,
    extracted: bool,
) -> Result<()> {
    if extracted {
        return Ok(());
    }
    for entry in &timestamps.entries {
        let path = &entry.path;
        let disposition = if path.is_empty() {
            Disposition::Reject
        } else if entry.key && path.len() == 1 {
            Disposition::Drop
        } else if path[0] == "condition" {
            model_field(&path[1..], entry.key, CONDITIONS)
        } else {
            model_field(
                path,
                entry.key,
                &["action", "resource", "effect", "budget", "tier"],
            )
        };
        if matches!(disposition, Disposition::Reject) {
            return Err(invalid(
                "typed timestamp is invalid in a declared permission field",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_host_timestamps(timestamps: &TimestampPaths, wildcard: bool) -> Result<()> {
    for entry in &timestamps.entries {
        let path = &entry.path;
        if path.is_empty() {
            return Err(invalid("host configuration must be a mapping"));
        }
        if entry.key && path.len() == 1 {
            continue;
        }
        let disposition = match path[0].as_str() {
            "rate_limit" => Disposition::Reject,
            "bypass" if !wildcard => Disposition::Reject,
            "credentials" if !wildcard => Disposition::Reject,
            "addons" if !wildcard => addon(&path[1..], entry.key),
            _ => Disposition::Drop,
        };
        if matches!(disposition, Disposition::Reject) {
            return Err(invalid(
                "typed timestamp is invalid in a declared host field",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_credential_source(timestamps: &TimestampPaths) -> Result<()> {
    for entry in &timestamps.entries {
        if entry.path.len() <= 1 || entry.key && entry.path.len() == 1 {
            return Err(invalid(
                "credential declarations need string names and mappings",
            ));
        }
        if entry.key && entry.path.len() == 2 {
            continue;
        }
        if matches!(
            entry.path[1].as_str(),
            "patterns" | "headers" | "allowed_hosts" | "suggested_url"
        ) {
            return Err(invalid(
                "credential declarations must not contain typed timestamps",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_risk_timestamps(timestamps: &TimestampPaths) -> Result<()> {
    for entry in &timestamps.entries {
        if entry.path.len() <= 1 {
            return Err(invalid("risk rules must be mappings"));
        }
        if entry.key && entry.path.len() == 2 {
            continue;
        }
        if matches!(
            entry.path[1].as_str(),
            "decision" | "tactics" | "enables" | "irreversible" | "account" | "agent" | "service"
        ) {
            return Err(invalid("typed timestamp is invalid in a risk rule"));
        }
    }
    Ok(())
}
