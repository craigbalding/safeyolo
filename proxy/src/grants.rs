//! Service-risk grants and contract-binding persistence. One Store (or its clones)
//! owns the active gateway state. Once reservations are process-local and must be
//! shared by all requests; they are not additional durable approvals.
//!
//! Unlike the Python gateway, pending once requests reserve their grant and
//! persisted-state reload removes externally revoked grants and bindings. Live
//! sessions survive reload. No transport, HTTP authentication, or secret access is
//! activated here; callers supply trusted agent identity and activation callbacks.
//!
//! Binding persistence keeps authored integers beyond TOML's native i64 syntax
//! lossless through the shared policy adapter. The on-disk representation stays
//! an integer literal, while edits use a private in-memory marker only while
//! toml_edit holds the document.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::{
    approvals::{ApprovalError, ErrorKind, update_policy},
    contracts::ContractBinding,
    policy::{large_integer_marker_value, parse_expiry, parse_toml_document},
    services::resource_matches,
};

type Result<T> = std::result::Result<T, ApprovalError>;
fn invalid(message: impl Into<String>) -> ApprovalError {
    ApprovalError {
        kind: ErrorKind::Invalid,
        message: message.into(),
    }
}
fn timestamp(now: OffsetDateTime) -> Result<String> {
    now.format(&Rfc3339)
        .map_err(|error| invalid(error.to_string()))
}
fn identifier(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..24]
    )
}
fn nonempty(values: &[&str]) -> Result<()> {
    if values.contains(&"") {
        Err(invalid("agent, service and request scope must be nonempty"))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantScope {
    Once,
    Session,
    Remembered,
}
impl GrantScope {
    /// The admin API treats integer lifetimes as a session alias, not a TTL.
    pub fn from_admin_lifetime(value: &Json) -> Result<Self> {
        if value.is_boolean()
            || value
                .as_number()
                .is_some_and(|number| !number.to_string().contains(['.', 'e', 'E']))
        {
            return Ok(Self::Session);
        }
        match value.as_str() {
            Some("once") => Ok(Self::Once),
            Some("session") => Ok(Self::Session),
            Some("remembered") => Ok(Self::Remembered),
            _ => Err(invalid("lifetime must be once, session, or remembered")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    pub agent: String,
    pub service: String,
    pub method: String,
    pub path: String,
    pub scope: GrantScope,
    pub created: String,
    pub expires: String,
}
impl Grant {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        parse_expiry(&self.expires).is_none_or(|expires| now >= expires)
    }
    pub fn matches(&self, scope: RequestScope<'_>, now: OffsetDateTime) -> bool {
        !self.is_expired(now)
            && self.agent == scope.agent
            && self.service == scope.service
            && self.method.eq_ignore_ascii_case(scope.method)
            && resource_matches(scope.path, &self.path)
    }
}
#[derive(Debug, Clone, Copy)]
pub struct RequestScope<'a> {
    pub agent: &'a str,
    pub service: &'a str,
    pub method: &'a str,
    pub path: &'a str,
}
#[derive(Debug, Clone)]
pub struct GrantRequest {
    pub agent: String,
    pub service: String,
    pub method: String,
    pub path: String,
    pub scope: GrantScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Persistence {
    Durable,
    SessionOnly,
    AgentNotConfigured,
}
#[derive(Debug, Clone, Serialize)]
pub struct GrantAddition {
    pub grant: Grant,
    pub persistence: Persistence,
}
#[derive(Debug, Clone, Serialize)]
pub struct StoredBinding {
    #[serde(flatten)]
    pub binding: ContractBinding,
    pub created: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct BindingAddition {
    pub binding: StoredBinding,
    pub persistence: Persistence,
}
#[derive(Debug, Clone, Serialize)]
pub struct ListedGrant {
    #[serde(flatten)]
    pub grant: Grant,
    pub expired: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOutcome {
    Consumed,
    Retained,
    Stale,
}

#[derive(Debug, Clone, Default)]
struct Snapshot {
    grants: Vec<Grant>,
    bindings: Vec<StoredBinding>,
    ephemeral_grants: BTreeSet<String>,
    ephemeral_bindings: BTreeSet<String>,
    reservations: BTreeMap<String, String>,
    ttl_seconds: i64,
    load_problems: Vec<String>,
}
impl Snapshot {
    fn from_document(
        document: &DocumentMut,
        now: OffsetDateTime,
        previous: Option<&Self>,
    ) -> Result<Self> {
        let json = parse_toml_document(&document.to_string())
            .map_err(|error| invalid(error.to_string()))?;
        let mut candidate = Self {
            ttl_seconds: previous.map_or(3600, |old| old.ttl_seconds),
            ..Self::default()
        };
        if let Some(ttl) = json.pointer("/gateway/grant_ttl_seconds") {
            let number = match ttl {
                Json::Bool(value) => Some(if *value { 1. } else { 0. }),
                _ => ttl.as_f64(),
            };
            if let Some(ttl) = number.filter(|ttl| *ttl > 0.) {
                if !ttl.is_finite() || ttl >= i64::MAX as f64 {
                    return Err(invalid("grant TTL exceeds supported duration"));
                }
                candidate.ttl_seconds = ttl as i64;
            }
        }
        if let Some(agents) = json.get("agents") {
            for (agent, data) in agents
                .as_object()
                .ok_or_else(|| invalid("agents must be a table"))?
            {
                let data = data
                    .as_object()
                    .ok_or_else(|| invalid("agent must be a table"))?;
                for raw in records(data.get("grants"))? {
                    match load_grant(agent, raw, now) {
                        Ok(grant)
                            if grant.scope != GrantScope::Session
                                && (!grant.is_expired(now)
                                    || previous.is_some_and(|old| {
                                        old.reservations.contains_key(&grant.grant_id)
                                            && old.grants.iter().any(|existing| existing == &grant)
                                    })) =>
                        {
                            replace_grant(&mut candidate.grants, grant)
                        }
                        Ok(_) => {}
                        Err(error) => candidate
                            .load_problems
                            .push(format!("grant for {agent}: {error}")),
                    }
                }
                for raw in records(data.get("contract_bindings"))? {
                    // Unlike the old accumulating loader, reject an invalid candidate
                    // atomically rather than publishing earlier records from it.
                    let binding = load_binding(agent, raw, now)?;
                    replace_binding(&mut candidate.bindings, binding);
                }
            }
        }
        if let Some(previous) = previous {
            for grant in &previous.grants {
                if previous.ephemeral_grants.contains(&grant.grant_id) && !grant.is_expired(now) {
                    replace_grant(&mut candidate.grants, grant.clone());
                    candidate.ephemeral_grants.insert(grant.grant_id.clone());
                }
            }
            for binding in &previous.bindings {
                if previous
                    .ephemeral_bindings
                    .contains(&binding.binding.binding_id)
                {
                    replace_binding(&mut candidate.bindings, binding.clone());
                    candidate
                        .ephemeral_bindings
                        .insert(binding.binding.binding_id.clone());
                }
            }
            for (grant_id, reservation) in &previous.reservations {
                if let (Some(old), Some(new)) = (
                    previous
                        .grants
                        .iter()
                        .find(|grant| &grant.grant_id == grant_id),
                    candidate
                        .grants
                        .iter()
                        .find(|grant| &grant.grant_id == grant_id),
                ) && old == new
                {
                    candidate
                        .reservations
                        .insert(grant_id.clone(), reservation.clone());
                }
            }
        }
        Ok(candidate)
    }
}
fn records(value: Option<&Json>) -> Result<&[Json]> {
    match value {
        None => Ok(&[]),
        Some(Json::Array(values)) => Ok(values),
        _ => Err(invalid("grants and contract_bindings must be arrays")),
    }
}
fn load_grant(agent: &str, raw: &Json, now: OffsetDateTime) -> Result<Grant> {
    let mut raw = raw
        .as_object()
        .ok_or_else(|| invalid("grant must be an object"))?
        .clone();
    raw.insert("agent".into(), agent.into());
    raw.entry("grant_id")
        .or_insert_with(|| identifier("grt").into());
    raw.entry("scope").or_insert("once".into());
    raw.entry("created").or_insert(timestamp(now)?.into());
    if raw.get("expires").is_none_or(|value| value == "") {
        let created = raw
            .get("created")
            .and_then(Json::as_str)
            .and_then(parse_expiry)
            .ok_or_else(|| invalid("invalid grant creation time"))?;
        let expiry = created
            .checked_add(Duration::hours(1))
            .ok_or_else(|| invalid("grant expiry overflow"))?;
        raw.insert("expires".into(), timestamp(expiry)?.into());
    }
    serde_json::from_value(Json::Object(raw)).map_err(|error| invalid(error.to_string()))
}
fn load_binding(agent: &str, raw: &Json, now: OffsetDateTime) -> Result<StoredBinding> {
    let mut raw = raw
        .as_object()
        .ok_or_else(|| invalid("binding must be an object"))?
        .clone();
    raw.insert("agent".into(), agent.into());
    raw.entry("binding_id")
        .or_insert_with(|| identifier("cbs").into());
    let created = raw
        .get("created")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("binding created must be a string"))
        })
        .transpose()?
        .unwrap_or(timestamp(now)?);
    let binding: ContractBinding =
        serde_json::from_value(Json::Object(raw)).map_err(|error| invalid(error.to_string()))?;
    nonempty(&[&binding.agent, &binding.service, &binding.capability])?;
    Ok(StoredBinding { binding, created })
}

/// Persist the defaults accepted by the old loader once, before a record can
/// become a live grant. Regenerating IDs or creation times on each reload would
/// invalidate an in-flight reservation and prevent durable consumption/revocation.
fn normalize_legacy_records(document: &mut DocumentMut, now: OffsetDateTime) -> Result<()> {
    let source =
        parse_toml_document(&document.to_string()).map_err(|error| invalid(error.to_string()))?;
    let Some(agents) = source.get("agents") else {
        return Ok(());
    };
    for (agent, data) in agents
        .as_object()
        .ok_or_else(|| invalid("agents must be a table"))?
    {
        for (collection, fields) in [
            ("grants", &["grant_id", "scope", "created", "expires"][..]),
            ("contract_bindings", &["binding_id", "created"][..]),
        ] {
            for (index, raw) in records(data.get(collection))?.iter().enumerate() {
                let defaults = if collection == "grants" {
                    let Ok(grant) = load_grant(agent, raw, now) else {
                        // Invalid grants remain reported/skipped by the snapshot
                        // loader; normalization must not turn them into approvals.
                        continue;
                    };
                    grant_record(&grant)?
                } else {
                    binding_record(&load_binding(agent, raw, now)?)?
                };
                let item = agent_table(document, agent)?
                    .and_then(|agent| agent.get_mut(collection))
                    .ok_or_else(|| invalid("record disappeared during normalization"))?;
                let record: &mut dyn TableLike = match item {
                    Item::ArrayOfTables(records) => records
                        .get_mut(index)
                        .ok_or_else(|| invalid("grant record disappeared"))?,
                    Item::Value(Value::Array(records)) => records
                        .get_mut(index)
                        .and_then(Value::as_inline_table_mut)
                        .ok_or_else(|| invalid("grant record must be an inline table"))?,
                    _ => return Err(invalid("grant/binding records must be an array of tables")),
                };
                for field in fields {
                    if !record.contains_key(field)
                        || (*field == "expires"
                            && record.get(field).and_then(Item::as_str) == Some(""))
                    {
                        record.insert(field, Item::Value(json_to_toml(&defaults[*field])?));
                    }
                }
            }
        }
    }
    Ok(())
}
fn replace_grant(grants: &mut Vec<Grant>, grant: Grant) {
    if let Some(existing) = grants
        .iter_mut()
        .find(|existing| existing.grant_id == grant.grant_id)
    {
        *existing = grant;
    } else {
        grants.push(grant);
    }
}
fn binding_key(binding: &ContractBinding) -> (&str, &str, &str) {
    (&binding.agent, &binding.service, &binding.capability)
}
fn replace_binding(bindings: &mut Vec<StoredBinding>, binding: StoredBinding) {
    if let Some(existing) = bindings
        .iter_mut()
        .find(|existing| binding_key(&existing.binding) == binding_key(&binding.binding))
    {
        *existing = binding;
    } else {
        bindings.push(binding);
    }
}

/// Clones share state and once reservations. Open one authoritative Store per
/// running gateway. Independent processes coordinate durable edits through flock;
/// they must not both act as live gateway grant consumers for the same policy.
#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    state: Arc<Mutex<Snapshot>>,
}
impl Store {
    /// Normalize accepted legacy metadata atomically under the policy lock before
    /// publishing a snapshot. The defaults do not change granted permissions.
    pub fn open(path: impl Into<PathBuf>, now: OffsetDateTime) -> Result<Self> {
        let path = path.into();
        let snapshot = update_policy(
            &path,
            true,
            |document| {
                normalize_legacy_records(document, now)?;
                Snapshot::from_document(document, now, None)
            },
            |_| Ok(()),
        )?;
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(snapshot)),
        })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Snapshot>> {
        self.state
            .lock()
            .map_err(|_| invalid("grant state lock poisoned"))
    }
    pub fn load_problems(&self) -> Result<Vec<String>> {
        Ok(self.lock()?.load_problems.clone())
    }
    pub fn list_grants_for_agent(
        &self,
        agent: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<ListedGrant>> {
        Ok(self
            .lock()?
            .grants
            .iter()
            .filter(|grant| grant.agent == agent)
            .map(|grant| ListedGrant {
                grant: grant.clone(),
                expired: grant.is_expired(now),
            })
            .collect())
    }
    pub fn list_grants(&self, now: OffsetDateTime) -> Result<Vec<ListedGrant>> {
        Ok(self
            .lock()?
            .grants
            .iter()
            .map(|grant| ListedGrant {
                grant: grant.clone(),
                expired: grant.is_expired(now),
            })
            .collect())
    }
    pub fn binding_for_agent(
        &self,
        agent: &str,
        service: &str,
        capability: &str,
    ) -> Result<Option<StoredBinding>> {
        Ok(self
            .lock()?
            .bindings
            .iter()
            .find(|record| binding_key(&record.binding) == (agent, service, capability))
            .cloned())
    }
    /// Activation callbacks must not re-enter this Store. Both memory publication
    /// and the shared policy transaction remain serialized until activation ends.
    fn transaction<T>(
        &self,
        now: OffsetDateTime,
        skip_unchanged: bool,
        mutate: impl FnOnce(&mut DocumentMut, &mut Snapshot) -> Result<T>,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<T> {
        let mut current = self.lock()?;
        let (result, next) = update_policy(
            &self.path,
            skip_unchanged,
            |document| {
                normalize_legacy_records(document, now)?;
                let mut next = Snapshot::from_document(document, now, Some(&current))?;
                let result = mutate(document, &mut next)?;
                Ok((result, next))
            },
            activate,
        )?;
        *current = next;
        Ok(result)
    }
    /// Replace persisted records, removing revocations made outside this process.
    /// Same-process sessions survive; restart always discards them.
    pub fn reload(
        &self,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<()> {
        // Normalization still writes legacy records when it changes the
        // document, while an unchanged reload leaves its inode and mtime
        // untouched. Runtime publication can therefore reconcile an external
        // edit without racing a service-catalog token publication.
        self.transaction(now, true, |_, _| Ok(()), activate)
    }
    pub fn add_grant(
        &self,
        request: GrantRequest,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<GrantAddition> {
        nonempty(&[
            &request.agent,
            &request.service,
            &request.method,
            &request.path,
        ])?;
        self.transaction(
            now,
            true,
            |document, state| {
                let expires = now
                    .checked_add(Duration::seconds(state.ttl_seconds))
                    .ok_or_else(|| invalid("grant expiry overflow"))?;
                let grant = Grant {
                    grant_id: identifier("grt"),
                    agent: request.agent,
                    service: request.service,
                    method: request.method,
                    path: request.path,
                    scope: request.scope,
                    created: timestamp(now)?,
                    expires: timestamp(expires)?,
                };
                let persistence = if grant.scope == GrantScope::Session {
                    Persistence::SessionOnly
                } else if upsert_record(
                    document,
                    &grant.agent,
                    "grants",
                    "grant_id",
                    &grant.grant_id,
                    grant_record(&grant)?,
                    None,
                )? {
                    Persistence::Durable
                } else {
                    Persistence::AgentNotConfigured
                };
                if persistence != Persistence::Durable {
                    state.ephemeral_grants.insert(grant.grant_id.clone());
                }
                replace_grant(&mut state.grants, grant.clone());
                Ok(GrantAddition { grant, persistence })
            },
            activate,
        )
    }
    pub fn approve_binding(
        &self,
        mut binding: ContractBinding,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<BindingAddition> {
        nonempty(&[&binding.agent, &binding.service, &binding.capability])?;
        if binding.bound_values.is_empty() {
            return Err(invalid("bindings must be a nonempty object"));
        }
        // Admin approval supplies values and operation names; the service compiler
        // remains responsible for template, declared-tier and resolution checks.
        binding.binding_id = identifier("cbs");
        let record = StoredBinding {
            binding,
            created: timestamp(now)?,
        };
        self.transaction(
            now,
            true,
            |document, state| {
                let binding = &record.binding;
                let persistence = if upsert_record(
                    document,
                    &binding.agent,
                    "contract_bindings",
                    "binding_id",
                    &binding.binding_id,
                    binding_record(&record)?,
                    Some((&binding.service, &binding.capability)),
                )? {
                    Persistence::Durable
                } else {
                    Persistence::AgentNotConfigured
                };
                for old in &state.bindings {
                    if binding_key(&old.binding) == binding_key(binding) {
                        state.ephemeral_bindings.remove(&old.binding.binding_id);
                    }
                }
                if persistence != Persistence::Durable {
                    state.ephemeral_bindings.insert(binding.binding_id.clone());
                }
                replace_binding(&mut state.bindings, record.clone());
                Ok(BindingAddition {
                    binding: record,
                    persistence,
                })
            },
            activate,
        )
    }
    pub fn revoke_grant(
        &self,
        agent: &str,
        grant_id: &str,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<bool> {
        self.transaction(
            now,
            true,
            |document, state| {
                let Some(index) = state
                    .grants
                    .iter()
                    .position(|grant| grant.agent == agent && grant.grant_id == grant_id)
                else {
                    return Ok(false);
                };
                remove_record(document, agent, "grants", "grant_id", grant_id)?;
                state.grants.remove(index);
                state.ephemeral_grants.remove(grant_id);
                state.reservations.remove(grant_id);
                Ok(true)
            },
            activate,
        )
    }
    pub fn revoke_grant_by_id(
        &self,
        grant_id: &str,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<bool> {
        let agent = self
            .lock()?
            .grants
            .iter()
            .find(|grant| grant.grant_id == grant_id)
            .map(|grant| grant.agent.clone());
        match agent {
            Some(agent) => self.revoke_grant(&agent, grant_id, now, activate),
            None => Ok(false),
        }
    }
    pub fn revoke_binding(
        &self,
        agent: &str,
        binding_id: &str,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<bool> {
        self.transaction(
            now,
            true,
            |document, state| {
                let Some(index) = state.bindings.iter().position(|record| {
                    record.binding.agent == agent && record.binding.binding_id == binding_id
                }) else {
                    return Ok(false);
                };
                remove_record(
                    document,
                    agent,
                    "contract_bindings",
                    "binding_id",
                    binding_id,
                )?;
                state.bindings.remove(index);
                state.ephemeral_bindings.remove(binding_id);
                Ok(true)
            },
            activate,
        )
    }
    /// Reserve a matching once grant before the caller bypasses risky-route policy.
    /// No matching grant means the caller must perform ordinary policy enforcement.
    pub fn check_grant(
        &self,
        scope: RequestScope<'_>,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<Option<GrantLease>> {
        let expired: Vec<_> = {
            let state = self.lock()?;
            state
                .grants
                .iter()
                .filter(|grant| {
                    grant.is_expired(now) && !state.reservations.contains_key(&grant.grant_id)
                })
                .cloned()
                .collect()
        };
        let selected = self.transaction(
            now,
            true,
            |document, state| {
                for expired in expired {
                    // The locked policy may contain a renewal made after the
                    // previous in-memory snapshot. Do not delete that approval.
                    if state
                        .grants
                        .iter()
                        .any(|grant| grant.grant_id == expired.grant_id && grant != &expired)
                    {
                        continue;
                    }
                    remove_record(
                        document,
                        &expired.agent,
                        "grants",
                        "grant_id",
                        &expired.grant_id,
                    )?;
                    state
                        .grants
                        .retain(|grant| grant.grant_id != expired.grant_id);
                    state.ephemeral_grants.remove(&expired.grant_id);
                    state.reservations.remove(&expired.grant_id);
                }
                let Some(grant) = state
                    .grants
                    .iter()
                    .find(|grant| {
                        grant.matches(scope, now)
                            && !state.reservations.contains_key(&grant.grant_id)
                    })
                    .cloned()
                else {
                    return Ok(None);
                };
                let reservation = identifier("use");
                if grant.scope == GrantScope::Once {
                    state
                        .reservations
                        .insert(grant.grant_id.clone(), reservation.clone());
                }
                Ok(Some((grant, reservation)))
            },
            activate,
        )?;
        Ok(selected.map(|(grant, reservation)| GrantLease {
            grant,
            reservation,
            state: Arc::downgrade(&self.state),
            release_on_drop: true,
        }))
    }
    pub fn finish_response(
        &self,
        mut lease: GrantLease,
        status: Option<u16>,
        now: OffsetDateTime,
        activate: impl FnMut(&str) -> std::result::Result<(), String>,
    ) -> Result<ResponseOutcome> {
        let consume = lease.grant.scope == GrantScope::Once
            && status.is_some_and(|status| (200..300).contains(&status));
        // A successful origin action must never regain its once grant because
        // persistence or activation failed. Keep that reservation fail-closed.
        // This quarantine is process-local: a failed durable write plus restart
        // cannot provide exactly-once external side effects across that crash.
        lease.release_on_drop = !consume;
        if !Weak::ptr_eq(&lease.state, &Arc::downgrade(&self.state)) {
            return Err(invalid("grant lease belongs to another store"));
        }
        if !consume {
            return Ok(ResponseOutcome::Retained);
        }
        self.transaction(
            now,
            true,
            |document, state| {
                if state.reservations.get(&lease.grant.grant_id) != Some(&lease.reservation) {
                    return Ok(ResponseOutcome::Stale);
                }
                remove_record(
                    document,
                    &lease.grant.agent,
                    "grants",
                    "grant_id",
                    &lease.grant.grant_id,
                )?;
                state
                    .grants
                    .retain(|grant| grant.grant_id != lease.grant.grant_id);
                state.ephemeral_grants.remove(&lease.grant.grant_id);
                state.reservations.remove(&lease.grant.grant_id);
                Ok(ResponseOutcome::Consumed)
            },
            activate,
        )
    }
}

/// Opaque, non-cloneable request reservation. Dropping after cancellation releases
/// this reservation only; an old request cannot release a replacement reservation.
pub struct GrantLease {
    grant: Grant,
    reservation: String,
    state: Weak<Mutex<Snapshot>>,
    release_on_drop: bool,
}
impl GrantLease {
    pub fn grant(&self) -> &Grant {
        &self.grant
    }
}
impl Drop for GrantLease {
    fn drop(&mut self) {
        if self.release_on_drop
            && let Some(state) = self.state.upgrade()
            && let Ok(mut state) = state.lock()
            && state.reservations.get(&self.grant.grant_id) == Some(&self.reservation)
        {
            state.reservations.remove(&self.grant.grant_id);
        }
    }
}

fn grant_record(grant: &Grant) -> Result<Json> {
    let mut value = serde_json::to_value(grant).map_err(|error| invalid(error.to_string()))?;
    value.as_object_mut().unwrap().remove("agent");
    Ok(value)
}
fn binding_record(record: &StoredBinding) -> Result<Json> {
    let mut value = serde_json::to_value(record).map_err(|error| invalid(error.to_string()))?;
    value.as_object_mut().unwrap().remove("agent");
    Ok(value)
}
fn agent_table<'a>(
    document: &'a mut DocumentMut,
    agent: &str,
) -> Result<Option<&'a mut dyn TableLike>> {
    let Some(agents) = document.get_mut("agents") else {
        return Ok(None);
    };
    let agents = agents
        .as_table_like_mut()
        .ok_or_else(|| invalid("agents must be a table"))?;
    let Some(agent) = agents.get_mut(agent) else {
        return Ok(None);
    };
    agent
        .as_table_like_mut()
        .map(Some)
        .ok_or_else(|| invalid("agent must be a table"))
}
fn record_matches(
    item: &dyn TableLike,
    key: &str,
    value: &str,
    tuple: Option<(&str, &str)>,
) -> bool {
    if let Some((service, capability)) = tuple {
        item.get("service").and_then(Item::as_str) == Some(service)
            && item.get("capability").and_then(Item::as_str) == Some(capability)
    } else {
        item.get(key).and_then(Item::as_str) == Some(value)
    }
}
fn remove_from_list(
    item: &mut Item,
    key: &str,
    value: &str,
    tuple: Option<(&str, &str)>,
) -> Result<()> {
    if let Some(array) = item.as_array_of_tables_mut() {
        array.retain(|table| !record_matches(table, key, value, tuple));
        return Ok(());
    }
    if let Some(array) = item.as_array_mut() {
        array.retain(|record| {
            record
                .as_inline_table()
                .is_none_or(|table| !record_matches(table, key, value, tuple))
        });
        return Ok(());
    }
    Err(invalid("grant/binding records must be an array of tables"))
}
fn remove_record(
    document: &mut DocumentMut,
    agent: &str,
    collection: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    if let Some(agent) = agent_table(document, agent)?
        && let Some(item) = agent.get_mut(collection)
    {
        remove_from_list(item, key, value, None)?;
    }
    Ok(())
}
fn upsert_record(
    document: &mut DocumentMut,
    agent: &str,
    collection: &str,
    key: &str,
    value: &str,
    record: Json,
    tuple: Option<(&str, &str)>,
) -> Result<bool> {
    let inline = document
        .get("agents")
        .and_then(Item::as_table_like)
        .and_then(|agents| agents.get(agent))
        .is_some_and(Item::is_inline_table);
    let Some(agent) = agent_table(document, agent)? else {
        return Ok(false);
    };
    if !agent.contains_key(collection) {
        agent.insert(
            collection,
            if inline {
                Item::Value(Value::Array(Array::new()))
            } else {
                Item::ArrayOfTables(ArrayOfTables::new())
            },
        );
    }
    let item = agent.get_mut(collection).unwrap();
    remove_from_list(item, key, value, tuple)?;
    let mut table = Table::new();
    for (key, value) in record
        .as_object()
        .ok_or_else(|| invalid("record must be an object"))?
    {
        table.insert(key, Item::Value(json_to_toml(value)?));
    }
    if let Some(array) = item.as_array_of_tables_mut() {
        array.push(table);
    } else if let Some(array) = item.as_array_mut() {
        array.push(Value::InlineTable(table.into_inline_table()));
    } else {
        return Err(invalid("records must be an array"));
    }
    Ok(true)
}

// serde_json's arbitrary_precision Number serializes through a private marker
// structure with non-JSON serializers. Convert values directly so even ordinary
// integers cannot become marker tables or rounded float bindings in policy TOML.
fn json_to_toml(value: &Json) -> Result<Value> {
    Ok(match value {
        Json::Null => return Err(invalid("TOML cannot persist a null binding value")),
        Json::Bool(value) => Value::from(*value),
        Json::String(value) => Value::from(value.clone()),
        Json::Number(value) => {
            if let Some(integer) = value.as_i64() {
                Value::from(integer)
            } else if value.to_string().contains(['.', 'e', 'E']) {
                Value::from(
                    value
                        .as_f64()
                        .filter(|value| value.is_finite())
                        .ok_or_else(|| ApprovalError {
                            kind: ErrorKind::Unsupported,
                            message: "binding float exceeds finite TOML numeric range".into(),
                        })?,
                )
            } else {
                large_integer_marker_value(&value.to_string())
            }
        }
        Json::Array(values) => {
            let mut array = Array::new();
            for value in values {
                array.push(json_to_toml(value)?);
            }
            Value::Array(array)
        }
        Json::Object(values) => {
            let mut table = InlineTable::new();
            for (key, value) in values {
                table.insert(key, json_to_toml(value)?);
            }
            Value::InlineTable(table)
        }
    })
}
