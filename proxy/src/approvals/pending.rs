//! Host-owned pending requests. Audit events describe this authority; they do
//! not create it. Policy and gateway stores still own every permission effect.

use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Result, invalid};
use crate::{
    audit::{Event, Writer},
    policy::Policy,
};

pub(crate) mod context;
mod explanation;
mod gateway;
pub(crate) use explanation::explain;
pub(crate) use gateway::{bind_agent_request, bind_risky};

#[derive(Clone)]
pub(crate) struct Store {
    path: PathBuf,
    pub(crate) session_id: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OptionScope {
    pub(crate) id: String,
    pub(crate) effect: String,
    pub(crate) session_id: Option<String>,
    pub(crate) parameters: Value,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    pub(crate) action: Value,
    pub(crate) revision: String,
    pub(crate) method: String,
    pub(crate) scheme: String,
    pub(crate) port: Option<u16>,
    /// Includes the complete request target, without storing its query or any
    /// bearer value. The host's action separately states the actual grant scope.
    pub(crate) resource_digest: String,
    pub(crate) options: Vec<OptionScope>,
    pub(crate) expires_at: Option<String>,
    pub(crate) credential_bindings: std::collections::BTreeMap<String, String>,
}

impl Authority {
    pub(crate) fn selected_option(&self, option: Option<&str>) -> Option<&OptionScope> {
        match option {
            Some(id) => self.options.iter().find(|option| option.id == id),
            None if self.options.len() == 1 => self.options.first(),
            None if self.action["kind"] == "gateway_route" => {
                self.options.iter().find(|option| option.id == "once")
            }
            _ => None,
        }
    }

    fn material(&self) -> Value {
        let mut material = json!(self);
        if let Some(options) = material["options"].as_array_mut() {
            for option in options.iter_mut() {
                if let Some(fields) = option.as_object_mut() {
                    fields.shift_remove("effect");
                }
            }
            options.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        }
        material
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) approval_id: String,
    pub(crate) request_id: String,
    pub(crate) authority: Authority,
    pub(crate) authority_digest: String,
    pub(crate) created_at: i64,
    pub(crate) status: String,
    pub(crate) option: Option<String>,
    pub(crate) result: Value,
    pub(crate) untrusted_reason_text: Option<String>,
}

/// Sort object keys recursively. Presentation order cannot change equivalence.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let sorted: std::collections::BTreeMap<_, _> = fields.iter().collect();
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(k, v)| (k.clone(), canonical(v)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        _ => value.clone(),
    }
}

pub(crate) fn digest(value: &Value) -> String {
    let mut ordered = canonical(value);
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&ordered).expect("JSON value"));
    crate::credentials::wipe_json(&mut ordered);
    ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unavailable(_: impl std::fmt::Display) -> super::ApprovalError {
    super::ApprovalError {
        kind: super::ErrorKind::Io,
        message:
            "pending approval state unavailable; inspect policy and approval before deciding again"
                .into(),
    }
}

pub(crate) fn valid_id(id: &str) -> bool {
    crate::agent_api::valid_request_id(id)
        || id.strip_prefix("apr-").is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

pub(crate) fn normalized_expiry(value: &str) -> String {
    crate::policy::parse_expiry(value)
        .filter(|_| crate::policy::expiry_has_offset(value))
        .and_then(|expiry| {
            expiry
                .to_offset(time::UtcOffset::UTC)
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "invalid".into())
}

fn expired_at(expires_at: Option<&str>, now: time::OffsetDateTime) -> bool {
    expires_at
        .is_some_and(|value| crate::policy::parse_expiry(value).is_none_or(|expiry| now >= expiry))
}

impl Store {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            session_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub(crate) fn initialize(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        let connection = self.connect()?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS approvals (
               approval_id TEXT PRIMARY KEY, authority_digest TEXT NOT NULL,
               status TEXT NOT NULL, record TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS equivalent_pending ON approvals(authority_digest, status);
             CREATE TABLE IF NOT EXISTS approval_requests (
               request_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL REFERENCES approvals(approval_id));
             CREATE TABLE IF NOT EXISTS approval_context (
               approval_id TEXT PRIMARY KEY REFERENCES approvals(approval_id), record TEXT NOT NULL);"
        ).map_err(unavailable)?;
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        // Reads never create or reconstruct missing authority from a log.
        let connection =
            Connection::open_with_flags(&self.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(unavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(unavailable)?;
        connection
            .execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
            .map_err(unavailable)?;
        Ok(connection)
    }

    pub(crate) fn submit(
        &self,
        authority: Authority,
        request_id: &str,
        policy: &Policy,
    ) -> Result<Record> {
        let authority_digest = digest(&authority.material());
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        if let Some(record) = read(&transaction, request_id)? {
            if record.authority.material() != authority.material() {
                return Err(invalid(
                    "changed request requires a new traffic request and approval",
                ));
            }
            return Ok(record);
        }
        let mut statement = transaction
            .prepare("SELECT record FROM approvals WHERE authority_digest=?1 AND status='pending'")
            .map_err(unavailable)?;
        let records = statement
            .query_map([&authority_digest], |row| row.get::<_, String>(0))
            .map_err(unavailable)?;
        let mut selected = None;
        for record in records {
            let record = decode_record(&record.map_err(unavailable)?)?;
            if record.authority.material() == authority.material()
                && record.current_status(policy)? == "pending"
            {
                selected = Some(record);
                break;
            }
        }
        drop(statement);
        let record = selected.unwrap_or_else(|| Record {
            approval_id: format!("apr-{}", uuid::Uuid::new_v4().simple()),
            request_id: request_id.into(),
            authority,
            authority_digest,
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            status: "pending".into(),
            option: None,
            result: Value::Null,
            untrusted_reason_text: None,
        });
        save(&transaction, &record)?;
        transaction
            .execute(
                "INSERT INTO approval_requests VALUES (?1,?2)",
                params![request_id, record.approval_id],
            )
            .map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        Ok(record)
    }

    pub(crate) fn get(&self, id: &str) -> Result<Option<Record>> {
        read(&self.connect()?, id)
    }

    pub(crate) fn list(&self) -> Result<Vec<Record>> {
        let connection = self.connect()?;
        let mut statement = connection
            .prepare("SELECT record FROM approvals ORDER BY rowid")
            .map_err(unavailable)?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(unavailable)?
            .map(|row| decode_record(&row.map_err(unavailable)?))
            .collect()
    }

    /// The database serializes competing resolvers. A policy commit also stores
    /// its receipt beside the effect. A restart after that commit can finish the
    /// receipt without creating a second grant, even when the audit was lost.
    pub(crate) fn decide(
        &self,
        id: &str,
        resolve: impl FnOnce(&mut Record) -> Result<()>,
    ) -> Result<Option<Record>> {
        let mut connection = self.connect()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let Some(mut record) = read(&transaction, id)? else {
            return Ok(None);
        };
        resolve(&mut record)?;
        save(&transaction, &record)?;
        transaction.commit().map_err(unavailable)?;
        Ok(Some(record))
    }
}

fn read(connection: &Connection, id: &str) -> Result<Option<Record>> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT record FROM approvals WHERE approval_id=?1 OR approval_id=(
           SELECT approval_id FROM approval_requests WHERE request_id=?1)",
            [id],
            |row| row.get(0),
        )
        .optional()
        .map_err(unavailable)?;
    encoded.map(|encoded| decode_record(&encoded)).transpose()
}

fn decode_record(encoded: &str) -> Result<Record> {
    let record: Record = serde_json::from_str(encoded).map_err(unavailable)?;
    if digest(&record.authority.material()) != record.authority_digest {
        return Err(invalid(
            "approval authority is inconsistent; no decision was made",
        ));
    }
    Ok(record)
}

fn save(connection: &Connection, record: &Record) -> Result<()> {
    connection
        .execute(
            "INSERT INTO approvals VALUES (?1,?2,?3,?4) ON CONFLICT(approval_id)
           DO UPDATE SET status=excluded.status, record=excluded.record",
            params![
                record.approval_id,
                record.authority_digest,
                record.status,
                serde_json::to_string(record).map_err(unavailable)?
            ],
        )
        .map_err(unavailable)?;
    Ok(())
}

impl Record {
    fn expired(&self) -> bool {
        expired_at(
            self.authority.expires_at.as_deref(),
            time::OffsetDateTime::now_utc(),
        )
    }

    pub(crate) fn current_status(&self, policy: &Policy) -> Result<String> {
        if self.status != "pending" {
            return Ok(self.status.clone());
        }
        if self.committed(policy)?.is_some() {
            return Ok("approved".into());
        }
        if self.expired() {
            return Ok("expired".into());
        }
        let action = &self.authority.action;
        if policy.evidence_agent_id(action["agent"].as_str().unwrap_or(""))
            != action["agent_id"].as_str()
            || revision(policy, action).as_deref() != Some(self.authority.revision.as_str())
        {
            return Ok("superseded".into());
        }
        Ok("pending".into())
    }

    pub(crate) fn committed(&self, policy: &Policy) -> Result<Option<Value>> {
        let Some(result) = policy.approval_result(&self.approval_id).map_err(invalid)? else {
            return Ok(None);
        };
        if result["authority_digest"] != self.authority_digest
            || !result["option"]
                .as_str()
                .is_some_and(|id| self.authority.options.iter().any(|option| option.id == id))
            || !result["result"].is_object()
        {
            return Err(invalid(
                "approval receipt has different authority; no decision was made",
            ));
        }
        Ok(Some(result))
    }

    pub(crate) fn view(&self, policy: &Policy) -> Result<Value> {
        let receipt = if self.status == "pending" {
            self.committed(policy)?
        } else {
            None
        };
        let chosen = receipt
            .as_ref()
            .and_then(|value| value["option"].as_str())
            .or(self.option.as_deref());
        let effect = chosen
            .and_then(|id| self.authority.options.iter().find(|option| option.id == id))
            .or_else(|| self.authority.options.first())
            .map(|option| option.effect.as_str())
            .unwrap_or(
                "No approval option is available. Configure a credential and make a new request.",
            );
        let (event, approval_type) = match self.authority.action["kind"].as_str() {
            Some("network_allow") => ("security.network_guard", "network_egress"),
            Some("credential_allow") => ("security.credential_guard", "credential"),
            Some("gateway_route") => ("gateway.risky_route", "gateway_risky_route"),
            Some("service_authorize") => ("gateway.request_access", "service"),
            Some("operator_action") => ("agent.operator_action_requested", "desktop_present"),
            _ => ("gateway.contract_binding_requested", "contract_binding"),
        };
        let target = self
            .authority
            .action
            .get("host")
            .or_else(|| self.authority.action.get("service"))
            .or_else(|| self.authority.action.get("agent_id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut view = json!({"approval_id":self.approval_id,"request_id":self.request_id,
            "status":self.current_status(policy)?,"created_at":self.created_at,
            "action":self.authority.action,"authority":self.authority,
            "agent":self.authority.action["agent"],
            "host":self.authority.action["host"],"event":event,
            "summary":self.authority.options.first().map(|option| option.effect.as_str()).unwrap_or(effect),
            "approval":{"required":self.current_status(policy)? == "pending",
                "target":target,"approval_type":approval_type,"key":self.approval_id,
                "scope_hint":{"agent_id":self.authority.action["agent_id"],"port":self.authority.port}},
            "details":{"service":self.authority.action["service"],"method":self.authority.method,"path":self.authority.action["path"]},
            "authority_digest":self.authority_digest,"options":self.authority.options,
            "effect":effect,
            "option":receipt.as_ref().map(|value| &value["option"]).unwrap_or(&json!(self.option)),
            "result":receipt.as_ref().map(|value| &value["result"]).unwrap_or(&self.result)});
        if let Some(reason) = &self.untrusted_reason_text {
            view["untrusted_reason_text"] = json!(reason);
        }
        if self.authority.action["kind"] == "network_allow" {
            view["details"]["network_action"] = self.authority.action.clone();
            if let Some(reason) = &self.untrusted_reason_text {
                view["details"]["untrusted_reason_text"] = json!(reason);
            }
        }
        if self.authority.action["kind"] == "operator_action" {
            view["details"]["untrusted_reason_text"] = json!(self.untrusted_reason_text);
            view["details"]["browser_url"] =
                self.authority.action["parameters"]["browser_url"].clone();
            view["details"]["presentation"] = self.authority.action["presentation"].clone();
            view["details"]["ttl_seconds"] =
                self.authority.action["parameters"]["ttl_seconds"].clone();
        }
        Ok(view)
    }

    pub(crate) fn receipt(&self) -> Value {
        json!({"authority_digest":self.authority_digest,"option":self.option,"result":self.result})
    }
}

pub(crate) fn save_receipt(document: &mut toml_edit::DocumentMut, record: &Record) -> Result<()> {
    document["approval_results"][&record.approval_id] =
        toml_edit::value(serde_json::to_string(&record.receipt()).map_err(unavailable)?);
    Ok(())
}

pub(crate) fn revision(policy: &Policy, action: &Value) -> Option<String> {
    if action["kind"] == "operator_action" {
        Some(digest(
            &json!({"action_id":crate::operator_actions::DESKTOP_PRESENT,
            "agent_id":policy.evidence_agent_id(action["agent"].as_str()?)?}),
        ))
    } else if action["kind"] == "network_allow" {
        policy.network_action_revision(action["agent"].as_str()?)
    } else {
        policy.approval_revision(
            action["agent"].as_str()?,
            action["kind"].as_str()?,
            action["service"].as_str(),
        )
    }
}

/// Called at the reached enforcement hook, before publishing a pending response.
pub(crate) async fn bind_network(
    writer: &Writer,
    policy: &Policy,
    event: &mut Event,
    request: &crate::policy::NetworkRequest<'_>,
    scheme: &str,
    guard: Option<&crate::credential_guard::CredentialGuard>,
) -> Result<Option<Record>> {
    if policy.native_controls().is_none() {
        return Ok(None);
    }
    let Some(action) = event
        .details
        .as_object()
        .and_then(|fields| fields.get("network_action"))
    else {
        // Name-only listeners retain their original 428 and direct policy
        // controls. They cannot bind an assisted action to a durable agent.
        return Ok(None);
    };
    let action = action.json().map_err(unavailable)?;
    let guard = guard.ok_or_else(|| invalid("request binding unavailable"))?;
    let effect = event.summary.clone();
    let authority = Authority {
        revision: revision(policy, &action)
            .ok_or_else(|| invalid("approval revision unavailable"))?,
        action,
        method: request.method.into(),
        scheme: scheme.into(),
        port: request.port,
        resource_digest: guard.approval_resource(request.path),
        options: vec![OptionScope {
            id: "persistent".into(),
            effect,
            session_id: None,
            parameters: Value::Null,
        }],
        expires_at: None,
        credential_bindings: Default::default(),
    };
    let store = writer.approvals().clone();
    let current_policy = policy.clone();
    let request_id = event
        .request_id
        .clone()
        .ok_or_else(|| invalid("traffic identity unavailable"))?;
    let record =
        tokio::task::spawn_blocking(move || store.submit(authority, &request_id, &current_policy))
            .await
            .map_err(unavailable)??;
    annotate(event, &record);
    Ok(Some(record))
}

pub(crate) async fn bind_credentials(
    writer: &Writer,
    policy: &Policy,
    events: &mut [Event],
    request: &crate::policy::NetworkRequest<'_>,
    scheme: &str,
    pending_response: bool,
    guard: &crate::credential_guard::CredentialGuard,
) -> Result<Option<Record>> {
    if policy.native_controls().is_none() || !pending_response {
        return Ok(None);
    }
    let requested: Vec<_> = events
        .iter()
        .filter(|event| {
            event.approval.as_ref().is_some_and(|approval| {
                approval.required
                    && approval.approval_type == crate::audit::ApprovalType::Credential
            })
        })
        .collect();
    let Some(first) = requested.first() else {
        return Ok(None);
    };
    let Some(agent) = first.agent.as_deref() else {
        return Ok(None);
    };
    let Some(agent_id) = policy.evidence_agent_id(agent) else {
        return Ok(None);
    };
    let request_id = first
        .request_id
        .clone()
        .ok_or_else(|| invalid("traffic identity unavailable"))?;
    let mut credentials: Vec<_> = requested
        .iter()
        .filter_map(|event| event.approval.as_ref().map(|approval| approval.key.clone()))
        .collect();
    credentials.sort();
    credentials.dedup();
    if credentials
        .iter()
        .any(|key| !key.starts_with("hmac:") || key.len() <= 5)
    {
        return Err(invalid("credential fingerprint unavailable"));
    }
    let action = json!({"kind":"credential_allow","agent":agent,"agent_id":agent_id,
        "host":request.host,"credentials":credentials});
    let effect = format!(
        "Allow these credential fingerprints to {} for all agents in this instance, including future agents. This changes shared persistent policy until explicitly removed. Existing network rules still apply.",
        crate::network_guard::sanitize(request.host)
    );
    let authority = Authority {
        revision: revision(policy, &action)
            .ok_or_else(|| invalid("credential policy revision unavailable"))?,
        action,
        method: request.method.into(),
        scheme: scheme.into(),
        port: request.port,
        resource_digest: guard.approval_resource(request.path),
        options: vec![OptionScope {
            id: "persistent".into(),
            effect,
            session_id: None,
            parameters: Value::Null,
        }],
        expires_at: None,
        credential_bindings: Default::default(),
    };
    let store = writer.approvals().clone();
    let current_policy = policy.clone();
    let record =
        tokio::task::spawn_blocking(move || store.submit(authority, &request_id, &current_policy))
            .await
            .map_err(unavailable)??;
    for event in events {
        if event
            .approval
            .as_ref()
            .is_some_and(|approval| approval.required)
        {
            annotate(event, &record);
        }
    }
    Ok(Some(record))
}

pub(crate) fn annotate(event: &mut Event, record: &Record) {
    if let crate::circuits::CircuitValue::Object(fields) = &mut event.details {
        fields.insert("approval_id".into(), json!(record.approval_id).into());
        fields.insert(
            "authority_digest".into(),
            json!(record.authority_digest).into(),
        );
    }
}

pub(crate) fn correlate_credential(policy: &Policy, event: &mut Event) {
    if event.decision != Some(crate::audit::Decision::Allow) {
        return;
    }
    let Some(host) = event.host.as_deref() else {
        return;
    };
    if let crate::circuits::CircuitValue::Object(fields) = &mut event.details {
        let id = fields
            .get("fingerprint")
            .and_then(|value| value.json().ok())
            .and_then(|value| {
                value
                    .as_str()
                    .and_then(|fingerprint| policy.credential_approval(host, fingerprint))
                    .map(str::to_owned)
            });
        if let Some(id) = id {
            fields.insert("approval_id".into(), json!(id).into());
        }
    }
}

pub(crate) fn lookup(writer: &Writer, id: &str) -> Result<Option<Record>> {
    if writer.approvals_enabled() || id.starts_with("apr-") {
        writer.approvals().get(id)
    } else {
        Ok(None)
    }
}

pub(crate) fn current_view(
    writer: &Writer,
    policy: &Policy,
    record: &Record,
    state: Option<&crate::RuntimeState>,
) -> Result<Value> {
    let mut view = record.view(policy)?;
    if record.status == "pending"
        && let Some(state) = state
    {
        let saved = record.view(&saved_policy(state, policy)?)?;
        if saved["status"] == "approved" || view["status"] == "pending" {
            view = saved;
        }
    }
    let runtime = state
        .map(|state| state.read().map_err(|_| invalid("runtime unavailable")))
        .transpose()?;
    if view["status"] == "pending"
        && let Some(runtime) = runtime.as_deref()
        && !gateway::credentials_current(runtime, record)?
    {
        view["status"] = json!("superseded");
    }
    for (saved, option) in record
        .authority
        .options
        .iter()
        .zip(view["options"].as_array_mut().into_iter().flatten())
        .filter(|_| record.status == "pending")
    {
        let expired = saved
            .session_id
            .as_ref()
            .is_some_and(|id| id != &writer.approvals().session_id)
            || expired_at(
                saved.parameters["expires_at"].as_str(),
                time::OffsetDateTime::now_utc(),
            );
        option["status"] = if expired {
            json!("expired")
        } else if let Some(runtime) = runtime.as_deref() {
            if gateway::option_current(runtime, saved)? {
                json!("available")
            } else {
                json!("superseded")
            }
        } else {
            json!("available")
        };
    }
    view["approval"]["required"] = json!(view["status"] == "pending");
    Ok(view)
}

pub(crate) fn inspect(
    writer: &Writer,
    policy: &Policy,
    record: &Record,
    state: Option<&crate::RuntimeState>,
) -> Result<Value> {
    let mut view = current_view(writer, policy, record, state)?;
    let mut event = Event::new(
        "admin.approval_inspected",
        crate::audit::Kind::Admin,
        crate::audit::Severity::Low,
        format!("Approval {} inspected", record.approval_id),
    );
    event.request_id = Some(record.request_id.clone());
    event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
    event.details =
        json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
        "status":view["status"]})
        .into();
    if writer.emit(event).is_err() {
        view["audit_status"] = json!("inspection audit unavailable");
    }
    Ok(view)
}

fn active_policy(state: &crate::RuntimeState) -> Result<Policy> {
    state
        .read()
        .map_err(|_| invalid("runtime unavailable"))?
        .policy
        .clone()
        .ok_or_else(|| invalid("active policy unavailable"))
}

fn saved_policy(state: &crate::RuntimeState, policy: &Policy) -> Result<Policy> {
    let path = state
        .read()
        .map_err(|_| invalid("runtime unavailable"))?
        .config
        .policy_file
        .clone()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let source = zeroize::Zeroizing::new(std::fs::read_to_string(&path).map_err(unavailable)?);
    policy
        .reload_native_source(&source, &path)
        .map_err(|_| invalid("saved policy unavailable"))
}

pub(crate) fn check_saved(
    state: &crate::RuntimeState,
    source: &str,
    record: &Record,
) -> Result<bool> {
    let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
    let policy = runtime
        .policy
        .as_ref()
        .ok_or_else(|| invalid("active policy unavailable"))?;
    let path = runtime
        .config
        .policy_file
        .as_ref()
        .ok_or_else(|| invalid("policy unavailable"))?;
    let saved = policy
        .reload_native_source(source, path)
        .map_err(|_| invalid("saved policy unavailable"))?;
    Ok(record.current_status(policy)? == "pending"
        && record.current_status(&saved)? == "pending"
        && gateway::credentials_current(&runtime, record)?)
}

pub(crate) fn resolve(
    state: &crate::RuntimeState,
    writer: &Writer,
    id: &str,
    decision: super::network_action::Decision,
    option: Option<&str>,
) -> Result<Option<(u16, Value)>> {
    match lookup(writer, id)? {
        Some(record) if record.authority.action["kind"] == "operator_action" => {
            return crate::operator_actions::resolve(state, writer, id, decision, option).map(Some);
        }
        Some(_) => {}
        None => return Ok(None),
    }
    let mut changed = false;
    let selected = writer.approvals().decide(id, |record| {
        let policy = active_policy(state)?;
        if record.status != "pending" { return Ok(()); }
        let saved = saved_policy(state, &policy)?;
        if let Some(receipt) = record.committed(&policy)?.or(record.committed(&saved)?) {
            record.status = "approved".into();
            record.option = receipt["option"].as_str().map(str::to_owned);
            record.result = receipt["result"].clone();
            return Ok(());
        }
        record.status = record.current_status(&policy)?;
        if record.status == "pending" { record.status = record.current_status(&saved)?; }
        if record.status != "pending" { return Ok(()); }
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
        let credentials_current = gateway::credentials_current(&runtime, record)?;
        drop(runtime);
        if !credentials_current {
            record.status = "superseded".into();
            return Ok(());
        }
        if matches!(decision, super::network_action::Decision::Reject) {
            record.status = "rejected".into();
            record.result = json!({"permission_changed":false});
            changed = true;
            return Ok(());
        }
        let selected = record.authority.selected_option(option)
            .ok_or_else(|| invalid("select one of this approval's fixed options"))?;
        if selected.session_id.as_ref().is_some_and(|id| id != &writer.approvals().session_id) {
            return Err(invalid("the selected session expired; make a new request"));
        }
        record.option = Some(selected.id.clone());
        let parameters = selected.parameters.clone();
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
        let option_current = gateway::option_current(&runtime, selected)?;
        drop(runtime);
        if !option_current { return Err(invalid("the selected credential option expired or changed; make a new request")); }
        let action = record.authority.action.clone();
        if action["kind"] == "contract_binding" {
            let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
            let store = runtime.gateway_grants.clone().ok_or_else(|| invalid("gateway grant store unavailable"))?;
            let registry = runtime.policy.as_ref().and_then(Policy::gateway).and_then(|gateway| gateway.registry())
                .ok_or_else(|| invalid("service catalogue unavailable"))?;
            let service = action["service"].as_str().ok_or_else(|| invalid("service unavailable"))?;
            let capability = action["capability"].as_str().ok_or_else(|| invalid("capability unavailable"))?;
            let contract = registry.services.get(service).and_then(|service| service.capabilities.get(capability))
                .and_then(|capability| capability.contract.clone()).ok_or_else(|| invalid("contract unavailable"))?;
            let binding = crate::contracts::ContractBinding {
                binding_id:String::new(), agent:action["agent"].as_str().unwrap_or("").into(),
                service:service.into(),capability:capability.into(),template:action["template"].as_str().unwrap_or("").into(),
                bound_values:serde_json::from_value(action["bindings"].clone()).map_err(unavailable)?,
                grantable_operations:serde_json::from_value(action["grantable_operations"].clone()).map_err(unavailable)? };
            let path = runtime.config.policy_file.clone().ok_or_else(|| invalid("policy unavailable"))?;
            drop(runtime);
            let mut activate = crate::native_policy_activation(state, path);
            let result = store.approve_pending_binding(binding, &contract, state, record,
                |source| activate(source, super::PolicyActivation::Candidate));
            if record.status == "superseded" { return Ok(()); }
            result?;
            record.status = "approved".into(); changed = true;
            return Ok(());
        }
        if action["kind"] == "gateway_route" {
            let store = state.read().map_err(|_| invalid("runtime unavailable"))?.gateway_grants.clone()
                .ok_or_else(|| invalid("gateway grant store unavailable"))?;
            let scope = crate::grants::GrantScope::from_admin_lifetime(&json!(record.option))?;
            let request = crate::grants::GrantRequest { agent:action["agent"].as_str().unwrap_or("").into(),
                service:action["service"].as_str().unwrap_or("").into(),
                method:action["method"].as_str().unwrap_or("").into(), path:action["path"].as_str().unwrap_or("").into(), scope };
            let path = state.read().map_err(|_| invalid("runtime unavailable"))?.config.policy_file.clone()
                .ok_or_else(|| invalid("policy unavailable"))?;
            let mut activate = crate::native_policy_activation(state, path);
            let result = store.add_approval_grant(request, time::OffsetDateTime::now_utc(), state, record,
                |source| activate(source, super::PolicyActivation::Candidate));
            if record.status == "superseded" { return Ok(()); }
            result?;
            record.status = "approved".into(); changed = true;
            return Ok(());
        }
        if !matches!(action["kind"].as_str(), Some("network_allow" | "credential_allow" | "service_authorize")) { return Err(invalid("approval action is not supported")); }
        record.result = json!({"permission_changed":true,"lifetime":"persistent"});
        crate::edit_native_policy(state, true, |source| {
            if !check_saved(state, source, record)? {
                record.status = "superseded".into();
                record.result = Value::Null;
                return Ok(((), source.to_owned()));
            }
            let (mut document, context) = crate::policy::parse_toml_for_edit(source)
                .map_err(|_| invalid("policy unavailable"))?;
            if action["kind"] == "network_allow" {
                let scope = super::NetworkScope::new(action["host"].as_str().unwrap_or(""),
                    action["agent"].as_str(), action["port"].as_u64().and_then(|port| u16::try_from(port).ok()))?;
                let hosts = super::hosts_table(&mut document, &scope)?;
                let entry = hosts.entry(&scope.destination()).or_insert(toml_edit::Item::Value(
                    toml_edit::Value::InlineTable(toml_edit::InlineTable::new())));
                let fields = entry.as_table_like_mut().ok_or_else(|| invalid("host entry must be a table"))?;
                fields.insert("egress", toml_edit::value("allow"));
                fields.remove("expires");
                fields.insert("approval_id", toml_edit::value(&record.approval_id));
                record.result["scope"] = json!(scope);
            } else if action["kind"] == "credential_allow" {
                let host = action["host"].as_str().ok_or_else(|| invalid("credential destination unavailable"))?;
                let fingerprints: Vec<String> = serde_json::from_value(action["credentials"].clone()).map_err(unavailable)?;
                let count = super::insert_credentials(&mut document, host, &fingerprints)?;
                for fingerprint in &fingerprints {
                    document["hosts"][host]["credential_approval_ids"][fingerprint] = toml_edit::value(&record.approval_id);
                }
                record.result["fingerprints"] = json!(fingerprints);
                record.result["host"] = json!(host);
                record.result["permission_count"] = json!(count);
            } else {
                let agent = action["agent"].as_str().ok_or_else(|| invalid("agent unavailable"))?;
                let service = action["service"].as_str().ok_or_else(|| invalid("service unavailable"))?;
                let capability = action["capability"].as_str().ok_or_else(|| invalid("capability unavailable"))?;
                let host = action["host"].as_str().ok_or_else(|| invalid("service host unavailable"))?;
                let credential = parameters["credential"].as_str().ok_or_else(|| invalid("credential option unavailable"))?;
                document["agents"][agent]["services"][service]["capability"] = toml_edit::value(capability);
                document["agents"][agent]["services"][service]["account"] = toml_edit::value("agent");
                if !credential.is_empty() {
                    document["agents"][agent]["services"][service]["token"] = toml_edit::value(credential);
                } else if let Some(fields) = document["agents"][agent]["services"][service].as_table_like_mut() { fields.remove("token"); }
                document["hosts"][host]["service"] = toml_edit::value(service);
                record.result["service"] = json!(service);
                record.result["capability"] = json!(capability);
            }
            save_receipt(&mut document, record)?;
            Ok(((), crate::policy::restore_large_toml_integers(&document.to_string(), &context)))
        }).map_err(|_| invalid("approval effect could not be confirmed; inspect canonical state before retrying"))?;
        if record.status == "pending" { record.status = "approved".into(); changed = true; }
        Ok(())
    })?.ok_or_else(|| invalid("approval unavailable"))?;
    let policy = active_policy(state)?;
    let mut view = current_view(writer, &policy, &selected, Some(state))?;
    if changed {
        let mut event = Event::new(
            "admin.approval_decided",
            crate::audit::Kind::Admin,
            crate::audit::Severity::High,
            format!("Approval {} {}", selected.approval_id, selected.status),
        );
        event.agent = selected.authority.action["agent"]
            .as_str()
            .map(str::to_owned);
        event.request_id = Some(selected.request_id.clone());
        event.details =
            json!({"approval_id":selected.approval_id,"authority_digest":selected.authority_digest,
            "status":selected.status,"option":selected.option,"result":selected.result})
            .into();
        if tokio::runtime::Handle::current()
            .block_on(writer.emit_confirmed(event))
            .is_err()
        {
            view["audit_status"] = json!("unavailable; the canonical decision is saved");
        }
    }
    let status = if matches!(selected.status.as_str(), "expired" | "superseded") {
        409
    } else {
        200
    };
    Ok(Some((status, view)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_expiry_keeps_subsecond_precision() {
        let now = crate::policy::parse_expiry("2026-10-20T05:00:00.500Z").unwrap();
        assert!(!expired_at(Some("2026-10-20T05:00:00.750Z"), now));
        assert!(expired_at(Some("2026-10-20T05:00:00.250Z"), now));
        assert!(expired_at(Some("invalid"), now));
        assert!(!expired_at(None, now));
        assert_eq!(
            normalized_expiry("2026-10-20T06:00:00.750+01:00"),
            normalized_expiry("2026-10-20T05:00:00.750Z")
        );
        let guard = crate::credential_guard::CredentialGuard::new(b"expiry-test");
        let mut credential = crate::credentials::Credential::new(
            "expiry-test",
            "bearer",
            crate::credentials::Secret::new("synthetic"),
        );
        let binding = guard.approval_binding(&credential);
        credential.expires_at = Some(String::new());
        assert_eq!(guard.approval_binding(&credential), binding);
    }
}
