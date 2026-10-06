//! Human-decided network actions use the existing audit and policy owners.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use toml_edit::{InlineTable, Item, Value as TomlValue};
use zeroize::Zeroizing;

use super::{NetworkScope, invalid};
use crate::{
    audit::{self, Event, Kind, Severity, Writer},
    policy::{Policy, evidence::Read},
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkAction {
    kind: ActionKind,
    pub(crate) agent: String,
    pub(crate) agent_id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    revision: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ActionKind {
    NetworkAllow,
}

impl NetworkAction {
    fn scope(&self) -> super::Result<NetworkScope> {
        NetworkScope::new(&self.host, Some(&self.agent), Some(self.port))
    }

    fn current(&self, policy: &Policy) -> bool {
        policy.evidence_agent_id(&self.agent) == Some(self.agent_id.as_str())
            && policy.network_action_revision(&self.agent).as_deref()
                == Some(self.revision.as_str())
    }

    fn effect(&self) -> String {
        format!(
            "Allow reusable network access for {} ({}) to {} port {} until explicitly removed.",
            crate::network_guard::sanitize(&self.agent),
            self.agent_id,
            crate::network_guard::sanitize(&self.host),
            self.port
        )
    }
}

/// Bind newly produced native prompts at their trusted enforcement snapshot.
/// Name-only historical events remain readable to the operator but cannot be
/// promoted into an assisted action for a recreated agent.
pub(crate) fn bind(event: &mut Event, policy: &Policy) {
    if event
        .approval
        .as_ref()
        .is_none_or(|approval| approval.approval_type != audit::ApprovalType::NetworkEgress)
    {
        return;
    }
    let (Some(agent), Some(host)) = (event.agent.as_deref(), event.host.as_deref()) else {
        return;
    };
    let Some(agent_id) = policy.evidence_agent_id(agent) else {
        return;
    };
    let Some(revision) = policy.network_action_revision(agent) else {
        return;
    };
    let Some(approval) = &event.approval else {
        return;
    };
    let Ok(hint) = approval.scope_hint.render_json(false) else {
        return;
    };
    let Ok(hint) = serde_json::from_str::<Value>(&hint) else {
        return;
    };
    let Some(port) = hint["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
    else {
        return;
    };
    let action = NetworkAction {
        kind: ActionKind::NetworkAllow,
        agent: agent.into(),
        agent_id: agent_id.into(),
        host: host.into(),
        port,
        revision,
    };
    // Existing operator clients display the event summary before deciding.
    // State the reusable permission there as well as in the canonical read.
    event.summary = action.effect();
    if let crate::circuits::CircuitValue::Object(fields) = &mut event.details {
        fields.insert("network_action".into(), json!(action).into());
        fields.insert("effect".into(), json!(action.effect()).into());
    }
}

pub(crate) struct Record {
    pub(crate) action: NetworkAction,
    status: String,
    reason: Option<String>,
}
impl Record {
    pub(crate) fn view(&self, request_id: &str, operator: bool) -> Value {
        let mut value = json!({"request_id":request_id,"status":self.status,
            "action":self.action,"effect":self.action.effect()});
        if operator && let Some(reason) = &self.reason {
            value["untrusted_reason_text"] = json!(reason);
        }
        value
    }

    pub(crate) fn readable(
        &self,
        policy: &Policy,
        caller: &str,
        request_id: &str,
        read: Read,
    ) -> bool {
        policy.evidence_agent_id(&self.action.agent) == Some(self.action.agent_id.as_str())
            && ((caller == self.action.agent)
                || policy.evidence_reader(caller, request_id, read).as_deref()
                    == Some(self.action.agent.as_str()))
    }
}

struct AuditDocument(crate::circuits::CircuitValue);
impl Drop for AuditDocument {
    fn drop(&mut self) {
        audit::wipe(&mut self.0);
    }
}
struct Json(Value);
impl Drop for Json {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.0);
    }
}

pub(crate) fn record(
    writer: &Writer,
    policy: &Policy,
    request_id: &str,
) -> super::Result<Option<Record>> {
    // A committed host entry is canonical permission evidence even if the
    // client lost its response or the post-commit audit write failed.
    if let Some(source) = policy.native_source_text() {
        let document = Json(
            crate::policy::parse_toml_document(source)
                .map_err(|_| invalid("policy evidence unavailable"))?,
        );
        if let Some(agents) = document.0["agents"].as_object() {
            for (name, agent) in agents {
                if let Some(hosts) = agent["hosts"].as_object() {
                    for (destination, entry) in hosts {
                        if entry["approval_request_id"].as_str() == Some(request_id)
                            && entry["egress"].as_str() == Some("allow")
                            && let Ok(action) = serde_json::from_value::<NetworkAction>(
                                entry["approval_action"].clone(),
                            )
                            && action.agent == *name
                            && action
                                .scope()
                                .is_ok_and(|scope| scope.destination() == *destination)
                            && policy.evidence_agent_id(name) == Some(action.agent_id.as_str())
                        {
                            return Ok(Some(Record {
                                action,
                                status: "approved".into(),
                                reason: None,
                            }));
                        }
                    }
                }
            }
        }
    }
    let document = AuditDocument(
        writer
            .approval_events(request_id)
            .map_err(|_| invalid("approval evidence unavailable"))?,
    );
    let text = Zeroizing::new(
        document
            .0
            .render_json(false)
            .map_err(|_| invalid("approval evidence unavailable"))?,
    );
    let value =
        Json(serde_json::from_str(&text).map_err(|_| invalid("approval evidence unavailable"))?);
    let mut events = value
        .0
        .as_array()
        .ok_or_else(|| invalid("approval evidence unavailable"))?
        .iter()
        .collect::<Vec<_>>();
    events.sort_by_key(|event| event["ts"].as_str().unwrap_or(""));
    let mut result = None;
    for event in events {
        let Some(action) = event.pointer("/details/network_action") else {
            continue;
        };
        let action: NetworkAction = serde_json::from_value(action.clone())
            .map_err(|_| invalid("approval evidence unavailable"))?;
        let prior = result.get_or_insert(Record {
            action: action.clone(),
            status: "pending".into(),
            reason: None,
        });
        if prior.action != action {
            return Err(invalid("approval identity has conflicting actions"));
        }
        if let Some(status) = event.pointer("/details/resolution").and_then(Value::as_str) {
            prior.status = status.into();
        }
        if let Some(reason) = event
            .pointer("/details/untrusted_reason_text")
            .and_then(Value::as_str)
        {
            prior.reason = Some(reason.into());
        }
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preparation {
    action: NetworkAction,
    reason: String,
}

/// Produce a preparation event for the same immutable pending request. The
/// reason is literal untrusted text and never enters a summary or notification.
pub(crate) fn prepare(
    writer: &Writer,
    policy: &Policy,
    caller: &str,
    request_id: &str,
    input: Preparation,
) -> super::Result<Event> {
    let record =
        record(writer, policy, request_id)?.ok_or_else(|| invalid("approval unavailable"))?;
    if !record.readable(policy, caller, request_id, Read::Approval) {
        return Err(invalid("selected approval read is not granted"));
    }
    if record.status != "pending" || !record.action.current(policy) {
        return Err(invalid(
            "approval is resolved or stale; read the canonical outcome",
        ));
    }
    if record.action != input.action {
        return Err(invalid("changed action requires a new canonical request"));
    }
    let scope = record.action.scope()?;
    let mut event = Event::new(
        "agent.network_action_prepared",
        Kind::Agent,
        Severity::High,
        record.action.effect(),
    );
    event.agent = Some(record.action.agent.clone());
    event.host = Some(record.action.host.clone());
    event.request_id = Some(request_id.into());
    event.decision = Some(audit::Decision::RequireApproval);
    event.approval = Some(audit::Approval {
        // This annotates the existing canonical prompt. A delayed preparation
        // must not create or reopen pending work after a terminal decision.
        required: false,
        approval_type: audit::ApprovalType::NetworkEgress,
        key: scope.approval_key()?,
        target: scope.destination(),
        scope_hint: json!({"port":scope.port}).into(),
    });
    // Sanitize controls with the existing sanitizer, then display metacharacters
    // literally in both Markdown and HTML consumers.
    let mut reason = crate::network_guard::sanitize(&input.reason);
    for (from, to) in [
        ("&", "&amp;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("#", "\\#"),
        ("[", "\\["),
        ("]", "\\]"),
        ("`", "\\`"),
        ("*", "\\*"),
    ] {
        reason = reason.replace(from, to);
    }
    event.details = json!({"network_action":record.action,"effect":record.action.effect(),
        "prepared_by":caller,"prepared_by_id":policy.evidence_agent_id(caller),
        "untrusted_reason_text":reason})
    .into();
    Ok(event)
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Decision {
    Approve,
    Reject,
}

/// Select two already supported read projections without copying evidence or
/// granting network permission. Use the existing policy lock and activation.
pub(crate) fn share_reads(
    state: &crate::RuntimeState,
    writer: &Writer,
    request_id: &str,
    helper: &str,
    helper_id: &str,
) -> std::result::Result<(u16, Value), crate::Error> {
    let mut shared = None;
    let result = crate::edit_native_policy(state, true, |source| {
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
        let policy = runtime
            .policy
            .as_ref()
            .ok_or_else(|| invalid("active policy unavailable"))?;
        let Some(record) = record(writer, policy, request_id)? else {
            return Ok((
                (404, json!({"error":"approval unavailable"})),
                source.to_owned(),
            ));
        };
        let path = runtime
            .config
            .policy_file
            .as_ref()
            .ok_or_else(|| invalid("policy unavailable"))?;
        let saved = policy
            .reload_native_source(source, path)
            .map_err(|_| invalid("saved policy unavailable"))?;
        // Sharing evidence does not decide the action. Keep the existing read
        // identity checks; terminal or stale-policy records remain inspectable.
        if policy.evidence_agent_id(&record.action.agent) != Some(record.action.agent_id.as_str())
            || saved.evidence_agent_id(&record.action.agent)
                != Some(record.action.agent_id.as_str())
            || policy.evidence_agent_id(helper) != Some(helper_id)
            || saved.evidence_agent_id(helper) != Some(helper_id)
        {
            return Ok((
                (
                    409,
                    json!({"error":"Worker or Helper identity changed; select current state"}),
                ),
                source.to_owned(),
            ));
        }
        let (mut document, context) = crate::policy::parse_toml_for_edit(source)
            .map_err(|_| invalid("policy unavailable"))?;
        let agent = document["agents"][helper]
            .as_table_like_mut()
            .ok_or_else(|| invalid("Helper unavailable"))?;
        let reads = agent
            .entry("evidence_reads")
            .or_insert(Item::Value(TomlValue::Array(toml_edit::Array::new())))
            .as_array_mut()
            .ok_or_else(|| invalid("evidence_reads must be an array"))?;
        let mut selected = InlineTable::new();
        for (key, value) in [
            ("reader_id", helper_id),
            ("agent", record.action.agent.as_str()),
            ("agent_id", record.action.agent_id.as_str()),
            ("request_id", request_id),
        ] {
            selected.insert(key, TomlValue::from(value));
        }
        selected.insert(
            "reads",
            TomlValue::Array(["diagnostic", "approval"].into_iter().collect()),
        );
        let selected = TomlValue::InlineTable(selected);
        let value = json!({"request_id":request_id,"status":"shared","helper":helper,"helper_id":helper_id,
            "agent":record.action.agent,"agent_id":record.action.agent_id,"reads":["diagnostic","approval"],
            "effect":"Selected diagnostic and approval reads only. No network permission or operator authority was granted."});
        if [Read::Diagnostic, Read::Approval].into_iter().all(|read| {
            saved.evidence_reader(helper, request_id, read).as_deref()
                == Some(record.action.agent.as_str())
        }) {
            return Ok(((200, value), source.to_owned()));
        }
        reads.push(selected);
        let mut event = Event::new(
            "admin.evidence_reads_shared",
            Kind::Admin,
            Severity::High,
            "Selected diagnostic and approval reads shared with Helper; no network permission granted.",
        );
        event.agent = Some(record.action.agent.clone());
        event.request_id = Some(request_id.into());
        event.details =
            json!({"helper":helper,"helper_id":helper_id,"agent_id":record.action.agent_id,
            "reads":["diagnostic","approval"]})
            .into();
        shared = Some(event);
        Ok((
            (200, value),
            crate::policy::restore_large_toml_integers(&document.to_string(), &context),
        ))
    })?;
    if let Some(event) = shared {
        tokio::runtime::Handle::current()
            .block_on(writer.emit_confirmed(event))
            .map_err(|_| {
                invalid("read grant saved; audit receipt unavailable; inspect policy show")
            })?;
    }
    Ok(result)
}

/// Run on the existing process-owned blocking mutation executor. A canceled
/// HTTP receiver cannot abandon an admitted policy edit or its audit result.
pub(crate) fn resolve(
    state: &crate::RuntimeState,
    writer: &Writer,
    request_id: &str,
    decision: Decision,
) -> std::result::Result<(u16, Value), crate::Error> {
    let mut resolved = None;
    let result = crate::edit_native_policy(state, true, |source| {
        let runtime = state.read().map_err(|_| invalid("runtime unavailable"))?;
        let policy = runtime
            .policy
            .as_ref()
            .ok_or_else(|| invalid("active policy unavailable"))?;
        let Some(record) = record(writer, policy, request_id)? else {
            return Ok((
                (404, json!({"error":"approval unavailable"})),
                source.to_owned(),
            ));
        };
        if record.status != "pending" {
            return Ok(((200, record.view(request_id, true)), source.to_owned()));
        }
        if matches!(decision, Decision::Approve) {
            let path = runtime
                .config
                .policy_file
                .as_ref()
                .ok_or_else(|| invalid("policy unavailable"))?;
            let saved = policy
                .reload_native_source(source, path)
                .map_err(|_| invalid("saved policy unavailable"))?;
            if !record.action.current(policy) || !record.action.current(&saved) {
                return Ok((
                    (
                        409,
                        json!({"error":"approval is stale; a new request and decision are required"}),
                    ),
                    source.to_owned(),
                ));
            }
        }
        let scope = record.action.scope()?;
        let status = match decision {
            Decision::Approve => "approved",
            Decision::Reject => "rejected",
        };
        let mut event = Event::new(
            match decision {
                Decision::Approve => "admin.host_allowed",
                Decision::Reject => "admin.network_action_rejected",
            },
            Kind::Admin,
            Severity::High,
            record.action.effect(),
        );
        event.agent = Some(record.action.agent.clone());
        event.host = Some(record.action.host.clone());
        event.request_id = Some(request_id.into());
        event.details = json!({"network_action":record.action,"resolution":status,
            "approval_request_id":request_id,"host":scope.host,"agent":scope.agent,"port":scope.port}).into();
        let value = json!({"request_id":request_id,"status":status,"action":record.action,"effect":record.action.effect()});
        let changed = if matches!(decision, Decision::Approve) {
            let (mut document, context) = crate::policy::parse_toml_for_edit(source)
                .map_err(|_| invalid("policy unavailable"))?;
            let hosts = super::hosts_table(&mut document, &scope)?;
            let host = hosts
                .entry(&scope.destination())
                .or_insert(Item::Value(TomlValue::InlineTable(InlineTable::new())));
            let fields = host
                .as_table_like_mut()
                .ok_or_else(|| invalid("host entry must be a table"))?;
            // The fixed action changes egress and its until-removed lifetime,
            // while retaining the operator's rate and other host fields.
            fields.insert("egress", Item::Value(TomlValue::from("allow")));
            fields.remove("expires");
            fields.insert(
                "approval_request_id",
                Item::Value(TomlValue::from(request_id)),
            );
            let mut action = InlineTable::new();
            for (key, value) in serde_json::to_value(&record.action)
                .map_err(|_| invalid("action unavailable"))?
                .as_object()
                .ok_or_else(|| invalid("action unavailable"))?
            {
                action.insert(
                    key,
                    match value {
                        Value::String(text) => TomlValue::from(text.as_str()),
                        Value::Number(number) => TomlValue::from(
                            number
                                .as_i64()
                                .ok_or_else(|| invalid("action port unavailable"))?,
                        ),
                        _ => return Err(invalid("action unavailable")),
                    },
                );
            }
            fields.insert(
                "approval_action",
                Item::Value(TomlValue::InlineTable(action)),
            );
            resolved = Some(event);
            crate::policy::restore_large_toml_integers(&document.to_string(), &context)
        } else {
            // Confirm rejection while still holding the policy lock so two
            // clients cannot both decide a still-pending request.
            tokio::runtime::Handle::current()
                .block_on(writer.emit_confirmed(event))
                .map_err(|_| invalid("rejection evidence unavailable; read canonical state"))?;
            source.to_owned()
        };
        Ok(((200, value), changed))
    })?;
    if let Some(event) = resolved {
        // The rule contains the request/action identity before this write. A
        // missing receipt does not invite replay or revoke a committed decision.
        if tokio::runtime::Handle::current()
            .block_on(writer.emit_confirmed(event))
            .is_err()
        {
            let mut value = result.1;
            value["evidence_status"] =
                json!("unavailable; read canonical approval before retrying");
            return Ok((result.0, value));
        }
    }
    Ok(result)
}
