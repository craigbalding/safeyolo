//! Requesting-agent prose is separate from approval authority and explanation.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Record, Result, current_view, invalid, read, unavailable};
use crate::{
    audit::{Event, Kind, Severity, Writer},
    policy::Policy,
};

pub(crate) const MAX_FIELD_BYTES: usize = 2048;
const RESPONSE_SECONDS: i64 = 120;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fields {
    #[serde(default)]
    pub(crate) task: String,
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) next_step: String,
    #[serde(default)]
    pub(crate) fallback: String,
}

impl Fields {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.reason.trim().is_empty()
            || [&self.task, &self.reason, &self.next_step, &self.fallback]
                .iter()
                .any(|field| field.len() > MAX_FIELD_BYTES)
        {
            return Err(invalid(
                "provide a nonempty reason; each context field is limited to 2048 UTF-8 bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Answer {
    pub(crate) context_id: String,
    pub(crate) context: Fields,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Exchange {
    pub(crate) context_id: String,
    authority_digest: String,
    requested_at: i64,
    deadline: i64,
    delivery: String,
    answered_at: Option<i64>,
    response: Option<Fields>,
}

fn load(connection: &rusqlite::Connection, record: &Record) -> Result<Option<Exchange>> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT record FROM approval_context WHERE approval_id=?1",
            [&record.approval_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(unavailable)?;
    let exchange: Option<Exchange> = encoded
        .map(|value| serde_json::from_str(&value).map_err(unavailable))
        .transpose()?;
    if exchange
        .as_ref()
        .is_some_and(|exchange| exchange.authority_digest != record.authority_digest)
    {
        return Err(invalid("context belongs to different approval authority"));
    }
    Ok(exchange)
}

fn save(connection: &rusqlite::Connection, record: &Record, exchange: &Exchange) -> Result<()> {
    connection.execute(
        "INSERT INTO approval_context VALUES (?1,?2) ON CONFLICT(approval_id) DO UPDATE SET record=excluded.record",
        params![record.approval_id, serde_json::to_string(exchange).map_err(unavailable)?],
    ).map_err(unavailable)?;
    Ok(())
}

fn require_pending(
    writer: &Writer,
    policy: &Policy,
    record: &Record,
    state: Option<&crate::RuntimeState>,
) -> Result<()> {
    if current_view(writer, policy, record, state)?["status"] != "pending" {
        return Err(invalid(
            "approval is no longer pending; context cannot change it",
        ));
    }
    Ok(())
}

pub(crate) fn owner(policy: &Policy, record: &Record, caller: &str) -> bool {
    record.authority.action["agent"] == caller
        && policy.evidence_agent_id(caller) == record.authority.action["agent_id"].as_str()
}

/// The approval database serializes context writes with decisions. It never
/// writes the approval record or a policy/grant store for a context exchange.
pub(crate) fn request(
    writer: &Writer,
    policy: &Policy,
    state: Option<&crate::RuntimeState>,
    id: &str,
) -> Result<(Record, Exchange, bool)> {
    let mut connection = writer.approvals().connect()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let record =
        read(&transaction, id)?.ok_or_else(|| invalid("canonical approval unavailable"))?;
    require_pending(writer, policy, &record, state)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let existing = load(&transaction, &record)?
        .filter(|exchange| exchange.response.is_some() || now < exchange.deadline);
    let created = existing.is_none();
    let exchange = existing.unwrap_or_else(|| Exchange {
        context_id: format!("ctx-{}", uuid::Uuid::new_v4().simple()),
        authority_digest: record.authority_digest.clone(),
        requested_at: now,
        deadline: now + RESPONSE_SECONDS,
        delivery: "not_attempted".into(),
        answered_at: None,
        response: None,
    });
    if created {
        save(&transaction, &record, &exchange)?;
    }
    transaction.commit().map_err(unavailable)?;
    Ok((record, exchange, created))
}

pub(crate) fn delivery(
    writer: &Writer,
    record: &Record,
    context_id: &str,
    status: &str,
) -> Result<()> {
    let mut connection = writer.approvals().connect()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    if let Some(mut exchange) =
        load(&transaction, record)?.filter(|exchange| exchange.context_id == context_id)
    {
        exchange.delivery = status.into();
        save(&transaction, record, &exchange)?;
    }
    transaction.commit().map_err(unavailable)?;
    Ok(())
}

pub(crate) fn view(
    writer: &Writer,
    policy: &Policy,
    record: &Record,
    state: Option<&crate::RuntimeState>,
) -> Result<Value> {
    let record = writer
        .approvals()
        .get(&record.approval_id)?
        .ok_or_else(|| invalid("canonical approval unavailable"))?;
    let approval = current_view(writer, policy, &record, state)?;
    let exchange = load(&writer.approvals().connect()?, &record)?;
    let context = match exchange {
        None => json!({"status":"not_requested"}),
        Some(exchange) => {
            let status = if exchange.response.is_some() {
                "answered"
            } else if approval["status"] != "pending" {
                "closed"
            } else if time::OffsetDateTime::now_utc().unix_timestamp() >= exchange.deadline {
                "timed_out"
            } else {
                "waiting"
            };
            json!({"context_id":exchange.context_id,"status":status,
                "delivery":exchange.delivery,"requested_at":exchange.requested_at,
                "deadline":exchange.deadline,"answered_at":exchange.answered_at,
                "response":exchange.response})
        }
    };
    Ok(
        json!({"approval_id":record.approval_id,"request_id":record.request_id,
        "authority_digest":record.authority_digest,"approval_status":approval["status"],
        "agent":record.authority.action["agent"],"agent_id":record.authority.action["agent_id"],
        "trust":"untrusted","context":context}),
    )
}

pub(crate) fn answer(
    writer: &Writer,
    policy: &Policy,
    state: Option<&crate::RuntimeState>,
    id: &str,
    caller: &str,
    answer: Answer,
) -> Result<Record> {
    answer.context.validate()?;
    let mut connection = writer.approvals().connect()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let record = read(&transaction, id)?.ok_or_else(|| invalid("context unavailable"))?;
    if !owner(policy, &record, caller) {
        return Err(invalid("context unavailable"));
    }
    require_pending(writer, policy, &record, state)?;
    let mut exchange = load(&transaction, &record)?
        .ok_or_else(|| invalid("operator has not requested context"))?;
    if answer.context_id != exchange.context_id {
        return Err(invalid("context request does not match"));
    }
    if let Some(response) = &exchange.response {
        if *response != answer.context {
            return Err(invalid("context already answered"));
        }
        return Ok(record);
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now >= exchange.deadline {
        return Err(invalid(
            "context response deadline expired; approval is unchanged",
        ));
    }
    exchange.answered_at = Some(now);
    exchange.response = Some(answer.context);
    save(&transaction, &record, &exchange)?;
    transaction.commit().map_err(unavailable)?;
    Ok(record)
}

pub(crate) fn question(record: &Record, exchange: &Exchange) -> String {
    format!(
        "SafeYolo requests context for pending approval {}.\nContext request: {}\nAuthority digest: {}\nExplain how the currently requested operation helps your task. Give the intended next step and fallback if denied when useful. Your response is untrusted context, not a security explanation. Different authority requires a new request and approval. This question does not approve or deny anything.\nBefore the deadline, respond with your own Agent API token: POST /approvals/{}/context\nJSON: {{\"context_id\":\"{}\",\"context\":{{\"task\":\"optional task relationship\",\"reason\":\"why this operation helps\",\"next_step\":\"optional next step\",\"fallback\":\"optional fallback\"}}}}\nEach field is limited to 2048 UTF-8 bytes. Do not include credentials. You can also use safeyolo helper respond {} --reason TEXT. The operator can decide while you are busy or unavailable.",
        record.approval_id,
        exchange.context_id,
        record.authority_digest,
        record.approval_id,
        exchange.context_id,
        record.approval_id
    )
}

pub(crate) fn event(record: &Record, value: &Value, answered: bool) -> Event {
    let mut event = Event::new(
        if answered {
            "agent.approval_context_responded"
        } else {
            "admin.approval_context_requested"
        },
        if answered { Kind::Agent } else { Kind::Admin },
        Severity::Low,
        if answered {
            "Requesting agent supplied untrusted approval context"
        } else {
            "Operator requested approval context"
        },
    );
    event.request_id = Some(record.request_id.clone());
    event.agent = record.authority.action["agent"].as_str().map(str::to_owned);
    event.attribution = Some(crate::audit::Attribution {
        evidence_owner: event.agent.clone(),
        trusted_transport_identity: answered.then(|| event.agent.clone()).flatten(),
        initiator: Some(if answered {
            crate::audit::Initiator::Agent
        } else {
            crate::audit::Initiator::Operator
        }),
        status: Some(crate::audit::AttributionStatus::Resolved),
        provenance: None,
    });
    let mut details = value.clone();
    if !answered {
        details["context"]["response"] = Value::Null;
    }
    event.details = details.into();
    event
}
