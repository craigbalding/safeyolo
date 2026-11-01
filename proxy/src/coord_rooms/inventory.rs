//! Operator room advertisements, using the existing mutation ledger and outbox.
use super::{Error, Path, hash, now, open};
use crate::agent_api::coord::{
    inventory::{MAX_CAPABILITIES, MAX_PROVIDERS, MAX_RESOURCES},
    valid_agent_id, valid_capability,
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

pub const HELP: &str = "safeyolo [--root ROOT] coord state ROOM\nsafeyolo [--root ROOT] coord inventory advertise-capability|unadvertise-capability ROOM AGENT LABEL [--operation-id ID]\nsafeyolo [--root ROOT] coord inventory advertise-resource|unadvertise-resource ROOM PROVIDER RESOURCE [--operation-id ID]\n\nAdvertisements select public collaboration labels; current host service grants authorize them. Only fresh provider evidence establishes availability or lease ownership. Agent declarations remain separate. Identical operation-ID retries return the original result; changed input conflicts. Unadvertising a removed agent also accepts its durable agent ID.";

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<Value, Error> {
    let (arguments, operation) = match arguments {
        [arguments @ .., flag, id] if flag == "--operation-id" => (arguments, Some(id.as_str())),
        arguments => (arguments, None),
    };
    let [command, room, subject, label] = arguments else {
        return Err(HELP.into());
    };
    let capability = match command.as_str() {
        "advertise-capability" | "unadvertise-capability" => true,
        "advertise-resource" | "unadvertise-resource" => false,
        _ => return Err(HELP.into()),
    };
    let advertise = command.starts_with("advertise-");
    if !valid_capability(
        if capability {
            label.clone()
        } else {
            format!("{subject}:{label}")
        }
        .as_str(),
    ) {
        return Err(
            "inventory labels must be public provider:name labels without sensitive fields".into(),
        );
    }
    let agent = if capability {
        if !advertise && valid_agent_id(subject) {
            subject.clone()
        } else {
            let config = crate::native_config::read(&root.join("config.toml"))?;
            let source = zeroize::Zeroizing::new(std::fs::read_to_string(
                config.policy_file.ok_or("policy path is missing")?,
            )?);
            let document = source.parse::<toml_edit::DocumentMut>()?;
            document
                .get("agents")
                .and_then(|a| a.get(subject))
                .and_then(|a| a.get("agent_id"))
                .and_then(toml_edit::Item::as_str)
                .ok_or("agent identity is not configured")?
                .to_owned()
        }
    } else {
        String::new()
    };
    change(
        root,
        room,
        capability.then_some(agent.as_str()),
        if capability {
            label.split_once(':').unwrap().0
        } else {
            subject
        },
        label,
        advertise,
        operation,
    )
}

fn change(
    root: &Path,
    room: &str,
    agent: Option<&str>,
    provider: &str,
    label: &str,
    advertise: bool,
    operation: Option<&str>,
) -> Result<Value, Error> {
    let generated = uuid::Uuid::new_v4().simple().to_string();
    let operation = operation.unwrap_or(&generated);
    if operation.trim().is_empty() {
        return Err("operation ID must be nonempty".into());
    }
    let mut conn = open(root)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let room_id: String = tx
        .query_row("SELECT room_id FROM rooms WHERE name=?1", [room], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or("Coord room does not exist")?;
    let kind = if agent.is_some() {
        "capability"
    } else {
        "resource"
    };
    let operation_type = format!("coord.inventory.{kind}");
    let request = json!({"room_id":room_id,"agent_id":agent,"provider":provider,"label":label,"advertised":advertise});
    let request_hash = hash(request.to_string().as_bytes());
    let prior: Option<(String,String)> = tx.query_row("SELECT request_hash,outcome_json FROM coord_operations WHERE principal_kind='operator' AND principal_id='operator' AND operation_type=?1 AND operation_id=?2",params![operation_type,operation],|r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((original, result)) = prior {
        if original != request_hash {
            return Err("operation ID conflicts with the original canonical request".into());
        }
        return Ok(serde_json::from_str(&result)?);
    }
    let changed_at = now();
    if let Some(agent) = agent {
        if advertise && !tx.query_row("SELECT EXISTS(SELECT 1 FROM memberships WHERE room_id=?1 AND principal_kind='agent' AND principal_id=?2 AND revoked_at IS NULL)",params![room_id,agent],|r| r.get::<_,bool>(0))? {
            return Err("capability subject is not a current room member".into());
        }
        if advertise {
            tx.execute("INSERT OR IGNORE INTO coord_capability_advertisements(room_id,agent_id,capability,operation_id,created_at) VALUES(?1,?2,?3,?4,?5)",params![room_id,agent,label,operation,changed_at])?;
        } else {
            tx.execute("DELETE FROM coord_capability_advertisements WHERE room_id=?1 AND agent_id=?2 AND capability=?3",params![room_id,agent,label])?;
        }
    } else if advertise {
        tx.execute("INSERT OR IGNORE INTO coord_resource_advertisements(room_id,provider,resource,operation_id,created_at) VALUES(?1,?2,?3,?4,?5)",params![room_id,provider,label,operation,changed_at])?;
    } else {
        tx.execute("DELETE FROM coord_resource_advertisements WHERE room_id=?1 AND provider=?2 AND resource=?3",params![room_id,provider,label])?;
    }
    let (capabilities, resources, providers): (i64,i64,i64) = tx.query_row("SELECT
        (SELECT count(*) FROM coord_capability_advertisements WHERE room_id=?1),
        (SELECT count(*) FROM coord_resource_advertisements WHERE room_id=?1),
        (SELECT count(*) FROM (SELECT substr(capability,1,instr(capability,':')-1) AS provider FROM coord_capability_advertisements WHERE room_id=?1 UNION SELECT provider FROM coord_resource_advertisements WHERE room_id=?1))",[&room_id],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if capabilities > MAX_CAPABILITIES as i64
        || resources > MAX_RESOURCES as i64
        || providers > MAX_PROVIDERS as i64
    {
        return Err("room inventory exceeds its advertisement bounds".into());
    }
    let result = json!({"room_id":room_id,"kind":kind,"agent_id":agent,"provider":provider,"label":label,"advertised":advertise,"operation_id":operation,"changed_at":changed_at});
    tx.execute("INSERT INTO coord_operations(principal_kind,principal_id,operation_type,operation_id,request_hash,outcome_kind,outcome_json,created_at) VALUES('operator','operator',?1,?2,?3,'success',?4,?5)",params![operation_type,operation,request_hash,result.to_string(),changed_at])?;
    let event_id = format!("evt-{}", uuid::Uuid::new_v4().simple());
    let event_type = "coord.inventory_advertisement_changed";
    let event = json!({"schema_version":crate::audit::SCHEMA_VERSION,"event_id":event_id,"ts":time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,"event":event_type,"kind":"coord","severity":"low","summary":"Coord room advertisement changed","addon":"coord","details":{"actor":"operator","room_id":room_id,"kind":kind,"agent_id":agent,"provider":provider,"label":label,"advertised":advertise,"operation_id":operation,"operation_type":operation_type}});
    tx.execute("INSERT INTO coord_outbox(event_id,destination,event_type,payload_json,created_at) VALUES(?1,'audit-jsonl',?2,?3,?4)",params![event_id,event_type,event.to_string(),changed_at])?;
    tx.commit()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
