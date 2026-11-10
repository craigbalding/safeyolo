//! Human reads of the existing private receipts under the owning Admin boundary.
use super::*;
use std::path::Path;

fn read(path: &Path) -> Result<Value, Error> {
    let lock = match crate::host_platform::try_lock_host_state(&path.with_extension("lock")) {
        Ok(lock) => Some(lock),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(error) => return Err(error.into()),
    };
    let receipt = crate::guest_commands::read_state_bounded(path, 1024 * 1024)?
        .ok_or("recorded support operation unavailable")?;
    Ok(reconcile(receipt, lock.is_none()))
}

fn paths() -> Result<Vec<PathBuf>, Error> {
    let directory = crate::host_platform::config_dir().join("data/support-operations");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    entries
        .map(|entry| Ok(entry?.path()))
        .filter(|path: &Result<PathBuf, Error>| {
            path.as_ref().map_or(true, |path| {
                path.extension().is_some_and(|ext| ext == "json")
            })
        })
        .collect()
}

pub(crate) fn summary(receipt: &Value) -> Value {
    let mut value = json!({});
    for field in [
        "operation_id",
        "instance_id",
        "initiator",
        "target_id",
        "target_name",
        "target_run",
        "grant",
        "grant_revision",
        "grant_expires_at",
        "action",
        "recorded_action",
        "lifecycle_operation",
        "state",
        "requested_at",
        "finished_at",
        "execution_started",
        "completion_verified",
        "last_recorded_state",
        "resulting_run",
        "diagnostic",
        "recovery",
        "audit_event_id",
        "audit_delivered",
        "audit_status",
    ] {
        if let Some(recorded) = receipt.get(field) {
            value[field] = recorded.clone();
        }
    }
    if let Ok(caller) = serde_json::from_value::<Caller>(receipt["initiator"].clone()) {
        value["initiator_principal"] = json!(caller.principal());
    }
    value
}

pub(crate) fn list(limit: usize, target: Option<&str>) -> Result<Value, Error> {
    let mut receipts = paths()?
        .iter()
        .map(|path| read(path).map(|receipt| summary(&receipt)))
        .collect::<Result<Vec<_>, _>>()?;
    receipts.retain(|receipt| target.is_none_or(|id| receipt["target_id"] == id));
    receipts
        .sort_by_key(|receipt| std::cmp::Reverse(receipt["requested_at"].as_i64().unwrap_or(0)));
    let total = receipts.len();
    receipts.truncate(limit);
    Ok(
        json!({"instance_id":crate::peer_support::instance_id()?,"receipts":receipts,"total":total,"omitted":total.saturating_sub(limit),
        "authority":"Owning operator Admin access. Guest output is excluded; select an explicit detail view to read it."}),
    )
}

pub(crate) async fn detail(
    state: &RuntimeState,
    id: &str,
    initiator: Option<&str>,
    output: bool,
    current: bool,
) -> Result<Value, Error> {
    let mut matches = Vec::new();
    for path in paths()? {
        let receipt = read(&path)?;
        let caller: Caller = serde_json::from_value(receipt["initiator"].clone())?;
        if receipt["operation_id"] == id && initiator.is_none_or(|id| caller.principal() == id) {
            matches.push(receipt);
        }
    }
    if matches.len() != 1 {
        return Err(if matches.is_empty() {
            "original operation receipt unavailable on this owner"
        } else {
            "operation ID has several initiators; select --initiator from the receipt list"
        }
        .into());
    }
    let receipt = matches.remove(0);
    let original: Caller = serde_json::from_value(receipt["initiator"].clone())?;
    let mut view = json!({"receipt":summary(&receipt),"output_included":output,"read_at":time::OffsetDateTime::now_utc().unix_timestamp(),
        "authority":"Owning operator Admin access. Agent result reads separately require current support authority.",
        "recovery":"The original operation was not submitted again. Current target state cannot establish which uncertain earlier effect occurred. Select any further action deliberately under current authority."});
    if output {
        view["recorded_result"] = receipt["result"].clone();
        view["recorded_action"] = receipt["permission"]["operation"].clone();
    }
    if current {
        let policy = match super::super::current_policy(state) {
            Ok(policy) => policy,
            Err(_) => {
                view["current_target"] = json!({"availability":"unavailable","next_action":"On this owner, restore the current policy and inspect agent diagnostics. The original receipt remains recorded evidence."});
                view["current_grant"] = json!({"availability":"unavailable"});
                return Ok(view);
            }
        };
        let target = crate::host_agents::list().map(|agents| {
            agents.into_iter().find(|agent| {
                receipt["target_id"] == agent.id
                    && policy.evidence_agent_id(&agent.name) == Some(agent.id.as_str())
            })
        });
        view["current_target"] = match target {
            Ok(Some(target)) => {
                let observed = crate::host_commands::diagnostics(&target).await;
                match super::super::current_policy(state).map(|policy| {
                    policy.evidence_agent_id(&target.name) == Some(target.id.as_str())
                }) {
                    Err(_) => {
                        json!({"availability":"unavailable","next_action":"On this owner, restore current policy and inspect the durable target inventory before a new action."})
                    }
                    Ok(false) => {
                        json!({"availability":"identity_changed","next_action":"On this owner, inspect the durable target inventory. A recreated same-name agent is a different target."})
                    }
                    Ok(true) => match observed {
                        Ok(observed) => {
                            json!({"availability":"observed","observed_at":time::OffsetDateTime::now_utc().unix_timestamp(),"state":inspection(&observed)})
                        }
                        Err(_) => {
                            json!({"availability":"unavailable","next_action":"On this owner, run agent diagnostics for the recorded target; preserve its runtime before recovery."})
                        }
                    },
                }
            }
            Ok(None) => {
                json!({"availability":"identity_changed_or_removed","next_action":"On this owner, inspect the durable target inventory. Do not apply the old receipt to a recreated same-name agent."})
            }
            Err(_) => {
                json!({"availability":"unavailable","next_action":"On this owner, restore the agent inventory and inspect local agent diagnostics. The original receipt remains recorded evidence."})
            }
        };
        view["current_grant"] = match super::super::current_policy(state) {
            Ok(policy) => policy.support_grants().remove(receipt["grant"].as_str().ok_or("receipt grant unavailable")?)
            .map(|grant| {
                let mut current = super::super::grant_view(&policy, receipt["grant"].as_str().unwrap(), &grant, receipt["instance_id"].as_str().unwrap_or(""));
                current["matches_recorded_revision"] = json!(receipt["grant_revision"] == grant.revision());
                current["matches_recorded_initiator"] = json!(super::super::support_principal(&policy,&grant).as_deref() == Some(original.principal()));
                current
            })
            .unwrap_or_else(|| json!({"active":false,"reason":"removed","next_action":"Inspect remaining authority with support report or configure support on this owner."})),
            Err(_) => json!({"availability":"unavailable","next_action":"On this owner, restore current policy before assessing present authority."}),
        };
    }
    Ok(view)
}
