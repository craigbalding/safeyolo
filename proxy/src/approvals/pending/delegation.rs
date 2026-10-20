//! Delegated decisions use the canonical resolver and typed permission owners.
use super::{Record, Result, invalid};
use crate::{
    host_runs::AgentRun,
    policy::{
        Policy,
        delegation::{Agent, IssuedAccess},
    },
};
use serde_json::{Value, json};

pub(crate) fn authorize(
    policy: &Policy,
    record: &Record,
    reviewer: &AgentRun,
    name: &str,
    option: &str,
) -> Result<IssuedAccess> {
    if !reviewer.current(policy) {
        return Err(invalid("reviewer current-run identity is unavailable"));
    }
    let delegation = policy
        .delegations()
        .get(name)
        .ok_or_else(|| invalid("delegation is unavailable"))?;
    let decider = Agent {
        name: reviewer.agent.clone(),
        agent_id: reviewer.agent_id.clone(),
    };
    if !delegation.dependencies_current(policy)
        || !delegation.reviewers.contains(&decider)
        || !delegation.contains(record, option)
    {
        return Err(invalid(
            "this complete approval option does not fit one current delegation",
        ));
    }
    issue(policy, record, name, Some(decider), option)
}

pub(crate) fn issue(
    policy: &Policy,
    record: &Record,
    name: &str,
    reviewer: Option<Agent>,
    option: &str,
) -> Result<IssuedAccess> {
    let run: AgentRun =
        serde_json::from_value(record.authority.action["run"].clone()).map_err(|_| {
            invalid("this request has no trusted current-run binding; make a new request")
        })?;
    if !run.current(policy)
        || record.authority.action["agent"] != run.agent
        || record.authority.action["agent_id"] != run.agent_id
    {
        return Err(invalid("requester current-run identity changed"));
    }
    let delegation = policy.delegations().get(name);
    let now = time::OffsetDateTime::now_utc();
    let gateway_seconds = (record.authority.action["kind"] == "gateway_route")
        .then(|| {
            record
                .authority
                .options
                .iter()
                .find_map(|o| o.parameters["ttl_seconds"].as_u64())
        })
        .flatten();
    let seconds = match (delegation.and_then(|d| d.grant_seconds), gateway_seconds) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let mut expiry = seconds
        .map(|seconds| {
            now.checked_add(time::Duration::seconds(seconds as i64))
                .ok_or_else(|| invalid("grant expiry overflow"))
        })
        .transpose()?;
    for bound in [
        delegation.and_then(|d| d.expires_at.as_deref()),
        record.authority.expires_at.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let time =
            crate::policy::parse_expiry(bound).ok_or_else(|| invalid("invalid grant expiry"))?;
        expiry = Some(expiry.map_or(time, |existing| time.min(existing)));
    }
    Ok(IssuedAccess {
        delegation: name.into(),
        delegation_revision: delegation.map(|d| d.revision()).unwrap_or_default(),
        reviewer: reviewer.unwrap_or(Agent {
            name: "operator".into(),
            agent_id: "operator".into(),
        }),
        beneficiary: run,
        approval_id: record.approval_id.clone(),
        policy_revision: record.authority.revision.clone(),
        action: record.authority.action.clone(),
        option: option.into(),
        expires_at: expiry.map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .expect("UTC time")
        }),
    })
}

pub(crate) fn eligible(
    policy: &Policy,
    record: &Record,
    reviewer: &AgentRun,
) -> Vec<(String, String)> {
    policy
        .delegations()
        .iter()
        .flat_map(|(name, _)| {
            record.authority.options.iter().filter_map(|option| {
                authorize(policy, record, reviewer, name, &option.id)
                    .ok()
                    .map(|_| (name.clone(), option.id.clone()))
            })
        })
        .collect()
}

/// A reviewer sees trusted, bounded facts. Raw URL paths, queries, request
/// headers, bodies and agent prose are not copied into this projection.
pub(crate) fn view(
    writer: &crate::audit::Writer,
    policy: &Policy,
    record: &Record,
    state: &crate::RuntimeState,
    reviewer: &AgentRun,
) -> Result<Value> {
    let choices = eligible(policy, record, reviewer);
    if choices.is_empty() {
        return Err(invalid("approval unavailable"));
    }
    let mut view = super::explain(writer, policy, record, Some(state), Some(&choices[0].1))?;
    let choices: Vec<_>=choices.iter().map(|(name,option)| {
        let issued=authorize(policy,record,reviewer,name,option)?;
        Ok(json!({"delegation":name,"delegation_revision":issued.delegation_revision,"option":option,
            "grant_expires_if_issued_now":issued.expires_at,"grant_seconds":policy.delegations()[name].grant_seconds,"worker_run":issued.beneficiary,
            "delegation_expires_at":policy.delegations()[name].expires_at}))
    }).collect::<Result<Vec<_>>>()?;
    view["choices"] = json!(choices);
    // Explain includes all operator options; guests may select only the choices
    // returned above. Remove operator-only options from the guest projection.
    if let Some(options) = view["options"].as_array_mut() {
        options.retain(|option| {
            choices
                .iter()
                .any(|choice| option["id"] == choice["option"])
        });
    }
    Ok(view)
}

/// Persist an attempt before publication. An uncertain send is never replayed.
/// Reconnect uses the authorized canonical list, independently of attention.
pub(crate) async fn notify(runtime: &crate::Runtime, record: &Record) {
    let Some(policy) = runtime.policy.as_ref() else {
        return;
    };
    let mut reviewers = std::collections::BTreeMap::new();
    for delegation in policy.delegations().values() {
        if delegation.dependencies_current(policy)
            && record
                .authority
                .options
                .iter()
                .any(|option| delegation.contains(record, &option.id))
        {
            for reviewer in &delegation.reviewers {
                reviewers
                    .entry(reviewer.agent_id.clone())
                    .or_insert_with(|| {
                        (
                            reviewer.name.clone(),
                            format!("{}:{}", reviewer.agent_id, delegation.revision()),
                        )
                    });
            }
        }
    }
    for (id, (name, delivery_key)) in reviewers {
        let store = runtime.audit.approvals().clone();
        let (approval, recipient) = (record.approval_id.clone(), delivery_key.clone());
        let attempted = tokio::task::spawn_blocking(move || {
            store.claim_reviewer_delivery(&approval, &recipient)
        })
        .await;
        if !matches!(attempted, Ok(Ok(true))) {
            continue;
        }
        let body = format!(
            "SafeYolo delegated approval is pending: {}. This reference grants no authority. Use the existing MCP read_approval tool with approval_id={} or GET /approvals/{} through your own Agent API token. Select only a host-generated choice with resolve_approval. You may approve, reject or defer. The operator can still decide. Reconnect with list_approvals or GET /approvals. Do not include secrets in room messages.",
            record.approval_id, record.approval_id, record.approval_id
        );
        let delivered = runtime.coord.send_approval_notice(&name, &id, &body).await;
        let store = runtime.audit.approvals().clone();
        let approval = record.approval_id.clone();
        let status = if delivered.is_ok() {
            "published"
        } else {
            "unavailable or unknown; canonical list and operator controls remain available"
        };
        let _ = tokio::task::spawn_blocking(move || {
            store.decide(&approval, |record| {
                record.reviewer_delivery.insert(delivery_key, status.into());
                Ok(())
            })
        })
        .await;
    }
}
