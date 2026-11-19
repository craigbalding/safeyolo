//! Local diagnostic reads use current support authority and private receipts.
use crate::{
    Error, RuntimeState, audit,
    host_runs::AgentRun,
    policy::{Policy, support::Grant},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};

const RETAIN_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Filter {
    pub sources: Vec<String>,
    pub subject_ids: Vec<String>,
    pub events: Vec<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub runtime_id: Option<String>,
    pub run_id: Option<String>,
    pub request_id: Option<String>,
    pub connection_id: Option<String>,
    pub failures_only: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Query {
    pub operation_id: String,
    pub grant: String,
    #[serde(default)]
    pub filter: Filter,
    #[serde(default = "page_limit")]
    pub limit: usize,
    pub page_token: Option<String>,
}
fn page_limit() -> usize {
    100
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC timestamp")
}

fn authorize(policy: &Policy, run: &AgentRun, name: &str) -> Result<Grant, Error> {
    let instance = super::instance_id()?;
    let grant=policy.support_grants().remove(name).filter(|g|g.active() && g.instance_id==instance && g.diagnostics.is_some()
        && super::Caller::local(run).matches(policy,g)
        && g.targets.iter().all(|a|policy.evidence_agent_id(&a.name)==Some(&a.agent_id)))
        .ok_or_else(||super::refuse(403,"current diagnostic disclosure required; discover evidence and request the missing scope"))?;
    Ok(grant)
}

pub(crate) fn discover(state: &RuntimeState, run: &AgentRun) -> Result<Value, Error> {
    let policy = super::current_policy(state)?;
    if !run.current(&policy) {
        return Err(super::refuse(
            403,
            "current authenticated requester run required",
        ));
    }
    let instance = super::instance_id()?;
    let readable:Vec<_>=policy.support_grants().into_iter().filter(|(_,g)|g.diagnostics.is_some() && g.instance_id==instance && super::Caller::local(run).matches(&policy,g))
        .map(|(name,g)|json!({"grant":name,"disclosure":g,"readable":authorize(&policy,run,&name).is_ok()})).collect();
    Ok(
        json!({"instance_id":instance,"requester":run,"readable":readable,
        "requestable":{"subjects":"Explicit local agent names are resolved to durable identities by the owner; select your own name for own logs.",
            "sources":["audit","runtime","coord_history","coord_membership","coord_attention","coord_health","audit_health"],
            "lifetimes":["snapshot","selected_expiry","until_revoked"],
            "history":"Select since/until RFC3339 timestamps independently of access expiry. future=true requires until=null and is unavailable for snapshots. Null since means all retained history.",
            "run_selection":"Optional runs maps selected durable subject IDs to sandbox run IDs; absent or empty selects all provably attributed retained runs.",
            "room_selection":"Select exact room IDs and history, membership and recipient-attention permissions separately. Existing room receive rights also remain usable through normal Coord tools."},
        "snapshot_retention_seconds":RETAIN_SECONDS,"collection_limit":{"rows":2000,"bytes":MAX_BYTES,"page":200},
        "limitations":"Name-only historical audit records cannot establish durable ownership and are excluded. System categories return typed health facts, never arbitrary nested references. Room history is untrusted content and may mention unrelated peers. Current runtime and membership are observations, not reconstructed history. No permission is added by discovery.",
        "next_action":"Use request_diagnostic_access, read_approval, then query_diagnostic_evidence. Inspect or narrow/revoke through the owning operator's support grant controls. Notifications carry private references; direct reads need no notification."}),
    )
}

pub(crate) async fn request(
    state: &RuntimeState,
    writer: &Arc<audit::Writer>,
    run: &AgentRun,
    input: crate::approvals::pending::diagnostics::Request,
) -> Result<Value, Error> {
    let config = crate::operator_actions::config_path(state)?;
    crate::host_platform::in_config(config,async {
        let policy=super::current_policy(state)?;
        let record=crate::approvals::pending::diagnostics::submit(writer,&policy,run,input)?;
        let runtime=state.read().map_err(|_|"runtime unavailable")?.clone();
        let mut event=audit::Event::new("agent.diagnostic_access_requested",audit::Kind::Agent,audit::Severity::Low,"Agent requested diagnostic disclosure");
        event.agent=Some(run.agent.clone());event.request_id=Some(record.request_id.clone());
        event.details=json!({"approval_id":record.approval_id,"requester":run,"authority_digest":record.authority_digest,"disclosure":record.authority.action["grant"],
            "instance_id":record.authority.action["grant"]["instance_id"],"runtime_id":runtime.instance_id,"sandbox_run":run}).into();
        let audit_available=writer.emit_confirmed(event).await.is_ok();
        crate::approvals::pending::delegation::notify(&runtime,&record).await;
        let mut view=record.view(&policy)?;
        view["audit_available"]=json!(audit_available);
        view["next_action"]=json!("Read this canonical approval directly. Pending or rejected requests grant no evidence. After approval use its grant ID for diagnostic queries.");
        Ok(view)
    }).await
}

fn validate(query: &Query, grant: &Grant) -> Result<(), Error> {
    use crate::policy::support::diagnostics::timestamp;
    let scope = grant.diagnostics.as_ref().expect("diagnostic grant");
    let f = &query.filter;
    if !super::operations::valid_operation_id(&query.operation_id)
        || !(1..=200).contains(&query.limit)
        || f.sources.iter().any(|s| {
            !matches!(
                s.as_str(),
                "audit"
                    | "runtime"
                    | "coord_history"
                    | "coord_membership"
                    | "coord_attention"
                    | "coord_health"
                    | "audit_health"
            )
        })
        || f.subject_ids
            .iter()
            .any(|id| !grant.targets.iter().any(|a| &a.agent_id == id))
        || f.events.iter().any(|event| {
            !event.contains('.')
                || event.len() > 128
                || !event
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._".contains(&b))
        })
        || [&f.since, &f.until]
            .iter()
            .any(|v| v.as_deref().is_some_and(|v| timestamp(v).is_none()))
        || (f.since.is_some()
            && f.until.is_some()
            && f.since.as_deref().and_then(timestamp) > f.until.as_deref().and_then(timestamp))
        || (f.since.as_deref().and_then(timestamp).is_some_and(|t| {
            scope
                .history
                .since
                .as_deref()
                .and_then(timestamp)
                .is_some_and(|s| t < s)
        }))
        || (f.until.as_deref().and_then(timestamp).is_some_and(|t| {
            scope
                .history
                .until
                .as_deref()
                .and_then(timestamp)
                .is_some_and(|s| t > s)
        }))
        || (f.request_id.is_some() || f.connection_id.is_some()) && f.runtime_id.is_none()
        || [&f.runtime_id, &f.run_id, &f.request_id, &f.connection_id]
            .iter()
            .any(|v| v.as_ref().is_some_and(|v| v.is_empty() || v.len() > 128))
    {
        return Err(super::refuse(
            400,
            "unsupported, malformed or out-of-scope diagnostic filter; correlation requires its runtime namespace",
        ));
    }
    if f.sources
        .iter()
        .any(|source| !source_allowed(source, scope, None))
    {
        return Err(super::refuse(
            403,
            "the selected evidence source is outside this diagnostic disclosure; request its explicit scope",
        ));
    }
    Ok(())
}

fn source_allowed(
    source: &str,
    scope: &crate::policy::support::diagnostics::Scope,
    room: Option<&str>,
) -> bool {
    match source {
        "audit" => scope.audit,
        "runtime" => scope.runtime,
        "coord_history" => scope
            .rooms
            .iter()
            .any(|r| r.history && room.is_none_or(|id| r.room_id == id)),
        "coord_membership" => scope
            .rooms
            .iter()
            .any(|r| r.membership && room.is_none_or(|id| r.room_id == id)),
        "coord_attention" => scope
            .rooms
            .iter()
            .any(|r| r.attention && room.is_none_or(|id| r.room_id == id)),
        system => scope.system_categories.iter().any(|s| s == system),
    }
}

fn permitted_row(row: &Value, grant: &Grant) -> bool {
    let scope = grant.diagnostics.as_ref().unwrap();
    let source = row["source"].as_str().unwrap_or("");
    if !source_allowed(source, scope, row["room_id"].as_str()) {
        return false;
    }
    if let Some(id) = row["subject_id"].as_str() {
        if !grant.targets.iter().any(|a| a.agent_id == id) {
            return false;
        }
        if let Some(runs) = scope.runs.get(id)
            && !runs.is_empty()
        {
            let run = if source == "runtime" {
                row["record"]["observation"]["run_id"].as_str()
            } else {
                row["record"]["details"]["sandbox_run"]["run_id"].as_str()
            };
            if run.is_none_or(|run| !runs.iter().any(|r| r == run)) {
                return false;
            }
        }
    }
    !matches!(
        source,
        "audit" | "audit_health" | "coord_history" | "coord_attention"
    ) || row["record"]["ts"]
        .as_str()
        .is_some_and(|t| scope.contains_time(t))
}

fn path(run: &AgentRun, key: &str) -> Result<PathBuf, Error> {
    let directory = super::audit_delivery::directory("support-diagnostics")?;
    // A bounded receipt, never a second audit archive. Expired data is removed
    // on diagnostic use. The canonical approval preserves a snapshot marker.
    for entry in std::fs::read_dir(&directory)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("diagnostic-")
            && entry.path().extension().is_some_and(|v| v == "json")
            && let Ok(Some(value)) =
                crate::guest_commands::read_state_bounded(&entry.path(), MAX_BYTES)
            && value["retain_until"]
                .as_i64()
                .is_some_and(|time| time <= now())
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(directory.join(format!(
        "diagnostic-{}.json",
        crate::approvals::pending::digest(&json!([run.agent_id, key]))
    )))
}

fn matches_filter(row: &Value, f: &Filter) -> bool {
    use crate::policy::support::diagnostics::timestamp;
    let record = &row["record"];
    (f.sources.is_empty() || f.sources.iter().any(|s| row["source"] == *s))
        && (f.subject_ids.is_empty() || f.subject_ids.iter().any(|s| row["subject_id"] == *s))
        && (f.events.is_empty() || f.events.iter().any(|s| record["event"] == *s))
        && f.since.as_deref().and_then(timestamp).is_none_or(|since| {
            record["ts"]
                .as_str()
                .and_then(timestamp)
                .is_some_and(|t| t >= since)
        })
        && f.until.as_deref().and_then(timestamp).is_none_or(|until| {
            record["ts"]
                .as_str()
                .and_then(timestamp)
                .is_some_and(|t| t <= until)
        })
        && f.runtime_id
            .as_ref()
            .is_none_or(|id| record["details"]["runtime_id"] == *id)
        && f.run_id
            .as_ref()
            .is_none_or(|id| record["details"]["sandbox_run"]["run_id"] == *id)
        && f.request_id
            .as_ref()
            .is_none_or(|id| record["request_id"] == *id)
        && f.connection_id.as_ref().is_none_or(|id| {
            [
                "client_connection_id",
                "parent_connection_id",
                "upstream_connection_id",
            ]
            .iter()
            .any(|key| record["details"][key] == *id)
        })
        && (!f.failures_only
            || matches!(
                record["decision"].as_str(),
                Some("deny" | "require_approval" | "budget_exceeded")
            )
            || record["severity"] == "high"
            || record["severity"] == "critical")
}

async fn collect(state: &RuntimeState, writer: &Arc<audit::Writer>, grant: &Grant) -> Value {
    let scope = grant.diagnostics.as_ref().expect("diagnostic grant");
    let mut sources = Vec::new();
    if scope.audit
        || scope
            .system_categories
            .iter()
            .any(|category| category == "audit_health")
    {
        let writer = writer.clone();
        let grant = grant.clone();
        let audit = tokio::task::spawn_blocking(move || {
            crate::audit::disclosure::read(
                &writer,
                &grant.instance_id,
                &grant.targets,
                grant.diagnostics.as_ref().unwrap(),
            )
        })
        .await;
        sources.push(audit.unwrap_or(json!({"source":"audit","status":"unavailable","rows":[],"limitations":["audit reader worker unavailable"]})));
    }
    if scope.runtime {
        for subject in &grant.targets {
            let result = match crate::host_agents::list().and_then(|agents| {
                crate::host_agents::by_id(&agents, &subject.agent_id).map(|a| a.cloned())
            }) {
                Ok(Some(agent)) => crate::host_commands::diagnostics(&agent)
                    .await
                    .map(|v| super::operations::inspection(&v)),
                Ok(None) => Err("selected subject configuration unavailable".into()),
                Err(e) => Err(e),
            };
            sources.push(match result {
                Ok(record)=>json!({"source":"runtime","subject_id":subject.agent_id,"status":"observed","rows":[{"source":"runtime","subject_id":subject.agent_id,"record":{"ts":iso_now(),"observation":record}}],"limitations":["current control observation; historical runtime states are not reconstructed"]}),
                Err(_)=>json!({"source":"runtime","subject_id":subject.agent_id,"status":"unavailable","rows":[],"limitations":["selected runtime control observation unavailable"]}),
            });
        }
    }
    let client = state.read().ok().map(|s| s.coord.clone());
    if !scope.rooms.is_empty() || scope.system_categories.iter().any(|s| s == "coord_health") {
        if let Some(client) = client {
            sources.extend(client.diagnostic_evidence(grant).await);
        } else {
            sources.push(json!({"source":"coord","status":"unavailable","rows":[]}));
        }
    }
    let mut rows = Vec::new();
    let mut statuses = Vec::new();
    let mut bytes = 0;
    let mut truncated = false;
    for mut source in sources {
        if let Some(items) = source
            .as_object_mut()
            .and_then(|s| s.remove("rows"))
            .and_then(|s| s.as_array().cloned())
        {
            for row in items {
                let len = row.to_string().len();
                if rows.len() >= 2000 || bytes + len > 3 * 1024 * 1024 {
                    truncated = true;
                    continue;
                }
                bytes += len;
                rows.push(row);
            }
        }
        statuses.push(source);
    }
    json!({"rows":rows,"sources":statuses,"truncated":truncated,"collected_at":iso_now()})
}

pub(crate) async fn query(
    state: &RuntimeState,
    writer: &Arc<audit::Writer>,
    run: &AgentRun,
    input: Query,
) -> Result<Value, Error> {
    let policy = super::current_policy(state)?;
    let grant = authorize(&policy, run, &input.grant)?;
    validate(&input, &grant)?;
    let snapshot = grant.diagnostics.as_ref().unwrap().snapshot;
    let key = if snapshot {
        format!("snapshot:{}", input.grant)
    } else {
        format!("query:{}:{}", input.grant, input.operation_id)
    };
    let path = path(run, &key)?;
    let lock =
        crate::host_platform::try_lock_host_state(&path.with_extension("lock")).map_err(|_| {
            super::refuse(
                409,
                "diagnostic collection in progress; retry this exact request",
            )
        })?;
    let expected = crate::approvals::pending::digest(&json!([
        run.agent_id,
        input.grant,
        grant.revision(),
        input.filter
    ]));
    let existing = crate::guest_commands::read_state_bounded(&path, MAX_BYTES)?;
    let mut receipt = if let Some(receipt) = existing {
        let original: Grant = serde_json::from_value(receipt["scope"].clone())?;
        if !crate::approvals::pending::diagnostics::grant_subset(&grant, &original)
            || (!snapshot
                && receipt["query_digest"] != expected
                && receipt["grant_revision"] == grant.revision())
        {
            return Err(super::refuse(
                409,
                "diagnostic selection changed; do not reuse this collection",
            ));
        }
        receipt
    } else {
        if input.page_token.is_some() {
            return Err(super::refuse(
                410,
                "diagnostic collection unavailable; a continuation cannot collect replacement evidence",
            ));
        }
        if snapshot {
            let mut first = false;
            writer
                .approvals()
                .decide(&input.grant, |record| {
                    if record.result.get("diagnostic_snapshot").is_none() {
                        record.result["diagnostic_snapshot"] =
                            json!({"started_at":now(),"retain_until":now()+RETAIN_SECONDS});
                        first = true;
                    }
                    Ok(())
                })?
                .ok_or_else(|| {
                    super::refuse(410, "canonical snapshot authorization unavailable")
                })?;
            if !first {
                return Err(super::refuse(
                    410,
                    "snapshot data was lost or expired; the original selection will not be recollected",
                ));
            }
        }
        let mut receipt = json!({"state":"collecting","grant":input.grant,"grant_revision":grant.revision(),"requester":run,"query_digest":expected,
            "retain_until":now()+RETAIN_SECONDS,"collection_id":uuid::Uuid::new_v4().to_string(),"scope":grant});
        crate::guest_commands::write_json(&path, &receipt)?;
        receipt["evidence"] = collect(state, writer, &grant).await;
        receipt["state"] = json!("complete");
        let encoded_bytes = receipt.to_string().len();
        if encoded_bytes > MAX_BYTES as usize {
            let mut excess = encoded_bytes - MAX_BYTES as usize + 64;
            while excess > 0 {
                let Some(row) = receipt["evidence"]["rows"]
                    .as_array_mut()
                    .and_then(Vec::pop)
                else {
                    return Err(super::refuse(
                        413,
                        "diagnostic selection metadata exceeds the private collection limit; request a narrower selection",
                    ));
                };
                excess = excess.saturating_sub(row.to_string().len() + 1);
            }
            receipt["evidence"]["truncated"] = json!(true);
        }
        crate::guest_commands::write_json(&path, &receipt)?;
        receipt
    };
    if receipt["state"] != "complete" {
        return Err(super::refuse(
            503,
            "original collection is incomplete; evidence will not be silently replaced",
        ));
    }
    if receipt["retain_until"]
        .as_i64()
        .is_none_or(|time| time <= now())
    {
        return Err(super::refuse(
            410,
            "diagnostic collection retention expired",
        ));
    }
    let rows = receipt["evidence"]["rows"]
        .as_array()
        .ok_or("diagnostic collection invalid")?;
    let selected: Vec<_> = rows
        .iter()
        .filter(|row| permitted_row(row, &grant) && matches_filter(row, &input.filter))
        .collect();
    let binding = crate::approvals::pending::digest(&json!([
        receipt["collection_id"],
        expected,
        input.limit
    ]));
    let offset = match input.page_token.as_deref() {
        None => 0,
        Some(token) => {
            let (prefix, offset) = token
                .split_once(':')
                .ok_or_else(|| super::refuse(403, "invalid diagnostic continuation"))?;
            let offset = offset
                .parse::<usize>()
                .map_err(|_| super::refuse(403, "invalid diagnostic continuation"))?;
            if prefix != binding || offset > selected.len() {
                return Err(super::refuse(
                    403,
                    "diagnostic continuation belongs to different authority or filters",
                ));
            }
            offset
        }
    };
    let page = selected
        .iter()
        .skip(offset)
        .take(input.limit)
        .copied()
        .collect::<Vec<_>>();
    let end = offset + page.len();
    let current = authorize(&super::current_policy(state)?, run, &input.grant)?;
    if current.revision() != grant.revision() {
        return Err(super::refuse(
            403,
            "diagnostic authority changed during the read",
        ));
    }
    let scope = grant.diagnostics.as_ref().unwrap();
    let statuses: Vec<_> = receipt["evidence"]["sources"]
        .as_array()
        .ok_or("diagnostic source status unavailable")?
        .iter()
        .filter(|source| {
            let allowed = match source["source"].as_str() {
                Some("audit") => {
                    scope.audit || scope.system_categories.iter().any(|c| c == "audit_health")
                }
                Some("coord") => scope.rooms.iter().any(|r| source["room_id"] == r.room_id),
                Some(name) => source_allowed(name, scope, None),
                None => false,
            };
            allowed
                && source["subject_id"]
                    .as_str()
                    .is_none_or(|id| grant.targets.iter().any(|a| a.agent_id == id))
        })
        .cloned()
        .collect();
    let result = if statuses.iter().any(|s| s["status"] == "unavailable") {
        "source_unavailable"
    } else if receipt["evidence"]["truncated"] == true
        || statuses
            .iter()
            .any(|s| matches!(s["status"].as_str(), Some("incomplete_search" | "limited")))
    {
        "incomplete_search"
    } else if selected.is_empty() {
        "no_matching_retained_evidence"
    } else {
        "retained_evidence"
    };
    let output = json!({"instance_id":grant.instance_id,"grant":input.grant,"requester":run,"applied_scope":grant,"filter":input.filter,
        "rows":page,"total_matches":selected.len(),"offset":offset,"next_page_token":if end<selected.len(){Some(format!("{binding}:{end}"))}else{None},
        "sources":statuses,"collected_at":receipt["evidence"]["collected_at"],"truncated":receipt["evidence"]["truncated"],
        "retain_until":receipt["retain_until"],"collection_id":receipt["collection_id"],"snapshot":snapshot,
        "result":result});
    // Result bytes never enter an ordinary audit summary or attention.
    let mut event = audit::Event::new(
        "agent.diagnostic_evidence_read",
        audit::Kind::Agent,
        audit::Severity::Low,
        "Agent read approved diagnostic evidence",
    );
    event.agent = Some(run.agent.clone());
    event.details=json!({"requester":run,"grant":input.grant,"grant_revision":grant.revision(),"collection_id":receipt["collection_id"],"returned":page.len(),"offset":offset,
        "instance_id":grant.instance_id,"runtime_id":state.read().ok().map(|runtime|runtime.instance_id.clone()),"sandbox_run":run}).into();
    let _ = writer.emit(event);
    receipt.as_object_mut().unwrap().remove("evidence");
    drop(lock);
    Ok(output)
}
