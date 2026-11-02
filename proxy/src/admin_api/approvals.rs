//! Operator reads and decisions use canonical request scope. Retained Plumb
//! prompts use their existing audit-backed owner.

use super::*;
use crate::approvals::network_action;
use crate::approvals::pending;

/// Plumb still publishes audit prompts. Other approval types use
/// the canonical store. Select these events before decoding their payloads.
pub(super) fn plumb_prompts(path: &Path) -> Vec<Value> {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::io::BufRead;

    #[derive(serde::Deserialize)]
    struct EventName<'a> {
        #[serde(borrow)]
        event: std::borrow::Cow<'a, str>,
    }

    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();
    let mut events = VecDeque::new();
    let mut sequence = 0usize;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return Vec::new(),
        }
        sequence += 1;
        // Keep the existing 50,000-line window, including malformed and
        // unrelated lines, without retaining their text or JSON values.
        while events
            .front()
            .is_some_and(|(saved, _)| sequence - saved >= 50_000)
        {
            events.pop_front();
        }
        let Ok(name) = serde_json::from_str::<EventName<'_>>(&line) else {
            continue;
        };
        let selected = matches!(
            name.event.as_ref(),
            "plumb.requested" | "plumb.approved" | "plumb.denied"
        );
        if selected && let Ok(event) = serde_json::from_str::<Value>(&line) {
            events.push_back((sequence, event));
        }
    }

    let mut resolved = HashSet::new();
    let mut prompts: HashMap<String, (usize, Value)> = HashMap::new();
    for (sequence, event) in events {
        match event["event"].as_str() {
            Some("plumb.approved" | "plumb.denied") => {
                let Some(id) = event["details"]["request_id"].as_str() else {
                    continue;
                };
                let Some(participants) = event["details"]["participants"].as_array() else {
                    continue;
                };
                let participants = participants
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>();
                if !participants.is_empty() {
                    let key = format!("{id}:{}", participants.join(","));
                    prompts.remove(&key);
                    resolved.insert(key);
                }
            }
            Some("plumb.requested") => {
                if event["approval"]["required"] != true
                    || !event["details"]["approval_id"].is_null()
                    || !matches!(event["approval"]["approval_type"].as_str(), Some("plumb"))
                {
                    continue;
                }
                let (Some(key), Some(target)) = (
                    event["approval"]["key"].as_str(),
                    event["approval"]["target"].as_str(),
                ) else {
                    continue;
                };
                let key = format!("{key}:{target}");
                if !resolved.contains(&key) {
                    prompts.insert(key, (sequence, event));
                }
            }
            _ => {}
        }
    }
    let mut prompts = prompts.into_values().collect::<Vec<_>>();
    prompts.sort_unstable_by_key(|(sequence, _)| *sequence);
    prompts.into_iter().map(|(_, prompt)| prompt).collect()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    decision: network_action::Decision,
    option: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedReads {
    helper: String,
    helper_id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Explanation {
    option: Option<String>,
}

pub(super) async fn respond<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    policy: Option<&Arc<Policy>>,
    audit: Option<&Arc<crate::audit::Writer>>,
    state: Option<&crate::RuntimeState>,
    service_audit: Option<ServiceAudit<'_>>,
) -> Result<Outcome, Error> {
    if let Some(path) = path.strip_suffix("/context") {
        return context(request, path, policy, audit, state).await;
    }
    if let Some(path) = path.strip_suffix("/attention") {
        return attention(request, path, policy, audit, state).await;
    }
    let (path, explain) = path
        .strip_suffix("/explain")
        .map_or((path, false), |path| (path, true));
    let (path, share) = path
        .strip_suffix("/readers")
        .map_or((path, false), |path| (path, true));
    let Some(id) = path
        .strip_prefix("/admin/approvals/")
        .filter(|id| !id.contains('/') && crate::approvals::pending::valid_id(id))
    else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"approval unavailable"}),
        ));
    };
    let (Some(policy), Some(writer)) = (policy, audit) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"approval evidence unavailable; direct policy controls remain available"}),
        ));
    };
    if explain {
        if share || request.method() != Method::POST {
            return Ok(unsupported(request.method()));
        }
        let input = match read_json(request).await? {
            ParsedBody::Value(data) => serde_json::from_value::<Explanation>(data.0.clone()).ok(),
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Some(Explanation { option: None }),
        };
        let Some(input) = input else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"supply only an offered option; explanation scope comes from the canonical approval"}),
            ));
        };
        let (policy, writer, id, state) = (
            Arc::clone(policy),
            writer.clone(),
            id.to_owned(),
            state.cloned(),
        );
        return tokio::task::spawn_blocking(move || {
            let record = match pending::lookup(&writer, &id) {
                Ok(Some(record)) => record,
                Ok(None) => return Ok(response(StatusCode::NOT_FOUND,
                    json!({"error":"canonical approval unavailable; original scope is unknown"}))),
                Err(error) => return Ok(response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":error.to_string()}))),
            };
            Ok(match pending::explain(&writer, &policy, &record, state.as_ref(), input.option.as_deref()) {
                Ok(view) => response(StatusCode::OK, view),
                Err(error) => response(if error.kind == crate::approvals::ErrorKind::Io { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::CONFLICT }, json!({"error":error.to_string()})),
            })
        }).await.map_err(|_| Error::Audit(crate::audit::ErrorKind::Io))?;
    }
    if request.method() == Method::GET && !share {
        let (policy, writer, id, state) = (
            Arc::clone(policy),
            writer.clone(),
            id.to_owned(),
            state.cloned(),
        );
        return tokio::task::spawn_blocking(move || {
            match pending::lookup(&writer, &id) {
                Ok(Some(record)) => return Ok(match pending::inspect(&writer, &policy, &record, state.as_ref()) {
                    Ok(view) => response(StatusCode::OK, view),
                    Err(error) => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":error.to_string()})),
                }),
                Ok(None) if id.starts_with("apr-") => return Ok(response(StatusCode::NOT_FOUND, json!({"error":"approval unavailable"}))),
                Ok(None) => {},
                Err(error) => return Ok(response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":error.to_string()}))),
            }
            Ok(match network_action::record(&writer, &policy, &id) {
                Ok(Some(record)) => response(StatusCode::OK, record.view(&id, true)),
                Ok(None) => response(StatusCode::NOT_FOUND, json!({"error":"approval unavailable"})),
                Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"approval evidence unavailable; direct policy controls remain available"})),
            })
        }).await.map_err(|_| Error::Audit(crate::audit::ErrorKind::Io))?;
    }
    if request.method() != Method::POST {
        return Ok(unsupported(request.method()));
    }
    let data = match read_json(request).await? {
        ParsedBody::Value(data) => data,
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"decision is required"}),
            ));
        }
    };
    let selected = if share {
        let Ok(input) = serde_json::from_value::<SelectedReads>(data.0.clone()) else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"supply only helper and helper_id; selected reads come from the canonical request"}),
            ));
        };
        Some(input)
    } else {
        None
    };
    let resolution = if share {
        None
    } else {
        serde_json::from_value::<Resolution>(data.0.clone()).ok()
    };
    if !share && resolution.is_none() {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"supply decision: approve or reject, and an offered option when required; scope comes from the canonical approval"}),
        ));
    }
    let (Some(state), Some(owner)) = (state, service_audit) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"approval resolver unavailable"}),
        ));
    };
    let (state, writer, id) = (state.clone(), writer.clone(), id.to_owned());
    owner.mutation_owner.spawn_blocking(move || {
        let result = if let Some(input) = selected {
            network_action::share_reads(&state, &writer, &id, &input.helper, &input.helper_id)
        } else if let Some(input) = resolution {
            match pending::resolve(&state, &writer, &id, input.decision, input.option.as_deref()) {
                Ok(Some(result)) => Ok(result),
                Ok(None) if id.starts_with("apr-") => Ok((404, json!({"error":"approval unavailable"}))),
                Ok(None) => Ok((404, json!({"error":"durable approval unavailable; make a new request or use explicit policy controls"}))),
                Err(error) => Ok((if error.kind == crate::approvals::ErrorKind::Io {503} else {409}, json!({"error":error.to_string()}))),
            }
        } else { return Err(Error::ServiceMutation); };
        Ok(match result {
            Ok((status, value)) => response(StatusCode::from_u16(status).map_err(|_| Error::ServiceMutation)?, value),
                Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"resolution unavailable; read canonical outcome before retrying; direct policy controls remain available"})),
        })
    }).await?.await.map_err(|_| Error::ServiceMutation)?
}

/// This endpoint claims only an interruption. It cannot decide an approval.
async fn attention<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    policy: Option<&Arc<Policy>>,
    audit: Option<&Arc<crate::audit::Writer>>,
    state: Option<&crate::RuntimeState>,
) -> Result<Outcome, Error> {
    if request.method() != Method::POST {
        return Ok(unsupported(request.method()));
    }
    let Some(id) = path
        .strip_prefix("/admin/approvals/")
        .filter(|id| !id.contains('/') && pending::valid_id(id))
    else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"approval unavailable"}),
        ));
    };
    let id = id.to_owned();
    match read_json(request).await? {
        ParsedBody::Absent => {}
        ParsedBody::Value(data) if data.0.as_object().is_some_and(|fields| fields.is_empty()) => {}
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        _ => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"attention takes no requester-selected fields"}),
            ));
        }
    }
    let (Some(policy), Some(writer)) = (policy, audit) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"approval state unavailable"}),
        ));
    };
    let (policy, writer, state) = (policy.clone(), writer.clone(), state.cloned());
    tokio::task::spawn_blocking(move || {
        let claim = || -> crate::approvals::Result<_> {
            let Some(record) = writer.approvals().get(&id)? else {
                if let Some(prompt) = plumb_prompts(writer.path()).into_iter().find(|prompt| prompt["request_id"] == id) {
                    let agent = prompt["agent"].as_str().unwrap_or("");
                    if let Some(agent_id) = policy.evidence_agent_id(agent) {
                        let authority_digest = pending::digest(&json!({"agent_id":agent_id,"kind":"plumb","participants":prompt["details"]["participants"],"ttl_seconds":prompt["details"]["ttl_seconds"]}));
                        let notify = writer.approvals().claim_plumb_attention(&id,agent_id,&authority_digest)?;
                        let mut event = crate::audit::Event::new("security.approval_attention",crate::audit::Kind::Security,crate::audit::Severity::Medium,"Plumb approval attention claimed or suppressed");
                        event.agent=Some(agent.into());
                        event.request_id=Some(id.clone());
                        event.details=json!({"approval_id":id,"authority_digest":authority_digest,"recipient":"operator","admitted":notify}).into();
                        let _=tokio::runtime::Handle::current().block_on(writer.emit_confirmed(event));
                        return Ok((notify,None));
                    }
                }
                return Ok((false, None));
            };
            let current = pending::current_view(&writer, &policy, &record, state.as_ref())?;
            if current["status"] != "pending" {
                return Ok((false, None));
            }
            if record.attention.contains_key("operator") {
                return Ok((false, None));
            }
            let notify = writer
                .approvals()
                .claim_attention(&id, "operator", &policy)?;
            let record = writer.approvals().get(&id)?;
            Ok((notify, record))
        };
        Ok(match claim() {
            Ok((notify, record)) => {
                let mut value = json!({"notify":notify,"approval_id":id});
                if let Some(record) = record {
                    value["attention"] = json!(record.attention);
                    if tokio::runtime::Handle::current()
                        .block_on(
                            writer.emit_confirmed(pending::attention::event(&record, "operator")),
                        )
                        .is_err()
                    {
                        value["audit_status"] =
                            json!("unavailable; delivery claim is saved and will not be replayed");
                    }
                }
                response(StatusCode::OK, value)
            }
            Err(error) => response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":error.to_string()}),
            ),
        })
    })
    .await
    .map_err(|_| Error::ServiceMutation)?
}

async fn context<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    policy: Option<&Arc<Policy>>,
    audit: Option<&Arc<crate::audit::Writer>>,
    state: Option<&crate::RuntimeState>,
) -> Result<Outcome, Error> {
    let Some(id) = path
        .strip_prefix("/admin/approvals/")
        .filter(|id| !id.contains('/') && pending::valid_id(id))
    else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"approval unavailable"}),
        ));
    };
    let (Some(policy), Some(writer)) = (policy, audit) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"approval context unavailable; ordinary decisions remain available"}),
        ));
    };
    let ask = request.method() == Method::POST;
    if !ask && request.method() != Method::GET {
        return Ok(unsupported(request.method()));
    }
    if ask {
        match read_json(request).await? {
            ParsedBody::Absent => {}
            ParsedBody::Value(data)
                if data.0.as_object().is_some_and(|fields| fields.is_empty()) => {}
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            _ => {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"context question and recipient come from the canonical approval; send an empty object"}),
                ));
            }
        }
    }
    let (writer, policy, state, id) = (
        writer.clone(),
        Arc::clone(policy),
        state.cloned(),
        id.to_owned(),
    );
    let work_writer = writer.clone();
    let work_policy = policy.clone();
    let work_state = state.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        if ask {
            pending::context::request(&work_writer, &work_policy, work_state.as_ref(), &id)
                .map(|(record, exchange, created)| (record, Some(exchange), created))
        } else {
            pending::lookup(&work_writer, &id)?
                .map(|record| (record, None, false))
                .ok_or_else(|| crate::approvals::ApprovalError {
                    kind: crate::approvals::ErrorKind::Invalid,
                    message: "canonical approval unavailable".into(),
                })
        }
    })
    .await
    .map_err(|_| Error::ServiceMutation)?;
    let (record, exchange, created) = match prepared {
        Ok(value) => value,
        Err(error) => return Ok(context_error(error)),
    };
    if created {
        let coord = state
            .as_ref()
            .and_then(|state| state.read().ok().map(|runtime| runtime.coord.clone()));
        let delivery = if let Some(coord) = coord {
            let question =
                pending::context::question(&record, exchange.as_ref().expect("new exchange"));
            match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                coord.send_approval_notice(
                    record.authority.action["agent"].as_str().unwrap_or(""),
                    record.authority.action["agent_id"].as_str().unwrap_or(""),
                    &question,
                ),
            )
            .await
            {
                Ok(Ok(_)) => "sent",
                Ok(Err(error)) if !error.unknown => "unavailable",
                _ => "unknown",
            }
        } else {
            "unavailable"
        };
        let (work_writer, work_record) = (writer.clone(), record.clone());
        let context_id = exchange.as_ref().expect("new exchange").context_id.clone();
        tokio::task::spawn_blocking(move || {
            pending::context::delivery(&work_writer, &work_record, &context_id, delivery)
        })
        .await
        .map_err(|_| Error::ServiceMutation)?
        .map_err(|_| Error::ServiceMutation)?;
    }
    let (work_writer, work_record) = (writer.clone(), record.clone());
    let value = tokio::task::spawn_blocking(move || {
        pending::context::view(&work_writer, &policy, &work_record, state.as_ref())
    })
    .await
    .map_err(|_| Error::ServiceMutation)?;
    let value = match value {
        Ok(value) => value,
        Err(error) => return Ok(context_error(error)),
    };
    if ask
        && writer
            .emit_confirmed(pending::context::event(&record, &value, false))
            .await
            .is_err()
    {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"context audit unavailable; read context before retrying; approval is unchanged"}),
        ));
    }
    Ok(response(
        if created {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        value,
    ))
}

fn context_error(error: crate::approvals::ApprovalError) -> Outcome {
    response(
        if error.kind == crate::approvals::ErrorKind::Io {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::CONFLICT
        },
        json!({"error":error.to_string()}),
    )
}

pub(super) async fn delegations<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    policy: Option<&Arc<Policy>>,
    state: Option<&crate::RuntimeState>,
    owner: Option<ServiceAudit<'_>>,
) -> Result<Outcome, Error> {
    let (Some(policy), Some(state)) = (policy, state) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"native policy unavailable"}),
        ));
    };
    if request.method() == Method::GET && path == "/admin/approval-delegations" {
        let issued = policy.delegation_grants();
        let gateway = state
            .read()
            .ok()
            .and_then(|r| r.gateway_grants.clone())
            .and_then(|s| s.list_grants(time::OffsetDateTime::now_utc()).ok());
        return Ok(response(
            StatusCode::OK,
            json!({"delegations":policy.delegations().iter().map(|(name,d)| json!({"name":name,"revision":d.revision(),"active":d.current() && d.dependencies_current(policy),"delegation":d})).collect::<Vec<_>>(),"issued_access":issued,"gateway_grants":gateway}),
        ));
    }
    let Some((name, operation)) = path
        .strip_prefix("/admin/approval-delegations/")
        .and_then(|p| p.split_once('/'))
    else {
        return Ok(response(
            StatusCode::NOT_FOUND,
            json!({"error":"delegation operation unavailable"}),
        ));
    };
    if !crate::host_platform::valid_agent_name(name)
        || !matches!(operation, "preview" | "apply" | "revoke")
        || request.method() != Method::POST
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"use a named delegation and preview, apply or revoke"}),
        ));
    }
    let data = match read_json(request).await? {
        ParsedBody::Value(value) => value,
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"proposal is required"}),
            ));
        }
    };
    let (name, operation, state, policy) = (
        name.to_owned(),
        operation.to_owned(),
        state.clone(),
        Arc::clone(policy),
    );
    let Some(owner) = owner else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"mutation owner unavailable"}),
        ));
    };
    let writer = owner.writer.clone();
    owner.mutation_owner.spawn_blocking(move || {
        let before_revision = data.0["expected_revision"].clone();
        let result=if operation=="revoke" {
            #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Revoke { expected_revision:String }
            match serde_json::from_value::<Revoke>(data.0.clone()) {
                Ok(input)=>crate::approvals::delegations::revoke(&state,&name,&input.expected_revision),
                Err(_)=>Err(crate::approvals::invalid("supply only expected_revision")),
            }
        } else {
            match serde_json::from_value::<crate::approvals::delegations::Proposal>(data.0.clone()) {
                Ok(input) if operation=="apply"=>crate::approvals::delegations::apply(&state,&name,input),
                Ok(input)=>crate::approvals::delegations::preview(&policy,&name,&input,&state),
                Err(_)=>Err(crate::approvals::invalid("invalid delegation proposal; unknown fields and unsupported bounds are rejected")),
            }
        };
        Ok(match result { Ok(mut value)=>{
            if operation != "preview" {
                let mut event=crate::audit::Event::new("admin.approval_delegation_changed",crate::audit::Kind::Admin,crate::audit::Severity::High,format!("Approval delegation {name} {operation}"));
                event.details=json!({"delegation":name,"operation":operation,"before_revision":before_revision,"revision":value["revision"]}).into();
                if tokio::runtime::Handle::current().block_on(writer.emit_confirmed(event)).is_err() {
                    value["audit_status"]=json!("unavailable; the delegation change is saved. Inspect current state before retrying.");
                }
            }
            response(StatusCode::OK,value)
        },Err(e)=>response(StatusCode::CONFLICT,json!({"error":e.to_string()})) })
    }).await?.await.map_err(|_| Error::ServiceMutation)?
}
