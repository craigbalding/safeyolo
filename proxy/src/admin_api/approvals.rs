//! Operator reads retain canonical request scope across credential retries.

use super::*;
use crate::approvals::network_action;
use crate::approvals::pending;

pub(super) fn credential_view<'a>(
    events: impl IntoIterator<Item = &'a Value>,
    id: &str,
) -> Result<Option<Value>, &'static str> {
    let matching: Vec<_> = events
        .into_iter()
        .filter(|event| {
            event["request_id"] == id
                && event["event"] == "security.credential_guard"
                && event["approval"]["approval_type"] == "credential"
        })
        .collect();
    let Some(first) = matching.first() else {
        return Ok(None);
    };
    if matching
        .iter()
        .any(|event| event.pointer("/details/approval_id").is_some())
    {
        return Err(
            "canonical approval state unavailable; audit text cannot replace its authority",
        );
    }
    let agent = first["agent"]
        .as_str()
        .ok_or("credential request has no agent")?;
    let agent_id = first["details"]["agent_id"].as_str().ok_or("credential request predates identity binding; use direct credential policy controls or make a new request")?;
    let host = first["approval"]["target"]
        .as_str()
        .ok_or("credential request has no destination")?;
    let mut credentials = Vec::new();
    for event in &matching {
        if event["agent"] != agent
            || event["details"]["agent_id"] != agent_id
            || event["approval"]["target"] != host
        {
            return Err("credential request has conflicting scope; use direct policy controls");
        }
        let key = event["approval"]["key"]
            .as_str()
            .filter(|key| key.starts_with("hmac:") && key.len() > 5)
            .ok_or("credential request has no fingerprint")?;
        if !credentials.iter().any(|saved| saved == key) {
            credentials.push(key.to_owned());
        }
    }
    credentials.sort();
    Ok(Some(json!({"request_id":id,"status":"pending",
        "action":{"kind":"credential_allow","agent":agent,"agent_id":agent_id,"host":host,"credentials":credentials},
        "effect":format!("Allow these credential fingerprints to {} for all agents in this instance, including future agents. This changes shared persistent policy until explicitly removed. Existing network rules still apply.", crate::network_guard::sanitize(host))})))
}

// The retained audit supplies the selected request's original identity. The
// pending reducer supplies its current state; a newer representative is usable
// only when its entire action still matches that original identity.
pub(super) fn credential_record(
    writer: &crate::audit::Writer,
    policy: &Policy,
    id: &str,
) -> Result<Option<Value>, &'static str> {
    let mut document = writer
        .approval_events(id)
        .map_err(|_| "credential approval evidence unavailable")?;
    let rendered = document.render_json(false);
    crate::audit::wipe(&mut document);
    let rendered =
        Zeroizing::new(rendered.map_err(|_| "credential approval evidence unavailable")?);
    let events = Json(
        serde_json::from_str(&rendered).map_err(|_| "credential approval evidence unavailable")?,
    );
    let Some(mut view) = credential_view(
        events
            .0
            .as_array()
            .ok_or("credential approval evidence unavailable")?,
        id,
    )?
    else {
        return Ok(None);
    };
    let current = read_audit_events(writer.path());
    let pending = pending_approval_events(&current);
    let action = &view["action"];
    let mut matches = policy.evidence_agent_id(
        action["agent"]
            .as_str()
            .ok_or("credential request has no agent")?,
    ) == action["agent_id"].as_str();
    for credential in action["credentials"]
        .as_array()
        .ok_or("credential request has no fingerprints")?
    {
        let representative = pending.as_array().and_then(|events| {
            events.iter().find(|event| {
                event["event"] == "security.credential_guard"
                    && event["approval"]["key"] == *credential
                    && event["approval"]["target"] == action["host"]
            })
        });
        matches &= match representative.and_then(|event| event["request_id"].as_str()) {
            Some(current_id) => credential_view(&current, current_id)?
                .is_some_and(|current| current["action"] == *action),
            None => false,
        };
    }
    if !matches {
        view["status"] = json!("stale");
        view["effect"] = json!(
            "This credential request is resolved or changed, or its current evidence is unavailable. Inspect the pending requests again before deciding."
        );
    }
    Ok(Some(view))
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

pub(super) async fn respond<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    policy: Option<&Policy>,
    audit: Option<&Arc<crate::audit::Writer>>,
    state: Option<&crate::RuntimeState>,
    service_audit: Option<ServiceAudit<'_>>,
) -> Result<Outcome, Error> {
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
    if request.method() == Method::GET && !share {
        let (policy, writer, id, state) = (
            policy.clone(),
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
            match credential_record(&writer, &policy, &id) {
                Ok(Some(view)) => return Ok(response(StatusCode::OK, view)),
                Ok(None) => {},
                Err(error) => {
                    // A credential evidence failure cannot hide a committed
                    // network grant. Audit-only records cannot supply this fallback.
                    return Ok(match network_action::committed_record(&policy, &id) {
                        Ok(Some(record)) => response(StatusCode::OK, record.view(&id, true)),
                        _ => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":error})),
                    });
                },
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
