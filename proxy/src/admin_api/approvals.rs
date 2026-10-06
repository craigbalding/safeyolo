//! All operator consumers resolve the immutable network request here.

use super::*;
use crate::approvals::network_action;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    decision: network_action::Decision,
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
        .filter(|id| !id.contains('/') && crate::agent_api::valid_request_id(id))
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
        let (policy, writer, id) = (policy.clone(), writer.clone(), id.to_owned());
        return tokio::task::spawn_blocking(move || {
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
            json!({"error":"supply only decision: approve or reject; scope comes from the canonical request"}),
        ));
    }
    let (Some(state), Some(owner)) = (state, service_audit) else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"native approval resolver unavailable"}),
        ));
    };
    let (state, writer, id) = (state.clone(), writer.clone(), id.to_owned());
    owner.mutation_owner.spawn_blocking(move || {
        let result = if let Some(input) = selected {
            network_action::share_reads(&state, &writer, &id, &input.helper, &input.helper_id)
        } else if let Some(input) = resolution {
            network_action::resolve(&state, &writer, &id, input.decision)
        } else { return Err(Error::ServiceMutation); };
        Ok(match result {
            Ok((status, value)) => response(StatusCode::from_u16(status).map_err(|_| Error::ServiceMutation)?, value),
                Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"resolution unavailable; read canonical outcome before retrying; direct policy controls remain available"})),
        })
    }).await?.await.map_err(|_| Error::ServiceMutation)?
}
