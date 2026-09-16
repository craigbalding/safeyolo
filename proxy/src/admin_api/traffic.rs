//! Authorized access to the process-owned live traffic view.

use super::{Audit, Error, Json, Outcome, ParsedBody, TrafficScopeAudit, read_json, response};
use crate::traffic_view::{Side, TrafficView};
use bytes::Bytes;
use hyper::{Method, Request, StatusCode, body::Body};
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::sync::Arc;

// Pagination bounds one JSON response, without limiting retained messages.
const MESSAGE_PAGE_BYTES: usize = 64 * 1024;

pub(super) async fn respond<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    view: Option<&Arc<TrafficView>>,
) -> Result<Outcome, Error> {
    let Some(view) = view else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"traffic scope addon is unavailable"}),
        ));
    };
    if request.method() == Method::PUT && path == "/admin/traffic/scope" {
        let data = match read_json(request).await? {
            ParsedBody::Terminal(outcome) => return Ok(outcome),
            ParsedBody::Absent => Json(Value::Null),
            ParsedBody::Value(data) => data,
        };
        if !data.0.is_object() {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                json!({"error":"request body must be a JSON object"}),
            ));
        }
        return Ok(match view.set_scope(&data.0) {
            Ok(mut scope) => {
                let mut result = serde_json::Map::new();
                result.insert("status".into(), json!("updated"));
                result.extend(std::mem::take(scope.as_object_mut().expect("scope object")));
                let mut outcome = response(StatusCode::OK, Value::Object(result));
                outcome.audit = Some(Audit::TrafficScopeUpdated(TrafficScopeAudit {
                    fields: data.0.clone(),
                }));
                outcome
            }
            Err(error) => response(StatusCode::BAD_REQUEST, json!({"error":error})),
        });
    }
    if request.method() != Method::GET {
        return Ok(not_found());
    }
    let value = match path {
        "/admin/traffic/scope" => Some(view.scope()),
        "/admin/traffic/flows" => Some(view.flows()),
        "/admin/traffic/facets" => Some(view.facets()),
        _ => {
            let Some(tail) = path.strip_prefix("/admin/traffic/flows/") else {
                return Ok(not_found());
            };
            if let Some((id, message)) = tail.rsplit_once("/websocket/messages/") {
                let Some(message) = message.strip_suffix("/body") else {
                    return Ok(not_found());
                };
                return websocket_body(view.clone(), id, message, request.uri().query()).await;
            }
            if let Some(id) = tail.strip_suffix("/websocket/messages") {
                let Ok(id) = percent_decode_str(id).decode_utf8() else {
                    return Ok(invalid_flow_id());
                };
                return Ok(optional_response(view.websocket_messages(&id)));
            }
            let (id, body) = tail
                .strip_suffix("/body")
                .map_or((tail, false), |id| (id, true));
            let Ok(id) = percent_decode_str(id).decode_utf8() else {
                return Ok(invalid_flow_id());
            };
            if body {
                let side = request
                    .uri()
                    .query()
                    .unwrap_or("")
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("side="));
                let side = match side {
                    Some("request") => Side::Request,
                    Some("response") => Side::Response,
                    _ => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            json!({"error":"side must be request or response"}),
                        ));
                    }
                };
                view.body(&id, side)
            } else {
                view.detail(&id)
            }
        }
    };
    Ok(optional_response(value))
}

async fn websocket_body(
    view: Arc<TrafficView>,
    id: &str,
    message: &str,
    query: Option<&str>,
) -> Result<Outcome, Error> {
    let Ok(id) = percent_decode_str(id).decode_utf8() else {
        return Ok(invalid_flow_id());
    };
    let id = id.into_owned();
    let Ok(message) = message.parse::<u64>() else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"invalid message id"}),
        ));
    };
    let offset = query
        .unwrap_or("")
        .split('&')
        .find_map(|pair| pair.strip_prefix("offset="))
        .unwrap_or("0");
    let Some(offset) = percent_decode_str(offset)
        .decode_utf8()
        .ok()
        .and_then(|offset| offset.parse::<u64>().ok())
    else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"offset must be a non-negative integer"}),
        ));
    };
    // A message may use an anonymous file. Read its page outside the async
    // connection executor; the core releases its view lock before file I/O.
    // Return the wiping response owner even if the awaiting request is canceled.
    tokio::task::spawn_blocking(move || {
        optional_response(view.websocket_message_body(&id, message, offset, MESSAGE_PAGE_BYTES))
    })
    .await
    .map_err(|_| Error::TrafficReporting)
}

fn invalid_flow_id() -> Outcome {
    response(
        StatusCode::BAD_REQUEST,
        json!({"error":"invalid flow id encoding"}),
    )
}

fn optional_response(value: Option<Value>) -> Outcome {
    value.map_or_else(not_found, |value| response(StatusCode::OK, value))
}

fn not_found() -> Outcome {
    response(StatusCode::NOT_FOUND, json!({"error":"not found"}))
}

#[cfg(test)]
mod tests;
