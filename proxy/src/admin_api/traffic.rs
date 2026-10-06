//! Authorized access to the process-owned live traffic view.

use super::{Audit, Error, Json, Outcome, ParsedBody, TrafficScopeAudit, read_json, response};
use crate::traffic_view::{ExportError, ExportFormat, FilterError, Side, TrafficView};
use bytes::Bytes;
use hyper::{Method, Request, StatusCode, body::Body};
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use std::sync::Arc;

const MAX_BODY_PREVIEW_BYTES: usize = 64 * 1024;

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
            Ok(scope) => {
                let mut outcome = updated_scope(scope);
                outcome.audit = Some(Audit::TrafficScopeUpdated(TrafficScopeAudit {
                    fields: data.0.clone(),
                }));
                outcome
            }
            Err(error) => response(StatusCode::BAD_REQUEST, json!({"error":error})),
        });
    }
    if request.method() == Method::PUT && path == "/admin/traffic/filter" {
        return update_filter(request, view.clone()).await;
    }
    if request.method() != Method::GET {
        return Ok(not_found());
    }
    let value = match path {
        "/admin/traffic/scope" => Some(view.scope()),
        "/admin/traffic/flows" => {
            let view = view.clone();
            let selected = request.uri().query().map(selected_scope).transpose();
            let selected = match selected {
                Ok(selected) => selected,
                Err(()) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid explicit traffic selection"}),
                    ));
                }
            };
            // Decoding and regex searches can read anonymous message files.
            // The model snapshots first, then evaluates outside its view lock.
            return tokio::task::spawn_blocking(move || {
                match selected.map_or_else(
                    || view.flows(),
                    |(scope, filter)| view.selected_flows(&scope, &filter),
                ) {
                    Ok(flows) => response(StatusCode::OK, flows),
                    Err(error) => filter_error(error),
                }
            })
            .await
            .map_err(|_| Error::TrafficReporting);
        }
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
            if let Some(id) = tail.strip_suffix("/export") {
                let Ok(id) = percent_decode_str(id).decode_utf8() else {
                    return Ok(invalid_flow_id());
                };
                let id = id.into_owned();
                let Some(format) = export_format(request.uri().query()) else {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"format must be raw, raw_request, raw_response, curl, httpie, har, or zhar"}),
                    ));
                };
                let selected = match export_selection(request.uri().query()) {
                    Ok(selected) => selected,
                    Err(()) => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            json!({"error":"invalid explicit export selection"}),
                        ));
                    }
                };
                let view = view.clone();
                let plan = tokio::task::spawn_blocking(move || match selected {
                    None => view.export(&id, format),
                    Some(agent) => view.selected_export(&id, format, agent.as_deref()),
                })
                .await
                .map_err(|_| Error::TrafficReporting)?;
                return Ok(match plan {
                    Ok(plan) => super::export_response(plan),
                    Err(error) => export_error(error),
                });
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
                match body_preview_bytes(request.uri().query()) {
                    Ok(Some(limit)) => view.body_preview(&id, side, limit),
                    Ok(None) => view.body(&id, side),
                    Err(()) => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            json!({"error":"preview_bytes must be between 0 and 65536"}),
                        ));
                    }
                }
            } else {
                view.detail(&id)
            }
        }
    };
    Ok(optional_response(value))
}

fn selected_scope(query: &str) -> Result<(Value, String), ()> {
    let mut scope = serde_json::Map::new();
    let mut filter = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or(())?;
        let value = percent_decode_str(value)
            .decode_utf8()
            .map_err(|_| ())?
            .into_owned();
        match key {
            "filter" if filter.is_none() => filter = Some(value),
            "unattributed"
                if !scope.contains_key(key) && matches!(value.as_str(), "true" | "false") =>
            {
                scope.insert(key.into(), json!(value == "true"));
            }
            "agent" | "test_id" | "intent" | "role" | "expect" if !scope.contains_key(key) => {
                scope.insert(key.into(), json!(value));
            }
            _ => return Err(()),
        }
    }
    Ok((Value::Object(scope), filter.unwrap_or_default()))
}

fn body_preview_bytes(query: Option<&str>) -> Result<Option<usize>, ()> {
    let mut limit = None;
    for value in query
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| pair.strip_prefix("preview_bytes="))
    {
        if limit.is_some() {
            return Err(());
        }
        let parsed = value.parse::<usize>().map_err(|_| ())?;
        if parsed > MAX_BODY_PREVIEW_BYTES {
            return Err(());
        }
        limit = Some(parsed);
    }
    Ok(limit)
}

fn export_format(query: Option<&str>) -> Option<ExportFormat> {
    let query = query?;
    let mut found = None;
    for pair in query.split('&') {
        let Some(value) = pair.strip_prefix("format=") else {
            continue;
        };
        let value = percent_decode_str(value).decode_utf8().ok()?;
        if found.is_some() {
            return None;
        }
        found = Some(ExportFormat::parse(&value)?);
    }
    found
}

fn export_selection(query: Option<&str>) -> Result<Option<Option<String>>, ()> {
    let mut selected = None;
    for pair in query.unwrap_or("").split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if !matches!(key, "agent" | "selection") {
            continue;
        }
        if selected.is_some() {
            return Err(());
        }
        let value = percent_decode_str(value).decode_utf8().map_err(|_| ())?;
        selected = Some(match key {
            "agent" if !value.is_empty() => Some(value.into_owned()),
            "selection" if value == "all" => None,
            _ => return Err(()),
        });
    }
    Ok(selected)
}

fn export_error(error: ExportError) -> Outcome {
    let status = match error {
        ExportError::MissingFlow => StatusCode::NOT_FOUND,
        ExportError::MissingRequest
        | ExportError::MissingResponse
        | ExportError::MissingBody
        | ExportError::Decode
        | ExportError::Unsupported => StatusCode::UNPROCESSABLE_ENTITY,
        ExportError::Storage | ExportError::Allocation => StatusCode::INTERNAL_SERVER_ERROR,
    };
    response(status, json!({"error":error.to_string()}))
}

async fn update_filter<B: Body<Data = Bytes>>(
    request: Request<B>,
    view: Arc<TrafficView>,
) -> Result<Outcome, Error> {
    let data = match read_json(request).await? {
        ParsedBody::Terminal(outcome) => return Ok(outcome),
        ParsedBody::Absent => Json(Value::Null),
        ParsedBody::Value(data) => data,
    };
    let Some(object) = data.0.as_object() else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"request body must be a JSON object"}),
        ));
    };
    if object.len() != 1 || !object.contains_key("user_filter") {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"request body must contain only user_filter"}),
        ));
    }
    if !object["user_filter"].is_string() {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            json!({"error":"user_filter must be a string"}),
        ));
    }
    // Compile before publication on a blocking worker. Both its input and
    // response retain wiping owners even when the awaiting request is canceled.
    tokio::task::spawn_blocking(move || {
        match view.set_user_filter(data.0["user_filter"].as_str().expect("validated string")) {
            Ok(scope) => updated_scope(scope),
            Err(error) => filter_error(error),
        }
    })
    .await
    .map_err(|_| Error::TrafficReporting)
}

fn updated_scope(mut scope: Value) -> Outcome {
    let mut result = serde_json::Map::new();
    result.insert("status".into(), json!("updated"));
    result.extend(std::mem::take(scope.as_object_mut().expect("scope object")));
    response(StatusCode::OK, Value::Object(result))
}

fn filter_error(error: FilterError) -> Outcome {
    let status = match error {
        FilterError::Invalid => StatusCode::BAD_REQUEST,
        FilterError::Unsupported | FilterError::Compatibility => StatusCode::NOT_IMPLEMENTED,
        FilterError::Runtime
        | FilterError::DecodeType
        | FilterError::Allocation
        | FilterError::Storage => StatusCode::INTERNAL_SERVER_ERROR,
    };
    response(status, json!({"error":error.to_string()}))
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

#[cfg(test)]
mod har_tests;
