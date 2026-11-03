//! Operator reads of pending signal metadata and exact immutable revisions.
use super::{Error, Outcome, response};
use bytes::Bytes;
use hyper::{Method, Request, StatusCode, body::Body};
use serde_json::json;
use std::collections::BTreeMap;

pub(super) async fn respond<B: Body<Data = Bytes>>(
    request: Request<B>,
    path: &str,
    state: Option<&crate::RuntimeState>,
) -> Result<Outcome, Error> {
    if request.method() != Method::GET {
        return Ok(response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"Method Not Allowed","allowed":["GET"]}),
        ));
    }
    let Some(state) = state else {
        return Ok(response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"runtime unavailable"}),
        ));
    };
    let mut query = BTreeMap::new();
    for pair in request
        .uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|v| !v.is_empty())
    {
        let Some((key, value)) = pair.split_once('=') else {
            return Ok(bad_query());
        };
        let Ok(value) = percent_encoding::percent_decode_str(value).decode_utf8() else {
            return Ok(bad_query());
        };
        if !["revision", "after", "limit", "room_id"].contains(&key)
            || query.insert(key, value.into_owned()).is_some()
        {
            return Ok(bad_query());
        }
    }
    let id = match path.strip_prefix("/admin/coord/signals/") {
        Some(id) if !id.is_empty() && !id.contains('/') => {
            match percent_encoding::percent_decode_str(id).decode_utf8() {
                Ok(id) => Some(id.into_owned()),
                Err(_) => return Ok(bad_query()),
            }
        }
        Some(_) => {
            return Ok(response(
                StatusCode::NOT_FOUND,
                json!({"error":"endpoint not found"}),
            ));
        }
        None => None,
    };
    let revision = match query.get("revision").map(|s| s.parse::<i64>()).transpose() {
        Ok(value) if value.is_none_or(|r| r > 0) => value,
        _ => return Ok(bad_query()),
    };
    let limit = match query
        .get("limit")
        .map_or("50", String::as_str)
        .parse::<usize>()
    {
        Ok(value) => value,
        _ => return Ok(bad_query()),
    };
    let result = crate::agent_api::coord::signals::operator_read(
        state,
        id,
        revision,
        query.get("after").cloned().unwrap_or_default(),
        limit,
        query.get("room_id").cloned(),
    )
    .await;
    Ok(match result {
        Ok(value) => response(StatusCode::OK, value),
        Err(error) => response(
            StatusCode::from_u16(error.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            json!({"error":error.1}),
        ),
    })
}
fn bad_query() -> Outcome {
    response(
        StatusCode::BAD_REQUEST,
        json!({"error":"invalid signal query"}),
    )
}
