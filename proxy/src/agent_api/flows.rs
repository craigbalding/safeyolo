//! Authorized flow reads use the process store and the reconciled ingress owner.
//! Queries preserve the source method-specific validation order. Direct reads
//! require the authoritative evidence_owner before loading/decompressing bodies.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hyper::body::Body;
use num_bigint::{BigInt, ToBigInt};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::{Failure, Outcome, Request, RequestBody, agent, declarations, response};
use crate::{
    circuits::CircuitValue,
    flow_store::{self, ErrorKind, FlowStore, Side},
};

/// Content-free failure categories; no filters, database paths or bodies escape
/// through diagnostics. Compatibility remains distinct from a source exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowFailure {
    Store(ErrorKind),
    Type,
    Attribute,
    Value,
    Overflow,
    Worker,
    QueryCompatibility,
    JsonCompatibility,
    DispatchInteger,
}

#[derive(Clone, Copy)]
pub(super) enum Route {
    NotFound,
    Search,
    Endpoints,
    Facets,
    ResponseSearch,
    RequestSearch,
    Diff,
    TagAdd(Id),
    TagDelete(Id),
    Detail(Id),
    Body(Id, Side),
}
#[derive(Clone, Copy)]
pub(super) enum Id {
    Sql(i64),
    Overflow,
    ConversionError,
}

pub(super) fn recognize(request: Request<'_>) -> Option<Route> {
    let path = super::route(request);
    match path {
        "/api/flows/search" => return Some(Route::Search),
        "/api/flows/diff" if request.method == "POST" => return Some(Route::Diff),
        "/api/flows/endpoints" if request.method == "POST" => return Some(Route::Endpoints),
        "/api/flows/facets" if request.method == "POST" => return Some(Route::Facets),
        "/api/flows/body-search" if request.method == "POST" => return Some(Route::ResponseSearch),
        "/api/flows/request-body-search" if request.method == "POST" => {
            return Some(Route::RequestSearch);
        }
        "/api/flows/diff"
        | "/api/flows/endpoints"
        | "/api/flows/facets"
        | "/api/flows/body-search"
        | "/api/flows/request-body-search" => return Some(Route::NotFound),
        _ => {}
    }
    // Python's route uses Unicode decimal \d and $, which accepts one terminal
    // LF. Percent-escaped digits are not decoded at this routing boundary.
    let rest = path.strip_prefix("/api/flows/")?;
    // A tag name's [^/]+ capture includes a final LF; plain route suffixes
    // instead use the regex $ allowance for one terminal LF.
    let tag_suffix = rest
        .split_once('/')
        .map(|(_, suffix)| suffix)
        .filter(|suffix| suffix.starts_with("tag/"));
    let rest = if tag_suffix.is_some() {
        rest
    } else {
        rest.strip_suffix('\n').unwrap_or(rest)
    };
    let (digits, suffix) = match rest.split_once('/') {
        Some((_, "")) => return Some(Route::NotFound),
        value => value.unwrap_or((rest, "")),
    };
    let tag_name = suffix
        .strip_prefix("tag/")
        .filter(|name| !name.is_empty() && !name.contains('/'));
    if digits.is_empty()
        || (!matches!(suffix, "" | "request-body" | "response-body" | "tag") && tag_name.is_none())
    {
        return Some(Route::NotFound);
    }
    let mut number = Some(0_i64);
    let mut count = 0;
    for ch in digits.chars() {
        let Some(digit) = crate::python_text::decimal(ch) else {
            return Some(Route::NotFound);
        };
        count += 1;
        number = number.and_then(|value| value.checked_mul(10)?.checked_add(i64::from(digit)));
    }
    let id = if count > 4300 {
        // Source int() is evaluated outside the handler exception boundary.
        Id::ConversionError
    } else {
        number.map_or(Id::Overflow, Id::Sql)
    };
    // Even a disallowed tag method reaches int(route ID) before dispatch.
    if matches!(id, Id::ConversionError) {
        return Some(Route::Detail(id));
    }
    Some(match suffix {
        "tag" if request.method == "POST" => Route::TagAdd(id),
        _ if tag_name.is_some() && request.method == "DELETE" => Route::TagDelete(id),
        "tag" => Route::NotFound,
        _ if tag_name.is_some() => Route::NotFound,
        "request-body" => Route::Body(id, Side::Request),
        "response-body" => Route::Body(id, Side::Response),
        _ => Route::Detail(id),
    })
}

pub(super) async fn respond<B>(
    route: Route,
    request: Request<'_>,
    store: Option<&Arc<FlowStore>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    if matches!(route, Route::NotFound) {
        return Ok(response(
            404,
            json!({"error":"Not Found", "endpoints":super::ENDPOINTS}),
        ));
    }
    if matches!(
        route,
        Route::Detail(Id::ConversionError) | Route::Body(Id::ConversionError, _)
    ) {
        return Ok(super::unavailable(
            request,
            Failure::FlowReporting(FlowFailure::DispatchInteger),
        ));
    }
    let Some(store) = store else {
        return Ok(response(503, json!({"error":"Flow store not available"})));
    };
    let filters = match route {
        Route::Detail(_) | Route::Body(..) => None,
        Route::TagDelete(_) => {
            let name = super::route(request)
                .split_once("/tag/")
                .expect("recognized tag route")
                .1;
            Some(Filters(CircuitValue::Other(Value::String(name.into()))))
        }
        Route::Search if request.method == "GET" => match query(request) {
            Ok(value) => Some(value),
            Err(failure) => {
                return Ok(if agent(request.identity).is_none() {
                    response(403, json!({"error":"Could not identify agent"}))
                } else {
                    failed(request, failure)
                });
            }
        },
        _ => {
            let content = declarations::read_content(body).await?;
            let content = match content {
                Ok(content) => content,
                Err(error) => return Ok(declarations::content_error(error)),
            };
            let parsed = if content.is_empty() {
                Some(CircuitValue::Object(Default::default()))
            } else if let Ok(text) = crate::python_json::decode_json_text(&content) {
                match CircuitValue::parse_api_json(&text) {
                    Ok(value) => Some(value),
                    Err(error) if error.kind() == crate::circuits::ErrorKind::Value => {
                        return Ok(failed(request, FlowFailure::Value));
                    }
                    Err(error) if error.kind() == crate::circuits::ErrorKind::Compatibility => {
                        return Ok(failed(request, FlowFailure::JsonCompatibility));
                    }
                    Err(_) => None,
                }
            } else {
                None
            };
            let Some(value) =
                parsed.filter(|value| !matches!(value, CircuitValue::Other(Value::Null)))
            else {
                return Ok(response(400, json!({"error":"Invalid JSON body"})));
            };
            Some(Filters(value))
        }
    };
    let owner = agent(request.identity).map(|value| Zeroizing::new(value.to_owned()));
    let store = Arc::clone(store);
    let result = tokio::task::spawn_blocking(move || {
        execute(&store, route, owner.as_deref().map(String::as_str), filters)
    })
    .await;
    Ok(match result {
        Ok(Ok(reply)) => {
            let mut outcome = response(reply.status, Value::Null);
            outcome.response.body = reply.body;
            outcome
        }
        Ok(Err(failure)) => failed(request, failure),
        Err(_) => failed(request, FlowFailure::Worker),
    })
}

// The worker can outlive a canceled request. Its inputs and unclaimed result
// retain wiping owners until completion; SQL/decompression never block Tokio.
struct Json(Value);
impl Drop for Json {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.0);
    }
}
struct Reply {
    status: u16,
    body: super::ResponseBody<'static>,
}
impl Reply {
    fn new(status: u16, value: Value) -> Self {
        Self {
            status,
            body: super::ResponseBody::Json(value),
        }
    }
    fn error(status: u16, message: &str) -> Self {
        Self::new(status, json!({"error":message}))
    }
    fn missing() -> Self {
        Self::error(404, "Flow not found")
    }
}
struct Filters(CircuitValue);
impl Drop for Filters {
    fn drop(&mut self) {
        let mut pending = vec![std::mem::replace(&mut self.0, CircuitValue::Bool(false))];
        while let Some(mut value) = pending.pop() {
            match &mut value {
                CircuitValue::Object(values) => {
                    for (mut key, value) in std::mem::take(values) {
                        key.zeroize();
                        pending.push(value);
                    }
                }
                CircuitValue::Array(values) => pending.append(values),
                CircuitValue::Other(value) => crate::credentials::wipe_json(value),
                _ => {}
            }
        }
    }
}

fn query(request: Request<'_>) -> Result<Filters, FlowFailure> {
    let clean = Zeroizing::new(
        request
            .path_and_query
            .chars()
            .filter(|ch| !matches!(ch, '\t' | '\r' | '\n'))
            .collect::<String>(),
    );
    let query = clean
        .split('#')
        .next()
        .unwrap()
        .split_once('?')
        .map_or("", |(_, tail)| tail);
    let mut output = Filters(CircuitValue::Object(Default::default()));
    let CircuitValue::Object(values) = &mut output.0 else {
        unreachable!()
    };
    for part in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let super::Decoded::Scalar(key) = super::unquote(key) else {
            return Err(FlowFailure::QueryCompatibility);
        };
        let mut key = Zeroizing::new(key);
        if values.contains_key(key.as_str()) {
            continue;
        }
        // The source replaces this supplied value with trusted identity before
        // any query consumes it, including a value containing surrogateescape.
        if key.as_str() == "evidence_owner" {
            continue;
        }
        let super::Decoded::Scalar(value) = super::unquote(value) else {
            return Err(FlowFailure::QueryCompatibility);
        };
        values.insert(
            std::mem::take(&mut *key),
            CircuitValue::Other(Value::String(value)),
        );
    }
    Ok(output)
}

fn execute(
    store: &FlowStore,
    route: Route,
    owner: Option<&str>,
    mut filters: Option<Filters>,
) -> Result<Reply, FlowFailure> {
    match route {
        Route::Diff => diff(
            store,
            owner,
            &filters.as_ref().expect("diff input parsed").0,
        ),
        Route::TagAdd(id) | Route::TagDelete(id) => tag(
            store,
            route,
            id,
            owner,
            &filters.as_ref().expect("tag input parsed").0,
        ),
        Route::Detail(id) | Route::Body(id, _) => {
            let id = match id {
                Id::Sql(id) => id,
                _ => return Err(FlowFailure::Overflow),
            };
            let Some(metadata) = store.get_flow(id).map_err(store_error)? else {
                return Ok(Reply::missing());
            };
            let mut metadata = Json(Value::Object(metadata));
            // Never fall back to the legacy agent_id of an owner-null v2 row.
            if owner.is_none() || metadata.0.get("evidence_owner").and_then(Value::as_str) != owner
            {
                return Ok(Reply::missing());
            }
            let Route::Body(_, side) = route else {
                return Ok(Reply::new(200, metadata.0.take()));
            };
            let Some(mut body) = store.body(id, side).map_err(store_error)? else {
                return Ok(Reply::missing());
            };
            let mut result = Json(Value::Object(std::mem::take(&mut body.metadata)));
            let fields = result.0.as_object_mut().unwrap();
            fields.insert(
                "body_base64".into(),
                Value::String(STANDARD.encode(&body.body)),
            );
            fields.insert("body_length".into(), Value::from(body.body.len()));
            let content_type = match side {
                Side::Request => "request_content_type",
                Side::Response => "response_content_type",
            };
            if flow_store::is_text_like_content_type(
                fields.get(content_type).unwrap_or(&Value::Null),
            )
            .map_err(store_error)?
            {
                fields.insert(
                    "body_text".into(),
                    Value::String(String::from_utf8_lossy(&body.body).into_owned()),
                );
            }
            Ok(Reply::new(200, result.0.take()))
        }
        _ => {
            let filters = &mut filters.as_mut().expect("collection input parsed").0;
            let object = filters.as_object();
            if matches!(route, Route::Search) && object.is_none() {
                return Ok(Reply::error(400, "Search filters must be a JSON object"));
            }
            if matches!(route, Route::Endpoints | Route::Facets) && object.is_none() {
                return Ok(Reply::error(400, "Invalid JSON body"));
            }
            if matches!(route, Route::RequestSearch | Route::ResponseSearch) {
                let Some(object) = object else {
                    return Ok(Reply::error(400, "Invalid JSON body"));
                };
                if !object
                    .get("engagement_id")
                    .is_some_and(CircuitValue::truthy)
                {
                    return Ok(Reply::error(400, "engagement_id required"));
                }
                if !object.get("query").is_some_and(CircuitValue::truthy) {
                    return Ok(Reply::error(400, "query required"));
                }
            }
            let Some(owner) = owner else {
                return Ok(Reply::error(403, "Could not identify agent"));
            };
            let CircuitValue::Object(object) = filters else {
                return Err(FlowFailure::Type);
            };
            if let Some(previous) = object.insert(
                "evidence_owner".into(),
                CircuitValue::Other(Value::String(owner.into())),
            ) {
                drop(Filters(previous));
            }
            let result = match route {
                Route::Search => store.search_flows(filters),
                Route::Endpoints => store.get_endpoints(filters),
                Route::Facets => store.get_facets(filters),
                Route::RequestSearch => store.search_request_bodies(filters),
                Route::ResponseSearch => store.search_bodies(filters),
                _ => unreachable!(),
            };
            let results = match result {
                Ok(value) => value,
                Err(error) => {
                    if matches!(route, Route::Search | Route::Facets)
                        && let Some(message) = error.validation_message()
                    {
                        return Ok(Reply::error(400, message));
                    }
                    return Err(FlowFailure::Store(error.kind()));
                }
            };
            let body = match route {
                Route::Facets => json!({"facets":results}),
                Route::Endpoints => {
                    let count = results.as_array().expect("endpoint list").len();
                    json!({"endpoints":results,"count":count})
                }
                _ => {
                    let count = results.as_array().expect("flow list").len();
                    json!({"flows":results,"count":count})
                }
            };
            Ok(Reply::new(200, body))
        }
    }
}
// Body IDs use source int() before either ownership read. SQLite range is
// checked only when that specific ID's read is reached.
fn body_id(value: &CircuitValue) -> Result<Id, FlowFailure> {
    let number = match value {
        CircuitValue::Bool(value) => BigInt::from(u8::from(*value)),
        CircuitValue::Float(value) if value.is_infinite() => return Err(FlowFailure::Overflow),
        CircuitValue::Float(value) => value.to_bigint().ok_or(FlowFailure::Value)?,
        value @ (CircuitValue::Integer(_) | CircuitValue::Other(Value::String(_))) => {
            flow_store::integer(value).ok_or(FlowFailure::Value)?
        }
        _ => return Err(FlowFailure::Type),
    };
    Ok(i64::try_from(number).map_or(Id::Overflow, Id::Sql))
}
fn owned(store: &FlowStore, id: Id, owner: Option<&str>) -> Result<Option<i64>, FlowFailure> {
    let Id::Sql(id) = id else {
        return Err(FlowFailure::Overflow);
    };
    let Some(metadata) = store.get_flow(id).map_err(store_error)? else {
        return Ok(None);
    };
    let metadata = Json(Value::Object(metadata));
    Ok(
        (owner.is_some() && metadata.0.get("evidence_owner").and_then(Value::as_str) == owner)
            .then_some(id),
    )
}
fn diff(
    store: &FlowStore,
    owner: Option<&str>,
    input: &CircuitValue,
) -> Result<Reply, FlowFailure> {
    let converted = || {
        let fields = input.as_object().ok_or(FlowFailure::Type)?;
        let left = body_id(fields.get("flow_id_a").ok_or(FlowFailure::Value)?)?;
        let right = body_id(fields.get("flow_id_b").ok_or(FlowFailure::Value)?)?;
        Ok::<_, FlowFailure>((left, right))
    };
    let (left, right) = match converted() {
        Ok(ids) => ids,
        Err(FlowFailure::Type | FlowFailure::Value) => {
            return Ok(Reply::error(
                400,
                "flow_id_a and flow_id_b (integers) required",
            ));
        }
        Err(error) => return Err(error),
    };
    let Some(left) = owned(store, left, owner)? else {
        return Ok(Reply::error(404, "One or both flows not found"));
    };
    let Some(right) = owned(store, right, owner)? else {
        return Ok(Reply::error(404, "One or both flows not found"));
    };
    Ok(match store.diff_flows(left, right).map_err(store_error)? {
        Some(value) => Reply::new(200, value),
        None => Reply::error(404, "One or both flows not found"),
    })
}
fn tag(
    store: &FlowStore,
    route: Route,
    id: Id,
    owner: Option<&str>,
    input: &CircuitValue,
) -> Result<Reply, FlowFailure> {
    match route {
        Route::TagAdd(_) => {
            let Some(fields) = input.as_object() else {
                return Ok(Reply::error(400, "Invalid JSON body"));
            };
            let Some(tag) = fields.get("tag").filter(|value| value.truthy()) else {
                return Ok(Reply::error(400, "tag required"));
            };
            let Some(id) = owned(store, id, owner)? else {
                return Ok(Reply::missing());
            };
            let default_value = CircuitValue::Other(Value::String(String::new()));
            let value = fields.get("value").unwrap_or(&default_value);
            let result = Filters(
                store
                    .tag_flow(id, tag, value, crate::policy::current_time_ms() as i64)
                    .map_err(store_error)?,
            );
            let text = result
                .0
                .render_json(false)
                .map_err(|_| FlowFailure::JsonCompatibility)?;
            Ok(Reply {
                status: 200,
                body: super::ResponseBody::Circuit(Zeroizing::new(text)),
            })
        }
        Route::TagDelete(_) => {
            let Some(id) = owned(store, id, owner)? else {
                return Ok(Reply::missing());
            };
            let CircuitValue::Other(Value::String(name)) = input else {
                unreachable!("parsed tag name")
            };
            // urllib.unquote uses replacement UTF-8 and preserves literal +.
            let name = percent_encoding::percent_decode_str(name)
                .decode_utf8_lossy()
                .into_owned();
            let mut tag = Filters(CircuitValue::Other(Value::String(name)));
            if !store.untag_flow(id, &tag.0).map_err(store_error)? {
                return Ok(Reply::error(404, "Tag not found"));
            }
            let CircuitValue::Other(value) = &mut tag.0 else {
                unreachable!()
            };
            Ok(Reply::new(
                200,
                json!({"deleted":true,"flow_id":id,"tag":value.take()}),
            ))
        }
        _ => unreachable!("tag route"),
    }
}
fn store_error(error: flow_store::Error) -> FlowFailure {
    FlowFailure::Store(error.kind())
}
fn failed(request: Request<'_>, failure: FlowFailure) -> Outcome<'static> {
    let class = match failure {
        FlowFailure::Type | FlowFailure::Store(ErrorKind::Type) => "TypeError",
        FlowFailure::Attribute | FlowFailure::Store(ErrorKind::Attribute) => "AttributeError",
        FlowFailure::Value | FlowFailure::Store(ErrorKind::Value) => "ValueError",
        FlowFailure::Overflow | FlowFailure::Store(ErrorKind::Overflow) => "OverflowError",
        FlowFailure::Store(ErrorKind::BadGzip) => "BadGzipFile",
        FlowFailure::Store(ErrorKind::UnexpectedEof) => "EOFError",
        FlowFailure::Store(ErrorKind::Deflate) => "error",
        FlowFailure::Store(ErrorKind::Database) => "DatabaseError",
        FlowFailure::Store(ErrorKind::Integrity) => "IntegrityError",
        FlowFailure::Store(ErrorKind::Operational) => "OperationalError",
        FlowFailure::Store(ErrorKind::Programming) => "ProgrammingError",
        FlowFailure::Store(ErrorKind::Poisoned) => "RuntimeError",
        FlowFailure::Store(
            ErrorKind::SchemaVersion | ErrorKind::Compatibility | ErrorKind::Compression,
        )
        | FlowFailure::Worker
        | FlowFailure::QueryCompatibility
        | FlowFailure::JsonCompatibility
        | FlowFailure::DispatchInteger => {
            return super::unavailable(request, Failure::FlowReporting(failure));
        }
    };
    let mut result = response(500, json!({"error":format!("Internal error: {class}")}));
    result.failure = Some(Failure::FlowReporting(failure));
    result
}
