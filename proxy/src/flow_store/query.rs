//! Source-compatible retained-flow selections over the existing connection.
//!
//! Authorization belongs to the caller, which supplies `evidence_owner` from
//! trusted identity. Endpoint/body filters deliberately retain the source's lax
//! behavior; metadata search and facets validate their documented filter sets.

use std::{cmp::Ordering, fmt};

use indexmap::IndexMap;
use num_bigint::BigInt;
use rusqlite::{Connection, params_from_iter, types::Value as SqlValue};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use super::{Error, ErrorKind, FlowStore, SqlParams, row_map, sql_value};
use crate::{
    circuits::CircuitValue,
    policy::python_whitespace,
    python_text::{decimal, uppercase},
};

/// Validation text is available only for the caller's source-compatible 400.
/// Diagnostics never display filters, SQL parameters, or stored flow content.
pub enum QueryError {
    Validation(String),
    Store(Error),
}
impl QueryError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Validation(_) => ErrorKind::Value,
            Self::Store(error) => error.kind(),
        }
    }
    pub fn validation_message(&self) -> Option<&str> {
        match self {
            Self::Validation(message) => Some(message),
            Self::Store(_) => None,
        }
    }
}
impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("flow query failed")
    }
}
impl fmt::Debug for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.kind(), f)
    }
}
impl std::error::Error for QueryError {}
impl From<Error> for QueryError {
    fn from(error: Error) -> Self {
        Self::Store(error)
    }
}
impl From<rusqlite::Error> for QueryError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}
type Result<T> = std::result::Result<T, QueryError>;

const EXACT: &[&str] = &[
    "engagement_id",
    "agent_id",
    "evidence_owner",
    "trusted_transport_identity",
    "initiator",
    "attribution_status",
    "run",
    "test",
    "role",
    "test_agent",
    "suite",
    "subject",
    "step",
    "intent",
    "expect",
    "host",
    "method",
    "status_code",
    "flow_state",
    "source_type",
];
const TEXT: &[&str] = &[
    "path_contains",
    "text_contains",
    "response_header_contains",
    "request_header_contains",
    "tag",
    "path",
    "q",
    "status_class",
];
const INTEGER: &[&str] = &[
    "status_code",
    "status_min",
    "status_max",
    "from_ts",
    "to_ts",
    "limit",
    "offset",
];
const DIMENSIONS: &[&str] = &[
    "agent_id",
    "evidence_owner",
    "trusted_transport_identity",
    "initiator",
    "attribution_status",
    "test",
    "intent",
    "expect",
];
const SUMMARY: &str = "id, request_id, ts_start, ts_end, duration_ms,
 engagement_id, agent_id, evidence_owner, trusted_transport_identity, initiator,
 attribution_status, attribution_provenance_json, source_id,
 run, test, role, test_agent, suite, subject, step, intent, expect,
 source_type, flow_state, method, host, path, query_string, full_url, status_code, reason,
 request_content_type, response_content_type, is_websocket, request_body_size, response_body_size,
 request_body_truncated, response_body_truncated, response_body_text_preview";
const FTS_SUMMARY: &str = "f.id, f.request_id, f.ts_start, f.duration_ms,
 f.engagement_id, f.agent_id, f.evidence_owner, f.trusted_transport_identity, f.initiator,
 f.attribution_status, f.attribution_provenance_json, f.run, f.test, f.role, f.test_agent,
 f.suite, f.subject, f.step, f.intent, f.expect, f.method, f.host, f.path, f.status_code, f.flow_state";

fn invalid(message: impl Into<String>) -> QueryError {
    QueryError::Validation(message.into())
}
fn failure(kind: ErrorKind) -> QueryError {
    Error(kind).into()
}

type Filters = IndexMap<String, CircuitValue>;

fn text(value: &CircuitValue) -> Option<&str> {
    match value {
        CircuitValue::Other(Value::String(value)) => Some(value),
        _ => None,
    }
}
fn text_value(value: impl Into<String>) -> CircuitValue {
    CircuitValue::Other(Value::String(value.into()))
}
fn is_null(value: &CircuitValue) -> bool {
    matches!(value, CircuitValue::Other(Value::Null))
}
fn wipe(value: &mut CircuitValue) {
    let mut pending = vec![std::mem::replace(value, CircuitValue::Other(Value::Null))];
    while let Some(mut value) = pending.pop() {
        match &mut value {
            CircuitValue::Other(value) => crate::credentials::wipe_json(value),
            CircuitValue::Array(values) => pending.append(values),
            CircuitValue::Object(values) => {
                for (mut key, value) in std::mem::take(values) {
                    key.zeroize();
                    pending.push(value);
                }
            }
            _ => {}
        }
    }
}
fn binding(value: &CircuitValue) -> Result<SqlValue> {
    Ok(match value {
        CircuitValue::Float(value) => SqlValue::Real(*value),
        CircuitValue::Integer(value) => SqlValue::Integer(
            value
                .to_string()
                .parse()
                .map_err(|_| failure(ErrorKind::Overflow))?,
        ),
        CircuitValue::Bool(value) => SqlValue::Integer(i64::from(*value)),
        CircuitValue::Other(value) => sql_value(value)?,
        _ => return Err(failure(ErrorKind::Programming)),
    })
}

struct Normalized(Filters);
impl Drop for Normalized {
    fn drop(&mut self) {
        for (mut key, mut value) in std::mem::take(&mut self.0) {
            key.zeroize();
            wipe(&mut value);
        }
    }
}

/// Python int(str), using the existing pinned decimal table. Integer JSON
/// tokens retain arbitrary precision until SQLite binding (or the source cap).
pub(crate) fn integer(value: &CircuitValue) -> Option<BigInt> {
    match value {
        CircuitValue::Integer(value) => Some(value.clone()),
        CircuitValue::Other(Value::String(value)) => {
            let value = value.trim_matches(char::is_whitespace);
            let negative = value.starts_with('-');
            let value = value.strip_prefix(['+', '-']).unwrap_or(value);
            let mut digits = String::new();
            let mut previous_digit = false;
            for character in value.chars() {
                if let Some(digit) = decimal(character) {
                    digits.push(char::from(b'0' + digit as u8));
                    previous_digit = true;
                } else if character == '_' && previous_digit {
                    previous_digit = false;
                } else {
                    return None;
                }
            }
            if !previous_digit || digits.len() > 4300 {
                return None;
            }
            let number: BigInt = digits.parse().ok()?;
            Some(if negative { -number } else { number })
        }
        _ => None,
    }
}
fn integer_json(value: BigInt) -> Value {
    Value::Number(value.to_string().parse().expect("BigInt is a JSON integer"))
}
fn normalize(filters: &CircuitValue) -> Result<Normalized> {
    let filters = filters
        .as_object()
        .ok_or_else(|| invalid("Search filters must be a JSON object"))?;
    let mut valid: Vec<&str> = EXACT.iter().chain(TEXT).chain(INTEGER).copied().collect();
    valid.sort_unstable();
    valid.dedup();
    let mut unknown: Vec<&str> = filters
        .keys()
        .map(String::as_str)
        .filter(|key| !valid.contains(key))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Err(invalid(format!(
            "unknown filter(s): {}; valid filters: {}",
            unknown.join(", "),
            valid.join(", ")
        )));
    }
    let mut output = Normalized(filters.clone());
    for &key in INTEGER {
        if let Some(value) = output.0.get_mut(key) {
            *value = CircuitValue::Integer(
                integer(value).ok_or_else(|| invalid(format!("{key} must be an integer")))?,
            );
        }
    }
    for &key in EXACT
        .iter()
        .chain(TEXT)
        .filter(|&&key| key != "status_code")
    {
        if let Some(value) = output.0.get(key)
            && text(value).is_none_or(|value| value.is_empty())
        {
            return Err(invalid(format!("{key} must be a non-empty string")));
        }
    }
    if let Some(CircuitValue::Other(Value::String(method))) = output.0.get_mut("method") {
        *method = uppercase(method);
    }
    if let Some(CircuitValue::Other(Value::String(class))) = output.0.get_mut("status_class") {
        class.make_ascii_lowercase();
        if !["2xx", "3xx", "4xx", "5xx"].contains(&class.as_str()) {
            return Err(invalid("status_class must be one of: 2xx, 3xx, 4xx, 5xx"));
        }
    }
    if let Some(limit) = output.0.get_mut("limit") {
        let number = integer(limit).expect("normalized integer");
        if number < BigInt::from(1) {
            return Err(invalid("limit must be at least 1"));
        }
        if number > BigInt::from(500) {
            *limit = CircuitValue::from(500);
        }
    }
    for key in [
        "offset",
        "status_code",
        "status_min",
        "status_max",
        "from_ts",
        "to_ts",
    ] {
        if output
            .0
            .get(key)
            .and_then(integer)
            .is_some_and(|value| value < BigInt::from(0))
        {
            return Err(invalid(format!("{key} must be at least 0")));
        }
    }
    for (low, high) in [("status_min", "status_max"), ("from_ts", "to_ts")] {
        if let (Some(low_value), Some(high_value)) = (
            output.0.get(low).and_then(integer),
            output.0.get(high).and_then(integer),
        ) && low_value > high_value
        {
            return Err(invalid(format!("{low} must not exceed {high}")));
        }
    }
    Ok(output)
}

#[derive(Default)]
struct Selection {
    clauses: Vec<String>,
    values: Vec<CircuitValue>,
}
impl Drop for Selection {
    fn drop(&mut self) {
        for value in &mut self.values {
            wipe(value);
        }
    }
}
impl Selection {
    fn add(&mut self, clause: impl Into<String>, value: CircuitValue) {
        self.clauses.push(clause.into());
        self.values.push(value);
    }
    fn exact(&mut self, filters: &Filters, keys: &[&str], prefix: &str) {
        for &key in keys {
            if let Some(value) = filters.get(key).filter(|value| !is_null(value)) {
                self.add(format!("{prefix}{key} = ?"), value.clone());
            }
        }
    }
    fn time(&mut self, filters: &Filters, prefix: &str) {
        for (key, operator) in [("from_ts", ">="), ("to_ts", "<=")] {
            if let Some(value) = filters.get(key).filter(|value| !is_null(value)) {
                self.add(format!("{prefix}ts_start {operator} ?"), value.clone());
            }
        }
    }
    fn where_sql(&self) -> String {
        if self.clauses.is_empty() {
            "1=1".into()
        } else {
            self.clauses.join(" AND ")
        }
    }
    fn params(&self) -> Result<SqlParams> {
        let mut output = SqlParams(Vec::with_capacity(self.values.len()));
        for value in &self.values {
            output.0.push(binding(value)?);
        }
        Ok(output)
    }
    fn page(&mut self, filters: &Filters, default: i64) -> Result<()> {
        let limit = filters
            .get("limit")
            .cloned()
            .unwrap_or_else(|| CircuitValue::from(default));

        let capped = match limit
            .compare(&CircuitValue::from(500))
            .map_err(|_| failure(ErrorKind::Type))?
        {
            Some(Ordering::Greater) => CircuitValue::from(500),
            _ => limit,
        };
        self.values.extend([
            capped,
            filters
                .get("offset")
                .cloned()
                .unwrap_or_else(|| CircuitValue::from(0)),
        ]);
        Ok(())
    }
}
fn rows(connection: &Connection, sql: &str, params: &SqlParams) -> Result<Vec<Value>> {
    let mut statement = connection.prepare(sql)?;
    let mut cursor = statement.query(params_from_iter(&params.0))?;
    let mut result = Vec::new();
    while let Some(row) = cursor.next()? {
        result.push(Value::Object(row_map(row)?));
    }
    Ok(result)
}

impl FlowStore {
    pub fn search_flows(&self, filters: &CircuitValue) -> Result<Value> {
        let filters = normalize(filters)?;
        let filters = &filters.0;
        let mut selection = Selection::default();
        selection.exact(filters, EXACT, "");
        for (key, clause, count) in [
            ("path_contains", "path LIKE ?", 1),
            (
                "text_contains",
                "(response_body_text_preview LIKE ? OR request_body_text_preview LIKE ?)",
                2,
            ),
        ] {
            if let Some(CircuitValue::Other(Value::String(value))) = filters.get(key) {
                selection.clauses.push(clause.into());
                for _ in 0..count {
                    selection.values.push(text_value(format!("%{value}%")));
                }
            }
        }
        for (key, operator) in [("status_min", ">="), ("status_max", "<=")] {
            if let Some(value) = filters.get(key) {
                selection.add(format!("status_code {operator} ?"), value.clone());
            }
        }
        if let Some(CircuitValue::Other(Value::String(class))) = filters.get("status_class") {
            let low = i64::from(class.as_bytes()[0] - b'0') * 100;
            selection.add("status_code >= ?", low.into());
            selection.add("status_code <= ?", (low + 99).into());
        }
        for (key, column) in [
            ("response_header_contains", "response_headers_json"),
            ("request_header_contains", "request_headers_json"),
        ] {
            if let Some(CircuitValue::Other(Value::String(value))) = filters.get(key) {
                selection.add(format!("{column} LIKE ?"), text_value(format!("%{value}%")));
            }
        }
        if let Some(CircuitValue::Other(Value::String(tag))) = filters.get("tag") {
            if let Some((name, value)) = tag.split_once(':') {
                selection.add(
                    "id IN (SELECT flow_id FROM flow_tags WHERE tag = ? AND value = ?)",
                    text_value(name),
                );
                selection.values.push(text_value(value));
            } else {
                selection.add(
                    "id IN (SELECT flow_id FROM flow_tags WHERE tag = ?)",
                    text_value(tag.clone()),
                );
            }
        }
        selection.time(filters, "");
        if let Some(CircuitValue::Other(Value::String(path))) = filters.get("path") {
            selection.add("path LIKE ?", text_value(format!("%{path}%")));
        }
        if let Some(CircuitValue::Other(Value::String(query))) = filters.get("q") {
            selection.clauses.push("(path LIKE ? OR host LIKE ? OR full_url LIKE ? OR response_body_text_preview LIKE ? OR request_body_text_preview LIKE ?)".into());
            for _ in 0..5 {
                selection.values.push(text_value(format!("%{query}%")));
            }
        }
        selection.page(filters, 50)?;
        let sql = format!(
            "SELECT {SUMMARY} FROM flows WHERE {} ORDER BY ts_start DESC LIMIT ? OFFSET ?",
            selection.where_sql()
        );
        let mut result = rows(&*self.lock()?, &sql, &selection.params()?)?;
        for row in &mut result {
            let row = row.as_object_mut().expect("selected row object");
            let preview = row
                .shift_remove("response_body_text_preview")
                .unwrap_or(Value::Null);
            let preview = preview.as_str().unwrap_or_default();
            let mut characters = preview.chars();
            let mut preview: String = characters.by_ref().take(512).collect();
            if characters.next().is_some() {
                preview.push_str("...");
            }
            row.insert("response_preview".into(), preview.into());
        }
        Ok(Value::Array(result))
    }

    pub fn get_endpoints(&self, filters: &CircuitValue) -> Result<Value> {
        let filters = filters
            .as_object()
            .ok_or_else(|| failure(ErrorKind::Attribute))?;
        let mut selection = Selection::default();
        selection.exact(filters, &EXACT[..15], "");
        selection.time(filters, "");
        selection.page(filters, 100)?;
        let sql = format!(
            "SELECT method, host, path, COUNT(*) as count, MAX(ts_start) as last_seen,
            GROUP_CONCAT(DISTINCT status_code) as status_codes FROM flows WHERE {}
            GROUP BY method, host, path ORDER BY count DESC LIMIT ? OFFSET ?",
            selection.where_sql()
        );
        let mut result = rows(&*self.lock()?, &sql, &selection.params()?)?;
        for row in &mut result {
            let row = row.as_object_mut().expect("selected row object");
            let codes = row.shift_remove("status_codes").unwrap_or(Value::Null);
            let codes = codes
                .as_str()
                .unwrap_or_default()
                .split(',')
                .filter(|value| !value.is_empty())
                .map(|value| {
                    integer(&text_value(value))
                        .map(integer_json)
                        .ok_or_else(|| failure(ErrorKind::Value))
                })
                .collect::<Result<Vec<_>>>()?;
            row.insert("status_codes".into(), Value::Array(codes));
        }
        Ok(Value::Array(result))
    }

    pub fn get_facets(&self, filters: &CircuitValue) -> Result<Value> {
        // Source computes set(filters) before object normalization.
        let keys: Vec<String> = match filters {
            CircuitValue::Object(filters) => filters.keys().cloned().collect(),
            CircuitValue::Array(filters) => {
                if filters
                    .iter()
                    .any(|value| matches!(value, CircuitValue::Array(_) | CircuitValue::Object(_)))
                {
                    return Err(failure(ErrorKind::Type));
                }
                if filters.iter().any(|value| text(value).is_none()) {
                    return Err(failure(ErrorKind::Type));
                }
                filters.iter().filter_map(text).map(str::to_owned).collect()
            }
            CircuitValue::Other(Value::String(value)) => value
                .chars()
                .map(|character| character.to_string())
                .collect(),
            _ => return Err(failure(ErrorKind::Type)),
        };
        let mut unknown: Vec<String> = keys
            .into_iter()
            .filter(|key| {
                !EXACT.contains(&key.as_str()) && !["from_ts", "to_ts"].contains(&key.as_str())
            })
            .collect();
        unknown.sort_unstable();
        unknown.dedup();
        if !unknown.is_empty() {
            return Err(invalid(format!(
                "unknown facet filter(s): {}",
                unknown.join(", ")
            )));
        }
        let filters = normalize(filters)?;
        let mut selection = Selection::default();
        selection.exact(&filters.0, EXACT, "");
        selection.time(&filters.0, "");
        let params = selection.params()?;
        let connection = self.lock()?;
        let mut result = Map::new();
        for &dimension in DIMENSIONS {
            let sql = format!(
                "SELECT {dimension} AS value, COUNT(*) AS count, MAX(ts_start) AS last_seen
                FROM flows WHERE {} AND {dimension} IS NOT NULL GROUP BY {dimension}
                ORDER BY count DESC, value ASC",
                selection.where_sql()
            );
            result.insert(
                dimension.into(),
                Value::Array(rows(&connection, &sql, &params)?),
            );
        }
        Ok(Value::Object(result))
    }

    pub fn search_bodies(&self, filters: &CircuitValue) -> Result<Value> {
        self.body_query(filters, false)
    }
    pub fn search_request_bodies(&self, filters: &CircuitValue) -> Result<Value> {
        self.body_query(filters, true)
    }
    fn body_query(&self, filters: &CircuitValue, request: bool) -> Result<Value> {
        let filters = filters
            .as_object()
            .ok_or_else(|| failure(ErrorKind::Attribute))?;
        let Some(query) = filters.get("query").filter(|value| value.truthy()) else {
            return Ok(Value::Array(Vec::new()));
        };
        if !filters
            .get("engagement_id")
            .is_some_and(CircuitValue::truthy)
        {
            return Ok(Value::Array(Vec::new()));
        }
        let query = text(query).ok_or_else(|| failure(ErrorKind::Attribute))?;
        let tokens: Vec<String> = query
            .split(python_whitespace)
            .filter(|value| !value.is_empty())
            .map(|value| format!("\"{}\"", value.replace('"', "\"\"")))
            .collect();
        let query = if tokens.is_empty() {
            query.into()
        } else {
            tokens.join(" ")
        };
        let mut selection = Selection::default();
        selection.exact(filters, &EXACT[..15], "f.");
        selection.time(filters, "f.");
        for key in ["host", "path"] {
            if let Some(value) = filters.get(key).filter(|value| value.truthy()) {
                selection.add(format!("f.{key} = ?"), value.clone());
            }
        }
        selection.values.push(text_value(query));
        selection.page(filters, 50)?;
        let (table, column) = if request {
            ("flow_request_fts", "request_body_text")
        } else {
            ("flow_fts", "response_body_text")
        };
        let sql = format!(
            "SELECT {FTS_SUMMARY}, snippet({table}, 7, '<mark>', '</mark>', '...', 64) as snippet
            FROM {table} fts JOIN flows f ON f.id = fts.flow_id WHERE {} AND fts.{column} MATCH ?
            ORDER BY f.ts_start DESC LIMIT ? OFFSET ?",
            selection.where_sql()
        );
        Ok(Value::Array(rows(
            &*self.lock()?,
            &sql,
            &selection.params()?,
        )?))
    }
}
