//! Process-owned live HTTP observations. This store has no transport ownership.
//! Retention targets are soft while observation handles remain alive.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

const SELECTORS: [(&str, &str); 5] = [
    ("agent", "agent"),
    ("test_id", "test_id"),
    ("intent", "test_intent"),
    ("role", "test_role"),
    ("expect", "test_expect"),
];

/// Header pairs retain the order, spelling, duplicates and text supplied by the
/// reached HTTP observer. Raw HTTP bytes can be projected losslessly as Latin-1.
pub struct RequestInfo {
    pub id: String,
    pub connection_id: String,
    pub agent: Option<String>,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub started: f64,
}

impl Drop for RequestInfo {
    fn drop(&mut self) {
        self.id.zeroize();
        self.connection_id.zeroize();
        self.agent.zeroize();
        self.method.zeroize();
        self.url.zeroize();
        wipe_headers(&mut self.headers);
    }
}

#[derive(Clone, Copy)]
pub enum Side {
    Request,
    Response,
}

pub struct TrafficView {
    state: Mutex<State>,
}

struct State {
    rows: IndexMap<String, Row>,
    scope: Scope,
    max_flows: usize,
    max_body_bytes: usize,
}

/// Only the view owns retained evidence. A handle holds a weak view reference,
/// so retaining an exchange cannot keep a stopped process's view alive.
pub struct Exchange {
    view: Weak<TrafficView>,
    id: Zeroizing<String>,
}

struct Row {
    handle: Weak<Exchange>,
    request: RequestInfo,
    metadata: Value,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    request_body: Body,
    response_body: Body,
    state: &'static str,
    ended: Option<f64>,
    error: Option<Zeroizing<String>>,
}

enum Body {
    Pending,
    Unavailable,
    Bytes(Zeroizing<Vec<u8>>),
}

impl Body {
    fn observe(bytes: Option<&[u8]>) -> Self {
        bytes.map_or(Self::Unavailable, |bytes| {
            Self::Bytes(Zeroizing::new(bytes.to_vec()))
        })
    }

    fn size(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            _ => 0,
        }
    }

    fn facts(&self) -> Value {
        json!({
            "available": matches!(self, Self::Bytes(_)),
            "size": self.size(),
            "reason": match self {
                Self::Pending => Some("pending"),
                Self::Unavailable => Some("streamed_or_unavailable"),
                Self::Bytes(_) => None,
            },
        })
    }

    fn snapshot(&self) -> Value {
        let mut facts = self.facts();
        facts.as_object_mut().expect("body facts").insert(
            "data_base64".into(),
            match self {
                Self::Bytes(bytes) => Value::String(STANDARD.encode(bytes)),
                _ => Value::Null,
            },
        );
        facts
    }
}

impl TrafficView {
    pub fn new(max_flows: usize, max_body_bytes: usize) -> Self {
        Self {
            state: Mutex::new(State {
                rows: IndexMap::new(),
                scope: Scope::default(),
                max_flows,
                max_body_bytes,
            }),
        }
    }

    // Observation must not create a new forwarding error. Recover the contained
    // display state after a panic; no transport decision depends on this lock.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn begin(self: &Arc<Self>, info: RequestInfo) -> Arc<Exchange> {
        let handle = Arc::new(Exchange {
            view: Arc::downgrade(self),
            id: Zeroizing::new(info.id.clone()),
        });
        let mut metadata = Map::new();
        if let Some(agent) = &info.agent {
            metadata.insert("agent".into(), Value::String(agent.clone()));
        }
        let mut state = self.lock();
        // Replacing a duplicate correlation ID cannot let an older handle edit
        // the replacement: each write checks the concrete handle's identity.
        if let Some((mut id, _)) = state.rows.shift_remove_entry(&info.id) {
            id.zeroize();
        }
        state.rows.insert(
            info.id.clone(),
            Row {
                handle: Arc::downgrade(&handle),
                request: info,
                metadata: Value::Object(metadata),
                response_headers: Vec::new(),
                status: None,
                request_body: Body::Pending,
                response_body: Body::Pending,
                state: "pending",
                ended: None,
                error: None,
            },
        );
        state.prune();
        handle
    }

    pub fn configure(&self, max_flows: usize, max_body_bytes: usize) {
        let mut state = self.lock();
        state.max_flows = max_flows;
        state.max_body_bytes = max_body_bytes;
        state.prune();
    }

    pub fn scope(&self) -> Value {
        self.lock().scope.snapshot()
    }

    pub fn set_scope(&self, input: &Value) -> Result<Value, String> {
        let scope = Scope::parse(input)?;
        let result = scope.snapshot();
        self.lock().scope = scope;
        Ok(result)
    }

    pub fn flows(&self) -> Value {
        let state = self.lock();
        let mut rows: Vec<_> = state
            .rows
            .values()
            .filter(|row| state.scope.matches(row))
            .collect();
        rows.sort_by(|a, b| {
            b.request
                .started
                .total_cmp(&a.request.started)
                .then_with(|| b.request.id.cmp(&a.request.id))
        });
        json!({"flows": rows.into_iter().map(Row::summary).collect::<Vec<_>>(), "scope": state.scope.snapshot()})
    }

    /// Direct reads address all retained rows; pinned display scope is not an
    /// authorization boundary. The operator route owns authorization.
    pub fn detail(&self, id: &str) -> Option<Value> {
        self.lock().rows.get(id).map(|row| {
            let mut result = row.summary();
            let object = result.as_object_mut().expect("row summary");
            object.insert("request_headers".into(), json!(row.request.headers));
            object.insert("response_headers".into(), json!(row.response_headers));
            object.insert("metadata".into(), row.metadata.clone());
            result
        })
    }

    pub fn body(&self, id: &str, side: Side) -> Option<Value> {
        self.lock().rows.get(id).map(|row| match side {
            Side::Request => row.request_body.snapshot(),
            Side::Response => row.response_body.snapshot(),
        })
    }

    pub fn facets(&self) -> Value {
        let state = self.lock();
        let mut result = Map::new();
        for (_, key) in SELECTORS {
            let mut counts = BTreeMap::<String, usize>::new();
            for row in state.rows.values() {
                if key != "agent"
                    && state.scope.selected("agent").is_some_and(|agent| {
                        row.metadata.get("agent").and_then(Value::as_str) != Some(agent)
                    })
                {
                    continue;
                }
                if !matches!(key, "agent" | "test_id")
                    && state.scope.selected("test_id").is_some_and(|test| {
                        row.metadata.get("test_id").and_then(Value::as_str) != Some(test)
                    })
                {
                    continue;
                }
                if let Some(value) = row.metadata.get(key).filter(|v| !v.is_null()) {
                    *counts.entry(python_text(value)).or_default() += 1;
                }
            }
            let mut counts: Vec<_> = counts.into_iter().collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            result.insert(
                key.into(),
                Value::Array(
                    counts
                        .into_iter()
                        .map(|(value, count)| json!({"value":value,"count":count}))
                        .collect(),
                ),
            );
        }
        Value::Object(result)
    }
}

impl Exchange {
    fn update(&self, change: impl FnOnce(&mut Row)) {
        if let Some(view) = self.view.upgrade() {
            let mut state = view.lock();
            if let Some(row) = state
                .rows
                .get_mut(self.id.as_str())
                .filter(|row| std::ptr::eq(row.handle.as_ptr(), self))
            {
                change(row);
            }
        }
    }

    pub fn request_headers(&self, headers: Vec<(String, String)>) {
        // Own/wipe even if the row has already been evicted/replaced.
        let mut headers = headers;
        self.update(|row| {
            wipe_headers(&mut row.request.headers);
            row.request.headers = std::mem::take(&mut headers);
        });
        wipe_headers(&mut headers);
    }

    pub fn request_body(&self, bytes: Option<&[u8]>) {
        self.update(|row| row.request_body = Body::observe(bytes));
    }

    /// Merge reached metadata. The trusted ingress agent remains authoritative;
    /// an arbitrary caller-supplied metadata agent cannot relabel the row.
    pub fn metadata(&self, metadata: &Map<String, Value>) {
        self.update(|row| {
            let current = row.metadata.as_object_mut().expect("row metadata");
            for (key, value) in metadata {
                if key != "agent" {
                    if let Some(replaced) = current.get_mut(key) {
                        wipe_json(replaced);
                        *replaced = value.clone();
                    } else {
                        current.insert(key.clone(), value.clone());
                    }
                }
            }
        });
    }

    pub fn response_head(&self, status: u16, headers: Vec<(String, String)>) {
        let mut headers = headers;
        self.update(|row| {
            wipe_headers(&mut row.response_headers);
            row.response_headers = std::mem::take(&mut headers);
            row.status = Some(status);
        });
        wipe_headers(&mut headers);
    }

    pub fn response_body(&self, bytes: Option<&[u8]>) {
        self.update(|row| row.response_body = Body::observe(bytes));
    }

    pub fn finish(&self, error: Option<&str>) {
        self.finish_at(error, now());
    }

    fn finish_at(&self, error: Option<&str>, ended: f64) {
        self.update(|row| {
            if row.ended.is_none() {
                row.state = if error.is_some() { "error" } else { "complete" };
                row.ended = Some(ended);
                // A peer may finish its response while the request parser is
                // still receiving bytes. Keep that side pending until its
                // validated observation or the final handle release.
                if matches!(row.response_body, Body::Pending) {
                    row.response_body = Body::Unavailable;
                }
                row.error = error.map(|error| Zeroizing::new(error.into()));
            }
        });
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if let Some(view) = self.view.upgrade() {
            let mut state = view.lock();
            if let Some(row) = state
                .rows
                .get_mut(self.id.as_str())
                .filter(|row| std::ptr::eq(row.handle.as_ptr(), self))
            {
                if row.ended.is_none() {
                    row.state = "incomplete";
                    row.ended = Some(now());
                    row.error = Some(Zeroizing::new("cancelled".into()));
                }
                row.finalize_bodies();
            }
            state.prune();
        }
    }
}

impl Row {
    fn finalize_bodies(&mut self) {
        if matches!(self.request_body, Body::Pending) {
            self.request_body = Body::Unavailable;
        }
        if matches!(self.response_body, Body::Pending) {
            self.response_body = Body::Unavailable;
        }
    }

    fn summary(&self) -> Value {
        json!({
            "id": self.request.id,
            "connection_id": self.request.connection_id,
            "agent": self.request.agent,
            "method": self.request.method,
            "url": self.request.url,
            "status": self.status,
            "state": self.state,
            "started": self.request.started,
            "ended": self.ended,
            "error": self.error.as_ref().map(|s| s.as_str()),
            "request_body": self.request_body.facts(),
            "response_body": self.response_body.facts(),
        })
    }
}

impl Drop for Row {
    fn drop(&mut self) {
        wipe_headers(&mut self.response_headers);
        wipe_json(&mut self.metadata);
    }
}

impl State {
    fn prune(&mut self) {
        let mut bytes: usize = self
            .rows
            .values()
            .map(|row| row.request_body.size() + row.response_body.size())
            .sum();
        if self.rows.len() <= self.max_flows && bytes <= self.max_body_bytes {
            return;
        }
        let mut terminal: Vec<_> = self
            .rows
            .iter()
            .filter(|(_, row)| row.ended.is_some() && row.handle.strong_count() == 0)
            .map(|(id, row)| {
                (
                    row.ended.unwrap_or(row.request.started),
                    Zeroizing::new(id.clone()),
                )
            })
            .collect();
        terminal.sort_by(|a, b| {
            a.0.total_cmp(&b.0)
                .then_with(|| a.1.as_str().cmp(b.1.as_str()))
        });
        for (_, id) in terminal {
            if self.rows.len() <= self.max_flows && bytes <= self.max_body_bytes {
                break;
            }
            if let Some((mut key, row)) = self.rows.shift_remove_entry(id.as_str()) {
                key.zeroize();
                bytes -= row.request_body.size() + row.response_body.size();
            }
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for (mut key, _) in std::mem::take(&mut self.rows) {
            key.zeroize();
        }
    }
}

struct Scope {
    fields: Value,
    effective: Zeroizing<String>,
    needles: Vec<Zeroizing<String>>,
}

impl Default for Scope {
    fn default() -> Self {
        Self::parse(&json!({})).expect("empty scope")
    }
}

impl Scope {
    fn selected(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(Value::as_str)
    }

    fn parse(value: &Value) -> Result<Self, String> {
        let input = value
            .as_object()
            .ok_or("request body must be a JSON object")?;
        let mut unknown: Vec<_> = input
            .keys()
            .filter(|key| {
                !SELECTORS.iter().any(|(field, _)| key == field) && key.as_str() != "unattributed"
            })
            .cloned()
            .collect();
        unknown.sort();
        if !unknown.is_empty() {
            return Err(format!("unknown scope field(s): {}", unknown.join(", ")));
        }
        let unattributed = input.get("unattributed").unwrap_or(&Value::Bool(false));
        if truthy(unattributed) && input.get("agent").is_some_and(|v| !v.is_null()) {
            return Err("agent and unattributed are mutually exclusive".into());
        }
        for (field, _) in SELECTORS {
            if input
                .get(field)
                .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(str::is_empty))
            {
                return Err(format!("{field} must be a non-empty string or null"));
            }
        }
        let mut fields = Map::new();
        fields.insert(
            "agent".into(),
            input.get("agent").cloned().unwrap_or(Value::Null),
        );
        fields.insert("unattributed".into(), unattributed.clone());
        for (field, _) in &SELECTORS[1..] {
            fields.insert(
                (*field).into(),
                input.get(*field).cloned().unwrap_or(Value::Null),
            );
        }
        let mut parts = Vec::new();
        let mut needles = Vec::new();
        if truthy(unattributed) {
            parts.push("!(~meta ^agent:)".to_string());
        }
        for (field, key) in SELECTORS {
            if field == "agent" && truthy(unattributed) {
                continue;
            }
            if let Some(value) = fields.get(field).and_then(Value::as_str) {
                let raw = Zeroizing::new(format!("{key}: {value}"));
                needles.push(Zeroizing::new(raw.to_lowercase()));
                let mut escaped = Zeroizing::new(String::new());
                for ch in raw.chars() {
                    if "()[]{}?*+-|^$\\.&~# \t\n\r\u{b}\u{c}\"".contains(ch) {
                        escaped.push('\\');
                    }
                    escaped.push(ch);
                }
                parts.push(format!("~meta \"^{}$\"", escaped.as_str()));
            }
        }
        let effective = Zeroizing::new(parts.join(" & "));
        parts.zeroize();
        Ok(Self {
            fields: Value::Object(fields),
            effective,
            needles,
        })
    }

    fn snapshot(&self) -> Value {
        let mut fields = self.fields.clone();
        let object = fields.as_object_mut().expect("scope fields");
        object.insert("user_filter".into(), Value::String(String::new()));
        object.insert(
            "effective_filter".into(),
            Value::String(self.effective.to_string()),
        );
        fields
    }

    fn matches(&self, row: &Row) -> bool {
        // Source FMeta searches newline-joined Python presentations. This uses
        // its default case-insensitive, multiline mode with literal anchors.
        // Unicode lowercase is a finite approximation of Python regex folding;
        // environment-sensitive regex mode and Unicode-fold differences remain
        // outside this finite display adapter. The source command lexer also
        // consumes some escapes and rejects newline selectors; native matching
        // is deliberately literal and accepts those strings. This is not a
        // general mitmproxy/user-filter interpreter.
        if self.effective.is_empty() {
            return true;
        }
        let mut text = Zeroizing::new(String::new());
        for (key, value) in row.metadata.as_object().expect("row metadata") {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(key);
            text.push_str(": ");
            let value = Zeroizing::new(python_text(value));
            text.push_str(&value);
        }
        let text = Zeroizing::new(text.to_lowercase());
        if truthy(&self.fields["unattributed"])
            && text.split('\n').any(|line| line.starts_with("agent:"))
        {
            return false;
        }
        self.needles.iter().all(|needle| {
            std::iter::once(0)
                .chain(text.match_indices('\n').map(|(index, _)| index + 1))
                .any(|start| {
                    text[start..].starts_with(needle.as_str())
                        && text
                            .as_bytes()
                            .get(start + needle.len())
                            .is_none_or(|byte| *byte == b'\n')
                })
        })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        wipe_json(&mut self.fields);
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_none_or(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

/// Only JSON-representable metadata is accepted at this seam. Python string
/// representation keeps facet values distinct from JSON (True, None, quotes).
fn python_text(value: &Value) -> String {
    enum Part<'a> {
        Value(&'a Value, bool),
        Text(&'a str),
        Key(&'a str),
    }
    let mut output = String::new();
    let mut pending = vec![Part::Value(value, true)];
    while let Some(part) = pending.pop() {
        match part {
            Part::Text(text) => output.push_str(text),
            Part::Key(text) => output.push_str(&Zeroizing::new(crate::agent_api::repr(text))),
            Part::Value(Value::Null, _) => output.push_str("None"),
            Part::Value(Value::Bool(value), _) => {
                output.push_str(if *value { "True" } else { "False" })
            }
            Part::Value(Value::String(value), true) => output.push_str(value),
            Part::Value(Value::String(value), false) => {
                output.push_str(&Zeroizing::new(crate::agent_api::repr(value)))
            }
            Part::Value(value @ Value::Number(_), _) => {
                crate::python_json::write(value, &mut output).expect("String sink");
            }
            Part::Value(Value::Array(values), _) => {
                output.push('[');
                pending.push(Part::Text("]"));
                for (index, value) in values.iter().enumerate().rev() {
                    pending.push(Part::Value(value, false));
                    if index > 0 {
                        pending.push(Part::Text(", "));
                    }
                }
            }
            Part::Value(Value::Object(values), _) => {
                output.push('{');
                pending.push(Part::Text("}"));
                for (index, (key, value)) in values.iter().enumerate().rev() {
                    pending.push(Part::Value(value, false));
                    pending.push(Part::Text(": "));
                    pending.push(Part::Key(key));
                    if index > 0 {
                        pending.push(Part::Text(", "));
                    }
                }
            }
        }
    }
    output
}

fn wipe_headers(headers: &mut Vec<(String, String)>) {
    for (name, value) in headers.iter_mut() {
        name.zeroize();
        value.zeroize();
    }
    headers.clear();
}

fn wipe_json(value: &mut Value) {
    // Iterative cleanup also covers caller-built deep metadata. This does not
    // impose a parser limit or copy strings into a second retained owner.
    let mut pending = vec![value.take()];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(mut value) => value.zeroize(),
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => {
                for (mut key, value) in values {
                    key.zeroize();
                    pending.push(value);
                }
            }
            _ => {}
        }
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |error| -error.duration().as_secs_f64(),
        |duration| duration.as_secs_f64(),
    )
}

#[cfg(test)]
mod tests;
