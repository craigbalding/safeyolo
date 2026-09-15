//! Request-only service contracts. State capture/enforcement and response validators
//! remain declarations. Callers must apply compiled route permissions before these checks.

use std::collections::{BTreeMap, BTreeSet};

use serde::{
    Deserialize, Serialize,
    de::{self},
};
use serde_json::{Map, Value};

use crate::{Error, services::normalize_path};

fn get_method() -> String {
    "GET".into()
}
fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ContractTemplate {
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub bindings: Map<String, Value>,
    #[serde(default)]
    pub operations: Vec<ContractOperation>,
    #[serde(default)]
    pub enforcement: BTreeMap<String, String>,
    #[serde(default)]
    pub state: Value,
}

const TIERS: &[&str] = &[
    "request_shape",
    "transport_hygiene",
    "state_capture",
    "state_enforcement",
    "response_validators",
];

impl ContractTemplate {
    pub fn validate(&self) -> Result<(), Error> {
        for tier in TIERS {
            if let Some(value) = self.enforcement.get(*tier)
                && !["enforced", "declared"].contains(&value.as_str())
            {
                return Err(format!("Invalid enforcement status for {tier}").into());
            }
        }
        for (name, definition) in &self.bindings {
            let object = definition
                .as_object()
                .ok_or("binding definition must be an object")?;
            let kind = object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("string");
            if !["string", "enum", "integer", "boolean", "string_list"].contains(&kind) {
                return Err(format!("Invalid binding type for {name}").into());
            }
            if kind == "enum"
                && object
                    .get("options")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
            {
                return Err(format!("Enum binding {name} needs options").into());
            }
        }
        for operation in &self.operations {
            if !operation.requires_enforcement.is_empty()
                && !TIERS.contains(&operation.requires_enforcement.as_str())
            {
                return Err("Invalid requires_enforcement tier".into());
            }
            if let Some(transport) = &operation.request.transport {
                transport.validate()?;
            }
        }
        Ok(())
    }

    pub fn grantable_operations(&self) -> impl DoubleEndedIterator<Item = &ContractOperation> {
        self.operations.iter().filter(|operation| {
            let tier = if operation.requires_enforcement.is_empty() {
                "request_shape"
            } else {
                &operation.requires_enforcement
            };
            self.enforcement
                .get(tier)
                .is_some_and(|status| status == "enforced")
        })
    }

    pub fn is_grantable(&self) -> bool {
        self.grantable_operations().next().is_some()
    }

    pub fn match_operation(&self, method: &str, path: &str) -> Option<&ContractOperation> {
        let mut best = None;
        let mut specificity = -1;
        for operation in self.grantable_operations() {
            if operation.request.method.eq_ignore_ascii_case(method) {
                let score = path_specificity(path, &operation.request.path);
                if score > specificity {
                    best = Some(operation);
                    specificity = score;
                }
            }
        }
        best
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ContractOperation {
    pub name: String,
    #[serde(default)]
    pub requires_enforcement: String,
    #[serde(default)]
    pub request: OperationRequest,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OperationRequest {
    #[serde(default = "get_method")]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub transport: Option<TransportConstraint>,
    #[serde(default)]
    pub query: Constraints,
    #[serde(default)]
    pub body: Constraints,
    #[serde(default)]
    pub path_params: BTreeMap<String, Constraint>,
}
impl Default for OperationRequest {
    fn default() -> Self {
        Self {
            method: get_method(),
            path: String::new(),
            transport: None,
            query: Constraints::default(),
            body: Constraints::default(),
            path_params: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TransportConstraint {
    #[serde(default)]
    pub require_no_body: bool,
    /// Missing and an explicit empty list have different production behavior.
    #[serde(default, deserialize_with = "present_value")]
    pub allow_headers: Option<Value>,
    #[serde(default)]
    pub deny_ambiguous_encoding: bool,
}
fn present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}
impl TransportConstraint {
    fn validate(&self) -> Result<(), Error> {
        if let Some(value) = &self.allow_headers
            && !value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
        {
            return Err("transport.allow_headers must be a list of header names".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Constraints {
    #[serde(default)]
    pub allow: BTreeMap<String, Constraint>,
    #[serde(default = "yes")]
    pub deny_unknown: bool,
}
impl Default for Constraints {
    fn default() -> Self {
        Self {
            allow: BTreeMap::new(),
            deny_unknown: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Constraint {
    #[serde(default)]
    pub equals_var: String,
    #[serde(default)]
    pub integer_range: Vec<i64>,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub in_state_set: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractBinding {
    #[serde(default)]
    pub binding_id: String,
    pub agent: String,
    pub service: String,
    pub capability: String,
    #[serde(default)]
    pub template: String,
    #[serde(default, deserialize_with = "deserialize_bound_values")]
    pub bound_values: Map<String, Value>,
    #[serde(default)]
    pub grantable_operations: Vec<String>,
}

impl ContractOperation {
    pub fn bound_value_references(&self) -> BTreeSet<&str> {
        self.request
            .path_params
            .values()
            .chain(self.request.query.allow.values())
            .chain(self.request.body.allow.values())
            .filter_map(|constraint| {
                (!constraint.equals_var.is_empty()).then_some(constraint.equals_var.as_str())
            })
            .collect()
    }
    pub fn has_state_reference(&self) -> bool {
        self.request
            .path_params
            .values()
            .any(|constraint| !constraint.in_state_set.is_empty())
    }
    pub fn is_prebinding_grantable(&self) -> bool {
        self.bound_value_references().is_empty()
            && !self.has_state_reference()
            && !self.request.path.contains(['{', '}', '*', '?', '['])
    }
    pub fn resolved_path(&self, values: &Map<String, Value>) -> Option<String> {
        if self.has_state_reference() {
            return None;
        }
        for constraint in self.request.path_params.values() {
            if !constraint.equals_var.is_empty()
                && let Some(value) = values.get(&constraint.equals_var).filter(|v| !v.is_null())
            {
                safe_path_component(value)?;
            }
        }
        let mut path = self.request.path.clone();
        while let Some(start) = path.find('{') {
            let end = path[start + 1..].find('}')? + start + 1;
            let parameter = &path[start + 1..end];
            if parameter.is_empty() || parameter.contains('{') {
                return None;
            }
            let constraint = self.request.path_params.get(parameter)?;
            if constraint.equals_var.is_empty() {
                return None;
            }
            let value = safe_path_component(values.get(&constraint.equals_var)?)?;
            path.replace_range(start..=end, &value);
            // A literal brace inside an approved value remains unresolved as in Python.
            if value.contains(['{', '}']) {
                return None;
            }
        }
        (!path.contains('}')).then_some(path)
    }
}

pub fn safe_path_component(value: &Value) -> Option<String> {
    let component = match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => if *value { "True" } else { "False" }.into(),
        Value::Number(value) if value.is_i64() || value.is_u64() => value.to_string(),
        _ => return None,
    };
    if component.is_empty()
        || [".", ".."].contains(&component.as_str())
        || component.contains(['/', '\\', '*', '?', '[', ']'])
    {
        None
    } else {
        Some(component)
    }
}

fn parts(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}
pub fn path_specificity(actual: &str, template: &str) -> i8 {
    let (actual, template) = (parts(actual), parts(template));
    let mut parameter = false;
    for (index, segment) in template.iter().enumerate() {
        if ["*", "**"].contains(segment) {
            return 0;
        }
        let Some(actual) = actual.get(index) else {
            return -1;
        };
        if segment.starts_with('{') && segment.ends_with('}') {
            parameter = true;
        } else if segment != actual {
            return -1;
        }
    }
    if actual.len() != template.len() {
        -1
    } else if parameter {
        1
    } else {
        2
    }
}

#[derive(Clone, Copy)]
pub struct ContractRequest<'a> {
    pub method: &'a str,
    /// Raw path and query before URL normalization; duplicate fields must remain present.
    pub target: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanonicalRequest {
    pub operation: String,
    pub method: String,
    pub path: String,
    pub query: Map<String, Value>,
    pub body: Option<Map<String, Value>>,
    pub content_type: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContractCode {
    TransportPathTrick,
    TransportDuplicateHeader,
    TransportAmbiguousEncoding,
    OperationNotGrantable,
    ContractNotBound,
    TransportContentType,
    ContractViolation,
    TransportDuplicateJsonKey,
    TransportCrossLocation,
    TransportBodyDenied,
    TransportHeaderDenied,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContractDenial {
    pub code: ContractCode,
    pub field: Option<String>,
}
fn deny(code: ContractCode, field: Option<&str>) -> ContractDenial {
    ContractDenial {
        code,
        field: field.map(str::to_owned),
    }
}

pub fn reject_path_tricks(raw: &str) -> bool {
    let path = raw.split('?').next().unwrap_or_default();
    path.split('/').any(|part| [".", ".."].contains(&part))
        || path.contains("//")
        || percent_problem(path, true)
}

fn percent_problem(value: &str, path: bool) -> bool {
    let bytes = value.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'%' || index + 2 >= bytes.len() {
            continue;
        }
        let a = bytes[index + 1];
        let b = bytes[index + 2];
        if !a.is_ascii_hexdigit() || !b.is_ascii_hexdigit() {
            continue;
        }
        if a.is_ascii_lowercase() || b.is_ascii_lowercase() {
            return true;
        }
        if path && ((a == b'2' && b == b'F') || (a == b'5' && b == b'C')) {
            return true;
        }
        if a == b'2'
            && b == b'5'
            && index + 4 < bytes.len()
            && bytes[index + 3].is_ascii_hexdigit()
            && bytes[index + 4].is_ascii_hexdigit()
        {
            return true;
        }
    }
    false
}

fn query_params(query: &str) -> Result<Map<String, Value>, ContractDenial> {
    let mut parsed = Map::new();
    for item in query.split('&').filter(|item| !item.is_empty()) {
        let (key, value) = item.split_once('=').unwrap_or((item, ""));
        let decode = |value: &str| {
            percent_encoding::percent_decode_str(&value.replace('+', " "))
                .decode_utf8_lossy()
                .into_owned()
        };
        // Intentional repair: the old gateway checks only raw keys, then keeps
        // the first decoded value. An upstream can consume a forbidden second
        // value from an encoded alias. Contract-bound names must be unambiguous.
        if parsed
            .insert(decode(key), Value::String(decode(value)))
            .is_some()
        {
            return Err(deny(ContractCode::TransportAmbiguousEncoding, None));
        }
    }
    Ok(parsed)
}

/// Applies current production request checks. Compiled route permission supplies
/// agent/service/capability and approved-operation scope before this function runs.
pub fn enforce_request(
    contract: &ContractTemplate,
    binding: Option<&ContractBinding>,
    auth_header: &str,
    request: ContractRequest<'_>,
) -> Result<CanonicalRequest, ContractDenial> {
    use ContractCode::*;
    if reject_path_tricks(request.target) {
        return Err(deny(TransportPathTrick, None));
    }
    let mut headers = BTreeMap::new();
    for (name, value) in request.headers {
        let name = name.to_lowercase();
        if headers.insert(name.clone(), value.clone()).is_some() {
            return Err(deny(TransportDuplicateHeader, None));
        }
    }
    let (raw_path, query) = request
        .target
        .split_once('?')
        .unwrap_or((request.target, ""));
    let mut raw_keys = BTreeSet::new();
    let duplicate = query
        .split('&')
        .filter(|item| !item.is_empty())
        .map(|item| item.split('=').next().unwrap())
        .any(|key| !raw_keys.insert(key));
    let parsed_query = query_params(query)?;
    if duplicate
        || percent_problem(query, false)
        || parsed_query.contains_key("_method")
        || headers.contains_key("x-http-method-override")
        || headers.contains_key("x-method-override")
    {
        return Err(deny(TransportAmbiguousEncoding, None));
    }
    let path = normalize_path(raw_path);
    let operation = contract
        .match_operation(request.method, &path)
        .ok_or_else(|| deny(OperationNotGrantable, None))?;
    if binding.is_none() && !operation.is_prebinding_grantable() {
        return Err(deny(ContractNotBound, None));
    }
    let empty = Map::new();
    let bound_values = binding.map_or(&empty, |binding| &binding.bound_values);
    let content_type = headers
        .get("content-type")
        .map_or("", |value| value.split(';').next().unwrap_or_default())
        .trim()
        .to_lowercase();
    let mut body = None;
    let writes = ["POST", "PUT", "PATCH"].contains(&request.method);
    if writes && !request.body.is_empty() {
        if content_type != "application/json" {
            return Err(deny(TransportContentType, None));
        }
        let value = serde_json::from_slice::<StrictJson>(request.body)
            .map_err(|error| {
                deny(
                    if error.to_string().contains("duplicate JSON key") {
                        TransportDuplicateJsonKey
                    } else {
                        ContractViolation
                    },
                    None,
                )
            })?
            .0;
        let Value::Object(object) = value else {
            return Err(deny(ContractViolation, None));
        };
        body = Some(object);
    }
    if let Some(body) = &body
        && let Some(field) = parsed_query
            .keys()
            .filter(|key| body.contains_key(*key))
            .min()
    {
        return Err(deny(TransportCrossLocation, Some(field)));
    }
    if operation
        .request
        .transport
        .as_ref()
        .is_some_and(|constraint| constraint.require_no_body)
        && !request.body.is_empty()
    {
        return Err(deny(TransportBodyDenied, None));
    }
    let implicit = [
        "host",
        "connection",
        "content-length",
        "content-type",
        "transfer-encoding",
        "accept-encoding",
        "via",
        "proxy-connection",
    ];
    let mut allowed: BTreeSet<String> = implicit.iter().map(|header| (*header).into()).collect();
    if !auth_header.is_empty() {
        allowed.insert(auth_header.to_lowercase());
    }
    match operation
        .request
        .transport
        .as_ref()
        .and_then(|transport| transport.allow_headers.as_ref())
    {
        None => allowed.extend(["accept", "user-agent", "accept-encoding"].map(str::to_owned)),
        Some(Value::Array(names)) => allowed.extend(
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_lowercase),
        ),
        Some(_) => return Err(deny(TransportHeaderDenied, None)),
    }
    // Iterate original order so the first denied field matches the production hook.
    for (name, _) in request.headers {
        let name = name.to_lowercase();
        if !allowed.contains(&name) {
            return Err(deny(TransportHeaderDenied, None));
        }
    }
    for (name, value) in &parsed_query {
        let Some(constraint) = operation.request.query.allow.get(name) else {
            if operation.request.query.deny_unknown {
                return Err(deny(ContractViolation, Some(name)));
            }
            continue;
        };
        if !constraint.equals_var.is_empty() {
            let empty = Value::String(String::new());
            if value != bound_values.get(&constraint.equals_var).unwrap_or(&empty) {
                return Err(deny(ContractViolation, Some(name)));
            }
        } else if !constraint.integer_range.is_empty() {
            let value = value.as_str().unwrap();
            let integer = python_integer(value);
            if constraint.integer_range.len() < 2
                || integer.is_none_or(|value| {
                    value < constraint.integer_range[0] as i128
                        || value > constraint.integer_range[1] as i128
                })
            {
                return Err(deny(ContractViolation, Some(name)));
            }
        }
    }
    if let Some(body) = &body {
        for (name, value) in body {
            let Some(constraint) = operation.request.body.allow.get(name) else {
                if operation.request.body.deny_unknown {
                    return Err(deny(ContractViolation, Some(name)));
                }
                continue;
            };
            let empty = Value::String(String::new());
            if !constraint.equals_var.is_empty()
                && !python_equal(
                    value,
                    bound_values.get(&constraint.equals_var).unwrap_or(&empty),
                )
            {
                return Err(deny(ContractViolation, Some(name)));
            }
        }
    }
    if !operation.request.path_params.is_empty() {
        let actual = parts(&path);
        let template = parts(&operation.request.path);
        if actual.len() != template.len() {
            return Err(deny(ContractViolation, None));
        }
        for (actual, template) in actual.iter().zip(template) {
            if let Some(name) = template
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
            {
                if let Some(constraint) = operation.request.path_params.get(name)
                    && !constraint.equals_var.is_empty()
                    && let Some(expected) = bound_values
                        .get(&constraint.equals_var)
                        .filter(|value| !value.is_null())
                    && *actual != python_string(expected)
                {
                    return Err(deny(ContractViolation, Some(name)));
                }
            } else if actual != &template {
                return Err(deny(ContractViolation, None));
            }
        }
    }
    Ok(CanonicalRequest {
        operation: operation.name.clone(),
        method: request.method.into(),
        path,
        query: parsed_query,
        body,
        content_type,
        headers,
    })
}

fn python_integer(value: &str) -> Option<i128> {
    let value = value.trim();
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    value.replace('_', "").parse().ok()
}
fn python_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => if *value { "True" } else { "False" }.into(),
        Value::Null => "None".into(),
        _ => value.to_string(),
    }
}
// JSON integer tokens remain exact at every magnitude. Python compares a
// float to an integer using the float's exact represented value, not by
// rounding the integer to f64 first.
fn integer_text(value: &Value) -> Option<&str> {
    match value {
        Value::Bool(value) => Some(if *value { "1" } else { "0" }),
        Value::Number(number) => {
            let text = number.as_str();
            (!text.contains(['.', 'e', 'E'])).then_some(if text == "-0" { "0" } else { text })
        }
        _ => None,
    }
}
fn numeric_float(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_str().parse().ok(),
        Value::Bool(value) => Some(if *value { 1. } else { 0. }),
        _ => None,
    }
}
fn python_equal(left: &Value, right: &Value) -> bool {
    match (integer_text(left), integer_text(right)) {
        (Some(left), Some(right)) => return left == right,
        (Some(integer), None) if right.is_number() => {
            return numeric_float(right).is_some_and(|float| float_equals_integer(float, integer));
        }
        (None, Some(integer)) if left.is_number() => {
            return numeric_float(left).is_some_and(|float| float_equals_integer(float, integer));
        }
        _ => {}
    }
    if let (Some(left), Some(right)) = (numeric_float(left), numeric_float(right)) {
        return left == right;
    }
    match (left, right) {
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| python_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|other| python_equal(value, other))
                })
        }
        _ => left == right,
    }
}

fn float_equals_integer(float: f64, integer: &str) -> bool {
    float.is_finite()
        && float.fract() == 0.0
        && if float == 0.0 {
            integer == "0"
        } else {
            // Fixed zero-decimal formatting emits the full integer value of
            // this binary float, including digits beyond shortest notation.
            format!("{float:.0}") == integer
        }
}

struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        crate::policy::parse_json(raw.get(), true)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

/// Decode the authored object before serde's private numeric representation can
/// reinterpret a literal marker key. Policy/binding JSON retains last-key-wins.
fn deserialize_bound_values<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Map<String, Value>, D::Error> {
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    match crate::policy::parse_json(raw.get(), false).map_err(de::Error::custom)? {
        Value::Object(values) => Ok(values),
        _ => Err(de::Error::custom("bound_values must be an object")),
    }
}
