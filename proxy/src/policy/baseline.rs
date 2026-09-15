//! Canonical baseline data emitted by the sole policy loader.
//!
//! These helpers normalize the shipped model's fields. They do not match a
//! request or load another policy source. Arbitrary addon and gateway data can
//! contain credentials, so the retained view has no data-bearing Debug output.

use std::collections::HashSet;

use num_bigint::BigInt;
use serde_json::{Map, Value};

use super::{Result, boolean, invalid, object, string, string_array};

#[derive(Clone)]
pub(super) struct Baseline {
    pub(super) value: Value,
    pub(super) generated_permissions: Vec<usize>,
    pub(super) timestamps: super::TimestampPaths,
}

impl std::fmt::Debug for Baseline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Baseline { .. }")
    }
}

impl Drop for Baseline {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.value);
    }
}

pub(super) struct Builder {
    pub(super) document: Map<String, Value>,
    permissions: Vec<(Value, bool)>,
    simple: Map<String, Value>,
    resources: std::collections::HashMap<(ScalarKey, ScalarKey), HashSet<String>>,
    group_order: Vec<((ScalarKey, ScalarKey), (String, String))>,
    host_centric: bool,
    pub(super) timestamps: super::TimestampPaths,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ScalarKey {
    Null,
    String(String),
    Integer(BigInt),
    Float(u64),
    Temporal(super::TemporalValue),
}

fn scalar_key(value: &Value) -> Result<ScalarKey> {
    Ok(match value {
        Value::Null => ScalarKey::Null,
        Value::String(value) => ScalarKey::String(value.clone()),
        Value::Bool(value) => ScalarKey::Integer(BigInt::from(u8::from(*value))),
        Value::Number(value) => {
            let raw = value.to_string();
            if !raw.contains(['.', 'e', 'E']) {
                ScalarKey::Integer(
                    raw.parse()
                        .map_err(|_| invalid("invalid numeric permission group"))?,
                )
            } else {
                let float: f64 = raw
                    .parse()
                    .map_err(|_| invalid("invalid numeric permission group"))?;
                if float.is_finite() && float.fract() == 0. {
                    ScalarKey::Integer(format!("{float:.0}").parse().expect("finite integer float"))
                } else {
                    ScalarKey::Float(float.to_bits())
                }
            }
        }
        _ => return Err(invalid("permission group values must be hashable scalars")),
    })
}

fn scalar_display(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        Value::Number(number) => {
            if number.to_string().contains(['.', 'e', 'E'])
                && let Ok(float) = number.to_string().parse::<f64>()
                && float.is_infinite()
            {
                if float.is_sign_negative() {
                    "-inf".into()
                } else {
                    "inf".into()
                }
            } else {
                crate::python_json::encode(value)
            }
        }
        _ => unreachable!("group keys were validated as scalars"),
    }
}

impl Builder {
    pub(super) fn new(
        source: &Map<String, Value>,
        host_centric: bool,
        timestamps: &super::TimestampPaths,
    ) -> Result<Self> {
        let timestamps = super::source::baseline_timestamps(timestamps, host_centric, source)?;
        let mut document = Map::new();
        document.insert("metadata".into(), metadata(source.get("metadata"))?);
        document.insert("permissions".into(), Value::Array(Vec::new()));
        let budgets = if host_centric && source.contains_key("global_budget") {
            Value::Object(Map::from_iter([(
                "network:request".into(),
                source["global_budget"].clone(),
            )]))
        } else {
            source.get("budgets").cloned().unwrap_or_else(empty_object)
        };
        document.insert("budgets".into(), integer_map(&budgets, "budgets")?);
        document.insert(
            "required".into(),
            array_of_strings(source.get("required"), "required")?,
        );
        let credentials = if host_centric && source.contains_key("credentials") {
            compile_credentials(source)?
        } else {
            source
                .get("credential_rules")
                .cloned()
                .unwrap_or_else(empty_array)
        };
        document.insert("credential_rules".into(), credential_rules(&credentials)?);
        document.insert(
            "scan_patterns".into(),
            scan_patterns(source.get("scan_patterns"))?,
        );
        document.insert("addons".into(), addons(source.get("addons"))?);
        // Host compilation replaces whole domain entries before normalizing
        // the final overrides. Keep their complete declared configuration.
        document.insert(
            "domains".into(),
            source.get("domains").cloned().unwrap_or_else(empty_object),
        );
        document.insert("clients".into(), overrides(source.get("clients"))?);
        document.insert(
            "gateway".into(),
            if host_centric {
                empty_object()
            } else {
                let value = source.get("gateway").cloned().unwrap_or_else(empty_object);
                object(&value, "gateway")?;
                value
            },
        );
        let simple = if host_centric {
            Map::new()
        } else {
            integer_map(
                &source
                    .get("simple_permissions")
                    .cloned()
                    .unwrap_or_else(empty_object),
                "simple_permissions",
            )?
            .as_object()
            .expect("integer map")
            .clone()
        };
        document.insert("simple_permissions".into(), Value::Object(simple.clone()));
        Ok(Self {
            document,
            permissions: Vec::new(),
            simple,
            resources: Default::default(),
            group_order: Vec::new(),
            host_centric,
            timestamps,
        })
    }

    pub(super) fn from_baseline(baseline: &Baseline) -> Self {
        let mut document = baseline.value.as_object().expect("baseline object").clone();
        let permissions = document["permissions"]
            .as_array()
            .expect("permissions")
            .iter()
            .enumerate()
            .filter(|(index, _)| !baseline.generated_permissions.contains(index))
            .map(|(_, value)| (value.clone(), false))
            .collect();
        let simple = document["simple_permissions"]
            .as_object()
            .expect("counts")
            .clone();
        document["permissions"] = empty_array();
        Self {
            document,
            permissions,
            simple,
            resources: Default::default(),
            group_order: Vec::new(),
            host_centric: false,
            timestamps: baseline.timestamps.clone(),
        }
    }

    /// Source host compilation extracts simple exact rules before schema
    /// validation. The caller may still emit an existing native simple Rule.
    pub(super) fn extract_simple(
        &mut self,
        raw: &Map<String, Value>,
        timestamps: &super::TimestampPaths,
    ) -> Result<bool> {
        if !self.host_centric {
            return Ok(false);
        }
        if timestamps.value_at(&["resource"]).is_some() {
            return Ok(false);
        }
        let Some(resource) = raw.get("resource").and_then(Value::as_str) else {
            return Ok(false);
        };
        if !super::exact_resource(resource)
            || raw.get("condition").is_some_and(truthy)
            || raw.get("effect").and_then(Value::as_str) == Some("budget")
            || raw
                .get("tier")
                .is_some_and(|value| value.as_str() != Some("explicit"))
        {
            return Ok(false);
        }
        let action = raw
            .get("action")
            .ok_or_else(|| invalid("permission needs action"))?;
        let default_effect = Value::String("allow".into());
        let effect = raw.get("effect").unwrap_or(&default_effect);
        let action_key = timestamps
            .value_at(&["action"])
            .map(|value| ScalarKey::Temporal(value.clone()))
            .map_or_else(|| scalar_key(action), Ok)?;
        let effect_key = timestamps
            .value_at(&["effect"])
            .map(|value| ScalarKey::Temporal(value.clone()))
            .map_or_else(|| scalar_key(effect), Ok)?;
        let key = (action_key, effect_key);
        if !self.resources.contains_key(&key) {
            self.group_order.push((
                key.clone(),
                (
                    timestamps
                        .value_at(&["action"])
                        .map_or_else(|| scalar_display(action), |value| value.python_display()),
                    timestamps
                        .value_at(&["effect"])
                        .map_or_else(|| scalar_display(effect), |value| value.python_display()),
                ),
            ));
        }
        self.resources
            .entry(key)
            .or_default()
            .insert(resource.to_owned());
        Ok(true)
    }

    pub(super) fn push(&mut self, permission: Value, generated: bool) {
        self.permissions.push((permission, generated));
    }

    pub(super) fn finish(mut self) -> Result<Baseline> {
        super::source::finish_domain_timestamps(&mut self.timestamps)?;
        self.document["domains"] = overrides(self.document.get("domains"))?;
        self.permissions.sort_by_key(|(permission, _)| {
            let condition = permission.get("condition").filter(|value| !value.is_null());
            std::cmp::Reverse(super::specificity_score(
                permission["resource"].as_str().expect("validated resource"),
                condition.is_some(),
                condition.is_some_and(|condition| !condition["port"].is_null()),
            ))
        });
        let generated_permissions = self
            .permissions
            .iter()
            .enumerate()
            .filter_map(|(index, (_, generated))| generated.then_some(index))
            .collect();
        self.document["permissions"] = Value::Array(
            std::mem::take(&mut self.permissions)
                .into_iter()
                .map(|(value, _)| value)
                .collect(),
        );
        // Source extraction groups by tuples, then formats the summary key.
        // A display-key collision overwrites the count in group insertion order.
        for (key, (action, effect)) in &self.group_order {
            self.simple.insert(
                format!("{}:{}", action, effect),
                Value::from(self.resources[key].len()),
            );
        }
        self.document["simple_permissions"] = Value::Object(std::mem::take(&mut self.simple));
        Ok(Baseline {
            value: Value::Object(std::mem::take(&mut self.document)),
            generated_permissions,
            timestamps: std::mem::take(&mut self.timestamps),
        })
    }
}

impl Drop for Builder {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut Value::Object(std::mem::take(&mut self.document)));
        for (permission, _) in &mut self.permissions {
            crate::credentials::wipe_json(permission);
        }
    }
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}
fn empty_array() -> Value {
    Value::Array(Vec::new())
}

fn value_or(value: Option<&Value>, default: impl FnOnce() -> Value) -> Value {
    value.cloned().unwrap_or_else(default)
}

fn array_of_strings(value: Option<&Value>, field: &str) -> Result<Value> {
    let value = value_or(value, empty_array);
    string_array(&value, field)?;
    Ok(value)
}

fn string_default(source: &Map<String, Value>, name: &str, default: &str) -> Result<Value> {
    let value = source
        .get(name)
        .cloned()
        .unwrap_or_else(|| Value::String(default.into()));
    string(&value, name)?;
    Ok(value)
}

fn nullable_string(source: &Map<String, Value>, name: &str) -> Result<Value> {
    let value = source.get(name).cloned().unwrap_or(Value::Null);
    if !value.is_null() {
        string(&value, name)?;
    }
    Ok(value)
}

fn metadata(value: Option<&Value>) -> Result<Value> {
    let source = value_or(value, empty_object);
    let source = object(&source, "metadata")?;
    let mut output = Map::new();
    output.insert("version".into(), string_default(source, "version", "1.0")?);
    for name in [
        "task_id",
        "description",
        "created",
        "approved",
        "brief_hash",
        "policy_hash",
    ] {
        let value = nullable_string(source, name)?;
        if name == "task_id"
            && let Some(task) = value.as_str()
            && (task.is_empty()
                || task.len() > 128
                || !task.as_bytes()[0].is_ascii_alphanumeric()
                || !task
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
        {
            return Err(invalid("invalid task identifier"));
        }
        output.insert(name.into(), value);
    }
    Ok(Value::Object(output))
}

/// Pydantic's non-strict integer fields preserve arbitrary Python integers.
/// Native network budget validation remains separate and unchanged.
fn integer(value: &Value, field: &str) -> Result<Value> {
    let text = match value {
        Value::Bool(value) => return Ok(Value::from(u8::from(*value))),
        Value::Number(value)
            if value
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-') =>
        {
            value.to_string()
        }
        Value::Number(value) => {
            let number = value
                .as_f64()
                .filter(|value| value.is_finite() && value.fract() == 0.)
                .ok_or_else(|| invalid(format!("{field} must be integer")))?;
            // Formatting a finite whole f64 with precision zero preserves the
            // exact integer that Python also obtains from that float value.
            format!("{number:.0}")
        }
        Value::String(value) => {
            let text = value.trim();
            // Pydantic accepts a decimal suffix only when every digit is zero.
            let text = if let Some((whole, fraction)) = text.split_once('.') {
                if fraction.is_empty() || !fraction.bytes().all(|byte| byte == b'0') {
                    return Err(invalid(format!("{field} must be integer")));
                }
                whole
            } else {
                text
            };
            let mut digits = String::with_capacity(text.len());
            for (index, character) in text.chars().enumerate() {
                if (index == 0 && matches!(character, '+' | '-'))
                    || character.is_ascii_digit()
                    || character == '_'
                {
                    digits.push(character);
                } else {
                    return Err(invalid(format!("{field} must be integer")));
                }
            }
            if digits.contains("__")
                || digits.starts_with('_')
                || digits.ends_with('_')
                || digits.starts_with("+_")
                || digits.starts_with("-_")
            {
                return Err(invalid(format!("{field} must be integer")));
            }
            digits.replace('_', "")
        }
        _ => return Err(invalid(format!("{field} must be integer"))),
    };
    let integer = text
        .parse::<BigInt>()
        .map_err(|_| invalid(format!("{field} must be integer")))?;
    let number = integer
        .to_string()
        .parse::<serde_json::Number>()
        .map_err(|_| invalid(format!("{field} must be integer")))?;
    Ok(Value::Number(number))
}

fn integer_map(value: &Value, field: &str) -> Result<Value> {
    object(value, field)?
        .iter()
        .map(|(key, value)| Ok((key.clone(), integer(value, field)?)))
        .collect::<Result<Map<_, _>>>()
        .map(Value::Object)
}

pub(super) fn permission(value: &Value) -> Result<Value> {
    let source = object(value, "permission")?;
    let action = source
        .get("action")
        .and_then(Value::as_str)
        .filter(|action| {
            matches!(
                *action,
                "credential:use"
                    | "network:request"
                    | "file:read"
                    | "file:write"
                    | "subprocess:exec"
                    | "gateway:risky_route"
                    | "gateway:request"
            )
        })
        .ok_or_else(|| invalid("unknown or missing permission action"))?;
    let resource = source
        .get("resource")
        .ok_or_else(|| invalid("permission needs resource"))?;
    string(resource, "resource")?;
    let effect = source
        .get("effect")
        .and_then(Value::as_str)
        .unwrap_or("allow");
    if source.get("effect").is_some_and(|value| !value.is_string())
        || !matches!(effect, "allow" | "deny" | "prompt" | "budget")
    {
        return Err(invalid("invalid permission effect"));
    }
    let tier = source
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("explicit");
    if source.get("tier").is_some_and(|value| !value.is_string())
        || !matches!(tier, "explicit" | "inferred")
    {
        return Err(invalid("invalid permission tier"));
    }
    let budget = source
        .get("budget")
        .filter(|value| !value.is_null())
        .map(|value| integer(value, "budget"))
        .transpose()?
        .unwrap_or(Value::Null);
    if effect == "budget" && budget.is_null() {
        return Err(invalid("budget effect requires budget"));
    }
    let mut output = Map::new();
    output.insert("action".into(), Value::String(action.into()));
    output.insert("resource".into(), resource.clone());
    output.insert("effect".into(), Value::String(effect.into()));
    output.insert("budget".into(), budget);
    output.insert("tier".into(), Value::String(tier.into()));
    output.insert("condition".into(), condition(source.get("condition"))?);
    Ok(Value::Object(output))
}

fn condition(value: Option<&Value>) -> Result<Value> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Value::Null);
    };
    let source = object(value, "condition")?;
    let mut output = Map::new();
    for name in [
        "credential",
        "method",
        "port",
        "path_prefix",
        "content_type",
        "tactics",
        "enables",
        "irreversible",
        "account",
        "agent",
        "service",
        "capability",
    ] {
        let value = source.get(name).cloned().unwrap_or(Value::Null);
        if !value.is_null() {
            match name {
                "credential" | "method" | "account" => {
                    super::string_list(&value, name)?;
                }
                "port" => {
                    let entries = value
                        .as_array()
                        .map_or_else(|| vec![&value], |values| values.iter().collect());
                    if entries.is_empty()
                        || entries.iter().any(|value| {
                            value
                                .as_u64()
                                .is_none_or(|value| value == 0 || value > 65535)
                        })
                    {
                        return Err(invalid("port must be an integer from 1 to 65535"));
                    }
                }
                "tactics" | "enables" => {
                    string_array(&value, name)?;
                }
                "irreversible" => {
                    output.insert(name.into(), Value::Bool(boolean(&value, name)?));
                    continue;
                }
                _ => {
                    string(&value, name)?;
                }
            }
        }
        output.insert(name.into(), value);
    }
    Ok(Value::Object(output))
}

fn addons(value: Option<&Value>) -> Result<Value> {
    let source = value_or(value, empty_object);
    let mut output = Map::new();
    for (name, value) in object(&source, "addons")? {
        let config = object(value, "addon")?;
        let mut addon = Map::new();
        addon.insert(
            "enabled".into(),
            Value::Bool(
                config
                    .get("enabled")
                    .map(|value| boolean(value, "addon enabled"))
                    .transpose()?
                    .unwrap_or(true),
            ),
        );
        let settings = value_or(config.get("settings"), empty_object);
        object(&settings, "addon settings")?;
        addon.insert("settings".into(), settings);
        addon.extend(
            config
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "enabled" | "settings"))
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        output.insert(name.clone(), Value::Object(addon));
    }
    Ok(Value::Object(output))
}

fn overrides(value: Option<&Value>) -> Result<Value> {
    let source = value_or(value, empty_object);
    object(&source, "overrides")?
        .iter()
        .map(|(name, value)| {
            let source = object(value, "override")?;
            Ok((
                name.clone(),
                Value::Object(Map::from_iter([
                    (
                        "bypass".into(),
                        array_of_strings(source.get("bypass"), "bypass")?,
                    ),
                    ("addons".into(), addons(source.get("addons"))?),
                ])),
            ))
        })
        .collect::<Result<Map<_, _>>>()
        .map(Value::Object)
}

fn credential_rules(value: &Value) -> Result<Value> {
    value
        .as_array()
        .ok_or_else(|| invalid("credential_rules must be an array"))?
        .iter()
        .map(|value| {
            let source = object(value, "credential rule")?;
            let mut rule = Map::new();
            for field in ["name", "patterns", "allowed_hosts"] {
                let value = source
                    .get(field)
                    .ok_or_else(|| invalid(format!("credential rule needs {field}")))?;
                if field == "name" {
                    string(value, field)?;
                } else {
                    string_array(value, field)?;
                }
                rule.insert(field.into(), value.clone());
            }
            let headers = source
                .get("header_names")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(["authorization", "x-api-key"]));
            string_array(&headers, "header_names")?;
            rule.insert("header_names".into(), headers);
            rule.insert(
                "suggested_url".into(),
                string_default(source, "suggested_url", "")?,
            );
            Ok(Value::Object(rule))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn compile_credentials(source: &Map<String, Value>) -> Result<Value> {
    let credentials = object(&source["credentials"], "credentials")?;
    let hosts = object(&source["hosts"], "hosts")?;
    let mut rules = Vec::new();
    for (name, config) in credentials {
        let config = object(config, "credential configuration")?;
        let mut rule = Map::new();
        rule.insert("name".into(), Value::String(name.clone()));
        rule.insert(
            "patterns".into(),
            config
                .get("patterns")
                .ok_or_else(|| invalid("credential needs patterns"))?
                .clone(),
        );
        let allowed = if let Some(value) = config.get("allowed_hosts") {
            value.clone()
        } else {
            let mut allowed = Vec::new();
            for (host, config) in hosts {
                if host == "*" {
                    continue;
                }
                let Some(config) = config.as_object() else {
                    continue;
                };
                let Some(credentials) = config.get("credentials") else {
                    continue;
                };
                let credentials = super::string_list(credentials, "host credentials")?;
                if credentials
                    .iter()
                    .any(|value| value == name || value == &format!("{name}:*"))
                {
                    allowed.push(Value::String(
                        if host.contains('/') {
                            host.trim_end_matches(['/', '*'])
                        } else {
                            host
                        }
                        .into(),
                    ));
                }
            }
            Value::Array(allowed)
        };
        rule.insert("allowed_hosts".into(), allowed);
        for (from, to) in [
            ("headers", "header_names"),
            ("suggested_url", "suggested_url"),
        ] {
            if let Some(value) = config.get(from) {
                rule.insert(to.into(), value.clone());
            }
        }
        rules.push(Value::Object(rule));
    }
    Ok(Value::Array(rules))
}

fn scan_patterns(value: Option<&Value>) -> Result<Value> {
    let value = value_or(value, empty_array);
    value
        .as_array()
        .ok_or_else(|| invalid("scan_patterns must be an array"))?
        .iter()
        .map(|value| {
            let source = object(value, "scan pattern")?;
            let mut pattern = Map::new();
            for name in ["name", "pattern"] {
                let value = source
                    .get(name)
                    .ok_or_else(|| invalid(format!("scan pattern needs {name}")))?;
                string(value, name)?;
                pattern.insert(name.into(), value.clone());
            }
            for (name, default, allowed) in [
                ("target", "both", &["request", "response", "both"][..]),
                ("action", "log", &["block", "log"][..]),
                (
                    "severity",
                    "medium",
                    &["low", "medium", "high", "critical"][..],
                ),
            ] {
                let value = string_default(source, name, default)?;
                if !allowed.contains(&value.as_str().expect("string")) {
                    return Err(invalid(format!("invalid scan {name}")));
                }
                pattern.insert(name.into(), value);
            }
            let scope = source
                .get("scope")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(["body"]));
            if string_array(&scope, "scope")?
                .iter()
                .any(|scope| !matches!(scope.as_str(), "url" | "headers" | "body"))
            {
                return Err(invalid("invalid scan scope"));
            }
            // Preserve the model's field order, which puts scope before action.
            let action = pattern.shift_remove("action").expect("action");
            let severity = pattern.shift_remove("severity").expect("severity");
            pattern.insert("scope".into(), scope);
            pattern.insert("action".into(), action);
            pattern.insert("severity".into(), severity);
            pattern.insert("message".into(), string_default(source, "message", "")?);
            pattern.insert(
                "case_sensitive".into(),
                Value::Bool(
                    source
                        .get("case_sensitive")
                        .map(|value| boolean(value, "case_sensitive"))
                        .transpose()?
                        .unwrap_or(true),
                ),
            );
            Ok(Value::Object(pattern))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_none_or(|value| value != 0.),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::{Effect, Format, NetworkRequest, Policy};
    use serde_json::json;

    #[test]
    fn retained_timestamps_fail_only_the_json_view_and_survive_mutations() {
        use crate::policy::BaselineSerializationError::NonJsonTimestamp;
        use std::sync::Arc;

        for source in [
            "addons: {synthetic: {settings: {observed: 2001-02-03}}}",
            "addons: {synthetic: {settings: {observed: 2001-02-03T04:05:06Z}}}",
            "addons: {synthetic: {settings: {observed: !!timestamp '2001-02-03'}}}",
        ] {
            let policy = Policy::parse(source, Format::Yaml).unwrap();
            assert!(matches!(policy.baseline(), Err(NonJsonTimestamp)));
            let task = policy
                .with_task_source("permissions: []", Format::Yaml)
                .unwrap();
            assert!(Arc::ptr_eq(
                policy.baseline.as_ref().unwrap(),
                task.baseline.as_ref().unwrap()
            ));
            assert!(matches!(
                task.without_task().baseline(),
                Err(NonJsonTimestamp)
            ));
            let replaced = task.with_gateway_routes(&[]);
            assert!(matches!(replaced.baseline(), Err(NonJsonTimestamp)));
            assert!(
                policy
                    .reload_from_source_at(
                        "metadata: {created: 2001-02-03T04:05:06Z}",
                        Format::Yaml,
                        0.
                    )
                    .is_err()
            );
            assert!(matches!(policy.baseline(), Err(NonJsonTimestamp)));
            let next = task.reload_from_source_at("{}", Format::Yaml, 0.).unwrap();
            assert!(next.baseline().unwrap().is_some());
            assert!(next.task.is_some());
        }
        for source in [
            "metadata: {ignored: 2001-02-03T04:05:06Z}",
            "domains: {example.test: {ignored: 2001-02-03}}",
            "addons: {synthetic: {settings: {observed: !!str 2001-02-03}}}",
            "addons: {synthetic: {settings: {observed: {yaml_date: '2001-02-03'}}}}",
        ] {
            assert!(
                Policy::parse(source, Format::Yaml)
                    .unwrap()
                    .baseline()
                    .is_ok()
            );
        }
    }

    #[test]
    fn temporal_mapping_keys_keep_identity_order_and_cannot_collide_with_authored_keys() {
        let source = r#"
base: &base
  2001-02-03: original
  '2001-02-03': quoted
  "\0temporal-key-0": authored
addons:
  synthetic:
    settings:
      nested:
        <<: *base
        2001-02-03: replacement
"#;
        let policy = Policy::parse(source, Format::Yaml).unwrap();
        assert!(policy.baseline().is_err());
        let baseline = policy.baseline.as_ref().unwrap();
        let map = baseline.value["addons"]["synthetic"]["settings"]["nested"]
            .as_object()
            .unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["2001-02-03"], "quoted");
        assert_eq!(map["\0temporal-key-0"], "authored");
        let typed_key = map
            .keys()
            .find(|key| {
                baseline
                    .timestamps
                    .key_at(&["addons", "synthetic", "settings", "nested", key])
                    .is_some()
            })
            .unwrap();
        assert_ne!(typed_key, "2001-02-03");
        assert_ne!(typed_key, "\0temporal-key-0");
        assert_eq!(map[typed_key], "replacement");
        assert_eq!(
            map.values().collect::<Vec<_>>(),
            vec![&json!("replacement"), &json!("quoted"), &json!("authored")]
        );

        let policy = Policy::parse(
            r#"
addons:
  synthetic:
    settings:
      nested:
        2001-02-03T04:05:06Z: original
        2001-02-03T05:05:06+01:00: replacement
        '2001-02-03 04:05:06+00:00': quoted
"#,
            Format::Yaml,
        )
        .unwrap();
        let baseline = policy.baseline.as_ref().unwrap();
        let nested = baseline.value["addons"]["synthetic"]["settings"]["nested"]
            .as_object()
            .unwrap();
        assert_eq!(nested.len(), 2);
        assert_eq!(
            nested.values().collect::<Vec<_>>(),
            vec![&json!("replacement"), &json!("quoted")]
        );
    }

    #[test]
    fn temporal_provenance_follows_sibling_overrides_lists_and_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.yaml");
        let sibling = directory.path().join("addons.yaml");
        std::fs::write(&sibling, "metadata: {created: 2001-02-03T04:05:06Z}\naddons: {synthetic: {settings: {observed: 2001-02-03}}}").unwrap();
        std::fs::write(
            &path,
            "metadata: {version: '1.0'}\naddons: {synthetic: {enabled: false}}",
        )
        .unwrap();
        let initial = Policy::from_path_at(&path, 0.).unwrap();
        assert!(initial.baseline().is_ok());
        std::fs::write(&path, "metadata: {version: '1.0'}").unwrap();
        let retained = initial.reload_from_path_at(&path, 0.).unwrap();
        assert!(retained.baseline().is_err());
        std::fs::write(&path, "metadata: {created: 2001-02-03T04:05:06Z}").unwrap();
        assert!(retained.reload_from_path_at(&path, 0.).is_err());
        assert!(retained.baseline().is_err());
        std::fs::write(&sibling, "{").unwrap();
        std::fs::write(&path, "hosts: {'$missing': {expires: 2001-02-03T04:05:06Z, bypass: [2001-02-03]}}\nlists: {missing: absent.txt}").unwrap();
        assert!(
            Policy::from_path_at(&path, 1_800_000_000_000.)
                .unwrap()
                .baseline()
                .is_ok()
        );
        std::fs::write(
            directory.path().join("hosts.txt"),
            "a.example.test\nb.example.test\n",
        )
        .unwrap();
        std::fs::write(&path, "hosts: {'$targets': {addons: {synthetic: {settings: {observed: 2001-02-03}}}}}\nlists: {targets: hosts.txt}").unwrap();
        let from_list = Policy::from_path_at(&path, 0.).unwrap();
        assert!(from_list.baseline().is_err());
        let baseline = from_list.baseline.as_ref().unwrap();
        assert!(
            baseline
                .timestamps
                .value_at(&[
                    "domains",
                    "a.example.test",
                    "addons",
                    "synthetic",
                    "settings",
                    "observed"
                ])
                .is_some()
        );
        assert!(
            baseline
                .timestamps
                .value_at(&[
                    "domains",
                    "b.example.test",
                    "addons",
                    "synthetic",
                    "settings",
                    "observed"
                ])
                .is_some()
        );
        std::fs::write(&path, "hosts: {'$targets': {addons: {synthetic: {settings: {observed: 2001-02-03}}}}, a.example.test: {egress: allow}, b.example.test: {egress: allow}}\nlists: {targets: hosts.txt}").unwrap();
        assert!(Policy::from_path_at(&path, 0.).unwrap().baseline().is_ok());
    }

    #[test]
    fn typed_toml_values_follow_alias_winners_and_any_serialization() {
        for source in [
            "version = 2001-02-03\n",
            "[metadata]\ncreated = 2001-02-03T04:05:06Z\n",
            "[hosts]\n[credential.synthetic]\nmatch = [2001-02-03]\n",
            "[[risk]]\nirreversible = 04:05:06\n[hosts]\n",
        ] {
            assert!(Policy::parse(source, Format::Toml).is_err());
        }
        for source in [
            "version='1.0'\n[metadata]\ncreated=2001-02-03T04:05:06Z\n",
            "[hosts]\n[credential.synthetic]\nmatch=[2001-02-03]\npatterns=['literal']\n",
            "[hosts]\n[credential.synthetic]\npatterns=[2001-02-03]\nmatch=['literal']\n",
            "[hosts.'example.test']\nallow=[2001-02-03]\ncredentials=['synthetic:*']\n",
        ] {
            assert!(
                Policy::parse(source, Format::Toml)
                    .unwrap()
                    .baseline()
                    .is_ok()
            );
        }
        for source in [
            "[addons.synthetic.settings]\nobserved=2001-02-03\n",
            "[addons.synthetic.settings]\nobserved=2001-02-03T04:05:06Z\n",
            "[addons.synthetic.settings]\nobserved=04:05:06.123456\n",
        ] {
            assert!(
                Policy::parse(source, Format::Toml)
                    .unwrap()
                    .baseline()
                    .is_err()
            );
        }
    }

    #[test]
    fn toml_temporal_projection_matches_thirty_actual_loader_and_api_rows() {
        use crate::policy::BaselineSerializationError::NonJsonTimestamp;

        let fixture =
            crate::policy::parse_json(include_str!("../../tests/policy_toml_temporal.json"), false)
                .unwrap();
        let rows = fixture["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 30);
        let mut policy = Policy::parse("", Format::Toml).unwrap();
        for row in rows {
            let name = row["case"].as_str().unwrap();
            if !name.starts_with("lifecycle_") || name == "lifecycle_initial" {
                policy = Policy::parse("", Format::Toml).unwrap();
            }
            let candidate = policy.reload_from_source_at(
                row["input_toml"].as_str().unwrap(),
                Format::Toml,
                1_800_000_000_000.,
            );
            assert_eq!(
                candidate.is_ok(),
                row["loaded"].as_bool().unwrap(),
                "{name}: actual candidate admission"
            );
            if let Ok(candidate) = candidate {
                policy = candidate;
            }
            match row["status"].as_u64().unwrap() {
                200 => assert_eq!(
                    policy.baseline().unwrap().unwrap(),
                    &row["body"]["policy"],
                    "{name}: baseline retained after load outcome"
                ),
                500 => assert!(
                    matches!(policy.baseline(), Err(NonJsonTimestamp)),
                    "{name}: ordinary JSON failure"
                ),
                _ => panic!("unexpected frozen source status"),
            }
            let baseline = policy.baseline.as_ref().unwrap();
            for temporal in row["retained_temporal"].as_array().unwrap() {
                let path = temporal["path"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|part| {
                        part.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| part.to_string())
                    })
                    .collect::<Vec<_>>();
                let native = baseline
                    .timestamps
                    .value_at(&path.iter().map(String::as_str).collect::<Vec<_>>())
                    .expect("retained source temporal provenance");
                assert_eq!(
                    native.python_display(),
                    temporal["display"].as_str().unwrap(),
                    "{name}: exact time and fractional truncation"
                );
            }
            assert_eq!(
                baseline.value["simple_permissions"], row["simple_permissions"],
                "{name}: source extraction display"
            );
            if let Some(effect) = row
                .get("enforcement_effect")
                .and_then(serde_json::Value::as_str)
            {
                let request = NetworkRequest {
                    agent: Some("alice"),
                    host: "lifecycle.invalid",
                    port: Some(80),
                    method: "GET",
                    path: "/",
                };
                assert_eq!(
                    policy.evaluate(request, 0., false).unwrap().effect,
                    if effect == "allow" {
                        Effect::Allow
                    } else {
                        Effect::Deny
                    }
                );
            }
        }
    }

    #[test]
    fn schema_keeps_defaults_scalar_shapes_and_nonproxy_actions() {
        let policy = Policy::parse(&json!({"permissions":[
            {"action":"file:read", "resource":"*", "budget":18446744073709551617_u128},
            {"action":"network:request", "resource":"*", "condition":{"method":"GET", "account":["agent"], "ignored":true}}
        ], "gateway":{"object":{"$serde_json::private::Number":"123"}}}).to_string(), Format::Json).unwrap();
        let baseline = policy.baseline().unwrap().unwrap();
        assert_eq!(baseline.as_object().unwrap().len(), 11);
        assert_eq!(baseline["metadata"]["version"], "1.0");
        assert_eq!(baseline["permissions"][0]["condition"]["method"], "GET");
        assert_eq!(
            baseline["permissions"][0]["condition"]["account"],
            json!(["agent"])
        );
        assert_eq!(
            baseline["permissions"][0]["condition"]
                .as_object()
                .unwrap()
                .len(),
            12
        );
        assert_eq!(
            baseline["permissions"][1]["budget"].to_string(),
            "18446744073709551617"
        );
        assert!(baseline["gateway"]["object"].is_object());
        assert_eq!(
            baseline["gateway"]["object"]["$serde_json::private::Number"],
            "123"
        );
        assert!(!format!("{policy:?}").contains("$serde_json"));
    }

    #[test]
    fn tuple_groups_survive_formatted_summary_collisions() {
        let policy = Policy::parse(
            &json!({"hosts":{"x.invalid":{"rules":[
                {"action":"a:b","effect":"c","resource":"one.invalid/*"},
                {"action":"a","effect":"b:c","resource":"two.invalid/*"},
                {"action":"a:b","effect":"c","resource":"three.invalid/*"}
            ]}}})
            .to_string(),
            Format::Json,
        )
        .unwrap();
        assert_eq!(
            policy.baseline().unwrap().unwrap()["simple_permissions"],
            json!({"a:b:c":1})
        );
        assert_eq!(
            policy.baseline().unwrap().unwrap()["permissions"],
            json!([])
        );
    }

    #[test]
    fn scalar_tuple_groups_preserve_python_equality_and_never_grant_unknown_effects() {
        let source = json!({"hosts":{"x.invalid":{"rules":[
            {"action":true,"effect":null,"resource":"one.invalid/*"},
            {"action":1,"effect":null,"resource":"two.invalid/*"},
            {"action":1.0,"effect":null,"resource":"three.invalid/*"},
            {"action":"network:request","effect":true,"resource":"x.invalid/*"},
            {"action":"network:request","effect":null,"resource":"y.invalid/*"}
        ]}}});
        let policy = Policy::parse(&source.to_string(), Format::Json).unwrap();
        assert_eq!(
            policy.baseline().unwrap().unwrap()["simple_permissions"],
            json!({"True:None":3,"network:request:True":1,"network:request:None":1})
        );
        for host in ["x.invalid", "y.invalid"] {
            assert_eq!(
                policy
                    .evaluate(
                        NetworkRequest {
                            agent: None,
                            host,
                            port: Some(443),
                            method: "GET",
                            path: "/"
                        },
                        0.,
                        false
                    )
                    .unwrap()
                    .effect,
                Effect::Deny
            );
        }
        let tier_null = json!({"hosts":{"x.invalid":{"rules":[{"action":"network:request","resource":"x.invalid/*","tier":null}]}}});
        assert!(Policy::parse(&tier_null.to_string(), Format::Json).is_err());
    }

    #[test]
    fn toml_normalization_drives_the_same_risk_and_credential_matcher() {
        let policy = Policy::parse(
            r#"
version = "3.0"
description = "top"
[metadata]
description = "nested"
[credential.fixture]
match = ["abc"]
[hosts."api.invalid"]
allow = ["fixture:*"]
egress = "allow"
[[risk]]
decision = "deny"
agent = "alice"
"#,
            Format::Toml,
        )
        .unwrap();
        let baseline = policy.baseline().unwrap().unwrap();
        assert_eq!(baseline["metadata"]["description"], "top");
        assert_eq!(
            baseline["credential_rules"][0]["allowed_hosts"],
            json!(["api.invalid"])
        );
        assert!(
            baseline["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|permission| permission["action"] == "gateway:risky_route")
        );
        assert_eq!(
            policy
                .evaluate_credential(
                    crate::policy::CredentialRequest {
                        credential_type: "fixture",
                        destination: "api.invalid",
                        path: "/",
                        credential_hmac: None
                    },
                    0.
                )
                .unwrap()
                .effect,
            Effect::Allow
        );
    }

    #[test]
    fn reads_tasks_and_failed_reload_preserve_the_authoritative_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"deny"}]}"#,
        )
        .unwrap();
        std::fs::write(path.with_file_name("addons.yaml"), "addons: [").unwrap();
        let policy = Policy::from_path_at(&path, 0.).unwrap();
        let view = policy.baseline().unwrap().unwrap().clone();
        let task = policy
            .with_task_source(
                r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
                Format::Json,
            )
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(
            policy.baseline.as_ref().unwrap(),
            task.baseline.as_ref().unwrap()
        ));
        assert_eq!(task.baseline().unwrap().unwrap(), &view);
        assert_eq!(
            task.evaluate(
                NetworkRequest {
                    agent: Some("alice"),
                    host: "x.invalid",
                    port: Some(443),
                    method: "GET",
                    path: "/"
                },
                0.,
                false
            )
            .unwrap()
            .effect,
            Effect::Allow
        );
        std::fs::write(&path, "{").unwrap();
        assert_eq!(policy.baseline().unwrap().unwrap(), &view);
        assert!(policy.reload_from_path_at(&path, 0.).is_err());
        assert_eq!(policy.baseline().unwrap().unwrap(), &view);
        assert_eq!(task.without_task().baseline().unwrap().unwrap(), &view);
    }

    #[test]
    #[ignore = "historical Python loader oracle; set SAFEYOLO_POLICY_PYTHON"]
    fn projection_matches_the_actual_python_loader_matrix() {
        use std::{path::Path, process::Command, sync::Arc};
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let output = Command::new(
            std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
        )
        .arg(root.join("proxy/tests/policy_projection_oracle.py"))
        .current_dir(root)
        .env("PYTHONPATH", "cli/src:.")
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "source fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let source =
            crate::policy::parse_json(std::str::from_utf8(&output.stdout).unwrap(), false).unwrap();
        assert_eq!(source["row_count"], 18);
        for row in source["rows"].as_array().unwrap() {
            let name = row["case"].as_str().unwrap();
            if name == "no_configured_path" {
                assert!(Policy::unconfigured().baseline().unwrap().is_none());
                continue;
            }
            if name == "task_and_reload" {
                let initial = Policy::parse(&row["before"].to_string(), Format::Json).unwrap();
                let task=initial.with_task_source(r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,Format::Json).unwrap();
                assert_eq!(task.baseline().unwrap().unwrap(), &row["after_task"]);
                let next = task
                    .reload_from_source_at(&row["after_reload"].to_string(), Format::Json, 0.)
                    .unwrap();
                assert!(next.reload_from_source_at("{", Format::Json, 0.).is_err());
                assert_eq!(next.baseline().unwrap().unwrap(), &row["after_failure"]);
                continue;
            }
            let directory = tempfile::tempdir().unwrap();
            let path = directory
                .path()
                .join(row["input"]["filename"].as_str().unwrap());
            std::fs::write(&path, row["input"]["source"].as_str().unwrap()).unwrap();
            for (name, contents) in row["input"]["siblings"].as_object().unwrap() {
                std::fs::write(directory.path().join(name), contents.as_str().unwrap()).unwrap();
            }
            let registry = if name == "gateway_registry_present" {
                let builtin = std::fs::read_dir(root.join("cli/src/safeyolo/services"))
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| {
                        path.extension()
                            .is_some_and(|extension| extension == "yaml")
                    })
                    .map(|path| {
                        (
                            path.file_name().unwrap().to_string_lossy().into_owned(),
                            std::fs::read_to_string(path).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                Some(Arc::new(
                    crate::services::Registry::from_sources(&builtin, &[]).unwrap(),
                ))
            } else {
                None
            };
            let loaded = Policy::from_path_with_registry_at(&path, registry, 1_800_000_000_000.);
            if name == "invalid_initial_load" {
                // The source initialized loader keeps its empty model on this
                // schema error. Native runtime startup policy is separate.
                assert!(loaded.is_err());
                assert_eq!(
                    Policy::parse("{}", Format::Json)
                        .unwrap()
                        .baseline()
                        .unwrap()
                        .unwrap(),
                    &row["baseline"]
                );
                continue;
            }
            let policy = loaded.unwrap_or_else(|error| panic!("{name}: {error}"));
            let mut actual = policy.baseline().unwrap().unwrap().clone();
            mask_generated_tokens(&mut actual, &row["baseline"]);
            assert_eq!(actual, row["baseline"], "{name}");
        }
        assert_eq!(source["timestamps"].as_array().unwrap().len(), 87);
        for row in source["timestamps"].as_array().unwrap() {
            let name = row["case"].as_str().unwrap();
            let scalar = row["scalar"].as_str().unwrap();
            let loaded = Policy::parse(row["source"].as_str().unwrap(), Format::Yaml);
            assert_eq!(
                loaded.is_ok(),
                row["loaded"].as_bool().unwrap(),
                "{name}/{scalar} admission"
            );
            if let Ok(policy) = loaded {
                if row["serializable"] == false {
                    assert!(
                        matches!(
                            policy.baseline(),
                            Err(crate::policy::BaselineSerializationError::NonJsonTimestamp)
                        ),
                        "{name}/{scalar} serialization must retain source type"
                    );
                } else {
                    let mut actual = policy.baseline().unwrap().unwrap().clone();
                    mask_generated_tokens(&mut actual, &row["expected"]);
                    assert_eq!(actual, row["expected"], "{name}/{scalar}");
                }
            }
        }
        for case in source["supplemental"]["scalar_groups"].as_array().unwrap() {
            let policy = Policy::parse(&case["source"].to_string(), Format::Json).unwrap();
            assert_eq!(
                policy.baseline().unwrap().unwrap()["simple_permissions"],
                case["expected"]
            );
        }
        for case in source["supplemental"]["integers"].as_array().unwrap() {
            let actual = super::integer(&case["value"], "fixture integer");
            assert_eq!(
                actual.is_ok(),
                case["accepted"].as_bool().unwrap(),
                "integer admission {}",
                case["value"]
            );
            if let Ok(actual) = actual {
                assert_eq!(actual, case["expected"]);
            }
        }
    }

    fn mask_generated_tokens(actual: &mut serde_json::Value, expected: &serde_json::Value) {
        use serde_json::{Map, Value};
        let Some(expected_tokens) = expected["gateway"]
            .get("token_map")
            .and_then(Value::as_object)
        else {
            assert!(
                actual["gateway"]
                    .get("token_map")
                    .and_then(Value::as_object)
                    .is_none_or(Map::is_empty),
                "unexpected generated token collection"
            );
            return;
        };
        let Some(actual_tokens) = actual["gateway"]
            .get_mut("token_map")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        assert_eq!(actual_tokens.len(), expected_tokens.len(), "token count");
        let old = std::mem::take(actual_tokens);
        let mut labels = std::collections::HashMap::new();
        for ((mut token, binding), (label, _)) in old.into_iter().zip(expected_tokens) {
            labels.insert(token.clone(), label.clone());
            actual_tokens.insert(label.clone(), binding);
            zeroize::Zeroize::zeroize(&mut token);
        }
        if let Some(environment) = actual["gateway"]
            .get_mut("agent_env")
            .and_then(Value::as_object_mut)
        {
            for services in environment.values_mut().filter_map(Value::as_object_mut) {
                for token in services.values_mut() {
                    let label = labels
                        .get(token.as_str().expect("synthetic token must be string"))
                        .expect("environment token belongs to same snapshot")
                        .clone();
                    crate::credentials::wipe_json(token);
                    *token = Value::String(label);
                }
            }
        }
        let mut keys = Value::Object(
            labels
                .into_iter()
                .map(|(key, value)| (key, Value::String(value)))
                .collect::<Map<_, _>>(),
        );
        crate::credentials::wipe_json(&mut keys);
    }
}
