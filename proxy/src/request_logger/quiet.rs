//! Only reached source quiet operations interpret raw policy values.
use std::collections::HashMap;

use serde_json::Value;
use zeroize::Zeroizing;

use super::{Error, ErrorKind};
use crate::policy::Policy;

#[derive(Default)]
pub(super) struct Quiet {
    hosts: Vec<Zeroizing<String>>,
    patterns: Vec<Zeroizing<String>>,
    paths: HashMap<String, Vec<Pattern>>,
}
enum Pattern {
    Text(Zeroizing<String>),
    Invalid,
}
pub(super) enum LoadError {
    Malformed(String),
    Reached(Error),
}
fn reached(kind: ErrorKind) -> LoadError {
    LoadError::Reached(Error(kind))
}
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.to_string().contains(['.', 'e', 'E']) {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}
impl Quiet {
    pub(super) fn load(policy: &Policy) -> Result<Self, LoadError> {
        let view = policy.request_logger_settings();
        let empty = serde_json::Map::new();
        let section = match view.value() {
            None => &empty,
            Some(value) if view.temporal_value(&[]).is_none() => value
                .as_object()
                .ok_or_else(|| reached(ErrorKind::Attribute))?,
            Some(_) => return Err(reached(ErrorKind::Attribute)),
        };
        let list = Vec::new();
        let hosts = if let Some(value) = section.get("hosts") {
            if view.temporal_value(&["hosts"]).is_some() || !value.is_array() {
                let name = view
                    .temporal_value(&["hosts"])
                    .map_or_else(|| type_name(value), |value| value.python_type_name());
                return Err(LoadError::Malformed(format!(
                    "quiet_hosts.hosts must be a list, got {name}. Fix addons.request_logger.quiet_hosts.hosts in policy."
                )));
            }
            value.as_array().unwrap()
        } else {
            &list
        };
        let paths = if let Some(value) = section.get("paths") {
            if view.temporal_value(&["paths"]).is_some() || !value.is_object() {
                let name = view
                    .temporal_value(&["paths"])
                    .map_or_else(|| type_name(value), |value| value.python_type_name());
                return Err(LoadError::Malformed(format!(
                    "quiet_hosts.paths must be a dict of host -> [path, ...], got {name}. Fix addons.request_logger.quiet_hosts.paths in policy."
                )));
            }
            value.as_object().unwrap()
        } else {
            &empty
        };
        let mut result = Self::default();
        for (index, host) in hosts.iter().enumerate() {
            let temporal = view
                .temporal_value(&["hosts", &index.to_string()])
                .is_some();
            let Some(host) = host.as_str().filter(|_| !temporal) else {
                // Containers permit the membership operation, then fail .lower;
                // noniterable scalars fail the earlier `"*" in host` operation.
                return Err(reached(
                    if !temporal && (host.is_array() || host.is_object()) {
                        ErrorKind::Attribute
                    } else {
                        ErrorKind::Type
                    },
                ));
            };
            let destination = if host.contains('*') {
                &mut result.patterns
            } else {
                &mut result.hosts
            };
            destination.push(Zeroizing::new(host.to_lowercase()));
        }
        for (host, patterns) in paths {
            let path = ["paths", host];
            if view.temporal_value(&path).is_some() || !patterns.is_array() {
                let name = view
                    .temporal_value(&path)
                    .map_or_else(|| type_name(patterns), |value| value.python_type_name());
                let display = view
                    .temporal_key(&path)
                    .map_or_else(|| host.to_owned(), |key| key.python_display());
                return Err(LoadError::Malformed(format!(
                    "quiet_hosts.paths['{display}'] must be a list of path patterns, got {name}. Fix policy."
                )));
            }
            if view.temporal_key(&path).is_some() {
                return Err(reached(ErrorKind::Attribute));
            }
            let patterns = patterns
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(index, pattern)| {
                    match pattern.as_str().filter(|_| {
                        view.temporal_value(&["paths", host, &index.to_string()])
                            .is_none()
                    }) {
                        Some(text) => Pattern::Text(Zeroizing::new(text.to_owned())),
                        None => Pattern::Invalid,
                    }
                })
                .collect();
            result.paths.insert(host.to_lowercase(), patterns);
        }
        Ok(result)
    }
    pub(super) fn matches(&self, host: &str, path: &str) -> Result<bool, Error> {
        let host = host.to_lowercase();
        if self.hosts.iter().any(|value| value.as_str() == host) {
            return Ok(true);
        }
        for pattern in &self.patterns {
            if crate::policy::glob(&host, pattern) {
                return Ok(true);
            }
        }
        if let Some(patterns) = self.paths.get(&host) {
            for pattern in patterns {
                match pattern {
                    Pattern::Text(pattern) if crate::policy::glob(path, pattern) => {
                        return Ok(true);
                    }
                    Pattern::Text(_) => {}
                    Pattern::Invalid => return Err(Error(ErrorKind::Type)),
                }
            }
        }
        Ok(false)
    }
}
impl Drop for Quiet {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (mut key, _) in self.paths.drain() {
            key.zeroize();
        }
    }
}
