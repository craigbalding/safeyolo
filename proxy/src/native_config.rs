//! Fresh operator configuration compiled into the existing native runtime.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::{Config, Error};

/// All relative paths belong to the directory containing config.toml. The
/// runtime's JSON struct remains an internal representation, not another file
/// the operator must maintain.
pub fn read(path: &Path) -> Result<Config, Error> {
    if path.extension().and_then(|value| value.to_str()) != Some("toml") {
        return Err("native configuration requires config.toml".into());
    }
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let mut value = crate::policy::parse_toml_document(&std::fs::read_to_string(path)?)?;
    let fields = value
        .as_object_mut()
        .ok_or("configuration must be a table")?;
    for key in [
        "addons",
        "native_product",
        "network_guard_enabled",
        "network_guard_block",
        "network_guard_homoglyph",
        "credential_guard_block",
        "credguard_block",
        "circuit_breaker_enabled",
        "test_context_block",
        "test_context_inject_declared",
        "test_context_declared_ttl",
        "inspection",
    ] {
        if fields.contains_key(key) {
            return Err(format!(
                "config.toml: {key} is a policy choice; use named controls in policy.toml"
            )
            .into());
        }
    }
    for (key, default) in [
        ("data_dir", "data"),
        ("policy_file", "policy.toml"),
        ("admin_api_token_file", "data/admin_token"),
        ("readiness_file", "data/ready.json"),
        ("audit_log_path", "logs/audit.jsonl"),
        ("event_log", "logs/events.jsonl"),
        ("flow_store_db_path", "logs/flows.sqlite3"),
        ("circuit_state_file", "data/circuits.json"),
    ] {
        fields.entry(key).or_insert_with(|| json!(default));
    }
    fields.entry("admin_port").or_insert_with(|| json!(9090));
    fields.entry("listeners").or_insert_with(|| json!([]));
    for key in [
        "data_dir",
        "policy_file",
        "admin_api_token_file",
        "readiness_file",
        "audit_log_path",
        "event_log",
        "flow_store_db_path",
        "circuit_state_file",
        "gateway_builtin_services_dir",
        "gateway_services_dir",
        "upstream_ca_file",
        "tls_ca_file",
        "agent_map_file",
    ] {
        if let Some(value) = fields.get_mut(key) {
            resolve_path(value, root, key)?;
        }
    }
    if let Some(listeners) = fields.get_mut("listeners").and_then(Value::as_array_mut) {
        for listener in listeners {
            if let Some(value) = listener.get_mut("socket_path") {
                resolve_path(value, root, "listeners.socket_path")?;
            }
        }
    }
    let mut config: Config = serde_json::from_value(value)?;
    config.native_product = true;
    config.validate()?;
    Ok(config)
}

fn resolve_path(value: &mut Value, root: &Path, field: &str) -> Result<(), Error> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{field} must be a path string"))?;
    if !text.is_empty() {
        let path = PathBuf::from(text);
        if path.is_relative() {
            *value = serde_json::to_value(root.join(path))?;
        }
    }
    Ok(())
}
