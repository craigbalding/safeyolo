//! Host-centred TOML authoring for the native product. Compilation, matching,
//! budgets and service policy remain owned by the existing Policy implementation.

use std::{path::Path, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Policy, Result, TimestampPaths, invalid, source::ParsedPolicy};

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Block,
    Warn,
}

impl Action {
    fn blocks(self) -> bool {
        matches!(self, Self::Block)
    }
}

fn enabled() -> bool {
    true
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub enabled: bool,
    pub action: Action,
    pub homoglyph: bool,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            enabled: true,
            action: Action::Block,
            homoglyph: true,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Credentials {
    pub enabled: bool,
    pub action: Action,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            enabled: true,
            action: Action::Block,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Patterns {
    pub request: Action,
    pub response: Action,
    pub websocket_request: Action,
    pub websocket_response: Action,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TestContext {
    pub action: Action,
    pub inject_declared: bool,
    pub declared_ttl: Value,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            action: Action::Block,
            inject_declared: false,
            declared_ttl: json!(900),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Circuits {
    #[serde(default = "enabled")]
    pub enabled: bool,
}

impl Default for Circuits {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Controls {
    pub network: Network,
    pub credentials: Credentials,
    pub patterns: Patterns,
    pub test_context: TestContext,
    pub circuits: Circuits,
}

impl Controls {
    pub(crate) fn configure(&self, config: &mut crate::Config) {
        config.network_guard_enabled = self.network.enabled;
        config.network_guard_block = self.network.action.blocks();
        config.network_guard_homoglyph = self.network.homoglyph;
        config.credential_guard_block = self.credentials.action.blocks();
        config.circuit_breaker_enabled = self.circuits.enabled;
        config.test_context_block = self.test_context.action.blocks();
        config.test_context_inject_declared = self.test_context.inject_declared;
        config.test_context_declared_ttl = self.test_context.declared_ttl.clone();
        config.inspection = config.policy_file.as_ref().map(|path| crate::Inspection {
            policy_file: path.clone(),
            block_request: self.patterns.request.blocks(),
            block_response: self.patterns.response.blocks(),
            block_websocket_request: self.patterns.websocket_request.blocks(),
            block_websocket_response: self.patterns.websocket_response.blocks(),
        });
    }
}

#[derive(Clone)]
pub(super) struct Snapshot {
    source: Zeroizing<String>,
    authored: Value,
    pub(crate) controls: Controls,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut self.authored);
    }
}

impl Policy {
    /// Preserve FILE-relative named-list references when a candidate is saved
    /// under the instance root. Inline lists and absolute paths stay unchanged.
    pub fn read_native_candidate(path: &Path) -> Result<Zeroizing<String>> {
        let source = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|error| invalid(error.to_string()))?,
        );
        let (mut document, context) = super::parse_toml_for_edit(&source)?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let parent = if parent.is_absolute() {
            parent.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|error| invalid(error.to_string()))?
                .join(parent)
        };
        if let Some(lists) = document
            .get_mut("lists")
            .and_then(toml_edit::Item::as_table_like_mut)
        {
            for (_name, entry) in lists.iter_mut() {
                if let Some(value) = entry.as_str() {
                    let value = Path::new(value);
                    if value.is_relative() {
                        let path = parent.join(value);
                        *entry = toml_edit::value(
                            path.to_str()
                                .ok_or_else(|| invalid("named list path must be Unicode"))?,
                        );
                    }
                }
            }
        }
        Ok(Zeroizing::new(super::restore_large_toml_integers(
            &document.to_string(),
            &context,
        )))
    }

    /// Read-only checking resolves named list files relative to FILE. Neither
    /// expiry pruning nor a quota evaluation is persisted by this operation.
    pub fn from_native_path(path: &Path) -> Result<Self> {
        let source = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|error| invalid(error.to_string()))?,
        );
        Self::native_source(&source, path, None, super::current_time_ms())
    }

    pub(crate) fn native_source(
        source: &str,
        path: &Path,
        registry: Option<Arc<crate::services::Registry>>,
        now_ms: f64,
    ) -> Result<Self> {
        let (mut authored, mut timestamps) = super::parse_toml_with_timestamps(source)?;
        validate_authoring(&authored)?;
        let controls: Controls = serde_json::from_value(
            authored
                .get("controls")
                .cloned()
                .unwrap_or_else(|| json!({})),
        )
        .map_err(|error| invalid(format!("controls: {error}")))?;
        if !controls
            .test_context
            .declared_ttl
            .as_number()
            .is_some_and(|number| {
                number
                    .to_string()
                    .parse::<super::BigInt>()
                    .is_ok_and(|value| value > super::BigInt::from(0))
            })
        {
            return Err(invalid(
                "controls.test_context.declared_ttl must be a positive integer",
            ));
        }
        let expired = super::expired_host_entries(&authored, now_ms)?;
        for (agent, host) in expired {
            let hosts = match agent.as_deref() {
                Some(agent) => authored
                    .get_mut("agents")
                    .and_then(|agents| agents.get_mut(agent))
                    .and_then(|agent| agent.get_mut("hosts")),
                None => authored.get_mut("hosts"),
            };
            if let Some(hosts) = hosts.and_then(Value::as_object_mut) {
                hosts.shift_remove(&host);
            }
        }
        let mut fields = authored.as_object().expect("TOML root is a table").clone();
        fields.shift_remove("controls");
        // An absent hosts table still has host-centred defaults. Advanced
        // authored permissions continue through the same compiler.
        if !fields.contains_key("permissions") {
            fields.entry("hosts").or_insert_with(|| json!({}));
        }
        compile_exceptions(&mut fields, &mut timestamps)?;
        fields.insert(
            "addons".into(),
            json!({"credential_guard":{"enabled":controls.credentials.enabled}}),
        );
        let fields = super::normalize_toml(fields, &mut timestamps)?;
        let mut policy = Self::from_document(
            ParsedPolicy {
                document: fields,
                timestamps,
            },
            path.parent(),
            registry,
            false,
        )?;
        policy.native = Some(Snapshot {
            source: Zeroizing::new(source.to_owned()),
            authored,
            controls,
        });
        policy.baseline_path = Some(path.to_owned());
        Ok(policy)
    }

    pub(crate) fn reload_native_source(&self, source: &str, path: &Path) -> Result<Self> {
        let mut replacement = Self::native_source(
            source,
            path,
            self.gateway().and_then(|gateway| gateway.registry()),
            super::current_time_ms(),
        )?;
        replacement.budgets = self.budgets.clone();
        replacement.evaluations = self.evaluations.clone();
        replacement.task = self.task.clone();
        Ok(replacement)
    }

    pub(crate) fn native_controls(&self) -> Option<&Controls> {
        self.native.as_ref().map(|native| &native.controls)
    }

    pub(crate) fn retain_runtime_state(&mut self, previous: &Self) {
        self.budgets = previous.budgets.clone();
        self.evaluations = previous.evaluations.clone();
        self.task = previous.task.clone();
    }

    pub(crate) fn set_native_source(&mut self, source: String) {
        if let Some(native) = self.native.as_mut() {
            native.source = Zeroizing::new(source);
        }
    }

    pub(crate) fn native_source_text(&self) -> Option<&str> {
        self.native.as_ref().map(|native| native.source.as_str())
    }

    pub(crate) fn native_view(&self, path: &Path) -> Option<Value> {
        let native = self.native.as_ref()?;
        let mut effective = native.authored.clone();
        effective["controls"] =
            serde_json::to_value(&native.controls).expect("validated native controls");
        let mut sources = serde_json::Map::new();
        sources.insert("policy".into(), json!(path));
        if native.authored.get("lists").is_some() {
            let mut lists = serde_json::Map::new();
            for (name, list) in &self.list_files {
                lists.insert(name.clone(), json!(list.hosts));
                sources.insert(format!("lists.{name}"), json!(list.path));
            }
            effective["lists"] = Value::Object(lists);
        }
        let controls = effective["controls"]
            .as_object()
            .expect("controls are a table");
        for (control, values) in controls {
            for key in values.as_object().expect("control is a table").keys() {
                let source = if native
                    .authored
                    .pointer(&format!("/controls/{control}/{key}"))
                    .is_some()
                {
                    path.display().to_string()
                } else {
                    "default".into()
                };
                sources.insert(format!("controls.{control}.{key}"), json!(source));
            }
        }
        Some(json!({"effective":effective, "sources":sources, "permission_count":self.rules.len()}))
    }

    pub(crate) fn native_list_file_status(&self) -> serde_json::Map<String, Value> {
        self.list_files
            .iter()
            .map(|(name, list)| {
                let mut status = json!({"source":list.path});
                match std::fs::read_to_string(&list.path) {
                    Ok(saved) => {
                        let saved = Zeroizing::new(saved);
                        let matches = saved.as_str() == list.source.as_str();
                        status["saved_matches_active"] = json!(matches);
                        status["status"] = json!(if matches { "active" } else { "saved_differs" });
                    }
                    Err(error) => {
                        status["saved_matches_active"] = json!(false);
                        status["status"] = json!("saved_unreadable");
                        status["saved_error"] = json!(error.to_string());
                    }
                }
                (name.clone(), status)
            })
            .collect()
    }
}

fn validate_authoring(document: &Value) -> Result<()> {
    let fields = document
        .as_object()
        .ok_or_else(|| invalid("policy must be a table"))?;
    for key in [
        "addons",
        "required",
        "domains",
        "clients",
        "simple_permissions",
        "metadata",
        "global_budget",
        "credentials",
        "credential_rules",
        "test_context_rules",
    ] {
        if fields.contains_key(key) {
            return Err(invalid(format!("policy.toml: unsupported field '{key}'")));
        }
    }
    validate_hosts(fields.get("hosts"), "hosts")?;
    if let Some(agents) = fields.get("agents") {
        for (name, agent) in super::object(agents, "agents")? {
            let agent = super::object(agent, &format!("agents.{name}"))?;
            reject_replaced_fields(agent, &format!("agents.{name}"))?;
            if let Some(egress) = agent.get("egress") {
                super::egress_effect(egress)?;
            }
            validate_hosts(agent.get("hosts"), &format!("agents.{name}.hosts"))?;
        }
    }
    Ok(())
}

fn validate_hosts(hosts: Option<&Value>, path: &str) -> Result<()> {
    if let Some(hosts) = hosts {
        for (name, host) in super::object(hosts, path)? {
            let fields = super::object(host, &format!("{path}.{name}"))?;
            reject_replaced_fields(fields, &format!("{path}.{name}"))?;
            if let Some(egress) = fields.get("egress") {
                super::egress_effect(egress)?;
            }
        }
    }
    Ok(())
}

fn reject_replaced_fields(fields: &serde_json::Map<String, Value>, path: &str) -> Result<()> {
    for key in [
        "addons",
        "bypass",
        "credentials",
        "rate_limit",
        "unknown_credentials",
    ] {
        if fields.contains_key(key) {
            return Err(invalid(format!("{path}: unsupported field '{key}'")));
        }
    }
    Ok(())
}

fn control_name(name: &str) -> Result<&'static str> {
    match name {
        "network" => Ok("network_guard"),
        "credentials" => Ok("credential_guard"),
        "circuits" => Ok("circuit_breaker"),
        "streaming" => Ok("sse_streaming"),
        _ => Err(invalid(format!("unknown policy control '{name}'"))),
    }
}

fn compile_exceptions(
    fields: &mut serde_json::Map<String, Value>,
    timestamps: &mut TimestampPaths,
) -> Result<()> {
    fn compile(fields: &mut serde_json::Map<String, Value>) -> Result<()> {
        if let Some(exceptions) = fields.shift_remove("exceptions") {
            let names = super::string_array(&exceptions, "exceptions")?;
            let names = names
                .iter()
                .map(|name| control_name(name).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            fields.insert("bypass".into(), json!(names));
        }
        Ok(())
    }
    if let Some(hosts) = fields.get_mut("hosts").and_then(Value::as_object_mut) {
        for (host, entry) in hosts {
            if let Some(entry) = entry.as_object_mut() {
                compile(entry)?;
            }
            // Exception values are strings; their original timestamp provenance
            // cannot be used as a forgeable control name.
            if timestamps.has_under(&["hosts", host, "exceptions"]) {
                return Err(invalid("exceptions must contain control names"));
            }
        }
    }
    if let Some(agents) = fields.get_mut("agents").and_then(Value::as_object_mut) {
        for (_agent, entry) in agents {
            if let Some(entry) = entry.as_object_mut() {
                compile(entry)?;
                if let Some(hosts) = entry.get_mut("hosts").and_then(Value::as_object_mut) {
                    for entry in hosts.values_mut() {
                        if let Some(entry) = entry.as_object_mut() {
                            compile(entry)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_authoring_reuses_precedence_and_ignores_sibling_addon_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.toml");
        std::fs::create_dir(directory.path().join("addons.yaml")).unwrap();
        std::fs::write(
            &path,
            "budget=12\n[hosts]\n'*'={egress='deny'}\n'owned.invalid'={egress='allow'}\n[controls.test_context]\ndeclared_ttl=7\n",
        )
        .unwrap();
        let mut policy = Policy::from_native_path(&path).unwrap();
        policy.observe_baseline_files(None).unwrap();
        assert!(!policy.baseline_files_changed().unwrap());
        let request = super::super::NetworkRequest {
            host: "owned.invalid",
            port: Some(80),
            method: "GET",
            path: "/",
            agent: Some("alice"),
        };
        assert_eq!(
            policy
                .evaluate(request, super::super::current_time_ms(), true)
                .unwrap()
                .effect,
            super::super::Effect::Allow
        );
        let denied = super::super::NetworkRequest {
            host: "unlisted.invalid",
            ..request
        };
        assert_eq!(
            policy
                .evaluate(denied, super::super::current_time_ms(), true)
                .unwrap()
                .effect,
            super::super::Effect::Deny
        );
        assert_eq!(
            policy.native_view(&path).unwrap()["effective"]["hosts"]["*"]["egress"],
            "deny"
        );
        assert_eq!(
            policy.native_view(&path).unwrap()["effective"]["controls"]["network"]["action"],
            "block"
        );
        let config_path = directory.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let mut config = crate::native_config::read(&config_path).unwrap();
        policy.native_controls().unwrap().configure(&mut config);
        assert_eq!(config.test_context_declared_ttl, json!(7));
    }

    #[test]
    fn native_validation_names_replaced_and_invalid_controls() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.toml");
        for (source, expected) in [
            ("[addons.network_guard]\nenabled=false", "addons"),
            ("required=['network_guard']", "required"),
            ("[controls.network_guard]\nenabled=false", "network_guard"),
            ("[controls.network]\naction='allow'", "controls"),
            ("[controls.network]\nenabled='true'", "controls"),
            ("[controls.test_context]\ndeclared_ttl=2.5", "declared_ttl"),
            ("[controls.test_context]\ndeclared_ttl=0", "declared_ttl"),
            ("[agents.alice]\negress='invalid'", "egress"),
            ("[hosts]\n'owned.invalid'={rate=0}", "rate"),
        ] {
            std::fs::write(&path, source).unwrap();
            assert!(
                Policy::from_native_path(&path)
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
        }
    }
}
