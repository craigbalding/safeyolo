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

/// Name the concrete control on native API/audit envelopes. Only these known
/// fields change; raw context, request bodies and operator evidence are intact.
pub(crate) fn name_control_fields(value: &mut Value) {
    if let Some(fields) = value.as_object_mut() {
        if let Some(name) = fields.shift_remove("addon") {
            let name = name
                .as_str()
                .map(control_label)
                .map(|name| json!(name))
                .unwrap_or(name);
            fields.insert("control".into(), name);
        }
        if fields.get("reason").and_then(Value::as_str) == Some("addon_disabled") {
            fields.insert("reason".into(), json!("control_disabled"));
        }
        if let Some(audit) = fields.get_mut("audit") {
            name_control_fields(audit);
        }
        for key in ["steps", "not_loaded"] {
            if let Some(steps) = fields.get_mut(key).and_then(Value::as_array_mut) {
                for step in steps {
                    name_control_fields(step);
                }
            }
        }
    }
}

pub(crate) fn control_label(name: &str) -> &str {
    match name {
        "network-guard" | "network_guard" => "network",
        "credential-guard" | "credential_guard" => "credentials",
        "pattern-scanner" | "pattern_scanner" => "patterns",
        "test-context" => "test_context",
        "circuit-breaker" | "circuit_breaker" => "circuits",
        "flow-store" => "capture",
        "flow-recorder" => "capture",
        "request-logger" => "audit",
        "sse-streaming" => "streaming",
        "agent-api" | "agent-api-request-guard" => "agent_api",
        "admin-api" => "admin_api",
        "service-gateway" => "services",
        "policy-engine" => "policy",
        other => other,
    }
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
    pub detection_level: String,
    pub standard_auth_headers: Vec<String>,
    pub use_default_credential_rules: bool,
    pub safe_headers: SafeHeaders,
    pub entropy: Entropy,
}

impl Default for Credentials {
    fn default() -> Self {
        Self {
            enabled: true,
            action: Action::Block,
            detection_level: "standard".into(),
            standard_auth_headers: [
                "authorization",
                "x-api-key",
                "api-key",
                "x-auth-token",
                "apikey",
                "x-goog-api-key",
            ]
            .map(str::to_owned)
            .into(),
            use_default_credential_rules: true,
            safe_headers: SafeHeaders::default(),
            entropy: Entropy::default(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafeHeaders {
    pub safe_patterns: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Entropy {
    pub min_length: f64,
    pub min_charset_diversity: f64,
    pub min_shannon_entropy: f64,
}

impl Default for Entropy {
    fn default() -> Self {
        Self {
            min_length: 20.,
            min_charset_diversity: 0.5,
            min_shannon_entropy: 3.5,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Patterns {
    pub enabled: bool,
    pub request: Action,
    pub response: Action,
    pub websocket_request: Action,
    pub websocket_response: Action,
    pub builtin_sets: Vec<String>,
}
impl Default for Patterns {
    fn default() -> Self {
        Self {
            enabled: true,
            request: Action::Block,
            response: Action::Block,
            websocket_request: Action::Block,
            websocket_response: Action::Block,
            builtin_sets: Vec::new(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TestContext {
    pub action: Action,
    pub inject_declared: bool,
    pub declared_ttl: Value,
    pub target_hosts: Vec<String>,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            action: Action::Block,
            inject_declared: false,
            declared_ttl: json!(900),
            target_hosts: Vec::new(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Circuits {
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub failure_threshold: i64,
    pub success_threshold: i64,
    pub timeout_seconds: f64,
    pub half_open_max_requests: i64,
    pub use_exponential_backoff: bool,
    pub max_timeout_seconds: f64,
    pub backoff_multiplier: f64,
    pub jitter_factor: f64,
    pub streak_decay_seconds: f64,
    pub excluded_domains: Vec<String>,
}

impl Default for Circuits {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            success_threshold: 2,
            timeout_seconds: 60.,
            half_open_max_requests: 3,
            use_exponential_backoff: true,
            max_timeout_seconds: 3600.,
            backoff_multiplier: 2.,
            jitter_factor: 0.3,
            streak_decay_seconds: 3600.,
            excluded_domains: Vec::new(),
        }
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

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Logging {
    quiet_hosts: QuietHosts,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct QuietHosts {
    hosts: Vec<String>,
    paths: std::collections::BTreeMap<String, Vec<String>>,
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
        config.inspection = config
            .policy_file
            .as_ref()
            .filter(|_| self.patterns.enabled)
            .map(|path| crate::Inspection {
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
        let logging: Logging =
            serde_json::from_value(fields.shift_remove("logging").unwrap_or_else(|| json!({})))
                .map_err(|error| invalid(format!("logging: {error}")))?;
        // An absent hosts table still has host-centred defaults. Advanced
        // authored permissions continue through the same compiler.
        if !fields.contains_key("permissions") {
            fields.entry("hosts").or_insert_with(|| json!({}));
        }
        compile_exceptions(&mut fields, &mut timestamps)?;
        // These are compiler inputs for the existing consumers, never another
        // operator document. Normal native loading never reads addons.yaml.
        fields.insert("addons".into(), json!({
            "credential_guard": controls.credentials,
            "circuit_breaker": controls.circuits,
            "test_context": {"target_hosts": controls.test_context.target_hosts},
            "pattern_scanner": {"enabled": controls.patterns.enabled, "builtin_sets": controls.patterns.builtin_sets},
            "request_logger": {"quiet_hosts": logging.quiet_hosts},
        }));
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
        effective["logging"] = json!({"quiet_hosts": self.request_logger_settings().value()});
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
        fn settings_sources(
            effective: &Value,
            authored: Option<&Value>,
            prefix: &str,
            path: &Path,
            sources: &mut serde_json::Map<String, Value>,
        ) {
            if let Some(fields) = effective.as_object() {
                for (key, value) in fields {
                    settings_sources(
                        value,
                        authored.and_then(|value| value.get(key)),
                        &format!("{prefix}.{key}"),
                        path,
                        sources,
                    );
                }
            } else {
                sources.insert(
                    prefix.into(),
                    if authored.is_some() {
                        json!(path)
                    } else {
                        json!("default")
                    },
                );
            }
        }
        settings_sources(
            &effective["controls"],
            native.authored.get("controls"),
            "controls",
            path,
            &mut sources,
        );
        settings_sources(
            &effective["logging"],
            native.authored.get("logging"),
            "logging",
            path,
            &mut sources,
        );
        Some(json!({"effective":effective, "sources":sources, "permission_count":self.rules.len()}))
    }

    pub(crate) fn native_sensor_config(
        &self,
    ) -> Option<std::result::Result<Value, super::BaselineSerializationError>> {
        let native = self.native.as_ref()?;
        // Preserve the Agent API's sensor projection, including active task
        // rules. Operator service bindings and other agents' settings belong
        // only in the authenticated operator policy view.
        Some(self.sensor_config().map(|mut config| {
            if let Some(mut settings) = config.as_object_mut().unwrap().shift_remove("addons") {
                crate::credentials::wipe_json(&mut settings);
            }
            config["controls"] =
                serde_json::to_value(&native.controls).expect("validated native controls");
            config["logging"] = json!({"quiet_hosts": self.request_logger_settings().value()});
            config
        }))
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
        "patterns" => Ok("pattern_scanner"),
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
    fn nondefault_control_flags_reach_existing_runtime_consumers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.toml");
        let config_path = directory.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let source = r#"
[controls.network]
enabled=false
action="warn"
homoglyph=false
[controls.credentials]
enabled=false
action="warn"
[controls.patterns]
enabled=false
request="warn"
response="warn"
websocket_request="warn"
websocket_response="warn"
[controls.circuits]
enabled=false
failure_threshold=-1
success_threshold=-2
half_open_max_requests=-3
[controls.test_context]
action="warn"
"#;
        let policy = Policy::native_source(source, &path, None, 0.).unwrap();
        let mut config = crate::native_config::read(&config_path).unwrap();
        policy.native_controls().unwrap().configure(&mut config);
        assert!(
            !config.network_guard_enabled
                && !config.network_guard_block
                && !config.network_guard_homoglyph
        );
        assert!(
            !config.credential_guard_block
                && !config.circuit_breaker_enabled
                && !config.test_context_block
        );
        assert!(config.inspection.is_none());
        assert!(!policy.is_addon_enabled(
            super::super::Addon::CredentialGuard,
            Some("owned.invalid"),
            Some("alice")
        ));
        let sensor = policy.sensor_config().unwrap();
        assert_eq!(sensor["addons"]["circuit_breaker"]["failure_threshold"], -1);
        assert_eq!(sensor["addons"]["circuit_breaker"]["success_threshold"], -2);
        assert_eq!(
            sensor["addons"]["circuit_breaker"]["half_open_max_requests"],
            -3
        );
        let enabled = Policy::native_source(
            &source.replace("enabled=false", "enabled=true"),
            &path,
            None,
            0.,
        )
        .unwrap();
        enabled.native_controls().unwrap().configure(&mut config);
        let inspection = config.inspection.unwrap();
        assert!(
            !inspection.block_request
                && !inspection.block_response
                && !inspection.block_websocket_request
                && !inspection.block_websocket_response
        );
    }

    #[test]
    fn named_controls_feed_existing_detectors_and_report_nested_sources() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.toml");
        let source = r#"
[hosts]
"*"={egress="deny"}
"exempt.invalid"={exceptions=["patterns"]}
[controls.credentials]
detection_level="paranoid"
standard_auth_headers=["x-owned-auth"]
use_default_credential_rules=false
[controls.credentials.entropy]
min_length=8
min_charset_diversity=0.25
min_shannon_entropy=2.0
[controls.credentials.safe_headers]
safe_patterns=["^owned-.*$"]
[controls.patterns]
builtin_sets=["secrets"]
request="warn"
[controls.circuits]
failure_threshold=2
success_threshold=1
timeout_seconds=9
half_open_max_requests=1
use_exponential_backoff=false
max_timeout_seconds=10
backoff_multiplier=1.5
jitter_factor=0.0
streak_decay_seconds=13
excluded_domains=["owned.invalid"]
[controls.test_context]
target_hosts=["owned.invalid"]
inject_declared=true
declared_ttl=4
[logging.quiet_hosts]
hosts=["quiet.invalid"]
[logging.quiet_hosts.paths]
"owned.invalid"=["/events/*"]
"#;
        let policy = Policy::native_source(source, &path, None, 0.).unwrap();
        policy
            .with_credential_guard_config(|value| {
                let settings = &value["addons"]["credential_guard"];
                assert_eq!(settings["detection_level"], "paranoid");
                assert_eq!(settings["standard_auth_headers"], json!(["x-owned-auth"]));
                assert_eq!(settings["use_default_credential_rules"], false);
                assert_eq!(
                    settings["safe_headers"]["safe_patterns"],
                    json!(["^owned-.*$"])
                );
                assert_eq!(
                    settings["entropy"],
                    json!({"min_length":8.0,"min_charset_diversity":0.25,"min_shannon_entropy":2.0})
                );
            })
            .unwrap();
        let sensor = policy.sensor_config().unwrap();
        assert_eq!(
            sensor["addons"]["test_context"]["target_hosts"],
            json!(["owned.invalid"])
        );
        assert_eq!(
            sensor["addons"]["pattern_scanner"]["builtin_sets"],
            json!(["secrets"])
        );
        assert_eq!(sensor["addons"]["circuit_breaker"]["failure_threshold"], 2);
        assert!(!policy.is_addon_enabled(
            super::super::Addon::PatternScanner,
            Some("exempt.invalid"),
            Some("alice")
        ));
        assert!(policy.is_addon_enabled(
            super::super::Addon::PatternScanner,
            Some("neighbor.invalid"),
            Some("alice")
        ));
        let quiet = crate::request_logger::RequestLogger::default();
        let writer = crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        );
        let mut exchange = crate::request_logger::Exchange::new(
            crate::audit::Attribution::default(),
            Some("alice".into()),
        );
        // The existing logger consumes the compiled quiet rule, without loading a sibling file.
        quiet
            .request(
                Some(&policy),
                &mut exchange,
                &crate::request_logger::Request {
                    method: "GET",
                    parsed: Ok(crate::request_logger::PrettyUrl {
                        host: "quiet.invalid",
                        path: "/",
                    }),
                    request_id: None,
                    client: None,
                },
                || Ok(0),
                &writer,
            )
            .unwrap();
        assert!(exchange.quieted());
        assert!(writer.shutdown(std::time::Duration::from_secs(3)).unwrap());
        let view = policy.native_view(&path).unwrap();
        assert_eq!(
            view["sources"]["controls.credentials.entropy.min_length"],
            json!(path)
        );
        assert_eq!(
            view["sources"]["controls.credentials.entropy.min_shannon_entropy"],
            json!(path)
        );
        assert_eq!(view["sources"]["controls.network.action"], "default");
        assert_eq!(
            view["effective"]["controls"]["circuits"]["streak_decay_seconds"],
            13.0
        );
        assert!(view["effective"].get("addons").is_none());
    }

    #[test]
    fn native_control_labels_do_not_rewrite_raw_evidence() {
        let raw = json!({"addon":"user-annotation","reason":"addon_disabled"});
        let mut value = json!({"addon":"pattern-scanner","steps":[{"addon":"network-guard","reason":"addon_disabled"}],
            "context":raw,"details":raw,"body":raw});
        name_control_fields(&mut value);
        assert_eq!(value["control"], "patterns");
        assert_eq!(
            value["steps"][0],
            json!({"control":"network","reason":"control_disabled"})
        );
        for field in ["context", "details", "body"] {
            assert_eq!(value[field], raw);
        }
    }

    #[test]
    fn native_service_binding_constraint_and_risk_compile_for_the_owned_scope() {
        let definition = json!({"schema_version":1,"name":"demo","default_host":"service.invalid",
            "capabilities":{"reader":{"contract":{"template":"native.read.v1",
                "bindings":{"project":{"source":"operator","type":"string"}},
                "operations":[{"name":"read","request":{"method":"GET","path":"/projects/{project}",
                    "path_params":{"project":{"equals_var":"project"}}}}],
                "enforcement":{"request_shape":"enforced"}}}}});
        let registry = crate::services::Registry::from_sources(
            &[("demo.yaml".into(), definition.to_string())],
            &[],
        )
        .unwrap();
        let source = r#"
[hosts."service.invalid"]
egress="allow"
service="demo"
[agents.alice.services.demo]
capability="reader"
account="owned"
[[agents.alice.contract_bindings]]
service="demo"
capability="reader"
template="native.read.v1"
bound_values={project="alpha"}
grantable_operations=["read"]
[[risk]]
agent="alice"
account="owned"
service="demo"
tactics=["impact"]
decision="allow"
"#;
        let path = Path::new("/owned/policy.toml");
        let policy = Policy::native_source(source, path, Some(Arc::new(registry)), 0.).unwrap();
        let sensor = policy.native_sensor_config().unwrap().unwrap();
        assert_eq!(
            sensor
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "credential_rules",
                "scan_patterns",
                "policy_hash",
                "controls",
                "logging"
            ])
        );
        assert!(!sensor.to_string().contains("contract_bindings"));
        assert_eq!(
            policy.native_view(path).unwrap()["effective"]["agents"]["alice"]["services"]["demo"]["account"],
            "owned"
        );
        let request = super::super::GatewayRequest {
            service: "demo",
            capability: "reader",
            agent: "alice",
            method: "GET",
            path: "/projects/alpha",
        };
        assert_eq!(
            policy.evaluate_gateway_request(request).effect,
            super::super::Effect::Allow
        );
        for denied in [
            super::super::GatewayRequest {
                agent: "bob",
                ..request
            },
            super::super::GatewayRequest {
                path: "/projects/beta",
                ..request
            },
            super::super::GatewayRequest {
                method: "POST",
                ..request
            },
        ] {
            assert_eq!(
                policy.evaluate_gateway_request(denied).effect,
                super::super::Effect::Deny
            );
        }
        let tactics = ["impact".into()];
        let risky = super::super::RiskyRouteRequest {
            service: "demo",
            agent: "alice",
            account: "owned",
            tactics: &tactics,
            enables: &[],
            irreversible: false,
            method: "POST",
            path: "/write",
        };
        assert_eq!(
            policy.evaluate_risky_route(risky).effect,
            super::super::Effect::Allow
        );
        for other in [
            super::super::RiskyRouteRequest {
                agent: "bob",
                ..risky
            },
            super::super::RiskyRouteRequest {
                account: "neighbor",
                ..risky
            },
            super::super::RiskyRouteRequest {
                service: "neighbor",
                ..risky
            },
        ] {
            assert_eq!(
                policy.evaluate_risky_route(other).effect,
                super::super::Effect::Prompt
            );
        }
    }

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
