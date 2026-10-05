//! Fresh operator configuration compiled into the existing native runtime.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Config, Error};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub capture: Capture,
    pub trace: Trace,
    pub audit: Audit,
    pub agent_launcher: AgentLauncher,
    pub desktop: Desktop,
    pub command_centre: CommandCentre,
    pub web: Web,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capture {
    pub max_request_body_bytes: i64,
    pub max_response_body_bytes: i64,
    pub preview_text_chars: i64,
    pub compress_bodies: bool,
    pub queue_max: i64,
}
impl Default for Capture {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 1_048_576,
            max_response_body_bytes: 4_194_304,
            preview_text_chars: 8192,
            compress_bodies: true,
            queue_max: 500,
        }
    }
}
impl Capture {
    pub(crate) fn store_settings(&self) -> crate::flow_store::Settings {
        crate::flow_store::Settings {
            max_request_body_bytes: self.max_request_body_bytes.into(),
            max_response_body_bytes: self.max_response_body_bytes.into(),
            preview_text_chars: self.preview_text_chars.into(),
            compress_bodies: crate::circuits::CircuitValue::Bool(self.compress_bodies),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Trace {
    pub ttl_s: i64,
    pub global_max: i64,
    pub per_agent_max: i64,
    pub steps_max: i64,
    pub details_max_bytes: i64,
}
impl Default for Trace {
    fn default() -> Self {
        Self {
            ttl_s: 300,
            global_max: 1000,
            per_agent_max: 200,
            steps_max: 128,
            details_max_bytes: 4096,
        }
    }
}
impl Trace {
    pub(crate) fn store_settings(&self) -> crate::trace::Settings {
        crate::trace::Settings {
            ttl_s: self.ttl_s.into(),
            global_max: self.global_max.into(),
            per_agent_max: self.per_agent_max.into(),
            steps_max: self.steps_max.into(),
            details_max_bytes: self.details_max_bytes.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Audit {
    pub queue_max: i64,
    pub max_bytes: i64,
    pub backups: i64,
}
impl Default for Audit {
    fn default() -> Self {
        Self {
            queue_max: 10000,
            max_bytes: 50_000_000,
            backups: 5,
        }
    }
}
impl Audit {
    pub(crate) fn writer_settings(&self) -> crate::audit::Settings {
        crate::audit::Settings {
            max_queue: self.queue_max.into(),
            max_bytes: self.max_bytes.into(),
            backups: self.backups.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentLauncher {
    pub default: Option<String>,
    pub tmux_session: String,
}
impl Default for AgentLauncher {
    fn default() -> Self {
        Self {
            default: None,
            tmux_session: "safeyolo".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Desktop {
    pub size: String,
    pub present_host_port: u16,
}
impl Default for Desktop {
    fn default() -> Self {
        Self {
            size: "auto".into(),
            present_host_port: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CommandCentre {
    pub enabled: bool,
    pub events_port: u16,
    pub share: String,
    pub tailnet_admin_port: u16,
    pub tailnet_events_port: u16,
}
impl Default for CommandCentre {
    fn default() -> Self {
        Self {
            enabled: false,
            events_port: 9091,
            share: "local".into(),
            tailnet_admin_port: 9443,
            tailnet_events_port: 9444,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Web {
    pub host: String,
    pub port: u16,
    pub tailnet_enabled: bool,
    pub tailnet_port: u16,
}
impl Default for Web {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8081,
            tailnet_enabled: false,
            tailnet_port: 443,
        }
    }
}

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
        "modes",
        "proxy",
        "backend",
        "rust_config",
        "required",
    ] {
        if fields.contains_key(key) {
            return Err(format!(
                "config.toml: unsupported field '{key}'; use named controls in policy.toml and native runtime keys"
            )
            .into());
        }
    }
    let mut settings = serde_json::Map::new();
    for key in [
        "capture",
        "trace",
        "audit",
        "agent_launcher",
        "desktop",
        "command_centre",
        "web",
    ] {
        if let Some(value) = fields.shift_remove(key) {
            settings.insert(key.into(), value);
        }
    }
    let settings: Settings = serde_json::from_value(Value::Object(settings))
        .map_err(|error| format!("config.toml settings: {error}"))?;
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
    config.native_settings = Some(settings);
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

/// Native host readers share the same file and type checks as proxy startup.
/// Missing configuration uses built-in launcher defaults; malformed input is
/// an error. No config.yaml or generated document is a fallback source.
pub(crate) fn host_settings() -> Result<Settings, Error> {
    let path = std::env::var_os("SAFEYOLO_NATIVE_CONFIG_PATH")
        .map(PathBuf::from)
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .unwrap_or_else(|| crate::host_platform::config_dir().join("config.toml"));
    match std::fs::metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(error) => Err(error.into()),
        Ok(_) => read(&path)?
            .native_settings
            .ok_or_else(|| "native settings are missing".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_loader_keeps_nondefault_settings_and_resolves_runtime_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
data_dir="state"
policy_file="permissions.toml"
admin_port=19090
admin_api_token_file="state/operator-token"
readiness_file="state/ready-marker.json"
audit_log_path="records/security.jsonl"
event_log="records/diagnostics.jsonl"
circuit_state_file="state/circuit-state.json"
reload_id="owned-reload"
agent_map_file="state/agents.json"
parent_proxy="http://127.0.0.1:18080"
upstream_ca_file="certs/upstream.pem"
tls_ca_file="certs/signing.pem"
gateway_builtin_services_dir="builtin"
gateway_services_dir="services"
agent_api_enabled=false
sse_streaming_enabled=false
sse_stream_json=true
flow_store_enabled=false
flow_store_db_path="records/flows.sqlite3"
flow_pruner_max=7
flow_pruner_max_body_bytes=11
admin_shield_extra_ports="19091"
ignore_hosts=["example.invalid:443"]
via_token="owned"
[[listeners]]
agent_id="alice"
socket_path="state/alice.sock"
source_id="10.0.0.2"
[plumb]
max_participants=3
max_message_bytes=0
message_page_limit=9
default_ttl_seconds=17
[capture]
max_request_body_bytes=2
max_response_body_bytes=3
preview_text_chars=4
compress_bodies=false
queue_max=6
[trace]
ttl_s=10
global_max=11
per_agent_max=12
steps_max=13
details_max_bytes=14
[audit]
queue_max=15
max_bytes=16
backups=2
[agent_launcher]
default="tmux-window"
tmux_session="owned"
[desktop]
size="640x480"
present_host_port=19590
[command_centre]
enabled=true
events_port=19091
share="tailnet"
tailnet_admin_port=19443
tailnet_events_port=19444
[web]
host="localhost"
port=18081
tailnet_enabled=true
tailnet_port=8443
"#,
        )
        .unwrap();
        // Normal native loading does not inspect these old files.
        std::fs::create_dir(directory.path().join("addons.yaml")).unwrap();
        std::fs::write(directory.path().join("config.yaml"), "not: [").unwrap();
        let config = read(&path).unwrap();
        assert_eq!(config.data_dir, Some(directory.path().join("state")));
        assert_eq!(
            config.policy_file,
            Some(directory.path().join("permissions.toml"))
        );
        assert_eq!(
            config.listeners[0].socket_path,
            directory.path().join("state/alice.sock")
        );
        assert_eq!(config.listeners[0].source_id.as_deref(), Some("10.0.0.2"));
        assert_eq!(config.admin_port, Some(19090));
        assert_eq!(
            config.agent_map_file,
            directory.path().join("state/agents.json").to_str().unwrap()
        );
        assert_eq!(
            config.parent_proxy.as_deref(),
            Some("http://127.0.0.1:18080")
        );
        for (actual, expected) in [
            (&config.admin_api_token_file, "state/operator-token"),
            (&config.audit_log_path, "records/security.jsonl"),
            (&config.circuit_state_file, "state/circuit-state.json"),
            (&config.upstream_ca_file, "certs/upstream.pem"),
            (&config.tls_ca_file, "certs/signing.pem"),
            (&config.gateway_builtin_services_dir, "builtin"),
            (&config.gateway_services_dir, "services"),
        ] {
            assert_eq!(actual.as_ref().unwrap(), &directory.path().join(expected));
        }
        assert_eq!(
            config.readiness_file,
            directory.path().join("state/ready-marker.json")
        );
        assert_eq!(
            config.event_log,
            directory.path().join("records/diagnostics.jsonl")
        );
        assert_eq!(config.reload_id.as_deref(), Some("owned-reload"));
        assert!(
            !config.agent_api_enabled && !config.sse_streaming_enabled && config.sse_stream_json
        );
        assert!(!config.flow_store_enabled);
        assert_eq!(
            config.flow_store_db_path,
            directory.path().join("records/flows.sqlite3")
        );
        assert_eq!(
            (config.flow_pruner_max, config.flow_pruner_max_body_bytes),
            (7, 11)
        );
        assert_eq!(config.admin_shield_extra_ports, "19091");
        assert_eq!(config.ignore_hosts, ["example.invalid:443"]);
        assert_eq!(config.via_token.as_deref(), Some("owned"));
        assert_eq!(config.plumb.max_participants, 3);
        assert_eq!(config.plumb.max_message_bytes, 0);
        assert_eq!(config.plumb.message_page_limit, 9);
        assert_eq!(config.plumb.default_ttl_seconds, 17);
        let settings = config.native_settings.unwrap();
        let capture = settings.capture.store_settings();
        assert_eq!(capture.max_request_body_bytes, 2);
        assert_eq!(capture.max_response_body_bytes, 3);
        assert_eq!(capture.preview_text_chars, 4);
        assert_eq!(
            capture.compress_bodies,
            crate::circuits::CircuitValue::Bool(false)
        );
        assert_eq!(settings.capture.queue_max, 6);
        let trace = settings.trace.store_settings();
        assert_eq!(trace.ttl_s, 10);
        assert_eq!(trace.global_max, 11.into());
        assert_eq!(trace.per_agent_max, 12.into());
        assert_eq!(trace.steps_max, 13.into());
        assert_eq!(trace.details_max_bytes, 14.into());
        let audit = settings.audit.writer_settings();
        assert_eq!(audit.max_queue, 15.into());
        assert_eq!(audit.max_bytes, 16.into());
        assert_eq!(audit.backups, 2.into());
        assert_eq!(
            settings.agent_launcher.default.as_deref(),
            Some("tmux-window")
        );
        assert_eq!(settings.agent_launcher.tmux_session, "owned");
        assert_eq!(
            (
                settings.desktop.size.as_str(),
                settings.desktop.present_host_port
            ),
            ("640x480", 19590)
        );
        assert!(settings.command_centre.enabled && settings.web.tailnet_enabled);
        assert_eq!(settings.command_centre.events_port, 19091);
        assert_eq!(settings.command_centre.share, "tailnet");
        assert_eq!(
            (
                settings.command_centre.tailnet_admin_port,
                settings.command_centre.tailnet_events_port
            ),
            (19443, 19444)
        );
        assert_eq!(
            (
                settings.web.host.as_str(),
                settings.web.port,
                settings.web.tailnet_port
            ),
            ("localhost", 18081, 8443)
        );
        // Retain the existing capture owner's negative slice semantics and
        // the recorder's nonpositive unbounded queue setting.
        std::fs::write(
            &path,
            "[capture]\nmax_response_body_bytes=-1\npreview_text_chars=-2\nqueue_max=-1\n",
        )
        .unwrap();
        let capture = read(&path).unwrap().native_settings.unwrap().capture;
        assert_eq!(
            capture.store_settings().max_response_body_bytes,
            (-1).into()
        );
        assert_eq!(capture.store_settings().preview_text_chars, (-2).into());
        assert_eq!(capture.queue_max, -1);
    }

    #[test]
    fn native_configuration_rejects_old_owners_and_wrong_setting_types() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        for (source, field) in [
            ("[addons]\n", "addons"),
            ("[modes]\n", "modes"),
            ("[proxy]\n", "proxy"),
            ("network_guard_block=false", "network_guard_block"),
            ("[capture]\ncompress_bodies='false'", "boolean"),
            ("[capture]\nqueue_max=1.5", "number"),
            ("[trace]\nsteps_max=1.2", "number"),
            ("[command_centre]\nevents_port=70000", "number"),
            ("[desktop]\nsize=42", "string"),
            ("[audit]\nunknown=1", "unknown"),
            ("data_dir=42", "data_dir"),
            ("[listeners]\nagent_id='alice'", "sequence"),
        ] {
            std::fs::write(&path, source).unwrap();
            let error = read(&path).unwrap_err().to_string();
            assert!(error.contains(field), "{source}: {error}");
        }
    }
}
