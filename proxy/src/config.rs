use std::{collections::HashSet, path::PathBuf};

use hyper::Uri;
use serde::{Deserialize, Serialize};

use crate::{Error, is_reserved};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentListener {
    pub agent_id: String,
    pub socket_path: PathBuf,
    /// Trusted source slot for declarations on listeners with arbitrary paths.
    /// Conventional per-agent paths supply their IPv4 source when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

impl AgentListener {
    pub(crate) fn source_id(&self) -> Option<String> {
        if let Some(source) = &self.source_id {
            return Some(source.clone());
        }
        if self.socket_path.file_name()?.to_str()? != "proxy.sock" {
            return None;
        }
        let parent = self.socket_path.parent()?.file_name()?.to_str()?;
        let (ip, agent) = parent.split_once('_')?;
        ip.parse::<std::net::Ipv4Addr>().ok()?;
        // Match sockets.parse's existing agent-name expression, including its
        // Python end-anchor acceptance of one final newline. This recognizes a
        // source convention; it does not constrain other configured paths.
        let agent = agent.strip_suffix('\n').unwrap_or(agent);
        let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if agent.is_empty()
            || agent.len() > 63
            || !alphanumeric(agent.as_bytes()[0])
            || !alphanumeric(*agent.as_bytes().last()?)
            || !agent.bytes().all(|byte| alphanumeric(byte) || byte == b'-')
        {
            return None;
        }
        Some(ip.to_owned())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub policy_file: PathBuf,
    #[serde(default)]
    pub block_websocket_request: bool,
    #[serde(default)]
    pub block_websocket_response: bool,
}

/// Development configuration. Production CLI selection comes later.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listeners: Vec<AgentListener>,
    pub temporary_policy_socket: Option<PathBuf>,
    pub policy_file: Option<PathBuf>,
    #[serde(default = "enabled")]
    pub network_guard_enabled: bool,
    #[serde(default = "enabled")]
    pub network_guard_block: bool,
    #[serde(default = "enabled")]
    pub network_guard_homoglyph: bool,
    #[serde(default = "enabled")]
    pub circuit_breaker_enabled: bool,
    /// An absent or empty path disables circuit snapshots.
    pub circuit_state_file: Option<PathBuf>,
    #[serde(default = "enabled")]
    pub agent_api_enabled: bool,
    #[serde(default = "enabled")]
    pub test_context_block: bool,
    #[serde(default)]
    pub test_context_inject_declared: bool,
    #[serde(default = "declared_ttl")]
    pub test_context_declared_ttl: serde_json::Value,
    #[serde(default = "enabled")]
    pub sse_streaming_enabled: bool,
    #[serde(default)]
    pub sse_stream_json: bool,
    #[serde(default = "enabled")]
    pub flow_store_enabled: bool,
    #[serde(default = "flow_store_path")]
    pub flow_store_db_path: PathBuf,
    /// Development opt-in for the existing separate IPv4-loopback operator API.
    /// Listener and token settings are read at process startup.
    pub admin_port: Option<u16>,
    pub admin_api_token_file: Option<PathBuf>,
    #[serde(default)]
    pub admin_shield_extra_ports: String,
    pub readiness_file: PathBuf,
    pub event_log: PathBuf,
    pub parent_proxy: Option<String>,
    pub upstream_ca_file: Option<PathBuf>,
    pub tls_ca_file: Option<PathBuf>,
    /// Canonical exact entries emitted by the existing CLI's normalize_ignore_hosts.
    #[serde(default)]
    pub ignore_hosts: Vec<String>,
    pub via_token: Option<String>,
    pub inspection: Option<Inspection>,
}

fn enabled() -> bool {
    true
}

fn declared_ttl() -> serde_json::Value {
    serde_json::json!(900)
}

fn flow_store_path() -> PathBuf {
    "/app/logs/flows.sqlite3".into()
}

#[derive(Clone)]
pub(crate) struct ParentProxy {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

pub(crate) fn authority_port(
    authority: &hyper::http::uri::Authority,
    default: u16,
) -> Result<u16, Error> {
    let value = authority.as_str();
    let port = if value.starts_with('[') {
        value
            .split_once(']')
            .and_then(|(_, suffix)| suffix.strip_prefix(':'))
    } else {
        value.rsplit_once(':').map(|(_, port)| port)
    };
    match port {
        Some(port) => Ok(port.parse::<u16>()?),
        None => Ok(default),
    }
}

impl Config {
    pub fn read(path: &std::path::Path) -> Result<Self, Error> {
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.temporary_policy_socket.is_some() == self.policy_file.is_some() {
            return Err("configure exactly one policy_file or temporary_policy_socket".into());
        }
        let mut paths = HashSet::new();
        for listener in &self.listeners {
            if listener.agent_id.is_empty() || !paths.insert(&listener.socket_path) {
                return Err("listeners need an agent identity and a unique socket path".into());
            }
        }
        for path in [&self.readiness_file, &self.event_log]
            .into_iter()
            .chain(self.temporary_policy_socket.iter())
            .chain(self.policy_file.iter())
        {
            if !paths.insert(path) {
                return Err("listener, policy, readiness and event paths must be distinct".into());
            }
        }
        if let Some(token) = &self.via_token
            && (token.is_empty()
                || token.len() > 128
                || !token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b)))
        {
            return Err("via_token must be one RFC token of at most 128 characters".into());
        }
        self.parent()?;
        Ok(())
    }

    pub(crate) fn parent(&self) -> Result<Option<ParentProxy>, Error> {
        let Some(value) = self.parent_proxy.as_deref().filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let uri: Uri = value.parse()?;
        let scheme = uri
            .scheme_str()
            .ok_or("parent proxy needs HTTP(S) scheme")?;
        if !matches!(scheme, "http" | "https")
            || uri.authority().is_none()
            || uri.authority().unwrap().as_str().contains('@')
            || !matches!(uri.path(), "" | "/")
            || uri.query().is_some()
            || value.contains('#')
        {
            return Err(
                "parent proxy must be an unauthenticated HTTP(S) URL without a path".into(),
            );
        }
        let authority = uri.authority().unwrap();
        let host = authority
            .host()
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        if host.is_empty() || is_reserved(&host) {
            return Err("reserved local destinations cannot be parent proxies".into());
        }
        let port = authority_port(authority, if scheme == "https" { 443 } else { 80 })?;
        Ok(Some(ParentProxy {
            host,
            port,
            tls: scheme == "https",
        }))
    }
}
