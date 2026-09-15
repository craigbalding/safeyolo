use std::{collections::HashSet, path::PathBuf};

use hyper::Uri;
use serde::{Deserialize, Serialize};

use crate::{Error, is_reserved};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentListener {
    pub agent_id: String,
    pub socket_path: PathBuf,
}

/// Development-only M2 configuration. Production CLI selection comes later.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listeners: Vec<AgentListener>,
    pub temporary_policy_socket: PathBuf,
    pub readiness_file: PathBuf,
    pub event_log: PathBuf,
    pub parent_proxy: Option<String>,
    pub upstream_ca_file: Option<PathBuf>,
    pub via_token: Option<String>,
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
        let mut paths = HashSet::new();
        for listener in &self.listeners {
            if listener.agent_id.is_empty() || !paths.insert(&listener.socket_path) {
                return Err("listeners need an agent identity and a unique socket path".into());
            }
        }
        for path in [
            &self.temporary_policy_socket,
            &self.readiness_file,
            &self.event_log,
        ] {
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
