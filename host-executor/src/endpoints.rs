//! Selected endpoint observations. The pinned native helper filters host facts
//! before producing output; it never lists listeners or accepts connections.
use crate::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

pub const INSPECT_COMMAND: &str = "inspect-endpoint";

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointCandidate {
    pub transport: NetworkTransport,
    pub family: AddressFamily,
    /// None resolves an address on the explicitly selected interface.
    pub address: Option<IpAddr>,
    pub interface: Option<String>,
    pub port: u16,
    pub ipv6_only: bool,
    pub reuse_address: bool,
    pub reuse_port: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointSelection {
    /// Ordered, explicitly authorised alternatives. No fallback is invented.
    pub candidates: Vec<EndpointCandidate>,
}

impl EndpointSelection {
    pub fn validate(&self) -> bool {
        !self.candidates.is_empty()
            && self.candidates.iter().all(|c| {
                (c.address.is_some() || c.interface.is_some())
                    && c.interface
                        .as_ref()
                        .is_none_or(|name| !name.is_empty() && !name.contains('\0'))
                    && c.address.is_none_or(|address| {
                        matches!(
                            (&c.family, address),
                            (AddressFamily::Ipv4, IpAddr::V4(_))
                                | (AddressFamily::Ipv6, IpAddr::V6(_))
                        ) && !(address.is_unspecified() && c.interface.is_some())
                    })
                    && (!matches!(c.family, AddressFamily::Ipv4) || !c.ipv6_only)
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStatus {
    AvailableAtObservation,
    Conflict,
    Denied,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectedInterface {
    pub name: String,
    pub index: u32,
    pub up: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservation {
    pub status: EndpointStatus,
    pub observed_at: u64,
    pub selected: EndpointCandidate,
    pub binding: Option<SocketAddr>,
    pub interface: Option<SelectedInterface>,
    pub reason: String,
    pub os_error: Option<i32>,
    pub reservation: bool,
    pub application_ready: Option<bool>,
    pub reachable_audience: Option<String>,
}

pub fn disclosure() -> Vec<String> {
    vec![
        "Selected endpoint inspection runs the pinned native executor helper with a typed, authorised selector. Only that selector's address/interface, bind result and observation time leave the trusted helper; unrelated listeners, ports, processes, routes and interfaces are not returned.".into(),
        "The helper observes the target executor's network context and briefly binds each authorised candidate until one works. TCP also tests listen; UDP tests bind. Selected address family, IPv6-only and reuse options are applied. An interface selects the source of a concrete address; it does not enforce an ingress device restriction. Probe sockets close before the result is returned. This is an observation, never a reservation or permission to start, replace or stop a service.".into(),
        "Configured binding is separate from application readiness, publication and reachable audience. Firewall, forwarding, application authentication/TLS and VPN/tunnel protection are unobserved. The eventual service must revalidate its binding; a competing bind can win. Only explicit alternatives are tried, in their supplied order.".into(),
    ]
}

#[cfg(unix)]
pub(crate) fn validate(operation: &Operation) -> Result<bool, Refusal> {
    use std::{fs, path::Path};
    let e = &operation.execution;
    if !matches!(e.argv.first(), Some(Word::Literal {value}) if value == INSPECT_COMMAND) {
        return Ok(false);
    }
    let refuse = || {
        crate::native::unavailable(
            "endpoint inspection requires the current pinned native executor, one typed endpoint argument, an empty environment and no file, network or delegated-service workload scope",
        )
    };
    let current = std::env::current_exe().map_err(crate::native::unavailable)?;
    let source = Path::new(&e.executable)
        .canonicalize()
        .map_err(crate::native::unavailable)?;
    if source != current.canonicalize().map_err(crate::native::unavailable)? {
        return Ok(false);
    }
    let own_hash = ring::digest::digest(
        &ring::digest::SHA256,
        &fs::read(&current).map_err(crate::native::unavailable)?,
    )
    .as_ref()
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let [Word::Literal { .. }, Word::Argument { name }] = e.argv.as_slice() else {
        return Err(refuse());
    };
    require(
        own_hash == e.executable_sha256
            && operation.arguments.len() == 1
            && operation.arguments.get(name).is_some_and(|a| {
                matches!(a.kind, ArgumentType::Enum)
                    && a.required
                    && a.options.iter().all(|value| {
                        serde_json::from_value::<EndpointSelection>(value.clone())
                            .is_ok_and(|selection| selection.validate())
                    })
            })
            && e.environment.is_empty()
            && e.filesystem.read.is_empty()
            && e.filesystem.write.is_empty()
            && e.dependencies.is_empty()
            && e.network.destinations.is_empty()
            && e.network.listeners.is_empty()
            && e.network.ipc.is_empty()
            && e.delegated_services.is_empty()
            && e.working_directory == "/",
        RefusalCode::Unavailable,
        &refuse().message,
    )?;
    Ok(true)
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::command;
