//! Docker's HTTP API and its operation-bound exec/attach stream switch.

use hyper::Uri;
use serde::Deserialize;

use crate::Error;

pub mod enforcement;
pub use enforcement::{DockerAccess, ExecutionBoundary};

pub const SERVICE_HEADER: &str = "x-safeyolo-docker-service";
pub const API_PREFIX: &str = "/v1.45";

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "EndpointDocument")]
pub struct DockerEndpoint {
    pub(crate) uri: Uri,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub execution_boundary: ExecutionBoundary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointDocument {
    endpoint: String,
    execution_boundary: ExecutionBoundary,
}

impl TryFrom<EndpointDocument> for DockerEndpoint {
    type Error = Error;

    fn try_from(document: EndpointDocument) -> Result<Self, Error> {
        let uri: Uri = document.endpoint.parse()?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri
                .authority()
                .is_none_or(|authority| authority.as_str().contains('@'))
            || !matches!(
                uri.path_and_query().map(|value| value.as_str()),
                None | Some("/")
            )
        {
            return Err(
                "docker.endpoint must be an HTTP(S) origin without credentials, path or query"
                    .into(),
            );
        }
        let host = uri
            .host()
            .ok_or("docker.endpoint needs a hostname")?
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        if host.is_empty() || host.ends_with('.') {
            return Err("docker.endpoint needs a canonical hostname".into());
        }
        let port = crate::config::authority_port(
            uri.authority().unwrap(),
            if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            },
        )?;
        Ok(Self {
            uri,
            host,
            port,
            execution_boundary: document.execution_boundary,
        })
    }
}

impl DockerEndpoint {
    pub(crate) fn matches(&self, host: &str, port: u16) -> bool {
        self.port == port && self.host.eq_ignore_ascii_case(host.trim_end_matches('.'))
    }
}

/// Keep version and operation selection explicit. These are the ordinary
/// standalone Engine operations used by the documented CLI/Compose workflow.
/// The capability and all applicable request constraints still run afterward.
pub(crate) fn supported_request(method: &str, target: &str) -> bool {
    let path = target.split('?').next().unwrap_or_default();
    if ["/_ping", "/version"].contains(&path) {
        return method == "GET" || (method == "HEAD" && path == "/_ping");
    }
    let Some(path) = path
        .strip_prefix(API_PREFIX)
        .and_then(|path| path.strip_prefix('/'))
    else {
        return false;
    };
    let parts: Vec<_> = path.split('/').collect();
    match (method, parts.as_slice()) {
        ("GET" | "HEAD", ["_ping"]) => true,
        ("GET", ["version" | "info" | "events"]) => true,
        ("GET", ["containers", "json"]) => true,
        ("POST", ["containers", "create"]) => true,
        ("DELETE", ["containers", id]) if !id.is_empty() => true,
        ("GET", ["containers", id, "json" | "logs" | "top" | "stats"]) if !id.is_empty() => true,
        ("GET" | "HEAD" | "PUT", ["containers", id, "archive"]) if !id.is_empty() => true,
        (
            "POST",
            [
                "containers",
                id,
                "start" | "stop" | "restart" | "kill" | "pause" | "unpause" | "wait" | "resize"
                | "update" | "exec" | "attach",
            ],
        ) if !id.is_empty() => true,
        ("POST", ["exec", id, "start" | "resize"]) if !id.is_empty() => true,
        ("GET", ["exec", id, "json"]) if !id.is_empty() => true,
        ("GET", ["images", "json"]) => true,
        ("POST", ["images", "create"] | ["build"]) => true,
        ("GET", ["images", name @ .., "json"]) if !name.is_empty() => true,
        ("DELETE", ["images", name @ ..]) if !name.is_empty() => true,
        ("GET", ["networks"] | ["volumes"]) => true,
        ("POST", ["networks" | "volumes", "create"]) => true,
        ("GET" | "DELETE", ["networks" | "volumes", id]) if !id.is_empty() => true,
        ("POST", ["networks", id, "connect" | "disconnect"]) if !id.is_empty() => true,
        _ => false,
    }
}

pub(crate) fn stream_request(method: &str, target: &str) -> bool {
    if method != "POST" {
        return false;
    }
    let path = target.split('?').next().unwrap_or_default();
    let Some(path) = path
        .strip_prefix(API_PREFIX)
        .and_then(|path| path.strip_prefix('/'))
    else {
        return false;
    };
    let parts: Vec<_> = path.split('/').collect();
    matches!(parts.as_slice(), ["exec", id, "start"] | ["containers", id, "attach"] if !id.is_empty())
}
