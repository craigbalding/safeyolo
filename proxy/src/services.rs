//! Pure service-definition snapshots and gateway route selection. A selection is
//! not authorization to dial: risky-route policy and credential lifecycle still follow.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

use crate::{
    Error,
    contracts::{
        ContractBinding, ContractDenial, ContractRequest, ContractTemplate, enforce_request,
    },
};

fn authorization() -> String {
    "Authorization".into()
}
fn bearer() -> String {
    "Bearer".into()
}
#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default = "authorization")]
    pub header: String,
    #[serde(default = "bearer")]
    pub scheme: String,
    #[serde(default)]
    pub refresh_on_401: bool,
    #[serde(default)]
    pub allow_http: bool,
}

#[derive(Clone, Debug)]
pub struct CapabilityRoute {
    pub methods: Vec<String>,
    pub path: String,
}
#[derive(Clone, Debug, Default)]
pub struct Capability {
    pub name: String,
    pub routes: Vec<CapabilityRoute>,
    pub contract: Option<ContractTemplate>,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RiskyRoute {
    pub path: String,
    pub methods: Vec<String>,
    pub description: String,
    pub tactics: Vec<String>,
    pub enables: Vec<String>,
    pub irreversible: bool,
    pub group: Option<String>,
}
#[derive(Clone, Debug)]
pub struct ServiceDefinition {
    pub name: String,
    pub default_host: String,
    pub auth: Option<AuthConfig>,
    pub capabilities: BTreeMap<String, Capability>,
    pub risky_routes: Vec<RiskyRoute>,
    /// Original definition includes descriptive and declared response/state fields.
    pub raw: Value,
}
impl ServiceDefinition {
    pub fn from_yaml(source: &str) -> Result<Self, Error> {
        let raw: Value = serde_yaml_ng::from_str(source)?;
        Self::from_value(raw)
    }
    pub fn from_value(raw: Value) -> Result<Self, Error> {
        let object = raw
            .as_object()
            .ok_or("service definition must be a mapping")?;
        if object.get("schema_version") != Some(&Value::from(1)) {
            return Err("Unsupported service schema_version (expected 1)".into());
        }
        let name = required_string(object, "name")?;
        let default_host = string(object, "default_host", "")?;
        let auth = object
            .get("auth")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?;
        let mut capabilities = BTreeMap::new();
        if let Some(raw_caps) = object.get("capabilities") {
            for (name, raw_cap) in raw_caps
                .as_object()
                .ok_or("capabilities must be a mapping")?
            {
                let cap = raw_cap.as_object().ok_or("capability must be a mapping")?;
                let mut routes = Vec::new();
                for route in array(cap.get("routes"))? {
                    let route = route.as_object().ok_or("route must be a mapping")?;
                    routes.push(CapabilityRoute {
                        methods: methods(route.get("methods").ok_or("route methods required")?)?,
                        path: required_string(route, "path")?,
                    });
                }
                let contract: Option<ContractTemplate> = cap
                    .get("contract")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?;
                if let Some(contract) = &contract {
                    contract.validate()?;
                }
                capabilities.insert(
                    name.clone(),
                    Capability {
                        name: name.clone(),
                        routes,
                        contract,
                    },
                );
            }
        }
        let mut risky_routes = Vec::new();
        for entry in array(object.get("risky_routes"))? {
            let entry = entry.as_object().ok_or("risky route must be a mapping")?;
            if entry.contains_key("group") {
                for route in array(entry.get("routes"))? {
                    risky_routes.push(risky_route(
                        route.as_object().ok_or("risky route must be a mapping")?,
                        Some(entry),
                    )?);
                }
            } else {
                risky_routes.push(risky_route(entry, None)?);
            }
        }
        Ok(Self {
            name,
            default_host,
            auth,
            capabilities,
            risky_routes,
            raw,
        })
    }
}
fn array(value: Option<&Value>) -> Result<&[Value], Error> {
    match value {
        None => Ok(&[]),
        Some(Value::Array(value)) => Ok(value),
        _ => Err("expected a list".into()),
    }
}
fn required_string(map: &Map<String, Value>, key: &str) -> Result<String, Error> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} must be a string").into())
}
fn string(map: &Map<String, Value>, key: &str, default: &str) -> Result<String, Error> {
    if map.contains_key(key) {
        required_string(map, key)
    } else {
        Ok(default.into())
    }
}
fn methods(value: &Value) -> Result<Vec<String>, Error> {
    match value {
        Value::String(value) => Ok(vec![value.to_uppercase()]),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_uppercase)
                    .ok_or_else(|| "method must be a string".into())
            })
            .collect(),
        _ => Err("methods must be a string or list".into()),
    }
}
fn risky_route(
    route: &Map<String, Value>,
    group: Option<&Map<String, Value>>,
) -> Result<RiskyRoute, Error> {
    let empty = Map::new();
    let group = group.unwrap_or(&empty);
    let merged = |key| -> Result<Vec<String>, Error> {
        let mut values = Vec::new();
        for value in array(group.get(key))?.iter().chain(array(route.get(key))?) {
            let value = value
                .as_str()
                .ok_or("risk signal must be a string")?
                .to_owned();
            if !values.contains(&value) {
                values.push(value);
            }
        }
        Ok(values)
    };
    Ok(RiskyRoute {
        path: required_string(route, "path")?,
        methods: methods(route.get("methods").unwrap_or(&Value::String("*".into())))?,
        description: string(route, "description", &string(group, "description", "")?)?,
        tactics: merged("tactics")?,
        enables: merged("enables")?,
        irreversible: route
            .get("irreversible")
            .or_else(|| group.get("irreversible"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        group: group
            .get("group")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// A complete immutable candidate. Callers replace their live snapshot only after
/// construction succeeds; builtin documents load before user overrides.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub services: BTreeMap<String, ServiceDefinition>,
    pub source_by_service: BTreeMap<String, String>,
}
impl Registry {
    /// Inputs identify source filenames and YAML contents. Duplicate service names
    /// within one source reject the candidate. A user definition overrides a builtin.
    pub fn from_sources(
        builtin: &[(String, String)],
        user: &[(String, String)],
    ) -> Result<Self, Error> {
        let mut registry = Self::default();
        for source in [builtin, user] {
            let mut names = BTreeSet::new();
            let mut documents: Vec<_> = source.iter().collect();
            documents.sort_by(|left, right| left.0.cmp(&right.0));
            for (filename, contents) in documents {
                let service = ServiceDefinition::from_yaml(contents)?;
                if !names.insert(service.name.clone()) {
                    return Err(
                        format!("Duplicate service name in source: {}", service.name).into(),
                    );
                }
                registry
                    .source_by_service
                    .insert(service.name.clone(), filename.clone());
                registry.services.insert(service.name.clone(), service);
            }
        }
        Ok(registry)
    }
}

pub type HostMap = BTreeMap<String, String>;
/// Synthetic gateway token and non-secret vault selection reference. Never emit
/// token-bearing bindings in diagnostics; this type intentionally omits Debug.
#[derive(Clone, Deserialize)]
pub struct TokenBinding {
    pub token: String,
    pub agent: String,
    pub service: String,
    pub capability: String,
    pub vault_token: String,
    #[serde(default)]
    pub account: String,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CompiledRoute {
    pub agent: String,
    pub service: String,
    pub capability: String,
    pub methods: Vec<String>,
    pub path: String,
}

pub fn compile_routes(
    service: &ServiceDefinition,
    binding: &TokenBinding,
    contracts: &[ContractBinding],
) -> Vec<CompiledRoute> {
    if service.name != binding.service {
        return Vec::new();
    }
    let Some(capability) = service.capabilities.get(&binding.capability) else {
        return Vec::new();
    };
    let make = |methods, path| CompiledRoute {
        agent: binding.agent.clone(),
        service: service.name.clone(),
        capability: capability.name.clone(),
        methods,
        path,
    };
    let Some(contract) = &capability.contract else {
        return capability
            .routes
            .iter()
            .map(|route| make(route.methods.clone(), route.path.clone()))
            .collect();
    };
    let state = contracts.iter().find(|state| {
        state.agent == binding.agent
            && state.service == service.name
            && state.capability == capability.name
            && state.template == contract.template
    });
    let empty = Map::new();
    let values = state.map_or(&empty, |state| &state.bound_values);
    let mut seen = BTreeSet::new();
    let operations: Vec<_> = if let Some(state) = state {
        state
            .grantable_operations
            .iter()
            .filter(|name| seen.insert(*name))
            .filter_map(|name| {
                contract
                    .grantable_operations()
                    .rev()
                    .find(|operation| &operation.name == name)
            })
            .collect()
    } else {
        contract
            .grantable_operations()
            .filter(|operation| operation.is_prebinding_grantable())
            .collect()
    };
    operations
        .into_iter()
        .filter_map(|operation| {
            if operation.bound_value_references().iter().any(|name| {
                !contract.bindings.contains_key(*name)
                    || values.get(*name).is_none_or(Value::is_null)
            }) {
                return None;
            }
            operation
                .resolved_path(values)
                .map(|path| make(vec![operation.request.method.to_uppercase()], path))
        })
        .collect()
}

pub fn method_matches(method: &str, methods: &[String]) -> bool {
    methods
        .iter()
        .any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(method))
}

/// Mirrors detection/core matching: normalize resource path, lowercase only its
/// host/service prefix, then lowercase the complete pattern. '*' crosses '/'.
pub fn resource_matches(resource: &str, pattern: &str) -> bool {
    let resource = if resource.starts_with('/') {
        normalize_path(resource)
    } else if let Some((prefix, path)) = resource.split_once('/') {
        format!(
            "{}{}",
            prefix.to_lowercase(),
            normalize_path(&format!("/{path}"))
        )
    } else {
        resource.to_lowercase()
    };
    let pattern = pattern.to_lowercase();
    crate::policy::glob(&resource, &pattern.replace("**", "*"))
        || (pattern.contains("**")
            && resource == pattern.trim_end_matches('*').trim_end_matches('/'))
}

/// The path normalization used by the shipped yarl-based matcher. Invalid UTF-8
/// percent bytes remain escaped; query/fragment text is outside the path.
pub fn normalize_path(path: &str) -> String {
    let path: String = path.nfkc().collect();
    if !path.starts_with('/') {
        return "/".into();
    }
    let raw = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .replace(['\r', '\n', '\t'], "");
    // yarl resolves dot segments after decoding unreserved escapes, before %2F
    // becomes a slash. Encoded separators therefore do not create dot segments.
    let unreserved = decode_unreserved(&raw);
    let mut segments = Vec::new();
    for segment in unreserved.split('/') {
        match segment {
            "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    let normalized = decode_path(&segments.join("/"));
    format!(
        "/{}",
        normalized
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    )
}
fn decode_unreserved(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if let Some(decoded) = percent_byte(bytes, index)
            && (decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded))
        {
            result.push(decoded);
            index += 3;
            continue;
        }
        result.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(result).expect("ASCII percent substitutions preserve UTF-8")
}
fn percent_byte(bytes: &[u8], index: usize) -> Option<u8> {
    if bytes.get(index) != Some(&b'%') {
        return None;
    }
    let high = (*bytes.get(index + 1)? as char).to_digit(16)?;
    let low = (*bytes.get(index + 2)? as char).to_digit(16)?;
    Some((high * 16 + low) as u8)
}
fn decode_path(value: &str) -> String {
    let mut result = String::new();
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        if let Some(first) = percent_byte(bytes, index) {
            let length = if first < 128 {
                1
            } else if first & 0xe0 == 0xc0 {
                2
            } else if first & 0xf0 == 0xe0 {
                3
            } else if first & 0xf8 == 0xf0 {
                4
            } else {
                0
            };
            let encoded: Option<Vec<u8>> = (0..length)
                .map(|offset| percent_byte(bytes, index + offset * 3))
                .collect();
            if length > 0
                && let Some(encoded) = encoded
                && let Ok(decoded) = std::str::from_utf8(&encoded)
            {
                result.push_str(decoded);
                index += 3 * length;
                continue;
            }
        }
        let character = value[index..].chars().next().unwrap();
        result.push(character);
        index += character.len_utf8();
    }
    result
}

#[derive(Clone, Copy)]
pub enum TrustedIdentity<'a> {
    Agent(&'a str),
    Missing,
    Conflict,
}
#[derive(Clone, Copy)]
pub enum RouteMode {
    CompiledPolicy,
    LocalFallback,
}
pub struct GatewayRequest<'a> {
    pub identity: TrustedIdentity<'a>,
    pub host: &'a str,
    pub request: ContractRequest<'a>,
    /// Explicitly select production compiled permissions or the existing local fallback.
    pub route_mode: RouteMode,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CredentialSelection {
    pub agent: String,
    pub service: String,
    pub capability: String,
    pub vault_token: String,
    pub account: String,
    pub auth_header: String,
    pub auth_scheme: String,
    pub allow_http: bool,
    pub refresh_on_401: bool,
    /// The caller must evaluate/consume applicable risky-route grants before use.
    pub risky_route: Option<RiskyRoute>,
    pub contract_operation: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum GatewayDecision {
    PassThrough,
    Deny {
        status: u16,
        code: String,
        field: Option<String>,
        strip_headers: Vec<String>,
    },
    Selected {
        credential: Box<CredentialSelection>,
    },
}
fn denied(status: u16, code: &str) -> GatewayDecision {
    GatewayDecision::Deny {
        status,
        code: code.into(),
        field: None,
        strip_headers: Vec::new(),
    }
}

fn folded_header(headers: &[(String, String)], name: &str) -> String {
    headers
        .iter()
        .filter(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}
fn token_candidate(value: &str) -> Option<&str> {
    let candidate = value.trim();
    let candidate = candidate
        .split_once(' ')
        .map_or(candidate, |(_, value)| value.trim());
    candidate.starts_with("sgw_").then_some(candidate)
}

pub fn select_route(
    registry: &Registry,
    hosts: &HostMap,
    tokens: &[TokenBinding],
    bindings: &[ContractBinding],
    request: GatewayRequest<'_>,
) -> GatewayDecision {
    let header_service = hosts
        .get(&request.host.to_lowercase())
        .and_then(|name| registry.services.get(name));
    let auth = header_service.and_then(|service| service.auth.as_ref());
    let token = auth.and_then(|auth| {
        let value = folded_header(request.request.headers, &auth.header);
        let value = if auth.kind == "bearer" {
            value
                .split_once(' ')
                .map_or(value.as_str(), |(_, value)| value)
        } else {
            &value
        };
        let value = value.trim();
        value.starts_with("sgw_").then(|| value.to_owned())
    });
    let Some(token) = token else {
        for (_, value) in request.request.headers {
            if let Some(token) = token_candidate(value) {
                return GatewayDecision::Deny {
                    status: 503,
                    code: "GATEWAY_CONFIGURATION_ERROR".into(),
                    field: None,
                    strip_headers: request
                        .request
                        .headers
                        .iter()
                        .filter(|(_, value)| value.contains(token))
                        .map(|(name, _)| name.clone())
                        .collect(),
                };
            }
        }
        return GatewayDecision::PassThrough;
    };
    let Some(binding) = tokens.iter().find(|binding| binding.token == token) else {
        return denied(403, "INVALID_TOKEN");
    };
    let agent = match request.identity {
        TrustedIdentity::Conflict => return denied(403, "AGENT_IDENTITY_CONFLICT"),
        TrustedIdentity::Missing => return denied(403, "AGENT_IDENTITY_REQUIRED"),
        TrustedIdentity::Agent(agent) => agent,
    };
    if agent != binding.agent {
        return denied(403, "AGENT_MISMATCH");
    }
    let Some(service) = registry.services.get(&binding.service) else {
        return denied(403, "SERVICE_NOT_FOUND");
    };
    let Some(capability) = service.capabilities.get(&binding.capability) else {
        return denied(403, "CAPABILITY_NOT_FOUND");
    };
    if hosts.get(&request.host.to_lowercase()) != Some(&binding.service) {
        return denied(403, "HOST_MISMATCH");
    }
    let path = request.request.target.split('?').next().unwrap_or_default();
    let permitted = match request.route_mode {
        RouteMode::CompiledPolicy => {
            compile_routes(service, binding, bindings)
                .iter()
                .any(|route| {
                    method_matches(request.request.method, &route.methods)
                        && resource_matches(
                            &format!("{}:{path}", service.name),
                            &format!("{}:{}", service.name, route.path),
                        )
                })
        }
        RouteMode::LocalFallback => capability.routes.iter().any(|route| {
            method_matches(request.request.method, &route.methods)
                && resource_matches(path, &route.path)
        }),
    };
    if !permitted {
        return denied(403, "ROUTE_DENIED");
    }
    let mut operation = None;
    if let Some(contract) = &capability.contract
        && contract.is_grantable()
    {
        let state = bindings.iter().find(|state| {
            state.agent == agent
                && state.service == service.name
                && state.capability == capability.name
        });
        match enforce_request(
            contract,
            state,
            service
                .auth
                .as_ref()
                .map_or("authorization", |auth| auth.header.as_str()),
            request.request,
        ) {
            Ok(canonical) => operation = Some(canonical.operation),
            Err(ContractDenial { code, field }) => {
                return GatewayDecision::Deny {
                    status: 403,
                    code: serde_json::to_value(code).unwrap().as_str().unwrap().into(),
                    field,
                    strip_headers: Vec::new(),
                };
            }
        }
    }
    let auth = service.auth.as_ref();
    GatewayDecision::Selected {
        credential: Box::new(CredentialSelection {
            agent: agent.into(),
            service: service.name.clone(),
            capability: capability.name.clone(),
            vault_token: binding.vault_token.clone(),
            account: binding.account.clone(),
            auth_header: auth
                .map_or("Authorization", |auth| auth.header.as_str())
                .into(),
            auth_scheme: auth
                .filter(|auth| auth.kind == "bearer")
                .map_or("", |auth| auth.scheme.as_str())
                .into(),
            allow_http: auth.is_some_and(|auth| auth.allow_http),
            refresh_on_401: auth.is_some_and(|auth| auth.refresh_on_401),
            risky_route: service
                .risky_routes
                .iter()
                .find(|route| {
                    method_matches(request.request.method, &route.methods)
                        && resource_matches(path, &route.path)
                })
                .cloned(),
            contract_operation: operation,
        }),
    }
}
