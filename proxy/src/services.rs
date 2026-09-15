//! Pure service-definition snapshots and gateway route selection. A selection is
//! not authorization to dial: risky-route policy and credential lifecycle still follow.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{
    Error,
    contracts::{
        BoundValueTypes, ContractBinding, ContractCode, ContractDenial, ContractRequest,
        ContractTemplate, enforce_request_with_timestamps,
    },
    credentials::{Secret, wipe_json},
    policy::{Effect, Policy, TimestampPaths},
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
        let raw = crate::policy::parse_yaml(source)?;
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
/// Gateway token and non-secret vault selection reference. Never emit
/// token-bearing bindings in diagnostics; this type intentionally omits Debug.
#[derive(Clone, Deserialize)]
pub struct TokenBinding {
    #[serde(deserialize_with = "deserialize_token")]
    pub token: Secret,
    #[serde(deserialize_with = "deserialize_field")]
    pub agent: Value,
    #[serde(deserialize_with = "deserialize_field")]
    pub service: Value,
    #[serde(deserialize_with = "deserialize_field")]
    pub capability: Value,
    #[serde(deserialize_with = "deserialize_field")]
    pub vault_token: Value,
    #[serde(default, deserialize_with = "deserialize_field")]
    pub account: Value,
}
impl Drop for TokenBinding {
    fn drop(&mut self) {
        for field in [
            &mut self.agent,
            &mut self.service,
            &mut self.capability,
            &mut self.vault_token,
            &mut self.account,
        ] {
            wipe_json(field);
        }
    }
}
fn deserialize_token<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Secret, D::Error> {
    String::deserialize(deserializer).map(Secret::new)
}
fn deserialize_field<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    crate::policy::parse_json(raw.get(), false).map_err(serde::de::Error::custom)
}

/// The accepted gateway configuration, its active tokens and routes are one
/// immutable load candidate. The Policy loader owns publication. In particular,
/// an empty candidate revokes every previous token (source defect D43).
///
/// Token-bearing state deliberately has neither Debug nor Serialize. Authorized
/// API/provisioning callers use the explicit secret-returning views below.
pub struct GatewaySnapshot {
    registry: Option<Arc<Registry>>,
    tokens: Vec<TokenBinding>,
    hosts: HostMap,
    contracts: Vec<ContractBinding>,
    contract_issues: ContractIssues,
    routes: Vec<CompiledRoute>,
    canonical: Value,
    token_issue: Option<GatewayCompatibility>,
    canonical_timestamps: TimestampPaths,
    token_timestamps: Vec<TokenTimestamps>,
}
#[derive(Clone, Copy, Default)]
struct TokenTimestamps {
    token: bool,
    agent: bool,
    service: bool,
    capability: bool,
    vault_token: bool,
    account: bool,
    view_non_json: bool,
}
struct GatewayJson(Value);
impl Drop for GatewayJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}
impl Drop for GatewaySnapshot {
    fn drop(&mut self) {
        wipe_json(&mut self.canonical);
    }
}
impl GatewaySnapshot {
    /// Consume the same normalized, expiry-pruned and list-expanded document as
    /// Policy. IAM gateway objects retain their supplied tokens and extra fields;
    /// host-format documents mint exactly once here, including without a registry.
    pub fn from_document(
        document: &Map<String, Value>,
        host_centric: bool,
        registry: Option<Arc<Registry>>,
    ) -> Result<Self, Error> {
        Self::from_typed_document(document, host_centric, registry, &TimestampPaths::default())
    }
    pub(crate) fn from_typed_document(
        document: &Map<String, Value>,
        host_centric: bool,
        registry: Option<Arc<Registry>>,
        timestamps: &TimestampPaths,
    ) -> Result<Self, Error> {
        let (canonical, canonical_timestamps) = if host_centric {
            compile_gateway_document(document, timestamps)?
        } else {
            (
                document
                    .get("gateway")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new())),
                timestamps.projected(&["gateway"]),
            )
        };
        // Construct the wiping owner before validating any token-bearing data.
        let mut snapshot = Self {
            registry,
            tokens: Vec::new(),
            hosts: HostMap::new(),
            contracts: Vec::new(),
            contract_issues: ContractIssues::default(),
            routes: Vec::new(),
            canonical,
            token_issue: None,
            canonical_timestamps,
            token_timestamps: Vec::new(),
        };
        let gateway = snapshot
            .canonical
            .as_object()
            .ok_or("gateway must be an object")?;
        if let Some(raw_hosts) = gateway.get("host_map").and_then(Value::as_object) {
            for (host, service) in raw_hosts {
                if snapshot
                    .canonical_timestamps
                    .value_at(&["host_map", host])
                    .is_none()
                    && snapshot
                        .canonical_timestamps
                        .key_at(&["host_map", host])
                        .is_none()
                    && let Some(service) = service.as_str()
                {
                    snapshot.hosts.insert(host.clone(), service.into());
                }
            }
        }
        if let Some(raw_tokens) = gateway.get("token_map") {
            if let Some(raw_tokens) = raw_tokens.as_object() {
                for (token, raw) in raw_tokens {
                    let Some(raw) = raw.as_object().filter(|raw| {
                        ["agent", "service", "token"]
                            .iter()
                            .all(|key| raw.contains_key(*key))
                    }) else {
                        snapshot.token_issue = Some(GatewayCompatibility::Binding);
                        continue;
                    };
                    snapshot.tokens.push(TokenBinding {
                        token: Secret::new(token.clone()),
                        agent: raw["agent"].clone(),
                        service: raw["service"].clone(),
                        capability: raw
                            .get("capability")
                            .or_else(|| raw.get("role"))
                            .cloned()
                            .unwrap_or_else(|| "".into()),
                        vault_token: raw["token"].clone(),
                        account: raw
                            .get("account")
                            .cloned()
                            .unwrap_or_else(|| "agent".into()),
                    });
                    let has = |field| {
                        snapshot
                            .canonical_timestamps
                            .value_at(&["token_map", token, field])
                            .is_some()
                    };
                    snapshot.token_timestamps.push(TokenTimestamps {
                        token: snapshot
                            .canonical_timestamps
                            .key_at(&["token_map", token])
                            .is_some(),
                        agent: has("agent"),
                        service: has("service"),
                        capability: has("capability")
                            || (!raw.contains_key("capability") && has("role")),
                        vault_token: has("token"),
                        account: has("account"),
                        view_non_json: ["service", "capability", "account"].iter().any(|field| {
                            snapshot
                                .canonical_timestamps
                                .has_under(&["token_map", token, field])
                        }) || (!raw.contains_key("capability")
                            && snapshot.canonical_timestamps.has_under(&[
                                "token_map",
                                token,
                                "role",
                            ])),
                    });
                }
            } else if python_truthy(raw_tokens) {
                snapshot.token_issue = Some(GatewayCompatibility::TokenMap);
            }
        }
        // The compiler uses the first matching template; the request-time source
        // cache uses the last record for (agent, service, capability). Retain both
        // observable orders while sharing the same typed binding representation.
        let (compiler_contracts, contract_issues) = document_contracts(document, timestamps);
        let compiler_annotations = contract_issues.annotations.clone();
        snapshot.contract_issues = contract_issues;
        snapshot.contract_issues.annotations.clear();
        for (binding, annotation) in compiler_contracts.iter().zip(&compiler_annotations) {
            if !annotation.runtime_available {
                continue;
            }
            if let Some(index) = snapshot.contracts.iter().position(|previous| {
                previous.agent == binding.agent
                    && previous.service == binding.service
                    && previous.capability == binding.capability
            }) {
                snapshot.contracts[index] = binding.clone();
                snapshot.contract_issues.annotations[index] = annotation.clone();
            } else {
                snapshot.contracts.push(binding.clone());
                snapshot
                    .contract_issues
                    .annotations
                    .push(annotation.clone());
            }
        }
        // IAM already contains its authored/compiled permissions. Only the
        // host-format compiler synthesizes new route permissions.
        if host_centric && let Some(registry) = &snapshot.registry {
            for (binding, typed) in snapshot.tokens.iter().zip(&snapshot.token_timestamps) {
                if typed.service || typed.capability {
                    continue;
                }
                if let Some(service) = binding
                    .service
                    .as_str()
                    .and_then(|name| registry.services.get(name))
                {
                    if unhashable(&binding.capability) {
                        return Err("gateway capability cannot be used as a registry key".into());
                    }
                    let routes = compile_routes_with_annotations(
                        service,
                        binding,
                        &compiler_contracts,
                        &compiler_annotations,
                    );
                    if typed.agent && !routes.is_empty() {
                        return Err(
                            "typed gateway agent is not a valid permission condition".into()
                        );
                    }
                    snapshot.routes.extend(routes);
                }
            }
        }
        Ok(snapshot)
    }

    pub fn registry(&self) -> Option<Arc<Registry>> {
        self.registry.clone()
    }

    pub fn compiled_routes(&self) -> &[CompiledRoute] {
        &self.routes
    }

    /// Only the authoritative Policy baseline composer may copy this view. Its
    /// owner must wipe copied token strings and omit them from diagnostic Debug.
    pub(crate) fn canonical_gateway(&self) -> &Value {
        &self.canonical
    }
    pub(crate) fn canonical_timestamps(&self) -> &TimestampPaths {
        &self.canonical_timestamps
    }

    /// Exact per-agent provisioning map (service -> active token). This reads
    /// source agent_env, including supplied IAM data, without minting tokens.
    pub fn agent_environment_json(&self, agent: &str) -> Result<Secret, Error> {
        let empty = Value::Object(Map::new());
        if self
            .canonical_timestamps
            .key_at(&["agent_env", agent])
            .is_some()
        {
            return Ok(Secret::new("{}"));
        }
        if self.canonical_timestamps.has_under(&["agent_env", agent]) {
            return Err("gateway provisioning contains a non-JSON timestamp".into());
        }
        let value = match self.canonical.get("agent_env") {
            None => &empty,
            Some(environment) => environment
                .as_object()
                .ok_or("gateway provisioning environment must be an object")?
                .get(agent)
                .unwrap_or(&empty),
        };
        Ok(Secret::new(crate::python_json::encode(value)))
    }

    /// Authenticated agent API projection of live bindings. The caller has
    /// already established this trusted agent; a request header is not identity.
    pub fn agent_services_json(&self, agent: &str) -> Result<Secret, Error> {
        if self.token_issue.is_some() {
            return Err("gateway binding view is unavailable for this source shape".into());
        }
        if self
            .tokens
            .iter()
            .zip(&self.token_timestamps)
            .any(|(binding, typed)| {
                (!typed.agent && unhashable(&binding.agent))
                    || (!typed.service && unhashable(&binding.service))
            })
        {
            return Err("gateway service view contains an unhashable binding key".into());
        }
        let mut reverse_hosts = BTreeMap::new();
        if let Some(hosts) = self.canonical.get("host_map").and_then(Value::as_object) {
            for (host, service) in hosts {
                if self
                    .canonical_timestamps
                    .value_at(&["host_map", host])
                    .is_none()
                    && unhashable(service)
                {
                    return Err("gateway service view contains an unhashable host binding".into());
                }
                // Only source string service names match the registry. Last
                // source host wins independently of sorted exact-lookup maps.
                if self
                    .canonical_timestamps
                    .value_at(&["host_map", host])
                    .is_none()
                    && let Some(service) = service.as_str()
                {
                    reverse_hosts.insert(
                        service,
                        (
                            host.as_str(),
                            self.canonical_timestamps
                                .key_at(&["host_map", host])
                                .is_some(),
                        ),
                    );
                }
            }
        }
        let mut services = Value::Object(Map::new());
        for (binding, typed) in self
            .tokens
            .iter()
            .zip(&self.token_timestamps)
            .filter(|(binding, typed)| !typed.agent && binding.agent == agent)
        {
            if typed.token || typed.view_non_json {
                wipe_json(&mut services);
                return Err("gateway service view contains a non-JSON timestamp".into());
            }
            let Some(name) = binding.service.as_str() else {
                wipe_json(&mut services);
                return Err("gateway service API requires a representable service key".into());
            };
            let mut service = Map::new();
            let (host, typed_host) = reverse_hosts.get(name).copied().unwrap_or(("", false));
            if typed_host {
                wipe_json(&mut services);
                return Err("gateway service view contains a non-JSON timestamp".into());
            }
            service.insert("host".into(), host.into());
            service.insert("token".into(), binding.token.expose_secret().into());
            service.insert("capability".into(), binding.capability.clone());
            service.insert("account".into(), binding.account.clone());
            services
                .as_object_mut()
                .unwrap()
                .insert(name.into(), Value::Object(service));
        }
        let encoded = crate::python_json::encode(&services);
        wipe_json(&mut services);
        Ok(Secret::new(encoded))
    }

    pub fn select(&self, request: GatewayRequest<'_>) -> GatewayDecision {
        if let Some(hosts) = self.canonical.get("host_map") {
            let Some(hosts) = hosts.as_object() else {
                return incompatible(GatewayCompatibility::HostMap);
            };
            if hosts
                .get(&request.host.to_lowercase())
                .is_some_and(|value| python_truthy(value) && unhashable(value))
                && self
                    .canonical_timestamps
                    .value_at(&["host_map", &request.host.to_lowercase()])
                    .is_none()
            {
                return incompatible(GatewayCompatibility::HostMap);
            }
        }
        let decision = match self.registry.as_deref() {
            Some(registry) => select_route_inner(
                registry,
                &self.hosts,
                &self.tokens,
                &self.contracts,
                &self.contract_issues,
                &self.token_timestamps,
                request,
            ),
            // Source cannot extract a configured token without registry metadata.
            // It still contains the reserved token prefix before ordinary traffic.
            None => unresolved_token(request.request.headers),
        };
        if matches!(decision, GatewayDecision::Selected { .. })
            && let Some(issue) = self.token_issue
        {
            return incompatible(issue);
        }
        decision
    }
}

#[derive(Default)]
struct ContractIssues {
    unavailable: BTreeSet<(String, String, String)>,
    annotations: Vec<ContractAnnotation>,
}
#[derive(Clone)]
struct ContractAnnotation {
    runtime_available: bool,
    template_matches: bool,
    values: TimestampPaths,
}
fn document_contracts(
    document: &Map<String, Value>,
    timestamps: &TimestampPaths,
) -> (Vec<ContractBinding>, ContractIssues) {
    let mut result = Vec::new();
    let mut issues = ContractIssues::default();
    let Some(agents) = document.get("agents").and_then(Value::as_object) else {
        return (result, issues);
    };
    // The runtime callback retains its valid prefix, whereas the compiler
    // continues scanning the full list. Track both in this one pass.
    let mut runtime_loading = true;
    for (agent, config) in agents {
        let Some(config) = config.as_object() else {
            continue;
        };
        let Some(raw_bindings) = config.get("contract_bindings") else {
            continue;
        };
        let Some(bindings) = raw_bindings.as_array() else {
            // Empty strings/dicts iterate zero times in Python. Other non-list
            // values fail either iteration or their first record access.
            if !matches!(raw_bindings, Value::String(value) if value.is_empty())
                && !matches!(raw_bindings, Value::Object(value) if value.is_empty())
            {
                runtime_loading = false;
            }
            continue;
        };
        for (index, raw) in bindings.iter().enumerate() {
            let index = index.to_string();
            let Some(raw) = raw.as_object() else {
                runtime_loading = false;
                continue;
            };
            if ["service", "capability"].iter().any(|field| {
                raw.get(*field).is_none_or(|value| {
                    unhashable(value)
                        && timestamps
                            .value_at(&["agents", agent, "contract_bindings", &index, field])
                            .is_none()
                })
            }) {
                runtime_loading = false;
            }
            if timestamps.key_at(&["agents", agent]).is_some() {
                // Preserve callback failure above, but a temporal agent key is
                // never an ordinary trusted string or a compiled string scope.
                continue;
            }
            let (Some(service), Some(capability)) = (
                raw.get("service").and_then(Value::as_str),
                raw.get("capability").and_then(Value::as_str),
            ) else {
                continue;
            };
            if ["service", "capability"].iter().any(|field| {
                timestamps
                    .value_at(&["agents", agent, "contract_bindings", &index, field])
                    .is_some()
            }) {
                continue;
            }
            let empty = Value::Object(Map::new());
            let values = raw
                .get("bound_values")
                .unwrap_or(&empty)
                .as_object()
                .filter(|_| {
                    timestamps
                        .value_at(&["agents", agent, "contract_bindings", &index, "bound_values"])
                        .is_none()
                });
            let operations = match raw.get("grantable_operations") {
                None => Some(Vec::new()),
                Some(Value::Array(operations)) => operations
                    .iter()
                    .map(|name| name.as_str().map(str::to_owned))
                    .collect(),
                _ => None,
            };
            let operations = operations.filter(|_| {
                !timestamps.has_under(&[
                    "agents",
                    agent,
                    "contract_bindings",
                    &index,
                    "grantable_operations",
                ])
            });
            let template = raw.get("template").map_or(Some(""), Value::as_str);
            let template_matches = template.is_some()
                && timestamps
                    .value_at(&["agents", agent, "contract_bindings", &index, "template"])
                    .is_none();
            let invalid = values.is_none() || operations.is_none();
            if runtime_loading && values.is_none() {
                issues
                    .unavailable
                    .insert((agent.clone(), service.into(), capability.into()));
            } else if runtime_loading {
                // The runtime source cache uses the last record for this key.
                issues
                    .unavailable
                    .remove(&(agent.clone(), service.into(), capability.into()));
            }
            // A matching malformed approval grants no compiled operations, as in
            // _compile_capability_routes. Preserve its position so it cannot fall
            // through to a later record or the no-binding discovery subset.
            result.push(ContractBinding {
                binding_id: raw
                    .get("binding_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into(),
                agent: agent.clone(),
                service: service.into(),
                capability: capability.into(),
                template: template.unwrap_or("").into(),
                bound_values: values.cloned().unwrap_or_default(),
                grantable_operations: if invalid {
                    Vec::new()
                } else {
                    operations.unwrap()
                },
            });
            issues.annotations.push(ContractAnnotation {
                runtime_available: runtime_loading,
                template_matches,
                values: timestamps.projected(&[
                    "agents",
                    agent,
                    "contract_bindings",
                    &index,
                    "bound_values",
                ]),
            });
        }
    }
    (result, issues)
}

fn mint_gateway_token() -> Result<Secret, Error> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| "gateway entropy unavailable")?;
    let mut value = String::with_capacity(68);
    value.push_str("sgw_");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes.iter() {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(Secret::new(value))
}

fn compile_gateway_document(
    document: &Map<String, Value>,
    timestamps: &TimestampPaths,
) -> Result<(Value, TimestampPaths), Error> {
    let mut typed = TimestampPaths::default();
    let mut hosts = Map::new();
    if let Some(raw_hosts) = document.get("hosts").and_then(Value::as_object) {
        for (host, raw) in raw_hosts {
            if host != "*"
                && crate::policy::split_destination(host)?.1.is_none()
                && let Some(service) = raw.get("service")
            {
                hosts.insert(host.clone(), service.clone());
                typed.extend(
                    timestamps.copy_under(&["hosts", host, "service"], &["host_map", host]),
                );
                if let Some(value) = timestamps.key_at(&["hosts", host]) {
                    typed.insert_key(&["host_map", host], value.clone());
                }
            }
        }
    }
    let mut gateway = Map::new();
    if document.contains_key("agents") || document.contains_key("services") || !hosts.is_empty() {
        let mut tokens = GatewayJson(Value::Object(Map::new()));
        let mut environment = GatewayJson(Value::Object(Map::new()));
        if let Some(agents) = document.get("agents").and_then(Value::as_object) {
            for (agent, config) in agents {
                let Some(config) = config.as_object() else {
                    continue;
                };
                let empty = Map::new();
                let services = match config.get("services") {
                    None => &empty,
                    Some(Value::Object(services)) => services,
                    _ => continue,
                };
                let mut agent_env = GatewayJson(Value::Object(Map::new()));
                if let Some(value) = timestamps.key_at(&["agents", agent]) {
                    typed.insert_key(&["agent_env", agent], value.clone());
                }
                for (service, config) in services {
                    let source_path = ["agents", agent, "services", service];
                    if timestamps.value_at(&source_path).is_some() {
                        continue;
                    }
                    let (capability, vault_token, account) = match config {
                        Value::String(capability) => (
                            Value::String(capability.clone()),
                            Value::String(String::new()),
                            Value::String("agent".into()),
                        ),
                        Value::Object(config) => (
                            config
                                .get("capability")
                                .or_else(|| config.get("role"))
                                .cloned()
                                .unwrap_or_else(|| "".into()),
                            config.get("token").cloned().unwrap_or_else(|| "".into()),
                            config
                                .get("account")
                                .cloned()
                                .unwrap_or_else(|| "agent".into()),
                        ),
                        _ => continue,
                    };
                    if !python_truthy(&capability) {
                        continue;
                    }
                    let token = mint_gateway_token()?;
                    let key = token.expose_secret();
                    typed.extend(
                        timestamps
                            .copy_key_as_value(&["agents", agent], &["token_map", key, "agent"]),
                    );
                    typed.extend(
                        timestamps.copy_key_as_value(&source_path, &["token_map", key, "service"]),
                    );
                    if let Some(value) = timestamps.key_at(&source_path) {
                        typed.insert_key(&["agent_env", agent, service], value.clone());
                    }
                    if let Some(config) = config.as_object() {
                        for field in ["capability", "token", "account"] {
                            let source_field =
                                if field == "capability" && !config.contains_key(field) {
                                    "role"
                                } else {
                                    field
                                };
                            typed.extend(timestamps.copy_under(
                                &["agents", agent, "services", service, source_field],
                                &["token_map", key, field],
                            ));
                        }
                    }
                    let mut binding = Map::new();
                    binding.insert("agent".into(), agent.clone().into());
                    binding.insert("service".into(), service.clone().into());
                    binding.insert("capability".into(), capability);
                    binding.insert("token".into(), vault_token);
                    binding.insert("account".into(), account);
                    tokens
                        .0
                        .as_object_mut()
                        .unwrap()
                        .insert(token.expose_secret().into(), Value::Object(binding));
                    agent_env
                        .0
                        .as_object_mut()
                        .unwrap()
                        .insert(service.clone(), token.expose_secret().into());
                }
                environment
                    .0
                    .as_object_mut()
                    .unwrap()
                    .insert(agent.clone(), std::mem::take(&mut agent_env.0));
            }
        }
        gateway.insert("token_map".into(), std::mem::take(&mut tokens.0));
        gateway.insert("agent_env".into(), std::mem::take(&mut environment.0));
        gateway.insert("host_map".into(), Value::Object(hosts));
    }
    if let Some(ttl) = document
        .get("gateway")
        .and_then(|gateway| gateway.get("grant_ttl_seconds"))
    {
        gateway.insert("grant_ttl_seconds".into(), ttl.clone());
        typed.extend(
            timestamps.copy_under(&["gateway", "grant_ttl_seconds"], &["grant_ttl_seconds"]),
        );
    }
    Ok((Value::Object(gateway), typed))
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
    compile_routes_with_annotations(service, binding, contracts, &[])
}

fn compile_routes_with_annotations(
    service: &ServiceDefinition,
    binding: &TokenBinding,
    contracts: &[ContractBinding],
    annotations: &[ContractAnnotation],
) -> Vec<CompiledRoute> {
    if service.name != binding.service {
        return Vec::new();
    }
    let Some(agent) = binding.agent.as_str() else {
        return Vec::new();
    };
    let Some(capability) = binding
        .capability
        .as_str()
        .and_then(|name| service.capabilities.get(name))
    else {
        return Vec::new();
    };
    let make = |methods, path| CompiledRoute {
        agent: agent.into(),
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
    let state = contracts.iter().enumerate().find(|(index, state)| {
        annotations
            .get(*index)
            .is_none_or(|annotation| annotation.template_matches)
            && state.agent == binding.agent
            && state.service == service.name
            && state.capability == capability.name
            && state.template == contract.template
    });
    let empty = Map::new();
    let empty_types = TimestampPaths::default();
    let value_types = state
        .and_then(|(index, _)| annotations.get(index))
        .map_or(&empty_types, |annotation| &annotation.values);
    let state = state.map(|(_, state)| state);
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
                    || value_types.key_at(&[name]).is_some()
            }) {
                return None;
            }
            if operation.request.path_params.values().any(|constraint| {
                !constraint.equals_var.is_empty()
                    && value_types.value_at(&[&constraint.equals_var]).is_some()
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
pub enum RouteMode<'a> {
    CompiledPolicy(&'a Policy),
    LocalFallback,
}
pub struct GatewayRequest<'a> {
    pub identity: TrustedIdentity<'a>,
    pub host: &'a str,
    pub request: ContractRequest<'a>,
    /// Explicitly select production compiled permissions or the existing local fallback.
    pub route_mode: RouteMode<'a>,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CredentialSelection {
    pub agent: String,
    pub service: String,
    pub capability: String,
    pub vault_token: String,
    pub account: String,
    /// Exact source kind; None means no auth section. Unknown kinds remain
    /// remove-only during injection.
    pub auth_kind: Option<String>,
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
    /// A source-accepted shape reaches an operation the typed native downstream
    /// cannot yet represent. This must never be treated as allow or local fallback.
    Compatibility {
        field: GatewayCompatibility,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayCompatibility {
    TokenMap,
    Binding,
    HostMap,
    ServiceLookup,
    CapabilityLookup,
    VaultReference,
    Account,
    ContractBinding,
}
fn incompatible(field: GatewayCompatibility) -> GatewayDecision {
    GatewayDecision::Compatibility { field }
}
fn unhashable(value: &Value) -> bool {
    matches!(value, Value::Array(_) | Value::Object(_))
}
fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
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
    let candidate = value.trim_matches(crate::policy::python_whitespace);
    let candidate = candidate.split_once(' ').map_or(candidate, |(_, value)| {
        value.trim_matches(crate::policy::python_whitespace)
    });
    candidate.starts_with("sgw_").then_some(candidate)
}

fn unresolved_token(headers: &[(String, String)]) -> GatewayDecision {
    for (_, value) in headers {
        if let Some(token) = token_candidate(value) {
            return GatewayDecision::Deny {
                status: 503,
                code: "GATEWAY_CONFIGURATION_ERROR".into(),
                field: None,
                strip_headers: headers
                    .iter()
                    .filter(|(_, value)| value.contains(token))
                    .map(|(name, _)| name.clone())
                    .collect(),
            };
        }
    }
    GatewayDecision::PassThrough
}

pub fn select_route(
    registry: &Registry,
    hosts: &HostMap,
    tokens: &[TokenBinding],
    bindings: &[ContractBinding],
    request: GatewayRequest<'_>,
) -> GatewayDecision {
    select_route_inner(
        registry,
        hosts,
        tokens,
        bindings,
        &ContractIssues::default(),
        &[],
        request,
    )
}
fn select_route_inner(
    registry: &Registry,
    hosts: &HostMap,
    tokens: &[TokenBinding],
    bindings: &[ContractBinding],
    issues: &ContractIssues,
    timestamps: &[TokenTimestamps],
    request: GatewayRequest<'_>,
) -> GatewayDecision {
    let token = extract_token(registry, hosts, &request);
    let Some(token) = token else {
        return unresolved_token(request.request.headers);
    };
    let Some((index, binding)) = tokens.iter().enumerate().find(|(index, binding)| {
        !timestamps.get(*index).is_some_and(|typed| typed.token)
            && binding.token.expose_secret() == token.expose_secret()
    }) else {
        return denied(403, "INVALID_TOKEN");
    };
    select_binding(
        registry,
        hosts,
        binding,
        bindings,
        issues,
        timestamps.get(index).copied().unwrap_or_default(),
        request,
    )
}
fn extract_token(
    registry: &Registry,
    hosts: &HostMap,
    request: &GatewayRequest<'_>,
) -> Option<Secret> {
    let header_service = hosts
        .get(&request.host.to_lowercase())
        .and_then(|name| registry.services.get(name));
    let auth = header_service.and_then(|service| service.auth.as_ref());
    auth.and_then(|auth| {
        let value = Zeroizing::new(folded_header(request.request.headers, &auth.header));
        let value = if auth.kind == "bearer" {
            value
                .split_once(' ')
                .map_or(value.as_str(), |(_, value)| value)
        } else {
            &value
        };
        let value = value.trim_matches(crate::policy::python_whitespace);
        value.starts_with("sgw_").then(|| Secret::new(value))
    })
}
fn select_binding(
    registry: &Registry,
    hosts: &HostMap,
    binding: &TokenBinding,
    bindings: &[ContractBinding],
    issues: &ContractIssues,
    typed: TokenTimestamps,
    request: GatewayRequest<'_>,
) -> GatewayDecision {
    let agent = match request.identity {
        TrustedIdentity::Conflict => return denied(403, "AGENT_IDENTITY_CONFLICT"),
        TrustedIdentity::Missing => return denied(403, "AGENT_IDENTITY_REQUIRED"),
        TrustedIdentity::Agent(agent) => agent,
    };
    if typed.agent || binding.agent != agent {
        return denied(403, "AGENT_MISMATCH");
    }
    if typed.service {
        return denied(403, "SERVICE_NOT_FOUND");
    }
    if unhashable(&binding.service) {
        return incompatible(GatewayCompatibility::ServiceLookup);
    }
    let Some(service) = binding
        .service
        .as_str()
        .and_then(|name| registry.services.get(name))
    else {
        return denied(403, "SERVICE_NOT_FOUND");
    };
    if typed.capability {
        return denied(403, "CAPABILITY_NOT_FOUND");
    }
    if unhashable(&binding.capability) {
        return incompatible(GatewayCompatibility::CapabilityLookup);
    }
    let Some(capability) = binding
        .capability
        .as_str()
        .and_then(|name| service.capabilities.get(name))
    else {
        return denied(403, "CAPABILITY_NOT_FOUND");
    };
    if hosts.get(&request.host.to_lowercase()).map(String::as_str) != binding.service.as_str() {
        return denied(403, "HOST_MISMATCH");
    }
    let path = request.request.target.split('?').next().unwrap_or_default();
    let permitted = match request.route_mode {
        RouteMode::CompiledPolicy(policy) => {
            policy
                .evaluate_gateway_request(crate::policy::GatewayRequest {
                    service: &service.name,
                    capability: &capability.name,
                    agent,
                    method: request.request.method,
                    path,
                })
                .effect
                == Effect::Allow
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
        let state = bindings.iter().enumerate().find(|(_, state)| {
            state.agent == agent
                && state.service == service.name
                && state.capability == capability.name
        });
        let empty_types = TimestampPaths::default();
        let timestamps = state
            .and_then(|(index, _)| issues.annotations.get(index))
            .map_or(&empty_types, |annotation| &annotation.values);
        let mapping_available = !issues.unavailable.contains(&(
            agent.into(),
            service.name.clone(),
            capability.name.clone(),
        ));
        match enforce_request_with_timestamps(
            contract,
            state.map(|(_, state)| state),
            service
                .auth
                .as_ref()
                .map_or("authorization", |auth| auth.header.as_str()),
            request.request,
            BoundValueTypes {
                timestamps,
                mapping_available,
            },
        ) {
            Ok(canonical) => operation = Some(canonical.operation),
            Err(ContractDenial {
                code: ContractCode::ValueCompatibility,
                ..
            }) => {
                return incompatible(GatewayCompatibility::ContractBinding);
            }
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
    let Some(vault_token) = binding.vault_token.as_str().filter(|_| !typed.vault_token) else {
        return incompatible(GatewayCompatibility::VaultReference);
    };
    let Some(account) = binding.account.as_str().filter(|_| !typed.account) else {
        return incompatible(GatewayCompatibility::Account);
    };
    GatewayDecision::Selected {
        credential: Box::new(CredentialSelection {
            agent: agent.into(),
            service: service.name.clone(),
            capability: capability.name.clone(),
            vault_token: vault_token.into(),
            account: account.into(),
            auth_kind: auth.map(|auth| auth.kind.clone()),
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
