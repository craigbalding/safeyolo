//! Native network-policy evaluation under development; not selected by the proxy.
//!
//! Decisions mirror PolicyEngine.evaluate_request, including its existing exact
//! index case sensitivity, shared host budgets and separate CONNECT counters.
//! Credential/service permissions and addon enforcement are outside this API.
//! Lists, expiry, task overlays and unsupported network conditions are not silently
//! approximated. Loading a document that needs them reports Unsupported.

use std::{collections::HashMap, fmt, net::Ipv6Addr, path::Path, sync::Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug)]
pub enum Format {
    Toml,
    Yaml,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Invalid,
    Unsupported,
    Read,
}

#[derive(Debug)]
pub struct PolicyError {
    pub kind: ErrorKind,
    pub message: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for PolicyError {}

type Result<T> = std::result::Result<T, PolicyError>;

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError {
        kind: ErrorKind::Invalid,
        message: message.into(),
    }
}
fn unsupported(message: impl Into<String>) -> PolicyError {
    PolicyError {
        kind: ErrorKind::Unsupported,
        message: message.into(),
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
    Prompt,
    BudgetExceeded,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    /// The actual authored rule, rather than Python's synthetic simple-rule '*'.
    pub matched_resource: Option<String>,
    pub budget_remaining: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct NetworkRequest<'a> {
    pub agent: Option<&'a str>,
    pub host: &'a str,
    pub port: Option<u16>,
    pub method: &'a str,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug)]
enum RuleEffect {
    Allow,
    Deny,
    Prompt,
    Budget(u64),
}

#[derive(Default, Debug)]
struct Condition {
    present: bool,
    agent: Option<String>,
    ports: Option<Vec<u16>>,
    methods: Option<Vec<String>>,
    path_prefix: Option<String>,
}

impl Condition {
    fn matches(&self, request: &NetworkRequest<'_>) -> bool {
        self.agent
            .as_ref()
            .is_none_or(|pattern| glob(request.agent.unwrap_or(""), pattern))
            && self
                .ports
                .as_ref()
                .is_none_or(|ports| request.port.is_some_and(|port| ports.contains(&port)))
            && self.methods.as_ref().is_none_or(|methods| {
                methods
                    .iter()
                    .any(|method| method.to_uppercase() == request.method.to_uppercase())
            })
            && self
                .path_prefix
                .as_ref()
                .is_none_or(|prefix| request.path.starts_with(prefix))
    }
}

#[derive(Debug)]
struct Rule {
    resource: String,
    effect: RuleEffect,
    condition: Condition,
    inferred: bool,
}

impl Rule {
    fn exact(&self) -> bool {
        self.resource
            .strip_suffix("/*")
            .is_some_and(|prefix| !prefix.contains(['/', ':', '*', '?', '[']))
    }
    fn simple(&self) -> bool {
        self.exact()
            && !self.condition.present
            && !self.inferred
            && !matches!(self.effect, RuleEffect::Budget(_))
    }
    fn score(&self) -> (i64, bool) {
        let score = if self.resource == "*" {
            0
        } else {
            self.resource.chars().count() as i64 * 10
                - self.resource.matches('*').count() as i64 * 50
        };
        (
            score + if self.condition.present { 5 } else { 0 },
            self.condition.ports.is_some(),
        )
    }
}

#[derive(Default, Debug)]
struct Override {
    pattern: String,
    bypass: bool,
    enabled: Option<bool>,
}

/// One network rule representation and one atomic GCRA state map.
#[derive(Debug)]
pub struct Policy {
    rules: Vec<Rule>,
    global_budget: Option<u64>,
    budgets: Mutex<HashMap<String, f64>>,
    required: bool,
    enabled: bool,
    domains: Vec<Override>,
    clients: Vec<Override>,
}

impl Policy {
    pub fn parse(source: &str, format: Format) -> Result<Self> {
        Self::from_document(parse_document(source, format)?)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path).map_err(|error| PolicyError {
            kind: ErrorKind::Read,
            message: error.to_string(),
        })?;
        let format = match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Format::Toml,
            Some("yaml" | "yml") => Format::Yaml,
            _ => Format::Json,
        };
        let mut document = parse_document(&source, format)?;
        // Existing loader merges sibling addons.yaml defaults before compilation.
        let addons = path.with_file_name("addons.yaml");
        if addons.exists() && addons != path {
            let defaults = parse_document(
                &std::fs::read_to_string(addons).map_err(|error| PolicyError {
                    kind: ErrorKind::Read,
                    message: error.to_string(),
                })?,
                Format::Yaml,
            )?;
            for (key, value) in defaults {
                if key == "addons" && document.contains_key(&key) {
                    let mut merged = object(&value, "addons")?.clone();
                    merged.extend(object(&document[&key], "addons")?.clone());
                    document.insert(key, Value::Object(merged));
                } else {
                    document.entry(key).or_insert(value);
                }
            }
        }
        Self::from_document(document)
    }

    fn from_document(document: Map<String, Value>) -> Result<Self> {
        if document.contains_key("lists") {
            return Err(unsupported(
                "native network policy does not yet expand configured lists",
            ));
        }
        let budgets = document
            .get("budgets")
            .map(|budgets| object(budgets, "budgets"))
            .transpose()?;
        let global = if document.contains_key("hosts") {
            document.get("global_budget")
        } else {
            None
        }
        .or_else(|| budgets.and_then(|budgets| budgets.get("network:request")));
        let global_budget = global
            .map(|value| positive_integer(value, "global network budget"))
            .transpose()?;
        let mut policy = Self {
            rules: Vec::new(),
            global_budget,
            budgets: Mutex::new(HashMap::new()),
            required: false,
            enabled: true,
            domains: Vec::new(),
            clients: Vec::new(),
        };
        policy.required = document
            .get("required")
            .map(|value| {
                string_list(value, "required")
                    .map(|values| values.iter().any(|value| value == "network_guard"))
            })
            .transpose()?
            .unwrap_or(false);
        policy.enabled = network_enabled(document.get("addons"))?.unwrap_or(true);
        policy.domains = overrides(document.get("domains"))?;
        policy.clients = overrides(document.get("clients"))?;
        if let Some(hosts) = document.get("hosts") {
            policy.compile_hosts(object(hosts, "hosts")?, None)?;
            if let Some(agents) = document.get("agents") {
                for (agent, config) in object(agents, "agents")? {
                    let Some(config) = config.as_object() else {
                        continue;
                    };
                    if let Some(egress) = config.get("egress") {
                        let effect = egress_effect(egress)?;
                        policy.rules.push(Rule {
                            resource: "*".into(),
                            effect,
                            condition: Condition {
                                present: true,
                                agent: Some(agent.clone()),
                                ..Default::default()
                            },
                            inferred: false,
                        });
                    }
                    if let Some(hosts) = config.get("hosts") {
                        policy.compile_hosts(object(hosts, "agent hosts")?, Some(agent))?;
                    }
                }
            }
        } else if let Some(permissions) = document.get("permissions") {
            policy.compile_iam(permissions, false)?;
        }
        // Stable ordering preserves author order when specificity is tied.
        policy
            .rules
            .sort_by_key(|rule| std::cmp::Reverse(rule.score()));
        Ok(policy)
    }

    fn compile_hosts(&mut self, hosts: &Map<String, Value>, agent: Option<&str>) -> Result<()> {
        for (pattern, config) in hosts {
            let empty = Map::new();
            let config = if config.is_null() {
                &empty
            } else {
                object(config, "host configuration")?
            };
            if config.contains_key("expires") {
                return Err(unsupported(
                    "native network policy does not yet implement host expiry",
                ));
            }
            if pattern.starts_with('$') {
                return Err(unsupported(
                    "native network policy does not yet expand host list references",
                ));
            }
            if agent.is_some()
                && config
                    .get("bypass")
                    .map(|value| {
                        string_list(value, "bypass")
                            .map(|values| values.iter().any(|value| value == "network_guard"))
                    })
                    .transpose()?
                    .unwrap_or(false)
            {
                return Err(unsupported(
                    "agent-host network bypass is not yet supported; the current compiler does not propagate it",
                ));
            }
            let (host, port) = split_destination(pattern)?;
            let rate = config
                .get("rate_limit")
                .map(|value| positive_integer(value, "host rate"))
                .transpose()?;
            if let (Some(rate), Some(global)) = (rate, self.global_budget)
                && rate > global
            {
                return Err(invalid(format!(
                    "host rate {rate} exceeds global budget {global}"
                )));
            }
            let egress = config.get("egress").map(egress_effect).transpose()?;
            let resource = if (pattern == "*" && agent.is_none()) || (port.is_some() && host == "*")
            {
                "*".into()
            } else {
                format!("{}/*", if port.is_some() { &host } else { pattern })
            };
            let condition = || Condition {
                present: agent.is_some() || port.is_some(),
                agent: agent.map(str::to_owned),
                ports: port.map(|port| vec![port]),
                ..Default::default()
            };
            if port.is_some() {
                if config
                    .keys()
                    .any(|key| !matches!(key.as_str(), "egress" | "rate_limit"))
                {
                    return Err(invalid(
                        "endpoint entries support only network egress and rate fields",
                    ));
                }
                let effect = match (egress, rate) {
                    (Some(RuleEffect::Allow) | None, Some(rate)) => RuleEffect::Budget(rate),
                    (Some(effect), _) => effect,
                    _ => return Err(invalid("endpoint requires egress or a rate")),
                };
                self.rules.push(Rule {
                    resource,
                    effect,
                    condition: condition(),
                    inferred: false,
                });
                continue;
            }
            if let Some(effect) = egress
                && (!matches!(effect, RuleEffect::Allow) || rate.is_none())
            {
                self.rules.push(Rule {
                    resource: resource.clone(),
                    effect,
                    condition: condition(),
                    inferred: false,
                });
            }
            if let Some(rate) = rate {
                self.rules.push(Rule {
                    resource,
                    effect: RuleEffect::Budget(rate),
                    condition: condition(),
                    inferred: false,
                });
            }
            // The current compiler ignores global '*' domain overrides.
            if agent.is_none()
                && pattern != "*"
                && (config.contains_key("bypass") || config.contains_key("addons"))
            {
                let entry = parse_override(pattern, config)?;
                if let Some(existing) = self
                    .domains
                    .iter_mut()
                    .find(|entry| entry.pattern == *pattern)
                {
                    *existing = entry;
                } else {
                    self.domains.push(entry);
                }
            }
            if let Some(rules) = config.get("rules")
                && agent.is_none()
            {
                self.compile_iam(rules, true)?;
            }
        }
        Ok(())
    }

    fn compile_iam(&mut self, permissions: &Value, host_compiled: bool) -> Result<()> {
        for value in permissions
            .as_array()
            .ok_or_else(|| invalid("permissions must be an array"))?
        {
            let rule = object(value, "permission")?;
            match rule.get("action").and_then(Value::as_str) {
                Some("network:request") => {}
                Some(
                    "credential:use"
                    | "file:read"
                    | "file:write"
                    | "subprocess:exec"
                    | "gateway:risky_route"
                    | "gateway:request",
                ) => continue,
                _ => return Err(invalid("unknown or missing permission action")),
            }
            let resource = string(
                rule.get("resource")
                    .ok_or_else(|| invalid("network permission needs resource"))?,
                "resource",
            )?
            .to_owned();
            let effect = if rule.get("effect").and_then(Value::as_str) == Some("budget") {
                RuleEffect::Budget(positive_integer(
                    rule.get("budget")
                        .ok_or_else(|| invalid("budget effect requires budget"))?,
                    "budget",
                )?)
            } else {
                rule.get("effect")
                    .map(egress_effect)
                    .transpose()?
                    .unwrap_or(RuleEffect::Allow)
            };
            let inferred = match rule
                .get("tier")
                .and_then(Value::as_str)
                .unwrap_or("explicit")
            {
                "explicit" => false,
                "inferred" => true,
                _ => return Err(invalid("invalid permission tier")),
            };
            let mut condition = Condition::default();
            if let Some(value) = rule.get("condition").filter(|value| !value.is_null()) {
                let fields = object(value, "condition")?;
                // Host compilation extracts empty-condition exact rules into
                // simple sets before validation; hand-authored IAM retains them.
                condition.present = !host_compiled || !fields.is_empty();
                for (key, value) in fields {
                    if value.is_null() {
                        continue;
                    }
                    match key.as_str() {
                        "agent" => condition.agent = Some(string(value, key)?.to_owned()),
                        "method" => condition.methods = Some(string_list(value, key)?),
                        "path_prefix" => {
                            condition.path_prefix = Some(string(value, key)?.to_owned())
                        }
                        "port" => {
                            let values = value
                                .as_array()
                                .cloned()
                                .unwrap_or_else(|| vec![value.clone()]);
                            if values.is_empty() {
                                return Err(invalid("port list must not be empty"));
                            }
                            condition.ports = Some(
                                values
                                    .iter()
                                    .map(|value| {
                                        let port = positive_integer(value, "port")?;
                                        u16::try_from(port)
                                            .map_err(|_| invalid("port must be from 1 to 65535"))
                                    })
                                    .collect::<Result<Vec<_>>>()?,
                            );
                        }
                        _ => {
                            return Err(unsupported(format!(
                                "native network condition is not implemented: {key}"
                            )));
                        }
                    }
                }
            }
            self.rules.push(Rule {
                resource,
                effect,
                condition,
                inferred,
            });
        }
        Ok(())
    }

    fn matching(&self, request: &NetworkRequest<'_>, resource: &str) -> Option<&Rule> {
        let matches = |rule: &&Rule, agent: bool, exact: bool, port_only: bool| {
            !rule.inferred
                && rule.exact() == exact
                && rule.condition.agent.is_some() == agent
                && (!port_only || rule.condition.ports.is_some())
                && (if exact {
                    rule.resource == resource
                } else {
                    resource_matches(resource, &rule.resource)
                })
                && rule.condition.matches(request)
        };
        if request.agent.is_some_and(|agent| !agent.is_empty()) {
            if let Some(rule) = self
                .rules
                .iter()
                .find(|rule| matches(rule, true, true, false))
            {
                return Some(rule);
            }
            if let Some(rule) = self
                .rules
                .iter()
                .find(|rule| matches(rule, true, false, false))
            {
                return Some(rule);
            }
        }
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| matches(rule, false, true, true))
        {
            return Some(rule);
        }
        for effect in [Effect::Deny, Effect::Prompt, Effect::Allow] {
            if let Some(rule) = self.rules.iter().find(|rule| {
                rule.simple() && rule.resource == resource && effect_of(rule.effect) == effect
            }) {
                return Some(rule);
            }
        }
        self.rules
            .iter()
            .find(|rule| !rule.simple() && matches(rule, false, true, false))
            .or_else(|| {
                self.rules
                    .iter()
                    .find(|rule| matches(rule, false, false, false))
            })
    }

    /// `now_ms` is epoch milliseconds; a lookup with consume=false changes no state.
    pub fn evaluate(
        &self,
        request: NetworkRequest<'_>,
        now_ms: f64,
        consume: bool,
    ) -> Result<Decision> {
        if request.port == Some(0) {
            return Err(invalid("port must be from 1 to 65535"));
        }
        if !now_ms.is_finite() {
            return Err(invalid("budget timestamp must be finite"));
        }
        let Some(rule) = self
            .matching(&request, &format!("{}/*", request.host))
            .or_else(|| self.matching(&request, "*"))
        else {
            return Ok(Decision {
                effect: Effect::Deny,
                matched_resource: None,
                budget_remaining: None,
            });
        };
        let mut decision = Decision {
            effect: effect_of(rule.effect),
            matched_resource: Some(rule.resource.clone()),
            budget_remaining: None,
        };
        if !matches!(rule.effect, RuleEffect::Allow | RuleEffect::Budget(_)) {
            return Ok(decision);
        }
        let action = if request.method.eq_ignore_ascii_case("CONNECT") {
            "network:connect"
        } else {
            "network:request"
        };
        let mut limits = Vec::new();
        if let RuleEffect::Budget(rate) = rule.effect {
            let host = if rule.condition.ports.is_some() {
                let port = request.port.expect("matched port condition");
                if request.host.contains(':') {
                    format!("[{}]:{port}", request.host)
                } else {
                    format!("{}:{port}", request.host)
                }
            } else {
                request.host.to_owned()
            };
            limits.push((format!("{action}:{host}"), rate));
        }
        if let Some(rate) = self.global_budget {
            limits.push((format!("{action}:__global__"), rate));
        }
        if limits.is_empty() {
            return Ok(decision);
        }
        let mut budgets = self
            .budgets
            .lock()
            .map_err(|_| invalid("budget state lock poisoned"))?;
        let mut planned = HashMap::new();
        let mut remaining = u64::MAX;
        for (key, rate) in limits {
            let tat = *planned
                .get(&key)
                .or_else(|| budgets.get(&key))
                .unwrap_or(&now_ms);
            let interval = 60000.0 / rate as f64;
            let burst = (rate / 10).max(1);
            let offset = interval * burst as f64;
            if now_ms < tat - offset {
                decision.effect = Effect::BudgetExceeded;
                decision.budget_remaining = Some(0);
                return Ok(decision);
            }
            let new_tat = tat.max(now_ms) + interval;
            let left = ((now_ms - (new_tat - offset)) / interval)
                .trunc()
                .max(0.0)
                .min(burst as f64) as u64;
            remaining = remaining.min(left);
            planned.insert(key, new_tat);
        }
        if consume {
            budgets.extend(planned);
        }
        decision.budget_remaining = Some(remaining);
        Ok(decision)
    }

    /// Mirrors the separate existing addon-enable query without changing the
    /// network decision or implementing warn/block mode. Required addons resist
    /// configured bypasses as in the existing engine.
    pub fn network_guard_enabled(&self, request: NetworkRequest<'_>) -> bool {
        for entry in &self.domains {
            if host_matches(request.host, &entry.pattern) && entry.bypass {
                return self.required;
            }
        }
        if let Some(agent) = request.agent {
            for entry in &self.clients {
                if client_matches(agent, &entry.pattern)
                    && (entry.bypass || entry.enabled == Some(false))
                {
                    return self.required;
                }
            }
        }
        let mut enabled = self.enabled;
        for entry in &self.domains {
            if host_matches(request.host, &entry.pattern)
                && let Some(value) = entry.enabled
            {
                enabled = value;
            }
        }
        enabled
    }
}

fn effect_of(effect: RuleEffect) -> Effect {
    match effect {
        RuleEffect::Allow | RuleEffect::Budget(_) => Effect::Allow,
        RuleEffect::Deny => Effect::Deny,
        RuleEffect::Prompt => Effect::Prompt,
    }
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{field} must be a table")))
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| invalid(format!("{field} must be a string")))
}
fn string_list(value: &Value, field: &str) -> Result<Vec<String>> {
    if let Some(value) = value.as_str() {
        return Ok(vec![value.into()]);
    }
    value
        .as_array()
        .ok_or_else(|| invalid(format!("{field} must be a string or list")))?
        .iter()
        .map(|value| string(value, field).map(str::to_owned))
        .collect()
}
fn positive_integer(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(format!("{field} must be a positive integer")))
}
fn egress_effect(value: &Value) -> Result<RuleEffect> {
    match value.as_str() {
        Some("allow") => Ok(RuleEffect::Allow),
        Some("deny") => Ok(RuleEffect::Deny),
        Some("prompt") => Ok(RuleEffect::Prompt),
        _ => Err(invalid("network egress must be allow, deny or prompt")),
    }
}

fn parse_document(source: &str, format: Format) -> Result<Map<String, Value>> {
    let value: Value = match format {
        Format::Json => serde_json::from_str(source).map_err(|error| invalid(error.to_string()))?,
        Format::Yaml => {
            let mut yaml: serde_yaml_ng::Value =
                serde_yaml_ng::from_str(source).map_err(|error| invalid(error.to_string()))?;
            merge_yaml(&mut yaml)?;
            serde_json::to_value(yaml).map_err(|error| invalid(error.to_string()))?
        }
        Format::Toml => toml::from_str(source).map_err(|error| invalid(error.to_string()))?,
    };
    let mut document = if value.is_null() && matches!(format, Format::Yaml) {
        Map::new()
    } else {
        object(&value, "policy document")?.clone()
    };
    if matches!(format, Format::Toml) {
        if document.contains_key("budget") && document.contains_key("global_budget") {
            return Err(invalid("budget and global_budget are the same field"));
        }
        if let Some(value) = document.remove("budget") {
            document.insert("global_budget".into(), value);
        }
        if let Some(hosts) = document.get_mut("hosts") {
            normalize_hosts(hosts)?;
        }
        if let Some(agents) = document.get_mut("agents") {
            for config in agents
                .as_object_mut()
                .ok_or_else(|| invalid("agents must be a table"))?
                .values_mut()
            {
                if let Some(hosts) = config.get_mut("hosts") {
                    normalize_hosts(hosts)?;
                }
            }
        }
    }
    Ok(document)
}

/// PyYAML inserts merged rules before local rules. serde_yaml_ng::apply_merge
/// inserts them afterwards, changing equal-specificity policy precedence.
fn merge_yaml(value: &mut serde_yaml_ng::Value) -> Result<()> {
    use serde_yaml_ng::{Mapping, Value as Yaml};
    match value {
        Yaml::Mapping(mapping) => {
            for child in mapping.values_mut() {
                merge_yaml(child)?;
            }
            if let Some(inherited) = mapping.remove("<<") {
                let mut merged = Mapping::new();
                match inherited {
                    Yaml::Mapping(parent) => merged = parent,
                    Yaml::Sequence(parents) => {
                        // In a merge sequence the first mapping takes precedence.
                        for parent in parents.into_iter().rev() {
                            let Yaml::Mapping(parent) = parent else {
                                return Err(invalid("YAML merge requires mappings"));
                            };
                            for (key, value) in parent {
                                merged.insert(key, value);
                            }
                        }
                    }
                    _ => return Err(invalid("YAML merge requires a mapping or mapping list")),
                }
                for (key, value) in std::mem::take(mapping) {
                    merged.insert(key, value);
                }
                *mapping = merged;
            }
        }
        Yaml::Sequence(sequence) => {
            for value in sequence {
                merge_yaml(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_hosts(hosts: &mut Value) -> Result<()> {
    for config in hosts
        .as_object_mut()
        .ok_or_else(|| invalid("hosts must be a table"))?
        .values_mut()
    {
        if let Some(fields) = config.as_object_mut() {
            // Preserve source-order assignment when both aliases exist, as normalize() does.
            let source = std::mem::take(fields);
            for (key, value) in source {
                fields.insert(
                    match key.as_str() {
                        "rate" => "rate_limit".into(),
                        "allow" => "credentials".into(),
                        "unknown_creds" => "unknown_credentials".into(),
                        _ => key,
                    },
                    value,
                );
            }
        }
    }
    Ok(())
}

fn split_destination(pattern: &str) -> Result<(String, Option<u16>)> {
    if !pattern.contains(':') {
        return Ok((pattern.into(), None));
    }
    let (host, port) = if let Some(rest) = pattern.strip_prefix('[')
        && let Some((host, port)) = rest.split_once("]:")
    {
        (
            host.parse::<Ipv6Addr>()
                .map_err(|_| invalid("invalid IPv6 endpoint"))?
                .to_string(),
            port,
        )
    } else if pattern.matches(':').count() == 1 {
        let (host, port) = pattern.rsplit_once(':').unwrap();
        (host.into(), port)
    } else {
        pattern
            .parse::<Ipv6Addr>()
            .map_err(|_| invalid("invalid IPv6 host"))?;
        return Ok((pattern.into(), None));
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("destination must be host:port or [IPv6]:port"));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| invalid("port must be from 1 to 65535"))?;
    Ok((host, Some(port)))
}

fn network_enabled(addons: Option<&Value>) -> Result<Option<bool>> {
    let Some(addons) = addons else {
        return Ok(None);
    };
    let Some(network) = object(addons, "addons")?.get("network_guard") else {
        return Ok(None);
    };
    let value = object(network, "network_guard")?.get("enabled");
    value
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid("addon enabled must be boolean"))
        })
        .transpose()
        .map(|enabled| Some(enabled.unwrap_or(true)))
}
fn parse_override(pattern: &str, fields: &Map<String, Value>) -> Result<Override> {
    Ok(Override {
        pattern: pattern.into(),
        bypass: fields
            .get("bypass")
            .map(|value| {
                string_list(value, "bypass")
                    .map(|values| values.iter().any(|value| value == "network_guard"))
            })
            .transpose()?
            .unwrap_or(false),
        enabled: network_enabled(fields.get("addons"))?,
    })
}
fn overrides(value: Option<&Value>) -> Result<Vec<Override>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    object(value, "overrides")?
        .iter()
        .map(|(pattern, value)| parse_override(pattern, object(value, "override")?))
        .collect()
}
fn host_matches(host: &str, pattern: &str) -> bool {
    let (host, pattern) = (host.to_lowercase(), pattern.to_lowercase());
    pattern
        .strip_prefix("*.")
        .map_or(host == pattern, |suffix| {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        })
}
fn client_matches(client: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        host_matches(client, pattern)
    } else {
        glob(&client.to_lowercase(), &pattern.to_lowercase())
    }
}
fn resource_matches(resource: &str, pattern: &str) -> bool {
    let (resource, pattern) = (resource.to_lowercase(), pattern.to_lowercase());
    glob(&resource, &pattern)
        || (pattern.contains("**")
            && resource == pattern.trim_end_matches('*').trim_end_matches('/'))
}

/// Python fnmatch semantics for network resource/agent globs: '*' crosses '/',
/// '?' matches one character, and bracket classes support ranges/negation.
fn glob(value: &str, pattern: &str) -> bool {
    let value: Vec<char> = value.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let token = pattern[index];
        let mut next = vec![false; value.len() + 1];
        if token == '*' {
            next[0] = previous[0];
            for position in 1..=value.len() {
                next[position] = previous[position] || next[position - 1];
            }
        } else {
            let class = if token == '[' {
                character_class(&pattern, index)
            } else {
                None
            };
            for position in 1..=value.len() {
                let matches = match &class {
                    Some((end, negate, start)) => {
                        let mut found = false;
                        let mut cursor = *start;
                        while cursor < *end {
                            if cursor + 2 < *end && pattern[cursor + 1] == '-' {
                                found |= pattern[cursor] <= value[position - 1]
                                    && value[position - 1] <= pattern[cursor + 2];
                                cursor += 3;
                            } else {
                                found |= value[position - 1] == pattern[cursor];
                                cursor += 1;
                            }
                        }
                        found != *negate
                    }
                    None => token == '?' || token == value[position - 1],
                };
                next[position] = previous[position - 1] && matches;
            }
            if let Some((end, _, _)) = class {
                index = end;
            }
        }
        previous = next;
        index += 1;
    }
    previous[value.len()]
}
fn character_class(pattern: &[char], index: usize) -> Option<(usize, bool, usize)> {
    let mut start = index + 1;
    let negate = pattern.get(start) == Some(&'!');
    if negate {
        start += 1;
    }
    let mut end = start;
    if pattern.get(end) == Some(&']') {
        end += 1;
    }
    while end < pattern.len() && pattern[end] != ']' {
        end += 1;
    }
    (end < pattern.len()).then_some((end, negate, start))
}
