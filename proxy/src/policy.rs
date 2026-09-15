//! Native network-policy evaluation under development; not selected by the proxy.
//!
//! Decisions mirror PolicyEngine.evaluate_request, including its existing exact
//! index case sensitivity, shared host budgets and separate CONNECT counters.
//! Credential/service permissions and addon enforcement are outside this API.
//! File-backed host lists and IAM task overlays retain production precedence.
//! All network conditions use the context actually supplied by evaluate_request;
//! this API does not claim to validate credential or service policy schemas.
//! Expiry is applied at load/reload, including the intentional agent-host expiry
//! fix; reaching a deadline alone does not schedule a reload.

use std::{
    collections::HashMap,
    fmt,
    net::Ipv6Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

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

#[derive(Clone, Debug)]
struct Condition {
    present: bool,
    agent: Option<String>,
    ports: Option<Vec<u16>>,
    methods: Option<Vec<String>>,
    path_prefix: Option<String>,
    other_context_matches: bool,
}

impl Default for Condition {
    fn default() -> Self {
        Self {
            present: false,
            agent: None,
            ports: None,
            methods: None,
            path_prefix: None,
            other_context_matches: true,
        }
    }
}

impl Condition {
    fn matches(&self, request: &NetworkRequest<'_>) -> bool {
        self.other_context_matches
            && self
                .agent
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Default, Debug)]
struct Override {
    pattern: String,
    bypass: bool,
    enabled: Option<bool>,
}

/// One network rule representation and one atomic GCRA state map.
#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<Rule>,
    global_budget: Option<u64>,
    budgets: Arc<Mutex<HashMap<String, f64>>>,
    required: bool,
    enabled: bool,
    domains: Vec<Override>,
    clients: Vec<Override>,
    task: Option<TaskPolicy>,
}

#[derive(Clone, Debug)]
struct TaskPolicy {
    rules: Vec<Rule>,
    global_budget: Option<u64>,
    domains: Vec<Override>,
    enabled: Option<bool>,
    path: Option<PathBuf>,
}

impl Policy {
    pub fn parse(source: &str, format: Format) -> Result<Self> {
        Self::parse_at(source, format, current_time_ms())
    }

    pub fn parse_at(source: &str, format: Format, now_ms: f64) -> Result<Self> {
        let mut document = parse_document(source, format)?;
        prune_document(&mut document, now_ms)?;
        Self::from_document(document, None)
    }

    /// Reloaded rule snapshots keep the same host/global budget counters.
    pub fn reload_from_source_at(&self, source: &str, format: Format, now_ms: f64) -> Result<Self> {
        let mut replacement = Self::parse_at(source, format, now_ms)?;
        replacement.budgets = self.budgets.clone();
        replacement.task = self.task.clone();
        Ok(replacement)
    }

    /// File-backed reload also rereads sibling addon defaults. This read-only
    /// loader does not acquire the approval transaction's file lock.
    pub fn reload_from_path_at(&self, path: &Path, now_ms: f64) -> Result<Self> {
        let mut replacement = Self::from_path_at(path, now_ms)?;
        replacement.budgets = self.budgets.clone();
        replacement.task = self.task.clone();
        Ok(replacement)
    }

    /// Task loading uses the shipped IAM schema. Host-centric task keys are
    /// ignored by Python's UnifiedPolicy loader and are not compiled here.
    pub fn with_task_source(&self, source: &str, format: Format) -> Result<Self> {
        let mut document = parse_document(source, format)?;
        for key in ["hosts", "agents", "lists", "global_budget"] {
            document.shift_remove(key);
        }
        let enabled = network_enabled(document.get("addons"))?;
        let task = Self::from_document(document, None)?;
        let mut replacement = self.clone();
        replacement.task = Some(TaskPolicy {
            rules: task.rules,
            global_budget: task.global_budget,
            domains: task.domains,
            enabled,
            path: None,
        });
        Ok(replacement)
    }

    pub fn with_task_path(&self, path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path).map_err(|error| PolicyError {
            kind: ErrorKind::Read,
            message: error.to_string(),
        })?;
        let format = match path.extension().and_then(|value| value.to_str()) {
            Some("toml") => Format::Toml,
            Some("yaml" | "yml") => Format::Yaml,
            _ => Format::Json,
        };
        let mut replacement = self.with_task_source(&source, format)?;
        replacement.task.as_mut().expect("task was loaded").path = Some(path.to_owned());
        Ok(replacement)
    }

    /// Reload the task independently, matching the production loader's separate
    /// baseline/task success boundaries. An error leaves this snapshot valid.
    pub fn reload_task(&self) -> Result<Self> {
        match self.task.as_ref().and_then(|task| task.path.as_deref()) {
            Some(path) => self.with_task_path(path),
            None => Ok(self.clone()),
        }
    }

    pub fn without_task(&self) -> Self {
        let mut replacement = self.clone();
        replacement.task = None;
        replacement
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        Self::from_path_at(path, current_time_ms())
    }

    pub fn from_path_at(path: &Path, now_ms: f64) -> Result<Self> {
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
        // Production expires baseline entries before merging addon defaults or
        // opening list files, so an expired reference cannot require its file.
        prune_document(&mut document, now_ms)?;
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
        Self::from_document(document, path.parent())
    }

    fn from_document(
        mut document: Map<String, Value>,
        list_base_dir: Option<&Path>,
    ) -> Result<Self> {
        expand_lists(&mut document, list_base_dir)?;
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
            budgets: Arc::new(Mutex::new(HashMap::new())),
            required: false,
            enabled: true,
            domains: Vec::new(),
            clients: Vec::new(),
            task: None,
        };
        policy.required = document
            .get("required")
            .map(|value| {
                string_array(value, "required")
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
            if agent.is_some()
                && config
                    .get("bypass")
                    .map(|value| {
                        string_array(value, "bypass")
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
                    .any(|key| !matches!(key.as_str(), "egress" | "rate_limit" | "expires"))
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
                .map(|value| string(value, "tier"))
                .transpose()?
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
                        "credential" => {
                            condition.other_context_matches &=
                                string_list(value, key)?.iter().any(|pattern| {
                                    !pattern.starts_with("hmac:") && client_matches(":x", pattern)
                                });
                        }
                        "content_type" => {
                            condition.other_context_matches &= string(value, key)?.is_empty()
                        }
                        "tactics" | "enables" => {
                            string_array(value, key)?;
                            condition.other_context_matches = false;
                        }
                        "irreversible" => {
                            condition.other_context_matches &= !boolean(value, "irreversible")?
                        }
                        "account" => {
                            condition.other_context_matches &=
                                string_list(value, key)?.iter().any(String::is_empty)
                        }
                        "service" | "capability" => {
                            condition.other_context_matches &= glob("", string(value, key)?)
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
        let task = self
            .task
            .as_ref()
            .map_or(&[][..], |task| task.rules.as_slice());
        let task_exact = task
            .iter()
            .any(|rule| rule.exact() && !rule.simple() && rule.resource == resource);
        let candidates = || {
            task.iter().chain(self.rules.iter().filter(|rule| {
                !(task_exact && rule.exact() && !rule.simple() && rule.resource == resource)
            }))
        };
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
            if let Some(rule) = candidates().find(|rule| matches(rule, true, true, false)) {
                return Some(rule);
            }
            if let Some(rule) = candidates().find(|rule| matches(rule, true, false, false)) {
                return Some(rule);
            }
        }
        if let Some(rule) = candidates().find(|rule| matches(rule, false, true, true)) {
            return Some(rule);
        }
        for effect in [Effect::Deny, Effect::Prompt, Effect::Allow] {
            if let Some(rule) = candidates().find(|rule| {
                rule.simple() && rule.resource == resource && effect_of(rule.effect) == effect
            }) {
                return Some(rule);
            }
        }
        candidates()
            .find(|rule| !rule.simple() && matches(rule, false, true, false))
            .or_else(|| candidates().find(|rule| matches(rule, false, false, false)))
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
        let global_budget = match (
            self.global_budget,
            self.task.as_ref().and_then(|task| task.global_budget),
        ) {
            (Some(baseline), Some(task)) => Some(baseline.min(task)),
            (baseline, task) => baseline.or(task),
        };
        if let Some(rate) = global_budget {
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
        if let Some(task) = &self.task {
            for entry in &task.domains {
                if host_matches(request.host, &entry.pattern) && entry.bypass {
                    return self.required;
                }
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
        if let Some(task_enabled) = self.task.as_ref().and_then(|task| task.enabled) {
            enabled = self.required || task_enabled;
        }
        enabled
    }
}

fn prune_document(document: &mut Map<String, Value>, now_ms: f64) -> Result<()> {
    for (agent, host) in expired_host_entries(&Value::Object(document.clone()), now_ms)? {
        let hosts = match agent {
            Some(agent) => document
                .get_mut("agents")
                .and_then(|agents| agents.get_mut(&agent))
                .and_then(|agent| agent.get_mut("hosts")),
            None => document.get_mut("hosts"),
        };
        if let Some(hosts) = hosts.and_then(Value::as_object_mut) {
            hosts.shift_remove(&host);
        }
    }
    Ok(())
}

/// Existing lists are local files. URL-looking values are filenames too: the
/// production loader does not fetch remote lists or introduce another egress.
fn expand_lists(document: &mut Map<String, Value>, base_dir: Option<&Path>) -> Result<()> {
    let Some(lists) = document
        .get("lists")
        .and_then(Value::as_object)
        .filter(|lists| !lists.is_empty())
        .cloned()
    else {
        return Ok(());
    };
    let Some(hosts) = document.get_mut("hosts").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    let references: Vec<_> = hosts
        .iter()
        .filter_map(|(host, config)| {
            host.strip_prefix('$')
                .map(|name| (host.clone(), name.to_owned(), config.clone()))
        })
        .collect();
    if !references.is_empty() && base_dir.is_none() {
        return Err(unsupported("host lists require file-backed policy loading"));
    }
    for (_, name, _) in &references {
        if !lists.contains_key(name) {
            return Err(invalid(format!("undefined list reference ${name}")));
        }
    }
    for (host, name, config) in references {
        let path = Path::new(string(&lists[&name], "list path")?);
        let path = if path.is_absolute() {
            path.to_owned()
        } else {
            base_dir
                .ok_or_else(|| {
                    unsupported("relative host lists require file-backed policy loading")
                })?
                .join(path)
        };
        let source = std::fs::read_to_string(&path).map_err(|error| PolicyError {
            kind: ErrorKind::Read,
            message: format!(
                "failed to read list {} referenced by ${name}: {error}",
                path.display()
            ),
        })?;
        let config = if config.is_null() {
            Value::Object(Map::new())
        } else {
            object(&config, "list host configuration")?;
            config
        };
        hosts.shift_remove(&host);
        for line in source.split([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ]) {
            let mut entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            let parts: Vec<_> = entry.split_whitespace().collect();
            if parts.len() >= 2
                && (matches!(parts[0], "0.0.0.0" | "127.0.0.1" | "255.255.255.255")
                    || parts[0].starts_with([':', 'f']))
            {
                entry = parts[1];
            }
            if matches!(
                entry,
                "0.0.0.0"
                    | "127.0.0.1"
                    | "localhost"
                    | "localhost.localdomain"
                    | "local"
                    | "broadcasthost"
            ) || !entry.contains('.')
            {
                continue;
            }
            hosts
                .entry(entry.to_owned())
                .or_insert_with(|| config.clone());
        }
    }
    Ok(())
}

fn current_time_ms() -> f64 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1_000_000.0
}

pub(crate) fn expired_host_entries(
    document: &Value,
    now_ms: f64,
) -> Result<Vec<(Option<String>, String)>> {
    if !now_ms.is_finite() {
        return Err(invalid("expiry timestamp must be finite"));
    }
    let mut expired = Vec::new();
    let mut scan = |hosts: Option<&Value>, agent: Option<&str>| {
        if let Some(hosts) = hosts.and_then(Value::as_object) {
            for (host, config) in hosts {
                let Some(value) = config.get("expires").filter(|value| !value.is_null()) else {
                    continue;
                };
                let expiry = value.as_str().and_then(parse_expiry);
                match expiry {
                    Some(expiry)
                        if expiry.unix_timestamp_nanos() as f64 / 1_000_000.0 <= now_ms =>
                    {
                        expired.push((agent.map(str::to_owned), host.clone()))
                    }
                    Some(_) => {}
                    None => eprintln!(
                        "policy host {host:?} has an invalid expires value; keeping the entry"
                    ),
                }
            }
        }
    };
    scan(document.get("hosts"), None);
    if let Some(agents) = document.get("agents").and_then(Value::as_object) {
        for (agent, config) in agents {
            scan(config.get("hosts"), Some(agent));
        }
    }
    Ok(expired)
}

/// The calendar/week dates, basic/extended times, arbitrary date separator,
/// fractional seconds and UTC offsets accepted by datetime.fromisoformat.
/// Invalid values remain unexpired, matching the existing loader's warning path.
pub(crate) fn parse_expiry(value: &str) -> Option<time::OffsetDateTime> {
    use time::{Duration, Time, UtcOffset};
    let (date, clock) = expiry_parts(value)?;
    let Some(clock) = clock else {
        return Some(date.midnight().assume_utc());
    };
    let zone = clock
        .char_indices()
        .find(|(_, character)| matches!(character, '+' | '-' | 'Z'));
    let (clock, offset_ns) = match zone {
        Some((index, 'Z')) if index + 1 == clock.len() => (&clock[..index], 0),
        Some((index, sign @ ('+' | '-'))) => (
            &clock[..index],
            clock_nanoseconds(&clock[index + 1..], true)? * if sign == '-' { -1 } else { 1 },
        ),
        Some(_) => return None,
        None => (clock, 0),
    };
    // CPython treats an offset with zero whole seconds as UTC, ignoring its
    // fractional part. Retain that existing timestamp interpretation.
    let offset_ns = if offset_ns.abs() < 1_000_000_000 {
        0
    } else {
        offset_ns
    };
    let clock_ns = clock_nanoseconds(clock, false)?;
    let hour = (clock_ns / 3_600_000_000_000) as u8;
    let minute = (clock_ns / 60_000_000_000 % 60) as u8;
    let second = (clock_ns / 1_000_000_000 % 60) as u8;
    let micros = (clock_ns % 1_000_000_000 / 1000) as u32;
    let datetime = date.with_time(Time::from_hms_micro(hour, minute, second, micros).ok()?);
    if offset_ns % 1_000_000_000 == 0 {
        let offset = UtcOffset::from_whole_seconds((offset_ns / 1_000_000_000) as i32).ok()?;
        Some(datetime.assume_offset(offset))
    } else {
        datetime
            .assume_utc()
            .checked_sub(Duration::nanoseconds_i128(offset_ns))
    }
}

pub(crate) fn expiry_has_offset(value: &str) -> bool {
    expiry_parts(value)
        .is_some_and(|(_, clock)| clock.is_some_and(|clock| clock.contains(['+', '-', 'Z'])))
}

fn expiry_parts(value: &str) -> Option<(time::Date, Option<&str>)> {
    use time::{Date, format_description::well_known::Iso8601};
    let bytes = value.as_bytes();
    if bytes.len() < 7 {
        return None;
    }
    let (length, week_without_day) = if bytes.get(4) == Some(&b'-') && bytes.get(5) == Some(&b'W') {
        if bytes.get(8) == Some(&b'-') && bytes.get(9).is_some_and(u8::is_ascii_digit) {
            (10, false)
        } else {
            (8, true)
        }
    } else if bytes.get(4) == Some(&b'W') {
        if bytes.get(7).is_some_and(u8::is_ascii_digit) {
            (8, false)
        } else {
            (7, true)
        }
    } else if bytes.get(4) == Some(&b'-') {
        (10, false)
    } else {
        (8, false)
    };
    let date = value.get(..length)?;
    let date = if week_without_day {
        format!("{date}{}", if date.contains('-') { "-1" } else { "1" })
    } else {
        date.to_owned()
    };
    let date = Date::parse(&date, &Iso8601::DEFAULT).ok()?;
    let remaining = value.get(length..)?;
    if remaining.is_empty() {
        return Some((date, None));
    }
    let separator = remaining.chars().next()?;
    let clock = &remaining[separator.len_utf8()..];
    Some((date, Some(clock)))
}

fn clock_nanoseconds(value: &str, offset: bool) -> Option<i128> {
    let (whole, fraction) = value.find(['.', ',']).map_or((value, None), |index| {
        (&value[..index], Some(&value[index + 1..]))
    });
    let parts: Vec<&str> = if whole.contains(':') {
        whole.split(':').collect()
    } else {
        if !matches!(whole.len(), 2 | 4 | 6) || !whole.is_ascii() {
            return None;
        }
        (0..whole.len())
            .step_by(2)
            .map(|index| &whole[index..index + 2])
            .collect()
    };
    if parts.is_empty()
        || parts.len() > 3
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let hour = parts[0].parse::<i128>().ok()?;
    let minute = parts
        .get(1)
        .map_or(Some(0), |value| value.parse::<i128>().ok())?;
    let second = parts
        .get(2)
        .map_or(Some(0), |value| value.parse::<i128>().ok())?;
    let seconds = hour * 3600 + minute * 60 + second;
    if (offset && seconds >= 86400) || (!offset && (hour >= 24 || minute >= 60 || second >= 60)) {
        return None;
    }
    let micros = match fraction {
        None => 0,
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            let count = value.len().min(6);
            value[..count].parse::<i128>().ok()? * 10i128.pow((6 - count) as u32)
        }
        Some(_) => return None,
    };
    Some(seconds * 1_000_000_000 + micros * 1000)
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
fn string_array(value: &Value, field: &str) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| invalid(format!("{field} must be an array")))?
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

/// Resolve typed TOML datetimes before converting to JSON. An authored table
/// resembling serde's private datetime marker must remain an invalid expiry.
pub(crate) fn parse_toml_document(source: &str) -> Result<Value> {
    let syntax = source
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| invalid(error.to_string()))?;
    // Build structure from syntax nodes, never serde's private marker transport.
    let mut document = Value::Object(
        syntax
            .iter()
            .map(|(key, item)| Ok((key.to_owned(), toml_item(item)?)))
            .collect::<Result<Map<_, _>>>()?,
    );
    let normalize = |syntax: Option<&toml_edit::Item>, hosts: Option<&mut Value>| {
        if let (Some(syntax), Some(hosts)) = (
            syntax.and_then(toml_edit::Item::as_table_like),
            hosts.and_then(Value::as_object_mut),
        ) {
            for (name, config) in syntax.iter() {
                if let Some(date) = config
                    .as_table_like()
                    .and_then(|config| config.get("expires"))
                    .and_then(toml_edit::Item::as_datetime)
                    && date.date.is_some()
                    && date.time.is_some()
                    && let Some(expiry) =
                        hosts.get_mut(name).and_then(|host| host.get_mut("expires"))
                {
                    *expiry = Value::String(date.to_string());
                }
            }
        }
    };
    normalize(syntax.get("hosts"), document.get_mut("hosts"));
    if let Some(agents) = syntax
        .get("agents")
        .and_then(toml_edit::Item::as_table_like)
    {
        for (name, agent) in agents.iter() {
            normalize(
                agent.as_table_like().and_then(|agent| agent.get("hosts")),
                document
                    .get_mut("agents")
                    .and_then(|agents| agents.get_mut(name))
                    .and_then(|agent| agent.get_mut("hosts")),
            );
        }
    }
    Ok(document)
}

fn toml_item(item: &toml_edit::Item) -> Result<Value> {
    match item {
        toml_edit::Item::None => Ok(Value::Null),
        toml_edit::Item::Value(value) => toml_value(value),
        toml_edit::Item::Table(table) => table
            .iter()
            .map(|(key, value)| Ok((key.to_owned(), toml_item(value)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        toml_edit::Item::ArrayOfTables(tables) => tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .map(|(key, value)| Ok((key.to_owned(), toml_item(value)?)))
                    .collect::<Result<Map<_, _>>>()
                    .map(Value::Object)
            })
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

fn toml_value(value: &toml_edit::Value) -> Result<Value> {
    match value {
        toml_edit::Value::String(value) => Ok(Value::String(value.value().clone())),
        toml_edit::Value::Integer(value) => Ok(Value::from(*value.value())),
        toml_edit::Value::Float(value) => serde_json::Number::from_f64(*value.value())
            .map(Value::Number)
            .ok_or_else(|| unsupported("non-finite TOML numbers are unsupported")),
        toml_edit::Value::Boolean(value) => Ok(Value::Bool(*value.value())),
        toml_edit::Value::Datetime(value) => Ok(Value::Object(Map::from_iter([(
            "$__toml_private_datetime".into(),
            Value::String(value.value().to_string()),
        )]))),
        toml_edit::Value::Array(values) => values
            .iter()
            .map(toml_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        toml_edit::Value::InlineTable(table) => table
            .iter()
            .map(|(key, value)| Ok((key.to_owned(), toml_value(value)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
    }
}

/// Preserve source object structure with arbitrary precision numbers enabled.
/// Request bodies reject duplicates; operator policy files retain last-key-wins.
pub(crate) fn parse_json(source: &str, reject_duplicates: bool) -> serde_json::Result<Value> {
    json_value(source, reject_duplicates, 0)
}

fn json_value(source: &str, reject_duplicates: bool, depth: usize) -> serde_json::Result<Value> {
    use serde::de::{self, MapAccess, Visitor};
    use serde_json::value::RawValue;
    if depth > 128 {
        return Err(de::Error::custom("JSON nesting limit exceeded"));
    }
    match source.trim_start().as_bytes().first() {
        Some(b'{') => {
            struct ObjectVisitor {
                reject_duplicates: bool,
                depth: usize,
            }
            impl<'de> Visitor<'de> for ObjectVisitor {
                type Value = Value;
                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("JSON object")
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Value, A::Error> {
                    let mut object = Map::new();
                    while let Some((key, raw)) = map.next_entry::<String, Box<RawValue>>()? {
                        if self.reject_duplicates && object.contains_key(&key) {
                            return Err(de::Error::custom("duplicate JSON key"));
                        }
                        let value = json_value(raw.get(), self.reject_duplicates, self.depth + 1)
                            .map_err(de::Error::custom)?;
                        object.insert(key, value);
                    }
                    Ok(Value::Object(object))
                }
            }
            let mut deserializer = serde_json::Deserializer::from_str(source);
            let value = serde::Deserializer::deserialize_map(
                &mut deserializer,
                ObjectVisitor {
                    reject_duplicates,
                    depth,
                },
            )?;
            deserializer.end()?;
            Ok(value)
        }
        Some(b'[') => {
            let raw: Vec<Box<RawValue>> = serde_json::from_str(source)?;
            raw.iter()
                .map(|item| json_value(item.get(), reject_duplicates, depth + 1))
                .collect::<serde_json::Result<Vec<_>>>()
                .map(Value::Array)
        }
        _ => serde_json::from_str(source),
    }
}

/// One YAML frontend for native policy consumers. Event scalar styles and tags
/// preserve the distinctions erased by a generic JSON deserializer.
pub(crate) fn parse_yaml(source: &str) -> Result<Value> {
    use yaml_rust2::parser::{Event, Parser};
    let mut parser = Parser::new_from_str(source);
    let next = |parser: &mut Parser<std::str::Chars<'_>>| {
        parser
            .next_token()
            .map(|(event, _)| event)
            .map_err(|error| invalid(error.to_string()))
    };
    if next(&mut parser)? != Event::StreamStart {
        return Err(invalid("expected YAML stream"));
    }
    match next(&mut parser)? {
        Event::StreamEnd => return Ok(Value::Null),
        Event::DocumentStart => {}
        _ => return Err(invalid("expected YAML document")),
    }
    let value = yaml_node(&mut parser, &mut HashMap::new())?.0;
    if next(&mut parser)? != Event::DocumentEnd || next(&mut parser)? != Event::StreamEnd {
        return Err(invalid("policy YAML must contain one document"));
    }
    Ok(value)
}

fn yaml_node(
    parser: &mut yaml_rust2::parser::Parser<std::str::Chars<'_>>,
    anchors: &mut HashMap<usize, (Value, bool)>,
) -> Result<(Value, bool)> {
    use yaml_rust2::parser::Event;
    let (event, _) = parser
        .next_token()
        .map_err(|error| invalid(error.to_string()))?;
    let (anchor, result) = match event {
        Event::Scalar(value, style, anchor, tag) => {
            (anchor, yaml_scalar(&value, style, tag.as_ref())?)
        }
        Event::Alias(anchor) => {
            return anchors.get(&anchor).cloned().ok_or_else(|| {
                unsupported("recursive or unresolved YAML aliases are not supported")
            });
        }
        Event::SequenceStart(anchor, tag) => {
            yaml_collection_tag(tag.as_ref(), "seq")?;
            let mut values = Vec::new();
            while !matches!(
                parser.peek().map_err(|error| invalid(error.to_string()))?.0,
                Event::SequenceEnd
            ) {
                values.push(yaml_node(parser, anchors)?.0);
            }
            parser
                .next_token()
                .map_err(|error| invalid(error.to_string()))?;
            (anchor, (Value::Array(values), false))
        }
        Event::MappingStart(anchor, tag) => {
            yaml_collection_tag(tag.as_ref(), "map")?;
            let (mut merged, mut local) = (Map::new(), Vec::new());
            while !matches!(
                parser.peek().map_err(|error| invalid(error.to_string()))?.0,
                Event::MappingEnd
            ) {
                let (key, is_merge) = yaml_node(parser, anchors)?;
                let value = yaml_node(parser, anchors)?.0;
                if is_merge {
                    let parents = match value {
                        Value::Object(mapping) => vec![Value::Object(mapping)],
                        Value::Array(parents) => parents.into_iter().rev().collect(),
                        _ => return Err(invalid("YAML merge requires mappings")),
                    };
                    for parent in parents {
                        for (key, value) in object(&parent, "YAML merge")? {
                            merged.insert(key.clone(), value.clone());
                        }
                    }
                } else {
                    local.push((string(&key, "YAML mapping key")?.to_owned(), value));
                }
            }
            parser
                .next_token()
                .map_err(|error| invalid(error.to_string()))?;
            for (key, value) in local {
                merged.insert(key, value);
            }
            (anchor, (Value::Object(merged), false))
        }
        _ => return Err(invalid("unexpected YAML event")),
    };
    if anchor != 0 {
        anchors.insert(anchor, result.clone());
    }
    Ok(result)
}

fn yaml_collection_tag(tag: Option<&yaml_rust2::parser::Tag>, expected: &str) -> Result<()> {
    if let Some(tag) = tag
        && (tag.handle != "tag:yaml.org,2002:" || tag.suffix != expected)
    {
        return Err(unsupported("unsupported YAML collection tag"));
    }
    Ok(())
}

fn yaml_scalar(
    value: &str,
    style: yaml_rust2::scanner::TScalarStyle,
    tag: Option<&yaml_rust2::parser::Tag>,
) -> Result<(Value, bool)> {
    use yaml_rust2::scanner::TScalarStyle;
    let explicit = tag
        .map(|tag| {
            if tag.handle != "tag:yaml.org,2002:" {
                return Err(unsupported("unsupported YAML scalar tag"));
            }
            Ok(tag.suffix.as_str())
        })
        .transpose()?;
    if explicit == Some("str") || (explicit.is_none() && style != TScalarStyle::Plain) {
        return Ok((Value::String(value.into()), false));
    }
    if explicit == Some("merge") || (explicit.is_none() && value == "<<") {
        return Ok((Value::String(value.into()), true));
    }
    let normalized_boolean = if explicit == Some("bool") {
        value.to_lowercase()
    } else {
        value.to_owned()
    };
    let boolean = match normalized_boolean.as_str() {
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => Some(true),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => Some(false),
        _ => None,
    };
    if explicit == Some("bool") || (explicit.is_none() && boolean.is_some()) {
        return Ok((
            Value::Bool(boolean.ok_or_else(|| invalid("invalid YAML boolean"))?),
            false,
        ));
    }
    if explicit == Some("null")
        || (explicit.is_none() && matches!(value, "" | "~" | "null" | "Null" | "NULL"))
    {
        return Ok((Value::Null, false));
    }
    if explicit == Some("timestamp") || (explicit.is_none() && yaml_resolvers()[2].is_match(value))
    {
        return Ok((
            yaml_timestamp(value)?.ok_or_else(|| invalid("invalid YAML timestamp"))?,
            false,
        ));
    }
    if explicit == Some("int") || (explicit.is_none() && yaml_resolvers()[0].is_match(value)) {
        return Ok((yaml_integer(value)?, false));
    }
    let normalized = value.replace('_', "");
    if explicit == Some("float") || (explicit.is_none() && yaml_resolvers()[1].is_match(value)) {
        let (sign, number) = normalized
            .strip_prefix('-')
            .map_or((1., normalized.as_str()), |value| (-1., value));
        let number = number.strip_prefix('+').unwrap_or(number);
        if matches!(number.to_lowercase().as_str(), ".nan" | ".inf") {
            return Err(unsupported("non-finite YAML numbers are unsupported"));
        }
        let number = number
            .split(':')
            .try_fold(0., |total, part| {
                part.parse::<f64>().map(|part| total * 60. + part)
            })
            .map_err(|_| invalid("invalid YAML float"))?
            * sign;
        return Ok((
            serde_json::Number::from_f64(number)
                .map(Value::Number)
                .ok_or_else(|| unsupported("non-finite YAML numbers are unsupported"))?,
            false,
        ));
    }
    if explicit.is_some() {
        return Err(unsupported("unsupported YAML scalar tag"));
    }
    Ok((Value::String(value.into()), false))
}

/// PyYAML's published YAML1.1 scalar resolver grammars, applied only to decoded
/// scalar tokens from yaml-rust2; these never parse YAML document structure.
fn yaml_resolvers() -> &'static [regex::Regex; 3] {
    static RESOLVERS: std::sync::LazyLock<[regex::Regex; 3]> = std::sync::LazyLock::new(|| {
        [
        r"^[-+]?(?:0b[0-1_]+|0[0-7_]+|(?:0|[1-9][0-9_]*)|0x[0-9a-fA-F_]+|[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
        r"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?)$",
    ].map(|pattern|regex::Regex::new(pattern).expect("fixed scalar resolver regex"))
    });
    &RESOLVERS
}

fn yaml_integer(value: &str) -> Result<Value> {
    use num_bigint::BigInt;
    let normalized = value.replace('_', "");
    let (negative, number) = normalized
        .strip_prefix('-')
        .map_or((false, normalized.as_str()), |value| (true, value));
    let number = number.strip_prefix('+').unwrap_or(number);
    let integer = if let Some(binary) = number.strip_prefix("0b") {
        BigInt::parse_bytes(binary.as_bytes(), 2)
    } else if let Some(hex) = number.strip_prefix("0x") {
        BigInt::parse_bytes(hex.as_bytes(), 16)
    } else if number.starts_with('0') && number.len() > 1 {
        BigInt::parse_bytes(&number.as_bytes()[1..], 8)
    } else if number.contains(':') {
        number.split(':').try_fold(BigInt::from(0), |total, part| {
            BigInt::parse_bytes(part.trim().as_bytes(), 10).map(|part| total * 60 + part)
        })
    } else {
        BigInt::parse_bytes(number.trim().as_bytes(), 10)
    };
    let integer = integer.ok_or_else(|| invalid("invalid YAML integer"))?;
    let decimal = if negative { -integer } else { integer }.to_string();
    decimal
        .parse::<serde_json::Number>()
        .map(Value::Number)
        .map_err(|error| invalid(error.to_string()))
}

/// Resolve YAML timestamp scalars after structural parsing. Quoted strings never
/// enter this resolver unless explicitly tagged !!timestamp.
fn yaml_timestamp(value: &str) -> Result<Option<Value>> {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || bytes.get(4) != Some(&b'-') || !bytes[..4].iter().all(u8::is_ascii_digit)
    {
        return Ok(None);
    }
    let mut index = 5;
    let digits = |index: &mut usize, min: usize, max: usize| -> Option<&str> {
        let start = *index;
        while *index < bytes.len() && bytes[*index].is_ascii_digit() && *index - start < max {
            *index += 1;
        }
        if *index - start < min {
            None
        } else {
            value.get(start..*index)
        }
    };
    let Some(month) = digits(&mut index, 1, 2) else {
        return Ok(None);
    };
    if bytes.get(index) != Some(&b'-') {
        return Ok(None);
    }
    index += 1;
    let Some(day) = digits(&mut index, 1, 2) else {
        return Ok(None);
    };
    let date = format!("{}-{:0>2}-{:0>2}", &value[..4], month, day);
    if index == bytes.len() {
        if month.len() != 2 || day.len() != 2 {
            return Ok(None);
        }
        if parse_expiry(&date).is_none() {
            return Err(invalid("invalid YAML date"));
        }
        // An actual date object is not a datetime and must stay unexpired.
        return Ok(Some(serde_json::json!({"yaml_date":date})));
    }
    match bytes.get(index) {
        Some(b'T' | b't') => index += 1,
        Some(b' ' | b'\t') => {
            while matches!(bytes.get(index), Some(b' ' | b'\t')) {
                index += 1;
            }
        }
        _ => return Ok(None),
    }
    let Some(hour) = digits(&mut index, 1, 2) else {
        return Ok(None);
    };
    if bytes.get(index) != Some(&b':') {
        return Ok(None);
    }
    index += 1;
    let Some(minute) = digits(&mut index, 2, 2) else {
        return Ok(None);
    };
    if bytes.get(index) != Some(&b':') {
        return Ok(None);
    }
    index += 1;
    let Some(second) = digits(&mut index, 2, 2) else {
        return Ok(None);
    };
    let mut rendered = format!("{date}T{hour:0>2}:{minute}:{second}");
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index > start {
            rendered.push('.');
            rendered.push_str(&value[start..index]);
        }
    }
    let before_space = index;
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'Z') => {
            rendered.push('Z');
            index += 1;
        }
        Some(sign @ (b'+' | b'-')) => {
            let sign = *sign as char;
            index += 1;
            let Some(hour) = digits(&mut index, 1, 2) else {
                return Ok(None);
            };
            let minute = if bytes.get(index) == Some(&b':') {
                index += 1;
                let Some(minute) = digits(&mut index, 2, 2) else {
                    return Ok(None);
                };
                minute
            } else {
                "00"
            };
            rendered.push_str(&format!("{sign}{hour:0>2}:{minute}"));
        }
        None if before_space == index => {}
        _ => return Ok(None),
    }
    if index != bytes.len() {
        return Ok(None);
    }
    if parse_expiry(&rendered).is_none() {
        return Err(invalid("invalid YAML datetime"));
    }
    Ok(Some(Value::String(rendered)))
}

fn parse_document(source: &str, format: Format) -> Result<Map<String, Value>> {
    let value: Value = match format {
        Format::Json => parse_json(source, false).map_err(|error| invalid(error.to_string()))?,
        Format::Yaml => parse_yaml(source)?,
        Format::Toml => parse_toml_document(source)?,
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

pub(crate) fn split_destination(pattern: &str) -> Result<(String, Option<u16>)> {
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

fn boolean(value: &Value, field: &str) -> Result<bool> {
    if let Some(value) = value.as_bool() {
        return Ok(value);
    }
    if let Some(value) = value.as_f64() {
        if value == 0. {
            return Ok(false);
        }
        if value == 1. {
            return Ok(true);
        }
    }
    if let Some(value) = value.as_str() {
        match value.to_ascii_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => return Ok(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => return Ok(true),
            _ => {}
        }
    }
    Err(invalid(format!("{field} must be boolean")))
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
        .map(|value| boolean(value, "addon enabled"))
        .transpose()
        .map(|enabled| Some(enabled.unwrap_or(true)))
}
fn parse_override(pattern: &str, fields: &Map<String, Value>) -> Result<Override> {
    Ok(Override {
        pattern: pattern.into(),
        bypass: fields
            .get("bypass")
            .map(|value| {
                string_array(value, "bypass")
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
pub(crate) fn glob(value: &str, pattern: &str) -> bool {
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

#[cfg(test)]
mod yaml_tests {
    use super::*;

    #[test]
    fn authored_private_number_objects_remain_objects_in_every_format() {
        for (format, source) in [
            (
                Format::Json,
                r#"{"budgets":{"network:request":{"$serde_json::private::Number":"1"}},"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
            ),
            (
                Format::Toml,
                "budget={'$serde_json::private::Number'='1'}\n[hosts]\n'*'={egress='allow'}",
            ),
            (
                Format::Yaml,
                "global_budget: {'$serde_json::private::Number': '1'}\nhosts:\n  '*': {egress: allow}",
            ),
        ] {
            assert_eq!(
                Policy::parse(source, format).unwrap_err().kind,
                ErrorKind::Invalid,
                "{source}"
            );
        }
        for value in [
            parse_json(
                r#"{"nested":{"$serde_json::private::Number":"1"},"number":18446744073709551616}"#,
                false,
            )
            .unwrap(),
            parse_toml_document("nested={'$serde_json::private::Number'='1'}\nnumber=1").unwrap(),
            parse_yaml("nested: {'$serde_json::private::Number': '1'}\nnumber: 1").unwrap(),
        ] {
            assert!(value["nested"].is_object());
            assert_eq!(
                value["nested"]["$serde_json::private::Number"].as_str(),
                Some("1")
            );
        }
        assert_eq!(
            parse_json("18446744073709551616", false)
                .unwrap()
                .as_number()
                .unwrap()
                .to_string(),
            "18446744073709551616"
        );
        assert_eq!(
            parse_json(r#"{"x":1,"x":2}"#, false).unwrap()["x"].as_u64(),
            Some(2)
        );
        assert!(parse_json(r#"{"x":1,"x":2}"#, true).is_err());
    }

    #[test]
    fn styles_and_merge_keys_keep_constraints_and_precedence() {
        let source = "a: &a {limit: 1, inherited: yes}\nb: &b {limit: 2, other: no}\nvalue: {<<: [*a, *b], local: on}\nliteral: {'<<': {limit: 7}}\n";
        let value = parse_yaml(source).unwrap();
        assert_eq!(
            value["value"],
            serde_json::json!({"limit":1,"other":false,"inherited":true,"local":true})
        );
        assert_eq!(value["literal"]["<<"]["limit"], 7);
        assert_eq!(
            value["value"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["limit", "other", "inherited", "local"]
        );
        assert_eq!(parse_yaml("value: !!str yes").unwrap()["value"], "yes");
        assert!(parse_yaml("value: !!unknown x").is_err());
        assert!(parse_yaml("a: &recursive {x: *recursive}").is_err());
        assert!(parse_yaml("a: 1\n---\na: 2").is_err());
    }

    #[test]
    #[ignore = "historical Python scalar oracle; set SAFEYOLO_POLICY_PYTHON"]
    fn scalar_resolution_matches_pyyaml_tokens() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let tokens = [
            "yes",
            "Yes",
            "YES",
            "no",
            "No",
            "NO",
            "on",
            "off",
            "true",
            "FALSE",
            "tRuE",
            "null",
            "~",
            "",
            "0",
            "+1",
            "-1",
            "010",
            "08",
            "0_8",
            "0b10",
            "0b12",
            "0xFf",
            "0o10",
            "1_000",
            "1:02",
            "0:10",
            "1:60",
            "1.2",
            ".1",
            "-.1",
            "+1.2",
            "1.2e3",
            "1.2e+3",
            "1e3",
            "1:20.5",
            "-.Inf",
            ".NaN",
            "18446744073709551616",
            "0xFFFFFFFFFFFFFFFFFFFFFFFF",
            "0b111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "777777777777777777:59",
        ];
        let mut sources = Vec::new();
        for token in tokens {
            sources.push(format!("value: {token}"));
            sources.push(format!("value: '{token}'"));
            sources.push(format!("value: !!str '{token}'"));
        }
        sources.extend(
            [
                "value: !!bool tRuE",
                "value: !!int '012'",
                "value: !!int '0xFF'",
                "value: !!float '1:20.5'",
                "value: !!null arbitrary",
            ]
            .map(str::to_owned),
        );
        let script = "import json,math,sys,yaml\nout=[]\nfor source in json.load(sys.stdin):\n value=yaml.safe_load(source)['value']\n out.append({'unsupported':'nonfinite'} if isinstance(value,float) and not math.isfinite(value) else {'value':value})\njson.dump(out,sys.stdout)";
        let mut child = Command::new(
            std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
        )
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(serde_json::to_string(&sources).unwrap().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
        for (index, source) in sources.iter().enumerate() {
            if expected[index].get("unsupported").is_some() {
                assert_eq!(parse_yaml(source).unwrap_err().kind, ErrorKind::Unsupported);
            } else {
                assert_eq!(
                    parse_yaml(source).unwrap()["value"],
                    expected[index]["value"],
                    "{source}"
                );
            }
        }
        eprintln!(
            "Compared {} YAML scalar/style cases against PyYAML",
            sources.len()
        );
    }
}
