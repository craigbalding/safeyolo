//! Native proxy-policy evaluation, selected by the development policy_file option.
//!
//! Decisions mirror PolicyEngine.evaluate_request, including its existing exact
//! index case sensitivity, shared host budgets and separate CONNECT counters.
//! Credential and gateway decisions share the same rule matcher and budget state.
//! File-backed host lists and IAM task overlays retain production precedence.
//! Each action supplies only its existing Python context. Credential detection,
//! service route compilation, addon enforcement and PDP effect mapping live elsewhere.
//! Expiry is applied at load/reload, including the intentional agent-host expiry
//! fix; reaching a deadline alone does not schedule a reload.

use std::{
    collections::HashMap,
    fmt,
    net::Ipv6Addr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use indexmap::IndexMap;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod baseline;
mod budgets;
pub(crate) mod circuit_settings;
mod expiry;
mod model_json;
mod sensor_config;
mod source;
mod stats;
mod test_context_targets;
mod watch;
use baseline::{Baseline, Builder as BaselineBuilder};
pub use budgets::{BudgetResetError, BudgetStatsError};
use source::{ParsedPolicy, TemporalEntry};
pub(crate) use source::{TemporalValue, TimestampPaths};
pub use stats::EngineStatsError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BaselineSerializationError {
    NonJsonTimestamp,
}

#[derive(Debug)]
pub struct PolicyError {
    pub kind: ErrorKind,
    pub message: String,
}

/// Reached native load phase, not an inferred Python exception class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyLoadStage {
    Read,
    Decode(Format),
    JsonNull,
    Document,
    Prepare,
}

pub(crate) struct PolicyLoadError {
    pub stage: PolicyLoadStage,
    pub error: PolicyError,
}
impl fmt::Debug for PolicyLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PolicyLoadError")
            .field(&self.stage)
            .finish()
    }
}
impl fmt::Display for PolicyLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("baseline policy load failed")
    }
}
impl std::error::Error for PolicyLoadError {}

fn load_error(stage: PolicyLoadStage, error: PolicyError) -> PolicyLoadError {
    PolicyLoadError { stage, error }
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
    /// Raw gateway budget effect; these Python paths do not consume budgets.
    Budget,
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
pub struct CredentialRequest<'a> {
    pub credential_type: &'a str,
    pub destination: &'a str,
    pub path: &'a str,
    pub credential_hmac: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub struct RiskyRouteRequest<'a> {
    pub service: &'a str,
    pub agent: &'a str,
    pub account: &'a str,
    pub tactics: &'a [String],
    pub enables: &'a [String],
    pub irreversible: bool,
    pub method: &'a str,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayRequest<'a> {
    pub service: &'a str,
    pub capability: &'a str,
    pub agent: &'a str,
    pub method: &'a str,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Network,
    Credential,
    RiskyRoute,
    Gateway,
}

#[derive(Clone, Copy, Debug)]
enum RuleEffect {
    Allow,
    Deny,
    Prompt,
    Budget(u64),
}

/// Missing fields retain the defaults used by Condition.matches in Python.
/// In particular credential evaluation has no agent and gateway has no path.
#[derive(Default)]
struct Context<'a> {
    agent: Option<&'a str>,
    port: Option<u16>,
    method: &'a str,
    path: &'a str,
    credential_type: &'a str,
    credential_hmac: &'a str,
    content_type: &'a str,
    tactics: &'a [String],
    enables: &'a [String],
    irreversible: bool,
    account: &'a str,
    service: &'a str,
    capability: &'a str,
}

#[derive(Clone, Debug, Default)]
struct Condition {
    present: bool,
    agent: Option<String>,
    ports: Option<Vec<u16>>,
    methods: Option<Vec<String>>,
    path_prefix: Option<String>,
    credentials: Option<Vec<String>>,
    content_type: Option<String>,
    tactics: Option<Vec<String>>,
    enables: Option<Vec<String>>,
    irreversible: Option<bool>,
    accounts: Option<Vec<String>>,
    service: Option<String>,
    capability: Option<String>,
}

impl Condition {
    fn matches(&self, context: &Context<'_>) -> bool {
        self.agent
            .as_ref()
            .is_none_or(|pattern| glob(context.agent.unwrap_or(""), pattern))
            && self
                .ports
                .as_ref()
                .is_none_or(|ports| context.port.is_some_and(|port| ports.contains(&port)))
            && self.methods.as_ref().is_none_or(|methods| {
                methods.iter().any(|method| {
                    crate::python_text::uppercase(method)
                        == crate::python_text::uppercase(context.method)
                })
            })
            && self
                .path_prefix
                .as_ref()
                .is_none_or(|prefix| context.path.starts_with(prefix))
            && self.credentials.as_ref().is_none_or(|patterns| {
                patterns.iter().any(|pattern| {
                    if let Some(hmac) = pattern.strip_prefix("hmac:") {
                        !context.credential_hmac.is_empty() && context.credential_hmac == hmac
                    } else {
                        client_matches(&format!("{}:x", context.credential_type), pattern)
                    }
                })
            })
            && self
                .content_type
                .as_ref()
                .is_none_or(|value| context.content_type.contains(value))
            && self
                .tactics
                .as_ref()
                .is_none_or(|values| values.iter().any(|value| context.tactics.contains(value)))
            && self
                .enables
                .as_ref()
                .is_none_or(|values| values.iter().any(|value| context.enables.contains(value)))
            && self
                .irreversible
                .is_none_or(|value| context.irreversible == value)
            && self
                .accounts
                .as_ref()
                .is_none_or(|values| values.iter().any(|value| value == context.account))
            && self
                .service
                .as_ref()
                .is_none_or(|pattern| glob(context.service, pattern))
            && self
                .capability
                .as_ref()
                .is_none_or(|pattern| glob(context.capability, pattern))
    }
}

#[derive(Clone, Debug)]
struct Rule {
    action: Action,
    generated_route: bool,
    resource: String,
    effect: RuleEffect,
    reporting_budget: Option<BigInt>,
    condition: Condition,
    inferred: bool,
}

impl Rule {
    fn exact(&self) -> bool {
        exact_resource(&self.resource)
    }
    fn simple(&self) -> bool {
        self.exact()
            && !self.condition.present
            && !self.inferred
            && !matches!(self.effect, RuleEffect::Budget(_))
    }
    fn score(&self) -> (i64, bool) {
        specificity_score(
            &self.resource,
            self.condition.present,
            self.condition.ports.is_some(),
        )
    }
}

fn exact_resource(resource: &str) -> bool {
    resource
        .strip_suffix("/*")
        .is_some_and(|prefix| !prefix.contains(['/', ':', '*', '?', '[']))
}

fn specificity_score(resource: &str, condition_present: bool, port_present: bool) -> (i64, bool) {
    let score = if resource == "*" {
        0
    } else {
        resource.chars().count() as i64 * 10 - resource.matches('*').count() as i64 * 50
    };
    (score + if condition_present { 5 } else { 0 }, port_present)
}

/// Concrete controls represented by the native policy query. Other addon
/// configuration remains outside this query's validation and representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addon {
    NetworkGuard,
    CredentialGuard,
    CircuitBreaker,
    SseStreaming,
}
impl Addon {
    fn index(self) -> usize {
        match self {
            Self::NetworkGuard => 0,
            Self::CredentialGuard => 1,
            Self::CircuitBreaker => 2,
            Self::SseStreaming => 3,
        }
    }
}
const ADDON_COUNT: usize = 4;
const ADDON_NAMES: [&str; ADDON_COUNT] = [
    "network_guard",
    "credential_guard",
    "circuit_breaker",
    "sse_streaming",
];

#[derive(Clone, Default, Debug)]
struct Override {
    pattern: String,
    bypass: [bool; ADDON_COUNT],
    enabled: [Option<bool>; ADDON_COUNT],
}

/// One proxy permission representation and one atomic GCRA state map.
#[derive(Clone)]
pub struct Policy {
    baseline: Option<Arc<Baseline>>,
    baseline_path: Option<PathBuf>,
    file_times: Option<watch::PolicyFileTimes>,
    gateway: Option<Arc<crate::services::GatewaySnapshot>>,
    rules: Vec<Rule>,
    global_budget: Option<u64>,
    budgets: Arc<Mutex<IndexMap<String, f64>>>,
    evaluations: Arc<AtomicU64>,
    required: [bool; ADDON_COUNT],
    enabled: [bool; ADDON_COUNT],
    domains: Vec<Override>,
    clients: Vec<Override>,
    task: Option<TaskPolicy>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Policy")
            .field("rules", &self.rules.len())
            .field("baseline", &self.baseline.is_some())
            .field("task", &self.task.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct TaskPolicy {
    baseline: Arc<Baseline>,
    rules: Vec<Rule>,
    global_budget: Option<u64>,
    domains: Vec<Override>,
    enabled: [Option<bool>; ADDON_COUNT],
    path: Option<PathBuf>,
}

/// Validate a registered task without compiling or activating its permissions.
/// The operator registry retains the supplied JSON rather than this temporary
/// canonical model. Validation uses the same schema helpers as policy loading.
pub(crate) fn validate_task_document(value: &Value) -> Result<usize> {
    let source = object(value, "task policy")?;
    let mut builder = BaselineBuilder::new(source, false, &TimestampPaths::default())?;
    if let Some(permissions) = source.get("permissions") {
        let permissions = permissions
            .as_array()
            .ok_or_else(|| invalid("permissions must be an array"))?;
        for permission in permissions {
            builder.push(baseline::permission(permission)?, false);
        }
    }
    let model = builder.finish()?;
    Ok(model.value["permissions"]
        .as_array()
        .expect("canonical permissions are an array")
        .len())
}

pub(crate) fn validate_task_id(task: &str) -> Result<()> {
    if task.is_empty()
        || task.len() > 128
        || !task.as_bytes()[0].is_ascii_alphanumeric()
        || !task
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(invalid("invalid task identifier"));
    }
    Ok(())
}

impl Policy {
    /// An initialized local engine without a configured baseline defaults to
    /// denial while the baseline API reports null.
    pub fn unconfigured() -> Self {
        let mut policy = Self::from_document(
            ParsedPolicy {
                document: Map::new(),
                timestamps: TimestampPaths::default(),
            },
            None,
            None,
            true,
        )
        .expect("empty policy matches its schema");
        policy.baseline = None;
        policy
    }

    pub fn parse(source: &str, format: Format) -> Result<Self> {
        Self::parse_at(source, format, current_time_ms())
    }

    pub fn parse_at(source: &str, format: Format, now_ms: f64) -> Result<Self> {
        Self::parse_with_registry_at(source, format, None, now_ms)
    }

    /// Load one baseline against an already committed service registry.
    pub fn parse_with_registry_at(
        source: &str,
        format: Format,
        registry: Option<Arc<crate::services::Registry>>,
        now_ms: f64,
    ) -> Result<Self> {
        let mut parsed = parse_policy_document(source, format)?;
        prune_parsed_document(&mut parsed, now_ms)?;
        Self::from_document(parsed, None, registry, false)
    }

    /// Reloaded rule snapshots keep the same host/global budget counters.
    pub fn reload_from_source_at(&self, source: &str, format: Format, now_ms: f64) -> Result<Self> {
        let mut replacement = Self::parse_with_registry_at(
            source,
            format,
            self.gateway.as_ref().and_then(|gateway| gateway.registry()),
            now_ms,
        )?;
        replacement.budgets = self.budgets.clone();
        replacement.evaluations = self.evaluations.clone();
        replacement.baseline_path = self.baseline_path.clone();
        replacement.file_times = self.file_times;
        replacement.task = self.task.clone();
        Ok(replacement)
    }

    /// File-backed reload also rereads sibling addon defaults. This read-only
    /// loader does not acquire the approval transaction's file lock.
    pub fn reload_from_path_at(&self, path: &Path, now_ms: f64) -> Result<Self> {
        self.reload_from_path_with_registry_at(
            path,
            self.gateway.as_ref().and_then(|gateway| gateway.registry()),
            now_ms,
        )
    }

    /// Replace a registry and baseline together, preserving shared counters and
    /// the current task only when the complete load candidate succeeds.
    pub fn reload_from_path_with_registry_at(
        &self,
        path: &Path,
        registry: Option<Arc<crate::services::Registry>>,
        now_ms: f64,
    ) -> Result<Self> {
        self.reload_baseline_at(path, registry, now_ms, false)
            .map_err(|error| error.error)
    }

    /// Runtime also persists expired TOML entries. Public file loaders remain
    /// read-only and return their original policy error without phase metadata.
    pub(crate) fn reload_baseline_at(
        &self,
        path: &Path,
        registry: Option<Arc<crate::services::Registry>>,
        now_ms: f64,
        persist_expired_hosts: bool,
    ) -> std::result::Result<Self, PolicyLoadError> {
        let mut replacement =
            Self::load_baseline_at(path, registry, now_ms, persist_expired_hosts)?;
        replacement.budgets = self.budgets.clone();
        replacement.evaluations = self.evaluations.clone();
        replacement.task = self.task.clone();
        Ok(replacement)
    }

    /// Task loading uses the shipped IAM schema. Host-centric task keys are
    /// ignored by Python's UnifiedPolicy loader and are not compiled here.
    pub fn with_task_source(&self, source: &str, format: Format) -> Result<Self> {
        let mut parsed = parse_policy_document(source, format)?;
        for key in ["hosts", "agents", "lists", "global_budget"] {
            parsed.document.shift_remove(key);
            parsed.timestamps.remove_under(&[key]);
        }
        let enabled = addon_enabled_values(parsed.document.get("addons"))?;
        let task = Self::from_document(parsed, None, None, true)?;
        let mut replacement = self.clone();
        replacement.task = Some(TaskPolicy {
            baseline: task.baseline.expect("loaded task has a canonical model"),
            rules: task.rules,
            global_budget: task.global_budget,
            domains: task.domains,
            enabled,
            path: None,
        });
        Ok(replacement)
    }

    /// Compile one already registered operator document at the explicit
    /// activation boundary. Serialization is only the bridge from the raw
    /// JSON owner to the existing canonical task loader; the loader remains
    /// the sole validator and matcher compiler.
    pub(crate) fn with_task_document(&self, document: &Value) -> Result<Self> {
        let source = serde_json::to_string(document)
            .map_err(|error| invalid(format!("task policy JSON encoding failed: {error}")))?;
        self.with_task_source(&source, Format::Json)
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
        Self::from_path_with_registry_at(path, None, now_ms)
    }

    /// The caller supplies the same service registry used by gateway selection.
    pub fn from_path_with_registry_at(
        path: &Path,
        registry: Option<Arc<crate::services::Registry>>,
        now_ms: f64,
    ) -> Result<Self> {
        Self::load_baseline_at(path, registry, now_ms, false).map_err(|error| error.error)
    }

    /// Keep disk pruning at the reached source load phase. Only Runtime opts
    /// into that write; candidate rejection later in the load does not undo it.
    pub(crate) fn load_baseline_at(
        path: &Path,
        registry: Option<Arc<crate::services::Registry>>,
        now_ms: f64,
        persist_expired_hosts: bool,
    ) -> std::result::Result<Self, PolicyLoadError> {
        let source = std::fs::read_to_string(path).map_err(|error| {
            load_error(
                PolicyLoadStage::Read,
                PolicyError {
                    kind: ErrorKind::Read,
                    message: error.to_string(),
                },
            )
        })?;
        let format = match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Format::Toml,
            Some("yaml" | "yml") => Format::Yaml,
            _ => Format::Json,
        };
        let mut parsed = parse_policy_document_staged(&source, format)?;
        // Production expires baseline entries before merging addon defaults or
        // opening list files, so an expired reference cannot require its file.
        let expired = prune_parsed_document(&mut parsed, now_ms)
            .map_err(|error| load_error(PolicyLoadStage::Prepare, error))?;
        if persist_expired_hosts && matches!(format, Format::Toml) && !expired.is_empty() {
            // Source persists the removed names before addon/list processing or
            // validation. A later rejected candidate does not undo this write.
            expiry::persist_expired_hosts(path, &expired)
                .map_err(|error| load_error(PolicyLoadStage::Prepare, error))?;
        }
        // Existing loader merges sibling addons.yaml defaults before compilation.
        let addons = path.with_file_name("addons.yaml");
        if addons.exists() && addons != path {
            let defaults = std::fs::read_to_string(addons)
                .ok()
                .and_then(|source| parse_policy_document(&source, Format::Yaml).ok());
            if let Some(defaults) = defaults {
                parsed = merge_parsed_defaults(parsed, defaults)
                    .map_err(|error| load_error(PolicyLoadStage::Prepare, error))?;
            }
        }
        let mut policy = Self::from_document(parsed, path.parent(), registry, false)
            .map_err(|error| load_error(PolicyLoadStage::Prepare, error))?;
        policy.baseline_path = Some(path.to_owned());
        Ok(policy)
    }

    /// Count the validated canonical permissions after host-centric simple-rule
    /// extraction, without serializing unrelated (possibly temporal) fields.
    pub(crate) fn baseline_permissions_count(&self) -> Option<usize> {
        self.baseline.as_ref().map(|baseline| {
            baseline.value["permissions"]
                .as_array()
                .expect("validated baseline permissions")
                .len()
        })
    }

    /// Count the canonical permissions contributed by the active task overlay.
    pub(crate) fn task_permissions_count(&self) -> Option<usize> {
        self.task.as_ref().map(|task| {
            task.baseline.value["permissions"]
                .as_array()
                .expect("validated task permissions")
                .len()
        })
    }

    fn from_document(
        mut parsed: ParsedPolicy,
        list_base_dir: Option<&Path>,
        registry: Option<Arc<crate::services::Registry>>,
        is_task: bool,
    ) -> Result<Self> {
        let document = &mut parsed.document;
        let timestamps = &mut parsed.timestamps;
        expand_lists(document, list_base_dir, timestamps)?;
        let host_centric = document.contains_key("hosts");
        if host_centric {
            let global = document.get("global_budget").or_else(|| {
                document
                    .get("budgets")
                    .and_then(|budgets| budgets.get("network:request"))
            });
            if let Some(global) = global {
                positive_integer(global, "global network budget")?;
            }
        }
        if host_centric && document.contains_key("credentials") {
            source::validate_credential_source(&timestamps.projected(&["credentials"]))?;
        }
        if host_centric {
            source::validate_risk_timestamps(&timestamps.projected(&["gateway", "risk_appetite"]))?;
        }
        let mut view = BaselineBuilder::new(document, host_centric, timestamps)?;
        let global_budget = view.document["budgets"]
            .get("network:request")
            .map(|value| positive_integer(value, "global network budget"))
            .transpose()?;
        let mut policy = Self {
            baseline: None,
            baseline_path: None,
            file_times: None,
            gateway: None,
            rules: Vec::new(),
            global_budget,
            budgets: Arc::new(Mutex::new(IndexMap::new())),
            evaluations: Arc::new(AtomicU64::new(0)),
            required: [false; ADDON_COUNT],
            enabled: [true; ADDON_COUNT],
            domains: Vec::new(),
            clients: Vec::new(),
            task: None,
        };
        if let Some(hosts) = document.get("hosts") {
            policy.compile_hosts(
                object(hosts, "hosts")?,
                None,
                false,
                &mut view,
                &timestamps.projected(&["hosts"]),
            )?;
            policy.compile_risk_appetite(document.get("gateway"), &mut view)?;
            if let Some(agents) = document.get("agents") {
                for (agent, config) in object(agents, "agents")? {
                    if timestamps.value_at(&["agents", agent]).is_some() {
                        continue;
                    }
                    let Some(config) = config.as_object() else {
                        continue;
                    };
                    if let Some(egress) = config
                        .get("egress")
                        .filter(|value| matches!(value.as_str(), Some("allow" | "deny" | "prompt")))
                    {
                        if timestamps.key_at(&["agents", agent]).is_some() {
                            return Err(invalid("condition.agent must be a string"));
                        }
                        policy.emit_permission(
                            &serde_json::json!({
                                "action":"network:request", "resource":"*", "effect":egress,
                                "condition":{"agent":agent}
                            }),
                            &mut view,
                            false,
                        )?;
                    }
                    if let Some(hosts) = config.get("hosts") {
                        policy.compile_hosts(
                            object(hosts, "agent hosts")?,
                            Some(agent),
                            timestamps.key_at(&["agents", agent]).is_some(),
                            &mut view,
                            &timestamps.projected(&["agents", agent, "hosts"]),
                        )?;
                    }
                }
            }
        } else if let Some(permissions) = document.get("permissions") {
            policy.compile_iam(
                permissions,
                &mut view,
                &timestamps.projected(&["permissions"]),
            )?;
        }
        if !is_task {
            let gateway = crate::services::GatewaySnapshot::from_typed_document(
                document,
                host_centric,
                registry,
                timestamps,
            )
            .map_err(|_| invalid("gateway snapshot failed to load"))?;
            view.document["gateway"] = gateway.canonical_gateway().clone();
            view.timestamps.remove_under(&["gateway"]);
            view.timestamps
                .extend(gateway.canonical_timestamps().copy_under(&[], &["gateway"]));
            for route in gateway.compiled_routes() {
                policy.emit_gateway_route(route, &mut view);
            }
            policy.gateway = Some(Arc::new(gateway));
        }
        let baseline = view.finish()?;
        let fields = baseline.value.as_object().expect("canonical baseline");
        let required = string_array(&fields["required"], "required")?;
        policy.required = ADDON_NAMES.map(|name| required.iter().any(|value| value == name));
        policy.enabled =
            addon_enabled_values(fields.get("addons"))?.map(|value| value.unwrap_or(true));
        policy.domains = overrides(fields.get("domains"))?;
        policy.clients = overrides(fields.get("clients"))?;
        policy
            .rules
            .sort_by_key(|rule| std::cmp::Reverse(rule.score()));
        policy.baseline = Some(Arc::new(baseline));
        Ok(policy)
    }

    /// Borrow the canonical baseline for an authorized API response. This value
    /// may contain gateway tokens and must not enter diagnostics or event logs.
    pub(crate) fn baseline(
        &self,
    ) -> std::result::Result<Option<&Value>, BaselineSerializationError> {
        if self
            .baseline
            .as_ref()
            .is_some_and(|baseline| !baseline.timestamps.is_empty())
        {
            return Err(BaselineSerializationError::NonJsonTimestamp);
        }
        Ok(self.baseline.as_ref().map(|baseline| &baseline.value))
    }

    /// Borrow the active gateway state without minting or reloading tokens.
    pub fn gateway(&self) -> Option<&crate::services::GatewaySnapshot> {
        self.gateway.as_deref()
    }

    fn compile_hosts(
        &mut self,
        hosts: &Map<String, Value>,
        agent: Option<&str>,
        agent_temporal: bool,
        view: &mut BaselineBuilder,
        timestamps: &TimestampPaths,
    ) -> Result<()> {
        if timestamps.value_at(&[]).is_some() {
            return Err(invalid("hosts must be a mapping"));
        }
        for (pattern, config) in hosts {
            if timestamps.key_at(&[pattern]).is_some() {
                return Err(invalid("host keys must be strings"));
            }
            let config_timestamps = timestamps.projected(&[pattern]);
            if config_timestamps.value_at(&[]).is_some() && agent.is_some() {
                continue;
            }
            source::validate_host_timestamps(
                &config_timestamps,
                pattern == "*" && agent.is_none(),
            )?;
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
            if port.is_some()
                && let Some(egress) = config.get("egress")
            {
                egress_effect(egress)?;
            }
            if agent_temporal
                && (config.contains_key("rate_limit")
                    || config.contains_key("credentials")
                    || config.get("egress").is_some_and(|value| {
                        matches!(value.as_str(), Some("allow" | "deny" | "prompt"))
                    }))
            {
                return Err(invalid("condition.agent must be a string"));
            }
            let resource = if (pattern == "*" && agent.is_none()) || (port.is_some() && host == "*")
            {
                "*".to_owned()
            } else {
                format!("{}/*", if port.is_some() { &host } else { pattern })
            };
            let condition = || {
                let mut fields = Map::new();
                if let Some(port) = port {
                    fields.insert("port".into(), Value::from(port));
                }
                if let Some(agent) = agent {
                    fields.insert("agent".into(), Value::String(agent.into()));
                }
                if fields.is_empty() {
                    Value::Null
                } else {
                    Value::Object(fields)
                }
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
                let effect = config
                    .get("egress")
                    .and_then(Value::as_str)
                    .or_else(|| rate.map(|_| "allow"))
                    .ok_or_else(|| invalid("endpoint requires egress or a rate"))?;
                self.emit_permission(
                    &serde_json::json!({"action":"network:request", "resource":resource,
                    "effect":if effect == "allow" && rate.is_some() {"budget"} else {effect},
                    "budget":if effect == "allow" {rate} else {None}, "condition":condition()}),
                    view,
                    false,
                )?;
                continue;
            }
            let mut credential = None;
            if pattern == "*" && agent.is_none() {
                if let Some(value) = config
                    .get("unknown_credentials")
                    .or_else(|| config.get("credentials"))
                    && matches!(value.as_str(), Some("prompt" | "deny"))
                {
                    credential = Some(
                        serde_json::json!({"action":"credential:use", "resource":"*", "effect":value}),
                    );
                }
            } else if let Some(value) = config.get("credentials") {
                let credentials = if value.is_string() {
                    Value::Array(vec![value.clone()])
                } else {
                    value.clone()
                };
                let mut fields = Map::new();
                fields.insert("credential".into(), credentials);
                if let Some(agent) = agent {
                    fields.insert("agent".into(), Value::String(agent.into()));
                }
                credential = Some(
                    serde_json::json!({"action":"credential:use", "resource":resource, "condition":fields}),
                );
            }
            if agent.is_none()
                && let Some(credential) = credential.as_ref()
            {
                self.emit_permission(credential, view, false)?;
            }
            if let Some(effect) = config.get("egress").and_then(Value::as_str)
                && matches!(effect, "allow" | "deny" | "prompt")
                && (effect != "allow" || rate.is_none())
            {
                self.emit_permission(&serde_json::json!({"action":"network:request", "resource":resource, "effect":effect, "condition":condition()}), view, false)?;
            }
            if let Some(rate) = rate {
                self.emit_permission(&serde_json::json!({"action":"network:request", "resource":resource, "effect":"budget", "budget":rate, "condition":condition()}), view, false)?;
            }
            // The source agent compiler emits network rules before credentials.
            if agent.is_some()
                && let Some(credential) = credential.as_ref()
            {
                self.emit_permission(credential, view, false)?;
            }
            if agent.is_none()
                && pattern != "*"
                && (config.contains_key("bypass") || config.contains_key("addons"))
            {
                let fields = ["bypass", "addons"]
                    .into_iter()
                    .filter_map(|key| config.get(key).map(|value| (key.into(), value.clone())))
                    .collect();
                view.document
                    .get_mut("domains")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| invalid("domains must be a table"))?
                    .insert(pattern.clone(), Value::Object(fields));
                view.timestamps.remove_under(&["domains", pattern]);
                for field in ["bypass", "addons"] {
                    view.timestamps.extend(
                        config_timestamps.copy_under(&[field], &["domains", pattern, field]),
                    );
                }
            }
            if let Some(rules) = config.get("rules")
                && agent.is_none()
            {
                self.compile_iam(rules, view, &config_timestamps.projected(&["rules"]))?;
            }
        }
        Ok(())
    }

    fn compile_risk_appetite(
        &mut self,
        gateway: Option<&Value>,
        view: &mut BaselineBuilder,
    ) -> Result<()> {
        let Some(rules) = gateway
            .and_then(Value::as_object)
            .and_then(|gateway| gateway.get("risk_appetite"))
        else {
            return Ok(());
        };
        for rule in rules
            .as_array()
            .ok_or_else(|| invalid("risk_appetite must be an array"))?
        {
            let rule = object(rule, "risk appetite rule")?;
            let effect = match rule
                .get("decision")
                .map(|value| string(value, "risk decision"))
                .transpose()?
                .unwrap_or("require_approval")
            {
                "allow" => "allow",
                "require_approval" => "prompt",
                "deny" => "deny",
                _ => return Err(invalid("unknown risk appetite decision")),
            };
            // The host compiler accepts only these condition fields here. Raw
            // IAM rules can express method/path and the other schema fields.
            let condition: Map<String, Value> = [
                "tactics",
                "enables",
                "irreversible",
                "account",
                "agent",
                "service",
            ]
            .into_iter()
            .filter_map(|key| rule.get(key).map(|value| (key.to_owned(), value.clone())))
            .collect();
            let mut permission = serde_json::json!({"action":"gateway:risky_route", "resource":"*", "effect":effect});
            if !condition.is_empty() {
                permission["condition"] = Value::Object(condition);
            }
            self.emit_permission(&permission, view, false)?;
        }
        Ok(())
    }

    /// Accept routes already selected and compiled by the service module.
    /// Replacing generated routes preserves authored IAM rules. A baseline
    /// reload builds a fresh snapshot; its caller must compile its routes again.
    pub fn with_gateway_routes(&self, routes: &[crate::services::CompiledRoute]) -> Self {
        let mut replacement = self.clone();
        replacement.rules.retain(|rule| !rule.generated_route);
        if self.baseline.is_none() {
            return replacement;
        }
        let baseline = self.baseline.as_deref().expect("configured baseline");
        let mut view = BaselineBuilder::from_baseline(baseline);
        for route in routes {
            replacement.emit_gateway_route(route, &mut view);
        }
        replacement
            .rules
            .sort_by_key(|rule| std::cmp::Reverse(rule.score()));
        replacement.baseline = Some(Arc::new(
            view.finish().expect("previously validated baseline"),
        ));
        replacement
    }

    fn emit_gateway_route(
        &mut self,
        route: &crate::services::CompiledRoute,
        view: &mut BaselineBuilder,
    ) {
        let permission = serde_json::json!({"action":"gateway:request", "resource":format!("{}:{}", route.service, route.path),
            "effect":"allow", "condition":{"agent":route.agent, "method":route.methods, "capability":route.capability}});
        self.emit_permission(&permission, view, true)
            .expect("typed compiled route matches the permission schema");
    }

    fn compile_iam(
        &mut self,
        permissions: &Value,
        view: &mut BaselineBuilder,
        timestamps: &TimestampPaths,
    ) -> Result<()> {
        if timestamps.value_at(&[]).is_some() {
            return Err(invalid("permissions must be an array"));
        }
        for (index, permission) in permissions
            .as_array()
            .ok_or_else(|| invalid("permissions must be an array"))?
            .iter()
            .enumerate()
        {
            self.emit_typed_permission(
                permission,
                view,
                false,
                &timestamps.projected(&[&index.to_string()]),
            )?;
        }
        Ok(())
    }

    fn emit_permission(
        &mut self,
        permission: &Value,
        view: &mut BaselineBuilder,
        generated: bool,
    ) -> Result<()> {
        self.emit_typed_permission(permission, view, generated, &TimestampPaths::default())
    }

    fn emit_typed_permission(
        &mut self,
        permission: &Value,
        view: &mut BaselineBuilder,
        generated: bool,
        timestamps: &TimestampPaths,
    ) -> Result<()> {
        if timestamps.value_at(&[]).is_some() {
            return Err(invalid("permission must be a mapping"));
        }
        let raw = object(permission, "permission")?;
        if view.extract_simple(raw, timestamps)? {
            source::validate_permission_timestamps(timestamps, true)?;
            if timestamps.value_at(&["action"]).is_some()
                || timestamps.value_at(&["effect"]).is_some()
            {
                return Ok(());
            }
            let action = match raw.get("action").and_then(Value::as_str) {
                Some("network:request") => Action::Network,
                Some("credential:use") => Action::Credential,
                Some("gateway:risky_route") => Action::RiskyRoute,
                Some("gateway:request") => Action::Gateway,
                _ => return Ok(()),
            };
            let effect = match raw
                .get("effect")
                .map(Value::as_str)
                .unwrap_or(Some("allow"))
            {
                Some("allow") => RuleEffect::Allow,
                Some("deny") => RuleEffect::Deny,
                Some("prompt") => RuleEffect::Prompt,
                _ => return Ok(()),
            };
            self.rules.push(Rule {
                action,
                generated_route: generated,
                resource: raw["resource"]
                    .as_str()
                    .expect("exact string resource")
                    .into(),
                effect,
                reporting_budget: None,
                condition: Condition::default(),
                inferred: false,
            });
            return Ok(());
        }
        source::validate_permission_timestamps(timestamps, false)?;
        let permission = baseline::permission(permission)?;
        view.push(permission.clone(), generated);
        let rule = permission.as_object().expect("normalized permission");
        let action = match rule.get("action").and_then(Value::as_str) {
            Some("network:request") => Action::Network,
            Some("credential:use") => Action::Credential,
            Some("gateway:risky_route") => Action::RiskyRoute,
            Some("gateway:request") => Action::Gateway,
            // These accepted actions cannot be requested through this API.
            Some("file:read" | "file:write" | "subprocess:exec") => return Ok(()),
            _ => return Err(invalid("unknown or missing permission action")),
        };
        let resource = string(
            rule.get("resource")
                .ok_or_else(|| invalid("permission needs resource"))?,
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
        let reporting_budget = rule
            .get("budget")
            .filter(|value| !value.is_null())
            .map(|value| {
                value
                    .to_string()
                    .parse::<BigInt>()
                    .expect("normalized permission budget is an integer")
            });
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
            condition.present = true;
            for (key, value) in fields {
                if value.is_null() {
                    continue;
                }
                match key.as_str() {
                    "agent" => condition.agent = Some(string(value, key)?.to_owned()),
                    "method" => condition.methods = Some(string_list(value, key)?),
                    "path_prefix" => condition.path_prefix = Some(string(value, key)?.to_owned()),
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
                    "credential" => condition.credentials = Some(string_list(value, key)?),
                    "content_type" => condition.content_type = Some(string(value, key)?.to_owned()),
                    "tactics" => condition.tactics = Some(string_array(value, key)?),
                    "enables" => condition.enables = Some(string_array(value, key)?),
                    "irreversible" => condition.irreversible = Some(boolean(value, key)?),
                    "account" => condition.accounts = Some(string_list(value, key)?),
                    "service" => condition.service = Some(string(value, key)?.to_owned()),
                    "capability" => condition.capability = Some(string(value, key)?.to_owned()),
                    _ => {
                        return Err(unsupported(format!(
                            "native policy condition is not implemented: {key}"
                        )));
                    }
                }
            }
        }
        self.rules.push(Rule {
            action,
            generated_route: generated,
            resource,
            effect,
            reporting_budget,
            condition,
            inferred,
        });
        Ok(())
    }

    fn matching(&self, action: Action, context: &Context<'_>, resource: &str) -> Option<&Rule> {
        let task = self
            .task
            .as_ref()
            .map_or(&[][..], |task| task.rules.as_slice());
        let task_exact = task.iter().any(|rule| {
            rule.action == action && rule.exact() && !rule.simple() && rule.resource == resource
        });
        let candidates = || {
            task.iter()
                .chain(self.rules.iter().filter(|rule| {
                    !(task_exact && rule.exact() && !rule.simple() && rule.resource == resource)
                }))
                .filter(|rule| rule.action == action)
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
                && rule.condition.matches(context)
        };
        if context.agent.is_some_and(|agent| !agent.is_empty()) {
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

    /// `now_ms` is epoch milliseconds. A lookup with consume=false counts one
    /// evaluation while leaving the budget counters unchanged.
    pub fn evaluate(
        &self,
        request: NetworkRequest<'_>,
        now_ms: f64,
        consume: bool,
    ) -> Result<Decision> {
        if request.port == Some(0) {
            return Err(invalid("port must be from 1 to 65535"));
        }
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        if !now_ms.is_finite() {
            return Err(invalid("budget timestamp must be finite"));
        }
        let context = Context {
            agent: request.agent,
            port: request.port,
            method: request.method,
            path: request.path,
            ..Default::default()
        };
        let Some(rule) = self
            .matching(Action::Network, &context, &format!("{}/*", request.host))
            .or_else(|| self.matching(Action::Network, &context, "*"))
        else {
            return Ok(Decision {
                effect: Effect::Deny,
                matched_resource: None,
                budget_remaining: None,
            });
        };
        let decision = Decision {
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
        if let Some(rate) = self.effective_network_budget() {
            limits.push((format!("{action}:__global__"), rate));
        }
        self.charge(decision, limits, now_ms, consume)
    }

    fn charge(
        &self,
        mut decision: Decision,
        limits: Vec<(String, u64)>,
        now_ms: f64,
        consume: bool,
    ) -> Result<Decision> {
        if !now_ms.is_finite() {
            return Err(invalid("budget timestamp must be finite"));
        }
        if limits.is_empty() {
            return Ok(decision);
        }
        let mut budgets = self
            .budgets
            .lock()
            .map_err(|_| invalid("budget state lock poisoned"))?;
        let mut planned = IndexMap::new();
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

    /// Credential checks intentionally receive neither agent nor request method.
    /// Different HMACs of one type share a destination/type counter; network and
    /// configured aggregate credential budgets do not participate in this path.
    pub fn evaluate_credential(
        &self,
        request: CredentialRequest<'_>,
        now_ms: f64,
    ) -> Result<Decision> {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        if !now_ms.is_finite() {
            return Err(invalid("budget timestamp must be finite"));
        }
        let context = Context {
            credential_type: request.credential_type,
            credential_hmac: request.credential_hmac.unwrap_or(""),
            path: request.path,
            ..Default::default()
        };
        let rule = self
            .matching(
                Action::Credential,
                &context,
                &format!("{}/*", request.destination),
            )
            .or_else(|| self.matching(Action::Credential, &context, "*"));
        let mut decision = raw_decision(rule, Effect::Prompt);
        if let Some(Rule {
            effect: RuleEffect::Budget(rate),
            ..
        }) = rule
        {
            decision.effect = Effect::Allow;
            return self.charge(
                decision,
                vec![(
                    format!(
                        "credential:use:{}:{}",
                        request.destination, request.credential_type
                    ),
                    *rate,
                )],
                now_ms,
                true,
            );
        }
        Ok(decision)
    }

    /// Raw gateway policy effects match the existing PolicyEngine. In particular
    /// Budget is not charged here; the existing PDP maps it to ERROR for risk.
    pub fn evaluate_risky_route(&self, request: RiskyRouteRequest<'_>) -> Decision {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        let context = Context {
            service: request.service,
            agent: Some(request.agent),
            account: request.account,
            tactics: request.tactics,
            enables: request.enables,
            irreversible: request.irreversible,
            method: request.method,
            path: request.path,
            ..Default::default()
        };
        raw_decision(
            self.matching(Action::RiskyRoute, &context, "*"),
            Effect::Prompt,
        )
    }

    /// Path contributes to the resource only, preserving the shipped missing
    /// path condition context. The existing gateway PDP maps raw Budget to DENY.
    pub fn evaluate_gateway_request(&self, request: GatewayRequest<'_>) -> Decision {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        let context = Context {
            service: request.service,
            capability: request.capability,
            agent: Some(request.agent),
            method: request.method,
            ..Default::default()
        };
        raw_decision(
            self.matching(
                Action::Gateway,
                &context,
                &format!("{}:{}", request.service, request.path),
            ),
            Effect::Deny,
        )
    }

    /// Mirrors the separate existing addon-enable query without changing the
    /// network decision or implementing warn/block mode. Required addons resist
    /// configured bypasses as in the existing engine.
    pub fn network_guard_enabled(&self, request: NetworkRequest<'_>) -> bool {
        self.is_addon_enabled(Addon::NetworkGuard, Some(request.host), request.agent)
    }

    /// Existing source order: domain bypass, task domain bypass, baseline client
    /// bypass/disable, then baseline/domain/task enabled overrides. This query
    /// never evaluates permissions or consumes a budget.
    pub fn is_addon_enabled(
        &self,
        addon: Addon,
        domain: Option<&str>,
        client: Option<&str>,
    ) -> bool {
        let index = addon.index();
        let required = self.required[index];
        if let Some(domain) = domain.filter(|domain| !domain.is_empty()) {
            for entry in &self.domains {
                if host_matches(domain, &entry.pattern) && entry.bypass[index] {
                    return required;
                }
            }
            if let Some(task) = &self.task {
                for entry in &task.domains {
                    if host_matches(domain, &entry.pattern) && entry.bypass[index] {
                        return required;
                    }
                }
            }
        }
        if let Some(client) = client.filter(|client| !client.is_empty()) {
            for entry in &self.clients {
                if client_matches(client, &entry.pattern)
                    && (entry.bypass[index] || entry.enabled[index] == Some(false))
                {
                    return required;
                }
            }
        }
        let mut enabled = self.enabled[index];
        if let Some(domain) = domain.filter(|domain| !domain.is_empty()) {
            for entry in &self.domains {
                if host_matches(domain, &entry.pattern)
                    && let Some(value) = entry.enabled[index]
                {
                    enabled = value;
                }
            }
        }
        if let Some(task_enabled) = self.task.as_ref().and_then(|task| task.enabled[index]) {
            enabled = required || task_enabled;
        }
        enabled
    }
}

fn prune_parsed_document(
    parsed: &mut ParsedPolicy,
    now_ms: f64,
) -> Result<Vec<(Option<String>, String)>> {
    let expired = prune_document(&mut parsed.document, now_ms)?;
    parsed.timestamps.retain_document(&parsed.document);
    Ok(expired)
}

fn merge_parsed_defaults(authored: ParsedPolicy, defaults: ParsedPolicy) -> Result<ParsedPolicy> {
    let (document, timestamps) = authored.into_parts();
    let authored = YamlNode {
        value: Value::Object(document),
        timestamps,
    };
    let (document, timestamps) = defaults.into_parts();
    let defaults = YamlNode {
        value: Value::Object(document),
        timestamps,
    };
    let mut merged = YamlMapping::default();
    for (key, value) in authored.into_mapping()? {
        merged.insert(key, value);
    }
    for (key, value) in defaults.into_mapping()? {
        if let Some(index) = merged.index.get(&key).copied() {
            if key == YamlKey::String("addons".into())
                && value.value.is_object()
                && value.timestamps.value_at(&[]).is_none()
                && merged.entries[index].1.value.is_object()
                && merged.entries[index].1.timestamps.value_at(&[]).is_none()
            {
                let authored = std::mem::replace(
                    &mut merged.entries[index].1,
                    YamlNode {
                        value: Value::Null,
                        timestamps: TimestampPaths::default(),
                    },
                );
                let mut addons = YamlMapping::default();
                for (key, value) in value.into_mapping()? {
                    addons.insert(key, value);
                }
                for (key, value) in authored.into_mapping()? {
                    addons.insert(key, value);
                }
                merged.entries[index].1 = finish_yaml_mapping(addons.entries);
            }
        } else {
            merged.insert(key, value);
        }
    }
    let node = finish_yaml_mapping(merged.entries);
    let Value::Object(document) = node.value else {
        unreachable!("finished mapping")
    };
    Ok(ParsedPolicy {
        document,
        timestamps: node.timestamps,
    })
}

fn prune_document(
    document: &mut Map<String, Value>,
    now_ms: f64,
) -> Result<Vec<(Option<String>, String)>> {
    let expired = expired_host_entries(&Value::Object(document.clone()), now_ms)?;
    for (agent, host) in &expired {
        let hosts = match agent {
            Some(agent) => document
                .get_mut("agents")
                .and_then(|agents| agents.get_mut(agent))
                .and_then(|agent| agent.get_mut("hosts")),
            None => document.get_mut("hosts"),
        };
        if let Some(hosts) = hosts.and_then(Value::as_object_mut) {
            hosts.shift_remove(host);
        }
    }
    Ok(expired)
}

/// Existing lists are local files. URL-looking values are filenames too: the
/// production loader does not fetch remote lists or introduce another egress.
fn expand_lists(
    document: &mut Map<String, Value>,
    base_dir: Option<&Path>,
    timestamps: &mut TimestampPaths,
) -> Result<()> {
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
        if !lists.contains_key(name) || timestamps.key_at(&["lists", name]).is_some() {
            return Err(invalid(format!("undefined list reference ${name}")));
        }
    }
    for (host, name, config) in references {
        if timestamps.value_at(&["lists", &name]).is_some() {
            return Err(invalid("list path must be a string"));
        }
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
        let inherited_timestamps = timestamps.projected(&["hosts", &host]);
        timestamps.remove_under(&["hosts", &host]);
        for line in source.split([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ]) {
            let mut entry = line.trim_matches(python_whitespace);
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            let parts: Vec<_> = entry
                .split(python_whitespace)
                .filter(|part| !part.is_empty())
                .collect();
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
            if !hosts.contains_key(entry) {
                timestamps.extend(inherited_timestamps.copy_under(&[], &["hosts", entry]));
                hosts.insert(entry.to_owned(), config.clone());
            }
        }
    }
    Ok(())
}

// Python str.strip/split also treat the four information separators as space;
// Rust's Unicode White_Space predicate omits them. Host-list entries must not
// retain these bytes and accidentally fall through a permissive default rule.
pub(crate) fn python_whitespace(character: char) -> bool {
    character.is_whitespace() || matches!(character, '\u{1c}'..='\u{1f}')
}

pub(crate) fn current_time_ms() -> f64 {
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

fn raw_decision(rule: Option<&Rule>, default: Effect) -> Decision {
    Decision {
        effect: rule.map_or(default, |rule| match rule.effect {
            RuleEffect::Budget(_) => Effect::Budget,
            effect => effect_of(effect),
        }),
        matched_resource: rule.map(|rule| rule.resource.clone()),
        budget_remaining: None,
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
    Ok(parse_toml_with_timestamps(source)?.0)
}

fn parse_toml_with_timestamps(source: &str) -> Result<(Value, TimestampPaths)> {
    let (syntax_source, context) = mask_large_toml_integers(source)?;
    parse_toml_with_context(&syntax_source, &context)
}

pub(crate) fn parse_toml_document_with_context(
    source: &str,
    context: &LargeIntegerContext,
) -> Result<Value> {
    Ok(parse_toml_with_context(source, context)?.0)
}

fn parse_toml_with_context(
    source: &str,
    context: &LargeIntegerContext,
) -> Result<(Value, TimestampPaths)> {
    let syntax = source
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| invalid(error.to_string()))?;
    // Build structure from syntax nodes, never serde's private marker transport.
    let mut document = Value::Object(
        syntax
            .iter()
            .map(|(key, item)| Ok((key.to_owned(), toml_item(item, context)?)))
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
    let mut timestamps = TimestampPaths::default();
    for (key, item) in syntax.iter() {
        collect_toml_timestamps(item, &mut vec![key.to_owned()], &mut timestamps)?;
    }
    Ok((document, timestamps))
}

/// Parse the editable syntax tree with the same lossless integer adapter used
/// by policy loading.  Callers must run `restore_large_toml_integers` before
/// persisting the rendered document.
pub(crate) fn parse_toml_for_edit(
    source: &str,
) -> Result<(toml_edit::DocumentMut, LargeIntegerContext)> {
    let (masked, context) = mask_large_toml_integers(source)?;
    let document = masked
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| invalid(error.to_string()))?;
    Ok((document, context))
}

#[derive(Debug, Clone)]
pub(crate) struct LargeIntegerContext {
    prefix: String,
    values: HashMap<String, String>,
}

impl LargeIntegerContext {
    fn new(source: &str) -> Self {
        let mut prefix;
        loop {
            prefix = format!(
                "__safeyolo_large_toml_integer__{}:",
                uuid::Uuid::new_v4().simple()
            );
            if !source.contains(&prefix) {
                break;
            }
        }
        Self {
            prefix,
            values: HashMap::new(),
        }
    }

    fn register(&mut self, literal: &str) -> String {
        let token = format!("{}{}", self.prefix, self.values.len());
        self.values.insert(token.clone(), literal.to_owned());
        token
    }

    fn literal(&self, token: &str) -> Option<&str> {
        self.values.get(token).map(String::as_str)
    }
}

pub(crate) fn large_integer_marker_value(
    context: &mut LargeIntegerContext,
    literal: &str,
) -> toml_edit::Value {
    toml_edit::Value::from(context.register(literal))
}

fn large_integer_from_marker(
    value: &str,
    context: &LargeIntegerContext,
) -> Option<serde_json::Number> {
    let literal = context.literal(value)?;
    let integer = parsed_integer_literal(literal)?;
    if !is_out_of_range(&integer) {
        return None;
    }
    integer.to_string().parse::<serde_json::Number>().ok()
}

/// Replace only out-of-range TOML integer value tokens.  Strings, comments,
/// keys, dates and floating point values remain byte-for-byte untouched.
fn mask_large_toml_integers(source: &str) -> Result<(String, LargeIntegerContext)> {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut context = LargeIntegerContext::new(source);
    let mut index = 0;
    let mut line_has_content = false;
    let mut table_header = false;
    while index < bytes.len() {
        if let Some(end) = skip_toml_string(bytes, index) {
            output.push_str(&source[index..end]);
            line_has_content = true;
            index = end;
            continue;
        }
        if bytes[index] == b'#' {
            let end = source[index..]
                .find('\n')
                .map_or(bytes.len(), |offset| index + offset);
            output.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if bytes[index] == b'\n' {
            output.push('\n');
            line_has_content = false;
            table_header = false;
            index += 1;
            continue;
        }
        if !line_has_content && matches!(bytes[index], b' ' | b'\t' | b'\r') {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        if !line_has_content && bytes[index] == b'[' {
            table_header = true;
            line_has_content = true;
            output.push('[');
            index += 1;
            continue;
        }
        if is_integer_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_integer_char(bytes[index]) {
                index += 1;
            }
            let literal = &source[start..index];
            let next = skip_ascii_whitespace(bytes, index);
            // A numeric-looking bare key is not a value.  TOML dates and
            // floats are also excluded by out_of_range_integer_literal.
            if !table_header && (next >= bytes.len() || bytes[next] != b'=') {
                if integer_literal_candidate(literal) {
                    if parsed_integer_literal(literal).is_none() {
                        return Err(invalid(format!("invalid TOML integer literal: {literal}")));
                    }
                }
                if out_of_range_integer_literal(literal) {
                    output.push('"');
                    output.push_str(&context.register(literal));
                    output.push('"');
                    continue;
                }
            }
            output.push_str(literal);
            line_has_content = true;
            continue;
        }
        let character = source[index..].chars().next().expect("index in source");
        output.push(character);
        if !character.is_whitespace() {
            line_has_content = true;
        }
        index += character.len_utf8();
    }
    Ok((output, context))
}

/// Undo the transient adapter strings emitted by toml_edit after a mutation.
/// Marker contents are restricted to the TOML numeric token alphabet, so this
/// scan cannot consume a quoted string or a following policy token.
pub(crate) fn restore_large_toml_integers(source: &str, context: &LargeIntegerContext) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            let character = source[index..].chars().next().expect("index in source");
            output.push(character);
            index += character.len_utf8();
            continue;
        }
        let Some(end) = skip_toml_string(bytes, index) else {
            output.push('"');
            index += 1;
            continue;
        };
        let content_start = index + 1;
        let content_end = end.saturating_sub(1);
        let content = &source[content_start..content_end];
        if let Some(literal) = context.literal(content) {
            output.push_str(literal);
        } else {
            output.push_str(&source[index..end]);
        }
        index = end;
    }
    output
}

fn skip_toml_string(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') && bytes.get(start) != Some(&b'\'') {
        return None;
    }
    let quote = bytes[start];
    let triple = bytes.get(start..start + 3) == Some(&[quote, quote, quote]);
    let mut index = start + if triple { 3 } else { 1 };
    while index < bytes.len() {
        if triple {
            if bytes.get(index..index + 3) == Some(&[quote, quote, quote]) {
                return Some(index + 3);
            }
            index += 1;
        } else if bytes[index] == quote && (quote == b'\'' || !is_escaped(bytes, index)) {
            return Some(index + 1);
        } else {
            index += 1;
        }
    }
    None
}

fn is_escaped(bytes: &[u8], index: usize) -> bool {
    let mut backslashes = 0;
    let mut cursor = index;
    while cursor > 0 && bytes[cursor - 1] == b'\\' {
        backslashes += 1;
        cursor -= 1;
    }
    backslashes % 2 == 1
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    index
}

fn is_integer_start(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b'+' || byte == b'-'
}

fn is_integer_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-' | b'.' | b':')
}

fn integer_literal_candidate(literal: &str) -> bool {
    if literal.starts_with('+') || literal.starts_with('-') {
        return !literal[1..].contains(['.', 'e', 'E', ':']);
    }
    if literal.starts_with("0x") || literal.starts_with("0o") || literal.starts_with("0b") {
        return true;
    }
    if literal.contains(['.', 'e', 'E', ':']) {
        return false;
    }
    // A local TOML date contains two hyphens but is not an integer.
    literal.matches('-').count() < 2
}

fn out_of_range_integer_literal(literal: &str) -> bool {
    parsed_integer_literal(literal).is_some_and(|value| is_out_of_range(&value))
}

fn parsed_integer_literal(literal: &str) -> Option<BigInt> {
    if literal.is_empty()
        || literal.contains(['.', 'e', 'E', ':'])
        || (literal.starts_with('+') && literal.len() == 1)
    {
        return None;
    }
    let (signed, negative, unsigned) = if let Some(value) = literal.strip_prefix('-') {
        (true, true, value)
    } else if let Some(value) = literal.strip_prefix('+') {
        (true, false, value)
    } else {
        (false, false, literal)
    };
    let (radix, digits) = if let Some(value) = unsigned.strip_prefix("0x") {
        (16, value)
    } else if let Some(value) = unsigned.strip_prefix("0o") {
        (8, value)
    } else if let Some(value) = unsigned.strip_prefix("0b") {
        (2, value)
    } else {
        (10, unsigned)
    };
    if signed && radix != 10 || !valid_integer_digits(digits, radix) {
        return None;
    }
    let normalized = digits.replace('_', "");
    let mut value = BigInt::parse_bytes(normalized.as_bytes(), radix)?;
    if negative {
        value = -value;
    }
    Some(value)
}

fn valid_integer_digits(digits: &str, radix: u32) -> bool {
    let mut previous_was_digit = false;
    let mut saw_digit = false;
    for byte in digits.bytes() {
        if byte == b'_' {
            if !previous_was_digit {
                return false;
            }
            previous_was_digit = false;
            continue;
        }
        let valid = match radix {
            2 => matches!(byte, b'0' | b'1'),
            8 => (b'0'..=b'7').contains(&byte),
            10 => byte.is_ascii_digit(),
            16 => byte.is_ascii_hexdigit(),
            _ => false,
        };
        if !valid {
            return false;
        }
        saw_digit = true;
        previous_was_digit = true;
    }
    if !saw_digit || !previous_was_digit {
        return false;
    }
    if radix == 10 {
        let plain = digits.replace('_', "");
        plain == "0" || !plain.starts_with('0')
    } else {
        true
    }
}

fn is_out_of_range(value: &BigInt) -> bool {
    value < &BigInt::from(i64::MIN) || value > &BigInt::from(i64::MAX)
}

fn collect_toml_timestamps(
    item: &toml_edit::Item,
    path: &mut Vec<String>,
    timestamps: &mut TimestampPaths,
) -> Result<()> {
    match item {
        toml_edit::Item::None => {}
        toml_edit::Item::Value(value) => collect_toml_value_timestamps(value, path, timestamps)?,
        toml_edit::Item::Table(table) => {
            for (key, value) in table.iter() {
                path.push(key.to_owned());
                collect_toml_timestamps(value, path, timestamps)?;
                path.pop();
            }
        }
        toml_edit::Item::ArrayOfTables(tables) => {
            for (index, table) in tables.iter().enumerate() {
                path.push(index.to_string());
                for (key, value) in table.iter() {
                    path.push(key.to_owned());
                    collect_toml_timestamps(value, path, timestamps)?;
                    path.pop();
                }
                path.pop();
            }
        }
    }
    Ok(())
}

fn collect_toml_value_timestamps(
    value: &toml_edit::Value,
    path: &mut Vec<String>,
    timestamps: &mut TimestampPaths,
) -> Result<()> {
    match value {
        toml_edit::Value::Datetime(value) => timestamps.insert_value(
            &path.iter().map(String::as_str).collect::<Vec<_>>(),
            TemporalValue::from_toml(value.value())?,
        ),
        toml_edit::Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                path.push(index.to_string());
                collect_toml_value_timestamps(value, path, timestamps)?;
                path.pop();
            }
        }
        toml_edit::Value::InlineTable(table) => {
            for (key, value) in table.iter() {
                path.push(key.to_owned());
                collect_toml_value_timestamps(value, path, timestamps)?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

fn toml_item(item: &toml_edit::Item, context: &LargeIntegerContext) -> Result<Value> {
    match item {
        toml_edit::Item::None => Ok(Value::Null),
        toml_edit::Item::Value(value) => toml_value(value, context),
        toml_edit::Item::Table(table) => table
            .iter()
            .map(|(key, value)| Ok((key.to_owned(), toml_item(value, context)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        toml_edit::Item::ArrayOfTables(tables) => tables
            .iter()
            .map(|table| {
                table
                    .iter()
                    .map(|(key, value)| Ok((key.to_owned(), toml_item(value, context)?)))
                    .collect::<Result<Map<_, _>>>()
                    .map(Value::Object)
            })
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

fn toml_value(value: &toml_edit::Value, context: &LargeIntegerContext) -> Result<Value> {
    match value {
        toml_edit::Value::String(value) => {
            if let Some(integer) = large_integer_from_marker(value.value(), context) {
                Ok(Value::Number(integer))
            } else {
                Ok(Value::String(value.value().clone()))
            }
        }
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
            .map(|value| toml_value(value, context))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        toml_edit::Value::InlineTable(table) => table
            .iter()
            .map(|(key, value)| Ok((key.to_owned(), toml_value(value, context)?)))
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
    Ok(parse_yaml_node(source)?.value)
}

/// Vault fields require strings. Retain timestamp types through aliases and
/// merges before rejecting them in declared fields; unknown fields are ignored
/// by the vault schema, including timestamp values in those fields.
pub(crate) fn parse_yaml_for_vault(source: &str) -> Result<Value> {
    let node = parse_yaml_node(source)?;
    if node
        .timestamps
        .entries
        .iter()
        .filter(|entry| !entry.key)
        .any(|entry| {
            let path = &entry.path;
            path.len() == 3
                && path[0] == "credentials"
                && matches!(
                    path[2].as_str(),
                    "name"
                        | "type"
                        | "value"
                        | "refresh_token"
                        | "token_url"
                        | "client_id"
                        | "client_secret"
                        | "expires_at"
                )
        })
    {
        return Err(invalid(
            "vault credential fields must not contain typed YAML timestamps",
        ));
    }
    Ok(node.value)
}

/// Timestamp provenance is parser-owned, never encoded as an authored JSON
/// object marker. Paths are relative to this node and survive alias cloning.
#[derive(Clone)]
struct YamlNode {
    value: Value,
    timestamps: TimestampPaths,
}

impl YamlNode {
    fn into_sequence(self) -> Result<Vec<Self>> {
        let Value::Array(values) = self.value else {
            return Err(invalid("expected YAML sequence"));
        };
        Ok(values
            .into_iter()
            .enumerate()
            .map(|(index, value)| Self {
                value,
                timestamps: self.timestamps.projected(&[&index.to_string()]),
            })
            .collect())
    }

    fn into_mapping(self) -> Result<Vec<(YamlKey, Self)>> {
        if self.timestamps.value_at(&[]).is_some() {
            return Err(invalid("YAML merge requires mappings"));
        }
        let Value::Object(values) = self.value else {
            return Err(invalid("YAML merge requires mappings"));
        };
        Ok(values
            .into_iter()
            .map(|(key, value)| {
                let typed = self.timestamps.key_at(&[&key]).cloned();
                let timestamps = self.timestamps.projected(&[&key]);
                (
                    typed.map_or_else(|| YamlKey::String(key), YamlKey::Temporal),
                    Self { value, timestamps },
                )
            })
            .collect())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum YamlKey {
    String(String),
    Temporal(TemporalValue),
}

#[derive(Default)]
struct YamlMapping {
    entries: Vec<(YamlKey, YamlNode)>,
    index: HashMap<YamlKey, usize>,
}

impl YamlMapping {
    fn insert(&mut self, key: YamlKey, value: YamlNode) {
        if let Some(index) = self.index.get(&key) {
            self.entries[*index].1 = value;
        } else {
            self.index.insert(key.clone(), self.entries.len());
            self.entries.push((key, value));
        }
    }
}

fn finish_yaml_mapping(entries: Vec<(YamlKey, YamlNode)>) -> YamlNode {
    // Every authored string key is known before private identities are chosen.
    // This spelling is never interpreted as provenance by any consumer.
    let mut used: std::collections::HashSet<String> = entries
        .iter()
        .filter_map(|(key, _)| match key {
            YamlKey::String(key) => Some(key.clone()),
            _ => None,
        })
        .collect();
    let mut serial = 0;
    let mut values = Map::new();
    let mut timestamps = TimestampPaths::default();
    for (key, mut node) in entries {
        let (key, typed) = match key {
            YamlKey::String(key) => (key, None),
            YamlKey::Temporal(value) => {
                let key = loop {
                    let key = format!("\0temporal-key-{serial}");
                    serial += 1;
                    if used.insert(key.clone()) {
                        break key;
                    }
                };
                (key, Some(value))
            }
        };
        node.timestamps.prepend(&[&key]);
        timestamps.extend(node.timestamps);
        if let Some(value) = typed {
            timestamps.entries.push(TemporalEntry {
                path: vec![key.clone()],
                key: true,
                value,
            });
        }
        values.insert(key, node.value);
    }
    YamlNode {
        value: Value::Object(values),
        timestamps,
    }
}

fn parse_yaml_node(source: &str) -> Result<YamlNode> {
    parse_yaml_node_with_keys(source, false)
}

fn parse_yaml_node_with_keys(source: &str, temporal_keys: bool) -> Result<YamlNode> {
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
        Event::StreamEnd => {
            return Ok(YamlNode {
                value: Value::Null,
                timestamps: TimestampPaths::default(),
            });
        }
        Event::DocumentStart => {}
        _ => return Err(invalid("expected YAML document")),
    }
    let value = yaml_node(&mut parser, &mut HashMap::new(), temporal_keys)?.0;
    if next(&mut parser)? != Event::DocumentEnd || next(&mut parser)? != Event::StreamEnd {
        return Err(invalid("policy YAML must contain one document"));
    }
    Ok(value)
}

fn yaml_node(
    parser: &mut yaml_rust2::parser::Parser<std::str::Chars<'_>>,
    anchors: &mut HashMap<usize, (YamlNode, bool)>,
    temporal_keys: bool,
) -> Result<(YamlNode, bool)> {
    use yaml_rust2::parser::Event;
    let (event, _) = parser
        .next_token()
        .map_err(|error| invalid(error.to_string()))?;
    let (anchor, result) = match event {
        Event::Scalar(value, style, anchor, tag) => {
            let mut timestamp = false;
            let (value, is_merge) = yaml_scalar(&value, style, tag.as_ref(), &mut timestamp)?;
            let mut timestamps = TimestampPaths::default();
            if timestamp {
                timestamps.insert_value(&[], TemporalValue::from_yaml(&value)?);
            }
            (anchor, (YamlNode { value, timestamps }, is_merge))
        }

        Event::Alias(anchor) => {
            return anchors.get(&anchor).cloned().ok_or_else(|| {
                unsupported("recursive or unresolved YAML aliases are not supported")
            });
        }
        Event::SequenceStart(anchor, tag) => {
            yaml_collection_tag(tag.as_ref(), "seq")?;
            let mut values = Vec::new();
            let mut timestamps = TimestampPaths::default();
            while !matches!(
                parser.peek().map_err(|error| invalid(error.to_string()))?.0,
                Event::SequenceEnd
            ) {
                let mut node = yaml_node(parser, anchors, temporal_keys)?.0;
                let index = values.len().to_string();
                node.timestamps.prepend(&[&index]);
                timestamps.extend(node.timestamps);
                values.push(node.value);
            }
            parser
                .next_token()
                .map_err(|error| invalid(error.to_string()))?;
            (
                anchor,
                (
                    YamlNode {
                        value: Value::Array(values),
                        timestamps,
                    },
                    false,
                ),
            )
        }
        Event::MappingStart(anchor, tag) => {
            yaml_collection_tag(tag.as_ref(), "map")?;
            let (mut merged, mut local) = (YamlMapping::default(), Vec::new());
            while !matches!(
                parser.peek().map_err(|error| invalid(error.to_string()))?.0,
                Event::MappingEnd
            ) {
                let (key, is_merge) = yaml_node(parser, anchors, temporal_keys)?;
                let value = yaml_node(parser, anchors, temporal_keys)?.0;
                if is_merge {
                    let parents = match value.value {
                        Value::Object(_) => vec![value],
                        Value::Array(_) => value.into_sequence()?.into_iter().rev().collect(),
                        _ => return Err(invalid("YAML merge requires mappings")),
                    };
                    for parent in parents {
                        for (key, value) in parent.into_mapping()? {
                            merged.insert(key, value);
                        }
                    }
                } else {
                    let key = if temporal_keys {
                        key.timestamps.value_at(&[]).cloned().map(YamlKey::Temporal)
                    } else {
                        None
                    }
                    .map_or_else(
                        || {
                            string(&key.value, "YAML mapping key")
                                .map(|key| YamlKey::String(key.to_owned()))
                        },
                        Ok,
                    )?;
                    local.push((key, value));
                }
            }
            parser
                .next_token()
                .map_err(|error| invalid(error.to_string()))?;
            for (key, value) in local {
                merged.insert(key, value);
            }
            (anchor, (finish_yaml_mapping(merged.entries), false))
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
    timestamp: &mut bool,
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
        *timestamp = true;
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

pub(crate) fn parse_document(source: &str, format: Format) -> Result<Map<String, Value>> {
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
        document = normalize_toml(document, &mut TimestampPaths::default())?;
    }
    Ok(document)
}

fn parse_policy_document(source: &str, format: Format) -> Result<ParsedPolicy> {
    parse_policy_document_staged(source, format).map_err(|error| error.error)
}

fn parse_policy_document_staged(
    source: &str,
    format: Format,
) -> std::result::Result<ParsedPolicy, PolicyLoadError> {
    let decode_error = |error| load_error(PolicyLoadStage::Decode(format), error);
    let (value, mut timestamps) = decode_policy_value(source, format).map_err(decode_error)?;
    if timestamps.value_at(&[]).is_some() {
        return Err(load_error(
            PolicyLoadStage::Document,
            invalid("policy document must be a mapping"),
        ));
    }
    let mut document = if value.is_null() && matches!(format, Format::Yaml) {
        Map::new()
    } else if let Value::Object(document) = value {
        document
    } else {
        let stage = if value.is_null() && matches!(format, Format::Json) {
            PolicyLoadStage::JsonNull
        } else {
            PolicyLoadStage::Document
        };
        return Err(load_error(
            stage,
            invalid("policy document must be a mapping"),
        ));
    };
    if matches!(format, Format::Toml) {
        // Source load_as_internal includes TOML normalization inside _load_file.
        document = normalize_toml(document, &mut timestamps).map_err(decode_error)?;
    }
    Ok(ParsedPolicy {
        document,
        timestamps,
    })
}

// Share the existing format decoders with raw-baseline watch observation. Root
// mapping admission and TOML transforms remain at their existing call sites.
fn decode_policy_value(source: &str, format: Format) -> Result<(Value, TimestampPaths)> {
    match format {
        Format::Yaml => {
            let node = parse_yaml_node_with_keys(source, true)?;
            Ok((node.value, node.timestamps))
        }
        Format::Toml => parse_toml_with_timestamps(source),
        Format::Json => Ok((
            parse_json(source, false).map_err(|error| invalid(error.to_string()))?,
            TimestampPaths::default(),
        )),
    }
}

fn normalize_toml(
    mut source: Map<String, Value>,
    timestamps: &mut TimestampPaths,
) -> Result<Map<String, Value>> {
    for (alias, internal) in [("budget", "global_budget"), ("credential", "credentials")] {
        if source.contains_key(alias) && source.contains_key(internal) {
            return Err(invalid(format!(
                "{alias} and {internal} are the same field"
            )));
        }
    }
    if source.contains_key("risk")
        && source
            .get("gateway")
            .and_then(Value::as_object)
            .is_some_and(|gateway| gateway.contains_key("risk_appetite"))
    {
        return Err(invalid("risk and gateway.risk_appetite are the same field"));
    }
    for field in ["hosts", "credential", "agents"] {
        if let Some(value) = source.get(field) {
            object(value, field)?;
        }
    }
    if source.get("risk").is_some_and(|value| !value.is_array()) {
        return Err(invalid("risk must be an array"));
    }
    let mut output = Map::new();
    let metadata: Map<String, Value> = ["version", "description"]
        .into_iter()
        .filter_map(|key| source.get(key).map(|value| (key.into(), value.clone())))
        .collect();
    if !metadata.is_empty() {
        timestamps.remove_under(&["metadata"]);
        for key in ["version", "description"] {
            timestamps.move_under(&[key], &["metadata", key]);
        }
        output.insert("metadata".into(), Value::Object(metadata));
    }
    if let Some(value) = source.shift_remove("budget") {
        timestamps.move_under(&["budget"], &["global_budget"]);
        output.insert("global_budget".into(), value);
    }
    if let Some(mut hosts) = source.shift_remove("hosts") {
        normalize_hosts(&mut hosts, timestamps, &["hosts"])?;
        output.insert("hosts".into(), hosts);
    }
    if let Some(credentials) = source.shift_remove("credential") {
        timestamps.move_under(&["credential"], &["credentials"]);
        let credentials = object(&credentials, "credential")?
            .iter()
            .map(|(name, config)| {
                let value = if let Some(config) = config.as_object() {
                    let mut renamed = Map::new();
                    let original = timestamps.projected(&["credentials", name]);
                    timestamps.remove_under(&["credentials", name]);
                    for (key, value) in config {
                        let target = if key == "match" { "patterns" } else { key };
                        timestamps.remove_under(&["credentials", name, target]);
                        timestamps
                            .extend(original.copy_under(&[key], &["credentials", name, target]));
                        renamed.insert(
                            if key == "match" {
                                "patterns".into()
                            } else {
                                key.clone()
                            },
                            value.clone(),
                        );
                    }
                    Value::Object(renamed)
                } else {
                    config.clone()
                };
                (name.clone(), value)
            })
            .collect();
        output.insert("credentials".into(), Value::Object(credentials));
    }
    if let Some(risk) = source.shift_remove("risk") {
        timestamps.move_under(&["risk"], &["gateway", "risk_appetite"]);
        let mut gateway = source
            .get("gateway")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        gateway.insert("risk_appetite".into(), risk);
        output.insert("gateway".into(), Value::Object(gateway));
    }
    for (key, value) in source {
        if matches!(key.as_str(), "version" | "description") {
            continue;
        }
        output.entry(key).or_insert(value);
    }
    if let Some(agents) = output.get_mut("agents").and_then(Value::as_object_mut) {
        for (agent, config) in agents.iter_mut() {
            if let Some(hosts) = config.get_mut("hosts") {
                normalize_hosts(hosts, timestamps, &["agents", agent, "hosts"])?;
            }
        }
    }
    Ok(output)
}

fn normalize_hosts(
    hosts: &mut Value,
    timestamps: &mut TimestampPaths,
    prefix: &[&str],
) -> Result<()> {
    for (host, config) in hosts
        .as_object_mut()
        .ok_or_else(|| invalid("hosts must be a table"))?
        .iter_mut()
    {
        if let Some(fields) = config.as_object_mut() {
            // Preserve source-order assignment when both aliases exist, as normalize() does.
            let source = std::mem::take(fields);
            let mut base = prefix.to_vec();
            base.push(host);
            let original = timestamps.projected(&base);
            timestamps.remove_under(&base);
            for (key, value) in source {
                let normalized = match key.as_str() {
                    "rate" => "rate_limit",
                    "allow" => "credentials",
                    "unknown_creds" => "unknown_credentials",
                    _ => &key,
                };
                let mut target = base.clone();
                target.push(normalized);
                timestamps.remove_under(&target);
                timestamps.extend(original.copy_under(&[&key], &target));
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

fn canonical_ipv6(address: &str) -> Result<String> {
    // CPython's IPv6Address retains a nonempty scope verbatim, except '%' or
    // '/' within the scope. It canonicalizes only the address before '%'.
    if address.contains('/') {
        return Err(invalid("invalid IPv6 host"));
    }
    let (address, scope) = match address.split_once('%') {
        Some((address, scope)) if !scope.is_empty() && !scope.contains('%') => {
            (address, Some(scope))
        }
        Some(_) => return Err(invalid("invalid IPv6 scope")),
        None => (address, None),
    };
    let mut address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| invalid("invalid IPv6 host"))?
        .to_string();
    if let Some(scope) = scope {
        address.push('%');
        address.push_str(scope);
    }
    Ok(address)
}

pub(crate) fn split_destination(pattern: &str) -> Result<(String, Option<u16>)> {
    if !pattern.contains(':') {
        return Ok((pattern.into(), None));
    }
    let (host, port) = if let Some(rest) = pattern.strip_prefix('[')
        && let Some((host, port)) = rest.split_once("]:")
    {
        (canonical_ipv6(host)?, port)
    } else if pattern.matches(':').count() == 1 {
        let (host, port) = pattern.rsplit_once(':').unwrap();
        (host.into(), port)
    } else {
        return Ok((canonical_ipv6(pattern)?, None));
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

fn addon_enabled_values(addons: Option<&Value>) -> Result<[Option<bool>; ADDON_COUNT]> {
    let Some(addons) = addons else {
        return Ok([None; ADDON_COUNT]);
    };
    let addons = object(addons, "addons")?;
    let mut values = [None; ADDON_COUNT];
    for (index, name) in ADDON_NAMES.iter().enumerate() {
        if let Some(config) = addons.get(*name) {
            let value = object(config, name)?.get("enabled");
            values[index] = Some(
                value
                    .map(|value| boolean(value, "addon enabled"))
                    .transpose()?
                    .unwrap_or(true),
            );
        }
    }
    Ok(values)
}

fn parse_override(pattern: &str, fields: &Map<String, Value>) -> Result<Override> {
    Ok(Override {
        pattern: pattern.into(),
        bypass: fields
            .get("bypass")
            .map(|value| {
                string_array(value, "bypass")
                    .map(|values| ADDON_NAMES.map(|name| values.iter().any(|value| value == name)))
            })
            .transpose()?
            .unwrap_or([false; ADDON_COUNT]),
        enabled: addon_enabled_values(fields.get("addons"))?,
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
pub(crate) fn host_matches(host: &str, pattern: &str) -> bool {
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
    crate::services::resource_matches(resource, pattern)
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
    fn toml_large_integer_adapter_preserves_exact_values_and_other_scalars() {
        let source = concat!(
            "quoted = \"18446744073709551617\"\n",
            "marker = \"__safeyolo_large_toml_integer__:18446744073709551617\"\n",
            "float = 1.25e2\n",
            "date = 2024-01-01T00:00:00Z\n",
            "integer = 18446744073709551617\n",
            "underscored = +9_223_372_036_854_775_808\n",
            "nested = { value = 9223372036854775808 }\n",
        );
        let parsed = parse_toml_document(source).unwrap();
        assert_eq!(parsed["quoted"], "18446744073709551617");
        assert_eq!(
            parsed["marker"],
            "__safeyolo_large_toml_integer__:18446744073709551617"
        );
        assert_eq!(parsed["float"].as_f64(), Some(125.0));
        assert_eq!(
            parsed["date"]["$__toml_private_datetime"],
            "2024-01-01T00:00:00Z"
        );
        assert_eq!(
            parsed["integer"].as_number().unwrap().to_string(),
            "18446744073709551617"
        );
        assert_eq!(
            parsed["nested"]["value"].as_number().unwrap().to_string(),
            "9223372036854775808"
        );
        assert_eq!(
            parsed["underscored"].as_number().unwrap().to_string(),
            "9223372036854775808"
        );
        let (editable, context) = parse_toml_for_edit(source).unwrap();
        let restored = restore_large_toml_integers(&editable.to_string(), &context);
        assert!(restored.contains("integer = 18446744073709551617"));
        assert!(restored.contains("value = 9223372036854775808"));
        assert!(restored.contains("quoted = \"18446744073709551617\""));
        assert!(restored.contains("underscored = +9_223_372_036_854_775_808"));
        assert!(parse_toml_document("number = 09223372036854775808\n").is_err());
        assert!(parse_toml_document("number = 9__223372036854775808\n").is_err());
        for signed_radix in [
            "+0x8000000000000000",
            "+0o1000000000000000000000",
            "+0b1000000000000000000000000000000000000000000000000000000000000000",
            "-0x8000000000000000",
        ] {
            assert!(
                parse_toml_document(&format!("number = {signed_radix}\n")).is_err(),
                "{signed_radix}"
            );
        }
        let radix_source = concat!(
            "hex = 0x8000000000000000\n",
            "octal = 0o1000000000000000000000\n",
            "binary = 0b1000000000000000000000000000000000000000000000000000000000000000\n",
        );
        let radix_values = parse_toml_document(radix_source).unwrap();
        for key in ["hex", "octal", "binary"] {
            assert_eq!(
                radix_values[key].as_number().unwrap().to_string(),
                "9223372036854775808"
            );
        }
        let (radix_document, radix_context) = parse_toml_for_edit(radix_source).unwrap();
        assert_eq!(
            restore_large_toml_integers(&radix_document.to_string(), &radix_context),
            radix_source
        );
        let table_key = "[9223372036854775808]\nvalue = 1\n";
        assert_eq!(
            parse_toml_document(table_key).unwrap()["9223372036854775808"]["value"],
            1
        );
    }

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
    fn vault_timestamps_keep_type_through_aliases_and_effective_merges() {
        for field in [
            "name",
            "type",
            "value",
            "refresh_token",
            "token_url",
            "client_id",
            "client_secret",
            "expires_at",
        ] {
            for timestamp in [
                "2026-01-01",
                "2026-01-01T00:00:00Z",
                "!!timestamp '2026-01-01T00:00:00Z'",
            ] {
                let source = format!("credentials: [{{{field}: {timestamp}}}]");
                assert_eq!(
                    parse_yaml_for_vault(&source).unwrap_err().kind,
                    ErrorKind::Invalid,
                    "{source}"
                );
                // Existing policy/service callers still receive their previous
                // normalized timestamp representation from the same frontend.
                assert!(parse_yaml(&source).is_ok());
            }
        }
        for (source, accepted) in [
            ("credentials: [{expires_at: '2026-01-01T00:00:00Z'}]", true),
            (
                "credentials: [{expires_at: !!str 2026-01-01T00:00:00Z}]",
                true,
            ),
            (
                "ignored: 2026-01-01T00:00:00Z\ncredentials: [{extra: !!timestamp '2026-01-01'}]",
                true,
            ),
            (
                "ignored: &stamp 2026-01-01T00:00:00Z\ncredentials: [{expires_at: *stamp}]",
                false,
            ),
            (
                "ignored: &stamp '2026-01-01T00:00:00Z'\ncredentials: [{expires_at: *stamp}]",
                true,
            ),
            (
                "ignored: &record {expires_at: 2026-01-01T00:00:00Z}\ncredentials: [*record]",
                false,
            ),
            (
                "ignored: &records [{expires_at: 2026-01-01T00:00:00Z}]\ncredentials: *records",
                false,
            ),
            (
                "defaults: &d {expires_at: 2026-01-01T00:00:00Z}\ncredentials: [{<<: *d}]",
                false,
            ),
            (
                "defaults: &d {expires_at: 2026-01-01T00:00:00Z}\ncredentials: [{<<: *d, expires_at: '2027-01-01T00:00:00Z'}]",
                true,
            ),
            (
                "a: &a {expires_at: '2026-01-01T00:00:00Z'}\nb: &b {expires_at: 2026-01-01T00:00:00Z}\ncredentials: [{<<: [*a, *b]}]",
                true,
            ),
            (
                "a: &a {expires_at: '2026-01-01T00:00:00Z'}\nb: &b {expires_at: 2026-01-01T00:00:00Z}\ncredentials: [{<<: [*b, *a]}]",
                false,
            ),
            (
                "credentials: [{expires_at: 2026-01-01T00:00:00Z, expires_at: '2027-01-01T00:00:00Z'}]",
                true,
            ),
            (
                "credentials: [{extra: {expires_at: 2026-01-01T00:00:00Z}}]",
                true,
            ),
        ] {
            let result = parse_yaml_for_vault(source);
            assert_eq!(result.is_ok(), accepted, "{source}");
            if let Ok(value) = result {
                assert_eq!(value, parse_yaml(source).unwrap());
            }
        }
        for source in ["x: {<<: 2026-01-01}", "x: {<<: [2026-01-01]}"] {
            assert_eq!(parse_yaml(source).unwrap_err().kind, ErrorKind::Invalid);
            assert_eq!(
                parse_yaml_for_vault(source).unwrap_err().kind,
                ErrorKind::Invalid
            );
        }
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

#[cfg(test)]
mod load_tests;

#[cfg(test)]
mod task_activation_tests {
    use super::*;

    fn request(host: &str) -> NetworkRequest<'_> {
        NetworkRequest {
            agent: None,
            host,
            port: Some(443),
            method: "GET",
            path: "/",
        }
    }

    #[test]
    fn activation_replacement_and_clear_share_enforcement_config_and_hash() {
        let baseline = Policy::parse(
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"allow"}]}"#,
            Format::Json,
        )
        .unwrap();
        let first = serde_json::json!({
            "permissions":[{"action":"network:request","resource":"target.invalid/*","effect":"deny"}]
        });
        let replacement = serde_json::json!({
            "permissions":[{"action":"network:request","resource":"other.invalid/*","effect":"deny"}]
        });
        let active = baseline.with_task_document(&first).unwrap();
        assert_eq!(
            active
                .evaluate(request("target.invalid"), 0., false)
                .unwrap()
                .effect,
            Effect::Deny
        );
        let first_config = active.sensor_config().unwrap();
        assert_eq!(first_config["policy_hash"], active.policy_hash());
        assert_ne!(active.policy_hash(), baseline.policy_hash());

        let replaced = active.with_task_document(&replacement).unwrap();
        assert_eq!(
            replaced
                .evaluate(request("target.invalid"), 0., false)
                .unwrap()
                .effect,
            Effect::Allow
        );
        assert_eq!(
            replaced
                .evaluate(request("other.invalid"), 0., false)
                .unwrap()
                .effect,
            Effect::Deny
        );
        let replaced_config = replaced.sensor_config().unwrap();
        assert_eq!(replaced_config["policy_hash"], replaced.policy_hash());
        assert_ne!(replaced.policy_hash(), active.policy_hash());

        let cleared = replaced.without_task();
        assert_eq!(cleared.policy_hash(), baseline.policy_hash());
        assert_eq!(
            cleared.sensor_config().unwrap()["policy_hash"],
            cleared.policy_hash()
        );
        assert_eq!(
            cleared
                .evaluate(request("target.invalid"), 0., false)
                .unwrap()
                .effect,
            Effect::Allow
        );
        assert!(
            active
                .with_task_document(&serde_json::json!({"permissions":false}))
                .is_err()
        );
        assert_eq!(active.policy_hash(), first_config["policy_hash"]);
    }
}
