//! Test-context parsing and declaration decisions, inactive in transport.
//!
//! Context `agent` is a caller-supplied provenance claim, never trusted identity.
//! The caller supplies authenticated source/agent identity and the existing trusted
//! flow metadata separately. Only the declared fallback resolves/stamps identity
//! in the Python addon; an explicit header uses preexisting metadata for its match
//! flag. Applied metadata contains no replacement for the trusted `agent` field.
//!
//! Target-host configuration reloads only when policy_hash changes. Declaration
//! enable/TTL settings and inherited block/warn options are evaluated independently.
//! Declaring context remains allowed when injection is disabled or targets are empty.
//! Declarations are process-local, capped only by configured TTL, and expire using
//! caller-supplied monotonic seconds. An agent mismatch evicts a reused source slot;
//! DELETE clears that caller's source slot even if it held the former agent's record.
//!
//! Callers own bearer authentication, authoritative identity resolution, config
//! cache availability, header serialization, request/response audit emission and
//! FlowStore recording. This module returns decisions and metadata updates, not
//! a flow/addon framework. Response recording uses the applied context and the
//! request-id start_time; body snippets are the first 512 characters of capture_body.
//! The shared Python atomic context-file writer remains a CLI producer helper.
//! Header formatting here does not publish files or install a watcher.

use num_bigint::BigInt;
use serde::Serialize;
use serde_json::{Map, Number, Value, json};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use crate::policy::{host_matches, python_whitespace};

pub const HEADER: &str = "X-SafeYolo-Test-Context";
pub const CANONICAL_KEYS: [&str; 9] = [
    "run", "agent", "role", "suite", "subject", "step", "test", "intent", "expect",
];
pub const MAX_CONTEXT_PAIRS: usize = 20;
const LIVE_KEYS: [&str; 9] = [
    "test_run",
    "test_agent",
    "test_role",
    "test_suite",
    "test_subject",
    "test_step",
    "test_id",
    "test_intent",
    "test_expect",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextError(pub String);
impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ContextError {}
type Result<T> = std::result::Result<T, ContextError>;
fn invalid(message: impl Into<String>) -> ContextError {
    ContextError(message.into())
}
fn trim(value: &str) -> &str {
    value.trim_matches(python_whitespace)
}
// Parser errors are returned verbatim by the existing Agent API.
fn python_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::from(quote);
    for character in value.chars() {
        if character == quote || character == '\\' {
            result.push('\\');
            result.push(character);
        } else if matches!(character, '\n' | '\r' | '\t') {
            result.push_str(&character.escape_debug().to_string());
        } else if character.is_control() || character.escape_debug().to_string().starts_with("\\u{")
        {
            let code = character as u32;
            result.push_str(&if code <= 0xff {
                format!("\\x{code:02x}")
            } else if code <= 0xffff {
                format!("\\u{code:04x}")
            } else {
                format!("\\U{code:08x}")
            });
        } else {
            result.push(character);
        }
    }
    result.push(quote);
    result
}
fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || b"_.:-".contains(&value))
}

/// Construction validates required fields and duplicates before declarations can
/// accept a context. Extra safe fields remain available in nested test_context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Context(Map<String, Value>);
impl Context {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Result<Self> {
        let mut fields = Map::new();
        for (key, value) in pairs {
            if key.is_empty() {
                return Err(invalid("context key must be a non-empty string"));
            }
            if value.is_empty() {
                return Err(invalid(format!(
                    "context value for {} must be a non-empty string",
                    python_repr(&key)
                )));
            }
            if !safe_token(&key) {
                return Err(invalid(format!(
                    "context key {} contains characters outside [A-Za-z0-9_.:-]",
                    python_repr(&key)
                )));
            }
            if !safe_token(&value) {
                return Err(invalid(format!(
                    "context value for {} contains characters outside [A-Za-z0-9_.:-]",
                    python_repr(&key)
                )));
            }
            if fields.contains_key(&key) {
                return Err(invalid(format!("duplicate context key: {key}")));
            }
            fields.insert(key, Value::String(value));
            if fields.len() > MAX_CONTEXT_PAIRS {
                return Err(invalid(format!(
                    "context has more than {MAX_CONTEXT_PAIRS} key/value pairs"
                )));
            }
        }
        let missing: Vec<_> = ["run", "agent"]
            .into_iter()
            .filter(|key| !fields.contains_key(*key))
            .collect();
        if !missing.is_empty() {
            return Err(invalid(format!(
                "missing required context field(s): {}",
                missing.join(", ")
            )));
        }
        Ok(Self(fields))
    }
    pub fn parse(value: &str) -> Result<Self> {
        if trim(value).is_empty() {
            return Err(invalid("context header value must not be empty"));
        }
        let mut pairs = Vec::new();
        for part in value.split(';').map(trim).filter(|part| !part.is_empty()) {
            let (key, value) = part.split_once('=').ok_or_else(|| {
                invalid(format!(
                    "context field has no '=' separator: {}",
                    python_repr(part)
                ))
            })?;
            pairs.push((trim(key).to_owned(), trim(value).to_owned()));
        }
        Self::from_pairs(pairs)
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }
    pub fn fields(&self) -> &Map<String, Value> {
        &self.0
    }
    pub fn format(&self) -> String {
        let mut keys: Vec<_> = self.0.keys().collect();
        keys.sort_by_key(|key| {
            (
                CANONICAL_KEYS
                    .iter()
                    .position(|canonical| canonical == key)
                    .unwrap_or(CANONICAL_KEYS.len()),
                key.as_str(),
            )
        });
        keys.into_iter()
            .map(|key| format!("{key}={}", self.get(key).unwrap()))
            .collect::<Vec<_>>()
            .join(";")
    }
    pub fn header_line(&self) -> String {
        format!("{HEADER}: {}", self.format())
    }
}

/// These values must come from authenticated transport/service discovery, never
/// from context fields or an API body. Validation alone does not authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIdentity {
    source: String,
    agent: String,
}
impl TrustedIdentity {
    pub fn new(source: impl Into<String>, agent: impl Into<String>) -> Result<Self> {
        let source = source.into();
        let agent = agent.into();
        if source.is_empty() || source == "unknown" {
            return Err(invalid("invalid source identity"));
        }
        if agent.is_empty() || matches!(agent.as_str(), "unknown" | "default") {
            return Err(invalid("invalid trusted agent"));
        }
        Ok(Self { source, agent })
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn agent(&self) -> &str {
        &self.agent
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub block: bool,
    pub inject_declared: bool,
    pub declared_ttl: Value,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            block: true,
            inject_declared: false,
            declared_ttl: json!(900),
        }
    }
}
#[derive(Debug, Clone)]
struct Config {
    targets: Vec<String>,
    last_hash: Value,
    options: Options,
    inject: bool,
    ttl_max: Number,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            last_hash: json!(""),
            options: Options::default(),
            inject: false,
            ttl_max: Number::from(900),
        }
    }
}
fn positive_integer(value: &Value) -> Option<Number> {
    let number = value.as_number()?;
    let integer = number.to_string().parse::<BigInt>().ok()?;
    (integer > BigInt::from(0)).then(|| number.clone())
}
fn smaller(left: Number, right: &Number) -> Number {
    if left.to_string().parse::<BigInt>().unwrap() < right.to_string().parse::<BigInt>().unwrap() {
        left
    } else {
        right.clone()
    }
}
fn check_time(now: f64) -> Result<()> {
    if now.is_finite() {
        Ok(())
    } else {
        Err(invalid("monotonic time must be finite"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Declaration {
    pub context: Context,
    pub expires_in: Number,
}
#[derive(Debug, Clone)]
struct Record {
    agent: String,
    context: Context,
    expires_at: f64,
}
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Stats {
    pub active: bool,
    pub target_hosts: usize,
    pub checks_total: u64,
    pub allowed_total: u64,
    pub blocked_total: u64,
    pub warned_total: u64,
    pub declared_injections_total: u64,
    pub declared_active: usize,
}
#[derive(Default)]
struct State {
    config: Config,
    declarations: BTreeMap<String, Record>,
    stats: Stats,
}
fn lookup(state: &mut State, identity: &TrustedIdentity, now: f64) -> Result<Option<Declaration>> {
    let Some(record) = state.declarations.get(identity.source()) else {
        return Ok(None);
    };
    if record.agent != identity.agent || now >= record.expires_at {
        state.declarations.remove(identity.source());
        return Ok(None);
    }
    let seconds = (record.expires_at - now).ceil().max(1.);
    if !seconds.is_finite() {
        return Err(invalid("remaining ttl exceeds monotonic clock range"));
    }
    Ok(Some(Declaration {
        context: record.context.clone(),
        expires_in: format!("{seconds:.0}")
            .parse()
            .expect("finite nonnegative integral float"),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSource {
    Header,
    Declared,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppliedContext {
    pub context: Context,
    pub source: ContextSource,
    pub trusted_agent: Option<String>,
    pub test_agent_match: Option<bool>,
    /// Merge these entries into the existing metadata. Python retains optional
    /// fields from prior metadata when the current context does not name them.
    pub live_metadata: Map<String, Value>,
}
fn apply_context(
    context: Context,
    source: ContextSource,
    trusted_agent: Option<&str>,
) -> AppliedContext {
    let mut live = Map::new();
    live.insert(
        "test_context".into(),
        Value::Object(context.fields().clone()),
    );
    live.insert("test_context_source".into(), json!(source));
    for (key, metadata) in CANONICAL_KEYS.into_iter().zip(LIVE_KEYS) {
        if let Some(value) = context.get(key) {
            live.insert(metadata.into(), json!(value));
        }
    }
    let test_agent_match = trusted_agent.map(|agent| Some(agent) == context.get("agent"));
    if let Some(value) = test_agent_match {
        live.insert("test_agent_match".into(), json!(value));
    }
    AppliedContext {
        context,
        source,
        trusted_agent: trusted_agent.map(str::to_owned),
        test_agent_match,
        live_metadata: live,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    MissingContext,
    MalformedContext,
    MalformedOptionalContext,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RequestOutcome {
    PriorResponse,
    NotTargetHost,
    Applied {
        applied: AppliedContext,
    },
    Warn {
        reason: Reason,
        resolved_agent: Option<String>,
    },
    Block {
        reason: Reason,
        resolved_agent: Option<String>,
        status: u16,
        body: Value,
    },
}
impl RequestOutcome {
    /// The declared-fallback path resolves trusted identity even if its record
    /// is missing or expired. The caller stamps this value before audit/recording;
    /// explicit headers never change trusted identity.
    pub fn trusted_identity_update(&self) -> Option<&str> {
        match self {
            Self::Applied { applied } if applied.source == ContextSource::Declared => {
                applied.trusted_agent.as_deref()
            }
            Self::Warn { resolved_agent, .. } | Self::Block { resolved_agent, .. } => {
                resolved_agent.as_deref()
            }
            _ => None,
        }
    }
}
pub struct Request<'a> {
    pub host: &'a str,
    pub prior_response: bool,
    pub identity: Option<&'a TrustedIdentity>,
    /// Existing trusted flow.metadata["agent"], used by the explicit-header path.
    pub metadata_agent: Option<&'a str>,
}
pub type Header = (String, Vec<u8>);

#[derive(Clone, Default)]
pub struct TestContext {
    state: Arc<Mutex<State>>,
}
impl TestContext {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| invalid("test-context state lock poisoned"))
    }
    /// None represents unavailable policy configuration: retain existing targets,
    /// and use option fallbacks for declaration settings. No new enable flag.
    pub fn configure(&self, sensor: Option<&Value>, options: Options) -> Result<()> {
        let mut state = self.lock()?;
        let mut candidate = state.config.clone();
        let section = sensor.and_then(|sensor| sensor.pointer("/addons/test_context"));
        if let Some(section) = section
            && !section.is_object()
        {
            return Err(invalid("test_context config must be an object"));
        }
        if let Some(sensor) = sensor {
            let hash = sensor.get("policy_hash").cloned().unwrap_or(json!(""));
            if hash != candidate.last_hash {
                let targets = section.and_then(|section| section.get("target_hosts"));
                candidate.targets = match targets {
                    None => Vec::new(),
                    Some(Value::Array(values)) => values
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| invalid("target host must be a string"))
                        })
                        .collect::<Result<_>>()?,
                    _ => return Err(invalid("target_hosts must be an array")),
                };
                candidate.last_hash = hash;
            }
        }
        candidate.inject = section
            .and_then(|section| section.get("inject_declared"))
            .and_then(Value::as_bool)
            .unwrap_or(options.inject_declared);
        candidate.ttl_max = section
            .and_then(|section| section.get("declared_ttl_max"))
            .and_then(positive_integer)
            .or_else(|| positive_integer(&options.declared_ttl))
            .unwrap_or(Number::from(900));
        candidate.options = options;
        state.config = candidate;
        Ok(())
    }
    pub fn set_declaration(
        &self,
        identity: &TrustedIdentity,
        context: Context,
        ttl: Option<&Value>,
        now: f64,
    ) -> Result<Number> {
        check_time(now)?;
        let mut state = self.lock()?;
        let granted = match ttl.filter(|value| !value.is_null()) {
            None => state.config.ttl_max.clone(),
            Some(value) => smaller(
                positive_integer(value).ok_or_else(|| invalid("ttl must be a positive integer"))?,
                &state.config.ttl_max,
            ),
        };
        let seconds = granted
            .to_string()
            .parse::<f64>()
            .map_err(|_| invalid("ttl exceeds monotonic clock range"))?;
        let expires_at = now + seconds;
        if !expires_at.is_finite() {
            return Err(invalid("ttl exceeds monotonic clock range"));
        }
        state.declarations.insert(
            identity.source.clone(),
            Record {
                agent: identity.agent.clone(),
                context,
                expires_at,
            },
        );
        Ok(granted)
    }
    pub fn get_declaration(
        &self,
        identity: &TrustedIdentity,
        now: f64,
    ) -> Result<Option<Declaration>> {
        check_time(now)?;
        let mut state = self.lock()?;
        lookup(&mut state, identity, now)
    }
    pub fn clear_declaration(&self, identity: &TrustedIdentity) -> Result<bool> {
        Ok(self
            .lock()?
            .declarations
            .remove(identity.source())
            .is_some())
    }
    pub fn stats(&self, now: f64) -> Result<Stats> {
        check_time(now)?;
        let mut state = self.lock()?;
        state
            .declarations
            .retain(|_, record| now < record.expires_at);
        let mut stats = state.stats.clone();
        stats.active = !state.config.targets.is_empty();
        stats.target_hosts = state.config.targets.len();
        stats.declared_active = state.declarations.len();
        Ok(stats)
    }
    /// Strip every reserved-header occurrence, except a prior-response bypass
    /// where Python does not touch the already-answered flow. Duplicate values
    /// join with comma-space before parsing, matching mitmproxy Headers.get().
    pub fn request(
        &self,
        request: Request<'_>,
        headers: &mut Vec<Header>,
        now: f64,
    ) -> Result<RequestOutcome> {
        if request.prior_response {
            return Ok(RequestOutcome::PriorResponse);
        }
        check_time(now)?;
        let mut value = Vec::new();
        let mut seen = false;
        for (_, part) in headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(HEADER))
        {
            if seen {
                value.extend_from_slice(b", ");
            }
            seen = true;
            value.extend_from_slice(part);
        }
        headers.retain(|(name, _)| !name.eq_ignore_ascii_case(HEADER));
        let mut state = self.lock()?;
        let target = state
            .config
            .targets
            .iter()
            .any(|pattern| host_matches(request.host, pattern));
        if !target && value.is_empty() {
            return Ok(RequestOutcome::NotTargetHost);
        }
        state.stats.checks_total += 1;
        let context = std::str::from_utf8(&value)
            .ok()
            .and_then(|value| Context::parse(value).ok());
        let resolved_agent = (target && value.is_empty() && state.config.inject)
            .then(|| request.identity.map(|identity| identity.agent.clone()))
            .flatten();
        let applied = if let Some(context) = context {
            Some(apply_context(
                context,
                ContextSource::Header,
                request.metadata_agent,
            ))
        } else if !target {
            state.stats.warned_total += 1;
            return Ok(RequestOutcome::Warn {
                reason: Reason::MalformedOptionalContext,
                resolved_agent: None,
            });
        } else if value.is_empty() && state.config.inject {
            match request.identity {
                Some(identity) => lookup(&mut state, identity, now)?.map(|record| {
                    apply_context(
                        record.context,
                        ContextSource::Declared,
                        Some(identity.agent()),
                    )
                }),
                None => None,
            }
        } else {
            None
        };
        if let Some(applied) = applied {
            state.stats.allowed_total += 1;
            if applied.source == ContextSource::Declared {
                state.stats.declared_injections_total += 1;
            }
            return Ok(RequestOutcome::Applied { applied });
        }
        let reason = if value.is_empty() {
            Reason::MissingContext
        } else {
            Reason::MalformedContext
        };
        if state.config.options.block {
            state.stats.blocked_total += 1;
            let body = json!({"error":"Test context required","type":reason,"destination":request.host,"action":"add_header","header":HEADER,
                "format":"run=<run_id>;agent=<agent_id>;test=<test_id>","example":format!("{HEADER}: run=sec1;agent=idor;test=IDOR-003"),
                "reflection":format!("Add {HEADER} header to link this request to your test activity.")});
            Ok(RequestOutcome::Block {
                reason,
                resolved_agent,
                status: 428,
                body,
            })
        } else {
            state.stats.warned_total += 1;
            Ok(RequestOutcome::Warn {
                reason,
                resolved_agent,
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApiOutcome {
    pub status: u16,
    pub body: Value,
    pub audit: Option<ApiAudit>,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApiAudit {
    pub event: &'static str,
    pub source_id: String,
    pub trusted_agent: String,
    pub details: Value,
}
fn response(status: u16, body: Value) -> ApiOutcome {
    ApiOutcome {
        status,
        body,
        audit: None,
    }
}
/// Inner /api/test-context/current handler. The outer Agent API must authenticate
/// its bearer before calling. Body source_id/agent fields are never authority.
pub fn api_current(
    owner: Option<&TestContext>,
    source: Option<&str>,
    agent: Option<&str>,
    method: &str,
    body: Option<&Value>,
    now: f64,
) -> Result<ApiOutcome> {
    let Some(agent) =
        agent.filter(|agent| !agent.is_empty() && !matches!(*agent, "unknown" | "default"))
    else {
        return Ok(response(403, json!({"error":"Could not identify agent"})));
    };
    let Some(source) = source.filter(|source| !source.is_empty() && *source != "unknown") else {
        return Ok(response(403, json!({"error":"Could not identify source"})));
    };
    let identity = TrustedIdentity::new(source, agent)?;
    let Some(owner) = owner else {
        return Ok(response(
            503,
            json!({"error":"test-context addon not loaded"}),
        ));
    };
    match method {
        "GET" => Ok(response(
            200,
            match owner.get_declaration(&identity, now)? {
                Some(record) => {
                    json!({"agent":agent,"context":record.context,"expires_in":record.expires_in})
                }
                None => json!({"agent":agent,"context":null}),
            },
        )),
        "DELETE" => {
            let existed = owner.clear_declaration(&identity)?;
            Ok(ApiOutcome {
                status: 200,
                body: json!({"status":"cleared"}),
                audit: Some(ApiAudit {
                    event: "security.test_context_cleared",
                    source_id: source.into(),
                    trusted_agent: agent.into(),
                    details: json!({"source_id":source,"trusted_agent":agent,"had_declaration":existed}),
                }),
            })
        }
        "POST" => {
            let Some(body) = body.and_then(Value::as_object) else {
                return Ok(response(400, json!({"error":"Invalid JSON body"})));
            };
            let Some(context) = body.get("context").and_then(Value::as_str) else {
                return Ok(response(
                    400,
                    json!({"error":"context must be a string","format":"run=<run_id>;agent=<agent_id>;test=<test_id>"}),
                ));
            };
            let context = match Context::parse(context) {
                Ok(context) => context,
                Err(error) => {
                    return Ok(response(
                        400,
                        json!({"error":"Invalid test context","detail":error.to_string(),"format":"run=<run_id>;agent=<agent_id>;test=<test_id>","example":"run=sec1;agent=idor;test=IDOR-003;intent=probe;expect=blocked"}),
                    ));
                }
            };
            let ttl = body.get("ttl").filter(|value| !value.is_null());
            if ttl.is_some_and(|value| positive_integer(value).is_none()) {
                return Ok(response(
                    400,
                    json!({"error":"ttl must be a positive integer (seconds)"}),
                ));
            }
            let granted = match owner.set_declaration(&identity, context.clone(), ttl, now) {
                Ok(granted) => granted,
                Err(error) => return Ok(response(400, json!({"error":error.to_string()}))),
            };
            let details = json!({"source_id":source,"trusted_agent":agent,"declared_agent":context.get("agent"),"test_agent_match":context.get("agent")==Some(agent),"context":context,"requested_ttl":ttl,"granted_ttl":granted});
            Ok(ApiOutcome {
                status: 200,
                body: json!({"status":"set","agent":agent,"expires_in":granted,"context":context}),
                audit: Some(ApiAudit {
                    event: "security.test_context_declared",
                    source_id: source.into(),
                    trusted_agent: agent.into(),
                    details,
                }),
            })
        }
        _ => Ok(response(
            405,
            json!({"error":"Method Not Allowed","allowed":["GET","POST","DELETE"]}),
        )),
    }
}

pub fn capture_body(content: &[u8], max_head: usize, tail_lines: usize) -> String {
    if content.is_empty() {
        return String::new();
    }
    let head = String::from_utf8_lossy(&content[..content.len().min(max_head)]);
    if content.len() <= max_head {
        return head.into_owned();
    }
    let tail = String::from_utf8_lossy(&content[content.len().saturating_sub(8192)..]);
    let lines: Vec<_> = tail.trim_end_matches('\n').split('\n').collect();
    let tail = if lines.len() > tail_lines {
        lines[if tail_lines == 0 {
            0
        } else {
            lines.len() - tail_lines
        }..]
            .join("\n")
    } else {
        String::new()
    };
    format!(
        "{head}\n...[truncated, {} bytes total]...\n{tail}",
        content.len()
    )
}
