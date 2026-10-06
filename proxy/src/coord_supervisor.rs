//! Bounded harness turns over canonical Coord attention and local recovery state.

mod preflight;
mod process;

use crate::{
    Error,
    coord_tools::{Client, attention_id, target_url, text},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

const STATE_SCHEMA: &str = "safeyolo.coord-supervisor/v1";
const MAX_PENDING: usize = 16;
const MAX_RECENT: usize = 256;
const MAX_BODY: usize = 64 * 1024;
const MAX_STATE: usize = 2 * 1024 * 1024;

pub fn simple_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn type_name(name: &str) -> bool {
    name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub request: String,
    #[serde(rename = "from")]
    pub source: String,
    #[serde(rename = "to")]
    pub destination: String,
    pub responses: Vec<String>,
    #[serde(default)]
    pub response_to: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "from")]
    pub source: String,
    #[serde(rename = "to")]
    pub destination: String,
    pub fields: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repair {
    pub request: String,
    #[serde(rename = "from")]
    pub source: String,
    pub args: Vec<String>,
    pub after_rounds: u64,
    pub max_rounds: u64,
    pub release_on: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorInput {
    pub to: String,
    pub types: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Factory {
    pub schema: String,
    pub name: String,
    pub role: String,
    pub roles: BTreeMap<String, String>,
    pub handoffs: Vec<Handoff>,
    pub operator_input: OperatorInput,
    pub contract_sha256: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub updates: Vec<Update>,
    #[serde(default)]
    pub repairs: BTreeMap<String, Repair>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub agent_name: String,
    pub rooms: Vec<String>,
    pub coordinators: Vec<String>,
    pub harness: String,
    pub agent_room: Option<String>,
    pub factory: Option<Factory>,
    pub workspace: PathBuf,
    pub wait_seconds: u64,
    pub page_limit: usize,
    pub startup_timeout_seconds: u64,
    pub work_timeout_seconds: u64,
    pub completion_grace_seconds: u64,
    pub terminate_grace_seconds: u64,
    pub backoff_initial_seconds: u64,
    pub backoff_max_seconds: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            agent_name: String::new(),
            rooms: vec![],
            coordinators: vec![],
            harness: "codex".into(),
            agent_room: None,
            factory: None,
            workspace: "/workspace".into(),
            wait_seconds: 300,
            page_limit: 16,
            startup_timeout_seconds: 480,
            work_timeout_seconds: 3600,
            completion_grace_seconds: 90,
            terminate_grace_seconds: 10,
            backoff_initial_seconds: 5,
            backoff_max_seconds: 300,
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let value = read(path)?;
        let config: Self = serde_json::from_value(value)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if !simple_name(&self.agent_name)
            || self.rooms.is_empty()
            || self.coordinators.is_empty()
            || self
                .rooms
                .iter()
                .chain(&self.coordinators)
                .any(|n| !simple_name(n))
            || self.agent_room.as_ref().is_some_and(|n| !simple_name(n))
            || !["codex", "pi"].contains(&self.harness.as_str())
            || !self.workspace.is_absolute()
        {
            return Err(
                "invalid supervisor agent, rooms, coordinators, harness or workspace".into(),
            );
        }
        for (name, value, min, max) in [
            ("wait_seconds", self.wait_seconds, 1, 300),
            ("page_limit", self.page_limit as u64, 1, 16),
            (
                "startup_timeout_seconds",
                self.startup_timeout_seconds,
                30,
                3600,
            ),
            ("work_timeout_seconds", self.work_timeout_seconds, 30, 86400),
            (
                "completion_grace_seconds",
                self.completion_grace_seconds,
                5,
                600,
            ),
            (
                "terminate_grace_seconds",
                self.terminate_grace_seconds,
                1,
                60,
            ),
            (
                "backoff_initial_seconds",
                self.backoff_initial_seconds,
                1,
                300,
            ),
            ("backoff_max_seconds", self.backoff_max_seconds, 1, 3600),
        ] {
            if !(min..=max).contains(&value) {
                return Err(format!("{name} must be from {min} to {max}").into());
            }
        }
        if self.backoff_initial_seconds > self.backoff_max_seconds {
            return Err("invalid supervisor backoff bounds".into());
        }
        if let Some(f) = &self.factory {
            if f.schema != "safeyolo.factory/v1"
                || !simple_name(&f.name)
                || f.roles.get(&f.role) != Some(&self.agent_name)
                || f.roles
                    .iter()
                    .any(|(r, a)| !simple_name(r) || !simple_name(a))
                || !hash(&f.contract_sha256)
                || !hash(&f.snapshot_id)
                || f.handoffs.is_empty()
                || !f.roles.contains_key(&f.operator_input.to)
                || f.operator_input.types.is_empty()
                || f.operator_input.types.iter().any(|t| !type_name(t))
            {
                return Err("invalid factory role binding".into());
            }
            let mut reserved = BTreeSet::from(["PROTOCOL_WARNING".to_owned()]);
            for h in &f.handoffs {
                if !type_name(&h.request)
                    || !f.roles.contains_key(&h.source)
                    || !f.roles.contains_key(&h.destination)
                    || h.responses.is_empty()
                    || h.responses.iter().any(|t| !type_name(t))
                    || (!h.response_to.is_empty()
                        && (!h.response_to.contains(&h.source)
                            || h.response_to.iter().any(|r| !f.roles.contains_key(r))
                            || !unique(&h.response_to)))
                {
                    return Err("invalid factory handoff".into());
                }
                reserved.insert(h.request.clone());
                reserved.extend(h.responses.iter().cloned());
            }
            if f.operator_input.types.iter().any(|t| reserved.contains(t))
                || !unique(&f.operator_input.types)
            {
                return Err("operator input overlaps handoff types".into());
            }
            reserved.extend(f.operator_input.types.iter().cloned());
            let mut reached = BTreeSet::from([f.operator_input.to.clone()]);
            loop {
                let before = reached.len();
                for h in &f.handoffs {
                    if reached.contains(&h.source) {
                        reached.insert(h.destination.clone());
                    }
                }
                if reached.len() == before {
                    break;
                }
            }
            if f.roles.keys().any(|r| !reached.contains(r)) {
                return Err("factory role is unreachable from operator input".into());
            }
            let mut updates = BTreeSet::new();
            for u in &f.updates {
                if !type_name(&u.kind)
                    || reserved.contains(&u.kind)
                    || !f.roles.contains_key(&u.source)
                    || !f.roles.contains_key(&u.destination)
                    || !unique(&u.fields)
                    || u.fields.iter().any(|n| !field_name(n))
                    || !updates.insert((&u.kind, &u.source, &u.destination))
                {
                    return Err("invalid or duplicated factory update".into());
                }
            }
            for (role, r) in &f.repairs {
                if !f.roles.contains_key(role)
                    || !f.roles.contains_key(&r.source)
                    || !type_name(&r.request)
                    || reserved.contains(&r.request)
                    || f.updates.iter().any(|u| u.kind == r.request)
                    || r.args.is_empty()
                    || r.args.iter().any(|a| a.contains('\0'))
                    || r.after_rounds == 0
                    || r.max_rounds == 0
                    || !f
                        .handoffs
                        .iter()
                        .any(|h| &h.source == role && h.request == r.release_on)
                    || !f
                        .handoffs
                        .iter()
                        .any(|h| h.source == r.source && &h.destination == role)
                {
                    return Err("invalid factory repair policy".into());
                }
            }
        }
        Ok(())
    }
    fn incoming(&self, sender: &str, body: &str) -> Option<&Handoff> {
        let f = self.factory.as_ref()?;
        f.handoffs.iter().find(|h| {
            h.destination == f.role
                && f.roles.get(&h.source).map(String::as_str) == Some(sender)
                && request_header(body, &h.request, &self.agent_name).is_some()
        })
    }
    fn repair_policy(&self) -> Option<&Repair> {
        let f = self.factory.as_ref()?;
        f.repairs.get(&f.role)
    }
}
fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn field_name(value: &str) -> bool {
    value.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub attention_id: String,
    pub room_name: String,
    pub sender_agent_id: String,
    pub sender_agent_name: String,
    pub sequence: u64,
    pub body: String,
    pub requires_terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub protocol_warning: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Awaiting {
    pub room_name: String,
    pub request: String,
    pub recipient_agent: String,
    pub body: String,
    pub correlation: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_attention_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub attention_id: String,
    pub instruction: Pending,
    pub snapshot_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owned {
    pub pid: i32,
    pub token: String,
    pub descendants: BTreeMap<i32, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: String,
    pub harness: String,
    pub thread_id: Option<String>,
    pub safe_cursor: u64,
    pub recent_attention_ids: Vec<String>,
    pub in_flight: Vec<Pending>,
    pub awaiting_handoffs: Vec<Awaiting>,
    pub briefs: BTreeMap<String, Value>,
    pub consecutive_failures: u32,
    pub owned_process: Option<Owned>,
    pub repair_selection: Option<Selection>,
    pub phase: String,
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA.into(),
            harness: "codex".into(),
            thread_id: None,
            safe_cursor: 0,
            recent_attention_ids: vec![],
            in_flight: vec![],
            awaiting_handoffs: vec![],
            briefs: BTreeMap::new(),
            consecutive_failures: 0,
            owned_process: None,
            repair_selection: None,
            phase: "idle".into(),
        }
    }
}
impl State {
    pub fn load(path: &Path) -> Result<Self, Error> {
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        }
        let state: Self = serde_json::from_value(read(path)?)?;
        state.validate()?;
        Ok(state)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.schema != STATE_SCHEMA
            || !["codex", "pi"].contains(&self.harness.as_str())
            || !["idle", "accepted", "running", "uncertain"].contains(&self.phase.as_str())
            || self.recent_attention_ids.len() > MAX_RECENT
            || self.in_flight.len() > MAX_PENDING
            || self.awaiting_handoffs.len() > MAX_PENDING
            || self.consecutive_failures > 31
            || self
                .thread_id
                .as_ref()
                .is_some_and(|id| id.is_empty() || id.contains('\0'))
            || self.recent_attention_ids.iter().any(|id| !attention_id(id))
            || !unique(&self.recent_attention_ids)
        {
            return Err(
                "invalid native Coord checkpoint; old-product checkpoint conversion is unsupported"
                    .into(),
            );
        }
        let mut ids = BTreeSet::new();
        for p in &self.in_flight {
            validate_pending(p)?;
            if !ids.insert(&p.attention_id) || self.recent_attention_ids.contains(&p.attention_id) {
                return Err("duplicate in-flight attention".into());
            }
        }
        for a in &self.awaiting_handoffs {
            if !simple_name(&a.room_name)
                || !simple_name(&a.recipient_agent)
                || request_header(&a.body, &a.request, &a.recipient_agent)
                    != Some(a.correlation.clone())
                || a.parent_attention_id
                    .as_ref()
                    .is_some_and(|id| !attention_id(id))
            {
                return Err("invalid checkpointed handoff correlation".into());
            }
        }
        for (room, brief) in &self.briefs {
            validate_brief(room, brief)?;
        }
        let valid_token = |pid: i32, token: &str| {
            let fields: Vec<_> = token.split(':').collect();
            pid > 1
                && fields.len() == 4
                && fields[0] == "linux"
                && !fields[1].is_empty()
                && fields[2] == pid.to_string()
                && fields[3].parse::<u64>().is_ok()
        };
        if let Some(o) = &self.owned_process
            && (!valid_token(o.pid, &o.token)
                || o.descendants.len() > 64
                || o.descendants
                    .iter()
                    .any(|(pid, token)| !valid_token(*pid, token)))
        {
            return Err("invalid owned invocation identity".into());
        }
        if let Some(r) = &self.repair_selection {
            validate_pending(&r.instruction)?;
            if !attention_id(&r.attention_id)
                || !hash(&r.snapshot_id)
                || r.instruction.requires_terminal
            {
                return Err("invalid repair selection".into());
            }
        }
        Ok(())
    }
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        atomic_write(path, &serde_json::to_vec(self)?, 0o600)
    }
    fn complete(&mut self, id: &str) {
        self.in_flight.retain(|p| p.attention_id != id);
        self.remember(id);
        if self
            .repair_selection
            .as_ref()
            .is_some_and(|r| r.attention_id == id)
        {
            self.repair_selection = None;
            self.thread_id = None;
        }
    }
    fn remember(&mut self, id: &str) {
        if !self.recent_attention_ids.iter().any(|i| i == id) {
            self.recent_attention_ids.push(id.into());
            if self.recent_attention_ids.len() > MAX_RECENT {
                self.recent_attention_ids.remove(0);
            }
        }
    }
    fn objects(&self) -> Vec<&Pending> {
        if let Some(r) = &self.repair_selection {
            self.in_flight
                .iter()
                .filter(|p| p.attention_id == r.attention_id)
                .chain(std::iter::once(&r.instruction))
                .collect()
        } else {
            self.in_flight.iter().collect()
        }
    }
}
fn validate_pending(p: &Pending) -> Result<(), Error> {
    if !attention_id(&p.attention_id)
        || p.sequence == 0
        || (!p.sender_agent_name.is_empty()
            && (!simple_name(&p.sender_agent_name) || p.sender_agent_id.is_empty()))
        || (p.requires_terminal && p.sender_agent_name.is_empty())
        || !simple_name(&p.room_name)
        || p.body.len() > MAX_BODY
        || (p.protocol_warning.is_some() && p.requires_terminal)
        || (p.requires_terminal
            && header(&p.body).is_none_or(|(kind, _)| {
                request_header(&p.body, &kind, "").is_none() && kind != "TASK"
            }))
    {
        return Err("invalid in-flight object".into());
    }
    if p.requires_terminal {
        let (kind, fields) = header(&p.body).ok_or("invalid request header")?;
        if !target_url(fields.get("target").map(String::as_str).unwrap_or(""))
            || fields.len() != if kind == "TASK" { 2 } else { 1 }
            || (kind == "TASK" && fields.get("assignee").is_none_or(|name| !simple_name(name)))
        {
            return Err("invalid request correlation".into());
        }
    }
    Ok(())
}
fn validate_brief(room: &str, brief: &Value) -> Result<(), Error> {
    if !simple_name(room)
        || brief["revision"].as_u64().is_none_or(|r| r == 0)
        || brief["markdown"]
            .as_str()
            .is_none_or(|s| s.len() > MAX_BODY)
        || brief["room_id"].as_str().is_none()
        || brief["object_id"].as_str().is_none()
        || brief["content_hash"].as_str().is_none_or(|s| !hash(s))
    {
        return Err("invalid trusted brief".into());
    }
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        brief["markdown"].as_str().unwrap().as_bytes(),
    );
    let computed: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    if brief["content_hash"] != computed {
        return Err("trusted brief hash does not match".into());
    }
    Ok(())
}
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    if bytes.len() > MAX_STATE {
        return Err("native checkpoint exceeds two MiB".into());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn read(path: &Path) -> Result<Value, Error> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("checkpoint/config must be a regular file".into());
    }
    let mut data = Vec::new();
    file.take(MAX_STATE as u64 + 1).read_to_end(&mut data)?;
    if data.len() > MAX_STATE {
        return Err("checkpoint/config exceeds two MiB".into());
    }
    Ok(serde_json::from_slice(&data)?)
}
pub fn header(body: &str) -> Option<(String, BTreeMap<String, String>)> {
    let line = body.split('\n').next()?;
    let mut tokens = line.split_whitespace();
    let kind = tokens.next()?.to_owned();
    let mut fields = BTreeMap::new();
    for token in tokens {
        let (k, v) = token.split_once('=')?;
        if !field_name(k) || v.is_empty() || fields.insert(k.into(), v.into()).is_some() {
            return None;
        }
    }
    Some((kind, fields))
}
fn request_header(body: &str, expected: &str, assignee: &str) -> Option<BTreeMap<String, String>> {
    let (kind, mut fields) = header(body)?;
    if kind != expected || !target_url(fields.get("target")?) {
        return None;
    }
    if expected == "TASK" {
        if fields.len() != 2
            || fields.get("assignee")? != assignee
            || body.lines().next()?
                != format!("TASK target={} assignee={assignee}", fields.get("target")?)
        {
            return None;
        }
        fields.remove("assignee");
    } else if fields.len() != 1 {
        return None;
    }
    Some(fields)
}
fn response_matches(config: &Config, p: &Pending, body: &str) -> bool {
    let Some((kind, fields)) = header(body) else {
        return false;
    };
    if fields.len() != 2
        || fields.get("attention_id") != Some(&p.attention_id)
        || fields.get("target")
            != header(&p.body)
                .and_then(|(_, f)| f.get("target").cloned())
                .as_ref()
    {
        return false;
    }
    match &config.factory {
        None => ["DONE", "BLOCKED", "FAILED"].contains(&kind.as_str()),
        Some(_) => config
            .incoming(&p.sender_agent_name, &p.body)
            .is_some_and(|h| h.responses.contains(&kind)),
    }
}
fn response_recipients(config: &Config, p: &Pending, notify: &Value) -> bool {
    let Some(f) = &config.factory else {
        return true;
    };
    let Some(h) = config.incoming(&p.sender_agent_name, &p.body) else {
        return false;
    };
    let expected: BTreeSet<_> = if h.response_to.is_empty() {
        std::iter::once(&h.source).collect()
    } else {
        h.response_to.iter().collect()
    };
    let expected: BTreeSet<_> = expected.into_iter().map(|r| f.roles[r].as_str()).collect();
    let Some(actual) = notify.as_array() else {
        return false;
    };
    let Some(actual): Option<Vec<_>> = actual.iter().map(Value::as_str).collect() else {
        return false;
    };
    let set: BTreeSet<_> = actual.iter().copied().collect();
    actual.len() == set.len() && set == expected
}

pub struct Supervisor {
    pub config: Config,
    pub state: State,
    pub state_path: PathBuf,
    pub client: Client,
    pub harness_args: Vec<String>,
    pub initial_preflight_complete: bool,
}
impl Supervisor {
    async fn preflight(&mut self) -> Result<BTreeMap<String, String>, Error> {
        if self.client.get("/health").await?["agent_api"] != "ok" {
            return Err("Agent API is unavailable".into());
        }
        if !self.initial_preflight_complete {
            preflight::check(&self.config, &self.harness_args).await?;
            self.initial_preflight_complete = true;
        }
        let mut ids = BTreeMap::new();
        for room in self
            .config
            .rooms
            .iter()
            .chain(self.config.agent_room.iter())
        {
            let joined = self
                .client
                .call("join_room", &json!({"room_name":room}))
                .await?;
            if joined["permissions"]
                .as_array()
                .is_none_or(|p| !p.iter().any(|v| v == "receive"))
            {
                return Err(format!("room {room} lacks receive permission").into());
            }
            let id = text(&joined, "room_id")?.to_owned();
            if self.config.factory.is_some()
                && joined["brief"]["revision"].as_u64().is_some_and(|r| r > 0)
            {
                let brief = narrow_brief(&joined["brief"])?;
                validate_brief(room, &brief)?;
                if brief["room_id"] != id {
                    return Err("joined brief belongs to another room".into());
                }
                self.state.briefs.insert(room.clone(), brief);
            } else {
                self.state.briefs.remove(room);
            }
            ids.insert(id, room.clone());
        }
        self.state.briefs.retain(|room, _| {
            self.config.rooms.contains(room) || self.config.agent_room.as_ref() == Some(room)
        });
        self.state.save(&self.state_path)?;
        Ok(ids)
    }
    pub fn accept_page(
        &mut self,
        page: &Value,
        rooms: &BTreeMap<String, String>,
    ) -> Result<usize, Error> {
        let objects = page["objects"]
            .as_array()
            .filter(|o| o.len() <= self.config.page_limit)
            .ok_or("invalid resolved attention page")?;
        let next = page["next_cursor"]
            .as_u64()
            .filter(|n| *n >= self.state.safe_cursor)
            .ok_or("invalid resolved attention cursor")?;
        let mut candidate = self.state.clone();
        let mut added = 0;
        let mut page_ids = BTreeSet::new();
        for resolved in objects {
            let edge = &resolved["edge"];
            let obj = &resolved["object"];
            let id = text(edge, "attention_id")?;
            edge["revision_or_sequence"]
                .as_u64()
                .ok_or("invalid attention object sequence")?;
            if !attention_id(id) || !page_ids.insert(id) || !obj.is_object() {
                return Err("invalid resolved attention identity".into());
            }
            if candidate.recent_attention_ids.iter().any(|i| i == id)
                || candidate.in_flight.iter().any(|p| p.attention_id == id)
            {
                continue;
            }
            let Some(room) = rooms.get(text(edge, "room_id")?) else {
                candidate.remember(id);
                continue;
            };
            if edge["kind"] == "brief_changed" {
                if self.config.factory.is_some() {
                    let brief = narrow_brief(obj)?;
                    validate_brief(room, &brief)?;
                    if brief["room_id"] != edge["room_id"]
                        || brief["object_id"] != edge["object_id"]
                        || brief["revision"] != edge["revision_or_sequence"]
                    {
                        return Err("mismatched trusted brief attention".into());
                    }
                    if candidate
                        .briefs
                        .get(room)
                        .is_none_or(|b| b["revision"].as_u64() <= brief["revision"].as_u64())
                    {
                        candidate.briefs.insert(room.clone(), brief);
                    }
                }
                candidate.remember(id);
                continue;
            }
            if edge["kind"] != "message" {
                candidate.remember(id);
                continue;
            }
            let body = text(obj, "body")?.to_owned();
            let sequence = obj["sequence"]
                .as_u64()
                .ok_or("invalid canonical message sequence")?;
            if body.len() > MAX_BODY
                || obj["msg_id"] != edge["object_id"]
                || obj["sequence"] != edge["revision_or_sequence"]
            {
                return Err("invalid or mismatched canonical message".into());
            }
            let (sender, sender_id, operator) = match obj["sender_kind"].as_str() {
                Some("agent") => (
                    text(obj, "sender_agent_name")?.to_owned(),
                    text(obj, "sender_agent_id")?.to_owned(),
                    false,
                ),
                Some("operator")
                    if obj["sender_agent_name"].is_null() && obj["sender_agent_id"].is_null() =>
                {
                    (String::new(), String::new(), true)
                }
                _ => {
                    candidate.remember(id);
                    continue;
                }
            };
            let mut p = Pending {
                attention_id: id.into(),
                room_name: room.clone(),
                sender_agent_name: sender,
                sender_agent_id: sender_id,
                sequence,
                body,
                requires_terminal: false,
                protocol_warning: None,
            };
            if let Some(f) = &self.config.factory {
                if operator {
                    if self.config.agent_room.as_ref() != Some(room)
                        && f.operator_input.to != f.role
                    {
                        candidate.remember(id);
                        continue;
                    }
                } else {
                    p.requires_terminal = self.config.rooms.contains(room)
                        && self
                            .config
                            .incoming(&p.sender_agent_name, &p.body)
                            .is_some();
                    let context = self.config.rooms.contains(room)
                        && f.updates.iter().any(|u| {
                            u.destination == f.role
                                && f.roles[&u.source] == p.sender_agent_name
                                && header(&p.body).is_some_and(|(k, fields)| {
                                    k == u.kind
                                        && fields.keys().collect::<BTreeSet<_>>()
                                            == u.fields.iter().collect::<BTreeSet<_>>()
                                        && fields.get("target").is_none_or(|t| target_url(t))
                                })
                        });
                    let response = self.match_awaiting(&candidate, &p);
                    let observed = header(&p.body).is_some_and(|(k, fields)| {
                        fields.len() == 2
                            && fields
                                .get("attention_id")
                                .is_some_and(|id| attention_id(id))
                            && fields.get("target").is_some_and(|t| target_url(t))
                            && f.handoffs.iter().any(|h| {
                                h.response_to.contains(&f.role)
                                    && h.source != f.role
                                    && f.roles[&h.destination] == p.sender_agent_name
                                    && h.responses.contains(&k)
                            })
                    });
                    let repair = self.repair_control(&p);
                    if let Some(index) = response {
                        candidate.awaiting_handoffs.remove(index);
                    }
                    if !p.requires_terminal
                        && !context
                        && !observed
                        && response.is_none()
                        && !repair
                        && !p.body.starts_with("PROTOCOL_WARNING ")
                    {
                        p.protocol_warning=Some("Message header, sender route or response correlation does not match the factory contract; information only.".into());
                    }
                }
            } else if !operator {
                if !self.config.rooms.contains(room)
                    || !self.config.coordinators.contains(&p.sender_agent_name)
                    || request_header(&p.body, "TASK", &self.config.agent_name).is_none()
                {
                    candidate.remember(id);
                    continue;
                }
                p.requires_terminal = true;
            }
            if candidate.in_flight.len() >= MAX_PENDING {
                return Err("attention page exceeds checkpoint capacity".into());
            }
            candidate.in_flight.push(p);
            added += 1;
        }
        candidate.safe_cursor = next;
        self.select_repair(&mut candidate)?;
        if added > 0 {
            candidate.phase = "accepted".into();
        }
        candidate.save(&self.state_path)?;
        self.state = candidate;
        Ok(added)
    }
    fn match_awaiting(&self, state: &State, p: &Pending) -> Option<usize> {
        let f = self.config.factory.as_ref()?;
        let (kind, fields) = header(&p.body)?;
        if fields.len() != 2 || !attention_id(fields.get("attention_id")?) {
            return None;
        }
        state.awaiting_handoffs.iter().position(|a| {
            a.room_name == p.room_name
                && a.recipient_agent == p.sender_agent_name
                && a.correlation.get("target") == fields.get("target")
                && f.handoffs.iter().any(|h| {
                    h.request == a.request
                        && h.source == f.role
                        && f.roles[&h.destination] == p.sender_agent_name
                        && h.responses.contains(&kind)
                })
        })
    }
    fn repair_control(&self, p: &Pending) -> bool {
        let Some(f) = &self.config.factory else {
            return false;
        };
        let Some(r) = self.config.repair_policy() else {
            return false;
        };
        self.config.rooms.contains(&p.room_name)
            && f.roles[&r.source] == p.sender_agent_name
            && header(&p.body).is_some_and(|(k, v)| {
                k == r.request
                    && v.len() == 2
                    && v.get("target").is_some_and(|t| target_url(t))
                    && v.get("attention_id").is_some_and(|id| attention_id(id))
            })
    }
    fn select_repair(&self, state: &mut State) -> Result<(), Error> {
        for mut p in state.in_flight.clone() {
            if !self.repair_control(&p) || p.protocol_warning.is_some() {
                continue;
            }
            let (_, fields) = header(&p.body).ok_or("invalid repair selection")?;
            let valid = state.in_flight.iter().any(|task| {
                task.requires_terminal
                    && task.attention_id == fields["attention_id"]
                    && task.sender_agent_name == p.sender_agent_name
                    && header(&task.body)
                        .is_some_and(|(_, v)| v.get("target") == fields.get("target"))
            });
            if !valid
                || state
                    .repair_selection
                    .as_ref()
                    .is_some_and(|r| r.attention_id != fields["attention_id"])
            {
                p.protocol_warning=Some("Repair selection does not match an active task from this sender, or another repair is active.".into());
                if let Some(live) = state
                    .in_flight
                    .iter_mut()
                    .find(|i| i.attention_id == p.attention_id)
                {
                    *live = p;
                }
            } else {
                state.complete(&p.attention_id);
                state.thread_id = None;
                state.repair_selection = Some(Selection {
                    attention_id: fields["attention_id"].clone(),
                    instruction: p,
                    snapshot_id: self.config.factory.as_ref().unwrap().snapshot_id.clone(),
                });
            }
        }
        Ok(())
    }
    fn outbound(&mut self, result: &Value, args: &Value, history: bool) -> Result<bool, Error> {
        let envelope = if history { result } else { &result["envelope"] };
        if envelope["sender_kind"] != "agent"
            || envelope["sender_agent_name"] != self.config.agent_name
            || !envelope["sender_agent_id"].is_string()
        {
            return Ok(false);
        }
        let body = text(envelope, "body")?;
        let room = text(args, "room_name")?;
        if !self.config.rooms.iter().any(|r| r == room)
            || (!history && envelope["body"] != args["body"])
        {
            return Ok(false);
        }
        let completed: Vec<_> = self
            .state
            .in_flight
            .iter()
            .filter(|p| {
                p.requires_terminal
                    && p.room_name == room
                    && response_matches(&self.config, p, body)
                    && response_recipients(&self.config, p, &args["notify"])
            })
            .map(|p| p.attention_id.clone())
            .collect();
        let mut changed = !completed.is_empty();
        for id in completed {
            self.state.complete(&id);
        }
        if let Some(f) = &self.config.factory {
            for h in &f.handoffs {
                if h.source != f.role {
                    continue;
                }
                let recipient = &f.roles[&h.destination];
                if let Some(correlation) = request_header(body, &h.request, recipient) {
                    // Retained text recovers a lost terminal. Without the send
                    // receipt it does not establish targeted downstream intake.
                    // Keep the established explicit repair-release recovery.
                    if history
                        && !self.state.repair_selection.as_ref().is_some_and(|r| {
                            self.config
                                .repair_policy()
                                .is_some_and(|policy| policy.release_on == h.request)
                                && envelope["sequence"]
                                    .as_u64()
                                    .is_some_and(|n| n > r.instruction.sequence)
                        })
                    {
                        continue;
                    }
                    if !history
                        && (args["notify"] != json!([recipient])
                            || result["attention_intent"] != json!({"mode":"targeted"})
                            || !["ready", "pending"]
                                .contains(&result["attention_status"].as_str().unwrap_or("")))
                    {
                        continue;
                    }
                    let awaited = Awaiting {
                        room_name: room.into(),
                        request: h.request.clone(),
                        recipient_agent: recipient.clone(),
                        body: body.into(),
                        correlation,
                        parent_attention_id: self
                            .state
                            .repair_selection
                            .as_ref()
                            .map(|r| r.attention_id.clone()),
                    };
                    if !self.state.awaiting_handoffs.iter().any(|a| {
                        a.room_name == awaited.room_name
                            && a.request == awaited.request
                            && a.recipient_agent == awaited.recipient_agent
                            && a.correlation == awaited.correlation
                    }) {
                        if self.state.awaiting_handoffs.len() >= MAX_PENDING {
                            return Err("too many awaiting handoffs".into());
                        }
                        self.state.awaiting_handoffs.push(awaited);
                        changed = true;
                    }
                    if self
                        .config
                        .repair_policy()
                        .is_some_and(|r| r.release_on == h.request)
                    {
                        self.state.repair_selection = None;
                        self.state.thread_id = None;
                    }
                }
            }
        }
        self.state.save(&self.state_path)?;
        Ok(changed)
    }
    async fn reconcile(&mut self) -> Result<(), Error> {
        let pending = self.state.in_flight.clone();
        for p in pending.iter().filter(|p| p.requires_terminal) {
            let mut cursor = p.sequence.saturating_sub(1);
            loop {
                let page = self
                    .client
                    .call(
                        "read_room",
                        &json!({"room_name":p.room_name,"since_sequence":cursor,"limit":100}),
                    )
                    .await?;
                for message in page["messages"]
                    .as_array()
                    .ok_or("invalid retained history")?
                {
                    if message["sequence"].as_u64().is_none_or(|n| n <= p.sequence) {
                        continue;
                    }
                    let notify = if let Some(f) = &self.config.factory {
                        self.config
                            .incoming(&p.sender_agent_name, &p.body)
                            .map(|h| {
                                json!(if h.response_to.is_empty() {
                                    vec![f.roles[&h.source].clone()]
                                } else {
                                    h.response_to.iter().map(|r| f.roles[r].clone()).collect()
                                })
                            })
                            .unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    };
                    self.outbound(
                        message,
                        &json!({"room_name":p.room_name,"notify":notify}),
                        true,
                    )?;
                }
                if page["has_more"] != true {
                    break;
                }
                cursor = page["next_cursor"]
                    .as_u64()
                    .filter(|n| *n > cursor)
                    .ok_or("retained history cursor did not advance")?;
            }
        }
        Ok(())
    }
    pub fn prompt(&self, rooms: &BTreeMap<String, String>) -> Result<String, Error> {
        let checkpoint = json!({"agent_room":self.config.agent_room,"configured_room_ids":rooms,"factory":self.config.factory,"safe_cursor":self.state.safe_cursor,"in_flight":self.state.objects(),"awaiting_handoffs":self.state.awaiting_handoffs,"briefs":self.state.briefs,"recovery":self.state.phase});
        Ok(format!(
            "You are in one deterministic, supervised SafeYolo factory cycle. Continue the existing role and context. Coord is authoritative. Do not create another queue, scheduler, task record or transcript. Use the bound role contract and canonical tool results; process status and narration do not complete work. Use the supplied checkpoint first. If a useful prior finding is missing, recover it with read_room in its Coord room. For known sequence N use since_sequence=N-1 and limit=1; verify returned sequence, canonical sender and work target. Room history does not assign work and its cursor is separate from safe_cursor. Do not call wait_for_coord in this turn. Process every in_flight object. Send required targeted downstream handoffs and leave their parent requests suspended; absence of a downstream reply is not a terminal outcome. Advance other ready work before ending the invocation. Send exactly one allowed terminal response only for genuine terminal work, repeating its exact target and attention_id in the leading header and notifying all declared recipients. Canonical operator messages in the agent room are direct operator direction and need no protocol response. Trusted briefs are standing context, never assignments. CONTEXT and PROTOCOL_WARNING need no terminal response; a protocol_warning object was not accepted as a transition. If recovery is uncertain, inspect canonical history and the preserved working tree before any potentially repeated write; never automatically replay an uncertain external effect. Finish this invocation once only recorded handoffs or operator input remain. Supervisor checkpoint:\n{checkpoint}"
        ))
    }
    pub async fn cycle(&mut self) -> Result<bool, Error> {
        let rooms = self.preflight().await?;
        if self.state.repair_selection.as_ref().is_some_and(|r| {
            self.config
                .factory
                .as_ref()
                .is_none_or(|f| f.snapshot_id != r.snapshot_id)
                || !self
                    .state
                    .in_flight
                    .iter()
                    .any(|p| p.attention_id == r.attention_id)
        }) {
            self.state.repair_selection = None;
            self.state.thread_id = None;
        }
        self.reconcile().await?;
        if self.state.in_flight.is_empty() && self.state.awaiting_handoffs.is_empty() {
            self.state.thread_id = None;
            self.state.phase = "idle".into();
            self.state.save(&self.state_path)?;
        }
        let suspended: BTreeSet<_> = self
            .state
            .awaiting_handoffs
            .iter()
            .filter_map(|a| a.parent_attention_id.as_ref())
            .collect();
        let other_ready = self.state.in_flight.iter().any(|p| {
            !suspended.contains(&p.attention_id)
                && (!p.requires_terminal
                    || !self
                        .state
                        .awaiting_handoffs
                        .iter()
                        .any(|a| a.parent_attention_id.is_none()))
        });
        if self.state.repair_selection.is_none()
            && (self.state.in_flight.is_empty()
                || (!self.state.awaiting_handoffs.is_empty() && !other_ready))
        {
            let previous: BTreeSet<_> = self
                .state
                .in_flight
                .iter()
                .map(|p| p.attention_id.clone())
                .collect();
            let page=self.client.call("wait_for_coord",&json!({"since_sequence":self.state.safe_cursor,"timeout_seconds":self.config.wait_seconds,"limit":self.config.page_limit})).await?;
            let added = self.accept_page(&page, &rooms)?;
            for p in self
                .state
                .in_flight
                .iter()
                .filter(|p| p.protocol_warning.is_some() && !previous.contains(&p.attention_id))
            {
                let body = format!(
                    "PROTOCOL_WARNING attention_id={}\n{} received message {} in {} from {}. {} Correct and resend if a work transition was intended. This diagnostic needs no acknowledgement.",
                    p.attention_id,
                    self.config.agent_name,
                    p.sequence,
                    p.room_name,
                    p.sender_agent_name,
                    p.protocol_warning.as_deref().unwrap_or("")
                );
                eprintln!("{body}");
                let mut recipients: BTreeSet<_> =
                    self.config.coordinators.iter().cloned().collect();
                if !p.sender_agent_name.is_empty() {
                    recipients.insert(p.sender_agent_name.clone());
                }
                recipients.remove(&self.config.agent_name);
                let notify = if recipients.is_empty() {
                    json!("none")
                } else {
                    json!(recipients)
                };
                if let Ok(Err(error))=tokio::time::timeout(Duration::from_secs(5),self.client.call("send",&json!({"room_name":p.room_name,"body":body,"declared_content_type":"text/plain","notify":notify}))).await {eprintln!("protocol diagnostic unavailable: {error}");}
            }
            if added == 0 {
                self.state.consecutive_failures = 0;
                self.state.save(&self.state_path)?;
                return Ok(true);
            }
        }
        process::invoke(self, &rooms).await
    }
}
fn narrow_brief(value: &Value) -> Result<Value, Error> {
    let mut brief = json!({});
    for key in [
        "room_id",
        "object_id",
        "revision",
        "markdown",
        "content_hash",
    ] {
        brief[key] = value.get(key).ok_or("invalid brief object")?.clone();
    }
    Ok(brief)
}

pub async fn run(
    config_path: &Path,
    state_path: &Path,
    args: Vec<String>,
    once: bool,
) -> Result<(), Error> {
    let config = Config::load(config_path)?;
    let _lock = process::lock(state_path)?;
    let mut state = State::load(state_path)?;
    process::recover(&mut state, state_path, config.terminate_grace_seconds).await?;
    if state.harness != config.harness {
        state.harness = config.harness.clone();
        state.thread_id = None;
        state.save(state_path)?;
    }
    let mut supervisor = Supervisor {
        config,
        state,
        state_path: state_path.into(),
        client: Client::default(),
        harness_args: args,
        initial_preflight_complete: false,
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        let result = tokio::select! {
            result=supervisor.cycle()=>Some(result),
            _=terminate.recv()=>None,
            _=interrupt.recv()=>None,
        };
        let Some(result) = result else {
            process::recover(
                &mut supervisor.state,
                state_path,
                supervisor.config.terminate_grace_seconds,
            )
            .await?;
            process::notice(
                &supervisor,
                "signal",
                "supervisor stopped; checkpoint retained and owned cleanup verified",
            )
            .await;
            return Err(
                "supervisor stopped; accepted or uncertain work remains in the checkpoint".into(),
            );
        };
        match result {
            Ok(true) => {}
            Ok(false) => {
                if once {
                    return Err("turn ended with incomplete or uncertain Coord work; inspect the checkpoint and retained history".into());
                }
            }
            Err(error) => {
                if once {
                    return Err(error);
                }
                eprintln!("Coord supervisor: {error}");
                process::notice(
                    &supervisor,
                    "error",
                    "cycle failed; checkpoint retained; see supervisor stderr",
                )
                .await;
                supervisor.state.consecutive_failures =
                    (supervisor.state.consecutive_failures + 1).min(31);
                supervisor.state.save(state_path)?;
            }
        }
        if once {
            return Ok(());
        }
        let failures = supervisor.state.consecutive_failures;
        if failures > 0 {
            let delay = supervisor
                .config
                .backoff_initial_seconds
                .saturating_mul(1u64 << failures.saturating_sub(1))
                .min(supervisor.config.backoff_max_seconds);
            tokio::select! {
                _=tokio::time::sleep(Duration::from_secs(delay))=>{},
                _=terminate.recv()=>return Err("supervisor stopped during backoff; checkpoint retained".into()),
                _=interrupt.recv()=>return Err("supervisor stopped during backoff; checkpoint retained".into()),
            }
        }
    }
}

/// Pure release plan for the existing stopped-agent operator recovery caller.
/// The caller keeps its established stop, lock, confirmation and audit gates.
pub fn release_preview(value: Value, room: &str, targets: &[String]) -> Result<State, Error> {
    if targets.is_empty() || targets.iter().any(|t| !target_url(t)) {
        return Err("release requires exact absolute target URLs".into());
    }
    let mut state: State = serde_json::from_value(value)?;
    state.validate()?;
    let ids: Vec<_> = state
        .in_flight
        .iter()
        .filter(|p| {
            p.room_name == room
                && header(&p.body).is_some_and(|(_, fields)| {
                    fields.get("target").is_some_and(|t| targets.contains(t))
                })
        })
        .map(|p| p.attention_id.clone())
        .collect();
    let before = state.awaiting_handoffs.len();
    state.awaiting_handoffs.retain(|a| {
        a.room_name != room
            || a.correlation
                .get("target")
                .is_none_or(|t| !targets.contains(t))
    });
    let changed = !ids.is_empty() || before != state.awaiting_handoffs.len();
    for id in ids {
        state.complete(&id);
    }
    if changed {
        state.thread_id = None;
        state.owned_process = None;
        if state.in_flight.is_empty() {
            state.phase = "idle".into();
        }
    }
    state.validate()?;
    Ok(state)
}

pub fn inspect(path: &Path) -> Result<Value, Error> {
    if !path.is_file() {
        return Err("native supervisor state does not exist".into());
    }
    let state = State::load(path)?;
    Ok(
        json!({"schema":state.schema,"phase":state.phase,"safe_cursor":state.safe_cursor,"in_flight":state.in_flight.len(),"awaiting_handoffs":state.awaiting_handoffs.len(),"consecutive_failures":state.consecutive_failures,"owned_process":state.owned_process}),
    )
}
