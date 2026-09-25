//! Native bridge for the retained, host-mediated `plumb` mailbox.
//!
//! The mailbox is intentionally a process-owned facade over the same SQLite
//! files used by the legacy host service.  Request identity is supplied by
//! the accepted agent listener; participant fields are data only.  The
//! operator and agent routes below share one owner and therefore observe one
//! approval/membership state. Long polls wait on a per-conversation watch
//! channel, while admitted mutations and their audit attempts stay with the
//! process owner after a request future is dropped.

use std::{
    collections::HashMap,
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hyper::body::Body;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use tokio::{
    sync::{Mutex as AsyncMutex, oneshot, watch},
    task::JoinSet,
};
use zeroize::Zeroizing;

use super::declarations::{content_error, read_content};
use super::{Outcome, Request, RequestBody, agent, response};
use crate::{inspection::Scanner, network_guard::sanitize};

const DEFAULT_MAX_PARTICIPANTS: usize = 8;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 1_048_576;
const DEFAULT_PAGE_LIMIT: usize = 200;
const DEFAULT_TTL_SECONDS: i64 = 3600;
const MAX_WAIT_SECONDS: u64 = 30;
const MAX_WAITERS: usize = 64;
const AGENT_NAME_MAX: usize = 63;

#[derive(Clone, Copy)]
struct Limits {
    max_participants: usize,
    max_message_bytes: usize,
    page_limit: usize,
    default_ttl_seconds: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_participants: DEFAULT_MAX_PARTICIPANTS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            page_limit: DEFAULT_PAGE_LIMIT,
            default_ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }
}

impl Limits {
    fn from_config(
        max_participants: usize,
        max_message_bytes: usize,
        page_limit: usize,
        default_ttl_seconds: i64,
    ) -> Self {
        Self {
            // Source uses max(2, int(value or default)).
            max_participants: if max_participants == 0 {
                DEFAULT_MAX_PARTICIPANTS
            } else {
                max_participants.max(2)
            },
            // Source uses zero to disable this cap.
            max_message_bytes,
            page_limit: if page_limit == 0 {
                DEFAULT_PAGE_LIMIT
            } else {
                page_limit.max(1)
            },
            default_ttl_seconds: if default_ttl_seconds <= 0 {
                DEFAULT_TTL_SECONDS
            } else {
                default_ttl_seconds
            },
        }
    }
}

const CREATE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS plumb_grants (
    conversation_id TEXT PRIMARY KEY,
    participants_json TEXT NOT NULL,
    topic TEXT,
    requested_by TEXT,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    closed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS plumb_pending (
    request_id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    participants_json TEXT NOT NULL,
    topic TEXT,
    note TEXT,
    ttl_seconds INTEGER NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS plumb_messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    from_agent TEXT NOT NULL,
    created_at REAL NOT NULL,
    body TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plumb_messages_conv
    ON plumb_messages (conversation_id, created_at);
"#;

#[derive(Clone)]
struct Pending {
    request_id: String,
    requester: String,
    participants: Vec<String>,
    topic: String,
    note: String,
    ttl_seconds: i64,
    created_at: f64,
    status: String,
}

#[derive(Clone)]
struct Conversation {
    conversation_id: String,
    participants: Vec<String>,
    topic: String,
    requested_by: String,
    created_at: f64,
    expires_at: f64,
}

struct Memory {
    pending: HashMap<String, Pending>,
    conversations: HashMap<String, Conversation>,
    notifications: HashMap<String, watch::Sender<u64>>,
    generation: HashMap<String, u64>,
}

struct Store {
    connection: Mutex<Connection>,
}

impl Store {
    fn open(path: &Path) -> rusqlite::Result<(Arc<Self>, Memory)> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        connection.execute_batch(CREATE_SCHEMA)?;
        // A second process may hold the writer lock. Return a truthful 503
        // before an agent's ordinary response timeout expires.
        connection.busy_timeout(Duration::from_secs(1))?;
        let mut pending = HashMap::new();
        let mut conversations = HashMap::new();
        {
            let mut rows = connection.prepare(
                "SELECT conversation_id, participants_json, topic, requested_by,
                        created_at, expires_at
                 FROM plumb_grants WHERE closed=0",
            )?;
            let values = rows.query_map([], |row| {
                let participants: String = row.get(1)?;
                Ok(Conversation {
                    conversation_id: row.get(0)?,
                    participants: serde_json::from_str(&participants).unwrap_or_default(),
                    topic: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    requested_by: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            })?;
            for value in values {
                let value = value?;
                conversations.insert(value.conversation_id.clone(), value);
            }
        }
        {
            let mut rows = connection.prepare(
                "SELECT request_id, requester, participants_json, topic, note,
                        ttl_seconds, created_at, status
                 FROM plumb_pending WHERE status='pending'",
            )?;
            let values = rows.query_map([], |row| {
                let participants: String = row.get(2)?;
                Ok(Pending {
                    request_id: row.get(0)?,
                    requester: row.get(1)?,
                    participants: serde_json::from_str(&participants).unwrap_or_default(),
                    topic: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    note: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    ttl_seconds: row.get(5)?,
                    created_at: row.get(6)?,
                    status: row.get(7)?,
                })
            })?;
            for value in values {
                let value = value?;
                pending.insert(value.request_id.clone(), value);
            }
        }
        Ok((
            Arc::new(Self {
                connection: Mutex::new(connection),
            }),
            Memory {
                pending,
                conversations,
                notifications: HashMap::new(),
                generation: HashMap::new(),
            },
        ))
    }

    fn put_pending(&self, request: &Pending) -> rusqlite::Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connection.execute(
            "INSERT OR REPLACE INTO plumb_pending
             (request_id, requester, participants_json, topic, note, ttl_seconds, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.request_id,
                request.requester,
                serde_json::to_string(&request.participants).unwrap_or_else(|_| "[]".into()),
                request.topic,
                request.note,
                request.ttl_seconds,
                request.created_at,
                request.status,
            ],
        )?;
        Ok(())
    }

    fn set_pending_status(&self, request_id: &str, status: &str) -> rusqlite::Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connection.execute(
            "UPDATE plumb_pending SET status=?1 WHERE request_id=?2",
            params![status, request_id],
        )?;
        Ok(())
    }

    fn put_conversation(&self, conversation: &Conversation) -> rusqlite::Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connection.execute(
            "INSERT OR REPLACE INTO plumb_grants
             (conversation_id, participants_json, topic, requested_by, created_at, expires_at, closed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![
                conversation.conversation_id,
                serde_json::to_string(&conversation.participants).unwrap_or_else(|_| "[]".into()),
                conversation.topic,
                conversation.requested_by,
                conversation.created_at,
                conversation.expires_at,
            ],
        )?;
        Ok(())
    }

    fn approve_request(
        &self,
        request_id: &str,
        conversation: &Conversation,
    ) -> rusqlite::Result<()> {
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE plumb_pending SET status='approved' WHERE request_id=?1",
            params![request_id],
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO plumb_grants
             (conversation_id, participants_json, topic, requested_by, created_at, expires_at, closed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![
                conversation.conversation_id,
                serde_json::to_string(&conversation.participants)
                    .unwrap_or_else(|_| "[]".into()),
                conversation.topic,
                conversation.requested_by,
                conversation.created_at,
                conversation.expires_at,
            ],
        )?;
        transaction.commit()
    }

    fn close_conversation(&self, conversation_id: &str) -> rusqlite::Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connection.execute(
            "UPDATE plumb_grants SET closed=1 WHERE conversation_id=?1",
            params![conversation_id],
        )?;
        Ok(())
    }

    fn append_message(&self, message: &Message) -> rusqlite::Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        connection.execute(
            "INSERT OR REPLACE INTO plumb_messages
             (id, conversation_id, from_agent, created_at, body, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                message.id,
                message.conversation_id,
                message.from_agent,
                message.created_at,
                message.body,
                serde_json::to_string(&message.metadata).unwrap_or_else(|_| "{}".into()),
            ],
        )?;
        Ok(())
    }

    fn list_messages(
        &self,
        conversation_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<(Vec<Value>, bool, Option<String>)> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let after_rowid = after.filter(|value| !value.is_empty()).and_then(|value| {
            connection
                .query_row(
                    "SELECT rowid FROM plumb_messages WHERE conversation_id=?1 AND id=?2",
                    params![conversation_id, value],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .ok()
                .flatten()
        });
        let mut messages = Vec::new();
        if let Some(rowid) = after_rowid {
            let mut statement = connection.prepare(
                "SELECT rowid, id, from_agent, created_at, body, metadata_json
                 FROM plumb_messages WHERE conversation_id=?1 AND rowid>?2
                 ORDER BY rowid ASC LIMIT ?3",
            )?;
            let mut rows = statement.query(params![conversation_id, rowid, (limit + 1) as i64])?;
            while let Some(row) = rows.next()? {
                let metadata: String = row.get(5)?;
                messages.push(json!({
                    "id":row.get::<_, String>(1)?,
                    "conversation_id":conversation_id,
                    "from_agent":row.get::<_, String>(2)?,
                    "created_at":row.get::<_, f64>(3)?,
                    "body":row.get::<_, String>(4)?,
                    "metadata":serde_json::from_str::<Value>(&metadata).unwrap_or_else(|_| json!({})),
                }));
            }
        } else {
            let mut statement = connection.prepare(
                "SELECT rowid, id, from_agent, created_at, body, metadata_json
                 FROM plumb_messages WHERE conversation_id=?1 ORDER BY rowid ASC LIMIT ?2",
            )?;
            let mut rows = statement.query(params![conversation_id, (limit + 1) as i64])?;
            while let Some(row) = rows.next()? {
                let metadata: String = row.get(5)?;
                messages.push(json!({
                    "id":row.get::<_, String>(1)?,
                    "conversation_id":conversation_id,
                    "from_agent":row.get::<_, String>(2)?,
                    "created_at":row.get::<_, f64>(3)?,
                    "body":row.get::<_, String>(4)?,
                    "metadata":serde_json::from_str::<Value>(&metadata).unwrap_or_else(|_| json!({})),
                }));
            }
        }
        let has_more = messages.len() > limit;
        messages.truncate(limit);
        let next = messages
            .last()
            .and_then(|message| message.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| after.map(str::to_owned));
        Ok((messages, has_more, next))
    }
}

struct Message {
    id: String,
    conversation_id: String,
    from_agent: String,
    created_at: f64,
    body: String,
    metadata: Value,
}

struct WaiterGuard<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Process-owned owner for one native mailbox. Runtime retains one owner across
/// policy reloads; tests can construct an isolated owner with `for_data_dir`.
#[derive(Clone)]
pub(crate) struct PlumbOwner {
    store: Option<Arc<Store>>,
    memory: Arc<AsyncMutex<Memory>>,
    calls: Arc<AsyncMutex<JoinSet<()>>>,
    operations: Arc<AsyncMutex<JoinSet<()>>>,
    closing: Arc<std::sync::atomic::AtomicBool>,
    error: Option<String>,
    limits: Arc<std::sync::RwLock<Limits>>,
    scanner: Scanner,
    scan_failure: Arc<std::sync::atomic::AtomicBool>,
    waiters: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    waiter_started: Arc<tokio::sync::Notify>,
}

impl PlumbOwner {
    fn from_path(path: PathBuf) -> Self {
        let scanner = Scanner::default();
        // Keep plumb on the retained full source builtin catalogue. The
        // scanner's native parser and action handling are shared with HTTP
        // pattern inspection; an unavailable catalogue remains a no-rule
        // scanner rather than reviving a partial ad-hoc matcher.
        let scan_failure = scanner
            .load_policy_config(&json!({
                "addons": {"pattern_scanner": {"builtin_sets": ["secrets"]}}
            }))
            .is_err();
        match Store::open(&path) {
            Ok((store, memory)) => Self {
                store: Some(store),
                memory: Arc::new(AsyncMutex::new(memory)),
                calls: Arc::new(AsyncMutex::new(JoinSet::new())),
                operations: Arc::new(AsyncMutex::new(JoinSet::new())),
                closing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error: None,
                limits: Arc::new(std::sync::RwLock::new(Limits::default())),
                scanner,
                scan_failure: Arc::new(std::sync::atomic::AtomicBool::new(scan_failure)),
                waiters: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                #[cfg(test)]
                waiter_started: Arc::new(tokio::sync::Notify::new()),
            },
            Err(error) => Self {
                store: None,
                memory: Arc::new(AsyncMutex::new(Memory {
                    pending: HashMap::new(),
                    conversations: HashMap::new(),
                    notifications: HashMap::new(),
                    generation: HashMap::new(),
                })),
                calls: Arc::new(AsyncMutex::new(JoinSet::new())),
                operations: Arc::new(AsyncMutex::new(JoinSet::new())),
                closing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                error: Some(error.to_string()),
                limits: Arc::new(std::sync::RwLock::new(Limits::default())),
                scanner,
                scan_failure: Arc::new(std::sync::atomic::AtomicBool::new(scan_failure)),
                waiters: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                #[cfg(test)]
                waiter_started: Arc::new(tokio::sync::Notify::new()),
            },
        }
    }

    pub(crate) fn for_data_dir(data_dir: &Path) -> Self {
        Self::from_path(data_dir.join("plumb").join("plumb.db"))
    }

    pub(crate) fn unavailable(&self) -> Option<Outcome<'static>> {
        self.error
            .as_ref()
            .map(|_| response(503, json!({"error":"plumb backing state unavailable"})))
    }

    pub(crate) fn available(&self) -> bool {
        self.error.is_none()
    }

    /// Stop new store work and wake long polls before the process drains its
    /// accepted listeners. Existing calls remain owned by this process until
    /// their blocking SQLite operation returns.
    pub(crate) async fn stop_admission(&self) {
        let _operations = self.operations.lock().await;
        self.closing
            .store(true, std::sync::atomic::Ordering::Release);
        let memory = self.memory.lock().await;
        for sender in memory.notifications.values() {
            let next = sender.borrow().saturating_add(1);
            sender.send_replace(next);
        }
    }

    /// Join all blocking store calls admitted before shutdown. A canceled
    /// request drops only its result receiver; the blocking call remains in
    /// this owner until it reaches a terminal SQLite result.
    pub(crate) async fn drain(&self) {
        {
            let mut operations = self.operations.lock().await;
            while let Some(result) = operations.join_next().await {
                if let Err(error) = result {
                    eprintln!("plumb operation failed: {error}");
                }
            }
        }
        let mut calls = self.calls.lock().await;
        while let Some(result) = calls.join_next().await {
            if let Err(error) = result {
                eprintln!("plumb store task failed: {error}");
            }
        }
    }

    /// Run the whole mailbox operation under the process owner. The caller
    /// receives only a result channel; dropping that channel does not cancel
    /// persistence, projection updates, or the operation's audit attempt.
    async fn spawn_owned<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> Result<oneshot::Receiver<T>, ()> {
        let (sender, receiver) = oneshot::channel();
        let mut operations = self.operations.lock().await;
        while operations.try_join_next().is_some() {}
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err(());
        }
        operations.spawn(async move {
            let _ = sender.send(work.await);
        });
        Ok(receiver)
    }

    pub(crate) fn configure_limits(
        &self,
        max_participants: usize,
        max_message_bytes: usize,
        page_limit: usize,
        default_ttl_seconds: i64,
    ) {
        if let Ok(mut limits) = self.limits.write() {
            *limits = Limits::from_config(
                max_participants,
                max_message_bytes,
                page_limit,
                default_ttl_seconds,
            );
        }
    }

    #[cfg(test)]
    fn inject_scan_failure(&self, failed: bool) {
        self.scan_failure
            .store(failed, std::sync::atomic::Ordering::Release);
    }

    fn limits(&self) -> Limits {
        self.limits.read().map(|limits| *limits).unwrap_or_default()
    }

    fn notify_for(memory: &mut Memory, conversation_id: &str) -> watch::Receiver<u64> {
        if let Some(sender) = memory.notifications.get(conversation_id) {
            return sender.subscribe();
        }
        let generation = *memory
            .generation
            .entry(conversation_id.to_owned())
            .or_default();
        let (sender, receiver) = watch::channel(generation);
        memory
            .notifications
            .insert(conversation_id.to_owned(), sender);
        receiver
    }

    fn bump(memory: &mut Memory, conversation_id: &str) {
        let generation = memory
            .generation
            .entry(conversation_id.to_owned())
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
        if let Some(sender) = memory.notifications.get(conversation_id) {
            sender.send_replace(*generation);
        }
    }

    async fn db_call<T: Send + 'static>(
        &self,
        store: Arc<Store>,
        call: impl FnOnce(Arc<Store>) -> rusqlite::Result<T> + Send + 'static,
    ) -> Result<T, ()> {
        let (sender, receiver) = oneshot::channel();
        let mut calls = self.calls.lock().await;
        while calls.try_join_next().is_some() {}
        calls.spawn_blocking(move || {
            let _ = sender.send(call(store));
        });
        drop(calls);
        receiver.await.ok().and_then(Result::ok).ok_or(())
    }

    async fn is_closing(&self) -> bool {
        self.closing.load(std::sync::atomic::Ordering::Acquire)
    }

    fn closing_response() -> Value {
        json!({"status":503,"error":"plumb backing state unavailable"})
    }

    fn id(prefix: &str) -> String {
        format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
    }

    fn clean(value: Option<&Value>) -> String {
        let value = value.and_then(Value::as_str).unwrap_or_default();
        value
            .chars()
            .filter(|character| !character.is_control())
            .collect::<String>()
            .trim()
            .to_owned()
    }

    fn valid_agent(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= AGENT_NAME_MAX
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (byte == b'-' && index > 0 && index + 1 < value.len())
            })
            && value
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    }

    fn ttl_with_default(&self, value: Option<&Value>, default: i64) -> i64 {
        value
            .and_then(|value| match value {
                Value::Number(value) => value.as_i64(),
                Value::String(value) => value.parse().ok(),
                _ => None,
            })
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    pub(crate) async fn request_chat(
        &self,
        requester: &str,
        participants: &[Value],
        topic: Option<&Value>,
        note: Option<&Value>,
        ttl: Option<&Value>,
    ) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let mut invalid_participant = false;
        let mut names = participants
            .iter()
            .map(|value| match value {
                Value::String(value) => value.clone(),
                _ => {
                    invalid_participant = true;
                    String::new()
                }
            })
            .collect::<Vec<_>>();
        if invalid_participant {
            return json!({"status":400,"error":"invalid participant name"});
        }
        names.retain(|name| name != requester);
        names.sort();
        names.dedup();
        if names.is_empty() {
            return json!({"status":400,"error":"no participants to chat with"});
        }
        let mut all = names.clone();
        all.push(requester.to_owned());
        all.sort();
        all.dedup();
        if all.iter().any(|name| !Self::valid_agent(name)) {
            return json!({"status":400,"error":"invalid participant name"});
        }
        let limits = self.limits();
        if all.len() > limits.max_participants {
            return json!({"status":400,"error":format!("too many participants (max {})", limits.max_participants)});
        }
        let request = Pending {
            request_id: Self::id("req"),
            requester: requester.to_owned(),
            participants: all.clone(),
            topic: Self::clean(topic),
            note: Self::clean(note),
            ttl_seconds: self.ttl_with_default(ttl, limits.default_ttl_seconds),
            created_at: now(),
            status: "pending".into(),
        };
        let Some(store) = &self.store else {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        };
        let db_request = request.clone();
        if self
            .db_call(store.clone(), move |store| store.put_pending(&db_request))
            .await
            .is_err()
        {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        }
        let mut memory = self.memory.lock().await;
        memory
            .pending
            .insert(request.request_id.clone(), request.clone());
        json!({
            "status":202,
            "state":"pending",
            "request_id":request.request_id,
            "participants":all,
            "topic":request.topic,
            "note":request.note,
            "ttl_seconds":request.ttl_seconds,
        })
    }

    pub(crate) async fn list_conversations(&self, agent_name: &str) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let memory = self.memory.lock().await;
        let conversations = memory
            .conversations
            .values()
            .filter(|conversation| {
                conversation
                    .participants
                    .iter()
                    .any(|value| value == agent_name)
                    && conversation.expires_at > now()
            })
            .map(|conversation| {
                json!({
                    "conversation_id":conversation.conversation_id,
                    "participants":conversation.participants,
                    "topic":conversation.topic,
                    "expires_at":conversation.expires_at,
                })
            })
            .collect::<Vec<_>>();
        json!({"status":200,"conversations":conversations})
    }

    fn member(memory: &Memory, conversation_id: &str, agent_name: &str) -> bool {
        memory
            .conversations
            .get(conversation_id)
            .is_some_and(|conversation| {
                conversation.expires_at > now()
                    && conversation
                        .participants
                        .iter()
                        .any(|value| value == agent_name)
            })
    }

    fn scan_message(&self, body: &str) -> Result<(Vec<String>, bool), ()> {
        if self.scan_failure.load(std::sync::atomic::Ordering::Acquire) {
            return Err(());
        }
        let findings = self.scanner.scan_request_body_rules(body).map_err(|_| ())?;
        let should_block = findings
            .iter()
            .any(|finding| finding.pattern_action == "block");
        let detected = findings
            .into_iter()
            .map(|finding| finding.rule_name)
            .collect();
        Ok((detected, should_block))
    }

    pub(crate) async fn post_message(
        &self,
        agent_name: &str,
        conversation_id: &str,
        body: &str,
        references: Value,
    ) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let raw_size = body.len();
        let limits = self.limits();
        if limits.max_message_bytes != 0 && raw_size > limits.max_message_bytes {
            return json!({"status":413,"error":"message too large"});
        }
        let mut memory = self.memory.lock().await;
        if !Self::member(&memory, conversation_id, agent_name) {
            return json!({"status":403,"error":"not a participant"});
        }
        let (detected, should_block) = match self.scan_message(body) {
            Ok(result) => result,
            Err(()) => {
                return json!({
                    "status":503,
                    "error":"message scanning unavailable"
                });
            }
        };
        if should_block {
            return json!({
                "status":403,
                "error":"message blocked: credential/secret detected",
                "detected_classes":detected,
            });
        }
        let message = Message {
            id: Self::id("msg"),
            conversation_id: conversation_id.to_owned(),
            from_agent: agent_name.to_owned(),
            created_at: now(),
            body: body.to_owned(),
            metadata: json!({"size_bytes":raw_size,"detected_classes":detected.clone(),"references":references}),
        };
        let Some(store) = &self.store else {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        };
        let message_id = message.id.clone();
        if self
            .db_call(store.clone(), move |store| store.append_message(&message))
            .await
            .is_err()
        {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        }
        Self::bump(&mut memory, conversation_id);
        json!({"status":200,"id":message_id,"detected_classes":detected})
    }

    pub(crate) async fn read_messages(
        &self,
        agent_name: &str,
        conversation_id: &str,
        after: Option<String>,
        wait: u64,
        limit: usize,
    ) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let configured_page_limit = self.limits().page_limit;
        let page_limit = if limit == 0 {
            configured_page_limit
        } else {
            limit.clamp(1, configured_page_limit)
        };
        let mut receiver = {
            let mut memory = self.memory.lock().await;
            if !Self::member(&memory, conversation_id, agent_name) {
                return json!({"status":403,"error":"not a participant"});
            }
            Self::notify_for(&mut memory, conversation_id)
        };
        let Some(store) = &self.store else {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        };
        let store_for_page = store.clone();
        let conversation_for_page = conversation_id.to_owned();
        let after_for_page = after.clone();
        let snapshot = || async {
            self.db_call(store_for_page.clone(), {
                let conversation_id = conversation_for_page.clone();
                let after = after_for_page.clone();
                move |store| store.list_messages(&conversation_id, after.as_deref(), page_limit)
            })
            .await
        };
        let mut page = match snapshot().await {
            Ok(page) => page,
            Err(()) => return json!({"status":503,"error":"plumb backing state unavailable"}),
        };
        if page.0.is_empty() && wait > 0 {
            let previous = self
                .waiters
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            if previous >= MAX_WAITERS {
                self.waiters
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            } else {
                #[cfg(test)]
                self.waiter_started.notify_one();
                let _waiter = WaiterGuard(&self.waiters);
                let timeout = tokio::time::Duration::from_secs(wait.min(MAX_WAIT_SECONDS));
                let _ = tokio::time::timeout(timeout, receiver.changed()).await;
                if self.is_closing().await {
                    return Self::closing_response();
                }
                page = match snapshot().await {
                    Ok(page) => page,
                    Err(()) => {
                        return json!({"status":503,"error":"plumb backing state unavailable"});
                    }
                };
            }
        }
        json!({
            "status":200,
            "messages":page.0,
            "has_more":page.1,
            "next_after":page.2.or(after),
            "limit":page_limit,
        })
    }

    #[cfg(test)]
    pub(crate) async fn leave(&self, agent_name: &str, conversation_id: &str) -> Value {
        self.leave_with_closed(agent_name, conversation_id).await.0
    }

    async fn leave_with_closed(&self, agent_name: &str, conversation_id: &str) -> (Value, bool) {
        if self.is_closing().await {
            return (Self::closing_response(), false);
        }
        let Some(store) = &self.store else {
            return (
                json!({"status":503,"error":"plumb backing state unavailable"}),
                false,
            );
        };
        let mut memory = self.memory.lock().await;
        let Some(existing) = memory.conversations.get(conversation_id) else {
            return (json!({"status":403,"error":"not a participant"}), false);
        };
        if !existing
            .participants
            .iter()
            .any(|value| value == agent_name)
        {
            return (json!({"status":403,"error":"not a participant"}), false);
        }
        let mut updated = existing.clone();
        updated.participants.retain(|value| value != agent_name);
        let close = updated.participants.len() <= 1;
        let result = if close {
            self.db_call(store.clone(), {
                let id = conversation_id.to_owned();
                move |store| store.close_conversation(&id)
            })
            .await
        } else {
            let db_updated = updated.clone();
            self.db_call(store.clone(), move |store| {
                store.put_conversation(&db_updated)
            })
            .await
        };
        if result.is_err() {
            return (
                json!({"status":503,"error":"plumb backing state unavailable"}),
                false,
            );
        }
        if close {
            memory.conversations.remove(conversation_id);
        } else {
            memory
                .conversations
                .insert(conversation_id.to_owned(), updated);
        }
        (json!({"status":200,"left":conversation_id}), close)
    }

    pub(crate) async fn list_pending(&self) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let memory = self.memory.lock().await;
        json!({"status":200,"pending":memory.pending.values().filter(|request| request.status == "pending").map(pending_json).collect::<Vec<_>>()})
    }

    pub(crate) async fn pending_details(&self, request_id: &str) -> Option<Value> {
        if self.is_closing().await {
            return None;
        }
        let memory = self.memory.lock().await;
        memory
            .pending
            .get(request_id)
            .filter(|request| request.status == "pending")
            .map(pending_json)
    }

    pub(crate) async fn admin_list_conversations(&self) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let memory = self.memory.lock().await;
        json!({"status":200,"conversations":memory.conversations.values().map(conversation_json).collect::<Vec<_>>()})
    }

    pub(crate) async fn approve(&self, request_id: &str, operator_ttl: Option<i64>) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let Some(store) = &self.store else {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        };
        let mut memory = self.memory.lock().await;
        let Some(request) = memory
            .pending
            .get(request_id)
            .filter(|request| request.status == "pending")
            .cloned()
        else {
            return json!({"status":404,"error":"unknown or already-resolved request"});
        };
        let ttl = operator_ttl
            .filter(|value| *value > 0)
            .unwrap_or(request.ttl_seconds);
        let conversation = Conversation {
            conversation_id: Self::id("conv"),
            participants: request.participants.clone(),
            topic: request.topic.clone(),
            requested_by: request.requester.clone(),
            created_at: now(),
            expires_at: now() + ttl as f64,
        };
        let db_conversation = conversation.clone();
        let result = self
            .db_call(store.clone(), {
                let request_id = request_id.to_owned();
                move |store| store.approve_request(&request_id, &db_conversation)
            })
            .await;
        if result.is_err() {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        }
        if let Some(request) = memory.pending.get_mut(request_id) {
            request.status = "approved".into();
        }
        memory
            .conversations
            .insert(conversation.conversation_id.clone(), conversation.clone());
        let mut result = conversation_json(&conversation);
        result["status"] = json!(200);
        result
    }

    pub(crate) async fn deny(&self, request_id: &str) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let Some(store) = &self.store else {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        };
        let mut memory = self.memory.lock().await;
        let Some(request) = memory
            .pending
            .get(request_id)
            .filter(|request| request.status == "pending")
            .cloned()
        else {
            return json!({"status":404,"error":"unknown or already-resolved request"});
        };
        if self
            .db_call(store.clone(), {
                let request_id = request_id.to_owned();
                move |store| store.set_pending_status(&request_id, "denied")
            })
            .await
            .is_err()
        {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        }
        if let Some(request) = memory.pending.get_mut(request_id) {
            request.status = "denied".into();
        }
        json!({"status":200,"denied":request.request_id})
    }

    pub(crate) async fn close(&self, conversation_id: &str) -> Value {
        if self.is_closing().await {
            return Self::closing_response();
        }
        let Some(store) = &self.store else {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        };
        let mut memory = self.memory.lock().await;
        if !memory.conversations.contains_key(conversation_id) {
            return json!({"status":404,"error":"unknown conversation"});
        }
        if self
            .db_call(store.clone(), {
                let id = conversation_id.to_owned();
                move |store| store.close_conversation(&id)
            })
            .await
            .is_err()
        {
            return json!({"status":503,"error":"plumb backing state unavailable"});
        }
        memory.conversations.remove(conversation_id);
        json!({"status":200,"closed":conversation_id})
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_chat_owned(
        &self,
        request_id: String,
        requester: String,
        participants: Vec<Value>,
        topic: Option<Value>,
        note: Option<Value>,
        ttl: Option<Value>,
        writer: Option<Arc<crate::audit::Writer>>,
    ) -> OwnedAgentResult {
        let owner = self.clone();
        let receiver = match self
            .spawn_owned(async move {
                let result = owner
                    .request_chat(
                        &requester,
                        &participants,
                        topic.as_ref(),
                        note.as_ref(),
                        ttl.as_ref(),
                    )
                    .await;
                let intent = (result["status"].as_u64() == Some(202))
                    .then(|| audit_request_values(&request_id, &requester, result.clone()));
                let audit_owned = writer.is_some() && intent.is_some();
                let audit_failed =
                    if let (Some(writer), Some(intent)) = (writer.as_ref(), intent.as_ref()) {
                        writer.emit_confirmed(intent.to_event()).await.is_err()
                    } else {
                        false
                    };
                OwnedAgentResult {
                    value: if audit_failed {
                        json!({"status":500,"error":"Internal error: RuntimeError"})
                    } else {
                        result
                    },
                    audit: intent,
                    audit_owned,
                    failure: audit_failed.then_some(super::Failure::AuditWrite),
                }
            })
            .await
        {
            Ok(receiver) => receiver,
            Err(()) => {
                return OwnedAgentResult {
                    value: Self::closing_response(),
                    audit: None,
                    audit_owned: false,
                    failure: None,
                };
            }
        };
        receiver.await.unwrap_or_else(|_| OwnedAgentResult {
            value: Self::closing_response(),
            audit: None,
            audit_owned: false,
            failure: None,
        })
    }

    async fn post_message_owned(
        &self,
        request_id: String,
        agent_name: String,
        conversation_id: String,
        body: String,
        references: Value,
        writer: Option<Arc<crate::audit::Writer>>,
    ) -> OwnedAgentResult {
        let owner = self.clone();
        let raw_size = body.len();
        let receiver = match self
            .spawn_owned(async move {
                let result = owner
                    .post_message(&agent_name, &conversation_id, &body, references)
                    .await;
                let intent = message_audit_values(
                    &request_id,
                    &agent_name,
                    &conversation_id,
                    raw_size,
                    &result,
                );
                let audit_owned = writer.is_some() && intent.is_some();
                if let Some(intent) = intent.as_ref() {
                    let _ = submit_agent_audit(writer.as_ref(), intent);
                }
                OwnedAgentResult {
                    value: result,
                    audit: intent,
                    audit_owned,
                    failure: None,
                }
            })
            .await
        {
            Ok(receiver) => receiver,
            Err(()) => {
                return OwnedAgentResult {
                    value: Self::closing_response(),
                    audit: None,
                    audit_owned: false,
                    failure: None,
                };
            }
        };
        receiver.await.unwrap_or_else(|_| OwnedAgentResult {
            value: Self::closing_response(),
            audit: None,
            audit_owned: false,
            failure: None,
        })
    }

    async fn leave_owned(
        &self,
        request_id: String,
        agent_name: String,
        conversation_id: String,
        writer: Option<Arc<crate::audit::Writer>>,
    ) -> OwnedAgentResult {
        let owner = self.clone();
        let conversation_for_audit = conversation_id.clone();
        let receiver = match self
            .spawn_owned(async move {
                let (result, closed) = owner.leave_with_closed(&agent_name, &conversation_id).await;
                let intent = (closed && result["status"].as_u64() == Some(200)).then(|| {
                    conversation_closed_audit_values(
                        &request_id,
                        &conversation_for_audit,
                        "last participant left",
                    )
                });
                let audit_owned = writer.is_some() && intent.is_some();
                if let Some(intent) = intent.as_ref() {
                    let _ = submit_agent_audit(writer.as_ref(), intent);
                }
                OwnedAgentResult {
                    value: result,
                    audit: intent,
                    audit_owned,
                    failure: None,
                }
            })
            .await
        {
            Ok(receiver) => receiver,
            Err(()) => {
                return OwnedAgentResult {
                    value: Self::closing_response(),
                    audit: None,
                    audit_owned: false,
                    failure: None,
                };
            }
        };
        receiver.await.unwrap_or_else(|_| OwnedAgentResult {
            value: Self::closing_response(),
            audit: None,
            audit_owned: false,
            failure: None,
        })
    }

    pub(crate) async fn approve_owned(
        &self,
        request_id: String,
        operator_ttl: Option<i64>,
        writer: Option<Arc<crate::audit::Writer>>,
    ) -> Result<Value, crate::admin_api::Error> {
        let owner = self.clone();
        let request_for_audit = request_id.clone();
        let receiver = match self
            .spawn_owned(async move {
                let result = owner.approve(&request_id, operator_ttl).await;
                if result["status"].as_u64() == Some(200) {
                    let participants = result
                        .get("participants")
                        .cloned()
                        .unwrap_or_else(|| json!([]));
                    let details = json!({
                        "request_id": request_for_audit,
                        "participants": participants,
                        "conversation_id": result.get("conversation_id").cloned().unwrap_or(Value::Null),
                    });
                    let agent = result
                        .get("requested_by")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    submit_admin_plumb_audit(
                        writer.as_ref(),
                        "plumb.approved",
                        format!(
                            "chat approved: {}",
                            details["participants"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        details,
                        agent,
                        crate::audit::Decision::Allow,
                    )?;
                }
                Ok(result)
            })
            .await
        {
            Ok(receiver) => receiver,
            Err(()) => return Ok(Self::closing_response()),
        };
        receiver
            .await
            .unwrap_or_else(|_| Ok(Self::closing_response()))
    }

    pub(crate) async fn deny_owned(
        &self,
        request_id: String,
        writer: Option<Arc<crate::audit::Writer>>,
    ) -> Result<Value, crate::admin_api::Error> {
        let owner = self.clone();
        let request_for_audit = request_id.clone();
        let receiver = match self
            .spawn_owned(async move {
                let pending = owner.pending_details(&request_id).await;
                let result = owner.deny(&request_id).await;
                if result["status"].as_u64() == Some(200) {
                    let participants = pending
                        .as_ref()
                        .and_then(|value| value.get("participants"))
                        .cloned()
                        .unwrap_or_else(|| json!([]));
                    let agent = pending
                        .as_ref()
                        .and_then(|value| value.get("requester"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    submit_admin_plumb_audit(
                        writer.as_ref(),
                        "plumb.denied",
                        format!("chat denied: {request_for_audit}"),
                        json!({
                            "request_id": request_for_audit,
                            "participants": participants,
                        }),
                        agent,
                        crate::audit::Decision::Deny,
                    )?;
                }
                Ok(result)
            })
            .await
        {
            Ok(receiver) => receiver,
            Err(()) => return Ok(Self::closing_response()),
        };
        receiver
            .await
            .unwrap_or_else(|_| Ok(Self::closing_response()))
    }

    pub(crate) async fn close_owned(
        &self,
        conversation_id: String,
        writer: Option<Arc<crate::audit::Writer>>,
    ) -> Result<Value, crate::admin_api::Error> {
        let owner = self.clone();
        let conversation_for_audit = conversation_id.clone();
        let receiver = match self
            .spawn_owned(async move {
                let result = owner.close(&conversation_id).await;
                if result["status"].as_u64() == Some(200) {
                    submit_admin_plumb_audit(
                        writer.as_ref(),
                        "plumb.conversation_closed",
                        format!("conversation {conversation_for_audit} closed: operator closed"),
                        json!({
                            "conversation_id": conversation_for_audit,
                            "reason": "operator closed",
                        }),
                        None,
                        crate::audit::Decision::Log,
                    )?;
                }
                Ok(result)
            })
            .await
        {
            Ok(receiver) => receiver,
            Err(()) => return Ok(Self::closing_response()),
        };
        receiver
            .await
            .unwrap_or_else(|_| Ok(Self::closing_response()))
    }
}

struct OwnedAgentResult {
    value: Value,
    audit: Option<super::AuditIntent>,
    audit_owned: bool,
    failure: Option<super::Failure>,
}

fn submit_agent_audit(
    writer: Option<&Arc<crate::audit::Writer>>,
    intent: &super::AuditIntent,
) -> Result<(), crate::audit::ErrorKind> {
    let Some(writer) = writer else {
        return Ok(());
    };
    writer
        .emit(intent.to_event())
        .map(|_| ())
        .map_err(|error| error.kind())?;
    Ok(())
}

fn submit_admin_plumb_audit(
    writer: Option<&Arc<crate::audit::Writer>>,
    event: &'static str,
    summary: String,
    details: Value,
    agent: Option<String>,
    decision: crate::audit::Decision,
) -> Result<(), crate::admin_api::Error> {
    let Some(writer) = writer else {
        return Ok(());
    };
    for event in crate::admin_api::plumb_events(event, summary, details, agent, decision) {
        writer
            .emit(event)
            .map_err(|error| crate::admin_api::Error::Audit(error.kind()))?;
    }
    Ok(())
}

fn pending_json(request: &Pending) -> Value {
    json!({
        "request_id":request.request_id,
        "requester":request.requester,
        "participants":request.participants,
        "topic":request.topic,
        "note":request.note,
        "ttl_seconds":request.ttl_seconds,
        "created_at":request.created_at,
        "status":request.status,
    })
}

fn conversation_json(conversation: &Conversation) -> Value {
    json!({
        "conversation_id":conversation.conversation_id,
        "participants":conversation.participants,
        "topic":conversation.topic,
        "requested_by":conversation.requested_by,
        "created_at":conversation.created_at,
        "expires_at":conversation.expires_at,
    })
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs_f64())
        .unwrap_or(0.0)
}

fn body_value(bytes: Zeroizing<Vec<u8>>) -> Value {
    if bytes.is_empty() {
        return json!({});
    }
    serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}))
}

fn string_field(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string(),
    }
}

fn query(path_and_query: &str, name: &str) -> Option<String> {
    path_and_query.split_once('?').and_then(|(_, query)| {
        query.split('&').find_map(|field| {
            let (key, value) = field.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
    })
}

#[cfg(test)]
fn message_audit(
    request: Request<'_>,
    agent_name: &str,
    conversation_id: &str,
    raw_size: usize,
    result: &Value,
) -> Option<super::AuditIntent> {
    message_audit_values(
        request.request_id,
        agent_name,
        conversation_id,
        raw_size,
        result,
    )
}

fn message_audit_values(
    request_id: &str,
    agent_name: &str,
    conversation_id: &str,
    raw_size: usize,
    result: &Value,
) -> Option<super::AuditIntent> {
    let status = result.get("status").and_then(Value::as_u64)?;
    let blocked = status == 403
        && result
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| error.starts_with("message blocked:"));
    if status != 200 && !blocked {
        return None;
    }
    let detected = result
        .get("detected_classes")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let kind = if blocked {
        super::AuditKind::PlumbMessageBlocked
    } else if detected.as_array().is_some_and(|values| !values.is_empty()) {
        super::AuditKind::PlumbMessageFlagged
    } else {
        super::AuditKind::PlumbMessageAllowed
    };
    let (event, severity, summary) = match kind {
        super::AuditKind::PlumbMessageBlocked => (
            "plumb.message_blocked",
            "critical",
            format!(
                "{} -> {}: blocked (secret detected)",
                sanitize(agent_name),
                sanitize(conversation_id)
            ),
        ),
        super::AuditKind::PlumbMessageFlagged => (
            "plumb.message_flagged",
            "high",
            format!(
                "{} -> {} ({}B)",
                sanitize(agent_name),
                sanitize(conversation_id),
                raw_size
            ),
        ),
        super::AuditKind::PlumbMessageAllowed => (
            "plumb.message_allowed",
            "low",
            format!(
                "{} -> {} ({}B)",
                sanitize(agent_name),
                sanitize(conversation_id),
                raw_size
            ),
        ),
        _ => unreachable!("message audit helper called for non-message event"),
    };
    Some(super::AuditIntent {
        kind,
        event,
        severity,
        addon: "plumb",
        summary,
        agent: Some(agent_name.to_owned()),
        request_id: Some(request_id.to_owned()),
        host: Some(super::API_HOST.to_owned()),
        details: json!({
            "conversation_id": conversation_id,
            "detected_classes": detected,
        }),
        approval: None,
    })
}

#[cfg(test)]
fn conversation_closed_audit(
    request: Request<'_>,
    conversation_id: &str,
    reason: &str,
) -> super::AuditIntent {
    conversation_closed_audit_values(request.request_id, conversation_id, reason)
}

fn conversation_closed_audit_values(
    request_id: &str,
    conversation_id: &str,
    reason: &str,
) -> super::AuditIntent {
    super::AuditIntent {
        kind: super::AuditKind::PlumbConversationClosed,
        event: "plumb.conversation_closed",
        severity: "low",
        addon: "plumb",
        summary: format!(
            "conversation {} closed: {}",
            sanitize(conversation_id),
            sanitize(reason)
        ),
        agent: None,
        request_id: Some(request_id.to_owned()),
        host: Some(super::API_HOST.to_owned()),
        details: json!({
            "conversation_id": conversation_id,
            "reason": reason,
        }),
        approval: None,
    }
}

pub(super) async fn respond<B>(
    request: Request<'_>,
    body: RequestBody<'_, B>,
    owner: Option<&PlumbOwner>,
    audit: Option<Arc<crate::audit::Writer>>,
) -> Result<Outcome<'static>, B::Error>
where
    B: Body<Data = bytes::Bytes> + Unpin,
{
    let Some(agent_name) = agent(request.identity) else {
        return Ok(response(403, json!({"error":"Could not identify agent"})));
    };
    let Some(owner) = owner else {
        return Ok(response(
            503,
            json!({"error":"plumb backing state unavailable"}),
        ));
    };
    if let Some(outcome) = owner.unavailable() {
        return Ok(outcome);
    }
    let path = super::route(request);
    if request.method == "GET" && path == "/plumb/conversations" {
        return Ok(result_response(owner.list_conversations(agent_name).await));
    }
    if request.method == "POST" && path == "/plumb/request-chat" {
        let content = read_content(body).await?;
        let value = match content {
            Ok(content) => body_value(content),
            Err(error) => return Ok(content_error(error)),
        };
        let object = value.as_object();
        let participants = object
            .and_then(|object| object.get("participants"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let note = object
            .and_then(|object| object.get("reason"))
            .or_else(|| object.and_then(|object| object.get("note")));
        let result = owner
            .request_chat_owned(
                request.request_id.to_owned(),
                agent_name.to_owned(),
                participants.to_vec(),
                object.and_then(|object| object.get("topic")).cloned(),
                note.cloned(),
                object.and_then(|object| object.get("ttl_seconds")).cloned(),
                audit.clone(),
            )
            .await;
        let mut response_value = result.value;
        if let Some(fields) = response_value.as_object_mut() {
            fields.remove("topic");
            fields.remove("note");
            fields.remove("ttl_seconds");
        }
        return Ok(owned_result_response(
            response_value,
            result.audit,
            result.audit_owned,
            result.failure,
        ));
    }
    let Some((conversation_id, tail)) = path
        .strip_prefix("/plumb/conversations/")
        .and_then(|value| value.split_once('/'))
    else {
        return Ok(response(
            404,
            json!({"error":"Not Found","endpoints":[
                "/plumb/request-chat (POST)", "/plumb/conversations (GET)",
                "/plumb/conversations/{id}/messages (GET long-poll, POST)",
                "/plumb/conversations/{id}/leave (POST)"
            ]}),
        ));
    };
    if conversation_id.is_empty() || conversation_id.contains('/') {
        return Ok(response(404, json!({"error":"Not Found"})));
    }
    match (request.method, tail) {
        ("GET", "messages") => {
            let wait = query(request.path_and_query, "wait")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            let limit = query(request.path_and_query, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(DEFAULT_PAGE_LIMIT);
            let result = owner
                .read_messages(
                    agent_name,
                    conversation_id,
                    query(request.path_and_query, "after"),
                    wait,
                    limit,
                )
                .await;
            Ok(result_response(result))
        }
        ("POST", "messages") => {
            let content = read_content(body).await?;
            let value = match content {
                Ok(content) => body_value(content),
                Err(error) => return Ok(content_error(error)),
            };
            let object = value.as_object();
            let references = object
                .and_then(|object| object.get("metadata"))
                .and_then(Value::as_object)
                .and_then(|metadata| metadata.get("references"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            let body = string_field(object.and_then(|object| object.get("body")));
            let result = owner
                .post_message_owned(
                    request.request_id.to_owned(),
                    agent_name.to_owned(),
                    conversation_id.to_owned(),
                    body,
                    references,
                    audit.clone(),
                )
                .await;
            Ok(owned_result_response(
                result.value,
                result.audit,
                result.audit_owned,
                result.failure,
            ))
        }
        ("POST", "leave") => {
            let result = owner
                .leave_owned(
                    request.request_id.to_owned(),
                    agent_name.to_owned(),
                    conversation_id.to_owned(),
                    audit,
                )
                .await;
            Ok(owned_result_response(
                result.value,
                result.audit,
                result.audit_owned,
                result.failure,
            ))
        }
        _ => Ok(response(404, json!({"error":"Not Found"}))),
    }
}

pub(crate) fn result_response(mut value: Value) -> Outcome<'static> {
    let status = value
        .as_object_mut()
        .and_then(|object| object.remove("status"))
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(200);
    response(status, value)
}

fn owned_result_response(
    value: Value,
    audit: Option<super::AuditIntent>,
    audit_owned: bool,
    failure: Option<super::Failure>,
) -> Outcome<'static> {
    let mut outcome = result_response(value);
    outcome.audit = audit;
    outcome.audit_owned = audit_owned;
    outcome.failure = failure;
    outcome
}

fn audit_request_values(request_id: &str, agent_name: &str, details: Value) -> super::AuditIntent {
    super::AuditIntent {
        kind: super::AuditKind::PlumbRequested,
        event: "plumb.requested",
        severity: "critical",
        addon: "plumb",
        summary: "Agent requested a plumb conversation".to_owned(),
        agent: Some(agent_name.to_owned()),
        request_id: Some(request_id.to_owned()),
        host: Some(super::API_HOST.to_owned()),
        approval: Some(super::AuditApproval {
            required: true,
            approval_type: crate::audit::ApprovalType::Plumb,
            key: details
                .get("request_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            target: details
                .get("participants")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default(),
            scope_hint: details.clone(),
        }),
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentListener, Config, Proxy,
        audit::{Event, Kind, Severity, Submission},
        network_guard::Identity,
    };
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UnixStream},
    };

    const SHUTDOWN_AGENT_TOKEN: &str = "plumb-shutdown-agent-token";
    const SHUTDOWN_OPERATOR_TOKEN: &str = "plumb-shutdown-operator-token";

    fn text(value: &Value, field: &str) -> String {
        value
            .get(field)
            .and_then(Value::as_str)
            .expect("string field")
            .to_owned()
    }

    fn shutdown_config(root: &Path) -> Config {
        serde_json::from_value(json!({
            "listeners": [AgentListener {
                agent_id: "alice".to_owned(),
                socket_path: root.join("alice.sock"),
                source_id: None,
            }],
            "data_dir": root.join("data"),
            "temporary_policy_socket": root.join("policy.sock"),
            "agent_api_enabled": true,
            "test_context_block": true,
            "test_context_inject_declared": false,
            "test_context_declared_ttl": 900,
            "sse_streaming_enabled": true,
            "flow_store_enabled": false,
            "flow_store_db_path": root.join("flows.sqlite3"),
            "admin_port": 0,
            "admin_api_token_file": root.join("operator-token"),
            "readiness_file": root.join("ready.json"),
            "audit_log_path": root.join("audit.jsonl"),
            "event_log": root.join("events.jsonl"),
            "via_token": "plumb-shutdown-test"
        }))
        .unwrap()
    }

    fn response_status(bytes: &[u8]) -> u16 {
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse().ok())
            .expect("HTTP response status")
    }

    fn response_json(bytes: &[u8]) -> Value {
        let body = std::str::from_utf8(bytes)
            .unwrap()
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("HTTP response body");
        serde_json::from_str(body).unwrap()
    }

    async fn raw_agent_request(socket: &Path, body: &[u8]) -> Vec<u8> {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        let request = format!(
            "POST http://_safeyolo.proxy.internal/plumb/request-chat HTTP/1.1\r\n\
             Host: _safeyolo.proxy.internal\r\nAuthorization: Bearer {SHUTDOWN_AGENT_TOKEN}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("agent request must finish")
            .unwrap();
        response
    }

    async fn raw_admin_approval(port: u16, request_id: &str) -> std::io::Result<Vec<u8>> {
        let body =
            serde_json::to_string(&json!({"request_id":request_id,"ttl_seconds":120})).unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let request = format!(
            "POST /admin/plumb/approve HTTP/1.1\r\nHost: localhost\r\n\
             Authorization: Bearer {SHUTDOWN_OPERATOR_TOKEN}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .expect("operator approval must finish")?;
        Ok(response)
    }

    #[tokio::test]
    async fn approval_membership_message_and_persistence_share_one_store() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        let request = owner
            .request_chat(
                "alice",
                &[json!("alice"), json!("bob")],
                Some(&json!("topic")),
                Some(&json!("note")),
                None,
            )
            .await;
        assert_eq!(request["status"], 202);
        let request_id = text(&request, "request_id");
        let approved = owner.approve(&request_id, None).await;
        assert_eq!(approved["status"], 200);
        let conversation_id = text(&approved, "conversation_id");

        let denied = owner
            .post_message("mallory", &conversation_id, "forbidden", json!([]))
            .await;
        assert_eq!(denied["status"], 403);
        let sent = owner
            .post_message("bob", &conversation_id, "hello", json!([]))
            .await;
        assert_eq!(sent["status"], 200);
        assert_eq!(sent["detected_classes"], json!([]));
        let logged = owner
            .post_message(
                "bob",
                &conversation_id,
                "bearer abcdefghijklmnopqrst",
                json!([]),
            )
            .await;
        assert_eq!(logged["status"], 200);
        assert_eq!(
            logged["detected_classes"],
            json!(["generic-bearer-in-body"])
        );
        let blocked = owner
            .post_message(
                "bob",
                &conversation_id,
                "sk-admin-12345678 bearer abcdefghijklmnopqrst",
                json!([]),
            )
            .await;
        assert_eq!(blocked["status"], 403);
        assert_eq!(
            blocked["detected_classes"],
            json!(["openai-admin-key", "generic-bearer-in-body"])
        );
        let page = owner
            .read_messages("alice", &conversation_id, None, 0, DEFAULT_PAGE_LIMIT)
            .await;
        assert_eq!(page["status"], 200);
        assert_eq!(page["messages"][0]["from_agent"], "bob");

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        let conversations = reloaded.list_conversations("alice").await;
        assert_eq!(
            conversations["conversations"][0]["conversation_id"],
            conversation_id
        );
        let persisted = reloaded
            .read_messages("alice", &conversation_id, None, 0, DEFAULT_PAGE_LIMIT)
            .await;
        assert_eq!(persisted["messages"][0]["body"], "hello");
    }

    #[tokio::test]
    async fn canonical_agent_labels_accept_leading_digit() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        let request = owner
            .request_chat("1alice", &[json!("bob")], None, None, None)
            .await;
        assert_eq!(request["status"], 202);
        assert_eq!(request["participants"], json!(["1alice", "bob"]));
    }

    #[tokio::test]
    async fn scan_failure_returns_unavailable_instead_of_clean_allow() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let approved = owner.approve(&text(&request, "request_id"), None).await;
        let conversation_id = text(&approved, "conversation_id");
        owner.inject_scan_failure(true);
        let result = owner
            .post_message("bob", &conversation_id, "ordinary", json!([]))
            .await;
        assert_eq!(result["status"], 503);
        assert_eq!(result["error"], "message scanning unavailable");
    }

    #[test]
    fn message_and_leave_close_audits_match_source_shape() {
        let request = Request {
            method: "POST",
            path_and_query: "/plumb/conversations/conv-1/messages",
            authorization: None,
            identity: Identity::Resolved("alice"),
            client_ip: Some("127.0.0.1"),
            request_id: "req-1",
        };
        for (result, expected_event, expected_decision) in [
            (
                json!({
                    "status": 200,
                    "detected_classes": [],
                }),
                "plumb.message_allowed",
                crate::audit::Decision::Allow,
            ),
            (
                json!({
                    "status": 200,
                    "detected_classes": ["generic-bearer-in-body"],
                }),
                "plumb.message_flagged",
                crate::audit::Decision::Allow,
            ),
            (
                json!({
                    "status": 403,
                    "error": "message blocked: credential/secret detected",
                    "detected_classes": ["openai-admin-key"],
                }),
                "plumb.message_blocked",
                crate::audit::Decision::Deny,
            ),
        ] {
            let audit =
                message_audit(request, "alice", "conv-1", 7, &result).expect("message audit");
            let event = audit.to_event();
            assert_eq!(event.event, expected_event);
            assert_eq!(event.kind, crate::audit::Kind::Plumb);
            assert_eq!(event.decision, Some(expected_decision));
            assert_eq!(event.agent.as_deref(), Some("alice"));
            assert_eq!(event.request_id.as_deref(), Some("req-1"));
            let details: Value =
                serde_json::from_str(&event.details.render_json(false).unwrap()).unwrap();
            assert_eq!(details["conversation_id"], "conv-1");
            assert_eq!(details["detected_classes"], result["detected_classes"]);
            assert!(details.get("body").is_none());
            assert!(!event.summary.contains("bearer"));
        }

        let event =
            conversation_closed_audit(request, "conv-1", "last participant left").to_event();
        assert_eq!(event.event, "plumb.conversation_closed");
        assert_eq!(event.kind, crate::audit::Kind::Plumb);
        assert_eq!(event.severity, crate::audit::Severity::Low);
        assert_eq!(event.decision, Some(crate::audit::Decision::Log));
        assert_eq!(event.agent, None);
        let details: Value =
            serde_json::from_str(&event.details.render_json(false).unwrap()).unwrap();
        assert_eq!(details["conversation_id"], "conv-1");
        assert_eq!(details["reason"], "last participant left");
        assert!(details.get("body").is_none());
    }

    #[tokio::test]
    async fn configured_limits_match_source_defaults_and_zero_message_cap() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        owner.configure_limits(2, 0, 1, 17);
        let too_many = owner
            .request_chat("1alice", &[json!("bob"), json!("carol")], None, None, None)
            .await;
        assert_eq!(too_many["status"], 400);
        let request = owner
            .request_chat("1alice", &[json!("bob")], None, None, None)
            .await;
        assert_eq!(request["ttl_seconds"], 17);
        let approved = owner.approve(&text(&request, "request_id"), None).await;
        let conversation_id = text(&approved, "conversation_id");
        let body = "x".repeat(DEFAULT_MAX_MESSAGE_BYTES + 1);
        let sent = owner
            .post_message("bob", &conversation_id, &body, json!([]))
            .await;
        assert_eq!(sent["status"], 200);
        let page = owner
            .read_messages("1alice", &conversation_id, None, 0, DEFAULT_PAGE_LIMIT)
            .await;
        assert_eq!(page["limit"], 1);
    }

    #[tokio::test]
    async fn leave_closes_without_waking_waiters_and_rejects_subsequent_reads() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let approved = owner.approve(&text(&request, "request_id"), None).await;
        let conversation_id = text(&approved, "conversation_id");

        let waiter_ready = owner.waiter_started.notified();
        let waiting = {
            let owner = owner.clone();
            let conversation_id = conversation_id.clone();
            tokio::spawn(async move {
                owner
                    .read_messages("alice", &conversation_id, None, MAX_WAIT_SECONDS, 1)
                    .await
            })
        };
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_secs(1), waiter_ready)
                .await
                .is_ok()
        );
        assert_eq!(owner.waiters.load(std::sync::atomic::Ordering::Acquire), 1);
        let mut waiting = waiting;
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        let left = owner.leave("bob", &conversation_id).await;
        assert_eq!(left["status"], 200);
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        waiting.abort();
        let _ = waiting.await;
        assert_eq!(owner.waiters.load(std::sync::atomic::Ordering::Acquire), 0);
        let rejected = owner
            .read_messages("alice", &conversation_id, None, 0, DEFAULT_PAGE_LIMIT)
            .await;
        assert_eq!(rejected["status"], 403);
        assert_eq!(
            owner.list_conversations("alice").await["conversations"],
            json!([])
        );
    }

    #[tokio::test]
    async fn operator_close_does_not_wake_waiters_and_rejects_subsequent_reads() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let approved = owner.approve(&text(&request, "request_id"), None).await;
        let conversation_id = text(&approved, "conversation_id");
        let owner_for_wait = owner.clone();
        let conversation_for_wait = conversation_id.clone();
        let waiter_ready = owner.waiter_started.notified();
        let mut waiting = tokio::spawn(async move {
            owner_for_wait
                .read_messages("alice", &conversation_for_wait, None, MAX_WAIT_SECONDS, 1)
                .await
        });
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_secs(1), waiter_ready)
                .await
                .is_ok()
        );
        assert_eq!(owner.waiters.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(owner.close(&conversation_id).await["status"], 200);
        assert!(
            tokio::time::timeout(tokio::time::Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        waiting.abort();
        let _ = waiting.await;
        assert_eq!(owner.waiters.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(
            owner
                .read_messages("alice", &conversation_id, None, 0, DEFAULT_PAGE_LIMIT)
                .await["status"],
            403
        );
    }

    #[tokio::test]
    async fn shutdown_wakes_waiters_and_closes_new_plumb_admission() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let approved = owner.approve(&text(&request, "request_id"), None).await;
        let conversation_id = text(&approved, "conversation_id");

        let waiter_ready = owner.waiter_started.notified();
        let owner_for_wait = owner.clone();
        let conversation_for_wait = conversation_id.clone();
        let mut waiting = tokio::spawn(async move {
            owner_for_wait
                .read_messages("alice", &conversation_for_wait, None, MAX_WAIT_SECONDS, 1)
                .await
        });
        tokio::time::timeout(tokio::time::Duration::from_secs(1), waiter_ready)
            .await
            .expect("shutdown control must observe the active waiter");
        assert_eq!(owner.waiters.load(std::sync::atomic::Ordering::Acquire), 1);

        owner.stop_admission().await;
        let result = tokio::time::timeout(tokio::time::Duration::from_secs(1), &mut waiting)
            .await
            .expect("shutdown must release an active long poll")
            .expect("waiter task must join");
        assert_eq!(result["status"], 503);
        assert_eq!(owner.waiters.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(
            owner
                .request_chat("alice", &[json!("carol")], None, None, None)
                .await["status"],
            503
        );
        assert_eq!(owner.list_pending().await["status"], 503);
        assert_eq!(owner.admin_list_conversations().await["status"], 503);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_store_call_remains_owned_until_plumb_drain() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let store = owner.store.clone().expect("test owner has a store");
        let (started_sender, started_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let owner_for_call = owner.clone();
        let call = tokio::spawn(async move {
            owner_for_call
                .db_call(store, move |_| {
                    started_sender
                        .send(())
                        .expect("test call receiver must still exist");
                    release_receiver.recv().expect("test call must be released");
                    Ok::<_, rusqlite::Error>(())
                })
                .await
        });
        started_receiver.await.expect("owned store call must start");
        call.abort();
        owner.stop_admission().await;
        release_sender
            .send(())
            .expect("owned store call must still be running");
        owner.drain().await;
        assert!(owner.calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn request_audit_submission_failure_keeps_committed_projection() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        writer.poison_for_test();

        let result = owner
            .request_chat_owned(
                "request-audit-failure".into(),
                "alice".into(),
                vec![json!("bob")],
                None,
                None,
                None,
                Some(writer.clone()),
            )
            .await;
        assert_eq!(result.value["status"], 500);
        owner.stop_admission().await;
        owner.drain().await;

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        assert_eq!(
            reloaded.list_pending().await["pending"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(!directory.path().join("audit.jsonl").exists());
    }

    #[tokio::test]
    async fn request_audit_destination_failure_does_not_claim_operator_submission() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        let path = directory.path().join("audit.jsonl");
        std::fs::create_dir(&path).unwrap();
        let writer = Arc::new(crate::audit::Writer::new(
            path.clone(),
            crate::audit::Settings::default(),
        ));
        let failed = owner
            .request_chat_owned(
                "unwritten-plumb-request".into(),
                "alice".into(),
                vec![json!("bob")],
                None,
                None,
                None,
                Some(writer.clone()),
            )
            .await;
        assert_eq!(failed.value["status"], 500);
        assert_eq!(failed.failure, Some(super::super::Failure::AuditWrite));
        assert!(path.is_dir());

        std::fs::remove_dir(&path).unwrap();
        let healthy = owner
            .request_chat_owned(
                "written-plumb-request".into(),
                "alice".into(),
                vec![json!("bob")],
                None,
                None,
                None,
                Some(writer.clone()),
            )
            .await;
        assert_eq!(healthy.value["status"], 202);
        let audit = std::fs::read_to_string(&path).unwrap();
        assert!(audit.contains("written-plumb-request"));
        assert!(!audit.contains("unwritten-plumb-request"));
        owner.stop_admission().await;
        owner.drain().await;
        assert!(writer.shutdown(std::time::Duration::from_secs(2)).unwrap());
    }

    #[tokio::test]
    async fn admin_audit_submission_failure_keeps_committed_projection() {
        let directory = tempfile::tempdir().unwrap();
        let owner = PlumbOwner::for_data_dir(directory.path());
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let request_id = text(&request, "request_id");
        let writer = Arc::new(crate::audit::Writer::new(
            directory.path().join("audit.jsonl"),
            crate::audit::Settings::default(),
        ));
        writer.poison_for_test();

        let result = owner.approve_owned(request_id, None, Some(writer)).await;
        assert!(matches!(result, Err(crate::admin_api::Error::Audit(_))));
        owner.stop_admission().await;
        owner.drain().await;

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        assert_eq!(
            reloaded.admin_list_conversations().await["conversations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // Hold SQLite open to deterministically gate the owned worker.
    async fn canceled_request_chat_keeps_projection_and_canonical_audit() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let store = owner.store.clone().expect("test owner has a store");
        let connection = store.connection.lock().unwrap();
        let audit_path = directory.path().join("audit.jsonl");
        let writer = Arc::new(crate::audit::Writer::new(
            audit_path.clone(),
            crate::audit::Settings::default(),
        ));
        let caller = {
            let owner = owner.clone();
            let writer = writer.clone();
            tokio::spawn(async move {
                owner
                    .request_chat_owned(
                        "request-chat-cancelled".into(),
                        "alice".into(),
                        vec![json!("bob")],
                        None,
                        None,
                        None,
                        Some(writer),
                    )
                    .await
            })
        };
        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                if !owner.calls.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("request mutation must enter the owned SQLite task");
        caller.abort();
        owner.stop_admission().await;
        drop(connection);
        owner.drain().await;
        assert_eq!(owner.list_pending().await["status"], 503);
        assert!(writer.shutdown(std::time::Duration::from_secs(2)).unwrap());

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        assert_eq!(
            reloaded.list_pending().await["pending"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let rows: Vec<Value> = std::fs::read_to_string(audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|row| row["event"] == "plumb.requested")
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // Hold SQLite open to deterministically gate the owned worker.
    async fn canceled_message_keeps_projection_and_canonical_audit() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let request_id = text(&request, "request_id");
        let approved = owner.approve(&request_id, None).await;
        let conversation_id = text(&approved, "conversation_id");
        owner.drain().await;

        let store = owner.store.clone().expect("test owner has a store");
        let connection = store.connection.lock().unwrap();
        let audit_path = directory.path().join("audit.jsonl");
        let writer = Arc::new(crate::audit::Writer::new(
            audit_path.clone(),
            crate::audit::Settings::default(),
        ));
        let caller = {
            let owner = owner.clone();
            let writer = writer.clone();
            let conversation_id = conversation_id.clone();
            tokio::spawn(async move {
                owner
                    .post_message_owned(
                        "message-cancelled".into(),
                        "bob".into(),
                        conversation_id,
                        "hello from the canceled caller".into(),
                        json!([]),
                        Some(writer),
                    )
                    .await
            })
        };
        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                if !owner.calls.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("message mutation must enter the owned SQLite task");
        caller.abort();
        drop(connection);
        owner.stop_admission().await;
        owner.drain().await;
        assert!(writer.shutdown(std::time::Duration::from_secs(2)).unwrap());

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        let page = reloaded
            .read_messages("alice", &conversation_id, None, 0, 1)
            .await;
        assert_eq!(
            page["messages"][0]["body"],
            "hello from the canceled caller"
        );
        let rows: Vec<Value> = std::fs::read_to_string(audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|row| row["event"] == "plumb.message_allowed")
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // Hold SQLite open to deterministically gate the owned worker.
    async fn canceled_leave_keeps_projection_and_canonical_audit() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let request_id = text(&request, "request_id");
        let approved = owner.approve(&request_id, None).await;
        let conversation_id = text(&approved, "conversation_id");
        owner.drain().await;

        let store = owner.store.clone().expect("test owner has a store");
        let connection = store.connection.lock().unwrap();
        let audit_path = directory.path().join("audit.jsonl");
        let writer = Arc::new(crate::audit::Writer::new(
            audit_path.clone(),
            crate::audit::Settings::default(),
        ));
        let caller = {
            let owner = owner.clone();
            let writer = writer.clone();
            let conversation_id = conversation_id.clone();
            tokio::spawn(async move {
                owner
                    .leave_owned(
                        "leave-cancelled".into(),
                        "bob".into(),
                        conversation_id,
                        Some(writer),
                    )
                    .await
            })
        };
        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                if !owner.calls.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("leave mutation must enter the owned SQLite task");
        caller.abort();
        drop(connection);
        owner.stop_admission().await;
        owner.drain().await;
        assert!(writer.shutdown(std::time::Duration::from_secs(2)).unwrap());

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        assert_eq!(
            reloaded.admin_list_conversations().await["conversations"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let rows: Vec<Value> = std::fs::read_to_string(audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|row| row["event"] == "plumb.conversation_closed")
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // Hold SQLite open to deterministically gate the owned worker.
    async fn canceled_approval_keeps_projection_and_both_canonical_audits() {
        let directory = tempfile::tempdir().unwrap();
        let owner = Arc::new(PlumbOwner::for_data_dir(directory.path()));
        let request = owner
            .request_chat("alice", &[json!("bob")], None, None, None)
            .await;
        let request_id = text(&request, "request_id");
        let store = owner.store.clone().expect("test owner has a store");
        let audit_path = directory.path().join("audit.jsonl");
        let writer = Arc::new(crate::audit::Writer::new(
            audit_path.clone(),
            crate::audit::Settings::default(),
        ));
        owner.drain().await;
        let connection = store.connection.lock().unwrap();
        let caller = {
            let owner = owner.clone();
            let writer = writer.clone();
            let request_id = request_id.clone();
            tokio::spawn(async move { owner.approve_owned(request_id, None, Some(writer)).await })
        };
        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            loop {
                if !owner.calls.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval mutation must enter the owned SQLite task");
        caller.abort();
        drop(connection);
        owner.stop_admission().await;
        owner.drain().await;
        assert!(writer.shutdown(std::time::Duration::from_secs(2)).unwrap());

        let reloaded = PlumbOwner::for_data_dir(directory.path());
        assert_eq!(
            reloaded.admin_list_conversations().await["conversations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let rows: Vec<Value> = std::fs::read_to_string(audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|row| row["event"] == "plumb.approved")
                .count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row["event"] == "plumb.conversation_created")
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::await_holding_lock)] // Hold the real store boundary until the shutdown owner begins to drain it.
    async fn shutdown_fence_rejects_later_admin_approval_while_admitted_approval_drains() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let data_dir = root.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("agent_token"), SHUTDOWN_AGENT_TOKEN).unwrap();
        std::fs::write(root.join("operator-token"), SHUTDOWN_OPERATOR_TOKEN).unwrap();

        let proxy = Proxy::start(shutdown_config(root)).await.unwrap();
        let admin_port = proxy.admin.as_ref().unwrap().address().port();
        let agent_socket = root.join("alice.sock");

        // These real accepted-agent requests leave two durable pending rows.
        // The first will be admitted before the fence and the second gives the
        // post-fence control a distinct state and audit identity.
        let control_requested = raw_agent_request(
            &agent_socket,
            br#"{"participants":["bob"],"topic":"admitted shutdown control"}"#,
        )
        .await;
        assert_eq!(response_status(&control_requested), 202);
        let control_request_id = text(&response_json(&control_requested), "request_id");
        let declined_requested = raw_agent_request(
            &agent_socket,
            br#"{"participants":["carol"],"topic":"post-fence decline control"}"#,
        )
        .await;
        assert_eq!(response_status(&declined_requested), 202);
        let declined_request_id = text(&response_json(&declined_requested), "request_id");

        let runtime = proxy.runtime.read().unwrap().clone();
        let plumb = runtime.plumb.clone();
        let writer = runtime.audit.clone();
        plumb.drain().await;
        let store = plumb
            .store
            .clone()
            .expect("started proxy has plumb storage");
        let connection = store.connection.lock().unwrap();

        let control = {
            let request_id = control_request_id.clone();
            tokio::spawn(async move { raw_admin_approval(admin_port, &request_id).await })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            while plumb.calls.lock().await.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("admitted admin approval must reach the owned SQLite call");

        // This is the exact fence Proxy::shutdown invokes before listener
        // drain. It publishes `closing` before waiting for the control's held
        // memory/store operation, so a later request cannot acquire an owned
        // operation slot.
        let fence = {
            let plumb = plumb.clone();
            tokio::spawn(async move { plumb.stop_admission().await })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            while !plumb.closing.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown fence must close plumb admission");

        // The admitted operation holds the memory lock while its SQLite call
        // is blocked. The fence closes admission while holding the operations
        // lock, then waits for memory. Shutdown may close the admin listener
        // before this later request receives its 503.
        let declined = {
            let request_id = declined_request_id.clone();
            tokio::spawn(async move { raw_admin_approval(admin_port, &request_id).await })
        };
        // A closed transport cannot prove the owner rejected the request, so
        // probe admission directly with the same pending row as well.
        let declined_owner = {
            let plumb = plumb.clone();
            let writer = writer.clone();
            let request_id = declined_request_id.clone();
            tokio::spawn(async move {
                plumb
                    .approve_owned(request_id, Some(120), Some(writer))
                    .await
            })
        };
        let mut shutdown = tokio::spawn(proxy.shutdown());
        tokio::time::timeout(Duration::from_secs(3), async {
            while root.join("ready.json").exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("proxy shutdown must remove readiness before drain completion");
        assert!(
            !shutdown.is_finished(),
            "shutdown must retain the admitted SQLite operation rather than stopping the writer"
        );

        drop(connection);
        fence.await.unwrap();
        let control = tokio::time::timeout(Duration::from_secs(5), control)
            .await
            .expect("admitted control must finish after fixture release")
            .unwrap()
            .expect("admitted control must receive an HTTP response");
        let declined = tokio::time::timeout(Duration::from_secs(5), declined)
            .await
            .expect("post-fence request must receive a terminal result")
            .unwrap();
        let declined_owner = tokio::time::timeout(Duration::from_secs(5), declined_owner)
            .await
            .expect("post-fence owner request must finish")
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut shutdown)
            .await
            .expect("proxy shutdown must join the admitted operation")
            .unwrap();
        assert!(
            plumb.calls.lock().await.is_empty() && plumb.operations.lock().await.is_empty(),
            "shutdown must join the admitted plumb operation and its SQLite call"
        );

        assert_eq!(
            response_status(&control),
            200,
            "the admitted control must report its completed approval"
        );
        assert_eq!(
            declined_owner["status"], 503,
            "the fence must deny an owned operation even if the listener closes"
        );
        let database = Connection::open(data_dir.join("plumb").join("plumb.db")).unwrap();
        let control_status: String = database
            .query_row(
                "SELECT status FROM plumb_pending WHERE request_id=?1",
                params![&control_request_id],
                |row| row.get(0),
            )
            .unwrap();
        let declined_status: String = database
            .query_row(
                "SELECT status FROM plumb_pending WHERE request_id=?1",
                params![&declined_request_id],
                |row| row.get(0),
            )
            .unwrap();
        let grants: i64 = database
            .query_row("SELECT COUNT(*) FROM plumb_grants", [], |row| row.get(0))
            .unwrap();
        assert_eq!(control_status, "approved");
        assert_eq!(declined_status, "pending");
        assert_eq!(grants, 1, "only the admitted request may create a grant");

        let rows: Vec<Value> = std::fs::read_to_string(root.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows.iter()
                .filter(|row| {
                    row["event"] == "plumb.approved"
                        && row["details"]["request_id"] == control_request_id
                })
                .count(),
            1,
            "the admitted approval must retain one canonical approval attempt"
        );
        assert_eq!(
            rows.iter()
                .filter(|row| {
                    row["event"] == "plumb.approved"
                        && row["details"]["request_id"] == declined_request_id
                })
                .count(),
            0,
            "the declined request must not submit an approval audit"
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row["event"] == "plumb.conversation_created")
                .count(),
            1,
            "the admitted approval must retain one canonical conversation audit attempt"
        );

        // These independent state/audit assertions are detector-sensitive:
        // admitting the second request would alter its SQLite/audit identity,
        // and stopping the writer before the control drains leaves the two
        // required canonical events absent.
        assert_eq!(
            writer
                .emit(Event::new(
                    "ops.plumb_shutdown_probe",
                    Kind::Ops,
                    Severity::Low,
                    "Plumb shutdown probe",
                ))
                .unwrap(),
            Submission::Stopped,
            "writer must stop only after the admitted approval's audit attempt"
        );
        assert!(!root.join("ready.json").exists());
        assert!(!agent_socket.exists());
        assert!(
            TcpStream::connect(("127.0.0.1", admin_port)).await.is_err(),
            "shutdown must release the authenticated admin listener"
        );
        // Shutdown can close the listener or an accepted connection before
        // it sends 503. The owner and durable-state checks above still prove
        // that the later approval was not admitted.
        match declined {
            Ok(response) if response.is_empty() => {}
            Ok(response) => assert_eq!(
                response_status(&response),
                503,
                "the post-fence request must be declined before it starts"
            ),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                ) => {}
            Err(error) => panic!("unexpected post-fence transport failure: {error}"),
        }
    }
}
