//! Native bridge to the retained coordination substrate.
//!
//! Room membership and instance identity remain authoritative in the
//! versioned SQLite store owned by the CLI.  Message history remains in the
//! per-room JetStream stream.  This module is deliberately a client of those
//! stores: it does not maintain a second room database or proxy through the
//! Python Agent API.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},

    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_nats::jetstream::{
    self,
    consumer::{AckPolicy, DeliverPolicy, pull},
};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};

use super::{AuditIntent, AuditKind, Outcome, Request, RequestBody, agent, response};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_COORD_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAGE: usize = 200;
const ROOM_MAX_BYTES: usize = 4 * 1024 * 1024;
const NATS_USER: &str = "safeyolo";
const CURRENT_SCHEMA_VERSION: i64 = 5;
const MAX_DECLARATIONS_PER_AGENT: usize = 32;
const MAX_DECLARATION_TTL_SECONDS: i64 = 3600;

#[derive(Debug)]
enum CoordError {
    NotFound,
    Forbidden,
    Unavailable,
    Data,
    PublishUnknown,
}

/// Process-owned coordination client.  The client object is retained when a
/// Runtime is reloaded, so all native Agent API requests use the same NATS
/// connection and durable SQLite/NATS namespace.
pub struct CoordClient {
    data_dir: PathBuf,
    policy_file: Option<PathBuf>,
    nats: tokio::sync::Mutex<Option<async_nats::Client>>,
}

impl CoordClient {
    pub(crate) fn new(policy_file: Option<PathBuf>) -> Self {
        let data_dir = std::env::var_os("SAFEYOLO_COORD_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".safeyolo/data/coord"))
            })
            .unwrap_or_else(|| PathBuf::from(".safeyolo/data/coord"));
        Self {
            data_dir,
            policy_file,
            nats: tokio::sync::Mutex::new(None),
        }
    }

    async fn client(&self) -> Result<async_nats::Client, CoordError> {
        let mut current = self.nats.lock().await;
        if let Some(client) = current.as_ref()
            && matches!(
                client.connection_state(),
                async_nats::connection::State::Connected
            )
        {
            return Ok(client.clone());
        }
        let url = self.nats_url();
        let password = std::fs::read(self.data_dir.join("nats/creds"))
            .map_err(|_| CoordError::Unavailable)?;
        let password = std::str::from_utf8(&password)
            .map_err(|_| CoordError::Unavailable)?
            .trim()
            .to_owned();
        if password.is_empty() {
            return Err(CoordError::Unavailable);
        }
        let client = async_nats::ConnectOptions::new()
            .user_and_password(NATS_USER.to_owned(), password)
            .connection_timeout(Duration::from_secs(2))
            .request_timeout(Some(Duration::from_secs(2)))
            .connect(url)
            .await
            .map_err(|_| CoordError::Unavailable)?;
        *current = Some(client.clone());
        Ok(client)
    }

    fn nats_url(&self) -> String {
        if let Some(url) = std::env::var_os("SAFEYOLO_COORD_NATS_URL") {
            return url.to_string_lossy().into_owned();
        }
        let endpoint = self.data_dir.join("nats/test-endpoints.json");
        if let Ok(bytes) = std::fs::read(endpoint)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && let Some(port) = value.get("client_port").and_then(Value::as_u64)
            && port <= u16::MAX as u64
        {
            return format!("nats://127.0.0.1:{port}");
        }
        "nats://127.0.0.1:4222".to_owned()
    }

    async fn principal_id(&self, name: &str) -> String {
        let name = name.to_owned();
        let fallback = name.clone();
        let policy_file = self.policy_file.clone();
        tokio::task::spawn_blocking(move || {
            if name.starts_with("ag-") {
                return name;
            }
            let Some(path) = policy_file else {
                return name;
            };
            let Ok(source) = std::fs::read_to_string(path) else {
                return name;
            };
            let Ok(document) = source.parse::<toml_edit::DocumentMut>() else {
                return name;
            };
            document
                .get("agents")
                .and_then(toml_edit::Item::as_table_like)
                .and_then(|agents| agents.get(&name))
                .and_then(toml_edit::Item::as_table_like)
                .and_then(|agent| agent.get("agent_id"))
                .and_then(toml_edit::Item::as_str)
                .map_or(name.clone(), str::to_owned)
        })
        .await
        .unwrap_or(fallback)
    }

    async fn access(&self, room: &str, principal: &str) -> Result<RoomAccess, CoordError> {
        let db = self.data_dir.join("v0.db");
        let room = room.to_owned();
        let principal = principal.to_owned();
        tokio::task::spawn_blocking(move || read_access(&db, &room, &principal))
            .await
            .map_err(|_| CoordError::Unavailable)?
    }

    async fn display_names(&self, principal_ids: &[String]) -> HashMap<String, String> {
        let principal_ids = principal_ids.to_vec();
        let policy_file = self.policy_file.clone();
        tokio::task::spawn_blocking(move || {
            let Some(path) = policy_file else {
                return HashMap::new();
            };
            let Ok(source) = std::fs::read_to_string(path) else {
                return HashMap::new();
            };
            let Ok(document) = source.parse::<toml_edit::DocumentMut>() else {
                return HashMap::new();
            };
            let Some(agents) = document
                .get("agents")
                .and_then(toml_edit::Item::as_table_like)
            else {
                return HashMap::new();
            };
            agents
                .iter()
                .filter_map(|(name, item)| {
                    let id = item
                        .as_table_like()?
                        .get("agent_id")?
                        .as_str()?;
                    principal_ids
                        .iter()
                        .any(|principal_id| principal_id == id)
                        .then(|| (id.to_owned(), name.to_owned()))
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    async fn room_state(
        &self,
        room_name: &str,
        principal: &str,
        _access: &RoomAccess,
    ) -> Result<Value, CoordError> {
        let db = self.data_dir.join("v0.db");
        let room = room_name.to_owned();
        let principal = principal.to_owned();
        let data = tokio::task::spawn_blocking(move || {
            read_state_data(&db, &room, &principal)
        })
        .await
        .map_err(|_| CoordError::Unavailable)??;
        // The bounded SQLite read above is a provider boundary.  Re-read the
        // current grant before exposing the assembled state so a revoke or a
        // newer membership generation cannot race the response.
        let current_access = self.access(room_name, principal).await?;
        if !current_access
            .permissions
            .iter()
            .any(|permission| permission == "receive")
        {
            return Err(CoordError::Forbidden);
        }
        let agent_ids = current_access
            .members
            .iter()
            .filter(|member| member.principal_kind == "agent")
            .map(|member| member.principal_id.clone())
            .collect::<Vec<_>>();
        let display_names = self.display_names(&agent_ids).await;
        let declaration_map = data.declarations.into_iter().fold(
            HashMap::<String, Vec<Value>>::new(),
            |mut declarations, (agent_id, capability, asserted_at, valid_until)| {
                let asserted_by_agent_id = agent_id.clone();
                declarations.entry(agent_id).or_default().push(json!({
                    "capability": capability,
                    "asserted_by_agent_id": asserted_by_agent_id,
                    "asserted_at": asserted_at,
                    "valid_until": valid_until,
                    "freshness": "fresh",
                    "provenance": "agent_declared",
                }));
                declarations
            },
        );
        let mut seen = HashSet::new();
        let members = current_access
            .members
            .iter()
            .filter(|member| member.principal_kind == "agent")
            .filter(|member| seen.insert(member.principal_id.clone()))
            .map(|member| {
                let declarations = declaration_map
                    .get(&member.principal_id)
                    .cloned()
                    .unwrap_or_default();
                json!({
                    "agent_id": member.principal_id,
                    "display_name": display_names.get(&member.principal_id),
                    "configured": display_names.contains_key(&member.principal_id),
                    "origin_instance_id": current_access.instance_id,
                    "room_permissions": member.permissions,
                    "verified": [],
                    "declared": declarations,
                })
            })
            .collect::<Vec<_>>();
        let resource_leases = data
            .resources
            .into_iter()
            .map(|(provider, resource)| {
                json!({
                    "provider": provider,
                    "resource": resource,
                    "state": "unknown",
                    "holder_agent_id": Value::Null,
                    "holder_display_name": Value::Null,
                    "observed_at": Value::Null,
                    "valid_until": Value::Null,
                    "freshness": "unknown",
                    "provenance": "provider_owned_lease",
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "room_id": current_access.room_id,
            "room_name": current_access.room_name,
            "origin_instance_id": current_access.instance_id,
            "generated_at": now_ms(),
            "brief": current_access.brief,
            "members": members,
            "resource_leases": resource_leases,
        }))
    }

    async fn write_declarations(
        &self,
        room_name: &str,
        principal: &str,
        capabilities: &[String],
        ttl_seconds: i64,
    ) -> Result<Value, CoordError> {
        let db = self.data_dir.join("v0.db");
        let room = room_name.to_owned();
        let principal = principal.to_owned();
        let capabilities = capabilities.to_vec();
        tokio::task::spawn_blocking(move || {
            write_declarations(&db, &room, &principal, &capabilities, ttl_seconds)
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }

    async fn attention_feed(
        &self,
        principal: &str,
        since: u64,
        limit: usize,
    ) -> Result<FeedPage, CoordError> {
        let db = self.data_dir.join("v0.db");
        let principal = principal.to_owned();
        tokio::task::spawn_blocking(move || read_attention_feed(&db, &principal, since, limit))
            .await
            .map_err(|_| CoordError::Unavailable)?
    }

    async fn wait_attention(
        &self,
        principal: &str,
        since: u64,
        limit: usize,
        timeout_seconds: f64,
    ) -> Result<FeedPage, CoordError> {
        let page = self.attention_feed(principal, since, limit).await?;
        if !page.edges.is_empty() || page.next_cursor != since {
            return Ok(page);
        }
        let connection = self.client().await?;
        let subject = format!("coord.attention.{principal}");
        let mut subscription = connection
            .subscribe(subject)
            .await
            .map_err(|_| CoordError::Unavailable)?;
        connection
            .flush()
            .await
            .map_err(|_| CoordError::Unavailable)?;
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs_f64(timeout_seconds.max(0.0));
        loop {
            let page = self.attention_feed(principal, since, limit).await?;
            if !page.edges.is_empty() || page.next_cursor != since {
                let _ = subscription.unsubscribe().await;
                return Ok(page);
            }
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                let _ = subscription.unsubscribe().await;
                return Ok(page);
            };
            if remaining.is_zero() {
                let _ = subscription.unsubscribe().await;
                return Ok(page);
            }
            let _ = tokio::time::timeout(remaining, subscription.next()).await;
        }
    }

    async fn attention_object(
        &self,
        principal: &str,
        attention_id: &str,
    ) -> Result<Value, CoordError> {
        let db = self.data_dir.join("v0.db");
        let principal_owned = principal.to_owned();
        let attention_owned = attention_id.to_owned();
        let edge = tokio::task::spawn_blocking(move || {
            read_attention_edge(&db, &principal_owned, &attention_owned)
        })
        .await
        .map_err(|_| CoordError::Unavailable)??;
        if edge.kind == "brief_changed" {
            let db = self.data_dir.join("v0.db");
            let edge_for_read = edge.clone();
            let object = tokio::task::spawn_blocking(move || {
                read_brief_revision(&db, &edge_for_read)
            })
            .await
            .map_err(|_| CoordError::Unavailable)??;
            return Ok(json!({"edge": edge.public_json(), "object": object}));
        }
        let connection = self.client().await?;
        let stream = jetstream::new(connection);
        let stream = stream
            .get_stream(room_stream(&edge.room_id))
            .await
            .map_err(|_| CoordError::Unavailable)?;
        let raw = stream
            .get_raw_message(edge.revision_or_sequence)
            .await
            .map_err(|_| CoordError::Unavailable)?;
        let mut envelope: Value = serde_json::from_slice(&raw.payload).map_err(|_| CoordError::Data)?;
        let object = envelope.as_object_mut().ok_or(CoordError::Data)?;
        if object.get("msg_id").and_then(Value::as_str) != Some(edge.object_id.as_str()) {
            return Err(CoordError::Data);
        }
        object.insert("sequence".to_owned(), Value::from(edge.revision_or_sequence));
        let db = self.data_dir.join("v0.db");
        let principal_owned = principal.to_owned();
        let attention_owned = attention_id.to_owned();
        let edge_check = edge.clone();
        tokio::task::spawn_blocking(move || {
            verify_attention_edge(&db, &principal_owned, &attention_owned, &edge_check)
        })
        .await
        .map_err(|_| CoordError::Unavailable)??;
        Ok(json!({"edge": edge.public_json(), "object": object}))
    }
}

pub struct CoordContext<'a> {
    pub(crate) client: &'a CoordClient,
}

struct Membership {
    principal_kind: String,
    principal_id: String,
    granted_at: i64,
    permissions: Vec<String>,
}

struct RoomAccess {
    room_id: String,
    room_name: String,
    permissions: Vec<String>,
    members: Vec<Membership>,
    instance_id: String,
    brief: Value,
}

struct StateData {
    declarations: Vec<(String, String, i64, i64)>,
    resources: Vec<(String, String)>,
}

#[derive(Clone)]
struct AttentionEdge {
    attention_id: String,
    room_id: String,
    kind: String,
    object_id: String,
    revision_or_sequence: u64,
    membership_granted_at: i64,
}

struct FeedEdge {
    attention_id: String,
    room_id: String,
    kind: String,
    object_id: String,
    revision_or_sequence: u64,
}

struct FeedPage {
    edges: Vec<FeedEdge>,
    next_cursor: u64,
}

impl AttentionEdge {
    fn public_json(&self) -> Value {
        json!({
            "attention_id": self.attention_id,
            "room_id": self.room_id,
            "kind": self.kind,
            "object_id": self.object_id,
            "revision_or_sequence": self.revision_or_sequence,
        })
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn open_db(db: &Path, writable: bool) -> Result<Connection, CoordError> {
    if !db.is_file() {
        return Err(CoordError::Unavailable);
    }
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
    };
    let conn = Connection::open_with_flags(db, flags).map_err(|_| CoordError::Unavailable)?;
    conn.busy_timeout(Duration::from_millis(500))
        .map_err(|_| CoordError::Unavailable)?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|_| CoordError::Unavailable)?;
    let version = conn
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(|_| CoordError::Unavailable)?;
    if version != CURRENT_SCHEMA_VERSION {
        return Err(CoordError::Unavailable);
    }
    Ok(conn)
}

fn room_id_for(conn: &Connection, room_name: &str) -> Result<String, CoordError> {
    conn.query_row(
        "SELECT room_id FROM rooms WHERE name = ?1",
        params![room_name],
        |row| row.get(0),
    )
    .optional()
    .map_err(|_| CoordError::Data)?
    .ok_or(CoordError::NotFound)
}

fn current_agent_permissions(
    conn: &Connection,
    room_id: &str,
    principal: &str,
) -> Result<Vec<String>, CoordError> {
    let permissions = conn
        .query_row(
            "SELECT permissions FROM memberships
             WHERE room_id = ?1 AND principal_kind = 'agent'
               AND principal_id = ?2 AND revoked_at IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM memberships AS newer
                  WHERE newer.room_id = memberships.room_id
                    AND newer.principal_kind = 'agent'
                    AND newer.principal_id = memberships.principal_id
                    AND newer.revoked_at IS NULL
                    AND newer.granted_at > memberships.granted_at
               )
             ORDER BY granted_at DESC LIMIT 1",
            params![room_id, principal],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| CoordError::Data)?
        .ok_or(CoordError::NotFound)?;
    Ok(permissions
        .split(',')
        .filter(|permission| !permission.is_empty())
        .map(str::to_owned)
        .collect())
}

fn read_state_data(db: &Path, room_name: &str, principal: &str) -> Result<StateData, CoordError> {
    let conn = open_db(db, false)?;
    let room_id = room_id_for(&conn, room_name)?;
    let permissions = current_agent_permissions(&conn, &room_id, principal)?;
    if !permissions.iter().any(|permission| permission == "receive") {
        return Err(CoordError::Forbidden);
    }
    let declarations = conn
        .prepare(
            "SELECT agent_id, capability, asserted_at, valid_until
             FROM coord_capability_declarations
             WHERE room_id = ?1 AND valid_until > ?2
             ORDER BY agent_id, capability",
        )
        .map_err(|_| CoordError::Data)?
        .query_map(params![room_id, now_ms()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        })
        .map_err(|_| CoordError::Data)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoordError::Data)?;
    let resources = conn
        .prepare(
            "SELECT provider, resource FROM coord_resource_advertisements
             WHERE room_id = ?1 ORDER BY provider, resource",
        )
        .map_err(|_| CoordError::Data)?
        .query_map(params![room_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|_| CoordError::Data)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoordError::Data)?;
    Ok(StateData {
        declarations,
        resources,
    })
}

fn read_attention_feed(
    db: &Path,
    principal: &str,
    since: u64,
    limit: usize,
) -> Result<FeedPage, CoordError> {
    let conn = open_db(db, false)?;
    let highwater = conn
        .query_row(
            "SELECT last_sequence FROM coord_attention_feeds
             WHERE recipient_agent_id = ?1",
            params![principal],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| CoordError::Data)?
        .unwrap_or(0)
        .max(0) as u64;
    let since_i64 = i64::try_from(since).map_err(|_| CoordError::Data)?;
    let limit_i64 = i64::try_from(limit).map_err(|_| CoordError::Data)?;
    let mut statement = conn
        .prepare(
            "SELECT e.attention_id, e.room_id, e.kind, e.object_id,
                    e.revision_or_sequence
             FROM coord_attention_edges AS e
             JOIN memberships AS m
               ON m.room_id = e.room_id
              AND m.principal_kind = 'agent'
              AND m.principal_id = e.recipient_agent_id
              AND m.granted_at = e.membership_granted_at
              AND m.revoked_at IS NULL
             WHERE e.recipient_agent_id = ?1 AND e.feed_sequence > ?2
               AND instr(',' || m.permissions || ',', ',receive,') > 0
               AND NOT EXISTS (
                 SELECT 1 FROM memberships AS newer
                  WHERE newer.room_id = m.room_id
                    AND newer.principal_kind = 'agent'
                    AND newer.principal_id = m.principal_id
                    AND newer.revoked_at IS NULL
                    AND newer.granted_at > m.granted_at
               )
             ORDER BY e.feed_sequence LIMIT ?3",
        )
        .map_err(|_| CoordError::Data)?;
    let edges = statement
        .query_map(params![principal, since_i64, limit_i64], |row| {
            Ok(FeedEdge {
                attention_id: row.get(0)?,
                room_id: row.get(1)?,
                kind: row.get(2)?,
                object_id: row.get(3)?,
                revision_or_sequence: row.get::<_, i64>(4)?.max(0) as u64,
            })
        })
        .map_err(|_| CoordError::Data)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoordError::Data)?;
    let next_cursor = if edges.len() == limit && !edges.is_empty() {
        // The query's feed sequence is intentionally not returned in the
        // public edge. Re-read the last sequence by its stable attention ID.
        conn.query_row(
            "SELECT feed_sequence FROM coord_attention_edges WHERE attention_id = ?1",
            params![edges.last().map(|edge| edge.attention_id.as_str()).unwrap_or_default()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| CoordError::Data)?
        .max(0) as u64
    } else {
        since.max(highwater)
    };
    Ok(FeedPage { edges, next_cursor })
}

fn read_attention_edge(
    db: &Path,
    principal: &str,
    attention_id: &str,
) -> Result<AttentionEdge, CoordError> {
    let conn = open_db(db, false)?;
    conn.query_row(
        "SELECT e.attention_id, e.room_id, e.kind, e.object_id,
                e.revision_or_sequence, e.membership_granted_at
         FROM coord_attention_edges AS e
         JOIN memberships AS m
           ON m.room_id = e.room_id
          AND m.principal_kind = 'agent'
          AND m.principal_id = e.recipient_agent_id
          AND m.granted_at = e.membership_granted_at
          AND m.revoked_at IS NULL
         WHERE e.recipient_agent_id = ?1 AND e.attention_id = ?2
           AND instr(',' || m.permissions || ',', ',receive,') > 0
           AND NOT EXISTS (
             SELECT 1 FROM memberships AS newer
              WHERE newer.room_id = m.room_id
                AND newer.principal_kind = 'agent'
                AND newer.principal_id = m.principal_id
                AND newer.revoked_at IS NULL
                AND newer.granted_at > m.granted_at
           )",
        params![principal, attention_id],
        |row| {
            Ok(AttentionEdge {
                attention_id: row.get(0)?,
                room_id: row.get(1)?,
                kind: row.get(2)?,
                object_id: row.get(3)?,
                revision_or_sequence: row.get::<_, i64>(4)?.max(0) as u64,
                membership_granted_at: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(|_| CoordError::Data)?
    .ok_or(CoordError::NotFound)
}

fn verify_attention_edge(
    db: &Path,
    principal: &str,
    attention_id: &str,
    expected: &AttentionEdge,
) -> Result<(), CoordError> {
    let current = read_attention_edge(db, principal, attention_id)?;
    if current.attention_id != expected.attention_id
        || current.room_id != expected.room_id
        || current.kind != expected.kind
        || current.object_id != expected.object_id
        || current.revision_or_sequence != expected.revision_or_sequence
        || current.membership_granted_at != expected.membership_granted_at
    {
        return Err(CoordError::Data);
    }
    Ok(())
}

fn read_brief_revision(db: &Path, edge: &AttentionEdge) -> Result<Value, CoordError> {
    let conn = open_db(db, false)?;
    conn.query_row(
        "SELECT room_id, revision, markdown, content_hash, updated_at
         FROM coord_brief_revisions
         WHERE room_id = ?1 AND revision = ?2",
        params![edge.room_id, i64::try_from(edge.revision_or_sequence).map_err(|_| CoordError::Data)?],
        |row| {
            Ok(json!({
                "room_id": row.get::<_, String>(0)?,
                "object_id": format!("brief-{}", edge.room_id.trim_start_matches("rm-")),
                "revision": row.get::<_, i64>(1)?,
                "markdown": row.get::<_, String>(2)?,
                "content_hash": row.get::<_, String>(3)?,
                "updated_at": row.get::<_, i64>(4)?,
            }))
        },
    )
    .optional()
    .map_err(|_| CoordError::Data)?
    .ok_or(CoordError::Data)
}

fn public_name_part(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase().then_some(()).is_some()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}

fn valid_capability(value: &str) -> bool {
    let Some((provider, name)) = value.split_once(':') else {
        return false;
    };
    value.matches(':').count() == 1
        && public_name_part(provider)
        && public_name_part(name)
        && ![provider, name].iter().any(|part| {
            part.split(['.', '_', '-'])
                .any(|term| matches!(term, "account" | "credential" | "key" | "password" | "path" | "secret" | "token" | "url"))
        })
}

fn write_declarations(
    db: &Path,
    room_name: &str,
    principal: &str,
    capabilities: &[String],
    ttl_seconds: i64,
) -> Result<Value, CoordError> {
    if capabilities.len() > MAX_DECLARATIONS_PER_AGENT
        || !(1..=MAX_DECLARATION_TTL_SECONDS).contains(&ttl_seconds)
        || capabilities.iter().any(|capability| !valid_capability(capability))
    {
        return Err(CoordError::Data);
    }
    let conn = open_db(db, true)?;
    let room_id = room_id_for(&conn, room_name)?;
    let permissions = current_agent_permissions(&conn, &room_id, principal)?;
    if !permissions.iter().any(|permission| permission == "receive") {
        return Err(CoordError::Forbidden);
    }
    let mut labels = capabilities.to_vec();
    labels.sort();
    labels.dedup();
    let asserted_at = now_ms();
    let valid_until = asserted_at + ttl_seconds * 1000;
    conn.execute("BEGIN IMMEDIATE", []).map_err(|_| CoordError::Unavailable)?;
    let result = (|| {
        conn.execute(
            "DELETE FROM coord_capability_declarations
             WHERE room_id = ?1 AND agent_id = ?2",
            params![room_id, principal],
        )
        .map_err(|_| CoordError::Data)?;
        for capability in &labels {
            conn.execute(
                "INSERT INTO coord_capability_declarations
                 (room_id, agent_id, capability, asserted_at, valid_until)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![room_id, principal, capability, asserted_at, valid_until],
            )
            .map_err(|_| CoordError::Data)?;
        }
        Ok::<_, CoordError>(json!({
            "agent_id": principal,
            "count": labels.len(),
            "asserted_at": asserted_at,
            "valid_until": valid_until,
        }))
    })();
    match result {
        Ok(value) => {
            conn.execute("COMMIT", []).map_err(|_| CoordError::Unavailable)?;
            Ok(value)
        }
        Err(error) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(error)
        }
    }
}

fn attention_event_id(attention_id: &str) -> String {
    // The event is an idempotent projection of one attention edge.  A stable
    // key lets a retry after a process interruption use INSERT OR IGNORE
    // without creating duplicate outbox work.
    let suffix = attention_id.strip_prefix("attn-").unwrap_or(attention_id);
    format!("evt-{suffix}")
}

fn materialize_attention(
    db: &Path,
    room_id: &str,
    envelope: &Value,
    recipients: &[Recipient],
    sequence: u64,
) -> Result<(), CoordError> {
    let conn = open_db(db, true)?;
    let room_id_i = room_id.to_owned();
    let msg_id = envelope
        .get("msg_id")
        .and_then(Value::as_str)
        .ok_or(CoordError::Data)?;
    let sent_at = envelope
        .get("sent_at")
        .and_then(Value::as_i64)
        .ok_or(CoordError::Data)?;
    conn.execute("BEGIN IMMEDIATE", []).map_err(|_| CoordError::Unavailable)?;
    let result = (|| {
        for recipient in recipients {
            conn.execute(
                "INSERT OR IGNORE INTO coord_attention_feeds
                 (recipient_agent_id, last_sequence) VALUES (?1, 0)",
                params![recipient.agent_id],
            )
            .map_err(|_| CoordError::Data)?;
            let feed_sequence = conn
                .query_row(
                    "SELECT last_sequence + 1 FROM coord_attention_feeds
                     WHERE recipient_agent_id = ?1",
                    params![recipient.agent_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| CoordError::Data)?;
            conn.execute(
                "UPDATE coord_attention_feeds SET last_sequence = ?1
                 WHERE recipient_agent_id = ?2",
                params![feed_sequence, recipient.agent_id],
            )
            .map_err(|_| CoordError::Data)?;
            conn.execute(
                "INSERT INTO coord_attention_edges
                 (recipient_agent_id, feed_sequence, attention_id, room_id, kind,
                  object_id, revision_or_sequence, membership_granted_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'message', ?5, ?6, ?7, ?8)",
                params![
                    recipient.agent_id,
                    feed_sequence,
                    recipient.attention_id,
                    room_id_i,
                    msg_id,
                    i64::try_from(sequence).map_err(|_| CoordError::Data)?,
                    recipient.membership_granted_at,
                    sent_at,
                ],
            )
            .map_err(|_| CoordError::Data)?;
            let payload = json!({
                "attention_id": recipient.attention_id,
                "recipient_agent_id": recipient.agent_id,
                "feed_sequence": feed_sequence,
            });
            conn.execute(
                "INSERT OR IGNORE INTO coord_outbox
                 (event_id, destination, event_type, payload_json, created_at)
                 VALUES (?1, 'attention-nats', 'coord.attention_hint', ?2, ?3)",
                params![
                    attention_event_id(&recipient.attention_id),
                    serde_json::to_string(&payload).map_err(|_| CoordError::Data)?,
                    now_ms(),
                ],
            )
            .map_err(|_| CoordError::Data)?;
        }
        Ok::<_, CoordError>(())
    })();
    match result {
        Ok(()) => {
            conn.execute("COMMIT", []).map_err(|_| CoordError::Unavailable)?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(error)
        }
    }
}

#[derive(Clone)]
struct Recipient {
    attention_id: String,
    agent_id: String,
    membership_granted_at: i64,
}

fn read_access(db: &Path, room_name: &str, principal: &str) -> Result<RoomAccess, CoordError> {
    let conn = open_db(db, false)?;
    let room = conn
        .query_row(
            "SELECT room_id, name FROM rooms WHERE name = ?1",
            params![room_name],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| CoordError::Data)?
        .ok_or(CoordError::NotFound)?;
    let room_id = room.0;
    let room_name = room.1;
    let mut membership_statement = conn
        .prepare(
            "SELECT principal_kind, principal_id, permissions, granted_at FROM memberships
             WHERE room_id = ?1 AND revoked_at IS NULL ORDER BY granted_at DESC",
        )
        .map_err(|_| CoordError::Data)?;
    let mut memberships = membership_statement
        .query(params![&room_id])
        .map_err(|_| CoordError::Data)?;
    let mut members = Vec::new();
    while let Some(row) = memberships.next().map_err(|_| CoordError::Data)? {
        let permissions = row
            .get::<_, String>(2)
            .map_err(|_| CoordError::Data)?
            .split(',')
            .filter(|permission| !permission.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        members.push(Membership {
            principal_kind: row.get(0).map_err(|_| CoordError::Data)?,
            principal_id: row.get(1).map_err(|_| CoordError::Data)?,
            granted_at: row.get(3).map_err(|_| CoordError::Data)?,
            permissions,
        });
    }
    let member = members
        .iter()
        .find(|member| member.principal_kind == "agent" && member.principal_id == principal)
        .ok_or(CoordError::NotFound)?;
    let instance_id = conn
        .query_row("SELECT id FROM instance LIMIT 1", [], |row| row.get(0))
        .optional()
        .map_err(|_| CoordError::Data)?
        .ok_or(CoordError::Unavailable)?;
    let brief = conn
        .query_row(
            "SELECT revision, markdown, content_hash, updated_at
             FROM coord_briefs WHERE room_id = ?1",
            params![&room_id],
            |row| {
                Ok(json!({
                    "room_id": room_id,
                    "object_id": format!("brief-{}", room_id.trim_start_matches("rm-")),
                    "revision": row.get::<_, i64>(0)?,
                    "markdown": row.get::<_, String>(1)?,
                    "content_hash": row.get::<_, String>(2)?,
                    "updated_at": row.get::<_, i64>(3)?,
                }))
            },
        )
        .optional()
        .map_err(|_| CoordError::Data)?
        .unwrap_or_else(|| {
            json!({
                "room_id": room_id,
                "object_id": format!("brief-{}", room_id.trim_start_matches("rm-")),
                "revision": 0,
                "markdown": Value::Null,
                "content_hash": Value::Null,
                "updated_at": Value::Null,
            })
        });
    Ok(RoomAccess {
        room_id,
        room_name,
        permissions: member.permissions.clone(),
        members,
        instance_id,
        brief,
    })
}

fn room_stream(room_id: &str) -> String {
    format!("ROOM_{room_id}")
}

fn room_subject(room_id: &str) -> String {
    format!("rooms.{room_id}")
}

fn route_parts(request: Request<'_>) -> Option<(String, &'static str)> {
    let path = super::route(request);
    let mut parts = path.split('/');
    if parts.next() != Some("")
        || parts.next() != Some("api")
        || parts.next() != Some("coord")
        || parts.next() != Some("rooms")
    {
        return None;
    }
    let room = parts.next()?;
    let op = match parts.next()? {
        "join" => "join",
        "send" => "send",
        "messages" => "messages",
        "wait" => "wait",
        "members" => "members",
        "brief" => "brief",
        "state" => "state",
        "declarations" => "declarations",
        _ => return None,
    };
    if parts.next().is_some() || room.is_empty() {
        return None;
    }
    let room = percent_encoding::percent_decode_str(room).decode_utf8().ok()?;
    Some((room.into_owned(), op))
}

fn attention_wait_route(request: Request<'_>) -> bool {
    super::route(request) == "/api/coord/attention/wait"
}

fn attention_object_route(request: Request<'_>) -> Option<String> {
    let mut parts = super::route(request).split('/');
    if parts.next() != Some("")
        || parts.next() != Some("api")
        || parts.next() != Some("coord")
        || parts.next() != Some("attention")
    {
        return None;
    }
    let attention_id = parts.next()?;
    if parts.next()? != "object" || parts.next().is_some() {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(attention_id)
        .decode_utf8()
        .ok()?
        .into_owned();
    decoded.starts_with("attn-").then_some(decoded)
}

pub(super) fn is_route(request: Request<'_>) -> bool {
    super::route(request).starts_with("/api/coord/")
}

pub(super) async fn respond(request: Request<'_>, context: Option<CoordContext<'_>>) -> Outcome<'static> {
    respond_payload(request, context, None).await
}

pub(super) async fn respond_with_body<B>(
    request: Request<'_>,
    context: Option<CoordContext<'_>>,
    body: RequestBody<'_, B>,
) -> Result<Outcome<'static>, B::Error>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let payload = if route_parts(request).is_some_and(|(_, op)| op == "send") {
        match read_capped_content(body).await? {
            CappedContent::TooLarge => {
                return Ok(response(
                    413,
                    json!({
                        "error":"request body too large",
                        "max_bytes":MAX_COORD_REQUEST_BYTES,
                    }),
                ));
            }
            CappedContent::Decoded(content) => {
                let content = match content {
                    Ok(content) => content,
                    Err(error) => return Ok(super::declarations::content_error(error)),
                };
                Some(content)
            }
        }
    } else if route_parts(request).is_some_and(|(_, op)| op == "declarations") {
        match read_capped_content(body).await? {
            CappedContent::TooLarge => {
                return Ok(response(
                    413,
                    json!({
                        "error":"request body too large",
                        "max_bytes":MAX_COORD_REQUEST_BYTES,
                    }),
                ));
            }
            CappedContent::Decoded(content) => {
                let content = match content {
                    Ok(content) => content,
                    Err(error) => return Ok(super::declarations::content_error(error)),
                };
                Some(content)
            }
        };
    } else {
        None
    };
    Ok(respond_payload(
        request,
        context,
        payload.as_deref().map(|value| value.as_slice()),
    )
    .await)
}

enum CappedContent {
    TooLarge,
    Decoded(Result<zeroize::Zeroizing<Vec<u8>>, crate::http_content::ContentError>),
}

async fn read_capped_content<B>(mut body: RequestBody<'_, B>) -> Result<CappedContent, B::Error>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let mut too_large = body
        .content_length
        .is_some_and(|length| length > MAX_COORD_REQUEST_BYTES as u64);
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    while let Some(frame) = body.body.frame().await {
        let frame = frame?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if too_large {
            continue;
        }
        if raw.len().saturating_add(data.len()) > MAX_COORD_REQUEST_BYTES {
            too_large = true;
            continue;
        }
        raw.extend_from_slice(&data);
    }
    if too_large {
        return Ok(CappedContent::TooLarge);
    }
    Ok(CappedContent::Decoded(crate::http_content::decode(
        &raw,
        body.content_encoding,
    )))
}

async fn respond_payload(
    request: Request<'_>,
    context: Option<CoordContext<'_>>,
    payload: Option<&[u8]>,
) -> Outcome<'static> {
    let Some(context) = context else {
        return response(503, json!({"error":"coordination substrate unavailable"}));
    };
    let Some(agent_name) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let principal = context.client.principal_id(agent_name).await;
    if attention_wait_route(request) {
        if request.method != "GET" {
            return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
        }
        let since = query_u64(request.path_and_query, "since", 0).unwrap_or(0);
        let limit = query_u64(request.path_and_query, "limit", 1)
            .map_or(1, |value| value.clamp(1, MAX_PAGE as u64) as usize);
        let timeout = query_f64(request.path_and_query, "timeout", 30.0)
            .unwrap_or(30.0)
            .clamp(0.1, 300.0);
        return match context
            .client
            .wait_attention(&principal, since, limit, timeout)
            .await
        {
            Ok(page) => response(
                200,
                json!({
                    "edges": page.edges.into_iter().map(|edge| json!({
                        "attention_id": edge.attention_id,
                        "room_id": edge.room_id,
                        "kind": edge.kind,
                        "object_id": edge.object_id,
                        "revision_or_sequence": edge.revision_or_sequence,
                    })).collect::<Vec<_>>(),
                    "next_cursor": page.next_cursor,
                }),
            ),
            Err(error) => error_response(error),
        };
    }
    if let Some(attention_id) = attention_object_route(request) {
        if request.method != "GET" {
            return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
        }
        return match context.client.attention_object(&principal, &attention_id).await {
            Ok(value) => response(200, value),
            Err(error) => error_response(error),
        };
    }
    let Some((room_name, operation)) = route_parts(request) else {
        return response(404, json!({"error":"coord resource not found or not accessible"}));
    };
    let access = match context.client.access(&room_name, &principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    match operation {
        "join" => {
            if request.method != "POST" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["POST"]}));
            }
            let state = if access.permissions.iter().any(|p| p == "receive") {
                match context.client.room_state(&room_name, &principal, &access).await {
                    Ok(state) => state,
                    Err(error) => return error_response(error),
                }
            } else {
                Value::Null
            };
            response(
                200,
                json!({
                    "room_id": access.room_id,
                    "room_name": access.room_name,
                    "permissions": access.permissions,
                    "history_visibility":"retained",
                    "brief": if access.permissions.iter().any(|p| p == "receive") { access.brief.clone() } else { Value::Null },
                    "state": state,
                }),
            )
        }
        "send" => {
            if request.method != "POST" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["POST"]}));
            }
            if !access.permissions.iter().any(|permission| permission == "send") {
                return response(403, json!({"error":"permission 'send' denied"}));
            }
            let Some(payload) = payload else {
                return response(400, json!({"error":"body required (non-empty string)"}));
            };
            send(context.client, request, &room_name, access, &principal, agent_name, payload).await
        }
        "messages" => {
            if request.method != "GET" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
            }
            if !access.permissions.iter().any(|permission| permission == "receive") {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            let since = query_u64(request.path_and_query, "since", 0).unwrap_or(0);
            let limit = query_u64(request.path_and_query, "limit", 50)
                .map_or(50, |value| value.clamp(1, MAX_PAGE as u64) as usize);
            read_messages(context.client, &room_name, access, &principal, since, limit).await
        }
        "wait" => {
            if request.method != "GET" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
            }
            if !access.permissions.iter().any(|permission| permission == "receive") {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            let since = query_u64(request.path_and_query, "since", 0).unwrap_or(0);
            let limit = query_u64(request.path_and_query, "limit", 1)
                .map_or(1, |value| value.clamp(1, MAX_PAGE as u64) as usize);
            let timeout = query_f64(request.path_and_query, "timeout", 30.0)
                .unwrap_or(30.0)
                .clamp(0.1, 300.0);
            let include_self = query_bool(request.path_and_query, "include_self", false)
                .unwrap_or(false);
            wait_room(
                context.client,
                &room_name,
                &principal,
                since,
                limit,
                timeout,
                !include_self,
            )
            .await
        }
        "brief" => {
            if request.method != "GET" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
            }
            if !access.permissions.iter().any(|permission| permission == "receive") {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            response(200, access.brief.clone())
        }
        "state" => {
            if request.method != "GET" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
            }
            if !access.permissions.iter().any(|permission| permission == "receive") {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            match context.client.room_state(&room_name, &principal, &access).await {
                Ok(state) => response(200, state),
                Err(error) => error_response(error),
            }
        }
        "declarations" => {
            if request.method != "POST" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["POST"]}));
            }
            let Some(payload) = payload else {
                return response(400, json!({"error":"body required"}));
            };
            let Ok(document) = serde_json::from_slice::<Value>(payload) else {
                return response(400, json!({"error":"invalid JSON body"}));
            };
            let Some(object) = document.as_object() else {
                return response(400, json!({"error":"JSON body must be an object"}));
            };
            let Some(capabilities) = object.get("capabilities").and_then(Value::as_array) else {
                return response(400, json!({"error":"capabilities must be a list"}));
            };
            let capabilities = capabilities
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if capabilities.len() != object["capabilities"].as_array().map_or(0, Vec::len) {
                return response(400, json!({"error":"capabilities must contain strings"}));
            }
            let Some(ttl) = object.get("ttl_seconds").and_then(Value::as_i64) else {
                return response(400, json!({"error":"ttl_seconds must be an integer"}));
            };
            match context.client.write_declarations(&room_name, &principal, &capabilities, ttl).await {
                Ok(result) => response(200, result),
                Err(error) => error_response(error),
            }
        }
        "members" => {
            if request.method != "GET" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["GET"]}));
            }
            // `access` has already enforced active membership, so the roster
            // cannot become a room-existence oracle. Deduplicate generations
            // exactly as the retained coord API does.
            let mut unique = Vec::new();
            for member in access.members {
                if !unique.iter().any(|existing: &Membership| {
                    existing.principal_kind == member.principal_kind
                        && existing.principal_id == member.principal_id
                }) {
                    unique.push(member);
                }
            }
            let agent_ids = unique
                .iter()
                .filter(|member| member.principal_kind == "agent")
                .map(|member| member.principal_id.clone())
                .collect::<Vec<_>>();
            let display_names = context.client.display_names(&agent_ids).await;
            let origin_instance_id = access.instance_id.clone();
            let members = unique
                .into_iter()
                .map(|member| {
                    if member.principal_kind == "agent" {
                        let agent_name = display_names.get(&member.principal_id);
                        json!({
                            "principal_kind":"agent",
                            "agent_id":member.principal_id,
                            "agent_name":agent_name,
                            "origin_instance_id":origin_instance_id,
                        })
                    } else {
                        json!({"principal_kind":member.principal_kind})
                    }
                })
                .collect::<Vec<_>>();
            response(200, json!({"members":members}))
        }
        _ => unreachable!(),
    }
}

fn error_response(error: CoordError) -> Outcome<'static> {
    match error {
        CoordError::NotFound => response(404, json!({"error":"room not found or not accessible"})),
        CoordError::Forbidden => response(403, json!({"error":"coordination permission denied"})),
        CoordError::Unavailable => response(503, json!({"error":"coordination substrate unavailable"})),
        CoordError::Data => response(500, json!({"error":"coordination state unavailable"})),
        CoordError::PublishUnknown => response(
            503,
            json!({
                "error":"message acceptance outcome unknown; inspect retained room history before retrying",
                "send_outcome":"unknown",
            }),
        ),
    }
}

fn publish_unknown_response(request: Request<'_>) -> Outcome<'static> {
    let mut outcome = response(
        503,
        json!({
            "error":"message acceptance outcome unknown; inspect retained room history before retrying",
            "send_outcome":"unknown",
        }),
    );
    outcome.audit = Some(AuditIntent {
        kind: AuditKind::CoordPublishOutcomeUnknown,
        event: "coord.publish_outcome_unknown",
        severity: "high",
        addon: "agent-api",
        summary: "Coordination publish acceptance outcome is unknown".to_owned(),
        agent: agent(request.identity).map(str::to_owned),
        request_id: Some(request.request_id.to_owned()),
        host: Some(super::API_HOST.to_owned()),
        details: json!({
            "method": request.method,
            "path": super::path_no_query(request),
            "send_outcome": "unknown",
        }),
        approval: None,
    });
    outcome
}

fn query_u64(path_and_query: &str, wanted: &str, default: u64) -> Option<u64> {
    let Some(query) = path_and_query.split_once('?').map(|(_, query)| query) else {
        return Some(default);
    };
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Ok(key) = percent_encoding::percent_decode_str(key).decode_utf8() else {
            continue;
        };
        if key == wanted {
            return percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .ok()
                .and_then(|value| value.parse().ok());
        }
    }
    Some(default)
}

fn query_f64(path_and_query: &str, wanted: &str, default: f64) -> Option<f64> {
    let Some(query) = path_and_query.split_once('?').map(|(_, query)| query) else {
        return Some(default);
    };
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Ok(key) = percent_encoding::percent_decode_str(key).decode_utf8() else {
            continue;
        };
        if key == wanted {
            return percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .ok()
                .and_then(|value| value.parse().ok());
        }
    }
    Some(default)
}

fn query_bool(path_and_query: &str, wanted: &str, default: bool) -> Option<bool> {
    let Some(query) = path_and_query.split_once('?').map(|(_, query)| query) else {
        return Some(default);
    };
    for part in query.split('&') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Ok(key) = percent_encoding::percent_decode_str(key).decode_utf8() else {
            continue;
        };
        if key == wanted {
            return percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .ok()
                .and_then(|value| match value.as_ref() {
                    "1" | "true" | "yes" => Some(true),
                    "0" | "false" | "no" => Some(false),
                    _ => None,
                });
        }
    }
    Some(default)
}

async fn send(
    client: &CoordClient,
    request: Request<'_>,
    room_name: &str,
    access: RoomAccess,
    principal: &str,
    agent_name: &str,
    payload: &[u8],
) -> Outcome<'static> {
    let Ok(document) = serde_json::from_slice::<Value>(payload) else {
        return response(400, json!({"error":"invalid JSON body"}));
    };
    let Some(object) = document.as_object() else {
        return response(400, json!({"error":"JSON body must be an object"}));
    };
    let Some(body) = object.get("body").and_then(Value::as_str) else {
        return response(400, json!({"error":"body required (non-empty string)"}));
    };
    if body.is_empty() {
        return response(400, json!({"error":"body required (non-empty string)"}));
    }
    if body.len() > MAX_BODY_BYTES {
        return response(413, json!({"error":"body too large", "max_bytes":MAX_BODY_BYTES}));
    }
    if body.as_bytes().len() > MAX_BODY_BYTES {
        return response(413, json!({"error":"body too large", "max_bytes":MAX_BODY_BYTES}));
    }
    let content_type = match object.get("declared_content_type") {
        None => "text/markdown",
        Some(value) => match value.as_str() {
            Some(value) => value,
            None => return response(400, json!({"error":"content_type must be a string"})),
        },
    };
    if !matches!(content_type, "text/plain" | "text/markdown") {
        return response(400, json!({"error":"content_type is not allowed"}));
    }
    enum Notification {
        None,
        Room,
        Agents(Vec<String>),
    }
    let notification = match object.get("notify") {
        None => Notification::Room,
        Some(Value::String(value)) if value == "none" => Notification::None,
        Some(Value::String(value)) if value == "room" => Notification::Room,
        Some(Value::Array(values)) => {
            let mut agents = Vec::with_capacity(values.len());
            for value in values {
                let Some(name) = value.as_str() else {
                    return response(400, json!({"error":"notify list must contain agent names"}));
                };
                agents.push(name.to_owned());
            }
            Notification::Agents(agents)
        }
        Some(_) => return response(400, json!({"error":"notify must be 'none', 'room', or a list of agent names"})),
    };
    let connection = match client.client().await {
        Ok(connection) => connection,
        Err(error) => return error_response(error),
    };
    let jetstream = jetstream::new(connection.clone());
    let _stream = match jetstream.get_stream(room_stream(&access.room_id)).await {
        Ok(stream) => stream,
        Err(_) => return error_response(CoordError::Unavailable),
    };

    // The SQLite grant is authoritative at the last provider boundary.  The
    // initial RoomAccess can be stale while stream lookup is in flight, so
    // take a fresh snapshot before constructing the manifest and publishing.
    let access = match client.access(room_name, principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    if !access.permissions.iter().any(|permission| permission == "send") {
        return response(403, json!({"error":"permission 'send' denied"}));
    }
    let agent_ids = access
        .members
        .iter()
        .filter(|member| {
            member.principal_kind == "agent"
                && member.permissions.iter().any(|permission| permission == "receive")
        })
        .map(|member| member.principal_id.clone())
        .collect::<Vec<_>>();
    let display_names = client.display_names(&agent_ids).await;
    let msg_id = format!("msg-{}", uuid::Uuid::new_v4().simple());
    let sent_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let recipient_agents = match notification {
        Notification::None => Vec::new(),
        Notification::Room => access
            .members
            .iter()
            .filter(|member| {
                member.principal_kind == "agent"
                    && member.principal_id != principal
                    && member.permissions.iter().any(|permission| permission == "receive")
            })
            .map(|member| member.principal_id.clone())
            .collect::<Vec<_>>(),
        Notification::Agents(names) => {
            let mut ids = Vec::with_capacity(names.len());
            for name in names {
                let Some(agent_id) = display_names
                    .iter()
                    .find_map(|(agent_id, display_name)| (display_name == &name).then_some(agent_id.clone()))
                else {
                    return response(400, json!({"error":"notify target is not an active agent in this room"}));
                };
                let Some(member) = access.members.iter().find(|member| {
                    member.principal_kind == "agent" && member.principal_id == agent_id
                }) else {
                    return response(400, json!({"error":"notify target is not an active agent in this room"}));
                };
                if !member.permissions.iter().any(|permission| permission == "receive") {
                    return response(403, json!({"error":"notify target cannot receive in this room"}));
                }
                if !ids.contains(&agent_id) {
                    ids.push(agent_id);
                }
            }
            ids
        }
    };
    let recipients = recipient_agents
        .iter()
        .filter_map(|agent_id| {
            let member = access.members.iter().find(|member| {
                member.principal_kind == "agent" && &member.principal_id == agent_id
            })?;
            Some(Recipient {
                attention_id: format!("attn-{}", uuid::Uuid::new_v4().simple()),
                agent_id: agent_id.clone(),
                membership_granted_at: member.granted_at,
            })
        })
        .collect::<Vec<_>>();
    let recipients_json = recipients
        .iter()
        .map(|recipient| json!({
            "attention_id": recipient.attention_id,
            "agent_id": recipient.agent_id,
            "membership_granted_at": recipient.membership_granted_at,
        }))
        .collect::<Vec<_>>();
    let mode = match object.get("notify") {
        Some(Value::String(value)) if value == "none" => "none",
        Some(Value::Array(_)) => "agents",
        _ => "room",
    };
    let envelope = json!({
        "msg_id":msg_id,
        "sent_at":sent_at,
        "sender_kind":"agent",
        "sender_agent_id":principal,
        "sender_agent_name":agent_name,
        "origin_instance_id":access.instance_id,
        "content_type":content_type,
        "body":body,
    });
    let manifest = json!({"version":1,"msg_id":envelope["msg_id"],"mode":mode,"recipients":recipients_json});
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", envelope["msg_id"].as_str().unwrap_or_default());
    headers.insert("SafeYolo-Coord-Attention", manifest.to_string());
    let ack = match jetstream
        .publish_with_headers(room_subject(&access.room_id), headers, Bytes::from(envelope.to_string()))
        .await
    {
        Ok(ack) => ack,
        Err(_) => return publish_unknown_response(request),
    };
    let sequence = match ack.await {
        Ok(ack) => ack.sequence,
        Err(_) => return publish_unknown_response(request),
    };
    let db = client.data_dir.clone();
    let room_id = access.room_id.clone();
    let projection_envelope = envelope.clone();
    let projection_recipients = recipients.clone();
    let projected = tokio::task::spawn_blocking(move || {
        materialize_attention(
            &db,
            &room_id,
            &projection_envelope,
            &projection_recipients,
            sequence,
        )
    })
    .await
    .ok()
    .and_then(Result::ok)
    .is_some();
    let mut attention_ready = projected;
    if projected {
        for recipient in &recipients {
            let hint = json!({"attention_id":recipient.attention_id}).to_string();
            if connection
                .publish(
                    format!("coord.attention.{}", recipient.agent_id),
                    Bytes::from(hint),
                )
                .await
                .is_err()
            {
                attention_ready = false;
                break;
            }
        }
    }
    response(
        200,
        json!({
            "envelope": envelope,
            "sequence": sequence,
            "attention_status":if attention_ready {"ready"} else {"pending"},
            "attention_intent":{"mode":mode},
        }),
    )
}

struct ConsumerCleanup {
    stream: Option<jetstream::stream::Stream>,
    name: String,
}

impl ConsumerCleanup {
    async fn finish(&mut self) -> Result<(), CoordError> {
        let Some(stream) = self.stream.take() else {
            return Ok(());
        };
        match stream.delete_consumer(&self.name).await {
            Ok(_) => Ok(()),
            Err(error) if consumer_delete_not_found(&error) => Ok(()),
            Err(_) => Err(CoordError::Unavailable),
        }
    }
}

impl Drop for ConsumerCleanup {
    fn drop(&mut self) {
        let Some(stream) = self.stream.take() else {
            return;
        };
        let name = self.name.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // Cancellation can drop this guard while a fetch or acknowledgement
        // is pending.  Best-effort deletion prevents abandoned ephemeral
        // consumers; an ordinary completion uses finish() and surfaces any
        // non-NotFound deletion error to the caller.
        handle.spawn(async move {
            let _ = stream.delete_consumer(&name).await;
        });
    }
}

fn consumer_delete_not_found(error: &jetstream::stream::ConsumerError) -> bool {
    matches!(
        error.kind(),
        jetstream::stream::ConsumerErrorKind::JetStream(error)
            if error.error_code() == jetstream::ErrorCode::CONSUMER_NOT_FOUND
    )
}

async fn read_messages(
    client: &CoordClient,
    room_name: &str,
    access: RoomAccess,
    principal: &str,
    since: u64,
    limit: usize,
) -> Outcome<'static> {
    read_messages_with_timeout(
        client,
        room_name,
        access,
        principal,
        since,
        limit,
        Duration::from_millis(500),
        false,
    )
    .await
}

async fn wait_room(
    client: &CoordClient,
    room_name: &str,
    principal: &str,
    since: u64,
    limit: usize,
    timeout_seconds: f64,
    exclude_self: bool,
) -> Outcome<'static> {
    let access = match client.access(room_name, principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    if !access.permissions.iter().any(|permission| permission == "receive") {
        return response(403, json!({"error":"permission 'receive' denied"}));
    }
    read_messages_with_timeout(
        client,
        room_name,
        access,
        principal,
        since,
        limit,
        Duration::from_secs_f64(timeout_seconds.clamp(0.1, 300.0)),
        exclude_self,
    )
    .await
}

async fn read_messages_with_timeout(
    client: &CoordClient,
    room_name: &str,
    access: RoomAccess,
    principal: &str,
    since: u64,
    limit: usize,
    fetch_timeout: Duration,
    exclude_self: bool,
) -> Outcome<'static> {
    let connection = match client.client().await {
        Ok(connection) => connection,
        Err(error) => return error_response(error),
    };
    let jetstream = jetstream::new(connection);
    let mut stream = match jetstream.get_stream(room_stream(&access.room_id)).await {
        Ok(stream) => stream,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let state = match stream.info().await {
        Ok(info) => (info.state.first_sequence, info.state.last_sequence),
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let config = pull::Config {
        deliver_policy: DeliverPolicy::ByStartSequence {
            start_sequence: since.saturating_add(1),
        },
        ack_policy: AckPolicy::Explicit,
        ..Default::default()
    };
    let mut consumer = match stream.create_consumer(config).await {
        Ok(consumer) => consumer,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let cleanup_name = consumer.cached_info().name.clone();
    let mut cleanup = ConsumerCleanup {
        stream: Some(stream),
        name: cleanup_name,
    };
    let result = async {
        let mut messages = consumer
            .fetch()
            .max_messages(limit.saturating_add(1))
            .max_bytes(ROOM_MAX_BYTES)
            .expires(fetch_timeout)
            .messages()
            .await
            .map_err(|_| CoordError::Unavailable)?;
        let mut page = Vec::new();
        while let Some(message) = messages.next().await {
            let message = message.map_err(|_| CoordError::Unavailable)?;
            // JetStream delivers the authoritative stream sequence in the
            // message metadata.  Nats-Sequence is an implementation detail
            // of some server paths and is absent from valid pull messages.
            let sequence = message
                .info()
                .map_err(|_| CoordError::Data)?
                .stream_sequence;
            let mut value: Value = serde_json::from_slice(&message.payload)
                .map_err(|_| CoordError::Data)?;
            let object = value.as_object_mut().ok_or(CoordError::Data)?;
            let is_self = object
                .get("sender_agent_id")
                .and_then(Value::as_str)
                == Some(principal);
            if !(exclude_self && is_self) {
                object.insert("sequence".to_owned(), Value::from(sequence));
                page.push(value);
            }
            message.ack().await.map_err(|_| CoordError::Unavailable)?;
            if page.len() >= limit.saturating_add(1) {
                break;
            }
        }
        // A revoke can land during the NATS fetch/ack window.  Never return
        // messages after that grant has ceased to authorize receipt.
        let current = client.access(room_name, principal).await?;
        if !current.permissions.iter().any(|permission| permission == "receive") {
            return Err(CoordError::Forbidden);
        }
        Ok::<_, CoordError>((page, state))
    }
    .await;
    let cleanup_result = cleanup.finish().await;
    if let Err(error) = cleanup_result {
        return error_response(error);
    }
    let (mut page, (first_sequence, last_sequence)) = match result {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let has_more = page.len() > limit;
    page.truncate(limit);
    let next_cursor = page
        .last()
        .and_then(|message| message.get("sequence"))
        .and_then(Value::as_u64)
        .unwrap_or(since);
    response(
        200,
        json!({
            "messages": page,
            "next_cursor":next_cursor,
            "has_more":has_more || last_sequence > next_cursor,
            "history_truncated": first_sequence > 0 && since < first_sequence.saturating_sub(1),
            "oldest_available_at":Value::Null,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coord_routes_are_parsed_without_accepting_extra_segments() {
        let request = Request {
            method: "GET",
            path_and_query: "/api/coord/rooms/shared/messages?since=2&limit=3",
            authorization: None,
            identity: crate::network_guard::Identity::Resolved("alice"),
            client_ip: None,
            request_id: "req-00000000000000000000000000000000",
        };
        assert_eq!(route_parts(request), Some(("shared".to_owned(), "messages")));
        let invalid = Request { path_and_query: "/api/coord/rooms/shared/messages/extra", ..request };
        assert_eq!(route_parts(invalid), None);
    }
}
