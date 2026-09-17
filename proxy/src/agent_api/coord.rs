//! Native bridge to the retained coordination substrate.
//!
//! Room membership and instance identity remain authoritative in the
//! versioned SQLite store owned by the CLI.  Message history remains in the
//! per-room JetStream stream.  This module is deliberately a client of those
//! stores: it does not maintain a second room database or proxy through the
//! Python Agent API.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},

    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_nats::jetstream::{
    self,
    consumer::{AckPolicy, DeliverPolicy, pull},
};
use bytes::Bytes;
use futures_util::StreamExt;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};

use super::{Outcome, Request, RequestBody, agent, response};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_PAGE: usize = 200;
const ROOM_MAX_BYTES: usize = 4 * 1024 * 1024;
const NATS_USER: &str = "safeyolo";

#[derive(Debug)]
enum CoordError {
    NotFound,
    Unavailable,
    Data,
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

fn read_access(db: &Path, room_name: &str, principal: &str) -> Result<RoomAccess, CoordError> {
    if !db.is_file() {
        return Err(CoordError::Unavailable);
    }
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| CoordError::Unavailable)?;
    conn.busy_timeout(Duration::from_millis(500))
        .map_err(|_| CoordError::Unavailable)?;
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
        .find(|member| member.principal_id == principal)
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
        "members" => "members",
        _ => return None,
    };
    if parts.next().is_some() || room.is_empty() {
        return None;
    }
    let room = percent_encoding::percent_decode_str(room).decode_utf8().ok()?;
    Some((room.into_owned(), op))
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
        let content = super::declarations::read_content(body).await?;
        let content = match content {
            Ok(content) => content,
            Err(error) => return Ok(super::declarations::content_error(error)),
        };
        Some(content)
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

async fn respond_payload(
    request: Request<'_>,
    context: Option<CoordContext<'_>>,
    payload: Option<&[u8]>,
) -> Outcome<'static> {
    let Some((room_name, operation)) = route_parts(request) else {
        return response(404, json!({"error":"coord resource not found or not accessible"}));
    };
    let Some(context) = context else {
        return response(503, json!({"error":"coordination substrate unavailable"}));
    };
    let Some(agent_name) = agent(request.identity) else {
        return response(403, json!({"error":"Could not identify agent"}));
    };
    let principal = context.client.principal_id(agent_name).await;
    let access = match context.client.access(&room_name, &principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    match operation {
        "join" => {
            if request.method != "POST" {
                return response(405, json!({"error":"Method Not Allowed", "allowed":["POST"]}));
            }
            response(
                200,
                json!({
                    "room_id": access.room_id,
                    "room_name": access.room_name,
                    "permissions": access.permissions,
                    "history_visibility":"retained",
                    "brief": if access.permissions.iter().any(|p| p == "receive") { access.brief } else { Value::Null },
                    "state": Value::Null,
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
            send(context.client, access, &principal, agent_name, payload).await
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
            read_messages(context.client, access, since, limit).await
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
        CoordError::Unavailable => response(503, json!({"error":"coordination substrate unavailable"})),
        CoordError::Data => response(500, json!({"error":"coordination state unavailable"})),
    }
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

async fn send(
    client: &CoordClient,
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
    let content_type = object
        .get("declared_content_type")
        .and_then(Value::as_str)
        .unwrap_or("text/markdown");
    if !matches!(content_type, "text/plain" | "text/markdown") {
        return response(400, json!({"error":"content_type is not allowed"}));
    }
    if let Some(notify) = object.get("notify")
        && !matches!(notify.as_str(), Some("none" | "room"))
    {
        return response(400, json!({"error":"notify must be 'none' or 'room'"}));
    }
    let msg_id = format!("msg-{}", uuid::Uuid::new_v4().simple());
    let sent_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let notify_room = object
        .get("notify")
        .and_then(Value::as_str)
        .is_none_or(|notify| notify == "room");
    let recipients = if notify_room {
        access
            .members
            .iter()
            .filter(|member| {
                member.principal_id != principal
                    && member.permissions.iter().any(|p| p == "receive")
                    && member.principal_id.starts_with("ag-")
            })
            .map(|member| {
                json!({
                    "attention_id": format!("attn-{}", uuid::Uuid::new_v4().simple()),
                    "agent_id": member.principal_id,
                    "membership_granted_at": member.granted_at,
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mode = if notify_room { "room" } else { "none" };
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
    let manifest = json!({"version":1,"msg_id":envelope["msg_id"],"mode":mode,"recipients":recipients});
    let connection = match client.client().await {
        Ok(connection) => connection,
        Err(error) => return error_response(error),
    };
    let jetstream = jetstream::new(connection);
    let _stream = match jetstream.get_stream(room_stream(&access.room_id)).await {
        Ok(stream) => stream,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", envelope["msg_id"].as_str().unwrap_or_default());
    headers.insert("SafeYolo-Coord-Attention", manifest.to_string());
    let ack = match jetstream
        .publish_with_headers(room_subject(&access.room_id), headers, Bytes::from(envelope.to_string()))
        .await
    {
        Ok(ack) => ack,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let sequence = match ack.await {
        Ok(ack) => ack.sequence,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    response(
        200,
        json!({
            "envelope": envelope,
            "sequence": sequence,
            "attention_status":"pending",
            "attention_intent":{"mode":if mode == "room" {"room"} else {"none"}},
        }),
    )
}

async fn read_messages(
    client: &CoordClient,
    access: RoomAccess,
    since: u64,
    limit: usize,
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
        Ok(info) => info.state.clone(),
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
    let consumer_name = match consumer.info().await {
        Ok(info) => info.name.clone(),
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let mut messages = match consumer
        .fetch()
        .max_messages(limit.saturating_add(1))
        .max_bytes(ROOM_MAX_BYTES)
        .expires(Duration::from_millis(500))
        .messages()
        .await
    {
        Ok(messages) => messages,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let mut page = Vec::new();
    while let Some(message) = messages.next().await {
        let message = match message {
            Ok(message) => message,
            Err(_) => return error_response(CoordError::Unavailable),
        };
        let sequence = message
            .headers
            .as_ref()
            .and_then(|headers| headers.get_last(async_nats::header::NATS_SEQUENCE))
            .and_then(|value| value.as_str().parse::<u64>().ok())
            .ok_or(CoordError::Data);
        let sequence = match sequence {
            Ok(sequence) => sequence,
            Err(error) => return error_response(error),
        };
        let Ok(mut value) = serde_json::from_slice::<Value>(&message.payload) else {
            return error_response(CoordError::Data);
        };
        let Some(object) = value.as_object_mut() else {
            return error_response(CoordError::Data);
        };
        object.insert("sequence".to_owned(), Value::from(sequence));
        page.push(value);
        if let Err(_) = message.ack().await {
            return error_response(CoordError::Unavailable);
        }
        if page.len() >= limit.saturating_add(1) {
            break;
        }
    }
    let _ = stream.delete_consumer(&consumer_name).await;
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
            "has_more":has_more || state.last_sequence > next_cursor,
            "history_truncated": state.first_sequence > 0 && since < state.first_sequence.saturating_sub(1),
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
