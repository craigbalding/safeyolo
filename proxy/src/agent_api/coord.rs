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
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_nats::jetstream::{
    self,
    consumer::{AckPolicy, DeliverPolicy, pull},
};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use ring::digest::{Context, SHA256};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AuditIntent, AuditKind, Outcome, Request, RequestBody, agent, response};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_COORD_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_DECLARATION_REQUEST_BYTES: usize = 32 * 1024;
const MAX_PAGE: usize = 200;
const ROOM_MAX_BYTES: usize = 4 * 1024 * 1024;
const NATS_USER: &str = "safeyolo";
const CURRENT_SCHEMA_VERSION: i64 = 5;
const MAX_DECLARATIONS_PER_AGENT: usize = 32;
const MAX_DECLARATION_TTL_SECONDS: i64 = 3600;
const PROJECTION_PAGE: u64 = 200;
const RECOVERY_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
enum CoordError {
    NotFound,
    Forbidden,
    Invalid,
    Unavailable,
    Data,
    PublishUnknown,
    Cancelled,
}

#[derive(Clone, Copy)]
enum ProjectionOutcome {
    Projected,
    Lost,
}

/// Process-owned coordination state. Runtime reloads replace only the
/// policy-facing facade, retaining this NATS connection, namespace, and
/// cleanup owner across accepted Runtime publications.
struct CoordCleanup {
    pending: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl CoordCleanup {
    fn new() -> Self {
        Self {
            pending: StdMutex::new(Vec::new()),
        }
    }

    fn enqueue(
        &self,
        handle: &tokio::runtime::Handle,
        stream: jetstream::stream::Stream,
        name: String,
    ) {
        let task = handle.spawn(async move {
            let _ = stream.delete_consumer(&name).await;
        });
        if let Ok(mut pending) = self.pending.lock() {
            pending.push(task);
        } else {
            task.abort();
        }
    }

    async fn drain(&self) {
        loop {
            let pending = match self.pending.lock() {
                Ok(mut pending) => std::mem::take(&mut *pending),
                Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
            };
            if pending.is_empty() {
                return;
            }
            for task in pending {
                let _ = task.await;
            }
        }
    }
}

pub(crate) struct CoordOwner {
    data_dir: PathBuf,
    nats: tokio::sync::Mutex<Option<async_nats::Client>>,
    cleanup: Arc<CoordCleanup>,
}

impl CoordOwner {
    fn new() -> Self {
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
            nats: tokio::sync::Mutex::new(None),
            cleanup: Arc::new(CoordCleanup::new()),
        }
    }
}

/// Runtime-scoped policy facade over process-owned coordination state.
/// Rejected reload candidates are dropped with this facade and leave the
/// previously active policy path untouched.
pub struct CoordClient {
    owner: Arc<CoordOwner>,
    policy_file: Option<PathBuf>,
}

impl CoordClient {
    pub(crate) fn new(policy_file: Option<PathBuf>) -> Self {
        Self::with_owner(Arc::new(CoordOwner::new()), policy_file)
    }

    pub(crate) fn with_owner(owner: Arc<CoordOwner>, policy_file: Option<PathBuf>) -> Self {
        Self { owner, policy_file }
    }

    pub(crate) fn owner(&self) -> Arc<CoordOwner> {
        self.owner.clone()
    }

    pub(crate) async fn shutdown(&self) {
        self.owner.cleanup.drain().await;
    }

    async fn client(&self) -> Result<async_nats::Client, CoordError> {
        let mut current = self.owner.nats.lock().await;
        if let Some(client) = current.as_ref()
            && matches!(
                client.connection_state(),
                async_nats::connection::State::Connected
            )
        {
            return Ok(client.clone());
        }
        let url = self.nats_url();
        let password = std::fs::read(self.owner.data_dir.join("nats/creds"))
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
        let endpoint = self.owner.data_dir.join("nats/test-endpoints.json");
        if let Ok(bytes) = std::fs::read(endpoint)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && let Some(port) = value.get("client_port").and_then(Value::as_u64)
            && port <= u16::MAX as u64
        {
            return format!("nats://127.0.0.1:{port}");
        }
        "nats://127.0.0.1:4222".to_owned()
    }

    async fn principal_id(&self, listener_name: &str) -> Result<String, CoordError> {
        let listener_name = listener_name.to_owned();
        let policy_file = self.policy_file.clone();
        tokio::task::spawn_blocking(move || {
            let Some(path) = policy_file else {
                return Err(CoordError::Unavailable);
            };
            let source = std::fs::read_to_string(path).map_err(|_| CoordError::Unavailable)?;
            let document = source
                .parse::<toml_edit::DocumentMut>()
                .map_err(|_| CoordError::Unavailable)?;
            let agents = document
                .get("agents")
                .and_then(toml_edit::Item::as_table_like)
                .ok_or(CoordError::Unavailable)?;
            let agent = agents
                .get(listener_name.as_str())
                .and_then(toml_edit::Item::as_table_like)
                .and_then(|agent| agent.get("agent_id"))
                .and_then(toml_edit::Item::as_str)
                .ok_or(CoordError::Unavailable)?;
            if !valid_agent_id(agent)
                || agents
                    .iter()
                    .filter_map(|(_, item)| {
                        item.as_table_like()?
                            .get("agent_id")
                            .and_then(toml_edit::Item::as_str)
                    })
                    .filter(|candidate| *candidate == agent)
                    .count()
                    != 1
            {
                // A durable ID with more than one configured display name is
                // ambiguous. Do not let a listener name silently alias it.
                return Err(CoordError::Unavailable);
            }
            Ok(agent.to_owned())
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }

    async fn access(&self, room: &str, principal: &str) -> Result<RoomAccess, CoordError> {
        let db = self.owner.data_dir.join("v0.db");
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
            let mut names = HashMap::new();
            let mut duplicate_ids = HashSet::new();
            for (name, item) in agents.iter() {
                let Some(id) = item
                    .as_table_like()
                    .and_then(|item| item.get("agent_id"))
                    .and_then(toml_edit::Item::as_str)
                    .filter(|id| valid_agent_id(id))
                else {
                    continue;
                };
                if principal_ids.iter().any(|principal_id| principal_id == id)
                    && names.insert(id.to_owned(), name.to_owned()).is_some()
                {
                    duplicate_ids.insert(id.to_owned());
                }
            }
            for id in duplicate_ids {
                names.remove(&id);
            }
            names
        })
        .await
        .unwrap_or_default()
    }

    async fn resolve_agent_names(
        &self,
        requested_names: &[String],
    ) -> Result<HashMap<String, String>, CoordError> {
        let requested_names = requested_names.to_vec();
        let policy_file = self.policy_file.clone();
        tokio::task::spawn_blocking(move || {
            let Some(path) = policy_file else {
                return Err(CoordError::Unavailable);
            };
            let source = std::fs::read_to_string(path).map_err(|_| CoordError::Unavailable)?;
            let document = source
                .parse::<toml_edit::DocumentMut>()
                .map_err(|_| CoordError::Unavailable)?;
            let agents = document
                .get("agents")
                .and_then(toml_edit::Item::as_table_like)
                .ok_or(CoordError::Unavailable)?;
            let mut by_name = HashMap::new();
            let mut names_by_id: HashMap<String, String> = HashMap::new();
            let mut duplicate_ids = HashSet::new();
            for (name, item) in agents.iter() {
                let Some(id) = item
                    .as_table_like()
                    .and_then(|item| item.get("agent_id"))
                    .and_then(toml_edit::Item::as_str)
                    .filter(|id| valid_agent_id(id))
                else {
                    continue;
                };
                by_name.insert(name.to_owned(), id.to_owned());
                if names_by_id.insert(id.to_owned(), name.to_owned()).is_some() {
                    duplicate_ids.insert(id.to_owned());
                }
            }
            let mut resolved = HashMap::new();
            for name in requested_names {
                let id = by_name.get(&name).ok_or(CoordError::Invalid)?;
                if duplicate_ids.contains(id) {
                    return Err(CoordError::Invalid);
                }
                resolved.insert(name, id.clone());
            }
            Ok(resolved)
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }

    async fn room_state(
        &self,
        room_name: &str,
        principal: &str,
        _access: &RoomAccess,
    ) -> Result<Value, CoordError> {
        let db = self.owner.data_dir.join("v0.db");
        let room = room_name.to_owned();
        let principal = principal.to_owned();
        let principal_for_read = principal.clone();
        let data =
            tokio::task::spawn_blocking(move || read_state_data(&db, &room, &principal_for_read))
                .await
                .map_err(|_| CoordError::Unavailable)??;
        // The bounded SQLite read above is a provider boundary.  Re-read the
        // current grant before exposing the assembled state so a revoke or a
        // newer membership generation cannot race the response.
        let current_access = self.access(room_name, &principal).await?;
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
        let db = self.owner.data_dir.join("v0.db");
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
        let db = self.owner.data_dir.join("v0.db");
        let principal = principal.to_owned();
        tokio::task::spawn_blocking(move || read_attention_feed(&db, &principal, since, limit))
            .await
            .map_err(|_| CoordError::Unavailable)?
    }

    async fn verify_attention_access(
        &self,
        principal: &str,
        edge: &AttentionEdge,
    ) -> Result<(), CoordError> {
        let db = self.owner.data_dir.join("v0.db");
        let principal = principal.to_owned();
        let attention_id = edge.attention_id.clone();
        let expected = edge.clone();
        tokio::task::spawn_blocking(move || {
            verify_attention_edge(&db, &principal, &attention_id, &expected)
        })
        .await
        .map_err(|_| CoordError::Unavailable)?
    }

    async fn wait_attention(
        &self,
        principal: &str,
        since: u64,
        limit: usize,
        timeout_seconds: f64,
        mut cancellation: tokio::sync::watch::Receiver<bool>,
    ) -> Result<FeedPage, CoordError> {
        if *cancellation.borrow() {
            return Err(CoordError::Cancelled);
        }
        let page = self.attention_feed(principal, since, limit).await?;
        if !page.edges.is_empty() || page.next_cursor != since {
            return Ok(page);
        }
        // A definite JetStream acknowledgement can precede a process crash
        // before the SQLite attention projection. Recover accepted manifests
        // from retained messages before entering the long poll, and close
        // every provider failure with one more authoritative ledger read.
        if let Err(error) = self.recover_attention(principal).await {
            let ledger = self.attention_feed(principal, since, limit).await;
            return match ledger {
                Ok(page) if !page.edges.is_empty() || page.next_cursor != since => Ok(page),
                _ => Err(error),
            };
        }
        let page = self.attention_feed(principal, since, limit).await?;
        if !page.edges.is_empty() || page.next_cursor != since {
            return Ok(page);
        }
        let connection = match self.client().await {
            Ok(connection) => connection,
            Err(error) => {
                // Reconnect failure is not authoritative: another projector
                // may have committed the edge after the previous ledger read.
                // Close this provider path with one final SQLite ledger read.
                let ledger = self.attention_feed(principal, since, limit).await;
                return match ledger {
                    Ok(page) if !page.edges.is_empty() || page.next_cursor != since => Ok(page),
                    _ => Err(error),
                };
            }
        };
        let subject = format!("coord.attention.{principal}");
        let mut subscription = match connection.subscribe(subject).await {
            Ok(subscription) => subscription,
            Err(_) => {
                let ledger = self.attention_feed(principal, since, limit).await;
                return match ledger {
                    Ok(page) if !page.edges.is_empty() || page.next_cursor != since => Ok(page),
                    _ => Err(CoordError::Unavailable),
                };
            }
        };
        if connection.flush().await.is_err() {
            let _ = subscription.unsubscribe().await;
            let ledger = self.attention_feed(principal, since, limit).await;
            return match ledger {
                Ok(page) if !page.edges.is_empty() || page.next_cursor != since => Ok(page),
                _ => Err(CoordError::Unavailable),
            };
        }
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs_f64(timeout_seconds.max(0.0));
        let mut next_recovery = tokio::time::Instant::now();
        loop {
            if *cancellation.borrow() {
                let _ = subscription.unsubscribe().await;
                return Err(CoordError::Cancelled);
            }
            let page = self.attention_feed(principal, since, limit).await?;
            if !page.edges.is_empty() || page.next_cursor != since {
                let _ = subscription.unsubscribe().await;
                return Ok(page);
            }
            // A publisher can have a confirmed JetStream publish while its
            // SQLite projection is still missing, so no attention hint is
            // guaranteed. Re-scan the retained stream at each recovery
            // interval for the entire long-poll deadline.
            let now = tokio::time::Instant::now();
            if now >= next_recovery {
                if let Err(error) = self.recover_attention(principal).await {
                    let ledger = self.attention_feed(principal, since, limit).await;
                    return match ledger {
                        Ok(page) if !page.edges.is_empty() || page.next_cursor != since => {
                            let _ = subscription.unsubscribe().await;
                            Ok(page)
                        }
                        _ => {
                            let _ = subscription.unsubscribe().await;
                            Err(error)
                        }
                    };
                }
                next_recovery = now + RECOVERY_INTERVAL;
                let recovered = self.attention_feed(principal, since, limit).await?;
                if !recovered.edges.is_empty() || recovered.next_cursor != since {
                    let _ = subscription.unsubscribe().await;
                    return Ok(recovered);
                }
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
            let until_recovery = next_recovery
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            let wait_for = remaining.min(until_recovery.max(Duration::from_millis(1)));
            tokio::select! {
                biased;
                cancelled = wait_cancelled(&mut cancellation) => {
                    if cancelled {
                        let _ = subscription.unsubscribe().await;
                        return Err(CoordError::Cancelled);
                    }
                }
                received = tokio::time::timeout(wait_for, subscription.next()) => {
                    if matches!(received, Ok(None)) {
                        let ledger = self.attention_feed(principal, since, limit).await;
                        let _ = subscription.unsubscribe().await;
                        return match ledger {
                            Ok(page) if !page.edges.is_empty() || page.next_cursor != since => Ok(page),
                            _ => Err(CoordError::Unavailable),
                        };
                    }
                }
            }
        }
    }

    async fn recover_attention(&self, principal: &str) -> Result<(), CoordError> {
        let db = self.owner.data_dir.join("v0.db");
        let principal_owned = principal.to_owned();
        let rooms =
            tokio::task::spawn_blocking(move || receive_room_generations(&db, &principal_owned))
                .await
                .map_err(|_| CoordError::Unavailable)??;
        if rooms.is_empty() {
            return Ok(());
        }
        let connection = self.client().await?;
        let jetstream = jetstream::new(connection);
        for room_id in rooms {
            let mut stream = jetstream
                .get_stream(room_stream(&room_id))
                .await
                .map_err(|_| CoordError::Unavailable)?;
            // Recovery can be the first native operation for a room. Establish
            // the Stage-1 baseline before looking at retained messages so
            // pre-baseline history is never imported into the native feed.
            self.ensure_room_projection(&room_id, &mut stream).await?;
            let state = stream
                .info()
                .await
                .map(|info| info.state.last_sequence)
                .map_err(|_| CoordError::Unavailable)?;
            let _ = self
                .project_room_through(&room_id, &mut stream, state)
                .await?;
        }
        Ok(())
    }

    async fn ensure_room_projection(
        &self,
        room_id: &str,
        stream: &mut jetstream::stream::Stream,
    ) -> Result<(), CoordError> {
        let last_sequence = stream
            .info()
            .await
            .map(|info| info.state.last_sequence)
            .map_err(|_| CoordError::Unavailable)?;
        let db = self.owner.data_dir.join("v0.db");
        let room_id = room_id.to_owned();
        tokio::task::spawn_blocking(move || {
            ensure_projection_baseline(&db, &room_id, last_sequence)
        })
        .await
        .map_err(|_| CoordError::Unavailable)??;
        Ok(())
    }

    async fn project_room_through(
        &self,
        room_id: &str,
        stream: &mut jetstream::stream::Stream,
        through_sequence: u64,
    ) -> Result<ProjectionOutcome, CoordError> {
        let db = self.owner.data_dir.join("v0.db");
        let room_for_frontier = room_id.to_owned();
        let mut frontier =
            tokio::task::spawn_blocking(move || read_projection_frontier(&db, &room_for_frontier))
                .await
                .map_err(|_| CoordError::Unavailable)??;
        loop {
            if frontier >= through_sequence {
                let db = self.owner.data_dir.join("v0.db");
                let room_for_loss = room_id.to_owned();
                let lost = tokio::task::spawn_blocking(move || {
                    projection_sequence_was_lost(&db, &room_for_loss, through_sequence)
                })
                .await
                .map_err(|_| CoordError::Unavailable)??;
                return Ok(if lost {
                    ProjectionOutcome::Lost
                } else {
                    ProjectionOutcome::Projected
                });
            }
            let state = stream
                .info()
                .await
                .map(|info| (info.state.first_sequence, info.state.last_sequence))
                .map_err(|_| CoordError::Unavailable)?;
            let next_sequence = frontier.saturating_add(1);
            if state.0 > next_sequence {
                let db = self.owner.data_dir.join("v0.db");
                let room_for_gap = room_id.to_owned();
                let gap = tokio::task::spawn_blocking(move || {
                    advance_over_retention_gap(&db, &room_for_gap, frontier, state.0)
                })
                .await
                .map_err(|_| CoordError::Unavailable)??;
                match gap {
                    GapAdvance::Advanced {
                        frontier: advanced,
                        lost_last,
                    } => {
                        frontier = advanced;
                        if through_sequence <= lost_last {
                            return Ok(ProjectionOutcome::Lost);
                        }
                    }
                    GapAdvance::Conflict(current) => frontier = current,
                }
                continue;
            }
            if next_sequence > state.1 {
                return Err(CoordError::Unavailable);
            }
            let end_sequence =
                through_sequence.min(frontier.saturating_add(PROJECTION_PAGE).min(state.1));
            let mut messages = Vec::new();
            for sequence in next_sequence..=end_sequence {
                let raw = stream
                    .get_raw_message(sequence)
                    .await
                    .map_err(|_| CoordError::Unavailable)?;
                let envelope: Value =
                    serde_json::from_slice(&raw.payload).map_err(|_| CoordError::Data)?;
                let header = raw
                    .headers
                    .get_last("SafeYolo-Coord-Attention")
                    .map(|value| value.as_str());
                let (recipients, has_attention_manifest) = match header {
                    // Existing room messages without a Stage-1 header are
                    // still valid stream entries. Advance the projection
                    // frontier across them without requiring native fields.
                    None => (Vec::new(), false),
                    Some(header) => {
                        let msg_id = envelope
                            .get("msg_id")
                            .and_then(Value::as_str)
                            .ok_or(CoordError::Data)?;
                        let recipients = parse_attention_manifest(Some(header), msg_id)?
                            .map(|manifest| manifest.recipients)
                            .ok_or(CoordError::Data)?;
                        (recipients, true)
                    }
                };
                messages.push(ProjectedMessage {
                    sequence,
                    envelope,
                    recipients,
                    has_attention_manifest,
                });
            }
            let db = self.owner.data_dir.join("v0.db");
            let room_for_projection = room_id.to_owned();
            match tokio::task::spawn_blocking(move || {
                project_attention_prefix(&db, &room_for_projection, frontier, messages)
            })
            .await
            .map_err(|_| CoordError::Unavailable)??
            {
                ProjectionCommit::Advanced(sequence) => frontier = sequence,
                ProjectionCommit::Conflict(sequence) => frontier = sequence,
            }
        }
    }

    async fn attention_object(
        &self,
        principal: &str,
        attention_id: &str,
    ) -> Result<Value, CoordError> {
        let db = self.owner.data_dir.join("v0.db");
        let principal_owned = principal.to_owned();
        let attention_owned = attention_id.to_owned();
        let edge = tokio::task::spawn_blocking(move || {
            read_attention_edge(&db, &principal_owned, &attention_owned)
        })
        .await
        .map_err(|_| CoordError::Unavailable)??;
        if edge.kind == "brief_changed" {
            let expected_object_id = format!("brief-{}", edge.room_id.trim_start_matches("rm-"));
            if edge.object_id != expected_object_id {
                return Err(CoordError::Data);
            }
            let db = self.owner.data_dir.join("v0.db");
            let edge_for_read = edge.clone();
            let object =
                tokio::task::spawn_blocking(move || read_brief_revision(&db, &edge_for_read))
                    .await
                    .map_err(|_| CoordError::Unavailable)??;
            self.verify_attention_access(principal, &edge).await?;
            return Ok(json!({"edge": edge.public_json(), "object": object}));
        }
        if edge.kind != "message" {
            return Err(CoordError::Data);
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
        let mut envelope: Value =
            serde_json::from_slice(&raw.payload).map_err(|_| CoordError::Data)?;
        let object = envelope.as_object_mut().ok_or(CoordError::Data)?;
        if object.get("msg_id").and_then(Value::as_str) != Some(edge.object_id.as_str()) {
            return Err(CoordError::Data);
        }
        let manifest = parse_attention_manifest(
            raw.headers
                .get_last("SafeYolo-Coord-Attention")
                .map(|value| value.as_str()),
            edge.object_id.as_str(),
        )?
        .ok_or(CoordError::Data)?;
        let recipient = manifest
            .recipients
            .iter()
            .find(|recipient| recipient.attention_id == edge.attention_id)
            .ok_or(CoordError::Data)?;
        if recipient.agent_id != principal
            || recipient.membership_granted_at != edge.membership_granted_at
            || matches!(manifest.mode.as_str(), "none")
        {
            return Err(CoordError::Data);
        }
        object.insert(
            "sequence".to_owned(),
            Value::from(edge.revision_or_sequence),
        );
        let object_value = Value::Object(object.clone());
        self.verify_attention_access(principal, &edge).await?;
        Ok(json!({"edge": edge.public_json(), "object": object_value}))
    }
}

pub struct CoordContext<'a> {
    pub(crate) client: &'a CoordClient,
    pub(crate) cancellation: tokio::sync::watch::Receiver<bool>,
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

struct AttentionManifest {
    mode: String,
    recipients: Vec<Recipient>,
}

fn valid_attention_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("attn-")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_agent_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("ag-") else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn parse_attention_manifest(
    header: Option<&str>,
    expected_msg_id: &str,
) -> Result<Option<AttentionManifest>, CoordError> {
    let Some(header) = header else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(header).map_err(|_| CoordError::Data)?;
    let object = value.as_object().ok_or(CoordError::Data)?;
    if object.len() != 4
        || !object.contains_key("version")
        || !object.contains_key("msg_id")
        || !object.contains_key("mode")
        || !object.contains_key("recipients")
        || object.get("version").and_then(Value::as_u64) != Some(1)
        || object.get("msg_id").and_then(Value::as_str) != Some(expected_msg_id)
    {
        return Err(CoordError::Data);
    }
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "none" | "room" | "agents" | "legacy_room"))
        .ok_or(CoordError::Data)?
        .to_owned();
    let raw_recipients = object
        .get("recipients")
        .and_then(Value::as_array)
        .ok_or(CoordError::Data)?;
    let mut recipients = Vec::with_capacity(raw_recipients.len());
    let mut attention_ids = HashSet::new();
    let mut generations = HashSet::new();
    for raw in raw_recipients {
        let raw = raw.as_object().ok_or(CoordError::Data)?;
        if raw.len() != 3
            || !raw.contains_key("attention_id")
            || !raw.contains_key("agent_id")
            || !raw.contains_key("membership_granted_at")
        {
            return Err(CoordError::Data);
        }
        let attention_id = raw
            .get("attention_id")
            .and_then(Value::as_str)
            .filter(|id| valid_attention_id(id))
            .ok_or(CoordError::Data)?
            .to_owned();
        let agent_id = raw
            .get("agent_id")
            .and_then(Value::as_str)
            .filter(|id| valid_agent_id(id))
            .ok_or(CoordError::Data)?
            .to_owned();
        let granted_at = raw
            .get("membership_granted_at")
            .and_then(Value::as_i64)
            .filter(|value| *value >= 0)
            .ok_or(CoordError::Data)?;
        if !attention_ids.insert(attention_id.clone())
            || !generations.insert((agent_id.clone(), granted_at))
        {
            return Err(CoordError::Data);
        }
        recipients.push(Recipient {
            attention_id,
            agent_id,
            membership_granted_at: granted_at,
        });
    }
    if (mode == "none" && !recipients.is_empty()) || (mode == "agents" && recipients.is_empty()) {
        return Err(CoordError::Data);
    }
    Ok(Some(AttentionManifest { mode, recipients }))
}

fn recipient_generation(access: &RoomAccess, agent_id: &str) -> Option<i64> {
    access
        .members
        .iter()
        .find(|member| {
            member.principal_kind == "agent"
                && member.principal_id == agent_id
                && member
                    .permissions
                    .iter()
                    .any(|permission| permission == "receive")
        })
        .map(|member| member.granted_at)
}

fn message_wakes_waiter(
    headers: Option<&async_nats::HeaderMap>,
    value: &Value,
    principal: &str,
    access: &RoomAccess,
    exclude_self: bool,
) -> Result<bool, CoordError> {
    let sender_is_self = value.get("sender_agent_id").and_then(Value::as_str) == Some(principal);
    let header = headers
        .and_then(|headers| headers.get_last("SafeYolo-Coord-Attention"))
        .map(|value| value.as_str());
    // Legacy room messages have no Stage-1 header. Do not require native
    // envelope fields while scanning them, but still require the current
    // receive grant before exposing a message.
    let Some(header) = header else {
        // Unannotated messages predate Stage 1 and have no published grant
        // generation to compare. They still require the waiter's current
        // receive grant, which is re-read after each pull wakes.
        return Ok(
            (!exclude_self || !sender_is_self) && recipient_generation(access, principal).is_some()
        );
    };
    let msg_id = value
        .get("msg_id")
        .and_then(Value::as_str)
        .ok_or(CoordError::Data)?;
    let manifest = parse_attention_manifest(Some(header), msg_id)?;
    let manifest = manifest.ok_or(CoordError::Data)?;
    match manifest.mode.as_str() {
        "none" => Ok(false),
        "agents" => Ok(manifest.recipients.iter().any(|recipient| {
            recipient.agent_id == principal
                && recipient_generation(access, principal) == Some(recipient.membership_granted_at)
        })),
        "legacy_room" | "room" => Ok((!exclude_self || !sender_is_self)
            && manifest.recipients.iter().any(|recipient| {
                recipient.agent_id == principal
                    && recipient_generation(access, principal)
                        == Some(recipient.membership_granted_at)
            })),
        _ => Err(CoordError::Data),
    }
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
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
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
    // Keep the allocator high-water mark, visible edges, and final cursor
    // lookup on one SQLite snapshot. A revoke or concurrent projection cannot
    // make the returned page and cursor describe different states.
    conn.execute("BEGIN", [])
        .map_err(|_| CoordError::Unavailable)?;
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
            params![
                edges
                    .last()
                    .map(|edge| edge.attention_id.as_str())
                    .unwrap_or_default()
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| CoordError::Data)?
        .max(0) as u64
    } else {
        since.max(highwater)
    };
    let page = FeedPage { edges, next_cursor };
    conn.execute("COMMIT", [])
        .map_err(|_| CoordError::Unavailable)?;
    Ok(page)
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
        "SELECT room_id, revision, markdown, content_hash, created_at
         FROM coord_brief_revisions
         WHERE room_id = ?1 AND revision = ?2",
        params![
            edge.room_id,
            i64::try_from(edge.revision_or_sequence).map_err(|_| CoordError::Data)?
        ],
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
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
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
            part.split(['.', '_', '-']).any(|term| {
                matches!(
                    term,
                    "account"
                        | "binding"
                        | "credential"
                        | "credentials"
                        | "host"
                        | "key"
                        | "password"
                        | "path"
                        | "persona"
                        | "route"
                        | "secret"
                        | "token"
                        | "url"
                )
            })
        })
}

fn write_declarations(
    db: &Path,
    room_name: &str,
    principal: &str,
    capabilities: &[String],
    ttl_seconds: i64,
) -> Result<Value, CoordError> {
    let conn = open_db(db, true)?;
    conn.execute("BEGIN IMMEDIATE", [])
        .map_err(|_| CoordError::Unavailable)?;
    let result = (|| {
        let room_id = room_id_for(&conn, room_name)?;
        let permissions = current_agent_permissions(&conn, &room_id, principal)?;
        if !permissions.iter().any(|permission| permission == "receive") {
            return Err(CoordError::Forbidden);
        }
        // Check the grant before validating caller-controlled declarations.
        // Both authorization and replacement now share this transaction, so
        // validation cannot become an unauthorized oracle or race a revoke.
        if capabilities.len() > MAX_DECLARATIONS_PER_AGENT
            || !(1..=MAX_DECLARATION_TTL_SECONDS).contains(&ttl_seconds)
            || capabilities
                .iter()
                .any(|capability| !valid_capability(capability))
        {
            return Err(CoordError::Invalid);
        }
        let mut labels = capabilities.to_vec();
        labels.sort();
        labels.dedup();
        let asserted_at = now_ms();
        let valid_until = asserted_at + ttl_seconds * 1000;
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
            conn.execute("COMMIT", [])
                .map_err(|_| CoordError::Unavailable)?;
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

struct ProjectedMessage {
    sequence: u64,
    envelope: Value,
    recipients: Vec<Recipient>,
    has_attention_manifest: bool,
}

enum ProjectionCommit {
    Advanced(u64),
    Conflict(u64),
}

enum GapAdvance {
    Advanced { frontier: u64, lost_last: u64 },
    Conflict(u64),
}

fn ensure_projection_baseline(db: &Path, room_id: &str, baseline: u64) -> Result<(), CoordError> {
    let baseline = i64::try_from(baseline).map_err(|_| CoordError::Data)?;
    let conn = open_db(db, true)?;
    conn.execute("BEGIN IMMEDIATE", [])
        .map_err(|_| CoordError::Unavailable)?;
    let result = conn
        .execute(
            "INSERT OR IGNORE INTO coord_message_attention_projection
             (room_id, last_sequence, updated_at) VALUES (?1, ?2, ?3)",
            params![room_id, baseline, now_ms()],
        )
        .map(|_| ());
    match result {
        Ok(()) => {
            conn.execute("COMMIT", [])
                .map_err(|_| CoordError::Unavailable)?;
            Ok(())
        }
        Err(_) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(CoordError::Data)
        }
    }
}

fn read_projection_frontier(db: &Path, room_id: &str) -> Result<u64, CoordError> {
    let conn = open_db(db, false)?;
    conn.query_row(
        "SELECT last_sequence FROM coord_message_attention_projection
         WHERE room_id = ?1",
        params![room_id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(|_| CoordError::Data)?
    .map(|sequence| sequence.max(0) as u64)
    .ok_or(CoordError::Data)
}

fn projection_sequence_was_lost(
    db: &Path,
    room_id: &str,
    sequence: u64,
) -> Result<bool, CoordError> {
    let conn = open_db(db, false)?;
    let mut statement = conn
        .prepare(
            "SELECT payload_json FROM coord_outbox
             WHERE event_type = 'coord.attention_projection_lost'",
        )
        .map_err(|_| CoordError::Data)?;
    let mut rows = statement.query([]).map_err(|_| CoordError::Data)?;
    while let Some(row) = rows.next().map_err(|_| CoordError::Data)? {
        let payload = row.get::<_, String>(0).map_err(|_| CoordError::Data)?;
        let payload: Value = serde_json::from_str(&payload).map_err(|_| CoordError::Data)?;
        let details = payload
            .get("details")
            .and_then(Value::as_object)
            .ok_or(CoordError::Data)?;
        let same_room = details.get("room_id").and_then(Value::as_str) == Some(room_id);
        let first = details
            .get("from_sequence")
            .and_then(Value::as_u64)
            .ok_or(CoordError::Data)?;
        let last = details
            .get("to_sequence")
            .and_then(Value::as_u64)
            .ok_or(CoordError::Data)?;
        if same_room && first <= sequence && sequence <= last {
            return Ok(true);
        }
    }
    Ok(false)
}

fn projection_loss_event_id(room_id: &str, first: u64, last: u64) -> String {
    let mut context = Context::new(&SHA256);
    context
        .update(format!("coord.attention_projection_lost\0{room_id}\0{first}\0{last}").as_bytes());
    let digest = context.finish();
    let suffix = digest
        .as_ref()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("evt-{suffix}")
}

fn advance_over_retention_gap(
    db: &Path,
    room_id: &str,
    expected_frontier: u64,
    retained_floor: u64,
) -> Result<GapAdvance, CoordError> {
    if retained_floor <= expected_frontier.saturating_add(1) {
        return Ok(GapAdvance::Conflict(expected_frontier));
    }
    let lost_first = expected_frontier.saturating_add(1);
    let lost_last = retained_floor.saturating_sub(1);
    let expected_i64 = i64::try_from(expected_frontier).map_err(|_| CoordError::Data)?;
    let lost_last_i64 = i64::try_from(lost_last).map_err(|_| CoordError::Data)?;
    let conn = open_db(db, true)?;
    conn.execute("BEGIN IMMEDIATE", [])
        .map_err(|_| CoordError::Unavailable)?;
    let result = (|| {
        let current = conn
            .query_row(
                "SELECT last_sequence
                 FROM coord_message_attention_projection WHERE room_id = ?1",
                params![room_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| CoordError::Data)?;
        if current != expected_i64 {
            return Ok(ProjectionCommit::Conflict(current.max(0) as u64));
        }
        let event_id = projection_loss_event_id(room_id, lost_first, lost_last);
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CoordError::Data)?;
        let payload = json!({
            "schema_version": 1,
            "event_id": event_id.clone(),
            "ts": timestamp,
            "event": "coord.attention_projection_lost",
            "kind": "coord",
            "severity": "medium",
            "summary": "Coord attention projection lost to retention",
            "addon": "coord",
            "details": {
                "room_id": room_id,
                "from_sequence": lost_first,
                "to_sequence": lost_last,
            },
        });
        conn.execute(
            "INSERT OR IGNORE INTO coord_outbox
             (event_id, destination, event_type, payload_json, created_at)
             VALUES (?1, 'audit-jsonl', 'coord.attention_projection_lost', ?2, ?3)",
            params![
                event_id,
                serde_json::to_string(&payload).map_err(|_| CoordError::Data)?,
                now_ms(),
            ],
        )
        .map_err(|_| CoordError::Data)?;
        let changed = conn
            .execute(
                "UPDATE coord_message_attention_projection
                 SET last_sequence = ?1, updated_at = ?2
                 WHERE room_id = ?3 AND last_sequence = ?4",
                params![lost_last_i64, now_ms(), room_id, expected_i64],
            )
            .map_err(|_| CoordError::Data)?;
        if changed != 1 {
            return Err(CoordError::Data);
        }
        Ok(ProjectionCommit::Advanced(lost_last))
    })();
    match result {
        Ok(ProjectionCommit::Advanced(frontier)) => {
            conn.execute("COMMIT", [])
                .map_err(|_| CoordError::Unavailable)?;
            Ok(GapAdvance::Advanced {
                frontier,
                lost_last,
            })
        }
        Ok(ProjectionCommit::Conflict(frontier)) => {
            let _ = conn.execute("ROLLBACK", []);
            Ok(GapAdvance::Conflict(frontier))
        }
        Err(error) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(error)
        }
    }
}

fn project_attention_prefix(
    db: &Path,
    room_id: &str,
    expected_frontier: u64,
    messages: Vec<ProjectedMessage>,
) -> Result<ProjectionCommit, CoordError> {
    let Some(last_message) = messages.last() else {
        return Ok(ProjectionCommit::Advanced(expected_frontier));
    };
    let expected_i64 = i64::try_from(expected_frontier).map_err(|_| CoordError::Data)?;
    let last_sequence = last_message.sequence;
    let last_sequence_i64 = i64::try_from(last_sequence).map_err(|_| CoordError::Data)?;
    let conn = open_db(db, true)?;
    conn.execute("BEGIN IMMEDIATE", [])
        .map_err(|_| CoordError::Unavailable)?;
    let result = (|| {
        let current = conn
            .query_row(
                "SELECT last_sequence
                 FROM coord_message_attention_projection WHERE room_id = ?1",
                params![room_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| CoordError::Data)?;
        if current != expected_i64 {
            return Ok(ProjectionCommit::Conflict(current.max(0) as u64));
        }
        let mut expected = expected_frontier.saturating_add(1);
        for message in &messages {
            if message.sequence != expected {
                return Err(CoordError::Data);
            }
            let sequence_i64 = i64::try_from(message.sequence).map_err(|_| CoordError::Data)?;
            let msg_id = message.envelope.get("msg_id").and_then(Value::as_str);
            if message.has_attention_manifest && msg_id.is_none() {
                return Err(CoordError::Data);
            }
            let sent_at = message.envelope.get("sent_at").and_then(Value::as_i64);
            for recipient in &message.recipients {
                let msg_id = msg_id.ok_or(CoordError::Data)?;
                let sent_at = sent_at.ok_or(CoordError::Data)?;
                let existing = conn
                    .query_row(
                        "SELECT attention_id, room_id, revision_or_sequence,
                                membership_granted_at
                         FROM coord_attention_edges
                         WHERE recipient_agent_id = ?1 AND kind = 'message'
                           AND object_id = ?2 AND membership_granted_at = ?3",
                        params![recipient.agent_id, msg_id, recipient.membership_granted_at],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|_| CoordError::Data)?;
                if let Some((
                    existing_attention_id,
                    existing_room_id,
                    existing_sequence,
                    existing_generation,
                )) = existing
                {
                    if existing_attention_id != recipient.attention_id
                        || existing_room_id != room_id
                        || existing_sequence != sequence_i64
                        || existing_generation != recipient.membership_granted_at
                    {
                        return Err(CoordError::Data);
                    }
                    continue;
                }
                let attention_conflict = conn
                    .query_row(
                        "SELECT recipient_agent_id, room_id, object_id,
                                revision_or_sequence, membership_granted_at
                         FROM coord_attention_edges WHERE attention_id = ?1",
                        params![recipient.attention_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, i64>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|_| CoordError::Data)?;
                if let Some((
                    existing_recipient,
                    existing_room,
                    existing_object,
                    existing_sequence,
                    existing_generation,
                )) = attention_conflict
                {
                    if existing_recipient != recipient.agent_id
                        || existing_room != room_id
                        || existing_object != msg_id
                        || existing_sequence != sequence_i64
                        || existing_generation != recipient.membership_granted_at
                    {
                        return Err(CoordError::Data);
                    }
                    continue;
                }
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
                        room_id,
                        msg_id,
                        sequence_i64,
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
            expected = expected.saturating_add(1);
        }
        let changed = conn
            .execute(
                "UPDATE coord_message_attention_projection
                 SET last_sequence = ?1, updated_at = ?2
                 WHERE room_id = ?3 AND last_sequence = ?4",
                params![last_sequence_i64, now_ms(), room_id, expected_i64],
            )
            .map_err(|_| CoordError::Data)?;
        if changed != 1 {
            return Err(CoordError::Data);
        }
        Ok(ProjectionCommit::Advanced(last_sequence))
    })();
    match result {
        Ok(ProjectionCommit::Advanced(sequence)) => {
            conn.execute("COMMIT", [])
                .map_err(|_| CoordError::Unavailable)?;
            Ok(ProjectionCommit::Advanced(sequence))
        }
        Ok(ProjectionCommit::Conflict(sequence)) => {
            let _ = conn.execute("ROLLBACK", []);
            Ok(ProjectionCommit::Conflict(sequence))
        }
        Err(error) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(error)
        }
    }
}

fn receive_room_generations(db: &Path, principal: &str) -> Result<Vec<String>, CoordError> {
    let conn = open_db(db, false)?;
    let mut statement = conn
        .prepare(
            "SELECT room_id FROM memberships AS m
             WHERE m.principal_kind = 'agent' AND m.principal_id = ?1
               AND m.revoked_at IS NULL
               AND instr(',' || m.permissions || ',', ',receive,') > 0
               AND NOT EXISTS (
                 SELECT 1 FROM memberships AS newer
                  WHERE newer.room_id = m.room_id
                    AND newer.principal_kind = 'agent'
                    AND newer.principal_id = m.principal_id
                    AND newer.revoked_at IS NULL
                    AND newer.granted_at > m.granted_at
               )
             ORDER BY room_id",
        )
        .map_err(|_| CoordError::Data)?;
    statement
        .query_map(params![principal], |row| row.get(0))
        .map_err(|_| CoordError::Data)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoordError::Data)
}

#[derive(Clone)]
struct Recipient {
    attention_id: String,
    agent_id: String,
    membership_granted_at: i64,
}

struct WaitCandidate {
    value: Value,
    headers: Option<async_nats::HeaderMap>,
}

fn filter_wait_candidates(
    candidates: Vec<WaitCandidate>,
    principal: &str,
    access: &RoomAccess,
    exclude_self: bool,
) -> Result<Vec<WaitCandidate>, CoordError> {
    let mut filtered = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if message_wakes_waiter(
            candidate.headers.as_ref(),
            &candidate.value,
            principal,
            access,
            exclude_self,
        )? {
            filtered.push(candidate);
        }
    }
    Ok(filtered)
}

async fn wait_cancelled(receiver: &mut tokio::sync::watch::Receiver<bool>) -> bool {
    if *receiver.borrow() {
        return true;
    }
    receiver.changed().await.is_err() || *receiver.borrow()
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
             WHERE room_id = ?1 AND revoked_at IS NULL
               AND NOT EXISTS (
                 SELECT 1 FROM memberships AS newer
                  WHERE newer.room_id = memberships.room_id
                    AND newer.principal_kind = memberships.principal_kind
                    AND newer.principal_id = memberships.principal_id
                    AND newer.revoked_at IS NULL
                    AND newer.granted_at > memberships.granted_at
               )
             ORDER BY granted_at DESC",
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
    let room = percent_encoding::percent_decode_str(room)
        .decode_utf8()
        .ok()?;
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
    valid_attention_id(&decoded).then_some(decoded)
}

pub(super) fn is_route(request: Request<'_>) -> bool {
    super::route(request).starts_with("/api/coord/")
}

pub(super) async fn respond(
    request: Request<'_>,
    context: Option<CoordContext<'_>>,
) -> Outcome<'static> {
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
        match read_capped_content(body, MAX_COORD_REQUEST_BYTES).await? {
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
        match read_capped_content(body, MAX_DECLARATION_REQUEST_BYTES).await? {
            CappedContent::TooLarge => {
                return Ok(response(
                    413,
                    json!({
                        "error":"request body too large",
                        "max_bytes":MAX_DECLARATION_REQUEST_BYTES,
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

async fn read_capped_content<B>(
    body: RequestBody<'_, B>,
    max_bytes: usize,
) -> Result<CappedContent, B::Error>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let mut too_large = body
        .content_length
        .is_some_and(|length| length > max_bytes as u64);
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    while let Some(frame) = body.body.frame().await {
        let frame = frame?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if too_large {
            continue;
        }
        if raw.len().saturating_add(data.len()) > max_bytes {
            too_large = true;
            continue;
        }
        raw.extend_from_slice(&data);
    }
    if too_large {
        return Ok(CappedContent::TooLarge);
    }
    let decoded = crate::http_content::decode_prefix_with_size(
        &raw,
        body.content_encoding,
        max_bytes.saturating_add(1),
    );
    match decoded {
        Ok(decoded) if decoded.total_bytes > max_bytes => Ok(CappedContent::TooLarge),
        Ok(decoded) => Ok(CappedContent::Decoded(Ok(decoded.content))),
        Err(error) => Ok(CappedContent::Decoded(Err(error))),
    }
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
    let principal = match context.client.principal_id(agent_name).await {
        Ok(principal) => principal,
        Err(_) => return response(403, json!({"error":"Could not identify registered agent"})),
    };
    if attention_wait_route(request) {
        if request.method != "GET" {
            return response(
                405,
                json!({"error":"Method Not Allowed", "allowed":["GET"]}),
            );
        }
        let since = match query_u64(request.path_and_query, "since", 0, 0, i64::MAX as u64) {
            Ok(value) => value,
            Err(()) => return response(400, json!({"error":"invalid since"})),
        };
        let limit = match query_u64(request.path_and_query, "limit", 1, 1, i64::MAX as u64) {
            Ok(value) => value.min(MAX_PAGE as u64) as usize,
            Err(()) => return response(400, json!({"error":"invalid limit"})),
        };
        let timeout = match query_f64(request.path_and_query, "timeout", 30.0) {
            Ok(value) => value.max(0.1).min(300.0),
            Err(()) => return response(400, json!({"error":"invalid timeout"})),
        };
        return match context
            .client
            .wait_attention(
                &principal,
                since,
                limit,
                timeout,
                context.cancellation.clone(),
            )
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
            return response(
                405,
                json!({"error":"Method Not Allowed", "allowed":["GET"]}),
            );
        }
        return match context
            .client
            .attention_object(&principal, &attention_id)
            .await
        {
            Ok(value) => response(200, value),
            Err(error) => error_response(error),
        };
    }
    let Some((room_name, operation)) = route_parts(request) else {
        return response(
            404,
            json!({"error":"coord resource not found or not accessible"}),
        );
    };
    let access = match context.client.access(&room_name, &principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    match operation {
        "join" => {
            if request.method != "POST" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["POST"]}),
                );
            }
            let state = if access.permissions.iter().any(|p| p == "receive") {
                match context
                    .client
                    .room_state(&room_name, &principal, &access)
                    .await
                {
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
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["POST"]}),
                );
            }
            if !access
                .permissions
                .iter()
                .any(|permission| permission == "send")
            {
                return response(403, json!({"error":"permission 'send' denied"}));
            }
            let Some(payload) = payload else {
                return response(400, json!({"error":"body required (non-empty string)"}));
            };
            send(
                context.client,
                request,
                &room_name,
                access,
                &principal,
                agent_name,
                payload,
            )
            .await
        }
        "messages" => {
            if request.method != "GET" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["GET"]}),
                );
            }
            if !access
                .permissions
                .iter()
                .any(|permission| permission == "receive")
            {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            let since = match query_u64(request.path_and_query, "since", 0, 0, i64::MAX as u64) {
                Ok(value) => value,
                Err(()) => return response(400, json!({"error":"invalid since"})),
            };
            let limit = match query_u64(request.path_and_query, "limit", 50, 1, i64::MAX as u64) {
                Ok(value) => value.min(MAX_PAGE as u64) as usize,
                Err(()) => return response(400, json!({"error":"invalid limit"})),
            };
            read_messages(context.client, &room_name, access, &principal, since, limit).await
        }
        "wait" => {
            if request.method != "GET" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["GET"]}),
                );
            }
            if !access
                .permissions
                .iter()
                .any(|permission| permission == "receive")
            {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            let since = match query_u64(request.path_and_query, "since", 0, 0, i64::MAX as u64) {
                Ok(value) => value,
                Err(()) => return response(400, json!({"error":"invalid since"})),
            };
            let limit = match query_u64(request.path_and_query, "limit", 1, 1, i64::MAX as u64) {
                Ok(value) => value.min(MAX_PAGE as u64) as usize,
                Err(()) => return response(400, json!({"error":"invalid limit"})),
            };
            let timeout = match query_f64(request.path_and_query, "timeout", 30.0) {
                Ok(value) => value.max(0.1).min(300.0),
                Err(()) => return response(400, json!({"error":"invalid timeout"})),
            };
            let include_self = match query_bool(request.path_and_query, "include_self", false) {
                Ok(value) => value,
                Err(()) => return response(400, json!({"error":"invalid include_self"})),
            };
            wait_room(
                context.client,
                &room_name,
                &principal,
                since,
                limit,
                timeout,
                !include_self,
                context.cancellation.clone(),
            )
            .await
        }
        "brief" => {
            if request.method != "GET" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["GET"]}),
                );
            }
            if !access
                .permissions
                .iter()
                .any(|permission| permission == "receive")
            {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            response(200, access.brief.clone())
        }
        "state" => {
            if request.method != "GET" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["GET"]}),
                );
            }
            if !access
                .permissions
                .iter()
                .any(|permission| permission == "receive")
            {
                return response(403, json!({"error":"permission 'receive' denied"}));
            }
            match context
                .client
                .room_state(&room_name, &principal, &access)
                .await
            {
                Ok(state) => response(200, state),
                Err(error) => error_response(error),
            }
        }
        "declarations" => {
            if request.method != "POST" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["POST"]}),
                );
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
            match context
                .client
                .write_declarations(&room_name, &principal, &capabilities, ttl)
                .await
            {
                Ok(result) => response(200, result),
                Err(error) => error_response(error),
            }
        }
        "members" => {
            if request.method != "GET" {
                return response(
                    405,
                    json!({"error":"Method Not Allowed", "allowed":["GET"]}),
                );
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
        CoordError::Invalid => response(400, json!({"error":"invalid coordination request"})),
        CoordError::Unavailable => {
            response(503, json!({"error":"coordination substrate unavailable"}))
        }
        CoordError::Data => response(500, json!({"error":"coordination state unavailable"})),
        CoordError::Cancelled => response(503, json!({"error":"coordination wait cancelled"})),
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

fn query_parameter(path_and_query: &str, wanted: &str) -> Result<Option<String>, ()> {
    let Some(query) = path_and_query.split_once('?').map(|(_, query)| query) else {
        return Ok(None);
    };
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_encoding::percent_decode_str(raw_key)
            .decode_utf8()
            .map_err(|_| ())?;
        if key == wanted {
            let value = percent_encoding::percent_decode_str(raw_value)
                .decode_utf8()
                .map_err(|_| ())?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn query_u64(
    path_and_query: &str,
    wanted: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ()> {
    let Some(raw) = query_parameter(path_and_query, wanted)? else {
        return Ok(default);
    };
    if raw.is_empty() {
        return Ok(default);
    }
    let value = raw.parse::<u64>().map_err(|_| ())?;
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or(())
}

fn query_f64(path_and_query: &str, wanted: &str, default: f64) -> Result<f64, ()> {
    let Some(raw) = query_parameter(path_and_query, wanted)? else {
        return Ok(default);
    };
    if raw.is_empty() {
        return Ok(default);
    }
    raw.parse::<f64>().map_err(|_| ())
}

fn query_bool(path_and_query: &str, wanted: &str, default: bool) -> Result<bool, ()> {
    let Some(raw) = query_parameter(path_and_query, wanted)? else {
        return Ok(default);
    };
    if raw.is_empty() {
        return Ok(default);
    }
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Ok(false),
    }
}

async fn send(
    client: &CoordClient,
    request: Request<'_>,
    room_name: &str,
    _access: RoomAccess,
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
        return response(
            413,
            json!({"error":"body too large", "max_bytes":MAX_BODY_BYTES}),
        );
    }
    if body.as_bytes().len() > MAX_BODY_BYTES {
        return response(
            413,
            json!({"error":"body too large", "max_bytes":MAX_BODY_BYTES}),
        );
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
        LegacyRoom,
        Agents(Vec<String>),
    }
    let notification = match object.get("notify") {
        None => Notification::LegacyRoom,
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
            if agents.is_empty() {
                Notification::None
            } else {
                Notification::Agents(agents)
            }
        }
        Some(_) => {
            return response(
                400,
                json!({"error":"notify must be 'none', 'room', or a list of agent names"}),
            );
        }
    };
    let connection = match client.client().await {
        Ok(connection) => connection,
        Err(error) => return error_response(error),
    };
    let jetstream = jetstream::new(connection.clone());

    // The SQLite grant is authoritative for the stream lookup. A second
    // snapshot below is taken after every preparation step, immediately
    // before the manifest is constructed and published.
    let access = match client.access(room_name, principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    if !access
        .permissions
        .iter()
        .any(|permission| permission == "send")
    {
        return response(403, json!({"error":"permission 'send' denied"}));
    }
    let mut stream = match jetstream.get_stream(room_stream(&access.room_id)).await {
        Ok(stream) => stream,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    // Establish the Stage-1 baseline before this process publishes its first
    // manifest. Existing retained history is then outside the native
    // projection contract, while an existing frontier remains untouched.
    if let Err(error) = client
        .ensure_room_projection(&access.room_id, &mut stream)
        .await
    {
        return error_response(error);
    }
    let resolved_names = match &notification {
        Notification::Agents(names) => match client.resolve_agent_names(names).await {
            Ok(resolved_names) => Some(resolved_names),
            Err(CoordError::Invalid | CoordError::Unavailable) => {
                return response(
                    400,
                    json!({"error":"notify target is not an active agent in this room"}),
                );
            }
            Err(error) => return error_response(error),
        },
        Notification::None | Notification::Room | Notification::LegacyRoom => None,
    };
    // Stream lookup, baseline setup, and target-name resolution all perform
    // provider I/O. Re-read the newest active membership generation after
    // those operations so a revoke/regrant cannot authorize a stale manifest.
    let final_access = match client.access(room_name, principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    if final_access.room_id != access.room_id {
        return error_response(CoordError::Unavailable);
    }
    if !final_access
        .permissions
        .iter()
        .any(|permission| permission == "send")
    {
        return response(403, json!({"error":"permission 'send' denied"}));
    }
    let msg_id = format!("msg-{}", uuid::Uuid::new_v4().simple());
    let sent_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let recipient_agents = match &notification {
        Notification::None => Vec::new(),
        Notification::Room | Notification::LegacyRoom => final_access
            .members
            .iter()
            .filter(|member| {
                member.principal_kind == "agent"
                    && member.principal_id != principal
                    && member
                        .permissions
                        .iter()
                        .any(|permission| permission == "receive")
            })
            .map(|member| member.principal_id.clone())
            .collect::<Vec<_>>(),
        Notification::Agents(names) => {
            let resolved_names = resolved_names.as_ref().expect("agent names resolved");
            let mut ids = Vec::with_capacity(names.len());
            for name in names {
                let Some(agent_id) = resolved_names.get(name) else {
                    return response(
                        400,
                        json!({"error":"notify target is not an active agent in this room"}),
                    );
                };
                let Some(member) = final_access.members.iter().find(|member| {
                    member.principal_kind == "agent" && member.principal_id == *agent_id
                }) else {
                    return response(
                        400,
                        json!({"error":"notify target is not an active agent in this room"}),
                    );
                };
                if !member
                    .permissions
                    .iter()
                    .any(|permission| permission == "receive")
                {
                    return response(
                        403,
                        json!({"error":"notify target cannot receive in this room"}),
                    );
                }
                if !ids.contains(agent_id) {
                    ids.push(agent_id.clone());
                }
            }
            ids
        }
    };
    let recipients = recipient_agents
        .iter()
        .filter_map(|agent_id| {
            let member = final_access.members.iter().find(|member| {
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
        .map(|recipient| {
            json!({
                "attention_id": recipient.attention_id,
                "agent_id": recipient.agent_id,
                "membership_granted_at": recipient.membership_granted_at,
            })
        })
        .collect::<Vec<_>>();
    let manifest_mode = match &notification {
        Notification::None => "none",
        Notification::Room => "room",
        Notification::LegacyRoom => "legacy_room",
        Notification::Agents(_) => "agents",
    };
    let public_mode = match &notification {
        Notification::None => "none",
        Notification::Room | Notification::LegacyRoom => "room",
        Notification::Agents(_) => "targeted",
    };
    let envelope = json!({
        "msg_id":msg_id,
        "sent_at":sent_at,
        "sender_kind":"agent",
        "sender_agent_id":principal,
        "sender_agent_name":agent_name,
        "origin_instance_id":final_access.instance_id,
        "content_type":content_type,
        "body":body,
    });
    let manifest = json!({
        "version":1,
        "msg_id":envelope["msg_id"],
        "mode":manifest_mode,
        "recipients":recipients_json
    });
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(
        "Nats-Msg-Id",
        envelope["msg_id"].as_str().unwrap_or_default(),
    );
    headers.insert("SafeYolo-Coord-Attention", manifest.to_string());
    let ack = match jetstream
        .publish_with_headers(
            room_subject(&access.room_id),
            headers,
            Bytes::from(envelope.to_string()),
        )
        .await
    {
        Ok(ack) => ack,
        Err(_) => return publish_unknown_response(request),
    };
    let sequence = match ack.await {
        Ok(ack) => ack.sequence,
        Err(_) => return publish_unknown_response(request),
    };
    let projection_outcome = client
        .project_room_through(&access.room_id, &mut stream, sequence)
        .await;
    let mut attention_status = match projection_outcome {
        Ok(ProjectionOutcome::Projected) => "ready",
        Ok(ProjectionOutcome::Lost) => "lost",
        Err(_) => "pending",
    };
    if attention_status == "ready" {
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
                attention_status = "pending";
                break;
            }
        }
    }
    response(
        200,
        json!({
            "envelope": envelope,
            "sequence": sequence,
            "attention_status":attention_status,
            "attention_intent":{"mode":public_mode},
        }),
    )
}

struct ConsumerCleanup {
    stream: Option<jetstream::stream::Stream>,
    name: String,
    owner: Arc<CoordCleanup>,
}

impl ConsumerCleanup {
    async fn finish(&mut self) -> Result<(), CoordError> {
        let Some(stream) = self.stream.as_ref() else {
            return Ok(());
        };
        // Keep the stream in the guard while the delete RPC is pending.  If
        // cancellation interrupts this await, Drop can still hand the same
        // cleanup operation to the runtime instead of losing the handle.
        let result = stream.delete_consumer(&self.name).await;
        match result {
            Ok(_) => {
                self.stream = None;
                Ok(())
            }
            Err(error) if consumer_delete_not_found(&error) => {
                self.stream = None;
                Ok(())
            }
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
        // is pending.  Retain the deletion join handle in the process owner;
        // Proxy::shutdown drains these tasks after listeners stop, so cleanup
        // cannot become an unobserved fire-and-forget operation.
        self.owner.enqueue(&handle, stream, name);
    }
}

fn consumer_delete_not_found(error: &jetstream::stream::ConsumerError) -> bool {
    matches!(
        error.kind(),
        jetstream::stream::ConsumerErrorKind::JetStream(error)
            if error.error_code() == jetstream::ErrorCode::CONSUMER_NOT_FOUND
    )
}

fn fetch_max_messages(wake_mode: bool, limit: usize) -> usize {
    if wake_mode {
        1
    } else {
        limit.saturating_add(1)
    }
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
        false,
        tokio::sync::watch::channel(false).1,
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
    cancellation: tokio::sync::watch::Receiver<bool>,
) -> Outcome<'static> {
    let access = match client.access(room_name, principal).await {
        Ok(access) => access,
        Err(error) => return error_response(error),
    };
    if !access
        .permissions
        .iter()
        .any(|permission| permission == "receive")
    {
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
        true,
        cancellation,
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
    wake_mode: bool,
    mut cancellation: tokio::sync::watch::Receiver<bool>,
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
    let consumer = match stream.create_consumer(config).await {
        Ok(consumer) => consumer,
        Err(_) => return error_response(CoordError::Unavailable),
    };
    let cleanup_name = consumer.cached_info().name.clone();
    let mut cleanup = ConsumerCleanup {
        stream: Some(stream),
        name: cleanup_name,
        owner: client.owner.cleanup.clone(),
    };
    let result = async {
        let deadline = tokio::time::Instant::now() + fetch_timeout;
        let mut page: Vec<WaitCandidate> = Vec::new();
        loop {
            if *cancellation.borrow() {
                return Err(CoordError::Cancelled);
            }
            // Recheck the grant before every additional provider fetch. If a
            // regrant rotated the membership generation, discard candidates
            // from the previous snapshot and keep waiting for a new match.
            if wake_mode {
                let current = match client.access(room_name, principal).await {
                    Ok(current) => current,
                    Err(CoordError::NotFound) => {
                        return Ok((Vec::new(), (since, since)));
                    }
                    Err(error) => return Err(error),
                };
                if !current
                    .permissions
                    .iter()
                    .any(|permission| permission == "receive")
                {
                    return Ok((Vec::new(), (since, since)));
                }
                page = filter_wait_candidates(page, principal, &current, exclude_self)?;
                if page.len() >= limit.saturating_add(1) {
                    break;
                }
            }
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                break;
            }
            let messages = consumer
                .fetch()
                .max_messages(fetch_max_messages(wake_mode, limit))
                .max_bytes(ROOM_MAX_BYTES)
                .expires(remaining)
                .messages();
            let mut messages = tokio::select! {
                biased;
                cancelled = wait_cancelled(&mut cancellation) => {
                    if cancelled {
                        return Err(CoordError::Cancelled);
                    }
                    continue;
                }
                result = messages => result.map_err(|_| CoordError::Unavailable)?,
            };
            // Evaluate the attention manifest against a grant snapshot taken
            // after this provider fetch, before any message is exposed.
            let evaluation_access = if wake_mode {
                match client.access(room_name, principal).await {
                    Ok(access) => Some(access),
                    Err(CoordError::NotFound) => {
                        return Ok((Vec::new(), (since, since)));
                    }
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            loop {
                let message = tokio::select! {
                    biased;
                    cancelled = wait_cancelled(&mut cancellation) => {
                        if cancelled {
                            return Err(CoordError::Cancelled);
                        }
                        continue;
                    }
                    message = messages.next() => message,
                };
                let Some(message) = message else {
                    break;
                };
                let message = message.map_err(|_| CoordError::Unavailable)?;
                // JetStream delivers the authoritative stream sequence in the
                // message metadata. Nats-Sequence is absent from valid pull
                // messages on some server paths.
                let sequence = message
                    .info()
                    .map_err(|_| CoordError::Data)?
                    .stream_sequence;
                let mut value: Value =
                    serde_json::from_slice(&message.payload).map_err(|_| CoordError::Data)?;
                let qualifies = if wake_mode {
                    message_wakes_waiter(
                        message.headers.as_ref(),
                        &value,
                        principal,
                        evaluation_access.as_ref().unwrap_or(&access),
                        exclude_self,
                    )?
                } else {
                    true
                };
                let mut return_after_ack = false;
                if qualifies {
                    let object = value.as_object_mut().ok_or(CoordError::Data)?;
                    object.insert("sequence".to_owned(), Value::from(sequence));
                    page.push(WaitCandidate {
                        value,
                        headers: message.headers.clone(),
                    });
                    // A room wait is an event-driven wake. Returning as soon
                    // as one message qualifies avoids waiting for the pull
                    // expiry when the batch contains fewer than its limit.
                    return_after_ack = wake_mode;
                }
                message.ack().await.map_err(|_| CoordError::Unavailable)?;
                if return_after_ack {
                    break;
                }
                if page.len() >= limit.saturating_add(1) {
                    break;
                }
            }
            if !wake_mode {
                break;
            }
            if !page.is_empty() {
                break;
            }
            // A self-only, non-targeted, or generation-stale batch must not
            // terminate a wait. The same consumer advances beyond every
            // acknowledged message; the next loop rechecks membership before
            // fetching again.
        }
        if !wake_mode {
            // A revoke can land during the ordinary fetch/ack window. Never
            // return messages after that grant has ceased to authorize receipt.
            let current = client.access(room_name, principal).await?;
            if !current
                .permissions
                .iter()
                .any(|permission| permission == "receive")
            {
                return Err(CoordError::Forbidden);
            }
        }
        Ok::<_, CoordError>((page, state))
    }
    .await;
    let cleanup_result = cleanup.finish().await;
    if let Err(error) = cleanup_result {
        return error_response(error);
    }
    let (page, (first_sequence, last_sequence)) = match result {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let mut page = page
        .into_iter()
        .map(|candidate| candidate.value)
        .collect::<Vec<_>>();
    let has_more = page.len() > limit;
    page.truncate(limit);
    let next_cursor = page
        .last()
        .and_then(|message| message.get("sequence"))
        .and_then(Value::as_u64)
        .unwrap_or(since);
    let mut result = json!({
        "messages": page,
        "next_cursor":next_cursor,
        "history_truncated": first_sequence > 0 && since < first_sequence.saturating_sub(1),
        "oldest_available_at":Value::Null,
    });
    if !wake_mode {
        result["has_more"] = Value::from(has_more || last_sequence > next_cursor);
    }
    response(200, result)
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
        assert_eq!(
            route_parts(request),
            Some(("shared".to_owned(), "messages"))
        );
        let invalid = Request {
            path_and_query: "/api/coord/rooms/shared/messages/extra",
            ..request
        };
        assert_eq!(route_parts(invalid), None);
    }

    #[test]
    fn attention_manifest_uses_simple_uuid_attention_ids() {
        let header = json!({
            "version": 1,
            "msg_id": "msg-1",
            "mode": "agents",
            "recipients": [{
                "attention_id": "attn-0123456789abcdef0123456789abcdef",
                "agent_id": "ag-alice",
                "membership_granted_at": 7,
            }],
        })
        .to_string();
        assert!(parse_attention_manifest(Some(&header), "msg-1").is_ok());

        let invalid = header.replace(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0",
        );
        assert!(matches!(
            parse_attention_manifest(Some(&invalid), "msg-1"),
            Err(CoordError::Data)
        ));

        let uppercase = header.replace("abcdef", "ABCDEF");
        assert!(matches!(
            parse_attention_manifest(Some(&uppercase), "msg-1"),
            Err(CoordError::Data)
        ));
        assert!(!valid_agent_id("ag-"));
        assert!(valid_agent_id("ag-Alice_1"));
        assert!(!valid_agent_id("ag-Alice!"));
    }

    #[test]
    fn explicit_room_manifest_matches_recipient_generation() {
        let value = json!({"msg_id":"msg-1", "sender_agent_id":"ag-bob"});
        let header = json!({
            "version": 1,
            "msg_id": "msg-1",
            "mode": "room",
            "recipients": [{
                "attention_id": "attn-0123456789abcdef0123456789abcdef",
                "agent_id": "ag-alice",
                "membership_granted_at": 7,
            }],
        })
        .to_string();
        let access = RoomAccess {
            room_id: "rm-shared".to_owned(),
            room_name: "shared".to_owned(),
            permissions: vec!["receive".to_owned()],
            members: vec![Membership {
                principal_kind: "agent".to_owned(),
                principal_id: "ag-alice".to_owned(),
                granted_at: 7,
                permissions: vec!["receive".to_owned()],
            }],
            instance_id: "instance".to_owned(),
            brief: Value::Null,
        };
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("SafeYolo-Coord-Attention", header);
        assert!(
            message_wakes_waiter(Some(&headers), &value, "ag-alice", &access, false,)
                .expect("valid manifest")
        );
        let mut stale = access;
        stale.members[0].granted_at = 8;
        assert!(
            !message_wakes_waiter(Some(&headers), &value, "ag-alice", &stale, false,)
                .expect("valid manifest")
        );
    }

    #[test]
    fn legacy_unannotated_wait_requires_active_grant_after_revoke() {
        let access = RoomAccess {
            room_id: "rm-shared".to_owned(),
            room_name: "shared".to_owned(),
            permissions: vec!["receive".to_owned()],
            members: vec![Membership {
                principal_kind: "agent".to_owned(),
                principal_id: "ag-alice".to_owned(),
                granted_at: 7,
                permissions: vec!["receive".to_owned()],
            }],
            instance_id: "instance".to_owned(),
            brief: Value::Null,
        };
        let legacy = json!({"body": "old client message"});
        assert!(message_wakes_waiter(None, &legacy, "ag-alice", &access, false).unwrap());

        let self_message = json!({"sender_agent_id": "ag-alice"});
        assert!(!message_wakes_waiter(None, &self_message, "ag-alice", &access, true,).unwrap());

        let annotated = json!({"msg_id": "msg-legacy", "sender_agent_id": "ag-bob"});
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(
            "SafeYolo-Coord-Attention",
            json!({
                "version": 1,
                "msg_id": "msg-legacy",
                "mode": "legacy_room",
                "recipients": [{
                    "attention_id": "attn-0123456789abcdef0123456789abcdef",
                    "agent_id": "ag-alice",
                    "membership_granted_at": 7,
                }],
            })
            .to_string(),
        );
        assert!(
            message_wakes_waiter(Some(&headers), &annotated, "ag-alice", &access, false).unwrap()
        );

        // A legacy/unannotated pull can wake after a revoke raced the fetch;
        // the post-fetch grant snapshot must suppress that delivery.
        let mut revoked = access;
        revoked.members.clear();
        assert!(!message_wakes_waiter(None, &legacy, "ag-alice", &revoked, false).unwrap());
        assert!(
            !message_wakes_waiter(Some(&headers), &annotated, "ag-alice", &revoked, false,)
                .unwrap()
        );
        assert!(
            filter_wait_candidates(
                vec![WaitCandidate {
                    value: legacy,
                    headers: None,
                }],
                "ag-alice",
                &revoked,
                false,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn stage1_header_requires_native_message_id() {
        let header = json!({
            "version": 1,
            "msg_id": "msg-1",
            "mode": "none",
            "recipients": [],
        })
        .to_string();
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("SafeYolo-Coord-Attention", header);
        let access = RoomAccess {
            room_id: "rm-shared".to_owned(),
            room_name: "shared".to_owned(),
            permissions: vec!["receive".to_owned()],
            members: Vec::new(),
            instance_id: "instance".to_owned(),
            brief: Value::Null,
        };
        assert!(matches!(
            message_wakes_waiter(
                Some(&headers),
                &json!({"body": "missing msg_id"}),
                "ag-alice",
                &access,
                false,
            ),
            Err(CoordError::Data)
        ));
    }

    #[test]
    fn brief_attention_object_reads_created_at_as_public_updated_at() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("v0.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA user_version=5;
             CREATE TABLE coord_brief_revisions(
                 room_id TEXT NOT NULL,
                 revision INTEGER NOT NULL,
                 markdown TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY(room_id, revision)
             );
             INSERT INTO coord_brief_revisions
                 (room_id, revision, markdown, content_hash, created_at)
                 VALUES ('rm-shared', 3, '# brief',
                         'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         1234);",
        )
        .unwrap();
        drop(conn);

        let edge = AttentionEdge {
            attention_id: "attn-0123456789abcdef0123456789abcdef".to_owned(),
            room_id: "rm-shared".to_owned(),
            kind: "brief_changed".to_owned(),
            object_id: "brief-shared".to_owned(),
            revision_or_sequence: 3,
            membership_granted_at: 7,
        };
        let object = read_brief_revision(&db, &edge).unwrap();
        assert_eq!(object["updated_at"], 1234);
        assert_eq!(object["revision"], 3);
        assert_eq!(object["markdown"], "# brief");
    }

    #[test]
    fn capability_grammar_matches_retained_public_validator() {
        for value in ["svc:2fa", "a:2", "2:2", "svc.reader:worker-2"] {
            assert!(valid_capability(value), "expected capability: {value}");
        }
        for value in [
            "binding:host",
            "svc:binding",
            "svc:credentials",
            "credentials:x",
            "persona:x",
            "route:x",
            "host:x",
            "svc:host",
            "svc:persona",
            "svc:route",
            "svc:bad term",
        ] {
            assert!(!valid_capability(value), "unexpected capability: {value}");
        }
    }

    #[test]
    fn room_wait_fetches_one_message_to_wake_before_pull_expiry() {
        assert_eq!(fetch_max_messages(true, 1), 1);
        assert_eq!(fetch_max_messages(true, 200), 1);
        assert_eq!(fetch_max_messages(false, 3), 4);
    }

    #[tokio::test]
    async fn wait_cancellation_observes_connection_close() {
        let (sender, mut receiver) = tokio::sync::watch::channel(false);
        sender.send(true).unwrap();
        assert!(wait_cancelled(&mut receiver).await);

        let (sender, mut receiver) = tokio::sync::watch::channel(false);
        drop(sender);
        assert!(wait_cancelled(&mut receiver).await);
    }

    #[test]
    fn query_parameters_follow_source_defaults_clamps_and_cursor_validation() {
        assert_eq!(
            query_u64("/api?since=0", "since", 0, 0, i64::MAX as u64),
            Ok(0)
        );
        assert_eq!(
            query_u64("/api?since=", "since", 0, 0, i64::MAX as u64),
            Ok(0)
        );
        assert_eq!(query_f64("/api?timeout=", "timeout", 30.0), Ok(30.0));
        assert_eq!(
            query_u64("/api?limit=", "limit", 50, 1, i64::MAX as u64),
            Ok(50)
        );
        assert_eq!(
            query_u64("/api?limit=201", "limit", 50, 1, i64::MAX as u64),
            Ok(201)
        );
        assert!(query_u64("/api?limit=0", "limit", 50, 1, MAX_PAGE as u64).is_err());
        assert!(query_u64("/api?limit=-1", "limit", 50, 1, MAX_PAGE as u64).is_err());
        assert!(query_u64("/api?limit=oops", "limit", 50, 1, MAX_PAGE as u64).is_err());
        assert!(query_u64("/api?since=-1", "since", 0, 0, i64::MAX as u64).is_err());
        assert!(
            query_u64(
                "/api?since=9223372036854775808",
                "since",
                0,
                0,
                i64::MAX as u64
            )
            .is_err()
        );
        assert_eq!(
            query_f64("/api?timeout=301", "timeout", 30.0).map(|value| value.max(0.1).min(300.0)),
            Ok(300.0)
        );
        assert_eq!(
            query_f64("/api?timeout=-1", "timeout", 30.0).map(|value| value.max(0.1).min(300.0)),
            Ok(0.1)
        );
        assert!(query_f64("/api?timeout=oops", "timeout", 30.0).is_err());
        assert_eq!(
            query_bool("/api?include_self=TrUe", "include_self", false),
            Ok(true)
        );
        assert_eq!(
            query_bool("/api?include_self=unexpected", "include_self", false),
            Ok(false)
        );
    }

    #[test]
    fn access_snapshot_keeps_only_newest_active_generation() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("v0.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA user_version=5;
             CREATE TABLE rooms(room_id TEXT PRIMARY KEY, name TEXT NOT NULL);
             CREATE TABLE memberships(
                 room_id TEXT NOT NULL,
                 principal_kind TEXT NOT NULL,
                 principal_id TEXT NOT NULL,
                 permissions TEXT NOT NULL,
                 granted_at INTEGER NOT NULL,
                 revoked_at INTEGER,
                 PRIMARY KEY(room_id, principal_kind, principal_id, granted_at)
             );
             CREATE TABLE instance(id TEXT PRIMARY KEY);
             CREATE TABLE coord_briefs(
                 room_id TEXT PRIMARY KEY,
                 revision INTEGER NOT NULL,
                 markdown TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             INSERT INTO rooms(room_id, name) VALUES ('rm-shared', 'shared');
             INSERT INTO instance(id) VALUES ('instance');
             INSERT INTO memberships
                 (room_id, principal_kind, principal_id, permissions, granted_at)
                 VALUES ('rm-shared', 'agent', 'ag-alice', 'receive', 7);
             INSERT INTO memberships
                 (room_id, principal_kind, principal_id, permissions, granted_at)
                 VALUES ('rm-shared', 'agent', 'ag-alice', 'send', 8);",
        )
        .unwrap();
        drop(conn);

        let access = read_access(&db, "shared", "ag-alice").unwrap();
        assert_eq!(access.permissions, vec!["send"]);
        assert_eq!(access.members.len(), 1);
        assert_eq!(access.members[0].granted_at, 8);
    }

    #[test]
    fn projection_advances_across_manifestless_messages() {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("v0.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA user_version=5;
             CREATE TABLE coord_message_attention_projection(
                 room_id TEXT PRIMARY KEY,
                 last_sequence INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             INSERT INTO coord_message_attention_projection
                 (room_id, last_sequence, updated_at) VALUES ('rm-shared', 0, 0);",
        )
        .unwrap();
        drop(conn);

        let result = project_attention_prefix(
            &db,
            "rm-shared",
            0,
            vec![ProjectedMessage {
                sequence: 1,
                envelope: json!({"legacy": true}),
                recipients: Vec::new(),
                has_attention_manifest: false,
            }],
        )
        .unwrap();
        assert!(matches!(result, ProjectionCommit::Advanced(1)));
        let conn = Connection::open(db).unwrap();
        let frontier: i64 = conn
            .query_row(
                "SELECT last_sequence FROM coord_message_attention_projection WHERE room_id='rm-shared'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(frontier, 1);
    }

    #[test]
    fn reload_facades_share_only_process_coord_owner() {
        let owner = Arc::new(CoordOwner::new());
        let first = CoordClient::with_owner(owner.clone(), Some(PathBuf::from("old.toml")));
        let replacement = CoordClient::with_owner(owner, Some(PathBuf::from("new.toml")));
        assert!(Arc::ptr_eq(&first.owner(), &replacement.owner()));
        assert_ne!(first.policy_file, replacement.policy_file);
    }
}
