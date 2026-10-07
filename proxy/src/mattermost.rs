//! Native host-only Mattermost projection and authenticated operator ingress.
//! Mattermost has no Coord principal, agent identity or Admin mutation route.
mod config;
mod listener;
mod render;
mod state;
#[cfg(test)]
mod tests;

use crate::{Error, agent_api::coord::OperatorCoord};
use config::{Config, Room, coord_id, hex64, mm_id};
use render::{OPERATOR_SCHEMA, PROJECTION_SCHEMA};
use rusqlite::params;
use serde_json::{Value, json};
use state::{State, now};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

pub const HELP: &str = "safeyolo [--root ROOT] coord mattermost check|run [--config FILE] [--once]\nExternal TOML defaults to ~/.safeyolo/coord-mattermost.toml. check validates identities, local grants, private state and callback bind; run is a foreground adapter. run --once does not issue buttons. Mattermost projects selected rooms and authenticates one operator; Coord stays authoritative. Unknown appends require manual reconciliation and are never replayed automatically.";

struct Api {
    base: String,
    token: Zeroizing<String>,
}
impl Api {
    async fn request(
        &self,
        method: hyper::Method,
        path: &str,
        body: Value,
    ) -> Result<Value, Error> {
        // Never display a remote response body or transport error containing a
        // request/header. The credential is neither in URLs nor diagnostics.
        crate::native_client::https_json(
            &format!("{}/api/v4{path}", self.base),
            &self.token,
            method,
            body,
        )
        .await
        .map_err(|_| {
            "Mattermost HTTP request failed; backend, authentication or response is unavailable"
                .into()
        })
    }
    async fn get(&self, path: &str) -> Result<Value, Error> {
        self.request(hyper::Method::GET, path, Value::Null).await
    }
    async fn posts(
        &self,
        channel: &str,
        since: Option<i64>,
        per_page: u16,
    ) -> Result<Vec<Value>, Error> {
        let query = since.map_or_else(
            || format!("page=0&per_page={per_page}"),
            |v| format!("since={}", v.max(1)),
        );
        let value = self
            .get(&format!("/channels/{channel}/posts?{query}"))
            .await?;
        let order = value["order"]
            .as_array()
            .ok_or("Mattermost post order is malformed")?;
        let posts = value["posts"]
            .as_object()
            .ok_or("Mattermost post page is malformed")?;
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        for id in order {
            let id = id
                .as_str()
                .filter(|v| mm_id(v))
                .ok_or("Mattermost post ID is malformed")?;
            if !seen.insert(id) {
                return Err("Mattermost post page has duplicate IDs".into());
            }
            let post = posts
                .get(id)
                .filter(|v| v.is_object() && v["id"] == id)
                .ok_or("Mattermost post correlation is malformed")?;
            result.push(post.clone());
        }
        Ok(result)
    }
}
struct Adapter {
    config: Config,
    state: Mutex<State>,
    api: Api,
    coord: Arc<OperatorCoord>,
    listener_healthy: AtomicBool,
}
impl Adapter {
    fn state<T>(&self, call: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Mattermost state is unavailable")?;
        state.validate()?;
        let value = call(&mut state)?;
        state.validate()?;
        Ok(value)
    }
    fn query(&self, sql: &str, parameters: impl rusqlite::Params) -> Result<Vec<Value>, Error> {
        self.state(|s| s.query(sql, parameters))
    }
    fn execute(&self, sql: &str, parameters: impl rusqlite::Params) -> Result<usize, Error> {
        self.state(|s| s.execute(sql, parameters))
    }
    async fn verify_operator(&self) -> Result<(), Error> {
        let user = self
            .api
            .get(&format!("/users/{}", self.config.operator))
            .await?;
        if user["id"] != self.config.operator
            || user["delete_at"].as_i64() != Some(0)
            || !user.get("is_bot").is_none_or(|v| v == false)
        {
            return Err("configured Mattermost operator is not one active human user".into());
        }
        Ok(())
    }
    async fn verify(&self) -> Result<(), Error> {
        let bot = self.api.get("/users/me").await?;
        if bot["id"] != self.config.bot
            || bot["is_bot"] != true
            || bot["delete_at"].as_i64() != Some(0)
        {
            return Err("Mattermost token does not identify the configured active bot".into());
        }
        self.verify_operator().await?;
        for room in &self.config.rooms {
            let channel = self.api.get(&format!("/channels/{}", room.channel)).await?;
            if channel["id"] != room.channel || channel["delete_at"].as_i64() != Some(0) {
                return Err("configured Mattermost channel is unavailable".into());
            }
            self.api.posts(&room.channel, None, 1).await?;
            self.coord.require_send_receive(&room.name).await?;
        }
        Ok(())
    }
    async fn read(&self, room: &str, cursor: u64, limit: usize) -> Result<Value, Error> {
        let (_cancel, cancellation) = tokio::sync::watch::channel(false);
        Ok(self
            .coord
            .read(room, cursor, limit, false, cancellation)
            .await?)
    }
    async fn bootstrap(&self, room: &Room) -> Result<(), Error> {
        let current = self.room(room)?;
        if current["initialized"] == 1 {
            return Ok(());
        }
        let posts = self.api.posts(&room.channel, None, 1).await?;
        let mut inbound = 0;
        for post in &posts {
            inbound = inbound.max(timestamp(post)?);
        }
        let mut cursor = 0;
        if !room.backfill {
            loop {
                let page = self.read(&room.name, cursor, 200).await?;
                cursor = page["next_cursor"]
                    .as_u64()
                    .ok_or("Coord cursor is invalid")?;
                if page["has_more"] != true {
                    break;
                }
            }
        }
        self.state(|s| s.initialize_room(&room.name, cursor, inbound.saturating_add(1)))?;
        Ok(())
    }
    fn room(&self, room: &Room) -> Result<Value, Error> {
        self.query("SELECT * FROM room_state WHERE coord_room=?1", [&room.name])?
            .into_iter()
            .next()
            .ok_or_else(|| "Mattermost room state is missing".into())
    }
    fn validate_post(&self, post: &Value, channel: &str, key: &str) -> Result<String, Error> {
        let id = post["id"]
            .as_str()
            .filter(|v| mm_id(v))
            .ok_or("Mattermost post ID is malformed")?;
        if post["user_id"] != self.config.bot
            || post["channel_id"] != channel
            || post["root_id"] != ""
            || post["props"]["safeyolo_coord"]["projection_key"] != key
        {
            return Err(
                "Mattermost post attribution or projection correlation is ambiguous".into(),
            );
        }
        Ok(id.to_owned())
    }
    async fn reconcile(&self) -> Result<(), Error> {
        for pending in self.query(
            "SELECT * FROM outbound_projection WHERE status='pending' ORDER BY created_at",
            [],
        )? {
            let channel = required(&pending, "channel_id")?;
            let key = required(&pending, "projection_key")?;
            let posts = self
                .api
                .posts(
                    channel,
                    Some(
                        pending["created_at"]
                            .as_i64()
                            .ok_or("invalid pending projection time")?
                            .saturating_sub(60000),
                    ),
                    200,
                )
                .await?;
            let matches: Vec<_> = posts
                .iter()
                .filter(|post| post["props"]["safeyolo_coord"]["projection_key"] == key)
                .collect();
            if matches.len() != 1 {
                return Err("uncertain or duplicate Mattermost projection requires operator reconciliation; no automatic retry".into());
            }
            let post = self.validate_post(matches[0], channel, key)?;
            self.state(|s| s.finish_projection(required(&pending, "coord_msg_id")?, &post))?;
        }
        Ok(())
    }
    fn own_inbound(&self, envelope: &Value) -> bool {
        if envelope["sender_kind"] != "operator" || envelope["content_type"] != "text/plain" {
            return false;
        }
        serde_json::from_str::<Value>(envelope["body"].as_str().unwrap_or(""))
            .is_ok_and(|v| v["schema"] == OPERATOR_SCHEMA && v["adapter_id"] == self.config.id)
    }
    async fn project(&self, room: &Room) -> Result<(), Error> {
        let mut cursor = self.state(|s| s.coord_cursor(&room.name))?;
        loop {
            let page = self.read(&room.name, cursor, 50).await?;
            for envelope in page["messages"]
                .as_array()
                .ok_or("Coord message page is invalid")?
            {
                let msg = required(envelope, "msg_id")?;
                let sequence = envelope["sequence"]
                    .as_u64()
                    .ok_or("Coord sequence is invalid")?;
                if !coord_id(msg, "msg-") || sequence <= cursor {
                    return Err("Coord envelope identity/order is invalid".into());
                }
                let existing = self
                    .query(
                        "SELECT * FROM outbound_projection WHERE coord_msg_id=?1",
                        [msg],
                    )?
                    .into_iter()
                    .next();
                if self.own_inbound(envelope)
                    || existing.as_ref().is_some_and(|v| v["status"] == "sent")
                {
                    cursor = sequence;
                    self.state(|s| s.set_coord_cursor(&room.name, cursor))?;
                    continue;
                }
                if existing.is_some() {
                    return Err(
                        "uncertain Mattermost projection remains pending; no automatic retry"
                            .into(),
                    );
                }
                let key = crate::coord_setup::sha256(
                    format!("{}\0{}\0{msg}", self.config.id, room.name).as_bytes(),
                );
                self.execute("INSERT INTO outbound_projection(coord_msg_id,coord_room,channel_id,projection_key,status,created_at) VALUES (?1,?2,?3,?4,'pending',?5)",params![msg,room.name,room.channel,key,now()])?;
                let semantic = self
                    .config
                    .actions
                    .as_ref()
                    .and_then(|a| render::semantic(envelope, &a.trusted));
                let mut capability = None;
                if let (Some(request), Some(actions)) = (&semantic, &self.config.actions)
                    && !request.allowed_actions.is_empty()
                    && self.listener_healthy.load(Ordering::Acquire)
                {
                    use base64::Engine;
                    let mut bytes = [0u8; 32];
                    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
                        .map_err(|_| "action capability randomness unavailable")?;
                    let token = Zeroizing::new(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
                    );
                    self.execute("INSERT INTO action_capability(capability_hash,coord_msg_id,coord_room,channel_id,projection_key,adapter_id,allowed_actions,status,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'issued',?8)",params![crate::coord_setup::sha256(token.as_bytes()),msg,room.name,room.channel,key,self.config.id,serde_json::to_string(&request.allowed_actions)?,now().saturating_add(actions.ttl*1000)])?;
                    capability = Some(token);
                }
                let mut props = json!({"safeyolo_coord":{"schema":PROJECTION_SCHEMA,"adapter_id":self.config.id,"projection_key":key,"coord_room":room.name,"coord_msg_id":msg},"attachments":[]});
                let message =
                    if let (Some(request), Some(actions)) = (&semantic, &self.config.actions) {
                        let (message, attachment) = render::attachment(
                            request,
                            envelope,
                            &room.name,
                            actions,
                            capability.as_ref().map(|v| v.as_str()),
                            &self.config.id,
                            &key,
                        );
                        props["attachments"] = json!([attachment]);
                        message
                    } else {
                        render::routine(envelope, &room.name)?
                    };
                if message.chars().count() > 14000 {
                    return Err("Mattermost projection exceeded post limit".into());
                }
                let post = self
                    .api
                    .request(
                        hyper::Method::POST,
                        "/posts?silent=true",
                        json!({"channel_id":room.channel,"message":message,"props":props}),
                    )
                    .await?;
                let post = self.validate_post(&post, &room.channel, &key)?;
                self.state(|s| s.finish_projection(msg, &post))?;
                cursor = sequence;
                self.state(|s| s.set_coord_cursor(&room.name, cursor))?;
            }
            if page["has_more"] != true {
                break;
            }
        }
        Ok(())
    }
    fn operator_body(
        &self,
        kind: &str,
        action: Option<&str>,
        text: &str,
        correlation: Value,
    ) -> String {
        json!({"schema":OPERATOR_SCHEMA,"adapter_id":self.config.id,"kind":kind,"action":action,"text":text,"correlation":correlation}).to_string()
    }
    async fn inbound(&self, room: &Room, post: &Value) -> Result<(), Error> {
        let id = required(post, "id")?;
        let existing = self.query(
            "SELECT status FROM inbound_post WHERE mattermost_post_id=?1",
            [id],
        )?;
        if let Some(existing) = existing.first() {
            if existing["status"] == "pending" {
                return Err("uncertain Coord append remains pending; no automatic replay".into());
            }
            return Ok(());
        }
        let ignored = if post["channel_id"] != room.channel {
            Some("channel_mismatch")
        } else if ["create_at", "update_at", "edit_at", "delete_at"]
            .iter()
            .any(|k| post[*k].as_i64().is_none())
        {
            Some("malformed_timestamps")
        } else if post["delete_at"] != 0
            || post["edit_at"] != 0
            || post["update_at"] != post["create_at"]
        {
            Some("edited_or_deleted")
        } else if post["user_id"] != self.config.operator {
            Some("not_configured_operator")
        } else if !post["root_id"].as_str().is_some_and(mm_id) {
            Some("unmapped_thread")
        } else {
            None
        };
        let mut reason = ignored;
        let projection = if reason.is_none() {
            self.query("SELECT * FROM outbound_projection WHERE mattermost_post_id=?1 AND coord_room=?2 AND channel_id=?3 AND status='sent'",params![required(post,"root_id")?,room.name,room.channel])?.into_iter().next()
        } else {
            None
        };
        if projection.is_none() && reason.is_none() {
            reason = Some("unmapped_thread");
        }
        let mut selected = None;
        let mut note = post["message"].as_str().unwrap_or("");
        if reason.is_none() {
            if note.trim().is_empty() || note.len() > 65536 {
                reason = Some("malformed_body_or_action");
            } else if note.starts_with("!safeyolo") {
                if let Some(rest) = note.strip_prefix("!safeyolo ") {
                    let (command, text) = rest.split_once(' ').unwrap_or((rest, ""));
                    if render::action(command) {
                        selected = Some(command);
                        note = text.trim();
                    } else {
                        reason = Some("malformed_body_or_action");
                    }
                } else {
                    reason = Some("malformed_body_or_action");
                }
            }
        }
        if let Some(reason) = reason {
            self.execute("INSERT INTO inbound_post(mattermost_post_id,coord_room,status,reason,created_at) VALUES (?1,?2,'ignored',?3,?4)",params![id,room.name,reason,now()])?;
            return Ok(());
        }
        let projection = projection.ok_or("missing inbound projection")?;
        let body=self.operator_body(if selected.is_some(){"action"}else{"reply"},selected,note,json!({"coord_msg_id":projection["coord_msg_id"],"mattermost_post_id":id,"mattermost_root_post_id":post["root_id"],"mattermost_channel_id":room.channel}));
        self.execute("INSERT INTO inbound_post(mattermost_post_id,coord_room,status,created_at) VALUES (?1,?2,'pending',?3)",params![id,room.name,now()])?;
        let result = self
            .coord
            .send(&room.name, &body, "text/plain", json!("room"))
            .await?;
        let msg = accepted_id(&result)?;
        self.execute("UPDATE inbound_post SET status='sent',coord_msg_id=?2 WHERE mattermost_post_id=?1 AND status='pending'",params![id,msg])?;
        Ok(())
    }
    async fn poll(&self, room: &Room) -> Result<(), Error> {
        self.verify_operator().await?;
        let since = self.room(room)?["inbound_since"]
            .as_i64()
            .ok_or("invalid inbound cursor")?;
        let mut posts = self
            .api
            .posts(&room.channel, Some(since.saturating_sub(5000)), 200)
            .await?;
        for post in &posts {
            timestamp(post)?;
        }
        posts.sort_by(|a, b| {
            (a["update_at"].as_i64(), a["id"].as_str())
                .cmp(&(b["update_at"].as_i64(), b["id"].as_str()))
        });
        let mut observed = since;
        for post in &posts {
            self.inbound(room, post).await?;
            observed = observed.max(timestamp(post)?);
        }
        self.execute(
            "UPDATE room_state SET inbound_since=MAX(inbound_since,?2) WHERE coord_room=?1",
            params![room.name, observed.saturating_add(1)],
        )?;
        Ok(())
    }
    async fn cycle(&self) -> Result<(), Error> {
        if !self
            .query(
                "SELECT mattermost_post_id FROM inbound_post WHERE status='pending'",
                [],
            )?
            .is_empty()
        {
            return Err("uncertain Coord append remains pending; inspect canonical room before recovery; no automatic replay".into());
        }
        for room in &self.config.rooms {
            self.bootstrap(room).await?;
        }
        self.reconcile().await?;
        for room in &self.config.rooms {
            self.poll(room).await?;
            self.project(room).await?;
        }
        Ok(())
    }
    fn health(&self) -> Result<Value, Error> {
        let rows = self.query(
            "SELECT COUNT(*) AS count FROM action_capability WHERE status='pending'",
            [],
        )?;
        Ok(
            json!({"adapter":"ready","listener":if self.listener_healthy.load(Ordering::Acquire){"healthy"}else{"failed"},"pending_action_reconciliation":rows.first().ok_or("missing action count")?["count"]}),
        )
    }
    async fn callback(&self, payload: &Value) -> (u16, Value) {
        let error = |status: u16| {
            (
                status,
                json!({"error":match status{400=>"invalid callback",403=>"action is not authorized",409=>"action was already accepted",410=>"action has expired",_=>"action acceptance is pending operator reconciliation or unavailable"}}),
            )
        };
        if self.config.actions.is_none() {
            return (404, json!({"error":"not found"}));
        }
        let context = &payload["context"];
        if !["user_id", "channel_id", "post_id"]
            .iter()
            .all(|k| payload[*k].as_str().is_some_and(mm_id))
            || payload
                .get("root_id")
                .is_some_and(|v| !v.is_null() && v != "" && !v.as_str().is_some_and(mm_id))
            || !context.as_object().is_some_and(|v| {
                v.len() == 4
                    && ["adapter_id", "projection_key", "capability", "action"]
                        .iter()
                        .all(|k| v.contains_key(*k))
            })
            || !context["projection_key"].as_str().is_some_and(hex64)
            || !context["capability"].as_str().is_some_and(|v| {
                (32..=128).contains(&v.len())
                    && v.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            })
            || !context["action"].as_str().is_some_and(render::action)
        {
            return error(400);
        }
        if payload["user_id"] != self.config.operator || context["adapter_id"] != self.config.id {
            return error(403);
        }
        let validation = match self.state.lock() {
            Ok(mut s) => s.begin_action(payload, &self.config.id, false),
            Err(_) => Err(503),
        };
        if let Err(status) = validation {
            return error(status);
        }
        if self.verify_operator().await.is_err() {
            return error(503);
        }
        let record = match self.state.lock() {
            Ok(mut s) => s.begin_action(payload, &self.config.id, true),
            Err(_) => Err(503),
        };
        let record = match record {
            Ok(record) => record,
            Err(status) => return error(status),
        };
        let action = context["action"].as_str().unwrap_or("");
        let body=self.operator_body("action",Some(action),"",json!({"coord_msg_id":record["coord_msg_id"],"mattermost_post_id":payload["post_id"],"mattermost_root_post_id":payload["post_id"],"mattermost_channel_id":payload["channel_id"],"projection_key":context["projection_key"]}));
        let sent = self
            .coord
            .send(
                record["coord_room"].as_str().unwrap_or(""),
                &body,
                "text/plain",
                json!("room"),
            )
            .await;
        let hash =
            crate::coord_setup::sha256(context["capability"].as_str().unwrap_or("").as_bytes());
        let completed = match sent {
            Ok(result) => {
                accepted_id(&result).and_then(|msg| self.state(|s| s.finish_action(&hash, msg)))
            }
            Err(_) => Err("action append uncertain".into()),
        };
        if completed.is_err() {
            return error(503);
        }
        let marker = json!({"schema":PROJECTION_SCHEMA,"adapter_id":self.config.id,"projection_key":context["projection_key"],"coord_room":record["coord_room"],"coord_msg_id":record["coord_msg_id"]});
        if self
            .api
            .request(
                hyper::Method::PUT,
                &format!("/posts/{}/patch", payload["post_id"].as_str().unwrap_or("")),
                json!({"props":{"safeyolo_coord":marker,"attachments":[]}}),
            )
            .await
            .is_err()
        {
            eprintln!("Mattermost action accepted; button retirement failed");
        }
        (
            200,
            json!({"ephemeral_text":format!("SafeYolo accepted {action}{}.",if action=="revise"{"; reply in this thread with the requested revision"}else{""})}),
        )
    }
    async fn foreground(self: Arc<Self>) -> Result<(), Error> {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let listener_task = if let Some(actions) = &self.config.actions {
            match listener::bind(actions).await {
                Ok(socket) => {
                    self.listener_healthy.store(true, Ordering::Release);
                    let adapter = self.clone();
                    Some(tokio::spawn(async move {
                        let result = listener::serve(socket, adapter.clone(), cancel_rx).await;
                        adapter.listener_healthy.store(false, Ordering::Release);
                        if result.is_err() {
                            eprintln!(
                                "Mattermost action listener failed; routine projection/replies remain available"
                            );
                        }
                        result
                    }))
                }
                Err(_) => {
                    eprintln!(
                        "Mattermost action listener bind failed; routine projection/replies remain available"
                    );
                    None
                }
            }
        } else {
            None
        };
        let work = async {
            loop {
                self.cycle().await?;
                tokio::time::sleep(self.config.interval).await;
            }
        };
        let result = tokio::select! {result=work=>result,signal=tokio::signal::ctrl_c()=>signal.map_err(|_|"Mattermost interrupt listener unavailable".into()),_=terminate.recv()=>Ok(())};
        self.listener_healthy.store(false, Ordering::Release);
        let _ = cancel_tx.send(true);
        if let Some(task) = listener_task {
            let _ = task.await;
        }
        result
    }
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("protocol field {key} must be a string").into())
}
fn timestamp(post: &Value) -> Result<i64, Error> {
    post["update_at"]
        .as_i64()
        .filter(|v| *v >= 0)
        .ok_or_else(|| "Mattermost update_at is invalid".into())
}
fn accepted_id(result: &Value) -> Result<&str, Error> {
    result["envelope"]["msg_id"]
        .as_str()
        .filter(|v| coord_id(v, "msg-"))
        .ok_or_else(|| "Coord append has no canonical message ID; acceptance uncertain".into())
}

pub async fn run(native_config: &Path, arguments: &[String]) -> Result<(), Error> {
    if arguments == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let Some(command) = arguments
        .first()
        .filter(|v| ["check", "run"].contains(&v.as_str()))
    else {
        return Err(HELP.into());
    };
    let mut config = None;
    let mut once = false;
    let mut args = arguments[1..].iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(
                    args.next().ok_or("--config requires a path")?,
                ))
            }
            "--once" if command == "run" && !once => once = true,
            _ => return Err("unknown or duplicate Mattermost option".into()),
        }
    }
    let path = config.unwrap_or_else(|| {
        native_config
            .parent()
            .unwrap_or(Path::new("."))
            .join("coord-mattermost.toml")
    });
    let config = Config::load(&path)?;
    let token=state::token(&config.token).map_err(|_|"Mattermost bot_token_file must be private, regular, operator-owned and contain one token")?;
    let state=State::open(&config).map_err(|_|"Mattermost state is unavailable, owned by another adapter, unsafe or bound to different configuration; preserve it and check state_file/lease")?;
    let coord = Arc::new(OperatorCoord::open(native_config)?);
    let adapter = Arc::new(Adapter {
        api: Api {
            base: config.server.clone(),
            token,
        },
        config,
        state: Mutex::new(state),
        coord: coord.clone(),
        listener_healthy: AtomicBool::new(false),
    });
    let result = async {
        adapter.verify().await?;
        if command == "check" {
            if let Some(actions) = &adapter.config.actions {
                drop(
                    listener::bind(actions)
                        .await
                        .map_err(|_| "Mattermost callback port is unavailable")?,
                );
            }
            println!("Mattermost adapter configuration is valid.");
            Ok(())
        } else if once {
            adapter.cycle().await
        } else {
            adapter.foreground().await
        }
    }
    .await;
    coord.shutdown().await;
    result
}
