//! Agent-facing Coord tools. All authority remains at the native Agent API.

use crate::{Error, native_client::helper_timeout};
use hyper::Method;
use serde_json::{Value, json};
use std::{collections::HashSet, path::PathBuf, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[derive(Clone)]
pub struct Client {
    pub socket: Option<PathBuf>,
    pub token_file: PathBuf,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            socket: std::env::var_os("SAFEYOLO_COORD_SOCKET").map(PathBuf::from),
            token_file: std::env::var_os("SAFEYOLO_COORD_TOKEN_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/app/agent_token".into()),
        }
    }
}

pub fn segment(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, Error> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a string").into())
}

fn integer(value: &Value, field: &str, default: u64) -> Result<u64, Error> {
    match value.get(field) {
        None => Ok(default),
        Some(number) => number
            .as_u64()
            .ok_or_else(|| format!("{field} must be a nonnegative integer").into()),
    }
}

pub fn attention_id(value: &str) -> bool {
    value.strip_prefix("attn-").is_some_and(|id| {
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub fn target_url(value: &str) -> bool {
    if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if rest.is_empty()
        || !scheme
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    {
        return false;
    }
    // Preserve absolute non-HTTP references while rejecting malformed bracketed
    // authorities, as the replaced urlsplit producer did.
    if let Some(authority) = rest.strip_prefix("//") {
        let host = authority
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit('@')
            .next()
            .unwrap_or("");
        if host.contains(['[', ']']) {
            let Some((address, suffix)) = host.strip_prefix('[').and_then(|v| v.split_once(']'))
            else {
                return false;
            };
            if address.parse::<std::net::Ipv6Addr>().is_err()
                || (!suffix.is_empty() && !suffix.starts_with(':'))
            {
                return false;
            }
        }
    }
    true
}

impl Client {
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Value,
        timeout: Duration,
    ) -> Result<Value, Error> {
        helper_timeout(
            self.socket.as_deref(),
            &self.token_file,
            path,
            method,
            body,
            timeout,
        )
        .await
    }

    pub async fn get(&self, path: &str) -> Result<Value, Error> {
        self.request(Method::GET, path, Value::Null, Duration::from_secs(60))
            .await
    }

    pub async fn call(&self, name: &str, args: &Value) -> Result<Value, Error> {
        let spec = tools()
            .into_iter()
            .find(|tool| tool["name"] == name)
            .ok_or("unknown Coord tool")?;
        validate_arguments(args, &spec["inputSchema"])?;
        if matches!(
            name,
            "wait_for_coord" | "wait_for_attention" | "read_attention"
        ) {
            if name == "read_attention" {
                let id = text(args, "attention_id")?;
                if !attention_id(id) {
                    return Err("invalid attention_id".into());
                }
                return self.get(&format!("/api/coord/attention/{id}/object")).await;
            }
            let since = integer(args, "since_sequence", 0)?;
            let limit = integer(args, "limit", 1)?;
            let seconds = args
                .get("timeout_seconds")
                .map_or(Some(60.0), Value::as_f64)
                .ok_or("timeout_seconds must be a number")?;
            if !seconds.is_finite() || seconds < 0.0 {
                return Err("timeout_seconds must be finite and nonnegative".into());
            }
            let timeout = Duration::from_secs_f64(seconds.min(300.0) + 30.0);
            let page = self
                .request(
                    Method::GET,
                    &format!(
                        "/api/coord/attention/wait?since={since}&limit={limit}&timeout={seconds}"
                    ),
                    Value::Null,
                    timeout,
                )
                .await?;
            if name == "wait_for_attention" {
                return Ok(page);
            }
            let edges = page["edges"]
                .as_array()
                .ok_or("invalid attention edge page")?;
            let next = page["next_cursor"]
                .as_u64()
                .filter(|next| *next >= since)
                .ok_or("invalid attention cursor")?;
            if edges.len() as u64 > limit {
                return Err("attention page exceeds requested limit".into());
            }
            let mut objects = Vec::new();
            let mut seen = HashSet::new();
            for edge in edges {
                let id = text(edge, "attention_id")?;
                if !attention_id(id) || !seen.insert(id) {
                    return Err("invalid or duplicate attention identity".into());
                }
                let resolved = self
                    .get(&format!("/api/coord/attention/{id}/object"))
                    .await?;
                if resolved.get("edge") != Some(edge) || !resolved["object"].is_object() {
                    return Err("mismatched canonical attention object".into());
                }
                objects.push(resolved);
            }
            return Ok(json!({"objects":objects,"next_cursor":next}));
        }
        let room = segment(text(args, "room_name")?);
        let base = format!("/api/coord/rooms/{room}");
        let (method, path, body, timeout) = match name {
            "join_room" => (Method::POST, format!("{base}/join"), json!({}), 60.0),
            "read_brief" => (Method::GET, format!("{base}/brief"), Value::Null, 60.0),
            "get_room_state" => (Method::GET, format!("{base}/state"), Value::Null, 60.0),
            "declare_capabilities" => (
                Method::POST,
                format!("{base}/declarations"),
                json!({"capabilities":args["capabilities"],"ttl_seconds":integer(args,"ttl_seconds",900)?}),
                60.0,
            ),
            "send" => (
                Method::POST,
                format!("{base}/send"),
                json!({"body":text(args,"body")?,"declared_content_type":args.get("declared_content_type").cloned().unwrap_or(json!("text/markdown")),"notify":args.get("notify").cloned().unwrap_or(json!("none"))}),
                60.0,
            ),
            "send_task" => {
                let assignee = text(args, "assignee")?;
                let target = text(args, "target")?;
                let body = text(args, "body")?;
                if !crate::coord_supervisor::simple_name(text(args, "room_name")?)
                    || !crate::coord_supervisor::simple_name(assignee)
                    || !target_url(target)
                    || body.trim().is_empty()
                    || body
                        .lines()
                        .any(|line| line == "TASK" || line.starts_with("TASK "))
                {
                    return Err("invalid or duplicate TASK header".into());
                }
                (
                    Method::POST,
                    format!("{base}/send"),
                    json!({"body":format!("TASK target={target} assignee={assignee}\n\n{body}"),"notify":[assignee],"declared_content_type":"text/markdown"}),
                    60.0,
                )
            }
            "read_room" => (
                Method::GET,
                format!(
                    "{base}/messages?since={}&limit={}",
                    integer(args, "since_sequence", 0)?,
                    integer(args, "limit", 50)?
                ),
                Value::Null,
                60.0,
            ),
            "wait_for_message" => {
                let seconds = args
                    .get("timeout_seconds")
                    .map_or(Some(60.0), Value::as_f64)
                    .ok_or("invalid timeout_seconds")?;
                if !seconds.is_finite() || seconds < 0.0 {
                    return Err("invalid timeout_seconds".into());
                }
                (
                    Method::GET,
                    format!(
                        "{base}/wait?since={}&limit={}&timeout={seconds}&include_self={}",
                        integer(args, "since_sequence", 0)?,
                        integer(args, "limit", 1)?,
                        args.get("include_self")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    ),
                    Value::Null,
                    seconds.min(300.0) + 30.0,
                )
            }
            _ => return Err("unknown Coord tool".into()),
        };
        let result = self
            .request(method, &path, body, Duration::from_secs_f64(timeout))
            .await?;
        if name == "send_task" && result["sequence"].as_u64().is_none_or(|n| n == 0) {
            return Err(
                "task send returned no canonical room sequence; inspect history before retrying"
                    .into(),
            );
        }
        Ok(result)
    }
}

fn validate_arguments(args: &Value, schema: &Value) -> Result<(), Error> {
    let args = args.as_object().ok_or("arguments must be an object")?;
    for field in schema["required"].as_array().ok_or("invalid tool schema")? {
        if !args.contains_key(field.as_str().ok_or("invalid schema field")?) {
            return Err(format!("missing argument {field}").into());
        }
    }
    for (field, value) in args {
        let property = schema["properties"]
            .get(field)
            .ok_or_else(|| format!("unknown argument {field}"))?;
        let valid = match property["type"].as_str() {
            Some("string") => value.is_string(),
            Some("integer") => value.as_u64().is_some(),
            Some("number") => value.is_number(),
            Some("boolean") => value.is_boolean(),
            Some("array") => value
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)),
            _ => {
                value.is_string()
                    || value
                        .as_array()
                        .is_some_and(|a| a.iter().all(Value::is_string))
            }
        };
        if !valid {
            return Err(format!("invalid type for {field}").into());
        }
    }
    Ok(())
}

pub fn tools() -> Vec<Value> {
    let string = json!({"type":"string"});
    let integer = json!({"type":"integer","minimum":0});
    let number = json!({"type":"number","minimum":0});
    let array = json!({"type":"array","items":{"type":"string"}});
    let mut result = Vec::new();
    let mut add = |name: &str, description: &str, properties: Value, required: &[&str]| {
        result.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}}));
    };
    add(
        "join_room",
        "Attach to an existing permitted membership. A room name is not a capability.",
        json!({"room_name":string}),
        &["room_name"],
    );
    add(
        "read_brief",
        "Read the current trusted operator brief. A brief is standing context, not assigned work.",
        json!({"room_name":string}),
        &["room_name"],
    );
    add(
        "get_room_state",
        "Read authoritative identity, declarations and provider-owned leases. Stale evidence is unknown.",
        json!({"room_name":string}),
        &["room_name"],
    );
    add(
        "declare_capabilities",
        "Replace bounded expiring declarations. Declarations are untrusted, never verified capabilities.",
        json!({"room_name":string,"capabilities":array,"ttl_seconds":integer}),
        &["room_name", "capabilities"],
    );
    add(
        "send",
        "Send through transport-derived identity. notify is none, room, or agent names. Attention affects interruption, not visibility. Unknown publication must be inspected in history before another send.",
        json!({"room_name":string,"body":string,"declared_content_type":string,"notify":{"anyOf":[{"type":"string"},array]}}),
        &["room_name", "body"],
    );
    add(
        "send_task",
        "Send one canonical TASK header and notify exactly its assignee. This validates a producer; it creates no task store.",
        json!({"room_name":string,"assignee":string,"target":string,"body":string}),
        &["room_name", "assignee", "target", "body"],
    );
    add(
        "read_room",
        "Read retained history from since_sequence, including own sends. For known sequence N use N-1 and limit=1; verify sequence and canonical sender. History does not assign work or change the attention cursor.",
        json!({"room_name":string,"since_sequence":integer,"limit":integer}),
        &["room_name"],
    );
    add(
        "wait_for_coord",
        "Foreground idle wait across authorized rooms. Resolves every returned edge before exposing next_cursor. Failure exposes no later cursor. Supervised turns leave waiting to their supervisor.",
        json!({"since_sequence":integer,"timeout_seconds":number,"limit":integer}),
        &["since_sequence"],
    );
    add(
        "wait_for_attention",
        "Lower-level identity-derived attention wait. Resolve every returned edge with read_attention before adopting its cursor.",
        json!({"since_sequence":integer,"timeout_seconds":number,"limit":integer}),
        &["since_sequence"],
    );
    add(
        "read_attention",
        "Resolve one canonical attention object. Authorization is rechecked.",
        json!({"attention_id":string}),
        &["attention_id"],
    );
    add(
        "wait_for_message",
        "Legacy per-room wait. Read history from the pre-wait cursor; its wake cursor can omit your own sends.",
        json!({"room_name":string,"since_sequence":integer,"timeout_seconds":number,"limit":integer,"include_self":{"type":"boolean"}}),
        &["room_name"],
    );
    result
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

async fn rpc(client: Client, request: Value) -> Option<Value> {
    let id = request.get("id").cloned();
    if !request.is_object()
        || request["jsonrpc"] != "2.0"
        || !request["method"].is_string()
        || id
            .as_ref()
            .is_some_and(|id| !id.is_null() && !id.is_string() && !id.is_number())
    {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let method = request["method"].as_str()?;
    let id = id?;
    let result = match method {
        "initialize" => {
            let version = request["params"]["protocolVersion"]
                .as_str()
                .unwrap_or("2024-11-05");
            let version = if ["2024-11-05", "2025-03-26", "2025-06-18"].contains(&version) {
                version
            } else {
                "2025-06-18"
            };
            json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"safeyolo-coord","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":tools()}),
        "tools/call" => {
            let Some(name) = request["params"]["name"].as_str() else {
                return Some(rpc_error(id, -32602, "Missing tool name"));
            };
            let args = request["params"]
                .get("arguments")
                .cloned()
                .unwrap_or(json!({}));
            match client.call(name, &args).await {
                Ok(value) => {
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false})
                }
                Err(error) => {
                    json!({"content":[{"type":"text","text":format!("Coord unavailable or request refused: {error}")}],"isError":true})
                }
            }
        }
        _ => return Some(rpc_error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

/// JSON-RPC over newline-delimited stdio. Independent waits and sends can run
/// concurrently; only the writer owns stdout. EOF drains bounded outstanding
/// responses for one-shot callers; terminating the adapter cancels its tasks.
pub async fn stdio(client: Client) -> Result<(), Error> {
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Value>(32);
    let writer = tokio::spawn(async move {
        let mut output = tokio::io::stdout();
        while let Some(value) = receiver.recv().await {
            output.write_all(value.to_string().as_bytes()).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let mut calls = tokio::task::JoinSet::new();
    let mut line = Vec::new();
    loop {
        let buffer = input.fill_buf().await?;
        if buffer.is_empty() {
            break;
        }
        let count = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |i| i + 1);
        let complete = buffer[count - 1] == b'\n';
        line.extend_from_slice(&buffer[..count]);
        input.consume(count);
        if line.len() > 2 * 1024 * 1024 {
            return Err("MCP request exceeds the Agent API request bound".into());
        }
        if complete {
            let parsed = serde_json::from_slice(&line);
            line.clear();
            let client = client.clone();
            let sender = sender.clone();
            calls.spawn(async move {
                let response = match parsed {
                    Ok(request) => rpc(client, request).await,
                    Err(_) => Some(rpc_error(Value::Null, -32700, "Parse error")),
                };
                if let Some(response) = response {
                    let _ = sender.send(response).await;
                }
            });
            while let Some(result) = calls.try_join_next() {
                result?;
            }
        }
    }
    // Finish responses already in progress for piped one-shot callers. The
    // request deadlines still bound waits; killing stdio cancels its tasks.
    while let Some(result) = calls.join_next().await {
        result?;
    }
    drop(sender);
    writer.await??;
    Ok(())
}
