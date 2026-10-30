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
        if name == "list_approvals" {
            return self.get("/approvals").await;
        }
        if matches!(name, "read_approval" | "resolve_approval") {
            let id = text(args, "approval_id")?;
            if !crate::approvals::pending::valid_id(id) {
                return Err("invalid approval_id".into());
            }
            let path = format!("/approvals/{id}");
            if name == "read_approval" {
                return self.get(&path).await;
            }
            return self.request(Method::POST,&format!("{path}/resolve"),json!({
                "decision":text(args,"decision")?,"delegation":text(args,"delegation")?,"option":text(args,"option")?
            }),Duration::from_secs(60)).await;
        }
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
            "create_signal" => {
                let mut body = args
                    .as_object()
                    .ok_or("signal arguments must be an object")?
                    .clone();
                body.remove("room_name");
                body.insert("action".into(), json!("create"));
                (
                    Method::POST,
                    format!("{base}/signals"),
                    Value::Object(body),
                    60.0,
                )
            }
            "read_signal" | "list_signals" => {
                let mut path = format!("{base}/signals?limit={}", integer(args, "limit", 50)?);
                for key in ["signal_id", "revision", "after", "state", "needs_operator"] {
                    if let Some(value) = args.get(key) {
                        let value = value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string());
                        path.push_str(&format!("&{key}={}", segment(&value)));
                    }
                }
                (Method::GET, path, Value::Null, 60.0)
            }
            "create_work" | "claim_work" | "release_work" | "complete_work"
            | "change_work_target" | "attest_work" => {
                let mut body = args
                    .as_object()
                    .ok_or("work arguments must be an object")?
                    .clone();
                body.remove("room_name");
                let action = match name {
                    "change_work_target" => "change_target",
                    _ => name.trim_end_matches("_work"),
                };
                body.insert("action".into(), json!(action));
                (
                    Method::POST,
                    format!("{base}/work"),
                    Value::Object(body),
                    60.0,
                )
            }
            "read_work" => (
                Method::GET,
                format!("{base}/work?work_id={}", segment(text(args, "work_id")?)),
                Value::Null,
                60.0,
            ),
            "list_work" => {
                let mut path = format!("{base}/work?limit={}", integer(args, "limit", 50)?);
                for key in ["after", "state"] {
                    if let Some(value) = args.get(key).and_then(Value::as_str) {
                        path.push_str(&format!("&{key}={}", segment(value)));
                    }
                }
                (Method::GET, path, Value::Null, 60.0)
            }
            "list_work_attestations" => {
                let mut path = format!(
                    "{base}/work?work_id={}&attestations=true&limit={}",
                    segment(text(args, "work_id")?),
                    integer(args, "limit", 50)?
                );
                if let Some(after) = args.get("after").and_then(Value::as_str) {
                    path.push_str(&format!("&after={}", segment(after)));
                }
                (Method::GET, path, Value::Null, 60.0)
            }
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
            Some("object") => validate_arguments(value, property).is_ok(),
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
        "create_signal",
        "Raise an attributed blocker, decision, result or correction. observed means the author reports observation; it is not platform attestation. Summary is 1..1024 UTF-8 bytes; refs are opaque, at most 16 strings of 1024 bytes. Corrections require supersedes with your own signal_id and expected_revision. Only current page_operator permission pages unresolved blocker/decision, subject to dedup and rate limits. Creation remains usable without that permission. Choose operation_id before writing; recover an ambiguous result using its exact original inputs.",
        json!({"room_name":string,"kind":{"type":"string","enum":["blocker","decision","result","correction"]},"summary":string,"basis":{"type":"string","enum":["observed","inferred"]},"work_id":string,"refs":array,"supersedes":{"type":"object","properties":{"signal_id":string,"expected_revision":integer},"required":["signal_id","expected_revision"],"additionalProperties":false},"operation_id":string}),
        &["room_name", "kind", "summary", "basis"],
    );
    add(
        "read_signal",
        "Read the current signal or an exact immutable revision. Author identity is trusted; the claim and refs remain author-supplied data. Current receive permission is checked on every read, including history.",
        json!({"room_name":string,"signal_id":string,"revision":integer}),
        &["room_name", "signal_id"],
    );
    add(
        "list_signals",
        "List canonical material signals, defaulting to current claims. Resolved and superseded revisions remain auditable. Lists are bounded by 100 items and 65536 bytes; follow next_after. needs_operator filters permitted unresolved blocker/decision pages. Pages do not share a snapshot.",
        json!({"room_name":string,"after":string,"limit":integer,"state":{"type":"string","enum":["current","resolved","superseded","all"]},"needs_operator":{"type":"boolean"}}),
        &["room_name"],
    );
    add(
        "create_work",
        "Create open work in an authorized room. external_ref is opaque. Content is attributed to the authenticated agent. Supply operation_id before a write to recover an ambiguous result.",
        json!({"room_name":string,"title":string,"external_ref":string,"operation_id":string}),
        &["room_name", "title"],
    );
    add(
        "list_work",
        "List canonical work ordered by work_id. Use next_after to continue. Pages contain at most 200 items; they do not share a snapshot.",
        json!({"room_name":string,"after":string,"limit":integer,"state":string}),
        &["room_name"],
    );
    add(
        "read_work",
        "Read the current canonical work, version, claim generation and candidate target_ref/target_generation. Room receive permission is checked on every read.",
        json!({"room_name":string,"work_id":string}),
        &["room_name", "work_id"],
    );
    add(
        "change_work_target",
        "Explicitly change the work candidate using its current version and target generation. Every successful change advances target_generation, including a reused opaque ref after squash/rebase. Prior attestations remain stale history. Requires room send and receive; does not transfer ownership or complete work. Pick operation_id before writing; retry its original inputs after an ambiguous response. target_ref is never fetched.",
        json!({"room_name":string,"work_id":string,"expected_version":integer,"expected_target_generation":integer,"target_ref":string,"operation_id":string}),
        &[
            "room_name",
            "work_id",
            "expected_version",
            "expected_target_generation",
            "target_ref",
        ],
    );
    add(
        "attest_work",
        "Append an immutable attributed attestation for the current target_generation. Author comes only from authenticated identity. Independent submissions do not require an expected work version; a changed candidate conflicts. kind is review, acceptance or another stated kind; verdict is approve, reject or abstain. Summaries and opaque evidence_refs are author reports; external content gains no trust and is never fetched. No vote threshold or automatic completion. Pick operation_id before writing; retry with original inputs. Limits: kind 128 UTF-8 bytes, summary 1024, at most 16 refs of 1024 bytes, complete serialized record 32768 bytes.",
        json!({"room_name":string,"work_id":string,"target_generation":integer,"kind":string,"verdict":{"type":"string","enum":["approve","reject","abstain"]},"summary":string,"evidence_refs":array,"operation_id":string}),
        &[
            "room_name",
            "work_id",
            "target_generation",
            "kind",
            "verdict",
            "summary",
        ],
    );
    add(
        "list_work_attestations",
        "Read full canonical attestations for work, with authenticated authors, evidence_refs and current/stale flags against the returned target_generation. Current receive permission is required. Ordered by attestation_id; follow next_after. At most 200 items and 65536 item JSON bytes per page. Pages do not share a snapshot. References remain untrusted external content.",
        json!({"room_name":string,"work_id":string,"after":string,"limit":integer}),
        &["room_name", "work_id"],
    );
    for (name, description) in [
        (
            "claim_work",
            "Atomically claim open work for your durable agent ID. Claims never expire or transfer with process liveness. Mutations require send and receive. Supply original expectations and operation_id for retry; changed input conflicts.",
        ),
        (
            "release_work",
            "Release your current claim with its exact version and generation. A former holder cannot release a later claim. An identical operation-ID retry returns its original result while room authority remains current.",
        ),
        (
            "complete_work",
            "Complete your current claim with its exact version and generation and an optional short_result. Completion never creates a result signal. Work/result content stays in canonical storage; audit and attention contain metadata.",
        ),
    ] {
        let mut properties = json!({"room_name":string,"work_id":string,"expected_version":integer,"expected_generation":integer,"operation_id":string});
        if name == "complete_work" {
            properties["short_result"] = string.clone();
        }
        add(
            name,
            description,
            properties,
            &[
                "room_name",
                "work_id",
                "expected_version",
                "expected_generation",
            ],
        );
    }
    add(
        "list_approvals",
        "List canonical pending approvals inside your current deciding delegation. Room references confer no authority.",
        json!({}),
        &[],
    );
    add(
        "read_approval",
        "Read trusted request facts and host-generated choices. Raw peer traffic and secrets are not returned. Authorization is checked on every read.",
        json!({"approval_id":string}),
        &["approval_id"],
    );
    add(
        "resolve_approval",
        "Approve, reject or defer a canonical request using one current delegation and an offered option. A lost response requires canonical readback before another decision. This does not grant policy administration.",
        json!({"approval_id":string,"decision":{"type":"string","enum":["approve","reject","defer"]},"delegation":string,"option":string}),
        &["approval_id", "decision", "delegation", "option"],
    );
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
        "Read the canonical bounded room projection: brief revision/excerpt, current members and authorized capabilities, declarations, provider-owned leases, active work, completed work, current signals, operator needs and latest current results. Work includes its target generation, current acceptance disposition counts and bounded attributed current/stale attestations. No majority or automatic completion is inferred. Counts and truncation expose omitted items. Declarations and signal claims remain attributed reports, not verified capabilities or independent attestation. Stale provider evidence is unknown; durable claims do not expire.",
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
