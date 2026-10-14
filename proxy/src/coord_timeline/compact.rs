//! Compact operator transcript, matching the updated Python agent-room watcher.

use super::*;

// The reference watcher uses Python's readable diagnostic representation for
// structured errors. Keep it distinct from canonical JSON/raw output modes.
fn diagnostic(value: &Value, nested: bool) -> String {
    match value {
        Value::String(s) if !nested => s.clone(),
        Value::String(s) => {
            let quote = if s.contains('\'') && !s.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = quote.to_string();
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if c.is_ascii_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push(quote);
            out
        }
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}: {}", diagnostic(&json!(k), true), diagnostic(v, true)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(|v| diagnostic(v, true))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Null => "None".into(),
        _ => value.to_string(),
    }
}

fn count(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}m", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn compact_usage(value: &Value) -> String {
    let mut seen = std::collections::HashSet::new();
    [
        ("input_tokens", "in"),
        ("cached_input_tokens", "cached"),
        ("output_tokens", "out"),
        ("reasoning_output_tokens", "think"),
        ("input", "in"),
        ("cacheRead", "cached"),
        ("output", "out"),
        ("reasoning", "think"),
    ]
    .into_iter()
    .filter_map(|(key, label)| {
        let n = value[key].as_u64()?;
        seen.insert(label).then(|| format!("{label}={}", count(n)))
    })
    .collect::<Vec<_>>()
    .join(" ")
}

fn identifier(value: &Value) -> String {
    match value.as_str().filter(|s| !s.is_empty()) {
        Some(s) if s.chars().count() > 16 => format!("{}…", s.chars().take(12).collect::<String>()),
        Some(s) => s.into(),
        None => "?".into(),
    }
}

fn clean(display: &Display, text: &str, redact: bool) -> String {
    let text = if redact {
        redact_text(text)
    } else {
        text.into()
    };
    let text = visible(&text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    match display.max_text {
        Some(n) if text.chars().count() > n => {
            // Omitted-middle provenance remains visible even at short limits,
            // just as in the rendered view and updated Python watcher.
            let (detail, marker) = text
                .rsplit_once(" [middle snipped;")
                .map(|(detail, marker)| (detail, format!(" [middle snipped;{marker}")))
                .unwrap_or((&text, String::new()));
            let count = n.saturating_sub(marker.chars().count()).max(1);
            format!(
                "{}…{marker}",
                detail
                    .chars()
                    .take(count.saturating_sub(1))
                    .collect::<String>()
            )
        }
        _ => text,
    }
}

fn key(event: &Value, item: &Value) -> Option<String> {
    [
        item.get("id"),
        item.get("call_id"),
        item.get("toolCallId"),
        item.get("tool_call_id"),
        event.get("call_id"),
        event.get("toolCallId"),
        event.get("tool_call_id"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .find(|s| !s.is_empty())
    .map(str::to_owned)
}

fn compact_files(item: &Value) -> String {
    let mut shown = Vec::new();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for change in item["changes"].as_array().into_iter().flatten() {
        let Some(path) = change["path"].as_str().filter(|s| !s.is_empty()) else {
            continue;
        };
        if let Some(kind) = change["kind"].as_str().filter(|s| !s.is_empty()) {
            *counts.entry(kind.into()).or_default() += 1;
            shown.push(format!("{kind}:{path}"));
        } else {
            shown.push(path.into());
        }
    }
    let mut out = "file_change".to_owned();
    if !shown.is_empty() {
        out.push_str(&format!(" files={}", shown.len()));
        for kind in ["add", "update", "delete", "move"] {
            if let Some(n) = counts.remove(kind) {
                out.push_str(&format!(" {kind}={n}"));
            }
        }
        for (kind, n) in counts {
            out.push_str(&format!(" {kind}={n}"));
        }
        out.push(' ');
        out.push_str(&shown.join(" "));
    }
    out
}

fn receipt(item: &Value) -> String {
    if item["server"] != "safeyolo-coord" {
        return String::new();
    }
    let result = &item["result"];
    let Some(v) = result["structured_content"]
        .as_object()
        .or_else(|| result["structuredContent"].as_object())
    else {
        return String::new();
    };
    let mut parts = Vec::new();
    let mut number = |key: &str, label: &str| {
        if let Some(n) = v.get(key).and_then(Value::as_u64) {
            parts.push(format!("{label}={n}"));
        }
    };
    match item["tool"].as_str().unwrap_or_default() {
        "send" | "send_task" => {
            number("sequence", "seq");
            if let Some(s) = v
                .get("attention_status")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                parts.push(format!("attention={s}"));
            }
        }
        "read_room" => {
            if let Some(a) = v.get("messages").and_then(Value::as_array) {
                parts.push(format!("messages={}", a.len()));
            }
            if let Some(n) = v.get("next_cursor").and_then(Value::as_u64) {
                parts.push(format!("cursor={n}"));
            }
            if let Some(b) = v.get("has_more").and_then(Value::as_bool) {
                parts.push(format!("more={b}"));
            }
        }
        "wait_for_attention" | "wait_for_coord" => {
            for label in ["objects", "edges"] {
                if let Some(a) = v.get(label).and_then(Value::as_array) {
                    parts.push(format!("{label}={}", a.len()));
                    break;
                }
            }
            if let Some(n) = v.get("next_cursor").and_then(Value::as_u64) {
                parts.push(format!("cursor={n}"));
            }
        }
        "get_room_state" => {
            for (field, label) in [("members", "members"), ("resource_leases", "leases")] {
                if let Some(a) = v.get(field).and_then(Value::as_array) {
                    parts.push(format!("{label}={}", a.len()));
                }
            }
            if let Some(n) = v.get("brief").and_then(|b| b["revision"].as_u64()) {
                parts.push(format!("brief={n}"));
            }
        }
        _ => {}
    }
    parts.join(" ")
}

// Tokenize only literal shell words for the existing successful-skill-read label.
// This does not execute a command or infer that the agent followed the skill.
fn words(command: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut active = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c == '\\' && quote != Some('\'') {
            let next = chars.next()?;
            if quote == Some('"') && !matches!(next, '"' | '\\') {
                word.push(c);
            }
            word.push(next);
            active = true;
        } else if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
            active = true;
        } else if quote.is_none() && c.is_whitespace() {
            if active {
                out.push(std::mem::take(&mut word));
                active = false;
            }
        } else {
            word.push(c);
            active = true;
        }
    }
    if quote.is_some() {
        return None;
    }
    if active {
        out.push(word);
    }
    Some(out)
}

fn opened_skill(command: &str) -> Option<String> {
    let mut args = words(command)?;
    let basename = |s: &str| {
        std::path::Path::new(s)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned()
    };
    if args.len() == 3 && matches!(basename(&args[0]).as_str(), "bash" | "sh") && args[1] == "-lc" {
        args = words(&args[2])?;
    }
    if !matches!(
        basename(args.first()?).as_str(),
        "cat" | "sed" | "head" | "tail" | "bat" | "less"
    ) {
        return None;
    }
    args.iter().skip(1).find_map(|arg| {
        let parts = arg.split('/').collect::<Vec<_>>();
        if parts.len() < 3
            || parts[parts.len() - 3] != "skills"
            || parts.last() != Some(&"SKILL.md")
        {
            return None;
        }
        let name = parts[parts.len() - 2];
        (!name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)))
        .then(|| name.to_owned())
    })
}

fn from_rendered(label: &'static str, text: String) -> Option<(&'static str, String)> {
    match label {
        "AGENT" | "THINK" => Some(("#", text)),
        "ERROR" | "TOOLERR" | "STDERR" => Some(("!", text)),
        "SUPERV" => Some(("#", format!("supervisor {text}"))),
        "TOOL" => {
            let text = text
                .strip_prefix("started ")
                .or_else(|| text.strip_prefix("completed "))
                .unwrap_or(&text)
                .to_owned();
            if let Some(command) = text.strip_prefix("command ") {
                let command = command
                    .strip_prefix("rc=")
                    .and_then(|s| s.split_once(' '))
                    .map_or(command, |(_, s)| s);
                Some(("$", command.into()))
            } else {
                Some(("@", text))
            }
        }
        "EVENT" => Some(("?", text)),
        _ => None,
    }
}

fn render_event(display: &Display, e: &Value) -> Option<(&'static str, String)> {
    let kind = e["type"].as_str().unwrap_or_default();
    match kind {
        "safeyolo.codex.stderr" | "safeyolo.pi.stderr" => return Some(("!", get(e, "text", ""))),
        "safeyolo.supervisor" => {
            let (_, text) = event(e, display.show_unknown)?;
            return Some((
                if matches!(e["event"].as_str(), Some("error" | "crashed")) {
                    "!"
                } else {
                    "#"
                },
                format!("supervisor {text}"),
            ));
        }
        "error" | "turn.failed" | "extension_error" => {
            let field = if kind == "error" { "message" } else { "error" };
            return Some((
                "!",
                e.get(field)
                    .map(|v| diagnostic(v, false))
                    .unwrap_or_else(|| {
                        if kind == "turn.failed" {
                            "turn failed"
                        } else if kind == "extension_error" {
                            "extension failed"
                        } else {
                            "error"
                        }
                        .into()
                    }),
            ));
        }
        "thread.started" => return Some(("#", format!("session {}", identifier(&e["thread_id"])))),
        "session" => return Some(("#", format!("session {}", identifier(&e["id"])))),
        "turn.started" | "agent_start" => return Some(("#", "turn start".into())),
        "turn.completed" | "agent_end" => {
            let usage = compact_usage(&e["usage"]);
            return Some((
                "#",
                if usage.is_empty() {
                    "turn done".into()
                } else {
                    format!("turn done {usage}")
                },
            ));
        }
        "message_end" if e["message"]["role"] == "assistant" => {
            return event(e, display.show_unknown).map(|(_, s)| {
                (
                    if matches!(
                        e["message"]["stopReason"].as_str(),
                        Some("error" | "aborted")
                    ) {
                        "!"
                    } else {
                        "#"
                    },
                    s,
                )
            });
        }
        _ => {}
    }
    let pi = matches!(kind, "tool_execution_start" | "tool_execution_end");
    let item = if pi { e } else { &e["item"] };
    let item_type = if pi {
        "pi_tool"
    } else {
        item["type"].as_str().unwrap_or_default()
    };
    if pi || matches!(kind, "item.started" | "item.completed") && item.is_object() {
        let start = kind.ends_with("started") || kind.ends_with("start");
        if matches!(item_type, "agent_message" | "reasoning" | "agent_reasoning") {
            return Some(("#", get(item, "text", "")));
        }
        if matches!(
            item_type,
            "function_call_output" | "custom_tool_call_output"
        ) {
            return None;
        }
        if item_type == "error" {
            return Some(("!", get(item, "message", "error")));
        }
        if matches!(item_type, "file_change" | "file_write" | "apply_patch") {
            return (!start).then(|| ("@", compact_files(item)));
        }
        let (marker, detail) = match item_type {
            "pi_tool" => (
                if matches!(
                    e["toolName"].as_str(),
                    Some("bash" | "shell" | "command" | "exec_command")
                ) {
                    "$"
                } else {
                    "@"
                },
                pi_tool(e, "").trim_start().to_owned(),
            ),
            "command_execution" | "local_shell_call" => (
                "$",
                item.get("command")
                    .or_else(|| item.get("action"))
                    .or_else(|| item.get("arguments"))
                    .map(string)
                    .unwrap_or_default(),
            ),
            "mcp_tool_call" => {
                let detail = mcp(item, "").trim_start().to_owned();
                let status = format!(" status={}", get(item, "status", "?"));
                ("@", detail.replacen(&status, "", 1))
            }
            "function_call" | "custom_tool_call" => (
                "@",
                item.get("name")
                    .or_else(|| item.get("tool"))
                    .map(string)
                    .unwrap_or_else(|| "tool".into()),
            ),
            "web_search" | "web_search_call" => ("@", web(item, "").trim_start().to_owned()),
            _ => return display.show_unknown.then(|| ("?", format!("{kind} {e}"))),
        };
        let id = key(e, item);
        if start {
            if let Some(id) = id {
                display
                    .compact_state
                    .borrow_mut()
                    .insert(id, (marker, detail.clone()));
            }
            if item_type == "mcp_tool_call"
                && item["server"] == "safeyolo-coord"
                && matches!(
                    item["tool"].as_str(),
                    Some("send" | "send_task" | "read_room" | "get_room_state")
                )
            {
                return None;
            }
            return Some((marker, detail));
        }
        let prior = id.and_then(|id| display.compact_state.borrow_mut().remove(&id));
        if pi && e["isError"] == true {
            return Some(("!", format!("{} failed", prior.map_or(detail, |(_, s)| s))));
        }
        if item_type == "mcp_tool_call" {
            if (!item["error"].is_null() && item["error"] != false && item["error"] != "")
                || item["status"] == "failed"
            {
                return Some((
                    "!",
                    format!(
                        "{} failed: {}",
                        prior.map_or(detail, |(_, s)| s),
                        item.get("error")
                            .filter(|v| !v.is_null())
                            .map(|v| diagnostic(v, false))
                            .unwrap_or_else(|| "failed".into())
                    ),
                ));
            }
            let receipt = receipt(item);
            if !receipt.is_empty() {
                return Some((
                    "@",
                    format!("{} → {receipt}", prior.map_or(detail, |(_, s)| s)),
                ));
            }
        }
        if matches!(item_type, "command_execution" | "local_shell_call") {
            if let Some(code) = item["exit_code"].as_i64().filter(|c| *c != 0) {
                let excerpt = ["stderr", "aggregated_output", "stdout", "formatted_output"]
                    .iter()
                    .find_map(|key| {
                        item[*key]
                            .as_str()
                            .and_then(|s| s.lines().rev().find(|l| !l.trim().is_empty()))
                    });
                let mut text = format!("command failed rc={code}");
                if let Some(s) = excerpt {
                    text.push_str(": ");
                    text.push_str(&clean(display, s, true));
                }
                return Some(("!", clean(display, &text, true)));
            }
            if item["exit_code"] == 0 {
                let command = if detail.is_empty() {
                    prior.as_ref().map(|(_, text)| text.as_str()).unwrap_or("")
                } else {
                    &detail
                };
                if let Some(skill) = opened_skill(command) {
                    return Some(("#", format!("skill file read: {skill}")));
                }
            }
        }
        return if prior.is_some() {
            None
        } else {
            Some((marker, detail))
        };
    }
    if matches!(kind, "safeyolo.codex.oversize" | "safeyolo.pi.oversize") {
        return event(e, true).and_then(|(label, text)| from_rendered(label, text));
    }
    display.show_unknown.then(|| {
        (
            "?",
            format!("{} {e}", if kind.is_empty() { "unknown" } else { kind }),
        )
    })
}

pub(super) fn message(display: &Display, message: &Value) -> String {
    let Some(body) = message["body"].as_str() else {
        return String::new();
    };
    let operator = message["sender_kind"] == "operator";
    let line = if message["sender_kind"] == "agent" {
        match serde_json::from_str::<Value>(body) {
            Ok(e) if e.is_object() => render_event(display, &e),
            _ => Some(("#", body.into())),
        }
    } else {
        Some(("#", body.to_owned()))
    };
    let Some((marker, text)) = line else {
        return String::new();
    };
    // This marker comes only from the canonical envelope, never agent text.
    // Color alone cannot preserve attribution in logs or --plain output.
    let marker = if operator { ">" } else { marker };
    let text = clean(display, &text, display.redact);
    let text = if operator {
        format!("operator: {text}")
    } else {
        text
    };
    let time = timestamp(message).chars().take(5).collect::<String>();
    if display.no_color
        || !std::io::stdout().is_terminal()
        || std::env::var_os("NO_COLOR").is_some()
    {
        return format!("{time} {marker} {text}\n");
    }
    let time = format!("\x1b[2m{time}\x1b[0m");
    let code = match marker {
        "!" => "31;1",
        "?" => "33;1",
        "$" => "36;1",
        "@" => "35;1",
        _ if operator => "34",
        _ if text.starts_with("session ")
            || text.starts_with("turn ")
            || text.starts_with("supervisor ") =>
        {
            "2;32"
        }
        _ => "32",
    };
    if matches!(marker, "$" | "@") {
        format!("{time} \x1b[{code}m{marker}\x1b[0m {text}\n")
    } else {
        format!("{time} \x1b[{code}m{marker} {text}\x1b[0m\n")
    }
}
