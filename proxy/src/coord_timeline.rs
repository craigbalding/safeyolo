//! Operator display of room messages and the existing Codex/Pi event formats.

use std::io::IsTerminal;

use regex::Regex;
use serde_json::{Value, json};
use unicode_width::UnicodeWidthChar;

pub(crate) fn visible(text: &str) -> String {
    let mut output = String::new();
    for character in text.chars() {
        let direction = match character {
            '\u{202a}' => Some("LRE"),
            '\u{202b}' => Some("RLE"),
            '\u{202c}' => Some("PDF"),
            '\u{202d}' => Some("LRO"),
            '\u{202e}' => Some("RLO"),
            '\u{2066}' => Some("LRI"),
            '\u{2067}' => Some("RLI"),
            '\u{2068}' => Some("FSI"),
            '\u{2069}' => Some("PDI"),
            '\u{200e}' => Some("LRM"),
            '\u{200f}' => Some("RLM"),
            '\u{061c}' => Some("ALM"),
            _ => None,
        };
        if let Some(name) = direction {
            output.push_str(&format!("⟦{name} U+{:04X}⟧", character as u32));
        } else if character.is_control() && !matches!(character, '\n' | '\t') {
            output.push_str(&format!("\\x{:02x}", character as u32));
        } else {
            output.push(character);
        }
    }
    output
}

fn width() -> usize {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 2
    {
        usize::from(size.ws_col) - 2
    } else {
        78
    }
}

pub(crate) fn chat_message(message: &Value) -> String {
    let who = if message["sender_kind"] == "operator" {
        "operator"
    } else {
        message["sender_agent_name"]
            .as_str()
            .or_else(|| message["sender_agent_id"].as_str())
            .unwrap_or("?")
    };
    let mut output = format!(
        "{} {} seq={} attention={}\n",
        visible(who),
        timestamp(message),
        message["sequence"],
        message["attention_intent"]["mode"]
            .as_str()
            .unwrap_or("unknown")
    );
    let limit = width();
    for line in visible(message["body"].as_str().unwrap_or_default()).split('\n') {
        output.push_str("│ ");
        let mut column = 0;
        for character in line.chars() {
            // Expand tabs inside the gutter so they cannot wrap without it.
            let fragment = if character == '\t' {
                " ".repeat(8 - column % 8)
            } else {
                character.to_string()
            };
            for character in fragment.chars() {
                let cells = character.width().unwrap_or(0);
                if column + cells > limit {
                    output.push_str("\n│ ");
                    column = 0;
                }
                output.push(character);
                column += cells;
            }
        }
        output.push('\n');
    }
    output.push('\n');
    output
}

fn timestamp(message: &Value) -> String {
    let seconds = message["sent_at"]
        .as_i64()
        .map(|ms| ms / 1000)
        .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp());
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(t) => format!("{:02}:{:02}:{:02}Z", t.hour(), t.minute(), t.second()),
        Err(_) => "?".into(),
    }
}

fn string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
fn get(value: &Value, name: &str, fallback: &str) -> String {
    if value[name].is_null() {
        fallback.into()
    } else {
        string(&value[name])
    }
}

fn usage(value: &Value, keys: &[(&str, &str)]) -> String {
    keys.iter()
        .filter_map(|(key, label)| {
            value[*key].as_u64().map(|n| {
                let digits = n.to_string();
                let mut formatted = String::new();
                for (i, c) in digits.chars().enumerate() {
                    if i > 0 && (digits.len() - i).is_multiple_of(3) {
                        formatted.push(',');
                    }
                    formatted.push(c);
                }
                format!("{label}={formatted}")
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}
const PI_USAGE: &[(&str, &str)] = &[
    ("input", "uncached"),
    ("cacheRead", "cached"),
    ("cacheWrite", "cache_write"),
    ("output", "output"),
    ("reasoning", "reasoning"),
    ("totalTokens", "total"),
];

fn pi_tool(event: &Value, phase: &str) -> String {
    let mut detail = format!("{phase} {}", get(event, "toolName", "tool"));
    for key in [
        "command",
        "path",
        "offset",
        "limit",
        "room_name",
        "target",
        "query",
        "url",
    ] {
        let v = &event["args"][key];
        if v.is_string() || v.is_number() {
            detail.push_str(&format!(" {key}={}", string(v)));
        }
    }
    if phase == "completed" {
        detail.push_str(if event["isError"] == true {
            " status=error"
        } else {
            " status=ok"
        });
    }
    detail
}

fn mcp(item: &Value, phase: &str) -> String {
    let mut detail = format!(
        "{phase} {}.{} status={}",
        get(item, "server", "mcp"),
        get(item, "tool", "tool"),
        get(item, "status", "?")
    );
    // As in the existing watcher, show routing fields without dumping tool
    // bodies/results, authentication parameters or arbitrary arguments.
    for (keys, shown) in [
        (&["room_name"][..], "room"),
        (&["assignee"][..], "assignee"),
        (&["target"][..], "target"),
        (&["repository_full_name", "repo_full_name"][..], "repo"),
        (&["issue_number"][..], "issue"),
        (&["pr_number"][..], "pr"),
        (&["path"][..], "path"),
        (&["ref"][..], "ref"),
        (&["commit_sha", "sha"][..], "sha"),
        (&["head", "head_branch"][..], "head"),
        (&["base", "base_branch"][..], "base"),
        (&["branch", "branch_name"][..], "branch"),
        (&["run_id"][..], "run"),
        (&["job_id"][..], "job"),
        (&["query"][..], "query"),
        (&["url"][..], "url"),
        (&["since_sequence"][..], "cursor"),
        (&["timeout_seconds"][..], "timeout"),
        (&["limit"][..], "limit"),
    ] {
        if let Some(v) = keys.iter().find_map(|key| {
            let v = &item["arguments"][*key];
            (v.is_string() || v.is_number()).then_some(v)
        }) {
            detail.push_str(&format!(" {shown}={}", string(v)));
        }
    }
    if let Some(start) = item["arguments"]["start_line"].as_u64() {
        detail.push_str(&format!(" lines={start}"));
        if let Some(end) = item["arguments"]["end_line"].as_u64() {
            detail.push_str(&format!("-{end}"));
        }
    }
    if !item["error"].is_null() {
        detail.push_str(&format!(" error={}", string(&item["error"])));
    }
    detail
}

fn web(item: &Value, phase: &str) -> String {
    let action = &item["action"];
    let query = action.get("query").or_else(|| item.get("query"));
    let url = action
        .get("url")
        .or_else(|| item.get("url"))
        .and_then(Value::as_str)
        .or_else(|| {
            query
                .and_then(Value::as_str)
                .filter(|q| q.starts_with("http://") || q.starts_with("https://"))
        });
    let mut detail = format!("{phase} web_search");
    if let Some(url) = url {
        detail.push_str(&format!(" url={url}"));
    } else if let Some(queries) = action["queries"].as_array() {
        detail.push_str(&format!(
            " queries={}",
            queries
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    } else if let Some(query) = query.and_then(Value::as_str) {
        detail.push_str(&format!(" query={query}"));
    }
    detail
}

fn files(item: &Value, phase: &str) -> String {
    let mut detail = format!("{phase} file_change");
    for change in item["changes"].as_array().into_iter().flatten() {
        if let Some(path) = change["path"].as_str() {
            detail.push(' ');
            if let Some(kind) = change["kind"].as_str() {
                detail.push_str(kind);
                detail.push(':');
            }
            detail.push_str(path);
        }
    }
    detail
}

fn event(event: &Value, show_unknown: bool) -> Option<(&'static str, String)> {
    let kind = event["type"].as_str().unwrap_or_default();
    let rendered = match kind {
        "safeyolo.codex.oversize" | "safeyolo.pi.oversize" => {
            let original = get(event, "original_type", "unknown");
            let mut reconstructed = json!({"type":original,"item":event["summary"]});
            if !original.starts_with("item.") {
                if let Some(summary) = event["summary"].as_object() {
                    for (key, value) in summary {
                        reconstructed[key] = value.clone();
                    }
                }
            }
            let (label, text) = if matches!(
                original.as_str(),
                "safeyolo.codex.oversize" | "safeyolo.pi.oversize"
            ) {
                ("EVENT", original)
            } else {
                self::event(&reconstructed, true).unwrap_or(("EVENT", original))
            };
            (
                label,
                format!(
                    "{text} [middle snipped; original_bytes={} omitted_bytes={} sha256={}]",
                    get(event, "original_bytes", "?"),
                    get(event, "omitted_middle_bytes", "?"),
                    get(event, "sha256", "?")
                ),
            )
        }
        "safeyolo.codex.stderr" | "safeyolo.pi.stderr" => ("STDERR", get(event, "text", "")),
        "safeyolo.supervisor" => {
            let action = get(event, "event", "event");
            let mut detail = action.clone();
            for key in [
                "pid",
                "signal",
                "exit_code",
                "status",
                "path",
                "retry_after",
                "error_type",
                "message",
            ] {
                if let Some(v) = event.get(key) {
                    detail.push_str(&format!(" {key}={}", string(v)));
                }
            }
            (
                if matches!(action.as_str(), "error" | "crashed") {
                    "ERROR"
                } else {
                    "SUPERV"
                },
                detail,
            )
        }
        "error" => ("ERROR", get(event, "message", "error")),
        "thread.started" => (
            "SESSION",
            format!("thread={}", get(event, "thread_id", "?")),
        ),
        "session" => ("SESSION", format!("session={}", get(event, "id", "?"))),
        "turn.started" | "agent_start" => ("TURN", "started".into()),
        "turn.completed" => {
            let u = usage(
                &event["usage"],
                &[
                    ("input_tokens", "input"),
                    ("cached_input_tokens", "cached"),
                    ("output_tokens", "output"),
                    ("reasoning_output_tokens", "reasoning"),
                ],
            );
            (
                "DONE",
                if u.is_empty() {
                    "turn completed".into()
                } else {
                    format!("turn completed tokens {u}")
                },
            )
        }
        "agent_end" => {
            let u = usage(&event["usage"], PI_USAGE);
            (
                "DONE",
                if u.is_empty() {
                    "turn completed (token usage unavailable)".into()
                } else {
                    format!("turn completed tokens {u}")
                },
            )
        }
        "turn.failed" => ("ERROR", get(event, "error", "turn failed")),
        "tool_execution_start" | "tool_execution_end" => (
            if event["isError"] == true {
                "TOOLERR"
            } else {
                "TOOL"
            },
            pi_tool(
                event,
                if kind.ends_with("start") {
                    "started"
                } else {
                    "completed"
                },
            ),
        ),
        "message_end" if event["message"]["role"] == "assistant" => {
            let message = &event["message"];
            let text = message["content"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|b| b["type"] == "text")
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let u = usage(&message["usage"], PI_USAGE);
            (
                if matches!(message["stopReason"].as_str(), Some("error" | "aborted")) {
                    "ERROR"
                } else {
                    "AGENT"
                },
                if text.is_empty() {
                    format!(
                        "assistant message{}",
                        if u.is_empty() {
                            String::new()
                        } else {
                            format!(" tokens {u}")
                        }
                    )
                } else {
                    text
                },
            )
        }
        "extension_error" => ("ERROR", get(event, "error", "extension failed")),
        "item.started" | "item.completed" if event["item"].is_object() => {
            let item = &event["item"];
            let phase = kind.strip_prefix("item.").unwrap_or(kind);
            match item["type"].as_str().unwrap_or_default() {
                "agent_message" => ("AGENT", get(item, "text", "")),
                "reasoning" | "agent_reasoning" => ("THINK", get(item, "text", "")),
                "mcp_tool_call" => (
                    if !item["error"].is_null() || item["status"] == "failed" {
                        "TOOLERR"
                    } else {
                        "TOOL"
                    },
                    mcp(item, phase),
                ),
                "command_execution" | "local_shell_call" => {
                    let code = item["exit_code"].as_i64();
                    let command = item
                        .get("command")
                        .or_else(|| item.get("action"))
                        .or_else(|| item.get("arguments"))
                        .map(string)
                        .unwrap_or_default();
                    (
                        if code.is_some_and(|c| c != 0) {
                            "TOOLERR"
                        } else {
                            "TOOL"
                        },
                        format!(
                            "{phase} command{} {command}",
                            code.map(|c| format!(" rc={c}")).unwrap_or_default()
                        ),
                    )
                }
                "function_call" | "custom_tool_call" => (
                    "TOOL",
                    format!(
                        "{phase} {}",
                        item.get("name")
                            .or_else(|| item.get("tool"))
                            .map(string)
                            .unwrap_or_else(|| "tool".into())
                    ),
                ),
                "function_call_output" | "custom_tool_call_output" => (
                    "TOOL",
                    format!("{phase} result {}", get(item, "call_id", "")),
                ),
                "web_search" | "web_search_call" => ("TOOL", web(item, phase)),
                "file_change" | "file_write" | "apply_patch" => ("TOOL", files(item, phase)),
                "error" => ("ERROR", get(item, "message", "error")),
                _ if show_unknown => ("EVENT", event.to_string()),
                _ => return None,
            }
        }
        _ if show_unknown => ("EVENT", event.to_string()),
        _ => return None,
    };
    Some(rendered)
}

// Redaction is an explicit display choice, never a change to stored payloads.
fn redact_text(text: &str) -> String {
    static PATTERNS: std::sync::LazyLock<Vec<Regex>> = std::sync::LazyLock::new(|| {
        [
        r"(?i)\bBearer\s+[^\s,;]+", r"\b(?:sgw_|sk-|gh[pousr]_)[A-Za-z0-9._-]{8,}",
        r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b",
        r"(?i)\b(authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|cookie|private[_-]?key)\s*([:=])\s*([^\s,;]+)",
        r#"https?://[^\s\]\[\"'<>]+"#,
    ].iter().map(|p| Regex::new(p).expect("fixed watcher redaction expression")).collect()
    });
    let mut text = text.to_owned();
    for pattern in &PATTERNS[..3] {
        text = pattern.replace_all(&text, "<redacted>").into_owned();
    }
    text = PATTERNS[3]
        .replace_all(&text, "${1}${2}<redacted>")
        .into_owned();
    PATTERNS[4]
        .replace_all(&text, |c: &regex::Captures<'_>| {
            let url = &c[0];
            url.find(['?', '#'])
                .map(|index| format!("{}?<omitted>", &url[..index]))
                .unwrap_or_else(|| url.to_owned())
        })
        .into_owned()
}
fn redact_value(value: &Value) -> Value {
    match value {
        Value::String(s) => json!(redact_text(s)),
        Value::Array(a) => a.iter().map(redact_value).collect(),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), redact_value(v)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

#[derive(Default)]
pub(crate) struct Display {
    pub raw: bool,
    pub json: bool,
    pub redact: bool,
    pub show_unknown: bool,
    pub no_color: bool,
    pub max_text: Option<usize>,
}
impl Display {
    pub(crate) fn message(&self, message: &Value) -> String {
        if self.json {
            return format!(
                "{}\n",
                if self.redact {
                    redact_value(message)
                } else {
                    message.clone()
                }
            );
        }
        let body = message["body"].as_str().unwrap_or_default();
        if self.raw {
            let sender = message["sender_agent_name"]
                .as_str()
                .or_else(|| message["sender_kind"].as_str())
                .unwrap_or("unknown");
            return format!(
                "[{}] {}\n{}\n",
                timestamp(message),
                visible(sender),
                visible(&if self.redact {
                    redact_text(body)
                } else {
                    body.into()
                })
            );
        }
        let (label, text) = if message["sender_kind"] == "agent" {
            match serde_json::from_str::<Value>(body) {
                Ok(e) if e.is_object() => match event(&e, self.show_unknown) {
                    Some(line) => line,
                    None => return String::new(),
                },
                _ => ("CHAT", body.into()),
            }
        } else {
            (
                if message["sender_kind"] == "operator" {
                    "OP"
                } else {
                    "CHAT"
                },
                body.into(),
            )
        };
        let text = visible(&if self.redact {
            redact_text(&text)
        } else {
            text
        });
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let text = if let Some(limit) = self.max_text.filter(|l| text.chars().count() > *l) {
            // Preserve the existing oversize provenance marker even when the
            // operator selects a short event summary.
            let (detail, marker) = text
                .rsplit_once(" [middle snipped;")
                .map(|(detail, marker)| (detail, format!(" [middle snipped;{marker}")))
                .unwrap_or((&text, String::new()));
            let count = limit.saturating_sub(marker.chars().count()).max(1);
            format!(
                "{}…{}",
                detail
                    .chars()
                    .take(count.saturating_sub(1))
                    .collect::<String>(),
                marker
            )
        } else {
            text
        };
        let label = if !self.no_color
            && std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
        {
            let code = match label {
                "ERROR" | "TOOLERR" => "31;1",
                "STDERR" => "31",
                "AGENT" | "CHAT" => "32",
                "DONE" => "32;1",
                "TOOL" => "33",
                "OP" | "TURN" => "34;1",
                "THINK" => "35",
                "SUPERV" => "36;1",
                "SESSION" => "36",
                _ => "2",
            };
            format!("\x1b[{code}m{label:7}\x1b[0m")
        } else {
            format!("{label:7}")
        };
        format!("[{}] {label} {text}\n", timestamp(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_visible_and_chat_bodies_keep_a_gutter() {
        let m = json!({"sender_kind":"agent","sender_agent_name":"worker\u{001b}[2J","sequence":3,"body":"x\u{001b}]52;c;SECRET\u{0007}\rOP\u{202e}\nsecond"});
        let text = chat_message(&m);
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\x07'));
        assert!(!text.contains('\r'));
        assert!(text.contains("\\x1b]52;c;SECRET\\x07\\x0dOP⟦RLO U+202E⟧"));
        assert!(text.contains("\n│ second"));
    }

    #[test]
    fn timeline_preserves_events_and_explicit_output_choices() {
        let m = json!({"sent_at":0,"sender_kind":"agent","body":json!({"type":"item.completed","item":{"type":"mcp_tool_call","server":"coord","tool":"send","status":"completed","arguments":{"room_name":"backlog","body":"private message","token":"sk-privatevalue"},"result":"private output"}}).to_string()});
        let displayed = Display::default().message(&m);
        assert!(displayed.contains("TOOL    completed coord.send status=completed room=backlog"));
        assert!(!displayed.contains("private"));
        let raw = Display {
            raw: true,
            ..Default::default()
        }
        .message(&m);
        assert!(raw.contains("private message"));
        let json = Display {
            json: true,
            ..Default::default()
        }
        .message(&m);
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), m);
        let secret = json!({"sender_kind":"operator","body":"token=fixture-secret https://example.test/p?secret=abc#x"});
        assert!(
            Display::default()
                .message(&secret)
                .contains("fixture-secret")
        );
        let redacted = Display {
            redact: true,
            ..Default::default()
        }
        .message(&secret);
        assert!(!redacted.contains("fixture-secret"));
        assert!(redacted.contains("token=<redacted>"));
    }
}
