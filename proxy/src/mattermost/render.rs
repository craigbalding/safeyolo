//! Fixed semantic schema and inert CommonMark projection. Sender text never
//! supplies the canonical footer or an action integration.
use super::config::{Actions, coord_id};
use crate::Error;
use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag, TagEnd};
use serde::Deserialize;
use serde_json::{Value, json};

pub(super) const REQUEST_SCHEMA: &str = "safeyolo.coord.operator-request/v1";
pub(super) const OPERATOR_SCHEMA: &str = "safeyolo.coord.mattermost.operator/v1";
pub(super) const PROJECTION_SCHEMA: &str = "safeyolo.coord.mattermost.projection/v1";
const CLAIM_MARKER: &str = "[sender provenance claim]";

pub(super) fn action(value: &str) -> bool {
    [
        "acknowledge",
        "approve",
        "reject",
        "defer",
        "revise",
        "publish",
        "open-issue",
    ]
    .contains(&value)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticRequest {
    schema: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub reference: String,
    pub details: Vec<String>,
    pub allowed_actions: Vec<String>,
}
fn bounded(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.trim().len() <= maximum
        && !value
            .trim()
            .chars()
            .any(|c| c == '\r' || c == '\n' || (c as u32) < 0x20)
}
pub(super) fn semantic(envelope: &Value, trusted: &[String]) -> Option<SemanticRequest> {
    if envelope["sender_kind"] != "agent"
        || envelope["content_type"] != "text/plain"
        || !trusted.iter().any(|v| envelope["sender_agent_id"] == *v)
        || !coord_id(envelope["msg_id"].as_str()?, "msg-")
    {
        return None;
    }
    let body = envelope["body"].as_str()?;
    if body.len() > 32768 {
        return None;
    }
    // Struct deserialization rejects duplicate keys, extra keys and wrong field
    // types rather than accepting Value's last-key-wins representation.
    let request: SemanticRequest = serde_json::from_str(body).ok()?;
    let vocabulary: &[&str] = match request.kind.as_str() {
        "status" => &[],
        "decision" => &["acknowledge", "approve", "reject", "defer", "revise"],
        "factory-proposal" => &["open-issue", "revise", "defer", "reject"],
        "dispatch-publication" => &["publish", "revise", "defer"],
        _ => return None,
    };
    if request.schema != REQUEST_SCHEMA
        || !bounded(&request.title, 256)
        || !bounded(&request.summary, 2048)
        || !bounded(&request.reference, 256)
        || request.details.len() > 8
        || !request.details.iter().all(|v| bounded(v, 512))
        || request.allowed_actions.len() > 7
        || request
            .allowed_actions
            .iter()
            .any(|v| !vocabulary.contains(&v.as_str()))
        || request
            .allowed_actions
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != request.allowed_actions.len()
    {
        return None;
    }
    Some(request)
}

fn control(c: char) -> bool {
    c.is_control()
        || matches!(c as u32, 0xad | 0x61c | 0x180e | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0xfeff | 0xfff9..=0xfffb | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0000..=0xe0fff)
}
fn safe_chars(value: &str, multiline: bool) -> String {
    let mut result = String::new();
    for c in value.chars() {
        if c == '\n' && multiline {
            result.push(c);
        } else if c == '\n' {
            result.push(' ');
        } else if control(c) {
            result.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            result.push(match c {
                '@' => '＠',
                '~' => '～',
                _ => c,
            });
        }
    }
    result
}
fn escape(value: &str) -> String {
    let mut result = String::new();
    for c in value.chars() {
        if c == '&' {
            result.push_str("&amp;");
        } else {
            if "\\`*_[]()<>~#+=|{}!-.:".contains(c) {
                result.push('\\');
            }
            result.push(c);
        }
    }
    result
}
fn prefix(value: &str, maximum: usize) -> &str {
    let mut end = maximum.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}
pub(super) fn line(value: &str, maximum: usize) -> String {
    let value = if value.len() > maximum {
        format!(
            "{}… [truncated; sha256 {}]",
            prefix(value, maximum.saturating_sub(80)),
            &crate::coord_setup::sha256(value.as_bytes())[..16]
        )
    } else {
        value.to_owned()
    };
    escape(&safe_chars(&value, false))
}
fn https_link(value: &str) -> bool {
    value.starts_with("https://")
        && !value
            .chars()
            .any(|c| c.is_whitespace() || control(c) || "<>\\()\"'".contains(c))
        && value.parse::<hyper::Uri>().is_ok_and(|u| {
            u.host().is_some() && !u.authority().is_some_and(|v| v.as_str().contains('@'))
        })
}
pub(super) fn visible(events: &[Event<'_>]) -> String {
    let mut result = String::new();
    for event in events {
        match event {
            Event::Text(v) | Event::Code(v) | Event::Html(v) | Event::InlineHtml(v) => {
                result.push_str(v)
            }
            Event::SoftBreak | Event::HardBreak => result.push('\n'),
            Event::End(
                TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::Item | TagEnd::CodeBlock,
            ) => result.push('\n'),
            _ => {}
        }
    }
    result
}
fn claim_regex() -> &'static regex::Regex {
    static REGEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| {
        regex::Regex::new(r"(?i)canonical\s+provenance").expect("constant provenance expression")
    })
}

pub(super) fn markdown(body: &str, maximum: usize) -> String {
    let source = prefix(body, 8192);
    let mut events: Vec<_> = Parser::new(source).collect();
    // Break disguised visible provenance inside the contributing text event,
    // preserving surrounding links/emphasis/list structure. HTML stays escaped.
    let claims: Vec<_> = claim_regex()
        .find_iter(&visible(&events))
        .map(|m| m.start() + 8)
        .collect();
    let mut offset = 0;
    for event in &mut events {
        match event {
            Event::Text(v) | Event::Code(v) | Event::Html(v) | Event::InlineHtml(v) => {
                let old_len = v.len();
                let mut text = v.to_string();
                for at in claims
                    .iter()
                    .rev()
                    .copied()
                    .filter(|at| *at >= offset && *at < offset + old_len)
                {
                    text.insert_str(at - offset, CLAIM_MARKER);
                }
                *v = text.into();
                offset += old_len;
            }
            Event::SoftBreak
            | Event::HardBreak
            | Event::End(
                TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::Item | TagEnd::CodeBlock,
            ) => offset += 1,
            _ => {}
        }
    }
    let mut output = String::new();
    let mut links = Vec::new();
    let mut lists = Vec::new();
    let mut fence = String::new();
    for event in events {
        match event {
            Event::Start(Tag::Paragraph) => {}
            Event::Start(Tag::Heading { level, .. }) => {
                output.push_str(&"#".repeat(level as usize));
                output.push(' ');
            }
            Event::Start(Tag::Emphasis) => output.push('*'),
            Event::Start(Tag::Strong) => output.push_str("**"),
            Event::Start(Tag::List(start)) => lists.push(start),
            Event::Start(Tag::Item) => {
                output.push('\n');
                if let Some(Some(n)) = lists.last_mut() {
                    output.push_str(&format!("{n}. "));
                    *n += 1;
                } else {
                    output.push_str("- ");
                }
            }
            Event::Start(Tag::BlockQuote(_)) => output.push_str("\\> "),
            Event::Start(Tag::Link { dest_url, .. }) => {
                output.push('[');
                links.push(dest_url.to_string());
            }
            Event::Start(Tag::Image { dest_url, .. }) => {
                output.push_str("[image: ");
                links.push(dest_url.to_string());
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                fence = "~~~".to_owned();
                output.push('\n');
                output.push_str(&fence);
                if let CodeBlockKind::Fenced(language) = kind {
                    output.push_str(&safe_chars(&language, false).replace('`', ""));
                }
                output.push('\n');
            }
            Event::End(TagEnd::CodeBlock) => {
                if !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str(&fence);
                output.push_str("\n\n");
                fence.clear();
            }
            Event::End(
                TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::BlockQuote(_) | TagEnd::Item,
            ) => output.push_str("\n\n"),
            Event::End(TagEnd::Emphasis) => output.push('*'),
            Event::End(TagEnd::Strong) => output.push_str("**"),
            Event::End(TagEnd::List(_)) => {
                lists.pop();
                output.push('\n');
            }
            Event::End(TagEnd::Link | TagEnd::Image) => {
                let url = links.pop().unwrap_or_default();
                if https_link(&url) {
                    output.push_str(&format!("]({url})"));
                } else {
                    output.push_str("\\] \\[blocked link\\]");
                }
            }
            Event::Text(text) => {
                let text = safe_chars(&text, true);
                output.push_str(&if fence.is_empty() {
                    escape(&text)
                } else {
                    text
                });
            }
            Event::Code(text) => {
                let text = safe_chars(&text, false);
                let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
                let ticks = "`".repeat(longest + 1);
                output.push_str(&format!("{ticks} {text} {ticks}"));
            }
            Event::Html(text) | Event::InlineHtml(text) => {
                output.push_str(&escape(&safe_chars(&text, true)))
            }
            Event::SoftBreak => output.push('\n'),
            Event::HardBreak => output.push_str("  \n"),
            Event::Rule => output.push_str("\\---\n\n"),
            _ => {}
        }
    }
    let mut output = output.trim_end().to_owned();
    if output.starts_with("ACCEPTED") && output[8..].chars().next().is_none_or(char::is_whitespace)
    {
        output.insert_str(0, "TASK ");
    }
    if source.len() != body.len() || output.chars().count() > maximum {
        // Reparse a bounded prefix so cuts cannot leave an open code fence or
        // inline span which would absorb the trusted footer. At this rare bound,
        // a code block preserves complete literal text and the truncation hash.
        let literal = visible(&Parser::new(&output).collect::<Vec<_>>());
        let text = prefix(&literal, maximum.saturating_sub(160));
        let ticks = "~~~";
        output = format!(
            "{ticks}\n{text}\n{ticks}\n\n[truncated; sha256 {}]",
            &crate::coord_setup::sha256(body.as_bytes())[..16]
        );
    }
    if claim_regex().is_match(&visible(&Parser::new(&output).collect::<Vec<_>>())) {
        output = escape(&claim_regex().replace_all(
            &safe_chars(&visible(&Parser::new(&output).collect::<Vec<_>>()), true),
            CLAIM_MARKER,
        ));
    }
    output
}

pub(super) fn routine(envelope: &Value, room: &str) -> Result<String, Error> {
    for field in [
        "msg_id",
        "sent_at",
        "sender_kind",
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "content_type",
    ] {
        if envelope.get(field).is_none() {
            return Err("Coord envelope is missing canonical fields".into());
        }
    }
    let body = envelope["body"]
        .as_str()
        .ok_or("Coord body must be a string")?;
    let sender = envelope["sender_agent_name"]
        .as_str()
        .filter(|v| !v.is_empty())
        .or_else(|| envelope["sender_kind"].as_str())
        .unwrap_or("unknown");
    let code = |value: &str| safe_chars(prefix(value, 128), false).replace('`', "\\u0060");
    let mut footer = format!(
        "Canonical provenance · sender {} · agent `{}` · kind `{}` · room `{}` · message `{}`",
        line(sender, 128),
        code(envelope["sender_agent_id"].as_str().unwrap_or("none")),
        code(envelope["sender_kind"].as_str().unwrap_or("unknown")),
        code(room),
        code(envelope["msg_id"].as_str().unwrap_or("none"))
    );
    if let Some(mode) = envelope["attention_intent"]["mode"]
        .as_str()
        .filter(|v| ["none", "room", "targeted"].contains(v))
    {
        footer.push_str(&format!(" · attention `{mode}`"));
    }
    Ok(format!(
        "{}\n\n---\n{footer}",
        markdown(body, 13500 - footer.chars().count() - 6)
    ))
}
pub(super) fn attachment(
    request: &SemanticRequest,
    envelope: &Value,
    room: &str,
    actions: &Actions,
    capability: Option<&str>,
    adapter: &str,
    key: &str,
) -> (String, Value) {
    let sender = envelope["sender_agent_name"].as_str().unwrap_or("agent");
    let agent = envelope["sender_agent_id"].as_str().unwrap_or("none");
    let message = format!(
        "{}\n{} ({}) · canonical trusted agent · room {} · {}",
        line(request.title.trim(), 256),
        line(sender, 128),
        line(agent, 64),
        line(room, 128),
        line(request.reference.trim(), 256)
    );
    let mut buttons = Vec::new();
    if let Some(capability) = capability {
        for action in &request.allowed_actions {
            let mut button = json!({"id":action,"type":"button","name":action.replace('-'," "),"integration":{"url":actions.callback_url(),"context":{"adapter_id":adapter,"projection_key":key,"capability":capability,"action":action}}});
            if ["acknowledge", "approve", "publish", "open-issue"].contains(&action.as_str()) {
                button["style"] = json!("primary");
            } else if action == "reject" {
                button["style"] = json!("danger");
            }
            buttons.push(button);
        }
    }
    let label = match request.kind.as_str() {
        "status" => "SafeYolo status",
        "decision" => "SafeYolo decision",
        "factory-proposal" => "Factory improvement proposal",
        _ => "Dispatch publication candidate",
    };
    let detail = request
        .details
        .iter()
        .map(|v| format!("• {}", line(v.trim(), 512)))
        .collect::<Vec<_>>()
        .join("\n");
    let footer = if buttons.is_empty() {
        format!("{sender} ({agent}) · canonical provenance · {room} · no interactive actions")
    } else {
        format!(
            "{sender} ({agent}) · canonical trusted agent · {room} · actions expire in {} minutes",
            actions.ttl / 60
        )
    };
    (
        message,
        json!({"fallback":line(&format!("{label}: {}",request.title.trim()),512),"color":if request.kind=="status"{"#6a737d"}else{"#3d85c6"},"pretext":label,"title":line(request.title.trim(),256),"text":format!("{}\n\n**Reference:** {}\n{detail}",line(request.summary.trim(),2048),line(request.reference.trim(),256)),"footer":line(&footer,512),"actions":buttons}),
    )
}

// Callback parsing must reject duplicates at every level, not only in context.
pub(super) struct Unique(pub Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    values.insert(key, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
