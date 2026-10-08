//! Evidence-backed Dispatch Markdown. Generation has no publication effects.

use crate::Error;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};
use time::{Date, Duration, Month, Weekday};

pub mod request;
mod site;
#[cfg(test)]
mod tests;

const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 512 * 1024;
const SECTIONS: [&str; 4] = ["shipped", "lens_caught", "worth_knowing", "factory_pulse"];
const ATTRIBUTIONS: [(&str, &str); 6] = [
    ("lens_review_finding", "Independent review finding (Lens)"),
    (
        "forge_implementation_discovery",
        "Implementation discovery (Forge issue owner)",
    ),
    (
        "preexisting_bug_exposed_by_testing",
        "Pre-existing bug exposed by testing",
    ),
    (
        "infrastructure_environment_problem",
        "Infrastructure or environment finding",
    ),
    (
        "factory_process_observation",
        "Software-factory process observation",
    ),
    ("relay_synthesis", "Editorial synthesis (Relay coordinator)"),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    version: u32,
    pub period: Period,
    #[serde(default)]
    definitions: BTreeMap<String, String>,
    sections: Vec<Section>,
    #[serde(default)]
    topic_updates: Vec<Topic>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Period {
    pub kind: String,
    #[serde(deserialize_with = "deserialize_date")]
    pub start: Date,
    #[serde(deserialize_with = "deserialize_date")]
    pub end: Date,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    kind: String,
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    kind: String,
    label: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snippet {
    language: String,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    title: String,
    body: String,
    attribution: String,
    evidence: Vec<Evidence>,
    #[serde(default, deserialize_with = "present_text")]
    theme: Option<String>,
    #[serde(default, deserialize_with = "present_snippet")]
    snippet: Option<Snippet>,
    #[serde(default, deserialize_with = "present_text")]
    lesson: Option<String>,
}

// Missing optional fields are allowed; explicitly supplied null is not text.
fn present_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn present_snippet<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Snippet>, D::Error> {
    Snippet::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Topic {
    slug: String,
    title: String,
    state_key: String,
    summary: String,
    current_state: Vec<String>,
    evidence: Vec<Evidence>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GeneratedFile {
    pub relative_path: PathBuf,
    pub content: String,
}

pub fn parse_date(text: &str) -> Result<Date, Error> {
    let bytes = text.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| i != 4 && i != 7 && !b.is_ascii_digit())
    {
        return Err("date must be an exact YYYY-MM-DD date".into());
    }
    let year = text[..4].parse::<i32>()?;
    if year == 0 {
        return Err("date must be an exact YYYY-MM-DD date".into());
    }
    Ok(Date::from_calendar_date(
        year,
        Month::try_from(text[5..7].parse::<u8>()?)?,
        text[8..].parse::<u8>()?,
    )?)
}

fn deserialize_date<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Date, D::Error> {
    let source = String::deserialize(d)?;
    manifest_date(source.trim()).map_err(serde::de::Error::custom)
}

fn manifest_date(source: &str) -> Result<Date, Error> {
    // Retain the compact calendar and ISO-week forms accepted by the original
    // manifest reader. The request command itself requires YYYY-MM-DD.
    if source.len() == 8 && source.bytes().all(|b| b.is_ascii_digit()) {
        return parse_date(&format!(
            "{}-{}-{}",
            &source[..4],
            &source[4..6],
            &source[6..]
        ));
    }
    let iso_week =
        Regex::new(r"^(?:([0-9]{4})-W([0-9]{2})(?:-([1-7]))?|([0-9]{4})W([0-9]{2})([1-7])?)$")?;
    if let Some(captures) = iso_week.captures(source) {
        let extended = captures.get(1).is_some();
        let year = captures
            .get(if extended { 1 } else { 4 })
            .ok_or("invalid manifest date")?
            .as_str();
        let week = captures
            .get(if extended { 2 } else { 5 })
            .ok_or("invalid manifest date")?
            .as_str();
        let weekday = captures
            .get(if extended { 3 } else { 6 })
            .map_or("1", |value| value.as_str());
        let year = year.parse::<i32>()?;
        if year == 0 {
            return Err("invalid manifest date".into());
        }
        let weekday = match weekday {
            "1" => Weekday::Monday,
            "2" => Weekday::Tuesday,
            "3" => Weekday::Wednesday,
            "4" => Weekday::Thursday,
            "5" => Weekday::Friday,
            "6" => Weekday::Saturday,
            "7" => Weekday::Sunday,
            _ => return Err("invalid manifest date".into()),
        };
        return Ok(Date::from_iso_week_date(year, week.parse()?, weekday)?);
    }
    parse_date(source)
}

fn patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let secrets = [
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
            r"\bgithub_pat_[A-Za-z0-9_]{16,}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bsgw_[A-Za-z0-9_-]{16,}\b",
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b",
            r"\b(?:sk|xox[baprs])-[A-Za-z0-9-]{16,}\b",
        ];
        let private = [
            r"(?i)\b(?:msg|ag|sy|rm|attn)-[0-9a-f]{32}\b",
            r"(?i)\b(?:coord(?:ination)?[\s_-]*)?(?:seq(?:uence)?)[\s:=#_-]*\d+\b",
            r"(?i)\b(?:sender_agent_id|origin_instance_id|mattermost_channel_id|adapter_id)\b",
            r"SAFEYOLO_COMPLETION_NOTES|DISPATCH_CANDIDATE|FACTORY_CANDIDATE",
            r"(?i)\b(?:chain[- ]of[- ]thought|private reasoning|raw reasoning|scratchpad)\b",
            r"(?:/Users/|/home/agent/|/app/agent_token)",
        ];
        secrets
            .into_iter()
            .map(|p| (p, "apparent credential or secret"))
            .chain(
                private
                    .into_iter()
                    .map(|p| (p, "private coordination or reasoning material")),
            )
            .map(|(p, message)| {
                (
                    Regex::new(p).expect("constant Dispatch hygiene pattern"),
                    message,
                )
            })
            .collect()
    })
}

pub fn validate_publication_text(text: &str) -> Result<(), Error> {
    for (pattern, message) in patterns() {
        if pattern.is_match(text) {
            return Err(format!("publication text contains {message}").into());
        }
    }
    Ok(())
}

fn text(value: &mut String, maximum: usize, multiline: bool) -> Result<(), Error> {
    *value = value.trim().to_owned();
    if value.is_empty() || value.len() > maximum {
        return Err(
            format!("public text must be non-empty and at most {maximum} UTF-8 bytes").into(),
        );
    }
    if value
        .chars()
        .any(|c| c < '\u{20}' && !(multiline && matches!(c, '\n' | '\t')))
    {
        return Err("public text contains disallowed controls".into());
    }
    validate_publication_text(value)
}

fn token(value: &mut String, pattern: &str, maximum: usize) -> Result<(), Error> {
    text(value, maximum, false)?;
    if !Regex::new(pattern)?.is_match(value) {
        return Err("invalid public token".into());
    }
    Ok(())
}

// The publication URL guard retains Python 3.12's is_global classification.
// It examines literal addresses only and performs no DNS or network requests.
fn ipv4_public(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    if matches!(value, 0xc0000009 | 0xc000000a) {
        return true;
    }
    ![
        (0x00000000, 8),
        (0x0a000000, 8),
        (0x64400000, 10),
        (0x7f000000, 8),
        (0xa9fe0000, 16),
        (0xac100000, 12),
        (0xc0000000, 24),
        (0xc0000200, 24),
        (0xc0a80000, 16),
        (0xc6120000, 15),
        (0xc6336400, 24),
        (0xcb007100, 24),
        (0xf0000000, 4),
    ]
    .iter()
    .any(|&(network, prefix)| value >> (32 - prefix) == network >> (32 - prefix))
}

pub fn validate_public_url(url: &str) -> Result<(String, String), Error> {
    let error = || -> Error { "URL must be public HTTPS without credentials or query data".into() };
    if url.is_empty()
        || url.len() > 512
        || url
            .chars()
            .any(|c| c.is_whitespace() || "<>()[]{}\\\"".contains(c))
    {
        return Err(error());
    }
    validate_publication_text(url)?;
    let (scheme, rest) = url.split_once("://").ok_or_else(error)?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    // Python's URL parser treats an empty trailing port as no port.
    let authority = rest[..authority_end]
        .strip_suffix(':')
        .unwrap_or(&rest[..authority_end]);
    if !scheme.eq_ignore_ascii_case("https")
        || authority.contains(['@', ':'])
        || rest
            .split('#')
            .next()
            .and_then(|s| s.split_once('?'))
            .is_some_and(|(_, query)| !query.is_empty())
    {
        return Err(error());
    }
    let host = crate::host_names::encode_idna2003(authority)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let public = match host.parse::<Ipv4Addr>() {
        Ok(ip) => ipv4_public(ip),
        Err(_) => {
            let labels: Vec<_> = host.split('.').collect();
            labels.len() >= 2
                && !(host.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && host
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() || matches!(c, b'x' | b'X' | b'.')))
                && labels.iter().all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
                && ![
                    ".internal",
                    ".local",
                    ".localhost",
                    ".localdomain",
                    ".test",
                    ".invalid",
                    ".lan",
                    ".home",
                    ".home.arpa",
                    ".corp",
                    ".intranet",
                    ".private",
                ]
                .iter()
                .any(|suffix| host.ends_with(suffix))
        }
    };
    if !public {
        return Err(error());
    }
    let path = rest[authority_end..]
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    Ok((host, path.to_owned()))
}

fn evidence(items: &mut [Evidence]) -> Result<(), Error> {
    if items.is_empty() || items.len() > 12 {
        return Err("evidence must cite 1 through 12 public sources".into());
    }
    let mut seen = BTreeSet::new();
    for item in items {
        if !["issue", "pr", "commit", "document", "test", "runtime"].contains(&item.kind.as_str()) {
            return Err("invalid public evidence kind".into());
        }
        text(&mut item.label, 256, false)?;
        text(&mut item.url, 512, false)?;
        let (host, path) = validate_public_url(&item.url)?;
        let suffix = match item.kind.as_str() {
            "issue" => Some(r"issues/\d+/?"),
            "pr" => Some(r"pull/\d+/?"),
            "commit" => Some(r"commit/[0-9a-f]{40}/?"),
            "document" | "test" => Some(r"blob/[^/]+/.+"),
            _ => None,
        };
        if host == "github.com"
            && let Some(suffix) = suffix
            && !Regex::new(&format!(r"^/[^/]+/[^/]+/{suffix}$"))?.is_match(&path)
        {
            return Err("evidence kind does not match its GitHub URL".into());
        }
        if !seen.insert(item.url.clone()) {
            return Err("duplicate public sources".into());
        }
    }
    Ok(())
}

fn check_numbers(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(number) => {
            let raw = number.to_string();
            if raw.bytes().all(|b| b.is_ascii_digit() || b == b'-') && raw.len() > 12 {
                return Err("dispatch source integer is unreasonably large".into());
            }
        }
        Value::Array(values) => {
            for value in values {
                check_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                check_numbers(value)?;
            }
        }
        _ => (),
    }
    Ok(())
}

pub fn parse_manifest(source: &str) -> Result<Manifest, Error> {
    if source.len() > MAX_MANIFEST_BYTES {
        return Err("dispatch source exceeds 262144 bytes".into());
    }
    let value = crate::policy::parse_json(source, true)?;
    check_numbers(&value)?;
    let mut manifest: Manifest = serde_json::from_value(value)?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn read_regular(path: &Path, bound: usize) -> Result<String, Error> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("source must be a regular non-symlink file".into());
    }
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err("publication file exceeds its size bound".into());
    }
    Ok(String::from_utf8(bytes)?)
}

pub fn load_manifest(path: &Path) -> Result<Manifest, Error> {
    parse_manifest(&read_regular(path, MAX_MANIFEST_BYTES)?)
}

impl Period {
    fn validate(&self) -> Result<(), Error> {
        let valid = match self.kind.as_str() {
            "daily" => self.start == self.end,
            "weekly" => {
                self.start.weekday() == Weekday::Monday
                    && self.start.checked_add(Duration::days(6)) == Some(self.end)
            }
            "monthly" => {
                self.start.day() == 1
                    && self.start.year() == self.end.year()
                    && self.start.month() == self.end.month()
                    && self
                        .end
                        .next_day()
                        .is_none_or(|day| day.month() != self.start.month())
            }
            _ => false,
        };
        if !valid {
            return Err("invalid Dispatch period boundaries".into());
        }
        Ok(())
    }
    pub fn relative_path(&self) -> PathBuf {
        match self.kind.as_str() {
            "daily" => PathBuf::from(format!("dispatch/{}.md", self.start)),
            "weekly" => {
                let (year, week, _) = self.start.to_iso_week_date();
                PathBuf::from(format!("snapshots/{year}-W{week:02}.md"))
            }
            _ => PathBuf::from(format!(
                "snapshots/{:04}-{:02}.md",
                self.start.year(),
                u8::from(self.start.month())
            )),
        }
    }
    fn heading(&self) -> String {
        match self.kind.as_str() {
            "daily" => format!(
                "{} {}, {}",
                self.start.month(),
                self.start.day(),
                self.start.year()
            ),
            "weekly" => {
                let (year, week, _) = self.start.to_iso_week_date();
                format!("{year}-W{week:02}")
            }
            _ => format!("{} {}", self.start.month(), self.start.year()),
        }
    }
}

impl Item {
    fn texts(&self) -> Vec<&str> {
        let mut texts = vec![self.title.as_str(), self.body.as_str()];
        texts.extend(self.evidence.iter().map(|e| e.label.as_str()));
        texts.extend(self.theme.as_deref());
        texts.extend(self.lesson.as_deref());
        texts.extend(self.snippet.as_ref().map(|s| s.code.as_str()));
        texts
    }
    fn validate(&mut self, kind: &str) -> Result<(), Error> {
        text(&mut self.title, 256, false)?;
        text(&mut self.body, 4096, false)?;
        if !ATTRIBUTIONS
            .iter()
            .any(|(name, _)| *name == self.attribution)
        {
            return Err("invalid public attribution".into());
        }
        if let Some(theme) = &mut self.theme {
            text(theme, 256, false)?;
        }
        if let Some(lesson) = &mut self.lesson {
            text(lesson, 4096, false)?;
        }
        if let Some(snippet) = &mut self.snippet {
            token(&mut snippet.language, r"^[a-z0-9_+-]{1,32}$", 32)?;
            text(&mut snippet.code, 8192, true)?;
        }
        match kind {
            "shipped"
                if self.theme.is_none() || self.snippet.is_some() || self.lesson.is_some() =>
            {
                return Err("Shipped requires a theme and cannot contain a review example".into());
            }
            "lens_caught"
                if self.attribution != "lens_review_finding"
                    || self.snippet.is_none()
                    || self.lesson.is_none()
                    || self.theme.is_some() =>
            {
                return Err(
                    "Lens review requires review attribution, snippet and lesson without a theme"
                        .into(),
                );
            }
            "worth_knowing" | "factory_pulse"
                if self.theme.is_some() || self.snippet.is_some() || self.lesson.is_some() =>
            {
                return Err("section contains unused fields".into());
            }
            _ => (),
        }
        evidence(&mut self.evidence)
    }
}

impl Topic {
    fn texts(&self) -> Vec<&str> {
        let mut texts = vec![self.title.as_str(), self.summary.as_str()];
        texts.extend(self.current_state.iter().map(String::as_str));
        texts.extend(self.evidence.iter().map(|e| e.label.as_str()));
        texts
    }
}

impl Manifest {
    fn validate(&mut self) -> Result<(), Error> {
        if self.version != 1 {
            return Err("dispatch source version must be 1".into());
        }
        self.period.validate()?;
        if self.sections.len() > 4 || self.topic_updates.len() > 16 {
            return Err("too many Dispatch sections or topic updates".into());
        }
        let mut previous = None;
        for section in &mut self.sections {
            let index = SECTIONS
                .iter()
                .position(|kind| *kind == section.kind)
                .ok_or("invalid Dispatch section kind")?;
            if previous.is_some_and(|p| index <= p) {
                return Err("sections must be unique and in editorial order".into());
            }
            previous = Some(index);
            if section.items.is_empty() || section.items.len() > 32 {
                return Err("section must contain 1 through 32 items; omit empty sections".into());
            }
            for item in &mut section.items {
                item.validate(&section.kind)?;
            }
        }
        let mut slugs = BTreeSet::new();
        for topic in &mut self.topic_updates {
            token(&mut topic.slug, r"^[a-z][a-z0-9_-]{0,63}$", 64)?;
            token(&mut topic.state_key, r"^[a-z][a-z0-9_.:-]{0,127}$", 128)?;
            text(&mut topic.title, 256, false)?;
            text(&mut topic.summary, 4096, false)?;
            if topic.current_state.is_empty() || topic.current_state.len() > 24 {
                return Err("topic current state must contain 1 through 24 items".into());
            }
            for state in &mut topic.current_state {
                text(state, 4096, false)?;
            }
            evidence(&mut topic.evidence)?;
            if !slugs.insert(&topic.slug) {
                return Err("duplicate topic slugs".into());
            }
        }
        let mut definitions = BTreeMap::new();
        for (term, explanation) in &mut self.definitions {
            let mut normalized = term.clone();
            token(&mut normalized, r"^[A-Za-z][A-Za-z0-9_.:+/-]{0,63}$", 64)?;
            text(explanation, 512, false)?;
            definitions.insert(normalized, explanation.clone());
        }
        self.definitions = definitions;
        let mut texts: Vec<_> = self
            .sections
            .iter()
            .flat_map(|s| s.items.iter().flat_map(Item::texts))
            .collect();
        texts.extend(self.topic_updates.iter().flat_map(Topic::texts));
        if used_definitions(&texts, &self.definitions)?.len() != self.definitions.len() {
            return Err("unused public definitions would add filler".into());
        }
        texts.extend(self.definitions.values().map(String::as_str));
        let authored_link = Regex::new(
            r"(?i)(?:\b(?:https?|mailto):|\bwww\.|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)",
        )?;
        if texts.iter().any(|text| authored_link.is_match(text)) {
            return Err(
                "Relay-authored text cannot contain links; use validated public evidence".into(),
            );
        }
        Ok(())
    }
}

fn markdown(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        if c == '&' {
            result.push_str("&amp;");
            continue;
        }
        if "\\`*_[]<>#|~".contains(c) {
            result.push('\\');
        }
        result.push(c);
    }
    if Regex::new(r"^(?:[-+=]|\d+[.)])\s")
        .expect("constant Markdown pattern")
        .is_match(&result)
    {
        result.insert(0, '\\');
    }
    result
}

fn evidence_markdown(items: &[Evidence]) -> String {
    items
        .iter()
        .map(|item| {
            format!(
                "[{}]({})",
                markdown(&item.label).replace("\\#", "#"),
                item.url
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn used_definitions<'a>(
    texts: &[&str],
    definitions: &'a BTreeMap<String, String>,
) -> Result<Vec<(&'a str, &'a str)>, Error> {
    let mut texts = texts.to_vec();
    let mut used = BTreeSet::new();
    loop {
        let mut changed = false;
        for (term, explanation) in definitions {
            if used.contains(term.as_str()) {
                continue;
            }
            // Include separators outside the match to preserve whole-word
            // behavior for terms that themselves contain punctuation.
            let pattern = Regex::new(&format!(
                r"(?i)(?:^|[^\w]){}(?:$|[^\w])",
                regex::escape(term)
            ))?;
            if texts.iter().any(|text| pattern.is_match(text)) {
                used.insert(term.as_str());
                texts.push(explanation);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(definitions
        .iter()
        .filter(|(term, _)| used.contains(term.as_str()))
        .map(|(term, explanation)| (term.as_str(), explanation.as_str()))
        .collect())
}

fn render_definitions(
    texts: &[&str],
    definitions: &BTreeMap<String, String>,
) -> Result<String, Error> {
    let used = used_definitions(texts, definitions)?;
    if used.is_empty() {
        return Ok(String::new());
    }
    let mut result = "**SafeYolo terms used here:**\n".to_owned();
    for (term, explanation) in used {
        result.push_str(&format!("- `{term}` — {}\n", markdown(explanation)));
    }
    result.push('\n');
    Ok(result)
}

fn render_item(item: &Item, level: usize) -> Result<String, Error> {
    let attribution = ATTRIBUTIONS
        .iter()
        .find(|(name, _)| *name == item.attribution)
        .ok_or("invalid public attribution")?
        .1;
    let mut result = format!(
        "{} {}\n\n**Attribution:** {attribution}\n\n",
        "#".repeat(level),
        markdown(&item.title)
    );
    if let Some(snippet) = &item.snippet {
        let longest = snippet
            .code
            .split(|c| c != '`')
            .map(str::len)
            .max()
            .unwrap_or(0);
        let fence = "`".repeat(3.max(longest + 1));
        result.push_str(&format!(
            "{fence}{}\n{}\n{fence}\n\n",
            snippet.language, snippet.code
        ));
    }
    result.push_str(&format!("{}\n\n", markdown(&item.body)));
    if let Some(lesson) = &item.lesson {
        result.push_str(&format!("**Lesson:** {}\n\n", markdown(lesson)));
    }
    result.push_str(&format!(
        "**Evidence:** {}\n\n",
        evidence_markdown(&item.evidence)
    ));
    Ok(result)
}

fn generated(path: PathBuf, content: String) -> Result<GeneratedFile, Error> {
    // Jekyll evaluates Liquid before Markdown, including code fences. Emit
    // opening delimiters from literal expressions so authored tags are never
    // parsed. The order keeps newly inserted expressions from being escaped.
    let content = format!("{}\n", content.trim_end())
        .replace("{{", "{{ '{{' }}")
        .replace("{%", "{{ '{%' }}");
    if content.len() > MAX_OUTPUT_BYTES {
        return Err("rendered Dispatch exceeds the output bound".into());
    }
    validate_publication_text(&content)?;
    Ok(GeneratedFile {
        relative_path: path,
        content,
    })
}

pub fn generate_files(manifest: &Manifest) -> Result<Vec<GeneratedFile>, Error> {
    let mut files = Vec::new();
    if !manifest.sections.is_empty() {
        let period = &manifest.period;
        let path = period.relative_path();
        let texts: Vec<_> = manifest
            .sections
            .iter()
            .flat_map(|s| s.items.iter().flat_map(Item::texts))
            .collect();
        let mut result = format!(
            "---\nlayout: default\ndispatch_schema: safeyolo.dispatch/v1\nperiod: {}\nstart: {}\nend: {}\neditor: Relay\npermalink: /{}/\n---\n\n# SafeYolo Dispatch — {}\n\n_Relay, SafeYolo's coordinator and editor, selected and synthesized this material from linked public evidence. Worker notes were treated as nominations, not publication copy._\n\n",
            period.kind,
            period.start,
            period.end,
            path.with_extension("").display(),
            period.heading()
        );
        result.push_str(&render_definitions(&texts, &manifest.definitions)?);
        for section in &manifest.sections {
            let heading = match section.kind.as_str() {
                "shipped" => "Shipped",
                "lens_caught" => "Lens caught this",
                "worth_knowing" => "Worth knowing",
                _ => "Factory pulse",
            };
            result.push_str(&format!("## {heading}\n\n"));
            if section.kind == "shipped" {
                let mut themes: Vec<(&str, Vec<&Item>)> = Vec::new();
                for item in &section.items {
                    let theme = item.theme.as_deref().ok_or("Shipped theme is missing")?;
                    if let Some((_, items)) = themes.iter_mut().find(|(name, _)| *name == theme) {
                        items.push(item);
                    } else {
                        themes.push((theme, vec![item]));
                    }
                }
                for (theme, items) in themes {
                    result.push_str(&format!("### {}\n\n", markdown(theme)));
                    for item in items {
                        result.push_str(&render_item(item, 4)?);
                    }
                }
            } else {
                for item in &section.items {
                    result.push_str(&render_item(item, 3)?);
                }
            }
        }
        files.push(generated(path, result)?);
    }
    for topic in &manifest.topic_updates {
        let end = manifest.period.end;
        let mut result = format!(
            "---\nlayout: default\ndispatch_schema: safeyolo.dispatch-topic/v1\ntopic: {}\nupdated_through: {end}\neditor: Relay\npermalink: /topics/{}/\n---\n\n<!-- safeyolo-topic-state: {} -->\n# {}\n\n_Last materially updated through {end}. Relay editorial synthesis._\n\n",
            topic.slug,
            topic.slug,
            topic.state_key,
            markdown(&topic.title)
        );
        result.push_str(&render_definitions(&topic.texts(), &manifest.definitions)?);
        result.push_str(&format!(
            "{}\n\n## Current state\n\n",
            markdown(&topic.summary)
        ));
        for state in &topic.current_state {
            result.push_str(&format!("- {}\n", markdown(state)));
        }
        result.push_str("\n## Public evidence\n\n");
        for item in &topic.evidence {
            result.push_str(&format!(
                "- {}\n",
                evidence_markdown(std::slice::from_ref(item))
            ));
        }
        files.push(generated(
            PathBuf::from(format!("topics/{}.md", topic.slug)),
            result,
        )?);
    }
    Ok(files)
}

fn validate_output_path(path: &Path) -> Result<(), Error> {
    let parts: Vec<_> = path.components().collect();
    if parts.len() != 2
        || !matches!(parts[0], Component::Normal(_))
        || !matches!(parts[1], Component::Normal(_))
        || !["dispatch", "snapshots", "topics"]
            .iter()
            .any(|root| parts[0].as_os_str() == *root)
        || path.extension().is_none_or(|ext| ext != "md")
    {
        return Err("generated output path is outside the publication tree".into());
    }
    Ok(())
}

pub fn write_generated_files(
    output_root: &Path,
    files: &[GeneratedFile],
    check: bool,
) -> Result<Vec<PathBuf>, Error> {
    let mut seen = BTreeSet::new();
    for file in files {
        validate_output_path(&file.relative_path)?;
        if !seen.insert(&file.relative_path) || file.content.len() > MAX_OUTPUT_BYTES {
            return Err("duplicate or oversized generated output".into());
        }
    }
    if files.is_empty() {
        return Ok(Vec::new());
    }
    if fs::symlink_metadata(output_root).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("output root cannot be a symlink".into());
    }
    if !output_root.exists() && !check {
        fs::create_dir_all(output_root)?;
    }
    let root = fs::canonicalize(output_root)
        .map_err(|_| "generated output root or directory is missing")?;
    if !root.is_dir() {
        return Err("output root must be a real directory".into());
    }
    let mut changed = Vec::new();
    for file in files {
        let parent = root.join(file.relative_path.parent().ok_or("output parent missing")?);
        if !parent.exists() && !check {
            fs::create_dir(&parent)?;
        }
        let parent = fs::canonicalize(&parent)
            .map_err(|_| "generated output root or directory is missing")?;
        if !parent.starts_with(&root) || !parent.is_dir() {
            return Err("generated output escapes through a symlink".into());
        }
        let target = parent.join(
            file.relative_path
                .file_name()
                .ok_or("output name missing")?,
        );
        let existing = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() => Some(read_regular(&target, MAX_OUTPUT_BYTES)?),
            Ok(_) => return Err("generated output must be a regular non-symlink file".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if existing.as_deref() == Some(file.content.as_str()) {
            continue;
        }
        if check {
            return Err(format!(
                "generated output is missing or stale: {}",
                file.relative_path.display()
            )
            .into());
        }
        crate::coord_supervisor::atomic_write(&target, file.content.as_bytes(), 0o644)?;
        changed.push(file.relative_path.clone());
    }
    Ok(changed)
}

pub const HELP: &str = "safeyolo dispatch generate SOURCE [--output-root SITE] [--check]\nsafeyolo dispatch check-site [--site-root SITE] [--publication-base REVISION]\n\nGenerate deterministic Markdown from a nonsecret manifest. --check fails without writing when output is missing or stale. check-site verifies retained sources, bytes, metadata, links and publication hygiene. These commands do not publish or install a schedule.";

pub fn run(arguments: &[String]) -> Result<(), Error> {
    if arguments.is_empty() || arguments.iter().any(|a| a == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    match arguments[0].as_str() {
        "generate" => {
            let source = arguments
                .get(1)
                .filter(|a| !a.starts_with('-'))
                .ok_or("a source manifest is required")?;
            let mut root = PathBuf::from("site");
            let mut check = false;
            let mut args = arguments[2..].iter();
            let mut seen = BTreeSet::new();
            while let Some(arg) = args.next() {
                if !seen.insert(arg) {
                    return Err(format!("duplicate {arg} option").into());
                }
                match arg.as_str() {
                    "--output-root" => {
                        root = PathBuf::from(args.next().ok_or("--output-root requires a path")?)
                    }
                    "--check" => check = true,
                    _ => return Err(format!("unknown Dispatch generation option: {arg}").into()),
                }
            }
            let files = generate_files(&load_manifest(Path::new(source))?)?;
            let changed = write_generated_files(&root, &files, check)?;
            if files.is_empty() {
                println!("No substantive Dispatch or material topic update; wrote nothing.");
            } else if check {
                println!("Dispatch output is current ({} files).", files.len());
            } else if changed.is_empty() {
                println!("Dispatch output already current; wrote nothing.");
            } else {
                println!(
                    "Generated: {}",
                    changed
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Ok(())
        }
        "check-site" => site::run(&arguments[1..]),
        _ => Err("unknown Dispatch command; use dispatch --help".into()),
    }
}
