//! Content-pattern scanner, corresponding to detection/patterns.py and
//! mitm_addons/pattern_scanner.py. It inspects one complete message at a time.
//!
//! This is a native engine compatibility candidate. `compatibility_gaps()` is
//! deliberately nonempty: fancy-regex is not an exact Python `re` replacement.
//! Callers must resolve those gaps before production use. A compile incompatibility
//! retains the previous snapshot; it never silently removes an accepted rule.
//! Proved remaining examples include named Unicode escapes, uncovered Unicode
//! properties/casefold behavior, and parse nesting. Generated Python 3.12 /
//! Unicode 15 ranges pin `\w` and `\d` category membership. The pinned engine patch
//! removes the scanner's private stack cutoff: VM buffers grow fallibly and are
//! released after each scan. The complete-message regression matches at 1,000,100
//! bytes, 4 MiB and 8 MiB. Remaining gaps still block production acceptance.
//! Configurable backtracking and compiled-size cutoffs use usize::MAX without
//! eager capacity allocation.
//!
//! Python ASCII scopes and octal escapes are lowered before compilation. ASCII
//! mode changes categories/case folding while preserving Unicode scalar input.
//! The internal backreference flag is gated and authored Python-invalid A flags
//! are rejected. Unicode-insensitive literals/classes close Python's four-I set.
//! Backreferences use a separate opt-in scalar-lowercase instruction with pinned
//! Unicode 15 data; each subject scalar advances by its own UTF-8 byte width.
//! ASCII backreferences keep non-ASCII scalars exact. Comparisons allocate no
//! buffer and preserve per-call cancellation. Python 3.12's scoped-ASCII INFO
//! prefilter can miss a match that its own matching instructions accept. Native
//! inspection honors the configured rule in those proved cases; the oracle
//! records this intentional D41 correction.
//!
//! Callers supply mitmproxy-equivalent decoded HTTP text and ordered, combined
//! header values. HTTP charset/content-encoding and surrogate-escaped text still
//! require a transport adapter. A streamed body is absent, not a clean scan.
//! The scanner adds no HTTP body or WebSocket message size cap. URL inspection
//! alone has the shipped 16 KiB UTF-8 byte bound. The transport owns complete
//! message assembly/decompression, private spooling, identity and audit emission.
//! Per-call WS cancellation returns a distinct error and suppresses scan results.
//! VM loops cooperate; opaque delegated searches delay cancellation until return.
//! The caller checks its connection flag again before publishing any evidence.
//!
//! Request/response hooks in Python do not call should_bypass or short-circuit
//! prior responses. This module adds no policy bypass. WS errors drop the current
//! message, including in log mode; with no rules, decoding is bypassed entirely.
//! General HTTP matching errors return Error. The old HTTP hook propagates those
//! exceptions; only URL inspection failures have a shipped unconditional block.

use fancy_regex::{Regex, RegexBuilder, RegexInput};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    fmt,
    sync::{
        Arc, LazyLock, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

pub const MAX_URL_SCAN_BYTES: usize = 16 * 1024;

/// These remaining differences block production acceptance. They are not new
/// restrictions on accepted operator policy and must not be hidden by rule skips.
pub fn compatibility_gaps() -> &'static [&'static str] {
    &[
        "arbitrary_python_re_grammar_and_flags",
        "python_unicode_classes_casefold_and_unicode_version",
        "regex_compilation_expansion_and_backtracking_resources",
        "http_charset_content_encoding_and_surrogate_text_adapter",
    ]
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Cancelled,
    InvalidConfig,
    RegexCompatibility,
    RegexRuntime,
    StateUnavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Error {
    pub kind: ErrorKind,
    pub rule_index: Option<usize>,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pattern inspection {:?}", self.kind)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn check_cancelled(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(error(ErrorKind::Cancelled, None))
    } else {
        Ok(())
    }
}
fn error(kind: ErrorKind, index: Option<usize>) -> Error {
    Error {
        kind,
        rule_index: index,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
}
impl Direction {
    fn text(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Text,
    Binary,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub block_request: bool,
    pub block_response: bool,
    /// Some(false) is the registered production default. None represents older
    /// direct callers lacking this option and falls back to the HTTP mode.
    pub block_websocket_request: Option<bool>,
    pub block_websocket_response: Option<bool>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            block_request: false,
            block_response: false,
            block_websocket_request: Some(false),
            block_websocket_response: Some(false),
        }
    }
}
impl Options {
    fn http(self, direction: Direction) -> bool {
        match direction {
            Direction::Request => self.block_request,
            Direction::Response => self.block_response,
        }
    }
    fn websocket(self, direction: Direction) -> bool {
        match direction {
            Direction::Request => self.block_websocket_request,
            Direction::Response => self.block_websocket_response,
        }
        .unwrap_or(self.http(direction))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub direction: Direction,
    pub rule_name: String,
    pub rule_id: String,
    pub pattern_action: String,
    pub pattern_severity: String,
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_type: Option<MessageType>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    NoRules,
    NoMessage,
    NoMatch,
    MatchLogged,
    MatchBlocked,
    InspectionError,
}
/// Only bounded identities and categorical evidence are retained. No input,
/// compiled regex, match text, custom message, or underlying exception text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub outcome: Outcome,
    pub finding: Option<Finding>,
    pub drop_message: bool,
    pub status: Option<u16>,
    pub body: Option<Value>,
    pub metadata: Map<String, Value>,
    pub failure: Option<&'static str>,
    pub error_type: Option<&'static str>,
}
impl Decision {
    fn plain(outcome: Outcome) -> Self {
        Self {
            outcome,
            finding: None,
            drop_message: false,
            status: None,
            body: None,
            metadata: Map::new(),
            failure: None,
            error_type: None,
        }
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub rules_total: usize,
    pub scans_total: u64,
    pub matches_total: u64,
    pub blocks_total: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    MissingNameOrPattern,
    DangerousPattern,
    InvalidPattern,
    UnknownBuiltin,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedRule {
    pub index: usize,
    pub reason: SkipReason,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadReport {
    pub rules_total: usize,
    pub skipped: Vec<SkippedRule>,
    pub compatibility_gaps: Vec<&'static str>,
}
struct Rule {
    name: String,
    rule_id: String,
    pattern: Regex,
    target: String,
    scopes: Vec<String>,
    action: String,
    severity: String,
}
impl Rule {
    fn applies(&self, direction: Direction, scope: &str) -> bool {
        (self.target == "both" || self.target == direction.text())
            && self.scopes.iter().any(|value| value == scope)
    }
    fn finding(
        &self,
        direction: Direction,
        location: String,
        message_type: Option<MessageType>,
    ) -> Finding {
        Finding {
            direction,
            rule_name: self.name.clone(),
            rule_id: self.rule_id.clone(),
            pattern_action: self.action.clone(),
            pattern_severity: self.severity.clone(),
            location,
            message_type,
        }
    }
}
struct Snapshot {
    hash: Value,
    rules: Arc<Vec<Rule>>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            hash: json!(""),
            rules: Arc::new(Vec::new()),
        }
    }
}
#[derive(Clone, Default)]
pub struct Scanner {
    snapshot: Arc<RwLock<Snapshot>>,
    stats: Arc<Mutex<Stats>>,
}
impl fmt::Debug for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner").finish_non_exhaustive()
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Number(value) => value.as_f64() != Some(0.),
    }
}
fn python_value(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(python_repr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!("{}: {}", python_repr(&json!(key)), python_repr(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
fn python_repr(value: &Value) -> String {
    if let Value::String(value) = value {
        let quote = if value.contains('\'') && !value.contains('"') {
            '"'
        } else {
            '\''
        };
        let mut result = String::from(quote);
        for character in value.chars() {
            if character == quote || character == '\\' {
                result.push('\\');
                result.push(character)
            } else if matches!(character, '\n' | '\r' | '\t') {
                result.push_str(&character.escape_debug().to_string())
            } else if character.is_control()
                || character.escape_debug().to_string().starts_with("\\u{")
            {
                let code = character as u32;
                result.push_str(&if code <= 0xff {
                    format!("\\x{code:02x}")
                } else if code <= 0xffff {
                    format!("\\u{code:04x}")
                } else {
                    format!("\\U{code:08x}")
                });
            } else {
                result.push(character)
            }
        }
        result.push(quote);
        result
    } else {
        python_value(value)
    }
}
fn safe_value(value: &Value, max: usize, fallback: &str) -> String {
    static ANSI: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap());
    static SAFE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\A[\p{L}\p{N}\p{P}\p{S}\p{Zs}]\z").unwrap());
    if value.is_null() {
        return fallback.chars().take(max).collect();
    }
    let value = python_value(value)
        .replace("\r\n", "?")
        .replace(['\r', '\n'], "?");
    let value = ANSI.replace_all(&value, "?");
    let mut result = String::new();
    let mut previous_question = false;
    let mut count = 0;
    for ch in value.chars() {
        let mut bytes = [0; 4];
        let safe = (ch as u32) >= 0x20
            && !matches!(ch, '\u{7f}' | '\u{2028}' | '\u{2029}')
            && SAFE.is_match(ch.encode_utf8(&mut bytes));
        let ch = if safe { ch } else { '?' };
        if ch == '?' && previous_question {
            continue;
        }
        if count == max {
            break;
        }
        result.push(ch);
        count += 1;
        previous_question = ch == '?';
    }
    if result.is_empty() {
        fallback.chars().take(max).collect()
    } else {
        result
    }
}
fn safe_location(name: &str) -> String {
    format!("header:{}", safe_value(&json!(name), 64, "unknown"))
}

const PYTHON_SPACE: &str =
    r"[\t-\r\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]";

#[derive(Deserialize)]
struct PythonUnicodeCategories {
    word: Vec<[u32; 2]>,
    decimal: Vec<[u32; 2]>,
}

fn python_unicode_categories() -> &'static PythonUnicodeCategories {
    static DATA: LazyLock<PythonUnicodeCategories> = LazyLock::new(|| {
        serde_json::from_str(include_str!("../data/inspection/unicode.json"))
            .expect("validated Python 3.12 Unicode category tables")
    });
    &DATA
}

fn category_class(ranges: &[[u32; 2]]) -> String {
    let mut result = String::from("[");
    for [start, end] in ranges {
        result.push_str(&format!(r"\x{{{start:x}}}"));
        if start != end {
            result.push_str(&format!(r"-\x{{{end:x}}}"));
        }
    }
    result.push(']');
    result
}

fn python_word() -> &'static str {
    static WORD: LazyLock<String> =
        LazyLock::new(|| category_class(&python_unicode_categories().word));
    &WORD
}

fn python_decimal() -> &'static str {
    static DECIMAL: LazyLock<String> =
        LazyLock::new(|| category_class(&python_unicode_categories().decimal));
    &DECIMAL
}
pub(crate) enum PatternIssue {
    Invalid,
    Compatibility,
}

/// One Python-pattern adapter for the scanner and credential-header detector.
/// Callers classify invalid rules separately from engine compatibility gaps;
/// neither path exposes the operator's expression in diagnostic errors.
pub(crate) fn compile_python_pattern(
    pattern: &str,
    insensitive: bool,
) -> std::result::Result<Regex, PatternIssue> {
    let adapted = python_pattern(pattern, insensitive)?;
    compile_engine_pattern(&adapted, insensitive)
}
fn compile_engine_pattern(
    adapted: &str,
    insensitive: bool,
) -> std::result::Result<Regex, PatternIssue> {
    let mut builder = RegexBuilder::new(adapted);
    // These are failure cutoffs, not cache capacities. The old scanner does
    // not impose them; ordinary default DFA caching remains bounded. The local
    // patch makes VM growth fallible and releases unbounded buffers after use.
    builder
        .case_insensitive(insensitive)
        .allow_ascii_backref_flag(true)
        .python_backreferences(true)
        .backtrack_limit(usize::MAX)
        .stack_limit(None)
        .delegate_size_limit(usize::MAX);
    match builder.build() {
        Ok(regex) => Ok(regex),
        Err(fancy_regex::Error::ParseError(
            _,
            fancy_regex::ParseError::UnclosedOpenParen | fancy_regex::ParseError::TrailingBackslash,
        )) => Err(PatternIssue::Invalid),
        Err(_) => Err(PatternIssue::Compatibility),
    }
}
#[derive(Clone, Copy)]
struct PatternMode {
    ascii: bool,
    insensitive: bool,
    verbose: bool,
}
struct PatternGroup {
    mode: PatternMode,
    capture: Option<usize>,
    lookbehind_start: Option<usize>,
}
fn pattern_literal(value: char, mode: PatternMode) -> String {
    if mode.ascii && mode.insensitive {
        if value.is_ascii_alphabetic() {
            return format!(
                "(?-i:[{}{}])",
                value.to_ascii_lowercase(),
                value.to_ascii_uppercase()
            );
        }
        return format!(r"(?-i:\x{{{:x}}})", value as u32);
    }
    if mode.insensitive && matches!(value, 'I' | 'i' | 'İ' | 'ı') {
        return "(?-i:[Iiİı])".into();
    }
    format!(r"\x{{{:x}}}", value as u32)
}
fn octal_escape(
    chars: &[char],
    index: usize,
    class: bool,
) -> std::result::Result<Option<(char, usize)>, PatternIssue> {
    let first = chars[index + 1];
    if !first.is_ascii_digit() {
        return Ok(None);
    }
    let octal = |ch: char| matches!(ch, '0'..='7');
    let three_octal = chars
        .get(index + 1..index + 4)
        .is_some_and(|digits| digits.iter().copied().all(octal));
    if first == '0' || class || three_octal {
        if !octal(first) {
            return Err(PatternIssue::Invalid);
        }
        let mut end = index + 2;
        while end < (index + 4).min(chars.len()) && octal(chars[end]) {
            end += 1;
        }
        let value = chars[index + 1..end]
            .iter()
            .fold(0u32, |value, ch| value * 8 + (*ch as u32 - '0' as u32));
        if value > 0o377 {
            return Err(PatternIssue::Invalid);
        }
        return Ok(Some((char::from_u32(value).unwrap(), end)));
    }
    Ok(None)
}
fn hex_escape(chars: &[char], index: usize) -> std::result::Result<(char, usize), PatternIssue> {
    let width = match chars[index + 1] {
        'x' => 2,
        'u' => 4,
        'U' => 8,
        _ => unreachable!(),
    };
    let end = index + 2 + width;
    let digits = chars.get(index + 2..end).ok_or(PatternIssue::Invalid)?;
    if !digits.iter().all(char::is_ascii_hexdigit) {
        return Err(PatternIssue::Invalid);
    }
    let value = digits
        .iter()
        .fold(0u32, |value, ch| value * 16 + ch.to_digit(16).unwrap());
    if value > 0x10ffff {
        return Err(PatternIssue::Invalid);
    }
    let value = char::from_u32(value).ok_or(PatternIssue::Compatibility)?;
    Ok((value, end))
}
fn category(escape: char, ascii: bool) -> Option<String> {
    let positive = match escape.to_ascii_lowercase() {
        'w' => {
            if ascii {
                "[A-Za-z0-9_]"
            } else {
                python_word()
            }
        }
        's' => {
            if ascii {
                r"[\t-\r ]"
            } else {
                PYTHON_SPACE
            }
        }
        'd' => {
            if ascii {
                "[0-9]"
            } else {
                python_decimal()
            }
        }
        _ => return None,
    };
    Some(if escape.is_ascii_uppercase() {
        format!("[^{}]", &positive[1..positive.len() - 1])
    } else {
        positive.into()
    })
}
fn ascii_case_class(class: &str) -> std::result::Result<String, PatternIssue> {
    // ASCII case folding closes only A-Z/a-z pairs. Determine membership with
    // the same compiled engine over this already lowered single character class.
    // No second subject matcher or runtime representation is introduced.
    let negative = class.starts_with("[^");
    let positive = if negative {
        format!("[{}", &class[2..])
    } else {
        class.into()
    };
    let expression = compile_engine_pattern(&positive, false)?;
    let mut additions = String::new();
    for lower in b'a'..=b'z' {
        let upper = lower.to_ascii_uppercase();
        let lower_text = char::from(lower).to_string();
        let upper_text = char::from(upper).to_string();
        if expression
            .is_match(&lower_text)
            .map_err(|_| PatternIssue::Compatibility)?
            || expression
                .is_match(&upper_text)
                .map_err(|_| PatternIssue::Compatibility)?
        {
            additions.push(char::from(lower));
            additions.push(char::from(upper));
        }
    }
    Ok(format!(
        "(?-i:[{}{}{}])",
        if negative { "^" } else { "" },
        positive,
        additions
    ))
}
fn unicode_i_class(class: &str) -> std::result::Result<String, PatternIssue> {
    // Close Python's four-I equivalence before complementing a negative class.
    // Reuse the existing engine for membership in the lowered positive class.
    let negative = class.starts_with("[^");
    let positive = if negative {
        format!("[{}", &class[2..])
    } else {
        class.into()
    };
    let expression = compile_engine_pattern(&positive, false)?;
    for text in ["I", "i", "İ", "ı"] {
        if expression
            .is_match(text)
            .map_err(|_| PatternIssue::Compatibility)?
        {
            return Ok(format!(
                "[{}{}Iiİı]",
                if negative { "^" } else { "" },
                positive
            ));
        }
    }
    Ok(class.into())
}

fn python_pattern(pattern: &str, insensitive: bool) -> std::result::Result<String, PatternIssue> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut result = String::new();
    let mut index = 0;
    let mut mode = PatternMode {
        ascii: false,
        insensitive,
        verbose: false,
    };
    let mut groups: Vec<PatternGroup> = Vec::new();
    let mut captures = vec![false];
    let mut names: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut lookbehind_start = None;
    let mut at_start = true;
    let mut global_ascii = false;
    let mut global_unicode = false;
    while index < chars.len() {
        let ch = chars[index];
        if mode.verbose && matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') {
            index += 1;
            continue;
        }
        if mode.verbose && ch == '#' {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == '[' {
            let mut class = String::from("[");
            index += 1;
            if chars.get(index) == Some(&'^') {
                class.push('^');
                index += 1;
            }
            if chars.get(index) == Some(&']') {
                class.push_str(r"\]");
                index += 1;
            }
            while index < chars.len() && chars[index] != ']' {
                let ch = chars[index];
                if ch == '\\' {
                    let escape = *chars.get(index + 1).ok_or(PatternIssue::Invalid)?;
                    if let Some((value, end)) = octal_escape(&chars, index, true)? {
                        class.push_str(&format!(r"\x{{{:x}}}", value as u32));
                        index = end;
                        continue;
                    }
                    if matches!(escape, 'x' | 'u' | 'U') {
                        let (value, end) = hex_escape(&chars, index)?;
                        class.push_str(&format!(r"\x{{{:x}}}", value as u32));
                        index = end;
                        continue;
                    }
                    if escape == 'N' {
                        return Err(PatternIssue::Compatibility);
                    }
                    if let Some(value) = category(escape, mode.ascii) {
                        class.push_str(&value);
                    } else if escape == 'b' {
                        class.push_str(r"\x08");
                    } else if escape.is_ascii_alphabetic() && !"afnrtv".contains(escape) {
                        return Err(PatternIssue::Invalid);
                    } else {
                        class.push('\\');
                        class.push(escape);
                    }
                    index += 2;
                    continue;
                }
                if matches!(ch, '[' | '&' | '~') {
                    class.push('\\');
                }
                class.push(ch);
                index += 1;
            }
            if index == chars.len() {
                return Err(PatternIssue::Invalid);
            }
            class.push(']');
            index += 1;
            if mode.ascii && mode.insensitive {
                result.push_str(&ascii_case_class(&class)?);
            } else if mode.insensitive {
                result.push_str(&unicode_i_class(&class)?);
            } else {
                result.push_str(&class);
            }
            at_start = false;
            continue;
        }
        if ch == '\\' {
            let escape = *chars.get(index + 1).ok_or(PatternIssue::Invalid)?;
            if let Some((value, end)) = octal_escape(&chars, index, false)? {
                result.push_str(&pattern_literal(value, mode));
                index = end;
                at_start = false;
                continue;
            }
            if matches!(escape, 'x' | 'u' | 'U') {
                let (value, end) = hex_escape(&chars, index)?;
                result.push_str(&pattern_literal(value, mode));
                index = end;
                at_start = false;
                continue;
            }
            if escape.is_ascii_digit() {
                let end = if chars.get(index + 2).is_some_and(char::is_ascii_digit) {
                    index + 3
                } else {
                    index + 2
                };
                let group = chars[index + 1..end].iter().fold(0usize, |value, ch| {
                    value * 10 + (*ch as usize - '0' as usize)
                });
                if !captures.get(group).copied().unwrap_or(false)
                    || lookbehind_start.is_some_and(|first| group >= first)
                {
                    return Err(PatternIssue::Invalid);
                }
                if mode.ascii && mode.insensitive {
                    result.push_str(&format!(r"(?A:\k<{group}>)"));
                } else {
                    result.push_str(&format!(r"\k<{group}>"));
                }
                index = end;
                at_start = false;
                continue;
            }
            if escape == 'N' {
                return Err(PatternIssue::Compatibility);
            }
            if let Some(value) = category(escape, mode.ascii) {
                if mode.ascii {
                    result.push_str(&format!("(?-i:{value})"));
                } else {
                    result.push_str(&value);
                }
            } else {
                match escape {
                    'Z' => result.push_str(r"\z"),
                    'b' | 'B' => {
                        let word = if mode.ascii {
                            "(?-i:[A-Za-z0-9_])"
                        } else {
                            python_word()
                        };
                        if escape == 'b' {
                            result.push_str(&format!(
                                "(?:(?<!{word})(?={word})|(?<={word})(?!{word}))"
                            ));
                        } else {
                            result.push_str(&format!("(?:(?<={word})(?={word})|(?<!{word})(?!{word})(?:(?=[\\s\\S])|(?<=[\\s\\S])))"));
                        }
                    }
                    'A' | 'a' | 'f' | 'n' | 'r' | 't' | 'v' => {
                        result.push('\\');
                        result.push(escape);
                    }
                    _ if escape.is_ascii_alphabetic() => return Err(PatternIssue::Invalid),
                    _ => result.push_str(&pattern_literal(escape, mode)),
                }
            }
            index += 2;
            at_start = false;
            continue;
        }
        if ch == '(' {
            if chars.get(index + 1..index + 3) == Some(&['?', '#']) {
                let mut end = index + 3;
                while end < chars.len() && chars[end] != ')' {
                    if chars[end] == '\\' {
                        end += 1;
                    }
                    end += 1;
                }
                if end >= chars.len() {
                    return Err(PatternIssue::Invalid);
                }
                index = end + 1;
                continue;
            }
            if chars.get(index + 1) == Some(&'?') {
                let mut end = index + 2;
                let mut positive = String::new();
                let mut negative = String::new();
                let mut minus = false;
                while let Some(&flag) = chars.get(end) {
                    if flag == '-' && !minus {
                        minus = true;
                        end += 1;
                        continue;
                    }
                    if !"aiLmsux".contains(flag) {
                        break;
                    }
                    if minus {
                        negative.push(flag);
                    } else {
                        positive.push(flag);
                    }
                    end += 1;
                }
                if end > index + 2 && matches!(chars.get(end), Some(':' | ')')) {
                    if positive.contains('L')
                        || positive.contains('a') && positive.contains('u')
                        || minus && negative.is_empty()
                        || negative
                            .chars()
                            .any(|f| !"imsx".contains(f) || positive.contains(f))
                    {
                        return Err(PatternIssue::Invalid);
                    }
                    let scoped = chars[end] == ':';
                    if !scoped && (!at_start || !groups.is_empty() || minus) {
                        return Err(PatternIssue::Invalid);
                    }
                    let mut changed = mode;
                    if positive.contains('a') {
                        changed.ascii = true;
                    }
                    if positive.contains('u') {
                        changed.ascii = false;
                    }
                    if positive.contains('i') {
                        changed.insensitive = true;
                    }
                    if negative.contains('i') {
                        changed.insensitive = false;
                    }
                    if positive.contains('x') {
                        changed.verbose = true;
                    }
                    if negative.contains('x') {
                        changed.verbose = false;
                    }
                    if scoped {
                        groups.push(PatternGroup {
                            mode,
                            capture: None,
                            lookbehind_start,
                        });
                    } else {
                        global_ascii |= positive.contains('a');
                        global_unicode |= positive.contains('u');
                        // Python raises ValueError (not re.error) for contradictory global type flags.
                        if global_ascii && global_unicode {
                            return Err(PatternIssue::Compatibility);
                        }
                    }
                    let flags: String = positive
                        .chars()
                        .filter(|flag| !matches!(flag, 'a' | 'u'))
                        .collect();
                    if scoped || !flags.is_empty() {
                        result.push_str("(?");
                        result.push_str(&flags);
                        if minus {
                            result.push('-');
                            result.push_str(&negative);
                        }
                        result.push(if scoped { ':' } else { ')' });
                    }
                    mode = changed;
                    index = end + 1;
                    continue;
                }
                if chars.get(index + 1..index + 4) == Some(&['?', 'P', '=']) {
                    let end = (index + 4..chars.len())
                        .find(|&i| chars[i] == ')')
                        .ok_or(PatternIssue::Invalid)?;
                    let name: String = chars[index + 4..end].iter().collect();
                    let group = *names.get(&name).ok_or(PatternIssue::Invalid)?;
                    if !captures[group] || lookbehind_start.is_some_and(|first| group >= first) {
                        return Err(PatternIssue::Invalid);
                    }
                    if mode.ascii && mode.insensitive {
                        result.push_str(&format!(r"(?A:\k<{group}>)"));
                    } else {
                        result.extend(&chars[index..=end]);
                    }
                    index = end + 1;
                    at_start = false;
                    continue;
                }
                if chars.get(index + 1..index + 4) == Some(&['?', 'P', '<']) {
                    let end = (index + 4..chars.len())
                        .find(|&i| chars[i] == '>')
                        .ok_or(PatternIssue::Invalid)?;
                    let name: String = chars[index + 4..end].iter().collect();
                    if names.insert(name, captures.len()).is_some() {
                        return Err(PatternIssue::Invalid);
                    }
                    groups.push(PatternGroup {
                        mode,
                        capture: Some(captures.len()),
                        lookbehind_start,
                    });
                    captures.push(false);
                    result.extend(&chars[index..=end]);
                    index = end + 1;
                    at_start = false;
                    continue;
                }
                if chars.get(index + 1..index + 3) == Some(&['?', '(']) {
                    let end = (index + 3..chars.len())
                        .find(|&i| chars[i] == ')')
                        .ok_or(PatternIssue::Invalid)?;
                    groups.push(PatternGroup {
                        mode,
                        capture: None,
                        lookbehind_start,
                    });
                    result.extend(&chars[index..=end]);
                    index = end + 1;
                    at_start = false;
                    continue;
                }
                let width = if matches!(chars.get(index + 2), Some(':' | '=' | '!' | '>')) {
                    3
                } else if chars.get(index + 2) == Some(&'<')
                    && matches!(chars.get(index + 3), Some('=' | '!'))
                {
                    4
                } else {
                    return Err(PatternIssue::Invalid);
                };
                groups.push(PatternGroup {
                    mode,
                    capture: None,
                    lookbehind_start,
                });
                if width == 4 && lookbehind_start.is_none() {
                    lookbehind_start = Some(captures.len());
                }
                result.extend(&chars[index..index + width]);
                index += width;
                at_start = false;
                continue;
            }
            groups.push(PatternGroup {
                mode,
                capture: Some(captures.len()),
                lookbehind_start,
            });
            captures.push(false);
        } else if ch == ')' {
            let group = groups.pop().ok_or(PatternIssue::Invalid)?;
            if let Some(capture) = group.capture {
                captures[capture] = true;
            }
            mode = group.mode;
            lookbehind_start = group.lookbehind_start;
        }
        if ch == '$' {
            result.push_str(r"(?:(?=\n\z)|$)");
        } else if mode.insensitive
            && (matches!(ch, 'I' | 'i' | 'İ' | 'ı')
                || mode.ascii && (ch.is_ascii_alphabetic() || !ch.is_ascii()))
            || mode.verbose && ch.is_whitespace()
        {
            result.push_str(&pattern_literal(ch, mode));
        } else {
            result.push(ch);
        }
        index += 1;
        at_start = false;
    }
    if !groups.is_empty() {
        return Err(PatternIssue::Invalid);
    }
    Ok(result)
}

fn compile_rules(sensor: &Value) -> Result<(Vec<Rule>, LoadReport)> {
    if !sensor.is_object()
        || sensor
            .get("addons")
            .is_some_and(|addons| !addons.is_object())
    {
        return Err(error(ErrorKind::InvalidConfig, None));
    }
    let mut configs = Vec::new();
    let mut skipped = Vec::new();
    let builtins: Value = serde_json::from_str(BUILTINS).expect("fixed source catalogue");
    if let Some(section) = sensor.pointer("/addons/pattern_scanner") {
        if !section.is_object() {
            return Err(error(ErrorKind::InvalidConfig, None));
        }
        if let Some(sets) = section.get("builtin_sets") {
            let sets = match sets {
                Value::Array(values) => values.clone(),
                Value::String(value) => value.chars().map(|ch| json!(ch.to_string())).collect(),
                _ => return Err(error(ErrorKind::InvalidConfig, None)),
            };
            for (index, set) in sets.into_iter().enumerate() {
                if set.is_array() || set.is_object() {
                    return Err(error(ErrorKind::InvalidConfig, None));
                }
                if let Some(values) = set
                    .as_str()
                    .and_then(|set| builtins.get(set))
                    .and_then(Value::as_array)
                {
                    configs.extend(values.clone())
                } else {
                    skipped.push(SkippedRule {
                        index,
                        reason: SkipReason::UnknownBuiltin,
                    })
                }
            }
        }
    }
    if let Some(users) = sensor.get("scan_patterns") {
        configs.extend(
            users
                .as_array()
                .ok_or_else(|| error(ErrorKind::InvalidConfig, None))?
                .clone(),
        );
    }
    let mut rules = Vec::new();
    for (index, config) in configs.iter().enumerate() {
        let config = config
            .as_object()
            .ok_or_else(|| error(ErrorKind::InvalidConfig, Some(index)))?;
        let name = config.get("name").unwrap_or(&Value::Null);
        let pattern = config.get("pattern").unwrap_or(&Value::Null);
        if !truthy(name) || !truthy(pattern) {
            skipped.push(SkippedRule {
                index,
                reason: SkipReason::MissingNameOrPattern,
            });
            continue;
        }
        let pattern = pattern
            .as_str()
            .ok_or_else(|| error(ErrorKind::InvalidConfig, Some(index)))?;
        if [r"(.+)+", r"(.*)*", r"(.+)*", r"(.*)+", r"(\w+)+", r"(\d+)+"]
            .iter()
            .any(|indicator| pattern.contains(indicator))
        {
            skipped.push(SkippedRule {
                index,
                reason: SkipReason::DangerousPattern,
            });
            continue;
        }
        if config
            .get("target")
            .is_some_and(|target| target.is_array() || target.is_object())
        {
            return Err(error(ErrorKind::InvalidConfig, Some(index)));
        }
        let target = match config
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("both")
        {
            "input" | "request" => "request",
            "output" | "response" => "response",
            _ => "both",
        }
        .to_owned();
        let mut scopes = Vec::new();
        if let Some(scope) = config.get("scope").filter(|value| !value.is_null()) {
            let values = match scope {
                Value::String(value) => vec![json!(value)],
                Value::Array(values) => values.clone(),
                Value::Object(values) => values.keys().map(|key| json!(key)).collect(),
                _ => return Err(error(ErrorKind::InvalidConfig, Some(index))),
            };
            for value in values {
                let value = value
                    .as_str()
                    .ok_or_else(|| error(ErrorKind::InvalidConfig, Some(index)))?
                    .to_lowercase();
                if ["body", "url", "headers"].contains(&value.as_str()) && !scopes.contains(&value)
                {
                    scopes.push(value)
                }
            }
        }
        if scopes.is_empty() {
            scopes.push("body".into())
        }
        let action = match config.get("action").and_then(Value::as_str) {
            Some("block") => "block",
            _ => "log",
        }
        .to_owned();
        let severity = config
            .get("severity")
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "low" | "medium" | "high" | "critical"))
            .unwrap_or("medium")
            .to_owned();
        let insensitive = !config.get("case_sensitive").map(truthy).unwrap_or(true);
        let compiled = match compile_python_pattern(pattern, insensitive) {
            Ok(regex) => regex,
            Err(PatternIssue::Invalid) => {
                skipped.push(SkippedRule {
                    index,
                    reason: SkipReason::InvalidPattern,
                });
                continue;
            }
            Err(PatternIssue::Compatibility) => {
                return Err(error(ErrorKind::RegexCompatibility, Some(index)));
            }
        };
        rules.push(Rule {
            name: safe_value(name, 128, "unnamed"),
            rule_id: safe_value(
                &json!(format!("scan:{}", python_value(name))),
                128,
                "scan:unnamed",
            ),
            pattern: compiled,
            target,
            scopes,
            action,
            severity,
        });
    }
    let report = LoadReport {
        rules_total: rules.len(),
        skipped,
        compatibility_gaps: compatibility_gaps().to_vec(),
    };
    Ok((rules, report))
}

/// PathBytes reproduces mitmproxy's surrogate-escaped request.path getter before
/// the scanner's surrogatepass/lossy normalization. Bytes is the direct Python
/// bytes input; Text is an already valid Unicode string. None is inspection_error.
pub enum UrlInput<'a> {
    PathBytes(&'a [u8]),
    Bytes(&'a [u8]),
    Text(&'a str),
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlFailure {
    UrlInspectionOverflow,
    UrlInspectionError,
}
impl UrlFailure {
    fn text(self) -> &'static str {
        match self {
            Self::UrlInspectionOverflow => "url_inspection_overflow",
            Self::UrlInspectionError => "url_inspection_error",
        }
    }
}
struct UrlText {
    raw: String,
    decoded: String,
}
fn path_source_bytes(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut input = input;
    while !input.is_empty() && output.len() <= MAX_URL_SCAN_BYTES {
        match std::str::from_utf8(input) {
            Ok(_) => {
                let remaining = (MAX_URL_SCAN_BYTES + 1).saturating_sub(output.len());
                output.extend_from_slice(&input[..input.len().min(remaining)]);
                break;
            }
            Err(err) => {
                let prefix = err.valid_up_to();
                let remaining = (MAX_URL_SCAN_BYTES + 1).saturating_sub(output.len());
                output.extend_from_slice(&input[..prefix.min(remaining)]);
                if output.len() > MAX_URL_SCAN_BYTES {
                    break;
                }
                input = &input[prefix..];
                let invalid = err.error_len().unwrap_or(input.len());
                for byte in &input[..invalid] {
                    let code = 0xdc00 + u16::from(*byte);
                    output.extend_from_slice(&[
                        0xe0 | (code >> 12) as u8,
                        0x80 | ((code >> 6) & 63) as u8,
                        0x80 | (code & 63) as u8,
                    ]);
                    if output.len() > MAX_URL_SCAN_BYTES {
                        break;
                    }
                }
                input = &input[invalid..];
            }
        }
    }
    output
}
fn url_text(input: UrlInput<'_>) -> std::result::Result<UrlText, UrlFailure> {
    let owned;
    let bytes = match input {
        UrlInput::PathBytes(bytes) => {
            owned = path_source_bytes(bytes);
            owned.as_slice()
        }
        UrlInput::Bytes(bytes) => bytes,
        UrlInput::Text(text) => text.as_bytes(),
        UrlInput::Unavailable => return Err(UrlFailure::UrlInspectionError),
    };
    if bytes.len() > MAX_URL_SCAN_BYTES {
        return Err(UrlFailure::UrlInspectionOverflow);
    }
    let raw = String::from_utf8_lossy(bytes);
    if raw.len() > MAX_URL_SCAN_BYTES {
        return Err(UrlFailure::UrlInspectionOverflow);
    }
    let raw = raw.split('#').next().unwrap().to_owned();
    let decoded = percent_encoding::percent_decode_str(&raw)
        .decode_utf8_lossy()
        .into_owned();
    if decoded.len() > MAX_URL_SCAN_BYTES {
        return Err(UrlFailure::UrlInspectionOverflow);
    }
    Ok(UrlText { raw, decoded })
}

impl Scanner {
    pub fn has_rules(&self) -> Result<bool> {
        Ok(!self.rules()?.is_empty())
    }
    fn rules(&self) -> Result<Arc<Vec<Rule>>> {
        Ok(self
            .snapshot
            .read()
            .map_err(|_| error(ErrorKind::StateUnavailable, None))?
            .rules
            .clone())
    }
    pub fn load_policy_config(&self, sensor: &Value) -> Result<LoadReport> {
        let (rules, report) = compile_rules(sensor)?;
        self.snapshot
            .write()
            .map_err(|_| error(ErrorKind::StateUnavailable, None))?
            .rules = Arc::new(rules);
        Ok(report)
    }
    /// None keeps the previous rules on unavailable configuration. Initial empty
    /// policy_hash does not trigger a reload, matching the shipped addon.
    pub fn maybe_reload(&self, sensor: Option<&Value>) -> Result<Option<LoadReport>> {
        let Some(sensor) = sensor else {
            return Ok(None);
        };
        let hash = sensor.get("policy_hash").cloned().unwrap_or(json!(""));
        let mut snapshot = self
            .snapshot
            .write()
            .map_err(|_| error(ErrorKind::StateUnavailable, None))?;
        if snapshot.hash == hash {
            return Ok(None);
        }
        let (rules, report) = compile_rules(sensor)?;
        snapshot.rules = Arc::new(rules);
        snapshot.hash = hash;
        Ok(Some(report))
    }
    pub fn stats(&self) -> Result<Stats> {
        let rules_total = self.rules()?.len();
        let mut result = *self
            .stats
            .lock()
            .map_err(|_| error(ErrorKind::StateUnavailable, None))?;
        result.rules_total = rules_total;
        Ok(result)
    }
    fn count(&self, scans: u64, matches: u64, blocks: u64) -> Result<()> {
        self.count_cancellable(scans, matches, blocks, None)
    }
    fn count_cancellable(
        &self,
        scans: u64,
        matches: u64,
        blocks: u64,
        cancel: Option<&AtomicBool>,
    ) -> Result<()> {
        let mut stats = self
            .stats
            .lock()
            .map_err(|_| error(ErrorKind::StateUnavailable, None))?;
        check_cancelled(cancel)?;
        stats.scans_total += scans;
        stats.matches_total += matches;
        stats.blocks_total += blocks;
        Ok(())
    }
    fn scan_scope<'a>(
        &self,
        rules: &'a [Rule],
        scope: &str,
        text: &str,
        direction: Direction,
        cancel: Option<&AtomicBool>,
    ) -> Result<Option<&'a Rule>> {
        check_cancelled(cancel)?;
        self.count_cancellable(1, 0, 0, cancel)?;
        for (index, rule) in rules.iter().enumerate() {
            check_cancelled(cancel)?;
            if !rule.applies(direction, scope) {
                continue;
            }
            let input = RegexInput::new(text);
            let input = match cancel {
                Some(flag) => input.with_cancel_flag(flag),
                None => input,
            };
            let matched = rule.pattern.is_match_input(input).map_err(|failure| {
                if matches!(
                    failure,
                    fancy_regex::Error::RuntimeError(fancy_regex::RuntimeError::Cancelled)
                ) {
                    error(ErrorKind::Cancelled, None)
                } else {
                    error(ErrorKind::RegexRuntime, Some(index))
                }
            })?;
            check_cancelled(cancel)?;
            if matched {
                self.count_cancellable(0, 1, 0, cancel)?;
                return Ok(Some(rule));
            }
        }
        Ok(None)
    }
    fn scan_url<'a>(&self, rules: &'a [Rule], text: &UrlText) -> Result<Option<&'a Rule>> {
        self.count(2, 0, 0)?;
        for (index, rule) in rules.iter().enumerate() {
            if !rule.applies(Direction::Request, "url") {
                continue;
            }
            let raw = rule
                .pattern
                .is_match(&text.raw)
                .map_err(|_| error(ErrorKind::RegexRuntime, Some(index)))?;
            let decoded = rule
                .pattern
                .is_match(&text.decoded)
                .map_err(|_| error(ErrorKind::RegexRuntime, Some(index)))?;
            if raw || decoded {
                self.count(0, 1, 0)?;
                return Ok(Some(rule));
            }
        }
        Ok(None)
    }
    fn matched(
        &self,
        rule: &Rule,
        direction: Direction,
        location: String,
        message: Option<MessageType>,
        options: Options,
        cancel: Option<&AtomicBool>,
    ) -> Result<Decision> {
        check_cancelled(cancel)?;
        let block = rule.action == "block"
            && if message.is_some() {
                options.websocket(direction)
            } else {
                options.http(direction)
            };
        let finding = rule.finding(direction, location.clone(), message);
        let mut decision = Decision::plain(if block {
            Outcome::MatchBlocked
        } else {
            Outcome::MatchLogged
        });
        if let Some(message) = message {
            decision
                .metadata
                .insert("websocket_pattern_matched".into(), json!(rule.name));
            decision
                .metadata
                .insert("websocket_pattern_direction".into(), json!(direction));
            decision
                .metadata
                .insert("websocket_pattern_message_type".into(), json!(message));
            if block {
                decision.drop_message = true;
                decision
                    .metadata
                    .insert("websocket_pattern_dropped".into(), json!(true));
            }
        } else {
            let suffix = if direction == Direction::Response {
                "_response"
            } else {
                ""
            };
            decision
                .metadata
                .insert(format!("pattern_matched{suffix}"), json!(rule.name));
            decision
                .metadata
                .insert(format!("pattern_location{suffix}"), json!(location));
            if block {
                decision.status = Some(if direction == Direction::Request {
                    403
                } else {
                    502
                });
                decision.body = Some(
                    json!({"error":if direction==Direction::Request{"Request blocked by pattern policy"}else{"Response blocked by pattern policy"},"rule":rule.name,"location":location,"action":rule.action}),
                );
                decision
                    .metadata
                    .insert("blocked_by".into(), json!("pattern-scanner"));
            }
        }
        if block {
            self.count_cancellable(0, 0, 1, cancel)?;
        }
        decision.finding = Some(finding);
        Ok(decision)
    }
    fn url_failure(&self, failure: UrlFailure) -> Result<Decision> {
        self.count(0, 0, 1)?;
        let reason = failure.text();
        let mut decision = Decision::plain(Outcome::InspectionError);
        decision.status = Some(403);
        decision.failure = Some(reason);
        decision.body = Some(
            json!({"error":"Request blocked because URL inspection failed","location":"url","action":"block","reason":reason}),
        );
        decision.metadata=json!({"pattern_scan_failure":reason,"pattern_location":"url","blocked_by":"pattern-scanner"}).as_object().unwrap().clone();
        Ok(decision)
    }
    /// Headers are values from ordered, case-insensitively combined header names.
    /// Body None preserves a streamed/unavailable body, without asserting that
    /// content was scanned. Empty HTTP bodies are skipped; empty WS bodies scan.
    pub fn scan_http_request(
        &self,
        path: UrlInput<'_>,
        headers: &[(&str, &str)],
        body: Option<&str>,
        options: Options,
    ) -> Result<Decision> {
        let rules = self.rules()?;
        if rules.is_empty() {
            return Ok(Decision::plain(Outcome::NoRules));
        }
        if rules
            .iter()
            .any(|rule| rule.applies(Direction::Request, "url"))
        {
            let text = match url_text(path) {
                Ok(text) => text,
                Err(failure) => return self.url_failure(failure),
            };
            if let Some(rule) = self.scan_url(&rules, &text)? {
                return self.matched(rule, Direction::Request, "url".into(), None, options, None);
            }
        }
        self.scan_http_content(&rules, Direction::Request, headers, body, options)
    }
    pub fn scan_http_response(
        &self,
        present: bool,
        headers: &[(&str, &str)],
        body: Option<&str>,
        options: Options,
    ) -> Result<Decision> {
        let rules = self.rules()?;
        if rules.is_empty() {
            return Ok(Decision::plain(Outcome::NoRules));
        }
        if !present {
            return Ok(Decision::plain(Outcome::NoMessage));
        }
        self.scan_http_content(&rules, Direction::Response, headers, body, options)
    }
    fn scan_http_content(
        &self,
        rules: &[Rule],
        direction: Direction,
        headers: &[(&str, &str)],
        body: Option<&str>,
        options: Options,
    ) -> Result<Decision> {
        for (name, value) in headers {
            if let Some(rule) = self.scan_scope(rules, "headers", value, direction, None)? {
                return self.matched(rule, direction, safe_location(name), None, options, None);
            }
        }
        if let Some(body) = body.filter(|body| !body.is_empty())
            && let Some(rule) = self.scan_scope(rules, "body", body, direction, None)?
        {
            return self.matched(rule, direction, "body".into(), None, options, None);
        }
        Ok(Decision::plain(Outcome::NoMatch))
    }
    fn websocket_failure(
        &self,
        error_type: &'static str,
        cancel: Option<&AtomicBool>,
    ) -> Result<Decision> {
        self.count_cancellable(0, 0, 1, cancel)?;
        let mut decision = Decision::plain(Outcome::InspectionError);
        decision.drop_message = true;
        decision.failure = Some("inspection_error");
        decision.error_type = Some(error_type);
        decision
            .metadata
            .insert("websocket_pattern_dropped".into(), json!(true));
        Ok(decision)
    }
    /// Convenience API. Binary Latin-1 conversion allocates at most twice the
    /// byte length; use scan_websocket_text with private spooled text for large
    /// messages. No input bytes survive this call.
    pub fn scan_websocket_bytes(
        &self,
        direction: Direction,
        kind: MessageType,
        payload: &[u8],
        options: Options,
    ) -> Result<Decision> {
        let rules = self.rules()?;
        if rules.is_empty() {
            return Ok(Decision::plain(Outcome::NoRules));
        }
        let binary;
        let text = match kind {
            MessageType::Text => match std::str::from_utf8(payload) {
                Ok(text) => text,
                Err(_) => return self.websocket_failure("UnicodeDecodeError", None),
            },
            MessageType::Binary => {
                binary = payload
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect::<String>();
                &binary
            }
            MessageType::Other => return self.websocket_failure("ValueError", None),
        };
        self.websocket_text(&rules, direction, kind, text, options, None)
    }
    /// Complete validated text, or the complete byte-for-byte Latin-1 mapping of
    /// a binary message. &str proves UTF-8 validity; binary callers must supply
    /// that exact mapping. The scanner does not concatenate separate messages.
    pub fn scan_websocket_text(
        &self,
        direction: Direction,
        kind: MessageType,
        text: &str,
        options: Options,
    ) -> Result<Decision> {
        let rules = self.rules()?;
        if rules.is_empty() {
            return Ok(Decision::plain(Outcome::NoRules));
        }
        if kind == MessageType::Other {
            return self.websocket_failure("ValueError", None);
        }
        self.websocket_text(&rules, direction, kind, text, options, None)
    }
    /// Scan complete validated text with cancellation owned by this call.
    ///
    /// Keep the flag true once the connection closes or shutdown begins. Observed
    /// cancellation returns ErrorKind::Cancelled without a finding or inspection
    /// failure. Regex VM loops cooperate; opaque delegated searches can delay
    /// observation until they return. The caller must also check the flag before
    /// publishing results, since cancellation can race with this call returning.
    pub fn scan_websocket_text_cancellable(
        &self,
        direction: Direction,
        kind: MessageType,
        text: &str,
        options: Options,
        cancel: &AtomicBool,
    ) -> Result<Decision> {
        check_cancelled(Some(cancel))?;
        let rules = self.rules()?;
        let result = if rules.is_empty() {
            Ok(Decision::plain(Outcome::NoRules))
        } else if kind == MessageType::Other {
            self.websocket_failure("ValueError", Some(cancel))
        } else {
            self.websocket_text(&rules, direction, kind, text, options, Some(cancel))
        };
        check_cancelled(Some(cancel))?;
        result
    }

    fn websocket_text(
        &self,
        rules: &[Rule],
        direction: Direction,
        kind: MessageType,
        text: &str,
        options: Options,
        cancel: Option<&AtomicBool>,
    ) -> Result<Decision> {
        let result = self.scan_scope(rules, "body", text, direction, cancel);
        check_cancelled(cancel)?;
        match result {
            Ok(Some(rule)) => self.matched(
                rule,
                direction,
                "websocket_message".into(),
                Some(kind),
                options,
                cancel,
            ),
            Ok(None) => Ok(Decision::plain(Outcome::NoMatch)),
            Err(failure) if failure.kind == ErrorKind::Cancelled => Err(failure),
            Err(_) => self.websocket_failure("RegexRuntimeError", cancel),
        }
    }
}

// Source snapshot: detection/patterns.py + credential_catalog.py. The Python
// differential test compares every builtin field and order to detect drift.
const BUILTINS: &str = r###"{
  "secrets": [
    {
      "name": "openai-admin-key",
      "pattern": "sk-admin-[A-Za-z0-9_-]{8,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "OpenAI organization admin key detected"
    },
    {
      "name": "openrouter-api-key",
      "pattern": "sk-or-v1-[A-Za-z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "OpenRouter API key detected"
    },
    {
      "name": "openai-api-key",
      "pattern": "sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "OpenAI project or service-account API key detected"
    },
    {
      "name": "anthropic-api-key",
      "pattern": "sk-ant-[a-z]+\\d{0,2}-[A-Za-z0-9_.-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Anthropic credential detected"
    },
    {
      "name": "github-pat",
      "pattern": "ghp_[A-Za-z0-9._-]{36,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "GitHub personal access token detected"
    },
    {
      "name": "github-oauth",
      "pattern": "gho_[A-Za-z0-9._-]{36,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "GitHub OAuth token detected"
    },
    {
      "name": "github-app-user",
      "pattern": "ghu_[A-Za-z0-9._-]{36,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "GitHub App user-to-server token detected"
    },
    {
      "name": "github-app-server",
      "pattern": "ghs_[A-Za-z0-9._-]{36,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "GitHub App installation token detected"
    },
    {
      "name": "github-refresh",
      "pattern": "ghr_[A-Za-z0-9._-]{36,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "GitHub refresh token detected"
    },
    {
      "name": "github-fine-grained-pat",
      "pattern": "github_pat_[A-Za-z0-9._-]{60,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "GitHub fine-grained personal access token detected"
    },
    {
      "name": "google-api-key",
      "pattern": "(?:AIza[0-9A-Za-z_-]{35}|AQ\\.[A-Za-z0-9_-]{40,})",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Google API or authorization key detected"
    },
    {
      "name": "xai-api-key",
      "pattern": "xai-[A-Za-z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "xAI API key detected"
    },
    {
      "name": "groq-api-key",
      "pattern": "gsk_[A-Za-z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Groq API key detected"
    },
    {
      "name": "huggingface-token",
      "pattern": "hf_(?:(?:jwt|oauth)_)?[A-Za-z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Hugging Face access token detected"
    },
    {
      "name": "ambiguous-sk-api-key",
      "pattern": "sk-(?!admin-)(?!ant-)(?!or-v1-)(?!proj-)(?!svcacct-)[A-Za-z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Provider-ambiguous sk- API key detected"
    },
    {
      "name": "aws-access-key",
      "pattern": "AKIA[0-9A-Z]{16}",
      "target": "both",
      "scope": [
        "body",
        "url",
        "headers"
      ],
      "action": "block",
      "severity": "critical",
      "message": "AWS access key ID detected"
    },
    {
      "name": "private-key",
      "pattern": "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
      "target": "both",
      "scope": [
        "body"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Private key detected"
    },
    {
      "name": "db-connection-string",
      "pattern": "(postgres|mysql|mongodb)://[^\\s]+:[^\\s]+@",
      "target": "both",
      "scope": [
        "body",
        "url"
      ],
      "action": "block",
      "severity": "critical",
      "message": "Database connection string with credentials detected",
      "case_sensitive": false
    },
    {
      "name": "generic-bearer-in-body",
      "pattern": "bearer\\s+[a-zA-Z0-9_-]{20,}",
      "target": "both",
      "scope": [
        "body"
      ],
      "action": "log",
      "severity": "high",
      "message": "Bearer token in request/response body",
      "case_sensitive": false
    }
  ],
  "pii": [
    {
      "name": "ssn-pattern",
      "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
      "target": "both",
      "scope": [
        "body"
      ],
      "action": "log",
      "severity": "high",
      "message": "Potential SSN pattern detected"
    },
    {
      "name": "credit-card",
      "pattern": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b",
      "target": "both",
      "scope": [
        "body"
      ],
      "action": "log",
      "severity": "high",
      "message": "Potential credit card number detected"
    },
    {
      "name": "email-address",
      "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
      "target": "both",
      "scope": [
        "body"
      ],
      "action": "log",
      "severity": "medium",
      "message": "Email address detected"
    }
  ]
}"###;
