//! Operator display expressions over immutable observations. No scanner or
//! enforcement state is consulted. Python regex compatibility remains finite.

use std::{fmt, sync::Arc};

use fancy_regex::Regex;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Body, Row, python_text, wipe_json};
use crate::{http_content, inspection, websocket::MessageContent};

mod bytes;
use bytes::ByteRegex;

/// Categorical failures contain no operator expression or captured content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterError {
    Invalid,
    Unsupported,
    Compatibility,
    Runtime,
    DecodeType,
    Allocation,
    Storage,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid traffic filter",
            Self::Unsupported => "traffic filter predicate is unavailable",
            Self::Compatibility => "traffic filter compatibility is unavailable",
            Self::Runtime => "traffic filter matching failed",
            Self::DecodeType => "traffic filter content decoder type error",
            Self::Allocation => "traffic filter allocation failed",
            Self::Storage => "traffic filter content storage failed",
        })
    }
}
impl std::error::Error for FilterError {}

type Result<T> = std::result::Result<T, FilterError>;

pub(super) struct WipingValue(pub(super) Value);
impl Drop for WipingValue {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Either,
    Request,
    Response,
}

enum Predicate {
    All,
    Request,
    Response,
    WebSocket,
    Error,
    Asset,
    Code(Option<u16>),
    Url(Regex),
    Method(ByteRegex),
    Metadata(Regex),
    Headers(Direction, ByteRegex),
    ContentType(Direction, ByteRegex),
    Body(Direction, ByteRegex),
}

enum Node {
    Leaf(Predicate),
    Not(usize),
    And(usize, usize),
    Or(usize, usize),
}

/// Flat nodes avoid recursive ownership/drop of an operator-authored tree.
pub(super) struct UserFilter {
    raw: Zeroizing<String>,
    nodes: Vec<Node>,
    root: Option<usize>,
    needs: Needs,
    pinned_display: Option<Zeroizing<String>>,
}

#[derive(Default)]
struct Needs {
    url: bool,
    method: bool,
    metadata: bool,
    request_headers: bool,
    response_headers: bool,
    request_body: bool,
    response_body: bool,
    messages: bool,
}

pub(super) struct Snapshot {
    pub(super) summary: Value,
    url: Zeroizing<String>,
    method: Zeroizing<Vec<u8>>,
    metadata: Zeroizing<String>,
    request_headers: Headers,
    response_headers: Headers,
    request_body: Option<Arc<Zeroizing<Vec<u8>>>>,
    response_body: Option<Arc<Zeroizing<Vec<u8>>>>,
    messages: Vec<(bool, Arc<MessageContent>)>,
    status: Option<u16>,
    websocket: bool,
    error: bool,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        wipe_json(&mut self.summary);
    }
}

type HeaderPair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);
#[derive(Default)]
struct Headers(Vec<HeaderPair>);
impl Headers {
    fn capture(pairs: &[(String, String)], needed: bool) -> Result<Self> {
        if !needed {
            return Ok(Self::default());
        }
        fn latin1(text: &str) -> Result<Zeroizing<Vec<u8>>> {
            text.chars()
                .map(|ch| u8::try_from(ch as u32).map_err(|_| FilterError::Compatibility))
                .collect::<Result<Vec<_>>>()
                .map(Zeroizing::new)
        }
        pairs
            .iter()
            .map(|(key, value)| Ok((latin1(key)?, latin1(value)?)))
            .collect::<Result<Vec<_>>>()
            .map(Self)
    }

    fn block(&self) -> Zeroizing<Vec<u8>> {
        let mut text = Zeroizing::new(Vec::new());
        for (key, value) in &self.0 {
            text.extend_from_slice(key);
            text.extend_from_slice(b": ");
            text.extend_from_slice(value);
            text.extend_from_slice(b"\r\n");
        }
        text
    }

    fn content_encoding(&self) -> Zeroizing<Vec<u8>> {
        let mut encoding = Zeroizing::new(Vec::new());
        let mut first = true;
        for (key, value) in &self.0 {
            if key.eq_ignore_ascii_case(b"content-encoding") {
                if !first {
                    encoding.extend_from_slice(b", ");
                }
                first = false;
                encoding.extend_from_slice(value);
            }
        }
        encoding
    }

    fn content_type(&self, pattern: &ByteRegex) -> Result<bool> {
        for (key, value) in &self.0 {
            if key.eq_ignore_ascii_case(b"content-type") && matches_bytes(pattern, value)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn asset(&self) -> bool {
        const TYPES: &[&[u8]] = &[
            b"text/javascript",
            b"application/x-javascript",
            b"application/javascript",
            b"text/css",
            b"image/",
            b"font/",
            b"application/font",
        ];
        self.0.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case(b"content-type")
                && TYPES
                    .iter()
                    .any(|needle| value.windows(needle.len()).any(|part| part == *needle))
        })
    }
}

impl UserFilter {
    pub(super) fn empty() -> Self {
        Self {
            raw: Zeroizing::new(String::new()),
            nodes: Vec::new(),
            root: None,
            needs: Needs::default(),
            pinned_display: None,
        }
    }
    pub(super) fn pinned_display(&self) -> Option<&str> {
        self.pinned_display.as_deref().map(String::as_str)
    }
    pub(super) fn raw(&self) -> &str {
        &self.raw
    }
    pub(super) fn trimmed(&self) -> &str {
        python_strip(&self.raw)
    }

    pub(super) fn compile(raw: &str, case_sensitive: bool) -> Result<Self> {
        let mut compiled = Self::empty();
        compiled.raw = Zeroizing::new(raw.into());
        if python_strip(raw).is_empty() {
            return Ok(compiled);
        }
        let effective_user = Zeroizing::new(format!("({})", python_strip(raw)));
        let mut parser = Parser {
            input: &effective_user,
            position: 0,
            case_sensitive,
            nodes: Vec::new(),
            outer_closed_early: false,
            implicit_offsets: Vec::new(),
        };
        compiled.root = Some(parser.parse()?);
        if parser.outer_closed_early {
            let display = if parser.implicit_offsets.is_empty() {
                Zeroizing::new(format!("({})", effective_user.as_str()))
            } else {
                // Each offset separates a complete top-level infix expression.
                // Group each one before spelling implicit conjunction as '&';
                // inserting '&' alone would change its lower precedence.
                let mut display = Zeroizing::new(String::from("("));
                let mut start = 0;
                for end in parser
                    .implicit_offsets
                    .iter()
                    .copied()
                    .chain(std::iter::once(effective_user.len()))
                {
                    if start != 0 {
                        display.push_str(" & ");
                    }
                    display.push('(');
                    display.push_str(effective_user[start..end].trim_matches(grammar_space));
                    // Preserve a word boundary even for a final bare unary.
                    display.push_str(" )");
                    start = end;
                }
                display.push(')');
                display
            };
            compiled.pinned_display = Some(display);
        }
        compiled.nodes = parser.nodes;
        compiled.plan_needs();
        Ok(compiled)
    }

    fn plan_needs(&mut self) {
        for node in &self.nodes {
            let Node::Leaf(predicate) = node else {
                continue;
            };
            match predicate {
                Predicate::Url(_) => self.needs.url = true,
                Predicate::Method(_) => self.needs.method = true,
                Predicate::Metadata(_) => self.needs.metadata = true,
                Predicate::Asset => self.needs.response_headers = true,
                Predicate::Headers(direction, _) | Predicate::ContentType(direction, _) => {
                    self.needs.request_headers |= !matches!(direction, Direction::Response);
                    self.needs.response_headers |= !matches!(direction, Direction::Request);
                }
                Predicate::Body(direction, _) => {
                    self.needs.request_body |= !matches!(direction, Direction::Response);
                    self.needs.response_body |= !matches!(direction, Direction::Request);
                    self.needs.request_headers |= self.needs.request_body;
                    self.needs.response_headers |= self.needs.response_body;
                    self.needs.messages = true;
                }
                _ => (),
            }
        }
    }

    pub(super) fn snapshot(&self, row: &Row) -> Result<Snapshot> {
        let needs = &self.needs;
        let mut metadata = Zeroizing::new(String::new());
        if needs.metadata {
            for (key, value) in row.metadata.as_object().expect("row metadata") {
                if !metadata.is_empty() {
                    metadata.push('\n');
                }
                metadata.push_str(key);
                metadata.push_str(": ");
                metadata.push_str(&Zeroizing::new(python_text(value)));
            }
        }
        fn body(body: &Body, needed: bool) -> Option<Arc<Zeroizing<Vec<u8>>>> {
            match body {
                Body::Bytes(value) if needed => Some(Arc::clone(value)),
                _ => None,
            }
        }
        Ok(Snapshot {
            // Construct summary only after fallible captured-header validation.
            request_headers: Headers::capture(&row.request.headers, needs.request_headers)?,
            response_headers: Headers::capture(&row.response_headers, needs.response_headers)?,
            summary: row.summary(),
            url: Zeroizing::new(if needs.url {
                row.request.url.clone()
            } else {
                String::new()
            }),
            method: Zeroizing::new(if needs.method {
                row.request.method.as_bytes().to_vec()
            } else {
                Vec::new()
            }),
            metadata,
            request_body: body(&row.request_body, needs.request_body),
            response_body: body(&row.response_body, needs.response_body),
            messages: if needs.messages {
                row.websocket
                    .as_ref()
                    .map_or_else(Vec::new, |session| session.filter_messages())
            } else {
                Vec::new()
            },
            status: row.status,
            websocket: row.websocket.is_some(),
            error: row.error.is_some()
                || row
                    .websocket
                    .as_ref()
                    .is_some_and(|session| session.error.is_some()),
        })
    }

    pub(super) fn matches(&self, row: &Snapshot) -> Result<bool> {
        enum Visit {
            Node(usize),
            Not,
            And(usize),
            Or(usize),
        }
        let Some(root) = self.root else {
            return Ok(true);
        };
        let mut pending = vec![Visit::Node(root)];
        let mut result = false;
        while let Some(visit) = pending.pop() {
            match visit {
                Visit::Node(index) => match &self.nodes[index] {
                    Node::Leaf(predicate) => result = predicate.matches(row)?,
                    Node::Not(inner) => {
                        pending.push(Visit::Not);
                        pending.push(Visit::Node(*inner));
                    }
                    Node::And(left, right) => {
                        pending.push(Visit::And(*right));
                        pending.push(Visit::Node(*left));
                    }
                    Node::Or(left, right) => {
                        pending.push(Visit::Or(*right));
                        pending.push(Visit::Node(*left));
                    }
                },
                Visit::Not => result = !result,
                Visit::And(next) if result => pending.push(Visit::Node(next)),
                Visit::Or(next) if !result => pending.push(Visit::Node(next)),
                _ => (),
            }
        }
        Ok(result)
    }
}

impl Predicate {
    fn matches(&self, row: &Snapshot) -> Result<bool> {
        match self {
            Self::All => Ok(true),
            Self::Request => Ok(row.status.is_none()),
            Self::Response => Ok(row.status.is_some()),
            Self::WebSocket => Ok(row.websocket),
            Self::Error => Ok(row.error),
            Self::Code(code) => Ok(code.is_some() && *code == row.status),
            Self::Asset => Ok(row.status.is_some() && row.response_headers.asset()),
            Self::Url(pattern) => matches_text(pattern, &row.url),
            Self::Method(pattern) => matches_bytes(pattern, &row.method),
            Self::Metadata(pattern) => matches_text(pattern, &row.metadata),
            Self::Headers(direction, pattern) => {
                if !matches!(direction, Direction::Response)
                    && matches_bytes(pattern, &row.request_headers.block())?
                {
                    return Ok(true);
                }
                Ok(!matches!(direction, Direction::Request)
                    && row.status.is_some()
                    && matches_bytes(pattern, &row.response_headers.block())?)
            }
            Self::ContentType(direction, pattern) => {
                if !matches!(direction, Direction::Response)
                    && row.request_headers.content_type(pattern)?
                {
                    return Ok(true);
                }
                Ok(!matches!(direction, Direction::Request)
                    && row.status.is_some()
                    && row.response_headers.content_type(pattern)?)
            }
            Self::Body(direction, pattern) => {
                if !matches!(direction, Direction::Response)
                    && body_matches(pattern, row.request_body.as_deref(), &row.request_headers)?
                {
                    return Ok(true);
                }
                if !matches!(direction, Direction::Request)
                    && row.status.is_some()
                    && body_matches(pattern, row.response_body.as_deref(), &row.response_headers)?
                {
                    return Ok(true);
                }
                for (from_client, content) in &row.messages {
                    if matches!(direction, Direction::Request) && !from_client
                        || matches!(direction, Direction::Response) && *from_client
                    {
                        continue;
                    }
                    if content
                        .with_bytes(|bytes| matches_bytes(pattern, bytes))
                        .map_err(|_| FilterError::Storage)??
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

fn body_matches(
    pattern: &ByteRegex,
    body: Option<&Zeroizing<Vec<u8>>>,
    headers: &Headers,
) -> Result<bool> {
    let Some(body) = body else {
        return Ok(false);
    };
    let encoding = headers.content_encoding();
    if encoding.is_empty() {
        return matches_bytes(pattern, body);
    }
    match http_content::decode(body, &encoding) {
        Ok(decoded) => matches_bytes(pattern, &decoded),
        Err(http_content::ContentError::Value) => matches_bytes(pattern, body),
        Err(http_content::ContentError::Type) => Err(FilterError::DecodeType),
        Err(http_content::ContentError::Allocation) => Err(FilterError::Allocation),
    }
}

fn matches_bytes(pattern: &ByteRegex, value: &[u8]) -> Result<bool> {
    pattern.is_match(value)
}
fn matches_text(pattern: &Regex, value: &str) -> Result<bool> {
    pattern.is_match(value).map_err(match_error)
}
fn match_error(error: fancy_regex::Error) -> FilterError {
    if matches!(
        error,
        fancy_regex::Error::RuntimeError(fancy_regex::RuntimeError::AllocationFailed)
    ) {
        FilterError::Allocation
    } else {
        FilterError::Runtime
    }
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(|ch: char| ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}'))
}
fn grammar_space(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r')
}

#[derive(Clone, Copy)]
enum Operator {
    Open,
    Not,
    And,
    Or,
    Implicit,
}
impl Operator {
    fn precedence(self) -> u8 {
        match self {
            Self::Not => 3,
            Self::And => 2,
            Self::Or => 1,
            _ => 0,
        }
    }
}

struct Parser<'a> {
    input: &'a str,
    position: usize,
    case_sensitive: bool,
    nodes: Vec<Node>,
    outer_closed_early: bool,
    implicit_offsets: Vec<usize>,
}
impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }
    fn take(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.position += ch.len_utf8();
        Some(ch)
    }
    fn space(&mut self) {
        while self.peek().is_some_and(grammar_space) {
            self.take();
        }
    }
    fn push(&mut self, node: Node) -> usize {
        let index = self.nodes.len();
        self.nodes.push(node);
        index
    }
    fn reduce(&mut self, operator: Operator, values: &mut Vec<usize>) -> Result<()> {
        let right = values.pop().ok_or(FilterError::Invalid)?;
        let node = if matches!(operator, Operator::Not) {
            Node::Not(right)
        } else {
            let left = values.pop().ok_or(FilterError::Invalid)?;
            if matches!(operator, Operator::Or) {
                Node::Or(left, right)
            } else {
                Node::And(left, right)
            }
        };
        values.push(self.push(node));
        Ok(())
    }
    fn parse(&mut self) -> Result<usize> {
        let mut values = Vec::new();
        let mut operators = Vec::new();
        let mut want_value = true;
        let mut depth = 0;
        loop {
            self.space();
            let Some(ch) = self.peek() else {
                break;
            };
            if want_value {
                match ch {
                    '!' => {
                        self.take();
                        operators.push(Operator::Not);
                        continue;
                    }
                    '(' => {
                        self.take();
                        operators.push(Operator::Open);
                        depth += 1;
                        continue;
                    }
                    ')' => return Err(FilterError::Invalid),
                    _ => (),
                }
                let leaf = self.predicate()?;
                values.push(self.push(Node::Leaf(leaf)));
                want_value = false;
                while matches!(operators.last(), Some(Operator::Not)) {
                    operators.pop();
                    self.reduce(Operator::Not, &mut values)?;
                }
            } else if ch == ')' {
                if depth == 0 {
                    return Err(FilterError::Invalid);
                }
                self.take();
                depth -= 1;
                if depth == 0 && !self.input[self.position..].chars().all(grammar_space) {
                    self.outer_closed_early = true;
                }
                while let Some(operator) = operators.pop() {
                    if matches!(operator, Operator::Open) {
                        break;
                    }
                    self.reduce(operator, &mut values)?;
                }
                while matches!(operators.last(), Some(Operator::Not)) {
                    operators.pop();
                    self.reduce(Operator::Not, &mut values)?;
                }
            } else {
                let next = match ch {
                    '&' => {
                        self.take();
                        Operator::And
                    }
                    '|' => {
                        self.take();
                        Operator::Or
                    }
                    _ if depth == 0 => {
                        self.implicit_offsets.push(self.position);
                        Operator::Implicit
                    }
                    _ => return Err(FilterError::Invalid),
                };
                while operators.last().is_some_and(|op| {
                    !matches!(op, Operator::Open) && op.precedence() >= next.precedence()
                }) {
                    self.reduce(operators.pop().expect("operator"), &mut values)?;
                }
                operators.push(next);
                want_value = true;
            }
        }
        if want_value || depth != 0 {
            return Err(FilterError::Invalid);
        }
        while let Some(op) = operators.pop() {
            self.reduce(op, &mut values)?;
        }
        if values.len() != 1 {
            return Err(FilterError::Invalid);
        }
        Ok(values[0])
    }

    fn predicate(&mut self) -> Result<Predicate> {
        let code = if self.peek() == Some('~') {
            self.take();
            let start = self.position;
            while self.peek().is_some_and(|ch| ch.is_ascii_alphabetic()) {
                self.take();
            }
            if start == self.position || self.peek().is_some_and(|ch| ch.is_ascii_graphic()) {
                return Err(FilterError::Invalid);
            }
            &self.input[start..self.position]
        } else {
            "u"
        };
        let direction = if code.ends_with('q') {
            Direction::Request
        } else if code.ends_with('s') {
            Direction::Response
        } else {
            Direction::Either
        };
        match code {
            "all" | "http" => return Ok(Predicate::All),
            "q" => return Ok(Predicate::Request),
            "s" => return Ok(Predicate::Response),
            "websocket" => return Ok(Predicate::WebSocket),
            "e" => return Ok(Predicate::Error),
            "a" => return Ok(Predicate::Asset),
            "d" | "src" | "dst" | "replay" | "replayq" | "replays" | "marked" | "marker"
            | "comment" | "tcp" | "udp" | "dns" => return Err(FilterError::Unsupported),
            "c" => {
                self.space();
                let start = self.position;
                while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                    self.take();
                }
                if start == self.position {
                    return Err(FilterError::Invalid);
                }
                let digits = self.input[start..self.position].trim_start_matches('0');
                let code = if digits.is_empty() {
                    Some(0)
                } else {
                    digits.parse().ok()
                };
                return Ok(Predicate::Code(code));
            }
            "u" | "m" | "meta" | "h" | "hq" | "hs" | "t" | "tq" | "ts" | "b" | "bq" | "bs" => (),
            _ => return Err(FilterError::Invalid),
        }
        self.space();
        let expression = self.regex_operand()?;
        let insensitive = !self.case_sensitive;
        if matches!(code, "u" | "meta") {
            let expression = Zeroizing::new(if code == "meta" {
                format!("(?m){}", expression.as_str())
            } else {
                expression.to_string()
            });
            let regex =
                inspection::compile_python_pattern(&expression, insensitive).map_err(|error| {
                    match error {
                        inspection::PatternIssue::Invalid => FilterError::Invalid,
                        inspection::PatternIssue::Compatibility => FilterError::Compatibility,
                    }
                })?;
            return Ok(if code == "u" {
                Predicate::Url(regex)
            } else {
                Predicate::Metadata(regex)
            });
        }
        let regex = bytes::compile(
            &expression,
            insensitive,
            code.starts_with('h'),
            code.starts_with('b'),
        )?;
        Ok(match code {
            "m" => Predicate::Method(regex),
            "h" | "hq" | "hs" => Predicate::Headers(direction, regex),
            "t" | "tq" | "ts" => Predicate::ContentType(direction, regex),
            _ => Predicate::Body(direction, regex),
        })
    }

    fn regex_operand(&mut self) -> Result<Zeroizing<String>> {
        let mut result = Zeroizing::new(String::new());
        if self.peek().is_some_and(|ch| matches!(ch, '\'' | '"')) {
            let quote = self.take().expect("quote");
            loop {
                match self.take().ok_or(FilterError::Invalid)? {
                    ch if ch == quote => break,
                    '\n' | '\r' => return Err(FilterError::Invalid),
                    '\\' => {
                        let ch = self.take().ok_or(FilterError::Invalid)?;
                        // Pinned pyparsing3.2.5's rf-string numeric branch
                        // contains literal 3/2/4, not quantifiers. Preserve its
                        // observed lexer output before regex compilation.
                        if matches!(ch, '0'..='7') && self.peek() == Some('3') {
                            result.push(ch);
                            result.push('3');
                            self.take();
                            continue;
                        }
                        let tail = &self.input.as_bytes()[self.position..];
                        let numeric = matches!(ch, 'x' | 'u')
                            && tail.get(..2).is_some_and(|part| {
                                part[0].is_ascii_hexdigit()
                                    && part[1] == if ch == 'x' { b'2' } else { b'4' }
                            });
                        let converted = if numeric {
                            let value = u8::from_str_radix(
                                &self.input[self.position..self.position + 2],
                                16,
                            )
                            .expect("lexer hex");
                            self.position += 2;
                            char::from(value)
                        } else {
                            match ch {
                                't' => '\t',
                                'n' => '\n',
                                'r' => '\r',
                                'f' => '\x0c',
                                '0' => '\0',
                                '\n' | '\r' => return Err(FilterError::Invalid),
                                _ => ch,
                            }
                        };
                        result.push(converted);
                    }
                    ch => result.push(ch),
                }
            }
        } else {
            while let Some(ch) = self
                .peek()
                .filter(|ch| !grammar_space(*ch) && !"()~\"'".contains(*ch))
            {
                self.take();
                result.push(ch);
            }
            if result.is_empty() {
                return Err(FilterError::Invalid);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
