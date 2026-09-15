//! Circuit JSON retains Python's nonfinite constants without changing shared
//! policy JSON admission. Container traversal uses explicit stacks. Ordinary
//! scalar syntax and escaping still use serde_json and the shared formatter.

use std::fmt;

use indexmap::IndexMap;
use serde_json::Value;

use super::{CircuitValue, Result, invalid};

impl CircuitValue {
    /// Parse the JSON dialect used by Python's circuit cache (allow_nan=True).
    /// Constants are recognized only as complete, unquoted scalar tokens.
    pub fn parse_json(source: &str) -> Result<Self> {
        parse(source)
    }

    /// Render a typed circuit document using Python's JSON presentation.
    /// `pretty` selects the source cache's indent=2 representation. Temporal
    /// operands return Type before writing; sink failures return Invalid and
    /// can leave a prefix in the caller-owned sink.
    pub fn write_json(&self, output: &mut impl fmt::Write, pretty: bool) -> Result<()> {
        validate_temporals(self)?;
        write(self, output, pretty, false).map_err(|_| invalid("cannot write circuit JSON output"))
    }

    pub fn render_json(&self, pretty: bool) -> Result<String> {
        let mut output = String::new();
        self.write_json(&mut output, pretty)?;
        Ok(output)
    }

    /// Source AuditEvent's JSON-mode Any fields encode nonfinite floats as
    /// null. This output-only mode leaves API/cache values and integers intact.
    pub(crate) fn render_audit_json(&self) -> Result<String> {
        validate_temporals(self)?;
        let mut output = String::new();
        write(self, &mut output, false, true)
            .map_err(|_| invalid("cannot write circuit audit JSON output"))?;
        Ok(output)
    }

    pub fn as_object(&self) -> Option<&IndexMap<String, Self>> {
        match self {
            Self::Object(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub(super) fn from_json_value(source: &Value) -> Self {
        fn shallow(value: &Value) -> CircuitValue {
            match value {
                Value::Bool(value) => CircuitValue::Bool(*value),
                Value::Number(value) => {
                    let text = value.to_string();
                    if text.contains(['.', 'e', 'E']) {
                        CircuitValue::Float(text.parse().expect("valid JSON floating number"))
                    } else {
                        CircuitValue::Integer(text.parse().expect("valid JSON integer"))
                    }
                }
                Value::Array(_) => CircuitValue::Array(Vec::new()),
                Value::Object(_) => CircuitValue::Object(IndexMap::new()),
                value => CircuitValue::Other(value.clone()),
            }
        }
        let mut result = shallow(source);
        let mut pending = vec![(source, &mut result)];
        while let Some((source, target)) = pending.pop() {
            match (source, target) {
                (Value::Array(source), Self::Array(target)) => {
                    target.extend(source.iter().map(shallow));
                    pending.extend(source.iter().zip(target.iter_mut()));
                }
                (Value::Object(source), Self::Object(target)) => {
                    target.extend(
                        source
                            .iter()
                            .map(|(key, value)| (key.clone(), shallow(value))),
                    );
                    pending.extend(source.values().zip(target.values_mut()));
                }
                _ => {}
            }
        }
        result
    }
}

impl Clone for CircuitValue {
    fn clone(&self) -> Self {
        fn shallow(value: &CircuitValue) -> CircuitValue {
            match value {
                CircuitValue::Bool(value) => CircuitValue::Bool(*value),
                CircuitValue::Integer(value) => CircuitValue::Integer(value.clone()),
                CircuitValue::Float(value) => CircuitValue::Float(*value),
                CircuitValue::Other(value) => CircuitValue::Other(value.clone()),
                CircuitValue::Temporal(value) => CircuitValue::Temporal(value.clone()),
                CircuitValue::Array(_) => CircuitValue::Array(Vec::new()),
                CircuitValue::Object(_) => CircuitValue::Object(IndexMap::new()),
            }
        }
        let mut result = shallow(self);
        let mut pending = vec![(self, &mut result)];
        while let Some((source, target)) = pending.pop() {
            match (source, target) {
                (Self::Array(source), Self::Array(target)) => {
                    target.extend(source.iter().map(shallow));
                    pending.extend(source.iter().zip(target.iter_mut()));
                }
                (Self::Object(source), Self::Object(target)) => {
                    target.extend(
                        source
                            .iter()
                            .map(|(key, value)| (key.clone(), shallow(value))),
                    );
                    pending.extend(source.values().zip(target.values_mut()));
                }
                _ => {}
            }
        }
        result
    }
}

impl PartialEq for CircuitValue {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        while let Some((left, right)) = pending.pop() {
            match (left, right) {
                (Self::Bool(left), Self::Bool(right)) if left == right => {}
                (Self::Integer(left), Self::Integer(right)) if left == right => {}
                (Self::Float(left), Self::Float(right)) if left == right => {}
                (Self::Other(left), Self::Other(right)) if left == right => {}
                (Self::Temporal(left), Self::Temporal(right)) if left == right => {}
                (Self::Array(left), Self::Array(right)) if left.len() == right.len() => {
                    pending.extend(left.iter().zip(right));
                }
                (Self::Object(left), Self::Object(right)) if left.len() == right.len() => {
                    for (key, left) in left {
                        let Some(right) = right.get(key) else {
                            return false;
                        };
                        pending.push((left, right));
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

// Parsed documents can be deeper than serde_json's recursive Value frontend.
// Empty children before their ordinary Drop runs, including error cleanup.
impl Drop for CircuitValue {
    fn drop(&mut self) {
        fn drain(value: &mut CircuitValue, pending: &mut Vec<CircuitValue>) {
            match value {
                CircuitValue::Array(values) => pending.append(values),
                CircuitValue::Object(values) => {
                    pending.extend(std::mem::take(values).into_values());
                }
                _ => {}
            }
        }
        let mut pending = Vec::new();
        drain(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            drain(&mut value, &mut pending);
        }
    }
}

#[derive(Clone, Copy)]
enum Expect {
    Value,
    ArrayFirst,
    Key(bool),
    Colon,
    Separator,
}
struct Frame {
    value: CircuitValue,
    key: Option<String>,
    expect: Expect,
}
fn accept(value: CircuitValue, frames: &mut [Frame], root: &mut Option<CircuitValue>) {
    if let Some(frame) = frames.last_mut() {
        match &mut frame.value {
            CircuitValue::Array(values) => values.push(value),
            CircuitValue::Object(values) => {
                values.insert(frame.key.take().expect("parsed object key"), value);
            }
            _ => unreachable!(),
        }
        frame.expect = Expect::Separator;
    } else {
        *root = Some(value);
    }
}
fn parse(source: &str) -> Result<CircuitValue> {
    let bytes = source.as_bytes();
    let mut position = 0;
    let mut frames: Vec<Frame> = Vec::new();
    let mut root = None;
    loop {
        while bytes
            .get(position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            position += 1;
        }
        if frames.is_empty()
            && let Some(value) = root.take()
        {
            return if position == bytes.len() {
                Ok(value)
            } else {
                Err(invalid_json())
            };
        }
        let byte = *bytes.get(position).ok_or_else(invalid_json)?;
        let expect = frames.last().map_or(Expect::Value, |frame| frame.expect);
        let closes = frames.last().is_some_and(|frame| {
            matches!(
                (&frame.value, byte),
                (CircuitValue::Array(_), b']') | (CircuitValue::Object(_), b'}')
            )
        });
        if closes
            && matches!(
                expect,
                Expect::ArrayFirst | Expect::Key(true) | Expect::Separator
            )
        {
            let frame = frames.pop().unwrap();
            position += 1;
            accept(frame.value, &mut frames, &mut root);
            continue;
        }
        match expect {
            Expect::Value | Expect::ArrayFirst => match byte {
                b'[' | b'{' => {
                    frames.push(Frame {
                        value: if byte == b'[' {
                            CircuitValue::Array(Vec::new())
                        } else {
                            CircuitValue::Object(IndexMap::new())
                        },
                        key: None,
                        expect: if byte == b'[' {
                            Expect::ArrayFirst
                        } else {
                            Expect::Key(true)
                        },
                    });
                    position += 1;
                }
                _ => {
                    let start = position;
                    if byte == b'"' {
                        position = string_end(bytes, position)?;
                    } else {
                        while bytes.get(position).is_some_and(|byte| {
                            !matches!(
                                byte,
                                b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}' | b':'
                            )
                        }) {
                            position += 1;
                        }
                    }
                    let value = match &source[start..position] {
                        "NaN" => CircuitValue::Float(f64::NAN),
                        "Infinity" => CircuitValue::Float(f64::INFINITY),
                        "-Infinity" => CircuitValue::Float(f64::NEG_INFINITY),
                        scalar => serde_json::from_str::<Value>(scalar)
                            .map(CircuitValue::from)
                            .map_err(|_| invalid_json())?,
                    };
                    accept(value, &mut frames, &mut root);
                }
            },
            Expect::Key(_) if byte == b'"' => {
                let end = string_end(bytes, position)?;
                let key =
                    serde_json::from_str(&source[position..end]).map_err(|_| invalid_json())?;
                let frame = frames.last_mut().unwrap();
                frame.key = Some(key);
                frame.expect = Expect::Colon;
                position = end;
            }
            Expect::Colon if byte == b':' => {
                frames.last_mut().unwrap().expect = Expect::Value;
                position += 1;
            }
            Expect::Separator if byte == b',' => {
                let frame = frames.last_mut().unwrap();
                frame.expect = if matches!(frame.value, CircuitValue::Array(_)) {
                    Expect::Value
                } else {
                    Expect::Key(false)
                };
                position += 1;
            }
            _ => return Err(invalid_json()),
        }
    }
}
fn invalid_json() -> super::Error {
    invalid("invalid circuit JSON document")
}
fn string_end(bytes: &[u8], mut position: usize) -> Result<usize> {
    position += 1;
    while let Some(byte) = bytes.get(position) {
        match byte {
            b'"' => return Ok(position + 1),
            b'\\' => position += 2,
            _ => position += 1,
        }
    }
    Err(invalid_json())
}

enum WritePart<'a> {
    Typed(&'a CircuitValue, usize),
    Plain(&'a Value, usize),
    Key(&'a str),
    Text(&'static str),
    Indent(usize),
}
fn write(
    value: &CircuitValue,
    output: &mut impl fmt::Write,
    pretty: bool,
    audit: bool,
) -> fmt::Result {
    let mut pending = vec![WritePart::Typed(value, 0)];
    while let Some(part) = pending.pop() {
        match part {
            WritePart::Typed(CircuitValue::Array(values), depth) => {
                array_parts(
                    values
                        .iter()
                        .map(|value| WritePart::Typed(value, depth + 1)),
                    depth,
                    pretty,
                    output,
                    &mut pending,
                )?;
            }
            WritePart::Typed(CircuitValue::Object(values), depth) => {
                object_parts(
                    values
                        .iter()
                        .map(|(key, value)| (key.as_str(), WritePart::Typed(value, depth + 1))),
                    depth,
                    pretty,
                    output,
                    &mut pending,
                )?;
            }
            WritePart::Typed(CircuitValue::Other(value), depth) => {
                pending.push(WritePart::Plain(value, depth))
            }
            WritePart::Typed(CircuitValue::Float(value), _) if audit && !value.is_finite() => {
                output.write_str("null")?
            }
            WritePart::Typed(CircuitValue::Float(value), _) if value.is_nan() => {
                output.write_str("NaN")?
            }
            WritePart::Typed(CircuitValue::Float(value), _) if value.is_infinite() => output
                .write_str(if value.is_sign_negative() {
                    "-Infinity"
                } else {
                    "Infinity"
                })?,
            WritePart::Typed(CircuitValue::Integer(value), _) => write!(output, "{value}")?,
            WritePart::Typed(value, _) => {
                crate::python_json::write(&value.json().map_err(|_| fmt::Error)?, output)?
            }
            WritePart::Plain(Value::Array(values), depth) => {
                array_parts(
                    values
                        .iter()
                        .map(|value| WritePart::Plain(value, depth + 1)),
                    depth,
                    pretty,
                    output,
                    &mut pending,
                )?;
            }
            WritePart::Plain(Value::Object(values), depth) => {
                object_parts(
                    values
                        .iter()
                        .map(|(key, value)| (key.as_str(), WritePart::Plain(value, depth + 1))),
                    depth,
                    pretty,
                    output,
                    &mut pending,
                )?;
            }
            WritePart::Plain(Value::Number(value), _)
                if audit
                    && value.to_string().contains(['.', 'e', 'E'])
                    && value.as_f64().is_none() =>
            {
                // Arbitrary-precision JSON retains floating overflow tokens
                // such as 1e400. Huge integer tokens must never pass through
                // this floating-point conversion or lose their exact digits.
                output.write_str("null")?
            }
            WritePart::Plain(value, _) => crate::python_json::write(value, output)?,
            WritePart::Key(value) => {
                crate::python_json::write(&Value::String(value.into()), output)?
            }
            WritePart::Text(value) => output.write_str(value)?,
            WritePart::Indent(depth) => {
                output.write_char('\n')?;
                for _ in 0..depth {
                    output.write_str("  ")?;
                }
            }
        }
    }
    Ok(())
}
fn array_parts<'a>(
    values: impl DoubleEndedIterator<Item = WritePart<'a>> + ExactSizeIterator,
    depth: usize,
    pretty: bool,
    output: &mut impl fmt::Write,
    pending: &mut Vec<WritePart<'a>>,
) -> fmt::Result {
    output.write_char('[')?;
    pending.push(WritePart::Text("]"));
    if pretty && values.len() != 0 {
        pending.push(WritePart::Indent(depth));
    }
    for (index, value) in values.enumerate().rev() {
        pending.push(value);
        if pretty {
            pending.push(WritePart::Indent(depth + 1));
        }
        if index != 0 {
            pending.push(WritePart::Text(if pretty { "," } else { ", " }));
        }
    }
    Ok(())
}
fn object_parts<'a>(
    values: impl DoubleEndedIterator<Item = (&'a str, WritePart<'a>)> + ExactSizeIterator,
    depth: usize,
    pretty: bool,
    output: &mut impl fmt::Write,
    pending: &mut Vec<WritePart<'a>>,
) -> fmt::Result {
    output.write_char('{')?;
    pending.push(WritePart::Text("}"));
    if pretty && values.len() != 0 {
        pending.push(WritePart::Indent(depth));
    }
    for (index, (key, value)) in values.enumerate().rev() {
        pending.push(value);
        pending.push(WritePart::Text(": "));
        pending.push(WritePart::Key(key));
        if pretty {
            pending.push(WritePart::Indent(depth + 1));
        }
        if index != 0 {
            pending.push(WritePart::Text(if pretty { "," } else { ", " }));
        }
    }
    Ok(())
}

fn validate_temporals(source: &CircuitValue) -> Result<()> {
    let mut pending = vec![source];
    while let Some(value) = pending.pop() {
        if value.annotated().is_some() {
            return Err(super::failure_kind(
                super::ErrorKind::Type,
                "temporal circuit operand is not JSON serializable",
            ));
        }
        match value {
            CircuitValue::Array(values) => pending.extend(values),
            CircuitValue::Object(values) => pending.extend(values.values()),
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn to_value(source: &CircuitValue) -> Result<Value> {
    validate_temporals(source)?;
    // Reject unsupported scalars before allocating a possibly deep recursive
    // serde_json tree; typed callers do not cross this compatibility boundary.
    let mut inspect = vec![source];
    while let Some(value) = inspect.pop() {
        match value {
            CircuitValue::Float(number) if !number.is_finite() => {
                value.json()?;
            }
            CircuitValue::Array(values) => inspect.extend(values),
            CircuitValue::Object(values) => inspect.extend(values.values()),
            _ => {}
        }
    }

    fn shallow(source: &CircuitValue) -> Result<Value> {
        match source {
            CircuitValue::Array(_) => Ok(Value::Array(Vec::new())),
            CircuitValue::Object(_) => Ok(Value::Object(serde_json::Map::new())),
            value => value.json(),
        }
    }
    let mut target = shallow(source)?;
    let mut pending = vec![(source, &mut target)];
    while let Some((source, target)) = pending.pop() {
        match (source, target) {
            (CircuitValue::Array(source), Value::Array(target)) => {
                for value in source {
                    target.push(shallow(value)?);
                }
                pending.extend(source.iter().zip(target.iter_mut()));
            }
            (CircuitValue::Object(source), Value::Object(target)) => {
                for (key, value) in source {
                    target.insert(key.clone(), shallow(value)?);
                }
                pending.extend(source.values().zip(target.values_mut()));
            }
            _ => {}
        }
    }
    Ok(target)
}
