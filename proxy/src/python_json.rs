//! Python's JSON response presentation for the shared policy/API values.
//!
//! Count before writing so token-bearing keys and strings are copied directly
//! into one allocation. The caller controls that allocation's lifetime.

use std::fmt::{self, Write};

use serde_json::Value;
use zeroize::Zeroizing;

/// A byte encoding cannot be represented as a strict Rust Unicode string.
/// Callers map this content-free error to their existing API error class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JsonEncodingError;

/// Decode JSON bytes using Python's UTF-8/16/32 BOM and byte-order detection.
/// This preserves the existing OAuth decoder's strict Unicode admission; JSON
/// syntax and escaped lone-surrogate handling belong to the caller's parser.
pub(crate) fn decode_json_text(body: &[u8]) -> Result<Zeroizing<String>, JsonEncodingError> {
    enum Encoding {
        Utf8,
        Utf16(bool),
        Utf32(bool),
    }
    let (body, encoding) = if let Some(body) = body.strip_prefix(&[0, 0, 0xfe, 0xff]) {
        (body, Encoding::Utf32(false))
    } else if let Some(body) = body.strip_prefix(&[0xff, 0xfe, 0, 0]) {
        (body, Encoding::Utf32(true))
    } else if let Some(body) = body.strip_prefix(&[0xfe, 0xff]) {
        (body, Encoding::Utf16(false))
    } else if let Some(body) = body.strip_prefix(&[0xff, 0xfe]) {
        (body, Encoding::Utf16(true))
    } else if let Some(body) = body.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        (body, Encoding::Utf8)
    } else if body.len() >= 4 && body[0] == 0 {
        (
            body,
            if body[1] == 0 {
                Encoding::Utf32(false)
            } else {
                Encoding::Utf16(false)
            },
        )
    } else if body.len() >= 4 && body[1] == 0 {
        (
            body,
            if body[2] == 0 && body[3] == 0 {
                Encoding::Utf32(true)
            } else {
                Encoding::Utf16(true)
            },
        )
    } else if body.len() == 2 && body[0] == 0 {
        (body, Encoding::Utf16(false))
    } else if body.len() == 2 && body[1] == 0 {
        (body, Encoding::Utf16(true))
    } else {
        (body, Encoding::Utf8)
    };
    let mut text = Zeroizing::new(String::new());
    match encoding {
        Encoding::Utf8 => text.push_str(std::str::from_utf8(body).map_err(|_| JsonEncodingError)?),
        Encoding::Utf16(little) => {
            if !body.len().is_multiple_of(2) {
                return Err(JsonEncodingError);
            }
            let words = body.chunks_exact(2).map(|bytes| {
                if little {
                    u16::from_le_bytes([bytes[0], bytes[1]])
                } else {
                    u16::from_be_bytes([bytes[0], bytes[1]])
                }
            });
            for character in char::decode_utf16(words) {
                text.push(character.map_err(|_| JsonEncodingError)?);
            }
        }
        Encoding::Utf32(little) => {
            if !body.len().is_multiple_of(4) {
                return Err(JsonEncodingError);
            }
            for bytes in body.chunks_exact(4) {
                let bytes: [u8; 4] = bytes.try_into().unwrap();
                let point = if little {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                };
                text.push(char::from_u32(point).ok_or(JsonEncodingError)?);
            }
        }
    }
    Ok(text)
}

struct Length(usize);
impl Write for Length {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0 = self.0.checked_add(value.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

pub(crate) fn encoded_len(value: &Value) -> usize {
    let mut length = Length(0);
    write(value, &mut length).expect("JSON response length overflow");
    length.0
}

pub(crate) fn encode(value: &Value) -> String {
    let mut output = String::with_capacity(encoded_len(value));
    write(value, &mut output).expect("String writes cannot fail");
    output
}

/// Python json.dumps(indent=2), used by the separate operator HTTP API.
/// The caller must retain these authorized bytes in its wiping response owner.
pub(crate) fn encode_indented(value: &Value) -> String {
    let mut length = Length(0);
    write_indented(value, 0, &mut length).expect("JSON response length overflow");
    let mut output = String::with_capacity(length.0);
    write_indented(value, 0, &mut output).expect("String writes cannot fail");
    output
}

fn indent(depth: usize, output: &mut impl Write) -> fmt::Result {
    output.write_char('\n')?;
    for _ in 0..depth {
        output.write_str("  ")?;
    }
    Ok(())
}

/// Render a borrowed operator response wrapper without cloning its policy.
pub(crate) fn encode_indented_fields(fields: &[(&str, &Value)]) -> String {
    let mut length = Length(0);
    write_indented_object(fields.iter().copied(), 0, &mut length)
        .expect("JSON response length overflow");
    let mut output = String::with_capacity(length.0);
    write_indented_object(fields.iter().copied(), 0, &mut output)
        .expect("String writes cannot fail");
    output
}

fn write_indented_object<'a>(
    fields: impl IntoIterator<Item = (&'a str, &'a Value)>,
    depth: usize,
    output: &mut impl Write,
) -> fmt::Result {
    output.write_char('{')?;
    let mut any = false;
    for (key, value) in fields {
        if any {
            output.write_char(',')?;
        }
        any = true;
        indent(depth + 1, output)?;
        string(key, output)?;
        output.write_str(": ")?;
        write_indented(value, depth + 1, output)?;
    }
    if any {
        indent(depth, output)?;
    }
    output.write_char('}')
}

fn write_indented(value: &Value, depth: usize, output: &mut impl Write) -> fmt::Result {
    match value {
        Value::Object(fields) => write_indented_object(
            fields.iter().map(|(key, value)| (key.as_str(), value)),
            depth,
            output,
        ),
        Value::Array(values) if !values.is_empty() => {
            output.write_char('[')?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.write_char(',')?;
                }
                indent(depth + 1, output)?;
                write_indented(value, depth + 1, output)?;
            }
            indent(depth, output)?;
            output.write_char(']')
        }
        _ => write(value, output),
    }
}

fn string(value: &str, output: &mut impl Write) -> fmt::Result {
    output.write_char('"')?;
    for character in value.chars() {
        match character {
            '"' => output.write_str("\\\"")?,
            '\\' => output.write_str("\\\\")?,
            '\u{8}' => output.write_str("\\b")?,
            '\u{c}' => output.write_str("\\f")?,
            '\n' => output.write_str("\\n")?,
            '\r' => output.write_str("\\r")?,
            '\t' => output.write_str("\\t")?,
            ' '..='~' => output.write_char(character)?,
            _ => {
                for unit in character.encode_utf16(&mut [0u16; 2]) {
                    write!(output, "\\u{unit:04x}")?;
                }
            }
        }
    }
    output.write_char('"')
}

fn number(value: &serde_json::Number, output: &mut impl Write) -> fmt::Result {
    let raw = value.to_string();
    if !raw.contains(['.', 'e', 'E']) {
        return output.write_str(&raw);
    }
    // Arbitrary-precision Number also retains input float spellings. Python
    // parses those through binary64 before dumping them; integer precision is
    // independent and must not pass through this conversion.
    let float: f64 = raw.parse().expect("JSON number is numeric");
    if float.is_sign_negative() {
        output.write_char('-')?;
    }
    if float.is_infinite() {
        return output.write_str("Infinity");
    }
    if float == 0.0 {
        return output.write_str("0.0");
    }
    let shortest = serde_json::Number::from_f64(float.abs())
        .expect("JSON numeric spelling cannot be NaN")
        .to_string();
    let (mantissa, exponent) = shortest
        .split_once('e')
        .map_or((shortest.as_str(), 0), |(mantissa, exponent)| {
            (mantissa, exponent.parse::<i32>().unwrap())
        });
    let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32;
    let mut digits = mantissa.replace('.', "");
    let leading = digits.bytes().take_while(|byte| *byte == b'0').count();
    let exponent = exponent + point - leading as i32 - 1;
    digits.drain(..leading);
    while digits.ends_with('0') {
        digits.pop();
    }
    if !(-4..16).contains(&exponent) {
        output.write_str(&digits[..1])?;
        if digits.len() > 1 {
            output.write_char('.')?;
            output.write_str(&digits[1..])?;
        }
        write!(
            output,
            "e{}{exponent:02}",
            if exponent >= 0 { "+" } else { "-" },
            exponent = exponent.abs()
        )
    } else if exponent < 0 {
        output.write_str("0.")?;
        for _ in 0..(-exponent - 1) {
            output.write_char('0')?;
        }
        output.write_str(&digits)
    } else {
        let point = exponent as usize + 1;
        if digits.len() > point {
            output.write_str(&digits[..point])?;
            output.write_char('.')?;
            output.write_str(&digits[point..])
        } else {
            output.write_str(&digits)?;
            for _ in digits.len()..point {
                output.write_char('0')?;
            }
            output.write_str(".0")
        }
    }
}

pub(crate) fn write(value: &Value, output: &mut impl Write) -> fmt::Result {
    match value {
        Value::String(value) => string(value, output),
        Value::Object(fields) => {
            output.write_char('{')?;
            for (index, (key, value)) in fields.iter().enumerate() {
                if index != 0 {
                    output.write_str(", ")?;
                }
                string(key, output)?;
                output.write_str(": ")?;
                write(value, output)?;
            }
            output.write_char('}')
        }
        Value::Array(values) => {
            output.write_char('[')?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.write_str(", ")?;
                }
                write(value, output)?;
            }
            output.write_char(']')
        }
        Value::Number(value) => number(value, output),
        Value::Bool(value) => output.write_str(if *value { "true" } else { "false" }),
        Value::Null => output.write_str("null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shared_json_preserves_order_escapes_and_python_number_presentation() {
        let value: Value = serde_json::from_str(
            r#"{"é😀\"\n": [true, null, 1e16, 1e-5, 1e-4, 1e15, -0.0, 1.23000, 18446744073709551617]}"#,
        )
        .unwrap();
        let expected = r#"{"\u00e9\ud83d\ude00\"\n": [true, null, 1e+16, 1e-05, 0.0001, 1000000000000000.0, -0.0, 1.23, 18446744073709551617]}"#;
        assert_eq!(encode(&value), expected);
        assert_eq!(encoded_len(&value), expected.len());
        for (raw, expected) in [
            ("1e999", "Infinity"),
            ("-1e999", "-Infinity"),
            ("1e-999", "0.0"),
            ("-1e-999", "-0.0"),
            ("4.9406564584124654e-324", "5e-324"),
        ] {
            assert_eq!(encode(&serde_json::from_str(raw).unwrap()), expected);
        }
    }

    #[test]
    #[ignore = "requires existing Python environment; set SAFEYOLO_POLICY_PYTHON"]
    fn json_presentation_matches_python_scalars_and_binary64_samples() {
        use std::{
            io::Write as _,
            process::{Command, Stdio},
        };
        let mut bits = vec![0, 1, u64::MAX >> 1, 1_u64 << 63];
        let mut state = 620_u64;
        for _ in 0..50_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if f64::from_bits(state).is_finite() {
                bits.push(state);
            }
        }
        for exponent in -324..=308 {
            let number: f64 = format!("1e{exponent}").parse().unwrap();
            for offset in -4_i64..=4 {
                let Some(sample) = number.to_bits().checked_add_signed(offset) else {
                    continue;
                };
                if f64::from_bits(sample).is_finite() {
                    bits.push(sample);
                    bits.push(sample | (1 << 63));
                }
            }
        }
        bits.retain(|bits| f64::from_bits(*bits).is_finite());
        let python = std::env::var("SAFEYOLO_POLICY_PYTHON").unwrap_or("python3".into());
        let mut child = Command::new(python)
            .args([
                "-c",
                r#"
import json, struct, sys
bits = json.load(sys.stdin)
numbers = [json.dumps(struct.unpack('>d', value.to_bytes(8, 'big'))[0]) for value in bits]
scalars = ''.join(chr(value) for value in range(0x110000) if not 0xd800 <= value <= 0xdfff)
print(json.dumps({'numbers': numbers, 'scalars': json.dumps(scalars)}))
"#,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&bits).unwrap())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        let source: Value = serde_json::from_slice(&result.stdout).unwrap();
        for (bits, expected) in bits.iter().zip(source["numbers"].as_array().unwrap()) {
            let actual = encode(&json!(f64::from_bits(*bits)));
            assert_eq!(actual, expected.as_str().unwrap(), "binary64 {bits:016x}");
        }
        let scalars: String = (0..=0x10ffff).filter_map(char::from_u32).collect();
        let scalar_value = Value::String(scalars);
        let actual = encode(&scalar_value);
        assert_eq!(actual, source["scalars"].as_str().unwrap());
        assert_eq!(encoded_len(&scalar_value), actual.len());
        eprintln!(
            "Python JSON oracle: {} finite binary64 values and 1,112,064 Unicode scalars",
            bits.len()
        );
    }
}

#[cfg(test)]
#[path = "python_json_byte_tests.rs"]
mod byte_tests;
