//! Lossless security-header text adaptation.
//!
//! The HTTP parser owns ordered byte fields, while the credential and pattern
//! consumers operate on Rust text. This module is the narrow boundary between
//! those representations. It keeps ordinary valid UTF-8 unchanged, escapes
//! its bridge-private scalars, and maps every malformed source byte to a
//! private, reversible scalar. The representation has the same one-byte
//! identity as Python's `surrogateescape` subject, without putting lone
//! UTF-16 surrogates into a Rust `String`.
//!
//! Callers must provide fields already grouped with the parser's first spelling
//! and arrival order. This owner does not consult a `HeaderMap`, regroup fields,
//! or rewrite bytes for forwarding. Values are held by `credentials::Secret`
//! and can be borrowed only for the one security decision that owns this
//! adapter.

use crate::{credential_guard, credentials::Secret};
use std::{fmt, str};
use zeroize::Zeroizing;

// Keep these scalars outside the BMP so they cannot collide with ordinary
// controls or the source's U+DCxx surrogateescape range. The escape scalar is
// emitted before a real private scalar so valid Unicode input round-trips too.
const SOURCE_BYTE_BASE: u32 = 0xF0000;
const SOURCE_ESCAPE: u32 = 0xF1000;

fn source_byte(byte: u8) -> char {
    char::from_u32(SOURCE_BYTE_BASE + u32::from(byte)).expect("source byte scalar")
}

fn encode_source_char(output: &mut String, value: char) {
    let scalar = value as u32;
    if scalar == SOURCE_ESCAPE || (SOURCE_BYTE_BASE..SOURCE_BYTE_BASE + 256).contains(&scalar) {
        output.push(char::from_u32(SOURCE_ESCAPE).expect("source escape scalar"));
    }
    output.push(value);
}

/// Convert parser bytes to source-equivalent text.
///
/// Ordinary valid UTF-8 is preserved scalar-for-scalar. The bridge-private
/// scalar range is escaped so valid private scalars cannot be confused with
/// malformed source bytes. Invalid UTF-8 bytes are mapped one-for-one to
/// private scalars, including malformed multi-byte sequences; no replacement
/// character or lossy fallback is introduced.
pub(crate) fn source_text(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match str::from_utf8(&bytes[offset..]) {
            Ok(valid) => {
                valid
                    .chars()
                    .for_each(|value| encode_source_char(&mut output, value));
                break;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len != 0 {
                    let valid = str::from_utf8(&bytes[offset..offset + valid_len])
                        .expect("valid UTF-8 prefix");
                    valid
                        .chars()
                        .for_each(|value| encode_source_char(&mut output, value));
                }
                offset += valid_len;
                // `error_len == None` means the remaining suffix is an
                // incomplete sequence. Each byte still has a distinct source
                // identity under surrogateescape.
                let malformed_len = error
                    .error_len()
                    .unwrap_or(bytes.len().saturating_sub(offset));
                let malformed_len = malformed_len.min(bytes.len().saturating_sub(offset));
                for &byte in &bytes[offset..offset + malformed_len] {
                    output.push(source_byte(byte));
                }
                offset += malformed_len;
                // This is defensive for an empty malformed suffix. The
                // standard UTF-8 validator normally reports a positive length
                // or an incomplete suffix, but no malformed input may loop.
                if malformed_len == 0 && offset < bytes.len() {
                    output.push(source_byte(bytes[offset]));
                    offset += 1;
                }
            }
        }
    }
    output
}

/// Recover the source bytes represented by security text.
///
/// This is intended only for keyed fingerprint input. The returned buffer is
/// zeroized on drop and must never be placed in evidence, a response, or a
/// diagnostic. Valid private scalars are escaped by [`source_text`] before
/// this function sees them, so they remain distinct from malformed bytes.
pub(crate) fn source_bytes(text: &str) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut chars = text.chars();
    while let Some(value) = chars.next() {
        let scalar = value as u32;
        if scalar == SOURCE_ESCAPE {
            if let Some(escaped) = chars.next() {
                let escaped_scalar = escaped as u32;
                if escaped_scalar == SOURCE_ESCAPE
                    || (SOURCE_BYTE_BASE..SOURCE_BYTE_BASE + 256).contains(&escaped_scalar)
                {
                    let mut encoded = [0; 4];
                    output.extend_from_slice(escaped.encode_utf8(&mut encoded).as_bytes());
                    continue;
                }
                let mut encoded = [0; 4];
                output.extend_from_slice(value.encode_utf8(&mut encoded).as_bytes());
                output.extend_from_slice(escaped.encode_utf8(&mut encoded).as_bytes());
            } else {
                let mut encoded = [0; 4];
                output.extend_from_slice(value.encode_utf8(&mut encoded).as_bytes());
            }
        } else if (SOURCE_BYTE_BASE..SOURCE_BYTE_BASE + 256).contains(&scalar) {
            output.push((scalar - SOURCE_BYTE_BASE) as u8);
        } else {
            let mut encoded = [0; 4];
            output.extend_from_slice(value.encode_utf8(&mut encoded).as_bytes());
        }
    }
    output
}

/// Adapt Python-style surrogateescape regex escapes to the private source-byte
/// representation. Only U+DC80..U+DCFF are source bytes; all other escapes are
/// left for the existing regex compatibility compiler to handle.
pub(crate) fn source_pattern(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0;
    let mut backslash_run = 0;
    while index < chars.len() {
        if chars[index] == '\\' {
            backslash_run += 1;
        } else {
            backslash_run = 0;
        }
        if chars[index] == '\\'
            && backslash_run % 2 == 1
            && chars
                .get(index + 1)
                .is_some_and(|value| *value == 'u' || *value == 'U')
        {
            let width = if chars[index + 1] == 'u' { 4 } else { 8 };
            let end = index + 2 + width;
            if let Some(digits) = chars.get(index + 2..end)
                && digits.iter().all(char::is_ascii_hexdigit)
            {
                let value = digits.iter().fold(0_u32, |value, digit| {
                    value * 16 + digit.to_digit(16).expect("checked hex digit")
                });
                if (0xDC80..=0xDCFF).contains(&value) {
                    output.push(source_byte((value - 0xDC00) as u8));
                    index = end;
                    backslash_run = 0;
                    continue;
                }
            }
        }
        encode_source_char(&mut output, chars[index]);
        index += 1;
    }
    output
}

/// A parser-ordered, source-text header owner.
///
/// Header names must be ASCII, as required by HTTP field-name syntax. Values
/// may contain malformed bytes because the source detector accepts
/// surrogateescaped text. The adapter retains no parser map and exposes no
/// debug/serialization implementation that could accidentally disclose a
/// credential.
pub(crate) struct Headers {
    fields: Vec<Field>,
}

struct Field {
    name: String,
    value: Secret,
}

/// Conversion failures intentionally contain only a category, never source
/// bytes, names, parser diagnostics, or credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidName,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("security header name encoding is invalid")
    }
}

impl std::error::Error for Error {}

impl Headers {
    /// Take parser-owned fields in their existing grouped order.
    pub(crate) fn from_ordered<'a>(
        fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    ) -> Result<Self, Error> {
        let fields = fields
            .into_iter()
            .map(|(name, value)| {
                let name = str::from_utf8(name).map_err(|_| Error::InvalidName)?;
                if !name.is_ascii() {
                    return Err(Error::InvalidName);
                }
                Ok(Field {
                    name: name.to_owned(),
                    value: Secret::new(source_text(value)),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self { fields })
    }

    /// Borrow source-text fields for exactly one consumer call. The returned
    /// iterator cannot outlive this owner; consumers must not retain values.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &Secret)> {
        self.fields
            .iter()
            .map(|field| (field.name.as_str(), &field.value))
    }

    /// Compatibility view for the existing guard caller. The returned
    /// references borrow this owner and cannot outlive the decision that uses
    /// them.
    pub(crate) fn as_guard_headers(&self) -> Vec<credential_guard::Header<'_>> {
        self.iter()
            .map(|(name, value)| credential_guard::Header { name, value })
            .collect()
    }

    #[cfg(test)]
    fn values(&self) -> impl Iterator<Item = (&str, &Secret)> {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_regex::Regex;

    fn headers(fields: &[(&[u8], &[u8])]) -> Headers {
        Headers::from_ordered(fields.iter().copied()).expect("valid header names")
    }

    #[test]
    fn preserves_parser_order_and_first_spelling_without_regrouping() {
        let fields = headers(&[
            (b"X-Api-Key", b"first"),
            (b"Authorization", b"Bearer key-a"),
            (b"x-api-key", b"second"),
        ]);
        let values = fields
            .values()
            .map(|(name, value)| (name, value.expose_secret()))
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                ("X-Api-Key", "first"),
                ("Authorization", "Bearer key-a"),
                ("x-api-key", "second"),
            ]
        );

        // Duplicate grouping belongs to the parser owner. A grouped value is
        // retained byte-for-byte, including the source comma-space separator.
        let grouped = headers(&[(b"X-Api-Key", b"first, second")]);
        assert_eq!(
            grouped.values().next().unwrap().1.expose_secret(),
            "first, second"
        );
    }

    #[test]
    fn preserves_valid_unicode_and_rejects_non_ascii_field_names() {
        let fields = headers(&[(b"X-Label", "café🙂".as_bytes())]);
        assert_eq!(fields.values().next().unwrap().1.expose_secret(), "café🙂");
        assert_eq!(
            Headers::from_ordered([(b"X-Name\xff".as_slice(), b"value".as_slice())]).err(),
            Some(Error::InvalidName)
        );
        assert_eq!(
            Headers::from_ordered([("X-é".as_bytes(), b"value".as_slice())]).err(),
            Some(Error::InvalidName)
        );
    }

    #[test]
    fn malformed_values_round_trip_without_replacement_or_loss() {
        for bytes in [
            b"prefix\xffsuffix".as_slice(),
            b"\xc3\x28".as_slice(),
            b"\xe2\x82".as_slice(),
            b"\xf0\x28\x8c\xbc".as_slice(),
            &[0_u8, 0x7f, 0x80, 0xff],
        ] {
            let text = source_text(bytes);
            assert!(!text.contains('\u{fffd}'));
            assert_eq!(source_bytes(&text).as_slice(), bytes);
            let fields = headers(&[(b"Authorization", bytes)]);
            assert_eq!(
                source_bytes(fields.values().next().unwrap().1.expose_secret()).as_slice(),
                bytes
            );
        }
    }

    #[test]
    fn source_pattern_matches_surrogateescape_and_preserves_backslash_parity() {
        let matching = Regex::new(&source_pattern(r"key-\uDCFF")).unwrap();
        assert!(matching.is_match(&source_text(b"key-\xff")).unwrap());

        // The even backslash run makes the source spelling literal. A raw
        // invalid byte must not match this pattern.
        let literal = Regex::new(&source_pattern(r"key-\\uDCFF")).unwrap();
        assert!(!literal.is_match(&source_text(b"key-\xff")).unwrap());
        assert!(literal.is_match(&source_text(b"key-\\uDCFF")).unwrap());

        let triple = Regex::new(&source_pattern(r"key-\\\uDCFF")).unwrap();
        assert!(triple.is_match(&source_text(b"key-\\\xff")).unwrap());
    }

    #[test]
    #[ignore = "runs the source Python regex oracle when SAFEYOLO_POLICY_PYTHON is set"]
    fn source_pattern_backslash_parity_matches_python_oracle() {
        use std::{env, path::PathBuf, process::Command};

        let python = env::var_os("SAFEYOLO_POLICY_PYTHON")
            .expect("SAFEYOLO_POLICY_PYTHON must point to the source Python runtime");
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("credential_text_source_oracle.py");
        let output = Command::new(python)
            .arg(script)
            .output()
            .expect("run source regex oracle");
        assert!(
            output.status.success(),
            "source oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(rows.len(), 136, "source oracle lost exhaustive byte rows");
        for row in rows {
            let pattern = row["pattern"].as_str().unwrap();
            let bytes = row["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|byte| byte.as_u64().unwrap() as u8)
                .collect::<Vec<_>>();
            let expected = row["matched"].as_bool().unwrap();
            let adapted = source_pattern(pattern);
            let compiled = crate::inspection::compile_python_pattern(&adapted, false)
                .unwrap_or_else(|_| panic!("pattern parity case did not compile: {pattern:?}"));
            assert_eq!(
                compiled.is_match(&source_text(&bytes)).unwrap(),
                expected,
                "pattern parity for {pattern:?}"
            );
        }
    }

    #[test]
    fn valid_private_scalars_are_escaped_before_round_trip() {
        let value = "prefix\u{F0000}\u{F1000}suffix";
        assert_eq!(
            source_bytes(&source_text(value.as_bytes())).as_slice(),
            value.as_bytes()
        );
    }
}
