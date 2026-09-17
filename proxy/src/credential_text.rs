//! Lossless security-header text adaptation.
//!
//! `RequestHeaders` owns the parser's ordered byte fields.  The credential
//! matcher consumes Rust text, so this module is the only boundary at which a
//! request header becomes a credential `Secret`.  Valid UTF-8 is kept as-is;
//! malformed bytes use a private, reversible scalar representation that has
//! the same one-byte identity as Python's surrogateescape subject.  There is
//! no replacement character, lossy conversion, or map fallback here.

use crate::{credential_guard, credentials::Secret};
use std::{fmt, str};

// Rust strings cannot contain Python's lone U+DCxx surrogate values.  Use one
// private-use scalar per malformed source byte instead.  The escape scalar
// lets us retain valid input that happens to use this reserved range, and is
// removed again before HMAC fingerprinting.  This representation is private
// to the detector; parser-owned bytes are still forwarded from RequestHeaders.
const SOURCE_BYTE_BASE: u32 = 0xF0000;
const SOURCE_ESCAPE: u32 = 0xF1000;

fn source_byte(byte: u8) -> char {
    char::from_u32(SOURCE_BYTE_BASE + u32::from(byte)).expect("source byte scalar")
}

fn encode_source_char(output: &mut String, value: char) {
    let scalar = value as u32;
    if scalar == SOURCE_ESCAPE || (SOURCE_BYTE_BASE..SOURCE_BYTE_BASE + 256).contains(&scalar) {
        output.push(char::from_u32(SOURCE_ESCAPE).unwrap());
    }
    output.push(value);
}

/// Convert parser bytes to source-equivalent security text. Every malformed
/// byte remains distinguishable and can be matched by a pattern containing a
/// Python-style `\\uDCxx` escape.
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
                let valid = &bytes[offset..offset + valid_len];
                // The prefix is known-valid even when the error is at EOF.
                if !valid.is_empty() {
                    let valid = str::from_utf8(valid).expect("valid UTF-8 prefix");
                    valid
                        .chars()
                        .for_each(|value| encode_source_char(&mut output, value));
                }
                offset += valid_len;
                let malformed_len = error.error_len().unwrap_or(1);
                for &byte in &bytes[offset..offset + malformed_len.min(bytes.len() - offset)] {
                    output.push(source_byte(byte));
                }
                offset += malformed_len.min(bytes.len() - offset);
            }
        }
    }
    output
}

/// Recover the source byte stream represented by security text. This is used
/// only for HMAC input; no recovered material is put in an event or response.
pub(crate) fn source_bytes(text: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(text.len());
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

/// Adapt source regex escapes for the reversible internal representation.
/// `python_pattern` intentionally rejects lone surrogates because Rust cannot
/// represent them; this small boundary adapter handles only the source
/// surrogateescape byte range and leaves the broader regex compatibility
/// contract unchanged.
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
                    value * 16 + digit.to_digit(16).unwrap()
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

/// Security text conversion failed.  This type carries no input bytes or
/// header names so parser details and credential material cannot escape in a
/// response, trace, or diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidName,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "security header name encoding is invalid",
        })
    }
}

impl std::error::Error for Error {}

/// Owned security-text fields.  The type intentionally has no `Debug`,
/// `Serialize`, or `Clone` implementation: its values are secrets and remain
/// borrowable only while a single guard call is in progress.
pub(crate) struct Headers {
    fields: Vec<Field>,
}

struct Field {
    name: String,
    value: Secret,
}

impl Headers {
    /// Convert the already grouped, parser-ordered fields without consulting
    /// `HeaderMap`.  The iterator must provide the first spelling and combine
    /// duplicate values before this boundary; no order or duplicate semantics
    /// are reconstructed here.
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

    /// Build the borrowed guard view for one request.  The returned vector is
    /// short-lived and contains references into this owner; it cannot outlive
    /// the conversion owner or be retained by guard outcomes.
    pub(crate) fn as_guard_headers(&self) -> Vec<credential_guard::Header<'_>> {
        self.fields
            .iter()
            .map(|field| credential_guard::Header {
                name: &field.name,
                value: &field.value,
            })
            .collect()
    }

    #[cfg(test)]
    fn fields(&self) -> impl Iterator<Item = (&[u8], &Secret)> {
        self.fields
            .iter()
            .map(|field| (field.name.as_bytes(), &field.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(fields: &[(&[u8], &[u8])]) -> Headers {
        Headers::from_ordered(fields.iter().copied()).unwrap()
    }

    #[test]
    fn preserves_first_spelling_order_and_combined_duplicate_bytes() {
        let headers = text(&[
            (b"X-Api-Key", b"first"),
            (b"authorization", b"Bearer key-a"),
            (b"x-api-key", b"second"),
        ]);
        let values = headers
            .fields()
            .map(|(name, value)| (name.to_owned(), value.expose_secret().as_bytes().to_owned()))
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                (b"X-Api-Key".to_vec(), b"first".to_vec()),
                (b"authorization".to_vec(), b"Bearer key-a".to_vec()),
                (b"x-api-key".to_vec(), b"second".to_vec()),
            ]
        );

        // Grouping belongs to RequestHeaders.  Supplying the grouped value
        // here must retain its bytes exactly, including comma-space.
        let grouped = text(&[(b"X-Api-Key", b"first, second")]);
        let value = grouped.fields().next().unwrap().1.expose_secret();
        assert_eq!(value, "first, second");
    }

    #[test]
    fn accepts_non_ascii_utf8_without_replacement() {
        let headers = text(&[(b"X-Label", "café🙂".as_bytes())]);
        let value = headers.fields().next().unwrap().1.expose_secret();
        assert_eq!(value, "café🙂");
    }

    #[test]
    fn rejects_invalid_name_but_preserves_invalid_value_source_bytes() {
        assert_eq!(
            Headers::from_ordered([(b"X-Name\xff".as_slice(), b"value".as_slice())]).err(),
            Some(Error::InvalidName)
        );
        let headers =
            Headers::from_ordered([(b"X-Name".as_slice(), b"value\xff".as_slice())]).unwrap();
        let value = headers.fields().next().unwrap().1.expose_secret();
        assert_eq!(source_bytes(value), b"value\xff");
        assert!(!value.contains('\u{FFFD}'));
    }

    #[test]
    fn guard_view_borrows_owned_text_and_has_no_raw_conversion_path() {
        let headers = text(&[(b"Authorization", b"Bearer key-a")]);
        let view = headers.as_guard_headers();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].name, "Authorization");
        assert_eq!(view[0].value.expose_secret(), "Bearer key-a");
    }

    #[test]
    fn source_pattern_maps_lone_surrogate_escape_without_loss() {
        let pattern = source_pattern(r"key-\uDCFF");
        assert!(pattern.contains(source_byte(0xff)));
        assert_eq!(source_bytes(&source_text(b"key-\xff")), b"key-\xff");
    }

    #[test]
    fn source_pattern_respects_backslash_parity_for_u_and_upper_u() {
        let cases = [
            // A single escape introduces the source-byte identity.
            (r"key-\uDCFF", b"key-\xff".as_slice(), true),
            // An even run escapes the slash, so the remaining spelling is
            // literal source text and must not become a byte identity.
            (r"key-\\uDCFF", b"key-\\uDCFF".as_slice(), true),
            (r"key-\\uDCFF", b"key-\xff".as_slice(), false),
            // An odd run leaves the preceding slashes literal and converts
            // the final escape.
            (r"key-\\\uDCFF", b"key-\\\xff".as_slice(), true),
            (r"key-\U0000DCFF", b"key-\xff".as_slice(), true),
            (r"key-\\U0000DCFF", b"key-\\U0000DCFF".as_slice(), true),
            (r"key-\\U0000DCFF", b"key-\xff".as_slice(), false),
            (r"key-\\\U0000DCFF", b"key-\\\xff".as_slice(), true),
        ];
        for (pattern, subject, expected) in cases {
            let adapted = source_pattern(pattern);
            let compiled = crate::inspection::compile_python_pattern(&adapted, false)
                .unwrap_or_else(|_| panic!("pattern parity case did not compile: {pattern:?}"));
            assert_eq!(
                compiled.is_match(&source_text(subject)).unwrap(),
                expected,
                "pattern parity for {pattern:?}"
            );
        }
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
    fn source_text_escapes_reserved_private_scalars_losslessly() {
        let value = "prefix\u{F0000}\u{F1000}suffix";
        assert_eq!(
            source_bytes(&source_text(value.as_bytes())),
            value.as_bytes()
        );
    }
}
