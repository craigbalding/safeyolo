//! Request-local, ordered header values captured by the existing H1/H2 parsers.
//!
//! Only this owner defines inspection order. HeaderMap still owns transport
//! fields and the HTTP implementation still owns framing/body state. Values are
//! explicit byte borrows: this module neither decodes credentials nor makes an
//! invalid UTF-8 value absent. The transport's original buffers are not wiped by
//! zeroizing this owner's copies.

use hyper::{HeaderMap, Request, Version};
use std::fmt;
use zeroize::Zeroizing;

const INTERNAL_AND_HOP: &[&[u8]] = &[
    b"x-safeyolo-request-id",
    b"x-safeyolo-trace",
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
];

// Deliberately no Debug, Serialize, Clone, or implicit textual value access.
pub(crate) struct RequestHeaders {
    fields: Vec<Field>,
}

struct Field {
    name: String,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    MissingOriginalFields,
    InvalidOriginalName,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingOriginalFields => "request header metadata unavailable",
            Self::InvalidOriginalName => "request header metadata invalid",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Hygiene {
    /// The combined trace field is nonempty. The caller retains an earlier
    /// trusted trace opt-in, if any; false does not revoke it.
    pub(crate) trace_requested: bool,
    /// Source RequestIdGenerator's header predicate, not complete WS validation.
    pub(crate) websocket: bool,
}

impl RequestHeaders {
    /// Take the appropriate parser extension exactly once, before mutations.
    /// H1 servers must enable preserve_header_case(true) for this capture.
    pub(crate) fn take<B>(request: &mut Request<B>) -> Result<Self, Error> {
        if request.version() == Version::HTTP_2 {
            let original = request
                .extensions_mut()
                .remove::<h2::ext::OriginalHeaderFields>()
                .ok_or(Error::MissingOriginalFields)?;
            Self::from_fields(original.iter())
        } else {
            let original = request
                .extensions_mut()
                .remove::<hyper::ext::OriginalHeaderFields>()
                .ok_or(Error::MissingOriginalFields)?;
            Self::from_fields(original.iter())
        }
    }

    fn from_fields<'a>(fields: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> Result<Self, Error> {
        // Group borrowed parser values first. Allocate each owned value at its
        // final size, so growing a Vec never leaves an unwiped old allocation.
        let mut grouped: Vec<(&str, Vec<&[u8]>)> = Vec::new();
        for (name, value) in fields {
            let name = std::str::from_utf8(name).map_err(|_| Error::InvalidOriginalName)?;
            if !name.is_ascii() {
                return Err(Error::InvalidOriginalName);
            }
            if let Some((_, values)) = grouped
                .iter_mut()
                .find(|(first, _)| first.eq_ignore_ascii_case(name))
            {
                values.push(value);
            } else {
                grouped.push((name, vec![value]));
            }
        }
        let fields = grouped
            .into_iter()
            .map(|(name, values)| {
                let length =
                    values.iter().map(|value| value.len()).sum::<usize>() + (values.len() - 1) * 2;
                let mut combined = Zeroizing::new(Vec::with_capacity(length));
                for (index, value) in values.into_iter().enumerate() {
                    if index != 0 {
                        combined.extend_from_slice(b", ");
                    }
                    combined.extend_from_slice(value);
                }
                Field {
                    name: name.to_owned(),
                    value: combined,
                }
            })
            .collect();
        Ok(Self { fields })
    }

    /// First name spelling/arrival position, with duplicate values joined by
    /// exactly comma-space. Callers must not log or serialize these raw values.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.fields
            .iter()
            .map(|field| (field.name.as_bytes(), field.value.as_slice()))
    }

    fn get(&self, name: &[u8]) -> &[u8] {
        self.iter()
            .find_map(|(field, value)| field.eq_ignore_ascii_case(name).then_some(value))
            .unwrap_or_default()
    }

    /// Apply the source request hook's deletions to the ordered inspection view
    /// and transport map. Surviving map values, body, and framing are untouched.
    /// Request IDs/timing and response correlation remain the caller's concern.
    pub(crate) fn apply_hygiene(&mut self, headers: &mut HeaderMap) -> Hygiene {
        let connection = self.get(b"connection");
        let facts = Hygiene {
            trace_requested: !self.get(b"x-safeyolo-trace").is_empty(),
            websocket: lower_equals_ascii(self.get(b"upgrade"), b"websocket", false)
                && connection_nominates(connection, b"upgrade"),
        };
        let remove: Vec<bool> = self
            .fields
            .iter()
            .map(|field| {
                let name = field.name.as_bytes();
                let preserve = facts.websocket
                    && (name.eq_ignore_ascii_case(b"connection")
                        || name.eq_ignore_ascii_case(b"upgrade"));
                !preserve
                    && (INTERNAL_AND_HOP
                        .iter()
                        .any(|hop| name.eq_ignore_ascii_case(hop))
                        || connection_nominates(connection, name))
            })
            .collect();
        let mut removal = remove.into_iter();
        self.fields.retain(|field| {
            if removal.next().expect("one decision per field") {
                headers.remove(field.name.as_str());
                false
            } else {
                true
            }
        });
        facts
    }
}

fn connection_nominates(raw: &[u8], name: &[u8]) -> bool {
    raw.split(|byte| *byte == b',')
        .any(|token| lower_equals_ascii(token, name, true))
}

/// Compare source UTF-8-surrogateescape str.lower() with an admitted ASCII
/// header name, without allocating a decoded copy of a header value. Invalid
/// bytes become non-whitespace, non-ASCII surrogates in Python, so such a token
/// cannot equal an ASCII name. This is only a nomination comparison: the raw
/// value remains available to the owner and is not rejected or skipped.
fn lower_equals_ascii(raw: &[u8], expected: &[u8], trim: bool) -> bool {
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let text = if trim {
        text.trim_matches(crate::policy::python_whitespace)
    } else {
        text
    };
    let mut expected = expected.iter();
    for character in text.chars() {
        // The only non-ASCII Python scalar whose lower() is entirely ASCII is
        // U+212A KELVIN SIGN. The source oracle exhaustively checks this finite
        // projection; casefold's LONG S mapping must not be used here.
        let lower = if character.is_ascii() {
            (character as u8).to_ascii_lowercase()
        } else if character == '\u{212a}' {
            b'k'
        } else {
            return false;
        };
        if expected.next().map(u8::to_ascii_lowercase) != Some(lower) {
            return false;
        }
    }
    expected.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use serde_json::{Value, json};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn view(owner: &RequestHeaders) -> Value {
        Value::Array(owner.iter().map(|(n, v)| json!([hex(n), hex(v)])).collect())
    }

    #[test]
    fn actual_source_ordered_view_and_hygiene() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/request_headers_source.json")).unwrap();
        for row in fixture["rows"].as_array().unwrap() {
            let fields: Vec<_> = row["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| {
                    (
                        unhex(field[0].as_str().unwrap()),
                        unhex(field[1].as_str().unwrap()),
                    )
                })
                .collect();
            let mut headers = HeaderMap::new();
            for (name, value) in &fields {
                headers.append(
                    HeaderName::from_bytes(name).unwrap(),
                    HeaderValue::from_bytes(value).unwrap(),
                );
            }
            let mut owner = RequestHeaders::from_fields(
                fields.iter().map(|(n, v)| (n.as_slice(), v.as_slice())),
            )
            .unwrap();
            assert_eq!(view(&owner), row["grouped"], "{} grouping", row["id"]);
            let facts = owner.apply_hygiene(&mut headers);
            assert_eq!(view(&owner), row["after_hygiene"], "{} hygiene", row["id"]);
            assert_eq!(facts.trace_requested, row["trace"], "{} trace", row["id"]);
            assert_eq!(facts.websocket, row["websocket"], "{} websocket", row["id"]);
            assert_eq!(headers.keys().count(), owner.fields.len());
            for (name, value) in &fields {
                let retained = owner.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
                let name = HeaderName::from_bytes(name).unwrap();
                assert_eq!(headers.contains_key(&name), retained, "{} map", row["id"]);
                if retained {
                    assert!(headers.get_all(&name).iter().any(|v| v.as_bytes() == value));
                }
            }
        }
    }

    #[test]
    fn missing_capture_is_an_error_for_each_protocol_without_map_fallback() {
        for version in [Version::HTTP_10, Version::HTTP_11, Version::HTTP_2] {
            let mut request = Request::builder()
                .version(version)
                .header("x-inert", "value")
                .body(b"body")
                .unwrap();
            assert!(matches!(
                RequestHeaders::take(&mut request),
                Err(Error::MissingOriginalFields)
            ));
            assert_eq!(request.headers()["x-inert"], "value");
            assert_eq!(request.body(), &b"body");
        }
    }

    #[test]
    fn source_unicode_trim_projection_and_no_value_rejection() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/request_headers_source.json")).unwrap();
        for scalar in fixture["python_whitespace"].as_array().unwrap() {
            let scalar = char::from_u32(scalar.as_u64().unwrap() as u32).unwrap();
            let text = format!("{scalar}X-REMOVE{scalar}");
            assert!(connection_nominates(text.as_bytes(), b"x-remove"));
        }
        assert!(!connection_nominates(b"x-remove\xff", b"x-remove"));
        assert!(connection_nominates(b"\xff, X-Remove", b"x-remove"));
        assert!(!connection_nominates("X-ſ".as_bytes(), b"x-s"));
        assert!(connection_nominates("X-K".as_bytes(), b"x-k"));
        assert!(!lower_equals_ascii(b" websocket ", b"websocket", false));
    }
}
