//! Lossless security-header text adaptation.
//!
//! `RequestHeaders` owns the parser's ordered byte fields.  The credential
//! matcher consumes Rust text, so this module is the only boundary at which a
//! request header becomes a credential `Secret`.  It deliberately accepts
//! only valid UTF-8.  An admitted invalid value is an explicit error: callers
//! must contain the request before releasing application bytes.  There is no
//! replacement character, lossy conversion, or map fallback here.

use crate::{credential_guard, credentials::Secret};
use std::{fmt, str};

/// Security text conversion failed.  This type carries no input bytes or
/// header names so parser details and credential material cannot escape in a
/// response, trace, or diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidName,
    InvalidValue,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "security header name encoding is invalid",
            Self::InvalidValue => "security header value encoding is unsupported",
        })
    }
}

impl std::error::Error for Error {}

/// Owned valid-text fields.  The type intentionally has no `Debug`,
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
                let value = str::from_utf8(value).map_err(|_| Error::InvalidValue)?;
                Ok(Field {
                    name: name.to_owned(),
                    value: Secret::new(value),
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
    fn rejects_invalid_name_and_value_without_a_successful_view() {
        assert_eq!(
            Headers::from_ordered([(b"X-Name\xff".as_slice(), b"value".as_slice())]).err(),
            Some(Error::InvalidName)
        );
        assert_eq!(
            Headers::from_ordered([(b"X-Name".as_slice(), b"value\xff".as_slice())]).err(),
            Some(Error::InvalidValue)
        );
        assert!(!Error::InvalidValue.to_string().contains("value-SECRET"));
    }

    #[test]
    fn guard_view_borrows_owned_text_and_has_no_raw_conversion_path() {
        let headers = text(&[(b"Authorization", b"Bearer key-a")]);
        let view = headers.as_guard_headers();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].name, "Authorization");
        assert_eq!(view[0].value.expose_secret(), "Bearer key-a");
    }
}
