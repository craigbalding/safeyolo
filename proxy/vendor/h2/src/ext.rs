//! Extensions specific to the HTTP/2 protocol.

mod completion;

pub(crate) use completion::ResponseCompletionProducer;
pub use completion::{on_response_complete, Aborted, ResponseCompletion};

use crate::hpack::BytesStr;

use bytes::Bytes;
use std::fmt;

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Ordered regular fields captured by the HPACK decoder before map grouping.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OriginalHeaderFields(pub(crate) Vec<(http::HeaderName, http::HeaderValue)>);
impl OriginalHeaderFields {
    /// Borrow the decoded field name/value bytes in arrival order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str().as_bytes(), value.as_bytes()))
    }
}
impl fmt::Debug for OriginalHeaderFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginalHeaderFields")
            .field("count", &self.0.len())
            .finish_non_exhaustive()
    }
}
