//! Source AuditEvent envelopes and one lazy JSONL writer. The caller retains
//! one writer across runtime snapshots; this module performs no global setup.

mod envelope;
mod writer;

pub use envelope::{
    Approval, ApprovalType, Attribution, AttributionStatus, Decision, Event, Initiator, Kind,
    Severity,
};
pub use writer::{Settings, Submission, Writer};

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Configuration,
    ThreadStart,
    Poisoned,
    Encoding,
    Io,
}

/// Categorical diagnostics never include an event, path or environment value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(ErrorKind);

impl Error {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ErrorKind::Configuration => "audit settings invalid",
            ErrorKind::ThreadStart => "audit writer could not start",
            ErrorKind::Poisoned => "audit writer state unavailable",
            ErrorKind::Encoding => "audit event encoding failed",
            ErrorKind::Io => "audit file operation failed",
        })
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
