//! Reached circuit transition submission, borrowing the process audit writer.

use crate::audit::{Event, Kind, Severity, Writer};

use super::{CircuitValue, ErrorKind, Result, Transition, failure_kind};

/// Submit at the source transition point while the circuit state lock is held.
/// Correlation is the caller's optional source flow metadata, not a new ID or
/// identity lookup. Only open/reopen/close carry it in the source envelope.
pub struct Audit<'a> {
    writer: &'a Writer,
    request_id: Option<&'a str>,
    agent: Option<&'a str>,
}

impl<'a> Audit<'a> {
    pub fn new(writer: &'a Writer, request_id: Option<&'a str>, agent: Option<&'a str>) -> Self {
        Self {
            writer,
            request_id,
            agent,
        }
    }

    pub(super) fn submit(&self, transition: &Transition) -> Result<()> {
        self.writer
            .emit(transition.audit_event(self.request_id, self.agent))
            .map(|_| ())
            .map_err(|error| {
                failure_kind(
                    ErrorKind::Audit(error.kind()),
                    "circuit audit submission failed",
                )
            })
    }
}

impl Transition {
    /// The direct source ops event has no security decision or attribution.
    pub fn audit_event(&self, request_id: Option<&str>, agent: Option<&str>) -> Event {
        let name = self.event.as_str();
        let mut event = Event::new(
            format!("ops.circuit_breaker.{name}"),
            Kind::Ops,
            Severity::Medium,
            format!(
                "Circuit {name} for {}",
                crate::network_guard::sanitize(&self.domain)
            ),
        );
        event.host = Some(self.domain.clone());
        event.addon = Some("circuit-breaker".into());
        if self.event.response_scoped() {
            event.request_id = request_id.map(str::to_owned);
            event.agent = agent.map(str::to_owned);
        }
        if let Some(details) = &self.details {
            event.details = CircuitValue::Object(details.clone());
        }
        event
    }
}

#[cfg(test)]
mod tests;
