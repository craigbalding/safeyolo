//! Canonical events for the active operator mutations and authentication.

use super::{Audit, Error, Outcome, response};
use crate::{
    audit::{Event, Kind, Severity, Writer},
    network_guard::sanitize,
};
use hyper::StatusCode;
use serde_json::json;

fn event(name: &str, kind: Kind, severity: Severity, summary: String, addon: &str) -> Event {
    let mut event = Event::new(name, kind, severity, summary);
    event.addon = Some(addon.into());
    event
}

impl Audit {
    /// These source call sites supply no agent attribution, decision or approval.
    pub fn canonical_events(&self, client_ip: &str, target: &str) -> Vec<Event> {
        match self {
            Self::TrafficScopeUpdated(scope) => {
                let mut event = event(
                    "admin.traffic_scope_update",
                    Kind::Admin,
                    Severity::Low,
                    "Shared traffic scope updated".into(),
                    "admin-api",
                );
                let mut details = serde_json::Map::new();
                details.insert("client_ip".into(), json!(client_ip));
                details.extend(
                    scope
                        .fields
                        .as_object()
                        .expect("validated scope object")
                        .clone(),
                );
                event.details = serde_json::Value::Object(details).into();
                vec![event]
            }
            Self::AuthenticationFailed => {
                let mut event = event(
                    "admin.auth_failure",
                    Kind::Admin,
                    Severity::High,
                    format!(
                        "Auth failure from {} on {}",
                        sanitize(client_ip),
                        sanitize(target)
                    ),
                    "admin-api",
                );
                event.details = json!({"client_ip":client_ip,"path":target,"reason":"invalid_or_missing_token"}).into();
                vec![event]
            }
            Self::TaskUpdated {
                task_id,
                permission_count,
            } => {
                let mut event = event(
                    "admin.task_policy_update",
                    Kind::Admin,
                    Severity::Medium,
                    format!(
                        "Task policy '{}' updated: {permission_count} permissions",
                        sanitize(task_id)
                    ),
                    "admin-api",
                );
                event.details = json!({"client_ip":client_ip,"task_id":task_id,"permission_count":permission_count}).into();
                vec![event]
            }
            Self::BudgetsReset(reset) => {
                let safe = reset.safe_resource();
                let mut engine = event(
                    "admin.budget_reset",
                    Kind::Admin,
                    Severity::Medium,
                    if reset.resets_all() {
                        "All budgets reset".into()
                    } else {
                        format!("Budget reset for {safe}")
                    },
                    "policy-engine",
                );
                engine.details = json!({"resource":if reset.resets_all() { json!("all") } else { reset.resource().clone() }}).into();
                let mut admin = event(
                    "admin.budgets_reset",
                    Kind::Admin,
                    Severity::Medium,
                    format!("Budget counters reset: {safe}"),
                    "admin-api",
                );
                admin.details = json!({"client_ip":client_ip,"resource":reset.resource()}).into();
                vec![engine, admin]
            }
            Self::CircuitReset(reset) => {
                let safe = reset.safe_host();
                let summary = format!("Circuit reset for {safe}");
                let ops = if let Some(host) = reset.host().as_str() {
                    let mut ops = event(
                        "ops.circuit_breaker.reset",
                        Kind::Ops,
                        Severity::Medium,
                        summary,
                        "circuit-breaker",
                    );
                    ops.host = Some(host.into());
                    ops
                } else {
                    Event::validation_fallback(
                        "ops.circuit_breaker.reset",
                        Kind::Ops,
                        Severity::Medium,
                        summary,
                    )
                };
                let mut admin = event(
                    "admin.circuit_breaker_reset",
                    Kind::Admin,
                    Severity::Medium,
                    format!("Circuit breaker reset: {safe}"),
                    "admin-api",
                );
                admin.details = json!({"client_ip":client_ip,"host":reset.host()}).into();
                vec![ops, admin]
            }
        }
    }
}

impl Outcome {
    /// Mutations have committed. A budget-engine enqueue exception maps to the
    /// source PDP failure response; other operator enqueue exceptions terminate
    /// the handler. Async writer failures do not reach this boundary.
    pub fn submit_audit(
        self,
        writer: &Writer,
        client_ip: &str,
        target: &str,
    ) -> Result<Self, Error> {
        self.submit_audit_with(client_ip, target, |event| writer.emit(event).map(|_| ()))
    }

    fn submit_audit_with(
        self,
        client_ip: &str,
        target: &str,
        mut submit: impl FnMut(Event) -> crate::audit::Result<()>,
    ) -> Result<Self, Error> {
        if let Some(intent) = self.audit() {
            for (index, event) in intent
                .canonical_events(client_ip, target)
                .into_iter()
                .enumerate()
            {
                if let Err(error) = submit(event) {
                    if index == 0 && matches!(intent, Audit::BudgetsReset(_)) {
                        return Ok(response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({"error":"Failed to reset budget counters"}),
                        ));
                    }
                    return Err(Error::Audit(error.kind()));
                }
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
