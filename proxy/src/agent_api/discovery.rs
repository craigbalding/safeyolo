//! Shared discovery reporting after the existing method and bearer checks.

use std::sync::Arc;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Failure, Outcome, Request, ResponseBody, response};
use crate::{
    agent_discovery::{AgentDiscovery, ErrorKind},
    audit,
    circuits::CircuitValue,
};

pub(super) async fn respond(
    request: Request<'_>,
    discovery: Option<&Arc<AgentDiscovery>>,
    writer: Option<&Arc<audit::Writer>>,
) -> Outcome<'static> {
    let Some(discovery) = discovery else {
        return response(503, json!({"error":"service-discovery addon not loaded"}));
    };
    let Some(writer) = writer else {
        return super::unavailable(
            request,
            Failure::DiscoveryReporting(ErrorKind::Compatibility),
        );
    };
    let discovery = discovery.clone();
    let writer = writer.clone();
    let result = tokio::task::spawn_blocking(move || {
        let document = Document(
            discovery
                .get_agents(&writer, crate::circuit_runtime::now)
                .map_err(|error| error.kind())?,
        );
        document
            .0
            .render_json(false)
            .map(Zeroizing::new)
            .map_err(|_| ErrorKind::Compatibility)
    })
    .await;
    match result {
        Ok(Ok(body)) => {
            let mut outcome = response(200, Value::Null);
            outcome.response.body = ResponseBody::Circuit(body);
            outcome
        }
        Ok(Err(kind)) => failed(request, kind),
        Err(_) => super::unavailable(
            request,
            Failure::DiscoveryReporting(ErrorKind::Compatibility),
        ),
    }
}

struct Document(CircuitValue);
impl Drop for Document {
    fn drop(&mut self) {
        audit::wipe(&mut self.0);
    }
}

fn failed(request: Request<'_>, kind: ErrorKind) -> Outcome<'static> {
    let class = match kind {
        ErrorKind::Attribute => "AttributeError",
        ErrorKind::Type => "TypeError",
        ErrorKind::UnicodeDecode => "UnicodeDecodeError",
        ErrorKind::Value => "ValueError",
        ErrorKind::Permission => "PermissionError",
        ErrorKind::Io => "OSError",
        ErrorKind::Audit(audit::ErrorKind::Io) => "OSError",
        ErrorKind::Audit(_) => "RuntimeError",
        ErrorKind::Compatibility | ErrorKind::Poisoned => {
            return super::unavailable(request, Failure::DiscoveryReporting(kind));
        }
    };
    let mut outcome = response(500, json!({"error":format!("Internal error: {class}")}));
    outcome.failure = Some(Failure::DiscoveryReporting(kind));
    outcome
}
