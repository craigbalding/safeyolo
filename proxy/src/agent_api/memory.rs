//! Global process reporting after the existing Agent API method and auth gates.

use std::sync::Arc;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Failure, Outcome, Request, ResponseBody, response};
use crate::{
    audit,
    circuits::{CircuitValue, ErrorKind as Numeric},
    memory_monitor::{ErrorKind, MemoryMonitor, MemorySample, SampleError},
};

/// One installed process owner, with explicit sampling at the reached report.
/// Production supplies the serving-process sampler and wall clock. The task
/// executes both after authorization, without reading the request body.
pub struct MemoryContext<'a> {
    pub owner: &'a Arc<MemoryMonitor>,
    pub sample: fn() -> Result<MemorySample, SampleError>,
    pub now: fn() -> f64,
}

pub(super) async fn respond(
    request: Request<'_>,
    context: Option<MemoryContext<'_>>,
) -> Outcome<'static> {
    let Some(context) = context else {
        return response(503, json!({"error":"memory-monitor addon not loaded"}));
    };
    let owner = context.owner.clone();
    let sample = context.sample;
    let now = context.now;
    let result = tokio::task::spawn_blocking(move || {
        let document = Document(owner.get_stats(sample, now).map_err(|error| error.kind())?);
        document
            .0
            .render_json(false)
            .map(Zeroizing::new)
            .map_err(|error| ErrorKind::Numeric(error.kind()))
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
            Failure::MemoryReporting(ErrorKind::Numeric(Numeric::Compatibility)),
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
        ErrorKind::Sample(SampleError::Index) => "IndexError",
        ErrorKind::Numeric(Numeric::Value) => "ValueError",
        ErrorKind::Numeric(Numeric::Overflow) => "OverflowError",
        ErrorKind::Numeric(Numeric::Type) => "TypeError",
        ErrorKind::Numeric(Numeric::ZeroDivision) => "ZeroDivisionError",
        ErrorKind::Poisoned
        | ErrorKind::Content(_)
        | ErrorKind::Audit(_)
        | ErrorKind::Numeric(_) => {
            return super::unavailable(request, Failure::MemoryReporting(kind));
        }
    };
    let mut outcome = response(500, json!({"error":format!("Internal error: {class}")}));
    outcome.failure = Some(Failure::MemoryReporting(kind));
    outcome
}
