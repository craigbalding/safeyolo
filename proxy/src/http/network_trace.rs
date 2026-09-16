//! Record only reached native NetworkGuard steps. These observations neither
//! authorize a request nor stand in for the other expected security checks.

use std::{io::Write, time::Instant};

use serde_json::json;

use super::PolicyRequest;
use crate::{
    Runtime,
    network_guard::{BypassReason, OutcomeKind, TraceIntent},
    trace::Step,
};

pub(super) fn observe(
    runtime: &Runtime,
    request: &PolicyRequest<'_>,
    started: Option<Instant>,
    intent: &TraceIntent,
) {
    let Some(started) = started else { return };
    let step = Step {
        addon: "network-guard".into(),
        hook: intent.hook.into(),
        state: intent.state.into(),
        outcome: intent.outcome.map(|outcome| {
            match outcome {
                OutcomeKind::Allowed => "allowed",
                OutcomeKind::Blocked => "blocked",
                OutcomeKind::Warned => "warned",
                OutcomeKind::Bypassed => "bypassed",
            }
            .into()
        }),
        reason: intent.reason.map(|reason| {
            match reason {
                BypassReason::AddonDisabled => "addon_disabled",
                BypassReason::PriorResponse => "prior_response",
                BypassReason::PolicyDisabled => "policy_disabled",
            }
            .into()
        }),
        // Source bypass helpers do not sample the decorator's timer.
        duration_us: (intent.state != "bypassed").then(|| started.elapsed().as_micros().into()),
        details: intent.status.map(|status| json!({"status":status}).into()),
        ts: crate::circuit_runtime::now(),
        connection_id: Some(request.connection_id.into()),
        method: Some(request.method.into()),
        host: Some(request.host.into()),
        port: Some(request.port.into()),
    };
    append(runtime, request, step);
}

pub(super) fn failed(runtime: &Runtime, request: &PolicyRequest<'_>, started: Option<Instant>) {
    let Some(started) = started else { return };
    append(
        runtime,
        request,
        Step {
            addon: "network-guard".into(),
            hook: if request.method == "CONNECT" {
                "http_connect"
            } else {
                "request"
            }
            .into(),
            state: "error".into(),
            outcome: None,
            // GuardError currently erases native producer categories. Do not
            // infer a Python exception class from its diagnostic message.
            reason: Some("GuardError".into()),
            duration_us: Some(started.elapsed().as_micros().into()),
            details: None,
            ts: crate::circuit_runtime::now(),
            connection_id: Some(request.connection_id.into()),
            method: Some(request.method.into()),
            host: Some(request.host.into()),
            port: Some(request.port.into()),
        },
    );
}

fn append(runtime: &Runtime, request: &PolicyRequest<'_>, step: Step) {
    if let Err(error) = runtime.traces.append(
        request.request_id,
        Some(request.agent_id),
        step,
        crate::circuit_runtime::now(),
    ) {
        // Instrumentation failure is observational and must not change the
        // already reached guard effects, response, or canonical audit stream.
        let _ = writeln!(
            std::io::stderr().lock(),
            "Trace recording failed: {:?}",
            error.kind()
        );
    }
}
