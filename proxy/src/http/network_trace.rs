//! Map only reached native NetworkGuard decisions into the shared request trace.

use serde_json::json;

use crate::{
    network_guard::{BypassReason, OutcomeKind, TraceIntent},
    request_trace::TraceHook,
};

pub(super) fn observe(trace: Option<&TraceHook>, intent: &TraceIntent) {
    let Some(trace) = trace else { return };
    if let Some(reason) = intent.reason {
        trace.bypassed(match reason {
            BypassReason::AddonDisabled => "addon_disabled",
            BypassReason::PriorResponse => "prior_response",
            BypassReason::PolicyDisabled => "policy_disabled",
        });
    } else if let Some(outcome) = intent.outcome {
        trace.evaluated(
            match outcome {
                OutcomeKind::Allowed => "allowed",
                OutcomeKind::Blocked => "blocked",
                OutcomeKind::Warned => "warned",
                OutcomeKind::Bypassed => "bypassed",
            },
            intent.status.map(|status| json!({"status":status}).into()),
        );
    }
}
