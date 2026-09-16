//! Circuit snapshot scheduling and current runtime ownership.

use std::{
    path::Path,
    sync::{
        Arc,
        mpsc::{self, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    ConnectionIdentity, Error, Runtime, RuntimeState, circuits,
    request_trace::{RequestTrace, TraceHook},
};

#[cfg(test)]
#[path = "circuit_runtime_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "circuit_runtime/trace_tests.rs"]
mod trace_tests;

pub(crate) fn now() -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    }
}

pub(crate) fn state_path(config: &crate::Config) -> Option<&Path> {
    config
        .circuit_state_file
        .as_deref()
        .filter(|path| !path.as_os_str().is_empty())
}

/// Transition metadata comes from the circuit operation, never upstream headers.
pub(crate) fn record_transition(
    runtime: &Runtime,
    transition: &circuits::Transition,
    scope: Option<(&ConnectionIdentity, &str)>,
) -> Result<(), Error> {
    let scope = scope.filter(|_| transition.event.response_scoped());
    let mut fields = indexmap::IndexMap::from([
        ("event".into(), serde_json::json!("proxy.circuit").into()),
        (
            "audit_intent".into(),
            serde_json::json!(format!("ops.circuit_breaker.{}", transition.event.as_str())).into(),
        ),
        ("kind".into(), serde_json::json!("ops").into()),
        ("severity".into(), serde_json::json!("medium").into()),
        ("addon".into(), serde_json::json!("circuit-breaker").into()),
        ("host".into(), serde_json::json!(transition.domain).into()),
        (
            "summary".into(),
            serde_json::json!(format!(
                "Circuit {} for {}",
                transition.event.as_str(),
                crate::network_guard::sanitize(&transition.domain),
            ))
            .into(),
        ),
        (
            "details".into(),
            transition
                .details
                .as_ref()
                .map(|details| circuits::CircuitValue::Object(details.clone()))
                .unwrap_or_else(|| serde_json::json!({}).into()),
        ),
    ]);
    fields.insert(
        "request_id".into(),
        serde_json::json!(scope.map(|(_, request_id)| request_id)).into(),
    );
    fields.insert(
        "agent".into(),
        serde_json::json!(scope.map(|(identity, _)| &identity.agent_id)).into(),
    );
    let bytes = circuits::CircuitValue::Object(fields)
        .render_audit_json()?
        .into_bytes();
    runtime.record_bytes(bytes)
}

pub(crate) fn record_transitions(
    runtime: &Runtime,
    transitions: &[circuits::Transition],
    scope: Option<(&ConnectionIdentity, &str)>,
) -> bool {
    let mut failed = false;
    for transition in transitions {
        failed |= record_transition(runtime, transition, scope).is_err();
    }
    failed
}

/// A source hook or synchronous audit submission exception stops later
/// production children. Diagnostic and worker sink failures remain separate.
pub(crate) enum ResponseOutcome {
    Complete { evidence_failed: bool },
    Exception { evidence_failed: bool },
}

impl ResponseOutcome {
    pub(crate) fn evidence_failed(&self) -> bool {
        match self {
            Self::Complete { evidence_failed } | Self::Exception { evidence_failed } => {
                *evidence_failed
            }
        }
    }
}

/// The parser has completed the upstream message. Resolve current configuration
/// here, independently of the runtime that originally admitted the request.
pub(crate) fn completed_response(
    state: &RuntimeState,
    identity: &ConnectionIdentity,
    request_id: &str,
    source_metadata_reached: bool,
    host: &str,
    status: u16,
    trace: Option<&Arc<RequestTrace>>,
) -> ResponseOutcome {
    response_operation(
        state,
        Some((identity, request_id)),
        source_metadata_reached,
        host,
        Some(status),
        false,
        trace,
    )
}

pub(crate) fn local_blocked_response(
    state: &RuntimeState,
    host: &str,
    trace: Option<&Arc<RequestTrace>>,
) -> ResponseOutcome {
    response_operation(state, None, false, host, None, true, trace)
}

fn response_operation(
    state: &RuntimeState,
    scope: Option<(&ConnectionIdentity, &str)>,
    source_metadata_reached: bool,
    host: &str,
    status: Option<u16>,
    prior_block: bool,
    trace: Option<&Arc<RequestTrace>>,
) -> ResponseOutcome {
    let trace = trace.and_then(|trace| trace.hook("circuit-breaker", "response"));
    let Ok(runtime) = state.read() else {
        if let Some(trace) = &trace {
            trace.error("CircuitRuntimeUnavailable");
        }
        eprintln!("Circuit response runtime unavailable");
        return ResponseOutcome::Exception {
            evidence_failed: true,
        };
    };
    let Some(policy) = runtime.policy.as_ref() else {
        return ResponseOutcome::Complete {
            evidence_failed: false,
        };
    };
    let source_scope = scope.filter(|_| source_metadata_reached);
    let audit = circuits::Audit::new(
        &runtime.audit,
        source_scope.map(|(_, request_id)| request_id),
        source_scope.map(|(identity, _)| identity.agent_id.as_str()),
    );
    let result = runtime.circuits.response_current_with_audit(
        policy,
        host,
        circuits::ResponseInput {
            enabled: runtime.config.circuit_breaker_enabled,
            prior_block,
            status,
        },
        now(),
        &mut rand::random::<f64>,
        &audit,
    );
    let outcome = match result {
        Ok(outcome) => {
            trace_response_decision(trace.as_ref(), outcome.value, status);
            ResponseOutcome::Complete {
                evidence_failed: record_transitions(&runtime, &outcome.events, scope),
            }
        }
        Err(error) => {
            trace_error(trace.as_ref(), &error);
            // Preserve emitted transitions and committed state, but the shared
            // ProductionAddons exception boundary skips later response hooks.
            eprintln!("Circuit response operation failed: {:?}", error.kind());
            ResponseOutcome::Exception {
                evidence_failed: record_transitions(&runtime, error.events(), scope),
            }
        }
    };
    if outcome.evidence_failed() {
        // This can occur after response headers. Do not corrupt a valid body or
        // claim that the committed circuit mutation was rolled back.
        eprintln!("Circuit response evidence write failed");
    }
    outcome
}

/// Observe a reached nonblocked request decision without querying state again.
/// A blocked core decision is incomplete until the caller constructs its reply.
pub(crate) fn trace_request_decision(
    trace: Option<&TraceHook>,
    decision: &circuits::RequestDecision,
) {
    use circuits::{RequestDecision, State};
    let Some(trace) = trace else { return };
    match decision {
        RequestDecision::AddonDisabled => trace.bypassed("addon_disabled"),
        RequestDecision::PriorResponse => trace.bypassed("prior_response"),
        RequestDecision::PolicyDisabled => trace.bypassed("policy_disabled"),
        RequestDecision::ExcludedDomain => trace.evaluated("excluded_domain", None),
        RequestDecision::Allowed { status } => {
            let state = match status.state {
                State::Closed => "closed",
                State::Open => "open",
                State::HalfOpen => "half_open",
            };
            trace.evaluated(
                "allowed",
                Some(serde_json::json!({"circuit_state":state}).into()),
            );
        }
        RequestDecision::Blocked { .. } => (),
    }
}

/// Call only after the canonical denial audit and response construction succeed.
pub(crate) fn trace_request_blocked(trace: Option<&TraceHook>) {
    if let Some(trace) = trace {
        trace.evaluated("blocked", Some(serde_json::json!({"status":503}).into()));
    }
}

fn trace_response_decision(
    trace: Option<&TraceHook>,
    decision: circuits::ResponseDecision,
    status: Option<u16>,
) {
    use circuits::ResponseDecision;
    let Some(trace) = trace else { return };
    match decision {
        ResponseDecision::AddonDisabled => trace.bypassed("addon_disabled"),
        ResponseDecision::PriorBlock => trace.evaluated("prior_block", None),
        ResponseDecision::NoResponse => (),
        ResponseDecision::ExcludedDomain => trace.evaluated("excluded_domain", None),
        ResponseDecision::SuccessRecorded
        | ResponseDecision::FailureRecorded
        | ResponseDecision::StatusNoAction => {
            let outcome = match decision {
                ResponseDecision::SuccessRecorded => "success_recorded",
                ResponseDecision::FailureRecorded => "failure_recorded",
                ResponseDecision::StatusNoAction => "status_no_action",
                _ => unreachable!("matched response classification"),
            };
            trace.evaluated(
                outcome,
                status.map(|code| serde_json::json!({"status_code":code}).into()),
            );
        }
    }
}

/// Typed operation categories only; diagnostic text is never a class oracle.
pub(crate) fn trace_error(trace: Option<&TraceHook>, error: &circuits::Error) {
    if let Some(trace) = trace {
        let reason = match error.kind() {
            circuits::ErrorKind::Type => "TypeError",
            circuits::ErrorKind::Value => "ValueError",
            circuits::ErrorKind::Overflow => "OverflowError",
            circuits::ErrorKind::ZeroDivision => "ZeroDivisionError",
            circuits::ErrorKind::Invalid | circuits::ErrorKind::Compatibility => "CircuitError",
            circuits::ErrorKind::Audit(kind) => audit_error_reason(kind),
        };
        trace.error(reason);
    }
}

/// Canonical denial submission has the same concrete writer error boundary.
pub(crate) fn trace_audit_error(trace: Option<&TraceHook>, kind: crate::audit::ErrorKind) {
    if let Some(trace) = trace {
        trace.error(audit_error_reason(kind));
    }
}

fn audit_error_reason(kind: crate::audit::ErrorKind) -> &'static str {
    match kind {
        crate::audit::ErrorKind::ThreadStart => "RuntimeError",
        // The writer erases the concrete stderr error (including possible
        // source subclasses such as BrokenPipeError), so retain a native label.
        crate::audit::ErrorKind::Io => "AuditIo",
        crate::audit::ErrorKind::Configuration
        | crate::audit::ErrorKind::Encoding
        | crate::audit::ErrorKind::Poisoned => "AuditError",
    }
}

/// One process-owned worker. Runtime publication and snapshot path selection
/// share the read/write lock, so a save cannot pair a new state with an old path.
pub(crate) struct Snapshots {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Snapshots {
    pub(crate) fn start(state: RuntimeState) -> Result<Self, Error> {
        let (stop, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("circuit-snapshots".into())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) =
                    receiver.recv_timeout(Duration::from_secs(10))
                {
                    save_current(&state);
                }
                save_current(&state);
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub(crate) fn stop(mut self) {
        self.join();
    }

    fn join(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            eprintln!("Circuit snapshot worker failed");
        }
    }
}

impl Drop for Snapshots {
    fn drop(&mut self) {
        self.join();
    }
}

fn save_current(state: &RuntimeState) {
    let Ok(runtime) = state.read() else {
        eprintln!("Circuit snapshot runtime unavailable");
        return;
    };
    if let Some(path) = state_path(&runtime.config)
        && runtime.circuits.save_file(path, now()).is_err()
    {
        eprintln!("Circuit state snapshot failed");
    }
}

/// The failure-count wording is Python str(), including persisted nonnumeric
/// fields. Traverse containers explicitly and reuse the API's scalar repr.
pub(crate) fn count_text(value: &circuits::CircuitValue) -> Result<String, Error> {
    use circuits::CircuitValue as C;
    use serde_json::Value as J;
    enum Part<'a> {
        Circuit(&'a C, bool),
        Json(&'a J, bool),
        Quoted(&'a str),
        Text(&'static str),
    }
    let mut output = String::new();
    let mut pending = vec![Part::Circuit(value, false)];
    while let Some(part) = pending.pop() {
        match part {
            Part::Text(text) => output.push_str(text),
            Part::Quoted(text) => output.push_str(&crate::agent_api::repr(text)),
            Part::Circuit(C::Bool(value), _) | Part::Json(J::Bool(value), _) => {
                output.push_str(if *value { "True" } else { "False" });
            }
            Part::Circuit(C::Integer(value), _) => output.push_str(&value.to_string()),
            Part::Circuit(value @ C::Float(number), _) => {
                if number.is_nan() {
                    output.push_str("nan");
                } else if number.is_infinite() {
                    output.push_str(if number.is_sign_negative() {
                        "-inf"
                    } else {
                        "inf"
                    });
                } else {
                    output.push_str(&value.render_json(false)?);
                }
            }
            Part::Circuit(C::Other(value), nested) => pending.push(Part::Json(value, nested)),
            Part::Circuit(C::Array(values), _) => {
                output.push('[');
                pending.push(Part::Text("]"));
                for (index, value) in values.iter().enumerate().rev() {
                    pending.push(Part::Circuit(value, true));
                    if index != 0 {
                        pending.push(Part::Text(", "));
                    }
                }
            }
            Part::Circuit(C::Object(values), _) => {
                output.push('{');
                pending.push(Part::Text("}"));
                for (index, (key, value)) in values.iter().enumerate().rev() {
                    pending.push(Part::Circuit(value, true));
                    pending.push(Part::Text(": "));
                    pending.push(Part::Quoted(key));
                    if index != 0 {
                        pending.push(Part::Text(", "));
                    }
                }
            }
            Part::Json(J::Array(values), _) => {
                output.push('[');
                pending.push(Part::Text("]"));
                for (index, value) in values.iter().enumerate().rev() {
                    pending.push(Part::Json(value, true));
                    if index != 0 {
                        pending.push(Part::Text(", "));
                    }
                }
            }
            Part::Json(J::Object(values), _) => {
                output.push('{');
                pending.push(Part::Text("}"));
                for (index, (key, value)) in values.iter().enumerate().rev() {
                    pending.push(Part::Json(value, true));
                    pending.push(Part::Text(": "));
                    pending.push(Part::Quoted(key));
                    if index != 0 {
                        pending.push(Part::Text(", "));
                    }
                }
            }
            Part::Json(J::Null, _) => output.push_str("None"),
            Part::Json(J::String(value), nested) => {
                if nested {
                    output.push_str(&crate::agent_api::repr(value));
                } else {
                    output.push_str(value);
                }
            }
            Part::Json(value @ J::Number(_), _) => {
                let value = crate::python_json::encode(value);
                output.push_str(match value.as_str() {
                    "Infinity" => "inf",
                    "-Infinity" => "-inf",
                    _ => &value,
                });
            }
            // HTTP cache fields are JSON. A retained temporal setting cannot
            // be fabricated as an ordinary date-shaped string at this boundary.
            Part::Circuit(value @ C::Temporal(_), _) => {
                output.push_str(&value.render_json(false)?);
            }
        }
    }
    Ok(output)
}
