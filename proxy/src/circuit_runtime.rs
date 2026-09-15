//! Circuit snapshot scheduling and current runtime ownership.

use std::{
    path::Path,
    sync::mpsc::{self, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{ConnectionIdentity, Error, Runtime, RuntimeState, circuits};

#[cfg(test)]
#[path = "circuit_runtime_tests.rs"]
mod tests;

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

/// The parser has completed the upstream message. Resolve current configuration
/// here, independently of the runtime that originally admitted the request.
pub(crate) fn completed_response(
    state: &RuntimeState,
    identity: &ConnectionIdentity,
    request_id: &str,
    host: &str,
    status: u16,
) -> bool {
    response_operation(
        state,
        Some((identity, request_id)),
        host,
        Some(status),
        false,
    )
}

pub(crate) fn local_blocked_response(state: &RuntimeState, host: &str) -> bool {
    response_operation(state, None, host, None, true)
}

fn response_operation(
    state: &RuntimeState,
    scope: Option<(&ConnectionIdentity, &str)>,
    host: &str,
    status: Option<u16>,
    prior_block: bool,
) -> bool {
    let Ok(runtime) = state.read() else {
        eprintln!("Circuit response runtime unavailable");
        return true;
    };
    let Some(policy) = runtime.policy.as_ref() else {
        return false;
    };
    let result = runtime.circuits.response_current(
        policy,
        host,
        circuits::ResponseInput {
            enabled: runtime.config.circuit_breaker_enabled,
            prior_block,
            status,
        },
        now(),
        &mut rand::random::<f64>,
    );
    let failed = match result {
        Ok(outcome) => record_transitions(&runtime, &outcome.events, scope),
        Err(error) => {
            // Shipped hook exceptions preserve the response and prior mutation.
            eprintln!("Circuit response operation failed: {:?}", error.kind());
            record_transitions(&runtime, error.events(), scope)
        }
    };
    if failed {
        // This can occur after response headers. Do not corrupt a valid body or
        // claim that the committed circuit mutation was rolled back.
        eprintln!("Circuit response evidence write failed");
    }
    failed
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
