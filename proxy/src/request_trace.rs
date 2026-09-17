//! Trusted per-request facts shared by the concrete security trace call sites.
//! This owns no dispatch, enforcement, completion decision or automatic step.

use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use zeroize::Zeroizing;

use crate::{
    ConnectionIdentity,
    circuits::CircuitValue,
    trace::{Step, TraceStore},
};

pub(crate) struct RequestTrace {
    store: Arc<TraceStore>,
    enabled: AtomicBool,
    request_id: Zeroizing<String>,
    agent: Option<Zeroizing<String>>,
    connection_id: Zeroizing<String>,
    method: String,
    host: Zeroizing<String>,
    port: u16,
}

impl RequestTrace {
    /// Construction is inert. The reached request-header hygiene operation
    /// activates this observation only after consuming the actual opt-in.
    pub(crate) fn new(
        store: Arc<TraceStore>,
        identity: &ConnectionIdentity,
        request_id: &str,
        method: &str,
        host: &str,
        port: u16,
    ) -> Self {
        Self {
            store,
            enabled: AtomicBool::new(false),
            request_id: Zeroizing::new(request_id.into()),
            agent: identity
                .request_agent()
                .map(|agent| Zeroizing::new(agent.to_owned())),
            connection_id: Zeroizing::new(identity.connection_id.clone()),
            method: method.into(),
            host: Zeroizing::new(host.into()),
            port,
        }
    }

    pub(crate) fn enable(&self, requested: bool) {
        if requested {
            self.enabled.store(true, Ordering::Release);
        }
    }

    pub(crate) fn hook(
        self: &Arc<Self>,
        addon: &'static str,
        hook: &'static str,
    ) -> Option<TraceHook> {
        self.enabled.load(Ordering::Acquire).then(|| TraceHook {
            request: self.clone(),
            addon,
            hook,
            started: Instant::now(),
        })
    }
}

/// A timer for a concrete reached hook. Drop emits nothing: callers know which
/// decision, exception or skipped operation actually occurred.
pub(crate) struct TraceHook {
    request: Arc<RequestTrace>,
    addon: &'static str,
    hook: &'static str,
    started: Instant,
}

impl TraceHook {
    pub(crate) fn evaluated(&self, outcome: &str, details: Option<CircuitValue>) {
        self.append("evaluated", Some(outcome), None, details, true);
    }

    pub(crate) fn bypassed(&self, reason: &str) {
        // The source bypass helper does not read its decorator's timer.
        self.append("bypassed", None, Some(reason), None, false);
    }

    pub(crate) fn error(&self, reason: &str) {
        self.append("error", None, Some(reason), None, true);
    }

    pub(crate) fn untimed_error(&self, reason: &str, details: Option<CircuitValue>) {
        self.append("error", None, Some(reason), details, false);
    }

    fn append(
        &self,
        state: &str,
        outcome: Option<&str>,
        reason: Option<&str>,
        details: Option<CircuitValue>,
        timed: bool,
    ) {
        let step = Step {
            addon: self.addon.into(),
            hook: self.hook.into(),
            state: state.into(),
            outcome: outcome.map(str::to_owned),
            reason: reason.map(str::to_owned),
            duration_us: timed.then(|| self.started.elapsed().as_micros().into()),
            details,
            ts: crate::circuit_runtime::now(),
            connection_id: Some(self.request.connection_id.to_string()),
            method: Some(self.request.method.clone()),
            host: Some(self.request.host.to_string()),
            port: Some(self.request.port.into()),
        };
        if let Err(error) = self.request.store.append(
            &self.request.request_id,
            self.request.agent.as_deref().map(String::as_str),
            step,
            crate::circuit_runtime::now(),
        ) {
            // Trace failures must not change enforcement, canonical audit,
            // completion ownership, response bytes or evidence flags.
            let _ = writeln!(
                std::io::stderr().lock(),
                "Trace recording failed: {:?}",
                error.kind()
            );
        }
    }
}
