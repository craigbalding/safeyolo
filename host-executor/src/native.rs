//! Native dispatch shares authenticated durable admission across platform backends.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeRuntime {
    #[cfg(target_os = "linux")]
    Linux(crate::linux::LinuxRuntime),
    #[cfg(target_os = "macos")]
    Macos(crate::macos::MacRuntime),
    #[cfg(windows)]
    Windows(crate::windows::WindowsRuntime),
}
impl NativeRuntime {
    pub(crate) fn network_enforcement(&self, operation: &Operation) -> Vec<String> {
        #[cfg(unix)]
        if crate::endpoints::validate(operation).unwrap_or(false) {
            return crate::endpoints::disclosure();
        }
        let mut facts = match self {
            #[cfg(target_os = "linux")]
            Self::Linux(_) => crate::linux::network_enforcement(operation),
            #[cfg(target_os = "macos")]
            Self::Macos(_) => crate::macos::network_enforcement(operation),
            #[cfg(windows)]
            _ => {
                let _ = operation;
                Vec::new()
            }
        };
        facts.extend(crate::endpoints::handoff_disclosure(operation));
        facts
    }

    pub(crate) fn validate_command(&self, command: &Command) -> Result<(), Refusal> {
        #[cfg(windows)]
        match self {
            Self::Windows(runtime) => runtime.validate_command(command),
        }
        #[cfg(unix)]
        {
            let _ = command;
            Ok(())
        }
    }
    pub fn validate(&self, target: &Target, protected: &[PathBuf]) -> Result<(), Refusal> {
        #[cfg(not(target_os = "linux"))]
        require(
            target
                .package
                .operations
                .values()
                .all(|op| op.execution.dependencies.is_empty()),
            RefusalCode::Unavailable,
            "content-pinned dependency snapshots are currently supported only by the Linux backend; mutable macOS/Windows dependencies remain explicitly unsupported",
        )?;
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(runtime) => runtime.validate(target, protected),
            #[cfg(target_os = "macos")]
            Self::Macos(runtime) => runtime.validate(target, protected),
            #[cfg(windows)]
            Self::Windows(runtime) => runtime.validate(target, protected),
        }
    }
    pub fn reconcile(&self, ledger: &mut Ledger) -> Result<(), Refusal> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(runtime) => runtime.reconcile(ledger),
            #[cfg(target_os = "macos")]
            Self::Macos(runtime) => runtime.reconcile(ledger),
            #[cfg(windows)]
            Self::Windows(runtime) => runtime.reconcile(ledger),
        }
    }
    pub fn execute(
        &self,
        target: &Target,
        ledger: Arc<Mutex<Ledger>>,
        id: &str,
        protected: &[PathBuf],
    ) -> Result<(), Refusal> {
        #[cfg(windows)]
        let _ = protected;
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(runtime) => runtime.execute(target, ledger, id, protected),
            #[cfg(target_os = "macos")]
            Self::Macos(runtime) => runtime.execute(target, ledger, id, protected),
            #[cfg(windows)]
            Self::Windows(runtime) => runtime.execute(target, ledger, id),
        }
    }
}

#[cfg(unix)]
pub(crate) fn launch_refused(backend: &str, error: impl std::fmt::Display) -> NativeObservation {
    NativeObservation {
        backend: backend.into(),
        enforcement: vec![
            "native validation or listener binding refused before workload launch".into(),
        ],
        dependencies: Vec::new(),
        exit_code: None,
        signal: None,
        processes_stopped: true,
        output_truncated: false,
        termination_reason: format!("launch_refused: {error}"),
    }
}

pub(crate) fn execute_job(
    target: &Target,
    ledger: Arc<Mutex<Ledger>>,
    id: &str,
    run: impl FnOnce(&Operation, &Receipt, &Arc<Mutex<Ledger>>) -> Result<NativeObservation, Refusal>,
) -> Result<(), Refusal> {
    let receipt = {
        let mut ledger = ledger.lock().map_err(unavailable)?;
        match ledger.begin(target, id, now()) {
            Ok(receipt) => receipt,
            Err(error) => {
                let receipt = ledger.observe(id)?;
                if receipt.state == JobState::Admitted {
                    let next = if receipt.cancellation_requested {
                        JobState::Cancelled
                    } else {
                        JobState::Failed
                    };
                    ledger.finish(
                        id,
                        next,
                        true,
                        now(),
                        format!("no process launched: {error}"),
                    )?;
                }
                return Err(error);
            }
        }
    };
    match run(
        &target.package.operations[&receipt.prepared.invocation.operation_id],
        &receipt,
        &ledger,
    ) {
        Ok(native) => {
            let quiescent = native.processes_stopped;
            let next = if !quiescent {
                JobState::Uncertain
            } else if native.termination_reason == "cancelled" {
                JobState::Cancelled
            } else if native.exit_code == Some(0)
                && native.termination_reason == "exited"
                && !native.output_truncated
            {
                JobState::Completed
            } else {
                JobState::Failed
            };
            ledger.lock().map_err(unavailable)?.finish_observed(
                id,
                next,
                quiescent,
                now(),
                "native result; stdout and stderr share the bounded retained byte stream".into(),
                Some(native),
            )?;
            Ok(())
        }
        Err(error) => {
            ledger.lock().map_err(unavailable)?.finish(
                id,
                JobState::Uncertain,
                false,
                now(),
                error.to_string(),
            )?;
            Err(error)
        }
    }
}

pub(crate) fn unavailable(error: impl std::fmt::Display) -> Refusal {
    Refusal {
        code: RefusalCode::Unavailable,
        message: format!("native execution: {error}"),
    }
}
