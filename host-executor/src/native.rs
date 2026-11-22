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
    ) -> Result<(), Refusal> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(runtime) => runtime.execute(target, ledger, id),
            #[cfg(target_os = "macos")]
            Self::Macos(runtime) => runtime.execute(target, ledger, id),
            #[cfg(windows)]
            Self::Windows(runtime) => runtime.execute(target, ledger, id),
        }
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
