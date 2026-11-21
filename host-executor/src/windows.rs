//! Windows uses a separate ordinary workload account, protected named pipes and
//! kill-on-close Job Objects. The account's filesystem, registry, network and
//! delegated service permissions are explicitly broader, not Job confinement.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

mod process;
pub(crate) mod security;
mod service;
pub(crate) mod transport;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRuntime {
    /// Generic Windows Credential Manager entry owned by the executor account.
    /// Its username/password select the separate, non-administrative workload.
    pub credential: String,
    pub executable_bytes: u64,
}

impl WindowsRuntime {
    pub fn validate(&self, target: &Target, protected: &[PathBuf]) -> Result<(), Refusal> {
        target.validate().map_err(native::unavailable)?;
        require(
            self.executable_bytes > 0 && self.executable_bytes <= isize::MAX as u64,
            RefusalCode::Budget,
            "Windows executable ceiling must be finite and positive",
        )?;
        let token = security::workload(&self.credential)?;
        let identity = security::identity(&token)?;
        for path in protected {
            security::deny_workload_write(path, &token)?;
        }
        for operation in target.package.operations.values() {
            require(
                operation.execution.broader
                    == [
                        BroaderBound::Filesystem,
                        BroaderBound::Registry,
                        BroaderBound::NetworkIpc,
                        BroaderBound::DelegatedServices,
                    ]
                    .into_iter()
                    .collect(),
                RefusalCode::Unavailable,
                "Windows requires explicit broader filesystem, registry, network_ipc and delegated_services authority; Job Objects do not enforce these scopes",
            )?;
            require(
                operation.execution.identity.principal == identity.principal
                    && operation
                        .execution
                        .identity
                        .groups
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        == identity.groups.iter().collect(),
                RefusalCode::Unavailable,
                "adopted Windows SID and stable token groups differ from the workload account",
            )?;
            let execution = &operation.execution;
            let _pin = security::executable(
                &execution.executable,
                &execution.executable_sha256,
                self.executable_bytes,
                &token,
            )?;
            security::absolute_local(&PathBuf::from(&execution.working_directory))?;
            require(
                execution
                    .environment
                    .keys()
                    .map(|s| s.to_uppercase())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == execution.environment.len(),
                RefusalCode::Arguments,
                "Windows environment names are case insensitive; duplicate aliases are ambiguous",
            )?;
            if operation.arguments.is_empty() {
                process::validate_command(&operation.command(&Default::default())?)?;
            }
        }
        Ok(())
    }
    pub(crate) fn validate_command(&self, command: &Command) -> Result<(), Refusal> {
        process::validate_command(command)
    }
    pub fn reconcile(&self, ledger: &mut Ledger) -> Result<(), Refusal> {
        process::reconcile(ledger)
    }
    pub fn execute(
        &self,
        target: &Target,
        ledger: Arc<Mutex<Ledger>>,
        id: &str,
    ) -> Result<(), Refusal> {
        native::execute_job(target, ledger, id, |operation, receipt, ledger| {
            process::run(self, operation, receipt, ledger)
        })
    }
}

/// Windows-only setup commands are explicit. Password input is stdin, never an
/// argument, configuration field, diagnostic or receipt.
pub fn command(args: Vec<String>) -> Option<Result<(), Refusal>> {
    match args.first().map(String::as_str) {
        Some("credential-store") => Some(security::store_credential(&args[1..])),
        Some("identity") => Some((|| {
            require(
                args.len() == 3 && args[1] == "--credential",
                RefusalCode::Arguments,
                "identity --credential NAME",
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&security::identity(&security::workload(&args[2])?)?)
                    .map_err(native::unavailable)?
            );
            Ok(())
        })()),
        Some("service") => Some(service::dispatch(args[1..].to_vec())),
        _ => None,
    }
}
