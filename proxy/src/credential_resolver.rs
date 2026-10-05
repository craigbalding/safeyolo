//! Host-only external resolution. Local reads and OAuth remain in the encrypted
//! store; this function returns a transient value only to the injection owner.

use std::{path::Path, process::Stdio, time::Duration};

use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use crate::credentials::{ExternalReference, Secret};

// Match the existing OAuth process boundary's ten-second network deadline.
pub const TIMEOUT: Duration = Duration::from_secs(10);
// An injected HTTP header is finite. Bound a faulty provider's stdout before it
// can consume host memory; this does not limit unrelated response bodies.
const MAX_VALUE_BYTES: u64 = 65_536;

#[derive(Clone, Copy, Debug)]
pub enum Failure {
    Unavailable,
    Rejected,
    Timeout,
    InvalidValue,
}

impl Failure {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "PROVIDER_UNAVAILABLE",
            Self::Rejected => "PROVIDER_REJECTED",
            Self::Timeout => "PROVIDER_TIMEOUT",
            Self::InvalidValue => "PROVIDER_INVALID_VALUE",
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::Unavailable => {
                "Configure an available host 1Password executable with credentials provider."
            }
            Self::Rejected => {
                "1Password rejected the read. Check host authentication and the configured item reference."
            }
            Self::Timeout => {
                "1Password did not complete within 10 seconds. Check the host provider, then retry."
            }
            Self::InvalidValue => {
                "1Password returned an empty or invalid HTTP credential value. Check the selected item field."
            }
        }
    }
}

pub async fn resolve(
    reference: &ExternalReference,
    executable: Option<&Path>,
) -> Result<Secret, Failure> {
    let ExternalReference::Onepassword(reference) = reference;
    let executable = executable
        .filter(|path| path.is_absolute())
        .ok_or(Failure::Unavailable)?;
    // The host chooses the executable. There is no shell, request-supplied
    // argv, stdin, provider output in diagnostics, or fallback to local state.
    let mut child = tokio::process::Command::new(executable)
        .args(["read", "--no-newline", reference])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Failure::Unavailable)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let result = tokio::time::timeout(TIMEOUT, async {
        child
            .stdout
            .take()
            .ok_or(Failure::Unavailable)?
            .take(MAX_VALUE_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Failure::Rejected)?;
        if bytes.len() as u64 > MAX_VALUE_BYTES {
            return Err(Failure::InvalidValue);
        }
        if !child.wait().await.map_err(|_| Failure::Rejected)?.success() {
            return Err(Failure::Rejected);
        }
        let value = std::str::from_utf8(&bytes).map_err(|_| Failure::InvalidValue)?;
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(Failure::InvalidValue);
        }
        Ok(Secret::new(value))
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        failure => {
            // Keep cancellation/timeout cleanup owned and reap the exact child.
            let _ = child.kill().await;
            let _ = child.wait().await;
            failure.unwrap_or(Err(Failure::Timeout))
        }
    }
}
