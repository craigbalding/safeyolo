//! Refuse to create or start an instance as host root unless the operator
//! explicitly allows it. The proxy holds the policy, the credential vault and
//! the interception CA; SECURITY.md describes it as an unprivileged process.

use std::sync::atomic::{AtomicBool, Ordering};

pub const FLAG: &str = "--dangerously-allow-root";
pub const ENVIRONMENT: &str = "SAFEYOLO_DANGEROUSLY_ALLOW_ROOT";

static ALLOWED_BY_FLAG: AtomicBool = AtomicBool::new(false);

/// Record that this process was started with `--dangerously-allow-root`.
pub fn allow_by_flag() {
    ALLOWED_BY_FLAG.store(true, Ordering::Release);
}

/// The flag or `SAFEYOLO_DANGEROUSLY_ALLOW_ROOT=1` permits running as root.
/// Child processes inherit the environment form.
pub fn allowed() -> bool {
    ALLOWED_BY_FLAG.load(Ordering::Acquire)
        || std::env::var_os(ENVIRONMENT).is_some_and(|v| v == "1")
}

fn refusal(effective_uid: u32, allowed: bool, action: &str) -> Result<(), String> {
    if effective_uid != 0 || allowed {
        return Ok(());
    }
    Err(format!(
        "Refusing to {action} as root. Nothing was started or changed. Repeat the command as your ordinary host account. To run as root anyway, add {FLAG} or set {ENVIRONMENT}=1"
    ))
}

/// `action` completes "Refusing to ... as root", for example "start the proxy".
pub fn refuse_root(action: &str) -> Result<(), crate::Error> {
    // SAFETY: geteuid has no arguments and only reads the process identity.
    refusal(unsafe { libc::geteuid() }, allowed(), action).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_refused_unless_explicitly_allowed() {
        let message = refusal(0, false, "start the proxy").unwrap_err();
        assert!(message.contains("Refusing to start the proxy as root"));
        assert!(message.contains("Nothing was started or changed"));
        assert!(message.contains(FLAG) && message.contains(ENVIRONMENT));
        assert_eq!(refusal(0, true, "start the proxy"), Ok(()));
    }

    #[test]
    fn ordinary_accounts_are_not_affected() {
        assert_eq!(refusal(1000, false, "start the proxy"), Ok(()));
        assert_eq!(refusal(1000, true, "start the proxy"), Ok(()));
    }
}
