//! Persist only the host names already removed by the reached expiry pass.

use std::{fs, io::Write, path::Path};

use toml_edit::{DocumentMut, Item};
use zeroize::Zeroizing;

use super::{Result, invalid};

/// Runtime calls this for a TOML baseline after pruning, before addon merge or
/// compilation. Persistence does not activate policy or roll back later errors.
pub(super) fn persist_expired_hosts(
    path: &Path,
    expired: &[(Option<String>, String)],
) -> Result<()> {
    let source = match fs::read(path) {
        Ok(source) => Zeroizing::new(source),
        Err(error) => {
            warning(&error);
            return Ok(());
        }
    };
    // Python's UnicodeDecodeError is outside the source OSError catch. Keep
    // decoding distinct from read I/O without rendering any policy bytes.
    let source =
        std::str::from_utf8(&source).map_err(|_| invalid("policy expiry TOML is not UTF-8"))?;
    let mut document = source
        .parse::<DocumentMut>()
        .map_err(|_| invalid("policy expiry TOML is invalid"))?;
    let mut changed = false;
    for (agent, host) in expired {
        let hosts = match agent {
            None => document.get_mut("hosts"),
            Some(agent) => document
                .get_mut("agents")
                .and_then(Item::as_table_like_mut)
                .and_then(|agents| agents.get_mut(agent))
                .and_then(Item::as_table_like_mut)
                .and_then(|agent| agent.get_mut("hosts")),
        };
        if let Some(hosts) = hosts.and_then(Item::as_table_like_mut) {
            changed |= hosts.remove(host).is_some();
        }
    }
    if changed {
        let changed = Zeroizing::new(document.to_string());
        if let Err(error) = crate::approvals::save_policy(path, &changed) {
            warning(&error.error);
        }
    }
    Ok(())
}

fn warning(error: &std::io::Error) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "Failed to prune expired hosts from TOML: {}",
        crate::network_guard::sanitize(&error.to_string())
    );
}

#[cfg(test)]
mod tests;
