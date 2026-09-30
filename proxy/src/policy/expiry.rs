//! Persist only expired host entries unchanged since the reached expiry pass.

use std::{fs, io::Write, path::Path};

use toml_edit::{DocumentMut, Item};
use zeroize::Zeroizing;

use super::{Result, invalid};

/// Runtime calls this for a TOML baseline after pruning, before addon merge or
/// compilation. Persistence does not activate policy or roll back later errors.
pub(super) fn persist_expired_hosts(
    path: &Path,
    expired: &[(Option<String>, String)],
    loaded_source: Option<&str>,
) -> Result<Option<f64>> {
    // The source read and replacement are one policy mutation. Without the
    // admin writer's lock, either side can replace the other's committed edit.
    let _lock = match crate::approvals::lock_policy(path) {
        Ok(lock) => lock,
        Err(error) => {
            warning(&error);
            return Ok(None);
        }
    };
    let source = match fs::read(path) {
        Ok(source) => Zeroizing::new(source),
        Err(error) => {
            warning(&error);
            return Ok(None);
        }
    };
    // Python's UnicodeDecodeError is outside the source OSError catch. Keep
    // decoding distinct from read I/O without rendering any policy bytes.
    let source =
        std::str::from_utf8(&source).map_err(|_| invalid("policy expiry TOML is not UTF-8"))?;
    #[cfg(test)]
    super::run_after_expiry_read();
    let same_source = loaded_source == Some(source);
    let loaded_document = loaded_source
        .filter(|loaded| *loaded != source)
        .and_then(|loaded| loaded.parse::<DocumentMut>().ok());
    let mut document = source
        .parse::<DocumentMut>()
        .map_err(|_| invalid("policy expiry TOML is invalid"))?;
    let mut changed = false;
    for (agent, host) in expired {
        if loaded_source.is_some()
            && !same_source
            && loaded_document.as_ref().is_none_or(|loaded| {
                host_item(loaded, agent.as_deref(), host).map(ToString::to_string)
                    != host_item(&document, agent.as_deref(), host).map(ToString::to_string)
            })
        {
            // An admin may have replaced this exact host after the loader
            // found it expired. Leave that newer decision for the next load.
            continue;
        }
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
        match crate::approvals::save_policy_with_metadata(path, &changed) {
            Ok(written) if same_source => return Ok(Some(super::watch::mtime(&written))),
            Ok(_) => {}
            Err(error) => warning(&error.error),
        }
    }
    Ok(None)
}

fn host_item<'a>(document: &'a DocumentMut, agent: Option<&str>, host: &str) -> Option<&'a Item> {
    let hosts = match agent {
        None => document.get("hosts"),
        Some(agent) => document
            .get("agents")
            .and_then(Item::as_table_like)
            .and_then(|agents| agents.get(agent))
            .and_then(Item::as_table_like)
            .and_then(|agent| agent.get("hosts")),
    };
    hosts
        .and_then(Item::as_table_like)
        .and_then(|hosts| hosts.get(host))
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
