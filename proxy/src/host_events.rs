//! Best-effort host operation events in the shared SafeYolo JSONL audit log.

use std::{path::PathBuf, time::Duration};

use serde_json::Value;

use crate::{Error, audit};

fn log_settings() -> Result<(PathBuf, audit::Settings), Error> {
    if let Ok(config) = crate::native_config::read(&crate::host_platform::config_path())
        && let Some(path) = config.audit_log_path
    {
        let settings = match config.native_settings {
            Some(settings) => settings.audit.writer_settings(),
            None => audit::Settings::from_env()?,
        };
        return Ok((path, settings));
    }
    let path = std::env::var_os("SAFEYOLO_LOG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let directory = std::env::var_os("SAFEYOLO_LOGS_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::var_os("XDG_STATE_HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                                .join(".local/state")
                        })
                        .join("safeyolo")
                });
            directory.join("safeyolo.jsonl")
        });
    Ok((path, audit::Settings::from_env()?))
}

pub(crate) fn write(
    agent: &str,
    event: &str,
    kind: &str,
    summary: String,
    addon: Option<&str>,
    details: Value,
) {
    let result = (|| -> Result<(), Error> {
        let (path, settings) = log_settings()?;
        let kind = match kind {
            "agent" => audit::Kind::Agent,
            "traffic" => audit::Kind::Traffic,
            _ => return Err("host event kind is invalid".into()),
        };
        let mut event = audit::Event::new(event, kind, audit::Severity::Low, summary);
        event.agent = Some(agent.to_owned());
        event.addon = addon.map(str::to_owned);
        event.details = details.into();
        let writer = audit::Writer::new(path, settings);
        writer.emit(event)?;
        // A short host command has no process-owned proxy shutdown to drain it.
        if !writer.shutdown(Duration::from_secs(5))? {
            return Err("host audit writer did not drain".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("SafeYolo host event write failed: {error}");
    }
}
