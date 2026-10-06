//! Best-effort host operation events in the shared SafeYolo JSONL audit log.

use std::{fs::OpenOptions, io::Write, path::PathBuf};

use serde_json::{Value, json};

use crate::Error;

fn log_path() -> PathBuf {
    if let Ok(config) = crate::native_config::read(&crate::host_platform::config_path())
        && let Some(path) = config.audit_log_path
    {
        return path;
    }
    std::env::var_os("SAFEYOLO_LOG_PATH")
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
        })
}

pub(crate) fn write(
    agent: &str,
    event: &str,
    kind: &str,
    summary: String,
    addon: Option<&str>,
    details: Value,
) {
    let path = log_path();
    let result = (|| -> Result<(), Error> {
        std::fs::create_dir_all(path.parent().ok_or("host event has no parent")?)?;
        let mut value = json!({
            "schema_version":1,
            "ts":time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
            "event":event,"kind":kind,"severity":"low",
            "summary":summary,"agent":agent,"details":details
        });
        if let Some(addon) = addon {
            value["addon"] = addon.into();
        }
        let mut data = serde_json::to_vec(&value)?;
        data.push(b'\n');
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(&data)?;
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("SafeYolo host event write failed: {error}");
    }
}
