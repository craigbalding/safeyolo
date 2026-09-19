//! Narrow host-operation boundary for native desktop presentation.
//!
//! The Rust proxy never launches a guest command itself.  When the host
//! launcher supplies the trusted SafeYolo Python interpreter, this boundary
//! invokes the fixed presenter RPC module with one validated stable agent ID.
//! Without that host capability the operation is explicitly unavailable.

use serde_json::Value;
use std::path::Path;

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
    NotFound,
    Failed,
    Protocol,
}

pub(crate) fn valid_agent_id(agent_id: &str) -> bool {
    !agent_id.is_empty()
        && agent_id.len() <= 128
        && agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn available() -> bool {
    std::env::var_os("SAFEYOLO_DESKTOP_PRESENTER_PYTHON").is_some_and(|value| {
        let path = Path::new(&value);
        path.is_absolute() && path.is_file()
    })
}

pub(crate) async fn present(agent_id: String) -> Result<Value, Error> {
    tokio::task::spawn_blocking(move || {
        let Some(python) = std::env::var_os("SAFEYOLO_DESKTOP_PRESENTER_PYTHON") else {
            return Err(Error::Unavailable);
        };
        let python = Path::new(&python);
        if !python.is_absolute() || !python.is_file() {
            return Err(Error::Unavailable);
        }
        let output = std::process::Command::new(python)
            .args([
                "-m",
                "safeyolo.desktop_presenter_rpc",
                "--agent-id",
                agent_id.as_str(),
            ])
            .output()
            .map_err(|_| Error::Unavailable)?;
        let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| Error::Protocol)?;
        if output.status.success() {
            let object = value.as_object().ok_or(Error::Protocol)?;
            for key in ["agent_id", "agent", "url", "unlock_code"] {
                if !object.get(key).is_some_and(Value::is_string) {
                    return Err(Error::Protocol);
                }
            }
            if !object.get("reused").is_some_and(Value::is_boolean) {
                return Err(Error::Protocol);
            }
            return Ok(value);
        }
        match value.get("error").and_then(Value::as_str) {
            Some("Agent not found") => Err(Error::NotFound),
            _ => Err(Error::Failed),
        }
    })
    .await
    .map_err(|_| Error::Failed)?
}
