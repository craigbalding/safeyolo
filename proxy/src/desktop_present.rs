//! Narrow host-operation boundary for native desktop presentation.
//!
//! The Rust proxy never launches a guest command itself. When the host
//! launcher supplies the trusted SafeYolo Python interpreter, this boundary
//! owns one long-lived presenter helper and sends it validated stable agent
//! IDs over a line-oriented protocol. The helper must outlive each request:
//! the managed preview server is owned by its `DesktopPresenter` instance.
//! Without that host capability the operation is explicitly unavailable.

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
    NotFound,
    Failed,
    Protocol,
}

struct PresenterOwner {
    child: Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
}

static PRESENTER: Mutex<Option<PresenterOwner>> = Mutex::new(None);

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

fn spawn_presenter(python: &Path) -> Result<PresenterOwner, Error> {
    let mut child = Command::new(python)
        .args(["-m", "safeyolo.desktop_presenter_rpc", "--daemon"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Unavailable)?;
    let Some(input) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Unavailable);
    };
    let Some(output) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Unavailable);
    };
    Ok(PresenterOwner {
        child,
        input: BufWriter::new(input),
        output: BufReader::new(output),
    })
}

fn terminate_presenter(mut owner: PresenterOwner) {
    let _ = owner.child.kill();
    let _ = owner.child.wait();
}

fn decode_response(value: Value) -> Result<Value, Error> {
    if let Some(kind) = value.get("kind").and_then(Value::as_str) {
        return match kind {
            "not_found" => Err(Error::NotFound),
            "unavailable" => Err(Error::Unavailable),
            "invalid" | "failed" => Err(Error::Failed),
            _ => Err(Error::Protocol),
        };
    }
    let object = value.as_object().ok_or(Error::Protocol)?;
    for key in ["agent_id", "agent", "url", "unlock_code"] {
        if !object.get(key).is_some_and(Value::is_string) {
            return Err(Error::Protocol);
        }
    }
    if !object.get("reused").is_some_and(Value::is_boolean) {
        return Err(Error::Protocol);
    }
    Ok(value)
}

fn request(owner: &mut PresenterOwner, agent_id: &str) -> Result<Value, Error> {
    serde_json::to_writer(&mut owner.input, &json!({"agent_id": agent_id}))
        .map_err(|_| Error::Failed)?;
    owner.input.write_all(b"\n").map_err(|_| Error::Failed)?;
    owner.input.flush().map_err(|_| Error::Failed)?;
    let mut line = String::new();
    if owner
        .output
        .read_line(&mut line)
        .map_err(|_| Error::Failed)?
        == 0
    {
        return Err(Error::Failed);
    }
    let value: Value = serde_json::from_str(&line).map_err(|_| Error::Protocol)?;
    decode_response(value)
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
        let mut presenter = PRESENTER.lock().map_err(|_| Error::Failed)?;
        if presenter.is_none() {
            *presenter = Some(spawn_presenter(python)?);
        }
        let result = request(
            presenter.as_mut().expect("presenter initialized"),
            &agent_id,
        );
        if matches!(
            result,
            Err(Error::Failed | Error::Protocol | Error::Unavailable)
        ) && let Some(owner) = presenter.take()
        {
            terminate_presenter(owner);
        }
        result
    })
    .await
    .map_err(|_| Error::Failed)?
}

/// Close the host helper and its managed previews during proxy shutdown.
pub(crate) fn shutdown() {
    let Ok(mut presenter) = PRESENTER.lock() else {
        return;
    };
    let Some(mut owner) = presenter.take() else {
        return;
    };
    let shutdown_sent = serde_json::to_writer(&mut owner.input, &json!({"shutdown": true})).is_ok()
        && owner.input.write_all(b"\n").is_ok()
        && owner.input.flush().is_ok();
    if shutdown_sent {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match owner.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
    }
    if owner.child.try_wait().ok().flatten().is_none() {
        let _ = owner.child.kill();
    }
    let _ = owner.child.wait();
}
