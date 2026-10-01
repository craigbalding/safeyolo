//! Host-to-guest byte streams for native proxy features.
//!
//! Linux uses runsc's connected-FD port forwarding. macOS uses the existing
//! per-agent VZ shell bridge. Neither path opens a host TCP listener.

#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{io, path::PathBuf};
#[cfg(target_os = "macos")]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;
#[cfg(target_os = "macos")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::Command;
#[cfg(target_os = "macos")]
use tokio::process::{Child, ChildStdin, ChildStdout};

use crate::tunnels::BoxStream;

pub(crate) fn config_dir() -> PathBuf {
    std::env::var_os("SAFEYOLO_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".safeyolo")
        })
}

pub(crate) fn valid_agent_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && (bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "provider sandbox or guest port is unavailable",
    )
}

#[cfg(target_os = "linux")]
async fn port_forward_failure(child: &mut tokio::process::Child) -> io::Error {
    let mut detail = String::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(4096).read_to_string(&mut detail).await;
    }
    if detail
        .to_ascii_lowercase()
        .contains("connection was refused")
        || detail.to_ascii_lowercase().contains("connection refused")
    {
        io::Error::new(io::ErrorKind::ConnectionRefused, detail)
    } else {
        unavailable()
    }
}

/// A guest command's byte pipes with the child lifetime tied to the stream.
#[cfg(target_os = "macos")]
struct ChildStream {
    _child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

#[cfg(target_os = "macos")]
impl AsyncRead for ChildStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_read(cx, buf)
    }
}

#[cfg(target_os = "macos")]
impl AsyncWrite for ChildStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.input).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.input).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.input).poll_shutdown(cx)
    }
}

#[cfg(target_os = "macos")]
fn child_stream(mut child: Child) -> io::Result<BoxStream> {
    let input = child.stdin.take().ok_or_else(unavailable)?;
    let output = child.stdout.take().ok_or_else(unavailable)?;
    Ok(Box::new(ChildStream {
        _child: child,
        input,
        output,
    }))
}

#[cfg(target_os = "linux")]
fn userns_pid(name: &str) -> Option<u32> {
    let path = config_dir().join("agents").join(name).join("userns.pid");
    let pid = std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    // A stale holder must never redirect runsc into an unrelated namespace.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        Some(pid)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn runsc_command(name: &str) -> Command {
    let mut command = if let Some(pid) = userns_pid(name) {
        let mut command = Command::new("nsenter");
        command.args([
            "--user",
            "--net",
            "--target",
            &pid.to_string(),
            "--",
            "runsc",
        ]);
        command
    } else {
        Command::new("runsc")
    };
    let root = std::env::var_os("SAFEYOLO_RUNSC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir().join("run"));
    command.arg("--root").arg(root);
    command
}

#[cfg(target_os = "linux")]
pub(crate) async fn is_sandbox_running(name: &str) -> bool {
    if !valid_agent_name(name) {
        return false;
    }
    let output = runsc_command(name)
        .args(["state", &format!("safeyolo-{name}")])
        .output()
        .await;
    let Ok(output) = output else {
        return false;
    };
    output.status.success()
        && serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .ok()
            .and_then(|value| {
                value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("running")
}

#[cfg(target_os = "linux")]
pub(crate) async fn open_guest_port(name: &str, port: u16) -> io::Result<BoxStream> {
    use tokio::net::UnixListener;

    if !valid_agent_name(name) || port == 0 || !is_sandbox_running(name).await {
        return Err(unavailable());
    }
    let directory = tempfile::Builder::new().prefix("sy-port-").tempdir()?;
    let path = directory.path().join("stream.sock");
    let listener = UnixListener::bind(&path)?;
    let mut command = runsc_command(name);
    let mut child = command
        .args([
            "port-forward",
            "--stream",
            path.to_str().unwrap_or_default(),
            &format!("safeyolo-{name}"),
            &port.to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    // runsc donates the connected descriptor, then exits. Require success
    // before exposing the stream so a closed port remains unavailable.
    let stream = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            accepted = listener.accept() => accepted.map(|(stream, _)| stream),
            status = child.wait() => {
                if !status?.success() {
                    return Err(port_forward_failure(&mut child).await);
                }
                tokio::time::timeout(Duration::from_secs(1), listener.accept())
                    .await.map_err(|_| unavailable())?
                    .map(|(stream, _)| stream)
            }
        }
    })
    .await
    .map_err(|_| unavailable())??;
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .map_err(|_| unavailable())??;
    if !status.success() {
        return Err(port_forward_failure(&mut child).await);
    }
    Ok(Box::new(stream))
}

#[cfg(target_os = "linux")]
pub(crate) async fn exec_guest_command(name: &str, command: &str) -> io::Result<i32> {
    if !valid_agent_name(name) || !is_sandbox_running(name).await {
        return Err(unavailable());
    }
    let wrapped = format!(
        ". /etc/environment 2>/dev/null; if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    );
    let status = runsc_command(name)
        .args([
            "exec",
            "--user",
            "1000:1000",
            "--cwd",
            "/workspace",
            &format!("safeyolo-{name}"),
            "/bin/bash",
            "-lc",
            &wrapped,
        ])
        .stdin(std::process::Stdio::null())
        .status()
        .await?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(target_os = "macos")]
pub(crate) async fn is_sandbox_running(name: &str) -> bool {
    if !valid_agent_name(name) {
        return false;
    }
    let path = config_dir().join("agents").join(name).join("vm.pid");
    let Some(pid) = std::fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<i32>().ok())
    else {
        return false;
    };
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(target_os = "macos")]
pub(crate) async fn open_guest_port(name: &str, port: u16) -> io::Result<BoxStream> {
    if !valid_agent_name(name) || port == 0 || !is_sandbox_running(name).await {
        return Err(unavailable());
    }
    let shell_socket = config_dir()
        .join("data/shell-sockets")
        .join(format!("{name}.sock"));
    if !shell_socket.exists() {
        return Err(unavailable());
    }
    let key = config_dir().join("data/vm_ssh_key");
    // OpenSSH runs ProxyCommand through a shell; quote the configured path.
    let socket = shell_socket.display().to_string().replace('\'', "'\\''");
    let proxy_command = format!("nc -U '{socket}'");
    let child = Command::new("ssh")
        .args([
            "-i",
            key.to_str().unwrap_or_default(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            &format!("ProxyCommand={proxy_command}"),
            "agent@sandbox",
            &format!("exec socat - TCP:127.0.0.1:{port}"),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    child_stream(child)
}

#[cfg(target_os = "macos")]
pub(crate) async fn exec_guest_command(name: &str, command: &str) -> io::Result<i32> {
    if !valid_agent_name(name) || !is_sandbox_running(name).await {
        return Err(unavailable());
    }
    let shell_socket = config_dir()
        .join("data/shell-sockets")
        .join(format!("{name}.sock"));
    if !shell_socket.exists() {
        return Err(unavailable());
    }
    let key = config_dir().join("data/vm_ssh_key");
    let socket = shell_socket.display().to_string().replace('\'', "'\\''");
    let proxy_command = format!("nc -U '{socket}'");
    let wrapped = format!(
        ". /etc/environment 2>/dev/null; if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    );
    let status = Command::new("ssh")
        .args([
            "-i",
            key.to_str().unwrap_or_default(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            &format!("ProxyCommand={proxy_command}"),
            "agent@sandbox",
            &wrapped,
        ])
        .stdin(std::process::Stdio::null())
        .status()
        .await?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn is_sandbox_running(_name: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn open_guest_port(_name: &str, _port: u16) -> io::Result<BoxStream> {
    Err(unavailable())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn exec_guest_command(_name: &str, _command: &str) -> io::Result<i32> {
    Err(unavailable())
}
