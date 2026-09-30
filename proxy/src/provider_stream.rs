//! One authorized request stream through the installed Python platform transport.
//! The CLI supplies its interpreter at launch; no host TCP listener is created.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
};

use crate::tunnels::BoxStream;

struct ProviderStream {
    _child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl AsyncRead for ProviderStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProviderStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

pub(crate) async fn open(agent: &str, port: u16) -> io::Result<BoxStream> {
    let python = std::env::var_os("SAFEYOLO_PROVIDER_PYTHON").ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "provider transport is unavailable")
    })?;
    let mut child = Command::new(python)
        .args([
            "-I",
            "-B",
            "-m",
            "safeyolo.provider_stream",
            agent,
            &port.to_string(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take().expect("piped provider stdin");
    let mut stdout = child.stdout.take().expect("piped provider stdout");
    let mut ready = [0];
    // Linux port forwarding allows ten seconds each for stream acceptance
    // and command completion; leave room for both before failing unavailable.
    tokio::time::timeout(Duration::from_secs(25), stdout.read_exact(&mut ready))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "provider stream timed out"))??;
    if ready != [1] {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "provider sandbox or guest port is unavailable",
        ));
    }
    Ok(Box::new(ProviderStream {
        _child: child,
        stdin,
        stdout,
    }))
}
