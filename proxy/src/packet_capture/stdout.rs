//! Pipe writes use reactor readiness, so cancelling a sink leaves no blocked worker.
use std::{
    fs::File,
    io::{self, IsTerminal, Write},
    os::{
        fd::{AsFd, AsRawFd, RawFd},
        unix::fs::FileTypeExt,
    },
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncWrite, unix::AsyncFd};

pub(super) fn open() -> io::Result<Box<dyn AsyncWrite + Unpin + Send>> {
    let file = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let kind = file.metadata()?.file_type();
    if !kind.is_fifo() && !kind.is_socket() && !file.is_terminal() {
        // Regular files and devices such as /dev/null do not support reactor
        // registration. They use the same file writer as the file adapter.
        return Ok(Box::new(tokio::fs::File::from_std(file)));
    }
    // SAFETY: file owns a live descriptor throughout these calls.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: NonblockingFile owns the descriptor and never replaces or
    // closes it before the AsyncFd is dropped and deregisters it.
    let descriptor = unsafe {
        AsyncFd::register_with_interest(
            NonblockingFile { file, flags },
            tokio::io::Interest::WRITABLE,
        )
    }?;
    Ok(Box::new(Stdout { descriptor }))
}

struct NonblockingFile {
    file: File,
    flags: libc::c_int,
}
impl AsRawFd for NonblockingFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
impl Drop for NonblockingFile {
    fn drop(&mut self) {
        // Duplicated stdout shares its open-file flags with the inherited
        // descriptor. Restore them when this sink stops, including on errors.
        // SAFETY: the owned file remains open until after this destructor.
        let _ = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, self.flags) };
    }
}
struct Stdout {
    descriptor: AsyncFd<NonblockingFile>,
}
impl AsyncWrite for Stdout {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.descriptor.poll_write_ready(context))?;
            match guard.try_io(|descriptor| (&descriptor.get_ref().file).write(bytes)) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // There is no userspace staging buffer in this writer.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(context)
    }
}
