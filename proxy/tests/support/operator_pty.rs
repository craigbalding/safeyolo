//! A real terminal for native operator interaction controls.
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) struct Terminal {
    child: tokio::process::Child,
    input: File,
    output: Arc<Mutex<Vec<u8>>>,
    changed: Arc<tokio::sync::Notify>,
    reader: tokio::task::JoinHandle<()>,
}

impl Terminal {
    pub(crate) fn start(root: &Path, args: &[&str]) -> Self {
        let (mut master, mut slave) = (-1, -1);
        let mut size = libc::winsize {
            ws_row: 40,
            ws_col: 160,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::addr_of_mut!(size),
                )
            },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let input = master.try_clone().unwrap();
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_safeyolo"));
        command
            .arg("--root")
            .arg(root)
            .args(args)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .kill_on_drop(true);
        let child = command.spawn().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let changed = Arc::new(tokio::sync::Notify::new());
        let bytes = output.clone();
        let notify = changed.clone();
        let reader = tokio::spawn(async move {
            // The owned File keeps this descriptor open and unchanged until
            // AsyncFd drops it. The input clone owns a separate descriptor.
            let terminal = unsafe { tokio::io::unix::AsyncFd::register(master) }.unwrap();
            loop {
                let mut ready = terminal.readable().await.unwrap();
                let mut buffer = [0; 4096];
                match ready.try_io(|terminal| terminal.get_ref().read(&mut buffer)) {
                    Ok(Ok(0)) => break,
                    Ok(Ok(count)) => {
                        bytes.lock().unwrap().extend_from_slice(&buffer[..count]);
                        notify.notify_one();
                    }
                    Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => break,
                    Ok(Err(error)) => panic!("terminal read failed: {error}"),
                    Err(_) => {}
                }
            }
        });
        Self {
            child,
            input,
            output,
            changed,
            reader,
        }
    }

    pub(crate) fn send(&mut self, input: &str) {
        self.input.write_all(input.as_bytes()).unwrap();
    }
    pub(crate) fn output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }
    pub(crate) fn mark(&self) -> usize {
        self.output.lock().unwrap().len()
    }

    pub(crate) async fn until(&self, after: usize, text: &str) -> String {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let output = self.output();
                if output[after..].contains(text) {
                    return output;
                }
                self.changed.notified().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "terminal did not show {text:?} after {after}: {}",
                self.output()
            )
        })
    }

    pub(crate) async fn finish(&mut self) {
        self.send("q\n");
        let status = tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("terminal did not detach: {}", self.output()))
            .unwrap();
        assert!(
            status.success(),
            "terminal exited {status}: {}",
            self.output()
        );
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
