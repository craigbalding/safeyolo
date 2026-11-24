//! Local byte pipes carry the same signed HTTP messages as Unix sockets.
//! Finite nonblocking calls use whole-request/response deadlines. One pending
//! instance remains open while a connected instance is handed to a worker,
//! preventing a pipe-name replacement gap after FIRST_PIPE_INSTANCE succeeds.
use super::{security::*, service};
use crate::{server::Configuration, *};
use std::{
    io::{Read, Write},
    mem::size_of,
    path::PathBuf,
    ptr::null_mut,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::*, System::Pipes::*,
};

static EXECUTING: AtomicUsize = AtomicUsize::new(0);
pub(crate) fn executing() -> bool {
    EXECUTING.load(Ordering::SeqCst) != 0
}
pub(crate) struct Execution;
impl Execution {
    pub(crate) fn new() -> Self {
        EXECUTING.fetch_add(1, Ordering::SeqCst);
        Self
    }
}
impl Drop for Execution {
    fn drop(&mut self) {
        EXECUTING.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct Pipe {
    handle: Handle,
    read_deadline: Instant,
    write_deadline: Instant,
    response_written: bool,
}
impl Pipe {
    fn new(name: &[u16], instances: u16, first: bool) -> Result<Self, Refusal> {
        let descriptor = private_descriptor()?;
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let handle = Handle::new(
            unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX
                        | if first {
                            FILE_FLAG_FIRST_PIPE_INSTANCE
                        } else {
                            0
                        },
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    instances as u32,
                    4096,
                    4096,
                    50,
                    &security,
                )
            },
            "create protected local control pipe",
        )?;
        Ok(Self {
            handle,
            read_deadline: Instant::now(),
            write_deadline: Instant::now(),
            response_written: false,
        })
    }
    pub(crate) fn set_read_timeout(&mut self, value: Option<Duration>) -> std::io::Result<()> {
        self.read_deadline = until(value)?;
        Ok(())
    }
    pub(crate) fn set_write_timeout(&mut self, value: Option<Duration>) -> std::io::Result<()> {
        self.write_deadline = until(value)?;
        Ok(())
    }
    fn connected(&self) -> Result<bool, Refusal> {
        if unsafe { ConnectNamedPipe(self.handle.0, null_mut()) } != 0 {
            return Ok(true);
        }
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(true),
            ERROR_PIPE_LISTENING => Ok(false),
            ERROR_NO_DATA => {
                // A client can disconnect before accept completes. Reuse the
                // pending instance without stopping unrelated native jobs.
                unsafe {
                    DisconnectNamedPipe(self.handle.0);
                }
                Ok(false)
            }
            _ => Err(error("accept control pipe")),
        }
    }
}
fn until(value: Option<Duration>) -> std::io::Result<Instant> {
    value
        .and_then(|d| Instant::now().checked_add(d))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pipe needs a finite deadline",
            )
        })
}
fn pending(deadline: Instant) -> std::io::Result<()> {
    if service::stopping() || Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "control pipe deadline/stop",
        ));
    }
    std::thread::sleep(Duration::from_millis(5));
    Ok(())
}
impl Read for Pipe {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            if service::stopping() || Instant::now() >= self.read_deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "control pipe read deadline/stop",
                ));
            }
            let mut length = 0;
            if unsafe {
                ReadFile(
                    self.handle.0,
                    bytes.as_mut_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut length,
                    null_mut(),
                )
            } != 0
                && length > 0
            {
                return Ok(length as usize);
            }
            match unsafe { GetLastError() } {
                ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED => return Ok(0),
                ERROR_NO_DATA | ERROR_SUCCESS => pending(self.read_deadline)?,
                code => return Err(std::io::Error::from_raw_os_error(code as i32)),
            }
        }
    }
}
impl Write for Pipe {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            if service::stopping() || Instant::now() >= self.write_deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "control pipe write deadline/stop",
                ));
            }
            let mut length = 0;
            if unsafe {
                WriteFile(
                    self.handle.0,
                    bytes.as_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut length,
                    null_mut(),
                )
            } != 0
            {
                if length > 0 {
                    self.response_written = true;
                    return Ok(length as usize);
                }
            } else {
                return Err(std::io::Error::last_os_error());
            }
            pending(self.write_deadline)?;
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        // FlushFileBuffers can block forever on an uncooperative client. HTTP
        // clients read Content-Length then close. Keep buffered response bytes
        // available until that close or the original bounded write deadline.
        if self.response_written {
            while !service::stopping() && Instant::now() < self.write_deadline {
                let ok = unsafe {
                    PeekNamedPipe(
                        self.handle.0,
                        null_mut(),
                        0,
                        null_mut(),
                        null_mut(),
                        null_mut(),
                    )
                };
                if ok == 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        unsafe {
            DisconnectNamedPipe(self.handle.0);
        }
    }
}

pub(crate) fn serve(
    config: PathBuf,
    state: PathBuf,
    settings: Configuration,
) -> Result<(), Refusal> {
    require(
        settings.connections < 253,
        RefusalCode::Budget,
        "Windows control pipe needs fewer than 253 workers to retain a finite instance count below the OS unlimited sentinel",
    )?;
    let mut ledger = Ledger::open(&state, &settings.target.target_id, settings.ledger.clone())?;
    let settings = crate::server::reconcile_configuration(&config, &state)?;
    settings.native.reconcile(&mut ledger)?;
    let name = wide(&format!(
        "\\\\.\\pipe\\safeyolo-host-{}",
        settings.target.target_id
    ))?;
    let mut listener = Pipe::new(&name, settings.connections + 2, true)?;
    let ledger = Arc::new(Mutex::new(ledger));
    let (tx, rx) = mpsc::sync_channel(0);
    let rx = Arc::new(Mutex::new(rx));
    let mut workers = Vec::new();
    for _ in 0..settings.connections {
        let (rx, config, state, ledger, original) = (
            rx.clone(),
            config.clone(),
            state.clone(),
            ledger.clone(),
            settings.clone(),
        );
        workers.push(std::thread::spawn(move || {
            loop {
                let stream = match rx.lock().expect("connection queue").recv() {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                if let Err(error) = server::connection(stream, &config, &state, &original, &ledger)
                {
                    eprintln!("{error}");
                }
            }
        }));
    }
    eprintln!(
        "target {} ready on {}",
        settings.target.target_id,
        String::from_utf16_lossy(&name[..name.len() - 1])
    );
    service::ready()?;
    let result = (|| {
        while !service::stopping() {
            if !listener.connected()? {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let next = Pipe::new(&name, settings.connections + 2, false)?;
            let connected = std::mem::replace(&mut listener, next);
            tx.send(connected).map_err(native::unavailable)?;
        }
        Ok(())
    })();
    service::stop();
    drop((tx, listener));
    for worker in workers {
        worker
            .join()
            .map_err(|_| native::unavailable("Windows connection worker failed"))?;
    }
    while EXECUTING.load(Ordering::SeqCst) != 0 {
        std::thread::sleep(Duration::from_millis(10));
    }
    result
}
