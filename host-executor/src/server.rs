//! The standalone server keeps the shared signed HTTP routes on an explicitly
//! protected local transport. Transport access never replaces issuer authorization.
#[cfg(windows)]
use crate::windows::{security::protected, transport::Pipe as UnixStream};
use crate::*;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::{
    fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    net::{UnixListener, UnixStream},
};
#[cfg(unix)]
use std::sync::mpsc;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub target: Target,
    pub ledger: LedgerLimits,
    pub native: NativeRuntime,
    pub connections: u16,
    pub connection_timeout_seconds: u64,
}

fn unavailable(error: impl std::fmt::Display) -> Refusal {
    Refusal {
        code: RefusalCode::Unavailable,
        message: format!("host executor: {error}"),
    }
}

/// Protect the path and its parents. A workload cannot replace target inputs by
/// renaming a file in a writable parent, following a symlink or adding an alias.
#[cfg(unix)]
fn protected(path: &Path, directory: bool) -> Result<PathBuf, Refusal> {
    let canonical = path.canonicalize().map_err(unavailable)?;
    require(
        path.is_absolute() && canonical == path,
        RefusalCode::Unavailable,
        "configuration/state paths must be canonical absolute paths",
    )?;
    let uid = unsafe { libc::geteuid() };
    for parent in canonical.ancestors() {
        let meta = fs::symlink_metadata(parent).map_err(unavailable)?;
        require(
            (meta.uid() == 0 || meta.uid() == uid)
                && (meta.mode() & 0o022 == 0 || meta.is_dir() && meta.mode() & 0o1000 != 0),
            RefusalCode::Unavailable,
            "configuration/state parents must prevent replacement by another account; writable shared parents require the sticky bit",
        )?;
    }
    let meta = fs::symlink_metadata(path).map_err(unavailable)?;
    require(
        if directory {
            meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0
        } else {
            meta.is_file() && meta.nlink() == 1
        },
        RefusalCode::Unavailable,
        "state must be a private executor-owned directory; configuration must be a regular file with one link",
    )?;
    Ok(canonical)
}

pub fn load(config: &Path, state: &Path) -> Result<Configuration, Refusal> {
    let config = protected(config, false)?;
    let state = protected(state, true)?;
    #[cfg(unix)]
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&config)
        .map_err(unavailable)?;
    #[cfg(windows)]
    let input = crate::windows::security::read_file(&config)?;
    // This is protected operator input, not an agent request. Do not introduce
    // an arbitrary catalogue-size policy while parsing the adopted definition.
    let settings: Configuration =
        serde_json::from_reader(BufReader::new(input)).map_err(unavailable)?;
    require(
        settings.connections > 0
            && settings.connection_timeout_seconds > 0
            && settings.ledger.request_bytes > 0
            && settings.ledger.request_bytes <= isize::MAX as u64,
        RefusalCode::Budget,
        "connection count, read deadline and request ceiling must be finite and positive",
    )?;
    #[cfg(windows)]
    require(
        settings.connections < 253,
        RefusalCode::Budget,
        "Windows control pipe requires fewer than 253 workers to retain a finite instance count",
    )?;
    settings
        .native
        .validate(&settings.target, &[config, state])?;
    Ok(settings)
}

pub fn command(args: Vec<String>) -> Result<(), Refusal> {
    if args.as_slice() == ["--version"] {
        println!(
            "safeyolo-host-executor {} commit={} profile={} target={}",
            env!("CARGO_PKG_VERSION"),
            env!("SAFEYOLO_BUILD_REVISION"),
            env!("SAFEYOLO_BUILD_PROFILE"),
            env!("SAFEYOLO_HOST_EXECUTOR_TARGET"),
        );
        return Ok(());
    }
    if args.as_slice() == ["--help"] || args.is_empty() {
        println!(
            "Usage: safeyolo-host-executor <check|serve> --config ABSOLUTE_JSON --state ABSOLUTE_DIRECTORY\n\ncheck validates the complete adopted target without running its programs.\nThe selected state directory must exist, be private and owned by this account.\nRequired enforcement that the selected backend cannot apply is refused."
        );
        #[cfg(unix)]
        println!(
            "serve uses STATE/control.sock for the shared signed HTTP routes.\nLinux requires pinned bubblewrap and delegated cgroup v2 memory/pids controls, with permission to place jobs from the executor's current cgroup.\nmacOS requires Seatbelt and explicit broader memory and executor_restart authority; a controller crash can leave an orphan with unknown cleanup."
        );
        #[cfg(windows)]
        println!(
            "serve uses the local pipe \\\\.\\pipe\\safeyolo-host-TARGET_ID.\nservice --name SCM_NAME --config ABSOLUTE_JSON --state ABSOLUTE_DIRECTORY runs the selected configuration under the installed Windows Service account.\ncredential-store --name NAME --account DOMAIN\\user reads the workload password as UTF-8 from stdin and stores it in this executor account's Windows Credential Manager.\nidentity --credential NAME prints the selected workload SID and stable groups.\nWindows requires a separate ordinary workload account and explicit broader filesystem, registry, network_ipc and delegated_services authority. Job Objects enforce process/resource lifetime, not those permissions.\nThe executor account needs SeImpersonatePrivilege or the assign-primary-token/quota privileges for native launch. Service installation and privileges remain explicit operator choices."
        );
        return Ok(());
    }
    require(
        args.len() == 5
            && matches!(args[0].as_str(), "check" | "serve")
            && args[1] == "--config"
            && args[3] == "--state",
        RefusalCode::Arguments,
        "use --help for explicit check/serve arguments",
    )?;
    let config = PathBuf::from(&args[2]);
    let state = PathBuf::from(&args[4]);
    let settings = load(&config, &state)?;
    if args[0] == "check" {
        println!(
            "target {}: complete catalogue validated; no command launched",
            settings.target.target_id
        );
        return Ok(());
    }
    serve(config, state, settings)
}

#[cfg(unix)]
pub fn serve(config: PathBuf, state: PathBuf, settings: Configuration) -> Result<(), Refusal> {
    let mut ledger = Ledger::open(&state, &settings.target.target_id, settings.ledger.clone())?;
    settings.native.reconcile(&mut ledger)?;
    let socket = state.join("control.sock");
    if let Ok(meta) = fs::symlink_metadata(&socket) {
        require(
            meta.file_type().is_socket() && meta.uid() == unsafe { libc::geteuid() },
            RefusalCode::Unavailable,
            "existing control socket has a different type or owner",
        )?;
        match UnixStream::connect(&socket) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                fs::remove_file(&socket).map_err(unavailable)?
            }
            _ => {
                return Err(unavailable(
                    "control socket remains live or its status is unknown",
                ));
            }
        }
    }
    let listener = UnixListener::bind(&socket).map_err(unavailable)?;
    eprintln!(
        "target {} ready on {}",
        settings.target.target_id,
        socket.display()
    );
    let ledger = Arc::new(Mutex::new(ledger));
    // Fixed workers and a zero-capacity channel bound both active connections
    // and user-space pending work. The Unix listener has a finite kernel queue.
    let (tx, rx) = mpsc::sync_channel(0);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..settings.connections {
        let (rx, config, state, ledger, original) = (
            rx.clone(),
            config.clone(),
            state.clone(),
            ledger.clone(),
            settings.clone(),
        );
        std::thread::spawn(move || {
            loop {
                let stream = match rx.lock().expect("connection queue").recv() {
                    Ok(stream) => stream,
                    Err(_) => break,
                };
                if let Err(error) = connection(stream, &config, &state, &original, &ledger) {
                    eprintln!("{error}");
                }
            }
        });
    }
    for stream in listener.incoming() {
        tx.send(stream.map_err(unavailable)?).map_err(unavailable)?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn serve(config: PathBuf, state: PathBuf, settings: Configuration) -> Result<(), Refusal> {
    crate::windows::transport::serve(config, state, settings)
}

pub(crate) fn connection(
    mut stream: UnixStream,
    config: &Path,
    state: &Path,
    original: &Configuration,
    ledger: &Arc<Mutex<Ledger>>,
) -> Result<(), Refusal> {
    let deadline = Duration::from_secs(original.connection_timeout_seconds);
    stream
        .set_read_timeout(Some(deadline))
        .map_err(unavailable)?;
    stream
        .set_write_timeout(Some(deadline))
        .map_err(unavailable)?;
    let response = (|| {
        let expires = std::time::Instant::now()
            .checked_add(deadline)
            .ok_or_else(|| unavailable("connection deadline exceeds clock range"))?;
        let (path, body) = request(
            &mut DeadlineRead {
                stream: &mut stream,
                expires,
            },
            original.ledger.request_bytes,
        )?;
        // Consume the bounded request before refusing a changed configuration.
        // Closing a Unix socket with unread bytes can reset the connection and
        // discard the refusal. Reload still precedes authorization/admission.
        let settings = load_selected(config, state, original)?;
        let admitted = ledger.lock().map_err(unavailable)?.handle_native(
            &settings.target,
            &path,
            &body,
            now(),
            &settings.native,
        )?;
        if admitted.dispatch {
            let Response::Job { receipt } = &admitted.response else {
                return Err(unavailable("dispatch without an admitted receipt"));
            };
            let (ledger, job_id) = (ledger.clone(), receipt.job_id.clone());
            let (config, state, original) = (config.to_owned(), state.to_owned(), original.clone());
            #[cfg(windows)]
            let executing = crate::windows::transport::Execution::new();
            std::thread::spawn(move || {
                #[cfg(windows)]
                let _executing = executing;
                // Admission does not freeze an issuer's authority for a later
                // dispatch. Reload the protected owners immediately before
                // begin reauthenticates the retained original request.
                match load_selected(&config, &state, &original) {
                    Ok(current) => {
                        if let Err(error) = current.native.execute(&current.target, ledger, &job_id)
                        {
                            eprintln!("{job_id}: {error}");
                        }
                    }
                    Err(error) => {
                        match ledger.lock() {
                            Ok(mut ledger) => {
                                if let Err(record_error) = ledger.finish(
                                    &job_id,
                                    JobState::Failed,
                                    true,
                                    now(),
                                    format!("no process launched: {error}"),
                                ) {
                                    eprintln!("{job_id}: {record_error}");
                                }
                            }
                            Err(lock_error) => eprintln!("{job_id}: {lock_error}"),
                        }
                        eprintln!("{job_id}: {error}");
                    }
                }
            });
        }
        Ok(admitted.response)
    })()
    .unwrap_or_else(|refusal| Response::Refused { refusal });
    let body = serde_json::to_vec(&response).map_err(unavailable)?;
    let mut output = DeadlineWrite {
        stream: &mut stream,
        expires: std::time::Instant::now()
            .checked_add(deadline)
            .ok_or_else(|| unavailable("response deadline exceeds clock range"))?,
    };
    write!(output, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(unavailable)?;
    output.write_all(&body).map_err(unavailable)
}

fn load_selected(
    config: &Path,
    state: &Path,
    original: &Configuration,
) -> Result<Configuration, Refusal> {
    let settings = load(config, state)?;
    require(
        settings.target.target_id == original.target.target_id
            && revision(&(
                &settings.native,
                &settings.ledger,
                settings.connections,
                settings.connection_timeout_seconds,
            )) == revision(&(
                &original.native,
                &original.ledger,
                original.connections,
                original.connection_timeout_seconds,
            )),
        RefusalCode::Stale,
        "runtime, limits or target identity changed; restart this selected executor",
    )?;
    Ok(settings)
}

struct DeadlineRead<'a> {
    stream: &'a mut UnixStream,
    expires: std::time::Instant,
}
impl Read for DeadlineRead<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .expires
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP request deadline elapsed",
                )
            })?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}

struct DeadlineWrite<'a> {
    stream: &'a mut UnixStream,
    expires: std::time::Instant,
}
impl Write for DeadlineWrite<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .expires
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP response deadline elapsed",
                )
            })?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn request(stream: &mut impl Read, max: u64) -> Result<(String, Vec<u8>), Refusal> {
    let mut reader = BufReader::new(stream);
    let mut header = Vec::new();
    while header.len() < 8192 {
        let n = reader
            .by_ref()
            .take((8192 - header.len()) as u64)
            .read_until(b'\n', &mut header)
            .map_err(unavailable)?;
        if n == 0 || header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    require(
        header.ends_with(b"\r\n\r\n"),
        RefusalCode::Malformed,
        "incomplete or oversized HTTP header",
    )?;
    let text = std::str::from_utf8(&header).map_err(unavailable)?;
    let mut lines = text.split("\r\n");
    let request: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    require(
        request.len() == 3 && request[0] == "POST" && request[2] == "HTTP/1.1",
        RefusalCode::Protocol,
        "signed routes require POST and HTTP/1.1",
    )?;
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| unavailable("invalid HTTP header"))?;
        require(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            RefusalCode::Protocol,
            "chunked requests are not supported",
        )?;
        if name.eq_ignore_ascii_case("content-length") {
            require(
                length.is_none(),
                RefusalCode::Malformed,
                "duplicate Content-Length",
            )?;
            length = Some(value.trim().parse::<u64>().map_err(unavailable)?);
        }
    }
    let length = length.ok_or_else(|| unavailable("Content-Length is required"))?;
    require(
        length <= max && length <= isize::MAX as u64,
        RefusalCode::Budget,
        "request body exceeds target byte ceiling",
    )?;
    let mut bytes = vec![0; length as usize];
    reader.read_exact(&mut bytes).map_err(unavailable)?;
    Ok((request[1].into(), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_http_framing_preserves_signed_bytes_and_rejects_ambiguous_lengths() {
        let data = b"POST /v1/host-execution/job HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            request(&mut &data[..], 2).unwrap(),
            (Verb::Job.path().into(), b"{}".to_vec())
        );
        assert!(request(&mut &data[..], 1).is_err());
        for header in [
            "Content-Length: 2\r\nContent-Length: 3",
            "Content-Length: 2\r\nTransfer-Encoding: chunked",
            "Content-Length: 4096",
        ] {
            let data = format!("POST /v1/host-execution/job HTTP/1.1\r\n{header}\r\n\r\n{{}}");
            assert!(request(&mut data.as_bytes(), 16).is_err());
        }
        assert!(request(&mut &b"POST / HTTP/1.1\r\n"[..], 16).is_err());
        assert!(
            request(
                &mut format!("POST / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(8192)).as_bytes(),
                16
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_reload_returns_a_complete_refusal_before_closing_the_request() {
        let root = std::env::temp_dir().join(format!(
            "host-reload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let limits = LedgerLimits {
            jobs: 1,
            mutation_records: 2,
            output_bytes: 4096,
            database_bytes: 128 * 1024,
            request_bytes: 4096,
        };
        let ledger = Arc::new(Mutex::new(
            Ledger::open(&root, "fixture", limits.clone()).unwrap(),
        ));
        let original = Configuration {
            target: Target {
                target_id: "fixture".into(),
                ceiling_revision: "1".into(),
                allowed_verbs: Default::default(),
                max_authority_age_seconds: 600,
                issuers: Default::default(),
                ceiling: Default::default(),
                package: Package {
                    format: VERSION.into(),
                    name: "fixture".into(),
                    version: 1,
                    source: Source { location: "fixture".into(), version: "1".into() },
                    operations: Default::default(),
                },
            },
            ledger: limits,
            native: serde_json::from_value(if cfg!(target_os = "linux") {
                serde_json::json!({"platform":"linux", "bubblewrap":"/unused", "bubblewrap_sha256":"", "cgroup":"/unused", "executable_bytes":4096})
            } else {
                serde_json::json!({"platform":"macos", "executable_bytes":4096})
            }).unwrap(),
            connections: 1,
            connection_timeout_seconds: 1,
        };
        // The changed configuration is unreadable. No native launch or valid
        // issuer is needed to exercise the transport's refusal path.
        let (server, mut client) = UnixStream::pair().unwrap();
        client
            .write_all(b"POST /v1/host-execution/job HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
            .unwrap();
        connection(
            server,
            &root.join("missing.json"),
            &root,
            &original,
            &ledger,
        )
        .unwrap();
        let mut output = Vec::new();
        client.read_to_end(&mut output).unwrap();
        let end = output.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(matches!(
            serde_json::from_slice::<Response>(&output[end..]).unwrap(),
            Response::Refused { .. }
        ));
        drop(ledger);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn response_deadline_bounds_an_unread_socket_response() {
        let (mut writer, _held_reader) = UnixStream::pair().unwrap();
        let mut output = DeadlineWrite {
            stream: &mut writer,
            expires: std::time::Instant::now() + Duration::from_millis(30),
        };
        let error = output.write_all(&vec![0; 1024 * 1024]).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
    }

    #[cfg(unix)]
    #[test]
    fn request_deadline_bounds_a_partial_socket_request() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"PO").unwrap();
        let mut input = DeadlineRead {
            stream: &mut reader,
            expires: std::time::Instant::now() + Duration::from_millis(30),
        };
        let mut data = [0; 4];
        let error = input.read_exact(&mut data).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
    }
}
