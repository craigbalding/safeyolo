//! Host-to-guest byte streams for native proxy features.
//!
//! Linux uses runsc's connected-FD port forwarding. macOS uses the existing
//! per-agent VZ shell bridge. Neither path opens a host TCP listener.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, PermissionsExt},
};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{io, path::PathBuf};
#[cfg(target_os = "macos")]
use std::{
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, PermissionsExt},
    },
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinProcessInfo {
    first_fields: [u32; 12],
    command: [u8; 16],
    name: [u8; 32],
    other_fields: [u32; 5],
    started_seconds: u64,
    started_microseconds: u64,
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut libc::c_void, size: i32) -> i32;
    fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, size: u32) -> i32;
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_process_token(pid: i64) -> Option<String> {
    macos_process_token_detail(pid).ok()
}

#[cfg(target_os = "macos")]
fn macos_process_token_detail(pid: i64) -> Result<String, String> {
    let pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| format!("stage=pid invalid_pid={pid}"))?;
    let mut info = std::mem::MaybeUninit::<DarwinProcessInfo>::zeroed();
    let size = std::mem::size_of::<DarwinProcessInfo>();
    if size != 136 {
        return Err(format!(
            "stage=proc_pidinfo_layout expected=136 observed={size}"
        ));
    }
    let returned = unsafe { proc_pidinfo(pid, 3, 0, info.as_mut_ptr().cast(), size as i32) };
    if returned != size as i32 {
        let errno = if returned <= 0 {
            io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        return Err(format!(
            "stage=proc_pidinfo return={returned} expected={size} errno={errno:?}"
        ));
    }
    let info = unsafe { info.assume_init() };
    if info.first_fields[3] != pid as u32
        || info.started_seconds == 0
        || info.started_microseconds >= 1_000_000
    {
        return Err(format!(
            "stage=process_birth observed_pid={} seconds={} microseconds={}",
            info.first_fields[3], info.started_seconds, info.started_microseconds
        ));
    }
    Ok(format!(
        "darwin:{pid}:{}:{}",
        info.started_seconds, info.started_microseconds
    ))
}

#[cfg(target_os = "macos")]
fn process_arguments(pid: i32, executable: &std::path::Path) -> Option<Vec<Vec<u8>>> {
    macos_process_arguments_detail(pid, executable).ok()
}

#[cfg(target_os = "macos")]
fn macos_process_arguments_detail(
    pid: i32,
    executable: &std::path::Path,
) -> Result<Vec<Vec<u8>>, String> {
    let mut buffer = [0u8; 4096];
    let size = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if size <= 0 {
        return Err(format!(
            "stage=proc_pidpath return={size} errno={:?}",
            io::Error::last_os_error().raw_os_error()
        ));
    }
    let path = std::ffi::CStr::from_bytes_until_nul(&buffer)
        .map_err(|_| format!("stage=proc_pidpath_parse return={size} missing_terminator"))?;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
    let actual = path.canonicalize().map_err(|error| {
        format!(
            "stage=actual_executable_canonicalize path={} errno={:?}",
            vz_diagnostic_path(path),
            error.raw_os_error()
        )
    })?;
    let expected = executable.canonicalize().map_err(|error| {
        format!(
            "stage=expected_executable_canonicalize actual_executable={} errno={:?}",
            vz_diagnostic_path(&actual),
            error.raw_os_error()
        )
    })?;
    if actual != expected {
        return Err(format!(
            "stage=executable_mismatch actual_executable={} expected_executable={}",
            vz_diagnostic_path(&actual),
            vz_diagnostic_path(&expected)
        ));
    }
    // A helper executable alone cannot identify an agent. Bind its actual
    // launch arguments to this instance's private control endpoint.
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0;
    let returned = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if returned != 0 {
        return Err(format!(
            "stage=sysctl_argv_size return={returned} errno={:?}",
            io::Error::last_os_error().raw_os_error()
        ));
    }
    if size > 1024 * 1024 {
        return Err(format!(
            "stage=sysctl_argv_size observed_size={size} limit=1048576"
        ));
    }
    let mut bytes = vec![0u8; size];
    let returned = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if returned != 0 {
        return Err(format!(
            "stage=sysctl_argv return={returned} errno={:?}",
            io::Error::last_os_error().raw_os_error()
        ));
    }
    bytes.truncate(size);
    let malformed = || format!("stage=argv_parse size={size} malformed_arguments");
    let argc = i32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    );
    if !(1..=1024).contains(&argc) {
        return Err(format!(
            "stage=argv_parse argc={argc} invalid_argument_count"
        ));
    }
    let mut offset = 4
        + bytes
            .get(4..)
            .ok_or_else(malformed)?
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(malformed)?
        + 1;
    while bytes.get(offset) == Some(&0) {
        offset += 1;
    }
    let mut arguments = Vec::new();
    for _ in 0..argc {
        let length = bytes
            .get(offset..)
            .ok_or_else(malformed)?
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(malformed)?;
        arguments.push(bytes[offset..offset + length].to_vec());
        offset += length + 1;
    }
    Ok(arguments)
}

#[cfg(target_os = "linux")]
fn process_arguments(pid: i32, executable: &std::path::Path) -> Option<Vec<Vec<u8>>> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    if std::fs::read_link(proc.join("exe"))
        .ok()?
        .canonicalize()
        .ok()?
        != executable.canonicalize().ok()?
    {
        return None;
    }
    Some(
        std::fs::read(proc.join("cmdline"))
            .ok()?
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

pub(crate) fn process_has_path_argument(
    pid: i64,
    executable: &std::path::Path,
    flag: &[u8],
    path: &std::path::Path,
) -> bool {
    i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .and_then(|pid| process_arguments(pid, executable))
        .is_some_and(|arguments| {
            arguments
                .windows(2)
                .any(|pair| pair[0] == flag && pair[1] == path.as_os_str().as_bytes())
        })
}

#[cfg(target_os = "linux")]
fn process_working_directory(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

#[cfg(target_os = "macos")]
fn process_working_directory(pid: i32) -> Option<PathBuf> {
    let mut info = std::mem::MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_vnodepathinfo>();
    let returned = unsafe {
        proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if returned != size as i32 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let bytes: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .iter()
        .flatten()
        .map(|byte| *byte as u8)
        .collect();
    let path = std::ffi::CStr::from_bytes_until_nul(&bytes).ok()?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
}

pub(crate) fn process_has_config_path(
    pid: i64,
    executable: &std::path::Path,
    config: &std::path::Path,
) -> bool {
    let Some(pid) = i32::try_from(pid).ok().filter(|pid| *pid > 0) else {
        return false;
    };
    let Ok(config) = config.canonicalize() else {
        return false;
    };
    process_arguments(pid, executable).is_some_and(|arguments| {
        arguments.windows(2).any(|pair| {
            if pair[0] != b"--config" {
                return false;
            }
            let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&pair[1]));
            // A relative launch argument belongs to the process's working
            // directory, which can differ from the current CLI caller's.
            let path = if path.is_absolute() {
                path.to_owned()
            } else if let Some(directory) =
                process_working_directory(pid).filter(|directory| directory.is_absolute())
            {
                directory.join(path)
            } else {
                return false;
            };
            path.canonicalize().is_ok_and(|path| path == config)
        })
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn vm_process_token(name: &str, pid: i32) -> Option<String> {
    vm_process_token_detail(name, pid).ok()
}

#[cfg(target_os = "macos")]
fn vz_diagnostic_path(path: &std::path::Path) -> String {
    let escaped = format!("{path:?}");
    if escaped.chars().count() <= 512 {
        escaped
    } else {
        format!(
            "{}...<truncated>",
            escaped.chars().take(512).collect::<String>()
        )
    }
}

#[cfg(target_os = "macos")]
fn vm_process_token_detail(name: &str, pid: i32) -> Result<String, String> {
    let executable = config_dir().join("bin/safeyolo-vm");
    let control = config_dir()
        .join("data/vm-control")
        .join(format!("{name}.sock"));
    let expected = format!(
        "expected_executable={} expected_control_argument={}",
        vz_diagnostic_path(&executable),
        vz_diagnostic_path(&control)
    );
    let token = macos_process_token_detail(i64::from(pid))
        .map_err(|error| format!("{error}; {expected}"))?;
    let arguments = macos_process_arguments_detail(pid, &executable)
        .map_err(|error| format!("{error}; observed_birth={token}; {expected}"))?;
    if !arguments
        .windows(2)
        .any(|pair| pair[0] == b"--control-socket" && pair[1] == control.as_os_str().as_bytes())
    {
        // Only the control pathname is diagnostic. Do not include other argv
        // or the environment, which can contain credentials.
        let actual = arguments
            .windows(2)
            .find(|pair| pair[0] == b"--control-socket")
            .map(|pair| {
                vz_diagnostic_path(std::path::Path::new(std::ffi::OsStr::from_bytes(&pair[1])))
            });
        return Err(format!(
            "stage=control_argument_mismatch actual_control_argument={} observed_birth={token}; {expected}",
            actual.as_deref().unwrap_or("missing")
        ));
    }
    Ok(token)
}

#[cfg(target_os = "macos")]
fn vz_process_absence_detail(pid: i32) -> String {
    let returned = unsafe { libc::kill(pid, 0) };
    let errno = if returned != 0 {
        io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    // Match host_runs::saved_backend_is_dead: denied inspection is not death.
    format!(
        "process_absent={} kill_zero_return={returned} errno={errno:?}",
        returned != 0 && errno == Some(libc::ESRCH)
    )
}

#[cfg(target_os = "macos")]
fn vz_wait_matches(
    name: &str,
    pid: i32,
    expected: &str,
    first_mismatch: &mut Option<String>,
) -> bool {
    let observed = vm_process_token_detail(name, pid);
    let matches = observed.as_deref() == Ok(expected);
    if !matches && first_mismatch.is_none() {
        let detail = match observed {
            Ok(token) => format!("stage=birth_mismatch observed_birth={token}"),
            Err(error) => error,
        };
        *first_mismatch = Some(format!("{detail}; {}", vz_process_absence_detail(pid)));
    }
    matches
}

#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;
#[cfg(target_os = "macos")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::process::Command;
#[cfg(target_os = "macos")]
use tokio::process::{Child, ChildStdin, ChildStdout};

use crate::tunnels::BoxStream;

pub(crate) fn config_dir() -> PathBuf {
    if let Ok(root) = INSTANCE_ROOT.try_with(Clone::clone) {
        return root;
    }
    std::env::var_os("SAFEYOLO_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".safeyolo")
        })
}

tokio::task_local! { static INSTANCE_ROOT: PathBuf; }
tokio::task_local! { static INSTANCE_CONFIG: PathBuf; }

pub(crate) fn config_path() -> PathBuf {
    if let Ok(path) = INSTANCE_CONFIG.try_with(Clone::clone) {
        return path;
    }
    if let Ok(root) = INSTANCE_ROOT.try_with(Clone::clone) {
        return root.join("config.toml");
    }
    std::env::var_os("SAFEYOLO_NATIVE_CONFIG_PATH")
        .map(PathBuf::from)
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .unwrap_or_else(|| config_dir().join("config.toml"))
}

pub(crate) async fn in_config<T>(path: PathBuf, work: impl std::future::Future<Output = T>) -> T {
    let root = path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_owned();
    INSTANCE_ROOT
        .scope(root, INSTANCE_CONFIG.scope(path, work))
        .await
}

pub(crate) async fn in_instance<T>(root: PathBuf, work: impl std::future::Future<Output = T>) -> T {
    INSTANCE_ROOT.scope(root, work).await
}

pub(crate) fn with_config<T>(path: PathBuf, work: impl FnOnce() -> T) -> T {
    let root = path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_owned();
    INSTANCE_ROOT.sync_scope(root, || INSTANCE_CONFIG.sync_scope(path, work))
}

pub(crate) fn agent_map_path() -> io::Result<PathBuf> {
    let path = config_path();
    if path.is_file() {
        let config = crate::native_config::read(&path).map_err(io::Error::other)?;
        if !config.agent_map_file.is_empty() {
            return Ok(config.agent_map_file.into());
        }
    }
    Ok(config_dir().join("data/agent_map.json"))
}

pub(crate) fn lock_host_state(path: &std::path::Path) -> io::Result<std::fs::File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    };

    std::fs::create_dir_all(
        path.parent()
            .ok_or(io::Error::other("host lock has no parent"))?,
    )?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::other("unsafe host state lock"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
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
fn provider_runtime_not_ready() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "provider runtime is not ready; run agent status",
    )
}

#[cfg(target_os = "linux")]
fn provider_namespace_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "provider namespace control is unavailable or recovery failed; run agent diagnostics",
    )
}

#[cfg(target_os = "linux")]
fn provider_runsc_failed() -> io::Error {
    io::Error::other(
        "provider runsc command, state or port forwarding failed; check runsc installation and agent diagnostics",
    )
}

#[cfg(target_os = "linux")]
fn provider_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "provider transport timed out; run agent diagnostics",
    )
}

#[cfg(target_os = "linux")]
async fn port_forward_failure(child: &mut tokio::process::Child) -> io::Error {
    let mut detail = Vec::new();
    if let Some(stderr) = child.stderr.take()
        && tokio::time::timeout(
            Duration::from_secs(1),
            stderr.take(4096).read_to_end(&mut detail),
        )
        .await
        .is_err()
    {
        return provider_timeout();
    }
    // Stderr is used only to classify refusal. Never propagate guest/tool
    // output, which can contain credentials or host paths, into diagnostics.
    let detail = String::from_utf8_lossy(&detail).to_ascii_lowercase();
    if detail.contains("connection was refused") || detail.contains("connection refused") {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "provider guest port refused the connection; check the guest listener",
        )
    } else {
        provider_runsc_failed()
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

#[cfg(target_os = "macos")]
fn macos_guest_command(command: &str) -> String {
    // OpenSSH can give the unprivileged session a lower file-descriptor
    // ceiling than guest PID 1. Preserve the CLI's session prelude.
    format!(
        "/usr/local/bin/sudo -n /usr/bin/prlimit --pid 1 --nofile=65536:65536 || exit 1; \
         /usr/local/bin/sudo -n /usr/bin/prlimit --pid \"$$\" --nofile=65536:65536 || exit 1; \
         if [ \"$(ulimit -Sn)\" != 65536 ] || [ \"$(ulimit -Hn)\" != 65536 ]; then exit 1; fi; \
         . /etc/environment 2>/dev/null; \
         if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn userns_pid(name: &str) -> Option<u32> {
    let path = config_dir().join("agents").join(name).join("userns.pid");
    let pid = std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    let run = crate::host_runs::read(name).ok()??;
    let token = crate::host_lifecycle::process_token(i64::from(pid))?;
    if run["holder_pid"].as_u64() != Some(u64::from(pid))
        || Some(token.as_str()) != run["holder_token"].as_str()
        || run["run_id"].as_str().map(|id| format!("safeyolo-{id}"))
            != crate::host_runs::id(name).ok()
    {
        return None;
    }
    checked_namespace(pid)
}

#[cfg(target_os = "linux")]
pub(crate) fn checked_namespace(pid: u32) -> Option<u32> {
    // A stale PID can point at another process. Verify the namespace and
    // subordinate mappings established by SafeYolo before nsenter or signal.
    let own_userns = std::fs::metadata("/proc/self/ns/user").ok()?.ino();
    let own_netns = std::fs::metadata("/proc/self/ns/net").ok()?.ino();
    let holder_userns = std::fs::metadata(format!("/proc/{pid}/ns/user"))
        .ok()?
        .ino();
    let holder_netns = std::fs::metadata(format!("/proc/{pid}/ns/net")).ok()?.ino();
    if holder_userns == own_userns || holder_netns == own_netns {
        return None;
    }
    let mapping = crate::linux_host::selected_mapping().ok()?;
    for (file, base, operator) in [
        ("uid_map", mapping.uid_base, unsafe { libc::getuid() }),
        ("gid_map", mapping.gid_base, unsafe { libc::getgid() }),
    ] {
        let expected = crate::linux_host::Mapping::entries(base, operator);
        let mappings = std::fs::read_to_string(format!("/proc/{pid}/{file}")).ok()?;
        let actual = mappings
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                Some((
                    fields.next()?.parse::<u32>().ok()?,
                    fields.next()?.parse::<u32>().ok()?,
                    fields.next()?.parse::<u32>().ok()?,
                ))
            })
            .collect::<Vec<_>>();
        let mut legacy = expected;
        // Older owned namespaces omitted the final subordinate ID. Keep
        // those live namespaces controllable while new starts map all IDs.
        legacy[2].2 -= 1;
        if actual != expected && actual != legacy {
            return None;
        }
    }
    Some(pid)
}

#[cfg(target_os = "linux")]
pub(crate) fn control_pid(name: &str) -> Option<u32> {
    if let Some(pid) = userns_pid(name) {
        return Some(pid);
    }
    // The live sentry retains the run's network namespace after holder loss.
    // Validate the incarnation, process birth, command and mapping before
    // recovering its owning user namespace. Never use direct runsc here.
    checked_namespace(backend_pid(name)?)
}

#[cfg(target_os = "linux")]
pub(crate) fn backend_pid(name: &str) -> Option<u32> {
    let run = crate::host_runs::read(name).ok()??;
    let pid = u32::try_from(run["backend_pid"].as_u64()?).ok()?;
    let token = crate::host_lifecycle::process_token(i64::from(pid))?;
    if Some(token.as_str()) != run["backend_token"].as_str() {
        return None;
    }
    let id = crate::host_runs::id(name).ok()?;
    if run["run_id"].as_str().map(|id| format!("safeyolo-{id}")) != Some(id.clone()) {
        return None;
    }
    let command = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if !is_runsc_boot(&command, &id, &runsc_root()) {
        return None;
    }
    Some(pid)
}

#[cfg(target_os = "linux")]
fn is_runsc_boot(command: &[u8], id: &str, root: &std::path::Path) -> bool {
    let fields = command.split(|b| *b == 0).collect::<Vec<_>>();
    let root = root.as_os_str().as_bytes();
    // gVisor serializes sentry argv as runsc-sandbox and --root=PATH.
    // Keep the original runsc/--root PATH form and exact root/run checks.
    fields.contains(&id.as_bytes())
        && fields.contains(&b"boot".as_slice())
        && (fields
            .windows(2)
            .any(|pair| pair[0] == b"--root" && pair[1] == root)
            || fields
                .iter()
                .any(|field| field.strip_prefix(b"--root=") == Some(root)))
        && fields.first().is_some_and(|arg| {
            std::path::Path::new(std::ffi::OsStr::from_bytes(arg))
                .file_name()
                .is_some_and(|name| name == "runsc" || name == "runsc-sandbox")
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn runsc_command(name: &str) -> io::Result<Command> {
    let mut command = userns_command(name, "runsc")?;
    command.arg("--root").arg(runsc_root());
    Ok(command)
}

#[cfg(target_os = "linux")]
pub(crate) fn runsc_root() -> PathBuf {
    std::env::var_os("SAFEYOLO_RUNSC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir().join("run"))
}

#[cfg(target_os = "linux")]
fn userns_command(name: &str, program: &str) -> io::Result<Command> {
    let mut command = Command::new("nsenter");
    if let Some(pid) = userns_pid(name) {
        command.args(["--user", "--net", "--target", &pid.to_string(), "--"]);
    } else {
        pin_namespace_arguments(name, &mut command)?;
    }
    if program == "runsc" {
        command.arg(crate::linux_host::runtime_path()?);
    } else {
        command.arg(program);
    }
    Ok(command)
}

#[cfg(target_os = "linux")]
pub(crate) fn pinned_namespaces(name: &str) -> io::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let unverified = || {
        io::Error::other(
            "sandbox namespace control is unavailable or changed; run agent diagnostics or stop the owned backend",
        )
    };
    let run = crate::host_runs::read(name)
        .ok()
        .flatten()
        .ok_or_else(unverified)?;
    let pid = control_pid(name).ok_or_else(unverified)?;
    let token = crate::host_lifecycle::process_token(i64::from(pid)).ok_or_else(unverified)?;
    let net = std::fs::File::open(format!("/proc/{pid}/ns/net"))?;
    // The sentry may inhabit a child user namespace while retaining the
    // holder's network namespace. Enter that network namespace's owner,
    // rather than losing entry authority in the sentry's child namespace.
    let fd = unsafe { libc::ioctl(net.as_raw_fd(), libc::NS_GET_USERNS) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { std::fs::File::from_raw_fd(fd) };
    if user.metadata()?.ino() == std::fs::metadata("/proc/self/ns/user")?.ino()
        || net.metadata()?.ino() != std::fs::metadata(format!("/proc/{pid}/ns/net"))?.ino()
        || crate::host_lifecycle::process_token(i64::from(pid)).as_deref() != Some(&token)
        || control_pid(name) != Some(pid)
        || crate::host_runs::read(name).ok().flatten().as_ref() != Some(&run)
    {
        return Err(unverified());
    }
    Ok((user, net))
}

#[cfg(target_os = "linux")]
pub(crate) fn pin_namespace_arguments(name: &str, command: &mut Command) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let (user, net) = pinned_namespaces(name)?;
    command.args([
        format!("--user=/proc/self/fd/{}", user.as_raw_fd()),
        format!("--net=/proc/self/fd/{}", net.as_raw_fd()),
        "--".into(),
    ]);
    // Keep both descriptors pinned through spawn. Only this child inherits
    // them; nsenter keeps its usual UID, GID and supplementary-group setup.
    // No subsequent lookup of a possibly reused process PID selects entry.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            for fd in [user.as_raw_fd(), net.as_raw_fd()] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn systemd_user_scope_available() -> bool {
    if std::fs::read_to_string("/proc/1/comm")
        .ok()
        .is_none_or(|value| value.trim() != "systemd")
        || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none()
            && std::env::var_os("XDG_RUNTIME_DIR").is_none()
    {
        return false;
    }
    let probe = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new("systemctl")
            .args(["--user", "show-environment"])
            .output(),
    )
    .await;
    if !probe
        .ok()
        .and_then(Result::ok)
        .is_some_and(|output| output.status.success())
    {
        return false;
    }
    tokio::time::timeout(
        Duration::from_secs(2),
        Command::new("systemd-run").arg("--version").output(),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .is_some_and(|output| output.status.success())
}

#[cfg(target_os = "linux")]
fn scoped_runsc_create(name: &str, memory_mb: u64) -> io::Result<Command> {
    let pid = control_pid(name)
        .ok_or_else(|| io::Error::other("sandbox namespace control is unavailable"))?;
    let mut command = Command::new("systemd-run");
    command.args([
        "--user",
        "--scope",
        "-p",
        "Delegate=yes",
        "-p",
        &format!("MemoryMax={memory_mb}M"),
        "-p",
        "CPUQuota=400%",
        "-p",
        &format!("Description=safeyolo-{name}"),
        "--",
        "nsenter",
        "--user",
        "--net",
        "--target",
        &pid.to_string(),
        "--",
    ]);
    command.arg(crate::linux_host::runtime_path()?);
    Ok(command)
}

#[cfg(target_os = "linux")]
async fn start_userns(name: &str) -> io::Result<u32> {
    let mapping = crate::linux_host::selected_mapping().map_err(io::Error::other)?;
    let settings = crate::native_config::host_settings().map_err(io::Error::other)?;
    let restricts =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|value| value.trim() == "1");
    // The recursive failed-start fixture exercises both launch commands without
    // changing its host's AppArmor policy. Production always uses the sysctl.
    #[cfg(test)]
    let restricts = match std::env::var("SAFEYOLO_TEST_FAILED_START_LAUNCH").as_deref() {
        Ok("direct") => false,
        Ok("apparmor" | "missing-aa-exec") => true,
        _ => restricts,
    };
    let mut holder = if restricts {
        let mut command = Command::new("aa-exec");
        command.args([
            "-p",
            settings
                .linux
                .as_ref()
                .and_then(|s| s.apparmor_profile.as_deref())
                .unwrap_or("safeyolo-runsc"),
            "--",
            "unshare",
            "-Un",
            "tail",
            "-f",
            "/dev/null",
        ]);
        command
    } else {
        let mut command = Command::new("unshare");
        command.args(["-Un", "tail", "-f", "/dev/null"]);
        command
    };
    unsafe {
        holder.as_std_mut().pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = holder
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child
        .id()
        .ok_or(io::Error::other("user namespace holder has no PID"))?;
    let prepared: io::Result<()> = async {
        let parent_user = std::fs::metadata("/proc/self/ns/user")?.ino();
        let parent_net = std::fs::metadata("/proc/self/ns/net")?.ino();
        let entered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if child.try_wait()?.is_some() {
                    return Err(io::Error::other(
                        "user namespace holder exited before setup",
                    ));
                }
                let user = std::fs::metadata(format!("/proc/{pid}/ns/user")).map(|info| info.ino());
                let net = std::fs::metadata(format!("/proc/{pid}/ns/net")).map(|info| info.ino());
                if user.is_ok_and(|inode| inode != parent_user)
                    && net.is_ok_and(|inode| inode != parent_net)
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if !matches!(entered, Ok(Ok(()))) {
            return Err(io::Error::other(
                "user namespace holder did not become ready",
            ));
        }
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        for (program, base, operator) in [
            ("newuidmap", mapping.uid_base, uid),
            ("newgidmap", mapping.gid_base, gid),
        ] {
            let mut arguments = vec![pid.to_string()];
            for (guest, host, count) in crate::linux_host::Mapping::entries(base, operator) {
                arguments.extend([guest.to_string(), host.to_string(), count.to_string()]);
            }
            let map = Command::new(program).args(arguments).output().await?;
            if !map.status.success() {
                return Err(io::Error::other(format!(
                    "{program} failed: {}",
                    String::from_utf8_lossy(&map.stderr)
                )));
            }
        }

        std::fs::write(
            config_dir().join("agents").join(name).join("userns.pid"),
            pid.to_string(),
        )?;
        crate::host_runs::remember_process(name, "holder", pid).map_err(io::Error::other)?;
        Ok(())
    }
    .await;
    if let Err(error) = prepared {
        if let Err(cleanup) = child.kill().await {
            return Err(io::Error::other(format!(
                "{error}; user namespace holder cleanup failed: {cleanup}"
            )));
        }
        return Err(error);
    }
    Ok(pid)
}

#[cfg(target_os = "linux")]
pub(crate) async fn start_sandbox(
    name: &str,
    ip: &str,
    memory_mb: u64,
    ephemeral: bool,
) -> io::Result<()> {
    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let mapping = crate::linux_host::selected_mapping().map_err(io::Error::other)?;
    if crate::native_config::host_settings()
        .map_err(io::Error::other)?
        .linux
        .is_some()
        || crate::guest_acquisition::packaged_runsc_version(&config_dir())
            .map_err(io::Error::other)?
            .is_some()
    {
        crate::linux_host::verify_selected_runtime().map_err(io::Error::other)?;
    }
    let directory = config_dir().join("agents").join(name);
    let bundle = directory.join("config.json");
    let share = directory.join("config-share");
    if !share.join("guest-init").is_file() || !bundle.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "agent boot configuration was not staged by the CLI",
        ));
    }
    let root = runsc_root();
    std::fs::create_dir_all(&root)?;
    let acl = Command::new("setfacl")
        .args(["-m", &format!("u:{}:rwx", mapping.uid_base)])
        .arg(&root)
        .output()
        .await?;
    if !acl.status.success() {
        return Err(io::Error::other("setfacl failed on runsc state directory"));
    }
    if userns_pid(name).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "existing sandbox control must be reconciled before start",
        ));
    }
    let pid = start_userns(name).await?;
    let result = async {
        let mut spec: serde_json::Value = serde_json::from_slice(&std::fs::read(&bundle)?)?;
        let namespaces = spec
            .pointer_mut("/linux/namespaces")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or(io::Error::other("agent OCI namespaces missing"))?;
        namespaces.retain(|entry| {
            entry.get("type").and_then(serde_json::Value::as_str) != Some("network")
        });
        namespaces.push(serde_json::json!({"type":"network","path":format!("/proc/{pid}/ns/net")}));
        let mode = std::fs::metadata(&bundle)?.permissions().mode();
        let mut file = tempfile::NamedTempFile::new_in(&directory)?;
        serde_json::to_writer_pretty(&mut file, &spec)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.persist(&bundle)?;
        let status_dir = directory.join("status");
        std::fs::create_dir_all(&status_dir)?;
        for marker in ["static-init-done", "per-run-started", "vm-status"] {
            let _ = std::fs::remove_file(status_dir.join(marker));
        }
        match std::fs::remove_file(share.join("per-run-go")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let set_loopback = userns_command(name, "ip")?
            .args(["link", "set", "lo", "up"])
            .status()
            .await?;
        if !set_loopback.success() {
            return Err(io::Error::other("could not activate sandbox loopback"));
        }
        let address = userns_command(name, "ip")?
            .args(["addr", "add", &format!("{ip}/32"), "dev", "lo"])
            .status()
            .await?;
        if !address.success() {
            return Err(io::Error::other(
                "could not assign sandbox attribution address",
            ));
        }
        let id = crate::host_runs::id(name).map_err(io::Error::other)?;
        let _ = runsc_command(name)?
            .args(["delete", "--force", &id])
            .status()
            .await;
        let overlay = if ephemeral {
            "--overlay2=root:memory".to_owned()
        } else {
            let path = directory.join("overlay");
            std::fs::create_dir_all(&path)?;
            format!("--overlay2=root:dir={}", path.display())
        };
        let platform = crate::linux_host::runsc_platform(mapping).map_err(io::Error::other)?;
        // runsc create forks a sandbox and gofer. A pipe inherited by either
        // child can keep Command::output waiting after create itself exits.
        let stderr = tempfile::tempfile()?;
        let use_scope = systemd_user_scope_available().await;
        let mut create = if use_scope {
            scoped_runsc_create(name, memory_mb)?
        } else {
            eprintln!(
                "systemd user scope unavailable; starting {name} without host MemoryMax/CPUQuota limits"
            );
            userns_command(name, "runsc")?
        };
        let create = create
            .arg("--root")
            .arg(&root)
            .arg(&overlay)
            .args([
                "--host-uds=open",
                "--ignore-cgroups",
                "--network=sandbox",
                &format!("--platform={platform}"),
                "create",
                "--bundle",
            ])
            .arg(&directory)
            .arg(&id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr.try_clone()?)
            .status()
            .await?;
        if !create.success() {
            use std::io::{Read, Seek};
            let mut stderr = stderr;
            stderr.rewind()?;
            let mut detail = String::new();
            stderr.take(4096).read_to_string(&mut detail)?;
            return Err(io::Error::other(format!("runsc create failed: {}", detail)));
        }
        let start = userns_command(name, "runsc")?
            .arg("--ignore-cgroups")
            .arg("--root")
            .arg(&root)
            .args(["start", &id])
            .output()
            .await?;
        if !start.status.success() {
            return Err(io::Error::other(format!(
                "runsc start failed: {}",
                String::from_utf8_lossy(&start.stderr)
            )));
        }
        let state = runsc_command(name)?.args(["state", &id]).output().await?;
        let value: serde_json::Value = serde_json::from_slice(&state.stdout)?;
        let backend = value.get("pid").and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok()).ok_or(io::Error::other("runsc did not identify its backend"))?;
        crate::host_runs::remember_process(name, "backend", backend).map_err(io::Error::other)?;
        let mut run = crate::host_runs::read(name).map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("sandbox runtime record disappeared"))?;
        run["linux"] = crate::linux_host::runsc_report();
        run["linux"]["platform"] = platform.into();
        run["linux"]["extra_share_startup"] = "starting".into();
        crate::host_runs::save(name, &run).map_err(io::Error::other)?;
        std::fs::write(
            directory.join("container.pid"),
            value
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                .to_string(),
        )?;
        crate::linux_host::shares::attach_startup(name)
            .await
            .map_err(io::Error::other)?;
        // Linux extras must be mounted before guest-init performs static
        // setup or launches any workload. The OCI entry shell waits here.
        std::fs::write(share.join("per-run-go"), b"")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while tokio::time::Instant::now() < deadline && backend_pid(name).is_some() {
            if status_dir.join("per-run-started").is_file() {
                let mut run = crate::host_runs::read(name).map_err(io::Error::other)?
                    .ok_or_else(|| io::Error::other("sandbox record disappeared before readiness"))?;
                if run["run_id"].as_str().map(|generation| format!("safeyolo-{generation}")) != Some(id.clone()) {
                    return Err(io::Error::other("sandbox incarnation changed before readiness"));
                }
                run["linux"]["extra_share_startup"] = "ready".into();
                crate::host_runs::save(name, &run).map_err(io::Error::other)?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(io::Error::other("guest did not reach per-run startup"))
    }
    .await;
    if let Err(error) = result {
        let failed_run = crate::host_runs::read(name).map_err(io::Error::other)?;
        if let Err(cleanup) = stop_sandbox(name).await {
            return Err(io::Error::other(format!(
                "{error}; sandbox cleanup failed: {cleanup}"
            )));
        }
        if let (Some(failed), Some(mut run)) = (
            failed_run,
            crate::host_runs::read(name).map_err(io::Error::other)?,
        ) && ["run_id", "agent_id", "holder_token", "backend_token"]
            .iter()
            .all(|key| failed[key] == run[key])
            && run["run_id"].as_str().map(|id| format!("safeyolo-{id}"))
                == Some(crate::host_runs::id(name).map_err(io::Error::other)?)
        {
            // Cleanup proved this attempt stopped, including a failure before
            // runsc create could produce a backend receipt. Keep the updated
            // share cleanup receipts rather than restoring the pre-stop copy.
            run["state"] = "stopped".into();
            crate::host_runs::save(name, &run).map_err(io::Error::other)?;
        }
        return Err(error);
    }
    result
}

#[cfg(target_os = "linux")]
pub(crate) async fn guest_exec_available(name: &str) -> bool {
    let observed = crate::host_runs::observe(name).await;
    observed["exec"] == true
}

#[cfg(target_os = "linux")]
pub(crate) async fn open_guest_port(name: &str, port: u16) -> io::Result<BoxStream> {
    use tokio::net::UnixListener;

    if !valid_agent_name(name) || port == 0 {
        return Err(provider_runtime_not_ready());
    }
    let observed = crate::host_runs::observe(name).await;
    if observed["port_forward"] != true {
        return Err(
            if observed["runtime_state"] == "stopped" || observed["runtime_state"] == "starting" {
                provider_runtime_not_ready()
            } else if userns_command(name, "runsc").is_err() {
                provider_namespace_unavailable()
            } else {
                provider_runsc_failed()
            },
        );
    }
    let directory = tempfile::Builder::new()
        .prefix("sy-port-")
        .tempdir()
        .map_err(|_| provider_runsc_failed())?;
    let path = directory.path().join("stream.sock");
    let listener = UnixListener::bind(&path).map_err(|_| provider_runsc_failed())?;
    let mut command = runsc_command(name).map_err(|_| provider_namespace_unavailable())?;
    let mut child = command
        .args([
            "port-forward",
            "--stream",
            path.to_str().unwrap_or_default(),
            &crate::host_runs::id(name).map_err(|_| provider_runtime_not_ready())?,
            &port.to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| provider_runsc_failed())?;
    // runsc donates the connected descriptor, then exits. Require success
    // before exposing the stream so a closed port remains unavailable.
    let stream = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            accepted = listener.accept() => accepted.map(|(stream, _)| stream).map_err(|_| provider_runsc_failed()),
            status = child.wait() => {
                if !status.map_err(|_| provider_runsc_failed())?.success() {
                    return Err(port_forward_failure(&mut child).await);
                }
                tokio::time::timeout(Duration::from_secs(1), listener.accept())
                    .await.map_err(|_| provider_timeout())?
                    .map(|(stream, _)| stream)
                    .map_err(|_| provider_runsc_failed())
            }
        }
    })
    .await
    .map_err(|_| provider_timeout())??;
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .map_err(|_| provider_timeout())?
        .map_err(|_| provider_runsc_failed())?;
    if !status.success() {
        return Err(port_forward_failure(&mut child).await);
    }
    Ok(Box::new(stream))
}

#[cfg(target_os = "linux")]
pub(crate) async fn exec_guest_command(name: &str, command: &str) -> io::Result<i32> {
    // runsc changes donated stdio ownership and open-file flags. Donate
    // pipes, then stream diagnostics to the caller's private descriptors.
    let mut child = spawn_guest_command_with_output(name, command, true, false).await?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or(io::Error::other("guest stdout is not captured"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or(io::Error::other("guest stderr is not captured"))?;
    let mut host_stdout = tokio::io::stdout();
    let mut host_stderr = tokio::io::stderr();
    let (status, _, _) = tokio::try_join!(
        child.wait(),
        tokio::io::copy(&mut stdout, &mut host_stdout),
        tokio::io::copy(&mut stderr, &mut host_stderr),
    )?;
    Ok(status.code().unwrap_or(1))
}

/// The diagnostic has fixed arguments and must not run agent login scripts.
#[cfg(target_os = "linux")]
pub(crate) async fn spawn_desktop_probe(name: &str) -> io::Result<tokio::process::Child> {
    if !valid_agent_name(name) || !guest_exec_available(name).await {
        return Err(unavailable());
    }
    guest_command_stdio(
        runsc_command(name)?.args([
            "exec",
            "--user",
            "1000:1000",
            "--cwd",
            "/workspace",
            &crate::host_runs::id(name).map_err(io::Error::other)?,
            "/safeyolo/safeyolo-guest",
            "desktop-probe",
        ]),
        true,
        false,
    )
    .spawn()
}

#[cfg(target_os = "macos")]
pub(crate) async fn spawn_desktop_probe(name: &str) -> io::Result<tokio::process::Child> {
    spawn_macos_guest_command(
        name,
        "exec /safeyolo/safeyolo-guest desktop-probe",
        true,
        false,
    )
    .await
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn spawn_desktop_probe(_name: &str) -> io::Result<tokio::process::Child> {
    Err(unavailable())
}

#[cfg(target_os = "linux")]
pub(crate) async fn spawn_guest_command_with_output(
    name: &str,
    command: &str,
    capture: bool,
    inherit_stdin: bool,
) -> io::Result<tokio::process::Child> {
    if !valid_agent_name(name) || !guest_exec_available(name).await {
        return Err(unavailable());
    }
    let wrapped = format!(
        ". /etc/environment 2>/dev/null; if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    );
    guest_command_stdio(
        runsc_command(name)?.args([
            "exec",
            "--user",
            "1000:1000",
            "--cwd",
            "/workspace",
            &crate::host_runs::id(name).map_err(io::Error::other)?,
            "/bin/bash",
            "-lc",
            &wrapped,
        ]),
        capture,
        inherit_stdin,
    )
    .spawn()
}

#[cfg(target_os = "linux")]
pub(crate) async fn stop_sandbox(name: &str) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let id = crate::host_runs::id(name).map_err(io::Error::other)?;
    // A surviving sentry can be identified without providing usable network
    // namespace control. Stop it through the verified process handle when
    // the original holder is gone; never run runsc outside its namespaces.
    if userns_pid(name).is_none() {
        crate::host_runs::stop_without_holder(name)
            .await
            .map_err(io::Error::other)?;
        return crate::linux_host::shares::cleanup_stopped(name)
            .await
            .map_err(io::Error::other);
    }
    let unverified = || {
        io::Error::other(
            "holder birth, run or namespaces changed or are unverified; no holder was signalled; state was preserved; run agent diagnostics",
        )
    };
    let run = crate::host_runs::read(name)
        .ok()
        .flatten()
        .ok_or_else(unverified)?;
    let pid = userns_pid(name).ok_or_else(unverified)?;
    // Pin the original holder before running stop commands. A reused PID or
    // a changed incarnation cannot acquire authority during the stop.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::other(format!(
            "could not open the verified holder: {}; no holder was signalled; state was preserved; run agent diagnostics",
            io::Error::last_os_error()
        )));
    }
    let holder = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let revalidate_holder = || {
        let current = crate::host_runs::read(name)
            .ok()
            .flatten()
            .ok_or_else(unverified)?;
        if userns_pid(name) != Some(pid)
            || run["run_id"].as_str() != Some(id.trim_start_matches("safeyolo-"))
            || current["holder_token"] != run["holder_token"]
            || current["run_id"] != run["run_id"]
        {
            return Err(unverified());
        }
        Ok(())
    };
    revalidate_holder()?;
    if guest_exec_available(name).await {
        let _ = runsc_command(name)?
            .args(["kill", &id, "SIGTERM"])
            .status()
            .await;
        for _ in 0..50 {
            if !guest_exec_available(name).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if guest_exec_available(name).await {
            let _ = runsc_command(name)?
                .args(["kill", "--all", &id, "SIGKILL"])
                .status()
                .await;
        }
    }
    if userns_pid(name).is_none() {
        crate::host_runs::stop_without_holder(name)
            .await
            .map_err(io::Error::other)?;
        return crate::linux_host::shares::cleanup_stopped(name)
            .await
            .map_err(io::Error::other);
    }
    let status = runsc_command(name)?
        .args(["delete", "--force", &id])
        .status()
        .await?;
    if !status.success() && guest_exec_available(name).await {
        return Err(io::Error::other("runsc could not delete the sandbox"));
    }
    revalidate_holder()?;
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            holder.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } != 0
    {
        return Err(io::Error::other(format!(
            "could not stop the verified holder: {}; state was preserved; run agent diagnostics",
            io::Error::last_os_error()
        )));
    }
    crate::host_runs::wait_for_pidfd_exit(&holder, Duration::from_secs(5))
        .await
        .map_err(|error| {
            io::Error::other(format!(
                "could not observe the verified holder exit: {error}; state was preserved; run agent diagnostics {name}"
            ))
        })?;
    let directory = config_dir().join("agents").join(name);
    let _ = std::fs::remove_file(directory.join("userns.pid"));
    let _ = std::fs::remove_file(directory.join("container.pid"));
    crate::linux_host::shares::cleanup_stopped(name)
        .await
        .map_err(io::Error::other)?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) async fn guest_exec_available(name: &str) -> bool {
    crate::host_runs::observe(name).await["exec"] == true
}

#[cfg(target_os = "macos")]
pub(crate) async fn open_guest_port(name: &str, port: u16) -> io::Result<BoxStream> {
    if !valid_agent_name(name)
        || port == 0
        || crate::host_runs::observe(name).await["port_forward"] != true
    {
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
    // The guest Bash build has no /dev/tcp support. Socat reports its own
    // successful connection on stderr before forwarding any bytes on stdout.
    // Wait for that report so a closed port cannot be mistaken for a stream.
    const CONNECTED: &[u8] = b"starting data transfer loop with FDs";
    let open = format!("exec socat -d -d - TCP4:127.0.0.1:{port}");
    let mut child = Command::new("ssh")
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
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
            "-o",
            "ControlPath=none",
            "-o",
            &format!("ProxyCommand={proxy_command}"),
            "agent@sandbox",
            &macos_guest_command(&open),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stderr = child.stderr.take().ok_or_else(unavailable)?;
    let mut diagnostics = Vec::with_capacity(1024);
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while diagnostics.len() < 8192 {
            let mut chunk = [0u8; 512];
            let count = stderr.read(&mut chunk).await?;
            if count == 0 {
                return Ok::<bool, io::Error>(false);
            }
            diagnostics.extend_from_slice(&chunk[..count]);
            if diagnostics
                .windows(CONNECTED.len())
                .any(|part| part == CONNECTED)
            {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await;
    if !matches!(result, Ok(Ok(true))) {
        return Err(unavailable());
    }
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
    });
    child_stream(child)
}

#[cfg(target_os = "macos")]
pub(crate) async fn exec_guest_command(name: &str, command: &str) -> io::Result<i32> {
    if !valid_agent_name(name) || !guest_exec_available(name).await {
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
    let wrapped = macos_guest_command(command);
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
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
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

#[cfg(target_os = "macos")]
pub(crate) async fn spawn_guest_command_with_output(
    name: &str,
    command: &str,
    capture: bool,
    inherit_stdin: bool,
) -> io::Result<tokio::process::Child> {
    spawn_macos_guest_command(name, &macos_guest_command(command), capture, inherit_stdin).await
}

#[cfg(target_os = "macos")]
async fn spawn_macos_guest_command(
    name: &str,
    command: &str,
    capture: bool,
    inherit_stdin: bool,
) -> io::Result<tokio::process::Child> {
    if !valid_agent_name(name) || !guest_exec_available(name).await {
        return Err(unavailable());
    }
    let shell = config_dir()
        .join("data/shell-sockets")
        .join(format!("{name}.sock"));
    if !shell.exists() {
        return Err(unavailable());
    }
    let key = config_dir().join("data/vm_ssh_key");
    let socket = shell.display().to_string().replace('\'', "'\\''");
    guest_command_stdio(
        Command::new("ssh").args([
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
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
            "-o",
            "ControlPath=none",
            "-o",
            &format!("ProxyCommand=nc -U '{socket}'"),
            if inherit_stdin { "-t" } else { "-T" },
            "agent@sandbox",
            command,
        ]),
        capture,
        inherit_stdin,
    )
    .spawn()
}

#[cfg(target_os = "macos")]
pub(crate) async fn stop_sandbox(name: &str) -> io::Result<()> {
    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let invocation = uuid::Uuid::new_v4();
    let root = config_dir();
    let mut helper_pid = None;
    let mut expected_birth = None;
    let mut first_wait_mismatch = None;
    let result = async {
        let path = config_dir().join("agents").join(name).join("vm.pid");
        // The private socket independently identifies this agent's helper when
        // the saved PID projection is missing or stale.
        let control = crate::host_runs::control(name, serde_json::json!({"operation":"status"}))
            .await
            .ok();
        let controlled = control
            .as_ref()
            .filter(|value| value["agent"] == name)
            .and_then(|value| value["pid"].as_i64())
            .and_then(|pid| i32::try_from(pid).ok());
        let saved = std::fs::read_to_string(&path)
            .ok()
            .and_then(|value| value.trim().parse::<i32>().ok());
        let saved = saved.filter(|pid| {
            vm_process_token(name, *pid).is_some_and(|token| {
                std::fs::read_to_string(config_dir().join("agents").join(name).join("vm.token"))
                    .is_ok_and(|saved| saved.trim() == token)
            })
        });
        let pid = controlled.or(saved).ok_or(io::Error::other(
            "VZ helper identity is missing; inspect agent diagnostics",
        ))?;
        helper_pid = Some(pid);
        let token = vm_process_token_detail(name, pid);
        let token = match token {
            Ok(token) => token,
            Err(detail) => {
                if unsafe { libc::kill(pid, 0) } != 0
                    && io::Error::last_os_error().kind() == io::ErrorKind::NotFound
                {
                    std::fs::remove_file(path)?;
                    let _ = std::fs::remove_file(
                        config_dir().join("agents").join(name).join("vm.token"),
                    );
                    return Ok(());
                }
                return Err(io::Error::other(format!(
                    "VM PID does not identify this agent's helper; {detail}; {}",
                    vz_process_absence_detail(pid)
                )));
            }
        };
        expected_birth = Some(token.clone());
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
        for _ in 0..100 {
            if !vz_wait_matches(name, pid, &token, &mut first_wait_mismatch) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if vz_wait_matches(name, pid, &token, &mut first_wait_mismatch) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            for _ in 0..50 {
                if !vz_wait_matches(name, pid, &token, &mut first_wait_mismatch) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if vz_wait_matches(name, pid, &token, &mut first_wait_mismatch) {
                return Err(io::Error::other("owned VZ helper did not stop"));
            }
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        };
        let _ = std::fs::remove_file(config_dir().join("agents").join(name).join("vm.token"));
        remove_stopped_vz_sockets(name)?;
        Ok(())
    }
    .await;
    result.map_err(|error| io::Error::new(error.kind(), format!(
        "VZ stop invocation={invocation} root={} agent={name} pid={helper_pid:?} expected_birth={} first_wait_mismatch={}: {error}",
        vz_diagnostic_path(&root), expected_birth.as_deref().unwrap_or("not_observed"), first_wait_mismatch.as_deref().unwrap_or("not_observed")
    )))
}

#[cfg(target_os = "macos")]
pub(crate) fn remove_stopped_vz_sockets(name: &str) -> io::Result<()> {
    let paths = ["data/vm-control", "data/shell-sockets"]
        .map(|directory| config_dir().join(directory).join(format!("{name}.sock")));
    // Called under the lifecycle lock after backend absence is established.
    // A stale pathname alone must not confer authority over another listener.
    for path in &paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_socket() => {
                return Err(io::Error::other("VZ socket path is not a socket"));
            }
            Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
                Ok(socket) => {
                    use std::os::fd::AsRawFd;
                    let mut pid: libc::pid_t = 0;
                    let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
                    // Inspect the guard's existing connection; do not open
                    // another connection or infer signal authority from it.
                    let returned = unsafe {
                        libc::getsockopt(
                            socket.as_raw_fd(),
                            0,
                            2,
                            (&mut pid as *mut libc::pid_t).cast(),
                            &mut length,
                        )
                    };
                    let peer = if returned == 0
                        && length as usize == std::mem::size_of_val(&pid)
                        && pid > 0
                    {
                        match macos_process_token_detail(i64::from(pid)) {
                            Ok(birth) => format!("peer_pid={pid} peer_birth={birth}"),
                            Err(error) => {
                                format!("peer_pid={pid} peer_birth_unavailable=({error})")
                            }
                        }
                    } else {
                        let errno = if returned != 0 {
                            io::Error::last_os_error().raw_os_error()
                        } else {
                            None
                        };
                        format!(
                            "stage=LOCAL_PEERPID return={returned} errno={errno:?} length={length} observed_pid={pid}"
                        )
                    };
                    return Err(io::Error::other(format!(
                        "VZ socket still has a live listener; socket={} {peer}",
                        vz_diagnostic_path(path)
                    )));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) => {}
                Err(error) => return Err(error),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for path in paths {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// The installed helper remains the direct child of an optional host-owned
/// deadline runner. This opt-in is supplied by the physical VZ test account,
/// never by an Admin request or guest configuration.
#[cfg(any(target_os = "macos", test))]
fn vz_helper_command(
    helper: &std::path::Path,
    runner: Option<&std::ffi::OsStr>,
    timeout: Option<&std::ffi::OsStr>,
) -> io::Result<Command> {
    match (runner, timeout) {
        (None, None) => Ok(Command::new(helper)),
        (Some(runner), Some(timeout)) => {
            let timeout = timeout
                .to_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit())
                        && value.parse::<u64>().is_ok_and(|seconds| seconds > 0)
                })
                .ok_or(io::Error::other(
                    "VZ test supervision needs a positive whole-number timeout",
                ))?;
            let runner = std::path::Path::new(runner);
            if !runner.is_absolute()
                || !runner.is_file()
                || runner.metadata()?.permissions().mode() & 0o111 == 0
            {
                return Err(io::Error::other(
                    "VZ test runner must be an absolute executable file",
                ));
            }
            let mut command = Command::new(runner);
            command
                .args(["--timeout-seconds", timeout, "--"])
                .arg(helper);
            Ok(command)
        }
        _ => Err(io::Error::other(
            "VZ test supervision needs both a runner and a timeout",
        )),
    }
}

#[cfg(any(target_os = "macos", test))]
async fn stop_vz_launch_owner(child: &mut tokio::process::Child) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    // Tokio owns this unreaped child, including a runner whose helper failed
    // before publishing control. TERM lets the runner clean up its child.
    if let Some(pid) = child.id() {
        if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
            .await
            .map_err(|_| {
                io::Error::other(
                    "VZ launch owner did not finish cleanup; preserve the disposable instance",
                )
            })??;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
async fn cleanup_failed_vz_start(
    startup: io::Error,
    sandbox_stop: io::Result<()>,
    child: &mut tokio::process::Child,
) -> io::Error {
    let owner_stop = stop_vz_launch_owner(child).await;
    match (sandbox_stop, owner_stop) {
        (Ok(()), Ok(())) => startup,
        (Err(sandbox), Ok(())) => io::Error::other(format!(
            "{startup}; sandbox stop failed: {sandbox}; owned VZ launch process stopped"
        )),
        (Ok(()), Err(owner)) => io::Error::other(format!(
            "{startup}; VZ launch-owner cleanup failed: {owner}"
        )),
        (Err(sandbox), Err(owner)) => io::Error::other(format!(
            "{startup}; sandbox cleanup failed: {sandbox}; VZ launch-owner cleanup failed: {owner}"
        )),
    }
}

#[cfg(any(target_os = "macos", test))]
fn vz_boot_inputs(
    config: &std::path::Path,
    directory: &std::path::Path,
    launch_context: &serde_json::Value,
) -> (PathBuf, PathBuf, PathBuf) {
    // stage() captured one complete selection for this incarnation. Reading
    // the moving default here could combine another guest's kernel and rootfs.
    let guest_inputs = launch_context
        .get("guest_inputs")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| config.join("share"));
    let rootfs = if directory.join("rootfs.ext4").is_file() {
        directory.join("rootfs.ext4")
    } else {
        guest_inputs.join("rootfs-base.ext4")
    };
    (
        rootfs,
        guest_inputs.join("Image"),
        guest_inputs.join("initramfs.cpio.gz"),
    )
}

#[cfg(target_os = "macos")]
pub(crate) async fn start_sandbox(
    name: &str,
    ip: &str,
    memory_mb: u64,
    ephemeral: bool,
) -> io::Result<()> {
    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let config = config_dir();
    let directory = config.join("agents").join(name);
    let share = directory.join("config-share");
    let status_dir = directory.join("status");
    let launch_context: serde_json::Value =
        serde_json::from_slice(&std::fs::read(share.join("host-launch-context.json"))?)?;
    let workspace = launch_context
        .get("workspace")
        .and_then(serde_json::Value::as_str)
        .ok_or(io::Error::other(
            "agent workspace missing from host launch context",
        ))?;
    let (rootfs, kernel, initrd) = vz_boot_inputs(&config, &directory, &launch_context);
    for path in [&rootfs, &kernel, &initrd, &share] {
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing agent boot input: {}", path.display()),
            ));
        }
    }
    std::fs::create_dir_all(&status_dir)?;
    std::fs::create_dir_all(directory.join("home"))?;
    let shell = config
        .join("data/shell-sockets")
        .join(format!("{name}.sock"));
    let control = config.join("data/vm-control").join(format!("{name}.sock"));
    for socket in [&shell, &control] {
        let parent = socket
            .parent()
            .ok_or(io::Error::other("VM socket has no parent"))?;
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        match std::fs::remove_file(socket) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for marker in ["static-init-done", "per-run-started", "vm-status"] {
        let _ = std::fs::remove_file(status_dir.join(marker));
    }
    std::fs::write(share.join("per-run-go"), b"")?;
    let proxy = config
        .join("data/sockets")
        .join(format!("{ip}_{name}/proxy.sock"));
    let runner = std::env::var_os("SAFEYOLO_VZ_TEST_RUNNER");
    let runner_timeout = std::env::var_os("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS");
    let mut command = vz_helper_command(
        &config.join("bin/safeyolo-vm"),
        runner.as_deref(),
        runner_timeout.as_deref(),
    )?;
    let mut cmdline = "console=hvc0 root=/dev/vda rw quiet".to_owned();
    if ephemeral {
        cmdline.push_str(" safeyolo.ephemeral_upper=1");
    }
    command.arg("run").args([
        "--kernel",
        kernel.to_str().unwrap_or_default(),
        "--initrd",
        initrd.to_str().unwrap_or_default(),
        "--rootfs",
        rootfs.to_str().unwrap_or_default(),
        "--cpus",
        "4",
        "--memory",
        &memory_mb.to_string(),
        "--share",
        &format!("{workspace}:workspace:rw"),
        "--share",
        &format!("{}:config:ro", share.display()),
        "--share",
        &format!("{}:status:rw", status_dir.display()),
        "--share",
        &format!("{}:home:rw", directory.join("home").display()),
        "--serial-log",
        &directory.join("console.log").display().to_string(),
        "--cmdline",
        &cmdline,
        "--proxy-socket",
        proxy.to_str().unwrap_or_default(),
        "--shell-socket",
        shell.to_str().unwrap_or_default(),
        "--control-socket",
        control.to_str().unwrap_or_default(),
        "--no-terminal",
    ]);
    if let Some(shares) = launch_context
        .get("extra_shares")
        .and_then(serde_json::Value::as_array)
    {
        for (index, entry) in shares.iter().enumerate() {
            let host = entry
                .get("host_path")
                .and_then(serde_json::Value::as_str)
                .ok_or(io::Error::other("invalid staged extra share"))?;
            let read_only = entry
                .get("read_only")
                .and_then(serde_json::Value::as_bool)
                .ok_or(io::Error::other("invalid staged extra share mode"))?;
            if !std::path::Path::new(host).is_absolute() {
                return Err(io::Error::other("staged extra share must be absolute"));
            }
            command.arg("--share").arg(format!(
                "{host}:extra{index}:{}",
                if read_only { "ro" } else { "rw" }
            ));
        }
    }
    if !ephemeral {
        let overlay = directory.join("overlay.img");
        if !overlay.is_file() || overlay.metadata()?.len() == 0 {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&overlay)?;
            file.set_len(256 * 1024 * 1024 * 1024)?;
            std::fs::set_permissions(&overlay, std::fs::Permissions::from_mode(0o600))?;
        }
        command.arg("--overlay").arg(overlay);
    }
    let serial = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(directory.join("serial.log"))?;
    let stderr = serial.try_clone()?;
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(serial)
        .stderr(stderr)
        .spawn()?;
    let started = async {
        let mut identity = None;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
        while tokio::time::Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                break;
            }
            if identity.is_none() && control.exists() {
                // The peer PID and installed executable/control arguments are
                // verified by control(). The runner PID is not a VM handle.
                if let Ok(observed) =
                    crate::host_runs::control(name, serde_json::json!({"operation":"status"})).await
                    && observed["agent"] == name
                    && let Some(pid) = observed["pid"]
                        .as_i64()
                        .and_then(|pid| u32::try_from(pid).ok())
                    && let Some(token) = vm_process_token(name, pid as i32)
                {
                    std::fs::write(directory.join("vm.pid"), pid.to_string())?;
                    std::fs::write(directory.join("vm.token"), token)?;
                    crate::host_runs::remember_process(name, "backend", pid)
                        .map_err(io::Error::other)?;
                    let mut run = crate::host_runs::read(name)
                        .map_err(io::Error::other)?
                        .ok_or(io::Error::other("sandbox record is missing"))?;
                    run["helper_instance"] = observed["instance"].clone();
                    crate::host_runs::save(name, &run).map_err(io::Error::other)?;
                    identity = Some(observed);
                }
            }
            if identity.is_some() && status_dir.join("per-run-started").is_file() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err(io::Error::other("VM did not reach per-run startup"))
    }
    .await;
    if let Err(error) = started {
        // Stop the independently verified helper when available. Also stop
        // the owned launch process if identity persistence itself failed.
        let sandbox_stop = stop_sandbox(name).await;
        return Err(cleanup_failed_vz_start(error, sandbox_stop, &mut child).await);
    }
    started
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn guest_command_stdio(command: &mut Command, capture: bool, inherit_stdin: bool) -> &mut Command {
    // runsc can set O_NONBLOCK on a donated descriptor's shared open-file
    // description. A guest-side redirect happens too late to protect a caller
    // that owns operator input; disconnect that input before spawning runsc.
    command
        .stdin(if inherit_stdin {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .stdout(if capture {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::inherit()
        })
        .stderr(if capture {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::inherit()
        })
        .kill_on_drop(capture)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn spawn_guest_command(
    name: &str,
    command: &str,
    inherit_stdin: bool,
) -> io::Result<tokio::process::Child> {
    spawn_guest_command_with_output(name, command, false, inherit_stdin).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn guest_command_output(
    name: &str,
    command: &str,
    timeout: std::time::Duration,
) -> io::Result<std::process::Output> {
    let child = spawn_guest_command_with_output(name, command, true, false).await?;
    wait_guest_command_output(child, timeout).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_guest_command_output(
    child: tokio::process::Child,
    timeout: std::time::Duration,
) -> io::Result<std::process::Output> {
    tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "guest command timed out"))?
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn coding_agent_observation(name: &str) -> io::Result<String> {
    let output = guest_command_output(
        name,
        "/safeyolo/safeyolo-guest observe check",
        std::time::Duration::from_secs(5),
    )
    .await
    .map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "coding-agent observation timed out",
            )
        } else {
            error
        }
    })?;
    if !output.status.success() {
        return Err(io::Error::other("coding-agent observation failed"));
    }
    let state = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    match state.trim() {
        "running" | "stopped" => Ok(state.trim().into()),
        _ => Err(io::Error::other("coding-agent observation is unverified")),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn guest_exec_available(_name: &str) -> bool {
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn spawn_guest_command(
    _name: &str,
    _command: &str,
    _inherit_stdin: bool,
) -> io::Result<tokio::process::Child> {
    Err(unavailable())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn stop_sandbox(_name: &str) -> io::Result<()> {
    Err(unavailable())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn start_sandbox(
    _name: &str,
    _ip: &str,
    _memory_mb: u64,
    _ephemeral: bool,
) -> io::Result<()> {
    Err(unavailable())
}

/// Reconstruct the existing attachment projection from host-owned run records
/// and retained agent listeners. Unknown bindings remain until backend proof
/// authorizes removal; this is not a second runtime store.
pub(crate) fn agent_map_from_runs() -> io::Result<serde_json::Map<String, serde_json::Value>> {
    use serde_json::json;
    let config = crate::native_config::read(&config_path()).map_err(io::Error::other)?;
    let root = config_dir();
    let sockets = root.join("data/sockets");
    let mut map = serde_json::Map::new();
    for agent in crate::host_agents::list().map_err(io::Error::other)? {
        for listener in &config.listeners {
            if listener.agent_id == agent.name
                && let Some(ip) = listener
                    .source_id
                    .as_deref()
                    .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
            {
                let expected = sockets
                    .join(format!("{ip}_{}", agent.name))
                    .join("proxy.sock");
                if listener.socket_path == expected {
                    map.insert(agent.name.clone(), json!({"ip":ip,"socket":expected}));
                }
            }
        }
        if let Ok(Some(run)) = crate::host_runs::read(&agent.name) {
            let ip = run["ip"]
                .as_str()
                .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok());
            if run["agent_id"] == agent.id
                && run["state"] != "stopped"
                && crate::host_runs::id(&agent.name).ok().as_deref()
                    == run["run_id"]
                        .as_str()
                        .map(|id| format!("safeyolo-{id}"))
                        .as_deref()
                && let Some(ip) = ip
            {
                map.insert(agent.name.clone(), json!({"ip":ip,"socket":sockets.join(format!("{ip}_{}",agent.name)).join("proxy.sock")}));
            }
        }
    }
    Ok(map)
}

pub(crate) fn update_agent_map(name: &str, ip: Option<&str>) -> io::Result<()> {
    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let path = agent_map_path()?;
    let _lock = lock_host_state(&path.with_file_name("agent_map.lock"))?;
    let mut map = match std::fs::read(&path) {
        Ok(content) => {
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&content)
                .or_else(|_| agent_map_from_runs())?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => agent_map_from_runs()?,
        Err(error) => return Err(error),
    };
    if let Some(ip) = ip {
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid agent IP",
            ));
        }
        let directory = config_dir()
            .join("data/sockets")
            .join(format!("{ip}_{name}"));
        std::fs::create_dir_all(&directory)?;
        let socket = directory.join("proxy.sock");
        let started = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(io::Error::other)?;
        let started = map
            .get(name)
            .and_then(|entry| entry.get("started"))
            .cloned()
            .unwrap_or_else(|| started.into());
        map.insert(
            name.to_owned(),
            serde_json::json!({"ip":ip,"started":started,"socket":socket}),
        );
    } else {
        map.remove(name);
    }
    std::fs::create_dir_all(
        path.parent()
            .ok_or(io::Error::other("agent map has no parent"))?,
    )?;
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    serde_json::to_writer_pretty(&mut temporary, &map)?;
    use std::io::Write;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(&path)?;
    std::fs::File::open(
        path.parent()
            .ok_or(io::Error::other("agent map has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/owned_run.rs"]
mod guest_command_test_run;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vz_stop_test_helper() {
        let Some(root) = std::env::var_os("SAFEYOLO_TEST_VZ_STOP_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let control =
            tokio::net::UnixListener::bind(root.join("data/vm-control/alice.sock")).unwrap();
        let _shell =
            tokio::net::UnixListener::bind(root.join("data/shell-sockets/alice.sock")).unwrap();
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut connections = 0;
        std::fs::write(root.join("helper.ready"), "ready").unwrap();
        loop {
            tokio::select! {
                _ = terminate.recv() => {
                    if std::env::var_os("SAFEYOLO_TEST_VZ_STOP_FAULT").is_none() {
                        break;
                    }
                    // The process and sockets stay live while executable
                    // inspection fails. This is not positive process absence.
                    std::fs::remove_file(root.join("bin/safeyolo-vm")).unwrap();
                }
                accepted = control.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    connections += 1;
                    std::fs::write(root.join("connections"), connections.to_string()).unwrap();
                    let mut request = [0; 4096];
                    if socket.read(&mut request).await.unwrap() != 0 {
                        use tokio::io::AsyncWriteExt;
                        let response = serde_json::json!({"schema_version":1,"ok":true,"instance":"owned-test","agent":"alice","pid":std::process::id()});
                        let _ = socket.write_all(format!("{response}\n").as_bytes()).await;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn spawn_vz_stop_test_helper(root: &std::path::Path, fault: bool) -> Child {
        for directory in [
            "bin",
            "agents/alice",
            "data/vm-control",
            "data/shell-sockets",
        ] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
        }
        let executable = root.join("bin/safeyolo-vm");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &executable).unwrap();
        let mut command = Command::new(&executable);
        command
            .args([
                "--exact",
                "host_platform::tests::vz_stop_test_helper",
                "--nocapture",
                "--",
                "--control-socket",
            ])
            .arg(root.join("data/vm-control/alice.sock"))
            .arg("fake-secret-argv-canary")
            .env("SAFEYOLO_TEST_VZ_STOP_ROOT", root)
            .env("SAFEYOLO_TEST_VZ_SECRET", "fake-secret-environment-canary")
            .env_remove("SAFEYOLO_TEST_VZ_STOP_FAULT")
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true);
        if fault {
            command.env("SAFEYOLO_TEST_VZ_STOP_FAULT", "1");
        }
        let mut child = command.spawn().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !root.join("helper.ready").exists() {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "helper exited before ready"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid = child.id().unwrap() as i32;
        std::fs::write(root.join("agents/alice/vm.pid"), pid.to_string()).unwrap();
        std::fs::write(
            root.join("agents/alice/vm.token"),
            macos_process_token(i64::from(pid)).unwrap(),
        )
        .unwrap();
        child
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vz_stop_failure_reports_first_identity_loss_and_listener_peer() {
        let temp = tempfile::tempdir().unwrap();
        in_config(temp.path().join("config.toml"), async {
            let mut child = spawn_vz_stop_test_helper(temp.path(), true).await;
            let pid = child.id().unwrap() as i32;
            let birth = vm_process_token("alice", pid).unwrap();
            let error = stop_sandbox("alice").await.unwrap_err().to_string();
            assert!(child.try_wait().unwrap().is_none());
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while std::fs::read_to_string(temp.path().join("connections")).unwrap() != "2" {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            // Cleanup the owned helper before testing the captured operands.
            child.kill().await.unwrap();
            assert!(error.contains("VZ stop invocation="), "{error}");
            assert!(!error.contains("fake-secret"), "{error}");
            assert!(
                error.contains(&format!("root={}", vz_diagnostic_path(temp.path()))),
                "{error}"
            );
            assert!(
                error.contains(&format!("expected_birth={birth}")),
                "{error}"
            );
            assert!(
                error.contains("first_wait_mismatch=stage=expected_executable_canonicalize"),
                "{error}"
            );
            assert!(error.contains("errno=Some(2)"), "{error}");
            assert!(
                error.contains("process_absent=false kill_zero_return=0 errno=None"),
                "{error}"
            );
            assert!(
                error.contains("VZ socket still has a live listener"),
                "{error}"
            );
            assert!(
                error.contains(&format!(
                    "socket={}",
                    vz_diagnostic_path(&temp.path().join("data/vm-control/alice.sock"))
                )),
                "{error}"
            );
            assert!(
                error.contains(&format!("peer_pid={pid} peer_birth={birth}")),
                "{error}"
            );
            // One status connection and the guard's existing connection only.
            assert_eq!(
                std::fs::read_to_string(temp.path().join("connections")).unwrap(),
                "2"
            );
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vz_wait_distinguishes_birth_control_and_executable_mismatch_from_absence() {
        let temp = tempfile::tempdir().unwrap();
        in_config(temp.path().join("config.toml"), async {
            let mut child = spawn_vz_stop_test_helper(temp.path(), false).await;
            let pid = child.id().unwrap() as i32;
            let birth = vm_process_token("alice", pid).unwrap();
            let mut mismatch = None;
            assert!(vz_wait_matches("alice", pid, &birth, &mut mismatch));
            assert!(mismatch.is_none());
            assert!(!vz_wait_matches(
                "alice",
                pid,
                "darwin:0:1:1",
                &mut mismatch
            ));
            let first = mismatch.clone();
            assert!(
                mismatch
                    .as_ref()
                    .unwrap()
                    .contains(&format!("stage=birth_mismatch observed_birth={birth}"))
            );
            assert!(!vz_wait_matches("bob", pid, &birth, &mut mismatch));
            assert_eq!(mismatch, first);
            let control_error = vm_process_token_detail("bob", pid).unwrap_err();
            assert!(!control_error.contains("fake-secret"), "{control_error}");
            assert!(
                control_error.contains("stage=control_argument_mismatch"),
                "{control_error}"
            );
            assert!(
                control_error.contains(&format!(
                    "actual_control_argument={}",
                    vz_diagnostic_path(&temp.path().join("data/vm-control/alice.sock"))
                )),
                "{control_error}"
            );
            assert!(
                control_error.contains(&format!(
                    "expected_control_argument={}",
                    vz_diagnostic_path(&temp.path().join("data/vm-control/bob.sock"))
                )),
                "{control_error}"
            );
            std::fs::remove_file(temp.path().join("bin/safeyolo-vm")).unwrap();
            std::os::unix::fs::symlink("/bin/sh", temp.path().join("bin/safeyolo-vm")).unwrap();
            let executable_error = vm_process_token_detail("alice", pid).unwrap_err();
            assert!(
                executable_error.contains("stage=executable_mismatch actual_executable="),
                "{executable_error}"
            );
            assert!(
                executable_error.contains("expected_executable="),
                "{executable_error}"
            );
            child.kill().await.unwrap();
            let mut absent = None;
            assert!(!vz_wait_matches("alice", pid, &birth, &mut absent));
            let absent = absent.unwrap();
            assert!(absent.contains("stage=proc_pidinfo return=0"), "{absent}");
            assert!(
                absent.contains(&format!(
                    "process_absent=true kill_zero_return=-1 errno=Some({})",
                    libc::ESRCH
                )),
                "{absent}"
            );
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vz_socket_guard_identifies_control_and_shell_and_preserves_paths() {
        let temp = tempfile::tempdir().unwrap();
        in_config(temp.path().join("config.toml"), async {
            let birth = macos_process_token(i64::from(std::process::id())).unwrap();
            for directory in ["data/vm-control", "data/shell-sockets"] {
                let path = temp.path().join(directory).join("alice.sock");
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
                let error = remove_stopped_vz_sockets("alice").unwrap_err().to_string();
                assert!(path.exists());
                assert!(
                    error.contains(&format!("socket={}", vz_diagnostic_path(&path))),
                    "{error}"
                );
                assert!(
                    error.contains(&format!(
                        "peer_pid={} peer_birth={birth}",
                        std::process::id()
                    )),
                    "{error}"
                );
                drop(listener);
            }
            remove_stopped_vz_sockets("alice").unwrap();
            assert!(!temp.path().join("data/vm-control/alice.sock").exists());
            assert!(!temp.path().join("data/shell-sockets/alice.sock").exists());
        })
        .await;
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn vz_diagnostic_paths_escape_controls_and_limit_output() {
        let path = PathBuf::from(format!("/{}", "a\n\t".repeat(1000)));
        let detail = vz_diagnostic_path(&path);
        assert!(!detail.contains(['\n', '\t']));
        assert!(detail.ends_with("...<truncated>"));
        assert!(detail.chars().count() <= 512 + "...<truncated>".len());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vz_stop_success_removes_receipts_and_stale_sockets() {
        let temp = tempfile::tempdir().unwrap();
        in_config(temp.path().join("config.toml"), async {
            let mut child = spawn_vz_stop_test_helper(temp.path(), false).await;
            stop_sandbox("alice").await.unwrap();
            assert!(child.wait().await.unwrap().success());
            for path in [
                "agents/alice/vm.pid",
                "agents/alice/vm.token",
                "data/vm-control/alice.sock",
                "data/shell-sockets/alice.sock",
            ] {
                assert!(!temp.path().join(path).exists(), "{path}");
            }
        })
        .await;
    }

    #[test]
    fn vz_boot_uses_one_staged_selection_and_preserves_explicit_rootfs() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path();
        let directory = config.join("agents/alice");
        std::fs::create_dir_all(&directory).unwrap();
        let selected = config.join("share/guest-versions/sha256/selected");
        let context = serde_json::json!({"guest_inputs":selected});
        // Other boot inputs exist, but must not be mixed into this incarnation.
        std::fs::create_dir_all(config.join("share")).unwrap();
        std::fs::write(config.join("share/Image"), "different kernel").unwrap();
        assert_eq!(
            vz_boot_inputs(config, &directory, &context),
            (
                selected.join("rootfs-base.ext4"),
                selected.join("Image"),
                selected.join("initramfs.cpio.gz"),
            )
        );
        std::fs::write(directory.join("rootfs.ext4"), "custom profile").unwrap();
        assert_eq!(
            vz_boot_inputs(config, &directory, &context),
            (
                directory.join("rootfs.ext4"),
                selected.join("Image"),
                selected.join("initramfs.cpio.gz"),
            )
        );
        std::fs::remove_file(directory.join("rootfs.ext4")).unwrap();
        assert_eq!(
            vz_boot_inputs(config, &directory, &serde_json::json!({})).0,
            config.join("share/rootfs-base.ext4")
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_linux_start_reports_workload_cleanup() {
        const TEST: &str = "host_platform::tests::failed_linux_start_reports_workload_cleanup";
        if let Some(root) = std::env::var_os("SAFEYOLO_TEST_FAILED_START_ROOT") {
            let root = PathBuf::from(root);
            let launch = std::env::var("SAFEYOLO_TEST_FAILED_START_LAUNCH").unwrap();
            let stop = std::env::var("SAFEYOLO_TEST_FAILED_START_STOP").unwrap();
            let directory = root.join("agents/alice");
            let share = directory.join("config-share");
            std::fs::create_dir_all(&share).unwrap();
            std::fs::create_dir(root.join("bin")).unwrap();
            // Restricted PATH cases omit the mapper or aa-exec, but still
            // need account lookup before reaching the intended failure.
            std::os::unix::fs::symlink("/usr/bin/getent", root.join("bin/getent")).unwrap();
            std::fs::write(share.join("guest-init"), b"fixture").unwrap();
            std::fs::write(
                directory.join("config.json"),
                br#"{"linux":{"namespaces":[]}}"#,
            )
            .unwrap();
            let run_id = "0123456789abcdef0123456789abcdef";
            std::fs::write(
                share.join("host-launch-context.json"),
                serde_json::json!({"generation":run_id}).to_string(),
            )
            .unwrap();
            std::fs::write(
                directory.join("runtime.json"),
                serde_json::json!({"run_id":run_id,"state":"starting"}).to_string(),
            )
            .unwrap();
            for (name, script) in [
                (
                    "setfacl",
                    format!(
                        "#!/bin/sh\nprintf 'prepared' > '{}/fixture-acl'\n",
                        directory.display()
                    ),
                ),
                ("ip", "#!/bin/sh\nexit 0\n".to_owned()),
                ("systemctl", "#!/bin/sh\nexit 1\n".to_owned()),
                (
                    "aa-exec",
                    format!(
                        r#"#!/bin/sh
[ "$1" = -p ] && [ "$2" = safeyolo-runsc ] && [ "$3" = -- ] && [ "$4" = unshare ] || exit 2
printf '%s\n' "$@" > '{}/fixture-aa-exec'
shift 3
exec "$@"
"#,
                        directory.display()
                    ),
                ),
                (
                    "unshare",
                    format!(
                        "#!/bin/sh\nprintf '%s' \"$$\" > '{}/fixture-holder.pid'\nexec /usr/bin/unshare \"$@\"\n",
                        directory.display()
                    ),
                ),
                ("tail", "#!/bin/sh\nexec /usr/bin/tail \"$@\"\n".to_owned()),
                (
                    "nsenter",
                    "#!/bin/sh\nexec /usr/bin/nsenter --preserve-credentials \"$@\"\n".to_owned(),
                ),
                (
                    "runsc",
                    format!(
                        r#"#!/bin/sh
case " $* " in
  *" create "*)
    /bin/cp '{0}/runtime.json' '{0}/fixture-holder.json'
    if [ "$SAFEYOLO_TEST_FAILED_START_STOP" = failed ]; then
      printf '{{"run_id":"changed"}}' > '{0}/runtime.json'
    fi
    printf 'fixture boot failure' >&2
    exit 17;;
  *" state "*) printf '{{"id":"safeyolo-{run_id}","status":"stopped"}}';;
  *" delete "*) exit 0;;
  *) exit 2;;
esac
"#,
                        directory.display()
                    ),
                ),
            ] {
                if name == "aa-exec" && launch == "missing-aa-exec" {
                    continue;
                }
                let path = root.join("bin").join(name);
                std::fs::write(&path, script).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            in_instance(root.clone(), async {
                let error = start_sandbox("alice", "10.200.0.1", 4096, true).await.unwrap_err();
                eprintln!("failed-start {launch}/{stop}: {error}");
                let record = std::fs::read(directory.join("fixture-holder.json"))
                    .or_else(|_| std::fs::read(directory.join("runtime.json"))).unwrap();
                let run: serde_json::Value = serde_json::from_slice(&record).unwrap();
                assert_eq!(std::fs::read_to_string(directory.join("fixture-acl")).unwrap(), "prepared");
                if launch == "missing-aa-exec" {
                    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
                    assert!(!directory.join("fixture-holder.pid").exists());
                    assert!(!directory.join("fixture-holder.json").exists());
                    assert!(!directory.join("userns.pid").exists());
                    assert_eq!(run, serde_json::json!({"run_id":run_id,"state":"starting"}));
                    return;
                }
                let error = error.to_string();
                let holder_pid: i64 = std::fs::read_to_string(directory.join("fixture-holder.pid"))
                    .unwrap_or_else(|receipt_error| panic!("namespace holder receipt: {receipt_error}; start_sandbox: {error}"))
                    .parse().unwrap();
                // A successful SIGKILL can return before process exit is visible.
                if stop != "failed" {
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                    while crate::host_lifecycle::process_token(holder_pid).is_some() && tokio::time::Instant::now() < deadline {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                let holder_live = run["holder_pid"].as_i64().is_some_and(|pid| {
                    crate::host_lifecycle::process_token(pid).as_deref() == run["holder_token"].as_str()
                });
                // Reap only this test's identified holder before assertions,
                // including the deliberately refused cleanup case.
                if holder_live {
                    unsafe { libc::kill(run["holder_pid"].as_i64().unwrap() as i32, libc::SIGKILL); }
                }
                let holder = PathBuf::from(format!("/proc/{holder_pid}"));
                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                while holder.exists() && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert!(!holder.exists(), "identified namespace holder was not reaped: {holder_pid}");
                let apparmor = match launch.as_str() {
                    "direct" => false,
                    "apparmor" => true,
                    "native" => std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                        .is_ok_and(|value| value.trim() == "1"),
                    _ => panic!("unknown launch fixture: {launch}"),
                };
                assert_eq!(directory.join("fixture-aa-exec").exists(), apparmor);
                if apparmor {
                    assert_eq!(std::fs::read_to_string(directory.join("fixture-aa-exec")).unwrap(),
                        "-p\nsafeyolo-runsc\n--\nunshare\n-Un\ntail\n-f\n/dev/null\n");
                }
                if stop == "missing-mapper" {
                    assert!(error.contains("No such file or directory"), "{error}");
                    assert!(!error.contains("cleanup failed"), "{error}");
                    assert!(crate::host_lifecycle::process_token(holder_pid).is_none());
                    assert!(!directory.join("userns.pid").exists());
                    return;
                }
                assert!(error.contains("runsc create failed: fixture boot failure"), "{error}");
                let failed_stop = stop == "failed";
                assert_eq!(error.contains("sandbox cleanup failed"), failed_stop, "{error}");
                assert_eq!(holder_live, failed_stop, "{error}");
                if failed_stop {
                    assert!(error.contains("backend process identity is stale or unverified; no process was signalled"), "{error}");
                    assert_eq!(std::fs::read(directory.join("runtime.json")).unwrap(), br#"{"run_id":"changed"}"#);
                    assert!(directory.join("userns.pid").is_file());
                } else {
                    assert!(!directory.join("userns.pid").exists());
                    assert_eq!(crate::host_runs::read("alice").unwrap().unwrap()["state"], "stopped");
                    assert_eq!(crate::host_runs::observe("alice").await["runtime_state"], "stopped");
                    stop_sandbox("alice").await.unwrap();
                }
            }).await;
            return;
        }
        for (launch, stop) in [
            ("native", "succeeded"),
            ("native", "failed"),
            ("native", "missing-mapper"),
            ("direct", "succeeded"),
            ("direct", "failed"),
            ("direct", "missing-mapper"),
            ("apparmor", "succeeded"),
            ("apparmor", "failed"),
            ("apparmor", "missing-mapper"),
            ("missing-aa-exec", "succeeded"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("SAFEYOLO_TEST_FAILED_START_ROOT", root.path())
                .env("SAFEYOLO_TEST_FAILED_START_STOP", stop)
                .env("SAFEYOLO_TEST_FAILED_START_LAUNCH", launch)
                .env(
                    "PATH",
                    if stop == "missing-mapper" || launch == "missing-aa-exec" {
                        root.path().join("bin").display().to_string()
                    } else {
                        format!("{}:/usr/bin:/bin", root.path().join("bin").display())
                    },
                )
                .env("SAFEYOLO_RUNSC_PLATFORM", "systrap")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{launch}/{stop}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guest_output_descriptor_mutator() {
        use std::io::{Read, Write};
        let Ok(command) = std::env::var("SAFEYOLO_TEST_GUEST_FD_MUTATOR") else {
            return;
        };
        assert_eq!(unsafe { (libc::getuid(), libc::geteuid()) }, (0, 0));
        assert_eq!(unsafe { (libc::getgid(), libc::getegid()) }, (0, 0));
        let mut byte = [0];
        assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
        for fd in [1, 2] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
            // Emulate runsc's stdio ownership setup in the real mapped user
            // namespace, including mutation of the shared open-file flags.
            assert_eq!(unsafe { libc::fchown(fd, 0, 0) }, 0);
            let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
            assert_eq!(unsafe { libc::fstat(fd, &mut metadata) }, 0);
            if metadata.st_mode & libc::S_IFMT == libc::S_IFREG {
                assert_eq!(unsafe { libc::fchmod(fd, 0o640) }, 0);
            }
            // Blocking writes exercise output larger than a pipe's buffer.
            if command.contains("large-output") {
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }, 0);
            }
        }
        if command.contains("large-output") {
            std::io::stdout()
                .write_all(&vec![b'O'; 128 * 1024])
                .unwrap();
            std::io::stderr()
                .write_all(&vec![b'E'; 128 * 1024])
                .unwrap();
        } else {
            println!("guest-output-ready");
            std::io::stdout().flush().unwrap();
            let root = std::env::var_os("SAFEYOLO_TEST_GUEST_STDIO_ROOT").unwrap();
            let release = PathBuf::from(root).join("release");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !release.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "guest output was not streamed"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            eprintln!("guest diagnostic: {command}");
            if command.contains("cancelled-output") {
                std::fs::write(
                    release.with_file_name("transport.pid"),
                    std::process::id().to_string(),
                )
                .unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        if command.contains("signal-exit") {
            unsafe { libc::raise(libc::SIGTERM) };
        }
        std::process::exit(if command.contains("auth-failure") {
            7
        } else {
            0
        });
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn guest_command_preserves_private_log_and_streams_output() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        const TEST: &str =
            "host_platform::tests::guest_command_preserves_private_log_and_streams_output";
        if let Some(root) = std::env::var_os("SAFEYOLO_TEST_GUEST_STDIO_ROOT") {
            let root = PathBuf::from(root);
            std::fs::create_dir(root.join("bin")).unwrap();
            let mut run = guest_command_test_run::OwnedRun::start(&root);
            // Descriptor setup needs mapped namespace root. Select its IDs
            // explicitly without requiring a rootless caller to clear groups
            // after the owned fixture has disabled setgroups.
            std::fs::write(
                root.join("bin/nsenter"),
                "#!/bin/sh\nexec /usr/bin/nsenter --preserve-credentials --setuid=0 --setgid=0 \"$@\"\n",
            )
            .unwrap();
            let script = format!(
                "#!/bin/sh\ncase \"$3\" in\n state) printf '{{\"id\":\"%s\",\"status\":\"running\"}}\\n' \"$4\";;\n exec) for argument; do SAFEYOLO_TEST_GUEST_FD_MUTATOR=$argument; done; export SAFEYOLO_TEST_GUEST_FD_MUTATOR; exec '{}' --exact host_platform::tests::guest_output_descriptor_mutator --nocapture;;\n *) exit 2;;\nesac\n",
                std::env::current_exe().unwrap().display()
            );
            std::fs::write(root.join("bin/runsc"), script).unwrap();
            std::fs::set_permissions(
                root.join("bin/runsc"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            // Environment changes are confined to this test's child process.
            unsafe {
                std::env::set_var("PATH", root.join("bin"));
            }
            in_instance(root.clone(), async {
                if std::env::var_os("SAFEYOLO_TEST_INHERITED_GUEST_OUTPUT").is_some() {
                    assert!(
                        runsc_command("alice")
                            .unwrap()
                            .args(["exec", "inherited-control"])
                            .stdin(std::process::Stdio::null())
                            .status()
                            .await
                            .unwrap()
                            .success()
                    );
                } else {
                    for (command, code) in [
                        ("/safeyolo/guest-desktop start 1280x800", 0),
                        ("/home/agent/.safeyolo-command --version", 0),
                        ("codex login status # auth-failure", 7),
                        ("large-output", 0),
                        ("signal-exit", 1),
                    ] {
                        assert_eq!(exec_guest_command("alice", command).await.unwrap(), code);
                    }
                    assert!(
                        exec_guest_command("../other-agent", "ignored")
                            .await
                            .is_err()
                    );
                    assert!(
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            exec_guest_command("alice", "cancelled-output")
                        )
                        .await
                        .is_err()
                    );
                    let pid: i64 = std::fs::read_to_string(root.join("transport.pid"))
                        .unwrap()
                        .parse()
                        .unwrap();
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                    while crate::host_lifecycle::process_token(pid).is_some() {
                        assert!(
                            tokio::time::Instant::now() < deadline,
                            "cancelled guest transport survived"
                        );
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    std::fs::remove_file(root.join("bin/runsc")).unwrap();
                    assert!(exec_guest_command("alice", "ignored").await.is_err());
                }
            })
            .await;
            run.child.kill().unwrap();
            run.assert_exited();
            return;
        }
        for inherited in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            std::fs::create_dir(root.join("logs")).unwrap();
            std::fs::set_permissions(root.join("logs"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let path = root.join("logs/proxy.log");
            let log = std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .append(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            let before = log.metadata().unwrap();
            let flags = unsafe { libc::fcntl(log.as_raw_fd(), libc::F_GETFL) };
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--nocapture"])
                .env("SAFEYOLO_TEST_GUEST_STDIO_ROOT", root)
                .stdin(std::process::Stdio::piped())
                .stdout(log.try_clone().unwrap())
                .stderr(log.try_clone().unwrap())
                .kill_on_drop(true);
            if inherited {
                command.env("SAFEYOLO_TEST_INHERITED_GUEST_OUTPUT", "1");
            }
            let mut child = command.spawn().unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let mut bytes = [0; 4096];
                let count = log.read_at(&mut bytes, 0).unwrap();
                if String::from_utf8_lossy(&bytes[..count]).contains("guest-output-ready") {
                    std::fs::write(root.join("release"), "continue").unwrap();
                    break;
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "guest transport exited before streaming output: {}",
                    String::from_utf8_lossy(&bytes[..count])
                );
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "guest output was not visible before completion: {}",
                    String::from_utf8_lossy(&bytes[..count])
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .unwrap()
                .unwrap();
            let after = log.metadata().unwrap();
            let observed = unsafe { libc::fcntl(log.as_raw_fd(), libc::F_GETFL) };
            if inherited {
                let mapping = crate::linux_host::selected_mapping().unwrap();
                assert_eq!(
                    (after.uid(), after.gid(), after.mode() & 0o777),
                    (mapping.uid_base, mapping.gid_base, 0o640)
                );
                assert_eq!(observed, flags | libc::O_NONBLOCK);
                assert_eq!(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
            } else {
                assert_eq!(
                    (after.uid(), after.gid(), after.mode()),
                    (before.uid(), before.gid(), before.mode())
                );
                assert_eq!(observed, flags);
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"restarted\n")
                    .unwrap();
                let output = std::fs::read(&path).unwrap();
                // Concurrent stdout/stderr writes may interleave in this shared sink.
                for byte in [b'O', b'E'] {
                    assert_eq!(
                        output.iter().filter(|&&value| value == byte).count(),
                        128 * 1024,
                        "incomplete guest output for byte {byte:?}"
                    );
                }
                assert!(String::from_utf8_lossy(&output).contains("guest diagnostic:"));
            }
            assert!(
                status.success(),
                "{}",
                String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default())
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn guest_output_deadline_refuses_partial_output_and_stops_its_transport() {
        let child = Command::new("/bin/sh")
            .args(["-c", "printf 'partial running state'; exec /bin/sleep 60"])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = i64::from(child.id().unwrap());
        let token = crate::host_lifecycle::process_token(pid).unwrap();
        let started = std::time::Instant::now();
        let error = wait_guest_command_output(child, std::time::Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while crate::host_lifecycle::process_token(pid).as_deref() == Some(&token) {
            assert!(
                std::time::Instant::now() < deadline,
                "owned transport survived its deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let completed = Command::new("/bin/sh")
            .args(["-c", "printf '{}'"])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        assert_eq!(
            wait_guest_command_output(completed, std::time::Duration::from_secs(1))
                .await
                .unwrap()
                .stdout,
            b"{}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn port_forward_failures_are_bounded_and_do_not_disclose_stderr() {
        for (script, kind, reason) in [
            (
                "printf 'connection was refused: /private/path secret-token' >&2; exit 1",
                io::ErrorKind::ConnectionRefused,
                "guest port refused",
            ),
            (
                "printf 'runsc failed: /private/path secret-token' >&2; exit 1",
                io::ErrorKind::Other,
                "runsc command, state or port forwarding failed",
            ),
            (
                "exec /bin/sleep 5",
                io::ErrorKind::TimedOut,
                "transport timed out",
            ),
        ] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", script])
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let failure = port_forward_failure(&mut child).await;
            let _ = child.kill().await;
            let _ = child.wait().await;
            assert_eq!(failure.kind(), kind);
            assert!(failure.to_string().contains(reason), "{failure}");
            assert!(!failure.to_string().contains("private"));
            assert!(!failure.to_string().contains("secret-token"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guest_stdin_flag_mutator() {
        // Run only as a child of the descriptor regression, so the test
        // runner's own input flags and bytes are never changed.
        let Ok(mode) = std::env::var("SAFEYOLO_TEST_STDIN_MUTATOR") else {
            return;
        };
        let flags = unsafe { libc::fcntl(0, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        use std::io::Read;
        if mode == "interactive" {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).unwrap();
            assert_eq!(input, "guest input\n");
        } else if mode == "null" {
            let mut byte = [0];
            assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn guest_command_stdin_preserves_operator_input_and_interactive_input() {
        use std::io::{BufRead, Read, Write};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        const TEST: &str = "host_platform::tests::guest_command_stdin_preserves_operator_input_and_interactive_input";
        if let Ok(mode) = std::env::var("SAFEYOLO_TEST_GUEST_STDIN") {
            let original = unsafe { libc::fcntl(0, libc::F_GETFL) };
            assert!(original >= 0 && original & libc::O_NONBLOCK == 0);
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "host_platform::tests::guest_stdin_flag_mutator",
                    "--nocapture",
                ])
                .env(
                    "SAFEYOLO_TEST_STDIN_MUTATOR",
                    if mode == "interactive" {
                        "interactive"
                    } else if mode == "inherited" {
                        "flags"
                    } else {
                        "null"
                    },
                );
            let mut runtime = guest_command_stdio(
                &mut command,
                mode != "visible",
                matches!(mode.as_str(), "inherited" | "interactive"),
            )
            .spawn()
            .unwrap();
            assert!(runtime.wait().await.unwrap().success());
            let observed = unsafe { libc::fcntl(0, libc::F_GETFL) };
            if matches!(mode.as_str(), "inherited" | "interactive") {
                assert_eq!(observed, original | libc::O_NONBLOCK);
                if mode == "inherited" {
                    let mut byte = [0];
                    assert_eq!(
                        std::io::stdin().read(&mut byte).unwrap_err().raw_os_error(),
                        Some(libc::EAGAIN)
                    );
                }
                // Only the deliberately inherited negative control needs
                // restoration. Production noninteractive commands do not.
                assert_eq!(unsafe { libc::fcntl(0, libc::F_SETFL, original) }, 0);
            } else {
                assert_eq!(observed, original);
            }
            if mode == "interactive" {
                let mut remaining = String::new();
                std::io::stdin().read_to_string(&mut remaining).unwrap();
                assert!(remaining.is_empty());
            } else {
                println!("operator-input-ready");
                std::io::stdout().flush().unwrap();
                let mut input = std::io::stdin().lock();
                let mut final_line = String::new();
                input.read_line(&mut final_line).unwrap();
                assert_eq!(final_line, "finish\n");
                let mut remaining = String::new();
                input.read_to_string(&mut remaining).unwrap();
                assert_eq!(remaining, "remaining input\n");
            }
            return;
        }
        for mode in ["inherited", "visible", "captured", "interactive"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env("SAFEYOLO_TEST_GUEST_STDIN", mode)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
            if mode == "interactive" {
                input.write_all(b"guest input\n").await.unwrap();
            } else {
                loop {
                    let line = tokio::time::timeout(Duration::from_secs(5), output.next_line())
                        .await
                        .unwrap()
                        .unwrap()
                        .expect("stdin control ended before final input");
                    if line == "operator-input-ready" {
                        break;
                    }
                }
                input.write_all(b"finish\nremaining input\n").await.unwrap();
            }
            drop(input);
            let result = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                result.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runsc_boot_accepts_sentry_serialization_and_exact_split_arguments() {
        let id = "safeyolo-f9c7cbfd6d8744b6bd6cbde0d10101f7";
        let root = std::path::Path::new("/home/agent/f817n/a/run");
        for program in ["runsc", "/usr/local/bin/runsc", "runsc-sandbox"] {
            for root_arguments in [
                "--root\0/home/agent/f817n/a/run",
                "--root=/home/agent/f817n/a/run",
            ] {
                let command =
                    format!("{program}\0{root_arguments}\0--platform=systrap\0boot\0{id}\0");
                assert!(is_runsc_boot(command.as_bytes(), id, root), "{command:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runsc_boot_rejects_a_foreign_root_run_or_command() {
        let id = "safeyolo-f9c7cbfd6d8744b6bd6cbde0d10101f7";
        let root = std::path::Path::new("/home/agent/f817n/a/run");
        for (program, root_arguments, operation, run) in [
            (
                "runsc-sandbox",
                "--root=/home/agent/f817n/b/run",
                "boot",
                id,
            ),
            ("runsc", "--root\0/home/agent/f817n/b/run", "boot", id),
            (
                "runsc-sandbox",
                "--root=/home/agent/f817n/a/run-other",
                "boot",
                id,
            ),
            (
                "runsc-sandbox",
                "--root=/home/agent/f817n/a/run",
                "boot",
                "safeyolo-0123456789abcdef0123456789abcdef",
            ),
            (
                "runsc-sandbox",
                "--root=/home/agent/f817n/a/run",
                "boot",
                "prefix-safeyolo-f9c7cbfd6d8744b6bd6cbde0d10101f7",
            ),
            (
                "runsc-sandbox",
                "--root=/home/agent/f817n/a/run",
                "state",
                id,
            ),
            (
                "not-runsc-sandbox",
                "--root=/home/agent/f817n/a/run",
                "boot",
                id,
            ),
            ("sleep", "--root=/home/agent/f817n/a/run", "boot", id),
        ] {
            let command = format!("{program}\0{root_arguments}\0{operation}\0{run}\0");
            assert!(!is_runsc_boot(command.as_bytes(), id, root), "{command:?}");
        }
    }

    #[test]
    fn vz_test_runner_receives_the_installed_helper_directly() {
        let helper = std::path::Path::new("/owned/bin/safeyolo-vm");
        let direct = vz_helper_command(helper, None, None).unwrap();
        assert_eq!(direct.as_std().get_program(), helper);
        assert_eq!(direct.as_std().get_args().count(), 0);
        let temporary = tempfile::tempdir().unwrap();
        let runner = temporary.path().join("run-vz-test");
        std::fs::write(&runner, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut supervised =
            vz_helper_command(helper, Some(runner.as_os_str()), Some(OsStr::new("900"))).unwrap();
        supervised
            .arg("run")
            .arg("--control-socket")
            .arg("/owned/data/vm-control/probe.sock");
        assert_eq!(supervised.as_std().get_program(), runner);
        assert_eq!(
            supervised.as_std().get_args().collect::<Vec<_>>(),
            vec![
                "--timeout-seconds",
                "900",
                "--",
                "/owned/bin/safeyolo-vm",
                "run",
                "--control-socket",
                "/owned/data/vm-control/probe.sock"
            ]
        );
        for timeout in [
            None,
            Some(OsStr::new("0")),
            Some(OsStr::new("-1")),
            Some(OsStr::new("1.5")),
        ] {
            assert!(vz_helper_command(helper, Some(runner.as_os_str()), timeout).is_err());
        }
        assert!(vz_helper_command(helper, None, Some(OsStr::new("900"))).is_err());
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            vz_helper_command(helper, Some(runner.as_os_str()), Some(OsStr::new("900"))).is_err()
        );
        assert!(
            vz_helper_command(
                helper,
                Some(OsStr::new("run-vz-test")),
                Some(OsStr::new("900"))
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn failed_vz_start_allows_the_owned_runner_to_finish_cleanup() {
        for sandbox_stop_failed in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("cleaned");
            let mut child = Command::new("/bin/sh")
            .args(["-c", "trap 'printf cleaned > \"$1\"; exit 0' TERM; printf ready; while :; do sleep 0.02; done", "runner"])
            .arg(&marker)
            .stdout(std::process::Stdio::piped())
            .spawn().unwrap();
            let mut ready = [0; 5];
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                child.stdout.as_mut().unwrap().read_exact(&mut ready),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&ready, b"ready");
            let startup = io::Error::new(io::ErrorKind::NotFound, "fixture startup failure");
            let stop = if sandbox_stop_failed {
                Err(io::Error::other("helper identity is missing"))
            } else {
                Ok(())
            };
            let error = cleanup_failed_vz_start(startup, stop, &mut child).await;
            assert!(error.to_string().starts_with("fixture startup failure"));
            if sandbox_stop_failed {
                assert!(error.to_string().contains("sandbox stop failed: helper identity is missing; owned VZ launch process stopped"));
            } else {
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
                assert_eq!(error.to_string(), "fixture startup failure");
            }
            assert_eq!(std::fs::read(marker).unwrap(), b"cleaned");
            assert!(child.try_wait().unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn failed_vz_start_preserves_the_startup_and_launch_owner_errors() {
        for sandbox_stop_failed in [false, true] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "trap '' TERM; printf ready; exec sleep 60"])
                .stdout(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut ready = [0; 5];
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                child.stdout.as_mut().unwrap().read_exact(&mut ready),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&ready, b"ready");
            let stop = if sandbox_stop_failed {
                Err(io::Error::other("fixture sandbox stop failure"))
            } else {
                Ok(())
            };
            tokio::time::pause();
            let error = cleanup_failed_vz_start(
                io::Error::other("fixture startup failure"),
                stop,
                &mut child,
            )
            .await
            .to_string();
            tokio::time::resume();
            let survived = child.try_wait().unwrap().is_none();
            child.kill().await.unwrap();
            assert!(survived);
            assert!(error.starts_with("fixture startup failure"), "{error}");
            assert!(error.contains("VZ launch-owner cleanup failed: VZ launch owner did not finish cleanup; preserve the disposable instance"), "{error}");
            assert_eq!(
                error.contains("sandbox cleanup failed: fixture sandbox stop failure"),
                sandbox_stop_failed,
                "{error}"
            );
            assert!(!error.contains("cleanup succeeded"));
        }
    }
}
