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
    let pid = i32::try_from(pid).ok().filter(|pid| *pid > 0)?;
    let mut info = std::mem::MaybeUninit::<DarwinProcessInfo>::zeroed();
    let size = std::mem::size_of::<DarwinProcessInfo>();
    if size != 136 {
        return None;
    }
    let returned = unsafe { proc_pidinfo(pid, 3, 0, info.as_mut_ptr().cast(), size as i32) };
    if returned != size as i32 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    if info.first_fields[3] != pid as u32
        || info.started_seconds == 0
        || info.started_microseconds >= 1_000_000
    {
        return None;
    }
    Some(format!(
        "darwin:{pid}:{}:{}",
        info.started_seconds, info.started_microseconds
    ))
}

#[cfg(target_os = "macos")]
fn process_arguments(pid: i32, executable: &std::path::Path) -> Option<Vec<Vec<u8>>> {
    let mut buffer = [0u8; 4096];
    let size = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if size <= 0 {
        return None;
    }
    let path = std::ffi::CStr::from_bytes_until_nul(&buffer).ok()?;
    let actual = std::fs::canonicalize(std::path::Path::new(std::ffi::OsStr::from_bytes(
        path.to_bytes(),
    )))
    .ok()?;
    let expected = executable.canonicalize().ok()?;
    if actual != expected {
        return None;
    }
    // A helper executable alone cannot identify an agent. Bind its actual
    // launch arguments to this instance's private control endpoint.
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0;
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size > 1024 * 1024
    {
        return None;
    }
    let mut bytes = vec![0u8; size];
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    bytes.truncate(size);
    let argc = i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
    if !(1..=1024).contains(&argc) {
        return None;
    }
    let mut offset = 4 + bytes.get(4..)?.iter().position(|b| *b == 0)? + 1;
    while bytes.get(offset) == Some(&0) {
        offset += 1;
    }
    let mut arguments = Vec::new();
    for _ in 0..argc {
        let length = bytes.get(offset..)?.iter().position(|b| *b == 0)?;
        arguments.push(bytes[offset..offset + length].to_vec());
        offset += length + 1;
    }
    Some(arguments)
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
    let token = macos_process_token(i64::from(pid))?;
    let control = config_dir()
        .join("data/vm-control")
        .join(format!("{name}.sock"));
    process_has_path_argument(
        i64::from(pid),
        &config_dir().join("bin/safeyolo-vm"),
        b"--control-socket",
        &control,
    )
    .then_some(token)
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
    let expected = [
        (0, 100000, 1000),
        (1000, unsafe { libc::getuid() }, 1),
        (1001, 101001, 64534),
    ];
    let mappings = std::fs::read_to_string(format!("/proc/{pid}/uid_map")).ok()?;
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
    if actual != expected {
        return None;
    }
    Some(pid)
}

#[cfg(target_os = "linux")]
pub(crate) fn control_pid(name: &str) -> Option<u32> {
    if let Some(pid) = userns_pid(name) {
        return Some(pid);
    }
    // The live sentry still owns the original namespaces after holder loss.
    // Validate the incarnation, process birth, command and mapping before
    // entering it. This is recovery of that context, never direct runsc.
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
    let pid = control_pid(name).ok_or_else(|| io::Error::other("sandbox namespace control is unavailable; run agent diagnostics or stop the owned backend"))?;
    let mut command = Command::new("nsenter");
    command.args([
        "--user",
        "--net",
        "--target",
        &pid.to_string(),
        "--",
        "runsc",
    ]);
    let root = std::env::var_os("SAFEYOLO_RUNSC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir().join("run"));
    command.arg("--root").arg(root);
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
    let pid = control_pid(name)
        .ok_or_else(|| io::Error::other("sandbox namespace control is unavailable"))?;
    let mut command = Command::new("nsenter");
    command.args([
        "--user",
        "--net",
        "--target",
        &pid.to_string(),
        "--",
        program,
    ]);
    Ok(command)
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
        "runsc",
    ]);
    Ok(command)
}

#[cfg(target_os = "linux")]
async fn start_userns(name: &str) -> io::Result<u32> {
    let restricts =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|value| value.trim() == "1");
    let mut holder = if restricts {
        let mut command = Command::new("aa-exec");
        command.args([
            "-p",
            "safeyolo-runsc",
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
        let _ = child.kill().await;
        return Err(io::Error::other(
            "user namespace holder did not become ready",
        ));
    }
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let map = Command::new("newuidmap")
        .args([
            pid.to_string(),
            "0".to_owned(),
            "100000".to_owned(),
            "1000".to_owned(),
            "1000".to_owned(),
            uid.to_string(),
            "1".to_owned(),
            "1001".to_owned(),
            "101001".to_owned(),
            "64534".to_owned(),
        ])
        .output()
        .await?;
    if !map.status.success() {
        let _ = child.kill().await;
        return Err(io::Error::other(format!(
            "newuidmap failed: {}",
            String::from_utf8_lossy(&map.stderr)
        )));
    }
    let map = Command::new("newgidmap")
        .args([
            pid.to_string(),
            "0".to_owned(),
            "100000".to_owned(),
            "1000".to_owned(),
            "1000".to_owned(),
            gid.to_string(),
            "1".to_owned(),
            "1001".to_owned(),
            "101001".to_owned(),
            "64534".to_owned(),
        ])
        .output()
        .await?;
    if !map.status.success() {
        let _ = child.kill().await;
        return Err(io::Error::other(format!(
            "newgidmap failed: {}",
            String::from_utf8_lossy(&map.stderr)
        )));
    }
    std::fs::write(
        config_dir().join("agents").join(name).join("userns.pid"),
        pid.to_string(),
    )?;
    if let Err(error) = crate::host_runs::remember_process(name, "holder", pid) {
        let _ = child.kill().await;
        return Err(io::Error::other(error));
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
        .args(["-m", "u:100000:rwx"])
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
        std::fs::write(share.join("per-run-go"), b"")?;
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
        let platform = match std::env::var("SAFEYOLO_RUNSC_PLATFORM")
            .unwrap_or_default()
            .as_str()
        {
            "systrap" => "systrap",
            "" | "auto" => {
                let operator_access = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/kvm")
                    .is_ok();
                let subordinate_access = if operator_access {
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        Command::new("getfacl").arg("/dev/kvm").output(),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .is_some_and(|output| {
                        output.status.success()
                            && String::from_utf8_lossy(&output.stdout).contains("user:100000:rw")
                    })
                } else {
                    false
                };
                if subordinate_access { "kvm" } else { "systrap" }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid runsc platform override",
                ));
            }
        };
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
        std::fs::write(
            directory.join("container.pid"),
            value
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                .to_string(),
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while tokio::time::Instant::now() < deadline && guest_exec_available(name).await {
            if status_dir.join("per-run-started").is_file() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(io::Error::other("guest did not reach per-run startup"))
    }
    .await;
    if result.is_err() {
        let _ = stop_sandbox(name).await;
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
            } else if control_pid(name).is_none() {
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
    if !valid_agent_name(name) || !guest_exec_available(name).await {
        return Err(unavailable());
    }
    let wrapped = format!(
        ". /etc/environment 2>/dev/null; if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    );
    let status = runsc_command(name)?
        .args([
            "exec",
            "--user",
            "1000:1000",
            "--cwd",
            "/workspace",
            &crate::host_runs::id(name).map_err(io::Error::other)?,
            "/bin/bash",
            "-lc",
            &wrapped,
        ])
        .stdin(std::process::Stdio::null())
        .status()
        .await?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(target_os = "linux")]
pub(crate) async fn spawn_guest_command_with_output(
    name: &str,
    command: &str,
    capture: bool,
) -> io::Result<tokio::process::Child> {
    if !valid_agent_name(name) || !guest_exec_available(name).await {
        return Err(unavailable());
    }
    let wrapped = format!(
        ". /etc/environment 2>/dev/null; if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    );
    runsc_command(name)?
        .args([
            "exec",
            "--user",
            "1000:1000",
            "--cwd",
            "/workspace",
            &crate::host_runs::id(name).map_err(io::Error::other)?,
            "/bin/bash",
            "-lc",
            &wrapped,
        ])
        .stdin(if capture {
            std::process::Stdio::null()
        } else {
            std::process::Stdio::inherit()
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
        return crate::host_runs::stop_without_holder(name)
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
        return crate::host_runs::stop_without_holder(name)
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
    let directory = config_dir().join("agents").join(name);
    let _ = std::fs::remove_file(directory.join("userns.pid"));
    let _ = std::fs::remove_file(directory.join("container.pid"));
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
    let wrapped = macos_guest_command(command);
    Command::new("ssh")
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
            &format!("ProxyCommand=nc -U '{socket}'"),
            if capture { "-T" } else { "-t" },
            "agent@sandbox",
            &wrapped,
        ])
        .stdin(if capture {
            std::process::Stdio::null()
        } else {
            std::process::Stdio::inherit()
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
    let Some(token) = vm_process_token(name, pid) else {
        if unsafe { libc::kill(pid, 0) } != 0
            && io::Error::last_os_error().kind() == io::ErrorKind::NotFound
        {
            std::fs::remove_file(path)?;
            let _ = std::fs::remove_file(config_dir().join("agents").join(name).join("vm.token"));
            return Ok(());
        }
        return Err(io::Error::other(
            "VM PID does not identify this agent's helper",
        ));
    };
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    for _ in 0..100 {
        if vm_process_token(name, pid).as_deref() != Some(&token) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if vm_process_token(name, pid).as_deref() == Some(&token) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        for _ in 0..50 {
            if vm_process_token(name, pid).as_deref() != Some(&token) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if vm_process_token(name, pid).as_deref() == Some(&token) {
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
                Ok(_) => return Err(io::Error::other("VZ socket still has a live listener")),
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
    let rootfs = if directory.join("rootfs.ext4").is_file() {
        directory.join("rootfs.ext4")
    } else {
        config.join("share/rootfs-base.ext4")
    };
    let kernel = config.join("share/Image");
    let initrd = config.join("share/initramfs.cpio.gz");
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
    if started.is_err() {
        // Stop the independently verified helper when available. Also stop
        // the owned launch process if identity persistence itself failed.
        let _ = stop_sandbox(name).await;
        stop_vz_launch_owner(&mut child).await?;
    }
    started
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn spawn_guest_command(
    name: &str,
    command: &str,
) -> io::Result<tokio::process::Child> {
    spawn_guest_command_with_output(name, command, false).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn guest_command_output(
    name: &str,
    command: &str,
    timeout: std::time::Duration,
) -> io::Result<std::process::Output> {
    let child = spawn_guest_command_with_output(name, command, true).await?;
    tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "guest command timed out"))?
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn coding_agent_observation(name: &str) -> io::Result<String> {
    let child =
        spawn_guest_command_with_output(name, "/safeyolo/safeyolo-guest observe check", true)
            .await?;
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait_with_output())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "coding-agent observation timed out",
            )
        })??;
    if !output.status.success() {
        return Err(io::Error::other("native coding-agent observation failed"));
    }
    let state = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    match state.trim() {
        "running" | "stopped" => Ok(state.trim().into()),
        _ => Err(io::Error::other(
            "native coding-agent observation is unverified",
        )),
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
/// and retained native listeners. Unknown bindings remain until backend proof
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

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
        stop_vz_launch_owner(&mut child).await.unwrap();
        assert_eq!(std::fs::read(marker).unwrap(), b"cleaned");
        assert!(child.try_wait().unwrap().is_some());
    }
}
