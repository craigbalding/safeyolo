//! Host-to-guest byte streams for native proxy features.
//!
//! Linux uses runsc's connected-FD port forwarding. macOS uses the existing
//! per-agent VZ shell bridge. Neither path opens a host TCP listener.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{io, path::PathBuf};
#[cfg(target_os = "macos")]
use std::{
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
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
    fn proc_listchildpids(pid: i32, buffer: *mut libc::c_void, size: i32) -> i32;
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
fn vm_process_token(name: &str, pid: i32) -> Option<String> {
    let token = macos_process_token(i64::from(pid))?;
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
    let expected = std::fs::canonicalize(config_dir().join("bin/safeyolo-vm")).ok()?;
    if actual != expected {
        return None;
    }
    let stored = config_dir().join("agents").join(name).join("vm.token");
    match std::fs::read_to_string(stored) {
        Ok(value) if value.trim() != token => None,
        Ok(_) => Some(token),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Some(token),
        Err(_) => None,
    }
}

#[cfg(any(target_os = "macos", test))]
fn vz_test_command(
    helper: &std::path::Path,
    runner: Option<std::ffi::OsString>,
    timeout: Option<std::ffi::OsString>,
) -> io::Result<Command> {
    use std::os::unix::fs::PermissionsExt;

    let (runner, timeout) = match (runner, timeout) {
        (None, None) => return Ok(Command::new(helper)),
        (Some(runner), Some(timeout)) => (PathBuf::from(runner), timeout),
        _ => {
            return Err(io::Error::other(
                "VZ test supervision needs a runner and timeout",
            ));
        }
    };
    let seconds = timeout
        .to_str()
        .and_then(|value| {
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
                value.parse::<u64>().ok().filter(|seconds| *seconds > 0)
            } else {
                None
            }
        })
        .ok_or(io::Error::other(
            "VZ test timeout must be a positive whole number",
        ))?;
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
        .arg("--timeout-seconds")
        .arg(seconds.to_string())
        .arg("--")
        .arg(helper);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn vz_runner_helper(name: &str, runner_pid: i32) -> io::Result<Option<(i32, String)>> {
    let mut pids = [0i32; 32];
    let count = unsafe {
        proc_listchildpids(
            runner_pid,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&pids) as i32,
        )
    };
    if count < 0 || count as usize >= pids.len() {
        return Err(io::Error::other(
            "cannot enumerate the VZ test runner's direct children",
        ));
    }
    let mut found = None;
    for &pid in &pids[..count as usize] {
        let mut info = std::mem::MaybeUninit::<DarwinProcessInfo>::zeroed();
        let size = std::mem::size_of::<DarwinProcessInfo>();
        if unsafe { proc_pidinfo(pid, 3, 0, info.as_mut_ptr().cast(), size as i32) } != size as i32
        {
            continue; // A direct child may exit between enumeration and inspection.
        }
        let info = unsafe { info.assume_init() };
        if info.first_fields[4] != runner_pid as u32 || info.first_fields[1] == 5 {
            continue;
        }
        let observed = format!(
            "darwin:{pid}:{}:{}",
            info.started_seconds, info.started_microseconds
        );
        if vm_process_token(name, pid).as_deref() == Some(&observed) {
            if found.is_some() {
                return Err(io::Error::other(
                    "VZ test runner has multiple matching helper children",
                ));
            }
            found = Some((pid, observed));
        }
    }
    Ok(found)
}

#[cfg(target_os = "macos")]
fn vz_receipt_process_alive(receipt: &serde_json::Value, field: &str) -> io::Result<bool> {
    if field == "helper_pid" && receipt.get(field).is_some_and(serde_json::Value::is_null) {
        return Ok(false); // A failed launch may not have exposed its helper child.
    }
    let pid = receipt
        .get(field)
        .and_then(serde_json::Value::as_i64)
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
        .ok_or(io::Error::other("invalid VZ test supervision PID"))?;
    let token_field = field.replace("pid", "start_token");
    let recorded = receipt
        .get(&token_field)
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or(io::Error::other("invalid VZ test supervision start token"))?;
    if unsafe { libc::kill(pid, 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(false);
        }
        return Err(error);
    }
    let mut info = std::mem::MaybeUninit::<DarwinProcessInfo>::zeroed();
    let size = std::mem::size_of::<DarwinProcessInfo>();
    if unsafe { proc_pidinfo(pid, 3, 0, info.as_mut_ptr().cast(), size as i32) } != size as i32 {
        if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return Ok(false); // The owned process exited after the liveness check.
        }
        return Err(io::Error::other(
            "cannot establish VZ supervision process identity",
        ));
    }
    let info = unsafe { info.assume_init() };
    if info.first_fields[3] != pid as u32
        || info.started_seconds == 0
        || info.started_microseconds >= 1_000_000
    {
        return Err(io::Error::other("invalid VZ supervision process identity"));
    }
    let observed = format!(
        "darwin:{pid}:{}:{}",
        info.started_seconds, info.started_microseconds
    );
    Ok(info.first_fields[1] != 5 && observed == recorded)
}

#[cfg(target_os = "macos")]
async fn stop_vz_test_runner(directory: &std::path::Path) -> io::Result<()> {
    let path = directory.join("vm-supervisor.json");
    let receipt: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    // Validate both identities before any signal.
    let runner_alive = vz_receipt_process_alive(&receipt, "pid")?;
    vz_receipt_process_alive(&receipt, "helper_pid")?;
    if runner_alive {
        let pid = receipt["pid"]
            .as_i64()
            .ok_or(io::Error::other("missing VZ runner PID"))? as i32;
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if !vz_receipt_process_alive(&receipt, "pid")?
            && !vz_receipt_process_alive(&receipt, "helper_pid")?
        {
            for name in ["vm.pid", "vm.token", "vm-supervisor.json"] {
                match std::fs::remove_file(directory.join(name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(io::Error::other(
        "VZ test runner or its owned helper did not stop",
    ))
}

#[cfg(target_os = "macos")]
async fn reclaim_stopped_vz_test_runner(directory: &std::path::Path) -> io::Result<()> {
    let path = directory.join("vm-supervisor.json");
    if path.exists() {
        let receipt: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        if vz_receipt_process_alive(&receipt, "pid")?
            || vz_receipt_process_alive(&receipt, "helper_pid")?
        {
            return Err(io::Error::other(
                "the existing VZ test runner or its helper is still active",
            ));
        }
        stop_vz_test_runner(directory).await?;
    }
    Ok(())
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
    std::env::var_os("SAFEYOLO_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".safeyolo")
        })
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
fn userns_pid(name: &str) -> Option<u32> {
    let path = config_dir().join("agents").join(name).join("userns.pid");
    let pid = std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
        return None;
    }
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
fn runsc_root() -> PathBuf {
    std::env::var_os("SAFEYOLO_RUNSC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir().join("run"))
}

#[cfg(target_os = "linux")]
fn userns_command(name: &str, program: &str) -> Command {
    let mut command = Command::new("nsenter");
    command.args([
        "--user",
        "--net",
        "--target",
        &userns_pid(name).unwrap_or(0).to_string(),
        "--",
        program,
    ]);
    command
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
fn scoped_runsc_create(name: &str, memory_mb: u64) -> Command {
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
        &userns_pid(name).unwrap_or(0).to_string(),
        "--",
        "runsc",
    ]);
    command
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
            "sleep",
            "86400",
        ]);
        command
    } else {
        let mut command = Command::new("unshare");
        command.args(["-Un", "sleep", "86400"]);
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
        stop_sandbox(name).await?;
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
        let set_loopback = userns_command(name, "ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .await?;
        if !set_loopback.success() {
            return Err(io::Error::other("could not activate sandbox loopback"));
        }
        let address = userns_command(name, "ip")
            .args(["addr", "add", &format!("{ip}/32"), "dev", "lo"])
            .status()
            .await?;
        if !address.success() {
            return Err(io::Error::other(
                "could not assign sandbox attribution address",
            ));
        }
        let id = format!("safeyolo-{name}");
        let _ = runsc_command(name)
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
            scoped_runsc_create(name, memory_mb)
        } else {
            eprintln!(
                "systemd user scope unavailable; starting {name} without host MemoryMax/CPUQuota limits"
            );
            userns_command(name, "runsc")
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
        let start = userns_command(name, "runsc")
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
        let state = runsc_command(name).args(["state", &id]).output().await?;
        let value: serde_json::Value = serde_json::from_slice(&state.stdout)?;
        std::fs::write(
            directory.join("container.pid"),
            value
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                .to_string(),
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while tokio::time::Instant::now() < deadline && is_sandbox_running(name).await {
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

#[cfg(target_os = "linux")]
pub(crate) async fn spawn_guest_command(
    name: &str,
    command: &str,
) -> io::Result<tokio::process::Child> {
    if !valid_agent_name(name) || !is_sandbox_running(name).await {
        return Err(unavailable());
    }
    let wrapped = format!(
        ". /etc/environment 2>/dev/null; if [ -f /etc/mise-activate.sh ]; then . /etc/mise-activate.sh; fi; {command}"
    );
    runsc_command(name)
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
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
}

#[cfg(target_os = "linux")]
pub(crate) async fn stop_sandbox(name: &str) -> io::Result<()> {
    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let id = format!("safeyolo-{name}");
    if is_sandbox_running(name).await {
        let _ = runsc_command(name)
            .args(["kill", &id, "SIGTERM"])
            .status()
            .await;
        for _ in 0..50 {
            if !is_sandbox_running(name).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if is_sandbox_running(name).await {
            let _ = runsc_command(name)
                .args(["kill", "--all", &id, "SIGKILL"])
                .status()
                .await;
        }
    }
    let status = runsc_command(name)
        .args(["delete", "--force", &id])
        .status()
        .await?;
    if !status.success() && is_sandbox_running(name).await {
        return Err(io::Error::other("runsc could not delete the sandbox"));
    }
    if let Some(pid) = userns_pid(name) {
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    let directory = config_dir().join("agents").join(name);
    let _ = std::fs::remove_file(directory.join("userns.pid"));
    let _ = std::fs::remove_file(directory.join("container.pid"));
    Ok(())
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
    vm_process_token(name, pid).is_some()
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
pub(crate) async fn spawn_guest_command(
    name: &str,
    command: &str,
) -> io::Result<tokio::process::Child> {
    if !valid_agent_name(name) || !is_sandbox_running(name).await {
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
            "ControlPath=none",
            "-o",
            &format!("ProxyCommand=nc -U '{socket}'"),
            "-t",
            "agent@sandbox",
            &wrapped,
        ])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
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
    let directory = config_dir().join("agents").join(name);
    if directory.join("vm-supervisor.json").exists() {
        return stop_vz_test_runner(&directory).await;
    }
    let path = directory.join("vm.pid");
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let pid = source
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid VM PID"))?;
    let Some(token) = vm_process_token(name, pid) else {
        if unsafe { libc::kill(pid, 0) } != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
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
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    for _ in 0..100 {
        if !is_sandbox_running(name).await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if vm_process_token(name, pid).as_deref() == Some(&token) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    std::fs::remove_file(path)?;
    let _ = std::fs::remove_file(config_dir().join("agents").join(name).join("vm.token"));
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
    reclaim_stopped_vz_test_runner(&directory).await?;
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
    let supervised = std::env::var_os("SAFEYOLO_VZ_TEST_RUNNER").is_some();
    let mut command = vz_test_command(
        &config.join("bin/safeyolo-vm"),
        std::env::var_os("SAFEYOLO_VZ_TEST_RUNNER"),
        std::env::var_os("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS"),
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
    let launch_pid = child.id().ok_or(io::Error::other("VM launch has no PID"))?;
    let _ = std::fs::remove_file(directory.join("vm.token"));
    let pid = if supervised {
        let path = directory.join("vm-supervisor.json");
        let registration = async {
            let mut receipt = serde_json::json!({
                "pid": launch_pid,
                "start_token": macos_process_token(i64::from(launch_pid))
                    .ok_or(io::Error::other("cannot observe VZ test runner start identity"))?,
                "helper_pid": null, "helper_start_token": null,
            });
            std::fs::write(&path, serde_json::to_vec(&receipt)?)?;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
            while tokio::time::Instant::now() < deadline && child.try_wait()?.is_none() {
                if let Some((pid, token)) = vz_runner_helper(name, launch_pid as i32)? {
                    receipt["helper_pid"] = pid.into();
                    receipt["helper_start_token"] = token.into();
                    std::fs::write(&path, serde_json::to_vec(&receipt)?)?;
                    return Ok(pid as u32);
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(io::Error::other(
                "VZ test runner did not expose its direct VM helper child",
            ))
        }
        .await;
        match registration {
            Ok(pid) => pid,
            Err(error) => {
                // Child still owns the launch PID. The host runner owns and
                // reaps its helper; killing the runner would orphan that child.
                if child.try_wait()?.is_none()
                    && unsafe { libc::kill(launch_pid as i32, libc::SIGTERM) } != 0
                {
                    let signal_error = io::Error::last_os_error();
                    if signal_error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(signal_error);
                    }
                }
                tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
                    .await
                    .map_err(|_| {
                        io::Error::other("VZ runner cleanup could not be established")
                    })??;
                if path.exists() {
                    stop_vz_test_runner(&directory).await?;
                }
                return Err(error);
            }
        }
    } else {
        let _ = std::fs::remove_file(directory.join("vm-supervisor.json"));
        launch_pid
    };
    let startup = async {
        std::fs::write(directory.join("vm.pid"), pid.to_string())?;
        if let Some(token) = vm_process_token(name, pid as i32) {
            std::fs::write(directory.join("vm.token"), token)?;
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
        while tokio::time::Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                break;
            }
            if status_dir.join("per-run-started").is_file() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err(io::Error::other("VM did not reach per-run startup"))
    }
    .await;
    if startup.is_err() {
        // Surface failed owned cleanup instead of discarding it on startup failure.
        stop_sandbox(name).await?;
        if supervised {
            tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
                .await
                .map_err(|_| io::Error::other("VZ runner cleanup could not be established"))??;
        }
    }
    startup
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

pub(crate) fn update_agent_map(name: &str, ip: Option<&str>) -> io::Result<()> {
    if !valid_agent_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent name",
        ));
    }
    let path = config_dir().join("data/agent_map.json");
    let _lock = lock_host_state(&path.with_file_name("agent_map.lock"))?;
    let mut map = match std::fs::read(&path) {
        Ok(content) => {
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&content)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => serde_json::Map::new(),
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
    temporary.persist(path)?;
    Ok(())
}

#[cfg(test)]
mod vz_test_runner_tests {
    use super::vz_test_command;
    use std::{ffi::OsString, os::unix::fs::PermissionsExt, path::Path};

    #[test]
    fn vz_test_runner_preserves_direct_helper_and_literal_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let runner = directory.path().join("run test with spaces");
        std::fs::write(&runner, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let helper = Path::new("/selected inputs/safeyolo-vm");
        let mut command =
            vz_test_command(helper, Some(runner.clone().into()), Some("003".into())).unwrap();
        command.arg("run").arg("--overlay").arg("owned overlay");
        assert_eq!(command.as_std().get_program(), runner);
        assert_eq!(
            command
                .as_std()
                .get_args()
                .map(OsString::from)
                .collect::<Vec<_>>(),
            [
                "--timeout-seconds",
                "3",
                "--",
                "/selected inputs/safeyolo-vm",
                "run",
                "--overlay",
                "owned overlay"
            ]
            .map(OsString::from)
        );
        let direct = vz_test_command(helper, None, None).unwrap();
        assert_eq!(direct.as_std().get_program(), helper);
        assert_eq!(direct.as_std().get_args().count(), 0);
    }

    #[test]
    fn vz_test_runner_rejects_incomplete_invalid_or_unavailable_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let runner = directory.path().join("runner");
        std::fs::write(&runner, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let helper = Path::new("/selected/safeyolo-vm");
        assert!(vz_test_command(helper, Some(runner.clone().into()), None).is_err());
        assert!(vz_test_command(helper, None, Some("1".into())).is_err());
        for value in [
            "",
            "0",
            "-1",
            "+1",
            "1.5",
            " 1",
            "1 ",
            "１２",
            "18446744073709551616",
        ] {
            assert!(
                vz_test_command(helper, Some(runner.clone().into()), Some(value.into())).is_err(),
                "{value:?}"
            );
        }
        for path in [Path::new("relative"), directory.path()] {
            assert!(vz_test_command(helper, Some(path.into()), Some("1".into())).is_err());
        }
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(vz_test_command(helper, Some(runner.into()), Some("1".into())).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn vz_supervision_observes_real_live_stale_and_reused_process_identities() {
        use super::{macos_process_token, vz_receipt_process_alive};

        let pid = i64::from(std::process::id());
        let token = macos_process_token(pid).unwrap();
        let mut receipt = serde_json::json!({"pid": pid, "start_token": token,
                                            "helper_pid": null, "helper_start_token": null});
        assert!(vz_receipt_process_alive(&receipt, "pid").unwrap());
        assert!(!vz_receipt_process_alive(&receipt, "helper_pid").unwrap());
        receipt["start_token"] = "older-process".into();
        assert!(!vz_receipt_process_alive(&receipt, "pid").unwrap());
        receipt["pid"] = true.into();
        assert!(vz_receipt_process_alive(&receipt, "pid").is_err());
        let mut exited = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let old_pid = exited.id();
        exited.wait().unwrap();
        let absent = serde_json::json!({"pid": old_pid, "start_token": "earlier-start"});
        assert!(
            !vz_receipt_process_alive(&absent, "pid").unwrap(),
            "ESRCH must establish exit"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn vz_supervision_reclaims_only_verified_inactive_receipts() {
        use super::{macos_process_token, reclaim_stopped_vz_test_runner};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vm-supervisor.json");
        let pid = i64::from(std::process::id());
        let live = serde_json::json!({"pid": pid, "start_token": macos_process_token(pid).unwrap(),
                                     "helper_pid": null, "helper_start_token": null});
        let original = serde_json::to_vec(&live).unwrap();
        std::fs::write(&path, &original).unwrap();
        assert!(
            reclaim_stopped_vz_test_runner(directory.path())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let old = serde_json::json!({"pid": pid, "start_token": "earlier-start",
                                    "helper_pid": null, "helper_start_token": null});
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        reclaim_stopped_vz_test_runner(directory.path())
            .await
            .unwrap();
        assert!(
            !path.exists(),
            "reused foreign PID survived and the stale receipt was removed"
        );
    }
}
