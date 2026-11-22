//! Linux execution with a private cgroup and bubblewrap namespaces. This path
//! supports read-only, disconnected operations under the executor's identity.
//! Only the pinned native service client receives its fixed manager channel.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRuntime {
    pub bubblewrap: PathBuf,
    pub bubblewrap_sha256: String,
    /// A dedicated, operator-delegated cgroup v2 subtree for this target.
    pub cgroup: PathBuf,
    pub executable_bytes: u64,
}

fn unavailable(error: impl std::fmt::Display) -> Refusal {
    Refusal {
        code: RefusalCode::Unavailable,
        message: format!("Linux execution: {error}"),
    }
}

pub use crate::now;

fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
}

fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hold a bounded, sealed snapshot of the verified executable. Replacing or
/// modifying its original inode cannot change the bytes subsequently launched.
fn executable(path: &Path, expected: &str, max: u64) -> Result<File, Refusal> {
    require(
        absolute(path) && max > 0 && max <= isize::MAX as u64,
        RefusalCode::Unavailable,
        "executable needs an absolute path and finite snapshot ceiling",
    )?;
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(unavailable)?;
    let metadata = source.metadata().map_err(unavailable)?;
    require(
        metadata.is_file() && metadata.mode() & 0o111 != 0 && metadata.len() <= max,
        RefusalCode::Unavailable,
        "executable must be an executable regular file within the snapshot ceiling",
    )?;
    let mut bytes = Vec::new();
    source
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    require(
        bytes.len() as u64 <= max && hash(&bytes) == expected,
        RefusalCode::Stale,
        "executable content differs from adoption",
    )?;
    // SAFETY: the NUL-terminated constant lives through the call. The returned
    // descriptor has one File owner and is closed on all error paths.
    let fd = unsafe {
        libc::memfd_create(
            c"safeyolo-executable".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    let mut snapshot = unsafe { File::from_raw_fd(fd) };
    snapshot.write_all(&bytes).map_err(unavailable)?;
    snapshot.seek(SeekFrom::Start(0)).map_err(unavailable)?;
    // SAFETY: fd is owned above; these fcntl operations take integer arguments.
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } < 0
    {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    Ok(snapshot)
}

impl LinuxRuntime {
    /// Pure filesystem validation: never run an adopted command for discovery,
    /// qualification, startup or reload. Every entry uses the same validation.
    pub fn validate(&self, target: &Target, protected: &[PathBuf]) -> Result<(), Refusal> {
        target.validate().map_err(unavailable)?;
        require(
            absolute(&self.cgroup)
                && self.cgroup.canonicalize().map_err(unavailable)? == self.cgroup,
            RefusalCode::Unavailable,
            "cgroup subtree must be a canonical absolute path",
        )?;
        let metadata = fs::metadata(&self.cgroup).map_err(unavailable)?;
        // SAFETY: identity accessors have no pointer arguments.
        let uid = unsafe { libc::geteuid() };
        require(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o022 == 0,
            RefusalCode::Unavailable,
            "cgroup subtree must be executor-owned and not writable by another account",
        )?;
        let fs_name = std::ffi::CString::new(self.cgroup.as_os_str().as_encoded_bytes())
            .map_err(unavailable)?;
        let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: both pointers are valid through statfs; status is read only
        // after successful initialization by the kernel.
        if unsafe { libc::statfs(fs_name.as_ptr(), status.as_mut_ptr()) } != 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        require(
            unsafe { status.assume_init() }.f_type == 0x63677270,
            RefusalCode::Unavailable,
            "memory, task and cleanup enforcement require a real cgroup v2 filesystem",
        )?;
        self.validate_migration()?;
        let controls =
            fs::read_to_string(self.cgroup.join("cgroup.subtree_control")).map_err(unavailable)?;
        require(
            ["memory", "pids"]
                .iter()
                .all(|name| controls.split_whitespace().any(|s| s == *name)),
            RefusalCode::Unavailable,
            "delegated cgroup needs enabled memory and pids controllers",
        )?;
        executable(
            &self.bubblewrap,
            &self.bubblewrap_sha256,
            self.executable_bytes,
        )?;
        for operation in target.package.operations.values() {
            self.validate_operation(operation, protected)?;
        }
        Ok(())
    }

    fn validate_migration(&self) -> Result<(), Refusal> {
        let memberships = fs::read_to_string("/proc/self/cgroup").map_err(unavailable)?;
        let current = memberships
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| unavailable("unified current cgroup observation is missing"))?;
        let mounts = mounts()?;
        let mount = mounts
            .iter()
            .filter(|m| m.filesystem == "cgroup2" && self.cgroup.starts_with(&m.path))
            .max_by_key(|m| m.path.components().count())
            .ok_or_else(|| unavailable("selected cgroup filesystem is not visible"))?;
        let relative = Path::new(current).strip_prefix(&mount.root).map_err(|_| {
            unavailable("current cgroup is outside the visible delegated hierarchy")
        })?;
        let current = mount.path.join(relative);
        let common = self
            .cgroup
            .ancestors()
            .find(|path| current.starts_with(path))
            .ok_or_else(|| {
                unavailable("current and selected cgroups have no visible common ancestor")
            })?;
        // Linux checks this permission on migration in addition to the target
        // cgroup.procs. Opening for write checks access but moves no process.
        OpenOptions::new().write(true).custom_flags(libc::O_CLOEXEC)
            .open(common.join("cgroup.procs"))
            .map_err(|error| unavailable(format!("cannot place jobs from current cgroup {} into {}: common-ancestor cgroup.procs {}: {error}; launch this executor within its properly delegated hierarchy", current.display(), self.cgroup.display(), common.display())))?;
        Ok(())
    }

    fn validate_operation(
        &self,
        operation: &Operation,
        protected: &[PathBuf],
    ) -> Result<(), Refusal> {
        let execution = &operation.execution;
        let service = crate::unix_services::validate(operation)?;
        require(
            service || execution.broader.is_empty(),
            RefusalCode::Unavailable,
            "this Linux profile enforces required read-only/disconnected bounds; broader profiles are not silently substituted",
        )?;
        // SAFETY: these identity accessors have no pointer arguments. getgroups
        // is given a vector sized by its immediately preceding count query.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        let mut groups = vec![0; count as usize];
        let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if actual < 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        groups.truncate(actual as usize);
        let mut expected: Vec<u32> = execution
            .identity
            .groups
            .iter()
            .map(|v| v.parse().map_err(unavailable))
            .collect::<Result<_, _>>()?;
        groups.sort_unstable();
        groups.dedup();
        expected.sort_unstable();
        expected.dedup();
        require(
            execution.identity.principal == uid.to_string()
                && groups == expected
                && groups.contains(&gid),
            RefusalCode::Unavailable,
            "this backend retains this executor host UID and all its supplementary host GIDs; identity cannot select another account or a group subset",
        )?;
        require(
            execution.filesystem.write.is_empty()
                && execution.network.destinations.is_empty()
                && (service || execution.network.ipc.is_empty())
                && (service || execution.delegated_services.is_empty()),
            RefusalCode::Unavailable,
            "writable storage and direct network/IPC are unavailable; the service channel requires the fixed native OS client profile",
        )?;
        let mut protected = protected.to_vec();
        protected.push(self.cgroup.clone());
        let mounts = mounts()?;
        for endpoint in &execution.network.ipc {
            let IpcEndpoint::UnixSocket { path } = endpoint else {
                return Err(unavailable(
                    "Linux service control needs its native Unix socket",
                ));
            };
            let path = Path::new(path);
            require(
                absolute(path)
                    && path.canonicalize().map_err(unavailable)? == path
                    && fs::symlink_metadata(path)
                        .map_err(unavailable)?
                        .file_type()
                        .is_socket()
                    && !protected
                        .iter()
                        .any(|p| path.starts_with(p) || p.starts_with(path)),
                RefusalCode::Unavailable,
                "service channel must be a canonical socket outside executor state",
            )?;
            validate_read_mounts(path, &protected, &mounts)?;
        }
        for path in &execution.filesystem.read {
            let path = Path::new(path);
            require(
                absolute(path),
                RefusalCode::Unavailable,
                "filesystem reads need absolute paths without parent traversal",
            )?;
            let canonical = path.canonicalize().map_err(unavailable)?;
            require(
                !protected
                    .iter()
                    .any(|p| canonical.starts_with(p) || p.starts_with(&canonical)),
                RefusalCode::Unavailable,
                "filesystem scope exposes executor state, configuration or cgroup authority",
            )?;
            validate_read_mounts(&canonical, &protected, &mounts)?;
            let meta = fs::metadata(&canonical).map_err(unavailable)?;
            require(
                meta.is_file() || meta.is_dir(),
                RefusalCode::Unavailable,
                "read scope must name a regular file or directory",
            )?;
        }
        require(
            absolute(Path::new(&execution.working_directory)),
            RefusalCode::Unavailable,
            "working directory must be absolute",
        )?;
        executable(
            Path::new(&execution.executable),
            &execution.executable_sha256,
            self.executable_bytes,
        )?;
        Ok(())
    }

    pub fn reconcile(&self, ledger: &mut Ledger) -> Result<(), Refusal> {
        for receipt in ledger.recover(now())? {
            let path = self.cgroup.join(&receipt.job_id);
            if path.exists() {
                fs::write(path.join("cgroup.kill"), b"1").map_err(unavailable)?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while !empty(&path)? && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                require(
                    empty(&path)?,
                    RefusalCode::Unavailable,
                    "prior job cgroup remains populated; reservation retained",
                )?;
                fs::remove_dir(&path).map_err(unavailable)?;
            }
            ledger.confirm_quiescent(&receipt.job_id, now(), "dedicated cgroup absent or observed unpopulated after cgroup.kill; prior side effects/exit remain unknown")?;
        }
        Ok(())
    }

    pub fn execute(
        &self,
        target: &Target,
        ledger: Arc<Mutex<Ledger>>,
        job_id: &str,
    ) -> Result<(), Refusal> {
        crate::native::execute_job(target, ledger, job_id, |op, receipt, ledger| {
            self.run(op, receipt, ledger)
        })
    }

    fn run(
        &self,
        operation: &Operation,
        receipt: &Receipt,
        ledger: &Arc<Mutex<Ledger>>,
    ) -> Result<NativeObservation, Refusal> {
        let path = self.cgroup.join(&receipt.job_id);
        fs::create_dir(&path).map_err(unavailable)?;
        let mut group = JobCgroup { path, child: None };
        fs::write(
            group.path.join("memory.max"),
            operation.execution.resources.memory_bytes.to_string(),
        )
        .map_err(unavailable)?;
        fs::write(group.path.join("memory.swap.max"), b"0").map_err(unavailable)?;
        fs::write(group.path.join("memory.oom.group"), b"1").map_err(unavailable)?;
        fs::write(
            group.path.join("pids.max"),
            operation.execution.resources.processes.to_string(),
        )
        .map_err(unavailable)?;
        let attach = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(group.path.join("cgroup.procs"))
            .map_err(unavailable)?;
        let binary = executable(
            Path::new(&operation.execution.executable),
            &operation.execution.executable_sha256,
            self.executable_bytes,
        )?;
        let helper = executable(
            &self.bubblewrap,
            &self.bubblewrap_sha256,
            self.executable_bytes,
        )?;
        let service = crate::unix_services::validate(operation)?;
        let seccomp = socket_filter(service)?;
        let command = operation.command(&receipt.prepared.invocation.arguments)?;
        let mut native = ProcessCommand::new(format!("/proc/self/fd/{}", helper.as_raw_fd()));
        native
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        native.args([
            "--unshare-user",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--disable-userns",
            "--assert-userns-disabled",
            "--new-session",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
            "--clearenv",
        ]);
        if !service {
            native.arg("--unshare-pid");
        }
        native.args([
            "--uid",
            &operation.execution.identity.principal,
            "--gid",
            &unsafe { libc::getegid() }.to_string(),
        ]);
        let mut reads = Vec::new();
        for path in &operation.execution.filesystem.read {
            let file = File::open(path).map_err(unavailable)?;
            native.args(["--ro-bind-fd", &file.as_raw_fd().to_string(), path]);
            reads.push(file);
        }
        for endpoint in &operation.execution.network.ipc {
            let IpcEndpoint::UnixSocket { path } = endpoint else {
                return Err(unavailable("unsupported Linux service socket"));
            };
            // O_PATH pins a Unix socket without connecting or running a probe.
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(unavailable)?;
            require(
                file.metadata()
                    .map_err(unavailable)?
                    .file_type()
                    .is_socket(),
                RefusalCode::Unavailable,
                "service endpoint changed before launch",
            )?;
            native.args(["--ro-bind-fd", &file.as_raw_fd().to_string(), path]);
            reads.push(file);
        }
        native.args([
            "--perms",
            "0555",
            "--ro-bind-data",
            &binary.as_raw_fd().to_string(),
            &command.executable,
        ]);
        native.args([
            "--seccomp",
            &seccomp.as_raw_fd().to_string(),
            "--chdir",
            &command.working_directory,
        ]);
        for (key, value) in &command.environment {
            native.args(["--setenv", key, value]);
        }
        // The otherwise-empty namespace root is also read-only. Read-only bind
        // mounts alone would leave writable scratch in bubblewrap's root tmpfs.
        native.args(["--remount-ro", "/"]);
        native
            .arg("--")
            .arg(&command.executable)
            .args(&command.argv);
        let fds: Vec<i32> = reads
            .iter()
            .chain([&binary, &helper, &seccomp])
            .map(|f| f.as_raw_fd())
            .collect();
        let attach_fd = attach.as_raw_fd();
        let parent = unsafe { libc::getpid() };
        // SAFETY: pre_exec uses only async-signal-safe syscalls and preallocated
        // values. Every workload starts in its cgroup before bwrap executes.
        unsafe {
            native.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                if libc::write(attach_fd, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                let zero = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in &fds {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        group.child = Some(native.spawn().map_err(|error| {
            unavailable(format!("place and launch the cgroup workload: {error}"))
        })?);
        drop((binary, helper, seccomp, reads, attach));
        let child = group.child.as_mut().expect("spawned child");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        // A bounded channel applies backpressure rather than accumulating output
        // in memory. Readers hold no ledger lock and stop when its receiver ends.
        let (tx, rx) = mpsc::sync_channel::<std::io::Result<Vec<u8>>>(2);
        let readers: Vec<_> = [Box::new(stdout) as Box<dyn Read + Send>, Box::new(stderr)]
            .into_iter()
            .map(|mut pipe| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut bytes = [0; 4096];
                    loop {
                        match pipe.read(&mut bytes) {
                            Ok(0) => break,
                            Ok(n) => {
                                if tx.send(Ok(bytes[..n].to_vec())).is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e));
                                break;
                            }
                        }
                    }
                })
            })
            .collect();
        drop(tx);
        let deadline = Instant::now() + Duration::from_secs(receipt.deadline.saturating_sub(now()));
        let mut status = None;
        let mut truncated = false;
        let mut reason = "exited";
        let mut output_open = true;
        loop {
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(Ok(bytes)) => {
                    let take = ledger.lock().map_err(unavailable)?.append_output(
                        &receipt.job_id,
                        &bytes,
                        now(),
                    )?;
                    if take < bytes.len() {
                        truncated = true;
                        reason = "output_limit";
                        break;
                    }
                }
                Ok(Err(e)) => return Err(unavailable(e)),
                Err(mpsc::RecvTimeoutError::Disconnected) => output_open = false,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            if ledger
                .lock()
                .map_err(unavailable)?
                .observe(&receipt.job_id)?
                .cancellation_requested
            {
                reason = "cancelled";
                break;
            }
            if Instant::now() >= deadline {
                reason = "timeout";
                break;
            }
            if status.is_none() {
                status = group
                    .child
                    .as_mut()
                    .expect("spawned")
                    .try_wait()
                    .map_err(unavailable)?;
            }
            if status.is_some() {
                break;
            }
        }
        // Always kill the entire cgroup, including children that outlive the
        // foreground command. Quiescence is checked independently of exit status.
        fs::write(group.path.join("cgroup.kill"), b"1").map_err(unavailable)?;
        let stop = Instant::now() + Duration::from_secs(5);
        while !empty(&group.path)? && Instant::now() < stop {
            std::thread::sleep(Duration::from_millis(10));
        }
        let quiescent = empty(&group.path)?;
        if quiescent {
            if status.is_none() {
                status = Some(
                    group
                        .child
                        .as_mut()
                        .expect("spawned")
                        .wait()
                        .map_err(unavailable)?,
                );
            }
            while output_open {
                match rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(Ok(bytes)) => {
                        let take = ledger.lock().map_err(unavailable)?.append_output(
                            &receipt.job_id,
                            &bytes,
                            now(),
                        )?;
                        truncated |= take < bytes.len();
                    }
                    Ok(Err(e)) => return Err(unavailable(e)),
                    Err(mpsc::RecvTimeoutError::Disconnected) => output_open = false,
                    Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= stop => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                }
            }
        }
        drop(rx);
        // Readers are guaranteed EOF only after observed cgroup quiescence.
        if quiescent {
            for reader in readers {
                reader
                    .join()
                    .map_err(|_| unavailable("output reader failed"))?;
            }
        }
        let mut result = NativeObservation {
            backend: "linux-bubblewrap-cgroup-v2".into(),
            enforcement: vec!["read-only opened filesystem mounts; sealed executable snapshot".into(), "separate user/PID/network/IPC/UTS namespaces; no sockets or nested namespaces".into(), "cgroup memory.max, memory.swap.max=0 and pids.max include runtime overhead".into(), "bounded retained merged output, deadline and descendant termination".into()],
            dependencies: vec![format!("host UID {} and supplementary host GIDs {:?}; the user namespace maps the primary GID, while supplementary GIDs are retained for host ACL checks and appear as the kernel overflow GID inside it", operation.execution.identity.principal, operation.execution.identity.groups), "pinned bubblewrap; kernel user namespaces, seccomp and delegated cgroup v2".into(), "adopted read paths include mutable host-owned runtime dependencies; their content is not pinned".into()],
            exit_code: status.and_then(|s| s.code()), signal: status.and_then(|s| s.signal()),
            processes_stopped: quiescent, output_truncated: truncated || output_open,
            termination_reason: reason.into(),
        };
        if service {
            result.enforcement[1] = "separate user/network/IPC/UTS namespaces; only AF_UNIX sockets and the fixed systemd user channel; host process signalling and cross-process memory/FD access are denied".into();
            result.dependencies.push("EXPLICIT BROADER PROCESS VISIBILITY: the trusted OS client shares the host PID namespace so the service owner has a visible peer PID for SO_PEERCRED authentication. Host /proc is not mounted. The cgroup still bounds and terminates the helper and its descendants".into());
            result.dependencies.push(crate::unix_services::disclosure());
        }
        if quiescent {
            fs::remove_dir(&group.path).map_err(unavailable)?;
        }
        Ok(result)
    }
}

fn empty(path: &Path) -> Result<bool, Refusal> {
    let events = fs::read_to_string(path.join("cgroup.events")).map_err(unavailable)?;
    require(
        events
            .lines()
            .any(|l| l == "populated 0" || l == "populated 1"),
        RefusalCode::Unavailable,
        "missing cgroup populated observation",
    )?;
    Ok(events.lines().any(|l| l == "populated 0"))
}

struct Mount {
    device: String,
    root: PathBuf,
    path: PathBuf,
    filesystem: String,
}

fn mounts() -> Result<Vec<Mount>, Refusal> {
    fn decode(value: &str) -> PathBuf {
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
            .into()
    }
    fs::read_to_string("/proc/self/mountinfo")
        .map_err(unavailable)?
        .lines()
        .map(|line| {
            let (left, right) = line
                .split_once(" - ")
                .ok_or_else(|| unavailable("invalid mount observation"))?;
            let words: Vec<_> = left.split_whitespace().collect();
            require(
                words.len() >= 6,
                RefusalCode::Unavailable,
                "invalid mount observation",
            )?;
            Ok(Mount {
                device: words[2].into(),
                root: decode(words[3]),
                path: decode(words[4]),
                filesystem: right
                    .split_whitespace()
                    .next()
                    .ok_or_else(|| unavailable("missing mount type"))?
                    .into(),
            })
        })
        .collect()
}

fn backing<'a>(path: &Path, mounts: &'a [Mount]) -> Result<(&'a str, PathBuf), Refusal> {
    let mount = mounts
        .iter()
        .filter(|m| path.starts_with(&m.path))
        .max_by_key(|m| m.path.components().count())
        .ok_or_else(|| unavailable("filesystem scope has no observed mount"))?;
    Ok((
        &mount.device,
        mount
            .root
            .join(path.strip_prefix(&mount.path).map_err(unavailable)?),
    ))
}

fn validate_read_mounts(
    path: &Path,
    protected: &[PathBuf],
    mounts: &[Mount],
) -> Result<(), Refusal> {
    let covered = std::iter::once(backing(path, mounts)?).chain(
        mounts
            .iter()
            .filter(|m| m.path.starts_with(path))
            .map(|m| (m.device.as_str(), m.root.clone())),
    );
    for (device, range) in covered {
        for secret in protected {
            let (secret_device, secret_path) = backing(secret, mounts)?;
            require(
                device != secret_device
                    || !(range.starts_with(&secret_path) || secret_path.starts_with(&range)),
                RefusalCode::Unavailable,
                "read scope exposes a mount alias of executor state or authority",
            )?;
        }
    }
    for mount in mounts
        .iter()
        .filter(|m| m.path.starts_with(path) || path.starts_with(&m.path))
    {
        // Do not mount an ancestor procfs, device, cgroup or other kernel control
        // filesystem into the workload namespace. Read-only procfs can still
        // expose an ancestor process's memory and filesystem through aliases.
        if mount.path.starts_with(path)
            || mounts
                .iter()
                .filter(|m| path.starts_with(&m.path))
                .max_by_key(|m| m.path.components().count())
                .is_some_and(|m| std::ptr::eq(m, mount))
        {
            require(
                ![
                    "proc",
                    "sysfs",
                    "cgroup",
                    "cgroup2",
                    "devtmpfs",
                    "devpts",
                    "debugfs",
                    "tracefs",
                    "securityfs",
                    "configfs",
                    "bpf",
                    "mqueue",
                    "nsfs",
                    "efivarfs",
                ]
                .contains(&mount.filesystem.as_str()),
                RefusalCode::Unavailable,
                "read scope includes an ancestor kernel/control filesystem",
            )?;
        }
    }
    Ok(())
}

struct JobCgroup {
    path: PathBuf,
    child: Option<Child>,
}
impl Drop for JobCgroup {
    fn drop(&mut self) {
        // This guard only signals this job's private cgroup. Failed cleanup is
        // retained in place for restart reconciliation, never reported stopped.
        let _ = fs::write(self.path.join("cgroup.kill"), b"1");
        if let Some(child) = &mut self.child {
            let _ = child.try_wait();
        }
    }
}

fn socket_filter(service: bool) -> Result<File, Refusal> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Linux native seccomp requires a qualified syscall architecture");
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    let mut filter = vec![
        stmt(0x20, 4),
        jump(ARCH, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
        // x32 shares the x86-64 audit architecture but uses different syscall
        // numbers. Reject its ABI bit before comparing native syscall numbers.
        libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        stmt(0x06, 0x00050000 | libc::EPERM as u32),
    ];
    for syscall in [libc::SYS_socket, libc::SYS_socketpair] {
        if service {
            filter.extend([
                jump(syscall as u32, 0, 4),
                stmt(0x20, 16),
                jump(libc::AF_UNIX as u32, 1, 0),
                stmt(0x06, 0x00050000 | libc::EPERM as u32),
                stmt(0x20, 0),
            ]);
        } else {
            filter.extend([
                jump(syscall as u32, 0, 1),
                stmt(0x06, 0x00050000 | libc::EPERM as u32),
            ]);
        }
    }
    if service {
        for syscall in [
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_pidfd_send_signal,
        ] {
            filter.extend([
                jump(syscall as u32, 0, 1),
                stmt(0x06, 0x00050000 | libc::EPERM as u32),
            ]);
        }
        // libc can query/change its own limits using pid=0. Other process
        // limits cannot be inspected or modified through the shared PID view.
        filter.extend([
            jump(libc::SYS_prlimit64 as u32, 0, 4),
            stmt(0x20, 16),
            jump(0, 1, 0),
            stmt(0x06, 0x00050000 | libc::EPERM as u32),
            stmt(0x20, 0),
        ]);
    }
    // Block socket creation (including io_uring), privilege/namespace changes,
    // cross-process inspection and huge-page allocations outside memory.max.
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_memfd_create,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_shmget,
        libc::SYS_shmat,
        libc::SYS_shmctl,
    ] {
        filter.extend([
            jump(syscall as u32, 0, 1),
            stmt(0x06, 0x00050000 | libc::EPERM as u32),
        ]);
    }
    // HugeTLB anonymous mappings may be accounted outside memory.max. Ordinary
    // mmap remains available; reject only the huge-page allocation flag.
    filter.extend([
        jump(libc::SYS_mmap as u32, 0, 4),
        stmt(0x20, 40), // seccomp_data.args[3], low flag word on supported LE ABIs
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: libc::MAP_HUGETLB as u32,
        },
        stmt(0x06, 0x00050000 | libc::EPERM as u32),
        stmt(0x20, 0),
    ]);
    filter.push(stmt(0x06, 0x7fff0000));
    let fd = unsafe { libc::memfd_create(c"safeyolo-seccomp".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    // SAFETY: sock_filter is a fixed C layout; the slice covers exactly the
    // initialized vector, and write_all does not outlive that vector.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            filter.as_ptr().cast(),
            filter.len() * std::mem::size_of::<libc::sock_filter>(),
        )
    };
    file.write_all(bytes).map_err(unavailable)?;
    file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[ignore = "requires native Linux kernel seccomp; run with the installed contract fixtures"]
    fn service_filter_allows_unix_ipc_and_denies_host_process_control() {
        let mut file = socket_filter(true).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let parent = unsafe { libc::getpid() };
        // SAFETY: the child uses only libc/syscalls and preallocated memory,
        // then _exit. It sends signal 0 (a permission probe), never a signal
        // that could alter its parent. The BPF lives until that child exits.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                let program = libc::sock_fprog {
                    len: (bytes.len() / std::mem::size_of::<libc::sock_filter>()) as u16,
                    filter: bytes.as_ptr().cast_mut().cast(),
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(1);
                }
                if libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0 {
                    libc::_exit(2);
                }
                let unix = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if unix < 0 {
                    libc::_exit(3);
                }
                libc::close(unix);
                if libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) != -1
                    || *libc::__errno_location() != libc::EPERM
                {
                    libc::_exit(4);
                }
                if libc::kill(parent, 0) != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(5);
                }
                let mut limits = libc::rlimit64 {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::prlimit64(parent, libc::RLIMIT_NOFILE, std::ptr::null(), &mut limits) != -1
                    || *libc::__errno_location() != libc::EPERM
                {
                    libc::_exit(6);
                }
                if libc::prlimit64(0, libc::RLIMIT_NOFILE, std::ptr::null(), &mut limits) != 0 {
                    libc::_exit(7);
                }
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn executable_snapshot_is_bounded_digest_bound_and_immutable() {
        let path = std::env::temp_dir().join(format!("safeyolo-executable-{}", std::process::id()));
        let mut cleanup = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        cleanup.write_all(b"first executable").unwrap();
        drop(cleanup);
        let result = std::panic::catch_unwind(|| {
            assert!(executable(&path, &hash(b"first executable"), 4).is_err());
            assert!(executable(&path, &hash(b"wrong"), 1024).is_err());
            let mut snapshot = executable(&path, &hash(b"first executable"), 1024).unwrap();
            fs::write(&path, b"replacement").unwrap();
            let mut bytes = Vec::new();
            snapshot.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"first executable");
            assert!(snapshot.write_all(b"changed").is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(executable(&path, &hash(b"replacement"), 1024).is_err());
        });
        let _ = fs::remove_file(path);
        result.unwrap();
    }

    #[test]
    fn read_mount_aliases_and_ancestor_kernel_filesystems_are_refused() {
        let mount = |device: &str, root: &str, path: &str, filesystem: &str| Mount {
            device: device.into(),
            root: root.into(),
            path: path.into(),
            filesystem: filesystem.into(),
        };
        let mounts = vec![
            mount("8:1", "/", "/", "ext4"),
            mount("8:1", "/private", "/alias", "ext4"),
            mount("0:2", "/", "/proc", "proc"),
            mount("0:2", "/", "/read/nested", "proc"),
        ];
        let protected = vec![PathBuf::from("/private/state")];
        for read in [
            "/alias",
            "/alias/state/jobs.sqlite",
            "/proc/version",
            "/read",
            "/",
        ] {
            assert!(
                validate_read_mounts(Path::new(read), &protected, &mounts).is_err(),
                "{read}"
            );
        }
        assert!(validate_read_mounts(Path::new("/usr"), &protected, &mounts).is_ok());
        assert!(validate_read_mounts(Path::new("/etc/hostname"), &protected, &mounts).is_ok());
    }
}
