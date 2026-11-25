//! Seatbelt denies undeclared file access, sockets and process creation. macOS
//! has no equivalent to a cgroup hard memory cap here: polling is available only
//! when the exact signed operation explicitly adopts that broader memory bound.
use crate::{
    native::{execute_job, unavailable},
    *,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::ExitStatusExt,
        },
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

mod filesystem;
mod network;
mod processes;
// <spawn.h>; the pinned libc omits this macOS flag.
const POSIX_SPAWN_SETSID: i16 = 0x0400;
const DESCENDANT_LIMIT: &str = "EXPLICIT BROADER PROCESSES: fork/exec and posix_spawn children inherit Seatbelt and can change groups or sessions. Only the original group is counted, memory-polled and stopped on cancellation or deadline; escaped descendants may outlive either. Group quiescence and output EOF do not prove tree cleanup. Multi-process jobs finish Uncertain with processes_stopped=false and retain their concurrency reservation, including after restart. This backend cannot establish complete descendant ownership or stop an escaped tree.";
pub(crate) fn network_enforcement(operation: &Operation) -> Vec<String> {
    let mut facts = network::disclosure(operation);
    if operation.execution.resources.processes > 1 {
        facts.push(DESCENDANT_LIMIT.into());
    } else {
        facts.push("Single-process authority: fork and child execution are denied.".into());
    }
    facts
}
use processes::{group_members, group_memory, group_quiescent};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacRuntime {
    pub executable_bytes: u64,
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn identity() -> Result<ExecutionIdentity, Refusal> {
    // SAFETY: getgroups writes at most the count returned by its size query.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    let mut groups = vec![0; n as usize];
    let actual = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    if actual < 0 {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    groups.truncate(actual as usize);
    groups.sort_unstable();
    groups.dedup();
    Ok(ExecutionIdentity {
        principal: unsafe { libc::geteuid() }.to_string(),
        groups: groups.into_iter().map(|g| g.to_string()).collect(),
    })
}

fn process_info(pid: u32) -> Result<Option<libc::proc_bsdinfo>, Refusal> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: proc_pidinfo receives a correctly sized output buffer. A zero
    // result is inspected through errno, never interpreted as successful-empty.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if n == size {
        let info = unsafe { info.assume_init() };
        return Ok(Some(info));
    }
    let error = std::io::Error::last_os_error();
    if n == 0 && error.raw_os_error() == Some(libc::ESRCH) {
        Ok(None)
    } else {
        Err(unavailable(error))
    }
}
fn process_birth(info: &libc::proc_bsdinfo) -> NativeProcess {
    NativeProcess {
        pid: info.pbi_pid,
        process_group: info.pbi_pgid,
        birth_seconds: info.pbi_start_tvsec,
        birth_microseconds: info.pbi_start_tvusec as u32,
        descendants_may_escape: false,
    }
}
fn birth(pid: u32) -> Result<Option<NativeProcess>, Refusal> {
    Ok(process_info(pid)?
        .filter(|info| info.pbi_status != 5)
        .map(|info| process_birth(&info)))
}
fn same(a: &NativeProcess, b: &NativeProcess) -> bool {
    a.pid == b.pid
        && a.birth_seconds == b.birth_seconds
        && a.birth_microseconds == b.birth_microseconds
}

impl MacRuntime {
    pub fn validate(&self, target: &Target, protected: &[PathBuf]) -> Result<(), Refusal> {
        target.validate().map_err(unavailable)?;
        require(
            self.executable_bytes > 0 && self.executable_bytes < isize::MAX as u64,
            RefusalCode::Budget,
            "executable snapshot ceiling must be finite and positive",
        )?;
        let mut disposition = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), disposition.as_mut_ptr()) }
            != 0
        {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        let disposition = unsafe { disposition.assume_init() };
        require(
            disposition.sa_sigaction == libc::SIG_DFL
                && disposition.sa_flags & libc::SA_NOCLDWAIT == 0,
            RefusalCode::Unavailable,
            "macOS direct-child tracking requires default SIGCHLD handling and retained wait status",
        )?;
        let current = identity()?;
        for op in target.package.operations.values() {
            let e = &op.execution;
            let service = crate::unix_services::validate(op)?;
            let endpoint = crate::endpoints::validate(op)?;
            let mut declared = e.identity.groups.clone();
            declared.sort();
            declared.dedup();
            let mut actual = current.groups.clone();
            actual.sort();
            require(
                e.identity.principal == current.principal && declared == actual,
                RefusalCode::Unavailable,
                "macOS backend uses this executor account and its exact supplementary groups",
            )?;
            require(
                service
                    || e.broader.contains(&BroaderBound::Memory)
                        && e.broader.contains(&BroaderBound::ExecutorRestart)
                        && e.broader.iter().all(|b| {
                            matches!(
                                b,
                                BroaderBound::Memory
                                    | BroaderBound::ExecutorRestart
                                    | BroaderBound::NetworkIpc
                                    | BroaderBound::Processes
                            )
                        }),
                RefusalCode::Unavailable,
                "macOS requires explicit broader memory and executor_restart authority: memory is polled and a controller crash can leave an orphan; restart preserves unknown cleanup and its reservation",
            )?;
            require(
                service
                    || endpoint
                    || e.resources.processes == 1
                    || e.broader.contains(&BroaderBound::Processes),
                RefusalCode::Unavailable,
                "macOS descendants require explicit broader processes authority: only the original group is polled and stopped; escaped descendants can outlive cancellation or deadline, and tree cleanup remains unconfirmed",
            )?;
            require(
                e.network.ipc.is_empty() && (service || e.delegated_services.is_empty()),
                RefusalCode::Unavailable,
                "ordinary macOS programs cannot bind/connect Unix sockets, look up Mach services or delegate service control; service effects require the validated fixed OS client or an independently enforced service boundary",
            )?;
            network::validate(e)?;
            filesystem::validate(&e.filesystem.write, protected)?;
            let mut read_paths = e.filesystem.read.clone();
            if endpoint {
                read_paths.extend(crate::endpoints::runtime_reads());
            }
            for path in read_paths.iter().chain([&e.executable]) {
                let path = Path::new(path);
                require(
                    path.is_absolute(),
                    RefusalCode::Unavailable,
                    "macOS execution paths must be absolute",
                )?;
                let real = path.canonicalize().map_err(unavailable)?;
                require(
                    !protected
                        .iter()
                        .any(|p| p.starts_with(&real) || real.starts_with(p)),
                    RefusalCode::Unavailable,
                    "filesystem scope exposes executor configuration or state",
                )?;
            }
            require(
                Path::new(&e.working_directory).is_absolute()
                    && fs::metadata(&e.working_directory)
                        .map_err(unavailable)?
                        .is_dir(),
                RefusalCode::Unavailable,
                "working directory must be an existing absolute directory; selecting it grants no file access",
            )?;
            let metadata = fs::metadata(&e.executable).map_err(unavailable)?;
            require(
                metadata.is_file()
                    && metadata.mode() & 0o111 != 0
                    && metadata.len() <= self.executable_bytes,
                RefusalCode::Unavailable,
                "executable needs a bounded regular-file snapshot",
            )?;
            require(
                file_hash(&e.executable, self.executable_bytes)? == e.executable_sha256,
                RefusalCode::Stale,
                "executable differs from adoption",
            )?;
        }
        Ok(())
    }

    pub fn reconcile(&self, ledger: &mut Ledger) -> Result<(), Refusal> {
        for receipt in ledger.recover(now())? {
            if let Some(process) = &receipt.process {
                if process.descendants_may_escape {
                    // Neither the current catalogue nor group membership can
                    // reconstruct the admitted tree after an intermediate
                    // parent exits. Keep the original reservation even when
                    // the leader, its group and its output writers are gone.
                    continue;
                }
                if birth(process.pid)?.is_some_and(|p| same(&p, process))
                    || !group_quiescent(process.process_group)?
                {
                    // A birth check followed by kill(pid) is still vulnerable
                    // to PID reuse after a restart: this executor no longer
                    // owns an unreaped child. Keep the reservation and unknown
                    // cleanup status instead of signalling by an unstable ID.
                    continue;
                }
                ledger.confirm_quiescent(&receipt.job_id, now(), "recorded single-process birth is absent or replaced and its original process group is quiescent; prior exit/effects stay unknown")?;
                let snapshot = ledger
                    .artifact_root()
                    .join(format!("{}.executable", receipt.job_id));
                match fs::remove_file(snapshot) {
                    Ok(()) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(unavailable(e)),
                }
            }
            // A crash between native spawn and durable PID capture can leave a
            // suspended process. Preserve that uncertainty and its reservation;
            // never redispatch or infer cleanup from the missing PID record.
        }
        Ok(())
    }

    pub fn execute(
        &self,
        target: &Target,
        ledger: Arc<Mutex<Ledger>>,
        id: &str,
        protected: &[PathBuf],
    ) -> Result<(), Refusal> {
        execute_job(target, ledger, id, |op, receipt, ledger| {
            self.run(op, receipt, ledger, protected)
        })
    }

    fn run(
        &self,
        op: &Operation,
        receipt: &Receipt,
        ledger: &Arc<Mutex<Ledger>>,
        protected: &[PathBuf],
    ) -> Result<NativeObservation, Refusal> {
        let command = op.command(&receipt.prepared.invocation.arguments)?;
        let service = crate::unix_services::validate(op)?;
        let endpoint = crate::endpoints::validate(op)?;
        network::validate(&op.execution)?;
        let writes = filesystem::validate(&op.execution.filesystem.write, protected)?;
        let listener = match crate::endpoints::bind_for_job(
            op.execution.network.listener_handoff.as_ref(),
            ledger,
            &receipt.job_id,
        ) {
            Ok(listener) => listener,
            Err(error) => {
                return Ok(crate::native::launch_refused("macos-seatbelt", error));
            }
        };
        let root = ledger
            .lock()
            .map_err(unavailable)?
            .artifact_root()
            .to_owned();
        let snapshot = root.join(format!("{}.executable", receipt.job_id));
        let mut input = File::open(&command.executable).map_err(unavailable)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut input)
            .take(self.executable_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        require(
            bytes.len() as u64 <= self.executable_bytes
                && hash(&bytes) == op.execution.executable_sha256,
            RefusalCode::Stale,
            "executable changed before snapshot",
        )?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&snapshot)
            .map_err(unavailable)?;
        file.write_all(&bytes).map_err(unavailable)?;
        file.sync_all().map_err(unavailable)?;
        drop((bytes, file, input));
        let mut profile = format!(
            "(version 1)(deny default)(allow process-exec (literal {}))(allow file-read* (literal {}) (literal \"/\") (literal \"/dev/null\"))(allow sysctl-read)",
            quoted(
                snapshot
                    .to_str()
                    .ok_or_else(|| unavailable("snapshot path is not UTF-8"))?
            ),
            quoted(snapshot.to_str().unwrap())
        );
        let descendants = !endpoint && !service && op.execution.resources.processes > 1;
        if descendants {
            // Seatbelt is inherited across both fork/exec and posix_spawn.
            // Process-group membership does not establish descendant lifetime.
            profile.push_str("(allow process-fork)");
        }
        if endpoint {
            // Only this executable's fixed native helper receives socket
            // access. Its typed selector and filtering are trusted executor
            // code; no arbitrary adopted program receives this exception.
            profile.push_str("(allow network*)");
            profile.push_str("(allow file-read* (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/Library/Apple/System/Library\"))");
        }
        if service {
            profile.push_str("(allow mach-lookup)");
            if matches!(
                op.execution.delegated_services[0].capability.as_str(),
                "stop" | "restart"
            ) {
                // launchd checks the client's signal permission before replacing
                // this fixed service process. Only the pinned OS client receives
                // this permission; arbitrary adopted programs remain denied.
                profile.push_str("(allow signal)");
            }
        }
        profile.push_str(&network::profile(&op.execution));
        if listener.is_some() {
            let observation = ledger
                .lock()
                .map_err(unavailable)?
                .observe(&receipt.job_id)?
                .listener_handoff
                .ok_or_else(|| unavailable("listener bind observation missing"))?;
            let binding = observation
                .binding
                .ok_or_else(|| unavailable("bound listener address missing"))?;
            // Creation and bind remain denied unless separately declared. This
            // rule permits accept on the already-bound inherited TCP socket.
            let address_class = if binding.ip().is_loopback() {
                "localhost"
            } else {
                "*"
            };
            profile.push_str(&format!(
                "(allow network-inbound (require-all (local tcp \"{}:{}\") (socket-type SOCK_STREAM)))",
                address_class, binding.port(),
            ));
        }
        for path in &writes {
            // Source and destination link/rename checks still pass through
            // Seatbelt. Resolving an inner symlink grants no outside access.
            profile.push_str(&format!(
                "(allow file-read* file-write* (subpath {}))",
                quoted(
                    path.to_str()
                        .ok_or_else(|| unavailable("write path is not UTF-8"))?
                )
            ));
        }
        for path in op
            .execution
            .filesystem
            .read
            .iter()
            .map(Path::new)
            .chain(writes.iter().map(PathBuf::as_path))
        {
            let real = path.canonicalize().map_err(unavailable)?;
            // realpath resolves each parent before opening the adopted path.
            // Parent metadata grants no sibling content or directory listing.
            for parent in real.ancestors().skip(1) {
                profile.push_str(&format!(
                    "(allow file-read-metadata (literal {}))",
                    quoted(
                        parent
                            .to_str()
                            .ok_or_else(|| unavailable("read parent is not UTF-8"))?
                    )
                ));
            }
            profile.push_str(&format!(
                "(allow file-read* (subpath {}))",
                quoted(
                    real.to_str()
                        .ok_or_else(|| unavailable("read path is not UTF-8"))?
                )
            ));
            if descendants {
                profile.push_str(&format!(
                    "(allow process-exec (subpath {}))",
                    quoted(real.to_str().unwrap())
                ));
            }
        }
        let args = [
            vec![
                "/usr/bin/sandbox-exec".into(),
                "-p".into(),
                profile,
                snapshot.to_str().unwrap().into(),
            ],
            command.argv,
        ]
        .concat();
        let child = spawn_suspended(
            &args,
            &command.environment,
            &command.working_directory,
            listener.as_ref().map(AsRawFd::as_raw_fd),
        )?;
        drop(listener);
        let mut child = child;
        let mut process = birth(child.pid)?
            .ok_or_else(|| unavailable("suspended process identity unavailable"))?;
        process.descendants_may_escape = descendants;
        ledger
            .lock()
            .map_err(unavailable)?
            .attach_process(&receipt.job_id, process)?;
        if unsafe { libc::kill(child.pid as i32, libc::SIGCONT) } != 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        let deadline = Instant::now() + Duration::from_secs(receipt.deadline.saturating_sub(now()));
        let mut reason = "exited";
        let mut truncated = false;
        loop {
            truncated |= child.output(ledger, &receipt.job_id, false)?.0;
            if truncated {
                reason = "output_limit";
                break;
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
            let members = group_members(child.pid)?;
            if members.len() > op.execution.resources.processes as usize {
                reason = "observed_process_limit";
                break;
            }
            if group_memory(&members)? > op.execution.resources.memory_bytes {
                reason = "observed_memory_limit";
                break;
            }
            if child.exited()? && group_quiescent(child.pid)? {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if reason != "exited" {
            child.kill_group()?;
            let cleanup_deadline = Instant::now() + Duration::from_secs(2);
            while !child.exited()? || !group_quiescent(child.pid)? {
                require(
                    Instant::now() < cleanup_deadline,
                    RefusalCode::Unavailable,
                    "process group did not become quiescent after SIGKILL; cleanup is unconfirmed",
                )?;
                // A fork already in progress can publish a new group member
                // after the first group-directed signal. Our unreaped leader
                // still reserves this group ID, so close that race by signalling
                // again until native observation confirms quiescence.
                child.kill_group()?;
                truncated |= child.output(ledger, &receipt.job_id, false)?.0;
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // Keep the leader unreaped until the group is quiescent. Its PID anchors
        // the group against reuse while group-directed signals are possible.
        let status = child.wait(true)?;
        // Escaped descendants can retain writers after group quiescence. Bound
        // this drain too; an escaped producer must not stall result recording.
        let (overflow, eof) = child.output(ledger, &receipt.job_id, !descendants)?;
        truncated |= overflow || !eof;
        require(
            eof || descendants,
            RefusalCode::Unavailable,
            "quiescent process group has an open output writer; cleanup is unconfirmed",
        )?;
        let stopped = status.is_some() && !descendants;
        if stopped {
            fs::remove_file(snapshot).map_err(unavailable)?;
            child.reaped = true;
        }
        let mut result = NativeObservation { backend: "macos-seatbelt".into(), enforcement: vec!["Seatbelt adopted read paths and ancestor directory metadata, no file writes, no direct socket connections or Mach lookups, pinned private primary executable snapshot and exact environment".into(), "dedicated initial session and process group; leader wait status is retained until original-group quiescence; bounded retained output and original-group wall deadline while the executor remains live".into()], dependencies: vec!["EXPLICIT BROADER MEMORY: original-group resident memory is polled; transient allocations, escaped descendants and kernel pressure are not hard-capped".into(), "EXPLICIT BROADER EXECUTOR RESTART: a controller crash may leave processes running beyond the deadline. Recovered PIDs/groups are never signalled. Single-process reconciliation can release a reservation after observing quiescence; multi-process cleanup and its reservation remain uncertain. macOS Seatbelt, baseline sysctl reads and host-owned libraries are required".into()], exit_code: status.and_then(|s| std::process::ExitStatus::from_raw(s).code()), signal: status.and_then(|s| std::process::ExitStatus::from_raw(s).signal()), processes_stopped: stopped, output_truncated: truncated, termination_reason: reason.into() };
        if endpoint {
            result.enforcement[0] = "Seatbelt permits host system libraries, denies workload file scopes, Mach lookups and fork; only the pinned trusted endpoint helper receives sockets. Its native implementation filters the authorised typed selector before output.".into();
            result.enforcement.extend(crate::endpoints::disclosure());
        }
        if service {
            result.enforcement[0] = "Seatbelt adopted read paths and ancestor directory metadata, no file writes, no direct sockets or fork; the pinned trusted launchctl client receives Mach lookup and, for stop/restart, native signal permission, with fixed adopted action/resource and exact environment".into();
            result.dependencies.push("EXPLICIT BROADER NETWORK/IPC: Mach lookup scope is not per-service isolation; the OS client and its system libraries are trusted executor code".into());
            result.dependencies.push(crate::unix_services::disclosure());
        }
        if !writes.is_empty() {
            result.enforcement[0] = "Seatbelt selected read/write paths, canonical ancestor metadata, no Mach lookup or Unix-socket bind/connect, pinned private primary executable snapshot and exact environment; process creation and selected IP sockets follow the separately reported boundaries".into();
            result.dependencies.push(format!("selected host read/write paths {writes:?}; validation refuses existing hard links outside the writable scope and executor control/runtime aliases. Seatbelt follows resolved paths at access time; host replacement changes the selected path contents. New descendants and file replacement are allowed within selected directories. Files persist after completion, cancellation and restart. Host services can consume written configuration outside this child's lifecycle; those indirect effects are not observed or rolled back. output_bytes bounds stdout/stderr, not file storage; Output does not retrieve these files."));
        }
        if !op.execution.network.destinations.is_empty()
            || !op.execution.network.listeners.is_empty()
        {
            result.dependencies.extend(network_enforcement(op));
            if writes.is_empty() {
                result.enforcement[0] = "Seatbelt selected read paths, no writes, Mach lookup or Unix-socket bind/connect, pinned private primary executable snapshot and exact environment; process creation and IP sockets follow the separately reported boundaries".into();
            }
        }
        if op.execution.network.listener_handoff.is_some() {
            result
                .dependencies
                .extend(crate::endpoints::handoff_disclosure(op));
            result.enforcement.push("The trusted executor passes the selected listening TCP socket as descriptor 3. Additional binding, implicit listen and outbound connections remain denied unless separately granted. Authorised descendants inherit the same network boundary and descriptor.".into());
        }
        if descendants {
            result.enforcement.push("Fork/exec and posix_spawn descendants inherit Seatbelt file/network/IPC bounds. Child executables use selected read/write paths; those mutable binaries are not content-pinned. Background work in the original group keeps the job running until that group becomes quiescent, cancellation or deadline. Output capture ends with that group; an open writer is reported as truncated.".into());
            if !result
                .dependencies
                .iter()
                .any(|fact| fact == DESCENDANT_LIMIT)
            {
                result.dependencies.push(DESCENDANT_LIMIT.into());
            }
        } else {
            result
                .enforcement
                .push("Single-process authority: fork and child execution remain denied.".into());
        }
        Ok(result)
    }
}

fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn file_hash(path: &str, max: u64) -> Result<String, Refusal> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(unavailable)?
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unavailable)?;
    require(
        bytes.len() as u64 <= max,
        RefusalCode::Budget,
        "executable exceeds snapshot ceiling",
    )?;
    Ok(hash(&bytes))
}

struct MacChild {
    pid: u32,
    pipes: [File; 2],
    reaped: bool,
}
impl MacChild {
    fn exited(&self) -> Result<bool, Refusal> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // WNOWAIT keeps the leader's PID/group reserved until its original
        // group is quiescent, even if a background launcher has exited.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        Ok(unsafe { info.assume_init() }.si_pid != 0)
    }
    fn kill_group(&self) -> Result<(), Refusal> {
        // The unreaped leader reserves this group ID. Do not reuse this
        // operation after executor restart, when that ownership is lost.
        if unsafe { libc::kill(-(self.pid as i32), libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            // A group containing only an unreaped zombie has no signal target;
            // Darwin can return EPERM. This is safe only while our leader's
            // wait status and an independent quiescence observation agree.
            if self.exited()? && group_quiescent(self.pid)? {
                return Ok(());
            }
            return Err(unavailable(format!(
                "signal job process group {}: {error}",
                self.pid
            )));
        }
        Ok(())
    }
    fn wait(&mut self, blocking: bool) -> Result<Option<i32>, Refusal> {
        let mut status = 0;
        let result = unsafe {
            libc::waitpid(
                self.pid as i32,
                &mut status,
                if blocking { 0 } else { libc::WNOHANG },
            )
        };
        if result < 0 {
            Err(unavailable(std::io::Error::last_os_error()))
        } else {
            self.reaped |= result > 0;
            Ok((result > 0).then_some(status))
        }
    }
    fn output(
        &mut self,
        ledger: &Arc<Mutex<Ledger>>,
        id: &str,
        final_drain: bool,
    ) -> Result<(bool, bool), Refusal> {
        let mut truncated = false;
        let mut eof = true;
        for pipe in &mut self.pipes {
            // Bound each drain so a continuous producer cannot starve timeout
            // or cancellation observation.
            let mut reads = 0;
            loop {
                let mut bytes = [0; 4096];
                match pipe.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => {
                        truncated |= ledger.lock().map_err(unavailable)?.append_output(
                            id,
                            &bytes[..n],
                            now(),
                        )? < n;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        eof = false;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(unavailable(e)),
                }
                reads += 1;
                if !final_drain && reads == 2 {
                    eof = false;
                    break;
                }
            }
        }
        Ok((truncated, eof))
    }
}
impl Drop for MacChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_group();
            unsafe {
                libc::waitpid(self.pid as i32, std::ptr::null_mut(), libc::WNOHANG);
            }
        }
    }
}

fn spawn_suspended(
    args: &[String],
    environment: &std::collections::BTreeMap<String, String>,
    cwd: &str,
    listener: Option<i32>,
) -> Result<MacChild, Refusal> {
    // All allocation happens before posix_spawn. The kernel creates a suspended
    // child, with only the explicit standard descriptors, before durable capture.
    let strings: Vec<_> = args
        .iter()
        .map(|s| CString::new(s.as_str()).map_err(unavailable))
        .collect::<Result<_, _>>()?;
    let env: Vec<_> = environment
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).map_err(unavailable))
        .collect::<Result<_, _>>()?;
    let mut argv: Vec<_> = strings.iter().map(|s| s.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let mut envp: Vec<_> = env.iter().map(|s| s.as_ptr().cast_mut()).collect();
    envp.push(std::ptr::null_mut());
    let cwd = CString::new(cwd).map_err(unavailable)?;
    let mut pipes = Vec::new();
    let mut writes = Vec::new();
    for _ in 0..2 {
        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        let (read, write) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        if unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(unavailable(std::io::Error::last_os_error()));
        }
        pipes.push(read);
        writes.push(write);
    }
    let null = File::open("/dev/null").map_err(unavailable)?;
    let mut actions = std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
    let mut attrs = std::mem::MaybeUninit::<libc::posix_spawnattr_t>::uninit();
    fn check(n: i32) -> Result<(), Refusal> {
        if n == 0 {
            Ok(())
        } else {
            Err(unavailable(std::io::Error::from_raw_os_error(n)))
        }
    }
    unsafe {
        check(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()))?;
        let mut actions = actions.assume_init();
        let result = (|| {
            check(libc::posix_spawnattr_init(attrs.as_mut_ptr()))?;
            let mut attrs = attrs.assume_init();
            let result = (|| {
                check(libc::posix_spawn_file_actions_adddup2(
                    &mut actions,
                    null.as_raw_fd(),
                    0,
                ))?;
                for (n, write) in writes.iter().enumerate() {
                    check(libc::posix_spawn_file_actions_adddup2(
                        &mut actions,
                        write.as_raw_fd(),
                        n as i32 + 1,
                    ))?;
                }
                if let Some(listener) = listener {
                    check(libc::posix_spawn_file_actions_adddup2(
                        &mut actions,
                        listener,
                        3,
                    ))?;
                }
                check(posix_spawn_file_actions_addchdir_np(
                    &mut actions,
                    cwd.as_ptr(),
                ))?;
                check(libc::posix_spawnattr_setflags(
                    &mut attrs,
                    (libc::POSIX_SPAWN_START_SUSPENDED
                        | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                        | POSIX_SPAWN_SETSID as i32) as i16,
                ))?;
                let mut pid = 0;
                check(libc::posix_spawn(
                    &mut pid,
                    strings[0].as_ptr(),
                    &actions,
                    &attrs,
                    argv.as_ptr(),
                    envp.as_ptr(),
                ))?;
                Ok(MacChild {
                    pid: pid as u32,
                    pipes: pipes
                        .try_into()
                        .map_err(|_| unavailable("invalid native pipe count"))?,
                    reaped: false,
                })
            })();
            libc::posix_spawnattr_destroy(&mut attrs);
            result
        })();
        libc::posix_spawn_file_actions_destroy(&mut actions);
        result
    }
}

// Available since macOS 10.15; the pinned libc binding omits this declaration.
unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}
