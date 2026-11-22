use super::{WindowsRuntime, security::*};
use crate::*;
use std::{
    fs::File,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Storage::FileSystem::*,
    System::{
        JobObjects::*,
        Pipes::*,
        SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE},
        Threading::*,
    },
};

/// Windows CRT command-line quoting. lpApplicationName is supplied separately;
/// this string is never passed to a shell. The selected executable owns any
/// non-CRT argument parsing and is assessed as an explicit interpreter if used.
fn quote(word: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in word.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
        } else {
            out.extend(std::iter::repeat_n('\\', slashes));
        }
        out.push(ch);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}
fn command_line(command: &Command) -> Result<Vec<u16>, Refusal> {
    let text = std::iter::once(&command.executable)
        .chain(command.argv.iter())
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(" ");
    let result = wide(&text)?;
    // CreateProcessAsUserW accepts up to 32767 UTF-16 units, including NUL.
    // The shorter token-launch fallback is checked only if it is needed.
    require(
        result.len() <= 32767,
        RefusalCode::Arguments,
        "Windows command line exceeds the 32767 UTF-16-unit native limit",
    )?;
    Ok(result)
}
fn environment(command: &Command) -> Result<Vec<u16>, Refusal> {
    let mut pairs: Vec<_> = command.environment.iter().collect();
    pairs.sort_by_key(|(key, _)| key.to_uppercase());
    let mut result = Vec::new();
    for (key, value) in pairs {
        result.extend(wide(&format!("{key}={value}"))?);
    }
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    Ok(result)
}
pub(super) fn validate_command(command: &Command) -> Result<(), Refusal> {
    command_line(command)?;
    environment(command)?;
    Ok(())
}
fn name(target: &str, job: &str) -> Result<Vec<u16>, Refusal> {
    wide(&format!("Local\\SafeYolo-host-{target}-{job}"))
}
fn active(job: &Handle) -> Result<u32, Refusal> {
    let mut info = unsafe { zeroed::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() };
    // SAFETY: the typed output has the exact size required by this information class.
    check(
        unsafe {
            QueryInformationJobObject(
                job.0,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        },
        "job population",
    )?;
    Ok(info.ActiveProcesses)
}
fn stop(job: &Handle) -> Result<bool, Refusal> {
    check(
        unsafe { TerminateJobObject(job.0, 1) },
        "terminate job descendants",
    )?;
    let end = Instant::now() + Duration::from_secs(5);
    while active(job)? != 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(active(job)? == 0)
}
pub(super) fn reconcile(ledger: &mut Ledger) -> Result<(), Refusal> {
    for receipt in ledger.recover(now())? {
        let handle = unsafe {
            OpenJobObjectW(
                JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY | READ_CONTROL,
                0,
                name(&receipt.target_id, &receipt.job_id)?.as_ptr(),
            )
        };
        let stopped = if handle.is_null() {
            let code = unsafe { GetLastError() };
            // KILL_ON_JOB_CLOSE and a non-inherited handle mean an absent Job
            // after the previous executor exited has no associated live process.
            if code != ERROR_FILE_NOT_FOUND {
                return Err(error("recover job handle"));
            }
            true
        } else {
            let job = Handle::new(handle, "recover job handle")?;
            own_job(job.0)?;
            stop(&job)?
        };
        if stopped {
            ledger.confirm_quiescent(&receipt.job_id, now(),
            "restart: direct Job Object population stopped/absent; prior output and delegated effects remain unknown; never replayed")?;
        }
    }
    Ok(())
}

struct Process(Handle);
impl Drop for Process {
    fn drop(&mut self) {
        // The handle identifies this exact process. No PID lookup/reuse can
        // target an unrelated process if launch fails before it is resumed.
        unsafe {
            TerminateProcess(self.0.0, 1);
        }
    }
}
struct Attributes {
    buffer: Vec<usize>,
    handles: Vec<HANDLE>,
    jobs: Vec<HANDLE>,
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.buffer.as_mut_ptr().cast());
        }
    }
}
fn attributes(handles: Vec<HANDLE>, job: HANDLE) -> Result<Attributes, Refusal> {
    let mut bytes = 0;
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes);
    }
    require(
        bytes > 0,
        RefusalCode::Unavailable,
        "Windows handle-list size unavailable",
    )?;
    let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    check(
        unsafe { InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 2, 0, &mut bytes) },
        "initialize inherited handle list",
    )?;
    let mut result = Attributes {
        buffer,
        handles,
        jobs: vec![job],
    };
    check(
        unsafe {
            UpdateProcThreadAttribute(
                result.buffer.as_ptr().cast_mut().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                result.handles.as_mut_ptr().cast(),
                std::mem::size_of_val(result.handles.as_slice()),
                null_mut(),
                null(),
            )
        },
        "restrict inherited handles",
    )?;
    // Assignment during creation closes the controller-crash window between
    // creating a suspended process and adding it to its kill-on-close Job.
    // Both backing arrays remain alive until this attribute list is deleted.
    check(
        unsafe {
            UpdateProcThreadAttribute(
                result.buffer.as_ptr().cast_mut().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                result.jobs.as_mut_ptr().cast(),
                std::mem::size_of_val(result.jobs.as_slice()),
                null_mut(),
                null(),
            )
        },
        "assign workload Job during process creation",
    )?;
    Ok(result)
}

pub(super) fn run(
    runtime: &WindowsRuntime,
    operation: &Operation,
    receipt: &Receipt,
    ledger: &Arc<Mutex<Ledger>>,
) -> Result<NativeObservation, Refusal> {
    let token = workload(&runtime.credential)?;
    let command = operation.command(&receipt.prepared.invocation.arguments)?;
    let _pins: Vec<File> = executable(
        &command.executable,
        &operation.execution.executable_sha256,
        runtime.executable_bytes,
        &token,
    )?;
    let descriptor = private_descriptor()?;
    let attributes_job = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let job = Handle::new(
        unsafe {
            CreateJobObjectW(
                &attributes_job,
                name(&receipt.target_id, &receipt.job_id)?.as_ptr(),
            )
        },
        "create private job",
    )?;
    require(
        unsafe { GetLastError() } != ERROR_ALREADY_EXISTS,
        RefusalCode::Unavailable,
        "job identity already exists; retained effects must be reconciled, not redispatched",
    )?;
    let mut limits = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = operation
        .execution
        .resources
        .processes
        .try_into()
        .map_err(native::unavailable)?;
    limits.JobMemoryLimit = operation
        .execution
        .resources
        .memory_bytes
        .try_into()
        .map_err(native::unavailable)?;
    check(
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        },
        "set job memory/process ceilings",
    )?;

    let inherit = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    check(
        unsafe { CreatePipe(&mut read, &mut write, &inherit, 4096) },
        "create bounded output pipe",
    )?;
    let read = Handle::new(read, "output reader")?;
    let write = Handle::new(write, "output writer")?;
    check(
        unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0) },
        "prevent inherited output reader",
    )?;
    let input = Handle::new(
        unsafe {
            CreateFileW(
                wide("NUL")?.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &inherit,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        },
        "null stdin",
    )?;
    let mut handles = attributes(vec![input.0, write.0], job.0)?;
    let mut startup = unsafe { zeroed::<STARTUPINFOEXW>() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.0;
    startup.StartupInfo.hStdOutput = write.0;
    startup.StartupInfo.hStdError = write.0;
    startup.lpAttributeList = handles.buffer.as_mut_ptr().cast();
    let mut info = unsafe { zeroed::<PROCESS_INFORMATION>() };
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW;
    let mut line = command_line(&command)?;
    let env = environment(&command)?;
    let (application, cwd) = (
        wide(&command.executable)?,
        wide(&command.working_directory)?,
    );
    require(
        !super::service::stopping(),
        RefusalCode::Unavailable,
        "executor is stopping; no process launched",
    )?;
    // Both calls use the exact selected primary token. The first supports a
    // service account with assign-primary/quota rights; the second requires
    // SeImpersonatePrivilege. No fallback changes identity or authorizes a shell.
    let created = unsafe {
        CreateProcessAsUserW(
            token.0,
            application.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
            flags,
            env.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    if created == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_PRIVILEGE_NOT_HELD {
            return Err(error("create suspended workload"));
        }
        line = command_line(&command)?;
        require(
            line.len() <= 1024,
            RefusalCode::Unavailable,
            "the selected executor lacks assign-primary-token/quota privilege and its token-launch fallback supports only 1024 UTF-16 units; use an executor account with the required native launch privileges for this command",
        )?;
        check(
            unsafe {
                CreateProcessWithTokenW(
                    token.0,
                    0,
                    application.as_ptr(),
                    line.as_mut_ptr(),
                    flags,
                    env.as_ptr().cast(),
                    cwd.as_ptr(),
                    &startup.StartupInfo,
                    &mut info,
                )
            },
            "create suspended workload with selected token",
        )?;
    }
    let process = Process(Handle::new(info.hProcess, "workload process")?);
    let thread = Handle::new(info.hThread, "workload primary thread")?;
    let mut in_job = 0;
    check(
        unsafe { IsProcessInJob(process.0.0, job.0, &mut in_job) },
        "verify creation-time Job assignment",
    )?;
    require(
        in_job != 0,
        RefusalCode::Unavailable,
        "native launch did not apply creation-time Job assignment; workload remains suspended and is terminated",
    )?;
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err(error("resume job workload"));
    }
    drop((thread, write, input, handles, token));
    let deadline = Instant::now() + Duration::from_secs(receipt.deadline.saturating_sub(now()));
    let mut truncated = false;
    let mut output_eof = false;
    let mut reason = "exited";
    loop {
        if drain(&read, ledger, receipt, &mut output_eof, &mut truncated)? {
            reason = "output_limit";
            break;
        }
        if super::service::stopping() {
            reason = "executor_stop";
            break;
        }
        if ledger
            .lock()
            .map_err(native::unavailable)?
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
        match unsafe { WaitForSingleObject(process.0.0, 0) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => (),
            _ => return Err(error("observe workload exit")),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut exit = 0;
    check(
        unsafe { GetExitCodeProcess(process.0.0, &mut exit) },
        "workload exit code",
    )?;
    let exited = unsafe { WaitForSingleObject(process.0.0, 0) } == WAIT_OBJECT_0;
    let stopped = stop(&job)?;
    // Drain only bounded chunks. A deliberately delegated service may retain a
    // pipe outside the Job; never block on its EOF or report that service stopped.
    let drain_deadline = Instant::now() + Duration::from_secs(1);
    while !output_eof && Instant::now() < drain_deadline {
        drain(&read, ledger, receipt, &mut output_eof, &mut truncated)?;
        if !output_eof {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(NativeObservation {
        backend: "windows-job-object-separate-account".into(),
        enforcement: vec!["explicit workload SID/groups; no administrator or ACL-bypass privileges".into(),
            "executable/ancestor handles prevent replacement; only stdin and merged output handles inherited".into(),
            "Job Object aggregate memory and active-process ceilings; no breakaway; kernel kill-on-close".into(),
            "bounded retained output, deadline/cancellation and observed direct Job population cleanup".into()],
        dependencies: vec!["filesystem (including disk writes without a per-job quota), registry, network/IPC and service effects use the broader workload account's OS permissions; declared paths/destinations/services are assessments, not confinement".into(),
            "service-manager/WMI/task-scheduler delegated processes and persistent effects may outlive the Job; processes_stopped refers only to associated Job processes".into(),
            "host-owned DLLs, executable directory dependencies and OS tools are not content-pinned; no user profile/HKCU hive is loaded automatically".into()],
        exit_code: if exited { Some(exit as i32) } else { None }, signal: None,
        processes_stopped: stopped, output_truncated: truncated || !output_eof, termination_reason: reason.into(),
    })
}
fn drain(
    pipe: &Handle,
    ledger: &Arc<Mutex<Ledger>>,
    receipt: &Receipt,
    eof: &mut bool,
    truncated: &mut bool,
) -> Result<bool, Refusal> {
    if *eof {
        return Ok(false);
    }
    let mut available = 0;
    if unsafe {
        PeekNamedPipe(
            pipe.0,
            null_mut(),
            0,
            null_mut(),
            &mut available,
            null_mut(),
        )
    } == 0
    {
        if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
            *eof = true;
            return Ok(false);
        }
        return Err(error("observe output pipe"));
    }
    if available == 0 {
        return Ok(false);
    }
    let mut bytes = [0u8; 4096];
    let mut read = 0;
    check(
        unsafe {
            ReadFile(
                pipe.0,
                bytes.as_mut_ptr(),
                available.min(bytes.len() as u32),
                &mut read,
                null_mut(),
            )
        },
        "read available output",
    )?;
    let kept = ledger.lock().map_err(native::unavailable)?.append_output(
        &receipt.job_id,
        &bytes[..read as usize],
        now(),
    )?;
    *truncated |= kept < read as usize;
    Ok(*truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crt_words_preserve_empty_quotes_and_trailing_slashes() {
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("x y"), "\"x y\"");
        assert_eq!(quote("a\\\"b\\"), "\"a\\\\\\\"b\\\\\"");
    }
    #[test]
    fn native_launch_limits_count_utf16_units_before_admission() {
        let mut command = Command {
            executable: "C:\\program.exe".into(),
            argv: vec!["😀".repeat(16360)],
            environment: Default::default(),
            working_directory: "C:\\".into(),
        };
        assert!(validate_command(&command).is_ok());
        command.argv = vec!["😀".repeat(16380)];
        assert_eq!(
            validate_command(&command).unwrap_err().code,
            RefusalCode::Arguments
        );
    }
}
