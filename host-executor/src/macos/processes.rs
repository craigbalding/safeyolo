//! Observe only a job's confined process group, including orphaned descendants.
use super::*;

// <sys/proc_info.h>; the pinned libc exposes proc_listpids but omits this selector.
const PROC_PGRP_ONLY: u32 = 2;

fn list(group: u32, buffer: *mut libc::c_void, bytes: i32) -> Result<usize, Refusal> {
    // libproc returns zero both for an empty list and for failure. Clear errno
    // before the call so a failed read cannot be reported as quiescence.
    unsafe {
        *libc::__error() = 0;
    }
    let result = unsafe { libc::proc_listpids(PROC_PGRP_ONLY, group, buffer, bytes) };
    let error = std::io::Error::last_os_error();
    if result < 0 || result == 0 && error.raw_os_error() != Some(0) {
        return Err(unavailable(error));
    }
    Ok(result as usize)
}

fn group_pids(group: u32) -> Result<Vec<u32>, Refusal> {
    // proc_listpids returns bytes, not a PID count. Allow growth between the
    // sizing and data calls; a filled buffer is incomplete and is never empty.
    for _ in 0..3 {
        let bytes = list(group, std::ptr::null_mut(), 0)?;
        let capacity = (bytes / std::mem::size_of::<u32>()).saturating_add(64);
        let mut pids = vec![0u32; capacity];
        let bytes = list(
            group,
            pids.as_mut_ptr().cast(),
            (capacity * std::mem::size_of::<u32>())
                .try_into()
                .map_err(unavailable)?,
        )?;
        let count = bytes / std::mem::size_of::<u32>();
        if count >= capacity {
            continue;
        }
        pids.truncate(count);
        pids.retain(|pid| *pid != 0);
        return Ok(pids);
    }
    Err(unavailable(
        "process group changed faster than a complete observation",
    ))
}

pub(super) fn group_empty(group: u32) -> Result<bool, Refusal> {
    Ok(group_pids(group)?.is_empty())
}

pub(super) fn children_absent(group: u32) -> Result<bool, Refusal> {
    // Call only after observing the leader's retained exit status. Inspect the
    // raw group list: a process that exits between listing and birth lookup
    // might have forked a child. Filtering that process out is not quiescence.
    Ok(group_pids(group)?.iter().all(|pid| *pid == group))
}

pub(super) fn group_members(group: u32) -> Result<Vec<NativeProcess>, Refusal> {
    let mut members = Vec::new();
    for pid in group_pids(group)? {
        if let Some(process) = birth(pid)? {
            if process.process_group == group {
                members.push(process);
            }
        }
    }
    Ok(members)
}

pub(super) fn group_memory(members: &[NativeProcess]) -> Result<u64, Refusal> {
    let mut memory = 0u64;
    for process in members {
        let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        let bytes = unsafe {
            libc::proc_pidinfo(
                process.pid as i32,
                libc::PROC_PIDTASKINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if bytes == size {
            memory = memory.saturating_add(unsafe { info.assume_init() }.pti_resident_size);
        } else if birth(process.pid)?.is_some_and(|current| same(&current, process)) {
            return Err(unavailable("live group member memory observation failed"));
        }
    }
    Ok(memory)
}
