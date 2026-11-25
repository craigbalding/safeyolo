//! Observe only a job's confined process group, including orphaned descendants.
use super::*;

pub(super) fn group_members(group: u32) -> Result<Vec<NativeProcess>, Refusal> {
    // proc_listpids returns bytes, not a PID count. Allow growth between the
    // sizing and data calls; a filled buffer is incomplete and is never empty.
    for _ in 0..3 {
        let bytes =
            unsafe { libc::proc_listpids(libc::PROC_PGRP_ONLY, group, std::ptr::null_mut(), 0) };
        require(
            bytes >= 0,
            RefusalCode::Unavailable,
            "process-group sizing failed",
        )?;
        let capacity = (bytes as usize / std::mem::size_of::<u32>()).saturating_add(64);
        let mut pids = vec![0u32; capacity];
        let bytes = unsafe {
            libc::proc_listpids(
                libc::PROC_PGRP_ONLY,
                group,
                pids.as_mut_ptr().cast(),
                (capacity * std::mem::size_of::<u32>())
                    .try_into()
                    .map_err(unavailable)?,
            )
        };
        require(
            bytes >= 0,
            RefusalCode::Unavailable,
            "process-group observation failed",
        )?;
        let count = bytes as usize / std::mem::size_of::<u32>();
        if count >= capacity {
            continue;
        }
        pids.truncate(count);
        let mut members = Vec::new();
        for pid in pids {
            if pid != 0 {
                if let Some(process) = birth(pid)? {
                    if process.process_group == group {
                        members.push(process);
                    }
                }
            }
        }
        return Ok(members);
    }
    Err(unavailable(
        "process group changed faster than a complete observation",
    ))
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
