//! Explicit allocator accounting, called only by the blocking stats report.

use serde_json::{Value, json};

pub(super) fn document() -> Value {
    document_with_sample(sample)
}

fn document_with_sample(sample: fn() -> Result<Value, &'static str>) -> Value {
    let sampled_at = crate::policy::current_time_ms();
    let mut report = json!({
        "status": "unavailable",
        "reason": null,
        "bytes": null,
        "libc": {"name": if cfg!(target_env = "musl") {"musl"} else {"unknown"}, "version": null},
        "pid": std::process::id(),
        "build": {
            "revision": env!("SAFEYOLO_BUILD_REVISION"),
            "profile": env!("SAFEYOLO_BUILD_PROFILE"),
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "sampled_at_unix_ms": sampled_at,
        "interpretation": "Allocator-visible occupied and free storage; these counters do not identify resident or immediately reclaimable pages, per-thread caches, fragmentation owners, or a leak.",
        "sampling_cost": "An explicit sample traverses allocator structures and locks arenas; concurrent allocation can be delayed."
    });
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: glibc owns this static, nul-terminated version string.
        let version = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) };
        report["libc"] = json!({"name": "glibc", "version": version.to_string_lossy()});
    }
    match sample() {
        Ok(bytes) => {
            report["status"] = json!("available");
            report["source"] = json!("mallinfo2");
            report["bytes"] = bytes;
        }
        Err(reason) => report["reason"] = json!(reason),
    }
    // The existing sampler preserves source-compatible zeroes on a missing
    // procfs read. This diagnostic reports that absence explicitly instead.
    let rss = crate::memory_monitor::process::sample()
        .ok()
        .and_then(|sample| u64::try_from(sample.rss_kb).ok())
        .filter(|kb| *kb > 0)
        .and_then(|kb| kb.checked_mul(1024));
    report["rss"] = json!({
        "status": if rss.is_some() { "available" } else { "unavailable" },
        "source": "/proc/self/status VmRSS",
        "bytes": rss,
    });
    report
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn sample() -> Result<Value, &'static str> {
    // SAFETY: RTLD_DEFAULT searches the process's loaded libraries and the
    // symbol name is nul-terminated. A missing capability is a null pointer.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mallinfo2".as_ptr()) };
    // SAFETY: the lookup requests glibc's mallinfo2 or returns null.
    unsafe { sample_mallinfo2(symbol) }
}

/// A non-null pointer must have glibc's mallinfo2 signature and remain loaded.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe fn sample_mallinfo2(symbol: *mut libc::c_void) -> Result<Value, &'static str> {
    if symbol.is_null() {
        return Err("mallinfo2 is unavailable in this process");
    }
    // SAFETY: glibc defines mallinfo2 with this signature. The loaded libc
    // remains present for the process lifetime and owns the arena locks.
    let read: unsafe extern "C" fn() -> libc::mallinfo2 = unsafe { std::mem::transmute(symbol) };
    let sample = unsafe { read() };
    Ok(json!({
        "arena": sample.arena,
        "uordblks": sample.uordblks,
        "fordblks": sample.fordblks,
        "hblkhd": sample.hblkhd,
    }))
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn sample() -> Result<Value, &'static str> {
    Err("GNU allocator accounting requires a GNU/Linux build")
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;

    #[test]
    fn missing_allocator_sample_is_explicit_and_keeps_process_context() {
        let report = document_with_sample(|| {
            // SAFETY: null is handled before any function call.
            unsafe { sample_mallinfo2(std::ptr::null_mut()) }
        });
        assert_eq!(report["status"], "unavailable");
        assert_eq!(report["reason"], "mallinfo2 is unavailable in this process");
        assert!(report["bytes"].is_null());
        assert_eq!(report["pid"], std::process::id());
        assert!(report["build"].is_object());
        assert!(report["sampled_at_unix_ms"].is_number());
        assert!(report["rss"].is_object());
    }
}
