use crate::{Error, Paths, generation, live_token, read_json, write_json};
use serde_json::json;
use std::{ffi::OsString, fs, os::unix::process::CommandExt, path::Path, process::Command};

pub(super) fn check(paths: &Paths) -> Result<i32, Error> {
    let current = generation(paths)?;
    let entries = match fs::read_dir(&paths.records) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("stopped");
            return Ok(0);
        }
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let record = match read_json(&path, 4096) {
            Ok(record) => record,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let pid = record["pid"]
            .as_i64()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("invalid observed command PID; command state is unknown")?;
        if record["generation"].as_str().is_none_or(str::is_empty)
            || record["token"].as_str().is_none_or(str::is_empty)
        {
            return Err("invalid observed command identity; command state is unknown".into());
        }
        if record["generation"].as_str() == Some(&current)
            && let Some(token) = live_token(pid)?
            && record["token"].as_str() == Some(&token)
        {
            println!("running");
            return Ok(0);
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {} // Another check retired the same stale record.
            Err(error) => return Err(error.into()),
        }
    }
    println!("stopped");
    Ok(0)
}

pub(super) fn exec(paths: &Paths, arguments: &[OsString]) -> Result<i32, Error> {
    let pid = std::process::id() as i32;
    let record = paths.records.join(format!("{pid}.json"));
    write_json(
        &record,
        &json!({"pid":pid, "token":live_token(pid)?.ok_or("cannot identify observed process")?, "generation":generation(paths)?,
            "launch_id":std::env::var("SAFEYOLO_GUEST_LAUNCH_ID").ok()}),
    )?;
    let error = Command::new(&arguments[0]).args(&arguments[1..]).exec();
    let error = if error.raw_os_error() == Some(libc::ENOEXEC) {
        // Preserve executable custom scripts that have no shebang.
        Command::new("/bin/bash").args(arguments).exec()
    } else {
        error
    };
    fs::remove_file(record)?;
    Err(format!(
        "cannot execute configured command {}: {error}",
        Path::new(&arguments[0]).display()
    )
    .into())
}

/// Stop only this run's recorded coding command. The pidfd pins the process
/// across signal delivery; a reused PID or another launch is never accepted.
pub(super) fn stop(paths: &Paths, expected_generation: &str, launch: &str) -> Result<i32, Error> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    if generation(paths)? != expected_generation || launch.is_empty() {
        return Err("coding-command run or launch identity changed".into());
    }
    let mut found = false;
    let entries = match fs::read_dir(&paths.records) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("no observation for this launch; harness stop is unverified".into());
        }
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let record = read_json(&path, 4096)?;
        if record["generation"] != expected_generation || record["launch_id"] != launch {
            continue;
        }
        found = true;
        let pid = record["pid"]
            .as_i64()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("invalid observed command PID")?;
        if live_token(pid)?.as_deref() != record["token"].as_str() {
            continue;
        }
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let process = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
        if generation(paths)? != expected_generation
            || live_token(pid)?.as_deref() != record["token"].as_str()
        {
            return Err("coding-command ownership changed before stop".into());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                process.as_raw_fd(),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while live_token(pid)?.as_deref() == record["token"].as_str() {
            if Instant::now() >= deadline {
                return Err("coding-command stop timed out; completion is unverified".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if !found {
        return Err("no observation for this launch; harness stop is unverified".into());
    }
    println!("stopped");
    Ok(0)
}
