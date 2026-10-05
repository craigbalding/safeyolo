use crate::{Error, Paths, generation, live_token, read_json, write_json};
use serde_json::json;
use std::{fs, os::unix::process::CommandExt, process::Command};

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

pub(super) fn exec(paths: &Paths, arguments: &[String]) -> Result<i32, Error> {
    let pid = std::process::id() as i32;
    let record = paths.records.join(format!("{pid}.json"));
    write_json(
        &record,
        &json!({"pid":pid, "token":live_token(pid)?.ok_or("cannot identify observed process")?, "generation":generation(paths)?}),
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
        arguments[0]
    )
    .into())
}
