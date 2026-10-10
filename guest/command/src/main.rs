//! Linux guest command operations. PID 1 owns the supervisor; the host owns boot inputs.

mod lab_evidence;
mod observation;
mod probe;
mod supervision;

use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn version() -> String {
    format!(
        "safeyolo-guest {} commit={} profile={}",
        env!("CARGO_PKG_VERSION"),
        env!("SAFEYOLO_BUILD_REVISION"),
        env!("SAFEYOLO_BUILD_PROFILE")
    )
}

struct Paths {
    context: PathBuf,
    records: PathBuf,
    state: PathBuf,
    stop: PathBuf,
    workspace: PathBuf,
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |time| time.as_secs_f64())
}

fn read_json(path: &Path, limit: u64) -> Result<Value, Error> {
    let mut data = Vec::new();
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(format!("{} is not a regular state file", path.display()).into());
    }
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(format!("{} exceeds the state size limit", path.display()).into());
    }
    Ok(serde_json::from_slice(&data)?)
}

fn write_json(path: &Path, value: &Value) -> Result<(), Error> {
    let parent = path.parent().ok_or("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}

fn generation(paths: &Paths) -> Result<String, Error> {
    read_json(&paths.context, 128 * 1024)?["generation"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "host launch context has no current-run generation".into())
}

fn process_stat_read(result: std::io::Result<Vec<u8>>) -> std::io::Result<Option<Vec<u8>>> {
    match result {
        Ok(stat) => Ok(Some(stat)),
        // A PID can disappear after /proc/PID/stat opens but before it reads.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

// Linux comm can contain spaces and parentheses. Split after its final ')'.
fn process(pid: i32) -> Result<Option<(String, char, i32)>, Error> {
    if pid <= 0 {
        return Ok(None);
    }
    let Some(stat) = process_stat_read(fs::read(format!("/proc/{pid}/stat")))? else {
        return Ok(None);
    };
    // comm also permits non-UTF-8 filename bytes. Only the numeric suffix
    // belongs to the process identity; do not decode the name.
    let fields = std::str::from_utf8(
        stat.rsplit(|byte| *byte == b')')
            .next()
            .ok_or("invalid process stat")?,
    )?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let start = fields.get(19).ok_or("process start time is missing")?;
    let state = fields
        .first()
        .and_then(|value| value.chars().next())
        .ok_or("process state is missing")?;
    let group = fields.get(2).ok_or("process group is missing")?.parse()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(Some((format!("{}:{start}", boot.trim()), state, group)))
}

fn live_token(pid: i32) -> Result<Option<String>, Error> {
    Ok(process(pid)?
        .filter(|(_, state, _)| !matches!(state, 'Z' | 'X'))
        .map(|(token, _, _)| token))
}

fn command_paths(
    args: &mut Vec<OsString>,
    state: Option<OsString>,
    stop: Option<OsString>,
) -> Result<Paths, Error> {
    let mut paths = Paths {
        context: "/safeyolo/host-launch-context.json".into(),
        records: "/safeyolo-status/guest-commands".into(),
        state: state
            .map(PathBuf::from)
            .unwrap_or_else(|| "/home/agent/.safeyolo-command-supervisor.json".into()),
        stop: stop
            .map(PathBuf::from)
            .unwrap_or_else(|| "/home/agent/.safeyolo-command-supervisor.stop".into()),
        workspace: "/workspace".into(),
    };
    while args.first().is_some_and(|arg| {
        matches!(
            arg.to_str(),
            Some("--context" | "--records" | "--state" | "--stop" | "--workspace")
        )
    }) {
        if args.len() < 2 {
            return Err("path option requires a value".into());
        }
        let value = PathBuf::from(args.remove(1));
        match args.remove(0).to_str() {
            Some("--context") => paths.context = value,
            Some("--records") => paths.records = value,
            Some("--state") => paths.state = value,
            Some("--stop") => paths.stop = value,
            Some("--workspace") => paths.workspace = value,
            _ => unreachable!(),
        }
    }
    Ok(paths)
}

fn run() -> Result<i32, Error> {
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let paths = command_paths(
        &mut args,
        std::env::var_os("SAFEYOLO_COMMAND_SUPERVISOR_STATE"),
        std::env::var_os("SAFEYOLO_COMMAND_SUPERVISOR_STOP"),
    )?;
    match args.as_slice() {
        [version] if version == "--version" => {
            println!("{}", self::version());
            Ok(0)
        }
        [help] if help == "--help" => {
            println!(
                "safeyolo-guest [--context FILE] [--records DIR] [--state FILE] [--stop FILE] [--workspace DIR] observe check | observe exec -- PROGRAM [ARGS] | supervise [check] | probe ID [--ssh-port PORT] | lab-evidence capture --output DIR [--socket PATH] [--pane ID] [--file PATH] | lab-evidence redact [--check-text FILE | INPUT OUTPUT]\nGuest-only Linux executable. PID 1 launches supervise as the agent user. The host publishes command state in the shared home."
            );
            Ok(0)
        }
        [lab, rest @ ..] if lab == "lab-evidence" => lab_evidence::run(rest),
        [observe, check] if observe == "observe" && check == "check" => observation::check(&paths),
        [observe, exec, separator, command @ ..]
            if observe == "observe"
                && exec == "exec"
                && separator == "--"
                && !command.is_empty() =>
        {
            observation::exec(&paths, command)
        }
        [supervise] if supervise == "supervise" => supervision::run(&paths),
        [supervise, check] if supervise == "supervise" && check == "check" => {
            supervision::check(&paths)
        }
        [probe, id] if probe == "probe" => probe::run(
            &paths,
            id.to_str().ok_or("probe ID must be hexadecimal text")?,
            22,
        ),
        [probe, id, option, port] if probe == "probe" && option == "--ssh-port" => probe::run(
            &paths,
            id.to_str().ok_or("probe ID must be hexadecimal text")?,
            port.to_str()
                .ok_or("SSH port must be numeric text")?
                .parse()?,
        ),
        _ => Err("usage: safeyolo-guest --help".into()),
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("safeyolo-guest: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod process_stat_tests {
    use super::process_stat_read;
    use std::io;

    #[test]
    fn process_stat_disappearance_is_absent_but_other_read_errors_are_preserved() {
        for errno in [libc::ENOENT, libc::ESRCH] {
            assert!(
                process_stat_read(Err(io::Error::from_raw_os_error(errno)))
                    .unwrap()
                    .is_none()
            );
        }
        for errno in [libc::EACCES, libc::EPERM, libc::EIO, libc::EINVAL] {
            assert_eq!(
                process_stat_read(Err(io::Error::from_raw_os_error(errno)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(errno)
            );
        }
        let invalid = io::Error::new(io::ErrorKind::InvalidData, "invalid process stat");
        assert_eq!(
            process_stat_read(Err(invalid)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let stat = b"unchanged stat bytes".to_vec();
        assert_eq!(process_stat_read(Ok(stat.clone())).unwrap(), Some(stat));
    }
}
