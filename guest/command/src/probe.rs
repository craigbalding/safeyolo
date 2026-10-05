use crate::{Error, Paths, write_json};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

fn ssh_banner(port: u16) -> Value {
    let deadline = Instant::now() + Duration::from_secs(1);
    let result = (|| -> Result<Value, Error> {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let mut socket = TcpStream::connect_timeout(
            &address,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        let mut raw = Vec::new();
        while raw.len() < 256 && raw.last() != Some(&b'\n') {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("SSH banner deadline expired".into());
            }
            socket.set_read_timeout(Some(remaining))?;
            let mut byte = [0];
            if socket.read(&mut byte)? == 0 {
                break;
            }
            raw.push(byte[0]);
        }
        Ok(
            json!({"received":raw.starts_with(b"SSH-2.0-") && raw.ends_with(b"\n"), "banner":String::from_utf8_lossy(&raw).trim_end()}),
        )
    })();
    result.unwrap_or_else(|error| json!({"received":false, "error":error.to_string().chars().take(256).collect::<String>()}))
}

fn processes() -> Result<Value, Error> {
    let names = [
        "sshd",
        "socat",
        "guest-shell-bri",
        "guest-proxy-bri",
        "vsock-term",
        "tmux: server",
    ];
    let mut found = Vec::new();
    let mut inspected = 0;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        inspected += 1;
        if inspected > 4096 || found.len() == 64 {
            return Ok(json!({"matches":found,"truncated":true}));
        }
        let comm = match fs::read_to_string(entry.path().join("comm")) {
            Ok(comm) => comm,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            } // Exited or inaccessible processes cannot supply this diagnostic.
            Err(error) => return Err(error.into()),
        };
        if names.contains(&comm.trim()) {
            found.push(json!({"pid":pid,"comm":comm.trim()}));
        }
    }
    Ok(json!({"matches":found,"truncated":false}))
}

pub(super) fn run(paths: &Paths, id: &str, port: u16) -> Result<i32, Error> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("probe ID must have 32 hexadecimal characters".into());
    }
    unsafe {
        libc::alarm(8);
    }
    let mut result = json!({"probe_id":id,"uid":unsafe {libc::getuid()},"pid":std::process::id()});
    result["processes"] = processes()?;
    result["sshd_loopback"] = ssh_banner(port);
    // Fence this one-shot command before exit. Block TERM only for this bounded
    // final publication so the stop watcher cannot destroy a complete result.
    unsafe {
        let mut signals = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGTERM);
        if libc::sigprocmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        libc::alarm(1);
    }
    let mut stderr = std::io::stderr().lock();
    serde_json::to_writer(&mut stderr, &result)?;
    stderr.write_all(b"\n")?;
    stderr.flush()?;
    write_json(&paths.stop, &json!({"probe_id":id}))?;
    Ok(0)
}
