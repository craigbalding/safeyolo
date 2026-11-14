//! One process owns one fresh VM. Caller and helper enforce the same deadline.
//! No provider credentials, ambient filesystem, sockets or snapshot are donated.

use hyperlight_unikraft::{Mount, SandboxBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    engine: String,
    artifact: PathBuf,
    input: PathBuf,
    argv: Vec<String>,
    memory_mb: usize,
    max_input_bytes: u64,
    rootfs: Option<PathBuf>,
    function: Option<String>,
    parent_pid: u32,
    deadline_monotonic_ms: u64,
    service_bridge: Option<PathBuf>,
}

/// The guest gets neither this private socket path nor gateway credentials.
#[derive(Clone)]
struct ServiceBridge {
    path: Option<PathBuf>,
    deadline: u64,
}
impl ServiceBridge {
    fn call(&self, message: &str) -> Result<String, Error> {
        const LIMIT: usize = 48 * 1024;
        if message.len() > LIMIT {
            return Err("host-call message limit exceeded".into());
        }
        let path = self
            .path
            .as_ref()
            .ok_or("mediated service access is unavailable")?;
        let remaining = self
            .deadline
            .checked_sub(monotonic_ms()?)
            .filter(|value| *value > 0)
            .ok_or("host-call deadline exceeded")?;
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_millis(remaining)))?;
        stream.set_write_timeout(Some(Duration::from_millis(remaining)))?;
        stream.write_all(&u32::try_from(message.len())?.to_be_bytes())?;
        stream.write_all(message.as_bytes())?;
        let mut size = [0; 4];
        stream.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size) as usize;
        if size > LIMIT {
            return Err("host-call reply limit exceeded".into());
        }
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    }
}

fn service_bridge(request: &Invocation) -> ServiceBridge {
    ServiceBridge {
        path: request.service_bridge.clone(),
        deadline: request.deadline_monotonic_ms,
    }
}

#[derive(Serialize)]
struct Report {
    /// This is library-observed VM completion, never a host OS process status.
    completion: Option<Value>,
    error: Option<String>,
}

fn monotonic_ms() -> io::Result<u64> {
    let mut time = std::mem::MaybeUninit::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let time = unsafe { time.assume_init() };
    Ok(time.tv_sec as u64 * 1000 + time.tv_nsec as u64 / 1_000_000)
}

fn guard_lifetime(parent: u32, deadline: u64) -> io::Result<()> {
    // This guard does not call guest code, take VM locks or run destructors.
    // It bounds spinning vCPUs and synchronous callbacks even if the caller
    // disappears or its async executor stops making progress.
    std::thread::Builder::new()
        .name("job-deadline".into())
        .spawn(move || {
            loop {
                let code = if unsafe { libc::getppid() } as u32 != parent {
                    Some(125)
                } else {
                    match monotonic_ms() {
                        Ok(now) if now < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(
                                (deadline - now).min(100),
                            ));
                            None
                        }
                        Ok(_) => Some(124),
                        Err(_) => Some(125),
                    }
                };
                if let Some(code) = code {
                    unsafe {
                        libc::_exit(code);
                    }
                }
            }
        })?;
    Ok(())
}

fn core(request: &Invocation) -> Result<Value, Error> {
    let directory =
        cap_std::fs::Dir::open_ambient_dir(&request.input, cap_std::ambient_authority())?;
    let limit = request.max_input_bytes;
    let bridge = service_bridge(request);
    let mut sandbox = hyperlight_host::SandboxBuilder::from_file(&request.artifact)
        // Core defaults to 4 KiB transport buffers. Size both directions and
        // their pools for the shared 48 KiB messages plus ABI framing. Unikraft
        // sizes its own pools for the corresponding supported host-call ABI.
        .g2h_buffer_size(64 * 1024)
        .h2g_buffer_size(64 * 1024)
        .g2h_pool_pages(36)
        .h2g_pool_pages(18)
        .scratch_size(
            request
                .memory_mb
                .checked_mul(1024 * 1024)
                .ok_or("memory size overflow")?,
        )
        .host_print(|text: String| -> hyperlight_host::Result<i32> {
            io::stdout().write_all(text.as_bytes())?;
            i32::try_from(text.len()).map_err(|_| {
                hyperlight_host::HyperlightError::Error("print length overflow".into())
            })
        })
        .host_function(
            "SYCall",
            move |message: String| -> hyperlight_host::Result<String> {
                bridge
                    .call(&message)
                    .map_err(|error| hyperlight_host::HyperlightError::Error(error.to_string()))
            },
        )
        .host_function(
            "ReadInput",
            move |path: String| -> hyperlight_host::Result<Vec<u8>> {
                let file = directory.open(path)?;
                if !file.metadata()?.is_file() {
                    return Err(hyperlight_host::HyperlightError::Error(
                        "input is not a regular file".into(),
                    ));
                }
                let mut bytes = Vec::new();
                file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > limit {
                    return Err(hyperlight_host::HyperlightError::Error(
                        "ReadInput exceeds max_input_bytes".into(),
                    ));
                }
                Ok(bytes)
            },
        )
        .build()?;
    // The ABI has a bounded message transport. Oversize arguments fail in the
    // library; there is no truncation into a different request.
    let returned: String = sandbox.call(
        request
            .function
            .as_deref()
            .ok_or("core job needs a function")?,
        serde_json::to_string(&request.argv)?,
    )?;
    io::stdout().write_all(returned.as_bytes())?;
    drop(sandbox);
    Ok(json!({"kind":"guest_function_returned"}))
}

fn unikraft(request: &Invocation) -> Result<Value, Error> {
    let bridge = service_bridge(request);
    let checker = request.artifact.parent().ok_or("checker has no parent")?;
    let file = request
        .artifact
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("checker name is not UTF-8")?;
    let mut sandbox = SandboxBuilder::from_initrd(
        request
            .rootfs
            .as_ref()
            .ok_or("Unikraft job needs a rootfs")?,
    )
    .scratch_mb(request.memory_mb)
    .mount(Mount::ro(&request.input, "/input"))
    .mount(Mount::ro(checker, "/checker"))
    // Do not enable .network() or .listen_ports(): no socket passthrough.
    .host_function("sy.call", move |args| {
        let [message]: [Value; 1] =
            serde_json::from_str(args).map_err(|error| error.to_string())?;
        bridge
            .call(&message.to_string())
            .map_err(|error| error.to_string())
    })
    // Forward every console write to pipes drained by the job caller.
    // The library decodes UTF-8; results identify that stream encoding.
    .output_limit(0)
    .boot()?;
    // JSON strings are valid Python string literals except JSON's boolean/null
    // values, which occur only inside the JSON loaded at runtime here.
    let argv = serde_json::to_string(&serde_json::to_string(&request.argv)?)?;
    let script = serde_json::to_string(&format!("/checker/{file}"))?;
    let code = format!(
        "import os,sys,json,runpy\nos.makedirs('/work',exist_ok=True)\nos.chdir('/work')\nsys.argv=json.loads({argv})\nrunpy.run_path({script},run_name='__main__')"
    );
    sandbox.run(code)?;
    drop(sandbox);
    Ok(json!({"kind":"guest_call_completed","reported_status":0}))
}

fn identity() -> Value {
    json!({"protocol":3,"hyperlight":"0.19.0","unikraft":"0.21.0",
        "kernel_contract":hyperlight_unikraft::SNAPSHOT_KEY,
        "os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "virtualization":if cfg!(target_os="macos") { "hvf" } else { "kvm" }})
}

fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--identity"] {
        println!("{}", identity());
        return Ok(());
    }
    if args == ["--discover"] {
        if !hyperlight_host::is_hypervisor_present() {
            return Err("Hyperlight requires accessible KVM on Linux or entitled HVF on Apple-silicon macOS".into());
        }
        println!("{}", identity());
        return Ok(());
    }
    let [invocation, report] = args.as_slice() else {
        return Err(
            "usage: safeyolo-hyperlight --identity | --discover | INVOCATION.json REPORT.json"
                .into(),
        );
    };
    let request: Invocation = serde_json::from_slice(&fs::read(invocation)?)?;
    guard_lifetime(request.parent_pid, request.deadline_monotonic_ms)?;
    let result = match request.engine.as_str() {
        "hyperlight" => core(&request),
        "hyperlight-unikraft" => unikraft(&request),
        _ => Err("unknown Hyperlight engine".into()),
    };
    let (report_value, failed) = match result {
        Ok(completion) => (
            Report {
                completion: Some(completion),
                error: None,
            },
            false,
        ),
        Err(error) => (
            Report {
                completion: None,
                error: Some(error.to_string()),
            },
            true,
        ),
    };
    // This path is private to the host; the guest has no mount or host call
    // that can reach it. Writing after VM disposal also records cleanup order.
    fs::write(Path::new(report), serde_json::to_vec(&report_value)?)?;
    io::stdout().flush()?;
    io::stderr().flush()?;
    if failed {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::net::UnixListener,
        process::Command,
        time::{Duration, Instant},
    };

    #[test]
    fn callback_messages_are_framed_and_oversized_replies_fail_before_allocation() {
        for (name, reply_size, succeeds) in [("small", 2u32, true), ("large", 48 * 1024 + 1, false)]
        {
            let path =
                std::env::temp_dir().join(format!("sy-call-{}-{name}.sock", std::process::id()));
            let listener = UnixListener::bind(&path).unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut size = [0; 4];
                stream.read_exact(&mut size).unwrap();
                let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
                stream.read_exact(&mut bytes).unwrap();
                assert_eq!(bytes, b"{}");
                stream.write_all(&reply_size.to_be_bytes()).unwrap();
                if succeeds {
                    stream.write_all(b"{}").unwrap();
                }
            });
            let bridge = ServiceBridge {
                path: Some(path.clone()),
                deadline: monotonic_ms().unwrap() + 2000,
            };
            let result = bridge.call("{}");
            assert_eq!(result.is_ok(), succeeds);
            if succeeds {
                assert_eq!(result.unwrap(), "{}");
            }
            worker.join().unwrap();
            fs::remove_file(path).unwrap();
        }
        let unavailable = ServiceBridge {
            path: None,
            deadline: monotonic_ms().unwrap() + 2000,
        };
        assert!(
            unavailable
                .call("{}")
                .unwrap_err()
                .to_string()
                .contains("unavailable")
        );
        assert!(
            unavailable
                .call(&"a".repeat(48 * 1024 + 1))
                .unwrap_err()
                .to_string()
                .contains("limit exceeded")
        );
    }

    // Each child deliberately stops cooperating with the main thread. The
    // real guard must terminate the process; no hypervisor is needed here.
    #[test]
    #[ignore]
    fn lifetime_child() {
        let mode = std::env::var("SAFEYOLO_LIFETIME_TEST").unwrap();
        let parent = unsafe { libc::getppid() } as u32;
        guard_lifetime(
            if mode == "parent" { 0 } else { parent },
            monotonic_ms().unwrap() + 200,
        )
        .unwrap();
        loop {
            if mode == "spin" {
                std::hint::spin_loop();
            } else {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }

    #[test]
    fn independent_guard_stops_spinning_and_blocked_work_and_lost_parent() {
        for (mode, expected) in [("spin", 124), ("blocked", 124), ("parent", 125)] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::lifetime_child", "--ignored"])
                .env("SAFEYOLO_LIFETIME_TEST", mode)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let started = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if started.elapsed() > Duration::from_secs(3) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("independent guard did not stop {mode}");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(expected), "{mode}");
        }
    }
}
