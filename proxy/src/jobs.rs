//! Host-only disposable execution. JobSpec never contains a host mount path.

mod input;
#[cfg(target_os = "macos")]
mod macos;

use crate::{Error, host_platform, host_runs};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs, io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "linux")]
use std::{
    os::fd::AsRawFd,
    process::{ExitStatus, Stdio},
};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const HELP: &str = "safeyolo [--root ROOT] job run SPEC.json [--input DIRECTORY]\nRun fixed argv from a trusted host-supplied JSON spec in a disposable sandbox.\nOnly the host caller selects DIRECTORY. Inputs are copied without following symlinks and mounted read-only at /input.\n/work and /home/agent are transient. Jobs have no Agent API, Coord, harness or host-script authority.\nPrint observed execution evidence as JSON. A PASS string from a job is ordinary output.\nThe command returns 0 only for an observed exit 0, 124 for timeout, and 1 for other job outcomes.\nRuntime and evidence-collection errors return an error; they do not produce a successful job result.";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Privilege {
    #[default]
    Unprivileged,
    GuestRoot,
}

fn memory_mb() -> u64 {
    4096
}

/// The trusted broker owns the definition and the mapping from facts to a verdict.
/// In particular, gate_id is provenance, not a grant of gate capabilities.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub gate_id: String,
    pub argv: Vec<String>,
    pub timeout_seconds: u64,
    pub max_input_bytes: u64,
    pub max_input_entries: u64,
    pub retain_bytes: usize,
    #[serde(default = "memory_mb")]
    pub memory_mb: u64,
    #[serde(default)]
    pub privilege: Privilege,
}

impl JobSpec {
    fn validate(&self) -> Result<(), Error> {
        if self.gate_id.is_empty()
            || self.argv.is_empty()
            || self.argv[0].is_empty()
            || self.argv.iter().any(|arg| arg.contains('\0'))
            || self.timeout_seconds == 0
            || self.memory_mb == 0
        {
            return Err(
                "job needs a gate_id, executable argv, positive timeout_seconds and memory_mb"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Exit { code: i32 },
    Signal { number: i32 },
    Timeout,
    Interrupted { signal: i32 },
}

#[derive(Debug, Serialize)]
pub struct Output {
    pub bytes: u64,
    pub sha256: String,
    pub retained_base64: String,
}

#[derive(Debug, Serialize)]
pub struct JobResult {
    pub run_id: String,
    pub gate_id: String,
    pub gate_definition_sha256: String,
    /// Stable provenance name. Credential delegation is not active in this mode.
    pub gate_principal: String,
    pub authorization_principal: Option<String>,
    pub rootfs: Value,
    pub input_sha256: String,
    pub started_unix_ms: u128,
    pub ended_unix_ms: u128,
    pub outcome: Outcome,
    pub stdout: Output,
    pub stderr: Output,
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&SHA256, bytes).as_ref())
}
fn now() -> Result<u128, Error> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

struct OutputCapture {
    hash: Context,
    retained: Vec<u8>,
    limit: usize,
    bytes: u64,
}

impl OutputCapture {
    fn new(limit: usize) -> Self {
        Self {
            hash: Context::new(&SHA256),
            retained: Vec::new(),
            limit,
            bytes: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("job output byte count overflow"))?;
        self.hash.update(bytes);
        let keep = bytes
            .len()
            .min(self.limit.saturating_sub(self.retained.len()));
        self.retained.extend_from_slice(&bytes[..keep]);
        Ok(())
    }

    fn finish(self) -> Output {
        Output {
            bytes: self.bytes,
            sha256: hex(self.hash.finish().as_ref()),
            retained_base64: STANDARD.encode(self.retained),
        }
    }
}

async fn collect(mut input: impl AsyncRead + Unpin, retained_limit: usize) -> io::Result<Output> {
    let mut capture = OutputCapture::new(retained_limit);
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        capture.write(&buffer[..count])?;
    }
    Ok(capture.finish())
}

#[cfg(target_os = "linux")]
fn process(spec: &JobSpec) -> Value {
    let root = spec.privilege == Privilege::GuestRoot;
    let caps = if root {
        vec![
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_NET_ADMIN",
            "CAP_MKNOD",
            "CAP_AUDIT_WRITE",
            "CAP_SETFCAP",
            "CAP_SYS_PTRACE",
        ]
    } else {
        vec![]
    };
    json!({"terminal":false,"user":{"uid":if root {0} else {1000},"gid":if root {0} else {1000},"additionalGids":[]},
        "args":spec.argv,"cwd":"/work","env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOME=/home/agent","USER=agent","LOGNAME=agent","LANG=C.UTF-8"],
        "capabilities":{"bounding":caps,"effective":caps,"permitted":caps,"inheritable":[],"ambient":[]},
        "noNewPrivileges":!root,"rlimits":[{"type":"RLIMIT_NOFILE","hard":65536,"soft":65536}]})
}

#[cfg(target_os = "linux")]
fn stage(
    root: &Path,
    directory: &Path,
    guest: &Path,
    spec: &JobSpec,
    generation: &str,
) -> Result<(), Error> {
    let lower = guest.join("rootfs-tree").canonicalize()?;
    let share = directory.join("config-share");
    fs::create_dir(&share)?;
    // The only host mounts are two read-only directories. Readiness is observed
    // through runsc, so even a guest-root job has no writable host status share.
    let bind = |source: PathBuf, target: &str| json!({"source":source,"destination":target,"type":"bind","options":["rbind","ro","nosuid","nodev"]});
    let mounts = vec![
        json!({"destination":"/proc","type":"proc","source":"proc"}),
        json!({"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","mode=755","size=65536k"]}),
        json!({"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]}),
        json!({"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=1777"]}),
        json!({"destination":"/home/agent","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=700","uid=1000","gid=1000"]}),
        bind(root.join("input"), "/workspace"),
        bind(share.clone(), "/safeyolo"),
    ];
    let mut init = process(spec);
    init["user"] = json!({"uid":0,"gid":0});
    init["args"] = json!(["/bin/bash", "/safeyolo/guest-init"]);
    init["cwd"] = "/".into();
    init["capabilities"] = process(&JobSpec {
        privilege: Privilege::GuestRoot,
        ..spec.clone()
    })["capabilities"]
        .clone();
    init["noNewPrivileges"] = false.into();
    let oci = json!({"ociVersion":"1.0.0","root":{"path":lower,"readonly":false},"process":init,"mounts":mounts,
        "linux":{"namespaces":[{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}]}});
    crate::guest_commands::write_json(&directory.join("config.json"), &oci)?;
    crate::guest_commands::write_json(&directory.join("process.json"), &process(spec))?;
    crate::guest_commands::write_json(&share.join("job.json"), &serde_json::to_value(spec)?)?;
    // Only incarnation data goes into the existing host runtime identity file.
    crate::guest_commands::write_json(
        &share.join("host-launch-context.json"),
        &json!({"generation":generation}),
    )?;
    fs::write(
        share.join("guest-init"),
        concat!(
            "#!/bin/bash\nset -euo pipefail\n",
            "mkdir -p /run /work /home/agent\n",
            "chown 1000:1000 /work /home/agent\n",
            "ln -s /workspace /input\n",
            "touch /run/job-ready\n",
            "exec /bin/sleep infinity\n",
        ),
    )?;
    fs::set_permissions(share.join("guest-init"), fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn raw_status(log: &Path, observed: ExitStatus) -> Result<Outcome, Error> {
    // Pinned runsc flattens signals to 128+signal in its CLI result. Its own
    // private exec log records the original Unix wait status before flattening.
    let mut status = None;
    for line in fs::read_to_string(log)?.lines() {
        let line: Value = serde_json::from_str(line)?;
        if line["level"] == "info"
            && let Some(message) = line.get("msg").and_then(Value::as_str)
            && let Some(raw) = message.strip_prefix("cli.go:317] Exiting with status: ")
        {
            if status.is_some() {
                return Err("runsc returned duplicate job wait status".into());
            }
            let raw: i32 = raw.parse()?;
            if !(0..=65535).contains(&raw) {
                return Err("runsc job wait status is out of range".into());
            }
            let value = if libc::WIFEXITED(raw) {
                Outcome::Exit {
                    code: libc::WEXITSTATUS(raw),
                }
            } else if libc::WIFSIGNALED(raw) {
                Outcome::Signal {
                    number: libc::WTERMSIG(raw),
                }
            } else {
                return Err("runsc job wait status was not terminal".into());
            };
            let code = match value {
                Outcome::Exit { code } => code,
                Outcome::Signal { number } => 128 + number,
                _ => unreachable!(),
            };
            if observed.code() != Some(code) {
                return Err("runsc job wait status differs from observed transport exit".into());
            }
            status = Some(value);
        }
    }
    status.ok_or_else(|| "runsc did not report an observed job wait status".into())
}

#[cfg(target_os = "linux")]
async fn rootfs(name: &str, guest: &Path) -> Result<Value, Error> {
    // Read the actual shared lower tree through the existing mapped namespace.
    // The host hashes the archive stream, including modes, owners and links.
    let mut child = host_platform::userns_command(name, "tar")?
        .args([
            "--sort=name",
            "--numeric-owner",
            "--format=gnu",
            "-cf",
            "-",
            "-C",
        ])
        .arg(guest.join("rootfs-tree"))
        .arg(".")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let output = child.stdout.take().ok_or("missing rootfs hash stream")?;
    let (status, output) = tokio::try_join!(child.wait(), collect(output, 0))?;
    if !status.success() {
        return Err("could not hash the actual shared job rootfs".into());
    }
    Ok(
        json!({"profile":"shared","kind":"gnu-tar-numeric-sorted","sha256":output.sha256,"bytes":output.bytes}),
    )
}

#[cfg(target_os = "linux")]
fn spawn(name: &str, directory: &Path) -> Result<tokio::process::Child, Error> {
    use std::os::unix::process::CommandExt;
    let log = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("exec.jsonl"))?;
    let mut command = host_platform::runsc_command(name)?;
    command
        .arg(format!("--debug-log-fd={}", log.as_raw_fd()))
        .arg("--debug-log-format=json")
        .arg("exec")
        .arg("--process")
        .arg(directory.join("process.json"))
        .arg(host_runs::id(name)?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // The mapped runtime receives a host-opened log descriptor. It cannot
    // otherwise create the log in the caller-owned runtime directory.
    // runsc donates only stdio to the guest, so this descriptor stays private.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::fcntl(log.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command.spawn()?)
}

/// This entry point is host-only. The Agent API does not expose job creation.
pub async fn run(config: &Path, spec: &JobSpec, input: Option<&Path>) -> Result<JobResult, Error> {
    spec.validate()?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let config = config.canonicalize()?;
    let installation = config.parent().ok_or("job instance config has no parent")?;
    let (host, guest) = crate::guest_acquisition::selected_boot_inputs(installation)?;
    // Runtime state is transient, but disk-backed so large input copies do not
    // consume the caller's /tmp memory. No durable job or agent record is added.
    #[cfg(not(target_os = "macos"))]
    let parent = installation.join("data");
    // VZ control/shell UDS paths have a 104-byte limit. Keep the disposable
    // root on disk at a short OS-owned path, independent of instance length.
    #[cfg(target_os = "macos")]
    let parent = PathBuf::from("/private/var/tmp");
    fs::create_dir_all(&parent)?;
    let temporary = tempfile::Builder::new()
        .prefix("job-")
        .tempdir_in(&parent)?;
    let root = temporary.path().to_owned();
    #[cfg(target_os = "linux")]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    for (source, destination) in [
        (host.join("bin"), "bin"),
        (host.join("libexec"), "libexec"),
        (host.join("package-info"), "package-info"),
        (host.join("SHA256SUMS"), "SHA256SUMS"),
        (installation.join("host"), "host"),
    ] {
        symlink(source, root.join(destination))?;
    }
    symlink(&config, root.join("config.toml"))?;
    let input_sha256 = input::copy(
        input,
        &root.join("input"),
        spec.max_input_bytes,
        spec.max_input_entries,
    )?;
    let generation = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("job-{generation}");
    let directory = root.join("agents").join(&name);
    fs::create_dir_all(&directory)?;
    let started_unix_ms = now()?;
    let mut cleanup_failed = false;
    let result: Result<(Value, Outcome, Output, Output), Error> = host_platform::in_config(root.join("config.toml"), async {
        #[cfg(target_os = "linux")]
        {
            stage(&root, &directory, &guest, spec, &generation)?;
            host_runs::save(&name, &json!({"name":name,"agent_id":name,"run_id":generation,"state":"starting"}))?;
            let mut child = None;
            let mut stdout = None;
            let mut stderr = None;
            let work = async {
                host_platform::start_job_sandbox(&name, spec.memory_mb).await?;
                let rootfs = rootfs(&name, &guest).await?;
                let mut command = spawn(&name, &directory)?;
                let output = command.stdout.take().ok_or("job stdout pipe is missing")?;
                let errors = command.stderr.take().ok_or("job stderr pipe is missing")?;
                stdout = Some(tokio::spawn(collect(output, spec.retain_bytes)));
                stderr = Some(tokio::spawn(collect(errors, spec.retain_bytes)));
                child = Some(command);
                let status = child.as_mut().unwrap();
                let outcome = tokio::select! {
                    status = status.wait() => raw_status(&directory.join("exec.jsonl"), status?)?,
                    _ = tokio::time::sleep(Duration::from_secs(spec.timeout_seconds)) => Outcome::Timeout,
                    _ = interrupt.recv() => Outcome::Interrupted { signal:libc::SIGINT },
                    _ = terminate.recv() => Outcome::Interrupted { signal:libc::SIGTERM },
                };
                Ok::<_, Error>((rootfs, outcome))
            };
            let result = work.await;
            let cleanup = host_platform::stop_sandbox(&name).await;
            if let Err(error) = cleanup {
                cleanup_failed = true;
                return Err(format!("job cleanup failed: {error}; runtime preserved at {}", root.display()).into());
            }
            // Teardown also closes pipes inherited by background descendants.
            // Only then can EOF establish a complete byte count and digest.
            if let Some(mut child) = child {
                child.kill().await.or_else(|error| if error.kind() == io::ErrorKind::InvalidInput { Ok(()) } else { Err(error) })?;
                child.wait().await?;
            }
            let (rootfs, outcome) = result?;
            let stdout = tokio::time::timeout(Duration::from_secs(5), stdout.ok_or("missing job stdout collector")?).await???;
            let stderr = tokio::time::timeout(Duration::from_secs(5), stderr.ok_or("missing job stderr collector")?).await???;
            Ok((rootfs, outcome, stdout, stderr))
        }
        #[cfg(target_os = "macos")]
        {
            macos::run(&name, &root, &directory, &host, &guest, spec, &generation,
                &mut interrupt, &mut terminate, &mut cleanup_failed).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { let _ = (host, guest); Err::<(Value, Outcome, Output, Output), Error>("jobs require Linux or macOS".into()) }
    }).await;
    // Never erase the only remaining verified handles after a cleanup failure.
    let (rootfs, outcome, stdout, stderr) = match result {
        Ok(result) => result,
        Err(error) => {
            if cleanup_failed {
                let _ = temporary.keep();
            }
            return Err(error);
        }
    };
    Ok(JobResult {
        run_id: name,
        gate_id: spec.gate_id.clone(),
        gate_definition_sha256: digest(&serde_json::to_vec(spec)?),
        gate_principal: format!("gate:{}", spec.gate_id),
        authorization_principal: None,
        rootfs,
        input_sha256,
        started_unix_ms,
        ended_unix_ms: now()?,
        outcome,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> JobSpec {
        serde_json::from_value(
            json!({"gate_id":"test", "argv":["/bin/true"], "timeout_seconds":5,
            "max_input_bytes":1024,"max_input_entries":100,"retain_bytes":16}),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn retained_output_is_bounded_while_digest_and_count_cover_every_byte() {
        let bytes: Vec<u8> = (0..100_000).map(|n| (n % 256) as u8).collect();
        for limit in [0, 1, 17, bytes.len() + 1] {
            let result = collect(bytes.as_slice(), limit).await.unwrap();
            assert_eq!(result.bytes, bytes.len() as u64);
            assert_eq!(result.sha256, digest(&bytes));
            assert_eq!(
                STANDARD.decode(result.retained_base64).unwrap(),
                bytes[..limit.min(bytes.len())]
            );
        }
    }

    #[test]
    fn spec_does_not_accept_mounts_or_implicit_authority() {
        for field in [
            "mounts",
            "input",
            "agent_id",
            "authorization_principal",
            "host_script",
            "agent_api",
        ] {
            let mut value = serde_json::to_value(spec()).unwrap();
            value[field] = json!("/etc");
            assert!(serde_json::from_value::<JobSpec>(value).is_err(), "{field}");
        }
        assert_eq!(spec().privilege, Privilege::Unprivileged);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_process_cannot_reacquire_guest_root() {
        let default_process = process(&spec());
        assert_eq!(
            default_process["user"],
            json!({"uid":1000,"gid":1000,"additionalGids":[]})
        );
        assert_eq!(default_process["noNewPrivileges"], true);
        for set in [
            "bounding",
            "effective",
            "permitted",
            "inheritable",
            "ambient",
        ] {
            assert_eq!(default_process["capabilities"][set], json!([]));
        }
        let root = process(&JobSpec {
            privilege: Privilege::GuestRoot,
            ..spec()
        });
        assert_eq!(root["user"]["uid"], 0);
        assert_eq!(root["noNewPrivileges"], false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn raw_wait_status_distinguishes_high_exit_code_and_signal_and_refuses_missing_evidence() {
        use std::os::unix::process::ExitStatusExt;
        let root = tempfile::tempdir().unwrap();
        let log = root.path().join("exec.jsonl");
        for (raw, expected) in [
            (139 << 8, Outcome::Exit { code: 139 }),
            (
                libc::SIGSEGV,
                Outcome::Signal {
                    number: libc::SIGSEGV,
                },
            ),
        ] {
            fs::write(
                &log,
                format!(
                    "{}\n",
                    json!({"level":"info","msg":format!("cli.go:317] Exiting with status: {raw}")})
                ),
            )
            .unwrap();
            assert_eq!(
                raw_status(&log, ExitStatus::from_raw(139 << 8)).unwrap(),
                expected
            );
        }
        for data in [
            "",
            "not json",
            "{\"level\":\"info\",\"msg\":\"cli.go:317] Exiting with status: nope\"}",
            "{\"level\":\"info\",\"msg\":\"cli.go:317] Exiting with status: 0\"}\n{\"level\":\"info\",\"msg\":\"cli.go:317] Exiting with status: 0\"}",
        ] {
            fs::write(&log, data).unwrap();
            assert!(raw_status(&log, ExitStatus::from_raw(0)).is_err(), "{data}");
        }
        fs::write(
            &log,
            json!({"level":"info","msg":"cli.go:317] Exiting with status: 256"}).to_string(),
        )
        .unwrap();
        assert!(raw_status(&log, ExitStatus::from_raw(0)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_job_has_no_writable_host_mount_or_agent_payload() {
        let root = tempfile::tempdir().unwrap();
        let guest = root.path().join("guest");
        let directory = root.path().join("runtime");
        fs::create_dir_all(guest.join("rootfs-tree")).unwrap();
        fs::create_dir(&directory).unwrap();
        stage(
            root.path(),
            &directory,
            &guest,
            &spec(),
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let oci: Value =
            serde_json::from_slice(&fs::read(directory.join("config.json")).unwrap()).unwrap();
        for mount in oci["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|mount| mount["type"] == "bind")
        {
            assert!(mount["options"].as_array().unwrap().contains(&json!("ro")));
        }
        let mut files: Vec<_> = fs::read_dir(directory.join("config-share"))
            .unwrap()
            .map(|file| file.unwrap().file_name())
            .collect();
        files.sort();
        assert_eq!(
            files,
            ["guest-init", "host-launch-context.json", "job.json"]
        );
    }
}

pub async fn command(config: &Path, args: &[String]) -> Result<i32, Error> {
    if args == ["--help"] {
        println!("{HELP}");
        return Ok(0);
    }
    let (spec, input) = match args {
        [run, spec] if run == "run" => (spec, None),
        [run, spec, flag, input] if run == "run" && flag == "--input" => {
            (spec, Some(Path::new(input)))
        }
        _ => return Err(HELP.into()),
    };
    let spec: JobSpec = serde_json::from_slice(&fs::read(spec)?)?;
    let result = run(config, &spec, input).await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(match result.outcome {
        Outcome::Exit { code: 0 } => 0,
        Outcome::Timeout => 124,
        _ => 1,
    })
}
