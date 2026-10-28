//! One-shot execution over the existing private VZ UDS/vsock/SSH route.

use super::{
    Error, JobSpec, Outcome, Output, OutputCapture, collect, fs, host_platform, host_runs, json,
};
use russh::{
    ChannelMsg, Sig, client,
    keys::{self, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate},
};
use serde_json::Value;
use std::{os::unix::fs::PermissionsExt, path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{net::UnixStream, signal::unix::Signal};

struct PinnedServer(PublicKey);

impl client::Handler for PinnedServer {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.certificate().is_none() && key.public_key().key_data() == self.0.key_data())
    }
}

async fn key(path: &Path) -> Result<(), Error> {
    let status = tokio::process::Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await?;
    if !status.success() {
        return Err("could not generate transient job SSH key".into());
    }
    Ok(())
}

fn launcher(spec: &JobSpec) -> String {
    let mut script = include_str!("vz-exec.sh").to_owned();
    // Keep env's executable fixed, so an argv[0] containing '=' cannot become
    // another environment assignment. Every step execs without a wait wrapper.
    script.push_str("\nexec /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/home/agent USER=agent LOGNAME=agent LANG=C.UTF-8 ");
    if spec.privilege == super::Privilege::Unprivileged {
        script.push_str("/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs -- ");
    } else {
        script.push_str("/bin/bash -c 'exec -- \"$@\"' job ");
    }
    // Each JSON string is one literal shell argument, including empty strings,
    // newlines and shell syntax. No guest JSON parser or Python is required.
    for argument in &spec.argv {
        script.push('\'');
        script.push_str(&argument.replace('\'', "'\\''"));
        script.push_str("' ");
    }
    script.push('\n');
    script
}

async fn stage(
    root: &Path,
    directory: &Path,
    host: &Path,
    guest: &Path,
    spec: &JobSpec,
    generation: &str,
) -> Result<PublicKey, Error> {
    // Include the terminating NUL in the existing Darwin sockaddr_un bound.
    // Check before boot, so an authorized but long TMPDIR has a useful error.
    use std::os::unix::ffi::OsStrExt;
    for folder in ["shell-sockets", "vm-control"] {
        let socket = root
            .join("data")
            .join(folder)
            .join(format!("job-{generation}.sock"));
        if socket.as_os_str().as_bytes().len() + 1 > 104 {
            return Err(format!(
                "job socket path exceeds the 104-byte platform limit: {}; use a shorter TMPDIR",
                socket.display()
            )
            .into());
        }
    }
    let share = directory.join("config-share");
    fs::create_dir(&share)?;
    fs::create_dir_all(root.join("data"))?;
    key(&root.join("data/job-client-key")).await?;
    key(&share.join("job-host-key")).await?;
    fs::copy(
        root.join("data/job-client-key.pub"),
        share.join("authorized_keys"),
    )?;
    let public = PublicKey::from_openssh(&fs::read_to_string(share.join("job-host-key.pub"))?)?;
    crate::guest_commands::write_json(&share.join("job.json"), &serde_json::to_value(spec)?)?;
    crate::guest_commands::write_json(
        &share.join("host-launch-context.json"),
        &json!({
            "generation":generation, "workspace":root.join("input"),
            "guest_inputs":guest, "host_package":host,
        }),
    )?;
    fs::write(
        share.join("sshd_config"),
        concat!(
            "Port 22\nListenAddress 127.0.0.1\nAddressFamily inet\n",
            "HostKey /run/job-host-key\nAuthorizedKeysFile /run/job-authorized-keys\n",
            "StrictModes yes\nPermitRootLogin prohibit-password\nAllowUsers root\n",
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n",
            "AllowTcpForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTunnel no\nPermitTTY no\n",
            "MaxSessions 1\nLogLevel DEBUG1\nForceCommand exec /safeyolo/job-ssh-command\n",
        ),
    )?;
    fs::write(share.join("guest-init"), include_str!("vz-guest-init.sh"))?;
    fs::write(
        share.join("job-ssh-command"),
        concat!(
            "#!/bin/sh\nset -eu\ncase ${SSH_ORIGINAL_COMMAND-} in\n",
            "run-job) umask 077; set -C; printf '%s\\n' \"$$\" > /run/job-command.pid; exec /safeyolo/job-exec ;;\n",
            "read-job-wait) exec /bin/cat /run/job-command.pid /run/job-sshd.log ;;\n",
            "*) exit 1 ;;\nesac\n",
        ),
    )?;
    // Exec at each step preserves the command's own wait status in sshd.
    // Neither an agent request nor SSH command text selects what is executed.
    fs::write(share.join("job-exec"), launcher(spec))?;
    for name in ["guest-init", "job-exec", "job-ssh-command"] {
        fs::set_permissions(share.join(name), fs::Permissions::from_mode(0o755))?;
    }
    Ok(public)
}

async fn rootfs(guest: &Path) -> Result<Value, Error> {
    let mut artifacts = serde_json::Map::new();
    for name in ["rootfs-base.ext4", "Image", "initramfs.cpio.gz"] {
        let file = tokio::fs::File::open(guest.join(name)).await?;
        let output = collect(file, 0).await?;
        artifacts.insert(
            name.to_owned(),
            json!({"sha256":output.sha256,"bytes":output.bytes}),
        );
    }
    Ok(json!({"profile":"shared","kind":"vz-boot-artifacts",
        "sha256":artifacts["rootfs-base.ext4"]["sha256"],
        "bytes":artifacts["rootfs-base.ext4"]["bytes"],"artifacts":artifacts}))
}

async fn connect(
    root: &Path,
    name: &str,
    public: &PublicKey,
) -> Result<client::Handle<PinnedServer>, Error> {
    let socket = root.join("data/shell-sockets").join(format!("{name}.sock"));
    let config = Arc::new(client::Config::default());
    // The helper can expose its UDS before the guest SSH listener is ready.
    // Retries happen only before starting the command, never after execution.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let attempt = async {
            let stream = UnixStream::connect(&socket).await?;
            let mut session =
                client::connect_stream(config.clone(), stream, PinnedServer(public.clone()))
                    .await?;
            let private = keys::load_secret_key(root.join("data/job-client-key"), None)?;
            if !session
                .authenticate_publickey("root", PrivateKeyWithHashAlg::new(Arc::new(private), None))
                .await?
                .success()
            {
                return Err::<_, Error>("job SSH authentication failed".into());
            }
            Ok(session)
        };
        match tokio::time::timeout(Duration::from_secs(5), attempt).await {
            Ok(Ok(session)) => return Ok(session),
            _ if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            _ => return Err("job did not reach authenticated SSH readiness".into()),
        }
    }
}

fn signal_number(signal: Sig) -> Result<Option<i32>, Error> {
    // The guest is Linux even though this observer runs on macOS. In
    // particular, libc::SIGUSR1 on the host is not Linux SIGUSR1.
    Ok(Some(match signal {
        Sig::HUP => 1,
        Sig::INT => 2,
        Sig::QUIT => 3,
        Sig::ILL => 4,
        Sig::ABRT => 6,
        Sig::FPE => 8,
        Sig::KILL => 9,
        Sig::USR1 => 10,
        Sig::SEGV => 11,
        Sig::PIPE => 13,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        Sig::Custom(name) => match name.as_str() {
            "SIG@openssh.com" => return Ok(None),
            "TRAP" => 5,
            "BUS" => 7,
            "USR2" => 12,
            "STKFLT" => 16,
            "CHLD" => 17,
            "CONT" => 18,
            "STOP" => 19,
            "TSTP" => 20,
            "TTIN" => 21,
            "TTOU" => 22,
            "URG" => 23,
            "XCPU" => 24,
            "XFSZ" => 25,
            "VTALRM" => 26,
            "PROF" => 27,
            "WINCH" => 28,
            "IO" => 29,
            "PWR" => 30,
            "SYS" => 31,
            _ => return Err(format!("unrecognized guest SSH exit signal: {name}").into()),
        },
    }))
}

#[derive(Clone)]
enum SshExit {
    Exit(i32),
    Signal(Option<i32>),
}

struct Evidence {
    status: Option<SshExit>,
    invalid_status: bool,
    closed: bool,
    stdout: OutputCapture,
    stderr: OutputCapture,
}

impl Evidence {
    fn new(limit: usize) -> Self {
        Self {
            status: None,
            invalid_status: false,
            closed: false,
            stdout: OutputCapture::new(limit),
            stderr: OutputCapture::new(limit),
        }
    }

    fn event(&mut self, message: ChannelMsg) -> Result<(), Error> {
        if self.closed {
            return Err("job SSH data arrived after channel close".into());
        }
        let status = match message {
            ChannelMsg::Data { data } => {
                self.stdout.write(&data)?;
                None
            }
            ChannelMsg::ExtendedData { ext: 1, data } => {
                self.stderr.write(&data)?;
                None
            }
            ChannelMsg::ExtendedData { .. } => return Err("unknown job SSH output stream".into()),
            ChannelMsg::ExitStatus { exit_status } => {
                if exit_status > 255 {
                    return Err("job SSH exit status is outside the Linux process range".into());
                }
                Some(SshExit::Exit(exit_status as i32))
            }
            ChannelMsg::ExitSignal { signal_name, .. } => {
                Some(SshExit::Signal(signal_number(signal_name)?))
            }
            ChannelMsg::Failure => return Err("job SSH command request failed".into()),
            ChannelMsg::Close => {
                self.closed = true;
                None
            }
            _ => None,
        };
        if let Some(status) = status {
            self.invalid_status |= self.status.is_some();
            self.status = Some(status);
        }
        Ok(())
    }

    fn outcome(&self) -> Result<Outcome, Error> {
        if self.invalid_status || !self.closed {
            return Err("job SSH did not supply one complete observed wait result".into());
        }
        match self.status {
            Some(SshExit::Exit(code)) => Ok(Outcome::Exit { code }),
            Some(SshExit::Signal(Some(number))) => Ok(Outcome::Signal { number }),
            _ => Err("job SSH channel lacks an exact observed wait result".into()),
        }
    }

    fn verify(&self, observed: Outcome) -> Result<Outcome, Error> {
        if self.invalid_status || !self.closed {
            return Err("job SSH result is incomplete or duplicate".into());
        }
        let matches = match (&self.status, &observed) {
            (Some(SshExit::Exit(wire)), Outcome::Exit { code }) => wire == code,
            (Some(SshExit::Signal(Some(wire))), Outcome::Signal { number }) => wire == number,
            (Some(SshExit::Signal(None)), Outcome::Signal { .. }) => true,
            _ => false,
        };
        if !matches {
            return Err("protected SSH observer record differs from channel result".into());
        }
        Ok(observed)
    }

    fn resolve(&self, protected: Result<Outcome, Error>) -> (Option<Outcome>, Option<String>) {
        match protected.and_then(|outcome| self.verify(outcome)) {
            Ok(outcome) => (Some(outcome), None),
            // A failed metadata read must not erase a known channel result or
            // captured streams. The error prevents the broker from accepting it.
            Err(error) => (self.outcome().ok(), Some(error.to_string())),
        }
    }
}

#[derive(Default)]
struct ObserverLog {
    line: Vec<u8>,
    long_line: bool,
    command_pid: Option<u32>,
    result: Option<Outcome>,
}

impl ObserverLog {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for &byte in bytes {
            if byte == b'\n' {
                self.line()?;
                self.line.clear();
                self.long_line = false;
            } else if self.line.len() < 512 {
                self.line.push(byte);
            } else {
                self.long_line = true;
            }
        }
        Ok(())
    }

    fn line(&mut self) -> Result<(), Error> {
        if self.command_pid.is_none() {
            let pid: u32 = std::str::from_utf8(&self.line)?
                .trim_end_matches('\r')
                .parse()?;
            if self.long_line || pid == 0 {
                return Err("protected SSH observer omitted its command PID".into());
            }
            self.command_pid = Some(pid);
            return Ok(());
        }
        if self.long_line {
            return Ok(());
        }
        static RECORD: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let pattern = RECORD.get_or_init(|| regex::Regex::new(r"^debug1: session_exit_message: session [0-9]+ channel [0-9]+ pid ([1-9][0-9]*) (?:exit ([0-9]+)|signal ([0-9]+)(?: core dumped)?)(?: \[postauth\])?\r?$").unwrap());
        let Ok(line) = std::str::from_utf8(&self.line) else {
            return Ok(());
        };
        let Some(record) = pattern.captures(line) else {
            return Ok(());
        };
        if record[1].parse::<u32>()? != self.command_pid.unwrap() {
            return Ok(());
        }
        if self.result.is_some() {
            return Err("duplicate protected SSH wait record".into());
        }
        let result = if let Some(code) = record.get(2) {
            let code: i32 = code.as_str().parse()?;
            if !(0..=255).contains(&code) {
                return Err("invalid protected SSH exit status".into());
            }
            Outcome::Exit { code }
        } else {
            let number: i32 = record.get(3).unwrap().as_str().parse()?;
            if !(1..=64).contains(&number) {
                return Err("invalid protected Linux signal number".into());
            }
            Outcome::Signal { number }
        };
        self.result = Some(result);
        Ok(())
    }

    fn finish(mut self) -> Result<Outcome, Error> {
        if !self.line.is_empty() {
            self.line()?;
        }
        self.result.ok_or_else(|| {
            "protected SSH observer omitted its command's numeric wait record".into()
        })
    }
}

async fn observed_wait(session: &mut client::Handle<PinnedServer>) -> Result<Outcome, Error> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, "read-job-wait").await?;
    channel.eof().await?;
    let mut log = ObserverLog::default();
    let mut evidence = Evidence::new(0);
    while let Some(message) = channel.wait().await {
        if let ChannelMsg::Data { data } = &message {
            log.write(data)?;
        }
        evidence.event(message)?;
        if evidence.closed {
            break;
        }
    }
    if evidence.outcome()? != (Outcome::Exit { code: 0 }) {
        return Err("could not read protected SSH wait record".into());
    }
    log.finish()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    name: &str,
    root: &Path,
    directory: &Path,
    host: &Path,
    guest: &Path,
    spec: &JobSpec,
    generation: &str,
    interrupt: &mut Signal,
    terminate: &mut Signal,
    cleanup_failed: &mut bool,
) -> Result<(Value, Option<Outcome>, Output, Output, Option<String>), Error> {
    let public = stage(root, directory, host, guest, spec, generation).await?;
    host_runs::save(
        name,
        &json!({"name":name,"agent_id":name,"run_id":generation,"state":"starting"}),
    )?;
    let mut observer = None;
    // Retain the connection through VM teardown so the collector can drain
    // output on timeout or interruption before its transport is dropped.
    let mut session = None;
    let work = async {
        let artifacts = rootfs(guest).await?;
        host_platform::start_job_sandbox(name, spec.memory_mb).await?;
        let connection = connect(root, name, &public).await?;
        let mut channel = connection.channel_open_session().await?;
        channel.exec(true, "run-job").await?;
        channel.eof().await?;
        session = Some(connection);
        let limit = spec.retain_bytes;
        observer = Some(tokio::spawn(async move {
            let mut evidence = Evidence::new(limit);
            let mut stream_error = None;
            while let Some(message) = channel.wait().await {
                if let Err(error) = evidence.event(message) {
                    stream_error.get_or_insert_with(|| error.to_string());
                }
                if evidence.closed {
                    break;
                }
            }
            (evidence, stream_error)
        }));
        let outcome = tokio::select! {
            evidence = observer.as_mut().unwrap() => {
                let (evidence, stream_error) = evidence?;
                // This read has its own short bound. Losing metadata must not
                // reclassify an already completed command as a job timeout.
                let connection = session.as_mut().unwrap();
                let protected = match tokio::time::timeout(Duration::from_secs(5), observed_wait(connection)).await {
                    Ok(result) => result,
                    Err(_) => Err("protected SSH wait-record read timed out".into()),
                };
                let (outcome, observation_error) = evidence.resolve(protected);
                let _ = connection.disconnect(russh::Disconnect::ByApplication, "job finished", "").await;
                return Ok::<_, Error>((artifacts, outcome, Some(evidence), stream_error.or(observation_error)));
            },
            _ = tokio::time::sleep(Duration::from_secs(spec.timeout_seconds)) => Outcome::Timeout,
            _ = interrupt.recv() => Outcome::Interrupted { signal:libc::SIGINT },
            _ = terminate.recv() => Outcome::Interrupted { signal:libc::SIGTERM },
        };
        Ok((artifacts, Some(outcome), None, None))
    }
    .await;
    if let Err(error) = host_platform::stop_sandbox(name).await {
        *cleanup_failed = true;
        return Err(super::cleanup_error(&work, error, root));
    }
    let (artifacts, outcome, evidence, observation_error) = work?;
    let (evidence, observation_error) = match evidence {
        Some(evidence) => (evidence, observation_error),
        None => {
            tokio::time::timeout(
                Duration::from_secs(5),
                observer.ok_or("job SSH observer is missing")?,
            )
            .await??
        }
    };
    Ok((
        artifacts,
        outcome,
        evidence.stdout.finish(),
        evidence.stderr.finish(),
        observation_error,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_argv_survives_shell_syntax_empty_arguments_and_newlines() {
        let arguments = [
            "",
            "two words",
            "'quoted'",
            "$(exit 71)`exit 72`",
            "a\nb",
            "\\",
        ];
        let mut spec = super::super::tests::spec();
        spec.privilege = super::super::Privilege::GuestRoot;
        spec.argv = ["/bin/bash", "-c", "printf '%s\\0' \"$@\"", "probe"]
            .into_iter()
            .chain(arguments)
            .map(str::to_owned)
            .collect();
        let script = launcher(&spec);
        // Exercise the exact generated exec, without performing guest mounts
        // on the host. The runtime driver covers the full namespace launcher.
        let command = script.rsplit_once("\nexec ").unwrap().1;
        let output = std::process::Command::new("/bin/bash")
            .args(["-c", &format!("exec {command}")])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let expected: Vec<u8> = arguments
            .iter()
            .flat_map(|arg| arg.bytes().chain(std::iter::once(0)))
            .collect();
        assert_eq!(output.stdout, expected);
        assert!(output.stderr.is_empty());

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("command=literal");
        std::os::unix::fs::symlink("/bin/echo", &executable).unwrap();
        spec.argv = vec![
            executable.to_str().unwrap().to_owned(),
            "literal command".into(),
        ];
        let script = launcher(&spec);
        let command = script.rsplit_once("\nexec ").unwrap().1;
        let output = std::process::Command::new("/bin/bash")
            .args(["-c", &format!("exec {command}")])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"literal command\n");
    }

    #[test]
    fn ssh_status_is_explicit_and_signal_numbers_belong_to_the_linux_guest() {
        let mut evidence = Evidence::new(16);
        evidence.event(ChannelMsg::Close).unwrap();
        assert!(evidence.outcome().is_err());
        let mut evidence = Evidence::new(16);
        evidence
            .event(ChannelMsg::ExitStatus { exit_status: 139 })
            .unwrap();
        assert!(evidence.outcome().is_err());
        evidence.event(ChannelMsg::Close).unwrap();
        assert_eq!(evidence.outcome().unwrap(), Outcome::Exit { code: 139 });
        let mut signalled = Evidence::new(16);
        signalled
            .event(ChannelMsg::ExitSignal {
                signal_name: Sig::SEGV,
                core_dumped: false,
                error_message: String::new(),
                lang_tag: String::new(),
            })
            .unwrap();
        signalled.event(ChannelMsg::Close).unwrap();
        assert_eq!(signalled.outcome().unwrap(), Outcome::Signal { number: 11 });
        let mut duplicate = Evidence::new(16);
        for _ in 0..2 {
            duplicate
                .event(ChannelMsg::ExitStatus { exit_status: 0 })
                .unwrap();
        }
        duplicate.event(ChannelMsg::Close).unwrap();
        assert!(duplicate.outcome().is_err());
        assert!(
            Evidence::new(16)
                .event(ChannelMsg::ExitStatus { exit_status: 256 })
                .is_err()
        );
        assert_eq!(signal_number(Sig::USR1).unwrap(), Some(10));
        assert!(signal_number(Sig::Custom("fake".into())).is_err());
    }

    #[test]
    fn numeric_wait_record_belongs_to_the_fixed_command_pid() {
        fn parse(bytes: &[u8]) -> Result<Outcome, Error> {
            let mut log = ObserverLog::default();
            // SSH need not preserve log line or UTF-8 chunk boundaries.
            for chunk in bytes.chunks(7) {
                log.write(chunk)?;
            }
            log.finish()
        }
        let exit = b"321\ndebug1: session_exit_message: session 0 channel 0 pid 999 exit 0\ndebug1: session_exit_message: session 0 channel 0 pid 321 exit 139\r\n";
        assert_eq!(parse(exit).unwrap(), Outcome::Exit { code: 139 });
        for number in [5, 7, 24, 64] {
            let signal = format!(
                "321\ndebug1: session_exit_message: session 0 channel 0 pid 321 signal {number} core dumped [postauth]\n"
            );
            assert_eq!(
                parse(signal.as_bytes()).unwrap(),
                Outcome::Signal { number }
            );
        }
        for invalid in [
            "321\ndebug1: session_exit_message: session 0 channel 0 pid 999 exit 0\n",
            "321\ndebug1: session_exit_message: session 0 channel 0 pid 321 exit 0\ndebug1: session_exit_message: session 1 channel 1 pid 321 exit 0\n",
            "321\ndebug1: session_exit_message: session 0 channel 0 pid 321 exit 256\n",
            "321\ndebug1: session_exit_message: session 0 channel 0 pid 321 signal 0\n",
            "321\ndebug1: session_exit_message: session 0 channel 0 pid 321 signal 65\n",
            "0\ndebug1: session_exit_message: session 0 channel 0 pid 321 exit 0\n",
            "debug1: session_exit_message: session 0 channel 0 pid 321 exit 0\n",
            "321\n",
            "",
        ] {
            assert!(parse(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn protected_wait_cross_check_handles_generic_signals_and_preserves_failed_read_evidence() {
        let mut evidence = Evidence::new(4);
        evidence.stdout.write(b"PASS\n").unwrap();
        evidence
            .event(ChannelMsg::ExitSignal {
                signal_name: Sig::Custom("SIG@openssh.com".into()),
                core_dumped: false,
                error_message: String::new(),
                lang_tag: String::new(),
            })
            .unwrap();
        evidence.event(ChannelMsg::Close).unwrap();
        assert!(evidence.outcome().is_err());
        let (outcome, error) = evidence.resolve(Ok(Outcome::Signal { number: 7 }));
        assert_eq!(outcome, Some(Outcome::Signal { number: 7 }));
        assert!(error.is_none());
        let (outcome, error) = evidence.resolve(Err("metadata channel failed".into()));
        assert!(outcome.is_none());
        assert_eq!(error.as_deref(), Some("metadata channel failed"));
        assert!(evidence.resolve(Ok(Outcome::Exit { code: 0 })).1.is_some());
        let stdout = evidence.stdout.finish();
        assert_eq!(stdout.bytes, 5);
        assert_eq!(stdout.sha256, super::super::digest(b"PASS\n"));

        let mut evidence = Evidence::new(4);
        evidence
            .event(ChannelMsg::ExitStatus { exit_status: 17 })
            .unwrap();
        evidence.event(ChannelMsg::Close).unwrap();
        let (outcome, error) = evidence.resolve(Err("metadata channel failed".into()));
        assert_eq!(outcome, Some(Outcome::Exit { code: 17 }));
        assert!(error.is_some());
        assert!(evidence.resolve(Ok(Outcome::Exit { code: 0 })).1.is_some());
        assert!(
            evidence
                .resolve(Ok(Outcome::Signal { number: 17 }))
                .1
                .is_some()
        );
    }
}
