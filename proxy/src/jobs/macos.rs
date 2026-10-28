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

async fn stage(
    root: &Path,
    directory: &Path,
    host: &Path,
    guest: &Path,
    spec: &JobSpec,
    generation: &str,
) -> Result<PublicKey, Error> {
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
            "MaxSessions 1\nForceCommand exec /safeyolo/job-exec\n",
        ),
    )?;
    fs::write(share.join("guest-init"), include_str!("vz-guest-init.sh"))?;
    // Exec at each step preserves the command's own wait status in sshd.
    // Neither an agent request nor SSH command text selects what is executed.
    fs::write(
        share.join("job-exec"),
        concat!("#!/bin/sh\nexec /usr/bin/python3 /safeyolo/job-exec.py\n",),
    )?;
    fs::write(share.join("job-exec.py"), include_str!("vz-exec.py"))?;
    for name in ["guest-init", "job-exec"] {
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

fn signal_number(signal: Sig) -> Result<i32, Error> {
    // The guest is Linux even though this observer runs on macOS. In
    // particular, libc::SIGUSR1 on the host is not Linux SIGUSR1.
    Ok(match signal {
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
    })
}

struct Evidence {
    status: Option<Outcome>,
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
                Some(Outcome::Exit {
                    code: exit_status as i32,
                })
            }
            ChannelMsg::ExitSignal { signal_name, .. } => Some(Outcome::Signal {
                number: signal_number(signal_name)?,
            }),
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
        self.status
            .clone()
            .ok_or_else(|| "job SSH channel closed without exit-status or exit-signal".into())
    }
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
) -> Result<(Value, Outcome, Output, Output), Error> {
    let public = stage(root, directory, host, guest, spec, generation).await?;
    host_runs::save(
        name,
        &json!({"name":name,"agent_id":name,"run_id":generation,"state":"starting"}),
    )?;
    let mut observer = None;
    let work = async {
        let artifacts = rootfs(guest).await?;
        host_platform::start_job_sandbox(name, spec.memory_mb).await?;
        let mut session = connect(root, name, &public).await?;
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, "exec /safeyolo/job-exec").await?;
        channel.eof().await?;
        let limit = spec.retain_bytes;
        observer = Some(tokio::spawn(async move {
            let mut evidence = Evidence::new(limit);
            while let Some(message) = channel.wait().await {
                evidence.event(message)?;
                if evidence.closed {
                    break;
                }
            }
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "job finished", "")
                .await;
            Ok::<_, Error>(evidence)
        }));
        let outcome = tokio::select! {
            evidence = observer.as_mut().unwrap() => {
                let evidence = evidence??;
                let outcome = evidence.outcome()?;
                return Ok::<_, Error>((artifacts, outcome, Some(evidence)));
            },
            _ = tokio::time::sleep(Duration::from_secs(spec.timeout_seconds)) => Outcome::Timeout,
            _ = interrupt.recv() => Outcome::Interrupted { signal:libc::SIGINT },
            _ = terminate.recv() => Outcome::Interrupted { signal:libc::SIGTERM },
        };
        Ok((artifacts, outcome, None))
    }
    .await;
    if let Err(error) = host_platform::stop_sandbox(name).await {
        *cleanup_failed = true;
        return Err(format!(
            "job cleanup failed: {error}; runtime preserved at {}",
            root.display()
        )
        .into());
    }
    let (artifacts, outcome, evidence) = work?;
    let evidence = match evidence {
        Some(evidence) => evidence,
        None => {
            tokio::time::timeout(
                Duration::from_secs(5),
                observer.ok_or("job SSH observer is missing")?,
            )
            .await???
        }
    };
    Ok((
        artifacts,
        outcome,
        evidence.stdout.finish(),
        evidence.stderr.finish(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(signal_number(Sig::USR1).unwrap(), 10);
        assert!(signal_number(Sig::Custom("fake".into())).is_err());
    }
}
