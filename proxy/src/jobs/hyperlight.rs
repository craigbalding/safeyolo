//! Pinned Hyperlight bundles reuse the job input, stream and result contract.
//! A fresh helper process owns the VM and every synchronous host callback.

use super::{
    HelperProcessStatus, JobEngine, JobResult, JobSpec, Outcome, PinnedArtifact, Privilege,
    collect, digest, input, now,
};
use crate::Error;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{
        fs::PermissionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Child,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    file: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    protocol: u32,
    os: String,
    architecture: String,
    hyperlight: String,
    unikraft: String,
    kernel_contract: String,
    helper: BundleFile,
    rootfs: BundleFile,
    rootfs_source: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Completion {
    GuestFunctionReturned,
    GuestCallCompleted { reported_status: i32 },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeReport {
    completion: Option<Completion>,
    error: Option<String>,
}

fn artifacts(engine: &JobEngine) -> Option<(&PinnedArtifact, &PinnedArtifact)> {
    match engine {
        JobEngine::Platform => None,
        JobEngine::Hyperlight { runtime, guest, .. } => Some((runtime, guest)),
        JobEngine::HyperlightUnikraft { runtime, checker } => Some((runtime, checker)),
    }
}

fn sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn validate_spec(spec: &JobSpec) -> Result<(), Error> {
    let Some((runtime, artifact)) = artifacts(&spec.engine) else {
        return Ok(());
    };
    if !cfg!(any(
        target_os = "linux",
        all(target_os = "macos", target_arch = "aarch64")
    )) || !cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
    {
        return Err(
            "Hyperlight jobs require Linux x86_64/aarch64 with KVM or Apple-silicon macOS with HVF"
                .into(),
        );
    }
    if spec.network {
        // DOC: docs/hyperlight-jobs.md
        return Err("Hyperlight jobs do not yet support delegated service/network capabilities; network must be false".into());
    }
    if spec.privilege != Privilege::Unprivileged {
        return Err("Hyperlight jobs cannot supply Unix guest-root privilege".into());
    }
    if !sha256(&runtime.sha256) || !sha256(&artifact.sha256) {
        return Err("Hyperlight runtime and checker artifacts need full SHA-256 digests".into());
    }
    if let JobEngine::Hyperlight { function, .. } = &spec.engine
        && (function.is_empty() || function.contains('\0'))
    {
        return Err("core Hyperlight needs a guest ABI function name".into());
    }
    usize::try_from(spec.memory_mb)?
        .checked_mul(1024 * 1024)
        .ok_or("Hyperlight memory size overflow")?;
    Ok(())
}

async fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > limit {
        return Err("Hyperlight metadata exceeds its byte limit".into());
    }
    Ok(bytes)
}

fn file_in(bundle: &Path, file: &BundleFile) -> Result<PinnedArtifact, Error> {
    // Only the trusted pinned manifest selects this host path. Verified bytes
    // are copied into the private invocation; the source is never a guest mount.
    if !sha256(&file.sha256) {
        return Err("invalid Hyperlight bundle file or digest".into());
    }
    Ok(PinnedArtifact {
        path: bundle
            .parent()
            .ok_or("runtime manifest has no parent")?
            .join(&file.file),
        sha256: file.sha256.clone(),
    })
}

async fn bundle(runtime: &PinnedArtifact) -> Result<Bundle, Error> {
    let bytes = bounded(&runtime.path, 64 * 1024).await?;
    if digest(&bytes) != runtime.sha256.to_ascii_lowercase() {
        return Err("Hyperlight runtime manifest digest mismatch".into());
    }
    let bundle: Bundle = serde_json::from_slice(&bytes)?;
    if bundle.protocol != 2 || bundle.hyperlight != "0.19.0" || bundle.unikraft != "0.21.0" {
        return Err(
            "incompatible Hyperlight runtime/guest ABI version; rebuild a matching bundle".into(),
        );
    }
    if bundle.os != std::env::consts::OS || bundle.architecture != std::env::consts::ARCH {
        return Err(format!(
            "Hyperlight bundle is for {}/{}, host is {}/{}",
            bundle.os,
            bundle.architecture,
            std::env::consts::OS,
            std::env::consts::ARCH
        )
        .into());
    }
    Ok(bundle)
}

async fn copy(
    artifact: &PinnedArtifact,
    destination: &Path,
    executable: bool,
) -> Result<(), Error> {
    let mut source = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&artifact.path)
        .await?;
    if !source.metadata().await?.is_file() {
        return Err("Hyperlight artifact must be a regular file".into());
    }
    let mut output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .await?;
    let mut hash = Context::new(&SHA256);
    let mut bytes = [0u8; 64 * 1024];
    loop {
        let count = source.read(&mut bytes).await?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
        output.write_all(&bytes[..count]).await?;
    }
    output.flush().await?;
    if super::hex(hash.finish().as_ref()) != artifact.sha256.to_ascii_lowercase() {
        // DOC: docs/hyperlight-jobs.md
        return Err(format!(
            "Hyperlight artifact digest mismatch: {}",
            artifact.path.display()
        )
        .into());
    }
    // Set before launching, and then leave the verified private copy unchanged.
    output
        .set_permissions(fs::Permissions::from_mode(if executable {
            0o500
        } else {
            0o400
        }))
        .await?;
    Ok(())
}

async fn prepare(spec: &JobSpec, root: &Path) -> Result<Bundle, Error> {
    let (runtime, artifact) = artifacts(&spec.engine).ok_or("not a Hyperlight engine")?;
    let bundle = bundle(runtime).await?;
    copy(
        &file_in(&runtime.path, &bundle.helper)?,
        &root.join("helper"),
        true,
    )
    .await?;
    tokio::fs::create_dir(root.join("code")).await?;
    let code = root.join("code/checker");
    copy(artifact, &code, false).await?;
    if matches!(spec.engine, JobEngine::Hyperlight { .. }) {
        let header = bounded_header(&code).await?;
        let machine = u16::from_le_bytes([header[18], header[19]]);
        let expected = if cfg!(target_arch = "aarch64") {
            183
        } else {
            62
        };
        if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 || machine != expected {
            return Err("core Hyperlight guest is not a compatible little-endian 64-bit ELF for this host architecture".into());
        }
    } else {
        copy(
            &file_in(&runtime.path, &bundle.rootfs)?,
            &root.join("python.cpio"),
            false,
        )
        .await?;
    }
    Ok(bundle)
}

async fn bounded_header(path: &Path) -> Result<[u8; 20], Error> {
    let mut header = [0u8; 20];
    tokio::fs::File::open(path)
        .await?
        .read_exact(&mut header)
        .await?;
    Ok(header)
}

fn command(helper: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(helper);
    command
        .env_clear()
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    command
}

struct Helper {
    child: Child,
    group: Option<u32>,
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Abort of the caller's future must also stop synchronous callbacks.
        // The unreaped leader pins this group ID until wait has completed.
        if let Some(group) = self.group {
            unsafe {
                libc::kill(-(group as i32), libc::SIGKILL);
            }
        }
    }
}

fn observed_status(status: std::process::ExitStatus) -> Result<HelperProcessStatus, Error> {
    Ok(if let Some(number) = status.signal() {
        HelperProcessStatus::Signal { number }
    } else {
        HelperProcessStatus::Exit {
            code: status.code().ok_or("helper status is unavailable")?,
        }
    })
}

fn monotonic_ms() -> Result<u64, Error> {
    let mut time = std::mem::MaybeUninit::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let time = unsafe { time.assume_init() };
    Ok(time.tv_sec as u64 * 1000 + time.tv_nsec as u64 / 1_000_000)
}

async fn stop(helper: &mut Helper) -> Result<HelperProcessStatus, Error> {
    if let Some(group) = helper.group
        && unsafe { libc::kill(-(group as i32), libc::SIGKILL) } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    let status = tokio::time::timeout(Duration::from_secs(5), helper.child.wait())
        .await
        .map_err(|_| "Hyperlight helper did not stop after SIGKILL; VM cleanup is unproved")??;
    helper.group = None;
    observed_status(status)
}

pub(super) async fn discover(config: &Path, spec: &JobSpec) -> Result<Option<Value>, Error> {
    if artifacts(&spec.engine).is_none() {
        return Ok(None);
    }
    // No guest is started by discovery. Use private, verified copies so a
    // later replacement of an adopted path cannot change what is invoked.
    let parent = config
        .parent()
        .ok_or("job instance config has no parent")?
        .join("data");
    tokio::fs::create_dir_all(&parent).await?;
    let temporary = tempfile::Builder::new()
        .prefix("hyperlight-discover-")
        .tempdir_in(parent)?;
    let root = temporary.path();
    let result = tokio::time::timeout(Duration::from_secs(spec.timeout_seconds), async {
        let bundle = prepare(spec, root).await?;
        let output = command(&root.join("helper"))
            .arg("--discover")
            .output()
            .await?;
        if !output.status.success() {
            return Err::<Option<Value>, Error>(
                format!(
                    "{} discovery failed: {}",
                    spec.engine.name(),
                    String::from_utf8_lossy(&output.stderr)
                )
                .into(),
            );
        }
        let identity: Value = serde_json::from_slice(&output.stdout)?;
        if identity["kernel_contract"] != bundle.kernel_contract {
            return Err("Hyperlight embedded kernel contract mismatch".into());
        }
        Ok(Some(identity))
    })
    .await
    .map_err(|_| "Hyperlight discovery deadline exceeded")?;
    temporary.close()?;
    result
}

pub(super) async fn run(
    config: &Path,
    spec: &JobSpec,
    source_input: Option<&Path>,
    mut cancel: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<JobResult, Error> {
    let config = config.canonicalize()?;
    let parent = config
        .parent()
        .ok_or("job instance config has no parent")?
        .join("data");
    tokio::fs::create_dir_all(&parent).await?;
    let temporary = tempfile::Builder::new()
        .prefix("job-hyperlight-")
        .tempdir_in(parent)?;
    let root = temporary.path().to_owned();
    let input_sha256 = input::copy(
        source_input,
        &root.join("input"),
        spec.max_input_bytes,
        spec.max_input_entries,
    )?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let started_unix_ms = now()?;
    let deadline_monotonic_ms = monotonic_ms()?
        .checked_add(
            spec.timeout_seconds
                .checked_mul(1000)
                .ok_or("Hyperlight deadline overflow")?,
        )
        .ok_or("Hyperlight deadline overflow")?;
    let mut child = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut runtime = None;
    let mut helper_process_status = None;
    let work = async {
        let bundle = prepare(spec, &root).await?;
        let function = if let JobEngine::Hyperlight { function, .. } = &spec.engine {
            Some(function.as_str())
        } else {
            None
        };
        let invocation = json!({"engine":spec.engine.name(),"artifact":root.join("code/checker"),
            "input":root.join("input"),"argv":spec.argv,"memory_mb":spec.memory_mb,
            "max_input_bytes":spec.max_input_bytes,"function":function,
            "parent_pid":std::process::id(),"deadline_monotonic_ms":deadline_monotonic_ms,
            "rootfs":if function.is_some() {None} else {Some(root.join("python.cpio"))}});
        tokio::fs::write(
            root.join("invocation.json"),
            serde_json::to_vec(&invocation)?,
        )
        .await?;
        runtime = Some(bundle);
        let mut helper = command(&root.join("helper"))
            .arg(root.join("invocation.json"))
            .arg(root.join("report.json"))
            .spawn()?;
        stdout = Some(tokio::spawn(collect(
            helper.stdout.take().ok_or("missing helper stdout")?,
            spec.retain_bytes,
        )));
        stderr = Some(tokio::spawn(collect(
            helper.stderr.take().ok_or("missing helper stderr")?,
            spec.retain_bytes,
        )));
        let group = helper.id();
        child = Some(Helper {
            child: helper,
            group,
        });
        let helper = child.as_mut().unwrap();
        let status = helper.child.wait().await?;
        helper.group = None;
        let status = observed_status(status)?;
        let outcome = match status {
            HelperProcessStatus::Exit { code: 124 } => Outcome::Timeout,
            HelperProcessStatus::Signal { number } => Outcome::Signal { number },
            HelperProcessStatus::Exit { code } => Outcome::Exit { code },
        };
        helper_process_status = Some(status);
        Ok::<_, Error>(outcome)
    };
    let result = tokio::select! {
        result = work => result,
        _ = tokio::time::sleep(Duration::from_secs(spec.timeout_seconds)) => Ok(Outcome::Timeout),
        _ = interrupt.recv() => Ok(Outcome::Interrupted {signal:libc::SIGINT}),
        _ = terminate.recv() => Ok(Outcome::Interrupted {signal:libc::SIGTERM}),
        _ = super::check_cancelled(&mut cancel) => Ok(Outcome::Interrupted {signal:libc::SIGTERM}),
    };
    if !matches!(result, Ok(Outcome::Exit { .. } | Outcome::Signal { .. }))
        && let Some(helper) = child.as_mut()
    {
        match stop(helper).await {
            Ok(status) => helper_process_status = Some(status),
            Err(error) => {
                let _ = temporary.keep();
                return Err(super::cleanup_error(&result, error, &root));
            }
        }
    }
    let outcome = result?;
    let empty = || super::OutputCapture::new(spec.retain_bytes).finish();
    let stdout = match stdout {
        Some(task) => tokio::time::timeout(Duration::from_secs(5), task).await???,
        None => empty(),
    };
    let stderr = match stderr {
        Some(task) => tokio::time::timeout(Duration::from_secs(5), task).await???,
        None => empty(),
    };
    let mut observation_error = None;
    let runtime_report = if matches!(outcome, Outcome::Exit { .. }) {
        match bounded(&root.join("report.json"), 64 * 1024)
            .await
            .and_then(|bytes| serde_json::from_slice::<RuntimeReport>(&bytes).map_err(Into::into))
        {
            Ok(report) => {
                let completed = matches!(
                    (&spec.engine, &report.completion),
                    (
                        JobEngine::Hyperlight { .. },
                        Some(Completion::GuestFunctionReturned)
                    ) | (
                        JobEngine::HyperlightUnikraft { .. },
                        Some(Completion::GuestCallCompleted { reported_status: 0 })
                    )
                );
                if outcome == (Outcome::Exit { code: 0 }) && (!completed || report.error.is_some())
                {
                    observation_error =
                        Some("Hyperlight helper success has no successful VM completion".into());
                }
                Some(serde_json::to_value(report)?)
            }
            Err(error) => {
                observation_error =
                    Some(format!("Hyperlight helper report is unavailable: {error}"));
                None
            }
        }
    } else {
        None
    };
    temporary.close().map_err(|error| {
        format!(
            "Hyperlight runtime removal failed: {error}; inspect {}",
            root.display()
        )
    })?;
    let (manifest, artifact) = artifacts(&spec.engine).unwrap();
    Ok(JobResult {
        engine: spec.engine.name().into(),
        outcome_source: if matches!(outcome, Outcome::Timeout | Outcome::Interrupted { .. }) {
            "host_watchdog"
        } else {
            "host_helper"
        }
        .into(),
        runtime_report,
        helper_process_status,
        run_id: format!("job-{}", uuid::Uuid::new_v4().simple()),
        gate_id: spec.gate_id.clone(),
        gate_definition_sha256: digest(&serde_json::to_vec(spec)?),
        gate_principal: format!("gate:{}", spec.gate_id),
        authorization_principal: None,
        rootfs: json!({"kind":spec.engine.name(),"runtime_manifest_sha256":manifest.sha256,
            "artifact_sha256":artifact.sha256,"bundle":runtime,"console_encoding":if matches!(spec.engine,JobEngine::Hyperlight {..}) {"utf-8"} else {"utf-8-with-replacement"}}),
        input_sha256,
        started_unix_ms,
        ended_unix_ms: now()?,
        outcome: Some(outcome),
        observation_error,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests;
