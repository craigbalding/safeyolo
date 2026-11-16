//! Decode the publisher's opaque tar archive with the host's maintained tar.

use std::{
    fs,
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use bytes::Bytes;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{Error, guest_oci::ConsumerPlatform, linux_host::Mapping};

/// Decode download chunks without interpreting archive paths or using privilege.
/// The anonymous tar file is usable only after the compressed blob verifies.
pub(super) struct DownloadDecoder {
    input: mpsc::Sender<Option<Bytes>>,
    worker: JoinHandle<Result<fs::File, Error>>,
}

impl DownloadDecoder {
    pub(super) fn new(output: fs::File) -> Result<Self, Error> {
        let mut decoder = zstd::stream::raw::Decoder::new()?;
        // Retain at most two queued network chunks. Moving Bytes shares the
        // existing allocation instead of copying the compressed payload.
        let (input, mut chunks) = mpsc::channel::<Option<Bytes>>(2);
        let worker = tokio::task::spawn_blocking(move || {
            use zstd::stream::raw::Operation;

            // Decode and write on one blocking worker. This avoids Tokio's
            // filesystem-buffer copy and a pool round trip for each output batch.
            let mut output = BufWriter::with_capacity(1024 * 1024, output);
            let mut buffer = vec![0; 128 * 1024];
            let mut finished_frame = false;
            while let Some(chunk) = chunks.blocking_recv() {
                let Some(chunk) = chunk else { break };
                let mut bytes = chunk.as_ref();
                if bytes.is_empty() {
                    continue;
                }
                loop {
                    // Dropping the sender cancels queued work, including when
                    // compressed verification fails. No extraction child exists.
                    if chunks.is_closed() {
                        return Err("guest download decoding cancelled".into());
                    }
                    let status = decoder.run_on_buffers(bytes, &mut buffer)?;
                    finished_frame = status.remaining == 0;
                    output.write_all(&buffer[..status.bytes_written])?;
                    bytes = &bytes[status.bytes_read..];
                    // Drain a full output buffer even after consuming the last
                    // input byte. A short output or frame end needs more input.
                    if bytes.is_empty() && (status.bytes_written < buffer.len() || finished_frame) {
                        break;
                    }
                }
            }
            if chunks.is_closed() {
                return Err("guest download decoding cancelled".into());
            }
            if !finished_frame {
                return Err("incomplete guest zstd frame".into());
            }
            output.flush()?;
            let mut output = output.into_inner().map_err(|error| error.into_error())?;
            output.rewind()?;
            Ok(output)
        });
        Ok(Self { input, worker })
    }

    pub(super) async fn write(&mut self, bytes: Bytes) -> Result<(), Error> {
        if self.input.send(Some(bytes)).await.is_err() {
            // Preserve the decoder or filesystem error when the worker exits.
            (&mut self.worker).await??;
            return Err("guest download decoder stopped".into());
        }
        Ok(())
    }

    pub(super) async fn finish(self) -> Result<fs::File, Error> {
        // An explicit end distinguishes completion from a dropped download.
        // Keep the sender open until the worker drains and flushes its output.
        let _ = self.input.send(None).await;
        let result = self.worker.await?;
        drop(self.input);
        result
    }
}

fn regular(path: &Path) -> Result<(), Error> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(format!("prepared guest file must be regular: {}", path.display()).into());
    }
    Ok(())
}

pub(super) fn validate_assets(
    path: &Path,
    platform: ConsumerPlatform,
    mapping: Mapping,
) -> Result<(), Error> {
    if platform == ConsumerPlatform::DarwinArm64 {
        for name in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"] {
            regular(&path.join(name))?;
        }
    } else {
        let tree = path.join("rootfs-tree");
        let metadata = tree.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != mapping.uid_base
            || metadata.gid() != mapping.gid_base
        {
            return Err(format!(
                "prepared rootfs-tree must be a directory owned by {}:{}: {}",
                mapping.uid_base,
                mapping.gid_base,
                tree.display()
            )
            .into());
        }
        regular(&path.join("cache-paths.txt"))?;
    }
    Ok(())
}

// Linux keeps one import namespace alive through extraction, validation and
// cleanup. macOS extracts its image bundle as the ordinary host account.
struct ExtractionCommands {
    #[cfg(target_os = "linux")]
    namespace: Option<super::namespace::ImportNamespace>,
}

#[derive(Debug)]
pub(super) struct StageCleanupError(String);

impl std::fmt::Display for StageCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StageCleanupError {}

impl ExtractionCommands {
    fn new(root: &Path, platform: ConsumerPlatform, mapping: Mapping) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                namespace: if platform == ConsumerPlatform::DarwinArm64 {
                    None
                } else {
                    Some(super::namespace::ImportNamespace::start(root, mapping)?)
                },
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, mapping);
            if platform != ConsumerPlatform::DarwinArm64 {
                return Err("Linux guest import requires a Linux host".into());
            }
            Ok(Self {})
        }
    }

    fn command(&mut self, program: impl AsRef<std::ffi::OsStr>) -> Result<Command, Error> {
        #[cfg(target_os = "linux")]
        if let Some(namespace) = &mut self.namespace {
            return namespace.command(program);
        }
        Ok(Command::new(program))
    }

    fn remove_stage(&mut self, stage: &Path) -> Result<(), Error> {
        // The host account owns the stage and its parent, even if a setgid
        // cache directory has a group outside the import map. Enter the stage
        // before switching credentials, remove its children in the namespace,
        // then remove the empty stage as its ordinary owner. rm follows no links.
        let entries = fs::read_dir(stage)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        let status = self
            .command("rm")?
            .current_dir(stage)
            .args(["-rf", "--"])
            .args(entries)
            .status()?;
        if !status.success() {
            return Err(format!("cannot remove private guest stage {} ({status}); restore namespace/filesystem access and remove this owned stage before retrying", stage.display()).into());
        }
        fs::remove_dir(stage)?;
        Ok(())
    }
}

fn extract_member(
    input: &mut fs::File,
    decoded: &mut Option<fs::File>,
    mut command: Command,
    stage: &Path,
    cancellation: Option<&AtomicBool>,
) -> Result<(), Error> {
    if cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err("guest preparation interrupted".into());
    }
    input.rewind()?;
    if let Some(decoded) = decoded.as_mut() {
        decoded.rewind()?;
    }
    let invocation = crate::host_sudo::display(&command);
    let mut errors = tempfile::tempfile_in(stage.parent().ok_or("guest stage has no parent")?)?;
    let mut child = command
        .env("LC_ALL", "C")
        .stdin(match decoded.as_ref() {
            Some(decoded) => Stdio::from(decoded.try_clone()?),
            None => Stdio::piped(),
        })
        .stdout(Stdio::null())
        .stderr(errors.try_clone()?)
        .spawn().map_err(|error| format!("{invocation} could not start: {error}; no guest tree was published. Repair the command or namespace setup, then retry; the verified archive remains reusable"))?;
    let copy = (|| -> Result<(), Error> {
        if let Some(mut output) = child.stdin.take() {
            // Read the same verified open descriptor for each selected-member
            // pass, including when a retained pathname has been replaced.
            let decoder = zstd::stream::read::Decoder::new(input)?;
            let mut decoder = BufReader::with_capacity(128 * 1024, decoder);
            std::io::copy(&mut decoder, &mut output)?;
        }
        Ok(())
    })();
    // Always reap the writer before propagating a copy or cancellation error.
    let status = child.wait()?;
    errors.seek(SeekFrom::Start(0))?;
    let mut diagnostic = Vec::new();
    let mut metadata_failed = false;
    let mut window = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let length = errors.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        diagnostic.extend_from_slice(&buffer[..length.min(4096 - diagnostic.len())]);
        // GNU tar can exit zero after failing an ACL or xattr write. Check
        // the complete C-locale diagnostic, retaining only bounded context;
        // harmless warnings still keep their existing warning behavior.
        window.extend_from_slice(&buffer[..length]);
        metadata_failed |= [b"Cannot set".as_slice(), b"Cannot restore", b"Can't set"]
            .iter()
            .any(|pattern| window.windows(pattern.len()).any(|part| part == *pattern));
        window.drain(..window.len().saturating_sub(32));
    }
    let diagnostic = String::from_utf8_lossy(&diagnostic);
    if !status.success() || metadata_failed {
        return Err(format!("cannot extract guest archive into {} ({status}): {diagnostic}\n{invocation} failed to preserve guest contents or metadata; no guest tree was published. Repair the reported extraction or namespace failure, then retry; the verified archive remains reusable", stage.display()).into());
    }
    copy?;
    if !diagnostic.is_empty() {
        eprintln!("Guest extraction warnings: {diagnostic}");
    }
    if cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err("guest preparation interrupted".into());
    }
    Ok(())
}

fn extract(
    input: &mut fs::File,
    decoded: &mut Option<fs::File>,
    stage: &Path,
    platform: ConsumerPlatform,
    mapping: Mapping,
    commands: &mut ExtractionCommands,
    cancellation: Option<&AtomicBool>,
) -> Result<(), Error> {
    let extraction_started = Instant::now();
    let linux = platform != ConsumerPlatform::DarwinArm64;
    let mut command = commands.command("tar")?;
    // Never enable absolute names or follow directory symlinks. Select only
    // the backend's inputs, preserving existing tar confinement.
    // chdir occurs as the host account before nsenter. Relative lookups avoid
    // requiring namespace-root access to unrelated cache-parent groups.
    command.current_dir(stage).args(["-xpf", "-", "-C", "."]);
    if linux {
        command.args([
            "--blocking-factor=256",
            "--numeric-owner",
            "--same-owner",
            "--acls",
            "--xattrs",
            "--xattrs-include=*",
            "--",
            "rootfs-tree",
        ]);
    } else {
        command.args(["--", "Image", "initramfs.cpio.gz", "rootfs-base.ext4"]);
    }
    extract_member(input, decoded, command, stage, cancellation)?;
    if linux {
        // This list is host text, not guest metadata. Its build-account owner
        // can be outside the guest ID range; do not map it as a guest identity.
        let mut cache = Command::new("tar");
        cache.args(["-xpf", "-", "-C"]).arg(stage).args([
            "--no-same-owner",
            "--",
            "cache-paths.txt",
        ]);
        extract_member(input, decoded, cache, stage, cancellation)?;
        #[cfg(test)]
        let executable = std::env::var_os("SAFEYOLO_NATIVE_CLI")
            .ok_or("set SAFEYOLO_NATIVE_CLI to the built native CLI for acquisition tests")?;
        #[cfg(not(test))]
        let executable = std::env::current_exe()?;
        // Reuse the pinned-inode, mount, owner, hardlink and xattr validation
        // in archive coordinates. No host-coordinate remapping runs here.
        let status = commands
            .command(executable)?
            .current_dir(stage)
            .args(["host", "validate-guest-import"])
            .arg("./rootfs-tree")
            .status()?;
        if !status.success() {
            return Err("guest metadata validation failed; no tree was published. Use a canonical guest archive and retry; the existing installation was preserved".into());
        }
    }
    validate_assets(stage, platform, mapping)?;
    eprintln!(
        "SafeYolo: guest archive prepared in {:.3}s.",
        extraction_started.elapsed().as_secs_f64()
    );
    Ok(())
}

pub(super) fn prepare(
    mut input: fs::File,
    mut decoded: Option<fs::File>,
    destination: &Path,
    platform: ConsumerPlatform,
    mapping: Mapping,
    namespace_root: &Path,
    cancellation: Option<&AtomicBool>,
) -> Result<(), Error> {
    // Namespace authorization belongs to the final installation root, even
    // when this executable/configuration is in an installer staging root.
    // Establish it before creating a stage, so missing authorization leaves
    // no mapped files and early preparation can safely defer to host consent.
    let mut commands = ExtractionCommands::new(namespace_root, platform, mapping)?;
    let parent = destination.parent().ok_or("guest tree has no parent")?;
    if destination.try_exists()? || destination.is_symlink() {
        return Err(
            "guest preparation destination already exists; existing inputs were preserved".into(),
        );
    }
    let stage = tempfile::Builder::new()
        .prefix("extract-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?
        .keep();
    let result = (|| -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        if platform != ConsumerPlatform::DarwinArm64 {
            use std::os::fd::AsRawFd;
            let directory = fs::File::open(&stage)?;
            // A setgid parent can assign an unrelated host group. This owned
            // private directory must use the operator group present in the map.
            if unsafe { libc::fchown(directory.as_raw_fd(), u32::MAX, mapping.host_gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        extract(
            &mut input,
            &mut decoded,
            &stage,
            platform,
            mapping,
            &mut commands,
            cancellation,
        )
    })()
    .and_then(|()| {
        if cancellation.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            Err("guest preparation interrupted".into())
        } else {
            Ok(())
        }
    })
    .and_then(|()| {
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).map_err(Into::into)
    })
    .and_then(|()| fs::rename(&stage, destination).map_err(Into::into));
    if let Err(error) = result {
        if let Err(cleanup) = commands.remove_stage(&stage) {
            return Err(Box::new(StageCleanupError(format!(
                "{error}; staging cleanup failed: {cleanup}"
            ))));
        }
        return Err(error);
    }
    Ok(())
}
