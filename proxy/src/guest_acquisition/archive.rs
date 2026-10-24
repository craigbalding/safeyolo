//! Decode the publisher's opaque tar archive with the host's maintained tar.

use std::{
    fs,
    io::{BufReader, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use crate::{
    Error,
    guest_oci::ConsumerPlatform,
    linux_host::{ARCHIVE_BASE, Mapping},
};

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

pub(super) fn remove_stage(path: &Path, platform: ConsumerPlatform) -> Result<(), Error> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && platform != ConsumerPlatform::DarwinArm64 =>
        {
            // Only the freshly created stage needs elevation for subuid-owned files.
            let status = Command::new("sudo")
                .args(["-n", "rm", "-rf", "--"])
                .arg(path)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("cannot remove guest staging directory {}", path.display()).into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn extract(
    input: &Path,
    stage: &Path,
    platform: ConsumerPlatform,
    mapping: Mapping,
    noninteractive: bool,
) -> Result<(), Error> {
    let extraction_started = Instant::now();
    let linux = platform != ConsumerPlatform::DarwinArm64;
    let mut command = if linux && unsafe { libc::geteuid() } != 0 {
        let mut command = Command::new("sudo");
        if noninteractive {
            command.arg("-n");
        }
        command.arg("tar");
        command
    } else {
        Command::new("tar")
    };
    // Never use tar's absolute-name or directory-symlink-following switches.
    // Selecting only backend inputs prevents an archive from installing host state.
    command.args(["-xpf", "-", "-C"]).arg(stage);
    if linux {
        command.args([
            "--numeric-owner",
            "--same-owner",
            "--acls",
            "--xattrs",
            "--xattrs-include=*",
        ]);
    }
    command.arg("--");
    if linux {
        command.args(["rootfs-tree", "cache-paths.txt"]);
    } else {
        command.args(["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]);
    }
    let mut errors = tempfile::tempfile_in(stage.parent().ok_or("guest stage has no parent")?)?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(errors.try_clone()?)
        .spawn()?;
    let copy = (|| -> Result<(), Error> {
        let mut output = child.stdin.take().ok_or("tar input is unavailable")?;
        let decoder = zstd::stream::read::Decoder::new(fs::File::open(input)?)?;
        // Give the decoder a full zstd-block buffer instead of small copy chunks.
        let mut decoder = BufReader::with_capacity(128 * 1024, decoder);
        std::io::copy(&mut decoder, &mut output)?;
        Ok(())
    })();
    let status = child.wait()?;
    errors.seek(SeekFrom::Start(0))?;
    let mut diagnostic = Vec::new();
    errors.take(4096).read_to_end(&mut diagnostic)?;
    let diagnostic = String::from_utf8_lossy(&diagnostic);
    if !status.success() {
        return Err(format!("cannot extract guest archive ({status}): {diagnostic}").into());
    }
    copy?;
    if !diagnostic.is_empty() {
        eprintln!("Guest extraction warnings: {diagnostic}");
    }
    validate_assets(
        stage,
        platform,
        Mapping::for_bases(ARCHIVE_BASE, ARCHIVE_BASE),
    )?;
    // A top-level symlink cannot stand in for the Linux rootfs directory.
    if linux && !fs::symlink_metadata(stage.join("rootfs-tree"))?.is_dir() {
        return Err("archive rootfs-tree must be a directory, not a link".into());
    }
    eprintln!(
        "SafeYolo: guest archive decoded and extracted in {:.3}s.",
        extraction_started.elapsed().as_secs_f64()
    );
    if linux {
        let ownership_started = Instant::now();
        // The private-stage remapper checks every owner and hard link before
        // changing anything. Reuse that traversal for all mappings, including
        // unchanged root IDs with guest-user ownership or named ACLs to shift.
        // Library tests run under libtest; only the built CLI dispatches host
        // commands. Both native test lanes supply this existing fixture input.
        #[cfg(test)]
        let executable = std::env::var_os("SAFEYOLO_NATIVE_CLI")
            .ok_or("set SAFEYOLO_NATIVE_CLI to the built native CLI for acquisition tests")?;
        #[cfg(not(test))]
        let executable = std::env::current_exe()?;
        let mut remap = Command::new("sudo");
        if noninteractive {
            remap.arg("-n");
        }
        remap
            .arg("--")
            .arg(executable)
            .args(["host", "remap-rootfs"])
            .arg(stage.join("rootfs-tree"))
            .arg(mapping.uid_base.to_string())
            .arg(mapping.gid_base.to_string())
            .arg(mapping.host_uid.to_string())
            .arg(mapping.host_gid.to_string());
        if !remap.status()?.success() {
            return Err("guest ownership preparation failed; no mapped tree was published. Repair the reported privilege or filesystem failure, then retry the installer".into());
        }
        validate_assets(stage, platform, mapping)?;
        eprintln!(
            "SafeYolo: guest ownership prepared in {:.3}s.",
            ownership_started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

pub(super) fn prepare(
    input: &Path,
    destination: &Path,
    platform: ConsumerPlatform,
    mapping: Mapping,
    early_cancellation: Option<&AtomicBool>,
) -> Result<(), Error> {
    let parent = destination.parent().ok_or("guest tree has no parent")?;
    let stage = tempfile::Builder::new()
        .prefix("extract-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?
        .keep();
    // Early cache preparation cannot ask for privilege or change host settings.
    // Finish and reap extraction/remapping before observing cancellation, so
    // cleanup cannot race a child still writing into the private stage.
    let result = extract(
        input,
        &stage,
        platform,
        mapping,
        early_cancellation.is_some(),
    )
    .and_then(|()| {
        if early_cancellation.is_some_and(|cancelled| cancelled.load(Ordering::Acquire)) {
            Err("early guest preparation interrupted".into())
        } else {
            Ok(())
        }
    })
    .and_then(|()| {
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).map_err(Into::into)
    })
    .and_then(|()| fs::rename(&stage, destination).map_err(Into::into));
    if let Err(error) = result {
        if let Err(cleanup) = remove_stage(&stage, platform) {
            return Err(format!("{error}; staging cleanup failed: {cleanup}").into());
        }
        if early_cancellation.is_some_and(|cancelled| !cancelled.load(Ordering::Acquire)) {
            eprintln!(
                "SafeYolo: early guest preparation could not finish: {error}. The installer will prepare the verified archive after host consent."
            );
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}
