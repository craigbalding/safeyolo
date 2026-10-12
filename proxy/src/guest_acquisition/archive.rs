//! Decode the publisher's opaque tar archive with the host's maintained tar.

use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

use crate::{Error, guest_oci::ConsumerPlatform};

fn regular(path: &Path) -> Result<(), Error> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(format!("prepared guest file must be regular: {}", path.display()).into());
    }
    Ok(())
}

pub(super) fn validate_assets(path: &Path, platform: ConsumerPlatform) -> Result<(), Error> {
    if platform == ConsumerPlatform::DarwinArm64 {
        for name in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"] {
            regular(&path.join(name))?;
        }
    } else {
        let tree = path.join("rootfs-tree");
        let metadata = tree.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 100000 || metadata.gid() != 100000 {
            return Err(format!(
                "prepared rootfs-tree must be a directory owned by 100000:100000: {}",
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

fn extract(input: &Path, stage: &Path, platform: ConsumerPlatform) -> Result<(), Error> {
    let linux = platform != ConsumerPlatform::DarwinArm64;
    let mut command = if linux && unsafe { libc::geteuid() } != 0 {
        let mut command = Command::new("sudo");
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
        let mut decoder = zstd::stream::read::Decoder::new(fs::File::open(input)?)?;
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
    validate_assets(stage, platform)?;
    // A top-level symlink cannot stand in for the Linux rootfs directory.
    if linux && !fs::symlink_metadata(stage.join("rootfs-tree"))?.is_dir() {
        return Err("archive rootfs-tree must be a directory, not a link".into());
    }
    if linux {
        // build-rootfs.sh chowns the entire finished tree to sandbox root.
        // Check descendants too before exposing the prepared tree to installations.
        let mut command = if unsafe { libc::geteuid() } != 0 {
            let mut command = Command::new("sudo");
            command.arg("find");
            command
        } else {
            Command::new("find")
        };
        let checked = command
            .arg(stage.join("rootfs-tree"))
            .args([
                "-xdev", "(", "!", "-uid", "100000", "-o", "!", "-gid", "100000", ")", "-print",
                "-quit",
            ])
            .output()
            .map_err(|error| format!("cannot check rootfs ownership with find: {error}"))?;
        if !checked.status.success() {
            return Err("cannot check prepared rootfs ownership".into());
        }
        if !checked.stdout.is_empty() {
            return Err(
                "archive rootfs-tree entries must retain sandbox ownership 100000:100000".into(),
            );
        }
    }
    Ok(())
}

pub(super) fn prepare(
    input: &Path,
    destination: &Path,
    platform: ConsumerPlatform,
) -> Result<(), Error> {
    let parent = destination.parent().ok_or("guest tree has no parent")?;
    let stage = tempfile::Builder::new()
        .prefix("extract-")
        .tempdir_in(parent)?
        .keep();
    let result = extract(input, &stage, platform)
        .and_then(|()| {
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).map_err(Into::into)
        })
        .and_then(|()| fs::rename(&stage, destination).map_err(Into::into));
    if let Err(error) = result {
        if let Err(cleanup) = remove_stage(&stage, platform) {
            return Err(format!("{error}; staging cleanup failed: {cleanup}").into());
        }
        return Err(error);
    }
    Ok(())
}
