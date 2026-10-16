//! Explicitly change the default guest for future sandbox boots.

use std::{os::unix::fs::PermissionsExt, process::Command};

use super::*;

/// Reuse the installer's Linux links and Darwin image clones in a new directory.
pub(super) fn install_inputs(
    root: &Path,
    selection: &GuestSelection,
    platform: ConsumerPlatform,
) -> Result<PathBuf, Error> {
    let parent = root.join("share/guest-versions/sha256");
    fs::create_dir_all(&parent)?;
    let mapping = crate::linux_host::mapping_for_root(root)?;
    let digest = guest_oci::sha256_hex(&selection.archive.digest)?;
    // Match Linux acquisition's mapping identity without retargeting legacy links.
    let destination = if platform == ConsumerPlatform::DarwinArm64 {
        parent.join(digest)
    } else {
        parent.join(mapping.tree_name(digest))
    };
    if destination.try_exists()? {
        let mut retained = selection.clone();
        retained.installed_assets = Some(destination.clone());
        retained.validate_inputs(root, platform)?;
        return Ok(destination);
    }
    let stage = tempfile::Builder::new()
        .prefix("install-")
        .tempdir_in(&parent)?;
    if platform == ConsumerPlatform::DarwinArm64 {
        for name in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"] {
            let status = Command::new("cp")
                .arg("-c")
                .arg(selection.assets.join(name))
                .arg(stage.path().join(name))
                .status()?;
            if !status.success() {
                return Err(format!("cannot clone guest input: {name}").into());
            }
            fs::File::open(stage.path().join(name))?.sync_all()?;
        }
    } else {
        std::os::unix::fs::symlink(
            selection.assets.join("rootfs-tree").canonicalize()?,
            stage.path().join("rootfs-tree"),
        )?;
        fs::copy(
            selection.assets.join("cache-paths.txt"),
            stage.path().join("cache-paths.txt"),
        )?;
        fs::File::open(stage.path().join("cache-paths.txt"))?.sync_all()?;
    }
    archive::validate_assets(stage.path(), platform, mapping)?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o755))?;
    fs::File::open(stage.path())?.sync_all()?;
    fs::rename(stage.path(), &destination)?;
    fs::File::open(&parent)?.sync_all()?;
    Ok(destination)
}

fn save(root: &Path, selection: &GuestSelection) -> Result<(), Error> {
    // The complete current/previous pair is one durable replacement. Boot
    // snapshots this file once; no series of file/link changes is observable.
    crate::coord_supervisor::atomic_write(
        &root.join("share/guest-selection.json"),
        &serde_json::to_vec_pretty(selection)?,
        0o600,
    )
}

async fn upgrade(
    root: &Path,
    package: &PackageGuest,
    client: &Client,
    store: &Path,
    index: Option<&str>,
) -> Result<GuestSelection, Error> {
    let current = installed(root, package)?
        .ok_or("no installed OCI guest selection; install a default guest before upgrading")?;
    let mut selected = acquire(
        client,
        package,
        store,
        index,
        Some(&current),
        crate::linux_host::mapping_for_root(root)?,
    )
    .await?;
    if selected.index == current.index
        && selected.manifest == current.manifest
        && selected.archive == current.archive
    {
        return Ok(current);
    }
    if selected.archive == current.archive {
        // Release identities can change without changing backend bytes.
        selected.installed_assets = current.installed_assets.clone();
    } else {
        selected.installed_assets = Some(install_inputs(root, &selected, package.platform)?);
    }
    let mut previous = current;
    previous.previous = None;
    selected.previous = Some(Box::new(previous));
    selected.validate_inputs(root, package.platform)?;
    save(root, &selected)?;
    Ok(selected)
}

fn rollback(root: &Path, package: &PackageGuest) -> Result<GuestSelection, Error> {
    let mut current: GuestSelection =
        serde_json::from_slice(&fs::read(root.join("share/guest-selection.json"))?)?;
    // A failed new guest must not prevent restoration of the retained inputs.
    let Some(previous) = current.previous.take() else {
        current.validate(package)?;
        current.validate_inputs(root, package.platform)?;
        return Ok(current);
    };
    previous.validate(package)?;
    previous.validate_inputs(root, package.platform)?;
    save(root, &previous)?;
    Ok(*previous)
}

pub(super) async fn run(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    let rollback_requested = arguments[0] == "rollback";
    let mut index = None;
    let mut options = arguments[1..].iter();
    while let Some(option) = options.next() {
        if rollback_requested {
            return Err("guest rollback takes no options".into());
        }
        let value = options
            .next()
            .ok_or("guest upgrade option requires a value")?;
        if option == "--index" && index.is_none() {
            let digest = value.to_str().ok_or("guest index digest must be UTF-8")?;
            guest_oci::sha256_hex(digest)?;
            index = Some(digest);
        } else {
            return Err("unknown or duplicate guest upgrade option".into());
        }
    }
    if !root.join("config.toml").is_file() {
        return Err("guest upgrade and rollback require an installed instance".into());
    }
    let root = root.canonicalize()?;
    let package = PackageGuest::read(&root.join("package-info"))?;
    let _install_lock = crate::host_platform::lock_host_state(&root.join("guest-install.lock"))?;
    let selected = if rollback_requested {
        rollback(&root, &package)?
    } else {
        let current = installed(&root, &package)?
            .ok_or("no installed OCI guest selection; install a default guest before upgrading")?;
        let store = current
            .assets
            .ancestors()
            .nth(3)
            .ok_or("installed guest store path is missing")?
            .to_path_buf();
        let store = store.canonicalize()?;
        let _store_lock = crate::host_platform::lock_host_state(&store.join("acquire.lock"))?;
        upgrade(&root, &package, &registry_client()?, &store, index).await?
    };
    eprintln!(
        "Selected guest {} {} for the next sandbox boot. Running guests are unchanged.",
        selected.version, selected.archive.digest
    );
    println!("{}", serde_json::to_string_pretty(&selected)?);
    Ok(())
}
