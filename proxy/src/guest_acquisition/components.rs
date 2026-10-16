//! Explicit host/guest targets, with one durable link selecting the complete pair.

use std::{
    collections::BTreeSet,
    ffi::CString,
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    },
    process::Command,
};

use ring::digest::{Context, SHA256};
use serde_json::{Value, json};

use super::*;

pub(super) const HELP: &str = "safeyolo [--root ROOT] upgrade status\nsafeyolo [--root ROOT] upgrade --release host-COMMIT [--guest-index sha256:DIGEST]\nsafeyolo [--root ROOT] upgrade --bundle UNPACKED_DIRECTORY [--guest-index sha256:DIGEST]\nsafeyolo [--root ROOT] upgrade rollback\nSelect an explicit host release or verified local bundle. Keep the installed guest unless --guest-index selects another OCI index.\nValidate and stage the complete compatible pair before activation. Existing processes keep running; restart the proxy and agents to use the selected components.\nRollback restores the previous host/guest pair without a download. Configuration, credentials, logs and agent homes stay in ROOT.\nGuest-only changes remain available through guest upgrade and guest rollback.\nFor an older host without this command, run a new bundle's bin/safeyolo --root ROOT upgrade --bundle UNPACKED_DIRECTORY.\nThe first upgrade retains ROOT/safeyolo-upgrade. Use ROOT/safeyolo-upgrade status, --release, --bundle or rollback even after selecting an older host.\nKeep ROOT/versions, ROOT/host-packages and ROOT/upgrade-tools: active, rollback and upgrade commands use them.";

// These are the host payload paths produced by build_host_packages.sh.
const HOST_PATHS: &[&str] = &[
    "bin",
    "libexec",
    "lib",
    "assets",
    "package-info",
    "SHA256SUMS",
    "LICENSE",
    "install.sh",
    "install_native.sh",
    "native_package.sh",
];

const INSTALLER_FILES: &[&str] = &["install.sh", "install_native.sh", "native_package.sh"];

fn legacy_installer_omissions(package: &Path) -> bool {
    INSTALLER_FILES.iter().all(|name| {
        fs::symlink_metadata(package.join(name))
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

fn hash_file(path: &Path) -> Result<String, Error> {
    let mut input = fs::File::open(path)?;
    let mut hash = Context::new(&SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn sync_directory(path: &Path) -> Result<(), Error> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn checked_command(mut command: Command, action: &str) -> Result<(), Error> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "{action} failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(4096)]),
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)]),
        )
        .into());
    }
    Ok(())
}

fn payload_files(
    directory: &Path,
    relative: &Path,
    files: &mut BTreeSet<PathBuf>,
    visited: &mut BTreeSet<PathBuf>,
) -> Result<(), Error> {
    let path = directory.join(relative);
    // Follow package links for hashing, as the existing installer does. A link
    // to a directory is walked at its package-relative name.
    if path.is_dir() {
        if !visited.insert(path.canonicalize()?) {
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            payload_files(
                directory,
                &relative.join(entry?.file_name()),
                files,
                visited,
            )?;
        }
    } else if path.is_file() {
        files.insert(path.canonicalize()?);
    } else {
        return Err(format!(
            "host package input is missing or is not a file: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn verify_package(package: &Path, installed: bool) -> Result<PackageGuest, Error> {
    let metadata = PackageGuest::read(&package.join("package-info"))?;
    let legacy_installed = installed && legacy_installer_omissions(package);
    let mut checked = BTreeSet::new();
    for line in fs::read_to_string(package.join("SHA256SUMS"))?.lines() {
        let (hash, name) = line
            .split_once("  ./")
            .ok_or("invalid host package checksum entry")?;
        guest_oci::sha256_hex(&format!("sha256:{hash}"))?;
        let path = Path::new(name);
        if path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || !checked.insert(path.to_path_buf())
        {
            return Err("invalid or duplicate host package checksum path".into());
        }
        if legacy_installed && INSTALLER_FILES.contains(&name) {
            continue;
        }
        if hash_file(&package.join(path))? != hash {
            return Err(format!("host package checksum differs: {name}").into());
        }
    }
    // The producer omits links from its inventory. A linked file is covered
    // when its target is one of the hashed files (for example license aliases).
    let checked = checked
        .iter()
        .filter(|path| {
            !legacy_installed || !INSTALLER_FILES.iter().any(|name| *path == Path::new(name))
        })
        .map(|path| package.join(path).canonicalize())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut files = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in HOST_PATHS.iter().filter(|name| **name != "SHA256SUMS") {
        if legacy_installed && INSTALLER_FILES.contains(name) {
            continue;
        }
        if *name == "lib" && !package.join(name).exists() {
            continue;
        }
        payload_files(package, Path::new(name), &mut files, &mut visited)?;
    }
    if !files.is_subset(&checked) {
        return Err("host package payload is missing from SHA256SUMS".into());
    }
    // Check complete hashes before executing any target program. Keep the
    // existing source/profile, runtime and signed-helper checks after them.
    let mut command = Command::new("bash");
    command
        .args(["--noprofile", "--norc", "-c"])
        .arg(concat!(
            include_str!("../../../scripts/native_package.sh"),
            "\nverify_native_package \"$1\" \"$2\"\n"
        ))
        .arg("verify-host-package")
        .arg(package)
        .arg(if installed { "--installed" } else { "" });
    checked_command(command, "host package verification")?;
    Ok(metadata)
}

fn verify_configuration(root: &Path, host: &Path) -> Result<(), Error> {
    let mut command = Command::new(host.join("bin/safeyolo"));
    command
        .args(["config", "check"])
        .arg(root.join("config.toml"));
    checked_command(command, "target configuration validation")
}

fn current_set(root: &Path) -> Result<Option<PathBuf>, Error> {
    let link = root.join("current");
    match fs::symlink_metadata(&link) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.is_symlink() => {
            let set = link.canonicalize()?;
            if set.parent() != Some(root.join("versions").as_path()) {
                return Err(
                    "installed current link does not select a retained component pair".into(),
                );
            }
            Ok(Some(set))
        }
        Ok(_) => Err("installed current path is not a component selection link".into()),
    }
}

fn host_path(root: &Path, set: Option<&Path>) -> PathBuf {
    set.filter(|set| *set != root.join("versions/initial") || set.join("share").is_dir())
        .map_or_else(|| root.to_path_buf(), |set| set.join("host"))
}

pub(super) fn installed_paths(root: &Path) -> Result<(PathBuf, PathBuf), Error> {
    let root = root.canonicalize()?;
    let set = current_set(&root)?;
    let host = host_path(&root, set.as_deref());
    if host == root {
        return Ok((host, root.join("share")));
    }
    Ok((
        host,
        set.map_or_else(|| root.join("share"), |set| set.join("share")),
    ))
}

pub(super) fn retained_host_binaries(root: &Path, name: &str) -> Result<Vec<PathBuf>, Error> {
    let mut binaries = vec![root.join("bin").join(name)];
    let initial = root.join("versions/initial/host/bin").join(name);
    if initial.is_file() {
        binaries.push(initial);
    }
    let packages = root.join("host-packages");
    if packages.try_exists()? {
        for entry in fs::read_dir(packages)? {
            let entry = entry?;
            // Incomplete stages are not retained executable identities.
            let filename = entry.file_name();
            let Some(filename) = filename.to_str() else {
                continue;
            };
            if filename.len() == 64 && filename.bytes().all(|b| b.is_ascii_hexdigit()) {
                binaries.push(entry.path().join("bin").join(name));
            }
        }
    }
    Ok(binaries)
}

fn replace_link(root: &Path, name: &str, target: &Path) -> Result<(), Error> {
    let stage = tempfile::Builder::new()
        .prefix("activate-")
        .tempdir_in(root)?;
    symlink(target, stage.path().join(name))?;
    sync_directory(stage.path())?;
    fs::rename(stage.path().join(name), root.join(name))?;
    sync_directory(root)
}

/// Exchange a legacy payload with its alias without an absent-path interval.
fn exchange(left: &Path, right: &Path) -> Result<(), Error> {
    let left = CString::new(left.as_os_str().as_bytes())?;
    let right = CString::new(right.as_os_str().as_bytes())?;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe { libc::renamex_np(left.as_ptr(), right.as_ptr(), libc::RENAME_SWAP) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn import_path(root: &Path, initial: &Path, name: &str, host: bool) -> Result<(), Error> {
    let relative = if host {
        Path::new("host").join(name)
    } else {
        PathBuf::from(name)
    };
    let destination = initial.join(&relative);
    let source = root.join(name);
    let alias = root.join("current").join(&relative);
    if fs::read_link(&source).ok().as_ref() == Some(&alias) {
        return Ok(());
    }
    // Empty lib/share directories also make proxy-only installations usable.
    if !source.try_exists()? && matches!(name, "lib" | "share") {
        fs::create_dir(&source)?;
    }
    if fs::symlink_metadata(&destination).is_err() {
        symlink(&alias, &destination)?;
        sync_directory(destination.parent().ok_or("import path has no parent")?)?;
    } else if fs::read_link(&destination)? != alias {
        return Err(format!(
            "component import path already exists: {}",
            destination.display()
        )
        .into());
    }
    exchange(&source, &destination)?;
    sync_directory(root)?;
    sync_directory(destination.parent().ok_or("import path has no parent")?)
}

fn import_installation(root: &Path) -> Result<PathBuf, Error> {
    let legacy_installed = legacy_installer_omissions(root);
    let initial = root.join("versions/initial");
    if current_set(root)?.is_none() && initial.try_exists()? {
        let existing = fs::read_dir(&initial)?.collect::<Result<Vec<_>, _>>()?;
        if existing.iter().any(|entry| entry.file_name() != "host")
            || (initial.join("host").try_exists()?
                && fs::read_dir(initial.join("host"))?.next().is_some())
        {
            return Err("existing versions/initial contents were preserved; move that unrelated directory before upgrading".into());
        }
    }
    for path in [root.join("versions"), initial.clone(), initial.join("host")] {
        fs::create_dir_all(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    sync_directory(&initial)?;
    sync_directory(&root.join("versions"))?;
    if current_set(root)?.is_none() {
        replace_link(root, "current", &initial)?;
    }
    // An interrupted first upgrade resumes these same exchanges. Every path
    // still supplies the original bytes until the complete target is selected.
    for name in HOST_PATHS {
        if legacy_installed && INSTALLER_FILES.contains(name) {
            continue;
        }
        import_path(root, &initial, name, true)?;
    }
    import_path(root, &initial, "share", false)?;
    Ok(initial)
}

fn sync_payload(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            sync_payload(&entry?.path())?;
        }
        sync_directory(path)?;
    } else if metadata.is_file() {
        fs::File::open(path)?.sync_all()?;
    }
    Ok(())
}

fn stage_host(root: &Path, package: &Path) -> Result<PathBuf, Error> {
    let parent = root.join("host-packages");
    fs::create_dir_all(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))?;
    let destination = parent.join(hash_file(&package.join("SHA256SUMS"))?);
    if destination.try_exists()? {
        verify_package(&destination, false)?;
        return Ok(destination);
    }
    let stage = tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(&parent)?;
    for name in HOST_PATHS {
        if *name == "lib" && !package.join(name).exists() {
            fs::create_dir(stage.path().join(name))?;
            continue;
        }
        let mut command = Command::new("cp");
        command
            .arg("-R")
            .arg(package.join(name))
            .arg(stage.path().join(name));
        checked_command(command, "host package staging")?;
    }
    verify_package(stage.path(), false)?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o755))?;
    sync_payload(stage.path())?;
    fs::rename(stage.path(), &destination)?;
    sync_directory(&parent)?;
    Ok(destination)
}

fn stage_share(
    root: &Path,
    destination: &Path,
    guest: Option<&GuestSelection>,
) -> Result<(), Error> {
    let source = root.join("share");
    // All pairs retain the same immutable guest-version directory. Older
    // binaries can still perform their native guest-only upgrades through it.
    fs::create_dir_all(source.join("guest-versions"))?;
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        if entry.file_name() == "guest-selection.json" {
            continue;
        }
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_file() {
            fs::hard_link(entry.path(), target)?;
        } else {
            symlink(entry.path().canonicalize()?, target)?;
        }
    }
    if let Some(guest) = guest {
        crate::coord_supervisor::atomic_write(
            &destination.join("guest-selection.json"),
            &serde_json::to_vec_pretty(guest)?,
            0o600,
        )?;
    }
    sync_directory(destination)
}

fn describe(host: &Path, share: &Path) -> Result<Value, Error> {
    PackageGuest::read(&host.join("package-info"))?;
    let fields = fs::read_to_string(host.join("package-info"))?;
    let fields = fields
        .lines()
        .map(|line| line.split_once('=').ok_or("invalid package-info field"))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let guest = if share.join("guest-selection.json").try_exists()? {
        serde_json::from_slice::<Value>(&fs::read(share.join("guest-selection.json"))?)?
    } else {
        Value::Null
    };
    Ok(
        json!({"host":fields, "host_checksums_sha256":hash_file(&host.join("SHA256SUMS"))?, "guest":guest}),
    )
}

fn status(root: &Path) -> Result<Value, Error> {
    let set = current_set(root)?;
    let (host, share) = installed_paths(root)?;
    let previous = if let Some(set) = &set {
        if set.join("previous").try_exists()? {
            let previous = set.join("previous").canonicalize()?;
            Some(describe(&previous.join("host"), &previous.join("share"))?)
        } else {
            None
        }
    } else {
        None
    };
    Ok(json!({"current":describe(&host, &share)?, "previous":previous}))
}

async fn prepare_guest(
    root: &Path,
    package: &PackageGuest,
    current: Option<&GuestSelection>,
    index: &str,
) -> Result<GuestSelection, Error> {
    let store = if let Some(current) = current {
        current
            .assets
            .ancestors()
            .nth(3)
            .ok_or("installed guest store path is missing")?
            .to_path_buf()
    } else {
        PathBuf::from(
            std::env::var_os("HOME")
                .ok_or("HOME is required for the persistent guest directory")?,
        )
        .join(".local/share/safeyolo/guests")
    };
    fs::create_dir_all(&store)?;
    let store = store.canonicalize()?;
    let _store_lock = crate::host_platform::lock_host_state(&store.join("acquire.lock"))?;
    let mut selected = acquire(
        &registry_client()?,
        package,
        &store,
        Some(index),
        current,
        crate::linux_host::mapping_for_root(root)?,
    )
    .await?;
    if let Some(current) = current.filter(|current| {
        current.index == selected.index
            && current.manifest == selected.manifest
            && current.archive == selected.archive
    }) {
        current.validate(package)?;
        return Ok(current.clone());
    }
    if let Some(current) = current.filter(|current| current.archive == selected.archive) {
        selected.installed_assets = current.installed_assets.clone();
    } else {
        selected.installed_assets =
            Some(upgrade::install_inputs(root, &selected, package.platform)?);
    }
    selected.validate_inputs(root, package.platform)?;
    selected.previous = current.map(|current| {
        let mut previous = current.clone();
        previous.previous = None;
        Box::new(previous)
    });
    Ok(selected)
}

fn retain_upgrader(root: &Path) -> Result<(), Error> {
    let entry = root.join("safeyolo-upgrade");
    if fs::symlink_metadata(&entry).is_ok()
        && !fs::read_link(&entry).is_ok_and(|target| target.starts_with(root.join("upgrade-tools")))
    {
        return Err("existing safeyolo-upgrade path was preserved; move that unrelated file before upgrading".into());
    }
    let executable = std::env::current_exe()?;
    let digest = hash_file(&executable)?;
    let parent = root.join("upgrade-tools").join(&digest);
    fs::create_dir_all(&parent)?;
    let destination = parent.join("safeyolo-upgrade");
    if destination.try_exists()? {
        if hash_file(&destination)? != digest {
            return Err(
                "retained upgrade executable checksum differs; active components were preserved"
                    .into(),
            );
        }
    } else {
        let temporary = tempfile::NamedTempFile::new_in(&parent)?;
        fs::copy(executable, temporary.path())?;
        temporary.as_file().sync_all()?;
        temporary.persist_noclobber(&destination)?;
        sync_directory(&parent)?;
        sync_directory(&root.join("upgrade-tools"))?;
    }
    replace_link(root, "safeyolo-upgrade", &destination)
}

pub(super) async fn run(root: &Path, arguments: &[OsString]) -> Result<(), Error> {
    if matches!(arguments, [help] if help == "--help") {
        println!("{HELP}");
        return Ok(());
    }
    let mut bundle = None;
    let mut release = None;
    let mut index = None;
    let status_requested = matches!(arguments, [command] if command == "status");
    let rollback_requested = matches!(arguments, [command] if command == "rollback");
    if !status_requested && !rollback_requested {
        let mut options = arguments.iter();
        while let Some(option) = options.next() {
            let value = options.next().ok_or("upgrade option requires a value")?;
            if option == "--bundle" && bundle.is_none() && release.is_none() {
                bundle = Some(PathBuf::from(value));
            } else if option == "--release" && release.is_none() && bundle.is_none() {
                release = Some(value.to_str().ok_or("host release must be UTF-8")?);
            } else if option == "--guest-index" && index.is_none() {
                let value = value.to_str().ok_or("guest index must be UTF-8")?;
                guest_oci::sha256_hex(value)?;
                index = Some(value);
            } else {
                return Err(format!("unknown or duplicate upgrade option\n{HELP}").into());
            }
        }
        if bundle.is_none() && release.is_none() && index.is_none() {
            return Err(
                format!("select an explicit host release, bundle or guest index\n{HELP}").into(),
            );
        }
    }
    let root = root.canonicalize()?;
    if !root.join("config.toml").is_file() {
        return Err("upgrade requires an installed native instance".into());
    }
    // The same lock serializes existing guest-only upgrades and complete pairs.
    let _lock = crate::host_platform::lock_host_state(&root.join("guest-install.lock"))?;
    if status_requested {
        println!("{}", serde_json::to_string_pretty(&status(&root)?)?);
        return Ok(());
    }
    if rollback_requested {
        let current = current_set(&root)?.ok_or("no previous host/guest pair is installed")?;
        if current.join("previous").try_exists()? {
            let previous = current.join("previous").canonicalize()?;
            let package = verify_package(&previous.join("host"), true)?;
            verify_configuration(&root, &previous.join("host"))?;
            if previous.join("share/guest-selection.json").try_exists()? {
                let guest: GuestSelection = serde_json::from_slice(&fs::read(
                    previous.join("share/guest-selection.json"),
                )?)?;
                guest.validate(&package)?;
                guest.validate_inputs(&root, package.platform)?;
            }
            replace_link(&root, "current", &previous)?;
        }
        println!("{}", serde_json::to_string_pretty(&status(&root)?)?);
        return Ok(());
    }
    if current_set(&root)?.as_deref() == Some(root.join("versions/initial").as_path()) {
        // Until import finishes, the top-level aliases and original paths
        // together still form the complete original package.
        verify_package(&root, true)?;
        import_installation(&root)?;
    }
    let current = current_set(&root)?;
    let current_host = host_path(&root, current.as_deref());
    let old_package = verify_package(&current_host, true)?;
    let old_guest = installed(&root, &old_package)?;
    let downloads = tempfile::Builder::new()
        .prefix("upgrade-")
        .tempdir_in(&root)?;
    if let Some(release) = release {
        let bootstrap = downloads.path().join("acquire.sh");
        fs::write(&bootstrap, include_str!("../../../install.sh"))?;
        let target = downloads.path().join("host");
        let mut command = Command::new("bash");
        command
            .arg(bootstrap)
            .args(["--release", release, "--download-only"])
            .arg(&target);
        checked_command(command, "host release acquisition")?;
        bundle = Some(target);
    }
    let target = bundle.as_deref().unwrap_or(&current_host);
    let package = verify_package(target, bundle.is_none())?;
    let selected = if let Some(index) = index {
        Some(prepare_guest(&root, &package, old_guest.as_ref(), index).await?)
    } else {
        if let Some(guest) = &old_guest {
            guest.validate(&package)?;
        }
        if old_package.compatibility != package.compatibility {
            return Err("target host requires another guest compatibility identifier; select a compatible --guest-index explicitly".into());
        }
        old_guest.clone()
    };
    let same_host =
        fs::read(target.join("SHA256SUMS"))? == fs::read(current_host.join("SHA256SUMS"))?;
    let same_guest = serde_json::to_value(&selected)? == serde_json::to_value(&old_guest)?;
    if same_host && same_guest {
        println!("{}", serde_json::to_string_pretty(&status(&root)?)?);
        return Ok(());
    }
    verify_configuration(&root, target)?;
    let staged_host = if same_host {
        None
    } else {
        Some(stage_host(&root, target)?)
    };
    retain_upgrader(&root)?;
    let current = match current {
        Some(set) if set != root.join("versions/initial") => set,
        _ => import_installation(&root)?,
    };
    let host = staged_host.unwrap_or(current.join("host").canonicalize()?);
    let parent = root.join("versions");
    let stage = tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(&parent)?;
    symlink(host, stage.path().join("host"))?;
    symlink(&current, stage.path().join("previous"))?;
    stage_share(&root, &stage.path().join("share"), selected.as_ref())?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o755))?;
    sync_directory(stage.path())?;
    let destination = parent.join(uuid::Uuid::new_v4().simple().to_string());
    fs::rename(stage.path(), &destination)?;
    sync_directory(&parent)?;
    replace_link(&root, "current", &destination)?;
    println!("{}", serde_json::to_string_pretty(&status(&root)?)?);
    Ok(())
}
