//! Prepare only missing Ubuntu host prerequisites, with explained consent.

use crate::{
    Error,
    linux_host::{self, ID_COUNT, Mapping, Settings},
};
use serde_json::json;
use std::{
    ffi::CString,
    fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

fn command_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

fn execute(command: &mut Command, purpose: &str, applied: &mut Vec<String>) -> Result<(), Error> {
    let status = command.status().map_err(|e| format!("{purpose}: {e}"))?;
    if !status.success() {
        return Err(format!("{purpose} failed ({status}); repair the reported host operation and run the installer again").into());
    }
    applied.push(purpose.into());
    Ok(())
}

fn privilege(program: &str) -> Command {
    let mut command = Command::new("sudo");
    command.arg("--").arg(program);
    command
}

fn allocation_limits(kind: &str) -> Result<(u32, u32), Error> {
    let text = fs::read_to_string("/etc/login.defs")?;
    let mut minimum = 100000;
    let mut maximum = 600100000;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some(key) if key == format!("SUB_{kind}_MIN") => {
                minimum = fields
                    .next()
                    .ok_or("missing subordinate allocation minimum")?
                    .parse()?
            }
            Some(key) if key == format!("SUB_{kind}_MAX") => {
                maximum = fields
                    .next()
                    .ok_or("missing subordinate allocation maximum")?
                    .parse()?
            }
            _ => (),
        }
    }
    Ok((minimum, maximum))
}

#[repr(C)]
struct ShadowRange {
    owner: *const libc::c_char,
    start: libc::c_ulong,
    count: libc::c_ulong,
}
type Grant = unsafe extern "C" fn(*mut ShadowRange, bool) -> bool;
type Ungrant = unsafe extern "C" fn(*mut ShadowRange) -> bool;

/// Use Ubuntu's public libsubid ABI. Its grant operation finds a free range
/// while holding the same shadow lock used by useradd and usermod.
fn allocate_ids(uid: u32) -> Result<(), Error> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "subordinate-ID allocation needs the installer's privileged account operation".into(),
        );
    }
    let owner = linux_host::login(uid)?;
    let owner_c = CString::new(owner.as_bytes())?;
    let library =
        unsafe { libc::dlopen(c"libsubid.so.4".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if library.is_null() {
        return Err(
            "Ubuntu libsubid.so.4 is missing; install libsubid4 and retry host preparation".into(),
        );
    }
    let result = (|| -> Result<(), Error> {
        for (file, kind, database, grant_name, ungrant_name) in [
            (
                "/etc/subuid",
                "UID",
                "passwd",
                c"subid_grant_uid_range",
                c"subid_ungrant_uid_range",
            ),
            (
                "/etc/subgid",
                "GID",
                "group",
                c"subid_grant_gid_range",
                c"subid_ungrant_gid_range",
            ),
        ] {
            let ranges = linux_host::host_ranges(file, &owner, uid)?;
            let ids = linux_host::occupied_ids(database)?;
            if linux_host::existing_base(&ranges, &owner, &ids).is_some() {
                continue;
            }
            let (minimum, maximum) = allocation_limits(kind)?;
            let start = linux_host::free_base(&ranges, &ids, minimum, maximum)?;
            let grant = unsafe { libc::dlsym(library, grant_name.as_ptr()) };
            let ungrant = unsafe { libc::dlsym(library, ungrant_name.as_ptr()) };
            if grant.is_null() || ungrant.is_null() {
                return Err(
                    "host libsubid does not provide Ubuntu's supported allocation API".into(),
                );
            }
            // dlsym is bound to the public signatures in shadow 4.13 subid.h.
            let grant: Grant = unsafe { std::mem::transmute(grant) };
            let ungrant: Ungrant = unsafe { std::mem::transmute(ungrant) };
            let mut range = ShadowRange {
                owner: owner_c.as_ptr(),
                start: start.into(),
                count: ID_COUNT.into(),
            };
            if !unsafe { grant(&mut range, false) } {
                return Err(format!("locked {file} allocation failed; no runtime settings were published. Check shadow's diagnostic and available allocation limits").into());
            }
            // The library rechecks all occupied subordinate ranges under its
            // lock. Also check the returned range against host IDs and limits.
            let end = range.start.checked_add(range.count);
            let occupied = match linux_host::occupied_ids(database) {
                Ok(ids) => ids,
                Err(error) => {
                    let removed = unsafe { ungrant(&mut range) };
                    return Err(format!("{error}; new {file} range {}:{} removal {}. No runtime settings were published",range.start,range.count,if removed{"succeeded"}else{"failed; ask the administrator to remove that allocation"}).into());
                }
            };
            let valid = range.start >= minimum.into()
                && end
                    .is_some_and(|end| end <= u64::from(maximum) + 1 && end <= u64::from(u32::MAX))
                && !occupied.iter().any(|id| {
                    u64::from(*id) >= range.start && end.is_some_and(|end| u64::from(*id) < end)
                });
            if !valid {
                if !unsafe { ungrant(&mut range) } {
                    return Err(format!("{file} allocated {}:{} but validation and removal failed; ask the host administrator to remove that new allocation before retrying",range.start,range.count).into());
                }
                return Err(format!("{file} allocation changed during setup; the new allocation was removed. Repair host allocation limits and retry").into());
            }
            if !linux_host::host_ranges(file, &owner, uid)?.iter().any(|r| {
                r.owner == owner
                    && u64::from(r.start) <= range.start
                    && u64::from(r.start) + u64::from(r.count) >= end.unwrap_or(u64::MAX)
            }) {
                return Err(format!("shadow reported a {file} allocation but its saved range could not be verified; inspect {file} before retrying. No runtime settings were published").into());
            }
            eprintln!(
                "SafeYolo: allocated {kind} range {}–{} for {owner} in {file}.",
                range.start,
                range.start + range.count - 1
            );
        }
        Ok(())
    })();
    unsafe { libc::dlclose(library) };
    result
}

fn profile_name(runtime: &Path) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        runtime.as_os_str().as_encoded_bytes(),
    );
    format!(
        "safeyolo-runsc-{}",
        digest.as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn profile_text(name: &str, runtime: &Path) -> Result<String, Error> {
    let path = runtime
        .to_str()
        .ok_or("AppArmor runtime path must be UTF-8")?;
    // Quote AppArmor path metacharacters as literals, not additional rules.
    let mut escaped = String::new();
    for c in path.chars() {
        if matches!(c, '\n' | '\r' | '\0') {
            return Err("AppArmor runtime path contains a control character".into());
        }
        if matches!(c, '\\' | '"' | '*' | '?' | '[' | ']' | '{' | '}' | '^') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    Ok(format!(
        "abi <abi/4.0>,\ninclude <tunables/global>\n\n# SafeYolo permits rootless namespaces for this installed runtime.\nprofile {name} \"{escaped}\" flags=(unconfined) {{\n  userns,\n}}\n"
    ))
}

fn load_profile(runtime: &Path) -> Result<(), Error> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "loading the runtime profile requires the installer's privileged profile operation"
                .into(),
        );
    }
    let name = profile_name(runtime);
    let text = profile_text(&name, runtime)?;
    let path = Path::new("/etc/apparmor.d").join(&name);
    let check_existing = || -> Result<(), Error> {
        if fs::read_to_string(&path)? != text {
            return Err(format!(
                "existing AppArmor profile {} differs and was preserved",
                path.display()
            )
            .into());
        }
        Ok(())
    };
    if path.try_exists()? {
        check_existing()?;
    } else {
        let mut temporary = tempfile::NamedTempFile::new_in("/etc/apparmor.d")?;
        temporary.write_all(text.as_bytes())?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => (),
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => check_existing()?,
            Err(error) => return Err(error.into()),
        }
        fs::File::open("/etc/apparmor.d")?.sync_all()?;
    }
    let status = Command::new("apparmor_parser")
        .arg("-r")
        .arg(&path)
        .status()?;
    if !status.success() {
        return Err(format!("AppArmor could not load {}; the profile file remains. Repair the reported parser or kernel failure, then retry host preparation",path.display()).into());
    }
    Ok(())
}

fn runtime_access_changes(runtime: &Path, uid: u32) -> Result<Vec<(PathBuf, String, bool)>, Error> {
    let mut paths: Vec<_> = runtime
        .ancestors()
        .skip(1)
        .map(|p| (p.to_owned(), false))
        .collect();
    let parent = runtime.parent().ok_or("runtime has no parent")?;
    paths.extend(super::runsc::FILES.iter().map(|name| {
        (
            if *name == "runsc" {
                runtime.to_owned()
            } else {
                parent.join(name)
            },
            true,
        )
    }));
    paths
        .into_iter()
        .filter_map(|(path, file)| access_change(&path, uid, if file { 5 } else { 1 }).transpose())
        .collect()
}

fn access_change(
    path: &Path,
    uid: u32,
    needed: u32,
) -> Result<Option<(PathBuf, String, bool)>, Error> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let bits = metadata.permissions().mode();
    if bits & needed == needed || metadata.uid() == uid && (bits >> 6) & needed == needed {
        return Ok(None);
    }
    let output = Command::new("getfacl").args(["-ncp"]).arg(path).output()?;
    if !output.status.success() {
        return Err(format!("cannot check access to {}", path.display()).into());
    }
    let text = std::str::from_utf8(&output.stdout)?;
    let prefix = format!("user:{uid}:");
    let permissions = |value: &str| -> u32 {
        value.chars().take(3).fold(0, |bits, c| {
            bits | match c {
                'r' => 4,
                'w' => 2,
                'x' => 1,
                _ => 0,
            }
        })
    };
    let old = text
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(permissions)
        .unwrap_or(0);
    let mask = text
        .lines()
        .find_map(|line| line.strip_prefix("mask::"))
        .map(permissions)
        .unwrap_or(7);
    if old & mask & needed == needed {
        return Ok(None);
    }
    let bits = old | needed;
    let permissions = format!(
        "{}{}{}",
        if bits & 4 != 0 { 'r' } else { '-' },
        if bits & 2 != 0 { 'w' } else { '-' },
        if bits & 1 != 0 { 'x' } else { '-' }
    );
    Ok(Some((
        path.to_owned(),
        permissions,
        metadata.uid() != unsafe { libc::getuid() },
    )))
}

fn grant_access(
    change: (PathBuf, String, bool),
    uid: u32,
    applied: &mut Vec<String>,
) -> Result<(), Error> {
    let (path, permissions, needs_sudo) = change;
    let mut command = if needs_sudo {
        privilege("setfacl")
    } else {
        Command::new("setfacl")
    };
    execute(
        command
            .args(["-m", &format!("u:{uid}:{permissions}")])
            .arg(&path),
        &format!("allow UID {uid} {permissions} access to {}", path.display()),
        applied,
    )
}

fn runtime_access(runtime: &Path, uid: u32, applied: &mut Vec<String>) -> Result<(), Error> {
    for change in runtime_access_changes(runtime, uid)? {
        grant_access(change, uid, applied)?;
    }
    Ok(())
}

fn kvm_access(mapping: Mapping, applied: &mut Vec<String>) -> Result<(), Error> {
    for uid in [mapping.host_uid, mapping.uid_base] {
        if let Some(change) = access_change(Path::new("/dev/kvm"), uid, 6)? {
            grant_access(change, uid, applied)?;
        }
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|error| {
            format!(
                "KVM device access failed: {error}; repair /dev/kvm access and retry host prepare"
            )
        })?;
    Ok(())
}

fn restricted() -> Result<bool, Error> {
    match fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        Ok(text) => match text.trim() {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err("invalid AppArmor namespace restriction setting".into()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn namespaces_enabled() -> Result<(), Error> {
    for (file, disabled) in [
        ("/proc/sys/user/max_user_namespaces", "0"),
        ("/proc/sys/kernel/unprivileged_userns_clone", "0"),
    ] {
        match fs::read_to_string(file) {
            Ok(text) if text.trim() == disabled => return Err(format!("{file} disables unprivileged user namespaces. Ask the host administrator to enable supported rootless namespaces, then retry. SafeYolo did not change this global setting").into()),
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn probe_namespace(profile: Option<&str>) -> Result<(), Error> {
    let mut command = if let Some(profile) = profile {
        let mut command = Command::new("aa-exec");
        command.args(["-p", profile, "--", "unshare"]);
        command
    } else {
        Command::new("unshare")
    };
    let output = command.args(["-Urn", "true"]).output()?;
    if !output.status.success() {
        return Err(format!("rootless namespace check failed: {}; repair the host namespace or AppArmor setup, then retry. No agent was started",String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(2048)])).into());
    }
    Ok(())
}

fn prepare(root: &Path, args: &[String], applied: &mut Vec<String>) -> Result<Settings, Error> {
    let mut bundle = root.to_owned();
    let mut installed_root = root.to_owned();
    let mut system_runsc = None;
    let mut platform_assets = None;
    let mut yes = false;
    let mut options = args.iter();
    while let Some(option) = options.next() {
        if option == "--yes" {
            yes = true;
            continue;
        }
        let value = options
            .next()
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--package-root" => bundle = PathBuf::from(value),
            "--installed-root" => installed_root = PathBuf::from(value),
            "--system-runsc" if system_runsc.is_none() => system_runsc = Some(PathBuf::from(value)),
            "--platform-assets" if platform_assets.is_none() => {
                platform_assets = Some(PathBuf::from(value))
            }
            "--write-settings" => (),
            _ => return Err(format!("unknown host preparation option: {option}").into()),
        }
    }
    if !args.windows(2).any(|a| a[0] == "--write-settings")
        && !root.join("config.toml").try_exists()?
    {
        return Err(
            "host prepare needs an installed config.toml; run the SafeYolo installer for first use"
                .into(),
        );
    }
    namespaces_enabled()?;
    let kvm = match std::env::var("SAFEYOLO_RUNSC_PLATFORM")
        .unwrap_or_default()
        .as_str()
    {
        "kvm" => true,
        "" | "auto" | "systrap" => false,
        _ => return Err("SAFEYOLO_RUNSC_PLATFORM must be auto, systrap or kvm".into()),
    };
    if kvm && !Path::new("/dev/kvm").try_exists()? {
        return Err("the selected KVM backend requires /dev/kvm; provide a supported KVM host or select SAFEYOLO_RUNSC_PLATFORM=systrap, then retry. No host changes were applied".into());
    }
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    if uid == 0 {
        return Err("run the installer or host prepare as your ordinary host account; use sudo only when preparation requests a specific host operation. Agents must not map to host root".into());
    }
    let owner = linux_host::login(uid)?;
    let existing = root.join("config.toml");
    let saved = if existing.try_exists()? {
        crate::native_config::read(&existing)?
            .native_settings
            .and_then(|s| s.linux)
    } else {
        None
    };
    let (source, destination, origin) = if let Some(path) = system_runsc {
        let path = path.canonicalize()?;
        (path.clone(), path, "system")
    } else if let Some(settings) = &saved {
        (
            settings.runsc.clone(),
            settings.runsc.clone(),
            settings.runsc_origin.as_str(),
        )
    } else {
        (
            bundle.join("libexec/runsc"),
            installed_root.join("libexec/runsc"),
            "bundled",
        )
    };
    if origin == "bundled" {
        super::runsc::verify_bundle_payload(
            source
                .parent()
                .and_then(Path::parent)
                .ok_or("bundled runtime has no package directory")?,
        )?;
    }
    linux_host::check_runtime(&source)?;
    let uid_ranges = linux_host::host_ranges("/etc/subuid", &owner, uid)?;
    let gid_ranges = linux_host::host_ranges("/etc/subgid", &owner, uid)?;
    let prepared_mapping = if let Some(assets) = platform_assets {
        let metadata = fs::metadata(assets.join("rootfs-tree"))?;
        let mapping = Mapping::for_bases(metadata.uid(), metadata.gid());
        linux_host::validate_current_mapping(mapping).map_err(|error| format!("prepared guest inputs do not match a safe mapping for this host account: {error}. The shared tree was preserved. Use inputs prepared for this account, or omit --platform-assets to acquire a separate mapped tree"))?;
        crate::guest_acquisition::validate_prepared_linux_assets(&assets, mapping)?;
        if let Some(settings) = &saved
            && settings.mapping()? != mapping
        {
            return Err("prepared guest mapping differs from this installation's saved mapping; both were preserved. Retain its existing guest inputs or use a separate installation".into());
        }
        Some(mapping)
    } else {
        None
    };
    let need_ranges =
        linux_host::existing_base(&uid_ranges, &owner, &linux_host::occupied_ids("passwd")?)
            .is_none()
            || linux_host::existing_base(&gid_ranges, &owner, &linux_host::occupied_ids("group")?)
                .is_none();
    if let Some(saved) = &saved {
        linux_host::validate_current_mapping(saved.mapping()?)?;
    }
    let apparmor = restricted()?;
    let name = profile_name(&destination);
    let text = profile_text(&name, &destination)?;
    let profile = Path::new("/etc/apparmor.d").join(&name);
    let missing_profile = apparmor && !profile.try_exists()?;
    if apparmor && !missing_profile && fs::read_to_string(&profile)? != text {
        return Err(format!("existing AppArmor profile {} differs and was preserved; ask the host administrator to reconcile this installation's profile",profile.display()).into());
    }
    let load_profile_needed =
        apparmor && (missing_profile || probe_namespace(Some(&name)).is_err());
    let mut packages = Vec::new();
    for (package, commands) in [
        ("uidmap", &["newuidmap", "newgidmap"][..]),
        ("acl", &["setfacl", "getfacl"][..]),
        ("util-linux", &["unshare", "nsenter"][..]),
        ("iproute2", &["ip"][..]),
        ("openssh-client", &["ssh"][..]),
        ("curl", &["curl"][..]),
        ("tar", &["tar"][..]),
        ("ca-certificates", &["update-ca-certificates"][..]),
    ] {
        if commands.iter().any(|name| command_path(name).is_none()) {
            packages.push(package);
        }
    }
    if need_ranges {
        let library =
            unsafe { libc::dlopen(c"libsubid.so.4".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if library.is_null() {
            packages.push("libsubid4");
        } else {
            unsafe { libc::dlclose(library) };
        }
    }
    if apparmor && command_path("aa-exec").is_none() {
        packages.push("apparmor-utils");
    }
    if apparmor && command_path("apparmor_parser").is_none() {
        packages.push("apparmor");
    }
    // Setup is supported on Ubuntu; already prepared contributor hosts need
    // no package changes and can retain their existing runtime paths.
    if !packages.is_empty()
        && !fs::read_to_string("/etc/os-release")?
            .lines()
            .any(|line| line == "ID=ubuntu" || line == "ID=\"ubuntu\"")
    {
        return Err(format!("automatic host package setup supports Ubuntu; missing packages: {}. Prepare these tools with your host package manager, then retry",packages.join(", ")).into());
    }
    let mut changes = Vec::new();
    if !packages.is_empty() {
        changes.push(format!(
            "install missing host packages: {}",
            packages.join(", ")
        ));
    }
    if need_ranges {
        changes.push(format!("allocate only missing unused subordinate UID/GID ranges for {owner}, preserving other accounts"));
    }
    if missing_profile {
        changes.push(format!(
            "install and load AppArmor profile {} for {}",
            profile.display(),
            destination.display()
        ));
    } else if load_profile_needed {
        changes.push(format!(
            "load the existing AppArmor profile {}",
            profile.display()
        ));
    }
    let planned_base = saved
        .as_ref()
        .map(|settings| settings.uid_base)
        .or(prepared_mapping.map(|mapping| mapping.uid_base))
        .or(linux_host::existing_base(
            &uid_ranges,
            &owner,
            &linux_host::occupied_ids("passwd")?,
        ));
    let access_needed = if let Some(base) = planned_base {
        if command_path("getfacl").is_some() {
            !runtime_access_changes(&destination, base)?.is_empty()
        } else {
            true
        }
    } else {
        true
    };
    if access_needed {
        changes.push("allow the selected sandbox-root UID to traverse private runtime parent directories and read or execute the selected runtime payload".into());
    }
    if kvm
        && (command_path("getfacl").is_none()
            || planned_base.is_none()
            || [uid, planned_base.unwrap_or(uid)].into_iter().any(|id| {
                access_change(Path::new("/dev/kvm"), id, 6).map_or(true, |change| change.is_some())
            }))
    {
        changes.push("allow only your host UID and the selected sandbox-root UID to read and write /dev/kvm for the selected KVM backend".into());
    }
    if !changes.is_empty() {
        eprintln!(
            "SafeYolo needs these host changes:\n  {}",
            changes.join("\n  ")
        );
        eprintln!(
            "Only the listed package, account and profile operations use sudo. The proxy and agent run as {owner}."
        );
        if !yes {
            eprint!("Allow these host changes? [y/N] ");
            io::stderr().flush()?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                return Err("host preparation was declined; no host changes were applied. Run the installer again when ready".into());
            }
        }
    }
    if !packages.is_empty() {
        execute(
            privilege("apt-get").args(["update", "-qq"]),
            "refresh Ubuntu package indexes",
            applied,
        )?;
        execute(
            privilege("apt-get")
                .args(["install", "-y", "--no-install-recommends"])
                .args(packages),
            "install required Ubuntu host packages (a failed apt operation may have installed some packages)",
            applied,
        )?;
    }
    if need_ranges {
        let executable = std::env::current_exe()?;
        applied.push("subordinate-ID allocation was requested; successful range writes are reported above and remain if a later range fails".into());
        execute(
            privilege(
                executable
                    .to_str()
                    .ok_or("installer executable path is not UTF-8")?,
            )
            .args(["host", "allocate-ids", &uid.to_string()]),
            "allocate missing subordinate IDs",
            applied,
        )?;
    }
    let mapping = if let Some(saved) = &saved {
        saved.mapping()?
    } else if let Some(mapping) = prepared_mapping {
        mapping
    } else {
        linux_host::current_mapping()?
    };
    linux_host::validate_current_mapping(mapping)?;
    if load_profile_needed {
        let executable = std::env::current_exe()?;
        applied.push(format!(
            "profile setup was requested; {} remains if the profile load fails",
            profile.display()
        ));
        execute(
            privilege(
                executable
                    .to_str()
                    .ok_or("installer executable path is not UTF-8")?,
            )
            .args(["host", "load-profile"])
            .arg(&destination),
            "load this runtime's AppArmor profile",
            applied,
        )?;
    }
    probe_namespace(apparmor.then_some(name.as_str()))?;
    // A private home may otherwise hide the installed runtime from mapped
    // sandbox root. Grant traversal to that one subordinate UID only.
    runtime_access(&destination, mapping.uid_base, applied)?;
    if kvm {
        kvm_access(mapping, applied)?;
    }
    Ok(Settings {
        host_uid: uid,
        host_gid: gid,
        uid_base: mapping.uid_base,
        gid_base: mapping.gid_base,
        runsc: destination,
        runsc_origin: origin.into(),
        apparmor_profile: apparmor.then_some(name),
    })
}

pub(super) fn run(root: &Path, args: &[String]) -> Result<(), Error> {
    match args {
        [help] if help == "--help" => {
            println!("{}", linux_host::HELP);
            Ok(())
        }
        [operation, uid] if operation == "allocate-ids" => allocate_ids(uid.parse()?),
        [operation, runtime] if operation == "load-profile" => load_profile(Path::new(runtime)),
        [operation] if operation == "grant-runtime-access" => {
            let settings = crate::native_config::read(&root.join("config.toml"))?
                .native_settings
                .and_then(|s| s.linux)
                .ok_or("Linux runtime settings are missing")?;
            let mut applied = Vec::new();
            runtime_access(&settings.runsc, settings.uid_base, &mut applied)
        }
        [operation, tree, uid, gid, host_uid, host_gid] if operation == "remap-rootfs" => {
            super::ownership::remap_tree(
                Path::new(tree),
                Mapping {
                    host_uid: host_uid.parse()?,
                    host_gid: host_gid.parse()?,
                    uid_base: uid.parse()?,
                    gid_base: gid.parse()?,
                },
            )
        }
        [operation, rest @ ..] if operation == "prepare" => {
            let mut applied = Vec::new();
            let result = (|| -> Result<(), Error> {
                let settings = prepare(root, rest, &mut applied)?;
                let mut document = toml_edit::DocumentMut::new();
                document["linux"] = toml_edit::Item::Table(toml_edit::Table::new());
                document["linux"]["uid_base"] = toml_edit::value(i64::from(settings.uid_base));
                document["linux"]["gid_base"] = toml_edit::value(i64::from(settings.gid_base));
                document["linux"]["host_uid"] = toml_edit::value(i64::from(settings.host_uid));
                document["linux"]["host_gid"] = toml_edit::value(i64::from(settings.host_gid));
                document["linux"]["runsc"] =
                    toml_edit::value(settings.runsc.to_str().ok_or("runtime path is not UTF-8")?);
                document["linux"]["runsc_origin"] = toml_edit::value(&settings.runsc_origin);
                if let Some(profile) = &settings.apparmor_profile {
                    document["linux"]["apparmor_profile"] = toml_edit::value(profile);
                }
                let output = rest
                    .windows(2)
                    .find(|args| args[0] == "--write-settings")
                    .map(|args| PathBuf::from(&args[1]));
                if let Some(output) = output {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&output)?;
                    file.write_all(document.to_string().as_bytes())?;
                    file.sync_all()?;
                } else {
                    let path = root.join("config.toml");
                    let _lock = crate::host_platform::lock_host_state(
                        &root.join("data/native-listeners.lock"),
                    )?;
                    if crate::native_config::read(&path)?
                        .native_settings
                        .and_then(|s| s.linux)
                        .as_ref()
                        == Some(&settings)
                    {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(
                                &json!({"state":"prepared","linux":settings,"applied":applied})
                            )?
                        );
                        return Ok(());
                    }
                    let mut existing: toml_edit::DocumentMut =
                        fs::read_to_string(&path)?.parse()?;
                    existing["linux"] = document["linux"].clone();
                    crate::coord_supervisor::atomic_write(
                        &path,
                        existing.to_string().as_bytes(),
                        0o600,
                    )?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"state":"prepared","linux":settings,"applied":applied})
                    )?
                );
                Ok(())
            })();
            result.map_err(|error|format!("{error}\nHost changes and attempted operations: {}. Completed changes remain; retry reuses valid prerequisites",if applied.is_empty(){"none".into()}else{applied.join("; ")}).into())
        }
        _ => Err(format!("use host prepare\n{}", linux_host::HELP).into()),
    }
}
