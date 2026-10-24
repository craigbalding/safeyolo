//! Prepare only missing Linux host prerequisites, with explained consent.

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
    process::{Command, Stdio},
};

fn command_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

const REQUIRED_PACKAGES: &[(&str, &[&str])] = &[
    ("uidmap", &["newuidmap", "newgidmap"]),
    ("acl", &["setfacl", "getfacl"]),
    ("util-linux", &["unshare", "nsenter"]),
    ("iproute2", &["ip"]),
    ("openssh-client", &["ssh"]),
    ("curl", &["curl"]),
    ("tar", &["tar"]),
];

fn host_tool_ready(name: &str) -> bool {
    let Some(path) = command_path(name) else {
        return false;
    };
    let arguments: &[&str] = match name {
        // Guest extraction preserves owners, ACLs and extended attributes.
        "tar" => &[
            "--numeric-owner",
            "--same-owner",
            "--acls",
            "--xattrs",
            "--xattrs-include=*",
            "--version",
        ],
        // Inspect one device's metadata without walking a host directory.
        // These are the ownership predicates used by guest acquisition.
        "find" => &[
            "/dev/null",
            "-xdev",
            "(",
            "-uid",
            "0",
            "-o",
            "-gid",
            "0",
            ")",
            "-print",
            "-quit",
        ],
        // Shared-directory Gofers need their child to stop with the launcher.
        // --version checks option parsing without creating a namespace.
        "unshare" => &["--kill-child=SIGKILL", "--version"],
        _ => return false,
    };
    Command::new(path)
        .args(arguments)
        .output()
        .is_ok_and(|output| output.status.success())
}

pub(super) fn check_prerequisites(
    root: &Path,
    settings: Option<&Settings>,
    mapping: Mapping,
) -> Result<(), Error> {
    namespaces_enabled()?;
    let missing: Vec<_> = REQUIRED_PACKAGES
        .iter()
        .flat_map(|(_, commands)| commands.iter().copied())
        .filter(|name| command_path(name).is_none())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "rootless Linux host tools are missing: {}; run safeyolo host prepare, then retry",
            missing.join(", ")
        )
        .into());
    }
    if restricted()? && settings.is_some_and(|s| s.apparmor_profile.is_none()) {
        return Err(
            "the selected runtime needs an AppArmor profile; run safeyolo host prepare, then retry"
                .into(),
        );
    }
    probe_namespace(root)?;
    runsc_platform(mapping)?;
    Ok(())
}

pub(crate) fn runsc_platform(mapping: Mapping) -> Result<&'static str, Error> {
    match std::env::var("SAFEYOLO_RUNSC_PLATFORM")
        .unwrap_or_default()
        .as_str()
    {
        "systrap" => Ok("systrap"),
        requested @ ("" | "auto" | "kvm") => {
            match check_kvm_access(Path::new("/dev/kvm"), mapping) {
                Ok(()) => Ok("kvm"),
                Err(error) if requested == "kvm" => Err(format!(
                    "the selected KVM backend is unavailable: {error}; run safeyolo host prepare with SAFEYOLO_RUNSC_PLATFORM=kvm, then retry"
                ).into()),
                Err(_) => Ok("systrap"),
            }
        }
        _ => Err("SAFEYOLO_RUNSC_PLATFORM must be auto, systrap or kvm".into()),
    }
}

fn check_kvm_access(path: &Path, mapping: Mapping) -> Result<(), Error> {
    // nsenter selects the mapped root and clears host supplementary groups.
    // runsc opens the device with that identity when creating the sandbox.
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot check KVM device {}: {error}", path.display()))?;
    let acl = read_acl(path)?;
    if !acl_allows(&metadata, &acl, mapping.uid_base, &[mapping.gid_base], 6) {
        return Err(format!(
            "mapped root UID {} cannot read and write {}",
            mapping.uid_base,
            path.display()
        )
        .into());
    }
    Ok(())
}

fn execute(command: &mut Command, purpose: &str, applied: &mut Vec<String>) -> Result<(), Error> {
    let record = applied.len();
    applied.push(format!("attempted {purpose}"));
    let status = command.status().map_err(|e| format!("{purpose}: {e}"))?;
    if !status.success() {
        return Err(format!("{purpose} failed ({status}); repair the reported host operation and run the installer again").into());
    }
    applied[record] = purpose.into();
    Ok(())
}

fn privilege(program: &str) -> Command {
    let mut command = Command::new("sudo");
    command.arg("--").arg(program);
    command
}

fn allocation_limits(kind: &str) -> Result<(u32, u32), Error> {
    let text = match fs::read_to_string("/etc/login.defs") {
        Ok(text) => text,
        // Minimal Alpine hosts can install shadow's allocator without its
        // account tools. Shadow uses these same defaults without login.defs.
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
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

fn open_subid_library() -> Option<*mut libc::c_void> {
    for name in [c"libsubid.so.4", c"libsubid.so.5"] {
        let library = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if !library.is_null() {
            return Some(library);
        }
    }
    None
}

/// Use shadow's public libsubid ABI. Its grant operation finds a free range
/// while holding the same shadow lock used by useradd and usermod.
/// Versions 4 (Ubuntu) and 5 (Alpine) share these range and grant signatures.
fn allocate_ids(uid: u32) -> Result<(), Error> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "subordinate-ID allocation needs the installer's privileged account operation".into(),
        );
    }
    let owner = linux_host::login(uid)?;
    let owner_c = CString::new(owner.as_bytes())?;
    let library = open_subid_library().ok_or(
        "shadow's libsubid.so.4 or libsubid.so.5 cannot load; run safeyolo host prepare to install the host's allocator, then retry",
    )?;
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
                    "host libsubid does not provide shadow's supported allocation API".into(),
                );
            }
            // dlsym is bound to the public signatures in shadow 4.13/4.17 subid.h.
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

fn profile_name(runtime: &Path, prefix: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        runtime.as_os_str().as_encoded_bytes(),
    );
    format!(
        "{prefix}-{}",
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

fn load_profile(runtime: &Path, prefix: &str) -> Result<(), Error> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "loading the runtime profile requires the installer's privileged profile operation"
                .into(),
        );
    }
    let name = profile_name(runtime, prefix);
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

fn runtime_access_changes(
    runtime: &Path,
    mapping: Mapping,
) -> Result<Vec<(PathBuf, String, bool)>, Error> {
    let mut paths: Vec<_> = runtime
        .ancestors()
        .skip(1)
        .map(|p| (p.to_owned(), false))
        .collect();
    let parent = runtime.parent().ok_or("runtime has no parent")?;
    paths.push((parent.join("gvisor-bin"), false));
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
        .filter_map(|(path, file)| {
            access_change(
                &path,
                mapping.uid_base,
                &[mapping.gid_base],
                if file { 5 } else { 1 },
            )
            .transpose()
        })
        .collect()
}

fn permissions(value: &str) -> u32 {
    value.chars().take(3).fold(0, |bits, c| {
        bits | match c {
            'r' => 4,
            'w' => 2,
            'x' => 1,
            _ => 0,
        }
    })
}

fn permission_text(bits: u32) -> String {
    format!(
        "{}{}{}",
        if bits & 4 != 0 { 'r' } else { '-' },
        if bits & 2 != 0 { 'w' } else { '-' },
        if bits & 1 != 0 { 'x' } else { '-' }
    )
}

fn read_acl(path: &Path) -> Result<String, Error> {
    let output = Command::new("getfacl").args(["-ncp"]).arg(path).output()?;
    if !output.status.success() {
        return Err(format!("cannot check access to {}", path.display()).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn acl_allows(metadata: &fs::Metadata, acl: &str, uid: u32, groups: &[u32], needed: u32) -> bool {
    let bits = metadata.permissions().mode();
    if metadata.uid() == uid {
        return (bits >> 6) & needed == needed;
    }
    let entry = |prefix: &str| {
        acl.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(permissions)
    };
    let mask = entry("mask::").unwrap_or(7);
    if let Some(named) = entry(&format!("user:{uid}:")) {
        return named & mask & needed == needed;
    }
    // A matching group must grant the whole requested operation. Do not
    // combine separate read and write entries to infer O_RDWR access.
    let mut matched_group = false;
    for gid in groups {
        for rights in [
            (metadata.gid() == *gid).then(|| entry("group::")).flatten(),
            entry(&format!("group:{gid}:")),
        ]
        .into_iter()
        .flatten()
        {
            matched_group = true;
            if rights & mask & needed == needed {
                return true;
            }
        }
    }
    !matched_group && bits & needed == needed
}

fn acl_grants(acl: &str, grants: &[(String, u32)]) -> String {
    let mask = acl
        .lines()
        .find_map(|line| line.strip_prefix("mask::"))
        .map(permissions)
        .unwrap_or(7);
    let new_mask = grants.iter().fold(mask, |mask, (_, rights)| mask | rights);
    let mut entries: Vec<_> = grants
        .iter()
        .map(|(prefix, rights)| format!("{prefix}{}", permission_text(*rights)))
        .collect();
    entries.push(format!("m::{}", permission_text(new_mask)));
    // A mask increase must not expose another user's or group's masked rights.
    for line in acl
        .lines()
        .filter(|line| !grants.iter().any(|(prefix, _)| line.starts_with(prefix)))
    {
        let mut fields = line.split(':');
        let (Some(kind), Some(id), Some(value)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if kind == "group" || kind == "user" && !id.is_empty() {
            let raw = permissions(value);
            if raw & new_mask != raw & mask {
                entries.push(format!("{kind}:{id}:{}", permission_text(raw & mask)));
            }
        }
    }
    entries.join(",")
}

fn access_change(
    path: &Path,
    uid: u32,
    groups: &[u32],
    needed: u32,
) -> Result<Option<(PathBuf, String, bool)>, Error> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let bits = metadata.permissions().mode();
    if metadata.uid() == uid {
        let owner = (bits >> 6) & 7;
        return Ok((owner & needed != needed).then(|| {
            (
                path.to_owned(),
                format!("u::{}", permission_text(owner | needed)),
                metadata.uid() != unsafe { libc::getuid() },
            )
        }));
    }
    // A named user entry takes precedence over other:: permissions. Read the
    // ACL even when the mode permits other users to traverse the directory.
    let text = read_acl(path)?;
    let prefix = format!("user:{uid}:");
    if acl_allows(&metadata, &text, uid, groups, needed) {
        return Ok(None);
    }
    let old = [4, 2, 1]
        .into_iter()
        .filter(|bit| acl_allows(&metadata, &text, uid, groups, *bit))
        .sum::<u32>();
    // other:: permissions were not subject to the old mask. Preserve them
    // when moving this UID into the masked named-user class.
    Ok(Some((
        path.to_owned(),
        acl_grants(&text, &[(prefix, old | needed)]),
        metadata.uid() != unsafe { libc::getuid() },
    )))
}

fn grant_access(
    change: (PathBuf, String, bool),
    identity: &str,
    applied: &mut Vec<String>,
) -> Result<(), Error> {
    let (path, acl, needs_sudo) = change;
    let mut command = if needs_sudo {
        privilege("setfacl")
    } else {
        Command::new("setfacl")
    };
    execute(
        command.args(["--no-mask", "-m", &acl]).arg(&path),
        &format!(
            "allow {identity} required access to {} while preserving other ACL permissions",
            path.display()
        ),
        applied,
    )
}

fn runtime_access(
    runtime: &Path,
    mapping: Mapping,
    applied: &mut Vec<String>,
) -> Result<(), Error> {
    for change in runtime_access_changes(runtime, mapping)? {
        grant_access(change, &format!("UID {}", mapping.uid_base), applied)?;
    }
    Ok(())
}

fn kvm_access_change(
    path: &Path,
    mapping: Mapping,
) -> Result<Option<(PathBuf, String, bool)>, Error> {
    let metadata = fs::metadata(path)?;
    if metadata.uid() == mapping.uid_base {
        return access_change(path, mapping.uid_base, &[mapping.gid_base], 6);
    }
    let acl = read_acl(path)?;
    let user = format!("user:{}:", mapping.uid_base);
    // Named-user device ACLs can be reset independently of group access.
    // Use the existing mapped root group, without changing namespace mappings.
    let without_user = acl
        .lines()
        .filter(|line| !line.starts_with(&user))
        .collect::<Vec<_>>()
        .join("\n");
    let mut grants = Vec::new();
    let mask = acl
        .lines()
        .find_map(|line| line.strip_prefix("mask::"))
        .map(permissions)
        .unwrap_or(7);
    if !acl_allows(
        &metadata,
        &without_user,
        mapping.uid_base,
        &[mapping.gid_base],
        6,
    ) {
        let group = if metadata.gid() == mapping.gid_base {
            "group::".to_owned()
        } else {
            format!("group:{}:", mapping.gid_base)
        };
        let old = acl
            .lines()
            .find_map(|line| line.strip_prefix(&group))
            .map(permissions)
            .unwrap_or(0)
            & mask;
        grants.push((group, old | 6));
    }
    if let Some(rights) = acl
        .lines()
        .find_map(|line| line.strip_prefix(&user))
        .map(permissions)
        && rights & mask & 6 != 6
    {
        // A named user denial takes precedence over the group grant.
        grants.push((user, (rights & mask) | 6));
    }
    Ok((!grants.is_empty()).then(|| {
        (
            path.to_owned(),
            acl_grants(&acl, &grants),
            metadata.uid() != unsafe { libc::getuid() },
        )
    }))
}

fn kvm_access(path: &Path, mapping: Mapping, applied: &mut Vec<String>) -> Result<(), Error> {
    if let Some(change) = kvm_access_change(path, mapping)? {
        grant_access(
            change,
            &format!(
                "mapped root GID {} (UID {})",
                mapping.gid_base, mapping.uid_base
            ),
            applied,
        )?;
    }
    check_kvm_access(path, mapping)
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

// Execute this installation's launcher so the kernel applies its attachment.
// change_profile (including aa-exec) retains restricted unconfined on newer hosts.
pub(super) const NAMESPACE_ENTRY: &[u8] = b"#!/bin/sh\nexec \"$@\"\n";

fn namespace_entry(root: &Path) -> PathBuf {
    root.join("host/namespace-entry")
}

pub(crate) fn namespace_command(root: &Path, program: &str) -> io::Result<Command> {
    let restricts = restricted().map_err(io::Error::other)?;
    #[cfg(test)]
    let restricts = match std::env::var("SAFEYOLO_TEST_FAILED_START_LAUNCH").as_deref() {
        Ok("direct") => false,
        Ok("apparmor" | "missing-entry") => true,
        _ => restricts,
    };
    Ok(if restricts {
        let entry = namespace_entry(root);
        fs::metadata(&entry).map_err(|error| io::Error::new(error.kind(), format!(
            "namespace entry {} is unavailable: {error}; run safeyolo host prepare, then retry",
            entry.display(),
        )))?;
        let mut command = Command::new(entry);
        command.arg(program);
        command
    } else {
        Command::new(program)
    })
}

#[cfg(test)]
pub(crate) struct TestNamespaceProfile(Option<PathBuf>);

#[cfg(test)]
impl TestNamespaceProfile {
    pub(crate) fn load(entry: &Path) -> Self {
        if !restricted().unwrap() {
            return Self(None);
        }
        let entry = entry.canonicalize().unwrap();
        let profile = entry.with_extension("apparmor");
        fs::write(
            &profile,
            profile_text(&profile_name(&entry, "safeyolo-test-userns"), &entry).unwrap(),
        )
        .unwrap();
        assert!(
            Command::new("sudo")
                .args(["-n", "apparmor_parser", "-r"])
                .arg(&profile)
                .status()
                .unwrap()
                .success()
        );
        Self(Some(profile))
    }
}

#[cfg(test)]
impl Drop for TestNamespaceProfile {
    fn drop(&mut self) {
        if let Some(profile) = &self.0 {
            let status = Command::new("sudo")
                .args(["-n", "apparmor_parser", "-R"])
                .arg(profile)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "namespace fixture profile was not removed"
            );
        }
    }
}

fn probe_namespace(root: &Path) -> Result<(), Error> {
    let mut command = namespace_command(root, "unshare")?;
    command.args(["-Urn", "true"]);
    let started = time::OffsetDateTime::now_utc();
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let finished = time::OffsetDateTime::now_utc();
        let read = |path: &Path| match fs::read_to_string(path) {
            Ok(text) => text.trim_end().to_owned(),
            Err(error) => format!("read failed: {error}"),
        };
        let mut diagnosis = format!(
            "namespace probe pid={pid} status={} started={started} finished={finished}\nsource={} command={command:?}\n",
            output.status,
            env!("SAFEYOLO_BUILD_REVISION"),
        );
        for name in [
            "apparmor_restrict_unprivileged_userns",
            "apparmor_restrict_unprivileged_unconfined",
        ] {
            diagnosis.push_str(&format!(
                "kernel.{name}={}\n",
                read(&Path::new("/proc/sys/kernel").join(name))
            ));
        }
        // Observe the selected transition separately, without changing the
        // namespace command or replacing its failed result.
        match namespace_command(root, "/bin/cat") {
            Ok(mut label) => {
                label.arg("/proc/self/attr/current");
                diagnosis.push_str(&format!("AppArmor label command={label:?}\n"));
                match label.output() {
                    Ok(label) => diagnosis.push_str(&format!(
                        "AppArmor label status={}\n{}{}",
                        label.status,
                        String::from_utf8_lossy(&label.stdout),
                        String::from_utf8_lossy(&label.stderr),
                    )),
                    Err(error) => {
                        diagnosis.push_str(&format!("AppArmor label read failed: {error}\n"))
                    }
                }
            }
            Err(error) => diagnosis.push_str(&format!("AppArmor label read failed: {error}\n")),
        }
        // Query only this probe's AppArmor denials during its execution window.
        // Do not request privilege or turn missing audit access into probe success.
        let mut audit = Command::new("journalctl");
        audit
            .args([
                "--dmesg",
                "--no-pager",
                "--output=short-iso-precise",
                "--since",
            ])
            .arg(format!("@{}", started.unix_timestamp()))
            .arg("--until")
            .arg(format!("@{}", finished.unix_timestamp() + 1))
            .arg("--grep")
            .arg(format!(r#"apparmor="DENIED".* pid={pid}( |$)"#));
        diagnosis.push_str(&format!("AppArmor audit command={audit:?}\n"));
        match audit.output() {
            Ok(audit) => diagnosis.push_str(&format!(
                "AppArmor audit status={}\n{}{}",
                audit.status,
                String::from_utf8_lossy(&audit.stdout),
                String::from_utf8_lossy(&audit.stderr),
            )),
            Err(error) => diagnosis.push_str(&format!("AppArmor audit read failed: {error}\n")),
        }
        return Err(format!("rootless namespace check failed: {}; repair the host namespace or AppArmor setup, then retry. No agent was started\n{diagnosis}",String::from_utf8_lossy(&output.stderr)).into());
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
            bundle.canonicalize()?.join("libexec/runsc"),
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
    let available_uid =
        linux_host::existing_base(&uid_ranges, &owner, &linux_host::occupied_ids("passwd")?);
    let available_gid =
        linux_host::existing_base(&gid_ranges, &owner, &linux_host::occupied_ids("group")?);
    let need_ranges = available_uid.is_none() || available_gid.is_none();
    if let Some(saved) = &saved {
        linux_host::validate_current_mapping(saved.mapping()?)?;
    }
    let apparmor = restricted()?;
    let name = profile_name(&destination, "safeyolo-runsc");
    let text = profile_text(&name, &destination)?;
    let profile = Path::new("/etc/apparmor.d").join(&name);
    let missing_profile = apparmor && !profile.try_exists()?;
    if apparmor && !missing_profile && fs::read_to_string(&profile)? != text {
        return Err(format!("existing AppArmor profile {} differs and was preserved; ask the host administrator to reconcile this installation's profile",profile.display()).into());
    }
    let entry = namespace_entry(root);
    let entry_missing = if apparmor {
        match fs::read(&entry) {
            Ok(bytes) if bytes == NAMESPACE_ENTRY => false,
            Ok(_) => {
                return Err(format!(
                    "existing namespace entry {} differs and was preserved",
                    entry.display()
                )
                .into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        }
    } else {
        false
    };
    let entry_setup_needed = apparmor && (entry_missing || probe_namespace(root).is_err());
    let load_profile_needed =
        apparmor && (missing_profile || (!entry_missing && entry_setup_needed));
    let mut packages = Vec::new();
    for &(package, commands) in REQUIRED_PACKAGES {
        if commands.iter().any(|name| command_path(name).is_none()) {
            packages.push(package);
        }
    }
    if need_ranges {
        if let Some(library) = open_subid_library() {
            unsafe { libc::dlclose(library) };
        } else {
            packages.push("libsubid4");
        }
    }
    if apparmor && command_path("apparmor_parser").is_none() {
        packages.push("apparmor");
    }
    // Already prepared contributor hosts need no package changes and retain
    // their runtime paths. Install only the missing tools on supported hosts.
    let release = fs::read_to_string("/etc/os-release");
    let alpine = release.as_ref().is_ok_and(|release| {
        release
            .lines()
            .any(|line| matches!(line, "ID=alpine" | "ID=\"alpine\""))
    });
    if alpine {
        for package in &mut packages {
            *package = match *package {
                "uidmap" => "shadow-subids",
                "util-linux" => "util-linux-misc",
                "libsubid4" => "shadow-libs",
                other => other,
            };
        }
        for (command, package) in [
            ("tar", "tar"),
            ("find", "findutils"),
            ("unshare", "util-linux-misc"),
        ] {
            if !host_tool_ready(command) && !packages.contains(&package) {
                packages.push(package);
            }
        }
    } else if !packages.is_empty() {
        // A prepared contributor host needs no distro metadata. Propagate a
        // read error only when automatic package setup actually needs it.
        if !release?
            .lines()
            .any(|line| matches!(line, "ID=ubuntu" | "ID=\"ubuntu\""))
        {
            return Err(format!("automatic host package setup supports Ubuntu and Alpine; missing packages: {}. Prepare these tools with your host package manager, then retry",packages.join(", ")).into());
        }
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
    if entry_setup_needed {
        changes.push(format!(
            "prepare namespace entry {} and load its installation-scoped AppArmor profile",
            entry.display()
        ));
    }
    let planned_mapping = saved
        .as_ref()
        .map(Settings::mapping)
        .transpose()?
        .or(prepared_mapping)
        .or(available_uid
            .zip(available_gid)
            .map(|(uid, gid)| Mapping::for_bases(uid, gid)));
    let access_needed = if let Some(mapping) = planned_mapping {
        if command_path("getfacl").is_some() {
            !runtime_access_changes(&destination, mapping)?.is_empty()
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
            || planned_mapping
                .map(|mapping| kvm_access_change(Path::new("/dev/kvm"), mapping))
                .transpose()?
                .flatten()
                .is_some()
            || planned_mapping.is_none())
    {
        changes.push("allow the selected sandbox-root GID to read and write /dev/kvm; repair a selected root UID denial if required, while preserving other ACL permissions".into());
    }
    if !changes.is_empty() {
        eprintln!(
            "SafeYolo needs these host changes:\n  {}",
            changes.join("\n  ")
        );
        eprintln!("Only the listed host operations use sudo. The proxy and agent run as {owner}.");
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
        if alpine {
            execute(
                privilege("apk").args(["add", "--no-cache"]).args(packages),
                "install required Alpine host packages (a failed APK operation may have installed some packages)",
                applied,
            )?;
        } else {
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
    if entry_setup_needed {
        fs::create_dir_all(entry.parent().ok_or("namespace entry has no parent")?)?;
        if entry_missing {
            let mut temporary = tempfile::NamedTempFile::new_in(entry.parent().unwrap())?;
            temporary.write_all(NAMESPACE_ENTRY)?;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o755))?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(&entry)?;
            applied.push(format!(
                "installed namespace entry {}; it remains if profile setup fails",
                entry.display()
            ));
        }
        fs::File::open(entry.parent().unwrap())?.sync_all()?;
        let executable = std::env::current_exe()?;
        execute(
            privilege(
                executable
                    .to_str()
                    .ok_or("installer executable path is not UTF-8")?,
            )
            .args(["host", "load-namespace-profile"])
            .arg(entry.canonicalize()?),
            "load this installation's namespace AppArmor profile",
            applied,
        )?;
    }
    probe_namespace(root)?;
    // A private home may otherwise hide the installed runtime from mapped
    // sandbox root. Grant traversal to that one subordinate UID only.
    runtime_access(&destination, mapping, applied)?;
    if kvm {
        kvm_access(Path::new("/dev/kvm"), mapping, applied)?;
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
        [operation, runtime] if operation == "load-profile" => {
            load_profile(Path::new(runtime), "safeyolo-runsc")
        }
        [operation, entry] if operation == "load-namespace-profile" => {
            load_profile(Path::new(entry), "safeyolo-userns")
        }
        [operation] if operation == "grant-runtime-access" => {
            let settings = crate::native_config::read(&root.join("config.toml"))?
                .native_settings
                .and_then(|s| s.linux)
                .ok_or("Linux runtime settings are missing")?;
            let mut applied = Vec::new();
            runtime_access(&settings.runsc, settings.mapping()?, &mut applied).map_err(|error| {
                format!(
                    "{error}\nHost changes and attempted operations: {}. Completed changes remain; retry the installer to finish runtime access",
                    if applied.is_empty() { "none".into() } else { applied.join("; ") }
                ).into()
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires getfacl, setfacl and a POSIX ACL-capable temporary directory"]
    fn kvm_access_checks_and_grants_only_the_mapped_root() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o000))
            .unwrap();
        let mapping = Mapping::for_bases(100000, 300000);
        let denied = check_kvm_access(file.path(), mapping)
            .unwrap_err()
            .to_string();
        assert!(denied.contains("mapped root UID 100000"), "{denied}");

        let mut applied = Vec::new();
        kvm_access(file.path(), mapping, &mut applied).unwrap();
        assert_eq!(applied.len(), 1);
        check_kvm_access(file.path(), mapping).unwrap();
        let acl = read_acl(file.path()).unwrap();
        assert!(acl.contains("group:300000:rw-"), "{acl}");
        assert!(acl.contains("user::---") && acl.contains("other::---"));
        assert!(!acl.contains("user:100000:"), "{acl}");
        assert!(!acl.contains(&format!("user:{}:", mapping.host_uid)));
        if mapping.host_uid != 0 {
            let denied = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file.path())
                .unwrap_err();
            assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        }

        applied.clear();
        kvm_access(file.path(), mapping, &mut applied).unwrap();
        assert!(applied.is_empty());
        assert_eq!(read_acl(file.path()).unwrap(), acl);

        // Repair an earlier user-only grant even while it currently permits
        // launch. A later named-user reset must leave mapped group access.
        assert!(
            Command::new("setfacl")
                .args(["--set", "u::---,u:100000:rw-,g::---,m::rw-,o::---"])
                .arg(file.path())
                .status()
                .unwrap()
                .success()
        );
        kvm_access(file.path(), mapping, &mut applied).unwrap();
        assert!(read_acl(file.path()).unwrap().contains("group:300000:rw-"));
        assert!(
            Command::new("setfacl")
                .args(["-x", "u:100000"])
                .arg(file.path())
                .status()
                .unwrap()
                .success()
        );
        check_kvm_access(file.path(), mapping).unwrap();
        applied.clear();
        kvm_access(file.path(), mapping, &mut applied).unwrap();
        assert!(applied.is_empty());

        // Increasing the mask must not expose another principal's masked
        // rights. A selected named-user denial must still be repaired.
        assert!(Command::new("setfacl").args(["--set", "u::---,u:100000:---,u:200000:rwx,g::rwx,g:300000:r--,g:400000:rwx,m::r--,o::---"]).arg(file.path()).status().unwrap().success());
        assert!(check_kvm_access(file.path(), mapping).is_err());
        kvm_access(file.path(), mapping, &mut applied).unwrap();
        let repaired = read_acl(file.path()).unwrap();
        for entry in [
            "user:100000:rw-",
            "user:200000:r--",
            "group::r--",
            "group:300000:rw-",
            "group:400000:r--",
        ] {
            assert!(repaired.contains(entry), "{repaired}");
        }
        check_kvm_access(file.path(), mapping).unwrap();

        assert!(
            Command::new("setfacl")
                .args(["--set", "u::---,g::rw-,o::---"])
                .arg(file.path())
                .status()
                .unwrap()
                .success()
        );
        let group_mapping = Mapping {
            gid_base: file.as_file().metadata().unwrap().gid(),
            ..mapping
        };
        check_kvm_access(file.path(), group_mapping).unwrap();
        assert!(check_kvm_access(file.path(), mapping).is_err());
        let missing = file.path().with_extension("missing");
        let error = check_kvm_access(&missing, mapping).unwrap_err().to_string();
        assert!(error.contains("cannot check KVM device"), "{error}");
        assert!(error.contains(&missing.display().to_string()), "{error}");
    }

    #[test]
    fn effective_access_honors_owner_named_user_groups_and_mask() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o606))
            .unwrap();
        let metadata = file.as_file().metadata().unwrap();
        let uid = metadata.uid() + 1;
        let gid = metadata.gid() + 1;
        let acl = format!("user::rw-\nuser:{uid}:---\ngroup::---\nmask::rw-\nother::rw-\n");
        assert!(acl_allows(&metadata, &acl, metadata.uid(), &[gid], 6));
        assert!(!acl_allows(&metadata, &acl, uid, &[gid], 6));
        let masked = acl
            .replace(&format!("user:{uid}:---"), &format!("user:{uid}:rw-"))
            .replace("mask::rw-", "mask::r--");
        assert!(acl_allows(&metadata, &masked, uid, &[gid], 4));
        assert!(!acl_allows(&metadata, &masked, uid, &[gid], 6));
        let unnamed = acl.replace(&format!("user:{uid}:---\n"), "");
        assert!(acl_allows(&metadata, &unnamed, uid, &[gid], 6));
        assert!(!acl_allows(&metadata, &unnamed, uid, &[metadata.gid()], 6));
        let groups = unnamed
            .replace("group::---", "group::r--")
            .replace("mask::rw-", &format!("group:{gid}:-w-\nmask::rw-"));
        assert!(acl_allows(
            &metadata,
            &groups,
            uid,
            &[metadata.gid(), gid],
            4
        ));
        assert!(acl_allows(
            &metadata,
            &groups,
            uid,
            &[metadata.gid(), gid],
            2
        ));
        assert!(!acl_allows(
            &metadata,
            &groups,
            uid,
            &[metadata.gid(), gid],
            6
        ));
        assert!(!acl_allows(
            &metadata,
            &groups.replace("mask::rw-", "mask::r--"),
            uid,
            &[gid],
            2
        ));
    }
}
