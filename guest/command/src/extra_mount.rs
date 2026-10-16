//! Host-selected extra mounts. The guest never selects a host directory.

use crate::{Error, Paths};
use serde_json::{Value, json};
use std::{
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io::{BufRead, Write},
    os::{fd::AsRawFd, unix::ffi::OsStrExt, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

const EXPORTS: &str = "/safeyolo/extra-mounts";
const TAG: &str = "safeyolo-extra";

fn unescape(value: &str) -> Result<String, Error> {
    let mut bytes = Vec::new();
    let mut input = value.as_bytes().iter().copied();
    while let Some(byte) = input.next() {
        if byte == b'\\' {
            let digits = [input.next(), input.next(), input.next()];
            let [
                Some(a @ b'0'..=b'7'),
                Some(b @ b'0'..=b'7'),
                Some(c @ b'0'..=b'7'),
            ] = digits
            else {
                return Err("invalid mountinfo escape".into());
            };
            bytes.push(((a - b'0') << 6) | ((b - b'0') << 3) | (c - b'0'));
        } else {
            bytes.push(byte);
        }
    }
    Ok(String::from_utf8(bytes)?)
}

fn mounts_from(input: &str) -> Result<Vec<Value>, Error> {
    input.split('\n').filter(|line| !line.is_empty()).map(|line| {
        let (before, after) = line.split_once(" - ").ok_or("invalid mountinfo row")?;
        let fields: Vec<_> = before.split(' ').collect();
        let fs: Vec<_> = after.split(' ').collect();
        if fields.len() < 6 || fs.len() < 3 { return Err("incomplete mountinfo row".into()); }
        Ok(json!({"mount_id":fields[0].parse::<u64>()?, "root":unescape(fields[3])?,
            "path":unescape(fields[4])?, "options":fields[5], "filesystem":fs[0], "source":unescape(fs[1])?}))
    }).collect()
}

fn mounts() -> Result<Vec<Value>, Error> {
    mounts_from(&fs::read_to_string("/proc/self/mountinfo")?)
}

fn check_path(path: &Path) -> Result<(), Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| part == std::path::Component::ParentDir)
        || ["/workspace", "/home/agent"]
            .iter()
            .any(|root| Path::new(root).starts_with(path))
        || ["/dev", "/proc", "/sys", "/safeyolo", "/safeyolo-status"]
            .iter()
            .any(|root| path.starts_with(root) || Path::new(root).starts_with(path))
    {
        return Err("extra mount destination is invalid or reserved".into());
    }
    Ok(())
}

struct Target {
    _directory: File,
    descriptor: PathBuf,
    resolved: PathBuf,
}

impl Target {
    fn open(path: &Path, create: bool) -> Result<Self, Error> {
        check_path(path)?;
        // Check the existing parent before mkdir, including symlink aliases.
        let mut existing = path;
        while !existing.exists() {
            existing = existing.parent().ok_or("missing destination parent")?;
        }
        let resolved_parent = existing.canonicalize()?;
        let candidate = resolved_parent.join(path.strip_prefix(existing)?);
        check_path(&candidate)?;
        if create {
            fs::create_dir_all(path)?;
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(path)?;
        let descriptor = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let resolved = fs::read_link(&descriptor)?;
        check_path(&resolved)?;
        Ok(Self {
            _directory: directory,
            descriptor,
            resolved,
        })
    }

    fn validate_add(&self, mounted: &[Value]) -> Result<(), Error> {
        if mounted
            .iter()
            .filter_map(|row| row["path"].as_str())
            .any(|path| Path::new(path).starts_with(&self.resolved))
        {
            return Err("extra mount destination would conceal an existing mount".into());
        }
        Ok(())
    }
}

fn inspect(path: &Path, expected: Option<u64>) -> Result<Value, Error> {
    check_path(path)?;
    let mounted = mounts()?;
    let resolved = if path.exists() {
        path.canonicalize()?
    } else {
        path.to_path_buf()
    };
    check_path(&resolved)?;
    let at_target = mounted
        .iter()
        .rev()
        .find(|row| row["path"].as_str().map(Path::new) == Some(&resolved));
    let expected_mount = expected.and_then(|id| mounted.iter().find(|row| row["mount_id"] == id));
    Ok(json!({"resolved_path":resolved, "mount":at_target, "expected_mount":expected_mount}))
}

fn call_mount(
    source: Option<&Path>,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
) -> Result<(), Error> {
    let source = source
        .map(|path| CString::new(path.as_os_str().as_bytes()))
        .transpose()?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let kind = kind.map(CString::new).transpose()?;
    if unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn exports() -> Result<PathBuf, Error> {
    fs::create_dir_all(EXPORTS)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(EXPORTS)?;
    let fd = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    if fs::read_link(&fd)? != Path::new(EXPORTS) {
        return Err("extra export directory changed".into());
    }
    if let Some(existing) = mounts()?.iter().find(|row| row["path"] == EXPORTS) {
        if existing["filesystem"] != "virtiofs"
            || existing["source"] != TAG
            || existing["root"] != "/"
        {
            return Err("extra export mount is not the prepared VirtioFS device".into());
        }
    } else {
        call_mount(
            Some(Path::new(TAG)),
            &fd,
            Some("virtiofs"),
            libc::MS_NOSUID | libc::MS_NODEV,
        )?;
    }
    Ok(PathBuf::from(EXPORTS))
}

fn bind(id: &str, path: &Path) -> Result<Value, Error> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid extra share ID".into());
    }
    let target = Target::open(path, true)?;
    target.validate_add(&mounts()?)?;
    let source = exports()?.join(id);
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(source)?;
    let source = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    call_mount(Some(&source), &target.descriptor, None, libc::MS_BIND)?;
    // VZSharedDirectory enforces each export's mode. A bind of one child
    // cannot change the mode of the shared backing device or another child.
    inspect(&target.resolved, None)
}

fn unmount(path: &Path, expected: u64) -> Result<Value, Error> {
    let observation = inspect(path, Some(expected))?;
    if observation["expected_mount"].is_null() {
        return Ok(observation);
    }
    if observation["mount"]["mount_id"] != expected {
        return Err("share mount identity or destination changed; removal was refused".into());
    }
    // An open descriptor on the mounted directory would itself make normal
    // unmount busy. Pin only its parent and recheck the selected mount ID.
    let resolved = Path::new(
        observation["resolved_path"]
            .as_str()
            .ok_or("missing resolved path")?,
    );
    let parent = resolved.parent().ok_or("missing share parent")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(parent)?;
    let fd = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    if fs::read_link(&fd)? != parent {
        return Err("share parent changed; removal was refused".into());
    }
    let target = fd.join(resolved.file_name().ok_or("missing share filename")?);
    if inspect(path, Some(expected))?["mount"]["mount_id"] != expected {
        return Err("share mount identity changed; removal was refused".into());
    }
    let pinned = CString::new(target.as_os_str().as_bytes())?;
    if unsafe { libc::umount2(pinned.as_ptr(), libc::UMOUNT_NOFOLLOW) } != 0 {
        return Err(format!(
            "extra mount removal refused; share remains available: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    inspect(resolved, Some(expected))
}

fn pin(path: &Path, create: bool) -> Result<i32, Error> {
    let target = if create {
        let target = Target::open(path, true)?;
        target.validate_add(&mounts()?)?;
        target
    } else {
        // Removal pins only the parent, which may be / for a top-level share.
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(path)?;
        let descriptor = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let resolved = fs::read_link(&descriptor)?;
        Target {
            _directory: directory,
            descriptor,
            resolved,
        }
    };
    let mut output = std::io::stdout().lock();
    write!(
        output,
        "{}\0{}\0{}\0",
        std::process::id(),
        target
            .resolved
            .to_str()
            .ok_or("share destination must be text")?,
        target._directory.as_raw_fd()
    )?;
    output.flush()?;
    let mut release = String::new();
    std::io::stdin().lock().read_line(&mut release)?;
    if release != "release\n" {
        return Err("share target connection closed before release".into());
    }
    Ok(0)
}

pub(crate) fn run(paths: &Paths, args: &[OsString]) -> Result<i32, Error> {
    let args = args
        .iter()
        .map(|arg| arg.to_str().ok_or("extra mount arguments must be text"))
        .collect::<Result<Vec<_>, _>>()?;
    let result = match args.as_slice() {
        [generation, operation, path, mode] if *operation == "pin" && matches!(*mode,"create"|"parent") => {
            if crate::generation(paths)? != *generation { return Err("sandbox generation changed; no mount was changed".into()); }
            return pin(Path::new(path),*mode=="create");
        }
        [generation, operation, path] if *operation == "prepare" || *operation == "inspect" => {
            if crate::generation(paths)? != *generation { return Err("sandbox generation changed; no mount was changed".into()); }
            if *operation == "prepare" { Target::open(Path::new(path), true)?.validate_add(&mounts()?)?; }
            inspect(Path::new(path), None)?
        }
        [generation, operation, path, id] if *operation == "inspect" || *operation == "unmount" => {
            if crate::generation(paths)? != *generation { return Err("sandbox generation changed; no mount was changed".into()); }
            let id = id.parse()?;
            if *operation == "unmount" { unmount(Path::new(path), id)? } else { inspect(Path::new(path), Some(id))? }
        }
        [generation, operation, id, path] if *operation == "bind" => {
            if crate::generation(paths)? != *generation { return Err("sandbox generation changed; no mount was changed".into()); }
            bind(id, Path::new(path))?
        }
        _ => return Err("extra-mount requires GENERATION prepare|inspect PATH [MOUNT_ID], bind ID PATH, or unmount PATH MOUNT_ID".into()),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_preserves_paths_and_mount_identity() {
        let rows = mounts_from("33 18 0:35 /a\\040b /mnt/line\\012tab\\011slash\\134\r rw,nosuid - virtiofs safeyolo-extra rw\n").unwrap();
        assert_eq!(rows[0]["mount_id"], 33);
        assert_eq!(rows[0]["path"], "/mnt/line\ntab\tslash\\\r");
        assert_eq!(rows[0]["root"], "/a b");
        assert!(mounts_from("broken\n").is_err());
    }

    #[test]
    fn resolved_targets_cannot_cover_control_mounts() {
        for path in [
            "/",
            "/home",
            "/home/agent",
            "/workspace",
            "/safeyolo/a",
            "/safeyolo/extra-mounts/a",
            "/mnt/../workspace",
        ] {
            assert!(check_path(Path::new(path)).is_err(), "{path}");
        }
        let fixture = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/proc", fixture.path().join("alias")).unwrap();
        assert!(Target::open(&fixture.path().join("alias/new"), true).is_err());
        let target = Target::open(fixture.path(), false).unwrap();
        assert!(
            target
                .validate_add(&[json!({"path":fixture.path().join("nested")})])
                .is_err()
        );
        assert!(target.validate_add(&[]).is_ok());
    }
}
