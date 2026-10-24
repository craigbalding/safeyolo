//! Shift only a newly extracted tree, without following links or losing modes.

use crate::{
    Error,
    linux_host::{ARCHIVE_BASE, ID_COUNT, Mapping},
};
use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
};

// O_PATH avoids opening devices and FIFOs in the archive. Every child lookup
// is relative to an already open directory and refuses the final symlink.
fn open_entry(parent: i32, name: &std::ffi::OsStr) -> Result<fs::File, Error> {
    let name = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn fd_path(file: &fs::File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn walk(
    file: &fs::File,
    path: &Path,
    visit: &mut impl FnMut(&fs::File, &fs::Metadata, &Path) -> Result<(), Error>,
) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        for entry in fs::read_dir(fd_path(file))? {
            let name = entry?.file_name();
            let child = open_entry(file.as_raw_fd(), &name)?;
            walk(&child, &path.join(name), visit)?;
        }
    }
    visit(file, &metadata, path)
}

struct OwnershipChange {
    path: PathBuf,
    metadata: fs::Metadata,
    uid: u32,
    gid: u32,
    attributes: Vec<(CString, Vec<u8>)>,
}

fn reopen_entry(root: &fs::File, path: &Path) -> Result<fs::File, Error> {
    let mut file = root.try_clone()?;
    // Paths come from walk, relative to the pinned root. Open one component
    // at a time: an intermediate symlink's O_PATH descriptor cannot be used
    // as a directory, and the final symlink is never followed either.
    for name in path {
        file = open_entry(file.as_raw_fd(), name)?;
    }
    Ok(file)
}

fn attributes(path: &CString) -> Result<Vec<(CString, Vec<u8>)>, Error> {
    let size = unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; size as usize];
    let length = unsafe { libc::listxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if length < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    names.truncate(length as usize);
    let mut result = Vec::new();
    for name in names.split(|c| *c == 0).filter(|name| !name.is_empty()) {
        let name = CString::new(name)?;
        let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut bytes = vec![0_u8; size as usize];
        let length = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        bytes.truncate(length as usize);
        result.push((name, bytes));
    }
    Ok(result)
}

fn shift_id(id: u32, base: u32, operator: u32) -> Result<u32, Error> {
    let offset = id.checked_sub(ARCHIVE_BASE).filter(|offset| *offset < ID_COUNT)
        .ok_or_else(|| format!("archive ownership {id} is outside the published subordinate-ID range {ARCHIVE_BASE}–{}", ARCHIVE_BASE + ID_COUNT - 1))?;
    Ok(if offset == 1000 {
        operator
    } else {
        base + offset
    })
}

fn shift_attribute(name: &CString, bytes: &mut [u8], mapping: Mapping) -> Result<(), Error> {
    if matches!(
        name.to_bytes(),
        b"system.posix_acl_access" | b"system.posix_acl_default"
    ) {
        if bytes.len() < 4
            || !(bytes.len() - 4).is_multiple_of(8)
            || bytes[..4] != 2_u32.to_le_bytes()
        {
            return Err("invalid POSIX ACL in the guest archive".into());
        }
        for entry in bytes[4..].chunks_exact_mut(8) {
            let tag = u16::from_le_bytes([entry[0], entry[1]]);
            let (base, operator) = match tag {
                2 => (mapping.uid_base, mapping.host_uid),
                8 => (mapping.gid_base, mapping.host_gid),
                _ => continue,
            };
            let id = u32::from_le_bytes(entry[4..8].try_into()?);
            if (ARCHIVE_BASE..ARCHIVE_BASE + ID_COUNT).contains(&id) {
                entry[4..8].copy_from_slice(&shift_id(id, base, operator)?.to_le_bytes());
            }
        }
    } else if name.to_bytes() == b"security.capability" && bytes.len() == 24 {
        let root = u32::from_le_bytes(bytes[20..24].try_into()?);
        if (ARCHIVE_BASE..ARCHIVE_BASE + ID_COUNT).contains(&root) {
            bytes[20..24].copy_from_slice(
                &shift_id(root, mapping.uid_base, mapping.host_uid)?.to_le_bytes(),
            );
        }
    }
    Ok(())
}

pub(super) fn remap_tree(tree: &Path, mapping: Mapping) -> Result<(), Error> {
    mapping.validate()?;
    let stage = tree.parent().ok_or("guest extraction stage is missing")?;
    let stage_metadata = fs::symlink_metadata(stage)?;
    if tree.file_name().is_none_or(|name| name != "rootfs-tree")
        || !stage_metadata.is_dir()
        || stage_metadata.uid() != mapping.host_uid
        || stage_metadata.mode() & 0o777 != 0o700
        || stage
            .file_name()
            .is_none_or(|name| !name.as_encoded_bytes().starts_with(b"extract-"))
    {
        return Err("ownership preparation accepts only the installer's private extract-*/rootfs-tree stage; shared prepared and live trees were preserved".into());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "guest ownership preparation requires the installer's narrow privileged file operation"
                .into(),
        );
    }
    let root_file = open_entry(libc::AT_FDCWD, tree.as_os_str())?;
    let root = root_file.metadata()?;
    if !root.is_dir() || root.uid() != ARCHIVE_BASE || root.gid() != ARCHIVE_BASE {
        return Err(
            "archive rootfs-tree must be a directory owned by published sandbox root 100000:100000"
                .into(),
        );
    }
    let mut records: HashMap<(u64, u64), (fs::Metadata, u64)> = HashMap::new();
    let mut changes = Vec::new();
    walk(&root_file, Path::new(""), &mut |file, metadata, path| {
        if metadata.dev() != root.dev() {
            return Err("guest staging tree contains another filesystem".into());
        }
        let uid = shift_id(metadata.uid(), mapping.uid_base, mapping.host_uid)?;
        let gid = shift_id(metadata.gid(), mapping.gid_base, mapping.host_gid)?;
        if let Some((_, count)) = records.get_mut(&(metadata.dev(), metadata.ino())) {
            *count += 1;
            return Ok(());
        }
        records.insert((metadata.dev(), metadata.ino()), (metadata.clone(), 1));
        let ownership_changes = metadata.uid() != uid || metadata.gid() != gid;
        let mut updates = Vec::new();
        if !metadata.file_type().is_symlink() {
            let path_c = CString::new(fd_path(file).as_os_str().as_bytes())?;
            for (name, mut value) in attributes(&path_c)? {
                let original = value.clone();
                shift_attribute(&name, &mut value, mapping)?;
                if ownership_changes || value != original {
                    updates.push((name, value));
                }
            }
        }
        if ownership_changes || !updates.is_empty() {
            changes.push(OwnershipChange {
                path: path.to_owned(),
                metadata: metadata.clone(),
                uid,
                gid,
                attributes: updates,
            });
        }
        Ok(())
    })?;
    for (metadata, count) in records.values() {
        if !metadata.is_dir() && metadata.nlink() != *count {
            return Err("guest staging tree has a hard link outside its private extraction; other installations were preserved".into());
        }
    }
    drop(records);
    // Check every owner, hard link and attribute before the first change.
    // Reopen only inodes that need writes instead of walking the whole tree
    // again. The usual root mapping leaves most inodes untouched. Relative
    // paths avoid retaining a descriptor for every inode in a large archive.
    for change in changes {
        let file = reopen_entry(&root_file, &change.path)?;
        let current = file.metadata()?;
        let metadata = change.metadata;
        if current.dev() != metadata.dev()
            || current.ino() != metadata.ino()
            || current.uid() != metadata.uid()
            || current.gid() != metadata.gid()
            || current.mode() != metadata.mode()
            || current.nlink() != metadata.nlink()
        {
            return Err("guest staging inode changed during ownership preparation; discard this unpublished stage and retry".into());
        }
        let path = fd_path(&file);
        let path_c = CString::new(path.as_os_str().as_bytes())?;
        let uid = change.uid;
        let gid = change.gid;
        let ownership_changes = metadata.uid() != uid || metadata.gid() != gid;
        if ownership_changes
            && unsafe {
                libc::fchownat(
                    file.as_raw_fd(),
                    c"".as_ptr(),
                    uid,
                    gid,
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if ownership_changes && !metadata.file_type().is_symlink() {
            fs::set_permissions(&path, fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        }
        // chown can clear set-ID bits and file capabilities. Restore the
        // archive's modes and attributes after changing the numeric owner.
        // Without chown, write only attributes whose embedded IDs changed.
        for (name, value) in change.attributes {
            if unsafe {
                libc::setxattr(
                    path_c.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn reopening_changes_never_follows_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), "preserved").unwrap();
        symlink(outside.path(), directory.path().join("link")).unwrap();
        let root = open_entry(libc::AT_FDCWD, directory.path().as_os_str()).unwrap();
        let link = reopen_entry(&root, Path::new("link")).unwrap();
        assert!(link.metadata().unwrap().file_type().is_symlink());
        assert!(reopen_entry(&root, Path::new("link/file")).is_err());
        assert_eq!(fs::read(outside.path().join("file")).unwrap(), b"preserved");
    }
}
