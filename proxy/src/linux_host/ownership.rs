//! Shift only a newly extracted tree, without following links or losing modes.

use crate::{
    Error,
    linux_host::{ARCHIVE_BASE, ID_COUNT, Mapping},
};
use std::{
    collections::{HashMap, HashSet},
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
    visit: &mut impl FnMut(&fs::File, &fs::Metadata) -> Result<(), Error>,
) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        for entry in fs::read_dir(fd_path(file))? {
            let child = open_entry(file.as_raw_fd(), &entry?.file_name())?;
            walk(&child, visit)?;
        }
    }
    visit(file, &metadata)
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
    walk(&root_file, &mut |_, metadata| {
        if metadata.dev() != root.dev() {
            return Err("guest staging tree contains another filesystem".into());
        }
        shift_id(metadata.uid(), mapping.uid_base, mapping.host_uid)?;
        shift_id(metadata.gid(), mapping.gid_base, mapping.host_gid)?;
        records
            .entry((metadata.dev(), metadata.ino()))
            .and_modify(|(_, count)| *count += 1)
            .or_insert_with(|| (metadata.clone(), 1));
        Ok(())
    })?;
    for (metadata, count) in records.values() {
        if !metadata.is_dir() && metadata.nlink() != *count {
            return Err("guest staging tree has a hard link outside its private extraction; other installations were preserved".into());
        }
    }
    // All owners have been checked before the first change. This is a fresh
    // stage; the caller publishes it only after this operation succeeds.
    let mut changed = HashSet::new();
    walk(&root_file, &mut |file, current| {
        let key = (current.dev(), current.ino());
        if !changed.insert(key) {
            return Ok(());
        }
        let (metadata, _) = records.get(&key).ok_or("guest staging tree changed during ownership preparation; discard this unpublished stage and retry")?;
        if current.uid() != metadata.uid()
            || current.gid() != metadata.gid()
            || current.mode() != metadata.mode()
            || current.nlink() != metadata.nlink()
        {
            return Err("guest staging inode changed during ownership preparation; discard this unpublished stage and retry".into());
        }
        let path = fd_path(file);
        let path_c = CString::new(path.as_os_str().as_bytes())?;
        // lchown does not remove symlink attributes. Leave them on that
        // pinned symlink; following its target would be incorrect.
        let attributes = if metadata.file_type().is_symlink() {
            Vec::new()
        } else {
            attributes(&path_c)?
        };
        let uid = shift_id(metadata.uid(), mapping.uid_base, mapping.host_uid)?;
        let gid = shift_id(metadata.gid(), mapping.gid_base, mapping.host_gid)?;
        let ownership_changes = metadata.uid() != uid || metadata.gid() != gid;
        let mut updates = Vec::new();
        for (name, mut value) in attributes {
            let original = value.clone();
            shift_attribute(&name, &mut value, mapping)?;
            if ownership_changes || value != original {
                updates.push((name, value));
            }
        }
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
        for (name, value) in updates {
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
        Ok(())
    })?;
    Ok(())
}
