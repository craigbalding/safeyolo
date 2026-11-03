//! Copy broker-selected inputs without following agent-controlled source links.

use std::{
    ffi::{CStr, CString, OsStr},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
};

use crate::Error;
use ring::digest::{Context, SHA256};

struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn names(directory: &File, limit: u64) -> Result<Vec<CString>, Error> {
    // fdopendir takes ownership. The duplicate keeps the caller's pin alive.
    let fd = directory.try_clone()?.into_raw_fd();
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = Directory(stream);
    let mut names = Vec::new();
    loop {
        // readdir uses errno to distinguish EOF from an error.
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            if names.len() as u64 == limit {
                return Err("job input exceeds max_input_entries".into());
            }
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

use std::os::fd::IntoRawFd;

fn open(directory: &File, name: &CStr, flags: i32) -> Result<File, Error> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn field(hash: &mut Context, value: &[u8]) {
    hash.update(&(value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn copy_directory(
    source: &File,
    destination: &Path,
    hash: &mut Context,
    remaining: &mut u64,
    entries: &mut u64,
) -> Result<(), Error> {
    for name in names(source, *entries)? {
        *entries = entries
            .checked_sub(1)
            .ok_or("job input exceeds max_input_entries")?;
        let path = destination.join(OsStr::from_bytes(name.to_bytes()));
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                source.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let metadata = unsafe { metadata.assume_init() };
        field(hash, name.to_bytes());
        match metadata.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                hash.update(b"directory");
                let child = open(source, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                fs::create_dir(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                copy_directory(&child, &path, hash, remaining, entries)?;
                hash.update(b"end-directory");
            }
            libc::S_IFREG => {
                hash.update(b"file");
                let mut input = open(source, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
                let actual = input.metadata()?;
                if !actual.is_file() {
                    return Err("job input changed type while copying".into());
                }
                let mode: u32 = if actual.permissions().mode() & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                };
                hash.update(&mode.to_be_bytes());
                let mut output = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(mode)
                    .open(path)?;
                output.set_permissions(fs::Permissions::from_mode(mode))?;
                let mut buffer = vec![0; 64 * 1024];
                let mut file_hash = Context::new(&SHA256);
                let mut file_bytes = 0u64;
                loop {
                    let count = input.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    *remaining = remaining
                        .checked_sub(count as u64)
                        .ok_or("job input exceeds max_input_bytes")?;
                    output.write_all(&buffer[..count])?;
                    file_bytes += count as u64;
                    file_hash.update(&buffer[..count]);
                }
                hash.update(&file_bytes.to_be_bytes());
                hash.update(file_hash.finish().as_ref());
            }
            libc::S_IFLNK => {
                hash.update(b"symlink");
                // A link is copied as data. It can never select a host input.
                let mut target = vec![0; 4096];
                let size = unsafe {
                    libc::readlinkat(
                        source.as_raw_fd(),
                        name.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if size < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if size as usize == target.len() {
                    return Err("job input symlink is too long".into());
                }
                target.truncate(size as usize);
                *remaining = remaining
                    .checked_sub(target.len() as u64)
                    .ok_or("job input exceeds max_input_bytes")?;
                field(hash, &target);
                std::os::unix::fs::symlink(OsStr::from_bytes(&target), path)?;
            }
            _ => {
                return Err(
                    "job inputs must contain directories, regular files or symlinks".into(),
                );
            }
        }
    }
    Ok(())
}

pub(super) fn copy(
    source: Option<&Path>,
    destination: &Path,
    mut max_bytes: u64,
    mut max_entries: u64,
) -> Result<String, Error> {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    let mut hash = Context::new(&SHA256);
    hash.update(b"safeyolo-job-input-v1");
    if let Some(source) = source {
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(source)?;
        copy_directory(
            &source,
            destination,
            &mut hash,
            &mut max_bytes,
            &mut max_entries,
        )?;
    }
    Ok(super::hex(hash.finish().as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_links_as_data_and_hashes_the_staged_content() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), "candidate").unwrap();
        std::os::unix::fs::symlink("/etc/shadow", source.join("outside")).unwrap();
        let first = copy(Some(&source), &root.path().join("a"), 100, 10).unwrap();
        let second = copy(Some(&source), &root.path().join("b"), 100, 10).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            fs::read_link(root.path().join("a/outside")).unwrap(),
            Path::new("/etc/shadow")
        );
        assert_eq!(fs::read(root.path().join("a/file")).unwrap(), b"candidate");
        fs::write(source.join("file"), "changed").unwrap();
        assert_ne!(
            first,
            copy(Some(&source), &root.path().join("c"), 100, 10).unwrap()
        );
        assert!(copy(Some(&source), &root.path().join("limited"), 1, 10).is_err());
        assert!(copy(Some(&source), &root.path().join("entries"), 100, 1).is_err());
    }

    #[test]
    fn refuses_root_links_and_special_files() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("link")).unwrap();
        assert!(
            copy(
                Some(&root.path().join("link")),
                &root.path().join("a"),
                100,
                10
            )
            .is_err()
        );
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let fifo = CString::new(source.join("pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(copy(Some(&source), &root.path().join("b"), 100, 10).is_err());
    }
}
