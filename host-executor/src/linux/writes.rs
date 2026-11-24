//! Writable bind mounts keep the selected referents alive. Symlinks inside a
//! mount resolve in the workload namespace. Existing hard links must all lie
//! within the selected write scope; otherwise writing one would change an
//! unselected host path without traversing the namespace boundary.
use super::{Mount, absolute, backing, mounts, require, unavailable, validate_read_mounts};
use crate::{Refusal, RefusalCode};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, Metadata},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};

#[derive(Debug)]
pub(super) struct WriteMount {
    pub file: File,
    pub path: String,
}

fn mapped_inodes() -> Result<BTreeSet<Inode>, Refusal> {
    let mut files = BTreeSet::new();
    // A write through a library's host inode can change pages mapped into the
    // trusted executor. Protect its mapped inputs as well as its executable.
    for line in fs::read_to_string("/proc/self/maps")
        .map_err(unavailable)?
        .lines()
    {
        let fields: Vec<_> = line.split_whitespace().take(5).collect();
        require(
            fields.len() == 5,
            RefusalCode::Unavailable,
            "executor memory-map observation is incomplete",
        )?;
        let number: u64 = fields[4].parse().map_err(unavailable)?;
        if number != 0 {
            let (major, minor) = fields[3]
                .split_once(':')
                .ok_or_else(|| unavailable("executor memory map has no device identity"))?;
            let major = u32::from_str_radix(major, 16).map_err(unavailable)?;
            let minor = u32::from_str_radix(minor, 16).map_err(unavailable)?;
            files.insert((libc::makedev(major, minor), number));
        }
    }
    Ok(files)
}

// Opening one component at a time prevents a replaced parent or symlink from
// redirecting the descriptor after canonical scope validation.
fn pin(path: &Path) -> Result<File, Refusal> {
    require(
        absolute(path),
        RefusalCode::Unavailable,
        "write scopes need absolute paths without parent traversal",
    )?;
    let mut file = File::open("/").map_err(unavailable)?;
    for part in path.components() {
        if let Component::Normal(name) = part {
            file = child(&file, name)?;
            require(
                !file
                    .metadata()
                    .map_err(unavailable)?
                    .file_type()
                    .is_symlink(),
                RefusalCode::Unavailable,
                "write scope changed to a symlink before it could be pinned",
            )?;
        }
    }
    Ok(file)
}

fn child(parent: &File, name: &std::ffi::OsStr) -> Result<File, Refusal> {
    let name = CString::new(name.as_encoded_bytes()).map_err(unavailable)?;
    // SAFETY: parent and the NUL-terminated name remain live through openat.
    // O_PATH does not open devices or FIFOs for I/O. Each descriptor has one owner.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

type Inode = (u64, u64);
type Entry = (String, PathBuf);
type Links = BTreeMap<Inode, (u64, BTreeSet<Entry>)>;
fn inode(meta: &Metadata) -> Inode {
    (meta.dev(), meta.ino())
}

fn record(
    links: &mut Links,
    meta: &Metadata,
    file: &File,
    mounts: &[Mount],
    mapped: &BTreeSet<Inode>,
) -> Result<(), Refusal> {
    require(
        !mapped.contains(&inode(meta)),
        RefusalCode::Unavailable,
        "write scope includes code or data mapped into the trusted executor",
    )?;
    let path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(unavailable)?;
    require(
        inode(&fs::symlink_metadata(&path).map_err(unavailable)?) == inode(meta),
        RefusalCode::Unavailable,
        "writable entry moved during alias validation",
    )?;
    // A bind alias is another view of the same directory entry, not another
    // hard link. Counting it twice would hide a link outside the write scope.
    let (device, path) = backing(&path, mounts)?;
    let entry = links
        .entry(inode(meta))
        .or_insert_with(|| (meta.nlink(), BTreeSet::new()));
    entry.0 = entry.0.max(meta.nlink());
    entry.1.insert((device.into(), path));
    Ok(())
}

fn scan(
    directory: &File,
    seen: &mut BTreeSet<Inode>,
    links: &mut Links,
    mounts: &[Mount],
    mapped: &BTreeSet<Inode>,
) -> Result<(), Refusal> {
    let parent = inode(&directory.metadata().map_err(unavailable)?);
    if !seen.insert(parent) {
        return Ok(());
    }
    for entry in
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(unavailable)?
    {
        let name = entry.map_err(unavailable)?.file_name();
        let file = child(directory, &name)?;
        let meta = file.metadata().map_err(unavailable)?;
        if meta.is_dir() {
            scan(&file, seen, links, mounts, mapped)?;
        } else if meta.is_file() {
            record(links, &meta, &file, mounts, mapped)?;
        } else {
            require(
                meta.file_type().is_symlink(),
                RefusalCode::Unavailable,
                "this Linux writable profile does not yet enforce special-file IPC or device scopes; select regular files/directories or an adopted supported IPC operation",
            )?;
        }
    }
    Ok(())
}

pub(super) fn open(paths: &[String], protected: &[PathBuf]) -> Result<Vec<WriteMount>, Refusal> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mounts = mounts()?;
    let mapped = mapped_inodes()?;
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    let mut links = Links::new();
    for path in paths {
        require(
            absolute(Path::new(path)),
            RefusalCode::Unavailable,
            "write scopes need absolute paths without parent traversal",
        )?;
        let real = Path::new(path).canonicalize().map_err(|error| unavailable(format!("write scope must already exist; select its parent directory to create new descendants: {error}")))?;
        require(
            !protected
                .iter()
                .any(|p| real.starts_with(p) || p.starts_with(&real)),
            RefusalCode::Unavailable,
            "write scope exposes executor configuration, trust, state or cgroup authority",
        )?;
        let file = pin(&real)?;
        // Validate backing mounts only after pinning. A trusted host rename
        // leaves this job bound to its selected inode rather than a replacement.
        require(
            fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(unavailable)?
                == real,
            RefusalCode::Unavailable,
            "write scope moved before mount validation",
        )?;
        validate_read_mounts(&real, protected, &mounts)?;
        let meta = file.metadata().map_err(unavailable)?;
        require(
            meta.is_file() || meta.is_dir(),
            RefusalCode::Unavailable,
            "write scope must name a regular file or directory",
        )?;
        if meta.is_dir() {
            scan(&file, &mut seen, &mut links, &mounts, &mapped)?;
        } else {
            record(&mut links, &meta, &file, &mounts, &mapped)?;
        }
        selected.push(WriteMount {
            file,
            path: path.clone(),
        });
    }
    require(
        links
            .values()
            .all(|(count, entries)| *count == entries.len() as u64),
        RefusalCode::Unavailable,
        "write scope has a hard link outside the selected writable paths",
    )?;
    // Overlay parents before children. Repeated paths must not alter precedence.
    selected.sort_by(|a, b| {
        (Path::new(&a.path).components().count(), &a.path)
            .cmp(&(Path::new(&b.path).components().count(), &b.path))
    });
    selected.dedup_by(|a, b| a.path == b.path);
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let mut nonce = [0; 8];
            SystemRandom::new().fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "host-writes-{}-{}",
                std::process::id(),
                u64::from_ne_bytes(nonce)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn scope(&self) -> Vec<String> {
            vec![self.0.to_str().unwrap().into()]
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn writes_refuse_external_hard_links_but_allow_internal_links_and_overlaps() {
        let selected = Directory::new();
        let outside = Directory::new();
        fs::write(selected.0.join("first"), b"result").unwrap();
        fs::hard_link(selected.0.join("first"), selected.0.join("second")).unwrap();
        let mut paths = selected.scope();
        paths.push(selected.0.join("first").to_str().unwrap().into());
        paths.extend(selected.scope());
        assert!(open(&paths, &[]).is_ok());
        fs::hard_link(selected.0.join("first"), outside.0.join("alias")).unwrap();
        assert!(
            open(&paths, &[])
                .unwrap_err()
                .message
                .contains("hard link outside")
        );
        paths.extend(outside.scope());
        assert!(open(&paths, &[]).is_ok());
    }

    #[test]
    fn writes_pin_selected_referent_and_do_not_follow_nested_symlinks() {
        let selected = Directory::new();
        let outside = Directory::new();
        fs::write(outside.0.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside.0, selected.0.join("alias")).unwrap();
        let mounts = open(&selected.scope(), &[]).unwrap();
        let before = inode(&mounts[0].file.metadata().unwrap());
        let moved = outside.0.join("moved");
        fs::rename(&selected.0, &moved).unwrap();
        fs::create_dir(&selected.0).unwrap();
        assert_eq!(inode(&mounts[0].file.metadata().unwrap()), before);
        assert_ne!(inode(&fs::metadata(&selected.0).unwrap()), before);
        fs::remove_dir_all(moved).unwrap();
    }

    #[test]
    fn writes_refuse_control_paths_aliases_and_nonexistent_scope_roots() {
        let selected = Directory::new();
        let protected = selected.0.join("control");
        fs::write(&protected, b"protected").unwrap();
        assert!(open(&selected.scope(), std::slice::from_ref(&protected)).is_err());
        let alias = Directory::new();
        std::os::unix::fs::symlink(&selected.0, alias.0.join("scope")).unwrap();
        assert!(
            open(
                &[alias.0.join("scope").to_str().unwrap().into()],
                &[protected]
            )
            .is_err()
        );
        assert!(
            open(&[selected.0.join("new").to_str().unwrap().into()], &[])
                .unwrap_err()
                .message
                .contains("parent directory")
        );
    }

    #[test]
    fn mount_aliases_cannot_count_as_additional_hard_links() {
        let directory = Directory::new();
        let first = directory.0.join("first");
        let alias = directory.0.join("alias");
        fs::write(&first, b"result").unwrap();
        fs::hard_link(&first, &alias).unwrap();
        let mounts = vec![
            Mount {
                device: "test".into(),
                root: "/".into(),
                path: "/".into(),
                filesystem: "ext4".into(),
            },
            Mount {
                device: "test".into(),
                root: first.clone(),
                path: alias.clone(),
                filesystem: "ext4".into(),
            },
        ];
        let mut links = Links::new();
        for path in [&first, &alias] {
            let file = pin(path).unwrap();
            record(
                &mut links,
                &file.metadata().unwrap(),
                &file,
                &mounts,
                &BTreeSet::new(),
            )
            .unwrap();
        }
        let (count, entries) = links.values().next().unwrap();
        assert_eq!(*count, 2);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn executor_mappings_are_protected_by_inode() {
        let executable = std::env::current_exe().unwrap();
        assert!(
            mapped_inodes()
                .unwrap()
                .contains(&inode(&fs::metadata(&executable).unwrap()))
        );
        assert!(
            open(&[executable.to_str().unwrap().into()], &[])
                .unwrap_err()
                .message
                .contains("mapped into the trusted executor")
        );
    }
}
