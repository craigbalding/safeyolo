//! Seatbelt resolves paths at access time. Validate existing aliases before
//! launch; the workload cannot create a link from an unselected source.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
};

type Inode = (u64, u64);
fn inode(meta: &fs::Metadata) -> Inode {
    (meta.dev(), meta.ino())
}

fn protected_paths(protected: &[PathBuf]) -> Result<Vec<PathBuf>, Refusal> {
    let mut paths = protected.to_vec();
    paths.push(std::env::current_exe().map_err(unavailable)?);
    // Shared-cache images can have no separate on-disk file. Protect their
    // system roots as well as each real image mapped into this executor.
    paths.extend(["/System/Library", "/usr/lib", "/Library/Apple/System"].map(PathBuf::from));
    // SAFETY: dyld owns these NUL-terminated names for the loaded images. Copy
    // each name immediately; this executable does not unload runtime images.
    for index in 0..unsafe { _dyld_image_count() } {
        let name = unsafe { _dyld_get_image_name(index) };
        require(
            !name.is_null(),
            RefusalCode::Unavailable,
            "executor image observation is incomplete",
        )?;
        let name = unsafe { CStr::from_ptr(name) }
            .to_str()
            .map_err(unavailable)?;
        paths.push(PathBuf::from(name));
    }
    Ok(paths)
}

// These two libSystem APIs need no separate Mach crate. libc has deprecated
// its bindings; the OS signatures are declared here, as for addchdir_np.
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(index: u32) -> *const libc::c_char;
}

type Links = BTreeMap<Inode, (u64, BTreeSet<(Inode, std::ffi::OsString)>)>;

fn scan(
    path: &Path,
    protected: &BTreeSet<Inode>,
    seen: &mut BTreeSet<Inode>,
    links: &mut Links,
) -> Result<(), Refusal> {
    let meta = fs::symlink_metadata(path).map_err(unavailable)?;
    require(
        !protected.contains(&inode(&meta)),
        RefusalCode::Unavailable,
        "write scope aliases executor control or runtime material",
    )?;
    if meta.is_dir() {
        if seen.insert(inode(&meta)) {
            for entry in fs::read_dir(path).map_err(unavailable)? {
                scan(&entry.map_err(unavailable)?.path(), protected, seen, links)?;
            }
        }
    } else if meta.is_file() {
        let parent = fs::metadata(
            path.parent()
                .ok_or_else(|| unavailable("write file has no parent"))?,
        )
        .map_err(unavailable)?;
        let entry = links
            .entry(inode(&meta))
            .or_insert_with(|| (meta.nlink(), BTreeSet::new()));
        entry.0 = entry.0.max(meta.nlink());
        // Firmlinks/overlapping scope paths can expose the same directory entry
        // twice. They must not hide a different hard link outside the scope.
        entry.1.insert((
            inode(&parent),
            path.file_name()
                .ok_or_else(|| unavailable("write file has no name"))?
                .to_owned(),
        ));
    } else {
        require(
            meta.file_type().is_symlink(),
            RefusalCode::Unavailable,
            "macOS write scopes require regular files/directories; special-file IPC needs an adopted supported IPC boundary",
        )?;
    }
    Ok(())
}

pub(super) fn validate(paths: &[String], protected: &[PathBuf]) -> Result<Vec<PathBuf>, Refusal> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let protected = protected_paths(protected)?;
    let mut protected_inodes = BTreeSet::new();
    for path in &protected {
        match fs::metadata(path) {
            Ok(meta) => {
                protected_inodes.insert(inode(&meta));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(unavailable(error)),
        }
    }
    let mut seen = BTreeSet::new();
    let mut links = Links::new();
    let mut selected = Vec::new();
    for path in paths {
        require(
            Path::new(path).is_absolute(),
            RefusalCode::Unavailable,
            "write scopes need absolute paths",
        )?;
        let real = Path::new(path).canonicalize().map_err(|error| unavailable(format!(
            "write scope must already exist; select its parent directory to create new descendants: {error}")))?;
        require(
            !protected
                .iter()
                .any(|p| real.starts_with(p) || p.starts_with(&real)),
            RefusalCode::Unavailable,
            "write scope exposes executor configuration, trust, state or runtime material",
        )?;
        // Check physical ancestors too: APFS firmlinks can spell a protected
        // directory differently without changing its device/inode identity.
        for parent in real.ancestors() {
            require(
                !protected_inodes.contains(&inode(&fs::metadata(parent).map_err(unavailable)?)),
                RefusalCode::Unavailable,
                "write scope aliases executor control or runtime material",
            )?;
        }
        scan(&real, &protected_inodes, &mut seen, &mut links)?;
        selected.push(real);
    }
    require(
        links
            .values()
            .all(|(count, entries)| *count == entries.len() as u64),
        RefusalCode::Unavailable,
        "write scope has a hard link outside the selected writable paths",
    )?;
    selected.sort();
    selected.dedup();
    Ok(selected)
}
