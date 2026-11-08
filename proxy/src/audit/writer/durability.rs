//! Persist audit files and the directory entries changed by this writer.
use std::{fs, io, path::Path};

pub(super) fn create_audit_directory(
    path: &Path,
    sync: &mut impl FnMut(&fs::File) -> io::Result<()>,
) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(io::ErrorKind::NotADirectory.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    create_audit_directory(parent, sync)?;
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => false,
        Err(error) => return Err(error),
    };
    // Persist each new directory entry before creating anything inside it,
    // including for ordinary batches that can precede a durable Coord append.
    // Existing ancestors above this entry have not been changed by the writer.
    let result = fs::File::open(parent).and_then(|directory| sync(&directory));
    if result.is_err() && created {
        // This directory is still empty. A retry must create and sync its entry
        // again rather than mistake a failed creation for a durable ancestor.
        if let Err(error) = fs::remove_dir(path) {
            eprintln!("[safeyolo] audit directory rollback failed: {error}");
        }
    }
    result
}

pub(super) fn sync_coord_append(
    file: &fs::File,
    path: &Path,
    mut sync: impl FnMut(&fs::File) -> io::Result<()>,
) -> io::Result<()> {
    sync(file)?;
    // Appends and rotation change entries only in the log's direct parent.
    // Directory creation persists its own entries before the append begins.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    sync(&fs::File::open(parent)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coord_durability_propagates_file_and_directory_sync_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let file = fs::File::create(&path).unwrap();
        for failed_call in [1, 2] {
            let mut calls = 0;
            let result = sync_coord_append(&file, &path, |file| {
                calls += 1;
                assert_eq!(file.metadata()?.is_file(), calls == 1);
                if calls == failed_call {
                    Err(io::Error::other("injected sync failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            assert_eq!(calls, failed_call);
        }
        sync_coord_append(&file, &path, fs::File::sync_all).unwrap();
        let mut calls = 0;
        sync_coord_append(&file, &path, |file| {
            calls += 1;
            // An inaccessible, unchanged ancestor must not prevent publication.
            assert!(calls <= 2);
            if calls == 2 {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(file.metadata()?.ino(), directory.path().metadata()?.ino());
            }
            file.sync_all()
        })
        .unwrap();
        assert_eq!(calls, 2);
    }

    #[test]
    fn new_audit_directories_sync_each_entry_before_use_and_retry_failed_creation() {
        use std::os::unix::fs::MetadataExt;
        for failed_call in [1, 2, 3, 4] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("one/two/three");
            let mut calls = 0;
            let result = create_audit_directory(&path, &mut |parent| {
                calls += 1;
                let created = directory.path().join(match calls {
                    1 => "one",
                    2 => "one/two",
                    3 => "one/two/three",
                    _ => panic!("unrelated ancestor"),
                });
                assert_eq!(
                    parent.metadata()?.ino(),
                    created.parent().unwrap().metadata()?.ino()
                );
                assert_eq!(fs::read_dir(&created)?.count(), 0);
                if calls == failed_call {
                    Err(io::Error::other("injected directory sync failure"))
                } else {
                    parent.sync_all()
                }
            });
            assert_eq!(result.is_err(), failed_call <= 3);
            assert_eq!(calls, failed_call.min(3));
            if failed_call <= 3 {
                assert!(!path.exists());
                let mut retry_calls = 0;
                create_audit_directory(&path, &mut |parent| {
                    retry_calls += 1;
                    parent.sync_all()
                })
                .unwrap();
                assert_eq!(retry_calls, 4 - failed_call);
            }
            create_audit_directory(&path, &mut |_| {
                panic!("existing directory entry was unchanged")
            })
            .unwrap();
        }
    }
}
