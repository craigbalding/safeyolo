//! Persist audit appends through the existing instance directory.
use std::{fs, io, path::Path};

pub(super) fn sync_coord_append(
    file: &fs::File,
    path: &Path,
    instance_directory: Option<&Path>,
    mut sync: impl FnMut(&fs::File) -> io::Result<()>,
) -> io::Result<()> {
    sync(file)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let instance = instance_directory.map(fs::canonicalize).transpose()?;
    // The loaded configuration establishes an existing instance directory.
    // The writer can create entries below it, but not the instance itself.
    // Resolve symlinks before choosing this boundary: an external destination
    // still needs its complete containing-directory durability path.
    let boundary = instance.as_deref().filter(|root| parent.starts_with(root));
    for directory in parent.ancestors() {
        sync(&fs::File::open(directory)?)?;
        if Some(directory) == boundary {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn required_file_and_directory_sync_failures_remain_failures_on_retry() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("new/deep");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("audit.jsonl");
        let file = fs::File::create(&path).unwrap();
        let intermediate = root.path().join("new");
        let expected = [&path, &parent, &intermediate, root.path()];
        for failed_call in 1..=expected.len() {
            for _ in 0..2 {
                let mut calls = 0;
                let result = sync_coord_append(&file, &path, Some(root.path()), |opened| {
                    assert_eq!(opened.metadata()?.ino(), expected[calls].metadata()?.ino());
                    calls += 1;
                    if calls == failed_call {
                        Err(io::Error::other("required sync unavailable"))
                    } else {
                        opened.sync_all()
                    }
                });
                assert!(result.is_err());
                assert_eq!(calls, failed_call);
                fs::write(parent.join("other-writer-entry"), b"owned fixture").unwrap();
            }
        }
        let mut calls = 0;
        sync_coord_append(&file, &path, Some(root.path()), |opened| {
            assert_eq!(opened.metadata()?.ino(), expected[calls].metadata()?.ino());
            calls += 1;
            opened.sync_all()
        })
        .unwrap();
        assert_eq!(calls, expected.len());
    }

    #[test]
    fn concurrent_visibility_cannot_skip_the_creating_parents_failed_sync() {
        use std::{sync::mpsc, time::Duration};
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("logs");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("audit.jsonl");
        let file = fs::File::create(&path).unwrap();
        let inode = root.path().metadata().unwrap().ino();
        let (visible, entered) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        let first_instance = root.path().to_owned();
        std::thread::scope(|scope| {
            let first = scope.spawn(move || {
                sync_coord_append(&file, &path, Some(&first_instance), |opened| {
                    if opened.metadata()?.ino() == inode {
                        visible.send(()).unwrap();
                        resumed.recv_timeout(Duration::from_secs(2)).unwrap();
                        return Err(io::Error::other("parent sync unavailable"));
                    }
                    opened.sync_all()
                })
            });
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            fs::write(parent.join("concurrent-writer-entry"), b"owned fixture").unwrap();
            let mut parent_calls = 0;
            let retry_path = parent.join("audit.jsonl");
            let retry_file = fs::File::open(&retry_path).unwrap();
            let instance = parent.parent().unwrap();
            let second = sync_coord_append(&retry_file, &retry_path, Some(instance), |opened| {
                if opened.metadata()?.ino() == inode {
                    parent_calls += 1;
                    return Err(io::Error::other("parent sync still unavailable"));
                }
                opened.sync_all()
            });
            resume.send(()).unwrap();
            assert!(first.join().unwrap().is_err());
            assert!(second.is_err());
            assert_eq!(parent_calls, 1);
        });
        let path = parent.join("audit.jsonl");
        sync_coord_append(
            &fs::File::open(&path).unwrap(),
            &path,
            parent.parent(),
            fs::File::sync_all,
        )
        .unwrap();
    }

    #[test]
    fn external_and_symlinked_destinations_keep_their_required_ancestor_syncs() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("linked")).unwrap();
        for path in [
            outside.path().join("external.jsonl"),
            root.path().join("linked/symlinked.jsonl"),
        ] {
            let file = fs::File::create(&path).unwrap();
            let mut calls = 0;
            let result = sync_coord_append(&file, &path, Some(root.path()), |opened| {
                calls += 1;
                if calls == 3 {
                    Err(io::Error::other("external ancestor unavailable"))
                } else {
                    opened.sync_all()
                }
            });
            assert!(result.is_err());
            assert_eq!(calls, 3);
        }
    }
}
