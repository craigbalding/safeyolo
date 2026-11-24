//! Selected job files remain at their adopted host paths. This route observes
//! those files; it does not create another artifact store or extend retention.
use crate::*;

#[cfg(unix)]
pub(crate) fn read(
    receipt: &Receipt,
    action: &Action,
    current_roots: &[String],
    observed_at: u64,
) -> Result<Response, Refusal> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        ffi::CString,
        fs::{File, Metadata},
        io::{Read, Seek, SeekFrom},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
        path::{Component, Path},
    };
    let Action::File {
        path,
        offset,
        max_bytes,
        expected_file_revision,
        ..
    } = action
    else {
        return Err(crate::native::unavailable("file request required"));
    };
    let path_value = Path::new(path);
    require(
        path_value.is_absolute()
            && path_value
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        RefusalCode::Arguments,
        "file result needs an absolute path without parent traversal",
    )?;
    // Check both scopes before any filesystem observation. A later operation
    // revision cannot turn an old job into access to new paths, and revocation
    // cannot be bypassed with a retained job ID.
    let selected = receipt
        .prepared
        .file_roots
        .iter()
        .filter(|root| path_value.starts_with(root))
        .min_by_key(|root| Path::new(root).components().count());
    // DOC: docs/host-operations.md
    require(
        selected.is_some()
            && current_roots
                .iter()
                .any(|root| path_value.starts_with(root)),
        RefusalCode::Authority,
        "file result is outside admitted or current writable paths",
    )?;
    let root = Path::new(selected.unwrap());
    let suffix = path_value
        .strip_prefix(root)
        .map_err(crate::native::unavailable)?;
    // Resolve only the operator-selected root. Pin each resulting component;
    // a workload symlink or replaced parent cannot redirect an openat read.
    let real = root.canonicalize().map_err(file_error)?;
    let mut file = File::open("/").map_err(file_error)?;
    for component in real.components().chain(suffix.components()) {
        if let Component::Normal(name) = component {
            let name = CString::new(name.as_encoded_bytes()).map_err(file_error)?;
            // SAFETY: descriptors/names remain live. O_NONBLOCK prevents FIFO
            // replacement from blocking; no special file is read below.
            let descriptor = unsafe {
                libc::openat(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                return Err(file_error(std::io::Error::last_os_error()));
            }
            file = unsafe { File::from_raw_fd(descriptor) };
        }
    }
    fn metadata_revision(meta: &Metadata) -> String {
        revision(&(
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        ))
    }
    let meta = file.metadata().map_err(file_error)?;
    require(
        meta.is_file(),
        RefusalCode::Arguments,
        "file result must be a regular file",
    )?;
    let file_revision = metadata_revision(&meta);
    require(
        expected_file_revision
            .as_ref()
            .is_none_or(|expected| *expected == file_revision),
        RefusalCode::Stale,
        "file result changed; inspect the selected file again before continuing",
    )?;
    require(
        *offset <= meta.len(),
        RefusalCode::Arguments,
        "file offset exceeds observed length",
    )?;
    let length = usize::try_from((*max_bytes).min(meta.len() - offset)).map_err(file_error)?;
    let mut data = Vec::new();
    data.try_reserve_exact(length).map_err(file_error)?;
    file.seek(SeekFrom::Start(*offset)).map_err(file_error)?;
    file.by_ref()
        .take(length as u64)
        .read_to_end(&mut data)
        .map_err(file_error)?;
    let after = file.metadata().map_err(file_error)?;
    require(
        metadata_revision(&after) == file_revision && data.len() == length,
        RefusalCode::Stale,
        "file result changed during the read; inspect it again",
    )?;
    let chunk_sha256 = ring::digest::digest(&ring::digest::SHA256, &data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Response::File {
        job_id: receipt.job_id.clone(),
        revision: receipt.revision,
        path: path.clone(),
        file_revision,
        observed_at,
        offset: *offset,
        eof: offset.saturating_add(data.len() as u64) == meta.len(),
        total_bytes: meta.len(),
        chunk_sha256,
        data_base64: STANDARD.encode(data),
    })
}

#[cfg(unix)]
fn file_error(error: impl std::fmt::Display) -> Refusal {
    crate::native::unavailable(format!("selected file result is unavailable: {error}"))
}

#[cfg(not(unix))]
pub(crate) fn read(_: &Receipt, _: &Action, _: &[String], _: u64) -> Result<Response, Refusal> {
    Err(crate::native::unavailable(
        "selected file retrieval is not implemented for this native backend",
    ))
}
