//! Disk templates contain initialization only. Locks protect mapped blobs from
//! eviction; no VM, callback, input mount or delegated handle stays idle.

use crate::Error;
use hyperlight_host::sandbox::snapshot::{OciDigest, OciTag, Snapshot};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_ENTRIES: usize = 4;
const MAX_BYTES: u64 = 1 << 30;
const MAX_AGE: Duration = Duration::from_secs(60 * 60);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub directory: PathBuf,
    pub key: String,
}

#[derive(Default, Serialize)]
pub struct Observation {
    pub mode: &'static str,
    pub template_key: Option<String>,
    pub snapshot_digest: Option<String>,
    pub cold_reason: Option<String>,
    pub construction_ms: u128,
    pub save_ms: u128,
    pub load_ms: u128,
    pub restore_ms: u128,
    pub payload_ms: u128,
    pub initialization_events: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    key: String,
    host_boot: String,
    digest: String,
    created_seconds: u64,
    bytes: u64,
}

// Keep the lease until every sandbox and mapped snapshot has been dropped.
pub struct Selection {
    pub snapshot: Option<Arc<Snapshot>>,
    _lease: Option<File>,
}

struct Building(Option<PathBuf>);
impl Drop for Building {
    fn drop(&mut self) {
        // A failed build has no published receipt and can never be selected.
        if let Some(path) = &self.0
            && let Err(error) = fs::remove_dir_all(path)
        {
            eprintln!(
                "Hyperlight unfinished template cleanup failed: {error}; inspect {}",
                path.display()
            );
        }
    }
}

fn seconds() -> Result<u64, Error> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn host_boot() -> Result<String, Error> {
    #[cfg(target_os = "linux")]
    return Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into());
    #[cfg(target_os = "macos")]
    {
        let mut boot = [0u8; 128];
        let mut size = boot.len();
        // SAFETY: the name is NUL-terminated, boot is writable for size bytes,
        // and a null new-value pointer makes this a read-only sysctl call.
        if unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                boot.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(std::str::from_utf8(&boot[..size])?
            .trim_end_matches('\0')
            .into())
    }
}

fn lock_file(path: &Path) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?)
}

fn try_exclusive(file: &File) -> Result<bool, Error> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn receipt(path: &Path) -> Result<Receipt, Error> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path.join("receipt.json"))?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("template receipt exceeds its byte limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn bytes(path: &Path) -> Result<u64, Error> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let size = if kind.is_dir() {
            bytes(&entry.path())?
        } else if kind.is_file() {
            entry.metadata()?.len()
        } else {
            return Err("template contains a non-regular file".into());
        };
        total = total.checked_add(size).ok_or("template size overflow")?;
    }
    Ok(total)
}

/// Called under the directory lock. An entry lease cannot be opened outside
/// that lock, so deleting an unlocked entry cannot race a new blob mapping.
fn entries(directory: &Path, host: &str, now: u64) -> Result<Vec<(PathBuf, Receipt)>, Error> {
    let mut retained = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b"template-")
            || !entry.file_type()?.is_dir()
        {
            continue;
        }
        let path = entry.path();
        let value = receipt(&path);
        let current = value.as_ref().is_ok_and(|r| {
            r.host_boot == host
                && now
                    .checked_sub(r.created_seconds)
                    .is_some_and(|age| age < MAX_AGE.as_secs())
        });
        if !current {
            let lease = lock_file(&path.join("lease"))?;
            if try_exclusive(&lease)? {
                fs::remove_dir_all(&path)?;
                continue;
            }
        }
        if let Ok(value) = value {
            retained.push((path, value));
        }
    }
    retained.sort_by_key(|(_, r)| r.created_seconds);
    Ok(retained)
}

/// The directory lock prevents new readers while idle entries are removed.
/// Repeat after saving: the new snapshot's size is only known at that point.
fn evict_idle_templates(retained: &mut Vec<(PathBuf, Receipt)>, size: u64) -> Result<bool, Error> {
    if size > MAX_BYTES {
        return Ok(false);
    }
    let mut total = retained
        .iter()
        .try_fold(0u64, |total, (_, r)| total.checked_add(r.bytes))
        .ok_or("invalid template retention sizes")?;
    while retained.len() >= MAX_ENTRIES || total >= MAX_BYTES || size > MAX_BYTES - total {
        let mut removed = false;
        for index in 0..retained.len() {
            let lease = lock_file(&retained[index].0.join("lease"))?;
            if try_exclusive(&lease)? {
                fs::remove_dir_all(&retained[index].0)?;
                let (_, value) = retained.remove(index);
                total = total.saturating_sub(value.bytes);
                removed = true;
                break;
            }
        }
        if !removed {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn select(
    request: Option<&Request>,
    observation: &mut Observation,
    build: impl FnOnce() -> Result<Arc<Snapshot>, Error>,
) -> Selection {
    observation.mode = "cold";
    let empty = || Selection {
        snapshot: None,
        _lease: None,
    };
    let Some(request) = request else {
        observation.cold_reason = Some("initialization reuse disabled".into());
        return empty();
    };
    observation.template_key = Some(request.key.clone());
    match select_inner(request, observation, build) {
        Ok(selected) => selected,
        Err(error) => {
            observation.mode = "cold";
            observation.cold_reason = Some(error.to_string());
            empty()
        }
    }
}

fn select_inner(
    request: &Request,
    observation: &mut Observation,
    build: impl FnOnce() -> Result<Arc<Snapshot>, Error>,
) -> Result<Selection, Error> {
    let host = host_boot()?;
    let now = seconds()?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&request.directory)?;
    fs::set_permissions(&request.directory, fs::Permissions::from_mode(0o700))?;
    let directory_lock = lock_file(&request.directory.join("lock"))?;
    directory_lock
        .try_lock()
        .map_err(|error| format!("template cache busy or unavailable: {error}"))?;
    let mut retained = entries(&request.directory, &host, now)?;
    if let Some((path, value)) = retained.iter().find(|(_, r)| {
        r.key == request.key
            && r.host_boot == host
            && now
                .checked_sub(r.created_seconds)
                .is_some_and(|age| age < MAX_AGE.as_secs())
    }) {
        let lease = lock_file(&path.join("lease"))?;
        lease.try_lock_shared()?;
        drop(directory_lock);
        let started = Instant::now();
        let loaded = Snapshot::checked_load(path, value.digest.parse::<OciDigest>()?);
        observation.load_ms = started.elapsed().as_millis();
        match loaded {
            Ok(snapshot) => {
                observation.mode = "restored";
                observation.snapshot_digest = Some(value.digest.clone());
                return Ok(Selection {
                    snapshot: Some(Arc::new(snapshot)),
                    _lease: Some(lease),
                });
            }
            Err(error) => {
                // Corruption never selects another entry or unverified code.
                // Remove only with both locks and no outstanding mapped reader.
                drop(lease);
                // If another reader owns the files, leave them protected and
                // retain the exact cleanup limit in the cold diagnostic.
                let cleanup = directory_lock_again(&request.directory, path)
                    .err()
                    .map(|error| format!("; template cleanup deferred: {error}"))
                    .unwrap_or_default();
                return Err(format!("template invalid or incompatible: {error}{cleanup}").into());
            }
        }
    }
    if !evict_idle_templates(&mut retained, 0)? {
        return Err("template capacity is in use; executing cold".into());
    }
    // The directory lock stays held through construction/publication. Other
    // invocations can execute cold without waiting for guest initialization.
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = request
        .directory
        .join(format!("template-{}-{unique}", std::process::id()));
    fs::create_dir(&path)?;
    let mut building = Building(Some(path.clone()));
    let lease = lock_file(&path.join("lease"))?;
    lease.try_lock()?;
    let started = Instant::now();
    let snapshot = build()?;
    observation.construction_ms = started.elapsed().as_millis();
    observation.mode = "constructed";
    let saving = Instant::now();
    let digest = snapshot
        .save(&path, &OciTag::new("initialized")?)?
        .to_string();
    // Reserve the bounded receipt size as well as the snapshot bytes.
    let size = bytes(&path)?
        .checked_add(8192)
        .ok_or("template size overflow")?;
    let retain = evict_idle_templates(&mut retained, size)?;
    observation.save_ms = saving.elapsed().as_millis();
    if !retain {
        observation.cold_reason =
            Some("initialized template exceeds available retention capacity; not retained".into());
        return Ok(Selection {
            snapshot: Some(snapshot),
            _lease: None,
        });
    }
    let value = Receipt {
        key: request.key.clone(),
        host_boot: host,
        digest: digest.clone(),
        created_seconds: now,
        bytes: size,
    };
    fs::write(path.join("receipt.json"), serde_json::to_vec(&value)?)?;
    observation.snapshot_digest = Some(digest);
    building.0 = None;
    Ok(Selection {
        snapshot: Some(snapshot),
        _lease: Some(lease),
    })
}

fn directory_lock_again(directory: &Path, path: &Path) -> Result<(), Error> {
    let directory_lock = lock_file(&directory.join("lock"))?;
    directory_lock.try_lock()?;
    let lease = lock_file(&path.join("lease"))?;
    lease.try_lock()?;
    fs::remove_dir_all(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> Building {
        let path = std::env::current_dir().unwrap().join(format!(
            "template-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        Building(Some(path))
    }

    fn saved(directory: &Path, name: &str, key: &str, created: u64) -> PathBuf {
        let path = directory.join(format!("template-{name}"));
        fs::create_dir(&path).unwrap();
        let receipt = Receipt {
            key: key.into(),
            host_boot: host_boot().unwrap(),
            digest: format!("sha256:{}", "a".repeat(64)),
            created_seconds: created,
            bytes: 100,
        };
        fs::write(
            path.join("receipt.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        path
    }

    #[test]
    fn disabled_or_contended_cache_does_not_construct_or_wait() {
        let _guard = crate::CHILD_FIXTURE_LOCK.lock().unwrap();
        let scratch = scratch();
        let directory = scratch.0.as_ref().unwrap();
        let mut observed = Observation::default();
        assert!(
            select(None, &mut observed, || panic!("disabled"))
                .snapshot
                .is_none()
        );
        assert_eq!(observed.mode, "cold");
        let lock = lock_file(&directory.join("lock")).unwrap();
        lock.try_lock().unwrap();
        let request = Request {
            directory: directory.clone(),
            key: "selected".into(),
        };
        let start = Instant::now();
        assert!(
            select(Some(&request), &mut observed, || panic!("busy"))
                .snapshot
                .is_none()
        );
        assert!(observed.cold_reason.unwrap().contains("busy"));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn corrupt_snapshot_falls_back_without_using_a_tag_or_rebuilding() {
        let _guard = crate::CHILD_FIXTURE_LOCK.lock().unwrap();
        let scratch = scratch();
        let directory = scratch.0.as_ref().unwrap();
        let path = saved(directory, "corrupt", "selected", seconds().unwrap());
        let request = Request {
            directory: directory.clone(),
            key: "selected".into(),
        };
        let mut observed = Observation::default();
        let selected = select(Some(&request), &mut observed, || {
            panic!("invalid cache must execute cold")
        });
        assert!(selected.snapshot.is_none());
        assert_eq!(observed.mode, "cold");
        assert!(
            observed
                .cold_reason
                .unwrap()
                .contains("invalid or incompatible")
        );
        assert!(!path.exists());
    }

    #[test]
    fn full_cache_evicts_an_idle_entry_but_never_an_active_reader() {
        let _guard = crate::CHILD_FIXTURE_LOCK.lock().unwrap();
        let scratch = scratch();
        let directory = scratch.0.as_ref().unwrap();
        let mut readers = Vec::new();
        for index in 0..MAX_ENTRIES {
            let path = saved(directory, &index.to_string(), "other", seconds().unwrap());
            let file = lock_file(&path.join("lease")).unwrap();
            file.try_lock_shared().unwrap();
            readers.push(file);
        }
        let request = Request {
            directory: directory.clone(),
            key: "new".into(),
        };
        let mut observed = Observation::default();
        assert!(
            select(Some(&request), &mut observed, || panic!("capacity in use"))
                .snapshot
                .is_none()
        );
        assert!(observed.cold_reason.unwrap().contains("capacity is in use"));
        readers.pop();
        assert!(
            select(Some(&request), &mut Observation::default(), || Err(
                "failed after eviction".into()
            ))
            .snapshot
            .is_none()
        );
        assert_eq!(
            entries(directory, &host_boot().unwrap(), seconds().unwrap())
                .unwrap()
                .len(),
            MAX_ENTRIES - 1
        );
    }

    #[test]
    fn saved_snapshot_size_evicts_idle_bytes_and_preserves_active_or_oversized_entries() {
        let _guard = crate::CHILD_FIXTURE_LOCK.lock().unwrap();
        let scratch = scratch();
        let directory = scratch.0.as_ref().unwrap();
        let active = saved(directory, "active", "other", seconds().unwrap());
        let idle = saved(directory, "idle", "other", seconds().unwrap());
        for path in [&active, &idle] {
            let mut value = receipt(path).unwrap();
            value.bytes = MAX_BYTES / 3;
            fs::write(
                path.join("receipt.json"),
                serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
        }
        let lease = lock_file(&active.join("lease")).unwrap();
        lease.try_lock_shared().unwrap();
        let mut retained = entries(directory, &host_boot().unwrap(), seconds().unwrap()).unwrap();
        // A snapshot larger than the whole budget must not evict useful entries.
        assert!(!evict_idle_templates(&mut retained, MAX_BYTES + 1).unwrap());
        assert!(active.exists() && idle.exists());
        // Before save there is room for an entry. After save, its measured
        // half-budget footprint needs the idle third-budget entry evicted.
        assert!(evict_idle_templates(&mut retained, 0).unwrap());
        assert!(idle.exists());
        assert!(evict_idle_templates(&mut retained, MAX_BYTES / 2).unwrap());
        assert!(active.exists() && !idle.exists());
        assert_eq!(retained.len(), 1);
        assert!(!evict_idle_templates(&mut retained, MAX_BYTES).unwrap());
        assert!(active.exists());
        lease.unlock().unwrap();
        assert!(evict_idle_templates(&mut retained, MAX_BYTES).unwrap());
        assert!(retained.is_empty() && !active.exists());
    }

    #[test]
    fn expiry_and_eviction_preserve_mapped_readers_and_failed_builds_leave_no_entry() {
        let _guard = crate::CHILD_FIXTURE_LOCK.lock().unwrap();
        let scratch = scratch();
        let directory = scratch.0.as_ref().unwrap();
        let old = seconds().unwrap() - MAX_AGE.as_secs();
        let protected = saved(directory, "reader", "old", old);
        let disposable = saved(directory, "expired", "old", old);
        let partial = directory.join("template-interrupted");
        fs::create_dir(&partial).unwrap();
        let lease = lock_file(&protected.join("lease")).unwrap();
        lease.try_lock_shared().unwrap();
        let retained = entries(directory, &host_boot().unwrap(), seconds().unwrap()).unwrap();
        assert_eq!(retained.len(), 1);
        assert!(protected.exists());
        assert!(!disposable.exists());
        assert!(!partial.exists());
        let request = Request {
            directory: directory.clone(),
            key: "new".into(),
        };
        let mut observed = Observation::default();
        assert!(
            select(Some(&request), &mut observed, || Err(
                "initialization failed".into()
            ))
            .snapshot
            .is_none()
        );
        assert!(
            observed
                .cold_reason
                .unwrap()
                .contains("initialization failed")
        );
        assert_eq!(
            fs::read_dir(directory)
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b"template-"))
                .count(),
            1
        );
        drop(lease);
        assert!(
            entries(directory, &host_boot().unwrap(), seconds().unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(!protected.exists());
    }
}
