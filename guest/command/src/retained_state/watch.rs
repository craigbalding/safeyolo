use super::{GuestState, configuration, coverage, packages};
use crate::{Error, now};
use serde_json::json;
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_ATTRIB
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;

fn directories(
    store: &GuestState,
    path: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<(), Error> {
    let relative = format!("/{}", path.strip_prefix(&store.root)?.display());
    if configuration::excluded(&relative) {
        return Ok(());
    }
    configuration::safe_parents(&store.root, &relative)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() {
        paths.insert(path.into());
        for entry in fs::read_dir(path)? {
            directories(store, &entry?.path(), paths)?;
        }
    }
    Ok(())
}

fn arm(
    store: &GuestState,
    paths: &[String],
) -> Result<(OwnedFd, std::collections::BTreeMap<i32, PathBuf>), Error> {
    configuration::validate_coverage(store, paths)?;
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut directories_to_watch = BTreeSet::new();
    for path in paths {
        directories(store, &store.actual(path), &mut directories_to_watch)?;
        let actual = store.actual(path);
        if let Some(parent) = actual.ancestors().skip(1).find(|x| x.is_dir()) {
            directories_to_watch.insert(parent.into());
        }
    }
    for path in ["/var/lib/dpkg", "/var/lib/apt"] {
        if store.actual(path).is_dir() {
            directories_to_watch.insert(store.actual(path));
        }
    }
    // Watching the whole state directory would observe every lock-file close
    // and wake the recorder again. Only coverage edits are external inputs.
    let marker = store.directory.join("coverage.changed");
    drop(
        fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&marker)?,
    );
    directories_to_watch.insert(marker);
    let mut watches = std::collections::BTreeMap::new();
    for path in directories_to_watch {
        let name = CString::new(path.as_os_str().as_bytes())?;
        let wd = unsafe {
            libc::inotify_add_watch(
                fd.as_raw_fd(),
                name.as_ptr(),
                MASK | libc::IN_DONT_FOLLOW | if path.is_dir() { libc::IN_ONLYDIR } else { 0 },
            )
        };
        if wd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        watches.insert(wd, path);
    }
    Ok((fd, watches))
}

pub(super) fn run(store: &GuestState) -> Result<i32, Error> {
    // The lock also prevents two capture daemons for this state directory.
    let daemon = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(store.directory.join("watch.lock"))?;
    if unsafe { libc::flock(daemon.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("guest state watcher is already running".into());
    }
    let mut value = {
        let _lock = store.lock()?;
        store.initialize()?
    };
    let mut selected = coverage(&value)?;
    let (mut fd, mut watches) = arm(store, &selected)?;
    let mut pending = Some(Instant::now());
    {
        let _lock = store.lock()?;
        value = store.read()?;
        value["watch"] = json!({"pid":std::process::id(),"owner":crate::live_token(std::process::id() as i32)?,"started":now(),"state":"watching","debounce_seconds":1});
        store.save(&value)?;
    }
    let mut buffer = [0u8; 65536];
    loop {
        let mut overflow = false;
        let mut descriptor = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready =
            unsafe { libc::poll(&mut descriptor, 1, if pending.is_some() { 250 } else { -1 }) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if ready > 0 {
            let count =
                unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if count < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let mut offset = 0;
            while offset + size_of::<libc::inotify_event>() <= count as usize {
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
                    )
                };
                let end = offset + size_of::<libc::inotify_event>() + event.len as usize;
                if end > count as usize {
                    return Err("truncated inotify event".into());
                }
                let bytes = &buffer[offset + size_of::<libc::inotify_event>()..end];
                let name = std::ffi::OsStr::from_bytes(
                    bytes.split(|x| *x == 0).next().unwrap_or_default(),
                );
                overflow |= event.mask & libc::IN_Q_OVERFLOW != 0;
                if event.mask & libc::IN_Q_OVERFLOW != 0
                    || watches.get(&event.wd).is_some_and(|parent| {
                        let path = parent.join(name);
                        let relative = format!(
                            "/{}",
                            path.strip_prefix(&store.root).unwrap_or(&path).display()
                        );
                        (path == store.directory.join("coverage.changed"))
                            || relative.starts_with("/var/lib/dpkg/")
                            || relative == "/var/lib/apt/extended_states"
                            || !configuration::excluded(&relative)
                                && selected.iter().any(|x| {
                                    relative == *x
                                        || relative.starts_with(&format!("{x}/"))
                                        || x.starts_with(&format!("{relative}/"))
                                })
                    })
                {
                    pending.get_or_insert_with(Instant::now);
                }
                offset = end;
            }
        }
        // Coverage is tiny; read its existing record, never scan rootfs on a timer.
        let _lock = store.lock()?;
        value = store.read()?;
        if overflow {
            value["watch"]["last_queue_overflow"] = json!(now());
            store.save(&value)?;
        }
        if selected != coverage(&value)? {
            selected = coverage(&value)?;
            pending = Some(Instant::now());
        }
        if pending.is_some_and(|x| x.elapsed() >= Duration::from_secs(1))
            && !packages::active(&value)?
        {
            (fd, watches) = arm(store, &selected)?;
            if let Err(error) = store.capture(&mut value) {
                value["status"] = json!("needs_attention");
                value["capture_error"] = json!(error.to_string());
                store.save(&value)?;
            }
            pending = None;
        }
    }
}
