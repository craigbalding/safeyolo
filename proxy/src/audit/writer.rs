use num_bigint::{BigInt, Sign};
use serde_json::Value;
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{Error, ErrorKind, Event, Result, envelope::Record};
use crate::circuits::CircuitValue;

#[derive(Clone)]
pub struct Settings {
    pub max_queue: BigInt,
    pub max_bytes: BigInt,
    pub backups: BigInt,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_queue: 10000.into(),
            max_bytes: 50_000_000.into(),
            backups: 5.into(),
        }
    }
}
impl Settings {
    /// Read source settings only when explicitly requested by the startup owner.
    /// This reads no log path and performs no I/O to a destination.
    pub fn from_env() -> Result<Self> {
        let value = |name| std::env::var_os(name).map(|value| value.to_str().map(str::to_owned));
        let queue = value("SAFEYOLO_AUDIT_QUEUE_MAX");
        let maximum = value("SAFEYOLO_LOG_MAX_MB");
        let backups = value("SAFEYOLO_LOG_BACKUPS");
        if maximum.as_ref().is_some_and(Option::is_none)
            || backups.as_ref().is_some_and(Option::is_none)
        {
            return Err(Error(ErrorKind::Configuration));
        }
        Self::from_environment_values(
            queue.flatten().as_deref(),
            maximum.flatten().as_deref(),
            backups.flatten().as_deref(),
        )
    }
    /// Pure constructor for injected environment values, including Python's
    /// decimal digits/underscores and the shipped integer conversion limit.
    pub fn from_environment_values(
        queue: Option<&str>,
        maximum_mb: Option<&str>,
        backups: Option<&str>,
    ) -> Result<Self> {
        let integer = |value: &str| {
            crate::flow_store::integer(&CircuitValue::Other(Value::String(value.into())))
        };
        Ok(Self {
            max_queue: queue.and_then(integer).unwrap_or_else(|| 10000.into()),
            max_bytes: integer(maximum_mb.unwrap_or("50"))
                .ok_or(Error(ErrorKind::Configuration))?
                * 1_000_000,
            backups: integer(backups.unwrap_or("5")).ok_or(Error(ErrorKind::Configuration))?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    Queued,
    QueueFull,
    Stopped,
}

enum Item {
    Record(Record),
    Stop,
}
#[derive(Default)]
struct Pending {
    items: VecDeque<Item>,
    inflight: usize,
    dropped: BigInt,
    closed: bool,
}
struct Queue {
    pending: Mutex<Pending>,
    changed: Condvar,
    capacity: BigInt,
}
struct ActiveBatch<'a>(&'a Queue, usize);
impl Drop for ActiveBatch<'_> {
    fn drop(&mut self) {
        self.0.release(self.1);
    }
}
impl Queue {
    fn full(&self, pending: &Pending) -> bool {
        self.capacity.sign() == Sign::Plus && BigInt::from(pending.items.len()) >= self.capacity
    }
    fn release(&self, count: usize) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        pending.inflight -= count;
        self.changed.notify_all();
    }
    fn next(&self) -> Option<(Vec<Record>, bool)> {
        let mut pending = self.pending.lock().ok()?;
        while pending.items.is_empty() {
            if pending.closed {
                return None;
            }
            pending = self.changed.wait(pending).ok()?;
        }
        let mut records = Vec::new();
        let mut stop = false;
        while let Some(item) = pending.items.pop_front() {
            match item {
                Item::Record(record) => records.push(record),
                Item::Stop => {
                    stop = true;
                    break;
                }
            }
        }
        self.changed.notify_all();
        Some((records, stop))
    }
}

#[derive(Default)]
struct Worker {
    task: Option<JoinHandle<()>>,
    done: Option<mpsc::Receiver<bool>>,
    stopped: bool,
    outcome: Option<bool>,
}

/// One process owner should retain this writer across Runtime reloads. Creation
/// is inert; file access and the worker start on the first emission only.
pub struct Writer {
    path: PathBuf,
    settings: Settings,
    queue: Arc<Queue>,
    worker: Mutex<Worker>,
}
impl Writer {
    pub fn new(path: PathBuf, settings: Settings) -> Self {
        Self {
            path,
            queue: Arc::new(Queue {
                pending: Mutex::new(Pending::default()),
                changed: Condvar::new(),
                capacity: settings.max_queue.clone(),
            }),
            settings,
            worker: Mutex::new(Worker::default()),
        }
    }
    pub fn emit(&self, event: Event) -> Result<Submission> {
        self.emit_at(event, OffsetDateTime::now_utc())
    }
    pub fn emit_at(&self, event: Event, at: OffsetDateTime) -> Result<Submission> {
        let record = event.record(at);
        let mut worker = self.worker.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
        if worker.stopped {
            return Ok(Submission::Stopped);
        }
        if worker.task.is_none() {
            let queue = self.queue.clone();
            let path = self.path.clone();
            let settings = self.settings.clone();
            let (send, done) = mpsc::channel();
            let task = std::thread::Builder::new()
                .name("safeyolo-audit-writer".into())
                .spawn(move || {
                    let mut healthy = true;
                    while let Some((batch, stop)) = queue.next() {
                        let reservation = ActiveBatch(&queue, batch.len());
                        let encoded = flush(&path, &settings, &batch).is_ok();
                        drop(reservation);
                        healthy &= encoded;
                        if stop || !encoded {
                            break;
                        }
                    }
                    let _ = send.send(healthy);
                })
                .map_err(|_| Error(ErrorKind::ThreadStart))?;
            worker.task = Some(task);
            worker.done = Some(done);
        }
        let mut pending = self
            .queue
            .pending
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?;
        // The same lock covers reservation/admission/observation, so a drain
        // cannot mistake an in-progress enqueue for an empty writer.
        if self.queue.full(&pending) {
            pending.dropped += 1;
            let total = pending.dropped.clone();
            drop(pending);
            drop(worker);
            writeln!(
                io::stderr().lock(),
                "[safeyolo] audit writer queue full (maxsize={}); dropped event (total_dropped={})",
                self.settings.max_queue,
                total
            )
            .map_err(|_| Error(ErrorKind::Io))?;
            return Ok(Submission::QueueFull);
        }
        pending.inflight += 1;
        pending.items.push_back(Item::Record(record));
        self.queue.changed.notify_one();
        Ok(Submission::Queued)
    }
    pub fn pending_count(&self) -> Result<usize> {
        Ok(self
            .queue
            .pending
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?
            .inflight)
    }
    pub fn dropped_count(&self) -> Result<BigInt> {
        Ok(self
            .queue
            .pending
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?
            .dropped
            .clone())
    }
    /// True means all admitted events finished a write/fallback attempt. It
    /// does not mean they reached disk or survived a process/filesystem crash.
    pub fn wait_for_drain(&self, timeout: Duration) -> Result<bool> {
        let started = Instant::now();
        let mut pending = self
            .queue
            .pending
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?;
        while pending.inflight != 0 {
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                return Ok(false);
            };
            let (next, wait) = self
                .queue
                .changed
                .wait_timeout(pending, remaining)
                .map_err(|_| Error(ErrorKind::Poisoned))?;
            pending = next;
            if wait.timed_out() && pending.inflight != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Stop producers, enqueue the source shutdown marker, and join. Each wait
    /// may use timeout; this is not a durability promise or a single time cap.
    /// The owner calls this only after stopping request/event producers.
    pub fn shutdown(&self, timeout: Duration) -> Result<bool> {
        let mut worker = self.worker.lock().map_err(|_| Error(ErrorKind::Poisoned))?;
        if worker.stopped && worker.task.is_none() {
            return Ok(worker.outcome.unwrap_or(true));
        }
        worker.stopped = true;
        if worker.task.is_none() {
            return Ok(true);
        }
        let started = Instant::now();
        let mut pending = self
            .queue
            .pending
            .lock()
            .map_err(|_| Error(ErrorKind::Poisoned))?;
        while self.queue.full(&pending) {
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                let records: Vec<_> = pending
                    .items
                    .drain(..)
                    .filter_map(|item| match item {
                        Item::Record(record) => Some(record),
                        Item::Stop => None,
                    })
                    .collect();
                drop(pending);
                let echoed = records
                    .iter()
                    .try_for_each(|record| fallback(record, "Event (shutdown)"));
                // Source timeout fallback removes entries but leaves its
                // in-flight reservations stranded. Release removed entries.
                self.queue.release(records.len());
                echoed?;
                return Ok(false);
            };
            let (next, _) = self
                .queue
                .changed
                .wait_timeout(pending, remaining)
                .map_err(|_| Error(ErrorKind::Poisoned))?;
            pending = next;
        }
        pending.items.push_back(Item::Stop);
        self.queue.changed.notify_one();
        drop(pending);
        let healthy = match worker.done.as_ref().map(|done| done.recv_timeout(timeout)) {
            Some(Ok(healthy)) => healthy,
            Some(Err(_)) => return Ok(false),
            None => true,
        };
        worker.done = None;
        let joined = worker.task.take().is_none_or(|task| task.join().is_ok());
        let outcome = healthy && joined && self.pending_count()? == 0;
        worker.outcome = Some(outcome);
        Ok(outcome)
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        // An unawaited owner drop stops admission and lets admitted records
        // drain; no detached owner task or blocked drop is introduced.
        let mut pending = self
            .queue
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        pending.closed = true;
        self.queue.changed.notify_one();
    }
}

fn rotate(path: &Path, settings: &Settings) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    match path.metadata() {
        Ok(metadata) if BigInt::from(metadata.len()) < settings.max_bytes => return Ok(()),
        Err(_) => return Ok(()),
        _ => {}
    }
    let mut index = settings.backups.clone();
    while index.sign() == Sign::Plus {
        let old = backup(path, &index);
        if old.exists() {
            if index == settings.backups {
                fs::remove_file(old)?;
            } else {
                fs::rename(old, backup(path, &(&index + 1)))?;
            }
        }
        index -= 1;
    }
    if path.exists() {
        fs::rename(path, backup(path, &1.into()))?;
    }
    Ok(())
}
fn backup(path: &Path, index: &BigInt) -> PathBuf {
    // Python 3.12 treats a terminal dot as no suffix; Rust treats it as an
    // empty extension. Preserve the original filename bytes in that case.
    if path
        .extension()
        .is_some_and(|extension| extension.is_empty())
    {
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".jsonl.{index}"));
        PathBuf::from(name)
    } else {
        path.with_extension(format!("jsonl.{index}"))
    }
}
fn append(path: &Path, settings: &Settings, batch: &[Record]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|_| Error(ErrorKind::Io))?;
    }
    rotate(path, settings).map_err(|_| Error(ErrorKind::Io))?;
    let mut lines = Zeroizing::new(String::new());
    for record in batch {
        lines.push_str(&record.encode()?);
        lines.push('\n');
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| Error(ErrorKind::Io))?;
    let written = file
        .write_all(lines.as_bytes())
        .map_err(|_| Error(ErrorKind::Io));
    // Python's context manager explicitly closes, with close failure taking
    // precedence over a write failure. Closing does not imply fsync.
    close(file)?;
    written
}
#[cfg(unix)]
fn close(file: std::fs::File) -> Result<()> {
    use std::os::fd::IntoRawFd;
    // Ownership transfers exactly once; POSIX close is never retried on EINTR.
    if unsafe { libc::close(file.into_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(Error(ErrorKind::Io))
    }
}
fn flush(path: &Path, settings: &Settings, batch: &[Record]) -> Result<()> {
    if let Err(error) = append(path, settings, batch) {
        writeln!(
            io::stderr().lock(),
            "[safeyolo] audit writer flush failed ({} entries): {error}",
            batch.len()
        )
        .map_err(|_| Error(ErrorKind::Io))?;
        for record in batch {
            fallback(record, "Event")?;
        }
    }
    Ok(())
}
fn fallback(record: &Record, label: &str) -> Result<()> {
    let encoded = record.encode()?;
    writeln!(
        io::stderr().lock(),
        "[safeyolo] {label}: {}",
        encoded.as_str()
    )
    .map_err(|_| Error(ErrorKind::Io))
}

#[cfg(test)]
mod tests;
