//! Queue completed flow records for compression and SQLite work off the HTTP
//! worker. The recorder counts submissions separately from these writer drops.

use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};

use serde_json::{Map, Value};

use crate::{
    flow_store::{BodyInput, FlowRecord, FlowStore},
    http_content::DecodedContent,
};

/// Owned data waiting for the existing flow-store write operation. Private
/// headers and body content must never be included in diagnostic formatting.
pub(crate) struct QueuedRecord {
    pub metadata: Map<String, Value>,
    /// A source surrogateescape Host or Content-Type cannot encode for SQLite.
    /// Preserve queue admission and count the failure in the writer, after the
    /// recorder has decoded both bodies. No replacement scalar is persisted.
    pub metadata_encoding_error: bool,
    pub request_body: DecodedContent,
    pub response_body: DecodedContent,
}

impl Drop for QueuedRecord {
    fn drop(&mut self) {
        crate::credentials::wipe_json(&mut Value::Object(std::mem::take(&mut self.metadata)));
    }
}

#[derive(Default)]
struct Pending {
    records: VecDeque<QueuedRecord>,
    closed: bool,
}

/// Python's queue grows with pending records, even when its configured maximum
/// is enormous. A preallocated synchronous channel would panic or exhaust
/// memory before the first record at otherwise valid source capacities.
struct RecordQueue {
    pending: Mutex<Pending>,
    ready: Condvar,
    capacity: usize,
}

impl RecordQueue {
    fn close(&self) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed = true;
        self.ready.notify_one();
    }

    fn next(&self) -> Option<QueuedRecord> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(record) = pending.records.pop_front() {
                return Some(record);
            }
            if pending.closed {
                return None;
            }
            pending = self.ready.wait(pending).unwrap_or_else(|e| e.into_inner());
        }
    }
}

struct Sender(Arc<RecordQueue>);

impl Sender {
    fn send(&self, record: QueuedRecord) -> Submission {
        let mut pending = self.0.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.closed {
            return Submission::Stopped;
        }
        if self.0.capacity != 0 && pending.records.len() >= self.0.capacity {
            return Submission::QueueFull;
        }
        pending.records.push_back(record);
        self.0.ready.notify_one();
        Submission::Queued
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.0.close();
    }
}

struct Receiver(Arc<RecordQueue>);

impl Drop for Receiver {
    fn drop(&mut self) {
        // A panicking worker must not leave a producer admitting more records.
        self.0.close();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Submission {
    Queued,
    QueueFull,
    Stopped,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Stats {
    pub queue_dropped: u64,
    pub write_errors: u64,
}

#[derive(Default)]
struct Counters {
    queue_dropped: AtomicU64,
    write_errors: AtomicU64,
}

#[derive(Default)]
struct Worker {
    sender: Option<Sender>,
    task: Option<JoinHandle<()>>,
    done: Option<mpsc::Receiver<()>>,
    stopped: bool,
}

pub(crate) struct FlowWriter {
    store: Arc<FlowStore>,
    capacity: usize,
    worker: Mutex<Worker>,
    counters: Arc<Counters>,
}

impl FlowWriter {
    /// Zero selects the source queue's unbounded mode. The configuration owner
    /// supplies 500 by default and maps source nonpositive limits to zero.
    pub(crate) fn new(store: Arc<FlowStore>, capacity: usize) -> Self {
        Self {
            store,
            capacity,
            worker: Mutex::new(Worker::default()),
            counters: Arc::new(Counters::default()),
        }
    }

    /// Enqueue without waiting for compression, database locks or disk writes.
    /// A queued result acknowledges ownership transfer, not persisted evidence.
    pub(crate) fn submit(&self, record: QueuedRecord) -> io::Result<Submission> {
        let mut worker = self.worker.lock().unwrap_or_else(|e| e.into_inner());
        if worker.stopped {
            return Ok(Submission::Stopped);
        }
        if worker.sender.is_none() {
            let queue = Arc::new(RecordQueue {
                pending: Mutex::new(Pending::default()),
                ready: Condvar::new(),
                capacity: self.capacity,
            });
            let sender = Sender(queue.clone());
            let receiver = Receiver(queue);
            let (done_send, done) = mpsc::channel();
            let store = self.store.clone();
            let counters = self.counters.clone();
            let task = std::thread::Builder::new()
                .name("safeyolo-flow-writer".into())
                .spawn(move || {
                    write_records(&store, &receiver, &counters);
                    let _ = done_send.send(());
                })?;
            worker.sender = Some(sender);
            worker.done = Some(done);
            worker.task = Some(task);
        }
        let result = worker.sender.as_ref().unwrap().send(record);
        if result == Submission::QueueFull {
            let total = self.counters.queue_dropped.fetch_add(1, Ordering::Relaxed) + 1;
            eprintln!(
                "flow writer queue full (maxsize={}); dropped record (total_dropped={total})",
                self.capacity
            );
        }
        Ok(result)
    }

    pub(crate) fn stats(&self) -> Stats {
        Stats {
            queue_dropped: self.counters.queue_dropped.load(Ordering::Relaxed),
            write_errors: self.counters.write_errors.load(Ordering::Relaxed),
        }
    }

    /// Stop admission and drain already accepted records. Call after request
    /// owners stop, outside async workers. False reports a timeout or failed
    /// worker; it never claims that queued evidence was persisted.
    pub(crate) fn shutdown(&self, timeout: Duration) -> bool {
        let mut worker = self.worker.lock().unwrap_or_else(|e| e.into_inner());
        worker.stopped = true;
        drop(worker.sender.take());
        let Some(done) = worker.done.as_ref() else {
            return true;
        };
        if done.recv_timeout(timeout).is_err() {
            return false;
        }
        worker.done = None;
        worker.task.take().is_none_or(|task| task.join().is_ok())
    }
}

impl Drop for FlowWriter {
    fn drop(&mut self) {
        // Closing the sender lets the worker drain. Its Arc retains the store
        // until it exits; an unawaited drop cannot close a live SQLite handle.
        let worker = self.worker.get_mut().unwrap_or_else(|e| e.into_inner());
        drop(worker.sender.take());
    }
}

fn write_records(store: &FlowStore, records: &Receiver, counters: &Counters) {
    while let Some(record) = records.0.next() {
        if record.metadata_encoding_error {
            counters.write_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("flow writer failed to record: metadata encoding");
            continue;
        }
        let result = store.record(
            FlowRecord {
                metadata: &record.metadata,
                request_body: Some(BodyInput::decoded_prefix(
                    &record.request_body.content,
                    record.request_body.total_bytes,
                )),
                response_body: Some(BodyInput::decoded_prefix(
                    &record.response_body.content,
                    record.response_body.total_bytes,
                )),
            },
            (crate::circuit_runtime::now() * 1000.).trunc() as i64,
        );
        match result {
            Ok(recorded) => {
                if recorded.response_fts_failed || recorded.request_fts_failed {
                    eprintln!("flow body search index write failed");
                }
            }
            Err(error) => {
                counters.write_errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("flow writer failed to record: {:?}", error.kind());
            }
        }
    }
}

#[cfg(test)]
mod tests;
