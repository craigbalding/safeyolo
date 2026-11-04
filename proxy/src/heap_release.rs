//! Return glibc's already-free pages without changing capture or request state.

use std::{
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};

/// One worker per proxy lifetime, retained across configuration reloads. The
/// interval amortizes arena scans rather than charging each request for a trim.
pub(crate) struct HeapRelease {
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl HeapRelease {
    pub(crate) fn start() -> Option<Self> {
        match Self::spawn(Duration::from_secs(30), || {
            // SAFETY: glibc's thread-safe trim only releases unused allocator
            // pages. It neither frees live allocations nor consumes pointers.
            // Zero is a normal result when no whole free pages can be released.
            unsafe { libc::malloc_trim(0) };
        }) {
            Ok(worker) => Some(worker),
            Err(error) => {
                eprintln!("Free heap release worker could not start: {error}");
                None
            }
        }
    }

    fn spawn(period: Duration, release: impl Fn() + Send + 'static) -> std::io::Result<Self> {
        let (stop, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("heap-release".into())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = receiver.recv_timeout(period) {
                    release();
                }
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for HeapRelease {
    fn drop(&mut self) {
        // Disconnect wakes an idle worker immediately. Join also waits for any
        // trim already in progress, so no worker outlives its proxy owner.
        self.stop.take();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            eprintln!("Free heap release worker failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_and_stops_when_owner_is_dropped() {
        let (sent, received) = mpsc::channel();
        let worker = HeapRelease::spawn(Duration::from_millis(5), move || {
            sent.send(()).unwrap();
        })
        .unwrap();
        for _ in 0..3 {
            received.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        drop(worker);
        // Drain a possible scan that started before Drop, then require channel
        // disconnection. A detached or spinning worker would time out instead.
        while received.try_recv().is_ok() {}
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)),
            Err(RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn stop_wakes_idle_worker_without_waiting_for_scan_interval() {
        let worker = HeapRelease::spawn(Duration::from_secs(3600), || {
            panic!("shutdown must not request another trim");
        })
        .unwrap();
        let (sent, received) = mpsc::channel();
        thread::spawn(move || {
            drop(worker);
            sent.send(()).unwrap();
        });
        received.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn real_trims_preserve_live_allocations() {
        let live = vec![0x5a; 1024 * 1024];
        let worker = HeapRelease::start().unwrap();
        // Exercise glibc's successful/no-pages result with live capture-like
        // bytes present; the periodic worker calls this same operation.
        for _ in 0..2 {
            unsafe { libc::malloc_trim(0) };
            assert!(live.iter().all(|byte| *byte == 0x5a));
        }
        drop(worker);
    }
}
