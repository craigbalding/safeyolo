//! Concrete memory-monitor lifecycle calls. Observation failures never alter
//! security decisions, transport results or evidence-failure flags.

use std::{io::Write, sync::Arc};

use zeroize::Zeroizing;

use crate::{Runtime, audit::Writer, circuit_runtime::now, memory_monitor};

pub(crate) fn observe(result: memory_monitor::Result<()>) {
    if let Err(error) = result {
        // In the source production container this exception can skip later
        // security hooks. Contain it here so monitoring cannot bypass them.
        let _ = writeln!(
            std::io::stderr().lock(),
            "Memory monitor observation failed: {:?}",
            error.kind()
        );
    }
}

#[cfg(not(test))]
pub(crate) fn sample() -> Result<memory_monitor::MemorySample, memory_monitor::SampleError> {
    // Request hooks are synchronous. Let a multithread runtime replace this
    // executor worker while procfs is read; sync/current-thread callers remain
    // valid and use the same direct sampler without inventing a new task.
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(memory_monitor::process::sample)
    } else {
        memory_monitor::process::sample()
    }
}

#[cfg(test)]
pub(crate) fn sample() -> Result<memory_monitor::MemorySample, memory_monitor::SampleError> {
    Ok(memory_monitor::MemorySample {
        rss_kb: 0.into(),
        peak_kb: 0.into(),
    })
}

pub(crate) fn running(runtime: &Runtime) {
    observe(runtime.memory_monitor.running(&runtime.audit, sample, now));
}

/// One accepted client task owns this guard, including before its first poll.
/// Request identity clones and inner CONNECT streams never own terminal calls.
pub(crate) struct Client {
    monitor: Arc<memory_monitor::MemoryMonitor>,
    writer: Arc<Writer>,
    id: Zeroizing<String>,
}

impl Client {
    pub(crate) fn new(runtime: &Runtime, id: &str) -> Self {
        observe(runtime.memory_monitor.client_connected(id, now));
        Self {
            monitor: runtime.memory_monitor.clone(),
            writer: runtime.audit.clone(),
            id: Zeroizing::new(id.into()),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        observe(
            self.monitor
                .client_disconnected(&self.id, &self.writer, now),
        );
    }
}

/// One upgraded relay owns the terminal call. Readers clone only its monitor,
/// so a canceled blocking scanner cannot retain the session's cleanup owner.
pub(crate) struct WebSocket {
    monitor: Arc<memory_monitor::MemoryMonitor>,
    writer: Arc<Writer>,
    id: Zeroizing<String>,
}

impl WebSocket {
    pub(crate) fn new(runtime: &Runtime, id: &str, host: &str) -> Self {
        observe(runtime.memory_monitor.websocket_start(id, host, now));
        Self {
            monitor: runtime.memory_monitor.clone(),
            writer: runtime.audit.clone(),
            id: Zeroizing::new(id.into()),
        }
    }

    pub(crate) fn monitor(&self) -> Arc<memory_monitor::MemoryMonitor> {
        self.monitor.clone()
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        observe(self.monitor.websocket_end(&self.id, &self.writer, now));
    }
}
