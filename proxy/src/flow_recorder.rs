//! Process-owned flow recording counters and the existing asynchronous writer.
//! Applied HTTP context controls eligibility; enqueue success is not durability.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};

use crate::{
    circuits::CircuitValue,
    flow_store::{ErrorKind, FlowStore},
    flow_writer::{FlowWriter, QueuedRecord},
    http_content::ContentError,
    policy::Policy,
};

pub(crate) struct FlowRecorder {
    enabled: AtomicBool,
    store: Option<Arc<FlowStore>>,
    writer: Option<FlowWriter>,
    recorded: AtomicU64,
    errors: AtomicU64,
    skipped: AtomicU64,
}

impl FlowRecorder {
    /// Read settings once. Reload changes admission but keeps this store and
    /// writer, including the case where recording was disabled at startup.
    pub(crate) fn start(enabled: bool, path: &Path, policy: Option<&Policy>) -> Self {
        let (store, writer) = if enabled {
            let (settings, configured_path) =
                policy.map(Policy::flow_store_settings).unwrap_or_default();
            let path = match configured_path.as_ref().filter(|value| value.truthy()) {
                Some(CircuitValue::Other(Value::String(path))) => Ok(Path::new(path)),
                Some(_) => Err(ErrorKind::Type),
                None => Ok(path),
            };
            let (store, error) = FlowStore::start(path, settings);
            let store = Arc::new(store);
            let writer = if let Some(error) = error {
                // Source running-hook exceptions preserve the assigned store,
                // including a usable partial connection, and install no writer.
                eprintln!("flow store initialization failed: {error}");
                None
            } else {
                Some(FlowWriter::new(
                    store.clone(),
                    queue_capacity(std::env::var("SAFEYOLO_FLOW_QUEUE_MAX").ok().as_deref()),
                ))
            };
            (Some(store), writer)
        } else {
            (None, None)
        };
        Self {
            enabled: AtomicBool::new(enabled),
            store,
            writer,
            recorded: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        }
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn store(&self) -> Option<&Arc<FlowStore>> {
        self.store.as_ref()
    }

    /// The exchange owner invokes this once at its actual terminal boundary.
    /// None means that no applied context/trusted owner existed at that moment.
    /// Build failures and queue drops retain the source's separate counters.
    pub(crate) fn record(
        &self,
        build: impl FnOnce(&FlowStore) -> Result<Option<QueuedRecord>, ContentError>,
    ) {
        let Some(store) = self
            .store
            .as_ref()
            .filter(|_| self.enabled.load(Ordering::Relaxed))
        else {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match build(store) {
            Ok(Some(record)) => {
                if let Some(writer) = &self.writer {
                    if writer.submit(record).is_err() {
                        eprintln!("flow writer could not start");
                        return;
                    }
                } else {
                    eprintln!("flow writer not installed; dropped record");
                }
                // The source counts enqueue attempts, including unavailable
                // writers and queue drops, independently of committed rows.
                self.recorded.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {
                self.skipped.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("flow record content failed: {error}");
            }
        }
    }

    pub(crate) fn stats(&self) -> Value {
        let mut stats = json!({
            "recorded": self.recorded.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "skipped": self.skipped.load(Ordering::Relaxed),
        });
        if let Some(writer) = &self.writer {
            let counts = writer.stats();
            stats["queue_dropped"] = counts.queue_dropped.into();
            stats["write_errors"] = counts.write_errors.into();
        }
        stats
    }

    pub(crate) fn shutdown(&self) -> bool {
        self.writer
            .as_ref()
            .is_none_or(|writer| writer.shutdown(Duration::from_secs(5)))
    }
}

/// Python int(string): Unicode decimal digits, optional sign and single
/// underscores between digits. Nonpositive queue sizes select unbounded mode.
fn queue_capacity(value: Option<&str>) -> usize {
    let Some(value) = value else {
        return 500;
    };
    let value = CircuitValue::Other(Value::String(value.into()));
    let Some(size) = crate::flow_store::integer(&value) else {
        return 500;
    };
    if size.sign() == num_bigint::Sign::Plus {
        usize::try_from(size).unwrap_or(usize::MAX)
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
