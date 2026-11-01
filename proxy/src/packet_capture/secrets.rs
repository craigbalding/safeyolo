//! Rustls-owned session secrets. Never canonical metadata, Debug, or log output.
use super::Limits;
use std::{
    collections::HashMap,
    fmt::{self, Write},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use zeroize::Zeroizing;

const CONNECTION_BYTES: usize = 1024;
pub(super) struct Store {
    connections: Mutex<HashMap<String, Weak<Secrets>>>,
    budget: Arc<Budget>,
    limits: Limits,
}
struct Budget {
    bytes: AtomicUsize,
    limit: usize,
}
impl Budget {
    fn charge(&self, bytes: usize) -> bool {
        self.bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .is_ok()
    }
}
impl Store {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            connections: Mutex::default(),
            budget: Arc::new(Budget {
                bytes: AtomicUsize::new(0),
                limit: limits.bytes,
            }),
            limits,
        }
    }
    pub(super) fn register(&self, connection: &str) -> Option<Arc<Secrets>> {
        let mut entries = self.connections.try_lock().ok()?;
        entries.retain(|_, entry| entry.strong_count() != 0);
        let metadata_bytes = CONNECTION_BYTES.saturating_add(connection.len());
        if entries.len() >= self.limits.items || !self.budget.charge(metadata_bytes) {
            return None;
        }
        let secrets = Arc::new(Secrets {
            state: Mutex::new(State {
                lines: Zeroizing::new(String::new()),
                pending: 0,
            }),
            failed: AtomicBool::new(false),
            budget: self.budget.clone(),
            notify: Notify::new(),
            metadata_bytes,
        });
        entries.insert(connection.to_owned(), Arc::downgrade(&secrets));
        Some(secrets)
    }
    pub(super) async fn snapshot(
        &self,
        connection: &str,
    ) -> (Zeroizing<String>, Option<&'static str>) {
        let entry = self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(connection)
            .and_then(Weak::upgrade);
        let Some(entry) = entry else {
            return (
                Zeroizing::new(String::new()),
                Some("tls_secrets_unavailable"),
            );
        };
        // The capture worker waits; rustls, the agent path and other consumers do not.
        let ready = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                let notified = entry.notify.notified();
                if entry.failed.load(Ordering::Acquire)
                    || entry
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .pending
                        == 0
                {
                    break;
                }
                notified.await;
            }
        })
        .await;
        if ready.is_err() {
            entry.failed.store(true, Ordering::Release);
        }
        let state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
        let reason = (entry.failed.load(Ordering::Acquire) || state.lines.is_empty())
            .then_some("tls_secret_order_or_budget_unavailable");
        (Zeroizing::new(state.lines.to_string()), reason)
    }
}
struct State {
    lines: Zeroizing<String>,
    pending: usize,
}
pub(crate) struct Secrets {
    state: Mutex<State>,
    failed: AtomicBool,
    budget: Arc<Budget>,
    notify: Notify,
    metadata_bytes: usize,
}
impl Secrets {
    pub(crate) fn begin(self: &Arc<Self>) -> Handshake {
        // Source setup and callbacks never wait for a capture-side lock.
        match self.state.try_lock() {
            Ok(mut state) => state.pending += 1,
            Err(_) => self.failed.store(true, Ordering::Release),
        }
        Handshake {
            secrets: self.clone(),
        }
    }
}
impl Drop for Secrets {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        self.budget
            .bytes
            .fetch_sub(self.metadata_bytes + state.lines.len(), Ordering::Relaxed);
    }
}
pub(crate) struct Handshake {
    secrets: Arc<Secrets>,
}
impl Handshake {
    pub(crate) fn logger(&self) -> Arc<dyn rustls::KeyLog> {
        self.secrets.clone()
    }
}
impl Drop for Handshake {
    fn drop(&mut self) {
        if let Ok(mut state) = self.secrets.state.try_lock() {
            state.pending = state.pending.saturating_sub(1);
        } else {
            self.secrets.failed.store(true, Ordering::Release);
        }
        self.secrets.notify.notify_waiters();
    }
}
impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CaptureTlsSecrets")
    }
}
impl rustls::KeyLog for Secrets {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let fail = || {
            self.failed.store(true, Ordering::Release);
            self.notify.notify_waiters();
        };
        // Inputs belong to rustls. Keep a finite allocation even if an upstream
        // implementation changes its labels or key sizes.
        if label.len() > 80
            || client_random.len() != 32
            || secret.len() > 256
            || !label
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            fail();
            return;
        }
        let size = label.len() + client_random.len() * 2 + secret.len() * 2 + 3;
        let Ok(mut state) = self.state.try_lock() else {
            fail();
            return;
        };
        if !self.budget.charge(size) {
            fail();
            return;
        }
        state.lines.reserve_exact(size);
        state.lines.push_str(label);
        state.lines.push(' ');
        for byte in client_random {
            write!(&mut *state.lines, "{byte:02x}").unwrap();
        }
        state.lines.push(' ');
        for byte in secret {
            write!(&mut *state.lines, "{byte:02x}").unwrap();
        }
        state.lines.push('\n');
        self.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::KeyLog;
    #[tokio::test(start_paused = true)]
    async fn bounded_handshake_and_secret_budget_failures_are_explicit_and_release_storage() {
        let store = Store::new(Limits {
            items: 1,
            bytes: 2048,
        });
        let secrets = store.register("one").unwrap();
        assert!(store.register("two").is_none());
        let handshake = secrets.begin();
        secrets.log("CLIENT_RANDOM", &[1; 32], &[2; 48]);
        let (lines, limitation) = store.snapshot("one").await;
        assert!(limitation.is_some());
        assert!(lines.starts_with("CLIENT_RANDOM "));
        assert_eq!(format!("{secrets:?}"), "CaptureTlsSecrets");
        drop(handshake);
        drop(secrets);
        assert_eq!(store.budget.bytes.load(Ordering::Relaxed), 0);
        let secrets = store.register("two").unwrap();
        let handshake = secrets.begin();
        for _ in 0..20 {
            secrets.log("CLIENT_RANDOM", &[1; 32], &[2; 48]);
        }
        drop(handshake);
        let (lines, limitation) = store.snapshot("two").await;
        assert!(limitation.is_some());
        assert!(lines.len() <= 1024);
        assert!(store.budget.bytes.load(Ordering::Relaxed) <= 2048);
        drop(secrets);
        assert_eq!(store.budget.bytes.load(Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn callbacks_and_handshake_completion_do_not_wait_for_capture_locks() {
        let store = Store::new(Limits::default());
        let secrets = store.register("one").unwrap();
        let handshake = secrets.begin();
        let held = secrets.state.lock().unwrap();
        secrets.log("CLIENT_RANDOM", &[1; 32], &[2; 48]);
        drop(handshake);
        drop(held);
        let (lines, limitation) = store.snapshot("one").await;
        assert!(lines.is_empty());
        assert!(limitation.is_some());
    }
}
