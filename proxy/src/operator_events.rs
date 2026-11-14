//! Shared log-backed operator feed. Recovery controls describe current state,
//! never a recorded event or delivery guarantee for the audit archive.
use crate::{Error, RuntimeState};
use bytes::Bytes;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{broadcast, watch};

mod log;

#[derive(Clone, PartialEq, Eq)]
struct State {
    signals: Option<[u8; 32]>,
    approvals: Option<[u8; 32]>,
    log_readable: bool,
    gap: Option<&'static str>,
    revision: u64,
    checked_log_revision: u64,
}
impl State {
    fn bytes(&self) -> Bytes {
        Bytes::from(
            json!({"type":"operator_state", "revision":self.revision,
            "signals":if self.signals.is_some() {"ready"} else {"unavailable"},
            "approvals":if self.approvals.is_some() {"ready"} else {"unavailable"},
            "log":if self.log_readable {"following"} else {"unavailable"},
            "history_gap":self.gap})
            .to_string(),
        )
    }
}

pub(crate) struct Feed {
    records: broadcast::Sender<Bytes>,
    state: watch::Sender<State>,
    pending_log_revision: AtomicU64,
}
impl Feed {
    pub(crate) async fn start(
        runtime: RuntimeState,
        stop: watch::Receiver<bool>,
        tasks: &crate::admin_listener::ListenerTasks,
    ) -> Arc<Self> {
        let (records, _) = broadcast::channel(64);
        let (state, _) = watch::channel(State {
            signals: None,
            approvals: None,
            log_readable: false,
            gap: None,
            revision: 0,
            checked_log_revision: 0,
        });
        let feed = Arc::new(Self {
            records,
            state,
            pending_log_revision: AtomicU64::new(0),
        });
        let source = runtime.read().ok().map(|r| r.audit.log_source());
        let follower = tokio::task::spawn_blocking(move || {
            source.map(|(path, settings)| log::Follower::new(path, settings))
        })
        .await
        .ok()
        .flatten();
        let owner = feed.clone();
        let mut stopped = stop.clone();
        crate::admin_listener::spawn_listener_task(tasks, async move {
            let Some(mut follower) = follower else { return };
            loop {
                let result = tokio::task::spawn_blocking(move || {
                    let result = follower.read();
                    (follower, result)
                })
                .await;
                let Ok((next, result)) = result else { return };
                follower = next;
                owner.state.send_if_modified(|state| {
                    let changed = state.log_readable != result.readable
                        || (result.gap.is_some() && state.gap != result.gap);
                    state.log_readable = result.readable;
                    if result.gap.is_some() {
                        state.gap = result.gap;
                    }
                    if changed {
                        state.revision += 1;
                    }
                    changed
                });
                for line in result.records {
                    let _ = owner.records.send(line);
                }
                // A client may refresh from these records while a complete
                // create/resolve cycle falls between host reads. Require a
                // later current-state control even if the digest is unchanged.
                // Mark after forwarding so a read cannot acknowledge a record
                // before that record becomes observable.
                if result.refresh_pending {
                    owner.pending_log_revision.fetch_add(1, Ordering::SeqCst);
                }
                tokio::select! {
                    _ = stopped.changed() => return,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                }
            }
        })
        .await;
        let owner = feed.clone();
        let mut stopped = stop;
        crate::admin_listener::spawn_listener_task(tasks, async move {
            loop {
                // One local read for all viewers. No client timer or broker is
                // involved. Retained watch versions reach each observer even
                // when intermediate invalidations coalesce.
                // Capture before the read: a delivery overlapping this read
                // must remain outstanding for the next host reconciliation.
                let log_revision = owner.pending_log_revision.load(Ordering::SeqCst);
                let state = runtime.clone();
                let result = tokio::task::spawn_blocking(move || pending(&state)).await;
                let (signals, approvals) = result.unwrap_or((None, None));
                owner.update_pending(log_revision, signals, approvals);
                tokio::select! {
                    _ = stopped.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
            }
        })
        .await;
        feed
    }
    fn update_pending(
        &self,
        log_revision: u64,
        signals: Option<[u8; 32]>,
        approvals: Option<[u8; 32]>,
    ) {
        self.state.send_if_modified(|state| {
            if (state.signals, state.approvals) == (signals, approvals)
                && state.checked_log_revision == log_revision
            {
                return false;
            }
            state.signals = signals;
            state.approvals = approvals;
            state.checked_log_revision = log_revision;
            state.revision += 1;
            true
        });
    }
    pub(crate) fn subscribe(&self) -> Subscription {
        Subscription {
            records: self.records.subscribe(),
            state: self.state.subscribe(),
            initial: true,
        }
    }
}

fn pending(state: &RuntimeState) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
    let Ok(runtime) = state.read().map(|r| r.clone()) else {
        return (None, None);
    };
    let signals = crate::agent_api::coord::signals::operator_fingerprint(&runtime.coord).ok();
    let approvals = if runtime.audit.approvals_enabled() {
        runtime.policy.as_ref().and_then(|policy| {
            runtime
                .audit
                .approvals()
                .pending_fingerprint(&runtime.audit, policy, state)
                .ok()
        })
    } else {
        Some([0; 32])
    };
    (signals, approvals)
}

pub(crate) struct Subscription {
    records: broadcast::Receiver<Bytes>,
    state: watch::Receiver<State>,
    initial: bool,
}
impl Subscription {
    pub(crate) async fn next(&mut self) -> Result<Bytes, Error> {
        if self.initial {
            self.initial = false;
            return Ok(self.state.borrow_and_update().bytes());
        }
        tokio::select! {
            biased;
            changed = self.state.changed() => {changed?; Ok(self.state.borrow_and_update().bytes())},
            record = self.records.recv() => record.map_err(|_| "operator event buffer overflow or feed stopped; history may be missing; reconnect to refresh current work".into()),
        }
    }
}

pub(crate) fn refreshes_pending(event: &Value) -> bool {
    event["type"] == "operator_state"
        || is_signal(event)
        || event["approval"]["required"] == true
        || event["event"].as_str().is_some_and(|name| {
            name.starts_with("admin.") || name == "agent.network_action_prepared"
        })
}

pub(crate) fn is_signal(event: &serde_json::Value) -> bool {
    matches!(
        event["event"].as_str(),
        Some("coord.signal_created" | "coord.signal_resolved" | "coord.signal_superseded")
    )
}

pub(crate) fn is_operator_event(event: &serde_json::Value) -> bool {
    if is_signal(event) {
        return true;
    }
    let approval = event.get("approval").and_then(serde_json::Value::as_object);
    if approval
        .and_then(|approval| approval.get("required"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    let event_name = event
        .get("event")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if event_name.starts_with("agent.")
        || event_name == "ops.circuit_breaker.open"
        || matches!(
            event_name,
            "admin.approval_added"
                | "admin.approval_decided"
                | "admin.denial"
                | "admin.host_allowed"
                | "admin.host_denied"
                | "admin.host_rate_updated"
                | "admin.host_bypass_added"
                | "admin.mode_change"
                | "admin.baseline_update"
                | "admin.task_policy_update"
                | "admin.task_policy_clear"
                | "admin.agent_service_authorized"
                | "admin.agent_service_revoked"
                | "admin.gateway_grant"
                | "admin.gateway_grant_revoked"
                | "admin.contract_binding_approved"
                | "admin.desktop_presented"
                | "admin.desktop_presentation_failed"
                | "coord.message_allowed"
                | "coord.message_flagged"
                | "coord.message_blocked"
                | "coord.message_scan_failed"
        )
        || matches!(
            event_name,
            "ops.command_centre_tailnet_exited"
                | "ops.command_centre_tailnet_failed"
                | "ops.command_centre_tailnet_started"
                | "ops.command_centre_tailnet_stopped"
                | "ops.proxy_start"
                | "ops.proxy_stop"
                | "ops.proxy_start_failed"
        )
    {
        return true;
    }
    event
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| matches!(kind, "security" | "gateway"))
        && event
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|severity| matches!(severity, "high" | "critical"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn overflow_is_explicit_and_one_observer_cannot_consume_anothers_state_change() {
        let (records, _) = broadcast::channel(2);
        let (state, _) = watch::channel(State {
            signals: None,
            approvals: None,
            log_readable: true,
            gap: None,
            revision: 0,
            checked_log_revision: 0,
        });
        let feed = Feed {
            records,
            state,
            pending_log_revision: AtomicU64::new(0),
        };
        let mut slow = feed.subscribe();
        let mut fast = feed.subscribe();
        slow.next().await.unwrap();
        fast.next().await.unwrap();
        for sequence in 0..5 {
            feed.records
                .send(Bytes::from(sequence.to_string()))
                .unwrap();
            assert_eq!(fast.next().await.unwrap(), sequence.to_string());
        }
        assert!(
            slow.next()
                .await
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
        let mut other = feed.subscribe();
        other.next().await.unwrap();
        feed.state.send_modify(|state| {
            state.signals = Some([1; 32]);
            state.revision += 1;
        });
        for observer in [&mut fast, &mut other] {
            let value: Value = serde_json::from_slice(&observer.next().await.unwrap()).unwrap();
            assert_eq!(value["type"], "operator_state");
            assert!(value.get("event").is_none());
            assert_eq!(value["signals"], "ready");
        }
    }

    #[tokio::test]
    async fn log_delivery_overlapping_a_read_requires_a_later_control_even_for_the_same_pending_set()
     {
        let (records, _) = broadcast::channel(2);
        let empty = Some([0; 32]);
        let (state, _) = watch::channel(State {
            signals: empty,
            approvals: empty,
            log_readable: true,
            gap: None,
            revision: 0,
            checked_log_revision: 0,
        });
        let feed = Feed {
            records,
            state,
            pending_log_revision: AtomicU64::new(0),
        };
        let mut observer = feed.subscribe();
        observer.next().await.unwrap();

        let before_read = feed.pending_log_revision.load(Ordering::SeqCst);
        // The log becomes visible while a host read is in progress. Neither
        // host read observes the brief pending state seen by the client.
        let creation = Bytes::from_static(br#"{"event":"coord.signal_created"}"#);
        feed.records.send(creation.clone()).unwrap();
        feed.pending_log_revision.fetch_add(1, Ordering::SeqCst);
        assert_eq!(observer.next().await.unwrap(), creation);
        feed.update_pending(before_read, empty, empty);
        assert!(!observer.state.has_changed().unwrap());
        let next_read = feed.pending_log_revision.load(Ordering::SeqCst);
        feed.update_pending(next_read, empty, empty);
        let control: Value = serde_json::from_slice(&observer.next().await.unwrap()).unwrap();
        assert_eq!(control["type"], "operator_state");
        assert_eq!(control["revision"], 1);
        assert!(control.get("event").is_none());

        // A settled, unchanged host does not cause idle viewer requests.
        feed.update_pending(next_read, empty, empty);
        assert!(!observer.state.has_changed().unwrap());
    }
}
