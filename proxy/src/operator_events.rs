//! Ephemeral host-only operator events. Canonical state and JSONL own recovery.
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::{mpsc, watch};

use crate::{Error, agent_api::CoordClient};

const SUBJECT: &str = "safeyolo.operator.events";
const TIMEOUT: Duration = Duration::from_secs(2);

/// A subscription is ready only after the server has processed SUB. A loss
/// closes this attachment; reconnect starts at the new subscription, with no
/// history replay. Separate connections isolate slow operator subscribers.
pub(crate) struct Subscription {
    client: async_nats::Client,
    messages: async_nats::Subscriber,
    failed: watch::Receiver<bool>,
}

pub(crate) async fn subscribe(directory: &Path) -> Result<Subscription, Error> {
    let coord = CoordClient::new(None, Some(directory.to_owned()));
    let (failure, failed) = watch::channel(false);
    let options = async_nats::ConnectOptions::new()
        .subscription_capacity(256)
        .max_reconnects(1)
        .event_callback(move |event| {
            let failure = failure.clone();
            async move {
                if matches!(
                    event,
                    async_nats::Event::Disconnected
                        | async_nats::Event::Closed
                        | async_nats::Event::SlowConsumer(_)
                ) {
                    let _ = failure.send(true);
                }
            }
        });
    tokio::time::timeout(TIMEOUT, async {
        let client = coord.connect_nats(options).await?;
        let messages = client.subscribe(SUBJECT).await?;
        client.flush().await?;
        if *failed.borrow() {
            return Err("live operator events unavailable".into());
        }
        Ok(Subscription {
            client,
            messages,
            failed,
        })
    })
    .await
    .map_err(|_| "live operator events unavailable")?
}

impl Subscription {
    pub(crate) async fn next(&mut self) -> Result<Bytes, Error> {
        if *self.failed.borrow()
            || self.client.connection_state() != async_nats::connection::State::Connected
        {
            return Err("live operator events lost; reconnect to resume (no replay)".into());
        }
        tokio::select! {
            biased;
            _ = self.failed.changed() => Err("live operator events lost; reconnect to resume (no replay)".into()),
            message = self.messages.next() => message.map(|message| message.payload).ok_or_else(|| "live operator events closed".into()),
        }
    }
}

/// The audit worker only tries an in-memory send. A separate bounded worker
/// prevents a broker outage from holding archive writes or request producers.
/// Each publish has one bounded attempt; this is not a durable queue.
pub(crate) struct Publisher {
    directory: PathBuf,
    worker: Mutex<Option<Worker>>,
}
struct Worker {
    send: mpsc::Sender<Bytes>,
    done: std::sync::mpsc::Receiver<()>,
}

impl Publisher {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            worker: Mutex::new(None),
        }
    }

    pub(crate) async fn subscribe(&self) -> Result<Subscription, Error> {
        subscribe(&self.directory).await
    }

    pub(crate) fn submit(&self, bytes: Bytes) {
        let Ok(mut worker) = self.worker.lock() else {
            return;
        };
        if worker.is_none() {
            let (send, mut receive) = mpsc::channel::<Bytes>(256);
            let (finished, done) = std::sync::mpsc::channel();
            let directory = self.directory.clone();
            let started = std::thread::Builder::new().name("safeyolo-live-events".into()).spawn(move || {
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    runtime.block_on(async move {
                        let coord = CoordClient::new(None, Some(directory));
                        let mut client = None;
                        let mut unavailable = false;
                        while let Some(bytes) = receive.recv().await {
                            let result: Result<(), Error> = tokio::time::timeout(TIMEOUT, async {
                                if client.as_ref().is_none_or(|client: &async_nats::Client| client.connection_state() != async_nats::connection::State::Connected) {
                                    client = Some(coord.connect_nats(async_nats::ConnectOptions::new().max_reconnects(1)).await?);
                                }
                                let connection = client.as_ref().expect("connected live publisher");
                                connection.publish(SUBJECT, bytes).await?;
                                // Short host commands must not exit with a queued publish.
                                connection.flush().await?;
                                Ok(())
                            }).await.unwrap_or_else(|_| Err("live publish timed out".into()));
                            if result.is_err() {
                                client = None;
                                // Do not replay events accumulated during a failed attempt.
                                while receive.try_recv().is_ok() {}
                                if !unavailable { eprintln!("Live operator events unavailable; events may be lost. Canonical state and audit remain independent."); }
                                unavailable = true;
                            } else if unavailable {
                                eprintln!("Live operator event publication recovered; missed events are not replayed.");
                                unavailable = false;
                            }
                        }
                    });
                } else {
                    eprintln!("Live operator event worker could not start.");
                }
                let _ = finished.send(());
            });
            if started.is_err() {
                eprintln!("Live operator event worker could not start.");
                return;
            }
            *worker = Some(Worker { send, done });
        }
        if worker
            .as_ref()
            .expect("live worker started")
            .send
            .try_send(bytes)
            .is_err()
        {
            eprintln!("Live operator event buffer unavailable; event lost.");
        }
    }

    pub(crate) fn shutdown(&self, timeout: Duration) {
        if let Ok(mut worker) = self.worker.lock()
            && let Some(Worker { send, done }) = worker.take()
        {
            drop(send);
            if done.recv_timeout(timeout).is_err() {
                eprintln!(
                    "Live operator event publication did not drain before shutdown; events may be lost."
                );
            }
        }
    }
}

pub(crate) fn is_signal(event: &serde_json::Value) -> bool {
    matches!(
        event["event"].as_str(),
        Some("coord.signal_created" | "coord.signal_resolved" | "coord.signal_superseded")
    )
}

pub(crate) fn is_operator_event(event: &serde_json::Value) -> bool {
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
                | "plumb.approved"
                | "plumb.denied"
                | "plumb.conversation_created"
                | "plumb.message_blocked"
                | "plumb.message_flagged"
                | "plumb.message_allowed"
                | "plumb.conversation_closed"
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
#[path = "../tests/support/operator_nats.rs"]
mod operator_nats;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Event, Kind, Settings, Severity, Writer};
    use serde_json::{Value, json};

    #[tokio::test]
    #[ignore = "requires the pinned SAFEYOLO_COORD_NATS_BINARY"]
    async fn short_host_command_finishes_live_publication() {
        const CHILD_ROOT: &str = "SAFEYOLO_HOST_EVENT_TEST_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            crate::host_platform::in_instance(root.into(), async {
                crate::host_events::write(
                    "alice",
                    "traffic.preview_http",
                    "traffic",
                    "Raw traffic stays in its archive".into(),
                    None,
                    json!({"private_body":"synthetic-private-body"}),
                );
                crate::host_events::write(
                    "alice",
                    "agent.stopped",
                    "agent",
                    "Short host command".into(),
                    None,
                    json!({"reason":"user_request"}),
                );
            })
            .await;
            return;
        }
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = directory.path();
        std::fs::write(
            root.join("config.toml"),
            "audit_log_path='host-audit.jsonl'\n",
        )
        .unwrap();
        let _nats = operator_nats::Nats::start(root).await;
        let mut events = subscribe(&root.join("data/coord")).await.unwrap();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "operator_events::tests::short_host_command_finishes_live_publication",
                "--ignored",
            ])
            .env(CHILD_ROOT, root)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = tokio::time::timeout(TIMEOUT, events.next())
            .await
            .unwrap()
            .unwrap();
        let event: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(event["event"], "agent.stopped");
        assert_eq!(event["agent"], "alice");
        assert_eq!(event["details"]["reason"], "user_request");
        assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-private-body"));
        let audit = std::fs::read_to_string(root.join("host-audit.jsonl")).unwrap();
        assert_eq!(audit.lines().count(), 2);
        assert!(audit.contains("synthetic-private-body"));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), events.next())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires the pinned SAFEYOLO_COORD_NATS_BINARY"]
    async fn subscription_orders_bursts_and_archive_failure_does_not_stop_live_events() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = directory.path();
        let _nats = operator_nats::Nats::start(root).await;
        let mut events = subscribe(&root.join("data/coord")).await.unwrap();
        let publisher = operator_nats::Nats::publisher(root).await;
        // Publish immediately after subscription readiness, before reading.
        for sequence in 0..20 {
            publisher
                .publish(SUBJECT, json!({"sequence":sequence}).to_string().into())
                .await
                .unwrap();
        }
        publisher.flush().await.unwrap();
        for sequence in 0..20 {
            let bytes = tokio::time::timeout(TIMEOUT, events.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap()["sequence"],
                sequence
            );
        }
        let sink = root.join("blocked-audit");
        std::fs::create_dir(&sink).unwrap();
        let writer = Writer::new(sink.clone(), Settings::default())
            .with_live_events(root.join("data/coord"));
        let event = Event::new(
            "agent.stopped",
            Kind::Agent,
            Severity::Low,
            "Archive sink is a directory",
        );
        assert!(writer.emit_confirmed(event).await.is_err());
        let bytes = tokio::time::timeout(TIMEOUT, events.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["event"],
            "agent.stopped"
        );
        assert!(writer.shutdown(Duration::from_secs(5)).unwrap());
        assert!(sink.is_dir());
    }

    #[tokio::test]
    #[ignore = "requires the pinned SAFEYOLO_COORD_NATS_BINARY"]
    async fn subscriber_overflow_reports_loss_instead_of_a_complete_feed() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let root = directory.path();
        let _nats = operator_nats::Nats::start(root).await;
        let mut stalled = subscribe(&root.join("data/coord")).await.unwrap();
        let publisher = operator_nats::Nats::publisher(root).await;
        for sequence in 0..512 {
            publisher
                .publish(SUBJECT, json!({"sequence":sequence}).to_string().into())
                .await
                .unwrap();
        }
        publisher.flush().await.unwrap();
        tokio::time::timeout(TIMEOUT, async {
            while !*stalled.failed.borrow() {
                stalled.failed.changed().await.unwrap();
            }
        })
        .await
        .expect("slow subscriber did not report loss");
        assert!(stalled.next().await.is_err());
        let mut fresh = subscribe(&root.join("data/coord")).await.unwrap();
        publisher
            .publish(SUBJECT, b"recovered".as_slice().into())
            .await
            .unwrap();
        publisher.flush().await.unwrap();
        assert_eq!(
            tokio::time::timeout(TIMEOUT, fresh.next())
                .await
                .unwrap()
                .unwrap(),
            "recovered"
        );
    }
}
