//! Reusable H2 sessions belong to one admitted CONNECT transport. Its trusted
//! identity and destination never change. A runtime snapshot additionally binds
//! parent/provider routing, TLS trust and configuration. Only initialization
//! holds the lock; sending or waiting for a response never holds it.

use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use tokio::{sync::Notify, time::Instant};

use super::*;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
type Sender = hyper::client::conn::http2::SendRequest<ForwardedRequestBody>;

#[derive(Default)]
pub(super) struct Sessions(tokio::sync::Mutex<Vec<Cached>>);

struct Cached {
    runtime: Weak<Runtime>,
    provider: Option<String>,
    agent: Option<String>,
    session: Arc<tokio::sync::Mutex<Option<Arc<Session>>>>,
}

struct Session {
    sender: Sender,
    observation: crate::traffic_view::UpstreamConnectionObservation,
    activity: Arc<Activity>,
    _driver: HttpTask,
}

struct Activity {
    state: Mutex<Idle>,
    changed: Notify,
}

struct Idle {
    active: usize,
    since: Instant,
    closed: bool,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Idle {
                active: 0,
                since: Instant::now(),
                closed: false,
            }),
            changed: Notify::new(),
        })
    }

    fn acquire(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return false;
        }
        state.active += 1;
        self.changed.notify_one();
        true
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        if state.active == 0 {
            state.since = Instant::now();
            self.changed.notify_one();
        }
    }

    async fn idle(&self) {
        loop {
            let changed = self.changed.notified();
            let deadline = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                (state.active == 0).then_some(state.since + IDLE_TIMEOUT)
            };
            if let Some(deadline) = deadline {
                tokio::select! {
                    _ = changed => {},
                    _ = tokio::time::sleep_until(deadline) => {
                        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        if state.active == 0 && Instant::now() >= state.since + IDLE_TIMEOUT {
                            // Acquisition and expiry use the same lock. A new
                            // request cannot race with closing an idle socket.
                            state.closed = true;
                            return;
                        }
                    },
                }
            } else {
                changed.await;
            }
        }
    }
}

/// A response owns a lease, not the shared connection's abort handle. Dropping
/// or resetting one stream cannot abort its siblings or a staged upload.
pub(super) struct Lease(Arc<Session>);

impl Lease {
    fn new(session: Arc<Session>) -> Option<Self> {
        if session.activity.acquire() {
            Some(Self(session))
        } else {
            None
        }
    }

    pub(super) fn sender(&self) -> Sender {
        self.0.sender.clone()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.activity.release();
    }
}

pub(super) enum Selected {
    Http2(Lease),
    Unshared(Outbound),
}

impl Selected {
    pub(super) fn observation(&self) -> &crate::traffic_view::UpstreamConnectionObservation {
        match self {
            Self::Http2(lease) => &lease.0.observation,
            Self::Unshared(outbound) => &outbound.observation,
        }
    }
    pub(super) fn http2(&self) -> bool {
        matches!(self, Self::Http2(_))
    }

    pub(super) fn h1_request_form(&self) -> H1RequestForm {
        match self {
            Self::Http2(_) => H1RequestForm::Origin,
            Self::Unshared(outbound) => outbound.h1_request_form,
        }
    }
}

impl Sessions {
    pub(super) async fn select(
        &self,
        runtime: &Arc<Runtime>,
        allowed: &AllowedRequest<'_>,
        provider: Option<&str>,
        tunnel: &Tunnel,
        live: Option<&crate::traffic_view::Exchange>,
    ) -> Result<Selected, Error> {
        let slot = {
            let mut sessions = self.0.lock().await;
            sessions.retain(|cached| cached.runtime.strong_count() != 0);
            if let Some(cached) = sessions.iter().find(|cached| {
                cached.runtime.ptr_eq(&Arc::downgrade(runtime))
                    && cached.provider.as_deref() == provider
                    && cached.agent.as_deref() == allowed.identity.request_agent()
            }) {
                cached.session.clone()
            } else {
                let session = Arc::new(tokio::sync::Mutex::new(None));
                sessions.push(Cached {
                    runtime: Arc::downgrade(runtime),
                    provider: provider.map(str::to_owned),
                    agent: allowed.identity.request_agent().map(str::to_owned),
                    session: session.clone(),
                });
                session
            }
        };
        // Single-flight applies to this admitted scope only. A stalled old
        // handshake must not hold a new configuration snapshot's connection.
        let mut cached = slot.lock().await;
        if let Some(session) = cached.as_ref()
            && !session.sender.is_closed()
            && let Some(lease) = Lease::new(session.clone())
        {
            if let Some(live) = live {
                live.upstream_connection(session.observation.clone());
            }
            return Ok(Selected::Http2(lease));
        }
        let outbound =
            open_outbound(runtime, allowed, provider, true, Some(tunnel), live, None).await?;
        if !outbound.http2 {
            // A negotiated H1 connection still has its ordinary request owner.
            return Ok(Selected::Unshared(outbound));
        }
        // Learn the peer's SETTINGS before opening streams. Hyper otherwise
        // permits an initial burst of 100 before a smaller origin limit arrives.
        let (sender, connection) =
            hyper::client::conn::http2::Builder::new(Executor(allowed.tasks.clone()))
                .initial_max_send_streams(0)
                .handshake(TokioIo::new(outbound.stream))
                .await?;
        let activity = Activity::new();
        let driver_activity = activity.clone();
        let task = allowed.tasks.spawn(async move {
            tokio::select! {
                result = connection => {
                    if let Err(error) = result {
                        eprintln!("upstream HTTP/2 connection: {error}");
                    }
                },
                _ = driver_activity.idle() => {},
            }
        });
        let session = Arc::new(Session {
            sender,
            observation: outbound.observation,
            activity,
            _driver: HttpTask::unobserved(task),
        });
        *cached = Some(session.clone());
        Ok(Selected::Http2(
            Lease::new(session).ok_or("upstream HTTP/2 session expired")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn idle_expiry_never_closes_active_or_newly_reused_streams() {
        let activity = Activity::new();
        for _ in 0..20 {
            assert!(activity.acquire());
        }
        let owner = activity.clone();
        let idle = tokio::spawn(async move { owner.idle().await });
        tokio::time::advance(IDLE_TIMEOUT * 2).await;
        assert!(!idle.is_finished());
        for _ in 0..19 {
            activity.release();
        }
        tokio::time::advance(IDLE_TIMEOUT * 2).await;
        assert!(!idle.is_finished());
        activity.release();
        tokio::task::yield_now().await;
        tokio::time::advance(IDLE_TIMEOUT / 2).await;
        assert!(activity.acquire());
        tokio::time::advance(IDLE_TIMEOUT).await;
        assert!(!idle.is_finished());
        activity.release();
        tokio::task::yield_now().await;
        tokio::time::advance(IDLE_TIMEOUT).await;
        idle.await.unwrap();
        assert!(!activity.acquire());
    }
}
