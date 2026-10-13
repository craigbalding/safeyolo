//! Ping/Pong on the two legs of the existing viewer WebSocket, without input.

use crate::{
    Error,
    websocket::{Event, Reader, Writer},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{io::AsyncRead, sync::mpsc, task::JoinSet};
use tungstenite::protocol::frame::coding::Control;

pub(crate) type Sessions = Mutex<BTreeMap<String, Arc<Mutex<Health>>>>;

pub(crate) struct Health {
    started: Instant,
    browser: Option<Instant>,
    relay: Option<Instant>,
}

pub(crate) fn status(sessions: &Sessions, id: &str) -> Value {
    let sessions = sessions.lock().unwrap_or_else(|error| error.into_inner());
    let Some(health) = sessions.get(id) else {
        return json!({"state":"closed"});
    };
    let health = health.lock().unwrap_or_else(|error| error.into_inner());
    let age = |value: Option<Instant>| value.map(|value| value.elapsed().as_millis() as u64);
    json!({"state":"open","age_ms":health.started.elapsed().as_millis(),
        "browser_pong_age_ms":age(health.browser),"relay_pong_age_ms":age(health.relay)})
}

pub(crate) async fn relay(
    browser: crate::tunnels::BoxStream,
    guest: crate::tunnels::BoxStream,
    sessions: &Sessions,
    id: String,
    access: &super::desktop_preview::Access,
) -> Result<u64, Error> {
    let health = Arc::new(Mutex::new(Health {
        started: Instant::now(),
        browser: None,
        relay: None,
    }));
    {
        let mut sessions = sessions.lock().unwrap_or_else(|error| error.into_inner());
        if sessions.contains_key(&id) {
            return Err("viewer attempt already exists".into());
        }
        sessions.insert(id.clone(), health.clone());
    }
    // This guard also removes the entry when the preview owner cancels a task.
    struct Remove<'a>(&'a Sessions, String);
    impl Drop for Remove<'_> {
        fn drop(&mut self) {
            self.0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&self.1);
        }
    }
    let _remove = Remove(sessions, id);
    let (browser_read, browser_write) = tokio::io::split(browser);
    let (guest_read, guest_write) = tokio::io::split(guest);
    let (send, mut events) = mpsc::channel(2);
    let mut readers = JoinSet::new();
    async fn read<R: AsyncRead + Unpin>(
        stream: R,
        from_client: bool,
        send: mpsc::Sender<(bool, Result<Event, crate::websocket::ReceiveError>)>,
    ) {
        // The native bridge emits at most 64 KiB per message; shipped noVNC
        // sends at most 10 KiB. Leave headroom, but do not let a replaced guest
        // service create an unlimited host spool or fragment index.
        let mut reader = Reader::new(stream, from_client, None).with_message_limit(1024 * 1024);
        loop {
            let result = reader.read().await;
            let done = result.is_err() || matches!(result, Ok(Event::Close(_)));
            if send.send((from_client, result)).await.is_err() || done {
                break;
            }
        }
    }
    readers.spawn(read(browser_read, true, send.clone()));
    readers.spawn(read(guest_read, false, send));
    let mut browser = Writer::new(browser_write, false, None);
    let mut guest = Writer::new(guest_write, true, None);
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending: Option<(Vec<u8>, Instant, bool, bool)> = None;
    let mut bytes = 0;
    let result = async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    access.check_target()?;
                    if let Some((_, sent, browser_ok, guest_ok)) = &pending {
                        if sent.elapsed() >= Duration::from_secs(15) && (!browser_ok || !guest_ok) {
                            return Err("existing viewer transport did not answer Ping".into());
                        }
                    } else {
                        let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
                        tokio::time::timeout(Duration::from_secs(5), async {
                            browser.control(Control::Ping, &nonce).await?;
                            guest.control(Control::Ping, &nonce).await
                        }).await.map_err(|_| "viewer Ping write timed out")??;
                        pending = Some((nonce, Instant::now(), false, false));
                    }
                }
                Some((from_browser, event)) = events.recv() => {
                    let event = event?;
                    match event {
                        Event::Pong(payload) if pending.as_ref().is_some_and(|value| value.0 == payload) => {
                            let pending = pending.as_mut().unwrap();
                            let mut health = health.lock().unwrap_or_else(|error| error.into_inner());
                            if from_browser { pending.2 = true; health.browser = Some(Instant::now()); }
                            else { pending.3 = true; health.relay = Some(Instant::now()); }
                        }
                        Event::Message(message) => {
                            let destination = if from_browser { &mut guest } else { &mut browser };
                            bytes += message.content().len();
                            tokio::time::timeout(Duration::from_secs(15), destination.message(message))
                                .await.map_err(|_| "viewer data write timed out")??;
                        }
                        Event::Ping(payload) => {
                            let source = if from_browser { &mut browser } else { &mut guest };
                            tokio::time::timeout(Duration::from_secs(5), source.control(Control::Pong, &payload))
                                .await.map_err(|_| "viewer Pong write timed out")??;
                        }
                        Event::Pong(_) => (),
                        Event::Close(payload) => {
                            let destination = if from_browser { &mut guest } else { &mut browser };
                            let _ = tokio::time::timeout(Duration::from_secs(2), destination.control(Control::Close, &payload)).await;
                            return Ok(bytes);
                        }
                    }
                    if pending.as_ref().is_some_and(|value| value.2 && value.3) { pending = None; }
                }
                else => return Ok(bytes),
            }
        }
    }.await;
    readers.abort_all();
    while readers.join_next().await.is_some() {}
    result
}
