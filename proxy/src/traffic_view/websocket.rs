//! Complete WebSocket observations and source-shaped retained-message eviction.
//! The relay owns transport/session lifetime; these methods only update display.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Exchange, Row, State, TrafficView};
use crate::websocket::{MessageContent, MessageType};

pub(super) struct Session {
    started: f64,
    pub(super) ended: Option<f64>,
    closed_by_client: Option<bool>,
    close_code: Option<u16>,
    close_reason: Option<Zeroizing<String>>,
    pub(super) error: Option<Zeroizing<String>>,
    incomplete: bool,
    messages: Vec<Message>,
    next_id: u64,
    trimmed: u64,
}

struct Message {
    id: u64,
    kind: MessageType,
    from_client: bool,
    timestamp: f64,
    dropped: bool,
    // The immutable relay spool retains decoded bytes without duplicating a
    // spilled message in RAM. Only its final Arc owner releases/wipes storage.
    content: Arc<MessageContent>,
}

impl Session {
    pub(super) fn filter_messages(&self) -> Vec<(bool, Arc<MessageContent>)> {
        self.messages
            .iter()
            .map(|message| (message.from_client, Arc::clone(&message.content)))
            .collect()
    }

    fn new(started: f64) -> Self {
        Self {
            started,
            ended: None,
            closed_by_client: None,
            close_code: None,
            close_reason: None,
            error: None,
            incomplete: false,
            messages: Vec::new(),
            next_id: 0,
            trimmed: 0,
        }
    }

    pub(super) fn flow_state(&self) -> &'static str {
        if self.ended.is_none() {
            "websocket_open"
        } else if self.incomplete {
            "incomplete"
        } else if self.error.is_some() {
            "error"
        } else {
            "complete"
        }
    }

    fn retained_bytes(&self) -> u64 {
        self.messages
            .iter()
            .map(|message| message.content.len())
            .sum()
    }

    pub(super) fn snapshot(&self) -> Value {
        json!({
            "state": match self.flow_state() {
                "websocket_open" => "open",
                "complete" => "closed",
                state => state,
            },
            // Unlike timestamp_end, started is a native observation fact;
            // mitmproxy's WebSocketData does not have a start-time member.
            "started": self.started,
            "timestamp_end": self.ended,
            "closed_by_client": self.closed_by_client,
            "close_code": self.close_code,
            "close_reason": self.close_reason.as_ref().map(|reason| reason.as_str()),
            "messages_meta": {
                "count": self.messages.len(),
                "contentLength": self.retained_bytes(),
                "timestamp_last": self.messages.last().map(|message| message.timestamp),
            },
            "trimmed_messages": self.trimmed,
        })
    }

    pub(super) fn cancel(&mut self, ended: f64) {
        if self.ended.is_none() {
            self.ended = Some(ended);
            self.incomplete = true;
            self.error = Some(Zeroizing::new("cancelled".into()));
        }
    }
}

impl Message {
    fn snapshot(&self) -> Value {
        json!({
            "id": self.id,
            "type": match self.kind { MessageType::Text => "text", MessageType::Binary => "binary" },
            "from_client": self.from_client,
            "timestamp": self.timestamp,
            "dropped": self.dropped,
            "injected": false,
            "body": {"available":true,"size":self.content.len(),"reason":null},
        })
    }
}

impl Exchange {
    /// Native validation can reject an already-completed HTTP 101. Annotate
    /// that rejection without replacing the parser's response or end time.
    /// Ordinary HTTP completion and a started WebSocket retain their owners.
    pub(crate) fn websocket_rejected(&self, error: &str) {
        self.update(|row| {
            if row.status == Some(101)
                && row.ended.is_some()
                && row.websocket.is_none()
                && row.error.is_none()
            {
                row.state = "error";
                row.error = Some(Zeroizing::new(error.into()));
            }
        });
    }

    /// Promote a validated upgrade's existing HTTP row. HTTP end remains in
    /// Row::ended for source completion-time fallback; session end is separate.
    pub(crate) fn websocket_start(&self, started: f64) {
        self.update(|row| {
            if row.websocket.is_none() {
                row.websocket = Some(Session::new(started));
            }
        });
    }

    /// Observe a complete message before the scanner. Stable per-flow IDs are
    /// not reused when an older message is trimmed from the retained vector.
    pub(crate) fn websocket_message(
        &self,
        kind: MessageType,
        from_client: bool,
        timestamp: f64,
        content: Arc<MessageContent>,
    ) -> Option<u64> {
        let view = self.view.upgrade()?;
        let mut state = view.lock();
        let row = state
            .rows
            .get_mut(self.id.as_str())
            .filter(|row| std::ptr::eq(row.handle.as_ptr(), self))?;
        let session = row
            .websocket
            .as_mut()
            .filter(|session| session.ended.is_none())?;
        let id = session.next_id;
        session.next_id += 1;
        session.messages.push(Message {
            id,
            kind,
            from_client,
            timestamp,
            dropped: false,
            content,
        });
        // Native pruning is reached on observation, not source's 30-second
        // callback cadence. Retained-message selection follows the same rules.
        state.prune();
        Some(id)
    }

    /// A reached scanner result is distinct from confirmed delivery. It may
    /// arrive after session end; already-observed retained messages still update.
    pub(crate) fn websocket_message_dropped(&self, id: u64, dropped: bool) {
        self.update(|row| {
            if let Some(message) = row
                .websocket
                .as_mut()
                .and_then(|session| session.messages.iter_mut().find(|message| message.id == id))
            {
                message.dropped = dropped;
            }
        });
    }

    /// Explicit supervisor cancellation, distinct from a peer close or a
    /// protocol/transport error. Late worker handles do not defer this state.
    pub(crate) fn websocket_cancel(&self, ended: f64) {
        self.update(|row| {
            if let Some(session) = &mut row.websocket {
                session.cancel(ended);
            }
        });
    }

    pub(crate) fn websocket_end(
        &self,
        ended: f64,
        closed_by_client: Option<bool>,
        close_code: Option<u16>,
        close_reason: Option<&str>,
        error: Option<&str>,
    ) {
        self.update(|row| {
            if let Some(session) = row
                .websocket
                .as_mut()
                .filter(|session| session.ended.is_none())
            {
                session.ended = Some(ended);
                session.closed_by_client = closed_by_client;
                session.close_code = close_code;
                session.close_reason = close_reason.map(|reason| Zeroizing::new(reason.into()));
                session.error = error.map(|error| Zeroizing::new(error.into()));
            }
        });
    }
}

impl TrafficView {
    pub(crate) fn websocket_messages(&self, id: &str) -> Option<Value> {
        let state = self.lock();
        let session = state.rows.get(id)?.websocket.as_ref()?;
        Some(json!({
            "websocket": session.snapshot(),
            "messages": session.messages.iter().map(Message::snapshot).collect::<Vec<_>>(),
        }))
    }

    /// Read one requested page after releasing the view lock. A storage failure
    /// is a display result, and cannot modify forwarding or scanner decisions.
    pub(crate) fn websocket_message_body(
        &self,
        id: &str,
        message_id: u64,
        offset: u64,
        length: usize,
    ) -> Option<Value> {
        let content = {
            let state = self.lock();
            state
                .rows
                .get(id)?
                .websocket
                .as_ref()?
                .messages
                .iter()
                .find(|message| message.id == message_id)?
                .content
                .clone()
        };
        let total_size = content.len();
        let offset = offset.min(total_size);
        Some(match content.read_range(offset, length) {
            Ok(bytes) => json!({
                "available":true,"offset":offset,"total_size":total_size,"size":bytes.len(),
                "data_base64":STANDARD.encode(bytes.as_slice()),
                "end":offset + bytes.len() as u64 >= total_size,"reason":null,
            }),
            Err(_) => json!({
                "available":false,"offset":offset,"total_size":total_size,"size":0,
                "data_base64":null,"end":false,"reason":"storage_error",
            }),
        })
    }
}

impl Row {
    pub(super) fn retained_bytes(&self) -> u64 {
        self.request_body.size() as u64
            + self.response_body.size() as u64
            + self.websocket.as_ref().map_or(0, Session::retained_bytes)
    }

    pub(super) fn completion_time(&self) -> f64 {
        self.websocket
            .as_ref()
            .and_then(|session| session.ended)
            .or(self.ended)
            .unwrap_or(self.request.started)
    }

    pub(super) fn terminal(&self) -> bool {
        self.websocket
            .as_ref()
            .map_or(self.ended.is_some(), |session| session.ended.is_some())
    }
}

impl State {
    pub(super) fn trim_websocket_messages(&mut self, mut bytes: u64, max_bytes: u64) {
        let mut candidates = Vec::new();
        for (flow_id, row) in &self.rows {
            let Some(session) = row
                .websocket
                .as_ref()
                .filter(|session| session.ended.is_none())
            else {
                continue;
            };
            for (position, message) in session
                .messages
                .iter()
                .enumerate()
                .take(session.messages.len().saturating_sub(1))
            {
                let size = message.content.len();
                if size > 0 {
                    candidates.push((
                        message.timestamp,
                        Zeroizing::new(flow_id.clone()),
                        position,
                        message.id,
                        size,
                    ));
                }
            }
        }
        candidates.sort_by(|a, b| {
            a.0.total_cmp(&b.0)
                .then_with(|| a.1.as_str().cmp(b.1.as_str()))
                .then_with(|| a.2.cmp(&b.2))
        });
        for (_, flow_id, _, message_id, size) in candidates {
            if bytes <= max_bytes {
                break;
            }
            let Some(session) = self
                .rows
                .get_mut(flow_id.as_str())
                .and_then(|row| row.websocket.as_mut())
            else {
                continue;
            };
            if let Some(position) = session
                .messages
                .iter()
                .position(|message| message.id == message_id)
            {
                session.messages.remove(position);
                session.trimmed += 1;
                bytes -= size;
            }
        }
    }
}
