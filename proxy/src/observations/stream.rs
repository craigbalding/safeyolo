use super::*;
use crate::{ConnectionIdentity, tunnels::BoxStream};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Source {
    bus: Arc<ObservationBus>,
    identity: ConnectionIdentity,
    connection_id: String,
    pub(crate) point: Point,
    layer: Layer,
    transport: Transport,
    parent: Option<Arc<Source>>,
    prefixes: Mutex<[Option<InputSpan>; 2]>,
    prefixes_current: [AtomicBool; 2],
}
impl Source {
    pub(crate) fn new(
        bus: Arc<ObservationBus>,
        identity: &ConnectionIdentity,
        connection_id: &str,
        point: Point,
        layer: Layer,
        transport: Transport,
        parent: Option<Arc<Self>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            bus,
            identity: identity.clone(),
            connection_id: connection_id.into(),
            point,
            layer,
            transport,
            parent,
            prefixes: Mutex::new([None, None]),
            prefixes_current: [const { AtomicBool::new(false) }; 2],
        })
    }
    pub(crate) fn tls(self: &Arc<Self>, point: Point) -> Arc<Self> {
        Self::new(
            self.bus.clone(),
            &self.identity,
            &self.connection_id,
            point,
            Layer::TlsCleartext,
            self.transport,
            Some(self.clone()),
        )
    }
    fn prefix(&self, direction: Direction) -> Option<InputSpan> {
        let prefixes = self.prefixes.try_lock().ok()?;
        if !self.prefixes_current[direction as usize].load(Ordering::Acquire) {
            return None;
        }
        prefixes[direction as usize].clone()
    }
    fn request_input_span(&self, consumed: Option<(u64, u64)>) -> Option<InputSpan> {
        let mut prefix = self.prefix(Direction::ToProxy)?;
        if let Some((start, end)) = consumed {
            if start < prefix.start_offset || end > prefix.end_offset || start > end {
                return None;
            }
            prefix.start_offset = start;
            prefix.end_offset = end;
            prefix.parser_consumed = true;
        }
        Some(prefix)
    }
    #[cfg(test)]
    pub(super) fn prefix_lock_for_test(&self) -> std::sync::MutexGuard<'_, [Option<InputSpan>; 2]> {
        self.prefixes.lock().unwrap()
    }
    fn record(
        &self,
        direction: Direction,
        offset: Option<u64>,
        length: Option<u64>,
        state: State,
    ) -> Observation {
        Observation {
            id: self.bus.id(0),
            timestamp: Timestamp {
                wall_unix_ns: 0,
                monotonic_ns: 0,
            },
            timestamp_resolution: self.bus.session.timestamp_resolution,
            point: self.point,
            layer: self.layer,
            direction,
            transport: self.transport,
            connection_id: self.connection_id.clone(),
            request_id: None,
            protocol_stream_id: None,
            agent: self.identity.request_agent().map(str::to_owned),
            attribution: self.identity.audit_attribution(),
            // Inbound TLS consumes ciphertext. Outbound cleartext is observed
            // before encryption; it must not claim already-written ciphertext.
            input_span: if direction == Direction::ToProxy {
                self.parent.as_ref().and_then(|p| p.prefix(direction))
            } else {
                None
            },
            parent_observation: None,
            transformed: false,
            stream_offset: offset,
            observed_length: length,
            captured_length: 0,
            state,
        }
    }
    fn chunk(&self, direction: Direction, offset: u64, length: usize) {
        // A skipped update must not leave the previous IDs available to a later parser.
        self.prefixes_current[direction as usize].store(false, Ordering::Release);
        let record = self.record(direction, Some(offset), Some(length as u64), State::Chunk);
        let Some(id) = self.bus.emit(record) else {
            return;
        };
        if let Ok(mut prefixes) = self.prefixes.try_lock() {
            let slot = &mut prefixes[direction as usize];
            let first = slot
                .as_ref()
                .map_or_else(|| id.clone(), |prefix| prefix.observed_from.clone());
            let start_offset = slot.as_ref().map_or(offset, |prefix| prefix.start_offset);
            *slot = Some(InputSpan {
                point: self.point,
                layer: self.layer,
                direction,
                observed_from: first,
                observed_through: id,
                start_offset,
                end_offset: offset + length as u64,
                parser_consumed: false,
            });
            self.prefixes_current[direction as usize].store(true, Ordering::Release);
        }
    }
    fn terminal(&self, direction: Direction, offset: u64, state: State) {
        self.bus
            .emit(self.record(direction, Some(offset), Some(0), state));
    }
    pub(crate) fn connection_state(&self, state: State) {
        let mut root = self;
        while let Some(parent) = &root.parent {
            root = parent;
        }
        root.bus
            .emit(root.record(Direction::Both, None, Some(0), state));
    }
    pub(crate) fn parse_error(&self) {
        let mut record = self.record(Direction::ToProxy, None, None, State::ParseError);
        record.layer = Layer::ProtocolMessage;
        record.point = Point::RequestParser;
        record.input_span = self.prefix(Direction::ToProxy);
        self.bus.emit(record);
    }
    pub(crate) fn application(
        self: &Arc<Self>,
        request_id: &str,
        protocol_stream_id: Option<u32>,
        byte_range: Option<hyper::ext::RequestByteRange>,
        content_expected: bool,
    ) -> Arc<Application> {
        let mut head = self.record(Direction::ToProxy, None, None, State::ParsedHead);
        head.point = Point::RequestParser;
        head.layer = Layer::ProtocolMessage;
        head.input_span = self.request_input_span(
            byte_range
                .as_ref()
                .map(|range| (range.start(), range.head_end())),
        );
        head.observed_length = byte_range
            .as_ref()
            .map(|range| range.head_end() - range.start());
        head.request_id = Some(request_id.into());
        head.protocol_stream_id = protocol_stream_id;
        let parent = self.bus.emit(head);
        Arc::new(Application {
            source: self.clone(),
            request_id: request_id.into(),
            protocol_stream_id,
            parent,
            completed: AtomicBool::new(!content_expected),
            byte_range,
        })
    }
}

pub(crate) struct Application {
    source: Arc<Source>,
    request_id: String,
    protocol_stream_id: Option<u32>,
    parent: Option<ObservationId>,
    completed: AtomicBool,
    byte_range: Option<hyper::ext::RequestByteRange>,
}
impl Application {
    pub(crate) fn complete(&self, length: Option<u64>, transformed: bool) {
        if self.completed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.emit(length, transformed, State::Complete);
    }
    fn emit(&self, length: Option<u64>, transformed: bool, state: State) {
        let mut record = self.source.record(Direction::ToProxy, None, length, state);
        record.layer = Layer::ApplicationContent;
        record.point = Point::RequestContent;
        record.request_id = Some(self.request_id.clone());
        record.protocol_stream_id = self.protocol_stream_id;
        record.parent_observation = self.parent.clone();
        record.input_span = self.source.request_input_span(
            self.byte_range
                .as_ref()
                .map(|range| (range.start(), range.end())),
        );
        record.transformed = transformed;
        self.source.bus.emit(record);
    }
}
impl Drop for Application {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            self.emit(None, false, State::Dropped);
        }
    }
}

struct Observed {
    stream: BoxStream,
    source: Arc<Source>,
    read_offset: u64,
    write_offset: u64,
    read_end: bool,
    write_end: bool,
}
pub(crate) fn observe(stream: BoxStream, source: Arc<Source>) -> BoxStream {
    Box::new(Observed {
        stream,
        source,
        read_offset: 0,
        write_offset: 0,
        read_end: false,
        write_end: false,
    })
}
impl AsyncRead for Observed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let capacity = buffer.remaining();
        let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
        if let Poll::Ready(result) = &result {
            let length = buffer.filled().len() - before;
            if length != 0 {
                self.source
                    .chunk(Direction::ToProxy, self.read_offset, length);
                self.read_offset += length as u64;
            }
            if !self.read_end && (result.is_err() || (capacity != 0 && length == 0)) {
                self.read_end = true;
                self.source.terminal(
                    Direction::ToProxy,
                    self.read_offset,
                    if result.is_err() {
                        State::ReadError
                    } else {
                        State::Eof
                    },
                );
            }
        }
        result
    }
}
impl AsyncWrite for Observed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        match result {
            Poll::Ready(Ok(length)) if length != 0 => {
                self.source
                    .chunk(Direction::FromProxy, self.write_offset, length);
                self.write_offset += length as u64;
            }
            Poll::Ready(Err(_)) if !self.write_end => {
                self.write_end = true;
                self.source
                    .terminal(Direction::FromProxy, self.write_offset, State::WriteError);
            }
            _ => {}
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) && !self.write_end {
            self.write_end = true;
            self.source
                .terminal(Direction::FromProxy, self.write_offset, State::WriteError);
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_shutdown(cx);
        if let Poll::Ready(result) = &result
            && !self.write_end
        {
            self.write_end = true;
            self.source.terminal(
                Direction::FromProxy,
                self.write_offset,
                if result.is_err() {
                    State::WriteError
                } else {
                    State::HalfClose
                },
            );
        }
        result
    }
}
impl Drop for Observed {
    fn drop(&mut self) {
        if !self.read_end {
            self.source
                .terminal(Direction::ToProxy, self.read_offset, State::Dropped);
        }
        if !self.write_end {
            self.source
                .terminal(Direction::FromProxy, self.write_offset, State::Dropped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Arc<Source> {
        Source::new(
            ObservationBus::new(
                "instance".into(),
                "runtime".into(),
                Limits::default(),
                Arc::default(),
            ),
            &ConnectionIdentity {
                agent_id: "alice".into(),
                run: None,
                connection_id: "connection".into(),
                source_id: None,
            },
            "connection",
            Point::AgentUds,
            Layer::TransportStream,
            Transport::Unix,
            None,
        )
    }

    #[test]
    fn missed_prefix_updates_recover_enclosing_ids_in_each_direction() {
        let source = source();
        for direction in [Direction::ToProxy, Direction::FromProxy] {
            source.chunk(direction, 0, 2);
            let first = source.prefix(direction).unwrap();
            {
                let _reader = source.prefixes.lock().unwrap();
                source.chunk(direction, 2, 3);
            }
            assert!(source.prefix(direction).is_none());
            source.chunk(direction, 5, 1);
            let recovered = source.prefix(direction).unwrap();
            assert_eq!(recovered.observed_from, first.observed_from);
            assert_eq!(
                recovered.observed_through,
                source.bus.id(source.bus.next_sequence() - 1)
            );
            assert_eq!((recovered.start_offset, recovered.end_offset), (0, 6));
        }
    }

    #[test]
    fn a_missed_first_prefix_never_claims_earlier_or_uncovered_parser_bytes() {
        let source = source();
        {
            let _reader = source.prefixes.lock().unwrap();
            source.chunk(Direction::ToProxy, 0, 5);
        }
        source.chunk(Direction::ToProxy, 5, 3);
        let prefix = source.prefix(Direction::ToProxy).unwrap();
        assert_eq!((prefix.start_offset, prefix.end_offset), (5, 8));
        assert_eq!(prefix.observed_from, source.bus.id(2));
        assert_eq!(prefix.observed_through, source.bus.id(2));
        assert!(!prefix.parser_consumed);
        for range in [(0, 8), (5, 9), (8, 5)] {
            assert!(source.request_input_span(Some(range)).is_none());
        }
        let consumed = source.request_input_span(Some((5, 8))).unwrap();
        assert!(consumed.parser_consumed);
        assert_eq!((consumed.start_offset, consumed.end_offset), (5, 8));
    }
}
