//! Canonical observations before capture encoding. Payload retention is explicit.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub items: usize,
    pub bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            items: 4096,
            bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    TransportStream,
    TlsCleartext,
    ProtocolMessage,
    ApplicationContent,
    WirePacket,
}
impl Layer {
    fn index(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::TransportStream => "transport_stream",
            Self::TlsCleartext => "tls_cleartext",
            Self::ProtocolMessage => "protocol_message",
            Self::ApplicationContent => "application_content",
            Self::WirePacket => "wire_packet",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Point {
    AgentUds,
    Upstream,
    ClientTls,
    ParentTls,
    OriginTls,
    RequestParser,
    RequestContent,
    HostPacket,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ToProxy,
    FromProxy,
    Both,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Unix,
    Tcp,
    Provider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Connected,
    Closed,
    Failed,
    Chunk,
    ParsedHead,
    Complete,
    Eof,
    HalfClose,
    ReadError,
    WriteError,
    ParseError,
    Dropped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservationId {
    pub instance_id: String,
    pub runtime_id: String,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Resolution {
    /// Kernel-reported clock resolution; None means unavailable, not nanosecond precision.
    pub wall_ns: Option<u64>,
    pub monotonic_ns: Option<u64>,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Timestamp {
    pub wall_unix_ns: i128,
    pub monotonic_ns: u64,
}

/// A source span presented to the next layer. TLS and HTTP/2 parsers
/// can buffer/read ahead. This is ancestry, never a claim of byte-for-byte
/// correspondence or exclusive ownership by one application message.
#[derive(Clone, Debug, Serialize)]
pub struct InputSpan {
    pub point: Point,
    pub layer: Layer,
    pub direction: Direction,
    pub observed_from: ObservationId,
    pub observed_through: ObservationId,
    pub start_offset: u64,
    pub end_offset: u64,
    /// False identifies an input prefix; true is an exact HTTP/1 parser span.
    pub parser_consumed: bool,
}

#[derive(Clone, Serialize)]
pub struct Observation {
    pub id: ObservationId,
    pub timestamp: Timestamp,
    pub timestamp_resolution: Resolution,
    pub point: Point,
    pub layer: Layer,
    pub direction: Direction,
    pub transport: Transport,
    pub connection_id: String,
    pub request_id: Option<String>,
    pub protocol_stream_id: Option<u32>,
    pub agent: Option<String>,
    #[serde(serialize_with = "serialize_attribution")]
    pub attribution: crate::audit::Attribution,
    pub input_span: Option<InputSpan>,
    pub parent_observation: Option<ObservationId>,
    pub transformed: bool,
    pub stream_offset: Option<u64>,
    /// None when no byte length is exposed (for example an HTTP/2 head).
    pub observed_length: Option<u64>,
    pub captured_length: u64,
    /// Private capture bytes never enter metadata serialization or diagnostics.
    #[serde(skip)]
    pub payload: Option<Arc<[u8]>>,
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet: Option<crate::packet_capture::Packet>,
}
impl Observation {
    // Conservatively charge inline storage, owned strings and optional lineage.
    // This is an in-memory budget, not an encoder byte count.
    pub fn metadata_bytes(&self) -> usize {
        let id_bytes = |id: &ObservationId| id.instance_id.len() + id.runtime_id.len();
        std::mem::size_of::<Self>() + id_bytes(&self.id) + self.connection_id.len()
            + self.request_id.as_ref().map_or(0, String::len)
            + self.agent.as_ref().map_or(0, String::len)
            + self.attribution.evidence_owner.as_ref().map_or(0, String::len)
            + self.attribution.trusted_transport_identity.as_ref().map_or(0, String::len)
            + self.parent_observation.as_ref().map_or(0, id_bytes)
            + 2048 // bounded transport attribution provenance and allocation overhead
            + self.input_span.as_ref().map_or(0, |parent| {
                id_bytes(&parent.observed_from) + id_bytes(&parent.observed_through)
            })
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossReason {
    CanonicalAdmissionUnavailable,
    ConsumerAdmissionUnavailable,
}
#[derive(Clone, Debug, Serialize)]
pub struct Gap {
    pub instance_id: String,
    pub runtime_id: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub count: u64,
    pub reason: LossReason,
}
#[derive(Clone, Serialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    Observation(Box<Observation>),
    Gap(Gap),
}
impl Record {
    fn range(&self) -> (u64, u64) {
        match self {
            Self::Observation(o) => (o.id.sequence, o.id.sequence),
            Self::Gap(g) => (g.first_sequence, g.last_sequence),
        }
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Observation(o) => o.metadata_bytes() + o.payload.as_ref().map_or(0, |p| p.len()),
            Self::Gap(g) => {
                std::mem::size_of::<Record>() + 64 + g.instance_id.len() + g.runtime_id.len()
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub instance_id: String,
    pub runtime_id: String,
    pub sink_session_id: String,
    pub schema_version: u32,
    pub timestamp_resolution: Resolution,
    pub first_sequence: u64,
}

/// Fixed operational labels. Consumer IDs, destinations and connection IDs are
/// never metric labels. No encoder or output adapter is installed here.
#[derive(Clone, Copy, Debug)]
pub enum ConsumerKind {
    Metrics,
    Capture,
}
impl ConsumerKind {
    fn index(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::Capture => "capture",
        }
    }
}
#[derive(Default)]
pub struct Counters {
    behaviour: Mutex<behaviour::TransportMetrics>,
    total: [AtomicU64; 5],
    metadata: [AtomicU64; 5],
    payload: [AtomicU64; 5],
    dropped: [AtomicU64; 5],
    gaps: AtomicU64,
    exhausted: AtomicU64,
    pub(crate) sink_bytes: [AtomicU64; 4],
    pub(crate) sink_dropped: [AtomicU64; 4],
    pub(crate) sink_errors: [AtomicU64; 4],
    pub(crate) sink_disconnects: [AtomicU64; 4],
    pub(crate) wire_received: AtomicU64,
    pub(crate) wire_kernel_dropped: AtomicU64,
    pub(crate) wire_interface_dropped: AtomicU64,
    pub(crate) wire_correlation_missed: AtomicU64,
    pub(crate) wire_source_errors: AtomicU64,
    consumer_bytes: [AtomicU64; 2],
    consumer_dropped: [AtomicU64; 2],
    consumer_disconnects: [AtomicU64; 2],
}
impl Counters {
    pub fn json(&self) -> serde_json::Value {
        use serde_json::json;
        let layers = [
            Layer::TransportStream,
            Layer::TlsCleartext,
            Layer::ProtocolMessage,
            Layer::ApplicationContent,
            Layer::WirePacket,
        ];
        let mut by_layer = serde_json::Map::new();
        for layer in layers {
            let i = layer.index();
            by_layer.insert(
                layer.name().into(),
                json!({
                    "observations_total": self.total[i].load(Ordering::Relaxed),
                    "observation_metadata_bytes_total": self.metadata[i].load(Ordering::Relaxed),
                    "observation_payload_bytes_total": self.payload[i].load(Ordering::Relaxed),
                    "observation_bus_dropped_total": self.dropped[i].load(Ordering::Relaxed),
                }),
            );
        }
        let mut sinks = serde_json::Map::new();
        for kind in [ConsumerKind::Metrics, ConsumerKind::Capture] {
            let i = kind.index();
            sinks.insert(kind.name().into(), json!({
            "sink_bytes_total": 0,
            "observation_consumer_metadata_bytes_total": self.consumer_bytes[i].load(Ordering::Relaxed),
            "sink_dropped_observations_total": self.consumer_dropped[i].load(Ordering::Relaxed),
            "sink_disconnects_total": self.consumer_disconnects[i].load(Ordering::Relaxed),
            "sink_errors_total": 0,
        }));
        }
        for kind in [
            crate::packet_capture::Sink::File,
            crate::packet_capture::Sink::Stdout,
            crate::packet_capture::Sink::Tcp,
            crate::packet_capture::Sink::Wss,
        ] {
            let i = kind.index();
            sinks.insert(
                kind.name().into(),
                json!({
                    "sink_bytes_total":self.sink_bytes[i].load(Ordering::Relaxed),
                    "sink_dropped_observations_total":self.sink_dropped[i].load(Ordering::Relaxed),
                    "sink_errors_total":self.sink_errors[i].load(Ordering::Relaxed),
                    "sink_disconnects_total":self.sink_disconnects[i].load(Ordering::Relaxed),
                }),
            );
        }
        json!({"layers": by_layer, "observation_gap_ranges_total": self.gaps.load(Ordering::Relaxed), "observation_sequence_exhausted_total": self.exhausted.load(Ordering::Relaxed), "sinks": sinks,
            "wire_source": {
                "wire_packets_received_total": self.wire_received.load(Ordering::Relaxed),
                "wire_kernel_dropped_total": self.wire_kernel_dropped.load(Ordering::Relaxed),
                "wire_interface_dropped_total": self.wire_interface_dropped.load(Ordering::Relaxed),
                "wire_correlation_missed_total": self.wire_correlation_missed.load(Ordering::Relaxed),
                "wire_source_errors_total": self.wire_source_errors.load(Ordering::Relaxed),
            },
            "behaviour": self.behaviour.lock().unwrap_or_else(|e| e.into_inner()).json()})
    }
    pub fn prometheus(&self) -> String {
        let mut out = String::new();
        for name in [
            "observations_total",
            "observation_metadata_bytes_total",
            "observation_payload_bytes_total",
            "observation_bus_dropped_total",
            "observation_gap_ranges_total",
            "observation_sequence_exhausted_total",
            "sink_bytes_total",
            "observation_consumer_metadata_bytes_total",
            "sink_dropped_observations_total",
            "sink_disconnects_total",
            "sink_errors_total",
        ] {
            out += &format!("# TYPE safeyolo_{name} counter\n");
        }
        let document = self.json();
        for (layer, values) in document["layers"].as_object().unwrap() {
            for (name, value) in values.as_object().unwrap() {
                out += &format!("safeyolo_{name}{{layer=\"{layer}\"}} {value}\n");
            }
        }
        out += &format!(
            "safeyolo_observation_gap_ranges_total {}\n",
            self.gaps.load(Ordering::Relaxed)
        );
        out += &format!(
            "safeyolo_observation_sequence_exhausted_total {}\n",
            self.exhausted.load(Ordering::Relaxed)
        );
        for (sink, values) in document["sinks"].as_object().unwrap() {
            for (name, value) in values.as_object().unwrap() {
                out += &format!("safeyolo_{name}{{sink=\"{sink}\"}} {value}\n");
            }
        }
        for (name, value) in document["wire_source"].as_object().unwrap() {
            out += &format!("# TYPE safeyolo_{name} counter\nsafeyolo_{name} {value}\n");
        }
        out += &self
            .behaviour
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prometheus();
        out
    }
}

struct Queue {
    records: VecDeque<Arc<Record>>,
    bytes: usize,
}
impl Queue {
    fn new() -> Self {
        Self {
            records: VecDeque::new(),
            bytes: 0,
        }
    }
    fn push(&mut self, record: Arc<Record>, limits: Limits) -> bool {
        let bytes = record.bytes();
        if self.records.len() >= limits.items || bytes > limits.bytes.saturating_sub(self.bytes) {
            return false;
        }
        self.bytes += bytes;
        self.records.push_back(record);
        true
    }
    fn pop(&mut self) -> Option<Arc<Record>> {
        let record = self.records.pop_front()?;
        self.bytes -= record.bytes();
        Some(record)
    }
}
struct ConsumerQueue {
    queue: Mutex<Queue>,
    limits: Limits,
    kind: ConsumerKind,
    // Only the fan-out worker writes this watermark; the receiver samples it
    // after draining the accepted prefix to report even a terminal loss tail.
    through: AtomicU64,
    notify: Notify,
    closed: AtomicBool,
}
pub struct Consumer {
    pub session: Session,
    inner: Arc<ConsumerQueue>,
    next: u64,
    counters: Arc<Counters>,
}
impl Consumer {
    fn delivered(&self, record: Arc<Record>) -> Option<Arc<Record>> {
        self.counters.consumer_bytes[self.inner.kind.index()].fetch_add(
            match record.as_ref() {
                Record::Observation(o) => o.metadata_bytes(),
                Record::Gap(_) => record.bytes(),
            } as u64,
            Ordering::Relaxed,
        );
        Some(record)
    }
    pub async fn recv(&mut self) -> Option<Arc<Record>> {
        loop {
            let notified = self.inner.notify.notified();
            let closed = {
                // This lock runs only on a consumer, never on the traffic path.
                let mut queue = self.inner.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(record) = queue.records.front() {
                    let first = record.range().0;
                    if first > self.next {
                        let gap = gap(
                            &self.session,
                            self.next,
                            first - 1,
                            LossReason::ConsumerAdmissionUnavailable,
                        );
                        self.next = first;
                        return self.delivered(Arc::new(Record::Gap(gap)));
                    }
                }
                if let Some(record) = queue.pop() {
                    self.next = record.range().1 + 1;
                    return self.delivered(record);
                }
                let through = self.inner.through.load(Ordering::Acquire);
                if through >= self.next {
                    let result = gap(
                        &self.session,
                        self.next,
                        through,
                        LossReason::ConsumerAdmissionUnavailable,
                    );
                    self.next = through + 1;
                    return self.delivered(Arc::new(Record::Gap(result)));
                }
                self.inner.closed.load(Ordering::Acquire)
            };
            if closed {
                return None;
            }
            notified.await;
        }
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        self.counters.consumer_disconnects[self.inner.kind.index()].fetch_add(1, Ordering::Relaxed);
    }
}
fn gap(session: &Session, first: u64, last: u64, reason: LossReason) -> Gap {
    Gap {
        instance_id: session.instance_id.clone(),
        runtime_id: session.runtime_id.clone(),
        first_sequence: first,
        last_sequence: last,
        count: last - first + 1,
        reason,
    }
}

pub struct ObservationBus {
    session: Session,
    payload_layers: Vec<Layer>,
    pub(crate) capture: std::sync::OnceLock<Arc<crate::packet_capture::Capture>>,
    pub(crate) wire: std::sync::OnceLock<Arc<crate::packet_capture::wire::Connections>>,
    sequence: AtomicU64,
    queue: Mutex<Queue>,
    limits: Limits,
    consumers: Mutex<Vec<Weak<ConsumerQueue>>>,
    wake: Arc<Notify>,
    origin: Instant,
    worker_started: AtomicBool,
    dispatched: AtomicU64,
    pub counters: Arc<Counters>,
}
impl ObservationBus {
    pub fn new(
        instance_id: String,
        runtime_id: String,
        limits: Limits,
        counters: Arc<Counters>,
    ) -> Arc<Self> {
        Self::with_payload(instance_id, runtime_id, limits, counters, Vec::new())
    }
    pub(crate) fn with_payload(
        instance_id: String,
        runtime_id: String,
        limits: Limits,
        counters: Arc<Counters>,
        payload_layers: Vec<Layer>,
    ) -> Arc<Self> {
        let bus = Arc::new(Self {
            payload_layers,
            capture: std::sync::OnceLock::new(),
            wire: std::sync::OnceLock::new(),
            session: Session {
                instance_id,
                runtime_id,
                sink_session_id: String::new(),
                schema_version: 1,
                timestamp_resolution: Resolution {
                    wall_ns: resolution(libc::CLOCK_REALTIME),
                    monotonic_ns: resolution(libc::CLOCK_MONOTONIC),
                },
                first_sequence: 1,
            },
            sequence: AtomicU64::new(1),
            queue: Mutex::new(Queue::new()),
            limits,
            consumers: Mutex::new(Vec::new()),
            wake: Arc::new(Notify::new()),
            origin: Instant::now(),
            worker_started: AtomicBool::new(false),
            dispatched: AtomicU64::new(0),
            counters,
        });
        // Runtime construction also has synchronous source-test callers. Start
        // the worker lazily on subscribe/observation if no executor exists yet.
        bus.start_worker();
        bus
    }
    fn start_worker(self: &Arc<Self>) {
        if self.worker_started.load(Ordering::Acquire) {
            return;
        }
        let Ok(executor) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if !self.worker_started.swap(true, Ordering::AcqRel) {
            let weak = Arc::downgrade(self);
            let wake = self.wake.clone();
            executor.spawn(async move {
                let mut expected = 1;
                loop {
                    wake.notified().await;
                    let Some(bus) = weak.upgrade() else {
                        return;
                    };
                    bus.drain(&mut expected);
                    bus.dispatched.store(expected - 1, Ordering::Release);
                    drop(bus);
                    tokio::task::yield_now().await;
                }
            });
        }
    }
    pub fn next_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    pub fn subscribe(self: &Arc<Self>, kind: ConsumerKind, limits: Limits) -> Consumer {
        self.start_worker();
        let mut consumers = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        let first = self.sequence.load(Ordering::Acquire);
        let inner = Arc::new(ConsumerQueue {
            queue: Mutex::new(Queue::new()),
            limits,
            kind,
            through: AtomicU64::new(first - 1),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        });
        consumers.retain(|consumer| consumer.strong_count() != 0);
        consumers.push(Arc::downgrade(&inner));
        let mut session = self.session.clone();
        session.first_sequence = first;
        session.sink_session_id = uuid::Uuid::new_v4().to_string();
        Consumer {
            session,
            inner,
            next: first,
            counters: self.counters.clone(),
        }
    }
    fn id(&self, sequence: u64) -> ObservationId {
        ObservationId {
            instance_id: self.session.instance_id.clone(),
            runtime_id: self.session.runtime_id.clone(),
            sequence,
        }
    }
    pub(crate) fn emit(self: &Arc<Self>, observation: Observation) -> Option<ObservationId> {
        self.emit_payload(observation, &[])
    }
    pub(crate) fn emit_payload(
        self: &Arc<Self>,
        mut observation: Observation,
        bytes: &[u8],
    ) -> Option<ObservationId> {
        // Refuse oversized snapshots before allocating or copying. Queue accounting
        // charges retained bytes in both the canonical and consumer stages.
        if self.payload_layers.contains(&observation.layer)
            && bytes.len()
                <= self
                    .limits
                    .bytes
                    .saturating_sub(observation.metadata_bytes())
        {
            observation.payload = (!bytes.is_empty()).then(|| Arc::from(bytes));
            observation.captured_length = bytes.len() as u64;
        }
        self.emit_with_clock(observation, || Timestamp {
            wall_unix_ns: SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
                |e| -(e.duration().as_nanos() as i128),
                |d| d.as_nanos() as i128,
            ),
            monotonic_ns: self.origin.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        })
    }
    fn emit_with_clock(
        self: &Arc<Self>,
        mut observation: Observation,
        clock: impl FnOnce() -> Timestamp,
    ) -> Option<ObservationId> {
        self.start_worker();
        // Successful admissions are serialized before sequence allocation.
        // A contender still allocates a sequence and records loss without waiting.
        let queue = try_queue(&self.queue);
        let Ok(sequence) =
            self.sequence
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                    next.checked_add(1)
                })
        else {
            self.counters.exhausted.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        observation.id = self.id(sequence);
        let timestamp = clock();
        if observation.layer == Layer::WirePacket {
            // Packet wall time and precision come from the acquisition source.
            // Monotonic time describes ingestion, not a kernel packet clock.
            observation.timestamp.monotonic_ns = timestamp.monotonic_ns;
        } else {
            observation.timestamp = timestamp;
            observation.timestamp_resolution = self.session.timestamp_resolution;
        }
        let id = observation.id.clone();
        let layer = observation.layer.index();
        self.counters.total[layer].fetch_add(1, Ordering::Relaxed);
        self.counters.payload[layer].fetch_add(observation.captured_length, Ordering::Relaxed);
        self.counters.metadata[layer]
            .fetch_add(observation.metadata_bytes() as u64, Ordering::Relaxed);
        let admitted = queue.is_some_and(|mut queue| {
            queue.push(
                Arc::new(Record::Observation(Box::new(observation))),
                self.limits,
            )
        });
        if !admitted {
            self.counters.dropped[layer].fetch_add(1, Ordering::Relaxed);
        }
        self.wake.notify_one();
        Some(id)
    }
    fn dispatch(&self, record: Arc<Record>) {
        // Measure canonical records once, before consumer loss or capture projection.
        self.counters
            .behaviour
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(&record);
        let mut consumers = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        consumers.retain(|consumer| {
            let Some(consumer) = consumer.upgrade() else {
                return false;
            };
            let (_, last) = record.range();
            if last < consumer.through.load(Ordering::Acquire) + 1 {
                return true;
            }
            let record = match record.as_ref() {
                Record::Gap(gap)
                    if gap.first_sequence <= consumer.through.load(Ordering::Acquire) =>
                {
                    let mut clipped = gap.clone();
                    clipped.first_sequence = consumer.through.load(Ordering::Acquire) + 1;
                    clipped.count = clipped.last_sequence - clipped.first_sequence + 1;
                    Arc::new(Record::Gap(clipped))
                }
                _ => record.clone(),
            };
            let accepted = try_queue(&consumer.queue)
                .is_some_and(|mut queue| queue.push(record.clone(), consumer.limits));
            if !accepted {
                self.counters.consumer_dropped[consumer.kind.index()]
                    .fetch_add(last - record.range().0 + 1, Ordering::Relaxed);
            }
            consumer.through.store(last, Ordering::Release);
            consumer.notify.notify_one();
            true
        });
    }
    fn drain(&self, expected: &mut u64) {
        for _ in 0..self.limits.items.max(1) {
            let Some(mut queue) = try_queue(&self.queue) else {
                self.wake.notify_one();
                return;
            };
            let record = queue.pop();
            let next = record.as_ref().map_or_else(
                || self.sequence.load(Ordering::Acquire),
                |record| record.range().0,
            );
            drop(queue);
            if next > *expected {
                self.counters.gaps.fetch_add(1, Ordering::Relaxed);
                self.dispatch(Arc::new(Record::Gap(gap(
                    &self.session,
                    *expected,
                    next - 1,
                    LossReason::CanonicalAdmissionUnavailable,
                ))));
                *expected = next;
            }
            let Some(record) = record else {
                return;
            };
            *expected = record.range().1 + 1;
            self.dispatch(record);
        }
        self.wake.notify_one();
    }
}
impl Drop for ObservationBus {
    fn drop(&mut self) {
        // The worker owns only Weak between turns. Flush its bounded remainder
        // before closing consumers when the final source/runtime owner leaves.
        let mut expected = self.dispatched.load(Ordering::Acquire) + 1;
        self.drain(&mut expected);
        self.drain(&mut expected);
        for consumer in self
            .consumers
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
        {
            consumer.closed.store(true, Ordering::Release);
            consumer.notify.notify_one();
        }
        self.wake.notify_one();
    }
}
fn resolution(clock: libc::clockid_t) -> Option<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_getres writes one initialized timespec and retains no pointer.
    (unsafe { libc::clock_getres(clock, &mut value) } == 0).then(|| {
        (value.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(value.tv_nsec as u64)
    })
}

mod behaviour;
mod stream;
pub(crate) use stream::{Application, Source, observe};

fn serialize_attribution<S: serde::Serializer>(
    attribution: &crate::audit::Attribution,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeStruct;
    let mut fields = serializer.serialize_struct("Attribution", 5)?;
    fields.serialize_field("evidence_owner", &attribution.evidence_owner)?;
    fields.serialize_field(
        "trusted_transport_identity",
        &attribution.trusted_transport_identity,
    )?;
    fields.serialize_field("status", &attribution.status.map(|status| status.as_str()))?;
    fields.serialize_field(
        "initiator",
        &attribution.initiator.map(|initiator| initiator.as_str()),
    )?;
    let provenance = attribution
        .provenance
        .as_ref()
        .map(|value| value.json())
        .transpose()
        .map_err(serde::ser::Error::custom)?;
    fields.serialize_field("provenance", &provenance)?;
    fields.end()
}

fn try_queue(queue: &Mutex<Queue>) -> Option<std::sync::MutexGuard<'_, Queue>> {
    match queue.try_lock() {
        Ok(queue) => Some(queue),
        Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

#[cfg(test)]
pub(crate) mod tests;
