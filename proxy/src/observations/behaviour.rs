//! Measurements of canonical metadata. IDs are accounting keys, never labels.

use super::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

const MAX_CONNECTIONS: usize = 4096;
const MAX_CHUNKS: usize = 16384;
const BYTE_BUCKETS: [f64; 8] = [64., 256., 1024., 4096., 16384., 65536., 1048576., 16777216.];
const TIME_BUCKETS: [f64; 8] = [0.001, 0.01, 0.1, 1., 10., 60., 600., 3600.];
const CHUNK_BUCKETS: [f64; 8] = [1., 2., 4., 8., 16., 64., 256., 1024.];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Labels {
    point: Point,
    layer: Layer,
    transport: Transport,
    direction: Direction,
}
impl Labels {
    fn of(o: &Observation) -> Self {
        Self {
            point: o.point,
            layer: o.layer,
            transport: o.transport,
            direction: o.direction,
        }
    }
    fn input(o: &Observation, span: &InputSpan) -> Self {
        Self {
            point: span.point,
            layer: span.layer,
            transport: o.transport,
            direction: span.direction,
        }
    }
    fn prometheus(self) -> String {
        serde_json::to_value(self)
            .unwrap()
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Default)]
struct Histogram {
    count: u64,
    sum: f64,
    buckets: [u64; 8],
}
impl Histogram {
    fn observe(&mut self, value: f64, bounds: &[f64; 8]) {
        self.count += 1;
        self.sum += value;
        for (count, bound) in self.buckets.iter_mut().zip(bounds) {
            *count += u64::from(value <= *bound);
        }
    }
    fn json(&self, bounds: &[f64; 8]) -> Value {
        json!({"count":self.count, "sum":self.sum, "buckets":bounds.iter().zip(self.buckets)
            .map(|(le, count)| json!({"le":le,"count":count})).collect::<Vec<_>>()})
    }
    fn prometheus(&self, out: &mut String, name: &str, labels: &str, bounds: &[f64; 8]) {
        for (bound, count) in bounds.iter().zip(self.buckets) {
            *out += &format!("safeyolo_{name}_bucket{{{labels},le=\"{bound}\"}} {count}\n");
        }
        *out += &format!(
            "safeyolo_{name}_bucket{{{labels},le=\"+Inf\"}} {}\n",
            self.count
        );
        *out += &format!("safeyolo_{name}_count{{{labels}}} {}\n", self.count);
        *out += &format!("safeyolo_{name}_sum{{{labels}}} {}\n", self.sum);
    }
}

#[derive(Default)]
struct Measurements {
    chunks: u64,
    bytes: u64,
    messages: u64,
    connections: u64,
    partial: u64,
    parse_failures: u64,
    message_chunks_unavailable: u64,
    chunk_bytes: Histogram,
    interval: Histogram,
    message_chunks: Histogram,
    lifetime: Histogram,
}
impl Measurements {
    fn counters(&self) -> [(&'static str, u64); 7] {
        [
            ("observation_chunks_total", self.chunks),
            ("observation_bytes_total", self.bytes),
            ("application_messages_total", self.messages),
            ("connections_started_total", self.connections),
            ("partial_or_aborted_streams_total", self.partial),
            ("protocol_parse_failures_total", self.parse_failures),
            (
                "chunks_per_application_message_unavailable_total",
                self.message_chunks_unavailable,
            ),
        ]
    }
    fn histograms(&self) -> [(&'static str, &Histogram, &[f64; 8]); 4] {
        [
            ("observation_chunk_bytes", &self.chunk_bytes, &BYTE_BUCKETS),
            (
                "observation_inter_chunk_interval_seconds",
                &self.interval,
                &TIME_BUCKETS,
            ),
            (
                "chunks_per_application_message",
                &self.message_chunks,
                &CHUNK_BUCKETS,
            ),
            ("connection_lifetime_seconds", &self.lifetime, &TIME_BUCKETS),
        ]
    }
}

#[derive(Hash, PartialEq, Eq)]
struct ConnectionKey {
    instance: String,
    runtime: String,
    connection: String,
}
impl ConnectionKey {
    fn of(o: &Observation) -> Self {
        Self {
            instance: o.id.instance_id.clone(),
            runtime: o.id.runtime_id.clone(),
            connection: o.connection_id.clone(),
        }
    }
}
struct Chunk {
    sequence: u64,
    start: u64,
    end: u64,
}
#[derive(Default)]
struct Stream {
    last: Option<u64>,
    chunks: VecDeque<Chunk>,
}
impl Stream {
    fn message_chunks(&mut self, span: &InputSpan, retained: &mut usize) -> Option<u64> {
        let mut through = span.start_offset;
        let mut count = 0;
        for chunk in &self.chunks {
            if chunk.end <= span.start_offset
                || chunk.start >= span.end_offset
                || chunk.sequence < span.observed_from.sequence
                || chunk.sequence > span.observed_through.sequence
            {
                continue;
            }
            if chunk.start > through {
                break;
            }
            through = through.max(chunk.end);
            count += 1;
        }
        // Keep a read-ahead chunk that also contains the next message. It
        // genuinely contributes to both messages; earlier chunks can retire.
        while self
            .chunks
            .front()
            .is_some_and(|chunk| chunk.end <= span.end_offset)
        {
            self.chunks.pop_front();
            *retained -= 1;
        }
        // A completed large message must release its backing allocation too.
        // Otherwise many idle connections can each keep an old full cache.
        self.chunks.shrink_to_fit();
        (through >= span.end_offset && span.end_offset > span.start_offset).then_some(count)
    }
}
#[derive(Default)]
struct Connection {
    started: Option<(Labels, u64)>,
    streams: BTreeMap<Labels, Stream>,
}

#[derive(Default)]
pub(super) struct TransportMetrics {
    series: BTreeMap<Labels, Measurements>,
    connections: HashMap<ConnectionKey, Connection>,
    retained_chunks: usize,
    canonical_loss: u64,
    accounting_loss: u64,
}
impl TransportMetrics {
    pub(super) fn record(&mut self, record: &Record) {
        match record {
            Record::Gap(gap) => {
                self.canonical_loss += gap.count;
                // The missing record may be a chunk, completion or terminal
                // event. Retire uncertain state, including timing adjacency.
                self.connections.retain(|key, connection| {
                    if key.instance != gap.instance_id || key.runtime != gap.runtime_id {
                        return true;
                    }
                    self.retained_chunks -= connection
                        .streams
                        .values()
                        .map(|s| s.chunks.len())
                        .sum::<usize>();
                    false
                });
            }
            Record::Observation(o) => self.observation(o),
        }
    }
    fn observation(&mut self, o: &Observation) {
        if o.layer == Layer::WirePacket {
            return; // Transport metrics use stream boundaries, never packet segmentation.
        }
        let labels = Labels::of(o);
        let values = self.series.entry(labels).or_default();
        match o.state {
            State::Chunk => {
                values.chunks += 1;
                if let Some(length) = o.observed_length {
                    values.bytes += length;
                    values.chunk_bytes.observe(length as f64, &BYTE_BUCKETS);
                }
            }
            State::Complete if o.layer == Layer::ApplicationContent => values.messages += 1,
            State::Connected => values.connections += 1,
            State::ParseError => values.parse_failures += 1,
            State::ReadError | State::WriteError => values.partial += 1,
            State::Dropped
                if matches!(o.layer, Layer::ProtocolMessage | Layer::ApplicationContent) =>
            {
                values.partial += 1
            }
            _ => {}
        }
        let key = ConnectionKey::of(o);
        if matches!(o.state, State::Closed | State::Failed) {
            if let Some(connection) = self.connections.remove(&key) {
                self.retained_chunks -= connection
                    .streams
                    .values()
                    .map(|s| s.chunks.len())
                    .sum::<usize>();
                if let Some((labels, start)) = connection.started
                    && let Some(ns) = o.timestamp.monotonic_ns.checked_sub(start)
                {
                    self.series
                        .entry(labels)
                        .or_default()
                        .lifetime
                        .observe(ns as f64 / 1e9, &TIME_BUCKETS);
                }
            }
            return;
        }
        if !matches!(o.state, State::Connected | State::Chunk | State::Complete) {
            return;
        }
        if o.state == State::Complete && !self.connections.contains_key(&key) {
            self.series
                .entry(labels)
                .or_default()
                .message_chunks_unavailable += 1;
            return;
        }
        if !self.connections.contains_key(&key) && self.connections.len() >= MAX_CONNECTIONS {
            self.accounting_loss += 1;
            return;
        }
        let connection = self.connections.entry(key).or_default();
        match o.state {
            State::Connected => connection.started = Some((labels, o.timestamp.monotonic_ns)),
            State::Chunk => {
                let stream = connection.streams.entry(labels).or_default();
                if let Some(last) = stream.last
                    && let Some(ns) = o.timestamp.monotonic_ns.checked_sub(last)
                {
                    self.series
                        .entry(labels)
                        .or_default()
                        .interval
                        .observe(ns as f64 / 1e9, &TIME_BUCKETS);
                }
                stream.last = Some(o.timestamp.monotonic_ns);
                if o.direction == Direction::ToProxy
                    && let (Some(start), Some(length)) = (o.stream_offset, o.observed_length)
                {
                    if self.retained_chunks < MAX_CHUNKS {
                        stream.chunks.push_back(Chunk {
                            sequence: o.id.sequence,
                            start,
                            end: start.saturating_add(length),
                        });
                        self.retained_chunks += 1;
                    } else {
                        self.accounting_loss += 1;
                    }
                }
            }
            State::Complete if o.layer == Layer::ApplicationContent => {
                let relation = o
                    .input_span
                    .as_ref()
                    .filter(|s| {
                        s.parser_consumed
                            && s.observed_from.instance_id == o.id.instance_id
                            && s.observed_through.instance_id == o.id.instance_id
                            && s.observed_from.runtime_id == o.id.runtime_id
                            && s.observed_through.runtime_id == o.id.runtime_id
                    })
                    .and_then(|span| {
                        let input = Labels::input(o, span);
                        connection
                            .streams
                            .get_mut(&input)?
                            .message_chunks(span, &mut self.retained_chunks)
                            .map(|count| (input, count))
                    });
                if let Some((input, count)) = relation {
                    self.series
                        .entry(input)
                        .or_default()
                        .message_chunks
                        .observe(count as f64, &CHUNK_BUCKETS);
                } else {
                    self.series
                        .entry(labels)
                        .or_default()
                        .message_chunks_unavailable += 1;
                }
            }
            _ => {}
        }
    }
    pub(super) fn json(&self) -> Value {
        let series = self
            .series
            .iter()
            .map(|(labels, values)| {
                let mut row = serde_json::to_value(labels).unwrap();
                for (name, value) in values.counters() {
                    row[name] = json!(value);
                }
                for (name, histogram, bounds) in values.histograms() {
                    row[name] = histogram.json(bounds);
                }
                row
            })
            .collect::<Vec<_>>();
        json!({"series":series, "observation_loss_total": {
            "canonical_admission_unavailable": self.canonical_loss,
            "metrics_accounting_capacity": self.accounting_loss}})
    }
    pub(super) fn prometheus(&self) -> String {
        let mut out = String::new();
        for (name, _) in Measurements::default().counters() {
            out += &format!("# TYPE safeyolo_{name} counter\n");
        }
        for (name, _, _) in Measurements::default().histograms() {
            out += &format!("# TYPE safeyolo_{name} histogram\n");
        }
        out += "# TYPE safeyolo_observation_loss_total counter\n";
        for (reason, count) in [
            ("canonical_admission_unavailable", self.canonical_loss),
            ("metrics_accounting_capacity", self.accounting_loss),
        ] {
            out += &format!("safeyolo_observation_loss_total{{reason=\"{reason}\"}} {count}\n");
        }
        for (labels, values) in &self.series {
            let labels = labels.prometheus();
            for (name, value) in values.counters() {
                out += &format!("safeyolo_{name}{{{labels}}} {value}\n");
            }
            for (name, histogram, bounds) in values.histograms() {
                histogram.prometheus(&mut out, name, &labels, bounds);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Observation {
        let bus = ObservationBus::new(
            "installation".into(),
            "runtime".into(),
            Limits::default(),
            Arc::default(),
        );
        crate::observations::tests::sample(&bus)
    }
    fn emit(metrics: &mut TransportMetrics, o: &Observation) {
        metrics.record(&Record::Observation(Box::new(o.clone())));
    }
    fn complete(o: &Observation, end: u64) -> Observation {
        let mut result = o.clone();
        result.layer = Layer::ApplicationContent;
        result.point = Point::RequestContent;
        result.state = State::Complete;
        result.input_span = Some(InputSpan {
            point: o.point,
            layer: o.layer,
            direction: o.direction,
            observed_from: o.id.clone(),
            observed_through: o.id.clone(),
            start_offset: 0,
            end_offset: end,
            parser_consumed: true,
        });
        result
    }

    #[test]
    fn prefix_ancestry_never_becomes_an_exact_message_distribution() {
        let mut metrics = TransportMetrics::default();
        let o = sample();
        emit(&mut metrics, &o);
        let mut completion = complete(&o, 1);
        completion.input_span.as_mut().unwrap().parser_consumed = false;
        emit(&mut metrics, &completion);
        let values = &metrics.series[&Labels::of(&o)];
        assert_eq!(values.chunks, 1);
        assert_eq!(values.message_chunks.count, 0);
        let application = &metrics.series[&Labels::of(&completion)];
        assert_eq!(application.messages, 1);
        assert_eq!(application.message_chunks_unavailable, 1);
    }

    #[test]
    fn a_gap_preserves_totals_but_breaks_timing_and_message_coverage() {
        let mut metrics = TransportMetrics::default();
        let mut o = sample();
        o.id.sequence = 1;
        emit(&mut metrics, &o);
        metrics.record(&Record::Gap(Gap {
            instance_id: o.id.instance_id.clone(),
            runtime_id: o.id.runtime_id.clone(),
            first_sequence: 2,
            last_sequence: 3,
            count: 2,
            reason: LossReason::CanonicalAdmissionUnavailable,
        }));
        assert_eq!(metrics.retained_chunks, 0);
        assert!(metrics.connections.is_empty());
        o.id.sequence = 4;
        o.stream_offset = Some(3);
        o.timestamp.monotonic_ns = 10_000_000;
        emit(&mut metrics, &o);
        let completion = complete(&o, 4);
        emit(&mut metrics, &completion);
        let values = &metrics.series[&Labels::of(&o)];
        assert_eq!(values.chunks, 2);
        assert_eq!(values.bytes, 2);
        assert_eq!(values.interval.count, 0);
        assert_eq!(values.message_chunks.count, 0);
        assert_eq!(metrics.canonical_loss, 2);
        assert_eq!(
            metrics.series[&Labels::of(&completion)].message_chunks_unavailable,
            1
        );
    }

    #[test]
    fn chunk_accounting_is_bounded_and_cannot_hide_missing_coverage() {
        let mut metrics = TransportMetrics::default();
        let mut o = sample();
        for offset in 0..=MAX_CHUNKS {
            o.stream_offset = Some(offset as u64);
            emit(&mut metrics, &o);
        }
        assert_eq!(metrics.retained_chunks, MAX_CHUNKS);
        assert_eq!(metrics.accounting_loss, 1);
        let completion = complete(&o, (MAX_CHUNKS + 1) as u64);
        emit(&mut metrics, &completion);
        assert_eq!(metrics.retained_chunks, 0);
        assert_eq!(
            metrics
                .connections
                .values()
                .flat_map(|c| c.streams.values())
                .map(|s| s.chunks.capacity())
                .sum::<usize>(),
            0
        );
        assert_eq!(
            metrics.series[&Labels::of(&o)].chunks,
            (MAX_CHUNKS + 1) as u64
        );
        assert_eq!(metrics.series[&Labels::of(&o)].message_chunks.count, 0);
        assert_eq!(
            metrics.series[&Labels::of(&completion)].message_chunks_unavailable,
            1
        );
    }

    #[test]
    fn completion_cannot_recreate_retired_connection_accounting() {
        let mut metrics = TransportMetrics::default();
        let mut o = sample();
        emit(&mut metrics, &o);
        let completion = complete(&o, 1);
        o.state = State::Closed;
        emit(&mut metrics, &o);
        emit(&mut metrics, &completion);
        assert!(metrics.connections.is_empty());
        assert_eq!(metrics.retained_chunks, 0);
        assert_eq!(metrics.series[&Labels::of(&completion)].messages, 1);
        assert_eq!(
            metrics.series[&Labels::of(&completion)].message_chunks_unavailable,
            1
        );
    }

    #[test]
    fn active_connections_are_bounded_and_retire_at_the_real_terminal_record() {
        let mut metrics = TransportMetrics::default();
        let mut o = sample();
        o.state = State::Connected;
        o.direction = Direction::Both;
        for number in 0..=MAX_CONNECTIONS {
            o.connection_id = number.to_string();
            emit(&mut metrics, &o);
        }
        assert_eq!(metrics.connections.len(), MAX_CONNECTIONS);
        assert_eq!(metrics.accounting_loss, 1);
        assert_eq!(
            metrics.series[&Labels::of(&o)].connections,
            (MAX_CONNECTIONS + 1) as u64
        );
        o.connection_id = "0".into();
        o.state = State::Closed;
        o.timestamp.monotonic_ns = 50_000_000;
        emit(&mut metrics, &o);
        assert_eq!(metrics.connections.len(), MAX_CONNECTIONS - 1);
        assert_eq!(metrics.series[&Labels::of(&o)].lifetime.count, 1);
        assert_eq!(metrics.series[&Labels::of(&o)].lifetime.sum, 0.05);
        let mut other_runtime = o.clone();
        other_runtime.id.runtime_id = "other-runtime".into();
        other_runtime.state = State::Connected;
        emit(&mut metrics, &other_runtime);
        assert_eq!(metrics.connections.len(), MAX_CONNECTIONS);
    }
}
