//! Explicit capture, shared encoding and bounded asynchronous delivery.
use crate::{
    Error,
    observations::{ConsumerKind, Layer, Limits, ObservationBus, Record, Session},
    policy::python_whitespace,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::{Notify, watch},
    task::JoinSet,
};

mod compat;
mod pcapng;
pub(crate) mod secrets;
mod stdout;
#[cfg(test)]
mod tests;
pub(crate) mod wire;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub payload_layers: Vec<Layer>,
    pub file: Option<PathBuf>,
    pub stdout: bool,
    pub tcp: Option<Tcp>,
    pub wss: bool,
    pub queue: Limits,
    pub profile: Profile,
    pub wire_interface: Option<String>,
    pub compatibility_packets: bool,
    pub tls_secrets: bool,
    pub secret_outputs: Vec<SecretOutput>,
    pub secrets_token_file: Option<PathBuf>,
    #[cfg(test)]
    #[serde(skip)]
    pub(super) test_enterprise: Option<pcapng::Enterprise>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOutput {
    File,
    Stdout,
    Tcp,
}
impl SecretOutput {
    fn permits(self, sink: Sink) -> bool {
        matches!(
            (self, sink),
            (Self::File, Sink::File) | (Self::Stdout, Sink::Stdout) | (Self::Tcp, Sink::Tcp)
        )
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Packet {
    pub link_type: u32,
    pub original_length: u32,
    pub precision_ns: u64,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub enum Profile {
    #[default]
    #[serde(rename = "pcap:compat")]
    Compat,
    #[serde(rename = "pcap:wire")]
    Wire,
    #[serde(rename = "pcapng")]
    Pcapng,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tcp {
    pub bind: SocketAddr,
    pub insecure_remote: bool,
}
impl Default for Tcp {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 46378),
            insecure_remote: false,
        }
    }
}
impl Settings {
    pub(crate) fn validate(&self, admin: bool) -> Result<(), Error> {
        // DOC: docs/native-observations.md
        if self
            .tcp
            .as_ref()
            .is_some_and(|tcp| !tcp.bind.ip().to_canonical().is_loopback() && !tcp.insecure_remote)
        {
            return Err("packet_capture.tcp non-loopback bind requires insecure_remote=true; use authenticated WSS for remote capture".into());
        }
        if self.wss && !admin {
            return Err("packet_capture.wss requires the authenticated Admin listener".into());
        }
        if self.tls_secrets && !matches!(self.profile, Profile::Pcapng) {
            return Err("packet_capture.tls_secrets requires profile=pcapng".into());
        }
        Ok(())
    }
    fn enterprise(&self) -> Option<pcapng::Enterprise> {
        #[cfg(test)]
        if let Some(enterprise) = self.test_enterprise {
            return Some(enterprise);
        }
        pcapng::ENTERPRISE
    }
    pub(crate) fn unavailable(&self) -> Option<&'static str> {
        match self.profile {
            Profile::Compat => None,
            Profile::Wire
                if self.wire_interface.is_none()
                    || !self.payload_layers.contains(&Layer::WirePacket) =>
            {
                Some("pcap_wire_disabled")
            }
            Profile::Wire => None,
            Profile::Pcapng if self.enterprise().is_none() => {
                Some("pcapng_portable_encoder_unavailable")
            }
            Profile::Pcapng => None,
        }
    }
    pub(crate) fn payload_layers(&self) -> Vec<Layer> {
        if self.active() && self.unavailable().is_none() {
            if matches!(self.profile, Profile::Wire) {
                vec![Layer::WirePacket]
            } else {
                self.payload_layers.clone()
            }
        } else {
            Vec::new()
        }
    }
    fn active(&self) -> bool {
        self.file.is_some() || self.stdout || self.tcp.is_some() || self.wss
    }
}

#[derive(Clone, Copy)]
enum Encoder {
    Compat,
    Wire(wire::Format),
    Pcapng(pcapng::Format),
}
impl Encoder {
    fn session(self, session: &Session, sink: &str, limit: usize) -> Result<Vec<u8>, ()> {
        match self {
            Self::Compat => compat::session(session, sink, limit),
            Self::Wire(format) => Ok(format.header()),
            Self::Pcapng(format) => format.session(session, sink, limit),
        }
    }
    fn encode(self, record: &Record, limit: usize) -> Result<Vec<u8>, ()> {
        match self {
            Self::Compat => compat::encode(record, limit),
            Self::Wire(f) => f.encode(record, limit),
            Self::Pcapng(f) => f.encode(record, limit),
        }
    }
    fn loss(
        self,
        session: &Session,
        sink: &str,
        first: u64,
        last: u64,
        reason: &str,
    ) -> Result<Vec<u8>, ()> {
        match self {
            Self::Compat => compat::loss(session, sink, first, last, reason),
            Self::Wire(_) => Err(()),
            Self::Pcapng(f) => f.loss(session, sink, first, last, reason),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Sink {
    File,
    Stdout,
    Tcp,
    Wss,
}
impl Sink {
    pub(crate) fn index(self) -> usize {
        self as usize
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Stdout => "stdout",
            Self::Tcp => "tcp",
            Self::Wss => "wss",
        }
    }
}
struct Batch {
    bytes: Arc<[u8]>,
    first: u64,
    last: u64,
}
impl Batch {
    fn charge(&self) -> usize {
        self.bytes.len() + 128
    }
}
struct Pending {
    batches: VecDeque<Batch>,
    bytes: usize,
    items: usize,
    through: u64,
    closed: bool,
}
struct SinkQueue {
    pending: Mutex<Pending>,
    limits: Limits,
    notify: Notify,
    session: Session,
    kind: Sink,
    counters: Arc<crate::observations::Counters>,
    encoder: Encoder,
    secrets: bool,
}
pub(crate) struct Receiver {
    inner: Arc<SinkQueue>,
    next: u64,
    initial: bool,
}
/// A writer retains its budget lease until the whole batch was written or failed.
/// A blocked socket cannot silently remove in-flight bytes from accounting.
pub(crate) struct Delivery {
    pub(crate) bytes: Arc<[u8]>,
    inner: Arc<SinkQueue>,
}
impl Drop for Delivery {
    fn drop(&mut self) {
        let mut pending = self.inner.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.bytes -= self.bytes.len() + 128;
        pending.items -= 1;
    }
}
impl Receiver {
    pub(crate) fn error(&self, reason: &'static str) {
        report(&self.inner.counters, self.inner.kind, reason);
    }
    pub(crate) fn written(&self, n: usize) {
        self.inner.counters.sink_bytes[self.inner.kind.index()]
            .fetch_add(n as u64, Ordering::Relaxed);
    }
    pub(crate) async fn recv(&mut self) -> Option<Delivery> {
        loop {
            let notified = self.inner.notify.notified();
            {
                let mut pending = self.inner.pending.lock().unwrap_or_else(|e| e.into_inner());
                let missing_through = pending
                    .batches
                    .front()
                    .map_or(pending.through, |b| b.first.saturating_sub(1));
                if !self.initial && missing_through >= self.next {
                    if matches!(self.inner.encoder, Encoder::Wire(_)) {
                        // Classic wire PCAP has no loss-record representation.
                        // End this session rather than insert invented packets.
                        report(
                            &self.inner.counters,
                            self.inner.kind,
                            "wire_evidence_gap_session_ended",
                        );
                        return None;
                    }
                    // Data admissions reserve one item and CONTROL_BYTES for this
                    // bounded, self-contained loss record. It precedes later bytes.
                    let bytes = self
                        .inner
                        .encoder
                        .loss(
                            &self.inner.session,
                            self.inner.kind.name(),
                            self.next,
                            missing_through,
                            "encoder_or_sink_admission_unavailable",
                        )
                        .ok()?;
                    self.next = missing_through + 1;
                    pending.bytes += bytes.len() + 128;
                    pending.items += 1;
                    debug_assert!(pending.bytes <= self.inner.limits.bytes);
                    debug_assert!(pending.items <= self.inner.limits.items);
                    return Some(Delivery {
                        bytes: bytes.into(),
                        inner: self.inner.clone(),
                    });
                }
                if let Some(batch) = pending.batches.pop_front() {
                    if self.initial {
                        self.initial = false;
                    } else {
                        self.next = self.next.max(batch.last + 1);
                    }
                    return Some(Delivery {
                        bytes: batch.bytes,
                        inner: self.inner.clone(),
                    });
                }
                if pending.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.inner.counters.sink_disconnects[self.inner.kind.index()]
            .fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct Capture {
    bus: Weak<ObservationBus>,
    pub(crate) tcp_endpoint: Option<crate::admin_shield::CaptureEndpoint>,
    session: Session,
    pub(crate) settings: Settings,
    sinks: Mutex<Vec<Weak<SinkQueue>>>,
    counters: Arc<crate::observations::Counters>,
    encoded_through: AtomicU64,
    progress: Notify,
    encoder: Encoder,
    secrets: Option<Arc<secrets::Store>>,
    secrets_token: zeroize::Zeroizing<String>,
}
impl Capture {
    pub(crate) fn register_secrets(&self, connection: &str) -> Option<Arc<secrets::Secrets>> {
        self.secrets.as_ref()?.register(connection)
    }
    #[cfg(test)]
    fn wire_format(&self) -> Option<wire::Format> {
        match self.encoder {
            Encoder::Wire(format) => Some(format),
            Encoder::Pcapng(format) => format.wire,
            _ => None,
        }
    }
    pub(crate) fn subscribe(&self, kind: Sink) -> Result<Receiver, ()> {
        let secrets = self
            .settings
            .secret_outputs
            .iter()
            .any(|output| output.permits(kind));
        self.subscribe_authorized(kind, secrets)
    }
    pub(crate) fn authorize_secrets(
        &self,
        headers: &hyper::HeaderMap,
    ) -> Result<bool, crate::admin_api::Error> {
        crate::admin_api::authenticate(headers, &self.secrets_token)
    }
    pub(crate) fn subscribe_authorized(&self, kind: Sink, secrets: bool) -> Result<Receiver, ()> {
        // Serialize registration against dispatch; never replay historical batches.
        let mut sinks = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        let bus = self.bus.upgrade().ok_or(())?;
        if matches!(self.encoder, Encoder::Wire(_))
            && !bus.wire.get().is_some_and(|source| source.is_active())
        {
            report(&self.counters, kind, "pcap_acquisition_unavailable");
            return Err(());
        }
        let encoder = match self.encoder {
            Encoder::Pcapng(mut format)
                if format.wire.is_some()
                    && !bus.wire.get().is_some_and(|source| source.is_active()) =>
            {
                format.wire_unavailable = Some("pcap_acquisition_unavailable");
                Encoder::Pcapng(format)
            }
            encoder => encoder,
        };
        let first = bus.next_sequence();
        let session = Session {
            sink_session_id: uuid::Uuid::new_v4().to_string(),
            first_sequence: first,
            ..self.session.clone()
        };
        if let Encoder::Wire(format) = self.encoder {
            eprintln!(
                "Packet capture session profile=pcap:wire sink={} session={} link_type={} precision_ns={}",
                kind.name(),
                serde_json::to_string(&session).map_err(|_| ())?,
                format.link_type,
                format.precision_ns
            );
        }
        let bytes = encoder
            .session(
                &session,
                kind.name(),
                self.settings
                    .queue
                    .bytes
                    .saturating_sub(compat::CONTROL_BYTES),
            )
            .map_err(|()| {
                report(&self.counters, kind, "session_budget_unavailable");
            })?;
        let batch = Batch {
            bytes: bytes.into(),
            first,
            last: first - 1,
        };
        let charged = batch.charge();
        if self.settings.queue.items < 2
            || charged
                > self
                    .settings
                    .queue
                    .bytes
                    .saturating_sub(compat::CONTROL_BYTES)
        {
            report(&self.counters, kind, "session_budget_unavailable");
            return Err(());
        }
        let inner = Arc::new(SinkQueue {
            pending: Mutex::new(Pending {
                batches: VecDeque::from([batch]),
                bytes: charged,
                items: 1,
                through: first - 1,
                closed: false,
            }),
            limits: self.settings.queue,
            notify: Notify::new(),
            session,
            kind,
            counters: self.counters.clone(),
            encoder,
            secrets: secrets && self.secrets.is_some(),
        });
        sinks.retain(|sink| sink.strong_count() != 0);
        sinks.push(Arc::downgrade(&inner));
        Ok(Receiver {
            inner,
            next: first,
            initial: true,
        })
    }
    fn dispatch(
        &self,
        record: &Record,
        encoded: Option<Arc<[u8]>>,
        secret_encoded: Option<Arc<[u8]>>,
    ) {
        let (first, last) = match record {
            Record::Observation(o) => (o.id.sequence, o.id.sequence),
            Record::Gap(g) => (g.first_sequence, g.last_sequence),
        };
        let mut sinks = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        sinks.retain(|sink| {
            let Some(sink) = sink.upgrade() else {
                return false;
            };
            if last < sink.session.first_sequence {
                return true;
            }
            let mut pending = sink.pending.lock().unwrap_or_else(|e| e.into_inner());
            let public = &encoded;
            let clipped;
            let encoded = if let Record::Gap(gap) = record
                && !matches!(self.encoder, Encoder::Wire(_))
                && gap.first_sequence < sink.session.first_sequence
            {
                let mut gap = gap.clone();
                gap.first_sequence = sink.session.first_sequence;
                gap.count = gap.last_sequence - gap.first_sequence + 1;
                clipped = self
                    .encoder
                    .encode(
                        &Record::Gap(gap),
                        sink.limits
                            .bytes
                            .saturating_sub(compat::CONTROL_BYTES + 128),
                    )
                    .ok()
                    .map(Arc::from);
                &clipped
            } else {
                if sink.secrets {
                    secret_encoded
                        .as_ref()
                        .map_or(&encoded, |_| &secret_encoded)
                } else {
                    &encoded
                }
            };
            if pending.closed {
                return true;
            }
            let mut fallback: Option<Arc<[u8]>> = None;
            let encoded = if sink.secrets
                && secret_encoded.as_ref().is_some_and(|bytes| {
                    bytes.len() + 128
                        > sink
                            .limits
                            .bytes
                            .saturating_sub(compat::CONTROL_BYTES + pending.bytes)
                })
                && let Encoder::Pcapng(format) = self.encoder
                && let Some(public) = public
                && let Ok(mut bytes) = format.limitation(
                    record,
                    "tls_secret_sink_budget_unavailable",
                    compat::CONTROL_BYTES / 2 - 128,
                )
                && bytes.len() + public.len() + 128
                    <= sink
                        .limits
                        .bytes
                        .saturating_sub(compat::CONTROL_BYTES / 2 + pending.bytes)
            {
                bytes.extend_from_slice(public);
                fallback = Some(Arc::from(bytes));
                &fallback
            } else {
                encoded
            };
            let admitted = encoded.as_ref().is_some_and(|bytes| {
                let batch = Batch {
                    bytes: bytes.clone(),
                    first: first.max(sink.session.first_sequence),
                    last,
                };
                let charge = batch.charge();
                if pending.items >= sink.limits.items.saturating_sub(1)
                    || charge
                        > sink
                            .limits
                            .bytes
                            .saturating_sub(if sink.secrets && fallback.is_some() {
                                compat::CONTROL_BYTES / 2
                            } else {
                                compat::CONTROL_BYTES
                            })
                            .saturating_sub(pending.bytes)
                {
                    return false;
                }
                pending.bytes += charge;
                pending.items += 1;
                pending.batches.push_back(batch);
                true
            });
            if !admitted {
                self.counters.sink_dropped[sink.kind.index()].fetch_add(
                    last - first.max(sink.session.first_sequence) + 1,
                    Ordering::Relaxed,
                );
            }
            pending.through = last;
            sink.notify.notify_one();
            true
        });
        self.encoded_through.store(last, Ordering::Release);
        self.progress.notify_waiters();
    }
    fn control(&self, bytes: Arc<[u8]>) {
        let mut sinks = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        sinks.retain(|sink| {
            let Some(sink) = sink.upgrade() else {
                return false;
            };
            let mut pending = sink.pending.lock().unwrap_or_else(|e| e.into_inner());
            let batch = Batch {
                bytes: bytes.clone(),
                first: pending.through + 1,
                last: pending.through,
            };
            if !pending.closed
                && pending.items < sink.limits.items.saturating_sub(1)
                && batch.charge()
                    <= sink
                        .limits
                        .bytes
                        .saturating_sub(compat::CONTROL_BYTES + pending.bytes)
            {
                pending.bytes += batch.charge();
                pending.items += 1;
                pending.batches.push_back(batch);
                sink.notify.notify_one();
            } else {
                report(
                    &self.counters,
                    sink.kind,
                    "capture_control_budget_unavailable",
                );
            }
            true
        });
    }
    fn wire_statistics(&self) {
        if let Encoder::Pcapng(format) = self.encoder {
            let ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |t| t.as_nanos() as i128);
            if let Ok(bytes) = format.statistics(
                ns,
                self.counters.wire_received.load(Ordering::Relaxed),
                self.counters.wire_kernel_dropped.load(Ordering::Relaxed),
                self.counters.wire_interface_dropped.load(Ordering::Relaxed),
                compat::CONTROL_BYTES,
            ) {
                self.control(bytes.into());
            }
        }
    }
    async fn encode_secrets(
        &self,
        record: &Record,
        encoded: &Option<Arc<[u8]>>,
        limit: usize,
    ) -> Option<Arc<[u8]>> {
        let store = self.secrets.as_ref()?;
        let Encoder::Pcapng(format) = self.encoder else {
            return None;
        };
        let Record::Observation(o) = record else {
            return None;
        };
        o.packet?;
        let base = encoded.as_ref()?;
        let (lines, reason) = store.snapshot(&o.connection_id).await;
        let remaining = limit.saturating_sub(base.len());
        let mut prefix = pcapng::secrets(lines.as_bytes(), remaining).ok();
        let reason = if prefix.is_none() {
            Some("tls_secret_export_budget_unavailable")
        } else {
            reason
        };
        if let Some(reason) = reason {
            let limitation = format.limitation(record, reason, remaining).ok()?;
            if prefix
                .as_ref()
                .is_some_and(|p| p.len() + limitation.len() <= remaining)
            {
                prefix.as_mut().unwrap().extend(limitation);
            } else {
                prefix = Some(limitation);
            }
        }
        let mut bytes = prefix?;
        bytes.extend_from_slice(base);
        Some(bytes.into())
    }
    fn close(&self) {
        for sink in self
            .sinks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
        {
            sink.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .closed = true;
            sink.notify.notify_one();
        }
    }
    fn report_sink_errors(&self, reason: &'static str) {
        for sink in self
            .sinks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
        {
            report(&sink.counters, sink.kind, reason);
        }
    }
    async fn flush(&self) {
        let Some(bus) = self.bus.upgrade() else {
            return;
        };
        let through = bus.next_sequence() - 1;
        loop {
            let notified = self.progress.notified();
            if self.encoded_through.load(Ordering::Acquire) >= through {
                return;
            }
            notified.await;
        }
    }
}
fn report(counters: &crate::observations::Counters, kind: Sink, reason: &'static str) {
    counters.sink_errors[kind.index()].fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "Packet capture sink error sink={} layer=unavailable reason={reason}",
        kind.name()
    );
}

pub(crate) struct BoundTcp {
    listener: tokio::net::TcpListener,
    pub(crate) endpoint: crate::admin_shield::CaptureEndpoint,
}
impl BoundTcp {
    fn new(listener: tokio::net::TcpListener) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let address = listener.local_addr()?;
        let mut ipv6_only: libc::c_int = 0;
        if address.is_ipv6() {
            let mut length = std::mem::size_of_val(&ipv6_only) as libc::socklen_t;
            // SAFETY: the socket and the writable option buffer remain valid
            // for the call. Retain the OS setting, not an assumed platform default.
            if unsafe {
                libc::getsockopt(
                    listener.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    (&mut ipv6_only as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self {
            listener,
            endpoint: crate::admin_shield::CaptureEndpoint {
                address,
                ipv6_only: ipv6_only != 0,
            },
        })
    }
}
pub(crate) async fn bind_tcp(config: &mut crate::Config) -> Option<Result<BoundTcp, ()>> {
    let settings = &mut config.native_settings.as_mut()?.packet_capture;
    if settings.unavailable().is_some() {
        return None;
    }
    let tcp = settings.tcp.as_mut()?;
    match tokio::net::TcpListener::bind(tcp.bind)
        .await
        .and_then(BoundTcp::new)
    {
        Ok(listener) => {
            tcp.bind = listener.endpoint.address;
            Some(Ok(listener))
        }
        Err(_) => Some(Err(())),
    }
}

pub(crate) struct Running {
    pub(crate) capture: Arc<Capture>,
    stop: watch::Sender<bool>,
    tasks: JoinSet<()>,
}
impl Running {
    pub(crate) fn start(
        runtime: &Arc<crate::Runtime>,
        tcp_listener: Option<Result<BoundTcp, ()>>,
    ) -> Option<Self> {
        let settings = runtime
            .config
            .native_settings
            .as_ref()?
            .packet_capture
            .clone();
        if !settings.active() {
            return None;
        }
        let bus = &runtime.connection_events.as_ref()?.observations;
        let wire_requested = matches!(settings.profile, Profile::Wire | Profile::Pcapng)
            && settings.wire_interface.is_some()
            && settings.payload_layers.contains(&Layer::WirePacket);
        let native = if wire_requested && settings.unavailable().is_none() {
            Some(wire::Source::open(
                settings.wire_interface.as_deref().unwrap(),
                settings.queue,
                bus.counters.clone(),
            ))
        } else {
            None
        };
        let wire_unavailable = native
            .as_ref()
            .and_then(|result| result.as_ref().err().copied());
        let unavailable = settings.unavailable().or(wire_unavailable);
        if let Some(reason) = unavailable {
            if wire_requested {
                bus.counters
                    .wire_source_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            for (kind, enabled) in [
                (Sink::File, settings.file.is_some()),
                (Sink::Stdout, settings.stdout),
                (Sink::Tcp, settings.tcp.is_some()),
                (Sink::Wss, settings.wss),
            ] {
                if enabled {
                    report(&bus.counters, kind, reason);
                }
            }
            if settings.unavailable().is_some() || matches!(settings.profile, Profile::Wire) {
                return None;
            }
        }
        let wire_format = native
            .as_ref()
            .and_then(|s| s.as_ref().ok())
            .map(|s| s.format);
        let encoder = match settings.profile {
            Profile::Compat => Encoder::Compat,
            Profile::Wire => Encoder::Wire(wire_format?),
            Profile::Pcapng => Encoder::Pcapng(pcapng::Format {
                enterprise: settings.enterprise()?,
                wire: wire_format,
                compatibility: settings.compatibility_packets,
                wire_unavailable,
            }),
        };
        let mut secrets_token = zeroize::Zeroizing::new(String::new());
        if settings.tls_secrets
            && let Some(path) = settings.secrets_token_file.as_deref()
        {
            let token = crate::admin_listener::read_token(Some(path)).map(|token| {
                zeroize::Zeroizing::new(token.trim_matches(python_whitespace).to_owned())
            });
            let read_token =
                crate::admin_listener::read_token(runtime.config.admin_api_token_file.as_deref());
            if let (Ok(token), Ok(read_token)) = (token, read_token)
                && !token.is_empty()
                && token.is_ascii()
                && token.as_str() != read_token.trim_matches(python_whitespace)
            {
                secrets_token = token;
            } else {
                report(
                    &bus.counters,
                    Sink::Wss,
                    "capture_secrets_authorization_unavailable",
                );
            }
        }
        let secrets = (settings.tls_secrets
            && (settings.secret_outputs.iter().any(|output| match output {
                SecretOutput::File => settings.file.is_some(),
                SecretOutput::Stdout => settings.stdout,
                SecretOutput::Tcp => settings.tcp.is_some(),
            }) || settings.wss && !secrets_token.is_empty()))
        .then(|| Arc::new(secrets::Store::new(settings.queue)));
        let mut source = bus.subscribe(ConsumerKind::Capture, settings.queue);
        let capture = Arc::new(Capture {
            bus: Arc::downgrade(bus),
            tcp_endpoint: tcp_listener
                .as_ref()
                .and_then(|listener| listener.as_ref().ok())
                .map(|listener| listener.endpoint),
            session: Session {
                timestamp_resolution: crate::observations::Resolution {
                    wall_ns: if matches!(settings.profile, Profile::Wire) {
                        wire_format.map(|f| f.precision_ns)
                    } else {
                        source.session.timestamp_resolution.wall_ns
                    },
                    ..source.session.timestamp_resolution
                },
                ..source.session.clone()
            },
            settings,
            sinks: Mutex::new(Vec::new()),
            counters: bus.counters.clone(),
            encoded_through: AtomicU64::new(source.session.first_sequence - 1),
            progress: Notify::new(),
            encoder,
            secrets,
            secrets_token,
        });
        let _ = bus.capture.set(capture.clone());
        let (stop, mut stopped) = watch::channel(false);
        let mut tasks = JoinSet::new();
        if let Some(Ok(source)) = native {
            let connections = source.connections.clone();
            let _ = bus.wire.set(connections);
            let capture = capture.clone();
            let stopped = stop.subscribe();
            tasks.spawn(async move {
                if let Err(reason) = source.run(stopped, &capture).await {
                    capture
                        .counters
                        .wire_source_errors
                        .fetch_add(1, Ordering::Relaxed);
                    capture.report_sink_errors(reason);
                    if let Encoder::Pcapng(format) = capture.encoder {
                        if let Ok(bytes) = format.source_limitation(&capture.session, reason) {
                            capture.control(bytes.into());
                        }
                    } else {
                        capture.close();
                    }
                }
            });
        }
        if let Some(path) = &capture.settings.file
            && let Ok(receiver) = capture.subscribe(Sink::File)
        {
            let path = path.clone();
            tasks.spawn(async move {
                match open_file(path).await {
                    Ok(file) => write_stream(file, receiver).await,
                    Err(()) => receiver.error("file_open_or_permissions_failed"),
                }
            });
        }
        if capture.settings.stdout
            && let Ok(receiver) = capture.subscribe(Sink::Stdout)
        {
            tasks.spawn(async move {
                match stdout::open() {
                    Ok(writer) => write_stream(writer, receiver).await,
                    Err(_) => receiver.error("stdout_open_or_nonblocking_failed"),
                }
            });
        }
        if let Some(listener) = tcp_listener {
            let capture = capture.clone();
            let mut stop = stop.subscribe();
            tasks.spawn(async move {
                let listener = match listener {
                    Ok(bound)=>bound.listener,
                    Err(_)=>{report(&capture.counters,Sink::Tcp,"tcp_bind_failed");return;}
                };
                let mut clients = JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = stop.changed()=>break,
                        Some(_) = clients.join_next(), if !clients.is_empty()=>{},
                        result=listener.accept()=>match result {
                            Ok((socket,_))=>if let Ok(receiver) = capture.subscribe(Sink::Tcp) {clients.spawn(write_stream(socket,receiver));},
                            Err(_)=>{report(&capture.counters,Sink::Tcp,"tcp_accept_failed");break;}
                        }
                    }
                }
                while clients.join_next().await.is_some() {}
            });
        }
        let weak = Arc::downgrade(&capture);
        tasks.spawn(async move {
            loop {
                let record = tokio::select! { biased; _=stopped.changed()=>break, record=source.recv()=>record };
                let Some(record) = record else {break;};
                let Some(capture) = weak.upgrade() else {return;};
                let limit = capture.settings.queue.bytes.saturating_sub(compat::CONTROL_BYTES+128);
                let base_limit=limit.saturating_sub(if capture.secrets.is_some() && matches!(record.as_ref(),Record::Observation(o) if o.packet.is_some()){compat::CONTROL_BYTES/2}else{0});
                let encoded=capture.encoder.encode(&record,base_limit).ok().map(Arc::from);
                let secret_encoded=capture.encode_secrets(&record,&encoded,limit).await;
                capture.dispatch(&record,encoded,secret_encoded);
            }
            if let Some(capture)=weak.upgrade(){capture.close();}
        });
        Some(Self {
            capture,
            stop,
            tasks,
        })
    }
    pub(crate) async fn stop(mut self) {
        if tokio::time::timeout(Duration::from_secs(2), self.capture.flush())
            .await
            .is_err()
        {
            self.capture
                .report_sink_errors("encoder_shutdown_incomplete");
        }
        let _ = self.stop.send(true);
        self.capture.close();
        if tokio::time::timeout(Duration::from_secs(3), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            self.capture.report_sink_errors("sink_shutdown_incomplete");
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
    }
}
async fn open_file(path: PathBuf) -> Result<tokio::fs::File, ()> {
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false) // Set owner-only permissions before truncating existing content.
        .mode(0o600)
        .open(path)
        .await
        .map_err(|_| ())?;
    // DOC: docs/native-observations.md
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .await
        .map_err(|_| ())?;
    file.set_len(0).await.map_err(|_| ())?;
    Ok(file)
}
pub(crate) async fn write_stream(mut stream: impl AsyncWrite + Unpin, mut receiver: Receiver) {
    while let Some(delivery) = receiver.recv().await {
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            // Bound the async file/stdout staging copy as well as the retained
            // queue batch. Flush publishes even a header-only stdout session.
            for chunk in delivery.bytes.chunks(16 * 1024) {
                stream.write_all(chunk).await?;
            }
            stream.flush().await
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            receiver.error("write_failed_or_timed_out");
            return;
        }
        receiver.written(delivery.bytes.len());
    }
    if !matches!(
        tokio::time::timeout(Duration::from_secs(1), stream.shutdown()).await,
        Ok(Ok(()))
    ) {
        receiver.error("flush_failed_or_timed_out");
    }
}
