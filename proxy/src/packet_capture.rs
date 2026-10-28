//! Explicit classic capture, shared encoding and bounded asynchronous delivery.
use crate::{
    Error,
    observations::{ConsumerKind, Layer, Limits, ObservationBus, Record, Session},
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
        Ok(())
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
            Profile::Pcapng => Some("pcapng_portable_encoder_unavailable"),
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
    wire: bool,
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
                    if self.inner.wire {
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
                    let bytes = compat::loss(
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
                        self.next = batch.last + 1;
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
    wire_format: Option<wire::Format>,
}
impl Capture {
    pub(crate) fn subscribe(&self, kind: Sink) -> Result<Receiver, ()> {
        // Serialize registration against dispatch; never replay historical batches.
        let mut sinks = self.sinks.lock().unwrap_or_else(|e| e.into_inner());
        let bus = self.bus.upgrade().ok_or(())?;
        if self.wire_format.is_some() && !bus.wire.get().is_some_and(|source| source.is_active()) {
            report(&self.counters, kind, "pcap_acquisition_unavailable");
            return Err(());
        }
        let first = bus.next_sequence();
        let session = Session {
            sink_session_id: uuid::Uuid::new_v4().to_string(),
            first_sequence: first,
            ..self.session.clone()
        };
        let bytes = if let Some(format) = self.wire_format {
            eprintln!("Packet capture session profile=pcap:wire sink={} session={} link_type={} precision_ns={}",kind.name(), serde_json::to_string(&session).map_err(|_| ())?,format.link_type,format.precision_ns);
            Ok(format.header())
        } else { compat::session(
            &session,
            kind.name(),
            self.settings
                .queue
                .bytes
                .saturating_sub(compat::CONTROL_BYTES),
        ) }
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
            wire: self.wire_format.is_some(),
        });
        sinks.retain(|sink| sink.strong_count() != 0);
        sinks.push(Arc::downgrade(&inner));
        Ok(Receiver {
            inner,
            next: first,
            initial: true,
        })
    }
    fn dispatch(&self, record: &Record, encoded: Option<Arc<[u8]>>) {
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
            let clipped;
            let encoded = if let Record::Gap(gap) = record
                && self.wire_format.is_none()
                && gap.first_sequence < sink.session.first_sequence
            {
                let mut gap = gap.clone();
                gap.first_sequence = sink.session.first_sequence;
                gap.count = gap.last_sequence - gap.first_sequence + 1;
                clipped = compat::encode(
                    &Record::Gap(gap),
                    sink.limits
                        .bytes
                        .saturating_sub(compat::CONTROL_BYTES + 128),
                )
                .ok()
                .map(Arc::from);
                &clipped
            } else {
                &encoded
            };
            if pending.closed {
                return true;
            }
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
                            .saturating_sub(compat::CONTROL_BYTES)
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
        let native =
            if matches!(settings.profile, Profile::Wire) && settings.unavailable().is_none() {
                Some(wire::Source::open(
                    settings.wire_interface.as_deref().unwrap(),
                    settings.queue,
                    bus.counters.clone(),
                ))
            } else {
                None
            };
        let unavailable = settings.unavailable().or_else(|| {
            native
                .as_ref()
                .and_then(|result| result.as_ref().err().copied())
        });
        if let Some(reason) = unavailable {
            if matches!(settings.profile, Profile::Wire) {
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
            return None;
        }
        let mut source = bus.subscribe(ConsumerKind::Capture, settings.queue);
        let capture = Arc::new(Capture {
            bus: Arc::downgrade(bus),
            tcp_endpoint: tcp_listener
                .as_ref()
                .and_then(|listener| listener.as_ref().ok())
                .map(|listener| listener.endpoint),
            session: Session {
                timestamp_resolution: crate::observations::Resolution {
                    wall_ns: native
                        .as_ref()
                        .and_then(|s| s.as_ref().ok())
                        .map_or(source.session.timestamp_resolution.wall_ns, |s| {
                            Some(s.format.precision_ns)
                        }),
                    ..source.session.timestamp_resolution
                },
                ..source.session.clone()
            },
            settings,
            sinks: Mutex::new(Vec::new()),
            counters: bus.counters.clone(),
            encoded_through: AtomicU64::new(source.session.first_sequence - 1),
            progress: Notify::new(),
            wire_format: native
                .as_ref()
                .and_then(|source| source.as_ref().ok())
                .map(|source| source.format),
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
                if let Err(reason) = source.run(stopped).await {
                    capture
                        .counters
                        .wire_source_errors
                        .fetch_add(1, Ordering::Relaxed);
                    capture.report_sink_errors(reason);
                    capture.close();
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
                let encoded = match capture.wire_format {
                    Some(format) => format.encode(&record, limit),
                    None => compat::encode(&record, limit),
                }.ok().map(Arc::from);
                capture.dispatch(&record,encoded);
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
