//! Native libpcap acquisition. Only registered upstream socket tuples become
//! observations. Export listeners and their accepted sockets never register.
use super::{Packet, Record};
use crate::observations::{Direction, Limits, Source as ObservationSource};
use std::{
    collections::HashMap,
    ffi::{CString, c_char, c_int, c_uint, c_void},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;

#[derive(Clone, Copy)]
pub(super) struct Format {
    pub link_type: u32,
    pub precision_ns: u64,
}
impl Format {
    pub(super) fn header(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        let magic: u32 = if self.precision_ns == 1 {
            0xa1b23c4d
        } else {
            0xa1b2c3d4
        };
        out.extend(magic.to_le_bytes());
        out.extend(2u16.to_le_bytes());
        out.extend(4u16.to_le_bytes());
        out.extend([0; 8]);
        out.extend(SNAPLEN.to_le_bytes());
        out.extend(self.link_type.to_le_bytes());
        out
    }
    pub(super) fn encode(self, record: &Record, limit: usize) -> Result<Vec<u8>, ()> {
        let Record::Observation(o) = record else {
            return Err(());
        };
        let Some(packet) = o.packet else {
            return Ok(Vec::new());
        };
        if packet.link_type != self.link_type || packet.precision_ns != self.precision_ns {
            return Err(());
        }
        let bytes = o.payload.as_deref().ok_or(())?;
        if bytes.len() + 16 > limit || bytes.len() > packet.original_length as usize {
            return Err(());
        }
        let seconds =
            u32::try_from(o.timestamp.wall_unix_ns.div_euclid(1_000_000_000)).map_err(|_| ())?;
        let fraction =
            (o.timestamp.wall_unix_ns.rem_euclid(1_000_000_000) / self.precision_ns as i128) as u32;
        let mut out = Vec::with_capacity(bytes.len() + 16);
        out.extend(seconds.to_le_bytes());
        out.extend(fraction.to_le_bytes());
        out.extend((bytes.len() as u32).to_le_bytes());
        out.extend(packet.original_length.to_le_bytes());
        out.extend_from_slice(bytes);
        Ok(out)
    }
}

type Tuple = (SocketAddr, SocketAddr);
pub(crate) struct Connections {
    owned: Mutex<HashMap<Tuple, Arc<Owned>>>,
    capacity: usize,
    active: AtomicBool,
    counters: Arc<crate::observations::Counters>,
}
struct Owned {
    source: Arc<ObservationSource>,
    start_ns: u64,
    closed_ns: AtomicU64,
}
pub(crate) struct Ownership(Arc<Owned>);
fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos().min(u64::MAX as u128) as u64)
}
impl Drop for Ownership {
    fn drop(&mut self) {
        // Retain correlation briefly for packets already in the kernel buffer.
        // Timestamp bounds prevent a reused tuple from admitting later traffic.
        self.0.closed_ns.store(wall_ns(), Ordering::Release);
    }
}
impl Connections {
    pub(crate) fn register(
        self: &Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        source: Arc<ObservationSource>,
        start_ns: u64,
    ) -> Option<Ownership> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let tuple = (canonical(local), canonical(remote));
        if let Ok(mut owned) = self.owned.try_lock() {
            if owned.len() < self.capacity
                && owned
                    .get(&tuple)
                    .is_none_or(|entry| entry.closed_ns.load(Ordering::Acquire) != 0)
            {
                let entry = Arc::new(Owned {
                    source,
                    start_ns,
                    closed_ns: AtomicU64::new(0),
                });
                owned.insert(tuple, entry.clone());
                return Some(Ownership(entry));
            }
        }
        self.counters
            .wire_correlation_missed
            .fetch_add(1, Ordering::Relaxed);
        None
    }
    fn lookup(
        &self,
        tuple: Tuple,
        timestamp_ns: i128,
    ) -> Option<(Arc<ObservationSource>, Direction)> {
        let owned = self.owned.lock().unwrap_or_else(|e| e.into_inner());
        let eligible = |entry: &Arc<Owned>| {
            let closed = entry.closed_ns.load(Ordering::Acquire);
            timestamp_ns >= entry.start_ns as i128
                && (closed == 0 || timestamp_ns <= closed as i128)
        };
        if let Some(entry) = owned.get(&tuple).filter(|entry| eligible(entry)) {
            return Some((entry.source.clone(), Direction::FromProxy));
        }
        owned
            .get(&(tuple.1, tuple.0))
            .filter(|entry| eligible(entry))
            .map(|entry| (entry.source.clone(), Direction::ToProxy))
    }
}
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}
const SNAPLEN: u32 = 65599;

// A small dynamic binding keeps libpcap an optional host facility. Missing
// libraries, permissions and unsupported devices affect wire capture alone.
#[repr(C)]
struct Header {
    time: libc::timeval,
    captured: c_uint,
    original: c_uint,
}
#[repr(C)]
struct Program {
    length: c_uint,
    instructions: *mut c_void,
}
struct Api {
    library: *mut c_void,
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void,
    activate: unsafe extern "C" fn(*mut c_void) -> c_int,
    close: unsafe extern "C" fn(*mut c_void),
    snaplen: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    promisc: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    timeout: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    buffer: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    immediate: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    set_precision: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    precision: unsafe extern "C" fn(*mut c_void) -> c_int,
    datalink: unsafe extern "C" fn(*mut c_void) -> c_int,
    compile: unsafe extern "C" fn(*mut c_void, *mut Program, *const c_char, c_int, c_uint) -> c_int,
    filter: unsafe extern "C" fn(*mut c_void, *mut Program) -> c_int,
    freecode: unsafe extern "C" fn(*mut Program),
    nonblock: unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int,
    next: unsafe extern "C" fn(*mut c_void, *mut *const Header, *mut *const u8) -> c_int,
    stats: unsafe extern "C" fn(*mut c_void, *mut c_uint) -> c_int,
}
impl Drop for Api {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.library);
        }
    }
}
impl Api {
    unsafe fn load() -> Result<Self, &'static str> {
        #[cfg(target_os = "macos")]
        let names = [c"/usr/lib/libpcap.A.dylib"];
        #[cfg(not(target_os = "macos"))]
        let names = [c"libpcap.so.1", c"libpcap.so.0.8", c"libpcap.so"];
        let library = names
            .iter()
            .find_map(|name| {
                let p = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                (!p.is_null()).then_some(p)
            })
            .ok_or("pcap_library_unavailable")?;
        macro_rules! symbol {
            ($name:literal, $t:ty) => {{
                let p = unsafe { libc::dlsym(library, concat!($name, "\0").as_ptr().cast()) };
                if p.is_null() {
                    unsafe {
                        libc::dlclose(library);
                    }
                    return Err("pcap_api_unavailable");
                }
                unsafe { std::mem::transmute::<*mut c_void, $t>(p) }
            }};
        }
        Ok(Self {
            library,
            create: symbol!(
                "pcap_create",
                unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void
            ),
            activate: symbol!("pcap_activate", unsafe extern "C" fn(*mut c_void) -> c_int),
            close: symbol!("pcap_close", unsafe extern "C" fn(*mut c_void)),
            snaplen: symbol!(
                "pcap_set_snaplen",
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int
            ),
            promisc: symbol!(
                "pcap_set_promisc",
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int
            ),
            timeout: symbol!(
                "pcap_set_timeout",
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int
            ),
            buffer: symbol!(
                "pcap_set_buffer_size",
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int
            ),
            immediate: symbol!(
                "pcap_set_immediate_mode",
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int
            ),
            set_precision: symbol!(
                "pcap_set_tstamp_precision",
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int
            ),
            precision: symbol!(
                "pcap_get_tstamp_precision",
                unsafe extern "C" fn(*mut c_void) -> c_int
            ),
            datalink: symbol!("pcap_datalink", unsafe extern "C" fn(*mut c_void) -> c_int),
            compile: symbol!(
                "pcap_compile",
                unsafe extern "C" fn(
                    *mut c_void,
                    *mut Program,
                    *const c_char,
                    c_int,
                    c_uint,
                ) -> c_int
            ),
            filter: symbol!(
                "pcap_setfilter",
                unsafe extern "C" fn(*mut c_void, *mut Program) -> c_int
            ),
            freecode: symbol!("pcap_freecode", unsafe extern "C" fn(*mut Program)),
            nonblock: symbol!(
                "pcap_setnonblock",
                unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int
            ),
            next: symbol!(
                "pcap_next_ex",
                unsafe extern "C" fn(*mut c_void, *mut *const Header, *mut *const u8) -> c_int
            ),
            stats: symbol!(
                "pcap_stats",
                unsafe extern "C" fn(*mut c_void, *mut c_uint) -> c_int
            ),
        })
    }
}
pub(super) struct Source {
    api: Api,
    handle: *mut c_void,
    pub format: Format,
    pub connections: Arc<Connections>,
    previous_stats: [u32; 3],
}
// The handle and library have a single owner. Calls are serialized by the
// acquisition task; moving that task between executor threads is safe.
unsafe impl Send for Source {}
impl Drop for Source {
    fn drop(&mut self) {
        self.connections.active.store(false, Ordering::Release);
        self.connections
            .owned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        unsafe {
            (self.api.close)(self.handle);
        }
    }
}
impl Source {
    pub(super) fn open(
        interface: &str,
        limits: Limits,
        counters: Arc<crate::observations::Counters>,
    ) -> Result<Self, &'static str> {
        let interface = CString::new(interface).map_err(|_| "pcap_interface_invalid")?;
        let api = unsafe { Api::load()? };
        let mut error = [0 as c_char; 256];
        let handle = unsafe { (api.create)(interface.as_ptr(), error.as_mut_ptr()) };
        if handle.is_null() {
            return Err("pcap_create_failed");
        }
        let mut source = Self {
            api,
            handle,
            format: Format {
                link_type: 0,
                precision_ns: 1000,
            },
            previous_stats: [0; 3],
            connections: Arc::new(Connections {
                owned: Mutex::default(),
                capacity: limits.items.min(limits.bytes / 4096),
                active: AtomicBool::new(true),
                counters,
            }),
        };
        // SAFETY: libpcap owns the live handle; all argument buffers have the
        // ABI layout above and remain valid for each call. Error text is private.
        unsafe {
            for (set, value) in [
                (source.api.snaplen, SNAPLEN as c_int),
                (source.api.promisc, 0),
                (source.api.timeout, 10),
                (source.api.immediate, 1),
                (
                    source.api.buffer,
                    limits.bytes.clamp(65536, c_int::MAX as usize) as c_int,
                ),
            ] {
                if set(handle, value) != 0 {
                    return Err("pcap_configuration_failed");
                }
            }
            // Unsupported nanoseconds leaves libpcap's actual microsecond mode.
            (source.api.set_precision)(handle, 1);
            if (source.api.activate)(handle) < 0 {
                return Err("pcap_acquisition_unavailable");
            }
            source.format.precision_ns = match (source.api.precision)(handle) {
                0 => 1000,
                1 => 1,
                _ => return Err("pcap_precision_unavailable"),
            };
            source.format.link_type = match (source.api.datalink)(handle) {
                0 => 0,
                1 => 1,
                12 => 101,
                108 => 108,
                113 => 113,
                276 => 276,
                _ => return Err("pcap_link_type_unavailable"),
            };
            let mut program = Program {
                length: 0,
                instructions: std::ptr::null_mut(),
            };
            if (source.api.compile)(
                handle,
                &mut program,
                c"tcp or (ip6 protochain 6)".as_ptr(),
                1,
                u32::MAX,
            ) != 0
            {
                return Err("pcap_filter_failed");
            }
            let status = (source.api.filter)(handle, &mut program);
            (source.api.freecode)(&mut program);
            if status != 0 {
                return Err("pcap_filter_failed");
            }
            if (source.api.nonblock)(handle, 1, error.as_mut_ptr()) != 0 {
                return Err("pcap_nonblocking_unavailable");
            }
        }
        Ok(source)
    }
    pub(super) async fn run(self, mut stopped: watch::Receiver<bool>) -> Result<(), &'static str> {
        let mut tick = tokio::time::interval(Duration::from_millis(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut n = 0u32;
        loop {
            tokio::select! { biased; _=stopped.changed()=>break, _=tick.tick()=>{} }
            // Bound work per turn under unrelated traffic or packet floods.
            for _ in 0..64 {
                let mut header = std::ptr::null();
                let mut data = std::ptr::null();
                let status = unsafe { (self.api.next)(self.handle, &mut header, &mut data) };
                match status {
                    0 => break,
                    1 => {}
                    _ => return Err("pcap_read_failed"),
                }
                if header.is_null() || data.is_null() {
                    return Err("pcap_record_invalid");
                }
                let h = unsafe { &*header };
                if h.captured > SNAPLEN || h.captured > h.original {
                    return Err("pcap_record_invalid");
                }
                // The slice is valid only until the next libpcap read. Never
                // copy unregistered host traffic into the observation plane.
                let bytes = unsafe { std::slice::from_raw_parts(data, h.captured as usize) };
                let Some(tuple) = tcp_tuple(self.format.link_type, bytes) else {
                    continue;
                };
                let Some((source, direction)) = self.connections.lookup(
                    tuple,
                    h.time.tv_sec as i128 * 1_000_000_000
                        + h.time.tv_usec as i128 * self.format.precision_ns as i128,
                ) else {
                    continue;
                };
                let fraction = h.time.tv_usec as i128;
                if fraction < 0 || fraction * self.format.precision_ns as i128 >= 1_000_000_000 {
                    return Err("pcap_timestamp_invalid");
                }
                source.packet(
                    Packet {
                        link_type: self.format.link_type,
                        original_length: h.original,
                        precision_ns: self.format.precision_ns,
                    },
                    h.time.tv_sec as i128 * 1_000_000_000
                        + fraction * self.format.precision_ns as i128,
                    direction,
                    bytes,
                );
            }
            let cutoff = wall_ns().saturating_sub(1_000_000_000);
            self.connections
                .owned
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, entry| {
                    let closed = entry.closed_ns.load(Ordering::Acquire);
                    closed == 0 || closed > cutoff
                });
            n = n.wrapping_add(1);
            if n % 500 == 0 {
                self.statistics();
            }
        }
        self.statistics();
        Ok(())
    }
    fn statistics(&mut self) {
        let mut stats = [0u32; 16];
        let status = unsafe { (self.api.stats)(self.handle, stats.as_mut_ptr()) };
        if status == 0 {
            let counters = &self.connections.counters;
            for (i, counter) in [
                &counters.wire_received,
                &counters.wire_kernel_dropped,
                &counters.wire_interface_dropped,
            ]
            .into_iter()
            .enumerate()
            {
                counter.fetch_add(
                    stats[i].wrapping_sub(self.previous_stats[i]) as u64,
                    Ordering::Relaxed,
                );
                self.previous_stats[i] = stats[i];
            }
        } else {
            self.connections
                .counters
                .wire_source_errors
                .fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "Packet capture source error layer=wire_packet reason=pcap_statistics_unavailable"
            );
        }
    }
}

fn tcp_tuple(link: u32, bytes: &[u8]) -> Option<Tuple> {
    let mut at = match link {
        0 | 108 => 4,
        1 => {
            let mut at = 14;
            let mut protocol = u16::from_be_bytes(bytes.get(12..14)?.try_into().ok()?);
            for _ in 0..2 {
                if !matches!(protocol, 0x8100 | 0x88a8) {
                    break;
                }
                protocol = u16::from_be_bytes(bytes.get(at + 2..at + 4)?.try_into().ok()?);
                at += 4;
            }
            if !matches!(protocol, 0x0800 | 0x86dd) {
                return None;
            }
            at
        }
        101 => 0,
        113 => 16,
        276 => 20,
        _ => return None,
    };
    let (src, dst) = match bytes.get(at)? >> 4 {
        4 => {
            let ip = bytes.get(at..at + 20)?;
            let ihl = (ip[0] & 15) as usize * 4;
            if ihl < 20 || ip[9] != 6 || u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
                return None;
            }
            at += ihl;
            (
                IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
                IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
            )
        }
        6 => {
            let ip = bytes.get(at..at + 40)?;
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?);
            let mut next = ip[6];
            at += 40;
            for _ in 0..8 {
                if next == 6 {
                    break;
                }
                let extension = bytes.get(at..at + 8)?;
                let length = match next {
                    0 | 43 | 60 => (extension[1] as usize + 1) * 8,
                    44 => {
                        if u16::from_be_bytes([extension[2], extension[3]]) & 0xfff8 != 0 {
                            return None;
                        }
                        8
                    }
                    51 => (extension[1] as usize + 2) * 4,
                    _ => return None,
                };
                next = extension[0];
                at += length;
            }
            if next != 6 {
                return None;
            }
            (
                IpAddr::V6(src).to_canonical(),
                IpAddr::V6(dst).to_canonical(),
            )
        }
        _ => return None,
    };
    let ports = bytes.get(at..at + 4)?;
    Some((
        SocketAddr::new(src, u16::from_be_bytes([ports[0], ports[1]])),
        SocketAddr::new(dst, u16::from_be_bytes([ports[2], ports[3]])),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observations::{ConsumerKind, Layer, ObservationBus, Point, Transport};
    fn source(bus: &Arc<ObservationBus>) -> Arc<ObservationSource> {
        ObservationSource::new(
            bus.clone(),
            &crate::ConnectionIdentity {
                agent_id: "owned".into(),
                connection_id: "ingress".into(),
                source_id: None,
                run: None,
            },
            "upstream",
            Point::Upstream,
            Layer::TransportStream,
            Transport::Tcp,
            None,
        )
    }
    fn connections(capacity: usize) -> Arc<Connections> {
        Arc::new(Connections {
            owned: Mutex::default(),
            capacity,
            active: AtomicBool::new(true),
            counters: Arc::default(),
        })
    }
    #[test]
    fn native_packet_scope_excludes_unowned_reverse_and_reused_tuples() {
        let bus = ObservationBus::new(
            "instance".into(),
            "runtime".into(),
            Limits::default(),
            Arc::default(),
        );
        let connections = connections(1);
        let local = "127.0.0.1:32000".parse().unwrap();
        let remote = "127.0.0.1:443".parse().unwrap();
        let ownership = connections
            .register(local, remote, source(&bus), 100)
            .unwrap();
        assert!(connections.lookup((local, remote), 99).is_none());
        assert_eq!(
            connections.lookup((local, remote), 101).unwrap().1,
            Direction::FromProxy
        );
        assert_eq!(
            connections.lookup((remote, local), 101).unwrap().1,
            Direction::ToProxy
        );
        assert!(
            connections
                .lookup(("127.0.0.1:32001".parse().unwrap(), remote), 101)
                .is_none()
        );
        assert!(
            connections
                .register(local, "127.0.0.1:444".parse().unwrap(), source(&bus), 100)
                .is_none()
        );
        assert_eq!(
            connections
                .counters
                .wire_correlation_missed
                .load(Ordering::Relaxed),
            1
        );
        drop(ownership);
        let end = connections.owned.lock().unwrap()[&(local, remote)]
            .closed_ns
            .load(Ordering::Acquire);
        assert!(
            connections
                .lookup((local, remote), end as i128 + 1)
                .is_none()
        );
        assert!(connections.lookup((local, remote), 101).is_some());
    }
    #[tokio::test]
    async fn wire_precision_and_bytes_survive_canonical_and_classic_encoding_without_transport_metrics()
     {
        for precision_ns in [1, 1000] {
            let bus = ObservationBus::with_payload(
                "instance".into(),
                "runtime".into(),
                Limits::default(),
                Arc::default(),
                vec![Layer::WirePacket],
            );
            let mut consumer = bus.subscribe(ConsumerKind::Capture, Limits::default());
            let wall = 1_791_234_567_123_456_000 + if precision_ns == 1 { 789 } else { 0 };
            let bytes = b"exact acquired bytes";
            let baseline = bus.counters.json()["behaviour"].clone();
            source(&bus).packet(
                Packet {
                    link_type: 0,
                    original_length: 100,
                    precision_ns,
                },
                wall,
                Direction::FromProxy,
                bytes,
            );
            let record = consumer.recv().await.unwrap();
            let Record::Observation(o) = record.as_ref() else {
                panic!()
            };
            assert_eq!(o.timestamp.wall_unix_ns, wall);
            assert_eq!(o.timestamp_resolution.wall_ns, Some(precision_ns));
            assert_eq!(o.payload.as_deref(), Some(bytes.as_slice()));
            assert_eq!(bus.counters.json()["behaviour"], baseline);
            assert_eq!(o.connection_id, "upstream");
            assert_eq!(o.agent.as_deref(), Some("owned"));
            let format = Format {
                link_type: 0,
                precision_ns,
            };
            let encoded = format.encode(&record, 4096).unwrap();
            assert_eq!(&encoded[16..], bytes);
            assert_eq!(u32::from_le_bytes(encoded[12..16].try_into().unwrap()), 100);
            assert_eq!(
                u32::from_le_bytes(encoded[4..8].try_into().unwrap()) as u64,
                wall.rem_euclid(1_000_000_000) as u64 / precision_ns
            );
            assert_eq!(
                format.header()[..4],
                if precision_ns == 1 {
                    0xa1b23c4du32
                } else {
                    0xa1b2c3d4u32
                }
                .to_le_bytes()
            );
            assert!(format.encode(&record, 20).is_err());
        }
    }
    #[test]
    fn bounded_ip_parsing_supports_native_link_types_and_refuses_fragments_without_ports() {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 1]);
        ip[20..24].copy_from_slice(&[0x80, 0, 1, 0xbb]);
        for (link, prefix) in [(0, 4), (108, 4), (1, 14), (101, 0), (113, 16), (276, 20)] {
            let mut bytes = vec![0u8; prefix];
            if link == 1 {
                bytes[12..14].copy_from_slice(&[8, 0]);
            }
            bytes.extend_from_slice(&ip);
            let tuple = tcp_tuple(link, &bytes).unwrap();
            assert_eq!(tuple.0, "127.0.0.1:32768".parse().unwrap());
            assert_eq!(tuple.1, "192.0.2.1:443".parse().unwrap());
            for end in 0..prefix + 24 {
                assert!(tcp_tuple(link, &bytes[..end]).is_none());
            }
        }
        ip[6] = 0;
        ip[7] = 1;
        assert!(tcp_tuple(101, &ip).is_none());
        let mut v6 = vec![0u8; 68];
        v6[0] = 0x60;
        v6[6] = 0;
        v6[23] = 1;
        v6[39] = 2;
        v6[40] = 6;
        v6[41] = 0;
        v6[48..52].copy_from_slice(&[0x80, 0, 1, 0xbb]);
        assert_eq!(
            tcp_tuple(101, &v6).unwrap().0,
            "[::1]:32768".parse().unwrap()
        );
    }
}

#[cfg(test)]
pub(super) fn tcp_tuple_for_test(link: u32, bytes: &[u8]) -> Option<Tuple> {
    tcp_tuple(link, bytes)
}
