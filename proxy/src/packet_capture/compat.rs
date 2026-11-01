//! Classic PCAP reconstruction. These packets never return to the observation bus.
use std::io::Write;

use serde::Serialize;
use serde_json::json;

use crate::observations::{
    Direction, Layer, Observation, Point, Record, Session, State, Timestamp, Transport,
};

pub(super) const CONTROL_BYTES: usize = 32 * 1024;
pub(super) const PAYLOAD_BYTES: usize = 1200;
const MAGIC: &[u8] = b"SAFEYOLO-PCAP-COMPAT/1\n";
const METADATA_BYTES: usize = 8192;

pub(crate) mod read;

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > METADATA_BYTES.saturating_sub(MAGIC.len() + self.0.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.0.reserve_exact(bytes.len());
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn metadata(value: &impl Serialize) -> Result<Vec<u8>, ()> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(json_bytes(value)?);
    Ok(bytes)
}
pub(super) fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, ()> {
    let mut bytes = Bounded(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(|_| ())?;
    Ok(bytes.0)
}
fn now() -> Timestamp {
    Timestamp {
        wall_unix_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())
            .map_or(0, |d| d.as_nanos() as i128),
        monotonic_ns: 0,
    }
}
pub(super) fn session(session: &Session, sink: &str, limit: usize) -> Result<Vec<u8>, ()> {
    let metadata = metadata(
        &json!({"type":"session", "sink":sink, "profile":"pcap:compat", "schema_version":1,
        "representation":"reconstructed", "pcap_timestamp_unit":"nanoseconds", "session":session}),
    )?;
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b23c4du32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    packet(&mut out, &metadata, 17, &[0; 32], 0, 0, now(), limit)?;
    Ok(out)
}
pub(super) fn loss(
    session: &Session,
    sink: &str,
    first: u64,
    last: u64,
    reason: &str,
) -> Result<Vec<u8>, ()> {
    let bytes = metadata(
        &json!({"type":"sink_gap", "sink":sink, "sink_session_id":session.sink_session_id,
        "instance_id":session.instance_id,"runtime_id":session.runtime_id,
        "first_sequence":first,"last_sequence":last,"count":last-first+1,"reason":reason}),
    )?;
    let mut out = Vec::new();
    packet(&mut out, &bytes, 17, &[0; 32], 0, 0, now(), CONTROL_BYTES)?;
    Ok(out)
}
pub(super) fn encode(record: &Record, limit: usize) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let Record::Observation(o) = record else {
        let bytes = metadata(record)?;
        packet(&mut out, &bytes, 17, &[0; 32], 0, 0, now(), limit)?;
        return Ok(out);
    };
    #[derive(Serialize)]
    struct Context<'a> {
        instance_id: &'a str,
        runtime_id: &'a str,
        connection_id: &'a str,
        observation_point: Point,
        observation_layer: Layer,
        transport: Transport,
        direction: Direction,
    }
    let context = Context {
        instance_id: &o.id.instance_id,
        runtime_id: &o.id.runtime_id,
        connection_id: &o.connection_id,
        observation_point: o.point,
        observation_layer: o.layer,
        transport: o.transport,
        direction: o.direction,
    };
    let key = metadata(&context)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &key);
    let hash: &[u8; 32] = digest.as_ref().try_into().map_err(|_| ())?;
    let id: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    // Repeat bounded context with each source observation. This makes every
    // accepted batch self-contained after a sink joins or loses an earlier batch,
    // without an unbounded remembered-flow table or historical payload replay.
    #[derive(Serialize)]
    struct Metadata<'a> {
        #[serde(rename = "type")]
        kind: &'static str,
        compat_flow_id: &'a str,
        representation: &'static str,
        source: &'a Context<'a>,
        observation: &'a Observation,
        payload_truncated: bool,
    }
    let bytes = metadata(&Metadata {
        kind: "observation",
        compat_flow_id: &id,
        representation: "reconstructed",
        source: &context,
        observation: o,
        payload_truncated: o.observed_length.is_some_and(|n| n > o.captured_length),
    })?;
    // Reserve once for the complete batch; refuse oversized output before allocating.
    let payload_len = o.payload.as_ref().map_or(0, |payload| payload.len());
    let segments = payload_len.div_ceil(PAYLOAD_BYTES);
    let required = (16 + 14 + 20 + 8 + bytes.len())
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(segments.checked_mul(16 + 14 + 20 + 20)?))
        .ok_or(())?;
    if required > limit {
        return Err(());
    }
    out.reserve_exact(required);
    packet(&mut out, &bytes, 17, hash, 0, 0, o.timestamp, limit)?;
    if let Some(payload) = &o.payload {
        let offset = o.stream_offset.ok_or(())?;
        for (index, segment) in payload.chunks(PAYLOAD_BYTES).enumerate() {
            let end = (index + 1) * PAYLOAD_BYTES >= payload.len();
            packet(
                &mut out,
                segment,
                6,
                hash,
                offset.wrapping_add((index * PAYLOAD_BYTES) as u64) as u32,
                if end { 0x18 } else { 0x10 },
                o.timestamp,
                limit,
            )?;
        }
    }
    if o.direction != Direction::Both {
        let flag = match o.state {
            State::Eof | State::HalfClose => 0x11,
            State::ReadError | State::WriteError | State::Dropped => 0x14,
            _ => 0,
        };
        if flag != 0 {
            packet(
                &mut out,
                &[],
                6,
                hash,
                o.stream_offset.unwrap_or(0) as u32,
                flag,
                o.timestamp,
                limit,
            )?;
        }
    }
    Ok(out)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
#[allow(clippy::too_many_arguments)]
fn packet(
    out: &mut Vec<u8>,
    payload: &[u8],
    protocol: u8,
    hash: &[u8; 32],
    sequence: u32,
    flags: u8,
    timestamp: Timestamp,
    limit: usize,
) -> Result<(), ()> {
    let transport_len = if protocol == 6 { 20 } else { 8 };
    let packet_len = 14 + 20 + transport_len + payload.len();
    let seconds: u32 = timestamp
        .wall_unix_ns
        .div_euclid(1_000_000_000)
        .try_into()
        .map_err(|_| ())?;
    let nanos = timestamp.wall_unix_ns.rem_euclid(1_000_000_000) as u32;
    if packet_len > 65535 || 16 + packet_len > limit.saturating_sub(out.len()) {
        return Err(());
    }
    out.reserve_exact(16 + packet_len);
    out.extend_from_slice(&seconds.to_le_bytes());
    out.extend_from_slice(&nanos.to_le_bytes());
    out.extend_from_slice(&(packet_len as u32).to_le_bytes());
    out.extend_from_slice(&(packet_len as u32).to_le_bytes());
    let start = out.len();
    // SafeYolo locally-administered namespace 02:53:59; both endpoints synthetic.
    out.extend_from_slice(&[0x02, 0x53, 0x59, hash[3], hash[4], hash[5]]);
    out.extend_from_slice(&[0x02, 0x53, 0x59, hash[0], hash[1], hash[2]]);
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    let ip_start = out.len();
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + transport_len + payload.len()) as u16).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&[192, 0, 2, hash[6] % 254 + 1]);
    ip[16..20].copy_from_slice(&[198, 51, 100, hash[7] % 254 + 1]);
    let check = checksum(&ip);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    out.extend_from_slice(&ip);
    let transport_start = out.len();
    out.extend_from_slice(&(1024 + (u16::from_be_bytes([hash[8], hash[9]]) % 64512)).to_be_bytes());
    out.extend_from_slice(
        &(1024 + (u16::from_be_bytes([hash[10], hash[11]]) % 64512)).to_be_bytes(),
    );
    if protocol == 6 {
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    } else {
        out.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
    }
    out.extend_from_slice(payload);
    // Synthetic pseudo-header checksum; no source measurement consumes it.
    let mut pseudo = Vec::with_capacity(12 + transport_len + payload.len());
    pseudo.extend_from_slice(&out[ip_start + 12..ip_start + 20]);
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&((transport_len + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&out[transport_start..]);
    let check = checksum(&pseudo);
    let check = if check == 0 { 65535 } else { check };
    let at = transport_start + if protocol == 6 { 16 } else { 6 };
    out[at..at + 2].copy_from_slice(&check.to_be_bytes());
    debug_assert_eq!(out.len() - start, packet_len);
    Ok(())
}
