//! PCAPNG blocks shared by all capture transports. No packet reconstruction here.
use super::{compat, wire};
use crate::observations::{Record, Session};
use serde::Serialize;
use serde_json::json;

#[cfg(test)]
mod tests;

// An isolated test identifier. Never a release assignment or portable proof.
#[cfg(test)]
pub(super) const TEST_ENTERPRISE: Enterprise = Enterprise {
    number: u32::MAX,
    name: "isolated test only",
};

/// #862 supplies the confirmed IANA assignment and owning registry name here.
/// None keeps release-format output unavailable; test identifiers never enter it.
pub(super) const ENTERPRISE: Option<Enterprise> = None;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Enterprise {
    pub number: u32,
    pub name: &'static str,
}

#[derive(Clone, Copy)]
pub(super) struct Format {
    pub enterprise: Enterprise,
    pub wire: Option<wire::Format>,
    pub compatibility: bool,
    pub wire_unavailable: Option<&'static str>,
}

const COPYABLE: u32 = 0x00000bad;
const NONCOPYABLE: u32 = 0x40000bad;
const CUSTOM_STRING: u16 = 2988;
const SECTION_STRING: u16 = 19372;

fn pad(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
fn block(kind: u32, mut body: Vec<u8>, limit: usize) -> Result<Vec<u8>, ()> {
    pad(&mut body);
    let length = u32::try_from(body.len().checked_add(12).ok_or(())?).map_err(|_| ())?;
    if length as usize > limit {
        return Err(());
    }
    let mut out = Vec::with_capacity(length as usize);
    out.extend(kind.to_le_bytes());
    out.extend(length.to_le_bytes());
    out.extend(body);
    out.extend(length.to_le_bytes());
    Ok(out)
}
fn option(out: &mut Vec<u8>, code: u16, bytes: &[u8]) -> Result<(), ()> {
    out.extend(code.to_le_bytes());
    out.extend(u16::try_from(bytes.len()).map_err(|_| ())?.to_le_bytes());
    out.extend_from_slice(bytes);
    pad(out);
    Ok(())
}
fn timestamp(out: &mut Vec<u8>, ns: i128, precision: u64) -> Result<(), ()> {
    let ticks = u64::try_from(ns.div_euclid(precision as i128)).map_err(|_| ())?;
    out.extend(((ticks >> 32) as u32).to_le_bytes());
    out.extend((ticks as u32).to_le_bytes());
    Ok(())
}
impl Format {
    fn custom_option(
        &self,
        out: &mut Vec<u8>,
        code: u16,
        value: &impl Serialize,
    ) -> Result<(), ()> {
        let mut bytes = self.enterprise.number.to_le_bytes().to_vec();
        bytes.extend(compat::json_bytes(value)?);
        option(out, code, &bytes)
    }
    fn custom(
        &self,
        kind: u32,
        value: &impl Serialize,
        payload: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, ()> {
        let json = compat::json_bytes(value)?;
        if json.len().saturating_add(payload.len()).saturating_add(28) > limit {
            return Err(());
        }
        let mut body = self.enterprise.number.to_le_bytes().to_vec();
        body.extend(*b"SYOB");
        body.extend((json.len() as u32).to_le_bytes());
        body.extend(u32::try_from(payload.len()).map_err(|_| ())?.to_le_bytes());
        body.extend(json);
        body.extend_from_slice(payload);
        block(kind, body, limit)
    }
    pub(super) fn session(
        &self,
        session: &Session,
        sink: &str,
        limit: usize,
    ) -> Result<Vec<u8>, ()> {
        let mut body = 0x1a2b3c4du32.to_le_bytes().to_vec();
        body.extend(1u16.to_le_bytes());
        body.extend(0u16.to_le_bytes());
        body.extend((-1i64).to_le_bytes());
        option(&mut body, 4, b"SafeYolo")?; // shb_userappl
        let description = json!({"schema_version":1,"profile":"pcapng","session":session,
            "enterprise_name":self.enterprise.name,"sink":sink,
            "wire_interface":self.wire.map(|_|0),"wire_unavailable":self.wire_unavailable,
            "compat_interface":self.compatibility.then_some(u32::from(self.wire.is_some()))});
        // Interface IDs and the starting sequence describe this particular section.
        self.custom_option(&mut body, SECTION_STRING, &description)?;
        option(&mut body, 0, &[])?;
        let mut out = block(0x0a0d0d0a, body, limit)?;
        if let Some(wire) = self.wire {
            out.extend(self.interface(
                wire.link_type,
                wire.precision_ns,
                "SafeYolo genuine upstream packets",
                limit.saturating_sub(out.len()),
            )?);
        }
        if self.compatibility {
            out.extend(self.interface(
                1,
                1,
                "SafeYolo reconstructed pcap:compat; synthetic Ethernet/IP/TCP",
                limit.saturating_sub(out.len()),
            )?);
        }
        out.extend(self.custom(
            NONCOPYABLE,
            &json!({"schema_version":1,"type":"section","section":description}),
            &[],
            limit.saturating_sub(out.len()),
        )?);
        Ok(out)
    }
    fn interface(
        &self,
        link: u32,
        precision: u64,
        name: &str,
        limit: usize,
    ) -> Result<Vec<u8>, ()> {
        let mut body = u16::try_from(link).map_err(|_| ())?.to_le_bytes().to_vec();
        body.extend([0; 2]);
        body.extend(65599u32.to_le_bytes());
        option(&mut body, 2, name.as_bytes())?;
        option(
            &mut body,
            9,
            &[match precision {
                1 => 9,
                1000 => 6,
                _ => return Err(()),
            }],
        )?;
        option(&mut body, 0, &[])?;
        block(1, body, limit)
    }
    #[allow(clippy::too_many_arguments)]
    fn packet(
        &self,
        interface: u32,
        ns: i128,
        precision: u64,
        original: u32,
        bytes: &[u8],
        record: Option<&Record>,
        limit: usize,
    ) -> Result<Vec<u8>, ()> {
        if bytes.len().saturating_add(36) > limit || bytes.len() > original as usize {
            return Err(());
        }
        let mut body = interface.to_le_bytes().to_vec();
        timestamp(&mut body, ns, precision)?;
        body.extend((bytes.len() as u32).to_le_bytes());
        body.extend(original.to_le_bytes());
        body.extend_from_slice(bytes);
        pad(&mut body);
        if let Some(record) = record {
            // Namespace/lineage are self-contained and survive interface renumbering.
            self.custom_option(
                &mut body,
                CUSTOM_STRING,
                &json!({"schema_version":1,"observation":record}),
            )?;
            option(&mut body, 0, &[])?;
        }
        block(6, body, limit)
    }
    pub(super) fn encode(&self, record: &Record, limit: usize) -> Result<Vec<u8>, ()> {
        if let Record::Observation(o) = record
            && let Some(packet) = o.packet
        {
            let wire = self.wire.ok_or(())?;
            if wire.link_type != packet.link_type || wire.precision_ns != packet.precision_ns {
                return Err(());
            }
            return self.packet(
                0,
                o.timestamp.wall_unix_ns,
                packet.precision_ns,
                packet.original_length,
                o.payload.as_deref().unwrap_or(&[]),
                Some(record),
                limit,
            );
        }
        let payload = match record {
            Record::Observation(o) => o.payload.as_deref().unwrap_or(&[]),
            _ => &[],
        };
        let mut metadata = json!({"schema_version":1,"type":"canonical","source":record,
            "compatibility_requested":self.compatibility,"compatibility_included":false});
        let mut out = self.custom(COPYABLE, &metadata, payload, limit)?;
        if self.compatibility
            && let Ok(projected) =
                self.compatibility_packets(record, limit.saturating_sub(out.len()))
        {
            metadata["compatibility_included"] = json!(true);
            out = self.custom(COPYABLE, &metadata, payload, limit)?;
            out.extend(projected);
        }
        Ok(out)
    }
    fn compatibility_packets(&self, record: &Record, limit: usize) -> Result<Vec<u8>, ()> {
        let packets = compat::encode(record, limit)?;
        let mut out = Vec::new();
        let mut at = 0;
        while at < packets.len() {
            let header = packets.get(at..at + 16).ok_or(())?;
            let word = |n| u32::from_le_bytes(header[n..n + 4].try_into().unwrap());
            let ns = word(0) as i128 * 1_000_000_000 + word(4) as i128;
            let len = word(8) as usize;
            let bytes = packets.get(at + 16..at + 16 + len).ok_or(())?;
            out.extend(self.packet(
                u32::from(self.wire.is_some()),
                ns,
                1,
                word(12),
                bytes,
                None,
                limit.saturating_sub(out.len()),
            )?);
            at += 16 + len;
        }
        Ok(out)
    }
    pub(super) fn loss(
        &self,
        session: &Session,
        sink: &str,
        first: u64,
        last: u64,
        reason: &str,
    ) -> Result<Vec<u8>, ()> {
        self.custom(
            COPYABLE,
            &json!({"schema_version":1,"type":"sink_gap","instance_id":session.instance_id,
            "runtime_id":session.runtime_id,"sink_session_id":session.sink_session_id,"sink":sink,
            "first_sequence":first,"last_sequence":last,"count":last-first+1,"reason":reason}),
            &[],
            compat::CONTROL_BYTES - 128,
        )
    }
    pub(super) fn limitation(
        &self,
        record: &Record,
        reason: &str,
        limit: usize,
    ) -> Result<Vec<u8>, ()> {
        let Record::Observation(o) = record else {
            return Ok(Vec::new());
        };
        self.custom(COPYABLE, &json!({"schema_version":1,"type":"decryption_limitation","observation_id":o.id,"reason":reason}), &[], limit)
    }
    pub(super) fn source_limitation(&self, session: &Session, reason: &str) -> Result<Vec<u8>, ()> {
        self.custom(COPYABLE,&json!({"schema_version":1,"type":"wire_unavailable","instance_id":session.instance_id,"runtime_id":session.runtime_id,"reason":reason}),&[],compat::CONTROL_BYTES)
    }
    pub(super) fn statistics(
        &self,
        ns: i128,
        received: u64,
        kernel_dropped: u64,
        interface_dropped: u64,
        limit: usize,
    ) -> Result<Vec<u8>, ()> {
        let wire = self.wire.ok_or(())?;
        let mut body = 0u32.to_le_bytes().to_vec();
        timestamp(&mut body, ns, wire.precision_ns)?;
        // BPF counts packets presented to the filter; Linux PACKET_STATISTICS
        // counts accepted packets. These are source totals, not correlated totals.
        #[cfg(target_os = "macos")]
        option(&mut body, 4, &received.to_le_bytes())?; // isb_ifrecv
        #[cfg(target_os = "linux")]
        option(&mut body, 6, &received.to_le_bytes())?; // isb_filteraccept
        option(&mut body, 7, &kernel_dropped.to_le_bytes())?; // isb_osdrop
        // A zero libpcap ps_ifdrop can mean unsupported, so leave it unknown.
        if interface_dropped != 0 {
            option(&mut body, 5, &interface_dropped.to_le_bytes())?;
        }
        option(&mut body, 0, &[])?;
        block(5, body, limit)
    }
}
pub(super) fn secrets(lines: &[u8], limit: usize) -> Result<Vec<u8>, ()> {
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    if lines.len().saturating_add(20) > limit {
        return Err(());
    }
    let mut body = 0x544c534bu32.to_le_bytes().to_vec();
    body.extend(u32::try_from(lines.len()).map_err(|_| ())?.to_le_bytes());
    body.extend_from_slice(lines);
    block(10, body, limit)
}
