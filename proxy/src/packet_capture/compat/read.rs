//! Read only the current compatibility encoder's metadata packets. Synthetic
//! TCP payload packets are skipped; their bytes never become audit evidence.
use std::{fs::File, io::Read, path::Path};

use serde_json::{Value, json};

use super::{MAGIC, METADATA_BYTES};

pub(crate) fn scan(
    path: &Path,
    mut metadata: impl FnMut(u64, u64, Value) -> Result<(), &'static str>,
) -> Value {
    let mut report = json!({"file":path,"status":"unavailable","packets_read":0,
        "bytes_read":0,"read_to_eof":false});
    if let Err(reason) = packets(path, &mut report, &mut metadata) {
        report["reason"] = json!(reason);
        if report["packets_read"].as_u64().unwrap_or(0) > 0 {
            report["status"] = json!("partial");
        }
    } else {
        report["status"] = json!("available");
        report["read_to_eof"] = json!(true);
    }
    report
}

fn packets(
    path: &Path,
    report: &mut Value,
    metadata: &mut impl FnMut(u64, u64, Value) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut file = File::open(path).map_err(|_| "capture file cannot be opened")?;
    if !file.metadata().is_ok_and(|info| info.is_file()) {
        return Err("capture input is not a regular file");
    }
    let mut header = [0u8; 24];
    file.read_exact(&mut header)
        .map_err(|_| "truncated PCAP header")?;
    report["bytes_read"] = json!(24);
    // This is the current producer contract, not a general PCAP reader.
    if header[..4] != 0xa1b23c4du32.to_le_bytes()
        || header[4..8] != [2, 0, 4, 0]
        || header[8..16] != [0; 8]
        || header[16..20] != 65535u32.to_le_bytes()
        || header[20..24] != 1u32.to_le_bytes()
    {
        return Err("unsupported capture; select current pcap:compat output");
    }
    let mut packet = 0;
    let mut offset = 24;
    loop {
        let mut header = [0u8; 16];
        match file.read(&mut header[..1]) {
            Ok(0) => {
                return if packet == 0 {
                    Err("capture session metadata is absent")
                } else {
                    Ok(())
                };
            }
            Ok(_) => {}
            Err(_) => return Err("capture read failed"),
        }
        file.read_exact(&mut header[1..])
            .map_err(|_| "truncated PCAP packet header")?;
        let length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        if !(54..=65535).contains(&length)
            || header[8..12] != header[12..16]
            || u32::from_le_bytes(header[4..8].try_into().unwrap()) >= 1_000_000_000
        {
            return Err("malformed or truncated compatibility packet");
        }
        // At most one producer-bounded frame is held, independent of file size.
        let mut frame = vec![0; length];
        file.read_exact(&mut frame)
            .map_err(|_| "truncated PCAP packet")?;
        packet += 1;
        report["packets_read"] = json!(packet);
        report["bytes_read"] = json!(offset + 16 + length as u64);
        if frame[..3] != [2, 0x53, 0x59]
            || frame[6..9] != [2, 0x53, 0x59]
            || frame[12..15] != [8, 0, 0x45]
            || frame[26..29] != [192, 0, 2]
            || frame[30..33] != [198, 51, 100]
            || u16::from_be_bytes(frame[16..18].try_into().unwrap()) as usize != length - 14
        {
            return Err("packet is not a current compatibility representation");
        }
        match frame[23] {
            17 => {
                if u16::from_be_bytes(frame[38..40].try_into().unwrap()) as usize != length - 34 {
                    return Err("malformed compatibility metadata datagram");
                }
                let bytes = &frame[42..];
                let encoded = bytes
                    .strip_prefix(MAGIC)
                    .ok_or("compatibility metadata marker is absent")?;
                if bytes.len() > METADATA_BYTES {
                    return Err("oversized compatibility metadata");
                }
                let value = serde_json::from_slice(encoded)
                    .map_err(|_| "malformed compatibility metadata JSON")?;
                metadata(packet, offset, value)?;
            }
            6 if packet > 1 && frame[46] == 0x50 => {}
            _ => return Err("unsupported compatibility packet"),
        }
        offset += 16 + length as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit::pivot::{Query, capture},
        observations::{Gap, LossReason, Record},
    };

    #[test]
    fn current_encoder_observation_and_both_loss_forms_reach_the_audit_consumer() {
        let session = crate::packet_capture::tests::encode_session();
        let observation = crate::packet_capture::tests::observation();
        let metadata = serde_json::to_value(&observation).unwrap();
        let mut attribution = metadata["attribution"].clone();
        attribution["attribution_status"] = attribution
            .as_object_mut()
            .unwrap()
            .remove("status")
            .unwrap();
        let pivot = json!({"records":[{"line":3,"record":{"agent":observation.agent,
            "event":"network.connection","details":{"connection_id":observation.connection_id,
            "attribution":attribution}}}]});
        let mut bytes = super::super::session(&session, "file", 65536).unwrap();
        bytes.extend(
            super::super::encode(&Record::Observation(Box::new(observation.clone())), 65536)
                .unwrap(),
        );
        bytes.extend(
            super::super::encode(
                &Record::Gap(Gap {
                    instance_id: session.instance_id.clone(),
                    runtime_id: session.runtime_id.clone(),
                    first_sequence: 2,
                    last_sequence: 3,
                    count: 2,
                    reason: LossReason::ConsumerAdmissionUnavailable,
                }),
                65536,
            )
            .unwrap(),
        );
        bytes.extend(
            super::super::loss(&session, "file", 4, 5, "encoder_admission_unavailable").unwrap(),
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.pcap");
        std::fs::write(&path, bytes).unwrap();
        let query = Query {
            instance: &session.instance_id,
            runtime: &session.runtime_id,
            kind: "connection",
            id: &observation.connection_id,
            agent: None,
            sandbox_run: None,
            lines: 100,
        };
        let result = capture::read(&path, &pivot, &query);
        assert_eq!(result["status"], "partial", "{result}");
        assert_eq!(result["scan"]["read_to_eof"], true, "{result}");
        assert_eq!(
            result["observations"].as_array().unwrap().len(),
            1,
            "{result}"
        );
        let loss = result["loss"].as_array().unwrap();
        assert_eq!(loss.len(), 2);
        assert_eq!(loss[0]["kind"], "canonical_gap");
        assert_eq!(loss[1]["kind"], "sink_gap");
        assert!(loss.iter().all(|gap| gap["scope"] == "runtime"
            && gap["connection_request_attribution"] == "unavailable"
            && gap["count"] == 2));
        let mut conflicting = pivot;
        conflicting["records"][0]["conflicting"] = json!(true);
        let refused = capture::read(&path, &conflicting, &query);
        assert_eq!(refused["status"], "unavailable");
        assert!(refused["observations"].as_array().unwrap().is_empty());
    }
}
