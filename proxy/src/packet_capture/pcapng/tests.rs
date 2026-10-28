use super::*;
mod native_tls;
use crate::observations::{Gap, LossReason};
use crate::packet_capture::{
    Packet,
    tests::{encode_session, observation},
};

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn blocks(bytes: &[u8]) -> Vec<(u32, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let length = word(bytes, at + 4) as usize;
        assert!(length >= 12 && length.is_multiple_of(4));
        assert_eq!(word(bytes, at + length - 4) as usize, length);
        out.push((word(bytes, at), &bytes[at + 8..at + length - 4]));
        at += length;
    }
    assert_eq!(at, bytes.len());
    out
}
fn options(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let code = u16::from_le_bytes(bytes[..2].try_into().unwrap());
        let length = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize;
        out.push((code, &bytes[4..4 + length]));
        bytes = &bytes[4 + length.next_multiple_of(4)..];
        if code == 0 {
            assert!(bytes.is_empty());
            break;
        }
    }
    out
}
fn format(precision: u64, compatibility: bool) -> Format {
    Format {
        enterprise: TEST_ENTERPRISE,
        wire: Some(wire::Format {
            link_type: 1,
            precision_ns: precision,
        }),
        compatibility,
        wire_unavailable: None,
    }
}
fn custom(body: &[u8]) -> (serde_json::Value, &[u8]) {
    assert_eq!(word(body, 0), TEST_ENTERPRISE.number);
    assert_eq!(&body[4..8], b"SYOB");
    let metadata = word(body, 8) as usize;
    let payload = word(body, 12) as usize;
    (
        serde_json::from_slice(&body[16..16 + metadata]).unwrap(),
        &body[16 + metadata..16 + metadata + payload],
    )
}
#[test]
fn canonical_blocks_preserve_payload_identity_lineage_and_deliberate_copy_forms() {
    let format = format(1, true);
    let session = encode_session();
    let mut file = format.session(&session, "file", 65536).unwrap();
    let mut o = observation();
    o.payload = Some(std::sync::Arc::from(&b"observed bytes"[..]));
    o.captured_length = 14;
    o.observed_length = Some(14);
    let payload = o.payload.clone().unwrap();
    let record = Record::Observation(Box::new(o.clone()));
    file.extend(format.encode(&record, 65536).unwrap());
    let rows = blocks(&file);
    assert_eq!(rows[0].0, 0x0a0d0d0a);
    let section = options(&rows[0].1[16..]);
    let section = section.iter().find(|o| o.0 == SECTION_STRING).unwrap();
    assert_eq!(word(section.1, 0), TEST_ENTERPRISE.number);
    let section: serde_json::Value = serde_json::from_slice(&section.1[4..]).unwrap();
    assert_eq!(section["session"]["instance_id"], session.instance_id);
    assert_eq!(
        section["session"]["sink_session_id"],
        session.sink_session_id
    );
    assert_eq!(section["session"]["first_sequence"], session.first_sequence);
    assert_eq!(section["wire_interface"], 0);
    assert_eq!(section["compat_interface"], 1);
    assert_eq!(rows.iter().filter(|b| b.0 == 1).count(), 2);
    assert_eq!(rows.iter().filter(|b| b.0 == NONCOPYABLE).count(), 1);
    let canonical = rows.iter().find(|b| b.0 == COPYABLE).unwrap();
    let (metadata, bytes) = custom(canonical.1);
    assert_eq!(metadata["source"]["id"]["sequence"], o.id.sequence);
    assert_eq!(
        metadata["source"]["timestamp"]["monotonic_ns"],
        o.timestamp.monotonic_ns
    );
    assert_eq!(bytes, payload.as_ref());
    let classic = compat::encode(&record, 65536).unwrap();
    let packets: Vec<_> = rows.iter().filter(|b| b.0 == 6).collect();
    let mut at = 0;
    for (_, body) in packets {
        assert_eq!(word(body, 0), 1);
        let len = word(&classic, at + 8) as usize;
        assert_eq!(&body[20..20 + len], &classic[at + 16..at + 16 + len]);
        at += 16 + len;
    }
    assert_eq!(at, classic.len());
    assert!(format.encode(&record, 32).is_err());
}
#[test]
fn wire_subset_keeps_actual_precision_and_packet_options_are_copyable() {
    for precision in [1, 1000] {
        let format = format(precision, false);
        let mut o = observation();
        o.payload = Some(std::sync::Arc::from(&b"packet bytes"[..]));
        o.captured_length = 12;
        o.timestamp.wall_unix_ns =
            1_750_000_000_123_456_789i128 / precision as i128 * precision as i128;
        o.packet = Some(Packet {
            link_type: 1,
            original_length: o.captured_length as u32 + 3,
            precision_ns: precision,
        });
        let record = Record::Observation(Box::new(o.clone()));
        let mut file = format.session(&encode_session(), "file", 65536).unwrap();
        file.extend(format.encode(&record, 65536).unwrap());
        let rows = blocks(&file);
        let idb = rows.iter().find(|b| b.0 == 1).unwrap();
        assert_eq!(
            options(&idb.1[8..]).iter().find(|o| o.0 == 9).unwrap().1,
            if precision == 1 { &[9] } else { &[6] }
        );
        let epb = rows.iter().find(|b| b.0 == 6).unwrap().1;
        let ticks = ((word(epb, 4) as u64) << 32) | word(epb, 8) as u64;
        assert_eq!(ticks as i128 * precision as i128, o.timestamp.wall_unix_ns);
        assert_eq!(word(epb, 16), o.captured_length as u32 + 3);
        let caplen = word(epb, 12) as usize;
        assert_eq!(&epb[20..20 + caplen], o.payload.as_ref().unwrap().as_ref());
        let option = options(&epb[20 + caplen.next_multiple_of(4)..]);
        assert!(option.iter().any(|o| o.0 == CUSTOM_STRING));
        let classic = format.wire.unwrap().encode(&record, 65536).unwrap();
        assert_eq!(&classic[16..], &epb[20..20 + caplen]);
        assert_eq!(
            word(&classic, 0) as i128 * 1_000_000_000
                + word(&classic, 4) as i128 * precision as i128,
            o.timestamp.wall_unix_ns
        );
    }
}
#[test]
fn genuine_statistics_and_canonical_gaps_remain_different_evidence() {
    let format = format(1, false);
    let bytes = format
        .statistics(1_750_000_000_123_456_789, 50, 4, 2, 65536)
        .unwrap();
    let rows = blocks(&bytes);
    assert_eq!(rows[0].0, 5);
    let opts = options(&rows[0].1[12..]);
    #[cfg(target_os = "linux")]
    let receive = 6;
    #[cfg(target_os = "macos")]
    let receive = 4;
    for (code, value) in [(receive, 50u64), (7, 4), (5, 2)] {
        let bytes = opts.iter().find(|o| o.0 == code).unwrap().1;
        assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), value);
    }
    let gap = Record::Gap(Gap {
        instance_id: "one".into(),
        runtime_id: "run".into(),
        first_sequence: 3,
        last_sequence: 8,
        count: 6,
        reason: LossReason::CanonicalAdmissionUnavailable,
    });
    let bytes = format.encode(&gap, 65536).unwrap();
    let rows = blocks(&bytes);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, COPYABLE);
    let (gap, payload) = custom(rows[0].1);
    assert!(payload.is_empty());
    assert_eq!(gap["source"]["reason"], "canonical_admission_unavailable");
    assert_eq!(gap["source"]["count"], 6);
    let bytes = format.statistics(0, 0, 0, 0, 65536).unwrap();
    let rows = blocks(&bytes);
    assert!(!options(&rows[0].1[12..]).iter().any(|o| o.0 == 5));
}
#[test]
fn standard_decryption_block_has_exact_unpadded_secret_length() {
    let lines = b"CLIENT_RANDOM 0000 1234\n";
    let bytes = secrets(lines, 65536).unwrap();
    let rows = blocks(&bytes);
    assert_eq!(rows[0].0, 10);
    assert_eq!(word(rows[0].1, 0), 0x544c534b);
    assert_eq!(word(rows[0].1, 4), lines.len() as u32);
    assert_eq!(&rows[0].1[8..8 + lines.len()], lines);
    assert!(secrets(lines, lines.len()).is_err());
    assert!(secrets(&[], 100).unwrap().is_empty());
}

#[test]
fn optional_projection_failure_preserves_the_complete_canonical_record() {
    let mut o = observation();
    o.timestamp.wall_unix_ns = (u32::MAX as i128 + 1) * 1_000_000_000;
    o.payload = Some(std::sync::Arc::from(&b"observed"[..]));
    o.captured_length = 8;
    let record = Record::Observation(Box::new(o));
    assert!(compat::encode(&record, 65536).is_err());
    let bytes = format(1, true).encode(&record, 65536).unwrap();
    let rows = blocks(&bytes);
    assert_eq!(rows.len(), 1);
    let (metadata, payload) = custom(rows[0].1);
    assert_eq!(payload, b"observed");
    assert_eq!(metadata["compatibility_requested"], true);
    assert_eq!(metadata["compatibility_included"], false);
    assert_eq!(
        metadata["source"]["timestamp"]["wall_unix_ns"],
        serde_json::json!((u32::MAX as i128 + 1) * 1_000_000_000)
    );
    let mut timestamp = Vec::new();
    assert!(super::timestamp(&mut timestamp, -1, 1000).is_err());
}

#[tokio::test]
async fn secret_batches_precede_packets_and_reader_authorization_never_inherits_them() {
    use crate::observations::ObservationBus;
    use crate::packet_capture::{Capture, Encoder, Limits, Settings, Sink};
    use rustls::KeyLog;
    use std::sync::{Arc, Mutex, atomic::AtomicU64};
    use tokio::sync::Notify;
    let bus = ObservationBus::new(
        "instance".into(),
        "runtime".into(),
        Limits::default(),
        Arc::default(),
    );
    let capture = Capture {
        bus: Arc::downgrade(&bus),
        tcp_endpoint: None,
        session: encode_session(),
        settings: Settings {
            tls_secrets: true,
            profile: crate::packet_capture::Profile::Pcapng,
            ..Default::default()
        },
        sinks: Mutex::default(),
        counters: bus.counters.clone(),
        encoded_through: AtomicU64::new(0),
        progress: Notify::new(),
        encoder: Encoder::Pcapng(format(1, false)),
        secrets: Some(Arc::new(crate::packet_capture::secrets::Store::new(
            Limits::default(),
        ))),
        secrets_token: zeroize::Zeroizing::new("separate-capture-secret-token".into()),
    };
    let mut read = capture.subscribe_authorized(Sink::Wss, false).unwrap();
    let mut authorized = capture.subscribe_authorized(Sink::Wss, true).unwrap();
    drop(read.recv().await.unwrap());
    drop(authorized.recv().await.unwrap());
    let mut o = observation();
    o.payload = Some(Arc::from(&b"packet bytes"[..]));
    o.captured_length = 12;
    o.packet = Some(Packet {
        link_type: 1,
        original_length: 12,
        precision_ns: 1,
    });
    let retained = capture.register_secrets(&o.connection_id).unwrap();
    let handshake = retained.begin();
    retained.log("CLIENT_RANDOM", &[1; 32], &[2; 48]);
    drop(handshake);
    let record = Record::Observation(Box::new(o));
    let bytes = Some(Arc::from(capture.encoder.encode(&record, 65536).unwrap()));
    let secret = capture.encode_secrets(&record, &bytes, 65536).await;
    capture.dispatch(&record, bytes, secret);
    let public = read.recv().await.unwrap();
    let secret = authorized.recv().await.unwrap();
    assert_eq!(
        blocks(&public.bytes)
            .iter()
            .map(|b| b.0)
            .collect::<Vec<_>>(),
        vec![6]
    );
    assert_eq!(
        blocks(&secret.bytes)
            .iter()
            .map(|b| b.0)
            .collect::<Vec<_>>(),
        vec![10, 6]
    );
    assert!(!public.bytes.windows(13).any(|b| b == b"CLIENT_RANDOM"));
    assert!(secret.bytes.ends_with(&public.bytes));
    drop(public);
    drop(secret);
    // A per-sink secret-budget failure preserves the packet with a limitation.
    let secret: Arc<[u8]> = vec![0; capture.settings.queue.bytes].into();
    let public: Arc<[u8]> = capture.encoder.encode(&record, 65536).unwrap().into();
    capture.dispatch(&record, Some(public), Some(secret));
    let fallback = authorized.recv().await.unwrap();
    let rows = blocks(&fallback.bytes);
    assert_eq!(
        rows.iter().map(|b| b.0).collect::<Vec<_>>(),
        vec![COPYABLE, 6]
    );
    assert_eq!(
        custom(rows[0].1).0["reason"],
        "tls_secret_sink_budget_unavailable"
    );
}
