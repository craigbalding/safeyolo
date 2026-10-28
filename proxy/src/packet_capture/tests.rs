use super::*;
use crate::observations::{Observation, State};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(5);

fn config(directory: &std::path::Path) -> crate::Config {
    let mut config = crate::connection_events::tests::config(directory);
    config.native_settings = Some(crate::native_config::Settings::default());
    config.native_config_dir = Some(directory.to_owned());
    std::fs::create_dir_all(config.data_dir()).unwrap();
    std::fs::write(
        config.data_dir().join("instance_id"),
        "sy-0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    config
}
fn bus(runtime: &crate::Runtime) -> Arc<ObservationBus> {
    runtime
        .connection_events
        .as_ref()
        .unwrap()
        .observations
        .clone()
}
async fn receive(receiver: &mut Receiver) -> Delivery {
    timeout(WAIT, receiver.recv()).await.unwrap().unwrap()
}
fn packets(bytes: &[u8]) -> Vec<(u64, &[u8])> {
    assert_eq!(&bytes[..4], &0xa1b23c4du32.to_le_bytes());
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 1);
    let mut at = 24;
    let mut out = Vec::new();
    while at < bytes.len() {
        let seconds = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as u64;
        let ns = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as u64;
        let len = u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as usize;
        assert_eq!(&bytes[at + 8..at + 12], &bytes[at + 12..at + 16]);
        at += 16;
        let frame = &bytes[at..at + len];
        assert_eq!(&frame[12..14], &[8, 0]);
        assert_eq!(&frame[0..3], &[2, 0x53, 0x59]);
        assert_eq!(&frame[6..9], &[2, 0x53, 0x59]);
        assert_eq!(&frame[26..29], &[192, 0, 2]);
        assert_eq!(&frame[30..33], &[198, 51, 100]);
        out.push((seconds * 1_000_000_000 + ns, frame));
        at += len;
    }
    assert_eq!(at, bytes.len());
    out
}
fn metadata(frame: &[u8]) -> Value {
    assert_eq!(frame[23], 17);
    let payload = &frame[42..];
    let prefix = b"SAFEYOLO-PCAP-COMPAT/1\n";
    assert!(payload.starts_with(prefix));
    serde_json::from_slice(&payload[prefix.len()..]).unwrap()
}
fn session(bytes: &[u8]) -> Value {
    metadata(packets(bytes)[0].1)["session"].clone()
}
fn encode_session() -> crate::observations::Session {
    crate::observations::Session {
        instance_id: "instance".into(),
        runtime_id: "runtime".into(),
        sink_session_id: "session".into(),
        schema_version: 1,
        timestamp_resolution: crate::observations::Resolution {
            wall_ns: Some(1),
            monotonic_ns: Some(1),
        },
        first_sequence: 1,
    }
}
fn observation() -> Observation {
    let bus = ObservationBus::new(
        "instance".into(),
        "runtime".into(),
        Limits::default(),
        Arc::default(),
    );
    let mut o = crate::observations::tests::sample(&bus);
    o.timestamp.wall_unix_ns = 1_234_567_890;
    o.timestamp.monotonic_ns = 123;
    o.id.sequence = 1;
    o
}
#[test]
fn compat_projection_is_deterministic_segmented_and_self_identifying() {
    let payload = (0..5001).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let mut o = observation();
    o.stream_offset = Some(9000);
    o.observed_length = Some(payload.len() as u64);
    o.captured_length = payload.len() as u64;
    o.payload = Some(payload.clone().into());
    let record = Record::Observation(Box::new(o));
    let encoded = compat::encode(&record, 64 * 1024).unwrap();
    assert_eq!(encoded, compat::encode(&record, 64 * 1024).unwrap());
    let mut file = compat::session(&encode_session(), "file", 64 * 1024).unwrap();
    file.extend_from_slice(&encoded);
    let rows = packets(&file);
    let info = metadata(rows[1].1);
    assert_eq!(info["source"]["observation_layer"], "transport_stream");
    assert_eq!(info["source"]["transport"], "unix");
    assert_eq!(info["compat_flow_id"].as_str().unwrap().len(), 64);
    assert!(!info.to_string().contains("payload\":"));
    let mut reassembled = Vec::new();
    for (i, (time, frame)) in rows[2..].iter().enumerate() {
        assert_eq!(*time, 1_234_567_890);
        assert_eq!(frame[23], 6);
        assert_eq!(
            u32::from_be_bytes(frame[38..42].try_into().unwrap()),
            9000 + (i * compat::PAYLOAD_BYTES) as u32
        );
        assert_eq!(frame[47] & 8, if i == 4 { 8 } else { 0 });
        reassembled.extend_from_slice(&frame[54..]);
    }
    assert_eq!(reassembled, payload);
    assert_eq!(rows.len(), 7);
    // A length too small for the complete source batch produces loss, never a
    // prefix falsely marked as a complete observed chunk.
    assert!(compat::encode(&record, 1000).is_err());
    let Record::Observation(source) = &record else {
        unreachable!()
    };
    let mut later = source.as_ref().clone();
    later.id.sequence = 2;
    later.timestamp.wall_unix_ns += 1;
    later.stream_offset = Some(14001);
    let later_record = Record::Observation(Box::new(later.clone()));
    let mut later_file = compat::session(&encode_session(), "file", 64 * 1024).unwrap();
    later_file.extend(compat::encode(&later_record, 64 * 1024).unwrap());
    assert_eq!(
        metadata(packets(&later_file)[1].1)["compat_flow_id"],
        info["compat_flow_id"]
    );
    later.direction = crate::observations::Direction::FromProxy;
    let mut reverse = compat::session(&encode_session(), "file", 64 * 1024).unwrap();
    reverse.extend(compat::encode(&Record::Observation(Box::new(later)), 64 * 1024).unwrap());
    assert_ne!(
        metadata(packets(&reverse)[1].1)["compat_flow_id"],
        info["compat_flow_id"]
    );
    let mut impossible = source.as_ref().clone();
    impossible.timestamp.wall_unix_ns = -1;
    assert!(compat::encode(&Record::Observation(Box::new(impossible)), 64 * 1024).is_err());
    let mut oversized = source.as_ref().clone();
    oversized.connection_id = "x".repeat(9000);
    assert!(compat::encode(&Record::Observation(Box::new(oversized)), 64 * 1024).is_err());
    let mut terminal = observation();
    terminal.state = State::HalfClose;
    terminal.stream_offset = Some(14001);
    let bytes = compat::encode(&Record::Observation(Box::new(terminal)), 64 * 1024).unwrap();
    file.truncate(file.len() - encoded.len());
    file.extend(bytes);
    assert_eq!(packets(&file).last().unwrap().1[47], 0x11);
}
#[test]
fn refused_profiles_remote_tcp_and_secret_config_remain_explicit() {
    let mut settings = Settings::default();
    assert!(settings.payload_layers.is_empty());
    assert!(!settings.active());
    assert!(Tcp::default().bind.ip().is_loopback());
    settings.tcp = Some(Tcp {
        bind: "0.0.0.0:46378".parse().unwrap(),
        insecure_remote: false,
    });
    assert!(
        settings
            .validate(true)
            .unwrap_err()
            .to_string()
            .contains("insecure_remote")
    );
    settings.tcp.as_mut().unwrap().insecure_remote = true;
    settings.validate(true).unwrap();
    settings.profile = Profile::Wire;
    assert_eq!(settings.unavailable(), Some("pcap_wire_unavailable"));
    settings.profile = Profile::Pcapng;
    assert_eq!(
        settings.unavailable(),
        Some("pcapng_portable_encoder_unavailable")
    );
    assert!(serde_json::from_value::<Settings>(json!({"secrets":true})).is_err());
}

#[tokio::test]
async fn shared_output_keeps_slow_sink_bounded_and_healthy_pipe_ordered() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.admin_port = Some(0);
    let settings = &mut config.native_settings.as_mut().unwrap().packet_capture;
    settings.wss = true;
    settings.payload_layers = vec![Layer::TransportStream];
    settings.queue = Limits {
        items: 8,
        bytes: 64 * 1024,
    };
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = bus(&runtime);
    let capture = bus.capture.get().unwrap();
    let mut slow = capture.subscribe(Sink::Tcp).unwrap();
    let mut healthy = capture.subscribe(Sink::Stdout).unwrap();
    let initial = receive(&mut healthy).await;
    assert_eq!(
        healthy.inner.pending.lock().unwrap().bytes,
        initial.bytes.len() + 128
    );
    let mut output = initial.bytes.to_vec();
    drop(initial);
    let initial = receive(&mut slow).await;
    drop(initial);
    let before = bus.counters.json();
    for sequence in 1..=50 {
        let mut o = crate::observations::tests::sample(&bus);
        o.stream_offset = Some(sequence - 1);
        bus.emit_payload(o, &[(sequence % 256) as u8]);
        let delivery = receive(&mut healthy).await;
        output.extend_from_slice(&delivery.bytes);
        let pending = slow.inner.pending.lock().unwrap();
        assert!(pending.bytes <= slow.inner.limits.bytes);
        assert!(pending.items < slow.inner.limits.items);
    }
    let encoded = packets(&output);
    let mut seen = Vec::new();
    for (_, frame) in encoded {
        if frame[23] == 6 {
            seen.extend_from_slice(&frame[54..]);
        }
    }
    assert_eq!(seen, (1..=50).collect::<Vec<u8>>());
    assert_eq!(
        bus.counters.json()["layers"]["transport_stream"]["observations_total"],
        50
    );
    assert_eq!(
        before["layers"]["transport_stream"]["observations_total"],
        0
    );
    assert_eq!(
        bus.counters.json()["layers"]["transport_stream"]["observation_payload_bytes_total"],
        50
    );
    let mut slow_bytes = compat::session(&slow.inner.session, "tcp", 64 * 1024).unwrap();
    loop {
        let d = receive(&mut slow).await;
        let done = d.bytes.windows(b"sink_gap".len()).any(|w| w == b"sink_gap");
        slow_bytes.extend_from_slice(&d.bytes);
        drop(d);
        if done {
            break;
        }
    }
    let rows = packets(&slow_bytes);
    let gap = metadata(rows.last().unwrap().1);
    assert_eq!(gap["type"], "sink_gap");
    assert_eq!(gap["last_sequence"], 50);
    assert_eq!(gap["sink_session_id"], slow.inner.session.sink_session_id);
    assert_eq!(
        bus.counters.json()["sinks"]["stdout"]["sink_dropped_observations_total"],
        0
    );
    assert!(
        bus.counters.json()["sinks"]["tcp"]["sink_dropped_observations_total"]
            .as_u64()
            .unwrap()
            > 0
    );
    // The normal pipe writer consumes the same shared bytes, including its
    // distinct session prefix, without adding delimiters or changing records.
    let pipe = capture.subscribe(Sink::Stdout).unwrap();
    let expected = pipe.inner.pending.lock().unwrap().batches[0].bytes.clone();
    let (writer, mut reader) = tokio::io::duplex(128);
    let task = tokio::spawn(write_stream(writer, pipe));
    let reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let mut canonical = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    bus.emit_payload(crate::observations::tests::sample(&bus), b"p");
    let record = timeout(WAIT, canonical.recv()).await.unwrap().unwrap();
    capture.flush().await;
    capture.close();
    timeout(WAIT, task).await.unwrap().unwrap();
    let bytes = timeout(WAIT, reader).await.unwrap().unwrap();
    let mut expected = expected.to_vec();
    expected.extend(compat::encode(&record, 64 * 1024).unwrap());
    assert_eq!(bytes, expected);
    proxy.shutdown().await;
}

async fn read_prefix(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut bytes = vec![0; 24 + 16];
    stream.read_exact(&mut bytes).await.unwrap();
    let len = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    bytes.resize(40 + len, 0);
    stream.read_exact(&mut bytes[40..]).await.unwrap();
    bytes
}
#[tokio::test]
async fn tcp_reconnect_headers_and_two_clients_preserve_shared_bytes_without_replay() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.native_settings.as_mut().unwrap().packet_capture = Settings {
        payload_layers: vec![Layer::TransportStream],
        tcp: Some(Tcp {
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = bus(&runtime);
    let capture = bus.capture.get().unwrap();
    let address = capture.settings.tcp.as_ref().unwrap().bind;
    assert!(address.port() != 0 && address.ip().is_loopback());
    assert!(
        runtime
            .admin_shield
            .blocks_request_destination("127.1", address.port())
    );
    assert!(runtime.admin_shield.blocks_address(address));
    bus.emit_payload(crate::observations::tests::sample(&bus), b"historical");
    capture.flush().await;
    let mut one = TcpStream::connect(address).await.unwrap();
    let mut two = TcpStream::connect(address).await.unwrap();
    let prefix_one = timeout(WAIT, read_prefix(&mut one)).await.unwrap();
    let prefix_two = timeout(WAIT, read_prefix(&mut two)).await.unwrap();
    assert_eq!(session(&prefix_one)["first_sequence"], 2);
    assert_eq!(session(&prefix_two)["first_sequence"], 2);
    assert_ne!(
        session(&prefix_one)["sink_session_id"],
        session(&prefix_two)["sink_session_id"]
    );
    let mut canonical = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    bus.emit_payload(crate::observations::tests::sample(&bus), b"live");
    let record = timeout(WAIT, canonical.recv()).await.unwrap().unwrap();
    capture.flush().await;
    capture.close();
    let mut a = Vec::new();
    let mut b = Vec::new();
    timeout(WAIT, one.read_to_end(&mut a))
        .await
        .unwrap()
        .unwrap();
    timeout(WAIT, two.read_to_end(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a, compat::encode(&record, 64 * 1024).unwrap());
    // A later session truthfully begins after the delivered sequence.
    let mut reconnected = TcpStream::connect(address).await.unwrap();
    let prefix = timeout(WAIT, read_prefix(&mut reconnected)).await.unwrap();
    assert_eq!(session(&prefix)["first_sequence"], 3);
    assert_ne!(
        session(&prefix)["sink_session_id"],
        session(&prefix_one)["sink_session_id"]
    );
    drop(reconnected);
    drop(one);
    drop(two);
    let mut agent = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    agent
        .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(
        crate::connection_events::tests::head(&mut agent)
            .await
            .starts_with(b"HTTP/1.1 403")
    );
    drop(agent);
    proxy.shutdown().await;
}

#[tokio::test]
async fn native_file_capture_preserves_one_many_and_partial_observed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let path = directory.path().join("capture.pcap");
    config.native_settings.as_mut().unwrap().packet_capture = Settings {
        payload_layers: vec![Layer::TransportStream, Layer::TlsCleartext],
        file: Some(path.clone()),
        ..Default::default()
    };
    config
        .native_settings
        .as_mut()
        .unwrap()
        .packet_capture
        .queue = Limits {
        items: 32,
        bytes: 512 * 1024,
    };
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = origin.accept().await.unwrap();
            let head = crate::connection_events::tests::head(&mut socket).await;
            assert!(head.windows(14).any(|bytes| bytes == b"content_canary"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = bus(&runtime);
    let mut slow = bus.capture.get().unwrap().subscribe(Sink::Tcp).unwrap();
    let slow_prefix = receive(&mut slow).await.bytes.clone();
    let mut canonical = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    let mut records = Vec::new();
    let request = format!(
        "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nX-Test: content_canary\r\nConnection: close\r\n\r\n"
    );
    for many in [false, true] {
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        for chunk in request
            .as_bytes()
            .chunks(if many { 7 } else { request.len() })
        {
            client.write_all(chunk).await.unwrap();
            loop {
                let record = timeout(WAIT, canonical.recv()).await.unwrap().unwrap();
                let observed = matches!(record.as_ref(),Record::Observation(o) if o.point==crate::observations::Point::AgentUds && o.state==State::Chunk && o.direction==crate::observations::Direction::ToProxy);
                records.push(record);
                if observed {
                    break;
                }
            }
        }
        let mut reply = Vec::new();
        timeout(WAIT, client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.ends_with(b"\r\n\r\nok"));
    }
    let partial = b"GET http://incomplete.invalid/ HTTP/1.1\r\nHost: ";
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client.write_all(partial).await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    server.await.unwrap();
    proxy.shutdown().await;
    let mut through = records.last().map_or(0, |r| match r.as_ref() {
        Record::Observation(o) => o.id.sequence,
        Record::Gap(g) => g.last_sequence,
    });
    while through < bus.next_sequence() - 1 {
        let record = timeout(WAIT, canonical.recv()).await.unwrap().unwrap();
        through = match record.as_ref() {
            Record::Observation(o) => o.id.sequence,
            Record::Gap(g) => g.last_sequence,
        };
        records.push(record);
    }
    let rows = records
        .iter()
        .map(|r| match r.as_ref() {
            Record::Observation(o) => o,
            Record::Gap(_) => panic!("unexpected loss"),
        })
        .collect::<Vec<_>>();
    let chunks = rows
        .iter()
        .filter(|o| {
            o.point == crate::observations::Point::AgentUds
                && o.state == State::Chunk
                && o.direction == crate::observations::Direction::ToProxy
        })
        .collect::<Vec<_>>();
    let mut groups: Vec<Vec<&Observation>> = Vec::new();
    for chunk in chunks {
        let chunk: &Observation = chunk;
        if groups
            .last()
            .is_none_or(|group| group[0].connection_id != chunk.connection_id)
        {
            groups.push(Vec::new());
        }
        groups.last_mut().unwrap().push(chunk);
    }
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0].len(), 1);
    assert!(groups[1].len() > 10);
    for (group, expected) in groups
        .iter()
        .zip([request.as_bytes(), request.as_bytes(), partial])
    {
        let mut bytes = Vec::new();
        let mut monotonic = 0;
        for o in group {
            assert_eq!(o.stream_offset, Some(bytes.len() as u64));
            assert_eq!(
                o.observed_length,
                Some(o.payload.as_ref().unwrap().len() as u64)
            );
            assert_eq!(o.captured_length, o.observed_length.unwrap());
            assert!(o.timestamp.monotonic_ns >= monotonic);
            monotonic = o.timestamp.monotonic_ns;
            bytes.extend_from_slice(o.payload.as_ref().unwrap());
        }
        assert_eq!(bytes, expected);
    }
    assert!(
        rows.iter()
            .any(|o| o.connection_id == groups[2][0].connection_id && o.state == State::Eof)
    );
    let heads = rows
        .iter()
        .filter(|o| o.state == State::ParsedHead)
        .collect::<Vec<_>>();
    assert_eq!(heads.len(), 2);
    assert!(bus.counters.sink_dropped[Sink::Tcp.index()].load(Ordering::Relaxed) > 0);
    let mut slow_bytes = slow_prefix.to_vec();
    while let Some(delivery) = timeout(WAIT, slow.recv()).await.unwrap() {
        slow_bytes.extend_from_slice(&delivery.bytes);
    }
    assert!(
        packets(&slow_bytes)
            .iter()
            .any(|(_, frame)| frame[23] == 17 && metadata(frame)["type"] == "sink_gap")
    );
    let actual = std::fs::read(&path).unwrap();
    let decoded = packets(&actual);
    assert_eq!(metadata(decoded[0].1)["session"]["first_sequence"], 1);
    assert!(metadata(decoded[0].1)["session"]["timestamp_resolution"]["wall_ns"].is_number());
    let mut expected = Vec::new();
    for record in records {
        expected.extend(compat::encode(&record, 4 * 1024 * 1024).unwrap());
    }
    let prefix = 24 + 16 + decoded[0].1.len();
    assert_eq!(&actual[prefix..], expected);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!directory.path().join("unused.sqlite3").exists());
    assert!(
        !std::fs::read_to_string(directory.path().join("audit.jsonl"))
            .unwrap()
            .contains("content_canary")
    );
    if let Some(path) = std::env::var_os("SAFEYOLO_COMPAT_PROBE_OUTPUT") {
        std::fs::write(path, actual).unwrap();
    }
}

#[tokio::test]
async fn failed_file_sink_keeps_agent_traffic_and_reports_only_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.native_settings.as_mut().unwrap().packet_capture = Settings {
        payload_layers: vec![Layer::TransportStream],
        file: Some(directory.path().to_owned()),
        ..Default::default()
    };
    let (origin, address) = crate::test_owned_endpoint::bind().await;
    let origin = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        crate::connection_events::tests::head(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = bus(&runtime);
    let mut client = UnixStream::connect(directory.path().join("alice.sock"))
        .await
        .unwrap();
    client.write_all(format!("GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nX-Canary: never_log_payload_858\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    timeout(WAIT, client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    timeout(WAIT, async {
        while bus.counters.sink_errors[Sink::File.index()].load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    origin.await.unwrap();
    struct FailedFile;
    impl tokio::io::AsyncWrite for FailedFile {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::other("never_log_payload_858")))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    let receiver = bus.capture.get().unwrap().subscribe(Sink::File).unwrap();
    timeout(WAIT, write_stream(FailedFile, receiver))
        .await
        .unwrap();
    let stats = bus.counters.json();
    assert_eq!(stats["sinks"]["file"]["sink_errors_total"], 2);
    assert!(!stats.to_string().contains("never_log_payload_858"));
    proxy.shutdown().await;
    assert!(
        !std::fs::read_to_string(directory.path().join("audit.jsonl"))
            .unwrap()
            .contains("never_log_payload_858")
    );
}

#[tokio::test]
async fn wss_authorization_binary_frames_and_session_start_cross_real_tls() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let token_path = directory.path().join("operator-token");
    std::fs::write(&token_path, "capture-operator-858").unwrap();
    config.admin_port = Some(0);
    config.admin_api_token_file = Some(token_path);
    config.native_settings.as_mut().unwrap().packet_capture = Settings {
        wss: true,
        payload_layers: vec![Layer::TlsCleartext],
        ..Default::default()
    };
    let proxy = crate::Proxy::start(config).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = bus(&runtime);
    let admin = runtime.admin_address.unwrap();
    let capture = bus.capture.get().unwrap();
    // The product reuses the existing Tailscale TLS publication of its native
    // operator listener. This owned TLS bridge exercises that HTTP boundary
    // without starting Tailscale or opening an external endpoint.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let (listener, address) = crate::test_owned_endpoint::bind().await;
    let bridge = tokio::spawn(async move {
        let mut clients = JoinSet::new();
        for _ in 0..3 {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = tls.clone();
            clients.spawn(async move {
                let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                    .accept(socket)
                    .await
                    .unwrap();
                let mut backend = TcpStream::connect(admin).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut backend).await;
            });
        }
        while clients.join_next().await.is_some() {}
    });
    async fn connect(
        address: SocketAddr,
        config: Arc<rustls::ClientConfig>,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        tokio_rustls::TlsConnector::from(config)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap()
    }
    let handshake = |token: &str| {
        format!(
            "GET /admin/capture HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{token}\r\n"
        )
    };
    let mut unauthorized = connect(address, client.clone()).await;
    unauthorized
        .write_all(handshake("").as_bytes())
        .await
        .unwrap();
    let mut denied = Vec::new();
    timeout(WAIT, unauthorized.read_to_end(&mut denied))
        .await
        .unwrap()
        .unwrap();
    assert!(denied.starts_with(b"HTTP/1.1 401"));
    assert!(!denied.windows(20).any(|w| w == b"SAFEYOLO-PCAP-COMPAT/"));
    assert_eq!(
        bus.counters.sink_bytes[Sink::Wss.index()].load(Ordering::Relaxed),
        0
    );
    assert!(capture.sinks.lock().unwrap().is_empty());
    drop(unauthorized);
    bus.emit(crate::observations::tests::sample(&bus));
    capture.flush().await;
    let mut tls = connect(address, client.clone()).await;
    tls.write_all(handshake("Authorization: Bearer capture-operator-858\r\n").as_bytes())
        .await
        .unwrap();
    let response = crate::connection_events::tests::head(&mut tls).await;
    assert!(response.starts_with(b"HTTP/1.1 101"));
    let (read, mut write) = tokio::io::split(tls);
    let mut reader = crate::websocket::Reader::new(read, false, None);
    async fn frame(
        reader: &mut crate::websocket::Reader<impl tokio::io::AsyncRead + Unpin>,
    ) -> Vec<u8> {
        match timeout(WAIT, reader.read()).await.unwrap().unwrap() {
            crate::websocket::Event::Message(message) => message
                .content()
                .with_bytes(|bytes| bytes.to_vec())
                .unwrap(),
            _ => panic!("binary capture message required"),
        }
    }
    let prefix = frame(&mut reader).await;
    assert_eq!(session(&prefix)["first_sequence"], 2);
    assert!(session(&prefix)["timestamp_resolution"]["monotonic_ns"].is_number());
    // A partial client control frame must survive cancellation of the capture
    // receive branch. Complete the masked ping after the next output arrives.
    write.write_all(&[0x89]).await.unwrap();
    let mut canonical = bus.subscribe(ConsumerKind::Metrics, Limits::default());
    let mut o = crate::observations::tests::sample(&bus);
    o.layer = Layer::TlsCleartext;
    o.point = crate::observations::Point::ClientTls;
    o.observed_length = Some(25);
    bus.emit_payload(o, b"observed_plaintext_canary");
    let record = timeout(WAIT, canonical.recv()).await.unwrap().unwrap();
    let bytes = frame(&mut reader).await;
    assert_eq!(bytes, compat::encode(&record, 64 * 1024).unwrap());
    write.write_all(&[0x80, 0, 0, 0, 0]).await.unwrap();
    assert!(matches!(
        timeout(WAIT, reader.read()).await.unwrap().unwrap(),
        crate::websocket::Event::Pong(_)
    ));
    let mut stream = prefix.clone();
    stream.extend(bytes);
    packets(&stream);
    drop(reader);
    drop(write);
    let mut tls = connect(address, client).await;
    tls.write_all(handshake("Authorization: Bearer capture-operator-858\r\n").as_bytes())
        .await
        .unwrap();
    assert!(
        crate::connection_events::tests::head(&mut tls)
            .await
            .starts_with(b"HTTP/1.1 101")
    );
    let mut reader = crate::websocket::Reader::new(tls, false, None);
    let reconnect = frame(&mut reader).await;
    assert_eq!(session(&reconnect)["first_sequence"], 3);
    assert_ne!(
        session(&reconnect)["sink_session_id"],
        session(&prefix)["sink_session_id"]
    );
    drop(reader);
    proxy.shutdown().await;
    timeout(WAIT, bridge).await.unwrap().unwrap();
}

#[tokio::test]
async fn unavailable_profiles_leave_metadata_and_traffic_running_without_capture() {
    for profile in [Profile::Wire, Profile::Pcapng] {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        let path = directory.path().join("unavailable.pcap");
        config.native_settings.as_mut().unwrap().packet_capture = Settings {
            profile,
            payload_layers: vec![Layer::TransportStream],
            file: Some(path.clone()),
            tcp: Some(Tcp {
                bind: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let proxy = crate::Proxy::start(config).await.unwrap();
        let runtime = proxy.runtime.read().unwrap().clone();
        let bus = bus(&runtime);
        assert!(bus.capture.get().is_none());
        assert!(!path.exists());
        let mut metadata = bus.subscribe(ConsumerKind::Metrics, Limits::default());
        let mut client = UnixStream::connect(directory.path().join("alice.sock"))
            .await
            .unwrap();
        client
            .write_all(b"GET http://incomplete.invalid/ HTTP/1.1\r\nHost: ")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(WAIT, client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        let mut found = false;
        while !found {
            let record = timeout(WAIT, metadata.recv()).await.unwrap().unwrap();
            if let Record::Observation(o) = record.as_ref() {
                assert!(o.payload.is_none());
                assert_eq!(o.captured_length, 0);
                found = o.state == State::Eof;
            }
        }
        assert_eq!(bus.counters.json()["sinks"]["file"]["sink_errors_total"], 1);
        assert_eq!(bus.counters.json()["sinks"]["tcp"]["sink_errors_total"], 1);
        proxy.shutdown().await;
    }
}

#[tokio::test]
async fn a_gap_crossing_a_new_sink_starts_at_that_sessions_first_sequence() {
    let bus = ObservationBus::new(
        "instance".into(),
        "runtime".into(),
        Limits::default(),
        Arc::default(),
    );
    for _ in 0..3 {
        bus.emit(crate::observations::tests::sample(&bus));
    }
    let source = bus.subscribe(ConsumerKind::Capture, Limits::default());
    let capture = Capture {
        bus: Arc::downgrade(&bus),
        tcp_address: None,
        session: source.session.clone(),
        settings: Settings::default(),
        sinks: Mutex::new(Vec::new()),
        counters: bus.counters.clone(),
        encoded_through: AtomicU64::new(3),
        progress: Notify::new(),
    };
    let mut receiver = capture.subscribe(Sink::Tcp).unwrap();
    let mut bytes = receive(&mut receiver).await.bytes.to_vec();
    assert_eq!(session(&bytes)["first_sequence"], 4);
    let record = Record::Gap(crate::observations::Gap {
        instance_id: "instance".into(),
        runtime_id: "runtime".into(),
        first_sequence: 1,
        last_sequence: 5,
        count: 5,
        reason: crate::observations::LossReason::CanonicalAdmissionUnavailable,
    });
    capture.dispatch(
        &record,
        Some(compat::encode(&record, 64 * 1024).unwrap().into()),
    );
    bytes.extend_from_slice(&receive(&mut receiver).await.bytes);
    let rows = packets(&bytes);
    let gap = metadata(rows.last().unwrap().1);
    assert_eq!(gap["first_sequence"], 4);
    assert_eq!(gap["last_sequence"], 5);
    assert_eq!(gap["count"], 2);
    assert_eq!(gap["reason"], "canonical_admission_unavailable");
}

#[test]
fn capture_endpoint_shield_covers_mapped_addresses_without_claiming_other_hosts() {
    let mut shield = crate::admin_shield::AdminShield::new(9090, "").unwrap();
    shield.protect_capture_endpoint("127.0.0.2:46378".parse().unwrap());
    assert!(shield.blocks_request_destination("127.0.0.2", 46378));
    assert!(shield.blocks_request_destination("::ffff:127.0.0.2", 46378));
    assert!(shield.blocks_address("[::ffff:127.0.0.2]:46378".parse().unwrap()));
    assert!(!shield.blocks_address("192.0.2.22:46378".parse().unwrap()));
}

#[tokio::test]
async fn failed_tcp_bind_and_reload_do_not_shield_an_unowned_capture_port() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    config.native_settings.as_mut().unwrap().packet_capture.tcp = Some(Tcp {
        bind: address,
        ..Default::default()
    });
    let mut proxy = crate::Proxy::start(config.clone()).await.unwrap();
    let runtime = proxy.runtime.read().unwrap().clone();
    let bus = bus(&runtime);
    timeout(WAIT, async {
        while bus.counters.sink_errors[Sink::Tcp.index()].load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!runtime.admin_shield.blocks_address(address));
    assert!(bus.capture.get().unwrap().tcp_address.is_none());
    config
        .native_settings
        .as_mut()
        .unwrap()
        .packet_capture
        .tcp
        .as_mut()
        .unwrap()
        .bind = "127.0.0.1:46378".parse().unwrap();
    proxy.reload(config).await.unwrap();
    assert!(
        !proxy
            .runtime
            .read()
            .unwrap()
            .admin_shield
            .blocks_address("127.0.0.1:46378".parse().unwrap())
    );
    proxy.shutdown().await;
}
